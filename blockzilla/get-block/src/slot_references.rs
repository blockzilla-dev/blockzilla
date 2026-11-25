//! Portable, complete block-local ID collection and bounded table resolution.
//! No index builder, network client, signature reads or persistent block copy.
use crate::archive_schema::{self, MessageSchema, MetadataSchema};
use crate::slot_resolution::{
    CheckedResolution, LocatorV1, MESSAGE_CURRENT, MESSAGE_MAY24, METADATA_CURRENT,
    METADATA_LEGACY, NamedSourceObject, ResolutionV1, SourceObjectIdentity,
};
use blockzilla_archive_v2::{
    ARCHIVE_V2_TX_FLAG_HAS_METADATA, ARCHIVE_V2_TX_FLAG_METADATA_RAW_FALLBACK,
    ARCHIVE_V2_TX_FLAG_TX_RAW_FALLBACK, ArchiveV2BlockAccessBlockhash, ArchiveV2BlockAccessPubkey,
    ArchiveV2BlockAccessVoteHash, ArchiveV2HotBlockBlob, ArchiveV2HotBlockIndexRow,
    ArchiveV2HotInstructionData, ArchiveV2HotMessagePayload, ArchiveV2VoteHashRef,
};
use blockzilla_primitives::CompactPubkey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_FAMILY_IDS: usize = 65_536;
pub const MAX_TRANSACTIONS: usize = 65_536;
pub const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_TABLE_WINDOW: usize = 64 * 1024;
const MAX_RECORD_GAP: u64 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoteReference {
    pub block_id: u32,
    pub bank_hash: bool,
    pub block_id_hash: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotReferences {
    pub slot: u64,
    pub parent_slot: u64,
    pub blockhash_id: u32,
    pub previous_blockhash_id: u32,
    pub signature_counts: Vec<u8>,
    pub pubkeys: Vec<u32>,
    pub blockhashes: Vec<i32>,
    pub votes: Vec<VoteReference>,
}

impl SlotReferences {
    pub fn current_hash_id(&self) -> Result<i32, String> {
        i32::try_from(self.blockhash_id).map_err(|_| "current hash ID exceeds i32".into())
    }

    /// The legacy first block obtains its parent from the newest tail entry.
    pub fn parent_hash_id(&self) -> Result<Option<i32>, String> {
        if self.slot == 0 {
            return Ok(None);
        }
        if self.blockhash_id == 0 && self.previous_blockhash_id == 0 {
            return Ok(Some(-1));
        }
        i32::try_from(self.previous_blockhash_id)
            .map(Some)
            .map_err(|_| "previous hash ID exceeds i32".into())
    }

    pub fn validate(&self, hot: &ArchiveV2HotBlockIndexRow) -> Result<(), String> {
        if self.slot != hot.slot
            || (self.slot == 0 && self.parent_slot != 0)
            || (self.slot != 0 && self.parent_slot >= self.slot)
            || self.signature_counts.len() > MAX_TRANSACTIONS
            || self.signature_counts.len() != hot.tx_count as usize
            || self
                .signature_counts
                .iter()
                .try_fold(0u32, |sum, n| sum.checked_add(u32::from(*n)))
                != Some(hot.signature_count)
        {
            return Err("reference header or signature counts differ from hot row".into());
        }
        if self.pubkeys.len() > MAX_FAMILY_IDS
            || self.blockhashes.len() > MAX_FAMILY_IDS
            || self.votes.len() > MAX_FAMILY_IDS
            || self.pubkeys.contains(&0)
            || !self.pubkeys.windows(2).all(|v| v[0] < v[1])
            || !self.blockhashes.windows(2).all(|v| v[0] < v[1])
            || !self.votes.windows(2).all(|v| v[0].block_id < v[1].block_id)
            || self.votes.iter().any(|v| !v.bank_hash && !v.block_id_hash)
        {
            return Err("reference families must be bounded, sorted and unique".into());
        }
        if self
            .blockhashes
            .binary_search(&self.current_hash_id()?)
            .is_err()
            || self
                .parent_hash_id()?
                .is_some_and(|id| self.blockhashes.binary_search(&id).is_err())
        {
            return Err("reference set omits a current or actual previous hash".into());
        }
        Ok(())
    }
}

/// Check a service response without decoding its dictionaries a second time.
pub fn validate_resolution(
    value: &CheckedResolution,
    references: &SlotReferences,
) -> Result<(), String> {
    references.validate(&value.locator_ref().hot.into())?;
    value.validate_exact_membership(
        &references.pubkeys,
        &references.blockhashes,
        &references
            .votes
            .iter()
            .map(|v| (v.block_id, v.bank_hash, v.block_id_hash))
            .collect::<Vec<_>>(),
    )?;
    value.validate_reference_header(
        references.slot,
        references.parent_slot,
        references.blockhash_id,
        references.previous_blockhash_id,
        &references.signature_counts,
    )
}

fn region(bytes: &[u8], offset: u32, length: u32) -> Result<&[u8], String> {
    let start = offset as usize;
    let end = start
        .checked_add(length as usize)
        .ok_or("reference region overflows")?;
    bytes
        .get(start..end)
        .ok_or_else(|| "reference region exceeds hot payload".into())
}

/// Collect every reference needed by full RPC rendering, not just message accounts.
pub fn collect(
    block: &ArchiveV2HotBlockBlob,
    hot: &ArchiveV2HotBlockIndexRow,
    message_schema: u8,
    metadata_schema: u8,
) -> Result<SlotReferences, String> {
    if block.header.slot != hot.slot
        || block.tx_count != hot.tx_count
        || block.tx_rows.len() != hot.tx_count as usize
        || block.tx_rows.len() > MAX_TRANSACTIONS
    {
        return Err("hot block identity differs from reference source row".into());
    }
    let message_schema = match message_schema {
        MESSAGE_CURRENT => MessageSchema::Current,
        MESSAGE_MAY24 => MessageSchema::May24,
        _ => return Err("unsupported reference message schema".into()),
    };
    let metadata_schema = match metadata_schema {
        METADATA_CURRENT => MetadataSchema::Current,
        METADATA_LEGACY => MetadataSchema::Legacy,
        _ => return Err("unsupported reference metadata schema".into()),
    };
    let mut refs = SlotReferences {
        slot: hot.slot,
        parent_slot: block.header.parent_slot,
        blockhash_id: block.header.blockhash_id,
        previous_blockhash_id: block.header.previous_blockhash_id,
        signature_counts: Vec::with_capacity(block.tx_rows.len()),
        pubkeys: Vec::new(),
        blockhashes: Vec::new(),
        votes: Vec::new(),
    };
    let mut hashes = BTreeSet::from([refs.current_hash_id()?]);
    if let Some(id) = refs.parent_hash_id()? {
        hashes.insert(id);
    }
    let mut pubkeys = BTreeSet::new();
    let mut votes = BTreeMap::<u32, u8>::new();
    let key = |value: CompactPubkey, out: &mut BTreeSet<u32>| -> Result<(), String> {
        if let CompactPubkey::Id(id) = value {
            out.insert(id);
            if out.len() > MAX_FAMILY_IDS {
                return Err("pubkey reference family exceeds its bound".into());
            }
        }
        Ok(())
    };
    if let Some(rewards) = &block.header.rewards {
        for reward in &rewards.decoded {
            key(reward.pubkey, &mut pubkeys)?;
        }
    }
    for (index, row) in block.tx_rows.iter().enumerate() {
        if row.tx_index as usize != index
            || row.reserved != [0; 3]
            || row.flags
                & (ARCHIVE_V2_TX_FLAG_TX_RAW_FALLBACK | ARCHIVE_V2_TX_FLAG_METADATA_RAW_FALLBACK)
                != 0
        {
            return Err(
                "raw fallback or invalid transaction row cannot supply complete references".into(),
            );
        }
        refs.signature_counts.push(row.signature_count);
        let message = archive_schema::decode_message(
            message_schema,
            region(&block.message_bytes, row.message_offset, row.message_len)?,
        )?;
        let (accounts, recent, instructions, required) = match &message {
            ArchiveV2HotMessagePayload::Legacy(v) => (
                &v.account_keys,
                &v.recent_blockhash,
                &v.instructions,
                v.header.num_required_signatures,
            ),
            ArchiveV2HotMessagePayload::V0(v) => {
                for lookup in &v.address_table_lookups {
                    key(lookup.account_key, &mut pubkeys)?;
                }
                (
                    &v.account_keys,
                    &v.recent_blockhash,
                    &v.instructions,
                    v.header.num_required_signatures,
                )
            }
            ArchiveV2HotMessagePayload::V1(v) => (
                &v.account_keys,
                &v.recent_blockhash,
                &v.instructions,
                v.header.num_required_signatures,
            ),
        };
        if required != row.signature_count {
            return Err("message signature count differs from hot transaction row".into());
        }
        for value in accounts {
            key(*value, &mut pubkeys)?;
        }
        if let blockzilla_compact::OwnedCompactRecentBlockhash::Id(id) = recent {
            hashes.insert(*id);
        }
        for instruction in instructions {
            let mut vote = |value: ArchiveV2VoteHashRef, mask: u8| {
                if let ArchiveV2VoteHashRef::Block(id) = value {
                    *votes.entry(id).or_default() |= mask;
                }
            };
            match &instruction.data {
                ArchiveV2HotInstructionData::VoteCompactUpdateVoteState(v)
                | ArchiveV2HotInstructionData::VoteCompactUpdateVoteStateSwitch {
                    update: v, ..
                } => vote(v.hash, 1),
                ArchiveV2HotInstructionData::VoteTowerSync(v)
                | ArchiveV2HotInstructionData::VoteTowerSyncSwitch { tower: v, .. } => {
                    vote(v.update.hash, 1);
                    vote(v.block_id_hash, 2);
                }
                _ => {}
            }
        }
        if row.flags & ARCHIVE_V2_TX_FLAG_HAS_METADATA != 0 {
            let meta = archive_schema::decode_metadata(
                metadata_schema,
                region(&block.metadata_bytes, row.metadata_offset, row.metadata_len)?,
            )?;
            for value in meta
                .loaded_writable_addresses
                .iter()
                .chain(&meta.loaded_readonly_addresses)
            {
                key(*value, &mut pubkeys)?;
            }
            for balance in meta
                .pre_token_balances
                .iter()
                .chain(&meta.post_token_balances)
            {
                for value in [balance.mint, balance.owner, balance.program_id]
                    .into_iter()
                    .flatten()
                {
                    key(value, &mut pubkeys)?;
                }
            }
            for reward in &meta.rewards {
                key(reward.pubkey, &mut pubkeys)?;
            }
            if let Some(value) = meta.return_data {
                key(value.program_id, &mut pubkeys)?;
            }
            if let Some(logs) = meta.logs {
                logs.try_for_each_pubkey(|value| {
                    key(value, &mut pubkeys)?;
                    Ok::<(), String>(())
                })?;
            }
        }
        if hashes.len() > MAX_FAMILY_IDS || votes.len() > MAX_FAMILY_IDS {
            return Err("reference family exceeds its bound".into());
        }
    }
    refs.pubkeys = pubkeys.into_iter().collect();
    refs.blockhashes = hashes.into_iter().collect();
    refs.votes = votes
        .into_iter()
        .map(|(block_id, mask)| VoteReference {
            block_id,
            bank_hash: mask & 1 != 0,
            block_id_hash: mask & 2 != 0,
        })
        .collect();
    refs.validate(hot)?;
    Ok(refs)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TailSchema {
    HashOnly32,
    HashAndSlot40,
}

pub struct ResolvedTables {
    pub blockhash: [u8; 32],
    pub previous_blockhash: [u8; 32],
    pub pubkeys: Vec<ArchiveV2BlockAccessPubkey>,
    pub blockhashes: Vec<ArchiveV2BlockAccessBlockhash>,
    pub vote_hashes: Vec<ArchiveV2BlockAccessVoteHash>,
}

impl ResolvedTables {
    /// Construct the existing resolution envelope without reading or allocating signatures.
    pub fn into_resolution(
        self,
        references: &SlotReferences,
        locator: LocatorV1,
        objects: Vec<NamedSourceObject>,
    ) -> Result<ResolutionV1, String> {
        references.validate(&locator.hot.into())?;
        if references.slot != locator.hot.slot
            || references.parent_slot != locator.parent_slot
            || self.blockhash != locator.blockhash
            || self.previous_blockhash != locator.previous_blockhash
        {
            return Err("resolved block identity differs from locator".into());
        }
        let value = ResolutionV1::from_resolved_tables(
            locator,
            objects,
            &references.signature_counts,
            &self.pubkeys,
            &self.blockhashes,
            &self.vote_hashes,
        )?;
        value.validate_membership(
            &references.pubkeys,
            &references.blockhashes,
            &references
                .votes
                .iter()
                .map(|v| (v.block_id, v.bank_hash, v.block_id_hash))
                .collect::<Vec<_>>(),
        )?;
        Ok(value)
    }
}

fn identity<'a>(
    objects: &'a [NamedSourceObject],
    name: &str,
) -> Result<&'a SourceObjectIdentity, String> {
    let value = objects
        .iter()
        .find(|o| o.name == name)
        .ok_or_else(|| format!("missing table identity {name}"))?;
    value.identity.validate()?;
    Ok(&value.identity)
}

/// Sorted nearby reads are joined into bounded 64 KiB windows, avoiding one read per key.
fn fixed<const N: usize>(
    name: &str,
    ids: &[u64],
    object: &SourceObjectIdentity,
    read: &mut impl FnMut(&str, u64, usize) -> Result<Vec<u8>, String>,
) -> Result<BTreeMap<u64, [u8; N]>, String> {
    if !object.length.is_multiple_of(N as u64)
        || ids.len() > MAX_FAMILY_IDS
        || !ids.windows(2).all(|v| v[0] < v[1])
        || ids.last().is_some_and(|id| *id >= object.length / N as u64)
    {
        return Err(format!("invalid {name} table length or ID range"));
    }
    let mut out = BTreeMap::new();
    let mut at = 0;
    while at < ids.len() {
        let mut end = at;
        while end + 1 < ids.len()
            && ids[end + 1] - ids[end] <= MAX_RECORD_GAP
            && (ids[end + 1] - ids[at] + 1) * N as u64 <= MAX_TABLE_WINDOW as u64
        {
            end += 1;
        }
        let offset = ids[at]
            .checked_mul(N as u64)
            .ok_or("table offset overflow")?;
        let length = usize::try_from((ids[end] - ids[at] + 1) * N as u64)
            .map_err(|_| "table length overflow")?;
        let bytes = read(name, offset, length)?;
        if bytes.len() != length {
            return Err(format!("short {name} table window"));
        }
        for id in &ids[at..=end] {
            let start =
                usize::try_from((id - ids[at]) * N as u64).map_err(|_| "table index overflow")?;
            out.insert(
                *id,
                bytes[start..start + N]
                    .try_into()
                    .expect("checked fixed table window"),
            );
        }
        at = end + 1;
    }
    Ok(out)
}

/// Resolve only typed IDs requested by one decoded hot block. The callback must
/// read an already pinned local object set. It is never called for signatures.
pub fn resolve(
    references: &SlotReferences,
    hot: &ArchiveV2HotBlockIndexRow,
    objects: &[NamedSourceObject],
    tail_schema: TailSchema,
    mut read: impl FnMut(&str, u64, usize) -> Result<Vec<u8>, String>,
) -> Result<ResolvedTables, String> {
    references.validate(hot)?;
    if objects.len() > 32 || objects.windows(2).any(|v| v[0].name >= v[1].name) {
        return Err("table source objects must be bounded, sorted and unique".into());
    }
    let key_ids: Vec<_> = references
        .pubkeys
        .iter()
        .map(|id| u64::from(*id) - 1)
        .collect();
    let keys = fixed::<32>(
        "registry.bin",
        &key_ids,
        identity(objects, "registry.bin")?,
        &mut read,
    )?;
    let hash_ids: Vec<_> = references
        .blockhashes
        .iter()
        .filter(|id| **id >= 0)
        .map(|id| *id as u64)
        .collect();
    let hashes = fixed::<32>(
        "blockhash_registry.bin",
        &hash_ids,
        identity(objects, "blockhash_registry.bin")?,
        &mut read,
    )?;
    let mut tail = Vec::new();
    if references.blockhashes.first().is_some_and(|id| *id < 0) {
        let source = identity(objects, "prev_blockhash_tail.bin")?;
        let width = match tail_schema {
            TailSchema::HashOnly32 => 32,
            TailSchema::HashAndSlot40 => 40,
        };
        if source.length == 0 || source.length > 300 * width || !source.length.is_multiple_of(width)
        {
            return Err("previous hash tail length differs from its declared schema".into());
        }
        let bytes = read("prev_blockhash_tail.bin", 0, source.length as usize)?;
        if bytes.len() as u64 != source.length {
            return Err("short previous hash tail".into());
        }
        let epoch_first = references.slot / 432_000 * 432_000;
        let mut previous_slot = None;
        for record in bytes.chunks_exact(width as usize) {
            let slot = if width == 40 {
                let slot =
                    u64::from_le_bytes(record[32..40].try_into().expect("checked tail width"));
                if slot < epoch_first.saturating_sub(432_000)
                    || slot >= epoch_first
                    || previous_slot.is_some_and(|previous| previous >= slot)
                {
                    return Err(
                        "previous hash tail slots are outside the pinned previous epoch".into(),
                    );
                }
                previous_slot = Some(slot);
                Some(slot)
            } else {
                None
            };
            tail.push((
                <[u8; 32]>::try_from(&record[..32]).expect("checked tail hash"),
                slot,
            ));
        }
    }
    let mut blockhashes = Vec::with_capacity(references.blockhashes.len());
    for id in &references.blockhashes {
        let value = if *id >= 0 {
            *hashes.get(&(*id as u64)).ok_or("missing current hash ID")?
        } else {
            let ordinal = (tail.len() as i64)
                .checked_add(i64::from(*id))
                .filter(|n| *n >= 0)
                .ok_or("previous hash ID exceeds tail")? as usize;
            tail.get(ordinal).ok_or("previous hash ID exceeds tail")?.0
        };
        blockhashes.push(ArchiveV2BlockAccessBlockhash {
            id: *id,
            blockhash: value,
        });
    }
    let hash = |id| {
        blockhashes
            .iter()
            .find(|v| v.id == id)
            .map(|v| v.blockhash)
            .ok_or("missing resolved header hash".to_string())
    };
    let blockhash = hash(references.current_hash_id()?)?;
    let previous_blockhash = match references.parent_hash_id()? {
        Some(id) => hash(id)?,
        None => [0; 32],
    };
    if references.slot != 0
        && references.blockhash_id == 0
        && references.previous_blockhash_id == 0
        && tail
            .last()
            .and_then(|v| v.1)
            .is_some_and(|slot| slot != references.parent_slot)
    {
        return Err("legacy predecessor tail slot differs from actual parent".into());
    }
    let vote_ids: Vec<_> = references
        .votes
        .iter()
        .map(|v| u64::from(v.block_id))
        .collect();
    let votes = if vote_ids.is_empty() {
        BTreeMap::new()
    } else {
        fixed::<65>(
            "vote_hash_registry.bin",
            &vote_ids,
            identity(objects, "vote_hash_registry.bin")?,
            &mut read,
        )?
    };
    let mut vote_hashes = Vec::with_capacity(references.votes.len());
    for request in &references.votes {
        let record = votes
            .get(&u64::from(request.block_id))
            .ok_or("missing vote hash ID")?;
        if record[0] & !3 != 0
            || (request.bank_hash && record[0] & 1 == 0)
            || (request.block_id_hash && record[0] & 2 == 0)
        {
            return Err("vote record omits a required hash or has unknown flags".into());
        }
        vote_hashes.push(ArchiveV2BlockAccessVoteHash {
            block_id: request.block_id,
            bank_hash: (record[0] & 1 != 0)
                .then(|| record[1..33].try_into().expect("checked vote width")),
            block_id_hash: (record[0] & 2 != 0)
                .then(|| record[33..65].try_into().expect("checked vote width")),
        });
    }
    let pubkeys = references
        .pubkeys
        .iter()
        .map(|id| {
            Ok(ArchiveV2BlockAccessPubkey {
                id: *id,
                pubkey: *keys.get(&(u64::from(*id) - 1)).ok_or("missing pubkey ID")?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(ResolvedTables {
        blockhash,
        previous_blockhash,
        pubkeys,
        blockhashes,
        vote_hashes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use blockzilla_archive_v2::{
        ArchiveV2HotBlockHeader, ArchiveV2HotInstruction, ArchiveV2HotRewards, ArchiveV2HotTxRow,
        ArchiveV2HotV0Message, ArchiveV2VoteStateUpdate, ArchiveV2VoteTowerSync,
    };
    use blockzilla_compact::{
        CompactLogStream, CompactMessageHeader, CompactMetaV1, CompactReturnData, CompactReward,
        CompactTokenBalance, LogEvent, OwnedCompactAddressTableLookup, OwnedCompactRecentBlockhash,
    };
    use blockzilla_primitives::wincode_leb128_config;

    fn reward(id: u32) -> CompactReward {
        CompactReward {
            pubkey: CompactPubkey::Id(id),
            lamports: 1,
            post_balance: 2,
            reward_type: 1,
            commission: None,
        }
    }

    fn fixture() -> (ArchiveV2HotBlockBlob, ArchiveV2HotBlockIndexRow) {
        let message = ArchiveV2HotMessagePayload::V0(ArchiveV2HotV0Message {
            header: CompactMessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 0,
            },
            account_keys: vec![CompactPubkey::Id(1), CompactPubkey::Raw([9; 32])],
            recent_blockhash: OwnedCompactRecentBlockhash::Id(-2),
            address_table_lookups: vec![OwnedCompactAddressTableLookup {
                account_key: CompactPubkey::Id(2),
                writable_indexes: vec![],
                readonly_indexes: vec![],
            }],
            instructions: vec![ArchiveV2HotInstruction {
                program_id_index: 0,
                accounts: vec![],
                data: ArchiveV2HotInstructionData::VoteTowerSync(ArchiveV2VoteTowerSync {
                    update: ArchiveV2VoteStateUpdate {
                        root: None,
                        lockout_offsets: vec![],
                        hash: ArchiveV2VoteHashRef::Block(3),
                        timestamp: None,
                    },
                    block_id_hash: ArchiveV2VoteHashRef::Block(3),
                }),
            }],
        });
        let metadata = CompactMetaV1 {
            err: None,
            fee: 1,
            pre_balances: vec![2],
            post_balances: vec![1],
            inner_instructions: None,
            logs: Some(CompactLogStream {
                events: vec![LogEvent::Invoke {
                    program: CompactPubkey::Id(10),
                    depth: 1,
                }],
                strings: Default::default(),
                data: Default::default(),
            }),
            pre_token_balances: vec![CompactTokenBalance {
                account_index: 0,
                mint: Some(CompactPubkey::Id(5)),
                owner: Some(CompactPubkey::Id(6)),
                program_id: Some(CompactPubkey::Id(7)),
                amount: 1,
                decimals: 0,
            }],
            post_token_balances: vec![],
            rewards: vec![reward(8)],
            loaded_writable_addresses: vec![CompactPubkey::Id(3)],
            loaded_readonly_addresses: vec![CompactPubkey::Id(4)],
            return_data: Some(CompactReturnData {
                program_id: CompactPubkey::Id(9),
                data: vec![],
            }),
            compute_units_consumed: None,
            cost_units: None,
        };
        let message_bytes = wincode::config::serialize(&message, wincode_leb128_config()).unwrap();
        let metadata_bytes =
            wincode::config::serialize(&metadata, wincode_leb128_config()).unwrap();
        let tx = ArchiveV2HotTxRow {
            tx_index: 0,
            flags: ARCHIVE_V2_TX_FLAG_HAS_METADATA,
            message_offset: 0,
            message_len: message_bytes.len() as u32,
            metadata_offset: 0,
            metadata_len: metadata_bytes.len() as u32,
            signature_count: 1,
            reserved: [0; 3],
        };
        (
            ArchiveV2HotBlockBlob {
                header: ArchiveV2HotBlockHeader {
                    slot: 432001,
                    parent_slot: 432000,
                    blockhash_id: 2,
                    previous_blockhash_id: 1,
                    block_time: Some(1),
                    block_height: Some(2),
                    rewards: Some(ArchiveV2HotRewards {
                        num_partitions: None,
                        decoded: vec![reward(11)],
                    }),
                },
                tx_count: 1,
                tx_rows: vec![tx],
                message_bytes,
                metadata_bytes,
            },
            ArchiveV2HotBlockIndexRow {
                block_id: 1,
                slot: 432001,
                compressed_offset: 0,
                compressed_len: 1,
                uncompressed_len: 1,
                tx_count: 1,
                first_tx_ordinal: 0,
                first_signature_ordinal: 0,
                signature_count: 1,
            },
        )
    }

    fn tables() -> BTreeMap<String, Vec<u8>> {
        let mut out = BTreeMap::new();
        out.insert(
            "registry.bin".into(),
            (1u8..=11).flat_map(|v| [v; 32]).collect(),
        );
        out.insert(
            "blockhash_registry.bin".into(),
            (100u8..=102).flat_map(|v| [v; 32]).collect(),
        );
        let mut tail = vec![];
        for (byte, slot) in [(98u8, 431998u64), (99, 431999)] {
            tail.extend_from_slice(&[byte; 32]);
            tail.extend_from_slice(&slot.to_le_bytes());
        }
        out.insert("prev_blockhash_tail.bin".into(), tail);
        let mut votes = vec![0; 4 * 65];
        votes[3 * 65] = 3;
        votes[3 * 65 + 1..3 * 65 + 33].fill(55);
        votes[3 * 65 + 33..4 * 65].fill(56);
        out.insert("vote_hash_registry.bin".into(), votes);
        out
    }

    fn sources(tables: &BTreeMap<String, Vec<u8>>) -> Vec<NamedSourceObject> {
        let mut out: Vec<_> = tables
            .iter()
            .map(|(name, data)| NamedSourceObject {
                name: name.clone(),
                identity: SourceObjectIdentity {
                    length: data.len() as u64,
                    etag: format!("\"{name}-v1\""),
                },
            })
            .collect();
        out.push(NamedSourceObject {
            name: "archive-v2-blocks.zstd".into(),
            identity: SourceObjectIdentity {
                length: 1,
                etag: "\"hot-v1\"".into(),
            },
        });
        out.push(NamedSourceObject {
            name: "signatures.bin".into(),
            identity: SourceObjectIdentity {
                length: 64,
                etag: "\"sig-v1\"".into(),
            },
        });
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    #[test]
    fn complete_collector_covers_metadata_lookup_log_reward_and_vote_columns() {
        let (block, hot) = fixture();
        let refs = collect(&block, &hot, MESSAGE_CURRENT, METADATA_CURRENT).unwrap();
        assert_eq!(refs.pubkeys, (1..=11).collect::<Vec<_>>());
        assert_eq!(refs.blockhashes, vec![-2, 1, 2]);
        assert_eq!(refs.signature_counts, vec![1]);
        assert_eq!(
            refs.votes,
            vec![VoteReference {
                block_id: 3,
                bank_hash: true,
                block_id_hash: true
            }]
        );
        let json = serde_json::to_vec(&refs).unwrap();
        assert!(json.len() < MAX_REQUEST_BYTES);
        assert_eq!(
            serde_json::from_slice::<SlotReferences>(&json).unwrap(),
            refs
        );
    }

    #[test]
    fn collector_rejects_raw_fallback_bad_rows_and_signature_disagreement() {
        for flag in [
            ARCHIVE_V2_TX_FLAG_TX_RAW_FALLBACK,
            ARCHIVE_V2_TX_FLAG_METADATA_RAW_FALLBACK,
        ] {
            let (mut block, hot) = fixture();
            block.tx_rows[0].flags |= flag;
            assert!(collect(&block, &hot, 0, 0).is_err());
        }
        let (mut block, hot) = fixture();
        block.tx_rows[0].message_len = u32::MAX;
        assert!(collect(&block, &hot, 0, 0).is_err());
        let (mut block, hot) = fixture();
        block.tx_rows[0].signature_count = 2;
        assert!(collect(&block, &hot, 0, 0).is_err());
        let (mut block, hot) = fixture();
        block.tx_rows[0].reserved[0] = 1;
        assert!(collect(&block, &hot, 0, 0).is_err());
    }

    #[test]
    fn reference_validation_rejects_missing_header_hash_duplicates_and_empty_votes() {
        let (block, hot) = fixture();
        let good = collect(&block, &hot, 0, 0).unwrap();
        let mut refs = good.clone();
        refs.blockhashes.pop();
        assert!(refs.validate(&hot).is_err());
        let mut refs = good.clone();
        refs.pubkeys.push(1);
        assert!(refs.validate(&hot).is_err());
        let mut refs = good.clone();
        refs.votes[0].bank_hash = false;
        refs.votes[0].block_id_hash = false;
        assert!(refs.validate(&hot).is_err());
        let mut refs = good;
        refs.pubkeys = vec![1; MAX_FAMILY_IDS + 1];
        assert!(refs.validate(&hot).is_err());
    }

    #[test]
    fn local_resolution_batches_tables_and_never_reads_signature_bytes() {
        let (block, hot) = fixture();
        let refs = collect(&block, &hot, 0, 0).unwrap();
        let data = tables();
        let objects = sources(&data);
        let mut calls = Vec::new();
        let resolved = resolve(
            &refs,
            &hot,
            &objects,
            TailSchema::HashAndSlot40,
            |name, offset, len| {
                assert_ne!(name, "signatures.bin");
                assert!(len <= MAX_TABLE_WINDOW);
                calls.push((name.to_string(), offset, len));
                Ok(data[name][offset as usize..offset as usize + len].to_vec())
            },
        )
        .unwrap();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[0], ("registry.bin".into(), 0, 11 * 32));
        assert_eq!(resolved.blockhash, [102; 32]);
        assert_eq!(resolved.previous_blockhash, [101; 32]);
        assert_eq!(resolved.pubkeys[0].pubkey, [1; 32]);
        assert_eq!(resolved.vote_hashes[0].bank_hash, Some([55; 32]));
        let locator = LocatorV1 {
            version: 1,
            source_prefix: "compact-v2/test".into(),
            generation: "g1".into(),
            epoch: 1,
            hot: hot.into(),
            parent_slot: refs.parent_slot,
            blockhash: resolved.blockhash,
            previous_blockhash: resolved.previous_blockhash,
            message_schema: 0,
            metadata_schema: 0,
            blocks: identity(&objects, "archive-v2-blocks.zstd")
                .unwrap()
                .clone(),
            signatures: identity(&objects, "signatures.bin").unwrap().clone(),
        };
        let value = resolved.into_resolution(&refs, locator, objects).unwrap();
        let checked = crate::slot_resolution::decode_checked(
            &crate::slot_resolution::encode(&value).unwrap(),
        )
        .unwrap();
        validate_resolution(&checked, &refs).unwrap();
        let mut subset = refs.clone();
        subset.pubkeys.pop();
        assert!(validate_resolution(&checked, &subset).is_err());
        assert!(checked.validate_membership(&[999], &[], &[]).is_err());
        assert!(
            checked
                .validate_reference_header(
                    refs.slot,
                    refs.parent_slot,
                    1,
                    2,
                    &refs.signature_counts
                )
                .is_err()
        );
    }

    #[test]
    fn legacy_first_block_uses_actual_tail_hash_and_checks_its_slot() {
        let (mut block, mut hot) = fixture();
        block.header.slot = 432000;
        hot.slot = 432000;
        hot.block_id = 0;
        block.header.parent_slot = 431999;
        block.header.blockhash_id = 0;
        block.header.previous_blockhash_id = 0;
        let refs = collect(&block, &hot, 0, 0).unwrap();
        assert!(refs.blockhashes.contains(&-1));
        let data = tables();
        let objects = sources(&data);
        let resolved = resolve(
            &refs,
            &hot,
            &objects,
            TailSchema::HashAndSlot40,
            |name, offset, len| Ok(data[name][offset as usize..offset as usize + len].to_vec()),
        )
        .unwrap();
        assert_eq!(resolved.blockhash, [100; 32]);
        assert_eq!(resolved.previous_blockhash, [99; 32]);
        let mut wrong = refs;
        wrong.parent_slot = 431998;
        assert!(
            resolve(
                &wrong,
                &hot,
                &objects,
                TailSchema::HashAndSlot40,
                |name, offset, len| Ok(data[name][offset as usize..offset as usize + len].to_vec())
            )
            .is_err()
        );
    }

    #[test]
    fn missing_vote_columns_and_short_reads_fail_closed() {
        let (block, hot) = fixture();
        let refs = collect(&block, &hot, 0, 0).unwrap();
        let mut data = tables();
        data.get_mut("vote_hash_registry.bin").unwrap()[3 * 65] = 1;
        let objects = sources(&data);
        assert!(
            resolve(
                &refs,
                &hot,
                &objects,
                TailSchema::HashAndSlot40,
                |name, offset, len| Ok(data[name][offset as usize..offset as usize + len].to_vec())
            )
            .is_err()
        );
        assert!(
            resolve(
                &refs,
                &hot,
                &objects,
                TailSchema::HashAndSlot40,
                |_, _, _| Ok(vec![])
            )
            .is_err()
        );
    }

    #[cfg(feature = "cli")]
    fn real_sample(slot: u64) {
        use blockzilla_archive_v2::{
            ArchiveV2BlockAccessBlob, BlockzillaGetBlockBundleV1,
            deserialize_archive_v2_hot_block_blob,
        };
        use blockzilla_primitives::bounded_historical_source_wincode_leb128_config;
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let input = root.join(".codex-tmp/get-block-resolution-20261121/inputs");
        let descriptor: serde_json::Value = serde_json::from_slice(
            &std::fs::read(input.join(format!("{slot}.descriptor.json"))).unwrap(),
        )
        .unwrap();
        let hot: crate::slot_resolution::ResolutionHotRow =
            serde_json::from_value(descriptor["hot_row"].clone()).unwrap();
        let hot: ArchiveV2HotBlockIndexRow = hot.into();
        let bytes = std::fs::read(input.join(format!("{slot}.bundle.wincode"))).unwrap();
        let bundle: BlockzillaGetBlockBundleV1 = wincode::config::deserialize_exact(
            &bytes,
            bounded_historical_source_wincode_leb128_config::<{ 32 * 1024 * 1024 }>(),
        )
        .unwrap();
        let decoded =
            zstd::bulk::decompress(&bundle.hot_block, hot.uncompressed_len as usize).unwrap();
        let block = deserialize_archive_v2_hot_block_blob(&decoded).unwrap();
        let access: ArchiveV2BlockAccessBlob = wincode::config::deserialize_exact(
            bundle.block_access.as_ref().unwrap(),
            bounded_historical_source_wincode_leb128_config::<{ 32 * 1024 * 1024 }>(),
        )
        .unwrap();
        let refs = collect(&block, &hot, 0, 0).unwrap();
        assert_eq!(
            refs.pubkeys,
            access.pubkeys.iter().map(|v| v.id).collect::<Vec<_>>(),
            "slot{slot} pubkey IDs"
        );
        assert_eq!(
            refs.blockhashes,
            access.blockhashes.iter().map(|v| v.id).collect::<Vec<_>>(),
            "slot{slot} hash IDs"
        );
        assert_eq!(refs.signature_counts, access.signature_counts);
        assert_eq!(
            refs.votes,
            access
                .vote_hashes
                .iter()
                .map(|v| VoteReference {
                    block_id: v.block_id,
                    bank_hash: v.bank_hash.is_some(),
                    block_id_hash: v.block_id_hash.is_some()
                })
                .collect::<Vec<_>>()
        );
        // Sparse local read facade: only original access dictionary records are available.
        let metadata:serde_json::Value=serde_json::from_slice(&std::fs::read(root.join("reports/stream-getblock-architecture-20261122/storage-current-object-metadata.json")).unwrap()).unwrap();
        let mut objects = Vec::new();
        for row in metadata["heads"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["epoch"] == 1089 && row["status"] == 200)
        {
            objects.push(NamedSourceObject {
                name: row["file"].as_str().unwrap().into(),
                identity: SourceObjectIdentity {
                    length: row["size"].as_u64().unwrap(),
                    etag: row["etag"].as_str().unwrap().into(),
                },
            });
        }
        objects.sort_by(|a, b| a.name.cmp(&b.name));
        let keys: BTreeMap<_, _> = access
            .pubkeys
            .iter()
            .map(|v| (u64::from(v.id) - 1, v.pubkey))
            .collect();
        let hashes: BTreeMap<_, _> = access
            .blockhashes
            .iter()
            .map(|v| (v.id, v.blockhash))
            .collect();
        let mut reads = 0;
        let resolved = resolve(
            &refs,
            &hot,
            &objects,
            TailSchema::HashAndSlot40,
            |name, offset, len| {
                reads += 1;
                assert_ne!(name, "signatures.bin");
                assert!(len <= MAX_TABLE_WINDOW);
                let mut out = vec![0; len];
                match name {
                    "registry.bin" => {
                        for (id, value) in &keys {
                            let at = *id * 32;
                            if at >= offset && at + 32 <= offset + len as u64 {
                                out[(at - offset) as usize..(at - offset + 32) as usize]
                                    .copy_from_slice(value);
                            }
                        }
                    }
                    "blockhash_registry.bin" => {
                        for (id, value) in &hashes {
                            if *id < 0 {
                                continue;
                            }
                            let at = *id as u64 * 32;
                            if at >= offset && at + 32 <= offset + len as u64 {
                                out[(at - offset) as usize..(at - offset + 32) as usize]
                                    .copy_from_slice(value);
                            }
                        }
                    }
                    _ => return Err(format!("unexpected real sample table {name}")),
                }
                Ok(out)
            },
        )
        .unwrap();
        assert_eq!(resolved.blockhash, access.blockhash);
        assert_eq!(resolved.previous_blockhash, access.previous_blockhash);
        let locator = LocatorV1 {
            version: 1,
            source_prefix: descriptor["source_prefix"].as_str().unwrap().into(),
            generation: descriptor["generation"].as_str().unwrap().into(),
            epoch: 1089,
            hot: hot.into(),
            parent_slot: block.header.parent_slot,
            blockhash: resolved.blockhash,
            previous_blockhash: resolved.previous_blockhash,
            message_schema: 0,
            metadata_schema: 0,
            blocks: identity(&objects, "archive-v2-blocks.zstd")
                .unwrap()
                .clone(),
            signatures: identity(&objects, "signatures.bin").unwrap().clone(),
        };
        let value = resolved.into_resolution(&refs, locator, objects).unwrap();
        let expected = wincode::config::serialize(
            &(&access.pubkeys, &access.blockhashes, &access.vote_hashes),
            wincode_leb128_config(),
        )
        .unwrap();
        assert_eq!(value.access_suffix(), expected);
        let checked = crate::slot_resolution::decode_checked(
            &crate::slot_resolution::encode(&value).unwrap(),
        )
        .unwrap();
        validate_resolution(&checked, &refs).unwrap();
        println!(
            "slot={slot} pubkeys={} hashIDs={} tableReads={reads} referenceJSON={} resolutionBytes={}",
            refs.pubkeys.len(),
            refs.blockhashes.len(),
            serde_json::to_vec(&refs).unwrap().len(),
            crate::slot_resolution::encode(&value).unwrap().len()
        );
    }

    #[cfg(feature = "cli")]
    #[test]
    #[ignore = "requires saved original session bundles; explicit fixture run"]
    fn real_470555971() {
        real_sample(470555971)
    }
    #[cfg(feature = "cli")]
    #[test]
    #[ignore = "requires saved original session bundles; explicit fixture run"]
    fn real_470663944() {
        real_sample(470663944)
    }
    #[cfg(feature = "cli")]
    #[test]
    #[ignore = "requires saved original session bundles; explicit fixture run"]
    fn real_470771932() {
        real_sample(470771932)
    }
    #[cfg(feature = "cli")]
    #[test]
    #[ignore = "requires saved original session bundles; explicit fixture run"]
    fn real_470879999() {
        real_sample(470879999)
    }
}
