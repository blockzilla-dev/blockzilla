//! Adapt one checked native Bank frame to the existing Base64 JSON renderer.
//!
//! The caller pins `metadata.source` to BZ_FOUNDATION_RECENT_SOURCE. This
//! adapter binds that metadata, the original payload and its exact root proof.
//! No native payload or binary response is re-encoded here.

use super::*;
use blockzilla_archive_v2::{
    ARCHIVE_V2_TX_FLAG_HAS_ERROR, ArchiveV2BlockAccessVoteHash,
    deserialize_archive_v2_hot_block_blob_borrowed_current_with_preallocation_limit,
};
use blockzilla_bank_stream_v2 as v2;
use bytes::Bytes;
use std::borrow::Cow;

const MAX_ROOT_BYTES: usize = 4096;
const MAX_HOT_BYTES: usize = 32 * 1024 * 1024;
const MAX_TRANSACTIONS: u32 = 65_536;
const MAX_SIGNATURE_BYTES: usize = 8 * 1024 * 1024;
const MAX_REGISTRY_BYTES: usize = 4 * 1024 * 1024;
const INDEX_BYTES: usize = 36 + 52;

pub(super) fn decode(
    source: &WorkerSource,
    slot: u64,
    frame: Vec<u8>,
    metadata: &foundation_first::RecentMetadata,
    root: &[u8],
) -> std::result::Result<FetchedHotBlock, String> {
    let started = now_ms();
    if frame.len() > v2::MAX_FRAME || root.is_empty() || root.len() > MAX_ROOT_BYTES {
        return Err("native payload or root exceeds its byte limit".into());
    }
    // Moving a Vec into Bytes retains its allocation. Only the small root
    // header value needs a copy for the shared owned transport admission API.
    let payload = v2::decode(Bytes::from(frame))
        .map_err(|error| format!("invalid native payload frame: {error}"))?;
    let rooted = v2::decode(Bytes::copy_from_slice(root))
        .map_err(|error| format!("invalid native root frame: {error}"))?;
    validate_binding(&payload, &rooted, slot, metadata)?;

    let blob = object(&payload, "archive-v2-blocks.zstd")?;
    let (flags, row) = index(
        object(&payload, "archive-v2-blocks.index")?,
        blob.len(),
        slot,
    )?;
    let decoded = hot_bytes(blob, flags, &row)?;
    let decoded_len = decoded.len();
    let block = owned_hot_block(&decoded, &row, &payload)?;
    // Release the decompression allocation before building the access tables.
    // In raw mode this is only a borrowed view into the original frame.
    drop(decoded);
    let access = access(&payload, &row, &block)?;
    source.record_elapsed(
        "native_block_decode",
        started,
        decoded_len as u64,
        if flags == 2 {
            "raw_current"
        } else {
            "zstd_current"
        },
        None,
    );
    Ok(FetchedHotBlock {
        epoch: epoch_for_slot(slot),
        index_row: ArchiveV2GetBlockIndexRow {
            block_offset: 0,
            block_len: row.compressed_len,
            access_offset: 0,
            access_len: 0,
        },
        row,
        decoded_len,
        block,
        access: Some(FetchedAccess::Full(access)),
        message_schema: MessageSchema::Current,
        metadata_schema: MetadataSchema::Current,
    })
}

fn validate_binding(
    payload: &v2::Frame,
    root: &v2::Frame,
    slot: u64,
    metadata: &foundation_first::RecentMetadata,
) -> std::result::Result<(), String> {
    let event = &payload.envelope.event;
    let bank = &event.bank;
    let identity = &payload.source;
    let declared = &metadata.source;
    if event.kind != "block"
        || metadata.version != 1
        || metadata.commitment != "finalized"
        || bank.slot != slot
        || metadata.slot != slot
        || metadata.bank_id != bank.bank_id
        || metadata.parent_slot != bank.parent_slot
        || metadata.blockhash != base58_32(&bank.blockhash)
        || metadata.parent_blockhash != base58_32(&bank.parent_blockhash)
        || metadata.frame_sha256 != payload.sha256
        || metadata.cursor != payload.cursor
        || declared.genesis_hash != identity.genesis_hash
        || declared.node_identity != identity.node_identity
        || declared.agave_revision != identity.agave_revision
        || declared.session_id != identity.session_id
    {
        return Err("native payload differs from its finalized metadata".into());
    }
    if root.source != payload.source
        || root.envelope.event.kind != "root"
        || root.envelope.event.commitment.as_deref() != Some("finalized")
        || root.envelope.event.sequence <= event.sequence
        || root.envelope.event.source_sequence < event.source_sequence
    {
        return Err("native root source, finality or ordering differs from its payload".into());
    }
    root.envelope
        .event
        .matches_payload(payload)
        .map_err(|error| format!("native root does not bind the exact payload: {error}"))?;
    if payload.envelope.marker["epoch"].as_u64() != Some(epoch_for_slot(slot))
        || payload.envelope.marker["produced_blocks"][0]["block_id"].as_u64() != Some(0)
    {
        return Err("native payload epoch or local block ordinal is invalid".into());
    }
    Ok(())
}

fn optional_object<'a>(
    frame: &'a v2::Frame,
    name: &str,
) -> std::result::Result<Option<&'a [u8]>, String> {
    let Some(entry) = frame
        .envelope
        .objects
        .iter()
        .find(|entry| entry.path == name)
    else {
        return Ok(None);
    };
    let meta = u32_at(&frame.wire, 8)? as usize;
    let start = (16 + meta)
        .checked_add(entry.offset)
        .ok_or_else(|| "native object offset overflows".to_string())?;
    let end = start
        .checked_add(entry.bytes)
        .ok_or_else(|| "native object length overflows".to_string())?;
    frame
        .wire
        .get(start..end)
        .map(Some)
        .ok_or_else(|| format!("native object {name} is outside its frame"))
}

fn object<'a>(frame: &'a v2::Frame, name: &str) -> std::result::Result<&'a [u8], String> {
    optional_object(frame, name)?.ok_or_else(|| format!("native object {name} is missing"))
}

fn u32_at(bytes: &[u8], offset: usize) -> std::result::Result<u32, String> {
    bytes
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| "native u32 field is truncated".into())
}

fn u64_at(bytes: &[u8], offset: usize) -> std::result::Result<u64, String> {
    bytes
        .get(offset..offset + 8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| "native u64 field is truncated".into())
}

fn index(
    bytes: &[u8],
    blob_len: usize,
    slot: u64,
) -> std::result::Result<(u32, ArchiveV2HotBlockIndexRow), String> {
    if bytes.len() != INDEX_BYTES
        || bytes.get(..8) != Some(b"BZV2HIX1")
        || u32_at(bytes, 8)? != 1
        || u64_at(bytes, 12)? != 1
        || u64_at(bytes, 20)? != blob_len as u64
    {
        return Err("native hot index header is not one complete local block".into());
    }
    // Bytes 28..32 record encoder effort, not a decoding or dictionary ID.
    // The flags select raw/zstd; the frame itself defines zstd parameters.
    let flags = u32_at(bytes, 32)?;
    if flags != 0 && flags != 2 {
        return Err("native hot index uses an unsupported encoding or dictionary".into());
    }
    let row = ArchiveV2HotBlockIndexRow {
        block_id: u32_at(bytes, 36)?,
        slot: u64_at(bytes, 40)?,
        compressed_offset: u64_at(bytes, 48)?,
        compressed_len: u32_at(bytes, 56)?,
        uncompressed_len: u32_at(bytes, 60)?,
        tx_count: u32_at(bytes, 64)?,
        first_tx_ordinal: u64_at(bytes, 68)?,
        first_signature_ordinal: u64_at(bytes, 76)?,
        signature_count: u32_at(bytes, 84)?,
    };
    if row.block_id != 0
        || row.slot != slot
        || row.compressed_offset != 0
        || row.compressed_len as usize != blob_len
        || row.compressed_len == 0
        || row.uncompressed_len == 0
        || row.uncompressed_len as usize > MAX_HOT_BYTES
        || row.tx_count > MAX_TRANSACTIONS
        || row.first_tx_ordinal != 0
        || row.first_signature_ordinal != 0
    {
        return Err("native hot index identity, range or limits are invalid".into());
    }
    Ok((flags, row))
}

fn hot_bytes<'a>(
    bytes: &'a [u8],
    flags: u32,
    row: &ArchiveV2HotBlockIndexRow,
) -> std::result::Result<Cow<'a, [u8]>, String> {
    if flags == 2 {
        if bytes.len() != row.uncompressed_len as usize {
            return Err("native raw hot length differs from its index".into());
        }
        return Ok(Cow::Borrowed(bytes));
    }
    let mut decoder = StreamingDecoder::new_with_max_window_size(bytes, MAX_HOT_BYTES as u64)
        .map_err(|error| format!("native zstd header is invalid: {error}"))?;
    let mut decoded = Vec::with_capacity((row.uncompressed_len as usize).min(1024 * 1024));
    std::io::Read::by_ref(&mut decoder)
        .take(u64::from(row.uncompressed_len) + 1)
        .read_to_end(&mut decoded)
        .map_err(|error| format!("native zstd decode failed: {error}"))?;
    if decoded.len() != row.uncompressed_len as usize || !decoder.into_inner().is_empty() {
        return Err("native zstd length or trailing bytes differ from its index".into());
    }
    Ok(Cow::Owned(decoded))
}

fn owned_hot_block(
    bytes: &[u8],
    row: &ArchiveV2HotBlockIndexRow,
    payload: &v2::Frame,
) -> std::result::Result<ArchiveV2HotBlockBlob, String> {
    let block = deserialize_archive_v2_hot_block_blob_borrowed_current_with_preallocation_limit::<
        1_048_576,
    >(bytes)
    .map_err(|error| format!("native current hot block is invalid: {error}"))?;
    let bank = &payload.envelope.event.bank;
    if block.header.slot != bank.slot
        || block.header.parent_slot != bank.parent_slot
        || block.header.block_height != payload.envelope.event.block_height
        || block.header.blockhash_id != 0
        || block.header.previous_blockhash_id != 0
        || block.tx_count != row.tx_count
        || block.tx_rows_len() != row.tx_count as usize
    {
        return Err("native hot block identity or transaction count differs from its frame".into());
    }
    let mut tx_rows = Vec::with_capacity(row.tx_count as usize);
    let (mut message_end, mut metadata_end, mut signatures) = (0usize, 0usize, 0u32);
    for (ordinal, tx) in block.tx_rows().enumerate() {
        if tx.tx_index as usize != ordinal
            || tx.reserved != [0; 3]
            || tx.flags & !2047 != 0
            || tx.flags
                & (ARCHIVE_V2_TX_FLAG_TX_RAW_FALLBACK | ARCHIVE_V2_TX_FLAG_METADATA_RAW_FALLBACK)
                != 0
            || tx.message_offset as usize != message_end
            || tx.metadata_offset as usize != metadata_end
            || tx.signature_count == 0
            || (tx.flags & ARCHIVE_V2_TX_FLAG_HAS_METADATA == 0
                && (tx.metadata_len != 0 || tx.flags & ARCHIVE_V2_TX_FLAG_HAS_ERROR != 0))
        {
            return Err("native transaction row, flags or contiguous regions are invalid".into());
        }
        message_end = message_end
            .checked_add(tx.message_len as usize)
            .ok_or_else(|| "native message region overflows".to_string())?;
        metadata_end = metadata_end
            .checked_add(tx.metadata_len as usize)
            .ok_or_else(|| "native metadata region overflows".to_string())?;
        if message_end > block.message_bytes.len() || metadata_end > block.metadata_bytes.len() {
            return Err("native transaction region is outside its hot block".into());
        }
        signatures = signatures
            .checked_add(u32::from(tx.signature_count))
            .ok_or_else(|| "native signature count overflows".to_string())?;
        tx_rows.push(tx);
    }
    if message_end != block.message_bytes.len()
        || metadata_end != block.metadata_bytes.len()
        || signatures != row.signature_count
    {
        return Err(
            "native transaction regions or signatures have trailing or missing bytes".into(),
        );
    }
    // This renderer owns the lanes and markers. Materialize them at this boundary.
    Ok(ArchiveV2HotBlockBlob {
        tx_count: block.tx_count,
        tx_rows,
        message_bytes: block.message_bytes.to_vec(),
        metadata_bytes: block.metadata_bytes.to_vec(),
        header: block.header,
        consensus_block_id: block.consensus_block_id,
        block_markers: block.block_markers.to_vec(),
    })
}

fn access(
    payload: &v2::Frame,
    row: &ArchiveV2HotBlockIndexRow,
    block: &ArchiveV2HotBlockBlob,
) -> std::result::Result<ArchiveV2BlockAccessBlob, String> {
    let bank = &payload.envelope.event.bank;
    let registry = object(payload, "registry.bin")?;
    let blockhashes = object(payload, "blockhash_registry.bin")?;
    let tail = object(payload, "prev_blockhash_tail.bin")?;
    let signatures = object(payload, "signatures.bin")?;
    if registry.len() > MAX_REGISTRY_BYTES || !registry.len().is_multiple_of(32) {
        return Err("native account registry length exceeds its limit or record width".into());
    }
    if blockhashes != bank.blockhash
        || tail.len() != 40
        || tail[..32] != bank.parent_blockhash
        || u64_at(tail, 32)? != bank.parent_slot
    {
        return Err("native current hash or predecessor tail differs from its Bank".into());
    }
    let signature_len = (row.signature_count as usize)
        .checked_mul(64)
        .filter(|length| *length <= MAX_SIGNATURE_BYTES)
        .ok_or_else(|| "native signature file exceeds its byte limit".to_string())?;
    if signatures.len() != signature_len {
        return Err("native signature file length differs from its hot index".into());
    }
    let pubkeys = registry
        .chunks_exact(32)
        .enumerate()
        .map(|(index, bytes)| ArchiveV2BlockAccessPubkey {
            id: (index + 1) as u32,
            pubkey: bytes
                .try_into()
                .expect("native registry record width checked"),
        })
        .collect();
    let mut vote_hashes = Vec::new();
    if let Some(votes) = optional_object(payload, "vote_hash_registry.bin")? {
        if votes.len() > MAX_REGISTRY_BYTES || !votes.len().is_multiple_of(65) {
            return Err("native vote hash registry length is invalid".into());
        }
        vote_hashes.reserve(votes.len() / 65);
        for (block_id, bytes) in votes.chunks_exact(65).enumerate() {
            if bytes[0] & !3 != 0 {
                return Err("native vote hash registry flags are invalid".into());
            }
            vote_hashes.push(ArchiveV2BlockAccessVoteHash {
                block_id: block_id as u32,
                bank_hash: (bytes[0] & 1 != 0).then(|| bytes[1..33].try_into().unwrap()),
                block_id_hash: (bytes[0] & 2 != 0).then(|| bytes[33..65].try_into().unwrap()),
            });
        }
    }
    let access = ArchiveV2BlockAccessBlob {
        version: WINCODE_ARCHIVE_V2_BLOCK_ACCESS_VERSION,
        flags: 0,
        blockhash: bank.blockhash,
        previous_blockhash: bank.parent_blockhash,
        signature_counts: block.tx_rows.iter().map(|tx| tx.signature_count).collect(),
        signatures: signatures.to_vec(),
        pubkeys,
        // Native produced-only registries use ID0 for this block and ID-1
        // for the one predecessor carried by the independent tail.
        blockhashes: vec![
            ArchiveV2BlockAccessBlockhash {
                id: -1,
                blockhash: bank.parent_blockhash,
            },
            ArchiveV2BlockAccessBlockhash {
                id: 0,
                blockhash: bank.blockhash,
            },
        ],
        vote_hashes,
    };
    validate_access_blob(&access, row)?;
    Ok(access)
}

#[cfg(test)]
mod tests {
    use super::*;
    use blockzilla_archive_v2::{
        ArchiveV2HotBlockHeader, ArchiveV2HotInstruction, ArchiveV2HotLegacyMessage,
        ArchiveV2HotRewards, ArchiveV2HotV1Message,
    };
    use blockzilla_compact::{CompactMessageHeader, CompactReward};
    use futures_util::FutureExt;

    fn source() -> WorkerSource {
        WorkerSource {
            archive_prefix: String::new(),
            backend: ArchiveBackend::S3(S3Source {
                endpoint: String::new(),
                host: String::new(),
                bucket: String::new(),
                region: String::new(),
                access_key: String::new(),
                secret_key: String::new(),
            }),
            profile: None,
            backend_read: BackendReadTracker::default(),
            storage_metrics: StorageMetrics::default(),
            stored_compact: true,
            use_dense_slot_index: true,
            cache: None,
            object_sizes: Rc::new(RefCell::new(BTreeMap::new())),
            signature_locator: None,
            message_schema_overrides: BTreeMap::new(),
            metadata_schema_override: None,
            cache_write_bytes: Rc::new(Cell::new(0)),
            resolution: None,
            native_reader: None,
            slot_bundle: None,
            foundation_lookup: None,
            foundation_prepared: Rc::new(RefCell::new(None)),
        }
    }

    // A complete standard Zstandard frame with one last, uncompressed block.
    // This exercises the actual ruzstd path without adding a native zstd crate.
    fn zstd_raw_block(bytes: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0xa0];
        frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        let block_header = ((bytes.len() as u32) << 3) | 1;
        frame.extend_from_slice(&block_header.to_le_bytes()[..3]);
        frame.extend_from_slice(bytes);
        frame
    }

    fn fixture(
        compressed: bool,
        version: u8,
        edit: impl FnOnce(&mut Vec<(&'static str, Vec<u8>)>),
    ) -> (v2::Frame, foundation_first::RecentMetadata, v2::Frame) {
        let bank = v2::BankIdentity {
            slot: 432_002,
            bank_id: 7,
            blockhash: [11; 32],
            parent_slot: 432_001,
            parent_blockhash: [10; 32],
        };
        let header = CompactMessageHeader {
            num_required_signatures: 1,
            num_readonly_signed_accounts: 0,
            num_readonly_unsigned_accounts: 1,
        };
        let keys = vec![CompactPubkey::Id(1), CompactPubkey::Id(2)];
        let instructions = vec![ArchiveV2HotInstruction {
            program_id_index: 1,
            accounts: vec![0],
            data: ArchiveV2HotInstructionData::Raw(vec![1, 2, 3]),
        }];
        let message = if version == 1 {
            ArchiveV2HotMessagePayload::V1(ArchiveV2HotV1Message {
                header,
                account_keys: keys,
                recent_blockhash: OwnedCompactRecentBlockhash::Id(-1),
                instructions,
                config: CompactTransactionConfig {
                    priority_fee: Some(0),
                    ..Default::default()
                },
            })
        } else {
            ArchiveV2HotMessagePayload::Legacy(ArchiveV2HotLegacyMessage {
                header,
                account_keys: keys,
                recent_blockhash: OwnedCompactRecentBlockhash::Id(-1),
                instructions,
            })
        };
        let message_bytes = wincode::config::serialize(&message, wincode_leb128_config()).unwrap();
        let metadata_bytes = wincode::config::serialize(
            &CompactMetaV1 {
                err: Some(StoredTransactionError::InsufficientFundsForFee),
                fee: 5000,
                pre_balances: vec![10_000, 1],
                post_balances: vec![5000, 1],
                inner_instructions: None,
                logs: None,
                pre_token_balances: vec![],
                post_token_balances: vec![],
                rewards: vec![],
                loaded_writable_addresses: vec![],
                loaded_readonly_addresses: vec![],
                return_data: None,
                compute_units_consumed: Some(10),
                cost_units: Some(11),
            },
            wincode_leb128_config(),
        )
        .unwrap();
        let block = ArchiveV2HotBlockBlob {
            header: ArchiveV2HotBlockHeader {
                slot: bank.slot,
                parent_slot: bank.parent_slot,
                blockhash_id: 0,
                previous_blockhash_id: 0,
                block_time: Some(1_700_000_000),
                block_height: Some(101),
                rewards: Some(ArchiveV2HotRewards {
                    num_partitions: None,
                    decoded: vec![
                        CompactReward {
                            pubkey: CompactPubkey::Id(1),
                            lamports: -10,
                            post_balance: 990,
                            reward_type: 5,
                            commission: None,
                        },
                        CompactReward {
                            pubkey: CompactPubkey::Id(2),
                            lamports: -20,
                            post_balance: 980,
                            reward_type: 6,
                            commission: None,
                        },
                    ],
                }),
            },
            tx_count: 1,
            tx_rows: vec![ArchiveV2HotTxRow {
                tx_index: 0,
                flags: ARCHIVE_V2_TX_FLAG_HAS_METADATA | ARCHIVE_V2_TX_FLAG_HAS_ERROR,
                message_offset: 0,
                message_len: message_bytes.len() as u32,
                metadata_offset: 0,
                metadata_len: metadata_bytes.len() as u32,
                signature_count: 1,
                reserved: [0; 3],
            }],
            message_bytes,
            metadata_bytes,
            consensus_block_id: Some([22; 32]),
            block_markers: vec![vec![1, 2, 3]],
        };
        let raw = wincode::config::serialize(&block, wincode_leb128_config()).unwrap();
        let blob = if compressed {
            zstd_raw_block(&raw)
        } else {
            raw.clone()
        };
        let mut index = b"BZV2HIX1".to_vec();
        index.extend_from_slice(&1u32.to_le_bytes());
        index.extend_from_slice(&1u64.to_le_bytes());
        index.extend_from_slice(&(blob.len() as u64).to_le_bytes());
        index.extend_from_slice(&(if compressed { 1i32 } else { 0i32 }).to_le_bytes());
        index.extend_from_slice(&(if compressed { 0u32 } else { 2u32 }).to_le_bytes());
        index.extend_from_slice(&0u32.to_le_bytes());
        index.extend_from_slice(&bank.slot.to_le_bytes());
        index.extend_from_slice(&0u64.to_le_bytes());
        index.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        index.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        index.extend_from_slice(&1u32.to_le_bytes());
        index.extend_from_slice(&0u64.to_le_bytes());
        index.extend_from_slice(&0u64.to_le_bytes());
        index.extend_from_slice(&1u32.to_le_bytes());
        let mut tail = bank.parent_blockhash.to_vec();
        tail.extend_from_slice(&bank.parent_slot.to_le_bytes());
        let mut votes = vec![3];
        votes.extend_from_slice(&[31; 32]);
        votes.extend_from_slice(&[32; 32]);
        let mut files = vec![
            ("DIRECT-AGAVE-NORMALIZED.v1.json", b"{}".to_vec()),
            ("archive-v2-blocks.index", index),
            ("archive-v2-blocks.zstd", blob),
            ("archive-v2-meta.wincode", vec![]),
            ("available-poh.wincode", vec![]),
            ("registry.bin", [[41; 32], [42; 32]].concat()),
            ("blockhash_registry.bin", bank.blockhash.to_vec()),
            ("prev_blockhash_tail.bin", tail),
            ("signatures.bin", vec![77; 64]),
            ("vote_hash_registry.bin", votes),
        ];
        edit(&mut files);
        let identity = v2::SourceIdentity {
            genesis_hash: base58_32(&[5; 32]),
            node_identity: base58_32(&[6; 32]),
            agave_revision: "native-worker-test".into(),
            session_id: "native-worker-test-session".into(),
        };
        let event = v2::BankEvent {
            sequence: 1,
            source_sequence: 1,
            kind: "block".into(),
            bank: bank.clone(),
            payload_sha256: v2::digest(b"original native marker"),
            payload_frame_sha256: None,
            commitment: Some("processed".into()),
            confirmation_basis: Some("operator-trusted-agave-processed-bank-callback".into()),
            block_height: Some(101),
            recent_blockhash: None,
            observed_at_unix_ms: 1000,
            reason: None,
        };
        let mut body = Vec::new();
        let objects: Vec<_> = files
            .iter()
            .map(|(path, bytes)| {
                let object = v2::Object {
                    path: (*path).into(),
                    offset: body.len(),
                    bytes: bytes.len(),
                    sha256: v2::digest(bytes),
                };
                body.extend_from_slice(bytes);
                object
            })
            .collect();
        let mut marker = serde_json::to_value(&identity).unwrap();
        marker["schema"] = json!("hivezilla-direct-agave-processed-compact-v1");
        marker["state"] = json!("COMPLETE");
        marker["source_profile"] = json!("agave-bank-callbacks-v1");
        marker["epoch"] = json!(1);
        marker["finalized"] = json!(false);
        marker["canonical"] = json!(false);
        marker["publication_ready"] = json!(false);
        let mut produced = serde_json::to_value(&bank).unwrap();
        produced["block_id"] = json!(0);
        marker["produced_blocks"] = json!([produced]);
        marker["files"] = json!(
            objects
                .iter()
                .map(|o| json!({"path":o.path,"bytes":o.bytes,"sha256":o.sha256}))
                .collect::<Vec<_>>()
        );
        let payload = v2::encode(
            v2::Envelope {
                schema: v2::ENVELOPE.into(),
                profile: v2::PROFILE.into(),
                evidence_included: false,
                marker,
                objects,
                event,
            },
            &body,
        )
        .unwrap();
        let metadata = foundation_first::RecentMetadata {
            version: 1,
            slot: bank.slot,
            blockhash: base58_32(&bank.blockhash),
            parent_slot: bank.parent_slot,
            parent_blockhash: base58_32(&bank.parent_blockhash),
            bank_id: bank.bank_id,
            source: foundation_first::RecentSource {
                genesis_hash: identity.genesis_hash.clone(),
                node_identity: identity.node_identity.clone(),
                agave_revision: identity.agave_revision.clone(),
                session_id: identity.session_id.clone(),
            },
            cursor: payload.cursor.clone(),
            frame_sha256: payload.sha256.clone(),
            commitment: "finalized".into(),
        };
        let mut event = payload.envelope.event.clone();
        event.sequence = 2;
        event.source_sequence = 2;
        event.kind = "root".into();
        event.payload_frame_sha256 = Some(payload.sha256.clone());
        event.commitment = Some("finalized".into());
        event.confirmation_basis = Some("operator-trusted-agave-rooted-bank-callback".into());
        event.recent_blockhash = Some(v2::RecentBlockhash {
            blockhash: metadata.blockhash.clone(),
            context_slot: bank.slot,
            last_valid_block_height: 251,
        });
        let root = v2::encode(
            v2::Envelope {
                schema: v2::ENVELOPE.into(),
                profile: v2::PROFILE.into(),
                evidence_included: false,
                marker: v2::control_marker(&identity, &event),
                objects: vec![],
                event,
            },
            &[],
        )
        .unwrap();
        (payload, metadata, root)
    }

    #[test]
    fn admits_raw_and_zstd_and_preserves_native_ids_parent_and_consensus_tail() {
        for compressed in [false, true] {
            let (payload, metadata, root) = fixture(compressed, 255, |_| {});
            let fetched = decode(
                &source(),
                metadata.slot,
                payload.wire.to_vec(),
                &metadata,
                &root.wire,
            )
            .unwrap();
            let access = fetched.access.as_ref().unwrap().full().unwrap();
            assert_eq!(fetched.block.header.parent_slot, 432_001);
            assert_eq!(access.pubkeys[0].id, 1);
            assert_eq!(access.pubkeys[0].pubkey, [41; 32]);
            assert_eq!(access.blockhashes[0].id, -1);
            assert_eq!(access.blockhashes[0].blockhash, [10; 32]);
            assert_eq!(access.blockhashes[1].id, 0);
            assert_eq!(access.blockhashes[1].blockhash, [11; 32]);
            assert_eq!(access.previous_blockhash, [10; 32]);
            assert_eq!(access.vote_hashes[0].bank_hash, Some([31; 32]));
            assert_eq!(access.vote_hashes[0].block_id_hash, Some([32; 32]));
            assert_eq!(fetched.block.consensus_block_id, Some([22; 32]));
            assert_eq!(fetched.block.block_markers, vec![vec![1, 2, 3]]);
        }
    }

    #[test]
    fn native_index_accepts_the_producer_compression_effort() {
        for compressed in [false, true] {
            for level in [-5i32, 1, 3] {
                let (payload, metadata, root) = fixture(compressed, 255, |files| {
                    let index = &mut files
                        .iter_mut()
                        .find(|(name, _)| *name == "archive-v2-blocks.index")
                        .unwrap()
                        .1;
                    index[28..32].copy_from_slice(&level.to_le_bytes());
                });
                let block = decode(
                    &source(),
                    metadata.slot,
                    payload.wire.to_vec(),
                    &metadata,
                    &root.wire,
                )
                .unwrap();
                assert_eq!(block.block.header.slot, metadata.slot);
            }
        }
    }

    #[test]
    fn native_legacy_and_v1_render_base64_with_exact_signature_position() {
        for version in [255, 1] {
            let source = source();
            let (payload, metadata, root) = fixture(false, version, |_| {});
            let fetched = decode(
                &source,
                metadata.slot,
                payload.wire.to_vec(),
                &metadata,
                &root.wire,
            )
            .unwrap();
            let mut writer = JsonByteWriter::with_capacity(4096);
            block_base64::stream_full_value_into(
                &source,
                &fetched,
                GetBlockConfig {
                    transaction_details: TransactionDetails::Full,
                    rewards: false,
                },
                &mut writer,
            )
            .now_or_never()
            .unwrap()
            .unwrap();
            let value: Value = serde_json::from_slice(&writer.into_inner()).unwrap();
            assert_eq!(value["previousBlockhash"], base58_32(&[10; 32]));
            let entry = &value["transactions"][0];
            assert_eq!(entry["transaction"][1], "base64");
            assert_eq!(entry["meta"]["err"], "InsufficientFundsForFee");
            let wire = BASE64
                .decode(entry["transaction"][0].as_str().unwrap())
                .unwrap();
            if version == 1 {
                assert_eq!(entry["version"], 1);
                assert_eq!(wire[0], 0x81);
                assert_eq!(&wire[wire.len() - 64..], &[77; 64]);
            } else {
                assert_eq!(&wire[..65], &[vec![1], vec![77; 64]].concat());
            }
            assert_eq!(
                source.storage_metrics.snapshot(),
                StorageSnapshot::default()
            );
        }
    }

    #[test]
    fn rejects_wrong_root_payload_source_and_nonfinalized_metadata() {
        let (payload, metadata, root) = fixture(false, 255, |_| {});
        let mut bad_root = root.envelope.clone();
        bad_root.event.payload_frame_sha256 = Some("00".repeat(32));
        let bad_root = v2::encode(bad_root, &[]).unwrap();
        assert!(
            decode(
                &source(),
                metadata.slot,
                payload.wire.to_vec(),
                &metadata,
                &bad_root.wire
            )
            .is_err()
        );
        let mut changed = metadata.clone();
        changed.source.session_id.push_str("-different");
        assert!(
            decode(
                &source(),
                metadata.slot,
                payload.wire.to_vec(),
                &changed,
                &root.wire
            )
            .is_err()
        );
        changed = metadata.clone();
        changed.commitment = "processed".into();
        assert!(
            decode(
                &source(),
                metadata.slot,
                payload.wire.to_vec(),
                &changed,
                &root.wire
            )
            .is_err()
        );
        changed = metadata.clone();
        changed.cursor.push('0');
        assert!(
            decode(
                &source(),
                metadata.slot,
                payload.wire.to_vec(),
                &changed,
                &root.wire
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_parent_tail_and_registry_geometry_even_with_valid_transport_hashes() {
        for name in ["prev_blockhash_tail.bin", "registry.bin", "signatures.bin"] {
            let (payload, metadata, root) = fixture(false, 255, |files| {
                let bytes = &mut files.iter_mut().find(|(path, _)| *path == name).unwrap().1;
                if name == "prev_blockhash_tail.bin" {
                    bytes[0] ^= 1;
                } else {
                    bytes.push(0);
                }
            });
            assert!(
                decode(
                    &source(),
                    metadata.slot,
                    payload.wire.to_vec(),
                    &metadata,
                    &root.wire
                )
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_unsupported_dictionary_and_tampered_original_frame() {
        let (payload, metadata, root) = fixture(false, 255, |files| {
            let index = &mut files
                .iter_mut()
                .find(|(name, _)| *name == "archive-v2-blocks.index")
                .unwrap()
                .1;
            index[32..36].copy_from_slice(&1u32.to_le_bytes());
        });
        assert!(
            decode(
                &source(),
                metadata.slot,
                payload.wire.to_vec(),
                &metadata,
                &root.wire
            )
            .is_err()
        );
        let (payload, metadata, root) = fixture(false, 255, |_| {});
        let mut wire = payload.wire.to_vec();
        *wire.last_mut().unwrap() ^= 1;
        assert!(decode(&source(), metadata.slot, wire, &metadata, &root.wire).is_err());
    }

    fn expected_transaction_wire(version: u8) -> Vec<u8> {
        // Independent packet layouts. Do not call the production message
        // serializer or JSON renderer to create the expected fixture bytes.
        if version == 1 {
            let mut wire = vec![0x81, 1, 0, 1, 3, 0, 0, 0];
            wire.extend_from_slice(&[10; 32]);
            wire.extend_from_slice(&[1, 2]);
            wire.extend_from_slice(&[41; 32]);
            wire.extend_from_slice(&[42; 32]);
            wire.extend_from_slice(&0u64.to_le_bytes());
            wire.extend_from_slice(&[1, 1, 3, 0, 0, 1, 2, 3]);
            wire.extend_from_slice(&[77; 64]);
            wire
        } else {
            let mut wire = vec![1];
            wire.extend_from_slice(&[77; 64]);
            wire.extend_from_slice(&[1, 0, 1, 2]);
            wire.extend_from_slice(&[41; 32]);
            wire.extend_from_slice(&[42; 32]);
            wire.extend_from_slice(&[10; 32]);
            wire.extend_from_slice(&[1, 1, 1, 0, 3, 1, 2, 3]);
            wire
        }
    }

    fn expected_block_rewards() -> Value {
        // Literal RPC names are independent of the production code mapping.
        json!([
            {"pubkey": base58_32(&[41; 32]), "lamports": -10, "postBalance": 990,
             "rewardType": "DeactivatedStake", "commission": null},
            {"pubkey": base58_32(&[42; 32]), "lamports": -20, "postBalance": 980,
             "rewardType": "VATDebit", "commission": null}
        ])
    }

    #[test]
    fn new_block_reward_types_keep_their_exact_rpc_names() {
        let source = source();
        let (payload, metadata, root) = fixture(false, 255, |_| {});
        let fetched = decode(
            &source,
            metadata.slot,
            payload.wire.to_vec(),
            &metadata,
            &root.wire,
        )
        .unwrap();
        let mut writer = JsonByteWriter::with_capacity(4096);
        block_base64::stream_full_value_into(
            &source,
            &fetched,
            GetBlockConfig {
                transaction_details: TransactionDetails::Full,
                rewards: true,
            },
            &mut writer,
        )
        .now_or_never()
        .unwrap()
        .unwrap();
        let actual: Value = serde_json::from_slice(&writer.into_inner()).unwrap();
        assert_eq!(actual["rewards"], expected_block_rewards());
        assert_eq!(
            actual["transactions"][0]["transaction"][0],
            BASE64.encode(expected_transaction_wire(255))
        );
    }

    #[test]
    fn export_native_wasm_fixture_if_requested() {
        let Some(path) = std::env::var_os("BZ_NATIVE_WASM_FIXTURE") else {
            return;
        };
        let mut variants = Vec::new();
        for (name, compressed, version) in [("raw-v1", false, 1), ("zstd-legacy", true, 255)] {
            let (payload, metadata, root) = fixture(compressed, version, |_| {});
            let wire = expected_transaction_wire(version);
            let transaction = json!({
                "transaction": [BASE64.encode(&wire), "base64"],
                "version": if version == 1 { json!(1) } else { json!("legacy") },
                "meta": {
                    "err": "InsufficientFundsForFee", "status": {"Err": "InsufficientFundsForFee"},
                    "fee": 5000, "preBalances": [10000, 1], "postBalances": [5000, 1],
                    "preTokenBalances": [], "postTokenBalances": [], "logMessages": null,
                    "innerInstructions": null, "loadedAddresses": {"writable": [], "readonly": []},
                    "rewards": null, "computeUnitsConsumed": 10, "costUnits": 11
                }
            });
            let expected = json!({"jsonrpc": "2.0", "id": 1, "result": {
                "blockhash": metadata.blockhash, "previousBlockhash": metadata.parent_blockhash,
                "parentSlot": metadata.parent_slot, "blockTime": 1700000000,
                "blockHeight": 101, "transactions": [transaction]
            }});
            let mut expected_with_rewards = expected.clone();
            expected_with_rewards["result"]["rewards"] = expected_block_rewards();
            expected_with_rewards["result"]["numRewardPartitions"] = Value::Null;
            expected_with_rewards["result"]["transactions"][0]["meta"]["rewards"] = json!([]);
            let source = source();
            let fetched = decode(
                &source,
                metadata.slot,
                payload.wire.to_vec(),
                &metadata,
                &root.wire,
            )
            .unwrap();
            let mut writer = JsonByteWriter::with_capacity(4096);
            block_base64::stream_full_value_into(
                &source,
                &fetched,
                GetBlockConfig {
                    transaction_details: TransactionDetails::Full,
                    rewards: false,
                },
                &mut writer,
            )
            .now_or_never()
            .unwrap()
            .unwrap();
            let actual: Value = serde_json::from_slice(&writer.into_inner()).unwrap();
            assert_eq!(actual, expected["result"]);
            let mut writer = JsonByteWriter::with_capacity(4096);
            block_base64::stream_full_value_into(
                &source,
                &fetched,
                GetBlockConfig {
                    transaction_details: TransactionDetails::Full,
                    rewards: true,
                },
                &mut writer,
            )
            .now_or_never()
            .unwrap()
            .unwrap();
            let actual: Value = serde_json::from_slice(&writer.into_inner()).unwrap();
            assert_eq!(actual, expected_with_rewards["result"]);
            variants.push(json!({
                "name": name, "slot": metadata.slot, "metadata": metadata,
                "frame_base64": BASE64.encode(&payload.wire), "root_base64": BASE64.encode(&root.wire),
                "expected_transaction_base64": BASE64.encode(wire), "expected_json_rpc": expected,
                "expected_json_rpc_with_rewards": expected_with_rewards
            }));
        }
        let path = std::path::PathBuf::from(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let fixture = json!({
            "schema": "blockzilla-native-finalized-worker-fixture-v1",
            "producer_generation": v2::digest(b"native-worker-finalized-fixture-producer"),
            "variants": variants,
            "scope": "Synthetic current Rust Compact V2 frames. Expected wire and RPC fields are built independently."
        });
        std::fs::write(path, serde_json::to_vec_pretty(&fixture).unwrap()).unwrap();
    }
}
