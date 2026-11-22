//! Bounded, block-local serving data. Durable blocks and signatures stay in
//! their original objects; this derived object carries no signature bytes.
use blockzilla_archive_v2::{
    ArchiveV2BlockAccessBlob, ArchiveV2BlockAccessBlockhash, ArchiveV2BlockAccessPubkey,
    ArchiveV2BlockAccessVoteHash, ArchiveV2HotBlockIndexRow,
    WINCODE_ARCHIVE_V2_BLOCK_ACCESS_VERSION,
};
use blockzilla_primitives::{bounded_wincode_leb128_config, wincode_leb128_config};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wincode::{SchemaRead, SchemaWrite};

pub const HEADER_LEN: usize = 96;
pub const MAX_RESOLUTION_BYTES: usize = 4 * 1024 * 1024;
pub const VERSION: u16 = 1;
pub const MESSAGE_CURRENT: u8 = 0;
pub const MESSAGE_MAY24: u8 = 1;
pub const METADATA_CURRENT: u8 = 0;
pub const METADATA_LEGACY: u8 = 1;
pub const MAGIC: &[u8; 8] = b"BZSLRS1!";
const BLOCKS: &str = "archive-v2-blocks.zstd";
const SIGNATURES: &str = "signatures.bin";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, SchemaRead, SchemaWrite)]
#[serde(deny_unknown_fields)]
pub struct SourceObjectIdentity {
    pub length: u64,
    pub etag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, SchemaRead, SchemaWrite)]
#[serde(deny_unknown_fields)]
pub struct NamedSourceObject {
    pub name: String,
    pub identity: SourceObjectIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, SchemaRead, SchemaWrite)]
#[serde(deny_unknown_fields)]
pub struct ResolutionHotRow {
    pub block_id: u32,
    pub slot: u64,
    pub compressed_offset: u64,
    pub compressed_len: u32,
    pub uncompressed_len: u32,
    pub tx_count: u32,
    pub first_tx_ordinal: u64,
    pub first_signature_ordinal: u64,
    pub signature_count: u32,
}

impl From<ArchiveV2HotBlockIndexRow> for ResolutionHotRow {
    fn from(row: ArchiveV2HotBlockIndexRow) -> Self {
        Self {
            block_id: row.block_id,
            slot: row.slot,
            compressed_offset: row.compressed_offset,
            compressed_len: row.compressed_len,
            uncompressed_len: row.uncompressed_len,
            tx_count: row.tx_count,
            first_tx_ordinal: row.first_tx_ordinal,
            first_signature_ordinal: row.first_signature_ordinal,
            signature_count: row.signature_count,
        }
    }
}

impl From<ResolutionHotRow> for ArchiveV2HotBlockIndexRow {
    fn from(row: ResolutionHotRow) -> Self {
        Self {
            block_id: row.block_id,
            slot: row.slot,
            compressed_offset: row.compressed_offset,
            compressed_len: row.compressed_len,
            uncompressed_len: row.uncompressed_len,
            tx_count: row.tx_count,
            first_tx_ordinal: row.first_tx_ordinal,
            first_signature_ordinal: row.first_signature_ordinal,
            signature_count: row.signature_count,
        }
    }
}

/// The small descriptor authenticated by a Worker-issued locator token.
/// It contains no dictionaries, signature counts, or signature bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, SchemaRead, SchemaWrite)]
#[serde(deny_unknown_fields)]
pub struct LocatorV1 {
    pub version: u16,
    pub source_prefix: String,
    pub generation: String,
    pub epoch: u64,
    pub hot: ResolutionHotRow,
    pub parent_slot: u64,
    pub blockhash: [u8; 32],
    pub previous_blockhash: [u8; 32],
    pub message_schema: u8,
    pub metadata_schema: u8,
    pub blocks: SourceObjectIdentity,
    pub signatures: SourceObjectIdentity,
}

impl LocatorV1 {
    pub fn validate(&self, prefix: &str, generation: &str, slot: u64) -> Result<(), String> {
        if self.version != VERSION
            || self.source_prefix != prefix
            || self.generation != generation
            || self.hot.slot != slot
            || self.epoch != slot / 432_000
        {
            return Err("resolution locator source, generation, version, or slot differs".into());
        }
        validate_prefix(&self.source_prefix)?;
        if self.generation.is_empty()
            || self.generation.len() > 128
            || !self
                .generation
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err("resolution locator generation is invalid".into());
        }
        if self.message_schema > MESSAGE_MAY24 || self.metadata_schema > METADATA_LEGACY {
            return Err("resolution locator selects an unsupported schema".into());
        }
        self.blocks.validate()?;
        self.signatures.validate()?;
        if self.blocks.length == 0 || !self.signatures.length.is_multiple_of(64) {
            return Err("resolution source object length is invalid".into());
        }
        let row = &self.hot;
        if row.compressed_len == 0
            || row.compressed_len > 16 * 1024 * 1024
            || row.uncompressed_len == 0
            || row.uncompressed_len > 32 * 1024 * 1024
            || u64::from(row.block_id) > slot % 432_000
        {
            return Err("resolution hot row exceeds the block bounds".into());
        }
        if row
            .compressed_offset
            .checked_add(u64::from(row.compressed_len))
            .is_none_or(|end| end > self.blocks.length)
        {
            return Err("resolution hot row exceeds the source blocks object".into());
        }
        let signature_end = row
            .first_signature_ordinal
            .checked_add(u64::from(row.signature_count))
            .and_then(|end| end.checked_mul(64));
        if signature_end.is_none_or(|end| end > self.signatures.length)
            || self.signature_bytes()? > 8 * 1024 * 1024
        {
            return Err("resolution signature window exceeds its bounds".into());
        }
        if self.blockhash == [0; 32]
            || (slot != 0 && self.previous_blockhash == [0; 32])
            || (slot == 0 && self.parent_slot != 0)
            || (slot != 0 && self.parent_slot >= slot)
        {
            return Err("resolution block or parent identity is invalid".into());
        }
        Ok(())
    }

    pub fn signature_bytes(&self) -> Result<usize, String> {
        usize::try_from(self.hot.signature_count)
            .ok()
            .and_then(|n| n.checked_mul(64))
            .ok_or_else(|| "resolution signature length overflows".into())
    }

    pub fn signature_offset(&self) -> Result<u64, String> {
        self.hot
            .first_signature_ordinal
            .checked_mul(64)
            .ok_or_else(|| "resolution signature offset overflows".into())
    }

    pub fn wincode_bytes(&self) -> Result<Vec<u8>, String> {
        wincode::config::serialize(self, wincode_leb128_config()).map_err(|e| e.to_string())
    }
}

impl SourceObjectIdentity {
    pub fn validate(&self) -> Result<(), String> {
        let bytes = self.etag.as_bytes();
        if bytes.len() < 3
            || bytes.len() > 130
            || bytes[0] != b'"'
            || bytes[bytes.len() - 1] != b'"'
            || bytes[1..bytes.len() - 1]
                .iter()
                .any(|b| !b.is_ascii_graphic() || *b == b'"')
        {
            return Err("resolution requires a bounded strong quoted source ETag".into());
        }
        Ok(())
    }
}

#[derive(Debug, SchemaRead, SchemaWrite)]
pub struct ResolutionV1 {
    pub locator: LocatorV1,
    pub source_objects: Vec<NamedSourceObject>,
    pub signature_counts: Vec<u8>,
    pub access_prefix: Vec<u8>,
    pub access_suffix: Vec<u8>,
}

#[derive(Debug, SchemaRead, SchemaWrite)]
struct AccessSuffix {
    pubkeys: Vec<ArchiveV2BlockAccessPubkey>,
    blockhashes: Vec<ArchiveV2BlockAccessBlockhash>,
    vote_hashes: Vec<ArchiveV2BlockAccessVoteHash>,
}

/// An immutable resolution whose framing, identity and dictionaries were checked.
/// The decoded dictionaries remain owned here until `into_access`, so a request
/// does not allocate and decode the same table at each validation step.
#[derive(Debug)]
pub struct CheckedResolution {
    value: ResolutionV1,
    suffix: AccessSuffix,
}

impl CheckedResolution {
    pub fn locator(&self) -> LocatorV1 {
        self.value.locator.clone()
    }

    pub fn locator_ref(&self) -> &LocatorV1 {
        &self.value.locator
    }

    /// Check the configured identity. All other invariants were checked at
    /// construction, and private fields prevent a caller from changing them.
    pub fn validate(&self, prefix: &str, generation: &str, slot: u64) -> Result<(), String> {
        self.value.locator.validate(prefix, generation, slot)
    }

    pub fn access_prefix(&self) -> &[u8] {
        &self.value.access_prefix
    }

    pub fn access_suffix(&self) -> &[u8] {
        &self.value.access_suffix
    }

    pub fn access_len(&self) -> Result<usize, String> {
        self.value.access_len()
    }

    pub fn signature_bytes(&self) -> Result<usize, String> {
        self.value.signature_bytes()
    }

    pub fn signature_counts(&self) -> &[u8] {
        &self.value.signature_counts
    }

    pub fn source_objects(&self) -> &[NamedSourceObject] {
        &self.value.source_objects
    }

    /// Check requested IDs using the already parsed dictionary tables.
    pub fn validate_membership(
        &self,
        pubkeys: &[u32],
        hashes: &[i32],
        votes: &[(u32, bool, bool)],
    ) -> Result<(), String> {
        validate_suffix_membership(&self.suffix, pubkeys, hashes, votes)
    }

    /// A per-request reply must contain exactly the requested dictionary IDs.
    /// Existing vote rows can carry both source columns when one was requested.
    pub fn validate_exact_membership(
        &self,
        pubkeys: &[u32],
        hashes: &[i32],
        votes: &[(u32, bool, bool)],
    ) -> Result<(), String> {
        if self.suffix.pubkeys.len() != pubkeys.len()
            || self.suffix.blockhashes.len() != hashes.len()
            || self.suffix.vote_hashes.len() != votes.len()
        {
            return Err("resolution dictionary IDs differ from the requested set".into());
        }
        self.validate_membership(pubkeys, hashes, votes)
    }

    /// Bind checked table values to the decoded hot header and signature rows.
    pub fn validate_reference_header(
        &self,
        slot: u64,
        parent_slot: u64,
        current_id: u32,
        previous_id: u32,
        signature_counts: &[u8],
    ) -> Result<(), String> {
        let locator = &self.value.locator;
        if slot != locator.hot.slot
            || parent_slot != locator.parent_slot
            || signature_counts != self.value.signature_counts
        {
            return Err("resolution header or signature rows differ from decoded hot block".into());
        }
        let lookup = |id| {
            self.suffix
                .blockhashes
                .binary_search_by_key(&id, |v| v.id)
                .ok()
                .map(|n| self.suffix.blockhashes[n].blockhash)
        };
        let current =
            i32::try_from(current_id).map_err(|_| "current header hash ID exceeds i32")?;
        if lookup(current) != Some(locator.blockhash) {
            return Err("resolved current blockhash differs from decoded header reference".into());
        }
        if slot == 0 {
            if locator.previous_blockhash != [0; 32] {
                return Err("genesis resolution has a nonzero previous hash".into());
            }
        } else {
            let previous = if current_id == 0 && previous_id == 0 {
                -1
            } else {
                i32::try_from(previous_id).map_err(|_| "previous header hash ID exceeds i32")?
            };
            if lookup(previous) != Some(locator.previous_blockhash) {
                return Err(
                    "resolved previous blockhash differs from decoded header reference".into(),
                );
            }
        }
        Ok(())
    }

    pub fn into_access(self, signatures: Vec<u8>) -> Result<ArchiveV2BlockAccessBlob, String> {
        if signatures.len() != self.signature_bytes()? {
            return Err("signature window length differs from the resolution".into());
        }
        Ok(ArchiveV2BlockAccessBlob {
            version: WINCODE_ARCHIVE_V2_BLOCK_ACCESS_VERSION,
            flags: 0,
            blockhash: self.value.locator.blockhash,
            previous_blockhash: self.value.locator.previous_blockhash,
            signature_counts: self.value.signature_counts,
            signatures,
            pubkeys: self.suffix.pubkeys,
            blockhashes: self.suffix.blockhashes,
            vote_hashes: self.suffix.vote_hashes,
        })
    }
}

impl ResolutionV1 {
    pub fn new(
        locator: LocatorV1,
        source_objects: Vec<NamedSourceObject>,
        access: &ArchiveV2BlockAccessBlob,
    ) -> Result<Self, String> {
        if access.version != WINCODE_ARCHIVE_V2_BLOCK_ACCESS_VERSION
            || access.flags != 0
            || access.blockhash != locator.blockhash
            || access.previous_blockhash != locator.previous_blockhash
        {
            return Err("source access blob and resolution identity differ".into());
        }
        if access.signatures.len() != locator.signature_bytes()? {
            return Err("source access signature bytes differ from the hot row".into());
        }
        Self::from_resolved_tables(
            locator,
            source_objects,
            &access.signature_counts,
            &access.pubkeys,
            &access.blockhashes,
            &access.vote_hashes,
        )
    }

    /// Build an index/ID-resolution response without reading signature bodies.
    pub fn from_resolved_tables(
        locator: LocatorV1,
        mut source_objects: Vec<NamedSourceObject>,
        signature_counts: &[u8],
        pubkeys: &[ArchiveV2BlockAccessPubkey],
        blockhashes: &[ArchiveV2BlockAccessBlockhash],
        vote_hashes: &[ArchiveV2BlockAccessVoteHash],
    ) -> Result<Self, String> {
        source_objects.sort_by(|a, b| a.name.cmp(&b.name));
        let access_suffix = wincode::config::serialize(
            &(pubkeys, blockhashes, vote_hashes),
            wincode_leb128_config(),
        )
        .map_err(|error| error.to_string())?;
        let access_prefix = access_prefix_bytes(&locator, signature_counts)?;
        let result = Self {
            locator,
            source_objects,
            signature_counts: signature_counts.to_vec(),
            access_prefix,
            access_suffix,
        };
        result.validate(
            &result.locator.source_prefix,
            &result.locator.generation,
            result.locator.hot.slot,
        )?;
        Ok(result)
    }

    pub fn locator(&self) -> LocatorV1 {
        self.locator.clone()
    }
    pub fn access_prefix(&self) -> &[u8] {
        &self.access_prefix
    }
    pub fn access_suffix(&self) -> &[u8] {
        &self.access_suffix
    }
    pub fn signature_bytes(&self) -> Result<usize, String> {
        self.locator.signature_bytes()
    }
    pub fn access_len(&self) -> Result<usize, String> {
        self.access_prefix
            .len()
            .checked_add(self.signature_bytes()?)
            .and_then(|n| n.checked_add(self.access_suffix.len()))
            .ok_or_else(|| "resolution access length overflows".into())
    }

    pub fn validate(&self, prefix: &str, generation: &str, slot: u64) -> Result<(), String> {
        self.validate_envelope(prefix, generation, slot)?;
        self.checked_suffix()?;
        Ok(())
    }

    fn validate_envelope(&self, prefix: &str, generation: &str, slot: u64) -> Result<(), String> {
        self.locator.validate(prefix, generation, slot)?;
        if self.source_objects.len() < 2 || self.source_objects.len() > 32 {
            return Err("resolution source object count is outside its bound".into());
        }
        for (index, object) in self.source_objects.iter().enumerate() {
            if object.name.is_empty()
                || object.name.len() > 128
                || !object
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                || (index > 0 && self.source_objects[index - 1].name >= object.name)
            {
                return Err("resolution source objects must be sorted, unique flat names".into());
            }
            object.identity.validate()?;
        }
        for (name, expected) in [
            (BLOCKS, &self.locator.blocks),
            (SIGNATURES, &self.locator.signatures),
        ] {
            if self
                .source_objects
                .iter()
                .find(|v| v.name == name)
                .map(|v| &v.identity)
                != Some(expected)
            {
                return Err(format!("resolution source identity differs for {name}"));
            }
        }
        if self.signature_counts.len() != self.locator.hot.tx_count as usize
            || self
                .signature_counts
                .iter()
                .try_fold(0u32, |sum, n| sum.checked_add(u32::from(*n)))
                != Some(self.locator.hot.signature_count)
        {
            return Err("resolution signature counts differ from the source hot row".into());
        }
        if self.access_prefix != access_prefix_bytes(&self.locator, &self.signature_counts)? {
            return Err("resolution access prefix differs from its checked identity".into());
        }
        if self
            .access_prefix
            .len()
            .saturating_add(self.access_suffix.len())
            > MAX_RESOLUTION_BYTES - HEADER_LEN
        {
            return Err("resolution access tables exceed their byte bound".into());
        }
        Ok(())
    }

    fn checked_suffix(&self) -> Result<AccessSuffix, String> {
        let suffix: AccessSuffix = wincode::config::deserialize_exact(
            &self.access_suffix,
            bounded_wincode_leb128_config::<MAX_RESOLUTION_BYTES>(),
        )
        .map_err(|e| format!("decode resolution tables: {e}"))?;
        if suffix.pubkeys.len() > 65_536
            || suffix.blockhashes.len() > 65_536
            || suffix.vote_hashes.len() > 65_536
        {
            return Err("resolution has too many dictionary entries".into());
        }
        if suffix.pubkeys.iter().any(|v| v.id == 0)
            || !suffix.pubkeys.windows(2).all(|v| v[0].id < v[1].id)
            || !suffix.blockhashes.windows(2).all(|v| v[0].id < v[1].id)
            || !suffix
                .vote_hashes
                .windows(2)
                .all(|v| v[0].block_id < v[1].block_id)
            || suffix
                .vote_hashes
                .iter()
                .any(|v| v.bank_hash.is_none() && v.block_id_hash.is_none())
        {
            return Err("resolution dictionaries must have unique sorted valid IDs".into());
        }
        if let Some(registry) = self
            .source_objects
            .iter()
            .find(|v| v.name == "registry.bin")
        {
            if !registry.identity.length.is_multiple_of(32)
                || suffix
                    .pubkeys
                    .iter()
                    .any(|v| u64::from(v.id) > registry.identity.length / 32)
            {
                return Err("resolution pubkey dictionary exceeds the source registry".into());
            }
        }
        Ok(suffix)
    }

    pub fn into_access(self, signatures: Vec<u8>) -> Result<ArchiveV2BlockAccessBlob, String> {
        self.validate_envelope(
            &self.locator.source_prefix,
            &self.locator.generation,
            self.locator.hot.slot,
        )?;
        if signatures.len() != self.signature_bytes()? {
            return Err("signature window length differs from the resolution".into());
        }
        let suffix = self.checked_suffix()?;
        Ok(ArchiveV2BlockAccessBlob {
            version: WINCODE_ARCHIVE_V2_BLOCK_ACCESS_VERSION,
            flags: 0,
            blockhash: self.locator.blockhash,
            previous_blockhash: self.locator.previous_blockhash,
            signature_counts: self.signature_counts,
            signatures,
            pubkeys: suffix.pubkeys,
            blockhashes: suffix.blockhashes,
            vote_hashes: suffix.vote_hashes,
        })
    }

    /// Check complete dictionary coverage during an offline block build.
    pub fn validate_membership(
        &self,
        pubkeys: &[u32],
        hashes: &[i32],
        votes: &[(u32, bool, bool)],
    ) -> Result<(), String> {
        let suffix: AccessSuffix = wincode::config::deserialize_exact(
            &self.access_suffix,
            bounded_wincode_leb128_config::<MAX_RESOLUTION_BYTES>(),
        )
        .map_err(|e| e.to_string())?;
        validate_suffix_membership(&suffix, pubkeys, hashes, votes)
    }
}

fn validate_suffix_membership(
    suffix: &AccessSuffix,
    pubkeys: &[u32],
    hashes: &[i32],
    votes: &[(u32, bool, bool)],
) -> Result<(), String> {
    for id in pubkeys {
        if suffix.pubkeys.binary_search_by_key(id, |v| v.id).is_err() {
            return Err(format!("resolution is missing pubkey ID {id}"));
        }
    }
    for id in hashes {
        if suffix
            .blockhashes
            .binary_search_by_key(id, |v| v.id)
            .is_err()
        {
            return Err(format!("resolution is missing blockhash ID {id}"));
        }
    }
    for (id, bank, block) in votes {
        let entry = suffix
            .vote_hashes
            .binary_search_by_key(id, |v| v.block_id)
            .ok()
            .map(|n| &suffix.vote_hashes[n])
            .ok_or_else(|| format!("resolution is missing vote-hash block {id}"))?;
        if (*bank && entry.bank_hash.is_none()) || (*block && entry.block_id_hash.is_none()) {
            return Err(format!(
                "resolution vote-hash block {id} is missing a required column"
            ));
        }
    }
    Ok(())
}

fn access_prefix_bytes(locator: &LocatorV1, counts: &[u8]) -> Result<Vec<u8>, String> {
    wincode::config::serialize(
        &(
            WINCODE_ARCHIVE_V2_BLOCK_ACCESS_VERSION,
            0u32,
            locator.blockhash,
            locator.previous_blockhash,
            counts,
            locator.signature_bytes()? as u64,
        ),
        wincode_leb128_config(),
    )
    .map_err(|e| e.to_string())
}

pub fn encode(value: &ResolutionV1) -> Result<Vec<u8>, String> {
    value.validate(
        &value.locator.source_prefix,
        &value.locator.generation,
        value.locator.hot.slot,
    )?;
    let payload =
        wincode::config::serialize(value, wincode_leb128_config()).map_err(|e| e.to_string())?;
    if payload.len() > MAX_RESOLUTION_BYTES - HEADER_LEN {
        return Err("resolution object exceeds four MiB".into());
    }
    let (prefix_offset, suffix_offset) = segment_offsets(
        payload.len(),
        value.access_prefix.len(),
        value.access_suffix.len(),
    )?;
    let mut output = vec![0; HEADER_LEN];
    output[..8].copy_from_slice(MAGIC);
    output[8..10].copy_from_slice(&VERSION.to_le_bytes());
    output[10..12].copy_from_slice(&(HEADER_LEN as u16).to_le_bytes());
    for (offset, number) in [
        (16, payload.len()),
        (20, prefix_offset),
        (24, value.access_prefix.len()),
        (28, suffix_offset),
        (32, value.access_suffix.len()),
    ] {
        output[offset..offset + 4].copy_from_slice(&(number as u32).to_le_bytes());
    }
    output[36] = value.locator.message_schema;
    output[37] = value.locator.metadata_schema;
    output[40..48].copy_from_slice(&value.locator.epoch.to_le_bytes());
    output[48..56].copy_from_slice(&value.locator.hot.slot.to_le_bytes());
    output[56..88].copy_from_slice(&Sha256::digest(&payload));
    output[88..92].copy_from_slice(&(value.locator.wincode_bytes()?.len() as u32).to_le_bytes());
    output.extend_from_slice(&payload);
    Ok(output)
}

/// Return the exact payload after checking the bounded outer framing.
/// This does not authenticate the payload or validate its decoded contents.
pub fn payload_for_digest(bytes: &[u8]) -> Result<&[u8], String> {
    if bytes.len() < HEADER_LEN
        || bytes.len() > MAX_RESOLUTION_BYTES
        || &bytes[..8] != MAGIC
        || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != VERSION
        || u16::from_le_bytes(bytes[10..12].try_into().unwrap()) != HEADER_LEN as u16
    {
        return Err("invalid resolution object header or byte length".into());
    }
    if bytes[12..16]
        .iter()
        .chain(&bytes[38..40])
        .chain(&bytes[92..96])
        .any(|b| *b != 0)
    {
        return Err("resolution header has nonzero reserved fields".into());
    }
    let payload = &bytes[HEADER_LEN..];
    if read_u32(bytes, 16) != payload.len() {
        return Err("resolution payload length differs".into());
    }
    Ok(payload)
}

/// Decode a resolution with a SHA-256 computed by a trusted local hash engine.
///
/// The caller MUST compute `payload_sha256` from the exact bytes returned by
/// `payload_for_digest(bytes)`. It must never supply the header digest or a
/// client-provided digest instead. This lets a Worker use native WebCrypto while
/// keeping the same SHA-256 check and all Rust format and dictionary checks.
pub fn decode_checked_with_payload_digest(
    bytes: &[u8],
    payload_sha256: [u8; 32],
) -> Result<CheckedResolution, String> {
    let payload = payload_for_digest(bytes)?;
    if payload_sha256 != bytes[56..88] {
        return Err("resolution payload length or SHA256 differs".into());
    }
    let value: ResolutionV1 = wincode::config::deserialize_exact(
        payload,
        bounded_wincode_leb128_config::<MAX_RESOLUTION_BYTES>(),
    )
    .map_err(|e| format!("decode resolution: {e}"))?;
    let (prefix, suffix) = segment_offsets(
        payload.len(),
        value.access_prefix.len(),
        value.access_suffix.len(),
    )?;
    if read_u32(bytes, 20) != prefix
        || read_u32(bytes, 24) != value.access_prefix.len()
        || read_u32(bytes, 28) != suffix
        || read_u32(bytes, 32) != value.access_suffix.len()
        || bytes[36] != value.locator.message_schema
        || bytes[37] != value.locator.metadata_schema
        || u64::from_le_bytes(bytes[40..48].try_into().unwrap()) != value.locator.epoch
        || u64::from_le_bytes(bytes[48..56].try_into().unwrap()) != value.locator.hot.slot
        || read_u32(bytes, 88) != value.locator.wincode_bytes()?.len()
    {
        return Err("resolution header and decoded descriptor differ".into());
    }
    value.validate_envelope(
        &value.locator.source_prefix,
        &value.locator.generation,
        value.locator.hot.slot,
    )?;
    let suffix = value.checked_suffix()?;
    Ok(CheckedResolution { value, suffix })
}

/// Fully check a resolution with the native Rust SHA-256 implementation.
pub fn decode_checked(bytes: &[u8]) -> Result<CheckedResolution, String> {
    let digest = Sha256::digest(payload_for_digest(bytes)?).into();
    decode_checked_with_payload_digest(bytes, digest)
}

/// Decode the public mutable representation with the complete native checks.
pub fn decode(bytes: &[u8]) -> Result<ResolutionV1, String> {
    Ok(decode_checked(bytes)?.value)
}

fn segment_offsets(payload: usize, prefix: usize, suffix: usize) -> Result<(usize, usize), String> {
    let suffix_start = payload
        .checked_sub(suffix)
        .ok_or("invalid resolution suffix length")?;
    let prefix_start = suffix_start
        .checked_sub(leb_len(suffix))
        .and_then(|n| n.checked_sub(prefix))
        .ok_or("invalid resolution prefix length")?;
    Ok((HEADER_LEN + prefix_start, HEADER_LEN + suffix_start))
}

fn leb_len(mut value: usize) -> usize {
    let mut n = 1;
    while value >= 128 {
        value >>= 7;
        n += 1;
    }
    n
}
fn read_u32(bytes: &[u8], offset: usize) -> usize {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize
}
fn validate_prefix(prefix: &str) -> Result<(), String> {
    if prefix.is_empty()
        || prefix.len() > 512
        || prefix.starts_with('/')
        || prefix.ends_with('/')
        || prefix
            .split('/')
            .any(|v| v.is_empty() || v == "." || v == "..")
        || !prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
    {
        return Err("resolution source prefix is invalid".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> ResolutionV1 {
        let blocks = SourceObjectIdentity {
            length: 1000,
            etag: "\"blocks-v1\"".into(),
        };
        let signatures = SourceObjectIdentity {
            length: 128,
            etag: "\"signatures-v1\"".into(),
        };
        let locator = LocatorV1 {
            version: VERSION,
            source_prefix: "compact-v2/test".into(),
            generation: "g1".into(),
            epoch: 1,
            hot: ResolutionHotRow {
                block_id: 0,
                slot: 432_000,
                compressed_offset: 100,
                compressed_len: 200,
                uncompressed_len: 300,
                tx_count: 1,
                first_tx_ordinal: 0,
                first_signature_ordinal: 0,
                signature_count: 2,
            },
            parent_slot: 431_999,
            blockhash: [11; 32],
            previous_blockhash: [10; 32],
            message_schema: MESSAGE_CURRENT,
            metadata_schema: METADATA_CURRENT,
            blocks: blocks.clone(),
            signatures: signatures.clone(),
        };
        let access = ArchiveV2BlockAccessBlob {
            version: 2,
            flags: 0,
            blockhash: [11; 32],
            previous_blockhash: [10; 32],
            signature_counts: vec![2],
            signatures: vec![77; 128],
            pubkeys: vec![ArchiveV2BlockAccessPubkey {
                id: 1,
                pubkey: [42; 32],
            }],
            blockhashes: vec![
                ArchiveV2BlockAccessBlockhash {
                    id: -1,
                    blockhash: [10; 32],
                },
                ArchiveV2BlockAccessBlockhash {
                    id: 0,
                    blockhash: [11; 32],
                },
            ],
            vote_hashes: vec![ArchiveV2BlockAccessVoteHash {
                block_id: 2,
                bank_hash: Some([20; 32]),
                block_id_hash: None,
            }],
        };
        ResolutionV1::new(
            locator,
            vec![
                NamedSourceObject {
                    name: BLOCKS.into(),
                    identity: blocks,
                },
                NamedSourceObject {
                    name: SIGNATURES.into(),
                    identity: signatures,
                },
            ],
            &access,
        )
        .unwrap()
    }

    #[test]
    fn round_trip_exposes_exact_zero_copy_access_segments() {
        let resolution = fixture();
        let expected = wincode::config::serialize(
            &fixture().into_access(vec![77; 128]).unwrap(),
            wincode_leb128_config(),
        )
        .unwrap();
        let mut streamed = resolution.access_prefix().to_vec();
        streamed.extend_from_slice(&[77; 128]);
        streamed.extend_from_slice(resolution.access_suffix());
        assert_eq!(streamed, expected);
        assert_eq!(streamed.len(), resolution.access_len().unwrap());
        let bytes = encode(&resolution).unwrap();
        let prefix = read_u32(&bytes, 20);
        let suffix = read_u32(&bytes, 28);
        assert_eq!(
            &bytes[prefix..prefix + resolution.access_prefix.len()],
            resolution.access_prefix()
        );
        assert_eq!(&bytes[suffix..], resolution.access_suffix());
        assert_eq!(
            &bytes[HEADER_LEN..HEADER_LEN + read_u32(&bytes, 88)],
            resolution.locator.wincode_bytes().unwrap()
        );
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded.locator(), resolution.locator());
        assert_eq!(decoded.access_prefix(), resolution.access_prefix());
        assert_eq!(decoded.access_suffix(), resolution.access_suffix());
    }

    #[test]
    fn rejects_corruption_truncation_and_extra_bytes() {
        let bytes = encode(&fixture()).unwrap();
        for index in [
            0,
            8,
            10,
            12,
            16,
            20,
            24,
            28,
            32,
            36,
            40,
            48,
            56,
            88,
            HEADER_LEN,
            bytes.len() - 1,
        ] {
            let mut broken = bytes.clone();
            broken[index] ^= 1;
            assert!(decode(&broken).is_err(), "byte {index}");
        }
        assert!(decode(&bytes[..HEADER_LEN - 1]).is_err());
        assert!(decode(&bytes[..bytes.len() - 1]).is_err());
        let mut extra = bytes;
        extra.push(0);
        assert!(decode(&extra).is_err());
    }

    #[test]
    fn rejects_mixed_generation_parent_and_source_ranges() {
        let mut resolution = fixture();
        assert!(
            resolution
                .validate("compact-v2/other", "g1", 432_000)
                .is_err()
        );
        assert!(
            resolution
                .validate("compact-v2/test", "g2", 432_000)
                .is_err()
        );
        assert!(
            resolution
                .validate("compact-v2/test", "g1", 432_001)
                .is_err()
        );
        resolution.locator.parent_slot = 432_000;
        assert!(encode(&resolution).is_err());
        resolution = fixture();
        resolution.locator.previous_blockhash = [0; 32];
        assert!(encode(&resolution).is_err());
        resolution = fixture();
        resolution.locator.hot.compressed_offset = u64::MAX;
        assert!(encode(&resolution).is_err());
        resolution = fixture();
        resolution.locator.hot.first_signature_ordinal = u64::MAX;
        assert!(encode(&resolution).is_err());
        resolution = fixture();
        resolution.locator.blocks.etag = "W/\"weak\"".into();
        assert!(encode(&resolution).is_err());
    }

    #[test]
    fn checks_signature_counts_dictionary_membership_and_bounds() {
        let mut resolution = fixture();
        resolution
            .validate_membership(&[1], &[-1, 0], &[(2, true, false)])
            .unwrap();
        assert!(resolution.validate_membership(&[2], &[], &[]).is_err());
        assert!(resolution.validate_membership(&[], &[1], &[]).is_err());
        assert!(
            resolution
                .validate_membership(&[], &[], &[(2, false, true)])
                .is_err()
        );
        assert!(
            resolution
                .validate_membership(&[], &[], &[(3, true, false)])
                .is_err()
        );
        assert!(fixture().into_access(vec![0; 127]).is_err());
        resolution.signature_counts = vec![1];
        assert!(encode(&resolution).is_err());
        resolution = fixture();
        resolution.access_suffix = vec![0; MAX_RESOLUTION_BYTES];
        assert!(encode(&resolution).is_err());
    }

    #[test]
    fn checked_decode_preserves_binary_segments_and_moves_decoded_tables() {
        let value = fixture();
        let bytes = encode(&value).unwrap();
        let digest: [u8; 32] = Sha256::digest(payload_for_digest(&bytes).unwrap()).into();
        let checked = decode_checked_with_payload_digest(&bytes, digest).unwrap();
        checked.validate("compact-v2/test", "g1", 432_000).unwrap();
        assert_eq!(checked.locator(), value.locator());
        assert_eq!(checked.locator_ref(), &value.locator);
        assert_eq!(checked.access_prefix(), value.access_prefix());
        assert_eq!(checked.access_suffix(), value.access_suffix());
        assert_eq!(checked.access_len().unwrap(), value.access_len().unwrap());
        assert_eq!(checked.signature_counts(), value.signature_counts);
        assert_eq!(checked.source_objects(), value.source_objects);
        let pubkeys = checked.suffix.pubkeys.as_ptr();
        let blockhashes = checked.suffix.blockhashes.as_ptr();
        let votes = checked.suffix.vote_hashes.as_ptr();
        let access = checked.into_access(vec![77; 128]).unwrap();
        assert_eq!(access.pubkeys.as_ptr(), pubkeys);
        assert_eq!(access.blockhashes.as_ptr(), blockhashes);
        assert_eq!(access.vote_hashes.as_ptr(), votes);
        let expected = fixture().into_access(vec![77; 128]).unwrap();
        assert_eq!(
            wincode::config::serialize(&access, wincode_leb128_config()).unwrap(),
            wincode::config::serialize(&expected, wincode_leb128_config()).unwrap()
        );
    }

    #[test]
    fn checked_decode_rejects_digest_identity_and_signature_mismatches() {
        let bytes = encode(&fixture()).unwrap();
        let mut digest: [u8; 32] = Sha256::digest(payload_for_digest(&bytes).unwrap()).into();
        digest[0] ^= 1;
        assert!(decode_checked_with_payload_digest(&bytes, digest).is_err());
        let checked = decode_checked(&bytes).unwrap();
        assert!(checked.validate("compact-v2/other", "g1", 432_000).is_err());
        assert!(checked.validate("compact-v2/test", "g2", 432_000).is_err());
        assert!(checked.validate("compact-v2/test", "g1", 432_001).is_err());
        assert!(checked.into_access(vec![77; 127]).is_err());
    }

    #[test]
    fn prehashed_decode_keeps_all_framing_and_header_checks() {
        let bytes = encode(&fixture()).unwrap();
        for index in [0, 8, 10, 12, 16, 20, 24, 28, 32, 36, 40, 48, 56, 88, 95] {
            let mut broken = bytes.clone();
            broken[index] ^= 1;
            let digest: [u8; 32] = Sha256::digest(&broken[HEADER_LEN..]).into();
            assert!(
                decode_checked_with_payload_digest(&broken, digest).is_err(),
                "header byte {index}"
            );
        }
        assert!(payload_for_digest(&bytes[..HEADER_LEN - 1]).is_err());
        assert!(payload_for_digest(&bytes[..bytes.len() - 1]).is_err());
        let mut extra = bytes;
        extra.push(0);
        assert!(payload_for_digest(&extra).is_err());
        assert!(payload_for_digest(&vec![0; MAX_RESOLUTION_BYTES + 1]).is_err());
    }

    fn unchecked_wire(value: &ResolutionV1) -> Vec<u8> {
        let payload = wincode::config::serialize(value, wincode_leb128_config()).unwrap();
        let mut bytes = encode(&fixture()).unwrap();
        bytes.truncate(HEADER_LEN);
        let (prefix, suffix) = segment_offsets(
            payload.len(),
            value.access_prefix.len(),
            value.access_suffix.len(),
        )
        .unwrap();
        for (offset, number) in [
            (16, payload.len()),
            (20, prefix),
            (24, value.access_prefix.len()),
            (28, suffix),
            (32, value.access_suffix.len()),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&(number as u32).to_le_bytes());
        }
        bytes[56..88].copy_from_slice(&Sha256::digest(&payload));
        bytes.extend(payload);
        bytes
    }

    #[test]
    fn valid_digest_cannot_promote_invalid_dictionary_or_envelope() {
        let mut cases = Vec::new();
        let mut value = fixture();
        let mut suffix = value.checked_suffix().unwrap();
        suffix.pubkeys[0].id = 0;
        value.access_suffix = wincode::config::serialize(&suffix, wincode_leb128_config()).unwrap();
        cases.push(value);
        let mut value = fixture();
        let mut suffix = value.checked_suffix().unwrap();
        suffix.pubkeys.push(suffix.pubkeys[0].clone());
        value.access_suffix = wincode::config::serialize(&suffix, wincode_leb128_config()).unwrap();
        cases.push(value);
        let mut value = fixture();
        value.access_suffix.push(0);
        cases.push(value);
        let mut value = fixture();
        value.signature_counts[0] = 1;
        cases.push(value);
        let mut value = fixture();
        value.source_objects[0].identity.length += 1;
        cases.push(value);
        for value in cases {
            let bytes = unchecked_wire(&value);
            let digest = Sha256::digest(payload_for_digest(&bytes).unwrap()).into();
            assert!(decode_checked_with_payload_digest(&bytes, digest).is_err());
            assert!(decode(&bytes).is_err());
        }
    }
}
