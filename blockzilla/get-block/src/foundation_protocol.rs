//! Authenticated Foundation requests before the parent hashes are resolved.
//! These descriptors carry source identities and offsets, never invented hashes.
use crate::slot_references::SlotReferences;
use crate::slot_resolution::{LocatorV1, ResolutionHotRow, SourceObjectIdentity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingLocatorV1 {
    pub version: u16,
    pub source_prefix: String,
    pub generation: String,
    pub epoch: u64,
    pub hot: ResolutionHotRow,
    pub message_schema: u8,
    pub metadata_schema: u8,
    pub blocks: SourceObjectIdentity,
    pub signatures: SourceObjectIdentity,
}

impl PendingLocatorV1 {
    pub fn from_locator(value: &LocatorV1) -> Self {
        Self {
            version: value.version,
            source_prefix: value.source_prefix.clone(),
            generation: value.generation.clone(),
            epoch: value.epoch,
            hot: value.hot,
            message_schema: value.message_schema,
            metadata_schema: value.metadata_schema,
            blocks: value.blocks.clone(),
            signatures: value.signatures.clone(),
        }
    }

    pub fn validate(&self, prefix: &str, generation: &str, slot: u64) -> Result<(), String> {
        self.validate_source_geometry(prefix, generation, slot)?;
        let row = &self.hot;
        if row.compressed_len > 16 * 1024 * 1024
            || row.uncompressed_len > 32 * 1024 * 1024
            || row.signature_count > 8 * 1024 * 1024 / 64
        {
            return Err("pending locator exceeds source or block bounds".into());
        }
        Ok(())
    }

    /// Validate a pinned archive row without applying request transport limits.
    /// An epoch can contain a large reward block that a request cannot serve.
    pub fn validate_source_geometry(
        &self,
        prefix: &str,
        generation: &str,
        slot: u64,
    ) -> Result<(), String> {
        if self.version != 1
            || self.source_prefix != prefix
            || self.generation != generation
            || self.hot.slot != slot
            || self.epoch != slot / 432_000
            || prefix.is_empty()
            || prefix.len() > 1024
            || prefix.starts_with('/')
            || prefix
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || prefix
                .bytes()
                .any(|b| !b.is_ascii_graphic() || b == b'\\' || b == b'?' || b == b'#')
            || generation.is_empty()
            || generation.len() > 128
            || !generation
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || self.message_schema > 1
            || self.metadata_schema > 1
        {
            return Err(
                "pending locator source, schema, generation, version or slot differs".into(),
            );
        }
        self.blocks.validate()?;
        self.signatures.validate()?;
        let row = &self.hot;
        if self.blocks.length == 0
            || !self.signatures.length.is_multiple_of(64)
            || row.compressed_len == 0
            || row.uncompressed_len == 0
            || u64::from(row.block_id) > slot % 432_000
            || row
                .compressed_offset
                .checked_add(u64::from(row.compressed_len))
                .is_none_or(|end| end > self.blocks.length)
            || row
                .first_signature_ordinal
                .checked_add(u64::from(row.signature_count))
                .and_then(|end| end.checked_mul(64))
                .is_none_or(|end| end > self.signatures.length)
        {
            return Err("pending locator exceeds source or block bounds".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveRequestV1 {
    pub version: u16,
    pub source: PendingLocatorV1,
    pub hot_sha256: String,
    pub references: SlotReferences,
}

impl ResolveRequestV1 {
    pub fn validate(&self, prefix: &str, generation: &str, slot: u64) -> Result<(), String> {
        self.source.validate(prefix, generation, slot)?;
        if self.version != 1
            || self.hot_sha256.len() != 64
            || !self
                .hot_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("resolve request version or hot frame digest is invalid".into());
        }
        self.references.validate(&self.source.hot.into())
    }
}
