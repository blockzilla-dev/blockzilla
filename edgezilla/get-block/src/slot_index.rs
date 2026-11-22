//! Optional dense slot lookup for a pinned Compact V2 archive generation.
//!
//! This derived index references only durable archive objects. It does not
//! require the old block-access blob. Integers use fixed little-endian bytes.
use blockzilla_archive_v2::{
    ARCHIVE_V2_HOT_INDEX_HEADER_LEN, ARCHIVE_V2_HOT_INDEX_ROW_LEN, ArchiveV2HotBlockIndexRow,
};

pub const SLOT_INDEX_FILE: &str = "archive-v2-slot-offsets.v1.index";
pub const SLOT_INDEX_HEADER_LEN: usize = 128;
pub const SLOT_INDEX_ROW_LEN: usize = 128;
pub const SLOT_INDEX_MAGIC: &[u8; 8] = b"BZSLOF1!";
pub const SLOT_INDEX_VERSION: u16 = 1;
pub const MAX_SLOT_COUNT: u64 = 432_000;
pub const MAX_BLOCK_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_COMPRESSED_BLOCK_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotIndexHeader {
    pub epoch: u64,
    pub first_slot: u64,
    pub slot_count: u64,
    pub blocks_bytes: u64,
    pub signatures_bytes: u64,
    pub registry_bytes: u64,
    pub blockhash_registry_bytes: u64,
    pub source_index_bytes: u64,
    pub source_index_sha256: [u8; 32],
    pub block_count: u64,
}

impl SlotIndexHeader {
    pub fn validate(&self) -> Result<(), String> {
        if self.slot_count == 0 || self.slot_count > MAX_SLOT_COUNT {
            return Err("slot index has an invalid slot count".into());
        }
        self.first_slot
            .checked_add(self.slot_count - 1)
            .ok_or("slot index slot range overflows")?;
        if self.block_count == 0 || self.block_count > self.slot_count {
            return Err("slot index has an invalid block count".into());
        }
        let expected = self
            .block_count
            .checked_mul(ARCHIVE_V2_HOT_INDEX_ROW_LEN as u64)
            .and_then(|n| n.checked_add(ARCHIVE_V2_HOT_INDEX_HEADER_LEN as u64))
            .ok_or("source index length overflows")?;
        if expected != self.source_index_bytes {
            return Err("slot index source index length differs from block count".into());
        }
        if !self.signatures_bytes.is_multiple_of(64)
            || !self.registry_bytes.is_multiple_of(32)
            || !self.blockhash_registry_bytes.is_multiple_of(32)
        {
            return Err("slot index source object has an invalid record length".into());
        }
        let hashes = self.blockhash_registry_bytes / 32;
        if hashes != self.block_count && hashes != self.block_count + 1 {
            return Err("slot index blockhash count differs from block count".into());
        }
        Ok(())
    }

    pub fn file_len(&self) -> Result<u64, String> {
        self.validate()?;
        self.slot_count
            .checked_mul(SLOT_INDEX_ROW_LEN as u64)
            .and_then(|n| n.checked_add(SLOT_INDEX_HEADER_LEN as u64))
            .ok_or_else(|| "slot index file length overflows".into())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SlotIndexRow {
    pub hot: ArchiveV2HotBlockIndexRow,
    pub parent_slot: u64,
    pub blockhash: [u8; 32],
    pub previous_blockhash: [u8; 32],
}

pub fn encode_header(header: &SlotIndexHeader) -> Result<[u8; SLOT_INDEX_HEADER_LEN], String> {
    header.validate()?;
    let mut out = [0; SLOT_INDEX_HEADER_LEN];
    out[..8].copy_from_slice(SLOT_INDEX_MAGIC);
    out[8..10].copy_from_slice(&SLOT_INDEX_VERSION.to_le_bytes());
    out[10..12].copy_from_slice(&(SLOT_INDEX_HEADER_LEN as u16).to_le_bytes());
    out[12..14].copy_from_slice(&(SLOT_INDEX_ROW_LEN as u16).to_le_bytes());
    for (offset, value) in [
        (16, header.epoch),
        (24, header.first_slot),
        (32, header.slot_count),
        (40, header.blocks_bytes),
        (48, header.signatures_bytes),
        (56, header.registry_bytes),
        (64, header.blockhash_registry_bytes),
        (72, header.source_index_bytes),
        (112, header.block_count),
    ] {
        out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    out[80..112].copy_from_slice(&header.source_index_sha256);
    Ok(out)
}

pub fn parse_header(bytes: &[u8]) -> Result<SlotIndexHeader, String> {
    if bytes.len() != SLOT_INDEX_HEADER_LEN {
        return Err("slot index header length differs".into());
    }
    if &bytes[..8] != SLOT_INDEX_MAGIC
        || u16_at(bytes, 8) != SLOT_INDEX_VERSION
        || u16_at(bytes, 10) != SLOT_INDEX_HEADER_LEN as u16
        || u16_at(bytes, 12) != SLOT_INDEX_ROW_LEN as u16
    {
        return Err("unsupported slot index header".into());
    }
    if bytes[14..16]
        .iter()
        .chain(&bytes[120..128])
        .any(|b| *b != 0)
    {
        return Err("slot index header has nonzero reserved bytes".into());
    }
    let header = SlotIndexHeader {
        epoch: u64_at(bytes, 16),
        first_slot: u64_at(bytes, 24),
        slot_count: u64_at(bytes, 32),
        blocks_bytes: u64_at(bytes, 40),
        signatures_bytes: u64_at(bytes, 48),
        registry_bytes: u64_at(bytes, 56),
        blockhash_registry_bytes: u64_at(bytes, 64),
        source_index_bytes: u64_at(bytes, 72),
        source_index_sha256: bytes[80..112].try_into().unwrap(),
        block_count: u64_at(bytes, 112),
    };
    header.validate()?;
    Ok(header)
}

pub fn row_offset(header: &SlotIndexHeader, slot: u64) -> Result<u64, String> {
    let index = slot
        .checked_sub(header.first_slot)
        .filter(|n| *n < header.slot_count)
        .ok_or("requested slot is outside the slot index")?;
    index
        .checked_mul(SLOT_INDEX_ROW_LEN as u64)
        .and_then(|n| n.checked_add(SLOT_INDEX_HEADER_LEN as u64))
        .ok_or_else(|| "slot index row offset overflows".into())
}

pub fn encode_row(row: &SlotIndexRow) -> [u8; SLOT_INDEX_ROW_LEN] {
    let mut bytes = [0; SLOT_INDEX_ROW_LEN];
    let hot = &row.hot;
    bytes[0..4].copy_from_slice(&hot.block_id.to_le_bytes());
    bytes[4..12].copy_from_slice(&hot.slot.to_le_bytes());
    bytes[12..20].copy_from_slice(&hot.compressed_offset.to_le_bytes());
    bytes[20..24].copy_from_slice(&hot.compressed_len.to_le_bytes());
    bytes[24..28].copy_from_slice(&hot.uncompressed_len.to_le_bytes());
    bytes[28..32].copy_from_slice(&hot.tx_count.to_le_bytes());
    bytes[32..40].copy_from_slice(&hot.first_tx_ordinal.to_le_bytes());
    bytes[40..48].copy_from_slice(&hot.first_signature_ordinal.to_le_bytes());
    bytes[48..52].copy_from_slice(&hot.signature_count.to_le_bytes());
    bytes[52..60].copy_from_slice(&row.parent_slot.to_le_bytes());
    bytes[60..92].copy_from_slice(&row.blockhash);
    bytes[92..124].copy_from_slice(&row.previous_blockhash);
    bytes
}

pub fn parse_row(bytes: &[u8]) -> Result<Option<SlotIndexRow>, String> {
    if bytes.len() != SLOT_INDEX_ROW_LEN {
        return Err("slot index row length differs".into());
    }
    if u32_at(bytes, 20) == 0 {
        return if bytes.iter().all(|b| *b == 0) {
            Ok(None)
        } else {
            Err("absent slot index row is not zero".into())
        };
    }
    if bytes[124..128].iter().any(|b| *b != 0) {
        return Err("slot index row has nonzero reserved bytes".into());
    }
    Ok(Some(SlotIndexRow {
        hot: ArchiveV2HotBlockIndexRow {
            block_id: u32_at(bytes, 0),
            slot: u64_at(bytes, 4),
            compressed_offset: u64_at(bytes, 12),
            compressed_len: u32_at(bytes, 20),
            uncompressed_len: u32_at(bytes, 24),
            tx_count: u32_at(bytes, 28),
            first_tx_ordinal: u64_at(bytes, 32),
            first_signature_ordinal: u64_at(bytes, 40),
            signature_count: u32_at(bytes, 48),
        },
        parent_slot: u64_at(bytes, 52),
        blockhash: bytes[60..92].try_into().unwrap(),
        previous_blockhash: bytes[92..124].try_into().unwrap(),
    }))
}

pub fn validate_row(header: &SlotIndexHeader, slot: u64, row: &SlotIndexRow) -> Result<(), String> {
    row_offset(header, slot)?;
    let hot = &row.hot;
    if hot.slot != slot || u64::from(hot.block_id) >= header.block_count {
        return Err("slot index row identity differs".into());
    }
    if (slot == 0 && row.parent_slot != 0) || (slot != 0 && row.parent_slot >= slot) {
        return Err("slot index row has an invalid parent slot".into());
    }
    if hot.compressed_len == 0
        || hot.uncompressed_len == 0
        || u64::from(hot.compressed_len) > MAX_COMPRESSED_BLOCK_BYTES
        || u64::from(hot.uncompressed_len) > MAX_BLOCK_BYTES
    {
        return Err("slot index row exceeds the block byte limit".into());
    }
    if hot
        .compressed_offset
        .checked_add(u64::from(hot.compressed_len))
        .is_none_or(|end| end > header.blocks_bytes)
    {
        return Err("slot index row exceeds the blocks object".into());
    }
    if hot
        .first_signature_ordinal
        .checked_add(u64::from(hot.signature_count))
        .and_then(|end| end.checked_mul(64))
        .is_none_or(|end| end > header.signatures_bytes)
    {
        return Err("slot index row exceeds the signatures object".into());
    }
    Ok(())
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> SlotIndexHeader {
        SlotIndexHeader {
            epoch: 1,
            first_slot: 432_000,
            slot_count: 432_000,
            blocks_bytes: 1000,
            signatures_bytes: 128,
            registry_bytes: 32,
            blockhash_registry_bytes: 64,
            source_index_bytes: 88,
            source_index_sha256: [7; 32],
            block_count: 1,
        }
    }
    fn row() -> SlotIndexRow {
        SlotIndexRow {
            hot: ArchiveV2HotBlockIndexRow {
                block_id: 0,
                slot: 432_010,
                compressed_offset: 50,
                compressed_len: 100,
                uncompressed_len: 200,
                tx_count: 1,
                first_tx_ordinal: 0,
                first_signature_ordinal: 0,
                signature_count: 2,
            },
            parent_slot: 431_999,
            blockhash: [4; 32],
            previous_blockhash: [5; 32],
        }
    }
    #[test]
    fn header_round_trip_and_fixed_geometry() {
        let h = header();
        assert_eq!(parse_header(&encode_header(&h).unwrap()).unwrap(), h);
        assert_eq!(h.file_len().unwrap(), 128 + 432_000 * 128);
        assert_eq!(row_offset(&h, 432_010).unwrap(), 128 + 10 * 128);
        assert!(row_offset(&h, 431_999).is_err());
        assert!(row_offset(&h, 864_000).is_err());
    }
    #[test]
    fn rejects_bad_header_and_truncation() {
        let original = encode_header(&header()).unwrap();
        for n in [0, 8, 12, 14, 120] {
            let mut bytes = original;
            bytes[n] ^= 1;
            assert!(parse_header(&bytes).is_err(), "offset {n}");
        }
        for n in 0..SLOT_INDEX_HEADER_LEN {
            assert!(parse_header(&original[..n]).is_err());
        }
        let mut h = header();
        h.first_slot = u64::MAX;
        assert!(encode_header(&h).is_err());
    }
    #[test]
    fn row_round_trip_keeps_parent_across_epoch_boundary() {
        let r = row();
        let decoded = parse_row(&encode_row(&r)).unwrap().unwrap();
        validate_row(&header(), r.hot.slot, &decoded).unwrap();
        assert_eq!(decoded.parent_slot, 431_999);
        assert_eq!(decoded.blockhash, [4; 32]);
        assert_eq!(decoded.previous_blockhash, [5; 32]);
        assert_eq!(
            decoded.hot.first_signature_ordinal,
            r.hot.first_signature_ordinal
        );
    }
    #[test]
    fn absent_rows_are_unambiguous() {
        assert!(parse_row(&[0; SLOT_INDEX_ROW_LEN]).unwrap().is_none());
        let mut bad = [0; SLOT_INDEX_ROW_LEN];
        bad[4] = 1;
        assert!(parse_row(&bad).is_err());
        let encoded = encode_row(&row());
        for n in 0..SLOT_INDEX_ROW_LEN {
            assert!(parse_row(&encoded[..n]).is_err());
        }
    }
    #[test]
    fn rejects_wrong_identity_overflow_and_object_bounds() {
        let h = header();
        let mut r = row();
        assert!(validate_row(&h, r.hot.slot + 1, &r).is_err());
        r.hot.compressed_offset = u64::MAX;
        assert!(validate_row(&h, r.hot.slot, &r).is_err());
        r = row();
        r.hot.first_signature_ordinal = u64::MAX;
        assert!(validate_row(&h, r.hot.slot, &r).is_err());
        r = row();
        r.parent_slot = r.hot.slot;
        assert!(validate_row(&h, r.hot.slot, &r).is_err());
        let mut bytes = encode_row(&row());
        bytes[127] = 1;
        assert!(parse_row(&bytes).is_err());
    }
}
