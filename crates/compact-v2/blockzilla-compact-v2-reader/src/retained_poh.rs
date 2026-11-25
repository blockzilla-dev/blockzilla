//! Frozen Compact V2 PoH payload grammars used by archive validation.
//!
//! These records also appeared in the Archive V3 prototype. They belong to
//! the retained V2 source format and do not require that prototype's container.
//! The caller validates the outer frame and selects one grammar before decoding.

use thiserror::Error;
use wincode::{SchemaRead, SchemaWrite, config::Configuration};

const PREALLOCATION_SIZE_LIMIT: usize = 64 << 20;
type RetainedPohConfig = Configuration<
    true,
    PREALLOCATION_SIZE_LIMIT,
    wincode::len::BincodeLen,
    wincode::int_encoding::LittleEndian,
    blockzilla_primitives::Leb128,
    u8,
>;

fn wire_config() -> RetainedPohConfig {
    Configuration::default()
        .with_preallocation_size_limit::<PREALLOCATION_SIZE_LIMIT>()
        .with_int_encoding::<blockzilla_primitives::Leb128>()
        .with_tag_encoding::<u8>()
}

/// The explicit historical names identify the frozen source grammars.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PohWireProfile {
    ArchiveV2CurrentWincode055 = 1,
    ArchiveV2LegacyNoSignatureCountWincode055 = 2,
}

#[derive(Debug, Clone, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CurrentPohRecord {
    pub block_id: u32,
    pub slot: u64,
    pub entries: Vec<CurrentPohEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CurrentPohEntry {
    pub num_hashes: u64,
    pub hash: [u8; 32],
    pub transaction_count: u32,
    pub signature_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct LegacyPohRecord {
    pub block_id: u32,
    pub slot: u64,
    pub entries: Vec<LegacyPohEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct LegacyPohEntry {
    pub num_hashes: u64,
    pub hash: [u8; 32],
    pub transaction_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedPohFrame {
    Current(CurrentPohRecord),
    LegacyNoSignatureCount(LegacyPohRecord),
}

impl DecodedPohFrame {
    pub const fn identity(&self) -> (u32, u64) {
        match self {
            Self::Current(record) => (record.block_id, record.slot),
            Self::LegacyNoSignatureCount(record) => (record.block_id, record.slot),
        }
    }

    pub fn entry_count(&self) -> usize {
        match self {
            Self::Current(record) => record.entries.len(),
            Self::LegacyNoSignatureCount(record) => record.entries.len(),
        }
    }

    pub fn final_hash(&self) -> Option<&[u8; 32]> {
        match self {
            Self::Current(record) => record.entries.last().map(|entry| &entry.hash),
            Self::LegacyNoSignatureCount(record) => record.entries.last().map(|entry| &entry.hash),
        }
    }
}

/// Decode exactly one payload with canonical integers and a bounded allocation.
/// A failure never retries another grammar.
pub fn decode_payload(
    profile: PohWireProfile,
    payload: &[u8],
) -> Result<DecodedPohFrame, PohError> {
    Ok(match profile {
        PohWireProfile::ArchiveV2CurrentWincode055 => {
            DecodedPohFrame::Current(wincode::config::deserialize_exact(payload, wire_config())?)
        }
        PohWireProfile::ArchiveV2LegacyNoSignatureCountWincode055 => {
            DecodedPohFrame::LegacyNoSignatureCount(wincode::config::deserialize_exact(
                payload,
                wire_config(),
            )?)
        }
    })
}

#[derive(Debug, Error)]
pub enum PohError {
    #[error("PoH Wincode: {0}")]
    Wincode(#[from] wincode::ReadError),
}

#[cfg(test)]
pub(crate) fn encode<T>(value: &T) -> wincode::WriteResult<Vec<u8>>
where
    T: SchemaWrite<RetainedPohConfig, Src = T> + ?Sized,
{
    wincode::config::serialize(value, wire_config())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_profiles_keep_frozen_bytes() {
        let current = CurrentPohRecord {
            block_id: 7,
            slot: 100,
            entries: vec![CurrentPohEntry {
                num_hashes: 2,
                hash: [9; 32],
                transaction_count: 1,
                signature_count: 2,
            }],
        };
        let mut expected = vec![7, 100, 1, 2];
        expected.extend_from_slice(&[9; 32]);
        expected.extend_from_slice(&[1, 2]);
        assert_eq!(encode(&current).unwrap(), expected);
        assert_eq!(
            decode_payload(PohWireProfile::ArchiveV2CurrentWincode055, &expected).unwrap(),
            DecodedPohFrame::Current(current)
        );

        let legacy = LegacyPohRecord {
            block_id: 7,
            slot: 100,
            entries: vec![LegacyPohEntry {
                num_hashes: 2,
                hash: [9; 32],
                transaction_count: 1,
            }],
        };
        expected.pop();
        assert_eq!(encode(&legacy).unwrap(), expected);
        assert_eq!(
            decode_payload(
                PohWireProfile::ArchiveV2LegacyNoSignatureCountWincode055,
                &expected,
            )
            .unwrap(),
            DecodedPohFrame::LegacyNoSignatureCount(legacy)
        );
        assert!(decode_payload(PohWireProfile::ArchiveV2CurrentWincode055, &expected).is_err());
    }

    #[test]
    fn retained_payload_rejects_padding_trailing_bytes_and_oversized_sequences() {
        let profile = PohWireProfile::ArchiveV2CurrentWincode055;
        assert!(decode_payload(profile, &[0x80, 0, 0, 0]).is_err());
        assert!(decode_payload(profile, &[0, 0, 0, 0]).is_err());
        assert!(decode_payload(profile, &[0, 0, 0x81, 0x80, 0x80, 0x20]).is_err());
    }
}
