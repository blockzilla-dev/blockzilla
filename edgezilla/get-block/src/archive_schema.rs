//! Exact Compact V2 message and metadata wire grammars for the edge reader.
//!
//! The frozen compatibility definitions come from
//! `blockzilla-compact-v2-reader/src/{message_schema,metadata_schema}.rs`.
//! Keep their enum order and field order identical to those definitions.
//! `Vec` has the same Wincode sequence grammar as the historical `SmallVec`.
//! This module contains no native range source, thread, or zstd dependency.
//! Callers select each grammar once for the complete archive generation.

use blockzilla_archive_v2::{
    ArchiveV2ComputeBudgetInstructionData, ArchiveV2HotInstruction, ArchiveV2HotInstructionData,
    ArchiveV2HotLegacyMessage, ArchiveV2HotMessagePayload, ArchiveV2HotV0Message,
    ArchiveV2SystemInstructionData, ArchiveV2VoteHashRef, ArchiveV2VoteStateUpdate,
    ArchiveV2VoteTowerSync,
};
use blockzilla_compact::{
    CompactInnerInstructions, CompactLogStream, CompactMessageHeader, CompactMetaV1,
    CompactReturnData, CompactReward, CompactTokenBalance, CompactTransactionError,
    OwnedCompactAddressTableLookup, OwnedCompactRecentBlockhash,
};
use blockzilla_primitives::{CompactPubkey, bounded_historical_source_wincode_leb128_config};
use wincode::{SchemaRead, SchemaWrite};

pub const CURRENT_MESSAGE_MARKER_FILE: &str = "archive-v2-message-schema-current-v1.marker";
pub const MAY24_MESSAGE_MARKER_FILE: &str =
    "archive-v2-message-schema-may24-pre-unknown-fallbacks-v1.marker";
pub const LEGACY_METADATA_MARKER_FILE: &str =
    "archive-v2-metadata-schema-legacy-raw-error-v1.marker";
pub const CURRENT_MESSAGE_MARKER_BYTES: &[u8; 52] = include_bytes!(
    "../../../crates/compact-v2/blockzilla-compact-v2-reader/assets/archive-v2-message-schema-current-v1.marker"
);
pub const MAY24_MESSAGE_MARKER_BYTES: &[u8; 87] = include_bytes!(
    "../../../crates/compact-v2/blockzilla-compact-v2-reader/assets/archive-v2-message-schema-may24-pre-unknown-fallbacks-v1.marker"
);
pub const LEGACY_METADATA_MARKER_BYTES: &[u8; 58] = include_bytes!(
    "../../../crates/compact-v2/blockzilla-compact-v2-reader/assets/archive-v2-metadata-schema-legacy-raw-error-v1.marker"
);

/// Bounds admission without changing the wire grammar or source integer form.
pub const MAX_RECORD_BYTES: usize = 32 * 1024 * 1024;

const _: () = assert!(
    blockzilla_program_logs::KNOWN_PROGRAM_LOGS_ENABLED,
    "the Worker must decode the complete stored program-log enum"
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageSchema {
    Current,
    May24,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataSchema {
    Current,
    Legacy,
}

/// Explicit source declarations for an operator-pinned archive generation.
/// These never infer a grammar from individual transaction records.
pub(crate) fn message_schema_overrides(
    text: Option<&str>,
) -> Result<std::collections::BTreeMap<u64, MessageSchema>, String> {
    let Some(text) = text else {
        return Ok(Default::default());
    };
    if text.len() > 8192 {
        return Err("message schema declarations exceed 8192 bytes".into());
    }
    let values: std::collections::BTreeMap<String, String> =
        serde_json::from_str(text).map_err(|_| {
            "BZ_MESSAGE_SCHEMA_OVERRIDES must be an epoch-to-schema JSON object".to_string()
        })?;
    values
        .into_iter()
        .map(|(epoch, name)| {
            let number = epoch
                .parse::<u64>()
                .map_err(|_| "message schema epoch is invalid".to_string())?;
            if number.to_string() != epoch {
                return Err("message schema epoch must use canonical decimal digits".into());
            }
            let schema = match name.as_str() {
                "current" => MessageSchema::Current,
                "may24" => MessageSchema::May24,
                _ => return Err("message schema must be current or may24".into()),
            };
            Ok((number, schema))
        })
        .collect()
}

pub(crate) fn metadata_schema_override(
    text: Option<&str>,
) -> Result<Option<MetadataSchema>, String> {
    match text {
        None | Some("markers") => Ok(None),
        Some("current") => Ok(Some(MetadataSchema::Current)),
        Some("legacy") => Ok(Some(MetadataSchema::Legacy)),
        _ => Err("BZ_METADATA_SCHEMA must be markers, current or legacy".into()),
    }
}

/// Decode the selected grammar exactly. Source integers can contain padding.
/// A parse failure never causes a retry with another grammar.
pub fn decode_message(
    schema: MessageSchema,
    bytes: &[u8],
) -> Result<ArchiveV2HotMessagePayload, String> {
    check_record_size(bytes)?;
    let config = bounded_historical_source_wincode_leb128_config::<MAX_RECORD_BYTES>();
    match schema {
        MessageSchema::Current => wincode::config::deserialize_exact(bytes, config)
            .map_err(|error| format!("decode {schema:?} Compact V2 message: {error}")),
        MessageSchema::May24 => {
            let historical: May24Message = wincode::config::deserialize_exact(bytes, config)
                .map_err(|error| format!("decode {schema:?} Compact V2 message: {error}"))?;
            Ok(historical.into())
        }
    }
}

/// Decode the selected metadata grammar, including failed legacy transactions.
pub fn decode_metadata(schema: MetadataSchema, bytes: &[u8]) -> Result<CompactMetaV1, String> {
    check_record_size(bytes)?;
    let config = bounded_historical_source_wincode_leb128_config::<MAX_RECORD_BYTES>();
    match schema {
        MetadataSchema::Current => wincode::config::deserialize_exact(bytes, config)
            .map_err(|error| format!("decode {schema:?} Compact V2 metadata: {error}")),
        MetadataSchema::Legacy => {
            let historical: LegacyMetadata = wincode::config::deserialize_exact(bytes, config)
                .map_err(|error| format!("decode {schema:?} Compact V2 metadata: {error}"))?;
            historical.try_into()
        }
    }
}

fn check_record_size(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(format!(
            "Compact V2 record exceeds {MAX_RECORD_BYTES} bytes"
        ));
    }
    Ok(())
}

#[derive(Debug, SchemaRead, SchemaWrite)]
enum May24Message {
    Legacy(May24LegacyMessage),
    V0(May24V0Message),
}

#[derive(Debug, SchemaRead, SchemaWrite)]
struct May24LegacyMessage {
    header: CompactMessageHeader,
    account_keys: Vec<CompactPubkey>,
    recent_blockhash: OwnedCompactRecentBlockhash,
    instructions: Vec<May24Instruction>,
}

#[derive(Debug, SchemaRead, SchemaWrite)]
struct May24V0Message {
    header: CompactMessageHeader,
    account_keys: Vec<CompactPubkey>,
    recent_blockhash: OwnedCompactRecentBlockhash,
    instructions: Vec<May24Instruction>,
    address_table_lookups: Vec<OwnedCompactAddressTableLookup>,
}

#[derive(Debug, SchemaRead, SchemaWrite)]
struct May24Instruction {
    program_id_index: u8,
    accounts: Vec<u8>,
    data: May24InstructionData,
}

/// Frozen pre-2026-06-25 enum order. Do not insert current fallback variants.
#[derive(Debug, SchemaRead, SchemaWrite)]
enum May24InstructionData {
    Raw(Vec<u8>),
    ComputeBudget(ArchiveV2ComputeBudgetInstructionData),
    System(ArchiveV2SystemInstructionData),
    VoteCompactUpdateVoteState(ArchiveV2VoteStateUpdate),
    VoteCompactUpdateVoteStateSwitch {
        update: ArchiveV2VoteStateUpdate,
        switch_proof_hash: ArchiveV2VoteHashRef,
    },
    VoteTowerSync(ArchiveV2VoteTowerSync),
    VoteTowerSyncSwitch {
        tower: ArchiveV2VoteTowerSync,
        switch_proof_hash: ArchiveV2VoteHashRef,
    },
}

impl From<May24Message> for ArchiveV2HotMessagePayload {
    fn from(value: May24Message) -> Self {
        match value {
            May24Message::Legacy(message) => Self::Legacy(ArchiveV2HotLegacyMessage {
                header: message.header,
                account_keys: message.account_keys,
                recent_blockhash: message.recent_blockhash,
                instructions: message.instructions.into_iter().map(Into::into).collect(),
            }),
            May24Message::V0(message) => Self::V0(ArchiveV2HotV0Message {
                header: message.header,
                account_keys: message.account_keys,
                recent_blockhash: message.recent_blockhash,
                instructions: message.instructions.into_iter().map(Into::into).collect(),
                address_table_lookups: message.address_table_lookups,
            }),
        }
    }
}

impl From<May24Instruction> for ArchiveV2HotInstruction {
    fn from(value: May24Instruction) -> Self {
        Self {
            program_id_index: value.program_id_index,
            accounts: value.accounts,
            data: value.data.into(),
        }
    }
}

impl From<May24InstructionData> for ArchiveV2HotInstructionData {
    fn from(value: May24InstructionData) -> Self {
        match value {
            May24InstructionData::Raw(bytes) => Self::Raw(bytes),
            May24InstructionData::ComputeBudget(data) => Self::ComputeBudget(data),
            May24InstructionData::System(data) => Self::System(data),
            May24InstructionData::VoteCompactUpdateVoteState(update) => {
                Self::VoteCompactUpdateVoteState(update)
            }
            May24InstructionData::VoteCompactUpdateVoteStateSwitch {
                update,
                switch_proof_hash,
            } => Self::VoteCompactUpdateVoteStateSwitch {
                update,
                switch_proof_hash,
            },
            May24InstructionData::VoteTowerSync(tower) => Self::VoteTowerSync(tower),
            May24InstructionData::VoteTowerSyncSwitch {
                tower,
                switch_proof_hash,
            } => Self::VoteTowerSyncSwitch {
                tower,
                switch_proof_hash,
            },
        }
    }
}

/// Frozen field order before the error field became typed.
#[derive(Debug, SchemaRead, SchemaWrite)]
struct LegacyMetadata {
    err: Option<Vec<u8>>,
    fee: u64,
    pre_balances: Vec<u64>,
    post_balances: Vec<u64>,
    inner_instructions: Option<Vec<CompactInnerInstructions>>,
    logs: Option<CompactLogStream>,
    pre_token_balances: Vec<CompactTokenBalance>,
    post_token_balances: Vec<CompactTokenBalance>,
    rewards: Vec<CompactReward>,
    loaded_writable_addresses: Vec<CompactPubkey>,
    loaded_readonly_addresses: Vec<CompactPubkey>,
    return_data: Option<CompactReturnData>,
    compute_units_consumed: Option<u64>,
    cost_units: Option<u64>,
}

impl TryFrom<LegacyMetadata> for CompactMetaV1 {
    type Error = String;

    fn try_from(value: LegacyMetadata) -> Result<Self, Self::Error> {
        let err = value
            .err
            .as_deref()
            .map(CompactTransactionError::from_stored_wincode_bytes)
            .transpose()
            .map_err(|error| format!("decode stored legacy transaction error: {error}"))?;
        Ok(Self {
            err,
            fee: value.fee,
            pre_balances: value.pre_balances,
            post_balances: value.post_balances,
            inner_instructions: value.inner_instructions,
            logs: value.logs,
            pre_token_balances: value.pre_token_balances,
            post_token_balances: value.post_token_balances,
            rewards: value.rewards,
            loaded_writable_addresses: value.loaded_writable_addresses,
            loaded_readonly_addresses: value.loaded_readonly_addresses,
            return_data: value.return_data,
            compute_units_consumed: value.compute_units_consumed,
            cost_units: value.cost_units,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_schema_declarations_are_explicit_and_checked() {
        let values = message_schema_overrides(Some(r#"{"0":"may24","900":"current"}"#)).unwrap();
        assert_eq!(values.get(&0), Some(&MessageSchema::May24));
        assert_eq!(values.get(&900), Some(&MessageSchema::Current));
        for value in [r#"{"00":"may24"}"#, r#"{"0":"guess"}"#, "[]", r#"{"0":4}"#] {
            assert!(message_schema_overrides(Some(value)).is_err());
        }
        assert_eq!(metadata_schema_override(None).unwrap(), None);
        assert_eq!(
            metadata_schema_override(Some("legacy")).unwrap(),
            Some(MetadataSchema::Legacy)
        );
        assert!(metadata_schema_override(Some("guess")).is_err());
    }

    #[test]
    fn foundation_metadata_with_known_program_log_keeps_complete_wire_grammar() {
        let bytes = include_bytes!("../tests/fixtures/slot-470987967-tx-71-metadata.wincode");
        let meta =
            decode_metadata(MetadataSchema::Current, bytes).expect("exact Foundation metadata");
        assert!(meta.err.is_none());
        assert_eq!(meta.fee, 34_571);
        assert_eq!(meta.compute_units_consumed, Some(234_870));
        assert_eq!(meta.cost_units, Some(247_078));
        assert_eq!(meta.pre_balances.len(), 46);
        assert_eq!(meta.post_balances.len(), 46);
        assert_eq!(meta.pre_token_balances.len(), 13);
        assert_eq!(meta.post_token_balances.len(), 13);
        assert!(blockzilla_program_logs::program_logs::KNOWN_PROGRAM_LOGS_ENABLED);
        assert!(
            meta.logs
                .as_ref()
                .unwrap()
                .events
                .iter()
                .any(|event| matches!(
                    event,
                    blockzilla_compact::LogEvent::ProgramLog(
                        blockzilla_program_logs::program_logs::ProgramLog::Known(_)
                    ) | blockzilla_compact::LogEvent::ProgramPlainLog(
                        blockzilla_program_logs::program_logs::ProgramLog::Known(_)
                    ) | blockzilla_compact::LogEvent::ProgramIdLog {
                        log: blockzilla_program_logs::program_logs::ProgramLog::Known(_),
                        ..
                    }
                ))
        );
    }
    use blockzilla_compact::CompactInstructionError;
    use blockzilla_primitives::wincode_leb128_config;

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn current_message(data: ArchiveV2HotInstructionData) -> ArchiveV2HotMessagePayload {
        ArchiveV2HotMessagePayload::Legacy(ArchiveV2HotLegacyMessage {
            header: CompactMessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 0,
            },
            account_keys: vec![CompactPubkey::Id(1)],
            recent_blockhash: OwnedCompactRecentBlockhash::Id(2),
            instructions: vec![ArchiveV2HotInstruction {
                program_id_index: 0,
                accounts: vec![0],
                data,
            }],
        })
    }

    #[test]
    fn current_unknown_instruction_fallbacks_keep_the_current_enum_order() {
        for (data, expected) in [
            (ArchiveV2HotInstructionData::UnknownSystem(vec![7, 8]), 1),
            (ArchiveV2HotInstructionData::UnknownVote(vec![9, 10]), 2),
        ] {
            let bytes = wincode::config::serialize(&current_message(data), wincode_leb128_config())
                .unwrap();
            let ArchiveV2HotMessagePayload::Legacy(decoded) =
                decode_message(MessageSchema::Current, &bytes).unwrap()
            else {
                panic!("expected legacy message");
            };
            match (&decoded.instructions[0].data, expected) {
                (ArchiveV2HotInstructionData::UnknownSystem(data), 1) => assert_eq!(data, &[7, 8]),
                (ArchiveV2HotInstructionData::UnknownVote(data), 2) => assert_eq!(data, &[9, 10]),
                _ => panic!("wrong fallback variant"),
            }
        }
    }

    #[test]
    fn real_may24_message_keeps_exact_bytes_and_selected_variant_order() {
        // This exact source fixture is also checked by the native reader.
        let bytes = decode_hex(
            "0002010206121813150e0d00c0e60c02040202000209ccf1736d29ad6e301871d2d5a34e01709272ebdc60b9b855a31b7c3036fae9360131c80106a1d8179137542a983437bdfe2a7ab2557f535c8a78722b68a49dc0000000000503030201000c030000000080c6a47e8d0300",
        );
        let frozen: May24Message =
            wincode::config::deserialize_exact(&bytes, wincode_leb128_config()).unwrap();
        assert_eq!(
            wincode::config::serialize(&frozen, wincode_leb128_config()).unwrap(),
            bytes
        );
        assert!(decode_message(MessageSchema::Current, &bytes).is_err());
        let ArchiveV2HotMessagePayload::Legacy(message) =
            decode_message(MessageSchema::May24, &bytes).unwrap()
        else {
            panic!("expected legacy message");
        };
        assert!(matches!(&message.instructions[0].data,
            ArchiveV2HotInstructionData::System(ArchiveV2SystemInstructionData::AllocateWithSeed { seed, space: 200, .. }) if seed == "1"));
        assert!(matches!(&message.instructions[1].data,
            ArchiveV2HotInstructionData::Raw(bytes) if bytes == &decode_hex("030000000080c6a47e8d0300")));
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_message(MessageSchema::May24, &trailing).is_err());
    }

    fn metadata(err: Option<CompactTransactionError>) -> CompactMetaV1 {
        CompactMetaV1 {
            err,
            fee: 5_000,
            pre_balances: vec![10, 20],
            post_balances: vec![9, 21],
            inner_instructions: None,
            logs: None,
            pre_token_balances: Vec::new(),
            post_token_balances: Vec::new(),
            rewards: Vec::new(),
            loaded_writable_addresses: Vec::new(),
            loaded_readonly_addresses: Vec::new(),
            return_data: None,
            compute_units_consumed: Some(42),
            cost_units: Some(84),
        }
    }

    #[test]
    fn current_failed_transaction_error_decodes_without_legacy_retry() {
        let bytes = wincode::config::serialize(
            &metadata(Some(CompactTransactionError::InvalidProgramForExecution)),
            wincode_leb128_config(),
        )
        .unwrap();
        let decoded = decode_metadata(MetadataSchema::Current, &bytes).unwrap();
        assert!(matches!(
            decoded.err,
            Some(CompactTransactionError::InvalidProgramForExecution)
        ));
        assert_eq!(decoded.fee, 5_000);
        assert_eq!(decoded.compute_units_consumed, Some(42));
        assert_eq!(decoded.cost_units, Some(84));
    }

    #[test]
    fn stored_metadata_decodes_known_program_log_tag_seventeen() {
        // Fixed wire fixture: one ProgramLog::Known Phoenix instruction Swap.
        // This tag was rejected by an isolated Worker build with log features
        // disabled, although a whole-workspace native test could mask it.
        let bytes = [
            0, 136, 39, 2, 10, 20, 2, 9, 21, 0, 1, 1, 5, 17, 3, 0, 1,
            // Empty string lengths/bytes and data arrays/chunk lengths/bytes.
            0, 0, 0, 0, 0, // Empty token balances, rewards, loaded addresses, return data.
            0, 0, 0, 0, 0, 0, // Present compute and cost units.
            1, 42, 1, 84,
        ];
        let decoded = decode_metadata(MetadataSchema::Current, &bytes).unwrap();
        let logs = decoded.logs.unwrap();
        assert!(matches!(
            &logs.events[..],
            [blockzilla_compact::LogEvent::ProgramLog(
                blockzilla_program_logs::ProgramLog::Known(
                    blockzilla_program_logs::known_programs::KnownProgramLog::PhoenixV1(
                        blockzilla_program_logs::known_programs::phoenix_v1::PhoenixLog::Instruction(
                            blockzilla_program_logs::known_programs::phoenix_v1::PhoenixInstructionLog::Swap
                        )
                    )
                )
            )]
        ));
        assert_eq!(decoded.fee, 5000);
        assert_eq!(decoded.compute_units_consumed, Some(42));
        assert_eq!(decoded.cost_units, Some(84));
    }

    #[test]
    fn real_epoch_900_legacy_failed_transaction_uses_the_selected_grammar() {
        let bytes = [
            0x01, 0x0d, 0x08, 0x00, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x90, 0x4e, 0x03, 0xcc, 0xef, 0xf0, 0xf2, 0x32, 0x80, 0xf6, 0xed, 0xdf, 0x09,
            0x01, 0x03, 0xbc, 0xa1, 0xf0, 0xf2, 0x32, 0x80, 0xf6, 0xed, 0xdf, 0x09, 0x01, 0x01,
            0x00, 0x01, 0x02, 0x0e, 0x03, 0x01, 0x16, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xb4, 0x10, 0x01, 0xe4, 0x1a,
        ];
        assert!(decode_metadata(MetadataSchema::Current, &bytes).is_err());
        let decoded = decode_metadata(MetadataSchema::Legacy, &bytes).unwrap();
        assert!(matches!(
            decoded.err,
            Some(CompactTransactionError::InstructionError(
                0,
                CompactInstructionError::Custom(0)
            ))
        ));
        assert_eq!(decoded.fee, 10_000);
        assert_eq!(decoded.pre_balances, [13_662_697_420, 2_616_949_504, 1]);
        assert_eq!(decoded.post_balances, [13_662_687_420, 2_616_949_504, 1]);
        assert_eq!(decoded.compute_units_consumed, Some(2_100));
        assert_eq!(decoded.cost_units, Some(3_428));
        let mut trailing = bytes.to_vec();
        trailing.push(0xff);
        assert!(decode_metadata(MetadataSchema::Legacy, &trailing).is_err());
    }

    #[test]
    fn current_and_legacy_source_integers_can_have_padding() {
        let canonical =
            wincode::config::serialize(&metadata(None), wincode_leb128_config()).unwrap();
        // The first metadata byte is the None error tag; the next is the fee.
        let mut padded = canonical.clone();
        padded[2] |= 0x80;
        padded.insert(3, 0);
        for schema in [MetadataSchema::Current, MetadataSchema::Legacy] {
            assert_eq!(decode_metadata(schema, &padded).unwrap().fee, 5_000);
        }
        assert!(
            wincode::config::deserialize_exact::<CompactMetaV1, _>(
                &padded,
                wincode_leb128_config()
            )
            .is_err()
        );

        let canonical = wincode::config::serialize(
            &current_message(ArchiveV2HotInstructionData::Raw(Vec::new())),
            wincode_leb128_config(),
        )
        .unwrap();
        // The first message byte is the Legacy enum tag. Pad that source tag.
        let mut padded = canonical;
        padded[0] |= 0x80;
        padded.insert(1, 0);
        assert!(decode_message(MessageSchema::Current, &padded).is_ok());
        assert!(decode_message(MessageSchema::May24, &padded).is_ok());
    }

    #[test]
    fn hostile_declared_sequence_lengths_do_not_allocate_unbounded_memory() {
        // Legacy message with a valid three-byte header followed by an
        // account sequence claiming u64::MAX elements.
        let bytes = [
            0, 1, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1,
        ];
        assert!(decode_message(MessageSchema::Current, &bytes).is_err());
        assert!(decode_message(MessageSchema::May24, &bytes).is_err());
    }
}
