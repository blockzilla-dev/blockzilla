//! Recover ambiguous TowerSync instruction bytes from transaction signatures.
//!
//! The archive decoder can retain both the current and the historical wire
//! forms. Use the same whole-message serializer and proof as the native reader
//! before exposing either form as Solana JSON instruction data.
#[allow(dead_code)]
#[path = "../../../../crates/compact-v2/blockzilla-compact-v2-reader/src/signed_message.rs"]
pub(super) mod signed_message;

use super::*;
use blockzilla_archive_v2::ArchiveV2HotInstruction;
use signed_message::{
    MAX_SIGNED_MESSAGE_CANDIDATE_COMBINATIONS, ResolvedAddressTableLookup, SelectedSignedMessage,
    SignedInstructionCandidates, SignedMessageCandidates, SignedMessageError, SignedMessageVersion,
    SignedTransactionConfig, VoteHashResolver, reconstruct_instruction_data_candidates,
    select_signed_message_candidate_ed25519,
};

/// Resolve a TowerSync message only when its erased wire form needs proof.
pub(super) async fn resolve_message(
    message: &mut ArchiveV2HotMessagePayload,
    resolver: &mut Resolver<'_>,
    signatures: &[u8],
) -> std::result::Result<(), String> {
    if !instructions(message).iter().any(|ix| ambiguous(&ix.data)) {
        return Ok(());
    }

    let selected = {
        let (header, static_keys, recent_hash, lookups) = match &*message {
            ArchiveV2HotMessagePayload::Legacy(message) => (
                message.header,
                &message.account_keys,
                &message.recent_blockhash,
                &[][..],
            ),
            ArchiveV2HotMessagePayload::V0(message) => (
                message.header,
                &message.account_keys,
                &message.recent_blockhash,
                message.address_table_lookups.as_slice(),
            ),
            ArchiveV2HotMessagePayload::V1(message) => (
                message.header,
                &message.account_keys,
                &message.recent_blockhash,
                &[][..],
            ),
        };
        let signatures = checked_signatures(header.num_required_signatures, signatures)?;
        if static_keys.len() > 256 {
            return Err("TowerSync signed message has more than 256 static account keys".into());
        }
        let mut resolved_keys = Vec::with_capacity(static_keys.len());
        for key in static_keys {
            resolved_keys.push(resolver.resolve_pubkey_bytes(*key).await?);
        }
        let recent_hash = resolver.resolve_recent_blockhash_bytes(recent_hash).await?;
        let mut resolved_lookups = Vec::with_capacity(lookups.len());
        for lookup in lookups {
            resolved_lookups.push(ResolvedAddressTableLookup {
                account_key: resolver.resolve_pubkey_bytes(lookup.account_key).await?,
                writable_indexes: &lookup.writable_indexes,
                readonly_indexes: &lookup.readonly_indexes,
            });
        }
        select_message(
            message,
            &resolved_keys,
            recent_hash,
            &resolved_lookups,
            &VoteResolver(resolver),
            &signatures,
        )?
    };
    apply_selection(message, selected)
}

fn checked_signatures(required: u8, bytes: &[u8]) -> std::result::Result<Vec<[u8; 64]>, String> {
    let expected = usize::from(required)
        .checked_mul(64)
        .ok_or_else(|| "TowerSync signature byte count overflows".to_string())?;
    if bytes.len() != expected {
        return Err(format!(
            "TowerSync message requires {required} signatures ({expected} bytes), but the archive supplied {} bytes",
            bytes.len()
        ));
    }
    bytes
        .chunks_exact(64)
        .map(|bytes| {
            bytes
                .try_into()
                .map_err(|_| "TowerSync signature does not have 64 bytes".to_string())
        })
        .collect()
}

struct VoteResolver<'r, 's>(&'r Resolver<'s>);

impl VoteHashResolver for VoteResolver<'_, '_> {
    fn resolve_vote_hash(
        &self,
        block_id: u32,
        kind: signed_message::VoteHashKind,
    ) -> std::result::Result<[u8; 32], SignedMessageError> {
        let worker_kind = match kind {
            signed_message::VoteHashKind::Bank => VoteHashKind::Bank,
            signed_message::VoteHashKind::BlockId => VoteHashKind::BlockId,
        };
        self.0
            .resolve_vote_hash_ref(ArchiveV2VoteHashRef::Block(block_id), worker_kind)
            .map_err(|_| SignedMessageError::MissingVoteHash { block_id, kind })
    }
}

fn select_message(
    message: &ArchiveV2HotMessagePayload,
    static_keys: &[[u8; 32]],
    recent_blockhash: [u8; 32],
    lookups: &[ResolvedAddressTableLookup<'_>],
    vote_hashes: &dyn VoteHashResolver,
    signatures: &[[u8; 64]],
) -> std::result::Result<SelectedSignedMessage, String> {
    let (header, version) = match message {
        ArchiveV2HotMessagePayload::Legacy(message) => {
            (message.header, SignedMessageVersion::Legacy)
        }
        ArchiveV2HotMessagePayload::V0(message) => (
            message.header,
            SignedMessageVersion::V0 {
                address_table_lookups: lookups,
            },
        ),
        ArchiveV2HotMessagePayload::V1(message) => (
            message.header,
            SignedMessageVersion::V1 {
                config: SignedTransactionConfig {
                    priority_fee: message.config.priority_fee,
                    compute_unit_limit: message.config.compute_unit_limit,
                    loaded_accounts_data_size_limit: message.config.loaded_accounts_data_size_limit,
                    heap_size: message.config.heap_size,
                },
            },
        ),
    };
    let instructions = instructions(message);
    let choices = instructions
        .iter()
        .map(|instruction| {
            reconstruct_instruction_data_candidates(&instruction.data, Some(vote_hashes)).map_err(
                |error| format!("reconstruct TowerSync signed-message instruction: {error}"),
            )
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let candidates = instructions
        .iter()
        .zip(&choices)
        .map(
            |(instruction, data_candidates)| SignedInstructionCandidates {
                program_id_index: instruction.program_id_index,
                accounts: &instruction.accounts,
                data_candidates,
            },
        )
        .collect::<Vec<_>>();
    select_signed_message_candidate_ed25519(
        &SignedMessageCandidates {
            version,
            header,
            static_account_keys: static_keys,
            recent_blockhash,
            instructions: &candidates,
        },
        MAX_SIGNED_MESSAGE_CANDIDATE_COMBINATIONS,
        signatures,
    )
    .map_err(|error| format!("prove TowerSync instruction bytes: {error}"))
}

fn apply_selection(
    message: &mut ArchiveV2HotMessagePayload,
    selected: SelectedSignedMessage,
) -> std::result::Result<(), String> {
    let instructions = match message {
        ArchiveV2HotMessagePayload::Legacy(message) => &mut message.instructions,
        ArchiveV2HotMessagePayload::V0(message) => &mut message.instructions,
        ArchiveV2HotMessagePayload::V1(message) => &mut message.instructions,
    };
    if selected.instruction_data.len() != instructions.len() {
        return Err("TowerSync proof instruction count differs from the decoded message".into());
    }
    for (instruction, bytes) in instructions.iter_mut().zip(selected.instruction_data) {
        if ambiguous(&instruction.data) {
            instruction.data = ArchiveV2HotInstructionData::Raw(bytes);
        }
    }
    Ok(())
}

fn instructions(message: &ArchiveV2HotMessagePayload) -> &[ArchiveV2HotInstruction] {
    match message {
        ArchiveV2HotMessagePayload::Legacy(message) => &message.instructions,
        ArchiveV2HotMessagePayload::V0(message) => &message.instructions,
        ArchiveV2HotMessagePayload::V1(message) => &message.instructions,
    }
}

fn ambiguous(data: &ArchiveV2HotInstructionData) -> bool {
    matches!(
        data,
        ArchiveV2HotInstructionData::VoteTowerSync(_)
            | ArchiveV2HotInstructionData::VoteTowerSyncSwitch { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use blockzilla_archive_v2::{ArchiveV2HotLegacyMessage, ArchiveV2VoteLockoutOffset};
    use blockzilla_compact::CompactMessageHeader;
    use ed25519_dalek::{Signer, SigningKey};
    use signed_message::{
        InstructionDataEncoding, SignedInstruction, SignedMessage, serialize_signed_message,
    };

    struct Hashes;
    impl VoteHashResolver for Hashes {
        fn resolve_vote_hash(
            &self,
            block_id: u32,
            kind: signed_message::VoteHashKind,
        ) -> std::result::Result<[u8; 32], SignedMessageError> {
            match (block_id, kind) {
                (7, signed_message::VoteHashKind::Bank) => Ok([31; 32]),
                (8, signed_message::VoteHashKind::BlockId) => Ok([32; 32]),
                _ => Err(SignedMessageError::MissingVoteHash { block_id, kind }),
            }
        }
    }

    fn message(signer: [u8; 32], switch: bool) -> ArchiveV2HotMessagePayload {
        let tower = ArchiveV2VoteTowerSync {
            update: ArchiveV2VoteStateUpdate {
                root: Some(100),
                lockout_offsets: vec![ArchiveV2VoteLockoutOffset {
                    offset: 2,
                    confirmation_count: 1,
                }],
                hash: ArchiveV2VoteHashRef::Block(7),
                timestamp: Some(1_700_000_000),
            },
            block_id_hash: ArchiveV2VoteHashRef::Block(8),
        };
        let data = if switch {
            ArchiveV2HotInstructionData::VoteTowerSyncSwitch {
                tower,
                switch_proof_hash: ArchiveV2VoteHashRef::Raw([33; 32]),
            }
        } else {
            ArchiveV2HotInstructionData::VoteTowerSync(tower)
        };
        ArchiveV2HotMessagePayload::Legacy(ArchiveV2HotLegacyMessage {
            header: CompactMessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 1,
            },
            account_keys: vec![CompactPubkey::Raw(signer), CompactPubkey::Raw([9; 32])],
            recent_blockhash: OwnedCompactRecentBlockhash::Nonce([10; 32]),
            instructions: vec![ArchiveV2HotInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data,
            }],
        })
    }

    #[test]
    fn proves_and_renders_both_real_tower_wire_forms() {
        let signer = SigningKey::from_bytes(&[1; 32]);
        let keys = [signer.verifying_key().to_bytes(), [9; 32]];
        for switch in [false, true] {
            for encoding in [
                InstructionDataEncoding::VoteTowerCanonical,
                InstructionDataEncoding::VoteTowerHistorical,
            ] {
                let mut message = message(keys[0], switch);
                let instruction = &instructions(&message)[0];
                let choices =
                    reconstruct_instruction_data_candidates(&instruction.data, Some(&Hashes))
                        .unwrap();
                let choice = choices
                    .iter()
                    .find(|choice| choice.encoding == encoding)
                    .unwrap();
                let header = match &message {
                    ArchiveV2HotMessagePayload::Legacy(message) => message.header,
                    _ => unreachable!(),
                };
                let signed_instructions = [SignedInstruction {
                    program_id_index: instruction.program_id_index,
                    accounts: &instruction.accounts,
                    data: &choice.bytes,
                }];
                let bytes = serialize_signed_message(&SignedMessage {
                    version: SignedMessageVersion::Legacy,
                    header,
                    static_account_keys: &keys,
                    recent_blockhash: [10; 32],
                    instructions: &signed_instructions,
                })
                .unwrap();
                let signature = signer.sign(&bytes).to_bytes();
                let selected =
                    select_message(&message, &keys, [10; 32], &[], &Hashes, &[signature]).unwrap();
                assert_eq!(selected.signed_message, bytes);
                assert_eq!(selected.instruction_data, vec![choice.bytes.to_vec()]);
                let expected = choice.bytes.to_vec();
                apply_selection(&mut message, selected).unwrap();
                match &instructions(&message)[0].data {
                    ArchiveV2HotInstructionData::Raw(actual) => assert_eq!(actual, &expected),
                    _ => panic!("TowerSync must render the signature-proved raw bytes"),
                }
                assert!(
                    select_message(&message, &keys, [10; 32], &[], &Hashes, &[[0; 64]]).is_err()
                );
            }
        }
    }

    #[test]
    fn rejects_partial_extra_and_missing_signature_bytes() {
        assert!(checked_signatures(1, &[0; 63]).is_err());
        assert!(checked_signatures(1, &[0; 65]).is_err());
        assert!(checked_signatures(1, &[]).is_err());
        assert!(checked_signatures(1, &[0; 128]).is_err());
        assert_eq!(checked_signatures(1, &[7; 64]).unwrap(), vec![[7; 64]]);
    }
}
