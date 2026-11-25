//! Solana getBlock with Base64 transaction wire bytes and normal RPC metadata.

use super::*;
use std::borrow::Cow;
use vote_proof::signed_message::{
    self, ResolvedAddressTableLookup, SignedInstruction, SignedMessage, SignedMessageError,
    SignedMessageVersion, SignedTransactionConfig, VoteHashResolver, reconstruct_instruction_data,
    serialize_signed_message,
};

const MAX_TRANSACTION_WIRE_BYTES: usize = 65_536;

pub(super) async fn stream_full_value_into(
    source: &WorkerSource,
    fetched: &FetchedHotBlock,
    config: GetBlockConfig,
    writer: &mut JsonByteWriter,
) -> std::result::Result<(), String> {
    let started = now_ms();
    let start_len = writer.len();
    let access = fetched
        .access
        .as_ref()
        .ok_or("Base64 getBlock requires block access")?;
    let full_access = access
        .full()
        .ok_or("Base64 getBlock requires full block access")?;
    let mut resolver = Resolver::new(source, Some(full_access));
    write_block_header_fields(writer, fetched, access);
    if config.rewards {
        writer.raw(b",\"rewards\":");
        stream_rewards_value(writer, &mut resolver, fetched.block.header.rewards.as_ref()).await?;
        stream_reward_partitions(writer, fetched.block.header.rewards.as_ref());
    }
    writer.raw(b",\"transactions\":[");
    let mut signature_index = 0usize;
    for (index, row) in fetched.block.tx_rows.iter().enumerate() {
        if index != 0 {
            writer.raw(b",");
        }
        let signatures = transaction_signature_bytes(fetched, row, signature_index)?;
        let mut message = decode_message(&fetched.block, row, fetched.message_schema)?;
        vote_proof::resolve_message(&mut message, &mut resolver, signatures).await?;
        let (wire_message, required) = message_wire_bytes(&message, &mut resolver).await?;
        if usize::from(required) != usize::from(row.signature_count) {
            return Err(format!(
                "transaction {} signature count differs from its message header",
                row.tx_index
            ));
        }
        writer.raw(b"{\"transaction\":[\"");
        write_transaction_base64(
            writer,
            signatures,
            required,
            &wire_message,
            matches!(message, ArchiveV2HotMessagePayload::V1(_)),
        )?;
        writer.raw(b"\",\"base64\"],\"meta\":");
        let metadata = decode_metadata(&fetched.block, row, fetched.metadata_schema)?;
        stream_metadata_value(writer, &mut resolver, metadata.as_ref(), config.rewards).await?;
        writer.raw(b",\"version\":");
        stream_message_version_value(writer, &message);
        writer.raw(b"}");
        signature_index = signature_index
            .checked_add(usize::from(row.signature_count))
            .ok_or("Base64 signature ordinal overflows")?;
        if index & 0x3f == 0x3f || writer.pending_bytes() >= JSON_STREAM_CHUNK_BYTES {
            writer.flush_chunk_async().await?;
        }
    }
    if signature_index.checked_mul(SIGNATURE_BYTES as usize) != Some(access.signatures().len()) {
        return Err("Base64 signature window has trailing bytes".into());
    }
    writer.raw(b"]}");
    source.record_elapsed(
        "render_base64_get_block",
        started,
        writer.len().saturating_sub(start_len) as u64,
        "full",
        None,
    );
    Ok(())
}

struct VoteHashes<'a, 'b>(&'a Resolver<'b>);

impl VoteHashResolver for VoteHashes<'_, '_> {
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

async fn message_wire_bytes(
    message: &ArchiveV2HotMessagePayload,
    resolver: &mut Resolver<'_>,
) -> std::result::Result<(Vec<u8>, u8), String> {
    let (header, keys, hash, instructions, lookups) = match message {
        ArchiveV2HotMessagePayload::Legacy(message) => (
            message.header,
            &message.account_keys,
            &message.recent_blockhash,
            &message.instructions,
            &[][..],
        ),
        ArchiveV2HotMessagePayload::V0(message) => (
            message.header,
            &message.account_keys,
            &message.recent_blockhash,
            &message.instructions,
            message.address_table_lookups.as_slice(),
        ),
        ArchiveV2HotMessagePayload::V1(message) => (
            message.header,
            &message.account_keys,
            &message.recent_blockhash,
            &message.instructions,
            &[][..],
        ),
    };
    let mut static_keys = Vec::with_capacity(keys.len());
    for key in keys {
        static_keys.push(resolver.resolve_pubkey_bytes(*key).await?);
    }
    let recent_blockhash = resolver.resolve_recent_blockhash_bytes(hash).await?;
    let mut resolved_lookups = Vec::with_capacity(lookups.len());
    for lookup in lookups {
        resolved_lookups.push(ResolvedAddressTableLookup {
            account_key: resolver.resolve_pubkey_bytes(lookup.account_key).await?,
            writable_indexes: &lookup.writable_indexes,
            readonly_indexes: &lookup.readonly_indexes,
        });
    }
    let version = match message {
        ArchiveV2HotMessagePayload::Legacy(_) => SignedMessageVersion::Legacy,
        ArchiveV2HotMessagePayload::V0(_) => SignedMessageVersion::V0 {
            address_table_lookups: &resolved_lookups,
        },
        ArchiveV2HotMessagePayload::V1(message) => SignedMessageVersion::V1 {
            config: SignedTransactionConfig {
                priority_fee: message.config.priority_fee,
                compute_unit_limit: message.config.compute_unit_limit,
                loaded_accounts_data_size_limit: message.config.loaded_accounts_data_size_limit,
                heap_size: message.config.heap_size,
            },
        },
    };
    let vote_hashes = VoteHashes(resolver);
    let data = instructions
        .iter()
        .map(|instruction| match &instruction.data {
            ArchiveV2HotInstructionData::Raw(bytes)
            | ArchiveV2HotInstructionData::UnknownSystem(bytes)
            | ArchiveV2HotInstructionData::UnknownVote(bytes) => {
                Ok(Cow::Borrowed(bytes.as_slice()))
            }
            value => reconstruct_instruction_data(value, Some(&vote_hashes))
                .map(Cow::Owned)
                .map_err(|error| format!("reconstruct transaction instruction: {error}")),
        })
        .collect::<std::result::Result<Vec<_>, String>>()?;
    let wire_instructions = instructions
        .iter()
        .zip(&data)
        .map(|(instruction, data)| SignedInstruction {
            program_id_index: instruction.program_id_index,
            accounts: &instruction.accounts,
            data,
        })
        .collect::<Vec<_>>();
    let bytes = serialize_signed_message(&SignedMessage {
        version,
        header,
        static_account_keys: &static_keys,
        recent_blockhash,
        instructions: &wire_instructions,
    })
    .map_err(|error| format!("serialize transaction message: {error}"))?;
    Ok((bytes, header.num_required_signatures))
}

fn write_transaction_base64(
    writer: &mut JsonByteWriter,
    signatures: &[u8],
    count: u8,
    message: &[u8],
    message_first: bool,
) -> std::result::Result<(), String> {
    if signatures.len() != usize::from(count) * SIGNATURE_BYTES as usize {
        return Err("Base64 transaction signature window has an invalid byte length".into());
    }
    let count = u16::from(count);
    let mut prefix = [0; 2];
    prefix[0] = (count & 0x7f) as u8;
    let prefix_len = if message_first {
        0
    } else if count >= 128 {
        prefix[0] |= 0x80;
        prefix[1] = (count >> 7) as u8;
        2
    } else {
        1
    };
    let total = prefix_len + signatures.len() + message.len();
    if total > MAX_TRANSACTION_WIRE_BYTES {
        return Err("Base64 transaction exceeds its 64 KiB wire limit".into());
    }
    // V1 writes the message followed by fixed-length signatures, with no count
    // prefix. Legacy/V0 write ShortU16(count), signatures, then the message.
    // Feed one continuous Base64 stream without a transaction Vec or String.
    let mut encoder = base64::write::EncoderWriter::new(writer, &BASE64);
    let result = if message_first {
        encoder
            .write_all(message)
            .and_then(|_| encoder.write_all(signatures))
    } else {
        encoder
            .write_all(&prefix[..prefix_len])
            .and_then(|_| encoder.write_all(signatures))
            .and_then(|_| encoder.write_all(message))
    };
    result
        .and_then(|_| encoder.finish().map(|_| ()))
        .map_err(|error| format!("encode Base64 transaction: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use blockzilla_archive_v2::{
        ARCHIVE_V2_TX_FLAG_HAS_ERROR, ArchiveV2HotBlockHeader, ArchiveV2HotInstruction,
        ArchiveV2HotLegacyMessage, ArchiveV2HotV0Message, ArchiveV2HotV1Message,
    };
    use blockzilla_compact::{CompactInnerInstruction, CompactMessageHeader};
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

    fn fetched(version: u8) -> FetchedHotBlock {
        let header = CompactMessageHeader {
            num_required_signatures: 1,
            num_readonly_signed_accounts: 0,
            num_readonly_unsigned_accounts: 1,
        };
        let keys = vec![CompactPubkey::Id(1), CompactPubkey::Id(2)];
        let hash = OwnedCompactRecentBlockhash::Id(0);
        let instructions = vec![ArchiveV2HotInstruction {
            program_id_index: 1,
            accounts: vec![0],
            data: ArchiveV2HotInstructionData::Raw(vec![1, 2, 3]),
        }];
        let message = match version {
            0 => ArchiveV2HotMessagePayload::V0(ArchiveV2HotV0Message {
                header,
                account_keys: keys,
                recent_blockhash: hash,
                instructions,
                address_table_lookups: vec![OwnedCompactAddressTableLookup {
                    account_key: CompactPubkey::Raw([43; 32]),
                    writable_indexes: vec![2],
                    readonly_indexes: vec![3],
                }],
            }),
            1 => ArchiveV2HotMessagePayload::V1(ArchiveV2HotV1Message {
                header,
                account_keys: keys,
                recent_blockhash: hash,
                instructions,
                config: CompactTransactionConfig {
                    priority_fee: Some(0),
                    ..Default::default()
                },
            }),
            _ => ArchiveV2HotMessagePayload::Legacy(ArchiveV2HotLegacyMessage {
                header,
                account_keys: keys,
                recent_blockhash: hash,
                instructions,
            }),
        };
        let metadata = CompactMetaV1 {
            err: Some(StoredTransactionError::InsufficientFundsForFee),
            fee: 5000,
            pre_balances: vec![10_000, 1],
            post_balances: vec![5000, 1],
            inner_instructions: Some(vec![CompactInnerInstructions {
                index: 0,
                instructions: vec![CompactInnerInstruction {
                    program_id_index: 1,
                    accounts: vec![0],
                    data: vec![9, 8],
                    stack_height: Some(2),
                }],
            }]),
            logs: None,
            pre_token_balances: vec![],
            post_token_balances: vec![],
            rewards: vec![],
            loaded_writable_addresses: vec![],
            loaded_readonly_addresses: vec![],
            return_data: None,
            compute_units_consumed: Some(123),
            cost_units: Some(456),
        };
        let message_bytes = wincode::config::serialize(&message, wincode_leb128_config()).unwrap();
        let metadata_bytes =
            wincode::config::serialize(&metadata, wincode_leb128_config()).unwrap();
        let row = ArchiveV2HotBlockIndexRow {
            block_id: 1,
            slot: 432_002,
            compressed_offset: 0,
            compressed_len: 1,
            uncompressed_len: 1,
            tx_count: 1,
            first_tx_ordinal: 1,
            first_signature_ordinal: 1,
            signature_count: 1,
        };
        FetchedHotBlock {
            epoch: 1,
            index_row: ArchiveV2GetBlockIndexRow {
                block_offset: 0,
                block_len: 1,
                access_offset: 0,
                access_len: 0,
            },
            row,
            decoded_len: message_bytes.len() + metadata_bytes.len(),
            block: ArchiveV2HotBlockBlob {
                header: ArchiveV2HotBlockHeader {
                    slot: 432_002,
                    parent_slot: 432_000,
                    blockhash_id: 1,
                    previous_blockhash_id: 0,
                    block_time: Some(1_700_000_000),
                    block_height: Some(101),
                    rewards: None,
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
            },
            access: Some(FetchedAccess::Full(ArchiveV2BlockAccessBlob {
                version: WINCODE_ARCHIVE_V2_BLOCK_ACCESS_VERSION,
                flags: 0,
                blockhash: [11; 32],
                previous_blockhash: [10; 32],
                signature_counts: vec![1],
                signatures: vec![77; 64],
                pubkeys: vec![
                    ArchiveV2BlockAccessPubkey {
                        id: 1,
                        pubkey: [41; 32],
                    },
                    ArchiveV2BlockAccessPubkey {
                        id: 2,
                        pubkey: [42; 32],
                    },
                ],
                blockhashes: vec![ArchiveV2BlockAccessBlockhash {
                    id: 0,
                    blockhash: [10; 32],
                }],
                vote_hashes: vec![],
            })),
            message_schema: MessageSchema::Current,
            metadata_schema: MetadataSchema::Current,
        }
    }

    #[test]
    fn preserves_legacy_v0_and_v1_wire_versions_and_standard_failure_metadata() {
        for version in [255, 0, 1] {
            let source = source();
            let fetched = fetched(version);
            let mut writer = JsonByteWriter::with_capacity(4096);
            stream_full_value_into(
                &source,
                &fetched,
                GetBlockConfig {
                    transaction_details: TransactionDetails::Full,
                    rewards: false,
                },
                &mut writer,
            )
            .now_or_never()
            .expect("local renderer completes without I/O")
            .unwrap();
            let json: Value = serde_json::from_slice(&writer.into_inner()).unwrap();
            let entry = &json["transactions"][0];
            assert_eq!(entry["transaction"][1], "base64");
            let wire = BASE64
                .decode(entry["transaction"][0].as_str().unwrap())
                .unwrap();
            if version == 1 {
                assert_eq!(entry["version"], 1);
                // Independent SIMD-0385 packet layout, with Some(0) priority
                // fee retained and fixed-length signatures after the message.
                let mut expected = vec![0x81, 1, 0, 1, 3, 0, 0, 0];
                expected.extend_from_slice(&[10; 32]);
                expected.extend_from_slice(&[1, 2]);
                expected.extend_from_slice(&[41; 32]);
                expected.extend_from_slice(&[42; 32]);
                expected.extend_from_slice(&0u64.to_le_bytes());
                expected.extend_from_slice(&[1, 1, 3, 0]);
                expected.extend_from_slice(&[0, 1, 2, 3]);
                expected.extend_from_slice(&[77; 64]);
                assert_eq!(wire, expected);
            } else {
                let mut expected = vec![1];
                expected.extend_from_slice(&[77; 64]);
                if version == 0 {
                    expected.push(0x80);
                }
                expected.extend_from_slice(&[1, 0, 1, 2]);
                expected.extend_from_slice(&[41; 32]);
                expected.extend_from_slice(&[42; 32]);
                expected.extend_from_slice(&[10; 32]);
                expected.extend_from_slice(&[1, 1, 1, 0, 3, 1, 2, 3]);
                if version == 0 {
                    expected.push(1);
                    expected.extend_from_slice(&[43; 32]);
                    expected.extend_from_slice(&[1, 2, 1, 3]);
                    assert_eq!(entry["version"], 0);
                } else {
                    assert_eq!(entry["version"], "legacy");
                }
                assert_eq!(wire, expected);
            }
            assert_eq!(json["parentSlot"], 432_000);
            assert_eq!(entry["meta"]["err"], "InsufficientFundsForFee");
            assert_eq!(entry["meta"]["status"]["Err"], "InsufficientFundsForFee");
            assert_eq!(
                entry["meta"]["innerInstructions"][0]["instructions"][0]["data"],
                bs58::encode([9, 8]).into_string()
            );
            assert!(json.get("rewards").is_none());
            assert_eq!(
                source.storage_metrics.snapshot(),
                StorageSnapshot::default()
            );
        }
    }

    #[test]
    fn streams_continuous_base64_across_signature_boundaries_and_rejects_invalid_windows() {
        for count in [0u8, 1, 2, 127, 128, 255] {
            let signatures = vec![77; usize::from(count) * 64];
            let mut writer = JsonByteWriter::with_capacity(512);
            write_transaction_base64(&mut writer, &signatures, count, &[1, 2, 3, 4, 5], false)
                .unwrap();
            let encoded = writer.into_inner();
            let decoded = BASE64.decode(encoded).unwrap();
            let prefix = if count < 128 {
                vec![count]
            } else {
                vec![(count & 127) | 128, 1]
            };
            assert_eq!(decoded, [prefix, signatures, vec![1, 2, 3, 4, 5]].concat());
        }
        assert!(
            write_transaction_base64(
                &mut JsonByteWriter::with_capacity(0),
                &[0; 63],
                1,
                &[],
                false
            )
            .is_err()
        );
        assert!(
            write_transaction_base64(
                &mut JsonByteWriter::with_capacity(0),
                &[],
                0,
                &vec![0; MAX_TRANSACTION_WIRE_BYTES],
                false
            )
            .is_err()
        );
    }
}
