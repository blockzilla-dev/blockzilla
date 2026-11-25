//! Local reconstruction from a checked resolution object and a parts frame.
//! The renderer uses the same codec as the Worker. It does not fetch objects.

use super::*;
use crate::slot_resolution::{self, LocatorV1};

pub const PARTS_HEADER_LEN: usize = 64;
pub const MAX_PARTS_BYTES: usize = PARTS_HEADER_LEN + 16 * 1024 * 1024 + 8 * 1024 * 1024;

/// Wall time and, where available, CPU time for this process. CPU time includes
/// all process threads; it is not a Cloudflare CPU billing measurement.
#[derive(Debug, Serialize)]
pub struct ClientStepTime {
    pub elapsed_ms: f64,
    pub process_cpu_ms: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct ClientRenderProfile {
    pub slot: u64,
    pub transactions: u32,
    pub resolution_bytes: usize,
    pub parts_bytes: usize,
    pub compressed_block_bytes: usize,
    pub decoded_block_bytes: usize,
    pub signature_bytes: usize,
    pub json_bytes: usize,
    pub resolution_decode: ClientStepTime,
    pub parts_validate: ClientStepTime,
    pub block_decode: ClientStepTime,
    pub access_decode: ClientStepTime,
    pub json_render: ClientStepTime,
    pub total: ClientStepTime,
}

#[derive(Debug, Serialize)]
pub struct ClientWorkload {
    pub slot: u64,
    pub transactions: usize,
    pub instructions: usize,
    pub proof_transactions: usize,
    pub ambiguous_tower_instructions: usize,
    pub raw_instruction_bytes: usize,
    pub max_raw_instruction_bytes: usize,
}

/// Count proof inputs separately from the timed renderer. This does not
/// estimate a native or Worker CPU cost from the input byte count.
pub fn inspect_resolution_parts_workload(
    resolution_bytes: &[u8],
    parts_bytes: &[u8],
) -> std::result::Result<ClientWorkload, String> {
    let resolution = slot_resolution::decode(resolution_bytes)?;
    let locator = resolution.locator();
    let (compressed, _) = validated_parts(&locator, parts_bytes)?;
    let (_, block) = stored::decode_block(
        &offline_source(),
        locator.hot.slot,
        &locator.hot.into(),
        compressed,
    )?;
    let schema = match locator.message_schema {
        slot_resolution::MESSAGE_CURRENT => MessageSchema::Current,
        slot_resolution::MESSAGE_MAY24 => MessageSchema::May24,
        _ => return Err("unsupported client message schema".into()),
    };
    let mut result = ClientWorkload {
        slot: locator.hot.slot,
        transactions: block.tx_rows.len(),
        instructions: 0,
        proof_transactions: 0,
        ambiguous_tower_instructions: 0,
        raw_instruction_bytes: 0,
        max_raw_instruction_bytes: 0,
    };
    for row in &block.tx_rows {
        let message = decode_message(&block, row, schema)?;
        let instructions = match &message {
            ArchiveV2HotMessagePayload::Legacy(message) => &message.instructions,
            ArchiveV2HotMessagePayload::V0(message) => &message.instructions,
            ArchiveV2HotMessagePayload::V1(message) => &message.instructions,
        };
        let mut proof = false;
        result.instructions += instructions.len();
        for instruction in instructions {
            match &instruction.data {
                ArchiveV2HotInstructionData::VoteTowerSync(_)
                | ArchiveV2HotInstructionData::VoteTowerSyncSwitch { .. } => {
                    result.ambiguous_tower_instructions += 1;
                    proof = true;
                }
                ArchiveV2HotInstructionData::Raw(bytes)
                | ArchiveV2HotInstructionData::UnknownSystem(bytes)
                | ArchiveV2HotInstructionData::UnknownVote(bytes) => {
                    result.raw_instruction_bytes += bytes.len();
                    result.max_raw_instruction_bytes =
                        result.max_raw_instruction_bytes.max(bytes.len());
                }
                _ => {}
            }
        }
        result.proof_transactions += usize::from(proof);
    }
    Ok(result)
}

struct StepTimer {
    wall: f64,
    cpu: Option<f64>,
}

impl StepTimer {
    fn start() -> Self {
        Self {
            wall: now_ms(),
            cpu: process_cpu_ms(),
        }
    }

    fn finish(self) -> ClientStepTime {
        ClientStepTime {
            elapsed_ms: (now_ms() - self.wall).max(0.0),
            process_cpu_ms: self
                .cpu
                .zip(process_cpu_ms())
                .and_then(|(start, end)| (end >= start).then_some(end - start)),
        }
    }
}

#[cfg(all(target_os = "macos", target_pointer_width = "64"))]
fn process_cpu_ms() -> Option<f64> {
    unsafe extern "C" {
        fn clock() -> std::ffi::c_ulong;
    }
    // The macOS SDK defines clock_t as unsigned long and CLOCKS_PER_SEC as
    // 1,000,000. No pointer crosses this C ABI boundary.
    let value = unsafe { clock() };
    (value != std::ffi::c_ulong::MAX).then_some(value as f64 / 1000.0)
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn process_cpu_ms() -> Option<f64> {
    unsafe extern "C" {
        fn clock() -> std::ffi::c_long;
    }
    // Linux uses signed long clock_t and the POSIX 1,000,000 ticks per second.
    let value = unsafe { clock() };
    (value >= 0).then_some(value as f64 / 1000.0)
}

#[cfg(not(all(
    any(target_os = "macos", target_os = "linux"),
    target_pointer_width = "64"
)))]
fn process_cpu_ms() -> Option<f64> {
    None
}

/// Render a full Base64 JSON-RPC getBlock response with id 1 from two local files.
/// The caller must trust the downloaded resolution source. SHA256 detects a
/// mismatch between the parts frame and that resolution; it is not a signature.
pub async fn render_resolution_parts_json(
    resolution_bytes: &[u8],
    parts_bytes: &[u8],
    include_rewards: bool,
) -> std::result::Result<Vec<u8>, String> {
    render_resolution_parts_json_profiled(resolution_bytes, parts_bytes, include_rewards)
        .await
        .map(|(json, _)| json)
}

pub async fn render_resolution_parts_json_profiled(
    resolution_bytes: &[u8],
    parts_bytes: &[u8],
    include_rewards: bool,
) -> std::result::Result<(Vec<u8>, ClientRenderProfile), String> {
    let total = StepTimer::start();
    let stage = StepTimer::start();
    let resolution = slot_resolution::decode(resolution_bytes)?;
    let locator = resolution.locator();
    let resolution_decode = stage.finish();

    let stage = StepTimer::start();
    let (compressed, signatures) = validated_parts(&locator, parts_bytes)?;
    let parts_validate = stage.finish();

    let source = offline_source();
    let row: ArchiveV2HotBlockIndexRow = locator.hot.into();
    let stage = StepTimer::start();
    let (decoded, block) = stored::decode_block(&source, locator.hot.slot, &row, compressed)?;
    let decoded_len = decoded.len();
    // The owned block has its message and metadata regions. Release the full
    // decompressed frame before the access tables and JSON output are allocated.
    drop(decoded);
    if block.header.parent_slot != locator.parent_slot {
        return Err("parts block parent differs from the resolution".into());
    }
    let block_decode = stage.finish();

    let stage = StepTimer::start();
    let access = resolution.into_access(signatures.to_vec())?;
    validate_access_blob(&access, &row)?;
    if block
        .tx_rows
        .iter()
        .map(|tx| tx.signature_count)
        .ne(access.signature_counts.iter().copied())
    {
        return Err("parts transaction signature counts differ from the resolution".into());
    }
    let access_decode = stage.finish();
    let fetched = FetchedHotBlock {
        epoch: locator.epoch,
        index_row: ArchiveV2GetBlockIndexRow {
            block_offset: row.compressed_offset,
            block_len: row.compressed_len,
            access_offset: 0,
            access_len: 0,
        },
        row,
        decoded_len,
        block,
        access: Some(FetchedAccess::Full(access)),
        message_schema: match locator.message_schema {
            slot_resolution::MESSAGE_CURRENT => MessageSchema::Current,
            slot_resolution::MESSAGE_MAY24 => MessageSchema::May24,
            _ => return Err("unsupported client message schema".into()),
        },
        metadata_schema: match locator.metadata_schema {
            slot_resolution::METADATA_CURRENT => MetadataSchema::Current,
            slot_resolution::METADATA_LEGACY => MetadataSchema::Legacy,
            _ => return Err("unsupported client metadata schema".into()),
        },
    };
    let stage = StepTimer::start();
    let full_access = fetched
        .access
        .as_ref()
        .and_then(FetchedAccess::full)
        .ok_or("client block access is missing")?;
    let mut writer = JsonByteWriter::with_capacity(full_json_capacity_hint(&fetched, full_access));
    stream_json_rpc_success_prefix(&mut writer);
    block_base64::stream_full_value_into(
        &source,
        &fetched,
        GetBlockConfig {
            transaction_details: TransactionDetails::Full,
            rewards: include_rewards,
        },
        &mut writer,
    )
    .await?;
    stream_json_rpc_success_suffix(&mut writer, &Value::from(1))?;
    let json = writer.into_inner();
    let json_render = stage.finish();
    if source.storage_metrics.snapshot() != StorageSnapshot::default() {
        return Err("client renderer attempted an archive operation".into());
    }
    let profile = ClientRenderProfile {
        slot: locator.hot.slot,
        transactions: locator.hot.tx_count,
        resolution_bytes: resolution_bytes.len(),
        parts_bytes: parts_bytes.len(),
        compressed_block_bytes: compressed.len(),
        decoded_block_bytes: decoded_len,
        signature_bytes: signatures.len(),
        json_bytes: json.len(),
        resolution_decode,
        parts_validate,
        block_decode,
        access_decode,
        json_render,
        total: total.finish(),
    };
    Ok((json, profile))
}

fn validated_parts<'a>(
    locator: &LocatorV1,
    bytes: &'a [u8],
) -> std::result::Result<(&'a [u8], &'a [u8]), String> {
    if bytes.len() < PARTS_HEADER_LEN || bytes.len() > MAX_PARTS_BYTES || &bytes[..8] != b"BZPART2!"
    {
        return Err("invalid client parts header or byte length".into());
    }
    let number = |offset| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
    let hot_len = locator.hot.compressed_len as usize;
    let sig_len = locator.signature_bytes()?;
    let expected = PARTS_HEADER_LEN
        .checked_add(hot_len)
        .and_then(|length| length.checked_add(sig_len))
        .ok_or("client parts byte length overflows")?;
    if number(8) != locator.hot.slot
        || number(16) != hot_len as u64
        || number(24) != sig_len as u64
        || bytes.len() != expected
    {
        return Err("client parts slot or byte lengths differ from the resolution".into());
    }
    if Sha256::digest(locator.wincode_bytes()?).as_slice() != &bytes[32..64] {
        return Err("client parts locator SHA256 differs from the resolution".into());
    }
    let hot_end = PARTS_HEADER_LEN + hot_len;
    Ok((&bytes[PARTS_HEADER_LEN..hot_end], &bytes[hot_end..]))
}

fn offline_source() -> WorkerSource {
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

#[cfg(test)]
mod tests {
    use super::*;
    use blockzilla_archive_v2::{
        ARCHIVE_V2_TX_FLAG_HAS_ERROR, ArchiveV2HotBlockHeader, ArchiveV2HotInstruction,
        ArchiveV2HotLegacyMessage, ArchiveV2HotRewards,
    };
    use blockzilla_compact::{CompactMessageHeader, CompactTransactionError};
    use slot_resolution::{NamedSourceObject, ResolutionV1, SourceObjectIdentity};

    // One real Wincode/zstd transaction uses registry IDs, a failed metadata
    // record, a signature window, and a parent separated by one skipped slot.
    fn fixture(block_parent: u64) -> (Vec<u8>, Vec<u8>) {
        let message = ArchiveV2HotMessagePayload::Legacy(ArchiveV2HotLegacyMessage {
            header: CompactMessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 1,
            },
            account_keys: vec![CompactPubkey::Id(1), CompactPubkey::Id(2)],
            recent_blockhash: OwnedCompactRecentBlockhash::Id(0),
            instructions: vec![ArchiveV2HotInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: ArchiveV2HotInstructionData::Raw(vec![1, 2, 3]),
            }],
        });
        let meta = CompactMetaV1 {
            err: Some(CompactTransactionError::InsufficientFundsForFee),
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
            compute_units_consumed: Some(123),
            cost_units: Some(456),
        };
        let message_bytes = wincode::config::serialize(&message, wincode_leb128_config()).unwrap();
        let metadata_bytes = wincode::config::serialize(&meta, wincode_leb128_config()).unwrap();
        let block = ArchiveV2HotBlockBlob {
            header: ArchiveV2HotBlockHeader {
                slot: 432_002,
                parent_slot: block_parent,
                blockhash_id: 1,
                previous_blockhash_id: 0,
                block_time: Some(1_700_000_001),
                block_height: Some(101),
                rewards: Some(ArchiveV2HotRewards {
                    num_partitions: Some(1),
                    decoded: vec![CompactReward {
                        pubkey: CompactPubkey::Id(1),
                        lamports: 25,
                        post_balance: 900,
                        reward_type: 1,
                        commission: None,
                    }],
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
        };
        let decoded = wincode::config::serialize(&block, wincode_leb128_config()).unwrap();
        let compressed = zstd::bulk::compress(&decoded, 1).unwrap();
        let blocks = SourceObjectIdentity {
            length: 100 + compressed.len() as u64,
            etag: "\"client-blocks-v1\"".into(),
        };
        let signatures = SourceObjectIdentity {
            length: 128,
            etag: "\"client-sigs-v1\"".into(),
        };
        let locator = LocatorV1 {
            version: slot_resolution::VERSION,
            source_prefix: "compact-v2/client-fixture".into(),
            generation: "g1".into(),
            epoch: 1,
            hot: slot_resolution::ResolutionHotRow {
                block_id: 1,
                slot: 432_002,
                compressed_offset: 100,
                compressed_len: compressed.len() as u32,
                uncompressed_len: decoded.len() as u32,
                tx_count: 1,
                first_tx_ordinal: 1,
                first_signature_ordinal: 1,
                signature_count: 1,
            },
            parent_slot: 432_000,
            blockhash: [11; 32],
            previous_blockhash: [10; 32],
            message_schema: slot_resolution::MESSAGE_CURRENT,
            metadata_schema: slot_resolution::METADATA_CURRENT,
            blocks: blocks.clone(),
            signatures: signatures.clone(),
        };
        let access = ArchiveV2BlockAccessBlob {
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
        };
        let resolution = ResolutionV1::new(
            locator.clone(),
            vec![
                NamedSourceObject {
                    name: "archive-v2-blocks.zstd".into(),
                    identity: blocks,
                },
                NamedSourceObject {
                    name: "signatures.bin".into(),
                    identity: signatures,
                },
            ],
            &access,
        )
        .unwrap();
        let mut parts = b"BZPART2!".to_vec();
        parts.extend_from_slice(&locator.hot.slot.to_le_bytes());
        parts.extend_from_slice(&(compressed.len() as u64).to_le_bytes());
        parts.extend_from_slice(&64u64.to_le_bytes());
        parts.extend_from_slice(&Sha256::digest(locator.wincode_bytes().unwrap()));
        parts.extend_from_slice(&compressed);
        parts.extend_from_slice(&access.signatures);
        (slot_resolution::encode(&resolution).unwrap(), parts)
    }

    #[tokio::test]
    async fn reconstructs_registry_keys_failure_signatures_and_real_parent_offline() {
        let (resolution, parts) = fixture(432_000);
        let (bytes, profile) = render_resolution_parts_json_profiled(&resolution, &parts, true)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&bytes).unwrap();
        let block = &json["result"];
        assert_eq!(json["id"], 1);
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(block["parentSlot"], 432_000);
        assert_eq!(block["blockhash"], base58_32(&[11; 32]));
        assert_eq!(block["previousBlockhash"], base58_32(&[10; 32]));
        assert_eq!(block["rewards"][0]["pubkey"], base58_32(&[41; 32]));
        assert_eq!(block["numRewardPartitions"], 1);
        let transaction = &block["transactions"][0];
        assert_eq!(transaction["transaction"][1], "base64");
        let wire = BASE64
            .decode(transaction["transaction"][0].as_str().unwrap())
            .unwrap();
        let mut expected_wire = vec![1];
        expected_wire.extend_from_slice(&[77; 64]);
        expected_wire.extend_from_slice(&[1, 0, 1, 2]);
        expected_wire.extend_from_slice(&[41; 32]);
        expected_wire.extend_from_slice(&[42; 32]);
        expected_wire.extend_from_slice(&[10; 32]);
        expected_wire.extend_from_slice(&[1, 1, 1, 0, 3, 1, 2, 3]);
        assert_eq!(wire, expected_wire);
        assert_eq!(transaction["version"], "legacy");
        assert_eq!(transaction["meta"]["err"], "InsufficientFundsForFee");
        assert_eq!(transaction["meta"]["fee"], 5000);
        assert_eq!(profile.slot, 432_002);
        assert_eq!(profile.json_bytes, bytes.len());
        assert_eq!(profile.signature_bytes, 64);
        assert!(profile.total.elapsed_ms.is_finite());
        let without_rewards: Value = serde_json::from_slice(
            &render_resolution_parts_json(&resolution, &parts, false)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(without_rewards["result"].get("rewards").is_none());
        assert!(
            without_rewards["result"]
                .get("numRewardPartitions")
                .is_none()
        );
        assert!(without_rewards["result"]["transactions"][0]["meta"]["rewards"].is_null());
    }

    #[test]
    fn rejects_malformed_parts_and_stale_locator_before_decode() {
        let (resolution, parts) = fixture(432_000);
        let mut locator = slot_resolution::decode(&resolution).unwrap().locator();
        assert!(validated_parts(&locator, &parts).is_ok());
        for length in [0, 7, 63, parts.len() - 1] {
            assert!(validated_parts(&locator, &parts[..length]).is_err());
        }
        for offset in [0, 8, 16, 24, 32, 63] {
            let mut corrupt = parts.clone();
            corrupt[offset] ^= 1;
            assert!(
                validated_parts(&locator, &corrupt).is_err(),
                "offset {offset}"
            );
        }
        let mut extra = parts.clone();
        extra.push(0);
        assert!(validated_parts(&locator, &extra).is_err());
        locator.generation = "g2".into();
        assert!(
            validated_parts(&locator, &parts)
                .unwrap_err()
                .contains("SHA256")
        );
    }

    #[tokio::test]
    async fn rejects_bad_resolution_compression_and_parent() {
        let (resolution, parts) = fixture(432_000);
        let mut corrupt_resolution = resolution.clone();
        *corrupt_resolution.last_mut().unwrap() ^= 1;
        assert!(
            render_resolution_parts_json(&corrupt_resolution, &parts, true)
                .await
                .unwrap_err()
                .contains("SHA256")
        );
        let mut corrupt_parts = parts.clone();
        corrupt_parts[PARTS_HEADER_LEN] ^= 1;
        assert!(
            render_resolution_parts_json(&resolution, &corrupt_parts, true)
                .await
                .is_err()
        );
        let (resolution, parts) = fixture(432_001);
        assert!(
            render_resolution_parts_json(&resolution, &parts, true)
                .await
                .unwrap_err()
                .contains("parent differs")
        );
    }

    #[tokio::test]
    async fn missing_local_dictionary_entry_fails_without_registry_fetch() {
        let (resolution, parts) = fixture(432_000);
        let original = slot_resolution::decode(&resolution).unwrap();
        let locator = original.locator();
        let source_objects = original.source_objects.clone();
        let mut access = original.into_access(vec![77; 64]).unwrap();
        access.pubkeys.remove(0);
        let incomplete =
            slot_resolution::encode(&ResolutionV1::new(locator, source_objects, &access).unwrap())
                .unwrap();
        let error = render_resolution_parts_json(&incomplete, &parts, true)
            .await
            .unwrap_err();
        assert!(error.contains("registry fallback is disabled"), "{error}");
    }
}
