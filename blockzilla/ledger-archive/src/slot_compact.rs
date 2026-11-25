//! One RAM-only ledger response. This is not a native stream frame or an R2
//! archive locator, and it contains no stream cursor or native root proof.

use std::io::Write;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use blockzilla_archive_v2::ArchiveV2HotBlockIndexRow;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::convert::encode_slot_bundle;
use crate::ledger::{SlotReadFailure, load_slot, open_read_only};
use crate::source::SlotData;

pub(crate) const MAGIC: &[u8; 8] = b"BZLGR01!";
pub(crate) const MAX_METADATA_BYTES: usize = 4096;
pub(crate) const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_HOT_BYTES: usize = 32 * 1024 * 1024;
pub(crate) const MAX_TRANSACTIONS: usize = 65_536;
const READ_DEADLINE: Duration = Duration::from_secs(10);

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct HotRow {
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

impl From<ArchiveV2HotBlockIndexRow> for HotRow {
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

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Metadata {
    pub version: u16,
    pub slot: u64,
    pub parent_slot: u64,
    /// Standard Solana Base58 hashes, as in JSON getBlock responses.
    pub blockhash: String,
    pub previous_blockhash: String,
    pub tx_count: u32,
    pub hot: HotRow,
    pub sha256: String,
    pub length: u64,
    pub message_schema: u8,
    pub metadata_schema: u8,
    pub rooted: bool,
    pub metadata_complete: bool,
}

pub(crate) struct Response {
    metadata: Vec<u8>,
    bundle: Vec<u8>,
}

impl Response {
    fn from_slot(block: &SlotData) -> Result<Self> {
        let encoded = encode_slot_bundle(block)?;
        let metadata = Metadata {
            version: 1,
            slot: block.slot,
            parent_slot: block.parent_slot.context("missing parent slot")?,
            blockhash: bs58::encode(block.blockhash).into_string(),
            previous_blockhash: bs58::encode(
                block.previous_blockhash.context("missing parent hash")?,
            )
            .into_string(),
            tx_count: encoded.hot.tx_count,
            hot: encoded.hot.into(),
            sha256: hex::encode(Sha256::digest(&encoded.bytes)),
            length: encoded.bytes.len() as u64,
            message_schema: 0,
            metadata_schema: 0,
            rooted: true,
            metadata_complete: true,
        };
        let metadata = serde_json::to_vec(&metadata).context("encode one-slot metadata")?;
        if metadata.is_empty() || metadata.len() > MAX_METADATA_BYTES {
            bail!("one-slot metadata exceeds its byte limit");
        }
        Ok(Self {
            metadata,
            bundle: encoded.bytes,
        })
    }

    /// Write the four parts directly. Do not copy the complete bundle into a
    /// second frame allocation, and do not write anything before all checks.
    pub(crate) fn write_to(&self, output: &mut impl Write) -> Result<()> {
        let result = (|| {
            output.write_all(MAGIC)?;
            output.write_all(&(self.metadata.len() as u32).to_le_bytes())?;
            output.write_all(&self.metadata)?;
            output.write_all(&self.bundle)?;
            output.flush()
        })();
        result.map_err(|error| {
            anyhow!(CommandFailure {
                exit_code: 7,
                message: format!("write one-slot frame: {error}")
            })
        })
    }
}

#[derive(Debug)]
struct CommandFailure {
    exit_code: i32,
    message: String,
}

impl std::fmt::Display for CommandFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(f)
    }
}
impl std::error::Error for CommandFailure {}

pub(crate) fn exit_code(error: &anyhow::Error) -> Option<i32> {
    error.chain().find_map(|cause| {
        cause
            .downcast_ref::<SlotReadFailure>()
            .map(|failure| failure.exit_code)
            .or_else(|| {
                cause
                    .downcast_ref::<CommandFailure>()
                    .map(|failure| failure.exit_code)
            })
    })
}

/// Each process opens a fresh strict read-only handle. The CLI exits on the
/// deadline, which also stops its read thread; it never returns a partial body.
pub(crate) fn read_with_deadline(ledger: PathBuf, slot: u64) -> Result<Response> {
    if !cfg!(feature = "bounded-ledger-read") {
        return Err(anyhow!(CommandFailure {
            exit_code: 7,
            message: "read-slot-compact requires the checked bounded-ledger-read SDK build".into(),
        }));
    }
    let (send, receive) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = (|| {
            let block = {
                let blockstore = open_read_only(&ledger)?;
                load_slot(&blockstore, slot)?
            };
            Response::from_slot(&block)
        })();
        let _ = send.send(result);
    });
    match receive.recv_timeout(READ_DEADLINE) {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(error)) => {
            let code = exit_code(&error).unwrap_or(7);
            Err(anyhow!(CommandFailure {
                exit_code: code,
                message: format!("{error:#}")
            }))
        }
        Err(mpsc::RecvTimeoutError::Timeout) => Err(anyhow!(CommandFailure {
            exit_code: 8,
            message: "one-slot ledger read exceeded 10 seconds".into(),
        })),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(anyhow!(CommandFailure {
            exit_code: 7,
            message: "one-slot ledger reader stopped without a result".into(),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{
        SourceHeader, SourceInstruction, SourceMessage, SourceMessageBody, SourceStatus, SourceTx,
        SourceTxConfig, SourceV1Message, test_block,
    };
    use blockzilla_archive_v2::{
        ArchiveV2BlockAccessBlob, BlockzillaGetBlockBlobEncoding, BlockzillaGetBlockBundleV1,
        deserialize_archive_v2_hot_block_blob,
    };
    use blockzilla_primitives::wincode_leb128_config;

    fn fixture() -> SlotData {
        let mut block = test_block(472_608_000, 472_607_998, [11; 32], [9; 32]);
        let header = SourceHeader {
            num_required_signatures: 1,
            num_readonly_signed_accounts: 0,
            num_readonly_unsigned_accounts: 1,
        };
        let body = SourceMessageBody {
            header,
            account_keys: vec![[17; 32], [18; 32]],
            recent_blockhash: [19; 32],
            instructions: vec![SourceInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: vec![1, 2, 3],
            }],
            lookups: Vec::new(),
        };
        let messages = [
            SourceMessage::Legacy(body.clone()),
            SourceMessage::V0(body.clone()),
            SourceMessage::V1(SourceV1Message {
                header,
                config: SourceTxConfig {
                    priority_fee: Some(42),
                    compute_unit_limit: Some(200_000),
                    loaded_accounts_data_size_limit: Some(65536),
                    heap_size: Some(32768),
                },
                account_keys: body.account_keys,
                recent_blockhash: body.recent_blockhash,
                instructions: body.instructions,
            }),
        ];
        block.transactions = messages
            .into_iter()
            .enumerate()
            .map(|(index, message)| {
                let mut status = SourceStatus::success();
                status.fee = 5000;
                status.pre_balances = vec![10000, 1];
                status.post_balances = vec![5000, 1];
                status.compute_units_consumed = Some(10);
                status.cost_units = Some(11);
                SourceTx {
                    signatures: vec![[index as u8 + 1; 64]],
                    message,
                    status: Some(status),
                }
            })
            .collect();
        block.entries[0].tx_count = 3;
        block.entries[0].signature_count = 3;
        block.block_time = Some(1_700_000_000);
        block.block_height = Some(101);
        block
    }

    #[test]
    fn framed_bundle_has_exact_lengths_hashes_parent_and_complete_access() {
        let block = fixture();
        let response = Response::from_slot(&block).unwrap();
        let mut frame = Vec::new();
        response.write_to(&mut frame).unwrap();
        assert_eq!(&frame[..8], MAGIC);
        let metadata_len = u32::from_le_bytes(frame[8..12].try_into().unwrap()) as usize;
        let metadata: Metadata = serde_json::from_slice(&frame[12..12 + metadata_len]).unwrap();
        let body = &frame[12 + metadata_len..];
        assert_eq!(body.len() as u64, metadata.length);
        assert_eq!(hex::encode(Sha256::digest(body)), metadata.sha256);
        assert_eq!(metadata.slot, block.slot);
        assert_eq!(metadata.parent_slot, block.parent_slot.unwrap());
        assert!(metadata.rooted && metadata.metadata_complete);
        let bundle: BlockzillaGetBlockBundleV1 =
            wincode::config::deserialize_exact(body, wincode_leb128_config()).unwrap();
        assert_eq!(
            bundle.hot_block_encoding,
            BlockzillaGetBlockBlobEncoding::ZstdWincode
        );
        assert_eq!(
            bundle.block_access_encoding,
            BlockzillaGetBlockBlobEncoding::Wincode
        );
        let raw = zstd::bulk::decompress(&bundle.hot_block, metadata.hot.uncompressed_len as usize)
            .unwrap();
        let hot = deserialize_archive_v2_hot_block_blob(&raw).unwrap();
        let access: ArchiveV2BlockAccessBlob = wincode::config::deserialize_exact(
            &bundle.block_access.unwrap(),
            wincode_leb128_config(),
        )
        .unwrap();
        assert_eq!(hot.header.parent_slot, block.parent_slot.unwrap());
        assert_eq!(hot.header.blockhash_id, 1);
        assert_eq!(hot.header.previous_blockhash_id, 0);
        assert_eq!(access.blockhash, block.blockhash);
        assert_eq!(access.previous_blockhash, block.previous_blockhash.unwrap());
        assert_eq!(metadata.hot.tx_count, hot.tx_count);
        assert_eq!(
            metadata.hot.signature_count as usize * 64,
            access.signatures.len()
        );
        assert_eq!(access.signatures, [[1; 64], [2; 64], [3; 64]].concat());
        assert_eq!(access.signature_counts, [1, 1, 1]);
        for (index, row) in hot.tx_rows.iter().enumerate() {
            let bytes = &hot.message_bytes
                [row.message_offset as usize..(row.message_offset + row.message_len) as usize];
            let message: blockzilla_archive_v2::ArchiveV2HotMessagePayload =
                wincode::config::deserialize_exact(bytes, wincode_leb128_config()).unwrap();
            use blockzilla_archive_v2::ArchiveV2HotMessagePayload;
            let recent = match (index, message) {
                (0, ArchiveV2HotMessagePayload::Legacy(message)) => message.recent_blockhash,
                (1, ArchiveV2HotMessagePayload::V0(message)) => message.recent_blockhash,
                (2, ArchiveV2HotMessagePayload::V1(message)) => {
                    assert_eq!(message.config.priority_fee, Some(42));
                    message.recent_blockhash
                }
                _ => panic!("transaction version changed"),
            };
            match recent {
                blockzilla_compact::OwnedCompactRecentBlockhash::Nonce(hash) => {
                    assert_eq!(hash, [19; 32])
                }
                _ => panic!("one-slot recent hash must stay inline"),
            };
        }
    }

    #[test]
    fn missing_status_cannot_claim_complete_metadata() {
        let mut block = fixture();
        block.transactions[0].status = None;
        assert!(Response::from_slot(&block).is_err());
    }

    #[test]
    fn missing_path_returns_no_frame_and_creates_no_ledger() {
        let directory = tempfile::tempdir().unwrap();
        let absent = directory.path().join("absent-ledger");
        let error = match read_with_deadline(absent.clone(), 11) {
            Ok(_) => panic!("missing ledger was accepted"),
            Err(error) => error,
        };
        assert_eq!(exit_code(&error), Some(7));
        assert!(!absent.exists());
    }

    #[cfg(not(feature = "bounded-ledger-read"))]
    #[test]
    fn read_slot_refuses_an_unbounded_sdk_build() {
        let error = match read_with_deadline(PathBuf::from("/not-opened"), 11) {
            Ok(_) => panic!("unbounded SDK build was accepted"),
            Err(error) => error,
        };
        assert_eq!(exit_code(&error), Some(7));
        assert!(error.to_string().contains("bounded-ledger-read"));
    }

    fn base64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut output = String::new();
        for part in bytes.chunks(3) {
            let bits = (u32::from(part[0]) << 16)
                | (u32::from(*part.get(1).unwrap_or(&0)) << 8)
                | u32::from(*part.get(2).unwrap_or(&0));
            output.push(ALPHABET[(bits >> 18) as usize] as char);
            output.push(ALPHABET[((bits >> 12) & 63) as usize] as char);
            output.push(if part.len() > 1 {
                ALPHABET[((bits >> 6) & 63) as usize] as char
            } else {
                '='
            });
            output.push(if part.len() > 2 {
                ALPHABET[(bits & 63) as usize] as char
            } else {
                '='
            });
        }
        output
    }

    /// Independent Solana packet layouts. This must not call the ledger
    /// compactor or the Worker message serializer to produce the expectation.
    fn expected_wire(index: usize) -> Vec<u8> {
        if index == 2 {
            let mut wire = vec![0x81, 1, 0, 1];
            wire.extend_from_slice(&31u32.to_le_bytes());
            wire.extend_from_slice(&[19; 32]);
            wire.extend_from_slice(&[1, 2]);
            wire.extend_from_slice(&[17; 32]);
            wire.extend_from_slice(&[18; 32]);
            wire.extend_from_slice(&42u64.to_le_bytes());
            wire.extend_from_slice(&200_000u32.to_le_bytes());
            wire.extend_from_slice(&65_536u32.to_le_bytes());
            wire.extend_from_slice(&32_768u32.to_le_bytes());
            wire.extend_from_slice(&[1, 1, 3, 0, 0, 1, 2, 3]);
            wire.extend_from_slice(&[3; 64]);
            wire
        } else {
            let mut wire = vec![1];
            wire.extend_from_slice(&[index as u8 + 1; 64]);
            if index == 1 {
                wire.push(0x80);
            }
            wire.extend_from_slice(&[1, 0, 1, 2]);
            wire.extend_from_slice(&[17; 32]);
            wire.extend_from_slice(&[18; 32]);
            wire.extend_from_slice(&[19; 32]);
            wire.extend_from_slice(&[1, 1, 1, 0, 3, 1, 2, 3]);
            if index == 1 {
                wire.push(0);
            }
            wire
        }
    }

    #[test]
    fn export_ledger_wasm_fixture_if_requested() {
        let Some(path) = std::env::var_os("BZ_LEDGER_WASM_FIXTURE") else {
            return;
        };
        let block = fixture();
        let response = Response::from_slot(&block).unwrap();
        let metadata: serde_json::Value = serde_json::from_slice(&response.metadata).unwrap();
        let transactions: Vec<_> = (0..3).map(|index| serde_json::json!({
            "transaction": [base64(&expected_wire(index)), "base64"],
            "version": match index { 0 => serde_json::json!("legacy"), 1 => serde_json::json!(0), _ => serde_json::json!(1) },
            "meta": {"err": null, "status": {"Ok": null}, "fee": 5000,
                "preBalances": [10000, 1], "postBalances": [5000, 1],
                "preTokenBalances": [], "postTokenBalances": [], "logMessages": null,
                "innerInstructions": null, "loadedAddresses": {"writable": [], "readonly": []},
                "rewards": null, "computeUnitsConsumed": 10, "costUnits": 11}
        })).collect();
        let expected = serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {
            "blockhash": metadata["blockhash"], "previousBlockhash": metadata["previous_blockhash"],
            "parentSlot": metadata["parent_slot"], "blockTime": 1_700_000_000, "blockHeight": 101,
            "transactions": transactions,
        }});
        let fixture = serde_json::json!({
            "schema": "blockzilla-ledger-compact-worker-fixture-v1",
            "ledger_generation": "ledger-compact-v1", "slot": block.slot,
            "metadata": metadata, "bundle_base64": base64(&response.bundle),
            "expected_json_rpc": expected,
            "scope": "Synthetic Legacy/V0/V1 blocks; expected transaction wire and RPC fields are built independently."
        });
        let path = PathBuf::from(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, serde_json::to_vec_pretty(&fixture).unwrap()).unwrap();
    }
}
