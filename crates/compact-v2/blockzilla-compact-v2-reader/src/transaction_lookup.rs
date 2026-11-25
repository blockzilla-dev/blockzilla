use crate::{ArchiveReader, DecodedBlock, Error, RangeSource, Result, SourceError};

const SIGNATURE_BYTES: usize = 64;
const SIGNATURE_WINDOW_COUNT: u64 = 1_024;

/// One transaction whose first signature exactly matches the requested ID.
///
/// The block retains the original message, metadata, and execution flags.
/// Lookup does not filter failed transactions or decode their message/metadata.
#[derive(Debug)]
pub struct LocatedArchiveTransaction {
    pub block: DecodedBlock,
    pub tx_index: u32,
    pub first_signature_ordinal: u64,
    pub signatures: Vec<[u8; SIGNATURE_BYTES]>,
}

impl<S: RangeSource> ArchiveReader<S> {
    /// Find an exact transaction ID within one candidate slot.
    ///
    /// The caller selects this archive generation and slot, for example from
    /// a probabilistic signature index. Only the first signature of each
    /// transaction is an ID. Other signers' signatures cannot produce a hit.
    /// Signature reads stay inside this block's range and use at most 64 KiB
    /// per request. The existing block decoder enforces its configured bounds.
    ///
    /// `Ok(None)` means the slot has no row or no matching transaction in this
    /// generation. It proves neither complete archive coverage nor a skipped
    /// slot. Missing signatures, source failures, and corrupt blocks are errors.
    /// This method does not establish chain identity or finality; the caller
    /// must select the correct admitted canonical generation.
    pub fn find_transaction_in_block(
        &self,
        slot: u64,
        signature: &[u8; SIGNATURE_BYTES],
    ) -> Result<Option<LocatedArchiveTransaction>> {
        let Ok(row_number) = self
            .index()
            .rows
            .binary_search_by_key(&slot, |row| row.slot)
        else {
            return Ok(None);
        };
        if !self.signatures_available() {
            return Err(Error::SignaturesUnavailable);
        }
        let block = self.read_block(row_number)?;
        // read_block validates that the row counts sum to the index signature
        // count. Every transaction start below is therefore inside this range.
        let first = block.index_row.first_signature_ordinal;
        let end = first
            .checked_add(u64::from(block.index_row.signature_count))
            .ok_or(Error::Overflow("block signature end"))?;
        let mut ordinal = first;
        let mut window_first = first;
        let mut window = Vec::new();
        for row in &block.block.tx_rows {
            let count = u64::from(row.signature_count);
            let next = ordinal
                .checked_add(count)
                .ok_or(Error::Overflow("transaction signature end"))?;
            if count != 0 {
                let window_end = window_first + (window.len() / SIGNATURE_BYTES) as u64;
                if ordinal >= window_end {
                    window_first = ordinal;
                    window = read_signature_range(
                        self.source(),
                        ordinal,
                        (end - ordinal).min(SIGNATURE_WINDOW_COUNT),
                    )?;
                }
                let offset = (ordinal - window_first) as usize * SIGNATURE_BYTES;
                if window[offset..offset + SIGNATURE_BYTES] == signature[..] {
                    let transaction_bytes = count as usize * SIGNATURE_BYTES;
                    let signatures = if offset + transaction_bytes <= window.len() {
                        window[offset..offset + transaction_bytes].to_vec()
                    } else {
                        read_signature_range(self.source(), ordinal, count)?
                    };
                    let tx_index = row.tx_index;
                    return Ok(Some(LocatedArchiveTransaction {
                        block,
                        tx_index,
                        first_signature_ordinal: ordinal,
                        signatures: signatures
                            .chunks_exact(SIGNATURE_BYTES)
                            .map(|bytes| bytes.try_into().expect("exact signature chunk"))
                            .collect(),
                    }));
                }
            }
            ordinal = next;
        }
        Ok(None)
    }
}

fn read_signature_range<S: RangeSource>(
    source: &S,
    first_ordinal: u64,
    count: u64,
) -> Result<Vec<u8>> {
    let offset = first_ordinal
        .checked_mul(SIGNATURE_BYTES as u64)
        .ok_or(Error::Overflow("signature byte offset"))?;
    let length = usize::try_from(count)
        .ok()
        .and_then(|count| count.checked_mul(SIGNATURE_BYTES))
        .ok_or(Error::Overflow("signature byte length"))?;
    let bytes = source.read_range(crate::manifest::SIGNATURES_FILE, offset, length)?;
    if bytes.len() != length {
        return Err(SourceError::ShortRead {
            object: crate::manifest::SIGNATURES_FILE.to_owned(),
            expected: length,
            actual: bytes.len(),
        }
        .into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::{
            Arc, Mutex,
            atomic::{AtomicU8, Ordering},
        },
    };

    use blockzilla_archive_v2::{
        ARCHIVE_V2_TX_FLAG_HAS_ERROR, ARCHIVE_V2_TX_FLAG_HAS_METADATA, ArchiveV2HotBlockBlob,
        ArchiveV2HotBlockHeader, ArchiveV2HotBlockIndexRow, ArchiveV2HotLegacyMessage,
        ArchiveV2HotMessagePayload, ArchiveV2HotMetaRecord, ArchiveV2HotTxRow,
        WINCODE_ARCHIVE_V2_FLAG_LEB128, WINCODE_ARCHIVE_V2_HOT_BLOCK_VERSION,
        WincodeArchiveV2Footer, WincodeArchiveV2Header, write_archive_v2_hot_block_index,
    };
    use blockzilla_compact::{
        CompactMessageHeader, CompactMetaV1, CompactTransactionError, OwnedCompactRecentBlockhash,
    };
    use blockzilla_primitives::wincode_leb128_config;
    use tempfile::TempDir;

    use super::*;
    use crate::manifest::{
        BLOCK_INDEX_FILE, BLOCKS_FILE, META_FILE, REGISTRY_FILE, SIGNATURES_FILE,
    };
    use crate::{LocalRangeSource, OpenOptions, SourceResult, descriptor::ArchiveIdentity};

    struct Fixture {
        directory: TempDir,
        fault: Arc<AtomicU8>,
        signature_reads: Arc<Mutex<Vec<(u64, usize)>>>,
    }

    #[derive(Clone)]
    struct TestSource {
        inner: LocalRangeSource,
        fault: Arc<AtomicU8>,
        signature_reads: Arc<Mutex<Vec<(u64, usize)>>>,
    }

    impl RangeSource for TestSource {
        fn size(&self, object: &str) -> SourceResult<Option<u64>> {
            self.inner.size(object)
        }

        fn read_range(&self, object: &str, offset: u64, length: usize) -> SourceResult<Vec<u8>> {
            if object == SIGNATURES_FILE {
                self.signature_reads.lock().unwrap().push((offset, length));
                if self.fault.load(Ordering::Relaxed) == 1 {
                    return Err(SourceError::NotFound(object.into()));
                }
            }
            let mut bytes = self.inner.read_range(object, offset, length)?;
            if object == SIGNATURES_FILE && self.fault.load(Ordering::Relaxed) == 2 {
                bytes.pop();
            }
            Ok(bytes)
        }
    }

    impl Fixture {
        fn new(counts: &[u8], with_signatures: bool) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path();
            fs::write(root.join(REGISTRY_FILE), []).unwrap();
            let mut blocks = Vec::new();
            let mut index = Vec::new();
            let mut signatures = Vec::new();
            let mut first_tx_ordinal = 0;
            for (block_id, block_counts) in [&[1][..], counts].into_iter().enumerate() {
                let slot = 101 + block_id as u64;
                let mut block = ArchiveV2HotBlockBlob {
                    header: ArchiveV2HotBlockHeader {
                        slot,
                        parent_slot: slot - 1,
                        blockhash_id: block_id as u32 + 1,
                        previous_blockhash_id: block_id as u32,
                        block_time: Some(1_700_000_000 + slot as i64),
                        block_height: Some(1000 + block_id as u64),
                        rewards: None,
                    },
                    tx_count: block_counts.len() as u32,
                    tx_rows: Vec::new(),
                    message_bytes: Vec::new(),
                    metadata_bytes: Vec::new(),
                };
                let first_signature_ordinal = signatures.len() as u64 / 64;
                for (tx_index, count) in block_counts.iter().copied().enumerate() {
                    let message = ArchiveV2HotMessagePayload::Legacy(ArchiveV2HotLegacyMessage {
                        header: CompactMessageHeader {
                            num_required_signatures: count,
                            num_readonly_signed_accounts: 0,
                            num_readonly_unsigned_accounts: 0,
                        },
                        account_keys: vec![crate::CompactPubkey::Raw([7; 32]); count as usize],
                        recent_blockhash: OwnedCompactRecentBlockhash::Id(0),
                        instructions: Vec::new(),
                    });
                    let message =
                        wincode::config::serialize(&message, wincode_leb128_config()).unwrap();
                    let mut row = ArchiveV2HotTxRow {
                        tx_index: tx_index as u32,
                        message_offset: block.message_bytes.len() as u32,
                        message_len: message.len() as u32,
                        signature_count: count,
                        ..ArchiveV2HotTxRow::default()
                    };
                    if block_id == 1 && tx_index == 1 {
                        let metadata = CompactMetaV1 {
                            err: Some(CompactTransactionError::AccountNotFound),
                            fee: 5000,
                            pre_balances: Vec::new(),
                            post_balances: Vec::new(),
                            inner_instructions: None,
                            logs: None,
                            pre_token_balances: Vec::new(),
                            post_token_balances: Vec::new(),
                            rewards: Vec::new(),
                            loaded_writable_addresses: Vec::new(),
                            loaded_readonly_addresses: Vec::new(),
                            return_data: None,
                            compute_units_consumed: Some(10),
                            cost_units: None,
                        };
                        block.metadata_bytes =
                            wincode::config::serialize(&metadata, wincode_leb128_config()).unwrap();
                        row.flags = ARCHIVE_V2_TX_FLAG_HAS_ERROR | ARCHIVE_V2_TX_FLAG_HAS_METADATA;
                        row.metadata_len = block.metadata_bytes.len() as u32;
                    }
                    block.message_bytes.extend(message);
                    block.tx_rows.push(row);
                    for signer in 0..count {
                        let mut signature = [0; 64];
                        signature[..4].copy_from_slice(&(tx_index as u32).to_le_bytes());
                        signature[4] = signer;
                        signature[5] = block_id as u8;
                        signatures.extend(signature);
                    }
                }
                let raw = wincode::config::serialize(&block, wincode_leb128_config()).unwrap();
                let compressed = zstd::bulk::compress(&raw, 1).unwrap();
                index.push(ArchiveV2HotBlockIndexRow {
                    block_id: block_id as u32,
                    slot,
                    compressed_offset: blocks.len() as u64,
                    compressed_len: compressed.len() as u32,
                    uncompressed_len: raw.len() as u32,
                    tx_count: block.tx_count,
                    first_tx_ordinal,
                    first_signature_ordinal,
                    signature_count: (signatures.len() as u64 / 64 - first_signature_ordinal)
                        as u32,
                });
                first_tx_ordinal += u64::from(block.tx_count);
                blocks.extend(compressed);
            }
            fs::write(root.join(BLOCKS_FILE), &blocks).unwrap();
            write_archive_v2_hot_block_index(
                &root.join(BLOCK_INDEX_FILE),
                blocks.len() as u64,
                1,
                0,
                &index,
            )
            .unwrap();
            if with_signatures {
                fs::write(root.join(SIGNATURES_FILE), signatures).unwrap();
            }
            let mut metadata = Vec::new();
            for record in [
                ArchiveV2HotMetaRecord::Header(WincodeArchiveV2Header {
                    version: WINCODE_ARCHIVE_V2_HOT_BLOCK_VERSION,
                    flags: WINCODE_ARCHIVE_V2_FLAG_LEB128,
                }),
                ArchiveV2HotMetaRecord::Footer(WincodeArchiveV2Footer {
                    blocks: 2,
                    transactions: first_tx_ordinal,
                    ..WincodeArchiveV2Footer::default()
                }),
            ] {
                let bytes = wincode::config::serialize(&record, wincode_leb128_config()).unwrap();
                assert!(bytes.len() < 128);
                metadata.push(bytes.len() as u8);
                metadata.extend(bytes);
            }
            fs::write(root.join(META_FILE), metadata).unwrap();
            Self {
                directory,
                fault: Arc::new(AtomicU8::new(0)),
                signature_reads: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn open(&self) -> ArchiveReader<TestSource> {
            ArchiveReader::open_pinned(
                TestSource {
                    inner: LocalRangeSource::new(self.directory.path()),
                    fault: self.fault.clone(),
                    signature_reads: self.signature_reads.clone(),
                },
                ArchiveIdentity {
                    cluster_id: "testnet".into(),
                    epoch: 1,
                    generation_id: "transaction-lookup-test".into(),
                    first_slot: 100,
                    slots_per_epoch: 100,
                },
                OpenOptions::default(),
            )
            .unwrap()
        }
    }

    fn signature(tx_index: u32, signer: u8) -> [u8; 64] {
        let mut signature = [0; 64];
        signature[..4].copy_from_slice(&tx_index.to_le_bytes());
        signature[4] = signer;
        signature[5] = 1;
        signature
    }

    #[test]
    fn finds_later_transaction_and_preserves_failed_execution() {
        let fixture = Fixture::new(&[2, 1], true);
        let archive = fixture.open();
        let found = archive
            .find_transaction_in_block(102, &signature(1, 0))
            .unwrap()
            .unwrap();
        assert_eq!(found.tx_index, 1);
        assert_eq!(found.first_signature_ordinal, 3);
        assert_eq!(found.signatures, vec![signature(1, 0)]);
        assert_eq!(found.block.block.header.slot, 102);
        let row = found.block.block.tx_rows[1];
        assert_ne!(row.flags & ARCHIVE_V2_TX_FLAG_HAS_ERROR, 0);
        let metadata = archive
            .decode_metadata(&found.block.block.metadata_bytes)
            .unwrap();
        assert!(matches!(
            metadata.err,
            Some(CompactTransactionError::AccountNotFound)
        ));
        assert_eq!(*fixture.signature_reads.lock().unwrap(), vec![(64, 3 * 64)]);
    }

    #[test]
    fn only_first_signatures_match_and_candidate_scope_is_exact() {
        let fixture = Fixture::new(&[2, 1], true);
        let archive = fixture.open();
        assert!(
            archive
                .find_transaction_in_block(102, &signature(0, 1))
                .unwrap()
                .is_none()
        );
        assert!(
            archive
                .find_transaction_in_block(102, &[9; 64])
                .unwrap()
                .is_none()
        );
        assert!(
            archive
                .find_transaction_in_block(101, &signature(1, 0))
                .unwrap()
                .is_none()
        );
        fixture.signature_reads.lock().unwrap().clear();
        assert!(
            archive
                .find_transaction_in_block(103, &signature(1, 0))
                .unwrap()
                .is_none()
        );
        assert!(fixture.signature_reads.lock().unwrap().is_empty());
        let found = archive
            .find_transaction_in_block(102, &signature(0, 0))
            .unwrap()
            .unwrap();
        assert_eq!(found.signatures, vec![signature(0, 0), signature(0, 1)]);
    }

    #[test]
    fn signature_reads_remain_bounded_inside_one_block() {
        let fixture = Fixture::new(&vec![1; 1030], true);
        let archive = fixture.open();
        let found = archive
            .find_transaction_in_block(102, &signature(1029, 0))
            .unwrap()
            .unwrap();
        assert_eq!(found.tx_index, 1029);
        assert_eq!(
            *fixture.signature_reads.lock().unwrap(),
            vec![(64, 65_536), (65_600, 384)]
        );
    }

    #[test]
    fn returns_all_signers_when_transaction_crosses_signature_window() {
        let mut counts = vec![1; 1023];
        counts.push(255);
        let fixture = Fixture::new(&counts, true);
        let archive = fixture.open();
        let found = archive
            .find_transaction_in_block(102, &signature(1023, 0))
            .unwrap()
            .unwrap();
        assert_eq!(found.signatures.len(), 255);
        assert_eq!(found.signatures[254], signature(1023, 254));
        assert_eq!(
            *fixture.signature_reads.lock().unwrap(),
            vec![(64, 65_536), (65_536, 255 * 64)]
        );
    }

    #[test]
    fn missing_and_short_signature_reads_are_errors() {
        let absent = Fixture::new(&[2, 1], false);
        assert!(matches!(
            absent
                .open()
                .find_transaction_in_block(102, &signature(1, 0)),
            Err(Error::SignaturesUnavailable),
        ));
        let fixture = Fixture::new(&[2, 1], true);
        let archive = fixture.open();
        fixture.fault.store(1, Ordering::Relaxed);
        assert!(matches!(
            archive.find_transaction_in_block(102, &signature(1, 0)),
            Err(Error::Source(SourceError::NotFound(_))),
        ));
        fixture.fault.store(2, Ordering::Relaxed);
        assert!(matches!(
            archive.find_transaction_in_block(102, &signature(1, 0)),
            Err(Error::Source(SourceError::ShortRead {
                expected: 192,
                actual: 191,
                ..
            })),
        ));
    }
}
