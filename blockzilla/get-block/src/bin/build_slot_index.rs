//! Build a small derived lookup without changing any durable archive object.
use anyhow::{Context, Result, anyhow, bail, ensure};
use blockzilla_archive_v2::{
    ARCHIVE_V2_BLOCK_INDEX_FILE, ARCHIVE_V2_BLOCKHASH_REGISTRY_FILE, ARCHIVE_V2_BLOCKS_FILE,
    ARCHIVE_V2_HOT_INDEX_FLAG_DICTIONARY, ARCHIVE_V2_HOT_INDEX_FLAG_RAW_BLOCKS,
    ARCHIVE_V2_HOT_INDEX_HEADER_LEN, ARCHIVE_V2_HOT_INDEX_MAGIC, ARCHIVE_V2_HOT_INDEX_ROW_LEN,
    ARCHIVE_V2_HOT_INDEX_VERSION, ARCHIVE_V2_PREV_BLOCKHASH_TAIL_FILE,
    ARCHIVE_V2_PUBKEY_REGISTRY_FILE, ARCHIVE_V2_SIGNATURES_FILE, ArchiveV2HotBlockIndexRow,
};
use blockzilla_get_block::slot_index::{
    MAX_BLOCK_BYTES, MAX_COMPRESSED_BLOCK_BYTES, MAX_SLOT_COUNT, SLOT_INDEX_FILE, SlotIndexHeader,
    SlotIndexRow, encode_header, encode_row, row_offset, validate_row,
};
use blockzilla_primitives::historical_source_wincode_leb128_config;
use clap::{Parser, ValueEnum};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, Metadata, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use wincode::SchemaRead;

#[derive(Parser)]
#[command(about = "Build the optional dense Compact V2 slot index; never replace an existing file")]
struct Args {
    /// Directory containing the original Compact V2 objects.
    #[arg(long)]
    archive_dir: PathBuf,
    #[arg(long)]
    epoch: u64,
    /// New index path. Defaults to archive-dir/archive-v2-slot-offsets.v1.index.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Explicit geometry for a non-mainnet archive. Requires --slot-count.
    #[arg(long, requires = "slot_count")]
    first_slot: Option<u64>,
    #[arg(long, requires = "first_slot")]
    slot_count: Option<u64>,
    /// Supply only when the legacy predecessor-tail schema is known.
    #[arg(long, value_enum)]
    previous_tail_schema: Option<TailSchema>,
}

#[derive(Clone, Copy, ValueEnum)]
enum TailSchema {
    Current,
    Legacy,
}

#[derive(SchemaRead)]
struct HeaderPrefix {
    slot: u64,
    parent_slot: u64,
    blockhash_id: u32,
    previous_blockhash_id: u32,
}

struct SourceFile {
    path: PathBuf,
    file: File,
    identity: Metadata,
}

impl SourceFile {
    fn open(path: PathBuf) -> Result<Self> {
        let identity =
            std::fs::symlink_metadata(&path).with_context(|| format!("stat {}", path.display()))?;
        ensure!(
            identity.is_file(),
            "{} must be a regular file without a symlink",
            path.display()
        );
        let file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
        ensure!(
            same_file(&identity, &file.metadata()?),
            "{} changed while opening",
            path.display()
        );
        Ok(Self {
            path,
            file,
            identity,
        })
    }
    fn unchanged(&self) -> Result<()> {
        ensure!(
            same_file(&self.identity, &self.file.metadata()?)
                && same_file(&self.identity, &std::fs::symlink_metadata(&self.path)?),
            "{} changed during the build",
            self.path.display()
        );
        Ok(())
    }
    fn range(&mut self, offset: u64, bytes: &mut [u8]) -> Result<()> {
        ensure!(
            offset
                .checked_add(bytes.len() as u64)
                .is_some_and(|end| end <= self.identity.len()),
            "read exceeds {}",
            self.path.display()
        );
        self.file.seek(SeekFrom::Start(offset))?;
        self.file
            .read_exact(bytes)
            .with_context(|| format!("read {} at {offset}", self.path.display()))
    }
    fn sha256(&mut self) -> Result<[u8; 32]> {
        self.file.seek(SeekFrom::Start(0))?;
        let mut digest = Sha256::new();
        let mut bytes = [0; 64 * 1024];
        loop {
            let n = self.file.read(&mut bytes)?;
            if n == 0 {
                break;
            }
            digest.update(&bytes[..n]);
        }
        Ok(digest.finalize().into())
    }
    fn hash(&mut self, id: u32) -> Result<[u8; 32]> {
        let mut bytes = [0; 32];
        self.range(u64::from(id) * 32, &mut bytes)?;
        Ok(bytes)
    }
}

fn same_file(a: &Metadata, b: &Metadata) -> bool {
    if !b.is_file() || a.len() != b.len() || a.modified().ok() != b.modified().ok() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
            && a.mtime_nsec() == b.mtime_nsec()
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn main() -> Result<()> {
    build(Args::parse())
}

fn build(args: Args) -> Result<()> {
    // Mainnet has no warm-up schedule. This matches the existing Compact V2
    // reader's explicit non-warmup epoch-0 test. Other schedules are explicit.
    let first_slot = match args.first_slot {
        Some(slot) => slot,
        None => args
            .epoch
            .checked_mul(MAX_SLOT_COUNT)
            .ok_or_else(|| anyhow!("mainnet epoch first slot overflows"))?,
    };
    let slot_count = args.slot_count.unwrap_or(MAX_SLOT_COUNT);
    let output = args
        .output
        .unwrap_or_else(|| args.archive_dir.join(SLOT_INDEX_FILE));
    ensure!(
        !output.exists(),
        "output already exists: {}",
        output.display()
    );
    let mut index = SourceFile::open(args.archive_dir.join(ARCHIVE_V2_BLOCK_INDEX_FILE))?;
    let mut blocks = SourceFile::open(args.archive_dir.join(ARCHIVE_V2_BLOCKS_FILE))?;
    let signatures = SourceFile::open(args.archive_dir.join(ARCHIVE_V2_SIGNATURES_FILE))?;
    let registry = SourceFile::open(args.archive_dir.join(ARCHIVE_V2_PUBKEY_REGISTRY_FILE))?;
    let mut hashes = SourceFile::open(args.archive_dir.join(ARCHIVE_V2_BLOCKHASH_REGISTRY_FILE))?;
    let tail_path = args.archive_dir.join(ARCHIVE_V2_PREV_BLOCKHASH_TAIL_FILE);
    let mut tail = match std::fs::symlink_metadata(&tail_path) {
        Ok(_) => Some(SourceFile::open(tail_path)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    let mut source_header = [0; ARCHIVE_V2_HOT_INDEX_HEADER_LEN];
    index.range(0, &mut source_header)?;
    ensure!(
        &source_header[..8] == ARCHIVE_V2_HOT_INDEX_MAGIC
            && u16_at(&source_header, 8) == ARCHIVE_V2_HOT_INDEX_VERSION
            && source_header[10..12] == [0, 0],
        "unsupported source hot index header"
    );
    let flags = u32_at(&source_header, 32);
    ensure!(
        flags & ARCHIVE_V2_HOT_INDEX_FLAG_DICTIONARY == 0,
        "dictionary-compressed archives are unsupported"
    );
    ensure!(
        flags & ARCHIVE_V2_HOT_INDEX_FLAG_RAW_BLOCKS == 0,
        "raw-block archives are unsupported"
    );
    ensure!(flags == 0, "unknown source hot index flags {flags:#x}");
    ensure!(
        u64_at(&source_header, 20) == blocks.identity.len(),
        "source index blocks length differs"
    );
    let header = SlotIndexHeader {
        epoch: args.epoch,
        first_slot,
        slot_count,
        blocks_bytes: blocks.identity.len(),
        signatures_bytes: signatures.identity.len(),
        registry_bytes: registry.identity.len(),
        blockhash_registry_bytes: hashes.identity.len(),
        source_index_bytes: index.identity.len(),
        source_index_sha256: index.sha256()?,
        block_count: u64_at(&source_header, 12),
    };
    let encoded_header = encode_header(&header).map_err(|e| anyhow!(e))?;
    let hash_offset = header.blockhash_registry_bytes / 32 - header.block_count;
    let previous_tail = if hash_offset == 0 && args.epoch != 0 {
        let source = tail
            .as_mut()
            .ok_or_else(|| anyhow!("legacy archive is missing its predecessor tail"))?;
        Some(read_tail_last(
            source,
            args.previous_tail_schema,
            first_slot,
        )?)
    } else {
        None
    };
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = output
        .file_name()
        .ok_or_else(|| anyhow!("output has no file name"))?
        .to_string_lossy();
    let temporary = parent.join(format!(".{name}.tmp-{}", std::process::id()));
    let mut target = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .with_context(|| format!("create new {}", temporary.display()))?;
    // set_len supplies zero rows for absent slots; source objects stay read-only.
    target.set_len(header.file_len().map_err(|e| anyhow!(e))?)?;
    target.write_all(&encoded_header)?;
    let mut compressed = Vec::new();
    let mut decoded = Vec::new();
    let mut previous: Option<(u64, [u8; 32])> = None;
    let mut next_compressed_offset = 0u64;
    let mut next_signature = 0u64;
    let mut next_transaction = 0u64;
    for ordinal in 0..header.block_count {
        let mut bytes = [0; ARCHIVE_V2_HOT_INDEX_ROW_LEN];
        index.range(
            ARCHIVE_V2_HOT_INDEX_HEADER_LEN as u64 + ordinal * ARCHIVE_V2_HOT_INDEX_ROW_LEN as u64,
            &mut bytes,
        )?;
        let hot = sparse_row(&bytes);
        ensure!(
            u64::from(hot.block_id) == ordinal,
            "source row {ordinal} has a wrong block ID"
        );
        ensure!(
            previous.as_ref().is_none_or(|(slot, _)| hot.slot > *slot),
            "source slots are not strictly ascending"
        );
        ensure!(
            hot.compressed_offset == next_compressed_offset,
            "source block ranges are not contiguous at slot {}",
            hot.slot
        );
        ensure!(
            hot.first_signature_ordinal == next_signature
                && hot.first_tx_ordinal == next_transaction,
            "source transaction or signature ordinals are not contiguous at slot {}",
            hot.slot
        );
        ensure!(
            u64::from(hot.compressed_len) <= MAX_COMPRESSED_BLOCK_BYTES
                && u64::from(hot.uncompressed_len) <= MAX_BLOCK_BYTES,
            "source block exceeds the 16 MiB compressed or 32 MiB decoded limit at slot {}",
            hot.slot
        );
        compressed.resize(hot.compressed_len as usize, 0);
        decoded.resize(hot.uncompressed_len as usize, 0);
        blocks.range(hot.compressed_offset, &mut compressed)?;
        let actual = zstd::bulk::decompress_to_buffer(&compressed, &mut decoded)
            .with_context(|| format!("decode source block at slot {}", hot.slot))?;
        ensure!(
            actual == decoded.len(),
            "source decoded length differs at slot {}",
            hot.slot
        );
        let prefix: HeaderPrefix =
            wincode::config::deserialize(&decoded, historical_source_wincode_leb128_config())
                .with_context(|| format!("read source header at slot {}", hot.slot))?;
        ensure!(
            prefix.slot == hot.slot && u64::from(prefix.blockhash_id) == ordinal + hash_offset,
            "source block identity differs from source index at slot {}",
            hot.slot
        );
        let blockhash = hashes.hash(prefix.blockhash_id)?;
        let previous_blockhash = if hot.slot == 0 {
            ensure!(
                prefix.parent_slot == 0 && prefix.previous_blockhash_id == 0,
                "slot zero has an invalid parent"
            );
            [0; 32]
        } else if prefix.blockhash_id == 0 && prefix.previous_blockhash_id == 0 {
            let (hash, slot) = previous_tail
                .ok_or_else(|| anyhow!("first source block has no exact predecessor hash"))?;
            ensure!(
                slot.is_none_or(|slot| slot == prefix.parent_slot),
                "predecessor tail slot differs from the source parent"
            );
            hash
        } else {
            ensure!(
                prefix.previous_blockhash_id < prefix.blockhash_id,
                "parent hash ID is not before the block"
            );
            hashes.hash(prefix.previous_blockhash_id)?
        };
        if let Some((slot, hash)) = previous {
            ensure!(
                prefix.parent_slot == slot && previous_blockhash == hash,
                "source parent chain differs at slot {}",
                hot.slot
            );
        }
        let row = SlotIndexRow {
            hot,
            parent_slot: prefix.parent_slot,
            blockhash,
            previous_blockhash,
        };
        validate_row(&header, hot.slot, &row).map_err(|e| anyhow!(e))?;
        target.seek(SeekFrom::Start(
            row_offset(&header, hot.slot).map_err(|e| anyhow!(e))?,
        ))?;
        target.write_all(&encode_row(&row))?;
        previous = Some((hot.slot, blockhash));
        next_compressed_offset = hot
            .compressed_offset
            .checked_add(u64::from(hot.compressed_len))
            .context("block offset overflow")?;
        next_signature = hot
            .first_signature_ordinal
            .checked_add(u64::from(hot.signature_count))
            .context("signature ordinal overflow")?;
        next_transaction = hot
            .first_tx_ordinal
            .checked_add(u64::from(hot.tx_count))
            .context("transaction ordinal overflow")?;
    }
    ensure!(
        next_compressed_offset == header.blocks_bytes
            && next_signature.checked_mul(64) == Some(header.signatures_bytes),
        "source block or signature coverage differs from source object lengths"
    );
    for source in [&index, &blocks, &signatures, &registry, &hashes] {
        source.unchanged()?;
    }
    if let Some(source) = &tail {
        source.unchanged()?;
    }
    ensure!(
        index.sha256()? == header.source_index_sha256,
        "source index bytes changed during the build"
    );
    target.sync_all()?;
    drop(target);
    // hard_link is atomic and fails if output appeared during the build.
    std::fs::hard_link(&temporary, &output)
        .with_context(|| format!("publish new {} without overwrite", output.display()))?;
    std::fs::remove_file(&temporary)?;
    File::open(parent)?.sync_all()?;
    println!(
        "{}",
        serde_json::json!({ "ok": true, "epoch": header.epoch, "output": output,
        "bytes": header.file_len().map_err(|e| anyhow!(e))?, "blocks": header.block_count,
        "firstSlot": header.first_slot, "slotCount": header.slot_count })
    );
    Ok(())
}

fn read_tail_last(
    source: &mut SourceFile,
    schema: Option<TailSchema>,
    first_slot: u64,
) -> Result<([u8; 32], Option<u64>)> {
    ensure!(
        source.identity.len() > 0 && source.identity.len() <= 300 * 40,
        "predecessor tail length is outside its bound"
    );
    let mut bytes = vec![0; source.identity.len() as usize];
    source.range(0, &mut bytes)?;
    let current = || -> Option<([u8; 32], Option<u64>)> {
        if !bytes.len().is_multiple_of(40) || bytes.len() / 40 > 300 {
            return None;
        }
        let mut previous = None;
        for entry in bytes.chunks_exact(40) {
            let slot = u64_at(entry, 32);
            if slot >= first_slot || previous.is_some_and(|n| slot <= n) {
                return None;
            }
            previous = Some(slot);
        }
        let entry = &bytes[bytes.len() - 40..];
        Some((entry[..32].try_into().unwrap(), previous))
    };
    let legacy = || -> Option<([u8; 32], Option<u64>)> {
        if !bytes.len().is_multiple_of(32) || bytes.len() / 32 > 300 {
            return None;
        }
        Some((bytes[bytes.len() - 32..].try_into().unwrap(), None))
    };
    match schema {
        Some(TailSchema::Current) => current().context("invalid current predecessor-tail schema"),
        Some(TailSchema::Legacy) => legacy().context("invalid legacy predecessor-tail schema"),
        None => match (current(), legacy()) {
            (Some(value), None) | (None, Some(value)) => Ok(value),
            (Some(_), Some(_)) => {
                bail!("ambiguous predecessor-tail schema; set --previous-tail-schema")
            }
            (None, None) => bail!("invalid predecessor-tail schema"),
        },
    }
}

fn sparse_row(bytes: &[u8; ARCHIVE_V2_HOT_INDEX_ROW_LEN]) -> ArchiveV2HotBlockIndexRow {
    ArchiveV2HotBlockIndexRow {
        block_id: u32_at(bytes, 0),
        slot: u64_at(bytes, 4),
        compressed_offset: u64_at(bytes, 12),
        compressed_len: u32_at(bytes, 20),
        uncompressed_len: u32_at(bytes, 24),
        tx_count: u32_at(bytes, 28),
        first_tx_ordinal: u64_at(bytes, 32),
        first_signature_ordinal: u64_at(bytes, 40),
        signature_count: u32_at(bytes, 48),
    }
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
    use blockzilla_archive_v2::{
        ARCHIVE_V2_META_FILE, ARCHIVE_V2_TX_FLAG_HAS_ERROR, ARCHIVE_V2_TX_FLAG_HAS_METADATA,
        ArchiveV2HotBlockBlob, ArchiveV2HotBlockHeader, ArchiveV2HotInstruction,
        ArchiveV2HotInstructionData, ArchiveV2HotLegacyMessage, ArchiveV2HotMessagePayload,
        ArchiveV2HotMetaRecord, ArchiveV2HotRewards, ArchiveV2HotTxRow,
        WINCODE_ARCHIVE_V2_FLAG_LEB128, WINCODE_ARCHIVE_V2_VERSION, WincodeArchiveV2Header,
        write_archive_v2_hot_block_index,
    };
    use blockzilla_compact::{
        CompactMessageHeader, CompactMetaV1, CompactReward, CompactTransactionError,
        OwnedCompactRecentBlockhash,
    };
    use blockzilla_get_block::slot_index::{
        SLOT_INDEX_HEADER_LEN, SLOT_INDEX_ROW_LEN, parse_header, parse_row,
    };
    use blockzilla_primitives::{CompactPubkey, wincode_leb128_config};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "blockzilla-slot-index-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    /// This fixture has two real Wincode/zstd blocks, one skipped slot, one
    /// signature per transaction, registry IDs, a raw reward key and a failure.
    fn fixture(directory: &Path) -> Result<()> {
        fixture_with_boundary(directory, true)
    }

    fn fixture_with_boundary(directory: &Path, boundary: bool) -> Result<()> {
        std::fs::create_dir_all(directory.parent().unwrap())?;
        std::fs::create_dir(directory)?;
        let mut frames = Vec::new();
        let mut rows = Vec::new();
        let mut signatures = Vec::new();
        for (ordinal, (slot, parent)) in [(432_000, 431_999), (432_002, 432_000)]
            .into_iter()
            .enumerate()
        {
            let message = ArchiveV2HotMessagePayload::Legacy(ArchiveV2HotLegacyMessage {
                header: CompactMessageHeader {
                    num_required_signatures: 1,
                    num_readonly_signed_accounts: 0,
                    num_readonly_unsigned_accounts: 1,
                },
                account_keys: vec![CompactPubkey::Id(1), CompactPubkey::Id(2)],
                recent_blockhash: OwnedCompactRecentBlockhash::Id(
                    ordinal as i32 - i32::from(!boundary),
                ),
                instructions: vec![ArchiveV2HotInstruction {
                    program_id_index: 1,
                    accounts: vec![0],
                    data: ArchiveV2HotInstructionData::Raw(vec![1, 2, 3]),
                }],
            });
            let metadata = CompactMetaV1 {
                err: (ordinal == 1).then_some(CompactTransactionError::InsufficientFundsForFee),
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
            let message_bytes = wincode::config::serialize(&message, wincode_leb128_config())?;
            let metadata_bytes = wincode::config::serialize(&metadata, wincode_leb128_config())?;
            let block = ArchiveV2HotBlockBlob {
                header: ArchiveV2HotBlockHeader {
                    slot,
                    parent_slot: parent,
                    blockhash_id: ordinal as u32 + u32::from(boundary),
                    previous_blockhash_id: if boundary {
                        ordinal as u32
                    } else {
                        (ordinal as u32).saturating_sub(1)
                    },
                    block_time: Some(1_700_000_000 + ordinal as i64),
                    block_height: Some(100 + ordinal as u64),
                    rewards: Some(ArchiveV2HotRewards {
                        num_partitions: Some(1),
                        decoded: vec![
                            CompactReward {
                                pubkey: CompactPubkey::Raw([99; 32]),
                                lamports: 25,
                                post_balance: 900,
                                reward_type: 1,
                                commission: None,
                            },
                            CompactReward {
                                pubkey: CompactPubkey::Id(1),
                                lamports: -1,
                                post_balance: 5000,
                                reward_type: 2,
                                commission: Some(7),
                            },
                        ],
                    }),
                },
                tx_count: 1,
                tx_rows: vec![ArchiveV2HotTxRow {
                    tx_index: 0,
                    flags: ARCHIVE_V2_TX_FLAG_HAS_METADATA
                        | if ordinal == 1 {
                            ARCHIVE_V2_TX_FLAG_HAS_ERROR
                        } else {
                            0
                        },
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
            let decoded = wincode::config::serialize(&block, wincode_leb128_config())?;
            let compressed = zstd::bulk::compress(&decoded, 1)?;
            rows.push(ArchiveV2HotBlockIndexRow {
                block_id: ordinal as u32,
                slot,
                compressed_offset: frames.len() as u64,
                compressed_len: compressed.len() as u32,
                uncompressed_len: decoded.len() as u32,
                tx_count: 1,
                first_tx_ordinal: ordinal as u64,
                first_signature_ordinal: ordinal as u64,
                signature_count: 1,
            });
            frames.extend_from_slice(&compressed);
            signatures.extend_from_slice(&[77 + ordinal as u8; 64]);
        }
        std::fs::write(directory.join(ARCHIVE_V2_BLOCKS_FILE), &frames)?;
        write_archive_v2_hot_block_index(
            &directory.join(ARCHIVE_V2_BLOCK_INDEX_FILE),
            frames.len() as u64,
            1,
            0,
            &rows,
        )?;
        std::fs::write(directory.join(ARCHIVE_V2_SIGNATURES_FILE), signatures)?;
        std::fs::write(
            directory.join(ARCHIVE_V2_PUBKEY_REGISTRY_FILE),
            [[42; 32], [43; 32]].concat(),
        )?;
        let hashes = if boundary {
            [[10; 32], [11; 32], [12; 32]].concat()
        } else {
            let mut tail = [10; 32].to_vec();
            tail.extend_from_slice(&431_999u64.to_le_bytes());
            std::fs::write(directory.join(ARCHIVE_V2_PREV_BLOCKHASH_TAIL_FILE), tail)?;
            [[11; 32], [12; 32]].concat()
        };
        std::fs::write(directory.join(ARCHIVE_V2_BLOCKHASH_REGISTRY_FILE), hashes)?;
        let meta = ArchiveV2HotMetaRecord::Header(WincodeArchiveV2Header {
            version: WINCODE_ARCHIVE_V2_VERSION,
            flags: WINCODE_ARCHIVE_V2_FLAG_LEB128,
        });
        let file = File::create(directory.join(ARCHIVE_V2_META_FILE))?;
        let mut writer = blockzilla_primitives::WincodeLeb128FramedWriter::new(file);
        writer.write(&meta)?;
        std::fs::write(
            directory.join("archive-v2-message-schema-current-v1.marker"),
            b"blockzilla/archive-v2-hot-message-schema/current/v1\n",
        )?;
        Ok(())
    }

    fn arguments(directory: &Path) -> Args {
        Args {
            archive_dir: directory.into(),
            epoch: 1,
            output: None,
            first_slot: None,
            slot_count: None,
            previous_tail_schema: None,
        }
    }

    #[test]
    fn builds_real_archive_and_preserves_absent_slot_and_boundary_hash() -> Result<()> {
        let keep = std::env::var_os("BLOCKZILLA_WORKER_FIXTURE_DIR").map(PathBuf::from);
        let directory = keep
            .as_ref()
            .map(|p| p.join("epoch-1"))
            .unwrap_or_else(|| temp_dir("real"));
        fixture(&directory)?;
        let originals: Vec<_> = [
            ARCHIVE_V2_BLOCK_INDEX_FILE,
            ARCHIVE_V2_BLOCKS_FILE,
            ARCHIVE_V2_SIGNATURES_FILE,
            ARCHIVE_V2_PUBKEY_REGISTRY_FILE,
            ARCHIVE_V2_BLOCKHASH_REGISTRY_FILE,
        ]
        .into_iter()
        .map(|name| Ok((name, std::fs::read(directory.join(name))?)))
        .collect::<Result<_>>()?;
        build(arguments(&directory))?;
        let bytes = std::fs::read(directory.join(SLOT_INDEX_FILE))?;
        let header = parse_header(&bytes[..SLOT_INDEX_HEADER_LEN]).map_err(|e| anyhow!(e))?;
        ensure!(
            header.block_count == 2 && header.first_slot == 432_000 && header.slot_count == 432_000
        );
        let read = |slot| -> Result<Option<SlotIndexRow>> {
            let offset = row_offset(&header, slot).map_err(|e| anyhow!(e))? as usize;
            parse_row(&bytes[offset..offset + SLOT_INDEX_ROW_LEN]).map_err(|e| anyhow!(e))
        };
        let first = read(432_000)?.unwrap();
        ensure!(
            first.parent_slot == 431_999
                && first.previous_blockhash == [10; 32]
                && first.blockhash == [11; 32]
        );
        ensure!(read(432_001)?.is_none());
        let second = read(432_002)?.unwrap();
        ensure!(
            second.parent_slot == first.hot.slot && second.previous_blockhash == first.blockhash
        );
        ensure!(second.hot.first_signature_ordinal == 1 && second.blockhash == [12; 32]);
        ensure!(
            build(arguments(&directory)).is_err(),
            "an existing index must never be overwritten"
        );
        ensure!(std::fs::read(directory.join(SLOT_INDEX_FILE))? == bytes);
        for (name, original) in originals {
            ensure!(std::fs::read(directory.join(name))? == original);
        }
        if keep.is_none() {
            std::fs::remove_dir_all(directory)?;
        }
        Ok(())
    }

    #[test]
    fn rejects_dictionary_archives_before_creating_output() -> Result<()> {
        let directory = temp_dir("dictionary");
        fixture(&directory)?;
        let path = directory.join(ARCHIVE_V2_BLOCK_INDEX_FILE);
        let mut bytes = std::fs::read(&path)?;
        bytes[32..36].copy_from_slice(&ARCHIVE_V2_HOT_INDEX_FLAG_DICTIONARY.to_le_bytes());
        std::fs::write(path, bytes)?;
        let error = build(arguments(&directory)).unwrap_err().to_string();
        ensure!(error.contains("dictionary"));
        ensure!(!directory.join(SLOT_INDEX_FILE).exists());
        std::fs::remove_dir_all(directory)?;
        Ok(())
    }

    #[test]
    fn resolves_legacy_first_block_from_exact_predecessor_tail() -> Result<()> {
        let directory = temp_dir("legacy");
        fixture_with_boundary(&directory, false)?;
        build(arguments(&directory))?;
        let bytes = std::fs::read(directory.join(SLOT_INDEX_FILE))?;
        let first =
            parse_row(&bytes[SLOT_INDEX_HEADER_LEN..SLOT_INDEX_HEADER_LEN + SLOT_INDEX_ROW_LEN])
                .map_err(|e| anyhow!(e))?
                .unwrap();
        ensure!(
            first.parent_slot == 431_999
                && first.blockhash == [11; 32]
                && first.previous_blockhash == [10; 32]
        );
        std::fs::remove_dir_all(directory)?;
        Ok(())
    }
}
