use anyhow::{Context, Result, anyhow, bail};

use blockzilla_archive_v2::{
    ARCHIVE_V2_BLOCK_INDEX_FILE, ARCHIVE_V2_BLOCKHASH_REGISTRY_FILE, ARCHIVE_V2_BLOCKS_FILE,
    ARCHIVE_V2_META_FILE, ARCHIVE_V2_POH_FILE, ARCHIVE_V2_PREV_BLOCKHASH_TAIL_FILE,
    ARCHIVE_V2_PUBKEY_REGISTRY_COUNTS_FILE, ARCHIVE_V2_PUBKEY_REGISTRY_FILE,
    ARCHIVE_V2_PUBKEY_REGISTRY_INDEX_FILE, ARCHIVE_V2_SHREDDING_FILE, ARCHIVE_V2_SIGNATURES_FILE,
    ARCHIVE_V2_TX_FLAG_HAS_COMPACT_VOTE_IX, ARCHIVE_V2_TX_FLAG_HAS_ERROR,
    ARCHIVE_V2_TX_FLAG_HAS_INNER_IX, ARCHIVE_V2_TX_FLAG_HAS_LOADED_ADDRESSES,
    ARCHIVE_V2_TX_FLAG_HAS_LOGS, ARCHIVE_V2_TX_FLAG_HAS_METADATA,
    ARCHIVE_V2_TX_FLAG_HAS_RETURN_DATA, ARCHIVE_V2_TX_FLAG_HAS_TOKEN_BALANCES,
    ARCHIVE_V2_TX_FLAG_MESSAGE_V0, ARCHIVE_V2_VOTE_HASH_REGISTRY_FILE,
    ArchiveV2ComputeBudgetInstructionData, ArchiveV2HotBlockBlob, ArchiveV2HotBlockHeader,
    ArchiveV2HotBlockIndexRow, ArchiveV2HotInstruction, ArchiveV2HotInstructionData,
    ArchiveV2HotLegacyMessage, ArchiveV2HotMessagePayload, ArchiveV2HotMetaRecord,
    ArchiveV2HotRewards, ArchiveV2HotTxRow, ArchiveV2HotV0Message, ArchiveV2HotV1Message,
    ArchiveV2SystemInstructionData, ArchiveV2VoteHashRef, ArchiveV2VoteLockoutOffset,
    ArchiveV2VoteStateUpdate, ArchiveV2VoteTowerSync, WINCODE_ARCHIVE_V2_FLAG_LEB128,
    WINCODE_ARCHIVE_V2_HOT_BLOCK_VERSION, WincodeArchiveV2Footer, WincodeArchiveV2Header,
    WincodeArchiveV2NoRegistryAddressTableLookup, WincodeArchiveV2NoRegistryBlock,
    WincodeArchiveV2NoRegistryBlockHeader, WincodeArchiveV2NoRegistryInstruction,
    WincodeArchiveV2NoRegistryLogs, WincodeArchiveV2NoRegistryMessage,
    WincodeArchiveV2NoRegistryMeta, WincodeArchiveV2NoRegistryReturnData,
    WincodeArchiveV2NoRegistryReward, WincodeArchiveV2NoRegistryRewards,
    WincodeArchiveV2NoRegistryTokenBalance, WincodeArchiveV2NoRegistryTransaction,
    WincodeArchiveV2NoRegistryTx, WincodeArchiveV2NoRegistryV1Message, WincodeArchiveV2Payload,
    WincodeArchiveV2PohRecord, WincodeArchiveV2Rewards, read_archive_v2_hot_block_index,
    write_archive_v2_hot_block_index,
};

use blockzilla_compact::{
    CompactBlockHeader, CompactInnerInstructions, CompactLogStream, CompactMessageHeader,
    CompactMetaV1, CompactPohEntry, CompactReturnData, CompactReward, CompactTokenBalance,
    CompactTransactionConfig, CompactTransactionError, LogEvent, OwnedCompactAddressTableLookup,
    OwnedCompactInstruction, OwnedCompactLegacyMessage, OwnedCompactMessage,
    OwnedCompactRecentBlockhash, OwnedCompactTransaction, OwnedCompactV0Message,
    OwnedCompactV1Message,
};

use blockzilla_live_format::{
    LIVE_PUBKEY_RUN_HOT_FILE, LIVE_PUBKEY_RUN_RECORD_LEN, LIVE_PUBKEY_RUNS_DIR,
    live_producer::LivePubkeyCountRecord,
};

use blockzilla_primitives::{
    CompactPubkey, WincodeLeb128FramedReader, WincodeLeb128FramedWriter, wincode_leb128_config,
};

use blockzilla_program_logs::{
    program_logs::ProgramLog, program_logs::system_program::PubkeyOrString,
    program_logs::system_program::SystemAddress, program_logs::system_program::SystemProgramLog,
    program_logs::token_2022::Token2022Log,
};

use blockzilla_registry::{KeyIndex, write_registry_iter};

use core::mem::MaybeUninit;

use gxhash::{GxBuildHasher, HashMap as GxHashMap};

use memmap2::{Mmap, MmapOptions};

use rayon::prelude::*;

use sha2::{Digest, Sha256};

use solana_pubkey::Pubkey;

use solana_vote_interface::{
    instruction::VoteInstruction,
    state::{TowerSync as SolanaTowerSync, VoteStateUpdate as SolanaVoteStateUpdate},
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use std::{
    collections::{BinaryHeap, VecDeque},
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};

use tracing::{info, warn};

use wincode::{ReadResult, SchemaRead, config::Config, io::Reader, len::SeqLen};

use crate::{BUFFER_SIZE, ProgressTracker};

pub(crate) mod direct_agave;

pub(crate) mod execution_canary;

const POH_FILE: &str = ARCHIVE_V2_POH_FILE;

const SHREDDING_FILE: &str = ARCHIVE_V2_SHREDDING_FILE;

const REGISTRY_FILE: &str = ARCHIVE_V2_PUBKEY_REGISTRY_FILE;

const REGISTRY_COUNTS_FILE: &str = ARCHIVE_V2_PUBKEY_REGISTRY_COUNTS_FILE;

const REGISTRY_INDEX_FILE: &str = ARCHIVE_V2_PUBKEY_REGISTRY_INDEX_FILE;

const BLOCKHASH_REGISTRY_FILE: &str = ARCHIVE_V2_BLOCKHASH_REGISTRY_FILE;

const PREV_BLOCKHASH_TAIL_FILE: &str = ARCHIVE_V2_PREV_BLOCKHASH_TAIL_FILE;

const ARCHIVE_FLAGS_LEB128: u32 = WINCODE_ARCHIVE_V2_FLAG_LEB128;

const ROLLING_BLOCKHASH_CAPACITY: usize = 300;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum LiveRegistrySource {
    Auto,
    Counts,
    Runs,
    Touches,
    Scan,
}

const LIVE_FINALIZER_IO_BUFFER_SIZE: usize = 8 << 20;

const LIVE_FINALIZER_MAX_FRAME_SIZE: usize = 256 << 20;

const LIVE_PUBKEY_RUN_MERGE_FAN_IN: usize = 64;

const LIVE_REGISTRY_PREPARED_MARKER: &str = "archive-v2-live-registry-prepared.v1";

const LIVE_REGISTRY_PREPARE_TEMP_DIR: &str = ".archive-v2-live-registry-prepare.tmp";

const HOT_REUSABLE_BUFFER_RETAIN_LIMIT: usize = 64 << 20;

const VOTE_INSTRUCTION_DECODE_LIMIT: u64 = 1232;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LiveRegistryRunSnapshot {
    files: usize,
    bytes: u64,
    fingerprint: [u8; 32],
}

fn snapshot_live_pubkey_runs(run_dir: &Path) -> Result<LiveRegistryRunSnapshot> {
    let runs = collect_pubkey_run_paths(run_dir)?;
    anyhow::ensure!(
        !runs.is_empty(),
        "live pubkey run sidecar missing or empty: {}",
        run_dir.display()
    );

    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    for path in &runs {
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("stat pubkey run {}", path.display()))?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .with_context(|| format!("pubkey run name is not UTF-8: {}", path.display()))?;
        let modified_nanos = metadata
            .modified()
            .with_context(|| format!("read pubkey run mtime {}", path.display()))?
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        hasher.update((name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update(metadata.len().to_le_bytes());
        hasher.update(modified_nanos.to_le_bytes());
        bytes = bytes.saturating_add(metadata.len());
    }

    Ok(LiveRegistryRunSnapshot {
        files: runs.len(),
        bytes,
        fingerprint: hasher.finalize().into(),
    })
}

fn live_registry_marker_field<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        line.strip_prefix(name)
            .and_then(|value| value.strip_prefix('='))
    })
}

fn validate_prepared_live_registry(
    output_dir: &Path,
    marker_path: &Path,
    source: LiveRegistryRunSnapshot,
) -> Result<(u64, u64)> {
    let marker = std::fs::read_to_string(marker_path)
        .with_context(|| format!("read live registry marker {}", marker_path.display()))?;
    anyhow::ensure!(
        live_registry_marker_field(&marker, "version") == Some("1"),
        "unsupported live registry marker version in {}",
        marker_path.display()
    );
    let marker_files = live_registry_marker_field(&marker, "source_run_files")
        .context("live registry marker is missing source_run_files")?
        .parse::<usize>()
        .context("invalid live registry marker source_run_files")?;
    let marker_source_bytes = live_registry_marker_field(&marker, "source_run_bytes")
        .context("live registry marker is missing source_run_bytes")?
        .parse::<u64>()
        .context("invalid live registry marker source_run_bytes")?;
    let marker_fingerprint = live_registry_marker_field(&marker, "source_fingerprint")
        .context("live registry marker is missing source_fingerprint")?;
    anyhow::ensure!(
        marker_files == source.files
            && marker_source_bytes == source.bytes
            && marker_fingerprint == hex32(&source.fingerprint),
        "live pubkey runs changed after registry preparation: marker={} current_files={} current_bytes={} current_fingerprint={}",
        marker_path.display(),
        source.files,
        source.bytes,
        hex32(&source.fingerprint),
    );

    let registry_path = output_dir.join(REGISTRY_FILE);
    let registry_counts_path = output_dir.join(REGISTRY_COUNTS_FILE);
    let registry_bytes = std::fs::metadata(&registry_path)
        .with_context(|| format!("stat prepared registry {}", registry_path.display()))?
        .len();
    let registry_counts_bytes = std::fs::metadata(&registry_counts_path)
        .with_context(|| {
            format!(
                "stat prepared registry counts {}",
                registry_counts_path.display()
            )
        })?
        .len();
    anyhow::ensure!(
        registry_bytes > 0 && registry_bytes % 32 == 0,
        "prepared live registry has invalid byte length {}: {}",
        registry_bytes,
        registry_path.display()
    );
    anyhow::ensure!(
        registry_counts_bytes > 0,
        "prepared live registry counts is empty: {}",
        registry_counts_path.display()
    );
    let marker_registry_bytes = live_registry_marker_field(&marker, "registry_bytes")
        .context("live registry marker is missing registry_bytes")?
        .parse::<u64>()
        .context("invalid live registry marker registry_bytes")?;
    let marker_registry_counts_bytes = live_registry_marker_field(&marker, "registry_counts_bytes")
        .context("live registry marker is missing registry_counts_bytes")?
        .parse::<u64>()
        .context("invalid live registry marker registry_counts_bytes")?;
    anyhow::ensure!(
        registry_bytes == marker_registry_bytes
            && registry_counts_bytes == marker_registry_counts_bytes,
        "prepared live registry files do not match marker {}",
        marker_path.display()
    );
    Ok((registry_bytes, registry_counts_bytes))
}

fn write_live_registry_prepared_marker(
    output_dir: &Path,
    marker_path: &Path,
    source: LiveRegistryRunSnapshot,
    registry_bytes: u64,
    registry_counts_bytes: u64,
) -> Result<()> {
    let marker_tmp = output_dir.join(format!("{LIVE_REGISTRY_PREPARED_MARKER}.tmp"));
    if marker_tmp.exists() {
        std::fs::remove_file(&marker_tmp)
            .with_context(|| format!("remove stale marker temp {}", marker_tmp.display()))?;
    }
    let mut file = File::create(&marker_tmp)
        .with_context(|| format!("create live registry marker {}", marker_tmp.display()))?;
    writeln!(file, "version=1")?;
    writeln!(file, "source_run_files={}", source.files)?;
    writeln!(file, "source_run_bytes={}", source.bytes)?;
    writeln!(file, "source_fingerprint={}", hex32(&source.fingerprint))?;
    writeln!(file, "registry_bytes={registry_bytes}")?;
    writeln!(file, "registry_counts_bytes={registry_counts_bytes}")?;
    file.sync_all()
        .with_context(|| format!("sync live registry marker {}", marker_tmp.display()))?;
    drop(file);
    std::fs::rename(&marker_tmp, marker_path).with_context(|| {
        format!(
            "publish live registry marker {} -> {}",
            marker_tmp.display(),
            marker_path.display()
        )
    })?;
    crate::first_seen_finalization::sync_directory(output_dir)?;
    Ok(())
}

pub(crate) fn prepare_live_registry_from_runs(
    capture_dir: &Path,
    output_dir: &Path,
    resume: bool,
) -> Result<()> {
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("create output dir {}", output_dir.display()))?;
    let run_dir = capture_dir.join("index").join(LIVE_PUBKEY_RUNS_DIR);
    let source = snapshot_live_pubkey_runs(&run_dir)?;
    let marker_path = output_dir.join(LIVE_REGISTRY_PREPARED_MARKER);

    if resume && marker_path.is_file() {
        let (registry_bytes, registry_counts_bytes) =
            validate_prepared_live_registry(output_dir, &marker_path, source)?;
        info!(
            "Reusing prepared live registry: runs={} run_bytes={} registry_bytes={} counts_bytes={} output={}",
            source.files,
            source.bytes,
            registry_bytes,
            registry_counts_bytes,
            output_dir.display()
        );
        return Ok(());
    }

    if marker_path.exists() {
        std::fs::remove_file(&marker_path).with_context(|| {
            format!(
                "remove stale live registry marker {}",
                marker_path.display()
            )
        })?;
        crate::first_seen_finalization::sync_directory(output_dir)?;
    }
    let marker_tmp = output_dir.join(format!("{LIVE_REGISTRY_PREPARED_MARKER}.tmp"));
    if marker_tmp.exists() {
        std::fs::remove_file(&marker_tmp)
            .with_context(|| format!("remove stale marker temp {}", marker_tmp.display()))?;
    }

    let prepare_dir = output_dir.join(LIVE_REGISTRY_PREPARE_TEMP_DIR);
    if prepare_dir.exists() {
        std::fs::remove_dir_all(&prepare_dir)
            .with_context(|| format!("remove stale prepare dir {}", prepare_dir.display()))?;
    }
    std::fs::create_dir_all(&prepare_dir)
        .with_context(|| format!("create prepare dir {}", prepare_dir.display()))?;
    let registry_candidate = prepare_dir.join(REGISTRY_FILE);
    let counts_candidate = prepare_dir.join(REGISTRY_COUNTS_FILE);
    build_live_pubkey_registry_from_runs(
        &run_dir,
        &registry_candidate,
        &counts_candidate,
        &prepare_dir.join("sort"),
    )?;

    let registry_bytes = std::fs::metadata(&registry_candidate)
        .with_context(|| format!("stat registry candidate {}", registry_candidate.display()))?
        .len();
    let registry_counts_bytes = std::fs::metadata(&counts_candidate)
        .with_context(|| format!("stat counts candidate {}", counts_candidate.display()))?
        .len();
    anyhow::ensure!(
        registry_bytes > 0 && registry_bytes % 32 == 0,
        "live registry candidate has invalid byte length {registry_bytes}"
    );
    anyhow::ensure!(
        registry_counts_bytes > 0,
        "live registry counts candidate is empty"
    );
    for path in [&registry_candidate, &counts_candidate] {
        File::open(path)
            .with_context(|| format!("open candidate for sync {}", path.display()))?
            .sync_all()
            .with_context(|| format!("sync candidate {}", path.display()))?;
    }

    let registry_path = output_dir.join(REGISTRY_FILE);
    let registry_counts_path = output_dir.join(REGISTRY_COUNTS_FILE);
    std::fs::rename(&registry_candidate, &registry_path).with_context(|| {
        format!(
            "publish live registry {} -> {}",
            registry_candidate.display(),
            registry_path.display()
        )
    })?;
    std::fs::rename(&counts_candidate, &registry_counts_path).with_context(|| {
        format!(
            "publish live registry counts {} -> {}",
            counts_candidate.display(),
            registry_counts_path.display()
        )
    })?;
    std::fs::remove_dir(&prepare_dir)
        .with_context(|| format!("remove empty prepare dir {}", prepare_dir.display()))?;
    crate::first_seen_finalization::sync_directory(output_dir)?;
    write_live_registry_prepared_marker(
        output_dir,
        &marker_path,
        source,
        registry_bytes,
        registry_counts_bytes,
    )?;
    info!(
        "Prepared live registry stage complete: runs={} run_bytes={} registry_bytes={} counts_bytes={} marker={}",
        source.files,
        source.bytes,
        registry_bytes,
        registry_counts_bytes,
        marker_path.display()
    );
    Ok(())
}

struct LiveHotBuildReport {
    blocks: u64,
    transactions: u64,
    signatures: u64,
    compressed_bytes: u64,
    uncompressed_bytes: u64,
}

fn build_degraded_hot_blocks_inner(
    capture_dir: &Path,
    output_dir: &Path,
    level: i32,
    max_blocks: Option<u64>,
    resume: bool,
    registry_source: LiveRegistrySource,
) -> Result<LiveHotBuildReport> {
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("create output dir {}", output_dir.display()))?;

    let live_blocks_path = capture_dir
        .join("blocks")
        .join("live-no-registry-blocks.bin");
    let live_pubkey_counts_path = capture_dir.join("index").join("pubkey-counts.bin");
    let live_pubkey_touches_path = capture_dir.join("index").join("pubkey-touches.bin");
    let live_pubkey_runs_dir = capture_dir.join("index").join(LIVE_PUBKEY_RUNS_DIR);
    let live_blockhash_registry_path = capture_dir.join("index").join(BLOCKHASH_REGISTRY_FILE);
    let live_signatures_path = capture_dir.join("index").join(ARCHIVE_V2_SIGNATURES_FILE);
    anyhow::ensure!(
        crate::file_nonempty(&live_blocks_path),
        "live block file missing or empty: {}",
        live_blocks_path.display()
    );
    anyhow::ensure!(
        crate::file_nonempty(&live_blockhash_registry_path),
        "live blockhash registry missing or empty: {}",
        live_blockhash_registry_path.display()
    );
    let live_blockhash_bytes = std::fs::metadata(&live_blockhash_registry_path)
        .with_context(|| format!("stat {}", live_blockhash_registry_path.display()))?
        .len();
    anyhow::ensure!(
        live_blockhash_bytes % 32 == 0,
        "live blockhash registry has invalid byte length {}: {}",
        live_blockhash_bytes,
        live_blockhash_registry_path.display()
    );
    let live_block_count = live_blockhash_bytes / 32;
    anyhow::ensure!(
        max_blocks.is_some() || live_block_count <= crate::SLOTS_PER_EPOCH,
        "live capture contains {} blockhash rows, exceeding one epoch's {} slots",
        live_block_count,
        crate::SLOTS_PER_EPOCH
    );
    let registry_path = output_dir.join(REGISTRY_FILE);
    let registry_counts_path = output_dir.join(REGISTRY_COUNTS_FILE);
    if resume
        && !matches!(registry_source, LiveRegistrySource::Runs)
        && crate::file_nonempty(&registry_path)
        && crate::file_nonempty(&registry_counts_path)
    {
        info!(
            "Reusing existing live pubkey registry: {}",
            registry_path.display()
        );
    } else {
        let registry_source = if max_blocks.is_some()
            && matches!(
                registry_source,
                LiveRegistrySource::Auto | LiveRegistrySource::Counts | LiveRegistrySource::Touches
            ) {
            warn!(
                "Bounded live finalization ignores unbounded whole-capture registry sidecars and scans only the selected block prefix; pass --registry-source runs with a bounded run directory to use the low-memory merge path"
            );
            LiveRegistrySource::Scan
        } else {
            registry_source
        };
        match registry_source {
            LiveRegistrySource::Scan => build_live_no_registry_pubkey_registry(
                &live_blocks_path,
                &registry_path,
                &registry_counts_path,
                max_blocks,
            )?,
            LiveRegistrySource::Counts => build_live_pubkey_registry_from_counts(
                &live_pubkey_counts_path,
                &registry_path,
                &registry_counts_path,
            )?,
            LiveRegistrySource::Runs => {
                prepare_live_registry_from_runs(capture_dir, output_dir, resume)?
            }
            LiveRegistrySource::Touches => build_live_pubkey_registry_from_touches(
                &live_pubkey_touches_path,
                &registry_path,
                &registry_counts_path,
                &output_dir.join(".pubkey-touch-sort"),
            )?,
            LiveRegistrySource::Auto => match preferred_auto_live_registry_source(
                &live_pubkey_counts_path,
                &live_pubkey_runs_dir,
                &live_pubkey_touches_path,
            )? {
                LiveRegistrySource::Runs => {
                    prepare_live_registry_from_runs(capture_dir, output_dir, resume)?;
                }
                LiveRegistrySource::Counts => {
                    build_live_pubkey_registry_from_counts(
                        &live_pubkey_counts_path,
                        &registry_path,
                        &registry_counts_path,
                    )?;
                }
                LiveRegistrySource::Touches => {
                    build_live_pubkey_registry_from_touches(
                        &live_pubkey_touches_path,
                        &registry_path,
                        &registry_counts_path,
                        &output_dir.join(".pubkey-touch-sort"),
                    )?;
                }
                LiveRegistrySource::Scan => {
                    warn!(
                        "Live pubkey-count/run/touch sidecars missing or empty; falling back to block scan: counts={} runs={} touches={}",
                        live_pubkey_counts_path.display(),
                        live_pubkey_runs_dir.display(),
                        live_pubkey_touches_path.display()
                    );
                    build_live_no_registry_pubkey_registry(
                        &live_blocks_path,
                        &registry_path,
                        &registry_counts_path,
                        max_blocks,
                    )?;
                }
                LiveRegistrySource::Auto => unreachable!("auto source selection returned auto"),
            },
        }
    }

    let blockhash_registry_path = output_dir.join(BLOCKHASH_REGISTRY_FILE);
    if !(resume && crate::file_nonempty(&blockhash_registry_path)) {
        if let Some(limit) = max_blocks {
            copy_file_prefix(
                &live_blockhash_registry_path,
                &blockhash_registry_path,
                limit
                    .checked_mul(32)
                    .context("live blockhash prefix length overflow")?,
            )?;
        } else {
            link_or_copy_registry_sidecar(&live_blockhash_registry_path, &blockhash_registry_path)?;
        }
    }
    let poh_path = output_dir.join(POH_FILE);
    anyhow::ensure!(
        !poh_path.exists(),
        "degraded repair finalization refuses canonical PoH output {}",
        poh_path.display()
    );

    let registry_index_path = output_dir.join(REGISTRY_INDEX_FILE);
    let key_index = load_or_build_registry_key_index(&registry_path, &registry_index_path, resume)?;
    let known_program_ids = KnownProgramIds::from_index(&key_index);
    let blockhashes = load_blockhash_registry_plain(&blockhash_registry_path)?;

    let blocks_path = output_dir.join(ARCHIVE_V2_BLOCKS_FILE);
    let index_path = output_dir.join(ARCHIVE_V2_BLOCK_INDEX_FILE);
    let meta_path = output_dir.join(ARCHIVE_V2_META_FILE);
    let meta_tmp = crate::first_seen_finalization::first_seen_temp_path(&meta_path);
    let signatures_path = output_dir.join(ARCHIVE_V2_SIGNATURES_FILE);
    let shredding_path = output_dir.join(SHREDDING_FILE);
    let vote_hash_registry_path = output_dir.join(ARCHIVE_V2_VOTE_HASH_REGISTRY_FILE);

    let input_file = File::open(&live_blocks_path)
        .with_context(|| format!("open {}", live_blocks_path.display()))?;
    let mut reader = WincodeLeb128FramedReader::new(BufReader::with_capacity(
        LIVE_FINALIZER_IO_BUFFER_SIZE,
        input_file,
    ));
    let blocks_file =
        File::create(&blocks_path).with_context(|| format!("create {}", blocks_path.display()))?;
    let mut blocks_writer = BufWriter::with_capacity(LIVE_FINALIZER_IO_BUFFER_SIZE, blocks_file);
    if meta_tmp.exists() {
        std::fs::remove_file(&meta_tmp)
            .with_context(|| format!("remove stale live metadata temp {}", meta_tmp.display()))?;
    }
    let meta_file =
        File::create(&meta_tmp).with_context(|| format!("create {}", meta_tmp.display()))?;
    let mut meta_writer = WincodeLeb128FramedWriter::new(BufWriter::with_capacity(
        LIVE_FINALIZER_IO_BUFFER_SIZE,
        meta_file,
    ));
    let mut reused_live_signatures = false;
    let mut signatures_writer =
        if max_blocks.is_none() && crate::file_nonempty(&live_signatures_path) {
            link_or_copy_registry_sidecar(&live_signatures_path, &signatures_path)?;
            reused_live_signatures = true;
            None
        } else {
            let signatures_file = File::create(&signatures_path)
                .with_context(|| format!("create {}", signatures_path.display()))?;
            Some(BufWriter::with_capacity(
                LIVE_FINALIZER_IO_BUFFER_SIZE,
                signatures_file,
            ))
        };
    anyhow::ensure!(
        !shredding_path.exists(),
        "degraded repair finalization refuses canonical shredding output {}",
        shredding_path.display()
    );

    write_hot_meta(
        &mut meta_writer,
        &ArchiveV2HotMetaRecord::Header(WincodeArchiveV2Header {
            version: WINCODE_ARCHIVE_V2_HOT_BLOCK_VERSION,
            flags: ARCHIVE_FLAGS_LEB128,
        }),
    )?;

    let mut compressor = zstd::bulk::Compressor::new(level).context("create zstd compressor")?;
    let mut rolling_blockhashes = RollingBlockhashIndex::new(ROLLING_BLOCKHASH_CAPACITY);
    let mut progress = ProgressTracker::new("Archive V2 Live Hot Write");
    let mut timings = ArchiveV2Timings::from_env();
    let mut rows = Vec::new();
    let mut slot_to_block_id: GxHashMap<u64, u32> =
        GxHashMap::with_hasher(GxBuildHasher::default());
    let mut vote_hashes = VoteHashRegistryBuilder::default();
    let mut footer = WincodeArchiveV2Footer::default();
    let mut block_bytes = Vec::new();
    let mut compressed_buf = Vec::new();
    let mut hot_block_buffers = HotBlockBuffers::default();
    let mut blob_offset = 0u64;
    let mut uncompressed_bytes = 0u64;
    let mut compressed_bytes = 0u64;
    let mut first_tx_ordinal = 0u64;
    let mut first_signature_ordinal = 0u64;
    let mut nonce_recent_blockhashes = 0u64;
    let mut block_id = 0u32;
    let started = Instant::now();

    let read_signature_counts_only = signatures_writer.is_none();
    while let Some((_len, block)) = if read_signature_counts_only {
        read_live_no_registry_block_signature_counts(&mut reader)?
            .map(|(len, block)| (len, LiveFinalizerBlock::SignatureCounts(block)))
    } else {
        read_live_no_registry_block(&mut reader)?
            .map(|(len, block)| (len, LiveFinalizerBlock::Full(block)))
    } {
        let slot = block.slot();
        anyhow::ensure!(
            block.blockhash_id() == block_id,
            "live block slot {} has blockhash id {}, expected {}",
            slot,
            block.blockhash_id(),
            block_id
        );
        let current_blockhash = *blockhashes.get(block_id as usize).with_context(|| {
            format!("missing live blockhash registry row for block_id {block_id}")
        })?;

        rolling_blockhashes.prune_for_slot(slot)?;
        let (hot_block, block_signature_count) = hot_block_from_live_finalizer_block(
            block,
            &key_index,
            &rolling_blockhashes,
            block_id,
            &mut nonce_recent_blockhashes,
            &known_program_ids,
            &slot_to_block_id,
            &mut vote_hashes,
            signatures_writer
                .as_mut()
                .map(|writer| writer as &mut dyn Write),
            None,
            &mut hot_block_buffers,
            &mut timings,
        )
        .with_context(|| format!("slot {slot} live hot block encode"))?;
        let tx_count = hot_block.tx_count;

        block_bytes.clear();
        let serialize_started = timings.detail_timer();
        wincode::config::serialize_into(&mut block_bytes, &hot_block, wincode_leb128_config())?;
        timings.hot_block_serialize += serialize_started.elapsed();
        hot_block_buffers.recycle(hot_block);
        let uncompressed_len =
            u32::try_from(block_bytes.len()).context("hot live block payload exceeds u32::MAX")?;
        let compress_bound = zstd::zstd_safe::compress_bound(block_bytes.len());
        if compressed_buf.capacity() < compress_bound {
            compressed_buf.reserve(compress_bound.saturating_sub(compressed_buf.len()));
            timings.hot_zstd_buffer_reserves += 1;
        }
        timings.hot_zstd_buffer_capacity_max = timings
            .hot_zstd_buffer_capacity_max
            .max(compressed_buf.capacity());
        let compress_started = timings.detail_timer();
        compressor
            .compress_to_buffer(&block_bytes, &mut compressed_buf)
            .with_context(|| format!("zstd compress live hot block_id {block_id}"))?;
        timings.hot_zstd_compress += compress_started.elapsed();
        let compressed_len = u32::try_from(compressed_buf.len())
            .context("compressed live hot block exceeds u32::MAX")?;
        let write_started = timings.detail_timer();
        blocks_writer
            .write_all(&compressed_buf)
            .with_context(|| format!("write {}", blocks_path.display()))?;
        timings.hot_block_write += write_started.elapsed();
        rows.push(ArchiveV2HotBlockIndexRow {
            block_id,
            slot,
            compressed_offset: blob_offset,
            compressed_len,
            uncompressed_len,
            tx_count,
            first_tx_ordinal,
            first_signature_ordinal,
            signature_count: block_signature_count,
        });
        blob_offset += compressed_len as u64;
        uncompressed_bytes += uncompressed_len as u64;
        compressed_bytes += compressed_len as u64;
        first_tx_ordinal += tx_count as u64;
        first_signature_ordinal += block_signature_count as u64;
        footer.blocks += 1;
        footer.transactions += tx_count as u64;

        rolling_blockhashes.insert(current_blockhash, block_id as i32, slot)?;
        slot_to_block_id.insert(slot, block_id);
        block_id = block_id.wrapping_add(1);
        progress.update_slot(slot);
        progress.update(1, tx_count as u64);
        trim_hot_memory(
            block_id,
            &mut block_bytes,
            &mut compressed_buf,
            &mut Vec::new(),
            None,
        );
        hot_block_buffers.trim();
        if max_blocks.is_some_and(|limit| rows.len() as u64 >= limit) {
            break;
        }
    }

    if max_blocks.is_none() {
        anyhow::ensure!(
            block_id as usize == blockhashes.len(),
            "live blockhash registry count {} does not match live blocks {}",
            blockhashes.len(),
            block_id
        );
    }

    footer.nonce_recent_blockhashes += nonce_recent_blockhashes;
    blocks_writer
        .flush()
        .with_context(|| format!("flush {}", blocks_path.display()))?;
    if let Some(writer) = signatures_writer.as_mut() {
        writer
            .flush()
            .with_context(|| format!("flush {}", signatures_path.display()))?;
    } else if reused_live_signatures {
        let expected_signature_bytes = first_signature_ordinal
            .checked_mul(64)
            .context("signature byte count overflow")?;
        let actual_signature_bytes = std::fs::metadata(&signatures_path)
            .with_context(|| format!("stat {}", signatures_path.display()))?
            .len();
        anyhow::ensure!(
            actual_signature_bytes == expected_signature_bytes,
            "live signature sidecar byte length {} does not match expected {} signatures bytes {}",
            actual_signature_bytes,
            first_signature_ordinal,
            expected_signature_bytes
        );
    }
    vote_hashes.write(&vote_hash_registry_path)?;
    write_archive_v2_hot_block_index(&index_path, blob_offset, level, 0, &rows)?;
    write_hot_meta(
        &mut meta_writer,
        &ArchiveV2HotMetaRecord::Footer(footer.clone()),
    )?;
    meta_writer.flush()?;
    drop(meta_writer);
    // Metadata is the publication marker for readers and the pipeline. Make every candidate
    // sidecar durable first, then atomically reveal metadata last. A killed live finalizer can
    // therefore leave only an unmistakable partial directory, never a false completed epoch.
    crate::first_seen_finalization::sync_candidate_files(output_dir)?;
    std::fs::rename(&meta_tmp, &meta_path)
        .with_context(|| format!("rename {} to {}", meta_tmp.display(), meta_path.display()))?;
    crate::first_seen_finalization::sync_directory(output_dir)?;
    progress.final_report();
    let ratio = if uncompressed_bytes > 0 {
        compressed_bytes as f64 * 100.0 / uncompressed_bytes as f64
    } else {
        0.0
    };
    info!(
        "Archive V2 live hot-block build complete in {:.2}s: blocks={} txs={} signatures={} level={} max_blocks={:?} uncompressed_bytes={} compressed_bytes={} ratio_pct={:.2} nonce_recent_blockhashes={} blocks_file={} index={} meta={} signatures={} vote_hash_registry={} poh={} shredding={}",
        started.elapsed().as_secs_f64(),
        rows.len(),
        first_tx_ordinal,
        first_signature_ordinal,
        level,
        max_blocks,
        uncompressed_bytes,
        compressed_bytes,
        ratio,
        nonce_recent_blockhashes,
        blocks_path.display(),
        index_path.display(),
        meta_path.display(),
        signatures_path.display(),
        vote_hash_registry_path.display(),
        "omitted_noncanonical",
        "omitted_noncanonical"
    );
    info!(
        "Archive V2 live hot timings: optimize_no_registry_total={:.3}s tx_decode_compact={:.3}s metadata_decode_compact={:.3}s metadata_logs_decode_compact={:.3}s metadata_pubkey_compact={:.3}s rewards_decode_compact={:.3}s hot_message_build={:.3}s hot_message_encode={:.3}s hot_metadata_encode={:.3}s hot_signature_write={:.3}s hot_block_serialize={:.3}s hot_zstd_compress={:.3}s hot_block_write={:.3}s hot_shredding_write={:.3}s zstd_buffer_reserves={} zstd_buffer_capacity_max={}",
        (timings.tx_decode_compact
            + timings.metadata_decode_compact
            + timings.rewards_decode_compact)
            .as_secs_f64(),
        timings.tx_decode_compact.as_secs_f64(),
        timings.metadata_decode_compact.as_secs_f64(),
        timings.metadata_logs_decode_compact.as_secs_f64(),
        timings.metadata_pubkey_compact.as_secs_f64(),
        timings.rewards_decode_compact.as_secs_f64(),
        timings.hot_message_build.as_secs_f64(),
        timings.hot_message_encode.as_secs_f64(),
        timings.hot_metadata_encode.as_secs_f64(),
        timings.hot_signature_write.as_secs_f64(),
        timings.hot_block_serialize.as_secs_f64(),
        timings.hot_zstd_compress.as_secs_f64(),
        timings.hot_block_write.as_secs_f64(),
        timings.hot_poh_write.as_secs_f64(),
        timings.hot_zstd_buffer_reserves,
        timings.hot_zstd_buffer_capacity_max,
    );
    Ok(LiveHotBuildReport {
        blocks: rows.len() as u64,
        transactions: first_tx_ordinal,
        signatures: first_signature_ordinal,
        compressed_bytes,
        uncompressed_bytes,
    })
}

fn build_live_no_registry_pubkey_registry(
    input: &Path,
    registry_path: &Path,
    registry_counts_path: &Path,
    max_blocks: Option<u64>,
) -> Result<()> {
    info!("Building live pubkey registry from {}", input.display());
    let file = File::open(input).with_context(|| format!("open {}", input.display()))?;
    let mut reader = WincodeLeb128FramedReader::new(BufReader::with_capacity(
        LIVE_FINALIZER_IO_BUFFER_SIZE,
        file,
    ));
    let mut counter = ArchivePubkeyCounter::new(8_000_000);
    let mut progress = ProgressTracker::new("Live Archive V2 Registry");
    let started = Instant::now();
    let mut blocks = 0u64;
    let mut txs = 0u64;

    while let Some((_len, block)) = read_live_no_registry_block(&mut reader)? {
        let tx_count = count_no_registry_block_pubkeys(&block, &mut counter)
            .with_context(|| format!("slot {} count pubkeys", block.header.compact.slot))?;
        blocks += 1;
        txs += tx_count;
        progress.update_slot(block.header.compact.slot);
        progress.update(1, tx_count);
        if max_blocks.is_some_and(|limit| blocks >= limit) {
            break;
        }
    }

    progress.final_report();
    let mut items: Vec<([u8; 32], u32)> = counter.counts.into_iter().collect();
    items.sort_unstable_by(|(left_key, left_count), (right_key, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_key.cmp(right_key))
    });

    const BUILTIN_PROGRAM_KEYS: &[Pubkey] = &[solana_pubkey::pubkey!(
        "ComputeBudget111111111111111111111111111111"
    )];
    let missing_builtins = BUILTIN_PROGRAM_KEYS
        .iter()
        .map(|key| key.to_bytes())
        .filter(|builtin| !items.iter().any(|(key, _)| key == builtin))
        .collect::<Vec<_>>();
    let registry_len = missing_builtins.len() + items.len();

    write_registry_iter(
        registry_path,
        missing_builtins
            .iter()
            .copied()
            .chain(items.iter().map(|(key, _)| *key)),
    )
    .with_context(|| format!("write {}", registry_path.display()))?;
    write_live_registry_counts(
        registry_counts_path,
        std::iter::repeat_n(0, missing_builtins.len()).chain(items.iter().map(|(_, count)| *count)),
    )
    .with_context(|| format!("write {}", registry_counts_path.display()))?;
    info!(
        "Live pubkey registry built in {:.2}s: blocks={} txs={} keys={} registry={} counts={}",
        started.elapsed().as_secs_f64(),
        blocks,
        txs,
        registry_len,
        registry_path.display(),
        registry_counts_path.display()
    );
    Ok(())
}

fn build_live_pubkey_registry_from_counts(
    input: &Path,
    registry_path: &Path,
    registry_counts_path: &Path,
) -> Result<()> {
    info!(
        "Building live pubkey registry from counts {}",
        input.display()
    );
    anyhow::ensure!(
        crate::file_nonempty(input),
        "live pubkey-count sidecar missing or empty: {}",
        input.display()
    );

    let started = Instant::now();
    let file = File::open(input).with_context(|| format!("open {}", input.display()))?;
    let mut reader = WincodeLeb128FramedReader::new(BufReader::with_capacity(
        LIVE_FINALIZER_IO_BUFFER_SIZE,
        file,
    ));
    let mut counts = GxHashMap::<[u8; 32], u32>::with_hasher(GxBuildHasher::default());
    let mut records = 0u64;
    while let Some((_len, record)) = reader.read::<LivePubkeyCountRecord>()? {
        records += 1;
        let count = u32::try_from(record.count).unwrap_or(u32::MAX);
        counts
            .entry(record.pubkey)
            .and_modify(|existing| *existing = existing.saturating_add(count))
            .or_insert(count);
    }
    let mut items = counts.into_iter().collect::<Vec<_>>();
    items.sort_unstable_by(|(left_key, left_count), (right_key, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_key.cmp(right_key))
    });

    const BUILTIN_PROGRAM_KEYS: &[Pubkey] = &[solana_pubkey::pubkey!(
        "ComputeBudget111111111111111111111111111111"
    )];
    let missing_builtins = BUILTIN_PROGRAM_KEYS
        .iter()
        .map(|key| key.to_bytes())
        .filter(|builtin| !items.iter().any(|(key, _)| key == builtin))
        .collect::<Vec<_>>();
    let registry_len = missing_builtins.len() + items.len();

    write_registry_iter(
        registry_path,
        missing_builtins
            .iter()
            .copied()
            .chain(items.iter().map(|(key, _)| *key)),
    )
    .with_context(|| format!("write {}", registry_path.display()))?;
    write_live_registry_counts(
        registry_counts_path,
        std::iter::repeat_n(0, missing_builtins.len()).chain(items.iter().map(|(_, count)| *count)),
    )
    .with_context(|| format!("write {}", registry_counts_path.display()))?;

    info!(
        "Live pubkey registry built from counts in {:.2}s: records={} keys={} registry={} counts={}",
        started.elapsed().as_secs_f64(),
        records,
        registry_len,
        registry_path.display(),
        registry_counts_path.display()
    );
    Ok(())
}

fn build_live_pubkey_registry_from_runs(
    run_dir: &Path,
    registry_path: &Path,
    registry_counts_path: &Path,
    temp_dir: &Path,
) -> Result<()> {
    info!(
        "Building live pubkey registry from sorted runs {}",
        run_dir.display()
    );
    let runs = collect_pubkey_run_paths(run_dir)?;
    anyhow::ensure!(
        !runs.is_empty(),
        "live pubkey run sidecar missing or empty: {}",
        run_dir.display()
    );

    if temp_dir.exists() {
        std::fs::remove_dir_all(temp_dir)
            .with_context(|| format!("remove {}", temp_dir.display()))?;
    }
    let freq_run_dir = temp_dir.join("freq-runs");
    std::fs::create_dir_all(&freq_run_dir)
        .with_context(|| format!("create {}", freq_run_dir.display()))?;

    let started = Instant::now();
    let bounded_key_runs = reduce_key_runs_to_fan_in(
        &runs,
        &temp_dir.join("key-merge-passes"),
        LIVE_PUBKEY_RUN_MERGE_FAN_IN,
    )?;
    let merge_report = merge_key_runs_to_frequency_runs(&bounded_key_runs, &freq_run_dir)?;
    let bounded_frequency_runs = reduce_frequency_runs_to_fan_in(
        &merge_report.frequency_runs,
        &temp_dir.join("frequency-merge-passes"),
        LIVE_PUBKEY_RUN_MERGE_FAN_IN,
    )?;
    write_registry_from_frequency_runs(
        &bounded_frequency_runs,
        registry_path,
        registry_counts_path,
        &merge_report.missing_builtins,
    )?;
    std::fs::remove_dir_all(temp_dir).with_context(|| format!("remove {}", temp_dir.display()))?;

    info!(
        "Live pubkey registry built from sorted runs in {:.2}s: unique_keys={} key_runs={} frequency_runs={} registry={} counts={}",
        started.elapsed().as_secs_f64(),
        merge_report.unique_keys,
        runs.len(),
        merge_report.frequency_runs.len(),
        registry_path.display(),
        registry_counts_path.display()
    );
    Ok(())
}

fn collect_pubkey_run_paths(run_dir: &Path) -> Result<Vec<PathBuf>> {
    if !run_dir.exists() {
        return Ok(Vec::new());
    }
    let mut runs = Vec::new();
    for entry in
        std::fs::read_dir(run_dir).with_context(|| format!("read {}", run_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == LIVE_PUBKEY_RUN_HOT_FILE || (name.starts_with("run-") && name.ends_with(".bin"))
        {
            let bytes = entry
                .metadata()
                .with_context(|| format!("stat {}", path.display()))?
                .len();
            anyhow::ensure!(
                bytes % LIVE_PUBKEY_RUN_RECORD_LEN as u64 == 0,
                "pubkey run {} has non-record-aligned length {}",
                path.display(),
                bytes
            );
            if bytes > 0 {
                runs.push(path);
            }
        }
    }
    runs.sort();
    Ok(runs)
}

fn pubkey_run_dir_nonempty(run_dir: &Path) -> Result<bool> {
    Ok(!collect_pubkey_run_paths(run_dir)?.is_empty())
}

fn preferred_auto_live_registry_source(
    counts_path: &Path,
    runs_dir: &Path,
    touches_path: &Path,
) -> Result<LiveRegistrySource> {
    if pubkey_run_dir_nonempty(runs_dir)? {
        Ok(LiveRegistrySource::Runs)
    } else if crate::file_nonempty(counts_path) {
        Ok(LiveRegistrySource::Counts)
    } else if crate::file_nonempty(touches_path) {
        Ok(LiveRegistrySource::Touches)
    } else {
        Ok(LiveRegistrySource::Scan)
    }
}

const PUBKEY_TOUCH_SORT_CHUNK_KEYS: usize = 1_000_000;

const PUBKEY_COUNT_SORT_CHUNK_RECORDS: usize = 1_000_000;

#[derive(Clone, Copy)]
struct PubkeyCountRecord {
    key: [u8; 32],
    count: u32,
}

fn build_live_pubkey_registry_from_touches(
    input: &Path,
    registry_path: &Path,
    registry_counts_path: &Path,
    temp_dir: &Path,
) -> Result<()> {
    info!(
        "Building live pubkey registry from touch log {}",
        input.display()
    );
    anyhow::ensure!(
        crate::file_nonempty(input),
        "live pubkey-touch sidecar missing or empty: {}",
        input.display()
    );
    let bytes = std::fs::metadata(input)
        .with_context(|| format!("stat {}", input.display()))?
        .len();
    anyhow::ensure!(
        bytes % 32 == 0,
        "pubkey touch log length {} is not a multiple of 32: {}",
        bytes,
        input.display()
    );

    if temp_dir.exists() {
        std::fs::remove_dir_all(temp_dir)
            .with_context(|| format!("remove {}", temp_dir.display()))?;
    }
    let key_run_dir = temp_dir.join("key-runs");
    let freq_run_dir = temp_dir.join("freq-runs");
    std::fs::create_dir_all(&key_run_dir)
        .with_context(|| format!("create {}", key_run_dir.display()))?;
    std::fs::create_dir_all(&freq_run_dir)
        .with_context(|| format!("create {}", freq_run_dir.display()))?;

    let started = Instant::now();
    let (key_runs, touch_count) = spill_pubkey_touch_key_runs(input, &key_run_dir)?;
    let merge_started = Instant::now();
    let bounded_key_runs = reduce_key_runs_to_fan_in(
        &key_runs,
        &temp_dir.join("key-merge-passes"),
        LIVE_PUBKEY_RUN_MERGE_FAN_IN,
    )?;
    let merge_report = merge_key_runs_to_frequency_runs(&bounded_key_runs, &freq_run_dir)?;
    let bounded_frequency_runs = reduce_frequency_runs_to_fan_in(
        &merge_report.frequency_runs,
        &temp_dir.join("frequency-merge-passes"),
        LIVE_PUBKEY_RUN_MERGE_FAN_IN,
    )?;
    write_registry_from_frequency_runs(
        &bounded_frequency_runs,
        registry_path,
        registry_counts_path,
        &merge_report.missing_builtins,
    )?;
    std::fs::remove_dir_all(temp_dir).with_context(|| format!("remove {}", temp_dir.display()))?;

    info!(
        "Live pubkey registry built from touches in {:.2}s: touches={} unique_keys={} key_runs={} frequency_runs={} key_merge_s={:.2} registry={} counts={}",
        started.elapsed().as_secs_f64(),
        touch_count,
        merge_report.unique_keys,
        key_runs.len(),
        merge_report.frequency_runs.len(),
        merge_started.elapsed().as_secs_f64(),
        registry_path.display(),
        registry_counts_path.display()
    );
    Ok(())
}

fn spill_pubkey_touch_key_runs(input: &Path, run_dir: &Path) -> Result<(Vec<PathBuf>, u64)> {
    let file = File::open(input).with_context(|| format!("open {}", input.display()))?;
    let total_touches = file
        .metadata()
        .with_context(|| format!("stat {}", input.display()))?
        .len()
        / 32;
    let mut reader = BufReader::with_capacity(LIVE_FINALIZER_IO_BUFFER_SIZE, file);
    let mut keys = Vec::<[u8; 32]>::with_capacity(PUBKEY_TOUCH_SORT_CHUNK_KEYS);
    let mut runs = Vec::new();
    let mut remaining = total_touches;
    let mut run_index = 0usize;

    while remaining > 0 {
        keys.clear();
        let take = remaining.min(PUBKEY_TOUCH_SORT_CHUNK_KEYS as u64) as usize;
        for _ in 0..take {
            let mut key = [0u8; 32];
            reader
                .read_exact(&mut key)
                .with_context(|| format!("read pubkey touch from {}", input.display()))?;
            keys.push(key);
        }
        keys.sort_unstable();
        let path = run_dir.join(format!("key-run-{run_index:05}.bin"));
        write_sorted_key_count_run(&path, &keys)?;
        runs.push(path);
        run_index += 1;
        remaining -= take as u64;
    }

    Ok((runs, total_touches))
}

fn write_sorted_key_count_run(path: &Path, keys: &[[u8; 32]]) -> Result<()> {
    let file = File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut writer = BufWriter::with_capacity(LIVE_FINALIZER_IO_BUFFER_SIZE, file);
    let mut index = 0usize;
    while index < keys.len() {
        let key = keys[index];
        let mut count = 1u32;
        index += 1;
        while index < keys.len() && keys[index] == key {
            count = count.saturating_add(1);
            index += 1;
        }
        write_pubkey_count_record(&mut writer, PubkeyCountRecord { key, count })?;
    }
    writer
        .flush()
        .with_context(|| format!("flush {}", path.display()))?;
    Ok(())
}

fn validate_live_run_merge_fan_in(fan_in: usize) -> Result<()> {
    anyhow::ensure!(
        fan_in >= 2,
        "live pubkey run merge fan-in must be at least 2"
    );
    anyhow::ensure!(
        fan_in <= LIVE_PUBKEY_RUN_MERGE_FAN_IN,
        "live pubkey run merge fan-in {fan_in} exceeds cursor cap {}",
        LIVE_PUBKEY_RUN_MERGE_FAN_IN
    );
    Ok(())
}

fn reduce_key_runs_to_fan_in(
    key_runs: &[PathBuf],
    merge_root: &Path,
    fan_in: usize,
) -> Result<Vec<PathBuf>> {
    validate_live_run_merge_fan_in(fan_in)?;
    if key_runs.len() <= fan_in {
        return Ok(key_runs.to_vec());
    }
    if merge_root.exists() {
        std::fs::remove_dir_all(merge_root)
            .with_context(|| format!("remove stale key merge root {}", merge_root.display()))?;
    }
    std::fs::create_dir_all(merge_root)
        .with_context(|| format!("create key merge root {}", merge_root.display()))?;

    let mut current = key_runs.to_vec();
    let mut pass = 0usize;
    while current.len() > fan_in {
        let pass_dir = merge_root.join(format!("pass-{pass:03}"));
        std::fs::create_dir_all(&pass_dir)
            .with_context(|| format!("create key merge pass {}", pass_dir.display()))?;
        let mut next = Vec::with_capacity(current.len().div_ceil(fan_in));
        for (group_index, group) in current.chunks(fan_in).enumerate() {
            let output = pass_dir.join(format!("key-run-{group_index:06}.bin"));
            merge_key_run_group(group, &output)?;
            next.push(output);
        }
        current = next;
        pass += 1;
    }
    Ok(current)
}

fn merge_key_run_group(key_runs: &[PathBuf], output: &Path) -> Result<()> {
    anyhow::ensure!(
        !key_runs.is_empty() && key_runs.len() <= LIVE_PUBKEY_RUN_MERGE_FAN_IN,
        "key-run merge group size {} exceeds cursor cap {}",
        key_runs.len(),
        LIVE_PUBKEY_RUN_MERGE_FAN_IN
    );
    let mut cursors = Vec::with_capacity(key_runs.len());
    let mut heap = BinaryHeap::<KeyRunHeapItem>::new();
    for path in key_runs {
        let cursor = PubkeyCountRunCursor::open(path)?;
        if let Some(record) = cursor.current {
            let run_index = cursors.len();
            heap.push(KeyRunHeapItem {
                key: record.key,
                run_index,
            });
        }
        cursors.push(cursor);
    }

    let file = File::create(output).with_context(|| format!("create {}", output.display()))?;
    let mut writer = BufWriter::with_capacity(LIVE_FINALIZER_IO_BUFFER_SIZE, file);
    while let Some(item) = heap.pop() {
        let key = item.key;
        let mut count = take_current_and_advance(&mut cursors, item.run_index, &mut heap)?
            .context("key-run heap pointed at empty cursor")?
            .count;
        while heap.peek().is_some_and(|next| next.key == key) {
            let next = heap.pop().expect("heap peeked Some");
            let record = take_current_and_advance(&mut cursors, next.run_index, &mut heap)?
                .context("key-run heap pointed at empty cursor")?;
            count = count.saturating_add(record.count);
        }
        write_pubkey_count_record(&mut writer, PubkeyCountRecord { key, count })?;
    }
    writer
        .flush()
        .with_context(|| format!("flush {}", output.display()))?;
    Ok(())
}

fn reduce_frequency_runs_to_fan_in(
    frequency_runs: &[PathBuf],
    merge_root: &Path,
    fan_in: usize,
) -> Result<Vec<PathBuf>> {
    validate_live_run_merge_fan_in(fan_in)?;
    if frequency_runs.len() <= fan_in {
        return Ok(frequency_runs.to_vec());
    }
    if merge_root.exists() {
        std::fs::remove_dir_all(merge_root).with_context(|| {
            format!("remove stale frequency merge root {}", merge_root.display())
        })?;
    }
    std::fs::create_dir_all(merge_root)
        .with_context(|| format!("create frequency merge root {}", merge_root.display()))?;

    let mut current = frequency_runs.to_vec();
    let mut pass = 0usize;
    while current.len() > fan_in {
        let pass_dir = merge_root.join(format!("pass-{pass:03}"));
        std::fs::create_dir_all(&pass_dir)
            .with_context(|| format!("create frequency merge pass {}", pass_dir.display()))?;
        let mut next = Vec::with_capacity(current.len().div_ceil(fan_in));
        for (group_index, group) in current.chunks(fan_in).enumerate() {
            let output = pass_dir.join(format!("freq-run-{group_index:06}.bin"));
            merge_frequency_run_group(group, &output)?;
            next.push(output);
        }
        current = next;
        pass += 1;
    }
    Ok(current)
}

fn merge_frequency_run_group(frequency_runs: &[PathBuf], output: &Path) -> Result<()> {
    anyhow::ensure!(
        !frequency_runs.is_empty() && frequency_runs.len() <= LIVE_PUBKEY_RUN_MERGE_FAN_IN,
        "frequency-run merge group size {} exceeds cursor cap {}",
        frequency_runs.len(),
        LIVE_PUBKEY_RUN_MERGE_FAN_IN
    );
    let mut cursors = Vec::with_capacity(frequency_runs.len());
    let mut heap = BinaryHeap::<FrequencyRunHeapItem>::new();
    for path in frequency_runs {
        let cursor = PubkeyCountRunCursor::open(path)?;
        if let Some(record) = cursor.current {
            let run_index = cursors.len();
            heap.push(FrequencyRunHeapItem {
                count: record.count,
                key: record.key,
                run_index,
            });
        }
        cursors.push(cursor);
    }

    let file = File::create(output).with_context(|| format!("create {}", output.display()))?;
    let mut writer = BufWriter::with_capacity(LIVE_FINALIZER_IO_BUFFER_SIZE, file);
    while let Some(item) = heap.pop() {
        write_pubkey_count_record(
            &mut writer,
            PubkeyCountRecord {
                key: item.key,
                count: item.count,
            },
        )?;
        let cursor = cursors
            .get_mut(item.run_index)
            .ok_or_else(|| anyhow!("invalid frequency-run cursor index {}", item.run_index))?;
        cursor.advance()?;
        if let Some(next) = cursor.current {
            heap.push(FrequencyRunHeapItem {
                count: next.count,
                key: next.key,
                run_index: item.run_index,
            });
        }
    }
    writer
        .flush()
        .with_context(|| format!("flush {}", output.display()))?;
    Ok(())
}

struct TouchMergeReport {
    frequency_runs: Vec<PathBuf>,
    missing_builtins: Vec<[u8; 32]>,
    unique_keys: u64,
}

fn merge_key_runs_to_frequency_runs(
    key_runs: &[PathBuf],
    freq_run_dir: &Path,
) -> Result<TouchMergeReport> {
    merge_key_runs_to_frequency_runs_with_chunk_records(
        key_runs,
        freq_run_dir,
        PUBKEY_COUNT_SORT_CHUNK_RECORDS,
    )
}

fn merge_key_runs_to_frequency_runs_with_chunk_records(
    key_runs: &[PathBuf],
    freq_run_dir: &Path,
    frequency_chunk_records: usize,
) -> Result<TouchMergeReport> {
    anyhow::ensure!(
        !key_runs.is_empty() && key_runs.len() <= LIVE_PUBKEY_RUN_MERGE_FAN_IN,
        "key-to-frequency merge input count {} exceeds cursor cap {}",
        key_runs.len(),
        LIVE_PUBKEY_RUN_MERGE_FAN_IN
    );
    anyhow::ensure!(
        frequency_chunk_records > 0,
        "frequency chunk record count must be positive"
    );
    let mut cursors = Vec::with_capacity(key_runs.len());
    let mut heap = BinaryHeap::<KeyRunHeapItem>::new();
    for path in key_runs {
        let cursor = PubkeyCountRunCursor::open(path)?;
        if let Some(record) = cursor.current {
            let run_index = cursors.len();
            heap.push(KeyRunHeapItem {
                key: record.key,
                run_index,
            });
        }
        cursors.push(cursor);
    }

    let builtin_keys = live_builtin_program_keys();
    let mut builtin_seen = vec![false; builtin_keys.len()];
    let mut frequency_chunk = Vec::<PubkeyCountRecord>::with_capacity(frequency_chunk_records);
    let mut frequency_runs = Vec::new();
    let mut unique_keys = 0u64;

    while let Some(item) = heap.pop() {
        let key = item.key;
        let mut count = take_current_and_advance(&mut cursors, item.run_index, &mut heap)?
            .context("key-run heap pointed at empty cursor")?
            .count;

        while heap.peek().is_some_and(|next| next.key == key) {
            let next = heap.pop().expect("heap peeked Some");
            let record = take_current_and_advance(&mut cursors, next.run_index, &mut heap)?
                .context("key-run heap pointed at empty cursor")?;
            count = count.saturating_add(record.count);
        }

        for (index, builtin) in builtin_keys.iter().enumerate() {
            if key == *builtin {
                builtin_seen[index] = true;
            }
        }
        frequency_chunk.push(PubkeyCountRecord { key, count });
        unique_keys += 1;
        if frequency_chunk.len() >= frequency_chunk_records {
            spill_frequency_run(freq_run_dir, &mut frequency_runs, &mut frequency_chunk)?;
        }
    }
    if !frequency_chunk.is_empty() {
        spill_frequency_run(freq_run_dir, &mut frequency_runs, &mut frequency_chunk)?;
    }

    let missing_builtins = builtin_keys
        .iter()
        .enumerate()
        .filter_map(|(index, key)| (!builtin_seen[index]).then_some(*key))
        .collect::<Vec<_>>();

    Ok(TouchMergeReport {
        frequency_runs,
        missing_builtins,
        unique_keys,
    })
}

fn take_current_and_advance(
    cursors: &mut [PubkeyCountRunCursor],
    run_index: usize,
    heap: &mut BinaryHeap<KeyRunHeapItem>,
) -> Result<Option<PubkeyCountRecord>> {
    let cursor = cursors
        .get_mut(run_index)
        .ok_or_else(|| anyhow!("invalid key-run cursor index {run_index}"))?;
    let record = cursor.current.take();
    cursor.advance()?;
    if let Some(next) = cursor.current {
        heap.push(KeyRunHeapItem {
            key: next.key,
            run_index,
        });
    }
    Ok(record)
}

fn spill_frequency_run(
    freq_run_dir: &Path,
    frequency_runs: &mut Vec<PathBuf>,
    chunk: &mut Vec<PubkeyCountRecord>,
) -> Result<()> {
    chunk.sort_unstable_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.key.cmp(&right.key))
    });
    let path = freq_run_dir.join(format!("freq-run-{:05}.bin", frequency_runs.len()));
    let file = File::create(&path).with_context(|| format!("create {}", path.display()))?;
    let mut writer = BufWriter::with_capacity(LIVE_FINALIZER_IO_BUFFER_SIZE, file);
    for record in chunk.drain(..) {
        write_pubkey_count_record(&mut writer, record)?;
    }
    writer
        .flush()
        .with_context(|| format!("flush {}", path.display()))?;
    frequency_runs.push(path);
    Ok(())
}

fn write_registry_from_frequency_runs(
    frequency_runs: &[PathBuf],
    registry_path: &Path,
    registry_counts_path: &Path,
    missing_builtins: &[[u8; 32]],
) -> Result<()> {
    anyhow::ensure!(
        !frequency_runs.is_empty() && frequency_runs.len() <= LIVE_PUBKEY_RUN_MERGE_FAN_IN,
        "final frequency-run input count {} exceeds cursor cap {}",
        frequency_runs.len(),
        LIVE_PUBKEY_RUN_MERGE_FAN_IN
    );
    let mut cursors = Vec::with_capacity(frequency_runs.len());
    let mut heap = BinaryHeap::<FrequencyRunHeapItem>::new();
    for path in frequency_runs {
        let cursor = PubkeyCountRunCursor::open(path)?;
        if let Some(record) = cursor.current {
            let run_index = cursors.len();
            heap.push(FrequencyRunHeapItem {
                count: record.count,
                key: record.key,
                run_index,
            });
        }
        cursors.push(cursor);
    }

    let registry_file = File::create(registry_path)
        .with_context(|| format!("create {}", registry_path.display()))?;
    let mut registry_writer =
        BufWriter::with_capacity(LIVE_FINALIZER_IO_BUFFER_SIZE, registry_file);
    let counts_file = File::create(registry_counts_path)
        .with_context(|| format!("create {}", registry_counts_path.display()))?;
    let mut counts_writer = BufWriter::with_capacity(LIVE_FINALIZER_IO_BUFFER_SIZE, counts_file);

    for builtin in missing_builtins {
        registry_writer.write_all(builtin)?;
        blockzilla_primitives::framed::write_u32_varint(&mut counts_writer, 0)?;
    }

    while let Some(item) = heap.pop() {
        registry_writer.write_all(&item.key)?;
        blockzilla_primitives::framed::write_u32_varint(&mut counts_writer, item.count)?;
        let cursor = cursors
            .get_mut(item.run_index)
            .ok_or_else(|| anyhow!("invalid frequency-run cursor index {}", item.run_index))?;
        cursor.advance()?;
        if let Some(next) = cursor.current {
            heap.push(FrequencyRunHeapItem {
                count: next.count,
                key: next.key,
                run_index: item.run_index,
            });
        }
    }

    registry_writer
        .flush()
        .with_context(|| format!("flush {}", registry_path.display()))?;
    counts_writer
        .flush()
        .with_context(|| format!("flush {}", registry_counts_path.display()))?;
    Ok(())
}

struct PubkeyCountRunCursor {
    reader: BufReader<File>,
    current: Option<PubkeyCountRecord>,
}

impl PubkeyCountRunCursor {
    fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
        let mut cursor = Self {
            reader: BufReader::with_capacity(LIVE_PUBKEY_RUN_READER_BUFFER_SIZE, file),
            current: None,
        };
        cursor.advance()?;
        Ok(cursor)
    }

    fn advance(&mut self) -> Result<()> {
        self.current = read_pubkey_count_record(&mut self.reader)?;
        Ok(())
    }
}

fn write_pubkey_count_record(writer: &mut impl Write, record: PubkeyCountRecord) -> Result<()> {
    writer.write_all(&record.key)?;
    writer.write_all(&record.count.to_le_bytes())?;
    Ok(())
}

#[derive(Eq, PartialEq)]
struct KeyRunHeapItem {
    key: [u8; 32],
    run_index: usize,
}

impl Ord for KeyRunHeapItem {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .key
            .cmp(&self.key)
            .then_with(|| other.run_index.cmp(&self.run_index))
    }
}

impl PartialOrd for KeyRunHeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Eq, PartialEq)]
struct FrequencyRunHeapItem {
    count: u32,
    key: [u8; 32],
    run_index: usize,
}

impl Ord for FrequencyRunHeapItem {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.count
            .cmp(&other.count)
            .then_with(|| other.key.cmp(&self.key))
            .then_with(|| other.run_index.cmp(&self.run_index))
    }
}

impl PartialOrd for FrequencyRunHeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

fn live_builtin_program_keys() -> &'static [[u8; 32]] {
    const BUILTIN_PROGRAM_KEYS: [[u8; 32]; 1] =
        [solana_pubkey::pubkey!("ComputeBudget111111111111111111111111111111").to_bytes()];
    &BUILTIN_PROGRAM_KEYS
}

fn write_live_registry_counts<I>(path: &Path, counts: I) -> Result<()>
where
    I: IntoIterator<Item = u32>,
{
    let file = File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut writer = BufWriter::with_capacity(LIVE_FINALIZER_IO_BUFFER_SIZE, file);
    for count in counts {
        blockzilla_primitives::framed::write_u32_varint(&mut writer, count)?;
    }
    writer
        .flush()
        .with_context(|| format!("flush {}", path.display()))?;
    Ok(())
}

fn read_live_no_registry_block<R: Read>(
    reader: &mut WincodeLeb128FramedReader<R>,
) -> Result<Option<(usize, WincodeArchiveV2NoRegistryBlock)>> {
    reader.read_bytes_with_limit(LIVE_FINALIZER_MAX_FRAME_SIZE, |bytes| {
        match wincode::config::deserialize::<WincodeArchiveV2NoRegistryBlock, _>(
            bytes,
            wincode_leb128_config(),
        ) {
            Ok(block) => Ok(block),
            Err(current_err) => {
                let legacy: LiveNoRegistryBlockLegacy = wincode::config::deserialize(
                    bytes,
                    wincode_leb128_config(),
                )
                .with_context(|| {
                    format!("decode live no-registry block failed; current error: {current_err}")
                })?;
                Ok(legacy.into_current())
            }
        }
    })
}

fn read_live_no_registry_block_signature_counts<R: Read>(
    reader: &mut WincodeLeb128FramedReader<R>,
) -> Result<Option<(usize, LiveNoRegistryBlockSignatureCounts)>> {
    reader.read_bytes_with_limit(LIVE_FINALIZER_MAX_FRAME_SIZE, |bytes| {
        match wincode::config::deserialize::<LiveNoRegistryBlockSignatureCounts, _>(
            bytes,
            wincode_leb128_config(),
        ) {
            Ok(block) => Ok(block),
            Err(current_err) => {
                let legacy: LiveNoRegistryBlockLegacy = wincode::config::deserialize(
                    bytes,
                    wincode_leb128_config(),
                )
                .with_context(|| {
                    format!(
                        "decode live no-registry signature-count block failed; current error: {current_err}"
                    )
                })?;
                live_signature_counts_from_full_block(legacy.into_current())
            }
        }
    })
}

enum LiveFinalizerBlock {
    Full(WincodeArchiveV2NoRegistryBlock),
    SignatureCounts(LiveNoRegistryBlockSignatureCounts),
}

impl LiveFinalizerBlock {
    fn slot(&self) -> u64 {
        match self {
            Self::Full(block) => block.header.compact.slot,
            Self::SignatureCounts(block) => block.header.compact.slot,
        }
    }

    fn blockhash_id(&self) -> u32 {
        match self {
            Self::Full(block) => block.header.compact.blockhash,
            Self::SignatureCounts(block) => block.header.compact.blockhash,
        }
    }
}

#[derive(Debug, SchemaRead)]
struct LiveNoRegistryBlockSignatureCounts {
    header: WincodeArchiveV2NoRegistryBlockHeader,
    txs: Vec<LiveNoRegistryTransactionSignatureCounts>,
}

#[derive(Debug, SchemaRead)]
struct LiveNoRegistryTransactionSignatureCounts {
    tx_index: u32,
    tx: WincodeArchiveV2Payload<LiveNoRegistryTxSignatureCounts>,
    metadata: Option<WincodeArchiveV2Payload<WincodeArchiveV2NoRegistryMeta>>,
}

#[derive(Debug, SchemaRead)]
struct LiveNoRegistryTxSignatureCounts {
    signatures: LiveSignatureCount,
    message: WincodeArchiveV2NoRegistryMessage,
}

#[derive(Debug, Clone, Copy)]
struct LiveSignatureCount {
    count: u8,
}

unsafe impl<'de, C: Config> SchemaRead<'de, C> for LiveSignatureCount {
    type Dst = Self;

    fn read(mut reader: impl Reader<'de>, dst: &mut MaybeUninit<Self::Dst>) -> ReadResult<()> {
        let len = <C::LengthEncoding as SeqLen<C>>::read(reader.by_ref())?;
        let count = u8::try_from(len)
            .map_err(|_| wincode::ReadError::InvalidValue("signature count exceeds u8::MAX"))?;
        for _ in 0..len {
            let signature_len = <C::LengthEncoding as SeqLen<C>>::read(reader.by_ref())?;
            reader.take_scoped(signature_len)?;
        }
        dst.write(Self { count });
        Ok(())
    }
}

fn live_signature_counts_from_full_block(
    block: WincodeArchiveV2NoRegistryBlock,
) -> Result<LiveNoRegistryBlockSignatureCounts> {
    Ok(LiveNoRegistryBlockSignatureCounts {
        header: block.header,
        txs: block
            .txs
            .into_iter()
            .map(live_signature_count_transaction_from_full)
            .collect::<Result<Vec<_>>>()?,
    })
}

fn live_signature_count_transaction_from_full(
    transaction: WincodeArchiveV2NoRegistryTransaction,
) -> Result<LiveNoRegistryTransactionSignatureCounts> {
    Ok(LiveNoRegistryTransactionSignatureCounts {
        tx_index: transaction.tx_index,
        tx: map_live_signature_count_payload(transaction.tx)?,
        metadata: transaction.metadata,
    })
}

fn map_live_signature_count_payload(
    payload: WincodeArchiveV2Payload<WincodeArchiveV2NoRegistryTx>,
) -> Result<WincodeArchiveV2Payload<LiveNoRegistryTxSignatureCounts>> {
    Ok(match payload {
        WincodeArchiveV2Payload::Decoded { source_len, value } => {
            WincodeArchiveV2Payload::Decoded {
                source_len,
                value: LiveNoRegistryTxSignatureCounts {
                    signatures: LiveSignatureCount {
                        count: u8::try_from(value.signatures.len())
                            .context("signature count exceeds u8::MAX")?,
                    },
                    message: value.message,
                },
            }
        }
        WincodeArchiveV2Payload::Raw { bytes, error } => {
            WincodeArchiveV2Payload::Raw { bytes, error }
        }
    })
}

#[derive(Debug, SchemaRead)]
struct LiveNoRegistryBlockLegacy {
    header: WincodeArchiveV2NoRegistryBlockHeader,
    txs: Vec<LiveNoRegistryTransactionLegacy>,
}

#[derive(Debug, SchemaRead)]
struct LiveNoRegistryTransactionLegacy {
    tx_index: u32,
    tx: WincodeArchiveV2Payload<WincodeArchiveV2NoRegistryTx>,
    metadata: Option<WincodeArchiveV2Payload<LiveNoRegistryMetaLegacy>>,
}

#[derive(Debug, SchemaRead)]
struct LiveNoRegistryMetaLegacy {
    err: Option<CompactTransactionError>,
    fee: u64,
    pre_balances: Vec<u64>,
    post_balances: Vec<u64>,
    inner_instructions: Option<Vec<CompactInnerInstructions>>,
    logs: Option<Vec<String>>,
    pre_token_balances: Vec<WincodeArchiveV2NoRegistryTokenBalance>,
    post_token_balances: Vec<WincodeArchiveV2NoRegistryTokenBalance>,
    rewards: Vec<WincodeArchiveV2NoRegistryReward>,
    loaded_writable_addresses: Vec<[u8; 32]>,
    loaded_readonly_addresses: Vec<[u8; 32]>,
    return_data: Option<WincodeArchiveV2NoRegistryReturnData>,
    compute_units_consumed: Option<u64>,
    cost_units: Option<u64>,
}

impl LiveNoRegistryBlockLegacy {
    fn into_current(self) -> WincodeArchiveV2NoRegistryBlock {
        WincodeArchiveV2NoRegistryBlock {
            header: self.header,
            txs: self
                .txs
                .into_iter()
                .map(LiveNoRegistryTransactionLegacy::into_current)
                .collect(),
        }
    }
}

impl LiveNoRegistryTransactionLegacy {
    fn into_current(self) -> WincodeArchiveV2NoRegistryTransaction {
        WincodeArchiveV2NoRegistryTransaction {
            tx_index: self.tx_index,
            tx: self.tx,
            metadata: self.metadata.map(|metadata| match metadata {
                WincodeArchiveV2Payload::Decoded { source_len, value } => {
                    WincodeArchiveV2Payload::Decoded {
                        source_len,
                        value: value.into_current(),
                    }
                }
                WincodeArchiveV2Payload::Raw { bytes, error } => {
                    WincodeArchiveV2Payload::Raw { bytes, error }
                }
            }),
        }
    }
}

impl LiveNoRegistryMetaLegacy {
    fn into_current(self) -> WincodeArchiveV2NoRegistryMeta {
        WincodeArchiveV2NoRegistryMeta {
            err: self.err,
            fee: self.fee,
            pre_balances: self.pre_balances,
            post_balances: self.post_balances,
            inner_instructions: self.inner_instructions,
            logs: self.logs.map(WincodeArchiveV2NoRegistryLogs::Raw),
            pre_token_balances: self.pre_token_balances,
            post_token_balances: self.post_token_balances,
            rewards: self.rewards,
            loaded_writable_addresses: self.loaded_writable_addresses,
            loaded_readonly_addresses: self.loaded_readonly_addresses,
            return_data: self.return_data,
            compute_units_consumed: self.compute_units_consumed,
            cost_units: self.cost_units,
        }
    }
}

fn trim_hot_memory(
    _next_block_id: u32,
    block_bytes: &mut Vec<u8>,
    compressed_buf: &mut Vec<u8>,
    access_bytes: &mut Vec<u8>,
    access_signature_bytes: Option<&mut Vec<u8>>,
) {
    let mut released = release_hot_reusable_buffer(block_bytes);
    released |= release_hot_reusable_buffer(compressed_buf);
    released |= release_hot_reusable_buffer(access_bytes);
    if let Some(access_signature_bytes) = access_signature_bytes {
        released |= release_hot_reusable_buffer(access_signature_bytes);
    }

    if released {
        trim_process_heap();
    }
}

fn release_hot_reusable_buffer(buf: &mut Vec<u8>) -> bool {
    buf.clear();
    if buf.capacity() > HOT_REUSABLE_BUFFER_RETAIN_LIMIT {
        *buf = Vec::with_capacity(HOT_REUSABLE_BUFFER_RETAIN_LIMIT);
        true
    } else {
        false
    }
}

#[cfg(all(unix, target_env = "gnu"))]
fn trim_process_heap() {
    unsafe {
        let _ = libc::malloc_trim(0);
    }
}

#[cfg(not(all(unix, target_env = "gnu")))]
fn trim_process_heap() {}

fn link_or_copy_registry_sidecar(source: &Path, target: &Path) -> Result<()> {
    if source == target {
        return Ok(());
    }
    if crate::file_nonempty(target) {
        std::fs::remove_file(target).with_context(|| format!("remove {}", target.display()))?;
    }
    match std::fs::hard_link(source, target) {
        Ok(()) => Ok(()),
        Err(link_err) => {
            std::fs::copy(source, target)
                .with_context(|| format!("copy {} to {}", source.display(), target.display()))?;
            info!(
                "Copied registry sidecar {} to {} after hard-link failed: {}",
                source.display(),
                target.display(),
                link_err
            );
            Ok(())
        }
    }
}

fn copy_file_prefix(source: &Path, target: &Path, bytes: u64) -> Result<()> {
    if source == target {
        anyhow::ensure!(
            std::fs::metadata(source)
                .with_context(|| format!("stat {}", source.display()))?
                .len()
                == bytes,
            "cannot truncate live sidecar in place: {}",
            source.display()
        );
        return Ok(());
    }
    if target.exists() {
        std::fs::remove_file(target).with_context(|| format!("remove {}", target.display()))?;
    }
    let source_file = File::open(source).with_context(|| format!("open {}", source.display()))?;
    let target_file =
        File::create(target).with_context(|| format!("create {}", target.display()))?;
    let mut reader =
        BufReader::with_capacity(LIVE_FINALIZER_IO_BUFFER_SIZE, source_file).take(bytes);
    let mut writer = BufWriter::with_capacity(LIVE_FINALIZER_IO_BUFFER_SIZE, target_file);
    let copied = std::io::copy(&mut reader, &mut writer)
        .with_context(|| format!("copy prefix {} to {}", source.display(), target.display()))?;
    anyhow::ensure!(
        copied == bytes,
        "live sidecar {} ended after {} bytes, expected at least {}",
        source.display(),
        copied,
        bytes
    );
    writer
        .flush()
        .with_context(|| format!("flush {}", target.display()))?;
    Ok(())
}

fn load_or_build_registry_key_index(
    registry_path: &Path,
    registry_index_path: &Path,
    resume: bool,
) -> Result<KeyIndex> {
    let expected_keys = registry_key_count(registry_path)?;
    if resume && crate::file_nonempty(registry_index_path) {
        let started = Instant::now();
        match KeyIndex::load(registry_index_path) {
            Ok(index) if index.len() == expected_keys => {
                info!(
                    "Loaded Archive V2 registry MPHF index in {:.2}s: keys={} path={}",
                    started.elapsed().as_secs_f64(),
                    index.len(),
                    registry_index_path.display()
                );
                return Ok(index);
            }
            Ok(index) => {
                warn!(
                    "Ignoring stale Archive V2 registry MPHF index: path={} keys={} expected={}",
                    registry_index_path.display(),
                    index.len(),
                    expected_keys
                );
            }
            Err(err) => {
                warn!(
                    "Ignoring unreadable Archive V2 registry MPHF index: path={} error={:#}",
                    registry_index_path.display(),
                    err
                );
            }
        }
    }

    let started = Instant::now();
    info!(
        "Building missing Archive V2 registry MPHF index in-process: {}",
        registry_index_path.display()
    );
    let registry = MappedRegistryKeys::open(registry_path)?;
    let index = KeyIndex::build_from_slice_low_memory(registry.keys());
    write_registry_key_index_atomic_checked(&index, registry_index_path, || {
        registry.ensure_unchanged()
    })?;
    info!(
        "Built Archive V2 registry MPHF index in {:.2}s: keys={} path={}",
        started.elapsed().as_secs_f64(),
        index.len(),
        registry_index_path.display()
    );
    Ok(index)
}

fn registry_key_count(registry_path: &Path) -> Result<usize> {
    let len = std::fs::metadata(registry_path)
        .with_context(|| format!("stat registry {}", registry_path.display()))?
        .len();
    anyhow::ensure!(
        len % 32 == 0,
        "invalid registry size {} (not multiple of 32): {}",
        len,
        registry_path.display()
    );
    let keys = len / 32;
    anyhow::ensure!(
        keys <= u64::from(u32::MAX),
        "registry key count {keys} exceeds compact ID space"
    );
    usize::try_from(keys).context("registry key count exceeds usize")
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RegistryFileStamp {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl RegistryFileStamp {
    fn read(file: &File) -> Result<Self> {
        let metadata = file.metadata().context("stat open registry")?;
        Ok(Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
        })
    }
}

struct MappedRegistryKeys {
    path: PathBuf,
    file: File,
    mmap: Option<Mmap>,
    stamp: RegistryFileStamp,
}

impl MappedRegistryKeys {
    fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("open registry for mmap {}", path.display()))?;
        let stamp = RegistryFileStamp::read(&file)
            .with_context(|| format!("stat registry before mmap {}", path.display()))?;
        anyhow::ensure!(
            stamp.len % 32 == 0,
            "invalid registry size {} (not multiple of 32): {}",
            stamp.len,
            path.display()
        );
        let key_count = stamp.len / 32;
        anyhow::ensure!(
            key_count <= u64::from(u32::MAX),
            "registry key count {key_count} exceeds compact ID space"
        );
        usize::try_from(key_count).context("registry key count exceeds usize")?;

        let mmap = if stamp.len == 0 {
            None
        } else {
            let len = usize::try_from(stamp.len).context("registry mmap length exceeds usize")?;
            // SAFETY: the mapping is read-only, `file` stays open for the life of
            // the mapping, and the pipeline treats a scan-complete registry as
            // immutable under its exclusive finalizer lock. We verify the open
            // file and its path identity again before publishing the index.
            Some(
                unsafe { MmapOptions::new().len(len).map(&file) }
                    .with_context(|| format!("mmap registry {}", path.display()))?,
            )
        };
        let mapped = Self {
            path: path.to_path_buf(),
            file,
            mmap,
            stamp,
        };
        mapped.ensure_unchanged()?;
        Ok(mapped)
    }

    fn keys(&self) -> &[[u8; 32]] {
        let bytes = self.mmap.as_deref().unwrap_or(&[]);
        debug_assert_eq!(bytes.len() % 32, 0);
        // SAFETY: `[u8; 32]` has alignment 1, the byte length was validated as
        // a multiple of 32, and the returned slice cannot outlive `self.mmap`.
        unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast::<[u8; 32]>(), bytes.len() / 32) }
    }

    fn ensure_unchanged(&self) -> Result<()> {
        let open_stamp = RegistryFileStamp::read(&self.file)
            .with_context(|| format!("restat open registry {}", self.path.display()))?;
        anyhow::ensure!(
            open_stamp == self.stamp,
            "registry changed while building MPHF: {}",
            self.path.display()
        );
        let current_file = File::open(&self.path)
            .with_context(|| format!("reopen registry after MPHF build {}", self.path.display()))?;
        let current_stamp = RegistryFileStamp::read(&current_file)
            .with_context(|| format!("restat registry path {}", self.path.display()))?;
        anyhow::ensure!(
            current_stamp == self.stamp,
            "registry path was replaced while building MPHF: {}",
            self.path.display()
        );
        Ok(())
    }
}

fn write_registry_key_index_atomic_checked<F>(
    index: &KeyIndex,
    path: &Path,
    validate_before_publish: F,
) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    let tmp_path = path.with_extension("mphf.tmp");
    if crate::file_nonempty(&tmp_path) {
        std::fs::remove_file(&tmp_path)
            .with_context(|| format!("remove {}", tmp_path.display()))?;
    }
    index.write(&tmp_path)?;
    File::open(&tmp_path)
        .with_context(|| format!("open {} for sync", tmp_path.display()))?
        .sync_all()
        .with_context(|| format!("sync {}", tmp_path.display()))?;
    validate_before_publish()?;
    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("rename {} to {}", tmp_path.display(), path.display()))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .with_context(|| format!("open {} for sync", parent.display()))?
        .sync_all()
        .with_context(|| format!("sync {}", parent.display()))?;
    Ok(())
}

fn write_hot_meta<W: Write>(
    writer: &mut WincodeLeb128FramedWriter<W>,
    record: &ArchiveV2HotMetaRecord,
) -> Result<()> {
    let bytes = wincode::config::serialize(record, wincode_leb128_config())?;
    writer.write_bytes(&bytes)
}

#[derive(Default)]
struct VoteHashRegistryBuilder {
    rows: Vec<VoteHashRegistryRow>,
    compact_vote_ix: u64,
    bank_hash_refs: u64,
    bank_hash_raw: u64,
    bank_hash_conflict_raw: u64,
    block_id_refs: u64,
    block_id_raw: u64,
    block_id_zero: u64,
    block_id_conflict_raw: u64,
}

#[derive(Clone, Copy, Default)]
struct VoteHashRegistryRow {
    bank_hash: Option<[u8; 32]>,
    block_id_hash: Option<[u8; 32]>,
}

impl VoteHashRegistryBuilder {
    fn ensure_block(&mut self, block_id: u32) {
        let needed = block_id as usize + 1;
        if self.rows.len() < needed {
            self.rows.resize(needed, VoteHashRegistryRow::default());
        }
    }

    fn ref_bank_hash(
        &mut self,
        slot: Option<u64>,
        hash: [u8; 32],
        slot_to_block_id: &GxHashMap<u64, u32>,
    ) -> Result<ArchiveV2VoteHashRef> {
        if hash == [0u8; 32] {
            return Ok(ArchiveV2VoteHashRef::Zero);
        }
        let Some(slot) = slot else {
            self.bank_hash_raw += 1;
            return Ok(ArchiveV2VoteHashRef::Raw(hash));
        };
        let Some(&block_id) = slot_to_block_id.get(&slot) else {
            self.bank_hash_raw += 1;
            return Ok(ArchiveV2VoteHashRef::Raw(hash));
        };
        self.ensure_block(block_id);
        let row = &mut self.rows[block_id as usize];
        if let Some(existing) = row.bank_hash {
            if existing != hash {
                self.bank_hash_raw += 1;
                self.bank_hash_conflict_raw += 1;
                return Ok(ArchiveV2VoteHashRef::Raw(hash));
            }
        } else {
            row.bank_hash = Some(hash);
        }
        self.bank_hash_refs += 1;
        Ok(ArchiveV2VoteHashRef::Block(block_id))
    }

    fn ref_block_id_hash(
        &mut self,
        slot: Option<u64>,
        hash: [u8; 32],
        slot_to_block_id: &GxHashMap<u64, u32>,
    ) -> Result<ArchiveV2VoteHashRef> {
        if hash == [0u8; 32] {
            self.block_id_zero += 1;
            return Ok(ArchiveV2VoteHashRef::Zero);
        }
        let Some(slot) = slot else {
            self.block_id_raw += 1;
            return Ok(ArchiveV2VoteHashRef::Raw(hash));
        };
        let Some(&block_id) = slot_to_block_id.get(&slot) else {
            self.block_id_raw += 1;
            return Ok(ArchiveV2VoteHashRef::Raw(hash));
        };
        self.ensure_block(block_id);
        let row = &mut self.rows[block_id as usize];
        if let Some(existing) = row.block_id_hash {
            if existing != hash {
                self.block_id_raw += 1;
                self.block_id_conflict_raw += 1;
                return Ok(ArchiveV2VoteHashRef::Raw(hash));
            }
        } else {
            row.block_id_hash = Some(hash);
        }
        self.block_id_refs += 1;
        Ok(ArchiveV2VoteHashRef::Block(block_id))
    }

    fn ref_aux_hash(&self, hash: [u8; 32]) -> ArchiveV2VoteHashRef {
        if hash == [0u8; 32] {
            ArchiveV2VoteHashRef::Zero
        } else {
            ArchiveV2VoteHashRef::Raw(hash)
        }
    }

    fn write(&self, path: &Path) -> Result<()> {
        let file = File::create(path).with_context(|| format!("create {}", path.display()))?;
        let mut writer = BufWriter::with_capacity(LIVE_FINALIZER_IO_BUFFER_SIZE, file);
        for row in &self.rows {
            let flags =
                u8::from(row.bank_hash.is_some()) | (u8::from(row.block_id_hash.is_some()) << 1);
            writer.write_all(&[flags])?;
            writer.write_all(&row.bank_hash.unwrap_or([0u8; 32]))?;
            writer.write_all(&row.block_id_hash.unwrap_or([0u8; 32]))?;
        }
        writer
            .flush()
            .with_context(|| format!("flush {}", path.display()))?;
        Ok(())
    }
}

#[derive(Default)]
struct HotBlockBuffers {
    tx_rows: Vec<ArchiveV2HotTxRow>,
    message_bytes: Vec<u8>,
    metadata_bytes: Vec<u8>,
    hot_instructions: Vec<ArchiveV2HotInstruction>,
}

impl HotBlockBuffers {
    fn take(&mut self) -> (Vec<ArchiveV2HotTxRow>, Vec<u8>, Vec<u8>) {
        (
            std::mem::take(&mut self.tx_rows),
            std::mem::take(&mut self.message_bytes),
            std::mem::take(&mut self.metadata_bytes),
        )
    }

    fn recycle(&mut self, mut block: ArchiveV2HotBlockBlob) {
        block.tx_rows.clear();
        block.message_bytes.clear();
        block.metadata_bytes.clear();
        self.tx_rows = block.tx_rows;
        self.message_bytes = block.message_bytes;
        self.metadata_bytes = block.metadata_bytes;
    }

    fn recycle_message_instructions(&mut self, message: ArchiveV2HotMessagePayload) {
        debug_assert!(self.hot_instructions.is_empty());
        self.hot_instructions = match message {
            ArchiveV2HotMessagePayload::Legacy(message) => message.instructions,
            ArchiveV2HotMessagePayload::V0(message) => message.instructions,
            ArchiveV2HotMessagePayload::V1(message) => message.instructions,
        };
        self.hot_instructions.clear();
    }

    fn trim(&mut self) {
        trim_hot_reusable_buffer(&mut self.message_bytes);
        trim_hot_reusable_buffer(&mut self.metadata_bytes);
        trim_hot_reusable_vec(&mut self.tx_rows);
        trim_hot_reusable_vec(&mut self.hot_instructions);
    }
}

#[inline]
fn reserve_total_capacity<T>(values: &mut Vec<T>, desired_len: usize) {
    values.reserve(desired_len.saturating_sub(values.len()));
}

fn hot_block_from_live_no_registry_block(
    block: WincodeArchiveV2NoRegistryBlock,
    key_index: &KeyIndex,
    rolling_blockhashes: &RollingBlockhashIndex,
    block_id: u32,
    nonce_recent_blockhashes: &mut u64,
    known_program_ids: &KnownProgramIds,
    slot_to_block_id: &GxHashMap<u64, u32>,
    vote_hashes: &mut VoteHashRegistryBuilder,
    mut signatures_writer: Option<&mut dyn Write>,
    mut block_signature_bytes: Option<&mut Vec<u8>>,
    buffers: &mut HotBlockBuffers,
    timings: &mut ArchiveV2Timings,
) -> Result<(ArchiveV2HotBlockBlob, u32)> {
    let WincodeArchiveV2NoRegistryBlock { header, txs } = block;
    let slot = header.compact.slot;
    let rewards_decode_started = timings.detail_timer();
    let rewards = header
        .rewards
        .as_ref()
        .map(|rewards| {
            optimize_no_registry_rewards(rewards, key_index).and_then(hot_rewards_from_archive)
        })
        .transpose()?;
    timings.rewards_decode_compact += rewards_decode_started.elapsed();

    let mut compact = header.compact;
    compact.blockhash = block_id;
    compact.previous_blockhash = block_id.saturating_sub(1);
    let header = ArchiveV2HotBlockHeader {
        slot: compact.slot,
        parent_slot: compact.parent_slot,
        blockhash_id: compact.blockhash,
        previous_blockhash_id: compact.previous_blockhash,
        block_time: compact.block_time,
        block_height: compact.block_height,
        rewards,
    };

    vote_hashes.ensure_block(block_id);
    let tx_capacity = txs.len();
    let (mut tx_rows, mut message_bytes, mut metadata_bytes) = buffers.take();
    tx_rows.clear();
    message_bytes.clear();
    metadata_bytes.clear();
    reserve_total_capacity(&mut tx_rows, tx_capacity);

    let mut block_signature_count = 0u32;
    for (tx_position, transaction) in txs.into_iter().enumerate() {
        let WincodeArchiveV2NoRegistryTransaction {
            tx_index,
            tx,
            metadata,
        } = transaction;
        let tx_decode_started = timings.detail_timer();
        let WincodeArchiveV2Payload::Decoded { value: tx, .. } = tx else {
            bail!("slot {slot} tx#{tx_position} raw transaction payload");
        };
        let tx = optimize_no_registry_tx(
            slot,
            tx_position,
            tx,
            key_index,
            rolling_blockhashes,
            nonce_recent_blockhashes,
        )?;
        timings.tx_decode_compact += tx_decode_started.elapsed();

        let metadata_decode_started = timings.detail_timer();
        let metadata = metadata
            .map(|payload| -> Result<CompactMetaV1> {
                match payload {
                    WincodeArchiveV2Payload::Decoded { value, .. } => optimize_no_registry_meta(
                        slot,
                        tx_position,
                        value,
                        key_index,
                        Some(timings),
                    ),
                    WincodeArchiveV2Payload::Raw { error, .. } => {
                        bail!("slot {slot} tx#{tx_position} raw metadata payload: {error}");
                    }
                }
            })
            .transpose()?;
        timings.metadata_decode_compact += metadata_decode_started.elapsed();

        let message_offset = u32::try_from(message_bytes.len())
            .context("hot message byte region exceeds u32::MAX")?;
        let message_build_started = timings.detail_timer();
        let (message, mut flags) =
            hot_message_from_owned(tx.message, known_program_ids, slot_to_block_id, vote_hashes)?;
        timings.hot_message_build += message_build_started.elapsed();
        let message_encode_started = timings.detail_timer();
        let before_message_len = message_bytes.len();
        wincode::config::serialize_into(&mut message_bytes, &message, wincode_leb128_config())?;
        let message_len = u32::try_from(message_bytes.len() - before_message_len)
            .context("hot message payload exceeds u32::MAX")?;
        timings.hot_message_encode += message_encode_started.elapsed();

        let signature_count =
            u8::try_from(tx.signatures.len()).context("signature count exceeds u8::MAX")?;
        let signature_write_started = timings.detail_timer();
        if signatures_writer.is_some() || block_signature_bytes.is_some() {
            for (signature_index, signature) in tx.signatures.iter().enumerate() {
                anyhow::ensure!(
                    signature.len() == 64,
                    "tx_index {} signature#{} is {} bytes, expected 64",
                    tx_index,
                    signature_index,
                    signature.len()
                );
                if let Some(writer) = signatures_writer.as_deref_mut() {
                    writer.write_all(signature)?;
                }
                if let Some(bytes) = block_signature_bytes.as_deref_mut() {
                    bytes.extend_from_slice(signature);
                }
            }
        }
        timings.hot_signature_write += signature_write_started.elapsed();
        block_signature_count = block_signature_count
            .checked_add(u32::from(signature_count))
            .context("block signature count overflow")?;

        let metadata_offset = u32::try_from(metadata_bytes.len())
            .context("hot metadata byte region exceeds u32::MAX")?;
        let mut metadata_len = 0u32;
        if let Some(metadata) = metadata {
            flags |= ARCHIVE_V2_TX_FLAG_HAS_METADATA;
            flags |= hot_metadata_flags(&metadata);
            let metadata_encode_started = timings.detail_timer();
            let before_metadata_len = metadata_bytes.len();
            wincode::config::serialize_into(
                &mut metadata_bytes,
                &metadata,
                wincode_leb128_config(),
            )?;
            metadata_len = u32::try_from(metadata_bytes.len() - before_metadata_len)
                .context("hot metadata payload exceeds u32::MAX")?;
            timings.hot_metadata_encode += metadata_encode_started.elapsed();
        }

        tx_rows.push(ArchiveV2HotTxRow {
            tx_index,
            flags,
            message_offset,
            message_len,
            metadata_offset,
            metadata_len,
            signature_count,
            reserved: [0; 3],
        });
    }

    let tx_count = u32::try_from(tx_rows.len()).context("hot block tx count exceeds u32::MAX")?;
    Ok((
        ArchiveV2HotBlockBlob {
            header,
            tx_count,
            tx_rows,
            message_bytes,
            metadata_bytes,
        },
        block_signature_count,
    ))
}

fn hot_block_from_live_finalizer_block(
    block: LiveFinalizerBlock,
    key_index: &KeyIndex,
    rolling_blockhashes: &RollingBlockhashIndex,
    block_id: u32,
    nonce_recent_blockhashes: &mut u64,
    known_program_ids: &KnownProgramIds,
    slot_to_block_id: &GxHashMap<u64, u32>,
    vote_hashes: &mut VoteHashRegistryBuilder,
    signatures_writer: Option<&mut dyn Write>,
    block_signature_bytes: Option<&mut Vec<u8>>,
    buffers: &mut HotBlockBuffers,
    timings: &mut ArchiveV2Timings,
) -> Result<(ArchiveV2HotBlockBlob, u32)> {
    match block {
        LiveFinalizerBlock::Full(block) => hot_block_from_live_no_registry_block(
            block,
            key_index,
            rolling_blockhashes,
            block_id,
            nonce_recent_blockhashes,
            known_program_ids,
            slot_to_block_id,
            vote_hashes,
            signatures_writer,
            block_signature_bytes,
            buffers,
            timings,
        ),
        LiveFinalizerBlock::SignatureCounts(block) => {
            anyhow::ensure!(
                signatures_writer.is_none() && block_signature_bytes.is_none(),
                "signature-count live decode cannot rewrite signature sidecars"
            );
            hot_block_from_live_no_registry_block_signature_counts(
                block,
                key_index,
                rolling_blockhashes,
                block_id,
                nonce_recent_blockhashes,
                known_program_ids,
                slot_to_block_id,
                vote_hashes,
                buffers,
                timings,
            )
        }
    }
}

fn hot_block_from_live_no_registry_block_signature_counts(
    block: LiveNoRegistryBlockSignatureCounts,
    key_index: &KeyIndex,
    rolling_blockhashes: &RollingBlockhashIndex,
    block_id: u32,
    nonce_recent_blockhashes: &mut u64,
    known_program_ids: &KnownProgramIds,
    slot_to_block_id: &GxHashMap<u64, u32>,
    vote_hashes: &mut VoteHashRegistryBuilder,
    buffers: &mut HotBlockBuffers,
    timings: &mut ArchiveV2Timings,
) -> Result<(ArchiveV2HotBlockBlob, u32)> {
    let LiveNoRegistryBlockSignatureCounts { header, txs } = block;
    let slot = header.compact.slot;
    let rewards_decode_started = timings.detail_timer();
    let rewards = header
        .rewards
        .as_ref()
        .map(|rewards| {
            optimize_no_registry_rewards(rewards, key_index).and_then(hot_rewards_from_archive)
        })
        .transpose()?;
    timings.rewards_decode_compact += rewards_decode_started.elapsed();

    let mut compact = header.compact;
    compact.blockhash = block_id;
    compact.previous_blockhash = block_id.saturating_sub(1);
    let header = ArchiveV2HotBlockHeader {
        slot: compact.slot,
        parent_slot: compact.parent_slot,
        blockhash_id: compact.blockhash,
        previous_blockhash_id: compact.previous_blockhash,
        block_time: compact.block_time,
        block_height: compact.block_height,
        rewards,
    };

    vote_hashes.ensure_block(block_id);
    let tx_capacity = txs.len();
    let (mut tx_rows, mut message_bytes, mut metadata_bytes) = buffers.take();
    tx_rows.clear();
    message_bytes.clear();
    metadata_bytes.clear();
    reserve_total_capacity(&mut tx_rows, tx_capacity);

    let mut block_signature_count = 0u32;
    for (tx_position, transaction) in txs.into_iter().enumerate() {
        let LiveNoRegistryTransactionSignatureCounts {
            tx_index,
            tx,
            metadata,
        } = transaction;
        let tx_decode_started = timings.detail_timer();
        let WincodeArchiveV2Payload::Decoded { value: tx, .. } = tx else {
            bail!("slot {slot} tx#{tx_position} raw transaction payload");
        };
        let message = optimize_no_registry_message(
            slot,
            tx_position,
            tx.message,
            key_index,
            rolling_blockhashes,
            nonce_recent_blockhashes,
        )?;
        timings.tx_decode_compact += tx_decode_started.elapsed();

        let metadata_decode_started = timings.detail_timer();
        let metadata = metadata
            .map(|payload| -> Result<CompactMetaV1> {
                match payload {
                    WincodeArchiveV2Payload::Decoded { value, .. } => optimize_no_registry_meta(
                        slot,
                        tx_position,
                        value,
                        key_index,
                        Some(timings),
                    ),
                    WincodeArchiveV2Payload::Raw { error, .. } => {
                        bail!("slot {slot} tx#{tx_position} raw metadata payload: {error}");
                    }
                }
            })
            .transpose()?;
        timings.metadata_decode_compact += metadata_decode_started.elapsed();

        let message_offset = u32::try_from(message_bytes.len())
            .context("hot message byte region exceeds u32::MAX")?;
        let message_build_started = timings.detail_timer();
        let (message, mut flags) =
            hot_message_from_owned(message, known_program_ids, slot_to_block_id, vote_hashes)?;
        timings.hot_message_build += message_build_started.elapsed();
        let message_encode_started = timings.detail_timer();
        let before_message_len = message_bytes.len();
        wincode::config::serialize_into(&mut message_bytes, &message, wincode_leb128_config())?;
        let message_len = u32::try_from(message_bytes.len() - before_message_len)
            .context("hot message payload exceeds u32::MAX")?;
        timings.hot_message_encode += message_encode_started.elapsed();

        let signature_count = tx.signatures.count;
        block_signature_count = block_signature_count
            .checked_add(u32::from(signature_count))
            .context("block signature count overflow")?;

        let metadata_offset = u32::try_from(metadata_bytes.len())
            .context("hot metadata byte region exceeds u32::MAX")?;
        let mut metadata_len = 0u32;
        if let Some(metadata) = metadata {
            flags |= ARCHIVE_V2_TX_FLAG_HAS_METADATA;
            flags |= hot_metadata_flags(&metadata);
            let metadata_encode_started = timings.detail_timer();
            let before_metadata_len = metadata_bytes.len();
            wincode::config::serialize_into(
                &mut metadata_bytes,
                &metadata,
                wincode_leb128_config(),
            )?;
            metadata_len = u32::try_from(metadata_bytes.len() - before_metadata_len)
                .context("hot metadata payload exceeds u32::MAX")?;
            timings.hot_metadata_encode += metadata_encode_started.elapsed();
        }

        tx_rows.push(ArchiveV2HotTxRow {
            tx_index,
            flags,
            message_offset,
            message_len,
            metadata_offset,
            metadata_len,
            signature_count,
            reserved: [0; 3],
        });
    }

    let tx_count = u32::try_from(tx_rows.len()).context("hot block tx count exceeds u32::MAX")?;
    Ok((
        ArchiveV2HotBlockBlob {
            header,
            tx_count,
            tx_rows,
            message_bytes,
            metadata_bytes,
        },
        block_signature_count,
    ))
}

fn hot_rewards_from_archive(rewards: WincodeArchiveV2Rewards) -> Result<ArchiveV2HotRewards> {
    anyhow::ensure!(
        rewards.raw_fallback.is_none() && rewards.decode_error.is_none(),
        "hot block writer requires decoded rewards"
    );
    Ok(ArchiveV2HotRewards {
        num_partitions: rewards.num_partitions,
        decoded: rewards.decoded.unwrap_or_default(),
    })
}

fn hot_message_from_owned(
    message: OwnedCompactMessage,
    known_program_ids: &KnownProgramIds,
    slot_to_block_id: &GxHashMap<u64, u32>,
    vote_hashes: &mut VoteHashRegistryBuilder,
) -> Result<(ArchiveV2HotMessagePayload, u32)> {
    hot_message_from_owned_with_instruction_scratch(
        message,
        &mut Vec::new(),
        known_program_ids,
        slot_to_block_id,
        vote_hashes,
    )
}

fn hot_message_from_owned_with_instruction_scratch(
    message: OwnedCompactMessage,
    instruction_scratch: &mut Vec<ArchiveV2HotInstruction>,
    known_program_ids: &KnownProgramIds,
    slot_to_block_id: &GxHashMap<u64, u32>,
    vote_hashes: &mut VoteHashRegistryBuilder,
) -> Result<(ArchiveV2HotMessagePayload, u32)> {
    match message {
        OwnedCompactMessage::Legacy(message) => {
            let has_compact_vote = match hot_instructions_from_owned_into(
                message.instructions,
                &message.account_keys,
                known_program_ids,
                slot_to_block_id,
                vote_hashes,
                instruction_scratch,
            ) {
                Ok(has_compact_vote) => has_compact_vote,
                Err(error) => {
                    instruction_scratch.clear();
                    return Err(error);
                }
            };
            let flags = if has_compact_vote {
                ARCHIVE_V2_TX_FLAG_HAS_COMPACT_VOTE_IX
            } else {
                0
            };
            Ok((
                ArchiveV2HotMessagePayload::Legacy(ArchiveV2HotLegacyMessage {
                    header: message.header,
                    account_keys: message.account_keys,
                    recent_blockhash: message.recent_blockhash,
                    instructions: std::mem::take(instruction_scratch),
                }),
                flags,
            ))
        }
        OwnedCompactMessage::V0(message) => {
            let has_compact_vote = match hot_instructions_from_owned_into(
                message.instructions,
                &message.account_keys,
                known_program_ids,
                slot_to_block_id,
                vote_hashes,
                instruction_scratch,
            ) {
                Ok(has_compact_vote) => has_compact_vote,
                Err(error) => {
                    instruction_scratch.clear();
                    return Err(error);
                }
            };
            let mut flags = ARCHIVE_V2_TX_FLAG_MESSAGE_V0;
            if has_compact_vote {
                flags |= ARCHIVE_V2_TX_FLAG_HAS_COMPACT_VOTE_IX;
            }
            Ok((
                ArchiveV2HotMessagePayload::V0(ArchiveV2HotV0Message {
                    header: message.header,
                    account_keys: message.account_keys,
                    recent_blockhash: message.recent_blockhash,
                    instructions: std::mem::take(instruction_scratch),
                    address_table_lookups: message.address_table_lookups,
                }),
                flags,
            ))
        }
        OwnedCompactMessage::V1(message) => {
            let has_compact_vote = match hot_instructions_from_owned_into(
                message.instructions,
                &message.account_keys,
                known_program_ids,
                slot_to_block_id,
                vote_hashes,
                instruction_scratch,
            ) {
                Ok(has_compact_vote) => has_compact_vote,
                Err(error) => {
                    instruction_scratch.clear();
                    return Err(error);
                }
            };
            let flags = if has_compact_vote {
                ARCHIVE_V2_TX_FLAG_HAS_COMPACT_VOTE_IX
            } else {
                0
            };
            Ok((
                ArchiveV2HotMessagePayload::V1(ArchiveV2HotV1Message {
                    header: message.header,
                    config: message.config,
                    account_keys: message.account_keys,
                    recent_blockhash: message.recent_blockhash,
                    instructions: std::mem::take(instruction_scratch),
                }),
                flags,
            ))
        }
    }
}

fn hot_instructions_from_owned_into(
    instructions: Vec<OwnedCompactInstruction>,
    account_keys: &[CompactPubkey],
    known_program_ids: &KnownProgramIds,
    slot_to_block_id: &GxHashMap<u64, u32>,
    vote_hashes: &mut VoteHashRegistryBuilder,
    out: &mut Vec<ArchiveV2HotInstruction>,
) -> Result<bool> {
    out.clear();
    reserve_total_capacity(out, instructions.len());
    let mut has_compact_vote = false;
    for instruction in instructions {
        let program_id =
            resolve_static_program_compact_id(account_keys, instruction.program_id_index);
        let data = if known_program_ids.is_vote(program_id) {
            let data =
                parse_hot_vote_instruction_data(&instruction.data, slot_to_block_id, vote_hashes)
                    .with_context(|| "parse vote instruction data")?;
            if matches!(
                data,
                ArchiveV2HotInstructionData::VoteCompactUpdateVoteState(_)
                    | ArchiveV2HotInstructionData::VoteCompactUpdateVoteStateSwitch { .. }
                    | ArchiveV2HotInstructionData::VoteTowerSync(_)
                    | ArchiveV2HotInstructionData::VoteTowerSyncSwitch { .. }
            ) {
                has_compact_vote = true;
                vote_hashes.compact_vote_ix += 1;
            }
            data
        } else if known_program_ids.is_compute_budget(program_id) {
            parse_hot_compute_budget_instruction_data(&instruction.data)
                .with_context(|| "parse compute budget instruction data")?
        } else if known_program_ids.is_system(program_id) {
            parse_hot_system_instruction_data(&instruction.data)
                .with_context(|| "parse system instruction data")?
        } else {
            ArchiveV2HotInstructionData::Raw(instruction.data)
        };
        out.push(ArchiveV2HotInstruction {
            program_id_index: instruction.program_id_index,
            accounts: instruction.accounts,
            data,
        });
    }
    Ok(has_compact_vote)
}

fn resolve_static_program_compact_id(
    account_keys: &[CompactPubkey],
    program_id_index: u8,
) -> Option<u32> {
    match account_keys.get(program_id_index as usize)? {
        CompactPubkey::Id(id) => Some(*id),
        CompactPubkey::Raw(_) => None,
    }
}

#[derive(Clone, Copy, Debug)]
struct KnownProgramIds {
    vote: Option<u32>,
    compute_budget: Option<u32>,
    system: Option<u32>,
}

impl KnownProgramIds {
    fn from_index(index: &KeyIndex) -> Self {
        Self {
            vote: index.lookup(&vote_program_id_bytes()),
            compute_budget: index.lookup(&compute_budget_program_id_bytes()),
            system: index.lookup(&system_program_id_bytes()),
        }
    }

    #[inline]
    fn is_vote(&self, id: Option<u32>) -> bool {
        id.is_some() && id == self.vote
    }

    #[inline]
    fn is_compute_budget(&self, id: Option<u32>) -> bool {
        id.is_some() && id == self.compute_budget
    }

    #[inline]
    fn is_system(&self, id: Option<u32>) -> bool {
        id.is_some() && id == self.system
    }
}

fn hot_metadata_flags(metadata: &CompactMetaV1) -> u32 {
    let mut flags = 0;
    if metadata.err.is_some() {
        flags |= ARCHIVE_V2_TX_FLAG_HAS_ERROR;
    }
    if metadata.return_data.is_some() {
        flags |= ARCHIVE_V2_TX_FLAG_HAS_RETURN_DATA;
    }
    if metadata.logs.is_some() {
        flags |= ARCHIVE_V2_TX_FLAG_HAS_LOGS;
    }
    if metadata.inner_instructions.is_some() {
        flags |= ARCHIVE_V2_TX_FLAG_HAS_INNER_IX;
    }
    if !metadata.pre_token_balances.is_empty() || !metadata.post_token_balances.is_empty() {
        flags |= ARCHIVE_V2_TX_FLAG_HAS_TOKEN_BALANCES;
    }
    if !metadata.loaded_writable_addresses.is_empty()
        || !metadata.loaded_readonly_addresses.is_empty()
    {
        flags |= ARCHIVE_V2_TX_FLAG_HAS_LOADED_ADDRESSES;
    }
    flags
}

fn parse_hot_vote_instruction_data(
    data: &[u8],
    slot_to_block_id: &GxHashMap<u64, u32>,
    vote_hashes: &mut VoteHashRegistryBuilder,
) -> Result<ArchiveV2HotInstructionData> {
    if data.is_empty() {
        return Ok(ArchiveV2HotInstructionData::UnknownVote(Vec::new()));
    }

    if data.len() > VOTE_INSTRUCTION_DECODE_LIMIT as usize {
        return Ok(ArchiveV2HotInstructionData::UnknownVote(data.to_vec()));
    }

    let instruction_result: std::result::Result<VoteInstruction, _> = bincode::deserialize(data);
    let instruction = match instruction_result {
        Ok(instruction) => instruction,
        Err(_) => {
            match try_parse_historical_tower_sync_instruction_data(
                data,
                slot_to_block_id,
                vote_hashes,
            ) {
                Ok(Some(parsed)) => return Ok(parsed),
                Ok(None) | Err(_) => {
                    return Ok(ArchiveV2HotInstructionData::UnknownVote(data.to_vec()));
                }
            }
        }
    };

    let parsed = match instruction {
        VoteInstruction::CompactUpdateVoteState(update) => {
            let update =
                match archive_vote_state_update_from_solana(&update, slot_to_block_id, vote_hashes)
                {
                    Ok(update) => update,
                    Err(_) => return Ok(ArchiveV2HotInstructionData::UnknownVote(data.to_vec())),
                };
            ArchiveV2HotInstructionData::VoteCompactUpdateVoteState(update)
        }
        VoteInstruction::CompactUpdateVoteStateSwitch(update, switch_proof_hash) => {
            let update =
                match archive_vote_state_update_from_solana(&update, slot_to_block_id, vote_hashes)
                {
                    Ok(update) => update,
                    Err(_) => return Ok(ArchiveV2HotInstructionData::UnknownVote(data.to_vec())),
                };
            let switch_proof_hash = vote_hashes.ref_aux_hash(switch_proof_hash.to_bytes());
            ArchiveV2HotInstructionData::VoteCompactUpdateVoteStateSwitch {
                update,
                switch_proof_hash,
            }
        }
        VoteInstruction::TowerSync(tower) => {
            let tower = match archive_tower_sync_from_solana(&tower, slot_to_block_id, vote_hashes)
            {
                Ok(tower) => tower,
                Err(_) => return Ok(ArchiveV2HotInstructionData::UnknownVote(data.to_vec())),
            };
            ArchiveV2HotInstructionData::VoteTowerSync(tower)
        }
        VoteInstruction::TowerSyncSwitch(tower, switch_proof_hash) => {
            let tower = match archive_tower_sync_from_solana(&tower, slot_to_block_id, vote_hashes)
            {
                Ok(tower) => tower,
                Err(_) => return Ok(ArchiveV2HotInstructionData::UnknownVote(data.to_vec())),
            };
            let switch_proof_hash = vote_hashes.ref_aux_hash(switch_proof_hash.to_bytes());
            ArchiveV2HotInstructionData::VoteTowerSyncSwitch {
                tower,
                switch_proof_hash,
            }
        }
        _ => ArchiveV2HotInstructionData::Raw(data.to_vec()),
    };
    Ok(parsed)
}

fn try_parse_historical_tower_sync_instruction_data(
    data: &[u8],
    slot_to_block_id: &GxHashMap<u64, u32>,
    vote_hashes: &mut VoteHashRegistryBuilder,
) -> Result<Option<ArchiveV2HotInstructionData>> {
    if data.len() < 4 {
        return Ok(None);
    }
    let mut cursor = VoteInstructionCursor::new(data);
    let variant = cursor.read_u32_le()?;
    let parsed = match variant {
        14 => {
            let tower = read_historical_tower_sync(&mut cursor)?;
            cursor.ensure_eof()?;
            ArchiveV2HotInstructionData::VoteTowerSync(compact_historical_tower_sync(
                tower,
                slot_to_block_id,
                vote_hashes,
            )?)
        }
        15 => {
            let tower = read_historical_tower_sync(&mut cursor)?;
            let switch_proof_hash = cursor.read_pubkey()?;
            cursor.ensure_eof()?;
            ArchiveV2HotInstructionData::VoteTowerSyncSwitch {
                tower: compact_historical_tower_sync(tower, slot_to_block_id, vote_hashes)?,
                switch_proof_hash: vote_hashes.ref_aux_hash(switch_proof_hash),
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(parsed))
}

struct HistoricalTowerSync {
    root: Option<u64>,
    lockouts: Vec<(u64, u8)>,
    hash: [u8; 32],
    timestamp: Option<i64>,
    block_id: [u8; 32],
}

fn read_historical_tower_sync(
    cursor: &mut VoteInstructionCursor<'_>,
) -> Result<HistoricalTowerSync> {
    let lockout_len = cursor.read_u64_le()?;
    anyhow::ensure!(
        lockout_len <= 31,
        "historical tower sync lockout history length {} exceeds MAX_LOCKOUT_HISTORY",
        lockout_len
    );
    let mut lockouts = Vec::with_capacity(lockout_len as usize);
    for _ in 0..lockout_len {
        let slot = cursor.read_u64_le()?;
        let confirmation_count = cursor.read_u32_le()?;
        let confirmation_count = u8::try_from(confirmation_count)
            .context("historical vote confirmation count exceeds u8::MAX")?;
        lockouts.push((slot, confirmation_count));
    }
    let root = cursor.read_option_u64_le()?;
    let hash = cursor.read_pubkey()?;
    let timestamp = cursor.read_option_i64_le()?;
    let block_id = cursor.read_pubkey()?;

    Ok(HistoricalTowerSync {
        root,
        lockouts,
        hash,
        timestamp,
        block_id,
    })
}

fn compact_historical_tower_sync(
    tower: HistoricalTowerSync,
    slot_to_block_id: &GxHashMap<u64, u32>,
    vote_hashes: &mut VoteHashRegistryBuilder,
) -> Result<ArchiveV2VoteTowerSync> {
    let (update, last_slot) = archive_vote_state_update_from_parts(
        tower.root,
        tower.lockouts.into_iter().map(Ok),
        tower.hash,
        tower.timestamp,
        slot_to_block_id,
        vote_hashes,
    )?;
    let block_id_hash =
        vote_hashes.ref_block_id_hash(last_slot, tower.block_id, slot_to_block_id)?;
    Ok(ArchiveV2VoteTowerSync {
        update,
        block_id_hash,
    })
}

fn hex_prefix(data: &[u8], max_len: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = &data[..data.len().min(max_len)];
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    if data.len() > max_len {
        out.push_str("...");
    }
    out
}

fn parse_hot_compute_budget_instruction_data(data: &[u8]) -> Result<ArchiveV2HotInstructionData> {
    match try_parse_hot_compute_budget_instruction_data(data).with_context(|| {
        format!(
            "parse compute budget instruction data len={} prefix={}",
            data.len(),
            hex_prefix(data, 32)
        )
    })? {
        Some(parsed) => Ok(parsed),
        None => Ok(ArchiveV2HotInstructionData::Raw(data.to_vec())),
    }
}

fn try_parse_hot_compute_budget_instruction_data(
    data: &[u8],
) -> Result<Option<ArchiveV2HotInstructionData>> {
    let Some((&tag, rest)) = data.split_first() else {
        anyhow::bail!("empty compute budget instruction data");
    };
    let mut cursor = VoteInstructionCursor::new(rest);
    let parsed = match tag {
        0 => {
            if !cursor.is_eof() {
                return Ok(None);
            }
            cursor.ensure_eof()?;
            ArchiveV2HotInstructionData::ComputeBudget(
                ArchiveV2ComputeBudgetInstructionData::Unused,
            )
        }
        1 => {
            let bytes = cursor.read_u32_le()?;
            if !cursor.is_eof() {
                return Ok(None);
            }
            ArchiveV2HotInstructionData::ComputeBudget(
                ArchiveV2ComputeBudgetInstructionData::RequestHeapFrame(bytes),
            )
        }
        2 => {
            let units = cursor.read_u32_le()?;
            if !cursor.is_eof() {
                return Ok(None);
            }
            ArchiveV2HotInstructionData::ComputeBudget(
                ArchiveV2ComputeBudgetInstructionData::SetComputeUnitLimit(units),
            )
        }
        3 => {
            let micro_lamports = cursor.read_u64_le()?;
            if !cursor.is_eof() {
                return Ok(None);
            }
            ArchiveV2HotInstructionData::ComputeBudget(
                ArchiveV2ComputeBudgetInstructionData::SetComputeUnitPrice(micro_lamports),
            )
        }
        4 => {
            let bytes = cursor.read_u32_le()?;
            if !cursor.is_eof() {
                return Ok(None);
            }
            ArchiveV2HotInstructionData::ComputeBudget(
                ArchiveV2ComputeBudgetInstructionData::SetLoadedAccountsDataSizeLimit(bytes),
            )
        }
        _ => return Ok(None),
    };
    Ok(Some(parsed))
}

fn parse_hot_system_instruction_data(data: &[u8]) -> Result<ArchiveV2HotInstructionData> {
    match try_parse_hot_system_instruction_data(data) {
        Some(parsed) => Ok(parsed),
        None => Ok(ArchiveV2HotInstructionData::UnknownSystem(data.to_vec())),
    }
}

fn try_parse_hot_system_instruction_data(data: &[u8]) -> Option<ArchiveV2HotInstructionData> {
    try_parse_hot_system_instruction_data_inner(data)
        .ok()
        .flatten()
}

fn try_parse_hot_system_instruction_data_inner(
    data: &[u8],
) -> Result<Option<ArchiveV2HotInstructionData>> {
    let mut cursor = VoteInstructionCursor::new(data);
    let variant = cursor.read_u32_le()?;
    macro_rules! preserve_raw_on_trailing_bytes {
        () => {
            if !cursor.is_eof() {
                return Ok(None);
            }
        };
    }
    let parsed = match variant {
        0 => {
            let lamports = cursor.read_u64_le()?;
            let space = cursor.read_u64_le()?;
            let owner = cursor.read_pubkey()?;
            preserve_raw_on_trailing_bytes!();
            ArchiveV2HotInstructionData::System(ArchiveV2SystemInstructionData::CreateAccount {
                lamports,
                space,
                owner,
            })
        }
        1 => {
            let owner = cursor.read_pubkey()?;
            preserve_raw_on_trailing_bytes!();
            ArchiveV2HotInstructionData::System(ArchiveV2SystemInstructionData::Assign { owner })
        }
        2 => {
            let lamports = cursor.read_u64_le()?;
            preserve_raw_on_trailing_bytes!();
            ArchiveV2HotInstructionData::System(ArchiveV2SystemInstructionData::Transfer {
                lamports,
            })
        }
        3 => {
            let base = cursor.read_pubkey()?;
            let seed = cursor.read_system_seed()?;
            let lamports = cursor.read_u64_le()?;
            let space = cursor.read_u64_le()?;
            let owner = cursor.read_pubkey()?;
            preserve_raw_on_trailing_bytes!();
            ArchiveV2HotInstructionData::System(
                ArchiveV2SystemInstructionData::CreateAccountWithSeed {
                    base,
                    seed,
                    lamports,
                    space,
                    owner,
                },
            )
        }
        4 => {
            preserve_raw_on_trailing_bytes!();
            ArchiveV2HotInstructionData::System(ArchiveV2SystemInstructionData::AdvanceNonceAccount)
        }
        5 => {
            let lamports = cursor.read_u64_le()?;
            preserve_raw_on_trailing_bytes!();
            ArchiveV2HotInstructionData::System(
                ArchiveV2SystemInstructionData::WithdrawNonceAccount { lamports },
            )
        }
        6 => {
            let authority = cursor.read_pubkey()?;
            preserve_raw_on_trailing_bytes!();
            ArchiveV2HotInstructionData::System(
                ArchiveV2SystemInstructionData::InitializeNonceAccount { authority },
            )
        }
        7 => {
            let authority = cursor.read_pubkey()?;
            preserve_raw_on_trailing_bytes!();
            ArchiveV2HotInstructionData::System(
                ArchiveV2SystemInstructionData::AuthorizeNonceAccount { authority },
            )
        }
        8 => {
            let space = cursor.read_u64_le()?;
            preserve_raw_on_trailing_bytes!();
            ArchiveV2HotInstructionData::System(ArchiveV2SystemInstructionData::Allocate { space })
        }
        9 => {
            let base = cursor.read_pubkey()?;
            let seed = cursor.read_system_seed()?;
            let space = cursor.read_u64_le()?;
            let owner = cursor.read_pubkey()?;
            preserve_raw_on_trailing_bytes!();
            ArchiveV2HotInstructionData::System(ArchiveV2SystemInstructionData::AllocateWithSeed {
                base,
                seed,
                space,
                owner,
            })
        }
        10 => {
            let base = cursor.read_pubkey()?;
            let seed = cursor.read_system_seed()?;
            let owner = cursor.read_pubkey()?;
            preserve_raw_on_trailing_bytes!();
            ArchiveV2HotInstructionData::System(ArchiveV2SystemInstructionData::AssignWithSeed {
                base,
                seed,
                owner,
            })
        }
        11 => {
            let lamports = cursor.read_u64_le()?;
            let from_seed = cursor.read_system_seed()?;
            let from_owner = cursor.read_pubkey()?;
            preserve_raw_on_trailing_bytes!();
            ArchiveV2HotInstructionData::System(ArchiveV2SystemInstructionData::TransferWithSeed {
                lamports,
                from_seed,
                from_owner,
            })
        }
        12 => {
            preserve_raw_on_trailing_bytes!();
            ArchiveV2HotInstructionData::System(ArchiveV2SystemInstructionData::UpgradeNonceAccount)
        }
        13 => {
            let lamports = cursor.read_u64_le()?;
            let space = cursor.read_u64_le()?;
            let owner = cursor.read_pubkey()?;
            preserve_raw_on_trailing_bytes!();
            ArchiveV2HotInstructionData::System(
                ArchiveV2SystemInstructionData::CreateAccountAllowPrefund {
                    lamports,
                    space,
                    owner,
                },
            )
        }
        _ => return Ok(None),
    };
    Ok(Some(parsed))
}

fn archive_tower_sync_from_solana(
    tower: &SolanaTowerSync,
    slot_to_block_id: &GxHashMap<u64, u32>,
    vote_hashes: &mut VoteHashRegistryBuilder,
) -> Result<ArchiveV2VoteTowerSync> {
    let (update, last_slot) = archive_vote_state_update_from_parts(
        tower.root,
        tower.lockouts.iter().map(|lockout| {
            Ok((
                lockout.slot(),
                u8::try_from(lockout.confirmation_count())
                    .context("vote confirmation count exceeds u8::MAX")?,
            ))
        }),
        tower.hash.to_bytes(),
        tower.timestamp,
        slot_to_block_id,
        vote_hashes,
    )?;
    let block_id_hash =
        vote_hashes.ref_block_id_hash(last_slot, tower.block_id.to_bytes(), slot_to_block_id)?;
    Ok(ArchiveV2VoteTowerSync {
        update,
        block_id_hash,
    })
}

fn archive_vote_state_update_from_solana(
    update: &SolanaVoteStateUpdate,
    slot_to_block_id: &GxHashMap<u64, u32>,
    vote_hashes: &mut VoteHashRegistryBuilder,
) -> Result<ArchiveV2VoteStateUpdate> {
    Ok(archive_vote_state_update_from_parts(
        update.root,
        update.lockouts.iter().map(|lockout| {
            Ok((
                lockout.slot(),
                u8::try_from(lockout.confirmation_count())
                    .context("vote confirmation count exceeds u8::MAX")?,
            ))
        }),
        update.hash.to_bytes(),
        update.timestamp,
        slot_to_block_id,
        vote_hashes,
    )?
    .0)
}

fn archive_vote_state_update_from_parts<I>(
    root: Option<u64>,
    lockouts: I,
    hash: [u8; 32],
    timestamp: Option<i64>,
    slot_to_block_id: &GxHashMap<u64, u32>,
    vote_hashes: &mut VoteHashRegistryBuilder,
) -> Result<(ArchiveV2VoteStateUpdate, Option<u64>)>
where
    I: IntoIterator<Item = Result<(u64, u8)>>,
{
    let lockouts = lockouts.into_iter().collect::<Result<Vec<_>>>()?;
    anyhow::ensure!(
        lockouts.len() <= 31,
        "vote lockout history length {} exceeds MAX_LOCKOUT_HISTORY",
        lockouts.len()
    );
    let mut lockout_offsets = Vec::with_capacity(lockouts.len());
    let mut slot = root.unwrap_or_default();
    let mut last_slot = None;
    for (next_slot, confirmation_count) in lockouts {
        let offset = next_slot
            .checked_sub(slot)
            .context("vote lockout slots are not monotonic")?;
        slot = next_slot;
        lockout_offsets.push(ArchiveV2VoteLockoutOffset {
            offset,
            confirmation_count,
        });
        last_slot = Some(slot);
    }
    let hash = vote_hashes.ref_bank_hash(last_slot, hash, slot_to_block_id)?;
    Ok((
        ArchiveV2VoteStateUpdate {
            root,
            lockout_offsets,
            hash,
            timestamp,
        },
        last_slot,
    ))
}

struct VoteInstructionCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> VoteInstructionCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn is_eof(&self) -> bool {
        self.pos == self.bytes.len()
    }

    fn ensure_eof(&self) -> Result<()> {
        anyhow::ensure!(
            self.pos == self.bytes.len(),
            "trailing {} bytes in instruction data",
            self.bytes.len().saturating_sub(self.pos)
        );
        Ok(())
    }

    fn read_u32_le(&mut self) -> Result<u32> {
        let bytes = self.read_array::<4>()?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_u64_le(&mut self) -> Result<u64> {
        let bytes = self.read_array::<8>()?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_i64_le(&mut self) -> Result<i64> {
        let bytes = self.read_array::<8>()?;
        Ok(i64::from_le_bytes(bytes))
    }

    fn read_option_u64_le(&mut self) -> Result<Option<u64>> {
        match self.read_option_tag()? {
            0 => Ok(None),
            1 => Ok(Some(self.read_u64_le()?)),
            tag => anyhow::bail!("invalid bincode Option<u64> tag {tag}"),
        }
    }

    fn read_option_i64_le(&mut self) -> Result<Option<i64>> {
        match self.read_option_tag()? {
            0 => Ok(None),
            1 => Ok(Some(self.read_i64_le()?)),
            tag => anyhow::bail!("invalid bincode Option<i64> tag {tag}"),
        }
    }

    fn read_option_tag(&mut self) -> Result<u8> {
        let tag = self.read_array::<1>()?;
        Ok(tag[0])
    }

    fn read_pubkey(&mut self) -> Result<[u8; 32]> {
        self.read_array::<32>()
    }

    fn read_system_seed(&mut self) -> Result<String> {
        let len = self.read_u64_le()?;
        let bytes = self.read_slice(len as usize)?;
        String::from_utf8(bytes.to_vec()).context("system instruction seed is not UTF-8")
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .context("instruction cursor overflow")?;
        anyhow::ensure!(
            end <= self.bytes.len(),
            "unexpected EOF in instruction data while reading {len} bytes"
        );
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self
            .pos
            .checked_add(N)
            .context("instruction cursor overflow")?;
        anyhow::ensure!(
            end <= self.bytes.len(),
            "unexpected EOF in instruction data while reading {N} bytes"
        );
        let mut out = [0u8; N];
        out.copy_from_slice(&self.bytes[self.pos..end]);
        self.pos = end;
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreviousBlockhash {
    hash: [u8; 32],
    slot: u64,
}

fn write_prev_blockhash_tail(output_dir: &Path, tail: &[PreviousBlockhash]) -> Result<()> {
    let path = output_dir.join(PREV_BLOCKHASH_TAIL_FILE);
    let file = File::create(&path).with_context(|| format!("create {}", path.display()))?;
    let mut writer = BufWriter::with_capacity(BUFFER_SIZE, file);
    for item in tail {
        writer
            .write_all(&item.hash)
            .with_context(|| format!("write {}", path.display()))?;
        writer
            .write_all(&item.slot.to_le_bytes())
            .with_context(|| format!("write {}", path.display()))?;
    }
    writer
        .flush()
        .with_context(|| format!("flush {}", path.display()))?;
    Ok(())
}

fn count_no_registry_block_pubkeys(
    block: &WincodeArchiveV2NoRegistryBlock,
    counter: &mut ArchivePubkeyCounter,
) -> Result<u64> {
    if let Some(rewards) = &block.header.rewards {
        count_no_registry_rewards_pubkeys(rewards, counter)?;
    }

    for (tx_index, tx) in block.txs.iter().enumerate() {
        let WincodeArchiveV2Payload::Decoded { value, .. } = &tx.tx else {
            anyhow::bail!(
                "slot {} tx#{tx_index} raw transaction payload in no-registry archive",
                block.header.compact.slot
            );
        };
        count_no_registry_tx_pubkeys(value, counter);

        if let Some(metadata) = &tx.metadata {
            let WincodeArchiveV2Payload::Decoded { value, .. } = metadata else {
                anyhow::bail!(
                    "slot {} tx#{tx_index} raw metadata payload in no-registry archive",
                    block.header.compact.slot
                );
            };
            count_no_registry_meta_pubkeys(value, counter);
        }
    }

    Ok(block.txs.len() as u64)
}

fn count_no_registry_tx_pubkeys(
    tx: &WincodeArchiveV2NoRegistryTx,
    counter: &mut ArchivePubkeyCounter,
) {
    match &tx.message {
        WincodeArchiveV2NoRegistryMessage::Legacy(message) => {
            for key in &message.account_keys {
                counter.add32(key);
            }
        }
        WincodeArchiveV2NoRegistryMessage::V0(message) => {
            for key in &message.account_keys {
                counter.add32(key);
            }
            for lookup in &message.address_table_lookups {
                counter.add32(&lookup.account_key);
            }
        }
        WincodeArchiveV2NoRegistryMessage::V1(message) => {
            for key in &message.account_keys {
                counter.add32(key);
            }
        }
    }
}

fn count_no_registry_meta_pubkeys(
    meta: &WincodeArchiveV2NoRegistryMeta,
    counter: &mut ArchivePubkeyCounter,
) {
    for key in &meta.loaded_writable_addresses {
        counter.add32(key);
    }
    for key in &meta.loaded_readonly_addresses {
        counter.add32(key);
    }
    for balance in meta
        .pre_token_balances
        .iter()
        .chain(meta.post_token_balances.iter())
    {
        if let Some(key) = &balance.mint {
            counter.add32(key);
        }
        if let Some(key) = &balance.owner {
            counter.add32(key);
        }
        if let Some(key) = &balance.program_id {
            counter.add32(key);
        }
    }
    for reward in &meta.rewards {
        counter.add32(&reward.pubkey);
    }
    if let Some(return_data) = &meta.return_data {
        counter.add32(&return_data.program_id);
    }
}

fn count_no_registry_rewards_pubkeys(
    rewards: &WincodeArchiveV2NoRegistryRewards,
    counter: &mut ArchivePubkeyCounter,
) -> Result<()> {
    anyhow::ensure!(
        rewards.raw_fallback.is_none() && rewards.decode_error.is_none(),
        "raw rewards fallback in no-registry archive"
    );
    let Some(decoded) = &rewards.decoded else {
        anyhow::bail!("rewards record present without decoded rewards");
    };
    for reward in decoded {
        counter.add32(&reward.pubkey);
    }
    Ok(())
}

fn optimize_no_registry_tx(
    slot: u64,
    tx_index: usize,
    tx: WincodeArchiveV2NoRegistryTx,
    key_index: &KeyIndex,
    rolling_blockhashes: &RollingBlockhashIndex,
    nonce_recent_blockhashes: &mut u64,
) -> Result<OwnedCompactTransaction> {
    let message = optimize_no_registry_message(
        slot,
        tx_index,
        tx.message,
        key_index,
        rolling_blockhashes,
        nonce_recent_blockhashes,
    )?;

    Ok(OwnedCompactTransaction {
        signatures: tx.signatures,
        message,
    })
}

fn optimize_no_registry_message(
    slot: u64,
    tx_index: usize,
    message: WincodeArchiveV2NoRegistryMessage,
    key_index: &KeyIndex,
    rolling_blockhashes: &RollingBlockhashIndex,
    nonce_recent_blockhashes: &mut u64,
) -> Result<OwnedCompactMessage> {
    Ok(match message {
        WincodeArchiveV2NoRegistryMessage::Legacy(message) => {
            OwnedCompactMessage::Legacy(OwnedCompactLegacyMessage {
                header: message.header,
                account_keys: compact_required_keys(
                    key_index,
                    &message.account_keys,
                    "transaction account key",
                )?,
                recent_blockhash: resolve_recent_blockhash(
                    rolling_blockhashes,
                    &message.recent_blockhash,
                    slot,
                    tx_index,
                    nonce_recent_blockhashes,
                )?,
                instructions: message
                    .instructions
                    .into_iter()
                    .map(owned_no_registry_instruction)
                    .collect(),
            })
        }
        WincodeArchiveV2NoRegistryMessage::V0(message) => {
            OwnedCompactMessage::V0(OwnedCompactV0Message {
                header: message.header,
                account_keys: compact_required_keys(
                    key_index,
                    &message.account_keys,
                    "transaction account key",
                )?,
                recent_blockhash: resolve_recent_blockhash(
                    rolling_blockhashes,
                    &message.recent_blockhash,
                    slot,
                    tx_index,
                    nonce_recent_blockhashes,
                )?,
                instructions: message
                    .instructions
                    .into_iter()
                    .map(owned_no_registry_instruction)
                    .collect(),
                address_table_lookups: message
                    .address_table_lookups
                    .into_iter()
                    .map(|lookup| optimize_no_registry_lookup(lookup, key_index))
                    .collect::<Result<Vec<_>>>()?,
            })
        }
        WincodeArchiveV2NoRegistryMessage::V1(message) => {
            OwnedCompactMessage::V1(OwnedCompactV1Message {
                header: message.header,
                config: message.config,
                account_keys: compact_required_keys(
                    key_index,
                    &message.account_keys,
                    "transaction account key",
                )?,
                recent_blockhash: resolve_recent_blockhash(
                    rolling_blockhashes,
                    &message.recent_blockhash,
                    slot,
                    tx_index,
                    nonce_recent_blockhashes,
                )?,
                instructions: message
                    .instructions
                    .into_iter()
                    .map(owned_no_registry_instruction)
                    .collect(),
            })
        }
    })
}

fn optimize_no_registry_lookup(
    lookup: WincodeArchiveV2NoRegistryAddressTableLookup,
    key_index: &KeyIndex,
) -> Result<OwnedCompactAddressTableLookup> {
    Ok(OwnedCompactAddressTableLookup {
        account_key: compact_required(key_index, &lookup.account_key, "address table lookup")?,
        writable_indexes: lookup.writable_indexes,
        readonly_indexes: lookup.readonly_indexes,
    })
}

fn owned_no_registry_instruction(
    instruction: WincodeArchiveV2NoRegistryInstruction,
) -> OwnedCompactInstruction {
    OwnedCompactInstruction {
        program_id_index: instruction.program_id_index,
        accounts: instruction.accounts,
        data: instruction.data,
    }
}

fn optimize_no_registry_meta(
    _slot: u64,
    _tx_index: usize,
    meta: WincodeArchiveV2NoRegistryMeta,
    key_index: &KeyIndex,
    mut timings: Option<&mut ArchiveV2Timings>,
) -> Result<blockzilla_compact::CompactMetaV1> {
    let logs_started = ArchiveV2Timings::optional_detail_timer(timings.as_deref());
    let logs = meta
        .logs
        .map(|logs| decode_no_registry_logs(logs, _slot, _tx_index, key_index))
        .transpose()?;
    if let Some(timings) = timings.as_mut() {
        timings.metadata_logs_decode_compact += logs_started.elapsed();
    }

    let pubkey_started = ArchiveV2Timings::optional_detail_timer(timings.as_deref());
    let pre_token_balances = meta
        .pre_token_balances
        .into_iter()
        .map(|balance| optimize_no_registry_token_balance(balance, key_index))
        .collect::<Result<Vec<_>>>()?;
    let post_token_balances = meta
        .post_token_balances
        .into_iter()
        .map(|balance| optimize_no_registry_token_balance(balance, key_index))
        .collect::<Result<Vec<_>>>()?;
    let rewards = meta
        .rewards
        .into_iter()
        .map(|reward| optimize_no_registry_reward(&reward, key_index))
        .collect::<Result<Vec<_>>>()?;
    let loaded_writable_addresses = meta
        .loaded_writable_addresses
        .into_iter()
        .map(|key| compact_required(key_index, &key, "loaded writable address"))
        .collect::<Result<Vec<_>>>()?;
    let loaded_readonly_addresses = meta
        .loaded_readonly_addresses
        .into_iter()
        .map(|key| compact_required(key_index, &key, "loaded readonly address"))
        .collect::<Result<Vec<_>>>()?;
    let return_data = meta
        .return_data
        .map(|return_data| {
            Ok::<CompactReturnData, anyhow::Error>(CompactReturnData {
                program_id: compact_required(
                    key_index,
                    &return_data.program_id,
                    "return data program id",
                )?,
                data: return_data.data,
            })
        })
        .transpose()?;
    if let Some(timings) = timings.as_mut() {
        timings.metadata_pubkey_compact += pubkey_started.elapsed();
    }

    Ok(blockzilla_compact::CompactMetaV1 {
        err: meta.err,
        fee: meta.fee,
        pre_balances: meta.pre_balances,
        post_balances: meta.post_balances,
        inner_instructions: meta.inner_instructions,
        logs,
        pre_token_balances,
        post_token_balances,
        rewards,
        loaded_writable_addresses,
        loaded_readonly_addresses,
        return_data,
        compute_units_consumed: meta.compute_units_consumed,
        cost_units: meta.cost_units,
    })
}

fn decode_no_registry_logs(
    logs: WincodeArchiveV2NoRegistryLogs,
    slot: u64,
    tx_index: usize,
    key_index: &KeyIndex,
) -> Result<CompactLogStream> {
    match logs {
        WincodeArchiveV2NoRegistryLogs::Raw(logs) => {
            Ok(blockzilla_compact::parse_logs(&logs, key_index))
        }
        WincodeArchiveV2NoRegistryLogs::WincodeZstd {
            uncompressed_len,
            bytes,
        } => {
            let decoded = zstd::stream::decode_all(bytes.as_slice())
                .with_context(|| format!("slot {slot} tx#{tx_index} live log zstd"))?;
            if decoded.len() as u64 != uncompressed_len {
                bail!(
                    "slot {slot} tx#{tx_index} live log zstd decoded length {} != expected {uncompressed_len}",
                    decoded.len()
                );
            }
            let logs: Vec<String> = wincode::config::deserialize(&decoded, wincode_leb128_config())
                .with_context(|| format!("slot {slot} tx#{tx_index} live log strings"))?;
            Ok(blockzilla_compact::parse_logs(&logs, key_index))
        }
        WincodeArchiveV2NoRegistryLogs::Compact(logs) => Ok(rekey_compact_logs(logs, key_index)),
    }
}

fn rekey_compact_logs(mut logs: CompactLogStream, key_index: &KeyIndex) -> CompactLogStream {
    for event in &mut logs.events {
        rekey_log_event(event, key_index);
    }
    logs
}

fn rekey_log_event(event: &mut LogEvent, key_index: &KeyIndex) {
    match event {
        LogEvent::LoaderUpgradedProgram { program }
        | LogEvent::Invoke { program, .. }
        | LogEvent::BpfInvoke { program }
        | LogEvent::Consumed { program, .. }
        | LogEvent::Success { program }
        | LogEvent::BpfSuccess { program }
        | LogEvent::Failure { program, .. }
        | LogEvent::BpfFailure { program, .. }
        | LogEvent::FailureCustomProgramError { program, .. }
        | LogEvent::BpfFailureCustomProgramError { program, .. }
        | LogEvent::FailureInvalidAccountData { program }
        | LogEvent::BpfFailureInvalidAccountData { program }
        | LogEvent::FailureInvalidProgramArgument { program }
        | LogEvent::BpfFailureInvalidProgramArgument { program }
        | LogEvent::Return { program, .. } => {
            rekey_compact_pubkey(program, key_index);
        }
        LogEvent::ProgramIdLog { program, log } => {
            rekey_compact_pubkey(program, key_index);
            rekey_program_log(log, key_index);
        }
        LogEvent::LoaderFinalizedAccount { account }
        | LogEvent::RuntimeWritablePrivilegeEscalated { account }
        | LogEvent::RuntimeSignerPrivilegeEscalated { account }
        | LogEvent::RuntimeAccountOwnerBalanceVerificationFailed { account } => {
            rekey_compact_pubkey(account, key_index);
        }
        LogEvent::ProgramNotDeployed { program } | LogEvent::ProgramNotCached { program } => {
            if let Some(program) = program {
                rekey_compact_pubkey(program, key_index);
            }
        }
        LogEvent::System(log) => rekey_system_program_log(log, key_index),
        LogEvent::ProgramLog(log) | LogEvent::ProgramPlainLog(log) => {
            rekey_program_log(log, key_index);
        }
        LogEvent::ProgramLogError { .. }
        | LogEvent::ProgramAccountNotWritable
        | LogEvent::ProgramIdMismatch
        | LogEvent::ProgramNotUpgradeable
        | LogEvent::ProgramAndProgramDataAccountMismatch
        | LogEvent::ProgramWasExtendedInThisBlockAlready
        | LogEvent::BpfConsumed { .. }
        | LogEvent::FailedToComplete { .. }
        | LogEvent::CustomProgramError { .. }
        | LogEvent::Data { .. }
        | LogEvent::Consumption { .. }
        | LogEvent::CbRequestUnits { .. }
        | LogEvent::UnknownProgram { .. }
        | LogEvent::UnknownAccount { .. }
        | LogEvent::VerifyEd25519
        | LogEvent::VerifySecp256k1
        | LogEvent::LogTruncated
        | LogEvent::StakeMergingAccounts
        | LogEvent::CloseContextState
        | LogEvent::Plain { .. }
        | LogEvent::Unparsed { .. } => {}
    }
}

fn rekey_program_log(log: &mut ProgramLog, key_index: &KeyIndex) {
    match log {
        ProgramLog::Token2022(log) => rekey_token_2022_log(log, key_index),
        ProgramLog::Empty
        | ProgramLog::Token(_)
        | ProgramLog::Ata(_)
        | ProgramLog::AddressLookupTable(_)
        | ProgramLog::LoaderV3(_)
        | ProgramLog::LoaderV4(_)
        | ProgramLog::Memo(_)
        | ProgramLog::Record(_)
        | ProgramLog::TransferHook(_)
        | ProgramLog::AccountCompression(_)
        | ProgramLog::Stake(_)
        | ProgramLog::ZkElgamalProof(_)
        | ProgramLog::AnchorInstruction { .. }
        | ProgramLog::AnchorErrorOccurred { .. }
        | ProgramLog::AnchorErrorThrown { .. }
        | ProgramLog::Unknown(_) => {}
        #[cfg(feature = "known-program-logs")]
        ProgramLog::Known(_) => {}
    }
}

fn rekey_token_2022_log(log: &mut Token2022Log, key_index: &KeyIndex) {
    match log {
        Token2022Log::ErrorHarvestingFrom { account_key, .. }
        | Token2022Log::ErrorHarvestingFrom2 { account_key, .. }
        | Token2022Log::ErrorHarvestingFrom3 { account_key, .. }
        | Token2022Log::ErrorHarvestingFrom4 { account_key, .. } => {
            rekey_compact_pubkey(account_key, key_index);
        }
        Token2022Log::Error(_)
        | Token2022Log::Static(_)
        | Token2022Log::CalculatedFee { .. }
        | Token2022Log::AccountNeedsResizePlusBytesDebug { .. }
        | Token2022Log::AccountNeedsResizePlusBytesDebug2 { .. } => {}
    }
}

fn rekey_system_program_log(log: &mut SystemProgramLog, key_index: &KeyIndex) {
    match log {
        SystemProgramLog::CreateAddressMismatch {
            provided_addr,
            derived_addr,
        }
        | SystemProgramLog::TransferFromAddressMismatch {
            provided_addr,
            derived_addr,
        } => {
            rekey_compact_pubkey(provided_addr, key_index);
            rekey_pubkey_or_string(derived_addr, key_index);
        }
        SystemProgramLog::CreateAccountAlreadyInUse { addr }
        | SystemProgramLog::AllocateAlreadyInUse { addr }
        | SystemProgramLog::AllocateToMustSign { addr }
        | SystemProgramLog::AllocateAccountAlreadyInUse { addr }
        | SystemProgramLog::AssignAccountMustSign { addr }
        | SystemProgramLog::CreateAccountAccountAlreadyInUse { addr } => {
            rekey_system_address(addr, key_index);
        }
        SystemProgramLog::TransferFromMustSign { from } => {
            rekey_compact_pubkey(from, key_index);
        }
        SystemProgramLog::NonceAccountMustBeWriteable { account, .. }
        | SystemProgramLog::NonceAccountMustBeSigner { account, .. }
        | SystemProgramLog::NonceAccountMustSign { account, .. }
        | SystemProgramLog::NonceAccountStateInvalid { account, .. } => {
            rekey_pubkey_or_string(account, key_index);
        }
        SystemProgramLog::Instruction(_)
        | SystemProgramLog::AllocateRequestedTooLarge { .. }
        | SystemProgramLog::CreateAccountDataSizeLimitedInInnerInstructions { .. }
        | SystemProgramLog::TransferFromMustNotCarryData
        | SystemProgramLog::TransferInsufficient { .. }
        | SystemProgramLog::AdvanceNonceRecentBlockhashesEmpty
        | SystemProgramLog::InitializeNonceRecentBlockhashesEmpty
        | SystemProgramLog::AuthorizeNonceAccount { .. }
        | SystemProgramLog::NonceInsufficientLamports { .. }
        | SystemProgramLog::NonceCanOnlyAdvanceOncePerSlot { .. } => {}
    }
}

fn rekey_system_address(address: &mut SystemAddress, key_index: &KeyIndex) {
    match address {
        SystemAddress::Pubkey(pubkey) => rekey_pubkey_or_string(pubkey, key_index),
        SystemAddress::Debug { address, base } => {
            rekey_pubkey_or_string(address, key_index);
            if let Some(base) = base {
                rekey_pubkey_or_string(base, key_index);
            }
        }
    }
}

fn rekey_pubkey_or_string(value: &mut PubkeyOrString, key_index: &KeyIndex) {
    if let PubkeyOrString::Pubkey(pubkey) = value {
        rekey_compact_pubkey(pubkey, key_index);
    }
}

fn rekey_compact_pubkey(pubkey: &mut CompactPubkey, key_index: &KeyIndex) {
    let CompactPubkey::Raw(raw) = pubkey else {
        return;
    };
    if let Some(id) = key_index.lookup(raw) {
        *pubkey = CompactPubkey::id(id);
    }
}

fn optimize_no_registry_token_balance(
    balance: WincodeArchiveV2NoRegistryTokenBalance,
    key_index: &KeyIndex,
) -> Result<CompactTokenBalance> {
    Ok(CompactTokenBalance {
        account_index: balance.account_index,
        mint: balance
            .mint
            .map(|key| compact_required(key_index, &key, "token balance mint"))
            .transpose()?,
        owner: balance
            .owner
            .map(|key| compact_required(key_index, &key, "token balance owner"))
            .transpose()?,
        program_id: balance
            .program_id
            .map(|key| compact_required(key_index, &key, "token balance program id"))
            .transpose()?,
        amount: balance.amount,
        decimals: balance.decimals,
    })
}

fn optimize_no_registry_reward(
    reward: &WincodeArchiveV2NoRegistryReward,
    key_index: &KeyIndex,
) -> Result<CompactReward> {
    Ok(CompactReward {
        pubkey: compact_required(key_index, &reward.pubkey, "reward pubkey")?,
        lamports: reward.lamports,
        post_balance: reward.post_balance,
        reward_type: reward.reward_type,
        commission: reward.commission,
    })
}

fn optimize_no_registry_rewards(
    rewards: &WincodeArchiveV2NoRegistryRewards,
    key_index: &KeyIndex,
) -> Result<WincodeArchiveV2Rewards> {
    anyhow::ensure!(
        rewards.raw_fallback.is_none() && rewards.decode_error.is_none(),
        "raw rewards fallback in no-registry archive"
    );
    let Some(decoded) = &rewards.decoded else {
        anyhow::bail!("rewards record present without decoded rewards");
    };
    Ok(WincodeArchiveV2Rewards {
        source_len: rewards.source_len,
        num_partitions: rewards.num_partitions,
        decoded: Some(
            decoded
                .iter()
                .map(|reward| optimize_no_registry_reward(reward, key_index))
                .collect::<Result<Vec<_>>>()?,
        ),
        raw_fallback: None,
        decode_error: None,
    })
}

fn compact_required_keys(
    key_index: &KeyIndex,
    keys: &[[u8; 32]],
    label: &str,
) -> Result<Vec<CompactPubkey>> {
    keys.iter()
        .map(|key| compact_required(key_index, key, label))
        .collect()
}

fn compact_required(key_index: &KeyIndex, key: &[u8; 32], label: &str) -> Result<CompactPubkey> {
    key_index
        .lookup(key)
        .map(CompactPubkey::id)
        .ok_or_else(|| anyhow!("pubkey registry missing {label}: {}", hex32(key)))
}

fn resolve_recent_blockhash(
    rolling_blockhashes: &RollingBlockhashIndex,
    hash: &[u8; 32],
    slot: u64,
    tx_index: usize,
    nonce_recent_blockhashes: &mut u64,
) -> Result<OwnedCompactRecentBlockhash> {
    let resolved = rolling_blockhashes.resolve_or_nonce(hash, slot, tx_index)?;
    if matches!(resolved, OwnedCompactRecentBlockhash::Nonce(_)) {
        *nonce_recent_blockhashes += 1;
    }
    Ok(resolved)
}

struct RollingBlockhashIndex {
    max_entries: usize,
    map: GxHashMap<[u8; 32], (i32, u64)>,
    order: VecDeque<RollingBlockhashEntry>,
}

/// Staged Archive V2 stores recent blockhashes as producing block ids when they
/// are in the live blockhash window. Durable nonce values are stored inline as
/// raw 32-byte hashes and counted in the footer for later nonce-account checks.
#[derive(Clone, Copy)]
struct RollingBlockhashEntry {
    hash: [u8; 32],
    block_id: i32,
    slot: u64,
}

impl RollingBlockhashIndex {
    fn new(max_entries: usize) -> Self {
        Self {
            max_entries,
            map: GxHashMap::with_capacity_and_hasher(max_entries, GxBuildHasher::default()),
            order: VecDeque::with_capacity(max_entries),
        }
    }

    fn seed_previous_tail(&mut self, tail: &[PreviousBlockhash]) -> Result<()> {
        for (index, item) in tail.iter().enumerate() {
            let distance_from_newest =
                i32::try_from(tail.len() - index).context("previous tail exceeds i32::MAX")?;
            self.insert(item.hash, -distance_from_newest, item.slot)?;
        }
        Ok(())
    }

    fn insert(&mut self, hash: [u8; 32], block_id: i32, slot: u64) -> Result<()> {
        anyhow::ensure!(
            !self.map.contains_key(&hash),
            "duplicate blockhash {} at block_id {} slot {}",
            hex32(&hash),
            block_id,
            slot
        );
        self.map.insert(hash, (block_id, slot));
        self.order.push_back(RollingBlockhashEntry {
            hash,
            block_id,
            slot,
        });
        self.enforce_capacity();
        Ok(())
    }

    fn prune_for_slot(&mut self, current_slot: u64) -> Result<()> {
        loop {
            let Some(entry) = self.order.front().copied() else {
                return Ok(());
            };
            anyhow::ensure!(
                entry.slot <= current_slot,
                "block slots went backwards: rolling blockhash slot {} is ahead of current slot {}",
                entry.slot,
                current_slot
            );
            if current_slot - entry.slot <= RECENT_BLOCKHASH_SLOT_WINDOW {
                return Ok(());
            }
            self.remove_front();
        }
    }

    fn enforce_capacity(&mut self) {
        while self.order.len() > self.max_entries {
            self.remove_front();
        }
    }

    fn remove_front(&mut self) {
        if let Some(old) = self.order.pop_front()
            && self.map.get(&old.hash).copied() == Some((old.block_id, old.slot))
        {
            self.map.remove(&old.hash);
        }
    }

    fn resolve_or_nonce(
        &self,
        hash: &[u8; 32],
        slot: u64,
        tx_index: usize,
    ) -> Result<OwnedCompactRecentBlockhash> {
        let Some((block_id, hash_slot)) = self.map.get(hash).copied() else {
            return Ok(OwnedCompactRecentBlockhash::Nonce(*hash));
        };
        anyhow::ensure!(
            hash_slot <= slot,
            "slot {slot} tx#{tx_index} recent_blockhash {} points at future block slot {}",
            hex32(hash),
            hash_slot
        );
        if slot - hash_slot > RECENT_BLOCKHASH_SLOT_WINDOW {
            return Ok(OwnedCompactRecentBlockhash::Nonce(*hash));
        }
        Ok(OwnedCompactRecentBlockhash::Id(block_id))
    }
}

struct ArchivePubkeyCounter {
    counts: GxHashMap<[u8; 32], u32>,
}

impl ArchivePubkeyCounter {
    fn new(capacity: usize) -> Self {
        Self {
            counts: GxHashMap::with_capacity_and_hasher(capacity, GxBuildHasher::default()),
        }
    }

    fn add32(&mut self, key: &[u8; 32]) {
        let count = self.counts.entry(*key).or_insert(0);
        *count = count.saturating_add(1);
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[derive(Default)]
struct ArchiveV2Timings {
    detailed: bool,
    scan_decode_node: Duration,
    classify: Duration,
    dataframe_assemble: Duration,
    tx_decode_compact: Duration,
    metadata_decode_compact: Duration,
    parallel_decode_wall: Duration,
    metadata_logs_decode_compact: Duration,
    metadata_pubkey_compact: Duration,
    rewards_decode_compact: Duration,
    wincode_encode: Duration,
    hot_message_build: Duration,
    hot_message_encode: Duration,
    hot_metadata_encode: Duration,
    hot_signature_write: Duration,
    hot_block_serialize: Duration,
    hot_zstd_compress: Duration,
    hot_block_write: Duration,
    hot_poh_write: Duration,
    tx_reassembled: u64,
    metadata_reassembled: u64,
    metadata_protobuf_visit: u64,
    metadata_owned_fallback: u64,
    tx_scratch_max: usize,
    metadata_scratch_max: usize,
    hot_zstd_buffer_reserves: u64,
    hot_zstd_buffer_capacity_max: usize,
}

impl ArchiveV2Timings {
    fn from_env() -> Self {
        Self {
            detailed: detailed_timings_enabled(),
            ..Self::default()
        }
    }

    #[inline]
    fn detail_timer(&self) -> DetailTimer {
        DetailTimer::start(self.detailed)
    }

    #[inline]
    fn optional_detail_timer(timings: Option<&Self>) -> DetailTimer {
        DetailTimer::start(timings.is_some_and(|timings| timings.detailed))
    }
}

const DETAILED_TIMINGS_ENV: &str = "BLOCKZILLA_DETAILED_TIMINGS";
const RECENT_BLOCKHASH_SLOT_WINDOW: u64 = 150;
fn detailed_timings_enabled_from_value(value: Option<&str>) -> bool {
    matches!(value, Some("1"))
}

pub(crate) fn detailed_timings_enabled() -> bool {
    detailed_timings_enabled_from_value(std::env::var(DETAILED_TIMINGS_ENV).ok().as_deref())
}

pub(crate) struct DetailTimer(Option<Instant>);

impl DetailTimer {
    #[inline]
    pub(crate) fn start(enabled: bool) -> Self {
        Self(enabled.then(Instant::now))
    }

    #[inline]
    pub(crate) fn elapsed(&self) -> Duration {
        self.0.as_ref().map_or(Duration::ZERO, Instant::elapsed)
    }
}

fn read_pubkey_count_record(reader: &mut impl Read) -> Result<Option<PubkeyCountRecord>> {
    let mut key = [0u8; 32];
    let read = reader.read(&mut key)?;
    if read == 0 {
        return Ok(None);
    }
    if read < key.len() {
        reader.read_exact(&mut key[read..])?;
    }
    let mut count_bytes = [0u8; 4];
    reader.read_exact(&mut count_bytes)?;
    Ok(Some(PubkeyCountRecord {
        key,
        count: u32::from_le_bytes(count_bytes),
    }))
}

fn trim_hot_reusable_buffer(buf: &mut Vec<u8>) {
    let _ = release_hot_reusable_buffer(buf);
}

fn trim_hot_reusable_vec<T>(buf: &mut Vec<T>) {
    buf.clear();
    let retain_limit = HOT_REUSABLE_BUFFER_RETAIN_LIMIT / std::mem::size_of::<T>().max(1);
    if buf.capacity() > retain_limit {
        *buf = Vec::with_capacity(retain_limit);
    }
}

fn vote_program_id_bytes() -> [u8; 32] {
    solana_pubkey::pubkey!("Vote111111111111111111111111111111111111111").to_bytes()
}

fn compute_budget_program_id_bytes() -> [u8; 32] {
    solana_pubkey::pubkey!("ComputeBudget111111111111111111111111111111").to_bytes()
}

fn system_program_id_bytes() -> [u8; 32] {
    solana_pubkey::pubkey!("11111111111111111111111111111111").to_bytes()
}

const LIVE_PUBKEY_RUN_READER_BUFFER_SIZE: usize = 64 << 10;

pub(crate) fn load_blockhash_registry_plain(path: &Path) -> Result<Vec<[u8; 32]>> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let bytes = file
        .metadata()
        .with_context(|| format!("stat {}", path.display()))?
        .len();
    if bytes % 32 != 0 {
        anyhow::bail!(
            "invalid blockhash registry length: {} (not multiple of 32) path={}",
            bytes,
            path.display()
        );
    }
    let count = usize::try_from(bytes / 32).context("blockhash registry length exceeds usize")?;
    let mut reader = BufReader::with_capacity(8 << 20, file);
    let mut hashes = Vec::with_capacity(count);
    for _ in 0..count {
        let mut hash = [0u8; 32];
        reader
            .read_exact(&mut hash)
            .with_context(|| format!("read {}", path.display()))?;
        hashes.push(hash);
    }
    Ok(hashes)
}
