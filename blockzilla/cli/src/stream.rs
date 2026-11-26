//! User-facing epoch scan. Archive discovery, cache binding, and ordered
//! decoding stay in the dedicated Compact V2 reader.

use std::{io::Write, num::NonZeroU32, path::PathBuf, time::Instant};

use anyhow::{Context, Result};
use blockzilla_compact_v2_reader::archive::{
    ArchiveInstructionSource, BlockSink, BlockView, CompactV2Archive, CompactV2LocalDescriptor,
    CompactV2ParallelScanConfig, QueryError, QueryResult, ScanRequest,
};
use clap::Args;
use serde::Serialize;

#[derive(Args, Debug)]
pub(crate) struct StreamArgs {
    #[command(flatten)]
    pub source: EpochSourceArgs,
}

#[derive(Args, Debug)]
pub(crate) struct EpochSourceArgs {
    /// Epoch to read from the public Foundation archive.
    #[arg(long)]
    pub epoch: u64,
    /// Compatible HTTPS archive origin. Omit it to read the public Foundation bucket.
    #[arg(long, env = "BLOCKZILLA_ORIGIN", conflicts_with = "archive_dir")]
    pub origin: Option<String>,
    /// Public HTTPS epoch directory. Omit `--archive-url` and `--origin` to read
    /// `https://pub-97348740d6ef467aa2f1b4b62daa98dc.r2.dev/compact-v2/blockzilla-20261004/epoch-<EPOCH>`.
    #[arg(long, env = "BLOCKZILLA_ARCHIVE_URL", conflicts_with_all = ["origin", "archive_dir"])]
    pub archive_url: Option<String>,
    /// Sign requests to --archive-url for a private S3-compatible bucket in this
    /// region (`auto` for Cloudflare R2). Credentials come from
    /// AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and the optional
    /// AWS_SESSION_TOKEN.
    #[arg(long, requires = "archive_url")]
    pub s3_region: Option<String>,
    /// Cache directory. Relative paths are resolved from the current directory.
    #[arg(long, default_value = ".blockzilla-cache")]
    pub cache_root: PathBuf,
    /// Read this local epoch directory instead of the HTTPS source.
    #[arg(long, requires = "source_id")]
    pub archive_dir: Option<PathBuf>,
    /// Stable ID for a local archive build. Change it when you replace that build.
    #[arg(long, requires = "archive_dir")]
    pub source_id: Option<String>,
    /// Concurrent block reads for --archive-dir. Use several on a NAS or disk
    /// array; 1 reads one range at a time.
    #[arg(long, default_value_t = 1, requires = "archive_dir", value_parser = clap::value_parser!(u16).range(1..=64))]
    pub read_concurrency: u16,
    /// Decode workers (1 through 64).
    #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u16).range(1..=64))]
    pub threads: u16,
    /// First block row to read. Use the next row after a saved checkpoint to
    /// resume a stream.
    #[arg(long, default_value_t = 0)]
    pub first_block: u32,
    /// Read at most this many block rows. Omit to stream all admitted rows.
    #[arg(long)]
    pub max_blocks: Option<NonZeroU32>,
}

#[derive(Serialize)]
struct BlockSummary {
    epoch: u64,
    block_ordinal: u32,
    slot: u64,
    transactions: u64,
}

struct JsonSink<W> {
    output: W,
    started: Instant,
    last_report: Instant,
    expected_blocks: u64,
    blocks: u64,
    transactions: u64,
}

impl<W: Write> BlockSink for JsonSink<W> {
    fn visit_block(&mut self, block: BlockView<'_>) -> QueryResult<()> {
        let transactions = block
            .counts
            .map_or(block.transactions.len() as u64, |counts| {
                counts.transactions
            });
        let row = BlockSummary {
            epoch: block.header.epoch,
            block_ordinal: block.header.block_ordinal,
            slot: block.header.slot,
            transactions,
        };
        serde_json::to_writer(&mut self.output, &row).map_err(QueryError::sink)?;
        self.output.write_all(b"\n").map_err(QueryError::sink)?;
        // Make the completed block visible immediately to a downstream pipe.
        self.output.flush().map_err(QueryError::sink)?;
        self.blocks += 1;
        self.transactions += transactions;
        if self.last_report.elapsed().as_secs() >= 3 {
            eprintln!(
                "Read {}/{} blocks, {} transactions in {:.1}s",
                self.blocks,
                self.expected_blocks,
                self.transactions,
                self.started.elapsed().as_secs_f64(),
            );
            self.last_report = Instant::now();
        }
        Ok(())
    }
}

pub(crate) fn open(args: &EpochSourceArgs) -> Result<CompactV2Archive> {
    eprintln!("Opening epoch {}...", args.epoch);
    let archive = if let Some(root) = &args.archive_dir {
        let root = std::fs::canonicalize(&root)
            .with_context(|| format!("Cannot open archive directory {}", root.display()))?;
        let source_id = args
            .source_id
            .as_deref()
            .context("Local reads require --source-id")?;
        let descriptor = CompactV2LocalDescriptor::mainnet(args.epoch, source_id)?;
        CompactV2Archive::open_local_with_read_concurrency(
            root,
            descriptor,
            usize::from(args.read_concurrency),
        )?
    } else {
        let cache_root = if args.cache_root.is_absolute() {
            args.cache_root.clone()
        } else {
            std::env::current_dir()?.join(&args.cache_root)
        };
        if let Some(epoch_url) = &args.archive_url {
            eprintln!("Source: {epoch_url}\nPreparing archive index and key registry...");
            match &args.s3_region {
                Some(region) => {
                    let signer = blockzilla_compact_v2_reader::S3SigV4Signer::new(
                        blockzilla_compact_v2_reader::S3Credentials::from_env()?,
                        region.as_str(),
                    )?;
                    CompactV2Archive::open_signed_epoch_url(
                        epoch_url,
                        args.epoch,
                        cache_root,
                        std::sync::Arc::new(signer),
                    )
                }
                None => CompactV2Archive::open_epoch_url(epoch_url, args.epoch, cache_root),
            }
            .with_context(|| format!("Cannot open epoch {} at {epoch_url}", args.epoch))?
        } else if let Some(origin) = args.origin.as_deref() {
            eprintln!("Source: {origin}\nPreparing archive index and key registry...");
            CompactV2Archive::open(origin, args.epoch, cache_root)
                .with_context(|| format!("Cannot open epoch {} at {origin}", args.epoch))?
        } else {
            let epoch_url = blockzilla::public_epoch_url(args.epoch);
            eprintln!("Source: {epoch_url}\nPreparing archive index and key registry...");
            CompactV2Archive::open_epoch_url(&epoch_url, args.epoch, cache_root)
                .with_context(|| format!("Cannot open epoch {} at {epoch_url}", args.epoch))?
        }
    };
    Ok(archive)
}

/// Parallel scan settings for the selected source. With `--read-concurrency`
/// above 1, a local archive keeps that many block reads in flight.
pub(crate) fn parallel_config(args: &EpochSourceArgs) -> CompactV2ParallelScanConfig {
    let mut config = CompactV2ParallelScanConfig::new(usize::from(args.threads));
    if args.archive_dir.is_some()
        && args.read_concurrency > 1
        && let Some(input) = config.network_input.as_mut()
    {
        input.workers = usize::from(args.read_concurrency);
    }
    config
}

pub(crate) fn request(archive: &CompactV2Archive, args: &EpochSourceArgs) -> Result<ScanRequest> {
    Ok(match (args.first_block, args.max_blocks) {
        (0, None) => ScanRequest::all(),
        (first_block, limit) => ScanRequest::bounded(
            archive.bounded_range(first_block, limit.unwrap_or(NonZeroU32::MAX))?,
        ),
    })
}

pub(crate) fn run(args: StreamArgs) -> Result<()> {
    let started = Instant::now();
    let args = args.source;
    let mut archive = open(&args)?;
    let request = request(&archive, &args)?
        .without_instructions()
        .without_primary_signatures()
        .without_required_signers()
        .without_execution_status();
    let expected_blocks = request
        .range
        .map_or(u64::from(archive.identity().block_count), |range| {
            u64::from(range.block_count.get())
        });
    eprintln!("Streaming {expected_blocks} blocks. JSON summaries go to stdout.");
    let stdout = std::io::stdout();
    let mut sink = JsonSink {
        output: stdout.lock(),
        started,
        last_report: Instant::now(),
        expected_blocks,
        blocks: 0,
        transactions: 0,
    };
    let receipt = archive.scan_ordered_parallel(&request, &mut sink, parallel_config(&args))?;
    archive.verify_local_unchanged()?;
    anyhow::ensure!(
        receipt.scan.blocks == expected_blocks
            && receipt.scan.blocks == sink.blocks
            && receipt.scan.transactions == sink.transactions,
        "Stream counts do not match the selected archive rows",
    );
    eprintln!(
        "Stream complete: {} blocks, {} transactions in {:.1}s",
        receipt.scan.blocks,
        receipt.scan.transactions,
        started.elapsed().as_secs_f64(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use blockzilla_model::{BlockHeader, CanonicalTransaction};

    #[test]
    fn summaries_include_empty_blocks_and_keep_one_json_record_per_line() {
        let now = Instant::now();
        let mut sink = JsonSink {
            output: Vec::new(),
            started: now,
            last_report: now,
            expected_blocks: 1,
            blocks: 0,
            transactions: 0,
        };
        let transactions: Vec<CanonicalTransaction> = Vec::new();
        sink.visit_block(BlockView {
            counts: None,
            header: BlockHeader {
                epoch: 900,
                block_ordinal: 7,
                slot: 388_800_010,
            },
            transactions: &transactions,
        })
        .unwrap();
        assert_eq!(sink.blocks, 1);
        assert_eq!(sink.transactions, 0);
        assert_eq!(
            std::str::from_utf8(&sink.output).unwrap(),
            "{\"epoch\":900,\"block_ordinal\":7,\"slot\":388800010,\"transactions\":0}\n"
        );
    }
}
