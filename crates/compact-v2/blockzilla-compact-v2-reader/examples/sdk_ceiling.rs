//! Measure whether the SDK or the input limits a scan on this machine.
//!
//! RUSTFLAGS='-C target-cpu=native' cargo run --release -p blockzilla-compact-v2-reader --features http --example sdk_ceiling -- \
//!   --archive-dir /data/epoch-200 --source-id my-build --epoch 200 --first-block 150000 --max-blocks 1000
//!
//! or, for an HTTPS epoch directory:
//!
//! RUSTFLAGS='-C target-cpu=native' cargo run --release -p blockzilla-compact-v2-reader --features http --example sdk_ceiling -- \
//!   --url https://pub-97348740d6ef467aa2f1b4b62daa98dc.r2.dev/compact-v2/blockzilla-20261004/epoch-1094 --cache-dir /tmp/bz-cache --epoch 1094 --max-blocks 1000
//!
//! Legs, on the same block-row range:
//! - `input`: only read the compressed bytes of the range, with the same request
//!   size and concurrency as the parallel scan. This is the input ceiling.
//! - `parallel`: `scan_ordered_parallel` with a sink that only counts rows.
//!   This is the SDK ceiling for the request.
//! - `sequential`: `scan_ordered` with the same counting sink, as a baseline.
//!
//! Each leg prints one JSON line. The `parallel` line also gives the pipeline
//! stage times. When `parallel` reaches about the `input` rate, the input limits
//! the scan; when it is clearly lower and the workers are busy, decode and
//! projection limit it and more cores help. A sink that is slower than the
//! `parallel` leg is the application's limit, not the SDK's.

use std::{
    env,
    num::NonZeroU32,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use blockzilla_compact_v2_reader::{
    CompactV2ParallelScanConfig, HttpObjectPathLayout, HttpRangeSource, HttpRangeSourceOptions,
    NetworkInputConfig, PinnedLocalRangeSource, RangeSource,
    archive::{
        ArchiveInstructionSource, BlockSink, BlockView, CompactV2Archive, CompactV2LocalDescriptor,
        QueryResult, ScanRequest,
    },
};
use serde_json::json;

const USAGE: &str = "usage: sdk_ceiling (--archive-dir DIR --source-id ID | --url URL --cache-dir DIR) \
    --epoch N [--first-block N] [--max-blocks N] [--workers N] [--input-requests N] \
    [--range-mib N] [--read-concurrency N] [--request token|signers] [--skip-sequential]";

const INDEX_FILE: &str = "archive-v2-blocks.index";
const BLOCKS_FILE: &str = "archive-v2-blocks.zstd";
const INDEX_HEADER_BYTES: usize = 36;
const INDEX_ROW_BYTES: usize = 52;

struct Options {
    archive_dir: Option<PathBuf>,
    source_id: Option<String>,
    url: Option<String>,
    cache_dir: Option<PathBuf>,
    epoch: u64,
    first_block: u32,
    max_blocks: Option<NonZeroU32>,
    workers: usize,
    input_requests: usize,
    range_bytes: usize,
    read_concurrency: usize,
    request: String,
    skip_sequential: bool,
}

fn options() -> Result<Options> {
    let defaults = NetworkInputConfig::default();
    let mut options = Options {
        archive_dir: None,
        source_id: None,
        url: None,
        cache_dir: None,
        epoch: u64::MAX,
        first_block: 0,
        max_blocks: None,
        workers: std::thread::available_parallelism().map_or(1, usize::from),
        input_requests: defaults.workers,
        range_bytes: defaults.range_bytes,
        read_concurrency: 6,
        request: "token".into(),
        skip_sequential: false,
    };
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--skip-sequential" {
            options.skip_sequential = true;
            continue;
        }
        let value = args
            .next()
            .with_context(|| format!("missing value for {arg}\n{USAGE}"))?;
        match arg.as_str() {
            "--archive-dir" => options.archive_dir = Some(value.into()),
            "--source-id" => options.source_id = Some(value),
            "--url" => options.url = Some(value),
            "--cache-dir" => options.cache_dir = Some(value.into()),
            "--epoch" => options.epoch = value.parse()?,
            "--first-block" => options.first_block = value.parse()?,
            "--max-blocks" => options.max_blocks = Some(value.parse()?),
            "--workers" => options.workers = value.parse()?,
            "--input-requests" => options.input_requests = value.parse()?,
            "--range-mib" => options.range_bytes = value.parse::<usize>()? << 20,
            "--read-concurrency" => options.read_concurrency = value.parse()?,
            "--request" => options.request = value,
            _ => bail!("unknown option {arg}\n{USAGE}"),
        }
    }
    ensure!(options.epoch != u64::MAX, "--epoch is required\n{USAGE}");
    ensure!(
        options.archive_dir.is_some() != options.url.is_some(),
        "give --archive-dir or --url\n{USAGE}"
    );
    ensure!(options.workers > 0 && options.input_requests > 0 && options.range_bytes > 0);
    Ok(options)
}

/// The byte source that the `input` leg reads, with no reader on top.
fn raw_source(options: &Options) -> Result<Box<dyn RangeSource>> {
    Ok(match (&options.archive_dir, &options.url) {
        (Some(directory), None) => Box::new(PinnedLocalRangeSource::new_anchored(
            directory,
            &[INDEX_FILE, BLOCKS_FILE],
        )?),
        (None, Some(url)) => Box::new(HttpRangeSource::with_options(
            url.trim_end_matches('/'),
            options.epoch,
            None,
            HttpRangeSourceOptions {
                object_path_layout: HttpObjectPathLayout::FlatObjects,
                ..HttpRangeSourceOptions::default()
            },
        )?),
        _ => unreachable!("checked in options"),
    })
}

fn open_archive(options: &Options) -> Result<CompactV2Archive> {
    Ok(match (&options.archive_dir, &options.url) {
        (Some(directory), None) => CompactV2Archive::open_local_with_read_concurrency(
            directory.canonicalize()?,
            CompactV2LocalDescriptor::mainnet(
                options.epoch,
                options
                    .source_id
                    .clone()
                    .context("--source-id is required with --archive-dir")?,
            )?,
            options.read_concurrency,
        )?,
        (None, Some(url)) => CompactV2Archive::open_epoch_url(
            url,
            options.epoch,
            options
                .cache_dir
                .clone()
                .context("--cache-dir is required with --url")?,
        )?,
        _ => unreachable!("checked in options"),
    })
}

/// Byte span `[start, end)` of the compressed blocks for the selected rows.
fn block_span(source: &dyn RangeSource, first: u32, count: u32) -> Result<(u64, u64)> {
    let index_size = source.size(INDEX_FILE)?.context("block index is absent")?;
    let rows = (index_size as usize - INDEX_HEADER_BYTES) / INDEX_ROW_BYTES;
    ensure!(
        INDEX_HEADER_BYTES + rows * INDEX_ROW_BYTES == index_size as usize,
        "unexpected block index length"
    );
    let row = |number: u32| -> Result<(u64, u64)> {
        let offset = INDEX_HEADER_BYTES as u64 + u64::from(number) * INDEX_ROW_BYTES as u64;
        let bytes = source.read_range(INDEX_FILE, offset, INDEX_ROW_BYTES)?;
        let compressed_offset = u64::from_le_bytes(bytes[12..20].try_into()?);
        let compressed_len = u32::from_le_bytes(bytes[20..24].try_into()?);
        Ok((compressed_offset, u64::from(compressed_len)))
    };
    ensure!(
        count > 0 && (first as usize) + (count as usize) <= rows,
        "range outside index"
    );
    let (start, _) = row(first)?;
    let (last_offset, last_length) = row(first + count - 1)?;
    Ok((start, last_offset + last_length))
}

/// Read `[start, end)` in `range_bytes` requests with `requests` threads.
fn read_span(
    source: &dyn RangeSource,
    start: u64,
    end: u64,
    range_bytes: usize,
    requests: usize,
) -> Result<(u64, Duration)> {
    let chunks: Vec<(u64, usize)> = (start..end)
        .step_by(range_bytes)
        .map(|offset| (offset, (end - offset).min(range_bytes as u64) as usize))
        .collect();
    let next = AtomicUsize::new(0);
    let started = Instant::now();
    let total = std::thread::scope(|scope| -> Result<u64> {
        let handles: Vec<_> = (0..requests.min(chunks.len()).max(1))
            .map(|_| {
                scope.spawn(|| -> Result<u64> {
                    let mut bytes = Vec::new();
                    let mut read = 0;
                    loop {
                        let Some(&(offset, length)) =
                            chunks.get(next.fetch_add(1, Ordering::Relaxed))
                        else {
                            return Ok(read);
                        };
                        source.read_range_into(BLOCKS_FILE, offset, length, &mut bytes)?;
                        read += bytes.len() as u64;
                    }
                })
            })
            .collect();
        let mut total = 0;
        for handle in handles {
            total += handle.join().expect("input reader panicked")?;
        }
        Ok(total)
    })?;
    Ok((total, started.elapsed()))
}

/// Counts rows and transactions; does no other work.
#[derive(Default)]
struct CountingSink {
    blocks: u64,
    transactions: u64,
    rows: u64,
}

impl BlockSink for CountingSink {
    fn visit_block(&mut self, block: BlockView<'_>) -> QueryResult<()> {
        self.blocks += 1;
        for transaction in block.transaction_views() {
            self.transactions += 1;
            self.rows += transaction.token_balances.len() as u64;
        }
        Ok(())
    }
}

fn rates(bytes: u64, blocks: u64, transactions: u64, elapsed: Duration) -> serde_json::Value {
    let seconds = elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
    json!({
        "seconds": seconds,
        "compressed_mib_per_second": bytes as f64 / (1 << 20) as f64 / seconds,
        "blocks_per_second": blocks as f64 / seconds,
        "transactions_per_second": transactions as f64 / seconds,
    })
}

fn main() -> Result<()> {
    let options = options()?;
    let request = match options.request.as_str() {
        "token" => ScanRequest::token_balances_only(),
        // The common mistake: all() keeps signatures and signers.
        "signers" => ScanRequest::all()
            .without_instructions()
            .with_token_balances(),
        other => bail!("unknown --request {other}; use token or signers"),
    };
    let mut archive = open_archive(&options)?;
    let range = archive.bounded_range(
        options.first_block,
        options.max_blocks.unwrap_or(NonZeroU32::MAX),
    )?;
    let request = ScanRequest {
        range: Some(range),
        ..request
    };

    let source = raw_source(&options)?;
    let (start, end) = block_span(source.as_ref(), range.first_block, range.block_count.get())?;
    let input_requests = if options.url.is_some() {
        options.input_requests
    } else {
        options.read_concurrency.max(1)
    };
    // One warm-up pass so the local page cache or the network path is in the
    // same state for every leg.
    read_span(
        source.as_ref(),
        start,
        end,
        options.range_bytes,
        input_requests,
    )?;
    let (bytes, elapsed) = read_span(
        source.as_ref(),
        start,
        end,
        options.range_bytes,
        input_requests,
    )?;
    let blocks = u64::from(range.block_count.get());
    let input = rates(bytes, blocks, 0, elapsed);
    println!(
        "{}",
        json!({"leg": "input", "requests_in_flight": input_requests,
               "range_bytes": options.range_bytes, "bytes": bytes, "rates": input})
    );

    let mut config = CompactV2ParallelScanConfig::new(options.workers);
    if let Some(network) = config.network_input.as_mut() {
        network.workers = input_requests;
        network.range_bytes = options.range_bytes;
    }
    let mut sink = CountingSink::default();
    let started = Instant::now();
    let receipt = archive.scan_ordered_parallel(&request, &mut sink, config)?;
    let elapsed = started.elapsed();
    let pipeline = receipt.pipeline;
    let parallel = rates(
        pipeline.compressed_bytes,
        sink.blocks,
        sink.transactions,
        elapsed,
    );
    let wall = elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
    let workers = receipt.effective_workers.max(1) as f64;
    println!(
        "{}",
        json!({
            "leg": "parallel", "workers": options.workers, "rows": sink.rows,
            "rates": parallel,
            "share_of_input_rate": parallel["compressed_mib_per_second"].as_f64().unwrap_or(0.0)
                / input["compressed_mib_per_second"].as_f64().unwrap_or(f64::MAX),
            "decode_worker_busy": (pipeline.worker_decompress_decode_sum_time
                + pipeline.worker_projection_sum_time).as_secs_f64() / (workers * wall),
            "ordered_consumer_busy": (receipt.signature_read_wall_time
                + receipt.signature_assign_wall_time
                + receipt.publish_wall_time).as_secs_f64() / wall,
            "consumer_wait_for_workers": pipeline.coordinator_wait_for_projection_buffer_time.as_secs_f64() / wall,
            "input_wait_for_free_buffer": pipeline.producer_wait_for_free_buffer_time.as_secs_f64() / wall,
            "source_read_bytes": receipt.scan.io.source_read_bytes,
        })
    );

    if !options.skip_sequential {
        let mut sink = CountingSink::default();
        let started = Instant::now();
        let receipt = archive.scan_ordered(&request, &mut sink)?;
        let elapsed = started.elapsed();
        let bytes = receipt.io.decoded_bytes.unwrap_or(0);
        println!(
            "{}",
            json!({"leg": "sequential", "rows": sink.rows,
                   "rates": rates(pipeline.compressed_bytes, sink.blocks, sink.transactions, elapsed),
                   "decoded_bytes": bytes})
        );
    }
    Ok(())
}

#[allow(dead_code)]
fn _assert_send(_: Arc<dyn RangeSource + Send + Sync>) {}
