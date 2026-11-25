//! Measure exact block reads and a bounded sequential scan on a local Compact V2 archive.
//!
//! cargo run --release --locked -p blockzilla-compact-v2-reader --example epoch_scan_sample -- \
//!   --repeats 5 --window-blocks 1024 --workers 4 /path/to/epoch-6 /path/to/epoch-1031
//!
//! A warm-up precedes each set of measurements. The sequential path creates a new
//! cursor per run so it uses the source on every pass even if the OS cache is warm.
//! Index admission and sample selection are outside the timed read paths. When
//! `--workers` is present, each window run also uses ordered parallel decoding.

use std::{
    cmp::Reverse,
    env,
    fmt::Write,
    ops::Range,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{Context, Result, bail, ensure};
use blockzilla_archive_v2::{ArchiveV2HotBlockIndexRow, read_archive_v2_hot_block_index};
use blockzilla_compact_v2_reader::{
    ArchiveReader, COMPACT_V2_OPTIONAL_OBJECTS, COMPACT_V2_REQUIRED_OBJECTS, HashVerification,
    MAX_ORDERED_PARALLEL_DECODE_WORKERS, OpenOptions, OrderedParallelBlockConfig,
    PinnedLocalRangeSource, RangeSource, compact_v2_first_slot, mainnet_identity_for_slot,
    manifest::{BLOCK_INDEX_FILE, GENERATION_MANIFEST_FILE, GENESIS_BIN_FILE},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const USAGE: &str = "Usage: epoch_scan_sample [--list] [--repeats N] [--window-blocks N] [--workers N] \
    [--sample-rows MIN,MEAN,MAX] EPOCH_DIR [EPOCH_DIR ...]";

struct Options {
    paths: Vec<PathBuf>,
    list: bool,
    repeats: usize,
    window_blocks: usize,
    workers: Option<usize>,
    sample_rows: Option<[usize; 3]>,
}

fn arguments() -> Result<Option<Options>> {
    let mut options = Options {
        paths: Vec::new(),
        list: false,
        repeats: 5,
        window_blocks: 1024,
        workers: None,
        sample_rows: None,
    };
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                println!("{USAGE}");
                return Ok(None);
            }
            "--list" => options.list = true,
            "--repeats" | "--window-blocks" | "--sample-rows" | "--workers" => {
                let value = args
                    .next()
                    .with_context(|| format!("missing value for {arg}"))?;
                match arg.as_str() {
                    "--repeats" => options.repeats = value.parse()?,
                    "--window-blocks" => options.window_blocks = value.parse()?,
                    "--workers" => options.workers = Some(value.parse()?),
                    _ => {
                        let rows = value
                            .split(',')
                            .map(str::parse)
                            .collect::<std::result::Result<Vec<_>, _>>()?;
                        options.sample_rows = Some(rows.try_into().map_err(|_| {
                            anyhow::anyhow!("--sample-rows requires three row numbers")
                        })?);
                    }
                }
            }
            _ if arg.starts_with('-') => bail!("unknown option {arg}\n{USAGE}"),
            _ => options.paths.push(arg.into()),
        }
    }
    ensure!(!options.paths.is_empty(), "{USAGE}");
    ensure!(options.repeats > 0, "--repeats must be greater than zero");
    ensure!(
        options.window_blocks > 0,
        "--window-blocks must be greater than zero"
    );
    ensure!(
        options.sample_rows.is_none() || options.paths.len() == 1,
        "--sample-rows applies to one epoch directory"
    );
    ensure!(
        options
            .workers
            .is_none_or(|workers| (1..=MAX_ORDERED_PARALLEL_DECODE_WORKERS).contains(&workers)),
        "--workers must be between 1 and {MAX_ORDERED_PARALLEL_DECODE_WORKERS}"
    );
    Ok(Some(options))
}

fn open_archive(path: &Path) -> Result<ArchiveReader<PinnedLocalRangeSource>> {
    let names: Vec<_> = COMPACT_V2_REQUIRED_OBJECTS
        .into_iter()
        .chain(COMPACT_V2_OPTIONAL_OBJECTS)
        .chain([GENESIS_BIN_FILE, GENERATION_MANIFEST_FILE])
        .collect();
    let source = PinnedLocalRangeSource::new_anchored(path, &names)?;
    let options = OpenOptions {
        hash_verification: HashVerification::SizesOnly,
        ..OpenOptions::default()
    };
    if source.size(GENERATION_MANIFEST_FILE)?.is_some() {
        return Ok(ArchiveReader::open_with_options(source, options)?);
    }

    let slot = compact_v2_first_slot(&source)?.context("archive index is empty")?;
    let identity = mainnet_identity_for_slot(slot, "local-epoch-scan-sample")?;
    Ok(ArchiveReader::open_pinned(source, identity, options)?)
}

fn select_rows(rows: &[ArchiveV2HotBlockIndexRow]) -> Option<([usize; 3], f64)> {
    let indexed = rows.iter().enumerate();
    let total: u128 = rows.iter().map(|row| u128::from(row.compressed_len)).sum();
    let count = rows.len() as u128;
    let (minimum, _) = indexed
        .clone()
        .min_by_key(|(i, row)| (row.compressed_len, *i))?;
    let (mean, _) = indexed
        .clone()
        .min_by_key(|(i, row)| ((u128::from(row.compressed_len) * count).abs_diff(total), *i))?;
    let (maximum, _) = indexed.min_by_key(|(i, row)| (Reverse(row.compressed_len), *i))?;
    Some(([minimum, mean, maximum], total as f64 / count as f64))
}

fn print_selection(
    path: &Path,
    rows: &[ArchiveV2HotBlockIndexRow],
    options: &Options,
) -> Result<([usize; 3], Range<usize>)> {
    let (selected, mean) = select_rows(rows).context("archive index is empty")?;
    let selected = options.sample_rows.unwrap_or(selected);
    ensure!(
        selected.iter().all(|&row| row < rows.len()),
        "sample row is outside the index"
    );
    let window = options.window_blocks.min(rows.len());
    let start = selected[1]
        .saturating_sub(window / 2)
        .min(rows.len() - window);
    let end = start + window;
    let sample_names = ["minimum", "nearest_mean", "maximum"];
    let samples: Vec<_> = sample_names.into_iter().zip(selected).map(|(name, i)| {
        let row = rows[i];
        json!({"sample": name, "row": i, "slot": row.slot, "compressed_bytes": row.compressed_len,
               "decoded_bytes": row.uncompressed_len, "transactions": row.tx_count})
    }).collect();
    println!(
        "{}",
        json!({
            "kind": "selection", "archive": path, "indexed_blocks": rows.len(),
            "first_slot": rows.first().map(|row| row.slot), "last_slot": rows.last().map(|row| row.slot),
            "mean_compressed_bytes": mean, "sample_rows": selected, "samples": samples,
            "window_start_row": start, "window_end_row_exclusive": end,
        })
    );
    Ok((selected, start..end))
}

struct Measurement {
    blocks: u64,
    transactions: u64,
    read_calls: u64,
    compressed_bytes: u64,
    decoded_bytes: u64,
    seconds: f64,
}

impl Measurement {
    fn same_work(&self, other: &Self) -> bool {
        self.blocks == other.blocks
            && self.transactions == other.transactions
            && self.compressed_bytes == other.compressed_bytes
            && self.decoded_bytes == other.decoded_bytes
    }

    fn report(&self) -> Value {
        json!({
            "blocks": self.blocks, "transactions": self.transactions, "source_read_calls": self.read_calls,
            "compressed_bytes": self.compressed_bytes, "decoded_bytes": self.decoded_bytes,
            "wall_seconds": self.seconds, "wall_milliseconds": self.seconds * 1000.0,
            "compressed_mib_per_second": self.compressed_bytes as f64 / (1 << 20) as f64 / self.seconds,
            "transactions_per_second": self.transactions as f64 / self.seconds,
        })
    }
}

#[derive(Default)]
struct WindowSummary {
    blocks: u64,
    transactions: u64,
    decoded_bytes: u64,
    row_digest: Sha256,
}

impl WindowSummary {
    fn record(&mut self, row: usize, index: ArchiveV2HotBlockIndexRow, transactions: u32) {
        self.blocks += 1;
        self.transactions += u64::from(transactions);
        self.decoded_bytes += u64::from(index.uncompressed_len);

        let mut bytes = [0; 28];
        bytes[..8].copy_from_slice(&(row as u64).to_le_bytes());
        bytes[8..16].copy_from_slice(&index.slot.to_le_bytes());
        bytes[16..20].copy_from_slice(&transactions.to_le_bytes());
        bytes[20..24].copy_from_slice(&index.compressed_len.to_le_bytes());
        bytes[24..28].copy_from_slice(&index.uncompressed_len.to_le_bytes());
        self.row_digest.update(bytes);
    }

    fn finish(self, read_calls: u64, compressed_bytes: u64, seconds: f64) -> (Measurement, String) {
        let measurement = Measurement {
            blocks: self.blocks,
            transactions: self.transactions,
            read_calls,
            compressed_bytes,
            decoded_bytes: self.decoded_bytes,
            seconds,
        };
        let mut digest = String::with_capacity(64);
        for byte in self.row_digest.finalize() {
            write!(digest, "{byte:02x}").expect("writing to a String cannot fail");
        }
        (measurement, digest)
    }
}

fn measure_sequential(
    archive: &ArchiveReader<PinnedLocalRangeSource>,
    window: Range<usize>,
) -> Result<(Measurement, String)> {
    let mut cursor = archive.block_cursor(window)?;
    let mut summary = WindowSummary::default();
    let started = Instant::now();
    while let Some(entry) = cursor.next_block()? {
        summary.record(entry.row, entry.block.index_row, entry.block.tx_count());
    }
    let seconds = started.elapsed().as_secs_f64();
    let io = cursor.io_stats().sequential;
    ensure!(
        summary.decoded_bytes == io.decoded_bytes,
        "sequential decoded bytes differ from the index"
    );
    Ok(summary.finish(io.source_read_calls, io.source_read_bytes, seconds))
}

fn measure_parallel(
    archive: &ArchiveReader<PinnedLocalRangeSource>,
    window: Range<usize>,
    workers: usize,
) -> Result<(Measurement, String, usize)> {
    let config = OrderedParallelBlockConfig {
        decode_workers: workers,
        discard_rewards: true,
        ..OrderedParallelBlockConfig::default()
    };
    let mut summary = WindowSummary::default();
    let started = Instant::now();
    let io = archive.process_borrowed_blocks_parallel_ordered(
        window,
        config,
        |_| Ok::<_, anyhow::Error>(()),
        |_, _, block| Ok((block.index_row, block.tx_count())),
        |row, (index, count)| {
            summary.record(row, index, count);
            Ok(())
        },
    )?;
    let seconds = started.elapsed().as_secs_f64();
    let (measurement, digest) = summary.finish(io.read_call_count, io.compressed_bytes, seconds);
    ensure!(
        measurement.blocks == io.block_count,
        "parallel block count differs from the ordered output"
    );
    Ok((measurement, digest, io.effective_workers))
}

fn benchmark(path: &Path, options: &Options) -> Result<()> {
    if options.list {
        let index = read_archive_v2_hot_block_index(&path.join(BLOCK_INDEX_FILE))?;
        print_selection(path, &index.rows, options)?;
        return Ok(());
    }

    let archive = open_archive(&path.canonicalize()?)?;
    let (selected, window) = print_selection(path, &archive.index().rows, options)?;
    for (name, row) in ["minimum", "nearest_mean", "maximum"]
        .into_iter()
        .zip(selected)
    {
        let mut cursor = archive.block_cursor(row..row + 1)?;
        for repeat in 0..=options.repeats {
            cursor.seek_row(row)?;
            let before = cursor.io_stats().sparse;
            let started = Instant::now();
            let transactions = {
                let entry = cursor
                    .next_matching_block(|_| true)?
                    .context("sample row was not read")?;
                u64::from(entry.block.tx_count())
            };
            let seconds = started.elapsed().as_secs_f64();
            let after = cursor.io_stats().sparse;
            if repeat > 0 {
                let measurement = Measurement {
                    blocks: after.block_count - before.block_count,
                    transactions,
                    read_calls: after.block_count - before.block_count,
                    compressed_bytes: after.compressed_bytes - before.compressed_bytes,
                    decoded_bytes: after.uncompressed_bytes - before.uncompressed_bytes,
                    seconds,
                };
                println!(
                    "{}",
                    json!({"kind": "exact", "archive": path, "epoch": archive.epoch(),
                    "sample": name, "row": row, "repeat": repeat, "measurement": measurement.report()})
                );
            }
        }
    }

    for repeat in 0..=options.repeats {
        let (sequential, digest) = measure_sequential(&archive, window.clone())?;
        if repeat > 0 {
            println!(
                "{}",
                json!({"kind": "sequential", "archive": path, "epoch": archive.epoch(),
                "start_row": window.start, "end_row_exclusive": window.end,
                "repeat": repeat, "row_digest": digest, "measurement": sequential.report()})
            );
        }
        if let Some(workers) = options.workers {
            let (parallel, parallel_digest, effective_workers) =
                measure_parallel(&archive, window.clone(), workers)?;
            ensure!(
                parallel.same_work(&sequential) && parallel_digest == digest,
                "ordered parallel decode does not match sequential decode"
            );
            if repeat > 0 {
                println!(
                    "{}",
                    json!({"kind": "parallel", "archive": path, "epoch": archive.epoch(),
                    "start_row": window.start, "end_row_exclusive": window.end,
                    "repeat": repeat, "row_digest": parallel_digest, "workers": workers,
                    "effective_workers": effective_workers, "measurement": parallel.report()})
                );
            }
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    if let Some(options) = arguments()? {
        for path in &options.paths {
            benchmark(path, &options).with_context(|| format!("benchmark {}", path.display()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chooses_nearest_exact_mean_and_first_row_for_ties() {
        let rows = [6, 2, 4, 2, 6, 4].map(|compressed_len| ArchiveV2HotBlockIndexRow {
            block_id: 0,
            slot: 0,
            compressed_offset: 0,
            compressed_len,
            uncompressed_len: 0,
            tx_count: 0,
            first_tx_ordinal: 0,
            first_signature_ordinal: 0,
            signature_count: 0,
        });
        assert_eq!(select_rows(&rows), Some(([1, 2, 0], 4.0)));
        assert_eq!(select_rows(&rows[..2]), Some(([1, 0, 0], 4.0)));
        assert_eq!(select_rows(&rows[..4]), Some(([1, 2, 0], 3.5)));
        assert!(select_rows(&[]).is_none());
    }
}
