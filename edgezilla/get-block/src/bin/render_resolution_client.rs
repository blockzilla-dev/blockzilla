//! Reconstruct JSON from downloaded files. This command makes no network calls.
use anyhow::{Context, Result, anyhow, ensure};
use blockzilla_get_block::{
    slot_resolution::MAX_RESOLUTION_BYTES,
    worker::client::{
        MAX_PARTS_BYTES, inspect_resolution_parts_workload, render_resolution_parts_json_profiled,
    },
};
use clap::Parser;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};

#[derive(Parser)]
#[command(about = "Render getBlock JSON locally from a resolution index and a parts-v2 frame")]
struct Args {
    #[arg(long)]
    resolution: PathBuf,
    #[arg(long)]
    parts: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    no_rewards: bool,
    /// Repeat the local codec to collect a bounded CPU profile.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=30))]
    iterations: u32,
    /// Save a CPU flamegraph and a sibling .top.tsv sample table.
    #[arg(long)]
    flamegraph_out: Option<PathBuf>,
    /// Count the proof inputs outside the measured renderer.
    #[arg(long)]
    inspect_workload: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(!args.output.exists(), "output already exists");
    let total = Instant::now();
    let stage = Instant::now();
    let resolution = read_bounded(&args.resolution, MAX_RESOLUTION_BYTES, "resolution")?;
    let parts = read_bounded(&args.parts, MAX_PARTS_BYTES, "parts")?;
    let file_read_ms = stage.elapsed().as_secs_f64() * 1000.0;
    let workload = args
        .inspect_workload
        .then(|| inspect_resolution_parts_workload(&resolution, &parts))
        .transpose()
        .map_err(|error| anyhow!(error))?;
    let profiler = args
        .flamegraph_out
        .as_ref()
        .map(|_| {
            pprof::ProfilerGuardBuilder::default()
                .frequency(997)
                .blocklist(&["libc", "libgcc", "pthread", "vdso"])
                .build()
                .context("start local CPU profiler")
        })
        .transpose()?;
    let mut renders = Vec::with_capacity(args.iterations as usize);
    let mut json = Vec::new();
    for _ in 0..args.iterations {
        let (next_json, profile) =
            render_resolution_parts_json_profiled(&resolution, &parts, !args.no_rewards)
                .await
                .map_err(|error| anyhow!(error))?;
        json = next_json;
        renders.push(profile);
    }
    if let Some(profiler) = profiler {
        write_cpu_profile(
            profiler,
            args.flamegraph_out.as_ref().expect("profile path checked"),
        )?;
    }
    let output_sha256 = hex(&Sha256::digest(&json));
    let stage = Instant::now();
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)
        .context("create output file")?;
    output.write_all(&json).context("write JSON output")?;
    output.flush().context("flush JSON output")?;
    let file_write_ms = stage.elapsed().as_secs_f64() * 1000.0;
    println!(
        "{}",
        serde_json::json!({
            "ok": true,
            "mode": "local-files-no-network",
            "include_rewards": !args.no_rewards,
            "transaction_encoding": "base64",
            "cpu_scope": "process-all-threads",
            "file_read_elapsed_ms": file_read_ms,
            "file_write_elapsed_ms": file_write_ms,
            "total_elapsed_ms": total.elapsed().as_secs_f64() * 1000.0,
            "json_sha256": output_sha256,
            "iterations": args.iterations,
            "render": renders.last(),
            "renders": renders,
            "workload": workload,
        })
    );
    Ok(())
}

fn write_cpu_profile(guard: pprof::ProfilerGuard<'static>, path: &Path) -> Result<()> {
    let report = guard.report().build().context("build local CPU report")?;
    let mut graph = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context("create CPU flamegraph")?;
    report
        .flamegraph(&mut graph)
        .context("write CPU flamegraph")?;
    let total: isize = report.data.values().sum();
    let mut leaves = BTreeMap::<String, isize>::new();
    let mut inclusive = BTreeMap::<String, isize>::new();
    for (frames, count) in &report.data {
        if let Some(leaf) = frames.frames.first().and_then(|symbols| symbols.first()) {
            *leaves.entry(leaf.name()).or_default() += *count;
        }
        let mut seen = std::collections::BTreeSet::new();
        for symbols in &frames.frames {
            for symbol in symbols {
                let name = symbol.name();
                if seen.insert(name.clone()) {
                    *inclusive.entry(name).or_default() += *count;
                }
            }
        }
    }
    let mut values = inclusive.into_iter().collect::<Vec<_>>();
    values.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut top_path = path.to_path_buf();
    top_path.set_extension("top.tsv");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(top_path)
        .context("create CPU sample table")?;
    writeln!(output, "samples_total\t{total}")?;
    writeln!(
        output,
        "inclusive_samples\tinclusive_percent\tleaf_samples\tleaf_percent\tfunction"
    )?;
    for (name, count) in values.into_iter().take(100) {
        let leaf = leaves.get(&name).copied().unwrap_or(0);
        let denominator = total.max(1) as f64;
        writeln!(
            output,
            "{count}\t{:.3}\t{leaf}\t{:.3}\t{}",
            count as f64 * 100.0 / denominator,
            leaf as f64 * 100.0 / denominator,
            name.replace(['\t', '\n'], " ")
        )?;
    }
    Ok(())
}

fn read_bounded(path: &Path, limit: usize, label: &str) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("open {label} file"))?;
    ensure!(
        file.metadata()?.len() <= limit as u64,
        "{label} file exceeds its byte limit"
    );
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {label} file"))?;
    ensure!(bytes.len() <= limit, "{label} file exceeds its byte limit");
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
