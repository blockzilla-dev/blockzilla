use anyhow::{Context, Result, ensure};
use blockzilla_primitives::wincode_leb128_config;
use blockzilla_sample_block_bench::{BlockSummary, MAX_DECODED_BYTES, decode, sha256, summarize};
use serde::Deserialize;
use std::{hint::black_box, io::Read, path::Path, time::Instant};

#[derive(Deserialize)]
struct FixtureManifest {
    schema: String,
    compressed_sha256: String,
    decoded_sha256: String,
    compressed_bytes: usize,
    decoded_bytes: usize,
    expected: BlockSummary,
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let iterations = args
        .next()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(100usize);
    ensure!(
        iterations > 0 && args.next().is_none(),
        "usage: blockzilla-sample-block-bench [positive-iterations]"
    );
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    let manifest: FixtureManifest =
        serde_json::from_slice(&std::fs::read(fixtures.join("manifest.json"))?)?;
    ensure!(
        manifest.schema == "blockzilla-sample-block-v1",
        "unsupported sample manifest"
    );
    let compressed = std::fs::read(fixtures.join("block.compact-v2.zst"))?;
    ensure!(
        compressed.len() == manifest.compressed_bytes
            && sha256(&compressed) == manifest.compressed_sha256,
        "compressed sample differs from manifest"
    );
    let decoded = decompress(&compressed)?;
    ensure!(
        decoded.len() == manifest.decoded_bytes && sha256(&decoded) == manifest.decoded_sha256,
        "decoded sample differs from manifest"
    );
    let block = decode(&decoded)?;
    ensure!(
        summarize(&block)? == manifest.expected,
        "sample row or signed-wire parity failure"
    );
    ensure!(
        wincode::config::serialize(&block, wincode_leb128_config())? == decoded,
        "sample does not roundtrip exactly"
    );

    let start = Instant::now();
    for _ in 0..iterations {
        black_box(decode(black_box(&decoded))?);
    }
    let decode_seconds = start.elapsed().as_secs_f64();
    let start = Instant::now();
    for _ in 0..iterations {
        let bytes = decompress(black_box(&compressed))?;
        black_box(decode(&bytes)?);
    }
    let compressed_seconds = start.elapsed().as_secs_f64();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "parity": "passed",
        "debug_assertions": cfg!(debug_assertions),
        "architecture": std::env::consts::ARCH,
        "fixture_sha256": manifest.compressed_sha256,
        "decoded_bytes": manifest.decoded_bytes,
            "iterations": iterations,
            "sample": manifest.expected,
            "decode_only": {
                "seconds": decode_seconds,
                "milliseconds_per_block": decode_seconds * 1000.0 / iterations as f64,
            },
            "decompress_and_decode": {
                "seconds": compressed_seconds,
                "milliseconds_per_block": compressed_seconds * 1000.0 / iterations as f64,
            },
            "timing_scope": "warm memory, full owned block decode and drop; excludes file reads, validation, signature checks and source conversion"
        }))?
    );
    Ok(())
}

fn decompress(bytes: &[u8]) -> Result<Vec<u8>> {
    let decoder = zstd::stream::read::Decoder::new(bytes).context("open zstd sample")?;
    let mut output = Vec::new();
    decoder
        .take((MAX_DECODED_BYTES + 1) as u64)
        .read_to_end(&mut output)?;
    ensure!(
        output.len() <= MAX_DECODED_BYTES,
        "sample exceeds decoded size limit"
    );
    Ok(output)
}
