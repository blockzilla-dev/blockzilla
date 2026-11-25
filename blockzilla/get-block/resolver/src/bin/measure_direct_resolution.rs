//! Bounded direct-resolution fixtures. No response files or new index is written.
use anyhow::{Context, Result, ensure};
use axum::body::Bytes;
use blockzilla_get_block::{slot_references, slot_resolution};
use blockzilla_resolution_service::{
    catalog::Catalog,
    direct::{self, Clock, Profile, Stage, VerifiedBody},
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
};

const MAX_MANIFEST: usize = 4 * 1024 * 1024;
const MAX_SAMPLES: usize = 512;

#[derive(Parser)]
#[command(
    about = "Build bounded direct-resolution request fixtures and small metrics; never write resolution/index records"
)]
struct Args {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    output_dir: PathBuf,
    #[arg(long, default_value_t = 800)]
    min_free_gib: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u16,
    mirror_root: PathBuf,
    catalog: PathBuf,
    samples: Vec<Sample>,
}

#[derive(Clone, Deserialize, Serialize)]
struct Sample {
    slot: u64,
    hot_frame: PathBuf,
    #[serde(default)]
    hot_sha256: Option<String>,
    #[serde(flatten)]
    annotations: BTreeMap<String, Value>,
}

#[derive(Serialize)]
struct Fixture {
    #[serde(flatten)]
    sample: Sample,
    epoch: u64,
    block_id: u32,
    hot_frame_sha256: String,
    hot_compressed_bytes: usize,
    hot_uncompressed_bytes: u32,
    request_json_path: PathBuf,
    request_json_bytes: usize,
    request_json_sha256: String,
    expected_resolution_sha256: String,
    expected_resolution_bytes: usize,
    parent_slot: u64,
    blockhash: String,
    previous_blockhash: String,
    signature_count: u32,
    signature_bytes_stored: u64,
    reference_counts: Value,
    local_pread_calls: u64,
    local_pread_bytes: u64,
    complete_resolution_verified: bool,
    profile: Profile,
    verification_profile: Stage,
}

fn read_bounded(path: &Path, bound: usize) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    ensure!(
        file.metadata()?.len() <= bound as u64,
        "input exceeds byte bound"
    );
    let mut bytes = Vec::new();
    file.take(bound as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= bound, "input grew beyond byte bound");
    Ok(bytes)
}
fn input_path(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        base.join(path)
    }
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn reserve(directory: &Path, min_free: u64, pending: usize) -> Result<()> {
    let output = Command::new("df")
        .arg("-Pk")
        .arg(directory)
        .output()
        .context("check output reserve")?;
    ensure!(output.status.success(), "output reserve check failed");
    let text = std::str::from_utf8(&output.stdout)?;
    let row = text
        .lines()
        .filter(|s| !s.trim().is_empty())
        .last()
        .context("df output has no data row")?;
    let available = row
        .split_whitespace()
        .nth(3)
        .context("df output has no free-block field")?
        .parse::<u64>()?
        .checked_mul(1024)
        .context("free bytes overflow")?;
    ensure!(
        available
            >= min_free
                .checked_add(pending as u64)
                .context("output reserve overflows")?,
        "output would cross disk reserve: available={available}, reserve={min_free}, pending={pending}"
    );
    Ok(())
}
fn publish(path: &Path, bytes: &[u8], min_free: u64) -> Result<()> {
    reserve(
        path.parent().context("output parent missing")?,
        min_free,
        bytes.len(),
    )?;
    let mut part = path.as_os_str().to_owned();
    part.push(".part");
    let part = PathBuf::from(part);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&part)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::hard_link(&part, path)?;
    fs::remove_file(part)?;
    Ok(())
}

fn measure(
    mut sample: Sample,
    catalog: &Catalog,
    base: &Path,
    output: &Path,
    min_free: u64,
) -> Result<Fixture> {
    let source = catalog
        .pending(sample.slot)?
        .context("sample slot is outside the local admitted catalog")?;
    let frame_path = input_path(base, &sample.hot_frame);
    sample.hot_frame = frame_path.canonicalize()?;
    let raw = read_bounded(&frame_path, direct::MAX_HOT_BYTES)?;
    let total = Clock::start()?;
    let verified = VerifiedBody::new(Bytes::from(raw), sample.hot_sha256.as_deref())?;
    let (request, mut profile) = direct::collect_hot(source.clone(), &verified)?;
    let clock = Clock::start()?;
    let resolved = catalog.resolve(&request)?;
    profile.table_resolve = clock.finish()?;
    let clock = Clock::start()?;
    let encoded = slot_resolution::encode(&resolved.resolution).map_err(anyhow::Error::msg)?;
    let expected_resolution_sha256 = sha(&encoded);
    profile.encode = clock.finish()?;
    profile.total = total.finish()?;
    // Validation is separate from construction CPU and does not write a reply.
    let clock = Clock::start()?;
    let checked = slot_resolution::decode_checked(&encoded).map_err(anyhow::Error::msg)?;
    slot_references::validate_resolution(&checked, &request.references)
        .map_err(anyhow::Error::msg)?;
    ensure!(
        slot_resolution::encode(&slot_resolution::decode(&encoded).map_err(anyhow::Error::msg)?)
            .map_err(anyhow::Error::msg)?
            == encoded,
        "resolution roundtrip differs"
    );
    let verification_profile = clock.finish()?;
    let request_json = serde_json::to_vec(&request)?;
    ensure!(
        request_json.len() <= slot_references::MAX_REQUEST_BYTES,
        "typed request exceeds byte bound"
    );
    let request_json_path = output.join(format!("slot-{}.request.json", sample.slot));
    publish(&request_json_path, &request_json, min_free)?;
    let locator = &resolved.resolution.locator;
    let refs = &request.references;
    Ok(Fixture {
        sample,
        epoch: source.epoch,
        block_id: source.hot.block_id,
        hot_frame_sha256: verified.sha256().into(),
        hot_compressed_bytes: verified.bytes().len(),
        hot_uncompressed_bytes: source.hot.uncompressed_len,
        request_json_path,
        request_json_bytes: request_json.len(),
        request_json_sha256: sha(&request_json),
        expected_resolution_sha256,
        expected_resolution_bytes: encoded.len(),
        parent_slot: locator.parent_slot,
        blockhash: hex::encode(locator.blockhash),
        previous_blockhash: hex::encode(locator.previous_blockhash),
        signature_count: source.hot.signature_count,
        signature_bytes_stored: 0,
        reference_counts: json!({"pubkeys":refs.pubkeys.len(),"blockhashes":refs.blockhashes.len(),"negative_blockhashes":refs.blockhashes.iter().filter(|id|**id<0).count(),"votes":refs.votes.len(),"vote_bank_hashes":refs.votes.iter().filter(|v|v.bank_hash).count(),"vote_block_id_hashes":refs.votes.iter().filter(|v|v.block_id_hash).count(),"signature_counts":refs.signature_counts.len()}),
        local_pread_calls: resolved.pread_calls,
        local_pread_bytes: resolved.pread_bytes,
        complete_resolution_verified: true,
        profile,
        verification_profile,
    })
}

fn run(args: Args) -> Result<()> {
    let path = args.manifest.canonicalize()?;
    let base = path.parent().context("manifest parent missing")?;
    let raw_manifest = read_bounded(&path, MAX_MANIFEST)?;
    let mut manifest: Manifest = serde_json::from_slice(&raw_manifest)?;
    ensure!(
        manifest.version == 1
            && !manifest.samples.is_empty()
            && manifest.samples.len() <= MAX_SAMPLES,
        "direct fixture run requires 1 to512 samples; use the bounded direct sample input"
    );
    let mut slots = BTreeSet::new();
    let reserved = [
        "epoch",
        "block_id",
        "hot_frame_sha256",
        "hot_compressed_bytes",
        "hot_uncompressed_bytes",
        "request_json_path",
        "request_json_bytes",
        "request_json_sha256",
        "expected_resolution_sha256",
        "expected_resolution_bytes",
        "parent_slot",
        "blockhash",
        "previous_blockhash",
        "signature_count",
        "signature_bytes_stored",
        "reference_counts",
        "local_pread_calls",
        "local_pread_bytes",
        "complete_resolution_verified",
        "profile",
        "verification_profile",
    ];
    for sample in &mut manifest.samples {
        if let Some(epoch) = sample.annotations.remove("epoch") {
            ensure!(
                epoch.as_u64() == Some(sample.slot / 432000),
                "sample epoch differs from slot"
            );
        }
        ensure!(slots.insert(sample.slot), "duplicate sample slot");
        ensure!(
            sample
                .annotations
                .keys()
                .all(|key| !reserved.contains(&key.as_str())),
            "sample label collides with a fixture field"
        );
    }
    let min_free = args
        .min_free_gib
        .checked_mul(1024 * 1024 * 1024)
        .context("reserve overflows")?;
    ensure!(
        !args.output_dir.exists(),
        "fixture output directory already exists"
    );
    let parent = args
        .output_dir
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    reserve(parent, min_free, 0)?;
    fs::create_dir(&args.output_dir)?;
    let output = args.output_dir.canonicalize()?;
    let catalog_path = input_path(base, &manifest.catalog);
    let catalog_bytes = read_bounded(&catalog_path, 16 * 1024 * 1024)?;
    let clock = Clock::start()?;
    let catalog = Catalog::load(&input_path(base, &manifest.mirror_root), &catalog_path)?;
    let catalog_load_profile = clock.finish()?;
    ensure!(
        read_bounded(&catalog_path, 16 * 1024 * 1024)? == catalog_bytes,
        "catalog changed during verification"
    );
    let mut fixtures = Vec::new();
    let mut failures = Vec::new();
    for sample in manifest.samples {
        match measure(sample.clone(), &catalog, base, &output, min_free) {
            Ok(fixture) => {
                eprintln!(
                    "direct fixture epoch={} slot={} request_bytes={} response_bytes={} CPU_us={}",
                    fixture.epoch,
                    fixture.sample.slot,
                    fixture.request_json_bytes,
                    fixture.expected_resolution_bytes,
                    fixture.profile.total.cpu_ns / 1000
                );
                fixtures.push(fixture);
            }
            Err(error) => {
                eprintln!("direct fixture failed slot={}: {error:#}", sample.slot);
                failures.push(json!({"sample":sample,"error":format!("{error:#}")}));
            }
        }
    }
    fixtures.sort_by_key(|f| (f.epoch, f.block_id));
    let report = json!({"version":1,"status":if failures.is_empty(){"complete"}else{"partial"},"source_prefix":catalog.source_prefix(),"generation":catalog.generation(),"input_manifest_sha256":sha(&raw_manifest),"catalog_sha256":sha(&catalog_bytes),"catalog_load_profile":catalog_load_profile,"resolution_ram_cache":"not_started_or_used","raw_signature_bytes_read":0,"raw_signature_bytes_stored":0,"resolution_files_written":0,"new_index_files_written":0,"disk_reserve_bytes":min_free,"cpu_clock":"CLOCK_THREAD_CPUTIME_ID","cpu_scope":"Synchronous construction only: request SHA, bounded decompression, hot decode, reference collection, local table resolution, resolution encoding and SHA. Validation proof is separate; HTTP transport is not measured here.","cold_io_limit":"Startup SHA verification can warm OS page cache. Local pread counts do not prove physical SSD reads.","fixtures":fixtures,"failures":failures});
    let report_path = output.join("fixtures.json");
    publish(&report_path, &serde_json::to_vec_pretty(&report)?, min_free)?;
    println!(
        "{}",
        json!({"fixtures":report_path,"samples":fixtures.len(),"failures":failures.len(),"resolution_files_written":0,"new_index_files_written":0})
    );
    ensure!(
        failures.is_empty(),
        "direct fixture run has{}failed samples; see fixtures.json",
        failures.len()
    );
    Ok(())
}
fn main() -> Result<()> {
    run(Args::parse())
}

#[cfg(test)]
mod tests {
    use super::*;
    use blockzilla_archive_v2::{
        ArchiveV2HotBlockBlob, ArchiveV2HotBlockHeader, ArchiveV2HotBlockIndexRow,
        write_archive_v2_hot_block_index,
    };
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn fixture_run_writes_only_small_json_and_preserves_previous_hash_and_labels() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let epoch = root.join("mirror/epoch-1");
        fs::create_dir_all(&epoch).unwrap();
        let hot = ArchiveV2HotBlockBlob {
            consensus_block_id: None,
            block_markers: Vec::new(),
            header: ArchiveV2HotBlockHeader {
                slot: 432000,
                parent_slot: 431999,
                blockhash_id: 0,
                previous_blockhash_id: 0,
                block_time: None,
                block_height: None,
                rewards: None,
            },
            tx_count: 0,
            tx_rows: vec![],
            message_bytes: vec![],
            metadata_bytes: vec![],
        };
        let decoded =
            wincode::config::serialize(&hot, blockzilla_primitives::wincode_leb128_config())
                .unwrap();
        let compressed = zstd::bulk::compress(&decoded, 1).unwrap();
        fs::write(root.join("hot.zstd"), &compressed).unwrap();
        let row = ArchiveV2HotBlockIndexRow {
            block_id: 0,
            slot: 432000,
            compressed_offset: 0,
            compressed_len: compressed.len() as u32,
            uncompressed_len: decoded.len() as u32,
            tx_count: 0,
            first_tx_ordinal: 0,
            first_signature_ordinal: 0,
            signature_count: 0,
        };
        write_archive_v2_hot_block_index(
            &epoch.join("archive-v2-blocks.index"),
            compressed.len() as u64,
            0,
            0,
            &[row],
        )
        .unwrap();
        fs::write(epoch.join("registry.bin"), []).unwrap();
        fs::write(epoch.join("vote_hash_registry.bin"), []).unwrap();
        fs::write(epoch.join("blockhash_registry.bin"), [9; 32]).unwrap();
        let mut tail = vec![8u8; 32];
        tail.extend_from_slice(&431999u64.to_le_bytes());
        fs::write(epoch.join("prev_blockhash_tail.bin"), tail).unwrap();
        let mut objects = Vec::new();
        for name in [
            "archive-v2-blocks.index",
            "registry.bin",
            "vote_hash_registry.bin",
            "blockhash_registry.bin",
            "prev_blockhash_tail.bin",
        ] {
            let path = epoch.join(name);
            let bytes = fs::read(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
            objects.push(json!({"name":name,"identity":{"length":bytes.len(),"etag":format!("\"{name}\"")},"relative_path":format!("epoch-1/{name}"),"sha256":sha(&bytes)}));
        }
        objects.push(json!({"name":"archive-v2-blocks.zstd","identity":{"length":compressed.len(),"etag":"\"hot\""}}));
        objects.push(json!({"name":"signatures.bin","identity":{"length":0,"etag":"\"sig\""}}));
        fs::write(root.join("catalog.json"),serde_json::to_vec(&json!({"version":1,"source_prefix":"compact-v2/test","generation":"direct-test","epochs":[{"epoch":1,"message_schema":0,"metadata_schema":0,"tail_schema":"hash_and_slot40","objects":objects}]})).unwrap()).unwrap();
        let manifest = json!({"version":1,"mirror_root":"mirror","catalog":"catalog.json","samples":[{"slot":432000,"epoch":1,"hot_frame":"hot.zstd","hot_sha256":sha(&compressed),"control":true,"window":"control"}]});
        let input = root.join("input.json");
        fs::write(&input, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let output = root.join("fixtures");
        run(Args {
            manifest: input,
            output_dir: output.clone(),
            min_free_gib: 0,
        })
        .unwrap();
        let report: Value =
            serde_json::from_slice(&fs::read(output.join("fixtures.json")).unwrap()).unwrap();
        assert_eq!(report["status"], "complete");
        assert_eq!(report["resolution_files_written"], 0);
        assert_eq!(report["new_index_files_written"], 0);
        assert_eq!(report["raw_signature_bytes_read"], 0);
        let fixture = &report["fixtures"][0];
        assert_eq!(fixture["previous_blockhash"], hex::encode([8; 32]));
        assert_eq!(fixture["parent_slot"], 431999);
        assert_eq!(fixture["control"], true);
        assert_eq!(fixture["window"], "control");
        assert_eq!(fixture["complete_resolution_verified"], true);
        let files: Vec<_> = fs::read_dir(&output)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(files.len(), 2);
        assert!(
            files
                .iter()
                .all(|p| p.extension().is_some_and(|e| e == "json"))
        );
        assert!(!epoch.join("signatures.bin").exists());
        let request = fs::read(output.join("slot-432000.request.json")).unwrap();
        assert_eq!(sha(&request), fixture["request_json_sha256"]);
        assert!(fixture["profile"]["total"]["cpu_ns"].as_u64().unwrap() > 0);
    }
}
