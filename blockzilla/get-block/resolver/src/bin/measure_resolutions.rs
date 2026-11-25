//! Offline sample measurement. It never starts the HTTP service or its RAM cache.
use anyhow::{Context, Result, ensure};
use blockzilla_archive_v2::{
    ARCHIVE_V2_HOT_INDEX_HEADER_LEN, ARCHIVE_V2_HOT_INDEX_ROW_LEN,
    WINCODE_ARCHIVE_V2_BLOCK_ACCESS_VERSION, deserialize_archive_v2_hot_block_blob,
};
use blockzilla_get_block::{
    foundation_protocol::ResolveRequestV1,
    slot_references,
    slot_resolution::{self, LocatorV1, NamedSourceObject, ResolutionHotRow, ResolutionV1},
};
use blockzilla_primitives::{bounded_wincode_leb128_config, wincode_leb128_config};
use blockzilla_resolution_service::catalog::Catalog;
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
    time::Instant,
};
use wincode::{SchemaRead, SchemaWrite};

const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_SAMPLES: usize = 4096;
const MAX_HOT_BYTES: usize = 16 * 1024 * 1024;
const MAX_DECODED_BYTES: usize = 32 * 1024 * 1024;
const GIB: u64 = 1024 * 1024 * 1024;

#[derive(Parser)]
#[command(
    about = "Measure exact signature-free per-block resolution records from bounded real samples"
)]
struct Args {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    output_dir: PathBuf,
    #[arg(long, default_value_t = 800)]
    min_free_gib: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u16,
    mirror_root: PathBuf,
    catalog: PathBuf,
    #[serde(default)]
    epochs: Vec<EpochSampling>,
    samples: Vec<Sample>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct EpochSampling {
    epoch: u64,
    #[serde(default)]
    sample_method: Option<String>,
    #[serde(flatten)]
    annotations: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Sample {
    slot: u64,
    hot_frame: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hot_sha256: Option<String>,
    #[serde(default)]
    control: bool,
    #[serde(default, skip_serializing)]
    projection_eligible: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sample_group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    window: Option<Value>,
    #[serde(flatten)]
    annotations: BTreeMap<String, Value>,
}

/// Measurement-only representation. Epoch metadata is in one exact JSON file.
/// No ID, hash, signature count or provenance is discarded during rehydration.
#[derive(Debug, SchemaRead, SchemaWrite)]
struct SharedBlockV1 {
    version: u16,
    epoch_manifest_sha256: [u8; 32],
    hot: ResolutionHotRow,
    parent_slot: u64,
    blockhash: [u8; 32],
    previous_blockhash: [u8; 32],
    signature_counts: Vec<u8>,
    access_suffix: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedEpochV1 {
    version: u16,
    source_prefix: String,
    generation: String,
    epoch: u64,
    message_schema: u8,
    metadata_schema: u8,
    source_objects: Vec<NamedSourceObject>,
}

impl SharedEpochV1 {
    fn from_resolution(value: &ResolutionV1) -> Self {
        Self {
            version: 1,
            source_prefix: value.locator.source_prefix.clone(),
            generation: value.locator.generation.clone(),
            epoch: value.locator.epoch,
            message_schema: value.locator.message_schema,
            metadata_schema: value.locator.metadata_schema,
            source_objects: value.source_objects.clone(),
        }
    }

    fn rehydrate(&self, body: SharedBlockV1, exact_manifest_bytes: &[u8]) -> Result<ResolutionV1> {
        ensure!(
            self.version == 1 && body.version == 1,
            "unsupported shared representation version"
        );
        ensure!(
            body.epoch_manifest_sha256 == sha256(exact_manifest_bytes),
            "shared epoch manifest SHA256 differs"
        );
        let parsed: SharedEpochV1 = serde_json::from_slice(exact_manifest_bytes)?;
        ensure!(
            parsed == *self,
            "shared epoch metadata differs from the exact manifest"
        );
        let identity = |name: &str| {
            self.source_objects
                .iter()
                .find(|o| o.name == name)
                .map(|o| o.identity.clone())
                .with_context(|| format!("shared manifest omits {name}"))
        };
        let locator = LocatorV1 {
            version: 1,
            source_prefix: self.source_prefix.clone(),
            generation: self.generation.clone(),
            epoch: self.epoch,
            hot: body.hot,
            parent_slot: body.parent_slot,
            blockhash: body.blockhash,
            previous_blockhash: body.previous_blockhash,
            message_schema: self.message_schema,
            metadata_schema: self.metadata_schema,
            blocks: identity("archive-v2-blocks.zstd")?,
            signatures: identity("signatures.bin")?,
        };
        let access_prefix = wincode::config::serialize(
            &(
                WINCODE_ARCHIVE_V2_BLOCK_ACCESS_VERSION,
                0u32,
                locator.blockhash,
                locator.previous_blockhash,
                body.signature_counts.as_slice(),
                locator.signature_bytes().map_err(anyhow::Error::msg)? as u64,
            ),
            wincode_leb128_config(),
        )?;
        let value = ResolutionV1 {
            locator,
            source_objects: self.source_objects.clone(),
            signature_counts: body.signature_counts,
            access_prefix,
            access_suffix: body.access_suffix,
        };
        value
            .validate(
                &self.source_prefix,
                &self.generation,
                value.locator.hot.slot,
            )
            .map_err(anyhow::Error::msg)?;
        Ok(value)
    }
}

struct SharedEpochFile {
    metadata: SharedEpochV1,
    bytes: Vec<u8>,
    path: PathBuf,
    sha256: [u8; 32],
}

#[derive(Serialize)]
struct Record {
    #[serde(flatten)]
    sample: Sample,
    epoch: u64,
    block_id: u32,
    path: PathBuf,
    bytes: usize,
    sha256: String,
    shared_body_path: PathBuf,
    shared_body_bytes: usize,
    shared_body_sha256: String,
    shared_epoch_manifest_sha256: String,
    hot_frame_sha256: String,
    hot_compressed_bytes: usize,
    hot_uncompressed_bytes: usize,
    message_schema: u8,
    metadata_schema: u8,
    parent_slot: u64,
    tx_count: u32,
    signature_count: u32,
    signature_bytes_stored: u64,
    source_signature_bytes: u64,
    pubkey_ids: usize,
    blockhash_ids: usize,
    negative_blockhash_ids: usize,
    vote_ids: usize,
    vote_bank_hashes: usize,
    vote_block_id_hashes: usize,
    access_prefix_bytes: usize,
    access_suffix_bytes: usize,
    request_json_bytes: usize,
    local_pread_calls: u64,
    local_pread_bytes: u64,
    decompress_micros: u128,
    hot_decode_micros: u128,
    collect_micros: u128,
    resolve_micros: u128,
    roundtrip_micros: u128,
    complete_roundtrip_verified: bool,
    shared_rehydration_matches_baseline: bool,
    projection_eligible: bool,
    projection_excluded: bool,
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn read_bounded(path: &Path, bound: usize) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    ensure!(
        file.metadata()?.len() <= bound as u64,
        "input exceeds byte bound: {}",
        path.display()
    );
    let mut bytes = Vec::new();
    file.take(bound as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= bound, "input grew beyond byte bound");
    Ok(bytes)
}

fn relative_to(base: &Path, value: &Path) -> PathBuf {
    if value.is_absolute() {
        value.to_owned()
    } else {
        base.join(value)
    }
}

fn parse_available_bytes(df_output: &[u8]) -> Result<u64> {
    let text = std::str::from_utf8(df_output)?;
    let row = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .last()
        .context("df output has no data row")?;
    let fields: Vec<_> = row.split_whitespace().collect();
    ensure!(fields.len() >= 6, "df output has no available-block field");
    fields[3]
        .parse::<u64>()?
        .checked_mul(1024)
        .context("available bytes overflow")
}

fn check_reserve(directory: &Path, reserve: u64, pending: usize) -> Result<()> {
    let output = Command::new("df")
        .arg("-Pk")
        .arg(directory)
        .output()
        .context("check output disk reserve")?;
    ensure!(output.status.success(), "df disk reserve check failed");
    let available = parse_available_bytes(&output.stdout)?;
    ensure!(
        available
            >= reserve
                .checked_add(pending as u64)
                .context("reserve overflows")?,
        "output disk reserve would be crossed: available={available}, reserve={reserve}, pending={pending}"
    );
    Ok(())
}

fn publish_new(path: &Path, bytes: &[u8], reserve: u64) -> Result<()> {
    let directory = path.parent().context("output has no parent")?;
    check_reserve(directory, reserve, bytes.len())?;
    ensure!(
        !path.exists(),
        "measurement output already exists: {}",
        path.display()
    );
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".part");
    let temporary = PathBuf::from(temporary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    // A new output directory belongs only to this run; hard_link also prevents
    // accidental replacement if a second process uses the same output path.
    fs::hard_link(&temporary, path)?;
    fs::remove_file(temporary)?;
    Ok(())
}

fn catalog_epoch_counts(raw: &[u8]) -> Result<BTreeMap<u64, u64>> {
    let catalog: Value = serde_json::from_slice(raw)?;
    let mut counts = BTreeMap::new();
    for epoch in catalog["epochs"]
        .as_array()
        .context("catalog has no epochs")?
    {
        let number = epoch["epoch"]
            .as_u64()
            .context("catalog epoch is invalid")?;
        let length = epoch["objects"]
            .as_array()
            .context("catalog epoch objects missing")?
            .iter()
            .find(|o| o["name"] == "archive-v2-blocks.index")
            .and_then(|o| o["identity"]["length"].as_u64())
            .context("catalog hot index length missing")?;
        let rows = length
            .checked_sub(ARCHIVE_V2_HOT_INDEX_HEADER_LEN as u64)
            .context("catalog hot index is short")?;
        ensure!(
            rows.is_multiple_of(ARCHIVE_V2_HOT_INDEX_ROW_LEN as u64),
            "catalog hot index row length differs"
        );
        ensure!(
            counts
                .insert(number, rows / ARCHIVE_V2_HOT_INDEX_ROW_LEN as u64)
                .is_none(),
            "duplicate catalog epoch"
        );
    }
    Ok(counts)
}

fn measure_one(
    sample: Sample,
    input_base: &Path,
    output: &Path,
    reserve: u64,
    catalog: &Catalog,
    shared: &mut BTreeMap<u64, SharedEpochFile>,
) -> Result<Record> {
    let pending = catalog
        .pending(sample.slot)?
        .context("sample slot is outside the admitted local catalog")?;
    let hot_path = relative_to(input_base, &sample.hot_frame);
    let compressed = read_bounded(&hot_path, MAX_HOT_BYTES)?;
    ensure!(
        compressed.len() == pending.hot.compressed_len as usize,
        "sample compressed hot length differs from the pinned row"
    );
    let hot_digest = hex::encode(sha256(&compressed));
    if let Some(expected) = &sample.hot_sha256 {
        ensure!(*expected == hot_digest, "sample hot frame SHA256 differs");
    }
    let started = Instant::now();
    ensure!(
        pending.hot.uncompressed_len as usize <= MAX_DECODED_BYTES,
        "hot uncompressed length exceeds bound"
    );
    let decoded = zstd::bulk::decompress(&compressed, pending.hot.uncompressed_len as usize)
        .context("decompress original hot frame")?;
    ensure!(
        decoded.len() == pending.hot.uncompressed_len as usize,
        "sample decompressed hot length differs from pinned row"
    );
    let decompress_micros = started.elapsed().as_micros();
    let started = Instant::now();
    let block = deserialize_archive_v2_hot_block_blob(&decoded)
        .context("decode stored hot schema; unsupported source must be explicit")?;
    let hot_decode_micros = started.elapsed().as_micros();
    let started = Instant::now();
    let references=slot_references::collect(&block,&pending.hot.into(),pending.message_schema,pending.metadata_schema).map_err(anyhow::Error::msg).context("collect complete typed IDs; raw fallbacks or unsupported historical schemas are not omitted")?;
    let collect_micros = started.elapsed().as_micros();
    let request = ResolveRequestV1 {
        version: 1,
        source: pending.clone(),
        hot_sha256: hot_digest.clone(),
        references,
    };
    let request_json_bytes = serde_json::to_vec(&request)?.len();
    ensure!(
        request_json_bytes <= slot_references::MAX_REQUEST_BYTES,
        "reference request exceeds bound"
    );
    let started = Instant::now();
    let resolved = catalog
        .resolve(&request)
        .context("resolve local dictionary windows without a RAM result cache")?;
    let resolve_micros = started.elapsed().as_micros();
    let value = resolved.resolution;
    let started = Instant::now();
    let envelope = slot_resolution::encode(&value).map_err(anyhow::Error::msg)?;
    let checked = slot_resolution::decode_checked(&envelope).map_err(anyhow::Error::msg)?;
    slot_references::validate_resolution(&checked, &request.references)
        .map_err(anyhow::Error::msg)?;
    ensure!(
        slot_resolution::encode(&slot_resolution::decode(&envelope).map_err(anyhow::Error::msg)?)
            .map_err(anyhow::Error::msg)?
            == envelope,
        "baseline ResolutionV1 roundtrip differs"
    );
    let baseline_roundtrip_micros = started.elapsed().as_micros();
    let epoch_meta = SharedEpochV1::from_resolution(&value);
    let directory = output.join(format!("epoch-{}", pending.epoch));
    if !directory.exists() {
        check_reserve(output, reserve, 0)?;
        fs::create_dir(&directory)?;
    }
    if let Some(existing) = shared.get(&pending.epoch) {
        ensure!(
            existing.metadata == epoch_meta,
            "mixed epoch metadata in measurement sample"
        );
    } else {
        let mut bytes = serde_json::to_vec(&epoch_meta)?;
        bytes.push(b'\n');
        let path = directory.join("shared-epoch-manifest.json");
        let digest = sha256(&bytes);
        publish_new(&path, &bytes, reserve)?;
        shared.insert(
            pending.epoch,
            SharedEpochFile {
                metadata: epoch_meta,
                bytes,
                path,
                sha256: digest,
            },
        );
    }
    let epoch_file = &shared[&pending.epoch];
    let shared_started = Instant::now();
    let shared_body = SharedBlockV1 {
        version: 1,
        epoch_manifest_sha256: epoch_file.sha256,
        hot: value.locator.hot,
        parent_slot: value.locator.parent_slot,
        blockhash: value.locator.blockhash,
        previous_blockhash: value.locator.previous_blockhash,
        signature_counts: value.signature_counts.clone(),
        access_suffix: value.access_suffix.clone(),
    };
    let shared_bytes = wincode::config::serialize(&shared_body, wincode_leb128_config())?;
    ensure!(
        shared_bytes.len() <= slot_resolution::MAX_RESOLUTION_BYTES,
        "shared measurement body exceeds bound"
    );
    let decoded_shared = wincode::config::deserialize_exact(
        &shared_bytes,
        bounded_wincode_leb128_config::<{ slot_resolution::MAX_RESOLUTION_BYTES }>(),
    )?;
    let rehydrated = epoch_file
        .metadata
        .rehydrate(decoded_shared, &epoch_file.bytes)?;
    ensure!(
        slot_resolution::encode(&rehydrated).map_err(anyhow::Error::msg)? == envelope,
        "shared body rehydration loses resolution information"
    );
    let roundtrip_micros = baseline_roundtrip_micros + shared_started.elapsed().as_micros();
    let name = format!("block-{}-slot-{}", pending.hot.block_id, sample.slot);
    let path = directory.join(format!("{name}.resolution.wincode"));
    let shared_body_path = directory.join(format!("{name}.shared-body.wincode"));
    publish_new(&path, &envelope, reserve)?;
    publish_new(&shared_body_path, &shared_bytes, reserve)?;
    let refs = &request.references;
    let projection_eligible = sample.projection_eligible.unwrap_or(true);
    let projection_excluded = !projection_eligible;
    Ok(Record {
        sample,
        epoch: pending.epoch,
        block_id: pending.hot.block_id,
        path,
        bytes: envelope.len(),
        sha256: hex::encode(sha256(&envelope)),
        shared_body_path,
        shared_body_bytes: shared_bytes.len(),
        shared_body_sha256: hex::encode(sha256(&shared_bytes)),
        shared_epoch_manifest_sha256: hex::encode(epoch_file.sha256),
        hot_frame_sha256: hot_digest,
        hot_compressed_bytes: compressed.len(),
        hot_uncompressed_bytes: decoded.len(),
        message_schema: pending.message_schema,
        metadata_schema: pending.metadata_schema,
        parent_slot: refs.parent_slot,
        tx_count: pending.hot.tx_count,
        signature_count: pending.hot.signature_count,
        signature_bytes_stored: 0,
        source_signature_bytes: u64::from(pending.hot.signature_count) * 64,
        pubkey_ids: refs.pubkeys.len(),
        blockhash_ids: refs.blockhashes.len(),
        negative_blockhash_ids: refs.blockhashes.iter().filter(|id| **id < 0).count(),
        vote_ids: refs.votes.len(),
        vote_bank_hashes: refs.votes.iter().filter(|v| v.bank_hash).count(),
        vote_block_id_hashes: refs.votes.iter().filter(|v| v.block_id_hash).count(),
        access_prefix_bytes: value.access_prefix.len(),
        access_suffix_bytes: value.access_suffix.len(),
        request_json_bytes,
        local_pread_calls: resolved.pread_calls,
        local_pread_bytes: resolved.pread_bytes,
        decompress_micros,
        hot_decode_micros,
        collect_micros,
        resolve_micros,
        roundtrip_micros,
        complete_roundtrip_verified: true,
        shared_rehydration_matches_baseline: true,
        projection_eligible,
        projection_excluded,
    })
}

fn run(args: Args) -> Result<()> {
    let manifest_path = args.manifest.canonicalize()?;
    let input_base = manifest_path
        .parent()
        .context("sample manifest has no parent")?;
    let input_bytes = read_bounded(&manifest_path, MAX_MANIFEST_BYTES)?;
    let mut manifest: Manifest = serde_json::from_slice(&input_bytes)?;
    ensure!(
        manifest.version == 1
            && !manifest.samples.is_empty()
            && manifest.samples.len() <= MAX_SAMPLES,
        "unsupported sample manifest version or sample count"
    );
    let mut seen = BTreeSet::new();
    let reserved = [
        "epoch",
        "block_id",
        "path",
        "bytes",
        "sha256",
        "shared_body_path",
        "shared_body_bytes",
        "shared_body_sha256",
        "shared_epoch_manifest_sha256",
        "hot_frame_sha256",
        "hot_compressed_bytes",
        "hot_uncompressed_bytes",
        "message_schema",
        "metadata_schema",
        "parent_slot",
        "tx_count",
        "signature_count",
        "signature_bytes_stored",
        "source_signature_bytes",
        "pubkey_ids",
        "blockhash_ids",
        "negative_blockhash_ids",
        "vote_ids",
        "vote_bank_hashes",
        "vote_block_id_hashes",
        "access_prefix_bytes",
        "access_suffix_bytes",
        "request_json_bytes",
        "local_pread_calls",
        "local_pread_bytes",
        "decompress_micros",
        "hot_decode_micros",
        "collect_micros",
        "resolve_micros",
        "roundtrip_micros",
        "complete_roundtrip_verified",
    ];
    for sample in &mut manifest.samples {
        ensure!(
            !sample.control || sample.projection_eligible.is_some(),
            "control samples require explicit projection_eligible to preserve overlapping windows"
        );
        if let Some(epoch) = sample.annotations.remove("epoch") {
            ensure!(
                epoch.as_u64() == Some(sample.slot / 432000),
                "supplied sample epoch differs from its slot"
            );
        }
        ensure!(
            seen.insert(sample.slot),
            "duplicate sample slot {}",
            sample.slot
        );
        ensure!(
            sample
                .annotations
                .keys()
                .all(|key| !reserved.contains(&key.as_str())
                    && key != "shared_rehydration_matches_baseline"
                    && key != "projection_excluded"),
            "sample annotation collides with a measurement field"
        );
    }
    let reserve = args
        .min_free_gib
        .checked_mul(GIB)
        .context("disk reserve overflows")?;
    ensure!(
        !args.output_dir.exists(),
        "measurement output directory already exists"
    );
    let parent = args
        .output_dir
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    check_reserve(parent, reserve, 0)?;
    fs::create_dir(&args.output_dir)?;
    let output = args.output_dir.canonicalize()?;
    let catalog_path = relative_to(input_base, &manifest.catalog);
    let catalog_bytes = read_bounded(&catalog_path, 16 * 1024 * 1024)?;
    let epoch_counts = catalog_epoch_counts(&catalog_bytes)?;
    let started = Instant::now();
    let catalog = Catalog::load(
        &relative_to(input_base, &manifest.mirror_root),
        &catalog_path,
    )?;
    ensure!(
        read_bounded(&catalog_path, 16 * 1024 * 1024)? == catalog_bytes,
        "catalog changed during startup verification"
    );
    let catalog_load_micros = started.elapsed().as_micros();
    let mut records = Vec::new();
    let mut failures = Vec::new();
    let mut shared = BTreeMap::new();
    for sample in manifest.samples {
        match measure_one(
            sample.clone(),
            input_base,
            &output,
            reserve,
            &catalog,
            &mut shared,
        ) {
            Ok(record) => {
                eprintln!(
                    "measured epoch={} slot={} resolution_bytes={} pubkeys={}",
                    record.epoch, record.sample.slot, record.bytes, record.pubkey_ids
                );
                records.push(record);
            }
            Err(error) => {
                eprintln!("sample failed slot={}: {error:#}", sample.slot);
                failures.push(json!({"sample":sample,"error":format!("{error:#}")}));
            }
        }
    }
    records.sort_by_key(|record| (record.epoch, record.block_id));
    let epochs:Vec<_>=epoch_counts.iter().map(|(epoch,count)|{
        let sample_metadata=manifest.epochs.iter().find(|row|row.epoch==*epoch);
        let mut row=json!({"epoch":epoch,"total_produced_blocks":count,"sample_method":sample_metadata.and_then(|s|s.sample_method.as_deref()).unwrap_or("supplied_real_hot_frames"),"sample_metadata":sample_metadata});
        if let Some(file)=shared.get(epoch) { row["shared_epoch_manifest_path"]=json!(file.path);row["shared_epoch_manifest_bytes"]=json!(file.bytes.len());row["shared_epoch_manifest_sha256"]=json!(hex::encode(file.sha256)); }
        row
    }).collect();
    let report = json!({"version":1,"status":if failures.is_empty(){"complete"}else{"partial"},"source_prefix":catalog.source_prefix(),"generation":catalog.generation(),"input_manifest_sha256":hex::encode(sha256(&input_bytes)),"catalog_sha256":hex::encode(sha256(&catalog_bytes)),"catalog_load_micros":catalog_load_micros,"resolution_ram_cache":"not_started_or_used","raw_signature_bytes_read":0,"raw_signature_bytes_stored":0,"disk_reserve_bytes":reserve,"cold_read_note":"Local pread counts are file calls, not physical SSD read proof. Startup SHA checks can warm OS page cache. No HTTP or resolution result cache is used.","shared_body_codec":{"name":"SharedBlockV1","status":"proposed_measurement_representation","encoding":"wincode_leb128","field_order":["version:u16","epoch_manifest_sha256:[u8;32]","hot:ResolutionHotRow","parent_slot:u64","blockhash:[u8;32]","previous_blockhash:[u8;32]","signature_counts:Vec<u8>","access_suffix:Vec<u8>"],"rehydration":"Restore LocatorV1 and source objects from the exact epoch manifest. Derive access_prefix with existing block-access version, flags=0, current and previous hashes, signature counts, and raw signature length. Re-encode ResolutionV1; every record must match baseline bytes exactly."},"epochs":epochs,"records":records,"failures":failures});
    publish_new(
        &output.join("metrics.json"),
        &serde_json::to_vec_pretty(&report)?,
        reserve,
    )?;
    println!(
        "{}",
        json!({"metrics":output.join("metrics.json"),"records":records.len(),"failures":failures.len(),"raw_signature_bytes_read":0})
    );
    ensure!(
        failures.is_empty(),
        "measurement has {} failed samples; see metrics.json; do not project them",
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
    use blockzilla_archive_v2::ArchiveV2BlockAccessBlockhash;
    use blockzilla_get_block::slot_resolution::SourceObjectIdentity;

    fn fixture() -> ResolutionV1 {
        let blocks = SourceObjectIdentity {
            length: 100,
            etag: "\"hot\"".into(),
        };
        let signatures = SourceObjectIdentity {
            length: 64,
            etag: "\"sig\"".into(),
        };
        let locator = LocatorV1 {
            version: 1,
            source_prefix: "compact-v2/test".into(),
            generation: "measurement-fixture".into(),
            epoch: 1,
            hot: ResolutionHotRow {
                block_id: 0,
                slot: 432000,
                compressed_offset: 0,
                compressed_len: 100,
                uncompressed_len: 200,
                tx_count: 1,
                first_tx_ordinal: 0,
                first_signature_ordinal: 0,
                signature_count: 1,
            },
            parent_slot: 431999,
            blockhash: [9; 32],
            previous_blockhash: [8; 32],
            message_schema: 0,
            metadata_schema: 0,
            blocks: blocks.clone(),
            signatures: signatures.clone(),
        };
        ResolutionV1::from_resolved_tables(
            locator,
            vec![
                NamedSourceObject {
                    name: "archive-v2-blocks.zstd".into(),
                    identity: blocks,
                },
                NamedSourceObject {
                    name: "signatures.bin".into(),
                    identity: signatures,
                },
            ],
            &[1],
            &[],
            &[
                ArchiveV2BlockAccessBlockhash {
                    id: -1,
                    blockhash: [8; 32],
                },
                ArchiveV2BlockAccessBlockhash {
                    id: 0,
                    blockhash: [9; 32],
                },
            ],
            &[],
        )
        .unwrap()
    }

    #[test]
    fn shared_variant_reconstructs_exact_resolution_and_binds_manifest() {
        let resolution = fixture();
        let meta = SharedEpochV1::from_resolution(&resolution);
        let raw = serde_json::to_vec(&meta).unwrap();
        let body = SharedBlockV1 {
            version: 1,
            epoch_manifest_sha256: sha256(&raw),
            hot: resolution.locator.hot,
            parent_slot: resolution.locator.parent_slot,
            blockhash: resolution.locator.blockhash,
            previous_blockhash: resolution.locator.previous_blockhash,
            signature_counts: resolution.signature_counts.clone(),
            access_suffix: resolution.access_suffix.clone(),
        };
        let wire = wincode::config::serialize(&body, wincode_leb128_config()).unwrap();
        let decoded = wincode::config::deserialize_exact(
            &wire,
            bounded_wincode_leb128_config::<{ slot_resolution::MAX_RESOLUTION_BYTES }>(),
        )
        .unwrap();
        let restored = meta.rehydrate(decoded, &raw).unwrap();
        assert_eq!(
            slot_resolution::encode(&restored).unwrap(),
            slot_resolution::encode(&resolution).unwrap()
        );
        assert!(wire.len() < slot_resolution::encode(&resolution).unwrap().len());
        let decoded = wincode::config::deserialize_exact(
            &wire,
            bounded_wincode_leb128_config::<{ slot_resolution::MAX_RESOLUTION_BYTES }>(),
        )
        .unwrap();
        let mut changed = raw.clone();
        changed.push(b' ');
        assert!(meta.rehydrate(decoded, &changed).is_err());
    }

    #[test]
    fn reserve_parser_and_new_only_publication_are_checked() {
        assert_eq!(parse_available_bytes(b"Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/nvme0n1 20000 1000 19000 5% /\n").unwrap(),19000*1024);
        assert!(parse_available_bytes(b"invalid").is_err());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sample.wincode");
        publish_new(&path, b"first", 0).unwrap();
        assert!(publish_new(&path, b"other", 0).is_err());
        assert_eq!(fs::read(path).unwrap(), b"first");
        assert!(check_reserve(dir.path(), u64::MAX, 0).is_err());
    }

    #[test]
    fn offline_measurement_keeps_labels_omits_signatures_and_reports_unsupported_samples() {
        use blockzilla_archive_v2::{
            ArchiveV2HotBlockBlob, ArchiveV2HotBlockHeader, ArchiveV2HotBlockIndexRow,
            write_archive_v2_hot_block_index,
        };
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let mirror = root.join("mirror");
        let epoch = mirror.join("epoch-0");
        fs::create_dir_all(&epoch).unwrap();
        let hot = ArchiveV2HotBlockBlob {
            consensus_block_id: None,
            block_markers: Vec::new(),
            header: ArchiveV2HotBlockHeader {
                slot: 0,
                parent_slot: 0,
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
        let decoded = wincode::config::serialize(&hot, wincode_leb128_config()).unwrap();
        let compressed = zstd::bulk::compress(&decoded, 1).unwrap();
        fs::write(root.join("hot.zstd"), &compressed).unwrap();
        let row = ArchiveV2HotBlockIndexRow {
            block_id: 0,
            slot: 0,
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
        let mut objects = Vec::new();
        for name in [
            "archive-v2-blocks.index",
            "registry.bin",
            "vote_hash_registry.bin",
            "blockhash_registry.bin",
        ] {
            let path = epoch.join(name);
            let bytes = fs::read(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
            objects.push(json!({"name":name,"identity":{"length":bytes.len(),"etag":format!("\"{name}\"")},"relative_path":format!("epoch-0/{name}"),"sha256":hex::encode(sha256(&bytes))}));
        }
        objects.push(json!({"name":"archive-v2-blocks.zstd","identity":{"length":compressed.len(),"etag":"\"hot\""}}));
        objects.push(json!({"name":"signatures.bin","identity":{"length":0,"etag":"\"sig\""}}));
        fs::write(root.join("catalog.json"),serde_json::to_vec(&json!({"version":1,"source_prefix":"compact-v2/test","generation":"offline-fixture","epochs":[{"epoch":0,"message_schema":0,"metadata_schema":0,"tail_schema":"hash_and_slot40","objects":objects}]})).unwrap()).unwrap();
        let input = root.join("input.json");
        let manifest = json!({"version":1,"mirror_root":"mirror","catalog":"catalog.json","samples":[{"slot":0,"epoch":0,"hot_frame":"hot.zstd","control":true,"projection_eligible":true,"window":"window-0","sample_group":"overlap","custom_label":"preserved"}]});
        fs::write(&input, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let output = root.join("output");
        run(Args {
            manifest: input.clone(),
            output_dir: output.clone(),
            min_free_gib: 0,
        })
        .unwrap();
        let metrics: Value =
            serde_json::from_slice(&fs::read(output.join("metrics.json")).unwrap()).unwrap();
        assert_eq!(metrics["status"], "complete");
        assert_eq!(metrics["raw_signature_bytes_read"], 0);
        assert!(!epoch.join("signatures.bin").exists());
        let record = &metrics["records"][0];
        assert_eq!(record["control"], true);
        assert_eq!(record["projection_eligible"], true);
        assert_eq!(record["projection_excluded"], false);
        assert_eq!(record["custom_label"], "preserved");
        assert_eq!(record["window"], "window-0");
        assert_eq!(record["shared_rehydration_matches_baseline"], true);
        let mut bad = manifest;
        bad["samples"][0]["hot_sha256"] = json!("00".repeat(32));
        fs::write(&input, serde_json::to_vec(&bad).unwrap()).unwrap();
        let output = root.join("failed-output");
        assert!(
            run(Args {
                manifest: input,
                output_dir: output.clone(),
                min_free_gib: 0
            })
            .is_err()
        );
        let metrics: Value =
            serde_json::from_slice(&fs::read(output.join("metrics.json")).unwrap()).unwrap();
        assert_eq!(metrics["status"], "partial");
        assert!(metrics["records"].as_array().unwrap().is_empty());
        assert_eq!(metrics["failures"].as_array().unwrap().len(), 1);
    }
}
