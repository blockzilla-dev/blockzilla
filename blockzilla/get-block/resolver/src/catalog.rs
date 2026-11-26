//! Immutable, local ID tables with source-bound remote block descriptors.
use crate::Resolved;
use anyhow::{Context, Result, anyhow, ensure};
use blockzilla_archive_v2::{
    ARCHIVE_V2_HOT_INDEX_HEADER_LEN, ARCHIVE_V2_HOT_INDEX_ROW_LEN, ArchiveV2HotBlockIndexRow,
    read_archive_v2_hot_block_index_file,
};
use blockzilla_get_block::{
    foundation_protocol::{PendingLocatorV1, ResolveRequestV1},
    slot_references::{self, TailSchema},
    slot_resolution::{LocatorV1, NamedSourceObject, SourceObjectIdentity},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, Metadata},
    io::{self, Read},
    os::unix::fs::{FileExt, MetadataExt},
    path::{Component, Path, PathBuf},
};

pub(crate) const SLOTS: u64 = 432_000;
const MAX_CATALOG_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EPOCHS: usize = 4096;
const BLOCKS: &str = "archive-v2-blocks.zstd";
const SIGNATURES: &str = "signatures.bin";
const INDEX: &str = "archive-v2-blocks.index";
const KEYS: &str = "registry.bin";
const HASHES: &str = "blockhash_registry.bin";
const VOTES: &str = "vote_hash_registry.bin";
const TAIL: &str = "prev_blockhash_tail.bin";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u16,
    source_prefix: String,
    generation: String,
    epochs: Vec<EpochManifest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EpochManifest {
    epoch: u64,
    message_schema: u8,
    metadata_schema: u8,
    tail_schema: TailSchema,
    objects: Vec<ObjectManifest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectManifest {
    name: String,
    identity: SourceObjectIdentity,
    relative_path: Option<String>,
    sha256: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    bytes: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
    mode: u32,
}

impl Stamp {
    fn read(meta: &Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            bytes: meta.len(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            ctime: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
            mode: meta.mode(),
        }
    }
}

struct PinnedFile {
    file: File,
    stamp: Stamp,
}

impl PinnedFile {
    fn open(
        root: &Path,
        relative: &str,
        expected: &SourceObjectIdentity,
        sha: &str,
    ) -> Result<Self> {
        let path = checked_path(root, relative)?;
        ensure!(valid_digest(sha), "invalid local object SHA256");
        let file = File::open(&path).with_context(|| format!("open local index {relative}"))?;
        let meta = file.metadata()?;
        ensure!(
            meta.is_file() && meta.len() == expected.length,
            "local index type or length differs"
        );
        ensure!(meta.mode() & 0o222 == 0, "local index must be read-only");
        let stamp = Stamp::read(&meta);
        let mut digest = Sha256::new();
        let mut buffer = vec![0u8; 1024 * 1024];
        let mut offset = 0u64;
        while offset < expected.length {
            let length = usize::try_from((expected.length - offset).min(buffer.len() as u64))?;
            file.read_exact_at(&mut buffer[..length], offset)?;
            digest.update(&buffer[..length]);
            offset += length as u64;
        }
        ensure!(
            hex::encode(digest.finalize()) == sha,
            "local index SHA256 differs"
        );
        ensure!(
            stamp == Stamp::read(&file.metadata()?),
            "local index changed during startup verification"
        );
        Ok(Self { file, stamp })
    }

    fn check(&self) -> Result<()> {
        ensure!(
            self.stamp == Stamp::read(&self.file.metadata()?),
            "admitted local index changed"
        );
        Ok(())
    }

    fn read(
        &self,
        offset: u64,
        length: usize,
        calls: &mut u64,
        bytes: &mut u64,
    ) -> Result<Vec<u8>> {
        ensure!(
            offset
                .checked_add(length as u64)
                .is_some_and(|end| end <= self.stamp.bytes),
            "local index range exceeds its pinned length"
        );
        let mut data = vec![0u8; length];
        let mut at = 0;
        while at < length {
            *calls = calls.checked_add(1).context("pread call count overflows")?;
            match self.file.read_at(&mut data[at..], offset + at as u64) {
                Ok(0) => return Err(anyhow!("short pinned local index read")),
                Ok(count) => {
                    at += count;
                    *bytes = bytes
                        .checked_add(count as u64)
                        .context("pread byte count overflows")?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(data)
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn checked_path(root: &Path, relative: &str) -> Result<PathBuf> {
    ensure!(
        !relative.is_empty() && relative.len() <= 1024,
        "invalid local index path"
    );
    let mut out = root.to_owned();
    for part in Path::new(relative).components() {
        let Component::Normal(part) = part else {
            return Err(anyhow!("local index path escapes the mirror"));
        };
        out.push(part);
        ensure!(
            !fs::symlink_metadata(&out)?.file_type().is_symlink(),
            "local index symlink is not allowed"
        );
    }
    ensure!(
        out.starts_with(root) && out.canonicalize()? == out,
        "local index path escapes the mirror"
    );
    Ok(out)
}

struct Epoch {
    epoch: u64,
    message_schema: u8,
    metadata_schema: u8,
    tail_schema: TailSchema,
    identities: Vec<NamedSourceObject>,
    files: BTreeMap<String, PinnedFile>,
    rows: Vec<ArchiveV2HotBlockIndexRow>,
    hash_prefix: u32,
    first_parent: Option<(u64, [u8; 32])>,
}

impl Epoch {
    fn identity(&self, name: &str) -> Result<&SourceObjectIdentity> {
        self.identities
            .iter()
            .find(|o| o.name == name)
            .map(|o| &o.identity)
            .with_context(|| format!("missing source identity {name}"))
    }

    fn check_files(&self) -> Result<()> {
        for file in self.files.values() {
            file.check()?;
        }
        Ok(())
    }

    fn pending(
        &self,
        prefix: &str,
        generation: &str,
        row: ArchiveV2HotBlockIndexRow,
    ) -> Result<PendingLocatorV1> {
        Ok(PendingLocatorV1 {
            version: 1,
            source_prefix: prefix.into(),
            generation: generation.into(),
            epoch: self.epoch,
            hot: row.into(),
            message_schema: self.message_schema,
            metadata_schema: self.metadata_schema,
            blocks: self.identity(BLOCKS)?.clone(),
            signatures: self.identity(SIGNATURES)?.clone(),
        })
    }
}

pub struct Catalog {
    source_prefix: String,
    generation: String,
    epochs: BTreeMap<u64, Epoch>,
}

impl Catalog {
    pub fn load(mirror_root: &Path, catalog_path: &Path) -> Result<Self> {
        ensure!(
            fs::symlink_metadata(mirror_root)?.is_dir(),
            "mirror root must be a real directory"
        );
        let root = mirror_root.canonicalize()?;
        ensure!(
            !fs::symlink_metadata(catalog_path)?.file_type().is_symlink(),
            "catalog symlink is not allowed"
        );
        let mut raw = Vec::new();
        File::open(catalog_path)?
            .take(MAX_CATALOG_BYTES + 1)
            .read_to_end(&mut raw)?;
        ensure!(
            raw.len() as u64 <= MAX_CATALOG_BYTES,
            "catalog exceeds its byte bound"
        );
        let manifest: Manifest = serde_json::from_slice(&raw)?;
        ensure!(
            manifest.version == 1
                && !manifest.epochs.is_empty()
                && manifest.epochs.len() <= MAX_EPOCHS,
            "catalog version or epoch count is invalid"
        );
        let mut catalog = Self {
            source_prefix: manifest.source_prefix,
            generation: manifest.generation,
            epochs: BTreeMap::new(),
        };
        for spec in manifest.epochs {
            let epoch = load_epoch(&root, spec)?;
            for row in &epoch.rows {
                epoch
                    .pending(&catalog.source_prefix, &catalog.generation, *row)?
                    .validate_source_geometry(&catalog.source_prefix, &catalog.generation, row.slot)
                    .map_err(|e| anyhow!(e))?;
            }
            ensure!(
                catalog.epochs.insert(epoch.epoch, epoch).is_none(),
                "duplicate catalog epoch"
            );
        }
        Ok(catalog)
    }

    pub fn source_prefix(&self) -> &str {
        &self.source_prefix
    }
    pub fn generation(&self) -> &str {
        &self.generation
    }

    pub fn has_epoch(&self, epoch: u64) -> bool {
        self.epochs.contains_key(&epoch)
    }

    /// All lookups here use startup-checked RAM rows. No file reads or locks.
    pub fn pending(&self, slot: u64) -> Result<Option<PendingLocatorV1>> {
        let Some(epoch) = self.epochs.get(&(slot / SLOTS)) else {
            return Ok(None);
        };
        let Ok(at) = epoch.rows.binary_search_by_key(&slot, |row| row.slot) else {
            return Ok(None);
        };
        let pending = epoch.pending(&self.source_prefix, &self.generation, epoch.rows[at])?;
        pending
            .validate(&self.source_prefix, &self.generation, slot)
            .map_err(|e| anyhow!(e))?;
        Ok(Some(pending))
    }

    /// One pinned 32-byte read. No hot frame or signature data is read.
    pub fn archived_blockhash(&self, slot: u64) -> Result<Option<[u8; 32]>> {
        let Some(pending) = self.pending(slot)? else {
            return Ok(None);
        };
        let epoch = self
            .epochs
            .get(&pending.epoch)
            .context("catalog epoch missing")?;
        let id = u64::from(pending.hot.block_id)
            .checked_add(u64::from(epoch.hash_prefix))
            .context("block hash offset overflows")?;
        let file = epoch
            .files
            .get(HASHES)
            .context("block hash table missing")?;
        file.check()?;
        let (mut calls, mut bytes) = (0, 0);
        let raw = file.read(
            id.checked_mul(32).context("block hash offset overflows")?,
            32,
            &mut calls,
            &mut bytes,
        )?;
        file.check()?;
        Ok(Some(raw.try_into().expect("checked hash width")))
    }

    pub fn resolve(&self, request: &ResolveRequestV1) -> Result<Resolved> {
        let slot = request.source.hot.slot;
        request
            .validate(&self.source_prefix, &self.generation, slot)
            .map_err(|e| anyhow!(e))?;
        let pending = self
            .pending(slot)?
            .context("slot is outside the admitted catalog")?;
        ensure!(
            request.source == pending,
            "request source differs from the admitted catalog"
        );
        let epoch = self
            .epochs
            .get(&pending.epoch)
            .context("catalog epoch missing")?;
        let ordinal = usize::try_from(pending.hot.block_id)?;
        let row = *epoch.rows.get(ordinal).context("catalog ordinal missing")?;
        let refs = &request.references;
        let current_id = row
            .block_id
            .checked_add(epoch.hash_prefix)
            .context("header hash ID overflows")?;
        let previous_id = current_id.saturating_sub(1);
        ensure!(
            refs.blockhash_id == current_id && refs.previous_blockhash_id == previous_id,
            "header hash IDs differ from the admitted block ordinal"
        );
        if ordinal > 0 {
            ensure!(
                refs.parent_slot == epoch.rows[ordinal - 1].slot,
                "parent slot differs from the prior archived block"
            );
        } else if let Some((parent_slot, _)) = epoch.first_parent {
            ensure!(
                refs.parent_slot == parent_slot,
                "first parent slot differs from the pinned predecessor tail"
            );
        }
        epoch.check_files()?;
        let mut pread_calls = 0u64;
        let mut pread_bytes = 0u64;
        let tables = slot_references::resolve(
            refs,
            &row,
            &epoch.identities,
            epoch.tail_schema,
            |name, offset, length| {
                epoch
                    .files
                    .get(name)
                    .ok_or_else(|| "requested table is not locally admitted".to_string())?
                    .read(offset, length, &mut pread_calls, &mut pread_bytes)
                    .map_err(|e| e.to_string())
            },
        )
        .map_err(|e| anyhow!(e))?;
        if ordinal == 0
            && let Some((_, expected)) = epoch.first_parent
        {
            ensure!(
                tables.previous_blockhash == expected,
                "first parent hash differs from the pinned predecessor tail"
            );
        }
        let locator = LocatorV1 {
            version: 1,
            source_prefix: self.source_prefix.clone(),
            generation: self.generation.clone(),
            epoch: epoch.epoch,
            hot: pending.hot,
            parent_slot: refs.parent_slot,
            blockhash: tables.blockhash,
            previous_blockhash: tables.previous_blockhash,
            message_schema: epoch.message_schema,
            metadata_schema: epoch.metadata_schema,
            blocks: pending.blocks,
            signatures: pending.signatures,
        };
        let resolution = tables
            .into_resolution(refs, locator, epoch.identities.clone())
            .map_err(|e| anyhow!(e))?;
        epoch.check_files()?;
        Ok(Resolved {
            resolution,
            pread_calls,
            pread_bytes,
        })
    }
}

fn load_epoch(root: &Path, spec: EpochManifest) -> Result<Epoch> {
    ensure!(
        spec.message_schema <= 1 && spec.metadata_schema <= 1,
        "unsupported catalog schemas"
    );
    ensure!(
        (2..=32).contains(&spec.objects.len()),
        "catalog source object count exceeds its bound"
    );
    let first_slot = spec
        .epoch
        .checked_mul(SLOTS)
        .context("catalog epoch overflows")?;
    let last_slot = first_slot
        .checked_add(SLOTS - 1)
        .context("catalog epoch end overflows")?;
    let mut files = BTreeMap::new();
    let mut identities = BTreeMap::new();
    for object in spec.objects {
        object.identity.validate().map_err(|e| anyhow!(e))?;
        let name = object.name;
        ensure!(
            !name.is_empty()
                && name.len() <= 128
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
            "source object name must be flat"
        );
        ensure!(
            identities
                .insert(name.clone(), object.identity.clone())
                .is_none(),
            "duplicate source object"
        );
        match name.as_str() {
            BLOCKS | SIGNATURES => ensure!(
                object.relative_path.is_none(),
                "hot and signature payloads must stay remote"
            ),
            INDEX
            | KEYS
            | HASHES
            | VOTES
            | TAIL
            | "archive-v2-meta.wincode"
            | "registry-first-seen.manifest"
            | "genesis.bin"
            | "archive-v2-message-schema-current-v1.marker"
            | "archive-v2-message-schema-may24-pre-unknown-fallbacks-v1.marker"
            | "archive-v2-metadata-schema-legacy-raw-error-v1.marker" => {
                let relative = object
                    .relative_path
                    .context("local table requires a relative path")?;
                ensure!(
                    relative == format!("epoch-{}/{name}", spec.epoch),
                    "local table path differs from its epoch/name"
                );
                let sha = object.sha256.context("local table requires SHA256")?;
                files.insert(
                    name,
                    PinnedFile::open(root, &relative, &object.identity, &sha)?,
                );
            }
            _ => return Err(anyhow!("unsupported local catalog object")),
        }
    }
    for name in [BLOCKS, SIGNATURES, INDEX, KEYS, HASHES, VOTES] {
        ensure!(
            identities.contains_key(name),
            "catalog misses required source {name}"
        );
    }
    ensure!(
        identities[INDEX].length
            <= ARCHIVE_V2_HOT_INDEX_HEADER_LEN as u64 + SLOTS * ARCHIVE_V2_HOT_INDEX_ROW_LEN as u64,
        "hot index exceeds one epoch"
    );
    let index_file = files.get(INDEX).context("hot index is not local")?;
    let index =
        read_archive_v2_hot_block_index_file(index_file.file.try_clone()?, Path::new(INDEX))?;
    ensure!(
        index.flags == 0 && !index.rows.is_empty() && index.rows.len() <= SLOTS as usize,
        "catalog requires bounded independent-zstd blocks"
    );
    ensure!(
        index.blob_file_bytes == identities[BLOCKS].length,
        "hot index payload length differs"
    );
    let (mut offset, mut tx, mut signatures) = (0u64, 0u64, 0u64);
    let mut prior_slot = None;
    for (at, row) in index.rows.iter().enumerate() {
        ensure!(
            row.block_id as usize == at
                && (first_slot..=last_slot).contains(&row.slot)
                && prior_slot.is_none_or(|value| value < row.slot),
            "hot index ordinal/slot order differs"
        );
        ensure!(
            row.compressed_offset == offset
                && row.first_tx_ordinal == tx
                && row.first_signature_ordinal == signatures,
            "hot index offsets or ordinals are discontinuous"
        );
        offset = offset
            .checked_add(u64::from(row.compressed_len))
            .context("hot range overflows")?;
        tx = tx
            .checked_add(u64::from(row.tx_count))
            .context("transaction ordinal overflows")?;
        signatures = signatures
            .checked_add(u64::from(row.signature_count))
            .context("signature ordinal overflows")?;
        prior_slot = Some(row.slot);
    }
    ensure!(
        offset == identities[BLOCKS].length
            && signatures.checked_mul(64) == Some(identities[SIGNATURES].length),
        "hot or signature total differs from source identity"
    );
    ensure!(
        identities[KEYS].length.is_multiple_of(32)
            && identities[HASHES].length.is_multiple_of(32)
            && identities[VOTES].length.is_multiple_of(65),
        "fixed-width table length differs"
    );
    let hashes = identities[HASHES].length / 32;
    ensure!(
        hashes == index.rows.len() as u64 || hashes == index.rows.len() as u64 + 1,
        "blockhash registry count differs from block index"
    );
    let hash_prefix = u32::from(hashes == index.rows.len() as u64 + 1);
    let mut first_parent = None;
    if let Some(tail) = files.get(TAIL) {
        let width = match spec.tail_schema {
            TailSchema::HashOnly32 => 32,
            TailSchema::HashAndSlot40 => 40,
        };
        ensure!(
            tail.stamp.bytes <= 300 * width && tail.stamp.bytes.is_multiple_of(width),
            "predecessor tail has invalid bounds"
        );
        if width == 40 && tail.stamp.bytes > 0 {
            let (mut calls, mut bytes) = (0, 0);
            let raw = tail.read(0, tail.stamp.bytes as usize, &mut calls, &mut bytes)?;
            let mut previous = None;
            for record in raw.chunks_exact(40) {
                let slot = u64::from_le_bytes(record[32..40].try_into()?);
                ensure!(
                    slot < first_slot
                        && slot >= first_slot.saturating_sub(SLOTS)
                        && previous.is_none_or(|value| value < slot),
                    "predecessor tail slots differ from the previous epoch"
                );
                previous = Some(slot);
                first_parent = Some((slot, record[..32].try_into()?));
            }
        }
    }
    let epoch = Epoch {
        epoch: spec.epoch,
        message_schema: spec.message_schema,
        metadata_schema: spec.metadata_schema,
        tail_schema: spec.tail_schema,
        identities: identities
            .into_iter()
            .map(|(name, identity)| NamedSourceObject { name, identity })
            .collect(),
        files,
        rows: index.rows,
        hash_prefix,
        first_parent,
    };
    epoch.check_files()?;
    Ok(epoch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use blockzilla_archive_v2::write_archive_v2_hot_block_index;
    use blockzilla_get_block::slot_references::SlotReferences;
    use serde_json::{Value, json};
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("epoch-1");
        fs::create_dir(&directory).unwrap();
        let rows = [
            ArchiveV2HotBlockIndexRow {
                block_id: 0,
                slot: SLOTS,
                compressed_offset: 0,
                compressed_len: 4,
                uncompressed_len: 40,
                tx_count: 1,
                first_tx_ordinal: 0,
                first_signature_ordinal: 0,
                signature_count: 1,
            },
            ArchiveV2HotBlockIndexRow {
                block_id: 1,
                slot: SLOTS + 2,
                compressed_offset: 4,
                compressed_len: 5,
                uncompressed_len: 50,
                tx_count: 1,
                first_tx_ordinal: 1,
                first_signature_ordinal: 1,
                signature_count: 1,
            },
        ];
        write_archive_v2_hot_block_index(&directory.join(INDEX), 9, 1, 0, &rows).unwrap();
        fs::write(directory.join(KEYS), [[1u8; 32], [2; 32]].concat()).unwrap();
        fs::write(
            directory.join(HASHES),
            [[9u8; 32], [10; 32], [11; 32]].concat(),
        )
        .unwrap();
        fs::write(directory.join(VOTES), [0u8; 130]).unwrap();
        let mut tail = [9u8; 32].to_vec();
        tail.extend_from_slice(&(SLOTS - 1).to_le_bytes());
        fs::write(directory.join(TAIL), tail).unwrap();
        fs::write(directory.join("archive-v2-meta.wincode"), [0u8; 64]).unwrap();
        let mut objects = Vec::new();
        for name in [INDEX, KEYS, HASHES, VOTES, TAIL, "archive-v2-meta.wincode"] {
            let path = directory.join(name);
            let bytes = fs::read(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
            objects.push(json!({"name":name,"identity":{"length":bytes.len(),"etag":format!("\"{name}\"")},
                "relative_path":format!("epoch-1/{name}"),"sha256":hex::encode(Sha256::digest(&bytes))}));
        }
        objects.push(json!({"name":BLOCKS,"identity":{"length":9,"etag":"\"blocks\""}}));
        objects.push(json!({"name":SIGNATURES,"identity":{"length":128,"etag":"\"signatures\""}}));
        let value = json!({"version":1,"source_prefix":"compact-v2/test","generation":"test-v1",
            "epochs":[{"epoch":1,"message_schema":0,"metadata_schema":0,"tail_schema":"hash_and_slot40","objects":objects}]});
        let path = temp.path().join("catalog.json");
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        (temp, path)
    }

    fn request(catalog: &Catalog, slot: u64) -> ResolveRequestV1 {
        let first = slot == SLOTS;
        ResolveRequestV1 {
            version: 1,
            source: catalog.pending(slot).unwrap().unwrap(),
            hot_sha256: "ab".repeat(32),
            references: SlotReferences {
                slot,
                parent_slot: if first { SLOTS - 1 } else { SLOTS },
                blockhash_id: if first { 1 } else { 2 },
                previous_blockhash_id: if first { 0 } else { 1 },
                signature_counts: vec![1],
                pubkeys: vec![1, 2],
                blockhashes: if first { vec![0, 1] } else { vec![1, 2] },
                votes: vec![],
            },
        }
    }

    #[test]
    fn resolves_only_local_id_windows_and_preserves_real_parent() {
        let (temp, path) = fixture();
        let catalog = Catalog::load(temp.path(), &path).unwrap();
        assert!(catalog.pending(SLOTS + 1).unwrap().is_none());
        assert!(catalog.pending(SLOTS * 2).unwrap().is_none());
        for slot in [SLOTS, SLOTS + 2] {
            let resolved = catalog.resolve(&request(&catalog, slot)).unwrap();
            let locator = &resolved.resolution.locator;
            assert_eq!(locator.blockhash, [if slot == SLOTS { 10 } else { 11 }; 32]);
            assert_eq!(
                locator.previous_blockhash,
                [if slot == SLOTS { 9 } else { 10 }; 32]
            );
            assert_eq!(resolved.pread_calls, 2);
            assert_eq!(resolved.pread_bytes, 128);
            assert_eq!(resolved.resolution.signature_counts, [1]);
        }
    }

    #[test]
    fn oversized_unselected_reward_row_does_not_reject_the_epoch() {
        for (compressed, decoded) in [(16 * 1024 * 1024 + 1, 40), (4, 32 * 1024 * 1024 + 1)] {
            let (temp, path) = fixture();
            let index_path = temp.path().join("epoch-1").join(INDEX);
            let mut index = read_archive_v2_hot_block_index_file(
                File::open(&index_path).unwrap(),
                Path::new(INDEX),
            )
            .unwrap();
            index.rows[0].compressed_len = compressed;
            index.rows[0].uncompressed_len = decoded;
            index.rows[1].compressed_offset = u64::from(compressed);
            let blob_bytes = u64::from(compressed) + u64::from(index.rows[1].compressed_len);
            fs::set_permissions(&index_path, fs::Permissions::from_mode(0o644)).unwrap();
            write_archive_v2_hot_block_index(&index_path, blob_bytes, 1, 0, &index.rows).unwrap();
            fs::set_permissions(&index_path, fs::Permissions::from_mode(0o444)).unwrap();
            let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            for object in value["epochs"][0]["objects"].as_array_mut().unwrap() {
                if object["name"] == INDEX {
                    object["sha256"] =
                        json!(hex::encode(Sha256::digest(fs::read(&index_path).unwrap())));
                } else if object["name"] == BLOCKS {
                    object["identity"]["length"] = json!(blob_bytes);
                }
            }
            fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            let catalog = Catalog::load(temp.path(), &path).unwrap();
            let normal = request(&catalog, SLOTS + 2);
            assert!(catalog.resolve(&normal).is_ok());
            assert!(catalog.pending(SLOTS).is_err());
            let epoch = catalog.epochs.get(&1).unwrap();
            let oversized = epoch
                .pending(catalog.source_prefix(), catalog.generation(), epoch.rows[0])
                .unwrap();
            assert!(
                oversized
                    .validate_source_geometry(catalog.source_prefix(), catalog.generation(), SLOTS)
                    .is_ok()
            );
            assert!(
                oversized
                    .validate(catalog.source_prefix(), catalog.generation(), SLOTS)
                    .is_err()
            );
            let mut selected = normal;
            selected.source = oversized;
            selected.references.slot = SLOTS;
            assert!(catalog.resolve(&selected).is_err());
        }
    }

    #[test]
    fn source_parent_and_hash_ordinal_mismatches_fail_before_resolution() {
        let (temp, path) = fixture();
        let catalog = Catalog::load(temp.path(), &path).unwrap();
        let mut bad = request(&catalog, SLOTS);
        bad.source.blocks.etag = "\"other\"".into();
        assert!(catalog.resolve(&bad).is_err());
        let mut bad = request(&catalog, SLOTS);
        bad.references.parent_slot -= 1;
        assert!(catalog.resolve(&bad).is_err());
        let mut bad = request(&catalog, SLOTS);
        bad.references.blockhash_id = 2;
        bad.references.blockhashes = vec![0, 2];
        assert!(catalog.resolve(&bad).is_err());
        let mut bad = request(&catalog, SLOTS + 2);
        bad.references.parent_slot = SLOTS - 1;
        assert!(catalog.resolve(&bad).is_err());
    }

    #[test]
    fn startup_rejects_sha_mutability_and_symlink_mismatches() {
        let (temp, path) = fixture();
        let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["epochs"][0]["objects"][0]["sha256"] = json!("00".repeat(32));
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(Catalog::load(temp.path(), &path).is_err());
        let (temp, path) = fixture();
        fs::set_permissions(
            temp.path().join("epoch-1").join(KEYS),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(Catalog::load(temp.path(), &path).is_err());
        let (temp, path) = fixture();
        let original = temp.path().join("epoch-1").join(KEYS);
        fs::rename(&original, temp.path().join("keys.bin")).unwrap();
        symlink(temp.path().join("keys.bin"), &original).unwrap();
        assert!(Catalog::load(temp.path(), &path).is_err());
    }

    #[test]
    fn pending_needs_no_files_but_resolve_rejects_post_startup_mutation() {
        let (temp, path) = fixture();
        let catalog = Catalog::load(temp.path(), &path).unwrap();
        let good = request(&catalog, SLOTS);
        let key_path = temp.path().join("epoch-1").join(KEYS);
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(&key_path, [7u8; 64]).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(catalog.resolve(&good).is_err());
        fs::remove_dir_all(temp.path().join("epoch-1")).unwrap();
        assert_eq!(catalog.pending(SLOTS).unwrap(), Some(good.source));
    }
}
