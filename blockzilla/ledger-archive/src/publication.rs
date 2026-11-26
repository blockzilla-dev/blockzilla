//! Coverage and object identities for the GetBlock archive handoff.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::check::Inspected;
use crate::ledger::{EPOCH_ARCHIVE_FILES, SLOTS_PER_EPOCH, epoch_slot_range};
use crate::source::SlotData;

pub(crate) const LOCAL_COVERAGE_FILE: &str = "GETBLOCK-EPOCH-COVERAGE.json";
pub(crate) const READY_FILE: &str = "GETBLOCK-EPOCH-READY.json";
const MAX_RECORD_BYTES: u64 = 64 * 1024;
const COVERAGE_KIND: &str = "rooted-ledger-scan-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Sample {
    pub(crate) slot: u64,
    pub(crate) parent_slot: u64,
    pub(crate) blockhash: String,
    pub(crate) previous_blockhash: String,
}

impl Sample {
    pub(crate) fn from_block(block: &SlotData) -> Result<Self> {
        Ok(Self {
            slot: block.slot,
            parent_slot: block.parent_slot.context("sample block has no parent")?,
            blockhash: bs58::encode(block.blockhash).into_string(),
            previous_blockhash: bs58::encode(
                block
                    .previous_blockhash
                    .context("sample block has no parent hash")?,
            )
            .into_string(),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Coverage {
    kind: String,
    epoch_first_slot: u64,
    epoch_last_slot: u64,
    block_count: u64,
    first_block_slot: u64,
    last_block_slot: u64,
    slots_sha256: String,
    skipped_slot_count: u64,
    abandoned_fork_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalObject {
    pub(crate) length: u64,
    pub(crate) sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteObject {
    pub(crate) length: u64,
    pub(crate) etag: String,
    pub(crate) sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalCoverage {
    version: u8,
    epoch: u64,
    coverage: Coverage,
    samples: Vec<Sample>,
    successor: Sample,
    pub(crate) objects: BTreeMap<String, LocalObject>,
}

#[derive(Serialize)]
struct Ready<'a> {
    version: u8,
    epoch: u64,
    bucket: &'a str,
    source_prefix: &'a str,
    coverage: &'a Coverage,
    samples: &'a [Sample],
    successor: &'a Sample,
    message_schema: u8,
    metadata_schema: u8,
    tail_schema: &'static str,
    objects: &'a BTreeMap<String, RemoteObject>,
}

impl LocalCoverage {
    pub(crate) fn write(
        directory: &Path,
        epoch: u64,
        inspected: &Inspected,
        samples: Vec<Sample>,
        successor: Sample,
    ) -> Result<()> {
        let (epoch_first_slot, epoch_last_slot) = epoch_slot_range(epoch)?;
        let block_count = inspected.block_slots.len() as u64;
        let expected = sample_slots(&inspected.block_slots)?;
        ensure!(
            samples.iter().map(|sample| sample.slot).eq(expected),
            "archive samples differ from checked ledger slots"
        );
        let mut slots = Sha256::new();
        for slot in &inspected.block_slots {
            slots.update(slot.to_le_bytes());
        }
        let mut objects = BTreeMap::new();
        for name in EPOCH_ARCHIVE_FILES {
            let path = directory.join(name);
            let file = File::open(&path).with_context(|| format!("open {name} for coverage"))?;
            objects.insert(name.to_owned(), fingerprint(&path, &file)?);
        }
        let value = Self {
            version: 1,
            epoch,
            coverage: Coverage {
                kind: COVERAGE_KIND.to_owned(),
                epoch_first_slot,
                epoch_last_slot,
                block_count,
                first_block_slot: expected[0],
                last_block_slot: expected[2],
                slots_sha256: hex::encode(slots.finalize()),
                skipped_slot_count: inspected.skips.len() as u64,
                abandoned_fork_count: inspected.forks.len() as u64,
            },
            samples,
            successor,
            objects,
        };
        value.validate(epoch)?;
        let path = directory.join(LOCAL_COVERAGE_FILE);
        let temporary = path.with_extension("json.tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let result = (|| {
            serde_json::to_writer(&mut file, &value)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            // Publish only after the complete receipt has been written. The
            // existing receipt, if any, belongs to another build.
            fs::hard_link(&temporary, &path)?;
            File::open(directory)?.sync_all()?;
            Ok(())
        })();
        fs::remove_file(&temporary)?;
        result
    }

    pub(crate) fn read(directory: &Path, epoch: u64) -> Result<Option<Self>> {
        let path = directory.join(LOCAL_COVERAGE_FILE);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        ensure!(
            metadata.is_file() && metadata.len() <= MAX_RECORD_BYTES,
            "invalid local coverage file"
        );
        let mut bytes = Vec::new();
        File::open(&path)?
            .take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == metadata.len(),
            "local coverage file changed"
        );
        let value: Self = serde_json::from_slice(&bytes).context("parse local archive coverage")?;
        value.validate(epoch)?;
        Ok(Some(value))
    }

    pub(crate) fn ready_bytes(
        &self,
        bucket: &str,
        source_prefix: &str,
        objects: &BTreeMap<String, RemoteObject>,
    ) -> Result<Vec<u8>> {
        ensure!(
            objects.len() == self.objects.len()
                && self
                    .objects
                    .iter()
                    .all(|(name, file)| objects
                        .get(name)
                        .is_some_and(|remote| remote.length == file.length
                            && remote.sha256 == file.sha256
                            && valid_etag(&remote.etag))),
            "remote objects differ from the checked local archive"
        );
        let ready = Ready {
            version: self.version,
            epoch: self.epoch,
            bucket,
            source_prefix,
            coverage: &self.coverage,
            samples: &self.samples,
            successor: &self.successor,
            message_schema: 0,
            metadata_schema: 0,
            tail_schema: "hash_and_slot40",
            objects,
        };
        let mut bytes = serde_json::to_vec(&ready)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    fn validate(&self, epoch: u64) -> Result<()> {
        let (first, last) = epoch_slot_range(epoch)?;
        let coverage = &self.coverage;
        ensure!(
            self.version == 1
                && self.epoch == epoch
                && coverage.kind == COVERAGE_KIND
                && coverage.epoch_first_slot == first
                && coverage.epoch_last_slot == last
                && coverage.first_block_slot >= first
                && coverage.last_block_slot <= last
                && valid_digest(&coverage.slots_sha256)
                && coverage.block_count >= 3
                && coverage
                    .block_count
                    .checked_add(coverage.skipped_slot_count)
                    .and_then(|count| count.checked_add(coverage.abandoned_fork_count))
                    == Some(SLOTS_PER_EPOCH),
            "coverage does not describe a complete, closed epoch"
        );
        ensure!(
            self.samples.len() == 3
                && self.samples[0].slot == coverage.first_block_slot
                && self.samples[0].parent_slot < first
                && self.samples[2].slot == coverage.last_block_slot
                && self
                    .samples
                    .windows(2)
                    .all(|pair| pair[0].slot < pair[1].slot)
                && self.successor.slot > last
                && self.successor.parent_slot == coverage.last_block_slot
                && self.successor.previous_blockhash == self.samples[2].blockhash
                && self
                    .samples
                    .iter()
                    .chain([&self.successor])
                    .all(|sample| sample.parent_slot < sample.slot
                        && valid_blockhash(&sample.blockhash)
                        && valid_blockhash(&sample.previous_blockhash)),
            "invalid finalized block or boundary anchors"
        );
        ensure!(
            self.objects.len() == EPOCH_ARCHIVE_FILES.len()
                && EPOCH_ARCHIVE_FILES.iter().all(|name| self
                    .objects
                    .get(*name)
                    .is_some_and(|file| valid_digest(&file.sha256))),
            "invalid local archive file digests"
        );
        Ok(())
    }
}

pub(crate) fn sample_slots(slots: &[u64]) -> Result<[u64; 3]> {
    ensure!(
        slots.len() >= 3,
        "at least three rooted blocks are required for coverage"
    );
    Ok([slots[0], slots[slots.len() / 2], slots[slots.len() - 1]])
}

pub(crate) fn valid_etag(etag: &str) -> bool {
    let Some(opaque) = etag
        .strip_prefix('"')
        .and_then(|text| text.strip_suffix('"'))
    else {
        return false;
    };
    !opaque.is_empty()
        && opaque.len() <= 128
        && opaque
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"')
}

fn valid_blockhash(value: &str) -> bool {
    (32..=44).contains(&value.len())
        && bs58::decode(value)
            .into_vec()
            .is_ok_and(|bytes| bytes.len() == 32)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FileStamp {
    device: u64,
    inode: u64,
    length: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl FileStamp {
    fn from_meta(metadata: &fs::Metadata) -> Result<Self> {
        ensure!(metadata.is_file(), "archive object is not a regular file");
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }

    pub(crate) fn capture(path: &Path, file: &File) -> Result<Self> {
        let stamp = Self::from_meta(&file.metadata()?)?;
        stamp.check(path, file)?;
        Ok(stamp)
    }

    pub(crate) fn check(&self, path: &Path, file: &File) -> Result<()> {
        ensure!(
            *self == Self::from_meta(&fs::symlink_metadata(path)?)?
                && *self == Self::from_meta(&file.metadata()?)?,
            "{} changed while verifying archive coverage",
            path.display()
        );
        Ok(())
    }
}

fn fingerprint(path: &Path, file: &File) -> Result<LocalObject> {
    let stamp = FileStamp::capture(path, file)?;
    let sha256 = digest_exact(file, stamp.length)?;
    stamp.check(path, file)?;
    Ok(LocalObject {
        length: stamp.length,
        sha256,
    })
}

pub(crate) fn digest_exact(mut reader: impl Read, length: u64) -> Result<String> {
    let mut hash = Sha256::new();
    let mut buffer = vec![0; 1024 * 1024];
    let mut remaining = length;
    while remaining > 0 {
        let requested = remaining.min(buffer.len() as u64) as usize;
        let count = reader.read(&mut buffer[..requested])?;
        ensure!(count > 0, "archive object ended before its declared length");
        hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    ensure!(
        reader.read(&mut buffer[..1])? == 0,
        "archive object exceeds its declared length"
    );
    Ok(hex::encode(hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> String {
        bs58::encode([byte; 32]).into_string()
    }

    fn fixtures(epoch: u64) -> (Inspected, Vec<Sample>, Sample) {
        let (start, end) = epoch_slot_range(epoch).unwrap();
        let slots = [start + 1, start + 24, end - 1];
        let sample = |slot, parent_slot, number| Sample {
            slot,
            parent_slot,
            blockhash: hash(number),
            previous_blockhash: hash(number - 1),
        };
        let ledger = Inspected {
            block_slots: slots.to_vec(),
            skips: (start..=end).filter(|slot| !slots.contains(slot)).collect(),
            forks: vec![],
            boundary_hash: [1; 32],
        };
        let samples = vec![
            sample(slots[0], start - 1, 2),
            sample(slots[1], slots[0], 3),
            sample(slots[2], slots[1], 4),
        ];
        (ledger, samples, sample(end + 1, slots[2], 5))
    }

    fn archive_files(directory: &Path) {
        for name in EPOCH_ARCHIVE_FILES {
            fs::write(directory.join(name), name).unwrap();
        }
    }

    #[test]
    fn closed_coverage_binds_exact_slot_order_and_remote_object_identities() {
        let epoch = 1094;
        let (ledger, samples, successor) = fixtures(epoch);
        let directory = tempfile::tempdir().unwrap();
        archive_files(directory.path());
        LocalCoverage::write(directory.path(), epoch, &ledger, samples, successor).unwrap();
        let sealed = LocalCoverage::read(directory.path(), epoch)
            .unwrap()
            .unwrap();
        let expected = Sha256::digest(
            ledger
                .block_slots
                .iter()
                .flat_map(|slot| slot.to_le_bytes())
                .collect::<Vec<_>>(),
        );
        assert_eq!(sealed.coverage.slots_sha256, hex::encode(expected));

        let mut objects: BTreeMap<_, _> = sealed
            .objects
            .iter()
            .map(|(name, object)| {
                (
                    name.clone(),
                    RemoteObject {
                        length: object.length,
                        sha256: object.sha256.clone(),
                        etag: "\"opaque\"".to_owned(),
                    },
                )
            })
            .collect();
        let receipt = sealed
            .ready_bytes("bucket", "compact-v2/test", &objects)
            .unwrap();
        let ready: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
        assert_eq!(ready["epoch"], epoch);
        assert_eq!(ready["coverage"]["kind"], COVERAGE_KIND);
        assert_eq!(ready["source_prefix"], "compact-v2/test");
        assert_eq!(ready["coverage"]["slots_sha256"], hex::encode(expected));
        assert_eq!(ready["samples"][1]["slot"], ledger.block_slots[1]);
        assert_eq!(ready["successor"]["parent_slot"], ledger.block_slots[2]);
        assert_eq!(
            ready["objects"].as_object().unwrap().len(),
            EPOCH_ARCHIVE_FILES.len()
        );

        let object = objects.values_mut().next().unwrap();
        object.etag = "W/\"weak\"".to_owned();
        assert!(
            sealed
                .ready_bytes("bucket", "compact-v2/test", &objects)
                .is_err()
        );
        let object = objects.values_mut().next().unwrap();
        object.etag = "\"changed\"".to_owned();
        object.sha256 = "0".repeat(64);
        assert!(
            sealed
                .ready_bytes("bucket", "compact-v2/test", &objects)
                .is_err()
        );
        assert!(LocalCoverage::read(directory.path(), epoch + 1).is_err());
    }

    #[test]
    fn a_gap_or_wrong_successor_cannot_publish_a_coverage_file() {
        let epoch = 1094;
        let (mut ledger, samples, mut successor) = fixtures(epoch);
        let directory = tempfile::tempdir().unwrap();
        archive_files(directory.path());
        let skipped = ledger.skips.pop().unwrap();
        let error = LocalCoverage::write(
            directory.path(),
            epoch,
            &ledger,
            samples.clone(),
            successor.clone(),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("complete, closed epoch"),
            "{error:#}"
        );
        assert!(
            LocalCoverage::read(directory.path(), epoch)
                .unwrap()
                .is_none()
        );

        ledger.skips.push(skipped);
        successor.previous_blockhash = hash(7);
        let error =
            LocalCoverage::write(directory.path(), epoch, &ledger, samples, successor).unwrap_err();
        assert!(error.to_string().contains("boundary anchors"), "{error:#}");
        assert!(
            LocalCoverage::read(directory.path(), epoch)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn object_digests_reject_truncated_and_excess_bytes() {
        assert_eq!(
            digest_exact(&b"published"[..], 9).unwrap(),
            hex::encode(Sha256::digest(b"published"))
        );
        assert!(digest_exact(&b"published"[..], 8).is_err());
        assert!(digest_exact(&b"published"[..], 10).is_err());
    }
}
