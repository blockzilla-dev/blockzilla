//! Complete bank payloads are immutable. Roots select payloads; they never rebuild them.
use crate::{
    event::{REVISION, SCHEMA, digest},
    journal::{atomic_json, open_reader},
    worker::{self, BlockRow, RawEvidence},
};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const PROFILE: &str = "native-processed-compact-v1";
const MAX_ACTIVE: u64 = 4096;
const LIVE_ROLE: &str = "native-live-only-canary-v1";
pub const CONTINUOUS_ROLE: &str = "native-live-continuous-v1";
pub const PROCESSED_RELEASE_SCHEMA: &str = "hivezilla-processed-release-v1";
pub const PROCESSED_RELEASE_RECEIPT_SCHEMA: &str = "hivezilla-processed-release-receipt-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuousLiveOptions {
    /// Desired downstream replay window. This is not a lifetime counter.
    pub retained_banks: u64,
    pub retained_events: u64,
    pub max_output_bytes: u64,
    pub min_retention_ms: u64,
    /// Includes incomplete Banks and forks awaiting safe release.
    pub max_retained_banks: u64,
    pub release_checkpoint: PathBuf,
    pub required_consumer: String,
}
impl ContinuousLiveOptions {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=MAX_ACTIVE).contains(&self.max_retained_banks),
            "invalid continuous retained Bank capacity"
        );
        ensure!(
            self.retained_banks > 0 && self.retained_banks < self.max_retained_banks,
            "continuous replay window needs retained Bank headroom"
        );
        ensure!(
            (1..=10_000_000).contains(&self.retained_events),
            "invalid continuous retained event capacity"
        );
        ensure!(
            (1024 * 1024..=64 * 1024u64.pow(3)).contains(&self.max_output_bytes),
            "invalid continuous byte capacity"
        );
        ensure!(
            self.min_retention_ms <= 3_600_000,
            "invalid continuous minimum retention age"
        );
        ensure!(
            self.release_checkpoint.is_absolute(),
            "continuous release checkpoint must be absolute"
        );
        ensure!(
            !self.required_consumer.is_empty()
                && self.required_consumer.len() <= 64
                && self
                    .required_consumer
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "invalid continuous required consumer"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessedReleasedBank {
    pub slot: u64,
    pub bank_id: u64,
    pub last_processed_event: u64,
    pub artifact: Option<String>,
    pub marker_sha256: Option<String>,
    pub gap_sequence: Option<u64>,
    pub evidence_sha256: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessedReleasedSlotControl {
    pub slot: u64,
    pub last_processed_event: u64,
    pub gap_sequence: u64,
    pub evidence_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessedReleaseCheckpoint {
    pub schema: String,
    pub source: blockzilla_bank_stream_v2::SourceIdentity,
    pub producer_generation: String,
    pub consumer_id: String,
    pub release_id: u64,
    pub processed_through_sequence: u64,
    pub acknowledged_cursor: String,
    pub replay_floor_cursor: String,
    pub acknowledged_gap_sequence: u64,
    pub released_banks: Vec<ProcessedReleasedBank>,
    #[serde(default)]
    pub released_slot_controls: Vec<ProcessedReleasedSlotControl>,
}
pub fn processed_release_digest(checkpoint: &ProcessedReleaseCheckpoint) -> Result<String> {
    Ok(digest(&serde_json::to_vec(checkpoint)?))
}

#[derive(Clone, Debug)]
struct ContinuousBinding {
    options: ContinuousLiveOptions,
    producer_generation: String,
    started_unix_ms: u64,
    source: blockzilla_bank_stream_v2::SourceIdentity,
    feed_header_sha256: String,
}
#[derive(Debug)]
struct RetentionPressure(&'static str);
impl std::fmt::Display for RetentionPressure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "continuous_retention_backpressure: {}", self.0)
    }
}
impl std::error::Error for RetentionPressure {}

/// Finite producer admission limits, not an OS-enforced filesystem quota.
/// Source capture keeps its separate journal quota. No live eviction is implied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveCanaryLimits {
    pub max_banks: u64,
    pub max_events: u64,
    pub max_output_bytes: u64,
    pub max_seconds: u64,
}
impl LiveCanaryLimits {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=MAX_ACTIVE).contains(&self.max_banks),
            "invalid live canary bank limit"
        );
        ensure!(
            (1..=10_000_000).contains(&self.max_events),
            "invalid live canary event limit"
        );
        ensure!(
            (1024 * 1024..=64 * 1024u64.pow(3)).contains(&self.max_output_bytes),
            "invalid live canary byte limit"
        );
        ensure!(
            (1..=3600).contains(&self.max_seconds),
            "invalid live canary time limit"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LiveBinding {
    limits: LiveCanaryLimits,
    started_unix_ms: u64,
    source_start: u64,
}
#[derive(Clone, Debug)]
struct LiveCanary {
    binding: LiveBinding,
    deadline: Instant,
    inventory: Arc<Mutex<InventoryState>>,
    continuous: Option<Arc<ContinuousBinding>>,
}
#[derive(Debug)]
struct InventorySample {
    output: PathBuf,
    checked_at: Instant,
    bytes: u64,
}

// Isolated Linux prototype. Sealed payloads are immutable under the producer
// contract. A kernel mutation watch makes later changes fail closed, rather
// than trusting chmod or re-reading every retained file at every admission.
#[derive(Debug, Default)]
struct InventoryState {
    sample: Option<InventorySample>,
    sealed: HashMap<PathBuf, SealedSubtree>,
    watch: Option<SealedWatch>,
    fault: Option<String>,
}
#[derive(Debug)]
struct SealedSubtree {
    device: u64,
    inode: u64,
    bytes: u64,
    entries: u64,
    marker_sha: String,
    slot: u64,
    bank: u64,
}
#[derive(Debug)]
struct SealedWatch {
    fd: std::os::fd::OwnedFd,
    paths: BTreeMap<i32, PathBuf>,
    removing: std::collections::BTreeSet<i32>,
}
impl SealedWatch {
    fn new() -> Result<Self> {
        use std::os::fd::FromRawFd;
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        ensure!(
            fd >= 0,
            "create sealed inventory watch: {}",
            std::io::Error::last_os_error()
        );
        Ok(Self {
            fd: unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) },
            paths: BTreeMap::new(),
            removing: Default::default(),
        })
    }
    fn add(&mut self, path: &Path, directory: bool) -> Result<()> {
        use std::os::{fd::AsRawFd, unix::ffi::OsStrExt};
        let path_c = std::ffi::CString::new(path.as_os_str().as_bytes())?;
        // CLOSE_WRITE can arrive after a pre-seal writer FD was inherited by
        // an unrelated fork and then closed at exec. Closing without a write
        // does not change charged bytes. Actual writes remain IN_MODIFY.
        let mask = libc::IN_MODIFY
            | libc::IN_ATTRIB
            | libc::IN_CREATE
            | libc::IN_DELETE
            | libc::IN_MOVED_FROM
            | libc::IN_MOVED_TO
            | libc::IN_DELETE_SELF
            | libc::IN_MOVE_SELF
            | libc::IN_UNMOUNT
            | libc::IN_DONT_FOLLOW
            | if directory { libc::IN_ONLYDIR } else { 0 };
        let wd = unsafe { libc::inotify_add_watch(self.fd.as_raw_fd(), path_c.as_ptr(), mask) };
        ensure!(
            wd >= 0,
            "watch sealed compact {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
        ensure!(
            !self.paths.contains_key(&wd),
            "duplicate sealed watch identity: {}",
            path.display()
        );
        self.paths.insert(wd, path.into());
        Ok(())
    }
    fn remove_subtree(&mut self, path: &Path) -> Result<()> {
        use std::os::fd::AsRawFd;
        self.check()?;
        let ids = self
            .paths
            .iter()
            .filter(|(_, watched)| watched.as_path() == path || watched.parent() == Some(path))
            .map(|(wd, _)| *wd)
            .collect::<Vec<_>>();
        for wd in ids {
            self.removing.insert(wd);
            let result = unsafe { libc::inotify_rm_watch(self.fd.as_raw_fd(), wd) };
            ensure!(
                result == 0,
                "remove authorized sealed watch: {}",
                std::io::Error::last_os_error()
            );
            self.paths.remove(&wd);
        }
        self.check()?;
        ensure!(
            self.removing.is_empty(),
            "authorized watch removal was not observed"
        );
        Ok(())
    }
    fn check(&mut self) -> Result<()> {
        use std::os::fd::AsRawFd;
        let mut buffer = [0u8; 65536];
        loop {
            let read = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if read < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    return Ok(());
                }
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error).context("read sealed inventory mutation watch");
            }
            ensure!(read != 0, "sealed inventory watch closed");
            let count = read as usize;
            ensure!(
                count >= std::mem::size_of::<libc::inotify_event>(),
                "short sealed watch event"
            );
            let mut offset = 0usize;
            while offset < count {
                let header = std::mem::size_of::<libc::inotify_event>();
                ensure!(offset + header <= count, "short sealed watch event");
                let event = unsafe {
                    std::ptr::read_unaligned(
                        buffer.as_ptr().add(offset).cast::<libc::inotify_event>(),
                    )
                };
                let end = offset + header + event.len as usize;
                ensure!(end <= count, "truncated sealed inventory event");
                if event.mask == libc::IN_IGNORED && self.removing.remove(&event.wd) {
                    offset = end;
                    continue;
                }
                // Only the exact IGNORED notification for our own durable
                // retirement is allowed. Overflow, lost watches and all
                // unexpected mutations remain permanently fatal.
                let path = self
                    .paths
                    .get(&event.wd)
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown/overflow".into());
                let name = &buffer[offset + header..end];
                let name =
                    String::from_utf8_lossy(name.split(|b| *b == 0).next().unwrap_or_default());
                anyhow::bail!(
                    "sealed inventory mutation path={path} entry={name} mask={:#x}",
                    event.mask
                );
            }
        }
    }
}
impl InventoryState {
    fn check_watches(&mut self) -> Result<()> {
        ensure!(
            self.fault.is_none(),
            "sealed inventory previously failed: {}",
            self.fault.as_deref().unwrap_or("")
        );
        if let Some(watch) = &mut self.watch
            && let Err(error) = watch.check()
        {
            self.sample = None;
            self.fault = Some(format!("{error:#}"));
            return Err(error);
        }
        Ok(())
    }
}
impl LiveCanary {
    fn release_seal(&self, path: &Path) -> Result<()> {
        ensure!(
            self.continuous.is_some(),
            "finite producer cannot release payload custody"
        );
        let mut inventory = self
            .inventory
            .lock()
            .map_err(|_| anyhow::anyhow!("live output inventory lock poisoned"))?;
        inventory.check_watches()?;
        if inventory.sealed.contains_key(path) {
            inventory
                .watch
                .as_mut()
                .context("sealed subtree lost mutation watch")?
                .remove_subtree(path)?;
            inventory.sealed.remove(path);
        }
        // Until unlink completes this becomes ordinary mutable inventory;
        // no bytes are omitted merely because retirement was requested.
        inventory.sample = None;
        Ok(())
    }
    fn seal_compact(
        &self,
        output: &Path,
        compact: &Path,
        slot: u64,
        bank: u64,
        marker_sha: &str,
    ) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        self.check_time()?;
        ensure!(
            compact == output.join(format!("live-banks/{slot}-{bank}.compact")),
            "sealed compact path/Bank mismatch"
        );
        let mut inventory = self
            .inventory
            .lock()
            .map_err(|_| anyhow::anyhow!("live output inventory lock poisoned"))?;
        self.check_time()?;
        inventory.check_watches()?;
        if let Some(seal) = inventory.sealed.get(compact) {
            ensure!(
                seal.slot == slot && seal.bank == bank && seal.marker_sha == marker_sha,
                "sealed compact binding changed"
            );
            return Ok(());
        }
        // Install the mutation watch before scanning. The child has exited,
        // validate_compact_commit passed and normalized links were removed.
        if inventory.watch.is_none() {
            inventory.watch = Some(SealedWatch::new()?);
        }
        inventory.watch.as_mut().unwrap().add(compact, true)?;
        let identity = fs::symlink_metadata(compact)
            .with_context(|| format!("inspect compact seal {}", compact.display()))?;
        ensure!(
            identity.file_type().is_dir(),
            "seal is not a real directory: {}",
            compact.display()
        );
        let mut bytes = 0u64;
        let mut entries = 0u64;
        for entry in fs::read_dir(compact)? {
            let path = entry?.path();
            inventory.watch.as_mut().unwrap().add(&path, false)?;
            let metadata = fs::symlink_metadata(&path)?;
            ensure!(
                metadata.file_type().is_file()
                    && metadata.nlink() == 1
                    && metadata.mode() & 0o222 == 0,
                "unsealed type/link/writable file: {}",
                path.display()
            );
            entries += 1;
            ensure!(entries <= 1_000_000, "sealed inventory entry limit");
            bytes = bytes
                .checked_add(metadata.len().max(metadata.blocks().saturating_mul(512)))
                .context("sealed byte overflow")?;
        }
        let marker_path = compact.join("DIRECT-AGAVE-COMPACT.v1.json");
        let metadata = fs::symlink_metadata(&marker_path)?;
        ensure!(
            metadata.len() <= 16 * 1024 * 1024,
            "sealed marker exceeds limit"
        );
        let marker_bytes = fs::read(&marker_path)?;
        ensure!(
            digest(&marker_bytes) == marker_sha,
            "sealed compact marker changed"
        );
        let marker: Value = serde_json::from_slice(&marker_bytes)?;
        ensure!(
            marker["state"] == "COMPLETE"
                && marker["produced_blocks"]
                    .as_array()
                    .is_some_and(|rows| rows.len() == 1
                        && rows[0]["slot"] == slot
                        && rows[0]["bank_id"] == bank),
            "sealed compact incomplete or different Bank"
        );
        let after = fs::symlink_metadata(compact)?;
        ensure!(
            after.dev() == identity.dev() && after.ino() == identity.ino(),
            "sealed directory replaced during registration"
        );
        inventory.check_watches()?;
        self.check_time()?;
        inventory.sealed.insert(
            compact.into(),
            SealedSubtree {
                device: identity.dev(),
                inode: identity.ino(),
                bytes,
                entries,
                marker_sha: marker_sha.into(),
                slot,
                bank,
            },
        );
        inventory.sample = None;
        Ok(())
    }
}

fn now_ms() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}
impl LiveCanary {
    fn from_binding(binding: LiveBinding) -> Result<Self> {
        binding.limits.validate()?;
        let now = now_ms()?;
        let end = binding
            .started_unix_ms
            .checked_add(binding.limits.max_seconds * 1000)
            .context("live canary deadline overflow")?;
        ensure!(
            now >= binding.started_unix_ms && now < end,
            "live_canary_time_limit"
        );
        Ok(Self {
            binding,
            deadline: Instant::now() + Duration::from_millis(end - now),
            inventory: Arc::new(Mutex::new(InventoryState::default())),
            continuous: None,
        })
    }
    fn for_continuous(binding: ContinuousBinding) -> Result<Self> {
        binding.options.validate()?;
        ensure!(
            now_ms()? >= binding.started_unix_ms,
            "continuous clock predates its binding"
        );
        Ok(Self {
            binding: LiveBinding {
                limits: LiveCanaryLimits {
                    max_banks: binding.options.max_retained_banks,
                    max_events: binding.options.retained_events,
                    max_output_bytes: binding.options.max_output_bytes,
                    max_seconds: 3600,
                },
                started_unix_ms: binding.started_unix_ms,
                source_start: 0,
            },
            deadline: Instant::now(),
            inventory: Arc::new(Mutex::new(InventoryState::default())),
            continuous: Some(Arc::new(binding)),
        })
    }
    fn source_ceiling(&self) -> Result<u64> {
        if self.continuous.is_some() {
            return Ok(u64::MAX);
        }
        self.binding
            .source_start
            .checked_add(self.binding.limits.max_events)
            .context("live canary source ceiling overflow")
    }
    fn check_time(&self) -> Result<()> {
        let now = now_ms()?;
        if let Some(continuous) = &self.continuous {
            ensure!(
                now >= continuous.started_unix_ms,
                "continuous clock predates its binding"
            );
            return Ok(());
        }
        ensure!(
            now >= self.binding.started_unix_ms
                && now < self.binding.started_unix_ms + self.binding.limits.max_seconds * 1000
                && Instant::now() < self.deadline,
            "live_canary_time_limit"
        );
        Ok(())
    }
    fn check(&self, output: &Path) -> Result<()> {
        self.inventory_check(output, true, |state| self.scan(output, &state.sealed))
    }
    /// Child and periodic monitoring may reuse a successful sample for 100 ms.
    /// Actual child admission and every feed commit always force a full scan.
    fn monitor(&self, output: &Path) -> Result<()> {
        self.inventory_check(output, false, |state| self.scan(output, &state.sealed))
    }
    fn scan(&self, output: &Path, sealed: &HashMap<PathBuf, SealedSubtree>) -> Result<u64> {
        let settling = Instant::now() + Duration::from_secs(5);
        retry_live_inventory_until(
            || live_output_bytes_once_sealed_with(output, sealed, |_| {}),
            if self.continuous.is_some() {
                settling
            } else {
                self.deadline.min(settling)
            },
        )
    }
    fn inventory_check(
        &self,
        output: &Path,
        force: bool,
        scan: impl FnOnce(&InventoryState) -> Result<u64>,
    ) -> Result<()> {
        self.check_time()?;
        let mut inventory = self
            .inventory
            .lock()
            .map_err(|_| anyhow::anyhow!("live output inventory lock poisoned"))?;
        self.check_time()?;
        inventory.check_watches()?;
        if !force
            && let Some(cached) = inventory.sample.as_ref()
            && cached.output == output
            && cached.checked_at.elapsed() < Duration::from_millis(100)
        {
            ensure!(
                cached.bytes < self.binding.limits.max_output_bytes,
                "live_canary_output_byte_limit"
            );
            self.check_time()?;
            return Ok(());
        }
        // No prior success remains available after any failed refresh.
        inventory.sample = None;
        let bytes = scan(&inventory)?;
        inventory.check_watches()?;
        self.check_time()?;
        if bytes >= self.binding.limits.max_output_bytes {
            if self.continuous.is_some() {
                return Err(RetentionPressure("output_byte_capacity").into());
            }
            anyhow::bail!("live_canary_output_byte_limit");
        }
        inventory.sample = Some(InventorySample {
            output: output.to_path_buf(),
            checked_at: Instant::now(),
            bytes,
        });
        Ok(())
    }
    fn before_event(&self, output: &Path, db: &Connection) -> Result<()> {
        self.check(output)?;
        let sequence: u64 = db.query_row(
            if self.continuous.is_some() {
                "SELECT count(*) FROM feed_events"
            } else {
                "SELECT event_sequence FROM feed_state WHERE id=1"
            },
            [],
            |r| r.get(0),
        )?;
        if sequence >= self.binding.limits.max_events {
            if self.continuous.is_some() {
                return Err(RetentionPressure("retained_feed_event_capacity").into());
            }
            anyhow::bail!("live_canary_feed_event_limit");
        }
        Ok(())
    }
}

/// Include SQLite/WAL/SHM and every owned stage; reject observed symbolic links.
#[cfg(test)]
fn live_output_bytes(output: &Path) -> Result<u64> {
    retry_live_inventory(|| live_output_bytes_once(output))
}

#[cfg(test)]
fn retry_live_inventory(mut scan: impl FnMut() -> Result<u64>) -> Result<u64> {
    retry_live_inventory_until(&mut scan, Instant::now() + Duration::from_secs(5))
}

fn retry_live_inventory_until(
    mut scan: impl FnMut() -> Result<u64>,
    deadline: Instant,
) -> Result<u64> {
    loop {
        match scan() {
            Ok(bytes) => return Ok(bytes),
            Err(error)
                if Instant::now() < deadline
                    && error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                // Several converters can rename stages during consecutive
                // walks. Allow a bounded settling interval, rather than only
                // four attempts. Never skip a vanished path or its bytes.
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
fn live_output_bytes_once(output: &Path) -> Result<u64> {
    live_output_bytes_once_with(output, |_| {})
}

#[cfg(test)]
fn live_output_bytes_once_with(output: &Path, before_metadata: impl FnMut(&Path)) -> Result<u64> {
    live_output_bytes_once_sealed_with(output, &HashMap::new(), before_metadata)
}
fn live_output_bytes_once_sealed_with(
    output: &Path,
    sealed: &HashMap<PathBuf, SealedSubtree>,
    mut before_metadata: impl FnMut(&Path),
) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    let mut pending = vec![output.to_path_buf()];
    let mut observed = HashSet::with_capacity(sealed.len());
    let mut total = sealed.values().try_fold(0u64, |n, seal| {
        n.checked_add(seal.bytes).context("sealed total overflow")
    })?;
    let mut entries = 0u64;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).with_context(|| {
            format!(
                "live output inventory read directory {}",
                directory.display()
            )
        })? {
            let entry = entry.with_context(|| {
                format!(
                    "live output inventory read entry in {}",
                    directory.display()
                )
            })?;
            let path = entry.path();
            before_metadata(&path);
            let metadata = fs::symlink_metadata(&path)
                .with_context(|| format!("live output inventory inspect {}", path.display()))?;
            entries += 1;
            ensure!(
                entries <= 1_000_000 && !metadata.file_type().is_symlink(),
                "unsafe live output inventory"
            );
            if metadata.is_dir() {
                if let Some(seal) = sealed.get(&path) {
                    ensure!(
                        metadata.dev() == seal.device && metadata.ino() == seal.inode,
                        "sealed directory identity changed: {}",
                        path.display()
                    );
                    entries = entries
                        .checked_add(seal.entries)
                        .context("sealed entry overflow")?;
                    ensure!(
                        entries <= 1_000_000,
                        "unsafe live output inventory entry limit"
                    );
                    observed.insert(path);
                } else {
                    pending.push(entry.path());
                }
            } else {
                ensure!(metadata.is_file(), "unsafe live output type");
                total = total
                    .checked_add(metadata.len().max(metadata.blocks().saturating_mul(512)))
                    .context("live output byte overflow")?;
            }
        }
    }
    ensure!(
        observed.len() == sealed.len(),
        "sealed compact missing from output inventory"
    );
    Ok(total)
}

fn live_writer(
    command: &mut Command,
    live: &LiveCanary,
    output: &Path,
) -> Result<std::process::ExitStatus> {
    live.check(output)?;
    let mut child = command.spawn()?;
    let result = (|| {
        loop {
            live.monitor(output)?;
            if let Some(status) = child.try_wait()? {
                return Ok(status);
            }
            thread::sleep(Duration::from_millis(20));
        }
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

struct ContextData {
    session: PathBuf,
    output: PathBuf,
    builder: PathBuf,
    meta: Value,
    id: String,
    genesis: String,
    codec: String,
    max_event_bytes: usize,
    live: Option<LiveCanary>,
}

#[cfg(test)]
fn database(output: &Path, source_start: u64) -> Result<Connection> {
    database_for_role(output, source_start, false)
}
fn database_for_role(output: &Path, source_start: u64, live: bool) -> Result<Connection> {
    let db = Connection::open(output.join("feed.sqlite"))?;
    if live {
        let archive_tables: u64 = db.query_row(
            "SELECT count(*) FROM sqlite_master WHERE name='archive_catalog'",
            [],
            |r| r.get(0),
        )?;
        ensure!(
            archive_tables == 0,
            "live output cannot adopt archive state"
        );
    }
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS feed_state(id INTEGER PRIMARY KEY CHECK(id=1),source_sequence INTEGER NOT NULL,event_sequence INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS banks(slot INTEGER NOT NULL,bank INTEGER NOT NULL,first_sequence INTEGER NOT NULL,last_sequence INTEGER NOT NULL,root_sequence INTEGER NOT NULL DEFAULT 0,invalid_sequence INTEGER NOT NULL DEFAULT 0,dirty INTEGER NOT NULL DEFAULT 1,state TEXT NOT NULL DEFAULT 'waiting',artifact TEXT,marker_sha TEXT,projection_sha TEXT,through_sequence INTEGER,identity TEXT,PRIMARY KEY(slot,bank));
        CREATE INDEX IF NOT EXISTS bank_work ON banks(dirty,last_sequence);
        CREATE INDEX IF NOT EXISTS bank_state_count ON banks(state);
        CREATE TABLE IF NOT EXISTS dead_slots(slot INTEGER PRIMARY KEY,sequence INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS feed_events(sequence INTEGER PRIMARY KEY,kind TEXT NOT NULL,slot INTEGER NOT NULL,bank INTEGER NOT NULL,artifact TEXT NOT NULL,event_json TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS feed_bank_events ON feed_events(slot,bank,sequence);
        CREATE TABLE IF NOT EXISTS bank_observations(slot INTEGER NOT NULL,bank INTEGER NOT NULL,frozen_json TEXT,frozen_sequence INTEGER NOT NULL DEFAULT 0,confirmed_json TEXT,confirmed_sequence INTEGER NOT NULL DEFAULT 0,root_observed_ms INTEGER NOT NULL DEFAULT 0,invalid_observed_ms INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(slot,bank));
        CREATE TABLE IF NOT EXISTS bank_controls(source_sequence INTEGER PRIMARY KEY,slot INTEGER NOT NULL,bank INTEGER,kind TEXT NOT NULL,observed_at_unix_ms INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS bank_parent_resolutions(source_sequence INTEGER PRIMARY KEY,slot INTEGER NOT NULL,bank INTEGER NOT NULL,original_json TEXT NOT NULL,parent_blockhash BLOB NOT NULL,proof_kind TEXT NOT NULL,proof_sequence INTEGER NOT NULL,proof_sha256 TEXT);")?;
    if !live {
        db.execute_batch("CREATE TABLE IF NOT EXISTS archive_catalog(slot INTEGER PRIMARY KEY,bank INTEGER NOT NULL,artifact TEXT NOT NULL,marker_sha TEXT NOT NULL,root_sequence INTEGER NOT NULL,custody_path TEXT NOT NULL,custody_sha TEXT NOT NULL,retirement_enqueued INTEGER NOT NULL DEFAULT 0);
            CREATE INDEX IF NOT EXISTS archive_pending_retirement ON archive_catalog(retirement_enqueued,slot);")?;
    }
    db.execute(
        "INSERT OR IGNORE INTO feed_state VALUES(1,?1,0)",
        [source_start],
    )?;
    Ok(db)
}

fn continuous_database(output: &Path) -> Result<Connection> {
    let db = database_for_role(output, 0, true)?;
    db.execute_batch("CREATE TABLE IF NOT EXISTS continuous_state(id INTEGER PRIMARY KEY CHECK(id=1),custody_sequence INTEGER NOT NULL,last_release_id INTEGER NOT NULL,released_event_sequence INTEGER NOT NULL,retired_slot_floor INTEGER NOT NULL);
        INSERT OR IGNORE INTO continuous_state VALUES(1,0,0,0,0);
        CREATE TABLE IF NOT EXISTS input_custody(sequence INTEGER PRIMARY KEY,slot INTEGER NOT NULL,bank INTEGER,kind TEXT NOT NULL,sha256 TEXT NOT NULL,payload BLOB NOT NULL);
        CREATE INDEX IF NOT EXISTS custody_bank ON input_custody(slot,bank,sequence);
        CREATE TABLE IF NOT EXISTS bank_activity(slot INTEGER NOT NULL,bank INTEGER NOT NULL,first_unix_ms INTEGER NOT NULL,last_unix_ms INTEGER NOT NULL,last_event_sequence INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(slot,bank));
        CREATE TABLE IF NOT EXISTS source_acks(id INTEGER PRIMARY KEY CHECK(id=1),schema TEXT NOT NULL,source_json TEXT NOT NULL,producer_generation TEXT NOT NULL,feed_header_sha256 TEXT NOT NULL,source_start_sequence INTEGER NOT NULL,custody_through_sequence INTEGER NOT NULL,proof_sha256 TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS bank_gaps(slot INTEGER NOT NULL,bank INTEGER NOT NULL,gap_sequence INTEGER NOT NULL,evidence_sha256 TEXT NOT NULL,gap_json TEXT NOT NULL,PRIMARY KEY(slot,bank));
        CREATE TABLE IF NOT EXISTS slot_activity(slot INTEGER PRIMARY KEY,first_sequence INTEGER NOT NULL,last_sequence INTEGER NOT NULL,first_unix_ms INTEGER NOT NULL,last_unix_ms INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS slot_gaps(slot INTEGER PRIMARY KEY,gap_sequence INTEGER NOT NULL,evidence_sha256 TEXT NOT NULL,gap_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS retired_slot_controls(slot INTEGER PRIMARY KEY,last_event_sequence INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS release_jobs(release_id INTEGER PRIMARY KEY,checkpoint_sha256 TEXT NOT NULL,checkpoint_json TEXT NOT NULL,state TEXT NOT NULL,released_bytes INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS release_targets(release_id INTEGER NOT NULL,slot INTEGER NOT NULL,bank INTEGER NOT NULL,path TEXT NOT NULL,device INTEGER NOT NULL,inode INTEGER NOT NULL,bytes INTEGER NOT NULL,PRIMARY KEY(release_id,slot,bank));
        CREATE TABLE IF NOT EXISTS retired_banks(slot INTEGER NOT NULL,bank INTEGER NOT NULL,last_event_sequence INTEGER NOT NULL,state TEXT NOT NULL,PRIMARY KEY(slot,bank));")?;
    Ok(db)
}

fn has_table(db: &Connection, table: &str) -> Result<bool> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [table],
        |r| r.get(0),
    )?)
}

fn record_source_custody(db: &Connection, binding: &ContinuousBinding, through: u64) -> Result<()> {
    let proof = crate::retention::source_ack_proof(
        &binding.source,
        &binding.producer_generation,
        &binding.feed_header_sha256,
        0,
        through,
    )?;
    db.execute(
        "UPDATE continuous_state SET custody_sequence=?1 WHERE id=1",
        [through],
    )?;
    db.execute("INSERT INTO source_acks VALUES(1,?1,?2,?3,?4,0,?5,?6) ON CONFLICT(id) DO UPDATE SET custody_through_sequence=excluded.custody_through_sequence,proof_sha256=excluded.proof_sha256",
        params![crate::retention::SOURCE_ACK_SCHEMA,serde_json::to_string(&binding.source)?,binding.producer_generation,binding.feed_header_sha256,through,proof])?;
    Ok(())
}

fn publish_source_custody(
    session: &Path,
    output: &Path,
    db: &Connection,
    binding: &ContinuousBinding,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let through: u64 = db.query_row(
        "SELECT custody_sequence FROM continuous_state WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    if through == 0 {
        return Ok(());
    }
    let path = output.join("feed.sqlite");
    let metadata = fs::symlink_metadata(&path)?;
    ensure!(
        metadata.file_type().is_file(),
        "producer custody database is not regular"
    );
    let ticket = crate::retention::SourceAckTicket {
        schema: crate::retention::SOURCE_ACK_SCHEMA.into(),
        source: binding.source.clone(),
        producer_db: path
            .to_str()
            .context("producer custody path is not UTF-8")?
            .into(),
        producer_db_device: metadata.dev(),
        producer_db_inode: metadata.ino(),
        producer_generation: binding.producer_generation.clone(),
        feed_header_sha256: binding.feed_header_sha256.clone(),
        source_start_sequence: 0,
        through_sequence: through,
        proof_sha256: crate::retention::source_ack_proof(
            &binding.source,
            &binding.producer_generation,
            &binding.feed_header_sha256,
            0,
            through,
        )?,
    };
    crate::retention::write_source_ack(session, &ticket)
}

fn bounded_regular(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect continuous checkpoint {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file() && metadata.len() <= limit,
        "unsafe continuous checkpoint {}",
        path.display()
    );
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "continuous checkpoint exceeds bound"
    );
    Ok(bytes)
}

fn verify_compact_custody(path: &Path, expected_marker: &str) -> Result<u64> {
    use sha2::{Digest, Sha256};
    let marker_bytes =
        bounded_regular(&path.join("DIRECT-AGAVE-COMPACT.v1.json"), 16 * 1024 * 1024)?;
    ensure!(
        digest(&marker_bytes) == expected_marker,
        "released compact marker changed"
    );
    let marker: Value = serde_json::from_slice(&marker_bytes)?;
    ensure!(
        marker["state"] == "COMPLETE",
        "released compact is incomplete"
    );
    for row in marker["files"]
        .as_array()
        .context("released marker lacks file custody")?
    {
        let name = row["path"].as_str().context("released file lacks path")?;
        ensure!(
            Path::new(name).components().count() == 1
                && matches!(
                    Path::new(name).components().next(),
                    Some(std::path::Component::Normal(_))
                ),
            "unsafe released compact file path"
        );
        let file_path = path.join(name);
        let metadata = fs::symlink_metadata(&file_path)?;
        ensure!(
            metadata.file_type().is_file() && metadata.len() <= 512 * 1024 * 1024,
            "unsafe released compact file"
        );
        let mut file = File::open(&file_path)?;
        let mut hash = Sha256::new();
        let mut bytes = 0u64;
        let mut buffer = [0u8; 65536];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            bytes += count as u64;
            hash.update(&buffer[..count]);
        }
        let sha = hash
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        ensure!(
            row["bytes"] == bytes && row["sha256"] == sha,
            "released compact object changed"
        );
    }
    live_output_bytes_once_sealed_with(path, &HashMap::new(), |_| {})
}

fn validate_release(
    db: &Connection,
    c: &ContextData,
    binding: &ContinuousBinding,
    checkpoint: &ProcessedReleaseCheckpoint,
) -> Result<()> {
    ensure!(
        checkpoint.schema == PROCESSED_RELEASE_SCHEMA
            && checkpoint.source == binding.source
            && checkpoint.producer_generation == binding.producer_generation
            && checkpoint.consumer_id == binding.options.required_consumer,
        "processed release source/generation/consumer mismatch"
    );
    ensure!(
        checkpoint.release_id > 0
            && (checkpoint.released_banks.len() + checkpoint.released_slot_controls.len()) as u64
                <= binding.options.max_retained_banks,
        "invalid processed release batch size/id"
    );
    for cursor in [
        &checkpoint.acknowledged_cursor,
        &checkpoint.replay_floor_cursor,
    ] {
        ensure!(
            blockzilla_bank_stream_v2::parse_cursor(cursor)?.0 == binding.source.session_id,
            "release cursor source mismatch"
        );
    }
    ensure!(
        blockzilla_bank_stream_v2::parse_cursor(&checkpoint.replay_floor_cursor)?.1
            <= blockzilla_bank_stream_v2::parse_cursor(&checkpoint.acknowledged_cursor)?.1,
        "release replay floor exceeds consumer ACK"
    );
    let position: u64 = db.query_row(
        "SELECT event_sequence FROM feed_state WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    ensure!(
        checkpoint.processed_through_sequence <= position,
        "release frontier exceeds emitted events"
    );
    let floor: u64 = db.query_row(
        "SELECT released_event_sequence FROM continuous_state WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    ensure!(
        checkpoint.processed_through_sequence >= floor,
        "processed release frontier regressed"
    );
    let mut unique = std::collections::BTreeSet::new();
    for bank in &checkpoint.released_banks {
        ensure!(
            unique.insert((bank.slot, bank.bank_id)),
            "duplicate released Bank"
        );
        let row:Option<(String,Option<String>,Option<String>,u64,u64,u64)>=db.query_row(
            "SELECT b.state,b.artifact,b.marker_sha,b.dirty,a.last_event_sequence,a.first_unix_ms FROM banks b JOIN bank_activity a ON a.slot=b.slot AND a.bank=b.bank WHERE b.slot=?1 AND b.bank=?2",
            params![bank.slot,bank.bank_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional()?;
        let (state, artifact, marker, dirty, last_event, first) =
            row.context("release references an unknown Bank")?;
        ensure!(
            matches!(
                state.as_str(),
                "rooted" | "invalidated" | "gapped" | "retiring"
            ) && dirty == 0,
            "release Bank is not terminal/quiescent"
        );
        ensure!(
            last_event == bank.last_processed_event
                && last_event <= checkpoint.processed_through_sequence,
            "release Bank event frontier changed"
        );
        ensure!(
            now_ms()?.saturating_sub(first) >= binding.options.min_retention_ms,
            "release Bank is younger than retention policy"
        );
        if state == "gapped" {
            let (gap, sha): (u64, String) = db.query_row(
                "SELECT gap_sequence,evidence_sha256 FROM bank_gaps WHERE slot=?1 AND bank=?2",
                params![bank.slot, bank.bank_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            ensure!(
                bank.gap_sequence == Some(gap)
                    && bank.evidence_sha256.as_ref() == Some(&sha)
                    && checkpoint.acknowledged_gap_sequence >= gap,
                "gap custody lacks its durable gap ACK"
            );
        } else {
            ensure!(
                bank.gap_sequence.is_none() && bank.evidence_sha256.is_none(),
                "ordinary release claims unrelated gap custody"
            );
        }
        if let Some(artifact) = artifact {
            let expected = c
                .output
                .join(format!("live-banks/{}-{}.compact", bank.slot, bank.bank_id));
            ensure!(
                Some(artifact.as_str()) == expected.to_str()
                    && bank.artifact.as_ref() == Some(&artifact)
                    && bank.marker_sha256 == marker,
                "release payload path/marker changed"
            );
        } else {
            ensure!(
                state == "gapped" && bank.artifact.is_none() && bank.marker_sha256.is_none(),
                "incomplete gap cannot claim a compact payload"
            );
        }
    }
    for slot in &checkpoint.released_slot_controls {
        ensure!(
            unique.insert((slot.slot, u64::MAX)),
            "duplicate slot-control release"
        );
        let (gap, sha): (u64, String) = db.query_row(
            "SELECT gap_sequence,evidence_sha256 FROM slot_gaps WHERE slot=?1",
            [slot.slot],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(
            gap == slot.gap_sequence
                && gap == slot.last_processed_event
                && gap <= checkpoint.processed_through_sequence
                && gap <= checkpoint.acknowledged_gap_sequence
                && sha == slot.evidence_sha256,
            "slot control lacks exact durable gap ACK"
        );
        ensure!(
            !db.query_row(
                "SELECT EXISTS(SELECT 1 FROM banks WHERE slot=?1)",
                [slot.slot],
                |r| r.get::<_, bool>(0)
            )?,
            "slot-only gap acquired Bank dependencies"
        );
    }
    Ok(())
}

fn process_continuous_release(c: &ContextData, db: &mut Connection) -> Result<bool> {
    let live = c
        .live
        .as_ref()
        .context("continuous release lacks live guard")?;
    let binding = live
        .continuous
        .as_deref()
        .context("finite producer cannot consume release checkpoint")?;
    let raw = match bounded_regular(&binding.options.release_checkpoint, 1024 * 1024) {
        Ok(raw) => raw,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    let checkpoint: ProcessedReleaseCheckpoint = serde_json::from_slice(&raw)?;
    apply_continuous_release(c, db, checkpoint)
}

fn apply_continuous_release(
    c: &ContextData,
    db: &mut Connection,
    checkpoint: ProcessedReleaseCheckpoint,
) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let live = c
        .live
        .as_ref()
        .context("continuous release lacks live guard")?;
    let binding = live
        .continuous
        .as_deref()
        .context("finite producer cannot consume release checkpoint")?;
    let sha = processed_release_digest(&checkpoint)?;
    let previous: Option<(String, String)> = db
        .query_row(
            "SELECT checkpoint_sha256,state FROM release_jobs WHERE release_id=?1",
            [checkpoint.release_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let directory = c.output.join("retention");
    fs::create_dir_all(&directory)?;
    let receipt_path = directory.join(format!("release-{}.json", checkpoint.release_id));
    if let Some((old, state)) = &previous {
        ensure!(
            old == &sha,
            "processed release ID was reused with different content"
        );
        if state == "COMPLETE" && receipt_path.exists() {
            return Ok(false);
        }
    } else {
        let last: u64 = db.query_row(
            "SELECT last_release_id FROM continuous_state WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        ensure!(
            checkpoint.release_id == last + 1,
            "processed release IDs are not contiguous"
        );
        validate_release(db, c, binding, &checkpoint)?;
        let mut targets = Vec::new();
        let mut planned_bytes = 0u64;
        for bank in &checkpoint.released_banks {
            if bank.gap_sequence.is_some() {
                let through: u64 = db.query_row(
                    "SELECT last_sequence FROM banks WHERE slot=?1 AND bank=?2",
                    params![bank.slot, bank.bank_id],
                    |r| r.get(0),
                )?;
                let source = open_reader(&c.session.join("events.sqlite"))?;
                let evidence =
                    continuous_records(db, &source, c, bank.slot, bank.bank_id, through)?;
                ensure!(
                    !evidence.is_empty()
                        && Some(digest(&serde_json::to_vec(&evidence)?)) == bank.evidence_sha256,
                    "released gap input custody changed"
                );
            }
            if let Some(path) = &bank.artifact {
                let path = Path::new(path);
                let bytes = verify_compact_custody(
                    path,
                    bank.marker_sha256
                        .as_deref()
                        .context("release lacks marker")?,
                )?;
                let metadata = fs::symlink_metadata(path)?;
                ensure!(
                    metadata.file_type().is_dir(),
                    "release target is not a real directory"
                );
                planned_bytes = planned_bytes
                    .checked_add(bytes)
                    .context("release byte overflow")?;
                targets.push((
                    bank.slot,
                    bank.bank_id,
                    path.to_str()
                        .context("release path is not UTF-8")?
                        .to_owned(),
                    metadata.dev(),
                    metadata.ino(),
                    bytes,
                ));
            }
        }
        for slot in &checkpoint.released_slot_controls {
            let evidence = slot_control_records(db, c, slot.slot)?;
            ensure!(
                !evidence.is_empty()
                    && digest(&serde_json::to_vec(&evidence)?) == slot.evidence_sha256,
                "released slot-control custody changed"
            );
        }
        let tx = db.transaction()?;
        tx.execute("INSERT INTO release_jobs(release_id,checkpoint_sha256,checkpoint_json,state,released_bytes) VALUES(?1,?2,?3,'DELETING',?4)",params![checkpoint.release_id,sha,serde_json::to_string(&checkpoint)?,planned_bytes])?;
        for (slot, bank, path, device, inode, bytes) in targets {
            tx.execute(
                "INSERT INTO release_targets VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![
                    checkpoint.release_id,
                    slot,
                    bank,
                    path,
                    device,
                    inode,
                    bytes
                ],
            )?;
        }
        for bank in &checkpoint.released_banks {
            tx.execute(
                "UPDATE banks SET state='retiring' WHERE slot=?1 AND bank=?2",
                params![bank.slot, bank.bank_id],
            )?;
        }
        tx.commit()?;
    }
    let released_bytes: u64 = db.query_row(
        "SELECT released_bytes FROM release_jobs WHERE release_id=?1",
        [checkpoint.release_id],
        |r| r.get(0),
    )?;
    for bank in &checkpoint.released_banks {
        if let Some(artifact) = &bank.artifact {
            let path = Path::new(artifact);
            ensure!(
                path == c
                    .output
                    .join(format!("live-banks/{}-{}.compact", bank.slot, bank.bank_id)),
                "retirement escaped its exact Bank path"
            );
            if path.try_exists()? {
                let (device,inode):(u64,u64)=db.query_row("SELECT device,inode FROM release_targets WHERE release_id=?1 AND slot=?2 AND bank=?3",params![checkpoint.release_id,bank.slot,bank.bank_id],|r|Ok((r.get(0)?,r.get(1)?)))?;
                let metadata = fs::symlink_metadata(path)?;
                ensure!(
                    metadata.file_type().is_dir()
                        && metadata.dev() == device
                        && metadata.ino() == inode,
                    "retiring directory identity changed"
                );
                live.release_seal(path)?;
                fs::remove_dir_all(path)
                    .with_context(|| format!("retire acknowledged compact {}", path.display()))?;
                File::open(path.parent().context("retired compact lacks parent")?)?.sync_all()?;
            }
        }
    }
    let tx = db.transaction()?;
    for bank in &checkpoint.released_banks {
        tx.execute(
            "INSERT OR REPLACE INTO retired_banks VALUES(?1,?2,?3,'released')",
            params![bank.slot, bank.bank_id, bank.last_processed_event],
        )?;
        for table in [
            "input_custody",
            "bank_observations",
            "bank_parent_resolutions",
            "bank_activity",
            "bank_gaps",
            "banks",
        ] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE slot=?1 AND bank=?2"),
                params![bank.slot, bank.bank_id],
            )?;
        }
        tx.execute("DELETE FROM bank_controls WHERE slot=?1 AND (bank=?2 OR (bank IS NULL AND NOT EXISTS(SELECT 1 FROM banks WHERE slot=?1)))",params![bank.slot,bank.bank_id])?;
        tx.execute("DELETE FROM input_custody WHERE slot=?1 AND bank IS NULL AND NOT EXISTS(SELECT 1 FROM banks WHERE slot=?1)",[bank.slot])?;
        tx.execute("DELETE FROM dead_slots WHERE slot=?1 AND NOT EXISTS(SELECT 1 FROM banks WHERE slot=?1)",[bank.slot])?;
        tx.execute("DELETE FROM slot_activity WHERE slot=?1 AND NOT EXISTS(SELECT 1 FROM input_custody WHERE slot=?1)",[bank.slot])?;
    }
    for slot in &checkpoint.released_slot_controls {
        tx.execute(
            "INSERT OR REPLACE INTO retired_slot_controls VALUES(?1,?2)",
            params![slot.slot, slot.last_processed_event],
        )?;
        for table in [
            "input_custody",
            "bank_controls",
            "slot_activity",
            "slot_gaps",
            "dead_slots",
        ] {
            tx.execute(&format!("DELETE FROM {table} WHERE slot=?1"), [slot.slot])?;
        }
    }
    tx.execute(
        "DELETE FROM feed_events WHERE sequence<=?1",
        [checkpoint.processed_through_sequence],
    )?;
    tx.execute("UPDATE continuous_state SET last_release_id=?1,released_event_sequence=max(released_event_sequence,?2) WHERE id=1",params![checkpoint.release_id,checkpoint.processed_through_sequence])?;
    tx.execute(
        "UPDATE release_jobs SET state='COMPLETE',released_bytes=?2 WHERE release_id=?1",
        params![checkpoint.release_id, released_bytes],
    )?;
    let old_slots:Option<u64>=tx.query_row("SELECT max(slot) FROM (SELECT slot FROM retired_banks ORDER BY last_event_sequence LIMIT max(0,(SELECT count(*) FROM retired_banks)-?1))",[binding.options.max_retained_banks*2],|r|r.get(0))?;
    if let Some(slot) = old_slots {
        tx.execute(
            "UPDATE continuous_state SET retired_slot_floor=max(retired_slot_floor,?1) WHERE id=1",
            [slot],
        )?;
    }
    tx.execute("DELETE FROM retired_banks WHERE (slot,bank) IN (SELECT slot,bank FROM retired_banks ORDER BY last_event_sequence LIMIT max(0,(SELECT count(*) FROM retired_banks)-?1))",[binding.options.max_retained_banks*2])?;
    let old:Option<u64>=tx.query_row("SELECT max(slot) FROM (SELECT slot FROM retired_slot_controls ORDER BY last_event_sequence LIMIT max(0,(SELECT count(*) FROM retired_slot_controls)-?1))",[binding.options.max_retained_banks*2],|r|r.get(0))?;
    if let Some(slot) = old {
        tx.execute(
            "UPDATE continuous_state SET retired_slot_floor=max(retired_slot_floor,?1) WHERE id=1",
            [slot],
        )?;
    }
    tx.execute("DELETE FROM retired_slot_controls WHERE slot IN (SELECT slot FROM retired_slot_controls ORDER BY last_event_sequence LIMIT max(0,(SELECT count(*) FROM retired_slot_controls)-?1))",[binding.options.max_retained_banks*2])?;
    tx.commit()?;
    let receipt = json!({"schema":PROCESSED_RELEASE_RECEIPT_SCHEMA,"state":"COMPLETE","source":binding.source,
        "producer_generation":binding.producer_generation,"consumer_id":checkpoint.consumer_id,"release_id":checkpoint.release_id,
        "checkpoint_sha256":sha,"processed_through_sequence":checkpoint.processed_through_sequence,
        "acknowledged_gap_sequence":checkpoint.acknowledged_gap_sequence,"released_banks":checkpoint.released_banks.len(),"released_slot_controls":checkpoint.released_slot_controls.len(),"released_bytes":released_bytes,"completed_unix_ms":now_ms()?});
    atomic_json(&receipt_path, &receipt)?;
    // The next durable batch proves the publisher consumed the prior receipt.
    // Keep two recent success receipts; failures and in-flight work are never pruned.
    if checkpoint.release_id > 2 {
        let cutoff = checkpoint.release_id - 2;
        let old = {
            let mut q = db.prepare(
                "SELECT release_id FROM release_jobs WHERE state='COMPLETE' AND release_id<=?1",
            )?;
            q.query_map([cutoff], |r| r.get::<_, u64>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        for id in old {
            let p = directory.join(format!("release-{id}.json"));
            if p.try_exists()? {
                fs::remove_file(p)?;
            }
            db.execute("DELETE FROM release_targets WHERE release_id=?1", [id])?;
            db.execute("DELETE FROM release_jobs WHERE release_id=?1", [id])?;
        }
        File::open(&directory)?.sync_all()?;
    }
    Ok(true)
}

fn resume_continuous_releases(c: &ContextData, db: &mut Connection) -> Result<()> {
    let rows = {
        let mut q = db.prepare(
            "SELECT checkpoint_json FROM release_jobs WHERE state!='COMPLETE' ORDER BY release_id",
        )?;
        q.query_map([], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    for raw in rows {
        apply_continuous_release(c, db, serde_json::from_str(&raw)?)?;
    }
    Ok(())
}

fn identity(row: &BlockRow) -> Value {
    json!({"slot":row.slot,"bank_id":row.bank_id,"blockhash":row.blockhash,
        "parent_slot":row.parent_slot,"parent_blockhash":row.parent_blockhash})
}
fn append_event(
    db: &Connection,
    kind: &str,
    source_sequence: u64,
    bank: &Value,
    marker_sha: &str,
    artifact: &str,
    reason: Option<&str>,
) -> Result<u64> {
    let previous: u64 = db.query_row(
        "SELECT event_sequence FROM feed_state WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    let sequence = previous.checked_add(1).context("event sequence overflow")?;
    ensure!(
        sequence <= 9_007_199_254_740_991,
        "event sequence exceeds portable cursor range"
    );
    let event = json!({"sequence":sequence,"source_sequence":source_sequence,"kind":kind,
        "bank":bank,"payload_sha256":marker_sha,"reason":reason});
    db.execute(
        "INSERT INTO feed_events VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            sequence,
            kind,
            bank["slot"].as_u64().context("missing slot")?,
            bank["bank_id"].as_u64().context("missing bank ID")?,
            artifact,
            event.to_string()
        ],
    )?;
    db.execute(
        "UPDATE feed_state SET event_sequence=?1 WHERE id=1",
        [sequence],
    )?;
    if has_table(db, "bank_activity")? {
        db.execute(
            "UPDATE bank_activity SET last_event_sequence=?3 WHERE slot=?1 AND bank=?2",
            params![bank["slot"].as_u64(), bank["bank_id"].as_u64(), sequence],
        )?;
    }
    Ok(sequence)
}

/// Persist discovery before building. Restart resumes dirty banks, including same-slot forks.
#[cfg(test)]
fn discover(source: &Connection, db: &mut Connection, through: u64) -> Result<()> {
    discover_for_role(source, db, through, None)
}
fn discover_for_role(
    source: &Connection,
    db: &mut Connection,
    through: u64,
    live: Option<&LiveCanary>,
) -> Result<()> {
    let after: u64 = db.query_row(
        "SELECT source_sequence FROM feed_state WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    let through = if let Some(live) = live {
        through.min(live.source_ceiling()?)
    } else {
        through
    };
    let continuous = live.and_then(|live| live.continuous.as_deref());
    let (rows, byte_limited) = {
        let mut q=source.prepare("SELECT sequence,slot,bank,kind,CASE WHEN ?3 OR kind IN ('bank_state_v2','rooted','dead','clear') THEN payload END,sha256 FROM events WHERE sequence>?1 AND sequence<=?2 ORDER BY sequence LIMIT 16384")?;
        let mut input = q.query(params![after, through, continuous.is_some()])?;
        let (mut rows, mut bytes, mut limited) = (Vec::new(), 0usize, false);
        while let Some(row) = input.next()? {
            let payload: Option<Vec<u8>> = row.get(4)?;
            let size = payload.as_ref().map_or(0, Vec::len);
            ensure!(
                size <= 32 * 1024 * 1024,
                "source discovery record exceeds stored bound"
            );
            if continuous.is_some() && !rows.is_empty() && bytes + size > 64 * 1024 * 1024 {
                limited = true;
                break;
            }
            bytes = bytes
                .checked_add(size)
                .context("source custody batch size overflow")?;
            rows.push((
                row.get::<_, u64>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, Option<u64>>(2)?,
                row.get::<_, String>(3)?,
                payload,
                row.get::<_, String>(5)?,
            ));
        }
        (rows, limited)
    };
    if live.is_some() {
        // There is no archive restore path in this role. A missing callback
        // cannot be treated as consumed, even if a later complete bank exists.
        let expected = through.saturating_sub(after).min(16384);
        ensure!(
            byte_limited || rows.len() as u64 == expected,
            "live source callback gap"
        );
        for (offset, (sequence, ..)) in rows.iter().enumerate() {
            ensure!(
                *sequence == after + offset as u64 + 1,
                "live source callback gap"
            );
        }
    }
    let tx = db.transaction()?;
    let mut bank_updates = BTreeMap::<(u64, u64), (u64, u64, u64, u64)>::new();
    for (sequence, slot, bank, kind, payload, sha) in &rows {
        if continuous.is_some() {
            let terminal_slot:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM slot_gaps WHERE slot=?1) OR EXISTS(SELECT 1 FROM retired_slot_controls WHERE slot=?1)",[slot],|r|r.get(0))?;
            ensure!(
                !terminal_slot,
                "late source input crosses a released or gapped slot control"
            );
            tx.execute(
                "INSERT INTO input_custody VALUES(?1,?2,?3,?4,?5,?6)",
                params![
                    sequence,
                    slot,
                    bank,
                    kind,
                    sha,
                    payload
                        .as_ref()
                        .context("continuous input custody has no payload")?
                ],
            )?;
            if let Some(bank) = bank {
                let retired: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM retired_banks WHERE slot=?1 AND bank=?2)",
                    params![slot, bank],
                    |r| r.get(0),
                )?;
                let gapped: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM bank_gaps WHERE slot=?1 AND bank=?2)",
                    params![slot, bank],
                    |r| r.get(0),
                )?;
                let state: Option<String> = tx
                    .query_row(
                        "SELECT state FROM banks WHERE slot=?1 AND bank=?2",
                        params![slot, bank],
                        |r| r.get(0),
                    )
                    .optional()?;
                let floor: u64 = tx.query_row(
                    "SELECT retired_slot_floor FROM continuous_state WHERE id=1",
                    [],
                    |r| r.get(0),
                )?;
                ensure!(
                    !retired
                        && !gapped
                        && state.as_deref() != Some("retiring")
                        && (state.is_some() || *slot > floor),
                    "late source input for a released or terminal gapped Bank"
                );
                let now = now_ms()?;
                tx.execute("INSERT INTO bank_activity(slot,bank,first_unix_ms,last_unix_ms) VALUES(?1,?2,?3,?3) ON CONFLICT(slot,bank) DO UPDATE SET last_unix_ms=excluded.last_unix_ms", params![slot,bank,now])?;
            } else {
                let now = now_ms()?;
                tx.execute("INSERT INTO slot_activity VALUES(?1,?2,?2,?3,?3) ON CONFLICT(slot) DO UPDATE SET last_sequence=excluded.last_sequence,last_unix_ms=excluded.last_unix_ms",params![slot,sequence,now])?;
                let terminal:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM bank_gaps WHERE slot=?1) OR EXISTS(SELECT 1 FROM retired_banks WHERE slot=?1)",[slot],|r|r.get(0))?;
                ensure!(
                    !terminal,
                    "late slot invalidation crosses released or gapped custody"
                );
            }
        }
        if let Some(bank) = bank {
            let entry = bank_updates
                .entry((*slot, *bank))
                .or_insert((*sequence, *sequence, 0, 0));
            entry.1 = *sequence;
            if kind == "rooted" {
                entry.2 = *sequence;
            }
            if matches!(kind.as_str(), "dead" | "clear") {
                entry.3 = *sequence;
            }
        } else if kind == "dead" {
            tx.execute("INSERT INTO dead_slots VALUES(?1,?2) ON CONFLICT(slot) DO UPDATE SET sequence=max(sequence,excluded.sequence)", params![slot,sequence])?;
            tx.execute(
                "UPDATE banks SET dirty=1,invalid_sequence=max(invalid_sequence,?2) WHERE slot=?1",
                params![slot, sequence],
            )?;
        }
        if let Some(payload) = payload
            && matches!(kind.as_str(), "bank_state_v2" | "rooted" | "dead" | "clear")
        {
            let codec = if payload.starts_with(b"{") {
                "json-v1"
            } else {
                "json-zstd-v1"
            };
            let raw = crate::journal::decode_payload(payload, codec, 65536)?;
            ensure!(
                digest(&raw) == *sha,
                "bank observation source digest changed"
            );
            persist_observation(
                source,
                &tx,
                *sequence,
                through,
                serde_json::from_slice(&raw)?,
            )?;
        }
    }
    // Preserve the same sequence extrema once per bank, instead of writing its
    // row twice for every account/transaction callback in this discovery batch.
    for ((slot, bank), (first, last, root, invalid)) in bank_updates {
        db_bank_update(&tx, slot, bank, first, last, root, invalid)?;
    }
    if let Some(live) = live {
        let banks: u64 = tx.query_row("SELECT count(*) FROM banks", [], |r| r.get(0))?;
        if banks > live.binding.limits.max_banks {
            if continuous.is_some() {
                return Err(RetentionPressure("retained_bank_capacity").into());
            }
            anyhow::bail!("live_canary_bank_limit");
        }
        if let Some(binding) = continuous {
            let inputs: u64 =
                tx.query_row("SELECT count(*) FROM input_custody", [], |r| r.get(0))?;
            if inputs > binding.options.retained_events {
                return Err(RetentionPressure("pending_input_event_capacity").into());
            }
        }
    }
    if let Some((last, ..)) = rows.last() {
        tx.execute(
            "UPDATE feed_state SET source_sequence=?1 WHERE id=1",
            [last],
        )?;
        if let Some(binding) = continuous {
            record_source_custody(&tx, binding, *last)?;
        }
    }
    tx.commit()?;
    let waiting: u64 = db.query_row(
        "SELECT count(*) FROM banks WHERE state='waiting'",
        [],
        |r| r.get(0),
    )?;
    ensure!(
        waiting <= MAX_ACTIVE,
        "more than 4096 unresolved banks; source retained, capture gap or backlog"
    );
    Ok(())
}
#[derive(Debug)]
struct ParentProof {
    parent_blockhash: [u8; 32],
    kind: &'static str,
    sequence: u64,
    sha256: Option<String>,
}

fn same_native_queue(a: &crate::event::NativeBankState, b: &crate::event::NativeBankState) -> bool {
    a.slot == b.slot
        && a.bank_id == b.bank_id
        && a.parent_slot == b.parent_slot
        && a.blockhash == b.blockhash
        && a.block_height == b.block_height
        && a.last_valid_block_height == b.last_valid_block_height
}

fn footer_parent_proof(
    source: &Connection,
    db: &Connection,
    state: &crate::event::NativeBankState,
    through: u64,
) -> Result<Option<ParentProof>> {
    // bank_events(slot,bank,sequence) bounds this lookup to one exact bank.
    // One footer and one exact duplicate are allowed; larger sets fail closed.
    // Do not load an oversized stored BLOB before checking its size.
    let mut rows = {
        let mut query = source.prepare("SELECT sequence,sha256,CASE WHEN length(payload)<=33554432 THEN payload END FROM events WHERE slot=?1 AND bank=?2 AND kind='block' AND sequence<=?3 ORDER BY sequence LIMIT 3")?;
        query
            .query_map(params![state.slot, state.bank_id, through], |r| {
                Ok((
                    r.get::<_, u64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<Vec<u8>>>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    if has_table(db, "input_custody")? {
        let mut query = db.prepare("SELECT sequence,sha256,CASE WHEN length(payload)<=33554432 THEN payload END FROM input_custody WHERE slot=?1 AND bank=?2 AND kind='block' AND sequence<=?3 ORDER BY sequence LIMIT 3")?;
        let recovered = query
            .query_map(params![state.slot, state.bank_id, through], |r| {
                Ok((
                    r.get::<_, u64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<Vec<u8>>>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for row in recovered {
            if let Some(old) = rows.iter().find(|old| old.0 == row.0) {
                ensure!(old == &row, "custody and source parent footer differ");
            } else {
                rows.push(row);
            }
        }
        rows.sort_by_key(|row| row.0);
    }
    ensure!(rows.len() <= 2, "too many native parent footer proofs");
    let mut proof: Option<ParentProof> = None;
    for (sequence, sha256, stored) in rows {
        let stored = stored.context("native parent footer exceeds bound")?;
        let codec = if stored.starts_with(b"{") {
            "json-v1"
        } else {
            "json-zstd-v1"
        };
        let raw = crate::journal::decode_payload(&stored, codec, 16 * 1024 * 1024)?;
        ensure!(
            digest(&raw) == sha256,
            "native parent footer digest changed"
        );
        let crate::event::Event::Block {
            slot,
            bank_id,
            parent_slot,
            parent_blockhash,
            blockhash,
            block_height,
            ..
        } = serde_json::from_slice(&raw)?
        else {
            anyhow::bail!("native parent proof is not a block footer");
        };
        ensure!(
            sequence <= through
                && slot == state.slot
                && bank_id == state.bank_id
                && parent_slot == state.parent_slot
                && blockhash == state.blockhash
                && block_height == Some(state.block_height)
                && parent_blockhash != [0; 32],
            "native parent footer identity differs"
        );
        if let Some(old) = &proof {
            ensure!(
                old.parent_blockhash == parent_blockhash && old.sha256.as_ref() == Some(&sha256),
                "contradictory native parent footers"
            );
        } else {
            proof = Some(ParentProof {
                parent_blockhash,
                kind: "native-block-footer",
                sequence,
                sha256: Some(sha256),
            });
        }
    }
    Ok(proof)
}

fn record_parent_resolution(
    db: &Connection,
    sequence: u64,
    original: &crate::event::NativeBankState,
    proof: &ParentProof,
) -> Result<()> {
    let raw = serde_json::to_string(original)?;
    db.execute("INSERT OR IGNORE INTO bank_parent_resolutions(source_sequence,slot,bank,original_json,parent_blockhash,proof_kind,proof_sequence,proof_sha256) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![sequence, original.slot, original.bank_id, raw, proof.parent_blockhash.as_slice(),
                proof.kind, proof.sequence, proof.sha256])?;
    let (previous, parent): (String, Vec<u8>) = db.query_row(
        "SELECT original_json,parent_blockhash FROM bank_parent_resolutions WHERE source_sequence=?1",
        [sequence], |r| Ok((r.get(0)?, r.get(1)?)))?;
    ensure!(
        previous == raw && parent == proof.parent_blockhash,
        "native parent resolution evidence changed"
    );
    Ok(())
}

fn persist_observation(
    source: &Connection,
    db: &Connection,
    sequence: u64,
    through: u64,
    event: crate::event::Event,
) -> Result<()> {
    use crate::event::Event;
    match event {
        Event::BankStateV2(mut state) => {
            state.validate()?;
            let row: Option<(Option<String>, u64, Option<String>, u64)> = db.query_row(
                "SELECT frozen_json,frozen_sequence,confirmed_json,confirmed_sequence FROM bank_observations WHERE slot=?1 AND bank=?2",
                params![state.slot, state.bank_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).optional()?;
            let mut previous = Vec::new();
            if let Some((frozen, frozen_sequence, confirmed, confirmed_sequence)) = row {
                for (column, raw, old_sequence, confirmed) in [
                    ("frozen", frozen, frozen_sequence, false),
                    ("confirmed", confirmed, confirmed_sequence, true),
                ] {
                    if let Some(raw) = raw {
                        let old: crate::event::NativeBankState = serde_json::from_str(&raw)?;
                        old.validate()?;
                        ensure!(
                            old_sequence > 0
                                && old_sequence <= through
                                && old.confirmed == confirmed
                                && same_native_queue(&old, &state),
                            "contradictory native bank queue tuple"
                        );
                        previous.push((column, old_sequence, old));
                    }
                }
            }
            let mut proof = (state.parent_blockhash != [0; 32]).then(|| ParentProof {
                parent_blockhash: state.parent_blockhash,
                kind: "native-bank-observation",
                sequence,
                sha256: None,
            });
            for (_, old_sequence, old) in &previous {
                if old.parent_blockhash != [0; 32] {
                    if let Some(proof) = &proof {
                        ensure!(
                            proof.parent_blockhash == old.parent_blockhash,
                            "contradictory native bank queue tuple"
                        );
                    } else {
                        proof = Some(ParentProof {
                            parent_blockhash: old.parent_blockhash,
                            kind: "native-bank-observation",
                            sequence: *old_sequence,
                            sha256: None,
                        });
                    }
                }
            }
            if state.parent_blockhash == [0; 32]
                || previous
                    .iter()
                    .any(|(_, _, old)| old.parent_blockhash == [0; 32])
            {
                if let Some(footer) = footer_parent_proof(source, db, &state, through)? {
                    if let Some(old) = &proof {
                        ensure!(
                            old.parent_blockhash == footer.parent_blockhash,
                            "contradictory native bank queue tuple"
                        );
                    }
                    proof = Some(footer);
                }
                let proof = proof.context("zero native parent hash has no exact retained proof")?;
                if state.parent_blockhash == [0; 32] {
                    record_parent_resolution(db, sequence, &state, &proof)?;
                    state.parent_blockhash = proof.parent_blockhash;
                }
                for (column, old_sequence, mut old) in previous {
                    if old.parent_blockhash == [0; 32] {
                        record_parent_resolution(db, old_sequence, &old, &proof)?;
                        old.parent_blockhash = proof.parent_blockhash;
                        db.execute(&format!("UPDATE bank_observations SET {column}_json=?3 WHERE slot=?1 AND bank=?2"),
                            params![old.slot, old.bank_id, serde_json::to_string(&old)?])?;
                    }
                }
                state.validate()?;
            }
            let raw = serde_json::to_string(&state)?;
            db.execute(
                "INSERT OR IGNORE INTO bank_observations(slot,bank) VALUES(?1,?2)",
                params![state.slot, state.bank_id],
            )?;
            if state.confirmed {
                db.execute("UPDATE bank_observations SET confirmed_json=coalesce(confirmed_json,?3),confirmed_sequence=CASE WHEN confirmed_sequence=0 THEN ?4 ELSE confirmed_sequence END WHERE slot=?1 AND bank=?2",params![state.slot,state.bank_id,raw,sequence])?;
            } else {
                db.execute("UPDATE bank_observations SET frozen_json=coalesce(frozen_json,?3),frozen_sequence=CASE WHEN frozen_sequence=0 THEN ?4 ELSE frozen_sequence END WHERE slot=?1 AND bank=?2",params![state.slot,state.bank_id,raw,sequence])?;
            }
        }
        Event::BankStatusV2 {
            schema,
            slot,
            bank_id,
            status,
            observed_at_unix_ms,
            ..
        } => {
            ensure!(
                schema == crate::event::BANK_V2
                    && observed_at_unix_ms <= blockzilla_bank_stream_v2::SAFE,
                "invalid native status"
            );
            if !matches!(status.as_str(), "rooted" | "clear" | "dead") {
                return Ok(());
            }
            db.execute(
                "INSERT INTO bank_controls VALUES(?1,?2,?3,?4,?5)",
                params![sequence, slot, bank_id, status, observed_at_unix_ms],
            )?;
            if let Some(bank) = bank_id {
                db.execute(
                    "INSERT OR IGNORE INTO bank_observations(slot,bank) VALUES(?1,?2)",
                    params![slot, bank],
                )?;
                let column = if status == "rooted" {
                    "root_observed_ms"
                } else {
                    "invalid_observed_ms"
                };
                db.execute(&format!("UPDATE bank_observations SET {column}=CASE WHEN {column}=0 THEN ?3 ELSE {column} END WHERE slot=?1 AND bank=?2"),params![slot,bank,observed_at_unix_ms])?;
            } else if status == "dead" {
                db.execute("UPDATE bank_observations SET invalid_observed_ms=CASE WHEN invalid_observed_ms=0 THEN ?2 ELSE invalid_observed_ms END WHERE slot=?1",params![slot,observed_at_unix_ms])?;
            }
        }
        _ => {}
    }
    Ok(())
}
#[cfg(test)]
fn db_bank(db: &Connection, slot: u64, bank: u64, sequence: u64, kind: &str) -> Result<()> {
    let rooted = if kind == "rooted" { sequence } else { 0 };
    let invalid = if matches!(kind, "dead" | "clear") {
        sequence
    } else {
        0
    };
    db_bank_update(db, slot, bank, sequence, sequence, rooted, invalid)
}
fn db_bank_update(
    db: &Connection,
    slot: u64,
    bank: u64,
    first: u64,
    last: u64,
    rooted: u64,
    invalid: u64,
) -> Result<()> {
    db.execute("INSERT INTO banks(slot,bank,first_sequence,last_sequence,root_sequence,invalid_sequence) VALUES(?1,?2,?3,?4,?5,?6)
        ON CONFLICT(slot,bank) DO UPDATE SET last_sequence=excluded.last_sequence,root_sequence=max(root_sequence,excluded.root_sequence),invalid_sequence=max(invalid_sequence,excluded.invalid_sequence),dirty=1",
        params![slot,bank,first,last,rooted,invalid])?;
    db.execute("UPDATE banks SET invalid_sequence=max(invalid_sequence,coalesce((SELECT sequence FROM dead_slots WHERE slot=?1),0)) WHERE slot=?1 AND bank=?2", params![slot,bank])?;
    Ok(())
}

fn projection(bank: &worker::CompleteBank) -> Result<String> {
    // Root/footer records are deliberately absent from the immutable execution identity.
    Ok(digest(&serde_json::to_vec(&(
        &bank.row,
        &bank.block,
        &bank.poh,
        &bank.signatures,
    ))?))
}
fn source_records(
    source: &Connection,
    c: &ContextData,
    slot: u64,
    bank: u64,
    through: u64,
) -> Result<Vec<RawEvidence>> {
    worker::bank_events_through(source, slot, bank, &c.codec, c.max_event_bytes, through)
}

fn continuous_records(
    db: &Connection,
    source: &Connection,
    c: &ContextData,
    slot: u64,
    bank: u64,
    through: u64,
) -> Result<Vec<RawEvidence>> {
    let mut records = BTreeMap::<u64, RawEvidence>::new();
    let artifact: Option<(String,String)> = db.query_row("SELECT artifact,marker_sha FROM banks WHERE slot=?1 AND bank=?2 AND artifact IS NOT NULL", params![slot,bank], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
    if let Some((artifact, marker_sha)) = artifact {
        let base = Path::new(&artifact);
        ensure!(
            base == c.output.join(format!("live-banks/{slot}-{bank}.compact")),
            "continuous replay artifact escaped its Bank path"
        );
        let marker_bytes =
            bounded_regular(&base.join("DIRECT-AGAVE-COMPACT.v1.json"), 16 * 1024 * 1024)?;
        ensure!(
            digest(&marker_bytes) == marker_sha,
            "continuous replay marker changed"
        );
        let marker: Value = serde_json::from_slice(&marker_bytes)?;
        let file = marker["files"]
            .as_array()
            .context("compact marker has no files")?
            .iter()
            .find(|row| row["path"] == "source-events.json.zst")
            .context("compact has no input custody")?;
        let path = base.join("source-events.json.zst");
        ensure!(
            fs::symlink_metadata(&path)?.file_type().is_file(),
            "continuous input custody is not regular"
        );
        let compressed = bounded_regular(&path, 512 * 1024 * 1024)?;
        ensure!(
            compressed.len() <= 512 * 1024 * 1024
                && file["bytes"] == compressed.len()
                && file["sha256"] == digest(&compressed),
            "compact input custody changed"
        );
        let mut bytes = Vec::new();
        zstd::stream::read::Decoder::new(compressed.as_slice())?
            .take(256 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 256 * 1024 * 1024
                && marker["source_events_uncompressed_bytes"] == bytes.len()
                && marker["source_events_uncompressed_sha256"] == digest(&bytes),
            "compact input custody decoded checksum differs"
        );
        for record in serde_json::from_slice::<Vec<RawEvidence>>(&bytes)? {
            ensure!(
                record.sequence <= through
                    && digest(record.event.get().as_bytes()) == record.sha256,
                "invalid compact input record"
            );
            records.insert(record.sequence, record);
        }
    }
    let mut query = db.prepare("SELECT sequence,sha256,payload FROM input_custody WHERE slot=?1 AND (bank=?2 OR bank IS NULL) AND sequence<=?3 ORDER BY sequence")?;
    let mut rows = query.query(params![slot, bank, through])?;
    let mut decoded_bytes = 0usize;
    while let Some(row) = rows.next()? {
        let sequence: u64 = row.get(0)?;
        let sha256: String = row.get(1)?;
        let stored: Vec<u8> = row.get(2)?;
        let bytes = crate::journal::decode_payload(&stored, &c.codec, c.max_event_bytes)?;
        decoded_bytes = decoded_bytes
            .checked_add(bytes.len())
            .context("continuous input size overflow")?;
        ensure!(
            decoded_bytes <= 128 * 1024 * 1024 && records.len() < 1_000_000,
            "continuous Bank input exceeds budget"
        );
        ensure!(
            digest(&bytes) == sha256,
            "continuous input custody digest differs"
        );
        let record = RawEvidence {
            sequence,
            sha256,
            event: serde_json::value::RawValue::from_string(String::from_utf8(bytes)?)?,
        };
        if let Some(old) = records.get(&sequence) {
            ensure!(
                old.sha256 == record.sha256,
                "continuous input custody conflict"
            );
        }
        records.insert(sequence, record);
    }
    for record in source_records(source, c, slot, bank, through)? {
        if let Some(old) = records.get(&record.sequence) {
            ensure!(
                old.sha256 == record.sha256,
                "continuous live source/custody conflict"
            );
        }
        records.insert(record.sequence, record);
    }
    Ok(records.into_values().collect())
}

fn expire_incomplete_banks(
    source: &Connection,
    db: &mut Connection,
    c: &ContextData,
) -> Result<usize> {
    let live = c.live.as_ref().context("gap expiry lacks live guard")?;
    let binding = live
        .continuous
        .as_deref()
        .context("gap expiry is continuous-only")?;
    let root:Option<(u64,u64)>=db.query_row("SELECT slot,source_sequence FROM bank_controls WHERE kind='rooted' ORDER BY slot DESC,source_sequence DESC LIMIT 1",[],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    let Some((root_slot, root_sequence)) = root else {
        return Ok(0);
    };
    let root_sha: String = db.query_row(
        "SELECT sha256 FROM input_custody WHERE sequence=?1",
        [root_sequence],
        |r| r.get(0),
    )?;
    let rows = {
        let mut q=db.prepare("SELECT b.slot,b.bank,b.first_sequence,b.last_sequence,b.invalid_sequence,a.last_unix_ms,b.artifact,b.marker_sha,b.identity FROM banks b JOIN bank_activity a ON a.slot=b.slot AND a.bank=b.bank WHERE ((b.artifact IS NULL AND b.state IN ('waiting','invalidated')) OR (b.state='published' AND NOT EXISTS(SELECT 1 FROM bank_observations o WHERE o.slot=b.slot AND o.bank=b.bank AND o.confirmed_json IS NOT NULL))) AND b.dirty=0 ORDER BY b.first_sequence LIMIT 32")?;
        q.query_map([], |r| {
            Ok((
                r.get::<_, u64>(0)?,
                r.get::<_, u64>(1)?,
                r.get::<_, u64>(2)?,
                r.get::<_, u64>(3)?,
                r.get::<_, u64>(4)?,
                r.get::<_, u64>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, Option<String>>(7)?,
                r.get::<_, Option<String>>(8)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?
    };
    let mut changed = 0;
    for (slot, bank, first, last, invalid, updated, artifact, marker, identity) in rows {
        if root_slot.saturating_sub(slot) <= binding.options.retained_banks
            || now_ms()?.saturating_sub(updated) < binding.options.min_retention_ms
        {
            continue;
        }
        let evidence = continuous_records(db, source, c, slot, bank, last)?;
        ensure!(
            !evidence.is_empty(),
            "incomplete Bank lost its durable input custody"
        );
        let evidence_sha256 = digest(&serde_json::to_vec(&evidence)?);
        live.before_event(&c.output, db)?;
        let tx = db.transaction()?;
        let complete = artifact.is_some();
        let reason = if complete {
            "complete-unconfirmed-bank-expired"
        } else if invalid > 0 {
            "incomplete-bank-invalidated"
        } else {
            "incomplete-bank-expired"
        };
        let sequence = append_event(
            &tx,
            "gap",
            last,
            &json!({"slot":slot,"bank_id":bank}),
            &evidence_sha256,
            "",
            Some(reason),
        )?;
        let gap = json!({"schema":if complete {"hivezilla-nonterminal-bank-gap-v1"}else{"hivezilla-incomplete-bank-gap-v1"},"producer_generation":binding.producer_generation,
            "gap_sequence":sequence,"slot":slot,"bank_id":bank,"first_source_sequence":first,"last_source_sequence":last,
            "reason":reason,"evidence_sha256":evidence_sha256,"evidence_records":evidence.len(),"expired_at_unix_ms":now_ms()?,
            "root_proof":{"slot":root_slot,"source_sequence":root_sequence,"payload_sha256":root_sha},
            "custody":{"producer_db":c.output.join("feed.sqlite"),"slot":slot,"bank_id":bank,"through_source_sequence":last,"artifact":artifact,"marker_sha256":marker},
            "bank_identity":identity.map(|raw|serde_json::from_str::<Value>(&raw)).transpose()?,
            "complete_bank":complete,"canonical_status":"UNKNOWN","captured_input_preserved":true});
        let raw: String = tx.query_row(
            "SELECT event_json FROM feed_events WHERE sequence=?1",
            [sequence],
            |r| r.get(0),
        )?;
        let mut event: Value = serde_json::from_str(&raw)?;
        event["gap"] = gap.clone();
        tx.execute(
            "UPDATE feed_events SET event_json=?2 WHERE sequence=?1",
            params![sequence, event.to_string()],
        )?;
        tx.execute(
            "INSERT INTO bank_gaps VALUES(?1,?2,?3,?4,?5)",
            params![slot, bank, sequence, evidence_sha256, gap.to_string()],
        )?;
        tx.execute(
            "UPDATE banks SET state='gapped',dirty=0 WHERE slot=?1 AND bank=?2",
            params![slot, bank],
        )?;
        tx.commit()?;
        changed += 1;
    }
    let slots = {
        let mut q=db.prepare("SELECT slot,first_sequence,last_sequence,last_unix_ms FROM slot_activity a WHERE NOT EXISTS(SELECT 1 FROM banks b WHERE b.slot=a.slot) AND NOT EXISTS(SELECT 1 FROM slot_gaps g WHERE g.slot=a.slot) ORDER BY first_sequence LIMIT 32")?;
        q.query_map([], |r| {
            Ok((
                r.get::<_, u64>(0)?,
                r.get::<_, u64>(1)?,
                r.get::<_, u64>(2)?,
                r.get::<_, u64>(3)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?
    };
    for (slot, first, last, updated) in slots {
        if root_slot.saturating_sub(slot) <= binding.options.retained_banks
            || now_ms()?.saturating_sub(updated) < binding.options.min_retention_ms
        {
            continue;
        }
        let evidence = slot_control_records(db, c, slot)?;
        ensure!(
            !evidence.is_empty(),
            "slot control lost its exact input custody"
        );
        let sha = digest(&serde_json::to_vec(&evidence)?);
        live.before_event(&c.output, db)?;
        let tx = db.transaction()?;
        let previous: u64 = tx.query_row(
            "SELECT event_sequence FROM feed_state WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        let sequence = previous.checked_add(1).context("slot gap event overflow")?;
        ensure!(
            sequence <= blockzilla_bank_stream_v2::SAFE,
            "slot gap event exceeds cursor bound"
        );
        let gap = json!({"schema":"hivezilla-slot-control-gap-v1","producer_generation":binding.producer_generation,"gap_sequence":sequence,
            "slot":slot,"bank_id":null,"first_source_sequence":first,"last_source_sequence":last,"reason":"slot-control-without-bank-expired",
            "evidence_sha256":sha,"evidence_records":evidence.len(),"expired_at_unix_ms":now_ms()?,"root_proof":{"slot":root_slot,"source_sequence":root_sequence,"payload_sha256":root_sha},
            "custody":{"producer_db":c.output.join("feed.sqlite"),"slot":slot,"bank_id":null,"through_source_sequence":last,"artifact":null,"marker_sha256":null},
            "bank_identity":null,"complete_bank":false,"canonical_status":"UNKNOWN","captured_input_preserved":true});
        let event = json!({"sequence":sequence,"source_sequence":last,"kind":"gap","bank":{"slot":slot,"bank_id":null},"payload_sha256":sha,"gap":gap});
        // feed_events.bank is an internal required INTEGER column. A slot-only
        // gap has no Bank identity in its JSON or release contract.
        tx.execute(
            "INSERT INTO feed_events VALUES(?1,'gap',?2,0,'',?3)",
            params![sequence, slot, event.to_string()],
        )?;
        tx.execute(
            "UPDATE feed_state SET event_sequence=?1 WHERE id=1",
            [sequence],
        )?;
        tx.execute(
            "INSERT INTO slot_gaps VALUES(?1,?2,?3,?4)",
            params![slot, sequence, sha, gap.to_string()],
        )?;
        tx.commit()?;
        changed += 1;
    }
    Ok(changed)
}
fn slot_control_records(db: &Connection, c: &ContextData, slot: u64) -> Result<Vec<RawEvidence>> {
    let mut q=db.prepare("SELECT sequence,sha256,payload FROM input_custody WHERE slot=?1 AND bank IS NULL ORDER BY sequence")?;
    let mut rows = q.query([slot])?;
    let mut output = Vec::new();
    let mut bytes = 0usize;
    while let Some(row) = rows.next()? {
        let raw: Vec<u8> = row.get(2)?;
        let raw = crate::journal::decode_payload(&raw, &c.codec, c.max_event_bytes)?;
        bytes = bytes
            .checked_add(raw.len())
            .context("slot-control custody size overflow")?;
        ensure!(
            bytes <= 128 * 1024 * 1024 && output.len() < 1_000_000,
            "slot-control custody exceeds bound"
        );
        let sha: String = row.get(1)?;
        ensure!(digest(&raw) == sha, "slot-control custody digest changed");
        output.push(RawEvidence {
            sequence: row.get(0)?,
            sha256: sha,
            event: serde_json::value::RawValue::from_string(String::from_utf8(raw)?)?,
        });
    }
    Ok(output)
}
fn read_retained_file(path: &Path, root: &Path, helper: Option<&Path>) -> Result<Vec<u8>> {
    match fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && helper.is_some() => {
            let helper = helper.unwrap();
            ensure!(
                helper.is_absolute() && path.starts_with(root),
                "unsafe archive restore path"
            );
            let status = Command::new(helper)
                .arg("restore")
                .arg("--output")
                .arg(root)
                .arg("--path")
                .arg(path)
                .status()
                .context("native archive restore helper failed")?;
            ensure!(
                status.success(),
                "native archive restore failed; source remains captured"
            );
            Ok(fs::read(path).context("restored native source is unavailable")?)
        }
        Err(error) => Err(error.into()),
    }
}

fn retained_records(
    db: &Connection,
    source: &Connection,
    c: &ContextData,
    slot: u64,
    bank: u64,
    through: u64,
) -> Result<Vec<RawEvidence>> {
    let proof: Option<(String, String)> = db
        .query_row(
            "SELECT custody_path,custody_sha FROM archive_catalog WHERE slot=?1 AND bank=?2",
            params![slot, bank],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let mut records = BTreeMap::new();
    if let Some((path, sha)) = proof {
        let raw = fs::read(&path)?;
        ensure!(digest(&raw) == sha, "retained custody proof changed");
        let proof: Value = serde_json::from_slice(&raw)?;
        let base = Path::new(&path)
            .parent()
            .context("missing custody directory")?;
        let row = &proof["files"][0];
        let helper = std::env::var_os("HIVEZILLA_NATIVE_ARCHIVE_HELPER").map(PathBuf::from);
        let compressed = read_retained_file(
            &base.join("source-events.json.zst"),
            &c.output,
            helper.as_deref(),
        )?;
        ensure!(
            row["bytes"] == compressed.len() && row["sha256"] == digest(&compressed),
            "retained custody source changed"
        );
        let mut bytes = Vec::new();
        zstd::stream::read::Decoder::new(compressed.as_slice())?
            .take(256 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 256 * 1024 * 1024,
            "retained source exceeds limit"
        );
        for record in serde_json::from_slice::<Vec<RawEvidence>>(&bytes)? {
            records.insert(record.sequence, record);
        }
    }
    for record in source_records(source, c, slot, bank, through)? {
        if let Some(old) = records.get(&record.sequence) {
            ensure!(
                old.sha256 == record.sha256,
                "retained and live source conflict"
            );
        }
        records.insert(record.sequence, record);
    }
    Ok(records.into_values().collect())
}

struct PendingPayload {
    end: u64,
    id: Value,
    normalized: PathBuf,
    compact: PathBuf,
    marker_sha: String,
    projection: String,
}

#[derive(Default)]
struct PreparedBank {
    complete: Option<worker::CompleteBank>,
    payload: Option<PendingPayload>,
    projection: Option<String>,
    custody: Option<PathBuf>,
}

fn prepare_payload(
    c: &ContextData,
    slot: u64,
    bank: u64,
    mut complete: worker::CompleteBank,
    initial_projection: String,
) -> Result<(worker::CompleteBank, PendingPayload)> {
    let end = complete
        .evidence
        .iter()
        .map(|e| e.sequence)
        .max()
        .context("empty source bank")?;
    let id = identity(&complete.row);
    if let Some(live) = &c.live {
        live.monitor(&c.output)?;
    }
    let base = if c.live.is_some() {
        c.output.join(format!("live-banks/{slot}-{bank}"))
    } else {
        c.output
            .join(format!("epoch-{}/{}-{}", slot / 432000, slot, bank))
    };
    fs::create_dir_all(base.parent().unwrap())?;
    let normalized = base.with_extension("normalized");
    let compact = base.with_extension("compact");
    if !normalized.exists() {
        worker::write_bank_normalized(
            &normalized,
            &c.meta,
            &c.id,
            &c.genesis,
            std::slice::from_mut(&mut complete),
            false,
        )?;
    } else {
        // An orphaned build is bound to its retained source evidence, not a new callback snapshot.
        let receipt: worker::Receipt = serde_json::from_slice(&fs::read(
            normalized.join("DIRECT-AGAVE-NORMALIZED.v1.json"),
        )?)?;
        ensure!(
            receipt.blocks == vec![complete.row.clone()] && !receipt.finalized,
            "pending processed bank identity changed"
        );
        let evidence: Vec<RawEvidence> =
            serde_json::from_slice(&fs::read(normalized.join("evidence/source-events.json"))?)?;
        let pending = worker::assemble_bank(slot, bank, evidence, false)?
            .context("pending processed bank is incomplete")?;
        ensure!(
            projection(&pending)? == initial_projection,
            "pending processed bank execution changed"
        );
    }
    if !compact.exists() {
        let mut command = Command::new(&c.builder);
        command
            .arg("build-direct-agave-compact")
            .arg(&normalized)
            .arg(&compact)
            .args(["--level", "1"]);
        let status = if let Some(live) = &c.live {
            live_writer(&mut command, live, &c.output)?
        } else {
            command.status()?
        };
        ensure!(
            status.success(),
            "processed compact writer failed; source and pending stage preserved"
        );
    }
    if let Some(live) = &c.live {
        live.monitor(&c.output)?;
    }
    worker::validate_compact_commit(&compact, &normalized)?;
    let marker_sha = digest(&fs::read(compact.join("DIRECT-AGAVE-COMPACT.v1.json"))?);
    Ok((
        complete,
        PendingPayload {
            end,
            id,
            normalized,
            compact,
            marker_sha,
            projection: initial_projection,
        },
    ))
}

fn commit_payload(
    c: &ContextData,
    db: &mut Connection,
    slot: u64,
    bank: u64,
    payload: &PendingPayload,
) -> Result<()> {
    commit_payload_record(db, slot, bank, payload)?;
    // This is the ordinary stage owned and validated by prepare_payload. A
    // restart after this FULL commit instead uses the strict recovery below.
    fs::remove_dir_all(&payload.normalized)?;
    File::open(
        payload
            .normalized
            .parent()
            .context("normalized lacks parent")?,
    )?
    .sync_all()?;
    if committed_recovery_needed(&payload.compact)? {
        recover_committed_payload(c, db, slot, bank)?;
    }
    Ok(())
}

fn commit_payload_record(
    db: &mut Connection,
    slot: u64,
    bank: u64,
    payload: &PendingPayload,
) -> Result<()> {
    let artifact = payload
        .compact
        .to_str()
        .context("non UTF-8 artifact path")?;
    let tx = db.transaction()?;
    append_event(
        &tx,
        "block",
        payload.end,
        &payload.id,
        &payload.marker_sha,
        artifact,
        None,
    )?;
    tx.execute("UPDATE banks SET state='published',artifact=?3,marker_sha=?4,projection_sha=?5,through_sequence=?6,identity=?7 WHERE slot=?1 AND bank=?2",
        params![slot,bank,artifact,payload.marker_sha,payload.projection,payload.end,payload.id.to_string()])?;
    tx.commit()?;
    Ok(())
}

fn committed_recovery_needed(compact: &Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    match fs::symlink_metadata(compact.with_extension("normalized")) {
        Ok(_) => return Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    for entry in fs::read_dir(compact)? {
        if fs::symlink_metadata(entry?.path())?.nlink() > 1 {
            return Ok(true);
        }
    }
    Ok(false)
}

fn owned_file_hash(path: &Path, max: u64, readonly: bool) -> Result<(fs::Metadata, String)> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.file_type().is_file()
            && before.uid() == unsafe { libc::geteuid() }
            && before.len() <= max
            && before.mode() & 0o022 == 0
            && (!readonly || before.mode() & 0o222 == 0),
        "unsafe recovery file: {}",
        path.display()
    );
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let opened = file.metadata()?;
    ensure!(
        opened.dev() == before.dev() && opened.ino() == before.ino(),
        "recovery file changed before open"
    );
    let mut digest = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        bytes = bytes
            .checked_add(n as u64)
            .context("recovery byte overflow")?;
        ensure!(bytes <= max, "recovery file exceeds bound");
        digest.update(&buffer[..n]);
    }
    let after = file.metadata()?;
    ensure!(
        bytes == before.len()
            && after.dev() == before.dev()
            && after.ino() == before.ino()
            && after.len() == before.len()
            && after.mtime() == before.mtime()
            && after.mtime_nsec() == before.mtime_nsec()
            && after.mode() == before.mode()
            && after.uid() == before.uid()
            && after.nlink() == before.nlink(),
        "recovery file changed during read"
    );
    Ok((
        before,
        digest
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    ))
}

fn owned_directory(path: &Path) -> Result<fs::Metadata> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o022 == 0,
        "unsafe recovery directory: {}",
        path.display()
    );
    Ok(metadata)
}

fn cleanup_committed_normalized(
    path: &Path,
    receipt: &worker::Receipt,
    receipt_sha: &str,
) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    }
    owned_directory(path)?;
    let mut allowed = BTreeMap::<PathBuf, (u64, String)>::new();
    let mut directories = std::collections::BTreeSet::new();
    for file in &receipt.files {
        let relative = Path::new(&file.path);
        ensure!(
            !relative.as_os_str().is_empty()
                && relative
                    .components()
                    .all(|c| matches!(c, std::path::Component::Normal(_))),
            "unsafe normalized receipt path"
        );
        ensure!(
            allowed
                .insert(relative.into(), (file.bytes, file.sha256.clone()))
                .is_none(),
            "duplicate normalized receipt path"
        );
        let mut parent = relative.parent();
        while let Some(p) = parent {
            if p.as_os_str().is_empty() {
                break;
            }
            directories.insert(p.to_path_buf());
            parent = p.parent();
        }
    }
    let receipt_path = PathBuf::from("DIRECT-AGAVE-NORMALIZED.v1.json");
    // The receipt can already be absent after a partial cleanup. Its exact
    // copy remains in the verified committed compact manifest.
    if path.join(&receipt_path).try_exists()? {
        let (metadata, sha) = owned_file_hash(&path.join(&receipt_path), 16 * 1024 * 1024, false)?;
        ensure!(sha == receipt_sha, "normalized recovery receipt changed");
        allowed.insert(receipt_path, (metadata.len(), sha));
    }
    let mut pending = vec![path.to_path_buf()];
    let mut entries = 0;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let full = entry?.path();
            entries += 1;
            ensure!(entries <= 1024, "normalized recovery entry bound");
            let relative = full.strip_prefix(path)?.to_path_buf();
            let metadata = fs::symlink_metadata(&full)?;
            if metadata.file_type().is_dir() {
                ensure!(
                    directories.contains(&relative),
                    "unknown normalized recovery directory: {}",
                    full.display()
                );
                owned_directory(&full)?;
                pending.push(full);
            } else {
                let (size, expected) = allowed.get(&relative).with_context(|| {
                    format!("unknown normalized recovery object: {}", full.display())
                })?;
                let (metadata, sha) = owned_file_hash(&full, 1024 * 1024 * 1024, false)?;
                ensure!(
                    metadata.len() == *size && &sha == expected,
                    "normalized recovery object changed: {}",
                    full.display()
                );
            }
        }
    }
    fs::remove_dir_all(path)?;
    File::open(path.parent().context("normalized recovery lacks parent")?)?.sync_all()?;
    Ok(())
}

fn detach_committed_alias(
    path: &Path,
    bytes: u64,
    sha: &str,
    before_rename: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let (before, observed) = owned_file_hash(path, 512 * 1024 * 1024, true)?;
    ensure!(
        before.len() == bytes && observed == sha,
        "committed alias differs from manifest"
    );
    if before.nlink() == 1 {
        return Ok(());
    }
    ensure!(before.nlink() > 1, "committed recovery file lost its link");
    let compact = path.parent().context("alias lacks compact directory")?;
    let parent = compact.parent().context("alias lacks output parent")?;
    owned_directory(compact)?;
    owned_directory(parent)?;
    let name = path
        .file_name()
        .context("alias lacks filename")?
        .to_str()
        .context("alias filename is not UTF-8")?;
    let temporary = parent.join(format!(
        ".{}.detach-{}-{}-{}",
        compact.file_name().unwrap().to_string_lossy(),
        name,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
        std::process::id()
    ));
    // This new inode is read-only from creation. Its open write descriptor is
    // used only for this verified copy; existing evidence is never chmodded.
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)?;
    let input = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let opened = input.metadata()?;
    ensure!(
        opened.dev() == before.dev() && opened.ino() == before.ino(),
        "alias replaced before copy"
    );
    let copied = std::io::copy(&mut input.take(bytes + 1), &mut output)?;
    ensure!(copied == bytes, "alias copy length changed");
    output.sync_all()?;
    drop(output);
    File::open(parent)?.sync_all()?;
    let (copy, copy_sha) = owned_file_hash(&temporary, 512 * 1024 * 1024, true)?;
    ensure!(
        copy.len() == bytes && copy.nlink() == 1 && copy_sha == sha,
        "private alias copy differs"
    );
    let (current, current_sha) = owned_file_hash(path, 512 * 1024 * 1024, true)?;
    ensure!(
        current.dev() == before.dev()
            && current.ino() == before.ino()
            && current.nlink() == before.nlink()
            && current.len() == bytes
            && current_sha == sha,
        "committed alias changed before replacement"
    );
    before_rename(&temporary)?;
    fs::rename(&temporary, path)?;
    File::open(compact)?.sync_all()?;
    File::open(parent)?.sync_all()?;
    let (after, after_sha) = owned_file_hash(path, 512 * 1024 * 1024, true)?;
    ensure!(
        after.nlink() == 1 && after.len() == bytes && after_sha == sha,
        "detached active object is not private"
    );
    Ok(())
}

fn recover_committed_payload(c: &ContextData, db: &Connection, slot: u64, bank: u64) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let (state, artifact, marker_sha, stored_identity): (String, String, String, String) = db
        .query_row(
            "SELECT state,artifact,marker_sha,identity FROM banks WHERE slot=?1 AND bank=?2",
            params![slot, bank],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
    ensure!(
        matches!(
            state.as_str(),
            "published" | "rooted" | "invalidated" | "gapped"
        ),
        "recovery Bank is not committed"
    );
    let base = if c.live.is_some() {
        c.output.join(format!("live-banks/{slot}-{bank}"))
    } else {
        c.output
            .join(format!("epoch-{}/{slot}-{bank}", slot / 432000))
    };
    let compact = base.with_extension("compact");
    let normalized = base.with_extension("normalized");
    ensure!(
        Path::new(&artifact) == compact,
        "committed recovery path differs"
    );
    owned_directory(&compact)?;
    if let Some(live) = &c.live {
        let inventory = live
            .inventory
            .lock()
            .map_err(|_| anyhow::anyhow!("recovery inventory lock poisoned"))?;
        ensure!(
            !inventory.sealed.contains_key(&compact),
            "cannot recover an already sealed compact"
        );
    }
    let marker_path = compact.join("DIRECT-AGAVE-COMPACT.v1.json");
    let (marker_metadata, sha) = owned_file_hash(&marker_path, 16 * 1024 * 1024, true)?;
    ensure!(
        marker_metadata.nlink() == 1 && sha == marker_sha,
        "committed recovery marker changed"
    );
    worker::validate_compact_commit(&compact, &compact)?;
    let marker: Value = serde_json::from_slice(&bounded_regular(&marker_path, 16 * 1024 * 1024)?)?;
    let blocks: Vec<BlockRow> = serde_json::from_value(marker["produced_blocks"].clone())?;
    ensure!(
        blocks.len() == 1
            && blocks[0].slot == slot
            && blocks[0].bank_id == bank
            && identity(&blocks[0]) == serde_json::from_str::<Value>(&stored_identity)?
            && marker["session_id"] == c.id
            && marker["genesis_hash"] == c.genesis
            && marker["agave_revision"] == REVISION
            && marker["node_identity"] == c.meta["config"]["node_identity"],
        "committed recovery source/Bank binding differs"
    );
    let receipt_bytes = bounded_regular(
        &compact.join("DIRECT-AGAVE-NORMALIZED.v1.json"),
        16 * 1024 * 1024,
    )?;
    let receipt: worker::Receipt = serde_json::from_slice(&receipt_bytes)?;
    let receipt_sha = digest(&receipt_bytes);
    ensure!(
        marker["source_receipt_sha256"] == receipt_sha,
        "committed recovery source receipt differs"
    );
    let mut objects = BTreeMap::new();
    for file in marker["files"]
        .as_array()
        .context("recovery manifest lacks files")?
    {
        let name = file["path"]
            .as_str()
            .context("recovery object lacks path")?;
        ensure!(
            Path::new(name).components().count() == 1
                && matches!(
                    Path::new(name).components().next(),
                    Some(std::path::Component::Normal(_))
                )
                && objects
                    .insert(
                        name.to_owned(),
                        (
                            file["bytes"]
                                .as_u64()
                                .context("recovery object lacks length")?,
                            file["sha256"]
                                .as_str()
                                .context("recovery object lacks hash")?
                                .to_owned()
                        )
                    )
                    .is_none(),
            "unsafe/duplicate recovery filename"
        );
    }
    for entry in fs::read_dir(&compact)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .unwrap()
            .to_str()
            .context("recovery name is not UTF-8")?;
        if name == "DIRECT-AGAVE-COMPACT.v1.json" {
            continue;
        }
        let (size, sha) = objects
            .get(name)
            .context("unknown committed compact recovery object")?;
        let (metadata, actual) = owned_file_hash(&path, 512 * 1024 * 1024, true)?;
        ensure!(
            metadata.len() == *size && &actual == sha,
            "committed compact recovery object changed"
        );
    }
    cleanup_committed_normalized(&normalized, &receipt, &receipt_sha)?;
    for (name, (bytes, sha)) in objects {
        let path = compact.join(name);
        if fs::symlink_metadata(&path)?.nlink() > 1 {
            detach_committed_alias(&path, bytes, &sha, |_| Ok(()))?;
        }
    }
    Ok(())
}

fn custody(
    c: &ContextData,
    slot: u64,
    bank: u64,
    complete: &worker::CompleteBank,
    artifact: &str,
    marker_sha: &str,
) -> Result<PathBuf> {
    let dir = c.output.join(format!("custody/{slot}-{bank}"));
    fs::create_dir_all(dir.parent().unwrap())?;
    let marker_path = dir.join("CUSTODY.json");
    if marker_path.exists() {
        return Ok(marker_path);
    }
    let stage = dir.with_extension("pending");
    if stage.exists() {
        fs::remove_dir_all(&stage)?;
    }
    fs::create_dir(&stage)?;
    let bytes = serde_json::to_vec(&complete.evidence)?;
    let compressed = zstd::stream::encode_all(bytes.as_slice(), 1)?;
    let mut file = File::create(stage.join("source-events.json.zst"))?;
    file.write_all(&compressed)?;
    file.sync_all()?;
    let end = complete
        .evidence
        .iter()
        .map(|e| e.sequence)
        .max()
        .context("empty rooted evidence")?;
    atomic_json(
        &stage.join("CUSTODY.json"),
        &json!({"schema":"hivezilla-direct-agave-processed-custody-v1",
        "state":"COMPLETE","session_id":c.id,"finalized":true,"canonical":false,
        "produced_blocks":[complete.row],"through_sequence":end,
        "payload_marker_path":Path::new(artifact).join("DIRECT-AGAVE-COMPACT.v1.json"),"payload_marker_sha256":marker_sha,
        "files":[{"path":"source-events.json.zst","bytes":compressed.len(),"sha256":digest(&compressed)}]}),
    )?;
    File::open(&stage)?.sync_all()?;
    fs::rename(stage, &dir)?;
    File::open(dir.parent().unwrap())?.sync_all()?;
    Ok(marker_path)
}

fn process_banks(
    _source: &Connection,
    db: &mut Connection,
    c: &ContextData,
    through: u64,
) -> Result<()> {
    if let Some(live) = &c.live {
        live.monitor(&c.output)?;
    }
    let keys = {
        let mut q = db.prepare(
            "SELECT slot,bank FROM banks WHERE dirty=1 ORDER BY last_sequence LIMIT 128",
        )?;
        q.query_map([], |r| Ok((r.get::<_, u64>(0)?, r.get::<_, u64>(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    // Keep at most four source banks in memory. Decode, normalize, convert and
    // prepare custody on separate workers. Only this writer commits feed state.
    // Live checks also run inside each converter and before every ordered
    // commit. Four pending builds can grow between checks; these application
    // limits are not a filesystem quota.
    for group in keys.chunks(4) {
        let prepared = std::thread::scope(|scope| -> Result<Vec<PreparedBank>> {
            let handles = group
                .iter()
                .copied()
                .map(|(slot, bank)| {
                    scope.spawn(move || -> Result<_> {
                        let audit = open_reader(&c.output.join("feed.sqlite"))?;
                        let (state,root,invalid,artifact,sha,old_projection):
                            (String,u64,u64,Option<String>,Option<String>,Option<String>) = audit.query_row(
                            "SELECT state,root_sequence,invalid_sequence,artifact,marker_sha,projection_sha FROM banks WHERE slot=?1 AND bank=?2",
                            params![slot, bank],
                            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)),
                        )?;
                        ensure!(root == 0 || invalid == 0, "bank has rooted and invalidation evidence");
                        if invalid > 0 {
                            return Ok(PreparedBank::default());
                        }
                        let input = open_reader(&c.session.join("events.sqlite"))?;
                        if state == "waiting" {
                            let mut footer_ready: bool = input.query_row(
                                "SELECT EXISTS(SELECT 1 FROM events WHERE slot=?1 AND bank=?2 AND kind='block' AND sequence<=?3)",
                                params![slot, bank, through], |r| r.get(0))?;
                            if !footer_ready && c.live.as_ref().is_some_and(|live| live.continuous.is_some()) {
                                footer_ready = audit.query_row("SELECT EXISTS(SELECT 1 FROM input_custody WHERE slot=?1 AND bank=?2 AND kind='block' AND sequence<=?3)", params![slot,bank,through], |r| r.get(0))?;
                            }
                            if !footer_ready {
                                return Ok(PreparedBank::default());
                            }
                        }
                        let events = if c.live.as_ref().is_some_and(|live| live.continuous.is_some()) {
                            continuous_records(&audit,&input,c,slot,bank,through)?
                        } else if c.live.is_some() {
                            source_records(&input, c, slot, bank, through)?
                        } else {
                            retained_records(&audit, &input, c, slot, bank, through)?
                        };
                        let Some(mut complete) = worker::assemble_bank(slot, bank, events, false)? else {
                            return Ok(PreparedBank::default());
                        };
                        let fingerprint = projection(&complete)?;
                        let payload = if state == "waiting" {
                            let (ready, payload) = prepare_payload(c, slot, bank, complete, fingerprint.clone())
                                .with_context(|| format!("prepare processed payload slot={slot} bank={bank} output={}", c.output.display()))?;
                            complete = ready;
                            Some(payload)
                        } else {
                            ensure!(old_projection.as_deref() == Some(&fingerprint), "execution changed after processed publication");
                            None
                        };
                        let proof = if c.live.is_none() && root > 0 && matches!(state.as_str(), "waiting" | "published") {
                            let (path, marker_sha) = if let Some(payload) = &payload {
                                (payload.compact.to_str().context("non UTF-8 artifact path")?, payload.marker_sha.as_str())
                            } else {
                                (artifact.as_deref().context("missing artifact")?, sha.as_deref().context("missing marker hash")?)
                            };
                            Some(custody(c, slot, bank, &complete, path, marker_sha)?)
                        } else { None };
                        Ok(PreparedBank { complete: Some(complete), payload, projection: Some(fingerprint), custody: proof })
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|h| {
                    h.join()
                        .map_err(|_| anyhow::anyhow!("bank reader panicked"))?
                })
                .collect()
        })?;
        for ((slot, bank), prepared) in group.iter().copied().zip(prepared) {
            let (mut state, root, invalid): (String, u64, u64) = db.query_row(
                "SELECT state,root_sequence,invalid_sequence FROM banks WHERE slot=?1 AND bank=?2",
                params![slot, bank],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
            ensure!(
                root == 0 || invalid == 0,
                "bank has both rooted and invalidation evidence: {slot}/{bank}"
            );
            if invalid > 0 {
                ensure!(state != "rooted", "rooted bank was invalidated");
                if state == "published" {
                    if let Some(live) = &c.live {
                        live.before_event(&c.output, db)?;
                    }
                    let (artifact, sha, id): (String, String, String) = db.query_row(
                        "SELECT artifact,marker_sha,identity FROM banks WHERE slot=?1 AND bank=?2",
                        params![slot, bank],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )?;
                    let tx = db.transaction()?;
                    append_event(
                        &tx,
                        "invalidate",
                        invalid,
                        &serde_json::from_str(&id)?,
                        &sha,
                        &artifact,
                        Some("agave_bank_invalidated"),
                    )?;
                    tx.execute(
                        "UPDATE banks SET state='invalidated' WHERE slot=?1 AND bank=?2",
                        params![slot, bank],
                    )?;
                    tx.commit()?;
                } else {
                    db.execute(
                        "UPDATE banks SET state='invalidated' WHERE slot=?1 AND bank=?2",
                        params![slot, bank],
                    )?;
                }
            } else {
                let complete = if state == "waiting" {
                    if let Some(complete) = prepared.complete {
                        let payload = prepared
                            .payload
                            .as_ref()
                            .context("missing prepared payload")?;
                        if let Some(live) = &c.live {
                            live.before_event(&c.output, db)?;
                        }
                        commit_payload(c, db, slot, bank, payload).with_context(|| format!(
                            "commit processed payload slot={slot} bank={bank} normalized={} compact={}",
                            payload.normalized.display(), payload.compact.display()))?;
                        // Source/compact hard links can remain until normalized
                        // cleanup. Keep the whole tree mutable-accounted until
                        // commit_payload has removed that owned duplicate.
                        if let Some(live) = &c.live {
                            live.seal_compact(
                                &c.output,
                                &payload.compact,
                                slot,
                                bank,
                                &payload.marker_sha,
                            )?;
                            if live.continuous.is_some() {
                                db.execute("DELETE FROM input_custody WHERE slot=?1 AND bank=?2 AND sequence<=?3 AND kind NOT IN ('block','bank_state_v2','rooted','dead','clear')", params![slot,bank,payload.end])?;
                            }
                        }
                        state = "published".into();
                        Some(complete)
                    } else {
                        None
                    }
                } else {
                    prepared.complete
                };
                if matches!(state.as_str(), "published" | "rooted") {
                    complete.context("published bank became incomplete")?;
                    let (sha,old_projection,artifact,id):(String,String,String,String)=db.query_row("SELECT marker_sha,projection_sha,artifact,identity FROM banks WHERE slot=?1 AND bank=?2",params![slot,bank],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
                    ensure!(
                        prepared.projection.as_deref() == Some(&old_projection),
                        "execution changed after processed publication"
                    );
                    if root > 0 && state == "published" {
                        let existing: Option<u64> = if c.live.is_some() {
                            db.query_row(
                                "SELECT bank FROM banks WHERE slot=?1 AND state='rooted'",
                                [slot],
                                |r| r.get(0),
                            )
                            .optional()?
                        } else {
                            db.query_row(
                                "SELECT bank FROM archive_catalog WHERE slot=?1",
                                [slot],
                                |r| r.get(0),
                            )
                            .optional()?
                        };
                        ensure!(
                            existing.is_none_or(|b| b == bank),
                            "two different banks rooted at one slot"
                        );
                        let custody = if c.live.is_none() {
                            let proof = prepared
                                .custody
                                .context("missing prepared rooted custody")?;
                            let custody_sha = digest(&fs::read(&proof)?);
                            Some((proof, custody_sha))
                        } else {
                            None
                        };
                        if let Some(live) = &c.live {
                            live.before_event(&c.output, db)?;
                        }
                        let tx = db.transaction()?;
                        append_event(
                            &tx,
                            "root",
                            root,
                            &serde_json::from_str(&id)?,
                            &sha,
                            &artifact,
                            None,
                        )?;
                        if let Some((proof, custody_sha)) = custody {
                            tx.execute("INSERT INTO archive_catalog(slot,bank,artifact,marker_sha,root_sequence,custody_path,custody_sha) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![slot,bank,artifact,sha,root,proof.to_str(),custody_sha])?;
                        }
                        tx.execute(
                            "UPDATE banks SET state='rooted' WHERE slot=?1 AND bank=?2",
                            params![slot, bank],
                        )?;
                        tx.commit()?;
                    }
                }
            }
            db.execute(
                "UPDATE banks SET dirty=0 WHERE slot=?1 AND bank=?2",
                params![slot, bank],
            )?;
            if let Some(live) = &c.live {
                live.monitor(&c.output)?;
            }
        }
    }
    // Retire only after the new capture writer advertises support for custody proofs.
    if c.live.is_none() && c.meta["processed_custody"] == true {
        let rows = {
            let mut q=db.prepare("SELECT slot,bank,custody_path FROM archive_catalog WHERE retirement_enqueued=0 LIMIT 128")?;
            q.query_map([], |r| {
                Ok((
                    r.get::<_, u64>(0)?,
                    r.get::<_, u64>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
        };
        for (slot, bank, path) in rows {
            let bytes = fs::read(&path)?;
            let proof: Value = serde_json::from_slice(&bytes)?;
            crate::retention::enqueue(
                &c.session,
                &crate::retention::Request {
                    schema: "hivezilla-direct-agave-retire-v1".into(),
                    session_id: c.id.clone(),
                    marker_path: path,
                    marker_sha256: digest(&bytes),
                    banks: vec![crate::retention::Bank {
                        slot,
                        bank_id: bank,
                        through_sequence: proof["through_sequence"]
                            .as_u64()
                            .context("missing custody sequence")?,
                    }],
                },
            )?;
            db.execute(
                "UPDATE archive_catalog SET retirement_enqueued=1 WHERE slot=?1",
                [slot],
            )?;
        }
    }
    Ok(())
}

pub fn run(
    session: &Path,
    output: &Path,
    builder: &Path,
    start: Option<u64>,
    follow: bool,
) -> Result<()> {
    run_mode(session, output, builder, start, follow, None)
}

/// Opt-in finite capture. It never takes custody of, restores, or retires source events.
pub fn run_live(
    session: &Path,
    output: &Path,
    builder: &Path,
    start: Option<u64>,
    follow: bool,
    limits: LiveCanaryLimits,
) -> Result<()> {
    limits.validate()?;
    run_mode(session, output, builder, start, follow, Some(limits))
}

/// A local rolling producer. Counters are monotonic; only retained custody is bounded.
pub fn run_continuous(
    session: &Path,
    output: &Path,
    builder: &Path,
    options: ContinuousLiveOptions,
) -> Result<()> {
    options.validate()?;
    fs::create_dir_all(output)?;
    let output = output.canonicalize()?;
    let session = session.canonicalize()?;
    let _lock = crate::journal::exclusive_lock(&output.join("WORKER.lock"))?;
    let result = continuous_inner(&session, &output, builder, options);
    if let Err(error) = &result {
        let failure = json!({"schema":"hivezilla-continuous-producer-failure-v1","state":"FAILED","producer_role":CONTINUOUS_ROLE,
            "error":format!("{error:#}"),"source_preserved":true,"updated_unix_ms":now_ms()?,"canonical":false,"publication_ready":false});
        let failures = output.join("failures");
        fs::create_dir_all(&failures)?;
        let path = failures.join(format!("failure-{}-{}.json", now_ms()?, std::process::id()));
        if !path.exists() {
            atomic_json(&path, &failure)?;
        }
        atomic_json(&output.join("STATUS.json"), &failure)?;
    }
    result
}

fn continuous_inner(
    session: &Path,
    output: &Path,
    builder: &Path,
    options: ContinuousLiveOptions,
) -> Result<()> {
    let meta: Value = serde_json::from_slice(&bounded_regular(
        &session.join("SESSION.json"),
        1024 * 1024,
    )?)?;
    ensure!(
        meta["schema"] == SCHEMA
            && meta["agave_revision"] == REVISION
            && meta["bank_observations_v2"] == true,
        "continuous source identity/profile is unsupported"
    );
    ensure!(
        meta["retirement"] == "local-consumed-prefix-v1"
            && meta["processed_custody"] == false
            && meta["config"]["live_source_ack"] == true,
        "continuous producer requires explicit local source ACK mode"
    );
    let journal_bytes = meta["config"]["max_journal_bytes"]
        .as_u64()
        .context("continuous source lacks journal capacity")?;
    ensure!(
        (1024 * 1024..=64 * 1024u64.pow(3)).contains(&journal_bytes),
        "continuous source journal capacity is unsupported"
    );
    let source_identity = blockzilla_bank_stream_v2::SourceIdentity {
        genesis_hash: meta["config"]["genesis_hash"]
            .as_str()
            .context("missing genesis")?
            .into(),
        node_identity: meta["config"]["node_identity"]
            .as_str()
            .context("missing node identity")?
            .into(),
        agave_revision: REVISION.into(),
        session_id: meta["session_id"]
            .as_str()
            .context("missing source session")?
            .into(),
    };
    source_identity.validate()?;
    ensure!(
        source_identity.genesis_hash == "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
        "continuous producer currently supports mainnet epoch geometry"
    );
    let source = open_reader(&session.join("events.sqlite"))?;
    let header_path = output.join("FEED.json");
    let previous: Option<Value> = if header_path.try_exists()? {
        Some(serde_json::from_slice(&bounded_regular(
            &header_path,
            65536,
        )?)?)
    } else {
        None
    };
    let started = previous
        .as_ref()
        .and_then(|p| p["started_unix_ms"].as_u64())
        .unwrap_or(now_ms()?);
    let generation = previous
        .as_ref()
        .and_then(|p| p["producer_generation"].as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            digest(
                format!(
                    "{}:{}:{}:{}",
                    source_identity.session_id,
                    started,
                    std::process::id(),
                    output.display()
                )
                .as_bytes(),
            )
        });
    let header = json!({"schema":"hivezilla-processed-feed-v1","profile":PROFILE,"producer_role":CONTINUOUS_ROLE,
        "producer_generation":generation,"started_unix_ms":started,"continuous":options,
        "session_id":source_identity.session_id,"genesis_hash":source_identity.genesis_hash,"node_identity":source_identity.node_identity,
        "agave_revision":REVISION,"start_source_sequence":0,"source_config_sha256":digest(&serde_json::to_vec(&meta["config"])?),
        "source_profile":"native-bank-observations-v2","processed_custody":false,"archive_work_enabled":false,
        "continuous_retention_implemented":true,"canonical":false,"publication_ready":false});
    if let Some(old) = &previous {
        ensure!(
            old == &header,
            "continuous source/generation/retention policy changed"
        );
        if !output.join("feed.sqlite").try_exists()? {
            // FEED is fsynced before SQLite is opened. A crash in that small
            // window has no custody or ACK. Recover only that exact layout.
            ensure!(
                !session.join("SOURCE-ACK.json").try_exists()?
                    && !session.join("SOURCE-RETIREMENT.json").try_exists()?,
                "continuous custody database is missing after source ACK"
            );
            let (first, durable): (Option<u64>, u64) = source.query_row(
                "SELECT (SELECT min(sequence) FROM events),durable_sequence FROM status WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            ensure!(
                first == Some(1) || (first.is_none() && durable == 0),
                "continuous initialization lost its source prefix"
            );
            for entry in fs::read_dir(output)? {
                let name = entry?.file_name();
                ensure!(
                    name == "FEED.json" || name == "WORKER.lock",
                    "missing continuous database has unexplained output state"
                );
            }
        } else {
            ensure!(
                fs::symlink_metadata(output.join("feed.sqlite"))?
                    .file_type()
                    .is_file(),
                "continuous custody database is not regular"
            );
        }
    } else {
        for entry in fs::read_dir(output)? {
            ensure!(
                entry?.file_name() == "WORKER.lock",
                "fresh continuous output contains unbound state"
            );
        }
        let (first, durable): (Option<u64>, u64) = source.query_row(
            "SELECT (SELECT min(sequence) FROM events),durable_sequence FROM status WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(
            first == Some(1) || (first.is_none() && durable == 0),
            "continuous fresh output cannot adopt a retired source prefix"
        );
        atomic_json(&header_path, &header)?;
    }
    let binding = ContinuousBinding {
        options,
        producer_generation: generation,
        started_unix_ms: started,
        source: source_identity.clone(),
        feed_header_sha256: digest(&bounded_regular(&header_path, 65536)?),
    };
    let max_event_bytes = meta["config"]["max_event_bytes"]
        .as_u64()
        .context("continuous source lacks event bound")? as usize;
    ensure!(
        max_event_bytes > 0 && max_event_bytes <= 16 * 1024 * 1024,
        "invalid continuous source event bound"
    );
    let live = LiveCanary::for_continuous(binding.clone())?;
    let c = ContextData {
        session: session.into(),
        output: output.into(),
        builder: builder.into(),
        id: source_identity.session_id,
        genesis: source_identity.genesis_hash,
        codec: meta["payload_codec"].as_str().unwrap_or("json-v1").into(),
        meta,
        max_event_bytes,
        live: Some(live),
    };
    let mut db = continuous_database(output)?;
    resume_continuous_releases(&c, &mut db)?;
    // Restart trusts neither saved byte totals nor old watch descriptors.
    let existing = {
        let mut q=db.prepare("SELECT slot,bank,artifact,marker_sha FROM banks WHERE artifact IS NOT NULL AND state IN ('published','rooted','invalidated','gapped')")?;
        q.query_map([], |r| {
            Ok((
                r.get::<_, u64>(0)?,
                r.get::<_, u64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?
    };
    for (slot, bank, artifact, sha) in existing {
        if committed_recovery_needed(Path::new(&artifact))? {
            recover_committed_payload(&c, &db, slot, bank)?;
        } else {
            verify_compact_custody(Path::new(&artifact), &sha)?;
        }
        c.live
            .as_ref()
            .unwrap()
            .seal_compact(output, Path::new(&artifact), slot, bank, &sha)?;
    }
    let mut published_ack = 0u64;
    loop {
        process_continuous_release(&c, &mut db)?;
        let failure: Value =
            serde_json::from_slice(&bounded_regular(&session.join("FAILURE.json"), 65536)?)?;
        ensure!(
            failure.get("state").is_none(),
            "continuous source failed: {failure}"
        );
        ensure!(
            !session.join("RETIREMENT-FAILED.json").try_exists()?,
            "continuous source retirement failed"
        );
        let (state, through): (String, u64) = source.query_row(
            "SELECT state,durable_sequence FROM status WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(state != "FAILED", "continuous source failed");
        if state == "CAPTURING" {
            ensure!(
                crate::journal::capture_is_live(session)?,
                "continuous source writer ended without a clean close"
            );
        }
        let before: (u64, u64) = db.query_row(
            "SELECT source_sequence,event_sequence FROM feed_state WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(
            before.0 <= through,
            "continuous source durable position regressed"
        );
        let pressure = match continuous_step(&source, &mut db, &c, through) {
            Ok(pressure) => pressure,
            Err(error) if error.is::<RetentionPressure>() => Some(error.to_string()),
            Err(error) => return Err(error),
        };
        let custody: u64 = db.query_row(
            "SELECT custody_sequence FROM continuous_state WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        if custody > published_ack {
            publish_source_custody(session, output, &db, &binding)?;
            published_ack = custody;
        }
        process_continuous_release(&c, &mut db)?;
        let after: (u64, u64) = db.query_row(
            "SELECT source_sequence,event_sequence FROM feed_state WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let retained:(u64,u64,u64,u64,u64)=db.query_row("SELECT (SELECT count(*) FROM banks),(SELECT count(*) FROM feed_events),(SELECT count(*) FROM input_custody),(SELECT count(*) FROM banks WHERE state='waiting'),(SELECT count(*) FROM banks WHERE state='gapped')",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
        let (release_id, floor): (u64, u64) = db.query_row(
            "SELECT last_release_id,released_event_sequence FROM continuous_state WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let last_slot: Option<u64> = db.query_row(
            "SELECT max(slot) FROM banks WHERE artifact IS NOT NULL AND state!='retiring'",
            [],
            |r| r.get(0),
        )?;
        let dirty: u64 =
            db.query_row("SELECT count(*) FROM banks WHERE dirty=1", [], |r| r.get(0))?;
        let drained = state == "CLOSED" && after.0 >= through && dirty == 0;
        let status = json!({"schema":"hivezilla-continuous-producer-status-v1","state":if pressure.is_some(){"BACKPRESSURED"}else if drained{"DRAINED"}else{"RUNNING"},
            "profile":PROFILE,"producer_role":CONTINUOUS_ROLE,"producer_generation":binding.producer_generation,"source_sequence":after.0,
            "input_custody_sequence":custody,"event_sequence":after.1,"retained_event_floor":floor,"last_release_id":release_id,
            "retained_banks":retained.0,"retained_events":retained.1,"pending_input_events":retained.2,"waiting_banks":retained.3,"gapped_banks":retained.4,
            "last_compact_slot":last_slot,"source_state":state,"backpressure":pressure,"continuous_retention_implemented":true,
            "full_bank_coverage_asserted":false,"source_preserved":true,"archive_work_enabled":false,"canonical":false,"publication_ready":false,"updated_unix_ms":now_ms()?});
        atomic_json(&output.join("STATUS.json"), &status)?;
        if drained {
            return Ok(());
        }
        if before == after || pressure.is_some() {
            thread::sleep(Duration::from_millis(if pressure.is_some() {
                100
            } else {
                20
            }));
        }
    }
}

fn continuous_step(
    source: &Connection,
    db: &mut Connection,
    c: &ContextData,
    through: u64,
) -> Result<Option<String>> {
    c.live
        .as_ref()
        .context("continuous step lacks guard")?
        .monitor(&c.output)?;
    let pressure = match discover_for_role(source, db, through, c.live.as_ref()) {
        Ok(()) => None,
        Err(error) if error.is::<RetentionPressure>() => Some(error.to_string()),
        Err(error) => return Err(error),
    };
    // A rejected new batch does not prevent progress on the prior FULL commit.
    // It also cannot advance the custody ACK to the rejected source frontier.
    let scanned: u64 = db.query_row(
        "SELECT source_sequence FROM feed_state WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    process_banks(source, db, c, scanned)?;
    expire_incomplete_banks(source, db, c)?;
    Ok(pressure)
}

fn run_mode(
    session: &Path,
    output: &Path,
    builder: &Path,
    start: Option<u64>,
    follow: bool,
    limits: Option<LiveCanaryLimits>,
) -> Result<()> {
    fs::create_dir_all(output)?;
    let output = output.canonicalize()?;
    let session = session.canonicalize()?;
    let _lock = crate::journal::exclusive_lock(&output.join("WORKER.lock"))?;
    let previous = match fs::read(output.join("FEED.json")) {
        Ok(raw) => Some(serde_json::from_slice::<Value>(&raw)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    check_role(previous.as_ref(), limits)?;
    if limits.is_some() {
        ensure!(
            !output.join("LIVE-CANARY-STOP.json").try_exists()?,
            "live canary already stopped; use a fresh output"
        );
        if previous.is_none() {
            for entry in fs::read_dir(&output)? {
                ensure!(
                    entry?.file_name() == "WORKER.lock",
                    "fresh live output contains unbound state"
                );
            }
        } else {
            ensure!(
                output.join("feed.sqlite").is_file(),
                "bound live database is missing"
            );
        }
    }
    let result = run_inner(&session, &output, builder, start, follow, limits);
    if let Err(error) = &result {
        if limits.is_some() {
            let _ = live_failure(&output, error);
            return result;
        }
        let _ = atomic_json(
            &output.join("STATUS.json"),
            &json!({"state":"FAILED","profile":PROFILE,"error":format!("{error:#}"),"source_preserved":true}),
        );
    }
    result
}

fn check_role(previous: Option<&Value>, limits: Option<LiveCanaryLimits>) -> Result<()> {
    if let Some(previous) = previous {
        if let Some(limits) = limits {
            ensure!(
                previous["producer_role"] == LIVE_ROLE,
                "cannot adopt archive/default output as live"
            );
            let binding: LiveBinding = serde_json::from_value(previous["live_canary"].clone())?;
            ensure!(binding.limits == limits, "live canary limits changed");
        } else {
            ensure!(
                previous.get("producer_role").is_none(),
                "cannot adopt live output as default/archive mode"
            );
        }
    }
    Ok(())
}

fn live_failure(output: &Path, error: &anyhow::Error) -> Result<()> {
    let db = open_reader(&output.join("feed.sqlite")).ok();
    let position = db.as_ref().and_then(|db| {
        db.query_row(
            "SELECT source_sequence,event_sequence FROM feed_state WHERE id=1",
            [],
            |r| Ok((r.get::<_, u64>(0)?, r.get::<_, u64>(1)?)),
        )
        .ok()
    });
    let waiting = db.as_ref().and_then(|db| {
        db.query_row(
            "SELECT count(*) FROM banks WHERE state='waiting'",
            [],
            |r| r.get::<_, u64>(0),
        )
        .ok()
    });
    let pending = db.as_ref().and_then(|db| db.query_row(
        "SELECT count(*),min(first_sequence),sum(CASE WHEN dirty=1 THEN 1 ELSE 0 END) FROM banks WHERE dirty=1 OR state='waiting'", [],
        |r| Ok((r.get::<_,u64>(0)?,r.get::<_,Option<u64>>(1)?,r.get::<_,Option<u64>>(2)?))).ok());
    let pending_banks = db.as_ref().map(|db| -> Result<Value> {
        let mut query = db.prepare("SELECT slot,bank,state,first_sequence,last_sequence,dirty FROM banks WHERE dirty=1 OR state='waiting' ORDER BY first_sequence,slot,bank LIMIT 32")?;
        let rows = query.query_map([], |r| Ok(json!({"slot":r.get::<_,u64>(0)?,"bank_id":r.get::<_,u64>(1)?,
            "state":r.get::<_,String>(2)?,"first_sequence":r.get::<_,u64>(3)?,"last_sequence":r.get::<_,u64>(4)?,"dirty":r.get::<_,u64>(5)?})))?
            .collect::<std::result::Result<Vec<_>,_>>()?;
        Ok(json!(rows))
    }).and_then(|value|value.ok());
    let stop = json!({"schema":"hivezilla-live-canary-stop-v1","state":"FAILED",
        "profile":PROFILE,"producer_role":LIVE_ROLE,"error":format!("{error:#}"),
        "discovered_through_source_sequence":position.map(|p|p.0),"event_sequence":position.map(|p|p.1),
        "waiting_banks":waiting,"producer_stopped":true,"source_preserved":true,
        "pending_banks":pending_banks,"pending_banks_list_limit":32,
        "pending_bank_count":pending.map(|p|p.0),"minimum_pending_first_sequence":pending.and_then(|p|p.1),
        "dirty_banks":pending.and_then(|p|p.2),"unpublished_banks":waiting,
        "discovery_position_is_emitted_coverage":false,"source_capture_stop_requested":false,
        "source_capture_state_asserted":false,"retirement_supported":false,
        "continuous_retention_implemented":false,"full_bank_coverage_asserted":false,
        "canonical":false,"publication_ready":false,"updated_unix_ms":now_ms()?});
    if !output.join("LIVE-CANARY-STOP.json").try_exists()? {
        atomic_json(&output.join("LIVE-CANARY-STOP.json"), &stop)?;
    }
    atomic_json(&output.join("STATUS.json"), &stop)
}

fn run_inner(
    session: &Path,
    output: &Path,
    builder: &Path,
    start: Option<u64>,
    follow: bool,
    limits: Option<LiveCanaryLimits>,
) -> Result<()> {
    let meta: Value = serde_json::from_slice(&fs::read(session.join("SESSION.json"))?)?;
    ensure!(
        meta["schema"] == SCHEMA && meta["agave_revision"] == REVISION,
        "unsupported source journal"
    );
    let id = meta["session_id"]
        .as_str()
        .context("missing session")?
        .to_owned();
    let genesis = meta["config"]["genesis_hash"]
        .as_str()
        .context("missing genesis")?
        .to_owned();
    ensure!(
        genesis == "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
        "processed worker currently supports mainnet epoch geometry only"
    );
    let codec = meta["payload_codec"]
        .as_str()
        .unwrap_or("json-v1")
        .to_owned();
    let max_event_bytes = meta["config"]["max_event_bytes"]
        .as_u64()
        .context("missing event bound")? as usize;
    ensure!(max_event_bytes <= 16 * 1024 * 1024, "invalid event bound");
    if limits.is_some() {
        ensure!(
            meta["bank_observations_v2"] == true,
            "live source requires native Bank observations v2"
        );
        let bound = meta["config"]["max_journal_bytes"]
            .as_u64()
            .context("missing source journal byte bound")?;
        ensure!(
            (1024 * 1024..=64 * 1024u64.pow(3)).contains(&bound),
            "live source journal must be bounded at 64 GiB or less"
        );
    }
    let source = open_reader(&session.join("events.sqlite"))?;
    if !output.join("FEED.json").exists() && start.is_none() {
        let durable: u64 =
            source.query_row("SELECT durable_sequence FROM status WHERE id=1", [], |r| {
                r.get(0)
            })?;
        let first: Option<u64> =
            source.query_row("SELECT min(sequence) FROM events", [], |r| r.get(0))?;
        ensure!(
            first == Some(1) || (first.is_none() && durable == 0),
            "source prefix was retired; specify --start-sequence or use a fresh capture session"
        );
    }
    let mut header = json!({"schema":"hivezilla-processed-feed-v1","profile":PROFILE,"session_id":id,"genesis_hash":genesis,
        "node_identity":meta["config"]["node_identity"],"agave_revision":REVISION,"start_source_sequence":start.unwrap_or(0),
        "processed_custody":meta["processed_custody"]==true,"canonical":false,"publication_ready":false});
    let header_path = output.join("FEED.json");
    let previous: Option<Value> = if header_path.try_exists()? {
        Some(serde_json::from_slice(&fs::read(&header_path)?)?)
    } else {
        None
    };
    check_role(previous.as_ref(), limits)?;
    let live = if let Some(limits) = limits {
        let binding = if let Some(previous) = &previous {
            serde_json::from_value::<LiveBinding>(previous["live_canary"].clone())?
        } else {
            LiveBinding {
                limits,
                started_unix_ms: now_ms()?,
                source_start: start.unwrap_or(0),
            }
        };
        ensure!(
            start.is_none_or(|s| s == binding.source_start),
            "source start changed"
        );
        header["producer_role"] = json!(LIVE_ROLE);
        header["live_canary"] = serde_json::to_value(&binding)?;
        header["start_source_sequence"] = json!(binding.source_start);
        header["source_config_sha256"] = json!(digest(&serde_json::to_vec(&meta["config"])?));
        header["source_profile"] = json!("native-bank-observations-v2");
        header["processed_custody"] = json!(false);
        header["archive_work_enabled"] = json!(false);
        header["continuous_retention_implemented"] = json!(false);
        Some(LiveCanary::from_binding(binding)?)
    } else {
        None
    };
    if header_path.exists() {
        let previous = previous.as_ref().unwrap();
        for k in [
            "schema",
            "profile",
            "session_id",
            "genesis_hash",
            "node_identity",
            "agave_revision",
        ] {
            ensure!(previous[k] == header[k], "processed feed identity changed");
        }
        if let Some(start) = start {
            ensure!(
                previous["start_source_sequence"] == start,
                "source start changed"
            );
        }
        if live.is_some() {
            ensure!(*previous == header, "live source or canary binding changed");
        }
    } else {
        atomic_json(&header_path, &header)?;
    }
    let durable: u64 =
        source.query_row("SELECT durable_sequence FROM status WHERE id=1", [], |r| {
            r.get(0)
        })?;
    ensure!(
        start.unwrap_or(0) <= durable,
        "source start exceeds durable position"
    );
    let mut db = database_for_role(output, start.unwrap_or(0), live.is_some())?;
    if let Some(live) = &live {
        let position: u64 = db.query_row(
            "SELECT source_sequence FROM feed_state WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        ensure!(
            position >= live.binding.source_start && position <= live.source_ceiling()?,
            "live source position outside binding"
        );
    }
    let c = ContextData {
        session: session.into(),
        output: output.into(),
        builder: builder.into(),
        meta,
        id,
        genesis,
        codec,
        max_event_bytes,
        live,
    };
    let snapshot: u64 =
        source.query_row("SELECT durable_sequence FROM status WHERE id=1", [], |r| {
            r.get(0)
        })?;
    loop {
        if let Some(live) = &c.live {
            live.monitor(output)?;
        }
        ensure!(
            !session.join("RETIREMENT-FAILED.json").exists(),
            "source retirement failed"
        );
        let failure: Value = serde_json::from_slice(&fs::read(session.join("FAILURE.json"))?)?;
        ensure!(failure.get("state").is_none(), "capture failed: {failure}");
        let (state, through): (String, u64) = source.query_row(
            "SELECT state,durable_sequence FROM status WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(state != "FAILED", "capture failed");
        ensure!(
            state != "CAPTURING"
                || crate::journal::exclusive_lock(&session.join("LIVE.lock")).is_err(),
            "capture ended without a clean close"
        );
        let ceiling = if follow { through } else { snapshot };
        discover_for_role(&source, &mut db, ceiling, c.live.as_ref())?;
        if let Some(live) = &c.live {
            live.monitor(output)?;
        }
        let scanned: u64 = db.query_row(
            "SELECT source_sequence FROM feed_state WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        process_banks(&source, &mut db, &c, scanned)?;
        let (source_sequence, event_sequence): (u64, u64) = db.query_row(
            "SELECT source_sequence,event_sequence FROM feed_state WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let last_compact_slot: Option<u64> = db.query_row(
            "SELECT max(slot) FROM banks WHERE state IN ('published','rooted')",
            [],
            |r| r.get(0),
        )?;
        let waiting: u64 = db.query_row(
            "SELECT count(*) FROM banks WHERE state='waiting'",
            [],
            |r| r.get(0),
        )?;
        if let Some(live) = &c.live {
            live.monitor(output)?;
            ensure!(
                source_sequence < live.source_ceiling()?,
                "live_canary_source_event_limit"
            );
            ensure!(
                event_sequence < live.binding.limits.max_events,
                "live_canary_feed_event_limit"
            );
        }
        let drained = ((!follow && source_sequence >= ceiling)
            || (state == "CLOSED" && source_sequence >= through))
            && db.query_row("SELECT count(*) FROM banks WHERE dirty=1", [], |r| {
                r.get::<_, u64>(0)
            })? == 0;
        if c.live.is_some() && drained {
            ensure!(
                waiting == 0,
                "live_canary_incomplete_banks_at_source_boundary"
            );
        }
        let mut status = json!({"state":if state=="CLOSED"{"DRAINED"}else{"RUNNING"},"profile":PROFILE,
            "source_sequence":source_sequence,"event_sequence":event_sequence,"last_compact_slot":last_compact_slot,"retirement_supported":c.meta["processed_custody"]==true,
            "updated_unix_ms":now_ms()?,"canonical":false,"publication_ready":false});
        if let Some(live) = &c.live {
            status["producer_role"] = json!(LIVE_ROLE);
            status["state"] = json!(if drained { "DRAINED" } else { "RUNNING" });
            status["live_canary"] = serde_json::to_value(&live.binding)?;
            status["waiting_banks"] = json!(waiting);
            status["retirement_supported"] = json!(false);
            status["continuous_retention_implemented"] = json!(false);
            status["full_bank_coverage_asserted"] = json!(false);
        }
        atomic_json(&output.join("STATUS.json"), &status)?;
        let dirty: u64 =
            db.query_row("SELECT count(*) FROM banks WHERE dirty=1", [], |r| r.get(0))?;
        if ((!follow && source_sequence >= ceiling)
            || (state == "CLOSED" && source_sequence >= through))
            && dirty == 0
        {
            return Ok(());
        }
        if source_sequence >= through && dirty == 0 {
            thread::sleep(Duration::from_millis(20));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn continuous_options(root: &Path) -> ContinuousLiveOptions {
        ContinuousLiveOptions {
            retained_banks: 1,
            max_retained_banks: 32,
            retained_events: 10000,
            max_output_bytes: 64 * 1024 * 1024,
            min_retention_ms: 0,
            release_checkpoint: root.join("v2/PROCESSED-RELEASE.json"),
            required_consumer: "sidecar-primary".into(),
        }
    }
    fn continuous_fixture(root: &Path) -> (Connection, ContextData, Connection) {
        let (session, source) = live_source(root);
        let output = root.join("continuous");
        fs::create_dir(&output).unwrap();
        let source_id = blockzilla_bank_stream_v2::SourceIdentity {
            session_id: "continuous-test".into(),
            genesis_hash: "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d".into(),
            node_identity: "J7qpvCEWhdBgPdYRV3s3btWPrRVXa2qnAzgvxWTvtbrQ".into(),
            agave_revision: REVISION.into(),
        };
        let binding = ContinuousBinding {
            options: continuous_options(root),
            producer_generation: "a".repeat(64),
            started_unix_ms: now_ms().unwrap() - 7_200_000,
            source: source_id.clone(),
            feed_header_sha256: "b".repeat(64),
        };
        let c = ContextData {
            session,
            output: output.clone(),
            builder: PathBuf::from("/missing"),
            meta: json!({"processed_custody":false,"config":{"node_identity":source_id.node_identity}}),
            id: source_id.session_id,
            genesis: source_id.genesis_hash,
            codec: "json-v1".into(),
            max_event_bytes: 16 * 1024 * 1024,
            live: Some(LiveCanary::for_continuous(binding).unwrap()),
        };
        (source, c, continuous_database(&output).unwrap())
    }
    fn continuous_checkpoint(
        c: &ContextData,
        id: u64,
        through: u64,
        banks: Vec<ProcessedReleasedBank>,
    ) -> ProcessedReleaseCheckpoint {
        let b = c.live.as_ref().unwrap().continuous.as_deref().unwrap();
        ProcessedReleaseCheckpoint {
            schema: PROCESSED_RELEASE_SCHEMA.into(),
            source: b.source.clone(),
            producer_generation: b.producer_generation.clone(),
            consumer_id: b.options.required_consumer.clone(),
            release_id: id,
            processed_through_sequence: through,
            acknowledged_cursor: blockzilla_bank_stream_v2::cursor(&c.id, through, &"c".repeat(64)),
            replay_floor_cursor: blockzilla_bank_stream_v2::cursor(&c.id, through, &"d".repeat(64)),
            acknowledged_gap_sequence: through,
            released_banks: banks,
            released_slot_controls: Vec::new(),
        }
    }
    fn gap_release_fixture(
        db: &Connection,
        c: &ContextData,
        slot: u64,
        bank: u64,
        sequence: u64,
    ) -> ProcessedReleasedBank {
        let event = crate::event::Event::Status {
            slot,
            bank_id: Some(bank),
            parent: Some(slot - 1),
            status: "processed".into(),
            dead_error: None,
        };
        let bytes = serde_json::to_vec(&event).unwrap();
        let sha = digest(&bytes);
        db_bank(db, slot, bank, sequence, "status").unwrap();
        db.execute(
            "UPDATE banks SET state='gapped',dirty=0 WHERE slot=?1 AND bank=?2",
            params![slot, bank],
        )
        .unwrap();
        db.execute(
            "INSERT INTO bank_activity VALUES(?1,?2,0,0,0)",
            params![slot, bank],
        )
        .unwrap();
        db.execute(
            "INSERT INTO input_custody VALUES(?1,?2,?3,'status',?4,?5)",
            params![sequence, slot, bank, sha, bytes],
        )
        .unwrap();
        let record = RawEvidence {
            sequence,
            sha256: sha,
            event: serde_json::value::RawValue::from_string(serde_json::to_string(&event).unwrap())
                .unwrap(),
        };
        let evidence_sha = digest(&serde_json::to_vec(&vec![record]).unwrap());
        let n = append_event(
            db,
            "gap",
            sequence,
            &json!({"slot":slot,"bank_id":bank}),
            &evidence_sha,
            "",
            Some("fixture incomplete prefix"),
        )
        .unwrap();
        db.execute(
            "INSERT INTO bank_gaps VALUES(?1,?2,?3,?4,'{}')",
            params![slot, bank, n, evidence_sha],
        )
        .unwrap();
        assert_eq!(c.codec, "json-v1");
        ProcessedReleasedBank {
            slot,
            bank_id: bank,
            last_processed_event: n,
            artifact: None,
            marker_sha256: None,
            gap_sequence: Some(n),
            evidence_sha256: Some(evidence_sha),
        }
    }

    #[test]
    fn continuous_counters_have_no_lifetime_bank_event_or_time_ceiling() {
        let t = tempfile::tempdir().unwrap();
        let (_source, c, db) = continuous_fixture(t.path());
        let live = c.live.as_ref().unwrap();
        assert_eq!(live.source_ceiling().unwrap(), u64::MAX);
        live.check_time().unwrap();
        db.execute(
            "UPDATE feed_state SET event_sequence=10000001,source_sequence=10000002",
            [],
        )
        .unwrap();
        live.before_event(&c.output, &db).unwrap();
        let mut options = continuous_options(t.path());
        options.max_retained_banks = 1;
        assert!(options.validate().is_err());
        options.max_retained_banks = 4097;
        assert!(options.validate().is_err());
    }
    #[test]
    fn continuous_source_custody_and_ack_advance_only_after_full_discovery_commit() {
        let t = tempfile::tempdir().unwrap();
        let (mut source, mut c, mut db) = continuous_fixture(t.path());
        for n in 1..=3 {
            insert_source(
                &source,
                n,
                crate::event::Event::Status {
                    slot: 10 + n,
                    bank_id: Some(n),
                    parent: Some(10),
                    status: "processed".into(),
                    dead_error: None,
                },
            );
        }
        discover_for_role(&source, &mut db, 1, c.live.as_ref()).unwrap();
        let mut binding = c
            .live
            .as_ref()
            .unwrap()
            .continuous
            .as_deref()
            .unwrap()
            .clone();
        binding.options.max_retained_banks = 2;
        c.live = Some(LiveCanary::for_continuous(binding.clone()).unwrap());
        assert!(
            discover_for_role(&source, &mut db, 3, c.live.as_ref())
                .unwrap_err()
                .is::<RetentionPressure>()
        );
        assert_eq!(
            db.query_row("SELECT custody_sequence FROM continuous_state", [], |r| r
                .get::<_, u64>(
                0
            ))
            .unwrap(),
            1
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM input_custody", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            1
        );
        publish_source_custody(&c.session, &c.output, &db, &binding).unwrap();
        let ticket: crate::retention::SourceAckTicket =
            serde_json::from_slice(&fs::read(c.session.join("SOURCE-ACK.json")).unwrap()).unwrap();
        assert_eq!(ticket.through_sequence, 1);
        assert_eq!(ticket.producer_generation, binding.producer_generation);
        source.execute_batch("PRAGMA synchronous=FULL; ALTER TABLE status ADD COLUMN retired_events INTEGER NOT NULL DEFAULT 0;").unwrap();
        crate::source_retention::initialize(&source).unwrap();
        assert!(
            crate::source_retention::process_one(&c.session, &mut source, &binding.source).unwrap()
        );
        assert_eq!(
            source
                .query_row("SELECT count(*) FROM events WHERE sequence=1", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            continuous_records(&db, &source, &c, 11, 1, 1)
                .unwrap()
                .len(),
            1
        );
        drop(db);
        let db = continuous_database(&c.output).unwrap();
        assert_eq!(
            db.query_row("SELECT proof_sha256 FROM source_acks", [], |r| r
                .get::<_, String>(0))
                .unwrap(),
            ticket.proof_sha256
        );
    }
    #[test]
    fn continuous_release_requires_source_generation_gap_ack_and_exact_input() {
        let t = tempfile::tempdir().unwrap();
        let (_source, c, mut db) = continuous_fixture(t.path());
        let bank = gap_release_fixture(&db, &c, 10, 7, 1);
        let checkpoint = continuous_checkpoint(&c, 1, 1, vec![bank]);
        for fault in 0..5 {
            let mut bad = checkpoint.clone();
            match fault {
                0 => bad.producer_generation = "f".repeat(64),
                1 => bad.source.session_id = "other".into(),
                2 => bad.acknowledged_gap_sequence = 0,
                3 => bad.released_banks[0].last_processed_event = 2,
                _ => bad.acknowledged_cursor = "continuous-test:p1:bad".into(),
            };
            assert!(apply_continuous_release(&c, &mut db, bad).is_err());
            assert_eq!(
                db.query_row("SELECT count(*) FROM banks", [], |r| r.get::<_, u64>(0))
                    .unwrap(),
                1
            );
        }
        db.execute("UPDATE input_custody SET payload=?1", [b"changed".to_vec()])
            .unwrap();
        assert!(apply_continuous_release(&c, &mut db, checkpoint).is_err());
        assert_eq!(
            db.query_row("SELECT count(*) FROM release_jobs", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            0
        );
    }
    #[test]
    fn continuous_authorized_seal_removal_keeps_bytes_charged_until_unlink() {
        let t = tempfile::tempdir().unwrap();
        let (_source, c, _db) = continuous_fixture(t.path());
        let live = c.live.as_ref().unwrap();
        let (a, sha) = sealed_fixture(&c.output, 10, 7);
        let (b, shab) = sealed_fixture(&c.output, 11, 8);
        live.seal_compact(&c.output, &a, 10, 7, &sha).unwrap();
        live.seal_compact(&c.output, &b, 11, 8, &shab).unwrap();
        live.release_seal(&a).unwrap();
        let inventory = live.inventory.lock().unwrap();
        assert_eq!(inventory.sealed.len(), 1);
        assert_eq!(inventory.watch.as_ref().unwrap().paths.len(), 3);
        assert_eq!(
            live_output_bytes_once_sealed_with(&c.output, &inventory.sealed, |_| {}).unwrap(),
            live_output_bytes_once(&c.output).unwrap()
        );
        drop(inventory);
        fs::remove_dir_all(a).unwrap();
        live.check(&c.output).unwrap();
        fs::write(b.join("unexpected"), b"changed").unwrap();
        assert!(live.check(&c.output).is_err());
    }
    #[test]
    fn continuous_release_restart_repairs_missing_receipt_and_keeps_database_identity() {
        use std::os::unix::fs::MetadataExt;
        let t = tempfile::tempdir().unwrap();
        let (_source, c, mut db) = continuous_fixture(t.path());
        let bank = gap_release_fixture(&db, &c, 10, 7, 1);
        let checkpoint = continuous_checkpoint(&c, 1, 1, vec![bank]);
        let inode = fs::metadata(c.output.join("feed.sqlite")).unwrap().ino();
        let sha = processed_release_digest(&checkpoint).unwrap();
        db.execute(
            "INSERT INTO release_jobs VALUES(1,?1,?2,'DELETING',0)",
            params![sha, serde_json::to_string(&checkpoint).unwrap()],
        )
        .unwrap();
        db.execute("UPDATE banks SET state='retiring'", []).unwrap();
        drop(db);
        let mut db = continuous_database(&c.output).unwrap();
        resume_continuous_releases(&c, &mut db).unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM banks", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            0
        );
        let receipt = c.output.join("retention/release-1.json");
        fs::remove_file(&receipt).unwrap();
        apply_continuous_release(&c, &mut db, checkpoint.clone()).unwrap();
        assert!(receipt.is_file());
        assert!(!apply_continuous_release(&c, &mut db, checkpoint).unwrap());
        assert_eq!(
            fs::metadata(c.output.join("feed.sqlite")).unwrap().ino(),
            inode
        );
    }
    #[test]
    fn continuous_rolls_more_than_4096_banks_with_bounded_rows_receipts_and_restart() {
        let t = tempfile::tempdir().unwrap();
        let (_source, c, mut db) = continuous_fixture(t.path());
        let mut n = 0;
        for id in 1..=130 {
            let tx = db.transaction().unwrap();
            let mut released = Vec::new();
            for _ in 0..32 {
                n += 1;
                released.push(gap_release_fixture(&tx, &c, 10 + n, n, n));
            }
            tx.commit().unwrap();
            c.live
                .as_ref()
                .unwrap()
                .before_event(&c.output, &db)
                .unwrap();
            apply_continuous_release(&c, &mut db, continuous_checkpoint(&c, id, n, released))
                .unwrap();
            assert_eq!(
                db.query_row("SELECT count(*) FROM banks", [], |r| r.get::<_, u64>(0))
                    .unwrap(),
                0
            );
            assert!(
                db.query_row("SELECT count(*) FROM retired_banks", [], |r| r
                    .get::<_, u64>(0))
                    .unwrap()
                    <= 64
            );
            assert!(fs::read_dir(c.output.join("retention")).unwrap().count() <= 2);
            if id == 65 {
                drop(db);
                db = continuous_database(&c.output).unwrap();
            }
        }
        assert_eq!(n, 4160);
        assert_eq!(
            db.query_row("SELECT event_sequence FROM feed_state", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            4160
        );
        for table in [
            "banks",
            "input_custody",
            "feed_events",
            "bank_gaps",
            "bank_activity",
        ] {
            assert_eq!(
                db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                    .get::<_, u64>(0))
                    .unwrap(),
                0
            );
        }
        assert_eq!(
            db.query_row("SELECT last_release_id FROM continuous_state", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            130
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM release_jobs", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            2
        );
    }
    #[test]
    fn continuous_incomplete_prefix_becomes_explicit_gap_and_keeps_input_until_gap_ack() {
        use crate::event::{BANK_V2, Event};
        let t = tempfile::tempdir().unwrap();
        let (source, c, mut db) = continuous_fixture(t.path());
        insert_source(
            &source,
            1,
            Event::Status {
                slot: 10,
                bank_id: Some(7),
                parent: Some(9),
                status: "processed".into(),
                dead_error: None,
            },
        );
        insert_source(
            &source,
            2,
            Event::BankStatusV2 {
                schema: BANK_V2.into(),
                slot: 20,
                bank_id: Some(8),
                parent: Some(19),
                parent_blockhash: None,
                status: "rooted".into(),
                dead_error: None,
                observed_at_unix_ms: now_ms().unwrap(),
            },
        );
        discover_for_role(&source, &mut db, 2, c.live.as_ref()).unwrap();
        db.execute("UPDATE banks SET dirty=0", []).unwrap();
        source.execute("DELETE FROM events", []).unwrap();
        assert_eq!(expire_incomplete_banks(&source, &mut db, &c).unwrap(), 1);
        let gap: String = db
            .query_row("SELECT gap_json FROM bank_gaps", [], |r| r.get(0))
            .unwrap();
        let gap: Value = serde_json::from_str(&gap).unwrap();
        assert_eq!(gap["complete_bank"], false);
        assert_eq!(gap["canonical_status"], "UNKNOWN");
        assert!(gap["bank_identity"].is_null());
        assert_eq!(
            db.query_row("SELECT count(*) FROM input_custody", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            2
        );
        let bank = ProcessedReleasedBank {
            slot: 10,
            bank_id: 7,
            last_processed_event: 1,
            artifact: None,
            marker_sha256: None,
            gap_sequence: Some(1),
            evidence_sha256: Some(gap["evidence_sha256"].as_str().unwrap().into()),
        };
        let mut checkpoint = continuous_checkpoint(&c, 1, 1, vec![bank]);
        checkpoint.acknowledged_gap_sequence = 0;
        assert!(apply_continuous_release(&c, &mut db, checkpoint.clone()).is_err());
        checkpoint.acknowledged_gap_sequence = 1;
        apply_continuous_release(&c, &mut db, checkpoint).unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM input_custody WHERE bank=7", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM input_custody WHERE bank=8", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            1
        );
    }
    #[test]
    fn continuous_role_and_policy_are_stable_and_old_capture_mode_is_rejected() {
        let t = tempfile::tempdir().unwrap();
        let (session, _source) = live_source(t.path());
        let output = t.path().join("rolling");
        let options = continuous_options(t.path());
        assert!(run_continuous(&session, &output, Path::new("/missing"), options.clone()).is_err());
        assert!(!output.join("feed.sqlite").exists());
        fs::remove_dir_all(&output).unwrap();
        let path = session.join("SESSION.json");
        let mut meta: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        meta["retirement"] = json!("local-consumed-prefix-v1");
        meta["processed_custody"] = json!(false);
        meta["config"]["live_source_ack"] = json!(true);
        atomic_json(&path, &meta).unwrap();
        run_continuous(&session, &output, Path::new("/missing"), options.clone()).unwrap();
        let header = fs::read(output.join("FEED.json")).unwrap();
        run_continuous(&session, &output, Path::new("/missing"), options.clone()).unwrap();
        assert_eq!(header, fs::read(output.join("FEED.json")).unwrap());
        let mut changed = options;
        changed.retained_banks = 2;
        assert!(run_continuous(&session, &output, Path::new("/missing"), changed).is_err());
        assert!(
            run_live(
                &session,
                &output,
                Path::new("/missing"),
                None,
                false,
                test_limits()
            )
            .is_err()
        );
        assert!(run(&session, &output, Path::new("/missing"), None, false).is_err());
    }
    #[test]
    fn continuous_recovers_only_the_exact_post_header_pre_database_crash_layout() {
        let t = tempfile::tempdir().unwrap();
        let (session, _source) = live_source(t.path());
        let meta_path = session.join("SESSION.json");
        let mut meta: Value = serde_json::from_slice(&fs::read(&meta_path).unwrap()).unwrap();
        meta["retirement"] = json!("local-consumed-prefix-v1");
        meta["processed_custody"] = json!(false);
        meta["config"]["live_source_ack"] = json!(true);
        atomic_json(&meta_path, &meta).unwrap();
        let output = t.path().join("continuous");
        let options = continuous_options(t.path());
        run_continuous(&session, &output, Path::new("/missing"), options.clone()).unwrap();
        let header = fs::read(output.join("FEED.json")).unwrap();
        fs::remove_file(output.join("feed.sqlite")).unwrap();
        fs::remove_file(output.join("STATUS.json")).unwrap();
        run_continuous(&session, &output, Path::new("/missing"), options.clone()).unwrap();
        assert_eq!(header, fs::read(output.join("FEED.json")).unwrap());
        fs::remove_file(output.join("feed.sqlite")).unwrap();
        fs::remove_file(output.join("STATUS.json")).unwrap();
        fs::write(session.join("SOURCE-ACK.json"), b"unexplained existing ACK").unwrap();
        assert!(run_continuous(&session, &output, Path::new("/missing"), options).is_err());
        assert!(!output.join("feed.sqlite").exists());
    }

    #[test]
    fn continuous_slot_only_control_requires_separate_gap_ack_without_bank_identity() {
        use crate::event::{BANK_V2, Event};
        let t = tempfile::tempdir().unwrap();
        let (source, c, mut db) = continuous_fixture(t.path());
        insert_source(
            &source,
            1,
            Event::BankStatusV2 {
                schema: BANK_V2.into(),
                slot: 10,
                bank_id: None,
                parent: None,
                parent_blockhash: None,
                status: "dead".into(),
                dead_error: Some("uncaptured fork".into()),
                observed_at_unix_ms: now_ms().unwrap(),
            },
        );
        insert_source(
            &source,
            2,
            Event::BankStatusV2 {
                schema: BANK_V2.into(),
                slot: 20,
                bank_id: Some(8),
                parent: Some(19),
                parent_blockhash: None,
                status: "rooted".into(),
                dead_error: None,
                observed_at_unix_ms: now_ms().unwrap(),
            },
        );
        discover_for_role(&source, &mut db, 2, c.live.as_ref()).unwrap();
        db.execute("UPDATE banks SET dirty=0", []).unwrap();
        assert_eq!(expire_incomplete_banks(&source, &mut db, &c).unwrap(), 1);
        let raw: String = db
            .query_row("SELECT gap_json FROM slot_gaps", [], |r| r.get(0))
            .unwrap();
        let gap: Value = serde_json::from_str(&raw).unwrap();
        assert!(gap["bank_id"].is_null());
        assert!(gap["bank_identity"].is_null());
        assert_eq!(gap["schema"], "hivezilla-slot-control-gap-v1");
        assert_eq!(
            db.query_row("SELECT count(*) FROM banks WHERE slot=10", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            0
        );
        let mut checkpoint = continuous_checkpoint(&c, 1, 1, Vec::new());
        checkpoint
            .released_slot_controls
            .push(ProcessedReleasedSlotControl {
                slot: 10,
                last_processed_event: 1,
                gap_sequence: 1,
                evidence_sha256: gap["evidence_sha256"].as_str().unwrap().into(),
            });
        checkpoint.acknowledged_gap_sequence = 0;
        assert!(apply_continuous_release(&c, &mut db, checkpoint.clone()).is_err());
        checkpoint.acknowledged_gap_sequence = 1;
        apply_continuous_release(&c, &mut db, checkpoint).unwrap();
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM input_custody WHERE slot=10",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM input_custody WHERE slot=20",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
            1
        );
        let receipt: Value =
            serde_json::from_slice(&fs::read(c.output.join("retention/release-1.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["released_slot_controls"], 1);
    }
    #[test]
    fn continuous_restart_finishes_only_durable_exact_artifact_release_after_partial_unlink() {
        use std::os::unix::fs::MetadataExt;
        let t = tempfile::tempdir().unwrap();
        let (_source, c, mut db) = continuous_fixture(t.path());
        let mut bank = gap_release_fixture(&db, &c, 10, 7, 1);
        let (path, sha) = sealed_fixture(&c.output, 10, 7);
        db.execute(
            "UPDATE banks SET state='rooted',artifact=?1,marker_sha=?2",
            params![path.to_str().unwrap(), sha],
        )
        .unwrap();
        db.execute("DELETE FROM bank_gaps", []).unwrap();
        bank.gap_sequence = None;
        bank.evidence_sha256 = None;
        bank.artifact = Some(path.to_str().unwrap().into());
        bank.marker_sha256 = Some(sha);
        let checkpoint = continuous_checkpoint(&c, 1, 1, vec![bank]);
        validate_release(
            &db,
            &c,
            c.live.as_ref().unwrap().continuous.as_deref().unwrap(),
            &checkpoint,
        )
        .unwrap();
        let bytes = verify_compact_custody(
            &path,
            checkpoint.released_banks[0]
                .marker_sha256
                .as_deref()
                .unwrap(),
        )
        .unwrap();
        let metadata = fs::metadata(&path).unwrap();
        db.execute(
            "INSERT INTO release_jobs VALUES(1,?1,?2,'DELETING',?3)",
            params![
                processed_release_digest(&checkpoint).unwrap(),
                serde_json::to_string(&checkpoint).unwrap(),
                bytes
            ],
        )
        .unwrap();
        db.execute(
            "INSERT INTO release_targets VALUES(1,10,7,?1,?2,?3,?4)",
            params![
                path.to_str().unwrap(),
                metadata.dev(),
                metadata.ino(),
                bytes
            ],
        )
        .unwrap();
        db.execute("UPDATE banks SET state='retiring'", []).unwrap();
        fs::remove_file(path.join("payload")).unwrap();
        drop(db);
        let mut db = continuous_database(&c.output).unwrap();
        resume_continuous_releases(&c, &mut db).unwrap();
        assert!(!path.exists());
        let receipt: Value =
            serde_json::from_slice(&fs::read(c.output.join("retention/release-1.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["released_bytes"], bytes);
        assert_eq!(
            db.query_row("SELECT count(*) FROM banks", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            0
        );
    }
    #[test]
    fn continuous_prefix_only_checkpoint_releases_events_without_deleting_payload_custody() {
        let t = tempfile::tempdir().unwrap();
        let (_source, c, mut db) = continuous_fixture(t.path());
        let bank = gap_release_fixture(&db, &c, 10, 7, 1);
        apply_continuous_release(&c, &mut db, continuous_checkpoint(&c, 1, 1, Vec::new())).unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM feed_events", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM input_custody", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM banks", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            1
        );
        apply_continuous_release(&c, &mut db, continuous_checkpoint(&c, 2, 1, vec![bank])).unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM banks", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            0
        );
    }
    #[test]
    fn continuous_discovery_backpressure_still_advances_committed_pending_gap_work() {
        use crate::event::{BANK_V2, Event};
        let t = tempfile::tempdir().unwrap();
        let (source, mut c, mut db) = continuous_fixture(t.path());
        insert_source(
            &source,
            1,
            Event::Status {
                slot: 10,
                bank_id: Some(7),
                parent: Some(9),
                status: "processed".into(),
                dead_error: None,
            },
        );
        insert_source(
            &source,
            2,
            Event::BankStatusV2 {
                schema: BANK_V2.into(),
                slot: 20,
                bank_id: Some(8),
                parent: Some(19),
                parent_blockhash: None,
                status: "rooted".into(),
                dead_error: None,
                observed_at_unix_ms: now_ms().unwrap(),
            },
        );
        discover_for_role(&source, &mut db, 2, c.live.as_ref()).unwrap();
        let mut binding = c
            .live
            .as_ref()
            .unwrap()
            .continuous
            .as_deref()
            .unwrap()
            .clone();
        binding.options.max_retained_banks = 2;
        c.live = Some(LiveCanary::for_continuous(binding).unwrap());
        insert_source(
            &source,
            3,
            Event::Status {
                slot: 21,
                bank_id: Some(9),
                parent: Some(20),
                status: "processed".into(),
                dead_error: None,
            },
        );
        assert!(
            continuous_step(&source, &mut db, &c, 3)
                .unwrap()
                .unwrap()
                .contains("retained_bank_capacity")
        );
        assert_eq!(
            db.query_row("SELECT source_sequence FROM feed_state", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            db.query_row("SELECT custody_sequence FROM continuous_state", [], |r| r
                .get::<_, u64>(
                0
            ))
            .unwrap(),
            2
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM bank_gaps WHERE slot=10 AND bank=7",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
            1
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM input_custody WHERE sequence=3",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
            0
        );
    }
    fn sealed_fixture(root: &Path, slot: u64, bank: u64) -> (PathBuf, String) {
        use std::os::unix::fs::PermissionsExt;
        let compact = root.join(format!("live-banks/{slot}-{bank}.compact"));
        fs::create_dir_all(&compact).unwrap();
        fs::write(compact.join("payload"), vec![3u8; 16384]).unwrap();
        let marker = serde_json::to_vec(
            &json!({"state":"COMPLETE", "produced_blocks":[{"slot":slot,"bank_id":bank}],"files":[{"path":"payload","bytes":16384,"sha256":digest(&vec![3u8;16384])}]}),
        )
        .unwrap();
        let sha = digest(&marker);
        fs::write(compact.join("DIRECT-AGAVE-COMPACT.v1.json"), marker).unwrap();
        for e in fs::read_dir(&compact).unwrap() {
            fs::set_permissions(e.unwrap().path(), fs::Permissions::from_mode(0o444)).unwrap();
        }
        (compact, sha)
    }
    #[test]
    fn live_only_sealed_inventory_is_exact_and_skips_retained_file_stats() {
        let t = tempfile::tempdir().unwrap();
        let live = test_live();
        let (compact, sha) = sealed_fixture(t.path(), 10, 1);
        live.seal_compact(t.path(), &compact, 10, 1, &sha).unwrap();
        let inventory = live.inventory.lock().unwrap();
        let mut visits = Vec::new();
        let fast = live_output_bytes_once_sealed_with(t.path(), &inventory.sealed, |p| {
            visits.push(p.to_path_buf())
        })
        .unwrap();
        assert_eq!(fast, live_output_bytes_once(t.path()).unwrap());
        assert!(!visits.iter().any(|p| p.parent() == Some(compact.as_path())));
        drop(inventory);
        fs::read(compact.join("payload")).unwrap();
        live.check(t.path()).unwrap();
    }
    #[test]
    fn live_only_sealed_inventory_mutations_are_permanently_fatal() {
        use std::os::unix::fs::PermissionsExt;
        for change in 0..5 {
            let t = tempfile::tempdir().unwrap();
            let live = test_live();
            let (compact, sha) = sealed_fixture(t.path(), 10, 1);
            live.seal_compact(t.path(), &compact, 10, 1, &sha).unwrap();
            let payload = compact.join("payload");
            match change {
                0 => {
                    fs::set_permissions(&payload, fs::Permissions::from_mode(0o644)).unwrap();
                    fs::write(payload, vec![4u8; 16384]).unwrap();
                }
                1 => {
                    fs::write(compact.join("unexpected"), vec![0; 1024]).unwrap();
                }
                2 => {
                    fs::remove_file(payload).unwrap();
                }
                3 => {
                    fs::rename(&compact, compact.with_extension("moved")).unwrap();
                }
                _ => {
                    fs::remove_dir_all(&compact).unwrap();
                }
            }
            assert!(
                live.check(t.path())
                    .unwrap_err()
                    .to_string()
                    .contains("sealed inventory mutation")
            );
            assert!(
                live.monitor(t.path())
                    .unwrap_err()
                    .to_string()
                    .contains("previously failed")
            );
            assert_eq!(live.inventory.lock().unwrap().sealed.len(), 1);
        }
    }
    #[test]
    fn live_only_sealed_inode_watch_rejects_alias_and_preopened_fd_writes() {
        use std::os::unix::fs::PermissionsExt;
        for alias in [false, true] {
            let t = tempfile::tempdir().unwrap();
            let live = test_live();
            let (compact, sha) = sealed_fixture(t.path(), 10, 1);
            let payload = compact.join("payload");
            fs::set_permissions(&payload, fs::Permissions::from_mode(0o644)).unwrap();
            let mut open = fs::OpenOptions::new().write(true).open(&payload).unwrap();
            fs::set_permissions(&payload, fs::Permissions::from_mode(0o444)).unwrap();
            live.seal_compact(t.path(), &compact, 10, 1, &sha).unwrap();
            if alias {
                fs::hard_link(&payload, t.path().join("alias")).unwrap();
            } else {
                open.write_all(&[7]).unwrap();
            }
            assert!(
                live.check(t.path())
                    .unwrap_err()
                    .to_string()
                    .contains("sealed inventory mutation")
            );
            assert!(live.monitor(t.path()).is_err());
        }
    }
    #[test]
    fn live_only_sealed_watch_allows_preopened_writer_close_without_a_write() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let live = test_live();
        let (compact, sha) = sealed_fixture(t.path(), 10, 1);
        let payload = compact.join("payload");
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o644)).unwrap();
        let open = fs::OpenOptions::new().write(true).open(&payload).unwrap();
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o444)).unwrap();
        live.seal_compact(t.path(), &compact, 10, 1, &sha).unwrap();
        drop(open);
        live.check(t.path()).unwrap();
    }
    #[test]
    fn live_only_sealed_inventory_keeps_unknown_orphan_and_pending_bytes() {
        let t = tempfile::tempdir().unwrap();
        let mut live = test_live();
        let (compact, sha) = sealed_fixture(t.path(), 10, 1);
        live.seal_compact(t.path(), &compact, 10, 1, &sha).unwrap();
        live.binding.limits.max_output_bytes = 1024 * 1024;
        let orphan = t
            .path()
            .join("live-banks/.11-2.compact.direct-agave-stage/subdir");
        fs::create_dir_all(&orphan).unwrap();
        fs::write(orphan.join("partial"), vec![0; 1024 * 1024]).unwrap();
        assert!(
            live.check(t.path())
                .unwrap_err()
                .to_string()
                .contains("live_canary_output_byte_limit")
        );
        assert_eq!(live.inventory.lock().unwrap().sealed.len(), 1);
    }
    #[test]
    fn live_only_seal_rejects_incomplete_writable_linked_and_wrong_bank_trees() {
        use std::os::unix::fs::PermissionsExt;
        for invalid in 0..6 {
            let t = tempfile::tempdir().unwrap();
            let live = test_live();
            let (compact, sha) = sealed_fixture(t.path(), 10, 1);
            match invalid {
                0 => {
                    fs::remove_file(compact.join("DIRECT-AGAVE-COMPACT.v1.json")).unwrap();
                }
                1 => {
                    fs::set_permissions(compact.join("payload"), fs::Permissions::from_mode(0o644))
                        .unwrap();
                }
                2 => {
                    std::os::unix::fs::symlink("/tmp", compact.join("link")).unwrap();
                }
                3 => {
                    fs::hard_link(compact.join("payload"), t.path().join("alias")).unwrap();
                }
                5 => {
                    fs::create_dir(compact.join("nested")).unwrap();
                }
                _ => {}
            }
            let bank = if invalid == 4 { 2 } else { 1 };
            assert!(
                live.seal_compact(t.path(), &compact, 10, bank, &sha)
                    .is_err()
            );
            assert!(live.inventory.lock().unwrap().sealed.is_empty());
        }
    }
    #[test]
    fn live_only_restart_does_not_trust_old_seal_totals_or_reset_binding() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let mut live = test_live();
        live.binding.limits.max_output_bytes = 1024 * 1024;
        let (compact, sha) = sealed_fixture(t.path(), 10, 1);
        live.seal_compact(t.path(), &compact, 10, 1, &sha).unwrap();
        let restarted = LiveCanary::from_binding(live.binding.clone()).unwrap();
        assert_eq!(restarted.binding, live.binding);
        assert!(restarted.inventory.lock().unwrap().sealed.is_empty());
        fs::set_permissions(compact.join("payload"), fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(compact.join("payload"), vec![0; 1024 * 1024]).unwrap();
        assert!(
            restarted
                .check(t.path())
                .unwrap_err()
                .to_string()
                .contains("live_canary_output_byte_limit")
        );
    }
    #[test]
    fn live_only_sealed_large_tree_scan_remains_exact_with_bounded_file_stats() {
        let t = tempfile::tempdir().unwrap();
        let live = test_live();
        for bank in 1..=256 {
            let (compact, sha) = sealed_fixture(t.path(), 10 + bank, bank);
            live.seal_compact(t.path(), &compact, 10 + bank, bank, &sha)
                .unwrap();
        }
        let inventory = live.inventory.lock().unwrap();
        let mut visits = 0usize;
        let fast = live_output_bytes_once_sealed_with(t.path(), &inventory.sealed, |_| visits += 1)
            .unwrap();
        assert_eq!(fast, live_output_bytes_once(t.path()).unwrap());
        assert_eq!(visits, 257); // live-banks plus one identity stat per Bank.
        assert_eq!(inventory.sealed.len(), 256);
    }
    #[test]
    fn live_only_sealed_watch_is_single_nonblocking_cloexec_descriptor() {
        use std::os::fd::AsRawFd;
        let t = tempfile::tempdir().unwrap();
        let live = test_live();
        for bank in 1..=4 {
            let (compact, sha) = sealed_fixture(t.path(), 10 + bank, bank);
            live.seal_compact(t.path(), &compact, 10 + bank, bank, &sha)
                .unwrap();
        }
        let inventory = live.inventory.lock().unwrap();
        let watch = inventory.watch.as_ref().unwrap();
        assert_eq!(watch.paths.len(), 12); // Four directories and two files each.
        let fd = watch.fd.as_raw_fd();
        assert!(unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC != 0);
        assert!(unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK != 0);
        let output = Command::new("/usr/bin/python3").args(["-c", "import os; print([os.readlink('/proc/self/fd/'+n) for n in os.listdir('/proc/self/fd') if os.path.exists('/proc/self/fd/'+n)])"]).output().unwrap();
        assert!(output.status.success());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("anon_inode:inotify"));
    }
    #[test]
    #[ignore = "near-bound isolated metadata benchmark on Foundation"]
    fn live_only_sealed_4096_bank_inventory_benchmark() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let mut live = test_live();
        live.binding.limits.max_output_bytes = 1024 * 1024 * 1024;
        live.binding.limits.max_seconds = 3600;
        for bank in 1..=4096 {
            let (compact, sha) = sealed_fixture(t.path(), 10 + bank, bank);
            for file in 0..12 {
                let path = compact.join(format!("extra-{file}"));
                fs::write(&path, [0u8; 32]).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o444)).unwrap();
            }
            live.seal_compact(t.path(), &compact, 10 + bank, bank, &sha)
                .unwrap();
        }
        let inventory = live.inventory.lock().unwrap();
        let mut fast_visits = 0usize;
        let started = Instant::now();
        let fast =
            live_output_bytes_once_sealed_with(t.path(), &inventory.sealed, |_| fast_visits += 1)
                .unwrap();
        let fast_micros = started.elapsed().as_micros();
        let mut full_visits = 0usize;
        let started = Instant::now();
        let full = live_output_bytes_once_with(t.path(), |_| full_visits += 1).unwrap();
        let full_micros = started.elapsed().as_micros();
        assert_eq!(fast, full);
        assert_eq!(fast_visits, 4097);
        assert_eq!(full_visits, 61441);
        println!(
            "SEALED_BENCH {}",
            json!({"banks":4096,"bytes":fast,"fast_visits":fast_visits,"full_visits":full_visits,"fast_micros":fast_micros,"full_micros":full_micros})
        );
    }

    fn test_limits() -> LiveCanaryLimits {
        LiveCanaryLimits {
            max_banks: 32,
            max_events: 1024,
            max_output_bytes: 64 * 1024 * 1024,
            max_seconds: 60,
        }
    }
    fn test_live() -> LiveCanary {
        LiveCanary::from_binding(LiveBinding {
            limits: test_limits(),
            started_unix_ms: now_ms().unwrap(),
            source_start: 0,
        })
        .unwrap()
    }
    fn assert_no_archive(output: &Path, db: &Connection, session: &Path) {
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='archive_catalog'",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
            0
        );
        assert!(!output.join("custody").exists());
        assert!(!fs::read_dir(output).unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("epoch-")
        }));
        assert_eq!(
            fs::read_dir(session.join("retire-pending"))
                .unwrap()
                .count(),
            0
        );
    }
    fn live_source(root: &Path) -> (PathBuf, Connection) {
        let session = root.join("source");
        fs::create_dir_all(session.join("retire-pending")).unwrap();
        let meta = json!({"schema":SCHEMA,"agave_revision":REVISION,"session_id":"live-test",
            "bank_observations_v2":true,"processed_custody":true,"payload_codec":"json-v1",
            "config":{"genesis_hash":"5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
                "node_identity":"J7qpvCEWhdBgPdYRV3s3btWPrRVXa2qnAzgvxWTvtbrQ",
                "max_event_bytes":16777216,"max_journal_bytes":68719476736u64}});
        atomic_json(&session.join("SESSION.json"), &meta).unwrap();
        atomic_json(&session.join("FAILURE.json"), &json!({})).unwrap();
        let source = Connection::open(session.join("events.sqlite")).unwrap();
        source.execute_batch("CREATE TABLE events(sequence INTEGER PRIMARY KEY,slot INTEGER,bank INTEGER,kind TEXT,sha256 TEXT,payload BLOB);CREATE INDEX bank_events ON events(slot,bank,sequence);CREATE TABLE status(id INTEGER,state TEXT,durable_sequence INTEGER);INSERT INTO status VALUES(1,'CLOSED',0);").unwrap();
        (session, source)
    }
    #[test]
    fn live_only_role_limits_and_first_start_are_bound_across_restart() {
        let t = tempfile::tempdir().unwrap();
        let (session, _source) = live_source(t.path());
        let output = t.path().join("live");
        let builder = t.path().join("must-not-run");
        run_live(&session, &output, &builder, None, false, test_limits()).unwrap();
        let header = fs::read(output.join("FEED.json")).unwrap();
        let value: Value = serde_json::from_slice(&header).unwrap();
        assert_eq!(value["producer_role"], LIVE_ROLE);
        assert_eq!(value["source_profile"], "native-bank-observations-v2");
        assert_eq!(value["processed_custody"], false);
        run_live(&session, &output, &builder, None, false, test_limits()).unwrap();
        assert_eq!(header, fs::read(output.join("FEED.json")).unwrap());
        assert!(run(&session, &output, &builder, None, false).is_err());
        let mut changed = test_limits();
        changed.max_events += 1;
        assert!(run_live(&session, &output, &builder, None, false, changed).is_err());
        assert!(run_live(&session, &output, &builder, Some(1), false, test_limits()).is_err());
        assert_eq!(header, fs::read(output.join("FEED.json")).unwrap());
        assert_no_archive(
            &output,
            &open_reader(&output.join("feed.sqlite")).unwrap(),
            &session,
        );
    }
    #[test]
    fn live_only_does_not_adopt_default_or_unbound_output() {
        let t = tempfile::tempdir().unwrap();
        let (session, _source) = live_source(t.path());
        let builder = t.path().join("must-not-run");
        let old = t.path().join("default");
        run(&session, &old, &builder, None, false).unwrap();
        let header = fs::read(old.join("FEED.json")).unwrap();
        assert!(run_live(&session, &old, &builder, None, false, test_limits()).is_err());
        assert_eq!(header, fs::read(old.join("FEED.json")).unwrap());
        assert_eq!(
            Connection::open(old.join("feed.sqlite"))
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE name='archive_catalog'",
                    [],
                    |r| r.get::<_, u64>(0)
                )
                .unwrap(),
            1
        );
        let unbound = t.path().join("unbound");
        fs::create_dir(&unbound).unwrap();
        fs::write(unbound.join("orphan"), b"retained").unwrap();
        assert!(run_live(&session, &unbound, &builder, None, false, test_limits()).is_err());
        assert!(!unbound.join("FEED.json").exists());
    }
    #[test]
    fn live_only_requires_native_observations_and_bounded_source_journal() {
        for field in ["bank_observations_v2", "max_journal_bytes"] {
            let t = tempfile::tempdir().unwrap();
            let (session, _source) = live_source(t.path());
            let path = session.join("SESSION.json");
            let mut meta: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            if field == "bank_observations_v2" {
                meta[field] = json!(false);
            } else {
                meta["config"][field] = json!(128 * 1024u64.pow(3));
            }
            atomic_json(&path, &meta).unwrap();
            let output = t.path().join("live");
            assert!(
                run_live(
                    &session,
                    &output,
                    Path::new("/missing"),
                    None,
                    false,
                    test_limits()
                )
                .is_err()
            );
            assert!(!output.join("feed.sqlite").exists());
            let status: Value =
                serde_json::from_slice(&fs::read(output.join("STATUS.json")).unwrap()).unwrap();
            assert_eq!(status["state"], "FAILED");
        }
    }
    #[test]
    fn live_only_counts_all_banks_and_rolls_back_discovery_before_overflow() {
        let t = tempfile::tempdir().unwrap();
        let (_session, source) = live_source(t.path());
        let output = t.path().join("live");
        fs::create_dir(&output).unwrap();
        let mut db = database_for_role(&output, 0, true).unwrap();
        db_bank(&db, 10, 7, 1, "status").unwrap();
        db.execute("UPDATE banks SET state='invalidated',dirty=0", [])
            .unwrap();
        insert_source(
            &source,
            1,
            crate::event::Event::Status {
                slot: 11,
                bank_id: Some(8),
                parent: Some(10),
                status: "processed".into(),
                dead_error: None,
            },
        );
        let mut live = test_live();
        live.binding.limits.max_banks = 1;
        assert!(discover_for_role(&source, &mut db, 1, Some(&live)).is_err());
        assert_eq!(
            db.query_row("SELECT count(*) FROM banks", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            db.query_row("SELECT source_sequence FROM feed_state", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            0
        );
    }
    #[test]
    fn live_only_four_bank_group_cannot_bypass_discovery_limit() {
        let t = tempfile::tempdir().unwrap();
        let (_session, source) = live_source(t.path());
        let output = t.path().join("live");
        fs::create_dir(&output).unwrap();
        let mut db = database_for_role(&output, 0, true).unwrap();
        for bank in 1..=4 {
            insert_source(
                &source,
                bank,
                crate::event::Event::Status {
                    slot: 10 + bank,
                    bank_id: Some(bank),
                    parent: Some(9 + bank),
                    status: "processed".into(),
                    dead_error: None,
                },
            );
        }
        let mut live = test_live();
        live.binding.limits.max_banks = 3;
        assert!(discover_for_role(&source, &mut db, 4, Some(&live)).is_err());
        assert_eq!(
            db.query_row("SELECT count(*) FROM banks", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            db.query_row("SELECT source_sequence FROM feed_state", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            db.query_row("SELECT event_sequence FROM feed_state", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            0
        );
    }
    #[test]
    fn live_only_event_ceiling_is_applied_before_source_discovery() {
        let t = tempfile::tempdir().unwrap();
        let (_session, source) = live_source(t.path());
        let output = t.path().join("live");
        fs::create_dir(&output).unwrap();
        let mut db = database_for_role(&output, 10, true).unwrap();
        for n in 11..=13 {
            insert_source(
                &source,
                n,
                crate::event::Event::Status {
                    slot: n,
                    bank_id: Some(n),
                    parent: Some(n - 1),
                    status: "processed".into(),
                    dead_error: None,
                },
            );
        }
        let mut live = test_live();
        live.binding.source_start = 10;
        live.binding.limits.max_events = 2;
        discover_for_role(&source, &mut db, 13, Some(&live)).unwrap();
        assert_eq!(
            db.query_row("SELECT source_sequence FROM feed_state", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            12
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM banks", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            2
        );
        db.execute("UPDATE feed_state SET event_sequence=2", [])
            .unwrap();
        assert!(live.before_event(&output, &db).is_err());
    }
    #[test]
    fn live_only_source_gaps_never_advance_the_feed_position() {
        for missing in [1, 2, 3] {
            let t = tempfile::tempdir().unwrap();
            let (_session, source) = live_source(t.path());
            let output = t.path().join("live");
            fs::create_dir(&output).unwrap();
            let mut db = database_for_role(&output, 0, true).unwrap();
            for n in 1..=3 {
                insert_source(
                    &source,
                    n,
                    crate::event::Event::Status {
                        slot: n,
                        bank_id: Some(n),
                        parent: Some(n - 1),
                        status: "processed".into(),
                        dead_error: None,
                    },
                );
            }
            source
                .execute("DELETE FROM events WHERE sequence=?1", [missing])
                .unwrap();
            assert!(discover_for_role(&source, &mut db, 3, Some(&test_live())).is_err());
            assert_eq!(
                db.query_row("SELECT source_sequence FROM feed_state", [], |r| r
                    .get::<_, u64>(0))
                    .unwrap(),
                0
            );
            assert_eq!(
                db.query_row("SELECT count(*) FROM banks", [], |r| r.get::<_, u64>(0))
                    .unwrap(),
                0
            );
        }
        let t = tempfile::tempdir().unwrap();
        let (_session, source) = live_source(t.path());
        let output = t.path().join("live");
        fs::create_dir(&output).unwrap();
        let mut db = database_for_role(&output, 0, true).unwrap();
        assert!(discover_for_role(&source, &mut db, 1, Some(&test_live())).is_err());
    }
    #[test]
    fn live_only_byte_inventory_covers_database_pending_and_orphan_files() {
        use std::os::unix::fs::symlink;
        let t = tempfile::tempdir().unwrap();
        for path in [
            "feed.sqlite",
            "feed.sqlite-wal",
            "feed.sqlite-shm",
            "live-banks/orphan.pending/payload",
        ] {
            let path = t.path().join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, vec![0u8; 1024 * 1024]).unwrap();
        }
        assert!(live_output_bytes(t.path()).unwrap() >= 4 * 1024 * 1024);
        let mut live = test_live();
        live.binding.limits.max_output_bytes = 4 * 1024 * 1024;
        assert!(live.check(t.path()).is_err());
        symlink("/tmp", t.path().join("external")).unwrap();
        assert!(live_output_bytes(t.path()).is_err());
    }
    #[test]
    fn live_only_inventory_restarts_on_atomic_rename_without_skipping_bytes() {
        let t = tempfile::tempdir().unwrap();
        fs::create_dir(t.path().join("stage")).unwrap();
        fs::write(t.path().join("stage/payload"), vec![0u8; 1024 * 1024]).unwrap();
        let mut attempts = 0;
        let bytes = retry_live_inventory(|| {
            attempts += 1;
            if attempts == 1 {
                fs::rename(t.path().join("stage"), t.path().join("compact")).unwrap();
                return Err(std::io::Error::from(std::io::ErrorKind::NotFound).into());
            }
            live_output_bytes_once(t.path())
        })
        .unwrap();
        assert_eq!(attempts, 2);
        assert!(bytes >= 1024 * 1024);
        attempts = 0;
        assert!(
            retry_live_inventory_until(
                || {
                    attempts += 1;
                    Err(std::io::Error::from(std::io::ErrorKind::NotFound).into())
                },
                Instant::now()
            )
            .is_err()
        );
        assert_eq!(attempts, 1);
        attempts = 0;
        assert!(
            retry_live_inventory(|| {
                attempts += 1;
                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into())
            })
            .is_err()
        );
        assert_eq!(attempts, 1);
    }
    #[test]
    fn live_only_inventory_retries_repeated_real_renames_and_keeps_path_errors() {
        let t = tempfile::tempdir().unwrap();
        let stage = t.path().join("stage");
        let compact = t.path().join("compact");
        fs::create_dir(&stage).unwrap();
        fs::write(stage.join("payload"), vec![0u8; 1024 * 1024]).unwrap();
        let mut renames = 0;
        let bytes = retry_live_inventory(|| {
            live_output_bytes_once_with(t.path(), |path| {
                if renames < 12 && (path == stage || path == compact) {
                    let target = if path == stage { &compact } else { &stage };
                    fs::rename(path, target).unwrap();
                    renames += 1;
                }
            })
        })
        .unwrap();
        assert_eq!(renames, 12);
        assert!(bytes >= 1024 * 1024);
        let missing = t.path().join("missing");
        let error = live_output_bytes_once(&missing).unwrap_err();
        assert!(error.to_string().contains(&missing.display().to_string()));
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::NotFound
        );
    }
    #[test]
    fn live_only_monitor_cache_is_shared_serialized_expiring_and_output_bound() {
        use std::sync::{
            Barrier,
            atomic::{AtomicUsize, Ordering},
        };
        let t = tempfile::tempdir().unwrap();
        let live = test_live();
        let calls = AtomicUsize::new(0);
        let ready = Barrier::new(5);
        thread::scope(|scope| {
            for _ in 0..4 {
                let live = live.clone();
                let (ready, calls, output) = (&ready, &calls, t.path());
                scope.spawn(move || {
                    ready.wait();
                    live.inventory_check(output, false, |_| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        thread::sleep(Duration::from_millis(20));
                        Ok(512)
                    })
                    .unwrap();
                });
            }
            ready.wait();
        });
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        live.inventory
            .lock()
            .unwrap()
            .sample
            .as_mut()
            .unwrap()
            .checked_at = Instant::now() - Duration::from_millis(101);
        live.inventory_check(t.path(), false, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(1024)
        })
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        live.inventory_check(&t.path().join("another-output"), false, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(2048)
        })
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }
    #[test]
    fn live_only_event_commit_forces_inventory_inside_monitor_cache_lifetime() {
        let t = tempfile::tempdir().unwrap();
        let db = database_for_role(t.path(), 0, true).unwrap();
        let mut live = test_live();
        live.binding.limits.max_output_bytes = 1024 * 1024;
        live.check(t.path()).unwrap();
        fs::write(t.path().join("new-payload"), vec![0u8; 1024 * 1024]).unwrap();
        // Arrange an exact cache hit without depending on filesystem speed.
        live.inventory
            .lock()
            .unwrap()
            .sample
            .as_mut()
            .unwrap()
            .checked_at = Instant::now();
        live.monitor(t.path()).unwrap();
        assert!(
            live.before_event(t.path(), &db)
                .unwrap_err()
                .to_string()
                .contains("live_canary_output_byte_limit")
        );
        assert!(live.inventory.lock().unwrap().sample.is_none());
        assert!(live.monitor(t.path()).is_err());
        assert_eq!(
            db.query_row("SELECT event_sequence FROM feed_state", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            0
        );
    }
    #[test]
    fn live_only_monitor_never_reuses_a_success_after_refresh_error() {
        let t = tempfile::tempdir().unwrap();
        let live = test_live();
        live.inventory_check(t.path(), false, |_| Ok(512)).unwrap();
        let error = live
            .inventory_check(t.path(), true, |_| {
                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into())
            })
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert!(live.inventory.lock().unwrap().sample.is_none());
        let calls = std::cell::Cell::new(0);
        live.inventory_check(t.path(), false, |_| {
            calls.set(1);
            Ok(1024)
        })
        .unwrap();
        assert_eq!(calls.get(), 1);
    }
    #[test]
    fn live_only_cached_monitor_still_checks_the_original_time_limit() {
        let t = tempfile::tempdir().unwrap();
        let mut live = test_live();
        live.inventory_check(t.path(), false, |_| Ok(512)).unwrap();
        live.deadline = Instant::now() - Duration::from_millis(1);
        assert!(
            live.inventory_check(t.path(), false, |_| panic!("cache hit must not scan"))
                .unwrap_err()
                .to_string()
                .contains("live_canary_time_limit")
        );
    }
    #[test]
    fn live_only_poisoned_monitor_lock_fails_closed() {
        let t = tempfile::tempdir().unwrap();
        let live = test_live();
        let other = live.clone();
        assert!(
            thread::spawn(move || {
                let _lock = other.inventory.lock().unwrap();
                panic!("poison test");
            })
            .join()
            .is_err()
        );
        assert!(
            live.monitor(t.path())
                .unwrap_err()
                .to_string()
                .contains("lock poisoned")
        );
    }
    #[test]
    fn live_only_expired_binding_cannot_get_a_new_time_budget() {
        let binding = LiveBinding {
            limits: test_limits(),
            started_unix_ms: now_ms().unwrap() - 61000,
            source_start: 0,
        };
        assert!(LiveCanary::from_binding(binding).is_err());
        for bad in [0, 4097] {
            let mut limits = test_limits();
            limits.max_banks = bad;
            assert!(limits.validate().is_err());
        }
        let mut limits = test_limits();
        limits.max_seconds = 0;
        assert!(limits.validate().is_err());
    }
    #[test]
    fn live_only_incomplete_boundary_fails_and_cannot_auto_resume() {
        let t = tempfile::tempdir().unwrap();
        let (session, source) = live_source(t.path());
        insert_source(
            &source,
            1,
            crate::event::Event::Status {
                slot: 10,
                bank_id: Some(7),
                parent: Some(9),
                status: "processed".into(),
                dead_error: None,
            },
        );
        insert_source(
            &source,
            2,
            crate::event::Event::Status {
                slot: 11,
                bank_id: Some(8),
                parent: Some(10),
                status: "processed".into(),
                dead_error: None,
            },
        );
        let output = t.path().join("live");
        assert!(
            run_live(
                &session,
                &output,
                Path::new("/missing"),
                None,
                false,
                test_limits()
            )
            .is_err()
        );
        let status: Value =
            serde_json::from_slice(&fs::read(output.join("STATUS.json")).unwrap()).unwrap();
        assert_eq!(status["state"], "FAILED");
        assert_eq!(status["waiting_banks"], 2);
        assert_eq!(status["discovered_through_source_sequence"], 2);
        assert_eq!(status["event_sequence"], 0);
        assert_eq!(status["pending_bank_count"], 2);
        assert_eq!(status["unpublished_banks"], 2);
        assert_eq!(status["minimum_pending_first_sequence"], 1);
        assert_eq!(status["pending_banks"][0]["first_sequence"], 1);
        assert_eq!(status["discovery_position_is_emitted_coverage"], false);
        assert!(status.get("producer_gap_after_source_sequence").is_none());
        assert!(status.get("source_capture_stopped").is_none());
        assert_eq!(status["source_capture_stop_requested"], false);
        assert_eq!(status["full_bank_coverage_asserted"], false);
        let stop = fs::read(output.join("LIVE-CANARY-STOP.json")).unwrap();
        assert!(
            run_live(
                &session,
                &output,
                Path::new("/missing"),
                None,
                false,
                test_limits()
            )
            .is_err()
        );
        assert_eq!(
            fs::read(output.join("LIVE-CANARY-STOP.json")).unwrap(),
            stop
        );
        assert_no_archive(
            &output,
            &open_reader(&output.join("feed.sqlite")).unwrap(),
            &session,
        );
    }
    #[test]
    fn live_only_stops_and_reaps_the_owned_writer_on_time_limit() {
        let t = tempfile::tempdir().unwrap();
        let mut live = test_live();
        live.deadline = Instant::now() + Duration::from_millis(100);
        let pidfile = t.path().join("child.pid");
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("echo $$ > \"$1\"; exec sleep 10")
            .arg("canary")
            .arg(&pidfile);
        assert!(live_writer(&mut command, &live, t.path()).is_err());
        let pid: i32 = fs::read_to_string(pidfile).unwrap().trim().parse().unwrap();
        assert_eq!(
            unsafe { libc::kill(pid, 0) },
            -1,
            "owned converter must have been reaped"
        );
    }
    #[test]
    fn discovery_batches_callbacks_without_losing_fork_root_or_dead_boundaries() {
        let t = tempfile::tempdir().unwrap();
        let source = Connection::open_in_memory().unwrap();
        source.execute_batch("CREATE TABLE events(sequence INTEGER PRIMARY KEY,slot INTEGER,bank INTEGER,kind TEXT,payload BLOB,sha256 TEXT);").unwrap();
        for (seq, slot, bank, kind) in [
            (1, 10, Some(1), "account"),
            (2, 10, Some(1), "transaction"),
            (3, 10, Some(2), "transaction"),
            (4, 10, Some(1), "rooted"),
            (5, 10, Some(2), "clear"),
            (6, 11, None, "dead"),
            (7, 11, Some(3), "transaction"),
            (8, 10, Some(1), "account"),
        ] {
            source
                .execute(
                    "INSERT INTO events VALUES(?1,?2,?3,?4,NULL,'unused')",
                    params![seq, slot, bank, kind],
                )
                .unwrap();
        }
        let mut db = database(t.path(), 0).unwrap();
        discover(&source, &mut db, 8).unwrap();
        let row = |slot: u64, bank: u64| -> (u64, u64, u64, u64, u64) {
            db.query_row("SELECT first_sequence,last_sequence,root_sequence,invalid_sequence,dirty FROM banks WHERE slot=?1 AND bank=?2",params![slot,bank],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).unwrap()
        };
        assert_eq!(row(10, 1), (1, 8, 4, 0, 1));
        assert_eq!(row(10, 2), (3, 5, 0, 5, 1));
        assert_eq!(row(11, 3), (7, 7, 0, 6, 1));
        assert_eq!(
            db.query_row("SELECT source_sequence FROM feed_state", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            8
        );
        discover(&source, &mut db, 8).unwrap();
        assert_eq!(
            db.query_row(
                "SELECT last_sequence FROM banks WHERE slot=10 AND bank=1",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
            8
        );
    }
    #[test]
    fn archived_native_evidence_can_be_restored_before_late_callback_audit() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let helper = t.path().join("restore");
        fs::write(&helper, "#!/bin/sh\nprintf recovered > \"$5\"\n").unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        let path = t.path().join("source-events.json.zst");
        assert_eq!(
            read_retained_file(&path, t.path(), Some(&helper)).unwrap(),
            b"recovered"
        );
        assert_eq!(fs::read(path).unwrap(), b"recovered");
    }
    #[test]
    fn warm_native_evidence_does_not_call_archive_helper() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("source-events.json.zst");
        fs::write(&path, b"warm").unwrap();
        assert_eq!(
            read_retained_file(&path, t.path(), Some(Path::new("/missing-helper"))).unwrap(),
            b"warm"
        );
        fs::remove_file(&path).unwrap();
        assert!(read_retained_file(&path, t.path(), None).is_err());
    }
    fn insert_source(db: &Connection, sequence: u64, event: crate::event::Event) {
        let raw = serde_json::to_vec(&event).unwrap();
        let (slot, bank, kind) = event.key();
        db.execute(
            "INSERT INTO events VALUES(?1,?2,?3,?4,?5,?6)",
            params![sequence, slot, bank, kind, digest(&raw), raw],
        )
        .unwrap();
        db.execute("UPDATE status SET durable_sequence=?1", [sequence])
            .unwrap();
    }
    fn parent_fixture() -> (tempfile::TempDir, Connection, Connection) {
        let temp = tempfile::tempdir().unwrap();
        let source = Connection::open_in_memory().unwrap();
        source.execute_batch("CREATE TABLE events(sequence INTEGER PRIMARY KEY,slot INTEGER,bank INTEGER,kind TEXT,sha256 TEXT,payload BLOB);CREATE INDEX bank_events ON events(slot,bank,sequence);CREATE TABLE status(id INTEGER,durable_sequence INTEGER);INSERT INTO status VALUES(1,0);").unwrap();
        let db = database(temp.path(), 0).unwrap();
        (temp, source, db)
    }
    fn native_parent_fixture() -> Value {
        serde_json::from_str(include_str!(
            "../tests/fixtures/native-parent-conflict.json"
        ))
        .unwrap()
    }
    fn native_parent_state(confirmed: bool, zero: bool) -> crate::event::NativeBankState {
        let fixture = native_parent_fixture();
        let index = if confirmed { 1 } else { 2 };
        let crate::event::Event::BankStateV2(mut state) =
            serde_json::from_value(fixture["events"][index]["decoded"].clone()).unwrap()
        else {
            unreachable!()
        };
        state.parent_blockhash = if zero {
            [0; 32]
        } else {
            serde_json::from_value(fixture["events"][0]["decoded"]["parent_blockhash"].clone())
                .unwrap()
        };
        state
    }
    fn native_parent_footer() -> crate::event::Event {
        serde_json::from_value(native_parent_fixture()["events"][0]["decoded"].clone()).unwrap()
    }
    fn observation_pair(
        db: &Connection,
    ) -> (
        crate::event::NativeBankState,
        u64,
        crate::event::NativeBankState,
        u64,
    ) {
        db.query_row("SELECT frozen_json,frozen_sequence,confirmed_json,confirmed_sequence FROM bank_observations WHERE slot=457459658 AND bank=958752", [], |r| {
            Ok((serde_json::from_str(&r.get::<_, String>(0)?).unwrap(), r.get(1)?,
                serde_json::from_str(&r.get::<_, String>(2)?).unwrap(), r.get(3)?))
        }).unwrap()
    }
    fn assert_parent_rollback(db: &Connection, cursor: u64, observations: u64) {
        assert_eq!(
            db.query_row("SELECT source_sequence FROM feed_state", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            cursor
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM bank_parent_resolutions", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM bank_observations", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            observations
        );
    }
    #[test]
    fn native_parent_actual_confirmed_then_zero_frozen_preserves_source_and_restart() {
        let fixture = native_parent_fixture();
        let (temp, source, mut db) = parent_fixture();
        for row in fixture["events"].as_array().unwrap() {
            let event: crate::event::Event =
                serde_json::from_value(row["decoded"].clone()).unwrap();
            assert_eq!(
                digest(&serde_json::to_vec(&event).unwrap()),
                row["sha256"].as_str().unwrap()
            );
            insert_source(&source, row["sequence"].as_u64().unwrap(), event);
        }
        let original = source
            .prepare("SELECT sequence,sha256,payload FROM events ORDER BY sequence")
            .unwrap()
            .query_map([], |r| {
                Ok((
                    r.get::<_, u64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        let after = fixture["worker_source_after"].as_u64().unwrap();
        db.execute("UPDATE feed_state SET source_sequence=?1", [after])
            .unwrap();
        let through = fixture["events"][2]["sequence"].as_u64().unwrap();
        discover(&source, &mut db, through).unwrap();
        let (frozen, frozen_sequence, confirmed, confirmed_sequence) = observation_pair(&db);
        assert_eq!(frozen, native_parent_state(false, false));
        assert_eq!(confirmed, native_parent_state(true, false));
        assert_eq!(frozen_sequence, through);
        assert_eq!(confirmed_sequence, 2149114053);
        let proof: (String, u64, String) = db.query_row("SELECT proof_kind,proof_sequence,proof_sha256 FROM bank_parent_resolutions WHERE source_sequence=?1", [through],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        assert_eq!(
            proof,
            (
                "native-block-footer".into(),
                2149060399,
                fixture["events"][0]["sha256"].as_str().unwrap().into()
            )
        );
        let unchanged = source
            .prepare("SELECT sequence,sha256,payload FROM events ORDER BY sequence")
            .unwrap()
            .query_map([], |r| {
                Ok((
                    r.get::<_, u64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(original, unchanged);
        drop(db);
        let mut db = database(temp.path(), 0).unwrap();
        discover(&source, &mut db, through).unwrap();
        assert_eq!(
            observation_pair(&db),
            (frozen, frozen_sequence, confirmed, confirmed_sequence)
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM bank_parent_resolutions", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            1
        );
    }
    #[test]
    fn native_parent_zero_frozen_before_confirmation_uses_compressed_footer() {
        use crate::event::Event;
        let (_temp, source, mut db) = parent_fixture();
        insert_source(&source, 1, native_parent_footer());
        let raw: Vec<u8> = source
            .query_row("SELECT payload FROM events WHERE sequence=1", [], |r| {
                r.get(0)
            })
            .unwrap();
        source
            .execute(
                "UPDATE events SET payload=?1 WHERE sequence=1",
                [zstd::bulk::compress(&raw, 1).unwrap()],
            )
            .unwrap();
        insert_source(
            &source,
            2,
            Event::BankStateV2(native_parent_state(false, true)),
        );
        insert_source(
            &source,
            3,
            Event::BankStateV2(native_parent_state(true, false)),
        );
        discover(&source, &mut db, 3).unwrap();
        let (frozen, fs, confirmed, cs) = observation_pair(&db);
        assert_eq!(frozen, native_parent_state(false, false));
        assert_eq!(confirmed, native_parent_state(true, false));
        assert_eq!((fs, cs), (2, 3));
    }
    #[test]
    fn native_parent_existing_observation_is_exact_proof_without_footer() {
        use crate::event::Event;
        let (_temp, source, mut db) = parent_fixture();
        insert_source(
            &source,
            1,
            Event::BankStateV2(native_parent_state(true, false)),
        );
        insert_source(
            &source,
            2,
            Event::BankStateV2(native_parent_state(false, true)),
        );
        discover(&source, &mut db, 2).unwrap();
        let kind: String = db
            .query_row("SELECT proof_kind FROM bank_parent_resolutions", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(kind, "native-bank-observation");
        assert_eq!(observation_pair(&db).0, native_parent_state(false, false));
    }
    #[test]
    fn native_parent_legacy_zero_row_is_repaired_without_renewing_observation() {
        use crate::event::Event;
        let (_temp, source, mut db) = parent_fixture();
        let old = native_parent_state(false, true);
        db.execute("INSERT INTO bank_observations(slot,bank,frozen_json,frozen_sequence) VALUES(?1,?2,?3,1)",
            params![old.slot, old.bank_id, serde_json::to_string(&old).unwrap()]).unwrap();
        db.execute("UPDATE feed_state SET source_sequence=1", [])
            .unwrap();
        insert_source(
            &source,
            2,
            Event::BankStateV2(native_parent_state(true, false)),
        );
        discover(&source, &mut db, 2).unwrap();
        let (frozen, fs, confirmed, cs) = observation_pair(&db);
        assert_eq!(frozen, native_parent_state(false, false));
        assert_eq!(confirmed, native_parent_state(true, false));
        assert_eq!((fs, cs), (1, 2));
    }
    #[test]
    fn native_parent_tuple_mismatches_remain_fatal_without_cursor_advance() {
        use crate::event::Event;
        for field in [
            "slot",
            "bank",
            "parent_slot",
            "blockhash",
            "height",
            "expiry",
            "parent_hash",
        ] {
            let (_temp, source, mut db) = parent_fixture();
            insert_source(
                &source,
                1,
                Event::BankStateV2(native_parent_state(true, false)),
            );
            discover(&source, &mut db, 1).unwrap();
            let mut changed = native_parent_state(false, true);
            match field {
                "slot" => changed.slot += 1,
                "bank" => changed.bank_id += 1,
                "parent_slot" => changed.parent_slot -= 1,
                "blockhash" => changed.blockhash[0] ^= 1,
                "height" => changed.block_height += 1,
                "expiry" => changed.last_valid_block_height += 1,
                "parent_hash" => changed.parent_blockhash = [1; 32],
                _ => unreachable!(),
            }
            insert_source(&source, 2, Event::BankStateV2(changed));
            assert!(discover(&source, &mut db, 2).is_err(), "{field}");
            assert_parent_rollback(&db, 1, 1);
        }
    }
    #[test]
    fn native_parent_missing_or_uncommitted_footer_is_not_proof() {
        use crate::event::Event;
        for future in [false, true] {
            let (_temp, source, mut db) = parent_fixture();
            insert_source(
                &source,
                1,
                Event::BankStateV2(native_parent_state(false, true)),
            );
            if future {
                insert_source(&source, 2, native_parent_footer());
            }
            assert!(discover(&source, &mut db, 1).is_err());
            assert_parent_rollback(&db, 0, 0);
        }
    }
    #[test]
    fn native_parent_footer_rejects_bad_digest_key_height_and_conflicting_parents() {
        use crate::event::Event;
        for field in [
            "digest",
            "sql_key",
            "height",
            "parent_slot",
            "blockhash",
            "zero",
            "conflict",
            "bound",
        ] {
            let (_temp, source, mut db) = parent_fixture();
            let mut footer = native_parent_footer();
            if let Event::Block {
                bank_id,
                block_height,
                parent_slot,
                blockhash,
                parent_blockhash,
                ..
            } = &mut footer
            {
                match field {
                    "sql_key" => *bank_id += 1,
                    "height" => *block_height = block_height.map(|h| h + 1),
                    "parent_slot" => *parent_slot -= 1,
                    "blockhash" => blockhash[0] ^= 1,
                    "zero" => *parent_blockhash = [0; 32],
                    _ => {}
                }
            }
            insert_source(&source, 1, footer);
            if field == "digest" {
                source
                    .execute("UPDATE events SET sha256='bad' WHERE sequence=1", [])
                    .unwrap();
            }
            if field == "sql_key" {
                source
                    .execute("UPDATE events SET bank=958752 WHERE sequence=1", [])
                    .unwrap();
            }
            if matches!(field, "conflict" | "bound") {
                let mut other = native_parent_footer();
                if field == "conflict" {
                    if let Event::Block {
                        parent_blockhash, ..
                    } = &mut other
                    {
                        *parent_blockhash = [1; 32];
                    }
                }
                insert_source(&source, 2, other);
                if field == "bound" {
                    insert_source(&source, 3, native_parent_footer());
                }
            }
            insert_source(
                &source,
                4,
                Event::BankStateV2(native_parent_state(false, true)),
            );
            assert!(discover(&source, &mut db, 4).is_err(), "{field}");
            assert_parent_rollback(&db, 0, 0);
        }
    }
    #[test]
    fn native_parent_hidden_confirmed_conflict_is_not_masked_by_frozen_row() {
        use crate::event::Event;
        let (_temp, source, mut db) = parent_fixture();
        let frozen = native_parent_state(false, false);
        let mut confirmed = native_parent_state(true, false);
        confirmed.parent_blockhash = [1; 32];
        db.execute("INSERT INTO bank_observations(slot,bank,frozen_json,frozen_sequence,confirmed_json,confirmed_sequence) VALUES(?1,?2,?3,1,?4,2)",
            params![frozen.slot, frozen.bank_id, serde_json::to_string(&frozen).unwrap(), serde_json::to_string(&confirmed).unwrap()]).unwrap();
        db.execute("UPDATE feed_state SET source_sequence=2", [])
            .unwrap();
        insert_source(
            &source,
            3,
            Event::BankStateV2(native_parent_state(false, true)),
        );
        assert!(discover(&source, &mut db, 3).is_err());
        assert_parent_rollback(&db, 2, 1);
    }
    #[test]
    fn native_parent_later_conflict_rolls_back_resolution_evidence_and_cursor() {
        use crate::event::Event;
        let (_temp, source, mut db) = parent_fixture();
        insert_source(&source, 1, native_parent_footer());
        insert_source(
            &source,
            2,
            Event::BankStateV2(native_parent_state(false, true)),
        );
        let mut changed = native_parent_state(true, false);
        changed.last_valid_block_height += 1;
        insert_source(&source, 3, Event::BankStateV2(changed));
        assert!(discover(&source, &mut db, 3).is_err());
        assert_parent_rollback(&db, 0, 0);
    }
    #[test]
    #[ignore = "requires BLOCKZILLA_BUILDER; run on the remote build host"]
    fn roots_reuse_payload_and_restart_retains_controls_and_late_source() {
        root_reuse_fixture(false);
    }
    fn committed_recovery_fixture() -> (
        tempfile::TempDir,
        Connection,
        ContextData,
        Connection,
        PendingPayload,
    ) {
        use crate::event::Event;
        let t = tempfile::tempdir().unwrap();
        let (source, mut c, mut db) = continuous_fixture(t.path());
        c.builder = PathBuf::from(std::env::var("BLOCKZILLA_BUILDER").unwrap());
        for (i, event) in [
            Event::Status {
                slot: 10,
                bank_id: Some(7),
                parent: Some(9),
                status: "processed".into(),
                dead_error: None,
            },
            Event::Entry {
                slot: 10,
                bank_id: 7,
                index: 0,
                num_hashes: 1,
                hash: [7; 32],
                transactions: 0,
                starting_transaction_index: 0,
            },
            Event::Block {
                slot: 10,
                bank_id: 7,
                parent_slot: 9,
                parent_blockhash: [6; 32],
                blockhash: [7; 32],
                transactions: 0,
                entries: 1,
                block_time: None,
                block_height: None,
                native_rewards: json!({"rewards":[]}),
                rewards: blockzilla_archive_v2::WincodeArchiveV2NoRegistryRewards {
                    source_len: 0,
                    num_partitions: None,
                    decoded: Some(vec![]),
                    raw_fallback: None,
                    decode_error: None,
                },
            },
        ]
        .into_iter()
        .enumerate()
        {
            insert_source(&source, i as u64 + 1, event);
        }
        discover_for_role(&source, &mut db, 3, c.live.as_ref()).unwrap();
        let records = continuous_records(&db, &source, &c, 10, 7, 3).unwrap();
        let complete = worker::assemble_bank(10, 7, records, false)
            .unwrap()
            .unwrap();
        let fingerprint = projection(&complete).unwrap();
        let (_, payload) = prepare_payload(&c, 10, 7, complete, fingerprint).unwrap();
        // The exact crash boundary: the payload event and Bank are FULL
        // committed, but no normalized cleanup or sealing has happened.
        commit_payload_record(&mut db, 10, 7, &payload).unwrap();
        (t, source, c, db, payload)
    }

    #[test]
    #[ignore = "requires the real compact writer on Foundation"]
    fn continuous_committed_recovery_cleans_only_verified_normalized_remainders() {
        for partial in [false, true] {
            let (_t, source, c, mut db, payload) = committed_recovery_fixture();
            let marker = fs::read(payload.compact.join("DIRECT-AGAVE-COMPACT.v1.json")).unwrap();
            if partial {
                let receipt: worker::Receipt = serde_json::from_slice(
                    &fs::read(payload.normalized.join("DIRECT-AGAVE-NORMALIZED.v1.json")).unwrap(),
                )
                .unwrap();
                fs::remove_file(payload.normalized.join(&receipt.files[0].path)).unwrap();
                fs::remove_file(payload.normalized.join("DIRECT-AGAVE-NORMALIZED.v1.json"))
                    .unwrap();
            }
            assert!(committed_recovery_needed(&payload.compact).unwrap());
            recover_committed_payload(&c, &db, 10, 7).unwrap();
            assert!(!payload.normalized.exists());
            assert!(!committed_recovery_needed(&payload.compact).unwrap());
            c.live
                .as_ref()
                .unwrap()
                .seal_compact(&c.output, &payload.compact, 10, 7, &payload.marker_sha)
                .unwrap();
            process_banks(&source, &mut db, &c, 3).unwrap();
            assert_eq!(
                db.query_row(
                    "SELECT count(*) FROM feed_events WHERE kind='block'",
                    [],
                    |r| r.get::<_, u64>(0)
                )
                .unwrap(),
                1
            );
            assert_eq!(
                fs::read(payload.compact.join("DIRECT-AGAVE-COMPACT.v1.json")).unwrap(),
                marker
            );
        }
    }

    #[test]
    #[ignore = "requires the real compact writer on Foundation"]
    fn continuous_committed_recovery_preserves_interrupted_alias_and_copy_crash() {
        use std::os::unix::fs::MetadataExt;
        for interrupt in [false, true] {
            let (_t, source, c, mut db, payload) = committed_recovery_fixture();
            let path = payload.compact.join("blockhash_registry.bin");
            let bytes = fs::read(&path).unwrap();
            let marker = fs::read(payload.compact.join("DIRECT-AGAVE-COMPACT.v1.json")).unwrap();
            let stage = payload
                .compact
                .parent()
                .unwrap()
                .join(".10-7.compact.direct-agave-interrupted-1795301067763930800-1872553");
            fs::create_dir(&stage).unwrap();
            let alias = stage.join("blockhash_registry.bin");
            fs::hard_link(&path, &alias).unwrap();
            fs::remove_dir_all(&payload.normalized).unwrap();
            let original = fs::metadata(&alias).unwrap();
            assert_eq!(original.nlink(), 2);
            let mut preserved_copy = None;
            if interrupt {
                let error = detach_committed_alias(
                    &path,
                    bytes.len() as u64,
                    &digest(&bytes),
                    |temporary| {
                        preserved_copy = Some(temporary.to_path_buf());
                        anyhow::bail!("test interruption after durable private copy")
                    },
                )
                .unwrap_err();
                assert!(error.to_string().contains("test interruption"));
                assert_eq!(fs::metadata(&path).unwrap().ino(), original.ino());
                assert_eq!(fs::read(preserved_copy.as_ref().unwrap()).unwrap(), bytes);
            }
            recover_committed_payload(&c, &db, 10, 7).unwrap();
            let active = fs::metadata(&path).unwrap();
            assert_ne!(active.ino(), original.ino());
            assert_eq!(active.nlink(), 1);
            assert_eq!(active.mode() & 0o777, 0o400);
            assert_eq!(fs::metadata(&alias).unwrap().ino(), original.ino());
            assert_eq!(fs::read(&alias).unwrap(), bytes);
            assert_eq!(fs::read(&path).unwrap(), bytes);
            assert_eq!(
                fs::read(payload.compact.join("DIRECT-AGAVE-COMPACT.v1.json")).unwrap(),
                marker
            );
            if let Some(copy) = preserved_copy {
                assert!(copy.exists());
            }
            assert!(!committed_recovery_needed(&payload.compact).unwrap());
            // A second startup has no recovery work and does not republish.
            verify_compact_custody(&payload.compact, &payload.marker_sha).unwrap();
            c.live
                .as_ref()
                .unwrap()
                .seal_compact(&c.output, &payload.compact, 10, 7, &payload.marker_sha)
                .unwrap();
            process_banks(&source, &mut db, &c, 3).unwrap();
            assert_eq!(
                db.query_row(
                    "SELECT count(*) FROM feed_events WHERE kind='block'",
                    [],
                    |r| r.get::<_, u64>(0)
                )
                .unwrap(),
                1
            );
        }
    }

    #[test]
    #[ignore = "requires the real compact writer on Foundation"]
    fn continuous_committed_recovery_rejects_unbound_changed_and_unknown_files() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
        for fault in 0..7 {
            let (_t, _source, mut c, db, payload) = committed_recovery_fixture();
            let target = payload.compact.join("blockhash_registry.bin");
            let inode = fs::metadata(&target).unwrap().ino();
            match fault {
                0 => {
                    db.execute("UPDATE banks SET marker_sha=?1", ["a".repeat(64)])
                        .unwrap();
                }
                1 => c.id = "wrong-source".into(),
                2 => fs::write(payload.compact.join("unknown"), b"preserve").unwrap(),
                3 => fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap(),
                4 => fs::write(payload.normalized.join("unknown"), b"preserve").unwrap(),
                5 => symlink("/missing", payload.normalized.join("unknown-link")).unwrap(),
                _ => {
                    fs::remove_file(payload.normalized.join("DIRECT-AGAVE-NORMALIZED.v1.json"))
                        .unwrap();
                    fs::write(
                        payload.normalized.join("DIRECT-AGAVE-NORMALIZED.v1.json"),
                        b"wrong",
                    )
                    .unwrap();
                }
            }
            assert!(
                recover_committed_payload(&c, &db, 10, 7).is_err(),
                "fault {fault}"
            );
            assert!(payload.normalized.exists(), "fault {fault} deleted stage");
            assert_eq!(fs::metadata(&target).unwrap().ino(), inode);
            assert_eq!(
                db.query_row("SELECT count(*) FROM feed_events", [], |r| r
                    .get::<_, u64>(0))
                    .unwrap(),
                1
            );
        }
    }
    #[test]
    #[ignore = "requires the real compact writer and Python 3 on Foundation"]
    fn live_only_four_converters_run_together_and_commit_complete_banks_in_order() {
        parallel_live_fixture(false, false);
    }
    #[test]
    #[ignore = "requires the real compact writer and Python 3 on Foundation"]
    fn live_only_parallel_converters_cannot_bypass_feed_event_limit() {
        parallel_live_fixture(true, false);
    }
    #[test]
    #[ignore = "requires the real compact writer and Python 3 on Foundation"]
    fn live_only_parallel_converters_survive_repeated_stage_rename_churn() {
        parallel_live_fixture(false, true);
    }
    fn parallel_live_fixture(limit_feed: bool, rename_churn: bool) {
        use crate::event::Event;
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let (session, source) = live_source(t.path());
        let output = t.path().join("output");
        fs::create_dir(&output).unwrap();
        let builder = PathBuf::from(std::env::var("BLOCKZILLA_BUILDER").unwrap());
        let state = t.path().join("converters.json");
        fs::write(
            &state,
            br#"{"entered":0,"active":0,"maximum":0,"finished":0}"#,
        )
        .unwrap();
        let wrapper = t.path().join("parallel-writer");
        // The barrier proves real process overlap. The old live chunk size of
        // one times out before any real conversion can complete.
        let script = format!(
            r#"#!/usr/bin/env python3
import fcntl, json, os, pathlib, subprocess, sys, time
state = {state}
builder = {builder}
churn_root = {churn_root}
rename_churn = {rename_churn}
def change(enter=False, finish=False):
    with open(state, 'r+') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        value = json.load(stream)
        if enter:
            value['entered'] += 1
            value['active'] += 1
            value['maximum'] = max(value['maximum'], value['active'])
        if finish:
            value['active'] -= 1
            value['finished'] += 1
        stream.seek(0)
        json.dump(value, stream)
        stream.truncate()
        stream.flush()
        return value
change(enter=True)
try:
    deadline = time.monotonic() + 10
    while change()['entered'] < 4:
        if time.monotonic() >= deadline:
            raise RuntimeError('four compact converters did not overlap')
        time.sleep(0.01)
    if rename_churn:
        stage = pathlib.Path(churn_root) / ('moving-' + str(os.getpid()))
        compact = stage.with_suffix('.compact')
        until = time.monotonic() + 0.4
        while time.monotonic() < until:
            stage.mkdir()
            (stage / 'payload').write_bytes(b'x' * 4096)
            stage.rename(compact)
            time.sleep(0.001)
            (compact / 'payload').unlink()
            compact.rmdir()
    result = subprocess.run([builder] + sys.argv[1:])
finally:
    change(finish=True)
sys.exit(result.returncode)
"#,
            state = serde_json::to_string(&state).unwrap(),
            builder = serde_json::to_string(&builder).unwrap(),
            churn_root = serde_json::to_string(&output).unwrap(),
            rename_churn = if rename_churn { "True" } else { "False" },
        );
        fs::write(&wrapper, script).unwrap();
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
        let mut live = test_live();
        if limit_feed {
            live.binding.limits.max_events = 3;
        }
        let c = ContextData {
            session: session.clone(),
            output: output.clone(),
            builder: wrapper,
            meta: json!({"config":{"node_identity":"J7qpvCEWhdBgPdYRV3s3btWPrRVXa2qnAzgvxWTvtbrQ"},"processed_custody":false}),
            id: "parallel-live-test".into(),
            genesis: "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d".into(),
            codec: "json-v1".into(),
            max_event_bytes: 16 * 1024 * 1024,
            live: Some(live),
        };
        let mut db = database_for_role(&output, 0, true).unwrap();
        let mut sequence = 0;
        for bank in 1..=6 {
            let slot = 10 + bank;
            let mut events = vec![Event::Status {
                slot,
                bank_id: Some(bank),
                parent: Some(slot - 1),
                status: "processed".into(),
                dead_error: None,
            }];
            if bank <= 4 {
                events.push(Event::Entry {
                    slot,
                    bank_id: bank,
                    index: 0,
                    num_hashes: 1,
                    hash: [bank as u8; 32],
                    transactions: 0,
                    starting_transaction_index: 0,
                });
            }
            // Bank 5 has a footer but lacks its entry. Bank 6 has no footer.
            if bank <= 5 {
                events.push(Event::Block {
                    slot,
                    bank_id: bank,
                    parent_slot: slot - 1,
                    parent_blockhash: [(bank - 1) as u8; 32],
                    blockhash: [bank as u8; 32],
                    transactions: 0,
                    entries: 1,
                    block_time: None,
                    block_height: None,
                    native_rewards: json!({"rewards":[]}),
                    rewards: blockzilla_archive_v2::WincodeArchiveV2NoRegistryRewards {
                        source_len: 0,
                        num_partitions: None,
                        decoded: Some(vec![]),
                        raw_fallback: None,
                        decode_error: None,
                    },
                });
            }
            for event in events {
                sequence += 1;
                insert_source(&source, sequence, event);
            }
        }
        // Source admission has a separate test above. Admit all source rows
        // here to isolate the feed-event check after concurrent preparation.
        discover_for_role(&source, &mut db, sequence, None).unwrap();
        let result = process_banks(&source, &mut db, &c, sequence);
        if limit_feed {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("live_canary_feed_event_limit")
            );
        } else {
            result.unwrap();
        }
        let state: Value = serde_json::from_slice(&fs::read(state).unwrap()).unwrap();
        assert_eq!(
            state,
            json!({"entered":4,"active":0,"maximum":4,"finished":4})
        );
        let published = if limit_feed { 3 } else { 4 };
        assert_eq!(
            db.query_row("SELECT count(*) FROM feed_events", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            published
        );
        assert_eq!(
            db.query_row("SELECT event_sequence FROM feed_state", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            published
        );
        let rows = db
            .prepare("SELECT bank,kind FROM feed_events ORDER BY sequence")
            .unwrap()
            .query_map([], |r| Ok((r.get::<_, u64>(0)?, r.get::<_, String>(1)?)))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            rows,
            (1..=published)
                .map(|bank| (bank, "block".into()))
                .collect::<Vec<_>>()
        );
        assert_eq!(db.query_row("SELECT count(*) FROM banks WHERE bank IN (5,6) AND state='waiting' AND artifact IS NULL", [], |r| r.get::<_, u64>(0)).unwrap(), 2);
        assert!(!output.join("live-banks/15-5.compact").exists());
        assert!(!output.join("live-banks/16-6.compact").exists());
        assert_no_archive(&output, &db, &session);
    }
    #[test]
    #[ignore = "requires BLOCKZILLA_BUILDER; run on the remote build host"]
    fn live_only_roots_and_forks_reuse_payload_without_archive_or_retirement() {
        root_reuse_fixture(true);
    }
    fn root_reuse_fixture(live: bool) {
        use crate::event::Event;
        let t = tempfile::tempdir().unwrap();
        let session = t.path().join("source");
        let output = t.path().join("output");
        fs::create_dir(&session).unwrap();
        fs::create_dir(session.join("retire-pending")).unwrap();
        fs::create_dir(&output).unwrap();
        let mut source = Connection::open(session.join("events.sqlite")).unwrap();
        source.execute_batch("CREATE TABLE events(sequence INTEGER PRIMARY KEY,slot INTEGER,bank INTEGER,kind TEXT,sha256 TEXT,payload BLOB); CREATE TABLE status(id INTEGER,state TEXT,durable_sequence INTEGER,retired_events INTEGER,latest_rooted_slot INTEGER); INSERT INTO status VALUES(1,'CLOSED',0,0,0);CREATE TABLE retire_jobs(id TEXT PRIMARY KEY,bank_index INTEGER,deleted_events INTEGER,marker_sha TEXT);").unwrap();
        let builder = PathBuf::from(std::env::var("BLOCKZILLA_BUILDER").unwrap());
        let c = ContextData {
            session: session.clone(),
            output: output.clone(),
            builder,
            meta: json!({"config":{"node_identity":"J7qpvCEWhdBgPdYRV3s3btWPrRVXa2qnAzgvxWTvtbrQ"},"processed_custody":true}),
            id: "test".into(),
            genesis: "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d".into(),
            codec: "json-v1".into(),
            max_event_bytes: 16 * 1024 * 1024,
            live: live.then(test_live),
        };
        let mut db = database_for_role(&output, 0, live).unwrap();
        let mut sequence = 0;
        for bank in [7, 8] {
            for event in [
                Event::Status {
                    slot: 10,
                    bank_id: Some(bank),
                    parent: Some(9),
                    status: "processed".into(),
                    dead_error: None,
                },
                Event::Entry {
                    slot: 10,
                    bank_id: bank,
                    index: 0,
                    num_hashes: 1,
                    hash: [bank as u8; 32],
                    transactions: 0,
                    starting_transaction_index: 0,
                },
                Event::Block {
                    slot: 10,
                    bank_id: bank,
                    parent_slot: 9,
                    parent_blockhash: [6; 32],
                    blockhash: [bank as u8; 32],
                    transactions: 0,
                    entries: 1,
                    block_time: None,
                    block_height: None,
                    native_rewards: json!({"rewards":[]}),
                    rewards: blockzilla_archive_v2::WincodeArchiveV2NoRegistryRewards {
                        source_len: 0,
                        num_partitions: None,
                        decoded: Some(vec![]),
                        raw_fallback: None,
                        decode_error: None,
                    },
                },
            ] {
                sequence += 1;
                insert_source(&source, sequence, event);
            }
        }
        discover(&source, &mut db, sequence).unwrap();
        process_banks(&source, &mut db, &c, sequence).unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM feed_events", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            2
        );
        let path: String = db
            .query_row("SELECT artifact FROM banks WHERE bank=8", [], |r| r.get(0))
            .unwrap();
        let payload_before =
            fs::read(Path::new(&path).join("DIRECT-AGAVE-COMPACT.v1.json")).unwrap();
        // No converter can run from this point onward. Rooting must reuse the bytes.
        let c = ContextData {
            builder: t.path().join("missing-converter"),
            ..c
        };
        insert_source(
            &source,
            7,
            Event::ClearBank {
                slot: 10,
                bank_id: 7,
                parent_slot: 9,
                parent_blockhash: [6; 32],
            },
        );
        insert_source(
            &source,
            8,
            Event::Status {
                slot: 10,
                bank_id: Some(8),
                parent: Some(9),
                status: "rooted".into(),
                dead_error: None,
            },
        );
        discover(&source, &mut db, 8).unwrap();
        process_banks(&source, &mut db, &c, 8).unwrap();
        assert_eq!(
            db.query_row(
                "SELECT group_concat(kind,',') FROM feed_events ORDER BY sequence",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            "block,block,invalidate,root"
        );
        assert_eq!(
            fs::read(Path::new(&path).join("DIRECT-AGAVE-COMPACT.v1.json")).unwrap(),
            payload_before
        );
        if live {
            assert_no_archive(&output, &db, &session);
            assert!(Path::new(&path).starts_with(output.join("live-banks")));
            assert_eq!(
                source
                    .query_row("SELECT count(*) FROM events", [], |r| r.get::<_, u64>(0))
                    .unwrap(),
                8
            );
        } else {
            assert_eq!(
                db.query_row("SELECT bank FROM archive_catalog", [], |r| r
                    .get::<_, u64>(0))
                    .unwrap(),
                8
            );
            // Default mode keeps the old verified custody and retirement path.
            crate::retention::process_one(&session, &mut source, "test").unwrap();
            assert_eq!(
                source
                    .query_row("SELECT count(*) FROM events WHERE bank=8", [], |r| r
                        .get::<_, u64>(0))
                    .unwrap(),
                0
            );
        }
        drop(db);
        let mut db = database_for_role(&output, 0, live).unwrap();
        insert_source(
            &source,
            9,
            Event::Footer {
                slot: 10,
                bank_id: 8,
                wire_footer: vec![1, 2, 3],
            },
        );
        discover(&source, &mut db, 9).unwrap();
        process_banks(&source, &mut db, &c, 9).unwrap();
        assert_eq!(
            db.query_row("SELECT event_sequence FROM feed_state", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            4
        );
        // A changed execution callback after publication fails without a second payload.
        insert_source(
            &source,
            10,
            Event::Entry {
                slot: 10,
                bank_id: 8,
                index: 0,
                num_hashes: 2,
                hash: [8; 32],
                transactions: 0,
                starting_transaction_index: 0,
            },
        );
        discover(&source, &mut db, 10).unwrap();
        assert!(process_banks(&source, &mut db, &c, 10).is_err());
    }
    #[test]
    #[ignore = "requires the real compact writer on Foundation"]
    fn native_v2_early_confirmation_waits_and_restart_reuses_original_payload() {
        early_confirmation_fixture(false, false);
    }
    #[test]
    #[ignore = "requires the real compact writer on Foundation"]
    fn live_only_v2_early_confirmation_waits_and_restart_reuses_original_payload() {
        early_confirmation_fixture(true, false);
    }
    #[test]
    #[ignore = "requires the real compact writer on Foundation"]
    fn continuous_source_gc_late_controls_and_restart_reuse_exact_compact_payload() {
        early_confirmation_fixture(true, true);
    }
    fn early_confirmation_fixture(live: bool, continuous: bool) {
        use crate::event::{BANK_V2, Event, NativeBankState};
        let t = tempfile::tempdir().unwrap();
        let session = t.path().join("source");
        let output = t.path().join("processed");
        let v2out = t.path().join("v2");
        fs::create_dir_all(session.join("retire-pending")).unwrap();
        fs::create_dir(&output).unwrap();
        let source = Connection::open(session.join("events.sqlite")).unwrap();
        source.execute_batch("CREATE TABLE events(sequence INTEGER PRIMARY KEY,slot INTEGER,bank INTEGER,kind TEXT,sha256 TEXT,payload BLOB);CREATE TABLE status(id INTEGER,state TEXT,durable_sequence INTEGER,retired_events INTEGER,latest_rooted_slot INTEGER);INSERT INTO status VALUES(1,'CAPTURING',0,0,0);").unwrap();
        let mut c = ContextData {
            session: session.clone(),
            output: output.clone(),
            builder: PathBuf::from(std::env::var("BLOCKZILLA_BUILDER").unwrap()),
            meta: json!({"config":{"node_identity":"J7qpvCEWhdBgPdYRV3s3btWPrRVXa2qnAzgvxWTvtbrQ"},"processed_custody":false}),
            id: "native-v2-test".into(),
            genesis: "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d".into(),
            codec: "json-v1".into(),
            max_event_bytes: 16 * 1024 * 1024,
            live: live.then(test_live),
        };
        atomic_json(&output.join("FEED.json"),&json!({"schema":"hivezilla-processed-feed-v1","profile":PROFILE,"session_id":c.id,"genesis_hash":c.genesis,"node_identity":c.meta["config"]["node_identity"],"agave_revision":REVISION})).unwrap();
        atomic_json(&output.join("STATUS.json"),&json!({"state":"RUNNING","updated_unix_ms":SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64})).unwrap();
        if continuous {
            let binding = ContinuousBinding {
                options: continuous_options(t.path()),
                producer_generation: "a".repeat(64),
                started_unix_ms: now_ms().unwrap(),
                source: blockzilla_bank_stream_v2::SourceIdentity {
                    session_id: c.id.clone(),
                    genesis_hash: c.genesis.clone(),
                    node_identity: c.meta["config"]["node_identity"].as_str().unwrap().into(),
                    agave_revision: REVISION.into(),
                },
                feed_header_sha256: "b".repeat(64),
            };
            c.live = Some(LiveCanary::for_continuous(binding).unwrap());
        }
        let mut db = if continuous {
            continuous_database(&output).unwrap()
        } else {
            database_for_role(&output, 0, live).unwrap()
        };
        let mut n = 0;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let tuple = |slot, bank, parent, hash, prev, height, confirmed| NativeBankState {
            schema: BANK_V2.into(),
            slot,
            bank_id: bank,
            parent_slot: parent,
            blockhash: [hash; 32],
            parent_blockhash: [prev; 32],
            block_height: height,
            last_valid_block_height: 166,
            observed_at_unix_ms: now,
            confirmed,
        };
        let status = |slot, bank, parent, status: &str| Event::BankStatusV2 {
            schema: BANK_V2.into(),
            slot,
            bank_id: Some(bank),
            parent: Some(parent),
            parent_blockhash: None,
            status: status.into(),
            dead_error: None,
            observed_at_unix_ms: now,
        };
        let entry = |slot, bank, hash| Event::Entry {
            slot,
            bank_id: bank,
            index: 0,
            num_hashes: 1,
            hash: [hash; 32],
            transactions: 0,
            starting_transaction_index: 0,
        };
        let block = |slot, bank, parent, hash, prev, height| Event::Block {
            slot,
            bank_id: bank,
            parent_slot: parent,
            parent_blockhash: [prev; 32],
            blockhash: [hash; 32],
            transactions: 0,
            entries: 1,
            block_time: None,
            block_height: Some(height),
            native_rewards: json!({"rewards":[]}),
            rewards: blockzilla_archive_v2::WincodeArchiveV2NoRegistryRewards {
                source_len: 0,
                num_partitions: None,
                decoded: Some(vec![]),
                raw_fallback: None,
                decode_error: None,
            },
        };
        for e in [
            Event::BankStateV2(tuple(10, 7, 9, 7, 6, 15, false)),
            status(10, 7, 9, "processed"),
            entry(10, 7, 7),
            block(10, 7, 9, 7, 6, 15),
            status(10, 7, 9, "rooted"),
        ] {
            n += 1;
            insert_source(&source, n, e);
        }
        discover_for_role(
            &source,
            &mut db,
            n,
            if continuous { c.live.as_ref() } else { None },
        )
        .unwrap();
        process_banks(&source, &mut db, &c, n).unwrap();
        if continuous {
            source.execute("DELETE FROM events", []).unwrap();
        }
        crate::confirmed::run(&output, &v2out, false).unwrap();
        let a = Connection::open(v2out.join("feed.sqlite")).unwrap();
        assert_eq!(
            a.query_row("SELECT event_sequence FROM feed_state", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            2
        );
        drop(a);
        // Native confirmation is durable while the complete-bank gate waits.
        for e in [
            Event::BankStateV2(tuple(17, 8, 10, 8, 7, 16, false)),
            Event::BankStateV2(tuple(17, 8, 10, 8, 7, 16, true)),
            status(17, 8, 10, "processed"),
        ] {
            n += 1;
            insert_source(&source, n, e);
        }
        discover_for_role(
            &source,
            &mut db,
            n,
            if continuous { c.live.as_ref() } else { None },
        )
        .unwrap();
        process_banks(&source, &mut db, &c, n).unwrap();
        if continuous {
            source.execute("DELETE FROM events", []).unwrap();
        }
        crate::confirmed::run(&output, &v2out, false).unwrap();
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM bank_observations WHERE confirmed_json IS NOT NULL",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
            1
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM feed_events", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            2
        );
        for e in [entry(17, 8, 8), block(17, 8, 10, 8, 7, 16)] {
            n += 1;
            insert_source(&source, n, e);
        }
        discover_for_role(
            &source,
            &mut db,
            n,
            if continuous { c.live.as_ref() } else { None },
        )
        .unwrap();
        process_banks(&source, &mut db, &c, n).unwrap();
        if continuous {
            source.execute("DELETE FROM events", []).unwrap();
        }
        crate::confirmed::run(&output, &v2out, false).unwrap();
        let a = Connection::open(v2out.join("feed.sqlite")).unwrap();
        let events: Vec<String> = a
            .prepare("SELECT event_json FROM feed_events ORDER BY sequence")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(events.len(), 4);
        let full: blockzilla_bank_stream_v2::BankEvent = serde_json::from_str(&events[2]).unwrap();
        let confirm: blockzilla_bank_stream_v2::BankEvent =
            serde_json::from_str(&events[3]).unwrap();
        assert_eq!(confirm.kind, "confirmed");
        assert_eq!(confirm.bank, full.bank);
        assert_eq!(
            confirm.recent_blockhash.unwrap().last_valid_block_height,
            166
        );
        let frames: Vec<String> = a
            .prepare("SELECT frame_sha256 FROM feed_events ORDER BY sequence")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        drop(a);
        // Simulate a crash after block/control commit but before its input position.
        let a = Connection::open(v2out.join("feed.sqlite")).unwrap();
        a.execute("UPDATE feed_state SET processed_sequence=2", [])
            .unwrap();
        drop(a);
        crate::confirmed::run(&output, &v2out, false).unwrap();
        let a = Connection::open(v2out.join("feed.sqlite")).unwrap();
        let again: Vec<String> = a
            .prepare("SELECT frame_sha256 FROM feed_events ORDER BY sequence")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(again, frames);
        if live {
            assert_no_archive(&output, &db, &session);
        }
    }
    #[test]
    fn same_slot_banks_and_controls_have_distinct_durable_positions() {
        let tmp = tempfile::tempdir().unwrap();
        let mut db = database(tmp.path(), 0).unwrap();
        db_bank(&db, 10, 7, 1, "status").unwrap();
        db_bank(&db, 10, 8, 2, "status").unwrap();
        let bank = |n| json!({"slot":10,"bank_id":n,"blockhash":vec![0;32],"parent_slot":9,"parent_blockhash":vec![0;32]});
        let tx = db.transaction().unwrap();
        assert_eq!(
            append_event(&tx, "block", 3, &bank(7), "abc", "a", None).unwrap(),
            1
        );
        assert_eq!(
            append_event(&tx, "block", 4, &bank(8), "def", "b", None).unwrap(),
            2
        );
        assert_eq!(
            append_event(&tx, "invalidate", 5, &bank(7), "abc", "a", Some("clear")).unwrap(),
            3
        );
        assert_eq!(
            append_event(&tx, "root", 6, &bank(8), "def", "b", None).unwrap(),
            4
        );
        tx.commit().unwrap();
        drop(db);
        let db = database(tmp.path(), 0).unwrap();
        assert_eq!(
            db.query_row("SELECT event_sequence FROM feed_state", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            4
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM banks", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            2
        );
    }
    #[test]
    fn control_and_position_commit_together() {
        let tmp = tempfile::tempdir().unwrap();
        let mut db = database(tmp.path(), 0).unwrap();
        {
            let tx = db.transaction().unwrap();
            append_event(
                &tx,
                "invalidate",
                2,
                &json!({"slot":10,"bank_id":7}),
                "abc",
                "a",
                None,
            )
            .unwrap();
        }
        assert_eq!(
            db.query_row("SELECT event_sequence FROM feed_state", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM feed_events", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            0
        );
    }
}
