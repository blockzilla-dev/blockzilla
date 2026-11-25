//! Bounded read-only ledger helper. Original compact bytes stay in RAM; the
//! Worker owns JSON rendering. This path asserts no stream cursor or R2 ID.
use anyhow::{Context, Result, ensure};
use axum::body::Bytes;
use blockzilla_bank_stream_v2 as v2;
use blockzilla_get_block::slot_resolution::ResolutionHotRow;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{ErrorKind, Read},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

pub const CONTENT_TYPE: &str = "application/vnd.blockzilla.get-block-bundle.wincode";
pub const MAX_BUNDLE: usize = 16 * 1024 * 1024;
const MAX_META: usize = 4096;
const MAX_STDERR: usize = 16384;
const MAX_STDOUT: usize = 12 + MAX_META + MAX_BUNDLE;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub helper: PathBuf,
    pub helper_sha256: String,
    pub ledger: PathBuf,
    pub minimum_slot: u64,
    pub max_wall_ms: u64,
    pub generation: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub version: u16,
    pub slot: u64,
    pub parent_slot: u64,
    pub blockhash: String,
    pub previous_blockhash: String,
    pub tx_count: u32,
    pub hot: ResolutionHotRow,
    pub sha256: String,
    pub length: u64,
    pub message_schema: u8,
    pub metadata_schema: u8,
    pub rooted: bool,
    pub metadata_complete: bool,
}

pub struct Block {
    pub body: Bytes,
    pub metadata: Metadata,
    pub metadata_bytes: Bytes,
    pub generation: String,
}

#[derive(Clone, PartialEq, Eq)]
struct Stamp(u64, u64, u64, i64, i64, i64, i64);
fn stamp(path: &Path) -> Result<Stamp> {
    let m = std::fs::symlink_metadata(path)?;
    ensure!(
        m.is_file() && m.mode() & 0o022 == 0 && path.canonicalize()? == path,
        "ledger_helper_changed"
    );
    Ok(Stamp(
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    ))
}

pub struct Client {
    config: Config,
    helper: Stamp,
    ledger: (u64, u64),
    helper_permit: Mutex<()>,
}
impl Client {
    pub fn new(config: Config) -> Result<Self> {
        ensure!(
            config.helper.is_absolute()
                && config.ledger.is_absolute()
                && v2::is_digest(&config.helper_sha256)
                && config.minimum_slot <= v2::SAFE
                && (1..=10000).contains(&config.max_wall_ms),
            "invalid_ledger_config"
        );
        ensure!(
            !config.generation.is_empty()
                && config.generation.len() <= 128
                && config
                    .generation
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
            "invalid_ledger_generation"
        );
        let helper = stamp(&config.helper)?;
        let mut file = File::open(&config.helper)?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
        }
        ensure!(
            hex::encode(hash.finalize()) == config.helper_sha256
                && stamp(&config.helper)? == helper,
            "ledger_helper_digest_changed"
        );
        let m = std::fs::symlink_metadata(&config.ledger)?;
        ensure!(
            m.is_dir() && config.ledger.canonicalize()? == config.ledger,
            "invalid_ledger_directory"
        );
        Ok(Self {
            config,
            helper,
            ledger: (m.dev(), m.ino()),
            helper_permit: Mutex::new(()),
        })
    }

    pub fn read(&self, slot: u64) -> Result<Option<Block>> {
        ensure!(slot <= v2::SAFE, "invalid_request");
        if slot < self.config.minimum_slot {
            return Ok(None);
        }
        // Separate from the HTTP permit pool: only one heavy Blockstore
        // helper may run. This guard outlives child kill/wait on every path.
        let _helper_permit = self
            .helper_permit
            .try_lock()
            .map_err(|_| anyhow::anyhow!("ledger_compact_unavailable"))?;
        ensure!(
            stamp(&self.config.helper)? == self.helper,
            "ledger_helper_changed"
        );
        let directory = std::fs::symlink_metadata(&self.config.ledger)?;
        ensure!(
            directory.is_dir()
                && self.config.ledger.canonicalize()? == self.config.ledger
                && (directory.dev(), directory.ino()) == self.ledger,
            "ledger_directory_changed"
        );
        let executable = File::open(&self.config.helper)?;
        let opened = executable.metadata()?;
        ensure!(
            (opened.dev(), opened.ino(), opened.len())
                == (self.helper.0, self.helper.1, self.helper.2),
            "ledger_helper_changed"
        );
        #[cfg(target_os = "linux")]
        let mut command = Command::new(format!("/proc/self/fd/{}", executable.as_raw_fd()));
        #[cfg(not(target_os = "linux"))]
        let mut command = Command::new(&self.config.helper);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::CommandExt;
            let fd = executable.as_raw_fd();
            // The child executes the pinned inode, even if the path is replaced.
            // fcntl is async-signal-safe; no allocation runs after fork.
            unsafe {
                command.pre_exec(move || {
                    if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                });
            }
        }
        command
            .arg("read-slot-compact")
            .arg("--ledger")
            .arg(&self.config.ledger)
            .arg("--slot")
            .arg(slot.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let deadline = Instant::now() + Duration::from_millis(self.config.max_wall_ms);
        let mut child = Reap(Some(command.spawn().context("ledger_helper_spawn_failed")?));
        let process = child.0.as_mut().expect("new helper");
        let mut stdout = process.stdout.take().context("ledger_stdout_missing")?;
        let mut stderr = process.stderr.take().context("ledger_stderr_missing")?;
        nonblocking(stdout.as_raw_fd())?;
        nonblocking(stderr.as_raw_fd())?;
        let (mut output, mut errors) = (Vec::with_capacity(65536), Vec::new());
        let (mut out_done, mut err_done) = (false, false);
        let status = loop {
            drain(&mut stdout, &mut output, &mut out_done, MAX_STDOUT)?;
            drain(&mut stderr, &mut errors, &mut err_done, MAX_STDERR)?;
            if output.len() >= 12 {
                ensure!(
                    &output[..8] == b"BZLGR01!"
                        && u32::from_le_bytes(output[8..12].try_into()?) as usize <= MAX_META,
                    "ledger_helper_frame_invalid"
                );
            }
            ensure!(Instant::now() < deadline, "ledger_compact_timeout");
            if let Some(status) = process.try_wait()? {
                if out_done && err_done {
                    break status;
                }
            }
            thread::sleep(Duration::from_millis(2));
        };
        child.0.take().expect("completed helper").wait()?;
        ensure!(
            stamp(&self.config.helper)? == self.helper,
            "ledger_helper_changed"
        );
        match status.code() {
            Some(0) => parse(Bytes::from(output), slot, self.config.generation.clone()).map(Some),
            Some(3) if output.is_empty() => Ok(None),
            Some(4) if output.is_empty() => anyhow::bail!("ledger_not_rooted"),
            _ => anyhow::bail!("ledger_compact_unavailable"),
        }
    }
}

struct Reap(Option<Child>);
impl Drop for Reap {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
fn nonblocking(fd: i32) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    ensure!(
        flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0,
        "ledger_pipe_setup_failed"
    );
    Ok(())
}
fn drain(
    reader: &mut impl Read,
    bytes: &mut Vec<u8>,
    done: &mut bool,
    maximum: usize,
) -> Result<()> {
    if *done {
        return Ok(());
    }
    let mut buffer = [0u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => {
                *done = true;
                return Ok(());
            }
            Ok(n) => {
                ensure!(
                    bytes.len() + n <= maximum,
                    "ledger_helper_output_exceeds_bound"
                );
                bytes.extend_from_slice(&buffer[..n]);
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

fn parse(output: Bytes, slot: u64, generation: String) -> Result<Block> {
    ensure!(
        output.len() >= 12 && &output[..8] == b"BZLGR01!",
        "ledger_helper_frame_invalid"
    );
    let n = u32::from_le_bytes(output[8..12].try_into()?) as usize;
    ensure!(
        (1..=MAX_META).contains(&n) && output.len() >= 12 + n,
        "ledger_helper_metadata_invalid"
    );
    let metadata: Metadata = serde_json::from_slice(&output[12..12 + n])?;
    let body = output.slice(12 + n..);
    let row = &metadata.hot;
    ensure!(
        metadata.version == 1
            && metadata.slot == slot
            && metadata.rooted
            && metadata.metadata_complete
            && metadata.message_schema == 0
            && metadata.metadata_schema == 0
            && metadata.tx_count == row.tx_count
            && metadata.tx_count <= 65536
            && row.slot == slot
            && row.block_id == 1
            && row.compressed_offset == 0
            && row.first_tx_ordinal == 0
            && row.first_signature_ordinal == 0
            && row.compressed_len > 0
            && row.compressed_len as usize <= MAX_BUNDLE
            && (1..=32 * 1024 * 1024).contains(&row.uncompressed_len)
            && row.signature_count <= 131072,
        "ledger_metadata_identity_invalid"
    );
    ensure!(
        (slot == 0 && metadata.parent_slot == 0) || metadata.parent_slot < slot,
        "ledger_parent_invalid"
    );
    ensure!(
        v2::hash(&metadata.blockhash)? != [0; 32]
            && (slot == 0 || v2::hash(&metadata.previous_blockhash)? != [0; 32]),
        "ledger_hash_invalid"
    );
    ensure!(
        !body.is_empty()
            && body.len() <= MAX_BUNDLE
            && metadata.length == body.len() as u64
            && v2::is_digest(&metadata.sha256)
            && hex::encode(Sha256::digest(&body)) == metadata.sha256,
        "ledger_bundle_digest_invalid"
    );
    bundle(&body, slot, row.compressed_len as usize)?;
    Ok(Block {
        body,
        metadata,
        metadata_bytes: output.slice(12..12 + n),
        generation,
    })
}

// Borrow the existing V1 Zstd/Wincode envelope, as in the Worker bundle reader.
fn bundle(mut input: &[u8], slot: u64, compressed: usize) -> Result<()> {
    ensure!(
        unsigned(&mut input)? == 1 && unsigned(&mut input)? == slot && byte(&mut input)? == 1,
        "ledger_bundle_identity_invalid"
    );
    ensure!(
        vector(&mut input)?.len() == compressed && byte(&mut input)? == 0 && byte(&mut input)? == 1,
        "ledger_bundle_access_invalid"
    );
    ensure!(
        !vector(&mut input)?.is_empty() && input.is_empty(),
        "ledger_bundle_trailing_or_missing_data"
    );
    Ok(())
}
fn byte(input: &mut &[u8]) -> Result<u8> {
    let (&value, rest) = input.split_first().context("truncated_ledger_bundle")?;
    *input = rest;
    Ok(value)
}
fn unsigned(input: &mut &[u8]) -> Result<u64> {
    let mut result = 0;
    for index in 0..10 {
        let value = byte(input)?;
        ensure!(index != 9 || value <= 1, "ledger_bundle_integer_overflow");
        result |= u64::from(value & 127) << (index * 7);
        if value & 128 == 0 {
            ensure!(
                index == 0 || value != 0,
                "ledger_bundle_noncanonical_integer"
            );
            return Ok(result);
        }
    }
    anyhow::bail!("ledger_bundle_integer_overflow")
}
fn vector<'a>(input: &mut &'a [u8]) -> Result<&'a [u8]> {
    let n = usize::try_from(unsigned(input)?)?;
    ensure!(
        n <= MAX_BUNDLE && n <= input.len(),
        "ledger_bundle_vector_invalid"
    );
    let (value, rest) = input.split_at(n);
    *input = rest;
    Ok(value)
}

#[cfg(test)]
#[path = "ledger_compact_tests.rs"]
pub(crate) mod tests;
