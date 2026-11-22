//! Direct native request work, with elapsed and per-thread CPU measurements.
use anyhow::{Context, Result, ensure};
use axum::body::Bytes;
use blockzilla_archive_v2::deserialize_archive_v2_hot_block_blob;
use blockzilla_get_block::{
    foundation_protocol::{PendingLocatorV1, ResolveRequestV1},
    slot_references,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::Instant;
use subtle::ConstantTimeEq;

pub const HOT_REQUEST_TYPE: &str = "application/vnd.blockzilla.compact-v2-hot.zstd";
pub const MAX_HOT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct Stage {
    pub wall_ns: u64,
    pub cpu_ns: u64,
}

#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct Profile {
    pub request_sha: Stage,
    pub decompress: Stage,
    pub hot_decode: Stage,
    pub collect: Stage,
    pub table_resolve: Stage,
    pub encode: Stage,
    pub total: Stage,
}

pub struct Clock {
    wall: Instant,
    cpu_ns: u64,
}

fn thread_cpu_ns() -> Result<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes one initialized timespec; the pointer is
    // valid, and the selected clock measures only the calling native thread.
    let status = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut time) };
    ensure!(
        status == 0 && time.tv_sec >= 0 && (0..1_000_000_000).contains(&time.tv_nsec),
        "native thread CPU clock is unavailable"
    );
    u64::try_from(time.tv_sec)?
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(time.tv_nsec as u64))
        .context("thread CPU time overflows")
}

impl Clock {
    pub fn start() -> Result<Self> {
        Ok(Self {
            wall: Instant::now(),
            cpu_ns: thread_cpu_ns()?,
        })
    }
    pub fn finish(self) -> Result<Stage> {
        Ok(Stage {
            wall_ns: u64::try_from(self.wall.elapsed().as_nanos())?,
            cpu_ns: thread_cpu_ns()?
                .checked_sub(self.cpu_ns)
                .context("thread CPU clock moved backwards")?,
        })
    }
}

/// SHA verification and body ownership form one value, so raw collection does
/// not hash the same frame again or accept an unchecked request digest.
pub struct VerifiedBody {
    bytes: Bytes,
    sha256: String,
    profile: Stage,
}

impl VerifiedBody {
    pub fn new(bytes: Bytes, expected: Option<&str>) -> Result<Self> {
        let clock = Clock::start()?;
        let sha256 = hex::encode(Sha256::digest(&bytes));
        if let Some(expected) = expected {
            ensure!(
                expected.len() == 64
                    && expected
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "request SHA256 is not canonical"
            );
            ensure!(
                bool::from(sha256.as_bytes().ct_eq(expected.as_bytes())),
                "request SHA256 differs"
            );
        }
        Ok(Self {
            bytes,
            sha256,
            profile: clock.finish()?,
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn profile(&self) -> Stage {
        self.profile
    }
}

pub fn collect_hot(
    source: PendingLocatorV1,
    body: &VerifiedBody,
) -> Result<(ResolveRequestV1, Profile)> {
    source
        .validate(&source.source_prefix, &source.generation, source.hot.slot)
        .map_err(anyhow::Error::msg)?;
    ensure!(
        body.bytes().len() == source.hot.compressed_len as usize
            && body.bytes().len() <= MAX_HOT_BYTES,
        "compressed hot body length differs from pinned source row"
    );
    let mut profile = Profile {
        request_sha: body.profile(),
        ..Profile::default()
    };
    let clock = Clock::start()?;
    let decoded = zstd::bulk::decompress(body.bytes(), source.hot.uncompressed_len as usize)
        .context("decode bounded compressed hot frame")?;
    ensure!(
        decoded.len() == source.hot.uncompressed_len as usize,
        "decompressed hot length differs from pinned source row"
    );
    profile.decompress = clock.finish()?;
    let clock = Clock::start()?;
    let block = deserialize_archive_v2_hot_block_blob(&decoded)
        .context("decode complete stored hot block")?;
    profile.hot_decode = clock.finish()?;
    let clock = Clock::start()?;
    let references = slot_references::collect(
        &block,
        &source.hot.into(),
        source.message_schema,
        source.metadata_schema,
    )
    .map_err(anyhow::Error::msg)
    .context("collect all typed references without raw fallback omission")?;
    profile.collect = clock.finish()?;
    let request = ResolveRequestV1 {
        version: 1,
        source,
        hot_sha256: body.sha256().into(),
        references,
    };
    request
        .validate(
            &request.source.source_prefix,
            &request.source.generation,
            request.references.slot,
        )
        .map_err(anyhow::Error::msg)?;
    Ok((request, profile))
}
