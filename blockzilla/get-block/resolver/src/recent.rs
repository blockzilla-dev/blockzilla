//! Read-only access to the producer's existing retained frames. No spool,
//! projection, payload copy on disk, per-block index or result cache is created.
use anyhow::{Context, Result, ensure};
use blockzilla_bank_stream_v2::{self as v2, Frame, SourceIdentity};
use hivezilla_stream::bank_source::BankSource;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

pub const CONTENT_TYPE: &str = "application/vnd.blockzilla.stream.v2";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecentConfig {
    pub bank_source_root: PathBuf,
    pub payload_root: PathBuf,
    pub source: SourceIdentity,
    pub producer_generation: String,
}

pub struct RecentClient {
    config: RecentConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecentRequest {
    pub blockhash: String,
    pub commitment: String,
    pub cursor: Option<String>,
    pub bank_id: Option<u64>,
    pub source_session: Option<String>,
}

impl RecentRequest {
    pub fn validate(&self, slot: u64, source: &SourceIdentity) -> Result<[u8; 32]> {
        ensure!(slot <= v2::SAFE, "invalid_request");
        let hash = v2::hash(&self.blockhash).context("invalid_request")?;
        ensure!(
            matches!(self.commitment.as_str(), "processed" | "finalized"),
            "invalid_request"
        );
        ensure!(
            self.bank_id.is_none_or(|id| id <= v2::SAFE),
            "invalid_request"
        );
        if let Some(session) = &self.source_session {
            ensure!(session == &source.session_id, "source_changed");
        }
        if let Some(cursor) = &self.cursor {
            let (session, sequence, sha) = v2::parse_cursor(cursor).context("invalid_request")?;
            ensure!(session == source.session_id, "source_changed");
            ensure!(sequence > 0 && v2::is_digest(sha), "invalid_request");
        }
        if self.commitment == "processed" {
            ensure!(
                self.cursor.is_some() && self.bank_id.is_some() && self.source_session.is_some(),
                "invalid_request"
            );
        }
        Ok(hash)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecentMetadata {
    pub version: u16,
    pub slot: u64,
    pub blockhash: String,
    pub parent_slot: u64,
    pub parent_blockhash: String,
    pub bank_id: u64,
    pub source: SourceIdentity,
    pub cursor: String,
    pub frame_sha256: String,
    pub commitment: String,
}

pub enum RecentOutcome {
    Hit {
        frame: Frame,
        metadata: RecentMetadata,
    },
    Miss,
    Expired,
}

fn bounded_json(path: &Path) -> Result<serde_json::Value> {
    ensure!(
        std::fs::symlink_metadata(path)?.file_type().is_file(),
        "recent_descriptor_not_a_regular_file"
    );
    let mut raw = Vec::new();
    File::open(path)?.take(65_537).read_to_end(&mut raw)?;
    ensure!(raw.len() <= 65_536, "recent_source_descriptor_too_large");
    Ok(serde_json::from_slice(&raw)?)
}

impl RecentClient {
    pub fn load(path: &Path) -> Result<Self> {
        let config: RecentConfig = serde_json::from_value(bounded_json(path)?)?;
        Self::new(config)
    }

    pub fn new(config: RecentConfig) -> Result<Self> {
        config.source.validate()?;
        ensure!(
            v2::is_digest(&config.producer_generation),
            "invalid_recent_producer_generation"
        );
        for path in [&config.bank_source_root, &config.payload_root] {
            ensure!(
                path.is_absolute()
                    && std::fs::symlink_metadata(path)?.is_dir()
                    && path.canonicalize()? == *path,
                "recent_source_requires_real_absolute_directory"
            );
        }
        let client = Self { config };
        client.open()?;
        Ok(client)
    }

    pub fn source(&self) -> &SourceIdentity {
        &self.config.source
    }

    fn open(&self) -> Result<BankSource> {
        for path in [&self.config.bank_source_root, &self.config.payload_root] {
            ensure!(
                std::fs::symlink_metadata(path)?.is_dir() && path.canonicalize()? == *path,
                "recent_source_directory_changed"
            );
        }
        // BankSource opens feed.sqlite with SQLITE_OPEN_READ_ONLY and sets
        // query_only. Its frame builder verifies the original object hashes.
        let source = BankSource::open(&self.config.bank_source_root)?;
        ensure!(source.source == self.config.source, "recent_source_changed");
        let feed = bounded_json(&self.config.bank_source_root.join("FEED.json"))?;
        ensure!(
            feed["producer_generation"].as_str() == Some(self.config.producer_generation.as_str()),
            "recent_generation_changed"
        );
        ensure!(
            feed["payload_root"].as_str() == self.config.payload_root.to_str(),
            "recent_payload_root_changed"
        );
        let payload = bounded_json(&self.config.payload_root.join("FEED.json"))?;
        ensure!(
            SourceIdentity::from_marker(&payload)? == self.config.source
                && payload["producer_generation"].as_str()
                    == Some(self.config.producer_generation.as_str()),
            "recent_payload_source_changed"
        );
        source.validate_beam_authority()?;
        ensure!(source.health()? != "failed", "recent_source_failed");
        Ok(source)
    }

    /// All work is request-local and synchronous; the HTTP handler runs this
    /// in a bounded blocking task. Every call reopens the existing read-only DB.
    pub fn read(&self, slot: u64, request: &RecentRequest) -> Result<RecentOutcome> {
        let expected_hash = request.validate(slot, &self.config.source)?;
        let source = self.open()?;
        let frame = if request.commitment == "finalized" {
            source.retained_finalized_block(slot, &expected_hash)?
        } else {
            let sha = v2::parse_cursor(request.cursor.as_deref().expect("checked cursor"))?.2;
            source.retained_chunk(sha)?
        };
        let Some(frame) = frame else {
            return Ok(if request.commitment == "finalized" {
                RecentOutcome::Miss
            } else {
                RecentOutcome::Expired
            });
        };
        let event = &frame.envelope.event;
        ensure!(
            frame.source == self.config.source
                && event.kind == "block"
                && event.bank.slot == slot
                && event.bank.blockhash == expected_hash
                && request.bank_id.is_none_or(|id| id == event.bank.bank_id)
                && request
                    .cursor
                    .as_deref()
                    .is_none_or(|cursor| cursor == frame.cursor),
            "recent_frame_identity_changed"
        );
        // Recheck source authority after the frame read. Retirement races and
        // descriptor changes are errors, never a signal to guess an R2 route.
        source.validate_beam_authority()?;
        let metadata = RecentMetadata {
            version: 1,
            slot,
            blockhash: request.blockhash.clone(),
            parent_slot: event.bank.parent_slot,
            parent_blockhash: encode_hash(&event.bank.parent_blockhash),
            bank_id: event.bank.bank_id,
            source: frame.source.clone(),
            cursor: frame.cursor.clone(),
            frame_sha256: frame.sha256.clone(),
            commitment: request.commitment.clone(),
        };
        Ok(RecentOutcome::Hit { frame, metadata })
    }
}

pub fn encode_hash(hash: &[u8; 32]) -> String {
    // Base58 is native identity metadata only. The block stays Compact V2.
    bs58::encode(hash).into_string()
}

#[cfg(test)]
#[path = "recent_tests.rs"]
pub(crate) mod tests;
