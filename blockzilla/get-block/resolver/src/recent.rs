//! Read-only access to the producer's existing retained frames. No spool,
//! projection, payload copy on disk, per-block index or result cache is created.
use anyhow::{Context, Result, ensure};
use blockzilla_bank_stream_v2::{self as v2, Frame, SourceIdentity};
use hivezilla_stream::bank_source::BankSource;
use rusqlite::{Connection, OpenFlags};
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
    #[serde(default)]
    pub native_archive_catalog: Option<PathBuf>,
    #[serde(default)]
    pub ledger_compact: Option<crate::ledger_compact::Config>,
}

pub struct RecentClient {
    config: RecentConfig,
    ledger: Option<crate::ledger_compact::Client>,
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

pub struct FinalizedBlock {
    pub frame: Frame,
    pub metadata: RecentMetadata,
    /// Exact original small control frame. The block payload is not repeated.
    pub root: Frame,
}

#[derive(Debug)]
pub(crate) struct FinalizedFeedUnavailable;

impl std::fmt::Display for FinalizedFeedUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("recent_source_failed")
    }
}

impl std::error::Error for FinalizedFeedUnavailable {}

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
        let ledger = config
            .ledger_compact
            .clone()
            .map(crate::ledger_compact::Client::new)
            .transpose()?;
        let client = Self { config, ledger };
        ensure!(
            client.open_checked()?.is_some() || client.ledger.is_some(),
            "recent_source_failed"
        );
        Ok(client)
    }

    pub fn source(&self) -> &SourceIdentity {
        &self.config.source
    }

    pub fn producer_generation(&self) -> &str {
        &self.config.producer_generation
    }

    pub fn native_archive(
        &self,
        slot: u64,
    ) -> Result<Option<crate::native_archive::NativeArchiveV1>> {
        self.config
            .native_archive_catalog
            .as_deref()
            .map_or(Ok(None), |path| {
                crate::native_archive::read(
                    path,
                    &self.config.source,
                    &self.config.producer_generation,
                    slot,
                )
            })
    }

    pub fn ledger_compact(&self, slot: u64) -> Result<Option<crate::ledger_compact::Block>> {
        self.ledger
            .as_ref()
            .map_or(Ok(None), |client| client.read(slot))
    }

    /// Select only a unique locally rooted bank. The caller does not need to
    /// know its hash. A failed feed at initial open can use an independent
    /// source. Invalid custody or a retirement race remains terminal.
    pub fn read_finalized_by_slot(&self, slot: u64) -> Result<Option<FinalizedBlock>> {
        ensure!(slot <= v2::SAFE, "invalid_request");
        let source = self.open_checked()?.ok_or(FinalizedFeedUnavailable)?;
        let db = Connection::open_with_flags(
            self.config.bank_source_root.join("feed.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        db.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF; BEGIN;")?;
        let mut query = db.prepare(
            "SELECT bank,payload_event,frame_sha256 FROM banks
             WHERE slot=?1 AND state='rooted' LIMIT 2",
        )?;
        let mut rows = query.query([slot])?;
        let Some(row) = rows.next()? else {
            drop(rows);
            drop(query);
            let present: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM banks WHERE slot=?1)",
                [slot],
                |row| row.get(0),
            )?;
            ensure!(!present, "finalized_not_rooted");
            // Recheck the source descriptors even when no bank was selected.
            self.open()?;
            return Ok(None);
        };
        let bank: u64 = row.get(0)?;
        let event: v2::BankEvent = serde_json::from_str(&row.get::<_, String>(1)?)?;
        let frame_sha: String = row.get(2)?;
        ensure!(rows.next()?.is_none(), "ambiguous_rooted_bank");
        event.validate()?;
        ensure!(
            event.kind == "block" && event.bank.key() == (slot, bank) && v2::is_digest(&frame_sha),
            "finalized_bank_identity_changed"
        );
        drop(rows);
        drop(query);
        let mut query = db.prepare(
            "SELECT r.frame_sha256 FROM feed_events r JOIN banks b ON r.artifact=b.artifact
             WHERE b.slot=?1 AND b.bank=?2 AND b.state='rooted'
               AND json_extract(r.event_json,'$.kind')='root' LIMIT 2",
        )?;
        let mut rows = query.query(rusqlite::params![slot, bank])?;
        let row = rows.next()?.context("finalized_root_unavailable")?;
        let root_sha: String = row.get(0)?;
        ensure!(rows.next()?.is_none(), "ambiguous_root_commit");
        drop(rows);
        drop(query);
        drop(db);
        let request = RecentRequest {
            blockhash: encode_hash(&event.bank.blockhash),
            commitment: "finalized".into(),
            cursor: None,
            bank_id: Some(bank),
            source_session: Some(self.config.source.session_id.clone()),
        };
        let RecentOutcome::Hit { frame, metadata } = self.read(slot, &request)? else {
            anyhow::bail!("finalized_frame_disappeared");
        };
        ensure!(
            frame.sha256 == frame_sha && frame.envelope.event == event,
            "finalized_bank_identity_changed"
        );
        let root = source
            .retained_chunk(&root_sha)?
            .context("finalized_root_unavailable")?;
        ensure!(
            root.source == frame.source && root.envelope.event.kind == "root",
            "finalized_root_identity_changed"
        );
        root.envelope.event.matches_payload(&frame)?;
        ensure!(root.wire.len() <= 4096, "finalized_root_too_large");
        source.require_retained(&root)?;
        // Source generation changes and retirement during this read fail closed.
        self.open()?.require_retained(&root)?;
        Ok(Some(FinalizedBlock {
            frame,
            metadata,
            root,
        }))
    }

    fn open(&self) -> Result<BankSource> {
        self.open_checked()?.context("recent_source_failed")
    }

    // None means that the checked source reported failed health. All source
    // identity, authority, and integrity checks must pass before that result.
    fn open_checked(&self) -> Result<Option<BankSource>> {
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
        Ok((source.health()? != "failed").then_some(source))
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
