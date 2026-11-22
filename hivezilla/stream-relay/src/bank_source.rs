use crate::source::bounded_file;
use anyhow::{Context, Result, ensure};
use blockzilla_bank_stream_v2::{self as v2, BankEvent, Frame, SourceIdentity, artifact};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde_json::Value;
use std::io;
use std::path::{Path, PathBuf};
pub struct BankSource {
    root: PathBuf,
    payload_root: PathBuf,
    db: Connection,
    pub source: SourceIdentity,
    pub position: u64,
    producer_generation: Option<String>,
}
impl BankSource {
    pub fn open(root: &Path) -> Result<Self> {
        let root = root.canonicalize()?;
        let h: Value = serde_json::from_slice(&bounded_file(&root.join("FEED.json"), 65536)?)?;
        ensure!(
            h["schema"] == "hivezilla-bank-feed-v2" && h["profile"] == v2::PROFILE,
            "unsupported_bank_source"
        );
        let source = SourceIdentity::from_marker(&h)?;
        let payload_root =
            PathBuf::from(h["payload_root"].as_str().context("missing_payload_root")?)
                .canonicalize()?;
        let db = open_feed(&root)?;
        let producer_generation = h
            .get("producer_generation")
            .map(|v| {
                v.as_str()
                    .context("invalid_producer_generation")
                    .map(str::to_owned)
            })
            .transpose()?;
        ensure!(
            producer_generation.as_deref().is_none_or(v2::is_digest),
            "invalid_producer_generation"
        );
        Ok(Self {
            root,
            payload_root,
            db,
            source,
            position: 0,
            producer_generation,
        })
    }
    pub fn seek(&mut self, cursor: &str) -> Result<()> {
        let (session, sequence, sha) = v2::parse_cursor(cursor)?;
        ensure!(session == self.source.session_id, "source_changed");
        let (base, base_sha) = self.floor()?;
        ensure!(sequence >= base, "replay_unavailable");
        if sequence == base {
            ensure!(sha == base_sha, "invalid_cursor");
        } else if sequence > 0 {
            let actual: Option<String> = self
                .db
                .query_row(
                    "SELECT frame_sha256 FROM feed_events WHERE sequence=?1",
                    [sequence],
                    |r| r.get(0),
                )
                .optional()?;
            ensure!(actual.as_deref() == Some(sha), "invalid_cursor");
        } else {
            ensure!(sha == "-", "invalid_cursor");
        }
        self.position = sequence;
        Ok(())
    }
    fn build(&self, row: (String, String, String)) -> Result<Frame> {
        let (path, event, sha) = row;
        self.committed_frame(&path, serde_json::from_str(&event)?, &sha)
    }
    fn committed_frame(&self, path: &str, event: BankEvent, sha: &str) -> Result<Frame> {
        let frame = artifact::build(&self.payload_root, Path::new(path), &self.source, event)?;
        ensure!(frame.sha256 == sha, "frame_commit_changed");
        Ok(frame)
    }
    pub fn next(&mut self) -> Result<Option<Frame>> {
        for attempt in 0..=5 {
            match self.next_once() {
                Err(e) if attempt < 5 && retryable(&e) => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    self.db = open_feed(&self.root)?;
                }
                result => return result,
            }
        }
        unreachable!()
    }
    fn next_once(&mut self) -> Result<Option<Frame>> {
        ensure!(self.position >= self.floor()?.0, "replay_unavailable");
        let row:Option<(u64,String,String,String)>=self.db.query_row("SELECT sequence,artifact,event_json,frame_sha256 FROM feed_events WHERE sequence>?1 ORDER BY sequence LIMIT 1",[self.position],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        let Some((sequence, path, event, sha)) = row else {
            return Ok(None);
        };
        ensure!(sequence == self.position + 1, "replay_unavailable");
        let frame = self.build((path, event, sha))?;
        ensure!(
            frame.envelope.event.sequence == sequence,
            "event_index_mismatch"
        );
        self.position = sequence;
        Ok(Some(frame))
    }
    pub fn chunk(&self, sha: &str) -> Result<Option<Frame>> {
        ensure!(v2::is_digest(sha), "invalid_digest");
        let mut row = self
            .db
            .query_row(
                "SELECT artifact,event_json,frame_sha256 FROM feed_events WHERE frame_sha256=?1",
                [sha],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if row.is_none() {
            row = self
                .db
                .query_row(
                    "SELECT artifact,payload_event,frame_sha256 FROM banks WHERE frame_sha256=?1",
                    [sha],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
        }
        if row
            .as_ref()
            .is_some_and(|row: &(String, String, String)| archived_payload(Path::new(&row.0)))
        {
            return Ok(None); // The bounded live API reports 410 for cold dependencies.
        }
        row.map(|row| self.build(row)).transpose()
    }
    fn floor(&self) -> Result<(u64, String)> {
        let exists:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='feed_retention')",[],|r|r.get(0))?;
        if !exists {
            return Ok((0, "-".into()));
        }
        Ok(self.db.query_row(
            "SELECT base_sequence,base_sha256 FROM feed_retention WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?)
    }
    /// Exact replay boundary retained by this source, independent of an
    /// origin's smaller in-memory/disk spool window.
    pub fn replay_floor_cursor(&self) -> Result<String> {
        let (sequence, sha) = self.floor()?;
        let cursor = v2::cursor(&self.source.session_id, sequence, &sha);
        v2::parse_cursor(&cursor)?;
        Ok(cursor)
    }
    /// Local beam custody is an explicit operator choice. The immutable FEED
    /// keeps its original binding; this separate descriptor cannot rebind it.
    pub fn validate_beam_authority(&self) -> Result<()> {
        let value: Value = serde_json::from_slice(&bounded_file(
            &self.root.join("RETENTION-AUTHORITY.json"),
            65536,
        )?)?;
        ensure!(
            value["schema"] == "blockzilla-retention-authority-v1"
                && value["mode"] == "local-beam-v1"
                && value["source"] == serde_json::to_value(&self.source)?
                && value["consumer_ack_required"] == false
                && value["producer_generation"].as_str() == self.producer_generation.as_deref()
                && self.producer_generation.is_some(),
            "retention_authority_changed"
        );
        Ok(())
    }
    /// A replay boundary can equal the floor. A served frame must be strictly
    /// above it and still have its exact committed native membership.
    pub fn require_retained(&self, frame: &Frame) -> Result<()> {
        ensure!(frame.source == self.source, "source_changed");
        let (base, _) = self.floor()?;
        ensure!(frame.envelope.event.sequence > base, "replay_unavailable");
        let sha: Option<String> = self
            .db
            .query_row(
                "SELECT frame_sha256 FROM feed_events WHERE sequence=?1",
                [frame.envelope.event.sequence],
                |row| row.get(0),
            )
            .optional()?;
        ensure!(
            sha.as_deref() == Some(frame.sha256.as_str()),
            "replay_unavailable"
        );
        Ok(())
    }
    pub fn retained_chunk(&self, sha: &str) -> Result<Option<Frame>> {
        ensure!(v2::is_digest(sha), "invalid_digest");
        let row: Option<(String, String, String)> = self.db.query_row(
            "SELECT artifact,event_json,frame_sha256 FROM feed_events WHERE frame_sha256=?1 AND sequence>(SELECT base_sequence FROM feed_retention WHERE id=1)",
            [sha], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).optional()?;
        let frame = if let Some(row) = row {
            self.build(row)?
        } else {
            // An old payload can still be a dependency of a later retained
            // control. A Bank row alone is not custody evidence.
            let row:Option<(String,String,String)>=self.db.query_row(
                "SELECT b.artifact,b.payload_event,b.frame_sha256 FROM banks b JOIN feed_events r ON r.artifact=b.artifact WHERE b.frame_sha256=?1 AND r.sequence>(SELECT base_sequence FROM feed_retention WHERE id=1) AND json_extract(r.event_json,'$.payload_frame_sha256')=?1 LIMIT 1",
                [sha],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
            ).optional()?;
            let Some(row) = row else {
                return Ok(None);
            };
            self.build(row)?
        };
        self.require_retained_or_dependency(&frame)?;
        Ok(Some(frame))
    }
    fn require_retained_or_dependency(&self, frame: &Frame) -> Result<()> {
        if self.require_retained(frame).is_ok() {
            return Ok(());
        }
        let (base, _) = self.floor()?;
        ensure!(frame.source == self.source, "source_changed");
        ensure!(
            frame.envelope.event.kind == "block" && frame.envelope.event.sequence <= base,
            "replay_unavailable"
        );
        let row:Option<(String,String,String)>=self.db.query_row(
            "SELECT r.artifact,r.event_json,r.frame_sha256 FROM banks b JOIN feed_events r ON r.artifact=b.artifact WHERE b.frame_sha256=?1 AND b.payload_event=?2 AND r.sequence>?3 AND json_extract(r.event_json,'$.payload_frame_sha256')=?1 ORDER BY r.sequence LIMIT 1",
            rusqlite::params![frame.sha256,serde_json::to_string(&frame.envelope.event)?,base],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        ).optional()?;
        let Some(row) = row else {
            anyhow::bail!("replay_unavailable");
        };
        let control = self.build(row)?;
        self.require_retained(&control)?;
        control.envelope.event.matches_payload(frame)?;
        let still_bound:bool=self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM banks b JOIN feed_events r ON r.artifact=b.artifact WHERE b.frame_sha256=?1 AND b.payload_event=?2 AND r.frame_sha256=?3 AND r.sequence>(SELECT base_sequence FROM feed_retention WHERE id=1))",
            rusqlite::params![frame.sha256,serde_json::to_string(&frame.envelope.event)?,control.sha256],|r|r.get(0),
        )?;
        ensure!(still_bound, "replay_unavailable");
        Ok(())
    }
    /// Read producer-owned metadata in one SQLite snapshot. This does not
    /// instantiate or apply a Chain, nor create a second replay checkpoint.
    pub fn beam_head(&self) -> Result<v2::Head> {
        self.validate_beam_authority()?;
        let tx = self.db.unchecked_transaction()?;
        let (base, base_sha): (u64, String) = tx.query_row(
            "SELECT base_sequence,base_sha256 FROM feed_retention WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let tip: Option<(u64, String)> = tx
            .query_row(
                "SELECT sequence,frame_sha256 FROM feed_events ORDER BY sequence DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let latest: Option<String> = tx.query_row(
            "SELECT json_extract(chain_json,'$.latest') FROM feed_state WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        let selected: Option<v2::ConfirmedObservation> =
            latest.as_deref().map(serde_json::from_str).transpose()?;
        tx.commit()?;
        let now = crate::store::now_ms();
        let observed = selected.as_ref().map(|s| s.observed_at_unix_ms);
        let lag = observed.map(|t| now.saturating_sub(t));
        let health = self.health()?;
        let status = if health == "failed" {
            "failed"
        } else if selected.is_none() {
            "starting"
        } else if health == "live" && lag.is_some_and(|n| n <= v2::DEFAULT_MAX_LAG_MS) {
            "live"
        } else {
            "stale"
        };
        let (sequence, sha) = tip.unwrap_or((base, base_sha.clone()));
        let head = v2::Head {
            schema: v2::HEAD.into(),
            profile: v2::PROFILE.into(),
            source: self.source.clone(),
            cursor: Some(v2::cursor(&self.source.session_id, sequence, &sha)),
            earliest_after: Some(v2::cursor(&self.source.session_id, base, &base_sha)),
            status: status.into(),
            sampled_at_unix_ms: now,
            source_observed_at_unix_ms: observed,
            source_lag_ms: lag,
            latest_confirmed: selected,
        };
        head.validate(&self.source, now, v2::DEFAULT_MAX_LAG_MS)?;
        Ok(head)
    }
    pub fn coverage_gap_exists(&self, n: u64) -> Result<bool> {
        if n == 0 {
            return Ok(true);
        }
        if self.producer_generation.is_none() {
            return Ok(false);
        }
        Ok(self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM coverage_gaps WHERE sequence=?1)",
            [n],
            |r| r.get(0),
        )?)
    }
    pub fn coverage_gaps_after(&self, after: u64, limit: usize) -> Result<Value> {
        let generation = self
            .producer_generation
            .as_deref()
            .context("coverage_gaps_unavailable")?;
        let tx = self.db.unchecked_transaction()?;
        let (base, latest): (u64, u64) = tx.query_row(
            "SELECT gap_base_sequence,latest_gap_sequence FROM feed_retention WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(after >= base, "replay_unavailable");
        ensure!(after <= latest, "invalid_gap_cursor");
        let mut gaps = Vec::new();
        let mut bytes = 0;
        {
            let mut q=tx.prepare("SELECT sequence,processed_sequence,gap_json FROM coverage_gaps WHERE sequence>?1 ORDER BY sequence LIMIT ?2")?;
            for row in q.query_map(rusqlite::params![after, limit.clamp(1, 256) as u64], |r| {
                Ok((
                    r.get::<_, u64>(0)?,
                    r.get::<_, u64>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })? {
                let (n, p, raw) = row?;
                let value = serde_json::json!({"sequence":n,"processed_sequence":p,"gap":serde_json::from_str::<Value>(&raw)?});
                let size = serde_json::to_vec(&value)?.len() + 1;
                if bytes + size > 4 * 1024 * 1024 - 8192 {
                    ensure!(!gaps.is_empty(), "coverage_gap_bound");
                    break;
                }
                bytes += size;
                gaps.push(value);
            }
        }
        tx.commit()?;
        Ok(
            serde_json::json!({"schema":"blockzilla-coverage-gaps-v1","source":self.source,"producer_generation":generation,"base_sequence":base,"latest_sequence":latest,"gaps":gaps}),
        )
    }
    /// Return the original block frame after verifying its local native root.
    /// This lookup does not move the stream cursor or classify skipped slots.
    /// A missing row, mismatched requested hash, or missing file is unavailable.
    pub fn finalized_block(
        &self,
        slot: u64,
        expected_blockhash: &[u8; 32],
    ) -> Result<Option<Frame>> {
        ensure!(slot <= v2::SAFE, "invalid_slot");
        if self.producer_generation.is_some() {
            return self.live_finalized_block(slot, expected_blockhash);
        }
        let catalog: Option<(u64, String, String, u64)> = open_feed(&self.payload_root)?
            .query_row(
                "SELECT bank,artifact,marker_sha,root_sequence FROM archive_catalog WHERE slot=?1",
                [slot],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((bank, catalog_path, marker_sha, native_root)) = catalog else {
            return Ok(None);
        };
        let (sequence, path, block, sha, root_sequence, root, root_sha): (
            u64,
            String,
            String,
            String,
            u64,
            String,
            String,
        ) = {
            let mut query = self.db.prepare_cached(
                "SELECT p.sequence,p.artifact,p.event_json,p.frame_sha256,
                        r.sequence,r.event_json,r.frame_sha256
                 FROM banks b
                 JOIN feed_events p ON p.frame_sha256=b.frame_sha256
                 JOIN feed_events r ON r.artifact=b.artifact AND r.sequence>p.sequence
                 WHERE b.slot=?1 AND b.bank=?2 AND b.state='rooted'
                   AND p.artifact=b.artifact AND p.event_json=b.payload_event
                   AND json_extract(r.event_json,'$.kind')='root'
                   AND json_extract(r.event_json,'$.source_sequence')=?3",
            )?;
            let mut rows = query.query([slot, bank, native_root])?;
            let Some(row) = rows.next()? else {
                return Ok(None);
            };
            let found = (
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            );
            ensure!(rows.next()?.is_none(), "ambiguous_root_commit");
            found
        };
        let block: BankEvent = serde_json::from_str(&block)?;
        let root: BankEvent = serde_json::from_str(&root)?;
        ensure!(
            block.kind == "block"
                && block.sequence == sequence
                && block.bank.key() == (slot, bank)
                && path == catalog_path
                && block.payload_sha256 == marker_sha
                && root.kind == "root"
                && root.sequence == root_sequence
                && root.source_sequence == native_root
                && root.bank == block.bank
                && root.block_height == block.block_height
                && root.payload_sha256 == marker_sha
                && root.payload_frame_sha256.as_deref() == Some(sha.as_str()),
            "rooted_catalog_commit_mismatch"
        );
        if &block.bank.blockhash != expected_blockhash {
            return Ok(None);
        }
        let result: Result<Frame> = (|| {
            let root = self.committed_frame(&path, root, &root_sha)?;
            let block = self.committed_frame(&path, block, &sha)?;
            root.envelope.event.matches_payload(&block)?;
            Ok(block)
        })();
        match result {
            Err(e)
                if e.downcast_ref::<io::Error>()
                    .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) =>
            {
                Ok(None)
            }
            other => other.map(Some),
        }
    }
    pub fn retained_finalized_block(&self, slot: u64, hash: &[u8; 32]) -> Result<Option<Frame>> {
        let Some(frame) = self.finalized_block(slot, hash)? else {
            return Ok(None);
        };
        self.require_retained_or_dependency(&frame)?;
        let root:Option<(u64,String)>=self.db.query_row(
            "SELECT sequence,frame_sha256 FROM feed_events WHERE artifact=(SELECT artifact FROM banks WHERE slot=?1 AND bank=?2) AND json_extract(event_json,'$.kind')='root' ORDER BY sequence DESC LIMIT 1",
            rusqlite::params![frame.envelope.event.bank.slot,frame.envelope.event.bank.bank_id],|r|Ok((r.get(0)?,r.get(1)?)),
        ).optional()?;
        let Some((sequence, sha)) = root else {
            anyhow::bail!("replay_unavailable");
        };
        let root = self.retained_chunk(&sha)?.context("replay_unavailable")?;
        ensure!(
            root.envelope.event.sequence == sequence,
            "event_index_mismatch"
        );
        root.envelope.event.matches_payload(&frame)?;
        self.require_retained_or_dependency(&frame)?;
        Ok(Some(frame))
    }
    fn live_finalized_block(&self, slot: u64, hash: &[u8; 32]) -> Result<Option<Frame>> {
        let mut q=self.db.prepare("SELECT b.artifact,b.payload_event,b.frame_sha256,r.event_json,r.frame_sha256 FROM banks b JOIN feed_events r ON r.artifact=b.artifact WHERE b.slot=?1 AND b.state='rooted' AND json_extract(r.event_json,'$.kind')='root'")?;
        let mut rows = q.query([slot])?;
        let Some(r) = rows.next()? else {
            return Ok(None);
        };
        let (path, block, sha, root, root_sha): (String, String, String, String, String) =
            (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?);
        ensure!(rows.next()?.is_none(), "ambiguous_root_commit");
        let block: BankEvent = serde_json::from_str(&block)?;
        let root: BankEvent = serde_json::from_str(&root)?;
        ensure!(
            block.kind == "block"
                && root.kind == "root"
                && root.bank == block.bank
                && root.payload_sha256 == block.payload_sha256
                && root.payload_frame_sha256.as_deref() == Some(sha.as_str()),
            "rooted_commit_mismatch"
        );
        if &block.bank.blockhash != hash {
            return Ok(None);
        }
        let result: Result<Frame> = (|| {
            let root = self.committed_frame(&path, root, &root_sha)?;
            let block = self.committed_frame(&path, block, &sha)?;
            root.envelope.event.matches_payload(&block)?;
            Ok(block)
        })();
        match result {
            Err(e)
                if e.downcast_ref::<io::Error>()
                    .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) =>
            {
                Ok(None)
            }
            other => other.map(Some),
        }
    }
    pub fn health(&self) -> Result<&'static str> {
        let status: Value =
            serde_json::from_slice(&bounded_file(&self.root.join("STATUS.json"), 65536)?)?;
        let input: Value = serde_json::from_slice(&bounded_file(
            &self.payload_root.join("STATUS.json"),
            65536,
        )?)?;
        if status["state"] == "FAILED" || input["state"] == "FAILED" {
            return Ok("failed");
        }
        let now = crate::store::now_ms();
        let fresh = |s: &Value| -> bool {
            s["updated_unix_ms"].as_u64().is_some_and(|t| {
                v2::clock_check(t, now).is_ok() && now.saturating_sub(t) <= v2::DEFAULT_MAX_LAG_MS
            })
        };
        Ok(
            if status["state"] == "RUNNING"
                && input["state"] == "RUNNING"
                && fresh(&status)
                && fresh(&input)
            {
                "live"
            } else {
                "stale"
            },
        )
    }
}

fn open_feed(root: &Path) -> Result<Connection> {
    let db = Connection::open_with_flags(
        root.join("feed.sqlite"),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    db.busy_timeout(std::time::Duration::from_millis(250))?;
    db.execute_batch("PRAGMA query_only=ON;")?;
    Ok(db)
}

fn archived_payload(path: &Path) -> bool {
    path.join("REMOTE-CUSTODY.json").is_file()
        && v2::REQUIRED.iter().any(|name| !path.join(name).is_file())
}

#[cfg(test)]
mod cold_tests {
    use super::*;
    use rusqlite::params;
    use serde_json::json;
    use std::fs;

    struct FinalizedFixture {
        source: BankSource,
        block: Frame,
        artifact: PathBuf,
        catalog: Connection,
        feed: Connection,
    }

    fn finalized_fixture(root: &Path) -> FinalizedFixture {
        let root = root.canonicalize().unwrap();
        let processed = root.join("processed");
        let artifact = processed.join("bank.compact");
        fs::create_dir_all(&artifact).unwrap();
        let template = v2::fixtures::block(1, 100, 7, 99, 90);
        let marker = serde_json::to_vec(&template.envelope.marker).unwrap();
        fs::write(artifact.join("DIRECT-AGAVE-COMPACT.v1.json"), &marker).unwrap();
        for name in v2::REQUIRED {
            fs::write(artifact.join(name), [42]).unwrap();
        }
        let mut event = template.envelope.event;
        event.payload_sha256 = v2::digest(&marker);
        let block = v2::artifact::build(&processed, &artifact, &template.source, event).unwrap();
        let rooted = v2::fixtures::control(&block, 3, "root", 2000);
        let mut header = serde_json::to_value(&block.source).unwrap();
        header["schema"] = json!("hivezilla-bank-feed-v2");
        header["profile"] = json!(v2::PROFILE);
        header["payload_root"] = json!(&processed);
        fs::write(root.join("FEED.json"), serde_json::to_vec(&header).unwrap()).unwrap();

        let catalog = Connection::open(processed.join("feed.sqlite")).unwrap();
        catalog.execute_batch("CREATE TABLE archive_catalog(slot INTEGER PRIMARY KEY,bank INTEGER,artifact TEXT,marker_sha TEXT,root_sequence INTEGER);").unwrap();
        let path = artifact.to_str().unwrap();
        catalog
            .execute(
                "INSERT INTO archive_catalog VALUES(100,7,?1,?2,?3)",
                params![
                    path,
                    block.envelope.event.payload_sha256,
                    rooted.envelope.event.source_sequence
                ],
            )
            .unwrap();

        let feed = Connection::open(root.join("feed.sqlite")).unwrap();
        feed.execute_batch(
            "CREATE TABLE banks(slot INTEGER,bank INTEGER,artifact TEXT,payload_event TEXT,frame_sha256 TEXT,state TEXT,PRIMARY KEY(slot,bank));
             CREATE TABLE feed_events(sequence INTEGER PRIMARY KEY,artifact TEXT,event_json TEXT,frame_sha256 TEXT UNIQUE);
             CREATE INDEX event_artifact ON feed_events(artifact,sequence);",
        ).unwrap();
        let payload_event = serde_json::to_string(&block.envelope.event).unwrap();
        feed.execute(
            "INSERT INTO banks VALUES(100,7,?1,?2,?3,'rooted')",
            params![path, payload_event, block.sha256],
        )
        .unwrap();
        for frame in [&block, &rooted] {
            feed.execute(
                "INSERT INTO feed_events VALUES(?1,?2,?3,?4)",
                params![
                    frame.envelope.event.sequence,
                    path,
                    serde_json::to_string(&frame.envelope.event).unwrap(),
                    frame.sha256
                ],
            )
            .unwrap();
        }
        FinalizedFixture {
            source: BankSource::open(&root).unwrap(),
            block,
            artifact,
            catalog,
            feed,
        }
    }

    #[test]
    fn cold_payload_is_unavailable_until_exact_files_are_restored() {
        let t = tempfile::tempdir().unwrap();
        assert!(!archived_payload(t.path()));
        std::fs::write(t.path().join("REMOTE-CUSTODY.json"), b"{}").unwrap();
        assert!(archived_payload(t.path()));
        for name in v2::REQUIRED {
            std::fs::write(t.path().join(name), b"data").unwrap();
        }
        assert!(!archived_payload(t.path()));
    }

    #[test]
    fn continuous_floor_keeps_exact_payload_dependencies_and_sparse_gap_cursors() {
        let t = tempfile::tempdir().unwrap();
        let mut f = finalized_fixture(t.path());
        f.feed.execute_batch("CREATE TABLE feed_retention(id INTEGER PRIMARY KEY,base_sequence INTEGER,base_sha256 TEXT,gap_base_sequence INTEGER,latest_gap_sequence INTEGER);CREATE TABLE coverage_gaps(sequence INTEGER PRIMARY KEY,processed_sequence INTEGER,gap_json TEXT);").unwrap();
        f.feed
            .execute(
                "INSERT INTO feed_retention VALUES(1,1,?1,0,19)",
                [&f.block.sha256],
            )
            .unwrap();
        f.feed
            .execute("DELETE FROM feed_events WHERE sequence=1", [])
            .unwrap();
        let mut h: Value =
            serde_json::from_slice(&fs::read(t.path().join("FEED.json")).unwrap()).unwrap();
        h["producer_generation"] = json!("a".repeat(64));
        fs::write(t.path().join("FEED.json"), serde_json::to_vec(&h).unwrap()).unwrap();
        f.source = BankSource::open(t.path()).unwrap();
        assert_eq!(
            f.source.next().unwrap_err().to_string(),
            "replay_unavailable"
        );
        assert_eq!(
            f.source
                .seek(&v2::cursor(&f.block.source.session_id, 0, "-"))
                .unwrap_err()
                .to_string(),
            "replay_unavailable"
        );
        assert!(
            f.source
                .seek(&v2::cursor(&f.block.source.session_id, 1, &"0".repeat(64)))
                .is_err()
        );
        f.source.seek(&f.block.cursor).unwrap();
        assert_eq!(
            f.source.chunk(&f.block.sha256).unwrap().unwrap().wire,
            f.block.wire
        );
        assert_eq!(
            f.source
                .finalized_block(100, &f.block.envelope.event.bank.blockhash)
                .unwrap()
                .unwrap()
                .wire,
            f.block.wire
        );
        for n in [7, 19] {
            f.feed
                .execute(
                    "INSERT INTO coverage_gaps VALUES(?1,?1,?2)",
                    params![n, json!({"gap_sequence":n}).to_string()],
                )
                .unwrap();
        }
        assert!(f.source.coverage_gap_exists(0).unwrap());
        assert!(!f.source.coverage_gap_exists(8).unwrap());
        let first = f.source.coverage_gaps_after(0, 1).unwrap();
        assert_eq!(first["gaps"][0]["sequence"], 7);
        let next = f.source.coverage_gaps_after(7, 256).unwrap();
        assert_eq!(next["gaps"][0]["sequence"], 19);
        assert_eq!(next["gaps"].as_array().unwrap().len(), 1);
        f.feed
            .execute("UPDATE feed_retention SET gap_base_sequence=7", [])
            .unwrap();
        assert_eq!(
            f.source.coverage_gaps_after(0, 1).unwrap_err().to_string(),
            "replay_unavailable"
        );
        assert!(f.source.coverage_gaps_after(20, 1).is_err());
        f.feed.execute("DELETE FROM feed_events", []).unwrap();
        f.feed
            .execute(
                "UPDATE feed_retention SET base_sequence=3,base_sha256=?1",
                ["b".repeat(64)],
            )
            .unwrap();
        assert_eq!(
            f.source.next().unwrap_err().to_string(),
            "replay_unavailable"
        );
    }

    #[test]
    fn finalized_lookup_returns_original_frame_and_never_infers_a_skip() {
        let t = tempfile::tempdir().unwrap();
        let f = finalized_fixture(t.path());
        let hash = &f.block.envelope.event.bank.blockhash;
        let found = f.source.finalized_block(100, hash).unwrap().unwrap();
        assert_eq!(found.wire, f.block.wire);
        assert_eq!(found.cursor, f.block.cursor);
        assert_eq!(
            found.envelope.event.commitment.as_deref(),
            Some("processed")
        );
        assert_eq!(f.source.position, 0);
        assert!(f.source.finalized_block(99, hash).unwrap().is_none());
        assert!(f.source.finalized_block(100, &[0; 32]).unwrap().is_none());
        f.feed
            .execute("UPDATE banks SET state='published'", [])
            .unwrap();
        assert!(f.source.finalized_block(100, hash).unwrap().is_none());
        f.feed
            .execute("UPDATE banks SET state='rooted'", [])
            .unwrap();
        fs::remove_file(f.artifact.join("signatures.bin")).unwrap();
        assert!(f.source.finalized_block(100, hash).unwrap().is_none());
    }

    #[test]
    fn finalized_lookup_rejects_changed_root_and_catalog_commits() {
        let t = tempfile::tempdir().unwrap();
        let f = finalized_fixture(t.path());
        let hash = &f.block.envelope.event.bank.blockhash;
        f.feed
            .execute(
                "UPDATE feed_events SET frame_sha256=?1 WHERE sequence=3",
                ["0".repeat(64)],
            )
            .unwrap();
        assert_eq!(
            f.source.finalized_block(100, hash).unwrap_err().to_string(),
            "frame_commit_changed"
        );
        f.catalog
            .execute("UPDATE archive_catalog SET marker_sha=?1", ["0".repeat(64)])
            .unwrap();
        assert_eq!(
            f.source.finalized_block(100, hash).unwrap_err().to_string(),
            "rooted_catalog_commit_mismatch"
        );
    }
}

fn retryable(e: &anyhow::Error) -> bool {
    matches!(e.downcast_ref::<rusqlite::Error>(),Some(rusqlite::Error::SqliteFailure(code,_))
        if matches!(code.code,rusqlite::ErrorCode::DatabaseBusy|rusqlite::ErrorCode::DatabaseLocked|rusqlite::ErrorCode::ReadOnly))
}
