//! Cursor, fork effects and webhook jobs have one FULL-synchronous SQLite commit.
use crate::{
    config::WebhookTarget,
    payload_cache::{PayloadCache, SharedPayload},
    projection::{self, Payload, PayloadMode},
};
use anyhow::{Context, Result, ensure};
use blockzilla_bank_client::{Bootstrap, Delivery};
use blockzilla_bank_stream_v2::{self as v2, SourceIdentity, chain::Chain};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::Notify;

pub const MAX_BODY: usize = 64 * 1024 * 1024;
#[cfg(test)]
#[path = "compact_store_tests.rs"]
mod compact_store_tests;
#[derive(Clone)]
pub struct Limits {
    pub replay_bytes: u64,
    pub replay_events: u64,
    pub database_bytes: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            replay_bytes: 512 * 1024 * 1024,
            replay_events: 8192,
            database_bytes: 16 * 1024 * 1024 * 1024,
        }
    }
}
pub struct Store {
    pub payload_mode: PayloadMode,
    connection: Mutex<Connection>,
    pub source: SourceIdentity,
    pub producer_generation: String,
    pub targets: Vec<WebhookTarget>,
    pub notify: Notify,
    limits: Limits,
    pub path: PathBuf,
    pub payloads: Arc<PayloadCache>,
    disk_reserve_bytes: AtomicU64,
}
pub struct Record {
    pub cursor: String,
    pub source_cursor: String,
    pub kind: String,
    pub event: Value,
    pub affected: Value,
    pub payload: Option<Arc<SharedPayload>>,
}
/// Compact response readers do not need to load the portable JSON projection.
pub struct NativeRecord {
    pub cursor: String,
    pub source_cursor: String,
    pub kind: String,
    pub event: Value,
    pub affected: Value,
    pub frame: Option<v2::Frame>,
}
impl NativeRecord {
    pub fn wire(&self) -> &[u8] {
        self.frame.as_ref().map_or(&[], |frame| frame.wire.as_ref())
    }
}
impl Record {
    pub fn payload_json(&self) -> &Value {
        self.payload.as_ref().map_or(&Value::Null, |p| &p.json)
    }
    pub fn wire(&self) -> &[u8] {
        self.payload.as_ref().map_or(&[], |p| p.frame.wire.as_ref())
    }
}
#[derive(Clone)]
pub struct Job {
    pub delivery_id: String,
    pub target: WebhookTarget,
    pub body: String,
    pub attempts: u32,
}
fn hash(bytes: &[u8]) -> String {
    v2::digest(bytes)
}
fn load_chain(c: &Connection) -> Result<Chain> {
    Ok(serde_json::from_str(&c.query_row(
        "SELECT chain_json FROM checkpoint WHERE id=1",
        [],
        |r| r.get::<_, String>(0),
    )?)?)
}
fn beam_generation(c: &Connection) -> Result<Option<String>> {
    Ok(c.query_row(
        "SELECT runtime_generation FROM beam_input WHERE id=1",
        [],
        |r| r.get(0),
    )
    .optional()?)
}
fn insert_payload(c: &Connection, p: &SharedPayload) -> Result<()> {
    let old: Option<Vec<u8>> = c
        .query_row(
            "SELECT wire FROM payloads WHERE sha=?",
            [&p.frame.sha256],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(old) = old {
        ensure!(old == p.frame.wire.as_ref(), "payload_digest_collision");
        return Ok(());
    }
    c.execute(
        "INSERT INTO payloads(sha,wire,projection,bytes) VALUES(?,?,?,?)",
        params![
            p.frame.sha256,
            p.frame.wire.as_ref(),
            p.text.as_str(),
            p.frame.wire.len() + p.text.len()
        ],
    )?;
    Ok(())
}
impl Store {
    pub fn open(
        path: &Path,
        source: SourceIdentity,
        producer_generation: String,
        targets: Vec<WebhookTarget>,
        limits: Limits,
    ) -> Result<Arc<Self>> {
        Self::open_with_mode(
            path,
            source,
            producer_generation,
            targets,
            limits,
            PayloadMode::Full,
            0,
        )
    }
    pub fn open_with_mode(
        path: &Path,
        source: SourceIdentity,
        producer_generation: String,
        targets: Vec<WebhookTarget>,
        limits: Limits,
        mode: PayloadMode,
        disk_reserve_bytes: u64,
    ) -> Result<Arc<Self>> {
        source.validate()?;
        ensure!(
            mode != PayloadMode::CompactOnly || targets.is_empty(),
            "compact_only_mode_disables_webhooks"
        );
        ensure!(
            !producer_generation.is_empty() && producer_generation.len() <= 128,
            "invalid_producer_generation"
        );
        ensure!(
            path.is_absolute() && targets.len() <= 16,
            "invalid_store_configuration"
        );
        ensure!(
            (128 * 1024 * 1024..=4 * 1024 * 1024 * 1024).contains(&limits.replay_bytes)
                && (1024..=65536).contains(&limits.replay_events),
            "invalid_replay_bounds"
        );
        let mut ids = std::collections::BTreeSet::new();
        for t in &targets {
            t.validate()?;
            ensure!(ids.insert(&t.id), "duplicate_webhook_id");
        }
        let quotas = targets.iter().map(|t| t.queue_bytes).sum::<u64>();
        ensure!(
            limits.database_bytes >= (limits.replay_bytes + quotas) * 2 + 64 * 1024 * 1024
                && limits.database_bytes <= 64 * 1024 * 1024 * 1024,
            "database_budget_too_small"
        );
        if path.exists() {
            let m = std::fs::symlink_metadata(path)?;
            ensure!(
                m.is_file() && !m.file_type().is_symlink(),
                "invalid_database_file"
            );
        }
        let c = Connection::open(path)?;
        c.busy_timeout(std::time::Duration::from_secs(2))?;
        c.pragma_update(None, "journal_mode", "WAL")?;
        c.pragma_update(None, "synchronous", "FULL")?;
        c.pragma_update(None, "wal_autocheckpoint", 256)?;
        let page_size: u64 = c.pragma_query_value(None, "page_size", |r| r.get(0))?;
        c.pragma_update(None, "max_page_count", limits.database_bytes / page_size)?;
        c.execute_batch("CREATE TABLE IF NOT EXISTS config(id INTEGER PRIMARY KEY CHECK(id=1),source TEXT NOT NULL,targets TEXT NOT NULL,producer_generation TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS checkpoint(id INTEGER PRIMARY KEY CHECK(id=1),cursor TEXT NOT NULL,base TEXT NOT NULL,chain_json TEXT NOT NULL,pending_ack INTEGER NOT NULL,bootstrap_boundary TEXT NOT NULL,origin_acked TEXT,output_cursor TEXT NOT NULL,gap_sequence INTEGER NOT NULL DEFAULT 0,gap_acked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS payloads(sha TEXT PRIMARY KEY,wire BLOB NOT NULL,projection TEXT NOT NULL,bytes INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS updates(sequence INTEGER PRIMARY KEY AUTOINCREMENT,cursor TEXT UNIQUE NOT NULL,kind TEXT NOT NULL,event TEXT NOT NULL,affected TEXT NOT NULL,payload_sha TEXT NOT NULL,source_cursor TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS subscriptions(id TEXT PRIMARY KEY,state TEXT NOT NULL,gap_start TEXT,gap_end TEXT,gap_count INTEGER NOT NULL DEFAULT 0,error TEXT);
CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY AUTOINCREMENT,delivery_id TEXT UNIQUE NOT NULL,target TEXT NOT NULL,cursor TEXT NOT NULL,body TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'pending',attempts INTEGER NOT NULL DEFAULT 0,next_ms INTEGER NOT NULL DEFAULT 0,error TEXT,UNIQUE(target,cursor));
CREATE TABLE IF NOT EXISTS beam_input(id INTEGER PRIMARY KEY CHECK(id=1),runtime_generation TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS payloads_bytes ON payloads(bytes);
CREATE INDEX IF NOT EXISTS payloads_wire_bytes ON payloads(length(wire),bytes);
CREATE INDEX IF NOT EXISTS outbox_target ON outbox(target,id);
CREATE INDEX IF NOT EXISTS outbox_state ON outbox(state,id);")?;
        if !c
            .prepare("PRAGMA table_info(config)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .iter()
            .any(|name| name == "payload_mode")
        {
            c.execute_batch(
                "ALTER TABLE config ADD COLUMN payload_mode TEXT NOT NULL DEFAULT 'full';",
            )?;
        }
        let sj = serde_json::to_string(&source)?;
        let tj = serde_json::to_string(&targets)?;
        let old: Option<(String, String, String)> = c
            .query_row(
                "SELECT source,targets,producer_generation FROM config WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((a, b, generation)) = old {
            ensure!(
                generation == producer_generation,
                "producer_generation_changed"
            );
            ensure!(a == sj, "source_changed");
            ensure!(b == tj, "webhook_configuration_changed_requires_migration");
        } else {
            c.execute(
                "INSERT INTO config(id,source,targets,producer_generation) VALUES(1,?,?,?)",
                params![sj, tj, producer_generation],
            )?;
        }
        for t in &targets {
            c.execute(
                "INSERT OR IGNORE INTO subscriptions(id,state) VALUES(?,'active')",
                [&t.id],
            )?;
        }
        let stored_mode: String =
            c.query_row("SELECT payload_mode FROM config WHERE id=1", [], |r| {
                r.get(0)
            })?;
        ensure!(
            stored_mode == "full" || stored_mode == "compact-only",
            "unknown_payload_mode"
        );
        ensure!(
            mode != PayloadMode::Full || stored_mode == "full",
            "compact_only_database_requires_saved_full_mode_backup"
        );
        let payloads = PayloadCache::with_mode(
            source.clone(),
            limits.database_bytes < 4 * 1024 * 1024 * 1024,
            mode,
        );
        let saved: Option<String> = c
            .query_row("SELECT cursor FROM checkpoint WHERE id=1", [], |r| r.get(0))
            .optional()?;
        if let Some(saved) = saved {
            let (session, sequence, _) = v2::parse_cursor(&saved)?;
            ensure!(session == source.session_id, "source_changed");
            payloads.committed(sequence);
        }
        let store = Arc::new(Self {
            payload_mode: mode,
            connection: Mutex::new(c),
            source,
            producer_generation,
            targets,
            notify: Notify::new(),
            limits,
            path: path.into(),
            payloads,
            disk_reserve_bytes: AtomicU64::new(0),
        });
        store.set_disk_reserve(disk_reserve_bytes)?;
        if mode == PayloadMode::CompactOnly && stored_mode != mode.name() {
            store.migrate_compact_only()?;
        }
        Ok(store)
    }
    pub fn set_disk_reserve(&self, bytes: u64) -> Result<()> {
        ensure!(bytes <= 1024 * 1024 * 1024 * 1024, "invalid_disk_reserve");
        self.disk_reserve_bytes.store(bytes, Ordering::Relaxed);
        self.check_disk(0)
    }
    fn check_disk(&self, incoming: u64) -> Result<()> {
        self.check_disk_charge(incoming.saturating_mul(2))
    }
    fn check_disk_charge(&self, charge: u64) -> Result<()> {
        let reserve = self.disk_reserve_bytes.load(Ordering::Relaxed);
        if reserve == 0 {
            return Ok(());
        }
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(
            self.path
                .parent()
                .context("database_parent_missing")?
                .as_os_str()
                .as_bytes(),
        )?;
        let mut value = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        ensure!(
            unsafe { libc::statvfs(path.as_ptr(), value.as_mut_ptr()) } == 0,
            "disk_reserve_probe_failed"
        );
        let value = unsafe { value.assume_init() };
        let available = (value.f_bavail as u64).saturating_mul(value.f_frsize as u64);
        ensure!(
            available
                >= reserve
                    .saturating_add(charge)
                    .saturating_add(8 * 1024 * 1024),
            "consumer_disk_reserve_reached"
        );
        Ok(())
    }
    /// One-way storage conversion. Keep the old database outside the bounded
    /// volume for rollback. A full-mode open of this database fails explicitly.
    fn migrate_compact_only(&self) -> Result<()> {
        let mut c = self.connection.lock().unwrap();
        // The service has not started intake or readers. Bound the conversion's
        // WAL by the current allocated database size, without increasing quotas.
        let busy: u64 = c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?;
        ensure!(busy == 0, "compact_migration_database_busy");
        let pages: u64 = c.pragma_query_value(None, "page_count", |r| r.get(0))?;
        let page_size: u64 = c.pragma_query_value(None, "page_size", |r| r.get(0))?;
        self.check_disk_charge(pages.saturating_mul(page_size))?;
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let saved: Option<(String, String, String)> = tx
            .query_row(
                "SELECT cursor,base,output_cursor FROM checkpoint WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((cursor, base, output)) = &saved {
            load_chain(&tx)?.validate(&self.source, cursor)?;
            crate::cursor::parse(base, &self.source.session_id)?;
            crate::cursor::parse(output, &self.source.session_id)?;
        }
        {
            let mut statement = tx.prepare("SELECT sha,wire FROM payloads")?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let sha: String = row.get(0)?;
                let wire: Vec<u8> = row.get(1)?;
                let frame = v2::decode(wire.into())?;
                ensure!(
                    frame.sha256 == sha && frame.source == self.source,
                    "compact_migration_payload_identity_mismatch"
                );
                blockzilla_stream_decoder::validate_bank_payload(&frame)?;
            }
        }
        {
            let mut statement = tx.prepare("SELECT sequence,cursor,source_cursor,payload_sha,event,affected FROM updates ORDER BY sequence")?;
            let mut rows = statement.query([])?;
            let mut last = None;
            while let Some(row) = rows.next()? {
                let sequence: u64 = row.get(0)?;
                let cursor: String = row.get(1)?;
                let source_cursor: String = row.get(2)?;
                let sha: String = row.get(3)?;
                let event: String = row.get(4)?;
                let affected: String = row.get(5)?;
                let digest =
                    hash(format!("{source_cursor}\n{sha}\n{event}\n{affected}").as_bytes());
                ensure!(
                    cursor == crate::cursor::make(&self.source.session_id, sequence, &digest),
                    "compact_migration_output_digest_mismatch"
                );
                last = Some(cursor);
            }
            if let Some(last) = last {
                ensure!(
                    saved.as_ref().is_some_and(|(_, _, output)| *output == last),
                    "compact_migration_checkpoint_mismatch"
                );
            }
        }
        tx.execute("UPDATE payloads SET projection='',bytes=length(wire)", [])?;
        tx.execute(
            "UPDATE config SET payload_mode='compact-only' WHERE id=1",
            [],
        )?;
        tx.commit()?;
        let busy: u64 = c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?;
        ensure!(busy == 0, "compact_migration_checkpoint_busy");
        Ok(())
    }
    fn payload(&self, c: &Connection, sha: &str) -> Result<Arc<SharedPayload>> {
        ensure!(
            self.payload_mode == PayloadMode::Full,
            "portable_projection_disabled_in_compact_only_mode"
        );
        if let Some(p) = self.payloads.get(sha) {
            ensure!(
                c.query_row("SELECT 1 FROM payloads WHERE sha=?", [sha], |_| Ok(true))
                    .optional()?
                    .unwrap_or(false),
                "payload_not_durable"
            );
            return Ok(p);
        }
        self.payloads.load_stored(|| {
            let (wire, text): (Vec<u8>, String) = c.query_row(
                "SELECT wire,projection FROM payloads WHERE sha=?",
                [sha],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            ensure!(hash(&wire) == sha, "stored_payload_digest_mismatch");
            let frame = v2::decode(wire.into())?;
            ensure!(frame.source == self.source, "source_changed");
            Ok((frame, text))
        })
    }
    /// Native controls need the admitted original frame, not its portable JSON.
    /// A cache miss must not materialize that much larger projection while the
    /// ordered SQLite commit is waiting for a root/confirmation dependency.
    fn native_payload(&self, c: &Connection, sha: &str) -> Result<v2::Frame> {
        if let Some(payload) = self.payloads.get(sha) {
            ensure!(
                c.query_row("SELECT 1 FROM payloads WHERE sha=?", [sha], |_| Ok(true))
                    .optional()?
                    .unwrap_or(false),
                "payload_not_durable"
            );
            return Ok(payload.frame.clone());
        }
        let wire: Vec<u8> =
            c.query_row("SELECT wire FROM payloads WHERE sha=?", [sha], |r| r.get(0))?;
        let frame = v2::decode(wire.into())?;
        ensure!(frame.sha256 == sha, "stored_payload_digest_mismatch");
        ensure!(frame.source == self.source, "source_changed");
        Ok(frame)
    }
    pub fn cursor(&self) -> Result<Option<String>> {
        Ok(self
            .connection
            .lock()
            .unwrap()
            .query_row("SELECT cursor FROM checkpoint WHERE id=1", [], |r| r.get(0))
            .optional()?)
    }
    pub fn pending_ack(&self) -> Result<Option<(String, u64)>> {
        Ok(self
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT cursor,gap_sequence FROM checkpoint WHERE id=1 AND pending_ack=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }
    pub fn acked(&self, cursor: &str, gap_sequence: u64) -> Result<()> {
        ensure!(
            v2::parse_cursor(cursor)?.0 == self.source.session_id,
            "source_changed"
        );
        let c = self.connection.lock().unwrap();
        let (current, old): (String, Option<String>) = c.query_row(
            "SELECT cursor,origin_acked FROM checkpoint WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let n = v2::parse_cursor(cursor)?.1;
        ensure!(n <= v2::parse_cursor(&current)?.1, "ack_ahead");
        let initial: String = c.query_row(
            "SELECT bootstrap_boundary FROM checkpoint WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        if cursor != current && cursor != initial {
            ensure!(
                c.query_row(
                    "SELECT 1 FROM updates WHERE source_cursor=? AND kind!='coverage_gap'",
                    [cursor],
                    |_| Ok(true)
                )
                .optional()?
                .unwrap_or(false),
                "unknown_ack_boundary"
            );
        }
        if let Some(old) = old {
            ensure!(n >= v2::parse_cursor(&old)?.1, "ack_regression");
        }
        let (current_gap, old_gap): (u64, u64) = c.query_row(
            "SELECT gap_sequence,gap_acked FROM checkpoint WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(
            gap_sequence <= current_gap && gap_sequence >= old_gap,
            "gap_ack_regression_or_ahead"
        );
        c.execute("UPDATE checkpoint SET origin_acked=?,gap_acked=?,pending_ack=CASE WHEN cursor=? AND gap_sequence=? THEN 0 ELSE 1 END WHERE id=1",params![cursor,gap_sequence,cursor,gap_sequence])?;
        Ok(())
    }
    pub fn ack_backlog(&self) -> Result<Value> {
        let c = self.connection.lock().unwrap();
        if beam_generation(&c)?.is_some() {
            return Ok(
                json!({"required":false,"pending":false,"bytes":0,"events":0,"pressure":false}),
            );
        }
        let row: Option<(String, Option<String>, u64, u64)> = c
            .query_row(
                "SELECT cursor,origin_acked,gap_sequence,gap_acked FROM checkpoint WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((cursor, acked, gaps, gap_acked)) = row else {
            return Ok(json!({"pending":false,"bytes":0,"events":0,"pressure":false}));
        };
        let sequence = acked
            .as_deref()
            .map(v2::parse_cursor)
            .transpose()?
            .map_or(0, |v| v.1);
        let predicate = "(kind!='coverage_gap' AND json_extract(event,'$.sequence')>?) OR (kind='coverage_gap' AND json_extract(event,'$.sequence')>?)";
        let count: u64 = c.query_row(
            &format!("SELECT count(*) FROM updates WHERE {predicate}"),
            params![sequence, gap_acked],
            |r| r.get(0),
        )?;
        let bytes:u64=c.query_row(&format!("SELECT coalesce(sum(bytes),0) FROM payloads WHERE sha IN(SELECT payload_sha FROM updates WHERE {predicate})"),params![sequence,gap_acked],|r|r.get(0))?;
        Ok(
            json!({"pending":acked.as_deref()!=Some(cursor.as_str()) || gaps!=gap_acked,"committedCursor":cursor,"originAckedCursor":acked,"coverageGapSequence":gaps,"originAckedGapSequence":gap_acked,"bytes":bytes,"events":count,"pressure":bytes>=64*1024*1024 || count>=256}),
        )
    }
    pub fn has_payload(&self, sha: &str) -> Result<bool> {
        Ok(self
            .connection
            .lock()
            .unwrap()
            .query_row("SELECT 1 FROM payloads WHERE sha=?", [sha], |_| Ok(true))
            .optional()?
            .unwrap_or(false))
    }
    pub fn selected_matches(&self, selected: &v2::ConfirmedObservation) -> Result<bool> {
        let c = self.connection.lock().unwrap();
        Ok(load_chain(&c)?.latest.as_ref() == Some(selected))
    }
    pub fn bootstrap(&self, b: &Bootstrap, payload: Option<&Payload>) -> Result<()> {
        let shared = payload
            .map(|p| self.payloads.materialize(p.clone()))
            .transpose()?;
        self.bootstrap_shared(b, shared)
    }
    pub fn bootstrap_shared(
        &self,
        b: &Bootstrap,
        shared: Option<Arc<SharedPayload>>,
    ) -> Result<()> {
        self.bootstrap_inner(b, shared, None)
    }
    pub fn bootstrap_beam(
        &self,
        b: &Bootstrap,
        shared: Option<Arc<SharedPayload>>,
        runtime_generation: &str,
    ) -> Result<()> {
        ensure!(
            runtime_generation.len() == 32
                && runtime_generation
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid_runtime_generation"
        );
        self.bootstrap_inner(b, shared, Some(runtime_generation))
    }
    fn bootstrap_inner(
        &self,
        b: &Bootstrap,
        shared: Option<Arc<SharedPayload>>,
        runtime_generation: Option<&str>,
    ) -> Result<()> {
        ensure!(
            b.head.source == self.source && v2::parse_cursor(&b.after)?.0 == self.source.session_id,
            "source_changed"
        );
        self.check_disk(
            shared
                .as_ref()
                .map_or(0, |p| (p.frame.wire.len() + p.text.len()) as u64),
        )?;
        let mut c = self.connection.lock().unwrap();
        let tx = c.transaction()?;
        let old: Option<String> = tx
            .query_row("SELECT cursor FROM checkpoint WHERE id=1", [], |r| r.get(0))
            .optional()?;
        match (beam_generation(&tx)?, runtime_generation) {
            (Some(saved), Some(expected)) => {
                ensure!(saved == expected, "runtime_generation_changed")
            }
            (None, Some(expected)) => {
                ensure!(
                    old.is_none(),
                    "input_policy_transition_requires_new_database"
                );
                tx.execute("INSERT INTO beam_input VALUES(1,?)", [expected])?;
            }
            (Some(_), None) => anyhow::bail!("beam_input_cannot_require_origin_ack"),
            (None, None) => {}
        }
        if let Some(p) = &shared {
            ensure!(p.frame.source == self.source, "source_changed");
            insert_payload(&tx, p)?;
        }
        if let Some(old) = old {
            ensure!(old == b.after, "bootstrap_cursor_changed");
        } else {
            if runtime_generation.is_some() {
                ensure!(
                    b.head.cursor.as_deref() == Some(b.after.as_str()),
                    "exact_initial_head_snapshot_required"
                );
            }
            let mut chain = Chain::default();
            if b.head.cursor.as_deref() == Some(b.after.as_str()) {
                if let (Some(observation), Some(p)) = (&b.head.latest_confirmed, &shared) {
                    chain.seed(observation.clone(), &p.frame)?;
                }
            }
            chain.validate(&self.source, &b.after)?;
            let output = crate::cursor::make(&self.source.session_id, 0, "-");
            tx.execute("INSERT INTO checkpoint(id,cursor,base,chain_json,pending_ack,bootstrap_boundary,origin_acked,output_cursor,gap_sequence,gap_acked) VALUES(1,?,?,?,?,?,NULL,?,0,0)",params![b.after,output,serde_json::to_string(&chain)?,if runtime_generation.is_some(){0}else{1},b.after,output])?;
        }
        tx.commit()?;
        self.payloads.committed(v2::parse_cursor(&b.after)?.1);
        Ok(())
    }
    pub fn commit(&self, d: &Delivery, payload: Option<&Payload>) -> Result<()> {
        let shared = payload
            .map(|p| self.payloads.materialize(p.clone()))
            .transpose()?;
        self.commit_shared(d, shared)
    }
    pub fn commit_shared(&self, d: &Delivery, payload: Option<Arc<SharedPayload>>) -> Result<()> {
        ensure!(d.frame.source == self.source, "source_changed");
        self.check_disk(
            payload
                .as_ref()
                .map_or(0, |p| (p.frame.wire.len() + p.text.len()) as u64),
        )?;
        let event = &d.frame.envelope.event;
        let mut c = self.connection.lock().unwrap();
        let tx = c.transaction()?;
        let current: String =
            tx.query_row("SELECT cursor FROM checkpoint WHERE id=1", [], |r| r.get(0))?;
        if current == d.frame.cursor {
            self.payloads.committed(event.sequence);
            return Ok(());
        }
        ensure!(
            v2::parse_cursor(&current)?.1 + 1 == event.sequence,
            "event_sequence_gap"
        );
        if let Some(p) = &payload {
            ensure!(p.frame.source == self.source, "source_changed");
            self.payloads.remember(p.clone())?;
            insert_payload(&tx, p)?;
        }
        let sha = if event.kind == "block" {
            &d.frame.sha256
        } else {
            event
                .payload_frame_sha256
                .as_ref()
                .context("missing_payload")?
        };
        let native_only = self.payload_mode == PayloadMode::CompactOnly
            || event.kind != "block" && self.targets.is_empty();
        let shared = if native_only {
            None
        } else {
            Some(self.payload(&tx, sha)?)
        };
        let native_frame = if native_only {
            Some(self.native_payload(&tx, sha)?)
        } else {
            None
        };
        let frame = shared
            .as_ref()
            .map(|payload| &payload.frame)
            .or(native_frame.as_ref())
            .context("missing_payload")?;
        let mut chain = load_chain(&tx)?;
        let before = chain.clone();
        if event.kind == "block" {
            chain.add_payload(&frame)?;
        } else {
            chain.apply_control(&d.frame, &frame)?;
        }
        let beam = beam_generation(&tx)?.is_some();
        if beam && event.kind == "root" {
            if let Some(root_height) = chain
                .banks
                .values()
                .filter(|b| b.rooted && !b.invalidated)
                .map(|b| b.block_height)
                .max()
            {
                let floor = root_height.saturating_sub(256);
                chain.banks.retain(|_, b| b.block_height >= floor);
                if let Some(anchor) = chain
                    .banks
                    .values()
                    .filter(|b| b.rooted && !b.invalidated)
                    .min_by_key(|b| b.block_height)
                {
                    chain.boundary = Some((anchor.bank.parent_slot, anchor.bank.parent_blockhash));
                }
            }
        }
        chain.validate(&self.source, &d.frame.cursor)?;
        let affected = json!(
            chain
                .banks
                .iter()
                .filter(
                    |(k, b)| b.invalidated && !before.banks.get(*k).is_some_and(|b| b.invalidated)
                )
                .map(|(_, b)| &b.bank)
                .collect::<Vec<_>>()
        );
        let ej = serde_json::to_value(event)?;
        let output = self.output(&tx, &ej, &affected, sha, &d.frame.cursor)?;
        if let Some(shared) = &shared {
            self.queue(
                &tx,
                &ej,
                &shared.json,
                &shared.frame.wire,
                &output,
                &d.frame.cursor,
                &affected,
            )?;
        }
        tx.execute(
            "UPDATE checkpoint SET cursor=?,chain_json=?,pending_ack=? WHERE id=1",
            params![
                d.frame.cursor,
                serde_json::to_string(&chain)?,
                if beam { 0 } else { 1 }
            ],
        )?;
        self.prune(&tx, &chain)?;
        tx.commit()?;
        drop(c);
        self.payloads.committed(event.sequence);
        self.notify.notify_waiters();
        Ok(())
    }
    pub fn commit_beam(&self, d: &Delivery, payload: Option<Arc<SharedPayload>>) -> Result<()> {
        ensure!(
            beam_generation(&self.connection.lock().unwrap())?.is_some(),
            "beam_bootstrap_required"
        );
        self.commit_shared(d, payload)
    }
    pub fn beam_signing(&self, now: u64) -> Result<Option<v2::ConfirmedObservation>> {
        let c = self.connection.lock().unwrap();
        ensure!(beam_generation(&c)?.is_some(), "beam_bootstrap_required");
        let chain = load_chain(&c)?;
        let Some(selected) = &chain.latest else {
            return Ok(None);
        };
        if chain.reconciliate
            || now < selected.observed_at_unix_ms
            || now - selected.observed_at_unix_ms > 5000
            || chain
                .banks
                .values()
                .any(|b| b.block_height >= selected.recent_blockhash.last_valid_block_height)
        {
            return Ok(None);
        }
        let cursor: String =
            c.query_row("SELECT cursor FROM checkpoint WHERE id=1", [], |r| r.get(0))?;
        chain.validate(&self.source, &cursor)?;
        Ok(Some(selected.clone()))
    }
    pub fn beam_needs_reconcile(&self) -> Result<bool> {
        Ok(load_chain(&self.connection.lock().unwrap())?.reconciliate)
    }
    pub fn reconcile_beam_head(&self, head: &v2::Head) -> Result<bool> {
        let now = blockzilla_bank_client::now_ms();
        head.validate(&self.source, now, 5000)?;
        if head.status != "live"
            || head
                .source_observed_at_unix_ms
                .is_none_or(|t| now < t || now - t > 5000)
        {
            return Ok(false);
        }
        let mut c = self.connection.lock().unwrap();
        let tx = c.transaction()?;
        ensure!(beam_generation(&tx)?.is_some(), "beam_bootstrap_required");
        let mut chain = load_chain(&tx)?;
        if chain.latest != head.latest_confirmed {
            return Ok(false);
        }
        let cursor: String =
            tx.query_row("SELECT cursor FROM checkpoint WHERE id=1", [], |r| r.get(0))?;
        if head
            .cursor
            .as_deref()
            .map(v2::parse_cursor)
            .transpose()?
            .is_none_or(|h| h.1 > v2::parse_cursor(&cursor).map(|c| c.1).unwrap_or(0))
        {
            return Ok(false);
        }
        if head
            .latest_confirmed
            .as_ref()
            .is_none_or(|h| h.event_sequence > v2::parse_cursor(&cursor).map(|c| c.1).unwrap_or(0))
        {
            return Ok(false);
        }
        chain.validate(&self.source, &cursor)?;
        chain.reconciliate = false;
        tx.execute(
            "UPDATE checkpoint SET chain_json=? WHERE id=1",
            [serde_json::to_string(&chain)?],
        )?;
        tx.commit()?;
        Ok(true)
    }
    pub fn beam_status(&self) -> Result<Value> {
        let c = self.connection.lock().unwrap();
        let generation = beam_generation(&c)?;
        let cursor: Option<String> = c
            .query_row("SELECT cursor FROM checkpoint WHERE id=1", [], |r| r.get(0))
            .optional()?;
        let chain = if cursor.is_some() {
            Some(load_chain(&c)?)
        } else {
            None
        };
        Ok(
            json!({"mode":"raw-ssh-beam-v1","runtimeGeneration":generation,"cursor":cursor,
            "originAckRequired":false,"coveragePollRequired":false,"reconciliationRequired":chain.as_ref().is_some_and(|c|c.reconciliate),
            "retainedBanks":chain.as_ref().map_or(0,|c|c.banks.len()),"archiveCoverageClaimed":false}),
        )
    }
    pub fn storage_status(&self) -> Result<Value> {
        let c = self.connection.lock().unwrap();
        let (payloads, wire, projection): (u64,u64,u64) = c.query_row(
            "SELECT count(*),coalesce(sum(length(wire)),0),coalesce(sum(bytes-length(wire)),0) FROM payloads INDEXED BY payloads_wire_bytes",
            [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        let events: u64 = c.query_row("SELECT count(*) FROM updates", [], |r| r.get(0))?;
        let boundary: Option<(String, String)> = c
            .query_row(
                "SELECT base,output_cursor FROM checkpoint WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let first: Option<String> = c
            .query_row(
                "SELECT event FROM updates ORDER BY sequence LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let last: Option<String> = c
            .query_row(
                "SELECT event FROM updates ORDER BY sequence DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let observed = |event: Option<String>| -> Option<u64> {
            serde_json::from_str::<Value>(&event?).ok()?["observed_at_unix_ms"].as_u64()
        };
        Ok(
            json!({"payloadMode":self.payload_mode.name(),"persistedPayloads":payloads,
            "persistedWireBytes":wire,"persistedProjectionBytes":projection,"chargedReplayBytes":wire+projection,
            "replayLimitBytes":self.limits.replay_bytes,"databaseLimitBytes":self.limits.database_bytes,
            "diskReserveBytes":self.disk_reserve_bytes.load(Ordering::Relaxed),"retainedEvents":events,
            "earliestAfter":boundary.as_ref().map(|b|&b.0),"latestOutputCursor":boundary.as_ref().map(|b|&b.1),
            "firstRetainedObservedAtMs":observed(first),"lastRetainedObservedAtMs":observed(last)}),
        )
    }
    fn gap(c: &Connection, target: &str, cursor: &str, error: &str) -> Result<()> {
        c.execute("UPDATE subscriptions SET state='paused',gap_start=coalesce(gap_start,?),gap_end=?,gap_count=gap_count+1,error=coalesce(error,?) WHERE id=?",params![cursor,cursor,error,target])?;
        Ok(())
    }
    pub fn output_cursor(&self) -> Result<String> {
        Ok(self.connection.lock().unwrap().query_row(
            "SELECT output_cursor FROM checkpoint WHERE id=1",
            [],
            |r| r.get(0),
        )?)
    }
    pub fn coverage_sequence(&self) -> Result<u64> {
        Ok(self.connection.lock().unwrap().query_row(
            "SELECT gap_sequence FROM checkpoint WHERE id=1",
            [],
            |r| r.get(0),
        )?)
    }
    fn output_position(&self, c: &Connection, cursor: &str) -> Result<u64> {
        let n = crate::cursor::parse(cursor, &self.source.session_id)?;
        let (latest, base): (String, String) = c.query_row(
            "SELECT output_cursor,base FROM checkpoint WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(
            n >= crate::cursor::parse(&base, &self.source.session_id)?,
            "replay_unavailable"
        );
        ensure!(
            n <= crate::cursor::parse(&latest, &self.source.session_id)?,
            "cursor_ahead"
        );
        if cursor != base && cursor != latest {
            let saved: Option<String> = c
                .query_row("SELECT cursor FROM updates WHERE sequence=?", [n], |r| {
                    r.get(0)
                })
                .optional()?;
            ensure!(saved.as_deref() == Some(cursor), "invalid_cursor");
        }
        Ok(n)
    }
    /// Cursor admission never materializes a payload or starts a decoder.
    pub fn validate_after(&self, cursor: &str) -> Result<()> {
        self.output_position(&self.connection.lock().unwrap(), cursor)
            .map(|_| ())
    }
    pub fn after(&self, cursor: &str) -> Result<Option<Record>> {
        ensure!(
            self.payload_mode == PayloadMode::Full,
            "portable_projection_disabled_in_compact_only_mode"
        );
        let (row, cached, stored) = {
            let c = self.connection.lock().unwrap();
            let n = self.output_position(&c, cursor)?;
            let row:Option<(String,String,String,String,String,String)>=c.query_row("SELECT cursor,kind,event,affected,payload_sha,source_cursor FROM updates WHERE sequence>? ORDER BY sequence LIMIT 1",[n],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional()?;
            let Some(row) = row else { return Ok(None) };
            let cached = if row.4.is_empty() {
                None
            } else {
                self.payloads.get(&row.4)
            };
            if cached.is_some() {
                ensure!(
                    c.query_row("SELECT 1 FROM payloads WHERE sha=?", [&row.4], |_| Ok(true))
                        .optional()?
                        .unwrap_or(false),
                    "payload_not_durable"
                );
            }
            let stored: Option<(Vec<u8>, String)> = if !row.4.is_empty() && cached.is_none() {
                Some(c.query_row(
                    "SELECT wire,projection FROM payloads WHERE sha=?",
                    [&row.4],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?)
            } else {
                None
            };
            (row, cached, stored)
        }; // Release SQLite before frame hashing, JSON decode or cache admission.
        let (cursor, kind, event, affected, sha, source_cursor) = row;
        let payload = if sha.is_empty() {
            None
        } else if let Some(cached) = cached {
            Some(cached)
        } else {
            let (wire, text) = stored.context("payload_unavailable")?;
            Some(self.payloads.load_stored(|| {
                ensure!(hash(&wire) == sha, "stored_payload_digest_mismatch");
                let frame = v2::decode(wire.into())?;
                ensure!(frame.source == self.source, "source_changed");
                Ok((frame, text))
            })?)
        };
        Ok(Some(Record {
            cursor,
            source_cursor,
            kind,
            event: serde_json::from_str(&event)?,
            affected: serde_json::from_str(&affected)?,
            payload,
        }))
    }
    pub fn after_native(&self, cursor: &str) -> Result<Option<NativeRecord>> {
        let (row, cached, stored) = {
            let c = self.connection.lock().unwrap();
            let n = self.output_position(&c, cursor)?;
            let row: Option<(String, String, String, String, String, String)> = c.query_row(
                "SELECT cursor,kind,event,affected,payload_sha,source_cursor FROM updates WHERE sequence>? ORDER BY sequence LIMIT 1",
                [n], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)),
            ).optional()?;
            let Some(row) = row else {
                return Ok(None);
            };
            let cached = if row.4.is_empty() {
                None
            } else {
                self.payloads.get(&row.4)
            };
            if cached.is_some() {
                ensure!(
                    c.query_row("SELECT 1 FROM payloads WHERE sha=?", [&row.4], |_| Ok(true))
                        .optional()?
                        .unwrap_or(false),
                    "payload_not_durable"
                );
            }
            let stored: Option<Vec<u8>> = if !row.4.is_empty() && cached.is_none() {
                Some(
                    c.query_row("SELECT wire FROM payloads WHERE sha=?", [&row.4], |r| {
                        r.get(0)
                    })?,
                )
            } else {
                None
            };
            (row, cached, stored)
        }; // Release SQLite before frame admission or response encoding.
        let (cursor, kind, event, affected, sha, source_cursor) = row;
        let frame = if sha.is_empty() {
            None
        } else if let Some(cached) = cached {
            Some(cached.frame.clone())
        } else {
            let frame = v2::decode(stored.context("payload_unavailable")?.into())?;
            ensure!(frame.sha256 == sha, "stored_payload_digest_mismatch");
            ensure!(frame.source == self.source, "source_changed");
            Some(frame)
        };
        Ok(Some(NativeRecord {
            cursor,
            source_cursor,
            kind,
            event: serde_json::from_str(&event)?,
            affected: serde_json::from_str(&affected)?,
            frame,
        }))
    }
    fn output(
        &self,
        c: &Connection,
        event: &Value,
        affected: &Value,
        sha: &str,
        source_cursor: &str,
    ) -> Result<String> {
        let text = serde_json::to_string(event)?;
        let affected = serde_json::to_string(affected)?;
        c.execute("INSERT INTO updates(cursor,kind,event,affected,payload_sha,source_cursor) VALUES(?,?,?,?,?,?)",params![format!("pending:{source_cursor}"),event["kind"].as_str().context("event_kind_missing")?,text,affected,sha,source_cursor])?;
        let sequence = c.last_insert_rowid() as u64;
        let digest = hash(format!("{source_cursor}\n{sha}\n{text}\n{affected}").as_bytes());
        let output = crate::cursor::make(&self.source.session_id, sequence, &digest);
        c.execute(
            "UPDATE updates SET cursor=? WHERE sequence=?",
            params![output, sequence],
        )?;
        c.execute(
            "UPDATE checkpoint SET output_cursor=? WHERE id=1",
            [&output],
        )?;
        Ok(output)
    }
    fn queue(
        &self,
        c: &Connection,
        event: &Value,
        payload: &Value,
        wire: &[u8],
        output: &str,
        source_cursor: &str,
        affected: &Value,
    ) -> Result<()> {
        let kind = event["kind"].as_str().context("event_kind_missing")?;
        for target in &self.targets {
            let state: String = c.query_row(
                "SELECT state FROM subscriptions WHERE id=?",
                [&target.id],
                |r| r.get(0),
            )?;
            if state != "active" {
                Self::gap(c, &target.id, output, "subscription_paused")?;
                continue;
            }
            if kind != "coverage_gap" && !target.kinds.iter().any(|v| v == kind) {
                continue;
            }
            let Some(body) = projection::render(
                event,
                &self.source,
                payload,
                wire,
                output,
                source_cursor,
                affected,
                target.view,
                &target.filter,
            )?
            else {
                continue;
            };
            let body = serde_json::to_string(&body)?;
            let(count,bytes):(u64,u64)=c.query_row("SELECT count(*),coalesce(sum(length(body)),0) FROM outbox WHERE target=? AND state!='acked'",[&target.id],|r|Ok((r.get(0)?,r.get(1)?)))?;
            if count >= target.queue_events
                || bytes.saturating_add(body.len() as u64) > target.queue_bytes
            {
                Self::gap(c, &target.id, output, "outbox_quota")?;
                continue;
            }
            let id =
                hash(format!("{}\n{}\n{output}", self.source.session_id, target.id).as_bytes());
            c.execute(
                "INSERT INTO outbox(delivery_id,target,cursor,body) VALUES(?,?,?,?)",
                params![id, target.id, output, body],
            )?;
        }
        Ok(())
    }
    fn prune(&self, c: &Connection, chain: &Chain) -> Result<()> {
        let selected = chain
            .latest
            .as_ref()
            .map(|v| v.payload_frame_sha256.as_str())
            .unwrap_or("");
        loop {
            let(count,bytes):(u64,u64)=c.query_row("SELECT (SELECT count(*) FROM updates),(SELECT coalesce(sum(bytes),0) FROM payloads)",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
            if count <= self.limits.replay_events && bytes <= self.limits.replay_bytes {
                break;
            }
            let oldest: Option<(u64, String)> = c
                .query_row(
                    "SELECT sequence,cursor FROM updates ORDER BY sequence LIMIT 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((sequence, cursor)) = oldest else {
                anyhow::bail!("single_payload_exceeds_replay_budget")
            };
            c.execute("DELETE FROM updates WHERE sequence=?", [sequence])?;
            c.execute("UPDATE checkpoint SET base=? WHERE id=1", [cursor])?;
            c.execute(
                "DELETE FROM payloads WHERE sha NOT IN(SELECT payload_sha FROM updates) AND sha!=?",
                [selected],
            )?;
        }
        c.execute("DELETE FROM outbox WHERE state='acked' AND id NOT IN(SELECT id FROM outbox WHERE state='acked' ORDER BY id DESC LIMIT 8192)",[])?;
        Ok(())
    }
    pub fn commit_coverage(&self, page: &blockzilla_bank_client::CoveragePage) -> Result<()> {
        ensure!(
            page.source == self.source && page.producer_generation == self.producer_generation,
            "source_or_generation_changed"
        );
        if page.gaps.is_empty() {
            ensure!(
                self.coverage_sequence()? >= page.base_sequence,
                "coverage_replay_unavailable"
            );
            return Ok(());
        }
        let mut c = self.connection.lock().unwrap();
        let tx = c.transaction()?;
        let mut after: u64 =
            tx.query_row("SELECT gap_sequence FROM checkpoint WHERE id=1", [], |r| {
                r.get(0)
            })?;
        ensure!(after >= page.base_sequence, "coverage_replay_unavailable");
        for row in &page.gaps {
            if row.sequence <= after {
                continue;
            }
            let source_cursor = format!("coverage:{}", row.sequence);
            let event = json!({"kind":"coverage_gap","sequence":row.sequence,"processed_sequence":row.processed_sequence,"gap":row.gap});
            let affected = json!([]);
            let output = self.output(&tx, &event, &affected, "", &source_cursor)?;
            self.queue(
                &tx,
                &event,
                &Value::Null,
                &[],
                &output,
                &source_cursor,
                &affected,
            )?;
            after = row.sequence;
        }
        tx.execute("UPDATE checkpoint SET gap_sequence=?,pending_ack=CASE WHEN gap_acked<? THEN 1 ELSE pending_ack END WHERE id=1",params![after,after])?;
        self.prune(&tx, &load_chain(&tx)?)?;
        tx.commit()?;
        drop(c);
        self.notify.notify_waiters();
        Ok(())
    }
    pub fn subscriptions(&self) -> Result<Value> {
        let c = self.connection.lock().unwrap();
        let mut q=c.prepare("SELECT s.id,s.state,s.gap_start,s.gap_end,s.gap_count,s.error,(SELECT count(*) FROM outbox WHERE target=s.id AND state!='acked'),(SELECT coalesce(sum(length(body)),0) FROM outbox WHERE target=s.id AND state!='acked') FROM subscriptions s ORDER BY s.id")?;
        let rows=q.query_map([],|r|Ok(json!({"id":r.get::<_,String>(0)?,"state":r.get::<_,String>(1)?,"gapStart":r.get::<_,Option<String>>(2)?,"gapEnd":r.get::<_,Option<String>>(3)?,"skippedEvents":r.get::<_,u64>(4)?,"error":r.get::<_,Option<String>>(5)?,"queuedEvents":r.get::<_,u64>(6)?,"queuedBytes":r.get::<_,u64>(7)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(json!(rows))
    }
    pub fn next_job(&self, target: &WebhookTarget, now: u64) -> Result<Option<Job>> {
        let c = self.connection.lock().unwrap();
        let row:Option<(String,String,u32,String,u64)>=c.query_row("SELECT delivery_id,body,attempts,state,next_ms FROM outbox WHERE target=? AND state!='acked' ORDER BY id LIMIT 1",[&target.id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
        Ok(row.filter(|r| r.3 == "pending" && r.4 <= now).map(
            |(delivery_id, body, attempts, _, _)| Job {
                delivery_id,
                body,
                attempts,
                target: target.clone(),
            },
        ))
    }
    pub fn finish_job(&self, job: &Job, success: bool, error: &str, now: u64) -> Result<()> {
        let mut c = self.connection.lock().unwrap();
        let tx = c.transaction()?;
        if success {
            tx.execute(
                "UPDATE outbox SET state='acked',error=NULL WHERE delivery_id=?",
                [&job.delivery_id],
            )?;
        } else {
            let attempts = job.attempts + 1;
            let failed = attempts >= job.target.retry_limit;
            let next = now + 1000u64.saturating_mul(1u64 << attempts.min(6)).min(60000);
            tx.execute(
                "UPDATE outbox SET attempts=?,next_ms=?,state=?,error=? WHERE delivery_id=?",
                params![
                    attempts,
                    next,
                    if failed { "failed" } else { "pending" },
                    error,
                    job.delivery_id
                ],
            )?;
            if failed {
                tx.execute(
                    "UPDATE subscriptions SET state='paused',error='retry_exhausted' WHERE id=?",
                    [&job.target.id],
                )?;
            }
        }
        tx.commit()?;
        self.notify.notify_waiters();
        Ok(())
    }
    pub fn retry_job(&self, id: &str) -> Result<()> {
        ensure!(v2::is_digest(id), "invalid_delivery_id");
        let c = self.connection.lock().unwrap();
        ensure!(c.execute("UPDATE outbox SET state='pending',attempts=0,next_ms=0,error=NULL WHERE delivery_id=? AND state='failed'",[id])?==1,"failed_job_not_found");
        Ok(())
    }
    pub fn resume(&self, id: &str, accept_gap: bool) -> Result<()> {
        ensure!(accept_gap, "explicit_gap_ack_required");
        let mut c = self.connection.lock().unwrap();
        let tx = c.transaction()?;
        let pending: u64 = tx.query_row(
            "SELECT count(*) FROM outbox WHERE target=? AND state!='acked'",
            [id],
            |r| r.get(0),
        )?;
        ensure!(pending == 0, "queued_jobs_must_drain_first");
        let (start, end, count): (Option<String>, Option<String>, u64) = tx.query_row(
            "SELECT gap_start,gap_end,gap_count FROM subscriptions WHERE id=? AND state='paused'",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        if let Some(end) = end {
            let cursor = format!("gap:{end}");
            let body = serde_json::to_string(
                &json!({"schema":"blockzilla-webhook-gap-v1","source":self.source,"fromCursor":start,"throughCursor":end,"skippedEvents":count,"recovery":"operator_acknowledged_gap"}),
            )?;
            let delivery = hash(format!("{}\n{id}\n{cursor}", self.source.session_id).as_bytes());
            tx.execute(
                "INSERT INTO outbox(delivery_id,target,cursor,body) VALUES(?,?,?,?)",
                params![delivery, id, cursor, body],
            )?;
        }
        tx.execute("UPDATE subscriptions SET state='active',gap_start=NULL,gap_end=NULL,gap_count=0,error=NULL WHERE id=?",[id])?;
        tx.commit()?;
        self.notify.notify_waiters();
        Ok(())
    }
}

#[cfg(test)]
#[path = "beam_store_tests.rs"]
mod beam_store_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Filter, View};
    use blockzilla_bank_stream_v2::{Head, fixtures::*};
    fn target() -> WebhookTarget {
        serde_json::from_value(json!({"id":"local-test","url":"http://127.0.0.1:1/","kinds":["block","root","invalidate"],"queue_events":1})).unwrap()
    }
    fn bootstrap() -> Bootstrap {
        let base = v2::cursor(&source().session_id, 0, "-");
        Bootstrap {
            after: base.clone(),
            head: Head {
                schema: v2::HEAD.into(),
                profile: v2::PROFILE.into(),
                source: source(),
                cursor: Some(base.clone()),
                earliest_after: Some(base),
                status: "starting".into(),
                sampled_at_unix_ms: 1000,
                source_observed_at_unix_ms: None,
                source_lag_ms: None,
                latest_confirmed: None,
            },
            control: None,
            payload: None,
        }
    }
    fn open(path: &Path, targets: Vec<WebhookTarget>) -> Arc<Store> {
        let store = Store::open(
            path,
            source(),
            "fixture-generation".into(),
            targets,
            Limits::default(),
        )
        .unwrap();
        store.bootstrap(&bootstrap(), None).unwrap();
        store
    }
    // These records test the atomic storage boundary after transport/decoder
    // admission. Separate real-frame tests cover the portable payload decoder.
    fn payload(sequence: u64, slot: u64) -> Payload {
        let frame = block(sequence, slot, slot, slot - 1, slot);
        let key = bs58::encode([8; 32]).into_string();
        Payload {
            frame,
            json: json!({"blocks":[{"slot":slot,"bankId":slot,"blockhash":bs58::encode([slot as u8;32]).into_string(),"parentSlot":slot-1,"parentBlockhash":bs58::encode([(slot-1)as u8;32]).into_string(),"blockHeight":slot,"transactionCount":1,"transactions":[{"index":0,"signature":bs58::encode([7;64]).into_string(),"signatures":[bs58::encode([7;64]).into_string()],"success":false,"err":{"InstructionError":[0,{"Custom":2}]},"accountKeys":[key],"topLevelPrograms":[],"innerPrograms":[]}]}]}),
        }
    }
    fn commit(store: &Store, p: Payload) {
        let d = Delivery {
            frame: p.frame.clone(),
            dependency: None,
        };
        store.commit(&d, Some(&p)).unwrap();
    }
    #[test]
    fn payload_accounting_uses_covering_index_after_existing_database_reopen() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("sidecar.sqlite");
        let store = open(&path, vec![]);
        let mut p = payload(1, 9);
        p.json["testPadding"] = json!("x".repeat(256 * 1024));
        commit(&store, p);
        let cursor = store.cursor().unwrap().unwrap();
        let before: (String, String, u64) = store
            .connection
            .lock()
            .unwrap()
            .query_row("SELECT sha,projection,bytes FROM payloads", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        // Model an existing database from the release before this index.
        store
            .connection
            .lock()
            .unwrap()
            .execute_batch("DROP INDEX payloads_bytes;")
            .unwrap();
        drop(store);
        let store = Store::open(
            &path,
            source(),
            "fixture-generation".into(),
            vec![],
            Limits::default(),
        )
        .unwrap();
        assert_eq!(store.cursor().unwrap().unwrap(), cursor);
        let c = store.connection.lock().unwrap();
        let after: (String, String, u64) = c
            .query_row("SELECT sha,projection,bytes FROM payloads", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!(after, before);
        let total: u64 = c
            .query_row("SELECT coalesce(sum(bytes),0) FROM payloads", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(total, before.2);
        let plan = c
            .prepare("EXPLAIN QUERY PLAN SELECT coalesce(sum(bytes),0) FROM payloads")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            plan.iter()
                .any(|line| line.contains("USING COVERING INDEX payloads_bytes")),
            "payload byte accounting must not read wire/projection overflow pages: {plan:?}"
        );
    }
    #[test]
    fn evicted_payload_for_a_late_control_is_reloaded_from_verified_durable_bytes() {
        let t = tempfile::tempdir().unwrap();
        let store = open(&t.path().join("sidecar.sqlite"), vec![]);
        let base = store.output_cursor().unwrap();
        let p = payload(1, 9);
        let frame = p.frame.clone();
        commit(&store, p);
        let original = store.after(&base).unwrap().unwrap();
        store.payloads.clear_resident();
        assert!(store.payloads.get(&frame.sha256).is_none());
        let root = control(&frame, 2, "root", 1000);
        store
            .commit(
                &Delivery {
                    frame: root,
                    dependency: None,
                },
                None,
            )
            .unwrap();
        assert!(
            store.payloads.get(&frame.sha256).is_none(),
            "an empty-webhook native control must not reload the portable projection"
        );
        let next = store.after(&original.cursor).unwrap().unwrap();
        assert_eq!(original.payload_json(), next.payload_json());
        assert_eq!(original.wire(), next.wire());
        assert_eq!(next.kind, "root");
        assert!(!Arc::ptr_eq(
            original.payload.as_ref().unwrap(),
            next.payload.as_ref().unwrap()
        ));
    }
    #[test]
    fn configured_webhook_control_still_materializes_projection_and_queues_full_results() {
        let t = tempfile::tempdir().unwrap();
        let mut configured = target();
        configured.queue_events = 10;
        let store = open(&t.path().join("sidecar.sqlite"), vec![configured]);
        let p = payload(1, 9);
        let frame = p.frame.clone();
        commit(&store, p);
        store.payloads.clear_resident();
        assert!(store.payloads.get(&frame.sha256).is_none());
        let root = control(&frame, 2, "root", 1000);
        store
            .commit(
                &Delivery {
                    frame: root.clone(),
                    dependency: None,
                },
                None,
            )
            .unwrap();
        assert!(
            store.payloads.get(&frame.sha256).is_some(),
            "configured webhook needs its existing portable projection"
        );
        let bodies: Vec<String> = store
            .connection
            .lock()
            .unwrap()
            .prepare("SELECT body FROM outbox ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(bodies.len(), 2);
        let body: Value = serde_json::from_str(&bodies[1]).unwrap();
        assert_eq!(body["kind"], "root");
        assert_eq!(body["event"]["commitment"], "finalized");
        assert_eq!(body["block"]["transactions"][0]["success"], false);
        assert_eq!(store.cursor().unwrap().unwrap(), root.cursor);
    }
    #[test]
    fn cursor_outbox_and_projection_roll_back_together() {
        let t = tempfile::tempdir().unwrap();
        let store = open(&t.path().join("sidecar.sqlite"), vec![target()]);
        let base = store.cursor().unwrap().unwrap();
        store.connection.lock().unwrap().execute_batch("CREATE TRIGGER reject_outbox BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'injected_commit_failure'); END;").unwrap();
        let p = payload(1, 9);
        assert!(
            store
                .commit(
                    &Delivery {
                        frame: p.frame.clone(),
                        dependency: None
                    },
                    Some(&p)
                )
                .is_err()
        );
        assert_eq!(store.cursor().unwrap().unwrap(), base);
        assert!(!store.has_payload(&p.frame.sha256).unwrap());
        assert!(store.next_job(&target(), 10000).unwrap().is_none());
        store
            .connection
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER reject_outbox;")
            .unwrap();
        commit(&store, p);
        assert_ne!(store.cursor().unwrap().unwrap(), base);
        assert!(store.next_job(&target(), 10000).unwrap().is_some());
    }
    #[test]
    fn subscription_quota_pauses_only_that_destination_and_persists_gap() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("sidecar.sqlite");
        let store = open(&path, vec![target()]);
        commit(&store, payload(1, 9));
        let first = store.next_job(&target(), 10000).unwrap().unwrap();
        commit(&store, payload(2, 10));
        commit(&store, payload(3, 11));
        assert_eq!(
            v2::parse_cursor(&store.cursor().unwrap().unwrap())
                .unwrap()
                .1,
            3
        );
        let status = store.subscriptions().unwrap();
        assert_eq!(status[0]["state"], "paused");
        assert_eq!(status[0]["skippedEvents"], 2);
        assert_eq!(status[0]["queuedEvents"], 1);
        let body = first.body.clone();
        let id = first.delivery_id.clone();
        drop(store);
        let store = Store::open(
            &path,
            source(),
            "fixture-generation".into(),
            vec![target()],
            Limits::default(),
        )
        .unwrap();
        let again = store.next_job(&target(), 10000).unwrap().unwrap();
        assert_eq!(again.delivery_id, id);
        assert_eq!(again.body, body);
        assert!(store.pending_ack().unwrap().is_some());
        store.finish_job(&again, true, "", 10000).unwrap();
        assert!(store.resume("local-test", false).is_err());
        store.resume("local-test", true).unwrap();
        let gap = store.next_job(&target(), 10000).unwrap().unwrap();
        let gap: Value = serde_json::from_str(&gap.body).unwrap();
        assert_eq!(gap["schema"], "blockzilla-webhook-gap-v1");
        assert_eq!(gap["skippedEvents"], 2);
    }
    #[test]
    fn independent_ack_frontiers_and_sparse_coverage_share_output_order() {
        let t = tempfile::tempdir().unwrap();
        let store = open(&t.path().join("sidecar.sqlite"), vec![]);
        let base = store.output_cursor().unwrap();
        commit(&store, payload(1, 9));
        let input = store.cursor().unwrap().unwrap();
        let page=blockzilla_bank_client::CoveragePage{schema:"blockzilla-coverage-gaps-v1".into(),source:source(),producer_generation:"fixture-generation".into(),base_sequence:0,latest_sequence:91,gaps:[7,91].map(|n|blockzilla_bank_client::CoverageGap{sequence:n,processed_sequence:n,gap:json!({"schema":"hivezilla-incomplete-bank-gap-v1","producer_generation":"fixture-generation","gap_sequence":n,"reason":"expired"})}).into()};
        store.commit_coverage(&page).unwrap();
        assert_eq!(store.cursor().unwrap().unwrap(), input);
        assert_eq!(store.coverage_sequence().unwrap(), 91);
        assert_eq!(
            crate::cursor::parse(&store.output_cursor().unwrap(), &source().session_id).unwrap(),
            3
        );
        let bank = store.after(&base).unwrap().unwrap();
        let first = store.after(&bank.cursor).unwrap().unwrap();
        let last = store.after(&first.cursor).unwrap().unwrap();
        assert_eq!(first.kind, "coverage_gap");
        assert_eq!(last.event["sequence"], 91);
        assert!(last.wire().is_empty());
        store.acked(&input, 7).unwrap();
        assert!(store.pending_ack().unwrap().is_some());
        store.acked(&input, 91).unwrap();
        assert!(store.pending_ack().unwrap().is_none());
        assert!(store.acked(&input, 7).is_err());
        assert!(
            store
                .acked(&v2::cursor(&source().session_id, 2, &"a".repeat(64)), 91)
                .is_err()
        );
    }
    #[test]
    fn invalidation_preserves_descendant_undo_and_root_rejection() {
        let t = tempfile::tempdir().unwrap();
        let store = open(&t.path().join("sidecar.sqlite"), vec![]);
        let p = payload(1, 9);
        let parent = p.frame.clone();
        commit(&store, p);
        commit(&store, payload(2, 10));
        let before = store.output_cursor().unwrap();
        let invalidate = control(&parent, 3, "invalidate", 1000);
        store
            .commit(
                &Delivery {
                    frame: invalidate,
                    dependency: None,
                },
                None,
            )
            .unwrap();
        let output = store.after(&before).unwrap().unwrap();
        assert_eq!(output.affected.as_array().unwrap().len(), 2);
        let t = tempfile::tempdir().unwrap();
        let store = open(&t.path().join("sidecar.sqlite"), vec![]);
        let p = payload(1, 9);
        let parent = p.frame.clone();
        commit(&store, p);
        let root = control(&parent, 2, "root", 1000);
        store
            .commit(
                &Delivery {
                    frame: root.clone(),
                    dependency: None,
                },
                None,
            )
            .unwrap();
        let invalid = control(&parent, 3, "invalidate", 1000);
        assert!(
            store
                .commit(
                    &Delivery {
                        frame: invalid,
                        dependency: None
                    },
                    None
                )
                .is_err()
        );
        assert_eq!(store.cursor().unwrap().unwrap(), root.cursor);
    }
    #[test]
    fn retry_exhaustion_and_source_generation_changes_are_explicit() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("sidecar.sqlite");
        let mut target = target();
        target.retry_limit = 1;
        let store = open(&path, vec![target.clone()]);
        commit(&store, payload(1, 9));
        let job = store.next_job(&target, 0).unwrap().unwrap();
        store
            .finish_job(&job, false, "webhook_http_503", 0)
            .unwrap();
        assert!(store.next_job(&target, 100000).unwrap().is_none());
        assert_eq!(
            store.subscriptions().unwrap()[0]["error"],
            "retry_exhausted"
        );
        store.retry_job(&job.delivery_id).unwrap();
        assert_eq!(
            store.next_job(&target, 0).unwrap().unwrap().delivery_id,
            job.delivery_id
        );
        drop(store);
        assert!(
            Store::open(
                &path,
                source(),
                "replacement".into(),
                vec![target],
                Limits::default()
            )
            .is_err()
        );
    }
    #[test]
    fn projections_keep_failed_outcomes_and_exact_canonical_frame() {
        let p = payload(1, 9);
        let event = serde_json::to_value(&p.frame.envelope.event).unwrap();
        let result = projection::render(
            &event,
            &source(),
            &p.json,
            &p.frame.wire,
            "output",
            "input",
            &json!([]),
            View::Blocks,
            &Filter::default(),
        )
        .unwrap()
        .unwrap();
        use base64::Engine;
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(result["compactFrameBase64"].as_str().unwrap())
                .unwrap(),
            p.frame.wire.as_ref()
        );
        assert_eq!(result["block"]["transactions"][0]["success"], false);
        let filter = Filter {
            failed: Some(false),
            ..Default::default()
        };
        assert!(
            projection::render(
                &event,
                &source(),
                &p.json,
                &p.frame.wire,
                "output",
                "input",
                &json!([]),
                View::Signatures,
                &filter
            )
            .unwrap()
            .is_none()
        );
    }
}

#[cfg(test)]
mod bootstrap_tests {
    use super::*;
    use blockzilla_bank_stream_v2::{Head, fixtures::*};
    #[test]
    fn earlier_explicit_join_keeps_head_dependencies_as_proofs_only() {
        let t = tempfile::tempdir().unwrap();
        let store = Store::open(
            &t.path().join("sidecar.sqlite"),
            source(),
            "fixture-generation".into(),
            vec![],
            Limits::default(),
        )
        .unwrap();
        let frame = block(1, 9, 1, 8, 9);
        let root = control(&frame, 2, "root", 1000);
        let selected = v2::ConfirmedObservation::from_frame(&root).unwrap();
        let base = v2::cursor(&source().session_id, 0, "-");
        let bootstrap = Bootstrap {
            after: base.clone(),
            head: Head {
                schema: v2::HEAD.into(),
                profile: v2::PROFILE.into(),
                source: source(),
                cursor: Some(root.cursor.clone()),
                earliest_after: Some(base.clone()),
                status: "live".into(),
                sampled_at_unix_ms: 1000,
                source_observed_at_unix_ms: Some(1000),
                source_lag_ms: Some(0),
                latest_confirmed: Some(selected.clone()),
            },
            control: Some(root),
            payload: Some(frame.clone()),
        };
        store
            .bootstrap(
                &bootstrap,
                Some(&Payload {
                    frame,
                    json: json!({"blocks":[]}),
                }),
            )
            .unwrap();
        assert_eq!(store.cursor().unwrap().unwrap(), base);
        assert!(!store.selected_matches(&selected).unwrap());
        assert_eq!(
            crate::cursor::parse(&store.output_cursor().unwrap(), &source().session_id).unwrap(),
            0
        );
    }
}
