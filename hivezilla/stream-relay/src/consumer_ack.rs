//! Durable local consumer acknowledgements. They authorize no deletion alone.
use anyhow::{Context, Result, ensure};
use blockzilla_bank_stream_v2::{self as v2, SourceIdentity};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path, time::Duration};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub schema: String,
    pub source: SourceIdentity,
    pub consumers: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: String,
    pub consumer_id: String,
    pub source: SourceIdentity,
    pub cursor: String,
    #[serde(default)]
    pub coverage_gap_sequence: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema: String,
    pub state: String,
    pub consumer_id: String,
    pub source: SourceIdentity,
    pub cursor: String,
    pub coverage_gap_sequence: u64,
}
pub fn consumer_id(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}
fn open(root: &Path) -> Result<Connection> {
    let path = root.join("consumer-acks.sqlite");
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            ensure!(metadata.file_type().is_file(), "unsafe_ack_database");
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                ensure!(
                    metadata.nlink() == 1
                        && metadata.uid() == unsafe { libc::geteuid() }
                        && metadata.mode() & 0o022 == 0,
                    "unsafe_ack_database"
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let db = Connection::open(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    db.busy_timeout(Duration::from_secs(2))?;
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
      CREATE TABLE IF NOT EXISTS ack_binding(id INTEGER PRIMARY KEY CHECK(id=1),json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS consumer_acks(consumer_id TEXT PRIMARY KEY,sequence INTEGER NOT NULL,cursor TEXT NOT NULL,gap_sequence INTEGER NOT NULL,updated_unix_ms INTEGER NOT NULL);")?;
    Ok(db)
}
pub fn configure(root: &Path, source: &SourceIdentity, consumers: &[String]) -> Result<()> {
    source.validate()?;
    ensure!(
        !consumers.is_empty() && consumers.len() <= 64,
        "invalid_ack_consumers"
    );
    let mut ids = consumers.to_vec();
    ids.sort();
    ids.dedup();
    ensure!(
        ids.len() == consumers.len() && ids.iter().all(|v| consumer_id(v)),
        "invalid_ack_consumers"
    );
    let binding = Configuration {
        schema: "blockzilla-consumer-ack-config-v1".into(),
        source: source.clone(),
        consumers: ids,
    };
    let mut db = open(root)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let previous: Option<String> = tx
        .query_row("SELECT json FROM ack_binding WHERE id=1", [], |r| r.get(0))
        .optional()?;
    if let Some(previous) = previous {
        ensure!(
            serde_json::from_str::<Configuration>(&previous)? == binding,
            "ack_binding_changed"
        );
    } else {
        tx.execute(
            "INSERT INTO ack_binding VALUES(1,?1)",
            [serde_json::to_string(&binding)?],
        )?;
    }
    tx.commit()?;
    Ok(())
}
pub fn configuration(root: &Path) -> Result<Configuration> {
    ensure!(
        root.join("consumer-acks.sqlite").is_file(),
        "ack_not_configured"
    );
    let db = open(root)?;
    Ok(serde_json::from_str(&db.query_row(
        "SELECT json FROM ack_binding WHERE id=1",
        [],
        |r| r.get::<_, String>(0),
    )?)?)
}
/// The validators check committed origin rows, not client-supplied assertions.
pub fn submit(
    root: &Path,
    expected: &SourceIdentity,
    request: Request,
    validate_cursor: impl FnOnce(&str) -> Result<()>,
    validate_gap: impl FnOnce(u64) -> Result<()>,
) -> Result<Receipt> {
    ensure!(
        request.schema == "blockzilla-consumer-ack-v1" && consumer_id(&request.consumer_id),
        "invalid_consumer_ack"
    );
    ensure!(&request.source == expected, "source_changed");
    let (session, sequence, _) = v2::parse_cursor(&request.cursor)?;
    ensure!(
        session == expected.session_id && request.coverage_gap_sequence <= v2::SAFE,
        "source_changed"
    );
    ensure!(
        root.join("consumer-acks.sqlite").try_exists()?,
        "ack_not_configured"
    );
    let mut db = open(root)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let binding: Configuration = serde_json::from_str(&tx.query_row(
        "SELECT json FROM ack_binding WHERE id=1",
        [],
        |r| r.get::<_, String>(0),
    )?)?;
    ensure!(binding.source == *expected, "ack_binding_changed");
    ensure!(
        binding.consumers.contains(&request.consumer_id),
        "unknown_consumer"
    );
    let previous: Option<(u64, String, u64)> = tx
        .query_row(
            "SELECT sequence,cursor,gap_sequence FROM consumer_acks WHERE consumer_id=?1",
            [&request.consumer_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let (old_sequence, old_gap) = if let Some((old, cursor, gap)) = previous {
        ensure!(
            sequence >= old && request.coverage_gap_sequence >= gap,
            "ack_regressed"
        );
        if sequence == old {
            ensure!(request.cursor == cursor, "ack_cursor_conflict");
        }
        (Some(old), Some(gap))
    } else {
        (None, None)
    };
    if old_sequence != Some(sequence) {
        validate_cursor(&request.cursor).context("ack_cursor_not_committed")?;
    }
    if old_gap != Some(request.coverage_gap_sequence) {
        validate_gap(request.coverage_gap_sequence).context("ack_gap_not_committed")?;
    }
    tx.execute("INSERT INTO consumer_acks VALUES(?1,?2,?3,?4,?5) ON CONFLICT(consumer_id) DO UPDATE SET sequence=excluded.sequence,cursor=excluded.cursor,gap_sequence=excluded.gap_sequence,updated_unix_ms=excluded.updated_unix_ms",
        params![request.consumer_id,sequence,request.cursor,request.coverage_gap_sequence,crate::store::now_ms()])?;
    tx.commit()?;
    Ok(Receipt {
        schema: "blockzilla-consumer-ack-receipt-v1".into(),
        state: "ACKED".into(),
        consumer_id: request.consumer_id,
        source: request.source,
        cursor: request.cursor,
        coverage_gap_sequence: request.coverage_gap_sequence,
    })
}
pub fn required_frontier(root: &Path) -> Result<(u64, u64)> {
    let config = configuration(root)?;
    let db = open(root)?;
    let mut sequence = u64::MAX;
    let mut gap = u64::MAX;
    for id in config.consumers {
        let row: Option<(u64, u64)> = db
            .query_row(
                "SELECT sequence,gap_sequence FROM consumer_acks WHERE consumer_id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((s, g)) = row else {
            return Ok((0, 0));
        };
        sequence = sequence.min(s);
        gap = gap.min(g);
    }
    Ok((sequence, gap))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn source() -> SourceIdentity {
        v2::fixtures::source()
    }
    fn request(n: u64, gap: u64) -> Request {
        Request {
            schema: "blockzilla-consumer-ack-v1".into(),
            consumer_id: "sidecar-primary".into(),
            source: source(),
            cursor: v2::cursor(
                &source().session_id,
                n,
                if n == 0 {
                    "-"
                } else {
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                },
            ),
            coverage_gap_sequence: gap,
        }
    }
    #[test]
    fn ack_is_durable_monotonic_and_idempotent_after_origin_retirement() {
        let t = tempfile::tempdir().unwrap();
        configure(t.path(), &source(), &["sidecar-primary".into()]).unwrap();
        submit(t.path(), &source(), request(4, 2), |_| Ok(()), |_| Ok(())).unwrap();
        let receipt = submit(
            t.path(),
            &source(),
            request(4, 2),
            |_| panic!("duplicate must not require retired frame"),
            |_| panic!("duplicate must not require retired gap"),
        )
        .unwrap();
        assert_eq!(receipt.coverage_gap_sequence, 2);
        assert_eq!(required_frontier(t.path()).unwrap(), (4, 2));
        assert!(submit(t.path(), &source(), request(3, 2), |_| Ok(()), |_| Ok(())).is_err());
        assert!(submit(t.path(), &source(), request(4, 1), |_| Ok(()), |_| Ok(())).is_err());
        assert!(
            submit(
                t.path(),
                &source(),
                request(5, 2),
                |_| anyhow::bail!("future"),
                |_| Ok(())
            )
            .is_err()
        );
        assert_eq!(required_frontier(t.path()).unwrap(), (4, 2));
    }
    #[test]
    fn all_registered_consumers_are_required_and_bindings_cannot_change() {
        let t = tempfile::tempdir().unwrap();
        configure(
            t.path(),
            &source(),
            &["sidecar-primary".into(), "other".into()],
        )
        .unwrap();
        submit(t.path(), &source(), request(4, 0), |_| Ok(()), |_| Ok(())).unwrap();
        assert_eq!(required_frontier(t.path()).unwrap(), (0, 0));
        assert!(configure(t.path(), &source(), &["sidecar-primary".into()]).is_err());
        let mut bad = request(5, 0);
        bad.consumer_id = "unknown".into();
        assert!(submit(t.path(), &source(), bad, |_| Ok(()), |_| Ok(())).is_err());
        let mut bad = request(5, 0);
        bad.source.node_identity = "wrong".into();
        assert!(submit(t.path(), &source(), bad, |_| Ok(()), |_| Ok(())).is_err());
    }
}
