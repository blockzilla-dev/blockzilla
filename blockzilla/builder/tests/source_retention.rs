use blockzilla_bank_stream_v2::SourceIdentity;
use hivezilla_direct_agave::{
    event::digest,
    journal::{Config, Journal},
    retention::{SOURCE_ACK_SCHEMA, SourceAckTicket, source_ack_proof, write_source_ack},
    source_retention::{self, SOURCE_RETIREMENT_FILE},
};
use rusqlite::{Connection, params};
use std::{fs, os::unix::fs::MetadataExt, path::Path, time::Duration};

fn source() -> SourceIdentity {
    SourceIdentity {
        genesis_hash: "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d".into(),
        node_identity: "11111111111111111111111111111111".into(),
        agave_revision: "fixture-revision".into(),
        session_id: "00000000000000000000000000000001-1".into(),
    }
}

fn writer(path: &Path) -> Connection {
    let db = Connection::open(path).unwrap();
    db.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA wal_autocheckpoint=0;",
    )
    .unwrap();
    db
}

struct Fixture {
    directory: tempfile::TempDir,
    source: Connection,
    producer: Connection,
    ticket: SourceAckTicket,
}
impl Fixture {
    fn new(rows: u64, frontier: u64) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut db = writer(&directory.path().join("events.sqlite"));
        db.execute_batch("CREATE TABLE events(sequence INTEGER PRIMARY KEY,slot INTEGER,bank INTEGER,kind TEXT,payload BLOB); CREATE TABLE status(id INTEGER PRIMARY KEY,durable_sequence INTEGER,retired_events INTEGER,latest_rooted_slot INTEGER); INSERT INTO status VALUES(1,0,0,99);").unwrap();
        source_retention::initialize(&db).unwrap();
        let tx = db.transaction().unwrap();
        for sequence in 1..=rows {
            tx.execute(
                "INSERT INTO events VALUES(?1,100,?2,?3,?4)",
                params![
                    sequence,
                    if sequence % 3 == 0 {
                        None
                    } else {
                        Some(sequence % 2)
                    },
                    if sequence % 7 == 0 { "dead" } else { "entry" },
                    vec![sequence as u8; 1024]
                ],
            )
            .unwrap();
        }
        tx.execute("UPDATE status SET durable_sequence=?1 WHERE id=1", [rows])
            .unwrap();
        tx.commit().unwrap();
        fs::create_dir(directory.path().join("producer")).unwrap();
        let path = directory.path().join("producer/feed.sqlite");
        let producer = writer(&path);
        producer.execute_batch("CREATE TABLE source_acks(id INTEGER PRIMARY KEY,schema TEXT,source_json TEXT,producer_generation TEXT,feed_header_sha256 TEXT,source_start_sequence INTEGER,custody_through_sequence INTEGER,proof_sha256 TEXT);").unwrap();
        let metadata = path.metadata().unwrap();
        let mut ticket = SourceAckTicket {
            schema: SOURCE_ACK_SCHEMA.into(),
            source: source(),
            producer_db: path.to_string_lossy().into(),
            producer_db_device: metadata.dev(),
            producer_db_inode: metadata.ino(),
            producer_generation: "producer-generation-1".into(),
            feed_header_sha256: digest(b"bound feed header"),
            source_start_sequence: 0,
            through_sequence: frontier,
            proof_sha256: String::new(),
        };
        ticket.proof_sha256 = source_ack_proof(
            &ticket.source,
            &ticket.producer_generation,
            &ticket.feed_header_sha256,
            0,
            frontier,
        )
        .unwrap();
        producer
            .execute(
                "INSERT INTO source_acks VALUES(1,?1,?2,?3,?4,0,?5,?6)",
                params![
                    SOURCE_ACK_SCHEMA,
                    serde_json::to_string(&ticket.source).unwrap(),
                    ticket.producer_generation,
                    ticket.feed_header_sha256,
                    frontier,
                    ticket.proof_sha256
                ],
            )
            .unwrap();
        Self {
            directory,
            source: db,
            producer,
            ticket,
        }
    }
    fn path(&self) -> &Path {
        self.directory.path()
    }
    fn count(&self) -> u64 {
        self.source
            .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
            .unwrap()
    }
    fn publish(&self) {
        write_source_ack(self.path(), &self.ticket).unwrap();
    }
    fn step(&mut self) -> anyhow::Result<bool> {
        source_retention::process_one(self.directory.path(), &mut self.source, &self.ticket.source)
    }
    fn custody(&self, frontier: u64) {
        let proof = source_ack_proof(
            &self.ticket.source,
            &self.ticket.producer_generation,
            &self.ticket.feed_header_sha256,
            0,
            frontier,
        )
        .unwrap();
        self.producer
            .execute(
                "UPDATE source_acks SET custody_through_sequence=?1,proof_sha256=?2 WHERE id=1",
                params![frontier, proof],
            )
            .unwrap();
    }
}

#[test]
fn consumed_prefix_deletion_is_bounded_and_keeps_later_rows_of_every_kind() {
    let mut f = Fixture::new(5000, 4500);
    f.publish();
    assert!(f.step().unwrap());
    assert_eq!(f.count(), 2952);
    assert!(!f.path().join(SOURCE_RETIREMENT_FILE).exists());
    assert!(f.step().unwrap());
    assert_eq!(f.count(), 904);
    assert!(f.step().unwrap());
    assert_eq!(f.count(), 500);
    let receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(f.path().join(SOURCE_RETIREMENT_FILE)).unwrap()).unwrap();
    assert_eq!(receipt["retired_through_sequence"], 4500);
    assert_eq!(receipt["deleted_events"], 4500);
    assert_eq!(
        f.source
            .query_row("SELECT min(sequence) FROM events", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        4501
    );
    assert_eq!(
        f.source
            .query_row(
                "SELECT durable_sequence,retired_events,latest_rooted_slot FROM status",
                [],
                |r| Ok((
                    r.get::<_, u64>(0)?,
                    r.get::<_, u64>(1)?,
                    r.get::<_, u64>(2)?
                ))
            )
            .unwrap(),
        (5000, 4500, 99)
    );
    let before = f
        .path()
        .join(SOURCE_RETIREMENT_FILE)
        .metadata()
        .unwrap()
        .ino();
    assert!(!f.step().unwrap());
    assert_eq!(
        f.path()
            .join(SOURCE_RETIREMENT_FILE)
            .metadata()
            .unwrap()
            .ino(),
        before
    );
}

#[test]
fn newer_full_custody_row_safely_covers_an_older_atomic_ticket() {
    let mut f = Fixture::new(5000, 3000);
    f.publish();
    f.custody(4500);
    while f.step().unwrap() {}
    assert_eq!(f.count(), 2000);
    let receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(f.path().join(SOURCE_RETIREMENT_FILE)).unwrap()).unwrap();
    assert_eq!(receipt["custody_through_sequence_used"], 4500);
    assert_ne!(receipt["proof_sha256_used"], f.ticket.proof_sha256);
}

#[test]
fn uncommitted_producer_custody_cannot_authorize_source_deletion() {
    let mut f = Fixture::new(5000, 3000);
    f.producer.execute_batch("BEGIN IMMEDIATE").unwrap();
    f.custody(4500);
    f.ticket.through_sequence = 4500;
    f.ticket.proof_sha256 = source_ack_proof(
        &f.ticket.source,
        &f.ticket.producer_generation,
        &f.ticket.feed_header_sha256,
        0,
        4500,
    )
    .unwrap();
    f.publish();
    assert!(f.step().is_err());
    assert_eq!(f.count(), 5000);
    f.producer.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn malformed_source_proof_inode_generation_and_future_frontiers_preserve_rows() {
    for case in 0..7 {
        let mut f = Fixture::new(5000, 3000);
        match case {
            0 => f.ticket.source.session_id = "00000000000000000000000000000002-1".into(),
            1 => f.ticket.producer_db_inode += 1,
            2 => f
                .producer
                .execute("UPDATE source_acks SET producer_generation='different'", [])
                .map(|_| ())
                .unwrap(),
            3 => f
                .producer
                .execute("UPDATE source_acks SET proof_sha256=?1", [digest(b"bad")])
                .map(|_| ())
                .unwrap(),
            4 => {
                f.ticket.through_sequence = 6000;
                f.custody(6000);
            }
            5 => f
                .producer
                .execute("UPDATE source_acks SET source_json='{}'", [])
                .map(|_| ())
                .unwrap(),
            _ => f.ticket.feed_header_sha256 = digest(b"different header"),
        }
        f.ticket.proof_sha256 = source_ack_proof(
            &f.ticket.source,
            &f.ticket.producer_generation,
            &f.ticket.feed_header_sha256,
            0,
            f.ticket.through_sequence,
        )
        .unwrap();
        f.publish();
        assert!(
            source_retention::process_one(f.directory.path(), &mut f.source, &source()).is_err(),
            "case {case}"
        );
        assert_eq!(f.count(), 5000);
    }
}

#[test]
fn an_unrecorded_source_hole_is_an_error_not_a_new_retirement_frontier() {
    let mut f = Fixture::new(5000, 3000);
    f.source
        .execute("DELETE FROM events WHERE sequence=2", [])
        .unwrap();
    f.publish();
    assert!(f.step().unwrap_err().to_string().contains("unrecorded gap"));
    assert_eq!(f.count(), 4999);
    assert_eq!(
        f.source
            .query_row("SELECT count(*) FROM live_source_gc", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn restart_resumes_committed_deletes_and_repairs_a_missing_receipt() {
    let mut f = Fixture::new(5000, 4500);
    f.publish();
    f.step().unwrap();
    let path = f.path().join("events.sqlite");
    drop(std::mem::replace(
        &mut f.source,
        Connection::open_in_memory().unwrap(),
    ));
    f.source = writer(&path);
    while f.step().unwrap() {}
    assert_eq!(f.count(), 500);
    fs::remove_file(f.path().join(SOURCE_RETIREMENT_FILE)).unwrap();
    assert!(!f.step().unwrap());
    assert!(f.path().join(SOURCE_RETIREMENT_FILE).exists());
    assert_eq!(
        f.source
            .query_row("SELECT retired_events FROM status", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        4500
    );
}

#[test]
fn later_ticket_or_custody_regression_is_rejected_after_partial_progress() {
    for ticket in [false, true] {
        let mut f = Fixture::new(5000, 3000);
        f.custody(4000);
        f.publish();
        f.step().unwrap();
        if ticket {
            f.ticket.through_sequence = 2000;
            f.ticket.proof_sha256 = source_ack_proof(
                &f.ticket.source,
                &f.ticket.producer_generation,
                &f.ticket.feed_header_sha256,
                0,
                2000,
            )
            .unwrap();
            f.publish();
        } else {
            f.custody(3500);
        }
        assert!(f.step().is_err());
        assert_eq!(f.count(), 2952);
    }
}

#[test]
fn unsafe_symlink_or_hard_link_proofs_are_rejected_without_delete() {
    for hard in [false, true] {
        let mut f = Fixture::new(5000, 3000);
        f.publish();
        let ack = f.path().join("SOURCE-ACK.json");
        if hard {
            fs::hard_link(&ack, f.path().join("alias")).unwrap();
        } else {
            fs::rename(&ack, f.path().join("real-ack")).unwrap();
            std::os::unix::fs::symlink(f.path().join("real-ack"), ack).unwrap();
        }
        assert!(f.step().is_err());
        assert_eq!(f.count(), 5000);
    }
}

#[test]
fn passive_checkpoint_does_not_wait_for_a_pinned_reader_and_pages_are_reused() {
    let mut f = Fixture::new(5000, 5000);
    f.source
        .execute_batch("PRAGMA wal_checkpoint(PASSIVE)")
        .unwrap();
    let before: u64 = f
        .source
        .query_row("PRAGMA page_count", [], |r| r.get(0))
        .unwrap();
    let reader = Connection::open(f.path().join("events.sqlite")).unwrap();
    reader.execute_batch("BEGIN").unwrap();
    assert_eq!(
        reader
            .query_row("SELECT count(*) FROM events", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        5000
    );
    f.publish();
    while f.step().unwrap() {}
    let (_, frames, done): (i64, i64, i64) = f
        .source
        .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert!(frames > done);
    assert_eq!(
        reader
            .query_row("SELECT count(*) FROM events", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        5000
    );
    reader.execute_batch("ROLLBACK").unwrap();
    drop(reader);
    f.source
        .execute_batch("PRAGMA wal_checkpoint(PASSIVE)")
        .unwrap();
    let free: u64 = f
        .source
        .query_row("PRAGMA freelist_count", [], |r| r.get(0))
        .unwrap();
    assert!(free > 0);
    let tx = f.source.transaction().unwrap();
    for sequence in 5001..=10000 {
        tx.execute(
            "INSERT INTO events VALUES(?1,100,NULL,'late',?2)",
            params![sequence, vec![0u8; 1024]],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    let after: u64 = f
        .source
        .query_row("PRAGMA page_count", [], |r| r.get(0))
        .unwrap();
    assert!(after <= before + 16, "before={before} after={after}");
}

#[test]
fn journal_advertises_live_prefix_custody_only_when_explicitly_enabled() {
    let directory = tempfile::tempdir().unwrap();
    let config = Config {
        bank_v2: true,
        live_source_ack: true,
        libpath: "fixture".into(),
        output_root: directory.path().join("capture"),
        genesis_hash: source().genesis_hash,
        node_identity: source().node_identity,
        queue_events: 512,
        queue_bytes: 16 * 1024 * 1024,
        max_event_bytes: 1024 * 1024,
        max_journal_bytes: 64 * 1024 * 1024,
        reserve_disk_bytes: 0,
        commit_interval_ms: 10,
    };
    let mut invalid = config.clone();
    invalid.bank_v2 = false;
    assert!(invalid.validate().is_err());
    let mut journal = Journal::start(config).unwrap();
    let path = journal.session_dir.clone();
    let session: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("SESSION.json")).unwrap()).unwrap();
    assert_eq!(session["retirement"], "local-consumed-prefix-v1");
    assert_eq!(session["processed_custody"], false);
    std::thread::sleep(Duration::from_millis(20));
    journal.close().unwrap();
    assert!(path.join("CLOSED.json").exists());
}

fn live_journal(root: &Path) -> Journal {
    Journal::start(Config {
        bank_v2: true,
        live_source_ack: true,
        libpath: "fixture".into(),
        output_root: root.join("capture"),
        genesis_hash: source().genesis_hash,
        node_identity: source().node_identity,
        queue_events: 4096,
        queue_bytes: 16 * 1024 * 1024,
        max_event_bytes: 1024 * 1024,
        max_journal_bytes: 64 * 1024 * 1024,
        reserve_disk_bytes: 0,
        commit_interval_ms: 10,
    })
    .unwrap()
}

fn wait_durable(session: &Path, sequence: u64) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let db =
            hivezilla_direct_agave::journal::open_reader(&session.join("events.sqlite")).unwrap();
        let durable: u64 = db
            .query_row("SELECT durable_sequence FROM status", [], |r| r.get(0))
            .unwrap();
        if durable >= sequence {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "source did not commit"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn journal_ticket(root: &Path, journal: &Journal, frontier: u64) -> SourceAckTicket {
    let fixture = Fixture::new(frontier, frontier);
    let path = root.join("feed.sqlite");
    // Build a distinct local custody proof for the actual journal generation.
    let producer = writer(&path);
    producer.execute_batch("CREATE TABLE source_acks(id INTEGER PRIMARY KEY,schema TEXT,source_json TEXT,producer_generation TEXT,feed_header_sha256 TEXT,source_start_sequence INTEGER,custody_through_sequence INTEGER,proof_sha256 TEXT);").unwrap();
    let mut ticket = fixture.ticket.clone();
    ticket.source.session_id = journal.session_id.clone();
    ticket.source.agave_revision = hivezilla_direct_agave::event::REVISION.into();
    let metadata = path.metadata().unwrap();
    ticket.producer_db = path.to_string_lossy().into();
    ticket.producer_db_device = metadata.dev();
    ticket.producer_db_inode = metadata.ino();
    ticket.proof_sha256 = source_ack_proof(
        &ticket.source,
        &ticket.producer_generation,
        &ticket.feed_header_sha256,
        0,
        frontier,
    )
    .unwrap();
    producer
        .execute(
            "INSERT INTO source_acks VALUES(1,?1,?2,?3,?4,0,?5,?6)",
            params![
                SOURCE_ACK_SCHEMA,
                serde_json::to_string(&ticket.source).unwrap(),
                ticket.producer_generation,
                ticket.feed_header_sha256,
                frontier,
                ticket.proof_sha256
            ],
        )
        .unwrap();
    ticket
}

#[test]
fn real_journal_writer_retires_idle_committed_source_after_durable_custody() {
    let directory = tempfile::tempdir().unwrap();
    let mut journal = live_journal(directory.path());
    for slot in 1..=1024 {
        journal
            .append(&hivezilla_direct_agave::event::Event::Status {
                slot,
                bank_id: None,
                parent: None,
                status: "processed".into(),
                dead_error: None,
            })
            .unwrap();
    }
    wait_durable(&journal.session_dir, 1024);
    let ticket = journal_ticket(directory.path(), &journal, 1024);
    write_source_ack(&journal.session_dir, &ticket).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !journal.session_dir.join(SOURCE_RETIREMENT_FILE).exists() {
        assert!(!journal.is_failed());
        assert!(
            std::time::Instant::now() < deadline,
            "idle journal did not retire acknowledged input"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let db =
        hivezilla_direct_agave::journal::open_reader(&journal.session_dir.join("events.sqlite"))
            .unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM events", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row(
            "SELECT durable_sequence,retired_events FROM status",
            [],
            |r| Ok((r.get::<_, u64>(0)?, r.get::<_, u64>(1)?))
        )
        .unwrap(),
        (1024, 1024)
    );
    journal.close().unwrap();
}

#[test]
fn invalid_source_ack_stops_retirement_but_not_callback_capture() {
    let directory = tempfile::tempdir().unwrap();
    let mut journal = live_journal(directory.path());
    let event = hivezilla_direct_agave::event::Event::Status {
        slot: 1,
        bank_id: None,
        parent: None,
        status: "processed".into(),
        dead_error: None,
    };
    journal.append(&event).unwrap();
    wait_durable(&journal.session_dir, 1);
    let mut ticket = journal_ticket(directory.path(), &journal, 1);
    ticket.producer_db_inode += 1;
    write_source_ack(&journal.session_dir, &ticket).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !journal.session_dir.join("RETIREMENT-FAILED.json").exists() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(!journal.is_failed());
    journal.append(&event).unwrap();
    wait_durable(&journal.session_dir, 2);
    let db =
        hivezilla_direct_agave::journal::open_reader(&journal.session_dir.join("events.sqlite"))
            .unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM events", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        2
    );
    journal.close().unwrap();
}

#[test]
fn capture_lock_reports_actual_writer_lifetime_without_creating_missing_files() {
    let directory = tempfile::tempdir().unwrap();
    assert!(hivezilla_direct_agave::journal::capture_is_live(directory.path()).is_err());
    assert!(!directory.path().join("LIVE.lock").exists());
    let mut journal = live_journal(directory.path());
    assert!(hivezilla_direct_agave::journal::capture_is_live(&journal.session_dir).unwrap());
    journal.close().unwrap();
    assert!(!hivezilla_direct_agave::journal::capture_is_live(&journal.session_dir).unwrap());
}

#[test]
fn unsafe_capture_lock_is_an_error_not_a_live_capture() {
    use std::os::unix::fs::PermissionsExt;
    for case in 0..3 {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("LIVE.lock");
        fs::write(&path, b"").unwrap();
        match case {
            0 => fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap(),
            1 => {
                fs::rename(&path, directory.path().join("target")).unwrap();
                std::os::unix::fs::symlink(directory.path().join("target"), &path).unwrap();
            }
            _ => fs::hard_link(&path, directory.path().join("alias")).unwrap(),
        }
        assert!(hivezilla_direct_agave::journal::capture_is_live(directory.path()).is_err());
    }
}
