use blockzilla_bank_stream_v2::SourceIdentity;
use hivezilla_direct_agave::{
    event::{Event, REVISION, digest},
    journal::{Config, Journal},
    retention::{SOURCE_ACK_SCHEMA, SourceAckTicket, source_ack_proof, write_source_ack},
};
use rusqlite::{Connection, params};
use std::{fs, os::unix::fs::MetadataExt, sync::Barrier, time::Duration};

#[test]
fn capture_commits_while_the_actual_ack_publisher_replaces_its_temp_file() {
    let temporary = tempfile::tempdir().unwrap();
    let config = Config {
        bank_v2: true,
        live_source_ack: true,
        libpath: "fixture".into(),
        output_root: temporary.path().join("capture"),
        genesis_hash: "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d".into(),
        node_identity: "J7qpvCEWhdBgPdYRV3s3btWPrRVXa2qnAzgvxWTvtbrQ".into(),
        queue_events: 4096,
        queue_bytes: 16 * 1024 * 1024,
        max_event_bytes: 1024 * 1024,
        max_journal_bytes: 64 * 1024 * 1024,
        reserve_disk_bytes: 0,
        commit_interval_ms: 1,
    };
    let mut journal = Journal::start(config.clone()).unwrap();
    let session = journal.session_dir.clone();
    let source = SourceIdentity {
        session_id: journal.session_id.clone(),
        genesis_hash: config.genesis_hash,
        node_identity: config.node_identity,
        agave_revision: REVISION.into(),
    };
    let path = temporary.path().join("feed.sqlite");
    let producer = Connection::open(&path).unwrap();
    producer.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
        CREATE TABLE source_acks(id INTEGER PRIMARY KEY,schema TEXT,source_json TEXT,producer_generation TEXT,feed_header_sha256 TEXT,source_start_sequence INTEGER,custody_through_sequence INTEGER,proof_sha256 TEXT);").unwrap();
    let metadata = path.metadata().unwrap();
    let mut ticket = SourceAckTicket {
        schema: SOURCE_ACK_SCHEMA.into(),
        source,
        producer_db: path.to_str().unwrap().into(),
        producer_db_device: metadata.dev(),
        producer_db_inode: metadata.ino(),
        producer_generation: "quota-test-producer".into(),
        feed_header_sha256: digest(b"fixed quota test header"),
        source_start_sequence: 0,
        through_sequence: 0,
        proof_sha256: String::new(),
    };
    ticket.proof_sha256 = source_ack_proof(
        &ticket.source,
        &ticket.producer_generation,
        &ticket.feed_header_sha256,
        0,
        0,
    )
    .unwrap();
    producer
        .execute(
            "INSERT INTO source_acks VALUES(1,?1,?2,?3,?4,0,0,?5)",
            params![
                ticket.schema,
                serde_json::to_string(&ticket.source).unwrap(),
                ticket.producer_generation,
                ticket.feed_header_sha256,
                ticket.proof_sha256
            ],
        )
        .unwrap();
    let ready = Barrier::new(2);
    std::thread::scope(|scope| {
        let publisher = scope.spawn(|| {
            ready.wait();
            for _ in 0..1000 {
                write_source_ack(&session, &ticket).unwrap();
            }
        });
        ready.wait();
        for n in 0..1000 {
            for _ in 0..2 {
                journal
                    .append(&Event::Status {
                        slot: 100 + n,
                        bank_id: Some(7),
                        parent: Some(99),
                        status: "processed".into(),
                        dead_error: None,
                    })
                    .unwrap();
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        publisher.join().unwrap();
    });
    journal.close().unwrap();
    assert!(!journal.is_failed());
    let source = Connection::open(session.join("events.sqlite")).unwrap();
    let status: (String, u64) = source
        .query_row("SELECT state,durable_sequence FROM status", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(status, ("CLOSED".into(), 2000));
    assert_eq!(
        source
            .query_row("SELECT count(*) FROM events", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        2000
    );
    assert!(!session.join("RETIREMENT-FAILED.json").exists());
    let failure: serde_json::Value =
        serde_json::from_slice(&fs::read(session.join("FAILURE.json")).unwrap()).unwrap();
    assert!(failure.get("state").is_none());
    println!(
        "SOURCE_QUOTA_CONCURRENCY publications=1000 accepted=2000 durable=2000 capture_failed=false"
    );
}
