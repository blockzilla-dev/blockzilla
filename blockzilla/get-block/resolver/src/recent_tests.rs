use super::*;
use rusqlite::{Connection, params};
use serde_json::json;
use std::fs;

pub(crate) struct Fixture {
    pub root: tempfile::TempDir,
    pub client: RecentClient,
    pub frame: Frame,
    pub db: Connection,
    pub artifact: PathBuf,
}

pub(crate) fn fixture() -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let processed = root_path.join("processed");
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
    let frame = v2::artifact::build(&processed, &artifact, &template.source, event).unwrap();
    let rooted = v2::fixtures::control(&frame, 3, "root", 2000);
    let generation = "a".repeat(64);
    let mut header = serde_json::to_value(&frame.source).unwrap();
    header["schema"] = json!("hivezilla-bank-feed-v2");
    header["profile"] = json!(v2::PROFILE);
    header["payload_root"] = json!(processed);
    header["producer_generation"] = json!(generation);
    fs::write(
        root_path.join("FEED.json"),
        serde_json::to_vec(&header).unwrap(),
    )
    .unwrap();
    fs::write(
        processed.join("FEED.json"),
        serde_json::to_vec(&header).unwrap(),
    )
    .unwrap();
    let status = json!({"state":"RUNNING","updated_unix_ms":1});
    for directory in [&root_path, &processed] {
        fs::write(
            directory.join("STATUS.json"),
            serde_json::to_vec(&status).unwrap(),
        )
        .unwrap();
    }
    fs::write(
        root_path.join("RETENTION-AUTHORITY.json"),
        serde_json::to_vec(&json!({
            "schema":"blockzilla-retention-authority-v1","mode":"local-beam-v1",
            "source":frame.source,"consumer_ack_required":false,"producer_generation":generation
        }))
        .unwrap(),
    )
    .unwrap();
    let db = Connection::open(root_path.join("feed.sqlite")).unwrap();
    db.execute_batch("CREATE TABLE banks(slot INTEGER,bank INTEGER,artifact TEXT,payload_event TEXT,frame_sha256 TEXT,state TEXT,PRIMARY KEY(slot,bank));
        CREATE TABLE feed_events(sequence INTEGER PRIMARY KEY,artifact TEXT,event_json TEXT,frame_sha256 TEXT UNIQUE);
        CREATE TABLE feed_retention(id INTEGER PRIMARY KEY,base_sequence INTEGER,base_sha256 TEXT,gap_base_sequence INTEGER,latest_gap_sequence INTEGER);
        INSERT INTO feed_retention VALUES(1,0,'-',0,0);").unwrap();
    db.execute(
        "INSERT INTO banks VALUES(100,7,?1,?2,?3,'rooted')",
        params![
            artifact.to_str().unwrap(),
            serde_json::to_string(&frame.envelope.event).unwrap(),
            frame.sha256
        ],
    )
    .unwrap();
    for value in [&frame, &rooted] {
        db.execute(
            "INSERT INTO feed_events VALUES(?1,?2,?3,?4)",
            params![
                value.envelope.event.sequence,
                artifact.to_str().unwrap(),
                serde_json::to_string(&value.envelope.event).unwrap(),
                value.sha256
            ],
        )
        .unwrap();
    }
    let client = RecentClient::new(RecentConfig {
        bank_source_root: root_path,
        payload_root: processed,
        source: frame.source.clone(),
        producer_generation: generation,
        native_archive_catalog: None,
        ledger_compact: None,
    })
    .unwrap();
    Fixture {
        root,
        client,
        frame,
        db,
        artifact,
    }
}

pub(crate) fn request(frame: &Frame, commitment: &str) -> RecentRequest {
    RecentRequest {
        blockhash: encode_hash(&frame.envelope.event.bank.blockhash),
        commitment: commitment.into(),
        cursor: Some(frame.cursor.clone()),
        bank_id: Some(frame.envelope.event.bank.bank_id),
        source_session: Some(frame.source.session_id.clone()),
    }
}

#[test]
fn recent_processed_and_finalized_return_original_frame_without_a_new_file() {
    let f = fixture();
    let before = fs::read(f.root.path().join("feed.sqlite")).unwrap();
    let count_before = fs::read_dir(f.root.path()).unwrap().count();
    for commitment in ["processed", "finalized"] {
        let RecentOutcome::Hit { frame, metadata } =
            f.client.read(100, &request(&f.frame, commitment)).unwrap()
        else {
            panic!("expected frame");
        };
        assert_eq!(frame.wire, f.frame.wire);
        assert_eq!(metadata.cursor, f.frame.cursor);
        assert_eq!(metadata.frame_sha256, f.frame.sha256);
        assert_eq!(metadata.source, f.frame.source);
        assert_eq!(metadata.commitment, commitment);
        assert_eq!(metadata.parent_slot, 99);
        assert_eq!(metadata.parent_blockhash, encode_hash(&[99; 32]));
        assert_eq!(
            frame.envelope.event.commitment.as_deref(),
            Some("processed")
        );
    }
    assert_eq!(before, fs::read(f.root.path().join("feed.sqlite")).unwrap());
    assert_eq!(count_before, fs::read_dir(f.root.path()).unwrap().count());
}

#[test]
fn absent_finalized_is_miss_but_absent_processed_is_expired() {
    let f = fixture();
    assert!(matches!(
        f.client.read(99, &request(&f.frame, "finalized")).unwrap(),
        RecentOutcome::Miss
    ));
    let mut r = request(&f.frame, "processed");
    r.cursor = Some(v2::cursor(&f.frame.source.session_id, 123, &"b".repeat(64)));
    assert!(matches!(
        f.client.read(100, &r).unwrap(),
        RecentOutcome::Expired
    ));
}

#[test]
fn processed_requires_the_exact_cursor_bank_and_hash() {
    let f = fixture();
    let valid = request(&f.frame, "processed");
    let mut r = valid.clone();
    r.bank_id = Some(8);
    assert!(f.client.read(100, &r).is_err());
    let mut r = valid.clone();
    r.blockhash = encode_hash(&[7; 32]);
    assert!(f.client.read(100, &r).is_err());
    let mut r = valid.clone();
    r.cursor = Some(v2::cursor(&f.frame.source.session_id, 2, &f.frame.sha256));
    assert!(f.client.read(100, &r).is_err());
    let mut r = valid.clone();
    r.source_session = Some("another-source".into());
    assert!(f.client.read(100, &r).is_err());
    let mut r = valid;
    r.cursor = None;
    assert!(f.client.read(100, &r).is_err());
}

#[test]
fn changed_source_generation_payload_root_and_failed_health_are_errors() {
    for field in ["session_id", "producer_generation", "payload_root"] {
        let f = fixture();
        let path = f.root.path().join("FEED.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value[field] = json!(if field == "producer_generation" {
            "b".repeat(64)
        } else {
            "/changed".into()
        });
        fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(f.client.read(100, &request(&f.frame, "processed")).is_err());
    }
    let f = fixture();
    fs::write(f.root.path().join("STATUS.json"), b"{\"state\":\"FAILED\"}").unwrap();
    assert!(f.client.read(100, &request(&f.frame, "processed")).is_err());
}

#[test]
fn changed_payload_and_root_proof_are_errors_not_cache_misses() {
    let f = fixture();
    fs::write(f.artifact.join("signatures.bin"), [43]).unwrap();
    assert!(f.client.read(100, &request(&f.frame, "processed")).is_err());
    assert!(f.client.read(100, &request(&f.frame, "finalized")).is_err());
    let f = fixture();
    f.db.execute("UPDATE feed_events SET event_json=json_set(event_json,'$.payload_frame_sha256',?1) WHERE sequence=3", ["b".repeat(64)]).unwrap();
    assert!(f.client.read(100, &request(&f.frame, "finalized")).is_err());
}

#[test]
fn retirement_removes_processed_frame_without_changing_the_reader_cursor() {
    let f = fixture();
    f.db.execute("DELETE FROM feed_events", []).unwrap();
    f.db.execute("DELETE FROM banks", []).unwrap();
    assert!(matches!(
        f.client.read(100, &request(&f.frame, "processed")).unwrap(),
        RecentOutcome::Expired
    ));
    assert!(matches!(
        f.client.read(100, &request(&f.frame, "finalized")).unwrap(),
        RecentOutcome::Miss
    ));
}

#[test]
fn finalized_slot_read_returns_original_frame_and_exact_root_without_client_hash() {
    let f = fixture();
    let before = fs::read(f.root.path().join("feed.sqlite")).unwrap();
    let found = f.client.read_finalized_by_slot(100).unwrap().unwrap();
    assert_eq!(found.frame.wire, f.frame.wire);
    assert_eq!(found.metadata.blockhash, encode_hash(&[100; 32]));
    assert_eq!(found.metadata.commitment, "finalized");
    assert_eq!(found.root.envelope.event.kind, "root");
    assert_eq!(found.root.source, found.frame.source);
    found
        .root
        .envelope
        .event
        .matches_payload(&found.frame)
        .unwrap();
    assert_eq!(before, fs::read(f.root.path().join("feed.sqlite")).unwrap());
    assert!(f.client.read_finalized_by_slot(99).unwrap().is_none());
    assert!(f.client.read_finalized_by_slot(v2::SAFE + 1).is_err());
}

#[test]
fn finalized_slot_read_never_selects_an_unrooted_or_ambiguous_bank() {
    let f = fixture();
    f.db.execute("UPDATE banks SET state='confirmed'", [])
        .unwrap();
    assert_eq!(
        f.client
            .read_finalized_by_slot(100)
            .err()
            .unwrap()
            .to_string(),
        "finalized_not_rooted"
    );
    let f = fixture();
    f.db.execute(
        "INSERT INTO banks SELECT slot,bank+1,artifact,payload_event,frame_sha256,state FROM banks",
        [],
    )
    .unwrap();
    assert_eq!(
        f.client
            .read_finalized_by_slot(100)
            .err()
            .unwrap()
            .to_string(),
        "ambiguous_rooted_bank"
    );
}

#[test]
fn finalized_slot_read_rejects_missing_or_changed_custody_instead_of_a_miss() {
    for mutation in [
        "root_missing",
        "root_corrupt",
        "payload_corrupt",
        "payload_missing",
        "expired",
        "source_changed",
    ] {
        let f = fixture();
        match mutation {
            "root_missing" => {
                f.db.execute("DELETE FROM feed_events WHERE sequence=3", [])
                    .unwrap();
            }
            "root_corrupt" => {
                f.db.execute("UPDATE feed_events SET event_json=json_set(event_json,'$.payload_frame_sha256',?1) WHERE sequence=3", ["b".repeat(64)]).unwrap();
            }
            "payload_corrupt" => fs::write(f.artifact.join("signatures.bin"), [43]).unwrap(),
            "payload_missing" => fs::remove_file(f.artifact.join("signatures.bin")).unwrap(),
            "expired" => {
                f.db.execute(
                    "UPDATE feed_retention SET base_sequence=3,base_sha256=?1",
                    [&v2::fixtures::control(&f.frame, 3, "root", 2000).sha256],
                )
                .unwrap();
            }
            "source_changed" => {
                let path = f.root.path().join("FEED.json");
                let mut value: serde_json::Value =
                    serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                value["producer_generation"] = json!("b".repeat(64));
                fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            f.client.read_finalized_by_slot(100).is_err(),
            "{mutation} became an archive miss"
        );
    }
}
