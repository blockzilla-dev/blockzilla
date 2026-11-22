//! Storage checks use already-admitted fixture envelopes. The retained-frame
//! test exercises the real semantic validator and cache before the same commit.
use super::*;
use blockzilla_bank_stream_v2::{Head, fixtures::*};

fn limits() -> Limits {
    Limits {
        replay_bytes: 128 * 1024 * 1024,
        replay_events: 1024,
        database_bytes: 320 * 1024 * 1024,
    }
}
fn bootstrap(frame: &v2::Frame) -> Bootstrap {
    let after = v2::cursor(
        &frame.source.session_id,
        frame.envelope.event.sequence - 1,
        &"0".repeat(64),
    );
    Bootstrap {
        after: after.clone(),
        control: None,
        payload: None,
        head: Head {
            schema: v2::HEAD.into(),
            profile: v2::PROFILE.into(),
            source: frame.source.clone(),
            cursor: Some(after.clone()),
            earliest_after: Some(after),
            status: "starting".into(),
            sampled_at_unix_ms: blockzilla_bank_client::now_ms(),
            source_observed_at_unix_ms: None,
            source_lag_ms: None,
            latest_confirmed: None,
        },
    }
}
fn snapshot(store: &Store) -> (String, String, String) {
    store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT cursor,output_cursor,chain_json FROM checkpoint WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap()
}

#[test]
fn compact_mode_is_explicit_and_controls_remain_atomic_without_json() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("compact.sqlite");
    let store = Store::open_with_mode(
        &path,
        source(),
        "producer".into(),
        vec![],
        limits(),
        PayloadMode::CompactOnly,
        0,
    )
    .unwrap();
    let frame = block(1, 10, 10, 9, 10);
    store
        .bootstrap_beam(&bootstrap(&frame), None, "0123456789abcdef0123456789abcdef")
        .unwrap();
    let base = store.output_cursor().unwrap();
    let payload = store
        .payloads
        .materialize(Payload {
            frame: frame.clone(),
            json: Value::Null,
        })
        .unwrap();
    store
        .commit_beam(
            &Delivery {
                frame: frame.clone(),
                dependency: None,
            },
            Some(payload),
        )
        .unwrap();
    let before = snapshot(&store);
    let root = control(&frame, 2, "root", 1000);
    store.connection.lock().unwrap().execute_batch("CREATE TRIGGER fail_checkpoint BEFORE UPDATE ON checkpoint BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    assert!(
        store
            .commit_beam(
                &Delivery {
                    frame: root.clone(),
                    dependency: None
                },
                None
            )
            .is_err()
    );
    assert_eq!(snapshot(&store), before);
    store
        .connection
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_checkpoint;")
        .unwrap();
    store
        .commit_beam(
            &Delivery {
                frame: root.clone(),
                dependency: None,
            },
            None,
        )
        .unwrap();
    assert_eq!(store.cursor().unwrap().unwrap(), root.cursor);
    assert!(store.after(&base).is_err());
    assert_eq!(
        store.after_native(&base).unwrap().unwrap().wire(),
        frame.wire.as_ref()
    );
    let stats = store.storage_status().unwrap();
    assert_eq!(stats["persistedProjectionBytes"], 0);
    assert_eq!(stats["persistedWireBytes"], frame.wire.len());
    assert_eq!(stats["chargedReplayBytes"], frame.wire.len());
    assert_eq!(stats["retainedEvents"], 2);
    let text: String = store
        .connection
        .lock()
        .unwrap()
        .query_row("SELECT projection FROM payloads", [], |r| r.get(0))
        .unwrap();
    assert!(text.is_empty());
    assert!(
        serde_json::from_str::<Value>(&text).is_err(),
        "old full readers must fail closed"
    );
    drop(store);
    assert!(Store::open(&path, source(), "producer".into(), vec![], limits()).is_err());
    assert!(
        Store::open_with_mode(
            &path,
            source(),
            "other-producer".into(),
            vec![],
            limits(),
            PayloadMode::CompactOnly,
            0
        )
        .is_err()
    );
    let reopened = Store::open_with_mode(
        &path,
        source(),
        "producer".into(),
        vec![],
        limits(),
        PayloadMode::CompactOnly,
        0,
    )
    .unwrap();
    assert_eq!(reopened.cursor().unwrap().unwrap(), root.cursor);
    // A consumer can crash after COMMIT and before it observes success. A
    // repeated original frame must not make a second output or payload copy.
    let committed = snapshot(&reopened);
    let committed_storage = reopened.storage_status().unwrap();
    reopened
        .commit_beam(
            &Delivery {
                frame: root,
                dependency: None,
            },
            None,
        )
        .unwrap();
    assert_eq!(snapshot(&reopened), committed);
    let retried_storage = reopened.storage_status().unwrap();
    for field in [
        "persistedProjectionBytes",
        "persistedWireBytes",
        "chargedReplayBytes",
        "retainedEvents",
    ] {
        assert_eq!(retried_storage[field], committed_storage[field]);
    }
    assert_eq!(
        reopened.after_native(&base).unwrap().unwrap().wire(),
        frame.wire.as_ref()
    );
}

#[test]
fn compact_recovery_restarts_at_commit_and_keeps_each_native_event_once() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("recover.sqlite");
    let open = || {
        Store::open_with_mode(
            &path,
            source(),
            "producer".into(),
            vec![],
            limits(),
            PayloadMode::CompactOnly,
            0,
        )
        .unwrap()
    };
    let mut frames = Vec::new();
    for index in 0..4 {
        let sequence = index * 3 + 1;
        let payload = block(sequence, 10 + index, 10 + index, 9 + index, 10 + index);
        frames.push(payload.clone());
        // The empty fixture Chain first needs a native root boundary. Later
        // blocks then have captured parents before their confirmations arrive.
        let kinds = if index == 0 {
            ["root", "confirmed"]
        } else {
            ["confirmed", "root"]
        };
        frames.push(control(&payload, sequence + 1, kinds[0], 1000));
        frames.push(control(&payload, sequence + 2, kinds[1], 1000));
    }
    let commit = |store: &Store, frame: &v2::Frame| {
        let shared = if frame.envelope.event.kind == "block" {
            Some(
                store
                    .payloads
                    .materialize(Payload {
                        frame: frame.clone(),
                        json: Value::Null,
                    })
                    .unwrap(),
            )
        } else {
            None
        };
        store.commit_beam(
            &Delivery {
                frame: frame.clone(),
                dependency: None,
            },
            shared,
        )
    };
    let store = open();
    store
        .bootstrap_beam(
            &bootstrap(&frames[0]),
            None,
            "0123456789abcdef0123456789abcdef",
        )
        .unwrap();
    for frame in &frames[..3] {
        commit(&store, frame).unwrap();
    }
    let disconnected = snapshot(&store);
    // A missing control is a gap, even when a later frame has a valid hash.
    assert!(commit(&store, &frames[4]).is_err());
    assert_eq!(snapshot(&store), disconnected);
    drop(store);
    let store = open();
    assert_eq!(snapshot(&store), disconnected);
    store.connection.lock().unwrap().execute_batch("CREATE TRIGGER fail_recovery BEFORE UPDATE ON checkpoint BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    assert!(commit(&store, &frames[3]).is_err());
    assert_eq!(snapshot(&store), disconnected);
    assert_eq!(store.storage_status().unwrap()["persistedPayloads"], 1);
    store
        .connection
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_recovery;")
        .unwrap();
    for frame in &frames[3..] {
        commit(&store, frame).unwrap();
        // Model a lost commit receipt. The durable cursor prevents duplicates.
        commit(&store, frame).unwrap();
    }
    let actual = store
        .connection
        .lock()
        .unwrap()
        .prepare("SELECT source_cursor FROM updates ORDER BY sequence")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        actual,
        frames
            .iter()
            .map(|frame| frame.cursor.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(store.cursor().unwrap().as_ref(), Some(&frames[11].cursor));
    let stats = store.storage_status().unwrap();
    assert_eq!(stats["persistedProjectionBytes"], 0);
    assert_eq!(stats["retainedEvents"], frames.len());
    assert_eq!(stats["persistedPayloads"], 4);
    let expected_bytes: usize = frames
        .iter()
        .filter(|frame| frame.envelope.event.kind == "block")
        .map(|frame| frame.wire.len())
        .sum();
    assert_eq!(stats["persistedWireBytes"], expected_bytes);
}

#[tokio::test]
#[ignore = "requires BLOCKZILLA_SIDECAR_FRAME from a retained real native Bank"]
async fn retained_native_compact_storage_migration_is_exact_and_bounded() {
    let wire = std::fs::read(std::env::var("BLOCKZILLA_SIDECAR_FRAME").unwrap()).unwrap();
    let frame = v2::decode(wire.clone().into()).unwrap();
    let summary = blockzilla_stream_decoder::validate_bank_payload(&frame).unwrap();
    let full = projection::decode(frame.clone()).unwrap();
    let rows = full.json["blocks"][0]["transactions"].as_array().unwrap();
    assert_eq!(summary.transactions, rows.len());
    assert_eq!(
        summary.failed,
        rows.iter().filter(|r| r["success"] == false).count()
    );
    assert_eq!(
        summary.successful,
        rows.iter().filter(|r| r["success"] == true).count()
    );
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("real.sqlite");
    let store = Store::open(
        &path,
        frame.source.clone(),
        "producer".into(),
        vec![],
        limits(),
    )
    .unwrap();
    store
        .bootstrap_beam(&bootstrap(&frame), None, "0123456789abcdef0123456789abcdef")
        .unwrap();
    let base = store.output_cursor().unwrap();
    let payload = store.payloads.load(frame.clone()).await.unwrap();
    store
        .commit_beam(
            &Delivery {
                frame: frame.clone(),
                dependency: None,
            },
            Some(payload),
        )
        .unwrap();
    let before = snapshot(&store);
    let original = store.storage_status().unwrap();
    assert!(original["persistedProjectionBytes"].as_u64().unwrap() > 0);
    store.connection.lock().unwrap().execute_batch("CREATE TRIGGER fail_mode BEFORE UPDATE OF payload_mode ON config BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    drop(store);
    assert!(
        Store::open_with_mode(
            &path,
            frame.source.clone(),
            "producer".into(),
            vec![],
            limits(),
            PayloadMode::CompactOnly,
            0
        )
        .is_err()
    );
    let old = Store::open(
        &path,
        frame.source.clone(),
        "producer".into(),
        vec![],
        limits(),
    )
    .unwrap();
    assert_eq!(snapshot(&old), before);
    assert_eq!(
        old.storage_status().unwrap()["persistedProjectionBytes"],
        original["persistedProjectionBytes"]
    );
    old.connection
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_mode;")
        .unwrap();
    drop(old);
    let compact = Store::open_with_mode(
        &path,
        frame.source.clone(),
        "producer".into(),
        vec![],
        limits(),
        PayloadMode::CompactOnly,
        0,
    )
    .unwrap();
    assert_eq!(snapshot(&compact), before);
    assert_eq!(compact.after_native(&base).unwrap().unwrap().wire(), wire);
    let stats = compact.storage_status().unwrap();
    assert_eq!(stats["persistedProjectionBytes"], 0);
    assert_eq!(stats["persistedWireBytes"], wire.len());
    assert_eq!(stats["chargedReplayBytes"], wire.len());
    assert!(
        stats["chargedReplayBytes"].as_u64().unwrap()
            < original["chargedReplayBytes"].as_u64().unwrap()
    );
    let checked = compact.payloads.load(frame.clone()).await.unwrap();
    assert!(checked.json.is_null() && checked.text.is_empty());
    assert_eq!(checked.frame.wire.as_ref(), wire);
    let root = control(
        &frame,
        frame.envelope.event.sequence + 1,
        "root",
        blockzilla_bank_client::now_ms(),
    );
    compact
        .commit_beam(
            &Delivery {
                frame: root.clone(),
                dependency: None,
            },
            None,
        )
        .unwrap();
    assert_eq!(compact.cursor().unwrap().unwrap(), root.cursor);
    assert_eq!(
        compact.storage_status().unwrap()["persistedProjectionBytes"],
        0
    );
    println!(
        "real compact frame: {} transactions, {} failed, wire={} bytes, removed projection={} bytes",
        summary.transactions,
        summary.failed,
        wire.len(),
        original["persistedProjectionBytes"]
    );
}
