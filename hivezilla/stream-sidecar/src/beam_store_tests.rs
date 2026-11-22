//! Raw beam storage checks. Input cursor, projections and outbox share one FULL
//! transaction; the source has no consumer ACK or coverage-poll dependency.
use super::*;
use blockzilla_bank_stream_v2::{Head, fixtures::*};

const RUNTIME: &str = "0123456789abcdef0123456789abcdef";
const PRODUCER: &str = "fixture-producer";
fn limits() -> Limits {
    Limits {
        replay_bytes: 128 * 1024 * 1024,
        replay_events: 1024,
        database_bytes: 768 * 1024 * 1024,
    }
}
fn bootstrap(after: String) -> Bootstrap {
    Bootstrap {
        after: after.clone(),
        head: Head {
            schema: v2::HEAD.into(),
            profile: v2::PROFILE.into(),
            source: source(),
            cursor: Some(after.clone()),
            earliest_after: Some(after),
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
    Store::open(path, source(), PRODUCER.into(), targets, limits()).unwrap()
}
fn start(path: &Path, targets: Vec<WebhookTarget>) -> Arc<Store> {
    let store = open(path, targets);
    store
        .bootstrap_beam(
            &bootstrap(v2::cursor(&source().session_id, 0, "-")),
            None,
            RUNTIME,
        )
        .unwrap();
    store
}
fn payload(sequence: u64, slot: u64, parent: u64, height: u64) -> Payload {
    Payload {
        frame: block(sequence, slot, slot, parent, height),
        json: json!({"blocks":[{"slot":slot,"bankId":slot,"blockhash":bs58::encode([slot as u8;32]).into_string(),"parentSlot":parent,"parentBlockhash":bs58::encode([parent as u8;32]).into_string(),"blockHeight":height,"transactionCount":1,"transactions":[{"index":0,"signature":"signed-fixture","signatures":["signed-fixture"],"success":false,"err":{"InstructionError":[0,{"Custom":7}]},"accountKeys":[],"topLevelPrograms":[],"innerPrograms":[]}]}]}),
    }
}
fn commit_payload(store: &Store, p: &Payload) {
    let shared = store.payloads.materialize(p.clone()).unwrap();
    store
        .commit_beam(
            &Delivery {
                frame: p.frame.clone(),
                dependency: None,
            },
            Some(shared),
        )
        .unwrap();
}
fn commit_control(
    store: &Store,
    p: &Payload,
    sequence: u64,
    kind: &str,
    observed: u64,
) -> v2::Frame {
    let frame = control(&p.frame, sequence, kind, observed);
    store
        .commit_beam(
            &Delivery {
                frame: frame.clone(),
                dependency: None,
            },
            None,
        )
        .unwrap();
    frame
}
fn head(frame: &v2::Frame, sampled: u64) -> Head {
    let observation = v2::ConfirmedObservation::from_frame(frame).unwrap();
    Head {
        schema: v2::HEAD.into(),
        profile: v2::PROFILE.into(),
        source: source(),
        cursor: Some(frame.cursor.clone()),
        earliest_after: Some(v2::cursor(&source().session_id, 0, "-")),
        status: "live".into(),
        sampled_at_unix_ms: sampled,
        source_observed_at_unix_ms: Some(observation.observed_at_unix_ms),
        source_lag_ms: Some(sampled.saturating_sub(observation.observed_at_unix_ms)),
        latest_confirmed: Some(observation),
    }
}

#[test]
fn raw_cursor_projection_and_outbox_roll_back_together_then_retry_exactly_once() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("beam.sqlite");
    let target: WebhookTarget =
        serde_json::from_value(json!({"id":"local","url":"http://127.0.0.1:1/","kinds":["block"]}))
            .unwrap();
    let store = start(&path, vec![target.clone()]);
    let base = store.cursor().unwrap().unwrap();
    let output = store.output_cursor().unwrap();
    assert_eq!(
        store
            .connection
            .lock()
            .unwrap()
            .pragma_query_value(None, "synchronous", |r| r.get::<_, u64>(0))
            .unwrap(),
        2
    );
    store.connection.lock().unwrap().execute_batch("CREATE TRIGGER reject_outbox BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'fixture_outbox_failure'); END;").unwrap();
    let p = payload(1, 9, 8, 9);
    let shared = store.payloads.materialize(p.clone()).unwrap();
    assert!(
        store
            .commit_beam(
                &Delivery {
                    frame: p.frame.clone(),
                    dependency: None
                },
                Some(shared)
            )
            .is_err()
    );
    assert_eq!(store.cursor().unwrap().as_deref(), Some(base.as_str()));
    assert_eq!(store.output_cursor().unwrap(), output);
    let c = store.connection.lock().unwrap();
    for table in ["updates", "payloads", "outbox"] {
        assert_eq!(
            c.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            0
        );
    }
    c.execute_batch("DROP TRIGGER reject_outbox;").unwrap();
    drop(c);
    assert!(store.pending_ack().unwrap().is_none());
    commit_payload(&store, &p);
    let cursor = store.output_cursor().unwrap();
    let delivery = store.next_job(&target, 0).unwrap().unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&delivery.body).unwrap()["cursor"],
        cursor
    );
    // A crash before the input caller observes success must not duplicate output.
    store
        .commit_beam(
            &Delivery {
                frame: p.frame.clone(),
                dependency: None,
            },
            None,
        )
        .unwrap();
    let c = store.connection.lock().unwrap();
    for table in ["updates", "payloads", "outbox"] {
        assert_eq!(
            c.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            1
        );
    }
    drop(c);
    drop(store);
    let store = open(&path, vec![target.clone()]);
    store
        .bootstrap_beam(&bootstrap(p.frame.cursor.clone()), None, RUNTIME)
        .unwrap();
    assert_eq!(store.output_cursor().unwrap(), cursor);
    assert_eq!(
        store.next_job(&target, 0).unwrap().unwrap().delivery_id,
        delivery.delivery_id
    );
    assert!(store.pending_ack().unwrap().is_none());
}

#[test]
fn beam_restart_requires_exact_source_runtime_producer_and_input_policy() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("beam.sqlite");
    let store = start(&path, vec![]);
    let p = payload(1, 9, 8, 9);
    commit_payload(&store, &p);
    drop(store);
    let mut changed = source();
    changed.session_id = "different-session".into();
    assert_eq!(
        Store::open(&path, changed, PRODUCER.into(), vec![], limits())
            .err()
            .unwrap()
            .to_string(),
        "source_changed"
    );
    assert_eq!(
        Store::open(
            &path,
            source(),
            "different-producer".into(),
            vec![],
            limits()
        )
        .err()
        .unwrap()
        .to_string(),
        "producer_generation_changed"
    );
    let store = open(&path, vec![]);
    let saved = bootstrap(p.frame.cursor.clone());
    assert_eq!(
        store
            .bootstrap_beam(&saved, None, "fedcba9876543210fedcba9876543210")
            .unwrap_err()
            .to_string(),
        "runtime_generation_changed"
    );
    assert_eq!(
        store
            .bootstrap_shared(&saved, None)
            .unwrap_err()
            .to_string(),
        "beam_input_cannot_require_origin_ack"
    );
    store.bootstrap_beam(&saved, None, RUNTIME).unwrap();
    assert_eq!(store.cursor().unwrap(), Some(p.frame.cursor));
    let legacy_path = t.path().join("legacy.sqlite");
    let legacy = open(&legacy_path, vec![]);
    let initial = bootstrap(v2::cursor(&source().session_id, 0, "-"));
    legacy.bootstrap_shared(&initial, None).unwrap();
    assert_eq!(
        legacy
            .bootstrap_beam(&initial, None, RUNTIME)
            .unwrap_err()
            .to_string(),
        "input_policy_transition_requires_new_database"
    );
}

#[test]
fn initial_join_requires_one_exact_head_snapshot_and_has_no_ack_state() {
    let t = tempfile::tempdir().unwrap();
    let store = open(&t.path().join("beam.sqlite"), vec![]);
    let mut b = bootstrap(v2::cursor(&source().session_id, 0, "-"));
    b.head.cursor = Some(v2::cursor(&source().session_id, 1, &"ab".repeat(32)));
    assert_eq!(
        store
            .bootstrap_beam(&b, None, RUNTIME)
            .unwrap_err()
            .to_string(),
        "exact_initial_head_snapshot_required"
    );
    assert!(store.cursor().unwrap().is_none());
    assert_eq!(
        store
            .connection
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM beam_input", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
    b.head.cursor = Some(b.after.clone());
    store.bootstrap_beam(&b, None, RUNTIME).unwrap();
    let pressure = store.ack_backlog().unwrap();
    assert_eq!(pressure["required"], false);
    assert_eq!(pressure["pressure"], false);
    assert!(store.pending_ack().unwrap().is_none());
}

#[test]
fn native_signing_uses_native_height_age_clock_and_finality() {
    let t = tempfile::tempdir().unwrap();
    let store = start(&t.path().join("beam.sqlite"), vec![]);
    let p = payload(1, 9, 8, 9);
    commit_payload(&store, &p);
    assert!(store.beam_signing(1000).unwrap().is_none());
    let rooted = commit_control(&store, &p, 2, "root", 10_000);
    let selected = store.beam_signing(10_001).unwrap().unwrap();
    assert_eq!(selected.commitment, "finalized");
    assert_eq!(selected.event_cursor, rooted.cursor);
    assert_eq!(selected.recent_blockhash.last_valid_block_height, 159);
    assert!(store.beam_signing(9_999).unwrap().is_none());
    assert!(store.beam_signing(15_001).unwrap().is_none());
    assert!(store.beam_signing(15_000).unwrap().is_some());
    for slot in 10..=158 {
        commit_payload(&store, &payload(slot - 7, slot, slot - 1, slot));
    }
    assert!(store.beam_signing(10_002).unwrap().is_some());
    commit_payload(&store, &payload(152, 159, 158, 159));
    assert!(
        store.beam_signing(10_003).unwrap().is_none(),
        "native last-valid height must bound readiness even when wall age is fresh"
    );
}

#[test]
fn ahead_heads_cannot_clear_invalidation_or_apply_uncommitted_selection() {
    let t = tempfile::tempdir().unwrap();
    let store = start(&t.path().join("beam.sqlite"), vec![]);
    let now = blockzilla_bank_client::now_ms();
    let first = payload(1, 9, 8, 9);
    commit_payload(&store, &first);
    commit_control(&store, &first, 2, "root", now - 1000);
    let old = payload(3, 10, 9, 10);
    commit_payload(&store, &old);
    commit_control(&store, &old, 4, "confirmed", now - 700);
    commit_control(&store, &old, 5, "invalidate", now - 600);
    let next = payload(6, 11, 9, 10);
    commit_payload(&store, &next);
    let root = commit_control(&store, &next, 7, "root", now - 400);
    assert!(store.beam_needs_reconcile().unwrap());
    assert!(store.beam_signing(now).unwrap().is_none());
    let saved = store.cursor().unwrap();
    let output = store.output_cursor().unwrap();
    let chain = store
        .connection
        .lock()
        .unwrap()
        .query_row("SELECT chain_json FROM checkpoint WHERE id=1", [], |r| {
            r.get::<_, String>(0)
        })
        .unwrap();
    let mut identical = head(&root, now);
    identical.cursor = Some(v2::cursor(&source().session_id, 8, &"ab".repeat(32)));
    assert!(!store.reconcile_beam_head(&identical).unwrap());
    let unseen = payload(8, 12, 11, 11);
    let unseen_control = control(&unseen.frame, 9, "confirmed", now - 100);
    assert!(
        !store
            .reconcile_beam_head(&head(&unseen_control, now))
            .unwrap()
    );
    assert_eq!(store.cursor().unwrap(), saved);
    assert_eq!(store.output_cursor().unwrap(), output);
    assert_eq!(
        store
            .connection
            .lock()
            .unwrap()
            .query_row("SELECT chain_json FROM checkpoint WHERE id=1", [], |r| {
                r.get::<_, String>(0)
            })
            .unwrap(),
        chain
    );
    assert!(store.reconcile_beam_head(&head(&root, now)).unwrap());
    assert!(!store.beam_needs_reconcile().unwrap());
    assert_eq!(
        store.beam_signing(now).unwrap().unwrap().event_cursor,
        root.cursor
    );
}

#[test]
fn cursor_admission_does_not_decode_or_hash_stored_payload() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("beam.sqlite");
    let store = start(&path, vec![]);
    let initial = store.output_cursor().unwrap();
    commit_payload(&store, &payload(1, 9, 8, 9));
    drop(store);
    let c = Connection::open(&path).unwrap();
    c.execute("UPDATE payloads SET projection='not JSON',wire=x'00'", [])
        .unwrap();
    drop(c);
    let store = open(&path, vec![]);
    store.validate_after(&initial).unwrap();
    assert_eq!(
        store.after(&initial).err().unwrap().to_string(),
        "stored_payload_digest_mismatch"
    );
    // Replay admission did not conceal corruption during actual data access.
    assert_eq!(
        store.cursor().unwrap().as_deref(),
        Some(block(1, 9, 9, 8, 9).cursor.as_str())
    );
}

#[test]
fn local_root_rollovers_bound_chain_and_replay_without_ack_pressure() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("beam.sqlite");
    let store = start(&path, vec![]);
    let initial = store.output_cursor().unwrap();
    let mut last = None;
    for offset in 0..600 {
        let slot = 9 + offset;
        let sequence = offset * 2 + 1;
        let p = payload(sequence, slot, slot - 1, slot);
        commit_payload(&store, &p);
        last = Some(commit_control(
            &store,
            &p,
            sequence + 1,
            "root",
            10_000 + offset,
        ));
        assert_eq!(store.ack_backlog().unwrap()["pressure"], false);
        assert!(store.pending_ack().unwrap().is_none());
    }
    assert_eq!(store.beam_status().unwrap()["retainedBanks"], 257);
    let c = store.connection.lock().unwrap();
    assert_eq!(
        c.query_row("SELECT count(*) FROM updates", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        1024
    );
    assert!(
        c.query_row("SELECT count(*) FROM payloads", [], |r| r.get::<_, u64>(0))
            .unwrap()
            <= 513
    );
    assert_eq!(
        c.query_row("SELECT pending_ack FROM checkpoint WHERE id=1", [], |r| r
            .get::<_, u64>(
            0
        ))
        .unwrap(),
        0
    );
    assert_eq!(
        c.query_row(
            "SELECT origin_acked IS NULL FROM checkpoint WHERE id=1",
            [],
            |r| r.get::<_, bool>(0)
        )
        .unwrap(),
        true
    );
    drop(c);
    assert_eq!(
        store.validate_after(&initial).unwrap_err().to_string(),
        "replay_unavailable"
    );
    let raw = last.unwrap().cursor;
    let output = store.output_cursor().unwrap();
    drop(store);
    let store = open(&path, vec![]);
    store
        .bootstrap_beam(&bootstrap(raw.clone()), None, RUNTIME)
        .unwrap();
    assert_eq!(store.cursor().unwrap(), Some(raw));
    assert_eq!(store.output_cursor().unwrap(), output);
    assert_eq!(store.beam_status().unwrap()["retainedBanks"], 257);
    assert_eq!(store.ack_backlog().unwrap()["required"], false);
}
