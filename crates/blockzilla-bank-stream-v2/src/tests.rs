use super::*;
use crate::fixtures::*;
#[test]
fn strict_version_fields_and_counter_limits() {
    let b = block(1, 17, 7, 3, 10);
    let mut e = serde_json::to_value(&b.envelope).unwrap();
    e["event"]
        .as_object_mut()
        .unwrap()
        .remove("recent_blockhash");
    assert!(serde_json::from_value::<Envelope>(e).is_err());
    let mut e = b.envelope.clone();
    e.schema = "blockzilla-stream-envelope-v1".into();
    assert!(encode(e, &vec![42; REQUIRED.len()]).is_err());
    let mut e = b.envelope.event.clone();
    e.source_sequence = SAFE + 1;
    assert!(e.validate().is_err());
    let mut c = control(&b, 2, "confirmed", 1000).envelope;
    c.marker["files"] = serde_json::json!([]);
    assert!(encode(c, &[]).is_err());
}
#[test]
fn controls_require_the_exact_bank_payload_and_native_expiry() {
    let a = block(1, 17, 7, 3, 10);
    let b = block(2, 17, 8, 3, 10);
    let c = control(&a, 3, "confirmed", 1000);
    c.envelope.event.matches_payload(&a).unwrap();
    assert!(c.envelope.event.matches_payload(&b).is_err());
    let mut c = c.envelope;
    c.event.recent_blockhash.as_mut().unwrap().context_slot = 18;
    assert!(encode(c, &[]).is_err());
    let mut c = control(&a, 3, "confirmed", 1000).envelope;
    c.event.recent_blockhash.as_mut().unwrap().blockhash = "1".into();
    assert!(encode(c, &[]).is_err());
}
#[test]
fn processed_is_not_confirmation_and_late_root_cannot_renew_head() {
    let a = block(1, 10, 7, 9, 10);
    let b = block(3, 17, 8, 10, 11);
    let mut chain = chain::Chain::default();
    chain.add_payload(&a).unwrap();
    assert!(chain.latest.is_none());
    chain
        .apply_control(&control(&a, 2, "root", 1000), &a)
        .unwrap();
    chain.add_payload(&b).unwrap();
    chain
        .apply_control(&control(&b, 4, "confirmed", 1200), &b)
        .unwrap();
    let current = chain.latest.clone().unwrap();
    chain
        .apply_control(&control(&a, 5, "root", 2000), &a)
        .unwrap();
    assert_eq!(chain.latest.unwrap(), current);
}
#[test]
fn invalidation_removes_descendants_and_rooted_invalidation_fails() {
    let root = block(1, 9, 1, 8, 9);
    let a = block(3, 10, 2, 9, 10);
    let b = block(4, 17, 3, 10, 11);
    let mut c = chain::Chain::default();
    c.add_payload(&root).unwrap();
    c.apply_control(&control(&root, 2, "root", 1000), &root)
        .unwrap();
    c.add_payload(&a).unwrap();
    c.add_payload(&b).unwrap();
    c.apply_control(&control(&b, 5, "confirmed", 1200), &b)
        .unwrap();
    c.apply_control(&control(&a, 6, "invalidate", 1300), &a)
        .unwrap();
    assert!(c.latest.is_none() && c.reconciliate);
    assert!(c.can_confirm(&b.envelope.event.bank).is_err());
    assert!(
        c.apply_control(&control(&root, 7, "invalidate", 1400), &root)
            .is_err()
    );
}
#[test]
fn head_source_age_and_cursor_are_strict() {
    let b = block(1, 17, 7, 3, 10);
    let f = control(&b, 2, "confirmed", 1000);
    let latest = ConfirmedObservation::from_frame(&f).unwrap();
    let mut h = Head {
        schema: HEAD.into(),
        profile: PROFILE.into(),
        source: source(),
        cursor: Some(f.cursor.clone()),
        earliest_after: Some(cursor("fixture-session", 0, "-")),
        status: "live".into(),
        sampled_at_unix_ms: 2000,
        source_observed_at_unix_ms: Some(1000),
        source_lag_ms: Some(1000),
        latest_confirmed: Some(latest),
    };
    h.validate(&source(), 2000, 5000).unwrap();
    let mut wrong = source();
    wrong.session_id = "other".into();
    assert!(h.validate(&wrong, 2000, 5000).is_err());
    h.sampled_at_unix_ms = 8000;
    h.source_lag_ms = Some(7000);
    assert!(h.validate(&source(), 8000, 5000).is_err());
    h.status = "stale".into();
    h.validate(&source(), 8000, 5000).unwrap();
    h.sampled_at_unix_ms = 20000;
    h.source_lag_ms = Some(19000);
    assert!(h.validate(&source(), 8000, 5000).is_err());
}
#[test]
fn frame_digest_is_not_a_reserialized_marker_digest() {
    let f = block(1, 17, 7, 3, 10);
    assert_ne!(f.envelope.event.payload_sha256, f.sha256);
    assert_ne!(
        f.envelope.event.payload_sha256,
        digest(&serde_json::to_vec(&f.envelope.marker).unwrap())
    );
    assert_eq!(decode(f.wire.clone()).unwrap().sha256, f.sha256);
}

#[test]
fn recovery_notice_checks_sequence_slot_and_exact_event() {
    let block = block(1, 17, 7, 3, 10);
    for frame in [&block, &control(&block, 2, "confirmed", 1000)] {
        let notice = RecoveryStreamNotice::from_frame(frame);
        let sequence = frame.envelope.event.sequence;
        notice
            .preflight(&frame.cursor, sequence, &source())
            .unwrap();
        notice
            .validate(&frame.cursor, frame, sequence, &source())
            .unwrap();
        let mut wrong_sequence = notice.clone();
        wrong_sequence.event.sequence += 1;
        assert!(
            wrong_sequence
                .preflight(&frame.cursor, sequence, &source())
                .is_err()
        );
        let mut wrong_slot = notice.clone();
        wrong_slot.notice.start_slot += 1;
        wrong_slot.notice.end_slot += 1;
        assert!(
            wrong_slot
                .preflight(&frame.cursor, sequence, &source())
                .is_err()
        );
        let mut wrong_bank = notice;
        wrong_bank.event.bank.bank_id += 1;
        assert!(
            wrong_bank
                .validate(&frame.cursor, frame, sequence, &source())
                .is_err()
        );
    }
}

fn rooted_three_banks() -> (chain::Chain, Frame, Frame, Frame) {
    let anchor = block(1, 10, 1, 9, 100);
    let middle = block(3, 17, 2, 10, 101);
    let root = block(4, 30, 3, 17, 102);
    let mut chain = chain::Chain::default();
    chain.add_payload(&anchor).unwrap();
    chain
        .apply_control(&control(&anchor, 2, "root", 1000), &anchor)
        .unwrap();
    chain.add_payload(&middle).unwrap();
    chain.add_payload(&root).unwrap();
    chain
        .apply_control(&control(&root, 5, "root", 1200), &root)
        .unwrap();
    (chain, anchor, middle, root)
}

#[test]
fn rooted_path_is_complete_and_height_ordered_across_skipped_slots() {
    let (chain, anchor, middle, root) = rooted_three_banks();
    let before = serde_json::to_string(&chain).unwrap();
    let path = chain
        .rooted_path_after(&root.envelope.event.bank, &anchor.envelope.event.bank, 100)
        .unwrap();
    assert_eq!(
        path.iter()
            .map(|b| (b.bank.slot, b.block_height))
            .collect::<Vec<_>>(),
        vec![(17, 101), (30, 102)]
    );
    assert_eq!(path[0].payload_frame_sha256, middle.sha256);
    assert_eq!(path[1].payload_frame_sha256, root.sha256);
    assert!(
        !path[0].rooted,
        "ancestor coverage follows the path, not a fabricated per-bank callback"
    );
    assert_eq!(serde_json::to_string(&chain).unwrap(), before);
    assert!(
        chain
            .rooted_path_after(&root.envelope.event.bank, &root.envelope.event.bank, 102)
            .unwrap()
            .is_empty()
    );
    assert!(
        chain
            .rooted_path_after(&root.envelope.event.bank, &root.envelope.event.bank, 103)
            .is_err()
    );
    assert!(
        chain
            .rooted_path_after(
                &middle.envelope.event.bank,
                &anchor.envelope.event.bank,
                100
            )
            .is_err()
    );
}

#[test]
fn rooted_path_rejects_missing_invalidated_or_wrong_height_ancestry() {
    let (chain, anchor, middle, root) = rooted_three_banks();
    let path = |c: &chain::Chain| {
        c.rooted_path_after(&root.envelope.event.bank, &anchor.envelope.event.bank, 100)
    };
    let mut missing = chain.clone();
    missing.banks.remove("17:2");
    assert!(path(&missing).is_err());
    let mut invalidated = chain.clone();
    invalidated.banks.get_mut("17:2").unwrap().invalidated = true;
    assert!(path(&invalidated).is_err());
    let mut wrong_height = chain.clone();
    wrong_height.banks.get_mut("17:2").unwrap().block_height += 1;
    assert!(path(&wrong_height).is_err());
    let mut missing_anchor = chain.clone();
    missing_anchor.banks.remove("10:1");
    assert!(path(&missing_anchor).is_err());
    let mut unknown_prefix = anchor.envelope.event.bank.clone();
    unknown_prefix.slot = 9;
    assert!(
        chain
            .rooted_path_after(&root.envelope.event.bank, &unknown_prefix, 99)
            .is_err()
    );
    let mut unrooted = chain;
    unrooted.banks.get_mut("30:3").unwrap().rooted = false;
    assert!(path(&unrooted).is_err());
    assert_eq!(middle.envelope.event.block_height, Some(101));
}

#[test]
fn rooted_path_does_not_stop_at_an_intermediate_root_or_capture_boundary() {
    let (mut chain, anchor, middle, root) = rooted_three_banks();
    chain
        .apply_control(&control(&middle, 6, "root", 1300), &middle)
        .unwrap();
    chain.boundary = Some((17, middle.envelope.event.bank.blockhash));
    let path = chain
        .rooted_path_after(&root.envelope.event.bank, &anchor.envelope.event.bank, 100)
        .unwrap();
    assert_eq!(path.len(), 2);
    chain.banks.remove("10:1");
    assert!(
        chain
            .rooted_path_after(&root.envelope.event.bank, &anchor.envelope.event.bank, 100)
            .is_err()
    );
}

#[test]
fn rooted_path_preserves_same_slot_banks_and_rejects_ambiguous_parents() {
    let (mut chain, anchor, middle, root) = rooted_three_banks();
    let competing = block(6, 17, 20, 10, 101);
    chain.add_payload(&competing).unwrap();
    assert!(
        chain
            .rooted_path_after(&root.envelope.event.bank, &anchor.envelope.event.bank, 100)
            .is_err()
    );
    chain.banks.get_mut("17:20").unwrap().invalidated = true;
    let path = chain
        .rooted_path_after(&root.envelope.event.bank, &anchor.envelope.event.bank, 100)
        .unwrap();
    assert_eq!(path[0].bank.bank_id, middle.envelope.event.bank.bank_id);
    let competing_root = block(7, 30, 30, 17, 102);
    chain.add_payload(&competing_root).unwrap();
    assert!(
        chain
            .rooted_path_after(
                &root.envelope.event.bank,
                &competing_root.envelope.event.bank,
                102
            )
            .is_err()
    );
    let mut wrong_anchor = anchor.envelope.event.bank.clone();
    wrong_anchor.parent_slot -= 1;
    assert!(
        chain
            .rooted_path_after(&root.envelope.event.bank, &wrong_anchor, 100)
            .is_err()
    );
}

fn seeded_child() -> (chain::Chain, Frame) {
    let child = block(1, 100, 10, 99, 1000);
    let confirmed = control(&child, 2, "confirmed", 1000);
    let mut chain = chain::Chain::default();
    chain
        .seed(
            ConfirmedObservation::from_frame(&confirmed).unwrap(),
            &child,
        )
        .unwrap();
    (chain, child)
}

fn processed_capture() -> (chain::Chain, Frame) {
    let child = block(1, 100, 10, 99, 1000);
    let mut chain = chain::Chain::default();
    chain.add_payload(&child).unwrap();
    chain.boundary = Some((99, [99; 32]));
    (chain, child)
}

#[test]
fn processed_capture_replays_children_and_old_roots_before_confirmation() {
    let (mut chain, child) = processed_capture();
    let descendant = block(2, 101, 11, 100, 1001);
    chain.add_payload(&descendant).unwrap();
    let old = block(3, 68, 20, 67, 968);
    let old_root = control(&old, 4, "root", 1000);
    let boundary = chain.boundary;
    chain.apply_control(&old_root, &old).unwrap();
    assert!(
        chain.latest.is_none(),
        "an older root is not the captured head"
    );
    assert_eq!(chain.boundary, boundary);
    assert!(chain.banks["68:20"].rooted);
    assert!(!chain.banks["100:10"].confirmed);
    assert_eq!(chain.banks.len(), 3, "no uncaptured parents were added");
    chain.validate(&source(), &old_root.cursor).unwrap();

    let confirmed = control(&child, 5, "confirmed", 1000);
    chain.apply_control(&confirmed, &child).unwrap();
    assert_eq!(
        chain.latest,
        Some(ConfirmedObservation::from_frame(&confirmed).unwrap())
    );
    let root = control(&descendant, 6, "root", 1000);
    chain.apply_control(&root, &descendant).unwrap();
    let path = chain
        .rooted_path_from_boundary(&descendant.envelope.event.bank, 99, [99; 32], 999)
        .unwrap();
    assert_eq!(
        path.iter()
            .map(|b| b.payload_frame_sha256.as_str())
            .collect::<Vec<_>>(),
        vec![child.sha256.as_str(), descendant.sha256.as_str()]
    );
    chain.validate(&source(), &root.cursor).unwrap();
}

#[test]
fn payload_cursor_bootstrap_is_unready_until_announced_head_is_replayed() {
    let (_, child) = processed_capture();
    let descendant = block(2, 101, 11, 100, 1001);
    let old = block(3, 68, 20, 67, 968);
    let old_root = control(&old, 4, "root", 1000);
    let confirmed = control(&child, 5, "confirmed", 1000);
    let head = Head {
        schema: HEAD.into(),
        profile: PROFILE.into(),
        source: source(),
        cursor: Some(confirmed.cursor.clone()),
        earliest_after: Some(cursor("fixture-session", 0, "-")),
        status: "live".into(),
        sampled_at_unix_ms: 1000,
        source_observed_at_unix_ms: Some(1000),
        source_lag_ms: Some(0),
        latest_confirmed: Some(ConfirmedObservation::from_frame(&confirmed).unwrap()),
    };
    let mut state = client::ClientState::new(source(), child.cursor.clone()).unwrap();
    state.resolve_head(&head, &confirmed, &child, 1000).unwrap();
    state.health(head, 1000).unwrap();
    assert!(state.ready_hash(1000).is_err());
    for frame in [&descendant, &old, &old_root] {
        state.apply(frame, None, 1000).unwrap();
        assert!(state.ready_hash(1000).is_err());
    }
    state.apply(&confirmed, None, 1000).unwrap();
    state.ready_hash(1000).unwrap();
}

#[test]
fn processed_capture_detached_confirmation_is_not_an_ancestry_anchor() {
    let (mut chain, _) = processed_capture();
    let old = block(2, 68, 20, 67, 968);
    chain
        .apply_control(&control(&old, 3, "confirmed", 1000), &old)
        .unwrap();
    assert!(chain.latest.is_none());
    assert!(chain.banks["68:20"].confirmed);
    assert!(!chain.banks["68:20"].rooted);
    assert!(chain.can_confirm(&old.envelope.event.bank).is_err());
    for kind in ["confirmed", "root"] {
        let mut invalid = chain.clone();
        let gap = block(4, 101, 30, 68, 969);
        assert!(
            invalid
                .apply_control(&control(&gap, 5, kind, 1000), &gap)
                .is_err()
        );
        assert!(invalid.latest.is_none());
        assert!(!invalid.banks["101:30"].confirmed);
        assert!(!invalid.banks["101:30"].rooted);
    }
}

#[test]
fn processed_capture_replays_old_confirmed_after_old_root_without_head_or_coverage() {
    let (mut chain, child) = processed_capture();
    let boundary = chain.boundary;
    let old_root_payload = block(2, 68, 20, 67, 968);
    chain
        .apply_control(
            &control(&old_root_payload, 3, "root", 1000),
            &old_root_payload,
        )
        .unwrap();
    let old = block(4, 98, 21, 97, 998);
    let confirmed = control(&old, 5, "confirmed", 1000);
    chain.apply_control(&confirmed, &old).unwrap();
    assert!(chain.latest.is_none());
    assert_eq!(chain.boundary, boundary);
    assert!(chain.banks["98:21"].confirmed);
    assert!(!chain.banks["98:21"].rooted);
    assert_eq!(chain.banks.len(), 3, "no missing prefix was invented");
    assert!(chain.can_confirm(&old.envelope.event.bank).is_err());
    assert!(
        chain
            .rooted_path_from_boundary(&old.envelope.event.bank, 99, [99; 32], 999)
            .is_err()
    );
    chain.validate(&source(), &confirmed.cursor).unwrap();

    let selected = control(&child, 6, "confirmed", 1000);
    chain.apply_control(&selected, &child).unwrap();
    let expected = ConfirmedObservation::from_frame(&selected).unwrap();
    assert_eq!(chain.latest.as_ref(), Some(&expected));
    let later_old = control(&old, 7, "confirmed", 2000);
    chain.apply_control(&later_old, &old).unwrap();
    assert_eq!(chain.latest.as_ref(), Some(&expected));
    assert_eq!(chain.boundary, boundary);
    assert!(!chain.banks["98:21"].rooted);
    chain.validate(&source(), &later_old.cursor).unwrap();
}

#[test]
fn detached_confirmed_rejects_invalid_ambiguous_wrong_source_and_boundary_proofs() {
    let old = block(3, 98, 21, 97, 998);
    let confirmed = control(&old, 4, "confirmed", 1000);
    let parent = block(2, 97, 30, 96, 997);
    let (mut invalidated, _) = processed_capture();
    invalidated
        .apply_control(&control(&parent, 3, "invalidate", 1000), &parent)
        .unwrap();
    assert!(invalidated.apply_control(&confirmed, &old).is_err());
    let (mut ambiguous, _) = processed_capture();
    ambiguous.add_payload(&parent).unwrap();
    ambiguous.add_payload(&block(2, 97, 31, 96, 997)).unwrap();
    assert!(ambiguous.apply_control(&confirmed, &old).is_err());
    let (mut wrong_source, _) = processed_capture();
    let mut changed = confirmed.clone();
    changed.source.session_id = "another-source".into();
    assert!(wrong_source.apply_control(&changed, &old).is_err());
    assert!(
        wrong_source
            .apply_control(&confirmed, &block(3, 98, 22, 97, 998))
            .is_err()
    );

    let (mut wrong_height, _) = processed_capture();
    let parent = block(2, 99, 20, 98, 998);
    assert!(
        wrong_height
            .apply_control(&control(&parent, 3, "confirmed", 1000), &parent)
            .is_err()
    );
    let (mut wrong_hash, _) = processed_capture();
    let parent = block(2, 99, 20, 98, 999);
    let mut envelope = parent.envelope.clone();
    envelope.event.bank.blockhash = [200; 32];
    envelope.marker["produced_blocks"] = serde_json::json!([envelope.event.bank]);
    let parent = encode(envelope, &vec![42; REQUIRED.len()]).unwrap();
    assert!(
        wrong_hash
            .apply_control(&control(&parent, 3, "confirmed", 1000), &parent)
            .is_err()
    );
    let (mut exact, _) = processed_capture();
    let parent = block(2, 99, 20, 98, 999);
    exact
        .apply_control(&control(&parent, 3, "confirmed", 1000), &parent)
        .unwrap();
    assert!(exact.latest.is_none());
    assert_eq!(exact.boundary, Some((99, [99; 32])));
    assert!(exact.banks["99:20"].confirmed);
    assert!(!exact.banks["99:20"].rooted);
}

#[test]
fn processed_capture_old_root_requires_valid_consistent_boundary_children() {
    let old = block(3, 68, 20, 67, 968);
    let root = control(&old, 4, "root", 1000);
    let mut missing = chain::Chain {
        boundary: Some((99, [99; 32])),
        ..Default::default()
    };
    assert!(missing.apply_control(&root, &old).is_err());

    let (mut invalid, child) = processed_capture();
    invalid
        .apply_control(&control(&child, 2, "invalidate", 1000), &child)
        .unwrap();
    assert!(invalid.apply_control(&root, &old).is_err());

    let (mut conflicting, _) = processed_capture();
    conflicting
        .add_payload(&block(2, 102, 11, 99, 1002))
        .unwrap();
    assert!(conflicting.apply_control(&root, &old).is_err());
    assert!(conflicting.latest.is_none());
    assert!(!conflicting.banks["68:20"].rooted);
}

#[test]
fn processed_capture_parent_root_requires_exact_hash_and_native_height() {
    let (mut chain, _) = processed_capture();
    let wrong_height = block(2, 99, 20, 98, 998);
    assert!(
        chain
            .apply_control(&control(&wrong_height, 3, "root", 1000), &wrong_height)
            .is_err()
    );

    let (mut chain, _) = processed_capture();
    let wrong_hash = block(2, 99, 20, 98, 999);
    let mut envelope = wrong_hash.envelope.clone();
    envelope.event.bank.blockhash = [200; 32];
    envelope.marker["produced_blocks"] = serde_json::json!([envelope.event.bank]);
    let wrong_hash = encode(envelope, &vec![42; REQUIRED.len()]).unwrap();
    assert!(
        chain
            .apply_control(&control(&wrong_hash, 3, "root", 1000), &wrong_hash)
            .is_err()
    );

    let (mut chain, _) = processed_capture();
    let parent = block(2, 99, 20, 98, 999);
    chain
        .apply_control(&control(&parent, 3, "root", 1000), &parent)
        .unwrap();
    assert!(chain.latest.is_none());
    assert_eq!(chain.boundary, Some((99, [99; 32])));
}

#[test]
fn seeded_head_admits_detached_old_root_without_renewal_or_prefix_claim() {
    let (mut chain, child) = seeded_child();
    let before = chain.latest.clone().unwrap();
    let boundary = chain.boundary;
    let old = block(3, 68, 20, 67, 968);
    let root = control(&old, 4, "root", 2000);
    chain.apply_control(&root, &old).unwrap();
    assert_eq!(chain.latest.as_ref(), Some(&before));
    assert_eq!(chain.boundary, boundary);
    assert!(chain.banks["68:20"].rooted);
    assert_eq!(chain.banks.len(), 2, "no uncaptured ancestors were added");
    chain.validate(&source(), &root.cursor).unwrap();
    chain.can_confirm(&child.envelope.event.bank).unwrap();
    assert!(
        chain
            .rooted_path_after(&old.envelope.event.bank, &child.envelope.event.bank, 1000)
            .is_err()
    );
    assert!(
        chain
            .rooted_path_after(&child.envelope.event.bank, &old.envelope.event.bank, 968)
            .is_err()
    );
}

#[test]
fn detached_confirmation_preserves_seeded_head_and_rejects_post_capture_gaps() {
    let (mut chain, _) = seeded_child();
    let selected = chain.latest.clone();
    let boundary = chain.boundary;
    let old = block(3, 68, 20, 67, 968);
    chain
        .apply_control(&control(&old, 4, "confirmed", 2000), &old)
        .unwrap();
    assert!(chain.banks["68:20"].confirmed);
    assert!(!chain.banks["68:20"].rooted);
    assert_eq!(chain.latest, selected);
    assert_eq!(chain.boundary, boundary);
    assert!(chain.can_confirm(&old.envelope.event.bank).is_err());
    for kind in ["confirmed", "root"] {
        let mut invalid = chain.clone();
        let gap = block(5, 101, 30, 97, 1001);
        assert!(
            invalid
                .apply_control(&control(&gap, 6, kind, 2000), &gap)
                .is_err()
        );
        assert!(!invalid.banks["101:30"].rooted);
        assert!(!invalid.banks["101:30"].confirmed);
        assert_eq!(invalid.latest, selected);
    }
}

#[test]
fn old_root_still_rejects_invalidated_ambiguous_and_wrong_source_dependencies() {
    let (mut invalidated, _) = seeded_child();
    let parent = block(3, 67, 30, 66, 967);
    invalidated
        .apply_control(&control(&parent, 4, "invalidate", 1500), &parent)
        .unwrap();
    let old = block(5, 68, 20, 67, 968);
    assert!(
        invalidated
            .apply_control(&control(&old, 6, "root", 2000), &old)
            .is_err()
    );
    let (mut ambiguous, _) = seeded_child();
    ambiguous.add_payload(&parent).unwrap();
    ambiguous.add_payload(&block(4, 67, 31, 66, 967)).unwrap();
    assert!(
        ambiguous
            .apply_control(&control(&old, 6, "root", 2000), &old)
            .is_err()
    );
    let (mut wrong_source, _) = seeded_child();
    let mut root = control(&old, 6, "root", 2000);
    root.source.session_id = "different-session".into();
    assert!(wrong_source.apply_control(&root, &old).is_err());
    let another = block(7, 68, 21, 67, 968);
    assert!(
        wrong_source
            .apply_control(&control(&old, 6, "root", 2000), &another)
            .is_err()
    );
}

#[test]
fn boundary_root_requires_the_selected_parent_hash_and_height() {
    let (mut chain, _) = seeded_child();
    let wrong_height = block(3, 99, 20, 98, 998);
    assert!(
        chain
            .apply_control(&control(&wrong_height, 4, "root", 2000), &wrong_height)
            .is_err()
    );
    let (mut chain, _) = seeded_child();
    let wrong_hash = block(3, 99, 20, 98, 999);
    let mut envelope = wrong_hash.envelope.clone();
    envelope.event.bank.blockhash = [200; 32];
    envelope.marker["produced_blocks"] = serde_json::json!([envelope.event.bank]);
    let wrong_hash = encode(envelope, &vec![42; REQUIRED.len()]).unwrap();
    assert!(
        chain
            .apply_control(&control(&wrong_hash, 4, "root", 2000), &wrong_hash)
            .is_err()
    );
    let (mut chain, _) = seeded_child();
    let parent = block(3, 99, 20, 98, 999);
    let selected = chain.latest.clone();
    chain
        .apply_control(&control(&parent, 4, "root", 2000), &parent)
        .unwrap();
    assert_eq!(chain.latest, selected);
    assert_eq!(chain.boundary, Some((99, [99; 32])));
}

#[test]
fn detached_old_root_does_not_move_boundary_at_prune_threshold() {
    let (mut chain, child) = seeded_child();
    for slot in 2000..2000 + chain::MAX_BANKS as u64 / 2 {
        chain
            .add_payload(&block(slot, slot, slot, slot - 1, slot))
            .unwrap();
    }
    let boundary = chain.boundary;
    let old = block(3, 68, 20, 67, 968);
    let root = control(&old, 4, "root", 2000);
    chain.apply_control(&root, &old).unwrap();
    assert_eq!(chain.boundary, boundary);
    chain.validate(&source(), &root.cursor).unwrap();
    chain.can_confirm(&child.envelope.event.bank).unwrap();
}

#[test]
fn root_path_from_boundary_uses_the_exact_excluded_parent_without_prefix_claim() {
    let (chain, anchor, middle, root) = rooted_three_banks();
    let path = chain
        .rooted_path_from_boundary(&root.envelope.event.bank, 9, [9; 32], 99)
        .unwrap();
    assert_eq!(
        path.iter().map(|b| b.bank.bank_id).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(
        path.iter()
            .map(|b| b.payload_frame_sha256.as_str())
            .collect::<Vec<_>>(),
        vec![
            anchor.sha256.as_str(),
            middle.sha256.as_str(),
            root.sha256.as_str()
        ]
    );
    assert!(!chain.banks.contains_key("9:0"));
    let before = serde_json::to_string(&chain).unwrap();
    assert_eq!(
        chain
            .rooted_path_from_boundary(&root.envelope.event.bank, 10, [10; 32], 100)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(serde_json::to_string(&chain).unwrap(), before);
    assert!(
        chain
            .rooted_path_from_boundary(&root.envelope.event.bank, 30, [30; 32], 102)
            .unwrap()
            .is_empty()
    );
    assert!(
        chain
            .rooted_path_from_boundary(&root.envelope.event.bank, 30, [200; 32], 102)
            .is_err()
    );
    assert!(
        chain
            .rooted_path_from_boundary(&root.envelope.event.bank, 30, [30; 32], 103)
            .is_err()
    );
    assert!(
        chain
            .rooted_path_from_boundary(&root.envelope.event.bank, 9, [9; 32], 98)
            .is_err()
    );
    assert!(
        chain
            .rooted_path_from_boundary(&root.envelope.event.bank, 9, [200; 32], 99)
            .is_err()
    );
    assert!(
        chain
            .rooted_path_from_boundary(&root.envelope.event.bank, 31, [31; 32], 103)
            .is_err()
    );
}

#[test]
fn root_path_from_boundary_rejects_missing_ambiguous_invalidated_or_bad_height_interior() {
    let (chain, _, _, root) = rooted_three_banks();
    let path =
        |c: &chain::Chain| c.rooted_path_from_boundary(&root.envelope.event.bank, 9, [9; 32], 99);
    let mut missing = chain.clone();
    missing.banks.remove("17:2");
    assert!(path(&missing).is_err());
    let mut invalidated = chain.clone();
    invalidated.banks.get_mut("17:2").unwrap().invalidated = true;
    assert!(path(&invalidated).is_err());
    let mut bad_height = chain.clone();
    bad_height.banks.get_mut("17:2").unwrap().block_height += 1;
    assert!(path(&bad_height).is_err());
    let mut ambiguous = chain.clone();
    ambiguous.add_payload(&block(6, 17, 20, 10, 101)).unwrap();
    assert!(path(&ambiguous).is_err());
    let mut unrooted = chain;
    unrooted.banks.get_mut("30:3").unwrap().rooted = false;
    assert!(path(&unrooted).is_err());
}
