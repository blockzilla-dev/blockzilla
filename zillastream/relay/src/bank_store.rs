//! A control pins its exact payload. Frame/spool/head commits have one boundary.
use crate::{
    source::bounded_file,
    store::{atomic, now_ms},
};
use anyhow::{Context, Result, ensure};
use blockzilla_bank_stream_v2::{
    self as v2, Frame, Head, SourceIdentity,
    chain::{BankState, Chain},
    finalized::BlockId,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    fs::{self, File},
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};
use tokio::sync::Notify;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    pub source: SourceIdentity,
    pub cursor: String,
    pub chain: Chain,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    schema: String,
    source: SourceIdentity,
    base: String,
    events: Vec<String>,
    frames: Vec<String>,
    chain: Chain,
}
#[derive(Clone)]
struct State {
    base: String,
    events: VecDeque<Arc<Frame>>,
    frames: BTreeMap<String, Arc<Frame>>,
    chain: Chain,
    selected_at: Instant,
    selected_age: u64,
    status: String,
    health_at: Instant,
    error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use v2::fixtures::*;
    fn fresh(mut f: Frame) -> Frame {
        f.envelope.event.observed_at_unix_ms = now_ms();
        let n = u32::from_le_bytes(f.wire[8..12].try_into().unwrap()) as usize;
        v2::encode(f.envelope, &f.wire[16 + n..]).unwrap()
    }
    #[test]
    fn durable_control_dependencies_resume_and_duplicate_admission() {
        let t = tempfile::tempdir().unwrap();
        let base = v2::cursor(&source().session_id, 0, "-");
        let s = BankStore::open(source(), base.clone(), v2::MAX_FRAME, t.path().into()).unwrap();
        let b = fresh(block(1, 9, 1, 8, 9));
        s.admit(b.clone(), None).unwrap();
        assert!(s.head().latest_confirmed.is_none());
        let c = control(&b, 2, "root", now_ms());
        s.admit(c.clone(), None).unwrap();
        s.admit(c.clone(), None).unwrap();
        s.set_health("live", None);
        assert_eq!(s.head().status, "live");
        assert_eq!(s.after(&base).unwrap().unwrap().cursor, b.cursor);
        assert_eq!(s.after(&b.cursor).unwrap().unwrap().cursor, c.cursor);
        assert!(s.after(&c.cursor).unwrap().is_none());
        assert_eq!(
            s.after(&v2::cursor(&source().session_id, 1, &c.sha256))
                .unwrap_err()
                .to_string(),
            "invalid_cursor"
        );
        assert_eq!(
            s.after(&v2::cursor(&source().session_id, 0, &b.sha256))
                .unwrap_err()
                .to_string(),
            "invalid_cursor"
        );
        assert!(
            s.after(&v2::cursor("wrong-session", 0, "-"))
                .unwrap_err()
                .to_string()
                .contains("source_changed")
        );
        drop(s);
        let s = BankStore::open(source(), base, v2::MAX_FRAME, t.path().into()).unwrap();
        assert_eq!(s.latest(), c.cursor);
        assert_eq!(s.chunk(&b.sha256).unwrap().wire, b.wire);
        assert_eq!(s.head().status, "stale");
        let mut bad = c.envelope;
        bad.event.sequence = 4;
        assert!(s.admit(v2::encode(bad, &[]).unwrap(), None).is_err());
    }
    #[test]
    fn landed_root_fallback_checks_earlier_confirmations_for_the_same_block() {
        let dir = tempfile::tempdir().unwrap();
        let store = BankStore::open(
            source(),
            v2::cursor(&source().session_id, 0, "-"),
            v2::MAX_FRAME,
            dir.path().into(),
        )
        .unwrap();
        let first = fresh(block(1, 9, 1, 8, 9));
        let first_root = control(&first, 2, "root", now_ms());
        store.admit(first, None).unwrap();
        store.admit(first_root.clone(), None).unwrap();
        assert!(!store.retained_confirmation_before(&first_root));

        let next = fresh(block(3, 17, 2, 9, 10));
        let confirmed = control(&next, 4, "confirmed", now_ms());
        let next_root = control(&next, 5, "root", now_ms());
        store.admit(next, None).unwrap();
        store.admit(confirmed, None).unwrap();
        store.admit(next_root.clone(), None).unwrap();
        assert!(store.retained_confirmation_before(&next_root));
        assert!(!store.retained_confirmation_before(&first_root));
    }
    #[test]
    fn memory_store_replays_exact_frames_and_has_no_saved_boundary() {
        let base = v2::cursor(&source().session_id, 0, "-");
        let payload = fresh(block(1, 9, 1, 8, 9));
        let root = control(&payload, 2, "root", now_ms());
        let store = BankStore::open_memory(source(), base.clone(), v2::MAX_FRAME).unwrap();
        store.admit(payload.clone(), None).unwrap();
        store.admit(root.clone(), None).unwrap();
        assert_eq!(store.after(&base).unwrap().unwrap().cursor, payload.cursor);
        assert_eq!(
            store.after(&payload.cursor).unwrap().unwrap().cursor,
            root.cursor
        );
        assert_eq!(store.chunk(&payload.sha256).unwrap().wire, payload.wire);
        assert!(!store.needs_bootstrap());
        drop(store);

        let store = BankStore::open_memory(source(), base, v2::MAX_FRAME).unwrap();
        assert!(store.needs_bootstrap());
        assert!(store.chunk(&payload.sha256).is_none());
        assert!(store.after(&root.cursor).is_err());
    }
    #[test]
    fn finalized_window_emits_exact_rooted_path_and_skips_unrooted_forks() {
        let store = BankStore::open_memory(
            source(),
            v2::cursor(&source().session_id, 0, "-"),
            v2::MAX_FRAME,
        )
        .unwrap();
        let anchor = fresh(block(1, 9, 1, 8, 9));
        let middle = fresh(block(3, 12, 2, 9, 10));
        let fork = fresh(block(4, 13, 3, 9, 10));
        let tip = fresh(block(5, 17, 4, 12, 11));
        let newer = fresh(block(7, 21, 5, 17, 12));
        store.admit(anchor.clone(), None).unwrap();
        assert!(store.finalized_window(None).unwrap().frames.is_empty());
        store
            .admit_batch(vec![
                (control(&anchor, 2, "root", now_ms()), None),
                (middle.clone(), None),
                (fork.clone(), None),
                (tip.clone(), None),
                (control(&tip, 6, "root", now_ms()), None),
                (newer.clone(), None),
                (control(&newer, 8, "confirmed", now_ms()), None),
            ])
            .unwrap();
        let tip_id = BlockId::from(&tip.envelope.event.bank);
        let anchor_id = BlockId::from(&anchor.envelope.event.bank);
        let window = store.finalized_window(None).unwrap();
        assert_eq!(window.tip, Some(tip_id));
        assert_eq!(window.frames.len(), 1);
        assert_eq!(window.frames[0].wire, tip.wire);
        assert_eq!(store.finalized_tip().unwrap(), Some(tip_id));

        let window = store.finalized_window(Some(&anchor_id)).unwrap();
        assert_eq!(window.frames.len(), 2);
        assert_eq!(window.frames[0].wire, middle.wire);
        assert_eq!(window.frames[1].wire, tip.wire);
        let middle_id = BlockId::from(&middle.envelope.event.bank);
        let window = store.finalized_window(Some(&middle_id)).unwrap();
        assert_eq!(window.frames.len(), 1);
        assert_eq!(window.frames[0].wire, tip.wire);
        assert!(
            store
                .finalized_window(Some(&tip_id))
                .unwrap()
                .frames
                .is_empty()
        );
        for frame in [&fork, &newer] {
            let after = BlockId::from(&frame.envelope.event.bank);
            assert!(store.finalized_window(Some(&after)).is_err());
        }

        store.state.lock().unwrap().frames.remove(&tip.sha256);
        assert_eq!(
            store
                .finalized_window(Some(&anchor_id))
                .unwrap_err()
                .to_string(),
            "replay_unavailable"
        );
        assert!(store.finalized_window(None).is_err());
    }

    #[test]
    fn finalized_window_refuses_conflicting_roots_even_on_fresh_join() {
        let store = BankStore::open_memory(
            source(),
            v2::cursor(&source().session_id, 0, "-"),
            v2::MAX_FRAME,
        )
        .unwrap();
        let anchor = fresh(block(1, 9, 1, 8, 9));
        let first_root = fresh(block(3, 12, 2, 9, 10));
        let fork = fresh(block(5, 13, 3, 9, 10));
        let competing_root = fresh(block(6, 17, 4, 13, 11));
        store
            .admit_batch(vec![
                (anchor.clone(), None),
                (control(&anchor, 2, "root", now_ms()), None),
                (first_root.clone(), None),
                (control(&first_root, 4, "root", now_ms()), None),
                (fork, None),
                (competing_root.clone(), None),
                (control(&competing_root, 7, "root", now_ms()), None),
            ])
            .unwrap();
        assert_eq!(
            store.finalized_window(None).unwrap_err().to_string(),
            "finalized_conflict"
        );
    }

    #[test]
    fn finalized_window_limits_batches_and_can_resume_from_an_ancestor() {
        let store = BankStore::open_memory(
            source(),
            v2::cursor(&source().session_id, 0, "-"),
            v2::MAX_FRAME,
        )
        .unwrap();
        let anchor = fresh(block(1, 2, 1, 1, 2));
        store.admit(anchor.clone(), None).unwrap();
        store
            .admit(control(&anchor, 2, "root", now_ms()), None)
            .unwrap();
        let mut tip = anchor.clone();
        for number in 3..=(MAX_FINALIZED_WINDOW + 3) as u64 {
            tip = fresh(block(number, number, number, number - 1, number));
            store.admit(tip.clone(), None).unwrap();
        }
        store
            .admit(
                control(&tip, tip.envelope.event.sequence + 1, "root", now_ms()),
                None,
            )
            .unwrap();
        let after = BlockId::from(&anchor.envelope.event.bank);
        let first = store.finalized_window(Some(&after)).unwrap();
        assert_eq!(first.frames.len(), MAX_FINALIZED_WINDOW);
        let after = BlockId::from(&first.frames.last().unwrap().envelope.event.bank);
        let second = store.finalized_window(Some(&after)).unwrap();
        assert_eq!(second.frames.len(), 1);
        assert_eq!(second.frames[0].wire, tip.wire);
    }

    #[test]
    fn retention_pins_control_and_head_and_expiry_is_an_explicit_gap() {
        let t = tempfile::tempdir().unwrap();
        let base = v2::cursor(&source().session_id, 0, "-");
        let s = BankStore::open(source(), base.clone(), v2::MAX_FRAME, t.path().into()).unwrap();
        let b = fresh(block(1, 9, 1, 8, 9));
        s.admit(b.clone(), None).unwrap();
        s.admit(control(&b, 2, "root", now_ms()), None).unwrap();
        // Inflate a permitted fixture object to exercise byte eviction with only a few events.
        for n in 3..8 {
            let f = block(n, 10 + n, n, 8, 10);
            let mut e = f.envelope;
            let bytes = vec![42; 4 * 1024 * 1024];
            let mut body = vec![42; v2::REQUIRED.len() - 1];
            e.objects.last_mut().unwrap().bytes = bytes.len();
            e.objects.last_mut().unwrap().sha256 = v2::digest(&bytes);
            let row = e.marker["files"]
                .as_array_mut()
                .unwrap()
                .last_mut()
                .unwrap();
            row["bytes"] = bytes.len().into();
            row["sha256"] = v2::digest(&bytes).into();
            body.extend(bytes);
            s.admit(v2::encode(e, &body).unwrap(), None).unwrap();
        }
        assert!(
            s.after(&base)
                .unwrap_err()
                .to_string()
                .contains("replay_unavailable")
        );
        assert!(s.chunk(&b.sha256).is_some());
        assert!(s.metrics()["replay_bytes"].as_u64().unwrap() <= v2::MAX_FRAME as u64);
        drop(s);
        let s = BankStore::open(source(), base, v2::MAX_FRAME, t.path().into()).unwrap();
        assert!(s.chunk(&b.sha256).is_some());
    }
    #[test]
    fn repeated_health_or_older_root_cannot_renew_observation_age() {
        let t = tempfile::tempdir().unwrap();
        let s = BankStore::open(
            source(),
            v2::cursor(&source().session_id, 0, "-"),
            v2::MAX_FRAME,
            t.path().into(),
        )
        .unwrap();
        let root = fresh(block(1, 9, 1, 8, 9));
        s.admit(root.clone(), None).unwrap();
        s.admit(control(&root, 2, "root", now_ms()), None).unwrap();
        let b = fresh(block(3, 17, 2, 9, 10));
        s.admit(b.clone(), None).unwrap();
        s.admit(control(&b, 4, "confirmed", now_ms()), None)
            .unwrap();
        {
            s.state.lock().unwrap().selected_age = 20_000;
        }
        s.set_health("live", None);
        s.admit(control(&root, 5, "root", now_ms()), None).unwrap();
        s.set_health("live", None);
        assert_eq!(s.head().status, "stale");
        assert_eq!(
            s.head().latest_confirmed.unwrap().bank,
            b.envelope.event.bank
        );
        let mut future = control(&b, 6, "confirmed", now_ms() + 6000);
        assert!(s.admit(future.clone(), None).is_err());
        future.envelope.event.sequence = 6;
    }
    #[test]
    fn status_cadence_leaves_delivery_margin_but_a_real_health_stall_expires() {
        let t = tempfile::tempdir().unwrap();
        let s = BankStore::open(
            source(),
            v2::cursor(&source().session_id, 0, "-"),
            v2::MAX_FRAME,
            t.path().into(),
        )
        .unwrap();
        let root = fresh(block(1, 9, 1, 8, 9));
        s.admit(root.clone(), None).unwrap();
        s.admit(control(&root, 2, "root", now_ms()), None).unwrap();
        s.set_health("live", None);
        let delivery_delay = Duration::from_millis(100);
        // The former five-second cadence uses the entire health lifetime.
        s.state.lock().unwrap().health_at =
            Instant::now() - Duration::from_secs(5) - delivery_delay;
        let next = fresh(block(3, 17, 2, 9, 10));
        s.admit(next.clone(), None).unwrap();
        s.admit(control(&next, 4, "confirmed", now_ms()), None)
            .unwrap();
        let h = s.head();
        assert!(h.source_lag_ms.unwrap() < v2::DEFAULT_MAX_LAG_MS);
        assert_eq!(h.latest_confirmed.unwrap().bank, next.envelope.event.bank);
        assert_eq!(h.status, "stale"); // Fresh frames cannot renew health.

        // Model the longest normal interval plus the same delivery delay.
        s.state.lock().unwrap().health_at =
            Instant::now() - crate::bank_server::STATUS_INTERVAL - delivery_delay;
        assert_eq!(s.head().status, "live");
        s.state.lock().unwrap().health_at =
            Instant::now() - Duration::from_millis(v2::DEFAULT_MAX_LAG_MS + 1);
        assert_eq!(s.head().status, "stale");
    }
    #[test]
    fn batch_commit_is_atomic_bounded_and_restores_all_dependencies() {
        let t = tempfile::tempdir().unwrap();
        let base = v2::cursor(&source().session_id, 0, "-");
        let s = BankStore::open(source(), base.clone(), v2::MAX_FRAME, t.path().into()).unwrap();
        let b = fresh(block(1, 9, 1, 8, 9));
        let root = control(&b, 2, "root", now_ms());
        assert!(
            s.admit_batch(vec![
                (b.clone(), None),
                (control(&b, 3, "root", now_ms()), None)
            ])
            .is_err()
        );
        assert_eq!(s.latest(), base);
        assert!(s.chunk(&b.sha256).is_none());
        assert!(!t.path().join("CHECKPOINT.json").exists());
        assert!(
            s.admit_batch(vec![(b.clone(), None); MAX_BATCH_EVENTS + 1])
                .is_err()
        );
        s.admit_batch(vec![(b.clone(), None), (root.clone(), None)])
            .unwrap();
        assert_eq!(s.latest(), root.cursor);
        drop(s);
        let s = BankStore::open(source(), base, v2::MAX_FRAME, t.path().into()).unwrap();
        assert_eq!(s.latest(), root.cursor);
        assert!(s.chunk(&b.sha256).is_some());
        assert_eq!(
            s.head().latest_confirmed.unwrap().bank,
            b.envelope.event.bank
        );
    }
    fn padded(f: Frame, bytes: usize) -> Frame {
        let mut envelope = f.envelope;
        let object = envelope.objects.last_mut().unwrap();
        object.bytes = bytes;
        let content = vec![42; bytes];
        object.sha256 = v2::digest(&content);
        let row = envelope.marker["files"]
            .as_array_mut()
            .unwrap()
            .last_mut()
            .unwrap();
        row["bytes"] = bytes.into();
        row["sha256"] = object.sha256.clone().into();
        let mut body = vec![42; v2::REQUIRED.len() - 1];
        body.extend(content);
        v2::encode(envelope, &body).unwrap()
    }
    #[test]
    fn oversized_batch_cannot_change_the_durable_boundary() {
        let t = tempfile::tempdir().unwrap();
        let base = v2::cursor(&source().session_id, 0, "-");
        let s = BankStore::open(source(), base.clone(), v2::MAX_FRAME, t.path().into()).unwrap();
        let f = padded(fresh(block(1, 9, 1, 8, 9)), 8 * 1024 * 1024);
        let count = MAX_BATCH_BYTES / f.wire.len() + 1;
        assert_eq!(
            s.admit_batch(vec![(f, None); count])
                .unwrap_err()
                .to_string(),
            "batch_too_large"
        );
        assert_eq!(s.latest(), base);
        assert!(!t.path().join("CHECKPOINT.json").exists());
    }
    #[test]
    #[ignore = "finite disk and replay capacity measurement"]
    fn bounded_spool_capacity_and_exact_restore() {
        let t = tempfile::tempdir().unwrap();
        let base = v2::cursor(&source().session_id, 0, "-");
        let s = BankStore::open(source(), base.clone(), v2::MAX_FRAME, t.path().into()).unwrap();
        let started = Instant::now();
        let mut batch = Vec::new();
        let mut last = base.clone();
        for bank in 1..=1024 {
            let b = padded(
                fresh(block(2 * bank - 1, bank + 8, bank, bank + 7, bank + 8)),
                65536,
            );
            let root = control(&b, 2 * bank, "root", now_ms());
            last = root.cursor.clone();
            batch.extend([(b, None), (root, None)]);
            if batch.len() == MAX_BATCH_EVENTS {
                s.admit_batch(std::mem::take(&mut batch)).unwrap();
            }
        }
        assert!(batch.is_empty());
        assert_eq!(s.latest(), last);
        assert_eq!(
            s.after(&base).unwrap_err().to_string(),
            "replay_unavailable"
        );
        let checkpoint = s.head().earliest_after.unwrap();
        let mut cursor = checkpoint.clone();
        let mut replayed = 0;
        while let Some(frame) = s.after(&cursor).unwrap() {
            cursor = frame.cursor.clone();
            replayed += 1;
        }
        assert_eq!(cursor, last);
        let seconds = started.elapsed().as_secs_f64();
        eprintln!(
            "capacity events=2048 seconds={seconds:.3} events_per_second={:.3} retained_events={replayed}",
            2048.0 / seconds
        );
        drop(s);
        let s = BankStore::open(source(), base, v2::MAX_FRAME, t.path().into()).unwrap();
        assert_eq!(s.latest(), last);
        assert_eq!(s.head().earliest_after.unwrap(), checkpoint);
        assert!(
            s.chunk(&s.head().latest_confirmed.unwrap().payload_frame_sha256)
                .is_some()
        );
    }
    #[test]
    #[ignore = "full retained-window disk and reader capacity measurement"]
    fn full_window_capacity_and_exact_restore() {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        const EVENTS: u64 = 66_048;
        const LAST_WINDOW: u64 = 4096;
        let t = tempfile::tempdir().unwrap();
        let base = v2::cursor(&source().session_id, 0, "-");
        let limit = 512 * 1024 * 1024;
        let s = BankStore::open(source(), base.clone(), limit, t.path().into()).unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let reads = Arc::new(AtomicU64::new(0));
        let max_read_ns = Arc::new(AtomicU64::new(0));
        let reader = {
            let s = s.clone();
            let stopped = stopped.clone();
            let reads = reads.clone();
            let maximum = max_read_ns.clone();
            std::thread::spawn(move || {
                while !stopped.load(Ordering::Relaxed) {
                    let before = Instant::now();
                    let _ = s.head();
                    maximum.fetch_max(before.elapsed().as_nanos() as u64, Ordering::Relaxed);
                    reads.fetch_add(1, Ordering::Relaxed);
                    std::thread::sleep(Duration::from_millis(10));
                }
            })
        };
        let started = Instant::now();
        let mut last_window = started;
        let mut batch = Vec::new();
        for bank in 1..=EVENTS / 2 {
            if bank == (EVENTS - LAST_WINDOW) / 2 + 1 {
                last_window = Instant::now();
            }
            let b = padded(
                fresh(block(2 * bank - 1, bank + 8, bank, bank + 7, bank + 8)),
                4096,
            );
            let root = control(&b, 2 * bank, "root", now_ms());
            batch.extend([(b, None), (root, None)]);
            if batch.len() == MAX_BATCH_EVENTS {
                s.admit_batch(std::mem::take(&mut batch)).unwrap();
            }
        }
        let write_seconds = started.elapsed().as_secs_f64();
        let last_seconds = last_window.elapsed().as_secs_f64();
        stopped.store(true, Ordering::Relaxed);
        reader.join().unwrap();
        assert!(batch.is_empty());
        assert_eq!(s.metrics()["retained_events"], 65536);
        assert_eq!(
            s.after(&base).unwrap_err().to_string(),
            "replay_unavailable"
        );
        let head = s.head();
        let latest = head.cursor.unwrap();
        let earliest = head.earliest_after.unwrap();
        assert_eq!(v2::parse_cursor(&earliest).unwrap().1, EVENTS - 65536);
        let before_replay = Instant::now();
        let mut cursor = earliest.clone();
        let mut replayed = 0;
        while let Some(frame) = s.after(&cursor).unwrap() {
            cursor = frame.cursor.clone();
            replayed += 1;
        }
        assert_eq!(replayed, 65536);
        assert_eq!(cursor, latest);
        let replay_seconds = before_replay.elapsed().as_secs_f64();
        let checkpoint = fs::read(t.path().join("CHECKPOINT.json")).unwrap();
        let checkpoint_digest = v2::digest(&checkpoint);
        let checkpoint_bytes = checkpoint.len();
        drop(s);
        let before_restore = Instant::now();
        let s = BankStore::open(source(), base, limit, t.path().into()).unwrap();
        let restore_seconds = before_restore.elapsed().as_secs_f64();
        assert_eq!(s.latest(), latest);
        assert_eq!(s.head().earliest_after.unwrap(), earliest);
        assert_eq!(s.metrics()["retained_events"], 65536);
        assert_eq!(
            v2::digest(&fs::read(t.path().join("CHECKPOINT.json")).unwrap()),
            checkpoint_digest
        );
        eprintln!(
            "full_window events={EVENTS} seconds={write_seconds:.3} events_per_second={:.3} last_window_events={LAST_WINDOW} last_window_seconds={last_seconds:.3} last_window_events_per_second={:.3} checkpoint_bytes={checkpoint_bytes} head_reads={} head_max_ms={:.3} replay_events={replayed} replay_seconds={replay_seconds:.3} restore_seconds={restore_seconds:.3}",
            EVENTS as f64 / write_seconds,
            LAST_WINDOW as f64 / last_seconds,
            reads.load(Ordering::Relaxed),
            max_read_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0
        );
    }
}
pub struct BankStore {
    state: Mutex<State>,
    writer: Mutex<()>,
    pub source: SourceIdentity,
    pub notify: Notify,
    pub limit: usize,
    spool: Option<DiskSpool>,
}
struct DiskSpool {
    path: PathBuf,
    _lock: File,
}
pub const MAX_BATCH_EVENTS: usize = 64;
pub const MAX_BATCH_BYTES: usize = 64 * 1024 * 1024;
const MAX_CHECKPOINT_BYTES: usize = 64 * 1024 * 1024;
const MAX_FINALIZED_WINDOW: usize = 128;

#[derive(Debug)]
pub(crate) struct FinalizedWindow {
    pub tip: Option<BlockId>,
    pub frames: Vec<Arc<Frame>>,
}

fn finalized_root(chain: &Chain) -> Result<Option<&BankState>> {
    let in_capture =
        |bank: &BankState| chain.boundary.is_none_or(|(slot, _)| bank.bank.slot > slot);
    let rooted = chain
        .banks
        .values()
        .filter(|bank| bank.rooted && in_capture(bank));
    let Some(tip) = rooted.clone().max_by_key(|bank| bank.block_height) else {
        return Ok(None);
    };
    ensure!(
        rooted
            .clone()
            .all(|bank| bank.confirmed && !bank.invalidated)
            && rooted
                .clone()
                .filter(|bank| bank.block_height == tip.block_height)
                .count()
                == 1,
        "finalized_conflict"
    );

    // Detached roots below the retained boundary do not prove a path into the
    // capture. Every retained root inside it must be on the same exact chain.
    // Index parent identities once so this check is linear in the snapshot.
    let key = |bank: &BankState| (bank.bank.slot, bank.bank.blockhash);
    let mut banks = HashMap::with_capacity(chain.banks.len());
    for bank in chain.banks.values().filter(|bank| !bank.invalidated) {
        banks
            .entry(key(bank))
            .and_modify(|entry| *entry = None)
            .or_insert(Some(bank));
    }
    let lowest_root = rooted.clone().map(|bank| bank.block_height).min().unwrap();
    let mut remaining = rooted.count();
    let mut bank = tip;
    loop {
        ensure!(
            in_capture(bank) && banks.get(&key(bank)).is_some_and(Option::is_some),
            "finalized_conflict"
        );
        bank.bank.validate().context("finalized_conflict")?;
        if bank.rooted {
            remaining -= 1;
            if remaining == 0 {
                return Ok(Some(tip));
            }
        }
        ensure!(bank.block_height > lowest_root, "finalized_conflict");
        let parent = banks
            .get(&(bank.bank.parent_slot, bank.bank.parent_blockhash))
            .copied()
            .context("replay_unavailable")?
            .context("finalized_conflict")?;
        ensure!(
            parent.block_height.checked_add(1) == Some(bank.block_height),
            "finalized_conflict"
        );
        bank = parent;
    }
}

impl BankStore {
    fn empty_state(source: &SourceIdentity, base: String, limit: usize) -> Result<State> {
        source.validate()?;
        ensure!(
            v2::parse_cursor(&base)?.0 == source.session_id,
            "source_changed"
        );
        ensure!(
            (v2::MAX_FRAME..=16 * 1024 * 1024 * 1024).contains(&limit),
            "invalid_replay_budget"
        );
        let now = Instant::now();
        Ok(State {
            base,
            events: VecDeque::new(),
            frames: BTreeMap::new(),
            chain: Chain::default(),
            selected_at: now,
            selected_age: 0,
            status: "starting".into(),
            health_at: now,
            error: None,
        })
    }
    fn new(
        source: SourceIdentity,
        state: State,
        limit: usize,
        spool: Option<DiskSpool>,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(state),
            writer: Mutex::new(()),
            source,
            notify: Notify::new(),
            limit,
            spool,
        })
    }
    pub fn open_memory(source: SourceIdentity, base: String, limit: usize) -> Result<Arc<Self>> {
        let state = Self::empty_state(&source, base, limit)?;
        Ok(Self::new(source, state, limit, None))
    }
    pub fn open(
        source: SourceIdentity,
        base: String,
        limit: usize,
        spool: PathBuf,
    ) -> Result<Arc<Self>> {
        let mut state = Self::empty_state(&source, base, limit)?;
        fs::create_dir_all(&spool)?;
        let lock = File::options()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(spool.join("LOCK"))?;
        use std::os::fd::AsRawFd;
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "bank_spool_in_use"
        );
        if spool.join("CHECKPOINT.json").exists() {
            let cp: Checkpoint = serde_json::from_slice(&bounded_file(
                &spool.join("CHECKPOINT.json"),
                MAX_CHECKPOINT_BYTES,
            )?)?;
            ensure!(
                cp.schema == "blockzilla-bank-spool-v2"
                    && cp.source == source
                    && cp.events.len() <= 65536
                    && cp.frames.len() <= 131072,
                "checkpoint_source_changed"
            );
            state.base = cp.base;
            state.chain = cp.chain;
            ensure!(
                v2::parse_cursor(&state.base)?.0 == source.session_id,
                "source_changed"
            );
            for sha in cp.frames {
                ensure!(v2::is_digest(&sha), "invalid_checkpoint_digest");
                let f = v2::decode(
                    bounded_file(&spool.join(format!("{sha}.frame")), v2::MAX_FRAME)?.into(),
                )?;
                ensure!(
                    f.sha256 == sha && f.source == source,
                    "checkpoint_frame_changed"
                );
                state.frames.insert(sha, Arc::new(f));
            }
            let mut sequence = v2::parse_cursor(&state.base)?.1;
            for cursor in cp.events {
                let (_, n, sha) = v2::parse_cursor(&cursor)?;
                let frame = state.frames.get(sha).context("dependency_unavailable")?;
                ensure!(
                    n == sequence + 1 && frame.cursor == cursor,
                    "checkpoint_event_gap"
                );
                sequence = n;
                state.events.push_back(frame.clone());
            }
            state.chain.validate(
                &source,
                state.events.back().map_or(&state.base, |f| &f.cursor),
            )?;
            Self::validate_dependencies(&state)?;
            ensure!(Self::bytes(&state) <= limit, "replay_budget_shrunk");
            if let Some(latest) = &state.chain.latest {
                v2::clock_check(latest.observed_at_unix_ms, now_ms())?;
                state.selected_age = now_ms().saturating_sub(latest.observed_at_unix_ms);
            }
        }
        for entry in fs::read_dir(&spool)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if entry.file_type()?.is_file()
                && ((name
                    .strip_suffix(".frame")
                    .is_some_and(|s| v2::is_digest(s) && !state.frames.contains_key(s)))
                    || name == "CHECKPOINT.tmp")
            {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(Self::new(
            source,
            state,
            limit,
            Some(DiskSpool {
                path: spool,
                _lock: lock,
            }),
        ))
    }
    fn bytes(s: &State) -> usize {
        s.frames.values().map(|f| f.wire.len()).sum()
    }
    fn trim(s: &mut State, limit: usize) -> Result<()> {
        // Count each dependency once per reference. Rebuilding a complete pin set
        // for every evicted event makes a full replay window quadratic to trim.
        let mut pins: BTreeMap<String, usize> = BTreeMap::new();
        for f in &s.events {
            *pins.entry(f.sha256.clone()).or_default() += 1;
            if let Some(sha) = &f.envelope.event.payload_frame_sha256 {
                *pins.entry(sha.clone()).or_default() += 1;
            }
        }
        if let Some(head) = &s.chain.latest {
            *pins.entry(head.payload_frame_sha256.clone()).or_default() += 1;
            *pins
                .entry(v2::parse_cursor(&head.event_cursor)?.2.into())
                .or_default() += 1;
        }
        s.frames.retain(|sha, _| pins.contains_key(sha));
        let mut bytes = Self::bytes(s);
        while bytes > limit || s.events.len() > 65536 {
            let old = s.events.pop_front().context("dependency_unavailable")?;
            s.base = old.cursor.clone();
            ensure!(!s.events.is_empty(), "dependency_unavailable");
            for sha in
                std::iter::once(&old.sha256).chain(old.envelope.event.payload_frame_sha256.iter())
            {
                let references = pins.get_mut(sha).context("dependency_unavailable")?;
                *references -= 1;
                if *references == 0 {
                    pins.remove(sha);
                    if let Some(f) = s.frames.remove(sha) {
                        bytes -= f.wire.len();
                    }
                }
            }
        }
        Ok(())
    }
    fn validate_dependencies(s: &State) -> Result<()> {
        for f in &s.events {
            if let Some(sha) = &f.envelope.event.payload_frame_sha256 {
                f.envelope
                    .event
                    .matches_payload(s.frames.get(sha).context("dependency_unavailable")?)?;
            }
        }
        if let Some(h) = &s.chain.latest {
            let control = s
                .frames
                .get(v2::parse_cursor(&h.event_cursor)?.2)
                .context("head_control_unavailable")?;
            ensure!(
                v2::ConfirmedObservation::from_frame(control)? == *h,
                "head_control_changed"
            );
            control.envelope.event.matches_payload(
                s.frames
                    .get(&h.payload_frame_sha256)
                    .context("dependency_unavailable")?,
            )?;
        }
        Ok(())
    }
    fn save(&self, s: &State, previous: &BTreeMap<String, Arc<Frame>>) -> Result<()> {
        let Some(spool) = &self.spool else {
            return Ok(());
        };
        // Existing dependencies were checked at restore or their original
        // admission. New controls are checked against their exact payload below.
        // Retention only removes frames with no remaining references.
        for (sha, f) in &s.frames {
            if !previous.contains_key(sha) {
                atomic(&spool.path.join(format!("{sha}.frame")), &f.wire)?;
            }
        }
        let cp = Checkpoint {
            schema: "blockzilla-bank-spool-v2".into(),
            source: self.source.clone(),
            base: s.base.clone(),
            events: s.events.iter().map(|f| f.cursor.clone()).collect(),
            frames: s.frames.keys().cloned().collect(),
            chain: s.chain.clone(),
        };
        let bytes = serde_json::to_vec(&cp)?;
        ensure!(bytes.len() <= MAX_CHECKPOINT_BYTES, "checkpoint_too_large");
        atomic(&spool.path.join("CHECKPOINT.json"), &bytes)?;
        for sha in previous.keys() {
            if !s.frames.contains_key(sha) {
                fs::remove_file(spool.path.join(format!("{sha}.frame")))?;
            }
        }
        File::open(&spool.path)?.sync_all()?;
        Ok(())
    }
    pub fn latest(&self) -> String {
        let s = self.state.lock().unwrap();
        s.events
            .back()
            .map_or_else(|| s.base.clone(), |f| f.cursor.clone())
    }
    pub fn needs_bootstrap(&self) -> bool {
        let s = self.state.lock().unwrap();
        s.frames.is_empty() && s.events.is_empty() && s.chain.banks.is_empty()
    }
    pub fn set_health(&self, status: &str, error: Option<String>) {
        if let ("failed", Some(spool)) = (status, &self.spool) {
            let report = serde_json::json!({"state":"failed","source":self.source,"error":error,"updated_unix_ms":now_ms()});
            let _ = atomic(
                &spool.path.join("SOURCE-ERROR.json"),
                &serde_json::to_vec(&report).unwrap(),
            );
        }
        let mut s = self.state.lock().unwrap();
        s.status = status.into();
        s.error = error;
        s.health_at = Instant::now();
        drop(s);
        self.notify.notify_waiters();
    }
    pub fn error(&self) -> Option<String> {
        self.state.lock().unwrap().error.clone()
    }
    pub fn head(&self) -> Head {
        let s = self.state.lock().unwrap();
        let now = now_ms();
        let latest = s.chain.latest.clone();
        let observed = latest.as_ref().map(|h| h.observed_at_unix_ms);
        let lag = observed.map(|t| now.saturating_sub(t));
        let mut status = if s.status == "failed" || s.chain.reconciliate {
            "failed"
        } else if latest.is_none() {
            "starting"
        } else {
            "stale"
        };
        if status != "failed"
            && s.status == "live"
            && s.health_at.elapsed() <= Duration::from_millis(v2::DEFAULT_MAX_LAG_MS)
            && s.selected_age
                .saturating_add(s.selected_at.elapsed().as_millis() as u64)
                <= v2::DEFAULT_MAX_LAG_MS
            && lag.is_some_and(|n| n <= v2::DEFAULT_MAX_LAG_MS)
            && observed.is_some_and(|t| v2::clock_check(t, now).is_ok())
        {
            status = "live";
        }
        Head {
            schema: v2::HEAD.into(),
            profile: v2::PROFILE.into(),
            source: self.source.clone(),
            cursor: Some(
                s.events
                    .back()
                    .map_or_else(|| s.base.clone(), |f| f.cursor.clone()),
            ),
            earliest_after: Some(s.base.clone()),
            status: status.into(),
            sampled_at_unix_ms: now,
            source_observed_at_unix_ms: observed,
            source_lag_ms: lag,
            latest_confirmed: latest,
        }
    }
    pub fn bootstrap(&self) -> Bootstrap {
        let s = self.state.lock().unwrap();
        Bootstrap {
            source: self.source.clone(),
            cursor: s
                .events
                .back()
                .map_or_else(|| s.base.clone(), |f| f.cursor.clone()),
            chain: s.chain.clone(),
        }
    }
    pub fn install_bootstrap(&self, b: Bootstrap, dependencies: Vec<Frame>) -> Result<()> {
        let _writer = self.writer.lock().unwrap();
        let previous = self.state.lock().unwrap().clone();
        let old = &previous;
        ensure!(
            b.source == self.source
                && old.events.is_empty()
                && old.frames.is_empty()
                && old.chain.banks.is_empty()
                && (old.base == b.cursor
                    || old.base == v2::cursor(&self.source.session_id, 0, "-")),
            "invalid_bootstrap"
        );
        let mut s = old.clone();
        s.base = b.cursor.clone();
        s.chain = b.chain;
        s.chain.validate(&self.source, &b.cursor)?;
        ensure!(
            s.chain.banks.len() <= v2::chain::MAX_BANKS,
            "bank_queue_overflow"
        );
        for f in dependencies {
            ensure!(f.source == self.source, "source_changed");
            s.frames.insert(f.sha256.clone(), Arc::new(f));
        }
        if let Some(latest) = &s.chain.latest {
            v2::clock_check(latest.observed_at_unix_ms, now_ms())?;
            s.selected_at = Instant::now();
            s.selected_age = now_ms().saturating_sub(latest.observed_at_unix_ms);
        }
        ensure!(Self::bytes(&s) <= self.limit, "dependency_unavailable");
        Self::validate_dependencies(&s)?;
        self.save(&s, &old.frames)?;
        self.publish(s);
        Ok(())
    }
    fn publish(&self, mut s: State) {
        let mut current = self.state.lock().unwrap();
        // Health can change while disk I/O runs. Preserve the latest factual
        // health sample; a durable frame commit cannot refresh source health.
        s.status = current.status.clone();
        s.health_at = current.health_at;
        s.error = current.error.clone();
        *current = s;
    }
    pub fn admit(&self, f: Frame, dependency: Option<Frame>) -> Result<()> {
        self.admit_batch(vec![(f, dependency)])
    }
    /// Publish one bounded batch atomically. A durable store syncs all frames
    /// and the checkpoint first. A failed batch leaves the boundary intact.
    pub fn admit_batch(&self, batch: Vec<(Frame, Option<Frame>)>) -> Result<()> {
        ensure!(
            !batch.is_empty() && batch.len() <= MAX_BATCH_EVENTS,
            "invalid_batch_size"
        );
        let bytes: usize = batch
            .iter()
            .map(|(f, dep)| f.wire.len() + dep.as_ref().map_or(0, |f| f.wire.len()))
            .sum();
        ensure!(bytes <= MAX_BATCH_BYTES, "batch_too_large");
        let _writer = self.writer.lock().unwrap();
        let mut s = self.state.lock().unwrap().clone();
        let previous = self
            .spool
            .as_ref()
            .map(|_| s.frames.clone())
            .unwrap_or_default();
        for (f, dependency) in batch {
            ensure!(f.source == self.source, "source_changed");
            v2::clock_check(f.envelope.event.observed_at_unix_ms, now_ms())?;
            if s.events.back().is_some_and(|p| p.cursor == f.cursor) {
                continue;
            }
            let previous = s.events.back().map_or(&s.base, |p| &p.cursor);
            ensure!(
                f.envelope.event.sequence == v2::parse_cursor(previous)?.1 + 1,
                "event_sequence_gap"
            );
            let prior = s.chain.latest.clone();
            if let Some(dep) = dependency {
                ensure!(
                    dep.source == self.source && f.envelope.event.source_sequence > 0,
                    "source_changed"
                );
                s.frames.insert(dep.sha256.clone(), Arc::new(dep));
            }
            if f.envelope.event.kind == "block" {
                s.chain.add_payload(&f)?;
            } else {
                let sha = f
                    .envelope
                    .event
                    .payload_frame_sha256
                    .as_ref()
                    .context("missing_payload_frame")?;
                let payload = s.frames.get(sha).context("dependency_unavailable")?;
                s.chain.apply_control(&f, payload)?;
            }
            if s.chain.latest != prior {
                let t = s
                    .chain
                    .latest
                    .as_ref()
                    .map_or(now_ms(), |h| h.observed_at_unix_ms);
                s.selected_age = now_ms().saturating_sub(t);
                s.selected_at = Instant::now();
            }
            let f = Arc::new(f);
            s.frames.insert(f.sha256.clone(), f.clone());
            s.events.push_back(f);
        }
        Self::trim(&mut s, self.limit)?;
        self.save(&s, &previous)?;
        self.publish(s);
        self.notify.notify_waiters();
        Ok(())
    }
    pub fn after(&self, cursor: &str) -> Result<Option<Arc<Frame>>> {
        let (session, n, _) = v2::parse_cursor(cursor)?;
        ensure!(session == self.source.session_id, "source_changed");
        let s = self.state.lock().unwrap();
        if cursor == s.base {
            return Ok(s.events.front().cloned());
        }
        let base = v2::parse_cursor(&s.base)?.1;
        ensure!(n >= base, "replay_unavailable");
        // The durable event window is consecutive. Its offset gives a constant
        // time lookup, but the exact saved cursor (including digest) must match.
        let i = n
            .checked_sub(base)
            .and_then(|offset| offset.checked_sub(1))
            .and_then(|offset| usize::try_from(offset).ok())
            .context("invalid_cursor")?;
        ensure!(
            s.events.get(i).is_some_and(|f| f.cursor == cursor),
            "invalid_cursor"
        );
        Ok(s.events.get(i + 1).cloned())
    }
    pub fn chunk(&self, sha: &str) -> Option<Arc<Frame>> {
        self.state.lock().unwrap().frames.get(sha).cloned()
    }
    fn finalized_state(&self) -> Result<MutexGuard<'_, State>> {
        let state = self.state.lock().unwrap();
        ensure!(
            state.status != "failed" && !state.chain.reconciliate,
            "source_failed"
        );
        Ok(state)
    }
    pub(crate) fn finalized_tip(&self) -> Result<Option<BlockId>> {
        let chain = self.finalized_state()?.chain.clone();
        Ok(finalized_root(&chain)?.map(|root| BlockId::from(&root.bank)))
    }
    pub(crate) fn finalized_window(&self, after: Option<&BlockId>) -> Result<FinalizedWindow> {
        let chain = self.finalized_state()?.chain.clone();
        let Some(root) = finalized_root(&chain)? else {
            ensure!(after.is_none(), "replay_unavailable");
            return Ok(FinalizedWindow {
                tip: None,
                frames: Vec::new(),
            });
        };
        let tip = Some(BlockId::from(&root.bank));
        let path = if let Some(after) = after {
            if Some(*after) == tip {
                Vec::new()
            } else {
                let mut anchors = chain
                    .banks
                    .values()
                    .filter(|bank| !bank.invalidated && BlockId::from(&bank.bank) == *after);
                let anchor = anchors.next().context("replay_unavailable")?;
                ensure!(anchors.next().is_none(), "finalized_conflict");
                chain
                    .rooted_path_after(&root.bank, &anchor.bank, anchor.block_height)
                    .context("replay_unavailable")?
            }
        } else {
            vec![root.clone()]
        };

        // Ancestry is checked outside the store lock. A writer may trim the
        // window before this lookup, in which case it is a gap for this batch.
        let state = self.finalized_state()?;
        let mut frames = Vec::new();
        let mut bytes = 0;
        for bank in path.iter().take(MAX_FINALIZED_WINDOW) {
            let frame = state
                .frames
                .get(&bank.payload_frame_sha256)
                .context("replay_unavailable")?;
            bytes += frame.wire.len();
            if bytes > MAX_BATCH_BYTES {
                break;
            }
            let event = &frame.envelope.event;
            ensure!(
                frame.source == self.source
                    && frame.sha256 == bank.payload_frame_sha256
                    && event.kind == "block"
                    && event.bank == bank.bank
                    && event.block_height == Some(bank.block_height)
                    && event.payload_sha256 == bank.payload_sha256,
                "finalized_conflict"
            );
            frames.push(frame.clone());
        }
        Ok(FinalizedWindow { tip, frames })
    }
    pub(crate) fn retained_confirmation_before(&self, root: &Frame) -> bool {
        let event = &root.envelope.event;
        let Some(digest) = event.payload_frame_sha256.as_deref() else {
            return false;
        };
        let state = self.state.lock().unwrap();
        let block_sequence = state
            .frames
            .get(digest)
            .map_or(0, |block| block.envelope.event.sequence);
        state
            .events
            .iter()
            .rev()
            .map(|frame| &frame.envelope.event)
            .skip_while(|earlier| earlier.sequence >= event.sequence)
            .take_while(|earlier| earlier.sequence > block_sequence)
            .any(|earlier| {
                earlier.kind == "confirmed"
                    && earlier.payload_frame_sha256.as_deref() == Some(digest)
            })
    }
    pub fn metrics(&self) -> serde_json::Value {
        let s = self.state.lock().unwrap();
        let times: Vec<_> = s
            .events
            .iter()
            .filter(|f| f.envelope.event.kind == "block")
            .map(|f| f.envelope.event.observed_at_unix_ms)
            .collect();
        serde_json::json!({"replay_bytes":Self::bytes(&s),"replay_limit_bytes":self.limit,"retained_events":s.events.len(),"retained_frames":s.frames.len(),"replay_duration_ms":times.first().zip(times.last()).map(|(a,b)|b.saturating_sub(*a)),"earliest_after":s.base})
    }
}
