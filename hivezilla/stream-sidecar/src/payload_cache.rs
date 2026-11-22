//! Speculative decode stays private. Only Store's ordered FULL commit publishes it.
use crate::projection::{self, Payload, PayloadMode};
use anyhow::{Context, Result, ensure};
use blockzilla_bank_stream_v2::{self as v2, Frame, SourceIdentity};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    mem::size_of,
    sync::atomic::{AtomicU64, Ordering},
    sync::{Arc, Mutex},
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

pub const DECODE_WORKERS: usize = 4;
pub const PREVIEW_BLOCKS: usize = 4;
pub const RESIDENT_BYTES: usize = 512 * 1024 * 1024;
pub const LIVE_BYTES: usize = 4 * 1024 * 1024 * 1024;
const DECODE_RESERVATION: usize = 512 * 1024 * 1024;
const MAX_PAYLOAD_MEMORY: usize = 256 * 1024 * 1024;

pub struct SharedPayload {
    pub frame: Frame,
    pub(crate) json: Value,
    pub(crate) text: String,
    pub memory_bytes: usize,
    // This charge follows every Arc reference, including an evicted SSE record.
    _memory: OwnedSemaphorePermit,
    budget: Arc<Semaphore>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use blockzilla_bank_stream_v2::fixtures::{block, source};
    use futures_util::{StreamExt, stream};
    use std::{
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };
    fn fixture(frame: Frame) -> Result<Payload> {
        Ok(Payload {
            frame,
            json: json!({"blocks":[{"transactions":[],"padding":"x".repeat(65536)}]}),
        })
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reversed_completion_has_bounded_preview_and_reconnect_reuses_it() {
        let cache = PayloadCache::with_limits(source(), 0, DECODE_RESERVATION * 2, 2, 2);
        let completed = Arc::new(Mutex::new(Vec::new()));
        let items = stream::iter(1..=4)
            .map(|n| {
                let c = cache.clone();
                let done = completed.clone();
                async move {
                    c.prepare_with(block(n, n + 8, n, n + 7, n + 8), move |f| {
                        std::thread::sleep(Duration::from_millis(if n == 1 { 60 } else { 2 }));
                        done.lock().unwrap().push(n);
                        fixture(f)
                    })
                    .await?;
                    Ok::<_, anyhow::Error>(n)
                }
            })
            .buffered(4);
        futures_util::pin_mut!(items);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), items.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            1
        );
        assert_eq!(*completed.lock().unwrap(), vec![2, 1]);
        let first = block(1, 9, 1, 8, 9);
        // All preview permits are held by private results. Reconnect must reuse
        // one without waiting for a permit which only its own commit releases.
        tokio::time::timeout(Duration::from_secs(1), cache.prepare(first.clone()))
            .await
            .unwrap()
            .unwrap();
        cache.committed(first.envelope.event.sequence);
        while let Some(n) = items.next().await {
            let n = n.unwrap();
            cache.committed(n);
        }
        assert_eq!(cache.previews.available_permits(), 2);
        assert!(cache.state.lock().unwrap().entries.is_empty());
    }
    #[test]
    fn global_charge_survives_eviction_until_the_last_arc_drops() {
        let cache = PayloadCache::with_limits(source(), 0, DECODE_RESERVATION, 1, 1);
        let p = cache
            .materialize(fixture(block(1, 9, 1, 8, 9)).unwrap())
            .unwrap();
        assert!(cache.state.lock().unwrap().entries.is_empty());
        assert!(p.memory_bytes > p.frame.wire.len() + p.text.len());
        assert_eq!(
            cache.memory.available_permits(),
            DECODE_RESERVATION - p.memory_bytes
        );
        let other = p.clone();
        drop(p);
        assert!(cache.memory.available_permits() < DECODE_RESERVATION);
        drop(other);
        assert_eq!(cache.memory.available_permits(), DECODE_RESERVATION);
        let mut wrong = fixture(block(1, 9, 1, 8, 9)).unwrap();
        wrong.frame.source.session_id = "wrong".into();
        assert!(cache.materialize(wrong).is_err());
    }
    #[tokio::test]
    async fn front_completion_between_state_check_and_wait_cannot_lose_its_wake() {
        let cache = PayloadCache::with_limits(source(), 0, DECODE_RESERVATION, 1, 1);
        let frame = block(1, 9, 1, 8, 9);
        let payload = cache.materialize(fixture(frame.clone()).unwrap()).unwrap();
        let occupied = cache.previews.clone().acquire_owned().await.unwrap();
        assert_eq!(cache.previews.available_permits(), 0);
        let c = cache.clone();
        *cache.before_preview_wait.lock().unwrap() = Some(Box::new(move || {
            c.insert(payload, Some(occupied));
        }));
        // The callback completes the front decode and notifies exactly after
        // the pending-state check, before select can poll either branch.
        tokio::time::timeout(Duration::from_millis(200), cache.prepare(frame.clone()))
            .await
            .unwrap()
            .unwrap();
        cache.committed(frame.envelope.event.sequence);
        assert_eq!(cache.previews.available_permits(), 1);
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_preview_keeps_the_running_decoder_charge() {
        let cache = PayloadCache::with_limits(source(), 0, DECODE_RESERVATION, 1, 1);
        let started = Arc::new(AtomicBool::new(false));
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let frame = block(1, 9, 1, 8, 9);
        let c = cache.clone();
        let s = started.clone();
        let b = barrier.clone();
        let f = frame.clone();
        let task = tokio::spawn(async move {
            c.prepare_with(f, move |f| {
                s.store(true, Ordering::SeqCst);
                b.wait();
                fixture(f)
            })
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while !started.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        task.abort();
        let _ = task.await;
        assert_eq!(cache.memory.available_permits(), 0);
        assert_eq!(cache.workers.available_permits(), 0);
        barrier.wait();
        tokio::time::timeout(Duration::from_secs(2), async {
            while cache.get(&frame.sha256).is_none() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert!(cache.memory.available_permits() < DECODE_RESERVATION);
        cache.committed(frame.envelope.event.sequence);
        assert_eq!(cache.memory.available_permits(), DECODE_RESERVATION);
    }
    #[tokio::test]
    async fn earlier_wanted_frame_can_reclaim_and_reload_a_completed_channel_result() {
        let cache = PayloadCache::with_limits(source(), 0, DECODE_RESERVATION * 4, 4, 4);
        let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
        for n in 2..=5 {
            let f = block(n, n + 8, n, n + 7, n + 8);
            cache.prepare_with(f.clone(), fixture).await.unwrap();
            sender.send(f).await.unwrap();
        }
        assert_eq!(cache.previews.available_permits(), 0);
        let farthest = block(5, 13, 5, 12, 13);
        let expected = cache.get(&farthest.sha256).unwrap().json.clone();
        let first = block(1, 9, 1, 8, 9);
        tokio::time::timeout(
            Duration::from_secs(1),
            cache.prepare_with(first.clone(), fixture),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(cache.get(&farthest.sha256).is_none());
        assert_eq!(cache.preview_evictions.load(Ordering::Relaxed), 1);
        cache.committed(first.envelope.event.sequence);
        drop(sender);
        while let Some(frame) = receiver.recv().await {
            let p = cache.load_with(frame.clone(), fixture).await.unwrap();
            assert_eq!(p.frame.wire, frame.wire);
            if frame.sha256 == farthest.sha256 {
                assert_eq!(p.json, expected);
            }
            cache.committed(frame.envelope.event.sequence);
        }
        assert_eq!(cache.previews.available_permits(), 4);
    }
    #[tokio::test]
    async fn cancelled_waiting_acquire_leaves_no_phantom_permit() {
        let cache = PayloadCache::with_limits(source(), 0, DECODE_RESERVATION * 2, 1, 1);
        let first = block(1, 9, 1, 8, 9);
        cache.prepare_with(first.clone(), fixture).await.unwrap();
        let entered = Arc::new(AtomicBool::new(false));
        let signal = entered.clone();
        *cache.before_preview_wait.lock().unwrap() =
            Some(Box::new(move || signal.store(true, Ordering::SeqCst)));
        let c = cache.clone();
        let task =
            tokio::spawn(async move { c.prepare_with(block(2, 10, 2, 9, 10), fixture).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !entered.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        task.abort();
        let _ = task.await;
        assert_eq!(cache.previews.available_permits(), 0);
        cache.committed(first.envelope.event.sequence);
        assert_eq!(cache.previews.available_permits(), 1);
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn late_duplicate_decoder_cannot_repin_a_committed_or_evicted_frame() {
        for resident in [0, 1024 * 1024] {
            let cache = PayloadCache::with_limits(source(), resident, DECODE_RESERVATION * 2, 2, 2);
            let frame = block(1, 9, 1, 8, 9);
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let started = Arc::new(AtomicBool::new(false));
            let c = cache.clone();
            let f = frame.clone();
            let b = barrier.clone();
            let s = started.clone();
            let old = tokio::spawn(async move {
                c.prepare_with(f, move |f| {
                    s.store(true, Ordering::SeqCst);
                    b.wait();
                    fixture(f)
                })
                .await
            });
            tokio::time::timeout(Duration::from_secs(1), async {
                while !started.load(Ordering::SeqCst) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            cache.prepare_with(frame.clone(), fixture).await.unwrap();
            cache.committed(1);
            assert_eq!(cache.previews.available_permits(), 1);
            assert_eq!(cache.get(&frame.sha256).is_some(), resident != 0);
            barrier.wait();
            old.await.unwrap().unwrap();
            assert_eq!(
                cache.previews.available_permits(),
                2,
                "old decoder must not regain preview ownership after the FULL frontier"
            );
            assert_eq!(cache.state.lock().unwrap().committed_through, 1);
        }
    }
}
struct Entry {
    payload: Arc<SharedPayload>,
    used: u64,
    preview: Option<OwnedSemaphorePermit>,
}
#[derive(Default)]
struct State {
    entries: BTreeMap<String, Entry>,
    clock: u64,
    committed_through: u64,
}
pub struct PayloadCache {
    mode: PayloadMode,
    source: SourceIdentity,
    state: Mutex<State>,
    memory: Arc<Semaphore>,
    workers: Arc<Semaphore>,
    previews: Arc<Semaphore>,
    resident_bytes: usize,
    live_bytes: usize,
    worker_limit: usize,
    preview_limit: usize,
    changed: Notify,
    preview_evictions: AtomicU64,
    #[cfg(test)]
    before_preview_wait: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}
fn heap(value: &Value) -> usize {
    let extra = match value {
        Value::String(s) => s.capacity(),
        Value::Array(a) => a
            .capacity()
            .saturating_mul(size_of::<Value>())
            .saturating_add(a.iter().map(heap).sum::<usize>()),
        // Include a conservative node/allocation allowance as well as keys and values.
        Value::Object(o) => o.len().saturating_mul(128).saturating_add(
            o.iter()
                .map(|(k, v)| k.capacity().saturating_add(heap(v)))
                .sum::<usize>(),
        ),
        _ => 0,
    };
    size_of::<Value>().saturating_add(extra)
}
impl PayloadCache {
    pub fn new(source: SourceIdentity) -> Arc<Self> {
        Self::with_limits(
            source,
            RESIDENT_BYTES,
            LIVE_BYTES,
            DECODE_WORKERS,
            PREVIEW_BLOCKS,
        )
    }
    /// One decoder and a small cache for a bounded relay on a shared host.
    pub fn relay(source: SourceIdentity) -> Arc<Self> {
        Self::with_limits(source, 128 * 1024 * 1024, 1536 * 1024 * 1024, 1, 1)
    }
    pub fn with_mode(source: SourceIdentity, relay: bool, mode: PayloadMode) -> Arc<Self> {
        let mut cache = if relay {
            Self::relay(source)
        } else {
            Self::new(source)
        };
        Arc::get_mut(&mut cache).unwrap().mode = mode;
        cache
    }
    fn with_limits(
        source: SourceIdentity,
        resident_bytes: usize,
        live_bytes: usize,
        workers: usize,
        previews: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            mode: PayloadMode::Full,
            source,
            state: Mutex::new(State::default()),
            memory: Arc::new(Semaphore::new(live_bytes)),
            workers: Arc::new(Semaphore::new(workers)),
            previews: Arc::new(Semaphore::new(previews)),
            resident_bytes,
            live_bytes,
            worker_limit: workers,
            preview_limit: previews,
            changed: Notify::new(),
            preview_evictions: AtomicU64::new(0),
            #[cfg(test)]
            before_preview_wait: Mutex::new(None),
        })
    }
    pub fn get(&self, sha: &str) -> Option<Arc<SharedPayload>> {
        let mut s = self.state.lock().unwrap();
        s.clock = s.clock.wrapping_add(1);
        let used = s.clock;
        s.entries.get_mut(sha).map(|e| {
            e.used = used;
            e.payload.clone()
        })
    }
    fn evict_resident(&self, reserve: bool) {
        let mut s = self.state.lock().unwrap();
        loop {
            let bytes = s
                .entries
                .values()
                .filter(|e| e.preview.is_none())
                .map(|e| e.payload.memory_bytes)
                .sum::<usize>();
            if bytes <= self.resident_bytes
                && (!reserve || self.memory.available_permits() >= DECODE_RESERVATION)
            {
                break;
            }
            let key = s
                .entries
                .iter()
                .filter(|(_, e)| e.preview.is_none())
                .min_by_key(|(_, e)| e.used)
                .map(|(k, _)| k.clone());
            let Some(key) = key else { break };
            s.entries.remove(&key);
        }
    }
    fn shared(
        &self,
        payload: Payload,
        stored: Option<String>,
        mut memory: OwnedSemaphorePermit,
    ) -> Result<Arc<SharedPayload>> {
        ensure!(
            payload.frame.source == self.source,
            "payload_cache_source_changed"
        );
        let admitted = v2::decode(payload.frame.wire.clone())?;
        ensure!(
            admitted.source == self.source
                && admitted.sha256 == payload.frame.sha256
                && admitted.cursor == payload.frame.cursor
                && serde_json::to_value(&admitted.envelope.event)?
                    == serde_json::to_value(&payload.frame.envelope.event)?,
            "payload_cache_frame_mismatch"
        );
        ensure!(
            self.mode != PayloadMode::CompactOnly || payload.json.is_null(),
            "portable_projection_disabled_in_compact_only_mode"
        );
        let text = match stored {
            Some(text) => text,
            None if self.mode == PayloadMode::CompactOnly => String::new(),
            None => serde_json::to_string(&payload.json)?,
        };
        ensure!(
            self.mode != PayloadMode::CompactOnly || text.is_empty(),
            "portable_projection_disabled_in_compact_only_mode"
        );
        ensure!(text.len() <= 32 * 1024 * 1024, "projection_too_large");
        let bytes = heap(&payload.json)
            .saturating_add(text.capacity())
            .saturating_add(payload.frame.wire.len())
            .saturating_add(v2::MAX_META * 4);
        ensure!(
            bytes <= MAX_PAYLOAD_MEMORY && bytes <= memory.num_permits(),
            "decoded_payload_memory_limit"
        );
        let extra = memory.num_permits() - bytes;
        drop(memory.split(extra));
        Ok(Arc::new(SharedPayload {
            frame: payload.frame,
            json: payload.json,
            text,
            memory_bytes: bytes,
            _memory: memory,
            budget: self.memory.clone(),
        }))
    }
    fn insert(
        &self,
        payload: Arc<SharedPayload>,
        mut preview: Option<OwnedSemaphorePermit>,
    ) -> Arc<SharedPayload> {
        let mut s = self.state.lock().unwrap();
        if payload.frame.envelope.event.sequence <= s.committed_through {
            preview.take();
        }
        s.clock = s.clock.wrapping_add(1);
        let used = s.clock;
        let sha = payload.frame.sha256.clone();
        let result = if let Some(old) = s.entries.get_mut(&sha) {
            old.used = used;
            if old.preview.is_none() {
                old.preview = preview;
            }
            old.payload.clone()
        } else {
            s.entries.insert(
                sha,
                Entry {
                    payload: payload.clone(),
                    used,
                    preview,
                },
            );
            payload
        };
        drop(s);
        self.changed.notify_waiters();
        self.evict_resident(false);
        result
    }
    pub fn materialize(&self, payload: Payload) -> Result<Arc<SharedPayload>> {
        self.materialize_text(payload, None)
    }
    pub fn materialize_text(
        &self,
        payload: Payload,
        text: Option<String>,
    ) -> Result<Arc<SharedPayload>> {
        ensure!(
            payload.frame.source == self.source,
            "payload_cache_source_changed"
        );
        if let Some(old) = self.get(&payload.frame.sha256) {
            ensure!(
                old.frame.wire == payload.frame.wire,
                "payload_digest_collision"
            );
            return Ok(old);
        }
        self.evict_resident(true);
        let memory = self
            .memory
            .clone()
            .try_acquire_many_owned(DECODE_RESERVATION as u32)
            .context("payload_memory_budget_busy")?;
        let shared = self.shared(payload, text, memory)?;
        Ok(self.insert(shared, None))
    }
    pub(crate) fn load_stored<F>(&self, load: F) -> Result<Arc<SharedPayload>>
    where
        F: FnOnce() -> Result<(Frame, String)>,
    {
        self.evict_resident(true);
        let memory = self
            .memory
            .clone()
            .try_acquire_many_owned(DECODE_RESERVATION as u32)
            .context("payload_memory_budget_busy")?;
        let (frame, text) = load()?;
        let json = if self.mode == PayloadMode::CompactOnly {
            ensure!(text.is_empty(), "compact_payload_migration_required");
            Value::Null
        } else {
            ensure!(
                !text.is_empty(),
                "compact_payload_requires_compact_only_mode"
            );
            serde_json::from_str(&text)?
        };
        let shared = self.shared(Payload { frame, json }, Some(text), memory)?;
        Ok(self.insert(shared, None))
    }
    pub async fn prepare(self: &Arc<Self>, frame: Frame) -> Result<()> {
        let decode = if self.mode == PayloadMode::CompactOnly {
            projection::validate_compact
        } else {
            projection::decode
        };
        self.prepare_with(frame, decode).await
    }
    async fn prepare_with<F>(self: &Arc<Self>, frame: Frame, decode: F) -> Result<()>
    where
        F: FnOnce(Frame) -> Result<Payload> + Send + 'static,
    {
        ensure!(frame.source == self.source, "payload_cache_source_changed");
        if frame.envelope.event.kind != "block" {
            return Ok(());
        }
        if frame.envelope.event.sequence <= self.state.lock().unwrap().committed_through {
            return Ok(());
        }
        // The client starts these futures in canonical queue order after its
        // ordered fetch stage. Fair permits prevent later work starving its head.
        // Keep the same fair acquire future across cache notifications. Dropping
        // it on every wake would move an older frame behind later requests.
        let acquire = self.previews.clone().acquire_owned();
        tokio::pin!(acquire);
        let preview = loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self
                .state
                .lock()
                .unwrap()
                .entries
                .get(&frame.sha256)
                .is_some_and(|e| e.preview.is_some())
            {
                return Ok(());
            }
            self.release_later_preview(frame.envelope.event.sequence);
            #[cfg(test)]
            {
                let callback = self.before_preview_wait.lock().unwrap().take();
                if let Some(callback) = callback {
                    callback();
                }
            }
            tokio::select! {biased;p=&mut acquire=>break p?,_=&mut changed=>{}}
        };
        if let Some(old) = self.get(&frame.sha256) {
            self.insert(old, Some(preview));
            return Ok(());
        }
        let worker = self.workers.clone().acquire_owned().await?;
        self.evict_resident(true);
        let memory = self
            .memory
            .clone()
            .acquire_many_owned(DECODE_RESERVATION as u32)
            .await?;
        let cache = self.clone();
        tokio::task::spawn_blocking(move || {
            // Cancellation of the async caller cannot release a running decoder's charge.
            let _worker = worker;
            let payload = decode(frame)?;
            let shared = cache.shared(payload, None, memory)?;
            cache.insert(shared, Some(preview));
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        Ok(())
    }
    fn release_later_preview(&self, wanted: u64) {
        if self.previews.available_permits() != 0 {
            return;
        }
        let mut s = self.state.lock().unwrap();
        let later = s
            .entries
            .iter()
            .filter(|(_, e)| {
                e.preview.is_some() && e.payload.frame.envelope.event.sequence > wanted
            })
            .max_by_key(|(_, e)| e.payload.frame.envelope.event.sequence)
            .map(|(k, _)| k.clone());
        if let Some(later) = later {
            s.entries.remove(&later);
            self.preview_evictions.fetch_add(1, Ordering::Relaxed);
            drop(s);
            self.changed.notify_waiters();
        }
    }
    pub(crate) fn remember(&self, payload: Arc<SharedPayload>) -> Result<()> {
        ensure!(
            payload.frame.source == self.source && Arc::ptr_eq(&payload.budget, &self.memory),
            "payload_cache_binding_changed"
        );
        self.insert(payload, None);
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn clear_resident(&self) {
        self.state
            .lock()
            .unwrap()
            .entries
            .retain(|_, e| e.preview.is_some());
    }
    /// Bootstrap/older control dependency. It never waits for a preview slot
    /// which can be held by later speculative Banks.
    pub async fn load(self: &Arc<Self>, frame: Frame) -> Result<Arc<SharedPayload>> {
        let decode = if self.mode == PayloadMode::CompactOnly {
            projection::validate_compact
        } else {
            projection::decode
        };
        self.load_with(frame, decode).await
    }
    async fn load_with<F>(self: &Arc<Self>, frame: Frame, decode: F) -> Result<Arc<SharedPayload>>
    where
        F: FnOnce(Frame) -> Result<Payload> + Send + 'static,
    {
        ensure!(frame.source == self.source, "payload_cache_source_changed");
        if let Some(p) = self.get(&frame.sha256) {
            return Ok(p);
        }
        let worker = self.workers.clone().acquire_owned().await?;
        self.evict_resident(true);
        let memory = self
            .memory
            .clone()
            .acquire_many_owned(DECODE_RESERVATION as u32)
            .await?;
        let cache = self.clone();
        tokio::task::spawn_blocking(move || {
            let _worker = worker;
            let payload = decode(frame)?;
            let shared = cache.shared(payload, None, memory)?;
            Ok::<_, anyhow::Error>(cache.insert(shared, None))
        })
        .await?
    }
    pub(crate) fn committed(&self, sequence: u64) {
        let mut s = self.state.lock().unwrap();
        s.committed_through = s.committed_through.max(sequence);
        let frontier = s.committed_through;
        for e in s.entries.values_mut() {
            if e.payload.frame.envelope.event.sequence <= frontier {
                e.preview.take();
            }
        }
        drop(s);
        self.changed.notify_waiters();
        self.evict_resident(false);
    }
    pub fn stats(&self) -> Value {
        let s = self.state.lock().unwrap();
        json!({"entries":s.entries.len(),"residentLimitBytes":self.resident_bytes,"liveLimitBytes":self.live_bytes,"chargedBytes":self.live_bytes.saturating_sub(self.memory.available_permits()),"previewBlocks":self.preview_limit-self.previews.available_permits(),"decodeWorkers":self.worker_limit-self.workers.available_permits(),"previewEvictions":self.preview_evictions.load(Ordering::Relaxed),"committedThroughSequence":s.committed_through})
    }
}
