use crate::store::Store;
use anyhow::{Context, Result};
use blockzilla_bank_client::{BankClient, BankStream, StreamEvent, now_ms};
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub struct Runtime {
    inner: Mutex<State>,
}
struct State {
    input: String,
    error: Option<String>,
    signing: Option<Value>,
    valid_until: u64,
    valid_for: Duration,
    set_at: Instant,
    ack_error: Option<String>,
    webhook_error: Option<String>,
    coverage_error: Option<String>,
    coverage_poll_ms: Option<u64>,
    beam_generation: Option<String>,
    beam_connected: bool,
    beam_last_receipt: Option<Instant>,
    beam_observed_ms: Option<u64>,
    beam_cursor: Option<String>,
    beam_reconcile_error: Option<String>,
    beam_recovery: RecoveryStatus,
}
#[derive(Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryStatus {
    enabled: bool,
    active: bool,
    completed_windows: u64,
    committed_blocks: u64,
    committed_controls: u64,
    from_cursor: Option<String>,
    to_cursor: Option<String>,
    failed_attempts: u64,
    last_error: Option<String>,
}
impl Default for Runtime {
    fn default() -> Self {
        Self {
            inner: Mutex::new(State {
                input: "starting".into(),
                error: None,
                signing: None,
                valid_until: 0,
                valid_for: Duration::ZERO,
                set_at: Instant::now(),
                ack_error: None,
                webhook_error: None,
                coverage_error: None,
                coverage_poll_ms: None,
                beam_generation: None,
                beam_connected: false,
                beam_last_receipt: None,
                beam_observed_ms: None,
                beam_cursor: None,
                beam_reconcile_error: None,
                beam_recovery: RecoveryStatus::default(),
            }),
        }
    }
}
impl Runtime {
    pub fn fail(&self, error: &str) {
        let mut s = self.inner.lock().unwrap();
        s.input = "failed".into();
        s.error = Some(error.into());
        s.signing = None;
        s.beam_connected = false;
    }
    pub fn webhook_failed(&self, error: &str) {
        self.inner.lock().unwrap().webhook_error = Some(error.into());
    }
    pub fn status(&self, store: &Store) -> Value {
        let s = self.inner.lock().unwrap();
        let beam = s.beam_generation.is_some();
        let fresh = Self::beam_fresh(&s);
        let ready = s.signing.is_some()
            && s.input == "live"
            && (!beam || fresh)
            && now_ms() <= s.valid_until
            && s.set_at.elapsed() <= s.valid_for;
        let input = if beam && s.input == "live" && !fresh {
            "unavailable"
        } else {
            &s.input
        };
        json!({"schema":"blockzilla-sidecar-health-v1","source":store.source,"producerGeneration":store.producer_generation,"inputMode":if beam{"raw_ssh"}else{"legacy_http_sse"},"runtimeGeneration":s.beam_generation,"input":input,"error":s.error,"signingReady":ready,"signing":if ready{s.signing.clone()}else{None},"payloadCache":store.payloads.stats(),"originAckRequired":!beam,"originAck":if beam{json!({"required":false})}else{store.ack_backlog().unwrap_or_else(|_|json!({"error":"ack_state_unavailable"}))},"originAckError":s.ack_error,"webhookTaskError":s.webhook_error,"coveragePollRequired":!beam,"coverageError":s.coverage_error,"coverageLastPollMs":s.coverage_poll_ms,"beamCommittedCursor":s.beam_cursor,"beamLastFrameAgeMs":s.beam_last_receipt.map(|t|t.elapsed().as_millis()as u64),"beamSourceObservedAtMs":s.beam_observed_ms,"beamReconcileError":s.beam_reconcile_error,"workerRecovery":s.beam_recovery,"beamProjection":if beam{store.beam_status().unwrap_or_else(|_|json!({"error":"beam_state_unavailable"}))}else{Value::Null},"subscriptions":store.subscriptions().unwrap_or(Value::Null),"sampledAtMs":now_ms()})
    }
    fn beam_fresh(s: &State) -> bool {
        s.beam_connected
            && s.beam_last_receipt
                .is_some_and(|time| time.elapsed() <= Duration::from_secs(5))
            && s.beam_observed_ms.is_some_and(|time| {
                blockzilla_bank_stream_v2::clock_check(time, now_ms()).is_ok()
                    && now_ms().saturating_sub(time) <= 5000
            })
    }
    pub fn begin_beam(&self, generation: &str) {
        let mut s = self.inner.lock().unwrap();
        s.beam_generation = Some(generation.into());
        s.beam_connected = false;
        s.signing = None;
        s.input = "starting".into();
    }
    pub fn failed(&self) -> bool {
        self.inner.lock().unwrap().input == "failed"
    }
    pub fn beam_connected(&self) {
        let mut s = self.inner.lock().unwrap();
        if s.input == "failed" {
            return;
        }
        s.beam_connected = true;
        s.input = "unavailable".into();
    }
    pub fn beam_unavailable(&self, error: &str) {
        let mut s = self.inner.lock().unwrap();
        if s.input == "failed" {
            return;
        }
        s.beam_connected = false;
        s.input = "reconnecting".into();
        s.error = Some(error.into());
        s.signing = None;
    }
    pub fn beam_committed(&self, frame: &blockzilla_bank_client::Frame) {
        let mut s = self.inner.lock().unwrap();
        if s.input == "failed" {
            return;
        }
        s.beam_last_receipt = Some(Instant::now());
        s.beam_observed_ms = Some(
            s.beam_observed_ms
                .unwrap_or(0)
                .max(frame.envelope.event.observed_at_unix_ms),
        );
        s.beam_cursor = Some(frame.cursor.clone());
        s.error = None;
    }
    pub fn beam_reconcile_error(&self, error: &str) {
        self.inner.lock().unwrap().beam_reconcile_error = if error.is_empty() {
            None
        } else {
            Some(error.into())
        };
    }
    pub fn configure_beam_recovery(&self, enabled: bool) {
        self.inner.lock().unwrap().beam_recovery.enabled = enabled;
    }
    pub fn begin_beam_recovery(&self, after: &str, until: &str) {
        let mut s = self.inner.lock().unwrap();
        if !s.beam_recovery.active {
            s.beam_recovery.from_cursor = Some(after.to_owned());
            s.beam_recovery.to_cursor = Some(until.to_owned());
            s.beam_recovery.last_error = None;
        }
        s.beam_recovery.active = true;
    }
    pub fn beam_recovered(&self, frame: &blockzilla_bank_client::Frame) {
        let mut s = self.inner.lock().unwrap();
        let count = if frame.envelope.event.kind == "block" {
            &mut s.beam_recovery.committed_blocks
        } else {
            &mut s.beam_recovery.committed_controls
        };
        *count = count.saturating_add(1);
    }
    pub fn finish_beam_recovery(&self) {
        let mut s = self.inner.lock().unwrap();
        s.beam_recovery.active = false;
        s.beam_recovery.completed_windows = s.beam_recovery.completed_windows.saturating_add(1);
        s.beam_recovery.last_error = None;
    }
    pub fn beam_recovery_failed(&self, error: &str) {
        let mut s = self.inner.lock().unwrap();
        s.beam_recovery.failed_attempts = s.beam_recovery.failed_attempts.saturating_add(1);
        s.beam_recovery.last_error = Some(error.to_owned());
    }
    pub fn refresh_beam(&self, store: &Store) -> Result<()> {
        let now = now_ms();
        let usable = store.beam_signing(now)?;
        let mut s = self.inner.lock().unwrap();
        if s.input == "failed" {
            return Ok(());
        }
        if !Self::beam_fresh(&s) {
            s.signing = None;
            if s.beam_connected {
                s.input = "unavailable".into();
            }
            return Ok(());
        }
        s.input = "live".into();
        s.error = None;
        if let Some(v) = usable {
            s.valid_until = v.observed_at_unix_ms.saturating_add(5000);
            s.valid_for = Duration::from_millis(s.valid_until.saturating_sub(now));
            s.set_at = Instant::now();
            s.signing = Some(
                json!({"source":store.source,"commitment":v.commitment,"contextSlot":v.recent_blockhash.context_slot,"blockHeight":v.block_height,"blockhash":v.recent_blockhash.blockhash,"lastValidBlockHeight":v.recent_blockhash.last_valid_block_height,"observedAtMs":v.observed_at_unix_ms,"sourceCursor":v.event_cursor}),
            );
        } else {
            s.signing = None;
        }
        Ok(())
    }
    fn refresh(&self, stream: &BankStream, store: &Store, pressure: bool) {
        let now = now_ms();
        let usable = stream
            .ready_hash(now)
            .ok()
            .and_then(|_| stream.selected())
            .filter(|v| store.selected_matches(v).unwrap_or(false));
        let mut s = self.inner.lock().unwrap();
        if pressure {
            s.input = "origin_ack_backlog".into();
            s.signing = None;
            return;
        }
        if let Some(v) = usable {
            s.input = "live".into();
            s.error = None;
            s.valid_until = v.observed_at_unix_ms.saturating_add(5000);
            s.valid_for = Duration::from_millis(s.valid_until.saturating_sub(now));
            s.set_at = Instant::now();
            s.signing = Some(
                json!({"source":store.source,"commitment":v.commitment,"contextSlot":v.recent_blockhash.context_slot,"blockHeight":v.block_height,"blockhash":v.recent_blockhash.blockhash,"lastValidBlockHeight":v.recent_blockhash.last_valid_block_height,"observedAtMs":v.observed_at_unix_ms,"sourceCursor":v.event_cursor}),
            );
        } else {
            s.input = "unavailable".into();
            s.signing = None;
        }
    }
}

pub async fn run(
    client: BankClient,
    store: Arc<Store>,
    runtime: Arc<Runtime>,
    initial_after: Option<String>,
    join_head: bool,
) -> Result<()> {
    let saved = store.cursor()?;
    anyhow::ensure!(
        saved.is_some() || initial_after.is_some() || join_head,
        "initial_boundary_required"
    );
    let bootstrap = client
        .bootstrap(saved.as_deref().or(initial_after.as_deref()))
        .await?;
    let payload = if let Some(frame) = bootstrap.payload.clone() {
        Some(store.payloads.load(frame).await?)
    } else {
        None
    };
    store.bootstrap_shared(&bootstrap, payload)?;
    let mut stream = client.connect(bootstrap).await?;
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let pressure = store.ack_backlog()?["pressure"].as_bool().unwrap_or(true);
        if pressure {
            stream.force_unavailable();
            runtime.refresh(&stream, &store, true);
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }
        tokio::select! {
            _=tick.tick()=>{runtime.refresh(&stream,&store,false);store.notify.notify_waiters();},
            next=stream.next()=>match next?{
                StreamEvent::Status(_)=>{runtime.refresh(&stream,&store,false);store.notify.notify_waiters();},
                StreamEvent::Bank(mut delivery)=>{
                    let candidate=if delivery.frame.envelope.event.kind=="block"{Some(delivery.frame.clone())}else{
                        let sha=delivery.frame.envelope.event.payload_frame_sha256.as_ref().context("missing_payload")?;
                        if store.has_payload(sha)?{None}else{
                            if delivery.dependency.is_none(){delivery.dependency=Some(client.fetch(sha).await?);}
                            delivery.dependency.clone()
                        }
                    };
                    let decoded=if let Some(frame)=candidate{Some(store.payloads.load(frame).await?)}else{None};
                    let cursor=delivery.frame.cursor.clone();let db=store.clone();
                    stream.ack(&cursor,||async move{tokio::task::spawn_blocking(move||db.commit_shared(&delivery,decoded)).await?}).await?;
                    runtime.refresh(&stream,&store,false);
                }
            }
        }
    }
}
pub async fn ack_loop(
    client: BankClient,
    consumer_id: String,
    store: Arc<Store>,
    runtime: Arc<Runtime>,
) -> Result<()> {
    let mut delay = 100u64;
    loop {
        tokio::time::sleep(Duration::from_millis(delay)).await;
        let result = async {
            if let Some((cursor, gaps)) = store.pending_ack()? {
                client
                    .acknowledge_coverage(&consumer_id, &cursor, gaps)
                    .await?;
                store.acked(&cursor, gaps)?;
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        match result {
            Ok(()) => {
                delay = 100;
                runtime.inner.lock().unwrap().ack_error = None;
            }
            Err(e) => {
                runtime.inner.lock().unwrap().ack_error = Some(e.to_string());
                if !e
                    .downcast_ref::<blockzilla_bank_client::ClientError>()
                    .is_some_and(|e| e.is_transient())
                {
                    return Err(e);
                }
                delay = (delay * 2).min(5000);
            }
        }
    }
}
pub async fn coverage_loop(
    client: BankClient,
    store: Arc<Store>,
    runtime: Arc<Runtime>,
) -> Result<()> {
    loop {
        tokio::time::sleep(Duration::from_millis(300)).await;
        if store.cursor()?.is_none() || store.ack_backlog()?["pressure"] == true {
            continue;
        }
        let after = store.coverage_sequence()?;
        match client
            .coverage_gaps(after, &store.producer_generation)
            .await
        {
            Ok(page) => {
                let db = store.clone();
                tokio::task::spawn_blocking(move || db.commit_coverage(&page)).await??;
                let mut s = runtime.inner.lock().unwrap();
                s.coverage_error = None;
                s.coverage_poll_ms = Some(now_ms());
            }
            Err(e) => {
                let terminal = e.is_terminal();
                runtime.inner.lock().unwrap().coverage_error = Some(e.to_string());
                store.notify.notify_waiters();
                if terminal {
                    return Err(e.into());
                }
            }
        }
    }
}

#[cfg(test)]
mod beam_tests {
    use super::*;
    use crate::{projection::Payload, store::Limits};
    use blockzilla_bank_client::{Bootstrap, Delivery};
    use blockzilla_bank_stream_v2::{
        self as v2,
        fixtures::{block, control, source},
    };
    fn fresh(mut frame: v2::Frame) -> v2::Frame {
        let meta = u32::from_le_bytes(frame.wire[8..12].try_into().unwrap()) as usize;
        frame.envelope.event.observed_at_unix_ms = now_ms();
        v2::encode(frame.envelope, &frame.wire[16 + meta..]).unwrap()
    }
    #[test]
    fn raw_readiness_requires_native_proof_fresh_receipt_and_expiry() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(
            &temp.path().join("beam.sqlite"),
            source(),
            "b".repeat(64),
            vec![],
            Limits::default(),
        )
        .unwrap();
        let zero = v2::cursor(&source().session_id, 0, "-");
        let head = v2::Head {
            schema: v2::HEAD.into(),
            profile: v2::PROFILE.into(),
            source: source(),
            cursor: Some(zero.clone()),
            earliest_after: Some(zero.clone()),
            status: "starting".into(),
            sampled_at_unix_ms: now_ms(),
            source_observed_at_unix_ms: None,
            source_lag_ms: None,
            latest_confirmed: None,
        };
        store
            .bootstrap_beam(
                &Bootstrap {
                    head,
                    after: zero,
                    control: None,
                    payload: None,
                },
                None,
                &"a".repeat(32),
            )
            .unwrap();
        let runtime = Runtime::default();
        runtime.begin_beam(&"a".repeat(32));
        runtime.beam_connected();
        assert_eq!(runtime.status(&store)["signingReady"], false);
        let payload = fresh(block(1, 9, 1, 8, 100));
        let shared = store
            .payloads
            .materialize(Payload {
                frame: payload.clone(),
                json: json!({"blocks":[{"transactions":[]}]}),
            })
            .unwrap();
        store
            .commit_beam(
                &Delivery {
                    frame: payload.clone(),
                    dependency: None,
                },
                Some(shared),
            )
            .unwrap();
        runtime.beam_committed(&payload);
        runtime.refresh_beam(&store).unwrap();
        assert_eq!(runtime.status(&store)["signingReady"], false);
        let root = control(&payload, 2, "root", now_ms());
        store
            .commit_beam(
                &Delivery {
                    frame: root.clone(),
                    dependency: None,
                },
                None,
            )
            .unwrap();
        runtime.beam_committed(&root);
        runtime.refresh_beam(&store).unwrap();
        let status = runtime.status(&store);
        assert_eq!(status["signingReady"], true);
        assert_eq!(status["originAckRequired"], false);
        assert_eq!(status["coveragePollRequired"], false);
        runtime.configure_beam_recovery(true);
        runtime.beam_unavailable("recovering_retained_stream");
        runtime.begin_beam_recovery(&payload.cursor, &root.cursor);
        runtime.beam_committed(&root);
        runtime.beam_recovered(&root);
        runtime.refresh_beam(&store).unwrap();
        let recovering = runtime.status(&store);
        assert_eq!(recovering["signingReady"], false);
        assert_eq!(recovering["workerRecovery"]["active"], true);
        assert_eq!(recovering["workerRecovery"]["fromCursor"], payload.cursor);
        assert_eq!(recovering["workerRecovery"]["toCursor"], root.cursor);
        assert_eq!(recovering["workerRecovery"]["committedControls"], 1);
        runtime.beam_recovery_failed("interrupted");
        // A retry keeps the original window rather than replacing its boundary.
        runtime.begin_beam_recovery(&root.cursor, &root.cursor);
        assert_eq!(
            runtime.status(&store)["workerRecovery"]["fromCursor"],
            payload.cursor
        );
        runtime.finish_beam_recovery();
        assert_eq!(runtime.status(&store)["signingReady"], false);
        runtime.beam_connected();
        runtime.refresh_beam(&store).unwrap();
        let resumed = runtime.status(&store);
        assert_eq!(resumed["signingReady"], true);
        assert_eq!(resumed["workerRecovery"]["active"], false);
        assert_eq!(resumed["workerRecovery"]["completedWindows"], 1);
        assert_eq!(resumed["workerRecovery"]["failedAttempts"], 1);
        assert!(resumed["workerRecovery"]["lastError"].is_null());
        runtime.inner.lock().unwrap().beam_last_receipt =
            Some(Instant::now() - Duration::from_secs(6));
        assert_eq!(runtime.status(&store)["signingReady"], false);
        {
            let mut state = runtime.inner.lock().unwrap();
            state.beam_last_receipt = Some(Instant::now());
            state.valid_until = now_ms() - 1;
        }
        assert_eq!(runtime.status(&store)["signingReady"], false);
        runtime.fail("source_changed");
        runtime.beam_connected();
        runtime.beam_unavailable("temporary");
        runtime.beam_committed(&root);
        assert!(runtime.failed());
        assert_eq!(runtime.status(&store)["error"], "source_changed");
    }
}
