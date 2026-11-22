//! Drive the real input loop and compact SQLite commit path with controlled
//! transport failures. HTTP body admission has separate SDK transport tests.
use super::*;
use crate::{projection::PayloadMode, store::Limits};
use blockzilla_bank_client::WorkerRecoveryConfig;
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

struct FailedStream(Option<ClientError>);
impl InputFrames for FailedStream {
    fn next(&mut self) -> BoxFuture<'_, blockzilla_bank_client::Result<Frame>> {
        Box::pin(async move { Err(self.0.take().unwrap_or(ClientError::Stopped)) })
    }
    fn close(&mut self) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}

struct ControlledTransport {
    frames: Vec<Frame>,
    first_head_is_zero: bool,
    disconnect_once: bool,
    interrupt_worker_once: bool,
    heads: AtomicUsize,
    plans: AtomicUsize,
    worker_reads: AtomicUsize,
    connected_after: Mutex<Vec<String>>,
}
impl ControlledTransport {
    fn new(payload: Frame, first_join: bool) -> Self {
        Self {
            frames: vec![
                payload.clone(),
                v2::fixtures::control(
                    &payload,
                    2,
                    "root",
                    payload.envelope.event.observed_at_unix_ms + 1,
                ),
                v2::fixtures::control(
                    &payload,
                    3,
                    "confirmed",
                    payload.envelope.event.observed_at_unix_ms + 2,
                ),
            ],
            first_head_is_zero: first_join,
            disconnect_once: first_join,
            interrupt_worker_once: first_join,
            heads: AtomicUsize::new(0),
            plans: AtomicUsize::new(0),
            worker_reads: AtomicUsize::new(0),
            connected_after: Mutex::new(Vec::new()),
        }
    }
    fn zero(&self) -> String {
        v2::cursor(&self.frames[0].source.session_id, 0, "-")
    }
    fn sampled_head(&self, zero: bool) -> Head {
        Head {
            schema: v2::HEAD.into(),
            profile: v2::PROFILE.into(),
            source: self.frames[0].source.clone(),
            cursor: Some(if zero {
                self.zero()
            } else {
                self.frames[2].cursor.clone()
            }),
            earliest_after: Some(self.zero()),
            status: "starting".into(),
            sampled_at_unix_ms: now_ms(),
            source_observed_at_unix_ms: None,
            source_lag_ms: None,
            latest_confirmed: None,
        }
    }
}
impl InputTransport for ControlledTransport {
    fn head(&self) -> BoxFuture<'_, blockzilla_bank_client::Result<Head>> {
        Box::pin(async move {
            let first = self.heads.fetch_add(1, Ordering::SeqCst) == 0;
            Ok(self.sampled_head(first && self.first_head_is_zero))
        })
    }
    fn fetch<'a>(&'a self, _: &'a str) -> BoxFuture<'a, blockzilla_bank_client::Result<Frame>> {
        Box::pin(async { panic!("unexpected native block dependency read") })
    }
    fn connect<'a>(
        &'a self,
        after: &'a str,
    ) -> BoxFuture<'a, blockzilla_bank_client::Result<Box<dyn InputFrames>>> {
        Box::pin(async move {
            let mut calls = self.connected_after.lock().unwrap();
            let first = calls.is_empty();
            calls.push(after.to_owned());
            let error = if first && self.disconnect_once {
                ClientError::Transient("beam_frame_interrupted".into())
            } else {
                ClientError::Source("controlled_input_stop".into())
            };
            Ok(Box::new(FailedStream(Some(error))) as Box<dyn InputFrames>)
        })
    }
    fn plan<'a>(
        &'a self,
        after: &'a str,
        until: &'a str,
    ) -> BoxFuture<'a, blockzilla_bank_client::Result<Vec<RecoveryEntry>>> {
        Box::pin(async move {
            self.plans.fetch_add(1, Ordering::SeqCst);
            assert_eq!(until, self.frames[2].cursor);
            let sequence = v2::parse_cursor(after).unwrap().1;
            Ok(self
                .frames
                .iter()
                .filter(|frame| frame.envelope.event.sequence > sequence)
                .map(|frame| RecoveryEntry {
                    notice: RecoveryNotice::from_frame(frame),
                    control: (frame.envelope.event.kind != "block").then(|| frame.clone()),
                })
                .collect())
        })
    }
    fn recover_block<'a>(
        &'a self,
        notice: &'a RecoveryNotice,
    ) -> BoxFuture<'a, blockzilla_bank_client::Result<Frame>> {
        Box::pin(async move {
            assert_eq!(notice.cursor, self.frames[0].cursor);
            let first = self.worker_reads.fetch_add(1, Ordering::SeqCst) == 0;
            if first && self.interrupt_worker_once {
                Err(ClientError::Transient("worker_recovery_interrupted".into()))
            } else {
                Ok(self.frames[0].clone())
            }
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires BLOCKZILLA_SIDECAR_FRAME from a retained real native Bank"]
async fn automatic_worker_recovery_commits_once_after_disconnect_and_restart() {
    let bytes = std::fs::read(std::env::var("BLOCKZILLA_SIDECAR_FRAME").unwrap()).unwrap();
    let frame = v2::decode(bytes.into()).unwrap();
    assert_eq!(frame.envelope.event.kind, "block");
    let meta = u32::from_le_bytes(frame.wire[8..12].try_into().unwrap()) as usize;
    let payload = frame.wire.slice(16 + meta..);
    let mut envelope = frame.envelope;
    envelope.event.sequence = 1;
    envelope.event.source_sequence = 1;
    let frame = v2::encode(envelope, &payload).unwrap();
    let config = SshConfig {
        host: "ubuntu@127.0.0.1".into(),
        helper: "/helper.py".into(),
        job: "/job".into(),
        generation: "a".repeat(32),
        producer_generation: "b".repeat(64),
        source: frame.source.clone(),
    };
    let input = RawSshInput {
        recovery: Some(
            WorkerRecoveryClient::new(WorkerRecoveryConfig::new(
                "https://example.invalid/",
                "k".repeat(48),
                frame.source.clone(),
            ))
            .unwrap(),
        ),
        config: config.clone(),
        initial_after: None,
        join_head: true,
        bootstrap: None,
    };
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("consumer.sqlite");
    let open = || {
        Store::open_with_mode(
            &path,
            frame.source.clone(),
            config.producer_generation.clone(),
            vec![],
            Limits {
                replay_bytes: 128 * 1024 * 1024,
                replay_events: 1024,
                database_bytes: 320 * 1024 * 1024,
            },
            PayloadMode::CompactOnly,
            0,
        )
        .unwrap()
    };
    let store = open();
    let transport = ControlledTransport::new(frame.clone(), true);
    let runtime = Arc::new(Runtime::default());
    let error = tokio::time::timeout(
        Duration::from_secs(10),
        run_with(&input, &transport, store.clone(), runtime.clone()),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(error.to_string().contains("controlled_input_stop"));
    assert_eq!(transport.worker_reads.load(Ordering::SeqCst), 2);
    assert_eq!(
        transport.heads.load(Ordering::SeqCst),
        2,
        "retry must keep one fixed head"
    );
    assert_eq!(transport.plans.load(Ordering::SeqCst), 2);
    assert_eq!(
        *transport.connected_after.lock().unwrap(),
        vec![transport.zero(), transport.frames[2].cursor.clone()]
    );
    assert_eq!(
        store.cursor().unwrap().as_ref(),
        Some(&transport.frames[2].cursor)
    );
    let output = store.output_cursor().unwrap();
    assert_eq!(
        crate::cursor::parse(&output, &frame.source.session_id).unwrap(),
        3
    );
    let stats = store.storage_status().unwrap();
    assert_eq!(stats["retainedEvents"], 3);
    assert_eq!(stats["persistedPayloads"], 1);
    assert_eq!(stats["persistedWireBytes"], frame.wire.len());
    assert_eq!(stats["persistedProjectionBytes"], 0);
    let status = runtime.status(&store);
    assert_eq!(status["workerRecovery"]["committedBlocks"], 1);
    assert_eq!(status["workerRecovery"]["committedControls"], 2);
    assert_eq!(status["workerRecovery"]["completedWindows"], 1);
    assert_eq!(status["workerRecovery"]["failedAttempts"], 1);
    drop(store);

    let store = open();
    let restarted = ControlledTransport::new(frame.clone(), false);
    let error = tokio::time::timeout(
        Duration::from_secs(10),
        run_with(
            &input,
            &restarted,
            store.clone(),
            Arc::new(Runtime::default()),
        ),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(error.to_string().contains("controlled_input_stop"));
    assert_eq!(restarted.worker_reads.load(Ordering::SeqCst), 0);
    assert_eq!(restarted.plans.load(Ordering::SeqCst), 0);
    assert_eq!(store.output_cursor().unwrap(), output);
    assert_eq!(store.storage_status().unwrap()["persistedPayloads"], 1);
    assert_eq!(store.storage_status().unwrap()["retainedEvents"], 3);
}
