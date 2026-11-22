//! Consumer-owned raw SSH input. Foundation supplies only immutable raw data.
use crate::{config::BeamBootstrapFile, consume::Runtime, store::Store};
use anyhow::{Context, Result, ensure};
use blockzilla_bank_client::{
    Bootstrap, ClientError, Delivery, Frame, Head, RecoveryEntry, RecoveryNotice,
    WorkerRecoveryClient, now_ms,
    ssh_beam::{SshBeam, SshConfig},
};
use blockzilla_bank_stream_v2 as v2;
use futures_util::future::BoxFuture;
use std::{sync::Arc, time::Duration};

#[derive(Clone)]
pub struct RawSshInput {
    pub config: SshConfig,
    pub initial_after: Option<String>,
    pub join_head: bool,
    pub bootstrap: Option<BeamBootstrapFile>,
    pub recovery: Option<WorkerRecoveryClient>,
}

// Keep transport failures separate from the durable input loop. The test
// transport uses the same admission, payload and SQLite commit path.
trait InputFrames: Send {
    fn next(&mut self) -> BoxFuture<'_, blockzilla_bank_client::Result<Frame>>;
    fn close(&mut self) -> BoxFuture<'_, ()>;
}
impl InputFrames for SshBeam {
    fn next(&mut self) -> BoxFuture<'_, blockzilla_bank_client::Result<Frame>> {
        Box::pin(SshBeam::next(self))
    }
    fn close(&mut self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let _ = SshBeam::close(self).await;
        })
    }
}
trait InputTransport: Send + Sync {
    fn head(&self) -> BoxFuture<'_, blockzilla_bank_client::Result<Head>>;
    fn fetch<'a>(&'a self, digest: &'a str)
    -> BoxFuture<'a, blockzilla_bank_client::Result<Frame>>;
    fn connect<'a>(
        &'a self,
        after: &'a str,
    ) -> BoxFuture<'a, blockzilla_bank_client::Result<Box<dyn InputFrames>>>;
    fn plan<'a>(
        &'a self,
        after: &'a str,
        until: &'a str,
    ) -> BoxFuture<'a, blockzilla_bank_client::Result<Vec<RecoveryEntry>>>;
    fn recover_block<'a>(
        &'a self,
        notice: &'a RecoveryNotice,
    ) -> BoxFuture<'a, blockzilla_bank_client::Result<Frame>>;
}
struct SshTransport<'a>(&'a RawSshInput);
impl InputTransport for SshTransport<'_> {
    fn head(&self) -> BoxFuture<'_, blockzilla_bank_client::Result<Head>> {
        Box::pin(self.0.config.head())
    }
    fn fetch<'a>(
        &'a self,
        digest: &'a str,
    ) -> BoxFuture<'a, blockzilla_bank_client::Result<Frame>> {
        Box::pin(self.0.config.fetch(digest))
    }
    fn connect<'a>(
        &'a self,
        after: &'a str,
    ) -> BoxFuture<'a, blockzilla_bank_client::Result<Box<dyn InputFrames>>> {
        Box::pin(async move {
            Ok(Box::new(SshBeam::connect(&self.0.config, after).await?) as Box<dyn InputFrames>)
        })
    }
    fn plan<'a>(
        &'a self,
        after: &'a str,
        until: &'a str,
    ) -> BoxFuture<'a, blockzilla_bank_client::Result<Vec<RecoveryEntry>>> {
        Box::pin(self.0.config.recovery_plan(after, until, 128))
    }
    fn recover_block<'a>(
        &'a self,
        notice: &'a RecoveryNotice,
    ) -> BoxFuture<'a, blockzilla_bank_client::Result<Frame>> {
        Box::pin(async move {
            self.0
                .recovery
                .as_ref()
                .ok_or(ClientError::Configuration("recovery_not_configured"))?
                .fetch(notice)
                .await
        })
    }
}
fn transient(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<ClientError>()
        .is_some_and(ClientError::is_transient)
}
fn check_after(head: &Head, after: &str) -> Result<()> {
    let (session, sequence, _) = v2::parse_cursor(after)?;
    ensure!(session == head.source.session_id, "source_changed");
    let floor = v2::parse_cursor(
        head.earliest_after
            .as_deref()
            .context("head_floor_missing")?,
    )?
    .1;
    let tip = v2::parse_cursor(head.cursor.as_deref().context("head_cursor_missing")?)?.1;
    ensure!(sequence >= floor, "saved_cursor_expired");
    ensure!(sequence <= tip, "saved_cursor_ahead");
    Ok(())
}
fn checked_bootstrap(
    config: &SshConfig,
    head: Head,
    after: String,
    control: Option<Frame>,
    payload: Option<Frame>,
) -> Result<Bootstrap> {
    head.validate(&config.source, now_ms(), v2::DEFAULT_MAX_LAG_MS)?;
    check_after(&head, &after)?;
    match (&head.latest_confirmed, &control, &payload) {
        (Some(selected), Some(control), Some(payload)) => {
            ensure!(
                control.source == config.source && payload.source == config.source,
                "source_changed"
            );
            ensure!(
                v2::ConfirmedObservation::from_frame(control)? == *selected,
                "head_control_changed"
            );
            control.envelope.event.matches_payload(payload)?;
        }
        (None, None, None) => {}
        _ => anyhow::bail!("bootstrap_dependency_missing"),
    }
    Ok(Bootstrap {
        head,
        after,
        control,
        payload,
    })
}

fn recovery_target(head: &Head, after: &str) -> Result<String> {
    check_after(head, after)?;
    let target = head.cursor.as_deref().context("head_cursor_missing")?;
    if v2::parse_cursor(after)?.1 == v2::parse_cursor(target)?.1 {
        ensure!(after == target, "recovery_target_cursor_changed");
    }
    Ok(target.to_owned())
}

/// Replay one fixed native window through the normal durable commit path.
/// Metadata and original controls come from the source; only missing block
/// payloads use the Worker. A retry starts at the last committed SQLite cursor.
async fn recover(
    input: &RawSshInput,
    transport: &impl InputTransport,
    store: &Arc<Store>,
    runtime: &Runtime,
    target: &mut Option<String>,
) -> Result<()> {
    if target.is_none() {
        let after = store.cursor()?.context("beam_checkpoint_missing")?;
        *target = Some(recovery_target(&transport.head().await?, &after)?);
    }
    let until = target.as_deref().context("recovery_target_missing")?;
    runtime.beam_unavailable("recovering_retained_stream");
    runtime.begin_beam_recovery(&store.cursor()?.context("beam_checkpoint_missing")?, until);
    store.notify.notify_waiters();
    loop {
        if runtime.failed() {
            std::future::pending::<()>().await;
        }
        let after = store.cursor()?.context("beam_checkpoint_missing")?;
        if after == until {
            runtime.finish_beam_recovery();
            return Ok(());
        }
        ensure!(
            v2::parse_cursor(&after)?.1 < v2::parse_cursor(until)?.1,
            "recovery_target_cursor_changed"
        );
        let entries = transport.plan(&after, until).await?;
        ensure!(!entries.is_empty(), "recovery_plan_ended_before_target");
        for entry in entries {
            if runtime.failed() {
                std::future::pending::<()>().await;
            }
            let committed = store.cursor()?.context("beam_checkpoint_missing")?;
            entry.notice.validate(&input.config.source, &committed)?;
            ensure!(
                entry.notice.event.sequence <= v2::parse_cursor(until)?.1,
                "recovery_plan_passed_target"
            );
            let frame = match entry.control {
                Some(frame) => frame,
                None => transport.recover_block(&entry.notice).await?,
            };
            entry.notice.validate_frame(&frame)?;
            commit_frame(transport, store, frame.clone()).await?;
            runtime.beam_committed(&frame);
            runtime.beam_recovered(&frame);
            // Recovery must not make signing data ready before the live raw
            // stream reconnects, even if the recovered frame is recent.
            runtime.refresh_beam(store)?;
        }
    }
}
async fn prepare(
    input: &RawSshInput,
    transport: &impl InputTransport,
    store: &Store,
) -> Result<Bootstrap> {
    let saved = store.cursor()?;
    let (head, pinned_after) = if saved.is_none() {
        if let Some(file) = &input.bootstrap {
            (file.head.clone(), Some(file.validate(&input.config)?))
        } else {
            (transport.head().await?, None)
        }
    } else {
        (transport.head().await?, None)
    };
    let after = if let Some(saved) = saved {
        saved
    } else if let Some(after) = pinned_after {
        after
    } else if input.join_head {
        head.cursor.clone().context("head_cursor_missing")?
    } else if let Some(after) = &input.initial_after {
        ensure!(
            head.cursor.as_deref() == Some(after.as_str()),
            "initial_after_requires_matching_head_snapshot_use_bootstrap_file"
        );
        after.clone()
    } else {
        anyhow::bail!("explicit_initial_boundary_required")
    };
    let (control, payload) = if let Some(selected) = &head.latest_confirmed {
        let sha = v2::parse_cursor(&selected.event_cursor)?.2.to_owned();
        let (control, payload) = tokio::try_join!(
            transport.fetch(&sha),
            transport.fetch(&selected.payload_frame_sha256)
        )?;
        (Some(control), Some(payload))
    } else {
        (None, None)
    };
    checked_bootstrap(&input.config, head, after, control, payload)
}

pub async fn run(input: RawSshInput, store: Arc<Store>, runtime: Arc<Runtime>) -> Result<()> {
    run_with(&input, &SshTransport(&input), store, runtime).await
}

async fn run_with(
    input: &RawSshInput,
    transport: &impl InputTransport,
    store: Arc<Store>,
    runtime: Arc<Runtime>,
) -> Result<()> {
    input.config.validate()?;
    ensure!(
        input.config.source == store.source
            && input.config.producer_generation == store.producer_generation
            && input
                .recovery
                .as_ref()
                .is_none_or(|worker| worker.source() == &input.config.source),
        "input_store_source_changed"
    );
    runtime.begin_beam(&input.config.generation);
    runtime.configure_beam_recovery(input.recovery.is_some());
    let mut needs_recovery = input.recovery.is_some() && store.cursor()?.is_some();
    let mut recovery_until = None;
    let mut delay = Duration::from_millis(250);
    loop {
        if runtime.failed() {
            std::future::pending::<()>().await;
        }
        match prepare(input, transport, &store).await {
            Ok(bootstrap) => {
                let shared = if let Some(payload) = bootstrap.payload.clone() {
                    Some(store.payloads.load(payload).await?)
                } else {
                    None
                };
                let db = store.clone();
                let generation = input.config.generation.clone();
                tokio::task::spawn_blocking(move || {
                    db.bootstrap_beam(&bootstrap, shared, &generation)
                })
                .await??;
                break;
            }
            Err(error) if transient(&error) => {
                runtime.beam_unavailable(&error.to_string());
                store.notify.notify_waiters();
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(5));
            }
            Err(error) => return Err(error),
        }
    }
    delay = Duration::from_millis(250);
    loop {
        if runtime.failed() {
            std::future::pending::<()>().await;
        }
        if needs_recovery {
            match recover(input, transport, &store, &runtime, &mut recovery_until).await {
                Ok(()) => {
                    needs_recovery = false;
                    recovery_until = None;
                }
                Err(error) if transient(&error) => {
                    runtime.beam_recovery_failed(&error.to_string());
                    runtime.beam_unavailable(&error.to_string());
                    store.notify.notify_waiters();
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(5));
                    continue;
                }
                Err(error) => {
                    runtime.beam_recovery_failed(&error.to_string());
                    return Err(error);
                }
            }
        }
        let after = store.cursor()?.context("beam_checkpoint_missing")?;
        let mut stream = match transport.connect(&after).await {
            Ok(stream) => stream,
            Err(error) if error.is_transient() => {
                needs_recovery = input.recovery.is_some();
                runtime.beam_unavailable(&error.to_string());
                store.notify.notify_waiters();
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(5));
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        runtime.beam_connected();
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let result = tokio::select! {
                _=tick.tick()=>{runtime.refresh_beam(&store)?;store.notify.notify_waiters();if runtime.failed(){stream.close().await;std::future::pending::<()>().await;}continue;},
                next=stream.next()=>next,
            };
            let frame = match result {
                Ok(frame) => frame,
                Err(error) if error.is_transient() => {
                    needs_recovery = input.recovery.is_some();
                    runtime.beam_unavailable(&error.to_string());
                    store.notify.notify_waiters();
                    break;
                }
                Err(error) => {
                    stream.close().await;
                    return Err(error.into());
                }
            };
            let commit = commit_frame(transport, &store, frame.clone()).await;
            match commit {
                Ok(()) => {
                    runtime.beam_committed(&frame);
                    runtime.refresh_beam(&store)?;
                    delay = Duration::from_millis(250);
                }
                Err(error) if transient(&error) => {
                    needs_recovery = input.recovery.is_some();
                    runtime.beam_unavailable(&error.to_string());
                    store.notify.notify_waiters();
                    break;
                }
                Err(error) => {
                    stream.close().await;
                    return Err(error);
                }
            }
        }
        stream.close().await;
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(5));
    }
}
async fn commit_frame(
    transport: &impl InputTransport,
    store: &Arc<Store>,
    frame: Frame,
) -> Result<()> {
    let dependency = if frame.envelope.event.kind == "block" {
        None
    } else {
        let sha = frame
            .envelope
            .event
            .payload_frame_sha256
            .as_deref()
            .context("control_payload_missing")?;
        if store.has_payload(sha)? {
            None
        } else {
            Some(transport.fetch(sha).await?)
        }
    };
    let candidate = if frame.envelope.event.kind == "block" {
        Some(frame.clone())
    } else {
        dependency.clone()
    };
    let decoded = if let Some(frame) = candidate {
        Some(store.payloads.load(frame).await?)
    } else {
        None
    };
    let delivery = Delivery { frame, dependency };
    let db = store.clone();
    tokio::task::spawn_blocking(move || db.commit_beam(&delivery, decoded)).await??;
    Ok(())
}

/// This is reconciliation of an explicit native invalidation only. It is not
/// a coverage poll, heartbeat dependency, or Foundation acknowledgement.
pub async fn reconcile(input: SshConfig, store: Arc<Store>, runtime: Arc<Runtime>) -> Result<()> {
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if runtime.failed() {
            std::future::pending::<()>().await;
        }
        if store.cursor()?.is_none() {
            continue;
        }
        if !store.beam_needs_reconcile()? {
            continue;
        }
        match input.head().await {
            Ok(head) => {
                let db = store.clone();
                let cleared =
                    tokio::task::spawn_blocking(move || db.reconcile_beam_head(&head)).await??;
                if cleared {
                    runtime.beam_reconcile_error("");
                }
                runtime.refresh_beam(&store)?;
                store.notify.notify_waiters();
            }
            Err(error) if error.is_transient() => {
                runtime.beam_reconcile_error(&error.to_string());
                store.notify.notify_waiters();
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
#[path = "input_recovery_tests.rs"]
mod recovery_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use v2::fixtures::{block, control, source};
    fn config() -> SshConfig {
        SshConfig {
            host: "ubuntu@127.0.0.1".into(),
            helper: "/helper.py".into(),
            job: "/job".into(),
            generation: "a".repeat(32),
            producer_generation: "b".repeat(64),
            source: source(),
        }
    }
    fn snapshot() -> (Head, Frame, Frame) {
        let payload = block(1, 9, 1, 8, 1);
        let control = control(&payload, 2, "root", 1000);
        let selected = v2::ConfirmedObservation::from_frame(&control).unwrap();
        let now = now_ms();
        let head = Head {
            schema: v2::HEAD.into(),
            profile: v2::PROFILE.into(),
            source: source(),
            cursor: Some(control.cursor.clone()),
            earliest_after: Some(v2::cursor(&source().session_id, 0, "-")),
            status: "stale".into(),
            sampled_at_unix_ms: now,
            source_observed_at_unix_ms: Some(1000),
            source_lag_ms: Some(now - 1000),
            latest_confirmed: Some(selected),
        };
        (head, control, payload)
    }
    #[test]
    fn exact_bootstrap_proves_control_and_payload_without_applying_future_cursor() {
        let (head, control, payload) = snapshot();
        let saved = payload.cursor.clone();
        let b = checked_bootstrap(&config(), head, saved.clone(), Some(control), Some(payload))
            .unwrap();
        assert_eq!(b.after, saved);
        assert_ne!(b.head.cursor.as_deref(), Some(b.after.as_str()));
    }
    #[test]
    fn wrong_or_missing_bootstrap_dependencies_never_become_ready() {
        let (head, control, payload) = snapshot();
        let after = head.cursor.clone().unwrap();
        assert!(checked_bootstrap(&config(), head.clone(), after.clone(), None, None).is_err());
        let wrong = block(1, 10, 2, 9, 2);
        assert!(
            checked_bootstrap(
                &config(),
                head.clone(),
                after.clone(),
                Some(control),
                Some(wrong)
            )
            .is_err()
        );
        let mut changed = config();
        changed.source.session_id = "other".into();
        assert!(checked_bootstrap(&changed, head, after, None, Some(payload)).is_err());
    }
    #[test]
    fn recovery_keeps_a_fixed_exact_target_and_rejects_missing_history() {
        let (mut head, control, payload) = snapshot();
        assert_eq!(
            recovery_target(&head, &payload.cursor).unwrap(),
            control.cursor
        );
        assert_eq!(
            recovery_target(&head, &control.cursor).unwrap(),
            control.cursor
        );
        let altered = v2::cursor(&source().session_id, 2, &"e".repeat(64));
        assert!(recovery_target(&head, &altered).is_err());
        let ahead = v2::cursor(&source().session_id, 3, &"e".repeat(64));
        assert!(recovery_target(&head, &ahead).is_err());
        let foreign = v2::cursor("other", 1, &payload.sha256);
        assert!(recovery_target(&head, &foreign).is_err());
        head.earliest_after = Some(control.cursor);
        assert!(recovery_target(&head, &payload.cursor).is_err());
    }
}
