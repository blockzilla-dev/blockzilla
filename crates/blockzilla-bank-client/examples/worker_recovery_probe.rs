//! Isolated disconnect test. Payloads stay in RAM; stdout contains only checked
//! identities, counts and hashes. This never changes a producer or consumer.
use anyhow::{Context, Result, ensure};
use blockzilla_bank_client::{
    Frame, SourceIdentity, WorkerRecoveryClient, WorkerRecoveryConfig, now_ms,
    ssh_beam::{SshBeam, SshConfig},
};
use blockzilla_bank_stream_v2 as v2;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::Duration,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    host: String,
    helper: String,
    job: String,
    generation: String,
    producer_generation: String,
    source: SourceIdentity,
    worker_url: String,
    worker_api_key_file: String,
}
fn private_read(path: &Path, max: u64) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.len() <= max
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o077 == 0,
        "unsafe private configuration file"
    );
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= max, "private input too large");
    Ok(bytes)
}
async fn accept(
    config: &SshConfig,
    state: &mut v2::client::ClientState,
    seen: &mut BTreeSet<String>,
    frame: Frame,
    phase: &str,
    records: &mut Vec<Value>,
    dependency_reads: &mut u64,
) -> Result<()> {
    ensure!(!seen.contains(&frame.cursor), "duplicate native cursor");
    let dependency = if frame.envelope.event.kind != "block" {
        let digest = frame
            .envelope
            .event
            .payload_frame_sha256
            .as_deref()
            .context("control dependency missing")?;
        if state.has_payload(digest) {
            None
        } else {
            *dependency_reads += 1;
            Some(config.fetch(digest).await?)
        }
    } else {
        None
    };
    ensure!(
        state.apply(&frame, dependency.as_ref(), now_ms())?,
        "duplicate application event"
    );
    ensure!(
        state.cursor() == frame.cursor,
        "checkpoint did not advance exactly"
    );
    seen.insert(frame.cursor.clone());
    records.push(json!({"phase":phase,"cursor":frame.cursor,"sha256":frame.sha256,
        "slot":frame.envelope.event.bank.slot,"bank_id":frame.envelope.event.bank.bank_id,
        "kind":frame.envelope.event.kind,"bytes":frame.wire.len(),"objects":frame.envelope.objects.len()}));
    // The application checkpoint is RAM-only in this probe. The production
    // consumer commits the same verified frame and cursor in one transaction.
    Ok(())
}
async fn run(path: &Path) -> Result<Value> {
    let config: Config = serde_json::from_slice(&private_read(path, 65536)?)?;
    let key = String::from_utf8(private_read(Path::new(&config.worker_api_key_file), 512)?)?
        .trim()
        .to_owned();
    let ssh = SshConfig {
        host: config.host,
        helper: config.helper,
        job: config.job,
        generation: config.generation,
        producer_generation: config.producer_generation,
        source: config.source,
    };
    ssh.validate()?;
    let worker = WorkerRecoveryClient::new(WorkerRecoveryConfig::new(
        config.worker_url,
        key,
        ssh.source.clone(),
    ))?;
    let head = ssh.head().await?;
    let initial = head.cursor.clone().context("native head missing")?;
    let mut state = v2::client::ClientState::new(ssh.source.clone(), initial.clone())?;
    if let Some(selected) = &head.latest_confirmed {
        let control_digest = v2::parse_cursor(&selected.event_cursor)?.2;
        let (control, payload) = tokio::try_join!(
            ssh.fetch(control_digest),
            ssh.fetch(&selected.payload_frame_sha256)
        )?;
        state.resolve_head(&head, &control, &payload, now_ms())?;
    }
    let mut seen = BTreeSet::new();
    let mut records = Vec::new();
    let mut dependency_reads = 0;
    let mut stream = SshBeam::connect(&ssh, state.cursor()).await?;
    for _ in 0..3 {
        let frame = stream.next().await?;
        accept(
            &ssh,
            &mut state,
            &mut seen,
            frame,
            "before_disconnect",
            &mut records,
            &mut dependency_reads,
        )
        .await?;
    }
    let disconnected_after = state.cursor().to_owned();
    stream.close().await;
    drop(stream);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let target_head = ssh.head().await?;
    let target = target_head
        .cursor
        .clone()
        .context("recovery target missing")?;
    ensure!(
        v2::parse_cursor(&target)?.1 > v2::parse_cursor(&disconnected_after)?.1,
        "no events during disconnect"
    );
    let mut pages = 0;
    let mut worker_blocks = 0;
    let mut inline_controls = 0;
    while state.cursor() != target {
        ensure!(pages < 16, "recovery page limit");
        let plan = ssh.recovery_plan(state.cursor(), &target, 128).await?;
        ensure!(!plan.is_empty(), "recovery made no progress");
        pages += 1;
        for entry in plan {
            entry.notice.validate(&ssh.source, state.cursor())?;
            let frame = match entry.control {
                Some(control) => {
                    inline_controls += 1;
                    control
                }
                None => {
                    worker_blocks += 1;
                    worker.fetch(&entry.notice).await?
                }
            };
            entry.notice.validate_frame(&frame)?;
            accept(
                &ssh,
                &mut state,
                &mut seen,
                frame,
                "worker_recovery",
                &mut records,
                &mut dependency_reads,
            )
            .await?;
        }
    }
    ensure!(worker_blocks > 0, "no missing blocks tested");
    let recovered_cursor = state.cursor().to_owned();
    let mut resumed = SshBeam::connect(&ssh, state.cursor()).await?;
    for _ in 0..6 {
        let frame = resumed.next().await?;
        accept(
            &ssh,
            &mut state,
            &mut seen,
            frame,
            "after_resume",
            &mut records,
            &mut dependency_reads,
        )
        .await?;
    }
    resumed.close().await;
    let evidence_hash = v2::digest(&serde_json::to_vec(&records)?);
    Ok(
        json!({"schema":"blockzilla-worker-client-recovery-probe-v1","state":"PASS","source":ssh.source,
        "initial_cursor":initial,"disconnected_after":disconnected_after,"fixed_target":target,
        "recovered_cursor":recovered_cursor,"final_cursor":state.cursor(),"pages":pages,
        "worker_blocks":worker_blocks,"inline_native_controls":inline_controls,"dependency_reads":dependency_reads,
        "accepted_events":records.len(),"duplicate_events":0,"missing_sequences":0,"payload_files_written":0,
        "evidence_sha256":evidence_hash,"frames":records}),
    )
}
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    ensure!(
        args.len() == 3 && args[1] == "--config",
        "usage: worker_recovery_probe --config PRIVATE_JSON_FILE"
    );
    let result = tokio::time::timeout(Duration::from_secs(180), run(Path::new(&args[2])))
        .await
        .context("probe deadline")??;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
