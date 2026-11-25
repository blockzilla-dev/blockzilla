//! Persistent receipt-only client. No archive spool, projection or remote ACK.
#![recursion_limit = "256"]
use anyhow::{Context, Result, ensure};
use blockzilla_bank_client::{
    ClientError, Frame, SourceIdentity, now_ms,
    ssh_beam::{SshBeam, SshConfig},
};
use blockzilla_bank_stream_v2 as v2;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    fs::{self, File, OpenOptions},
    future::Future,
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::{
    signal::unix::{Signal, SignalKind, signal},
    time::{Interval, MissedTickBehavior},
};

const LIMIT: usize = 65536;
const WINDOW_MS: u64 = 60000;
const SAMPLES: usize = 4096;
const USAGE: &str = "blockzilla-beam --ssh-host USER@HOST --ssh-helper /remote/helper.py --job /remote/job --source-file /local/source.json --generation HEX32 --producer-generation HEX64 --state /private/state.json [--after EXACT_INITIAL_CURSOR] [--status-file /private/status.json] [--clock-file /private/clock.json] [--stop-file /private/STOP] [--max-seconds SECONDS]\nExisting state always resumes its saved complete cursor. An optional --after must match its original initial boundary. Terminal errors persist a terminal status and return exit0; transient SSH errors retry internally.";

struct Options {
    ssh: SshConfig,
    state: PathBuf,
    status: PathBuf,
    initial: Option<String>,
    clock: Option<PathBuf>,
    stop: Option<PathBuf>,
    max: Option<Duration>,
}
fn input(path: &Path, private: bool) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.nlink() == 1 && meta.len() <= LIMIT as u64,
        "unsafe bounded input"
    );
    if private {
        ensure!(
            meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
            "private input requires owned0600 mode"
        );
    }
    let mut data = Vec::new();
    file.take(LIMIT as u64 + 1).read_to_end(&mut data)?;
    ensure!(data.len() <= LIMIT, "input exceeds bound");
    Ok(data)
}
fn private_path(path: &Path) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "local paths must be absolute");
    let parent = path.parent().context("path has no parent")?;
    if !parent.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    let meta = fs::symlink_metadata(parent)?;
    ensure!(
        meta.is_dir()
            && !meta.file_type().is_symlink()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o077 == 0,
        "state parent requires owned0700 mode"
    );
    let path = parent
        .canonicalize()?
        .join(path.file_name().context("path has no file name")?);
    if let Ok(meta) = fs::symlink_metadata(&path) {
        ensure!(
            meta.is_file()
                && meta.nlink() == 1
                && meta.uid() == unsafe { libc::geteuid() }
                && meta.mode() & 0o077 == 0,
            "unsafe existing output"
        );
    }
    Ok(path)
}
fn atomic(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= LIMIT, "checkpoint/status bound exceeded");
    let mut name = path
        .file_name()
        .context("missing output filename")?
        .to_os_string();
    name.push(format!(".pending-{}-{}", std::process::id(), now_ms()));
    let temporary = path.with_file_name(name);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        File::open(path.parent().context("missing output parent")?)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
struct Store {
    path: PathBuf,
    _lock: File,
}
impl Store {
    fn open(path: &Path) -> Result<Self> {
        let path = private_path(path)?;
        let lock_path = path.with_extension("lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(lock_path)?;
        let m = lock.metadata()?;
        ensure!(
            m.is_file()
                && m.nlink() == 1
                && m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o077 == 0,
            "unsafe checkpoint lock"
        );
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "checkpoint is already in use"
        );
        Ok(Self { path, _lock: lock })
    }
    fn save(&self, state: &State) -> Result<()> {
        atomic(&self.path, state)
    }
    fn load(&self, ssh: &SshConfig, initial: Option<&str>) -> Result<State> {
        match fs::symlink_metadata(&self.path) {
            Ok(_) => {
                let state: State = serde_json::from_slice(&input(&self.path, true)?)?;
                state.validate(ssh)?;
                if let Some(initial) = initial {
                    ensure!(
                        initial == state.initial_cursor,
                        "initial boundary differs from saved bootstrap"
                    );
                }
                Ok(state)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let state = State::new(
                    ssh,
                    initial.context("--after is required for a new checkpoint")?,
                )?;
                self.save(&state)?;
                Ok(state)
            }
            Err(e) => Err(e.into()),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema: String,
    source: SourceIdentity,
    generation: String,
    producer_generation: String,
    initial_cursor: String,
    cursor: String,
    hash_chain: String,
    frames: u64,
    blocks: u64,
    controls: u64,
    bytes: u64,
    reconnects: u64,
    created_unix_ms: u64,
    last_frame_received_unix_ms: Option<u64>,
    last_block_received_unix_ms: Option<u64>,
    latest_slot: Option<u64>,
}
impl State {
    fn new(ssh: &SshConfig, after: &str) -> Result<Self> {
        ensure!(
            v2::parse_cursor(after)?.0 == ssh.source.session_id,
            "initial cursor source differs"
        );
        Ok(Self {
            schema: "blockzilla-persistent-beam-cursor-v1".into(),
            source: ssh.source.clone(),
            generation: ssh.generation.clone(),
            producer_generation: ssh.producer_generation.clone(),
            initial_cursor: after.into(),
            cursor: after.into(),
            hash_chain: v2::digest(after.as_bytes()),
            frames: 0,
            blocks: 0,
            controls: 0,
            bytes: 0,
            reconnects: 0,
            created_unix_ms: now_ms(),
            last_frame_received_unix_ms: None,
            last_block_received_unix_ms: None,
            latest_slot: None,
        })
    }
    fn validate(&self, ssh: &SshConfig) -> Result<()> {
        ensure!(
            self.schema == "blockzilla-persistent-beam-cursor-v1"
                && self.source == ssh.source
                && self.generation == ssh.generation
                && self.producer_generation == ssh.producer_generation,
            "checkpoint source or generation differs; explicit rebootstrap required"
        );
        let (a, start, _) = v2::parse_cursor(&self.initial_cursor)?;
        let (b, end, _) = v2::parse_cursor(&self.cursor)?;
        ensure!(
            a == ssh.source.session_id
                && b == a
                && end.checked_sub(start) == Some(self.frames)
                && self.blocks.checked_add(self.controls) == Some(self.frames)
                && v2::is_digest(&self.hash_chain),
            "checkpoint counters or cursor differ"
        );
        Ok(())
    }
    fn received(&self, frame: &Frame, received: u64) -> Result<Self> {
        ensure!(
            frame.source == self.source
                && frame.envelope.event.sequence
                    == v2::parse_cursor(&self.cursor)?
                        .1
                        .checked_add(1)
                        .context("sequence overflow")?,
            "receipt source or sequence differs"
        );
        let mut state = self.clone();
        state.frames = state
            .frames
            .checked_add(1)
            .context("frame counter overflow")?;
        state.bytes = state
            .bytes
            .checked_add(frame.wire.len() as u64)
            .context("byte counter overflow")?;
        if frame.envelope.event.kind == "block" {
            state.blocks = state
                .blocks
                .checked_add(1)
                .context("block counter overflow")?;
            state.latest_slot = Some(frame.envelope.event.bank.slot);
            state.last_block_received_unix_ms = Some(received);
        } else {
            state.controls = state
                .controls
                .checked_add(1)
                .context("control counter overflow")?;
        }
        state.hash_chain = v2::digest(&serde_json::to_vec(&(
            &self.hash_chain,
            &frame.sha256,
            &frame.cursor,
        ))?);
        state.cursor = frame.cursor.clone();
        state.last_frame_received_unix_ms = Some(received);
        Ok(state)
    }
}

#[derive(Clone, Deserialize)]
struct Clock {
    server_minus_client_ms: i64,
    uncertainty_ms: u64,
    sampled_at_client_unix_ms: u64,
    valid_for_ms: u64,
}
impl Clock {
    fn valid(&self, now: u64) -> bool {
        self.server_minus_client_ms.unsigned_abs() <= 86400000
            && self.uncertainty_ms <= 60000
            && (1..=3600000).contains(&self.valid_for_ms)
            && now >= self.sampled_at_client_unix_ms
            && now - self.sampled_at_client_unix_ms <= self.valid_for_ms
    }
}
struct Sample {
    at: u64,
    raw: i64,
    corrected: Option<i64>,
    uncertainty: Option<u64>,
    startup: bool,
}
struct Metrics {
    start: Instant,
    start_unix_ms: u64,
    ssh_pid: Option<u32>,
    connections: u64,
    connection_after: Option<String>,
    first_sequence_after_connect: Option<u64>,
    connection_started_ms: Option<u64>,
    start_frames: u64,
    start_blocks: u64,
    start_bytes: u64,
    samples: VecDeque<Sample>,
    clock: Option<Clock>,
    clock_error: Option<&'static str>,
    last_error: Option<String>,
    last_activity: Instant,
    stop_reason: Option<&'static str>,
}
fn statistics(values: impl Iterator<Item = i64>) -> Value {
    let mut values = values.collect::<Vec<_>>();
    if values.is_empty() {
        return Value::Null;
    }
    values.sort_unstable();
    let n = values.len();
    let rank = |p: usize| values[((n * p + 99) / 100).saturating_sub(1).min(n - 1)];
    let median = if n % 2 == 1 {
        values[n / 2] as f64
    } else {
        (values[n / 2 - 1] as f64 + values[n / 2] as f64) / 2.0
    };
    json!({"n":n,"p50_ms":median,"p95_ms":rank(95),"p99_ms":rank(99),"min_ms":values[0],"max_ms":values[n-1]})
}
impl Metrics {
    fn new(state: &State) -> Self {
        Self {
            start: Instant::now(),
            start_unix_ms: now_ms(),
            ssh_pid: None,
            connections: 0,
            connection_after: None,
            first_sequence_after_connect: None,
            connection_started_ms: None,
            start_frames: state.frames,
            start_blocks: state.blocks,
            start_bytes: state.bytes,
            samples: VecDeque::new(),
            clock: None,
            clock_error: None,
            last_error: None,
            last_activity: Instant::now(),
            stop_reason: None,
        }
    }
    fn clock(&mut self, path: Option<&Path>) {
        self.clock = None;
        self.clock_error = None;
        if let Some(path) = path {
            match input(path, false).and_then(|b| Ok(serde_json::from_slice::<Clock>(&b)?)) {
                Ok(c) if c.valid(now_ms()) => self.clock = Some(c),
                Ok(_) => self.clock_error = Some("calibration_expired_or_invalid"),
                Err(_) => self.clock_error = Some("calibration_unavailable"),
            }
        }
    }
    fn receive(&mut self, frame: &Frame, at: u64) {
        self.last_activity = Instant::now();
        self.last_error = None;
        if frame.envelope.event.kind != "block" {
            return;
        }
        let raw = at as i64 - frame.envelope.event.observed_at_unix_ms as i64;
        let clock = self.clock.as_ref().filter(|c| c.valid(at));
        self.samples.push_back(Sample {
            at,
            raw,
            corrected: clock.map(|c| raw + c.server_minus_client_ms),
            uncertainty: clock.map(|c| c.uncertainty_ms),
            startup: clock.is_some_and(|c| {
                (frame.envelope.event.observed_at_unix_ms as i128
                    - c.server_minus_client_ms as i128)
                    < (self.start_unix_ms as i128)
            }),
        });
        while self.samples.len() > SAMPLES {
            self.samples.pop_front();
        }
    }
    fn status(&mut self, opt: &Options, state: &State, phase: &str) -> Result<()> {
        let now = now_ms();
        self.clock(opt.clock.as_deref());
        while self
            .samples
            .front()
            .is_some_and(|s| now.saturating_sub(s.at) > WINDOW_MS)
        {
            self.samples.pop_front();
        }
        let seconds = self.start.elapsed().as_secs_f64().max(0.001);
        let value = json!({"schema":"blockzilla-persistent-beam-status-v1","state":phase,"source":state.source,"generation":state.generation,"producer_generation":state.producer_generation,"cursor":state.cursor,"initial_cursor":state.initial_cursor,"latest_slot":state.latest_slot,"ssh_pid":self.ssh_pid,"connections":self.connections,"connection_after":self.connection_after,"first_sequence_after_connect":self.first_sequence_after_connect,"connection_started_ms":self.connection_started_ms,"hash_chain":state.hash_chain,"frames":state.frames,"blocks":state.blocks,"controls":state.controls,"bytes":state.bytes,"reconnects":state.reconnects,"last_frame_received_unix_ms":state.last_frame_received_unix_ms,"last_block_received_unix_ms":state.last_block_received_unix_ms,"frame_age_ms":state.last_frame_received_unix_ms.map(|t|now.saturating_sub(t)),"receipt_stale":state.last_frame_received_unix_ms.is_none_or(|t|now.saturating_sub(t)>5000),"session_seconds":seconds,"session_frames_per_second":(state.frames-self.start_frames)as f64/seconds,"session_blocks_per_second":(state.blocks-self.start_blocks)as f64/seconds,"session_bytes_per_second":(state.bytes-self.start_bytes)as f64/seconds,"latency_window_ms":WINDOW_MS,"latency_sample_limit":SAMPLES,"latency_raw_clock_delta":statistics(self.samples.iter().map(|s|s.raw)),"latency_clock_corrected":statistics(self.samples.iter().filter(|s|!s.startup).filter_map(|s|s.corrected)),"startup_inflight_samples":self.samples.iter().filter(|s|s.startup).count(),"startup_latency_clock_corrected":statistics(self.samples.iter().filter(|s|s.startup).filter_map(|s|s.corrected)),"maximum_clock_uncertainty_ms":self.samples.iter().filter_map(|s|s.uncertainty).max(),"clock_calibrated":self.clock.is_some(),"clock_error":self.clock_error,"latency_time_point":"native frozen-observer timestamp to full source/sequence/object/frame-hash validated receipt; excludes replay-to-observer queue delay","raw_latency_requires_clock_calibration":true,"latency_timestamp_resolution_ms":1,"last_error":self.last_error,"stop_reason":self.stop_reason,"updated_unix_ms":now,"remote_ack_sent":false,"block_or_projection_spool":false});
        atomic(&opt.status, &value)
    }
}

struct Control {
    interrupt: Signal,
    terminate: Signal,
    tick: Interval,
}
enum Observed<T> {
    Value(T),
    Stop,
    Idle,
}
impl Control {
    fn new() -> Result<Self> {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
            tick,
        })
    }
    async fn monitor<F: Future>(
        &mut self,
        future: F,
        opt: &Options,
        state: &State,
        metrics: &mut Metrics,
        phase: &str,
        idle: bool,
    ) -> Result<Observed<F::Output>> {
        tokio::pin!(future);
        loop {
            tokio::select! {
                value=&mut future=>return Ok(Observed::Value(value)),
                _=self.interrupt.recv()=>{metrics.stop_reason=Some("interrupt");return Ok(Observed::Stop)},
                _=self.terminate.recv()=>{metrics.stop_reason=Some("terminate");return Ok(Observed::Stop)},
                _=self.tick.tick()=>{
                    if opt.stop.as_ref().is_some_and(|p|p.exists()){metrics.stop_reason=Some("stop_file");return Ok(Observed::Stop)}
                    if opt.max.is_some_and(|d|metrics.start.elapsed()>=d){metrics.stop_reason=Some("requested_duration");return Ok(Observed::Stop)}
                    metrics.status(opt,state,phase)?;
                    if idle&&metrics.last_activity.elapsed()>=Duration::from_secs(30){return Ok(Observed::Idle)}
                }
            }
        }
    }
}
fn terminal(error: &ClientError) -> &'static str {
    match error {
        ClientError::Gap { .. } => "GAP",
        ClientError::Source(_) => "SOURCE_CHANGED",
        ClientError::Authentication(_) => "AUTH_FAILED",
        _ => "FAILED",
    }
}
async fn receive(opt: Options) -> Result<()> {
    let store = Store::open(&opt.state)?;
    let mut state = store.load(&opt.ssh, opt.initial.as_deref())?;
    let mut metrics = Metrics::new(&state);
    metrics.clock(opt.clock.as_deref());
    let mut control = Control::new()?;
    let mut delay = Duration::from_millis(250);
    let result: Result<()> = async {
        loop {
            let cursor = state.cursor.clone();
            let connection = control
                .monitor(
                    SshBeam::connect(&opt.ssh, &cursor),
                    &opt,
                    &state,
                    &mut metrics,
                    "CONNECTING",
                    false,
                )
                .await?;
            let mut connection = match connection {
                Observed::Stop => return Ok(()),
                Observed::Idle => unreachable!(),
                Observed::Value(Ok(c)) => c,
                Observed::Value(Err(error)) => {
                    if !error.is_transient() {
                        metrics.last_error = Some(error.to_string());
                        metrics.status(&opt, &state, terminal(&error))?;
                        return Ok(());
                    }
                    metrics.last_error = Some(error.to_string());
                    state.reconnects = state
                        .reconnects
                        .checked_add(1)
                        .context("retry counter overflow")?;
                    store.save(&state)?;
                    if matches!(
                        control
                            .monitor(
                                tokio::time::sleep(delay),
                                &opt,
                                &state,
                                &mut metrics,
                                "RECONNECTING",
                                false
                            )
                            .await?,
                        Observed::Stop
                    ) {
                        return Ok(());
                    }
                    delay = (delay * 2).min(Duration::from_secs(5));
                    continue;
                }
            };
            metrics.last_activity = Instant::now();
            metrics.ssh_pid = connection.process_id();
            metrics.connections = metrics
                .connections
                .checked_add(1)
                .context("connection counter overflow")?;
            metrics.connection_after = Some(cursor.clone());
            metrics.first_sequence_after_connect = None;
            metrics.connection_started_ms = Some(now_ms());
            metrics.status(&opt, &state, "RUNNING")?;
            loop {
                let event = control
                    .monitor(
                        connection.next(),
                        &opt,
                        &state,
                        &mut metrics,
                        "RUNNING",
                        true,
                    )
                    .await?;
                match event {
                    Observed::Stop => {
                        connection.close().await;
                        metrics.ssh_pid = None;
                        return Ok(());
                    }
                    Observed::Idle => {
                        metrics.last_error = Some("ssh_stream_idle".into());
                        break;
                    }
                    Observed::Value(Err(error)) => {
                        if !error.is_transient() {
                            metrics.last_error = Some(error.to_string());
                            connection.close().await;
                            metrics.ssh_pid = None;
                            metrics.status(&opt, &state, terminal(&error))?;
                            return Ok(());
                        }
                        metrics.last_error = Some(error.to_string());
                        break;
                    }
                    Observed::Value(Ok(frame)) => {
                        let received = now_ms();
                        let next = state.received(&frame, received)?;
                        // The only resume boundary is the FULL local receipt.
                        // It never depends on a remote application ACK.
                        store.save(&next)?;
                        state = next;
                        metrics.receive(&frame, received);
                        if metrics.first_sequence_after_connect.is_none() {
                            metrics.first_sequence_after_connect =
                                Some(frame.envelope.event.sequence);
                        }
                        drop(frame);
                        delay = Duration::from_millis(250);
                    }
                }
            }
            connection.close().await;
            metrics.ssh_pid = None;
            state.reconnects = state
                .reconnects
                .checked_add(1)
                .context("retry counter overflow")?;
            store.save(&state)?;
            if matches!(
                control
                    .monitor(
                        tokio::time::sleep(delay),
                        &opt,
                        &state,
                        &mut metrics,
                        "RECONNECTING",
                        false
                    )
                    .await?,
                Observed::Stop
            ) {
                return Ok(());
            }
            delay = (delay * 2).min(Duration::from_secs(5));
        }
    }
    .await;
    if let Err(error) = result {
        metrics.last_error = Some(format!("local_receipt_failed: {error}"));
        metrics.status(&opt, &state, "FAILED")?;
        return Ok(());
    }
    // Terminal admission errors already wrote their terminal state. Never
    // replace that record with STOPPED, and never trigger launchd retry loops.
    if metrics.stop_reason.is_some() {
        metrics.status(&opt, &state, "STOPPED")?;
    }
    Ok(())
}

fn options(args: impl Iterator<Item = String>) -> Result<Options> {
    let mut args = args;
    let mut values = BTreeMap::new();
    while let Some(key) = args.next() {
        ensure!(key.starts_with("--"), "invalid argument");
        ensure!(
            values
                .insert(key, args.next().context("missing option value")?)
                .is_none(),
            "duplicate option"
        );
    }
    let allowed = [
        "--ssh-host",
        "--ssh-helper",
        "--job",
        "--source-file",
        "--generation",
        "--producer-generation",
        "--state",
        "--status-file",
        "--after",
        "--clock-file",
        "--stop-file",
        "--max-seconds",
    ];
    ensure!(
        values.keys().all(|k| allowed.contains(&k.as_str())),
        "unknown option"
    );
    let required = |key: &str| {
        values
            .get(key)
            .cloned()
            .with_context(|| format!("missing {key}"))
    };
    let source_path = PathBuf::from(required("--source-file")?);
    let source: SourceIdentity = serde_json::from_slice(&input(&source_path, false)?)?;
    let ssh = SshConfig {
        host: required("--ssh-host")?,
        helper: required("--ssh-helper")?,
        job: required("--job")?,
        generation: required("--generation")?,
        producer_generation: required("--producer-generation")?,
        source,
    };
    ssh.validate()?;
    let state = private_path(Path::new(&required("--state")?))?;
    let status = private_path(
        &values
            .get("--status-file")
            .map(PathBuf::from)
            .unwrap_or_else(|| state.with_extension("status.json")),
    )?;
    let clock = values.get("--clock-file").map(PathBuf::from);
    let stop = values.get("--stop-file").map(PathBuf::from);
    let paths = [
        Some(&state),
        Some(&status),
        Some(&source_path),
        clock.as_ref(),
        stop.as_ref(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    ensure!(
        paths.iter().all(|p| p.is_absolute())
            && (0..paths.len()).all(|i| (i + 1..paths.len()).all(|j| paths[i] != paths[j])),
        "local paths must be distinct and absolute"
    );
    let max = values
        .get("--max-seconds")
        .map(|s| s.parse::<u64>())
        .transpose()?;
    ensure!(
        max.is_none_or(|n| (1..=86400).contains(&n)),
        "duration must be1..86400 seconds"
    );
    Ok(Options {
        ssh,
        state,
        status,
        clock,
        stop,
        initial: values.get("--after").cloned(),
        max: max.map(Duration::from_secs),
    })
}
fn main() {
    if std::env::args().skip(1).any(|v| v == "--help") {
        println!("{USAGE}");
        return;
    }
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let status_arg = args
        .windows(2)
        .find(|p| p[0] == "--status-file")
        .map(|p| PathBuf::from(&p[1]));
    let result = (|| -> Result<()> {
        let opt = options(args.into_iter())?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(receive(opt))
    })();
    if let Err(error) = result {
        let value = json!({"schema":"blockzilla-persistent-beam-status-v1","state":"FAILED","error":format!("client_setup_failed: {error}"),"updated_unix_ms":now_ms(),"remote_ack_sent":false});
        let in_use = error
            .chain()
            .any(|cause| cause.to_string() == "checkpoint is already in use");
        if let Some(path) = status_arg
            .filter(|_| !in_use)
            .and_then(|p| private_path(&p).ok())
        {
            let _ = atomic(&path, &value);
        }
        eprintln!("{value}");
    }
    // Expected terminal faults return success so KeepAlive/SuccessfulExit=false
    // leaves the saved source/cursor for an explicit operator decision.
}

#[cfg(test)]
mod tests {
    use super::*;
    use v2::fixtures::{block, source};
    fn temporary() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let path = tempfile::tempdir().unwrap();
        fs::set_permissions(path.path(), fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    fn ssh() -> SshConfig {
        SshConfig {
            host: "ubuntu@127.0.0.1".into(),
            helper: "/helper.py".into(),
            job: "/job".into(),
            generation: "a".repeat(32),
            producer_generation: "b".repeat(64),
            source: source(),
        }
    }
    fn base() -> String {
        v2::cursor(&source().session_id, 0, "-")
    }
    #[test]
    fn checkpoint_reopens_exact_cursor_and_static_bootstrap_never_overrides_it() {
        let temp = temporary();
        let path = temp.path().join("state.json");
        let cfg = ssh();
        let store = Store::open(&path).unwrap();
        let state = store.load(&cfg, Some(&base())).unwrap();
        let frame = block(1, 9, 1, 8, 1);
        let next = state.received(&frame, 2000).unwrap();
        store.save(&next).unwrap();
        drop(store);
        let store = Store::open(&path).unwrap();
        let saved = store.load(&cfg, Some(&base())).unwrap();
        assert_eq!(saved.cursor, frame.cursor);
        assert_eq!(saved.frames, 1);
        let mut changed = cfg;
        changed.generation = "c".repeat(32);
        assert!(store.load(&changed, None).is_err());
        assert_eq!(store.load(&ssh(), None).unwrap().cursor, frame.cursor);
    }
    #[test]
    fn source_counters_lock_and_failed_receipt_cannot_advance_saved_boundary() {
        let temp = temporary();
        let store = Store::open(&temp.path().join("state.json")).unwrap();
        assert!(Store::open(&store.path).is_err());
        let cfg = ssh();
        let state = store.load(&cfg, Some(&base())).unwrap();
        let mut wrong = block(1, 9, 1, 8, 1);
        wrong.source.session_id = "other".into();
        assert!(state.received(&wrong, 2000).is_err());
        assert_eq!(store.load(&cfg, None).unwrap().cursor, base());
        let mut broken = state;
        broken.frames = 1;
        assert!(broken.validate(&cfg).is_err());
    }
    #[test]
    fn clock_sign_expiry_and_metrics_memory_are_bounded() {
        let cfg = ssh();
        let state = State::new(&cfg, &base()).unwrap();
        let mut metrics = Metrics::new(&state);
        let now = now_ms();
        metrics.clock = Some(Clock {
            server_minus_client_ms: 1000,
            uncertainty_ms: 5,
            sampled_at_client_unix_ms: now,
            valid_for_ms: 1000,
        });
        let mut frame = block(1, 9, 1, 8, 1);
        frame.envelope.event.observed_at_unix_ms = now + 900;
        metrics.receive(&frame, now);
        assert_eq!(metrics.samples.back().unwrap().raw, -900);
        assert_eq!(metrics.samples.back().unwrap().corrected, Some(100));
        assert!(!metrics.clock.as_ref().unwrap().valid(now + 1001));
        for _ in 0..5000 {
            metrics.receive(&frame, now);
        }
        assert_eq!(metrics.samples.len(), SAMPLES);
        assert_eq!(statistics([1, 2, 3, 4].into_iter())["p50_ms"], 2.5);
    }
    #[tokio::test]
    async fn interrupted_second_frame_resumes_only_after_the_first_durable_receipt() {
        use blockzilla_bank_client::ssh_beam::FrameReader;
        let temp = temporary();
        let store = Store::open(&temp.path().join("state.json")).unwrap();
        let cfg = ssh();
        let mut state = store.load(&cfg, Some(&base())).unwrap();
        let first = block(1, 9, 1, 8, 1);
        let second = block(2, 10, 2, 9, 2);
        let mut wire = first.wire.to_vec();
        wire.extend_from_slice(&second.wire[..second.wire.len() - 1]);
        let mut reader = FrameReader::new(&wire[..], source(), &state.cursor).unwrap();
        let complete = reader.next().await.unwrap();
        let next = state.received(&complete, 2000).unwrap();
        store.save(&next).unwrap();
        state = next;
        assert!(reader.next().await.unwrap_err().is_transient());
        assert_eq!(store.load(&cfg, None).unwrap().cursor, first.cursor);
        let saved = store.load(&cfg, Some(&base())).unwrap();
        let mut resumed = FrameReader::new(&second.wire[..], source(), &saved.cursor).unwrap();
        let complete = resumed.next().await.unwrap();
        let next = state.received(&complete, 2100).unwrap();
        store.save(&next).unwrap();
        assert_eq!(store.load(&cfg, None).unwrap().cursor, second.cursor);
        assert_eq!(store.load(&cfg, None).unwrap().frames, 2);
    }
    #[test]
    fn fifo_inputs_are_rejected_without_waiting_and_clock_metadata_can_be_extended() {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let temp = temporary();
        let path = temp.path().join("bad-source");
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let start = Instant::now();
        assert!(input(&path, false).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
        let now = now_ms();
        let value = json!({"server_minus_client_ms":52,"uncertainty_ms":12,"sampled_at_client_unix_ms":now,"valid_for_ms":120000,"estimated_offset_ms":51.9});
        let clock: Clock = serde_json::from_value(value).unwrap();
        assert!(clock.valid(now));
    }
}
