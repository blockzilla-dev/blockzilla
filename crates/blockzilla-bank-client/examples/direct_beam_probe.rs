//! Bounded read-only acceptance of original native frames. No ACK or Chain.
use anyhow::{Context, Result, bail, ensure};
use blockzilla_bank_client::{BankClient, ClientConfig, ClientError, now_ms};
use blockzilla_bank_stream_v2 as v2;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const MAX_STATE: u64 = 65536;
const MAX_EVENTS: u64 = 1_000_000;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema: String,
    source: v2::SourceIdentity,
    producer_generation: String,
    start_cursor: String,
    cursor: String,
    hash_chain: String,
    events: u64,
    blocks: u64,
    controls: u64,
    bytes: u64,
    objects: u64,
    reconnects: u64,
    intentional_reconnects: u64,
    reconnect_proven: bool,
    reconnect_cursor: Option<String>,
    started_ms: u64,
    updated_ms: u64,
    state: String,
}
impl State {
    fn new(source: v2::SourceIdentity, generation: String, after: String) -> Result<Self> {
        source.validate()?;
        ensure!(v2::is_digest(&generation), "invalid generation");
        ensure!(
            v2::parse_cursor(&after)?.0 == source.session_id,
            "source changed"
        );
        let hash_chain = v2::digest(&serde_json::to_vec(&(
            "direct-beam-probe-v1",
            &source,
            &generation,
            &after,
        ))?);
        Ok(Self {
            schema: "blockzilla-direct-beam-probe-v1".into(),
            source,
            producer_generation: generation,
            start_cursor: after.clone(),
            cursor: after,
            hash_chain,
            events: 0,
            blocks: 0,
            controls: 0,
            bytes: 0,
            objects: 0,
            reconnects: 0,
            intentional_reconnects: 0,
            reconnect_proven: false,
            reconnect_cursor: None,
            started_ms: now_ms(),
            updated_ms: now_ms(),
            state: "RUNNING".into(),
        })
    }
    fn validate(&self, source: &v2::SourceIdentity, generation: &str) -> Result<()> {
        ensure!(
            self.schema == "blockzilla-direct-beam-probe-v1"
                && &self.source == source
                && self.producer_generation == generation,
            "saved source/generation differs"
        );
        ensure!(
            v2::parse_cursor(&self.cursor)?.0 == source.session_id
                && v2::parse_cursor(&self.start_cursor)?.0 == source.session_id,
            "saved cursor source differs"
        );
        ensure!(
            self.events <= MAX_EVENTS
                && self.blocks.checked_add(self.controls) == Some(self.events)
                && v2::is_digest(&self.hash_chain)
                && self.started_ms <= now_ms(),
            "saved counters differ"
        );
        Ok(())
    }
    fn accept(&mut self, frame: &v2::Frame) -> Result<()> {
        ensure!(frame.source == self.source, "frame source differs");
        let old = v2::parse_cursor(&self.cursor)?.1;
        ensure!(
            v2::parse_cursor(&frame.cursor)?.0 == self.source.session_id
                && frame.envelope.event.sequence
                    == old.checked_add(1).context("sequence overflow")?
                && v2::parse_cursor(&frame.cursor)?.1 == frame.envelope.event.sequence
                && v2::parse_cursor(&frame.cursor)?.2 == frame.sha256
                && self.events < MAX_EVENTS,
            "frame sequence/digest differs"
        );
        if let Some(after) = &self.reconnect_cursor {
            ensure!(after == &self.cursor, "reconnect cursor differs");
            self.reconnect_proven = true;
            self.reconnect_cursor = None;
        }
        let kind = &frame.envelope.event.kind;
        ensure!(
            matches!(kind.as_str(), "block" | "confirmed" | "root" | "invalidate"),
            "unexpected frame kind"
        );
        let next_hash = v2::digest(&serde_json::to_vec(&(
            &self.hash_chain,
            &frame.sha256,
            &frame.cursor,
            kind,
        ))?);
        self.bytes = self
            .bytes
            .checked_add(frame.wire.len() as u64)
            .context("byte overflow")?;
        self.objects = self
            .objects
            .checked_add(frame.envelope.objects.len() as u64)
            .context("object overflow")?;
        self.events += 1;
        if kind == "block" {
            self.blocks += 1;
        } else {
            self.controls += 1;
        }
        self.hash_chain = next_hash;
        self.cursor = frame.cursor.clone();
        self.updated_ms = now_ms();
        Ok(())
    }
}
fn read(path: &Path, max: u64) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.file_type().is_file() && m.nlink() == 1 && m.len() <= max,
        "unsafe bounded input"
    );
    let data = fs::read(path)?;
    ensure!(data.len() as u64 <= max, "input bound");
    Ok(data)
}
fn save(path: &Path, value: &impl Serialize) -> Result<()> {
    let data = serde_json::to_vec(value)?;
    ensure!(data.len() as u64 <= MAX_STATE, "state bound");
    let temporary = path.with_extension(format!("pending-{}-{}", std::process::id(), now_ms()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&data)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, path)?;
    fs::File::open(path.parent().context("state parent missing")?)?.sync_all()?;
    Ok(())
}
fn args() -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let mut a = std::env::args().skip(1);
    while let Some(key) = a.next() {
        ensure!(key.starts_with("--"), "invalid argument");
        ensure!(
            out.insert(key, a.next().context("missing value")?)
                .is_none(),
            "duplicate argument"
        );
    }
    let allowed = [
        "--socket",
        "--token-file",
        "--source-file",
        "--generation",
        "--state",
        "--after",
        "--max-seconds",
        "--stop-file",
        "--check-expired",
    ];
    ensure!(
        out.keys().all(|k| allowed.contains(&k.as_str())),
        "unknown argument"
    );
    Ok(out)
}
fn error_kind(error: &ClientError) -> &'static str {
    match error {
        ClientError::Gap { .. } => "GAP",
        ClientError::Source(_) => "SOURCE",
        ClientError::Authentication(_) => "AUTH",
        ClientError::Digest(_) => "DIGEST",
        ClientError::Protocol(_) => "PROTOCOL",
        _ => "IO",
    }
}
async fn consume(
    client: &BankClient,
    state: &mut State,
    path: &Path,
    stop: &Path,
    max_seconds: u64,
) -> Result<()> {
    let mut last_save = Instant::now();
    let deadline = state
        .started_ms
        .checked_add(max_seconds * 1000)
        .context("deadline overflow")?;
    loop {
        if stop.try_exists()? {
            state.state = "STOPPED".into();
            return Ok(());
        }
        if now_ms() >= deadline {
            state.state = "DEADLINE".into();
            bail!("acceptance deadline reached");
        }
        let after = state.cursor.clone();
        let mut stream =
            match tokio::time::timeout(Duration::from_secs(3), client.beam(&after)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) if !error.is_transient() => {
                    state.state = error_kind(&error).into();
                    bail!("native beam admission failed");
                }
                _ => {
                    state.reconnects += 1;
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    continue;
                }
            };
        loop {
            if stop.try_exists()? {
                state.state = "STOPPED".into();
                return Ok(());
            }
            if now_ms() >= deadline {
                state.state = "DEADLINE".into();
                bail!("acceptance deadline reached");
            }
            match tokio::time::timeout(Duration::from_millis(500), stream.next()).await {
                Err(_) => continue,
                Ok(Ok(frame)) => {
                    state.accept(&frame)?;
                    ensure!(stream.cursor() == state.cursor, "transport cursor differs");
                    drop(frame);
                }
                Ok(Err(error)) if error.is_transient() => {
                    state.reconnects += 1;
                    break;
                }
                Ok(Err(error)) => {
                    state.state = error_kind(&error).into();
                    bail!("native frame admission failed");
                }
            }
            if state.blocks >= 256 && state.intentional_reconnects == 0 {
                state.intentional_reconnects = 1;
                state.reconnects += 1;
                state.reconnect_cursor = Some(state.cursor.clone());
                save(path, state)?;
                last_save = Instant::now();
                break;
            }
            if last_save.elapsed() >= Duration::from_millis(500) {
                save(path, state)?;
                last_save = Instant::now();
            }
        }
    }
}
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let a = args()?;
    let required = |key: &str| {
        a.get(key)
            .map(String::as_str)
            .with_context(|| format!("missing {key}"))
    };
    let source: v2::SourceIdentity =
        serde_json::from_slice(&read(Path::new(required("--source-file")?), MAX_STATE)?)?;
    source.validate()?;
    let token_path = Path::new(required("--token-file")?);
    ensure!(
        fs::symlink_metadata(token_path)?.mode() & 0o077 == 0,
        "unsafe token mode"
    );
    let token = String::from_utf8(read(token_path, 4096)?)?
        .trim()
        .to_owned();
    ensure!(
        (32..=256).contains(&token.len()) && token.bytes().all(|c| (33..127).contains(&c)),
        "invalid token"
    );
    let mut config = ClientConfig::new("http://localhost/", token, source.clone());
    config.retry.max_retries = 0;
    let client = BankClient::new_unix(config, PathBuf::from(required("--socket")?))?;
    let path = Path::new(required("--state")?);
    if let Some(after) = a.get("--check-expired") {
        let result = tokio::time::timeout(Duration::from_secs(10), client.beam(after)).await?;
        match result {
            Err(ClientError::Gap {
                reason,
                head: Some(head),
            }) if reason == "replay_unavailable" => {
                ensure!(
                    v2::parse_cursor(head.earliest_after.as_deref().context("missing floor")?)?.1
                        > v2::parse_cursor(after)?.1,
                    "cursor is not below floor"
                );
                save(
                    path,
                    &serde_json::json!({"schema":"blockzilla-beam-expired-check-v1","state":"PASS","http_status":410,"source":source,"requested_after":after,"floor":head.earliest_after,"at_ms":now_ms(),"ack_sent":false}),
                )?;
                return Ok(());
            }
            _ => bail!("expired cursor was not rejected with 410"),
        }
    }
    let generation = required("--generation")?;
    let mut state = if path.try_exists()? {
        let s: State = serde_json::from_slice(&read(path, MAX_STATE)?)?;
        s.validate(&source, generation)?;
        ensure!(
            s.cursor == required("--after")?,
            "resume differs from saved cursor"
        );
        s
    } else {
        State::new(source, generation.to_owned(), required("--after")?.into())?
    };
    let seconds: u64 = a
        .get("--max-seconds")
        .map_or(Ok(1800), |v| v.parse())
        .context("invalid duration")?;
    ensure!((1..=1800).contains(&seconds), "duration bound");
    let stop = Path::new(required("--stop-file")?);
    ensure!(!stop.try_exists()?, "stop file already exists");
    state.state = "RUNNING".into();
    save(path, &state)?;
    let result = consume(&client, &mut state, path, stop, seconds).await;
    state.updated_ms = now_ms();
    if result.is_err() && state.state == "RUNNING" {
        state.state = "FAILED".into();
    }
    save(path, &state)?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use v2::fixtures::*;
    #[test]
    fn original_frames_count_blocks_controls_and_resume_hash_chain_exactly() {
        let src = source();
        let mut state = State::new(
            src.clone(),
            "a".repeat(64),
            v2::cursor(&src.session_id, 0, "-"),
        )
        .unwrap();
        let block = block(1, 9, 1, 8, 1);
        state.accept(&block).unwrap();
        let first = state.hash_chain.clone();
        let mut resumed: State =
            serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        resumed.validate(&src, &"a".repeat(64)).unwrap();
        resumed.reconnect_cursor = Some(resumed.cursor.clone());
        resumed
            .accept(&control(&block, 2, "confirmed", 1000))
            .unwrap();
        assert_eq!(
            (resumed.blocks, resumed.controls, resumed.events),
            (1, 1, 2)
        );
        assert!(resumed.reconnect_proven);
        assert_ne!(resumed.hash_chain, first);
        assert!(
            !serde_json::to_string(&resumed)
                .unwrap()
                .contains("archive-v2")
        );
    }
    #[test]
    fn source_gap_and_wrong_saved_generation_fail_without_advancing_cursor() {
        let src = source();
        let mut state = State::new(
            src.clone(),
            "a".repeat(64),
            v2::cursor(&src.session_id, 0, "-"),
        )
        .unwrap();
        assert!(state.accept(&block(2, 9, 1, 8, 1)).is_err());
        assert_eq!(state.events, 0);
        let mut wrong = block(1, 9, 1, 8, 1);
        wrong.source.session_id = "other".into();
        assert!(state.accept(&wrong).is_err());
        assert!(state.validate(&src, &"b".repeat(64)).is_err());
        assert_eq!(state.cursor, v2::cursor(&src.session_id, 0, "-"));
    }
    #[test]
    fn durable_state_is_small_and_has_matching_cursor_counters_and_hash() {
        let temp = tempfile::tempdir().unwrap();
        let src = source();
        let mut state = State::new(
            src.clone(),
            "a".repeat(64),
            v2::cursor(&src.session_id, 0, "-"),
        )
        .unwrap();
        state.accept(&block(1, 9, 1, 8, 1)).unwrap();
        let path = temp.path().join("state.json");
        save(&path, &state).unwrap();
        let saved: State = serde_json::from_slice(&read(&path, MAX_STATE).unwrap()).unwrap();
        assert_eq!(saved.cursor, state.cursor);
        assert_eq!(saved.events, 1);
        assert_eq!(saved.hash_chain, state.hash_chain);
        assert!(fs::metadata(path).unwrap().len() < 4096);
    }
}
