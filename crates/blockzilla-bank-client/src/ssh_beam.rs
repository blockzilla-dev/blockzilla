//! Strict original-frame transport through the installed private SSH gateway.
use crate::{ClientError, Frame, Result, SourceIdentity, admission, protocol};
use blockzilla_bank_stream_v2 as v2;
use serde_json::Value;
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader},
    process::{Child, ChildStdout, Command},
    sync::Semaphore,
    task::JoinHandle,
};

const FINALIZED_READ_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_FINALIZED_PATH_BLOCKS: usize = 1024;
pub const MAX_FINALIZED_PATH_BYTES: usize = 192 * 1024 * 1024;
pub const MAX_RECOVERY_PLAN_EVENTS: usize = 128;
pub const MAX_RECOVERY_PLAN_BYTES: usize = 4 * 1024 * 1024;
static FINALIZED_READS: Semaphore = Semaphore::const_new(2);
#[cfg(test)]
#[path = "ssh_finalized_tests.rs"]
mod finalized_tests;
#[cfg(test)]
#[path = "ssh_recovery_tests.rs"]
mod recovery_tests;

/// A sampled rolling native cursor window. It is not an admitted epoch or a
/// skipped-slot map; exact finalized lookups can still become unavailable.
#[derive(Clone, Debug)]
pub struct RetainedAvailability {
    pub head: v2::Head,
    pub runtime_generation: String,
    pub producer_generation: String,
    pub complete_epoch_coverage: bool,
}

#[derive(Clone)]
pub struct SshConfig {
    pub host: String,
    pub helper: String,
    pub job: String,
    pub generation: String,
    pub producer_generation: String,
    pub source: SourceIdentity,
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn absolute(value: &str) -> bool {
    !value.chars().any(char::is_control)
        && Path::new(value).is_absolute()
        && Path::new(value).components().all(|c| {
            matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
impl SshConfig {
    pub fn validate(&self) -> Result<()> {
        if self.host.is_empty()
            || self.host.len() > 255
            || self.host.starts_with('-')
            || !self
                .host
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.@:-[]".contains(&c))
            || !absolute(&self.helper)
            || !absolute(&self.job)
            || !hex(&self.generation, 32)
            || !v2::is_digest(&self.producer_generation)
        {
            return Err(ClientError::Configuration("invalid_ssh_source_or_paths"));
        }
        self.source.validate().map_err(admission)
    }
    pub fn remote_command(&self, after: &str) -> Result<String> {
        self.validate()?;
        if v2::parse_cursor(after).map_err(admission)?.0 != self.source.session_id {
            return Err(ClientError::Source("source_changed".into()));
        }
        let source =
            serde_json::to_string(&self.source).map_err(|_| protocol("source_encoding_failed"))?;
        Ok([
            "/usr/bin/python3",
            "-u",
            "-B",
            &self.helper,
            "--job",
            &self.job,
            "--mode",
            "stream",
            "--after",
            after,
            "--generation",
            &self.generation,
            "--source-json",
            &source,
        ]
        .into_iter()
        .map(quote)
        .collect::<Vec<_>>()
        .join(" "))
    }
    fn read_command(&self, mode: &str, digest: Option<&str>) -> Result<String> {
        self.validate()?;
        if let Some(digest) = digest {
            if !v2::is_digest(digest) {
                return Err(protocol("invalid_frame_digest"));
            }
        }
        let source =
            serde_json::to_string(&self.source).map_err(|_| protocol("source_encoding_failed"))?;
        let mut args = vec![
            "/usr/bin/python3",
            "-u",
            "-B",
            &self.helper,
            "--job",
            &self.job,
            "--mode",
            mode,
            "--generation",
            &self.generation,
            "--source-json",
            &source,
        ];
        if let Some(digest) = digest {
            args.extend(["--digest", digest]);
        }
        Ok(args.into_iter().map(quote).collect::<Vec<_>>().join(" "))
    }
    /// Read pinned factual head metadata. This never chooses a resume cursor.
    pub async fn head(&self) -> Result<v2::Head> {
        let base = v2::cursor(&self.source.session_id, 0, "-");
        let (mut connection, header) =
            SshBeam::open(self, self.read_command("head", None)?, &base).await?;
        let result = (|| {
            admit_common(&header, self)?;
            let head: v2::Head = serde_json::from_value(header["head"].clone())
                .map_err(|_| protocol("invalid_ssh_head"))?;
            head.validate(&self.source, crate::now_ms(), v2::DEFAULT_MAX_LAG_MS)
                .map_err(admission)?;
            if head.status == "failed" {
                return Err(ClientError::Source("source_failed".into()));
            }
            Ok(head)
        })();
        match result {
            Ok(head) => {
                connection.finish_finite().await?;
                Ok(head)
            }
            Err(error) => {
                connection.close().await;
                Err(error)
            }
        }
    }
    /// Fetch exactly one original immutable dependency. It has no projection,
    /// ACK or application effect, and does not move a stream's cursor.
    pub async fn fetch(&self, digest: &str) -> Result<Frame> {
        let base = v2::cursor(&self.source.session_id, 0, "-");
        let (mut connection, header) =
            SshBeam::open(self, self.read_command("frame", Some(digest))?, &base).await?;
        let result = async {
            admit_common(&header, self)?;
            if header["frame_sha256"] != digest
                || header["content_type"] != "application/vnd.blockzilla.stream.v2"
            {
                return Err(protocol("ssh_frame_header_changed"));
            }
            let expected = header["frame_bytes"]
                .as_u64()
                .filter(|n| (17..=v2::MAX_FRAME as u64).contains(n))
                .ok_or_else(|| protocol("invalid_ssh_frame_size"))?;
            let mut bytes = Vec::new();
            tokio::time::timeout(
                Duration::from_secs(20),
                (&mut connection.frames.input)
                    .take(expected + 1)
                    .read_to_end(&mut bytes),
            )
            .await
            .map_err(|_| ClientError::Transient("ssh_frame_read_timeout".into()))?
            .map_err(|_| ClientError::Transient("ssh_frame_io_failed".into()))?;
            if (bytes.len() as u64) < expected {
                return Err(ClientError::Transient("ssh_frame_interrupted".into()));
            }
            if bytes.len() as u64 != expected {
                return Err(protocol("ssh_frame_size_changed"));
            }
            admit_finite_frame(bytes, self, digest)
        }
        .await;
        match result {
            Ok(frame) => {
                connection.finish_finite().await?;
                Ok(frame)
            }
            Err(error) => {
                connection.close().await;
                Err(error)
            }
        }
    }

    /// Sample the existing pinned head without choosing a new resume boundary.
    pub async fn retained_availability(&self) -> Result<RetainedAvailability> {
        tokio::time::timeout(FINALIZED_READ_TIMEOUT, async {
            let _permit = FINALIZED_READS
                .acquire()
                .await
                .map_err(|_| protocol("ssh_recovery_closed"))?;
            Ok(RetainedAvailability {
                head: self.head().await?,
                runtime_generation: self.generation.clone(),
                producer_generation: self.producer_generation.clone(),
                complete_epoch_coverage: false,
            })
        })
        .await
        .map_err(|_| ClientError::Transient("ssh_recovery_timeout".into()))?
    }

    fn recovery_plan_command(&self, after: &str, until: &str, max_events: usize) -> Result<String> {
        let (session, first, _) = v2::parse_cursor(after).map_err(admission)?;
        let (target_session, last, _) = v2::parse_cursor(until).map_err(admission)?;
        if session != self.source.session_id || target_session != session {
            return Err(ClientError::Source("recovery_source_changed".into()));
        }
        if first > last
            || (first == last && after != until)
            || !(1..=MAX_RECOVERY_PLAN_EVENTS).contains(&max_events)
        {
            return Err(protocol("invalid_recovery_plan_bounds"));
        }
        Ok(format!(
            "{} {}",
            self.read_command("recovery-plan", None)?,
            [
                "--after",
                after,
                "--until",
                until,
                "--max-events",
                &max_events.to_string(),
            ]
            .into_iter()
            .map(quote)
            .collect::<Vec<_>>()
            .join(" ")
        ))
    }

    /// Read one finite page from a fixed native cursor window. This downloads
    /// metadata and original small controls, never block payloads. Admission
    /// requires a clean helper EOF and exit; no application cursor is moved.
    pub async fn recovery_plan(
        &self,
        after: &str,
        until: &str,
        max_events: usize,
    ) -> Result<Vec<crate::RecoveryEntry>> {
        let remote = self.recovery_plan_command(after, until, max_events)?;
        tokio::time::timeout(FINALIZED_READ_TIMEOUT, async {
            let _permit = FINALIZED_READS
                .acquire()
                .await
                .map_err(|_| protocol("ssh_recovery_closed"))?;
            let (mut connection, header) = SshBeam::open(self, remote, after).await?;
            let result =
                read_recovery_plan(&mut connection, &header, self, after, until, max_events).await;
            match result {
                Ok(entries) => {
                    connection.finish_finite().await?;
                    Ok(entries)
                }
                Err(error) => {
                    connection.close().await;
                    Err(error)
                }
            }
        })
        .await
        .map_err(|_| ClientError::Transient("ssh_recovery_timeout".into()))?
    }

    fn finalized_command(&self, id: &v2::finalized::BlockId) -> Result<String> {
        // BlockId fields are public, so check the bound even for constructed IDs.
        let block_id = id.to_string();
        block_id
            .parse::<v2::finalized::BlockId>()
            .map_err(admission)?;
        Ok(format!(
            "{} {} {}",
            self.read_command("finalized-block", None)?,
            quote("--block-id"),
            quote(&block_id)
        ))
    }

    /// Read an exact locally finalized original payload. Finality is admitted
    /// from the pinned helper's checked native-origin response header. The
    /// original processed payload event is not rewritten into a synthetic root.
    /// This read has no stream cursor, ACK, or application side effect.
    pub async fn fetch_finalized(&self, id: &v2::finalized::BlockId) -> Result<Frame> {
        let remote = self.finalized_command(id)?;
        tokio::time::timeout(FINALIZED_READ_TIMEOUT, async {
            let _permit = FINALIZED_READS
                .acquire()
                .await
                .map_err(|_| protocol("ssh_recovery_closed"))?;
            let base = v2::cursor(&self.source.session_id, 0, "-");
            let (mut connection, header) = SshBeam::open(self, remote, &base).await?;
            let result = read_finalized(&mut connection, &header, self, id).await;
            match result {
                Ok(frame) => {
                    connection.finish_finite().await?;
                    Ok(frame)
                }
                Err(error) => {
                    connection.close().await;
                    Err(error)
                }
            }
        })
        .await
        .map_err(|_| ClientError::Transient("ssh_recovery_timeout".into()))?
    }

    fn finalized_path_command(
        &self,
        target: &v2::finalized::BlockId,
        anchor: &v2::finalized::BlockId,
        max_blocks: usize,
        max_wire_bytes: usize,
    ) -> Result<String> {
        let target = target.to_string();
        let anchor = anchor.to_string();
        let target_id = target
            .parse::<v2::finalized::BlockId>()
            .map_err(admission)?;
        let anchor_id = anchor
            .parse::<v2::finalized::BlockId>()
            .map_err(admission)?;
        if target_id.slot <= anchor_id.slot
            || !(1..=MAX_FINALIZED_PATH_BLOCKS).contains(&max_blocks)
            || !(17..=MAX_FINALIZED_PATH_BYTES).contains(&max_wire_bytes)
        {
            return Err(protocol("invalid_finalized_path_bounds"));
        }
        let blocks = max_blocks.to_string();
        let bytes = max_wire_bytes.to_string();
        Ok(format!(
            "{} {}",
            self.read_command("finalized-path", None)?,
            [
                "--block-id",
                &target,
                "--anchor-id",
                &anchor,
                "--max-blocks",
                &blocks,
                "--max-wire-bytes",
                &bytes
            ]
            .into_iter()
            .map(quote)
            .collect::<Vec<_>>()
            .join(" ")
        ))
    }

    /// Return original finalized payloads in target-to-anchor order, excluding
    /// the already-applied anchor. Every parent link and native response digest
    /// is checked. Partial paths are discarded on any gap, limit, or helper error.
    pub async fn fetch_finalized_path(
        &self,
        target: &v2::finalized::BlockId,
        anchor: &v2::finalized::BlockId,
        max_blocks: usize,
        max_wire_bytes: usize,
    ) -> Result<Vec<Frame>> {
        let remote = self.finalized_path_command(target, anchor, max_blocks, max_wire_bytes)?;
        tokio::time::timeout(FINALIZED_READ_TIMEOUT, async {
            let _permit = FINALIZED_READS
                .acquire()
                .await
                .map_err(|_| protocol("ssh_recovery_closed"))?;
            let base = v2::cursor(&self.source.session_id, 0, "-");
            let (mut connection, header) = SshBeam::open(self, remote, &base).await?;
            let result = read_finalized_path(
                &mut connection,
                &header,
                self,
                target,
                anchor,
                max_blocks,
                max_wire_bytes,
            )
            .await;
            match result {
                Ok(frames) => {
                    connection.finish_finite().await?;
                    Ok(frames)
                }
                Err(error) => {
                    connection.close().await;
                    Err(error)
                }
            }
        })
        .await
        .map_err(|_| ClientError::Transient("ssh_recovery_timeout".into()))?
    }
}

async fn read_finalized(
    connection: &mut SshBeam,
    header: &Value,
    config: &SshConfig,
    id: &v2::finalized::BlockId,
) -> Result<Frame> {
    admit_recovery_status(header, config)?;
    if header["block_id"] != id.to_string()
        || header["commitment"] != "finalized"
        || header["content_type"] != "application/vnd.blockzilla.stream.v2"
        || header["retention"] != "rolling-native-only"
        || header["complete_epoch_coverage"] != false
    {
        return Err(protocol("ssh_finalized_header_changed"));
    }
    let digest = header["frame_sha256"]
        .as_str()
        .filter(|value| v2::is_digest(value))
        .ok_or_else(|| protocol("invalid_ssh_frame_digest"))?;
    let expected = header["frame_bytes"]
        .as_u64()
        .filter(|size| (17..=v2::MAX_FRAME as u64).contains(size))
        .ok_or_else(|| protocol("invalid_ssh_frame_size"))?;
    let mut bytes = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(20),
        (&mut connection.frames.input)
            .take(expected + 1)
            .read_to_end(&mut bytes),
    )
    .await
    .map_err(|_| ClientError::Transient("ssh_frame_read_timeout".into()))?
    .map_err(|_| ClientError::Transient("ssh_frame_io_failed".into()))?;
    if (bytes.len() as u64) < expected {
        return Err(ClientError::Transient("ssh_frame_interrupted".into()));
    }
    if bytes.len() as u64 != expected {
        return Err(protocol("ssh_frame_size_changed"));
    }
    let frame = admit_finite_frame(bytes, config, digest)?;
    if frame.envelope.event.kind != "block"
        || v2::finalized::BlockId::from(&frame.envelope.event.bank) != *id
    {
        return Err(protocol("ssh_finalized_block_changed"));
    }
    Ok(frame)
}

fn admit_recovery_status(header: &Value, config: &SshConfig) -> Result<()> {
    if let Err(error) = admit_common(header, config) {
        return match error {
            ClientError::Gap { .. } => {
                let head = if header["head"].is_null() {
                    None
                } else {
                    let head: v2::Head = serde_json::from_value(header["head"].clone())
                        .map_err(|_| protocol("invalid_ssh_head"))?;
                    head.validate(&config.source, crate::now_ms(), v2::DEFAULT_MAX_LAG_MS)
                        .map_err(admission)?;
                    Some(Box::new(head))
                };
                Err(ClientError::Gap {
                    reason: "finalized_block_unavailable".into(),
                    head,
                })
            }
            other => Err(other),
        };
    }
    Ok(())
}

async fn read_finalized_path(
    connection: &mut SshBeam,
    header: &Value,
    config: &SshConfig,
    target: &v2::finalized::BlockId,
    anchor: &v2::finalized::BlockId,
    max_blocks: usize,
    max_wire_bytes: usize,
) -> Result<Vec<Frame>> {
    admit_recovery_status(header, config)?;
    if header["target_id"] != target.to_string()
        || header["anchor_id"] != anchor.to_string()
        || header["max_blocks"] != max_blocks
        || header["max_wire_bytes"] != max_wire_bytes
        || header["framing"] != "sha256-raw32+bzstrm01"
        || header["commitment"] != "finalized"
        || header["content_type"] != "application/vnd.blockzilla.finalized-path.v1"
        || header["retention"] != "rolling-native-only"
        || header["complete_epoch_coverage"] != false
    {
        return Err(protocol("ssh_finalized_path_header_changed"));
    }
    let mut frames = Vec::new();
    let mut expected = *target;
    let mut total = 0usize;
    while expected != *anchor {
        if frames.len() >= max_blocks || expected.slot <= anchor.slot {
            return Err(ClientError::Gap {
                reason: "finalized_anchor_not_reached".into(),
                head: None,
            });
        }
        let mut digest = [0u8; 32];
        let n = connection
            .frames
            .input
            .read(&mut digest[..1])
            .await
            .map_err(|_| ClientError::Transient("ssh_frame_io_failed".into()))?;
        if n == 0 {
            return Err(ClientError::Gap {
                reason: "finalized_path_incomplete".into(),
                head: None,
            });
        }
        connection
            .frames
            .input
            .read_exact(&mut digest[1..])
            .await
            .map_err(|_| ClientError::Transient("ssh_frame_interrupted".into()))?;
        let mut header = [0u8; 16];
        connection
            .frames
            .input
            .read_exact(&mut header)
            .await
            .map_err(|_| ClientError::Transient("ssh_frame_interrupted".into()))?;
        let length = v2::frame_length(&header).map_err(admission)?;
        if length > max_wire_bytes.saturating_sub(total) {
            return Err(protocol("finalized_path_wire_limit"));
        }
        let mut bytes = Vec::with_capacity(length);
        bytes.extend_from_slice(&header);
        bytes.resize(length, 0);
        connection
            .frames
            .input
            .read_exact(&mut bytes[16..])
            .await
            .map_err(|_| ClientError::Transient("ssh_frame_interrupted".into()))?;
        let hex = b"0123456789abcdef";
        let digest = String::from_utf8(
            digest
                .iter()
                .flat_map(|byte| [hex[(byte >> 4) as usize], hex[(byte & 15) as usize]])
                .collect(),
        )
        .unwrap();
        let frame = admit_finite_frame(bytes, config, &digest)?;
        if frame.envelope.event.kind != "block"
            || v2::finalized::BlockId::from(&frame.envelope.event.bank) != expected
        {
            return Err(protocol("ssh_finalized_path_block_changed"));
        }
        let bank = &frame.envelope.event.bank;
        expected = v2::finalized::BlockId {
            slot: bank.parent_slot,
            blockhash: bank.parent_blockhash,
        };
        total += frame.wire.len();
        frames.push(frame);
    }
    Ok(frames)
}

pub struct SshBeam {
    process: Child,
    frames: FrameReader<BufReader<ChildStdout>>,
    stderr: JoinHandle<Vec<u8>>,
}
impl Drop for SshBeam {
    fn drop(&mut self) {
        self.stderr.abort();
        let _ = self.process.start_kill();
    }
}
impl SshBeam {
    pub async fn connect(config: &SshConfig, after: &str) -> Result<Self> {
        let remote = config.remote_command(after)?;
        let (mut connection, header) = Self::open(config, remote, after).await?;
        if let Err(error) = admit_status(&header, config, after) {
            connection.close().await;
            return Err(error);
        }
        Ok(connection)
    }
    async fn open(config: &SshConfig, remote: String, after: &str) -> Result<(Self, Value)> {
        let mut command = Command::new("/usr/bin/ssh");
        #[cfg(target_os = "macos")]
        command.args(["-o", "UseKeychain=yes"]);
        let mut process = command
            .args([
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ConnectTimeout=12",
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ServerAliveCountMax=3",
                &config.host,
                &remote,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| ClientError::Transient("ssh_spawn_failed".into()))?;
        let stdout = process
            .stdout
            .take()
            .ok_or_else(|| protocol("ssh_stdout_missing"))?;
        let mut errors = process
            .stderr
            .take()
            .ok_or_else(|| protocol("ssh_stderr_missing"))?;
        let stderr = tokio::spawn(async move {
            let mut saved = Vec::new();
            let mut bytes = [0; 1024];
            while let Ok(n) = errors.read(&mut bytes).await {
                if n == 0 {
                    break;
                }
                saved.extend_from_slice(&bytes[..n.min(4096usize.saturating_sub(saved.len()))]);
            }
            saved
        });
        let mut connection = Self {
            process,
            frames: FrameReader::new(BufReader::new(stdout), config.source.clone(), after)?,
            stderr,
        };
        let header = tokio::time::timeout(
            Duration::from_secs(20),
            status_line(&mut connection.frames.input),
        )
        .await;
        let header = match header {
            Ok(Ok(header)) => header,
            Ok(Err(error)) if !error.is_transient() => {
                connection.close().await;
                return Err(error);
            }
            _ => {
                let detail = connection.close().await;
                let detail = String::from_utf8_lossy(&detail);
                return Err(if detail.contains("Permission denied") {
                    ClientError::Authentication(401)
                } else if detail.contains("Host key verification failed")
                    || detail.contains("REMOTE HOST IDENTIFICATION HAS CHANGED")
                {
                    ClientError::Configuration("ssh_host_key_rejected")
                } else {
                    ClientError::Transient("ssh_status_unavailable".into())
                });
            }
        };
        Ok((connection, header))
    }
    pub async fn next(&mut self) -> Result<Frame> {
        self.frames.next().await
    }
    pub fn cursor(&self) -> &str {
        &self.frames.cursor
    }
    pub fn process_id(&self) -> Option<u32> {
        self.process.id()
    }
    /// A finite read is valid only after clean EOF and successful helper exit.
    /// A checked frame alone cannot certify the helper's upstream checks.
    async fn finish_finite(&mut self) -> Result<()> {
        let completed = tokio::time::timeout(Duration::from_secs(3), async {
            let mut extra = [0; 1];
            if self
                .frames
                .input
                .read(&mut extra)
                .await
                .map_err(|_| ClientError::Transient("ssh_finite_io_failed".into()))?
                != 0
            {
                return Err(protocol("ssh_finite_trailing_bytes"));
            }
            let status = self
                .process
                .wait()
                .await
                .map_err(|_| ClientError::Transient("ssh_finite_wait_failed".into()))?;
            if !status.success() {
                return Err(ClientError::Transient("ssh_finite_exit_failed".into()));
            }
            Ok(())
        })
        .await
        .unwrap_or_else(|_| Err(ClientError::Transient("ssh_finite_exit_timeout".into())));
        if completed.is_err() {
            self.close().await;
        }
        completed
    }
    pub async fn close(&mut self) -> Vec<u8> {
        let _ = self.process.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(3), self.process.wait()).await;
        match tokio::time::timeout(Duration::from_secs(1), &mut self.stderr).await {
            Ok(Ok(bytes)) => bytes,
            _ => Vec::new(),
        }
    }
}

async fn read_recovery_plan(
    connection: &mut SshBeam,
    header: &Value,
    config: &SshConfig,
    after: &str,
    until: &str,
    max_events: usize,
) -> Result<Vec<crate::RecoveryEntry>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Entry {
        cursor: String,
        sha256: String,
        event: v2::BankEvent,
        source: SourceIdentity,
        control_wire_base64: Option<String>,
    }
    admit_common(header, config)?;
    // Also admit public callers' bounds before allocating the plan body.
    config.recovery_plan_command(after, until, max_events)?;
    let count = header["entry_count"]
        .as_u64()
        .filter(|count| *count <= max_events as u64)
        .ok_or_else(|| protocol("invalid_recovery_plan_count"))? as usize;
    if header["start_cursor"] != after
        || header["until_cursor"] != until
        || header["framing"] != "recovery-plan-ndjson-v1"
        || header["content_type"] != "application/vnd.blockzilla.recovery-plan.v1+ndjson"
        || (count == 0 && after != until)
    {
        return Err(protocol("recovery_plan_headers_changed"));
    }
    // Reserve the maximum header line from the total response budget. This
    // conservative bound also covers whitespace in the received header.
    let limit = MAX_RECOVERY_PLAN_BYTES - v2::MAX_META;
    let mut bytes = Vec::new();
    (&mut connection.frames.input)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| ClientError::Transient("ssh_recovery_plan_interrupted".into()))?;
    if bytes.len() > limit {
        return Err(protocol("recovery_plan_too_large"));
    }
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err(ClientError::Transient(
            "ssh_recovery_plan_interrupted".into(),
        ));
    }
    let until_sequence = v2::parse_cursor(until).map_err(admission)?.1;
    let mut entries = Vec::with_capacity(count);
    let mut previous = after.to_owned();
    for raw_line in bytes.split_inclusive(|byte| *byte == b'\n') {
        let line = raw_line.strip_suffix(b"\n").unwrap_or(raw_line);
        if line.len() + 1 > v2::MAX_META || entries.len() >= count {
            return Err(protocol("recovery_plan_entry_bounds_changed"));
        }
        let entry: Entry =
            serde_json::from_slice(line).map_err(|_| protocol("recovery_plan_entry_invalid"))?;
        let notice = crate::RecoveryNotice {
            cursor: entry.cursor,
            sha256: entry.sha256,
            event: entry.event,
            source: entry.source,
        };
        notice.validate(&config.source, &previous)?;
        if notice.event.sequence > until_sequence
            || (notice.event.sequence == until_sequence && notice.cursor != until)
        {
            return Err(protocol("recovery_plan_target_changed"));
        }
        let control = if notice.event.kind == "block" {
            if entry.control_wire_base64.is_some() {
                return Err(protocol("recovery_plan_contains_block_copy"));
            }
            None
        } else {
            let encoded = entry
                .control_wire_base64
                .ok_or_else(|| protocol("recovery_plan_control_missing"))?;
            let wire = STANDARD
                .decode(&encoded)
                .map_err(|_| protocol("recovery_plan_control_encoding"))?;
            if wire.len() > v2::MAX_META || STANDARD.encode(&wire) != encoded {
                return Err(protocol("recovery_plan_control_encoding"));
            }
            let frame = v2::decode(wire.into()).map_err(admission)?;
            notice.validate_frame(&frame)?;
            Some(frame)
        };
        previous = notice.cursor.clone();
        entries.push(crate::RecoveryEntry { notice, control });
    }
    if entries.len() < count {
        return Err(ClientError::Transient(
            "ssh_recovery_plan_interrupted".into(),
        ));
    }
    if header["end_cursor"] != previous {
        return Err(protocol("recovery_plan_end_changed"));
    }
    Ok(entries)
}

async fn status_line(input: &mut (impl AsyncBufRead + Unpin)) -> Result<Value> {
    let mut bytes = Vec::new();
    loop {
        let available = input
            .fill_buf()
            .await
            .map_err(|_| ClientError::Transient("ssh_status_io_failed".into()))?;
        if available.is_empty() {
            return Err(ClientError::Transient("ssh_status_interrupted".into()));
        }
        let end = available.iter().position(|c| *c == b'\n');
        let take = end.map_or(available.len(), |n| n + 1);
        if bytes.len() + take > v2::MAX_META {
            return Err(protocol("ssh_status_too_large"));
        }
        bytes.extend_from_slice(&available[..take]);
        input.consume(take);
        if end.is_some() {
            return serde_json::from_slice(&bytes).map_err(|_| protocol("invalid_ssh_status"));
        }
    }
}
fn admit_status(value: &Value, config: &SshConfig, after: &str) -> Result<()> {
    admit_common(value, config)?;
    if value["start_cursor"] != after
        || value["content_type"] != "application/vnd.blockzilla.stream.v2"
    {
        return Err(protocol("ssh_start_or_content_type_changed"));
    }
    Ok(())
}
fn admit_common(value: &Value, config: &SshConfig) -> Result<()> {
    if value["schema"] != "blockzilla-ssh-beam-v1" {
        return Err(protocol("invalid_ssh_schema"));
    }
    match value["status"].as_u64() {
        Some(200) => {
            if value["source"]
                != serde_json::to_value(&config.source)
                    .map_err(|_| protocol("source_encoding_failed"))?
                || value["generation"] != config.generation
                || value["producer_generation"] != config.producer_generation
            {
                return Err(ClientError::Source(
                    "ssh_source_or_generation_changed".into(),
                ));
            }
            Ok(())
        }
        Some(401 | 403) => Err(ClientError::Authentication(
            value["status"].as_u64().unwrap() as u16,
        )),
        Some(409) => Err(ClientError::Source(
            "ssh_source_or_generation_changed".into(),
        )),
        Some(410) => Err(ClientError::Gap {
            reason: "replay_expired".into(),
            head: None,
        }),
        Some(429 | 500..=599) => Err(ClientError::Transient(
            "ssh_gateway_temporarily_unavailable".into(),
        )),
        _ => Err(protocol("ssh_gateway_rejected_request")),
    }
}
fn admit_finite_frame(bytes: Vec<u8>, config: &SshConfig, digest: &str) -> Result<Frame> {
    if bytes.len() < 16 {
        return Err(ClientError::Transient("ssh_frame_interrupted".into()));
    }
    let length = v2::frame_length(&bytes).map_err(admission)?;
    if bytes.len() < length {
        return Err(ClientError::Transient("ssh_frame_interrupted".into()));
    }
    if bytes.len() != length {
        return Err(protocol("ssh_frame_has_trailing_bytes"));
    }
    let frame = v2::decode(bytes.into()).map_err(admission)?;
    if frame.source != config.source {
        return Err(ClientError::Source("source_changed".into()));
    }
    if frame.sha256 != digest {
        return Err(ClientError::Digest("requested_frame_changed".into()));
    }
    Ok(frame)
}

pub struct FrameReader<R> {
    input: R,
    source: SourceIdentity,
    cursor: String,
    pending: Vec<u8>,
    stopped: bool,
}
impl<R: AsyncRead + Unpin> FrameReader<R> {
    pub fn new(input: R, source: SourceIdentity, after: &str) -> Result<Self> {
        source.validate().map_err(admission)?;
        if v2::parse_cursor(after).map_err(admission)?.0 != source.session_id {
            return Err(ClientError::Source("source_changed".into()));
        }
        Ok(Self {
            input,
            source,
            cursor: after.into(),
            pending: Vec::new(),
            stopped: false,
        })
    }
    pub fn cursor(&self) -> &str {
        &self.cursor
    }
    pub async fn next(&mut self) -> Result<Frame> {
        if self.stopped {
            return Err(ClientError::Stopped);
        }
        let result = self.read().await;
        if result.is_err() {
            self.stopped = true;
        }
        result
    }
    async fn read(&mut self) -> Result<Frame> {
        loop {
            let wanted = if self.pending.len() < 16 {
                16
            } else {
                v2::frame_length(&self.pending).map_err(admission)?
            };
            if self.pending.len() == wanted && wanted > 16 {
                let frame =
                    v2::decode(std::mem::take(&mut self.pending).into()).map_err(admission)?;
                if frame.source != self.source {
                    return Err(ClientError::Source("source_changed".into()));
                }
                let previous = v2::parse_cursor(&self.cursor).map_err(admission)?.1;
                if frame.envelope.event.sequence
                    != previous
                        .checked_add(1)
                        .ok_or_else(|| protocol("sequence_overflow"))?
                {
                    return Err(ClientError::Gap {
                        reason: "sequence_gap".into(),
                        head: None,
                    });
                }
                self.cursor = frame.cursor.clone();
                return Ok(frame);
            }
            self.pending.reserve_exact(wanted - self.pending.len());
            let mut bytes = [0; 8192];
            let size = (wanted - self.pending.len()).min(bytes.len());
            let n = self
                .input
                .read(&mut bytes[..size])
                .await
                .map_err(|_| ClientError::Transient("ssh_frame_io_failed".into()))?;
            if n == 0 {
                return Err(ClientError::Transient(
                    if self.pending.is_empty() {
                        "ssh_stream_closed"
                    } else {
                        "ssh_frame_interrupted"
                    }
                    .into(),
                ));
            }
            self.pending.extend_from_slice(&bytes[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use v2::fixtures::{block, source};
    fn config() -> SshConfig {
        SshConfig {
            host: "ubuntu@127.0.0.1".into(),
            helper: "/private/helper's file.py".into(),
            job: "/private/job".into(),
            generation: "a".repeat(32),
            producer_generation: "b".repeat(64),
            source: source(),
        }
    }
    fn base() -> String {
        v2::cursor(&source().session_id, 0, "-")
    }
    #[tokio::test]
    async fn partial_ssh_frame_never_advances_and_exact_resume_is_valid() {
        let frame = block(1, 9, 1, 8, 1);
        let mut reader =
            FrameReader::new(&frame.wire[..frame.wire.len() - 1], source(), &base()).unwrap();
        assert!(reader.next().await.unwrap_err().is_transient());
        assert_eq!(reader.cursor(), base());
        let mut resumed = FrameReader::new(&frame.wire[..], source(), reader.cursor()).unwrap();
        assert_eq!(resumed.next().await.unwrap().wire, frame.wire);
    }
    #[tokio::test]
    async fn partial_next_frame_recovers_from_last_complete_application_boundary() {
        let first = block(1, 9, 1, 8, 1);
        let second = block(2, 10, 2, 9, 2);
        let mut bytes = first.wire.to_vec();
        bytes.extend_from_slice(&second.wire[..second.wire.len() / 2]);
        let mut reader = FrameReader::new(&bytes[..], source(), &base()).unwrap();
        let mut state = v2::client::ClientState::new(source(), base()).unwrap();
        assert!(
            state
                .apply(&reader.next().await.unwrap(), None, 1000)
                .unwrap()
        );
        let durable = state.cursor().to_owned();
        assert_eq!(durable, first.cursor);
        assert!(reader.next().await.unwrap_err().is_transient());
        assert_eq!(reader.cursor(), durable);
        assert_eq!(state.cursor(), durable);
        let mut resumed = FrameReader::new(&second.wire[..], source(), &durable).unwrap();
        let recovered = resumed.next().await.unwrap();
        assert!(state.apply(&recovered, None, 1000).unwrap());
        assert!(!state.apply(&recovered, None, 1000).unwrap());
        assert_eq!(state.cursor(), second.cursor);
        let mut corrupt = second.wire.to_vec();
        corrupt[0] ^= 1;
        let mut invalid = FrameReader::new(&corrupt[..], source(), &durable).unwrap();
        assert!(!invalid.next().await.unwrap_err().is_transient());
        assert_eq!(invalid.cursor(), durable);
    }
    #[tokio::test]
    async fn cancellation_keeps_pending_bytes_and_digest_errors_are_terminal() {
        use tokio::io::AsyncWriteExt;
        let frame = block(1, 9, 1, 8, 1);
        let (mut sender, input) = tokio::io::duplex(v2::MAX_FRAME);
        sender.write_all(&frame.wire[..17]).await.unwrap();
        let mut reader = FrameReader::new(input, source(), &base()).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(5), reader.next())
                .await
                .is_err()
        );
        sender.write_all(&frame.wire[17..]).await.unwrap();
        assert_eq!(reader.next().await.unwrap().wire, frame.wire);
        let mut bad = frame.wire.to_vec();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        let mut reader = FrameReader::new(&bad[..], source(), &base()).unwrap();
        assert!(!reader.next().await.unwrap_err().is_transient());
        assert_eq!(reader.cursor(), base());
    }
    #[tokio::test]
    async fn status_is_bounded_and_binary_bytes_remain_for_frame_reader() {
        let cfg = config();
        let frame = block(1, 9, 1, 8, 1);
        let header = serde_json::json!({"schema":"blockzilla-ssh-beam-v1","status":200,"source":source(),"generation":cfg.generation,"producer_generation":cfg.producer_generation,"start_cursor":base(),"content_type":"application/vnd.blockzilla.stream.v2"});
        let mut data = serde_json::to_vec(&header).unwrap();
        data.push(b'\n');
        data.extend_from_slice(&frame.wire);
        let mut input = BufReader::new(&data[..]);
        admit_status(&status_line(&mut input).await.unwrap(), &cfg, &base()).unwrap();
        let mut reader = FrameReader::new(input, source(), &base()).unwrap();
        assert_eq!(reader.next().await.unwrap().wire, frame.wire);
        let huge = vec![b'x'; v2::MAX_META + 1];
        assert!(status_line(&mut BufReader::new(&huge[..])).await.is_err());
        let mut wrong = header;
        wrong["generation"] = Value::String("c".repeat(32));
        assert!(matches!(
            admit_status(&wrong, &cfg, &base()),
            Err(ClientError::Source(_))
        ));
        assert!(matches!(
            admit_status(
                &serde_json::json!({"schema":"blockzilla-ssh-beam-v1","status":410}),
                &cfg,
                &base()
            ),
            Err(ClientError::Gap { .. })
        ));
    }
    #[test]
    fn remote_arguments_are_shell_quoted_and_hosts_cannot_inject_options() {
        let mut cfg = config();
        let command = cfg.remote_command(&base()).unwrap();
        assert!(command.contains("'/private/helper'\\''s file.py'"));
        assert!(command.contains("'--source-json'"));
        cfg.host = "-oProxyCommand=bad".into();
        assert!(cfg.validate().is_err());
    }
    #[test]
    fn finite_dependencies_are_exact_and_read_only_commands_remain_pinned() {
        let cfg = config();
        let frame = block(1, 9, 1, 8, 1);
        let got = admit_finite_frame(frame.wire.to_vec(), &cfg, &frame.sha256).unwrap();
        assert_eq!(got.wire, frame.wire);
        assert!(admit_finite_frame(frame.wire.to_vec(), &cfg, &"c".repeat(64)).is_err());
        let mut extra = frame.wire.to_vec();
        extra.push(0);
        assert!(admit_finite_frame(extra, &cfg, &frame.sha256).is_err());
        assert!(
            admit_finite_frame(
                frame.wire[..frame.wire.len() - 1].to_vec(),
                &cfg,
                &frame.sha256
            )
            .unwrap_err()
            .is_transient()
        );
        let command = cfg.read_command("frame", Some(&frame.sha256)).unwrap();
        assert!(command.contains("'--generation'"));
        assert!(command.contains("'--source-json'"));
        assert!(command.contains("'--digest'"));
        assert!(!command.contains("ack"));
        assert!(cfg.read_command("frame", Some("not-a-sha")).is_err());
    }
    #[tokio::test]
    async fn checked_finite_body_requires_clean_helper_exit() {
        let frame = block(1, 9, 1, 8, 1);
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &frame.wire).unwrap();
        for exit_code in ["0", "75"] {
            let mut process = Command::new("/bin/sh")
                .args(["-c", "cat \"$1\"; exit \"$2\"", "finite-helper"])
                .arg(file.path())
                .arg(exit_code)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let stdout = process.stdout.take().unwrap();
            let mut connection = SshBeam {
                process,
                frames: FrameReader::new(BufReader::new(stdout), source(), &base()).unwrap(),
                stderr: tokio::spawn(async { Vec::new() }),
            };
            assert_eq!(connection.next().await.unwrap().wire, frame.wire);
            let completed = connection.finish_finite().await;
            if exit_code == "0" {
                completed.unwrap();
            } else {
                assert!(
                    matches!(completed, Err(ClientError::Transient(ref reason)) if reason == "ssh_finite_exit_failed")
                );
            }
        }
        let mut process = Command::new("/bin/sh")
            .args(["-c", "printf x"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let stdout = process.stdout.take().unwrap();
        let mut connection = SshBeam {
            process,
            frames: FrameReader::new(BufReader::new(stdout), source(), &base()).unwrap(),
            stderr: tokio::spawn(async { Vec::new() }),
        };
        assert!(
            matches!(connection.finish_finite().await, Err(ClientError::Protocol(ref reason)) if reason == "ssh_finite_trailing_bytes")
        );
    }
}
