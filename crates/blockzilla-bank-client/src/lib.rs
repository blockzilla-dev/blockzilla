//! Backend transport for the opt-in native bank v2 feed.
//!
//! Commit application data and the event cursor together, then acknowledge.
//! The client never advances its reconnect boundary before that acknowledgement.
use blockzilla_bank_stream_v2 as v2;
use bytes::BytesMut;
use futures_util::{StreamExt, future::BoxFuture, stream::BoxStream};
use reqwest::{Client, Response, Url};
use std::{future::Future, sync::Arc, time::Duration};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
mod beam;
pub use beam::BeamStream;
pub mod recovery;
pub mod ssh_beam;
pub use recovery::{RecoveryEntry, RecoveryNotice, WorkerRecoveryClient, WorkerRecoveryConfig};

// This budget covers announced frame bytes from before GET through queued
// delivery. The sole delivered frame and one consumer dependency are separate.
const MAX_PREPARED_BYTES: usize = 64 * 1024 * 1024;

pub use v2::{
    BankEvent, BankIdentity, ConfirmedObservation, Frame, Head, RecentBlockhash, SourceIdentity,
    chain::Chain, client::ClientState, decode, parse_cursor,
};

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("invalid client configuration: {0}")]
    Configuration(&'static str),
    #[error("stream authentication failed ({0})")]
    Authentication(u16),
    #[error("source unavailable or changed: {0}")]
    Source(String),
    #[error("stream recovery required: {reason}")]
    Gap {
        reason: String,
        head: Option<Box<Head>>,
    },
    #[error("stream digest admission failed: {0}")]
    Digest(String),
    #[error("stream protocol admission failed: {0}")]
    Protocol(String),
    #[error("transient stream I/O failure: {0}")]
    Transient(String),
    #[error("durable checkpoint failed: {0}")]
    Checkpoint(String),
    #[error("acknowledge the pending bank before reading another event")]
    AwaitingAck,
    #[error("acknowledgement does not match the pending bank")]
    AckOrder,
    #[error("stream stopped; reopen from the durable checkpoint")]
    Stopped,
}
impl ClientError {
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Transient(_))
    }
    pub fn is_terminal(&self) -> bool {
        !matches!(
            self,
            Self::Transient(_) | Self::AwaitingAck | Self::AckOrder
        )
    }
}
pub type Result<T> = std::result::Result<T, ClientError>;

fn admission(error: anyhow::Error) -> ClientError {
    let message = error.to_string();
    if message.contains("source_") || message.contains("rooted_bank_invalidated") {
        ClientError::Source(message)
    } else if message.contains("digest") || message.contains("sha256") {
        ClientError::Digest(message)
    } else if message.contains("sequence_gap") || message.contains("dependency_unavailable") {
        ClientError::Gap {
            reason: message,
            head: None,
        }
    } else {
        ClientError::Protocol(message)
    }
}
fn protocol(message: impl Into<String>) -> ClientError {
    ClientError::Protocol(message.into())
}
fn network(error: reqwest::Error) -> ClientError {
    // Request URLs contain no credential. Do not include headers or configuration.
    if error.is_builder() || error.is_redirect() {
        protocol("request_or_redirect_rejected")
    } else {
        ClientError::Transient(error.without_url().to_string())
    }
}

#[derive(Clone, Debug)]
pub struct RetryPolicy {
    /// Retries after the initial request; errors remain typed after exhaustion.
    pub max_retries: usize,
    pub initial_delay: Duration,
    pub max_delay: Duration,
}
impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 8,
            initial_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(5),
        }
    }
}
impl RetryPolicy {
    async fn wait(&self, attempt: usize) {
        let multiplier = 1u32 << attempt.min(20);
        tokio::time::sleep(
            self.initial_delay
                .saturating_mul(multiplier)
                .min(self.max_delay),
        )
        .await;
    }
}

#[derive(Clone)]
pub struct ClientConfig {
    pub url: String,
    pub api_key: String,
    pub source: SourceIdentity,
    /// Includes control dependency fetches, not only advertised frames.
    pub max_in_flight: usize,
    pub retry: RetryPolicy,
    /// Optional speculative work on admitted frames. This is not application
    /// delivery or ACK. Results must stay private until the ordered commit.
    pub preprocess: Option<Preprocessor>,
}
pub type Preprocessor = Arc<dyn Fn(Frame) -> BoxFuture<'static, Result<()>> + Send + Sync>;
impl ClientConfig {
    pub fn new(url: impl Into<String>, api_key: impl Into<String>, source: SourceIdentity) -> Self {
        Self {
            url: url.into(),
            api_key: api_key.into(),
            source,
            max_in_flight: 4,
            retry: RetryPolicy::default(),
            preprocess: None,
        }
    }
}
// Deliberately omit Debug: the configuration owns a backend credential.

#[derive(Clone)]
pub struct BankClient {
    config: Arc<ClientConfig>,
    base: Url,
    http: Client,
    reads: Arc<Semaphore>,
}

pub struct Bootstrap {
    pub head: Head,
    /// Exact application boundary. A saved boundary is never replaced by head.
    pub after: String,
    pub control: Option<Frame>,
    pub payload: Option<Frame>,
}
/// Durable consumer checkpoint receipt. It does not certify archive custody or
/// authorize the consumer to remove producer files.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckReceipt {
    pub schema: String,
    pub state: String,
    pub consumer_id: String,
    pub source: SourceIdentity,
    pub cursor: String,
    #[serde(default)]
    pub coverage_gap_sequence: u64,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageGap {
    pub sequence: u64,
    pub processed_sequence: u64,
    pub gap: serde_json::Value,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoveragePage {
    pub schema: String,
    pub producer_generation: String,
    pub source: SourceIdentity,
    pub base_sequence: u64,
    pub latest_sequence: u64,
    pub gaps: Vec<CoverageGap>,
}
impl CoverageGap {
    fn validate(&self, generation: &str) -> Result<()> {
        let g = &self.gap;
        let number = |key: &str| g[key].as_u64().filter(|v| *v <= v2::SAFE);
        let slot = number("slot");
        let first = number("first_source_sequence");
        let last = number("last_source_sequence");
        if self.sequence == 0
            || self.sequence > v2::SAFE
            || self.processed_sequence != self.sequence
            || g["producer_generation"] != generation
            || g["gap_sequence"] != self.sequence
            || slot.is_none()
            || first.is_none_or(|v| v == 0)
            || last.zip(first).is_none_or(|(last, first)| last < first)
            || !g["evidence_sha256"].as_str().is_some_and(v2::is_digest)
            || g["captured_input_preserved"] != true
            || g["canonical_status"] != "UNKNOWN"
            || !g["reason"]
                .as_str()
                .is_some_and(|v| !v.is_empty() && v.len() <= 256)
            || serde_json::to_vec(g)
                .map_err(|_| protocol("invalid_gap_json"))?
                .len()
                > v2::MAX_META
        {
            return Err(protocol("coverage_gap_mismatch"));
        }
        match g["schema"].as_str() {
            Some("hivezilla-incomplete-bank-gap-v1")
                if g["complete_bank"] == false && number("bank_id").is_some() => {}
            Some("hivezilla-slot-control-gap-v1")
                if g["complete_bank"] == false
                    && g.get("bank_id").is_some_and(serde_json::Value::is_null)
                    && g.get("bank_identity")
                        .is_some_and(serde_json::Value::is_null)
                    && g["custody"]["artifact"].is_null()
                    && g["custody"]["marker_sha256"].is_null() => {}
            Some("hivezilla-nonterminal-bank-gap-v1")
                if g["complete_bank"] == true
                    && g["reason"] == "complete-unconfirmed-bank-expired"
                    && number("bank_id").is_some() =>
            {
                let bank: BankIdentity = serde_json::from_value(g["bank_identity"].clone())
                    .map_err(|_| protocol("coverage_bank_identity_missing"))?;
                bank.validate().map_err(admission)?;
                if Some(bank.slot) != slot
                    || Some(bank.bank_id) != number("bank_id")
                    || !g["custody"]["artifact"]
                        .as_str()
                        .is_some_and(|v| !v.is_empty() && v.len() <= 4096)
                    || !g["custody"]["marker_sha256"]
                        .as_str()
                        .is_some_and(v2::is_digest)
                {
                    return Err(protocol("coverage_bank_custody_mismatch"));
                }
            }
            _ => return Err(protocol("coverage_gap_schema_or_semantics_mismatch")),
        }
        Ok(())
    }
}
pub struct Delivery {
    pub frame: Frame,
    /// Exact processed payload if this client's metadata state lacks it.
    pub dependency: Option<Frame>,
}
pub struct DecodedDelivery<T> {
    pub frame: T,
    pub dependency: Option<T>,
}
impl Delivery {
    /// Use the application's portable decoder. No Agave or archive decoder is linked.
    /// A decoder failure must stop application processing before acknowledgement.
    pub fn decode_with<T, E>(
        &self,
        mut decoder: impl FnMut(&[u8]) -> std::result::Result<T, E>,
    ) -> std::result::Result<DecodedDelivery<T>, E> {
        Ok(DecodedDelivery {
            frame: decoder(&self.frame.wire)?,
            dependency: self
                .dependency
                .as_ref()
                .map(|p| decoder(&p.wire))
                .transpose()?,
        })
    }
}
// Keep the public event API directly owned. The 1.2 KiB maximum is bounded;
// frame byte buffers remain shared Bytes without another per-event allocation.
#[allow(clippy::large_enum_variant)]
pub enum StreamEvent {
    Status(Head),
    Bank(Delivery),
}

impl BankClient {
    pub fn new(config: ClientConfig) -> Result<Self> {
        Self::build(config, false)
    }
    /// Connect only through the named local Unix socket. The HTTP origin is a
    /// fixed routing placeholder; it is never resolved or used as a TCP target.
    /// Bearer authentication, source pins, frame admission and ACK rules remain.
    #[cfg(unix)]
    pub fn new_unix(config: ClientConfig, socket: impl Into<std::path::PathBuf>) -> Result<Self> {
        use std::os::unix::fs::FileTypeExt;
        let socket = socket.into();
        if config.url != "http://localhost/"
            || !socket.is_absolute()
            || socket.as_os_str().as_encoded_bytes().len() > 100
            || !std::fs::symlink_metadata(&socket).is_ok_and(|meta| meta.file_type().is_socket())
        {
            return Err(ClientError::Configuration("invalid_unix_socket_or_origin"));
        }
        Self::build_transport(config, false, Some(socket))
    }
    fn build(config: ClientConfig, local_test: bool) -> Result<Self> {
        Self::build_transport(config, local_test, None)
    }
    fn build_transport(
        config: ClientConfig,
        local_test: bool,
        unix_socket: Option<std::path::PathBuf>,
    ) -> Result<Self> {
        let base =
            Url::parse(&config.url).map_err(|_| ClientError::Configuration("invalid_url"))?;
        if !(base.scheme() == "https"
            || ((local_test || unix_socket.is_some()) && base.scheme() == "http"))
            || base.path() != "/"
            || base.query().is_some()
            || base.fragment().is_some()
            || !base.username().is_empty()
            || base.password().is_some()
        {
            return Err(ClientError::Configuration("https_base_required"));
        }
        if !(1..=16).contains(&config.max_in_flight)
            || !(32..=256).contains(&config.api_key.len())
            || reqwest::header::HeaderValue::from_str(&format!("Bearer {}", config.api_key))
                .is_err()
            || config.retry.max_retries > 32
            || config.retry.initial_delay > config.retry.max_delay
            || config.retry.max_delay > Duration::from_secs(60)
        {
            return Err(ClientError::Configuration("invalid_bounds_or_credential"));
        }
        config.source.validate().map_err(admission)?;
        let http = Client::builder()
            .user_agent("blockzilla-bank-client/0.1")
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .read_timeout(Duration::from_secs(15));
        #[cfg(unix)]
        let http = match unix_socket {
            Some(socket) => http.no_proxy().unix_socket(socket).http1_only(),
            None => http,
        };
        #[cfg(not(unix))]
        let http = {
            if unix_socket.is_some() {
                return Err(ClientError::Configuration("unix_transport_unavailable"));
            }
            http
        };
        let http = http.build().map_err(network)?;
        Ok(Self {
            reads: Arc::new(Semaphore::new(config.max_in_flight)),
            config: Arc::new(config),
            base,
            http,
        })
    }
    pub fn source(&self) -> &SourceIdentity {
        &self.config.source
    }

    /// Record a preconfigured consumer's exact durable application boundary.
    /// Call only after the projection, webhook outbox and cursor commit together.
    /// A repeated identical request is safe after an ambiguous network failure.
    pub async fn acknowledge(&self, consumer_id: &str, cursor: &str) -> Result<AckReceipt> {
        self.acknowledge_coverage(consumer_id, cursor, 0).await
    }
    pub async fn acknowledge_coverage(
        &self,
        consumer_id: &str,
        cursor: &str,
        coverage_gap_sequence: u64,
    ) -> Result<AckReceipt> {
        if coverage_gap_sequence > v2::SAFE {
            return Err(protocol("invalid_coverage_gap_sequence"));
        }
        if consumer_id.is_empty()
            || consumer_id.len() > 64
            || !consumer_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return Err(ClientError::Configuration("invalid_consumer_id"));
        }
        self.check_cursor(cursor)?;
        self.retry(|| async {
            let response = self.http.post(self.base.join("v2/banks/ack")
                .map_err(|_| protocol("invalid_ack_url"))?)
                .bearer_auth(&self.config.api_key)
                .json(&serde_json::json!({"schema":"blockzilla-consumer-ack-v1",
                    "consumer_id":consumer_id,"source":self.source(),"cursor":cursor,"coverage_gap_sequence":coverage_gap_sequence}))
                .send().await.map_err(network)?;
            let status = response.status().as_u16();
            match status {
                200 => {},
                401 | 403 => return Err(ClientError::Authentication(status)),
                429 | 500..=599 => return Err(ClientError::Transient(format!("ack_http_{status}"))),
                _ => return Err(protocol(format!("ack_rejected_http_{status}"))),
            }
            let receipt: AckReceipt = serde_json::from_slice(&body(response, v2::MAX_META).await?)
                .map_err(|_| protocol("invalid_ack_receipt"))?;
            if receipt.schema != "blockzilla-consumer-ack-receipt-v1"
                || receipt.state != "ACKED" || receipt.consumer_id != consumer_id
                || receipt.cursor != cursor || &receipt.source != self.source()
                || receipt.coverage_gap_sequence != coverage_gap_sequence
            {
                return Err(protocol("ack_receipt_mismatch"));
            }
            Ok(receipt)
        }).await
    }

    /// Read explicit incomplete/expired coverage records. Sparse IDs are source
    /// sequence numbers. A changed source/generation or discarded prefix stops.
    pub async fn coverage_gaps(
        &self,
        after: u64,
        producer_generation: &str,
    ) -> Result<CoveragePage> {
        if after > v2::SAFE || producer_generation.is_empty() || producer_generation.len() > 128 {
            return Err(ClientError::Configuration("invalid_coverage_pin"));
        }
        self.retry(|| async {
            let mut url = self
                .base
                .join("v2/banks/coverage-gaps")
                .map_err(|_| protocol("invalid_coverage_url"))?;
            url.query_pairs_mut()
                .append_pair("after", &after.to_string());
            let response = self
                .http
                .get(url)
                .bearer_auth(&self.config.api_key)
                .send()
                .await
                .map_err(network)?;
            let status = response.status().as_u16();
            match status {
                200 => {}
                401 | 403 => return Err(ClientError::Authentication(status)),
                410 => {
                    return Err(ClientError::Gap {
                        reason: "coverage_replay_unavailable".into(),
                        head: None,
                    });
                }
                429 | 500..=599 => {
                    return Err(ClientError::Transient(format!("coverage_http_{status}")));
                }
                _ => return Err(protocol(format!("coverage_rejected_http_{status}"))),
            }
            let page: CoveragePage =
                serde_json::from_slice(&body(response, 4 * 1024 * 1024).await?)
                    .map_err(|_| protocol("invalid_coverage_page"))?;
            if page.schema != "blockzilla-coverage-gaps-v1"
                || &page.source != self.source()
                || page.producer_generation != producer_generation
                || (page.gaps.is_empty() && after < page.latest_sequence)
                || page.base_sequence > page.latest_sequence
                || page.latest_sequence > v2::SAFE
                || after > page.latest_sequence
                || page.gaps.len() > 256
            {
                return Err(protocol("coverage_page_mismatch"));
            }
            if after < page.base_sequence {
                return Err(ClientError::Gap {
                    reason: "coverage_replay_unavailable".into(),
                    head: None,
                });
            }
            let mut previous = after;
            for row in &page.gaps {
                row.validate(producer_generation)?;
                if row.sequence <= previous || row.sequence > page.latest_sequence {
                    return Err(protocol("coverage_gap_mismatch"));
                }
                previous = row.sequence;
            }
            Ok(page)
        })
        .await
    }

    async fn response(&self, path: &str, after: Option<&str>) -> Result<Response> {
        match after {
            Some(after) => self.response_query(path, &[("after", after)]).await,
            None => self.response_query(path, &[]).await,
        }
    }

    async fn response_query(&self, path: &str, query: &[(&str, &str)]) -> Result<Response> {
        let mut url = self
            .base
            .join(path)
            .map_err(|_| protocol("invalid_relative_url"))?;
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query.iter().copied());
        }
        let response = self
            .http
            .get(url)
            .bearer_auth(&self.config.api_key)
            .send()
            .await
            .map_err(network)?;
        let status = response.status().as_u16();
        match status {
            200 => Ok(response),
            401 | 403 => Err(ClientError::Authentication(status)),
            410 => {
                let value: serde_json::Value =
                    serde_json::from_slice(&body(response, v2::MAX_META).await?)
                        .map_err(|_| protocol("invalid_gap_body"))?;
                let reason = value["error"]
                    .as_str()
                    .ok_or_else(|| protocol("invalid_gap_reason"))?
                    .to_owned();
                let head: Head = serde_json::from_value(value["head"].clone())
                    .map_err(|_| protocol("invalid_gap_head"))?;
                head.validate(self.source(), now_ms(), v2::DEFAULT_MAX_LAG_MS)
                    .map_err(admission)?;
                Err(ClientError::Gap {
                    reason,
                    head: Some(Box::new(head)),
                })
            }
            429 | 500..=599 => Err(ClientError::Transient(format!("http_{status}"))),
            _ => Err(protocol(format!("terminal_http_{status}"))),
        }
    }
    async fn retry<T, F, Fut>(&self, mut operation: F) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let mut attempt = 0;
        loop {
            match operation().await {
                Err(error) if error.is_transient() && attempt < self.config.retry.max_retries => {
                    self.config.retry.wait(attempt).await;
                    attempt += 1;
                }
                result => return result,
            }
        }
    }
    pub async fn head(&self) -> Result<Head> {
        self.retry(|| async {
            let response = self.response("v2/banks/head", None).await?;
            let head: Head = serde_json::from_slice(&body(response, v2::MAX_META).await?)
                .map_err(|_| protocol("invalid_head_json"))?;
            head.validate(self.source(), now_ms(), v2::DEFAULT_MAX_LAG_MS)
                .map_err(admission)?;
            if head.status == "failed" {
                return Err(ClientError::Source("source_failed".into()));
            }
            Ok(head)
        })
        .await
    }
    pub async fn fetch(&self, sha256: &str) -> Result<Frame> {
        self.fetch_bounded(sha256, v2::MAX_FRAME).await
    }
    async fn fetch_bounded(&self, sha256: &str, limit: usize) -> Result<Frame> {
        if !v2::is_digest(sha256) {
            return Err(ClientError::Digest("invalid_digest".into()));
        }
        self.retry(|| async {
            let _permit = self
                .reads
                .acquire()
                .await
                .map_err(|_| ClientError::Stopped)?;
            let response = self
                .response(&format!("v2/banks/chunks/{sha256}"), None)
                .await?;
            if header(&response, "content-type") != Some("application/vnd.blockzilla.stream.v2") {
                return Err(protocol("chunk_content_type_mismatch"));
            }
            let wire = body(response, limit).await?;
            if v2::digest(&wire) != sha256 {
                return Err(ClientError::Digest("frame_digest_mismatch".into()));
            }
            let frame = v2::decode(wire.into()).map_err(admission)?;
            if &frame.source != self.source() {
                return Err(ClientError::Source("source_changed".into()));
            }
            Ok(frame)
        })
        .await
    }
    pub async fn bootstrap(&self, after: Option<&str>) -> Result<Bootstrap> {
        let head = self.head().await?;
        let after = after
            .map(str::to_owned)
            .or_else(|| head.cursor.clone())
            .ok_or_else(|| ClientError::Source("source_not_started".into()))?;
        self.check_cursor(&after)?;
        let number = v2::parse_cursor(&after).map_err(admission)?.1;
        let head_number = head
            .cursor
            .as_deref()
            .map(v2::parse_cursor)
            .transpose()
            .map_err(admission)?
            .ok_or_else(|| ClientError::Source("source_not_started".into()))?
            .1;
        if number > head_number {
            return Err(protocol("cursor_ahead_of_head"));
        }
        if head
            .earliest_after
            .as_deref()
            .map(v2::parse_cursor)
            .transpose()
            .map_err(admission)?
            .is_some_and(|(_, earliest, _)| number < earliest)
        {
            return Err(ClientError::Gap {
                reason: "replay_unavailable".into(),
                head: Some(Box::new(head)),
            });
        }
        let (control, payload) = if let Some(selected) = &head.latest_confirmed {
            let control_digest = v2::parse_cursor(&selected.event_cursor)
                .map_err(admission)?
                .2;
            let (control, payload) = futures_util::try_join!(
                self.fetch(control_digest),
                self.fetch(&selected.payload_frame_sha256)
            )?;
            let mut state =
                ClientState::new(self.source().clone(), after.clone()).map_err(admission)?;
            state
                .resolve_head(&head, &control, &payload, now_ms())
                .map_err(admission)?;
            (Some(control), Some(payload))
        } else {
            (None, None)
        };
        Ok(Bootstrap {
            head,
            after,
            control,
            payload,
        })
    }
    fn check_cursor(&self, cursor: &str) -> Result<()> {
        if v2::parse_cursor(cursor).map_err(admission)?.0 != self.source().session_id {
            return Err(ClientError::Source("source_changed".into()));
        }
        Ok(())
    }
    /// Commit bootstrap dependencies before calling this method.
    pub async fn connect(&self, bootstrap: Bootstrap) -> Result<BankStream> {
        self.check_cursor(&bootstrap.after)?;
        let mut state =
            ClientState::new(self.source().clone(), bootstrap.after.clone()).map_err(admission)?;
        match (
            &bootstrap.control,
            &bootstrap.payload,
            &bootstrap.head.latest_confirmed,
        ) {
            (Some(control), Some(payload), Some(_)) => {
                state
                    .resolve_head(&bootstrap.head, control, payload, now_ms())
                    .map_err(admission)?;
            }
            (None, None, None) => {}
            _ => return Err(protocol("incomplete_bootstrap_dependency")),
        }
        state.health(bootstrap.head, now_ms()).map_err(admission)?;
        let incoming = self.open(&bootstrap.after).await?;
        Ok(BankStream {
            client: self.clone(),
            incoming,
            state,
            cursor: bootstrap.after,
            pending: None,
            stopped: false,
            available: false,
            staging: None,
            reconnect: None,
            reconnect_attempts: 0,
        })
    }
    async fn open(&self, after: &str) -> Result<BoxStream<'static, Result<Prepared>>> {
        Ok(Box::pin(
            self.open_bounded(after, Arc::new(Semaphore::new(MAX_PREPARED_BYTES)))
                .await?,
        ))
    }
    async fn open_bounded(&self, after: &str, bytes: Arc<Semaphore>) -> Result<PreparedReceiver> {
        self.check_cursor(after)?;
        let response = self
            .retry(|| self.response("v2/banks/events", Some(after)))
            .await?;
        if header(&response, "x-blockzilla-start-cursor") != Some(after) {
            return Err(protocol("start_cursor_mismatch"));
        }
        if !header(&response, "content-type").is_some_and(|s| s.starts_with("text/event-stream")) {
            return Err(protocol("wrong_sse_content_type"));
        }
        let source = self.source().clone();
        let after = after.to_owned();
        let notices: BoxStream<'static, Result<NoticeEvent>> = Box::pin(
            async_stream::try_stream! {
                let mut bytes = response.bytes_stream();
                let mut parser = Sse::default();
                let mut sequence = v2::parse_cursor(&after).map_err(admission)?.1;
                let mut first = true;
                while let Some(part) = bytes.next().await {
                    let part = part.map_err(network)?;
                    // Bound the unparsed response chunk and partial line.
                    if parser.pending.len() + part.len() > 2 * v2::MAX_META {
                        Err(protocol("sse_read_too_large"))?;
                    }
                    parser.pending.extend_from_slice(&part);
                    while let Some(end) = parser.pending.iter().position(|b| *b == b'\n') {
                        let line = parser.pending.split_to(end + 1);
                        let Some((kind, id, data)) = parser.line(&line[..end])? else { continue; };
                        if first {
                            if kind != "status" || !id.is_empty() { Err(protocol("missing_initial_status"))?; }
                            first = false;
                        }
                        match kind.as_str() {
                            "chunk" => {
                                let notice: v2::Notice = serde_json::from_str(&data).map_err(|_| protocol("invalid_notice_json"))?;
                                notice.preflight(&id, sequence + 1, &source).map_err(admission)?;
                                sequence += 1;
                                yield NoticeEvent::Bank(id, notice, sequence);
                            }
                            "status" => {
                                if !id.is_empty() { Err(protocol("status_has_id"))?; }
                                let head: Head = serde_json::from_str(&data).map_err(|_| protocol("invalid_status_json"))?;
                                head.validate(&source, now_ms(), v2::DEFAULT_MAX_LAG_MS).map_err(admission)?;
                            yield NoticeEvent::Status(Box::new(head));
                            }
                            "gap" => {
                                if !id.is_empty() { Err(protocol("gap_has_id"))?; }
                                let value: serde_json::Value = serde_json::from_str(&data).map_err(|_| protocol("invalid_gap_json"))?;
                                let reason = value["error"].as_str().ok_or_else(|| protocol("invalid_gap_reason"))?.to_owned();
                                let head: Head = serde_json::from_value(value["head"].clone()).map_err(|_| protocol("invalid_gap_head"))?;
                                head.validate(&source, now_ms(), v2::DEFAULT_MAX_LAG_MS).map_err(admission)?;
                                Err(ClientError::Gap { reason, head: Some(Box::new(head)) })?;
                            }
                            _ => Err(protocol("unsupported_sse_event"))?,
                        }
                    }
                }
                Err(ClientError::Transient("sse_connection_closed".into()))?;
            },
        );
        let client = self.clone();
        let fetched = notices
            .map(move |notice| {
                let client = client.clone();
                let bytes = bytes.clone();
                async move {
                    match notice? {
                        NoticeEvent::Status(head) => Ok(QueuedPrepared {
                            prepared: Prepared::Status(*head),
                            _bytes: None,
                        }),
                        NoticeEvent::Bank(id, notice, sequence) => {
                            // Reserve before GET, and reject bodies larger
                            // than this admitted notice's reservation.
                            let reservation = bytes
                                .acquire_many_owned(notice.bytes as u32)
                                .await
                                .map_err(|_| ClientError::Stopped)?;
                            let frame = client.fetch_bounded(&notice.sha256, notice.bytes).await?;
                            notice
                                .validate(&id, &frame, sequence, client.source())
                                .map_err(admission)?;
                            Ok(QueuedPrepared {
                                prepared: Prepared::Bank(frame),
                                _bytes: Some(reservation),
                            })
                        }
                    }
                }
            })
            .buffered(self.config.max_in_flight)
            .boxed();
        let prepared = if let Some(preprocess) = self.config.preprocess.clone() {
            fetched
                // Fetch completion is reordered before preprocessing starts.
                // Its first reservation can therefore be made in queue order;
                // later decoded frames cannot starve the front frame's budget.
                .map(move |queued| {
                    let preprocess = preprocess.clone();
                    async move {
                        let queued = queued?;
                        if let Prepared::Bank(frame) = &queued.prepared {
                            preprocess(frame.clone()).await?;
                        }
                        Ok(queued)
                    }
                })
                .buffered(self.config.max_in_flight)
                .boxed()
        } else {
            fetched
        };
        Ok(PreparedReceiver::start(prepared, self.config.max_in_flight))
    }
}

enum NoticeEvent {
    Status(Box<Head>),
    Bank(String, v2::Notice, u64),
}
enum Prepared {
    Status(Head),
    Bank(Frame),
}
struct QueuedPrepared {
    prepared: Prepared,
    _bytes: Option<OwnedSemaphorePermit>,
}

// The producer owns only speculative notice reads. ClientState, control
// dependencies, application delivery and acknowledgement stay on BankStream.
struct PreparedReceiver {
    receiver: mpsc::Receiver<Result<QueuedPrepared>>,
    task: tokio::task::JoinHandle<()>,
}
impl PreparedReceiver {
    fn start(mut incoming: BoxStream<'static, Result<QueuedPrepared>>, capacity: usize) -> Self {
        let (sender, receiver) = mpsc::channel(capacity);
        let task = tokio::spawn(async move {
            while let Some(item) = incoming.next().await {
                let failed = item.is_err();
                if sender.send(item).await.is_err() || failed {
                    break;
                }
            }
        });
        Self { receiver, task }
    }
}
impl futures_util::Stream for PreparedReceiver {
    type Item = Result<Prepared>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.receiver
            .poll_recv(context)
            .map(|item| item.map(|result| result.map(|queued| queued.prepared)))
    }
}
impl Drop for PreparedReceiver {
    fn drop(&mut self) {
        self.task.abort();
    }
}
struct Staged {
    frame: Frame,
    dependency: BoxFuture<'static, Result<Option<Frame>>>,
}

pub struct BankStream {
    client: BankClient,
    incoming: BoxStream<'static, Result<Prepared>>,
    state: ClientState,
    cursor: String,
    pending: Option<String>,
    stopped: bool,
    available: bool,
    staging: Option<Staged>,
    reconnect: Option<BoxFuture<'static, Result<BoxStream<'static, Result<Prepared>>>>>,
    reconnect_attempts: usize,
}
impl BankStream {
    pub fn cursor(&self) -> &str {
        &self.cursor
    }
    pub fn source(&self) -> &SourceIdentity {
        self.client.source()
    }
    pub fn selected(&self) -> Option<&ConfirmedObservation> {
        self.state.selected()
    }
    pub fn force_unavailable(&mut self) {
        self.available = false;
    }
    pub fn ready_hash(&self, now: u64) -> Result<&RecentBlockhash> {
        if self.stopped || !self.available || self.pending.is_some() {
            return Err(ClientError::Source(
                "client_unavailable_or_uncommitted".into(),
            ));
        }
        self.state.ready_hash(now).map_err(admission)
    }
    pub async fn next(&mut self) -> Result<StreamEvent> {
        if self.stopped {
            return Err(ClientError::Stopped);
        }
        if self.pending.is_some() {
            return Err(ClientError::AwaitingAck);
        }
        loop {
            if let Some(reconnect) = &mut self.reconnect {
                let result = reconnect.await;
                self.reconnect = None;
                match result {
                    Ok(incoming) => self.incoming = incoming,
                    Err(error) => self.recover(error)?,
                }
                continue;
            }
            if let Some(staged) = &mut self.staging {
                let result = staged.dependency.as_mut().await;
                let staged = self.staging.take().unwrap();
                let dependency = match result {
                    Ok(dependency) => dependency,
                    Err(error) => {
                        self.recover(error)?;
                        continue;
                    }
                };
                if let Err(error) = self
                    .state
                    .apply(&staged.frame, dependency.as_ref(), now_ms())
                    .map_err(admission)
                {
                    self.stop();
                    return Err(error);
                }
                self.pending = Some(staged.frame.cursor.clone());
                return Ok(StreamEvent::Bank(Delivery {
                    frame: staged.frame,
                    dependency,
                }));
            }
            let next = self
                .incoming
                .next()
                .await
                .unwrap_or_else(|| Err(ClientError::Transient("sse_connection_closed".into())));
            match next {
                Ok(Prepared::Status(head)) => {
                    if let Err(error) = self.state.health(head.clone(), now_ms()).map_err(admission)
                    {
                        self.stop();
                        return Err(error);
                    }
                    if head.status == "failed" {
                        self.stop();
                        return Err(ClientError::Source("source_failed".into()));
                    }
                    self.available = true;
                    self.reconnect_attempts = 0;
                    return Ok(StreamEvent::Status(head));
                }
                Ok(Prepared::Bank(frame)) => {
                    let sha = frame
                        .envelope
                        .event
                        .payload_frame_sha256
                        .as_ref()
                        .filter(|sha| !self.state.has_payload(sha))
                        .cloned();
                    let client = self.client.clone();
                    // Store the consumed frame and future before any await. Timer
                    // cancellation of next() cannot lose an event or dependency.
                    self.staging = Some(Staged {
                        frame,
                        dependency: Box::pin(async move {
                            match sha {
                                Some(sha) => client.fetch(&sha).await.map(Some),
                                None => Ok(None),
                            }
                        }),
                    });
                }
                Err(error) => self.recover(error)?,
            }
        }
    }
    fn recover(&mut self, error: ClientError) -> Result<()> {
        self.available = false;
        // Drop speculative reads and retain only the durable resume boundary.
        self.incoming = Box::pin(futures_util::stream::empty());
        self.staging = None;
        if error.is_transient() && self.reconnect_attempts < self.client.config.retry.max_retries {
            let client = self.client.clone();
            let cursor = self.cursor.clone();
            let attempt = self.reconnect_attempts;
            self.reconnect_attempts += 1;
            self.reconnect = Some(Box::pin(async move {
                client.config.retry.wait(attempt).await;
                client.open(&cursor).await
            }));
            Ok(())
        } else {
            self.stopped = true;
            Err(error)
        }
    }
    fn stop(&mut self) {
        self.stopped = true;
        self.available = false;
        self.incoming = Box::pin(futures_util::stream::empty());
        self.staging = None;
        self.reconnect = None;
    }
    /// The hook must complete the durable application+cursor transaction, or verify
    /// that the caller already committed it. Failure stops this stream.
    pub async fn ack<F, Fut, E>(&mut self, cursor: &str, checkpoint: F) -> Result<()>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = std::result::Result<(), E>>,
        E: std::fmt::Display,
    {
        if self.stopped {
            return Err(ClientError::Stopped);
        }
        if self.pending.as_deref() != Some(cursor) {
            return Err(ClientError::AckOrder);
        }
        if let Err(error) = checkpoint().await {
            self.stop();
            return Err(ClientError::Checkpoint(error.to_string()));
        }
        self.cursor = cursor.to_owned();
        self.pending = None;
        self.reconnect_attempts = 0;
        Ok(())
    }
}

fn header<'a>(response: &'a Response, name: &str) -> Option<&'a str> {
    response.headers().get(name).and_then(|v| v.to_str().ok())
}
async fn body(mut response: Response, limit: usize) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(protocol("response_too_large"));
    }
    let mut body = Vec::new();
    while let Some(part) = response.chunk().await.map_err(network)? {
        if body.len() + part.len() > limit {
            return Err(protocol("response_too_large"));
        }
        body.extend_from_slice(&part);
    }
    Ok(body)
}

#[derive(Default)]
struct Sse {
    pending: BytesMut,
    kind: Option<String>,
    id: Option<String>,
    data: Vec<String>,
    size: usize,
}
impl Sse {
    fn line(&mut self, line: &[u8]) -> Result<Option<(String, String, String)>> {
        self.size += line.len() + 1;
        if self.size > v2::MAX_META {
            return Err(protocol("sse_event_too_large"));
        }
        let line = std::str::from_utf8(line)
            .map_err(|_| protocol("invalid_sse_utf8"))?
            .trim_end_matches('\r');
        if line.is_empty() {
            let result = (!self.data.is_empty()).then(|| {
                (
                    self.kind.take().unwrap_or_default(),
                    self.id.take().unwrap_or_default(),
                    self.data.join("\n"),
                )
            });
            self.kind = None;
            self.id = None;
            self.data.clear();
            self.size = 0;
            return Ok(result);
        }
        if line.starts_with(':') {
            return Ok(None);
        }
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => {
                if self.kind.is_some() {
                    return Err(protocol("duplicate_sse_event"));
                }
                self.kind = Some(value.into());
            }
            "id" => {
                if self.id.is_some() || value.contains('\0') {
                    return Err(protocol("invalid_sse_id"));
                }
                self.id = Some(value.into());
            }
            "data" => self.data.push(value.into()),
            _ => {}
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests;
