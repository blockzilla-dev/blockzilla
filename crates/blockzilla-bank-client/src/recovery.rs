//! Exact native recovery. This module creates no block store and never moves
//! an application cursor. Commit each checked frame with application data.
use crate::{
    BankEvent, ClientError, Frame, Result, RetryPolicy, SourceIdentity, admission, header, network,
    protocol,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use blockzilla_bank_stream_v2 as v2;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

/// Metadata from the pinned native feed. Slot numbers alone cannot identify a
/// frame, fork, control, skipped slot or an exact stream resume position.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryNotice {
    pub cursor: String,
    pub sha256: String,
    pub event: BankEvent,
    pub source: SourceIdentity,
}
impl RecoveryNotice {
    pub fn from_frame(frame: &Frame) -> Self {
        Self {
            cursor: frame.cursor.clone(),
            sha256: frame.sha256.clone(),
            event: frame.envelope.event.clone(),
            source: frame.source.clone(),
        }
    }
    fn validate_source(&self, source: &SourceIdentity) -> Result<()> {
        if &self.source != source {
            return Err(ClientError::Source("recovery_source_changed".into()));
        }
        self.source.validate().map_err(admission)?;
        self.event.validate().map_err(admission)?;
        let (session, sequence, digest) = v2::parse_cursor(&self.cursor).map_err(admission)?;
        if session != source.session_id
            || sequence != self.event.sequence
            || digest != self.sha256
            || !v2::is_digest(&self.sha256)
        {
            return Err(protocol("recovery_notice_identity_changed"));
        }
        Ok(())
    }
    /// Admit the exact next frame before any credentialed Worker request.
    pub fn validate(&self, source: &SourceIdentity, after: &str) -> Result<()> {
        self.validate_source(source)?;
        let (session, previous, _) = v2::parse_cursor(after).map_err(admission)?;
        if session != source.session_id {
            return Err(ClientError::Source("recovery_source_changed".into()));
        }
        if previous.checked_add(1) != Some(self.event.sequence) {
            return Err(ClientError::Gap {
                reason: "recovery_sequence_gap".into(),
                head: None,
            });
        }
        Ok(())
    }
    /// This is also required for original native control frames. A Worker
    /// archive bundle cannot satisfy this exact native-frame contract.
    pub fn validate_frame(&self, frame: &Frame) -> Result<()> {
        self.validate_source(&frame.source)?;
        if frame.cursor != self.cursor || frame.sha256 != self.sha256 {
            return Err(ClientError::Digest(
                "recovery_frame_identity_changed".into(),
            ));
        }
        if frame.envelope.event != self.event {
            return Err(protocol("recovery_event_changed"));
        }
        Ok(())
    }
}

/// The finite metadata plan contains block notices and original small controls.
/// Block payloads are fetched only through the configured Worker.
#[derive(Clone, Debug)]
pub struct RecoveryEntry {
    pub notice: RecoveryNotice,
    pub control: Option<Frame>,
}

/// No Debug implementation: this configuration owns a customer credential.
#[derive(Clone)]
pub struct WorkerRecoveryConfig {
    pub url: String,
    pub api_key: String,
    pub source: SourceIdentity,
    pub retry: RetryPolicy,
}
impl WorkerRecoveryConfig {
    pub fn new(url: impl Into<String>, api_key: impl Into<String>, source: SourceIdentity) -> Self {
        Self {
            url: url.into(),
            api_key: api_key.into(),
            source,
            retry: RetryPolicy {
                max_retries: 2,
                initial_delay: Duration::from_millis(250),
                max_delay: Duration::from_secs(2),
            },
        }
    }
}

/// Reuses one HTTP pool between recovery batches. The normal stream does not
/// call the Worker. There is no response cache or second persistent block copy.
#[derive(Clone)]
pub struct WorkerRecoveryClient {
    config: Arc<WorkerRecoveryConfig>,
    base: Url,
    http: Client,
    reads: Arc<Semaphore>,
}
impl WorkerRecoveryClient {
    pub fn new(config: WorkerRecoveryConfig) -> Result<Self> {
        Self::build(config, false)
    }
    fn build(config: WorkerRecoveryConfig, local_test: bool) -> Result<Self> {
        let base = Url::parse(&config.url)
            .map_err(|_| ClientError::Configuration("invalid_recovery_worker_url"))?;
        if !(base.scheme() == "https" || (local_test && base.scheme() == "http"))
            || base.path() != "/"
            || base.query().is_some()
            || base.fragment().is_some()
            || !base.username().is_empty()
            || base.password().is_some()
            || !(32..=256).contains(&config.api_key.len())
            || reqwest::header::HeaderValue::from_str(&format!("Bearer {}", config.api_key))
                .is_err()
            || config.retry.max_retries > 4
            || config.retry.initial_delay > config.retry.max_delay
            || config.retry.max_delay > Duration::from_secs(5)
        {
            return Err(ClientError::Configuration("invalid_recovery_worker_config"));
        }
        config.source.validate().map_err(admission)?;
        let http = Client::builder()
            .user_agent("blockzilla-bank-client/0.1")
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .read_timeout(Duration::from_secs(15))
            .build()
            .map_err(network)?;
        Ok(Self {
            config: Arc::new(config),
            base,
            http,
            reads: Arc::new(Semaphore::new(2)),
        })
    }
    pub fn source(&self) -> &SourceIdentity {
        &self.config.source
    }
    /// Fetch an exact original processed block. Expired native history, archive
    /// representations and source changes stop recovery without a cursor move.
    pub async fn fetch(&self, expected: &RecoveryNotice) -> Result<Frame> {
        expected.validate_source(self.source())?;
        if expected.event.kind != "block" {
            return Err(protocol("worker_recovery_requires_block_notice"));
        }
        tokio::time::timeout(Duration::from_secs(30), async {
            let _permit = self
                .reads
                .acquire()
                .await
                .map_err(|_| ClientError::Stopped)?;
            let mut attempt = 0;
            loop {
                match self.fetch_once(expected).await {
                    Err(error)
                        if error.is_transient() && attempt < self.config.retry.max_retries =>
                    {
                        self.config.retry.wait(attempt).await;
                        attempt += 1;
                    }
                    result => return result,
                }
            }
        })
        .await
        .map_err(|_| ClientError::Transient("worker_recovery_timeout".into()))?
    }
    async fn fetch_once(&self, expected: &RecoveryNotice) -> Result<Frame> {
        let bank = &expected.event.bank;
        let blockhash = bs58::encode(bank.blockhash).into_string();
        let parent_hash = bs58::encode(bank.parent_blockhash).into_string();
        let mut url = self
            .base
            .join(&format!("block/{}.compact", bank.slot))
            .map_err(|_| protocol("invalid_recovery_worker_path"))?;
        url.query_pairs_mut()
            .append_pair("blockhash", &blockhash)
            .append_pair("commitment", "processed")
            .append_pair("cursor", &expected.cursor)
            .append_pair("bank_id", &bank.bank_id.to_string())
            .append_pair("source_session", &expected.source.session_id);
        let mut response = self
            .http
            .get(url)
            .bearer_auth(&self.config.api_key)
            .send()
            .await
            .map_err(network)?;
        match response.status().as_u16() {
            200 => {}
            status @ (401 | 403) => return Err(ClientError::Authentication(status)),
            409 => {
                return Err(ClientError::Source(
                    "worker_recovery_identity_changed".into(),
                ));
            }
            404 | 410 => {
                return Err(ClientError::Gap {
                    reason: "worker_recovery_unavailable".into(),
                    head: None,
                });
            }
            status @ (429 | 500..=599) => {
                return Err(ClientError::Transient(format!(
                    "worker_recovery_http_{status}"
                )));
            }
            status => return Err(protocol(format!("worker_recovery_http_{status}"))),
        }
        for (name, value) in [
            ("content-type", "application/vnd.blockzilla.stream.v2"),
            ("x-blockzilla-source", "FOUNDATION_RECENT"),
            ("x-blockzilla-recovery-format", "native-bank-stream-v2"),
            ("x-blockzilla-commitment", "processed"),
            ("x-blockzilla-frame-sha256", expected.sha256.as_str()),
            ("x-blockzilla-cursor", expected.cursor.as_str()),
            ("x-blockzilla-blockhash", blockhash.as_str()),
            ("x-blockzilla-previous-blockhash", parent_hash.as_str()),
        ] {
            if response.headers().get_all(name).iter().count() != 1
                || header(&response, name) != Some(value)
            {
                return Err(protocol("worker_recovery_headers_changed"));
            }
        }
        let length = response
            .content_length()
            .filter(|length| (17..=v2::MAX_FRAME as u64).contains(length))
            .ok_or_else(|| protocol("worker_recovery_length_changed"))?
            as usize;
        let encoded = header(&response, "x-blockzilla-recent-metadata")
            .filter(|value| value.len() <= 16 * 1024)
            .ok_or_else(|| protocol("worker_recovery_metadata_missing"))?;
        let metadata_bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| protocol("worker_recovery_metadata_encoding"))?;
        if URL_SAFE_NO_PAD.encode(&metadata_bytes) != encoded {
            return Err(protocol("worker_recovery_metadata_encoding"));
        }
        let metadata: Metadata = serde_json::from_slice(&metadata_bytes)
            .map_err(|_| protocol("worker_recovery_metadata_invalid"))?;
        if metadata.version != 1
            || metadata.slot != bank.slot
            || metadata.bank_id != bank.bank_id
            || metadata.parent_slot != bank.parent_slot
            || metadata.blockhash != blockhash
            || metadata.parent_blockhash != parent_hash
            || metadata.cursor != expected.cursor
            || metadata.frame_sha256 != expected.sha256
            || metadata.source != expected.source
            || metadata.commitment != "processed"
        {
            return Err(protocol("worker_recovery_metadata_changed"));
        }
        // One bounded allocation is retained by Frame's Bytes. Complete-body
        // admission is required before an application cursor can advance.
        let mut wire = Vec::with_capacity(length);
        while let Some(part) = response.chunk().await.map_err(network)? {
            if wire.len() + part.len() > length {
                return Err(protocol("worker_recovery_length_changed"));
            }
            wire.extend_from_slice(&part);
        }
        if wire.len() != length {
            return Err(ClientError::Transient("worker_recovery_interrupted".into()));
        }
        // The shared decoder hashes each object and the whole frame once.
        let frame = v2::decode(wire.into()).map_err(admission)?;
        expected.validate_frame(&frame)?;
        Ok(frame)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    version: u16,
    slot: u64,
    blockhash: String,
    parent_slot: u64,
    parent_blockhash: String,
    bank_id: u64,
    source: SourceIdentity,
    cursor: String,
    frame_sha256: String,
    commitment: String,
}

#[cfg(test)]
mod tests;
