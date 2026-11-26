//! Optional authenticated Foundation disk lookup before the archive backend.
//!
//! A complete binary body stays in JavaScript. Its SHA-256 header describes a
//! broker-verified immutable cache object; this module does not hash an already
//! streaming binary body. JSON callers use `read_complete_verified` before
//! decoding. A cached resolution has no raw signatures. On a cache miss, the
//! Worker reads the archive ranges, collects typed IDs from the hot block and
//! sends only those IDs to `/v1/resolve`. Nothing here owns a native R2 binding.

use super::*;
pub(super) use crate::foundation_protocol::PendingLocatorV1;
use crate::foundation_protocol::ResolveRequestV1;
use crate::slot_resolution::{self, CheckedResolution, LocatorV1};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::time::Duration;
use wasm_bindgen::prelude::wasm_bindgen;
use worker::{ResponseBody, web_sys};
mod finalized;
mod recent;
pub(super) use finalized::{LedgerCompactMetadata, NativeArchiveV1, read_native_frame};
pub(super) use recent::{RecentMetadata, RecentOutcome, RecentRequest, RecentSource};

const PROTOCOL: &str = "1";
pub(super) const BUNDLE_TYPE: &str = "application/vnd.blockzilla.get-block-bundle.wincode";
pub(super) const RESOLUTION_TYPE: &str = "application/vnd.blockzilla.slot-resolution.wincode";
pub(super) const RESOLVE_REQUEST_TYPE: &str = "application/vnd.blockzilla.resolve-ids+json";
pub(super) const HOT_REQUEST_TYPE: &str = "application/vnd.blockzilla.compact-v2-hot.zstd";
const MAX_RESOLVE_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
const MAX_UNAVAILABLE_BYTES: usize = 4096;
const MAX_LOCATOR_HEADER_BYTES: usize = 4096;
const DEFAULT_HEADER_TIMEOUT_MS: u32 = 500;
const DEFAULT_BODY_TIMEOUT_MS: u32 = 5000;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone)]
pub(super) struct Config {
    endpoint: worker::Url,
    secret: String,
    prefix: String,
    generation: String,
    header_timeout_ms: u32,
    body_timeout_ms: u32,
    binary_uses_raw_block: bool,
    archive_lookup_mode: ArchiveLookupMode,
    finalized_source: Option<RecentSource>,
    native_finalized_min_slot: u64,
    native_producer_generation: Option<String>,
    native_archive_prefix: Option<String>,
    ledger_generation: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArchiveLookupMode {
    All,
    RecentOnly,
    Historical,
}

pub(super) enum Outcome {
    Native {
        response: Response,
        metadata: RecentMetadata,
        root: Vec<u8>,
        length: usize,
    },
    NativeArchive {
        record: NativeArchiveV1,
    },
    NativeUnavailable {
        status: u16,
        reason: String,
    },
    LedgerCompact {
        response: Response,
        metadata: LedgerCompactMetadata,
        length: usize,
        digest: [u8; 32],
    },
    Complete {
        response: Response,
        locator: LocatorV1,
        length: usize,
        digest: [u8; 32],
    },
    Resolution {
        checked: CheckedResolution,
        bytes: Vec<u8>,
    },
    /// A cache miss is not evidence that an archive slot is absent.
    NotCached {
        source: Option<PendingLocatorV1>,
    },
    Unavailable(Unavailable),
    TransportFailure(TransportFailure),
}

pub(super) enum ResolveOutcome {
    Resolved {
        checked: CheckedResolution,
        bytes: Vec<u8>,
    },
    Unavailable(Unavailable),
    TransportFailure(TransportFailure),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TransportFailure {
    HeaderTimeout,
    Network,
    BodyTimeout,
    BodyNetwork,
    ServerStatus(u16),
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Unavailable {
    Unavailable,
    Pruned,
    Incomplete,
    NotFinalized,
    CoverageUnavailable,
    SourceChanged,
    HashMismatch,
}

impl Unavailable {
    fn status(self) -> u16 {
        match self {
            Self::Unavailable | Self::CoverageUnavailable => 404,
            Self::Pruned => 410,
            Self::Incomplete | Self::NotFinalized | Self::SourceChanged | Self::HashMismatch => 409,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnavailableBody {
    version: u16,
    slot: u64,
    reason: Unavailable,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NotCachedBody {
    version: u16,
    slot: u64,
    reason: String,
    #[serde(default)]
    source: Option<PendingLocatorV1>,
}

#[derive(Debug, PartialEq, Eq)]
struct ResolveDiagnostics {
    cache: &'static str,
    pread_calls: u64,
    pread_bytes: u64,
    resolve_micros: Option<u64>,
}

enum Metadata {
    Complete {
        locator: LocatorV1,
        length: usize,
        digest: [u8; 32],
    },
    Resolution {
        locator: LocatorV1,
        length: usize,
        digest: [u8; 32],
    },
    Unavailable {
        length: usize,
        digest: [u8; 32],
        status: u16,
    },
    NotCached {
        length: usize,
        digest: [u8; 32],
    },
}

impl Config {
    pub(super) fn should_lookup_archive(&self, slot: u64, format: BlockResponseFormat) -> bool {
        match self.archive_lookup_mode {
            ArchiveLookupMode::All => true,
            ArchiveLookupMode::RecentOnly => false,
            ArchiveLookupMode::Historical => {
                format == BlockResponseFormat::Wincode || slot < self.native_finalized_min_slot
            }
        }
    }
    pub(super) fn body_timeout_ms(&self) -> u32 {
        self.body_timeout_ms
    }

    pub(super) fn binary_uses_raw_block(&self) -> bool {
        self.binary_uses_raw_block
    }

    pub(super) fn generation(&self) -> &str {
        &self.generation
    }

    /// Source lookup cache scope. Credentials are deliberately excluded.
    pub(super) fn cache_identity(&self) -> String {
        format!("{}|{}|{}", self.endpoint, self.prefix, self.generation)
    }

    pub(super) fn from_env(
        env: &worker::Env,
        archive_prefix: &str,
    ) -> std::result::Result<Option<Self>, String> {
        let endpoint = optional_var(env, "BZ_FOUNDATION_LOOKUP_URL");
        let secret = optional_var(env, "BZ_FOUNDATION_LOOKUP_SECRET");
        let generation = optional_var(env, "BZ_FOUNDATION_LOOKUP_GENERATION");
        if endpoint.is_none() && secret.is_none() && generation.is_none() {
            return Ok(None);
        }
        let endpoint =
            endpoint.ok_or("Foundation lookup URL, secret and generation are required together")?;
        let secret =
            secret.ok_or("Foundation lookup URL, secret and generation are required together")?;
        let generation = generation
            .ok_or("Foundation lookup URL, secret and generation are required together")?;
        let mut config = Self::parse(
            &endpoint,
            secret,
            archive_prefix,
            generation,
            optional_var(env, "BZ_FOUNDATION_LOOKUP_TIMEOUT_MS").as_deref(),
            optional_var(env, "BZ_FOUNDATION_LOOKUP_BODY_TIMEOUT_MS").as_deref(),
            false,
        )?;
        config.binary_uses_raw_block =
            binary_mode(optional_var(env, "BZ_FOUNDATION_BINARY_RESOLVE_MODE").as_deref())?;
        config.archive_lookup_mode =
            archive_lookup_mode(optional_var(env, "BZ_FOUNDATION_LOOKUP_MODE").as_deref())?;
        config.configure_finalized(env)?;
        if config.archive_lookup_mode == ArchiveLookupMode::Historical
            && config.native_finalized_min_slot == 0
        {
            return Err("Historical Foundation lookup requires a nonzero native slot floor".into());
        }
        Ok(Some(config))
    }

    fn parse(
        endpoint: &str,
        secret: String,
        prefix: &str,
        generation: String,
        header_timeout: Option<&str>,
        body_timeout: Option<&str>,
        allow_test_loopback: bool,
    ) -> std::result::Result<Self, String> {
        let mut endpoint =
            worker::Url::parse(endpoint).map_err(|_| "invalid Foundation lookup URL")?;
        let loopback = cfg!(test)
            && allow_test_loopback
            && endpoint.scheme() == "http"
            && matches!(
                endpoint.host_str(),
                Some("127.0.0.1" | "localhost" | "[::1]")
            );
        if (endpoint.scheme() != "https" && !loopback)
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !matches!(endpoint.path(), "" | "/" | "/v1/block" | "/v1/block/")
        {
            return Err(
                "Foundation lookup URL must be an HTTPS origin or /v1/block endpoint".into(),
            );
        }
        if !(32..=1024).contains(&secret.len()) || !secret.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(
                "Foundation lookup secret must contain 32 to 1024 visible ASCII bytes".into(),
            );
        }
        if prefix.is_empty()
            || prefix.len() > 512
            || prefix
                .split('/')
                .any(|p| p.is_empty() || p == "." || p == "..")
            || !prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
        {
            return Err("Foundation lookup source prefix is invalid".into());
        }
        if generation.is_empty()
            || generation.len() > 128
            || !generation
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err("Foundation lookup generation is invalid".into());
        }
        endpoint.set_path("/v1/block/");
        Ok(Self {
            endpoint,
            secret,
            prefix: prefix.into(),
            generation,
            header_timeout_ms: timeout(header_timeout, DEFAULT_HEADER_TIMEOUT_MS)?,
            body_timeout_ms: timeout(body_timeout, DEFAULT_BODY_TIMEOUT_MS)?,
            binary_uses_raw_block: true,
            archive_lookup_mode: ArchiveLookupMode::All,
            finalized_source: None,
            native_finalized_min_slot: 0,
            native_producer_generation: None,
            native_archive_prefix: None,
            ledger_generation: None,
        })
    }

    fn plan(
        &self,
        slot: u64,
        read_mode: &'static str,
    ) -> std::result::Result<(String, Vec<(&'static str, String)>), String> {
        if slot > MAX_SAFE_INTEGER {
            return Err("Foundation lookup slot exceeds its bound".into());
        }
        let mut url = self.endpoint.clone();
        url.set_path(&format!("/v1/block/{slot}"));
        Ok((
            url.into(),
            vec![
                ("Authorization", format!("Bearer {}", self.secret)),
                (
                    "Accept",
                    format!("{BUNDLE_TYPE}, {RESOLUTION_TYPE}, application/json"),
                ),
                ("Accept-Encoding", "identity".into()),
                ("Cache-Control", "no-store".into()),
                ("X-BZ-Foundation-Protocol", PROTOCOL.into()),
                ("X-BZ-Foundation-Generation", self.generation.clone()),
                ("X-BZ-Foundation-Source-Prefix", self.prefix.clone()),
                ("X-BZ-Foundation-Read-Mode", read_mode.into()),
            ],
        ))
    }

    /// Err means a protocol/auth/identity failure and must fail closed. Only
    /// the explicit TransportFailure outcome permits a checked archive fallback.
    pub(super) async fn lookup(
        &self,
        source: &WorkerSource,
        slot: u64,
    ) -> std::result::Result<Outcome, String> {
        let (url, headers) = self.plan(slot, read_mode(source))?;
        self.execute(source, slot, url, headers, None, None, "lookup")
            .await
    }

    /// Resolve only IDs collected from the exact hot bytes read by the Worker.
    /// No hot payload or signature bytes are sent to the broker. The complete
    /// request digest binds the reply to its source row, hash and typed ID sets.
    pub(super) async fn resolve_ids(
        &self,
        source: &WorkerSource,
        request: &ResolveRequestV1,
    ) -> std::result::Result<ResolveOutcome, String> {
        let slot = request.references.slot;
        request.validate(&self.prefix, &self.generation, slot)?;
        let body = serde_json::to_string(request)
            .map_err(|_| "cannot encode Foundation ID resolution request")?;
        if body.len() > MAX_RESOLVE_REQUEST_BYTES {
            return Err("Foundation ID resolution request exceeds its byte bound".into());
        }
        let request_digest = hex_lower(&native_hash::sha256(body.as_bytes()).await?);
        let (url, headers) = self.resolve_plan(slot, read_mode(source), &request_digest)?;
        let outcome = self
            .execute(
                source,
                slot,
                url,
                headers,
                Some(body.into()),
                Some(&request_digest),
                "resolve_ids",
            )
            .await?;
        match outcome {
            Outcome::Resolution { checked, bytes } => {
                validate_resolved(&request.source, &request.references, &checked)?;
                Ok(ResolveOutcome::Resolved { checked, bytes })
            }
            Outcome::Unavailable(reason) => Ok(ResolveOutcome::Unavailable(reason)),
            Outcome::TransportFailure(reason) => Ok(ResolveOutcome::TransportFailure(reason)),
            Outcome::NotCached { .. }
            | Outcome::Complete { .. }
            | Outcome::Native { .. }
            | Outcome::NativeArchive { .. }
            | Outcome::NativeUnavailable { .. }
            | Outcome::LedgerCompact { .. } => {
                Err("Foundation ID resolution returned an invalid result type".into())
            }
        }
    }

    /// Forward the original native hot stream. Only its already-computed
    /// SHA256 and the checked response metadata enter WASM; the hot bytes do
    /// not. The authenticated broker owns hot decoding and ID collection.
    pub(super) async fn resolve_block(
        &self,
        source: &WorkerSource,
        pending: &PendingLocatorV1,
        hot_sha256: &str,
        body: ResponseBody,
    ) -> std::result::Result<ResolveOutcome, String> {
        let slot = pending.hot.slot;
        pending.validate(&self.prefix, &self.generation, slot)?;
        digest(hot_sha256)?;
        ensure_js_safe_range(
            pending.hot.compressed_offset,
            pending.hot.compressed_len as usize,
        )?;
        let ResponseBody::Stream(stream) = body else {
            return Err("Foundation raw-block request requires a native body stream".into());
        };
        let (url, headers) = self.resolve_block_plan(slot, read_mode(source), hot_sha256)?;
        let outcome = self
            .execute(
                source,
                slot,
                url,
                headers,
                Some(stream.into()),
                Some(hot_sha256),
                "resolve_block",
            )
            .await?;
        match outcome {
            Outcome::Resolution { checked, bytes } => {
                validate_resolved_source(pending, &checked)?;
                Ok(ResolveOutcome::Resolved { checked, bytes })
            }
            Outcome::Unavailable(reason) => Ok(ResolveOutcome::Unavailable(reason)),
            Outcome::TransportFailure(reason) => Ok(ResolveOutcome::TransportFailure(reason)),
            Outcome::NotCached { .. }
            | Outcome::Complete { .. }
            | Outcome::Native { .. }
            | Outcome::NativeArchive { .. }
            | Outcome::NativeUnavailable { .. }
            | Outcome::LedgerCompact { .. } => {
                Err("Foundation raw-block resolution returned an invalid result type".into())
            }
        }
    }

    fn resolve_block_plan(
        &self,
        slot: u64,
        read_mode: &'static str,
        request_digest: &str,
    ) -> std::result::Result<(String, Vec<(&'static str, String)>), String> {
        let (_, mut headers) = self.resolve_plan(slot, read_mode, request_digest)?;
        let mut url = self.endpoint.clone();
        url.set_path(&format!("/v1/resolve-block/{slot}"));
        headers
            .iter_mut()
            .find(|(name, _)| *name == "Content-Type")
            .expect("Foundation content type")
            .1 = HOT_REQUEST_TYPE.into();
        Ok((url.into(), headers))
    }

    fn resolve_plan(
        &self,
        slot: u64,
        read_mode: &'static str,
        request_digest: &str,
    ) -> std::result::Result<(String, Vec<(&'static str, String)>), String> {
        digest(request_digest)?;
        let (_, mut headers) = self.plan(slot, read_mode)?;
        let mut url = self.endpoint.clone();
        url.set_path("/v1/resolve");
        let accept = headers
            .iter_mut()
            .find(|(name, _)| *name == "Accept")
            .expect("common Foundation accept header");
        accept.1 = format!("{RESOLUTION_TYPE}, application/json");
        headers.push(("Content-Type", RESOLVE_REQUEST_TYPE.into()));
        headers.push(("X-BZ-Foundation-Request-SHA256", request_digest.into()));
        Ok((url.into(), headers))
    }

    async fn execute(
        &self,
        source: &WorkerSource,
        slot: u64,
        url: String,
        plan: Vec<(&'static str, String)>,
        body: Option<JsValue>,
        request_digest: Option<&str>,
        operation: &'static str,
    ) -> std::result::Result<Outcome, String> {
        if source.archive_prefix != self.prefix {
            return Err("Foundation lookup source differs from configuration".into());
        }
        let headers = Headers::new();
        for (name, value) in plan {
            headers
                .set(name, &value)
                .map_err(|_| "invalid Foundation request headers")?;
        }
        let mut init = RequestInit::new();
        init.with_method(if body.is_some() {
            Method::Post
        } else {
            Method::Get
        })
        .with_headers(headers)
        .with_redirect(worker::RequestRedirect::Manual);
        if let Some(body) = body {
            init.with_body(Some(body));
        }
        let request =
            Request::new_with_init(&url, &init).map_err(|_| "invalid Foundation lookup request")?;
        let controller = web_sys::AbortController::new()
            .map_err(|_| "cannot create Foundation lookup cancellation")?;
        let signal = worker::AbortSignal::from(controller.signal());
        let started = now_ms();
        let transport = Fetch::Request(request);
        let fetch = transport.send_with_signal(&signal);
        let fetched = future::select(
            Box::pin(fetch),
            Box::pin(worker::Delay::from(Duration::from_millis(
                self.header_timeout_ms.into(),
            ))),
        )
        .await;
        let response = match fetched {
            future::Either::Left((Ok(response), _)) => response,
            future::Either::Left((Err(_), _)) => {
                controller.abort();
                return Ok(Outcome::TransportFailure(TransportFailure::Network));
            }
            future::Either::Right(_) => {
                controller.abort();
                return Ok(Outcome::TransportFailure(TransportFailure::HeaderTimeout));
            }
        };
        let status = response.status_code();
        source.record_elapsed(
            match operation {
                "resolve_ids" | "resolve_block" => "foundation_resolve_headers",
                _ => "foundation_lookup_headers",
            },
            started,
            0,
            "native_disk_broker",
            Some(status),
        );
        let tagged = response
            .headers()
            .get("X-BZ-Foundation-Result")
            .map_err(|_| "invalid Foundation response headers")?;
        if let Some(failure) = server_failure(status, tagged.as_deref()) {
            controller.abort();
            return Ok(Outcome::TransportFailure(failure));
        }
        if let Some(expected) = request_digest {
            let actual = response
                .headers()
                .get("X-BZ-Foundation-Request-SHA256")
                .map_err(|_| "invalid Foundation response headers")?;
            // Never create a complete streaming outcome for a POST result.
            // This also cancels its unread upstream body before failing closed.
            if let Err(error) =
                validate_resolve_binding(expected, actual.as_deref(), tagged.as_deref())
            {
                controller.abort();
                return Err(error);
            }
        }
        let metadata = match self.metadata(status, slot, |name| {
            response.headers().get(name).ok().flatten()
        }) {
            Ok(value) => value,
            Err(error) => {
                controller.abort();
                return Err(error);
            }
        };
        let diagnostics = if matches!(operation, "resolve_ids" | "resolve_block") {
            resolve_diagnostics(|name| response.headers().get(name).ok().flatten())
        } else {
            None
        };
        let length = match &metadata {
            Metadata::Complete { length, .. }
            | Metadata::Resolution { length, .. }
            | Metadata::Unavailable { length, .. }
            | Metadata::NotCached { length, .. } => *length,
        };
        let mut response =
            match bounded_response(response, length, self.body_timeout_ms, &controller) {
                Ok(value) => value,
                Err(error) => {
                    controller.abort();
                    return Err(error);
                }
            };
        if let Metadata::Complete {
            locator,
            length,
            digest,
        } = metadata
        {
            // The caller can forward this exact-length, cancellable native
            // stream. SHA identity is trusted broker metadata, as documented.
            return Ok(Outcome::Complete {
                response,
                locator,
                length,
                digest,
            });
        }
        let bytes = match response.bytes().await {
            Ok(value) => value,
            Err(error) => return body_error(&error.to_string()),
        };
        let (digest, locator) = match &metadata {
            Metadata::Resolution {
                digest, locator, ..
            } => (*digest, Some(locator)),
            Metadata::Unavailable { digest, .. } | Metadata::NotCached { digest, .. } => {
                (*digest, None)
            }
            Metadata::Complete { .. } => unreachable!(),
        };
        if bytes.len() != length || native_hash::sha256(&bytes).await? != digest {
            return Err("Foundation delivered body differs from its SHA256 or length".into());
        }
        if let Some(locator) = locator {
            let payload = slot_resolution::payload_for_digest(&bytes)?;
            let payload_digest = native_hash::sha256(payload).await?;
            let checked =
                slot_resolution::decode_checked_with_payload_digest(&bytes, payload_digest)?;
            checked.validate(&self.prefix, &self.generation, slot)?;
            if checked.locator_ref() != locator {
                return Err("Foundation resolution differs from its locator header".into());
            }
            source.record_elapsed(
                match operation {
                    "resolve_ids" | "resolve_block" => "foundation_resolve_resolution",
                    _ => "foundation_lookup_resolution",
                },
                started,
                bytes.len() as u64,
                "checked_body_no_signatures",
                Some(status),
            );
            if let Some(diagnostics) = diagnostics {
                // Authenticated service diagnostics are profiling data only.
                // They never alter the Worker's own R2 operation counters.
                source.record_elapsed(
                    "foundation_resolve_cache",
                    now_ms(),
                    diagnostics.pread_bytes,
                    format!(
                        "cache={};pread_calls={};resolve_us={}",
                        diagnostics.cache,
                        diagnostics.pread_calls,
                        diagnostics
                            .resolve_micros
                            .map_or_else(|| "missing".into(), |n| n.to_string())
                    ),
                    Some(status),
                );
            }
            Ok(Outcome::Resolution { checked, bytes })
        } else if matches!(metadata, Metadata::NotCached { .. }) {
            let source = validate_not_cached(&self.prefix, &self.generation, slot, &bytes)?;
            Ok(Outcome::NotCached { source })
        } else {
            Ok(Outcome::Unavailable(validate_unavailable(
                status, slot, &bytes,
            )?))
        }
    }

    fn metadata(
        &self,
        status: u16,
        slot: u64,
        mut get: impl FnMut(&str) -> Option<String>,
    ) -> std::result::Result<Metadata, String> {
        if matches!(status, 300..=399 | 401 | 403) {
            return Err("Foundation lookup rejected authentication or redirected".into());
        }
        let required = |get: &mut dyn FnMut(&str) -> Option<String>, name: &str| {
            get(name).ok_or_else(|| format!("missing Foundation response header {name}"))
        };
        if required(&mut get, "X-BZ-Foundation-Protocol")? != PROTOCOL
            || required(&mut get, "X-BZ-Foundation-Generation")? != self.generation
            || required(&mut get, "X-BZ-Foundation-Source-Prefix")? != self.prefix
        {
            return Err("Foundation response protocol or source identity differs".into());
        }
        if get("Content-Encoding").is_some_and(|v| v != "identity") {
            return Err("Foundation body must use identity content encoding".into());
        }
        let result = required(&mut get, "X-BZ-Foundation-Result")?;
        let content_type = required(&mut get, "Content-Type")?;
        let length_text = required(&mut get, "Content-Length")?;
        let length = length_text
            .parse::<usize>()
            .map_err(|_| "invalid Foundation body length")?;
        if length == 0 || length.to_string() != length_text {
            return Err("invalid Foundation body length".into());
        }
        let digest = digest(&required(&mut get, "X-BZ-Foundation-SHA256")?)?;
        if result == "unavailable" || result == "not_cached" {
            if !(if result == "not_cached" {
                status == 404
            } else {
                matches!(status, 404 | 409 | 410)
            }) || content_type != "application/json"
                || length > MAX_UNAVAILABLE_BYTES
            {
                return Err("invalid Foundation unavailable response".into());
            }
            if result == "not_cached" {
                return Ok(Metadata::NotCached { length, digest });
            }
            return Ok(Metadata::Unavailable {
                length,
                digest,
                status,
            });
        }
        if status != 200 || required(&mut get, "X-BZ-Foundation-Commitment")? != "finalized" {
            return Err("Foundation block is not an admitted finalized response".into());
        }
        let text = required(&mut get, "X-BZ-Foundation-Locator")?;
        if text.is_empty() || text.len() > MAX_LOCATOR_HEADER_BYTES || text.contains('=') {
            return Err("Foundation locator header exceeds its bounds or is not canonical".into());
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&text)
            .map_err(|_| "invalid Foundation locator header")?;
        if URL_SAFE_NO_PAD.encode(&bytes) != text {
            return Err("Foundation locator header is not canonical".into());
        }
        let locator: LocatorV1 = wincode::config::deserialize_exact(
            &bytes,
            blockzilla_primitives::bounded_wincode_leb128_config::<MAX_LOCATOR_HEADER_BYTES>(),
        )
        .map_err(|_| "invalid Foundation locator payload")?;
        locator.validate(&self.prefix, &self.generation, slot)?;
        ensure_js_safe_range(
            locator.hot.compressed_offset,
            locator.hot.compressed_len as usize,
        )?;
        let signature_bytes = locator.signature_bytes()?;
        // A rewards-only block has no signature range to request.
        if signature_bytes != 0 {
            ensure_js_safe_range(locator.signature_offset()?, signature_bytes)?;
        }
        match result.as_str() {
            "complete"
                if content_type == BUNDLE_TYPE
                    && length <= MAX_BUNDLE_BYTES
                    && required(&mut get, "X-BZ-Foundation-Signatures")? == "embedded"
                    && required(&mut get, "X-BZ-Foundation-Object-Verified")? == "sha256" =>
            {
                let minimum = (locator.hot.compressed_len as usize)
                    .checked_add(signature_bytes)
                    .and_then(|n| n.checked_add(74))
                    .ok_or("Foundation complete body length overflows")?;
                if length < minimum {
                    return Err(
                        "Foundation complete body is smaller than its payload ranges".into(),
                    );
                }
                Ok(Metadata::Complete {
                    locator,
                    length,
                    digest,
                })
            }
            "resolution"
                if content_type == RESOLUTION_TYPE
                    && (slot_resolution::HEADER_LEN..=slot_resolution::MAX_RESOLUTION_BYTES)
                        .contains(&length)
                    && required(&mut get, "X-BZ-Foundation-Signatures")? == "archive" =>
            {
                Ok(Metadata::Resolution {
                    locator,
                    length,
                    digest,
                })
            }
            _ => Err("Foundation result type, signature mode or body bounds differ".into()),
        }
    }
}

fn read_mode(source: &WorkerSource) -> &'static str {
    match source.profile.as_ref() {
        None => "normal",
        Some(p) if p.source_ranges_only() => "source",
        Some(_) => "full-cold",
    }
}

fn archive_lookup_mode(value: Option<&str>) -> std::result::Result<ArchiveLookupMode, String> {
    match value {
        None | Some("all") => Ok(ArchiveLookupMode::All),
        Some("recent-only") => Ok(ArchiveLookupMode::RecentOnly),
        Some("historical") => Ok(ArchiveLookupMode::Historical),
        _ => Err("Foundation lookup mode must be all, recent-only, or historical".into()),
    }
}

fn binary_mode(value: Option<&str>) -> std::result::Result<bool, String> {
    match value.unwrap_or("block") {
        "block" => Ok(true),
        "ids" => Ok(false),
        _ => Err("BZ_FOUNDATION_BINARY_RESOLVE_MODE must be block or ids".into()),
    }
}

fn validate_resolve_binding(
    expected: &str,
    actual: Option<&str>,
    result: Option<&str>,
) -> std::result::Result<(), String> {
    if actual != Some(expected) {
        return Err("Foundation resolution response request digest differs".into());
    }
    if !matches!(result, Some("resolution" | "unavailable")) {
        return Err("Foundation ID resolution returned an invalid result type".into());
    }
    Ok(())
}

fn resolve_diagnostics(mut get: impl FnMut(&str) -> Option<String>) -> Option<ResolveDiagnostics> {
    let cache = match get("X-BZ-Foundation-Cache")?.as_str() {
        "HIT" => "HIT",
        "MISS" => "MISS",
        "BYPASS" => "BYPASS",
        _ => return None,
    };
    let count = |value: String, maximum: u64| {
        if value.is_empty() || value.len() > 10 {
            return None;
        }
        let n = value.parse::<u64>().ok()?;
        (n <= maximum && n.to_string() == value).then_some(n)
    };
    Some(ResolveDiagnostics {
        cache,
        pread_calls: count(get("X-BZ-Foundation-Pread-Calls")?, 1_000_000)?,
        pread_bytes: count(get("X-BZ-Foundation-Pread-Bytes")?, 1024 * 1024 * 1024)?,
        resolve_micros: get("X-BZ-Foundation-Resolve-Micros").and_then(|v| count(v, 10_000_000)),
    })
}

fn validate_resolved(
    source: &PendingLocatorV1,
    references: &crate::slot_references::SlotReferences,
    checked: &CheckedResolution,
) -> std::result::Result<(), String> {
    validate_resolved_source(source, checked)?;
    let locator = checked.locator_ref();
    if locator.parent_slot != references.parent_slot
        || checked.signature_counts() != references.signature_counts
    {
        return Err("Foundation ID resolution differs from requested block header".into());
    }
    crate::slot_references::validate_resolution(checked, references)
}

fn validate_resolved_source(
    source: &PendingLocatorV1,
    checked: &CheckedResolution,
) -> std::result::Result<(), String> {
    let locator = checked.locator_ref();
    if locator.version != source.version
        || locator.source_prefix != source.source_prefix
        || locator.generation != source.generation
        || locator.epoch != source.epoch
        || locator.hot != source.hot
        || locator.message_schema != source.message_schema
        || locator.metadata_schema != source.metadata_schema
        || locator.blocks != source.blocks
        || locator.signatures != source.signatures
    {
        return Err("Foundation ID resolution differs from requested source or block".into());
    }
    Ok(())
}

fn validate_not_cached(
    prefix: &str,
    generation: &str,
    slot: u64,
    bytes: &[u8],
) -> std::result::Result<Option<PendingLocatorV1>, String> {
    let body: NotCachedBody =
        serde_json::from_slice(bytes).map_err(|_| "invalid Foundation cache-miss body")?;
    if body.version != 1 || body.slot != slot || body.reason != "not_cached" {
        return Err("Foundation cache-miss body differs from request".into());
    }
    if let Some(source) = &body.source {
        source.validate(prefix, generation, slot)?;
        ensure_js_safe_range(
            source.hot.compressed_offset,
            source.hot.compressed_len as usize,
        )?;
        if source.hot.signature_count != 0 {
            ensure_js_safe_range(
                source
                    .hot
                    .first_signature_ordinal
                    .checked_mul(64)
                    .ok_or("Foundation signature offset overflows")?,
                (source.hot.signature_count as usize)
                    .checked_mul(64)
                    .ok_or("Foundation signature length overflows")?,
            )?;
        }
    }
    Ok(body.source)
}

fn timeout(text: Option<&str>, default: u32) -> std::result::Result<u32, String> {
    let n = text
        .map(|v| {
            v.parse::<u32>()
                .map_err(|_| "invalid Foundation lookup timeout")
        })
        .transpose()?
        .unwrap_or(default);
    if !(100..=10_000).contains(&n) {
        return Err("Foundation lookup timeout must be 100 to 10000 milliseconds".into());
    }
    Ok(n)
}

fn digest(text: &str) -> std::result::Result<[u8; 32], String> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Foundation SHA256 must contain 64 lower-case hex digits".into());
    }
    let mut result = [0; 32];
    for (out, pair) in result.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let digit = |b| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        *out = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(result)
}

fn body_error(error: &str) -> std::result::Result<Outcome, String> {
    if error.contains("BZ_FOUNDATION_BODY_TIMEOUT") {
        Ok(Outcome::TransportFailure(TransportFailure::BodyTimeout))
    } else if error.contains("BZ_FOUNDATION_BODY_NETWORK") {
        Ok(Outcome::TransportFailure(TransportFailure::BodyNetwork))
    } else {
        Err("Foundation body failed its framing or length checks".into())
    }
}

fn server_failure(status: u16, result: Option<&str>) -> Option<TransportFailure> {
    // Untagged availability errors can use the checked archive fallback.
    // Tagged responses must pass identity checks even on an error status.
    (result.is_none() && matches!(status, 408 | 429 | 500 | 502 | 503 | 504))
        .then_some(TransportFailure::ServerStatus(status))
}

fn validate_unavailable(
    status: u16,
    slot: u64,
    bytes: &[u8],
) -> std::result::Result<Unavailable, String> {
    let parsed: UnavailableBody =
        serde_json::from_slice(bytes).map_err(|_| "invalid Foundation unavailable body")?;
    if parsed.version != 1 || parsed.slot != slot || parsed.reason.status() != status {
        return Err("Foundation unavailable body differs from request or status".into());
    }
    if matches!(
        parsed.reason,
        Unavailable::SourceChanged | Unavailable::HashMismatch
    ) {
        return Err("Foundation reported a source or block identity mismatch".into());
    }
    Ok(parsed.reason)
}

/// JSON consumes a complete bounded bundle and checks its delivered SHA before
/// the caller parses it. Binary callers must not use this buffering helper.
pub(super) async fn read_complete_verified(
    mut response: Response,
    length: usize,
    expected: [u8; 32],
) -> std::result::Result<Vec<u8>, String> {
    if length == 0 || length > MAX_BUNDLE_BYTES {
        return Err("Foundation bundle exceeds its bounds".into());
    }
    let bytes = response.bytes().await.map_err(|e| e.to_string())?;
    if bytes.len() != length || native_hash::sha256(&bytes).await? != expected {
        return Err("Foundation complete body differs from its SHA256 or length".into());
    }
    Ok(bytes)
}

fn bounded_response(
    response: Response,
    length: usize,
    timeout_ms: u32,
    controller: &web_sys::AbortController,
) -> std::result::Result<Response, String> {
    let (init, body) = response.into_parts();
    let ResponseBody::Stream(body) = body else {
        return Err("Foundation requires a native body stream".into());
    };
    let stream = deadline_body(&body, length as f64, timeout_ms as f64, controller.as_ref())
        .map_err(|_| "cannot bound Foundation body stream")?;
    Ok(init.stream(stream))
}

#[wasm_bindgen(inline_js = r#"
// Only upstream read wait consumes the budget. Client backpressure does not.
export function bzFoundationDeadlineBody(body, expected, budgetMs, abortController) {
    if (!body || typeof body.getReader !== 'function' || body.locked
        || !Number.isSafeInteger(expected) || expected <= 0 || expected > 16 + 65536 + 16 * 1024 * 1024
        || !Number.isInteger(budgetMs) || budgetMs <= 0 || budgetMs > 10000) {
        throw new TypeError('BZ_FOUNDATION_BODY_CONFIG');
    }
    let reader = null, received = 0, done = false, remaining = budgetMs, timer = null;
    function clear() { if (timer !== null) { clearTimeout(timer); timer = null; } }
    async function cancel(reason) {
        clear(); done = true; abortController.abort(reason);
        if (reader !== null) {
            try { await reader.cancel(reason); } catch (_) {}
            try { reader.releaseLock(); } catch (_) {}
            reader = null;
        } else { try { await body.cancel(reason); } catch (_) {} }
    }
    return new ReadableStream({
        async pull(controller) {
            let empty = 0;
            try {
                if (reader === null) reader = body.getReader();
                while (!done) {
                    const started = Date.now();
                    timer = setTimeout(() => {
                        const error = new Error('BZ_FOUNDATION_BODY_TIMEOUT');
                        if (!done) { controller.error(error); void cancel(error); }
                    }, remaining);
                    let next;
                    try { next = await reader.read(); }
                    catch (_) { if (!done) throw new Error('BZ_FOUNDATION_BODY_NETWORK'); else return; }
                    clear(); remaining -= Math.max(0, Date.now() - started);
                    if (done) return;
                    if (next.done) {
                        if (received !== expected) throw new RangeError('BZ_FOUNDATION_BODY_LENGTH');
                        done = true; reader.releaseLock(); reader = null; controller.close(); return;
                    }
                    if (!(next.value instanceof Uint8Array) || next.value.byteLength > expected - received) {
                        throw new RangeError('BZ_FOUNDATION_BODY_LENGTH');
                    }
                    if (remaining <= 0) throw new Error('BZ_FOUNDATION_BODY_TIMEOUT');
                    received += next.value.byteLength;
                    if (!next.value.byteLength) {
                        if (++empty > 1024) throw new Error('BZ_FOUNDATION_BODY_PROGRESS');
                        continue;
                    }
                    controller.enqueue(next.value); return;
                }
            } catch (error) {
                if (!done) controller.error(error);
                await cancel(error);
            }
        },
        cancel(reason) { return cancel(reason); }
    }, { highWaterMark: 0 });
}
"#)]
extern "C" {
    #[wasm_bindgen(catch, js_name = bzFoundationDeadlineBody)]
    fn deadline_body(
        body: &web_sys::ReadableStream,
        expected: f64,
        budget_ms: f64,
        controller: &JsValue,
    ) -> std::result::Result<web_sys::ReadableStream, JsValue>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config::parse(
            "https://foundation.example",
            "local_fixture_secret_abcdefghijklmnopqrstuvwxyz".into(),
            "compact-v2/test",
            "generation-1".into(),
            None,
            None,
            false,
        )
        .unwrap()
    }

    fn locator() -> LocatorV1 {
        use crate::slot_resolution::{ResolutionHotRow, SourceObjectIdentity};
        LocatorV1 {
            version: 1,
            source_prefix: "compact-v2/test".into(),
            generation: "generation-1".into(),
            epoch: 1,
            hot: ResolutionHotRow {
                block_id: 0,
                slot: 432000,
                compressed_offset: 100,
                compressed_len: 200,
                uncompressed_len: 300,
                tx_count: 1,
                first_tx_ordinal: 0,
                first_signature_ordinal: 0,
                signature_count: 2,
            },
            parent_slot: 431999,
            blockhash: [11; 32],
            previous_blockhash: [10; 32],
            message_schema: 0,
            metadata_schema: 0,
            blocks: SourceObjectIdentity {
                length: 1000,
                etag: "\"blocks-1\"".into(),
            },
            signatures: SourceObjectIdentity {
                length: 128,
                etag: "\"signatures-1\"".into(),
            },
        }
    }

    fn headers() -> BTreeMap<String, String> {
        [
            ("X-BZ-Foundation-Protocol", "1".into()),
            ("X-BZ-Foundation-Generation", "generation-1".into()),
            ("X-BZ-Foundation-Source-Prefix", "compact-v2/test".into()),
            ("X-BZ-Foundation-Result", "complete".into()),
            ("X-BZ-Foundation-Commitment", "finalized".into()),
            ("Content-Type", BUNDLE_TYPE.into()),
            ("Content-Length", "500".into()),
            ("X-BZ-Foundation-SHA256", "ab".repeat(32)),
            (
                "X-BZ-Foundation-Locator",
                URL_SAFE_NO_PAD.encode(locator().wincode_bytes().unwrap()),
            ),
            ("X-BZ-Foundation-Signatures", "embedded".into()),
            ("X-BZ-Foundation-Object-Verified", "sha256".into()),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v))
        .collect()
    }

    fn resolve_request() -> ResolveRequestV1 {
        let locator = locator();
        ResolveRequestV1 {
            version: 1,
            source: PendingLocatorV1 {
                version: locator.version,
                source_prefix: locator.source_prefix,
                generation: locator.generation,
                epoch: locator.epoch,
                hot: locator.hot,
                message_schema: locator.message_schema,
                metadata_schema: locator.metadata_schema,
                blocks: locator.blocks,
                signatures: locator.signatures,
            },
            hot_sha256: "ab".repeat(32),
            references: crate::slot_references::SlotReferences {
                slot: 432000,
                parent_slot: 431999,
                blockhash_id: 0,
                previous_blockhash_id: 0,
                signature_counts: vec![2],
                pubkeys: vec![1],
                blockhashes: vec![-1, 0],
                votes: vec![],
            },
        }
    }

    fn checked_resolution(current: [u8; 32], previous: [u8; 32]) -> CheckedResolution {
        use crate::slot_resolution::{NamedSourceObject, ResolutionV1};
        use blockzilla_archive_v2::{
            ArchiveV2BlockAccessBlob, ArchiveV2BlockAccessBlockhash, ArchiveV2BlockAccessPubkey,
        };
        let locator = locator();
        let access = ArchiveV2BlockAccessBlob {
            version: 2,
            flags: 0,
            blockhash: locator.blockhash,
            previous_blockhash: locator.previous_blockhash,
            signature_counts: vec![2],
            signatures: vec![77; 128],
            pubkeys: vec![ArchiveV2BlockAccessPubkey {
                id: 1,
                pubkey: [42; 32],
            }],
            blockhashes: vec![
                ArchiveV2BlockAccessBlockhash {
                    id: -1,
                    blockhash: previous,
                },
                ArchiveV2BlockAccessBlockhash {
                    id: 0,
                    blockhash: current,
                },
            ],
            vote_hashes: vec![],
        };
        let value = ResolutionV1::new(
            locator.clone(),
            vec![
                NamedSourceObject {
                    name: "archive-v2-blocks.zstd".into(),
                    identity: locator.blocks,
                },
                NamedSourceObject {
                    name: "signatures.bin".into(),
                    identity: locator.signatures,
                },
            ],
            &access,
        )
        .unwrap();
        slot_resolution::decode_checked(&slot_resolution::encode(&value).unwrap()).unwrap()
    }

    #[test]
    fn resolve_request_uses_same_origin_token_and_binds_exact_request_digest() {
        let cfg = config();
        let request = resolve_request();
        request
            .validate(&cfg.prefix, &cfg.generation, 432000)
            .unwrap();
        let encoded = serde_json::to_vec(&request).unwrap();
        let parsed: ResolveRequestV1 = serde_json::from_slice(&encoded).unwrap();
        parsed
            .validate(&cfg.prefix, &cfg.generation, 432000)
            .unwrap();
        assert!(
            !String::from_utf8(encoded)
                .unwrap()
                .contains("signatures\":[")
        );
        let sha = "ab".repeat(32);
        let (url, h) = cfg.resolve_plan(432000, "normal", &sha).unwrap();
        assert_eq!(url, "https://foundation.example/v1/resolve");
        assert!(
            h.iter()
                .any(|(k, v)| *k == "Content-Type" && v == RESOLVE_REQUEST_TYPE)
        );
        assert!(
            h.iter()
                .any(|(k, v)| *k == "X-BZ-Foundation-Request-SHA256" && v == &sha)
        );
        assert_eq!(h.iter().filter(|(k, _)| *k == "Authorization").count(), 1);
        assert!(cfg.resolve_plan(432000, "normal", "bad").is_err());
        for result in ["resolution", "unavailable"] {
            validate_resolve_binding(&sha, Some(&sha), Some(result)).unwrap();
        }
        assert!(validate_resolve_binding(&sha, None, Some("resolution")).is_err());
        assert!(
            validate_resolve_binding(&sha, Some(&"cd".repeat(32)), Some("resolution")).is_err()
        );
        for result in [None, Some("complete"), Some("not_cached"), Some("invalid")] {
            assert!(validate_resolve_binding(&sha, Some(&sha), result).is_err());
        }
    }

    #[test]
    fn raw_block_plan_preserves_origin_source_and_exact_hot_digest() {
        let cfg = config();
        assert!(cfg.binary_uses_raw_block());
        assert!(binary_mode(None).unwrap());
        assert!(binary_mode(Some("block")).unwrap());
        assert!(!binary_mode(Some("ids")).unwrap());
        assert!(binary_mode(Some("other")).is_err());
        let request_sha = "ab".repeat(32);
        let (url, headers) = cfg
            .resolve_block_plan(432000, "full-cold", &request_sha)
            .unwrap();
        assert_eq!(url, "https://foundation.example/v1/resolve-block/432000");
        for (name, value) in [
            ("Content-Type", HOT_REQUEST_TYPE),
            ("X-BZ-Foundation-Request-SHA256", request_sha.as_str()),
            ("X-BZ-Foundation-Source-Prefix", "compact-v2/test"),
            ("X-BZ-Foundation-Generation", "generation-1"),
            ("X-BZ-Foundation-Read-Mode", "full-cold"),
        ] {
            assert!(
                headers
                    .iter()
                    .any(|(key, field)| *key == name && field == value)
            );
        }
        assert_eq!(
            headers
                .iter()
                .filter(|(key, _)| *key == "Authorization")
                .count(),
            1
        );
        assert!(cfg.resolve_block_plan(432000, "normal", "bad").is_err());
        assert!(
            cfg.resolve_block_plan(MAX_SAFE_INTEGER + 1, "normal", &request_sha)
                .is_err()
        );
        let request = resolve_request();
        let checked = checked_resolution([11; 32], [10; 32]);
        validate_resolved_source(&request.source, &checked).unwrap();
        let mut wrong = request.source;
        wrong.signatures.etag = "\"different\"".into();
        assert!(validate_resolved_source(&wrong, &checked).is_err());
    }

    #[test]
    fn resolve_reply_matches_source_counts_membership_and_actual_previous_hash() {
        let request = resolve_request();
        let checked = checked_resolution([11; 32], [10; 32]);
        validate_resolved(&request.source, &request.references, &checked).unwrap();
        let mut source = request.source.clone();
        source.hot.compressed_offset += 1;
        assert!(validate_resolved(&source, &request.references, &checked).is_err());
        source = request.source.clone();
        source.blocks.etag = "\"other\"".into();
        assert!(validate_resolved(&source, &request.references, &checked).is_err());
        let mut references = request.references.clone();
        references.signature_counts = vec![1, 1];
        assert!(validate_resolved(&request.source, &references, &checked).is_err());
        references = request.references.clone();
        references.pubkeys.push(2);
        assert!(validate_resolved(&request.source, &references, &checked).is_err());
        references = request.references.clone();
        references.blockhashes.push(1);
        assert!(validate_resolved(&request.source, &references, &checked).is_err());
        references = request.references.clone();
        references
            .votes
            .push(crate::slot_references::VoteReference {
                block_id: 2,
                bank_hash: true,
                block_id_hash: false,
            });
        assert!(validate_resolved(&request.source, &references, &checked).is_err());
        for checked in [
            checked_resolution([9; 32], [10; 32]),
            checked_resolution([11; 32], [9; 32]),
        ] {
            assert!(validate_resolved(&request.source, &request.references, &checked).is_err());
        }
    }

    #[test]
    fn cache_miss_is_typed_and_never_proves_archive_absence() {
        let cfg = config();
        let mut h = headers();
        h.insert("X-BZ-Foundation-Result".into(), "not_cached".into());
        h.insert("Content-Type".into(), "application/json".into());
        assert!(matches!(
            cfg.metadata(404, 432000, |k| h.get(k).cloned()).unwrap(),
            Metadata::NotCached { .. }
        ));
        for status in [200, 409, 410, 503] {
            assert!(cfg.metadata(status, 432000, |k| h.get(k).cloned()).is_err());
        }
        assert!(
            validate_not_cached(
                &cfg.prefix,
                &cfg.generation,
                432000,
                br#"{"version":1,"slot":432000,"reason":"not_cached"}"#,
            )
            .unwrap()
            .is_none()
        );
        let body = serde_json::json!({"version":1,"slot":432000,"reason":"not_cached","source":resolve_request().source});
        assert!(
            validate_not_cached(
                &cfg.prefix,
                &cfg.generation,
                432000,
                &serde_json::to_vec(&body).unwrap()
            )
            .unwrap()
            .is_some()
        );
        for (field, value) in [
            ("source_prefix", serde_json::json!("wrong")),
            ("generation", serde_json::json!("wrong")),
            ("version", serde_json::json!(2)),
        ] {
            let mut bad = body.clone();
            bad["source"][field] = value;
            assert!(
                validate_not_cached(
                    &cfg.prefix,
                    &cfg.generation,
                    432000,
                    &serde_json::to_vec(&bad).unwrap()
                )
                .is_err()
            );
        }
        for bytes in [
            &br#"{"version":1,"slot":432001,"reason":"not_cached"}"#[..],
            &br#"{"version":2,"slot":432000,"reason":"not_cached"}"#[..],
            &br#"{"version":1,"slot":432000,"reason":"unavailable"}"#[..],
            &br#"{"version":1,"slot":432000,"reason":"not_cached","absent":true}"#[..],
        ] {
            assert!(validate_not_cached(&cfg.prefix, &cfg.generation, 432000, bytes).is_err());
        }
    }

    #[test]
    fn rewards_only_archive_locator_accepts_no_signature_range_but_checks_source_bounds() {
        let cfg = config();
        let slot = 432000;
        let mut rewards_only = locator();
        rewards_only.hot.tx_count = 0;
        rewards_only.hot.signature_count = 0;
        assert_eq!(rewards_only.signature_offset().unwrap(), 0);

        let check_pending = |locator: &LocatorV1| {
            let body = serde_json::json!({
                "version": 1, "slot": slot, "reason": "not_cached",
                "source": PendingLocatorV1::from_locator(locator),
            });
            validate_not_cached(
                &cfg.prefix,
                &cfg.generation,
                slot,
                &serde_json::to_vec(&body).unwrap(),
            )
        };
        let check_complete = |locator: &LocatorV1| {
            let mut headers = headers();
            headers.insert(
                "X-BZ-Foundation-Locator".into(),
                URL_SAFE_NO_PAD.encode(locator.wincode_bytes().unwrap()),
            );
            cfg.metadata(200, slot, |key| headers.get(key).cloned())
        };
        assert_eq!(
            check_pending(&rewards_only).unwrap(),
            Some(PendingLocatorV1::from_locator(&rewards_only))
        );
        assert!(matches!(
            check_complete(&rewards_only).unwrap(),
            Metadata::Complete { .. }
        ));

        rewards_only.hot.first_signature_ordinal = rewards_only.signatures.length / 64 + 1;
        assert!(check_pending(&rewards_only).is_err());
        assert!(check_complete(&rewards_only).is_err());
    }

    #[test]
    fn optional_service_diagnostics_are_bounded_and_do_not_affect_data_admission() {
        let h = BTreeMap::from([
            ("X-BZ-Foundation-Cache", "MISS".to_string()),
            ("X-BZ-Foundation-Pread-Calls", "17".to_string()),
            ("X-BZ-Foundation-Pread-Bytes", "4096".to_string()),
        ]);
        assert_eq!(
            resolve_diagnostics(|k| h.get(k).cloned()),
            Some(ResolveDiagnostics {
                cache: "MISS",
                pread_calls: 17,
                pread_bytes: 4096,
                resolve_micros: None,
            })
        );
        for status in ["HIT", "BYPASS"] {
            let mut good = h.clone();
            good.insert("X-BZ-Foundation-Cache", status.into());
            assert!(resolve_diagnostics(|k| good.get(k).cloned()).is_some());
        }
        for (name, value) in [
            ("X-BZ-Foundation-Cache", "unknown"),
            ("X-BZ-Foundation-Pread-Calls", "-1"),
            ("X-BZ-Foundation-Pread-Calls", "01"),
            ("X-BZ-Foundation-Pread-Calls", "1000001"),
            ("X-BZ-Foundation-Pread-Bytes", "1073741825"),
            ("X-BZ-Foundation-Pread-Bytes", "18446744073709551616"),
        ] {
            let mut bad = h.clone();
            bad.insert(name, value.into());
            assert!(resolve_diagnostics(|k| bad.get(k).cloned()).is_none());
        }
        for name in h.keys() {
            let mut missing = h.clone();
            missing.remove(name);
            assert!(resolve_diagnostics(|k| missing.get(k).cloned()).is_none());
        }
    }

    #[test]
    fn endpoint_and_credentials_are_bounded_and_do_not_accept_remote_cleartext_or_redirect_paths() {
        let cfg = config();
        assert_eq!(cfg.header_timeout_ms, 500);
        assert_eq!(cfg.body_timeout_ms, 5000);
        assert_eq!(cfg.body_timeout_ms(), 5000);
        assert_eq!(cfg.generation(), "generation-1");
        assert!(
            cfg.cache_identity()
                .contains("https://foundation.example/v1/block/")
        );
        assert!(!cfg.cache_identity().contains(&cfg.secret));
        let (url, h) = cfg.plan(432000, "normal").unwrap();
        assert_eq!(url, "https://foundation.example/v1/block/432000");
        assert_eq!(h.iter().filter(|(n, _)| *n == "Authorization").count(), 1);
        assert!(h.iter().any(|(n, v)| *n == "Authorization"
            && v == "Bearer local_fixture_secret_abcdefghijklmnopqrstuvwxyz"));
        assert!(h.iter().all(|(_, v)| !v.contains("customer_api_key")));
        for endpoint in [
            "http://foundation.example",
            "https://user:pass@foundation.example",
            "https://foundation.example/?token=x",
            "https://foundation.example/#x",
            "https://foundation.example/other",
        ] {
            assert!(
                Config::parse(
                    endpoint,
                    cfg.secret.clone(),
                    &cfg.prefix,
                    cfg.generation.clone(),
                    None,
                    None,
                    false
                )
                .is_err()
            );
        }
        assert!(
            Config::parse(
                "https://foundation.example",
                "short".into(),
                &cfg.prefix,
                cfg.generation.clone(),
                None,
                None,
                false
            )
            .is_err()
        );
        assert!(
            Config::parse(
                "https://foundation.example",
                cfg.secret.clone(),
                "compact/../test",
                cfg.generation.clone(),
                None,
                None,
                false
            )
            .is_err()
        );
        for t in ["0", "99", "10001", "invalid"] {
            assert!(timeout(Some(t), 500).is_err());
        }
        assert!(cfg.plan(MAX_SAFE_INTEGER + 1, "normal").is_err());
    }

    #[test]
    fn complete_headers_require_finalized_pinned_preverified_identity() {
        let cfg = config();
        let h = headers();
        assert!(matches!(
            cfg.metadata(200, 432000, |k| h.get(k).cloned()).unwrap(),
            Metadata::Complete { length: 500, .. }
        ));
        for (name, value) in [
            ("X-BZ-Foundation-Protocol", "2"),
            ("X-BZ-Foundation-Generation", "other"),
            ("X-BZ-Foundation-Source-Prefix", "other"),
            ("X-BZ-Foundation-Commitment", "processed"),
            ("X-BZ-Foundation-Object-Verified", "none"),
            ("X-BZ-Foundation-Signatures", "archive"),
            ("Content-Length", "0500"),
            ("Content-Length", "1"),
            ("Content-Length", "16777217"),
            ("X-BZ-Foundation-SHA256", "bad"),
            ("Content-Encoding", "gzip"),
            ("Content-Type", "application/json"),
        ] {
            let mut bad = h.clone();
            bad.insert(name.into(), value.into());
            assert!(
                cfg.metadata(200, 432000, |k| bad.get(k).cloned()).is_err(),
                "{name}"
            );
        }
        for name in h.keys() {
            let mut bad = h.clone();
            bad.remove(name);
            assert!(
                cfg.metadata(200, 432000, |k| bad.get(k).cloned()).is_err(),
                "missing {name}"
            );
        }
        assert!(cfg.metadata(200, 432001, |k| h.get(k).cloned()).is_err());
        for status in [301, 302, 307, 308, 401, 403] {
            assert!(cfg.metadata(status, 432000, |k| h.get(k).cloned()).is_err());
        }
    }

    #[test]
    fn resolution_requires_bounded_raw_signature_free_body_and_full_locator_equality_later() {
        let cfg = config();
        let mut h = headers();
        h.insert("X-BZ-Foundation-Result".into(), "resolution".into());
        h.insert("Content-Type".into(), RESOLUTION_TYPE.into());
        h.insert("X-BZ-Foundation-Signatures".into(), "archive".into());
        assert!(matches!(
            cfg.metadata(200, 432000, |k| h.get(k).cloned()).unwrap(),
            Metadata::Resolution { .. }
        ));
        h.insert(
            "Content-Length".into(),
            (slot_resolution::MAX_RESOLUTION_BYTES + 1).to_string(),
        );
        assert!(cfg.metadata(200, 432000, |k| h.get(k).cloned()).is_err());
        assert_eq!(digest(&"ab".repeat(32)).unwrap(), [0xab; 32]);
        assert!(digest(&"AB".repeat(32)).is_err());
    }

    #[test]
    fn only_body_transport_errors_allow_fallback_and_identity_errors_do_not() {
        assert_eq!(
            server_failure(503, None),
            Some(TransportFailure::ServerStatus(503))
        );
        for status in [301, 307, 401, 403, 404] {
            assert!(server_failure(status, None).is_none());
        }
        for result in ["complete", "resolution", "unavailable", "invalid"] {
            assert!(server_failure(503, Some(result)).is_none());
        }
        assert!(matches!(
            body_error("BZ_FOUNDATION_BODY_TIMEOUT").unwrap(),
            Outcome::TransportFailure(TransportFailure::BodyTimeout)
        ));
        assert!(matches!(
            body_error("BZ_FOUNDATION_BODY_NETWORK").unwrap(),
            Outcome::TransportFailure(TransportFailure::BodyNetwork)
        ));
        assert!(body_error("BZ_FOUNDATION_BODY_LENGTH").is_err());
        let cfg = config();
        let mut h = headers();
        h.insert("X-BZ-Foundation-Result".into(), "unavailable".into());
        h.insert("Content-Type".into(), "application/json".into());
        assert!(matches!(
            cfg.metadata(404, 432000, |k| h.get(k).cloned()).unwrap(),
            Metadata::Unavailable { status: 404, .. }
        ));
        assert!(cfg.metadata(200, 432000, |k| h.get(k).cloned()).is_err());
        assert_eq!(Unavailable::Pruned.status(), 410);
        assert_eq!(Unavailable::NotFinalized.status(), 409);
        assert_eq!(
            validate_unavailable(
                410,
                432000,
                br#"{"version":1,"slot":432000,"reason":"pruned"}"#
            )
            .unwrap(),
            Unavailable::Pruned
        );
        for bytes in [
            &br#"{"version":1,"slot":432001,"reason":"pruned"}"#[..],
            &br#"{"version":2,"slot":432000,"reason":"pruned"}"#[..],
            &br#"{"version":1,"slot":432000,"reason":"pruned","extra":true}"#[..],
        ] {
            assert!(validate_unavailable(410, 432000, bytes).is_err());
        }
        for reason in ["source_changed", "hash_mismatch"] {
            assert!(
                validate_unavailable(
                    409,
                    432000,
                    format!(r#"{{"version":1,"slot":432000,"reason":"{reason}"}}"#).as_bytes()
                )
                .is_err()
            );
        }
    }
}
