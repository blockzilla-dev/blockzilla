use crate::{
    ResolutionCatalog,
    direct::{self, Clock, Profile, VerifiedBody},
    recent::{self, RecentClient, RecentOutcome, RecentRequest},
};
use anyhow::{Result, ensure};
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{Path, Query, Request, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use blockzilla_get_block::{
    foundation_protocol::ResolveRequestV1, slot_references::MAX_REQUEST_BYTES, slot_resolution,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

const REQUEST_TYPE: &str = "application/vnd.blockzilla.resolve-ids+json";
const RESPONSE_TYPE: &str = "application/vnd.blockzilla.slot-resolution.wincode";

#[path = "finalized.rs"]
mod finalized;

#[derive(Default)]
struct Counters {
    lookups: AtomicU64,
    resolves: AtomicU64,
    raw_block_resolves: AtomicU64,
    pread_calls: AtomicU64,
    pread_bytes: AtomicU64,
    resolve_errors: AtomicU64,
    request_bytes: AtomicU64,
    cpu_ns: AtomicU64,
    recent_reads: AtomicU64,
    recent_hits: AtomicU64,
    recent_misses: AtomicU64,
    recent_errors: AtomicU64,
    recent_frame_bytes: AtomicU64,
    recent_cpu_ns: AtomicU64,
    recent_work_ns: AtomicU64,
}
struct AppState {
    catalog: Arc<dyn ResolutionCatalog>,
    token_digest: [u8; 32],
    permits: Arc<Semaphore>,
    counters: Counters,
    recent: Option<Arc<RecentClient>>,
}

pub fn router(
    catalog: Arc<dyn ResolutionCatalog>,
    token: &str,
    cache_bytes: usize,
    max_concurrent: usize,
) -> Result<Router> {
    router_with_recent(catalog, token, cache_bytes, max_concurrent, None)
}

pub fn router_with_recent(
    catalog: Arc<dyn ResolutionCatalog>,
    token: &str,
    cache_bytes: usize,
    max_concurrent: usize,
    recent: Option<Arc<RecentClient>>,
) -> Result<Router> {
    ensure!(
        cache_bytes == 0,
        "result caching is disabled; cache_bytes must be 0"
    );
    ensure!(
        (16..=512).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_graphic()),
        "invalid private bearer token"
    );
    ensure!(
        (1..=1024).contains(&max_concurrent),
        "invalid resolution concurrency"
    );
    ensure!(
        !catalog.source_prefix().is_empty() && !catalog.generation().is_empty(),
        "empty catalog identity"
    );
    ensure!(
        axum::http::HeaderValue::from_str(catalog.source_prefix()).is_ok()
            && axum::http::HeaderValue::from_str(catalog.generation()).is_ok(),
        "catalog identity is not valid header text"
    );
    let state = Arc::new(AppState {
        catalog,
        token_digest: Sha256::digest(token.as_bytes()).into(),
        permits: Arc::new(Semaphore::new(max_concurrent)),
        counters: Counters::default(),
        recent,
    });
    Ok(Router::new()
        .route("/healthz", get(|| async { "ready\n" }))
        .route("/v1/info", get(info))
        .route("/v1/block/{slot}", get(block))
        .route("/v1/recent/{slot}", get(recent_block))
        .route("/v1/finalized/{slot}", get(finalized::block))
        .route("/v1/resolve", post(resolve))
        .route("/v1/resolve-block/{slot}", post(resolve_block))
        .with_state(state))
}

async fn recent_block(
    State(state): State<Arc<AppState>>,
    Path(slot): Path<u64>,
    headers: HeaderMap,
    query: std::result::Result<Query<RecentRequest>, QueryRejection>,
) -> Response {
    if !authorized(&headers, &state) {
        return plain_error(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if !pinned(&headers, &state) {
        return unavailable(&state, slot, StatusCode::CONFLICT, "source_changed", None);
    }
    let Some(recent) = &state.recent else {
        return unavailable(
            &state,
            slot,
            StatusCode::SERVICE_UNAVAILABLE,
            "recent_unavailable",
            None,
        );
    };
    let Ok(Query(query)) = query else {
        return unavailable(
            &state,
            slot,
            StatusCode::BAD_REQUEST,
            "invalid_request",
            None,
        );
    };
    if let Err(error) = query.validate(slot, recent.source()) {
        let (status, code) = if error.to_string() == "source_changed" {
            (StatusCode::CONFLICT, "source_changed")
        } else {
            (StatusCode::BAD_REQUEST, "invalid_request")
        };
        return unavailable(&state, slot, status, code, None);
    }
    let Ok(permit) = state.permits.clone().try_acquire_owned() else {
        return unavailable(
            &state,
            slot,
            StatusCode::SERVICE_UNAVAILABLE,
            "recent_capacity_unavailable",
            None,
        );
    };
    state.counters.recent_reads.fetch_add(1, Ordering::Relaxed);
    let started = Instant::now();
    let recent = recent.clone();
    let request = query.clone();
    let catalog = state.catalog.clone();
    let joined = tokio::task::spawn_blocking(move || -> Result<_> {
        // A disconnected HTTP caller cannot cancel blocking disk work. Keep
        // its permit here until that work ends, even if the handler is dropped.
        let _permit = permit;
        let clock = Clock::start()?;
        let result = (|| -> Result<_> {
            let found = recent.read(slot, &request)?;
            let archive = if matches!(found, RecentOutcome::Miss) {
                let pending = catalog.pending(slot)?;
                let hash = if pending.is_some() {
                    catalog.archived_blockhash(slot)?
                } else {
                    None
                };
                ensure!(
                    pending.is_none() || hash.is_some(),
                    "archive_hash_unavailable"
                );
                Some((pending, hash))
            } else {
                None
            };
            Ok((found, archive))
        })();
        Ok((result, clock.finish()?))
    })
    .await;
    let (result, stage) = match joined {
        Ok(Ok((result, stage))) => {
            state
                .counters
                .recent_cpu_ns
                .fetch_add(stage.cpu_ns, Ordering::Relaxed);
            state
                .counters
                .recent_work_ns
                .fetch_add(stage.wall_ns, Ordering::Relaxed);
            (result, Some(stage))
        }
        _ => (Err(anyhow::anyhow!("recent task failed")), None),
    };
    let mut reply = match result {
        Ok((RecentOutcome::Hit { frame, metadata }, _)) => {
            let raw_metadata = serde_json::to_vec(&metadata).expect("recent metadata JSON");
            if raw_metadata.len() > 4096 {
                return unavailable(
                    &state,
                    slot,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "recent_metadata_unavailable",
                    None,
                );
            }
            state.counters.recent_hits.fetch_add(1, Ordering::Relaxed);
            state
                .counters
                .recent_frame_bytes
                .fetch_add(frame.wire.len() as u64, Ordering::Relaxed);
            let mut reply = response(
                &state,
                StatusCode::OK,
                "recent",
                recent::CONTENT_TYPE,
                frame.wire,
                &frame.sha256,
            );
            reply.headers_mut().insert(
                "x-bz-recent-metadata",
                URL_SAFE_NO_PAD
                    .encode(raw_metadata)
                    .parse()
                    .expect("Base64 metadata header"),
            );
            reply.headers_mut().insert(
                "x-bz-foundation-commitment",
                metadata.commitment.parse().expect("checked commitment"),
            );
            reply
                .headers_mut()
                .insert("x-bz-foundation-cache", "BYPASS".parse().unwrap());
            reply
        }
        Ok((RecentOutcome::Miss, Some((source, hash)))) => {
            state.counters.recent_misses.fetch_add(1, Ordering::Relaxed);
            if hash.is_some_and(|hash| recent::encode_hash(&hash) != query.blockhash) {
                return unavailable(
                    &state,
                    slot,
                    StatusCode::CONFLICT,
                    "blockhash_mismatch",
                    None,
                );
            }
            let raw = Bytes::from(
                serde_json::to_vec(&json!({"version":1,"slot":slot,
                "reason":"not_cached","source":source}))
                .expect("recent miss JSON"),
            );
            let sha = hex::encode(Sha256::digest(&raw));
            let mut reply = response(
                &state,
                StatusCode::NOT_FOUND,
                "not_cached",
                "application/json",
                raw,
                &sha,
            );
            if let Some(hash) = hash {
                reply.headers_mut().insert(
                    "x-bz-recent-blockhash",
                    recent::encode_hash(&hash).parse().expect("canonical hash"),
                );
            }
            reply
                .headers_mut()
                .insert("x-bz-foundation-cache", "BYPASS".parse().unwrap());
            reply
        }
        Ok((RecentOutcome::Expired, _)) => {
            state.counters.recent_misses.fetch_add(1, Ordering::Relaxed);
            unavailable(&state, slot, StatusCode::GONE, "replay_unavailable", None)
        }
        _ => {
            state.counters.recent_errors.fetch_add(1, Ordering::Relaxed);
            unavailable(
                &state,
                slot,
                StatusCode::SERVICE_UNAVAILABLE,
                "recent_unavailable",
                None,
            )
        }
    };
    if let Some(stage) = stage {
        for (name, value) in [
            ("x-bz-recent-cpu-micros", stage.cpu_ns / 1000),
            ("x-bz-recent-work-micros", stage.wall_ns / 1000),
            (
                "x-bz-recent-elapsed-micros",
                started.elapsed().as_micros() as u64,
            ),
        ] {
            reply.headers_mut().insert(
                name,
                value.to_string().parse().expect("numeric recent profile"),
            );
        }
    }
    reply
}
fn text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}
fn authorized(headers: &HeaderMap, state: &AppState) -> bool {
    let Some(token) = text(headers, "authorization").and_then(|s| s.strip_prefix("Bearer ")) else {
        return false;
    };
    if !(16..=512).contains(&token.len()) {
        return false;
    }
    let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    bool::from(digest.ct_eq(&state.token_digest))
}
fn pinned(headers: &HeaderMap, state: &AppState) -> bool {
    text(headers, "x-bz-foundation-protocol") == Some("1")
        && text(headers, "x-bz-foundation-generation") == Some(state.catalog.generation())
        && text(headers, "x-bz-foundation-source-prefix") == Some(state.catalog.source_prefix())
        && text(headers, "content-encoding").is_none_or(|s| s == "identity")
}
fn plain_error(status: StatusCode, message: &'static str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(json!({"error":message})),
    )
        .into_response()
}
fn response(
    state: &AppState,
    status: StatusCode,
    result: &str,
    content_type: &str,
    body: Bytes,
    sha256: &str,
) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, body.len())
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-bz-foundation-protocol", "1")
        .header("x-bz-foundation-generation", state.catalog.generation())
        .header(
            "x-bz-foundation-source-prefix",
            state.catalog.source_prefix(),
        )
        .header("x-bz-foundation-result", result)
        .header("x-bz-foundation-sha256", sha256)
        .body(Body::from(body))
        .expect("validated protocol headers")
}
fn unavailable(
    state: &AppState,
    slot: u64,
    status: StatusCode,
    reason: &str,
    request_sha: Option<&str>,
) -> Response {
    let body = Bytes::from(
        serde_json::to_vec(&json!({"version":1,"slot":slot,"reason":reason}))
            .expect("JSON scalars"),
    );
    let sha = hex::encode(Sha256::digest(&body));
    let mut reply = response(state, status, "unavailable", "application/json", body, &sha);
    if let Some(sha) = request_sha {
        reply.headers_mut().insert(
            "x-bz-foundation-request-sha256",
            sha.parse().expect("SHA hex"),
        );
    }
    reply
}
async fn block(
    State(state): State<Arc<AppState>>,
    Path(slot): Path<u64>,
    headers: HeaderMap,
) -> Response {
    if !authorized(&headers, &state) {
        return plain_error(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if !pinned(&headers, &state) {
        return plain_error(StatusCode::CONFLICT, "source identity differs");
    }
    let Ok(_permit) = state.permits.clone().try_acquire_owned() else {
        return plain_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "lookup capacity unavailable",
        );
    };
    state.counters.lookups.fetch_add(1, Ordering::Relaxed);
    let source = match state.catalog.pending(slot) {
        Ok(source) => source,
        Err(_) => return unavailable(&state, slot, StatusCode::CONFLICT, "incomplete", None),
    };
    let body = Bytes::from(
        serde_json::to_vec(&json!({"version":1,"slot":slot,"reason":"not_cached","source":source}))
            .expect("pending locator JSON"),
    );
    if body.len() > 4096 {
        return plain_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "pending locator exceeds wire bounds",
        );
    }
    let sha = hex::encode(Sha256::digest(&body));
    response(
        &state,
        StatusCode::NOT_FOUND,
        "not_cached",
        "application/json",
        body,
        &sha,
    )
}

#[derive(Clone, Copy)]
enum Input {
    Ids,
    Hot(u64),
}
async fn resolve(State(state): State<Arc<AppState>>, request: Request) -> Response {
    resolve_input(state, request, Input::Ids).await
}
async fn resolve_block(
    State(state): State<Arc<AppState>>,
    Path(slot): Path<u64>,
    request: Request,
) -> Response {
    resolve_input(state, request, Input::Hot(slot)).await
}

struct Payload {
    body: Bytes,
    sha256: String,
    locator: String,
}
struct WorkOutput {
    payload: Payload,
    calls: u64,
    bytes: u64,
    profile: Profile,
}
struct Failure {
    status: StatusCode,
    message: &'static str,
    slot: Option<u64>,
}
impl Failure {
    fn plain(status: StatusCode, message: &'static str) -> Self {
        Self {
            status,
            message,
            slot: None,
        }
    }
    fn tagged(slot: u64, status: StatusCode, reason: &'static str) -> Self {
        Self {
            status,
            message: reason,
            slot: Some(slot),
        }
    }
}
fn work(
    catalog: &dyn ResolutionCatalog,
    bytes: Bytes,
    expected_sha: &str,
    input: Input,
) -> std::result::Result<WorkOutput, Failure> {
    let total = Clock::start()
        .map_err(|_| Failure::plain(StatusCode::SERVICE_UNAVAILABLE, "CPU clock unavailable"))?;
    let body = VerifiedBody::new(bytes, Some(expected_sha))
        .map_err(|_| Failure::plain(StatusCode::BAD_REQUEST, "request SHA256 differs"))?;
    let (request, mut profile) = match input {
        Input::Ids => {
            let value: ResolveRequestV1 = serde_json::from_slice(body.bytes()).map_err(|_| {
                Failure::plain(StatusCode::BAD_REQUEST, "invalid typed resolution request")
            })?;
            (
                value,
                Profile {
                    request_sha: body.profile(),
                    ..Profile::default()
                },
            )
        }
        Input::Hot(slot) => {
            let source = match catalog.pending(slot) {
                Ok(Some(source)) => source,
                Ok(None) => {
                    return Err(Failure::tagged(
                        slot,
                        StatusCode::NOT_FOUND,
                        "coverage_unavailable",
                    ));
                }
                Err(_) => return Err(Failure::tagged(slot, StatusCode::CONFLICT, "incomplete")),
            };
            direct::collect_hot(source, &body).map_err(|error| {
                eprintln!("hot block resolution rejected slot={slot}: {error:#}");
                Failure::tagged(slot, StatusCode::CONFLICT, "hash_mismatch")
            })?
        }
    };
    let slot = request.references.slot;
    request
        .validate(catalog.source_prefix(), catalog.generation(), slot)
        .map_err(|_| Failure::tagged(slot, StatusCode::CONFLICT, "source_changed"))?;
    match catalog.pending(slot) {
        Ok(Some(pending)) if pending == request.source => {}
        Ok(None) => {
            return Err(Failure::tagged(
                slot,
                StatusCode::NOT_FOUND,
                "coverage_unavailable",
            ));
        }
        _ => {
            return Err(Failure::tagged(
                slot,
                StatusCode::CONFLICT,
                "source_changed",
            ));
        }
    }
    let stage = Clock::start()
        .map_err(|_| Failure::plain(StatusCode::SERVICE_UNAVAILABLE, "CPU clock unavailable"))?;
    let resolved = catalog.resolve(&request).map_err(|error| {
        eprintln!("ID resolution rejected slot={slot}: {error:#}");
        Failure::tagged(slot, StatusCode::CONFLICT, "source_changed")
    })?;
    profile.table_resolve = stage
        .finish()
        .map_err(|_| Failure::plain(StatusCode::SERVICE_UNAVAILABLE, "CPU clock unavailable"))?;
    let stage = Clock::start()
        .map_err(|_| Failure::plain(StatusCode::SERVICE_UNAVAILABLE, "CPU clock unavailable"))?;
    let locator = URL_SAFE_NO_PAD.encode(
        resolved
            .resolution
            .locator()
            .wincode_bytes()
            .map_err(|_| Failure::tagged(slot, StatusCode::CONFLICT, "source_changed"))?,
    );
    if locator.len() > 4096 {
        return Err(Failure::tagged(
            slot,
            StatusCode::CONFLICT,
            "source_changed",
        ));
    }
    let encoded = slot_resolution::encode(&resolved.resolution)
        .map_err(|_| Failure::tagged(slot, StatusCode::CONFLICT, "source_changed"))?;
    let payload = Payload {
        sha256: hex::encode(Sha256::digest(&encoded)),
        body: Bytes::from(encoded),
        locator,
    };
    profile.encode = stage
        .finish()
        .map_err(|_| Failure::plain(StatusCode::SERVICE_UNAVAILABLE, "CPU clock unavailable"))?;
    profile.total = total
        .finish()
        .map_err(|_| Failure::plain(StatusCode::SERVICE_UNAVAILABLE, "CPU clock unavailable"))?;
    Ok(WorkOutput {
        payload,
        calls: resolved.pread_calls,
        bytes: resolved.pread_bytes,
        profile,
    })
}
async fn resolve_input(state: Arc<AppState>, request: Request, input: Input) -> Response {
    let (parts, body) = request.into_parts();
    if !authorized(&parts.headers, &state) {
        return plain_error(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if !pinned(&parts.headers, &state) {
        return plain_error(StatusCode::CONFLICT, "source identity differs");
    }
    if !matches!(
        text(&parts.headers, "x-bz-foundation-read-mode"),
        Some("normal" | "source" | "full-cold")
    ) {
        return plain_error(StatusCode::BAD_REQUEST, "invalid read mode");
    }
    let (content_type, bound) = match input {
        Input::Ids => (REQUEST_TYPE, MAX_REQUEST_BYTES),
        Input::Hot(_) => (direct::HOT_REQUEST_TYPE, direct::MAX_HOT_BYTES),
    };
    if text(&parts.headers, "content-type") != Some(content_type) {
        return plain_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "invalid resolution content type",
        );
    }
    let Some(expected_sha) = text(&parts.headers, "x-bz-foundation-request-sha256") else {
        return plain_error(StatusCode::BAD_REQUEST, "missing request SHA256");
    };
    if expected_sha.len() != 64
        || !expected_sha
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return plain_error(StatusCode::BAD_REQUEST, "invalid request SHA256");
    }
    let expected_sha = expected_sha.to_owned();
    let Ok(permit) = state.permits.clone().try_acquire_owned() else {
        return plain_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "resolution capacity unavailable",
        );
    };
    let bytes =
        match tokio::time::timeout(std::time::Duration::from_secs(10), to_bytes(body, bound)).await
        {
            Ok(Ok(body)) => body,
            Ok(Err(_)) => {
                return plain_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "resolution request exceeds byte bound",
                );
            }
            Err(_) => {
                return plain_error(
                    StatusCode::REQUEST_TIMEOUT,
                    "resolution request body timeout",
                );
            }
        };
    state.counters.resolves.fetch_add(1, Ordering::Relaxed);
    state
        .counters
        .request_bytes
        .fetch_add(bytes.len() as u64, Ordering::Relaxed);
    if matches!(input, Input::Hot(_)) {
        state
            .counters
            .raw_block_resolves
            .fetch_add(1, Ordering::Relaxed);
    }
    let catalog = state.catalog.clone();
    let request_sha = expected_sha.clone();
    let started = Instant::now();
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work(catalog.as_ref(), bytes, &expected_sha, input)
    })
    .await;
    match result {
        Ok(Ok(value)) => {
            state
                .counters
                .pread_calls
                .fetch_add(value.calls, Ordering::Relaxed);
            state
                .counters
                .pread_bytes
                .fetch_add(value.bytes, Ordering::Relaxed);
            state
                .counters
                .cpu_ns
                .fetch_add(value.profile.total.cpu_ns, Ordering::Relaxed);
            resolved_response(
                &state,
                &value,
                &request_sha,
                started.elapsed().as_micros() as u64,
            )
        }
        Ok(Err(error)) => {
            state
                .counters
                .resolve_errors
                .fetch_add(1, Ordering::Relaxed);
            match error.slot {
                Some(slot) => unavailable(
                    &state,
                    slot,
                    error.status,
                    error.message,
                    Some(&request_sha),
                ),
                None => plain_error(error.status, error.message),
            }
        }
        Err(_) => {
            state
                .counters
                .resolve_errors
                .fetch_add(1, Ordering::Relaxed);
            plain_error(StatusCode::SERVICE_UNAVAILABLE, "resolution task failed")
        }
    }
}
fn resolved_response(
    state: &AppState,
    value: &WorkOutput,
    request_sha: &str,
    elapsed: u64,
) -> Response {
    let mut reply = response(
        state,
        StatusCode::OK,
        "resolution",
        RESPONSE_TYPE,
        value.payload.body.clone(),
        &value.payload.sha256,
    );
    let headers = reply.headers_mut();
    for (name, value) in [
        ("x-bz-foundation-commitment", "finalized"),
        ("x-bz-foundation-signatures", "archive"),
        ("x-bz-foundation-locator", value.payload.locator.as_str()),
        ("x-bz-foundation-request-sha256", request_sha),
        ("x-bz-foundation-cache", "BYPASS"),
    ] {
        headers.insert(name, value.parse().expect("validated protocol header"));
    }
    let p = &value.profile;
    for (name, value) in [
        ("x-bz-foundation-pread-calls", value.calls),
        ("x-bz-foundation-pread-bytes", value.bytes),
        ("x-bz-foundation-resolve-micros", elapsed),
        ("x-bz-foundation-cpu-micros", p.total.cpu_ns / 1000),
        ("x-bz-foundation-work-micros", p.total.wall_ns / 1000),
        (
            "x-bz-foundation-request-sha-micros",
            p.request_sha.wall_ns / 1000,
        ),
        (
            "x-bz-foundation-request-sha-cpu-micros",
            p.request_sha.cpu_ns / 1000,
        ),
        (
            "x-bz-foundation-decompress-micros",
            p.decompress.wall_ns / 1000,
        ),
        (
            "x-bz-foundation-decompress-cpu-micros",
            p.decompress.cpu_ns / 1000,
        ),
        (
            "x-bz-foundation-hot-decode-micros",
            p.hot_decode.wall_ns / 1000,
        ),
        (
            "x-bz-foundation-hot-decode-cpu-micros",
            p.hot_decode.cpu_ns / 1000,
        ),
        ("x-bz-foundation-collect-micros", p.collect.wall_ns / 1000),
        (
            "x-bz-foundation-collect-cpu-micros",
            p.collect.cpu_ns / 1000,
        ),
        (
            "x-bz-foundation-table-resolve-micros",
            p.table_resolve.wall_ns / 1000,
        ),
        (
            "x-bz-foundation-table-resolve-cpu-micros",
            p.table_resolve.cpu_ns / 1000,
        ),
        ("x-bz-foundation-encode-micros", p.encode.wall_ns / 1000),
        ("x-bz-foundation-encode-cpu-micros", p.encode.cpu_ns / 1000),
    ] {
        headers.insert(
            name,
            value.to_string().parse().expect("numeric profile header"),
        );
    }
    reply
}
async fn info(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !authorized(&headers, &state) {
        return plain_error(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    axum::Json(json!({"version":1,"source_prefix":state.catalog.source_prefix(),"generation":state.catalog.generation(),"cache_storage":"none","resolution_ram_cache":"disabled","cache":{"enabled":false,"bytes":0,"entries":0,"hits":0,"misses":0,"evictions":0,"limit_bytes":0},"lookups":state.counters.lookups.load(Ordering::Relaxed),"resolves":state.counters.resolves.load(Ordering::Relaxed),"raw_block_resolves":state.counters.raw_block_resolves.load(Ordering::Relaxed),"local_pread_calls":state.counters.pread_calls.load(Ordering::Relaxed),"local_pread_bytes":state.counters.pread_bytes.load(Ordering::Relaxed),"request_bytes":state.counters.request_bytes.load(Ordering::Relaxed),"resolve_errors":state.counters.resolve_errors.load(Ordering::Relaxed),"available_permits":state.permits.available_permits(),"blocking_thread_cpu_ns":state.counters.cpu_ns.load(Ordering::Relaxed),"cpu_scope":"CLOCK_THREAD_CPUTIME_ID around synchronous blocking request work, including SHA, decode, collection, local resolution and response encoding; HTTP transport is excluded","raw_signature_bytes_read":0,"persistent_result_files":0,"recent_enabled":state.recent.is_some(),"recent_storage":"existing_read_only_producer_window","recent_result_cache":false,"recent_reads":state.counters.recent_reads.load(Ordering::Relaxed),"recent_hits":state.counters.recent_hits.load(Ordering::Relaxed),"recent_misses":state.counters.recent_misses.load(Ordering::Relaxed),"recent_errors":state.counters.recent_errors.load(Ordering::Relaxed),"recent_frame_bytes":state.counters.recent_frame_bytes.load(Ordering::Relaxed),"recent_blocking_thread_cpu_ns":state.counters.recent_cpu_ns.load(Ordering::Relaxed),"recent_blocking_work_ns":state.counters.recent_work_ns.load(Ordering::Relaxed),"recent_cpu_scope":"CLOCK_THREAD_CPUTIME_ID around read-only source checks, frame/root verification and archive-miss hash read; excludes HTTP and metadata/header encoding","raw_signature_bytes_read_scope":"local epoch resolution IO only; recent frames include original signatures"})).into_response()
}

#[cfg(test)]
#[path = "http_tests.rs"]
mod tests;
