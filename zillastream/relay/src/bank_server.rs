use crate::{bank_store::BankStore, server::Api};
use anyhow::{Result, ensure};
use axum::{
    Json, Router,
    body::Body,
    extract::{
        DefaultBodyLimit, Path, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use blockzilla_bank_stream_v2::{self as v2, Notice};
use serde::Deserialize;
use serde_json::json;
use std::{path::PathBuf, sync::Arc, time::Duration};
// Keep delivery margin inside the unchanged five-second health lifetime.
pub(crate) const STATUS_INTERVAL: Duration = Duration::from_secs(1);
#[derive(Clone)]
pub struct BankApi {
    pub store: Arc<BankStore>,
    pub origin: bool,
    pub output: Option<PathBuf>,
    pub public_views: Option<Arc<crate::landed_view::LandedView>>,
    pub hot_upstream: Option<(crate::upstream::Upstream, reqwest::Client)>,
    pub direct_beam: bool,
}
pub fn routes(origin: bool, public_views: bool) -> Router<Api> {
    let mut r = Router::new()
        .route("/v2/banks/head", get(head))
        .route("/v2/banks/events", get(events))
        .route("/v2/banks/beam", get(beam))
        .route("/v2/banks/chunks/{sha}", get(chunk))
        .route(
            "/v2/banks/finalized/events",
            get(crate::finalized_view::events),
        )
        .route(
            "/v2/banks/finalized/blocks/{id}",
            get(crate::finalized_view::block),
        );
    // Provider-to-relay bootstrap is protected by the origin's mTLS and key.
    // It is never installed on the public relay or in the consumer contract.
    if origin {
        r = r
            .route("/v2/banks/state", get(bootstrap))
            .route(
                "/v2/banks/ack",
                post(ack).layer(DefaultBodyLimit::max(16 * 1024)),
            )
            .route("/v2/banks/coverage-gaps", get(coverage_gaps));
    }
    if !origin && public_views {
        r = r
            .route("/v2/blockhashes", get(crate::signing_view::events))
            .route("/v2/landed-blocks", get(crate::landed_view::events));
    }
    r
}
pub(crate) async fn replay_head(banks: &BankApi) -> Result<v2::Head> {
    if banks.direct_beam {
        let raw = direct_source(banks)?;
        return tokio::task::spawn_blocking(move || raw.beam_head()).await?;
    }
    let mut head = banks.store.head();
    if banks.origin {
        if let Some(output) = banks.output.clone() {
            let expected = banks.store.source.clone();
            let floor = tokio::task::spawn_blocking(move || -> Result<String> {
                let raw = crate::bank_source::BankSource::open(&output)?;
                ensure!(raw.source == expected, "source_changed");
                raw.replay_floor_cursor()
            })
            .await??;
            let source_floor = v2::parse_cursor(&floor)?.1;
            if head
                .earliest_after
                .as_deref()
                .map(v2::parse_cursor)
                .transpose()?
                .is_none_or(|(_, n, _)| source_floor < n)
            {
                head.earliest_after = Some(floor);
            }
        }
    }
    Ok(head)
}
async fn head(State(api): State<Api>) -> Response {
    let banks = api.banks.unwrap();
    match replay_head(&banks).await {
        Ok(head) => Json(head).into_response(),
        Err(_) if banks.direct_beam => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"source_unavailable"})),
        )
            .into_response(),
        Err(error) => failure(
            if code(&error) == "source_changed" {
                StatusCode::GONE
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            },
            if code(&error) == "source_changed" {
                "source_changed"
            } else {
                "source_unavailable"
            },
            &banks.store,
        ),
    }
}
async fn bootstrap(State(api): State<Api>) -> impl IntoResponse {
    let banks = api.banks.unwrap();
    if banks.direct_beam {
        return replay_failure(
            StatusCode::GONE,
            "bootstrap_not_available_direct_mode",
            &banks,
        )
        .await;
    }
    Json(banks.store.bootstrap()).into_response()
}

async fn ack(
    State(api): State<Api>,
    body: std::result::Result<Json<crate::consumer_ack::Request>, JsonRejection>,
) -> Response {
    let banks = api.banks.unwrap();
    if banks.direct_beam {
        return replay_failure(StatusCode::GONE, "ack_not_available_direct_mode", &banks).await;
    }
    let request = match body {
        Ok(Json(request)) => request,
        Err(error) => return failure(error.status(), "invalid_consumer_ack", &banks.store),
    };
    let Some(output) = banks.output.clone() else {
        return failure(StatusCode::NOT_FOUND, "ack_not_available", &banks.store);
    };
    let store = banks.store.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<_> {
        // An origin has a fixed consumer set. An HTTP request never creates it.
        crate::consumer_ack::configuration(&output)?;
        let expected = store.source.clone();
        crate::consumer_ack::submit(
            &output,
            &expected,
            request,
            |cursor| {
                if store.after(cursor).is_ok() {
                    return Ok(());
                }
                let mut raw = crate::bank_source::BankSource::open(&output)?;
                ensure!(raw.source == expected, "source_changed");
                raw.seek(cursor)
            },
            |sequence| {
                if sequence == 0 {
                    return Ok(());
                }
                let raw = crate::bank_source::BankSource::open(&output)?;
                ensure!(raw.source == expected, "source_changed");
                ensure!(
                    raw.coverage_gap_exists(sequence)?,
                    "coverage_gap_not_committed"
                );
                Ok(())
            },
        )
    })
    .await;
    match result {
        Ok(Ok(receipt)) => Json(receipt).into_response(),
        Ok(Err(error)) => {
            let code = error.to_string();
            let status = match code.as_str() {
                "source_changed" | "ack_binding_changed" => StatusCode::GONE,
                "unknown_consumer" => StatusCode::FORBIDDEN,
                "ack_not_configured" => StatusCode::SERVICE_UNAVAILABLE,
                "ack_regressed"
                | "ack_cursor_conflict"
                | "ack_cursor_not_committed"
                | "ack_gap_not_committed" => StatusCode::CONFLICT,
                "invalid_consumer_ack" | "invalid_cursor" => StatusCode::BAD_REQUEST,
                _ => {
                    return failure(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "ack_unavailable",
                        &banks.store,
                    );
                }
            };
            replay_failure(status, &code, &banks).await
        }
        Err(_) => failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ack_unavailable",
            &banks.store,
        ),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoveragePosition {
    #[serde(default)]
    after: u64,
    #[serde(default = "coverage_page_size")]
    limit: usize,
}
fn coverage_page_size() -> usize {
    256
}
async fn coverage_gaps(
    State(api): State<Api>,
    query: std::result::Result<Query<CoveragePosition>, QueryRejection>,
) -> Response {
    let banks = api.banks.unwrap();
    let position = match query {
        Ok(Query(position))
            if position.after <= v2::SAFE && (1..=256).contains(&position.limit) =>
        {
            position
        }
        _ => {
            return failure(
                StatusCode::BAD_REQUEST,
                "invalid_coverage_position",
                &banks.store,
            );
        }
    };
    let Some(output) = banks.output.clone() else {
        return failure(
            StatusCode::NOT_FOUND,
            "coverage_not_available",
            &banks.store,
        );
    };
    let expected = banks.store.source.clone();
    let direct_beam = banks.direct_beam;
    match tokio::task::spawn_blocking(move || -> Result<_> {
        let raw = crate::bank_source::BankSource::open(&output)?;
        ensure!(raw.source == expected, "source_changed");
        if direct_beam {
            raw.validate_beam_authority()?;
        }
        raw.coverage_gaps_after(position.after, position.limit)
    })
    .await
    {
        Ok(Ok(page)) => Json(page).into_response(),
        Ok(Err(error)) => {
            let code = error.to_string();
            let status = if matches!(
                code.as_str(),
                "source_changed" | "replay_unavailable" | "coverage_replay_unavailable"
            ) {
                StatusCode::GONE
            } else {
                StatusCode::BAD_REQUEST
            };
            replay_failure(status, &code, &banks).await
        }
        Err(_) => failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "coverage_unavailable",
            &banks.store,
        ),
    }
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Position {
    after: Option<String>,
}

#[derive(Deserialize)]
enum RecoveryFormat {
    #[serde(rename = "1")]
    V1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventsPosition {
    after: Option<String>,
    recovery: Option<RecoveryFormat>,
}

pub(crate) fn requested_after(p: Position, h: &HeaderMap) -> Result<Option<String>> {
    ensure!(
        h.get_all("last-event-id").iter().count() <= 1,
        "invalid_cursor"
    );
    let header = h.get("last-event-id").map(|v| v.to_str()).transpose()?;
    if let (Some(q), Some(h)) = (p.after.as_deref(), header) {
        ensure!(q == h, "cursor_conflict");
    }
    Ok(p.after.or_else(|| header.map(str::to_owned)))
}
pub(crate) fn accepted(store: &BankStore, p: Position, h: &HeaderMap) -> Result<String> {
    let after = requested_after(p, h)?.unwrap_or_else(|| store.latest());
    store.after(&after)?;
    Ok(after)
}
async fn accepted_replay(banks: &BankApi, p: Position, h: &HeaderMap) -> Result<String> {
    if banks.direct_beam {
        let mut raw = direct_source(banks)?;
        let requested = requested_after(p, h)?;
        return tokio::task::spawn_blocking(move || {
            let after = requested.map(Ok).unwrap_or_else(|| {
                raw.beam_head()?
                    .cursor
                    .ok_or_else(|| anyhow::anyhow!("source_not_started"))
            })?;
            raw.seek(&after)?;
            Ok(after)
        })
        .await?;
    }
    let after = requested_after(p, h)?.unwrap_or_else(|| banks.store.latest());
    match banks.store.after(&after) {
        Ok(_) => Ok(after),
        Err(error)
            if error.to_string() == "replay_unavailable"
                && banks.origin
                && banks.output.is_some() =>
        {
            let output = banks.output.clone().unwrap();
            let expected = banks.store.source.clone();
            let cursor = after.clone();
            tokio::task::spawn_blocking(move || -> Result<()> {
                let mut raw = crate::bank_source::BankSource::open(&output)?;
                ensure!(raw.source == expected, "source_changed");
                raw.seek(&cursor)
            })
            .await??;
            Ok(after)
        }
        Err(error) => Err(error),
    }
}
async fn replay_after(banks: &BankApi, after: &str) -> Result<Option<Arc<v2::Frame>>> {
    if banks.direct_beam {
        let mut raw = direct_source(banks)?;
        let after = after.to_owned();
        return tokio::task::spawn_blocking(move || {
            ensure!(raw.health()? != "failed", "source_failed");
            raw.seek(&after)?;
            let frame = raw.next()?;
            if let Some(frame) = &frame {
                raw.require_retained(frame)?;
            }
            Ok(frame.map(Arc::new))
        })
        .await?;
    }
    match banks.store.after(after) {
        Ok(frame) => Ok(frame),
        Err(error)
            if error.to_string() == "replay_unavailable"
                && banks.origin
                && banks.output.is_some() =>
        {
            let output = banks.output.clone().unwrap();
            let expected = banks.store.source.clone();
            let cursor = after.to_owned();
            // One bounded source frame per request stream. No detached replay
            // queue or new cache: release the frame before waiting on SSE.
            tokio::task::spawn_blocking(move || -> Result<_> {
                let mut raw = crate::bank_source::BankSource::open(&output)?;
                ensure!(raw.source == expected, "source_changed");
                raw.seek(&cursor)?;
                raw.next().map(|frame| frame.map(Arc::new))
            })
            .await?
        }
        Err(error) => Err(error),
    }
}
pub(crate) fn code(e: &anyhow::Error) -> &'static str {
    match e.to_string().as_str() {
        "source_changed" => "source_changed",
        "replay_unavailable" => "replay_unavailable",
        "cursor_conflict" => "cursor_conflict",
        _ => "invalid_cursor",
    }
}
fn failure(status: StatusCode, error: &str, store: &BankStore) -> Response {
    (status, Json(json!({"error":error,"head":store.head()}))).into_response()
}
fn direct_source(banks: &BankApi) -> Result<crate::bank_source::BankSource> {
    ensure!(
        banks.origin && banks.direct_beam,
        "direct_beam_not_available"
    );
    let raw = crate::bank_source::BankSource::open(
        banks
            .output
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("source_unavailable"))?,
    )?;
    ensure!(raw.source == banks.store.source, "source_changed");
    raw.validate_beam_authority()?;
    Ok(raw)
}
pub(crate) async fn replay_failure(status: StatusCode, error: &str, banks: &BankApi) -> Response {
    match replay_head(banks).await {
        Ok(head) => (status, Json(json!({"error":error,"head":head}))).into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"source_unavailable"})),
        )
            .into_response(),
    }
}
/// The existing frame header bounds each record. Do not insert status text,
/// heartbeats or a second serialization into the canonical binary stream.
async fn beam(
    State(api): State<Api>,
    position: std::result::Result<Query<Position>, QueryRejection>,
    headers: HeaderMap,
) -> Response {
    let banks = api.banks.unwrap();
    if !banks.direct_beam {
        return failure(
            StatusCode::NOT_FOUND,
            "direct_beam_not_available",
            &banks.store,
        );
    }
    let Ok(Query(position)) = position else {
        return replay_failure(StatusCode::BAD_REQUEST, "invalid_cursor", &banks).await;
    };
    let mut after = match accepted_replay(&banks, position, &headers).await {
        Ok(after) => after,
        Err(error) => {
            let code = code(&error);
            return replay_failure(
                if matches!(code, "replay_unavailable" | "source_changed") {
                    StatusCode::GONE
                } else {
                    StatusCode::BAD_REQUEST
                },
                code,
                &banks,
            )
            .await;
        }
    };
    let start = after.clone();
    match replay_head(&banks).await {
        Ok(head) if head.status == "failed" => {
            return replay_failure(StatusCode::GONE, "source_failed", &banks).await;
        }
        Err(_) => {
            return replay_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "source_unavailable",
                &banks,
            )
            .await;
        }
        _ => {}
    }
    let stream = async_stream::stream! {
        loop {
            // Floor and membership are read for every frame, including after
            // a slow reader resumes. A mid-body failure closes the response.
            match replay_after(&banks,&after).await {
                Ok(Some(frame))=>{ after=frame.cursor.clone();yield Ok::<bytes::Bytes,std::io::Error>(frame.wire.clone()); }
                Ok(None)=>tokio::time::sleep(Duration::from_millis(20)).await,
                Err(error)=>{yield Err(std::io::Error::other(error));break;}
            }
        }
    };
    let mut response = Body::from_stream(stream).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/vnd.blockzilla.stream.v2".parse().unwrap(),
    );
    response
        .headers_mut()
        .insert("x-blockzilla-start-cursor", start.parse().unwrap());
    response
}
async fn events(
    State(api): State<Api>,
    p: std::result::Result<Query<EventsPosition>, QueryRejection>,
    headers: HeaderMap,
) -> Response {
    let banks = api.banks.unwrap();
    let store = banks.store.clone();
    let p = match p {
        Ok(Query(p)) => p,
        Err(_) => return replay_failure(StatusCode::BAD_REQUEST, "invalid_cursor", &banks).await,
    };
    let recovery = p.recovery.is_some();
    let mut after = match accepted_replay(&banks, Position { after: p.after }, &headers).await {
        Ok(v) => v,
        Err(e) => {
            let c = code(&e);
            return replay_failure(
                if matches!(c, "source_changed" | "replay_unavailable") {
                    StatusCode::GONE
                } else {
                    StatusCode::BAD_REQUEST
                },
                c,
                &banks,
            )
            .await;
        }
    };
    if replay_head(&banks)
        .await
        .is_ok_and(|head| head.status == "failed")
    {
        return replay_failure(StatusCode::GONE, "source_failed", &banks).await;
    }
    let start = after.clone();
    let stream = async_stream::stream! {
        let first_head=match replay_head(&banks).await {Ok(head)=>head,Err(_)=>{yield Ok::<bytes::Bytes,std::io::Error>(format!("event: gap\ndata: {}\n\n",json!({"error":"source_unavailable","head":store.head()})).into());return;}};
        yield Ok::<bytes::Bytes,std::io::Error>(format!("event: status\ndata: {}\n\n",serde_json::to_string(&first_head).unwrap()).into());
        let mut next_status=tokio::time::Instant::now()+STATUS_INTERVAL;
        loop {
            let head=match replay_head(&banks).await { Ok(head)=>head,Err(_)=>{yield Ok(format!("event: gap\ndata: {}\n\n",json!({"error":"source_unavailable"})).into());break;} };
            if head.status=="failed" {
                let error=match store.error().as_deref() {Some("source_changed")=>"source_changed",Some("dependency_unavailable")=>"dependency_unavailable",_=>"source_failed"};
                yield Ok(format!("event: gap\ndata: {}\n\n",json!({"error":error,"head":head})).into());break;
            }
            if tokio::time::Instant::now()>=next_status {
                let head=match replay_head(&banks).await {Ok(head)=>head,Err(_)=>{yield Ok(format!("event: gap\ndata: {}\n\n",json!({"error":"source_unavailable","head":store.head()})).into());break;}};
                yield Ok(format!("event: status\ndata: {}\n\n",serde_json::to_string(&head).unwrap()).into());
                next_status=tokio::time::Instant::now()+STATUS_INTERVAL;
            }
            let ready=store.notify.notified();
            match replay_after(&banks,&after).await {
                Ok(Some(f))=>{
                    after=f.cursor.clone();
                    let notice = if recovery {
                        serde_json::to_string(&v2::RecoveryStreamNotice::from_frame(&f))
                    } else {
                        serde_json::to_string(&Notice::from_frame(&f))
                    }.unwrap();
                    // Hold only the notice while a slow SSE reader waits.
                    drop(f);yield Ok(format!("id: {after}\nevent: chunk\ndata: {notice}\n\n").into());
                }
                Ok(None)=>{tokio::select! { _=ready=>{},_=tokio::time::sleep_until(next_status)=>{} }}
                Err(e)=>{let error=if code(&e)=="invalid_cursor" {"replay_unavailable"}else{code(&e)};
                    let head=replay_head(&banks).await.ok();
                    yield Ok(format!("event: gap\ndata: {}\n\n",json!({"error":error,"head":head})).into());break;}
            }
        }
    };
    let mut r = Body::from_stream(stream).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        "text/event-stream; charset=utf-8".parse().unwrap(),
    );
    r.headers_mut()
        .insert("x-blockzilla-start-cursor", start.parse().unwrap());
    if recovery {
        r.headers_mut().insert(
            "x-blockzilla-notice-format",
            header::HeaderValue::from_static(v2::RECOVERY_NOTICE_FORMAT),
        );
    }
    r
}
async fn chunk(State(api): State<Api>, Path(sha): Path<String>) -> Response {
    let banks = api.banks.unwrap();
    if !v2::is_digest(&sha) {
        return replay_failure(StatusCode::BAD_REQUEST, "invalid_cursor", &banks).await;
    }
    if banks.direct_beam {
        let raw = match direct_source(&banks) {
            Ok(raw) => raw,
            Err(_) => {
                return replay_failure(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "source_unavailable",
                    &banks,
                )
                .await;
            }
        };
        return match tokio::task::spawn_blocking(move || raw.retained_chunk(&sha)).await {
            Ok(Ok(Some(frame))) => block_response(&frame),
            _ => replay_failure(StatusCode::GONE, "dependency_unavailable", &banks).await,
        };
    }
    let f = if let Some(f) = banks.store.chunk(&sha) {
        Some(f)
    } else if let Some(output) = banks.output {
        let sha = sha.clone();
        match tokio::task::spawn_blocking(move || {
            crate::bank_source::BankSource::open(&output)?.chunk(&sha)
        })
        .await
        {
            Ok(Ok(Some(f))) => Some(Arc::new(f)),
            Ok(Ok(None)) => None,
            _ => return failure(StatusCode::GONE, "dependency_unavailable", &banks.store),
        }
    } else {
        None
    };
    let Some(f) = f else {
        return failure(StatusCode::GONE, "dependency_unavailable", &banks.store);
    };
    block_response(&f)
}

pub(crate) fn block_response(f: &v2::Frame) -> Response {
    let mut r = f.wire.clone().into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/vnd.blockzilla.stream.v2".parse().unwrap(),
    );
    r.headers_mut().insert(
        header::CONTENT_LENGTH,
        f.wire.len().to_string().parse().unwrap(),
    );
    r.headers_mut()
        .insert(header::ETAG, format!("\"{}\"", f.sha256).parse().unwrap());
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{server, store::Store};
    use axum::http::Request;
    use tokio::sync::Semaphore;
    use v2::fixtures::*;
    fn api(store: Arc<BankStore>) -> Api {
        Api {
            store: Store::open("fixture-session:0:-".into(), v2::MAX_FRAME, None).unwrap(),
            token: Arc::new("k".repeat(32)),
            cors: None,
            requests: Arc::new(Semaphore::new(16)),
            allow_query_api_key: true,
            public_blockhashes: false,
            public_requests: Arc::new(Semaphore::new(0)),
            banks: Some(BankApi {
                store,
                origin: false,
                output: None,
                public_views: None,
                hot_upstream: None,
                direct_beam: false,
            }),
            bank_only: true,
        }
    }
    fn ack_fixture(root: &std::path::Path) -> (Api, String, rusqlite::Connection) {
        let payload = root.join("payload");
        std::fs::create_dir(&payload).unwrap();
        let mut header = serde_json::to_value(source()).unwrap();
        header["schema"] = json!("hivezilla-bank-feed-v2");
        header["profile"] = json!(v2::PROFILE);
        header["payload_root"] = json!(payload);
        header["producer_generation"] = json!(v2::digest(b"generation"));
        std::fs::write(root.join("FEED.json"), serde_json::to_vec(&header).unwrap()).unwrap();
        let db = rusqlite::Connection::open(root.join("feed.sqlite")).unwrap();
        db.execute_batch("CREATE TABLE feed_events(sequence INTEGER PRIMARY KEY,frame_sha256 TEXT); CREATE TABLE feed_retention(id INTEGER PRIMARY KEY,base_sequence INTEGER,base_sha256 TEXT,gap_base_sequence INTEGER,latest_gap_sequence INTEGER); INSERT INTO feed_retention VALUES(1,0,'-',0,7); CREATE TABLE coverage_gaps(sequence INTEGER PRIMARY KEY,processed_sequence INTEGER,gap_json TEXT);").unwrap();
        let frame = block(1, 10, 1, 9, 100);
        db.execute("INSERT INTO feed_events VALUES(1,?1)", [&frame.sha256])
            .unwrap();
        for sequence in [3, 7] {
            db.execute("INSERT INTO coverage_gaps VALUES(?1,?1,?2)",rusqlite::params![sequence,serde_json::to_string(&json!({"schema":"hivezilla-incomplete-bank-gap-v1","producer_generation":v2::digest(b"generation"),"gap_sequence":sequence})).unwrap()]).unwrap();
        }
        let base = v2::cursor(&source().session_id, 0, "-");
        let store = BankStore::open_memory(source(), base, v2::MAX_FRAME).unwrap();
        let mut a = api(store);
        let banks = a.banks.as_mut().unwrap();
        banks.origin = true;
        banks.output = Some(root.into());
        crate::consumer_ack::configure(root, &source(), &["sidecar-primary".into()]).unwrap();
        (a, frame.cursor, db)
    }
    async fn ack_listener(api: Api) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, server::router(api)).await.unwrap();
        });
        (url, task)
    }
    fn replay_fixture(root: &std::path::Path) -> (Api, Vec<v2::Frame>, rusqlite::Connection) {
        use rusqlite::params;
        let root = root.canonicalize().unwrap();
        let payload = root.join("payload");
        std::fs::create_dir(&payload).unwrap();
        let mut frames = Vec::new();
        for (sequence, slot, bank, parent, height) in [(1, 100, 7, 99, 90), (4, 101, 8, 100, 91)] {
            let template = block(sequence, slot, bank, parent, height);
            let directory = payload.join(format!("{slot}-{bank}.compact"));
            std::fs::create_dir(&directory).unwrap();
            let marker = serde_json::to_vec(&template.envelope.marker).unwrap();
            std::fs::write(directory.join("DIRECT-AGAVE-COMPACT.v1.json"), &marker).unwrap();
            for name in v2::REQUIRED {
                std::fs::write(directory.join(name), [42]).unwrap();
            }
            let mut event = template.envelope.event;
            event.payload_sha256 = v2::digest(&marker);
            event.observed_at_unix_ms = crate::store::now_ms();
            let frame = v2::artifact::build(&payload, &directory, &source(), event).unwrap();
            let confirmed = control(&frame, sequence + 1, "confirmed", crate::store::now_ms());
            let rooted = control(&frame, sequence + 2, "root", crate::store::now_ms());
            frames.extend([frame, confirmed, rooted]);
        }
        let mut header = serde_json::to_value(source()).unwrap();
        header["schema"] = json!("hivezilla-bank-feed-v2");
        header["profile"] = json!(v2::PROFILE);
        header["payload_root"] = json!(payload);
        header["producer_generation"] = json!("a".repeat(64));
        std::fs::write(root.join("FEED.json"), serde_json::to_vec(&header).unwrap()).unwrap();
        let db = rusqlite::Connection::open(root.join("feed.sqlite")).unwrap();
        db.execute_batch("CREATE TABLE feed_events(sequence INTEGER PRIMARY KEY,artifact TEXT,event_json TEXT,frame_sha256 TEXT UNIQUE);CREATE TABLE banks(slot INTEGER,bank INTEGER,artifact TEXT,payload_event TEXT,frame_sha256 TEXT,state TEXT DEFAULT 'rooted');CREATE TABLE feed_retention(id INTEGER PRIMARY KEY,base_sequence INTEGER,base_sha256 TEXT);INSERT INTO feed_retention VALUES(1,0,'-');").unwrap();
        for frame in &frames {
            let event = &frame.envelope.event;
            let path = payload.join(format!(
                "{}-{}.compact",
                event.bank.slot, event.bank.bank_id
            ));
            db.execute(
                "INSERT INTO feed_events VALUES(?1,?2,?3,?4)",
                params![
                    event.sequence,
                    path.to_str().unwrap(),
                    serde_json::to_string(event).unwrap(),
                    frame.sha256
                ],
            )
            .unwrap();
            if event.kind == "block" {
                db.execute("INSERT INTO banks(slot,bank,artifact,payload_event,frame_sha256) VALUES(?1,?2,?3,?4,?5)",params![event.bank.slot,event.bank.bank_id,path.to_str().unwrap(),serde_json::to_string(event).unwrap(),frame.sha256]).unwrap();
            }
        }
        db.execute_batch("CREATE TABLE feed_state(id INTEGER PRIMARY KEY,chain_json TEXT);")
            .unwrap();
        let latest = v2::ConfirmedObservation::from_frame(&frames[5]).unwrap();
        db.execute(
            "INSERT INTO feed_state VALUES(1,?1)",
            [serde_json::to_string(&json!({"latest":latest})).unwrap()],
        )
        .unwrap();
        let status = serde_json::to_vec(
            &json!({"state":"RUNNING","updated_unix_ms":crate::store::now_ms()}),
        )
        .unwrap();
        std::fs::write(root.join("STATUS.json"), &status).unwrap();
        std::fs::write(payload.join("STATUS.json"), &status).unwrap();
        std::fs::write(root.join("RETENTION-AUTHORITY.json"),serde_json::to_vec(&json!({"schema":"blockzilla-retention-authority-v1","mode":"local-beam-v1","source":source(),"producer_generation":"a".repeat(64),"consumer_ack_required":false})).unwrap()).unwrap();
        // The spool begins after frame3; the durable source still has1..6.
        let store = BankStore::open_memory(
            source(),
            v2::cursor(&source().session_id, 0, "-"),
            v2::MAX_FRAME,
        )
        .unwrap();
        let mut chain = v2::chain::Chain::default();
        chain
            .seed(
                v2::ConfirmedObservation::from_frame(&frames[2]).unwrap(),
                &frames[0],
            )
            .unwrap();
        store
            .install_bootstrap(
                crate::bank_store::Bootstrap {
                    source: source(),
                    cursor: frames[2].cursor.clone(),
                    chain,
                },
                vec![frames[0].clone(), frames[2].clone()],
            )
            .unwrap();
        for frame in &frames[3..] {
            store.admit(frame.clone(), None).unwrap();
        }
        store.set_health("live", None);
        let mut api = api(store);
        let banks = api.banks.as_mut().unwrap();
        banks.origin = true;
        banks.output = Some(root);
        (api, frames, db)
    }
    #[tokio::test]
    #[ignore = "requires the matching private release binary"]
    async fn direct_process_uses_only_native_feed_and_recovers_its_unix_socket() {
        use futures_util::StreamExt;
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let binary = std::env::var("BLOCKZILLA_BEAM_ORIGIN_BINARY").unwrap();
        let temp = tempfile::tempdir().unwrap();
        let (_api, frames, _db) = replay_fixture(temp.path());
        let socket = temp.path().join("origin.sock");
        let token = temp.path().join("token");
        std::fs::write(&token, "k".repeat(32)).unwrap();
        let spool = temp.path().join("unused-spool");
        let launch = || {
            Child(
                std::process::Command::new(&binary)
                    .args(["bank-origin", "--direct-beam", "--output"])
                    .arg(temp.path())
                    .arg("--spool")
                    .arg(&spool)
                    .arg("--unix-socket")
                    .arg(&socket)
                    .arg("--token-file")
                    .arg(&token)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap(),
            )
        };
        let http = reqwest::Client::builder()
            .unix_socket(socket.clone())
            .no_proxy()
            .build()
            .unwrap();
        let key = "k".repeat(32);
        let ready = || async {
            for _ in 0..100 {
                if std::fs::symlink_metadata(&socket).is_ok_and(|m| {
                    use std::os::unix::fs::FileTypeExt;
                    m.file_type().is_socket()
                }) {
                    if let Ok(response) = http
                        .get("http://localhost/v2/banks/head")
                        .bearer_auth(&key)
                        .send()
                        .await
                    {
                        if response.status() == StatusCode::OK {
                            return;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            panic!("private direct origin did not start");
        };
        let mut process = launch();
        ready().await;
        assert!(!spool.exists());
        let head: v2::Head = http
            .get("http://localhost/v2/banks/head")
            .bearer_auth(&key)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(head.cursor.as_deref(), Some(frames[5].cursor.as_str()));
        let base = v2::cursor(&source().session_id, 0, "-");
        let response = http
            .get("http://localhost/v2/banks/beam")
            .query(&[("after", &base)])
            .bearer_auth(&key)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        let expected = frames
            .iter()
            .flat_map(|f| f.wire.iter().copied())
            .collect::<Vec<_>>();
        let mut input = response.bytes_stream();
        let mut bytes = Vec::new();
        while bytes.len() < expected.len() {
            bytes.extend_from_slice(
                &tokio::time::timeout(Duration::from_secs(2), input.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap(),
            );
        }
        assert_eq!(bytes, expected);
        drop(input);
        unsafe {
            libc::kill(process.0.id() as i32, libc::SIGTERM);
        };
        process.0.wait().unwrap();
        drop(process);
        process = launch();
        ready().await;
        let response = http
            .get("http://localhost/v2/banks/beam")
            .query(&[("after", &frames[2].cursor)])
            .bearer_auth(&key)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        assert_eq!(
            response.headers()["x-blockzilla-start-cursor"],
            frames[2].cursor
        );
        drop(response);
        assert!(!spool.exists());
        assert!(!temp.path().join("consumer-acks.sqlite").exists());
        drop(process);
    }
    #[tokio::test]
    async fn direct_beam_is_exact_bounded_and_has_no_ack_or_projection() {
        use futures_util::StreamExt;
        let temp = tempfile::tempdir().unwrap();
        let (mut api, frames, _db) = replay_fixture(temp.path());
        api.banks.as_mut().unwrap().direct_beam = true;
        let (url, task) = ack_listener(api).await;
        let http = reqwest::Client::new();
        let key = "k".repeat(32);
        let base = v2::cursor(&source().session_id, 0, "-");
        assert_eq!(
            http.get(format!("{url}/v2/banks/beam"))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let response = http
            .get(format!("{url}/v2/banks/beam"))
            .query(&[("after", &base)])
            .bearer_auth(&key)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        assert_eq!(response.headers()["x-blockzilla-start-cursor"], base);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/vnd.blockzilla.stream.v2"
        );
        let expected = frames
            .iter()
            .flat_map(|f| f.wire.iter().copied())
            .collect::<Vec<_>>();
        let mut received = Vec::new();
        let mut input = response.bytes_stream();
        while received.len() < expected.len() {
            received.extend_from_slice(
                &tokio::time::timeout(Duration::from_secs(2), input.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap(),
            );
        }
        assert_eq!(received, expected);
        drop(input);
        let response = http
            .get(format!("{url}/v2/banks/beam"))
            .query(&[("after", &frames[2].cursor)])
            .bearer_auth(&key)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        let mut input = response.bytes_stream();
        let first = tokio::time::timeout(Duration::from_secs(2), input.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(frames[3].wire.starts_with(&first) || first.starts_with(&frames[3].wire));
        drop(input);
        assert!(!temp.path().join("consumer-acks.sqlite").exists());
        task.abort();
    }
    #[tokio::test]
    async fn direct_floor_overrides_spool_aliases_for_every_read_and_error_head() {
        let temp = tempfile::tempdir().unwrap();
        let (mut api, frames, db) = replay_fixture(temp.path());
        api.banks.as_mut().unwrap().direct_beam = true;
        db.execute(
            "UPDATE feed_retention SET base_sequence=4,base_sha256=?1",
            [&frames[3].sha256],
        )
        .unwrap();
        db.execute("DELETE FROM feed_events WHERE sequence<=4", [])
            .unwrap();
        let banks = api.banks.as_ref().unwrap();
        assert!(banks.store.chunk(&frames[3].sha256).is_some());
        assert_eq!(
            replay_head(banks).await.unwrap().earliest_after.as_deref(),
            Some(frames[3].cursor.as_str())
        );
        assert_eq!(
            accepted_replay(
                banks,
                Position {
                    after: Some(frames[2].cursor.clone())
                },
                &HeaderMap::new()
            )
            .await
            .unwrap_err()
            .to_string(),
            "replay_unavailable"
        );
        assert_eq!(
            replay_after(banks, &frames[2].cursor)
                .await
                .unwrap_err()
                .to_string(),
            "replay_unavailable"
        );
        assert_eq!(
            replay_after(banks, &frames[3].cursor)
                .await
                .unwrap()
                .unwrap()
                .wire,
            frames[4].wire
        );
        let (url, task) = ack_listener(api).await;
        let http = reqwest::Client::new();
        let key = "k".repeat(32);
        for path in [
            format!("events?after={}", frames[2].cursor),
            format!("beam?after={}", frames[2].cursor),
            format!("chunks/{}", frames[2].sha256),
            format!(
                "finalized/blocks/{}",
                v2::finalized::BlockId::from(&frames[0].envelope.event.bank)
            ),
            "finalized/events".into(),
            "state".into(),
        ] {
            let response = http
                .get(format!("{url}/v2/banks/{path}"))
                .bearer_auth(&key)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::GONE, "{path}");
            let value: serde_json::Value = response.json().await.unwrap();
            assert_eq!(value["head"]["earliest_after"], frames[3].cursor, "{path}");
        }
        assert_eq!(
            http.get(format!("{url}/v2/banks/chunks/{}", frames[4].sha256))
                .bearer_auth(&key)
                .send()
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap(),
            frames[4].wire
        );
        // Move the floor while an exact saved boundary is already in use.
        db.execute(
            "UPDATE feed_retention SET base_sequence=5,base_sha256=?1",
            [&frames[4].sha256],
        )
        .unwrap();
        db.execute("DELETE FROM feed_events WHERE sequence<=5", [])
            .unwrap();
        let response = http
            .get(format!("{url}/v2/banks/beam"))
            .query(&[("after", &frames[3].cursor)])
            .bearer_auth(&key)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::GONE);
        assert_eq!(
            response.json::<serde_json::Value>().await.unwrap()["head"]["earliest_after"],
            frames[4].cursor
        );
        task.abort();
    }
    #[tokio::test]
    async fn direct_chunks_keep_only_proven_late_control_dependencies_at_or_below_floor() {
        let temp = tempfile::tempdir().unwrap();
        let (mut api, frames, db) = replay_fixture(temp.path());
        api.banks.as_mut().unwrap().direct_beam = true;
        let late = control(&frames[0], 7, "root", crate::store::now_ms());
        let path = temp
            .path()
            .canonicalize()
            .unwrap()
            .join("payload/100-7.compact");
        db.execute(
            "INSERT INTO feed_events VALUES(7,?1,?2,?3)",
            rusqlite::params![
                path.to_str().unwrap(),
                serde_json::to_string(&late.envelope.event).unwrap(),
                late.sha256
            ],
        )
        .unwrap();
        db.execute(
            "UPDATE feed_retention SET base_sequence=1,base_sha256=?1",
            [&frames[0].sha256],
        )
        .unwrap();
        db.execute("DELETE FROM feed_events WHERE sequence<=1", [])
            .unwrap();
        let banks = api.banks.as_ref().unwrap();
        let raw = direct_source(banks).unwrap();
        // A block at the floor is a dependency object, not an event to replay.
        assert_eq!(
            raw.retained_chunk(&frames[0].sha256).unwrap().unwrap().wire,
            frames[0].wire
        );
        db.execute(
            "UPDATE feed_retention SET base_sequence=4,base_sha256=?1",
            [&frames[3].sha256],
        )
        .unwrap();
        db.execute("DELETE FROM feed_events WHERE sequence<=4", [])
            .unwrap();
        assert_eq!(
            raw.retained_chunk(&frames[0].sha256).unwrap().unwrap().wire,
            frames[0].wire
        );
        assert_eq!(
            raw.retained_chunk(&frames[3].sha256).unwrap().unwrap().wire,
            frames[3].wire
        );
        assert!(raw.retained_chunk(&frames[2].sha256).unwrap().is_none());
        db.execute("DELETE FROM feed_events WHERE sequence=7", [])
            .unwrap();
        assert!(raw.retained_chunk(&frames[0].sha256).unwrap().is_none());
        // The stale Bank row alone does not prove custody.
        assert_eq!(
            db.query_row("SELECT count(*) FROM banks WHERE slot=100", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            1
        );
    }
    #[tokio::test]
    async fn direct_authority_is_explicit_and_cannot_rebind_the_feed() {
        let temp = tempfile::tempdir().unwrap();
        let (mut api, _, _db) = replay_fixture(temp.path());
        api.banks.as_mut().unwrap().direct_beam = true;
        let banks = api.banks.as_ref().unwrap();
        replay_head(banks).await.unwrap();
        let path = temp.path().join("RETENTION-AUTHORITY.json");
        let original = std::fs::read(&path).unwrap();
        let mut changed: serde_json::Value = serde_json::from_slice(&original).unwrap();
        changed["producer_generation"] = json!("b".repeat(64));
        std::fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(replay_head(banks).await.is_err());
        std::fs::remove_file(path).unwrap();
        assert!(replay_head(banks).await.is_err());
        let (url, task) = ack_listener(api).await;
        let response = reqwest::Client::new()
            .get(format!("{url}/v2/banks/head"))
            .bearer_auth("k".repeat(32))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            response
                .json::<serde_json::Value>()
                .await
                .unwrap()
                .get("head")
                .is_none()
        );
        task.abort();
    }

    #[tokio::test]
    async fn direct_recovery_notices_require_auth_and_preserve_the_old_format() {
        let temp = tempfile::tempdir().unwrap();
        let (mut api, frames, _db) = replay_fixture(temp.path());
        api.banks.as_mut().unwrap().direct_beam = true;
        let (url, task) = ack_listener(api).await;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let base = v2::cursor(&source().session_id, 0, "-");
        let events = format!("{url}/v2/banks/events?after={base}");
        let key = "k".repeat(32);
        let response = http
            .get(format!("{events}&recovery=1"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = http
            .get(format!("{events}&recovery=2"))
            .bearer_auth(&key)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        for recovery in [false, true] {
            let request = http.get(&events).bearer_auth(&key);
            let request = if recovery {
                request.query(&[("recovery", "1")])
            } else {
                request
            };
            let mut response = request.send().await.unwrap().error_for_status().unwrap();
            assert_eq!(response.headers()["x-blockzilla-start-cursor"], base);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let format = response.headers().get("x-blockzilla-notice-format");
            assert_eq!(
                format.map(|value| value.to_str().unwrap()),
                recovery.then_some(v2::RECOVERY_NOTICE_FORMAT)
            );

            let mut bytes = Vec::new();
            let mut consumed = 0;
            let mut checked = 0;
            while checked < frames.len() {
                bytes.extend_from_slice(&response.chunk().await.unwrap().unwrap());
                assert!(bytes.len() < 128 * 1024);
                let text = std::str::from_utf8(&bytes).unwrap();
                while let Some(end) = text[consumed..].find("\n\n") {
                    let packet = &text[consumed..consumed + end];
                    consumed += end + 2;
                    let Some(id) = packet.lines().find_map(|line| line.strip_prefix("id: ")) else {
                        assert!(packet.starts_with("event: status\n"));
                        continue;
                    };
                    let frame = &frames[checked];
                    let raw = packet
                        .lines()
                        .find_map(|line| line.strip_prefix("data: "))
                        .unwrap();
                    assert!(packet.lines().any(|line| line == "event: chunk"));
                    if recovery {
                        let notice: v2::RecoveryStreamNotice = serde_json::from_str(raw).unwrap();
                        notice
                            .preflight(id, frame.envelope.event.sequence, &source())
                            .unwrap();
                        notice
                            .validate(id, frame, frame.envelope.event.sequence, &source())
                            .unwrap();
                    } else {
                        let notice: Notice = serde_json::from_str(raw).unwrap();
                        notice
                            .validate(id, frame, frame.envelope.event.sequence, &source())
                            .unwrap();
                    }
                    checked += 1;
                }
            }
        }
        task.abort();
    }

    #[tokio::test]
    async fn origin_replays_exact_retained_source_before_spool_without_jump_or_ack() {
        use futures_util::StreamExt;
        let temp = tempfile::tempdir().unwrap();
        let (api, frames, db) = replay_fixture(temp.path());
        let base = v2::cursor(&source().session_id, 0, "-");
        assert_eq!(
            api.banks
                .as_ref()
                .unwrap()
                .store
                .head()
                .earliest_after
                .as_deref(),
            Some(frames[2].cursor.as_str())
        );
        let (url, task) = ack_listener(api).await;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let key = "k".repeat(32);
        let head: v2::Head = http
            .get(format!("{url}/v2/banks/head"))
            .bearer_auth(&key)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(head.earliest_after.as_deref(), Some(base.as_str()));
        head.validate(&source(), crate::store::now_ms(), 5000)
            .unwrap();
        let bootstrap: serde_json::Value = http
            .get(format!("{url}/v2/banks/state"))
            .bearer_auth(&key)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(bootstrap["cursor"], frames[5].cursor);
        assert_eq!(bootstrap["source"], serde_json::to_value(source()).unwrap());
        let response = http
            .get(format!("{url}/v2/banks/events"))
            .query(&[("after", &base)])
            .header("last-event-id", &base)
            .bearer_auth(&key)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        assert_eq!(response.headers()["x-blockzilla-start-cursor"], base);
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        let mut ids = Vec::new();
        let mut consumed = 0;
        while ids.len() < 6 {
            bytes.extend_from_slice(
                &tokio::time::timeout(Duration::from_secs(2), stream.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap(),
            );
            assert!(bytes.len() < 1024 * 1024);
            let text = std::str::from_utf8(&bytes).unwrap();
            while let Some(end) = text[consumed..].find("\n\n") {
                let packet = &text[consumed..consumed + end];
                consumed += end + 2;
                if let Some(id) = packet.lines().find_map(|line| line.strip_prefix("id: ")) {
                    let raw = packet
                        .lines()
                        .find_map(|line| line.strip_prefix("data: "))
                        .unwrap();
                    let notice: v2::Notice = serde_json::from_str(raw).unwrap();
                    assert_eq!(notice.cursor, id);
                    ids.push(id.to_owned());
                }
            }
        }
        assert_eq!(
            ids,
            frames.iter().map(|f| f.cursor.clone()).collect::<Vec<_>>()
        );
        drop(stream);
        let dependency = http
            .get(format!("{url}/v2/banks/chunks/{}", frames[0].sha256))
            .bearer_auth(&key)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(dependency, frames[0].wire);
        assert_eq!(
            db.query_row("SELECT count(*) FROM feed_events", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            6
        );
        assert!(!temp.path().join("consumer-acks.sqlite").exists());
        task.abort();
    }
    #[tokio::test]
    async fn raw_replay_preserves_source_digest_floors_and_relay_window() {
        let temp = tempfile::tempdir().unwrap();
        let (mut api, frames, db) = replay_fixture(temp.path());
        let banks = api.banks.as_mut().unwrap();
        let headers = HeaderMap::new();
        let zero = v2::cursor(&source().session_id, 0, "-");
        let wrong = v2::cursor(&source().session_id, 1, &"b".repeat(64));
        assert_eq!(
            accepted_replay(banks, Position { after: Some(wrong) }, &headers)
                .await
                .unwrap_err()
                .to_string(),
            "invalid_cursor"
        );
        let other = v2::cursor("other-session", 0, "-");
        assert_eq!(
            accepted_replay(banks, Position { after: Some(other) }, &headers)
                .await
                .unwrap_err()
                .to_string(),
            "source_changed"
        );
        banks.origin = false;
        assert_eq!(
            accepted_replay(
                banks,
                Position {
                    after: Some(zero.clone())
                },
                &headers
            )
            .await
            .unwrap_err()
            .to_string(),
            "replay_unavailable"
        );
        assert_eq!(
            replay_head(banks).await.unwrap().earliest_after,
            Some(frames[2].cursor.clone())
        );
        banks.origin = true;
        accepted_replay(
            banks,
            Position {
                after: Some(zero.clone()),
            },
            &headers,
        )
        .await
        .unwrap();
        db.execute(
            "UPDATE feed_retention SET base_sequence=1,base_sha256=?1",
            [&frames[0].sha256],
        )
        .unwrap();
        db.execute("DELETE FROM feed_events WHERE sequence<=1", [])
            .unwrap();
        assert_eq!(
            replay_after(banks, &zero).await.unwrap_err().to_string(),
            "replay_unavailable"
        );
        assert_eq!(
            replay_after(banks, &frames[0].cursor)
                .await
                .unwrap()
                .unwrap()
                .wire,
            frames[1].wire
        );
        // Even if raw retirement advances further, the valid spool remains usable.
        db.execute(
            "UPDATE feed_retention SET base_sequence=4,base_sha256=?1",
            [&frames[3].sha256],
        )
        .unwrap();
        db.execute("DELETE FROM feed_events WHERE sequence<=4", [])
            .unwrap();
        assert_eq!(
            replay_head(banks).await.unwrap().earliest_after,
            Some(frames[2].cursor.clone())
        );
        assert_eq!(
            replay_after(banks, &frames[2].cursor)
                .await
                .unwrap()
                .unwrap()
                .wire,
            frames[3].wire
        );
        assert_eq!(
            accepted_replay(banks, Position { after: Some(zero) }, &headers)
                .await
                .unwrap_err()
                .to_string(),
            "replay_unavailable"
        );
        let mut header: serde_json::Value =
            serde_json::from_slice(&std::fs::read(temp.path().join("FEED.json")).unwrap()).unwrap();
        header["node_identity"] = json!(bs58::encode([55; 32]).into_string());
        std::fs::write(
            temp.path().join("FEED.json"),
            serde_json::to_vec(&header).unwrap(),
        )
        .unwrap();
        assert_eq!(
            replay_head(banks).await.unwrap_err().to_string(),
            "source_changed"
        );
    }
    #[tokio::test]
    async fn origin_ack_is_authenticated_pinned_bounded_and_duplicate_safe_after_retirement() {
        let directory = tempfile::tempdir().unwrap();
        let (a, cursor, db) = ack_fixture(directory.path());
        let (url, task) = ack_listener(a).await;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let endpoint = format!("{url}/v2/banks/ack");
        let token = "k".repeat(32);
        let mut request = json!({"schema":"blockzilla-consumer-ack-v1","consumer_id":"sidecar-primary","source":source(),"cursor":cursor});
        assert_eq!(
            http.post(&endpoint)
                .json(&request)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let receipt: serde_json::Value = http
            .post(&endpoint)
            .bearer_auth(&token)
            .json(&request)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(receipt["coverage_gap_sequence"], 0);
        assert_eq!(receipt["cursor"], cursor);
        request["coverage_gap_sequence"] = json!(3);
        let receipt: serde_json::Value = http
            .post(&endpoint)
            .bearer_auth(&token)
            .json(&request)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(receipt["coverage_gap_sequence"], 3);
        db.execute_batch("DELETE FROM feed_events; DELETE FROM coverage_gaps WHERE sequence=3; UPDATE feed_retention SET base_sequence=1,gap_base_sequence=3;").unwrap();
        db.execute(
            "UPDATE feed_retention SET base_sha256=?1",
            [v2::parse_cursor(&cursor).unwrap().2],
        )
        .unwrap();
        assert_eq!(
            http.post(&endpoint)
                .bearer_auth(&token)
                .json(&request)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let mut future = request.clone();
        future["cursor"] = json!(v2::cursor(&source().session_id, 2, &v2::digest(b"future")));
        assert_eq!(
            http.post(&endpoint)
                .bearer_auth(&token)
                .json(&future)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        let mut unknown = request.clone();
        unknown["consumer_id"] = json!("dynamic-consumer");
        assert_eq!(
            http.post(&endpoint)
                .bearer_auth(&token)
                .json(&unknown)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let mut changed = request.clone();
        changed["source"]["node_identity"] = json!("wrong-source");
        assert_eq!(
            http.post(&endpoint)
                .bearer_auth(&token)
                .json(&changed)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::GONE
        );
        let mut bad_gap = request.clone();
        bad_gap["coverage_gap_sequence"] = json!(8);
        assert_eq!(
            http.post(&endpoint)
                .bearer_auth(&token)
                .json(&bad_gap)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            http.post(&endpoint)
                .bearer_auth(&token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(" ".repeat(17 * 1024))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            crate::consumer_ack::required_frontier(directory.path()).unwrap(),
            (1, 3)
        );
        task.abort();
    }
    #[tokio::test]
    async fn origin_coverage_pages_are_private_sparse_and_report_retired_positions() {
        let directory = tempfile::tempdir().unwrap();
        let (a, _, db) = ack_fixture(directory.path());
        let (url, task) = ack_listener(a).await;
        let http = reqwest::Client::new();
        let endpoint = format!("{url}/v2/banks/coverage-gaps");
        let token = "k".repeat(32);
        assert_eq!(
            http.get(&endpoint).send().await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        let page: serde_json::Value = http
            .get(&endpoint)
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(page["source"], serde_json::to_value(source()).unwrap());
        assert_eq!(page["gaps"][0]["sequence"], 3);
        assert_eq!(page["gaps"][1]["sequence"], 7);
        let page: serde_json::Value = http
            .get(&endpoint)
            .query(&[("after", 3)])
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(page["gaps"].as_array().unwrap().len(), 1);
        assert_eq!(page["gaps"][0]["sequence"], 7);
        assert_eq!(
            http.get(&endpoint)
                .query(&[("limit", 257)])
                .bearer_auth(&token)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        db.execute("UPDATE feed_retention SET gap_base_sequence=3", [])
            .unwrap();
        assert_eq!(
            http.get(&endpoint)
                .bearer_auth(&token)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::GONE
        );
        task.abort();
    }
    #[tokio::test]
    async fn finalized_events_cover_the_root_path_and_resume_by_block_id() {
        let base = v2::cursor(&source().session_id, 0, "-");
        let store = BankStore::open_memory(source(), base, v2::MAX_FRAME).unwrap();
        let anchor = block(1, 10, 1, 9, 100);
        let middle = block(3, 17, 2, 10, 101);
        let tip = block(4, 30, 3, 17, 102);
        let now = crate::store::now_ms();
        store.admit(anchor.clone(), None).unwrap();
        store.admit(control(&anchor, 2, "root", now), None).unwrap();
        store.admit(middle.clone(), None).unwrap();
        store.admit(tip.clone(), None).unwrap();
        store.admit(control(&tip, 5, "root", now), None).unwrap();
        store.set_health("live", None);
        let id = |frame: &v2::Frame| {
            v2::finalized::BlockId::from(&frame.envelope.event.bank).to_string()
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, server::router(api(store)))
                .await
                .unwrap();
        });
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let url = format!("{base_url}/v2/banks/finalized/events");
        let key = "k".repeat(32);
        assert_eq!(http.get(&url).send().await.unwrap().status(), 401);

        async fn read_blocks(
            mut response: reqwest::Response,
            count: usize,
        ) -> Vec<serde_json::Value> {
            assert_eq!(response.status(), 200);
            let mut pending = Vec::new();
            let mut blocks = Vec::new();
            while blocks.len() < count {
                pending.extend_from_slice(&response.chunk().await.unwrap().unwrap());
                while let Some(end) = pending.windows(2).position(|bytes| bytes == b"\n\n") {
                    let record: Vec<_> = pending.drain(..end + 2).collect();
                    let text = std::str::from_utf8(&record).unwrap();
                    if text.contains("\nevent: block\n") {
                        let data = text
                            .lines()
                            .find_map(|line| line.strip_prefix("data: "))
                            .unwrap();
                        let data: serde_json::Value = serde_json::from_str(data).unwrap();
                        assert_eq!(
                            text.lines().next().unwrap().strip_prefix("id: ").unwrap(),
                            data["block_id"].as_str().unwrap()
                        );
                        blocks.push(data);
                    }
                }
            }
            blocks
        }
        let first = http
            .get(&url)
            .query(&[("after", id(&anchor))])
            .bearer_auth(&key)
            .send()
            .await
            .unwrap();
        let first = read_blocks(first, 2).await;
        assert_eq!(first[0]["block_id"], id(&middle));
        assert_eq!(first[0]["parent_id"], id(&anchor));
        assert_eq!(first[0]["commitment"], "finalized");
        assert_eq!(first[1]["block_id"], id(&tip));
        assert_eq!(first[1]["parent_id"], id(&middle));

        let resumed = http
            .get(&url)
            .header("last-event-id", id(&middle))
            .bearer_auth(&key)
            .send()
            .await
            .unwrap();
        assert_eq!(read_blocks(resumed, 1).await[0]["block_id"], id(&tip));
        let wrong = v2::finalized::BlockId {
            slot: 17,
            blockhash: [91; 32],
        }
        .to_string();
        let missing = http
            .get(&url)
            .query(&[("after", wrong)])
            .bearer_auth(&key)
            .send()
            .await
            .unwrap();
        assert_eq!(missing.status(), 410);
        assert_eq!(
            missing.json::<serde_json::Value>().await.unwrap()["head"]["tip"],
            id(&tip)
        );
        let bytes = http
            .get(format!("{base_url}{}", first[0]["url"].as_str().unwrap()))
            .bearer_auth(&key)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(bytes, middle.wire);
        task.abort();
    }

    #[tokio::test]
    async fn finalized_lookup_forwards_only_the_pinned_exact_origin_block() {
        let payload = block(1, 9, 1, 8, 9);
        let id = v2::finalized::BlockId::from(&payload.envelope.event.bank).to_string();
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_url = format!("http://{}/", origin.local_addr().unwrap());
        let origin_task = tokio::spawn({
            let payload = payload.clone();
            async move {
                let router = Router::new().route(
                    "/v2/banks/finalized/blocks/{id}",
                    get(move |Path(id): Path<String>, headers: HeaderMap| {
                        let payload = payload.clone();
                        async move {
                            assert_eq!(
                                headers[header::AUTHORIZATION],
                                "Bearer private-origin-token"
                            );
                            if id.starts_with("10:") {
                                return (
                                    StatusCode::NOT_FOUND,
                                    Json(json!({"error":"block_unavailable"})),
                                )
                                    .into_response();
                            }
                            let mut response = block_response(&payload);
                            response
                                .headers_mut()
                                .insert("x-blockzilla-commitment", "finalized".parse().unwrap());
                            response
                        }
                    }),
                );
                axum::serve(origin, router).await.unwrap();
            }
        });
        let upstream = crate::upstream::Upstream {
            url: origin_url,
            token: "private-origin-token".into(),
            ca: None,
            identity: None,
        };
        let client = upstream.client().unwrap();
        let base = v2::cursor(&source().session_id, 0, "-");
        let store = BankStore::open_memory(source(), base, v2::MAX_FRAME).unwrap();
        let mut api = api(store);
        api.banks.as_mut().unwrap().hot_upstream = Some((upstream, client));
        let relay = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/v2/banks/finalized/blocks",
            relay.local_addr().unwrap()
        );
        let relay_task =
            tokio::spawn(async move { axum::serve(relay, server::router(api)).await.unwrap() });
        let http = reqwest::Client::new();
        let good = format!("{url}/{id}");
        assert_eq!(http.get(&good).send().await.unwrap().status(), 401);
        let get = |url| http.get(url).bearer_auth("k".repeat(32)).send();
        let response = get(good).await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["x-blockzilla-commitment"], "finalized");
        assert_eq!(response.bytes().await.unwrap(), payload.wire);

        let wrong = v2::finalized::BlockId {
            slot: 9,
            blockhash: [77; 32],
        };
        assert_eq!(get(format!("{url}/{wrong}")).await.unwrap().status(), 503);
        let missing = v2::finalized::BlockId {
            slot: 10,
            blockhash: [10; 32],
        };
        let response = get(format!("{url}/{missing}")).await.unwrap();
        assert_eq!(response.status(), 404);
        assert_eq!(
            response.json::<serde_json::Value>().await.unwrap()["error"],
            "block_unavailable"
        );
        relay_task.abort();
        origin_task.abort();
    }

    #[tokio::test]
    async fn public_bank_views_share_native_confirmation_and_keep_full_blocks_private() {
        let payload = v2::decode(bytes::Bytes::from_static(include_bytes!(
            "../client/fixtures/bank-v2/block.bin"
        )))
        .unwrap();
        let base = v2::cursor(&payload.source.session_id, 0, "-");
        let store =
            BankStore::open_memory(payload.source.clone(), base.clone(), v2::MAX_FRAME).unwrap();
        let now = crate::store::now_ms();
        let root = control(&payload, 2, "root", now);
        store.admit(payload.clone(), None).unwrap();
        store.admit(root.clone(), None).unwrap();
        store.set_health("live", None);
        let mut api = api(store);
        api.banks.as_mut().unwrap().public_views = Some(Default::default());
        api.public_requests = Arc::new(Semaphore::new(2));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, server::router(api)).await.unwrap();
        });
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();

        let mut signing = client
            .get(format!("{url}/v2/blockhashes"))
            .send()
            .await
            .unwrap();
        assert_eq!(signing.status(), 200);
        let packet = signing.chunk().await.unwrap().unwrap();
        let packet = std::str::from_utf8(&packet).unwrap();
        let observation = v2::ConfirmedObservation::from_frame(&root).unwrap();
        assert!(packet.contains("event: blockhash\n"));
        assert!(packet.contains(&observation.recent_blockhash.blockhash));
        assert!(packet.contains(&format!(
            "\"lastValidBlockHeight\":{}",
            observation.recent_blockhash.last_valid_block_height
        )));

        let mut landed = client
            .get(format!("{url}/v2/landed-blocks?after={base}"))
            .send()
            .await
            .unwrap();
        assert_eq!(landed.status(), 200);
        let mut packets = landed.chunk().await.unwrap().unwrap().to_vec();
        let block = loop {
            if let Some(record) = std::str::from_utf8(&packets)
                .unwrap()
                .split("\n\n")
                .find(|record| record.contains("\nevent: block\n") && record.ends_with('}'))
            {
                break record.to_owned();
            }
            packets.extend_from_slice(&landed.chunk().await.unwrap().unwrap());
        };
        assert!(packets.starts_with(format!("id: {base}\nevent: status\n").as_bytes()));
        assert!(block.starts_with(&format!("id: {}\n", root.cursor)));
        let data = block
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap();
        let data: serde_json::Value = serde_json::from_str(data).unwrap();
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../client/fixtures/bank-v2/block.decoded.json"
        ))
        .unwrap();
        let tx = &expected["blocks"][0]["transactions"][0];
        assert_eq!(tx["success"], false);
        assert_eq!(data["signatures"], json!([tx["signature"]]));
        assert_eq!(data["blockhash"], expected["blocks"][0]["blockhash"]);
        assert_eq!(data["commitment"], "finalized");

        let chunk = format!("{url}/v2/banks/chunks/{}", payload.sha256);
        assert_eq!(client.get(&chunk).send().await.unwrap().status(), 401);
        let exact = client
            .get(&chunk)
            .bearer_auth("k".repeat(32))
            .send()
            .await
            .unwrap();
        assert_eq!(exact.bytes().await.unwrap(), payload.wire);
        task.abort();
    }
    #[tokio::test]
    async fn public_v2_bearer_headers_cursor_conflict_and_gap_contract() {
        let t = tempfile::tempdir().unwrap();
        let base = v2::cursor(&source().session_id, 0, "-");
        let store =
            BankStore::open(source(), base.clone(), v2::MAX_FRAME, t.path().into()).unwrap();
        let b = block(1, 9, 1, 8, 9);
        store.admit(b.clone(), None).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = server::router(api(store.clone()));
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = reqwest::Client::new();
        let url = format!("http://{addr}");
        let key = "k".repeat(32);
        assert_eq!(
            client
                .get(format!("{url}/v2/banks/head?api_key={key}"))
                .send()
                .await
                .unwrap()
                .status(),
            401
        );
        assert_eq!(
            client
                .get(format!("{url}/v2/banks/head"))
                .bearer_auth(&key)
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        let mut r = client
            .get(format!("{url}/v2/banks/events?after={base}"))
            .bearer_auth(&key)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers()["x-blockzilla-start-cursor"], base);
        let initial = r.chunk().await.unwrap().unwrap();
        let text = String::from_utf8(initial.to_vec()).unwrap();
        assert!(text.starts_with("event: status\ndata: ") && !text.starts_with("id:"));
        drop(r);
        let r = client
            .get(format!("{url}/v2/banks/events?after={base}"))
            .header("last-event-id", &b.cursor)
            .bearer_auth(&key)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400);
        assert_eq!(
            r.json::<serde_json::Value>().await.unwrap()["error"],
            "cursor_conflict"
        );
        let r = client
            .get(format!("{url}/v2/banks/events?after=other-session:p0:-"))
            .bearer_auth(&key)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 410);
        let gap = r.json::<serde_json::Value>().await.unwrap();
        assert_eq!(gap["error"], "source_changed");
        assert_eq!(gap["head"]["profile"], v2::PROFILE);
        let r = client
            .get(format!("{url}/v2/banks/chunks/{}", b.sha256))
            .bearer_auth(&key)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.bytes().await.unwrap(), b.wire);
        store.set_health("failed", None);
        let r = client
            .get(format!("{url}/v2/banks/events?after={}", b.cursor))
            .bearer_auth(&key)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 410);
        assert_eq!(
            r.json::<serde_json::Value>().await.unwrap()["error"],
            "source_failed"
        );
        task.abort();
    }
    #[test]
    fn notice_url_and_id_are_checked_before_any_credentialed_get() {
        let b = block(1, 17, 7, 3, 10);
        let n = Notice::from_frame(&b);
        n.preflight(&b.cursor, 1, &source()).unwrap();
        let mut n = n;
        n.url = "https://attacker.invalid/steal".into();
        assert!(n.preflight(&b.cursor, 1, &source()).is_err());
        n.url = format!("/v2/banks/chunks/{}", b.sha256);
        assert!(n.preflight("wrong", 1, &source()).is_err());
        let _ = Request::builder();
    }
}
