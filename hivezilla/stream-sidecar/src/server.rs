use crate::{
    config::{Filter, View},
    consume::Runtime,
    projection,
    store::Store,
};
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, Query, Request, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;
#[derive(Clone)]
pub struct Api {
    pub store: Arc<Store>,
    pub runtime: Arc<Runtime>,
    pub token: Arc<String>,
    pub reader_token: Option<Arc<String>>,
    pub clients: Arc<Semaphore>,
    pub renderers: Arc<Semaphore>,
}
fn error(status: StatusCode, reason: &str) -> Response {
    (status, Json(json!({"error":reason}))).into_response()
}
async fn auth(State(api): State<Api>, request: Request, next: Next) -> Response {
    let headers = request.headers();
    let key = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let matches = |expected: &str| {
        key.is_some_and(|value| {
            value.len() == expected.len()
                && value
                    .bytes()
                    .zip(expected.bytes())
                    .fold(0u8, |a, (x, y)| a | (x ^ y))
                    == 0
        })
    };
    let admin = matches(&api.token);
    let reader = api
        .reader_token
        .as_ref()
        .is_some_and(|token| matches(token));
    if headers.get_all("authorization").iter().count() != 1 || (!admin && !reader) {
        return error(StatusCode::UNAUTHORIZED, "authentication_required");
    }
    if request.method() != axum::http::Method::GET && !admin {
        return error(StatusCode::FORBIDDEN, "admin_scope_required");
    }
    if let Some(query) = request.uri().query() {
        if query.len() > 32768 {
            return error(StatusCode::BAD_REQUEST, "query_too_large");
        }
        let url = reqwest::Url::parse(&format!("http://localhost/?{query}"));
        if url.is_err()
            || url.is_ok_and(|url| {
                url.query_pairs().any(|(key, _)| {
                    matches!(
                        key.to_ascii_lowercase().as_str(),
                        "token" | "access_token" | "api_key" | "api-key" | "authorization" | "key"
                    )
                })
            })
        {
            return error(StatusCode::BAD_REQUEST, "query_credentials_not_supported");
        }
    }
    next.run(request).await
}
pub fn router(api: Api) -> Router {
    Router::new()
        .route("/v1/head", get(head))
        .route("/v1/blockhashes", get(blockhashes))
        .route("/v1/blockhash-observations", get(blockhash_observations))
        .route("/v1/blocks", get(blocks))
        .route("/v1/signatures", get(signatures))
        .route("/v1/updates", get(updates))
        .route("/v1/webhooks", get(webhooks))
        .route("/v1/webhooks/{id}/resume", post(resume))
        .route("/v1/webhook-jobs/{id}/retry", post(retry))
        .layer(DefaultBodyLimit::max(4096))
        .layer(middleware::from_fn_with_state(api.clone(), auth))
        .with_state(api)
}
async fn head(State(api): State<Api>) -> Json<Value> {
    let mut h = api.runtime.status(&api.store);
    h["payloadMode"] = json!(api.store.payload_mode.name());
    h["storage"] = api
        .store
        .storage_status()
        .unwrap_or_else(|_| json!({"error":"storage_state_unavailable"}));
    h["outputCursor"] = json!(api.store.output_cursor().ok());
    h["routes"] = json!({
        "blockhashes":{"path":"/v1/blockhashes","replay":false,"purpose":"current signing readiness; stale hashes are withheld","cursor":"native sourceCursor in each observation"},
        "blockhashObservations":{"path":"/v1/blockhash-observations","replay":true,"purpose":"historical native confirmation/finality observations; never proof of current signing readiness"},
        "blocks":{"path":"/v1/blocks","replay":true},
        "signatures":{"path":"/v1/signatures","replay":true},
        "updates":{"path":"/v1/updates","replay":true},
        "resume":{"header":"Last-Event-ID","cursor":"service output cursor","expiredStatus":410,"sourceChangeStatus":410},
        "authentication":{"read":"reader or admin Bearer header","management":"admin Bearer header","queryTokens":false}
    });
    if api.store.payload_mode == projection::PayloadMode::CompactOnly {
        h["routes"]["blocks"]["requiredQuery"] = json!({"projection":"compact"});
        h["routes"]["signatures"]["available"] = json!(false);
        h["routes"]["updates"]["available"] = json!(false);
    }
    Json(h)
}
async fn webhooks(State(api): State<Api>) -> Response {
    match api.store.subscriptions() {
        Ok(v) => Json(v).into_response(),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "store_unavailable"),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Resume {
    accept_gap: bool,
}
async fn resume(
    State(api): State<Api>,
    Path(id): Path<String>,
    Json(body): Json<Resume>,
) -> Response {
    match api.store.resume(&id, body.accept_gap) {
        Ok(()) => Json(json!({"state":"RESUMED","id":id})).into_response(),
        Err(e) => error(StatusCode::CONFLICT, &e.to_string()),
    }
}
async fn retry(State(api): State<Api>, Path(id): Path<String>) -> Response {
    match api.store.retry_job(&id) {
        Ok(()) => Json(json!({"state":"PENDING","deliveryId":id})).into_response(),
        Err(e) => error(StatusCode::CONFLICT, &e.to_string()),
    }
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Position {
    after: Option<String>,
    account: Option<String>,
    program: Option<String>,
    failed: Option<bool>,
    projection: Option<projection::BlockProjection>,
}
fn packet(kind: &str, id: Option<&str>, value: &Value) -> String {
    let mut s = String::new();
    if let Some(id) = id {
        s.push_str("id: ");
        s.push_str(id);
        s.push('\n');
    }
    s.push_str("event: ");
    s.push_str(kind);
    s.push_str("\ndata: ");
    s.push_str(&value.to_string());
    s.push_str("\n\n");
    s
}
fn response(body: Body) -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/event-stream; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        body,
    )
        .into_response()
}
async fn blocks(
    State(a): State<Api>,
    q: Result<Query<Position>, QueryRejection>,
    h: HeaderMap,
) -> Response {
    events(a, q, h, View::Blocks).await
}
async fn signatures(
    State(a): State<Api>,
    q: Result<Query<Position>, QueryRejection>,
    h: HeaderMap,
) -> Response {
    events(a, q, h, View::Signatures).await
}
async fn updates(
    State(a): State<Api>,
    q: Result<Query<Position>, QueryRejection>,
    h: HeaderMap,
) -> Response {
    events(a, q, h, View::Updates).await
}
async fn blockhash_observations(
    State(a): State<Api>,
    q: Result<Query<Position>, QueryRejection>,
    h: HeaderMap,
) -> Response {
    events(a, q, h, View::Blockhashes).await
}
async fn events(
    api: Api,
    q: Result<Query<Position>, QueryRejection>,
    headers: HeaderMap,
    view: View,
) -> Response {
    let Ok(Query(q)) = q else {
        return error(StatusCode::BAD_REQUEST, "invalid_query");
    };
    if q.projection.is_some() && view != View::Blocks {
        return error(StatusCode::BAD_REQUEST, "projection_requires_blocks_route");
    }
    let block_projection = q.projection.unwrap_or_default();
    if api.store.payload_mode == projection::PayloadMode::CompactOnly
        && !(view == View::Blockhashes
            || view == View::Blocks && block_projection == projection::BlockProjection::Compact)
    {
        return error(
            StatusCode::CONFLICT,
            "compact_only_mode_requires_compact_blocks_or_native_blockhashes",
        );
    }
    if headers.get_all("last-event-id").iter().count() > 1 {
        return error(StatusCode::BAD_REQUEST, "invalid_cursor");
    }
    let h = match headers.get("last-event-id").map(|v| v.to_str()).transpose() {
        Ok(v) => v,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_cursor"),
    };
    if let (Some(a), Some(b)) = (q.after.as_deref(), h) {
        if a != b {
            return error(StatusCode::BAD_REQUEST, "cursor_conflict");
        }
    }
    let filter = Filter {
        accounts: q
            .account
            .map(|v| v.split(',').map(str::to_owned).collect())
            .unwrap_or_default(),
        programs: q
            .program
            .map(|v| v.split(',').map(str::to_owned).collect())
            .unwrap_or_default(),
        failed: q.failed,
    };
    if filter.validate().is_err()
        || (matches!(view, View::Blocks | View::Blockhashes)
            && (!filter.accounts.is_empty()
                || !filter.programs.is_empty()
                || filter.failed.is_some()))
    {
        return error(StatusCode::BAD_REQUEST, "invalid_filter");
    }
    let mut cursor = match q
        .after
        .or_else(|| h.map(str::to_owned))
        .map(Ok)
        .unwrap_or_else(|| api.store.output_cursor())
    {
        Ok(v) => v,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "source_not_started"),
    };
    let Ok(permit) = api.clients.clone().try_acquire_owned() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "client_limit");
    };
    let admission = api.store.clone();
    let after = cursor.clone();
    let admission = tokio::task::spawn_blocking(move || admission.validate_after(&after)).await;
    if let Err(e) = admission.unwrap_or_else(|_| Err(anyhow::anyhow!("store_unavailable"))) {
        return error(
            if matches!(
                e.to_string().as_str(),
                "source_changed" | "replay_unavailable"
            ) {
                StatusCode::GONE
            } else {
                StatusCode::BAD_REQUEST
            },
            &e.to_string(),
        );
    }
    let stream = async_stream::stream! {
        let _permit=permit;let mut next_status=tokio::time::Instant::now();
        loop{
            let changed=api.store.notify.notified();tokio::pin!(changed);changed.as_mut().enable();let now=tokio::time::Instant::now();
            if now>=next_status{yield Ok::<_,std::io::Error>(bytes::Bytes::from(packet("status",None,&api.runtime.status(&api.store))));next_status=now+Duration::from_secs(1);}
            let store=api.store.clone();let after=cursor.clone();let filter=filter.clone();
            let Ok(render)=api.renderers.clone().acquire_owned().await else {
                yield Ok(bytes::Bytes::from(packet("error",None,&json!({"error":"renderer_unavailable"}))));break;
            };
            // Only one bounded read/render is in flight per admitted client.
            // The shared render permit and payload drop before socket backpressure.
            let next=tokio::task::spawn_blocking(move||{let _render=render;next_packet(&store,&after,view,&filter,block_projection)}).await
                .unwrap_or_else(|_|Err(anyhow::anyhow!("store_unavailable")));
            match next{
                Ok(Some((next,text)))=>{cursor=next;yield Ok(bytes::Bytes::from(text));continue;},
                Ok(None)=>{},
                Err(e)=>{yield Ok(bytes::Bytes::from(packet("gap",None,&json!({"error":e.to_string(),"source":api.store.source,"after":cursor}))));break;}
            }
            tokio::select!{_=&mut changed=>{},_=tokio::time::sleep_until(next_status)=>{}}
        }
    };
    response(Body::from_stream(stream))
}
fn next_packet(
    store: &Store,
    cursor: &str,
    view: View,
    filter: &Filter,
    block_projection: projection::BlockProjection,
) -> anyhow::Result<Option<(String, String)>> {
    if view == View::Blockhashes
        || view == View::Blocks && block_projection == projection::BlockProjection::Compact
    {
        let Some(record) = store.after_native(cursor)? else {
            return Ok(None);
        };
        let data = projection::render_with_block_projection(
            &record.event,
            &store.source,
            &Value::Null,
            record.wire(),
            &record.cursor,
            &record.source_cursor,
            &record.affected,
            view,
            filter,
            block_projection,
        )?
        .unwrap_or_else(|| json!({"source":store.source,"cursor":record.cursor,"matched":false}));
        let kind = if data["matched"] == false {
            "cursor"
        } else {
            &record.kind
        };
        let text = packet(kind, Some(&record.cursor), &data);
        anyhow::ensure!(text.len() <= crate::store::MAX_BODY, "output_too_large");
        return Ok(Some((record.cursor, text)));
    }
    let Some(record) = store.after(cursor)? else {
        return Ok(None);
    };
    let value = projection::render_with_block_projection(
        &record.event,
        &store.source,
        record.payload_json(),
        record.wire(),
        &record.cursor,
        &record.source_cursor,
        &record.affected,
        view,
        filter,
        block_projection,
    )?;
    let data = value
        .unwrap_or_else(|| json!({"source":store.source,"cursor":record.cursor,"matched":false}));
    let kind = if data["matched"] == false {
        "cursor"
    } else {
        record.kind.as_str()
    };
    let text = packet(kind, Some(&record.cursor), &data);
    anyhow::ensure!(text.len() <= crate::store::MAX_BODY, "output_too_large");
    Ok(Some((record.cursor, text)))
}
async fn blockhashes(
    State(api): State<Api>,
    q: Result<Query<Position>, QueryRejection>,
    h: HeaderMap,
) -> Response {
    let Ok(Query(q)) = q else {
        return error(StatusCode::BAD_REQUEST, "invalid_query");
    };
    if h.contains_key("last-event-id")
        || q.after.is_some()
        || q.account.is_some()
        || q.program.is_some()
        || q.failed.is_some()
        || q.projection.is_some()
    {
        return error(
            StatusCode::BAD_REQUEST,
            "current_readiness_does_not_support_replay_or_filters",
        );
    }
    let Ok(permit) = api.clients.clone().try_acquire_owned() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "client_limit");
    };
    let stream = async_stream::stream! {
        let _permit=permit;let mut last=None::<String>;
        loop{
            let changed=api.store.notify.notified();tokio::pin!(changed);changed.as_mut().enable();let health=api.runtime.status(&api.store);yield Ok::<_,std::io::Error>(bytes::Bytes::from(packet("status",None,&health)));
            if health["signingReady"]==true{
                let value=&health["signing"];if let Some(cursor)=value["sourceCursor"].as_str(){if last.as_deref()!=Some(cursor){last=Some(cursor.into());yield Ok(bytes::Bytes::from(packet("blockhash",None,value)));}}
            }
            tokio::select!{_=&mut changed=>{},_=tokio::time::sleep(Duration::from_secs(1))=>{}}
        }
    };
    response(Body::from_stream(stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{projection::Payload, store::Limits};
    use base64::{Engine, engine::general_purpose::STANDARD};
    use blockzilla_bank_client::{Bootstrap, Delivery};
    use blockzilla_bank_stream_v2::{self as v2, Head, fixtures::*};
    use futures_util::StreamExt;

    const ADMIN: &str = "fixture-admin-000000000000000000000000000000";
    const READER: &str = "fixture-reader-00000000000000000000000000000";
    struct Fixture {
        _temp: tempfile::TempDir,
        store: Arc<Store>,
        address: String,
        server: tokio::task::JoinHandle<()>,
        cursors: Vec<String>,
        payload: Payload,
        clients: Arc<Semaphore>,
        renderers: Arc<Semaphore>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }
    fn payload(sequence: u64, slot: u64) -> Payload {
        let account = bs58::encode([8; 32]).into_string();
        let program = bs58::encode([9; 32]).into_string();
        Payload {
            frame: block(sequence, slot, slot, slot - 1, slot),
            json: json!({"blocks":[{"slot":slot,"bankId":slot,"blockhash":bs58::encode([slot as u8;32]).into_string(),"parentSlot":slot-1,"parentBlockhash":bs58::encode([(slot-1) as u8;32]).into_string(),"blockHeight":slot,"transactionCount":2,"transactions":[
                {"index":0,"signature":"failed-signature","signatures":["failed-signature","second-signer"],"success":false,"err":{"InstructionError":[0,{"Custom":2}]},"accountKeys":[account],"topLevelPrograms":[],"innerPrograms":[]},
                {"index":1,"signature":"passed-signature","signatures":["passed-signature"],"success":true,"err":null,"accountKeys":[],"topLevelPrograms":[program],"innerPrograms":[]}
            ]}]}),
        }
    }
    async fn fixture(max_clients: usize) -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(
            &temp.path().join("sidecar.sqlite"),
            source(),
            "fixture-generation".into(),
            vec![],
            Limits::default(),
        )
        .unwrap();
        let base = v2::cursor(&source().session_id, 0, "-");
        store
            .bootstrap(
                &Bootstrap {
                    after: base.clone(),
                    head: Head {
                        schema: v2::HEAD.into(),
                        profile: v2::PROFILE.into(),
                        source: source(),
                        cursor: Some(base.clone()),
                        earliest_after: Some(base),
                        status: "starting".into(),
                        sampled_at_unix_ms: 1000,
                        source_observed_at_unix_ms: None,
                        source_lag_ms: None,
                        latest_confirmed: None,
                    },
                    control: None,
                    payload: None,
                },
                None,
            )
            .unwrap();
        let mut cursors = vec![store.output_cursor().unwrap()];
        let first = payload(1, 9);
        store
            .commit(
                &Delivery {
                    frame: first.frame.clone(),
                    dependency: None,
                },
                Some(&first),
            )
            .unwrap();
        cursors.push(store.output_cursor().unwrap());
        let root = control(&first.frame, 2, "root", 1001);
        store
            .commit(
                &Delivery {
                    frame: root,
                    dependency: None,
                },
                None,
            )
            .unwrap();
        cursors.push(store.output_cursor().unwrap());
        let second = payload(3, 10);
        store
            .commit(
                &Delivery {
                    frame: second.frame.clone(),
                    dependency: None,
                },
                Some(&second),
            )
            .unwrap();
        cursors.push(store.output_cursor().unwrap());
        for (sequence, kind) in [(4, "confirmed"), (5, "invalidate")] {
            store
                .commit(
                    &Delivery {
                        frame: control(&second.frame, sequence, kind, 1000 + sequence),
                        dependency: None,
                    },
                    None,
                )
                .unwrap();
            cursors.push(store.output_cursor().unwrap());
        }
        let clients = Arc::new(Semaphore::new(max_clients));
        let renderers = Arc::new(Semaphore::new(1));
        let app = router(Api {
            store: store.clone(),
            runtime: Arc::new(Runtime::default()),
            token: Arc::new(ADMIN.into()),
            reader_token: Some(Arc::new(READER.into())),
            clients: clients.clone(),
            renderers: renderers.clone(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Fixture {
            _temp: temp,
            store,
            address,
            server,
            cursors,
            payload: first,
            clients,
            renderers,
        }
    }

    #[tokio::test]
    async fn compact_only_mode_has_explicit_routes_and_wire_only_storage_status() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open_with_mode(
            &temp.path().join("compact.sqlite"),
            source(),
            "generation".into(),
            vec![],
            Limits::default(),
            projection::PayloadMode::CompactOnly,
            0,
        )
        .unwrap();
        let base = v2::cursor(&source().session_id, 0, "-");
        store
            .bootstrap(
                &Bootstrap {
                    after: base.clone(),
                    head: Head {
                        schema: v2::HEAD.into(),
                        profile: v2::PROFILE.into(),
                        source: source(),
                        cursor: Some(base.clone()),
                        earliest_after: Some(base),
                        status: "starting".into(),
                        sampled_at_unix_ms: 1000,
                        source_observed_at_unix_ms: None,
                        source_lag_ms: None,
                        latest_confirmed: None,
                    },
                    control: None,
                    payload: None,
                },
                None,
            )
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let app = router(Api {
            store,
            runtime: Arc::new(Runtime::default()),
            token: Arc::new(ADMIN.into()),
            reader_token: Some(Arc::new(READER.into())),
            clients: Arc::new(Semaphore::new(4)),
            renderers: Arc::new(Semaphore::new(1)),
        });
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = reqwest::Client::new();
        for route in [
            "/v1/blocks",
            "/v1/blocks?projection=full",
            "/v1/signatures",
            "/v1/updates",
        ] {
            let response = client
                .get(format!("{address}{route}"))
                .bearer_auth(READER)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::CONFLICT, "route {route}");
            assert!(response.text().await.unwrap().contains("compact_only_mode"));
        }
        for route in [
            "/v1/blocks?projection=compact",
            "/v1/blockhashes",
            "/v1/blockhash-observations",
        ] {
            let response = client
                .get(format!("{address}{route}"))
                .bearer_auth(READER)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "route {route}");
            drop(response);
        }
        let head: Value = client
            .get(format!("{address}/v1/head"))
            .bearer_auth(READER)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(head["payloadMode"], "compact-only");
        assert_eq!(head["storage"]["persistedProjectionBytes"], 0);
        assert_eq!(head["routes"]["signatures"]["available"], false);
        assert_eq!(
            head["routes"]["blocks"]["requiredQuery"]["projection"],
            "compact"
        );
        server.abort();
    }
    async fn read_updates(
        response: reqwest::Response,
        count: usize,
    ) -> Vec<(String, String, Value)> {
        let mut stream = response.bytes_stream();
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut pending = String::new();
            let mut values = vec![];
            while let Some(bytes) = stream.next().await {
                pending.push_str(std::str::from_utf8(&bytes.unwrap()).unwrap());
                while let Some(end) = pending.find("\n\n") {
                    let packet = pending[..end].to_owned();
                    pending.drain(..end + 2);
                    let id = packet.lines().find_map(|line| line.strip_prefix("id: "));
                    let kind = packet.lines().find_map(|line| line.strip_prefix("event: "));
                    let data = packet.lines().find_map(|line| line.strip_prefix("data: "));
                    if let (Some(id), Some(kind), Some(data)) = (id, kind, data) {
                        values.push((
                            id.to_owned(),
                            kind.to_owned(),
                            serde_json::from_str(data).unwrap(),
                        ));
                        if values.len() == count {
                            return values;
                        }
                    }
                }
            }
            panic!("SSE ended before expected updates");
        })
        .await
        .unwrap()
    }
    fn query(route: &str, pairs: &[(&str, &String)]) -> reqwest::Url {
        let mut url = reqwest::Url::parse(route).unwrap();
        for (key, value) in pairs {
            url.query_pairs_mut().append_pair(key, value);
        }
        url
    }
    #[tokio::test]
    async fn bearer_scope_and_query_credentials_are_checked_over_http() {
        let f = fixture(4).await;
        let http = reqwest::Client::new();
        let head = format!("{}/v1/head", f.address);
        assert_eq!(http.get(&head).send().await.unwrap().status(), 401);
        assert_eq!(
            http.get(format!("{head}?token={READER}"))
                .send()
                .await
                .unwrap()
                .status(),
            401
        );
        assert_eq!(
            http.get(&head)
                .bearer_auth("wrong")
                .send()
                .await
                .unwrap()
                .status(),
            401
        );
        assert_eq!(
            http.get(&head)
                .bearer_auth(READER)
                .header("authorization", format!("Bearer {ADMIN}"))
                .send()
                .await
                .unwrap()
                .status(),
            401
        );
        for token in [ADMIN, READER] {
            let response = http.get(&head).bearer_auth(token).send().await.unwrap();
            assert_eq!(response.status(), 200);
            let value: Value = response.json().await.unwrap();
            assert_eq!(value["routes"]["blockhashes"]["replay"], false);
            assert_eq!(value["routes"]["blockhashObservations"]["replay"], true);
            assert_eq!(
                http.get(format!("{head}?%74oKeN=hidden"))
                    .bearer_auth(token)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                400
            );
        }
        let route = format!("{}/v1/webhooks/unknown/resume", f.address);
        assert_eq!(
            http.post(&route)
                .bearer_auth(READER)
                .json(&json!({"accept_gap":true}))
                .send()
                .await
                .unwrap()
                .status(),
            403
        );
        assert_eq!(
            http.post(&route)
                .bearer_auth(ADMIN)
                .json(&json!({"accept_gap":true}))
                .send()
                .await
                .unwrap()
                .status(),
            409
        );
    }
    #[tokio::test]
    async fn full_blocks_replay_exact_frames_and_resume_with_control_identity() {
        let f = fixture(4).await;
        let http = reqwest::Client::new();
        let route = format!("{}/v1/blocks", f.address);
        let response = http
            .get(&route)
            .bearer_auth(READER)
            .header("last-event-id", &f.cursors[0])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let values = read_updates(response, 2).await;
        assert_eq!(values[0].0, f.cursors[1]);
        assert_eq!(values[0].1, "block");
        assert_eq!(
            STANDARD
                .decode(values[0].2["compactFrameBase64"].as_str().unwrap())
                .unwrap(),
            f.payload.frame.wire.as_ref()
        );
        assert_eq!(
            values[0].2["block"]["transactions"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(values[1].0, f.cursors[2]);
        assert_eq!(values[1].1, "root");
        assert_eq!(values[1].2["event"]["commitment"], "finalized");
        let response = http
            .get(&route)
            .bearer_auth(READER)
            .header("last-event-id", &values[1].0)
            .send()
            .await
            .unwrap();
        let values = read_updates(response, 3).await;
        assert_eq!(
            values.iter().map(|v| v.0.clone()).collect::<Vec<_>>(),
            f.cursors[3..].to_vec()
        );
        assert_eq!(values[2].1, "invalidate");
        assert!(
            values[2].2["invalidatedBanks"]
                .as_array()
                .is_some_and(|v| !v.is_empty())
        );
    }
    #[tokio::test]
    async fn compact_projection_keeps_frame_controls_and_resume_without_expanded_blocks() {
        let f = fixture(4).await;
        let http = reqwest::Client::new();
        let read = |query: &'static str| {
            let http = http.clone();
            let route = format!("{}/v1/blocks{query}", f.address);
            let after = f.cursors[0].clone();
            async move {
                let response = http
                    .get(route)
                    .bearer_auth(READER)
                    .header("last-event-id", after)
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), 200);
                read_updates(response, 5).await
            }
        };
        let full = read("").await;
        f.store.payloads.clear_resident();
        let compact = read("?projection=compact").await;
        assert_eq!(
            f.store.payloads.stats()["entries"],
            0,
            "compact response cache misses must not materialize portable projections"
        );
        let explicit_full = read("?projection=full").await;
        assert_eq!(
            full, explicit_full,
            "default full projection must remain unchanged"
        );
        let mut full_bytes = 0usize;
        let mut compact_bytes = 0usize;
        for (full, compact) in full.iter().zip(&compact) {
            assert_eq!(full.0, compact.0);
            assert_eq!(full.1, compact.1);
            full_bytes += packet(&full.1, Some(&full.0), &full.2).len();
            compact_bytes += packet(&compact.1, Some(&compact.0), &compact.2).len();
            let mut expected = full.2.clone();
            expected.as_object_mut().unwrap().remove("block");
            assert_eq!(
                compact.2, expected,
                "only expanded block projection may change"
            );
            if let Some(encoded) = compact.2["compactFrameBase64"].as_str() {
                let wire = STANDARD.decode(encoded).unwrap();
                let frame = v2::decode(wire.into()).unwrap();
                assert_eq!(
                    compact.2["event"]["bank"],
                    serde_json::to_value(&frame.envelope.event.bank).unwrap()
                );
                if let Some(digest) = compact.2["event"]["payload_frame_sha256"].as_str() {
                    assert_eq!(digest, frame.sha256);
                } else {
                    assert_eq!(compact.1, "block");
                }
            }
        }
        assert!(
            compact_bytes < full_bytes,
            "compact projection must transfer fewer SSE bytes"
        );
        assert_eq!(compact.last().unwrap().1, "invalidate");
        let response = http
            .get(format!("{}/v1/blocks?projection=compact", f.address))
            .bearer_auth(READER)
            .header("last-event-id", &compact[1].0)
            .send()
            .await
            .unwrap();
        let resumed = read_updates(response, 3).await;
        assert_eq!(resumed, compact[2..]);
    }

    #[tokio::test]
    async fn block_projection_query_rejects_unknown_values_filters_and_other_routes() {
        let f = fixture(4).await;
        let http = reqwest::Client::new();
        for route in [
            "/v1/blocks?projection=logs",
            "/v1/signatures?projection=compact",
            "/v1/updates?projection=full",
            "/v1/blockhashes?projection=compact",
            "/v1/blockhash-observations?projection=compact",
            "/v1/blocks?projection=compact&failed=true",
        ] {
            let response = http
                .get(format!("{}{route}", f.address))
                .bearer_auth(READER)
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                400,
                "unsupported route/query must fail: {route}"
            );
        }
    }
    #[tokio::test]
    async fn signature_filters_keep_failure_fields_and_unfiltered_invalidations() {
        let f = fixture(4).await;
        let http = reqwest::Client::new();
        let route = format!("{}/v1/signatures", f.address);
        let response = http
            .get(query(
                &route,
                &[
                    ("after", &f.cursors[0]),
                    ("account", &bs58::encode([8; 32]).into_string()),
                    ("failed", &"true".to_owned()),
                ],
            ))
            .bearer_auth(READER)
            .send()
            .await
            .unwrap();
        let values = read_updates(response, 5).await;
        for value in &values[..4] {
            let rows = value.2["block"]["transactions"].as_array().unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0]["index"], 0);
            assert_eq!(rows[0]["success"], false);
            assert!(rows[0]["err"].is_object());
            assert_eq!(rows[0]["signatures"].as_array().unwrap().len(), 2);
        }
        assert_eq!(values[4].1, "invalidate");
        let response = http
            .get(query(
                &route,
                &[
                    ("after", &f.cursors[0]),
                    ("program", &bs58::encode([9; 32]).into_string()),
                    ("failed", &"false".to_owned()),
                ],
            ))
            .bearer_auth(READER)
            .send()
            .await
            .unwrap();
        let values = read_updates(response, 1).await;
        assert_eq!(values[0].2["block"]["transactions"][0]["index"], 1);
        let response = http
            .get(query(
                &route,
                &[
                    ("after", &f.cursors[0]),
                    ("account", &bs58::encode([10; 32]).into_string()),
                ],
            ))
            .bearer_auth(READER)
            .send()
            .await
            .unwrap();
        let values = read_updates(response, 5).await;
        assert!(
            values[..4]
                .iter()
                .all(|v| v.1 == "cursor" && v.2["matched"] == false)
        );
        assert_eq!(values[4].1, "invalidate");
    }
    #[tokio::test]
    async fn historical_blockhashes_are_separate_from_current_signing_readiness() {
        let f = fixture(4).await;
        let http = reqwest::Client::new();
        let response = http
            .get(format!("{}/v1/blockhash-observations", f.address))
            .bearer_auth(READER)
            .header("last-event-id", &f.cursors[1])
            .send()
            .await
            .unwrap();
        let values = read_updates(response, 3).await;
        assert_eq!(values[0].1, "root");
        assert_eq!(values[1].1, "cursor");
        assert_eq!(values[2].1, "confirmed");
        for value in [&values[0], &values[2]] {
            assert_eq!(value.2["blockhashObservation"]["historicalUpdate"], true);
            assert_eq!(value.2["blockhashObservation"]["usableForSigning"], false);
            assert!(
                value.2["blockhashObservation"]["lastValidBlockHeight"]
                    .as_u64()
                    .is_some()
            );
        }
        for route in [
            format!("{}/v1/blockhashes?after={}", f.address, f.cursors[0]),
            format!("{}/v1/blockhashes", f.address),
        ] {
            let response = http
                .get(route)
                .bearer_auth(READER)
                .header("last-event-id", &f.cursors[0])
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 400);
        }
        let response = http
            .get(format!("{}/v1/blockhashes", f.address))
            .bearer_auth(READER)
            .send()
            .await
            .unwrap();
        let mut stream = response.bytes_stream();
        let first = tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let packet = std::str::from_utf8(&first).unwrap();
        assert!(packet.contains("event: status"));
        assert!(packet.contains("\"signingReady\":false"));
        assert!(!packet.contains("event: blockhash"));
    }
    #[tokio::test]
    async fn expired_changed_and_conflicting_cursors_fail_explicitly() {
        let f = fixture(4).await;
        let http = reqwest::Client::new();
        let route = format!("{}/v1/updates", f.address);
        let response = http
            .get(&route)
            .bearer_auth(READER)
            .header("last-event-id", "other-session:o0:-")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 410);
        let response = http
            .get(query(&route, &[("after", &f.cursors[0])]))
            .bearer_auth(READER)
            .header("last-event-id", &f.cursors[1])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400);
        // Model the exact replay retirement transaction, without a thousand
        // unrelated commits. A reader below the durable floor must get 410.
        let mut connection = rusqlite::Connection::open(&f.store.path).unwrap();
        let tx = connection.transaction().unwrap();
        tx.execute("DELETE FROM updates WHERE sequence<=1", [])
            .unwrap();
        tx.execute("UPDATE checkpoint SET base=? WHERE id=1", [&f.cursors[1]])
            .unwrap();
        tx.commit().unwrap();
        let response = http
            .get(&route)
            .bearer_auth(READER)
            .header("last-event-id", &f.cursors[0])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 410);
        assert_eq!(
            response.json::<Value>().await.unwrap()["error"],
            "replay_unavailable"
        );
        let response = http
            .get(&route)
            .bearer_auth(READER)
            .header("last-event-id", &f.cursors[1])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(read_updates(response, 1).await[0].0, f.cursors[2]);
    }
    #[tokio::test]
    async fn idle_sse_is_bounded_and_does_not_hold_ingestion_commit() {
        let f = fixture(1).await;
        let http = reqwest::Client::new();
        let route = format!("{}/v1/updates", f.address);
        let response = http.get(&route).bearer_auth(READER).send().await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            http.get(&route)
                .bearer_auth(READER)
                .send()
                .await
                .unwrap()
                .status(),
            503
        );
        let store = f.store.clone();
        tokio::time::timeout(
            Duration::from_secs(2),
            tokio::task::spawn_blocking(move || {
                let p = payload(6, 11);
                store
                    .commit(
                        &Delivery {
                            frame: p.frame.clone(),
                            dependency: None,
                        },
                        Some(&p),
                    )
                    .unwrap();
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            crate::cursor::parse(&f.store.output_cursor().unwrap(), &source().session_id).unwrap(),
            6
        );
        drop(response);
        tokio::time::timeout(Duration::from_secs(2), async {
            while f.clients.available_permits() != 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn busy_renderer_cannot_hold_the_input_commit_or_database_lock() {
        let f = fixture(4).await;
        let renderer = f.renderers.clone().acquire_owned().await.unwrap();
        let response = reqwest::Client::new()
            .get(format!("{}/v1/blocks", f.address))
            .bearer_auth(READER)
            .header("last-event-id", &f.cursors[0])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let store = f.store.clone();
        tokio::time::timeout(
            Duration::from_secs(2),
            tokio::task::spawn_blocking(move || {
                let p = payload(6, 11);
                store
                    .commit(
                        &Delivery {
                            frame: p.frame.clone(),
                            dependency: None,
                        },
                        Some(&p),
                    )
                    .unwrap();
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(f.renderers.available_permits(), 0);
        drop(renderer);
        let updates = read_updates(response, 1).await;
        assert_eq!(updates[0].0, f.cursors[1]);
        tokio::time::timeout(Duration::from_secs(2), async {
            while f.renderers.available_permits() != 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("socket output must not hold render admission");
    }
}
