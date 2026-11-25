use super::*;
use axum::{
    Router,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response as AxumResponse},
    routing::get,
};
use std::{
    collections::BTreeMap,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use v2::fixtures::{block, control, source};

const KEY: &str = "test-backend-key-0000000000000000000000";
fn base_cursor() -> String {
    v2::cursor("fixture-session", 0, "-")
}
fn fresh(mut frame: Frame) -> Frame {
    frame.envelope.event.observed_at_unix_ms = now_ms();
    let length = u32::from_le_bytes(frame.wire[8..12].try_into().unwrap()) as usize;
    v2::encode(frame.envelope, &frame.wire[16 + length..]).unwrap()
}
fn head(frames: &[Frame], selected: Option<&Frame>) -> Head {
    let now = now_ms();
    let observation = selected.map(|f| ConfirmedObservation::from_frame(f).unwrap());
    Head {
        schema: v2::HEAD.into(),
        profile: v2::PROFILE.into(),
        source: source(),
        cursor: Some(frames.last().map_or_else(base_cursor, |f| f.cursor.clone())),
        earliest_after: Some(base_cursor()),
        status: if selected.is_some() {
            "live"
        } else {
            "starting"
        }
        .into(),
        sampled_at_unix_ms: now,
        source_observed_at_unix_ms: observation.as_ref().map(|c| c.observed_at_unix_ms),
        source_lag_ms: observation
            .as_ref()
            .map(|c| now.saturating_sub(c.observed_at_unix_ms)),
        latest_confirmed: observation,
    }
}
#[derive(Default)]
struct Modes {
    wrong_start: bool,
    gap: bool,
    bad_notice: bool,
    wrong_source: bool,
    corrupt_chunk: bool,
    first_connection_one_bank: bool,
    bootstrap_selected: bool,
    http_gap: bool,
    source_failed: bool,
    short_notice: bool,
    beam_truncated: bool,
    beam_delayed: bool,
    beam_gap: bool,
    legacy_recovery_reply: bool,
}
struct ServerState {
    frames: Vec<Frame>,
    modes: Modes,
    chunk_hits: AtomicUsize,
    active: AtomicUsize,
    max_active: AtomicUsize,
    first_chunk_failures: AtomicUsize,
    delays: BTreeMap<String, Duration>,
    connections: Mutex<Vec<String>>,
    completed_fetches: Mutex<Vec<u64>>,
}
struct TestServer {
    client: BankClient,
    state: Arc<ServerState>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn server(
    frames: Vec<Frame>,
    modes: Modes,
    delays: BTreeMap<String, Duration>,
    failures: usize,
) -> TestServer {
    let state = Arc::new(ServerState {
        frames,
        modes,
        chunk_hits: AtomicUsize::new(0),
        active: AtomicUsize::new(0),
        max_active: AtomicUsize::new(0),
        first_chunk_failures: AtomicUsize::new(failures),
        delays,
        connections: Mutex::new(vec![]),
        completed_fetches: Mutex::new(vec![]),
    });
    let router = Router::new()
        .route("/v2/banks/head", get(get_head))
        .route("/v2/banks/events", get(get_events))
        .route("/v2/banks/beam", get(get_beam))
        .route("/v2/banks/chunks/{sha}", get(get_chunk))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = ClientConfig::new(
        format!("http://{}/", listener.local_addr().unwrap()),
        KEY,
        source(),
    );
    config.retry = RetryPolicy {
        max_retries: 2,
        initial_delay: Duration::from_millis(2),
        max_delay: Duration::from_millis(4),
    };
    config.max_in_flight = 2;
    let client = BankClient::build(config, true).unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    TestServer {
        client,
        state,
        task,
    }
}
async fn get_beam(
    State(state): State<Arc<ServerState>>,
    Query(position): Query<Position>,
    headers: HeaderMap,
) -> AxumResponse {
    if !authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let after = position.after;
    state.connections.lock().unwrap().push(after.clone());
    if state.modes.http_gap {
        return (
            StatusCode::GONE,
            axum::Json(
                serde_json::json!({"error":"replay_unavailable","head":head(&state.frames,None)}),
            ),
        )
            .into_response();
    }
    let sequence = v2::parse_cursor(&after).unwrap().1;
    let mut bytes = Vec::new();
    for frame in state
        .frames
        .iter()
        .filter(|f| f.envelope.event.sequence > sequence)
    {
        let mut frame = frame.clone();
        if state.modes.wrong_source {
            frame.envelope.marker["session_id"] = serde_json::json!("wrong-session");
            let meta = u32::from_le_bytes(frame.wire[8..12].try_into().unwrap()) as usize;
            frame = v2::encode(frame.envelope, &frame.wire[16 + meta..]).unwrap();
        }
        if state.modes.beam_gap && frame.envelope.event.sequence == sequence + 1 {
            continue;
        }
        bytes.extend_from_slice(&frame.wire);
    }
    if state.modes.corrupt_chunk && !bytes.is_empty() {
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
    }
    if state.modes.beam_truncated && !bytes.is_empty() {
        bytes.pop();
    }
    let delayed = state.modes.beam_delayed;
    let body = async_stream::stream! {
        // Split the header and coalesce all later frames in a single body
        // item. Neither case may change record or cursor boundaries.
        if !bytes.is_empty() {yield Ok::<_,std::io::Error>(bytes::Bytes::copy_from_slice(&bytes[..1]));if delayed{tokio::time::sleep(Duration::from_millis(40)).await;}yield Ok(bytes::Bytes::copy_from_slice(&bytes[1..]));}
    };
    let mut response = Body::from_stream(body).into_response();
    response.headers_mut().insert(
        "content-type",
        "application/vnd.blockzilla.stream.v2".parse().unwrap(),
    );
    response
        .headers_mut()
        .insert("x-blockzilla-start-cursor", after.parse().unwrap());
    response
}

#[tokio::test]
async fn binary_beam_preserves_all_wire_bytes_without_ack_projection_or_finite_gets() {
    let b = fresh(block(1, 10, 1, 9, 100));
    let frames = vec![
        b.clone(),
        control(&b, 2, "confirmed", now_ms()),
        control(&b, 3, "root", now_ms()),
    ];
    let server = server(frames.clone(), Modes::default(), BTreeMap::new(), 0).await;
    let mut stream = server.client.beam(&base_cursor()).await.unwrap();
    for expected in &frames {
        let actual = stream.next().await.unwrap();
        assert_eq!(actual.wire, expected.wire);
        assert_eq!(stream.cursor(), expected.cursor);
    }
    assert!(stream.next().await.unwrap_err().is_transient());
    assert!(matches!(stream.next().await, Err(ClientError::Stopped)));
    let mut resumed = server.client.beam(&frames[0].cursor).await.unwrap();
    assert_eq!(resumed.next().await.unwrap().wire, frames[1].wire);
    assert_eq!(server.state.chunk_hits.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn binary_beam_cancel_keeps_partial_frame_and_last_complete_boundary() {
    let frame = fresh(block(1, 10, 1, 9, 100));
    let server = server(
        vec![frame.clone()],
        Modes {
            beam_delayed: true,
            ..Default::default()
        },
        BTreeMap::new(),
        0,
    )
    .await;
    let mut stream = server.client.beam(&base_cursor()).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), stream.next())
            .await
            .is_err()
    );
    assert_eq!(stream.cursor(), base_cursor());
    assert_eq!(stream.next().await.unwrap().wire, frame.wire);
}
#[tokio::test]
async fn binary_beam_rejects_gaps_source_changes_corruption_and_truncation() {
    let b = fresh(block(1, 10, 1, 9, 100));
    let frames = vec![b.clone(), control(&b, 2, "root", now_ms())];
    for modes in [
        Modes {
            http_gap: true,
            ..Default::default()
        },
        Modes {
            wrong_source: true,
            ..Default::default()
        },
        Modes {
            corrupt_chunk: true,
            ..Default::default()
        },
        Modes {
            beam_truncated: true,
            ..Default::default()
        },
        Modes {
            beam_gap: true,
            ..Default::default()
        },
    ] {
        let server = server(frames.clone(), modes, BTreeMap::new(), 0).await;
        match server.client.beam(&base_cursor()).await {
            Err(ClientError::Gap { .. }) => {}
            Ok(mut stream) => {
                let mut failed = false;
                for _ in 0..=frames.len() {
                    match stream.next().await {
                        Ok(_) => {}
                        Err(_) => {
                            failed = true;
                            break;
                        }
                    }
                }
                assert!(failed);
                assert_ne!(stream.cursor(), frames.last().unwrap().cursor);
            }
            _ => panic!("unexpected beam admission"),
        }
    }
}
fn authorized(headers: &HeaderMap) -> bool {
    headers.get("authorization").and_then(|h| h.to_str().ok()) == Some(&format!("Bearer {KEY}"))
}
fn selected(state: &ServerState) -> Option<&Frame> {
    state
        .frames
        .iter()
        .rev()
        .find(|f| matches!(f.envelope.event.kind.as_str(), "confirmed" | "root"))
}
async fn get_head(State(state): State<Arc<ServerState>>, headers: HeaderMap) -> AxumResponse {
    if !authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let mut h = head(
        &state.frames,
        state
            .modes
            .bootstrap_selected
            .then(|| selected(&state))
            .flatten(),
    );
    if state.modes.wrong_source {
        h.source.session_id = "unexpected-session".into();
    }
    if state.modes.source_failed {
        h.status = "failed".into();
    }
    axum::Json(h).into_response()
}
#[derive(serde::Deserialize)]
struct Position {
    after: String,
    recovery: Option<String>,
}
async fn get_events(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Query(position): Query<Position>,
) -> AxumResponse {
    if !authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let connection = {
        let mut connections = state.connections.lock().unwrap();
        connections.push(position.after.clone());
        connections.len()
    };
    let h = head(&state.frames, selected(&state));
    let recovery = position.recovery.as_deref() == Some("1") && !state.modes.legacy_recovery_reply;
    if state.modes.http_gap {
        return (
            StatusCode::GONE,
            axum::Json(serde_json::json!({"error":"replay_unavailable","head":h})),
        )
            .into_response();
    }
    let mut events = format!(
        "event: status\r\ndata: {}\r\n\r\n",
        serde_json::to_string(&h).unwrap()
    );
    if state.modes.gap {
        events.push_str(&format!(
            "event: gap\ndata: {}\n\n",
            serde_json::json!({"error":"replay_unavailable","head":h})
        ));
    } else {
        let after = v2::parse_cursor(&position.after).unwrap().1;
        for f in &state.frames {
            if f.envelope.event.sequence <= after {
                continue;
            }
            let mut notice = v2::Notice::from_frame(f);
            if state.modes.bad_notice {
                notice.url = "https://unexpected.invalid/private".into();
            }
            if state.modes.short_notice {
                notice.bytes = 17;
            }
            let data = if recovery {
                if state.modes.short_notice && f.envelope.event.kind != "block" {
                    notice.bytes = v2::MAX_FRAME;
                }
                serde_json::to_string(&v2::RecoveryStreamNotice {
                    notice,
                    event: f.envelope.event.clone(),
                })
            } else {
                serde_json::to_string(&notice)
            }
            .unwrap();
            events.push_str(&format!(
                "event: chunk\nid: {}\ndata: {}\n\n",
                f.cursor, data
            ));
            if state.modes.first_connection_one_bank && connection == 1 {
                break;
            }
        }
    }
    let boundary = if state.modes.wrong_start {
        "wrong-boundary"
    } else {
        &position.after
    };
    let mut response = (
        [
            ("content-type", "text/event-stream"),
            ("x-blockzilla-start-cursor", boundary),
        ],
        Body::from(events),
    )
        .into_response();
    if recovery {
        response.headers_mut().insert(
            "x-blockzilla-notice-format",
            v2::RECOVERY_NOTICE_FORMAT.parse().unwrap(),
        );
    }
    response
}

#[tokio::test]
async fn public_recovery_pages_use_notice_only_blocks_and_original_controls() {
    let first = fresh(block(1, 10, 1, 9, 100));
    let control = control(&first, 2, "confirmed", now_ms());
    let second = fresh(block(3, 11, 2, 10, 100));
    let server = server(
        vec![first.clone(), control.clone(), second.clone()],
        Modes::default(),
        BTreeMap::new(),
        0,
    )
    .await;
    let first_page = server
        .client
        .recovery_plan(&base_cursor(), &second.cursor, 2)
        .await
        .unwrap();
    assert_eq!(first_page.len(), 2);
    assert!(first_page[0].control.is_none());
    first_page[0].notice.validate_frame(&first).unwrap();
    assert_eq!(first_page[1].control.as_ref().unwrap().wire, control.wire);
    let last_page = server
        .client
        .recovery_plan(&control.cursor, &second.cursor, 2)
        .await
        .unwrap();
    assert_eq!(last_page.len(), 1);
    assert!(last_page[0].control.is_none());
    last_page[0].notice.validate_frame(&second).unwrap();
    assert_eq!(server.state.chunk_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn public_recovery_rejects_an_old_format_wrong_boundary_and_large_control_before_get() {
    let first = fresh(block(1, 10, 1, 9, 100));
    let control = control(&first, 2, "confirmed", now_ms());
    for (modes, expected) in [
        (
            Modes {
                legacy_recovery_reply: true,
                ..Default::default()
            },
            "recovery_stream_headers_mismatch",
        ),
        (
            Modes {
                wrong_start: true,
                ..Default::default()
            },
            "recovery_stream_headers_mismatch",
        ),
        (
            Modes {
                short_notice: true,
                ..Default::default()
            },
            "recovery_control_too_large",
        ),
    ] {
        let server = server(
            vec![first.clone(), control.clone()],
            modes,
            BTreeMap::new(),
            0,
        )
        .await;
        let error = server
            .client
            .recovery_plan(&base_cursor(), &control.cursor, 2)
            .await
            .unwrap_err();
        assert!(
            matches!(error, ClientError::Protocol(ref reason) if reason == expected),
            "{error}"
        );
        assert_eq!(server.state.chunk_hits.load(Ordering::SeqCst), 0);
    }
    let server = server(vec![first, control], Modes::default(), BTreeMap::new(), 0).await;
    let wrong_target = v2::cursor("fixture-session", 2, &"1".repeat(64));
    let error = server
        .client
        .recovery_plan(&base_cursor(), &wrong_target, 2)
        .await
        .unwrap_err();
    assert!(
        matches!(error, ClientError::Protocol(ref reason) if reason == "recovery_target_mismatch"),
        "{error}"
    );
    assert_eq!(server.state.chunk_hits.load(Ordering::SeqCst), 0);
}
async fn get_chunk(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(sha): Path<String>,
) -> AxumResponse {
    if !authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    state.chunk_hits.fetch_add(1, Ordering::SeqCst);
    if state
        .first_chunk_failures
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1))
        .is_ok()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let Some(frame) = state.frames.iter().find(|f| f.sha256 == sha) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let active = state.active.fetch_add(1, Ordering::SeqCst) + 1;
    state.max_active.fetch_max(active, Ordering::SeqCst);
    if let Some(delay) = state.delays.get(&sha) {
        tokio::time::sleep(*delay).await;
    }
    state.active.fetch_sub(1, Ordering::SeqCst);
    state
        .completed_fetches
        .lock()
        .unwrap()
        .push(frame.envelope.event.sequence);
    let bytes = if state.modes.corrupt_chunk {
        vec![0; frame.wire.len()]
    } else {
        frame.wire.to_vec()
    };
    (
        [("content-type", "application/vnd.blockzilla.stream.v2")],
        Body::from(bytes),
    )
        .into_response()
}
async fn bank(stream: &mut BankStream) -> Delivery {
    loop {
        match stream.next().await.unwrap() {
            StreamEvent::Status(_) => {}
            StreamEvent::Bank(delivery) => return delivery,
        }
    }
}
async fn acknowledge(stream: &mut BankStream, delivery: &Delivery) {
    stream
        .ack(&delivery.frame.cursor, || async {
            Ok::<_, std::convert::Infallible>(())
        })
        .await
        .unwrap();
}

async fn wait_until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("mock condition timed out");
}

fn many_blocks(count: u64) -> Vec<Frame> {
    (1..=count)
        .map(|sequence| {
            fresh(block(
                sequence,
                20 + sequence,
                100 + sequence,
                19 + sequence,
                sequence,
            ))
        })
        .collect()
}

#[tokio::test]
async fn optional_preprocessing_is_parallel_but_delivery_and_ack_stay_ordered() {
    let frames = many_blocks(4);
    let delayed = frames[0].sha256.clone();
    let test = server(
        frames,
        Modes::default(),
        BTreeMap::from([(delayed, Duration::from_millis(25))]),
        0,
    )
    .await;
    let started = Arc::new(Mutex::new(Vec::new()));
    let completed = Arc::new(Mutex::new(Vec::new()));
    let active = Arc::new(AtomicUsize::new(0));
    let max = Arc::new(AtomicUsize::new(0));
    let mut config = (*test.client.config).clone();
    config.max_in_flight = 4;
    let s = started.clone();
    let d = completed.clone();
    let a = active.clone();
    let m = max.clone();
    config.preprocess = Some(Arc::new(move |frame| {
        let s = s.clone();
        let d = d.clone();
        let a = a.clone();
        let m = m.clone();
        Box::pin(async move {
            let n = frame.envelope.event.sequence;
            s.lock().unwrap().push(n);
            let count = a.fetch_add(1, Ordering::SeqCst) + 1;
            m.fetch_max(count, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(if n == 1 { 60 } else { 2 })).await;
            a.fetch_sub(1, Ordering::SeqCst);
            d.lock().unwrap().push(n);
            Ok(())
        })
    }));
    let client = BankClient::build(config, true).unwrap();
    let mut stream = client
        .connect(client.bootstrap(Some(&base_cursor())).await.unwrap())
        .await
        .unwrap();
    let first = bank(&mut stream).await;
    assert_eq!(first.frame.envelope.event.sequence, 1);
    assert_eq!(stream.cursor(), base_cursor());
    assert!(matches!(stream.next().await, Err(ClientError::AwaitingAck)));
    assert_eq!(*started.lock().unwrap(), vec![1, 2, 3, 4]);
    assert_ne!(completed.lock().unwrap()[0], 1);
    assert!(max.load(Ordering::SeqCst) >= 2);
    acknowledge(&mut stream, &first).await;
    for n in 2..=4 {
        let d = bank(&mut stream).await;
        assert_eq!(d.frame.envelope.event.sequence, n);
        acknowledge(&mut stream, &d).await;
    }
}

#[tokio::test]
async fn preprocessing_failure_never_advances_the_application_boundary() {
    let test = server(many_blocks(3), Modes::default(), BTreeMap::new(), 0).await;
    let mut config = (*test.client.config).clone();
    config.preprocess = Some(Arc::new(|f| {
        Box::pin(async move {
            if f.envelope.event.sequence == 2 {
                Err(protocol("injected_preprocess_failure"))
            } else {
                Ok(())
            }
        })
    }));
    let client = BankClient::build(config, true).unwrap();
    let mut stream = client
        .connect(client.bootstrap(Some(&base_cursor())).await.unwrap())
        .await
        .unwrap();
    let first = bank(&mut stream).await;
    acknowledge(&mut stream, &first).await;
    assert!(matches!(stream.next().await, Err(ClientError::Protocol(_))));
    assert_eq!(stream.cursor(), first.frame.cursor);
    assert!(matches!(stream.next().await, Err(ClientError::Stopped)));
}

#[tokio::test]
async fn rejected_notice_never_reaches_preprocessing() {
    let test = server(
        many_blocks(1),
        Modes {
            bad_notice: true,
            ..Default::default()
        },
        BTreeMap::new(),
        0,
    )
    .await;
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let mut config = (*test.client.config).clone();
    config.preprocess = Some(Arc::new(move |_| {
        let count = count.clone();
        Box::pin(async move {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }));
    let client = BankClient::build(config, true).unwrap();
    let mut stream = client
        .connect(client.bootstrap(Some(&base_cursor())).await.unwrap())
        .await
        .unwrap();
    assert!(matches!(
        stream.next().await.unwrap(),
        StreamEvent::Status(_)
    ));
    assert!(stream.next().await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(stream.cursor(), base_cursor());
}

#[tokio::test]
async fn background_prefetch_refills_while_delivery_is_unacknowledged() {
    let frames = many_blocks(12);
    let delayed = frames[1].sha256.clone();
    let test = server(
        frames,
        Modes::default(),
        BTreeMap::from([(delayed, Duration::from_millis(80))]),
        0,
    )
    .await;
    let mut stream = test
        .client
        .connect(test.client.bootstrap(Some(&base_cursor())).await.unwrap())
        .await
        .unwrap();
    let first = bank(&mut stream).await;
    assert_eq!(first.frame.envelope.event.sequence, 1);
    // Initial buffered reads are only two. Fetching five proves that the
    // producer continued and refilled without another consumer poll or ACK.
    wait_until(|| test.state.chunk_hits.load(Ordering::SeqCst) >= 5).await;
    assert_eq!(stream.cursor(), base_cursor());
    assert!(stream.selected().is_none());
    assert!(stream.ready_hash(now_ms()).is_err());
    assert!(matches!(stream.next().await, Err(ClientError::AwaitingAck)));
    let fetched = test.state.chunk_hits.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(30)).await;
    // One delivered frame, channel capacity two, up to two buffered futures,
    // and one result blocked on channel send form a finite count bound.
    assert!(test.state.chunk_hits.load(Ordering::SeqCst) <= 6);
    assert_eq!(test.state.chunk_hits.load(Ordering::SeqCst), fetched);
    let committed = AtomicUsize::new(0);
    stream
        .ack(&first.frame.cursor, || async {
            committed.store(1, Ordering::SeqCst);
            Ok::<_, std::convert::Infallible>(())
        })
        .await
        .unwrap();
    assert_eq!(committed.load(Ordering::SeqCst), 1);
    assert_eq!(stream.cursor(), first.frame.cursor);
    for expected in 2..=6 {
        let delivery = bank(&mut stream).await;
        assert_eq!(delivery.frame.envelope.event.sequence, expected);
        acknowledge(&mut stream, &delivery).await;
    }
}

#[tokio::test]
async fn queued_byte_budget_stops_gets_and_drop_aborts_the_producer() {
    let test = server(many_blocks(12), Modes::default(), BTreeMap::new(), 0).await;
    let budget_size = test.state.frames[0].wire.len() * 2;
    let budget = Arc::new(Semaphore::new(budget_size));
    let mut incoming = test
        .client
        .open_bounded(&base_cursor(), budget.clone())
        .await
        .unwrap();
    let producer = incoming.task.abort_handle();
    wait_until(|| test.state.chunk_hits.load(Ordering::SeqCst) == 2).await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(test.state.chunk_hits.load(Ordering::SeqCst), 2);
    assert_eq!(budget.available_permits(), 0);
    assert!(matches!(
        incoming.next().await.unwrap().unwrap(),
        Prepared::Status(_)
    ));
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(test.state.chunk_hits.load(Ordering::SeqCst), 2);
    assert!(matches!(
        incoming.next().await.unwrap().unwrap(),
        Prepared::Bank(_)
    ));
    wait_until(|| test.state.chunk_hits.load(Ordering::SeqCst) == 3).await;
    drop(incoming);
    wait_until(|| producer.is_finished() && budget.available_permits() == budget_size).await;
    let fetched = test.state.chunk_hits.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(test.state.chunk_hits.load(Ordering::SeqCst), fetched);
    assert_eq!(test.state.connections.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn notice_reservation_also_limits_the_response_body() {
    let test = server(
        many_blocks(1),
        Modes {
            short_notice: true,
            ..Default::default()
        },
        BTreeMap::new(),
        0,
    )
    .await;
    let budget = Arc::new(Semaphore::new(MAX_PREPARED_BYTES));
    let mut incoming = test
        .client
        .open_bounded(&base_cursor(), budget.clone())
        .await
        .unwrap();
    assert!(matches!(
        incoming.next().await.unwrap().unwrap(),
        Prepared::Status(_)
    ));
    assert!(matches!(
        incoming.next().await.unwrap(),
        Err(ClientError::Protocol(_))
    ));
    wait_until(|| budget.available_permits() == MAX_PREPARED_BYTES).await;
    assert_eq!(test.state.chunk_hits.load(Ordering::SeqCst), 1);
}

#[test]
fn requires_https_pinned_source_and_valid_bounds() {
    let config = ClientConfig::new("http://127.0.0.1/", KEY, source());
    assert!(matches!(
        BankClient::new(config),
        Err(ClientError::Configuration(_))
    ));
    let mut config = ClientConfig::new("https://example.invalid/?api_key=ignored", KEY, source());
    assert!(BankClient::new(config.clone()).is_err());
    config.url = "https://example.invalid/".into();
    config.max_in_flight = 0;
    assert!(BankClient::new(config.clone()).is_err());
    config.max_in_flight = 4;
    config.api_key.push('\n');
    assert!(BankClient::new(config).is_err());
}

#[tokio::test]
async fn preserves_order_bounded_reads_and_durable_ack() {
    let b = fresh(block(1, 17, 7, 3, 10));
    let c = control(&b, 2, "confirmed", now_ms());
    let delays = BTreeMap::from([(b.sha256.clone(), Duration::from_millis(80))]);
    let test = server(vec![b.clone(), c.clone()], Modes::default(), delays, 0).await;
    let bootstrap = test.client.bootstrap(Some(&base_cursor())).await.unwrap();
    let mut stream = test.client.connect(bootstrap).await.unwrap();
    let first = bank(&mut stream).await;
    assert_eq!(first.frame.cursor, b.cursor);
    assert_eq!(stream.cursor(), base_cursor());
    assert!(matches!(stream.next().await, Err(ClientError::AwaitingAck)));
    assert!(stream.ready_hash(now_ms()).is_err());
    let called = AtomicUsize::new(0);
    assert!(matches!(
        stream
            .ack(&c.cursor, || async {
                called.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(())
            })
            .await,
        Err(ClientError::AckOrder)
    ));
    assert_eq!(called.load(Ordering::SeqCst), 0);
    acknowledge(&mut stream, &first).await;
    let second = bank(&mut stream).await;
    assert_eq!(second.frame.cursor, c.cursor);
    assert!(second.dependency.is_none());
    assert!(stream.ready_hash(now_ms()).is_err());
    acknowledge(&mut stream, &second).await;
    assert_eq!(
        stream.ready_hash(now_ms()).unwrap().last_valid_block_height,
        160
    );
    assert!(test.state.max_active.load(Ordering::SeqCst) <= 2);
    assert_eq!(*test.state.completed_fetches.lock().unwrap(), vec![2, 1]);
}

#[tokio::test]
async fn checkpoint_failure_preserves_resume_and_stops_readiness() {
    let b = fresh(block(1, 17, 7, 3, 10));
    let test = server(vec![b], Modes::default(), BTreeMap::new(), 0).await;
    let mut stream = test
        .client
        .connect(test.client.bootstrap(Some(&base_cursor())).await.unwrap())
        .await
        .unwrap();
    let delivery = bank(&mut stream).await;
    assert!(matches!(
        stream
            .ack(&delivery.frame.cursor, || async {
                Err::<(), _>("disk full")
            })
            .await,
        Err(ClientError::Checkpoint(_))
    ));
    assert_eq!(stream.cursor(), base_cursor());
    assert!(matches!(stream.next().await, Err(ClientError::Stopped)));
    assert!(stream.ready_hash(now_ms()).is_err());
}

#[tokio::test]
async fn reconnects_from_acknowledged_cursor_and_retries_503() {
    let b = fresh(block(1, 17, 7, 3, 10));
    let c = control(&b, 2, "confirmed", now_ms());
    let test = server(
        vec![b.clone(), c.clone()],
        Modes {
            first_connection_one_bank: true,
            ..Default::default()
        },
        BTreeMap::new(),
        1,
    )
    .await;
    let mut stream = test
        .client
        .connect(test.client.bootstrap(Some(&base_cursor())).await.unwrap())
        .await
        .unwrap();
    let first = bank(&mut stream).await;
    acknowledge(&mut stream, &first).await;
    let second = bank(&mut stream).await;
    assert_eq!(second.frame.cursor, c.cursor);
    assert_eq!(
        *test.state.connections.lock().unwrap(),
        vec![base_cursor(), b.cursor]
    );
    assert_eq!(test.state.chunk_hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn validates_start_boundary_source_and_expired_resume() {
    let b = fresh(block(1, 17, 7, 3, 10));
    let test = server(
        vec![b.clone()],
        Modes {
            wrong_start: true,
            ..Default::default()
        },
        BTreeMap::new(),
        0,
    )
    .await;
    assert!(matches!(
        test.client
            .connect(test.client.bootstrap(Some(&base_cursor())).await.unwrap())
            .await,
        Err(ClientError::Protocol(_))
    ));
    let test = server(
        vec![b],
        Modes {
            wrong_source: true,
            ..Default::default()
        },
        BTreeMap::new(),
        0,
    )
    .await;
    assert!(matches!(
        test.client.bootstrap(Some(&base_cursor())).await,
        Err(ClientError::Source(_))
    ));
    let test = server(vec![], Modes::default(), BTreeMap::new(), 0).await;
    assert!(matches!(
        test.client.bootstrap(Some("other:p0:-")).await,
        Err(ClientError::Source(_))
    ));
}

#[tokio::test]
async fn sse_gap_is_terminal_and_never_resets_boundary() {
    let b = fresh(block(1, 17, 7, 3, 10));
    let test = server(
        vec![b],
        Modes {
            gap: true,
            ..Default::default()
        },
        BTreeMap::new(),
        0,
    )
    .await;
    let mut stream = test
        .client
        .connect(test.client.bootstrap(Some(&base_cursor())).await.unwrap())
        .await
        .unwrap();
    assert!(matches!(
        stream.next().await.unwrap(),
        StreamEvent::Status(_)
    ));
    let error = stream.next().await.err().unwrap();
    assert!(matches!(error, ClientError::Gap { .. }));
    assert!(error.is_terminal());
    assert_eq!(stream.cursor(), base_cursor());
    assert_eq!(test.state.connections.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn http_gap_authentication_and_stopped_source_are_terminal() {
    let b = fresh(block(1, 17, 7, 3, 10));
    let test = server(
        vec![b.clone()],
        Modes {
            http_gap: true,
            ..Default::default()
        },
        BTreeMap::new(),
        0,
    )
    .await;
    assert!(matches!(
        test.client
            .connect(test.client.bootstrap(Some(&base_cursor())).await.unwrap())
            .await,
        Err(ClientError::Gap { .. })
    ));
    assert_eq!(test.state.connections.lock().unwrap().len(), 1);
    let test = server(
        vec![b.clone()],
        Modes {
            source_failed: true,
            ..Default::default()
        },
        BTreeMap::new(),
        0,
    )
    .await;
    assert!(matches!(
        test.client.bootstrap(Some(&base_cursor())).await,
        Err(ClientError::Source(_))
    ));
    let test = server(vec![b], Modes::default(), BTreeMap::new(), 0).await;
    let mut wrong = (*test.client.config).clone();
    wrong.api_key = "incorrect-key-0000000000000000000000000".into();
    let client = BankClient::build(wrong, true).unwrap();
    assert!(matches!(
        client.head().await,
        Err(ClientError::Authentication(401))
    ));
}

#[tokio::test]
async fn cancelled_checkpoint_keeps_pending_bank_and_old_boundary() {
    let b = fresh(block(1, 17, 7, 3, 10));
    let test = server(vec![b], Modes::default(), BTreeMap::new(), 0).await;
    let mut stream = test
        .client
        .connect(test.client.bootstrap(Some(&base_cursor())).await.unwrap())
        .await
        .unwrap();
    let delivery = bank(&mut stream).await;
    assert!(
        tokio::time::timeout(
            Duration::from_millis(2),
            stream.ack(&delivery.frame.cursor, || async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok::<_, std::convert::Infallible>(())
            })
        )
        .await
        .is_err()
    );
    assert_eq!(stream.cursor(), base_cursor());
    assert!(matches!(stream.next().await, Err(ClientError::AwaitingAck)));
    acknowledge(&mut stream, &delivery).await;
    assert_eq!(stream.cursor(), delivery.frame.cursor);
}

#[tokio::test]
async fn rejects_notice_before_credentialed_fetch_and_checks_digest() {
    let b = fresh(block(1, 17, 7, 3, 10));
    let test = server(
        vec![b.clone()],
        Modes {
            bad_notice: true,
            ..Default::default()
        },
        BTreeMap::new(),
        0,
    )
    .await;
    let mut stream = test
        .client
        .connect(test.client.bootstrap(Some(&base_cursor())).await.unwrap())
        .await
        .unwrap();
    stream.next().await.unwrap();
    assert!(matches!(stream.next().await, Err(ClientError::Protocol(_))));
    assert_eq!(test.state.chunk_hits.load(Ordering::SeqCst), 0);
    let test = server(
        vec![b.clone()],
        Modes {
            corrupt_chunk: true,
            ..Default::default()
        },
        BTreeMap::new(),
        0,
    )
    .await;
    assert!(matches!(
        test.client.fetch(&b.sha256).await,
        Err(ClientError::Digest(_))
    ));
}

#[tokio::test]
async fn resolves_exact_bootstrap_and_fetches_missing_control_dependency() {
    let b = fresh(block(1, 17, 7, 3, 10));
    let c = control(&b, 2, "confirmed", now_ms());
    let test = server(
        vec![b.clone(), c.clone()],
        Modes {
            bootstrap_selected: true,
            ..Default::default()
        },
        BTreeMap::new(),
        0,
    )
    .await;
    let bootstrap = test.client.bootstrap(None).await.unwrap();
    assert_eq!(bootstrap.after, c.cursor);
    assert_eq!(bootstrap.control.as_ref().unwrap().sha256, c.sha256);
    assert_eq!(bootstrap.payload.as_ref().unwrap().sha256, b.sha256);
    let mut stream = test.client.connect(bootstrap).await.unwrap();
    assert!(stream.ready_hash(now_ms()).is_err());
    assert!(matches!(
        stream.next().await.unwrap(),
        StreamEvent::Status(_)
    ));
    assert!(stream.ready_hash(now_ms()).is_ok());
    stream.force_unavailable();
    assert!(stream.ready_hash(now_ms()).is_err());

    let test = server(
        vec![b.clone(), c.clone()],
        Modes::default(),
        BTreeMap::new(),
        0,
    )
    .await;
    let mut stream = test
        .client
        .connect(test.client.bootstrap(Some(&b.cursor)).await.unwrap())
        .await
        .unwrap();
    let delivery = bank(&mut stream).await;
    assert_eq!(delivery.dependency.as_ref().unwrap().sha256, b.sha256);
    let decoded = delivery
        .decode_with(|wire| v2::decode(wire.to_vec().into()).map(|f| f.envelope.event.sequence))
        .unwrap();
    assert_eq!(decoded.frame, 2);
    assert_eq!(decoded.dependency, Some(1));
}

#[tokio::test]
async fn cancelled_next_retains_control_and_dependency_fetch() {
    let b = fresh(block(1, 17, 7, 3, 10));
    let c = control(&b, 2, "confirmed", now_ms());
    let delays = BTreeMap::from([(b.sha256.clone(), Duration::from_millis(80))]);
    let test = server(vec![b.clone(), c.clone()], Modes::default(), delays, 0).await;
    let mut stream = test
        .client
        .connect(test.client.bootstrap(Some(&b.cursor)).await.unwrap())
        .await
        .unwrap();
    stream.next().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), stream.next())
            .await
            .is_err()
    );
    assert_eq!(stream.cursor(), b.cursor);
    let delivery = bank(&mut stream).await;
    assert_eq!(delivery.frame.cursor, c.cursor);
    assert_eq!(delivery.dependency.as_ref().unwrap().cursor, b.cursor);
    assert_eq!(test.state.chunk_hits.load(Ordering::SeqCst), 2);
}

#[test]
fn parser_bounds_and_crlf_multiline_fields() {
    let mut sse = Sse::default();
    for line in ["event: status\r", "data: first\r", "data: second\r"] {
        assert!(sse.line(line.as_bytes()).unwrap().is_none());
    }
    assert_eq!(
        sse.line(b"\r").unwrap().unwrap(),
        ("status".into(), "".into(), "first\nsecond".into())
    );
    sse.line(b"id:").unwrap();
    assert!(sse.line(b"id: duplicate").is_err());
    assert!(Sse::default().line(&vec![b'x'; v2::MAX_META]).is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn unix_socket_transport_preserves_admission_ack_and_sparse_coverage() {
    use axum::routing::post;
    async fn ack(
        headers: HeaderMap,
        axum::Json(value): axum::Json<serde_json::Value>,
    ) -> AxumResponse {
        if !authorized(&headers) {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        assert_eq!(value["schema"], "blockzilla-consumer-ack-v1");
        assert_eq!(value["consumer_id"], "sidecar-primary");
        axum::Json(serde_json::json!({"schema":"blockzilla-consumer-ack-receipt-v1","state":"ACKED","source":value["source"],"consumer_id":value["consumer_id"],"cursor":value["cursor"],"coverage_gap_sequence":value["coverage_gap_sequence"]})).into_response()
    }
    async fn gaps(headers: HeaderMap) -> AxumResponse {
        if !authorized(&headers) {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        axum::Json(serde_json::json!({"schema":"blockzilla-coverage-gaps-v1","source":source(),"producer_generation":"fixture-generation","base_sequence":0,"latest_sequence":91,"gaps":([7,91].map(|n|serde_json::json!({"sequence":n,"processed_sequence":n,"gap":{"schema":"hivezilla-incomplete-bank-gap-v1","producer_generation":"fixture-generation","gap_sequence":n,"reason":"missing_native_metadata","slot":88,"bank_id":9,"first_source_sequence":1,"last_source_sequence":2,"evidence_sha256":"b".repeat(64),"complete_bank":false,"captured_input_preserved":true,"canonical_status":"UNKNOWN"}})))})).into_response()
    }
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("origin.sock");
    let payload = fresh(block(1, 9, 1, 8, 9));
    let root = control(&payload, 2, "root", now_ms());
    let state = Arc::new(ServerState {
        frames: vec![payload.clone(), root],
        modes: Modes::default(),
        chunk_hits: AtomicUsize::new(0),
        active: AtomicUsize::new(0),
        max_active: AtomicUsize::new(0),
        first_chunk_failures: AtomicUsize::new(0),
        delays: BTreeMap::new(),
        connections: Mutex::new(vec![]),
        completed_fetches: Mutex::new(vec![]),
    });
    let router = Router::new()
        .route("/v2/banks/head", get(get_head))
        .route("/v2/banks/events", get(get_events))
        .route("/v2/banks/chunks/{sha}", get(get_chunk))
        .route("/v2/banks/ack", post(ack))
        .route("/v2/banks/coverage-gaps", get(gaps))
        .with_state(state);
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let mut config = ClientConfig::new("http://localhost/", KEY, source());
    config.retry.max_retries = 0;
    let client = BankClient::new_unix(config.clone(), &socket).unwrap();
    let bootstrap = client.bootstrap(Some(&base_cursor())).await.unwrap();
    let mut stream = client.connect(bootstrap).await.unwrap();
    assert!(matches!(
        stream.next().await.unwrap(),
        StreamEvent::Status(_)
    ));
    let StreamEvent::Bank(delivery) = stream.next().await.unwrap() else {
        panic!("missing bank")
    };
    assert_eq!(delivery.frame.wire, payload.wire);
    assert!(
        client
            .acknowledge("invalid id", &payload.cursor)
            .await
            .is_err()
    );
    stream
        .ack(&payload.cursor, || async { Ok::<(), &str>(()) })
        .await
        .unwrap();
    let page = client.coverage_gaps(0, "fixture-generation").await.unwrap();
    assert_eq!(
        page.gaps.iter().map(|g| g.sequence).collect::<Vec<_>>(),
        vec![7, 91]
    );
    assert!(
        client
            .coverage_gaps(0, "replacement-generation")
            .await
            .is_err()
    );
    let receipt = client
        .acknowledge_coverage("sidecar-primary", &payload.cursor, 91)
        .await
        .unwrap();
    assert_eq!(receipt.cursor, payload.cursor);
    assert_eq!(receipt.coverage_gap_sequence, 91);
    config.url = "https://example.com/".into();
    assert!(BankClient::new_unix(config, &socket).is_err());
    task.abort();
}

#[test]
fn coverage_gap_variants_preserve_unknown_and_null_bank_semantics() {
    let make = |sequence| CoverageGap {
        sequence,
        processed_sequence: sequence,
        gap: serde_json::json!({"schema":"hivezilla-incomplete-bank-gap-v1","producer_generation":"fixture-generation","gap_sequence":sequence,"slot":9,"bank_id":1,"first_source_sequence":1,"last_source_sequence":2,"reason":"incomplete-bank-expired","evidence_sha256":"b".repeat(64),"complete_bank":false,"captured_input_preserved":true,"canonical_status":"UNKNOWN"}),
    };
    let incomplete = make(7);
    incomplete.validate("fixture-generation").unwrap();
    let mut complete = make(91);
    complete.gap["schema"] = "hivezilla-nonterminal-bank-gap-v1".into();
    complete.gap["complete_bank"] = true.into();
    complete.gap["reason"] = "complete-unconfirmed-bank-expired".into();
    complete.gap["bank_identity"] =
        serde_json::to_value(block(1, 9, 1, 8, 9).envelope.event.bank).unwrap();
    complete.gap["custody"] = serde_json::json!({"artifact":"/private/saved-bank.compact","marker_sha256":"c".repeat(64)});
    complete.validate("fixture-generation").unwrap();
    let mut contradictory = complete.clone();
    contradictory.gap["canonical_status"] = "FINALIZED".into();
    assert!(contradictory.validate("fixture-generation").is_err());
    contradictory = complete.clone();
    contradictory.gap["custody"]["marker_sha256"] = serde_json::Value::Null;
    assert!(contradictory.validate("fixture-generation").is_err());
    let mut slot = make(123);
    slot.gap["schema"] = "hivezilla-slot-control-gap-v1".into();
    slot.gap["bank_id"] = serde_json::Value::Null;
    slot.gap["bank_identity"] = serde_json::Value::Null;
    slot.gap["custody"] = serde_json::json!({"artifact":null,"marker_sha256":null});
    slot.validate("fixture-generation").unwrap();
    slot.gap["bank_id"] = 0.into();
    assert!(slot.validate("fixture-generation").is_err());
    assert!(incomplete.validate("replacement-generation").is_err());
}
