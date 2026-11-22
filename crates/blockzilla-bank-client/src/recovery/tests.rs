use super::*;
use axum::{
    Router,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicUsize, Ordering},
};
use v2::fixtures::{block, control, source};

const KEY: &str = "test-worker-key-000000000000000000000000";
struct TestState {
    frame: Frame,
    mode: &'static str,
    calls: AtomicUsize,
}
struct Server {
    client: WorkerRecoveryClient,
    state: Arc<TestState>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn server(frame: Frame, mode: &'static str) -> Server {
    let state = Arc::new(TestState {
        frame,
        mode,
        calls: AtomicUsize::new(0),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = WorkerRecoveryConfig::new(
        format!("http://{}/", listener.local_addr().unwrap()),
        KEY,
        source(),
    );
    config.retry.initial_delay = Duration::from_millis(1);
    config.retry.max_delay = Duration::from_millis(2);
    let client = WorkerRecoveryClient::build(config, true).unwrap();
    let router = Router::new()
        .route("/block/{slot}", get(read))
        .with_state(state.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    Server {
        client,
        state,
        task,
    }
}
async fn read(
    State(state): State<Arc<TestState>>,
    Path(slot): Path<String>,
    Query(query): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let call = state.calls.fetch_add(1, Ordering::SeqCst);
    let frame = &state.frame;
    let bank = &frame.envelope.event.bank;
    assert_eq!(slot, format!("{}.compact", bank.slot));
    assert_eq!(
        headers.get("authorization").unwrap(),
        format!("Bearer {KEY}").as_str()
    );
    assert!(headers.get("range").is_none());
    assert_eq!(
        query,
        BTreeMap::from([
            ("bank_id".into(), bank.bank_id.to_string()),
            (
                "blockhash".into(),
                bs58::encode(bank.blockhash).into_string()
            ),
            ("commitment".into(), "processed".into()),
            ("cursor".into(), frame.cursor.clone()),
            ("source_session".into(), frame.source.session_id.clone()),
        ])
    );
    if state.mode == "expired" {
        return StatusCode::GONE.into_response();
    }
    if state.mode == "redirect" {
        return (StatusCode::FOUND, [("location", "http://127.0.0.1:1/")]).into_response();
    }
    let mut metadata = Metadata {
        version: 1,
        slot: bank.slot,
        bank_id: bank.bank_id,
        blockhash: bs58::encode(bank.blockhash).into_string(),
        parent_slot: bank.parent_slot,
        parent_blockhash: bs58::encode(bank.parent_blockhash).into_string(),
        source: frame.source.clone(),
        cursor: frame.cursor.clone(),
        frame_sha256: frame.sha256.clone(),
        commitment: "processed".into(),
    };
    if state.mode == "metadata-parent" {
        metadata.parent_slot -= 1;
    }
    if state.mode == "metadata-source" {
        metadata.source.session_id = "changed-source".into();
    }
    let mut wire = frame.wire.to_vec();
    if state.mode == "digest" {
        let last = wire.len() - 1;
        wire[last] ^= 1;
    }
    let short = state.mode == "partial-always" || (state.mode == "partial-first" && call == 0);
    let payload = if short {
        let partial = bytes::Bytes::copy_from_slice(&wire[..wire.len() / 2]);
        Body::from_stream(async_stream::stream! {
            yield Ok::<_,std::io::Error>(partial);
            yield Err(std::io::Error::other("disconnected"));
        })
    } else {
        Body::from(wire)
    };
    let mut response = payload.into_response();
    for (name, value) in [
        (
            "content-type",
            "application/vnd.blockzilla.stream.v2".into(),
        ),
        ("x-blockzilla-source", "FOUNDATION_RECENT".into()),
        (
            "x-blockzilla-recovery-format",
            "native-bank-stream-v2".into(),
        ),
        ("x-blockzilla-commitment", "processed".into()),
        ("x-blockzilla-frame-sha256", frame.sha256.clone()),
        ("x-blockzilla-cursor", frame.cursor.clone()),
        (
            "x-blockzilla-blockhash",
            bs58::encode(bank.blockhash).into_string(),
        ),
        (
            "x-blockzilla-previous-blockhash",
            bs58::encode(bank.parent_blockhash).into_string(),
        ),
        (
            "x-blockzilla-recent-metadata",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&metadata).unwrap()),
        ),
        ("content-length", frame.wire.len().to_string()),
    ] {
        response.headers_mut().insert(name, value.parse().unwrap());
    }
    if state.mode == "archive" {
        response.headers_mut().insert(
            "content-type",
            "application/vnd.blockzilla.get-block-bundle.wincode"
                .parse()
                .unwrap(),
        );
    }
    response
}

#[tokio::test]
async fn native_worker_read_preserves_original_bytes_and_reuses_client_without_store() {
    let frame = block(7, 12, 3, 11, 100);
    let server = server(frame.clone(), "valid").await;
    let notice = RecoveryNotice::from_frame(&frame);
    notice
        .validate(
            &source(),
            &v2::cursor("fixture-session", 6, &"a".repeat(64)),
        )
        .unwrap();
    let clone = server.client.clone();
    for _ in 0..2 {
        let got = clone.fetch(&notice).await.unwrap();
        assert_eq!(got.wire, frame.wire);
        assert_eq!(got.envelope.event, frame.envelope.event);
    }
    assert_eq!(server.state.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn partial_worker_body_retries_the_same_pins_and_never_delivers_partial_bytes() {
    let frame = block(1, 12, 3, 11, 100);
    for (mode, success, calls) in [("partial-first", true, 2), ("partial-always", false, 3)] {
        let server = server(frame.clone(), mode).await;
        let got = server
            .client
            .fetch(&RecoveryNotice::from_frame(&frame))
            .await;
        if success {
            assert_eq!(got.unwrap().wire, frame.wire);
        } else {
            assert!(got.unwrap_err().is_transient());
        }
        assert_eq!(server.state.calls.load(Ordering::SeqCst), calls);
    }
}

#[tokio::test]
async fn wrong_hash_parent_source_expiry_archive_and_redirect_fail_without_retry() {
    let frame = block(1, 12, 3, 11, 100);
    for mode in [
        "digest",
        "metadata-parent",
        "metadata-source",
        "expired",
        "archive",
        "redirect",
    ] {
        let server = server(frame.clone(), mode).await;
        let error = server
            .client
            .fetch(&RecoveryNotice::from_frame(&frame))
            .await
            .unwrap_err();
        assert!(!error.is_transient(), "{mode}: {error}");
        assert_eq!(server.state.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn invalid_notice_and_control_never_send_customer_key_to_worker() {
    let frame = block(1, 12, 3, 11, 100);
    let server = server(frame.clone(), "valid").await;
    let mut notice = RecoveryNotice::from_frame(&frame);
    notice.source.session_id = "changed-source".into();
    assert!(matches!(
        server.client.fetch(&notice).await,
        Err(ClientError::Source(_))
    ));
    let control = control(&frame, 2, "root", 1001);
    assert!(
        server
            .client
            .fetch(&RecoveryNotice::from_frame(&control))
            .await
            .is_err()
    );
    assert_eq!(server.state.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn duplicates_sequence_gaps_event_changes_and_source_changes_are_rejected() {
    let frame = block(2, 12, 3, 11, 100);
    let notice = RecoveryNotice::from_frame(&frame);
    assert!(notice.validate(&source(), &frame.cursor).is_err());
    assert!(
        notice
            .validate(&source(), &v2::cursor("fixture-session", 0, "-"))
            .is_err()
    );
    let mut changed = notice.clone();
    changed.event.bank.parent_slot -= 1;
    assert!(changed.validate_frame(&frame).is_err());
    let mut changed = notice.clone();
    changed.sha256 = "a".repeat(64);
    assert!(changed.validate_frame(&frame).is_err());
    for url in [
        "http://example.com/",
        "https://user@example.com/",
        "https://example.com/x",
        "https://example.com/?key=x",
        "https://example.com/#x",
    ] {
        assert!(WorkerRecoveryClient::new(WorkerRecoveryConfig::new(url, KEY, source())).is_err());
    }
}
