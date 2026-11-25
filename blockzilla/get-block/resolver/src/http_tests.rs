use super::*;
use crate::Resolved;
use blockzilla_archive_v2::ArchiveV2BlockAccessBlockhash;
use blockzilla_get_block::{
    foundation_protocol::PendingLocatorV1,
    slot_references::SlotReferences,
    slot_resolution::{
        LocatorV1, NamedSourceObject, ResolutionHotRow, ResolutionV1, SourceObjectIdentity,
    },
};
use http_body_util::BodyExt;
use std::sync::{Mutex, atomic::AtomicUsize};
use tower::ServiceExt;

const TOKEN: &str = "private-resolution-test-token-012345";
const PREFIX: &str = "compact-v2/fixture";
const GEN: &str = "fixture-generation";
const SLOT: u64 = 432_002;

fn raw_fixture() -> (Vec<u8>, usize) {
    let block = blockzilla_archive_v2::ArchiveV2HotBlockBlob {
        header: blockzilla_archive_v2::ArchiveV2HotBlockHeader {
            slot: SLOT,
            parent_slot: SLOT - 1,
            blockhash_id: 1,
            previous_blockhash_id: 0,
            block_time: None,
            block_height: None,
            rewards: None,
        },
        tx_count: 0,
        tx_rows: vec![],
        message_bytes: vec![],
        metadata_bytes: vec![],
    };
    let bytes =
        wincode::config::serialize(&block, blockzilla_primitives::wincode_leb128_config()).unwrap();
    (zstd::bulk::compress(&bytes, 1).unwrap(), bytes.len())
}

fn pending() -> PendingLocatorV1 {
    let (frame, decoded) = raw_fixture();
    PendingLocatorV1 {
        version: 1,
        source_prefix: PREFIX.into(),
        generation: GEN.into(),
        epoch: 1,
        hot: ResolutionHotRow {
            block_id: 1,
            slot: SLOT,
            compressed_offset: 12,
            compressed_len: frame.len() as u32,
            uncompressed_len: decoded as u32,
            tx_count: 0,
            first_tx_ordinal: 0,
            first_signature_ordinal: 0,
            signature_count: 0,
        },
        message_schema: 0,
        metadata_schema: 0,
        blocks: SourceObjectIdentity {
            length: 128,
            etag: "\"hot-etag\"".into(),
        },
        signatures: SourceObjectIdentity {
            length: 0,
            etag: "\"sig-etag\"".into(),
        },
    }
}

fn request_value() -> ResolveRequestV1 {
    ResolveRequestV1 {
        version: 1,
        source: pending(),
        hot_sha256: "ab".repeat(32),
        references: SlotReferences {
            slot: SLOT,
            parent_slot: SLOT - 1,
            blockhash_id: 1,
            previous_blockhash_id: 0,
            signature_counts: vec![],
            pubkeys: vec![],
            blockhashes: vec![0, 1],
            votes: vec![],
        },
    }
}

struct MockCatalog {
    calls: AtomicUsize,
}
impl ResolutionCatalog for MockCatalog {
    fn source_prefix(&self) -> &str {
        PREFIX
    }
    fn generation(&self) -> &str {
        GEN
    }
    fn pending(&self, slot: u64) -> Result<Option<PendingLocatorV1>> {
        Ok((slot == SLOT).then(pending))
    }
    fn archived_blockhash(&self, slot: u64) -> Result<Option<[u8; 32]>> {
        Ok((slot == SLOT).then_some([5; 32]))
    }
    fn resolve(&self, request: &ResolveRequestV1) -> Result<Resolved> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        ensure!(request.source == pending(), "wrong source");
        let source = pending();
        let locator = LocatorV1 {
            version: 1,
            source_prefix: source.source_prefix,
            generation: source.generation,
            epoch: 1,
            hot: source.hot,
            parent_slot: SLOT - 1,
            blockhash: [5; 32],
            previous_blockhash: [4; 32],
            message_schema: 0,
            metadata_schema: 0,
            blocks: source.blocks.clone(),
            signatures: source.signatures.clone(),
        };
        let objects = vec![
            NamedSourceObject {
                name: "archive-v2-blocks.zstd".into(),
                identity: source.blocks,
            },
            NamedSourceObject {
                name: "signatures.bin".into(),
                identity: source.signatures,
            },
        ];
        Ok(Resolved {
            resolution: ResolutionV1::from_resolved_tables(
                locator,
                objects,
                &[],
                &[],
                &[
                    ArchiveV2BlockAccessBlockhash {
                        id: 0,
                        blockhash: [4; 32],
                    },
                    ArchiveV2BlockAccessBlockhash {
                        id: 1,
                        blockhash: [5; 32],
                    },
                ],
                &[],
            )
            .map_err(anyhow::Error::msg)?,
            pread_calls: 3,
            pread_bytes: 128,
        })
    }
}

fn app() -> (Router, Arc<MockCatalog>) {
    let catalog = Arc::new(MockCatalog {
        calls: AtomicUsize::new(0),
    });
    (router(catalog.clone(), TOKEN, 0, 2).unwrap(), catalog)
}

fn get_request(path: &str) -> Request {
    Request::builder()
        .uri(path)
        .header("authorization", format!("Bearer {TOKEN}"))
        .header("x-bz-foundation-protocol", "1")
        .header("x-bz-foundation-generation", GEN)
        .header("x-bz-foundation-source-prefix", PREFIX)
        .body(Body::empty())
        .unwrap()
}

fn post_request(body: Vec<u8>, mode: &str) -> Request {
    let mut request = get_request("/v1/resolve");
    *request.method_mut() = axum::http::Method::POST;
    request
        .headers_mut()
        .insert(header::CONTENT_TYPE, REQUEST_TYPE.parse().unwrap());
    request
        .headers_mut()
        .insert("x-bz-foundation-read-mode", mode.parse().unwrap());
    request.headers_mut().insert(
        "x-bz-foundation-request-sha256",
        hex::encode(Sha256::digest(&body)).parse().unwrap(),
    );
    *request.body_mut() = Body::from(body);
    request
}

async fn bytes(response: Response) -> Bytes {
    response.into_body().collect().await.unwrap().to_bytes()
}

fn recent_uri(frame: &blockzilla_bank_stream_v2::Frame, commitment: &str) -> String {
    format!(
        "/v1/recent/100?blockhash={}&commitment={commitment}&cursor={}&bank_id=7&source_session={}",
        crate::recent::encode_hash(&frame.envelope.event.bank.blockhash),
        frame.cursor,
        frame.source.session_id
    )
}

#[tokio::test]
async fn recent_http_passes_original_processed_and_finalized_frames() {
    let f = crate::recent::tests::fixture();
    let catalog = Arc::new(MockCatalog {
        calls: AtomicUsize::new(0),
    });
    let app = router_with_recent(catalog.clone(), TOKEN, 0, 2, Some(Arc::new(f.client))).unwrap();
    for commitment in ["processed", "finalized"] {
        let response = app
            .clone()
            .oneshot(get_request(&recent_uri(&f.frame, commitment)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-bz-foundation-result"], "recent");
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            recent::CONTENT_TYPE
        );
        assert_eq!(response.headers()["x-bz-foundation-commitment"], commitment);
        assert_eq!(response.headers()["x-bz-foundation-sha256"], f.frame.sha256);
        let metadata: crate::recent::RecentMetadata = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(response.headers()["x-bz-recent-metadata"].as_bytes())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(metadata.cursor, f.frame.cursor);
        assert_eq!(metadata.source, f.frame.source);
        assert_eq!(bytes(response).await, f.frame.wire);
    }
    assert_eq!(catalog.calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn recent_finalized_miss_binds_archive_hash_before_any_r2_read() {
    let f = crate::recent::tests::fixture();
    let app = router_with_recent(
        Arc::new(MockCatalog {
            calls: AtomicUsize::new(0),
        }),
        TOKEN,
        0,
        2,
        Some(Arc::new(f.client)),
    )
    .unwrap();
    let hash = crate::recent::encode_hash(&[5; 32]);
    let uri = format!("/v1/recent/{SLOT}?blockhash={hash}&commitment=finalized");
    let response = app.clone().oneshot(get_request(&uri)).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.headers()["x-bz-foundation-result"], "not_cached");
    assert_eq!(response.headers()["x-bz-recent-blockhash"], hash);
    let body: serde_json::Value = serde_json::from_slice(&bytes(response).await).unwrap();
    assert_eq!(body["source"], serde_json::to_value(pending()).unwrap());
    let bad = uri.replace(&hash, &crate::recent::encode_hash(&[6; 32]));
    let response = app.oneshot(get_request(&bad)).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body: serde_json::Value = serde_json::from_slice(&bytes(response).await).unwrap();
    assert_eq!(body["reason"], "blockhash_mismatch");
}

#[tokio::test]
async fn recent_expired_processed_and_corrupt_payload_never_return_archive_miss() {
    let f = crate::recent::tests::fixture();
    let uri = recent_uri(&f.frame, "processed");
    let app = router_with_recent(
        Arc::new(MockCatalog {
            calls: AtomicUsize::new(0),
        }),
        TOKEN,
        0,
        2,
        Some(Arc::new(f.client)),
    )
    .unwrap();
    let expired = uri.replace(&f.frame.sha256, &"b".repeat(64));
    let response = app.clone().oneshot(get_request(&expired)).await.unwrap();
    assert_eq!(response.status(), StatusCode::GONE);
    assert_eq!(response.headers()["x-bz-foundation-result"], "unavailable");
    std::fs::write(f.artifact.join("signatures.bin"), [43]).unwrap();
    let response = app.oneshot(get_request(&uri)).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["x-bz-foundation-result"], "unavailable");
}

#[tokio::test]
async fn recent_is_opt_in_and_requires_pins_authentication_and_complete_processed_identity() {
    let (app, _) = app();
    let response = app
        .oneshot(get_request(
            "/v1/recent/100?blockhash=invalid&commitment=processed",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let f = crate::recent::tests::fixture();
    let app = router_with_recent(
        Arc::new(MockCatalog {
            calls: AtomicUsize::new(0),
        }),
        TOKEN,
        0,
        2,
        Some(Arc::new(f.client)),
    )
    .unwrap();
    let mut req = get_request(&recent_uri(&f.frame, "processed"));
    req.headers_mut().remove("authorization");
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let mut req = get_request(&recent_uri(&f.frame, "processed"));
    req.headers_mut().remove("x-bz-foundation-generation");
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::CONFLICT
    );
    let uri = format!(
        "/v1/recent/100?blockhash={}&commitment=processed",
        crate::recent::encode_hash(&[100; 32])
    );
    assert_eq!(
        app.oneshot(get_request(&uri)).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn cancelling_recent_http_does_not_release_a_running_blocking_job_permit() {
    use std::sync::Condvar;

    struct ReleaseOnDrop(Arc<(Mutex<bool>, Condvar)>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            let (released, ready) = &*self.0;
            *released.lock().unwrap() = true;
            ready.notify_all();
        }
    }
    struct LatchCatalog {
        entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }
    impl ResolutionCatalog for LatchCatalog {
        fn source_prefix(&self) -> &str {
            PREFIX
        }
        fn generation(&self) -> &str {
            GEN
        }
        fn pending(&self, slot: u64) -> Result<Option<PendingLocatorV1>> {
            if let Some(signal) = self.entered.lock().unwrap().take() {
                let _ = signal.send(());
            }
            let (released, ready) = &*self.release;
            let (released, _) = ready
                .wait_timeout_while(
                    released.lock().unwrap(),
                    std::time::Duration::from_secs(5),
                    |done| !*done,
                )
                .unwrap();
            ensure!(*released, "test blocking latch timed out");
            Ok((slot == SLOT).then(pending))
        }
        fn archived_blockhash(&self, slot: u64) -> Result<Option<[u8; 32]>> {
            Ok((slot == SLOT).then_some([5; 32]))
        }
        fn resolve(&self, _: &ResolveRequestV1) -> Result<Resolved> {
            anyhow::bail!("resolution is not part of this recent-read test")
        }
    }
    let f = crate::recent::tests::fixture();
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let release_on_drop = ReleaseOnDrop(release.clone());
    let (entered, wait_entered) = tokio::sync::oneshot::channel();
    let catalog = Arc::new(LatchCatalog {
        entered: Mutex::new(Some(entered)),
        release,
    });
    let app = router_with_recent(catalog, TOKEN, 0, 1, Some(Arc::new(f.client))).unwrap();
    let uri = format!(
        "/v1/recent/{SLOT}?blockhash={}&commitment=finalized",
        crate::recent::encode_hash(&[5; 32])
    );
    let task = tokio::spawn(app.clone().oneshot(get_request(&uri)));
    tokio::time::timeout(std::time::Duration::from_secs(2), wait_entered)
        .await
        .unwrap()
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());

    let info = app.clone().oneshot(get_request("/v1/info")).await.unwrap();
    let info: serde_json::Value = serde_json::from_slice(&bytes(info).await).unwrap();
    assert_eq!(
        info["available_permits"], 0,
        "cancelled HTTP caller must not free a running job's capacity"
    );
    let rejected = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        app.clone().oneshot(get_request(&uri)),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
    let rejected: serde_json::Value = serde_json::from_slice(&bytes(rejected).await).unwrap();
    assert_eq!(rejected["reason"], "recent_capacity_unavailable");

    drop(release_on_drop);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let info = app.clone().oneshot(get_request("/v1/info")).await.unwrap();
            let info: serde_json::Value = serde_json::from_slice(&bytes(info).await).unwrap();
            if info["available_permits"] == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn typed_miss_has_pinned_offsets_and_body_digest_and_no_resolve_call() {
    let (app, catalog) = app();
    let response = app
        .clone()
        .oneshot(get_request(&format!("/v1/block/{SLOT}")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.headers()["x-bz-foundation-result"], "not_cached");
    assert_eq!(response.headers()["x-bz-foundation-source-prefix"], PREFIX);
    let sha = response.headers()["x-bz-foundation-sha256"]
        .to_str()
        .unwrap()
        .to_owned();
    let length = response.headers()[header::CONTENT_LENGTH]
        .to_str()
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let body = bytes(response).await;
    assert_eq!(length, body.len());
    assert_eq!(sha, hex::encode(Sha256::digest(&body)));
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["source"], serde_json::to_value(pending()).unwrap());
    let other = app.oneshot(get_request("/v1/block/1")).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes(other).await).unwrap();
    assert!(value["source"].is_null());
    assert_eq!(catalog.calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn resolution_wire_is_verified_and_every_mode_resolves_without_cache() {
    let (app, catalog) = app();
    let body = serde_json::to_vec(&request_value()).unwrap();
    let request_sha = hex::encode(Sha256::digest(&body));
    let first = app
        .clone()
        .oneshot(post_request(body.clone(), "normal"))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    for (name, value) in [
        ("content-type", RESPONSE_TYPE),
        ("x-bz-foundation-result", "resolution"),
        ("x-bz-foundation-commitment", "finalized"),
        ("x-bz-foundation-signatures", "archive"),
        ("x-bz-foundation-cache", "BYPASS"),
        ("x-bz-foundation-pread-calls", "3"),
        ("x-bz-foundation-pread-bytes", "128"),
    ] {
        assert_eq!(first.headers()[name], value);
    }
    assert_eq!(
        first.headers()["x-bz-foundation-request-sha256"],
        request_sha
    );
    assert!(
        !first.headers()["x-bz-foundation-locator"]
            .to_str()
            .unwrap()
            .contains('=')
    );
    let sha = first.headers()["x-bz-foundation-sha256"]
        .to_str()
        .unwrap()
        .to_owned();
    let first_bytes = bytes(first).await;
    assert_eq!(sha, hex::encode(Sha256::digest(&first_bytes)));
    let checked = slot_resolution::decode_checked(&first_bytes).unwrap();
    blockzilla_get_block::slot_references::validate_resolution(
        &checked,
        &request_value().references,
    )
    .unwrap();
    let hit = app
        .clone()
        .oneshot(post_request(body, "source"))
        .await
        .unwrap();
    assert_eq!(hit.headers()["x-bz-foundation-cache"], "BYPASS");
    assert_eq!(hit.headers()["x-bz-foundation-pread-calls"], "3");
    assert_eq!(bytes(hit).await, first_bytes);
    assert_eq!(catalog.calls.load(Ordering::Relaxed), 2);
    let info = app.oneshot(get_request("/v1/info")).await.unwrap();
    let info: serde_json::Value = serde_json::from_slice(&bytes(info).await).unwrap();
    assert_eq!(info["cache_storage"], "none");
    assert_eq!(info["cache"]["hits"], 0);
    assert_eq!(info["local_pread_calls"], 6);
}

#[tokio::test]
async fn every_mode_bypasses_result_cache_for_repeated_and_changed_requests() {
    let (app, catalog) = app();
    let body = serde_json::to_vec(&request_value()).unwrap();
    for _ in 0..2 {
        let response = app
            .clone()
            .oneshot(post_request(body.clone(), "full-cold"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-bz-foundation-cache"], "BYPASS");
    }
    let response = app
        .clone()
        .oneshot(post_request(body.clone(), "normal"))
        .await
        .unwrap();
    assert_eq!(response.headers()["x-bz-foundation-cache"], "BYPASS");
    let response = app
        .clone()
        .oneshot(post_request(body.clone(), "full-cold"))
        .await
        .unwrap();
    assert_eq!(response.headers()["x-bz-foundation-cache"], "BYPASS");
    let mut whitespace = body.clone();
    whitespace.push(b' ');
    let response = app
        .clone()
        .oneshot(post_request(whitespace, "normal"))
        .await
        .unwrap();
    assert_eq!(response.headers()["x-bz-foundation-cache"], "BYPASS");
    let mut changed = request_value();
    changed.hot_sha256 = "cd".repeat(32);
    let response = app
        .clone()
        .oneshot(post_request(
            serde_json::to_vec(&changed).unwrap(),
            "normal",
        ))
        .await
        .unwrap();
    assert_eq!(response.headers()["x-bz-foundation-cache"], "BYPASS");
    let response = app.oneshot(post_request(body, "normal")).await.unwrap();
    assert_eq!(response.headers()["x-bz-foundation-cache"], "BYPASS");
    assert_eq!(catalog.calls.load(Ordering::Relaxed), 7);
}

#[tokio::test]
async fn auth_source_digest_size_and_typed_id_failures_do_not_read_tables() {
    let (app, catalog) = app();
    let body = serde_json::to_vec(&request_value()).unwrap();
    let mut request = post_request(body.clone(), "normal");
    request.headers_mut().remove(header::AUTHORIZATION);
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let mut request = post_request(body.clone(), "normal");
    request
        .headers_mut()
        .insert("x-bz-foundation-generation", "other".parse().unwrap());
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::CONFLICT
    );
    let mut request = post_request(body.clone(), "normal");
    request.headers_mut().insert(
        "x-bz-foundation-request-sha256",
        "00".repeat(32).parse().unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    let mut request = post_request(body.clone(), "normal");
    request
        .headers_mut()
        .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    let request = post_request(vec![b' '; MAX_REQUEST_BYTES + 1], "normal");
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let mut value = request_value();
    value.references.blockhashes = vec![1];
    assert_eq!(
        app.clone()
            .oneshot(post_request(serde_json::to_vec(&value).unwrap(), "normal"))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    value = request_value();
    value.source.blocks.etag = "\"changed\"".into();
    assert_eq!(
        app.oneshot(post_request(serde_json::to_vec(&value).unwrap(), "normal"))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(catalog.calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn capacity_is_acquired_before_body_read_and_shared_with_get() {
    struct SlowCatalog {
        inner: MockCatalog,
        entered: tokio::sync::Notify,
        release: (Mutex<bool>, std::sync::Condvar),
    }
    impl ResolutionCatalog for SlowCatalog {
        fn source_prefix(&self) -> &str {
            PREFIX
        }
        fn generation(&self) -> &str {
            GEN
        }
        fn pending(&self, slot: u64) -> Result<Option<PendingLocatorV1>> {
            self.inner.pending(slot)
        }
        fn resolve(&self, request: &ResolveRequestV1) -> Result<Resolved> {
            self.entered.notify_one();
            let (lock, signal) = &self.release;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = signal.wait(released).unwrap();
            }
            self.inner.resolve(request)
        }
    }
    let catalog = Arc::new(SlowCatalog {
        inner: MockCatalog {
            calls: AtomicUsize::new(0),
        },
        entered: tokio::sync::Notify::new(),
        release: (Mutex::new(false), std::sync::Condvar::new()),
    });
    let app = router(catalog.clone(), TOKEN, 0, 1).unwrap();
    let body = serde_json::to_vec(&request_value()).unwrap();
    let first = tokio::spawn(app.clone().oneshot(post_request(body, "normal")));
    catalog.entered.notified().await;
    let blocked_post = app
        .clone()
        .oneshot(post_request(vec![b' '; MAX_REQUEST_BYTES + 1], "normal"))
        .await
        .unwrap()
        .status();
    let blocked_get = app
        .clone()
        .oneshot(get_request(&format!("/v1/block/{SLOT}")))
        .await
        .unwrap()
        .status();
    *catalog.release.0.lock().unwrap() = true;
    catalog.release.1.notify_all();
    let first = first.await.unwrap().unwrap();
    assert_eq!(blocked_post, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(blocked_get, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(
        app.oneshot(get_request(&format!("/v1/block/{SLOT}")))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
}

fn raw_request(body: Vec<u8>, slot: u64) -> Request {
    let mut request = post_request(body, "normal");
    *request.uri_mut() = format!("/v1/resolve-block/{slot}").parse().unwrap();
    request.headers_mut().insert(
        header::CONTENT_TYPE,
        direct::HOT_REQUEST_TYPE.parse().unwrap(),
    );
    request
}

#[tokio::test]
async fn raw_hot_and_typed_ids_return_the_same_resolution_without_cache_or_signatures() {
    let (app, catalog) = app();
    let (raw, _) = raw_fixture();
    let typed = app
        .clone()
        .oneshot(post_request(
            serde_json::to_vec(&request_value()).unwrap(),
            "normal",
        ))
        .await
        .unwrap();
    assert_eq!(typed.status(), StatusCode::OK);
    let expected = bytes(typed).await;
    for _ in 0..2 {
        let response = app
            .clone()
            .oneshot(raw_request(raw.clone(), SLOT))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-bz-foundation-cache"], "BYPASS");
        assert_eq!(
            response.headers()["x-bz-foundation-request-sha256"],
            hex::encode(Sha256::digest(&raw))
        );
        assert_eq!(response.headers()["x-bz-foundation-pread-calls"], "3");
        for name in [
            "x-bz-foundation-cpu-micros",
            "x-bz-foundation-decompress-cpu-micros",
            "x-bz-foundation-hot-decode-cpu-micros",
            "x-bz-foundation-collect-cpu-micros",
            "x-bz-foundation-table-resolve-cpu-micros",
            "x-bz-foundation-encode-cpu-micros",
        ] {
            assert!(
                response.headers()[name]
                    .to_str()
                    .unwrap()
                    .parse::<u64>()
                    .is_ok()
            );
        }
        assert_eq!(bytes(response).await, expected);
    }
    assert_eq!(catalog.calls.load(Ordering::Relaxed), 3);
    let info = app.oneshot(get_request("/v1/info")).await.unwrap();
    let info: serde_json::Value = serde_json::from_slice(&bytes(info).await).unwrap();
    assert_eq!(info["cache"]["enabled"], false);
    assert_eq!(info["cache"]["bytes"], 0);
    assert_eq!(info["raw_block_resolves"], 2);
    assert_eq!(info["raw_signature_bytes_read"], 0);
}

#[tokio::test]
async fn raw_hot_rejects_wrong_sha_lengths_frames_and_source_before_table_reads() {
    let (app, catalog) = app();
    let (raw, _) = raw_fixture();
    let mut wrong_sha = raw_request(raw.clone(), SLOT);
    wrong_sha.headers_mut().insert(
        "x-bz-foundation-request-sha256",
        "00".repeat(32).parse().unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(wrong_sha).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        app.clone()
            .oneshot(raw_request(raw[..raw.len() - 1].to_vec(), SLOT))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        app.clone()
            .oneshot(raw_request(vec![0; raw.len()], SLOT))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        app.clone()
            .oneshot(raw_request(raw.clone(), 1))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let mut no_auth = raw_request(raw.clone(), SLOT);
    no_auth.headers_mut().remove(header::AUTHORIZATION);
    assert_eq!(
        app.clone().oneshot(no_auth).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let mut wrong_source = raw_request(raw.clone(), SLOT);
    wrong_source.headers_mut().insert(
        "x-bz-foundation-source-prefix",
        "compact-v2/other".parse().unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(wrong_source).await.unwrap().status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        app.oneshot(raw_request(vec![0; direct::MAX_HOT_BYTES + 1], SLOT))
            .await
            .unwrap()
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(catalog.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn a_nonzero_result_cache_budget_is_rejected() {
    let catalog = Arc::new(MockCatalog {
        calls: AtomicUsize::new(0),
    });
    assert!(router(catalog, TOKEN, 1, 1).is_err());
}
