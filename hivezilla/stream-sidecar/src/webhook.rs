//! At-least-once delivery is independent from the canonical stream and ACK task.
use crate::{
    config::{private_token, webhook_signing_key},
    store::Store,
};
use anyhow::{Context, Result};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

/// Sign the exact queued body. Each retry has a fresh timestamp and the same
/// durable delivery ID, so a receiver can check age and deduplicate by ID.
pub fn signature(key: &[u8], timestamp: u64, id: &str, body: &[u8]) -> Result<String> {
    anyhow::ensure!(
        blockzilla_bank_stream_v2::is_digest(id),
        "invalid_delivery_id"
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(key).context("invalid_signing_key")?;
    mac.update(b"blockzilla-webhook-v1\n");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b"\n");
    mac.update(id.as_bytes());
    mac.update(b"\n");
    mac.update(body);
    Ok(format!(
        "v1={}",
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
}

pub async fn run(store: Arc<Store>) -> Result<()> {
    let targets = store
        .targets
        .iter()
        .map(|target| {
            let path = target
                .signing_key_file
                .as_deref()
                .context("webhook_signing_key_required")?;
            Ok((target.clone(), webhook_signing_key(path)?))
        })
        .collect::<Result<Vec<_>>>()?;
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(5))
        .build()?;
    let permits = Arc::new(Semaphore::new(4));
    let mut tasks = tokio::task::JoinSet::new();
    for (target, signing_key) in targets {
        let db = store.clone();
        let http = http.clone();
        let permits = permits.clone();
        tasks.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let _permit = permits.acquire().await?;
                let lookup = db.clone();
                let selected = target.clone();
                let Some(job) = tokio::task::spawn_blocking(move || {
                    lookup.next_job(&selected, blockzilla_bank_client::now_ms())
                })
                .await??
                else {
                    continue;
                };
                let result = async {
                    let timestamp = blockzilla_bank_client::now_ms() / 1000;
                    let signed = signature(
                        signing_key.as_bytes(),
                        timestamp,
                        &job.delivery_id,
                        job.body.as_bytes(),
                    )?;
                    let mut request = http
                        .post(&job.target.url)
                        .header("content-type", "application/json")
                        .header("x-blockzilla-delivery-id", &job.delivery_id)
                        .header("x-blockzilla-timestamp", timestamp.to_string())
                        .header("x-blockzilla-signature", signed)
                        .body(job.body.clone());
                    if let Some(path) = &job.target.token_file {
                        request = request.bearer_auth(private_token(path)?);
                    }
                    let response = request
                        .send()
                        .await
                        .map_err(|e| anyhow::anyhow!(e.without_url().to_string()))?;
                    anyhow::ensure!(
                        response.status().is_success(),
                        "webhook_http_{}",
                        response.status().as_u16()
                    );
                    anyhow::ensure!(
                        response
                            .headers()
                            .get_all("x-blockzilla-ack")
                            .iter()
                            .count()
                            == 1
                            && response
                                .headers()
                                .get("x-blockzilla-ack")
                                .and_then(|v| v.to_str().ok())
                                == Some(job.delivery_id.as_str()),
                        "webhook_ack_mismatch"
                    );
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                let error = result
                    .as_ref()
                    .err()
                    .map(ToString::to_string)
                    .unwrap_or_default();
                let finished = db.clone();
                tokio::task::spawn_blocking(move || {
                    finished.finish_job(
                        &job,
                        result.is_ok(),
                        &error,
                        blockzilla_bank_client::now_ms(),
                    )
                })
                .await??;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        });
    }
    while let Some(result) = tasks.join_next().await {
        result??;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::WebhookTarget, projection::Payload, store::Limits};
    use axum::{
        Router,
        extract::State,
        http::{HeaderMap, StatusCode},
        response::{IntoResponse, Response},
        routing::post,
    };
    use blockzilla_bank_client::{Bootstrap, Delivery};
    use blockzilla_bank_stream_v2::{self as v2, Head, fixtures::*};
    use serde_json::json;
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    struct Receiver {
        calls: AtomicUsize,
        deliveries: Mutex<Vec<(String, String)>>,
        key: String,
    }
    async fn receive(State(s): State<Arc<Receiver>>, headers: HeaderMap, body: String) -> Response {
        let id = headers
            .get("x-blockzilla-delivery-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let timestamp = headers
            .get("x-blockzilla-timestamp")
            .unwrap()
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert!(blockzilla_bank_client::now_ms() / 1000 - timestamp <= 5);
        assert_eq!(
            headers
                .get("x-blockzilla-signature")
                .unwrap()
                .to_str()
                .unwrap(),
            signature(s.key.as_bytes(), timestamp, &id, body.as_bytes()).unwrap()
        );
        s.deliveries.lock().unwrap().push((id.clone(), body));
        if s.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        (StatusCode::OK, [("x-blockzilla-ack", id)]).into_response()
    }
    #[tokio::test]
    async fn local_receiver_retry_keeps_id_and_does_not_hold_input_commit() {
        let state = Arc::new(Receiver {
            calls: AtomicUsize::new(0),
            deliveries: Mutex::new(vec![]),
            key: "local-test-signing-key-0000000000000000000000000000".into(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = Router::new()
            .route("/hook", post(receive))
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let t = tempfile::tempdir().unwrap();
        let key = t.path().join("signing-key");
        std::fs::write(&key, &state.key).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let target:WebhookTarget=serde_json::from_value(json!({"id":"local","url":format!("http://{address}/hook"),"signing_key_file":key,"queue_events":1,"kinds":["block"]})).unwrap();
        let store = Store::open(
            &t.path().join("sidecar.sqlite"),
            source(),
            "fixture-generation".into(),
            vec![target.clone()],
            Limits::default(),
        )
        .unwrap();
        let base = v2::cursor(&source().session_id, 0, "-");
        let boot = Bootstrap {
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
        };
        store.bootstrap(&boot, None).unwrap();
        for (sequence, slot) in [(1, 9), (2, 10)] {
            let f = block(sequence, slot, slot, slot - 1, slot);
            let p = Payload {
                frame: f.clone(),
                json: json!({"blocks":[{"slot":slot,"bankId":slot,"blockhash":"fixture","parentSlot":slot-1,"parentBlockhash":"fixture","blockHeight":slot,"transactionCount":1,"transactions":[{"index":0,"signature":"fixture","signatures":["fixture"],"success":false,"err":"failure"}]}]}),
            };
            store
                .commit(
                    &Delivery {
                        frame: f,
                        dependency: None,
                    },
                    Some(&p),
                )
                .unwrap();
        }
        assert_eq!(
            v2::parse_cursor(&store.cursor().unwrap().unwrap())
                .unwrap()
                .1,
            2
        );
        assert_eq!(store.subscriptions().unwrap()[0]["state"], "paused");
        let db = store.clone();
        let sender = tokio::spawn(async move {
            run(db).await.unwrap();
        });
        tokio::time::timeout(Duration::from_secs(6), async {
            loop {
                if state.calls.load(Ordering::SeqCst) >= 2
                    && store.next_job(&target, u64::MAX).unwrap().is_none()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
        .await
        .unwrap();
        let deliveries = state.deliveries.lock().unwrap();
        assert_eq!(deliveries.len(), 2);
        assert_eq!(
            deliveries[0], deliveries[1],
            "retry must preserve both delivery ID and exact signed body"
        );
        assert_eq!(
            v2::parse_cursor(&store.cursor().unwrap().unwrap())
                .unwrap()
                .1,
            2
        );
        drop(deliveries);
        sender.abort();
        server.abort();
    }

    #[test]
    fn signature_binds_timestamp_id_and_exact_body() {
        let key = b"local-test-signing-key-0000000000000000000000000000";
        let id = "ab".repeat(32);
        let body = "{\"cursor\":\"fixture:o1:abc\",\"kind\":\"root\",\"text\":\"café\"}".as_bytes();
        let signed = signature(key, 1_700_000_000, &id, body).unwrap();
        // Independent Python stdlib HMAC-SHA256 reference.
        assert_eq!(
            signed,
            "v1=504a959d98adf8c9bab9a6cbf2f0ced12bcac7e50e42cab51db77e38d2c90472"
        );
        assert_ne!(signed, signature(key, 1_700_000_001, &id, body).unwrap());
        assert_ne!(
            signed,
            signature(key, 1_700_000_000, &"ac".repeat(32), body).unwrap()
        );
        assert_ne!(signed, signature(key, 1_700_000_000, &id, b"{}").unwrap());
        assert_ne!(
            signed,
            signature(b"different-key", 1_700_000_000, &id, body).unwrap()
        );
        assert!(signature(key, 1, "invalid-id", body).is_err());
    }

    #[tokio::test]
    async fn unsigned_target_is_rejected_before_any_delivery() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target: WebhookTarget = serde_json::from_value(
            json!({"id":"unsigned","url":format!("http://{}/",listener.local_addr().unwrap())}),
        )
        .unwrap();
        let t = tempfile::tempdir().unwrap();
        let store = Store::open(
            &t.path().join("sidecar.sqlite"),
            source(),
            "fixture-generation".into(),
            vec![target],
            Limits::default(),
        )
        .unwrap();
        assert_eq!(
            run(store).await.unwrap_err().to_string(),
            "webhook_signing_key_required"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }
}
