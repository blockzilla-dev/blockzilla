use crate::{
    bank_server::{Position, STATUS_INTERVAL, accepted, code},
    bank_store::BankStore,
    server::Api,
};
use anyhow::{Context, Result, ensure};
use axum::{
    Json,
    body::Body,
    extract::{Query, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use blockzilla_bank_stream_v2::Frame;
use bytes::Bytes;
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};
use tokio::sync::{OnceCell, Semaphore};

type Projection = Arc<OnceCell<Option<Bytes>>>;

pub struct LandedView {
    recent: Mutex<VecDeque<(String, Projection)>>,
    decoder: Arc<Semaphore>,
}

impl Default for LandedView {
    fn default() -> Self {
        Self {
            recent: Mutex::new(VecDeque::new()),
            decoder: Arc::new(Semaphore::new(1)),
        }
    }
}

impl LandedView {
    async fn block(&self, store: &BankStore, confirmation: &Frame) -> Result<Option<Bytes>> {
        let projection = {
            let mut recent = self.recent.lock().unwrap();
            if let Some((_, projection)) = recent.iter().find(|(id, _)| id == &confirmation.sha256)
            {
                projection.clone()
            } else {
                if recent.len() == 8 {
                    recent.pop_front();
                }
                let projection = Arc::new(OnceCell::new());
                recent.push_back((confirmation.sha256.clone(), projection.clone()));
                projection
            }
        };
        let bytes = projection.get_or_try_init(|| async {
            let event = &confirmation.envelope.event;
            if event.kind == "root" && store.retained_confirmation_before(confirmation) {
                return Ok(None);
            }
            let digest = event.payload_frame_sha256.as_deref().context("missing_payload_frame")?;
            let payload = store.chunk(digest).context("dependency_unavailable")?;
            ensure!(payload.source == confirmation.source, "source_changed");
            event.matches_payload(&payload)?;
            let permit = self.decoder.clone().acquire_owned().await?;
            let cursor = confirmation.cursor.clone();
            let observed_at = event.observed_at_unix_ms;
            let commitment = event.commitment.clone().context("missing_commitment")?;
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let signatures: Vec<_> = blockzilla_stream_decoder::bank_first_signatures(&payload)?
                    .iter()
                    .map(|signature| bs58::encode(signature).into_string())
                    .collect();
                let bank = &payload.envelope.event.bank;
                let data = json!({"slot":bank.slot,"blockhash":bs58::encode(bank.blockhash).into_string(),
                    "parent_blockhash":bs58::encode(bank.parent_blockhash).into_string(),"signatures":signatures,
                    "commitment":commitment,"observed_at_unix_ms":observed_at});
                Ok::<_, anyhow::Error>(Some(format!("id: {cursor}\nevent: block\ndata: {data}\n\n").into()))
            }).await?
        }).await?;
        Ok(bytes.clone())
    }
}

fn status(store: &BankStore) -> Value {
    let head = store.head();
    json!({"source":head.source,"status":head.status,"sampled_at_unix_ms":head.sampled_at_unix_ms})
}

fn failure(store: &BankStore, status_code: StatusCode, error: &str) -> Response {
    (
        status_code,
        Json(json!({"error":error,"head":status(store)})),
    )
        .into_response()
}

pub(crate) async fn events(
    State(api): State<Api>,
    position: std::result::Result<Query<Position>, QueryRejection>,
    headers: HeaderMap,
) -> Response {
    let banks = api.banks.unwrap();
    let store = banks.store;
    let view = banks.public_views.unwrap();
    let Ok(Query(position)) = position else {
        return failure(&store, StatusCode::BAD_REQUEST, "invalid_cursor");
    };
    let mut after = match accepted(&store, position, &headers) {
        Ok(cursor) => cursor,
        Err(error) => {
            let error = code(&error);
            let status = if matches!(error, "source_changed" | "replay_unavailable") {
                StatusCode::GONE
            } else {
                StatusCode::BAD_REQUEST
            };
            return failure(&store, status, error);
        }
    };
    if store.head().status == "failed" {
        return failure(&store, StatusCode::GONE, "source_failed");
    }
    let stream = async_stream::stream! {
        let initial = status(&store);
        yield Ok::<Bytes, std::io::Error>(format!("id: {after}\nevent: status\ndata: {initial}\n\n").into());
        let mut next_status = tokio::time::Instant::now() + STATUS_INTERVAL;
        loop {
            let notified = store.notify.notified();
            let head = status(&store);
            if head["status"] == "failed" {
                yield Ok::<Bytes, std::io::Error>(format!("event: gap\ndata: {}\n\n", json!({"error":"source_failed","head":head})).into());
                break;
            }
            if tokio::time::Instant::now() >= next_status {
                yield Ok(format!("event: status\ndata: {head}\n\n").into());
                next_status = tokio::time::Instant::now() + STATUS_INTERVAL;
            }
            if head["status"] == "live" {
                match store.after(&after) {
                    Ok(Some(frame)) => {
                        let next = frame.cursor.clone();
                        if matches!(frame.envelope.event.kind.as_str(), "confirmed" | "root") {
                            let result = view.block(&store, &frame).await;
                            drop(frame);
                            let current = status(&store);
                            if current["status"] != "live" {
                                continue;
                            }
                            match result {
                                Ok(Some(bytes)) => yield Ok(bytes),
                                Ok(None) => (),
                                Err(_) => {
                                    yield Ok(format!("event: gap\ndata: {}\n\n", json!({"error":"dependency_unavailable","head":current})).into());
                                    break;
                                }
                            }
                        }
                        after = next;
                        continue;
                    }
                    Ok(None) => (),
                    Err(error) => {
                        yield Ok(format!("event: gap\ndata: {}\n\n", json!({"error":code(&error),"head":head})).into());
                        break;
                    }
                }
            }
            tokio::select! { _ = notified => {}, _ = tokio::time::sleep_until(next_status) => {} }
        }
    };
    let mut response = Body::from_stream(stream).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        "text/event-stream; charset=utf-8".parse().unwrap(),
    );
    response
}
