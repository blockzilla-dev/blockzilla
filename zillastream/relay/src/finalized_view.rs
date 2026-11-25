use crate::{
    bank_server::{Position, STATUS_INTERVAL, block_response, requested_after},
    bank_source::BankSource,
    bank_store::BankStore,
    server::Api,
    upstream::Upstream,
};
use anyhow::{Result, ensure};
use axum::{
    Json,
    body::Body,
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use blockzilla_bank_stream_v2::{self as v2, Frame, SourceIdentity, finalized::BlockId};
use bytes::Bytes;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};

fn view_status(store: &BankStore, tip: Option<BlockId>) -> Value {
    let head = store.head();
    json!({"source":head.source,"status":head.status,"sampled_at_unix_ms":head.sampled_at_unix_ms,
        "tip":tip.map(|id| id.to_string())})
}

fn failure(status: StatusCode, error: &str) -> Response {
    (status, Json(json!({"error":error}))).into_response()
}

struct NoticeWindow {
    tip: Option<BlockId>,
    blocks: Vec<(BlockId, Bytes)>,
}

async fn window(store: &Arc<BankStore>, after: Option<BlockId>) -> Result<NoticeWindow> {
    let store = store.clone();
    tokio::task::spawn_blocking(move || {
        let window = store.finalized_window(after.as_ref())?;
        Ok(NoticeWindow {
            tip: window.tip,
            blocks: window
                .frames
                .iter()
                .map(|frame| block_notice(frame))
                .collect(),
        })
    })
    .await?
}

async fn tip_id(store: &Arc<BankStore>) -> Option<BlockId> {
    let store = store.clone();
    tokio::task::spawn_blocking(move || store.finalized_tip().ok().flatten())
        .await
        .ok()
        .flatten()
}

fn block_notice(frame: &Frame) -> (BlockId, Bytes) {
    let event = &frame.envelope.event;
    let id = BlockId::from(&event.bank);
    let parent = BlockId {
        slot: event.bank.parent_slot,
        blockhash: event.bank.parent_blockhash,
    };
    let data = json!({"block_id":id.to_string(),"parent_id":parent.to_string(),"slot":id.slot,
        "block_height":event.block_height,"commitment":"finalized","sha256":frame.sha256,
        "bytes":frame.wire.len(),"url":format!("/v2/banks/chunks/{}", frame.sha256)});
    (
        id,
        format!("id: {id}\nevent: block\ndata: {data}\n\n").into(),
    )
}

fn window_error(error: &anyhow::Error) -> &'static str {
    match error.to_string().as_str() {
        "source_failed" => "source_failed",
        "replay_unavailable" => "replay_unavailable",
        "finalized_conflict" => "finalized_conflict",
        _ => "finalized_unavailable",
    }
}

pub(crate) async fn events(
    State(api): State<Api>,
    position: std::result::Result<Query<Position>, QueryRejection>,
    headers: HeaderMap,
) -> Response {
    let banks = api.banks.unwrap();
    if banks.direct_beam {
        return crate::bank_server::replay_failure(
            StatusCode::GONE,
            "finalized_view_unavailable_direct_mode",
            &banks,
        )
        .await;
    }
    let store = banks.store;
    let Ok(Query(position)) = position else {
        return failure(StatusCode::BAD_REQUEST, "invalid_block_id");
    };
    let mut after = match requested_after(position, &headers) {
        Ok(value) => match value.map(|id| id.parse::<BlockId>()).transpose() {
            Ok(id) => id,
            Err(_) => return failure(StatusCode::BAD_REQUEST, "invalid_block_id"),
        },
        Err(error) => return failure(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let mut initial = match window(&store, after).await {
        Ok(value) => Some(value),
        Err(error) => {
            let tip = tip_id(&store).await;
            return (
                StatusCode::GONE,
                Json(json!({"error":window_error(&error),
                "head":view_status(&store, tip)})),
            )
                .into_response();
        }
    };
    let stream = async_stream::stream! {
        let mut next_status = tokio::time::Instant::now();
        let mut tip = initial.as_ref().and_then(|result| result.tip);
        loop {
            let notified = store.notify.notified();
            let status = view_status(&store, tip);
            if status["status"] == "failed" {
                yield Ok::<Bytes,std::io::Error>(format!("event: gap\ndata: {}\n\n", json!({"error":"source_failed","head":status})).into());
                break;
            }
            if tokio::time::Instant::now() >= next_status {
                yield Ok(format!("event: status\ndata: {status}\n\n").into());
                next_status = tokio::time::Instant::now() + STATUS_INTERVAL;
            }
            if status["status"] == "live" {
                let result = match initial.take() { Some(value) => Ok(value), None => window(&store, after).await };
                match result {
                    Ok(value) => {
                        if store.head().status != "live" {
                            continue;
                        }
                        tip = value.tip;
                        if !value.blocks.is_empty() {
                            for (id, notice) in value.blocks {
                                yield Ok(notice);
                                after = Some(id);
                            }
                            continue;
                        }
                    }
                    Err(error) => {
                        tip = tip_id(&store).await;
                        yield Ok(format!("event: gap\ndata: {}\n\n",json!({"error":window_error(&error),"head":view_status(&store,tip)})).into());
                        break;
                    }
                }
            } else {
                initial = None;
            }
            tokio::select! { _ = notified => {}, _ = tokio::time::sleep_until(next_status) => {} }
        }
    };
    (
        [(header::CONTENT_TYPE, "text/event-stream; charset=utf-8")],
        Body::from_stream(stream),
    )
        .into_response()
}

pub(crate) async fn block(State(api): State<Api>, Path(id): Path<String>) -> Response {
    let Ok(id) = id.parse::<BlockId>() else {
        return failure(StatusCode::BAD_REQUEST, "invalid_block_id");
    };
    let banks = api.banks.unwrap();
    let source = banks.store.source.clone();
    if banks.direct_beam {
        let output = banks.output.clone().unwrap();
        let found = tokio::task::spawn_blocking(move || -> Result<Option<Frame>> {
            let reader = BankSource::open(&output)?;
            ensure!(reader.source == source, "source_changed");
            reader.validate_beam_authority()?;
            reader.retained_finalized_block(id.slot, &id.blockhash)
        })
        .await;
        return match found {
            Ok(Ok(Some(frame))) => {
                let mut response = block_response(&frame);
                response
                    .headers_mut()
                    .insert("x-blockzilla-commitment", "finalized".parse().unwrap());
                response
            }
            _ => {
                crate::bank_server::replay_failure(StatusCode::GONE, "block_unavailable", &banks)
                    .await
            }
        };
    }
    let found = if let Some(output) = banks.output {
        tokio::task::spawn_blocking(move || {
            let reader = BankSource::open(&output)?;
            ensure!(reader.source == source, "source_changed");
            reader.finalized_block(id.slot, &id.blockhash)
        })
        .await
        .map_err(anyhow::Error::from)
        .and_then(|result| result)
    } else if let Some((upstream, client)) = banks.hot_upstream {
        fetch_block(&upstream, &client, &source, id).await
    } else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "finalized_lookup_unavailable",
        );
    };
    match found {
        Ok(Some(frame)) => {
            let mut response = block_response(&frame);
            response
                .headers_mut()
                .insert("x-blockzilla-commitment", "finalized".parse().unwrap());
            response
        }
        Ok(None) => failure(StatusCode::NOT_FOUND, "block_unavailable"),
        _ => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "finalized_lookup_unavailable",
        ),
    }
}

async fn fetch_block(
    upstream: &Upstream,
    client: &reqwest::Client,
    source: &SourceIdentity,
    id: BlockId,
) -> Result<Option<Frame>> {
    let response = client
        .get(format!("{}v2/banks/finalized/blocks/{id}", upstream.url))
        .bearer_auth(&upstream.token)
        .timeout(Duration::from_secs(10))
        .send()
        .await?;
    if response.status() == StatusCode::NOT_FOUND {
        let bytes = read_body(response, 256).await?;
        let error: Value = serde_json::from_slice(&bytes)?;
        ensure!(
            error["error"] == "block_unavailable",
            "hot_lookup_unavailable"
        );
        return Ok(None);
    }
    let headers = response.headers();
    let value = |name| headers.get(name).and_then(|value| value.to_str().ok());
    ensure!(
        response.status() == StatusCode::OK
            && value("content-type") == Some("application/vnd.blockzilla.stream.v2")
            && value("x-blockzilla-commitment") == Some("finalized"),
        "hot_lookup_unavailable"
    );
    let digest = value("etag")
        .and_then(|tag| tag.strip_prefix('"')?.strip_suffix('"'))
        .filter(|digest| v2::is_digest(digest))
        .ok_or_else(|| anyhow::anyhow!("invalid_hot_block_digest"))?
        .to_owned();
    let frame = v2::decode(
        crate::bank_upstream::bounded(response, v2::MAX_FRAME)
            .await?
            .into(),
    )?;
    let event = &frame.envelope.event;
    ensure!(
        &frame.source == source
            && frame.sha256 == digest
            && event.kind == "block"
            && BlockId::from(&event.bank) == id,
        "hot_block_changed"
    );
    Ok(Some(frame))
}

async fn read_body(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(body.len() + chunk.len() <= limit, "response_too_large");
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
