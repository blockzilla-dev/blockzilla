//! Cost-first recovery: one existing native-frame read; archive only on a checked miss.
use super::*;
use foundation_first::{RecentOutcome, RecentRequest, RecentSource};

pub(super) async fn handle(
    req: Request,
    env: worker::Env,
    ctx: Rc<worker::Context>,
    profile: Option<ProfileHandle>,
    api_key: RpcApiKeyRecord,
    request_started: f64,
    metrics: AnalyticsEngineDataset,
    raw_slot: &str,
) -> Result<Response> {
    let request = match RecentRequest::parse(&req, raw_slot) {
        Ok(value) if req.headers().get("Range")?.is_none() => value,
        _ => {
            return finish(
                json_error(
                    400,
                    "invalid_recovery_request",
                    "Use an exact compact block identity without Range",
                )?,
                &api_key,
                &metrics,
                request_started,
                profile.as_ref(),
                StorageSnapshot::default(),
                0,
            );
        }
    };
    let expected_source = match optional_var(&env, "BZ_FOUNDATION_RECENT_SOURCE")
        .ok_or_else(|| "recent source is not configured".to_owned())
        .and_then(|text| RecentSource::parse(&text))
    {
        Ok(value) => value,
        Err(_) => {
            return finish(
                json_error(
                    503,
                    "recent_source_unavailable",
                    "Recent source identity is not configured",
                )?,
                &api_key,
                &metrics,
                request_started,
                profile.as_ref(),
                StorageSnapshot::default(),
                0,
            );
        }
    };
    // Do not attach ArchiveCache. This route creates no result or range copy.
    let source = match WorkerSource::from_env(&env, profile.clone()) {
        Ok(value) => value,
        Err(_) => {
            return finish(
                json_error(
                    503,
                    "recent_source_unavailable",
                    "Recent source is not configured",
                )?,
                &api_key,
                &metrics,
                request_started,
                profile.as_ref(),
                StorageSnapshot::default(),
                0,
            );
        }
    };
    let result = if let Some(config) = &source.foundation_lookup {
        config
            .lookup_recent(&source, &request, &expected_source)
            .await
    } else {
        Err("Foundation recent lookup is not configured".into())
    };
    let mut response = match result {
        Ok(RecentOutcome::Recent {
            response,
            metadata,
            encoded_metadata,
        }) => {
            let length = response
                .headers()
                .get("Content-Length")?
                .ok_or_else(|| worker::Error::RustError("Missing recent frame length".into()))?;
            let native_diagnostics = [
                (
                    "X-BZ-Recent-CPU-Micros",
                    "X-Blockzilla-Recent-Native-CPU-Micros",
                ),
                (
                    "X-BZ-Recent-Work-Micros",
                    "X-Blockzilla-Recent-Native-Work-Micros",
                ),
                (
                    "X-BZ-Recent-Elapsed-Micros",
                    "X-Blockzilla-Recent-Native-Elapsed-Micros",
                ),
            ]
            .into_iter()
            .filter_map(|(private, public)| {
                let text = response.headers().get(private).ok()??;
                let value = text.parse::<u64>().ok()?;
                (value <= 60_000_000 && text == value.to_string()).then_some((public, text))
            })
            .collect::<Vec<_>>();
            let (_, body) = response.into_parts();
            let parts = stream_parts::response_and_completion_from_parts(
                Vec::new(),
                body,
                length
                    .parse::<u64>()
                    .map_err(|_| worker::Error::RustError("Invalid recent frame length".into()))?,
                Vec::new(),
                worker::ResponseBody::Empty,
                0,
                Vec::new(),
            )?;
            // FixedLengthStream is the final HTTP length authority. It keeps
            // body chunks in JS and does not clone or buffer the frame.
            let mut response = parts.response;
            ctx.wait_until(async move {
                let _ = wasm_bindgen_futures::JsFuture::from(parts.completion).await;
            });
            for (name, value) in [
                ("Content-Type", "application/vnd.blockzilla.stream.v2"),
                ("Content-Length", length.as_str()),
                ("Cache-Control", "private, no-store"),
                ("X-Blockzilla-Source", "FOUNDATION_RECENT"),
                ("X-Blockzilla-Recovery-Format", "native-bank-stream-v2"),
                ("X-Blockzilla-Frame-SHA256", metadata.frame_sha256.as_str()),
                ("X-Blockzilla-Recent-Metadata", encoded_metadata.as_str()),
                ("X-Blockzilla-Commitment", metadata.commitment.as_str()),
                ("X-Blockzilla-Cursor", metadata.cursor.as_str()),
                ("X-Blockzilla-Blockhash", metadata.blockhash.as_str()),
                (
                    "X-Blockzilla-Previous-Blockhash",
                    metadata.parent_blockhash.as_str(),
                ),
                ("X-Blockzilla-Storage-Bytes-Mode", "native-recent-stream"),
                ("X-Blockzilla-Origin-Expected-Bytes", "0"),
            ] {
                response.headers_mut().set(name, value)?;
            }
            response
                .headers_mut()
                .set("ETag", &format!("\"{}\"", metadata.frame_sha256))?;
            for (name, value) in native_diagnostics {
                response.headers_mut().set(name, &value)?;
            }
            response
        }
        Ok(RecentOutcome::NotCached {
            source: Some(route),
        }) if request.commitment == "finalized" => {
            match resolution::foundation_archive_binary_response_for_hash(
                &source,
                request.slot,
                route,
                &ctx,
                &metrics,
                &api_key,
                Some(request.expected_hash),
            )
            .await
            {
                Ok(mut response) => {
                    response
                        .headers_mut()
                        .set("X-Blockzilla-Source", "R2_ARCHIVE")?;
                    response
                        .headers_mut()
                        .set("X-Blockzilla-Recovery-Format", "archive-wincode-bundle-v1")?;
                    response
                        .headers_mut()
                        .set("X-Blockzilla-Commitment", "finalized")?;
                    response
                        .headers_mut()
                        .set("X-Blockzilla-Blockhash", &request.blockhash)?;
                    response
                        .headers_mut()
                        .set("Cache-Control", "private, no-store")?;
                    response
                }
                Err(error) if error == "archive blockhash differs from requested blockhash" => {
                    json_error(
                        409,
                        "hash_mismatch",
                        "Archive block differs from the expected hash",
                    )?
                }
                Err(_) => json_error(
                    502,
                    "archive_recovery_failed",
                    "Archive recovery could not complete",
                )?,
            }
        }
        Ok(RecentOutcome::NotCached { .. }) => json_error(
            404,
            "coverage_unavailable",
            "No admitted archive route exists for this block",
        )?,
        Ok(RecentOutcome::Unavailable { status, reason }) => json_error(status, &reason, &reason)?,
        Err(_) => json_error(
            502,
            "recent_lookup_rejected",
            "Recent source transport or identity check failed",
        )?,
    };
    // Body and error responses share the same request-local operation receipt.
    response
        .headers_mut()
        .set("X-Blockzilla-Result-Cache", "DISABLED")?;
    finish(
        response,
        &api_key,
        &metrics,
        request_started,
        profile.as_ref(),
        source.storage_metrics.snapshot(),
        source.billable_backend_reads(),
    )
}

fn finish(
    mut response: Response,
    api_key: &RpcApiKeyRecord,
    metrics: &AnalyticsEngineDataset,
    request_started: f64,
    profile: Option<&ProfileHandle>,
    storage: StorageSnapshot,
    reads: u8,
) -> Result<Response> {
    add_profile_headers(response.headers(), profile)?;
    response
        .headers_mut()
        .set("Cache-Control", "private, no-store")?;
    let outcome = if response.status_code() == 200 {
        "ok"
    } else {
        "recovery_error"
    };
    finish_metered_response(
        response,
        api_key,
        metrics,
        MeteredRequest::new("getBlock", outcome, "bypass", "http_compact", 0, reads)
            .with_storage(storage),
        request_started,
        profile,
    )
}
