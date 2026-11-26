//! Slot-only admission for original native frames. JSON conversion stays in
//! the Worker. A verified small root control accompanies the unchanged body.
use super::*;
use axum::extract::RawQuery;
use blockzilla_get_block::foundation_protocol::ARCHIVE_LOOKUP_REQUIRED;

#[derive(Debug)]
struct ArchiveLookupRequired;

impl std::fmt::Display for ArchiveLookupRequired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(ARCHIVE_LOOKUP_REQUIRED)
    }
}

impl std::error::Error for ArchiveLookupRequired {}

pub(super) async fn block(
    State(state): State<Arc<AppState>>,
    Path(slot): Path<u64>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if !authorized(&headers, &state) {
        return plain_error(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if !pinned(&headers, &state) {
        return unavailable(&state, slot, StatusCode::CONFLICT, "source_changed", None);
    }
    if slot > blockzilla_bank_stream_v2::SAFE || query.is_some() {
        return unavailable(
            &state,
            slot,
            StatusCode::BAD_REQUEST,
            "invalid_request",
            None,
        );
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
    let generation = recent.producer_generation().to_owned();
    let recent = recent.clone();
    let catalog = state.catalog.clone();
    let joined = tokio::task::spawn_blocking(move || -> Result<_> {
        // Keep the permit until synchronous work ends, even after disconnect.
        let _permit = permit;
        let clock = Clock::start()?;
        let result = (|| -> Result<_> {
            let (found, native_unavailable) = match recent.read_finalized_by_slot(slot) {
                Ok(found) => (found, false),
                Err(error) if error.is::<recent::FinalizedFeedUnavailable>() => (None, true),
                Err(error) => return Err(error),
            };
            let native_archive = if found.is_none() {
                recent.native_archive(slot)?
            } else {
                None
            };
            let archive = if found.is_none() && native_archive.is_none() {
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
            let ledger = if archive.as_ref().is_some_and(|(source, _)| source.is_none()) {
                recent.ledger_compact(slot).map_err(|error| {
                    if error.to_string() == "ledger_not_rooted" {
                        error
                    } else {
                        anyhow::anyhow!("ledger_compact_unavailable")
                    }
                })?
            } else {
                None
            };
            if native_unavailable && ledger.is_none() && matches!(archive, Some((None, None))) {
                // The checked feed reported failed health, and the independently
                // available local readers supplied no block. The archive is
                // still a possible source. Errors above never enter this path.
                return Err(ArchiveLookupRequired.into());
            }
            Ok((found, native_archive, archive, ledger))
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
        _ => (Err(anyhow::anyhow!("finalized task failed")), None),
    };
    let mut reply = match result {
        Ok((Some(found), None, _, None)) => {
            let metadata = serde_json::to_vec(&found.metadata).expect("finalized metadata JSON");
            if metadata.len() > 4096 || found.root.wire.len() > 4096 {
                state.counters.recent_errors.fetch_add(1, Ordering::Relaxed);
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
                .fetch_add(found.frame.wire.len() as u64, Ordering::Relaxed);
            let mut reply = response(
                &state,
                StatusCode::OK,
                "recent",
                recent::CONTENT_TYPE,
                found.frame.wire,
                &found.frame.sha256,
            );
            for (name, value) in [
                ("x-bz-recent-metadata", URL_SAFE_NO_PAD.encode(metadata)),
                (
                    "x-bz-finalized-root",
                    URL_SAFE_NO_PAD.encode(found.root.wire),
                ),
                ("x-bz-foundation-commitment", "finalized".into()),
                ("x-bz-foundation-cache", "BYPASS".into()),
            ] {
                reply
                    .headers_mut()
                    .insert(name, value.parse().expect("bounded finalized header"));
            }
            reply
        }
        Ok((None, Some(native_archive), None, None)) => {
            state.counters.recent_misses.fetch_add(1, Ordering::Relaxed);
            let raw=Bytes::from(serde_json::to_vec(&json!({"version":1,"slot":slot,"reason":"not_cached","source":null,"native_archive":native_archive})).expect("native archive miss JSON"));
            if raw.len() > 16384 {
                return unavailable(
                    &state,
                    slot,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "native_archive_metadata_unavailable",
                    None,
                );
            }
            let sha = hex::encode(Sha256::digest(&raw));
            let mut reply = response(
                &state,
                StatusCode::NOT_FOUND,
                "not_cached",
                "application/json",
                raw,
                &sha,
            );
            reply
                .headers_mut()
                .insert("x-bz-foundation-cache", "BYPASS".parse().unwrap());
            reply
        }
        Ok((None, None, _, Some(ledger))) => {
            state.counters.recent_hits.fetch_add(1, Ordering::Relaxed);
            let mut reply = response(
                &state,
                StatusCode::OK,
                "ledger_compact",
                crate::ledger_compact::CONTENT_TYPE,
                ledger.body,
                &ledger.metadata.sha256,
            );
            for (name, value) in [
                (
                    "x-bz-ledger-metadata",
                    URL_SAFE_NO_PAD.encode(ledger.metadata_bytes),
                ),
                ("x-bz-ledger-generation", ledger.generation),
                ("x-bz-foundation-commitment", "finalized".into()),
                ("x-bz-foundation-cache", "BYPASS".into()),
            ] {
                reply
                    .headers_mut()
                    .insert(name, value.parse().expect("bounded ledger header"));
            }
            reply
        }
        Ok((None, None, Some((source, hash)), None)) => {
            state.counters.recent_misses.fetch_add(1, Ordering::Relaxed);
            let raw = Bytes::from(
                serde_json::to_vec(
                    &json!({"version":1,"slot":slot,"reason":"not_cached","source":source}),
                )
                .expect("finalized miss JSON"),
            );
            if raw.len() > 4096 {
                return unavailable(
                    &state,
                    slot,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "archive_metadata_unavailable",
                    None,
                );
            }
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
        Err(error)
            if matches!(
                error.to_string().as_str(),
                "finalized_not_rooted" | "ledger_not_rooted"
            ) =>
        {
            state.counters.recent_errors.fetch_add(1, Ordering::Relaxed);
            unavailable(&state, slot, StatusCode::CONFLICT, "not_finalized", None)
        }
        Err(error) if error.is::<ArchiveLookupRequired>() => {
            state.counters.recent_misses.fetch_add(1, Ordering::Relaxed);
            unavailable(
                &state,
                slot,
                StatusCode::SERVICE_UNAVAILABLE,
                ARCHIVE_LOOKUP_REQUIRED,
                None,
            )
        }
        Err(error) if error.to_string() == "ledger_compact_unavailable" => {
            state.counters.recent_errors.fetch_add(1, Ordering::Relaxed);
            unavailable(
                &state,
                slot,
                StatusCode::SERVICE_UNAVAILABLE,
                "ledger_compact_unavailable",
                None,
            )
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
    if matches!(reply.status(), StatusCode::OK | StatusCode::NOT_FOUND) {
        reply.headers_mut().insert(
            "x-bz-finalized-producer-generation",
            generation.parse().expect("checked producer generation"),
        );
    }
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
                value
                    .to_string()
                    .parse()
                    .expect("numeric finalized profile"),
            );
        }
    }
    reply
}
