//! An admitted per-slot object replaces sparse-index and registry reads.
//! Binary bodies remain native streams; JSON alone reads and decodes them.
use super::*;
use crate::foundation_protocol::{PendingLocatorV1, ResolveRequestV1};
use crate::slot_resolution::{self, CheckedResolution, LocatorV1, SourceObjectIdentity};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::collections::BTreeSet;
use worker::ResponseBody;

#[derive(Clone)]
pub(super) struct Config {
    bucket: Bucket,
    prefix: String,
    pub(super) generation: String,
    slots: BTreeSet<u64>,
    locator_secret: String,
}

impl Config {
    pub(super) fn from_env(env: &worker::Env) -> std::result::Result<Option<Self>, String> {
        let Some(prefix) = optional_var(env, "BZ_RESOLUTION_PREFIX") else {
            return Ok(None);
        };
        let generation = required_var(env, "BZ_RESOLUTION_GENERATION")?;
        let raw_slots = required_var(env, "BZ_RESOLUTION_SLOTS")?;
        let slots: BTreeSet<u64> = raw_slots
            .split(',')
            .map(|s| {
                s.trim()
                    .parse::<u64>()
                    .map_err(|_| "BZ_RESOLUTION_SLOTS must contain decimal slots".to_string())
            })
            .collect::<std::result::Result<_, _>>()?;
        if slots.is_empty()
            || slots.len() > 10_000
            || prefix.len() > 512
            || prefix
                .split('/')
                .any(|p| p.is_empty() || p == "." || p == "..")
        {
            return Err("resolution admission or prefix is invalid".into());
        }
        let binding = optional_var(env, "BZ_RESOLUTION_BUCKET_BINDING")
            .unwrap_or_else(|| "BZ_RESOLUTION".into());
        let bucket = env
            .bucket(&binding)
            .map_err(|_| format!("missing R2 binding {binding}"))?;
        let locator_secret = required_var(env, "BZ_LOCATOR_SECRET")?;
        if locator_secret.len() < 32 {
            return Err("BZ_LOCATOR_SECRET must contain at least 32 bytes".into());
        }
        Ok(Some(Self {
            bucket,
            prefix,
            generation,
            slots,
            locator_secret,
        }))
    }

    pub(super) fn covers(&self, slot: u64) -> bool {
        self.slots.contains(&slot)
    }
    fn key(&self, slot: u64) -> String {
        format!(
            "{}/epoch-{}/slot-{slot}.resolution.v1",
            self.prefix,
            epoch_for_slot(slot)
        )
    }

    fn token(&self, locator: &LocatorV1) -> std::result::Result<String, String> {
        let bytes = wincode::config::serialize(locator, wincode_leb128_config())
            .map_err(|e| e.to_string())?;
        let mac = hmac_sha256(self.locator_secret.as_bytes(), &bytes);
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&bytes),
            URL_SAFE_NO_PAD.encode(mac)
        ))
    }

    fn verify_token(
        &self,
        token: &str,
        prefix: &str,
        slot: u64,
    ) -> std::result::Result<LocatorV1, String> {
        if token.len() > 4096 {
            return Err("locator token is too large".into());
        }
        let (payload, mac) = token.split_once('.').ok_or("invalid locator token")?;
        let bytes = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| "invalid locator payload")?;
        let received = URL_SAFE_NO_PAD
            .decode(mac)
            .map_err(|_| "invalid locator MAC")?;
        let expected = hmac_sha256(self.locator_secret.as_bytes(), &bytes);
        if received.len() != 32
            || received
                .iter()
                .zip(expected)
                .fold(0u8, |d, (a, b)| d | (a ^ b))
                != 0
        {
            return Err("invalid locator MAC".into());
        }
        let locator: LocatorV1 = wincode::config::deserialize_exact(
            &bytes,
            blockzilla_primitives::bounded_wincode_leb128_config::<4096>(),
        )
        .map_err(|_| "invalid locator payload")?;
        locator.validate(prefix, &self.generation, slot)?;
        if !self.covers(slot) {
            return Err("slot is outside the admitted resolution coverage".into());
        }
        Ok(locator)
    }
}

pub(super) fn covered(source: &WorkerSource, slot: u64) -> bool {
    source
        .resolution
        .as_ref()
        .is_some_and(|config| config.covers(slot))
}

async fn load(
    source: &WorkerSource,
    slot: u64,
) -> std::result::Result<(CheckedResolution, Vec<u8>), String> {
    let load_started = now_ms();
    let config = source
        .resolution
        .as_ref()
        .ok_or("resolution is not configured")?;
    if !config.covers(slot) {
        return Err("slot is outside the admitted resolution coverage".into());
    }
    let key = config.key(slot);
    let cache_key = source.cache.as_ref().map(|c| {
        format!(
            "{}/__blockzilla-resolution/{}/{}",
            c.origin,
            c.generation,
            api_key_digest(&key)
        )
    });
    let mut cached = cache_key.as_ref().and_then(|key| {
        ARCHIVE_BYTES
            .with(|cache| cache.borrow_mut().get(key))
            .filter(|bytes| {
                (slot_resolution::HEADER_LEN..=slot_resolution::MAX_RESOLUTION_BYTES)
                    .contains(&bytes.len())
            })
    });
    if cached.is_some() {
        source.storage_metrics.memory_hit();
    }
    if cached.is_none()
        && let Some(key) = &cache_key
    {
        if let Ok(Some(mut response)) = Cache::default().get(key.clone(), false).await {
            let length = response
                .headers()
                .get("Content-Length")
                .ok()
                .flatten()
                .and_then(|s| s.parse::<usize>().ok());
            if response.status_code() == 200
                && length.is_some_and(|n| n <= slot_resolution::MAX_RESOLUTION_BYTES)
            {
                if let Ok(bytes) = response.bytes().await {
                    if Some(bytes.len()) == length {
                        source.storage_metrics.edge_hit();
                        cached = Some(bytes);
                    }
                }
            }
        }
    }
    let from_cache = cached.is_some();
    let bytes = if let Some(bytes) = cached {
        bytes
    } else {
        source.backend_read.mark();
        source.storage_metrics.attempt_get(StorageBackend::R2);
        let object = config
            .bucket
            .get(&key)
            .execute()
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("admitted resolution object is missing for slot {slot}"))?;
        source.record_elapsed(
            "resolution_headers",
            load_started,
            object.size(),
            "owner_r2",
            Some(200),
        );
        let size = usize::try_from(object.size()).map_err(|_| "resolution object is too large")?;
        if !(slot_resolution::HEADER_LEN..=slot_resolution::MAX_RESOLUTION_BYTES).contains(&size) {
            return Err("resolution object length is out of bounds".into());
        }
        let body_started = now_ms();
        let bytes = object
            .body()
            .ok_or("resolution object has no body")?
            .bytes()
            .await
            .map_err(|e| e.to_string())?;
        source.record_elapsed(
            "resolution_body",
            body_started,
            bytes.len() as u64,
            "owner_r2",
            Some(200),
        );
        source
            .storage_metrics
            .complete_get(StorageBackend::R2, bytes.len(), bytes.len() == size);
        if bytes.len() != size {
            return Err("resolution body length differs from its object".into());
        }
        bytes
    };
    let decode_started = now_ms();
    let payload = slot_resolution::payload_for_digest(&bytes)?;
    let digest = native_hash::sha256(payload).await?;
    let resolution = slot_resolution::decode_checked_with_payload_digest(&bytes, digest)?;
    resolution.validate(&source.archive_prefix, &config.generation, slot)?;
    // Admit only complete, checked immutable objects. Larger resolution
    // entries still share the existing four-MiB LRU budget.
    if let Some(key) = cache_key {
        if !from_cache {
            source.cache_bytes(key.clone(), &bytes);
        }
        if bytes.len() <= 256 * 1024 {
            ARCHIVE_BYTES.with(|cache| cache.borrow_mut().insert(key, bytes.clone()));
        }
    }
    source.record_elapsed(
        "resolution_decode",
        decode_started,
        bytes.len() as u64,
        "wincode",
        None,
    );
    source.record_elapsed(
        "resolution_total",
        load_started,
        bytes.len() as u64,
        "owner_r2",
        None,
    );
    Ok((resolution, bytes))
}

pub(super) async fn fetch_block(
    source: &WorkerSource,
    slot: u64,
) -> std::result::Result<Option<FetchedHotBlock>, String> {
    let started = now_ms();
    let (resolution, _) = load(source, slot).await?;
    fetch_resolved_block(source, slot, resolution, started, "three_gets")
        .await
        .map(Some)
}

/// Use a resolution already admitted by the caller, without an owner-index GET.
/// The caller owns trusted generation/publication admission; this helper checks
/// the source prefix, slot and range bounds again before starting either read.
pub(super) async fn fetch_checked_block(
    source: &WorkerSource,
    slot: u64,
    resolution: CheckedResolution,
) -> std::result::Result<FetchedHotBlock, String> {
    fetch_resolved_block(source, slot, resolution, now_ms(), "broker_two_ranges").await
}

async fn fetch_resolved_block(
    source: &WorkerSource,
    slot: u64,
    resolution: CheckedResolution,
    started: f64,
    detail: &str,
) -> std::result::Result<FetchedHotBlock, String> {
    let locator = resolution.locator();
    resolution.validate(&source.archive_prefix, &locator.generation, slot)?;
    let (hot, signatures) = read_block_sources(source, slot, &locator).await?;
    assemble_fetched_block(
        source, started, &locator, resolution, hot, signatures, detail,
    )
}

/// A client hint removes the serial resolution wait, not a storage read.
/// The trusted resolution still supplies every dictionary and signature count.
pub(super) async fn fetch_block_with_hint(
    source: &WorkerSource,
    slot: u64,
    token: &str,
) -> std::result::Result<Option<FetchedHotBlock>, String> {
    let started = now_ms();
    let config = source
        .resolution
        .as_ref()
        .ok_or("resolution is not configured")?;
    // No future that can read storage is polled until MAC, bounds, generation,
    // source prefix and slot admission have all passed.
    let locator = config.verify_token(token, &source.archive_prefix, slot)?;
    let ((resolution, _), (hot, signatures)) = future::try_join(
        load(source, slot),
        read_block_sources(source, slot, &locator),
    )
    .await?;
    assemble_fetched_block(
        source,
        started,
        &locator,
        resolution,
        hot,
        signatures,
        "hinted_three_parallel_gets",
    )
    .map(Some)
}

struct DecodedHotBlock {
    block: ArchiveV2HotBlockBlob,
    decoded_len: usize,
}

struct FoundationHot {
    checked: CheckedResolution,
    hot: DecodedHotBlock,
    compressed: Vec<u8>,
}

/// Resolve IDs while the concurrent signature request remains in flight.
/// The same hot bytes are decoded once and reused by the final renderer.
async fn read_foundation_hot(
    source: &WorkerSource,
    slot: u64,
    route: &PendingLocatorV1,
    retain_compressed: bool,
) -> std::result::Result<FoundationHot, String> {
    let config = source
        .foundation_lookup
        .as_ref()
        .ok_or("Foundation is not configured")?;
    route.validate(&source.archive_prefix, config.generation(), slot)?;
    let row = route.hot.into();
    let block_path = epoch_file(&source.archive_prefix, route.epoch, ARCHIVE_V2_BLOCKS_FILE);
    let mut compressed = pinned_bytes(
        source,
        &block_path,
        route.hot.compressed_offset,
        route.hot.compressed_len as usize,
        &route.blocks,
    )
    .await?;
    let hot_sha256 = hex_lower(&native_hash::sha256(&compressed).await?);
    let (decoded, block) = stored::decode_block(source, slot, &row, &compressed)?;
    let decoded_len = decoded.len();
    drop(decoded);
    if !retain_compressed {
        compressed = Vec::new();
    }
    let started = now_ms();
    let references =
        crate::slot_references::collect(&block, &row, route.message_schema, route.metadata_schema)?;
    source.record_elapsed(
        "foundation_collect_ids",
        started,
        0,
        "complete_typed_references",
        None,
    );
    let request = ResolveRequestV1 {
        version: 1,
        source: route.clone(),
        hot_sha256,
        references,
    };
    source.backend_read.mark();
    source.storage_metrics.attempt_foundation_resolve_http();
    let checked = match config.resolve_ids(source, &request).await? {
        foundation_first::ResolveOutcome::Resolved { checked, .. } => checked,
        foundation_first::ResolveOutcome::Unavailable(reason) => {
            return Err(format!("Foundation resolution unavailable: {reason:?}"));
        }
        foundation_first::ResolveOutcome::TransportFailure(reason) => {
            return Err(format!(
                "Foundation resolution transport failed: {reason:?}"
            ));
        }
    };
    Ok(FoundationHot {
        checked,
        hot: DecodedHotBlock { block, decoded_len },
        compressed,
    })
}

pub(super) async fn fetch_foundation_block(
    source: &WorkerSource,
    slot: u64,
    route: PendingLocatorV1,
) -> std::result::Result<FetchedHotBlock, String> {
    let config = source
        .foundation_lookup
        .as_ref()
        .ok_or("Foundation is not configured")?;
    route.validate(&source.archive_prefix, config.generation(), slot)?;
    let started = now_ms();
    let sig_path = epoch_file(
        &source.archive_prefix,
        route.epoch,
        blockzilla_archive_v2::ARCHIVE_V2_SIGNATURES_FILE,
    );
    let (resolved, signatures) = future::try_join(
        read_foundation_hot(source, slot, &route, false),
        pinned_bytes(
            source,
            &sig_path,
            route
                .hot
                .first_signature_ordinal
                .checked_mul(64)
                .ok_or("signature offset overflows")?,
            route.hot.signature_count as usize * 64,
            &route.signatures,
        ),
    )
    .await?;
    let locator = resolved.checked.locator();
    assemble_fetched_block(
        source,
        started,
        &locator,
        resolved.checked,
        resolved.hot,
        signatures,
        "r2_then_foundation_ids",
    )
}

pub(super) async fn foundation_archive_binary_response(
    source: &WorkerSource,
    slot: u64,
    route: PendingLocatorV1,
    ctx: &Rc<worker::Context>,
    metrics: &Option<AnalyticsEngineDataset>,
    key: &RpcApiKeyRecord,
) -> std::result::Result<Response, String> {
    foundation_archive_binary_response_for_hash(source, slot, route, ctx, metrics, key, None).await
}

pub(super) async fn foundation_archive_binary_response_for_hash(
    source: &WorkerSource,
    slot: u64,
    route: PendingLocatorV1,
    ctx: &Rc<worker::Context>,
    metrics: &Option<AnalyticsEngineDataset>,
    key: &RpcApiKeyRecord,
    expected_hash: Option<[u8; 32]>,
) -> std::result::Result<Response, String> {
    let config = source
        .foundation_lookup
        .as_ref()
        .ok_or("Foundation is not configured")?;
    route.validate(&source.archive_prefix, config.generation(), slot)?;
    if route.message_schema == 0 && route.metadata_schema == 0 && config.binary_uses_raw_block() {
        return foundation_native_binary_response(
            source,
            slot,
            route,
            ctx,
            metrics,
            key,
            expected_hash,
        )
        .await;
    }
    let sig_path = epoch_file(
        &source.archive_prefix,
        route.epoch,
        blockzilla_archive_v2::ARCHIVE_V2_SIGNATURES_FILE,
    );
    let sig_len = route.hot.signature_count as usize * 64;
    let (resolved, sig) =
        future::try_join(read_foundation_hot(source, slot, &route, true), async {
            if sig_len == 0 {
                Ok(NativeRange {
                    response: Response::from_body(ResponseBody::Empty)
                        .map_err(|e| e.to_string())?,
                    origin: false,
                })
            } else {
                pinned_native_response(
                    source,
                    &sig_path,
                    route
                        .hot
                        .first_signature_ordinal
                        .checked_mul(64)
                        .ok_or("signature offset overflows")?,
                    sig_len,
                    &route.signatures,
                    ctx,
                    metrics,
                    key,
                )
                .await
            }
        })
        .await?;
    let FoundationHot {
        checked,
        hot,
        compressed,
    } = resolved;
    if expected_hash.is_some_and(|expected| expected != checked.locator_ref().blockhash) {
        native_hash::cancel_response(sig.response);
        return Err("archive blockhash differs from requested blockhash".into());
    }
    let (encoding, hot_bytes) = if route.message_schema == 0 && route.metadata_schema == 0 {
        drop(hot);
        (1u8, compressed)
    } else {
        drop(compressed);
        (
            0u8,
            stored::normalize_historical_hot_block(
                hot.block,
                (
                    if route.message_schema == 0 {
                        MessageSchema::Current
                    } else {
                        MessageSchema::May24
                    },
                    if route.metadata_schema == 0 {
                        MetadataSchema::Current
                    } else {
                        MetadataSchema::Legacy
                    },
                ),
            )?,
        )
    };
    let hot_len = hot_bytes.len();
    let mut prefix = Vec::new();
    leb(&mut prefix, 1);
    leb(&mut prefix, slot);
    prefix.push(encoding);
    leb(&mut prefix, hot_len as u64);
    let mut middle = vec![0, 1];
    leb(&mut middle, checked.access_len()? as u64);
    middle.extend_from_slice(checked.access_prefix());
    let trailer = checked.access_suffix().to_vec();
    // Convert the owned hot buffer once to a native Response stream. The
    // signatures never cross the WASM boundary, and the join retains native
    // backpressure. A Rust buffered ResponseBody is not a native stream.
    let native_hot: worker::web_sys::Response = Response::from_bytes(hot_bytes)
        .map_err(|e| e.to_string())?
        .into();
    let hot_body =
        ResponseBody::Stream(native_hot.body().ok_or("hot buffer has no native stream")?);
    let (_, sig_body) = sig.response.into_parts();
    let parts = super::stream_parts::response_and_completion_from_parts(
        prefix,
        hot_body,
        hot_len as u64,
        middle,
        sig_body,
        sig_len as u64,
        trailer,
    )
    .map_err(|e| e.to_string())?;
    let mut response = parts.response;
    add_profile_headers(response.headers(), source.profile.as_ref()).map_err(|e| e.to_string())?;
    for (name, value) in [
        (
            "Content-Type",
            "application/vnd.blockzilla.get-block-bundle.wincode",
        ),
        ("Cache-Control", BLOCK_CACHE_CONTROL),
        ("X-Blockzilla-Body", "hot-buffered-signatures-native-stream"),
        ("X-Blockzilla-Storage-Bytes-Mode", "streamed-completion"),
        ("X-Blockzilla-Resolution-Generation", config.generation()),
    ] {
        response
            .headers_mut()
            .set(name, value)
            .map_err(|e| e.to_string())?;
    }
    response
        .headers_mut()
        .set(
            "X-Blockzilla-Origin-Expected-Bytes",
            &(u64::from(sig.origin) * sig_len as u64).to_string(),
        )
        .map_err(|e| e.to_string())?;
    Ok(response)
}

/// The current-schema binary path never decodes or copies hot bytes through
/// WASM. A native clone is hashed, another goes to Foundation for resolution,
/// and the original joins the original signature stream for the client.
async fn foundation_native_binary_response(
    source: &WorkerSource,
    slot: u64,
    route: PendingLocatorV1,
    ctx: &Rc<worker::Context>,
    metrics: &Option<AnalyticsEngineDataset>,
    key: &RpcApiKeyRecord,
    expected_hash: Option<[u8; 32]>,
) -> std::result::Result<Response, String> {
    let config = source
        .foundation_lookup
        .as_ref()
        .ok_or("Foundation is not configured")?;
    let hot_path = epoch_file(&source.archive_prefix, route.epoch, ARCHIVE_V2_BLOCKS_FILE);
    let sig_path = epoch_file(
        &source.archive_prefix,
        route.epoch,
        blockzilla_archive_v2::ARCHIVE_V2_SIGNATURES_FILE,
    );
    let hot_len = route.hot.compressed_len as usize;
    let sig_len = route.hot.signature_count as usize * 64;
    let (mut hot, sig) = future::try_join(
        pinned_native_response(
            source,
            &hot_path,
            route.hot.compressed_offset,
            hot_len,
            &route.blocks,
            ctx,
            metrics,
            key,
        ),
        async {
            if sig_len == 0 {
                Ok(NativeRange {
                    response: Response::from_body(ResponseBody::Empty)
                        .map_err(|e| e.to_string())?,
                    origin: false,
                })
            } else {
                pinned_native_response(
                    source,
                    &sig_path,
                    route
                        .hot
                        .first_signature_ordinal
                        .checked_mul(64)
                        .ok_or("signature offset overflows")?,
                    sig_len,
                    &route.signatures,
                    ctx,
                    metrics,
                    key,
                )
                .await
            }
        },
    )
    .await?;
    let hash_started = now_ms();
    let digest =
        match native_hash::sha256_response(&mut hot.response, hot_len, config.body_timeout_ms())
            .await
        {
            Ok(digest) => digest,
            Err(error) => {
                native_hash::cancel_response(hot.response);
                native_hash::cancel_response(sig.response);
                return Err(error);
            }
        };
    source.record_elapsed(
        "foundation_native_hot_hash",
        hash_started,
        hot_len as u64,
        "native_js_bytes_only",
        None,
    );
    let (_, request_body) = hot
        .response
        .cloned()
        .map_err(|e| e.to_string())?
        .into_parts();
    source.backend_read.mark();
    source.storage_metrics.attempt_foundation_resolve_http();
    let resolved = config
        .resolve_block(source, &route, &hex_lower(&digest), request_body)
        .await;
    let checked = if let Ok(foundation_first::ResolveOutcome::Resolved { checked, .. }) = resolved {
        checked
    } else {
        native_hash::cancel_response(hot.response);
        native_hash::cancel_response(sig.response);
        return Err(match resolved {
            Err(error) => error,
            Ok(foundation_first::ResolveOutcome::Unavailable(reason)) => {
                format!("Foundation block resolution unavailable: {reason:?}")
            }
            Ok(foundation_first::ResolveOutcome::TransportFailure(reason)) => {
                format!("Foundation block resolution transport failed: {reason:?}")
            }
            _ => unreachable!(),
        });
    };
    if expected_hash.is_some_and(|expected| expected != checked.locator_ref().blockhash) {
        native_hash::cancel_response(hot.response);
        native_hash::cancel_response(sig.response);
        return Err("archive blockhash differs from requested blockhash".into());
    }
    if checked.signature_bytes()? != sig_len {
        return Err("Foundation signature size differs from source row".into());
    }
    let mut prefix = Vec::new();
    leb(&mut prefix, 1);
    leb(&mut prefix, slot);
    prefix.push(1);
    leb(&mut prefix, hot_len as u64);
    let mut middle = vec![0, 1];
    leb(&mut middle, checked.access_len()? as u64);
    middle.extend_from_slice(checked.access_prefix());
    let trailer = checked.access_suffix().to_vec();
    let (_, hot_body) = hot.response.into_parts();
    let (_, sig_body) = sig.response.into_parts();
    let parts = super::stream_parts::response_and_completion_from_parts(
        prefix,
        hot_body,
        hot_len as u64,
        middle,
        sig_body,
        sig_len as u64,
        trailer,
    )
    .map_err(|e| e.to_string())?;
    let mut response = parts.response;
    for (name, value) in [
        (
            "Content-Type",
            "application/vnd.blockzilla.get-block-bundle.wincode",
        ),
        ("Cache-Control", BLOCK_CACHE_CONTROL),
        ("X-Blockzilla-Body", "native-stream"),
        ("X-Blockzilla-Storage-Bytes-Mode", "streamed-completion"),
        ("X-Blockzilla-Foundation-Resolve-Mode", "block"),
        ("X-Blockzilla-Resolution-Generation", config.generation()),
    ] {
        response
            .headers_mut()
            .set(name, value)
            .map_err(|e| e.to_string())?;
    }
    response
        .headers_mut()
        .set(
            "X-Blockzilla-Origin-Expected-Bytes",
            &(u64::from(hot.origin) * hot_len as u64 + u64::from(sig.origin) * sig_len as u64)
                .to_string(),
        )
        .map_err(|e| e.to_string())?;
    add_profile_headers(response.headers(), source.profile.as_ref()).map_err(|e| e.to_string())?;
    Ok(response)
}

async fn read_block_sources(
    source: &WorkerSource,
    slot: u64,
    locator: &LocatorV1,
) -> std::result::Result<(DecodedHotBlock, Vec<u8>), String> {
    let row: ArchiveV2HotBlockIndexRow = locator.hot.into();
    let block_path = epoch_file(
        &source.archive_prefix,
        locator.epoch,
        ARCHIVE_V2_BLOCKS_FILE,
    );
    let sig_path = epoch_file(
        &source.archive_prefix,
        locator.epoch,
        blockzilla_archive_v2::ARCHIVE_V2_SIGNATURES_FILE,
    );
    let ranges_started = now_ms();
    let (hot, signatures) = future::try_join(
        async {
            let compressed = pinned_bytes(
                source,
                &block_path,
                row.compressed_offset,
                row.compressed_len as usize,
                &locator.blocks,
            )
            .await?;
            // Decode as soon as the hot range is ready. The signature and
            // hinted resolution I/O can remain in flight during this work.
            let (block_bytes, block) = stored::decode_block(source, slot, &row, &compressed)?;
            if block.header.parent_slot != locator.parent_slot {
                return Err("hot block parent differs from resolution".into());
            }
            // The owned parsed block is sufficient. Do not retain compressed
            // or decompressed copies while another branch is still pending.
            Ok(DecodedHotBlock {
                block,
                decoded_len: block_bytes.len(),
            })
        },
        pinned_bytes(
            source,
            &sig_path,
            locator.signature_offset()?,
            locator.signature_bytes()?,
            &locator.signatures,
        ),
    )
    .await?;
    source.record_elapsed(
        "source_ranges_parallel",
        ranges_started,
        u64::from(row.compressed_len) + signatures.len() as u64,
        "max_parallel_branches_including_hot_decode",
        None,
    );
    Ok((hot, signatures))
}

fn require_matching_locator(
    trusted: &LocatorV1,
    signed: &LocatorV1,
) -> std::result::Result<(), String> {
    if trusted != signed {
        return Err("stored resolution differs from signed locator hint".into());
    }
    Ok(())
}

fn assemble_fetched_block(
    source: &WorkerSource,
    started: f64,
    locator: &LocatorV1,
    resolution: CheckedResolution,
    hot: DecodedHotBlock,
    signatures: Vec<u8>,
    detail: &str,
) -> std::result::Result<FetchedHotBlock, String> {
    // Compare the complete descriptor, including schema, parent hashes,
    // offsets and both object identities, before any result can be rendered.
    require_matching_locator(resolution.locator_ref(), locator)?;
    let row: ArchiveV2HotBlockIndexRow = locator.hot.into();
    let access_started = now_ms();
    let access = resolution.into_access(signatures)?;
    validate_access_blob(&access, &row)?;
    if hot
        .block
        .tx_rows
        .iter()
        .map(|tx| tx.signature_count)
        .ne(access.signature_counts.iter().copied())
    {
        return Err("hot transaction signature counts differ from resolution".into());
    }
    source.record_elapsed(
        "resolution_access_decode",
        access_started,
        0,
        "wincode",
        None,
    );
    source.record_elapsed(
        "resolution_fetch_total",
        started,
        row.uncompressed_len as u64,
        detail,
        None,
    );
    Ok(FetchedHotBlock {
        epoch: locator.epoch,
        index_row: ArchiveV2GetBlockIndexRow {
            block_offset: row.compressed_offset,
            block_len: row.compressed_len,
            access_offset: 0,
            access_len: 0,
        },
        row,
        decoded_len: hot.decoded_len,
        block: hot.block,
        access: Some(FetchedAccess::Full(access)),
        message_schema: if locator.message_schema == 0 {
            MessageSchema::Current
        } else {
            MessageSchema::May24
        },
        metadata_schema: if locator.metadata_schema == 0 {
            MetadataSchema::Current
        } else {
            MetadataSchema::Legacy
        },
    })
}

#[cfg(test)]
mod hinted_fetch_tests {
    use super::*;

    fn locator() -> LocatorV1 {
        LocatorV1 {
            version: slot_resolution::VERSION,
            source_prefix: "compact-v2/hint-test".into(),
            generation: "hint-test-v1".into(),
            epoch: 0,
            hot: slot_resolution::ResolutionHotRow {
                block_id: 1,
                slot: 10,
                compressed_offset: 100,
                compressed_len: 1000,
                uncompressed_len: 2000,
                tx_count: 2,
                first_tx_ordinal: 5,
                first_signature_ordinal: 1,
                signature_count: 2,
            },
            parent_slot: 9,
            blockhash: [3; 32],
            previous_blockhash: [4; 32],
            message_schema: 0,
            metadata_schema: 0,
            blocks: SourceObjectIdentity {
                length: 8192,
                etag: "\"12345678901234567890123456789012\"".into(),
            },
            signatures: SourceObjectIdentity {
                length: 256,
                etag: "\"abcdefabcdefabcdefabcdefabcdefab\"".into(),
            },
        }
    }

    #[test]
    fn accepts_only_the_complete_stored_locator_for_a_json_hint() {
        let trusted = locator();
        trusted
            .validate("compact-v2/hint-test", "hint-test-v1", 10)
            .unwrap();
        assert!(require_matching_locator(&trusted, &trusted.clone()).is_ok());
        let changes: [(&str, fn(&mut LocatorV1)); 12] = [
            ("block offset", |l| l.hot.compressed_offset += 1),
            ("signature offset", |l| l.hot.first_signature_ordinal += 1),
            ("signature count", |l| l.hot.signature_count += 1),
            ("transaction count", |l| l.hot.tx_count += 1),
            ("block object ETag", |l| {
                l.blocks.etag = l.signatures.etag.clone()
            }),
            ("signature object length", |l| l.signatures.length += 64),
            ("previous blockhash", |l| l.previous_blockhash[0] ^= 1),
            ("blockhash", |l| l.blockhash[0] ^= 1),
            ("parent", |l| l.parent_slot -= 1),
            ("message schema", |l| l.message_schema = 1),
            ("metadata schema", |l| l.metadata_schema = 1),
            ("generation", |l| l.generation.push_str("-changed")),
        ];
        for (name, change) in changes {
            let mut signed = trusted.clone();
            change(&mut signed);
            assert!(
                require_matching_locator(&trusted, &signed).is_err(),
                "{name}"
            );
        }
    }
}

async fn pinned_bytes(
    source: &WorkerSource,
    path: &str,
    offset: u64,
    len: usize,
    identity: &SourceObjectIdentity,
) -> std::result::Result<Vec<u8>, String> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let key = pinned_cache_key(source, path, offset, len, identity);
    if let Some(key) = &key {
        if let Some(bytes) = source.cached_bytes(key, len).await {
            return Ok(bytes);
        }
    }
    let mut response = pinned_origin_response(source, path, offset, len, identity).await?;
    let body_started = now_ms();
    let bytes = response.bytes().await.map_err(|e| e.to_string())?;
    source.record_elapsed(
        if path.ends_with("signatures.bin") {
            "signature_body"
        } else {
            "block_body"
        },
        body_started,
        bytes.len() as u64,
        "source_range",
        Some(206),
    );
    source
        .storage_metrics
        .complete_get(backend_kind(source), bytes.len(), bytes.len() == len);
    if bytes.len() != len {
        return Err("pinned source returned an incorrect body length".into());
    }
    if let Some(key) = key {
        source.cache_bytes(key, &bytes);
    }
    Ok(bytes)
}

fn backend_kind(source: &WorkerSource) -> StorageBackend {
    if source.native_reader.is_some() {
        return StorageBackend::FoundationR2;
    }
    match source.backend {
        ArchiveBackend::R2 { .. } => StorageBackend::R2,
        ArchiveBackend::S3(_) => StorageBackend::S3,
    }
}

fn pinned_cache_key(
    source: &WorkerSource,
    path: &str,
    offset: u64,
    len: usize,
    identity: &SourceObjectIdentity,
) -> Option<String> {
    if source
        .profile
        .as_ref()
        .is_some_and(ProfileHandle::source_ranges_only)
    {
        return None;
    }
    source.range_cache_key(
        &format!("{path}\0{}\0{}", identity.etag, identity.length),
        offset,
        len,
    )
}

struct NativeRange {
    response: Response,
    origin: bool,
}

async fn pinned_native_response(
    source: &WorkerSource,
    path: &str,
    offset: u64,
    len: usize,
    identity: &SourceObjectIdentity,
    ctx: &Rc<worker::Context>,
    metrics: &Option<AnalyticsEngineDataset>,
    key_record: &RpcApiKeyRecord,
) -> std::result::Result<NativeRange, String> {
    ensure_js_safe_range(offset, len)?;
    identity.validate()?;
    if len == 0
        || len > MAX_ARCHIVE_RANGE_BYTES
        || offset
            .checked_add(len as u64)
            .is_none_or(|end| end > identity.length)
    {
        return Err("pinned source range is invalid".into());
    }
    let key = pinned_cache_key(source, path, offset, len, identity);
    if let Some(key) = &key {
        if let Ok(Some(response)) = Cache::default().get(key.clone(), false).await {
            let length = response
                .headers()
                .get("Content-Length")
                .ok()
                .flatten()
                .and_then(|s| s.parse::<usize>().ok());
            if response.status_code() == 200 && length == Some(len) {
                source.storage_metrics.edge_hit();
                return Ok(NativeRange {
                    response,
                    origin: false,
                });
            }
        }
    }
    let response = pinned_origin_response(source, path, offset, len, identity).await?;
    let (_, body) = response.into_parts();
    // Validate EOF and length before either branch can commit a cache entry.
    // All source chunks remain native JS streams, including cache writes.
    let parts = super::stream_parts::response_and_completion_from_parts(
        Vec::new(),
        body,
        len as u64,
        Vec::new(),
        ResponseBody::Empty,
        0,
        Vec::new(),
    )
    .map_err(|e| e.to_string())?;
    record_origin_completion(source, parts.completion, ctx, metrics, key_record);
    let mut response = parts.response;
    response
        .headers_mut()
        .set("Cache-Control", BLOCK_CACHE_CONTROL)
        .map_err(|e| e.to_string())?;
    // Cache.put cannot store 206 responses. This synthetic 200 contains one
    // exact immutable window under a private generation/ETag/range key.
    if len <= MAX_CACHED_RANGE_BYTES
        && let (Some(key), Some(cache)) = (key, source.cache.as_ref())
    {
        let queued = source.cache_write_bytes.get().saturating_add(len);
        if queued <= 8 * 1024 * 1024 {
            if let Ok(cached) = response.cloned() {
                source.cache_write_bytes.set(queued);
                cache.context.wait_until(async move {
                    if let Err(error) = Cache::default().put(key, cached).await {
                        console_error!("native range cache write failed: {error}");
                    }
                });
            }
        }
    }
    Ok(NativeRange {
        response,
        origin: true,
    })
}

fn record_origin_completion(
    source: &WorkerSource,
    completion: js_sys::Promise,
    ctx: &Rc<worker::Context>,
    metrics: &Option<AnalyticsEngineDataset>,
    key: &RpcApiKeyRecord,
) {
    let backend = backend_kind(source);
    let dataset = metrics.clone();
    let key_id = key.key_id.clone();
    let customer_id = key.customer_id.clone();
    // Register before another range can fail its headers. A cache fill may
    // finish even if the final client response fails or is cancelled.
    ctx.wait_until(async move {
        let Ok(value) = wasm_bindgen_futures::JsFuture::from(completion).await else {
            console_error!("native source stream failed or was cancelled");
            return;
        };
        let Some(dataset) = dataset else {
            return;
        };
        let bytes = js_sys::Reflect::get(&value, &JsValue::from_str("hotBytes"))
            .ok()
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        // The main receipt owns request, billing and attempt counters.
        let mut doubles = [0.0; 20];
        match backend {
            StorageBackend::R2 => {
                doubles[7] = bytes;
                doubles[13] = 1.0;
            }
            StorageBackend::S3 => {
                doubles[10] = bytes;
                doubles[15] = 1.0;
            }
            StorageBackend::FoundationR2 => {
                doubles[18] = bytes;
                doubles[19] = 1.0;
            }
        }
        let _ = AnalyticsEngineDataPointBuilder::new()
            .indexes([key_id.as_str()])
            .blobs([
                customer_id.as_str(),
                "getBlock",
                "source_range_complete",
                "continuation",
                "http_binary",
            ])
            .doubles(doubles)
            .write_to(&dataset);
    });
}

async fn pinned_origin_response(
    source: &WorkerSource,
    path: &str,
    offset: u64,
    len: usize,
    identity: &SourceObjectIdentity,
) -> std::result::Result<Response, String> {
    let started = now_ms();
    ensure_js_safe_range(offset, len)?;
    if len == 0
        || len > MAX_ARCHIVE_RANGE_BYTES
        || offset
            .checked_add(len as u64)
            .is_none_or(|end| end > identity.length)
    {
        return Err("pinned source range is invalid".into());
    }
    identity.validate()?;
    if let Some(reader) = &source.native_reader {
        return reader
            .fetch_range(source, path, offset, len, identity)
            .await;
    }
    source.backend_read.mark();
    source.storage_metrics.attempt_get(backend_kind(source));
    match &source.backend {
        ArchiveBackend::S3(s3) => {
            let range = s3_range_header(offset, len)?;
            let (url, headers) = s3.signed_get(path, Some(&range))?;
            headers
                .set("If-Match", &identity.etag)
                .map_err(|e| e.to_string())?;
            let request = request_with_headers(&url, headers).map_err(|e| e.to_string())?;
            let response = Fetch::Request(request)
                .send()
                .await
                .map_err(|e| e.to_string())?;
            let upstream_colo = response
                .headers()
                .get("cf-ray")
                .ok()
                .flatten()
                .and_then(|ray| ray.rsplit_once('-').map(|(_, colo)| colo.to_owned()))
                .unwrap_or_default();
            source.record_elapsed(
                if path.ends_with("signatures.bin") {
                    "signature_headers"
                } else {
                    "block_headers"
                },
                started,
                len as u64,
                format!("s3_collector={upstream_colo}"),
                Some(response.status_code()),
            );
            if response.status_code() != 206 {
                return Err(format!(
                    "pinned S3 range returned HTTP {}",
                    response.status_code()
                ));
            }
            let headers = response.headers();
            if headers.get("ETag").map_err(|e| e.to_string())?.as_deref()
                != Some(identity.etag.as_str())
                || headers
                    .get("Content-Length")
                    .map_err(|e| e.to_string())?
                    .and_then(|s| s.parse::<usize>().ok())
                    != Some(len)
            {
                return Err("pinned S3 ETag or range length differs".into());
            }
            let content_range = headers
                .get("Content-Range")
                .map_err(|e| e.to_string())?
                .ok_or("missing pinned Content-Range")?;
            validate_content_range(&content_range, offset, len)?;
            if content_range
                .rsplit_once('/')
                .and_then(|(_, s)| s.parse::<u64>().ok())
                != Some(identity.length)
            {
                return Err("pinned S3 object length differs".into());
            }
            Ok(response)
        }
        ArchiveBackend::R2 { bucket, .. } => {
            let object = bucket
                .get(path)
                .range(R2Range::OffsetWithLength {
                    offset,
                    length: len as u64,
                })
                .only_if(worker::Conditional {
                    etag_matches: Some(identity.etag.trim_matches('"').to_string()),
                    ..Default::default()
                })
                .execute()
                .await
                .map_err(|e| e.to_string())?
                .ok_or("pinned R2 object is missing")?;
            source.record_elapsed(
                if path.ends_with("signatures.bin") {
                    "signature_headers"
                } else {
                    "block_headers"
                },
                started,
                len as u64,
                "r2_binding",
                Some(206),
            );
            if object.http_etag() != identity.etag || object.size() != identity.length {
                return Err("pinned R2 ETag or object length differs".into());
            }
            Response::from_body(
                object
                    .body()
                    .ok_or("pinned R2 object has no body")?
                    .response_body()
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())
        }
    }
}

fn leb(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 127) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 128
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

pub(super) async fn binary_response(
    source: &WorkerSource,
    slot: u64,
    include_access: bool,
    token: Option<&str>,
    ctx: &Rc<worker::Context>,
    metrics: &Option<AnalyticsEngineDataset>,
    key: &RpcApiKeyRecord,
) -> std::result::Result<Response, String> {
    let config = source
        .resolution
        .as_ref()
        .ok_or("resolution is not configured")?;
    let (locator, resolution) = if let Some(token) = token {
        (
            config.verify_token(token, &source.archive_prefix, slot)?,
            None,
        )
    } else {
        let (resolution, _) = load(source, slot).await?;
        (resolution.locator(), Some(resolution))
    };
    binary_response_from_descriptor(
        source,
        slot,
        include_access,
        token.is_some(),
        locator,
        resolution,
        &config.generation,
        ctx,
        metrics,
        key,
    )
    .await
}

/// Full V1 output from an already checked resolution. Both source windows are
/// native streams and start together; no resolution object is read here.
pub(super) async fn binary_response_checked(
    source: &WorkerSource,
    slot: u64,
    resolution: CheckedResolution,
    ctx: &Rc<worker::Context>,
    metrics: &Option<AnalyticsEngineDataset>,
    key: &RpcApiKeyRecord,
) -> std::result::Result<Response, String> {
    let locator = resolution.locator();
    let generation = locator.generation.clone();
    resolution.validate(&source.archive_prefix, &generation, slot)?;
    binary_response_from_descriptor(
        source,
        slot,
        true,
        false,
        locator,
        Some(resolution),
        &generation,
        ctx,
        metrics,
        key,
    )
    .await
}

async fn binary_response_from_descriptor(
    source: &WorkerSource,
    slot: u64,
    include_access: bool,
    client_parts: bool,
    locator: LocatorV1,
    resolution: Option<CheckedResolution>,
    generation: &str,
    ctx: &Rc<worker::Context>,
    metrics: &Option<AnalyticsEngineDataset>,
    key: &RpcApiKeyRecord,
) -> std::result::Result<Response, String> {
    locator.validate(&source.archive_prefix, generation, slot)?;
    if let Some(resolution) = &resolution {
        require_matching_locator(resolution.locator_ref(), &locator)?;
    }
    if !client_parts
        && include_access
        && (locator.message_schema != 0 || locator.metadata_schema != 0)
    {
        return Err("historical streamed binary requires a client resolution index".into());
    }
    let block_path = epoch_file(
        &source.archive_prefix,
        locator.epoch,
        ARCHIVE_V2_BLOCKS_FILE,
    );
    let sig_path = epoch_file(
        &source.archive_prefix,
        locator.epoch,
        blockzilla_archive_v2::ARCHIVE_V2_SIGNATURES_FILE,
    );
    let need_signatures = include_access || client_parts;
    let signature_len = if need_signatures {
        locator.signature_bytes()?
    } else {
        0
    };
    let sig_offset = locator.signature_offset()?;
    let (hot, sig) = future::try_join(
        pinned_native_response(
            source,
            &block_path,
            locator.hot.compressed_offset,
            locator.hot.compressed_len as usize,
            &locator.blocks,
            ctx,
            metrics,
            key,
        ),
        async {
            if signature_len == 0 {
                Ok(NativeRange {
                    response: Response::from_body(ResponseBody::Empty)
                        .map_err(|e| e.to_string())?,
                    origin: false,
                })
            } else {
                pinned_native_response(
                    source,
                    &sig_path,
                    sig_offset,
                    signature_len,
                    &locator.signatures,
                    ctx,
                    metrics,
                    key,
                )
                .await
            }
        },
    )
    .await?;
    let hot_origin = hot.origin;
    let sig_origin = sig.origin;
    let (_, hot_body) = hot.response.into_parts();
    let (_, sig_body) = sig.response.into_parts();
    let mut prefix = Vec::new();
    let mut middle = Vec::new();
    let mut trailer = Vec::new();
    let content_type;
    if client_parts {
        // V2 client-parts frame: magic, slot, hot length, signature length,
        // and resolution descriptor digest, followed by the two native bodies.
        prefix.extend_from_slice(b"BZPART2!");
        prefix.extend_from_slice(&slot.to_le_bytes());
        prefix.extend_from_slice(&(locator.hot.compressed_len as u64).to_le_bytes());
        prefix.extend_from_slice(&(signature_len as u64).to_le_bytes());
        let descriptor = wincode::config::serialize(&locator, wincode_leb128_config())
            .map_err(|e| e.to_string())?;
        prefix.extend_from_slice(&Sha256::digest(&descriptor));
        content_type = "application/vnd.blockzilla.get-block-parts.v2";
    } else {
        leb(&mut prefix, 1);
        leb(&mut prefix, slot);
        prefix.push(1);
        leb(&mut prefix, locator.hot.compressed_len as u64);
        middle.push(0);
        middle.push(u8::from(include_access));
        if include_access {
            let resolution = resolution.as_ref().ok_or("missing resolution")?;
            leb(&mut middle, resolution.access_len()? as u64);
            middle.extend_from_slice(resolution.access_prefix());
            trailer.extend_from_slice(resolution.access_suffix());
        }
        content_type = "application/vnd.blockzilla.get-block-bundle.wincode";
    }
    let parts = super::stream_parts::response_and_completion_from_parts(
        prefix,
        hot_body,
        locator.hot.compressed_len as u64,
        middle,
        sig_body,
        signature_len as u64,
        trailer,
    )
    .map_err(|e| e.to_string())?;
    let mut response = parts.response;
    add_profile_headers(response.headers(), source.profile.as_ref()).map_err(|e| e.to_string())?;
    response
        .headers_mut()
        .set("Content-Type", content_type)
        .map_err(|e| e.to_string())?;
    response
        .headers_mut()
        .set("Cache-Control", BLOCK_CACHE_CONTROL)
        .map_err(|e| e.to_string())?;
    response
        .headers_mut()
        .set("X-Blockzilla-Body", "native-stream")
        .map_err(|e| e.to_string())?;
    response
        .headers_mut()
        .set("X-Blockzilla-Storage-Bytes-Mode", "streamed-completion")
        .map_err(|e| e.to_string())?;
    response
        .headers_mut()
        .set(
            "X-Blockzilla-Origin-Expected-Bytes",
            &(u64::from(hot_origin) * u64::from(locator.hot.compressed_len)
                + u64::from(sig_origin) * signature_len as u64)
                .to_string(),
        )
        .map_err(|e| e.to_string())?;
    response
        .headers_mut()
        .set("X-Blockzilla-Resolution-Generation", generation)
        .map_err(|e| e.to_string())?;
    Ok(response)
}

/// A client obtains this once per block and generation, then uses its signed
/// locator to request hot+signature bytes without another resolution GET.
pub(super) async fn index_response(
    source: &WorkerSource,
    slot: u64,
) -> std::result::Result<Response, String> {
    let (resolution, bytes) = load(source, slot).await?;
    let config = source
        .resolution
        .as_ref()
        .ok_or("resolution is not configured")?;
    let token = config.token(&resolution.locator())?;
    let mut response = Response::from_bytes(bytes).map_err(|e| e.to_string())?;
    response
        .headers_mut()
        .set(
            "Content-Type",
            "application/vnd.blockzilla.slot-resolution.v1",
        )
        .map_err(|e| e.to_string())?;
    response
        .headers_mut()
        .set("Cache-Control", BLOCK_CACHE_CONTROL)
        .map_err(|e| e.to_string())?;
    response
        .headers_mut()
        .set("X-Blockzilla-Locator", &token)
        .map_err(|e| e.to_string())?;
    response
        .headers_mut()
        .set("X-Blockzilla-Resolution-Generation", &config.generation)
        .map_err(|e| e.to_string())?;
    Ok(response)
}

pub(super) fn query_locator(req: &Request) -> Option<String> {
    req.url()
        .ok()?
        .query_pairs()
        .find(|(k, _)| k == "locator")
        .map(|(_, v)| v.into_owned())
}

pub(super) async fn handle_index(
    req: Request,
    env: worker::Env,
    ctx: worker::Context,
) -> Result<Response> {
    let started = now_ms();
    let profile = request_profile(&req);
    let auth = match authenticate_api_key_with_cache_policy(
        &req,
        &env,
        allow_index_and_auth_cache(profile.as_ref()),
    )
    .await
    {
        Ok(key) => key,
        Err(RpcAuthError::Unauthorized) => return api_unauthorized_response(),
        Err(RpcAuthError::Unavailable) => {
            return json_error(
                503,
                "api_unavailable",
                "Authentication is temporarily unavailable",
            );
        }
    };
    let auth_cache_status = auth.cache_status;
    let auth_cache_tier = auth.cache_tier;
    let archive_backend = archive_backend_label(&env);
    let mut response =
        handle_authenticated_index(req, env, ctx, profile, auth.record, started).await?;
    add_auth_cache_headers(&mut response, auth_cache_status, auth_cache_tier)?;
    response
        .headers_mut()
        .set("X-Blockzilla-Archive-Backend", archive_backend)?;
    Ok(response)
}

async fn handle_authenticated_index(
    req: Request,
    env: worker::Env,
    ctx: worker::Context,
    profile: Option<ProfileHandle>,
    key: RpcApiKeyRecord,
    started: f64,
) -> Result<Response> {
    let metrics = match rpc_metrics(&env, profile.as_ref()) {
        Ok(metrics) => metrics,
        Err(response) => return Ok(response),
    };
    let slot = full_block_route_path(&req.path())
        .and_then(|p| p.strip_suffix(".resolution"))
        .filter(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|p| p.parse::<u64>().ok());
    let Some(slot) = slot else {
        return finish_metered_response(
            json_error(400, "invalid_slot", "Invalid resolution slot")?,
            &key,
            &metrics,
            MeteredRequest::new(
                "getBlockResolution",
                "invalid_request",
                "bypass",
                "http_binary",
                0,
                0,
            ),
            started,
            profile.as_ref(),
        );
    };
    let ctx = Rc::new(ctx);
    let generation = archive_cache_generation(&env);
    let cache_key = if profile.is_none() {
        Some(format!(
            "{}/__blockzilla-resolution-response/{generation}/{slot}",
            req.url()?.origin().ascii_serialization()
        ))
    } else {
        None
    };
    if let Some(cache_key) = &cache_key {
        if let Ok(Some(response)) = Cache::default().get(cache_key.clone(), false).await {
            let mut response = response_with_mutable_headers(response);
            response
                .headers_mut()
                .set("Cache-Control", "private, no-store")?;
            return finish_metered_response(
                response,
                &key,
                &metrics,
                MeteredRequest::new("getBlockResolution", "ok", "hit", "http_binary", 0, 0),
                started,
                profile.as_ref(),
            );
        }
    }
    let mut source = match WorkerSource::from_env(&env, profile.clone()) {
        Ok(source) => source,
        Err(err) => {
            return finish_metered_response(
                json_error(500, "config_error", &err)?,
                &key,
                &metrics,
                MeteredRequest::new(
                    "getBlockResolution",
                    "config_error",
                    "bypass",
                    "http_binary",
                    0,
                    0,
                ),
                started,
                profile.as_ref(),
            );
        }
    };
    if allow_index_and_auth_cache(profile.as_ref()) {
        source.cache = Some(ArchiveCache {
            origin: req.url()?.origin().ascii_serialization(),
            generation,
            context: ctx.clone(),
        });
    }
    let (mut response, outcome) = if !covered(&source, slot) {
        (
            json_error(
                404,
                "resolution_unavailable",
                "This slot has no admitted resolution object",
            )?,
            "not_found",
        )
    } else {
        match index_response(&source, slot).await {
            Ok(response) => (response, "ok"),
            Err(err) => (json_error(502, "resolution_error", &err)?, "backend_error"),
        }
    };
    let cached = if outcome == "ok" {
        cache_key.and_then(|k| response.cloned().ok().map(|r| (k, r)))
    } else {
        None
    };
    response
        .headers_mut()
        .set("Cache-Control", "private, no-store")?;
    let response = finish_metered_response(
        response,
        &key,
        &metrics,
        MeteredRequest::new(
            "getBlockResolution",
            outcome,
            if profile.is_none() { "miss" } else { "bypass" },
            "http_binary",
            0,
            source.billable_backend_reads(),
        )
        .with_storage(source.storage_metrics.snapshot()),
        started,
        profile.as_ref(),
    )?;
    if let Some((cache_key, cached)) = cached {
        ctx.wait_until(async move {
            if let Err(err) = Cache::default().put(cache_key, cached).await {
                console_error!("resolution cache write failed: {err}");
            }
        });
    }
    Ok(response)
}
