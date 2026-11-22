//! Bounded, authenticated diagnostics. Normal binary streams do not use this.
use super::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(inline_js = r#"
export async function bzProbeRange(response, expected, started, headersAt, timeoutMs) {
    if (!Number.isSafeInteger(expected) || expected <= 0 || expected > 16 * 1024 * 1024
        || !Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 10000
        || response.body === null || response.body.locked) {
        throw new RangeError('Invalid bounded R2 probe');
    }
    const reader = response.body.getReader();
    const chunks = [];
    let received = 0, firstAt = null, endedAt, remaining = timeoutMs;
    try {
        while (true) {
            let timer;
            const beforeRead = performance.now();
            let next;
            try {
                if (remaining <= 0) throw new Error('R2 probe body timed out');
                next = await Promise.race([reader.read(), new Promise((_, reject) => {
                    timer = setTimeout(() => reject(new Error('R2 probe body timed out')), remaining);
                })]);
            } finally {
                remaining -= performance.now() - beforeRead;
                clearTimeout(timer);
            }
            if (next.done) { endedAt = performance.now(); break; }
            if (!(next.value instanceof Uint8Array) || next.value.byteLength > expected - received) {
                throw new RangeError('R2 probe body exceeds its declared length');
            }
            if (next.value.byteLength !== 0) {
                if (firstAt === null) firstAt = performance.now();
                received += next.value.byteLength;
                chunks.push(next.value);
            }
        }
        if (received !== expected) throw new RangeError('R2 probe body length differs');
    } catch (error) {
        void reader.cancel(error).catch(() => {});
        throw error;
    } finally {
        try { reader.releaseLock(); } catch (_) {}
    }
    // Capture EOF before concatenation and digest work. This diagnostic alone
    // retains native chunks; none of their bytes enter WASM.
    const bytes = new Uint8Array(received);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
    const ms = value => Math.max(0, value);
    return JSON.stringify({ expectedBytes: expected, receivedBytes: received,
        sha256: Array.from(digest, b => b.toString(16).padStart(2, '0')).join(''),
        headersMs: ms(headersAt - started), firstChunkMs: firstAt === null ? null : ms(firstAt - started),
        totalMs: ms(endedAt - started), bodyMs: ms(endedAt - headersAt),
        transferMs: firstAt === null ? null : ms(endedAt - firstAt), chunks: chunks.length,
        connectionMs: null, connectionReuse: null });
}
"#)]
extern "C" {
    #[wasm_bindgen::prelude::wasm_bindgen(catch)]
    fn bzProbeRange(
        response: &worker::web_sys::Response,
        expected: u32,
        started: f64,
        headers_at: f64,
        timeout_ms: u32,
    ) -> std::result::Result<js_sys::Promise, JsValue>;
}

async fn range(
    source: &WorkerSource,
    kind: &str,
    path: &str,
    offset: u64,
    len: usize,
    identity: &SourceObjectIdentity,
    timeout_ms: u32,
) -> std::result::Result<Value, String> {
    if len == 0 {
        return Ok(
            json!({ "kind": kind, "expectedBytes": 0, "receivedBytes": 0,
            "sha256": hex_lower(&sha2::Sha256::digest([])), "headersMs": 0,
            "firstChunkMs": null, "totalMs": 0, "bodyMs": 0, "transferMs": null,
            "chunks": 0, "upstreamColo": null, "connectionMs": null,
            "connectionReuse": null, "skipped": true }),
        );
    }
    let started = now_ms();
    // The shared fetch checks the source ETag, exact Content-Range and length.
    // Deliberately skip both application range caches and cache writes.
    let response = pinned_origin_response(source, path, offset, len, identity).await?;
    let headers_at = now_ms();
    let upstream_colo = response
        .headers()
        .get("cf-ray")
        .ok()
        .flatten()
        .and_then(|ray| ray.rsplit_once('-').map(|(_, colo)| colo.to_owned()));
    #[cfg(target_arch = "wasm32")]
    {
        let native: worker::web_sys::Response = response.into();
        let promise = bzProbeRange(&native, len as u32, started, headers_at, timeout_ms)
            .map_err(|_| "R2 native probe is unavailable")?;
        let value = wasm_bindgen_futures::JsFuture::from(promise)
            .await
            .map_err(|_| "R2 native probe body failed")?
            .as_string()
            .ok_or("R2 native probe returned no timing data")?;
        let mut value: Value = serde_json::from_str(&value).map_err(|e| e.to_string())?;
        value["kind"] = Value::from(kind);
        value["upstreamColo"] = json!(upstream_colo);
        source
            .storage_metrics
            .complete_get(backend_kind(source), len, true);
        Ok(value)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (response, started, headers_at, upstream_colo, timeout_ms);
        Err("R2 native probe requires the Worker runtime".into())
    }
}

pub(crate) async fn response(
    source: &WorkerSource,
    slot: u64,
    route: PendingLocatorV1,
) -> std::result::Result<Response, String> {
    let config = source
        .foundation_lookup
        .as_ref()
        .ok_or("Foundation is not configured")?;
    route.validate(&source.archive_prefix, config.generation(), slot)?;
    let hot_path = epoch_file(&source.archive_prefix, route.epoch, ARCHIVE_V2_BLOCKS_FILE);
    let sig_path = epoch_file(
        &source.archive_prefix,
        route.epoch,
        blockzilla_archive_v2::ARCHIVE_V2_SIGNATURES_FILE,
    );
    let signature_offset = route
        .hot
        .first_signature_ordinal
        .checked_mul(64)
        .ok_or("signature offset overflows")?;
    let (hot, signatures) = future::try_join(
        range(
            source,
            "hot",
            &hot_path,
            route.hot.compressed_offset,
            route.hot.compressed_len as usize,
            &route.blocks,
            config.body_timeout_ms(),
        ),
        range(
            source,
            "signatures",
            &sig_path,
            signature_offset,
            route.hot.signature_count as usize * 64,
            &route.signatures,
            config.body_timeout_ms(),
        ),
    )
    .await?;
    let mut response = Response::from_json(&json!({ "version": 1, "slot": slot,
        "epoch": route.epoch, "parallel": true, "clock": "workers-io-clock",
        "connectionTiming": "unavailable-in-workers-fetch", "ranges": [hot, signatures],
        "resultCache": false, "rangeCache": false,
        "timingScope": "each-range-start-to-native-body-EOF;digest-after-EOF" }))
    .map_err(|e| e.to_string())?;
    response
        .headers_mut()
        .set("Cache-Control", "private, no-store")
        .map_err(|e| e.to_string())?;
    response
        .headers_mut()
        .set("X-Blockzilla-Body", "native-r2-probe")
        .map_err(|e| e.to_string())?;
    add_profile_headers(response.headers(), source.profile.as_ref()).map_err(|e| e.to_string())?;
    Ok(response)
}
