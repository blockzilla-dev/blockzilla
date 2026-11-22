//! Native WebCrypto handles the bounded resolution payload hash. The digest is
//! computed from these exact bytes and never accepted from a caller or header.

#[cfg(target_arch = "wasm32")]
use js_sys::{Promise, Uint8Array};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(inline_js = r#"
export function bzResolutionSha256(bytes) {
    return crypto.subtle.digest('SHA-256', bytes);
}
export async function bzNativeResponseSha256(response, expected, timeoutMs) {
    if (!Number.isSafeInteger(expected) || expected <= 0 || expected > 16 * 1024 * 1024
        || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10000) {
        throw new RangeError('Native hot body exceeds its hash bound');
    }
    if (response.body === null || response.body.locked) throw new TypeError('Missing native hot body');
    const reader = response.body.getReader();
    let remaining = timeoutMs;
    let received = 0;
    let done = false;
    const guarded = new ReadableStream({
        async pull(controller) {
            let timer;
            const started = performance.now();
            try {
                if (remaining <= 0) throw new Error('Native hot hash body timed out');
                const next = await Promise.race([reader.read(), new Promise((_, reject) => {
                    timer = setTimeout(() => reject(new Error('Native hot hash body timed out')), remaining);
                })]);
                remaining -= performance.now() - started;
                clearTimeout(timer);
                if (next.done) {
                    if (received !== expected) throw new RangeError('Native hot body length differs');
                    done = true;
                    reader.releaseLock();
                    controller.close();
                } else {
                    if (!(next.value instanceof Uint8Array) || next.value.byteLength > expected - received) {
                        throw new RangeError('Native hot body exceeds its declared length');
                    }
                    received += next.value.byteLength;
                    controller.enqueue(next.value);
                }
            } catch (error) {
                clearTimeout(timer);
                controller.error(error);
                // A tee branch's cancellation can wait for its peer. The Rust
                // caller cancels the original hot and signature branches too.
                void reader.cancel(error).catch(() => {});
                try { reader.releaseLock(); } catch (_) {}
            }
        },
        cancel(reason) {
            if (done) return;
            void reader.cancel(reason).catch(() => {});
        }
    }, { highWaterMark: 0 });
    const bytes = await new Response(guarded).arrayBuffer();
    if (bytes.byteLength !== expected) throw new RangeError('Native hot body length differs');
    return crypto.subtle.digest('SHA-256', bytes);
}
export function bzCancelNativeResponse(response) {
    if (response.body !== null && !response.body.locked) {
        void response.body.cancel('Blockzilla request failed').catch(() => {});
    }
}
"#)]
extern "C" {
    #[wasm_bindgen(catch)]
    fn bzResolutionSha256(bytes: &Uint8Array) -> Result<Promise, JsValue>;
    #[wasm_bindgen(catch)]
    fn bzNativeResponseSha256(
        response: &worker::web_sys::Response,
        expected: u32,
        timeout_ms: u32,
    ) -> Result<Promise, JsValue>;
    #[wasm_bindgen(catch)]
    fn bzCancelNativeResponse(response: &worker::web_sys::Response) -> Result<(), JsValue>;
}

pub(super) fn cancel_response(response: worker::Response) {
    #[cfg(target_arch = "wasm32")]
    {
        let native: worker::web_sys::Response = response.into();
        let _ = bzCancelNativeResponse(&native);
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = response;
    }
}

/// Hash one native clone. Only the digest enters WASM; hot bytes stay in JS.
pub(super) async fn sha256_response(
    response: &mut worker::Response,
    expected: usize,
    timeout_ms: u32,
) -> Result<[u8; 32], String> {
    if expected == 0 || expected > 16 * 1024 * 1024 || timeout_ms == 0 || timeout_ms > 10_000 {
        return Err("native hot body exceeds its hash bound".into());
    }
    #[cfg(target_arch = "wasm32")]
    {
        let native: worker::web_sys::Response =
            response.cloned().map_err(|e| e.to_string())?.into();
        let promise = bzNativeResponseSha256(&native, expected as u32, timeout_ms)
            .map_err(|_| "native hot body SHA-256 is unavailable")?;
        let output = wasm_bindgen_futures::JsFuture::from(promise)
            .await
            .map_err(|_| "native hot body SHA-256 failed")?;
        let digest = Uint8Array::new(&output);
        if digest.length() != 32 {
            return Err("native hot body SHA-256 length differs".into());
        }
        let mut result = [0; 32];
        digest.copy_to(&mut result);
        Ok(result)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = response;
        Err("native body hashing requires the Worker runtime".into())
    }
}

pub(super) async fn sha256(bytes: &[u8]) -> Result<[u8; 32], String> {
    #[cfg(target_arch = "wasm32")]
    {
        // The input is bounded by the resolution framing check. Copy once into
        // a JS-owned buffer so concurrent requests cannot invalidate a borrowed
        // WASM memory view while WebCrypto is pending.
        let input = Uint8Array::from(bytes);
        let promise =
            bzResolutionSha256(&input).map_err(|_| "native resolution SHA-256 is unavailable")?;
        let output = wasm_bindgen_futures::JsFuture::from(promise)
            .await
            .map_err(|_| "native resolution SHA-256 failed")?;
        let digest = Uint8Array::new(&output);
        if digest.length() != 32 {
            return Err("native resolution SHA-256 has an invalid length".into());
        }
        let mut result = [0; 32];
        digest.copy_to(&mut result);
        Ok(result)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use sha2::{Digest, Sha256};
        Ok(Sha256::digest(bytes).into())
    }
}
