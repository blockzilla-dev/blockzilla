//! Join small Wincode framing buffers and native network body streams.
//!
//! Network chunks stay in JavaScript. Do not use `Response::stream`,
//! `ByteStream`, or `Response::bytes` here: those copy network bytes into WASM.
//! This does not claim zero-copy JSON conversion or zero copies inside the
//! platform. Framing buffers cross from WASM to JS once, with an explicit cap.

use js_sys::{Object, Promise, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue, prelude::wasm_bindgen};
use worker::{Error, Response, ResponseBody, web_sys::ReadableStream};

// A retained native frame can add up to 64 KiB of metadata and a 16-byte
// envelope to its 16 MiB payload. Archive callers retain their source caps.
const MAX_BODY_PART_BYTES: u64 = 16 + 65_536 + 16 * 1024 * 1024;
const MAX_FRAMING_BYTES: usize = 16 * 1024 * 1024;

#[wasm_bindgen(inline_js = r#"
// Static module code. There is no eval or per-chunk WASM callback.
export function bzStreamParts(prefix, hot, hotLength, middle, signatures, signatureLength, trailer) {
    const framingLimit = 16 * 1024 * 1024;
    const bodyLimit = 16 + 65536 + 16 * 1024 * 1024;
    if (![prefix, middle, trailer].every(value => value instanceof Uint8Array)
        || prefix.byteLength + middle.byteLength + trailer.byteLength > framingLimit) {
        throw new RangeError('Blockzilla framing exceeds its byte limit');
    }
    for (const [stream, length] of [[hot, hotLength], [signatures, signatureLength]]) {
        if (!Number.isSafeInteger(length) || length < 0 || length > bodyLimit) {
            throw new RangeError('Blockzilla stream length exceeds its byte limit');
        }
        if (stream === null) {
            if (length !== 0) throw new TypeError('Blockzilla body stream is missing');
        } else if (typeof stream.getReader !== 'function' || stream.locked) {
            throw new TypeError('Blockzilla requires an unlocked native body stream');
        }
    }

    const hotPart = { body: hot, expected: hotLength, received: 0, reader: null, done: hot === null };
    const signaturePart = { body: signatures, expected: signatureLength, received: 0, reader: null, done: signatures === null };
    const bodies = [hotPart, signaturePart];
    const parts = [{ bytes: prefix }, hotPart, { bytes: middle }, signaturePart, { bytes: trailer }];
    const totalBytes = prefix.byteLength + hotLength + middle.byteLength + signatureLength + trailer.byteLength;
    let position = 0;
    let cancelled = false;
    let cancellation = null;

    function cancelSources(reason) {
        if (cancellation !== null) return cancellation;
        cancelled = true;
        cancellation = Promise.allSettled(bodies.map(async part => {
            if (part.done) return;
            try {
                if (part.reader !== null) await part.reader.cancel(reason);
                else if (part.body !== null) await part.body.cancel(reason);
            } finally {
                if (part.reader !== null) {
                    try { part.reader.releaseLock(); } catch (_) { /* A pending read can already be rejected. */ }
                    part.reader = null;
                }
                part.body = null;
                part.done = true;
            }
        })).then(() => undefined);
        return cancellation;
    }

    const joined = new ReadableStream({
        async pull(controller) {
            let emptyChunks = 0;
            try {
                while (!cancelled && position < parts.length) {
                    const part = parts[position];
                    if (Object.prototype.hasOwnProperty.call(part, 'bytes')) {
                        const bytes = part.bytes;
                        part.bytes = null;
                        position += 1;
                        if (bytes.byteLength !== 0) {
                            controller.enqueue(bytes);
                            return;
                        }
                        continue;
                    }
                    if (part.done) {
                        position += 1;
                        continue;
                    }
                    if (part.reader === null) part.reader = part.body.getReader();
                    const next = await part.reader.read();
                    if (cancelled) return;
                    if (next.done) {
                        if (part.received !== part.expected) {
                            throw new RangeError('Blockzilla upstream body ended before its declared length');
                        }
                        part.reader.releaseLock();
                        part.reader = null;
                        part.body = null;
                        part.done = true;
                        position += 1;
                        continue;
                    }
                    if (!(next.value instanceof Uint8Array)) {
                        throw new TypeError('Blockzilla upstream body yielded a non-byte chunk');
                    }
                    if (next.value.byteLength > part.expected - part.received) {
                        throw new RangeError('Blockzilla upstream body exceeded its declared length');
                    }
                    part.received += next.value.byteLength;
                    if (next.value.byteLength === 0) {
                        if (++emptyChunks > 1024) throw new Error('Blockzilla upstream body made no byte progress');
                        continue;
                    }
                    // Enqueue the original JS Uint8Array. Do not slice, copy,
                    // buffer the complete body, or send it through WASM.
                    controller.enqueue(next.value);
                    return;
                }
                if (!cancelled) controller.close();
            } catch (error) {
                if (!cancelled) controller.error(error);
                await cancelSources(error);
            }
        },
        cancel(reason) { return cancelSources(reason); }
    }, { highWaterMark: 0 });

    // Only a native FixedLengthStream supplies an authoritative Content-Length
    // in Workers. Setting a header on an arbitrary JS ReadableStream does not.
    // pipeTo keeps native backpressure and cancellation; it does not tee.
    const fixed = new FixedLengthStream(totalBytes);
    const completion = joined.pipeTo(fixed.writable).then(() => ({
        hotBytes: hotPart.received,
        signatureBytes: signaturePart.received,
        totalBytes
    }));
    // The readable still fails on any pipe error. Mark the promise handled
    // even when the caller only needs the HTTP response, not completion data.
    void completion.catch(() => {});
    return { body: fixed.readable, completion };
}
"#)]
extern "C" {
    #[wasm_bindgen(catch, js_name = bzStreamParts)]
    fn native_parts(
        prefix: &Uint8Array,
        hot: &JsValue,
        hot_length: f64,
        middle: &Uint8Array,
        signatures: &JsValue,
        signature_length: f64,
        trailer: &Uint8Array,
    ) -> std::result::Result<Object, JsValue>;
}

/// `completion` resolves only after both exact upstream windows and all
/// framing were transferred. It rejects on upstream error or cancellation.
/// Use it for deferred byte accounting, never for pre-transfer receipt claims.
pub(super) struct StreamedParts {
    pub(super) response: Response,
    pub(super) completion: Promise,
}

/// No body clone or tee is performed. The caller owns any cache-write tee and
/// its byte limit. Stream errors occur after headers and cannot become JSON.
pub(super) fn response_from_parts(
    prefix: Vec<u8>,
    hot: ResponseBody,
    hot_length: u64,
    middle: Vec<u8>,
    signatures: ResponseBody,
    signature_length: u64,
    trailer: Vec<u8>,
) -> worker::Result<Response> {
    Ok(response_and_completion_from_parts(
        prefix,
        hot,
        hot_length,
        middle,
        signatures,
        signature_length,
        trailer,
    )?
    .response)
}

pub(super) fn response_and_completion_from_parts(
    prefix: Vec<u8>,
    hot: ResponseBody,
    hot_length: u64,
    middle: Vec<u8>,
    signatures: ResponseBody,
    signature_length: u64,
    trailer: Vec<u8>,
) -> worker::Result<StreamedParts> {
    let total = checked_length(
        prefix.len(),
        hot_length,
        middle.len(),
        signature_length,
        trailer.len(),
    )
    .map_err(|message| Error::RustError(message.into()))?;
    let hot = native_body(hot, hot_length)?;
    let signatures = native_body(signatures, signature_length)?;
    // Uint8Array::from copies only these bounded framing buffers. A WASM view
    // would become invalid when Rust drops the Vec or grows linear memory.
    let prefix = Uint8Array::from(prefix.as_slice());
    let middle = Uint8Array::from(middle.as_slice());
    let trailer = Uint8Array::from(trailer.as_slice());
    let joined = native_parts(
        &prefix,
        &hot,
        hot_length as f64,
        &middle,
        &signatures,
        signature_length as f64,
        &trailer,
    )
    .map_err(Error::from)?;
    let body = Reflect::get(&joined, &JsValue::from_str("body"))
        .map_err(Error::from)?
        .dyn_into::<ReadableStream>()
        .map_err(Error::from)?;
    let completion = Reflect::get(&joined, &JsValue::from_str("completion"))
        .map_err(Error::from)?
        .dyn_into::<Promise>()
        .map_err(Error::from)?;
    let mut response = Response::from_body(ResponseBody::Stream(body))?;
    // The native FixedLengthStream is the authority; this mirrors its size
    // for local callers before the response reaches the Workers runtime.
    response
        .headers_mut()
        .set("Content-Length", &total.to_string())?;
    Ok(StreamedParts {
        response,
        completion,
    })
}

fn native_body(body: ResponseBody, expected: u64) -> worker::Result<JsValue> {
    match body {
        ResponseBody::Stream(stream) => Ok(stream.into()),
        ResponseBody::Empty if expected == 0 => Ok(JsValue::NULL),
        ResponseBody::Body(bytes) if expected == 0 && bytes.is_empty() => Ok(JsValue::NULL),
        _ => Err(Error::RustError(
            "stream parts require native body streams; buffered bodies are not accepted".into(),
        )),
    }
}

fn checked_length(
    prefix: usize,
    hot: u64,
    middle: usize,
    signatures: u64,
    trailer: usize,
) -> std::result::Result<u64, &'static str> {
    let framing = prefix
        .checked_add(middle)
        .and_then(|value| value.checked_add(trailer))
        .filter(|value| *value <= MAX_FRAMING_BYTES)
        .ok_or("stream framing exceeds its 16 MiB byte limit")?;
    if hot > MAX_BODY_PART_BYTES || signatures > MAX_BODY_PART_BYTES {
        return Err("native body part exceeds its Compact V2 transport bound");
    }
    (framing as u64)
        .checked_add(hot)
        .and_then(|value| value.checked_add(signatures))
        .ok_or("stream total length overflow")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_all_framing_and_native_body_lengths_without_buffering() {
        assert_eq!(checked_length(7, 1000, 3, 128, 20).unwrap(), 1158);
        assert_eq!(checked_length(0, 0, 0, 0, 0).unwrap(), 0);
        assert_eq!(
            checked_length(
                MAX_FRAMING_BYTES,
                MAX_BODY_PART_BYTES,
                0,
                MAX_BODY_PART_BYTES,
                0
            )
            .unwrap(),
            MAX_FRAMING_BYTES as u64 + 2 * MAX_BODY_PART_BYTES
        );
    }

    #[test]
    fn rejects_body_and_framing_limits_and_integer_overflow() {
        assert!(checked_length(0, MAX_BODY_PART_BYTES + 1, 0, 0, 0).is_err());
        assert!(checked_length(0, 0, 0, MAX_BODY_PART_BYTES + 1, 0).is_err());
        assert!(checked_length(MAX_FRAMING_BYTES, 0, 1, 0, 0).is_err());
        assert!(checked_length(usize::MAX, 0, 1, 0, 0).is_err());
    }
}
