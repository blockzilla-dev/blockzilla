// A narrow, read-only native R2 transport. The public API remains in its owner account.
export const ARCHIVE_PREFIX = 'compact-v2/blockzilla-20261004';
export const MAX_RANGE_BYTES = 16 * 1024 * 1024;
export const MAX_AUTH_FUTURE_SECONDS = 60;
const MAX_URL_BYTES = 2048;
const FIELD_NAMES = new Set(['key', 'offset', 'length', 'object_length', 'etag']);
const KEY_PATTERN = /^compact-v2\/blockzilla-20261004\/epoch-(0|[1-9][0-9]*)\/(archive-v2-blocks\.zstd|signatures\.bin)$/;
const ETAG_PATTERN = /^"[0-9a-fA-F]{32}(?:-[1-9][0-9]*)?"$/;
const DECIMAL_PATTERN = /^(0|[1-9][0-9]*)$/;
const encoder = new TextEncoder();

class ReaderError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}

function decimal(value, positive = false) {
  if (typeof value !== 'string' || value.length > 16 || !DECIMAL_PATTERN.test(value)) throw new ReaderError(400, 'invalid_range');
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < (positive ? 1 : 0)) throw new ReaderError(400, 'invalid_range');
  return number;
}

export function canonicalRangeMessage(expires, fields) {
  return ['range-v1', expires, fields.key, fields.offset, fields.length, fields.object_length, fields.etag].join('\n');
}

export function parseRangeFields(url) {
  if (url.href.length > MAX_URL_BYTES) throw new ReaderError(400, 'invalid_request');
  const fields = {};
  for (const [name, value] of url.searchParams) {
    if (!FIELD_NAMES.has(name) || Object.hasOwn(fields, name)) throw new ReaderError(400, 'invalid_request');
    fields[name] = value;
  }
  if (Object.keys(fields).length !== FIELD_NAMES.size) throw new ReaderError(400, 'invalid_request');
  const match = KEY_PATTERN.exec(fields.key);
  if (!match || !Number.isSafeInteger(Number(match[1]))) throw new ReaderError(400, 'invalid_key');
  if (fields.etag.length > 128 || !ETAG_PATTERN.test(fields.etag)) throw new ReaderError(400, 'invalid_etag');
  const offset = decimal(fields.offset);
  const length = decimal(fields.length, true);
  const objectLength = decimal(fields.object_length, true);
  if (length > MAX_RANGE_BYTES || !Number.isSafeInteger(offset + length) || offset + length > objectLength) throw new ReaderError(400, 'invalid_range');
  return { fields, offset, length, objectLength };
}

function proofHeaders(gets) {
  return new Headers({
    'Cache-Control': 'private, no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-BZ-Reader-Backend': 'native-r2',
    'X-BZ-Reader-R2-GETs': String(gets),
    'X-BZ-Reader-R2-HEADs': '0',
  });
}

function errorResponse(status, code, gets) {
  const headers = proofHeaders(gets);
  headers.set('Content-Type', 'application/json');
  if (status === 405) headers.set('Allow', 'GET');
  return new Response(JSON.stringify({ error: code }), { status, headers });
}

function cancelBody(body, ctx) {
  if (body) ctx.waitUntil(body.cancel().catch(() => {}));
}

async function authenticate(request, env, fields) {
  const expires = request.headers.get('X-BZ-Reader-Expires');
  const signature = request.headers.get('X-BZ-Reader-Signature');
  if (!expires || !DECIMAL_PATTERN.test(expires) || expires.length > 16 || !signature || !/^[0-9a-f]{64}$/.test(signature)) throw new ReaderError(401, 'unauthorized');
  const expiry = Number(expires);
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(expiry) || expiry <= now || expiry > now + MAX_AUTH_FUTURE_SECONDS) throw new ReaderError(401, 'unauthorized');
  const bytes = Uint8Array.from(signature.match(/../g), value => Number.parseInt(value, 16));
  const key = await crypto.subtle.importKey('raw', encoder.encode(env.BZ_READER_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const valid = await crypto.subtle.verify('HMAC', key, bytes, encoder.encode(canonicalRangeMessage(expires, fields)));
  if (!valid) throw new ReaderError(401, 'unauthorized');
}

export default {
  async fetch(request, env, ctx) {
    let gets = 0;
    try {
      const url = new URL(request.url);
      if (request.method !== 'GET') return errorResponse(405, 'method_not_allowed', gets);
      if (url.pathname !== '/v1/range') return errorResponse(404, 'not_found', gets);
      // Reject missing authentication before parsing a range or touching a binding.
      if (!request.headers.has('X-BZ-Reader-Expires') || !request.headers.has('X-BZ-Reader-Signature')) return errorResponse(401, 'unauthorized', gets);
      if (typeof env.BZ_READER_SECRET !== 'string' || encoder.encode(env.BZ_READER_SECRET).length < 32 || encoder.encode(env.BZ_READER_SECRET).length > 1024
          || !env.FOUNDATION_ARCHIVE || typeof env.FOUNDATION_ARCHIVE.get !== 'function') return errorResponse(503, 'reader_unavailable', gets);
      const { fields, offset, length, objectLength } = parseRangeFields(url);
      const authStarted = performance.now();
      await authenticate(request, env, fields);
      const authMs = performance.now() - authStarted;
      const readStarted = performance.now();
      gets = 1;
      const object = await env.FOUNDATION_ARCHIVE.get(fields.key, {
        range: { offset, length },
        onlyIf: { etagMatches: fields.etag.slice(1, -1) },
      });
      const readMs = performance.now() - readStarted;
      if (!object) return errorResponse(404, 'object_missing', gets);
      if (!object.body) return errorResponse(412, 'source_identity_changed', gets);
      if (object.size !== objectLength || object.httpEtag !== fields.etag
          || (object.range && (object.range.offset !== offset || object.range.length !== length))) {
        cancelBody(object.body, ctx);
        return errorResponse(412, 'source_identity_changed', gets);
      }
      // A native FLS supplies the authoritative Content-Length and rejects
      // short/long bodies. No body buffering, decoding, tee, or WASM callback.
      const fixed = new FixedLengthStream(length);
      ctx.waitUntil(object.body.pipeTo(fixed.writable).catch(() => {
        console.error(JSON.stringify({ event: 'reader_stream_failed_or_cancelled' }));
      }));
      const headers = proofHeaders(gets);
      headers.set('Content-Type', 'application/octet-stream');
      headers.set('ETag', fields.etag);
      headers.set('Content-Length', String(length));
      headers.set('Content-Range', `bytes ${offset}-${offset + length - 1}/${objectLength}`);
      headers.set('Accept-Ranges', 'bytes');
      headers.set('X-BZ-Reader-Expected-Bytes', String(length));
      headers.set('Server-Timing', `reader_auth;dur=${authMs.toFixed(2)},reader_r2_headers;dur=${readMs.toFixed(2)}`);
      return new Response(fixed.readable, { status: 206, headers });
    } catch (error) {
      if (error instanceof ReaderError) return errorResponse(error.status, error.code, gets);
      console.error(JSON.stringify({ event: 'reader_failure', sourceAttempted: gets === 1 }));
      return errorResponse(502, 'source_unavailable', gets);
    }
  },
};
