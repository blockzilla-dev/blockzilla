const SOURCE_PREFIX = 'compact-v2/blockzilla-20261004/epoch-1089/';
const DEST_PREFIX = 'compact-v2/native-r2-full-1089-20261122/epoch-1089/';
const OBJECTS = {
  'archive-v2-blocks.zstd': { length: 52177905206, partSize: 64 * 1024 * 1024, etag: '"a27d4990dcb9ff26589f1b4404bf6048-778"' },
  'signatures.bin': { length: 10799377984, partSize: 128 * 1024 * 1024, etag: '"83324114ba7b311be228f17f3ba1e909-81"' },
};
const encoder = new TextEncoder();
function hex(bytes) { return [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join(''); }
function fail(status, message) { return Response.json({ error: message }, { status }); }
function objectInfo(object) { return { key: object.key, length: object.size, etag: object.httpEtag, uploaded: object.uploaded.toISOString() }; }
async function boundedBody(request) {
  const reader = request.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks = []; let length = 0;
  for (;;) {
    const next = await reader.read();
    if (next.done) break;
    length += next.value.byteLength;
    if (length > 65536) { void reader.cancel(); throw new Error('Request too large'); }
    chunks.push(next.value);
  }
  const result = new Uint8Array(length); let offset = 0;
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.byteLength; }
  return result;
}
async function authenticate(request, env, bytes) {
  const expires = request.headers.get('X-BZ-Copy-Expires');
  const signature = request.headers.get('X-BZ-Copy-Signature');
  if (typeof env.BZ_COPY_SECRET !== 'string' || env.BZ_COPY_SECRET.length < 32) return false;
  if (!/^[0-9]{10}$/.test(expires ?? '') || !/^[0-9a-f]{64}$/.test(signature ?? '')) return false;
  const now = Math.floor(Date.now() / 1000);
  if (Number(expires) < now || Number(expires) > now + 120) return false;
  const digest = hex(await crypto.subtle.digest('SHA-256', bytes));
  const message = encoder.encode(`copy-v1\nPOST\n${new URL(request.url).pathname}\n${expires}\n${digest}`);
  const key = await crypto.subtle.importKey('raw', encoder.encode(env.BZ_COPY_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const mac = Uint8Array.from(signature.match(/../g), value => parseInt(value, 16));
  return crypto.subtle.verify('HMAC', key, mac, message);
}
export default {
  async fetch(request, env) {
    let stage = 'request';
    try {
      const route = new URL(request.url).pathname;
      if (request.method !== 'POST' || !['/create','/part','/complete','/head','/sample','/abort'].includes(route)) return fail(404, 'Not found');
      if (Number(request.headers.get('Content-Length') ?? 0) > 65536) return fail(413, 'Request too large');
      const bytes = await boundedBody(request);
      if (bytes.byteLength > 65536 || !await authenticate(request, env, bytes)) return fail(401, 'Unauthorized');
      let input;
      try { input = JSON.parse(new TextDecoder().decode(bytes)); } catch { return fail(400, 'Invalid JSON'); }
      if (!Object.hasOwn(OBJECTS, input.name)) return fail(400, 'Object not allowed');
      const source = OBJECTS[input.name];
      const key = DEST_PREFIX + input.name;
      if (route === '/head') {
        const object = await env.DESTINATION.head(key);
        return Response.json({ object: object ? objectInfo(object) : null });
      }
      if (route === '/create') {
        if (await env.DESTINATION.head(key)) return fail(409, 'Destination already exists');
        const upload = await env.DESTINATION.createMultipartUpload(key, { httpMetadata: { contentType: 'application/octet-stream' }, customMetadata: { source: 'foundation-epoch-1089', sourceEtag: source.etag, sourceLength: String(source.length) } });
        return Response.json({ key, uploadId: upload.uploadId });
      }
      if (route === '/sample') {
        if (!Number.isSafeInteger(input.offset) || !Number.isSafeInteger(input.length) || input.offset < 0 || input.length <= 0 || input.length > 1024 * 1024 || input.offset + input.length > source.length) return fail(400, 'Invalid sample');
        if (!/^"[0-9a-f]{32}(?:-[1-9][0-9]*)?"$/.test(input.etag ?? '')) return fail(400, 'Invalid sample ETag');
        const object = await env.DESTINATION.get(key, { range: { offset: input.offset, length: input.length }, onlyIf: { etagMatches: input.etag.slice(1, -1) } });
        if (!object || !object.body || object.size !== source.length || object.httpEtag !== input.etag || object.range?.offset !== input.offset || object.range?.length !== input.length) return fail(412, 'Sample identity mismatch');
        const data = await object.arrayBuffer();
        if (data.byteLength !== input.length) return fail(502, 'Sample length mismatch');
        return Response.json({ offset: input.offset, length: data.byteLength, sha256: hex(await crypto.subtle.digest('SHA-256', data)), etag: object.httpEtag });
      }
      if (typeof input.uploadId !== 'string' || input.uploadId.length < 8 || input.uploadId.length > 2048 || /[\r\n]/.test(input.uploadId)) return fail(400, 'Invalid upload ID');
      const upload = env.DESTINATION.resumeMultipartUpload(key, input.uploadId);
      if (route === '/abort') { await upload.abort(); return Response.json({ aborted: true }); }
      if (route === '/complete') {
        const count = Math.ceil(source.length / source.partSize);
        if (!Array.isArray(input.parts) || input.parts.length !== count || input.parts.some((part, index) => part.partNumber !== index + 1 || !/^[0-9a-f]{32}$/.test(part.etag ?? ''))) return fail(400, 'Invalid completion parts');
        if (await env.DESTINATION.head(key)) return fail(409, 'Destination already exists');
        const object = await upload.complete(input.parts);
        if (object.size !== source.length) return fail(502, 'Completed length mismatch');
        return Response.json({ object: objectInfo(object) });
      }
      const count = Math.ceil(source.length / source.partSize);
      if (!Number.isSafeInteger(input.partNumber) || input.partNumber < 1 || input.partNumber > count) return fail(400, 'Invalid part number');
      const offset = (input.partNumber - 1) * source.partSize;
      const length = Math.min(source.partSize, source.length - offset);
      const range = `bytes=${offset}-${offset + length - 1}`;
      const auth = input.sourceHeaders;
      if (!auth || Object.keys(auth).sort().join(',') !== 'authorization,if-match,range,x-amz-content-sha256,x-amz-date' || auth.range !== range || auth['if-match'] !== source.etag || auth['x-amz-content-sha256'] !== 'UNSIGNED-PAYLOAD' || !/^[0-9]{8}T[0-9]{6}Z$/.test(auth['x-amz-date']) || !/^AWS4-HMAC-SHA256 Credential=/.test(auth.authorization) || Object.values(auth).some(value => typeof value !== 'string' || /[\r\n]/.test(value))) return fail(400, 'Invalid source signature');
      const endpoint = new URL(env.SOURCE_ENDPOINT);
      if (endpoint.protocol !== 'https:' || !/^[0-9a-f]{32}\.r2\.cloudflarestorage\.com$/.test(endpoint.hostname) || endpoint.pathname !== '/' || endpoint.search || endpoint.hash || env.SOURCE_BUCKET !== 'solana-archive-data') return fail(503, 'Invalid source configuration');
      const sourceUrl = `${endpoint.origin}/${env.SOURCE_BUCKET}/${SOURCE_PREFIX}${input.name}`;
      const started = performance.now();
      stage = 'source-fetch';
      const response = await fetch(sourceUrl, { headers: { ...auth, 'Accept-Encoding': 'identity' }, redirect: 'manual' });
      if (response.status !== 206 || response.headers.get('ETag') !== source.etag || response.headers.get('Content-Range') !== `bytes ${offset}-${offset + length - 1}/${source.length}` || response.headers.get('Content-Length') !== String(length) || response.headers.get('Content-Encoding') || !response.body) {
        if (response.body) await response.body.cancel();
        return fail(502, `Source range mismatch (${response.status})`);
      }
      const headersMs = performance.now() - started;
      stage = 'native-upload';
      const exact = new FixedLengthStream(length);
      const abort = new AbortController();
      const uploading = upload.uploadPart(input.partNumber, exact.readable);
      const piping = response.body.pipeTo(exact.writable, { signal: abort.signal });
      let part;
      try { [part] = await Promise.all([uploading, piping]); }
      catch (error) { abort.abort(); await Promise.allSettled([uploading, piping]); throw error; }
      return Response.json({ ...part, offset, length, sourceEtag: source.etag, headersMs, totalMs: performance.now() - started });
    } catch (error) {
      const safeName = /^[A-Za-z]+Error$/.test(error?.name ?? '') ? error.name : 'Error';
      const hint = String(error?.message ?? '').replace(/https?:\/\/[^\s]+/g, '[url]').replace(/[A-Za-z0-9+/_=-]{24,}/g, '[redacted]').slice(0, 240);
      return Response.json({ error: 'Copy operation failed', stage, errorName: safeName, hint }, { status: 502 });
    }
  },
};
