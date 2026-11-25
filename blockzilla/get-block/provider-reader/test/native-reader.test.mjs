#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createHmac, webcrypto } from 'node:crypto';
import { createRequire } from 'node:module';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalRangeMessage, parseRangeFields, MAX_RANGE_BYTES } from '../src/index.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
let miniflare;
try { miniflare = createRequire(join(ROOT, 'package.json'))('miniflare'); }
catch { miniflare = createRequire(join(ROOT, '../package.json'))('miniflare'); }
const SECRET = 'foundation-reader-local-test-secret-0123456789';
const KEY = 'compact-v2/blockzilla-20261004/epoch-1090/archive-v2-blocks.zstd';
const DATA = Buffer.from(Array.from({ length: 256 * 1024 + 17 }, (_, i) => (i * 31 + 7) % 251));
const receipt = { schema: 'foundation-reader-local-v1', status: 'RUNNING', scope: 'Actual Miniflare/workerd with native local R2; no external calls or cloud writes', checks: [] };
const passed = text => { receipt.checks.push(text); console.log(`Passed ${text}.`); };

const vector = JSON.parse(await readFile(join(ROOT, 'test/protocol-vector.json'), 'utf8'));
const message = canonicalRangeMessage(vector.expires, vector);
assert.equal(createHmac('sha256', vector.secret).update(message).digest('hex'), vector.mac);
assert.ok(!message.endsWith('\n'));
const cryptoKey = await webcrypto.subtle.importKey('raw', Buffer.from(vector.secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
assert.equal(await webcrypto.subtle.verify('HMAC', cryptoKey, Buffer.from(vector.mac, 'hex'), Buffer.from(message)), true);
passed('independent Node and WebCrypto fixed HMAC vector');

const temporary = await mkdtemp(join(tmpdir(), 'foundation-reader-test-'));
const v4 = {
  name: 'foundation-reader-local-test', compatibilityDate: '2026-09-10',
  modulesRoot: ROOT,
  modules: [{ type: 'ESModule', path: join(ROOT, 'test/fixture-worker.mjs') }, { type: 'ESModule', path: join(ROOT, 'src/index.mjs') }],
  resourcePersistencePath: join(temporary, 'storage'), telemetry: { enabled: false },
  bindings: { BZ_READER_SECRET: SECRET }, r2Buckets: { FOUNDATION_ARCHIVE: 'foundation-reader-local-archive' },
};
const convert = options => typeof miniflare.convertV4MiniflareOptions === 'function' ? miniflare.convertV4MiniflareOptions(options) : options;
const production = { ...v4, modules: [
  { type: 'ESModule', path: join(ROOT, 'src/worker.mjs') },
  { type: 'ESModule', path: join(ROOT, 'src/index.mjs') },
] };
const mf = new miniflare.Miniflare(convert(production));
let base;
const request = async (fields, options = {}) => {
  const expires = String(options.expires ?? (Math.floor(Date.now() / 1000) + 30));
  const url = new URL('/v1/range', base);
  for (const [key, value] of Object.entries(fields)) url.searchParams.set(key, String(value));
  const signature = createHmac('sha256', options.secret ?? SECRET).update(canonicalRangeMessage(expires, fields)).digest('hex');
  options.mutateUrl?.(url);
  const headers = { 'X-BZ-Reader-Expires': expires, 'X-BZ-Reader-Signature': signature, ...options.headers };
  if (options.noAuth) { delete headers['X-BZ-Reader-Expires']; delete headers['X-BZ-Reader-Signature']; }
  return fetch(url, { method: options.method ?? 'GET', headers, signal: options.signal ?? AbortSignal.timeout(3000) });
};
const stats = async () => (await fetch(`${base}/__fixture/stats`, { signal: AbortSignal.timeout(3000) })).json();
const mode = async value => { await (await fetch(`${base}/__fixture/mode?value=${value}`, { signal: AbortSignal.timeout(3000) })).arrayBuffer(); };
function proof(response, gets) {
  assert.equal(response.headers.get('X-BZ-Reader-Backend'), 'native-r2');
  assert.equal(response.headers.get('X-BZ-Reader-R2-GETs'), String(gets));
  assert.equal(response.headers.get('X-BZ-Reader-R2-HEADs'), '0');
  assert.equal(response.headers.get('Cache-Control'), 'private, no-store');
}
async function rejected(fields, status, gets, options) {
  const before = await stats(); const response = await request(fields, options);
  assert.equal(response.status, status); proof(response, gets);
  const text = await response.text(); assert.ok(!text.includes(SECRET) && !text.includes('solana-archive-data'));
  assert.equal((await stats()).attempts - before.attempts, gets);
}
try {
  base = (await mf.ready).origin;
  const productionBucket = await mf.getR2Bucket('FOUNDATION_ARCHIVE');
  const productionObject = await productionBucket.put(KEY, DATA);
  const productionEtag = productionObject.httpEtag ?? `"${productionObject.etag}"`;
  const productionResponse = await request({ key: KEY, offset: '1234', length: '65537', object_length: String(DATA.length), etag: productionEtag });
  assert.equal(productionResponse.status, 206); proof(productionResponse, 1);
  assert.deepEqual(Buffer.from(await productionResponse.arrayBuffer()), DATA.subarray(1234, 1234 + 65537));
  passed('exact deployment entry point starts and serves a signed native R2 range');
  await mf.setOptions(convert(v4));
  base = (await mf.ready).origin;
  const bucket = await mf.getR2Bucket('FOUNDATION_ARCHIVE');
  const object = await bucket.put(KEY, DATA);
  const etag = object.httpEtag ?? `"${object.etag}"`;
  const fields = { key: KEY, offset: '1234', length: '65537', object_length: String(DATA.length), etag };
  assert.equal(parseRangeFields(new URL(`https://fixture/v1/range?${new URLSearchParams(fields)}`)).length, 65537);
  await rejected(fields, 401, 0, { noAuth: true });
  await rejected(fields, 401, 0, { secret: 'wrong-local-test-secret-01234567890123456789' });
  await rejected(fields, 401, 0, { expires: Math.floor(Date.now() / 1000) - 1 });
  await rejected(fields, 401, 0, { expires: Math.floor(Date.now() / 1000) + 120 });
  await rejected(fields, 401, 0, { headers: { 'X-BZ-Reader-Signature': 'f'.repeat(64) } });
  await rejected(fields, 401, 0, { mutateUrl: url => url.searchParams.set('offset', '1235') });
  passed('MAC missing incorrect expired future and tampered requests reject before R2');

  for (const changed of [
    { offset: '00' }, { offset: '-1' }, { offset: '1.5' }, { length: '0' }, { length: String(MAX_RANGE_BYTES + 1) },
    { offset: '9007199254740992' }, { offset: String(DATA.length) }, { object_length: '0' },
    { key: KEY.replace('compact-v2/', '../compact-v2/') }, { key: KEY.replace('epoch-1090', 'epoch-01090') },
    { key: KEY.replace('archive-v2-blocks.zstd', 'registry.bin') }, { key: `${KEY}\nignored` }, { etag: `W/${etag}` }, { etag: '"unsafe,etag"' },
  ]) await rejected({ ...fields, ...changed }, 400, 0);
  await rejected(fields, 400, 0, { mutateUrl: url => url.searchParams.append('offset', '1234') });
  await rejected(fields, 400, 0, { mutateUrl: url => url.searchParams.set('unknown', '1') });
  passed('strict prefix filename integer bounds ETag and exact query grammar');

  for (const method of ['POST', 'HEAD', 'OPTIONS']) await rejected(fields, 405, 0, { method });
  const unknown = await fetch(`${base}/health`); assert.equal(unknown.status, 404); proof(unknown, 0);
  assert.ok(!(await unknown.text()).includes('solana-archive-data'));
  passed('GET-only routing with no public bucket or secret information');

  const validBefore = await stats();
  const response = await request(fields); assert.equal(response.status, 206); proof(response, 1);
  assert.equal(response.headers.get('ETag'), etag);
  assert.equal(response.headers.get('Content-Range'), `bytes 1234-66770/${DATA.length}`);
  assert.equal(response.headers.get('Content-Length'), '65537');
  assert.equal(response.headers.get('X-BZ-Reader-Expected-Bytes'), '65537');
  assert.equal(response.headers.get('Transfer-Encoding'), null);
  assert.ok(response.headers.get('Server-Timing').includes('reader_r2_headers'));
  assert.deepEqual(Buffer.from(await response.arrayBuffer()), DATA.subarray(1234, 1234 + 65537));
  const validAfter = await stats(); assert.equal(validAfter.nativeGets - validBefore.nativeGets, 1);
  assert.deepEqual(validAfter.lastOptions, { range: { offset: 1234, length: 65537 }, onlyIf: { etagMatches: etag.slice(1, -1) } });
  passed('one exact native conditional R2 range and authoritative 206 framing');

  const sigKey = KEY.replace('archive-v2-blocks.zstd', 'signatures.bin');
  const sigObject = await bucket.put(sigKey, DATA.subarray(0, 128));
  const sigEtag = sigObject.httpEtag ?? `"${sigObject.etag}"`;
  const sig = await request({ key: sigKey, offset: '64', length: '64', object_length: '128', etag: sigEtag });
  assert.equal(sig.status, 206); assert.deepEqual(Buffer.from(await sig.arrayBuffer()), DATA.subarray(64, 128));
  await rejected({ ...fields, key: KEY.replace('epoch-1090', 'epoch-1091') }, 404, 1);
  await rejected({ ...fields, etag: '"00000000000000000000000000000000"' }, 412, 1);
  await rejected({ ...fields, object_length: String(DATA.length + 1) }, 412, 1);
  for (const value of ['size', 'etag', 'range']) { await mode(value); await rejected(fields, 412, 1); }
  await mode('throw'); await rejected(fields, 502, 1);
  for (const value of ['missing-secret', 'missing-binding']) { await mode(value); await rejected(fields, 503, 0); }
  await mode('normal');
  passed('signature object missing object conditional failure and identity failures keep exact operation receipts');

  await mode('slow');
  const delayedStart = performance.now(); const slow = await request(fields); const headersMs = performance.now() - delayedStart;
  const slowReader = slow.body.getReader(); const first = await slowReader.read(); assert.ok(first.value.length > 0);
  const delayedBeforeEnd = await stats();
  const chunks = [Buffer.from(first.value)];
  while (true) { const next = await slowReader.read(); if (next.done) break; chunks.push(Buffer.from(next.value)); }
  const totalMs = performance.now() - delayedStart;
  assert.deepEqual(Buffer.concat(chunks), DATA.subarray(1234, 1234 + 65537));
  assert.ok(totalMs - headersMs >= 100, 'response starts before the complete body is read');
  assert.ok((await stats()).bodyCompletions > delayedBeforeEnd.bodyCompletions);
  receipt.streaming = { headersMs, totalMs };
  passed('native response streams before EOF with backpressure');

  const cancellationsBefore = (await stats()).cancellations;
  const controller = new AbortController();
  const cancelled = await request(fields, { signal: controller.signal });
  await cancelled.body.getReader().read(); controller.abort();
  for (let i = 0; i < 40 && (await stats()).cancellations === cancellationsBefore; i++) await new Promise(done => setTimeout(done, 10));
  assert.ok((await stats()).cancellations > cancellationsBefore);
  passed('client cancellation reaches the native source stream');

  for (const value of ['short', 'long']) {
    await mode(value); const broken = await request(fields); assert.equal(broken.status, 206); proof(broken, 1);
    await assert.rejects(() => broken.arrayBuffer());
    passed(`${value} source bodies abort instead of completing a valid range`);
  }
  await mode('normal'); const final = await request(fields); assert.equal(final.status, 206);
  assert.deepEqual(Buffer.from(await final.arrayBuffer()), DATA.subarray(1234, 1234 + 65537));
  receipt.status = 'PASSED'; receipt.attempts = (await stats()).attempts;
  passed('reader holds no cached failed body and recovers on the next exact range');
} finally {
  await mf.dispose(); await rm(temporary, { recursive: true, force: true });
  if (process.env.BZ_READER_TEST_RECEIPT) await writeFile(resolve(process.env.BZ_READER_TEST_RECEIPT), `${JSON.stringify(receipt, null, 2)}\n`);
}
console.log(`All ${receipt.checks.length} Foundation reader checks passed. No cloud calls were made.`);
