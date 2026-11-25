#!/usr/bin/env node

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as miniflare from 'miniflare';

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const REPOSITORY = resolve(PACKAGE_ROOT, '../..');
const SLOT = 470_987_967;
const KEY = 'bz_live_local_profile_abcdefghijklmnopqrstuvwxyz0123456789';
const SECRET = 'local-profile-locator-secret-01234567890123456789';
const ORIGIN = 'https://local-profile.test';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const delay = ms => new Promise(done => setTimeout(done, ms));

function argumentsFrom(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i];
    if (key === '--help') return { help: true };
    if (!['--fixture', '--build', '--output', '--samples', '--warmup', '--runtime'].includes(key)
      || !argv[i + 1] || argv[i + 1].startsWith('--') || args[key.slice(2)]) throw new Error('Invalid argument; use --help.');
    args[key.slice(2)] = argv[++i];
  }
  for (const [name, fallback, maximum] of [['samples', 10, 30], ['warmup', 2, 5]]) {
    args[name] = Number(args[name] ?? fallback);
    assert.ok(Number.isInteger(args[name]) && args[name] >= 1 && args[name] <= maximum, `bounded ${name}`);
  }
  return args;
}

function summary(samples) {
  const quantile = (field, fraction) => {
    const sorted = samples.map(value => value[field]).sort((a, b) => a - b);
    const index = (sorted.length - 1) * fraction;
    return Number((sorted[Math.floor(index)] + (sorted[Math.ceil(index)] - sorted[Math.floor(index)]) * (index % 1)).toFixed(3));
  };
  return { count: samples.length, headers_ms: { p50: quantile('headersMs', .5), p95: quantile('headersMs', .95) },
    first_byte_ms: { p50: quantile('firstByteMs', .5), p95: quantile('firstByteMs', .95) },
    total_ms: { p50: quantile('totalMs', .5), p95: quantile('totalMs', .95) } };
}

// This control compares I/O and native binary assembly only. It has no JSON codec.
const JS_IO_CONTROL = String.raw`
const utf8 = new TextEncoder();
const hex = bytes => Array.from(new Uint8Array(bytes), x => x.toString(16).padStart(2, '0')).join('');
const hash = async bytes => hex(await crypto.subtle.digest('SHA-256', bytes));
const hmac = async (key, text) => crypto.subtle.sign('HMAC', await crypto.subtle.importKey('raw', key,
  { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']), utf8.encode(text));
const leb = value => { let n = BigInt(value); const bytes = []; do { let b = Number(n & 127n); n >>= 7n;
  if (n) b |= 128; bytes.push(b); } while (n); return new Uint8Array(bytes); };
const concat = (...parts) => { const bytes = new Uint8Array(parts.reduce((n,p) => n+p.length,0));
  let at=0; for (const part of parts) { bytes.set(part,at); at+=part.length; } return bytes; };
async function signedGet(env, path, size, identity) {
  const uri = '/' + env.BZ_S3_BUCKET + '/' + path;
  const url = env.BZ_S3_ENDPOINT + uri;
  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
  const date = stamp.slice(0,8); const host = new URL(url).host;
  const canonicalHeaders = 'host:' + host + '\nx-amz-content-sha256:UNSIGNED-PAYLOAD\nx-amz-date:' + stamp + '\n';
  const names = 'host;x-amz-content-sha256;x-amz-date';
  const canonical = 'GET\n' + uri + '\n\n' + canonicalHeaders + '\n' + names + '\nUNSIGNED-PAYLOAD';
  const scope = date + '/auto/s3/aws4_request';
  const toSign = 'AWS4-HMAC-SHA256\n' + stamp + '\n' + scope + '\n' + await hash(utf8.encode(canonical));
  let key = utf8.encode('AWS4' + env.BZ_S3_SECRET_ACCESS_KEY);
  for (const part of [date, 'auto', 's3', 'aws4_request']) key = await hmac(key, part);
  const authorization = 'AWS4-HMAC-SHA256 Credential=' + env.BZ_S3_ACCESS_KEY_ID + '/' + scope
    + ', SignedHeaders=' + names + ', Signature=' + hex(await hmac(key,toSign));
  const response = await fetch(url, { headers: { Authorization: authorization, 'X-Amz-Date': stamp,
    'X-Amz-Content-Sha256': 'UNSIGNED-PAYLOAD', Range: 'bytes=0-' + (size-1), 'If-Match': identity.etag } });
  if (response.status !== 206 || response.headers.get('ETag') !== identity.etag
      || response.headers.get('Content-Length') !== String(size)
      || response.headers.get('Content-Range') !== 'bytes 0-' + (size-1) + '/' + identity.length) throw Error('Invalid control source range');
  return response.body;
}
async function sourceBody(env, descriptor, file, size) {
  const path = descriptor.source_prefix + '/epoch-' + descriptor.epoch + '/' + file;
  const identity = descriptor.objects[file];
  if (env.BZ_ARCHIVE_SOURCE === 's3') return signedGet(env,path,size,identity);
  const object = await env.BZ_ARCHIVE_BUCKET.get(path, { range: { offset:0,length:size }, onlyIf: { etagMatches:identity.etag.slice(1,-1) } });
  if (!object || !object.body || object.httpEtag !== identity.etag || object.size !== identity.length) throw Error('Invalid control R2 range');
  return object.body;
}
export default {
  async fetch(request, env, ctx) {
    const token = request.headers.get('Authorization')?.replace(/^Bearer /,'');
    const auth = token && await env.BZ_RPC_API_KEYS.get(await hash(utf8.encode(token)), 'json');
    if (!auth || auth.status !== 'enabled') return new Response('Unauthorized',{status:401});
    const d = JSON.parse(env.LOCAL_DESCRIPTOR);
    const key = env.BZ_RESOLUTION_PREFIX + '/epoch-' + d.epoch + '/slot-' + d.hot_row.slot + '.resolution.v1';
    const object = await env.BZ_RESOLUTION.get(key);
    if (!object || object.size > 4*1024*1024) throw Error('Missing bounded control resolution');
    const bytes = new Uint8Array(await object.arrayBuffer());
    if (await hash(bytes) !== env.LOCAL_RESOLUTION_SHA256) throw Error('Invalid control resolution SHA256');
    const view = new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength);
    const prefix = bytes.subarray(view.getUint32(20,true), view.getUint32(20,true)+view.getUint32(24,true));
    const suffix = bytes.subarray(view.getUint32(28,true), view.getUint32(28,true)+view.getUint32(32,true));
    const hotLength = d.hot_row.compressed_len; const signatureLength = d.hot_row.signature_count*64;
    const [hot,sigs] = await Promise.all([sourceBody(env,d,'archive-v2-blocks.zstd',hotLength),sourceBody(env,d,'signatures.bin',signatureLength)]);
    const leading = concat(leb(1),leb(d.hot_row.slot),new Uint8Array([1]),leb(hotLength));
    const middle = concat(new Uint8Array([0,1]),leb(prefix.length+signatureLength+suffix.length),prefix);
    const parts = [leading,{body:hot,length:hotLength},middle,{body:sigs,length:signatureLength},suffix];
    const total = leading.length+hotLength+middle.length+signatureLength+suffix.length;
    let position=0;
    const joined = new ReadableStream({
      async pull(controller) {
        try { while(position<parts.length) {
          const part=parts[position];
          if(part instanceof Uint8Array) { position++; if(part.length) { controller.enqueue(part); return; } continue; }
          part.reader ??= part.body.getReader(); part.seen ??= 0;
          const next=await part.reader.read();
          if(next.done) { if(part.seen!==part.length) throw Error('Short control source'); part.reader.releaseLock(); position++; continue; }
          part.seen+=next.value.byteLength; if(part.seen>part.length) throw Error('Long control source');
          controller.enqueue(next.value); return;
        } controller.close(); } catch(error) { controller.error(error); }
      },
      async cancel(reason) { await Promise.allSettled(parts.filter(x=>x.body).map(x=>x.reader?x.reader.cancel(reason):x.body.cancel(reason))); }
    },{highWaterMark:0});
    const fixed=new FixedLengthStream(total); ctx.waitUntil(joined.pipeTo(fixed.writable));
    return new Response(fixed.readable,{headers:{'Content-Type':'application/vnd.blockzilla.get-block-bundle.wincode',
      'Cache-Control':'private, no-store','X-Blockzilla-Control':'javascript-native-binary-only'}});
  }
};
`;

export async function createLocalWorkerHarness(options = {}) {
  const fixture = resolve(options.fixture ?? '/tmp/blockzilla-resolution-real-slot-fixture-20261121');
  const build = resolve(options.build ?? join(PACKAGE_ROOT, 'build/index.js'));
  const backend = options.backend ?? 'r2';
  const runtime = options.runtime ?? 'wasm';
  assert.ok(['wasm', 'js-control'].includes(runtime));
  assert.ok(['r2', 's3', 'native-reader'].includes(backend));
  assert.ok(backend !== 'native-reader' || runtime === 'wasm', 'native reader needs the actual WASM front end');
  const manifest = JSON.parse(await readFile(join(fixture, 'fixture.json'), 'utf8'));
  const descriptor = JSON.parse(await readFile(join(fixture, manifest.descriptor), 'utf8'));
  assert.equal(manifest.slot, SLOT);
  const [hot, signatures, resolutionBytes, bundle, oracleBytes, wasm] = await Promise.all([
    readFile(join(fixture, manifest.hot)), readFile(join(fixture, manifest.signatures)),
    readFile(join(fixture, manifest.resolution)), readFile(join(fixture, manifest.bundle)),
    readFile(join(REPOSITORY, `reports/get-block-cold-profile-20261121/oracle-base64-${SLOT}.json`)),
    readFile(join(dirname(build), 'index_bg.wasm')),
  ]);
  const oracle = JSON.parse(oracleBytes);
  const temporary = await mkdtemp(join(tmpdir(), 'blockzilla-local-profile-'));
  const sourceEvents = []; let active = 0; let serial = 0;
  let delayMs = options.delayMs ?? 0;
  let sourceFault = options.sourceFault ?? null;
  let server; let connectionSerial = 0;
  const connectionIds = new WeakMap(); const connectionEvents = [];
  const clockStarted = performance.now();
  const relative = () => Number((performance.now() - clockStarted).toFixed(3));
  if (backend === 's3') {
    server = createServer(async (request, response) => {
      const file = request.url?.split('/').at(-1);
      const bytes = file === 'archive-v2-blocks.zstd' ? hot : file === 'signatures.bin' ? signatures : undefined;
      const identity = descriptor.objects[file];
      if (request.method !== 'GET' || !bytes || !identity || request.headers['if-match'] !== identity.etag
          || request.headers.range !== `bytes=0-${bytes.length - 1}`) {
        response.writeHead(400).end('Invalid bounded local range request'); return;
      }
      const event = { id: ++serial, kind: file, enteredMs: relative(), delayMs, activeOnStart: ++active,
        connectionId: connectionIds.get(request.socket), remotePort: request.socket.remotePort,
        httpVersion: request.httpVersion, connectionHeader: request.headers.connection ?? null };
      sourceEvents.push(event);
      let finished = false;
      const finish = () => { if (finished) return; finished = true; event.completedMs = relative(); event.activeOnEnd = --active; };
      response.on('finish', finish); response.on('close', finish);
      await delay(event.delayMs);
      event.headersMs = relative();
      response.writeHead(206, { ETag: identity.etag, 'Content-Length': String(bytes.length),
        'Content-Range': `bytes 0-${bytes.length - 1}/${bytes.length}`, 'Content-Type': 'application/octet-stream' });
      if (sourceFault === 'truncate-hot' && file === 'archive-v2-blocks.zstd') {
        event.truncated = true; response.flushHeaders(); response.write(bytes.subarray(0, -1));
        setTimeout(() => response.destroy(), 5);
      } else response.end(bytes);
    });
    server.on('connection', socket => {
      const event = { id: ++connectionSerial, remotePort: socket.remotePort, openedMs: relative() };
      connectionIds.set(socket, event.id); connectionEvents.push(event);
      socket.on('close', () => { event.closedMs = relative(); });
    });
    await new Promise((done, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', done); });
  }
  const bindings = {
    BZ_ARCHIVE_SOURCE: backend === 'native-reader' ? 'r2' : backend, BZ_ARCHIVE_LAYOUT: 'stored', BZ_ARCHIVE_PREFIX: manifest.source_prefix,
    BZ_ARCHIVE_GENERATION: 'local-profile-original-v1', BZ_HTTP_GET_ONLY: 'true',
    BZ_AUTH_CACHE_SCOPE: 'local-profile-keys-v1',
    BZ_RESOLUTION_PREFIX: manifest.resolution_prefix, BZ_RESOLUTION_GENERATION: manifest.generation,
    BZ_RESOLUTION_SLOTS: String(SLOT), BZ_LOCATOR_SECRET: SECRET,
    ...(backend === 'native-reader' ? {
      BZ_NATIVE_READER_URL: 'https://foundation-reader.test/v1/range',
      BZ_NATIVE_READER_SECRET: options.nativeReaderSecret ?? 'local-native-reader-shared-secret-01234567890123456789',
    } : {}),
    ...(server ? { BZ_S3_ENDPOINT: `http://127.0.0.1:${server.address().port}`, BZ_S3_BUCKET: 'local-source',
      BZ_S3_REGION: 'auto', BZ_S3_ACCESS_KEY_ID: 'local-test-only', BZ_S3_SECRET_ACCESS_KEY: 'local-test-only-secret' } : {}),
  };
  let controlPath;
  if (runtime === 'js-control') {
    controlPath = join(temporary, 'local-io-control.mjs');
    await writeFile(controlPath, JS_IO_CONTROL);
    bindings.LOCAL_DESCRIPTOR = JSON.stringify(descriptor);
    bindings.LOCAL_RESOLUTION_SHA256 = sha(resolutionBytes);
  }
  const v4 = {
    modules: runtime === 'wasm' ? [{ type: 'ESModule', path: build }, { type: 'CompiledWasm', path: join(dirname(build), 'index_bg.wasm') }]
      : [{ type: 'ESModule', path: controlPath }],
    modulesRoot: runtime === 'wasm' ? dirname(build) : temporary, name: 'blockzilla-get-block-local-profile', compatibilityDate: '2026-09-10',
    resourcePersistencePath: join(temporary, 'storage'), telemetry: { enabled: false }, bindings,
    r2Buckets: { BZ_ARCHIVE_BUCKET: 'local-profile-source', BZ_RESOLUTION: 'local-profile-resolution' },
    kvNamespaces: { BZ_RPC_API_KEYS: 'local-profile-keys' },
    analyticsEngineDatasets: { BZ_RPC_METRICS: { dataset: 'local-profile-metrics' } },
    ...(options.inspectorPort !== undefined ? { inspectorPort: options.inspectorPort } : {}),
  };
  let configured = v4;
  if (backend === 'native-reader') {
    const { resourcePersistencePath, telemetry, inspectorPort, ...owner } = v4;
    owner.outboundService = 'foundation-reader-fixture';
    owner.compatibilityFlags = ['global_fetch_strictly_public'];
    const readerPath = join(REPOSITORY, 'edgezilla/foundation-reader/src/worker.mjs');
    const readerCorePath = join(REPOSITORY, 'edgezilla/foundation-reader/src/index.mjs');
    configured = { resourcePersistencePath, telemetry,
      ...(inspectorPort === undefined ? {} : { inspectorPort }),
      workers: [owner, {
        name: 'foundation-reader-fixture', compatibilityDate: '2026-09-10',
        modules: [{ type: 'ESModule', path: readerPath }, { type: 'ESModule', path: readerCorePath }], modulesRoot: dirname(readerPath),
        bindings: { BZ_READER_SECRET: options.foundationReaderSecret ?? 'local-native-reader-shared-secret-01234567890123456789' },
        r2Buckets: { FOUNDATION_ARCHIVE: 'local-profile-source' },
      }],
    };
  }
  const mf = new miniflare.Miniflare(typeof miniflare.convertV4MiniflareOptions === 'function'
    ? miniflare.convertV4MiniflareOptions(configured) : configured);
  options.onStage?.('runtime-starting');
  const runtimeOrigin = (await mf.ready).origin;
  options.onStage?.('runtime-ready');
  const source = await mf.getR2Bucket('BZ_ARCHIVE_BUCKET');
  options.onStage?.('source-binding-ready');
  for (const [file, bytes] of [['archive-v2-blocks.zstd', hot], ['signatures.bin', signatures]]) {
    const object = await source.put(`${manifest.source_prefix}/epoch-${descriptor.epoch}/${file}`, bytes);
    assert.equal(object.httpEtag ?? `"${object.etag}"`, descriptor.objects[file].etag);
  }
  await (await mf.getR2Bucket('BZ_RESOLUTION')).put(`${manifest.resolution_prefix}/epoch-${descriptor.epoch}/slot-${SLOT}.resolution.v1`, resolutionBytes);
  await (await mf.getKVNamespace('BZ_RPC_API_KEYS')).put(sha(KEY), JSON.stringify({ keyId: 'local_profile', customerId: 'local', label: 'Local profile', status: 'enabled' }));
  options.onStage?.('fixture-ready');
  const workerSource = await readFile(join(PACKAGE_ROOT, 'src/worker.rs'), 'utf8');
  const renderer = workerSource.match(/api_key_digest\(&format!\("(direct-render-[^"\\]+)\\0\{identity\}"\)\)/)?.[1];
  assert.ok(renderer, 'read source cache version for exact local cache invalidation');
  const fields = ['BZ_ARCHIVE_SOURCE', 'BZ_ARCHIVE_PREFIX', 'BZ_ARCHIVE_GENERATION', 'BZ_ARCHIVE_LAYOUT', 'BZ_SLOT_INDEX',
    'BZ_R2_BUCKET_BINDING', 'BZ_S3_ENDPOINT', 'BZ_S3_BUCKET', 'BZ_MESSAGE_SCHEMA_OVERRIDES', 'BZ_METADATA_SCHEMA',
    'BZ_RESOLUTION_PREFIX', 'BZ_RESOLUTION_GENERATION', 'BZ_RESOLUTION_BUCKET_BINDING', 'BZ_RESOLUTION_SLOTS', 'BZ_LOCATOR_SECRET',
    'BZ_NATIVE_READER_URL', 'BZ_NATIVE_READER_SECRET'];
  const generation = sha(`${renderer}\0${fields.map(field => `${field}=${bindings[field] ?? ''}`).join('\0')}`);
  const cacheKey = kind => `${ORIGIN}/__blockzilla-cache/v1/${generation}/block/${SLOT}.${kind === 'json' ? 'json?rewards=0' : 'bin?access=access'}`;
  const clearResponseCache = async kind => {
    const caches = await mf.getCaches();
    await caches.default.delete(cacheKey(kind));
  };
  let lastRead = { phase: 'idle' };
  const read = async (kind, readOptions = {}) => {
    assert.ok(['json', 'bin'].includes(kind));
    assert.ok(runtime === 'wasm' || kind === 'bin', 'JavaScript control has no JSON codec');
    const profile = readOptions.profile ?? true;
    assert.ok([true, false, 'source'].includes(profile), 'bounded cache profile mode');
    const profileQuery = profile === 'source' ? 'profile=source' : profile ? 'profile=1' : '';
    const path = `/block/${SLOT}.${kind}?${kind === 'json' ? 'rewards=false&' : ''}${profileQuery}${readOptions.buffered ? '&profile_body=buffered' : ''}`;
    const sourceStart = sourceEvents.length;
    const started = performance.now(); lastRead = { phase: 'dispatch', startedMs: relative() };
    const transport = readOptions.transport ?? 'dispatch';
    const target = transport === 'http' ? `${runtimeOrigin}${path}` : `${ORIGIN}${path}`;
    const fetcher = transport === 'http' ? fetch : mf.dispatchFetch;
    const response = await fetcher(target, { headers: { Authorization: `Bearer ${KEY}` }, signal: AbortSignal.timeout(readOptions.timeoutMs ?? 30_000) });
    lastRead.phase = 'body'; lastRead.headersAtMs = relative();
    const headersMs = performance.now() - started;
    const headers = Object.fromEntries([...response.headers].filter(([name]) => name.startsWith('x-blockzilla-') || name === 'server-timing'));
    const reader = response.body.getReader(); const chunks = []; let firstByteMs; let length = 0;
    try {
      while (true) {
        const chunk = await reader.read(); if (chunk.done) break;
        if (chunk.value.byteLength && firstByteMs === undefined) firstByteMs = performance.now() - started;
        chunks.push(Buffer.from(chunk.value.buffer, chunk.value.byteOffset, chunk.value.byteLength)); length += chunk.value.byteLength;
        lastRead.receivedBytes = length;
      }
    } catch (error) {
      error.localReceipt = { status: response.status, headers, totalMs: performance.now() - started,
        receivedBytes: length, sourceEvents: sourceEvents.slice(sourceStart).map(value => ({ ...value })) };
      throw error;
    }
    lastRead.phase = 'complete';
    const totalMs = performance.now() - started;
    const bytes = Buffer.concat(chunks, length);
    assert.equal(response.status, 200, bytes.toString().slice(0, 300));
    if (kind === 'json') assert.deepEqual(JSON.parse(bytes).result, oracle.result);
    else assert.deepEqual(bytes, bundle);
    const events = sourceEvents.slice(sourceStart).map(value => ({ ...value }));
    return { headersMs, firstByteMs: firstByteMs ?? totalMs, totalMs, bytes: bytes.length, sha256: sha(bytes),
      status: response.status, headers, profile, sourceEvents: events };
  };
  const close = async () => {
    await mf.dispose();
    if (server) await new Promise(done => server.close(done));
    await rm(temporary, { recursive: true, force: true });
  };
  return { mf, read, getLastRead() { return { ...lastRead }; }, clearResponseCache, setSourceDelay(ms) { assert.ok([0, 100, 250].includes(ms)); delayMs = ms; },
    setSourceFault(value) { assert.ok([null, 'truncate-hot'].includes(value)); sourceFault = value; },
    sourceEvents, connectionEvents, clearSourceEvents() { assert.equal(active, 0); sourceEvents.length = 0; }, close,
    artifact: { control_source_sha256: runtime === 'js-control' ? sha(JS_IO_CONTROL) : undefined, wasm_sha256: sha(wasm), wasm_bytes: wasm.length, renderer, build, fixture, backend, runtime,
      hot_bytes: hot.length, signature_bytes: signatures.length, resolution_bytes: resolutionBytes.length } };
}

async function main() {
  const args = argumentsFrom(process.argv.slice(2));
  if (args.help) { console.log('Usage: node scripts/profile-local-worker.mjs [--fixture DIR] [--build build/index.js] [--output report.json] [--samples 10] [--warmup 2] [--runtime wasm|js-control]\nUses saved real slot bytes only. Local R2 baseline and loopback-only S3 delay controls. No build, deployment, or external requests.'); return; }
  const runtime = args.runtime ?? 'wasm'; assert.ok(['wasm', 'js-control'].includes(runtime));
  const output = resolve(args.output ?? join(REPOSITORY, 'reports/get-block-base64-20261121/local-worker-profile.json'));
  const report = { status: 'RUNNING', runtime, slot: SLOT, started_at: new Date().toISOString(), samples: args.samples, warmup: args.warmup,
    scope: runtime === 'wasm' ? 'Actual release WASM in local Miniflare/workerd; original saved block; local R2 and loopback-only HTTP controls; no external network'
      : 'Pure JavaScript native-binary I/O control in Miniflare/workerd; exact original bundle and same local sources; no JSON codec or external network',
    limitations: ['Local compatibility date2026-09-10 differs from production2026-11-21.',
      'Local wall times include Miniflare and client body transfer; they are not hosted Worker CPU measurements.',
      'Loopback TCP reuse does not prove hosted Cloudflare-to-R2 connection reuse.'],
    timing: 'Node client dispatch-to-headers, first body chunk, and complete body. Correctness checks and JSON parsing occur after timing. These are wall times, not CPU.', scenarios: [] };
  await mkdir(dirname(output), { recursive: true });
  const save = () => writeFile(output, `${JSON.stringify(report, null, 2)}\n`);
  const sample = async (harness, kind, condition) => {
    for (let i = 0; i < args.warmup; i += 1) await harness.read(kind, { profile: condition === 'origin' });
    if (condition !== 'origin') {
      for (let attempt = 0; attempt < 30; attempt += 1) {
        const warmed = await harness.read(kind, { profile: false });
        if (warmed.headers['x-blockzilla-cache'] === 'HIT') break;
        assert.ok(attempt < 29, 'local response cache warms'); await delay(10);
      }
    }
    const rows = [];
    for (let i = 0; i < args.samples; i += 1) {
      if (condition === 'archive-cache') await harness.clearResponseCache(kind);
      const row = await harness.read(kind, { profile: condition === 'origin' });
      if (condition === 'response-hit') {
        assert.equal(row.headers['x-blockzilla-cache'], 'HIT');
        assert.equal(row.headers['x-blockzilla-billable-reads'], '0');
      }
      rows.push(row);
      if (condition === 'archive-cache') await delay(10);
    }
    return { kind, condition, summary: summary(rows), samples: rows };
  };
  for (const backend of ['r2', 's3']) {
    const harness = await createLocalWorkerHarness({ fixture: args.fixture, build: args.build, backend, runtime });
    report.artifact ??= harness.artifact;
    try {
      if (backend === 'r2') {
        for (const kind of runtime === 'wasm' ? ['json', 'bin'] : ['bin']) for (const condition of runtime === 'wasm' ? ['origin', 'response-hit', 'archive-cache'] : ['origin']) {
          const result = await sample(harness, kind, condition);
          report.scenarios.push({ backend, ...result }); await save();
          console.log(JSON.stringify({ backend, kind, condition, ...result.summary }));
        }
      } else {
        for (const delayMs of [0, 100, 250]) {
          harness.setSourceDelay(delayMs);
          for (const kind of runtime === 'wasm' ? ['json', 'bin'] : ['bin']) {
            const result = await sample(harness, kind, 'origin');
            for (const row of result.samples) {
              assert.equal(row.sourceEvents.length, 2, 'exactly two loopback source ranges');
              if (delayMs) assert.equal(Math.max(...row.sourceEvents.map(event => event.activeOnStart)), 2, 'source delays overlap');
            }
            report.scenarios.push({ backend, source_delay_ms: delayMs, ...result }); await save();
            console.log(JSON.stringify({ backend, delayMs, kind, ...result.summary }));
          }
        }
      }
    } finally {
      await harness.close();
      if (backend === 's3') report.source_connections = harness.connectionEvents;
    }
  }
  report.status = 'PASSED'; report.completed_at = new Date().toISOString(); await save();
  console.log(`Saved ${output}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(error); process.exitCode = 1; });
}
