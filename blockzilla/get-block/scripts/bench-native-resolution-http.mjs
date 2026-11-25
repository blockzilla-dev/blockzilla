#!/usr/bin/env node
// Direct HTTP only. No Worker calls, R2 calls or persistent response cache.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir, stat } from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import { dirname, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';
import { decodeResolution } from './bench-resolution-client.mjs';

const RESOLUTION_TYPE = 'application/vnd.blockzilla.slot-resolution.wincode';
const ID_TYPE = 'application/vnd.blockzilla.resolve-ids+json';
const HOT_TYPE = 'application/vnd.blockzilla.compact-v2-hot.zstd';
const LIMIT = 4 * 1024 * 1024;
const ENV = /^[A-Z][A-Z0-9_]*$/;
const sha = value => createHash('sha256').update(value).digest('hex');
const fault = code => Object.assign(new Error(code), { code });
const check = (condition, code) => { if (!condition) throw fault(code); };

function numberHeader(headers, name) {
  const text = headers[name];
  check(typeof text === 'string' && /^(0|[1-9][0-9]*)$/.test(text), 'INVALID_NUMERIC_HEADER');
  const value = Number(text); check(Number.isSafeInteger(value), 'NUMERIC_HEADER_OVERFLOW'); return value;
}

function safeHeaders(headers) {
  return Object.fromEntries(Object.entries(headers).filter(([name, value]) => name.startsWith('x-bz-foundation-')
    && !/locator|secret|token|authorization/.test(name) && typeof value === 'string' && value.length <= 4096)
    .map(([name, value]) => [name, value.replace(/https?:\/\/[^\s"<>]+/g, '[URL redacted]')]));
}

function hashBytes(value) {
  if (typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)) return Buffer.from(value, 'hex');
  if (Array.isArray(value) && value.length === 32 && value.every(n => Number.isInteger(n) && n >= 0 && n <= 255)) return Buffer.from(value);
  throw fault('INVALID_EXPECTED_HASH');
}

function unsigned(bytes, cursor) {
  let number = 0n, shift = 0n, byte, count = 0;
  do {
    check(cursor.offset < bytes.length && count++ < 5, 'INVALID_DICTIONARY_INTEGER');
    byte = bytes[cursor.offset++]; number |= BigInt(byte & 127) << shift; shift += 7n;
  } while (byte & 128);
  check(number <= 0xffffffffn && (count === 1 || byte !== 0), 'INVALID_DICTIONARY_INTEGER');
  return Number(number);
}

function dictionaries(bytes) {
  const cursor = { offset: 0 }, pubkeys = [], blockhashes = [], votes = [];
  const hash = () => { check(cursor.offset + 32 <= bytes.length, 'TRUNCATED_DICTIONARY'); const value = bytes.subarray(cursor.offset, cursor.offset + 32); cursor.offset += 32; return value; };
  const count = () => { const n = unsigned(bytes, cursor); check(n <= 65536, 'DICTIONARY_COUNT_BOUND'); return n; };
  for (let n = count(); n; n--) pubkeys.push({ id: unsigned(bytes, cursor), value: hash() });
  for (let n = count(); n; n--) { const u = unsigned(bytes, cursor); blockhashes.push({ id: u % 2 ? -(u + 1) / 2 : u / 2, value: hash() }); }
  const optional = () => { const tag = bytes[cursor.offset++]; check(tag === 0 || tag === 1, 'INVALID_VOTE_OPTION'); return tag ? hash() : null; };
  for (let n = count(); n; n--) votes.push({ block_id: unsigned(bytes, cursor), bank_hash: optional(), block_id_hash: optional() });
  check(cursor.offset === bytes.length, 'DICTIONARY_TRAILING_BYTES');
  return { pubkeys, blockhashes, votes };
}

export function validateReply(sample, fixture, manifest, requestDigest, bytes) {
  const h = sample.headers;
  check(sample.status === 200, 'HTTP_STATUS_' + sample.status);
  for (const [name, expected] of [
    ['content-type', RESOLUTION_TYPE], ['x-bz-foundation-protocol', '1'],
    ['x-bz-foundation-source-prefix', manifest.source_prefix], ['x-bz-foundation-generation', manifest.generation],
    ['x-bz-foundation-result', 'resolution'], ['x-bz-foundation-commitment', 'finalized'],
    ['x-bz-foundation-signatures', 'archive'], ['x-bz-foundation-cache', 'BYPASS'],
    ['x-bz-foundation-request-sha256', requestDigest], ['x-bz-foundation-sha256', sha(bytes)],
  ]) check(h[name] === expected, 'RESPONSE_' + name.toUpperCase().replaceAll('-', '_'));
  check(!h['content-encoding'] || h['content-encoding'] === 'identity', 'ENCODED_RESPONSE');
  check(numberHeader(h, 'content-length') === bytes.length && bytes.length <= LIMIT, 'RESPONSE_LENGTH');
  const proof = validateBody(bytes, fixture, manifest);
  const locatorHeader = h['x-bz-foundation-locator'];
  check(typeof locatorHeader === 'string' && /^[A-Za-z0-9_-]{1,4096}$/.test(locatorHeader)
    && sha(Buffer.from(locatorHeader, 'base64url')) === proof.locatorSha256, 'LOCATOR_HEADER_BINDING');
  check(numberHeader(h, 'x-bz-foundation-pread-calls') > 0, 'NO_DIRECT_TABLE_READS');
  numberHeader(h, 'x-bz-foundation-pread-bytes');
  return proof;
}

export function validateBody(bytes, fixture, manifest) {
  check(sha(bytes) === fixture.expected_resolution_sha256, 'EXPECTED_RESOLUTION_SHA');
  const decoded = decodeResolution(bytes, fixture.slot), locator = decoded.locator, request = fixture.request;
  check(locator.sourcePrefix === manifest.source_prefix && locator.generation === manifest.generation, 'MANIFEST_SOURCE_BINDING');
  const source = { version: locator.version, source_prefix: locator.sourcePrefix, generation: locator.generation,
    epoch: locator.epoch, hot: locator.hot, message_schema: locator.messageSchema, metadata_schema: locator.metadataSchema,
    blocks: locator.blocks, signatures: locator.signatures };
  assert.deepEqual(source, request.source, 'SOURCE_DESCRIPTOR_MISMATCH');
  check(locator.parentSlot === fixture.parent_slot && locator.parentSlot === request.references.parent_slot, 'PARENT_SLOT_MISMATCH');
  check(locator.blockhash.equals(hashBytes(fixture.blockhash)), 'CURRENT_HASH_MISMATCH');
  check(locator.previousBlockhash.equals(hashBytes(fixture.previous_blockhash)), 'PREVIOUS_HASH_MISMATCH');
  check(decoded.signatureBytes === fixture.signature_count * 64, 'SIGNATURE_RANGE_LENGTH');
  assert.deepEqual([...decoded.signatureCounts], request.references.signature_counts, 'SIGNATURE_COUNT_ROWS');
  const tables = dictionaries(decoded.suffix), refs = request.references;
  assert.deepEqual(tables.pubkeys.map(v => v.id), refs.pubkeys, 'PUBKEY_ID_SET');
  assert.deepEqual(tables.blockhashes.map(v => v.id), refs.blockhashes, 'BLOCKHASH_ID_SET');
  assert.deepEqual(tables.votes.map(v => ({ block_id: v.block_id, bank_hash: !!v.bank_hash, block_id_hash: !!v.block_id_hash })), refs.votes, 'VOTE_REFERENCE_SET');
  const byHashId = new Map(tables.blockhashes.map(v => [v.id, v.value]));
  check(byHashId.get(refs.blockhash_id)?.equals(locator.blockhash), 'CURRENT_ID_HASH_BINDING');
  if (fixture.slot === 0) check(locator.previousBlockhash.equals(Buffer.alloc(32)), 'GENESIS_PREVIOUS_HASH');
  else {
    const parentId = refs.blockhash_id === 0 && refs.previous_blockhash_id === 0 ? -1 : refs.previous_blockhash_id;
    check(byHashId.get(parentId)?.equals(locator.previousBlockhash), 'ACTUAL_PREVIOUS_ID_HASH_BINDING');
  }
  return { resolutionSha256: sha(bytes), locatorSha256: sha(decoded.locatorBytes),
    pubkeys: tables.pubkeys.length, blockhashes: tables.blockhashes.length, votes: tables.votes.length,
    signatureCount: fixture.signature_count, signatureBytesStored: 0,
    sourceMatched: true, mappingsMatched: true, actualPreviousHashMatched: true };
}

export async function requestOnce(url, token, headers, body, agent, timeoutMs) {
  const started = performance.now(), startedAt = new Date().toISOString();
  return new Promise((done, reject) => {
    let settled = false, timer;
    const finish = (error, value) => { if (settled) return; settled = true; clearTimeout(timer); error ? reject(error) : done(value); };
    const transport = url.protocol === 'https:' ? https : http;
    const request = transport.request(url, { method: 'POST', agent, headers: { ...headers,
      Authorization: 'Bearer ' + token, Accept: RESOLUTION_TYPE, 'Accept-Encoding': 'identity',
      'Content-Length': String(body.length), 'Cache-Control': 'no-store' } }, response => {
      const sample = { startedAt, status: response.statusCode, headers: response.headers,
        headersMs: performance.now() - started, ttfbMs: null, completeMs: null, bytes: 0,
        requestBytes: body.length, socketReused: request.reusedSocket, chunks: [] };
      const length = response.headers['content-length'];
      if (typeof length === 'string' && (/^[0-9]+$/.test(length) ? Number(length) > LIMIT : true)) {
        response.destroy(fault('RESPONSE_LENGTH_BOUND')); return;
      }
      response.on('data', chunk => {
        sample.ttfbMs ??= performance.now() - started; sample.bytes += chunk.length;
        if (sample.bytes > LIMIT) { response.destroy(fault('RESPONSE_BODY_BOUND')); return; }
        sample.chunks.push(chunk);
      });
      response.on('end', () => { sample.completeMs = performance.now() - started; sample.completedAt = new Date().toISOString();
        const bytes = Buffer.concat(sample.chunks, sample.bytes); delete sample.chunks; finish(null, { sample, bytes }); });
      response.on('error', error => finish(error));
      response.on('aborted', () => finish(fault('RESPONSE_ABORTED')));
    });
    request.on('error', error => finish(error));
    timer = setTimeout(() => request.destroy(fault('REQUEST_TIMEOUT')), timeoutMs);
    request.end(body);
  });
}

function summary(values) {
  const numbers = values.filter(Number.isFinite).sort((a, b) => a - b);
  if (!numbers.length) return { n: 0, p50: null, p95: null, mean: null };
  return { n: numbers.length, p50: numbers[Math.ceil(numbers.length * .5) - 1],
    p95: numbers[Math.ceil(numbers.length * .95) - 1], mean: numbers.reduce((a, b) => a + b, 0) / numbers.length };
}

function diagnostics(headers) {
  const result = {};
  for (const [name, value] of Object.entries(headers)) if (/^x-bz-foundation-.*(?:micros|calls|bytes)$/.test(name)
    && typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value) && Number.isSafeInteger(Number(value))) result[name] = Number(value);
  return result;
}

function args(argv) {
  if (argv.length === 1 && argv[0] === '--self-test') return { selfTest: true };
  const valid = new Set(['url', 'token-env', 'token-file', 'fixtures', 'output', 'rounds', 'warmup-rounds', 'timeout-ms', 'max-requests']);
  const a = new Map();
  for (let at = 0; at < argv.length; at += 2) {
    const name = argv[at]?.slice(2), value = argv[at + 1];
    check(argv[at]?.startsWith('--') && valid.has(name) && value && !value.startsWith('--') && !a.has(name), 'INVALID_ARGUMENTS');
    a.set(name, value);
  }
  for (const name of ['url', 'fixtures', 'output']) check(a.has(name), 'MISSING_ARGUMENTS');
  check(a.has('token-env') !== a.has('token-file'), 'ONE_TOKEN_SOURCE_REQUIRED');
  const integer = (key, fallback, minimum, maximum) => {
    const text = a.get(key) ?? String(fallback), value = Number(text);
    check(/^[0-9]+$/.test(text) && Number.isInteger(value) && value >= minimum && value <= maximum, 'INVALID_NUMERIC_ARGUMENT'); return value;
  };
  return { a, rounds: integer('rounds', 10, 1, 100), warmups: integer('warmup-rounds', 1, 0, 10),
    timeoutMs: integer('timeout-ms', 30000, 100, 300000), maxRequests: integer('max-requests', 1000, 2, 10000) };
}

async function boundedFile(path, bound) {
  check((await stat(path)).size <= bound, 'INPUT_FILE_BOUND');
  const bytes = await readFile(path); check(bytes.length <= bound, 'INPUT_FILE_BOUND'); return bytes;
}

export async function main(argv, env = process.env) {
  if (argv[0] === '--validate-python-receipt') return validatePythonReceipt(argv);
  const options = args(argv); if (options.selfTest) return selfTest();
  const a = options.a;
  check(/^@[A-Z][A-Z0-9_]*$/.test(a.get('url')), 'USE_URL_ENV_REFERENCE');
  let base; try { base = new URL(env[a.get('url').slice(1)]); } catch { throw fault('INVALID_URL_ENV'); }
  check((base.protocol === 'https:' || base.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(base.hostname))
    && base.pathname === '/' && !base.username && !base.password && !base.search && !base.hash, 'INVALID_PRIVATE_ENDPOINT');
  if (a.has('token-env')) check(ENV.test(a.get('token-env')), 'INVALID_TOKEN_ENV');
  const token = a.has('token-file') ? (await boundedFile(a.get('token-file'), 2048)).toString('utf8').trimEnd() : env[a.get('token-env')];
  check(typeof token === 'string' && /^[\x21-\x7e]{16,1024}$/.test(token), 'INVALID_TOKEN');
  const output = resolve(a.get('output'));
  try { await stat(output); throw fault('OUTPUT_EXISTS'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const inputPath = resolve(a.get('fixtures')), inputBytes = await boundedFile(inputPath, 16 * 1024 * 1024);
  const manifest = JSON.parse(inputBytes);
  check(manifest.version === 1 && Array.isArray(manifest.fixtures) && manifest.fixtures.length > 0 && manifest.fixtures.length <= 256,
    'INVALID_FIXTURE_MANIFEST');
  check(manifest.raw_signature_bytes_read === 0 && manifest.raw_signature_bytes_stored === 0
    && manifest.resolution_ram_cache === 'not_started_or_used', 'FIXTURE_SCOPE_MISMATCH');
  check(typeof manifest.source_prefix === 'string' && typeof manifest.generation === 'string', 'FIXTURE_SOURCE_MISSING');
  const planned = 2 * manifest.fixtures.length * (options.rounds + options.warmups);
  check(planned <= options.maxRequests, 'REQUEST_BUDGET_EXCEEDED');
  const local = path => resolve(dirname(inputPath), path);
  let totalInputBytes = 0;
  for (const fixture of manifest.fixtures) {
    fixture.hot = await boundedFile(local(fixture.hot_frame), 16 * 1024 * 1024);
    fixture.ids = await boundedFile(local(fixture.request_json_path), LIMIT);
    check(sha(fixture.hot) === fixture.hot_frame_sha256 && sha(fixture.ids) === fixture.request_json_sha256, 'FIXTURE_SHA_MISMATCH');
    check(/^[a-f0-9]{64}$/.test(fixture.expected_resolution_sha256), 'EXPECTED_RESOLUTION_SHA_MISSING');
    fixture.request = JSON.parse(fixture.ids);
    check(fixture.request.version === 1 && fixture.request.source.source_prefix === manifest.source_prefix
      && fixture.request.source.generation === manifest.generation && fixture.request.references.slot === fixture.slot
      && fixture.request.hot_sha256 === fixture.hot_frame_sha256, 'TYPED_FIXTURE_SOURCE_MISMATCH');
    totalInputBytes += fixture.hot.length + fixture.ids.length; check(totalInputBytes <= 80 * 1024 * 1024, 'FIXTURE_MEMORY_BOUND');
  }
  const agent = base.protocol === 'https:' ? new https.Agent({ keepAlive: true, maxSockets: 1, maxFreeSockets: 1 })
    : new http.Agent({ keepAlive: true, maxSockets: 1, maxFreeSockets: 1 });
  const samples = [], pairs = [], startedAt = new Date().toISOString();
  let stopped = false;
  try {
    for (const phase of ['warmup', 'timed']) {
      const rounds = phase === 'warmup' ? options.warmups : options.rounds;
      for (let round = 0; round < rounds && !stopped; round++) for (const [index, fixture] of manifest.fixtures.entries()) {
        let prior;
        const pair = [];
        for (const route of (round + index) % 2 ? ['raw_hot', 'typed_ids'] : ['typed_ids', 'raw_hot']) {
          const url = new URL(route === 'typed_ids' ? '/v1/resolve' : '/v1/resolve-block/' + fixture.slot, base);
          const body = route === 'typed_ids' ? fixture.ids : fixture.hot, bodyDigest = sha(body);
          const headers = { 'Content-Type': route === 'typed_ids' ? ID_TYPE : HOT_TYPE,
            'X-BZ-Foundation-Protocol': '1', 'X-BZ-Foundation-Generation': manifest.generation,
            'X-BZ-Foundation-Source-Prefix': manifest.source_prefix, 'X-BZ-Foundation-Read-Mode': 'full-cold',
            'X-BZ-Foundation-Request-SHA256': bodyDigest };
          let row;
          try {
            const { sample, bytes } = await requestOnce(url, token, headers, body, agent, options.timeoutMs);
            const validationStarted = performance.now(), proof = validateReply(sample, fixture, manifest, bodyDigest, bytes);
            row = { phase, round, route, slot: fixture.slot, epoch: fixture.epoch, ...sample,
              proof, diagnostics: diagnostics(sample.headers), publicHeaders: safeHeaders(sample.headers),
              validationMs: performance.now() - validationStarted, ok: true };
            delete row.headers;
            if (prior) check(prior.equals(bytes), 'ROUTE_MAPPING_BYTES_DIFFER');
            prior = bytes;
          } catch (error) {
            row = { phase, round, route, slot: fixture.slot, epoch: fixture.epoch, ok: false,
              error: /^[A-Z0-9_]{1,100}$/.test(error.code ?? '') ? error.code : 'VALIDATION_OR_TRANSPORT_FAILURE' };
            stopped = true;
          }
          samples.push(row); pair.push(row);
          console.log(JSON.stringify({ event: 'sample', phase, round, route, slot: fixture.slot,
            ok: row.ok, error: row.error, completeMs: row.completeMs, diagnostics: row.diagnostics }));
          if (stopped) break;
        }
        if (pair.length === 2 && pair.every(row => row.ok)) pairs.push({ phase, round, slot: fixture.slot,
          exactResolutionBytesMatch: true, resolutionSha256: pair[0].proof.resolutionSha256 });
        prior = undefined;
        if (stopped) break;
      }
    }
  } finally { agent.destroy(); }
  const groups = [];
  for (const phase of ['warmup', 'timed']) for (const route of ['typed_ids', 'raw_hot']) {
    const rows = samples.filter(row => row.phase === phase && row.route === route && row.ok);
    const diagnosticNames = [...new Set(rows.flatMap(row => Object.keys(row.diagnostics)))].sort();
    groups.push({ phase, route, requests: rows.length,
      headersMs: summary(rows.map(row => row.headersMs)), ttfbMs: summary(rows.map(row => row.ttfbMs)),
      completeMs: summary(rows.map(row => row.completeMs)), requestBytes: summary(rows.map(row => row.requestBytes)),
      replyBytes: summary(rows.map(row => row.bytes)), socketReused: rows.filter(row => row.socketReused).length,
      diagnostics: Object.fromEntries(diagnosticNames.map(name => [name, summary(rows.map(row => row.diagnostics[name]))])) });
  }
  const report = { schema: 'blockzilla.native-resolution-http.v1', status: stopped ? 'FAIL' : 'PASS', startedAt,
    completedAt: new Date().toISOString(), endpoint: '[redacted]', fixtureManifestSha256: sha(inputBytes),
    sourcePrefix: manifest.source_prefix, generation: manifest.generation,
    plan: { fixtures: manifest.fixtures.length, rounds: options.rounds, warmupRounds: options.warmups,
      plannedRequests: planned, timeoutMs: options.timeoutMs, retries: 0, maximumConcurrency: 1,
      order: 'routes alternate first position by round and fixture', persistentConnection: true },
    proof: { requests: samples.length, successful: samples.filter(row => row.ok).length,
      exactMappingPairs: pairs.length, resultCache: 'BYPASS required on every reply', signatureBytesStored: 0 },
    groups, pairs, samples, notes: [
      'This measures the private native service directly. It sends no Worker or R2 requests. A remote HTTPS run includes its TLS/tunnel path; a loopback run does not.',
      'Both routes must reproduce the offline expected ResolutionV1 SHA and exact bytes, ID sets, source row/object identities, signature counts and actual previous blockhash.',
      'The raw route receives only the existing compressed hot frame; the typed route receives the saved ID request. No raw signatures are loaded or sent.',
      'Every response must be Cache:BYPASS and report positive direct table pread calls. There is no decoded-result cache in this harness; only two reply buffers are held briefly for pair equality.',
      'Repeated reads can hit the OS file-page cache. pread calls/bytes do not prove physical disk reads. This is not a physical cold-storage claim.',
      'Server *-Micros headers are elapsed diagnostics unless explicitly named CPU. CPU-Micros covers native synchronous blocking work; it does not include all HTTP/runtime overhead.',
      'Network timing stops at body EOF. Client-side SHA, parsing and mapping checks occur after the network timer.',
      'Reply body data, tokens, locator headers and endpoint URLs are excluded from this report. No redirect is followed, and no request is retried.'
    ] };
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({ event: 'complete', status: report.status, requests: samples.length, exactMappingPairs: pairs.length, output }));
  if (stopped || samples.length !== planned) process.exitCode = 1;
  return report;
}

export async function validatePythonReceipt(argv) {
  const a = new Map();
  for (let at = 0; at < argv.length; at += 2) {
    const name = argv[at]?.slice(2);
    check(['validate-python-receipt', 'validation-dir', 'output'].includes(name) && argv[at + 1] && !a.has(name), 'INVALID_OFFLINE_ARGUMENTS');
    a.set(name, argv[at + 1]);
  }
  check(a.size === 3, 'MISSING_OFFLINE_ARGUMENTS');
  const receiptPath = resolve(a.get('validate-python-receipt')), bodyDir = resolve(a.get('validation-dir'));
  const receipt = JSON.parse(await boundedFile(receiptPath, 64 * 1024 * 1024));
  check(receipt.schema === 'blockzilla.native-resolution-http-python.v1' && receipt.status === 'PASS'
    && Array.isArray(receipt.validation_files) && receipt.validation_files.length > 0, 'INVALID_PYTHON_RECEIPT');
  const filename = path => {
    const value = String(path).split(/[\\/]/).at(-1);
    check(/^slot-[0-9]+\.(?:request\.json|(?:raw_hot|typed_ids)\.resolution\.bin)$/.test(value), 'INVALID_EVIDENCE_FILENAME');
    return value;
  };
  const checks = [];
  for (const entry of receipt.validation_files) {
    const fixture = entry.fixture;
    const request = await boundedFile(resolve(bodyDir, filename(entry.request_json)), LIMIT);
    check(sha(request) === fixture.request_json_sha256, 'OFFLINE_REQUEST_SHA');
    fixture.request = JSON.parse(request);
    const rows = receipt.samples.filter(row => row.ok && row.phase === 'timed' && row.round === 0 && row.slot === fixture.slot);
    check(rows.length === 2 && new Set(rows.map(row => row.route)).size === 2, 'OFFLINE_ROUTE_PAIR_MISSING');
    let previous;
    for (const row of rows) {
      check(row.validation_body, 'OFFLINE_BODY_MISSING');
      const bytes = await boundedFile(resolve(bodyDir, filename(row.validation_body)), LIMIT);
      const proof = validateBody(bytes, fixture, receipt);
      check(proof.locatorSha256 === row.proof.locator_sha256, 'OFFLINE_HTTP_LOCATOR_BINDING');
      if (previous) check(previous.equals(bytes), 'OFFLINE_ROUTE_BYTES_DIFFER');
      previous = bytes;
      checks.push({ slot: fixture.slot, route: row.route, ...proof });
    }
  }
  check(receipt.validation_files.length === receipt.plan.fixtures, 'OFFLINE_FIXTURE_COVERAGE');
  const output = resolve(a.get('output'));
  await mkdir(dirname(output), { recursive: true });
  const report = { schema: 'blockzilla.native-resolution-offline-validation.v1', status: 'PASS',
    receiptSha256: sha(await readFile(receiptPath)), fixtures: receipt.validation_files.length,
    bodies: checks.length, exactMappingPairs: checks.length / 2, rawSignatureBytesStored: 0, checks,
    scope: 'Independent Node Wincode dictionary/source/hash/signature-count validation of saved live HTTP replies. No network call.' };
  await writeFile(output, JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({ status: report.status, fixtures: report.fixtures, bodies: report.bodies, output }));
  return report;
}

async function selfTest() {
  const server = http.createServer((request, response) => {
    if (request.url === '/redirect') { response.writeHead(307, { Location: 'http://outside.invalid/' }); response.end(); }
    else if (request.url === '/timeout') { request.on('close', () => {}); }
    else { response.writeHead(200, { 'Content-Length': '4' }); response.end('test'); }
  });
  await new Promise(done => server.listen(0, '127.0.0.1', done));
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  const base = new URL('http://127.0.0.1:' + server.address().port);
  try {
    const one = await requestOnce(base, 'fixture-private-token-012345', {}, Buffer.from('body'), agent, 1000);
    assert.equal(one.bytes.toString(), 'test');
    const two = await requestOnce(base, 'fixture-private-token-012345', {}, Buffer.from('body'), agent, 1000);
    assert.equal(two.sample.socketReused, true);
    const redirect = await requestOnce(new URL('/redirect', base), 'fixture-private-token-012345', {}, Buffer.alloc(0), agent, 1000);
    assert.equal(redirect.sample.status, 307);
    await assert.rejects(requestOnce(new URL('/timeout', base), 'fixture-private-token-012345', {}, Buffer.alloc(0), agent, 100), e => e.code === 'REQUEST_TIMEOUT');
    assert.equal(safeHeaders({ 'x-bz-foundation-locator': 'private', 'x-bz-foundation-cache': 'BYPASS' })['x-bz-foundation-locator'], undefined);
    console.log(JSON.stringify({ status: 'PASS', keepAlive: true, manualRedirect: true, boundedDeadline: true, locatorOmitted: true }));
  } finally { agent.destroy(); server.closeAllConnections(); await new Promise(done => server.close(done)); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main(process.argv.slice(2)).catch(() => {
  console.error('Native resolution HTTP benchmark stopped. No private endpoint or credential was printed.'); process.exitCode = 1;
});
