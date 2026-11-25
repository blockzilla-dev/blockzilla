#!/usr/bin/env node
// Archive-ready input -> live buffers -> immutable segments -> Worker response.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import * as miniflare from 'miniflare';

const options = { oracle: [] };
for (let i = 2; i < process.argv.length; i += 2) {
  const key = process.argv[i]?.slice(2);
  const value = process.argv[i + 1];
  assert.ok(key && value, 'Arguments must use --name value pairs.');
  if (key === 'oracle') options.oracle.push(value);
  else options[key] = value;
}
for (const key of ['locator', 'token-file', 'admin-token-file', 'catalog-id', 'build', 'fixtures', 'plan', 'manifests']) {
  assert.ok(options[key], `Missing --${key}.`);
}
assert.ok(['update', 'recovered'].includes(options.phase ?? 'update'));
const token = (await readFile(options['token-file'], 'utf8')).trim();
const adminToken = (await readFile(options['admin-token-file'], 'utf8')).trim();
const inputPlan = JSON.parse(await readFile(options.plan, 'utf8'));
const sourceManifests = JSON.parse(await readFile(options.manifests, 'utf8'));
const oracles = (await Promise.all(options.oracle.map(path => readFile(path, 'utf8'))))
  .flatMap(text => text.trim().split('\n').filter(Boolean).map(line => JSON.parse(line)));
const epochs = [...new Set(oracles.map(row => Math.floor(row.slot / 432_000)))];
assert.equal(epochs.length, 2, 'This acceptance uses two independent CAR blocks.');
const prefixes = new Map(epochs.map(epoch => [epoch, options['archive-prefix'] ?? `live-acceptance/generation-${epoch}`]));
const temporary = await mkdtemp(join(tmpdir(), 'blockzilla-live-worker-'));
const apiKey = `bz_live_${randomBytes(32).toString('base64url')}`;
const native = async (path, data, expected = 200) => {
  const response = await fetch(`${options.locator}${path}`, {
    method: data === undefined ? 'GET' : 'POST',
    headers: { authorization: `Bearer ${['/v2/ingest', '/v2/seal'].includes(path) ? adminToken : token}`, 'content-type': 'application/json' },
    ...(data === undefined ? {} : { body: JSON.stringify(data) }),
  });
  const text = await response.text();
  assert.equal(response.status, expected, `${path}: ${text}`);
  return JSON.parse(text);
};
let mode = 'normal';
let falseCandidate;
const proxy = createServer(async (request, response) => {
  try {
    assert.equal(request.url, '/v2/lookup');
    assert.equal(request.headers.authorization, `Bearer ${token}`);
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const requestBody = JSON.parse(Buffer.concat(chunks));
    const body = await native('/v2/lookup', requestBody);
    if (mode === 'false-before-hit') body.candidates.unshift(falseCandidate);
    if (mode === 'wrong-identity') body.catalog_id = 'f'.repeat(64);
    if (mode === 'unsafe-prefix') body.candidates[0].archive_prefix = '../other';
    if (mode === 'too-many') body.candidates = Array(33).fill(falseCandidate);
    if (mode === 'source-error') body.candidates.unshift({ ...falseCandidate, archive_prefix: 'missing-generation' });
    response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(body));
  } catch (error) {
    console.error(`live locator proxy: ${error.message}`);
    response.writeHead(502).end('{}');
  }
});
const sockets = new Set();
proxy.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
await new Promise(done => proxy.listen(0, '127.0.0.1', done));
const build = resolve(options.build);
const mfOptions = {
  modules: [{ type: 'ESModule', path: build }, { type: 'CompiledWasm', path: join(dirname(build), 'index_bg.wasm') }],
  modulesRoot: dirname(build), name: 'transaction-live-acceptance', compatibilityDate: '2026-09-10',
  resourcePersistencePath: join(temporary, 'storage'), telemetry: { enabled: false },
  bindings: {
    BZ_ARCHIVE_SOURCE: 'r2', BZ_ARCHIVE_LAYOUT: 'stored', BZ_ARCHIVE_PREFIX: 'unused-default',
    BZ_ARCHIVE_GENERATION: 'live-acceptance', BZ_SLOT_INDEX: 'sparse', BZ_R2_BUCKET_BINDING: 'BZ_ARCHIVE_BUCKET',
    BZ_SIGNATURE_INDEX_URL: `http://127.0.0.1:${proxy.address().port}`,
    BZ_SIGNATURE_INDEX_TOKEN: token, BZ_SIGNATURE_CATALOG_ID: options['catalog-id'], BZ_SIGNATURE_CLUSTER_ID: 'mainnet-beta',
  },
  kvNamespaces: { BZ_RPC_API_KEYS: 'live-test-keys' }, r2Buckets: { BZ_ARCHIVE_BUCKET: 'live-test-archive' },
  analyticsEngineDatasets: { BZ_RPC_METRICS: { dataset: 'live_transaction_test_metrics' } },
};
const mf = new miniflare.Miniflare(typeof miniflare.convertV4MiniflareOptions === 'function'
  ? miniflare.convertV4MiniflareOptions(mfOptions) : mfOptions);
let requestId = 0;
const logProjectionRecords = new Map();
async function rpc(row, encoding = 'base64') {
  const id = ++requestId;
  const response = await mf.dispatchFetch('https://live.test/', {
    method: 'POST', headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id, method: 'getTransaction', params: [typeof row === 'string' ? row : row.signature, { encoding, maxSupportedTransactionVersion: 1 }] }),
  });
  const body = await response.json();
  assert.equal(body.id, id);
  assert.equal(response.headers.get('Cache-Control'), 'private, no-store');
  return body;
}
async function exact(row) {
  const body = await rpc(row);
  assert.ok(body.result, JSON.stringify(body.error));
  assert.equal(body.result.slot, row.slot);
  assert.deepEqual(body.result.transaction, row.transaction, `Signed CAR bytes: ${row.slot}/${row.tx_index}`);
  assert.equal(body.result.meta?.fee, row.meta?.fee);
  assert.equal(body.result.meta?.err != null, Boolean(row.meta?.error_present));
  assert.deepEqual(body.result.meta?.preBalances, row.meta?.preBalances);
  assert.deepEqual(body.result.meta?.postBalances, row.meta?.postBalances);
  assert.deepEqual(body.result.meta?.loadedAddresses, row.meta?.loadedAddresses);
  for (const field of ['computeUnitsConsumed', 'costUnits']) {
    if (row.meta?.[field] != null) assert.equal(body.result.meta[field], row.meta[field]);
  }
  const actualLogs = body.result.meta?.logMessages;
  const originalLogs = row.meta?.logMessages;
  if (options['allow-trailing-space-projection'] === 'true' && Array.isArray(actualLogs) && Array.isArray(originalLogs)) {
    assert.equal(actualLogs.length, originalLogs.length);
    for (let index = 0; index < originalLogs.length; index++) {
      if (actualLogs[index] === originalLogs[index]) continue;
      assert.equal(actualLogs[index], originalLogs[index].replace(/[ \t\r\n]+$/u, ''));
      const removed = originalLogs[index].slice(actualLogs[index].length);
      assert.ok(removed.length);
      logProjectionRecords.set(`${row.signature}:${index}`, { slot: row.slot, tx_index: row.tx_index, signature: row.signature,
        line_index: index, removed_suffix_utf8_hex: Buffer.from(removed).toString('hex'), original_line: originalLogs[index], actual_line: actualLogs[index] });
    }
  } else assert.deepEqual(actualLogs, originalLogs);
  return body.result;
}
const receipt = {
  status: 'RUNNING', phase: options.phase ?? 'update', source: 'original CAR signed bytes + native live HTTP + release Worker WASM + local R2',
  catalog_id: options['catalog-id'], worker_wasm_sha256: createHash('sha256').update(await readFile(join(dirname(build), 'index_bg.wasm'))).digest('hex'),
  checks: [], snapshots: [],
};
const check = message => { receipt.checks.push(message); console.log(`PASS ${message}`); };
async function snapshot(stage) {
  const info = await native('/v2/info');
  receipt.snapshots.push({ stage, ...info });
  return info;
}
const ingest = async (epoch, cursor) => native('/v2/ingest', {
  cursor, archive_prefix: prefixes.get(epoch),
  plan: { ...inputPlan, sources: inputPlan.sources.filter(source => source.epoch === epoch).map(source => ({
    ...source, expected_generation_digest: sourceManifests.find(manifest => manifest.epoch === epoch).generation_digest,
  })) },
});
try {
  const bucket = await mf.getR2Bucket('BZ_ARCHIVE_BUCKET');
  for (const manifest of sourceManifests) {
    const prefix = `${prefixes.get(manifest.epoch)}/epoch-${manifest.epoch}`;
    await bucket.put(`${prefix}/archive-v2-generation.json`, JSON.stringify(manifest));
    for (const file of manifest.files) {
      const bytes = await readFile(join(options.fixtures, `epoch-${manifest.epoch}`, file.name));
      assert.equal(createHash('sha256').update(bytes).digest('hex'), file.sha256);
      await bucket.put(`${prefix}/${file.name}`, bytes);
    }
  }
  const kv = await mf.getKVNamespace('BZ_RPC_API_KEYS');
  await kv.put(createHash('sha256').update(apiKey).digest('hex'), JSON.stringify({ keyId: 'live_acceptance', customerId: 'local_acceptance', label: 'Live transaction acceptance', status: 'enabled' }));
  const first = oracles.find(row => Math.floor(row.slot / 432_000) === epochs[0]);
  const second = oracles.find(row => Math.floor(row.slot / 432_000) === epochs[1]);
  if ((options.phase ?? 'update') === 'update') {
    const before = await snapshot('empty');
    assert.equal((await rpc(first)).error?.code, -32004);
    await ingest(epochs[0], 1);
    const active = await snapshot('first-active');
    assert.equal(active.active_rows, oracles.filter(row => Math.floor(row.slot / 432_000) === epochs[0]).length);
    await exact(first);
    check('active buffer returns exact signed transaction bytes');
    const firstSealStarted = performance.now();
    const sealing = native('/v2/seal', {}).then(result => {
      receipt.first_seal_seconds = (performance.now() - firstSealStarted) / 1000;
      return result;
    });
    void sealing.catch(() => {}); // The awaited promise below still reports a failed seal.
    let sealed;
    for (let i = 0; i < 200; i++) {
      sealed = await native('/v2/info');
      if (sealed.sealed_rows > 0) break;
      await new Promise(done => setTimeout(done, 5));
    }
    assert.ok(sealed.sealed_rows > 0, 'Observe the sealed buffer before publication.');
    receipt.snapshots.push({ stage: 'sealed', ...sealed });
    await ingest(epochs[1], 2);
    await exact(first);
    await exact(second);
    const overlapped = await snapshot('second-ingested');
    receipt.sealed_active_overlap_observed = overlapped.sealed_rows > 0 && overlapped.active_rows > 0;
    assert.ok(receipt.sealed_active_overlap_observed, 'New input must be visible while the prior buffer is still sealed.');
    await sealing;
    const one = await snapshot('first-published');
    assert.notEqual(one.catalog_digest, before.catalog_digest);
    await exact(first);
    await exact(second);
    check('reads continue through sealed construction and catalog publication');
    const secondSealStarted = performance.now();
    await native('/v2/seal', {});
    receipt.second_seal_seconds = (performance.now() - secondSealStarted) / 1000;
    const two = await snapshot('second-published');
    assert.notEqual(two.catalog_digest, one.catalog_digest);
    assert.equal(two.active_rows, 0);
    assert.equal(two.sealed_rows, 0);
    assert.equal(two.catalog_id, before.catalog_id);
    await ingest(epochs[1], 2); // exact durable input replay
    assert.equal((await snapshot('idempotent-replay')).catalog_digest, two.catalog_digest);
    check('two catalog swaps keep the pinned catalog identity and input replay is idempotent');
  } else {
    const recovered = await snapshot('recovered');
    assert.equal(recovered.active_rows, 0);
    assert.equal(recovered.sealed_rows, 0);
    await exact(first); await exact(second);
    check('process restart restores the published catalog and durable cursor');
  }
  const selected = options.all === 'true' ? oracles : oracles.filter((row, index) => index % 500 === 0 || row === first || row === second);
  let failed = 0; let versioned = 0;
  for (let index = 0; index < selected.length; index++) {
    const row = selected[index];
    await exact(row);
    failed += Number(Boolean(row.meta?.error_present)); versioned += Number(row.version === 0);
    if ((index + 1) % 500 === 0) console.log(`Checked ${index + 1}/${selected.length} signed transactions.`);
  }
  receipt.transactions = selected.length; receipt.failed_transactions = failed; receipt.v0_transactions = versioned;
  check('published segments return the original CAR signed bytes and checked fee/error fields');
  const found = await native('/v2/lookup', { signature: first.signature });
  falseCandidate = found.candidates.find(candidate => candidate.slot === first.slot);
  assert.ok(falseCandidate);
  mode = 'false-before-hit';
  await exact(second);
  mode = 'normal';
  check('a short-tag false candidate cannot hide a later exact signature match');
  for (const fault of ['wrong-identity', 'unsafe-prefix', 'too-many']) {
    mode = fault;
    assert.equal((await rpc(first)).error?.code, -32000, fault);
  }
  mode = 'source-error';
  await exact(second);
  assert.equal((await rpc('1'.repeat(64))).error?.code, -32000);
  mode = 'normal';
  assert.equal((await rpc('1'.repeat(64))).error?.code, -32004);
  check('identity, prefix, candidate count and archive errors cannot become a verified miss');
  receipt.status = 'PASSED';
  receipt.log_projection_records = [...logProjectionRecords.values()];
  receipt.strict_original_car_log_parity = logProjectionRecords.size ? 'NOT_EXACT_PREEXISTING_ARCHIVE_PROJECTION' : 'EXACT';
  receipt.independent_checks = ['original signed wire bytes', 'slot', 'fee', 'error presence', 'balances', 'loaded addresses', 'present compute/cost units', 'logs with explicit recorded source whitespace profile'];
  console.log(JSON.stringify(receipt, null, 2));
} finally {
  await mf.dispose();
  for (const socket of sockets) socket.destroy();
  await new Promise(done => proxy.close(done));
  await rm(temporary, { recursive: true, force: true });
}
