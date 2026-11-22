#!/usr/bin/env node
// Real locator HTTP + release Worker WASM + local R2/KV/metering acceptance.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as miniflare from 'miniflare';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const apiKey = `bz_live_${randomBytes(32).toString('base64url')}`;
const archivePrefix = 'transaction-acceptance';
const options = { oracle: [] };
for (let i = 2; i < process.argv.length; i += 2) {
  const key = process.argv[i];
  const value = process.argv[i + 1];
  if (!key.startsWith('--') || !value) throw new Error('Use --fixtures ROOT --oracle FILE [--oracle FILE] --locator URL --catalog HEX --token-file FILE [--build FILE].');
  if (key === '--oracle') options.oracle.push(value);
  else options[key.slice(2)] = value;
}
for (const required of ['fixtures', 'locator', 'catalog', 'token-file']) {
  if (!options[required]) throw new Error(`Missing --${required}.`);
}
if (!options.oracle.length) throw new Error('At least one independent CAR --oracle file is required.');
const token = (await readFile(options['token-file'], 'utf8')).trim();
if (options.all && !['true', 'false'].includes(options.all)) throw new Error('--all must be true or false.');
if (options.serve && !['true', 'false'].includes(options.serve)) throw new Error('--serve must be true or false.');
if (options['node-outbound'] && !['true', 'false'].includes(options['node-outbound'])) throw new Error('--node-outbound must be true or false.');
if (options['allow-trailing-space-projection'] && !['true', 'false'].includes(options['allow-trailing-space-projection'])) throw new Error('--allow-trailing-space-projection must be true or false.');
if (options.serve === 'true' && !options['client-token-file']) throw new Error('--serve true requires --client-token-file FILE.');
const oracles = (await Promise.all(options.oracle.map(path => readFile(path, 'utf8'))))
  .flatMap(text => text.trim().split('\n').filter(Boolean).map(line => JSON.parse(line)));
const epochs = [...new Set(oracles.map(row => Math.floor(row.slot / 432_000)))];
const build = resolve(options.build ?? join(packageRoot, 'build/index.js'));
const temporary = await mkdtemp(join(tmpdir(), 'blockzilla-transaction-worker-'));
const sockets = new Set();
let mode = 'normal';
let knownCandidate;
let proxyCalls = 0;
let nativeCalls = 0;
let outboundCalls = 0;
let redirectTargetCalls = 0;
let bridge;
const bridgeSockets = new Set();

const proxy = createServer(async (request, response) => {
  try {
    proxyCalls += 1;
    if (request.url === '/redirect-target') {
      redirectTargetCalls += 1;
      response.writeHead(200).end('Redirect target must never receive a request.');
      return;
    }
    if (request.headers.authorization !== `Bearer ${token}`) {
      response.writeHead(401).end('{"error":"test locator authentication failed"}');
      return;
    }
    const chunks = [];
    let length = 0;
    for await (const chunk of request) {
      length += chunk.length;
      if (length > 1024) throw new Error('Oversized locator request.');
      chunks.push(chunk);
    }
    const body = Buffer.concat(chunks).toString('utf8');
    const { signature } = JSON.parse(body);
    if (mode === 'redirect') {
      response.writeHead(302, { location: `${locatorUrl}/redirect-target` }).end();
      return;
    }
    if (mode === 'unavailable') { response.writeHead(503).end(); return; }
    if (mode === 'timeout') {
      const timer = setTimeout(() => response.writeHead(503).end(), 6000);
      timer.unref();
      return;
    }
    if (mode === 'oversized') { response.writeHead(200).end(' '.repeat(17000)); return; }
    if (mode === 'false-positive' || mode === 'false-positive-complete') {
      response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({
        schema_version: 1, signature, catalog_digest: options.catalog,
        candidate: knownCandidate, coverage_complete: mode.endsWith('complete'),
      }));
      return;
    }
    nativeCalls += 1;
    const upstream = await fetch(`${options.locator.replace(/\/$/, '')}/v1/lookup`, {
      method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` }, body,
    });
    const bytes = await upstream.text();
    if (mode === 'wrong-catalog' || mode === 'wrong-signature') {
      const result = JSON.parse(bytes);
      if (mode === 'wrong-catalog') result.catalog_digest = 'f'.repeat(64);
      else result.signature = '1'.repeat(64);
      response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(result));
      return;
    }
    response.writeHead(upstream.status, { 'content-type': 'application/json' }).end(bytes);
  } catch (error) {
    console.error(JSON.stringify({ event: 'test_locator_proxy_error', name: error.name, code: error.cause?.code, proxyCalls, nativeCalls }));
    response.writeHead(500).end('{"error":"test locator proxy failed"}');
  }
});
proxy.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
await new Promise(resolveListening => proxy.listen(0, '127.0.0.1', resolveListening));
const locatorUrl = `http://127.0.0.1:${proxy.address().port}`;
const mfOptions = {
  modules: [
    { type: 'ESModule', path: build },
    { type: 'CompiledWasm', path: join(dirname(build), 'index_bg.wasm') },
  ],
  modulesRoot: dirname(build), name: 'transaction-acceptance',
  compatibilityDate: options['compatibility-date'] ?? '2026-09-10',
  resourcePersistencePath: join(temporary, 'storage'), telemetry: { enabled: false },
  bindings: {
    BZ_ARCHIVE_SOURCE: 'r2', BZ_ARCHIVE_LAYOUT: 'stored', BZ_ARCHIVE_PREFIX: archivePrefix,
    BZ_ARCHIVE_GENERATION: 'transaction-acceptance-v1', BZ_SLOT_INDEX: 'sparse',
    BZ_R2_BUCKET_BINDING: 'BZ_ARCHIVE_BUCKET', BZ_SIGNATURE_INDEX_URL: locatorUrl,
    BZ_SIGNATURE_INDEX_TOKEN: token, BZ_SIGNATURE_CATALOG_DIGEST: options.catalog,
    BZ_SIGNATURE_CLUSTER_ID: options.cluster ?? 'mainnet-beta',
  },
  kvNamespaces: { BZ_RPC_API_KEYS: 'transaction-test-keys' },
  r2Buckets: { BZ_ARCHIVE_BUCKET: 'transaction-test-archive' },
  analyticsEngineDatasets: { BZ_RPC_METRICS: { dataset: 'transaction_test_metrics' } },
  // Optional diagnostic handler. Normal tests use Workerd's real fetch path.
  // This handler also keeps the HTTP hop to the proxy and native SSD service.
  outboundService: async request => {
    outboundCalls += 1;
    const url = new URL(request.url);
    if (url.origin !== locatorUrl || url.pathname !== '/v1/lookup') {
      return new Response('Unexpected test outbound request.', { status: 502 });
    }
    try {
      const upstream = await fetch(request.url, {
        method: request.method, headers: Object.fromEntries(request.headers),
        body: Buffer.from(await request.arrayBuffer()), redirect: 'error',
      });
      return new Response(await upstream.arrayBuffer(), { status: upstream.status, headers: Object.fromEntries(upstream.headers) });
    } catch (error) {
      console.error(JSON.stringify({ event: 'test_locator_outbound_error', name: error.name, code: error.cause?.code, outboundCalls, proxyCalls, nativeCalls }));
      return new Response('Test locator outbound request failed.', { status: 502 });
    }
  },
};
if (options['node-outbound'] !== 'true') delete mfOptions.outboundService;
const mf = new miniflare.Miniflare(typeof miniflare.convertV4MiniflareOptions === 'function'
  ? miniflare.convertV4MiniflareOptions(mfOptions) : mfOptions);
const request = (path, init = {}, key = apiKey) => mf.dispatchFetch(`https://transaction.test${path}`, {
  ...init, headers: { ...(key ? { authorization: `Bearer ${key}` } : {}), ...init.headers },
});
let rpcId = 0;
async function rpc(signature, config = { maxSupportedTransactionVersion: 1 }, key = apiKey) {
  const response = await request('/', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method: 'getTransaction', params: [signature, config] }),
  }, key);
  const body = await response.json();
  assert.equal(body.id, rpcId);
  assert.equal(response.headers.get('X-Blockzilla-Cache'), 'UNCACHED');
  assert.equal(response.headers.get('Cache-Control'), 'private, no-store');
  return { response, body };
}
const receipt = { checks: [], source: 'real CAR oracle + native SSD locator HTTP + Worker release WASM + local R2', epochs };
const check = name => { receipt.checks.push(name); console.log(`PASS ${name}`); };
const allowLogProjection = options['allow-trailing-space-projection'] === 'true';
const logProjectionRecords = [];
const logProjectionTransactions = new Set();
function compareOracleLogs(actual, row) {
  const original = row.meta?.logMessages;
  const context = `CAR logMessages mismatch: slot=${row.slot} tx_index=${row.tx_index} signature=${row.signature}`;
  if (!allowLogProjection || !Array.isArray(actual) || !Array.isArray(original)) {
    assert.deepEqual(actual, original, context);
    return;
  }
  assert.equal(actual.length, original.length, context);
  for (let index = 0; index < original.length; index += 1) {
    if (actual[index] === original[index]) continue;
    assert.equal(typeof original[index], 'string', `${context} line=${index}`);
    assert.equal(typeof actual[index], 'string', `${context} line=${index}`);
    const projected = original[index].replace(/[ \t\r\n]+$/u, '');
    assert.equal(actual[index], projected, `${context} line=${index}`);
    const removed = original[index].slice(projected.length);
    assert.ok(removed.length > 0, `${context} line=${index}`);
    logProjectionRecords.push({
      slot: row.slot, tx_index: row.tx_index, signature: row.signature,
      line_index: index, removed_suffix_utf8_hex: Buffer.from(removed, 'utf8').toString('hex'),
      original_line: original[index], actual_line: actual[index],
    });
    logProjectionTransactions.add(`${row.slot}:${row.tx_index}:${row.signature}`);
  }
}

try {
  const bucket = await mf.getR2Bucket('BZ_ARCHIVE_BUCKET');
  const originals = new Map();
  for (const epoch of epochs) {
    const response = await fetch(`${options.locator.replace(/\/$/, '')}/v1/epochs/${epoch}/manifest`, { headers: { authorization: `Bearer ${token}` } });
    assert.equal(response.status, 200, `native manifest for epoch ${epoch}`);
    const manifestBytes = Buffer.from(await response.arrayBuffer());
    const manifest = JSON.parse(manifestBytes);
    const objectKey = name => `${archivePrefix}/epoch-${epoch}/${name}`;
    await bucket.put(objectKey('archive-v2-generation.json'), manifestBytes);
    originals.set(objectKey('archive-v2-generation.json'), manifestBytes);
    for (const file of manifest.files) {
      const bytes = await readFile(join(options.fixtures, `epoch-${epoch}`, file.name));
      assert.equal(bytes.length, file.size);
      assert.equal(createHash('sha256').update(bytes).digest('hex'), file.sha256);
      await bucket.put(objectKey(file.name), bytes);
      originals.set(objectKey(file.name), bytes);
    }
  }
  const kv = await mf.getKVNamespace('BZ_RPC_API_KEYS');
  await kv.put(createHash('sha256').update(apiKey).digest('hex'), JSON.stringify({ keyId: 'transaction_acceptance', customerId: 'local_acceptance', label: 'Local transaction acceptance', status: 'enabled' }));
  const unauthorized = await request('/', { method: 'POST', body: '{}' }, null);
  assert.equal(unauthorized.status, 401);
  await unauthorized.arrayBuffer();
  assert.equal(proxyCalls, 0);
  check('authentication precedes locator and archive reads');

  for (const [signature, config] of [['invalid', {}], [12, {}], [oracles[0].signature, { commitment: 'processed' }], [oracles[0].signature, { encoding: 'jsonParsed' }], [oracles[0].signature, { maxSupportedTransactionVersion: -1 }]]) {
    const result = await rpc(signature, config);
    assert.equal(result.body.error.code, -32602);
    assert.equal(result.response.headers.get('X-Blockzilla-Billable-Reads'), '0');
  }
  assert.equal(proxyCalls, 0);
  check('invalid signatures, commitment and config fail before backend access');

  const blocks = new Map();
  for (const slot of new Set(oracles.map(row => row.slot))) {
    const response = await request(`/block/${slot}.json?rewards=true`);
    const body = await response.json();
    assert.ok(body.result, JSON.stringify(body.error));
    blocks.set(slot, body.result);
  }
  const selected = new Map();
  if (options.all === 'true') {
    for (const row of oracles) selected.set(row.signature, row);
  } else for (const epoch of epochs) {
    const rows = oracles.filter(row => Math.floor(row.slot / 432_000) === epoch);
    const add = row => { if (row) selected.set(row.signature, row); };
    add(rows[0]); add(rows.at(-1));
    add(rows.find(row => row.meta?.error_present));
    add(rows.find(row => row.version === 0));
    add(rows.find(row => row.version === 0 && (row.meta?.loadedAddresses?.writable?.length || row.meta?.loadedAddresses?.readonly?.length)));
    add(rows.find(row => row.signatures?.length > 1));
    for (let i = 1; i <= 4; i++) add(rows[Math.floor(rows.length * i / 5)]);
  }
  let positiveChecks = 0;
  let failedChecks = 0;
  let v0Checks = 0;
  for (const row of selected.values()) {
    const result = await rpc(row.signature);
    assert.ok(result.body.result, JSON.stringify({ error: result.body.error, outboundCalls, proxyCalls, nativeCalls }));
    const actual = result.body.result;
    const block = blocks.get(row.slot);
    const expected = block.transactions[row.tx_index];
    if (Array.isArray(expected.transaction)) {
      // The current GET block route emits signed base64. Compare its common
      // fields here and compare the wire transaction with the binary RPC below.
      const { transaction: jsonTransaction, ...common } = actual;
      const { transaction: blockTransaction, ...expectedCommon } = expected;
      assert.deepEqual(common, { slot: row.slot, blockTime: block.blockTime, ...expectedCommon });
      assert.deepEqual(jsonTransaction.signatures, row.signatures);
      assert.ok(jsonTransaction.message && !Array.isArray(jsonTransaction.message));
      assert.deepEqual(blockTransaction, row.transaction);
    } else {
      assert.deepEqual(actual, { slot: row.slot, blockTime: block.blockTime, ...expected });
    }
    assert.equal(actual.meta?.fee, row.meta?.fee);
    assert.deepEqual(actual.meta?.preBalances, row.meta?.preBalances);
    assert.deepEqual(actual.meta?.postBalances, row.meta?.postBalances);
    assert.deepEqual(actual.meta?.loadedAddresses, row.meta?.loadedAddresses);
    compareOracleLogs(actual.meta?.logMessages, row);
    if (row.meta?.computeUnitsConsumed != null) assert.equal(actual.meta.computeUnitsConsumed, row.meta.computeUnitsConsumed);
    if (row.meta?.costUnits != null) assert.equal(actual.meta.costUnits, row.meta.costUnits);
    assert.equal(actual.meta?.err != null, Boolean(row.meta?.error_present));
    const binary = await rpc(row.signature, { encoding: 'base64', maxSupportedTransactionVersion: 1 });
    assert.deepEqual(binary.body.result?.transaction, row.transaction, `CAR signed wire bytes for ${row.signature}`);
    assert.deepEqual(binary.body.result?.meta, actual.meta);
    assert.equal(result.response.headers.get('X-Blockzilla-Billable-Reads'), '1');
    positiveChecks += 1;
    failedChecks += Number(row.meta?.error_present);
    v0Checks += Number(row.version === 0);
    if (positiveChecks % 250 === 0) console.log(`Checked ${positiveChecks} of ${selected.size} real CAR transactions.`);
  }
  assert.ok(positiveChecks > 0 && nativeCalls >= positiveChecks * 2);
  receipt.positive_checks = positiveChecks; receipt.failed_transaction_checks = failedChecks; receipt.v0_checks = v0Checks;
  receipt.all_oracle_transactions = options.all === 'true';
  receipt.log_parity = allowLogProjection ? 'EXACT_EXCEPT_RECORDED_SOURCE_TRAILING_WHITESPACE' : 'EXACT';
  receipt.strict_original_car_log_parity = logProjectionRecords.length === 0 ? 'EXACT' : 'NOT_EXACT_PREEXISTING_ARCHIVE_PROJECTION';
  receipt.log_projection_count = logProjectionRecords.length;
  receipt.log_projection_affected_transactions = logProjectionTransactions.size;
  receipt.log_projection_records = logProjectionRecords;
  check('native persisted index -> local R2 archive -> getBlock JSON consistency, original CAR signed bytes and checked metadata subset');

  const versioned = oracles.find(row => row.version === 0);
  if (versioned) {
    const versionError = await rpc(versioned.signature, {});
    assert.equal(versionError.body.error.code, -32015);
    check('V0 requires explicit client version support');
  }
  const legacy = oracles.find(row => row.version === 'legacy');
  if (legacy) {
    const oldClient = await rpc(legacy.signature, 'base64');
    assert.deepEqual(oldClient.body.result?.transaction, legacy.transaction);
    assert.equal('version' in oldClient.body.result, false);
    check('legacy encoding-string clients retain the original wire contract');
  }
  const firstSignatures = new Set(oracles.map(row => row.signature));
  const secondary = oracles.flatMap(row => row.signatures?.slice(1) ?? []).find(signature => !firstSignatures.has(signature));
  if (secondary) {
    const coSigner = await rpc(secondary);
    assert.equal(coSigner.body.error?.code, -32004);
    check('a secondary signer signature does not identify a transaction');
  }
  const known = await fetch(`${options.locator.replace(/\/$/, '')}/v1/lookup`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ signature: oracles[0].signature }) }).then(response => response.json());
  knownCandidate = known.candidate;
  assert.ok(knownCandidate);
  const absent = '1'.repeat(64);
  mode = 'false-positive';
  const falsePositive = await rpc(absent);
  assert.equal(falsePositive.body.error.code, -32004);
  mode = 'false-positive-complete';
  const verifiedMiss = await rpc(absent);
  assert.equal(verifiedMiss.body.result, null);
  check('full first-signature check rejects false locator candidates');

  for (const fault of ['unavailable', 'redirect', 'wrong-catalog', 'wrong-signature', 'oversized', 'timeout']) {
    mode = fault;
    const result = await rpc(oracles[0].signature);
    assert.equal(result.body.error.code, -32000, fault);
    assert.ok(!('result' in result.body), fault);
    assert.equal(result.response.headers.get('X-Blockzilla-Billable-Reads'), '0', fault);
  }
  assert.equal(redirectTargetCalls, 0, 'the locator credential must never be forwarded to a redirect target');
  mode = 'normal';
  check('locator failures, redirects, changed catalog, oversized bodies and timeout are errors');
  const miss = await rpc(absent);
  assert.equal(miss.body.error.code, -32004);
  check('partial source coverage is never reported as a global absence');

  const firstEpoch = epochs[0];
  const signatureKey = `${archivePrefix}/epoch-${firstEpoch}/signatures.bin`;
  await bucket.delete(signatureKey);
  assert.equal((await rpc(oracles[0].signature)).body.error.code, -32000);
  await bucket.put(signatureKey, originals.get(signatureKey));
  const manifestKey = `${archivePrefix}/epoch-${firstEpoch}/archive-v2-generation.json`;
  const manifest = JSON.parse(originals.get(manifestKey));
  manifest.generation_digest = '0'.repeat(64);
  await bucket.put(manifestKey, JSON.stringify(manifest));
  assert.equal((await rpc(oracles[0].signature)).body.error.code, -32000);
  await bucket.put(manifestKey, originals.get(manifestKey));
  check('missing signature objects and mismatched archive generations remain errors');

  receipt.proxy_requests = proxyCalls; receipt.native_locator_requests = nativeCalls; receipt.outbound_requests = outboundCalls;
  receipt.redirect_target_requests = redirectTargetCalls;
  receipt.status = 'PASSED';
  console.log(JSON.stringify(receipt, null, 2));
  if (options.serve === 'true') {
    const port = Number(options['listen-port'] ?? 38800);
    if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Invalid --listen-port.');
    await writeFile(options['client-token-file'], `${apiKey}\n`, { mode: 0o600, flag: 'wx' });
    bridge = createServer(async (incoming, outgoing) => {
      try {
        const chunks = [];
        let length = 0;
        for await (const chunk of incoming) {
          length += chunk.length;
          if (length > 1024 * 1024) { outgoing.writeHead(413).end(); return; }
          chunks.push(chunk);
        }
        const body = Buffer.concat(chunks);
        const init = { method: incoming.method, headers: incoming.headers };
        if (incoming.method !== 'GET' && incoming.method !== 'HEAD') init.body = body;
        const result = await mf.dispatchFetch(`https://transaction.test${incoming.url}`, init);
        outgoing.writeHead(result.status, Object.fromEntries(result.headers));
        outgoing.end(Buffer.from(await result.arrayBuffer()));
      } catch {
        outgoing.writeHead(500).end('Local Worker bridge failed.');
      }
    });
    bridge.on('connection', socket => { bridgeSockets.add(socket); socket.on('close', () => bridgeSockets.delete(socket)); });
    await new Promise((resolveListening, reject) => {
      bridge.once('error', reject);
      bridge.listen(port, '127.0.0.1', resolveListening);
    });
    console.log(JSON.stringify({ status: 'SERVING', url: `http://127.0.0.1:${port}`, client_token_file: resolve(options['client-token-file']), scope: 'Local release Worker WASM, native signature service and real fixture archives; no public deployment' }));
    await new Promise(resolveStop => {
      process.once('SIGTERM', resolveStop);
      process.once('SIGINT', resolveStop);
    });
  }
} finally {
  if (bridge) {
    for (const socket of bridgeSockets) socket.destroy();
    await new Promise(resolveClosed => bridge.close(resolveClosed));
  }
  await mf.dispose();
  for (const socket of sockets) socket.destroy();
  await new Promise(resolveClosed => proxy.close(resolveClosed));
  await rm(temporary, { recursive: true, force: true });
}
