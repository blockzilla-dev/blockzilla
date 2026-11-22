#!/usr/bin/env node
// Public HTTP measurements. Store receipts and hashes, never block bodies.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { performance } from 'node:perf_hooks';
import { sampleRequest, summarize } from './bench-get-block.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const require = createRequire(import.meta.url);
const { Agent, fetch } = require('undici');
const SLOTS = [470987967, 471096104, 471204030, 471311999,
  470555971, 470663944, 470771932, 470879999];
const sleep = ms => new Promise(done => setTimeout(done, ms));
const { values } = parseArgs({ options: { output: { type: 'string' },
  'cold-rounds': { type: 'string', default: '3' },
  'hit-rounds': { type: 'string', default: '8' },
  'hits-only': { type: 'boolean', default: false },
  'pace-ms': { type: 'string', default: '0' } } });
assert.ok(values.output, '--output is required');
const coldRounds = Number(values['cold-rounds']), hitRounds = Number(values['hit-rounds']);
assert.ok(Number.isInteger(coldRounds) && coldRounds > 0 && coldRounds <= 5);
assert.ok(Number.isInteger(hitRounds) && hitRounds > 0 && hitRounds <= 16);
const paceMs = Number(values['pace-ms']);
assert.ok(Number.isInteger(paceMs) && paceMs >= 0 && paceMs <= 1000);
const plannedRequests = 1 + 2 * SLOTS.length
  * ((values['hits-only'] ? 0 : coldRounds) + hitRounds + 1);
assert.ok(plannedRequests <= 300, 'the plan exceeds the 300-request budget');
let exactNumbers = false;
JSON.parse('1', (_key, value, context) => { exactNumbers = context?.source === '1'; return value; });
assert.ok(exactNumbers, 'Node.js must support JSON number source text');
const output = resolve(values.output), directory = dirname(output);
try { await access(output); throw new Error('Output already exists; choose a new path'); }
catch (error) { if (error.code !== 'ENOENT') throw error; }
await mkdir(directory, { recursive: true });
const readJson = async path => JSON.parse(await readFile(resolve(ROOT, path), 'utf8'));
const references = await readJson('reports/public-getblock-benchmark-20261122/references.json');
const jsonDigests = new Map(references.samples.map(row => [row.slot, row.jsonSha256]));
const binaryDigests = new Map(references.samples.map(row => [row.slot, { bin: row.binarySha256 }]));
for (const slot of SLOTS) assert.ok(jsonDigests.has(slot) && binaryDigests.has(slot));

const agent = new Agent({ connections: 1, pipelining: 1, keepAliveTimeout: 60_000 });
let receipt, requestCount = 0;
const report = { schema: 'public-getblock-benchmark-v1', startedAt: new Date().toISOString(),
  host: 'getblock.blockzilla.dev', workerVersion: '4d1b4d55-31f1-4e30-a287-717846eeff3c',
  slots: SLOTS, concurrency: 1, coldRounds: values['hits-only'] ? 0 : coldRounds,
  hitRounds, paceMs, apiHeadersSent: 0,
  workerConfigurationChanged: false, blockPayloadFilesWritten: 0, samples: [], windows: {},
  notes: [
    'Cold means profile=1 bypasses Worker response, index and archive range caches. Physical R2 caches and Worker isolate startup are not controlled.',
    'Cold requests include profiling work; cache-hit requests use ordinary URLs.',
    'One keep-alive connection is used. A separate info request primes the client connection.',
    'Body transfer is timed before JSON parsing and digest validation. All original block digests must match.',
    'Cache fills and any misses in a hit window are reported separately from verified hits.',
    'Whole-second guards separate platform CPU query windows and are not included in request latency.',
  ] };
const settings = { blockzillaUrl: new URL('https://getblock.blockzilla.dev'), providers: [],
  timeoutMs: 30_000, binaryReferences: binaryDigests,
  async fetchImplementation(url, options) {
    assert.equal(new Headers(options.headers).has('Authorization'), false);
    assert.ok(++requestCount <= 300, 'hard request budget');
    const response = await fetch(url, { ...options, dispatcher: agent });
    const h = response.headers;
    receipt = { publicAuth: h.get('X-Blockzilla-Auth-Cache'),
      billableReads: h.has('X-Blockzilla-Billable-Reads') ? Number(h.get('X-Blockzilla-Billable-Reads')) : null,
      cfCacheStatus: h.get('CF-Cache-Status'), cfRay: h.get('CF-Ray'),
      cfRequestId: h.get('CF-Request-ID'), cacheControl: h.get('Cache-Control'),
      foundationResult: h.get('X-Blockzilla-Foundation-Result') };
    return response;
  } };
const save = async () => writeFile(output, JSON.stringify({ ...report,
  requests: requestCount, summary: summarize(report.samples) }, null, 2) + '\n');
async function phase(name, representation, rounds, condition) {
  await sleep(2_000 - Date.now() % 1_000);
  const window = { start: new Date().toISOString(), expectedWorkerRequests: 0,
    traffic: { representation, condition, measured: condition !== 'fill' } };
  report.windows[name] = window;
  for (let round = 0; round < rounds; round++) for (const slot of SLOTS) {
    const row = await sampleRequest({ source: 'blockzilla', representation, slot, round,
      phase: condition, uncached: condition === 'cold' }, settings);
    Object.assign(row, receipt);
    report.samples.push(row); window.expectedWorkerRequests++;
    assert.ok(row.ok, JSON.stringify({ phase: name, slot, error: row.error, status: row.status }));
    assert.equal(row.publicAuth, 'PUBLIC'); assert.equal(row.auth.kvReads, 0);
    assert.equal(row.billableReads, 0);
    if (representation === 'json') assert.equal(row.contentSha256, jsonDigests.get(slot));
    if (condition === 'cold') {
      assert.equal(row.profileMode, 'full'); assert.equal(row.storageClass, 'origin_uncached_verified');
      row.workerColdVerified = true;
    }
    row.verifiedResponseHit = row.cache === 'HIT' && row.storage.originReads === 0
      && (row.storage.readerHttpRequests ?? 0) === 0;
    if (condition === 'hit') assert.ok(row.verifiedResponseHit, 'a hit cohort must contain only proven hits');
    if (paceMs) await sleep(paceMs);
  }
  window.end = new Date().toISOString();
  window.traffic.workerRequests = window.expectedWorkerRequests;
  await save();
  console.log(JSON.stringify({ phase: name, requests: window.expectedWorkerRequests,
    caches: report.samples.filter(row => row.phase === condition && row.representation === representation)
      .reduce((out, row) => ({ ...out, [row.cache]: (out[row.cache] ?? 0) + 1 }), {}) }));
}
try {
  await sleep(2_000 - Date.now() % 1_000);
  const start = new Date().toISOString(), timer = performance.now();
  const prime = await fetch('https://getblock.blockzilla.dev/info', {
    dispatcher: agent, signal: AbortSignal.timeout(30_000) });
  requestCount++; assert.equal(prime.status, 200); await prime.arrayBuffer();
  report.connectionPrime = { start, end: new Date().toISOString(), totalMs: performance.now() - timer };
  report.windows.ConnectionPrime = { start, end: report.connectionPrime.end,
    expectedWorkerRequests: 1, traffic: { condition: 'connection_prime', measured: false, workerRequests: 1 } };
  if (!values['hits-only']) {
    await phase('ColdBin', 'bin', coldRounds, 'cold');
    await phase('ColdJson', 'json', coldRounds, 'cold');
  }
  await phase('FillBin', 'bin', 1, 'fill');
  await phase('HitBin', 'bin', hitRounds, 'hit');
  await phase('FillJson', 'json', 1, 'fill');
  await phase('HitJson', 'json', hitRounds, 'hit');
  report.finishedAt = new Date().toISOString(); report.passed = true;
} catch (error) {
  report.passed = false; report.error = String(error.message).slice(0, 300);
  throw error;
} finally {
  await save(); await agent.close();
  const plan = { account_id: '8df0426c80fcd1a04ed439f441db9ff8', worker: 'blockzilla-get-block',
    version: report.workerVersion, wasmSha256: 'a29bbabe6d5b3343c894dc681a3a785bc573b277bb86e25e8460d6e7c8b53a06',
    requestReceipt: output, observabilityHeadSamplingRate: 0.01,
    windows: Object.fromEntries(Object.entries(report.windows).filter(([, row]) => row.end)) };
  await writeFile(resolve(directory, 'cpu-plan.json'), JSON.stringify(plan, null, 2) + '\n');
}
