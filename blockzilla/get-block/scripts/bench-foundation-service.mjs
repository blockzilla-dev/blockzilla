#!/usr/bin/env node
// Bounded real-service benchmark. URLs and credentials stay in the environment.
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, access } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { sampleRequest, validateJsonSample, loadSlots, loadBinaryReferences, summarize,
  compareContents } from './bench-get-block.mjs';
import { TransportTrace } from './diagnose-get-block-transport.mjs';

const ENV_NAME = /^[A-Z][A-Z0-9_]*$/;
const sleep = ms => new Promise(done => setTimeout(done, ms));
const count = (rows, test) => rows.reduce((total, row) => total + Number(test(row)), 0);

function task(slot, phase, representation, condition, provider = false, round = 0) {
  return { source: provider ? 'provider' : 'blockzilla', label: provider ? 'helius' : 'worker', slot,
    phase, representation, round, providerIndex: 0, condition,
    uncached: !provider && condition === 'full-cold',
    sourceUncached: !provider && ['source-cold', 'source-prime'].includes(condition) };
}

export function foundationPlan(slots) {
  if (slots.length !== 4 || new Set(slots).size !== 4) throw Error('Exactly four distinct slots are required.');
  const phases = [];
  const add = (name, representation, condition, measured, paired = false, rounds = 1) => {
    const groups = [];
    for (let round = 0; round < rounds; round++) for (const slot of slots) {
      const worker = task(slot, name, representation, condition, false, round);
      const provider = task(slot, name, 'json', condition, true, round);
      groups.push(paired ? round % 2 ? [provider, worker] : [worker, provider] : [worker]);
    }
    phases.push({ name, representation, condition, measured, groups });
  };
  phases.push({ name: 'RuntimeWarmJson', representation: 'json', condition: 'warmup', measured: false,
    groups: [[task(slots[0], 'RuntimeWarmJson', 'json', 'full-cold'),
      task(slots[0], 'RuntimeWarmJson', 'json', 'full-cold', true)]] });
  phases.push({ name: 'RuntimeWarmBinary', representation: 'bin', condition: 'warmup', measured: false,
    groups: [[task(slots[0], 'RuntimeWarmBinary', 'bin', 'full-cold')]] });
  add('FullColdJson', 'json', 'full-cold', true, true, 2);
  add('FullColdBinary', 'bin', 'full-cold', true, false, 2);
  add('SourcePrimeJson', 'json', 'source-prime', false);
  add('SourceColdJson', 'json', 'source-cold', true, true, 2);
  add('SourcePrimeBinary', 'bin', 'source-prime', false);
  add('SourceColdBinary', 'bin', 'source-cold', true, false, 2);
  add('ResponsePrimeJson', 'json', 'response-prime', false);
  add('ResponseHitsJson', 'json', 'response-hit', true, true, 2);
  add('ResponsePrimeBinary', 'bin', 'response-prime', false);
  add('ResponseHitsBinary', 'bin', 'response-hit', true, false, 2);
  assert.equal(phases.flatMap(p => p.groups.flat()).length, 91);
  for (const p of phases.filter(p => p.measured)) assert.equal(count(p.groups.flat(), r => r.source === 'blockzilla'), 8);
  return phases;
}

export function publicHeaders(headers) {
  const result = {};
  for (const [name, value] of headers) {
    if (!(name.startsWith('x-blockzilla-') || name === 'x-bz-profile')) continue;
    if (/locator|token|secret|authorization|cookie/.test(name)) continue;
    const bound = name === 'x-bz-profile' ? 128 * 1024 : 4096;
    if (value.length > bound) continue;
    // A diagnostic must not copy a private endpoint, including a URL in JSON.
    result[name] = value.replace(/https?:\/\/[^\s"<>]+/g, '[URL redacted]');
  }
  return result;
}

function headerCount(sample, name) {
  const value = sample.publicHeaders?.[name.toLowerCase()];
  if (!/^(0|[1-9][0-9]*)$/.test(value ?? '')) return null;
  const n = Number(value); return Number.isSafeInteger(n) ? n : null;
}

export function requestProof(sample) {
  if (sample.source !== 'blockzilla') return undefined;
  const failures = [], storage = sample.storage;
  const lookup = headerCount(sample, 'X-Blockzilla-Foundation-Lookup-HTTP-Requests');
  const resolver = headerCount(sample, 'X-Blockzilla-Foundation-Resolve-HTTP-Requests');
  const require = (condition, name) => { if (!condition) failures.push(name); };
  require(storage?.originHeads === 0, 'zeroArchiveHeads');
  require(lookup !== null && resolver !== null, 'explicitBrokerCounters');
  if (['full-cold', 'source-cold', 'source-prime'].includes(sample.condition)) {
    require(storage?.originGets === 2, 'twoArchiveGets');
    require(resolver === 1, 'oneResolvePost');
    require(sample.cache === 'BYPASS', 'responseCacheBypass');
  }
  if (sample.condition === 'full-cold') {
    require(lookup === 1, 'oneLookupGet');
    require(sample.profileMode === 'full', 'fullProfile');
    require(storage?.archiveMemoryHits === 0 && storage?.archiveEdgeHits === 0, 'noArchiveCacheHits');
    require(sample.auth?.cache === 'BYPASS' && sample.auth?.kvReads === 1, 'coldApiKeyCheck');
  }
  if (sample.condition === 'source-cold') {
    require(lookup === 0, 'cachedSourceRouteSkipsLookup');
    require(sample.profileMode === 'source', 'sourceProfile');
    require(sample.publicHeaders?.['x-blockzilla-foundation-result'] === 'ROUTE_CACHE', 'sourceRouteCacheHit');
  }
  if (sample.condition === 'source-prime') require(lookup === 0 || lookup === 1, 'boundedSourcePrimeLookup');
  if (sample.condition === 'response-hit') {
    require(sample.cache === 'HIT', 'completeResponseCacheHit');
    require(storage?.originGets === 0, 'zeroArchiveGets');
    require(lookup === 0 && resolver === 0, 'zeroBrokerCalls');
  }
  return { passed: failures.length === 0, failures, lookupGets: lookup, resolvePosts: resolver,
    archiveGets: storage?.originGets ?? null, archiveHeads: storage?.originHeads ?? null };
}

function parse(argv) {
  const names = new Set(['url', 'rpc-url', 'api-key-env', 'rpc-key-env', 'slots', 'reference',
    'binary-reference', 'output', 'cpu-plan', 'account-id', 'worker', 'version', 'wasm-sha256',
    'timeout-ms', 'quiet-gap-ms']);
  if (argv.length === 1 && argv[0] === '--self-test') return { selfTest: true };
  if (argv.length === 1 && ['--help', '-h'].includes(argv[0])) return { help: true };
  const options = new Map();
  for (let i = 0; i < argv.length; i += 2) {
    const name = argv[i]?.slice(2), value = argv[i + 1];
    if (!argv[i]?.startsWith('--') || !names.has(name) || !value || value.startsWith('--') || options.has(name)) throw Error('Invalid benchmark arguments.');
    options.set(name, value);
  }
  for (const name of ['url', 'rpc-url', 'slots', 'reference', 'binary-reference', 'output', 'cpu-plan', 'account-id', 'worker', 'version', 'wasm-sha256']) {
    if (!options.has(name)) throw Error('A required benchmark argument is missing.');
  }
  if (!/^[a-f0-9]{32}$/.test(options.get('account-id')) || !/^[a-zA-Z0-9_-]{1,128}$/.test(options.get('worker'))
      || !/^[a-f0-9-]{16,80}$/.test(options.get('version')) || !/^[a-f0-9]{64}$/.test(options.get('wasm-sha256'))) throw Error('Invalid deployment identity.');
  for (const name of ['api-key-env', 'rpc-key-env']) if (options.has(name) && !ENV_NAME.test(options.get(name))) throw Error('Invalid key environment name.');
  const numeric = (name, fallback, minimum, maximum) => {
    const text = options.get(name) ?? String(fallback), value = Number(text);
    if (!/^[0-9]+$/.test(text) || !Number.isInteger(value) || value < minimum || value > maximum) throw Error('Invalid benchmark time bound.');
    return value;
  };
  return { options, timeoutMs: numeric('timeout-ms', 90000, 100, 300000), quietGapMs: numeric('quiet-gap-ms', 2200, 1200, 10000) };
}

function endpoint(value, env) {
  if (!/^@[A-Z][A-Z0-9_]*$/.test(value ?? '')) throw Error('Use @ENV_NAME for target URLs.');
  let url;
  try { url = new URL(env[value.slice(1)]); } catch { throw Error('A URL environment value is missing or invalid.'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw Error('Invalid private HTTPS endpoint.');
  return url.toString();
}

async function outputAbsent(path) {
  try { await access(path); } catch (error) { if (error.code === 'ENOENT') return; throw Error('Cannot inspect output path.'); }
  throw Error('An output file already exists.');
}

export async function runBenchmark(argv, env = process.env) {
  const parsed = parse(argv);
  if (parsed.selfTest) return selfTest();
  if (parsed.help) {
    console.log('Usage: node scripts/bench-foundation-service.mjs --url @OWNER_URL --rpc-url @HELIUS_URL --api-key-env BLOCKZILLA_RPC_API_KEY --slots FILE --reference JSON --binary-reference MANIFEST --output RECEIPT --cpu-plan PLAN --account-id ID --worker NAME --version UUID --wasm-sha256 SHA256');
    return;
  }
  const a = parsed.options, output = resolve(a.get('output')), cpuOutput = resolve(a.get('cpu-plan'));
  if (output === cpuOutput) throw Error('Receipt and CPU plan paths must differ.');
  await Promise.all([outputAbsent(output), outputAbsent(cpuOutput)]);
  const slots = await loadSlots(a.get('slots')), phases = foundationPlan(slots);
  const reference = JSON.parse(await readFile(a.get('reference'), 'utf8'));
  const digests = new Map(reference.samples.filter(r => r.ok !== false && /^[a-f0-9]{64}$/.test(r.contentSha256)).map(r => [r.slot, r.contentSha256]));
  const binaryReferences = await loadBinaryReferences(a.get('binary-reference'));
  for (const slot of slots) if (!digests.has(slot) || !binaryReferences.has(slot)) throw Error('A saved block reference is missing.');
  const workerUrl = endpoint(a.get('url'), env), providerUrl = endpoint(a.get('rpc-url'), env);
  const key = env[a.get('api-key-env') ?? 'BLOCKZILLA_RPC_API_KEY'];
  if (!key || /[\r\n]/.test(key)) throw Error('Worker key environment value is missing or invalid.');
  const providerKey = a.has('rpc-key-env') ? env[a.get('rpc-key-env')] : undefined;
  if (a.has('rpc-key-env') && (!providerKey || /[\r\n]/.test(providerKey))) throw Error('Provider key environment value is missing or invalid.');
  const trace = new TransportTrace(), dispatchers = { worker: trace.dispatcher('worker'), helius: trace.dispatcher('helius') };
  const settings = { blockzillaUrl: workerUrl, blockzillaKey: key, providers: [{ label: 'helius', url: providerUrl, key: providerKey }],
    timeoutMs: parsed.timeoutMs, rpcEncoding: 'base64', maxTransactionVersion: 1, binaryReferences };
  const samples = [], windows = {}, phaseRows = [], startedAt = new Date().toISOString();
  let stoppedEarly = false;
  console.log(JSON.stringify({ event: 'start', worker: a.get('worker'), version: a.get('version'), plannedRequests: 91 }));
  try {
    for (const [index, phase] of phases.entries()) {
      if (index) await sleep(parsed.quietGapMs);
      const start = new Date().toISOString(), rows = [];
      console.log(JSON.stringify({ event: 'phase_start', phase: phase.name, measured: phase.measured }));
      for (const group of phase.groups) {
        const deferred = [];
        const batch = await Promise.all(group.map(async item => {
          let captured = {};
          const span = trace.begin(item.label, dispatchers[item.label]);
          const fetchImplementation = async (url, options) => {
            const response = await span.fetch(url, options);
            if (item.source === 'blockzilla') captured = publicHeaders(response.headers);
            return response;
          };
          const sample = await sampleRequest(item, { ...settings, fetchImplementation, deferredJsonValidation: deferred });
          sample.transport = trace.finish(span); sample.condition = item.condition; sample.measured = phase.measured;
          if (item.source === 'blockzilla') sample.publicHeaders = captured;
          return sample;
        }));
        // Do not include JSON parsing or SHA checks in either paired network timer.
        for (const pending of deferred) {
          try { if (!validateJsonSample(pending.sample, pending.chunks)) pending.sample.ok = false; }
          catch { pending.sample.ok = false; pending.sample.error = 'content_validation_error'; }
          delete pending.sample.validationDeferred;
        }
        for (const sample of batch) {
          if (sample.representation === 'json') {
            sample.contentMatchesSavedReference = sample.contentSha256 === digests.get(sample.slot);
            if (!sample.contentMatchesSavedReference) { sample.ok = false; sample.error ??= 'saved_reference_mismatch'; }
          }
          sample.requestProof = requestProof(sample);
          if (sample.requestProof && !sample.requestProof.passed) { sample.ok = false; sample.error ??= 'request_receipt_mismatch'; }
          rows.push(sample); samples.push(sample);
          console.log(JSON.stringify({ event: 'sample', phase: phase.name, label: sample.label, slot: sample.slot,
            representation: sample.representation, ok: sample.ok, error: sample.error ?? null,
            ttfbMs: sample.ttfbMs, totalMs: sample.totalMs, proof: sample.requestProof }));
        }
        if (batch.some(row => !row.ok)) { stoppedEarly = true; break; }
      }
      const end = new Date().toISOString(), workers = rows.filter(row => row.source === 'blockzilla');
      const traffic = { condition: phase.condition, representation: phase.representation, measured: phase.measured,
        workerRequests: workers.length, heliusRequests: rows.length - workers.length, concurrentJsonPairs: phase.groups.some(g => g.length === 2) };
      windows[phase.name] = { start, end, expectedWorkerRequests: workers.length, traffic };
      phaseRows.push({ name: phase.name, start, end, ...traffic,
        responseCacheFills: count(workers, row => row.cache === 'MISS'), responseCacheHits: count(workers, row => row.cache === 'HIT'),
        lookupGets: workers.reduce((n, row) => n + (row.requestProof?.lookupGets ?? 0), 0),
        resolvePosts: workers.reduce((n, row) => n + (row.requestProof?.resolvePosts ?? 0), 0) });
      console.log(JSON.stringify({ event: 'phase_complete', phase: phase.name, requests: rows.length, successful: count(rows, row => row.ok) }));
      if (stoppedEarly) break;
    }
  } finally {
    await Promise.allSettled(Object.values(dispatchers).map(dispatcher => dispatcher.close())); trace.close();
  }
  const report = { schema: 'blockzilla.foundation-service-benchmark.v1', status: stoppedEarly ? 'FAIL' : 'PASS',
    startedAt, completedAt: new Date().toISOString(), deployment: { account_id: a.get('account-id'), worker: a.get('worker'),
      version: a.get('version'), wasmSha256: a.get('wasm-sha256'), url: '[redacted]' }, provider: { label: 'helius', url: '[redacted]' },
    plan: { slots, rounds: 2, timedWorkerRequestsPerPhase: 8, plannedRequests: 91, plannedWorkerRequests: 66,
      plannedHeliusRequests: 25, retries: 0, quietGapMs: parsed.quietGapMs, timeoutMs: parsed.timeoutMs,
      providerOptions: { encoding: 'base64', transactionDetails: 'full', rewards: false, commitment: 'finalized', maxSupportedTransactionVersion: 1 } },
    proof: { requests: samples.length, stoppedEarly, successful: count(samples, row => row.ok),
      workerReceiptsValid: count(samples, row => row.requestProof?.passed === true),
      jsonMatchesSaved: count(samples, row => row.contentMatchesSavedReference === true), binaryMatchesOriginal: count(samples, row => row.binaryMatchesReference === true) },
    phases: phaseRows, groups: summarize(samples), contentChecks: compareContents(samples, ['helius'], ['worker']),
    connections: trace.connectionReport(), samples, notes: [
      'Six measured phases each contain eight Worker requests: four fixed slots, two rounds. Warmups and prime calls have separate windows and counts.',
      'Each measured JSON Worker request runs concurrently with Helius for the same slot. Validation starts after both network bodies complete. Binary has no RPC payload-size comparison.',
      'TTFB is the first delivered body byte. Complete time ends at body EOF. JSON canonical checks and original binary SHA checks run after that timer.',
      'Full cold bypasses Worker response/index/auth caches and broker resolution RAM reads/inserts. This does not control physical R2, provider, OS file-page or network caches.',
      'Source cold bypasses source payload and final response caches, retains the small pending-source route, and performs one Foundation resolution POST. JSON sends typed IDs; current-schema binary forwards the native hot stream. Foundation result caching is disabled; pread diagnostics remain in profiles.',
      'Response HIT proof requires zero archive GET/HEAD, zero Foundation lookup GET and zero resolution POST. Auth KV counts remain separate.',
      'R2/S3 request counts are Worker-owned attempt receipts. Stream completion bytes/successes may be deferred. Broker pread headers are diagnostics, not billable R2 proof.',
      'One persistent connection pool is used per provider. No retry, purge, cache-busting query, locator disclosure, URL or credential appears in this receipt.',
      'Client process CPU spans for concurrent calls can overlap. Only platform windows support Worker CPU cost claims.',
      'CPU windows require separate version-filtered platform collection and exact unsampled request matching before a CPU cost claim.'
    ] };
  const cpuPlan = { account_id: a.get('account-id'), worker: a.get('worker'), version: a.get('version'),
    wasmSha256: a.get('wasm-sha256'), requestReceipt: output, windows };
  await Promise.all([mkdir(dirname(output), { recursive: true }), mkdir(dirname(cpuOutput), { recursive: true })]);
  await writeFile(output, JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  await writeFile(cpuOutput, JSON.stringify(cpuPlan, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({ event: 'complete', status: report.status, requests: samples.length, receipt: output, cpuPlan: cpuOutput }));
  if (stoppedEarly || samples.length !== 91 || report.proof.successful !== 91) process.exitCode = 1;
  return report;
}

function selfTest() {
  const plan = foundationPlan([1, 2, 3, 4]), tasks = plan.flatMap(p => p.groups.flat());
  assert.equal(count(tasks, row => row.source === 'blockzilla'), 66);
  assert.equal(count(tasks, row => row.source === 'provider'), 25);
  assert.equal(plan.filter(p => p.measured).length, 6);
  assert.ok(plan.every(p => /^[A-Za-z][A-Za-z0-9]*$/.test(p.name)));
  const h = publicHeaders(new Headers({ 'x-blockzilla-cache': 'HIT', 'x-blockzilla-locator': 'private-token',
    'x-bz-profile': '{"url":"https://private.example/?api-key=not-for-output"}', authorization: 'Bearer private' }));
  assert.equal(h['x-blockzilla-cache'], 'HIT'); assert.equal(h['x-blockzilla-locator'], undefined);
  assert.ok(!JSON.stringify(h).includes('not-for-output')); assert.ok(!JSON.stringify(h).includes('private-token'));
  const hit = { source: 'blockzilla', condition: 'response-hit', cache: 'HIT', storage: { originGets: 0, originHeads: 0 },
    publicHeaders: { 'x-blockzilla-foundation-lookup-http-requests': '0', 'x-blockzilla-foundation-resolve-http-requests': '0' } };
  assert.equal(requestProof(hit).passed, true);
  hit.publicHeaders['x-blockzilla-foundation-resolve-http-requests'] = '1'; assert.equal(requestProof(hit).passed, false);
  console.log(JSON.stringify({ status: 'PASS', phases: plan.length, measuredPhases: 6, requests: 91, workerRequests: 66, heliusRequests: 25 }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) runBenchmark(process.argv.slice(2)).catch(() => {
  console.error('Foundation service benchmark stopped. No private endpoint or credential was printed.'); process.exitCode = 1;
});
