#!/usr/bin/env node
// Bounded placement experiment. Endpoint values and keys stay in environment variables.
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, access } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { sampleRequest, validateJsonSample, loadSlots, loadBinaryReferences, summarize, compareContents,
  storageReceipt, authReceipt } from './bench-get-block.mjs';
import { publicHeaders } from './bench-foundation-service.mjs';
import { decodeV1Bundle } from './bench-resolution-client.mjs';
import { parseProfile } from './profile-get-block.mjs';
import { TransportTrace } from './diagnose-get-block-transport.mjs';

const ENV = /^[A-Z][A-Z0-9_]*$/;
const LABEL = /^[a-z][a-z0-9_-]{0,31}$/;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const finite = x => typeof x === 'number' && Number.isFinite(x) && x >= 0;
const integer = x => Number.isSafeInteger(x) && x >= 0;
const pct = values => {
  const sorted = values.filter(finite).sort((a, b) => a - b);
  return Object.fromEntries([['p50', .5], ['p95', .95], ['p99', .99]].map(([k, p]) => [k,
    sorted.length ? Number(sorted[Math.ceil(sorted.length * p) - 1].toFixed(3)) : null]));
};
const count = (rows, f) => rows.filter(f).length;
const safeError = error => /^[a-z0-9_]{1,80}$/.test(error?.message ?? '') ? error.message : 'validation_or_transport_error';

function parse(argv) {
  if (argv.length === 1 && argv[0] === '--self-test') return { selfTest: true };
  if (argv.length === 1 && ['--help', '-h'].includes(argv[0])) return { help: true };
  const allowed = new Set(['variants', 'rpc-url', 'slots', 'reference', 'binary-reference', 'output',
    'rounds', 'conditions', 'formats', 'timeout-ms', 'max-requests', 'api-key-env']);
  const args = new Map();
  for (let i = 0; i < argv.length; i += 2) {
    const name = argv[i]?.slice(2), value = argv[i + 1];
    if (!argv[i]?.startsWith('--') || !allowed.has(name) || !value || value.startsWith('--') || args.has(name)) throw Error('invalid_arguments');
    args.set(name, value);
  }
  for (const key of ['variants', 'rpc-url', 'slots', 'reference', 'binary-reference', 'output']) if (!args.has(key)) throw Error('missing_argument');
  const n = (name, fallback, max) => {
    const raw = args.get(name) ?? String(fallback), value = Number(raw);
    if (!/^[0-9]+$/.test(raw) || !Number.isInteger(value) || value < 1 || value > max) throw Error('invalid_numeric_bound');
    return value;
  };
  const conditions = (args.get('conditions') ?? 'full').split(','), formats = (args.get('formats') ?? 'json,bin,probe').split(',');
  if (!conditions.length || new Set(conditions).size !== conditions.length || conditions.some(x => !['full', 'source'].includes(x))) throw Error('invalid_conditions');
  if (!formats.length || new Set(formats).size !== formats.length || formats.some(x => !['json', 'bin', 'probe'].includes(x))) throw Error('invalid_formats');
  const keyEnv = args.get('api-key-env') ?? 'BLOCKZILLA_RPC_API_KEY';
  if (!ENV.test(keyEnv)) throw Error('invalid_key_environment');
  return { args, rounds: n('rounds', 2, 10), conditions, formats, timeoutMs: n('timeout-ms', 90000, 180000),
    maxRequests: n('max-requests', 300, 2000), keyEnv };
}

function endpoint(name, env) {
  if (!ENV.test(name ?? '')) throw Error('invalid_endpoint_environment');
  let value;
  try { value = new URL(env[name]); } catch { throw Error('missing_endpoint_environment'); }
  if (value.protocol !== 'https:' || value.username || value.password || value.hash) throw Error('invalid_endpoint');
  return value.toString();
}

export function placementPlan(slots, variants, { rounds = 2, formats = ['json', 'bin', 'probe'], conditions = ['full'] } = {}) {
  if (slots.length !== 4 || new Set(slots).size !== 4 || !variants.length) throw Error('four_slots_required');
  const tasks = [], add = (variant, slot, format, condition, phase, measured, round = 0) => {
    tasks.push({ variant, slot, format, condition, phase, measured, round, paired: measured && format === 'json' });
  };
  // All variants have equal, separately reported runtime/client-connection warmups.
  for (const variant of variants) for (const format of formats) add(variant, slots[0], format, 'full', `RuntimeWarm_${format}`, false);
  for (const condition of conditions) {
    if (condition === 'source') for (const variant of variants) for (const slot of slots) add(variant, slot, formats.includes('json') ? 'json' : 'bin', 'source', 'SourceRoutePrime', false);
    for (let round = 0; round < rounds; round++) for (let slotIndex = 0; slotIndex < slots.length; slotIndex++) {
      // Rotate both target and representation order. Do not give one target all first reads.
      const offset = (round + slotIndex) % variants.length;
      const targets = [...variants.slice(offset), ...variants.slice(0, offset)];
      const foff = (round + slotIndex) % formats.length;
      const orderedFormats = [...formats.slice(foff), ...formats.slice(0, foff)];
      for (const format of orderedFormats) for (const variant of targets) add(variant, slots[slotIndex], format, condition,
        `${condition === 'full' ? 'FullCold' : 'SourceCold'}_${format}`, true, round);
    }
  }
  return tasks;
}

function headerNumber(headers, name) {
  const raw = headers.get(name);
  return /^(0|[1-9][0-9]*)$/.test(raw ?? '') && Number.isSafeInteger(Number(raw)) ? Number(raw) : null;
}

export function operationProof(row) {
  if (row.source !== 'blockzilla') return undefined;
  const errors = [], need = (condition, code) => { if (!condition) errors.push(code); };
  need(row.storage?.originGets === 2 && row.storage?.originHeads === 0, 'two_gets_zero_heads');
  need(row.condition === 'full' ? row.lookupGets === 1 : row.phase === 'SourceRoutePrime'
    ? row.lookupGets === 0 || row.lookupGets === 1 : row.lookupGets === 0, 'source_lookup_count');
  need(row.resolvePosts === (row.representation === 'probe' ? 0 : 1), 'resolve_post_count');
  need(row.cache === 'BYPASS', 'response_cache_bypass');
  need(row.storage?.archiveMemoryHits === 0 && row.storage?.archiveEdgeHits === 0, 'zero_source_cache_hits');
  if (row.condition === 'full') need(row.auth?.cache === 'BYPASS' && row.auth?.kvReads === 1, 'cold_key_check');
  return { passed: errors.length === 0, errors, archiveGets: row.storage?.originGets ?? null,
    archiveHeads: row.storage?.originHeads ?? null, lookupGets: row.lookupGets, resolvePosts: row.resolvePosts };
}

function profile(headers) {
  try { return parseProfile(headers.get('X-BZ-Profile')); } catch { return null; }
}

export function capturePlacement(headers, parsedProfile) {
  const event = parsedProfile?.eventsByName?.worker_placement?.at(-1)?.placement;
  const raw = headers.get('cf-placement');
  const responseCfPlacement = raw === null ? null : /^[A-Za-z0-9 .,_:=;-]{1,160}$/.test(raw) ? raw : '[unparsed]';
  // request.cf.colo can remain at ingress when placement forwards execution.
  // Only the Worker-observed forwarding marker confirms remote execution.
  const confirmedPlacement = event?.mode === 'remote' && event.targetColo ? `remote-${event.targetColo}`
    : event?.mode === 'local' ? 'local' : 'unknown';
  return { requestColo: event?.colo ?? null, forwardingMode: event?.mode ?? null, targetColo: event?.targetColo ?? null,
    confirmedPlacement, confirmedExecutionColo: event?.mode === 'remote' ? event.targetColo ?? null
      : event?.mode === 'local' ? event.colo ?? null : null, responseCfPlacement };
}

export function placementSummary(samples) {
  const groups = new Map(), counts = values => Object.fromEntries([...new Set(values)].map(k => [k, values.filter(x => x === k).length]));
  for (const row of samples.filter(x => x.source === 'blockzilla' && x.measured)) {
    const group = groups.get(row.label) ?? []; group.push(row); groups.set(row.label, group);
  }
  return [...groups].map(([label, rows]) => ({ label, requests: rows.length,
    requestColos: counts(rows.map(x => x.placement?.requestColo ?? 'UNREPORTED')),
    clientIngressEdges: counts(rows.map(x => x.edgeLocation ?? 'UNREPORTED')),
    confirmedPlacements: counts(rows.map(x => x.placement?.confirmedPlacement ?? 'unknown')),
    confirmedExecutionColos: counts(rows.map(x => x.placement?.confirmedExecutionColo ?? 'UNPROVEN')),
    responseCfPlacements: counts(rows.map(x => x.placement?.responseCfPlacement ?? 'ABSENT')) }));
}

export function validateProbe(value, expected, slot) {
  assert.equal(value.version, 1, 'probe_version'); assert.equal(value.slot, slot, 'probe_slot');
  assert.equal(value.epoch, Math.floor(slot / 432000), 'probe_epoch');
  assert.equal(value.parallel, true, 'probe_parallel');
  assert.equal(value.connectionTiming, 'unavailable-in-workers-fetch', 'probe_connection_claim');
  assert.equal(value.clock, 'workers-io-clock', 'probe_clock');
  assert.equal(value.resultCache, false, 'probe_result_cache');
  assert.equal(value.rangeCache, false, 'probe_range_cache');
  assert.equal(value.timingScope, 'each-range-start-to-native-body-EOF;digest-after-EOF', 'probe_timing_scope');
  assert.ok(Array.isArray(value.ranges) && value.ranges.length === 2, 'probe_range_count');
  const ranges = [];
  for (const kind of ['hot', 'signatures']) {
    const found = value.ranges.filter(x => x?.kind === kind);
    assert.equal(found.length, 1, 'probe_range_kind');
    const x = found[0], ref = expected[kind];
    assert.equal(x.expectedBytes, ref.bytes, 'probe_expected_bytes');
    assert.equal(x.receivedBytes, ref.bytes, 'probe_received_bytes');
    assert.equal(x.sha256, ref.sha256, 'probe_original_range_sha');
    for (const name of ['headersMs', 'firstChunkMs', 'totalMs', 'bodyMs', 'transferMs']) assert.ok(finite(x[name]), 'probe_numeric_time');
    assert.ok(x.firstChunkMs >= x.headersMs && x.totalMs >= x.firstChunkMs, 'probe_time_order');
    assert.ok(Math.abs(x.bodyMs - (x.totalMs - x.headersMs)) < 0.01, 'probe_body_time_arithmetic');
    assert.ok(Math.abs(x.transferMs - (x.totalMs - x.firstChunkMs)) < 0.01, 'probe_transfer_time_arithmetic');
    assert.ok(integer(x.chunks) && x.chunks > 0, 'probe_chunks');
    assert.equal(x.connectionMs, null, 'probe_connection_unavailable');
    assert.equal(x.connectionReuse, null, 'probe_reuse_unavailable');
    assert.ok(x.upstreamColo === null || /^[A-Z]{3}$/.test(x.upstreamColo), 'probe_colo');
    ranges.push(Object.fromEntries(['kind', 'expectedBytes', 'receivedBytes', 'sha256', 'headersMs', 'firstChunkMs',
      'totalMs', 'bodyMs', 'transferMs', 'chunks', 'upstreamColo', 'connectionMs', 'connectionReuse'].map(k => [k, x[k]])));
  }
  return { version: value.version, slot, epoch: value.epoch, parallel: true, ranges,
    connectionTiming: value.connectionTiming, clock: value.clock, resultCache: false, rangeCache: false, timingScope: value.timingScope };
}

async function probeRequest(task, config, span, expected) {
  const started = performance.now(), startedAt = new Date().toISOString(), controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.timeoutMs);
  const row = { source: 'blockzilla', label: task.variant.label, slot: task.slot, phase: task.phase, round: task.round,
    representation: 'probe', condition: task.condition, measured: task.measured, startedAt, ok: false, bytes: 0, ttfbMs: null };
  try {
    const url = new URL(config.workerUrl); url.pathname = `${url.pathname.replace(/\/$/, '')}/block/${task.slot}.bin`;
    url.searchParams.set('profile', task.condition === 'source' ? 'source' : '1'); url.searchParams.set('r2_probe', '1');
    const response = await span.fetch(url, { method: 'GET', headers: { Authorization: `Bearer ${config.key}` },
      signal: controller.signal, redirect: 'error' });
    row.headersMs = performance.now() - started; row.status = response.status;
    row.cache = response.headers.get('X-Blockzilla-Cache') ?? 'UNREPORTED';
    row.storage = storageReceipt(response.headers); row.auth = authReceipt(response.headers);
    row.publicHeaders = publicHeaders(response.headers); row.profile = profile(response.headers);
    row.placement = capturePlacement(response.headers, row.profile);
    row.edgeLocation = response.headers.get('CF-Ray')?.split('-').at(-1)?.match(/^[A-Z]{3}$/)?.[0] ?? null;
    row.lookupGets = headerNumber(response.headers, 'X-Blockzilla-Foundation-Lookup-HTTP-Requests');
    row.resolvePosts = headerNumber(response.headers, 'X-Blockzilla-Foundation-Resolve-HTTP-Requests');
    const chunks = [], reader = response.body?.getReader();
    if (!reader) throw Error('probe_empty_body');
    try { while (true) {
      const { done, value } = await reader.read(); if (done) break;
      if (value.byteLength) { row.ttfbMs ??= performance.now() - started; row.bytes += value.byteLength;
        if (row.bytes > 65536) { controller.abort(); throw Error('probe_body_limit'); } chunks.push(value); }
    } } finally { reader.releaseLock(); }
    row.totalMs = performance.now() - started;
    if (response.status !== 200) throw Error('probe_http_error');
    row.probe = validateProbe(JSON.parse(Buffer.concat(chunks, row.bytes).toString('utf8')), expected, task.slot);
    row.ok = true;
  } catch (error) { row.totalMs ??= performance.now() - started; row.error = safeError(error); }
  finally { row.completedAt = new Date().toISOString(); clearTimeout(timer); }
  row.requestProof = operationProof(row);
  if (!row.requestProof.passed) { row.ok = false; row.error ??= 'operation_receipt_mismatch'; }
  return row;
}

export function probeSummary(samples) {
  const groups = new Map();
  for (const row of samples.filter(x => x.measured && x.representation === 'probe')) {
    const key = `${row.label}/${row.phase}`, group = groups.get(key) ?? []; group.push(row); groups.set(key, group);
  }
  return [...groups].map(([key, rows]) => ({ key, requests: rows.length, successful: count(rows, x => x.ok),
    ranges: ['hot', 'signatures'].map(kind => {
      const values = rows.filter(x => x.ok).map(x => x.probe.ranges.find(x => x.kind === kind));
      return { kind, samples: values.length, ...Object.fromEntries(['headersMs', 'firstChunkMs', 'totalMs', 'bodyMs', 'transferMs', 'receivedBytes']
        .map(name => [name, pct(values.map(x => x[name]))])), upstreamColos: [...new Set(values.map(x => x.upstreamColo))] };
    }) }));
}

export function pairedSummary(samples) {
  const pairs = new Map();
  for (const row of samples.filter(x => x.measured && x.representation === 'json')) {
    const label = row.source === 'provider' ? row.pairedVariant : row.label;
    const key = `${label}/${row.phase}/${row.slot}/${row.round}`;
    const pair = pairs.get(key) ?? { label, phase: row.phase, slot: row.slot, round: row.round };
    pair[row.source === 'provider' ? 'provider' : 'worker'] = row;
    pairs.set(key, pair);
  }
  const groups = new Map();
  for (const pair of pairs.values()) {
    const key = `${pair.label}/${pair.phase}`, group = groups.get(key) ?? []; group.push(pair); groups.set(key, group);
  }
  return [...groups].map(([key, pairs]) => {
    const valid = pairs.filter(x => x.worker?.ok && x.provider?.ok);
    return { key, pairs: pairs.length, validPairs: valid.length, workerFasterPairs: count(valid, x => x.worker.totalMs < x.provider.totalMs),
      workerTotalMs: pct(valid.map(x => x.worker.totalMs)), heliusTotalMs: pct(valid.map(x => x.provider.totalMs)),
      workerTtfbMs: pct(valid.map(x => x.worker.ttfbMs)), heliusTtfbMs: pct(valid.map(x => x.provider.ttfbMs)),
      pairsDetail: pairs.map(x => ({ slot: x.slot, round: x.round, passed: Boolean(x.worker?.ok && x.provider?.ok),
        workerTotalMs: x.worker?.totalMs ?? null, heliusTotalMs: x.provider?.totalMs ?? null,
        workerMinusHeliusMs: x.worker?.ok && x.provider?.ok ? x.worker.totalMs - x.provider.totalMs : null })) };
  });
}

export async function main(argv, env = process.env) {
  const p = parse(argv); if (p.selfTest) return selfTest();
  if (p.help) return console.log('Usage: node scripts/bench-r2-placement.mjs --variants FILE --rpc-url @HELIUS_URL --slots FILE --reference PRIOR_JSON_REPORT --binary-reference INPUT_MANIFEST --output NEW_REPORT [--rounds 2 --conditions full --formats json,bin,probe --max-requests 300]');
  const a = p.args, output = resolve(a.get('output'));
  try { await access(output); throw Error('output_exists'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const manifest = JSON.parse(await readFile(a.get('variants'), 'utf8')), variants = manifest.variants;
  if (!Array.isArray(variants) || !variants.length || variants.length > 12 || new Set(variants.map(x => x.label)).size !== variants.length) throw Error('invalid_variants');
  for (const x of variants) {
    if (!LABEL.test(x.label ?? '') || !ENV.test(x.urlEnv ?? '') || !/^[a-zA-Z0-9_-]{1,128}$/.test(x.worker ?? '')
      || !/^[a-f0-9-]{16,80}$/.test(x.version ?? '') || !/^[a-f0-9]{64}$/.test(x.wasmSha256 ?? '')) throw Error('invalid_variant_identity');
  }
  const slots = await loadSlots(a.get('slots')), tasks = placementPlan(slots, variants, p);
  const plannedRequests = tasks.length + count(tasks, x => x.paired);
  if (plannedRequests > p.maxRequests) throw Error('request_budget_exceeded');
  const reference = JSON.parse(await readFile(a.get('reference'), 'utf8'));
  const digests = new Map(reference.samples.filter(x => x.ok && /^[a-f0-9]{64}$/.test(x.contentSha256)).map(x => [x.slot, x.contentSha256]));
  const binaryReferences = await loadBinaryReferences(a.get('binary-reference'));
  const inputs = JSON.parse(await readFile(a.get('binary-reference'), 'utf8')), parts = new Map();
  for (const r of inputs.records) {
    if (!slots.includes(r.slot)) continue;
    const x = decodeV1Bundle(await readFile(r.bundlePath));
    parts.set(r.slot, { hot: { bytes: x.hot.length, sha256: sha256(x.hot) }, signatures: { bytes: x.signatures.length, sha256: sha256(x.signatures) },
      bundleBytes: x.bytes.length, accessBytes: x.access.length });
  }
  if (slots.some(slot => !digests.has(slot) || !binaryReferences.has(slot) || !parts.has(slot))) throw Error('missing_original_reference');
  const key = env[p.keyEnv]; if (!key || /[\r\n]/.test(key)) throw Error('missing_worker_key');
  const providerRef = a.get('rpc-url'); if (!/^@[A-Z][A-Z0-9_]*$/.test(providerRef)) throw Error('provider_environment_required');
  const providerUrl = endpoint(providerRef.slice(1), env), urls = new Map(variants.map(x => [x.label, endpoint(x.urlEnv, env)]));
  const trace = new TransportTrace(), pools = Object.fromEntries([...variants.map(x => x.label), 'helius'].map(label => [label, trace.dispatcher(label)]));
  const startedAt = new Date().toISOString(), samples = [], windows = [], settings = { providers: [{ label: 'helius', url: providerUrl }],
    blockzillaKey: key, timeoutMs: p.timeoutMs, rpcEncoding: 'base64', maxTransactionVersion: 1, binaryReferences };
  let stoppedEarly = false;
  console.log(JSON.stringify({ event: 'start', plannedRequests, variants: variants.map(x => x.label), formats: p.formats, rounds: p.rounds }));
  try { for (const task of tasks) {
    const deferred = [], condition = task.condition, workerSpan = trace.begin(task.variant.label, pools[task.variant.label]);
    const begin = new Date().toISOString();
    const worker = task.format === 'probe' ? probeRequest(task, { workerUrl: urls.get(task.variant.label), key, timeoutMs: p.timeoutMs }, workerSpan, parts.get(task.slot)) : (async () => {
      let headers;
      const fetchImplementation = async (url, options) => { const response = await workerSpan.fetch(url, options); headers = response.headers; return response; };
      const x = await sampleRequest({ source: 'blockzilla', label: task.variant.label, slot: task.slot, phase: task.phase, round: task.round,
        representation: task.format, uncached: condition === 'full', sourceUncached: condition === 'source' },
        { ...settings, blockzillaUrl: urls.get(task.variant.label), fetchImplementation, deferredJsonValidation: deferred });
      x.condition = condition; x.measured = task.measured;
      if (headers) { x.publicHeaders = publicHeaders(headers); x.profile = profile(headers); x.placement = capturePlacement(headers, x.profile);
        x.lookupGets = headerNumber(headers, 'X-Blockzilla-Foundation-Lookup-HTTP-Requests');
        x.resolvePosts = headerNumber(headers, 'X-Blockzilla-Foundation-Resolve-HTTP-Requests'); }
      x.requestProof = operationProof(x);
      if (!x.requestProof.passed) { x.ok = false; x.error ??= 'operation_receipt_mismatch'; }
      return x;
    })();
    let providerSpan, provider;
    if (task.paired) {
      providerSpan = trace.begin('helius', pools.helius);
      provider = sampleRequest({ source: 'provider', label: 'helius', providerIndex: 0, slot: task.slot, phase: task.phase,
        round: task.round, representation: 'json' }, { ...settings, fetchImplementation: providerSpan.fetch, deferredJsonValidation: deferred });
    }
    const rows = await Promise.all(provider ? [worker, provider] : [worker]);
    rows[0].transport = trace.finish(workerSpan);
    if (providerSpan) { rows[1].transport = trace.finish(providerSpan); rows[1].condition = condition; rows[1].measured = task.measured; rows[1].pairedVariant = task.variant.label; }
    // Both complete-body timers stop before canonical JSON validation.
    for (const pending of deferred) {
      try { if (!validateJsonSample(pending.sample, pending.chunks)) pending.sample.ok = false; }
      catch { pending.sample.ok = false; pending.sample.error = 'json_validation_error'; }
      delete pending.sample.validationDeferred;
    }
    for (const row of rows) {
      if (row.representation === 'json') { row.matchesSavedReference = row.contentSha256 === digests.get(row.slot);
        if (!row.matchesSavedReference) { row.ok = false; row.error ??= 'saved_json_mismatch'; } }
      samples.push(row);
      console.log(JSON.stringify({ event: 'sample', label: row.label, phase: row.phase, measured: row.measured, slot: row.slot,
        ok: row.ok, error: row.error ?? null, totalMs: row.totalMs, ttfbMs: row.ttfbMs, requests: row.requestProof ?? null }));
    }
    windows.push({ label: task.variant.label, phase: task.phase, measured: task.measured, round: task.round, slot: task.slot,
      start: begin, end: new Date().toISOString(), workerRequests: 1, providerRequests: task.paired ? 1 : 0 });
    if (rows.some(x => !x.ok)) { stoppedEarly = true; break; }
  } } finally { await Promise.allSettled(Object.values(pools).map(x => x.close())); trace.close(); }
  const report = { schema: 'blockzilla.r2-placement-benchmark.v1', status: stoppedEarly ? 'FAIL' : 'PASS', startedAt,
    completedAt: new Date().toISOString(), deployments: variants.map(({ urlEnv, ...x }) => x),
    plan: { slots, rounds: p.rounds, conditions: p.conditions, formats: p.formats, plannedRequests, retries: 0,
      workerRequests: tasks.length, providerRequests: count(tasks, x => x.paired), warmups: count(tasks, x => !x.measured),
      maxRequests: p.maxRequests, timeoutMs: p.timeoutMs, rotateVariantsAndFormats: true, pairedJsonConcurrent: true },
    proof: { requests: samples.length, successful: count(samples, x => x.ok), stoppedEarly,
      workerReceiptsPassed: count(samples, x => x.requestProof?.passed), exactBinaryMatches: count(samples, x => x.binaryMatchesReference),
      exactRangePairs: count(samples, x => x.probe?.ranges.length === 2 && x.ok), fullJsonMatches: count(samples, x => x.matchesSavedReference) },
    binaryComponents: [...parts].map(([slot, x]) => ({ slot, ...x })), windows,
    groups: summarize(samples.filter(x => x.representation !== 'probe')), rangeGroups: probeSummary(samples), pairedComparisons: pairedSummary(samples),
    placementGroups: placementSummary(samples),
    contentChecks: compareContents(samples, ['helius'], variants.map(x => x.label)), connections: trace.connectionReport(), samples,
    notes: [
      'FullCold bypasses application response, payload, source-route and API-key caches. It does not clear R2 service caches, provider caches, OS pages or Worker connection pools.',
      'Runtime warmups are separate from measured requests. Every measured request still bypasses application caches. SourceCold, if selected, retains routes/auth and has separate route primes.',
      'Each measured JSON request is paired concurrently with Helius for the same block and canonical content. Provider cache state is unknown. Binary and range-probe payloads have no equivalent Helius payload.',
      'The normal binary endpoint is the existing self-contained Wincode bundle with a compressed Compact V2 hot frame, raw signatures and a per-block address/hash mapping. The raw hot frame alone cannot reconstruct the full block.',
      'The probe reads the two original ranges once and consumes them in parallel. Its JSON response is a diagnostic, not a complete block or a binary throughput result. Its range SHA checks use saved original bundle components.',
      'Range headersMs, firstChunkMs and totalMs start at the individual fetch dispatch. bodyMs runs from headers to EOF; transferMs runs from first chunk to EOF. Overlapping range times must not be added.',
      'Workers fetch exposes no DNS, TCP, TLS, pool wait or upstream connection reuse breakdown. Null fields are unavailable, not zero. The IO clock can report zero for short intervals; these are elapsed measurements, not CPU.',
      'Client connection records expose DNS, TCP and TLS for client-to-Worker or client-to-Helius only. They do not describe Worker-to-R2 connections. Socket reuse requires the same recorded socket ID.',
      'No endpoint values, secret request headers, locator tokens, source keys or response bodies are stored. No object copy, cache purge or retry is part of this runner.',
      'Placements are requested configurations. Actual execution and upstream collector locations must be checked in each response; a configuration name does not prove the physical storage location.',
      'request.cf.colo and client CF-Ray are recorded separately from confirmed execution placement. Only the Worker-observed cf-placement=remote-COLO marker confirms a remote execution colo; upstream CF-Ray names an HTTP collector and does not identify the physical R2 bucket location.',
      'Two rounds over four fixed blocks give eight measured samples per format and target. The p95 is the largest of those eight; this small experiment does not prove a global provider ranking.',
    ] };
  await mkdir(dirname(output), { recursive: true }); await writeFile(output, JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({ event: 'complete', status: report.status, proof: report.proof, receipt: output }));
  if (stoppedEarly || samples.length !== plannedRequests) process.exitCode = 1;
  return report;
}

function selfTest() {
  const variants = [{ label: 'a' }, { label: 'b' }, { label: 'c' }], plan = placementPlan([1, 2, 3, 4], variants);
  assert.equal(plan.length, 81); assert.equal(count(plan, x => x.paired), 24);
  assert.equal(count(plan, x => !x.measured), 9);
  for (const v of variants) for (const format of ['json', 'bin', 'probe']) assert.equal(count(plan, x => x.variant.label === v.label && x.format === format && x.measured), 8);
  const expected = { hot: { bytes: 5, sha256: 'a'.repeat(64) }, signatures: { bytes: 64, sha256: 'b'.repeat(64) } };
  const value = { version: 1, slot: 1, epoch: 0, parallel: true, connectionTiming: 'unavailable-in-workers-fetch', clock: 'workers-io-clock',
    resultCache: false, rangeCache: false, timingScope: 'each-range-start-to-native-body-EOF;digest-after-EOF',
    ranges: ['hot', 'signatures'].map(kind => ({ kind, expectedBytes: expected[kind].bytes, receivedBytes: expected[kind].bytes,
      sha256: expected[kind].sha256, headersMs: 3, firstChunkMs: 4, totalMs: 5, bodyMs: 2, transferMs: 1,
      chunks: 1, upstreamColo: 'CDG', connectionMs: null, connectionReuse: null })) };
  assert.equal(validateProbe(value, expected, 1).ranges.length, 2);
  assert.throws(() => validateProbe({ ...value, slot: 2 }, expected, 1));
  assert.throws(() => validateProbe({ ...value, ranges: [{ ...value.ranges[0], connectionMs: 0 }, value.ranges[1]] }, expected, 1));
  assert.throws(() => validateProbe({ ...value, ranges: [{ ...value.ranges[0], firstChunkMs: 2 }, value.ranges[1]] }, expected, 1));
  assert.throws(() => validateProbe({ ...value, ranges: [{ ...value.ranges[0], bodyMs: 99 }, value.ranges[1]] }, expected, 1));
  assert.throws(() => validateProbe({ ...value, ranges: [{ ...value.ranges[0], transferMs: 99 }, value.ranges[1]] }, expected, 1));
  const row = { source: 'blockzilla', condition: 'full', representation: 'probe', phase: 'FullCold_probe', lookupGets: 1, resolvePosts: 0,
    cache: 'BYPASS', storage: { originGets: 2, originHeads: 0, archiveMemoryHits: 0, archiveEdgeHits: 0 }, auth: { cache: 'BYPASS', kvReads: 1 } };
  assert.equal(operationProof(row).passed, true); assert.equal(operationProof({ ...row, resolvePosts: 1 }).passed, false);
  const pair = pairedSummary([{ measured: true, representation: 'json', source: 'blockzilla', label: 'a', phase: 'FullCold_json', slot: 1, round: 0, ok: true, totalMs: 20, ttfbMs: 19 },
    { measured: true, representation: 'json', source: 'provider', pairedVariant: 'a', label: 'helius', phase: 'FullCold_json', slot: 1, round: 0, ok: true, totalMs: 30, ttfbMs: 29 }]);
  assert.equal(pair[0].validPairs, 1); assert.equal(pair[0].workerFasterPairs, 1); assert.equal(pair[0].pairsDetail[0].workerMinusHeliusMs, -10);
  const placement = capturePlacement(new Headers({ 'cf-placement': 'remote-FRA' }), { eventsByName: { worker_placement: [
    { placement: { colo: 'CDG', mode: 'remote', targetColo: 'FRA' } }] } });
  assert.equal(placement.requestColo, 'CDG'); assert.equal(placement.confirmedExecutionColo, 'FRA');
  assert.equal(capturePlacement(new Headers(), null).confirmedPlacement, 'unknown');
  console.log(JSON.stringify({ status: 'PASS', workerRequests: 81, heliusRequests: 24, plannedRequests: 105,
    warmups: 9, measuredPerVariantPerFormat: 8, invalidTimingClaimsRejected: true }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main(process.argv.slice(2)).catch(() => {
  console.error('R2 placement benchmark stopped. Private details were not printed.'); process.exitCode = 1;
});
