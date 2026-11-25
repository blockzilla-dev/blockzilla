#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir, stat } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import { dirname } from 'node:path';
import { pathToFileURL } from 'node:url';
import { canonicalBlockDigest, loadSlots, storageReceipt, storageClassification, authReceipt, sourceUncachedVerified } from './bench-get-block.mjs';
import { decodeV1Bundle, encodeULEB } from './bench-resolution-client.mjs';

const MAX_BODY = 64 * 1024 * 1024;
const MAX_PROFILE = 256 * 1024;
const NAME = /^[A-Za-z0-9_.:-]{1,80}$/;
const check = (condition, message) => { if (!condition) throw new Error(message); };
const finite = (value) => typeof value === 'number' && Number.isFinite(value) && value >= 0;
const integer = (value) => Number.isSafeInteger(value) && value >= 0;
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function usage() {
  return `Usage:
  BLOCKZILLA_RPC_API_KEY=... node scripts/profile-get-block.mjs \\
    --url @WORKER_URL --slots slots.json --representations json \\
    --max-requests 8 --output profile.json [--json-reference main-v7.json]

Options:
  --url              Worker base URL, or @ENV_NAME. Required.
  --slots            Slot list or file, as in bench-get-block.mjs. Required.
  --representations  json,bin,bin-no-access. Default: json.
  --profile-body     stream or buffered. Default: stream. Buffered supports JSON only.
  --profile-mode     full or source. Default: full. Source retains index/auth caches.
                     Prime those caches in a separate counted warmup before this runner.
  --max-requests     Hard request limit. Default: 12. Maximum: 32.
  --timeout-ms       Per-request timeout through the full body. Default: 90000.
  --json-reference   Existing benchmark report with successful Helius digests.
  --input-manifest   Existing input manifest for exact full binary SHA-256 checks.
  --required-stages  Comma-separated profile summary names required on each call.
  --output           New JSON report path. Required. Existing files are preserved.
  --self-test        Test parsers and four complete local HTTP requests.

Every request uses GET and profile=1 or profile=source. Requests run in order with no retry.
The runner stops on the first failure and saves the partial report.
The request budget is checked before any request. An oversized plan is rejected.
The report omits endpoints, credentials, locator tokens, source keys, and event details.
Profile durations are wall time. Nested and parallel stages can overlap.
Actual Worker CPU must come from the platform API, outside these headers.
Profile JSON can use a buffered render path. Its mode is reported separately.`;
}

export function parseArgs(argv) {
  if (argv.includes('--help') || argv.includes('-h')) return { help: true };
  if (argv.length === 1 && argv[0] === '--self-test') return { selfTest: true };
  const allowed = new Set(['url', 'slots', 'representations', 'profile-body', 'profile-mode', 'max-requests', 'timeout-ms', 'json-reference', 'input-manifest', 'required-stages', 'output']);
  const values = new Map();
  for (let at = 0; at < argv.length; at += 2) {
    const name = argv[at]?.slice(2), value = argv[at + 1];
    check(argv[at]?.startsWith('--') && allowed.has(name), 'Unknown argument. Use --help.');
    check(!values.has(name) && value && !value.startsWith('--'), 'Missing or repeated argument.');
    values.set(name, value);
  }
  for (const name of ['url', 'slots', 'output']) check(values.has(name), `Missing --${name}.`);
  const number = (name, fallback, maximum) => {
    const text = values.get(name) ?? String(fallback);
    check(/^[0-9]+$/.test(text), `Invalid --${name}.`);
    const value = Number(text);
    check(Number.isSafeInteger(value) && value > 0 && value <= maximum, `Invalid --${name}.`);
    return value;
  };
  const representations = (values.get('representations') ?? 'json').split(',');
  check(representations.length > 0 && new Set(representations).size === representations.length
    && representations.every(value => ['json', 'bin', 'bin-no-access'].includes(value)), 'Invalid representations.');
  const profileBody = values.get('profile-body') ?? 'stream';
  check(['stream', 'buffered'].includes(profileBody), 'Invalid profile body mode.');
  check(profileBody !== 'buffered' || representations.every(value => value === 'json'), 'Buffered profile supports JSON only.');
  const profileMode = values.get('profile-mode') ?? 'full';
  check(['full', 'source'].includes(profileMode), 'Invalid profile cache mode.');
  const requiredStages = values.has('required-stages') ? values.get('required-stages').split(',') : [];
  check(requiredStages.every(value => NAME.test(value)), 'Invalid required profile stage.');
  return { url: values.get('url'), slots: values.get('slots'), output: values.get('output'),
    representations, profileBody, profileMode, maxRequests: number('max-requests', 12, 32), timeoutMs: number('timeout-ms', 90000, 180000),
    jsonReference: values.get('json-reference'), inputManifest: values.get('input-manifest'), requiredStages };
}

function endpoint(value, env) {
  try {
    const url = new URL(value.startsWith('@') ? env[value.slice(1)] : value);
    check(['http:', 'https:'].includes(url.protocol) && !url.username && !url.password && !url.hash, 'Invalid endpoint.');
    return url;
  } catch { throw new Error('Invalid Worker URL or missing environment value.'); }
}

function safeMode(headers, name) {
  const text = headers.get(name);
  return text && /^[A-Za-z0-9_.:-]{1,80}$/.test(text) ? text : null;
}

export function parseProfile(raw) {
  check(typeof raw === 'string' && raw.length <= MAX_PROFILE, 'Missing or oversized profile header.');
  let value;
  try { value = JSON.parse(raw); } catch { throw new Error('Invalid profile header JSON.'); }
  check(value && finite(value.totalMs) && Array.isArray(value.events) && value.events.length <= 4096
    && Array.isArray(value.summary) && value.summary.length <= 512, 'Invalid profile header shape.');
  const summary = {};
  for (const row of value.summary) {
    check(row && NAME.test(row.name) && finite(row.totalMs) && integer(row.count) && integer(row.bytes)
      && !Object.hasOwn(summary, row.name), 'Invalid profile summary row.');
    Object.defineProperty(summary, row.name, { value: { totalMs: row.totalMs, count: row.count, bytes: row.bytes }, enumerable: true });
  }
  const events = value.events.map(row => {
    check(row && NAME.test(row.name) && finite(row.ms) && integer(row.bytes)
      && (row.status === null || row.status === undefined || integer(row.status) && row.status >= 100 && row.status <= 599), 'Invalid profile event.');
    const event = { name: row.name, ms: row.ms, bytes: row.bytes, status: row.status ?? null };
    if (row.name === 'worker_placement') {
      const match = typeof row.detail === 'string' && row.detail.length <= 256 ? /^colo=([A-Z]{3});placement=(.*)$/.exec(row.detail) : null;
      const placement = match ? /^(local|remote)(?:[-=:]([A-Z]{3}))?$/.exec(match[2].trim())
        ?? /^(targeted)-([A-Z]{3})$/.exec(match[2].trim()) : null;
      event.placement = { colo: match?.[1] ?? null, mode: placement?.[1] ?? null, targetColo: placement?.[2] ?? null,
        headerPresent: match ? match[2].trim().length > 0 : null };
    }
    const upstream = typeof row.detail === 'string' ? /^s3_collector=([A-Z]{3}|)$/.exec(row.detail) : null;
    if (upstream) event.upstreamColo = upstream[1] || null;
    return event;
  });
  return { totalMs: value.totalMs, events, eventsTruncated: value.eventsTruncated === true, eventsByName: Object.fromEntries(
    [...new Set(events.map(event => event.name))].map(name => [name, events.filter(event => event.name === name)])), summary, eventDetailsOmitted: true };
}

function splitQuoted(text, delimiter) {
  const result = [];
  let part = '', quoted = false, escape = false;
  for (const character of text) {
    if (escape) escape = false;
    else if (character === '\\' && quoted) escape = true;
    else if (character === '"') quoted = !quoted;
    if (character === delimiter && !quoted) { result.push(part); part = ''; } else part += character;
  }
  check(!quoted && !escape, 'Invalid Server-Timing quotes.');
  result.push(part);
  return result;
}

export function parseServerTiming(raw) {
  if (raw === null) return [];
  check(typeof raw === 'string' && raw.length <= MAX_PROFILE, 'Oversized Server-Timing header.');
  return splitQuoted(raw, ',').filter(part => part.trim()).map(part => {
    const [namePart, ...parameters] = splitQuoted(part, ';');
    const name = namePart.trim();
    check(NAME.test(name), 'Invalid Server-Timing name.');
    const durations = parameters.map(parameter => /^\s*dur\s*=\s*([0-9]+(?:\.[0-9]+)?)\s*$/.exec(parameter)).filter(Boolean);
    check(durations.length <= 1, 'Repeated Server-Timing duration.');
    const durationMs = durations.length ? Number(durations[0][1]) : null;
    check(durationMs === null || finite(durationMs), 'Invalid Server-Timing duration.');
    return { name, durationMs };
  });
}

function cacheStatus(headers) {
  const value = headers.get('X-Blockzilla-Cache')?.toUpperCase();
  return ['HIT', 'MISS', 'BYPASS', 'UNCACHED'].includes(value) ? value : 'UNREPORTED';
}

function validateNoAccessBundle(bytes, expectedSlot) {
  let offset = 0;
  const unsigned = () => {
    const start = offset;
    let value = 0n;
    for (let shift = 0n; shift < 70n; shift += 7n) {
      check(offset < bytes.length, 'Truncated binary integer.');
      const byte = bytes[offset++];
      value |= BigInt(byte & 127) << shift;
      if (!(byte & 128)) {
        check(value <= BigInt(Number.MAX_SAFE_INTEGER), 'Oversized binary integer.');
        const number = Number(value);
        check(offset - start === encodeULEB(number).length, 'Non-canonical binary integer.');
        return number;
      }
    }
    throw new Error('Oversized binary integer.');
  };
  check(unsigned() === 1 && unsigned() === expectedSlot && bytes[offset++] === 1, 'Binary header differs.');
  const length = unsigned();
  check(length > 0 && length <= 16 * 1024 * 1024 && offset + length + 2 === bytes.length, 'Binary hot length differs.');
  offset += length;
  check(bytes[offset++] === 0 && bytes[offset] === 0, 'Binary access mode differs.');
}

export async function profileRequest(settings, task) {
  const sourceMode = settings.profileMode === 'source';
  const sample = { startedAt: new Date().toISOString(), slot: task.slot, representation: task.representation,
    requestedProfileBody: settings.profileBody ?? 'stream', requestedProfileMode: settings.profileMode ?? 'full',
    source: 'blockzilla', uncached: !sourceMode, sourceUncached: sourceMode,
    ok: false, status: null, cache: 'UNREPORTED', bytes: 0, headersMs: null, ttfbMs: null, totalMs: null };
  const started = performance.now(), controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), settings.timeoutMs);
  try {
    const url = new URL(settings.url);
    url.pathname = `${url.pathname.replace(/\/$/, '')}/block/${task.slot}.${task.representation === 'bin-no-access' ? 'bin' : task.representation}`;
    url.searchParams.set('profile', sourceMode ? 'source' : '1');
    if (settings.profileBody === 'buffered') url.searchParams.set('profile_body', 'buffered');
    if (task.representation === 'json') url.searchParams.set('rewards', 'false');
    if (task.representation === 'bin-no-access') url.searchParams.set('access', '0');
    const headers = settings.key ? { Authorization: `Bearer ${settings.key}` } : {};
    const response = await fetch(url, { method: 'GET', headers, signal: controller.signal, redirect: 'error' });
    sample.headersMs = performance.now() - started;
    sample.status = response.status;
    sample.cache = cacheStatus(response.headers);
    sample.storage = storageReceipt(response.headers);
    sample.auth = authReceipt(response.headers);
    sample.profileMode = safeMode(response.headers, 'X-Blockzilla-Profile-Mode');
    sample.storageClass = storageClassification(sample);
    sample.coldVerified = sample.storageClass === 'origin_uncached_verified';
    sample.fullyColdVerified = sample.coldVerified && sample.auth.cache === 'BYPASS' && sample.auth.kvReads === 1;
    sample.sourceIndexCachedVerified = sourceUncachedVerified(sample);
    sample.sourceAuthCachedVerified = sample.sourceIndexCachedVerified && sample.auth.cache === 'HIT' && sample.auth.kvReads === 0;
    const cfRay = response.headers.get('CF-Ray');
    sample.cfRay = cfRay && /^[a-f0-9]{16,32}-[A-Z]{3}$/.test(cfRay) ? cfRay : null;
    sample.edgeLocation = response.headers.get('CF-Ray')?.split('-').at(-1)?.match(/^[A-Z]{3}$/)?.[0] ?? null;
    sample.contentEncoding = safeMode(response.headers, 'Content-Encoding');
    sample.profileBodyMode = safeMode(response.headers, 'X-Blockzilla-Profile-Body-Mode');
    sample.jsonRenderMode = safeMode(response.headers, 'X-Blockzilla-JSON-Render-Mode');
    sample.bodyMode = safeMode(response.headers, 'X-Blockzilla-Body');
    const profileRaw = response.headers.get('X-BZ-Profile');
    const serverTimingRaw = response.headers.get('Server-Timing');
    const chunks = [], reader = response.body?.getReader();
    if (reader) {
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (!value.byteLength) continue;
          sample.ttfbMs ??= performance.now() - started;
          sample.bytes += value.byteLength;
          check(sample.bytes <= MAX_BODY, 'Response body exceeds bound.');
          chunks.push(value);
        }
      } finally { reader.releaseLock(); }
    }
    sample.totalMs = performance.now() - started;
    sample.transferAfterHeadersMs = sample.totalMs - sample.headersMs;
    check(response.ok, `HTTP_${response.status}`);
    check(sample.bytes > 0, 'Empty response body.');
    check(sourceMode ? sample.sourceIndexCachedVerified : sample.coldVerified,
      sourceMode ? 'Source reads with cached index were not verified.' : 'Origin-uncached receipt not verified.');
    if (settings.profileBody === 'buffered') check(sample.bodyMode === 'profile-buffered', 'Buffered profile body was not confirmed.');
    else check(sample.bodyMode !== 'profile-buffered', 'Stream profile returned a buffered profile body.');
    const validationStarted = performance.now(), body = Buffer.concat(chunks, sample.bytes);
    sample.bodySha256 = sha256(body);
    if (task.representation === 'json') {
      let value, text;
      try { text = new TextDecoder('utf-8', { fatal: true }).decode(body); value = JSON.parse(text); } catch { throw new Error('Invalid JSON body.'); }
      check(value && value.jsonrpc === '2.0' && value.id === 1 && value.result && !value.error, 'Invalid JSON-RPC block result.');
      check(Array.isArray(value.result.transactions) && Number.isSafeInteger(value.result.parentSlot)
        && typeof value.result.blockhash === 'string' && typeof value.result.previousBlockhash === 'string', 'Invalid block identity.');
      sample.contentSha256 = canonicalBlockDigest(text);
      const expected = settings.jsonDigests.get(task.slot);
      sample.contentMatchesReference = expected ? sample.contentSha256 === expected : null;
      check(!expected || sample.contentMatchesReference, 'JSON differs from saved provider reference.');
    } else {
      if (task.representation === 'bin-no-access') validateNoAccessBundle(body, task.slot);
      else check(decodeV1Bundle(body).slot === task.slot, 'Binary slot differs.');
      const expected = task.representation === 'bin' ? settings.bundleDigests.get(task.slot) : null;
      sample.contentMatchesReference = expected ? sample.bodySha256 === expected : null;
      check(!expected || sample.contentMatchesReference, 'Binary differs from saved bundle reference.');
    }
    sample.validationMs = performance.now() - validationStarted;
    sample.workerProfile = parseProfile(profileRaw);
    sample.serverTiming = parseServerTiming(serverTimingRaw);
    for (const name of settings.requiredStages) check(Object.hasOwn(sample.workerProfile.summary, name), 'Required profile stage is missing.');
    sample.ok = true;
  } catch (error) {
    sample.totalMs ??= performance.now() - started;
    sample.error = controller.signal.aborted ? 'request_timeout' : error instanceof Error && /^[A-Za-z0-9 ._-]{1,100}$/.test(error.message) ? error.message : 'request_failed';
    controller.abort();
  } finally { clearTimeout(timer); sample.completedAt = new Date().toISOString(); }
  return sample;
}

function quantiles(values) {
  const sorted = values.filter(finite).sort((a, b) => a - b);
  return Object.fromEntries([['p50', 0.5], ['p95', 0.95], ['p99', 0.99]].map(([name, fraction]) =>
    [name, sorted.length ? Math.round(sorted[Math.max(0, Math.ceil(sorted.length * fraction) - 1)] * 1000) / 1000 : null]));
}

export function summarizeStages(samples) {
  return [...new Set(samples.map(sample => sample.representation))].map(representation => {
    const rows = samples.filter(sample => sample.representation === representation && sample.ok);
    const names = [...new Set(rows.flatMap(sample => Object.keys(sample.workerProfile.summary)))].sort();
    const authKvReads = rows.map(sample => sample.auth?.kvReads).filter(integer);
    const cachedIndexAndAuth = rows.filter(sample => sample.sourceAuthCachedVerified);
    return { representation, requests: rows.length, headersMs: quantiles(rows.map(sample => sample.headersMs)),
      ttfbMs: quantiles(rows.map(sample => sample.ttfbMs)), totalMs: quantiles(rows.map(sample => sample.totalMs)),
      auth: { kvReads: { reportedRequests: authKvReads.length, total: authKvReads.reduce((sum, value) => sum + value, 0),
        mean: authKvReads.length ? authKvReads.reduce((sum, value) => sum + value, 0) / authKvReads.length : null },
      cacheCounts: Object.fromEntries([...new Set(rows.map(sample => sample.auth?.cache ?? 'unreported'))]
        .map(cache => [cache, rows.filter(sample => (sample.auth?.cache ?? 'unreported') === cache).length])) },
      sourceIndexCachedRequests: rows.filter(sample => sample.sourceIndexCachedVerified).length,
      sourceIndexAndAuthCachedRequests: cachedIndexAndAuth.length,
      sourceIndexAndAuthCachedTiming: { ttfbMs: quantiles(cachedIndexAndAuth.map(sample => sample.ttfbMs)),
        totalMs: quantiles(cachedIndexAndAuth.map(sample => sample.totalMs)) },
      stages: Object.fromEntries(names.map(name => {
        const entries = rows.map(sample => sample.workerProfile.summary[name]).filter(Boolean);
        return [name, { reportedRequests: entries.length, totalMs: quantiles(entries.map(entry => entry.totalMs)),
          count: quantiles(entries.map(entry => entry.count)), bytes: quantiles(entries.map(entry => entry.bytes)) }];
      })) };
  });
}

async function references(args) {
  const jsonDigests = new Map(), bundleDigests = new Map();
  if (args.jsonReference) {
    let report;
    try { report = JSON.parse(await readFile(args.jsonReference, 'utf8')); } catch { throw new Error('Cannot read JSON reference report.'); }
    for (const sample of report.samples ?? []) {
      if (sample.label !== 'helius' || !sample.ok) continue;
      check(integer(sample.slot) && /^[a-f0-9]{64}$/.test(sample.contentSha256), 'Invalid JSON reference digest.');
      check(!jsonDigests.has(sample.slot) || jsonDigests.get(sample.slot) === sample.contentSha256, 'Provider reference digests differ.');
      jsonDigests.set(sample.slot, sample.contentSha256);
    }
  }
  if (args.inputManifest) {
    let report;
    try { report = JSON.parse(await readFile(args.inputManifest, 'utf8')); } catch { throw new Error('Cannot read binary reference manifest.'); }
    check(Array.isArray(report.records) && report.records.length > 0, 'Binary reference manifest is empty.');
    for (const row of report.records) {
      const slot = typeof row === 'number' ? row : row.slot;
      const digest = row.bundle_sha256 ?? row.bundleSha256 ?? row.sha256;
      check(integer(slot) && /^[a-f0-9]{64}$/.test(digest), 'Invalid binary reference digest.');
      bundleDigests.set(slot, digest);
    }
  }
  return { jsonDigests, bundleDigests };
}

export async function main(argv = process.argv.slice(2), env = process.env) {
  const args = parseArgs(argv);
  if (args.help) { console.log(usage()); return; }
  if (args.selfTest) { await selfTest(); return; }
  const slots = await loadSlots(args.slots);
  const tasks = args.representations.flatMap(representation => slots.map(slot => ({ slot, representation })));
  check(tasks.length <= args.maxRequests, 'Request plan exceeds --max-requests.');
  const ref = await references(args);
  if (args.jsonReference && args.representations.includes('json')) check(slots.every(slot => ref.jsonDigests.has(slot)), 'JSON reference is missing a requested slot.');
  if (args.inputManifest && args.representations.includes('bin')) check(slots.every(slot => ref.bundleDigests.has(slot)), 'Binary reference is missing a requested slot.');
  let outputExists = false;
  try { await stat(args.output); outputExists = true; } catch (error) { if (error.code !== 'ENOENT') throw new Error('Cannot check output path.'); }
  check(!outputExists, 'Output file already exists.');
  await mkdir(dirname(args.output), { recursive: true });
  const settings = { ...args, ...ref, url: endpoint(args.url, env), key: env.BLOCKZILLA_RPC_API_KEY };
  const startedAt = new Date().toISOString(), started = performance.now(), samples = [];
  for (const task of tasks) {
    const sample = await profileRequest(settings, task);
    samples.push(sample);
    if (!sample.ok) break;
  }
  const report = { schema: 'blockzilla-get-block-stage-profile-v1', startedAt, durationMs: performance.now() - started,
    plan: { slots, representations: args.representations, profileBody: args.profileBody, profileMode: args.profileMode, requests: tasks.length, maxRequests: args.maxRequests, concurrency: 1, profile: true, timeoutMs: args.timeoutMs },
    platformCpu: { available: false, source: 'Cloudflare platform API required; profile header durations are wall time' },
    notes: ['Full profile requests bypass Worker response and archive caches. Source profile requests retain index/auth caches while bypassing responses and source ranges. Physical storage caches remain unknown.',
      'Source-index proof and auth-cache proof are separate. Legitimate short-TTL auth misses remain valid and their KV reads are counted.',
      'Profile-only buffered JSON can delay headers and change streaming behavior. Check each response mode before comparison with production JSON.',
      'Stage durations can overlap through nesting or parallel source reads; do not add all durations as serial time.',
      'Worker clocks can remain fixed during CPU work. A zero-duration stage is not proof of zero CPU; use the platform CPU metric.',
      'Profile event details are omitted except parsed Worker location, placement mode, and source S3 collector location. Complete sanitized summaries are retained when event lists are truncated.',
      'No endpoint, credential, locator token, or source object key is written to this report.',
      'Client timers stop before local body validation. No retry is performed.'], stageSummaries: summarizeStages(samples), samples };
  await writeFile(args.output, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx' });
  const errors = samples.filter(sample => !sample.ok).length;
  console.log(JSON.stringify({ requests: samples.length, planned: tasks.length, errors, complete: samples.length === tasks.length }));
  if (errors || samples.length !== tasks.length) process.exitCode = 1;
  return report;
}

export async function selfTest() {
  const { createServer } = await import('node:http');
  const { once } = await import('node:events');
  const slot = 470987967;
  const profile = { totalMs: 4, events: [
    { name: 'auth_kv', ms: 1, bytes: 0, detail: 'https://private.invalid/?token=NEVER_REPORT', status: 200 },
    { name: 'worker_placement', ms: 0, bytes: 0, detail: 'colo=CDG;placement=remote-FRA', status: null },
    { name: 's3_headers', ms: 2, bytes: 0, detail: 's3_collector=FRA', status: 206 },
    { name: 's3_headers', ms: 2, bytes: 0, detail: 'private/source-key', status: 206 },
  ], eventsTruncated: true, summary: [
    { name: 'auth_kv', count: 1, totalMs: 1, bytes: 0 },
    { name: 's3_headers', count: 2, totalMs: 4, bytes: 0 },
    { name: 'render', count: 1, totalMs: 2, bytes: 100 },
  ] };
  const parsed = parseProfile(JSON.stringify(profile));
  check(parsed.summary.render.totalMs === 2 && parsed.eventsByName.s3_headers.length === 2 && parsed.eventsByName.s3_headers[0].upstreamColo === 'FRA'
    && parsed.eventsByName.worker_placement[0].placement.targetColo === 'FRA'
    && !JSON.stringify(parsed).includes('NEVER_REPORT'), 'Profile parser test failed.');
  check(parseServerTiming('s3_headers;dur=4.00;desc="2x 0B, parallel", render;dur=2.00').length === 2, 'Server-Timing parser test failed.');
  for (const invalid of [null, '{}', JSON.stringify({ ...profile, summary: [{ name: 'render', totalMs: -1, count: 1, bytes: 0 }] })]) {
    let rejected = false;
    try { parseProfile(invalid); } catch { rejected = true; }
    check(rejected, 'Invalid profile was accepted.');
  }
  const noAccess = Buffer.concat([encodeULEB(1), encodeULEB(slot), Buffer.from([1]), encodeULEB(3), Buffer.from([1, 2, 3, 0, 0])]);
  validateNoAccessBundle(noAccess, slot);
  for (const invalid of [noAccess.subarray(0, -1), Buffer.concat([noAccess, Buffer.from([0])])]) {
    let rejected = false;
    try { validateNoAccessBundle(invalid, slot); } catch { rejected = true; }
    check(rejected, 'Invalid binary framing was accepted.');
  }
  const body = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { parentSlot: slot - 1, blockhash: 'a', previousBlockhash: 'b', transactions: [] } }));
  let calls = 0;
  const server = createServer((request, response) => {
    calls += 1;
    const buffered = request.url === `/block/${slot}.json?profile=1&profile_body=buffered&rewards=false`;
    const sourceMode = request.url === `/block/${slot}.json?profile=source&rewards=false`;
    check((buffered || sourceMode || request.url === `/block/${slot}.json?profile=1&rewards=false`)
      && request.headers.authorization === 'Bearer local-fixture-key', 'Local request differs.');
    response.writeHead(200, { 'Content-Type': 'application/json', 'X-Blockzilla-Cache': 'BYPASS', 'X-BZ-Profile': JSON.stringify(profile), 'Server-Timing': 'auth_kv;dur=1.00, render;dur=2.00', 'X-Blockzilla-Profile-Mode': sourceMode ? 'source' : 'full',
      'X-Blockzilla-Body': buffered ? 'profile-buffered' : 'json-stream',
      ...Object.fromEntries(['R2', 'S3'].flatMap(backend => {
        const gets = backend === 'R2' ? sourceMode ? 0 : 1 : 2;
        return [['Reads', gets], ['GETs', gets], ['HEADs', 0], ['Bytes', gets * 100], ['GET-Successes', gets], ['HEAD-Successes', 0]]
          .map(([name, value]) => [`X-Blockzilla-${backend}-${name}`, String(value)]);
      })),
      'X-Blockzilla-Auth-Cache': sourceMode ? 'MISS' : 'BYPASS', 'X-Blockzilla-Auth-KV-Reads': '1',
      'X-Blockzilla-Archive-Memory-Hits': sourceMode ? '1' : '0', 'X-Blockzilla-Archive-Edge-Hits': '0' });
    response.end(body);
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  try {
    const settings = { url: new URL(`http://127.0.0.1:${server.address().port}`), key: 'local-fixture-key', timeoutMs: 1000,
      requiredStages: ['auth_kv', 'render'], jsonDigests: new Map([[slot, canonicalBlockDigest(body.toString())]]), bundleDigests: new Map() };
    const good = await profileRequest(settings, { slot, representation: 'json' });
    check(good.ok && good.fullyColdVerified && good.contentMatchesReference && good.profileMode === 'full', 'Local profile request failed.');
    const buffered = await profileRequest({ ...settings, profileBody: 'buffered' }, { slot, representation: 'json' });
    check(buffered.ok && buffered.bodyMode === 'profile-buffered', 'Buffered local profile request failed.');
    const source = await profileRequest({ ...settings, profileMode: 'source' }, { slot, representation: 'json' });
    check(source.ok && source.sourceIndexCachedVerified && !source.sourceAuthCachedVerified && source.auth.kvReads === 1, 'Source-mode local profile request failed.');
    const bad = await profileRequest({ ...settings, requiredStages: ['missing'] }, { slot, representation: 'json' });
    check(!bad.ok && bad.error === 'Required profile stage is missing.' && calls === 4, 'Missing-stage local test failed.');
  } finally { await new Promise(resolve => server.close(resolve)); }
  console.log(JSON.stringify({ selfTest: 'passed', localRequests: calls, remoteRequests: 0 }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => { console.error(error instanceof Error && /^[A-Za-z0-9 ._-]{1,150}$/.test(error.message) ? error.message : 'Profile runner failed.'); process.exitCode = 1; });
}
