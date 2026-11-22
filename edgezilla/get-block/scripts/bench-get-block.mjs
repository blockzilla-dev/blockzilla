#!/usr/bin/env node

import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';

const OPTIONS = new Set([
  'url', 'slots', 'rounds', 'concurrency', 'rpc-url', 'rpc-endpoint', 'output', 'timeout-ms',
  'uncached-rounds', 'source-uncached-rounds', 'max-requests', 'max-transaction-version',
  'representations', 'rpc-encoding', 'binary-reference',
]);
const JSON_BODY_LIMIT = 64 * 1024 * 1024;
const MAX_SLOTS = 10_000;
const HASH_PATTERN = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const LABEL_PATTERN = /^[a-z][a-z0-9_-]{0,31}$/;
const EXACT_NUMBER = Symbol('exactJsonNumber');

function usage() {
  return `Usage:
  BLOCKZILLA_RPC_API_KEY=... node scripts/bench-get-block.mjs \\
    --url https://RPC_HOST --slots 321000000,321000001 \\
    --rounds 5 --concurrency 4 [--rpc-url @RPC_URL] [--output report.json]

Options:
  --url            Blockzilla base URL, or @ENV_NAME. Required.
  --slots          Comma-separated slots, a file path, or @file. Required.
                   A file can contain a JSON array or slots separated by commas or spaces.
  --rounds         Normal passes over all slots. Default: 5. Range: 0 to 100.
                   Zero is allowed when an uncached pass is requested.
  --concurrency    Maximum requests in flight. Default: 4. Range: 1 to 64.
  --rpc-url        Optional provider URL, or @ENV_NAME. Uses POST getBlock.
  --rpc-endpoint   Repeatable label=@ENV_NAME (or label=URL) for several providers.
                   Bearer key: RPC_<UPPERCASE_LABEL>_API_KEY, then RPC_API_KEY.
  --uncached-rounds  Extra passes with Blockzilla profile=1. Default: 0.
                   These bypass response and archive caches. Metrics must prove origin reads.
  --source-uncached-rounds  Extra passes with profile=source. Default: 0.
                   Response and range caches are bypassed; index and API key caches remain.
                   One separate resolution warmup per slot runs before these passes.
  --max-requests   Hard request budget. Default: 500. Range: 1 to 10000.
  --max-transaction-version  Provider option. Default: 1. Range: 0 to 255.
  --rpc-encoding   Provider transaction encoding: base64 or json. Default: base64.
                   It must match the deployed Worker JSON format.
  --representations  Blockzilla formats: bin,json,bin-no-access. Default: bin,json.
  --binary-reference  Existing input manifest with saved original V1 bundles.
                   Check complete bin and derived access=0 SHA-256 after the body timer.
  --output         Write a JSON report. An existing file is not overwritten.
  --timeout-ms     Timeout per request, including the body. Default: 30000.
  --help           Show this help.

Read bearer keys from environment variables only.
URLs and keys are never written to the report. Use @ENV_NAME for private URLs.
Both JSON requests use full transactions and rewards=false.
The Worker controls its JSON route encoding; select the matching provider encoding.
The first pass and repeat passes are separate. A first pass can already hit a cache.
Only the response cache header proves a Blockzilla response cache hit.
Origin-uncached samples require BYPASS, positive storage reads, and zero archive cache hits.
Source-uncached samples are separate: cached index/auth and exact Foundation range reads.
Warmup costs and timing are reported separately. Source-uncached never means fully cold.
profile=1 adds timing work; it is reported separately from normal requests.
TTFB measures the first body byte. Total time includes the complete body.
JSON parse and identity checks happen after the body timer stops.
No cache purge, retry, or cache-busting query is used.`;
}

export function parseArgs(argv) {
  const options = new Map();
  const rpcEndpoints = [];
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--help' || arg === '-h') return { help: true };
    if (!arg.startsWith('--') || !OPTIONS.has(arg.slice(2))) {
      throw new Error('Unknown argument. Use --help.');
    }
    const name = arg.slice(2);
    const value = argv[index + 1];
    if (name !== 'rpc-endpoint' && options.has(name)) throw new Error(`Duplicate --${name}.`);
    if (!value || value.startsWith('--')) throw new Error(`Missing value for --${name}.`);
    if (name === 'rpc-endpoint') rpcEndpoints.push(providerArgument(value));
    else options.set(name, value);
    index += 1;
  }
  for (const name of ['url', 'slots']) {
    if (!options.has(name)) throw new Error(`Missing --${name}.`);
  }
  if (options.has('rpc-url')) rpcEndpoints.unshift({ label: 'provider', url: options.get('rpc-url') });
  if (new Set(rpcEndpoints.map((endpoint) => endpoint.label)).size !== rpcEndpoints.length) {
    throw new Error('Duplicate provider labels are not allowed.');
  }
  const rpcEncoding = options.get('rpc-encoding') ?? 'base64';
  if (!['base64', 'json'].includes(rpcEncoding)) throw new Error('Use --rpc-encoding base64 or json.');
  const rounds = integerOption(options.get('rounds') ?? '5', 'rounds', 0, 100);
  const uncachedRounds = integerOption(options.get('uncached-rounds') ?? '0', 'uncached-rounds', 0, 10);
  const sourceUncachedRounds = integerOption(options.get('source-uncached-rounds') ?? '0', 'source-uncached-rounds', 0, 10);
  if (rounds + uncachedRounds + sourceUncachedRounds === 0) throw new Error('Request at least one normal or uncached pass.');
  return {
    url: options.get('url'),
    slots: options.get('slots'),
    rpcUrl: options.get('rpc-url'),
    rpcEndpoints,
    output: options.get('output'),
    rounds,
    concurrency: integerOption(options.get('concurrency') ?? '4', 'concurrency', 1, 64),
    timeoutMs: integerOption(options.get('timeout-ms') ?? '30000', 'timeout-ms', 1, 600_000),
    uncachedRounds,
    sourceUncachedRounds,
    maxRequests: integerOption(options.get('max-requests') ?? '500', 'max-requests', 1, 10_000),
    maxTransactionVersion: integerOption(options.get('max-transaction-version') ?? '1', 'max-transaction-version', 0, 255),
    rpcEncoding,
    binaryReference: options.get('binary-reference'),
    representations: parseRepresentations(options.get('representations') ?? 'bin,json'),
  };
}

function parseRepresentations(value) {
  const representations = value.split(',');
  if (!representations.length || new Set(representations).size !== representations.length
      || representations.some((format) => !['bin', 'json', 'bin-no-access'].includes(format))) {
    throw new Error('Use --representations bin,json,bin-no-access with no repeated formats.');
  }
  return representations;
}

function providerArgument(value) {
  const at = value.indexOf('=');
  const label = value.slice(0, at);
  if (at < 1 || !LABEL_PATTERN.test(label) || label === 'blockzilla' || !value.slice(at + 1)) {
    throw new Error('Use --rpc-endpoint label=@ENV_NAME with a safe lowercase label.');
  }
  return { label, url: value.slice(at + 1) };
}

function integerOption(value, name, min, max) {
  if (!/^[0-9]+$/.test(value)) throw new Error(`--${name} must be an integer.`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`--${name} must be from ${min} to ${max}.`);
  }
  return parsed;
}

function endpointUrl(value, label, env) {
  const resolved = value.startsWith('@') ? env[value.slice(1)] : value;
  if (!resolved) throw new Error(`Missing ${label} URL or environment value.`);
  try {
    const url = new URL(resolved);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash) {
      throw new Error();
    }
    return url;
  } catch {
    // Do not include an endpoint in errors. A path or query can contain a key.
    throw new Error(`Invalid ${label} URL. Use HTTP or HTTPS without user info or a fragment.`);
  }
}

export async function loadSlots(value) {
  let text = value;
  if (!/^[0-9,\s]+$/.test(value)) {
    try {
      text = await readFile(value.startsWith('@') ? value.slice(1) : value, 'utf8');
    } catch {
      throw new Error('Cannot read the slot file.');
    }
  }
  let values;
  if (text.trim().startsWith('[')) {
    try {
      values = JSON.parse(text);
    } catch {
      throw new Error('The slot file has invalid JSON.');
    }
    if (!Array.isArray(values)) throw new Error('The slot file must contain an array.');
    values = values.map(String);
  } else {
    values = text.trim().split(/[,\s]+/);
  }
  if (!values.length || values.length > MAX_SLOTS) {
    throw new Error(`Supply from 1 to ${MAX_SLOTS} slots.`);
  }
  const slots = values.map((slot) => integerOption(slot, 'slots', 0, Number.MAX_SAFE_INTEGER));
  if (new Set(slots).size !== slots.length) throw new Error('Duplicate slots are not allowed.');
  return slots;
}

export async function loadBinaryReferences(path) {
  if (!path) return new Map();
  let manifest;
  try { manifest = JSON.parse(await readFile(path, 'utf8')); }
  catch { throw new Error('Cannot read the binary reference manifest.'); }
  if (!Array.isArray(manifest.records) || !manifest.records.length || manifest.records.length > MAX_SLOTS) {
    throw new Error('Invalid binary reference manifest.');
  }
  const { decodeV1Bundle, encodeULEB } = await import('./bench-resolution-client.mjs');
  const result = new Map();
  for (const row of manifest.records) {
    if (!Number.isSafeInteger(row.slot) || row.slot < 0 || result.has(row.slot)
        || typeof row.bundlePath !== 'string' || !/^[a-f0-9]{64}$/.test(row.bundleSha256)) {
      throw new Error('Invalid binary reference record.');
    }
    let bytes;
    try { bytes = await readFile(row.bundlePath); }
    catch { throw new Error('Cannot read a saved binary reference bundle.'); }
    const fullDigest = createHash('sha256').update(bytes).digest('hex');
    if (fullDigest !== row.bundleSha256) throw new Error('A saved binary reference bundle has changed.');
    const bundle = decodeV1Bundle(bytes);
    if (bundle.slot !== row.slot) throw new Error('A saved binary reference slot differs.');
    const noAccess = Buffer.concat([encodeULEB(1), encodeULEB(row.slot), Buffer.from([1]),
      encodeULEB(bundle.hot.length), bundle.hot, Buffer.from([0, 0])]);
    result.set(row.slot, { bin: fullDigest, 'bin-no-access': createHash('sha256').update(noAccess).digest('hex') });
  }
  return result;
}

function blockUrl(base, slot, representation, profileMode = 'none') {
  const url = new URL(base);
  url.pathname = `${url.pathname.replace(/\/$/, '')}/block/${slot}.${representation === 'bin-no-access' ? 'bin' : representation}`;
  if (representation === 'json') url.searchParams.set('rewards', 'false');
  if (representation === 'bin-no-access') url.searchParams.set('access', '0');
  if (profileMode !== 'none') url.searchParams.set('profile', profileMode === 'source' ? 'source' : '1');
  return url;
}

function cacheStatus(response, source) {
  if (source !== 'blockzilla') return 'UNREPORTED';
  const value = response.headers.get('X-Blockzilla-Cache')?.toUpperCase();
  return ['HIT', 'MISS', 'BYPASS', 'UNCACHED'].includes(value) ? value : 'UNREPORTED';
}

function counterHeader(headers, name) {
  const value = headers.get(name);
  if (value === null || !/^[0-9]+$/.test(value)) return null;
  const count = Number(value);
  return Number.isSafeInteger(count) ? count : null;
}

export function storageReceipt(headers) {
  const backend = (name) => Object.fromEntries([
    ['reads', 'Reads'], ['gets', 'GETs'], ['heads', 'HEADs'], ['bytes', 'Bytes'],
    ['getSuccesses', 'GET-Successes'], ['headSuccesses', 'HEAD-Successes'],
  ].map(([field, suffix]) => [field, counterHeader(headers, `X-Blockzilla-${name}-${suffix}`)]));
  const r2 = backend('R2');
  const s3 = backend('S3');
  const reader = headers.get('X-Blockzilla-Reader') === 'native-r2' ? 'native-r2' : null;
  const archiveBackendHeader = headers.get('X-Blockzilla-Archive-Backend');
  const archiveBackend = ['r2', 's3', 'reader'].includes(archiveBackendHeader) ? archiveBackendHeader : null;
  const readerHttpRequests = counterHeader(headers, 'X-Blockzilla-Reader-HTTP-Requests');
  const foundationGets = counterHeader(headers, 'X-Blockzilla-Foundation-R2-GETs');
  const foundationHeads = counterHeader(headers, 'X-Blockzilla-Foundation-R2-HEADs');
  const foundationR2 = { gets: foundationGets, heads: foundationHeads,
    reads: foundationGets !== null && foundationHeads !== null ? foundationGets + foundationHeads : null,
    bytes: counterHeader(headers, 'X-Blockzilla-Foundation-R2-Bytes'),
    getSuccesses: counterHeader(headers, 'X-Blockzilla-Foundation-R2-GET-Successes'),
    headSuccesses: foundationHeads === 0 ? 0 : null };
  const hasFoundationCounters = reader !== null || readerHttpRequests !== null || foundationGets !== null || foundationHeads !== null;
  const memoryHits = counterHeader(headers, 'X-Blockzilla-Archive-Memory-Hits');
  const edgeHits = counterHeader(headers, 'X-Blockzilla-Archive-Edge-Hits');
  const sum = (field) => {
    const values = [r2[field], s3[field], ...(hasFoundationCounters ? [foundationR2[field]] : [])];
    return values.every(value => value !== null) ? values.reduce((total, value) => total + value, 0) : null;
  };
  const unconfirmedReaderRequests = readerHttpRequests === null ? null
    : foundationGets === null ? readerHttpRequests : Math.max(0, readerHttpRequests - foundationGets);
  return {
    r2, s3, foundationR2, archiveBackend, reader, readerHttpRequests, unconfirmedReaderRequests,
    readerAccountingComplete: !hasFoundationCounters || unconfirmedReaderRequests === 0,
    originReads: sum('reads'), originGets: sum('gets'), originHeads: sum('heads'), originBytes: sum('bytes'),
    originGetSuccesses: sum('getSuccesses'), originHeadSuccesses: sum('headSuccesses'),
    archiveMemoryHits: memoryHits, archiveEdgeHits: edgeHits,
    originExpectedBytes: counterHeader(headers, 'X-Blockzilla-Origin-Expected-Bytes'),
    bytesMode: headers.get('X-Blockzilla-Storage-Bytes-Mode') ?? 'buffered',
  };
}

export function authReceipt(headers) {
  const cache = headers.get('X-Blockzilla-Auth-Cache')?.toUpperCase();
  const tier = headers.get('X-Blockzilla-Auth-Cache-Tier')?.toUpperCase();
  return { cache: ['HIT', 'MISS', 'BYPASS'].includes(cache) ? cache : null,
    kvReads: counterHeader(headers, 'X-Blockzilla-Auth-KV-Reads'),
    ...(tier ? { tier: ['L1', 'L2', 'MEMORY', 'EDGE', 'KV', 'BYPASS', 'NONE'].includes(tier) ? tier : null } : {}) };
}

export function sourceUncachedVerified(sample) {
  const storage = sample.storage;
  const expectedGets = sample.representation === 'bin-no-access' ? 1 : 2;
  const common = sample.source === 'blockzilla' && sample.sourceUncached === true && sample.cache === 'BYPASS'
    && sample.profileMode === 'source';
  if (!common) return false;
  if (storage?.archiveBackend === 'r2') {
    return storage.r2?.reads === expectedGets && storage.r2?.gets === expectedGets && storage.r2?.heads === 0
      && storage.s3?.reads === 0 && storage.s3?.gets === 0 && storage.s3?.heads === 0
      && (storage.foundationR2?.reads ?? 0) === 0 && (storage.readerHttpRequests ?? 0) === 0
      && storage.readerAccountingComplete !== false
      && (storage.archiveMemoryHits ?? 0) + (storage.archiveEdgeHits ?? 0) > 0;
  }
  if (storage?.r2?.reads !== 0 || storage?.r2?.gets !== 0 || storage?.r2?.heads !== 0) return false;
  const nativeReader = storage.reader === 'native-r2' || (storage.readerHttpRequests ?? 0) > 0 || (storage.foundationR2?.gets ?? 0) > 0;
  return nativeReader
    ? storage.reader === 'native-r2' && storage.s3?.reads === 0 && storage.s3?.gets === 0 && storage.s3?.heads === 0
      && storage.foundationR2?.reads === expectedGets && storage.foundationR2?.gets === expectedGets
      && storage.foundationR2?.heads === 0 && storage.readerHttpRequests === expectedGets && storage.readerAccountingComplete
    : storage.s3?.reads === expectedGets && storage.s3?.gets === expectedGets && storage.s3?.heads === 0;
}

export function storageClassification(sample) {
  const receipt = sample.storage;
  if (sample.source !== 'blockzilla') return 'provider_cache_unknown';
  if (!receipt || receipt.originReads === null) return 'storage_receipt_missing';
  if (sample.sourceUncached) return sourceUncachedVerified(sample) ? 'source_uncached_index_cached_verified' : 'source_uncached_index_cached_unverified';
  if (sample.cache === 'HIT') {
    return receipt.originReads === 0 && (receipt.readerHttpRequests ?? 0) === 0
      ? 'response_cache_hit' : 'invalid_response_cache_receipt';
  }
  const noArchiveHits = receipt.archiveMemoryHits === 0 && receipt.archiveEdgeHits === 0;
  if (sample.uncached && sample.cache === 'BYPASS' && receipt.originReads > 0 && noArchiveHits
      && receipt.readerAccountingComplete !== false) {
    return 'origin_uncached_verified';
  }
  if (sample.uncached) return 'origin_uncached_unverified';
  if (receipt.originReads > 0) return 'storage_backed_miss';
  if ((receipt.archiveMemoryHits ?? 0) + (receipt.archiveEdgeHits ?? 0) > 0) return 'archive_cache_only';
  return 'no_origin_read';
}

function profileSummary(headers) {
  const raw = headers.get('X-BZ-Profile');
  if (!raw || raw.length > 128 * 1024) return undefined;
  try {
    const value = JSON.parse(raw);
    if (!Array.isArray(value.summary) || value.summary.length > 100) return undefined;
    const summary = value.summary.filter((row) => /^[A-Za-z0-9_-]{1,80}$/.test(row.name)
      && Number.isFinite(row.totalMs) && Number.isSafeInteger(row.count) && Number.isSafeInteger(row.bytes))
      .map(({ name, totalMs, count, bytes }) => ({ name, totalMs, count, bytes }));
    return { totalMs: Number.isFinite(value.totalMs) ? value.totalMs : null, summary };
  } catch { return undefined; }
}

function normalizedDecimal(source) {
  const match = /^(-?)([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/.exec(source);
  if (!match) throw new Error('Invalid JSON number.');
  let digits = `${match[2]}${match[3] ?? ''}`.replace(/^0+/, '');
  if (!digits) return '0';
  let exponent = BigInt(match[4] ?? '0') - BigInt(match[3]?.length ?? 0);
  const zeroes = digits.length - digits.replace(/0+$/, '').length;
  if (zeroes) { digits = digits.slice(0, -zeroes); exponent += BigInt(zeroes); }
  return `${match[1]}${digits}e${exponent}`;
}

function canonicalValue(value) {
  if (value === null) return ['null'];
  if (typeof value === 'object' && Object.hasOwn(value, EXACT_NUMBER)) return ['number', value[EXACT_NUMBER]];
  if (Array.isArray(value)) return ['array', value.map(canonicalValue)];
  if (typeof value === 'object') {
    return ['object', Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])])];
  }
  return [typeof value, value];
}

export function canonicalBlockDigest(text) {
  let exactNumbers = true;
  const value = JSON.parse(text, (_key, value, context) => {
    if (typeof value !== 'number') return value;
    if (typeof context?.source !== 'string') { exactNumbers = false; return value; }
    return { [EXACT_NUMBER]: normalizedDecimal(context.source) };
  });
  if (!exactNumbers) throw new Error('This Node.js version does not preserve JSON number source text.');
  const block = Object.hasOwn(value, 'jsonrpc') ? value.result : value;
  return createHash('sha256').update(JSON.stringify(canonicalValue(block))).digest('hex');
}

function blockIdentity(value, slot, source) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return { error: 'invalid_json_block' };
  }
  const isEnvelope = Object.hasOwn(value, 'jsonrpc');
  if (source === 'provider' && !isEnvelope) return { error: 'invalid_rpc_envelope' };
  if (isEnvelope && (value.jsonrpc !== '2.0' || value.id !== 1)) {
    return { error: 'invalid_rpc_envelope' };
  }
  if (Object.hasOwn(value, 'error')) {
    return {
      error: isEnvelope ? 'rpc_error' : 'api_error',
      rpcCode: Number.isSafeInteger(value.error?.code) ? value.error.code : null,
    };
  }
  const block = isEnvelope ? value.result : value;
  if (block === null) return { error: 'block_unavailable' };
  if (!block || typeof block !== 'object' || Array.isArray(block)) {
    return { error: 'invalid_json_block' };
  }
  if (Object.hasOwn(block, 'slot') && block.slot !== slot) return { error: 'slot_mismatch' };
  if (!HASH_PATTERN.test(block.blockhash) || !HASH_PATTERN.test(block.previousBlockhash)
      || !Number.isSafeInteger(block.parentSlot) || block.parentSlot < 0
      || (slot !== 0 && block.parentSlot >= slot) || !Array.isArray(block.transactions)) {
    return { error: 'invalid_json_block' };
  }
  return {
    identity: {
      slot,
      blockhash: block.blockhash,
      previousBlockhash: block.previousBlockhash,
      parentSlot: block.parentSlot,
      transactions: block.transactions.length,
    },
  };
}

export function validateJsonSample(sample, chunks) {
  const decodeStarted = performance.now();
  let value;
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, sample.bytes));
    value = JSON.parse(text);
  } catch {
    sample.error = 'invalid_json';
    return false;
  } finally {
    sample.decodeMs = performance.now() - decodeStarted;
  }
  Object.assign(sample, blockIdentity(value, sample.slot, sample.source));
  if (sample.error) return false;
  const validationStarted = performance.now();
  sample.contentSha256 = canonicalBlockDigest(text);
  sample.contentValidationMs = performance.now() - validationStarted;
  return true;
}

export async function sampleRequest(task, settings) {
  const started = performance.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), settings.timeoutMs);
  const sample = {
    startedAt: new Date().toISOString(),
    source: task.source,
    label: task.label ?? task.source,
    representation: task.representation,
    slot: task.slot,
    round: task.round,
    phase: task.phase ?? (task.uncached ? 'origin_uncached' : task.round === 0 ? 'first' : 'repeat'),
    uncached: Boolean(task.uncached),
    sourceUncached: Boolean(task.sourceUncached),
    status: null,
    cache: 'UNREPORTED',
    bytes: 0,
    headersMs: null,
    ttfbMs: null,
    totalMs: null,
    decodeMs: null,
    ok: false,
  };
  try {
    const isProvider = task.source === 'provider';
    const provider = isProvider ? settings.providers[task.providerIndex] : undefined;
    const headers = {};
    const key = isProvider ? provider.key : settings.blockzillaKey;
    if (key) headers.Authorization = `Bearer ${key}`;
    let body;
    if (isProvider) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify({
        jsonrpc: '2.0', id: 1, method: 'getBlock',
        params: [task.slot, {
          commitment: 'finalized', encoding: settings.rpcEncoding, transactionDetails: 'full',
          maxSupportedTransactionVersion: settings.maxTransactionVersion, rewards: false,
        }],
      });
    }
    const response = await (settings.fetchImplementation ?? fetch)(
      isProvider ? provider.url : blockUrl(settings.blockzillaUrl, task.slot, task.representation,
        task.sourceUncached ? 'source' : task.uncached ? 'full' : 'none'),
      {
        method: isProvider ? 'POST' : 'GET', headers, body,
        signal: controller.signal, redirect: 'error',
      },
    );
    sample.headersMs = performance.now() - started;
    sample.status = response.status;
    sample.cache = cacheStatus(response, task.source);
    const cacheFill = response.headers.get('X-Blockzilla-Cache-Fill');
    sample.cacheFill = ['BYPASS', 'LEADER', 'COALESCED', 'FALLBACK', 'HIT'].includes(cacheFill) ? cacheFill : null;
    sample.contentEncoding = response.headers.get('Content-Encoding');
    sample.contentLength = counterHeader(response.headers, 'Content-Length');
    sample.transferEncoding = response.headers.get('Transfer-Encoding');
    sample.storage = isProvider ? undefined : storageReceipt(response.headers);
    sample.auth = isProvider ? undefined : authReceipt(response.headers);
    const profileMode = response.headers.get('X-Blockzilla-Profile-Mode');
    sample.profileMode = isProvider ? undefined : ['source', 'full'].includes(profileMode) ? profileMode : null;
    sample.storageClass = storageClassification(sample);
    sample.coldVerified = sample.storageClass === 'origin_uncached_verified';
    sample.fullyColdVerified = sample.coldVerified && sample.auth?.cache === 'BYPASS' && sample.auth?.kvReads === 1;
    sample.sourceIndexCachedVerified = sourceUncachedVerified(sample);
    sample.sourceAuthCachedVerified = sample.sourceIndexCachedVerified && sample.auth?.cache === 'HIT' && sample.auth?.kvReads === 0;
    sample.edgeLocation = response.headers.get('CF-Ray')?.split('-').at(-1)?.match(/^[A-Z]{3}$/)?.[0] ?? null;
    sample.workerProfile = isProvider ? undefined : profileSummary(response.headers);
    const chunks = [];
    const reader = response.body?.getReader();
    if (reader) {
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (!value.byteLength) continue;
          sample.ttfbMs ??= performance.now() - started;
          sample.bytes += value.byteLength;
          if (response.ok) {
            const bodyLimit = task.representation === 'resolution' ? 4 * 1024 * 1024
              : task.representation === 'json' ? JSON_BODY_LIMIT : 32 * 1024 * 1024;
            if (sample.bytes > bodyLimit) {
              sample.error = task.representation === 'resolution' ? 'resolution_body_limit'
                : task.representation === 'json' ? 'json_body_limit' : 'binary_body_limit';
              controller.abort();
              break;
            }
            chunks.push(value);
          }
        }
      } finally {
        reader.releaseLock();
      }
    }
    sample.totalMs = performance.now() - started;
    if (sample.error) return sample;
    if (!response.ok) {
      sample.error = `http_${response.status}`;
      return sample;
    }
    if (sample.bytes === 0) {
      sample.error = 'empty_body';
      return sample;
    }
    if (task.representation === 'json') {
      if (Array.isArray(settings.deferredJsonValidation)) {
        settings.deferredJsonValidation.push({ sample, chunks });
        sample.validationDeferred = true;
      } else if (!validateJsonSample(sample, chunks)) return sample;
    } else if (task.representation === 'resolution') {
      const validationStarted = performance.now();
      try {
        const { decodeResolution } = await import('./bench-resolution-client.mjs');
        const bytes = Buffer.concat(chunks, sample.bytes);
        const resolution = decodeResolution(bytes, task.slot);
        sample.resolutionSha256 = resolution.sha256;
      } catch {
        sample.error = 'invalid_resolution';
        return sample;
      }
      sample.contentValidationMs = performance.now() - validationStarted;
    } else {
      if (!response.headers.get('Content-Type')?.includes('wincode')) {
        sample.error = 'invalid_binary_content_type';
        return sample;
      }
      const validationStarted = performance.now();
      sample.bodySha256 = createHash('sha256').update(Buffer.concat(chunks, sample.bytes)).digest('hex');
      const expected = settings.binaryReferences?.get(task.slot)?.[task.representation];
      if (expected) {
        sample.binaryMatchesReference = sample.bodySha256 === expected;
        if (!sample.binaryMatchesReference) { sample.error = 'binary_content_mismatch'; return sample; }
      }
      sample.contentValidationMs = performance.now() - validationStarted;
    }
    if (sample.storageClass === 'invalid_response_cache_receipt') {
      sample.error = 'cache_hit_has_origin_reads';
      return sample;
    }
    sample.ok = true;
    return sample;
  } catch {
    // Fetch errors can include a private URL. Record only a fixed category.
    sample.totalMs = performance.now() - started;
    sample.error = controller.signal.aborted ? 'timeout' : 'transport_error';
    return sample;
  } finally {
    sample.completedAt = new Date().toISOString();
    clearTimeout(timeout);
  }
}

async function boundedMap(tasks, concurrency, operation) {
  const results = new Array(tasks.length);
  let cursor = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, tasks.length) }, async () => {
    while (cursor < tasks.length) {
      const index = cursor++;
      results[index] = await operation(tasks[index]);
    }
  }));
  return results;
}

function percentiles(values) {
  const sorted = values.filter((value) => Number.isFinite(value)).sort((a, b) => a - b);
  if (!sorted.length) return { p50: null, p95: null, p99: null };
  const percentile = (p) => Number(sorted[Math.max(0, Math.ceil(sorted.length * p) - 1)].toFixed(3));
  return { p50: percentile(0.5), p95: percentile(0.95), p99: percentile(0.99) };
}

function counts(values) {
  const result = {};
  for (const value of values) result[value] = (result[value] ?? 0) + 1;
  return result;
}

function operationStats(rows, field) {
  const values = rows.map((row) => row.storage?.[field]).filter((value) => Number.isFinite(value));
  const total = values.reduce((sum, value) => sum + value, 0);
  return {
    reportedRequests: values.length,
    total,
    mean: values.length ? Number((total / values.length).toFixed(3)) : null,
    ...percentiles(values),
  };
}

export function summarize(samples) {
  const groups = new Map();
  for (const sample of samples) {
    // ALL allows comparison by pass. A second group isolates measured cache outcomes.
    for (const cache of ['ALL', sample.cache]) {
      const key = [sample.source, sample.label ?? sample.source, sample.representation, sample.phase, cache].join('/');
      const group = groups.get(key) ?? [];
      group.push(sample);
      groups.set(key, group);
    }
  }
  return [...groups.entries()].map(([key, rows]) => {
    const [source, label, representation, phase, cache] = key.split('/');
    const successful = rows.filter((row) => row.ok);
    const sourceConditionTiming = (condition) => {
      const matched = successful.filter(condition);
      return { requests: matched.length, ttfbMs: percentiles(matched.map(row => row.ttfbMs)),
        totalMs: percentiles(matched.map(row => row.totalMs)) };
    };
    return {
      source, label, representation, phase, cache,
      requests: rows.length,
      successful: successful.length,
      successRate: rows.length ? Number((successful.length / rows.length).toFixed(6)) : null,
      errors: counts(rows.filter((row) => !row.ok).map((row) => row.error)),
      cacheCounts: counts(rows.map((row) => row.cache)),
      storageClassCounts: counts(rows.map((row) => row.storageClass ?? 'unreported')),
      storageBytesModes: counts(rows.map((row) => row.storage?.bytesMode ?? 'unreported')),
      readerKinds: counts(rows.map(row => row.storage?.reader ?? 'none')),
      archiveBackends: counts(rows.map(row => row.storage?.archiveBackend ?? 'unreported')),
      verifiedOriginUncached: successful.filter((row) => row.coldVerified).length,
      verifiedFullyColdWithAuthBypass: successful.filter((row) => row.fullyColdVerified).length,
      verifiedSourceIndexCached: successful.filter((row) => row.sourceIndexCachedVerified).length,
      verifiedSourceIndexAndAuthCached: successful.filter((row) => row.sourceAuthCachedVerified).length,
      auth: { cacheCounts: counts(rows.map((row) => row.auth?.cache ?? 'unreported')),
        kvReads: operationStats(rows.map((row) => ({ storage: row.auth })), 'kvReads') },
      sourceConditionTiming: source === 'blockzilla' && phase === 'source_uncached' ? {
        cachedIndex: sourceConditionTiming(row => row.sourceIndexCachedVerified),
        cachedIndexAndAuth: sourceConditionTiming(row => row.sourceAuthCachedVerified),
        cachedIndexWithAuthKvRead: sourceConditionTiming(row => row.sourceIndexCachedVerified && row.auth?.kvReads === 1),
      } : undefined,
      edgeLocations: counts(rows.map((row) => row.edgeLocation ?? 'UNREPORTED')),
      // Failed responses never improve the successful latency distribution.
      ttfbMs: percentiles(successful.map((row) => row.ttfbMs)),
      totalMs: percentiles(successful.map((row) => row.totalMs)),
      bytes: percentiles(successful.map((row) => row.bytes)),
      storage: Object.fromEntries(['originReads', 'originGets', 'originHeads', 'originBytes', 'originGetSuccesses', 'originHeadSuccesses', 'archiveMemoryHits', 'archiveEdgeHits', 'originExpectedBytes', 'readerHttpRequests', 'unconfirmedReaderRequests']
        .map((field) => [field, operationStats(rows, field)])),
      backendOperations: Object.fromEntries([['ownerR2', 'r2'], ['directS3', 's3'], ['foundationR2', 'foundationR2']]
        .map(([name, field]) => [name, Object.fromEntries(['reads', 'gets', 'heads', 'bytes', 'getSuccesses']
          .map(metric => [metric, operationStats(rows.map(row => ({ storage: row.storage?.[field] })), metric)]))])),
    };
  });
}

export function compareIdentities(samples, expectProvider) {
  const bySlot = new Map();
  for (const sample of samples) {
    if (sample.representation !== 'json' || !sample.ok) continue;
    const rows = bySlot.get(sample.slot) ?? [];
    rows.push(sample);
    bySlot.set(sample.slot, rows);
  }
  const checks = [];
  for (const [slot, rows] of bySlot) {
    const blockzilla = rows.filter((row) => row.source === 'blockzilla');
    const provider = rows.filter((row) => row.source === 'provider');
    const reference = blockzilla[0] ?? provider[0];
    const mismatched = rows.filter((row) => JSON.stringify(row.identity) !== JSON.stringify(reference.identity));
    for (const row of mismatched) {
      row.ok = false;
      row.error = 'block_identity_mismatch';
    }
    checks.push({
      slot,
      status: mismatched.length ? 'mismatch'
        : expectProvider && (!blockzilla.length || !provider.length) ? 'incomplete'
          : expectProvider ? 'matched' : 'consistent',
      blockzillaSamples: blockzilla.length,
      providerSamples: provider.length,
      providerLabels: [...new Set(provider.map((row) => row.label ?? 'provider'))],
      mismatchedSamples: mismatched.length,
    });
  }
  return checks;
}

export function compareContents(samples, expectedProviders = [], expectedWorkers = ['blockzilla']) {
  const bySlot = new Map();
  for (const sample of samples) {
    if (sample.representation !== 'json' || !sample.ok || !sample.contentSha256) continue;
    const rows = bySlot.get(sample.slot) ?? [];
    rows.push(sample);
    bySlot.set(sample.slot, rows);
  }
  return [...bySlot.entries()].map(([slot, rows]) => {
    const reference = rows.find((row) => row.source === 'provider') ?? rows[0];
    const labels = [...new Set(rows.map((row) => row.label ?? row.source))];
    const missing = [...expectedWorkers, ...expectedProviders].filter((label) => !labels.includes(label));
    const mismatched = rows.filter((row) => row.contentSha256 !== reference.contentSha256);
    for (const row of rows) row.contentMatchesReference = row.contentSha256 === reference.contentSha256;
    return {
      slot,
      status: missing.length ? 'incomplete' : mismatched.length ? 'content_mismatch' : 'matched',
      referenceLabel: reference.label ?? reference.source,
      missingLabels: missing,
      mismatchedSamples: mismatched.length,
      samples: rows.map((row) => ({ label: row.label ?? row.source, phase: row.phase, sha256: row.contentSha256 })),
    };
  });
}

export async function main(argv, env = process.env) {
  const args = parseArgs(argv);
  if (args.help) {
    console.log(usage());
    return;
  }
  const slots = await loadSlots(args.slots);
  let exactNumberSource = false;
  JSON.parse('1', (_key, value, context) => { exactNumberSource = context?.source === '1'; return value; });
  if (!exactNumberSource) throw new Error('Use a Node.js version that supplies JSON number source text.');
  const settings = {
    timeoutMs: args.timeoutMs,
    blockzillaUrl: endpointUrl(args.url, 'Blockzilla', env),
    providers: args.rpcEndpoints.map((provider) => ({
      label: provider.label,
      url: endpointUrl(provider.url, provider.label, env),
      key: env[`RPC_${provider.label.toUpperCase()}_API_KEY`] ?? env.RPC_API_KEY,
    })),
    blockzillaKey: env.BLOCKZILLA_RPC_API_KEY,
    maxTransactionVersion: args.maxTransactionVersion,
    rpcEncoding: args.rpcEncoding,
    binaryReferences: await loadBinaryReferences(args.binaryReference),
  };
  if (args.binaryReference && args.representations.some(value => value !== 'json')
      && slots.some(slot => !settings.binaryReferences.has(slot))) {
    throw new Error('The binary reference is missing a requested slot.');
  }
  if (settings.providers.length && !args.representations.includes('json')) {
    throw new Error('Include json in --representations for a provider comparison.');
  }
  if (!settings.blockzillaKey) throw new Error('Set BLOCKZILLA_RPC_API_KEY before the benchmark.');
  if ([settings.blockzillaKey, ...settings.providers.map((provider) => provider.key)]
    .some((key) => key && /[\r\n]/.test(key))) {
    throw new Error('A bearer key has an invalid line break.');
  }
  const startedAt = new Date().toISOString();
  const started = performance.now();
  const samples = [];
  const targets = [
    ...args.representations.map((representation) => ({ source: 'blockzilla', label: 'blockzilla', representation })),
    ...settings.providers.map((provider, providerIndex) => ({ source: 'provider', label: provider.label,
      providerIndex, representation: 'json' })),
  ];
  const sourceWarmupRequests = args.sourceUncachedRounds > 0 ? slots.length : 0;
  const requestCount = slots.length * targets.length * (args.rounds + args.uncachedRounds + args.sourceUncachedRounds) + sourceWarmupRequests;
  if (requestCount > args.maxRequests) {
    throw new Error(`The plan needs ${requestCount} requests, above --max-requests ${args.maxRequests}.`);
  }
  const runPass = async (round, profileMode) => {
    const tasks = slots.flatMap((slot, slotIndex) => {
      // Rotate ordering to reduce a fixed advantage from request order.
      const shift = (round + slotIndex) % targets.length;
      return [...targets.slice(shift), ...targets.slice(0, shift)]
        .map((target) => ({ ...target, slot, round, uncached: profileMode === 'full',
          sourceUncached: profileMode === 'source',
          phase: profileMode === 'source' ? 'source_uncached' : profileMode === 'full' ? 'origin_uncached' : round === 0 ? 'first' : 'repeat' }));
    });
    samples.push(...await boundedMap(tasks, args.concurrency, (task) => sampleRequest(task, settings)));
  };
  for (let round = 0; round < args.uncachedRounds; round += 1) await runPass(round, 'full');
  if (sourceWarmupRequests) {
    samples.push(...await boundedMap(slots.map(slot => ({ source: 'blockzilla', label: 'blockzilla', representation: 'resolution',
      slot, round: 0, phase: 'index_auth_warmup', uncached: false, sourceUncached: false })), args.concurrency,
    task => sampleRequest(task, settings)));
  }
  for (let round = 0; round < args.sourceUncachedRounds; round += 1) await runPass(round, 'source');
  for (let round = 0; round < args.rounds; round += 1) await runPass(round, 'none');
  const identityChecks = compareIdentities(samples, settings.providers.length > 0);
  const contentChecks = compareContents(samples, settings.providers.map((provider) => provider.label));
  const binaryChecks = args.binaryReference ? slots.flatMap(slot => args.representations.filter(value => value !== 'json').map(representation => {
    const rows = samples.filter(sample => sample.source === 'blockzilla' && sample.slot === slot && sample.representation === representation);
    const matched = rows.filter(sample => sample.ok && sample.binaryMatchesReference).length;
    return { slot, representation, samples: rows.length, matched, status: rows.length && matched === rows.length ? 'matched' : 'mismatch' };
  })) : [];
  for (const slot of args.representations.includes('json') ? slots : []) {
    if (!identityChecks.some((check) => check.slot === slot)) {
      identityChecks.push({ slot, status: 'incomplete', blockzillaSamples: 0, providerSamples: 0, mismatchedSamples: 0 });
    }
  }
  const report = {
    schema: 'blockzilla-get-block-http-benchmark-v2',
    startedAt,
    durationMs: Number((performance.now() - started).toFixed(3)),
    plan: {
      slots, rounds: args.rounds, concurrency: args.concurrency, timeoutMs: args.timeoutMs,
      uncachedRounds: args.uncachedRounds, maxRequests: args.maxRequests, requests: requestCount,
      sourceUncachedRounds: args.sourceUncachedRounds, sourceWarmupRequests,
      binaryReferenceIncluded: Boolean(args.binaryReference),
      representations: args.representations,
      providerIncluded: settings.providers.length > 0,
      providerLabels: settings.providers.map((provider) => provider.label),
      jsonOptions: { commitment: 'finalized', encoding: args.rpcEncoding, transactionDetails: 'full', rewards: false,
        maxSupportedTransactionVersion: args.maxTransactionVersion },
    },
    notes: [
      'First means the first pass in this run. It does not prove a cold cache.',
      'Repeat means a later pass. Use cache=HIT to select proven response cache hits.',
      'Origin-uncached passes use profile=1 on Blockzilla, which bypasses response and archive caches but adds timing work.',
      'Only origin_uncached_verified means BYPASS, positive origin reads, and zero reported archive cache hits.',
      'A separate fullyColdVerified flag additionally requires auth BYPASS and one reported KV read.',
      'Source-uncached passes use profile=source: response/range caches are bypassed, while index and API key caches remain enabled.',
      'Source-index proof depends on the explicit backend: owner-native R2 requires two R2 GETs (one with access=0), zero S3/reader operations, and positive retained-index cache hits. Direct S3 or Foundation-reader mode requires zero owner R2 reads and two source GETs (one with access=0).',
      'Source auth-cache proof is separate: auth HIT and zero KV reads. A legitimate short-TTL auth MISS remains a successful sample and is charged in the actual counters.',
      'Index/auth warmup GETs run once per slot before the source-uncached passes. Their requests, bytes, storage operations, and auth KV reads are reported separately.',
      'Provider caches and R2 internal caches cannot be purged or proved cold by this client.',
      'A storage-backed MISS can reuse archive pages. R2 and S3 counters count object API operations, not physical disk reads.',
      'S3 operation receipts must be included when an R2 bucket is accessed through its S3 endpoint.',
      'Foundation native R2 GET proofs and reader HTTP attempts are separate. Aggregate object reads add confirmed Foundation operations once; missing reader proofs leave unknown backend work visible.',
      'For streamed-completion bodies, receipt bytes count only buffered inputs. Origin-Expected-Bytes is a separate declared source window; it is not measured S3 bytes.',
      'TTFB is time to the first body byte. Total time ends after the last body byte.',
      'Client timings include DNS, connection setup, and connection reuse from this one benchmark host.',
      'Fetch reports decoded body bytes. Wire compression and network conditions can differ.',
      'Content-Encoding, Content-Length, and Transfer-Encoding headers are recorded separately from decoded body bytes.',
      'Binary and JSON are separate formats. Compare providers only in the JSON groups.',
      'Identity checks compare requested slot, blockhash, previous blockhash, parent slot, and transaction count.',
      'Content checks hash the complete result with sorted object keys and exact JSON decimal numbers. Arrays and absent/null fields remain distinct.',
      'Content mismatches remain visible; speed samples do not become correctness evidence because their block identity matches.',
      'When binary references are supplied, complete V1 bundle and derived access=0 hashes are checked after the body timer. Original stored frames are reused; no extra HTTP read is made.',
      'Percentiles use successful samples only and the nearest-rank method. No retries are used.',
      'URLs, bearer keys, response error messages, and JSON block bodies are not stored.',
    ],
    groups: summarize(samples),
    identityChecks,
    contentChecks,
    binaryChecks,
    samples,
  };
  const output = `${JSON.stringify(report, null, 2)}\n`;
  if (args.output) {
    try {
      await writeFile(args.output, output, { flag: 'wx', mode: 0o600 });
    } catch {
      throw new Error('Cannot write the report. An existing file is not overwritten.');
    }
    console.log(JSON.stringify({ report: args.output, groups: report.groups, identityChecks, contentChecks }, null, 2));
  } else {
    process.stdout.write(output);
  }
  if (samples.some((sample) => !sample.ok)
      || identityChecks.some((check) => ['mismatch', 'incomplete'].includes(check.status))) {
    process.exitCode = 1;
  }
  if (contentChecks.some((check) => check.status !== 'matched')
      || binaryChecks.some((check) => check.status !== 'matched')
      || samples.some((sample) => sample.source === 'blockzilla' && sample.uncached && sample.ok && !sample.coldVerified)
      || samples.some((sample) => sample.source === 'blockzilla' && sample.sourceUncached && sample.ok && !sample.sourceIndexCachedVerified)
      || args.sourceUncachedRounds > 0 && samples.some((sample) => sample.source === 'blockzilla' && sample.uncached && sample.ok && !sample.fullyColdVerified)) {
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error instanceof Error ? error.message : 'Benchmark failed.');
    process.exitCode = 1;
  });
}
