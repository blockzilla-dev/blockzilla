#!/usr/bin/env node

// Client framing only. Native client JSON decoding is timed separately by
// render-resolution-client; this script does not claim to decode Solana JSON.
import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir, stat } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { loadSlots, storageReceipt, storageClassification, summarize } from './bench-get-block.mjs';

const MiB = 1024 * 1024;
const RESOLUTION_HEADER = 96;
const MAX_RESOLUTION = 4 * MiB;
const MAX_HOT = 16 * MiB;
const MAX_SIGNATURES = 8 * MiB;
const PARTS_HEADER = 64;
export const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const digest = (bytes) => createHash('sha256').update(bytes).digest();
const check = (condition, message) => { if (!condition) throw new Error(message); };

export function encodeULEB(value) {
  check(Number.isSafeInteger(value) && value >= 0, 'Invalid unsigned integer');
  let number = BigInt(value);
  const result = [];
  do { let byte = Number(number & 127n); number >>= 7n; if (number) byte |= 128; result.push(byte); } while (number);
  return Buffer.from(result);
}

function unsigned(bytes, cursor) {
  const start = cursor.offset;
  let number = 0n;
  for (let shift = 0n; shift < 70n; shift += 7n) {
    check(cursor.offset < bytes.length, 'Truncated Wincode integer');
    const byte = bytes[cursor.offset++];
    number |= BigInt(byte & 127) << shift;
    if (!(byte & 128)) {
      check(number <= BigInt(Number.MAX_SAFE_INTEGER), 'Wincode integer exceeds client bounds');
      const value = Number(number);
      check(cursor.offset - start === encodeULEB(value).length, 'Non-canonical Wincode integer');
      return value;
    }
  }
  throw new Error('Oversized Wincode integer');
}

function fixed64(bytes, offset) {
  check(offset + 8 <= bytes.length, 'Truncated fixed integer');
  const number = bytes.readBigUInt64LE(offset);
  check(number <= BigInt(Number.MAX_SAFE_INTEGER), 'Fixed integer exceeds client bounds');
  return Number(number);
}

function raw(bytes, cursor, length) {
  check(Number.isSafeInteger(length) && length >= 0 && cursor.offset + length <= bytes.length, 'Truncated Wincode data');
  const result = bytes.subarray(cursor.offset, cursor.offset + length);
  cursor.offset += length;
  return result;
}

function vector(bytes, cursor, limit) {
  const length = unsigned(bytes, cursor);
  check(length <= limit, 'Wincode vector exceeds client bounds');
  return { start: cursor.offset, bytes: raw(bytes, cursor, length) };
}

function text(bytes, cursor, limit = 1024) {
  return new TextDecoder('utf-8', { fatal: true }).decode(vector(bytes, cursor, limit).bytes);
}

function identity(bytes, cursor) {
  const length = unsigned(bytes, cursor);
  const etag = text(bytes, cursor, 130);
  check(/^"[\x21\x23-\x7e]{1,128}"$/.test(etag), 'Invalid source ETag');
  return { length, etag };
}

function locator(bytes, cursor) {
  const version = unsigned(bytes, cursor);
  const sourcePrefix = text(bytes, cursor, 512);
  const generation = text(bytes, cursor, 128);
  const epoch = unsigned(bytes, cursor);
  const hot = {};
  for (const field of ['block_id', 'slot', 'compressed_offset', 'compressed_len', 'uncompressed_len', 'tx_count', 'first_tx_ordinal', 'first_signature_ordinal', 'signature_count']) hot[field] = unsigned(bytes, cursor);
  const parentSlot = unsigned(bytes, cursor);
  const blockhash = raw(bytes, cursor, 32);
  const previousBlockhash = raw(bytes, cursor, 32);
  const messageSchema = raw(bytes, cursor, 1)[0];
  const metadataSchema = raw(bytes, cursor, 1)[0];
  const blocks = identity(bytes, cursor);
  const signatures = identity(bytes, cursor);
  check(version === 1 && epoch === Math.floor(hot.slot / 432000), 'Invalid locator version or epoch');
  check(sourcePrefix.length > 0 && !sourcePrefix.split('/').some((part) => ['', '.', '..'].includes(part)), 'Invalid locator source prefix');
  check(/^[A-Za-z0-9._-]{1,128}$/.test(generation), 'Invalid locator generation');
  check(messageSchema <= 1 && metadataSchema <= 1, 'Unsupported locator schema');
  check(hot.compressed_len > 0 && hot.compressed_len <= MAX_HOT && hot.uncompressed_len > 0 && hot.uncompressed_len <= 32 * MiB, 'Hot block exceeds client bounds');
  check(hot.compressed_offset + hot.compressed_len <= blocks.length, 'Hot block exceeds source object');
  const signatureBytes = hot.signature_count * 64;
  check(Number.isSafeInteger(signatureBytes) && signatureBytes <= MAX_SIGNATURES && (hot.first_signature_ordinal * 64) + signatureBytes <= signatures.length, 'Signature window exceeds source object');
  check(hot.slot === 0 ? parentSlot === 0 : parentSlot < hot.slot, 'Invalid locator parent');
  return { version, sourcePrefix, generation, epoch, hot, slot: hot.slot, parentSlot, blockhash, previousBlockhash, messageSchema, metadataSchema, blocks, signatures, signatureBytes };
}

export function decodeResolution(input, expectedSlot) {
  const bytes = Buffer.from(input);
  check(bytes.length >= RESOLUTION_HEADER && bytes.length <= MAX_RESOLUTION, 'Invalid resolution length');
  check(bytes.subarray(0, 8).toString('ascii') === 'BZSLRS1!' && bytes.readUInt16LE(8) === 1 && bytes.readUInt16LE(10) === RESOLUTION_HEADER, 'Invalid resolution header');
  check([...bytes.subarray(12, 16), ...bytes.subarray(38, 40), ...bytes.subarray(92, 96)].every((byte) => byte === 0), 'Nonzero resolution reserved bytes');
  const payload = bytes.subarray(RESOLUTION_HEADER);
  check(bytes.readUInt32LE(16) === payload.length && digest(payload).equals(bytes.subarray(56, 88)), 'Resolution payload length or SHA256 differs');
  const cursor = { offset: 0 };
  const value = locator(payload, cursor);
  const locatorLength = bytes.readUInt32LE(88);
  check(locatorLength === cursor.offset && locatorLength > 0 && locatorLength <= 8192, 'Resolution locator length differs');
  const locatorBytes = payload.subarray(0, locatorLength);
  check(value.slot === fixed64(bytes, 48) && value.epoch === fixed64(bytes, 40) && (expectedSlot === undefined || value.slot === expectedSlot), 'Resolution slot or epoch differs');
  check(value.messageSchema === bytes[36] && value.metadataSchema === bytes[37], 'Resolution schema differs');
  const objectCount = unsigned(payload, cursor);
  check(objectCount <= 128, 'Too many source objects');
  const objects = new Map();
  for (let index = 0; index < objectCount; index += 1) {
    const name = text(payload, cursor, 256);
    check(!objects.has(name), 'Duplicate source object');
    objects.set(name, identity(payload, cursor));
  }
  for (const [name, expected] of [['archive-v2-blocks.zstd', value.blocks], ['signatures.bin', value.signatures]]) {
    const actual = objects.get(name);
    check(actual?.length === expected.length && actual?.etag === expected.etag, 'Resolution source identity differs');
  }
  const signatureCounts = vector(payload, cursor, 131072).bytes;
  check(signatureCounts.length === value.hot.tx_count && [...signatureCounts].reduce((sum, count) => sum + count, 0) === value.hot.signature_count, 'Resolution signature counts differ');
  const prefix = vector(payload, cursor, MAX_RESOLUTION);
  const suffix = vector(payload, cursor, MAX_RESOLUTION);
  check(cursor.offset === payload.length, 'Resolution has trailing bytes');
  check(bytes.readUInt32LE(20) === RESOLUTION_HEADER + prefix.start && bytes.readUInt32LE(24) === prefix.bytes.length && bytes.readUInt32LE(28) === RESOLUTION_HEADER + suffix.start && bytes.readUInt32LE(32) === suffix.bytes.length, 'Resolution segment offsets differ');
  const access = { offset: 0 };
  check(unsigned(prefix.bytes, access) === 2 && unsigned(prefix.bytes, access) === 0, 'Invalid access prefix version or flags');
  check(raw(prefix.bytes, access, 32).equals(value.blockhash) && raw(prefix.bytes, access, 32).equals(value.previousBlockhash), 'Access prefix hashes differ');
  check(vector(prefix.bytes, access, 131072).bytes.equals(signatureCounts), 'Access prefix signature counts differ');
  check(unsigned(prefix.bytes, access) === value.signatureBytes && access.offset === prefix.bytes.length, 'Access prefix signature byte length differs');
  return { bytes, payload, locator: value, locatorBytes, locatorDigest: digest(locatorBytes), prefix: prefix.bytes, suffix: suffix.bytes, signatureCounts, signatureBytes: value.signatureBytes, sha256: sha256(bytes) };
}

// Only the Worker can verify the HMAC. The client checks token framing and
// that its descriptor bytes match the downloaded resolution.
export function validateLocatorToken(token, resolution) {
  check(typeof token === 'string' && token.length <= 16384 && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token), 'Missing or invalid locator token');
  const [body, mac] = token.split('.');
  check(Buffer.from(body, 'base64url').equals(resolution.locatorBytes) && Buffer.from(mac, 'base64url').length === 32, 'Locator token differs from the resolution');
  return token;
}

export function decodeParts(input, resolution) {
  const bytes = Buffer.from(input);
  check(bytes.length >= PARTS_HEADER && bytes.length <= PARTS_HEADER + MAX_HOT + MAX_SIGNATURES, 'Invalid client-parts length');
  check(bytes.subarray(0, 8).toString('ascii') === 'BZPART2!', 'Invalid client-parts magic');
  const slot = fixed64(bytes, 8), hotLength = fixed64(bytes, 16), signatureLength = fixed64(bytes, 24);
  check(slot === resolution.locator.slot && hotLength === resolution.locator.hot.compressed_len && signatureLength === resolution.signatureBytes, 'Client-parts slot or lengths differ');
  check(bytes.length === PARTS_HEADER + hotLength + signatureLength, 'Client-parts body is truncated or has trailing bytes');
  check(bytes.subarray(32, 64).equals(resolution.locatorDigest), 'Client-parts locator digest differs');
  return { bytes, slot, hot: bytes.subarray(PARTS_HEADER, PARTS_HEADER + hotLength), signatures: bytes.subarray(PARTS_HEADER + hotLength), locatorDigest: bytes.subarray(32, 64) };
}

export function reconstructV1Bundle(resolution, input) {
  const parts = input.hot ? input : decodeParts(input, resolution);
  check(parts.slot === resolution.locator.slot && parts.hot.length === resolution.locator.hot.compressed_len && parts.signatures.length === resolution.signatureBytes && parts.locatorDigest.equals(resolution.locatorDigest), 'Client-parts do not match the resolution');
  const accessLength = resolution.prefix.length + parts.signatures.length + resolution.suffix.length;
  return Buffer.concat([encodeULEB(1), encodeULEB(parts.slot), Buffer.from([1]), encodeULEB(parts.hot.length), parts.hot, Buffer.from([0, 1]), encodeULEB(accessLength), resolution.prefix, parts.signatures, resolution.suffix]);
}

export function decodeV1Bundle(input) {
  const bytes = Buffer.from(input), cursor = { offset: 0 };
  check(unsigned(bytes, cursor) === 1, 'Invalid V1 bundle version');
  const slot = unsigned(bytes, cursor);
  check(raw(bytes, cursor, 1)[0] === 1, 'V1 bundle needs a zstd block');
  const hot = vector(bytes, cursor, MAX_HOT).bytes;
  check(raw(bytes, cursor, 1)[0] === 0 && raw(bytes, cursor, 1)[0] === 1, 'V1 bundle needs full Wincode access');
  const access = vector(bytes, cursor, MAX_RESOLUTION + MAX_SIGNATURES).bytes;
  check(cursor.offset === bytes.length, 'V1 bundle has trailing bytes');
  const accessCursor = { offset: 0 };
  check(unsigned(access, accessCursor) === 2 && unsigned(access, accessCursor) === 0, 'Invalid V1 access version or flags');
  const blockhash = raw(access, accessCursor, 32), previousBlockhash = raw(access, accessCursor, 32);
  const signatureCounts = vector(access, accessCursor, 131072).bytes;
  const signatures = vector(access, accessCursor, MAX_SIGNATURES).bytes;
  return { bytes, slot, hot, access, blockhash, previousBlockhash, signatureCounts, signatures };
}

async function saveExact(path, bytes) {
  try { await writeFile(path, bytes, { flag: 'wx', mode: 0o600 }); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    const existing = await readFile(path);
    check(existing.equals(bytes), 'An existing client input differs; use a fresh downloads directory');
  }
}

async function boundedBody(response, maximum) {
  const chunks = [];
  let length = 0;
  for await (const chunk of response.body) {
    length += chunk.byteLength;
    check(length <= maximum, 'HTTP body exceeds the client limit');
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks, length);
}

function argsFrom(argv) {
  const args = {};
  const names = new Set(['url', 'slots', 'input-manifest', 'resolution-dir', 'rounds', 'uncached-rounds', 'timeout-ms', 'output', 'downloads', 'concurrency', 'max-requests']);
  for (let index = 0; index < argv.length; index += 1) {
    if (['--help', '-h'].includes(argv[index])) return { help: true };
    if (argv[index] === '--self-test') { args.selfTest = true; continue; }
    const name = argv[index].slice(2), value = argv[++index];
    check(names.has(name) && value && !value.startsWith('--') && args[name] === undefined, 'Invalid client benchmark argument');
    args[name] = value;
  }
  const integer = (name, fallback, maximum) => { const value = Number(args[name] ?? fallback); check(Number.isSafeInteger(value) && value >= 0 && value <= maximum, 'Invalid client benchmark count'); return value; };
  args.rounds = integer('rounds', 5, 100); args.uncachedRounds = integer('uncached-rounds', 1, 10); args.timeoutMs = integer('timeout-ms', 90000, 600000);
  check(integer('concurrency', 1, 1) === 1, 'This client benchmark uses concurrency 1');
  args.maxRequests = integer('max-requests', 300, 300);
  return args;
}

export async function selfTest(inputManifest, resolutionDir) {
  const manifest = JSON.parse(await readFile(inputManifest, 'utf8'));
  let mutations = 0;
  const mustFail = (operation) => { let failed = false; try { operation(); } catch { failed = true; } check(failed, 'Corrupt fixture was accepted'); mutations += 1; };
  for (const record of manifest.records) {
    const bytes = await readFile(join(resolutionDir, `slot-${record.slot}.resolution.v1.bin`));
    const resolution = decodeResolution(bytes, record.slot);
    const old = decodeV1Bundle(await readFile(record.bundlePath));
    const frame = Buffer.concat([Buffer.from('BZPART2!'), Buffer.alloc(24), resolution.locatorDigest, old.hot, old.signatures]);
    frame.writeBigUInt64LE(BigInt(old.slot), 8); frame.writeBigUInt64LE(BigInt(old.hot.length), 16); frame.writeBigUInt64LE(BigInt(old.signatures.length), 24);
    const rebuilt = reconstructV1Bundle(resolution, decodeParts(frame, resolution));
    check(sha256(rebuilt) === record.bundleSha256, 'Rebuilt V1 bundle differs from the original');
    const token = `${resolution.locatorBytes.toString('base64url')}.${Buffer.alloc(32).toString('base64url')}`;
    validateLocatorToken(token, resolution);
    mustFail(() => decodeResolution(bytes.subarray(0, 95), record.slot));
    const badPayload = Buffer.from(bytes); badPayload[badPayload.length - 1] ^= 1; mustFail(() => decodeResolution(badPayload, record.slot));
    mustFail(() => decodeResolution(bytes, record.slot + 1));
    mustFail(() => decodeParts(frame.subarray(0, frame.length - 1), resolution));
    mustFail(() => decodeParts(Buffer.concat([frame, Buffer.from([0])]), resolution));
    const badDigest = Buffer.from(frame); badDigest[32] ^= 1; mustFail(() => decodeParts(badDigest, resolution));
    const badLength = Buffer.from(frame); badLength.writeBigUInt64LE(1n, 16); mustFail(() => decodeParts(badLength, resolution));
    mustFail(() => validateLocatorToken('invalid', resolution));
  }
  return { matchedBundles: manifest.records.length, rejectedMutations: mutations };
}

async function fetchSample(url, key, settings, phase, slot, representation, operation) {
  const started = performance.now();
  const sample = { source: 'blockzilla', label: 'blockzilla_client', slot, representation, phase, uncached: phase === 'origin_uncached', round: 0, status: null, cache: 'UNREPORTED', bytes: 0, ttfbMs: null, totalMs: null, ok: false };
  try {
    const response = await fetch(url, { headers: { Authorization: `Bearer ${key}` }, redirect: 'error', signal: AbortSignal.timeout(settings.timeoutMs) });
    sample.status = response.status;
    sample.headersMs = performance.now() - started;
    sample.cache = response.headers.get('X-Blockzilla-Cache') ?? 'UNREPORTED';
    sample.storage = storageReceipt(response.headers);
    sample.storageClass = storageClassification(sample);
    sample.coldVerified = sample.storageClass === 'origin_uncached_verified';
    sample.contentEncoding = response.headers.get('Content-Encoding');
    sample.contentLength = response.headers.get('Content-Length');
    sample.transferEncoding = response.headers.get('Transfer-Encoding');
    sample.edgeLocation = response.headers.get('CF-Ray')?.split('-').at(-1) ?? null;
    const reader = response.body.getReader(), chunks = [];
    const maximum = representation === 'resolution' ? MAX_RESOLUTION : PARTS_HEADER + MAX_HOT + MAX_SIGNATURES;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value.byteLength) continue;
        sample.ttfbMs ??= performance.now() - started;
        sample.bytes += value.byteLength;
        check(sample.bytes <= maximum, 'HTTP body exceeds the client limit');
        chunks.push(Buffer.from(value));
      }
    } finally { reader.releaseLock(); }
    sample.totalMs = performance.now() - started;
    if (!response.ok) { sample.error = `http_${response.status}`; return { sample }; }
    const bytes = Buffer.concat(chunks, sample.bytes), validationStarted = performance.now();
    const data = await operation(bytes, response);
    sample.validationMs = performance.now() - validationStarted;
    sample.ok = true;
    return { sample, data, bytes };
  } catch {
    sample.totalMs ??= performance.now() - started;
    sample.error = sample.status === 200 ? 'invalid_or_truncated_body' : 'transport_error';
    return { sample };
  }
}

export async function main(argv, env = process.env) {
  const args = argsFrom(argv);
  if (args.help) { console.log('Usage: --url @ENV --slots FILE --input-manifest FILE --output FILE [--downloads DIR] [--rounds 5] [--uncached-rounds 1]\nOffline: --self-test --input-manifest FILE --resolution-dir DIR'); return; }
  check(args['input-manifest'], 'Supply --input-manifest');
  if (args.selfTest) { console.log(JSON.stringify(await selfTest(args['input-manifest'], args['resolution-dir']))); return; }
  check(args.url && args.slots && args.output && env.BLOCKZILLA_RPC_API_KEY, 'Supply URL, slots, output, and the Worker API-key environment variable');
  const endpoint = args.url.startsWith('@') ? env[args.url.slice(1)] : args.url;
  const base = new URL(endpoint);
  check(['https:', 'http:'].includes(base.protocol) && !base.username && !base.password && !base.hash, 'Invalid Worker URL');
  const slots = await loadSlots(args.slots), manifest = JSON.parse(await readFile(args['input-manifest'], 'utf8'));
  const expected = new Map(manifest.records.map((record) => [record.slot, record]));
  check(slots.every((slot) => expected.has(slot)), 'An expected original bundle is missing');
  const requestCount = slots.length * (2 + args.rounds + args.uncachedRounds);
  check(requestCount <= args.maxRequests, 'Client benchmark exceeds its request budget');
  check(!await stat(args.output).then(() => true, (error) => { if (error.code === 'ENOENT') return false; throw error; }), 'The client report already exists');
  const downloads = resolve(args.downloads ?? 'profile-output/client-downloads');
  await mkdir(downloads, { recursive: true, mode: 0o700 });
  const startedAt = new Date().toISOString(), started = performance.now(), samples = [], indexes = new Map(), saved = new Set();
  const urlFor = (slot, kind, token, uncached) => { const url = new URL(base); url.pathname = `${url.pathname.replace(/\/$/, '')}/block/${slot}.${kind}`; url.search = ''; if (token) { url.searchParams.set('access', 'client'); url.searchParams.set('locator', token); } if (uncached) url.searchParams.set('profile', '1'); return url; };
  // Complete the first index pass before confirmation. This gives waitUntil
  // writes time to finish without a hidden retry or cache-busting query.
  for (const phase of ['index_first', 'index_repeat']) {
    for (const slot of slots) {
      const result = await fetchSample(urlFor(slot, 'resolution'), env.BLOCKZILLA_RPC_API_KEY, args, phase, slot, 'resolution', async (bytes, response) => {
        const resolution = decodeResolution(bytes, slot);
        const token = validateLocatorToken(response.headers.get('X-Blockzilla-Locator'), resolution);
        check(response.headers.get('Content-Type')?.includes('slot-resolution.v1'), 'Invalid resolution content type');
        if (!indexes.has(slot)) {
          await saveExact(join(downloads, `${slot}.resolution.v1.bin`), bytes);
          indexes.set(slot, { resolution, token });
        } else check(indexes.get(slot).resolution.sha256 === resolution.sha256, 'Resolution changed during the run');
        return { indexSha256: resolution.sha256 };
      });
      samples.push(result.sample);
    }
  }
  for (const uncached of [true, false]) {
    const rounds = uncached ? args.uncachedRounds : args.rounds;
    for (let round = 0; round < rounds; round += 1) {
      for (const slot of slots) {
        const index = indexes.get(slot);
        if (!index) continue;
        const phase = uncached ? 'origin_uncached' : round === 0 ? 'first' : 'repeat';
        const result = await fetchSample(urlFor(slot, 'bin', index.token, uncached), env.BLOCKZILLA_RPC_API_KEY, args, phase, slot, 'bin-client-parts', async (bytes, response) => {
          check(response.headers.get('Content-Type')?.includes('get-block-parts.v2'), 'Invalid parts content type');
          const partsStarted = performance.now();
          const parts = decodeParts(bytes, index.resolution);
          const partsValidationMs = performance.now() - partsStarted;
          const rebuildStarted = performance.now(), rebuilt = reconstructV1Bundle(index.resolution, parts);
          const bundleReconstructionMs = performance.now() - rebuildStarted;
          const hashStarted = performance.now(), bundleSha256 = sha256(rebuilt);
          const bundleHashMs = performance.now() - hashStarted;
          check(bundleSha256 === expected.get(slot).bundleSha256, 'Rebuilt V1 bundle differs from the original');
          if (!saved.has(slot)) { await saveExact(join(downloads, `${slot}.parts.v2.bin`), bytes); saved.add(slot); }
          return { bundleSha256, bundleBytes: rebuilt.length, partsValidationMs, bundleReconstructionMs, bundleHashMs, validatedDeliveredSourceWindowBytes: parts.hot.length + parts.signatures.length };
        });
        result.sample.round = round;
        if (result.data) Object.assign(result.sample, result.data);
        samples.push(result.sample);
      }
    }
  }
  const report = { schema: 'blockzilla-resolution-client-benchmark-v1', startedAt, durationMs: performance.now() - started, plan: { slots, rounds: args.rounds, uncachedRounds: args.uncachedRounds, concurrency: 1, requests: requestCount, indexDownloadsSeparate: true }, notes: [
    'Resolution downloads and confirmation reads are separate from steady client parts requests.',
    'The client retains one resolution and opaque signed locator per slot in memory.',
    'Origin-uncached parts use profile=1. Provider and R2 internal caches cannot be proved cold.',
    'V2 parts are framed and rebuilt into the exact prior V1 bundle. No client JSON timing is claimed here.',
    'Header storage bytes in streamed-completion mode cover buffered inputs only. Origin-Expected-Bytes is declared, not a measured S3 byte receipt.',
    'Validated source-window delivery is counted separately after complete frame validation.',
    'URLs, API keys, locator tokens, and block bodies are not stored in this report.',
  ], groups: summarize(samples), samples, matchedBundleSlots: [...saved], downloads };
  await writeFile(args.output, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({ report: args.output, matchedBundles: saved.size, requests: samples.length, errors: samples.filter((sample) => !sample.ok).map(({ slot, representation, phase, error }) => ({ slot, representation, phase, error })) }));
  if (samples.some((sample) => !sample.ok || sample.uncached && !sample.coldVerified) || saved.size !== slots.length) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main(process.argv.slice(2)).catch(() => { console.error('Resolution client check failed.'); process.exitCode = 1; });
