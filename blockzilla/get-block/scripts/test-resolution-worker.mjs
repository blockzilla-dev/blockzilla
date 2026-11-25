#!/usr/bin/env node

import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, stat, writeFile, mkdir, copyFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import * as miniflare from 'miniflare';

const run = promisify(execFile);
const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const REPOSITORY = resolve(PACKAGE_ROOT, '../..');
const SLOT = 470_987_967;
const EPOCH = Math.floor(SLOT / 432_000);
const SOURCE_PREFIX = 'resolution-fixture-source';
const RESOLUTION_PREFIX = 'serving/resolution-local-v1';
const GENERATION = 'resolution-local-v1';
const KEY = 'bz_live_resolution_fixture_abcdefghijklmnopqrstuvwxyz0123456789';
const SECRET = 'resolution-local-test-secret-01234567890123456789';
const ORIGIN = 'https://resolution.test';
const digest = bytes => createHash('sha256').update(bytes).digest();

function args(argv) {
  const result = {};
  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i];
    if (key === '--help') return { help: true };
    if (!['--build', '--builder', '--input-root', '--oracle', '--receipt', '--fixture-out'].includes(key)
        || !argv[i + 1] || argv[i + 1].startsWith('--') || result[key.slice(2)]) {
      throw new Error('Invalid argument. Use --help.');
    }
    result[key.slice(2)] = resolve(argv[++i]);
  }
  return result;
}

function leb(bytes, cursor) {
  let value = 0n;
  for (let shift = 0n; shift < 70n; shift += 7n) {
    assert.ok(cursor.offset < bytes.length, 'truncated Wincode integer');
    const byte = bytes[cursor.offset++];
    value |= BigInt(byte & 127) << shift;
    if (!(byte & 128)) {
      assert.ok(value <= BigInt(Number.MAX_SAFE_INTEGER));
      return Number(value);
    }
  }
  assert.fail('oversized Wincode integer');
}

function vector(bytes, cursor) {
  const length = leb(bytes, cursor);
  assert.ok(cursor.offset + length <= bytes.length, 'truncated Wincode vector');
  const result = bytes.subarray(cursor.offset, cursor.offset + length);
  cursor.offset += length;
  return result;
}

function originalBundle(bytes) {
  const cursor = { offset: 0 };
  assert.equal(leb(bytes, cursor), 1);
  assert.equal(leb(bytes, cursor), SLOT);
  assert.equal(bytes[cursor.offset++], 1);
  const hot = vector(bytes, cursor);
  assert.equal(bytes[cursor.offset++], 0);
  assert.equal(bytes[cursor.offset++], 1);
  const access = vector(bytes, cursor);
  assert.equal(cursor.offset, bytes.length);
  const accessCursor = { offset: 0 };
  assert.equal(leb(access, accessCursor), 2);
  assert.equal(leb(access, accessCursor), 0);
  accessCursor.offset += 64;
  const signatureCounts = vector(access, accessCursor);
  const signatures = vector(access, accessCursor);
  assert.equal(signatureCounts.reduce((sum, value) => sum + value, 0) * 64, signatures.length);
  return { hot, access, signatures, signatureCounts };
}

function shortvec(bytes, cursor) {
  const start = cursor.offset;
  const value = leb(bytes, cursor);
  assert.ok(value <= 65_535 && cursor.offset - start <= 3, 'Solana ShortU16 bound');
  assert.equal(encodeLeb(value).length, cursor.offset - start, 'canonical Solana ShortU16');
  return value;
}

function wireTransaction(entry) {
  assert.ok(Array.isArray(entry.transaction), 'GET transaction must be an encoded tuple');
  assert.equal(entry.transaction.length, 2);
  assert.equal(entry.transaction[1], 'base64');
  assert.equal(typeof entry.transaction[0], 'string');
  const bytes = Buffer.from(entry.transaction[0], 'base64');
  assert.equal(bytes.toString('base64'), entry.transaction[0], 'canonical Base64');
  assert.ok(bytes.length > 0 && bytes.length <= 65_536, 'bounded transaction wire bytes');
  const cursor = { offset: 0 };
  const take = length => {
    assert.ok(Number.isSafeInteger(length) && length >= 0 && cursor.offset + length <= bytes.length,
      'complete Solana wire field');
    const value = bytes.subarray(cursor.offset, cursor.offset + length);
    cursor.offset += length;
    return value;
  };
  let count; let signatures; let messageStart; let messageEnd;
  let header; let keyCount; let keys; let recentBlockhash;
  let version = 'legacy'; let loadedCount = 0;
  const instructions = [];
  if (bytes[0] === 0x81) {
    // SIMD-0385 V1 places its complete message before fixed-count signatures.
    version = 1; messageStart = 0; take(1);
    header = take(3); count = header[0];
    const mask = take(4).readUInt32LE();
    assert.equal(mask & ~31, 0, 'known V1 config mask');
    assert.ok((mask & 3) === 0 || (mask & 3) === 3, 'complete V1 priority-fee mask');
    recentBlockhash = take(32);
    const instructionCount = take(1)[0]; keyCount = take(1)[0];
    assert.ok(instructionCount <= 64 && keyCount <= 64, 'bounded V1 message');
    keys = Array.from({ length: keyCount }, () => take(32));
    if (mask & 3) take(8);
    for (const bit of [4, 8, 16]) if (mask & bit) take(4);
    const rows = Array.from({ length: instructionCount }, () => {
      const row = take(4);
      return { programIdIndex: row[0], accountsLength: row[1], dataLength: row.readUInt16LE(2) };
    });
    for (const row of rows) instructions.push({ programIdIndex: row.programIdIndex,
      accounts: take(row.accountsLength), data: take(row.dataLength) });
    messageEnd = cursor.offset;
    signatures = take(count * 64);
  } else {
    count = shortvec(bytes, cursor);
    assert.ok(count < 128, 'Legacy/V0 signature count leaves the version discriminator clear');
    signatures = take(count * 64); messageStart = cursor.offset;
    assert.ok(cursor.offset < bytes.length);
    if (bytes[cursor.offset] & 128) {
      version = take(1)[0] & 127;
      assert.equal(version, 0, 'supported prefix-encoded message version');
    }
    header = take(3);
    assert.equal(header[0], count, 'signature count equals the signed message header');
    keyCount = shortvec(bytes, cursor);
    assert.ok(keyCount <= 256, 'bounded static account keys');
    keys = Array.from({ length: keyCount }, () => take(32));
    recentBlockhash = take(32);
    const instructionCount = shortvec(bytes, cursor);
    for (let i = 0; i < instructionCount; i += 1) {
      const programIdIndex = take(1)[0];
      const accounts = take(shortvec(bytes, cursor));
      const data = take(shortvec(bytes, cursor));
      instructions.push({ programIdIndex, accounts, data });
    }
    if (version === 0) {
      const lookups = shortvec(bytes, cursor);
      for (let i = 0; i < lookups; i += 1) {
        take(32);
        loadedCount += take(shortvec(bytes, cursor)).length;
        loadedCount += take(shortvec(bytes, cursor)).length;
      }
    }
    messageEnd = cursor.offset;
  }
  assert.ok(count <= keyCount && header[1] <= count && header[2] <= keyCount - count,
    'valid signer and readonly account counts');
  assert.ok(keyCount + loadedCount <= 256, 'bounded resolved account indexes');
  for (const instruction of instructions) {
    assert.ok(instruction.programIdIndex < keyCount + loadedCount, 'instruction program index');
    for (const index of instruction.accounts) assert.ok(index < keyCount + loadedCount, 'instruction account index');
  }
  assert.equal(cursor.offset, bytes.length, 'complete transaction with no trailing wire bytes');
  assert.equal(entry.version, version, 'RPC version matches the signed wire message');
  return { bytes, count, signatures, message: bytes.subarray(messageStart, messageEnd),
    keys, recentBlockhash, instructions, version };
}

function checkWireTransactions(result, source) {
  assert.equal(result.transactions.length, source.signatureCounts.length);
  let signatureOffset = 0;
  let signatureCount = 0;
  const hashes = createHash('sha256');
  const versions = {};
  for (let index = 0; index < result.transactions.length; index += 1) {
    const transaction = wireTransaction(result.transactions[index]);
    assert.equal(transaction.count, source.signatureCounts[index], `source signature count at transaction ${index}`);
    assert.deepEqual(transaction.signatures,
      source.signatures.subarray(signatureOffset, signatureOffset + transaction.signatures.length),
      `exact original signatures at transaction ${index}`);
    for (let signer = 0; signer < transaction.count; signer += 1) {
      const publicKey = createPublicKey({
        key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), transaction.keys[signer]]),
        format: 'der', type: 'spki',
      });
      assert.ok(verify(null, transaction.message, publicKey,
        transaction.signatures.subarray(signer * 64, (signer + 1) * 64)),
      `valid original Ed25519 wire signature at transaction ${index}, signer ${signer}`);
    }
    signatureOffset += transaction.signatures.length;
    signatureCount += transaction.count;
    hashes.update(encodeLeb(transaction.bytes.length)); hashes.update(transaction.bytes);
    versions[transaction.version] = (versions[transaction.version] ?? 0) + 1;
  }
  assert.equal(signatureOffset, source.signatures.length);
  const first = result.transactions[0];
  const firstBytes = Buffer.from(first.transaction[0], 'base64');
  assert.throws(() => wireTransaction({ ...first, transaction: [firstBytes.subarray(0, -1).toString('base64'), 'base64'] }),
    /wire|integer|field/, 'truncated native wire transaction is rejected');
  assert.throws(() => wireTransaction({ ...first, transaction: [first.transaction[0], 'base58'] }));
  return { transactions: result.transactions.length, signatures: signatureCount, versions,
    length_prefixed_wire_sha256: hashes.digest('hex') };
}

function storage(response, gets) {
  assert.equal(response.headers.get('X-Blockzilla-R2-GETs'), String(gets));
  assert.equal(response.headers.get('X-Blockzilla-R2-HEADs'), '0');
  assert.equal(response.headers.get('X-Blockzilla-R2-Reads'), String(gets));
  for (const field of ['Reads', 'GETs', 'HEADs', 'Bytes']) {
    assert.equal(response.headers.get(`X-Blockzilla-S3-${field}`), '0');
  }
}

function zeroReads(response) {
  storage(response, 0);
  assert.equal(response.headers.get('X-Blockzilla-R2-Bytes'), '0');
  assert.equal(response.headers.get('X-Blockzilla-Billable-Reads'), '0');
}

function changedIdentity(bytes, oldEtag, newEtag) {
  const oldBytes = Buffer.from(oldEtag);
  const newBytes = Buffer.from(newEtag);
  assert.equal(oldBytes.length, newBytes.length, 'local R2 ETags retain their fixed MD5 width');
  const result = Buffer.from(bytes);
  let offset = 96;
  let replacements = 0;
  while ((offset = result.indexOf(oldBytes, offset)) !== -1) {
    newBytes.copy(result, offset); offset += oldBytes.length; replacements += 1;
  }
  assert.equal(replacements, 2, 'replace the locator and source-object ETags only');
  digest(result.subarray(96)).copy(result, 56);
  return result;
}

function encodeLeb(value) {
  let integer = BigInt(value); const bytes = [];
  do { let byte = Number(integer & 127n); integer >>= 7n; if (integer) byte |= 128; bytes.push(byte); } while (integer);
  return Buffer.from(bytes);
}

function withoutPubkeyDictionary(bytes) {
  const suffixOffset = bytes.readUInt32LE(28);
  const suffixLength = bytes.readUInt32LE(32);
  const suffix = bytes.subarray(suffixOffset, suffixOffset + suffixLength);
  const cursor = { offset: 0 };
  const count = leb(suffix, cursor);
  assert.ok(count > 0);
  for (let index = 0; index < count; index += 1) {
    leb(suffix, cursor); cursor.offset += 32;
    assert.ok(cursor.offset <= suffix.length);
  }
  const replacement = Buffer.concat([Buffer.from([0]), suffix.subarray(cursor.offset)]);
  const vectorStart = suffixOffset - encodeLeb(suffixLength).length;
  const payload = Buffer.concat([bytes.subarray(96, vectorStart), encodeLeb(replacement.length), replacement]);
  const header = Buffer.from(bytes.subarray(0, 96));
  header.writeUInt32LE(payload.length, 16);
  header.writeUInt32LE(vectorStart + encodeLeb(replacement.length).length, 28);
  header.writeUInt32LE(replacement.length, 32);
  digest(payload).copy(header, 56);
  return Buffer.concat([header, payload]);
}

function reconstructClientBundle(resolution, parts) {
  assert.equal(resolution.subarray(0, 8).toString(), 'BZSLRS1!');
  assert.equal(resolution.readUInt16LE(8), 1);
  assert.equal(resolution.readUInt16LE(10), 96);
  assert.equal(resolution.readUInt32LE(16), resolution.length - 96);
  assert.deepEqual(digest(resolution.subarray(96)), resolution.subarray(56, 88));
  const locatorLength = resolution.readUInt32LE(88);
  assert.ok(locatorLength > 0 && 96 + locatorLength <= resolution.length);
  assert.equal(parts.subarray(0, 8).toString(), 'BZPART2!');
  assert.equal(parts.readBigUInt64LE(8), BigInt(SLOT));
  const hotLength = Number(parts.readBigUInt64LE(16));
  const signatureLength = Number(parts.readBigUInt64LE(24));
  assert.equal(parts.length, 64 + hotLength + signatureLength);
  assert.deepEqual(parts.subarray(32, 64), digest(resolution.subarray(96, 96 + locatorLength)));
  const prefixOffset = resolution.readUInt32LE(20);
  const prefixLength = resolution.readUInt32LE(24);
  const suffixOffset = resolution.readUInt32LE(28);
  const suffixLength = resolution.readUInt32LE(32);
  assert.ok(prefixOffset >= 96 + locatorLength && prefixOffset + prefixLength <= suffixOffset);
  assert.equal(suffixOffset + suffixLength, resolution.length);
  return Buffer.concat([encodeLeb(1), encodeLeb(SLOT), Buffer.from([1]), encodeLeb(hotLength),
    parts.subarray(64, 64 + hotLength), Buffer.from([0, 1]), encodeLeb(prefixLength + signatureLength + suffixLength),
    resolution.subarray(prefixOffset, prefixOffset + prefixLength), parts.subarray(64 + hotLength),
    resolution.subarray(suffixOffset)]);
}

async function main() {
  const options = args(process.argv.slice(2));
  if (options.help) {
    console.log('Usage: node scripts/test-resolution-worker.mjs [--build build/index.js] [--builder /path/build-slot-resolution] --input-root DIR --oracle FILE [--receipt /path/result.json] [--fixture-out /path/new-fixture]\nRuns the current release WASM in local Miniflare. It does not build or deploy the Worker.');
    return;
  }
  assert.ok(options['input-root'] && options.oracle, 'Supply --input-root DIR and --oracle FILE.');
  const input = resolve(options['input-root']);
  const builder = options.builder ?? join(REPOSITORY, 'target/release/build-slot-resolution');
  const build = options.build ?? join(PACKAGE_ROOT, 'build/index.js');
  for (const path of [builder, build, join(dirname(build), 'index_bg.wasm')]) assert.ok((await stat(path)).isFile());
  const bundle = await readFile(join(input, `${SLOT}.bundle.wincode`));
  const parsed = originalBundle(bundle);
  const descriptor = JSON.parse(await readFile(join(input, `${SLOT}.descriptor.json`), 'utf8'));
  const oracle = JSON.parse(await readFile(resolve(options.oracle), 'utf8'));
  assert.ok(Array.isArray(oracle.result?.transactions?.[0]?.transaction), 'Use an independent provider Base64 oracle.');
  const temporary = await mkdtemp(join(tmpdir(), 'blockzilla-resolution-worker-'));
  const receipt = { status: 'RUNNING', slot: SLOT, scope: 'Local release WASM with one real compact block and independent provider JSON', checks: [] };
  let generation = GENERATION;
  let archiveGeneration = 'local-source-v1';
  const miniflareOptions = () => {
    const value = {
      modules: [{ type: 'ESModule', path: build }, { type: 'CompiledWasm', path: join(dirname(build), 'index_bg.wasm') }],
      modulesRoot: dirname(build), name: 'blockzilla-resolution-test', compatibilityDate: '2026-09-10',
      resourcePersistencePath: join(temporary, 'storage'), telemetry: { enabled: false },
      bindings: { BZ_ARCHIVE_SOURCE: 'r2', BZ_ARCHIVE_LAYOUT: 'stored', BZ_ARCHIVE_PREFIX: SOURCE_PREFIX,
        BZ_ARCHIVE_GENERATION: archiveGeneration, BZ_HTTP_GET_ONLY: 'true', BZ_AUTH_CACHE_SCOPE: 'local-resolution-auth-scope', BZ_RESOLUTION_PREFIX: RESOLUTION_PREFIX,
        BZ_RESOLUTION_GENERATION: generation, BZ_RESOLUTION_SLOTS: String(SLOT), BZ_LOCATOR_SECRET: SECRET },
      r2Buckets: { BZ_ARCHIVE_BUCKET: 'resolution-source', BZ_RESOLUTION: 'resolution-index' },
      kvNamespaces: { BZ_RPC_API_KEYS: 'resolution-keys' },
      analyticsEngineDatasets: { BZ_RPC_METRICS: { dataset: 'resolution-test-metrics' } },
    };
    return typeof miniflare.convertV4MiniflareOptions === 'function' ? miniflare.convertV4MiniflareOptions(value) : value;
  };
  const mf = new miniflare.Miniflare(miniflareOptions());
  const sourceKey = name => `${SOURCE_PREFIX}/epoch-${EPOCH}/${name}`;
  const resolutionKey = `${RESOLUTION_PREFIX}/epoch-${EPOCH}/slot-${SLOT}.resolution.v1`;
  const request = (path, authenticated = true) => mf.dispatchFetch(`${ORIGIN}${path}`, {
    headers: authenticated ? { Authorization: `Bearer ${KEY}` } : {}, signal: AbortSignal.timeout(30_000),
  });
  const check = text => { receipt.checks.push(text); console.log(`Passed ${text}.`); };
  const read = async (path, authenticated = true) => {
    const response = await request(path, authenticated);
    const bytes = Buffer.from(await response.arrayBuffer());
    return { response, bytes };
  };
  const hit = async path => {
    for (let attempt = 0; attempt < 30; attempt += 1) {
      const result = await read(path);
      assert.equal(result.response.status, 200, result.bytes.toString().slice(0, 400));
      if (result.response.headers.get('X-Blockzilla-Cache') === 'HIT') { zeroReads(result.response); return result; }
      await new Promise(done => setTimeout(done, 10));
    }
    assert.fail(`no response cache hit: ${path.split('?')[0]}`);
  };
  try {
    console.log(`Testing release WASM resolution paths for real slot ${SLOT}.`);
    const source = await mf.getR2Bucket('BZ_ARCHIVE_BUCKET');
    const index = await mf.getR2Bucket('BZ_RESOLUTION');
    const hotObject = await source.put(sourceKey('archive-v2-blocks.zstd'), parsed.hot);
    const signatureObject = await source.put(sourceKey('signatures.bin'), parsed.signatures);
    const etag = object => object.httpEtag ?? `"${object.etag}"`;
    descriptor.source_prefix = SOURCE_PREFIX;
    descriptor.generation = GENERATION;
    descriptor.hot_row.compressed_offset = 0;
    descriptor.hot_row.first_signature_ordinal = 0;
    descriptor.objects['archive-v2-blocks.zstd'] = { length: parsed.hot.length, etag: etag(hotObject) };
    descriptor.objects['signatures.bin'] = { length: parsed.signatures.length, etag: etag(signatureObject) };
    const descriptorPath = join(temporary, 'descriptor.json');
    const resolutionPath = join(temporary, 'resolution.v1.bin');
    await writeFile(descriptorPath, JSON.stringify(descriptor));
    const built = await run(builder, ['--bundle', join(input, `${SLOT}.bundle.wincode`), '--descriptor', descriptorPath, '--output', resolutionPath], { maxBuffer: 1024 * 1024 });
    receipt.builder = JSON.parse(built.stdout);
    const resolutionBytes = await readFile(resolutionPath);
    await index.put(resolutionKey, resolutionBytes);
    const kv = await mf.getKVNamespace('BZ_RPC_API_KEYS');
    await kv.put(digest(KEY).toString('hex'), JSON.stringify({ keyId: 'resolution_local', customerId: 'local', label: 'Local resolution test', status: 'enabled' }));
    if (options['fixture-out']) {
      await mkdir(options['fixture-out']);
      for (const [name, bytes] of [['hot.zstd', parsed.hot], ['signatures.bin', parsed.signatures], ['resolution.v1.bin', resolutionBytes], ['bundle-original.wincode', bundle]]) {
        await writeFile(join(options['fixture-out'], name), bytes, { flag: 'wx' });
      }
      await copyFile(descriptorPath, join(options['fixture-out'], 'descriptor.json'));
      await writeFile(join(options['fixture-out'], 'fixture.json'), JSON.stringify({ slot: SLOT, source_prefix: SOURCE_PREFIX,
        generation: GENERATION, resolution_prefix: RESOLUTION_PREFIX, hot: 'hot.zstd', signatures: 'signatures.bin',
        resolution: 'resolution.v1.bin', bundle: 'bundle-original.wincode', descriptor: 'descriptor.json' }, null, 2));
    }
    const unauthorized = await read(`/block/${SLOT}.resolution?profile=1`, false);
    assert.equal(unauthorized.response.status, 401);
    check('resolution authentication before storage');
    for (const encoding of ['json', 'base58', 'jsonParsed', 'invalid']) {
      const invalid = await read(`/block/${SLOT}.json?encoding=${encoding}&profile=1`);
      assert.equal(invalid.response.status, 400);
      assert.equal(JSON.parse(invalid.bytes).error.code, -32602);
      zeroReads(invalid.response);
    }
    check('unsupported direct JSON encodings fail before all storage reads');

    const full = await read(`/block/${SLOT}.bin?profile=1`);
    assert.equal(full.response.status, 200, full.bytes.toString().slice(0, 400));
    assert.equal(full.response.headers.get('X-Blockzilla-Body'), 'native-stream');
    storage(full.response, 3);
    assert.deepEqual(full.bytes, bundle);
    check('three GETs and zero HEADs for an exact native V1 binary stream');
    const json = await read(`/block/${SLOT}.json?rewards=false&profile=1`);
    assert.equal(json.response.status, 200, json.bytes.toString().slice(0, 400));
    storage(json.response, 3);
    const jsonResult = JSON.parse(json.bytes).result;
    assert.deepEqual(jsonResult, oracle.result);
    receipt.base64_wire = checkWireTransactions(jsonResult, parsed);
    check('three GETs and complete Base64 RPC parity with the independent provider oracle');
    check('original signature windows complete legacy V0 and V1 wire schemas and every Ed25519 signature');
    const explicit = await read(`/block/${SLOT}.json?rewards=false&encoding=base64&profile=1`);
    assert.equal(explicit.response.status, 200); storage(explicit.response, 3);
    assert.deepEqual(JSON.parse(explicit.bytes).result, oracle.result);
    check('explicit Base64 encoding matches the direct GET default');
    await read(`/block/${SLOT}.json?rewards=false`); await hit(`/block/${SLOT}.json?rewards=false`);
    for (const kind of ['json', 'bin']) {
      const query = kind === 'json' ? 'rewards=false&' : '';
      const sourceOnly = await read(`/block/${SLOT}.${kind}?${query}profile=source`);
      assert.equal(sourceOnly.response.status, 200); storage(sourceOnly.response, 2);
      assert.equal(sourceOnly.response.headers.get('X-Blockzilla-Cache'), 'BYPASS');
      assert.equal(sourceOnly.response.headers.get('X-Blockzilla-Profile-Mode'), 'source');
      assert.equal(sourceOnly.response.headers.get('X-Blockzilla-Auth-Cache'), 'HIT');
      assert.equal(sourceOnly.response.headers.get('X-Blockzilla-Auth-KV-Reads'), '0');
      if (kind === 'json') assert.deepEqual(JSON.parse(sourceOnly.bytes).result, oracle.result);
      else assert.deepEqual(sourceOnly.bytes, bundle);
      const fullyCold = await read(`/block/${SLOT}.${kind}?${query}profile=1`);
      assert.equal(fullyCold.response.status, 200); storage(fullyCold.response, 3);
      assert.equal(fullyCold.response.headers.get('X-Blockzilla-Profile-Mode'), 'full');
      assert.equal(fullyCold.response.headers.get('X-Blockzilla-Auth-Cache'), 'BYPASS');
      assert.equal(fullyCold.response.headers.get('X-Blockzilla-Auth-KV-Reads'), '1');
    }
    const sourceIndex = await read(`/block/${SLOT}.resolution?profile=source`);
    assert.equal(sourceIndex.response.status, 200); storage(sourceIndex.response, 0);
    assert.equal(sourceIndex.response.headers.get('X-Blockzilla-Auth-Cache'), 'HIT');
    assert.equal(sourceIndex.response.headers.get('X-Blockzilla-Auth-KV-Reads'), '0');
    assert.deepEqual(sourceIndex.bytes, resolutionBytes);
    check('source-only profile keeps checked auth and index caches while forcing both source GETs');
    check('fully cold profile bypasses auth and index caches with three object GETs and one KV read');
    const noAccess = await read(`/block/${SLOT}.bin?access=0&profile=1`);
    assert.equal(noAccess.response.status, 200);
    storage(noAccess.response, 2);
    const noAccessCursor = { offset: 0 };
    assert.equal(leb(noAccess.bytes, noAccessCursor), 1); assert.equal(leb(noAccess.bytes, noAccessCursor), SLOT);
    assert.equal(noAccess.bytes[noAccessCursor.offset++], 1);
    assert.deepEqual(vector(noAccess.bytes, noAccessCursor), parsed.hot);
    assert.equal(noAccess.bytes[noAccessCursor.offset++], 0); assert.equal(noAccess.bytes[noAccessCursor.offset++], 0);
    assert.equal(noAccessCursor.offset, noAccess.bytes.length);
    check('two GETs for the original compressed block without access data');

    const resolved = await read(`/block/${SLOT}.resolution?profile=1`);
    assert.equal(resolved.response.status, 200); storage(resolved.response, 1);
    assert.deepEqual(resolved.bytes, resolutionBytes);
    const token = resolved.response.headers.get('X-Blockzilla-Locator'); assert.ok(token);
    const clientPath = `/block/${SLOT}.bin?access=client&locator=${encodeURIComponent(token)}`;
    const parts = await read(`${clientPath}&profile=1`);
    assert.equal(parts.response.status, 200, parts.bytes.toString().slice(0, 400)); storage(parts.response, 2);
    assert.equal(parts.response.headers.get('Content-Type'), 'application/vnd.blockzilla.get-block-parts.v2');
    assert.deepEqual(reconstructClientBundle(resolved.bytes, parts.bytes), bundle);
    check('one resolution GET followed by two authenticated client-part GETs and exact V1 reconstruction');
    for (const path of [`/block/${SLOT}.bin`, `/block/${SLOT}.json?rewards=false`, `/block/${SLOT}.resolution`, clientPath]) {
      await read(path); await hit(path);
    }
    check('zero archive GETs HEADs and bytes for all four full response cache hits');

    for (const [firstKind, secondKind] of [['json', 'bin'], ['bin', 'json']]) {
      archiveGeneration = `local-source-cross-format-${firstKind}`;
      await mf.setOptions(miniflareOptions());
      const pathFor = kind => `/block/${SLOT}.${kind}${kind === 'json' ? '?rewards=false' : ''}`;
      await read(pathFor(firstKind)); await hit(pathFor(firstKind));
      const reused = await read(pathFor(secondKind));
      assert.equal(reused.response.status, 200, reused.bytes.toString().slice(0, 400));
      assert.equal(reused.response.headers.get('X-Blockzilla-Cache'), 'MISS');
      zeroReads(reused.response);
      assert.ok(Number(reused.response.headers.get('X-Blockzilla-Archive-Memory-Hits')) >= 1,
        'validated resolution is reused from the bounded immutable memory cache');
      if (secondKind === 'bin') {
        assert.deepEqual(reused.bytes, bundle);
        assert.equal(reused.response.headers.get('X-Blockzilla-Origin-Expected-Bytes'), '0');
      } else assert.deepEqual(JSON.parse(reused.bytes).result, oracle.result);
    }
    check('JSON and native binary reuse both source ranges in either order with zero origin operations');

    archiveGeneration = 'local-source-invalid-index-not-promoted';
    await mf.setOptions(miniflareOptions());
    const validationIndex = await mf.getR2Bucket('BZ_RESOLUTION');
    const invalidBeforePromotion = Buffer.from(resolutionBytes); invalidBeforePromotion[invalidBeforePromotion.length - 1] ^= 1;
    await validationIndex.put(resolutionKey, invalidBeforePromotion);
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const invalid = await read(`/block/${SLOT}.bin`);
      assert.equal(invalid.response.status, 502); storage(invalid.response, 1);
      assert.notEqual(invalid.response.headers.get('X-Blockzilla-Cache'), 'HIT');
    }
    await validationIndex.put(resolutionKey, resolutionBytes);
    const repairedIndex = await read(`/block/${SLOT}.bin`);
    assert.equal(repairedIndex.response.status, 200, repairedIndex.bytes.toString().slice(0, 400));
    assert.deepEqual(repairedIndex.bytes, bundle); storage(repairedIndex.response, 3);
    check('invalid resolution bytes are not promoted to either cache before validation');

    for (const path of [
      `/block/${SLOT}.bin?access=client&locator=${encodeURIComponent(`${token[0] === 'A' ? 'B' : 'A'}${token.slice(1)}`)}&profile=1`,
      `/block/${SLOT + 1}.bin?access=client&locator=${encodeURIComponent(token)}&profile=1`,
    ]) {
      const invalid = await read(path); assert.ok(invalid.response.status >= 400); zeroReads(invalid.response);
      assert.ok(JSON.parse(invalid.bytes).error);
    }
    generation = 'resolution-local-v2'; await mf.setOptions(miniflareOptions());
    const stale = await read(`${clientPath}&profile=1`); assert.ok(stale.response.status >= 400); zeroReads(stale.response);
    generation = GENERATION; await mf.setOptions(miniflareOptions());
    check('changed token wrong slot and changed generation rejection before origin reads');

    const currentIndex = await mf.getR2Bucket('BZ_RESOLUTION');
    await currentIndex.delete(resolutionKey);
    const missing = await read(`/block/${SLOT}.bin?profile=1`);
    assert.equal(missing.response.status, 502); storage(missing.response, 1); assert.ok(JSON.parse(missing.bytes).error);
    const corruptResolution = Buffer.from(resolutionBytes); corruptResolution[corruptResolution.length - 1] ^= 1;
    await currentIndex.put(resolutionKey, corruptResolution);
    const corrupt = await read(`/block/${SLOT}.bin?profile=1`);
    assert.equal(corrupt.response.status, 502); storage(corrupt.response, 1); assert.ok(JSON.parse(corrupt.bytes).error);
    await currentIndex.put(resolutionKey, resolutionBytes);
    check('missing and corrupt admitted resolution objects fail without source reads');

    const currentSource = await mf.getR2Bucket('BZ_ARCHIVE_BUCKET');
    const invalidHot = Buffer.from(parsed.hot); invalidHot[0] ^= 255;
    const changed = await currentSource.put(sourceKey('archive-v2-blocks.zstd'), invalidHot);
    const wrongEtag = await read(`/block/${SLOT}.bin?profile=1`);
    assert.equal(wrongEtag.response.status, 502); assert.ok(JSON.parse(wrongEtag.bytes).error);
    assert.notEqual(wrongEtag.response.headers.get('X-Blockzilla-Body'), 'native-stream');
    check('changed source ETag rejection before native binary body creation');

    // The local test operator admits the corrupt source with its actual ETag.
    // Binary routes must copy it exactly; only JSON should try zstd decoding.
    const invalidResolution = changedIdentity(resolutionBytes, descriptor.objects['archive-v2-blocks.zstd'].etag, etag(changed));
    await currentIndex.put(resolutionKey, invalidResolution);
    const undecoded = await read(`/block/${SLOT}.bin?access=0&profile=1`);
    assert.equal(undecoded.response.status, 200); storage(undecoded.response, 2);
    const badCursor = { offset: 0 }; leb(undecoded.bytes, badCursor); leb(undecoded.bytes, badCursor); badCursor.offset += 1;
    assert.deepEqual(vector(undecoded.bytes, badCursor), invalidHot);
    const badJson = await read(`/block/${SLOT}.json?rewards=false&profile=1`);
    assert.equal(badJson.response.status, 502); assert.ok(JSON.parse(badJson.bytes).error);
    await currentSource.put(sourceKey('archive-v2-blocks.zstd'), parsed.hot);
    await currentIndex.put(resolutionKey, resolutionBytes);
    check('binary streams do not decode hot blocks while JSON rejects corrupt zstd');

    // Admit a structurally valid index with missing first-transaction keys.
    // This reaches the asynchronous renderer, after the HTTP200 response was
    // created. Neither complete error JSON nor a valid cache entry may result.
    archiveGeneration = 'local-source-render-error';
    await mf.setOptions(miniflareOptions());
    const faultIndex = await mf.getR2Bucket('BZ_RESOLUTION');
    await faultIndex.put(resolutionKey, withoutPubkeyDictionary(resolutionBytes));
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const response = await request(`/block/${SLOT}.json?rewards=false`);
      assert.notEqual(response.headers.get('X-Blockzilla-Cache'), 'HIT');
      let failed = false;
      try { JSON.parse(await response.text()); }
      catch { failed = true; }
      assert.ok(failed, 'an early render error must abort the body instead of completing cacheable error JSON');
    }
    await faultIndex.put(resolutionKey, resolutionBytes);
    const repaired = await read(`/block/${SLOT}.json?rewards=false&profile=1`);
    assert.equal(repaired.response.status, 200);
    assert.deepEqual(JSON.parse(repaired.bytes).result, oracle.result);
    check('early render errors abort on both normal requests and never become response-cache hits');
    receipt.status = 'PASSED';
    receipt.original_bundle_sha256 = digest(bundle).toString('hex');
    receipt.resolution_sha256 = digest(resolutionBytes).toString('hex');
    receipt.resolution_bytes = resolutionBytes.length;
    console.log('All resolution Worker integration checks passed. No cloud or production service was used.');
  } finally {
    try { await mf.dispose(); }
    finally {
      if (options.receipt) await writeFile(options.receipt, `${JSON.stringify(receipt, null, 2)}\n`);
      await rm(temporary, { recursive: true, force: true });
    }
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
