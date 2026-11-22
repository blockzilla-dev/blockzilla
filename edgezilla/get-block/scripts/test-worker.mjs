#!/usr/bin/env node

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as miniflare from 'miniflare';

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ORIGIN = 'https://blockzilla.test';
const ARCHIVE_PREFIX = 'fixture-query';
const FIRST_SLOT = 432_000;
const KEY_A = 'bz_live_local_fixture_customer_a_abcdefghijklmnopqrstuvwxyz012345';
const KEY_B = 'bz_live_local_fixture_customer_b_abcdefghijklmnopqrstuvwxyz012345';
const CURRENT_MARKER = 'archive-v2-message-schema-current-v1.marker';
const MAY24_MARKER = 'archive-v2-message-schema-may24-pre-unknown-fallbacks-v1.marker';
const LEGACY_METADATA_MARKER = 'archive-v2-metadata-schema-legacy-raw-error-v1.marker';
const MAY24_MARKER_BYTES = 'blockzilla/archive-v2-hot-message-schema/may24-2026-pre-unknown-system-unknown-vote/v1\n';
const LEGACY_METADATA_MARKER_BYTES = 'blockzilla/archive-v2-metadata-schema/legacy-raw-error/v1\n';

function usage() {
  return `Usage:
  BLOCKZILLA_WORKER_FIXTURE_DIR=/path/to/fixture node scripts/test-worker.mjs
  node scripts/test-worker.mjs --fixture /path/to/fixture [--build /path/to/build/index.js]
    [--compatibility-date YYYY-MM-DD]

Build the Worker first with npm run build. The fixture is made by:
  BLOCKZILLA_WORKER_FIXTURE_DIR=/tmp/blockzilla-worker-fixture \\
    cargo test --locked -p blockzilla-get-block --bin build-slot-index \\
    tests::builds_real_archive_and_preserves_absent_slot_and_boundary_hash -- --exact

The fixture can be the epoch-1 directory or its parent directory.
The local test date defaults to 2026-09-10 for the bundled workerd binary.
This does not change the deployment compatibility date.
All requests, R2 objects, KV records, and metrics stay in local Miniflare.
The test changes only temporary local storage and never uses cloud credentials.`;
}

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 1) {
    const name = argv[index];
    if (name === '--help' || name === '-h') return { help: true };
    if (!['--fixture', '--build', '--compatibility-date'].includes(name) || !argv[index + 1]
        || argv[index + 1].startsWith('--')) throw new Error('Invalid argument. Use --help.');
    if (args[name.slice(2)]) throw new Error(`Duplicate ${name}.`);
    args[name.slice(2)] = argv[++index];
  }
  return args;
}

function base58(bytes) {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let value = 0n;
  for (const byte of bytes) value = value * 256n + BigInt(byte);
  let result = '';
  while (value) {
    result = alphabet[Number(value % 58n)] + result;
    value /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    result = `1${result}`;
  }
  return result;
}

function checkFixtureBase64Transaction(entry, ordinal = 0) {
  assert.ok(Array.isArray(entry.transaction), 'GET transaction must be an encoded tuple');
  assert.equal(entry.transaction.length, 2);
  assert.equal(entry.transaction[1], 'base64');
  const wire = Buffer.from(entry.transaction[0], 'base64');
  assert.equal(wire.toString('base64'), entry.transaction[0], 'canonical Base64');
  // Independent Solana wire bytes for the genuine fixture made by build-slot-index.
  const expected = Buffer.concat([
    Buffer.from([1]), Buffer.alloc(64, 77 + ordinal),
    Buffer.from([1, 0, 1, 2]), Buffer.alloc(32, 42), Buffer.alloc(32, 43),
    Buffer.alloc(32, 10 + ordinal), Buffer.from([1, 1, 1, 0, 3, 1, 2, 3]),
  ]);
  assert.deepEqual(wire, expected, 'full signed transaction wire bytes');
  assert.equal(entry.version, 'legacy');
}

function unsignedLeb128(bytes, cursor) {
  let value = 0n;
  for (let shift = 0n; shift < 70n; shift += 7n) {
    assert.ok(cursor.offset < bytes.length, 'truncated Wincode integer');
    const byte = bytes[cursor.offset++];
    value |= BigInt(byte & 127) << shift;
    if (!(byte & 128)) {
      assert.ok(value <= BigInt(Number.MAX_SAFE_INTEGER), 'Wincode integer exceeds safe test range');
      return Number(value);
    }
  }
  assert.fail('oversized Wincode integer');
}

function byteVector(bytes, cursor) {
  const length = unsignedLeb128(bytes, cursor);
  assert.ok(cursor.offset + length <= bytes.length, 'truncated Wincode vector');
  const value = bytes.subarray(cursor.offset, cursor.offset + length);
  cursor.offset += length;
  return value;
}

function checkBinaryBundle(bytes, withAccess, expectedCompressed, expectedEncoding = 1) {
  const cursor = { offset: 0 };
  assert.equal(unsignedLeb128(bytes, cursor), 1, 'bundle version');
  assert.equal(unsignedLeb128(bytes, cursor), FIRST_SLOT, 'binary slot');
  assert.equal(bytes[cursor.offset++], expectedEncoding, 'hot block encoding');
  const hot = byteVector(bytes, cursor);
  if (expectedEncoding === 1) {
    assert.deepEqual(hot, expectedCompressed, 'compressed block must remain exact');
  } else {
    const hotCursor = { offset: 0 };
    assert.equal(unsignedLeb128(hot, hotCursor), FIRST_SLOT, 'normalized hot block slot');
    assert.equal(unsignedLeb128(hot, hotCursor), 431_999, 'normalized hot block parent');
  }
  assert.equal(bytes[cursor.offset++], 0, 'access encoding must be Wincode');
  assert.equal(bytes[cursor.offset++], withAccess ? 1 : 0, 'access option tag');
  if (withAccess) {
    const access = byteVector(bytes, cursor);
    const accessCursor = { offset: 0 };
    assert.equal(unsignedLeb128(access, accessCursor), 2, 'access version');
    assert.equal(unsignedLeb128(access, accessCursor), 0, 'access flags');
    assert.deepEqual(access.subarray(accessCursor.offset, accessCursor.offset + 32), Buffer.alloc(32, 11));
    accessCursor.offset += 32;
    assert.deepEqual(access.subarray(accessCursor.offset, accessCursor.offset + 32), Buffer.alloc(32, 10));
  }
  assert.equal(cursor.offset, bytes.length, 'bundle must have no trailing bytes');
}

function checkPrivateResponse(response) {
  assert.equal(response.headers.get('Cache-Control'), 'private, no-store');
  assert.ok(!response.headers.get('Vary')?.toLowerCase().includes('authorization'));
  assert.ok(['HIT', 'MISS', 'BYPASS'].includes(response.headers.get('X-Blockzilla-Cache')));
  assert.ok(['0', '1'].includes(response.headers.get('X-Blockzilla-Billable-Reads')));
}

async function requireFile(path) {
  return (await stat(path).catch(() => undefined))?.isFile() ?? false;
}

async function putFixtureObject(bucket, key, bytes) {
  const partBytes = 8 * 1024 * 1024;
  if (bytes.length <= partBytes) return bucket.put(key, bytes);
  // Keep local proxy transfers bounded for the 55 MB dense-index fixture.
  const upload = await bucket.createMultipartUpload(key);
  try {
    const parts = [];
    for (let offset = 0, partNumber = 1; offset < bytes.length; offset += partBytes, partNumber += 1) {
      parts.push(await upload.uploadPart(partNumber,
        bytes.subarray(offset, Math.min(offset + partBytes, bytes.length))));
    }
    return await upload.complete(parts);
  } catch (error) {
    await upload.abort().catch(() => undefined);
    throw error;
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { console.log(usage()); return; }
  const suppliedFixture = args.fixture ?? process.env.BLOCKZILLA_WORKER_FIXTURE_DIR;
  if (!suppliedFixture) throw new Error('Set BLOCKZILLA_WORKER_FIXTURE_DIR or use --fixture.');
  let fixture = resolve(suppliedFixture);
  if (!await requireFile(join(fixture, 'archive-v2-blocks.index'))) fixture = join(fixture, 'epoch-1');
  if (!await requireFile(join(fixture, 'archive-v2-blocks.index'))) throw new Error('The fixture has no epoch-1 compact index.');
  const build = resolve(args.build ?? join(PACKAGE_ROOT, 'build/index.js'));
  if (!await requireFile(build)) throw new Error('Build the Worker first with npm run build.');
  const compatibilityDate = args['compatibility-date'] ?? '2026-09-10';
  if (!/^\d{4}-\d{2}-\d{2}$/.test(compatibilityDate)) throw new Error('Invalid test compatibility date.');
  const currentMarker = await readFile(join(fixture, CURRENT_MARKER));
  const originalIndex = await readFile(join(fixture, 'archive-v2-blocks.index'));
  const blocks = await readFile(join(fixture, 'archive-v2-blocks.zstd'));
  const firstOffset = Number(originalIndex.readBigUInt64LE(36 + 12));
  const firstLength = originalIndex.readUInt32LE(36 + 20);
  const expectedCompressed = blocks.subarray(firstOffset, firstOffset + firstLength);
  const temporary = await mkdtemp(join(tmpdir(), 'blockzilla-worker-test-'));
  let layout = 'sparse';
  let generation = 'local-test-v1';
  let binding = 'BZ_ARCHIVE_BUCKET';
  let authScope;
  const options = () => {
    const v4 = {
      modules: [
        { type: 'ESModule', path: build },
        { type: 'CompiledWasm', path: join(dirname(build), 'index_bg.wasm') },
      ],
      modulesRoot: dirname(build),
      name: 'blockzilla-get-block-test',
      compatibilityDate,
      resourcePersistencePath: join(temporary, 'storage'),
      telemetry: { enabled: false },
      bindings: {
        BZ_ARCHIVE_SOURCE: 'r2',
        BZ_ARCHIVE_LAYOUT: 'stored',
        BZ_ARCHIVE_PREFIX: ARCHIVE_PREFIX,
        BZ_ARCHIVE_GENERATION: generation,
        BZ_SLOT_INDEX: layout,
        BZ_R2_BUCKET_BINDING: binding,
        BZ_HTTP_GET_ONLY: 'true',
        ...(authScope ? { BZ_AUTH_CACHE_SCOPE: authScope } : {}),
      },
      kvNamespaces: { BZ_RPC_API_KEYS: 'test-api-keys' },
      // Both binding names read the same fixture store. Changing the selected
      // binding must still change the cache identity, without a second 55 MB copy.
      r2Buckets: { BZ_ARCHIVE_BUCKET: 'test-archive', BZ_OTHER_BUCKET: 'test-archive' },
      analyticsEngineDatasets: { BZ_RPC_METRICS: { dataset: 'blockzilla_rpc_metrics_test' } },
    };
    return typeof miniflare.convertV4MiniflareOptions === 'function'
      ? miniflare.convertV4MiniflareOptions(v4) : v4;
  };
  const mf = new miniflare.Miniflare(options());
  console.log(`Testing the release WASM with local compatibility date ${compatibilityDate}.`);
  const request = (path, key = KEY_A, init = {}) => mf.dispatchFetch(`${ORIGIN}${path}`, {
    ...init, headers: { ...(key ? { Authorization: `Bearer ${key}` } : {}), ...init.headers },
  });
  const getJson = async (path, key = KEY_A) => {
    const response = await request(path, key);
    const body = await response.json();
    return { response, body };
  };
  const assertEnvelope = (body) => {
    assert.equal(body.jsonrpc, '2.0');
    assert.equal(body.id, 1);
  };
  const expectHit = async (path, key = KEY_A) => {
    for (let attempt = 0; attempt < 20; attempt += 1) {
      const response = await request(path, key);
      const bytes = Buffer.from(await response.arrayBuffer());
      assert.equal(response.status, 200);
      if (response.headers.get('X-Blockzilla-Cache') === 'HIT') {
        checkPrivateResponse(response);
        assert.equal(response.headers.get('X-Blockzilla-Billable-Reads'), '0');
        for (const backend of ['R2', 'S3']) {
          for (const field of ['Reads', 'GETs', 'HEADs', 'Bytes']) {
            assert.equal(response.headers.get(`X-Blockzilla-${backend}-${field}`), '0');
          }
        }
        return { response, bytes };
      }
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 10));
    }
    assert.fail(`no response cache hit for ${path}`);
  };
  const update = async (changes) => {
    ({ layout = layout, generation = generation, binding = binding, authScope = authScope } = changes);
    await mf.setOptions(options());
  };
  const objectKey = (name) => `${ARCHIVE_PREFIX}/epoch-1/${name}`;
  try {
    console.log('Preparing the local R2 fixture store.');
    const fixtureBucket = await mf.getR2Bucket('BZ_ARCHIVE_BUCKET');
    for (const entry of await readdir(fixture, { withFileTypes: true })) {
      if (entry.isFile()) await putFixtureObject(fixtureBucket, objectKey(entry.name), await readFile(join(fixture, entry.name)));
      if (entry.name === 'archive-v2-slot-offsets.v1.index') console.log('Stored the local dense index fixture.');
    }
    console.log('Prepared the local R2 fixture store.');
    const kv = await mf.getKVNamespace('BZ_RPC_API_KEYS');
    const record = (id, status = 'enabled') => JSON.stringify({
      keyId: `key_${id}`, customerId: `customer_${id}`, label: `Local test ${id}`, status,
    });
    const digest = (key) => createHash('sha256').update(key).digest('hex');
    await kv.put(digest(KEY_A), record('a'));
    await kv.put(digest(KEY_B), record('b'));

    const post = await request('/', undefined, { method: 'POST', body: '{}' });
    // This baseline sets BZ_HTTP_GET_ONLY=true. The transaction harness tests
    // the separate POST-enabled configuration.
    assert.equal(post.status, 405);
    assert.equal(post.headers.get('Allow'), 'GET');
    await post.arrayBuffer();
    for (const method of ['PUT', 'DELETE', 'HEAD']) {
      const response = await request('/block/432000.json', undefined, { method });
      assert.equal(response.status, 405);
      assert.equal(response.headers.get('Allow'), 'GET');
      await response.arrayBuffer();
    }
    let result = await getJson('/block/432000.json', null);
    assert.equal(result.response.status, 401);
    assertEnvelope(result.body);
    assert.ok(result.body.error);
    console.log('Passed GET-only routing and JSON authentication errors.');

    for (const selectedLayout of ['sparse', 'dense']) {
      if (layout !== selectedLayout) await update({ layout: selectedLayout });
      const path = `/block/${FIRST_SLOT}.json?rewards=false`;
      result = await getJson(path);
      assert.equal(result.response.status, 200, JSON.stringify(result.body));
      assert.equal(result.response.headers.get('X-Blockzilla-Cache'), 'MISS');
      checkPrivateResponse(result.response);
      assertEnvelope(result.body);
      assert.equal(result.body.result.blockhash, base58(Buffer.alloc(32, 11)));
      assert.equal(result.body.result.previousBlockhash, base58(Buffer.alloc(32, 10)));
      assert.equal(result.body.result.parentSlot, 431_999);
      assert.equal(Object.hasOwn(result.body.result, 'rewards'), false);
      assert.equal(Object.hasOwn(result.body.result, 'numRewardPartitions'), false);
      assert.equal(result.body.result.transactions.length, 1);
      assert.equal(result.body.result.transactions[0].meta.fee, 5_000);
      assert.equal(result.body.result.transactions[0].meta.err, null);
      checkFixtureBase64Transaction(result.body.result.transactions[0]);
      const explicitBase64 = await getJson(`${path}&encoding=base64`);
      assert.equal(explicitBase64.response.status, 200);
      assert.deepEqual(explicitBase64.body.result, result.body.result);
      await expectHit(path);
      const shared = await expectHit(path, KEY_B);
      assert.equal(JSON.parse(shared.bytes).result.blockhash, result.body.result.blockhash);
      const unauthorized = await getJson(path, 'bz_live_unknown_key_abcdefghijklmnopqrstuvwxyz0123456789');
      assert.equal(unauthorized.response.status, 401);
      assertEnvelope(unauthorized.body);

      const binary = await request(`/block/${FIRST_SLOT}.bin`);
      assert.equal(binary.status, 200);
      assert.equal(binary.headers.get('X-Blockzilla-Cache'), 'MISS');
      checkPrivateResponse(binary);
      checkBinaryBundle(Buffer.from(await binary.arrayBuffer()), true, expectedCompressed);
      await expectHit(`/block/${FIRST_SLOT}.bin`);
      const noAccess = await request(`/block/${FIRST_SLOT}.bin?access=0`);
      assert.equal(noAccess.status, 200);
      assert.equal(noAccess.headers.get('X-Blockzilla-Cache'), 'MISS');
      checkBinaryBundle(Buffer.from(await noAccess.arrayBuffer()), false, expectedCompressed);
      await expectHit(`/block/${FIRST_SLOT}.bin?access=0`);

      const rewards = await getJson(`/block/${FIRST_SLOT}.json?rewards=true`);
      assert.equal(rewards.response.status, 200);
      assert.equal(rewards.response.headers.get('X-Blockzilla-Cache'), 'MISS');
      assert.ok(rewards.body.result.rewards.length > 0);
      assert.equal(rewards.body.result.numRewardPartitions, 1);
      result = await getJson('/block/432002.json?rewards=false');
      assert.equal(result.response.status, 200, JSON.stringify(result.body));
      assert.equal(result.body.result.blockhash, base58(Buffer.alloc(32, 12)));
      assert.equal(result.body.result.previousBlockhash, base58(Buffer.alloc(32, 11)));
      assert.equal(result.body.result.parentSlot, FIRST_SLOT);
      assert.equal(result.body.result.transactions[0].meta.err, 'InsufficientFundsForFee');
      checkFixtureBase64Transaction(result.body.result.transactions[0], 1);
      for (let attempt = 0; attempt < 2; attempt += 1) {
        const missing = await getJson('/block/432001.json');
        assert.equal(missing.response.status, 200);
        assertEnvelope(missing.body);
        assert.equal(missing.body.result, null);
        assert.notEqual(missing.response.headers.get('X-Blockzilla-Cache'), 'HIT');
      }
      for (const invalidPath of ['/block/not-a-slot.json', '/block/432000.json?rewards=invalid',
        ...['json', 'base58', 'jsonParsed', 'invalid'].map(encoding => `/block/432000.json?encoding=${encoding}`)]) {
        const invalid = await getJson(invalidPath);
        assert.equal(invalid.response.status, 400);
        assertEnvelope(invalid.body);
        assert.equal(invalid.body.error.code, -32602);
        assert.equal(invalid.response.headers.get('X-Blockzilla-Billable-Reads'), '0');
        for (const backend of ['R2', 'S3']) {
          for (const field of ['Reads', 'GETs', 'HEADs', 'Bytes']) {
            assert.equal(invalid.response.headers.get(`X-Blockzilla-${backend}-${field}`), '0');
          }
        }
      }
      console.log(`Passed ${selectedLayout} reads, failed transaction data, missing slots, and shared cache isolation.`);
    }

    const path = `/block/${FIRST_SLOT}.json?rewards=false`;
    // Prove that the shared cache is retained when the isolate restarts.
    await update({ generation });
    result = await getJson(path);
    assert.equal(result.response.headers.get('X-Blockzilla-Cache'), 'HIT');
    await update({ generation: 'local-test-v2' });
    result = await getJson(path);
    assert.equal(result.response.status, 200);
    assert.equal(result.response.headers.get('X-Blockzilla-Cache'), 'MISS');
    await expectHit(path);
    await update({ binding: 'BZ_OTHER_BUCKET' });
    result = await getJson(path);
    assert.equal(result.response.status, 200);
    assert.equal(result.response.headers.get('X-Blockzilla-Cache'), 'MISS');
    await expectHit(path);
    await (await mf.getKVNamespace('BZ_RPC_API_KEYS')).put(digest(KEY_A), record('a', 'disabled'));
    result = await getJson(path);
    assert.equal(result.response.status, 401, 'a shared response must not bypass key revocation');
    await (await mf.getKVNamespace('BZ_RPC_API_KEYS')).put(digest(KEY_A), record('a'));
    console.log('Passed source generation changes, binding changes, and uncached authentication before cache hits.');

    await update({ authScope: 'local-worker-auth-scope-v1' });
    const authReceipt = (response, state, reads) => {
      assert.equal(response.headers.get('X-Blockzilla-Auth-Cache'), state);
      assert.equal(response.headers.get('X-Blockzilla-Auth-KV-Reads'), String(reads));
    };
    result = await getJson(path); assert.equal(result.response.status, 200); authReceipt(result.response, 'MISS', 1);
    result = await getJson(path); assert.equal(result.response.status, 200); authReceipt(result.response, 'HIT', 0);
    const failedKey = 'bz_live_initially_missing_local_auth_key_abcdefghijklmnopqrstuvwxyz012345';
    result = await getJson(path, failedKey); assert.equal(result.response.status, 401);
    await (await mf.getKVNamespace('BZ_RPC_API_KEYS')).put(digest(failedKey), record('new'));
    result = await getJson(path, failedKey); assert.equal(result.response.status, 200); authReceipt(result.response, 'MISS', 1);
    const freshCold = await getJson(`${path}&profile=1`, KEY_B);
    assert.equal(freshCold.response.status, 200); authReceipt(freshCold.response, 'BYPASS', 1);
    const afterCold = await getJson(path, KEY_B);
    assert.equal(afterCold.response.status, 200); authReceipt(afterCold.response, 'MISS', 1);
    result = await getJson(path, KEY_B); authReceipt(result.response, 'HIT', 0);
    // This is the additional isolate-cache delay after KV has observed a record.
    // It does not establish a five-second global KV propagation guarantee.
    await (await mf.getKVNamespace('BZ_RPC_API_KEYS')).put(digest(KEY_A), record('a', 'disabled'));
    result = await getJson(path); assert.equal(result.response.status, 200); authReceipt(result.response, 'HIT', 0);
    const coldRevoked = await getJson(`${path}&profile=1`);
    assert.equal(coldRevoked.response.status, 401, 'fully cold checks must bypass a positive auth entry');
    await new Promise(done => setTimeout(done, 5_100));
    result = await getJson(path); assert.equal(result.response.status, 401, 'positive auth entry expires within five seconds');
    await (await mf.getKVNamespace('BZ_RPC_API_KEYS')).put(digest(KEY_A), record('a'));
    result = await getJson(path); assert.equal(result.response.status, 200); authReceipt(result.response, 'MISS', 1);
    console.log('Passed bounded positive auth reuse, five-second expiry, cold bypass/no population, and uncached failures.');

    const putObject = async (name, value) => (await mf.getR2Bucket(binding)).put(objectKey(name), value);
    const deleteObject = async (name) => (await mf.getR2Bucket(binding)).delete(objectKey(name));
    await putObject(CURRENT_MARKER, Buffer.alloc(currentMarker.length, 120));
    await update({ generation: 'local-test-corrupt-marker' });
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const invalid = await getJson(path);
      assert.equal(invalid.response.status, 502);
      assertEnvelope(invalid.body);
      assert.ok(invalid.body.error);
      assert.notEqual(invalid.response.headers.get('X-Blockzilla-Cache'), 'HIT');
    }
    await putObject(CURRENT_MARKER, currentMarker);
    await putObject(MAY24_MARKER, MAY24_MARKER_BYTES);
    await update({ generation: 'local-test-conflicting-markers' });
    result = await getJson(path);
    assert.equal(result.response.status, 502);
    assertEnvelope(result.body);
    await deleteObject(CURRENT_MARKER);
    await putObject(LEGACY_METADATA_MARKER, LEGACY_METADATA_MARKER_BYTES);
    await update({ generation: 'local-test-historical-markers' });
    result = await getJson(path);
    assert.equal(result.response.status, 200, JSON.stringify(result.body));
    assert.equal(result.body.result.blockhash, base58(Buffer.alloc(32, 11)));
    checkFixtureBase64Transaction(result.body.result.transactions[0]);
    const historicalBinary = await request(`/block/${FIRST_SLOT}.bin`);
    assert.equal(historicalBinary.status, 200);
    checkBinaryBundle(Buffer.from(await historicalBinary.arrayBuffer()), true, undefined, 0);
    const historicalNoAccess = await request(`/block/${FIRST_SLOT}.bin?access=0`);
    assert.equal(historicalNoAccess.status, 200);
    checkBinaryBundle(Buffer.from(await historicalNoAccess.arrayBuffer()), false, expectedCompressed);
    console.log('Passed corrupt/conflicting marker rejection and explicit historical schema selection.');
    console.log('All Worker integration checks passed. Cloud storage and production services were not used.');
  } finally {
    try { await mf.dispose(); }
    finally { await rm(temporary, { recursive: true, force: true }); }
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack : String(error));
  process.exitCode = 1;
});
