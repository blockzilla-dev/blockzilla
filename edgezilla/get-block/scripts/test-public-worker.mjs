#!/usr/bin/env node
// Real release-WASM requests, with no customer KV or billing binding available.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { createFoundationFirstHarness } from './test-foundation-first-worker.mjs';
import { canonicalBlockDigest } from './bench-get-block.mjs';

const ORIGIN = 'https://foundation-owner.test';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const checks = [];

async function main() {
  const { values } = parseArgs({ options: {
    build: { type: 'string' }, receipt: { type: 'string' },
  } });
  assert.ok(values.build && values.receipt, '--build and --receipt are required');
  const h = await createFoundationFirstHarness(values.build, {
    ownerBindings: { BZ_GET_BLOCK_PUBLIC: 'true', BZ_HTTP_GET_ONLY: 'false' },
    ownerTransform: text => text.replace('new worker(ctx,{...env,...lookup,',
      'new worker(ctx,{...env,...lookup,BZ_RPC_API_KEYS:undefined,BZ_RPC_METRICS:undefined,'),
  });
  const request = (path, headers) => h.mf.dispatchFetch(ORIGIN + path, { headers });
  try {
    const slot = h.slots[0], spec = h.specs[0];
    const identities = [undefined, { Authorization: 'Bearer invalid' },
      { Authorization: `Bearer bz_live_${randomBytes(32).toString('base64url')}` },
      { Authorization: `Bearer bz_live_${randomBytes(32).toString('base64url')}` }];
    for (const kind of ['json', 'bin']) {
      await h.control('complete', { rawBinary: true });
      for (const [index, headers] of identities.entries()) {
        const response = await request(`/block/${slot}.${kind}?rewards=false`, headers);
        const body = Buffer.from(await response.arrayBuffer());
        assert.equal(response.status, 200, body.toString().slice(0, 180));
        if (kind === 'json') assert.equal(canonicalBlockDigest(body.toString()), spec.referenceDigest);
        else assert.equal(sha(body), spec.bundleSha);
        assert.equal(response.headers.get('X-Blockzilla-Auth-KV-Reads'), '0');
        assert.equal(response.headers.get('X-Blockzilla-Billable-Reads'), '0');
        assert.equal(response.headers.get('Access-Control-Allow-Origin'), '*');
        assert.equal(response.headers.get('Access-Control-Expose-Headers'), '*');
        assert.match(response.headers.get('Cache-Control'), /^public,.*max-age=31536000/);
        checks.push({ name: `${kind}-public-identity-${index}`, status: response.status,
          cache: response.headers.get('X-Blockzilla-Cache') });
      }
      // Wait for the background fill, then verify the shared response path.
      let hit = false;
      for (let attempt = 0; attempt < 20 && !hit; attempt++) {
        const response = await request(`/block/${slot}.${kind}?rewards=false`);
        await response.arrayBuffer();
        hit = response.headers.get('X-Blockzilla-Cache') === 'HIT';
        if (!hit) await new Promise(done => setTimeout(done, 20));
      }
      assert.ok(hit, `${kind} shared response cache must remain available`);
      checks.push({ name: `${kind}-shared-cache-hit`, hit });
      const cacheIdentities = [...identities,
        { Authorization: 'Basic never-requested-before' },
        { Authorization: `Bearer bz_live_${randomBytes(32).toString('base64url')}` }];
      for (const [index, headers] of cacheIdentities.entries()) {
        const response = await request(`/block/${slot}.${kind}?rewards=false`, headers);
        const body = Buffer.from(await response.arrayBuffer());
        assert.equal(response.status, 200);
        assert.equal(response.headers.get('X-Blockzilla-Cache'), 'HIT');
        assert.equal(response.headers.get('X-Blockzilla-Foundation-Result'), 'RESPONSE_CACHE');
        assert.equal(response.headers.get('X-Blockzilla-Billable-Reads'), '0');
        if (kind === 'json') assert.equal(canonicalBlockDigest(body.toString()), spec.referenceDigest);
        else assert.equal(sha(body), spec.bundleSha);
        checks.push({ name: `${kind}-shared-hit-identity-${index}`, status: response.status });
      }
    }
    for (const [name, path, expected] of [
      ['bad-encoding', `/block/${slot}.json?encoding=base58`, 400],
      ['missing-compact-identity', `/block/${slot}.compact`, 400],
    ]) {
      const response = await request(path);
      await response.arrayBuffer();
      assert.equal(response.status, expected);
      assert.match(response.headers.get('Cache-Control'), /no-store/);
      assert.equal(response.headers.get('X-Blockzilla-Auth-KV-Reads'), '0');
      assert.equal(response.headers.get('X-Blockzilla-Billable-Reads'), '0');
      checks.push({ name, status: response.status });
    }
    await h.control('unavailable');
    for (let attempt = 0; attempt < 2; attempt++) {
      const response = await request(`/block/${slot}.bin`);
      await response.arrayBuffer();
      assert.equal(response.status, 404);
      assert.match(response.headers.get('Cache-Control'), /no-store/);
      assert.notEqual(response.headers.get('X-Blockzilla-Cache'), 'HIT');
      checks.push({ name: `unavailable-not-cached-${attempt}`, status: response.status });
    }
    const info = await request('/info');
    const description = await info.json();
    assert.deepEqual(description.public_get_block, { enabled: true, free: true });
    checks.push({ name: 'public-info', status: info.status });
    // These are separate APIs: the public getBlock switch must not unlock them.
    for (const [name, path, options] of [
      ['resolution-keeps-auth', `/block/${slot}.resolution`, {}],
      ['post-keeps-contract', '/', { method: 'POST', body: '{}' }],
    ]) {
      const response = await h.mf.dispatchFetch(ORIGIN + path, options);
      await response.arrayBuffer();
      assert.equal(response.status, 401, name);
      checks.push({ name, status: response.status });
    }
    const receipt = { state: 'PASS', checks, total: checks.length, artifact: h.artifact,
      scope: 'Local actual WASM; customer key and billing bindings removed from the request environment.' };
    await mkdir(dirname(resolve(values.receipt)), { recursive: true });
    await writeFile(values.receipt, JSON.stringify(receipt, null, 2) + '\n');
    console.log(JSON.stringify({ state: receipt.state, total: receipt.total }));
  } finally { await h.close(); }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
