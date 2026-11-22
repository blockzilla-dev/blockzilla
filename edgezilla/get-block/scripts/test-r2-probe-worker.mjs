#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { createFoundationFirstHarness } from './test-foundation-first-worker.mjs';

const { values } = parseArgs({ options: { build: { type: 'string' }, receipt: { type: 'string' } } });
assert.ok(values.build, '--build is required');
const h = await createFoundationFirstHarness(values.build), checks = [];
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const read = async (slot, query = 'profile=1&r2_probe=1') => {
  const response = await h.request(`/block/${slot}.bin?${query}`);
  return { status: response.status, headers: Object.fromEntries(response.headers), body: await response.json() };
};
const noReads = async () => {
  const stats = await h.stats();
  assert.equal(stats.events.filter(e => e.kind === 'source_get').length, 0);
  assert.equal(stats.broker.events.length, 0);
};
try {
  const slot = h.slots[0];
  await h.control('resolve-normal');
  assert.equal((await read(slot)).status, 404); await noReads(); checks.push('disabled diagnostic makes no backend call');
  await h.control('resolve-normal', { probeEnabled: true });
  assert.equal((await read(slot, 'r2_probe=1')).status, 404); await noReads(); checks.push('diagnostic requires cache-bypass profile');
  const bad = await h.request(`/block/${slot}.json?profile=1&r2_probe=1`);
  assert.equal(bad.status, 404); await noReads(); checks.push('diagnostic requires binary route');
  for (const spec of h.specs) {
    await h.control('resolve-normal', { probeEnabled: true });
    const result = await read(spec.slot);
    assert.equal(result.status, 200, JSON.stringify(result));
    assert.equal(result.headers['x-blockzilla-body'], 'native-r2-probe');
    assert.equal(result.headers['x-blockzilla-r2-gets'], '2');
    assert.equal(result.headers['x-blockzilla-r2-heads'], '0');
    assert.equal(result.headers['x-blockzilla-foundation-lookup-http-requests'], '1');
    assert.equal(result.headers['x-blockzilla-foundation-resolve-http-requests'], '0');
    assert.equal(result.body.parallel, true); assert.equal(result.body.rangeCache, false);
    for (const range of result.body.ranges) {
      const window = spec.windows.find(w => w.file === (range.kind === 'hot' ? 'archive-v2-blocks.zstd' : 'signatures.bin'));
      assert.ok(window, `Missing ${range.kind} test window`);
      assert.equal(range.expectedBytes, window.bytes.length); assert.equal(range.receivedBytes, window.bytes.length);
      assert.equal(range.sha256, sha(window.bytes));
      assert.equal(range.connectionMs, null); assert.equal(range.connectionReuse, null);
      assert.ok(range.headersMs >= 0 && range.firstChunkMs >= range.headersMs && range.totalMs >= range.firstChunkMs);
      assert.ok(Math.abs(range.bodyMs - (range.totalMs - range.headersMs)) < 0.001);
      assert.ok(Math.abs(range.transferMs - (range.totalMs - range.firstChunkMs)) < 0.001);
    }
    const stats = await h.stats(); assert.equal(stats.maximum, 2);
    assert.equal(stats.broker.events.length, 1); assert.equal(stats.broker.events[0].method, 'GET');
    assert.equal(stats.events.filter(e => e.kind === 'resolution_get').length, 0);
    checks.push(`slot ${spec.slot}: exact concurrent native ranges and bounded timing`);
  }
  for (const fault of ['short', 'long', 'error', 'stall']) {
    await h.control('resolve-source-' + fault, { probeEnabled: true, rawBinary: true });
    const result = await read(slot); assert.equal(result.status, 502);
    assert.equal(result.headers['x-blockzilla-r2-gets'], '2');
    assert.equal(result.headers['x-blockzilla-foundation-resolve-http-requests'], '0');
    checks.push(`source ${fault}: rejected without retry or resolver call`);
  }
  const report = { status: 'PASS', artifact: h.artifact, checks,
    scope: 'Actual release WASM with original four block ranges in local runtime; no hosted latency claim.' };
  if (values.receipt) { const path = resolve(values.receipt); await mkdir(dirname(path), { recursive: true }); await writeFile(path, JSON.stringify(report, null, 2) + '\n'); }
  console.log(JSON.stringify(report));
} finally { await h.close(); }
