#!/usr/bin/env node
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { createLocalWorkerHarness } from './profile-local-worker.mjs';

const { values } = parseArgs({ options: {
  fixture: { type: 'string' }, oracle: { type: 'string' },
  help: { type: 'boolean', default: false },
  build: { type: 'string', default: 'blockzilla/get-block/build/index.js' },
  output: { type: 'string', default: 'profile-output/local-native-reader.json' },
} });
if (values.help) {
  console.log('Usage: --fixture DIR --oracle FILE [--build FILE] [--output FILE]');
  process.exit(0);
}
assert.ok(values.fixture && values.oracle, 'Supply --fixture DIR and --oracle FILE.');
const report = { schema: 'blockzilla-owner-native-reader-local-v1', status: 'RUNNING',
  startedAt: new Date().toISOString(), scope: 'Actual public WASM and sibling JS reader with local R2; no cloud requests or data writes',
  checks: [], samples: [] };
const counter = (row, name) => Number(row.headers[name.toLowerCase()] ?? 0);
const sourceGets = row => counter(row, 'X-Blockzilla-Foundation-R2-GETs');
const assertNoS3 = row => assert.equal(counter(row, 'X-Blockzilla-S3-Reads'), 0);
const create = options => createLocalWorkerHarness({ fixture: resolve(values.fixture), oracle: resolve(values.oracle), build: resolve(values.build),
  backend: 'native-reader', ...options });

let harness;
try {
  harness = await create();
  report.artifact = harness.artifact;
  for (const kind of ['json', 'bin']) {
    const row = await harness.read(kind, { profile: true });
    assert.equal(row.headers['x-blockzilla-profile-mode'], 'full');
    assert.equal(row.headers['x-blockzilla-auth-cache'], 'BYPASS');
    assert.equal(counter(row, 'X-Blockzilla-Auth-KV-Reads'), 1);
    assert.equal(counter(row, 'X-Blockzilla-R2-GETs'), 1);
    assert.equal(sourceGets(row), 2);
    assert.equal(counter(row, 'X-Blockzilla-Reader-HTTP-Requests'), 2);
    assert.equal(row.headers['x-blockzilla-reader'], 'native-r2');
    assertNoS3(row);
    report.samples.push({ kind, phase: 'fully-cold', ...row });
  }
  report.checks.push('Full JSON oracle and exact binary bundle match through real Rust HMAC, JS WebCrypto, native R2 and streams');
  report.checks.push('Cold source proof: owner index GET1 plus confirmed Foundation GET2 and reader HTTP2, direct S3 zero');

  await harness.read('json', { profile: false });
  const source = await harness.read('json', { profile: 'source' });
  assert.equal(source.headers['x-blockzilla-profile-mode'], 'source');
  assert.equal(counter(source, 'X-Blockzilla-R2-GETs'), 0);
  assert.equal(sourceGets(source), 2);
  assert.equal(counter(source, 'X-Blockzilla-Reader-HTTP-Requests'), 2);
  assert.equal(source.headers['x-blockzilla-auth-cache'], 'HIT');
  assert.equal(counter(source, 'X-Blockzilla-Auth-KV-Reads'), 0);
  assertNoS3(source);
  report.samples.push({ kind: 'json', phase: 'source-only', ...source });
  report.checks.push('Source-only mode keeps index/auth and makes exactly two confirmed Foundation reads');

  const cached = await harness.read('json', { profile: false });
  assert.equal(cached.headers['x-blockzilla-cache'], 'HIT');
  assert.equal(counter(cached, 'X-Blockzilla-R2-Reads'), 0);
  assert.equal(sourceGets(cached), 0);
  assert.equal(counter(cached, 'X-Blockzilla-Reader-HTTP-Requests'), 0);
  assert.equal(cached.headers['x-blockzilla-reader'], 'none');
  assertNoS3(cached);
  report.samples.push({ kind: 'json', phase: 'response-hit', ...cached });
  report.checks.push('Complete response hits clear all source/reader counters');
  await harness.close(); harness = null;

  harness = await create({ nativeReaderSecret: 'wrong-owner-reader-secret-01234567890123456789012345' });
  let failed = false;
  try { await harness.read('json', { profile: true }); }
  catch (error) { failed = true; assert.match(error.message, /502/); }
  assert.ok(failed, 'Invalid private MAC must fail instead of using direct source R2 or S3');
  report.checks.push('Mismatched private secret fails closed with no direct-source fallback');
  report.status = 'PASSED';
} catch (error) {
  report.status = 'FAILED'; report.error = error.message; throw error;
} finally {
  if (harness) await harness.close();
  report.completedAt = new Date().toISOString();
  await mkdir(dirname(resolve(values.output)), { recursive: true });
  await writeFile(resolve(values.output), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify({ status: report.status, checks: report.checks.length }));
}
