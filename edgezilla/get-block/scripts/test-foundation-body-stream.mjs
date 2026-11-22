#!/usr/bin/env node
// Check the exact static native-stream helper, without any cloud request.
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const PACKAGE = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const { values } = parseArgs({ options: { receipt: { type: 'string' } } });
const source = await readFile(resolve(PACKAGE, 'src/worker/foundation_first.rs'), 'utf8');
const inline = source.match(/#\[wasm_bindgen\(inline_js = r#"([\s\S]*?)"#\)\]/)?.[1];
assert.ok(inline, 'static native helper is present');
const { bzFoundationDeadlineBody: bound } = await import(`data:text/javascript,${encodeURIComponent(inline)}`);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const checks = [];
const pass = name => { checks.push(name); console.log(`Passed ${name}.`); };
const bytes = async stream => new Uint8Array(await new Response(stream).arrayBuffer());

{
  const first = new Uint8Array([1, 2]), second = new Uint8Array([3, 4]);
  const input = new ReadableStream({ start(c) { c.enqueue(first); c.enqueue(second); c.close(); } });
  const controller = new AbortController();
  const reader = bound(input, 4, 100, controller).getReader();
  assert.equal((await reader.read()).value, first, 'forward the same native Uint8Array');
  assert.equal((await reader.read()).value, second);
  assert.equal((await reader.read()).done, true);
  assert.equal(controller.signal.aborted, false);
  pass('exact bytes use the original native chunks without a copy');
}

for (const [name, input, expected] of [
  ['short body', new ReadableStream({ start(c) { c.enqueue(new Uint8Array([1])); c.close(); } }), 2],
  ['long body', new ReadableStream({ start(c) { c.enqueue(new Uint8Array([1, 2])); c.close(); } }), 1],
  ['non-byte body', new ReadableStream({ start(c) { c.enqueue('bad'); c.close(); } }), 1],
]) {
  const controller = new AbortController();
  await assert.rejects(bytes(bound(input, expected, 100, controller)), /BZ_FOUNDATION_BODY_LENGTH/);
  assert.equal(controller.signal.aborted, true);
  pass(`${name} aborts before it can complete`);
}

{
  const controller = new AbortController();
  const input = new ReadableStream({ start(c) { c.error(new Error('upstream disconnected')); } });
  await assert.rejects(bytes(bound(input, 1, 100, controller)), /BZ_FOUNDATION_BODY_NETWORK/);
  assert.equal(controller.signal.aborted, true);
  pass('upstream disconnect has a transport-specific reason');
}

{
  let cancelled = false;
  const controller = new AbortController();
  const input = new ReadableStream({ pull() { return new Promise(() => {}); }, cancel() { cancelled = true; } });
  await assert.rejects(bytes(bound(input, 1, 30, controller)), /BZ_FOUNDATION_BODY_TIMEOUT/);
  await sleep(0);
  assert.equal(controller.signal.aborted, true);
  assert.equal(cancelled, true);
  pass('a pending upstream read times out and cancels the source');
}

{
  let next = 0;
  const input = new ReadableStream({ pull(c) { if (next < 2) c.enqueue(new Uint8Array([++next])); else c.close(); } }, { highWaterMark: 0 });
  const controller = new AbortController();
  const reader = bound(input, 2, 30, controller).getReader();
  await sleep(60);
  assert.deepEqual((await reader.read()).value, new Uint8Array([1]));
  await sleep(60);
  assert.deepEqual((await reader.read()).value, new Uint8Array([2]));
  assert.equal((await reader.read()).done, true);
  assert.equal(controller.signal.aborted, false);
  pass('client backpressure does not consume the upstream wait budget');
}

{
  let next = 0;
  const controller = new AbortController();
  const input = new ReadableStream({ async pull(c) { await sleep(25); c.enqueue(new Uint8Array([++next])); } }, { highWaterMark: 0 });
  await assert.rejects(bytes(bound(input, 3, 40, controller)), /BZ_FOUNDATION_BODY_TIMEOUT/);
  assert.equal(controller.signal.aborted, true);
  pass('cumulative upstream waits bound a slow drip response');
}

{
  let cancelled = false;
  const controller = new AbortController();
  const input = new ReadableStream({ cancel() { cancelled = true; } });
  await bound(input, 1, 100, controller).cancel('client closed');
  assert.equal(cancelled, true);
  assert.equal(controller.signal.aborted, true);
  pass('client cancellation aborts the lookup and releases the source');
}

{
  const controller = new AbortController();
  assert.throws(() => bound(null, 1, 100, controller), /BZ_FOUNDATION_BODY_CONFIG/);
  assert.throws(() => bound(new ReadableStream(), 0, 100, controller), /BZ_FOUNDATION_BODY_CONFIG/);
  assert.throws(() => bound(new ReadableStream(), 1, 10001, controller), /BZ_FOUNDATION_BODY_CONFIG/);
  pass('invalid stream, byte and timeout bounds are rejected');
}

const receipt = { status: 'PASS', checks, scope: 'Local Node native-stream helper tests; no actual-WASM or cloud latency claims.' };
if (values.receipt) {
  const path = resolve(values.receipt); await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(receipt, null, 2)}\n`);
}
console.log(JSON.stringify({ status: receipt.status, checks: checks.length }));
