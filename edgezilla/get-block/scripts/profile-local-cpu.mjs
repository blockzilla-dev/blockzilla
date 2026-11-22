#!/usr/bin/env node
// Capture the local application Worker through Miniflare's supported inspector.
// This does not build, deploy, or make a production request.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { createLocalWorkerHarness } from './profile-local-worker.mjs';

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const REPOSITORY = resolve(PACKAGE_ROOT, '../..');

function options(argv) {
  const { values } = parseArgs({ args: argv, options: {
    fixture: { type: 'string', default: '/tmp/blockzilla-resolution-real-slot-fixture-20261121' },
    build: { type: 'string', default: join(PACKAGE_ROOT, 'build/index.js') },
    iterations: { type: 'string', default: '20' },
    warmup: { type: 'string', default: '2' },
    profile: { type: 'string', default: join(REPOSITORY, 'reports/get-block-local-profile-20261121/worker-base64-local-r2.cpuprofile') },
    receipt: { type: 'string', default: join(REPOSITORY, 'reports/get-block-local-profile-20261121/worker-base64-local-r2-cpu.json') },
    buffered: { type: 'boolean', default: false },
    help: { type: 'boolean', default: false },
  } });
  values.iterations = Number(values.iterations);
  values.warmup = Number(values.warmup);
  assert.ok(Number.isInteger(values.iterations) && values.iterations >= 1 && values.iterations <= 30, 'Use 1–30 iterations.');
  assert.ok(Number.isInteger(values.warmup) && values.warmup >= 0 && values.warmup <= 5, 'Use 0–5 warmup reads.');
  return values;
}

export async function connectInspector(mf, workerName = 'blockzilla-get-block-local-profile') {
  const base = new URL(await mf.getInspectorURL());
  assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(base.hostname), 'Inspector must be local.');
  base.protocol = 'http:';
  base.pathname = '/json/list';
  const response = await fetch(base, { signal: AbortSignal.timeout(10_000) });
  assert.ok(response.ok, `Inspector target listing returned HTTP ${response.status}.`);
  const targets = await response.json();
  const candidates = targets.filter(target => typeof target.webSocketDebuggerUrl === 'string'
    && (target.title?.includes(workerName)
      || new URL(target.webSocketDebuggerUrl).pathname === `/${workerName}`));
  assert.equal(candidates.length, 1, `Expected one application Worker target, found ${candidates.length}.`);
  const target = candidates[0];
  const socket = new WebSocket(target.webSocketDebuggerUrl);
  const pending = new Map();
  let nextId = 1;
  const rejectPending = error => {
    for (const item of pending.values()) { clearTimeout(item.timer); item.reject(error); }
    pending.clear();
  };
  socket.addEventListener('message', event => {
    const value = JSON.parse(event.data);
    if (!value.id || !pending.has(value.id)) return;
    const item = pending.get(value.id);
    pending.delete(value.id);
    clearTimeout(item.timer);
    if (value.error) item.reject(new Error(`${item.method}: ${value.error.code} ${value.error.message}`));
    else item.resolve(value.result ?? {});
  });
  socket.addEventListener('close', () => rejectPending(new Error('Inspector socket closed.')));
  socket.addEventListener('error', () => rejectPending(new Error('Inspector socket failed.')));
  await new Promise((resolveOpen, rejectOpen) => {
    const timer = setTimeout(() => rejectOpen(new Error('Inspector connection timed out.')), 10_000);
    socket.addEventListener('open', () => { clearTimeout(timer); resolveOpen(); }, { once: true });
    socket.addEventListener('error', () => { clearTimeout(timer); rejectOpen(new Error('Inspector connection failed.')); }, { once: true });
  });
  return {
    target: { title: target.title, type: target.type, description: target.description },
    command(method, params = {}) {
      const id = nextId++;
      return new Promise((resolveCommand, rejectCommand) => {
        const timer = setTimeout(() => { pending.delete(id); rejectCommand(new Error(`${method} timed out.`)); }, 15_000);
        pending.set(id, { method, timer, resolve: resolveCommand, reject: rejectCommand });
        socket.send(JSON.stringify({ id, method, params }));
      });
    },
    close() { socket.close(); rejectPending(new Error('Inspector capture completed.')); },
  };
}

export function attribution(profile) {
  const nodes = new Map(profile.nodes.map(node => [node.id, node]));
  const parent = new Map();
  for (const node of nodes.values()) for (const id of node.children ?? []) parent.set(id, node.id);
  const leaves = new Map();
  const inclusive = new Map();
  const categories = { wasm: 0, javascript: 0, idle: 0, garbageCollector: 0, program: 0, other: 0 };
  let sampledUs = 0;
  const key = node => `${node.callFrame.functionName || '(anonymous)'}\t${node.callFrame.url || ''}`;
  for (let index = 0; index < (profile.samples ?? []).length; index += 1) {
    const node = nodes.get(profile.samples[index]);
    const weight = profile.timeDeltas?.[index] ?? 0;
    if (!node) continue;
    sampledUs += weight;
    const frame = node.callFrame;
    const category = frame.functionName === '(idle)' ? 'idle'
      : frame.functionName === '(garbage collector)' ? 'garbageCollector'
      : frame.functionName === '(program)' ? 'program'
      : frame.url.startsWith('wasm:') || /wasm-function|\$func\d/.test(frame.functionName) ? 'wasm'
      : frame.url ? 'javascript' : 'other';
    categories[category] += weight;
    leaves.set(key(node), (leaves.get(key(node)) ?? 0) + weight);
    let current = node;
    const seen = new Set();
    while (current && !seen.has(current.id)) {
      seen.add(current.id);
      inclusive.set(key(current), (inclusive.get(key(current)) ?? 0) + weight);
      current = nodes.get(parent.get(current.id));
    }
  }
  const activeUs = sampledUs - categories.idle;
  const top = values => [...values].sort((a,b) => b[1]-a[1]).slice(0,30).map(([name, us]) => {
    const [functionName, url] = name.split('\t');
    return { functionName, url, sampledMs: us / 1000, percentOfTrace: sampledUs ? us * 100 / sampledUs : 0 };
  });
  const wasm = profile.nodes.filter(node => node.callFrame.url.startsWith('wasm:'));
  return {
    samples: profile.samples?.length ?? 0,
    traceDurationMs: (profile.endTime - profile.startTime) / 1000,
    sampledDurationMs: sampledUs / 1000,
    sampledActiveMs: activeUs / 1000,
    categoriesMs: Object.fromEntries(Object.entries(categories).map(([name,us])=>[name,us/1000])),
    wasmNodes: wasm.length,
    numericWasmNodes: wasm.filter(node => /wasm-function|\$func\d/.test(node.callFrame.functionName)).length,
    topLeaves: top(leaves),
    topInclusive: top(inclusive),
    interpretation: 'Sample-weighted local trace time. This is not production CPU time or billable CPU. Release WASM can lack Rust names.',
  };
}

async function main() {
  const args = options(process.argv.slice(2));
  if (args.help) {
    console.log('Usage: node scripts/profile-local-cpu.mjs [--fixture DIR] [--build build/index.js] [--iterations 1..30] [--warmup 0..5] [--buffered] [--profile FILE.cpuprofile] [--receipt FILE.json]');
    return;
  }
  const result = {
    schema: 'blockzilla-local-release-wasm-cpu-v1', startedAt: new Date().toISOString(),
    status: 'RUNNING', scope: 'Local Miniflare application Worker, real slot, local R2, profile cache bypass; no production or external archive calls.',
    representation: 'base64-json', body: args.buffered ? 'buffered' : 'stream', warmup: args.warmup,
    iterations: args.iterations, samplingIntervalUs: 1000, nodeVersion: process.version,
  };
  let harness;
  let inspector;
  try {
    const wasm = await readFile(join(dirname(resolve(args.build)), 'index_bg.wasm'));
    result.wasmSha256 = createHash('sha256').update(wasm).digest('hex');
    harness = await createLocalWorkerHarness({ fixture: resolve(args.fixture), build: resolve(args.build), backend: 'r2', delayMs: 0, inspectorPort: 0 });
    for (let index = 0; index < args.warmup; index += 1) await harness.read('json', { profile: true, buffered: args.buffered });
    inspector = await connectInspector(harness.mf);
    result.inspectorTarget = inspector.target;
    await inspector.command('Profiler.enable');
    await inspector.command('Profiler.setSamplingInterval', { interval: result.samplingIntervalUs });
    await inspector.command('Profiler.start');
    result.reads = [];
    for (let index = 0; index < args.iterations; index += 1) {
      const read = await harness.read('json', { profile: true, buffered: args.buffered });
      result.reads.push({ status: read.status, bytes: read.bytes, headersMs: read.headersMs, totalMs: read.totalMs });
    }
    const { profile } = await inspector.command('Profiler.stop');
    assert.ok(profile?.nodes?.length && profile.samples?.length, 'Inspector returned no sampled CPU stacks.');
    await inspector.command('Profiler.disable');
    await mkdir(dirname(resolve(args.profile)), { recursive: true });
    await writeFile(resolve(args.profile), `${JSON.stringify(profile)}\n`, { flag: 'wx' });
    result.profile = resolve(args.profile);
    result.attribution = attribution(profile);
    result.status = 'SUCCESS';
  } catch (error) {
    result.status = 'UNAVAILABLE';
    result.error = String(error.message ?? error).slice(0, 1000);
    process.exitCode = 1;
  } finally {
    inspector?.close();
    await harness?.close();
  }
  result.completedAt = new Date().toISOString();
  await mkdir(dirname(resolve(args.receipt)), { recursive: true });
  await writeFile(resolve(args.receipt), `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx' });
  console.log(JSON.stringify({ status: result.status, error: result.error, profile: result.profile,
    receipt: resolve(args.receipt), samples: result.attribution?.samples,
    traceDurationMs: result.attribution?.traceDurationMs,
    topLeaves: result.attribution?.topLeaves.slice(0, 6) }));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
