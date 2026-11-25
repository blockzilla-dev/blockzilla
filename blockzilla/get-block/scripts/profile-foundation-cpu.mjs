#!/usr/bin/env node
// Local CPU only: actual Worker WASM, authenticated broker stub, exact windows.
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { createFoundationFirstHarness } from './test-foundation-first-worker.mjs';
import { connectInspector, attribution } from './profile-local-cpu.mjs';

const { values } = parseArgs({ options: {
  build: { type: 'string' }, output: { type: 'string' }, rounds: { type: 'string', default: '4' },
} });
assert.ok(values.build && values.output, 'Use --build and --output.');
const rounds = Number(values.rounds);
assert.ok(Number.isInteger(rounds) && rounds >= 1 && rounds <= 16);
const h = await createFoundationFirstHarness(values.build);
let inspector;
const rows = [];
try {
  // Tier startup is measured separately from these steady-runtime profiles.
  await h.control('not-cached');
  for (const slot of h.slots) { await h.read(slot, 'json'); await h.read(slot, 'bin'); }
  inspector = await connectInspector(h.mf, 'foundation-first-local-owner');
  await inspector.command('Profiler.enable');
  await inspector.command('Profiler.setSamplingInterval', { interval: 1000 });
  for (const kind of ['json', 'bin']) {
    for (const mode of ['not-cached', 'complete']) {
      await h.control(mode);
      await inspector.command('Profiler.start');
      const reads = [];
      for (let i = 0; i < rounds; ++i) for (const slot of h.slots) reads.push(await h.read(slot, kind));
      const { profile } = await inspector.command('Profiler.stop');
      const detail = attribution(profile), prefix = resolve(values.output) + `-${kind}-${mode}`;
      await mkdir(dirname(prefix), { recursive: true });
      await writeFile(prefix + '.cpuprofile', JSON.stringify(profile) + '\n');
      rows.push({ kind, mode, count: reads.length, sampledActiveMsPerRead: detail.sampledActiveMs / reads.length,
        sampledWasmMsPerRead: detail.categoriesMs.wasm / reads.length, profile: prefix + '.cpuprofile', attribution: detail });
    }
    await h.control('not-cached');
    for (const slot of h.slots) await h.read(slot, kind, { normal: true });
    await inspector.command('Profiler.start');
    let count = 0;
    for (let i = 0; i < rounds; ++i) for (const slot of h.slots) { await h.read(slot, kind, { normal: true }); ++count; }
    const { profile } = await inspector.command('Profiler.stop');
    const detail = attribution(profile), prefix = resolve(values.output) + `-${kind}-response-hit`;
    await writeFile(prefix + '.cpuprofile', JSON.stringify(profile) + '\n');
    rows.push({ kind, mode: 'response-hit', count, sampledActiveMsPerRead: detail.sampledActiveMs / count,
      sampledWasmMsPerRead: detail.categoriesMs.wasm / count, profile: prefix + '.cpuprofile', attribution: detail });
  }
  await inspector.command('Profiler.disable');
  const result = { status: 'PASS', artifact: h.artifact, rounds, warmupsPerFormat: h.slots.length,
    rows, limitations: ['Local sampled V8 time is not hosted billable CPU.',
      'R2 uses exact local windows and the Foundation service is a stub; no network latency conclusion.',
      'Runtime startup and initial compilation precede the profiles.'] };
  await writeFile(resolve(values.output) + '.json', JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify({ status: result.status, wasmSha256: h.artifact.wasmSha256,
    rows: rows.map(({ kind, mode, count, sampledActiveMsPerRead }) => ({ kind, mode, count, sampledActiveMsPerRead })) }));
} finally { inspector?.close(); await h.close(); }
