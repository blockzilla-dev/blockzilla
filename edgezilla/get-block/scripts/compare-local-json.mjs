#!/usr/bin/env node
// Compare two unchanged release artifacts using the same local real-block test.
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { createLocalWorkerHarness } from './profile-local-worker.mjs';

const { values } = parseArgs({ options: {
  before: { type: 'string' }, after: { type: 'string' },
  fixture: { type: 'string', default: '/tmp/blockzilla-resolution-real-slot-fixture-20261121' },
  output: { type: 'string', default: 'reports/get-block-cpu-20261121/local-json-comparison.json' },
  samples: { type: 'string', default: '10' }, warmup: { type: 'string', default: '2' },
} });
assert.ok(values.before && values.after, 'Pass --before and --after release index.js paths.');
const samples = Number(values.samples), warmup = Number(values.warmup);
assert.ok(Number.isInteger(samples) && samples > 0 && samples <= 30);
assert.ok(Number.isInteger(warmup) && warmup >= 0 && warmup <= 5);
const percentile = (rows, field, fraction) => {
  const list = rows.map(row => row[field]).sort((a,b) => a-b);
  const index = (list.length-1)*fraction, lower=Math.floor(index), upper=Math.ceil(index);
  return list[lower]+(list[upper]-list[lower])*(index-lower);
};
const report = {
  schema: 'blockzilla-metadata-local-wasm-comparison-v1', startedAt: new Date().toISOString(),
  scope: 'Same real slot in local Miniflare/workerd, local R2, streamed Base64 JSON, profile=1 fully cold cache mode; no external archive or production calls.',
  samples, warmup, runs: [],
};
for (const [label, build] of [['before', values.before], ['after', values.after]]) {
  const harness = await createLocalWorkerHarness({ fixture: resolve(values.fixture), build: resolve(build), backend: 'r2' });
  try {
    for (let i=0;i<warmup;i++) await harness.read('json', { profile: true });
    const rows=[];
    for (let i=0;i<samples;i++) {
      const result=await harness.read('json', { profile: true });
      assert.equal(result.headers['x-blockzilla-cache'], 'BYPASS');
      assert.equal(result.headers['x-blockzilla-r2-reads'], '3');
      assert.equal(result.headers['x-blockzilla-archive-memory-hits'], '0');
      assert.equal(result.headers['x-blockzilla-archive-edge-hits'], '0');
      rows.push(result);
    }
    report.runs.push({ label, artifact: harness.artifact, samples: rows,
      summary: Object.fromEntries(['headersMs','firstByteMs','totalMs'].map(field => [field, {
        p50: percentile(rows,field,.5), p95: percentile(rows,field,.95),
      }])) });
  } finally { await harness.close(); }
}
const before=report.runs[0], after=report.runs[1];
const hashes=new Set(report.runs.flatMap(run=>run.samples.map(row=>row.sha256)));
assert.equal(hashes.size,1,'Every complete response must be byte-identical across both artifacts.');
report.byteIdentical=true;
report.fullBodyMedianReductionPercent=100*(1-after.summary.totalMs.p50/before.summary.totalMs.p50);
report.notes=[
  'Each timed body was checked against the saved Helius Base64 oracle by the common harness.',
  'Timing is measured by the Node client. It excludes its correctness check and does not represent hosted CPU billing.',
  'Both runs use the same local compatibility date and fully bypassed caches. Warmups prepare the runtime, not the archive caches.',
  'The combined release artifacts also contain separate auth/profile changes; native byte-parity/CPU tests isolate the writer and amount changes.',
];
report.completedAt=new Date().toISOString();
await mkdir(dirname(resolve(values.output)),{recursive:true});
await writeFile(resolve(values.output),`${JSON.stringify(report,null,2)}\n`,{flag:'wx'});
console.log(JSON.stringify({byteIdentical:report.byteIdentical,before:before.summary,after:after.summary,
  fullBodyMedianReductionPercent:report.fullBodyMedianReductionPercent,output:resolve(values.output)}));
