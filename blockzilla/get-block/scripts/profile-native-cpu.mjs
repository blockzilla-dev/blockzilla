#!/usr/bin/env node
// CPU and parity only: original full-object geometry with bounded local windows.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, mkdir, writeFile, rm, copyFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { fixturePath } from './fixture-inputs.mjs';
import * as miniflare from 'miniflare';
import { decodeV1Bundle } from './bench-resolution-client.mjs';
import { canonicalBlockDigest } from './bench-get-block.mjs';
import { connectInspector, attribution } from './profile-local-cpu.mjs';

const PACKAGE = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ROOT = resolve(PACKAGE, '../..');
const KEY = 'bz_live_native_cpu_abcdefghijklmnopqrstuvwxyz0123456789';
const hash = value => createHash('sha256').update(value).digest('hex');
const NAME = 'blockzilla-get-block-local-profile';

const ADAPTER = String.raw`
import worker from './index.js';
const specs = JSON.parse(SPECS);
const byKey = new Map();
for (const spec of specs) for (const window of spec.windows) {
 const key = spec.sourcePrefix + '/epoch-1089/' + window.file;
 if (!byKey.has(key)) byKey.set(key, []);
 byKey.get(key).push(window);
}
export default { async fetch(request, env, ctx) {
 const ranges = { async get(key, options) {
  const choices = byKey.get(key);
  const row = choices?.find(row => options?.range?.offset === row.offset && options?.range?.length === row.length);
  if (!row || options.onlyIf?.etagMatches !== row.sourceEtag.slice(1,-1)) throw Error('Unexpected original range or ETag');
  const object = await env.LOCAL_WINDOWS.get(row.localKey, { range: { offset:0,length:row.length },onlyIf:{etagMatches:row.localEtag.slice(1,-1)} });
  if (!object || !object.body || object.size !== row.length || object.httpEtag !== row.localEtag) throw Error('Missing exact local window');
  return {key,version:object.version,size:row.sourceLength,etag:row.sourceEtag.slice(1,-1),httpEtag:row.sourceEtag,
   uploaded:object.uploaded,httpMetadata:object.httpMetadata,customMetadata:object.customMetadata,checksums:object.checksums,
   storageClass:object.storageClass,range:{offset:row.offset,length:row.length},body:object.body,bodyUsed:false};
 }, async head(){ throw Error('Unexpected source HEAD'); } };
 Object.setPrototypeOf(ranges,Object.getPrototypeOf(env.LOCAL_WINDOWS));
 return new worker(ctx,{...env,BZ_ARCHIVE_BUCKET:ranges}).fetch(request);
} };
`;

export async function createNativeCpuHarness(options = {}) {
  const build = resolve(options.build ?? join(PACKAGE, 'build/index.js'));
  const verification = JSON.parse(await readFile(fixturePath(options.fixtureRoot, 'verification.json'), 'utf8'));
  assert.equal(verification.status, 'REMOTE_VERIFIED');
  const reference = JSON.parse(await readFile(fixturePath(options.fixtureRoot, 'reference-base64.json'), 'utf8'));
  const inputs = JSON.parse(await readFile(fixturePath(options.fixtureRoot, 'input-manifest.json'), 'utf8'));
  const temporary = await mkdtemp(join(tmpdir(), 'blockzilla-native-cpu-'));
  const specs = [];
  for (const row of verification.resolutionObjects) {
    const original = inputs.records.find(input => input.slot === row.slot);
    const descriptor = JSON.parse(await readFile(fixturePath(options.fixtureRoot, 'descriptors', `${row.slot}.json`), 'utf8'));
    const bundle = await readFile(original.bundlePath); const decoded = decodeV1Bundle(bundle);
    specs.push({slot:row.slot,sourcePrefix:verification.sourcePrefix,resolutionKey:row.key,resolution:await readFile(row.localPath),bundle,
      referenceDigest:reference.samples.find(sample => sample.slot === row.slot).contentSha256,
      windows:[['archive-v2-blocks.zstd',descriptor.hot_row.compressed_offset,decoded.hot],['signatures.bin',descriptor.hot_row.first_signature_ordinal*64,decoded.signatures]].map(([file,offset,bytes])=>({file,offset,length:bytes.length,bytes,localKey:`windows/${row.slot}/${file}`,localEtag:`"${createHash('md5').update(bytes).digest('hex')}"`,sourceLength:descriptor.objects[file].length,sourceEtag:descriptor.objects[file].etag}))});
  }
  assert.equal(specs.length,4);
  const shim = join(temporary, 'adapter.mjs');
  // Optional local acceptance-test adapter. CPU profiles use ADAPTER unchanged.
  assert.ok(options.testAdapterSource === undefined || typeof options.testAdapterSource === 'string');
  await writeFile(shim,(options.testAdapterSource ?? ADAPTER).replace('JSON.parse(SPECS)',JSON.stringify(specs.map(spec=>({slot:spec.slot,sourcePrefix:spec.sourcePrefix,resolutionKey:spec.resolutionKey,windows:spec.windows.map(({bytes,...window})=>window)})))));
  // Copy the small release module and WASM so all module paths have one root.
  await copyFile(build,join(temporary,'index.js'));
  await copyFile(join(dirname(build),'index_bg.wasm'),join(temporary,'index_bg.wasm'));
  const variables = {
    BZ_ARCHIVE_SOURCE:'r2',BZ_ARCHIVE_LAYOUT:'stored',BZ_ARCHIVE_PREFIX:verification.sourcePrefix,
    BZ_ARCHIVE_GENERATION:'local-full-geometry-cpu-v1',BZ_HTTP_GET_ONLY:'true',BZ_AUTH_CACHE_SCOPE:'local-native-cpu-auth-v1',
    BZ_RESOLUTION_PREFIX:verification.resolutionPrefix,BZ_RESOLUTION_GENERATION:verification.generation,
    BZ_RESOLUTION_SLOTS:specs.map(spec=>spec.slot).join(','),BZ_LOCATOR_SECRET:'local-native-cpu-locator-secret-0123456789',
  };
  const config = {name:NAME,modulesRoot:temporary,modules:[{type:'ESModule',path:shim},{type:'ESModule',path:join(temporary,'index.js')},{type:'CompiledWasm',path:join(temporary,'index_bg.wasm')}],compatibilityDate:'2026-09-10',resourcePersistencePath:join(temporary,'storage'),telemetry:{enabled:false},bindings:variables,
    r2Buckets:{LOCAL_WINDOWS:'native-cpu-windows',BZ_RESOLUTION:'native-cpu-resolution'},kvNamespaces:{BZ_RPC_API_KEYS:'native-cpu-auth'},analyticsEngineDatasets:{BZ_RPC_METRICS:{dataset:'native-cpu-metrics'}},inspectorPort:0};
  const mf = new miniflare.Miniflare(typeof miniflare.convertV4MiniflareOptions==='function'?miniflare.convertV4MiniflareOptions(config):config);
  await mf.ready;
  const windows = await mf.getR2Bucket('LOCAL_WINDOWS');const resolutions=await mf.getR2Bucket('BZ_RESOLUTION');
  for(const spec of specs){
    for(const window of spec.windows){const object=await windows.put(window.localKey,window.bytes);assert.equal(object.httpEtag??`"${object.etag}"`,window.localEtag);}
    await resolutions.put(spec.resolutionKey,spec.resolution);
  }
  await(await mf.getKVNamespace('BZ_RPC_API_KEYS')).put(hash(KEY),JSON.stringify({keyId:'native_cpu',customerId:'local',label:'Local native CPU test',status:'enabled'}));
  const reads=[];const pendingValidation=[];
  const validate=(bytes,spec,kind,row)=>{
    if(kind==='json')assert.equal(canonicalBlockDigest(bytes.toString()),spec.referenceDigest,'independent full JSON digest');
    else assert.deepEqual(bytes,spec.bundle,'original full binary bytes');
    row.sha256=hash(bytes);
  };
  const read=async(slot,kind='json',options={})=>{
    const spec=specs.find(row=>row.slot===slot);assert.ok(spec);assert.ok(['json','bin'].includes(kind));
    const started=performance.now();
    const response=await mf.dispatchFetch(`https://native-cpu.test/block/${slot}.${kind}?profile=1${kind==='json'?'&rewards=false':''}`,{headers:{Authorization:`Bearer ${KEY}`}});
    const bytes=Buffer.from(await response.arrayBuffer());const totalMs=performance.now()-started;
    assert.equal(response.status,200,bytes.toString().slice(0,400));
    const row={slot,kind,bytes:bytes.length,totalMs};
    if(options.deferValidation)pendingValidation.push({bytes,spec,kind,row});else validate(bytes,spec,kind,row);
    reads.push(row);return row;
  };
  return {mf,slots:specs.map(spec=>spec.slot),reads,read,...(options.testAdapterSource ? {testFixtures:specs,testAuthorization:`Bearer ${KEY}`} : {}),validatePending(){for(const item of pendingValidation)validate(item.bytes,item.spec,item.kind,item.row);pendingValidation.length=0;},artifact:{wasmSha256:hash(await readFile(join(temporary,'index_bg.wasm'))),build,fullGeometry:true,sourceBytes:verification.sourceBytes,localWindowBytes:specs.reduce((n,spec)=>n+spec.windows.reduce((m,w)=>m+w.length,0),0),adapterIo:'Synthetic: native R2 holds only exact windows; adapter validates original full-object range/ETag and reports original object size. Wall I/O timings are not a full-object latency test.'},async close(){await mf.dispose();await rm(temporary,{recursive:true,force:true});}};
}

async function main(){
  const {values}=parseArgs({options:{'fixture-root':{type:'string'},build:{type:'string'},output:{type:'string',default:'profile-output/native-cpu'},rounds:{type:'string',default:'8'},warmup:{type:'string',default:'2'},fresh:{type:'boolean',default:false}}});
  const rounds=Number(values.rounds),warmup=Number(values.warmup);assert.ok(Number.isInteger(rounds)&&rounds>=1&&rounds<=20);assert.ok(Number.isInteger(warmup)&&warmup>=0&&warmup<=3);
  if(values.fresh){
    const rows=[];let artifact;
    for(const slot of [470555971,470663944,470771932,470879999]){
      const harness=await createNativeCpuHarness({build:values.build,fixtureRoot:values['fixture-root']});let inspector;
      try{
        artifact??=harness.artifact;inspector=await connectInspector(harness.mf);
        await inspector.command('Profiler.enable');await inspector.command('Profiler.setSamplingInterval',{interval:1000});await inspector.command('Profiler.start');
        const read=await harness.read(slot,'json',{deferValidation:true});
        const {profile}=await inspector.command('Profiler.stop');await inspector.command('Profiler.disable');harness.validatePending();
        const binary=await harness.read(slot,'bin');
        const path=resolve(values.output)+`-${slot}.cpuprofile`;await mkdir(dirname(path),{recursive:true});await writeFile(path,JSON.stringify(profile)+'\n',{flag:'wx'});
        rows.push({slot,read,binary,profile:path,attribution:attribution(profile)});
      }finally{inspector?.close();await harness.close();}
    }
    const report={status:'PASS',mode:'one first JSON request in each of four fresh application runtimes',artifact,rows,
      sampledActiveMsPerRead:rows.reduce((n,r)=>n+r.attribution.sampledActiveMs,0)/rows.length,
      sampledWasmMsPerRead:rows.reduce((n,r)=>n+r.attribution.categoriesMs.wasm,0)/rows.length,
      limitations:['Local sampled V8 time is not billable production CPU.','Native R2 I/O is synthetic from bounded exact windows; no full-object latency conclusion.','WASM module startup precedes inspector sampling. No request warmup precedes the sampled JSON read.']};
    await writeFile(resolve(values.output)+'.json',JSON.stringify(report,null,2)+'\n',{flag:'wx'});
    console.log(JSON.stringify({status:report.status,mode:report.mode,wasmSha256:artifact.wasmSha256,sampledActiveMsPerRead:report.sampledActiveMsPerRead,sampledWasmMsPerRead:report.sampledWasmMsPerRead}));return;
  }
  const harness=await createNativeCpuHarness({build:values.build,fixtureRoot:values['fixture-root']});let inspector;
  const report={status:'RUNNING',startedAt:new Date().toISOString(),artifact:harness.artifact,rounds,warmup,scope:'Local actual release WASM CPU and exact parity only. No external calls. Synthetic native-R2 adapter preserves original full-object read geometry.',limitations:['V8 sampled CPU is not billable production CPU.','The local compatibility date is fixed for repeatable tests.','Client wall time includes local proxy and body transfer.']};
  try{
    for(const slot of harness.slots){await harness.read(slot,'bin');for(let i=0;i<warmup;i++)await harness.read(slot);}
    inspector=await connectInspector(harness.mf);await inspector.command('Profiler.enable');await inspector.command('Profiler.setSamplingInterval',{interval:1000});await inspector.command('Profiler.start');
    const start=harness.reads.length;
    for(let round=0;round<rounds;round++)for(const slot of harness.slots)await harness.read(slot,'json',{deferValidation:true});
    const {profile}=await inspector.command('Profiler.stop');await inspector.command('Profiler.disable');
    harness.validatePending();
    report.reads=harness.reads.slice(start);report.attribution=attribution(profile);report.sampledActiveMsPerRead=report.attribution.sampledActiveMs/report.reads.length;report.sampledWasmMsPerRead=report.attribution.categoriesMs.wasm/report.reads.length;
    await mkdir(dirname(resolve(values.output)),{recursive:true});await writeFile(resolve(values.output)+'.cpuprofile',JSON.stringify(profile)+'\n',{flag:'wx'});report.profile=resolve(values.output)+'.cpuprofile';report.status='PASS';
  }finally{inspector?.close();await harness.close();}
  report.completedAt=new Date().toISOString();await writeFile(resolve(values.output)+'.json',JSON.stringify(report,null,2)+'\n',{flag:'wx'});
  console.log(JSON.stringify({status:report.status,wasmSha256:report.artifact.wasmSha256,reads:report.reads.length,sampledActiveMsPerRead:report.sampledActiveMsPerRead,sampledWasmMsPerRead:report.sampledWasmMsPerRead,topLeaves:report.attribution.topLeaves.slice(0,8)}));
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(error=>{console.error(error);process.exitCode=1;});
