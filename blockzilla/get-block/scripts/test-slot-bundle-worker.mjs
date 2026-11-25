#!/usr/bin/env node
// Actual release-WASM checks with four complete local R2 objects, no source fallback.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir, copyFile, mkdtemp, rm } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import * as miniflare from 'miniflare';
import { prepareSlotBundleManifest } from './prepare-slot-bundle-manifest.mjs';
import { canonicalBlockDigest } from './bench-get-block.mjs';

const PACKAGE = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ROOT = resolve(PACKAGE, '../..');
const KEY = 'bz_live_bundle_local_abcdefghijklmnopqrstuvwxyz0123456789';
const hash = value => createHash('sha256').update(value).digest('hex');
const ADAPTER = String.raw`
import worker from './index.js';
export default { async fetch(request, env, ctx) {
 const mode = new URL(request.url).searchParams.get('__mode');
 let gets=0, heads=0;
 const bucket = { async get(key, options) {
  gets++;
  if (options?.range) throw Error('Bundle must use a full GET');
  if (!key.startsWith('serving/slot-bundles-test-20261122-v1/epoch-1089/slot-')) throw Error('Unexpected source/index access');
  if (mode==='missing') return null;
  const object = await env.LOCAL_BUNDLES.get(key,options);
  if (!object) return object;
  let body=mode==='conditional'?undefined:object.body;
  if(mode==='short')body=new ReadableStream({start(c){c.enqueue(new Uint8Array([1]));c.close();}});
  if(mode==='corrupt')body=body.pipeThrough(new TransformStream({transform(chunk,c){chunk[0]^=1;c.enqueue(chunk);}}));
  const checksums=mode==='checksum'?{}:object.checksums;
  return {key:object.key,version:object.version,size:object.size+(mode==='size'?1:0),
   etag:object.etag,httpEtag:mode==='etag'?'"changed-etag"':object.httpEtag,
   uploaded:object.uploaded,httpMetadata:object.httpMetadata,customMetadata:object.customMetadata,
   checksums,storageClass:object.storageClass,body,bodyUsed:false};
 },async head(){heads++;throw Error('Unexpected HEAD');}};
 Object.setPrototypeOf(bucket,Object.getPrototypeOf(env.LOCAL_BUNDLES));
 const response=await new worker(ctx,{...env,BZ_ARCHIVE_BUCKET:bucket}).fetch(request);
 response.headers.set('X-Test-R2-GETs',String(gets));response.headers.set('X-Test-R2-HEADs',String(heads));
 return response;
} };
`;

export async function createBundleHarness(options = {}) {
  const preparation=await prepareSlotBundleManifest();
  const reference=JSON.parse(await readFile(join(ROOT,'reports/get-block-cold-profile-20261121/reference-base64.json'),'utf8'));
  const build=resolve(options.build??join(PACKAGE,'build/index.js'));
  const temporary=await mkdtemp(join(tmpdir(),'blockzilla-bundle-test-'));
  const shim=join(temporary,'adapter.mjs');await writeFile(shim,ADAPTER);
  await copyFile(build,join(temporary,'index.js'));await copyFile(join(dirname(build),'index_bg.wasm'),join(temporary,'index_bg.wasm'));
  const variables={BZ_ARCHIVE_SOURCE:'r2',BZ_ARCHIVE_LAYOUT:'stored',BZ_ARCHIVE_PREFIX:'bundle-unused-source',
    BZ_ARCHIVE_GENERATION:'local-slot-bundle-v1',BZ_HTTP_GET_ONLY:'true',BZ_AUTH_CACHE_SCOPE:'local-slot-bundle-auth-v1',
    BZ_SLOT_BUNDLE_PREFIX:preparation.prefix,BZ_SLOT_BUNDLE_GENERATION:preparation.generation,
    BZ_SLOT_BUNDLE_MANIFEST:JSON.stringify(preparation.manifest)};
  const config={name:'blockzilla-slot-bundle-local',modulesRoot:temporary,modules:[{type:'ESModule',path:shim},
    {type:'ESModule',path:join(temporary,'index.js')},{type:'CompiledWasm',path:join(temporary,'index_bg.wasm')}],
    compatibilityDate:'2026-09-10',resourcePersistencePath:join(temporary,'storage'),telemetry:{enabled:false},bindings:variables,
    r2Buckets:{LOCAL_BUNDLES:'bundles'},kvNamespaces:{BZ_RPC_API_KEYS:'bundle-test-auth'},
    analyticsEngineDatasets:{BZ_RPC_METRICS:{dataset:'bundle-test-metrics'}},inspectorPort:0};
  const mf=new miniflare.Miniflare(typeof miniflare.convertV4MiniflareOptions==='function'?miniflare.convertV4MiniflareOptions(config):config);
  await mf.ready;
  const bucket=await mf.getR2Bucket('LOCAL_BUNDLES');
  const fixtures=[];
  for(const row of preparation.objects){
    const bytes=await readFile(row.localPath);
    const object=await bucket.put(row.key,bytes,{sha256:row.sha256});
    assert.equal(object.httpEtag??`"${object.etag}"`,row.etag);
    fixtures.push({...row,bytes,referenceDigest:reference.samples.find(sample=>sample.slot===row.slot).contentSha256});
  }
  await(await mf.getKVNamespace('BZ_RPC_API_KEYS')).put(hash(KEY),JSON.stringify({keyId:'bundle_local',customerId:'local',label:'Local bundle test',status:'enabled'}));
  const reads=[];const pending=[];
  const validate=(bytes,fixture,kind,row)=>{
    if(kind==='json')assert.equal(canonicalBlockDigest(bytes.toString()),fixture.referenceDigest,'full JSON reference digest');
    else assert.deepEqual(bytes,fixture.bytes,'exact original V1 bytes');
    row.sha256=hash(bytes);
  };
  const response=async(slot,kind='json',options={})=>{
    const profile=options.profile??'1';
    const params=new URLSearchParams({rewards:'false'});if(profile!=='normal')params.set('profile',profile);
    if(options.mode)params.set('__mode',options.mode);
    for(const [key,value] of Object.entries(options.query??{}))params.set(key,value);
    return mf.dispatchFetch(`https://bundle.test/block/${slot}.${kind}?${params}`,{headers:{Authorization:`Bearer ${KEY}`}});
  };
  const read=async(slot,kind='json',options={})=>{
    const fixture=fixtures.find(row=>row.slot===slot);assert.ok(fixture||options.expectStatus);
    const started=performance.now();
    const result=await response(slot,kind,options);
    const bytes=Buffer.from(await result.arrayBuffer());
    const row={slot,kind,status:result.status,bytes:bytes.length,totalMs:performance.now()-started,headers:Object.fromEntries(result.headers)};
    if(options.expectStatus){assert.equal(result.status,options.expectStatus,bytes.toString().slice(0,300));}
    else {assert.equal(result.status,200,bytes.toString().slice(0,300));if(options.deferValidation)pending.push({bytes,fixture,kind,row});else validate(bytes,fixture,kind,row);}
    reads.push(row);return row;
  };
  return {mf,preparation,fixtures,slots:fixtures.map(row=>row.slot),reads,read,response,
    artifact:{build,wasmSha256:hash(await readFile(join(temporary,'index_bg.wasm')))},
    validatePending(){for(const item of pending)validate(item.bytes,item.fixture,item.kind,item.row);pending.length=0;},
    async close(){await mf.dispose();await rm(temporary,{recursive:true,force:true});}};
}

async function main(){
 const {values}=parseArgs({options:{build:{type:'string'},receipt:{type:'string',default:join(ROOT,'reports/get-block-one-read-20261122/local-acceptance.json')}}});
 const harness=await createBundleHarness({build:values.build});const checks=[];
 const check=(name,row,expectedGets)=>{assert.equal(row.headers['x-test-r2-gets'],String(expectedGets),name);assert.equal(row.headers['x-test-r2-heads'],'0',name);checks.push({name,slot:row.slot,status:row.status,gets:expectedGets});};
 try{
  for(const slot of harness.slots){
   for(const kind of ['json','bin']){const row=await harness.read(slot,kind);check(`cold ${kind} exact`,row,1);assert.equal(row.headers['x-blockzilla-archive-layout'],'bundle-v1');assert.equal(row.headers['x-blockzilla-auth-cache'],'BYPASS');}
  }
  const slot=harness.slots[0];
  for(const kind of ['json','bin'])for(const mode of ['missing','size','etag','checksum','conditional']){const row=await harness.read(slot,kind,{mode,expectStatus:502});check(`reject ${kind} ${mode}`,row,1);}
  const corrupt=await harness.read(slot,'json',{mode:'corrupt',expectStatus:502});check('reject corrupt delivered body SHA256',corrupt,1);
  for(const kind of ['json','bin']){const row=await harness.read(slot+1,kind,{expectStatus:404});check(`reject non-admitted ${kind}`,row,0);}
  const omitted=await harness.read(slot,'bin',{query:{access:'0'},expectStatus:400});check('reject incomplete bundle variant',omitted,0);
  const short=await harness.response(slot,'bin',{mode:'short'});assert.equal(short.status,200);
  assert.equal(short.headers.get('x-test-r2-gets'),'1');assert.equal(short.headers.get('x-test-r2-heads'),'0');
  await assert.rejects(short.arrayBuffer());checks.push({name:'short binary source terminates stream',slot,status:200,gets:1});
  for(const kind of ['json','bin']){
   const row=await harness.read(slot,kind,{profile:'source'});check(`source ${kind} one GET`,row,1);
  }
  // Normal application reads can fill response and complete-object caches.
  await harness.read(slot,'json',{profile:'normal'});
  await new Promise(resolve=>setTimeout(resolve,100));
  const hit=await harness.read(slot,'json',{profile:'normal'});check('normal response cache hit',hit,0);
  const objectHit=await harness.read(slot,'bin',{profile:'normal'});check('binary shares complete object cache after JSON fill',objectHit,0);
  await new Promise(resolve=>setTimeout(resolve,100));
  const binaryHit=await harness.read(slot,'bin',{profile:'normal'});check('normal binary response cache hit',binaryHit,0);
  const binaryFill=await harness.read(harness.slots[1],'bin',{profile:'normal'});check('normal binary origin fill',binaryFill,1);
  await new Promise(resolve=>setTimeout(resolve,100));
  const filledBinaryHit=await harness.read(harness.slots[1],'bin',{profile:'normal'});check('normal binary origin-fill response hit',filledBinaryHit,0);
  const source=await harness.read(slot,'json',{profile:'source'});check('source bypass after hit',source,1);
  const cold=await harness.read(slot,'json');check('full bypass after hit',cold,1);assert.equal(cold.headers['x-blockzilla-auth-cache'],'BYPASS');
  const report={status:'PASS',artifact:harness.artifact,checks,reads:harness.reads,
    limits:['Native R2 latency is local test I/O; use the hosted benchmark for latency.',
      'Local workerd supports compatibility date 2026-09-10; hosted test uses 2026-11-21.',
      'Binary verifies admitted R2 checksum metadata and exact stream length, without hashing payload in WASM.']};
  const path=resolve(values.receipt);await mkdir(dirname(path),{recursive:true});await writeFile(path,JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify({status:report.status,checks:checks.length,wasmSha256:report.artifact.wasmSha256,receipt:path}));
 }finally{await harness.close();}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(error=>{console.error(error);process.exitCode=1;});
