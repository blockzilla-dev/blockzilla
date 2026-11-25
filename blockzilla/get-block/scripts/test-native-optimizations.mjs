#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { writeFile, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { createNativeCpuHarness } from './profile-native-cpu.mjs';
import { canonicalBlockDigest } from './bench-get-block.mjs';
import { decodeResolution } from './bench-resolution-client.mjs';

// This adapter is used only by this local acceptance test. It cannot be enabled
// by a deployed Worker request. No whole source object is held locally.
const ADAPTER=String.raw`
import worker from './index.js';
const specs=JSON.parse(SPECS), byKey=new Map();
for(const spec of specs)for(const row of spec.windows){const key=spec.sourcePrefix+'/epoch-1089/'+row.file;if(!byKey.has(key))byKey.set(key,[]);byKey.get(key).push({...row,slot:spec.slot});}
let scope=0, state={events:[],gates:[]};
const event=(name,extra={})=>state.events.push({sequence:state.events.length+1,name,...extra});
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const cache=caches.default,match=cache.match.bind(cache),put=cache.put.bind(cache);
const responseKey=req=>new URL(typeof req==='string'?req:req.url).pathname.startsWith('/__blockzilla-cache/');
const facade={async match(req,opts){const tracked=responseKey(req);if(tracked)event('response_cache_match');const result=await match(req,opts);if(tracked)event('response_cache_result',{hit:!!result});return result;},async put(req,response){if(responseKey(req)){event('response_cache_put');if(state.failCachePuts){event('response_cache_put_failed');throw Error('Injected response cache put failure');}}const result=await put(req,response);if(responseKey(req))event('response_cache_put_complete');return result;},delete:cache.delete.bind(cache)};
Object.setPrototypeOf(facade,Object.getPrototypeOf(cache));Object.defineProperty(caches,'default',{value:facade});
const objectWithBody=(o,body,size=o.size,etag=o.httpEtag,range=o.range)=>({key:o.key,version:o.version,size,etag:etag.slice(1,-1),httpEtag:etag,uploaded:o.uploaded,httpMetadata:o.httpMetadata,customMetadata:o.customMetadata,checksums:o.checksums,storageClass:o.storageClass,range,body,bodyUsed:false});
export default{async fetch(request,env,ctx){
 const url=new URL(request.url);
 if(url.pathname==='/__native_test/control'){
  const command=await request.json();
  if(command.reset){for(const done of state.gates)done();scope++;state={events:[],gates:[],blockResolution:false,failSourceBody:false,failCachePuts:false};}
  if(command.release){state.blockResolution=false;for(const done of state.gates.splice(0))done();}
  for(const key of ['blockResolution','failSourceBody','failCachePuts','sourceDelayMs'])if(key in command)state[key]=command[key];
  return Response.json({scope,events:state.events});
 }
 const ranges={async get(key,options){
  const row=byKey.get(key)?.find(row=>row.offset===options?.range?.offset&&row.length===options?.range?.length);
  if(!row||options.onlyIf?.etagMatches!==row.sourceEtag.slice(1,-1))throw Error('Unexpected exact source range or ETag');
  event('source_start',{slot:row.slot,file:row.file});if(state.sourceDelayMs)await pause(state.sourceDelayMs);
  const o=await env.LOCAL_WINDOWS.get(row.localKey,{range:{offset:0,length:row.length},onlyIf:{etagMatches:row.localEtag.slice(1,-1)}});
  if(!o||!o.body||o.size!==row.length||o.httpEtag!==row.localEtag)throw Error('Missing local source window');
  event('source_headers',{slot:row.slot,file:row.file});
  let body=o.body;
  if(state.failSourceBody&&row.file==='archive-v2-blocks.zstd')body=new ReadableStream({async start(controller){await pause(10);controller.error(Error('Injected source body failure'));}});
  return objectWithBody(o,body,row.sourceLength,row.sourceEtag,{offset:row.offset,length:row.length});
 },async head(){event('source_head');throw Error('Unexpected HEAD');}};
 Object.setPrototypeOf(ranges,Object.getPrototypeOf(env.LOCAL_WINDOWS));
 const resolutions={async get(key,options){const slot=specs.find(s=>s.resolutionKey===key)?.slot;event('resolution_start',{slot});if(state.blockResolution)await pause(500);const result=await env.BZ_RESOLUTION.get(key,options);event('resolution_complete',{slot});return result;},async head(){event('resolution_head');throw Error('Unexpected resolution HEAD');}};
 Object.setPrototypeOf(resolutions,Object.getPrototypeOf(env.BZ_RESOLUTION));
 return new worker(ctx,{...env,BZ_ARCHIVE_BUCKET:ranges,BZ_RESOLUTION:resolutions,BZ_ARCHIVE_GENERATION:'local-optimizations-'+scope,BZ_AUTH_CACHE_SCOPE:'local-optimizations-auth-'+scope}).fetch(request);
}};
`;
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const SECRET='local-native-cpu-locator-secret-0123456789';
const {values}=parseArgs({options:{build:{type:'string'},receipt:{type:'string'}}});
assert.ok(values.build,'Use --build with a frozen release module.');
const harness=await createNativeCpuHarness({build:values.build,testAdapterSource:ADAPTER});
const receipt={status:'RUNNING',startedAt:new Date().toISOString(),wasmSha256:harness.artifact.wasmSha256,checks:[],cases:[],scope:'Actual release WASM in local Miniflare; exact saved source windows and original full-object range/ETag geometry; no external calls.'};
const control=async command=>(await harness.mf.dispatchFetch('https://native-cpu.test/__native_test/control',{method:'POST',body:JSON.stringify(command)})).json();
const fixtures=harness.testFixtures,slot=fixtures[0].slot,other=fixtures[1].slot;
const tokens=new Map(fixtures.map(spec=>{const resolution=decodeResolution(spec.resolution,spec.slot);return[spec.slot,resolution.locatorBytes.toString('base64url')+'.'+createHmac('sha256',SECRET).update(resolution.locatorBytes).digest('base64url')];}));
const path=(s=slot,kind='json',query='')=>`/block/${s}.${kind}?${kind==='json'?'rewards=false&':''}${query}`;
const request=(p,authenticated=true)=>harness.mf.dispatchFetch('https://native-cpu.test'+p,{headers:authenticated?{Authorization:harness.testAuthorization}:{Authorization:'Bearer bz_invalid_local_test'},signal:AbortSignal.timeout(15000)});
const read=async(p,authenticated=true)=>{const response=await request(p,authenticated);let bytes,bodyError=false;try{let timer;try{bytes=Buffer.from(await Promise.race([response.arrayBuffer(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Local response body timeout')),5000);})]));}finally{clearTimeout(timer);}}catch(error){if(error.message==='Local response body timeout')throw error;bodyError=true;bytes=Buffer.alloc(0);}return{response,bytes,bodyError};};
const validate=(row,s=slot,kind='json')=>{assert.equal(row.bodyError,false);assert.equal(row.response.status,200,row.bytes.toString().slice(0,400));const spec=fixtures.find(f=>f.slot===s);if(kind==='json')assert.equal(canonicalBlockDigest(row.bytes.toString()),spec.referenceDigest,'full Base64 JSON oracle');else assert.deepEqual(row.bytes,spec.bundle,'original full V1 bytes');};
const metrics=(row,gets)=>{assert.equal(row.response.headers.get('X-Blockzilla-R2-GETs'),String(gets));for(const name of ['X-Blockzilla-R2-HEADs','X-Blockzilla-S3-GETs','X-Blockzilla-S3-HEADs'])assert.equal(row.response.headers.get(name),'0');};
const events=async()=> (await control({})).events;
const waitFor=async predicate=>{const deadline=Date.now()+5000;while(Date.now()<deadline){const rows=await events();if(predicate(rows))return rows;await new Promise(r=>setTimeout(r,5));}assert.fail('Timed out waiting for deterministic adapter events.');};
const check=(name,extra={})=>{receipt.checks.push(name);receipt.cases.push({name,...extra});console.log('Passed '+name+'.');};
const badResult=row=>{assert.ok(row.bodyError||row.response.status!==200,'failure must not be a successful response');assert.notEqual(row.response.headers.get('X-Blockzilla-Cache'),'HIT');};
try{
 await control({reset:true});
 const issued=await read(`/block/${slot}.resolution?profile=1`);assert.equal(issued.response.status,200);assert.equal(issued.response.headers.get('X-Blockzilla-Locator'),tokens.get(slot));
 const valid=await read(path(slot,'json','profile=1&locator='+encodeURIComponent(tokens.get(slot))));validate(valid);metrics(valid,3);assert.equal(valid.response.headers.get('X-Blockzilla-Auth-Cache'),'BYPASS');assert.equal(valid.response.headers.get('X-Blockzilla-Auth-KV-Reads'),'1');
 check('signed JSON locator preserves exact Base64 JSON and three-read cold accounting');
 for(const [name,tok,s]of[['bad MAC',tokens.get(slot).replace(/^./,tokens.get(slot)[0]==='A'?'B':'A'),slot],['wrong slot',tokens.get(slot),other]]){
  await control({reset:true});const row=await read(path(s,'json','profile=1&locator='+encodeURIComponent(tok)));badResult(row);metrics(row,0);assert.equal((await events()).filter(e=>e.name==='resolution_start'||e.name==='source_start').length,0);check(name+' fails before all storage');
 }
 const spec=fixtures[0],original=spec.resolution,changed=Buffer.from(original),old=Buffer.from(spec.windows[0].sourceEtag),replacement=Buffer.from(spec.windows[0].sourceEtag.replace(/[a-f0-9]/,c=>c==='a'?'b':'a'));
 assert.equal(replacement.length,old.length);let offset=96,count=0;while((offset=changed.indexOf(old,offset))!==-1){replacement.copy(changed,offset);offset+=old.length;count++;}assert.equal(count,2);createHash('sha256').update(changed.subarray(96)).digest().copy(changed,56);decodeResolution(changed,slot);
 const bucket=await harness.mf.getR2Bucket('BZ_RESOLUTION');await bucket.put(spec.resolutionKey,changed);
 try{await control({reset:true});const mismatch=await read(path(slot,'json','profile=1&locator='+encodeURIComponent(tokens.get(slot))));badResult(mismatch);assert.ok((await events()).some(e=>e.name==='resolution_complete'));check('valid altered stored locator cannot match the signed hint or emit a successful block');}finally{await bucket.put(spec.resolutionKey,original);}
 for(const hinted of [true,false]){
  await control({reset:true,blockResolution:true});const pending=read(path(slot,'json','profile=1'+(hinted?'&locator='+encodeURIComponent(tokens.get(slot)):'')));
  let rows=await waitFor(rows=>rows.some(e=>e.name==='resolution_start'));
  if(hinted){rows=await waitFor(rows=>rows.filter(e=>e.name==='source_start').length===2);assert.ok(!rows.some(e=>e.name==='resolution_complete'));}
  else{await new Promise(r=>setTimeout(r,30));assert.equal((await events()).filter(e=>e.name==='source_start').length,0);}
  await control({release:true});const result=await pending;validate(result);metrics(result,3);rows=await events();const complete=rows.find(e=>e.name==='resolution_complete').sequence;const starts=rows.filter(e=>e.name==='source_start').map(e=>e.sequence);assert.ok(starts.every(seq=>hinted?seq<complete:seq>complete));
  check((hinted?'hinted':'plain')+' source reads have the required index-completion order',{resolutionCompleteSequence:complete,sourceStartSequences:starts});
 }
 await control({reset:true,blockResolution:true});
 const leader=read(path());await waitFor(rows=>rows.some(e=>e.name==='resolution_start'));
 const followers=Array.from({length:3},()=>read(path()));
 await waitFor(rows=>rows.filter(e=>e.name==='response_cache_match').length>=4);
 const denied=await read(path(),false);assert.equal(denied.response.status,401);assert.equal((await events()).filter(e=>e.name==='resolution_start').length,1);assert.equal((await events()).filter(e=>e.name==='source_start').length,0);
 await control({release:true});const shared=await Promise.all([leader,...followers]);console.log(JSON.stringify({case:'shared_fill',responses:shared.map(row=>({status:row.response.status,bodyError:row.bodyError,fill:row.response.headers.get('X-Blockzilla-Cache-Fill'),cache:row.response.headers.get('X-Blockzilla-Cache'),gets:row.response.headers.get('X-Blockzilla-R2-GETs'),bytes:row.bytes.length,error:row.response.status===200?undefined:row.bytes.toString().slice(0,250)})),events:await events()}));shared.forEach(row=>validate(row));const fills=shared.map(row=>row.response.headers.get('X-Blockzilla-Cache-Fill'));assert.equal(fills.filter(x=>x==='LEADER').length,1);assert.equal(fills.filter(x=>x==='COALESCED').length,3);metrics(shared[fills.indexOf('LEADER')],3);for(let i=0;i<shared.length;i++)if(fills[i]==='COALESCED'){metrics(shared[i],0);assert.equal(shared[i].response.headers.get('X-Blockzilla-Cache'),'HIT');}
 let rows=await events();assert.equal(rows.filter(e=>e.name==='resolution_start').length,1);assert.equal(rows.filter(e=>e.name==='source_start').length,2);check('concurrent identical misses share one three-read fill; invalid auth does not join',{fillStatuses:fills});
 for(const mode of ['body','cache']){
  await control({reset:true,blockResolution:true,failSourceBody:mode==='body',failCachePuts:mode==='cache'});
  const kind='json';const first=read(path(slot,kind));await waitFor(rows=>rows.some(e=>e.name==='resolution_start'));const waiter=read(path(slot,kind));await waitFor(rows=>rows.filter(e=>e.name==='response_cache_match').length>=2);await control({release:true});
  const failed=await Promise.all([first,waiter]);
  if(mode==='body')failed.forEach(badResult);else failed.forEach(row=>validate(row));
  assert.ok(failed.every(row=>row.response.headers.get('X-Blockzilla-Cache')!=='HIT'));
  assert.ok(failed.every(row=>row.response.headers.get('X-Blockzilla-Cache-Fill')!=='COALESCED'));
  if(mode==='cache')assert.ok((await events()).some(e=>e.name==='response_cache_put_failed'));
  await control({failSourceBody:false,failCachePuts:false});const retry=await read(path(slot,kind));validate(retry,slot,kind);assert.equal(retry.response.headers.get('X-Blockzilla-Cache'),'MISS');assert.equal(retry.response.headers.get('X-Blockzilla-Cache-Fill'),'LEADER');
  // A completed cache write must be visible before the subsequent hit assertion.
  await waitFor(rows=>rows.some(e=>e.name==='response_cache_put'));const hit=await read(path(slot,kind));validate(hit,slot,kind);assert.equal(hit.response.headers.get('X-Blockzilla-Cache'),'HIT');metrics(hit,0);
  check('failed '+mode+' fill releases waiters without a false HIT and permits a new leader');
 }
 await control({reset:true,blockResolution:true});const different=[{slot,kind:'json'},{slot,kind:'bin'},{slot:other,kind:'json'}];const isolated=different.map(t=>read(path(t.slot,t.kind)));
 await waitFor(rows=>rows.filter(e=>e.name==='resolution_start').length===3);await control({release:true});const isolatedRows=await Promise.all(isolated);isolatedRows.forEach((row,i)=>{validate(row,different[i].slot,different[i].kind);assert.equal(row.response.headers.get('X-Blockzilla-Cache-Fill'),'LEADER');});
 check('different formats and slots use separate response fills');
 receipt.status='PASS';receipt.completedAt=new Date().toISOString();receipt.fixture={slots:harness.slots,sourceBytes:harness.artifact.sourceBytes,localWindowBytes:harness.artifact.localWindowBytes};
}catch(error){receipt.status='FAIL';receipt.failure={name:error.name,message:error.message};throw error;}finally{await control({release:true}).catch(()=>{});await harness.close();if(values.receipt){await mkdir(dirname(resolve(values.receipt)),{recursive:true});await writeFile(resolve(values.receipt),JSON.stringify(receipt,null,2)+'\n');}}
console.log(JSON.stringify({status:receipt.status,checks:receipt.checks.length,wasmSha256:receipt.wasmSha256}));
