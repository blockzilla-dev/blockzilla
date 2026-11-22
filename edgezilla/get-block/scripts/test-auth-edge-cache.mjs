#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, writeFile, copyFile, rm, mkdir } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { parseArgs } from 'node:util';
import * as miniflare from 'miniflare';
const ORIGIN='https://auth-native.test',KEY='bz_live_auth_l2_fixture_abcdefghijklmnopqrstuvwxyz0123456789';
const sha=value=>createHash('sha256').update(value).digest('hex');
const enabled={keyId:'local_auth_l2',customerId:'local',label:'Local auth test',status:'enabled'};
const disabled={...enabled,status:'disabled'};
const ADAPTER=String.raw`
import worker from './index.js';
const cache=caches.default,nativeMatch=cache.match.bind(cache),nativePut=cache.put.bind(cache);
let state={scope:'initial',events:[],failGet:false,failPut:false,kvDelayMs:0};
const event=(name,extra={})=>state.events.push({name,...extra});
const facade={async match(req,options){event('cache_get');if(state.failGet)throw Error('Injected auth cache GET failure');return nativeMatch(req,options);},async put(req,response){event('cache_put');if(state.failPut)throw Error('Injected auth cache PUT failure');await nativePut(req,response);event('cache_put_complete');},delete:cache.delete.bind(cache)};
Object.setPrototypeOf(facade,Object.getPrototypeOf(cache));Object.defineProperty(caches,'default',{value:facade});
export default{async fetch(request,env,ctx){
 if(new URL(request.url).pathname==='/__auth_test/control'){
  const c=await request.json();
  if(c.reset)state={scope:c.scope,events:[],failGet:false,failPut:false,kvDelayMs:0};
  for(const key of ['scope','failGet','failPut','kvDelayMs'])if(key in c)state[key]=c[key];
  if(c.seed){await nativePut(c.seed.key,new Response(c.seed.text,{headers:{'Content-Type':'application/json','Content-Length':String(new TextEncoder().encode(c.seed.text).length),'Cache-Control':'public, max-age=60'}}));}
  let entry;
  if(c.peek){const r=await nativeMatch(c.peek);entry=r?{body:await r.text(),cacheControl:r.headers.get('Cache-Control')}:null;}
  return Response.json({nonce:env.BZ_TEST_NONCE,scope:state.scope,events:state.events,entry});
 }
 const ns=env.BZ_RPC_API_KEYS;
 const kv={async get(...args){event('kv_get');if(state.kvDelayMs)await new Promise(r=>setTimeout(r,state.kvDelayMs));return ns.get(...args);},getWithMetadata:ns.getWithMetadata.bind(ns),put:ns.put.bind(ns),delete:ns.delete.bind(ns),list:ns.list.bind(ns)};
 Object.setPrototypeOf(kv,Object.getPrototypeOf(ns));
 return new worker(ctx,{...env,BZ_AUTH_CACHE_SCOPE:state.scope,BZ_RPC_API_KEYS:kv}).fetch(request);
}};
`;
export async function createAuthHarness(build){
 const temp=await mkdtemp(join(tmpdir(),'blockzilla-auth-edge-'));
 const module=join(temp,'index.js'),wasm=join(temp,'index_bg.wasm'),adapter=join(temp,'adapter.mjs');
 await copyFile(resolve(build),module);await copyFile(join(dirname(resolve(build)),'index_bg.wasm'),wasm);await writeFile(adapter,ADAPTER);
 let nonce=0;
 const config=()=>{const raw={name:'blockzilla-auth-edge-local-test',modulesRoot:temp,modules:[{type:'ESModule',path:adapter},{type:'ESModule',path:module},{type:'CompiledWasm',path:wasm}],compatibilityDate:'2026-09-10',resourcePersistencePath:join(temp,'storage'),telemetry:{enabled:false},bindings:{BZ_HTTP_GET_ONLY:'true',BZ_AUTH_CACHE_SCOPE:'initial',BZ_ARCHIVE_SOURCE:'r2',BZ_TEST_NONCE:String(nonce)},r2Buckets:{BZ_ARCHIVE_BUCKET:'auth-unused'},kvNamespaces:{BZ_RPC_API_KEYS:'auth-edge-test-keys'},analyticsEngineDatasets:{BZ_RPC_METRICS:{dataset:'auth-edge-test-metrics'}}};return typeof miniflare.convertV4MiniflareOptions==='function'?miniflare.convertV4MiniflareOptions(raw):raw;};
 const mf=new miniflare.Miniflare(config());await mf.ready;
 const control=async command=>(await mf.dispatchFetch(ORIGIN+'/__auth_test/control',{method:'POST',body:JSON.stringify(command)})).json();
 const setKV=async value=>{const kv=await mf.getKVNamespace('BZ_RPC_API_KEYS');if(value===null)await kv.delete(sha(KEY));else await kv.put(sha(KEY),typeof value==='string'?value:JSON.stringify(value));};
 const read=async(profile=false)=>{const r=await mf.dispatchFetch(ORIGIN+'/block/not-a-slot.json'+(profile?'?profile=1':''),{headers:{Authorization:'Bearer '+KEY}});await r.arrayBuffer();return{status:r.status,cache:r.headers.get('X-Blockzilla-Auth-Cache'),kv:r.headers.get('X-Blockzilla-Auth-KV-Reads'),tier:r.headers.get('X-Blockzilla-Auth-Cache-Tier')};};
 return{mf,control,setKV,read,wasmSha256:sha(await readFile(wasm)),async fresh(scope){nonce++;await mf.setOptions(config());await mf.ready;const c=await control({reset:true,scope});assert.equal(c.nonce,String(nonce));return c;},async close(){await mf.dispose();await rm(temp,{recursive:true,force:true});}};
}
const {values}=parseArgs({options:{build:{type:'string'},receipt:{type:'string'}}});
if(!values.build)throw Error('Use --build with a frozen Worker module.');
const h=await createAuthHarness(values.build),receipt={status:'RUNNING',startedAt:new Date().toISOString(),wasmSha256:h.wasmSha256,checks:[],cases:[],scope:'Local actual-WASM auth tests only. Invalid-slot GETs exercise authorization without any block/index reads. No cloud calls.'};
const keyFor=scope=>ORIGIN+'/__blockzilla-auth-positive/v1/'+sha('auth-check-v1\0BZ_RPC_API_KEYS\0'+scope+'\0'+sha(KEY));
const envelope=(scope,checkedAt=Date.now())=>({version:1,originDigest:sha(ORIGIN),scopeDigest:sha('auth-check-v1\0BZ_RPC_API_KEYS\0'+scope+'\0'+sha(KEY)),keyDigest:sha(KEY),checkedAtUtcMs:checkedAt,record:enabled});
const control=c=>h.control(c),events=async()=>(await control({})).events;
const count=(rows,name)=>rows.filter(e=>e.name===name).length;
const valid=(r,cache,kv)=>{assert.equal(r.status,400,'valid auth must reach invalid-slot handling');assert.equal(r.cache,cache);assert.equal(r.kv,String(kv));if(cache==='MISS')assert.equal(r.tier,'KV');if(cache==='BYPASS')assert.equal(r.tier,'BYPASS');if(cache==='HIT')assert.ok(['MEMORY','EDGE'].includes(r.tier));};
const check=(name,details={})=>{receipt.checks.push(name);receipt.cases.push({name,...details});console.log('Passed '+name+'.');};
const waitPut=async()=>{const limit=Date.now()+2000;while(Date.now()<limit){const e=await events();if(count(e,'cache_put_complete'))return e;await new Promise(r=>setTimeout(r,5));}assert.fail('No completed positive auth cache put.');};
try{
 let scope='fresh-isolate';await h.fresh(scope);await h.setKV(enabled);valid(await h.read(),'MISS',1);await waitPut();const cached=await control({peek:keyFor(scope)});assert.ok(cached.entry);const published=JSON.parse(cached.entry.body);assert.equal(published.version,1);assert.equal(published.keyDigest,sha(KEY));assert.equal(published.scopeDigest,envelope(scope).scopeDigest);assert.equal(published.originDigest,sha(ORIGIN));assert.equal(published.record.status,'enabled');
 await h.fresh(scope);const edgeHit=await h.read();valid(edgeHit,'HIT',0);assert.equal(edgeHit.tier,'EDGE');let e=await events();assert.equal(count(e,'kv_get'),0);assert.equal(count(e,'cache_get'),1);assert.equal(count(e,'cache_put'),0);check('a fresh app instance authorizes from the shared positive cache with zero KV reads');
 const badCases=[
  ['stale',v=>({...v,checkedAtUtcMs:Date.now()-6000})],['future',v=>({...v,checkedAtUtcMs:Date.now()+6000})],['disabled',v=>({...v,record:disabled})],['invalid record',v=>({...v,record:{...enabled,keyId:''}})],['wrong scope',v=>({...v,scopeDigest:'f'.repeat(64)})],['wrong key digest',v=>({...v,keyDigest:'f'.repeat(64)})],['wrong origin',v=>({...v,originDigest:'f'.repeat(64)})],['wrong version',v=>({...v,version:2})],['unknown field',v=>({...v,unexpected:true})],['malformed',()=>'{'],['oversized',v=>JSON.stringify(v)+' '.repeat(1100)],
 ];
 for(let i=0;i<badCases.length;i++){
  const[name,change]=badCases[i];scope='bad-'+i;await h.fresh(scope);await h.setKV(disabled);const modified=change(envelope(scope));await control({seed:{key:keyFor(scope),text:typeof modified==='string'?modified:JSON.stringify(modified)}});const r=await h.read();assert.equal(r.status,401,name+' must not authorize');e=await events();assert.equal(count(e,'cache_get'),1);assert.equal(count(e,'kv_get'),1);assert.equal(count(e,'cache_put'),0);check(name+' shared record falls through to KV without authorizing');
 }
 for(const[name,value,status]of[['missing',null,401],['disabled',disabled,401],['malformed','{',503]]){
  scope='negative-'+name;await h.fresh(scope);await h.setKV(value);assert.equal((await h.read()).status,status);assert.equal((await h.read()).status,status);e=await events();assert.equal(count(e,'kv_get'),2);assert.equal(count(e,'cache_put'),0);check(name+' KV results never enter either positive auth cache');
 }
 for(const mode of ['failGet','failPut']){
  scope='cache-error-'+mode;await h.fresh(scope);await h.setKV(enabled);await control({[mode]:true});valid(await h.read(),'MISS',1);e=await events();assert.equal(count(e,'kv_get'),1);check('Cache API '+mode+' failure preserves valid KV authorization');
 }
 scope='remaining-ttl';await h.fresh(scope);await h.setKV(disabled);const original=Date.now()-4000;await control({seed:{key:keyFor(scope),text:JSON.stringify(envelope(scope,original))}});const promoted=await h.read();valid(promoted,'HIT',0);assert.equal(promoted.tier,'EDGE');await control({failGet:true});const memoryHit=await h.read();valid(memoryHit,'HIT',0);assert.equal(memoryHit.tier,'MEMORY');e=await events();assert.equal(count(e,'cache_get'),1);assert.equal(count(e,'cache_put'),0);await new Promise(r=>setTimeout(r,1150));assert.equal((await h.read()).status,401);e=await events();assert.equal(count(e,'kv_get'),1);check('L2-to-L1 promotion keeps only the original remaining TTL and never republishes');
 scope='slow-kv-anchor';await h.fresh(scope);await h.setKV(enabled);await control({kvDelayMs:1100});const before=Date.now();valid(await h.read(),'MISS',1);await waitPut();const slow=await control({peek:keyFor(scope)});const body=JSON.parse(slow.entry.body);assert.ok(body.checkedAtUtcMs>=before-100&&body.checkedAtUtcMs<=before+200,'expiry starts before the delayed KV operation');assert.match(slow.entry.cacheControl,/max-age=[1-4](?:\D|$)/);check('shared expiry starts at KV read start and slow reads reduce its Cache-Control TTL',{delayMs:1100,cacheControl:slow.entry.cacheControl});
 scope='full-profile';await h.fresh(scope);await h.setKV(enabled);valid(await h.read(),'MISS',1);await waitPut();valid(await h.read(),'HIT',0);const beforeBypass=await events();valid(await h.read(true),'BYPASS',1);e=await events();assert.equal(count(e,'cache_get'),count(beforeBypass,'cache_get'));assert.equal(count(e,'cache_put'),count(beforeBypass,'cache_put'));assert.equal(count(e,'kv_get'),2);check('full profile bypasses both auth caches and still performs exactly one KV read');
 receipt.status='PASS';receipt.completedAt=new Date().toISOString();
}catch(error){receipt.status='FAIL';receipt.failure={name:error.name,message:error.message};throw error;}finally{await h.close();if(values.receipt){await mkdir(dirname(resolve(values.receipt)),{recursive:true});await writeFile(resolve(values.receipt),JSON.stringify(receipt,null,2)+'\n');}}
console.log(JSON.stringify({status:receipt.status,checks:receipt.checks.length,wasmSha256:receipt.wasmSha256}));
