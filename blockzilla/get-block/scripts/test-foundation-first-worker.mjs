#!/usr/bin/env node
// Actual release-WASM routes with a local disk-service stub and exact windows.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir, copyFile, mkdtemp, rm } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { parseArgs } from 'node:util';
import { fixturePath } from './fixture-inputs.mjs';
import { zstdDecompressSync } from 'node:zlib';
import * as miniflare from 'miniflare';
import { decodeResolution, decodeV1Bundle } from './bench-resolution-client.mjs';
import { canonicalBlockDigest } from './bench-get-block.mjs';

const PACKAGE = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ROOT = resolve(PACKAGE, '../..');
const OWNER = 'foundation-first-local-owner', BROKER = 'foundation-first-local-broker';
const ORIGIN = 'https://foundation-owner.test';
const KEY = 'bz_live_foundation_first_local_abcdefghijklmnopqrstuvwxyz0123456789';
const SECRET = 'foundation_first_internal_fixture_abcdefghijklmnopqrstuvwxyz0123456789';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

function unsigned(bytes, cursor) {
  let value = 0n, shift = 0n, byte;
  do {
    assert.ok(cursor.offset < bytes.length && shift <= 63n);
    byte = bytes[cursor.offset++]; value |= BigInt(byte & 127) << shift; shift += 7n;
  } while (byte & 128);
  assert.ok(value <= BigInt(Number.MAX_SAFE_INTEGER)); return Number(value);
}

// Read independent ID sets from the original admitted access dictionary. Hot
// header IDs come from the original decompressed frame, not the POST request.
function expectedReferences(resolution, hot) {
  const bytes = resolution.suffix, cursor = { offset: 0 }, pubkeys = [], blockhashes = [], votes = [];
  const skipHash = () => { assert.ok(cursor.offset + 32 <= bytes.length); cursor.offset += 32; };
  for (let count = unsigned(bytes, cursor); count > 0; count--) { pubkeys.push(unsigned(bytes, cursor)); skipHash(); }
  for (let count = unsigned(bytes, cursor); count > 0; count--) {
    const zigzag = unsigned(bytes, cursor); blockhashes.push(zigzag % 2 ? -(zigzag + 1) / 2 : zigzag / 2); skipHash();
  }
  const optionHash = () => { const present = bytes[cursor.offset++]; assert.ok(present === 0 || present === 1); if (present) skipHash(); return !!present; };
  for (let count = unsigned(bytes, cursor); count > 0; count--) votes.push({ block_id: unsigned(bytes, cursor), bank_hash: optionHash(), block_id_hash: optionHash() });
  assert.equal(cursor.offset, bytes.length);
  const raw = zstdDecompressSync(hot, { maxOutputLength: 32 * 1024 * 1024 }), header = { offset: 0 };
  return { slot: unsigned(raw, header), parent_slot: unsigned(raw, header), blockhash_id: unsigned(raw, header),
    previous_blockhash_id: unsigned(raw, header), signature_counts: [...resolution.signatureCounts], pubkeys, blockhashes, votes };
}

// This reply keeps valid outer and inner hashes, lengths and source metadata.
// Only the resolved current-ID value disagrees with the decoded hot header.
function wrongHeaderHash(resolution, currentId) {
  const bytes = Buffer.from(resolution), cursor = { offset: bytes.readUInt32LE(28) };
  for (let count = unsigned(bytes, cursor); count > 0; count--) { unsigned(bytes, cursor); cursor.offset += 32; }
  let changed = false;
  for (let count = unsigned(bytes, cursor); count > 0; count--) {
    const encoded = unsigned(bytes, cursor), id = encoded % 2 ? -(encoded + 1) / 2 : encoded / 2;
    if (id === currentId) { bytes[cursor.offset] ^= 1; changed = true; }
    cursor.offset += 32;
  }
  assert.ok(changed); createHash('sha256').update(bytes.subarray(96)).digest().copy(bytes, 56);
  decodeResolution(bytes); return bytes;
}

function wrongSourceIdentity(resolution, etag) {
  const bytes = Buffer.from(resolution), old = Buffer.from(etag), changed = Buffer.from(etag);
  changed[1] = changed[1] === 97 ? 98 : 97;
  let found = 0, at = 0;
  while ((at = bytes.indexOf(old, at)) !== -1) { changed.copy(bytes, at); at += old.length; found++; }
  assert.ok(found >= 2, 'locator and named source identity must both change');
  createHash('sha256').update(bytes.subarray(96)).digest().copy(bytes, 56);
  decodeResolution(bytes); return bytes;
}

const pendingLocator = locator => ({ version: locator.version, source_prefix: locator.sourcePrefix, generation: locator.generation,
  epoch: locator.epoch, hot: locator.hot, message_schema: locator.messageSchema, metadata_schema: locator.metadataSchema,
  blocks: locator.blocks, signatures: locator.signatures });

const OWNER_ADAPTER = String.raw`
import worker from './index.js';
const specs=SPECS,byKey=new Map();
for(const spec of specs)for(const window of spec.windows){const key=spec.sourcePrefix+'/epoch-1089/'+window.file;if(!byKey.has(key))byKey.set(key,[]);byKey.get(key).push(window);}
let state={scope:'initial',mode:'complete',disabled:false,rawBinary:false,events:[],active:0,maximum:0};
function observedBody(body,row){
 const owner=state,reader=body.getReader();let delivered=0,extra=false,releaseStall;
 const fault=owner.rawBinary&&row.file==='archive-v2-blocks.zstd'?owner.mode.replace(/^resolve-source-/,''):null;
 return new ReadableStream({async pull(controller){
  if(fault==='error'){owner.events.push({kind:'source_fault',file:row.file,fault});controller.error(Error('Fixture source read error'));void reader.cancel('fixture injected read error');return;}
  if(fault==='stall'){owner.events.push({kind:'source_fault',file:row.file,fault});return new Promise(done=>{releaseStall=done;});}
  try{
   const result=await reader.read();
   if(result.done){if(fault==='long'&&!extra){extra=true;owner.events.push({kind:'source_fault',file:row.file,fault});controller.enqueue(new Uint8Array([0]));return;}controller.close();return;}
   let value=result.value;
   if(fault==='short'){
    const remaining=Math.max(0,row.length-1-delivered);if(value.byteLength>remaining)value=value.subarray(0,remaining);
    delivered+=value.byteLength;if(value.byteLength)controller.enqueue(value);
    if(delivered===row.length-1){owner.events.push({kind:'source_fault',file:row.file,fault});controller.close();void reader.cancel('fixture shortened EOF');}return;
   }
   controller.enqueue(value);
  }catch(error){controller.error(error);}
 },cancel(reason){owner.events.push({kind:'source_cancel',file:row.file,reason:String(reason).slice(0,100)});releaseStall?.();return reader.cancel(reason);}}, {highWaterMark:0});
}
export default{async fetch(request,env,ctx){
 const path=new URL(request.url).pathname;
 if(path==='/__foundation/control'){
  const command=await request.json();state={scope:command.scope,mode:command.mode,disabled:!!command.disabled,rawBinary:!!command.rawBinary,probeEnabled:!!command.probeEnabled,events:[],active:0,maximum:0};
  await env.TEST_BROKER.fetch('https://foundation.test/__control',{method:'POST',body:JSON.stringify(command)});
  return Response.json({scope:state.scope});
 }
 if(path==='/__foundation/stats'){
  const response=await env.TEST_BROKER.fetch('https://foundation.test/__stats');
  return Response.json({events:state.events,maximum:state.maximum,broker:await response.json()});
 }
 const ranges={async get(key,options){
  const choices=byKey.get(key),row=choices?.find(r=>options?.range?.offset===r.offset&&options?.range?.length===r.length);
  if(!row||options.onlyIf?.etagMatches!==row.sourceEtag.slice(1,-1))throw Error('Unexpected archive range or ETag');
  state.events.push({kind:'source_get',file:row.file,active:++state.active});state.maximum=Math.max(state.maximum,state.active);
  try{
   await new Promise(r=>setTimeout(r,20));
   const object=await env.LOCAL_WINDOWS.get(row.localKey,{range:{offset:0,length:row.length},onlyIf:{etagMatches:row.localEtag.slice(1,-1)}});
   if(!object||!object.body||object.size!==row.length||object.httpEtag!==row.localEtag)throw Error('Missing exact local window');
   return{key,version:object.version,size:row.sourceLength,etag:row.sourceEtag.slice(1,-1),httpEtag:row.sourceEtag,
    uploaded:object.uploaded,httpMetadata:object.httpMetadata,customMetadata:object.customMetadata,checksums:object.checksums,
    storageClass:object.storageClass,range:{offset:row.offset,length:row.length},body:observedBody(object.body,row),bodyUsed:false};
  }finally{--state.active;}
 },async head(){state.events.push({kind:'source_head'});throw Error('Unexpected archive HEAD');}};
 const resolution={async get(...args){state.events.push({kind:'resolution_get'});return env.BZ_RESOLUTION.get(...args);},async head(){throw Error('Unexpected resolution HEAD');}};
 Object.setPrototypeOf(ranges,Object.getPrototypeOf(env.LOCAL_WINDOWS));Object.setPrototypeOf(resolution,Object.getPrototypeOf(env.BZ_RESOLUTION));
 const lookup=state.disabled?{}:{BZ_FOUNDATION_LOOKUP_URL:'https://foundation.test',BZ_FOUNDATION_LOOKUP_SECRET:env.TEST_SECRET,
  BZ_FOUNDATION_LOOKUP_GENERATION:env.BZ_RESOLUTION_GENERATION,BZ_FOUNDATION_LOOKUP_TIMEOUT_MS:state.mode.endsWith('timeout')?'100':'500',
  BZ_FOUNDATION_LOOKUP_BODY_TIMEOUT_MS:state.mode.endsWith('resolution-stall')||state.mode.endsWith('source-stall')?'100':'5000',
  BZ_FOUNDATION_BINARY_RESOLVE_MODE:state.rawBinary?'block':'ids'};
 return new worker(ctx,{...env,...lookup,BZ_R2_PROBE_ENABLED:state.probeEnabled?'true':'false',BZ_ARCHIVE_GENERATION:state.scope,BZ_ARCHIVE_BUCKET:ranges,BZ_RESOLUTION:resolution}).fetch(request);
}};
`;

const BROKER_ADAPTER = String.raw`
const specs=SPECS;
let state={mode:'complete',events:[]};
const sha=async bytes=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),b=>b.toString(16).padStart(2,'0')).join('');
const stable=v=>Array.isArray(v)?v.map(stable):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,stable(v[k])])):v;
const equal=(a,b)=>JSON.stringify(stable(a))===JSON.stringify(stable(b));
export default{async fetch(request,env,ctx){
 const url=new URL(request.url);
 if(url.pathname==='/__control'){const c=await request.json();state={mode:c.mode,events:[]};return new Response(null,{status:204});}
 if(url.pathname==='/__stats')return Response.json(state);
 const rawMatch=/^\/v1\/resolve-block\/([0-9]+)$/.exec(url.pathname);
 const rawResolving=!!rawMatch, resolving=rawResolving||url.pathname==='/v1/resolve';
 let requestBytes,requestBody,requestDigest;
 if(resolving){requestBytes=new Uint8Array(await request.arrayBuffer());requestDigest=await sha(requestBytes);if(!rawResolving)requestBody=JSON.parse(new TextDecoder().decode(requestBytes));}
 const spec=specs.find(s=>rawResolving?s.slot===Number(rawMatch[1]):resolving?s.slot===requestBody?.references?.slot:url.pathname==='/v1/block/'+s.slot);
 const authorized=request.headers.get('Authorization')==='Bearer '+env.TEST_SECRET;
 const event={path:url.pathname,authorized,method:request.method,readMode:request.headers.get('X-BZ-Foundation-Read-Mode'),
  protocol:request.headers.get('X-BZ-Foundation-Protocol'),generation:request.headers.get('X-BZ-Foundation-Generation'),
  acceptEncoding:request.headers.get('Accept-Encoding'),customerKeyForwarded:request.headers.get('Authorization')==='Bearer '+env.TEST_API_KEY};
 state.events.push(event);
 if(!spec||url.origin!=='https://foundation.test')return new Response(null,{status:403});
 if(resolving){
  event.requestKind=rawResolving?'raw_hot':'typed_ids';
  event.requestValidated=request.method==='POST'&&requestBytes.length<=(rawResolving?16:4)*1024*1024
   &&request.headers.get('Content-Type')===(rawResolving?'application/vnd.blockzilla.compact-v2-hot.zstd':'application/vnd.blockzilla.resolve-ids+json')
   &&request.headers.get('X-BZ-Foundation-Request-SHA256')===requestDigest
   &&request.headers.get('X-BZ-Foundation-Source-Prefix')===spec.sourcePrefix
   &&request.headers.get('X-BZ-Foundation-Generation')===spec.generation
   &&(rawResolving?requestDigest===spec.hotSha&&requestBytes.length===spec.pending.hot.compressed_len
    :equal(requestBody,{version:1,source:spec.pending,hot_sha256:spec.hotSha,references:spec.references}));
  event.requestSha256=requestDigest;event.requestBytes=requestBytes.length;
  event.referenceCounts=rawResolving?undefined:{pubkeys:requestBody.references?.pubkeys?.length,blockhashes:requestBody.references?.blockhashes?.length,votes:requestBody.references?.votes?.length};
  if(!event.requestValidated)return new Response('POST does not match independently saved source IDs',{status:400});
 }
 const mode=resolving&&state.mode.startsWith('resolve-')?state.mode.slice(8):state.mode;
 if(!authorized||mode==='auth-failure')return new Response(null,{status:403});
 if(mode==='redirect')return new Response(null,{status:307,headers:{Location:'https://outside.test/collect'}});
 if(mode==='unavailable-server')return new Response(null,{status:503});
 if(mode==='timeout'){await new Promise(r=>setTimeout(r,250));return new Response(null,{status:503});}
 let result=resolving||state.mode.startsWith('resolution')?'resolution':'complete';
 let body,contentType,digest,status=200;
 if(!resolving&&(state.mode.startsWith('resolve-')||state.mode.startsWith('not-cached'))){
  result='not_cached';status=404;contentType='application/json';
  const source=state.mode==='not-cached-no-source'?undefined:structuredClone(spec.pending);
  if(state.mode==='not-cached-wrong-source')source.source_prefix='compact-v2/wrong';
  body=new TextEncoder().encode(JSON.stringify({version:1,slot:spec.slot,reason:'not_cached',source}));digest=await sha(body);
 }else if(mode==='unavailable'){
  result='unavailable';status=404;contentType='application/json';body=new TextEncoder().encode(JSON.stringify({version:1,slot:spec.slot,reason:'coverage_unavailable'}));digest=await sha(body);
 }else{
  const object=await env.FIXTURES.get('broker/'+spec.slot+(result==='complete'?'.bin':mode==='wrong-header-hash'?'.wrong-header-hash':mode==='wrong-source-body'?'.wrong-source':'.resolution'));
  body=new Uint8Array(await object.arrayBuffer());contentType=result==='complete'?'application/vnd.blockzilla.get-block-bundle.wincode':'application/vnd.blockzilla.slot-resolution.wincode';
  digest=['wrong-header-hash','wrong-source-body'].includes(mode)?await sha(body):result==='complete'?spec.bundleSha:spec.resolutionSha;
 }
 if(mode==='rehash-corrupt'){body[body.length-1]^=1;digest=await sha(body);}
 const length=body.byteLength;
 const headers=new Headers({'Content-Type':contentType,'Content-Length':String(length),'X-BZ-Foundation-Protocol':'1',
  'X-BZ-Foundation-Generation':spec.generation,'X-BZ-Foundation-Source-Prefix':spec.sourcePrefix,'X-BZ-Foundation-Result':result,
  'X-BZ-Foundation-SHA256':digest,'X-BZ-Foundation-Commitment':'finalized','X-BZ-Foundation-Locator':spec.locatorHeader,
  'X-BZ-Foundation-Signatures':result==='complete'?'embedded':'archive','X-BZ-Foundation-Object-Verified':'sha256'});
 if(resolving)headers.set('X-BZ-Foundation-Request-SHA256',requestDigest);
 if(resolving&&result==='resolution'){
  headers.set('X-BZ-Foundation-Cache',request.headers.get('X-BZ-Foundation-Read-Mode')==='full-cold'?'BYPASS':'MISS');
  headers.set('X-BZ-Foundation-Pread-Calls','17');headers.set('X-BZ-Foundation-Pread-Bytes','1234');
  headers.set('X-BZ-Foundation-Resolve-Micros','50');
  if(mode==='bad-diagnostics')headers.set('X-BZ-Foundation-Pread-Calls','017');
 }
 if(mode==='wrong-request-sha')headers.set('X-BZ-Foundation-Request-SHA256','00'.repeat(32));
 if(mode==='missing-request-sha')headers.delete('X-BZ-Foundation-Request-SHA256');
 if(mode==='wrong-generation')headers.set('X-BZ-Foundation-Generation','wrong');
 if(mode==='wrong-prefix')headers.set('X-BZ-Foundation-Source-Prefix','compact-v2/wrong');
 if(mode==='wrong-locator')headers.set('X-BZ-Foundation-Locator',specs.find(s=>s.slot!==spec.slot).locatorHeader);
 if(mode==='wrong-source-body')headers.set('X-BZ-Foundation-Locator',spec.wrongSourceLocatorHeader);
 if(mode==='malformed-digest')headers.set('X-BZ-Foundation-SHA256','bad');
 if(mode==='corrupt-complete'||mode==='resolution-corrupt')body[0]^=1;
 if(mode==='short-complete')body=body.subarray(0,-1);
 if(mode==='resolution-stall'){
  const start=body.subarray(0,32);body=new ReadableStream({start(c){c.enqueue(start);},pull(){return new Promise(()=>{});}});
 }else{const bytes=body;body=new ReadableStream({start(c){c.enqueue(bytes);c.close();}});}
 const fixed=new FixedLengthStream(length);
 ctx.waitUntil(body.pipeTo(fixed.writable).catch(()=>{}));
 return new Response(fixed.readable,{status,headers});
}};
`;

export async function createFoundationFirstHarness(build, { fixtureRoot, onProgress = () => {}, ownerTransform = text => text,
  brokerTransform = text => text, ownerBindings = {} } = {}) {
  const verification = JSON.parse(await readFile(fixturePath(fixtureRoot, 'verification.json'), 'utf8'));
  const reference = JSON.parse(await readFile(fixturePath(fixtureRoot, 'reference-base64.json'), 'utf8'));
  assert.equal(verification.status, 'REMOTE_VERIFIED');
  const temporary = await mkdtemp(join(tmpdir(), 'blockzilla-foundation-first-'));
  const specs = [];
  for (const record of verification.resolutionObjects) {
    const resolution = await readFile(record.localPath), decodedResolution = decodeResolution(resolution, record.slot);
    const bundle = await readFile(fixturePath(fixtureRoot, 'inputs', `${record.slot}.bundle.wincode`));
    const parsed = decodeV1Bundle(bundle), locator = decodedResolution.locator;
    const windows = [['archive-v2-blocks.zstd', locator.hot.compressed_offset, parsed.hot, locator.blocks],
      ['signatures.bin', locator.hot.first_signature_ordinal * 64, parsed.signatures, locator.signatures]]
      .map(([file, offset, bytes, identity]) => ({ file, offset, bytes, length: bytes.length, localKey: `windows/${record.slot}/${file}`,
        localEtag: `"${createHash('md5').update(bytes).digest('hex')}"`, sourceLength: identity.length, sourceEtag: identity.etag }));
    specs.push({ slot: record.slot, sourcePrefix: locator.sourcePrefix, generation: locator.generation,
      resolutionKey: record.key, resolution, bundle, windows, bundleSha: sha(bundle), resolutionSha: sha(resolution),
      pending: pendingLocator(locator), references: expectedReferences(decodedResolution, parsed.hot), hotSha: sha(parsed.hot),
      locatorHeader: decodedResolution.locatorBytes.toString('base64url'),
      wrongSourceLocatorHeader: decodeResolution(wrongSourceIdentity(resolution, locator.blocks.etag)).locatorBytes.toString('base64url'),
      referenceDigest: reference.samples.find(row => row.slot === record.slot).contentSha256 });
  }
  const publicSpecs = specs.map(({ resolution, bundle, windows, ...row }) => ({ ...row, windows: windows.map(({ bytes, ...window }) => window) }));
  const ownerModule = join(temporary, 'owner.mjs'), brokerModule = join(temporary, 'broker.mjs');
  await writeFile(ownerModule, ownerTransform(OWNER_ADAPTER.replace('SPECS', JSON.stringify(publicSpecs))));
  await writeFile(brokerModule, brokerTransform(BROKER_ADAPTER.replace('SPECS', JSON.stringify(publicSpecs))));
  await copyFile(resolve(build), join(temporary, 'index.js')); await copyFile(join(dirname(resolve(build)), 'index_bg.wasm'), join(temporary, 'index_bg.wasm'));
  const configuration = { resourcePersistencePath: join(temporary, 'storage'), telemetry: { enabled: false }, inspectorPort: 0,
    workers: [{ name: OWNER, modulesRoot: temporary, compatibilityDate: '2026-09-10',
      modules: [{ type: 'ESModule', path: ownerModule }, { type: 'ESModule', path: join(temporary, 'index.js') }, { type: 'CompiledWasm', path: join(temporary, 'index_bg.wasm') }],
      outboundService: BROKER, serviceBindings: { TEST_BROKER: BROKER },
      bindings: { BZ_ARCHIVE_SOURCE: 'r2', BZ_ARCHIVE_LAYOUT: 'stored', BZ_ARCHIVE_PREFIX: verification.sourcePrefix,
        BZ_ARCHIVE_GENERATION: 'initial', BZ_HTTP_GET_ONLY: 'true', BZ_AUTH_CACHE_SCOPE: 'foundation-first-local-auth',
        BZ_RESOLUTION_PREFIX: verification.resolutionPrefix, BZ_RESOLUTION_GENERATION: verification.generation,
        BZ_RESOLUTION_SLOTS: specs.map(s => s.slot).join(','), BZ_LOCATOR_SECRET: 'local_foundation_locator_fixture_abcdefghijklmnopqrstuvwxyz', TEST_SECRET: SECRET,
        ...ownerBindings },
      r2Buckets: { LOCAL_WINDOWS: 'foundation-first-windows', BZ_RESOLUTION: 'foundation-first-resolutions' },
      kvNamespaces: { BZ_RPC_API_KEYS: 'foundation-first-auth' }, analyticsEngineDatasets: { BZ_RPC_METRICS: { dataset: 'foundation_first_local_metrics' } },
    }, { name: BROKER, modulesRoot: temporary, compatibilityDate: '2026-09-10',
      modules: [{ type: 'ESModule', path: brokerModule }], bindings: { TEST_SECRET: SECRET, TEST_API_KEY: KEY },
      r2Buckets: { FIXTURES: 'foundation-first-fixtures' } }] };
  const mf = new miniflare.Miniflare(typeof miniflare.convertV4MiniflareOptions === 'function' ? miniflare.convertV4MiniflareOptions(configuration) : configuration);
  onProgress('Starting local Worker runtime');
  await mf.ready;
  onProgress('Loading original block windows');
  const windows = await mf.getR2Bucket('LOCAL_WINDOWS', OWNER), resolutions = await mf.getR2Bucket('BZ_RESOLUTION', OWNER), fixtures = await mf.getR2Bucket('FIXTURES', BROKER);
  for (const spec of specs) {
    for (const window of spec.windows) await windows.put(window.localKey, window.bytes);
    await resolutions.put(spec.resolutionKey, spec.resolution); await fixtures.put(`broker/${spec.slot}.bin`, spec.bundle); await fixtures.put(`broker/${spec.slot}.resolution`, spec.resolution);
    await fixtures.put(`broker/${spec.slot}.wrong-header-hash`, wrongHeaderHash(spec.resolution, spec.references.blockhash_id));
    await fixtures.put(`broker/${spec.slot}.wrong-source`, wrongSourceIdentity(spec.resolution, spec.pending.blocks.etag));
  }
  await (await mf.getKVNamespace('BZ_RPC_API_KEYS', OWNER)).put(sha(KEY), JSON.stringify({ keyId: 'foundation_first_local', customerId: 'local', label: 'Local Foundation route test', status: 'enabled' }));
  onProgress('Local fixtures are ready');
  let serial = 0;
  const request = (path, options = {}) => mf.dispatchFetch(ORIGIN + path, { ...options, headers: { Authorization: `Bearer ${KEY}`, ...options.headers } });
  const control = async (mode, options = {}) => { const response = await request('/__foundation/control', { method: 'POST', body: JSON.stringify({ mode, scope: `case-${++serial}`, ...options }) }); assert.equal(response.status, 200); };
  const stats = async () => (await request('/__foundation/stats')).json();
  const read = async (slot, kind, options = {}) => {
    const spec = specs.find(row => row.slot === slot); assert.ok(spec);
    const response = await request(`/block/${slot}.${kind}?rewards=false${options.normal ? '' : options.sourceProfile ? '&profile=source' : '&profile=1'}`);
    const headers = Object.fromEntries(response.headers); let bytes;
    try { bytes = Buffer.from(await response.arrayBuffer()); }
    catch (error) { if (options.expectStreamFailure) return { slot, kind, status: response.status, headers, streamFailed: true }; throw error; }
    assert.ok(!options.expectStreamFailure, 'expected binary stream failure');
    assert.equal(response.status, options.status ?? 200, bytes.toString().slice(0, 250));
    if (response.status === 200) {
      if (kind === 'json') assert.equal(canonicalBlockDigest(bytes.toString()), spec.referenceDigest);
      else assert.equal(sha(bytes), spec.bundleSha);
    }
    return { slot, kind, status: response.status, bytes: bytes.length, sha256: sha(bytes), headers };
  };
  return { mf, specs, slots: specs.map(s => s.slot), control, stats, read, request,
    artifact: { build: resolve(build), wasmSha256: sha(await readFile(join(temporary, 'index_bg.wasm'))), compatibilityDate: '2026-09-10' },
    async close() { await mf.dispose(); await rm(temporary, { recursive: true, force: true }); } };
}

async function main() {
  const { values } = parseArgs({ options: { 'fixture-root': { type: 'string' }, build: { type: 'string' }, receipt: { type: 'string', default: 'profile-output/worker-acceptance.json' } } });
  assert.ok(values.build, '--build frozen/index.js is required');
  const h = await createFoundationFirstHarness(values.build, { fixtureRoot: values['fixture-root'], onProgress: message => console.log(message) }), checks = [], reads = [];
  const counter = (row, name) => Number(row.headers[name.toLowerCase()] ?? 0);
  const check = async (name, row, expectedGets, expectedBroker, expectedResolve = 0) => {
    assert.equal(counter(row, 'X-Blockzilla-R2-GETs'), expectedGets, name);
    assert.equal(counter(row, 'X-Blockzilla-R2-HEADs'), 0, name);
    assert.equal(counter(row, 'X-Blockzilla-Foundation-Lookup-HTTP-Requests'), expectedBroker - expectedResolve, name + ' lookup GETs');
    assert.equal(counter(row, 'X-Blockzilla-Foundation-Resolve-HTTP-Requests'), expectedResolve, name + ' resolve POSTs');
    const stats = await h.stats();
    assert.ok(stats.broker.events.every(e => e.authorized && !e.customerKeyForwarded
      && (e.method === 'GET' || (e.method === 'POST' && (e.path === '/v1/resolve' || /^\/v1\/resolve-block\/[0-9]+$/.test(e.path)) && e.requestValidated))));
    if (row.status === 200 && row.headers['x-bz-profile'] && expectedResolve) {
      const diagnostic = JSON.parse(row.headers['x-bz-profile']).events.find(e => e.name === 'foundation_resolve_cache');
      if (stats.broker.mode === 'resolve-bad-diagnostics') assert.equal(diagnostic, undefined);
      else { assert.equal(diagnostic?.bytes, 1234); assert.match(diagnostic.detail, /cache=(MISS|BYPASS);pread_calls=17;resolve_us=50/); }
    }
    reads.push(row); checks.push({ name, slot: row.slot, kind: row.kind, status: row.status, gets: expectedGets,
      broker: expectedBroker, lookup: expectedBroker - expectedResolve, resolve: expectedResolve, observed: stats });
  };
  try {
    for (const mode of ['complete', 'resolution']) for (const slot of h.slots) for (const kind of ['json', 'bin']) {
      await h.control(mode); const row = await h.read(slot, kind); await check(`${mode} ${kind} exact`, row, mode === 'complete' ? 0 : 2, 1);
      if (mode === 'resolution') { const s = await h.stats(); assert.equal(s.events.filter(e => e.kind === 'resolution_get').length, 0); assert.equal(s.maximum, 2, 'archive windows must start together'); }
    }
    const slot = h.slots[0];
    for (const slot of h.slots) for (const kind of ['json', 'bin']) {
      await h.control('resolve-normal'); await check('cache miss resolves exact hot-frame typed IDs', await h.read(slot, kind), 2, 2, 1);
      const s = await h.stats(); assert.equal(s.events.filter(e => e.kind === 'resolution_get').length, 0);
      assert.equal(s.maximum, 2, 'cold hot/signature reads must start together');
      assert.equal(s.broker.events.filter(e => e.method === 'POST' && e.requestValidated).length, 1);
    }
    for (const slot of h.slots) {
      await h.control('resolve-normal', { rawBinary: true });
      const row = await h.read(slot, 'bin'); await check('raw native hot POST preserves original binary payload', row, 2, 2, 1);
      const s = await h.stats(), posted = s.broker.events.find(e => e.method === 'POST');
      assert.equal(posted.requestKind, 'raw_hot'); assert.equal(posted.requestValidated, true);
      assert.equal(posted.requestSha256, h.specs.find(spec => spec.slot === slot).hotSha);
      assert.equal(s.maximum, 2, 'raw binary source requests must overlap');
      const profile = JSON.parse(row.headers['x-bz-profile']);
      assert.ok(!profile.events.some(e => e.name === 'stored_block_decode' || e.name === 'foundation_collect_ids'), 'raw binary must not decode hot bytes or collect IDs in WASM');
    }
    await h.control('resolve-normal', { rawBinary: true });
    await check('JSON keeps typed ID transport when raw binary is enabled', await h.read(slot, 'json'), 2, 2, 1);
    assert.equal((await h.stats()).broker.events.find(e => e.method === 'POST').requestKind, 'typed_ids');
    for (const mode of ['wrong-request-sha', 'wrong-prefix', 'wrong-source-body', 'resolution-corrupt', 'rehash-corrupt', 'unavailable-server', 'resolution-stall']) {
      await h.control('resolve-' + mode, { rawBinary: true });
      await check(`raw binary ${mode} fails before output`, await h.read(slot, 'bin', { status: 502 }), 2, 2, 1);
      assert.equal((await h.stats()).broker.events.find(e => e.method === 'POST').requestKind, 'raw_hot');
    }
    for (const fault of ['short', 'long', 'error', 'stall']) {
      await h.control('resolve-source-' + fault, { rawBinary: true });
      const row = await h.read(slot, 'bin', { status: 502 });
      await check(`native hot ${fault} rejects before broker POST`, row, 2, 1, 0);
      let observed = await h.stats();
      for (let attempt = 0; attempt < 5 && !observed.events.some(e => e.kind === 'source_cancel'); attempt++) {
        await new Promise(done => setTimeout(done, 20)); observed = await h.stats();
      }
      assert.equal(observed.broker.events.filter(e => e.method === 'POST').length, 0);
      assert.ok(observed.events.some(e => e.kind === 'source_fault' && e.fault === fault));
      assert.ok(observed.events.some(e => e.kind === 'source_cancel'), 'hash failure must cancel the unconsumed source branch');
      assert.equal(Number(row.headers['x-blockzilla-archive-memory-hits']), 0);
      assert.equal(Number(row.headers['x-blockzilla-archive-edge-hits']), 0);
      assert.ok(!JSON.parse(row.headers['x-bz-profile']).events.some(e => e.name === 'stored_block_decode' || e.name === 'foundation_collect_ids'));
    }
    for (const kind of ['json', 'bin']) {
      await h.control('not-cached-wrong-source'); await check('pending cache miss source pin fails closed', await h.read(slot, kind, { status: 502 }), 0, 1);
      await h.control('not-cached-no-source'); await check('legacy cache miss keeps existing archive fallback', await h.read(slot, kind), 3, 1);
      await h.control('resolve-bad-diagnostics'); await check('malformed optional broker diagnostics do not affect block admission', await h.read(slot, kind), 2, 2, 1);
      for (const mode of ['wrong-request-sha', 'missing-request-sha', 'wrong-generation', 'wrong-prefix', 'wrong-locator', 'malformed-digest', 'auth-failure', 'redirect', 'resolution-corrupt', 'rehash-corrupt', 'wrong-header-hash']) {
        await h.control('resolve-' + mode); await check(`ID resolution ${mode} fails closed`, await h.read(slot, kind, { status: 502 }), 2, 2, 1);
        if (mode === 'redirect') assert.equal((await h.stats()).broker.events.length, 2, 'POST redirect must not forward the internal secret');
      }
      for (const mode of ['timeout', 'unavailable-server', 'resolution-stall']) {
        await h.control('resolve-' + mode); await check(`ID resolution ${mode} does not repeat archive reads`, await h.read(slot, kind, { status: 502 }), 2, 2, 1);
      }
      await h.control('resolve-normal');
      await check('first source profile loads small pending route', await h.read(slot, kind, { sourceProfile: true }), 2, 2, 1);
      await new Promise(r => setTimeout(r, 150));
      await check('pending route hit skips lookup and still reads both archive ranges', await h.read(slot, kind, { sourceProfile: true }), 2, 1, 1);
      assert.equal((await h.stats()).broker.events.filter(e => e.method === 'GET').length, 1);
      await check('full cold bypasses a populated pending route cache', await h.read(slot, kind), 2, 2, 1);
      assert.equal((await h.stats()).broker.events.filter(e => e.method === 'GET').length, 2);
      await h.control('resolve-normal'); await h.read(slot, kind, { normal: true }); await new Promise(r => setTimeout(r, 150));
      const hit = await h.read(slot, kind, { normal: true }); assert.equal(hit.headers['x-blockzilla-cache'], 'HIT');
      await check('resolved response cache hit avoids lookup resolve and archive', hit, 0, 0);
    }
    for (const mode of ['timeout', 'unavailable-server', 'resolution-stall']) for (const kind of ['json', 'bin']) {
      await h.control(mode); await check(`${mode} uses existing archive fallback`, await h.read(slot, kind), 3, 1);
    }
    for (const kind of ['json', 'bin']) {
      await h.control('unavailable'); await check('typed unavailable has no archive read', await h.read(slot, kind, { status: 404 }), 0, 1);
    }
    for (const mode of ['wrong-generation', 'wrong-prefix', 'wrong-locator', 'malformed-digest', 'auth-failure', 'redirect', 'resolution-corrupt']) for (const kind of ['json', 'bin']) {
      await h.control(mode); await check(`${mode} fails closed`, await h.read(slot, kind, { status: 502 }), 0, 1);
      if (mode === 'redirect') assert.equal((await h.stats()).broker.events.length, 1, 'redirect must not forward the internal secret');
    }
    await h.control('corrupt-complete'); await check('JSON complete body SHA is checked', await h.read(slot, 'json', { status: 502 }), 0, 1);
    await h.control('short-complete'); const short = await h.read(slot, 'bin', { expectStreamFailure: true }); assert.equal(short.streamFailed, true); await check('short binary body cannot complete', short, 0, 1);
    for (const kind of ['json', 'bin']) {
      await h.control('complete'); await h.read(slot, kind, { normal: true }); await new Promise(r => setTimeout(r, 150));
      const hit = await h.read(slot, kind, { normal: true }); assert.equal(hit.headers['x-blockzilla-cache'], 'HIT');
      await check('complete response hit avoids broker and R2', hit, 0, 0); assert.equal((await h.stats()).broker.events.length, 1);
    }
    for (const kind of ['json', 'bin']) {
      await h.control('complete', { disabled: true }); await check('absent config keeps previous path', await h.read(slot, kind), 3, 0); assert.equal((await h.stats()).broker.events.length, 0);
    }
    const report = { status: 'PASS', artifact: h.artifact, checks, reads,
      scope: 'Actual release WASM with local authenticated Foundation HTTP stub and synthetic original archive windows. No cloud call, deployment or hosted latency claim.',
      limits: ['Binary trusts authenticated preverified-object digest metadata; the client checks original payload hashes.', 'JSON checks delivered complete body SHA before decoding.', 'The local broker fixture uses local R2 only as test storage; it models production disk files, not a Foundation R2 operation.'] };
    const path = resolve(values.receipt); await mkdir(dirname(path), { recursive: true }); await writeFile(path, `${JSON.stringify(report, null, 2)}\n`);
    console.log(JSON.stringify({ status: report.status, checks: checks.length, wasmSha256: report.artifact.wasmSha256, receipt: path }));
  } finally { await h.close(); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(error => { console.error(error); process.exitCode = 1; });
