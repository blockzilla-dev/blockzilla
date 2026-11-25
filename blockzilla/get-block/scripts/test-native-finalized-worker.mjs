#!/usr/bin/env node
// Actual WASM native-frame JSON tests. All data and services are local fixtures.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { createFoundationFirstHarness } from './test-foundation-first-worker.mjs';
import { canonicalBlockDigest } from './bench-get-block.mjs';

const ORIGIN = 'https://foundation-owner.test';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const checks = [];

const NATIVE_TRANSPORT = String.raw`
const nativeUnderlyingFetch=globalThis.fetch.bind(globalThis);
globalThis.fetch=(input,init)=>{
 const target=typeof input==='string'?input:input?.url;
 if(state.mode==='native-network-error'&&target&&new URL(target).pathname.startsWith('/v1/finalized/')){
  state.events.push({kind:'native_transport_failure',path:new URL(target).pathname});
  return Promise.reject(new TypeError('Synthetic native network failure'));
 }
 return nativeUnderlyingFetch(input,init);
};
`;

const NATIVE_S3_BROKER = String.raw`
 if(url.origin==='https://native-r2.test'){
  const fixture=NATIVES.variants.find(f=>url.pathname==='/fixture-native-archive/'+f.key);
  const authorized=request.headers.get('Authorization')?.startsWith('AWS4-HMAC-SHA256 ')===true;
  const range=request.headers.get('Range');
  state.events.push({kind:'native_s3_get',path:url.pathname,method:request.method,range,authorized,customerKeyForwarded:false});
  if(!fixture||!authorized||request.method!=='GET'||range!=='bytes=0-'+(fixture.frame.length-1))throw Error('Unexpected native signed S3 range');
  const body=new Uint8Array(fixture.frame);
  if(state.mode==='native-archive-corrupt')body[body.length-1]^=1;
  return new Response(body,{status:206,headers:{'Content-Type':'application/octet-stream',
   'Content-Length':String(body.byteLength),'Content-Range':'bytes 0-'+(body.byteLength-1)+'/'+body.byteLength,
   ETag:fixture.etag,'Accept-Ranges':'bytes'}});
 }
`;

const FINALIZED_BROKER = String.raw`
 const finalizedMatch=/^\/v1\/finalized\/([0-9]+)$/.exec(url.pathname);
 if(finalizedMatch){
  const slot=Number(finalizedMatch[1]), mode=state.mode;
  const fixture=NATIVES.variants[mode==='native-zstd'?1:0];
  const spec=specs.find(s=>s.slot===slot), authorized=request.headers.get('Authorization')==='Bearer '+env.TEST_SECRET;
  state.events.push({path:url.pathname,method:request.method,authorized,customerKeyForwarded:false,
   readMode:request.headers.get('X-BZ-Foundation-Read-Mode')});
  if(!authorized)return new Response(null,{status:403});
  if(mode==='native-header-timeout')await new Promise(done=>setTimeout(done,250));
  if(mode.startsWith('ledger-')){
   if(!NATIVES.ledger)return new Response(null,{status:403});
   const metadata=structuredClone(NATIVES.ledger.metadata),body=new Uint8Array(NATIVES.ledger.bundle);
   if(mode==='ledger-wrong-slot')metadata.slot++;
   if(mode==='ledger-incomplete')metadata.metadata_complete=false;
   if(mode==='ledger-wrong-blockhash')metadata.blockhash=metadata.previous_blockhash;
   if(mode==='ledger-corrupt-bundle')body[body.length-1]^=1;
   return new Response(body,{headers:{'Content-Type':'application/vnd.blockzilla.get-block-bundle.wincode',
    'Content-Length':String(body.byteLength),'X-BZ-Foundation-Protocol':'1',
    'X-BZ-Foundation-Generation':specs[0].generation,'X-BZ-Foundation-Source-Prefix':specs[0].sourcePrefix,
    'X-BZ-Foundation-Result':'ledger_compact','X-BZ-Foundation-SHA256':metadata.sha256,
    'X-BZ-Finalized-Producer-Generation':NATIVES.producer_generation,
    'X-BZ-Ledger-Generation':mode==='ledger-wrong-generation'?'wrong-ledger-generation':NATIVES.ledger.ledger_generation,
    'X-BZ-Ledger-Metadata':btoa(JSON.stringify(metadata)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')
   }});
  }
  let body=new Uint8Array(fixture.frame), status=200, result='recent', type='application/vnd.blockzilla.stream.v2';
  const metadata=structuredClone(fixture.metadata);
  let root=fixture.root, generation=NATIVES.producer_generation;
  if(mode==='native-wrong-source')metadata.source.session_id+='-wrong';
  if(mode==='native-wrong-root')root=NATIVES.variants[1].root;
  if(mode==='native-wrong-generation')generation='ff'.repeat(32);
  if(mode==='native-wrong-hash')body[body.length-1]^=1;
  if(mode==='native-unrooted'){
   status=409;result='unavailable';type='application/json';
   body=new TextEncoder().encode(JSON.stringify({version:1,slot,reason:'not_finalized'}));
  }else if(mode==='native-unavailable'||mode==='native-capacity-unavailable'){
   status=503;result='unavailable';type='application/json';
   body=new TextEncoder().encode(JSON.stringify({version:1,slot,
    reason:mode==='native-capacity-unavailable'?'recent_capacity_unavailable':'recent_unavailable'}));
  }else if(mode.startsWith('native-archive')){
   status=404;result='not_cached';type='application/json';
   const native_archive={version:1,producer_generation:mode==='native-archive-wrong-generation'?'ff'.repeat(32):NATIVES.producer_generation,
    metadata,root_frame_base64:root,frame:{key:fixture.key,etag:fixture.etag,length:fixture.frame.length,sha256:metadata.frame_sha256}};
   body=new TextEncoder().encode(JSON.stringify({version:1,slot,reason:'not_cached',native_archive}));
  }else if(mode==='native-legacy-miss'){
   if(!spec)return new Response(null,{status:403});
   status=404;result='not_cached';type='application/json';
   body=new TextEncoder().encode(JSON.stringify({version:1,slot,reason:'not_cached',source:spec.pending}));
   // Later legacy resolution requests use the existing independent dictionary fixture.
   state.mode='resolve-normal';
  }else if(slot!==fixture.slot){return new Response(null,{status:403});}
  const digest=status===200?fixture.metadata.frame_sha256:await sha(body);
  const headers=new Headers({'Content-Type':type,'Content-Length':String(body.byteLength),'X-BZ-Foundation-Protocol':'1',
   'X-BZ-Foundation-Generation':specs[0].generation,'X-BZ-Foundation-Source-Prefix':specs[0].sourcePrefix,
   'X-BZ-Foundation-Result':result,'X-BZ-Foundation-SHA256':digest,
   'X-BZ-Recent-Metadata':btoa(JSON.stringify(metadata)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''),
   'X-BZ-Finalized-Root':root,'X-BZ-Finalized-Producer-Generation':generation});
  return new Response(body,{status,headers});
 }
`;

const NATIVE_R2 = String.raw`
  const native=NATIVES.variants.find(f=>f.key===key);
  if(native){
   if(options?.range?.offset!==0||options?.range?.length!==native.frame.length)throw Error('Native frame must be one exact original-object range');
   state.events.push({kind:'native_get',key,offset:options.range.offset,length:options.range.length});
   const object=await env.LOCAL_WINDOWS.get('native/'+native.name,{range:{offset:0,length:native.frame.length}});
   if(!object?.body)throw Error('Missing native fixture');
   let body=object.body;
   if(state.mode==='native-archive-corrupt'){
    const bytes=new Uint8Array(await object.arrayBuffer());bytes[bytes.length-1]^=1;
    body=new ReadableStream({start(controller){controller.enqueue(bytes);controller.close();}});
   }
   const readable=new Response(body);
   return{key,version:object.version,size:native.frame.length,etag:native.etag.slice(1,-1),httpEtag:native.etag,
    uploaded:object.uploaded,httpMetadata:object.httpMetadata,customMetadata:object.customMetadata,checksums:object.checksums,
    storageClass:object.storageClass,range:{offset:0,length:native.frame.length},body:readable.body,
    get bodyUsed(){return readable.bodyUsed;},arrayBuffer(){return readable.arrayBuffer();},
    text(){return readable.text();},json(){return readable.json();}};
  }
`;

async function main() {
  const { values } = parseArgs({ options: {
    build: { type: 'string' }, fixtures: { type: 'string' }, receipt: { type: 'string' },
    'ledger-fixtures': { type: 'string' },
  } });
  assert.ok(values.build && values.fixtures && values.receipt, '--build, --fixtures and --receipt are required');
  const exported = JSON.parse(await readFile(resolve(values.fixtures), 'utf8'));
  assert.equal(exported.schema, 'blockzilla-native-finalized-worker-fixture-v1');
  assert.match(exported.producer_generation, /^[0-9a-f]{64}$/);
  assert.equal(exported.variants.length, 2);
  const prefix = 'native-stream/bank-v2/' + exported.variants[0].metadata.source.session_id;
  const variants = exported.variants.map(fixture => {
    const frame = Buffer.from(fixture.frame_base64, 'base64');
    assert.equal(sha(frame), fixture.metadata.frame_sha256);
    return { ...fixture, frame: [...frame], root: Buffer.from(fixture.root_base64, 'base64').toString('base64url'),
      key: `${prefix}/frames/${fixture.metadata.frame_sha256}.bin`,
      etag: `"${createHash('md5').update(frame).digest('hex')}"` };
  });
  assert.notEqual(variants[0].metadata.frame_sha256, variants[1].metadata.frame_sha256);
  let ledger = null;
  if (values['ledger-fixtures']) {
    ledger = JSON.parse(await readFile(resolve(values['ledger-fixtures']), 'utf8'));
    assert.equal(ledger.schema, 'blockzilla-ledger-compact-worker-fixture-v1');
    ledger.bundle = [...Buffer.from(ledger.bundle_base64, 'base64')];
    assert.equal(sha(Buffer.from(ledger.bundle)), ledger.metadata.sha256);
    assert.equal(ledger.bundle.length, ledger.metadata.length);
    assert.equal(ledger.slot, ledger.metadata.slot);
    ledger.expected_transaction_base64 = ledger.expected_json_rpc.result.transactions[0].transaction[0];
  }
  const natives = { producer_generation: exported.producer_generation, variants, ledger };
  const insert = text => text.replace('const specs=', `const NATIVES=${JSON.stringify(natives)};const specs=`);
  const h = await createFoundationFirstHarness(values.build, {
    ownerBindings: { BZ_GET_BLOCK_PUBLIC: 'true', BZ_HTTP_GET_ONLY: 'true',
      BZ_FOUNDATION_LOOKUP_MODE: 'recent-only', BZ_FOUNDATION_NATIVE_FINALIZED: 'true',
      BZ_FOUNDATION_RECENT_SOURCE: JSON.stringify(variants[0].metadata.source),
      BZ_FOUNDATION_NATIVE_PRODUCER_GENERATION: exported.producer_generation,
      BZ_FOUNDATION_NATIVE_ARCHIVE_PREFIX: prefix,
      BZ_FOUNDATION_LEDGER_GENERATION: ledger?.ledger_generation ?? 'ledger-compact-v1',
      BZ_S3_ENDPOINT: 'https://native-r2.test', BZ_S3_BUCKET: 'fixture-native-archive',
      BZ_S3_REGION: 'auto', BZ_S3_ACCESS_KEY_ID: 'fixture-native-access',
      BZ_S3_SECRET_ACCESS_KEY: 'fixture-native-signing-secret-not-a-live-credential' },
    ownerTransform: text => {
      assert.ok(text.includes('const ranges={async get(key,options){'));
      assert.ok(text.includes('new worker(ctx,{...env,...lookup,'));
      assert.ok(text.includes('function observedBody'));
      return insert(text)
        .replace('function observedBody',NATIVE_TRANSPORT+'\nfunction observedBody')
        .replace('const ranges={async get(key,options){', 'const ranges={async get(key,options){' + NATIVE_R2)
        .replace('new worker(ctx,{...env,...lookup,',
          "new worker(ctx,{...env,...lookup,BZ_RPC_API_KEYS:undefined,BZ_RPC_METRICS:undefined,BZ_ARCHIVE_SOURCE:state.mode.startsWith('native-archive')&&state.mode!=='native-archive-r2'?'s3':env.BZ_ARCHIVE_SOURCE,");
    },
    brokerTransform: text => {
      assert.ok(text.includes('const rawMatch='));
      return insert(text).replace('const rawMatch=', NATIVE_S3_BROKER + FINALIZED_BROKER + '\n const rawMatch=');
    },
  });
  const windows = await h.mf.getR2Bucket('LOCAL_WINDOWS', 'foundation-first-local-owner');
  for (const fixture of variants) await windows.put('native/' + fixture.name, Buffer.from(fixture.frame));
  const request = path => h.mf.dispatchFetch(ORIGIN + path);
  const read = async (name, fixture, { profile = true, status = 200, r2 = 0, s3 = 0, prefix = '/block', rewards = false } = {}) => {
    const response = await request(`${prefix}/${fixture.slot}.json?rewards=${rewards}${profile ? '&profile=1' : ''}`);
    const bytes = Buffer.from(await response.arrayBuffer()), headers = Object.fromEntries(response.headers);
    assert.equal(response.status, status, `${name}: ${bytes.toString().slice(0, 240)}`);
    assert.equal(headers['x-blockzilla-auth-cache'], 'PUBLIC', name);
    assert.equal(headers['x-blockzilla-auth-kv-reads'], '0', name);
    assert.equal(headers['x-blockzilla-billable-reads'], '0', name);
    assert.equal(Number(headers['x-blockzilla-r2-gets']), r2, name);
    assert.equal(Number(headers['x-blockzilla-r2-heads']), 0, name);
    assert.equal(Number(headers['x-blockzilla-s3-gets']), s3, name);
    assert.equal(Number(headers['x-blockzilla-s3-heads']), 0, name);
    const value = JSON.parse(bytes);
    assert.equal(value.jsonrpc, '2.0', name);
    if (status === 200) {
      const expected = rewards ? fixture.expected_json_rpc_with_rewards : fixture.expected_json_rpc;
      assert.ok(expected, `${name}: independent expected RPC is missing`);
      assert.equal(canonicalBlockDigest(bytes.toString()), canonicalBlockDigest(JSON.stringify(expected)), name);
      if (rewards) {
        assert.deepEqual(value.result.rewards, expected.result.rewards, name);
        assert.deepEqual(value.result.rewards.map(reward => reward.rewardType), ['DeactivatedStake', 'VATDebit'], name);
      }
      assert.equal(value.result.transactions[0].transaction[0], fixture.expected_transaction_base64, name);
      assert.equal(value.result.transactions[0].transaction[1], 'base64', name);
      assert.deepEqual(value.result.transactions[0].meta.err, fixture.expected_json_rpc.result.transactions[0].meta.err, name);
      assert.match(headers['cache-control'], profile ? /no-store/ : /^public,.*max-age=31536000/, name);
    } else {
      assert.ok(value.error, name);
      assert.match(headers['cache-control'], /no-store/, name);
      assert.notEqual(headers['x-blockzilla-cache'], 'HIT', name);
    }
    const stats = await h.stats();
    assert.ok(stats.broker.events.every(e => e.authorized && !e.customerKeyForwarded), name);
    checks.push({ name, status: response.status, bytes: bytes.length, sha256: sha(bytes),
      r2Gets: r2, s3Gets: s3, cache: headers['x-blockzilla-cache'], foundation: headers['x-blockzilla-foundation-result'] });
    return { response, bytes, headers, stats };
  };
  const fail = async (name, mode, { r2 = 0, s3 = 0, slot = variants[0].slot } = {}) => {
    await h.control(mode);
    const response = await request(`/block/${slot}.json?rewards=false&profile=1`);
    const bytes = Buffer.from(await response.arrayBuffer()), headers = Object.fromEntries(response.headers);
    assert.ok(response.status >= 400, `${name}: ${bytes.toString().slice(0, 240)}`);
    assert.ok(JSON.parse(bytes).error, name);
    assert.equal(headers['x-blockzilla-auth-kv-reads'], '0', name);
    assert.equal(headers['x-blockzilla-billable-reads'], '0', name);
    assert.equal(Number(headers['x-blockzilla-r2-gets']), r2, name);
    assert.equal(Number(headers['x-blockzilla-r2-heads']), 0, name);
    assert.equal(Number(headers['x-blockzilla-s3-gets']), s3, name);
    assert.equal(Number(headers['x-blockzilla-s3-heads']), 0, name);
    assert.match(headers['cache-control'], /no-store/, name);
    const stats = await h.stats();
    assert.equal(stats.broker.events.filter(e => e.path.startsWith('/v1/finalized/')).length, 1, name);
    assert.equal(stats.events.filter(e => e.kind === 'source_get').length, 0, name);
    assert.equal(stats.events.filter(e => e.kind === 'native_get').length, r2, name);
    assert.equal(stats.broker.events.filter(e => e.kind === 'native_s3_get').length, s3, name);
    checks.push({ name, status: response.status, r2Gets: r2, s3Gets: s3, noLegacyArchiveFallback: true });
  };
  try {
    for (const [index, fixture] of variants.entries()) {
      await h.control(index ? 'native-zstd' : 'native-ok');
      const row = await read(`${fixture.name} native frame renders independent Base64 RPC`, fixture);
      assert.equal(row.stats.broker.events.filter(e => e.path.startsWith('/v1/finalized/')).length, 1);
      assert.equal(row.stats.events.filter(e => e.kind.endsWith('_get')).length, 0);
      assert.equal(row.headers['x-blockzilla-foundation-result'], 'NATIVE_RECENT');
      const alias = await read(`${fixture.name} archive alias returns the same native JSON`, fixture, { prefix: '/archive/block' });
      assert.deepEqual(alias.bytes, row.bytes);
      await read(`${fixture.name} includes exact DeactivatedStake and VATDebit rewards`, fixture, { rewards: true, prefix: '/archive/block' });
    }
    await h.control('native-archive');
    const archived = await read('native miss reads the original frame in one signed S3 range', variants[0], { s3: 1 });
    assert.equal(archived.headers['x-blockzilla-foundation-result'], 'NATIVE_ARCHIVE');
    assert.deepEqual(archived.stats.broker.events.filter(e => e.kind === 'native_s3_get')
      .map(({ path, range }) => ({ path, range })),
    [{ path: '/fixture-native-archive/' + variants[0].key, range: `bytes=0-${variants[0].frame.length - 1}` }]);
    await h.control('native-archive-r2');
    const nativeR2 = await read('native binding reads the same original frame once from R2', variants[0], { r2: 1 });
    assert.deepEqual(nativeR2.stats.events.filter(e => e.kind === 'native_get')
      .map(({ key, offset, length }) => ({ key, offset, length })),
    [{ key: variants[0].key, offset: 0, length: variants[0].frame.length }]);
    for (const [name, mode] of [
      ['wrong source is rejected before any R2 read', 'native-wrong-source'],
      ['wrong root cannot trigger archive fallback', 'native-wrong-root'],
      ['wrong frame bytes cannot trigger archive fallback', 'native-wrong-hash'],
      ['wrong producer cannot trigger archive fallback', 'native-wrong-generation'],
      ['wrong native locator producer is rejected before R2', 'native-archive-wrong-generation'],
    ]) await fail(name, mode);
    await fail('native S3 bytes must match the exact original frame identity', 'native-archive-corrupt', { s3: 1 });
    await h.control('native-unrooted');
    for (let repeat = 0; repeat < 2; repeat++) await read(`unrooted response stays uncached ${repeat}`, variants[0], { profile: false, status: 409 });
    assert.equal((await h.stats()).broker.events.length, 2);
    for (const mode of ['native-unavailable', 'native-capacity-unavailable']) {
      await h.control(mode);
      const unavailable = await read(`${mode} remains 503 without archive fallback`, variants[0], { profile: false, status: 503 });
      assert.equal(unavailable.stats.broker.events.length, 1, mode);
      assert.equal(unavailable.stats.broker.events[0].path, `/v1/finalized/${variants[0].slot}`, mode);
      assert.equal(unavailable.stats.events.filter(e => e.kind.endsWith('_get')).length, 0, mode);
    }
    for (const mode of ['native-network-error', 'native-header-timeout']) {
      await h.control(mode);
      for (let repeat=0;repeat<2;repeat++) {
        const unavailable=await read(`${mode} stays terminal and uncached ${repeat}`,variants[0],{profile:false,status:503});
        assert.equal(unavailable.headers['x-blockzilla-foundation-result'],'UNAVAILABLE',mode);
        assert.equal(JSON.parse(unavailable.bytes).error.code,-32000,mode);
        assert.equal(JSON.parse(unavailable.bytes).error.message,'Foundation block source is unavailable',mode);
        assert.equal(Number(unavailable.headers['x-blockzilla-foundation-resolve-http-requests']),0,mode);
        assert.equal(unavailable.stats.events.filter(e=>e.kind.endsWith('_get')).length,0,mode);
        assert.equal(unavailable.stats.broker.events.filter(e=>e.path==='/v1/resolve'||e.path.startsWith('/v1/resolve-block/')).length,0,mode);
        assert.equal(unavailable.stats.broker.events.length,mode==='native-network-error'?0:repeat+1,mode);
      }
    }
    if (ledger) {
      await h.control('ledger-ok');
      const compact = await read('ledger bundle renders exact Legacy/V0/V1 Base64 RPC', ledger);
      assert.equal(compact.headers['x-blockzilla-foundation-result'], 'LEDGER_COMPACT');
      assert.equal(compact.stats.broker.events.length, 1);
      assert.equal(compact.stats.events.filter(e => e.kind.endsWith('_get')).length, 0);
      const alias = await read('archive alias returns the same ledger JSON', ledger, { prefix: '/archive/block' });
      assert.deepEqual(alias.bytes, compact.bytes);
      for (const [name, mode] of [
        ['ledger slot proof must match the request', 'ledger-wrong-slot'],
        ['ledger blockhash must match the decoded bundle', 'ledger-wrong-blockhash'],
        ['ledger full-metadata proof is required', 'ledger-incomplete'],
        ['ledger helper generation is pinned', 'ledger-wrong-generation'],
        ['ledger bundle bytes must match their full SHA', 'ledger-corrupt-bundle'],
      ]) await fail(name, mode, { slot: ledger.slot });
      await h.control('ledger-ok');
      await read('ledger public response fill', ledger, { profile: false });
      await new Promise(done => setTimeout(done, 150));
      const before = await h.stats();
      const hit = await read('ledger archive alias shares the existing response cache', ledger, { profile: false, prefix: '/archive/block' });
      assert.equal(hit.headers['x-blockzilla-cache'], 'HIT');
      assert.equal(hit.stats.broker.events.length, before.broker.events.length);
      assert.equal(hit.stats.events.length, before.events.length);
    }
    for (const mode of ['native-ok', 'native-archive']) {
      await h.control(mode);
      await read(`${mode} public response fill`, variants[0], { profile: false, s3: mode === 'native-archive' ? 1 : 0 });
      await new Promise(done => setTimeout(done, 150));
      const before = await h.stats();
      const hit = await read(`${mode} archive alias shares the existing response cache`, variants[0], { profile: false, prefix: '/archive/block' });
      assert.equal(hit.headers['x-blockzilla-cache'], 'HIT');
      assert.equal(hit.headers['x-blockzilla-foundation-result'], 'RESPONSE_CACHE');
      assert.equal(hit.stats.broker.events.length, before.broker.events.length);
      assert.equal(hit.stats.events.length, before.events.length);
    }
    const legacy = h.specs[0];
    await h.control('native-legacy-miss');
    const response = await request(`/block/${legacy.slot}.json?rewards=false&profile=1`);
    const bytes = Buffer.from(await response.arrayBuffer());
    assert.equal(response.status, 200, bytes.toString().slice(0, 240));
    assert.equal(canonicalBlockDigest(bytes.toString()), legacy.referenceDigest);
    const legacyStats = await h.stats();
    assert.equal(legacyStats.broker.events.filter(e => e.path.startsWith('/v1/finalized/')).length, 1);
    assert.equal(legacyStats.events.filter(e => e.kind === 'native_get').length, 0);
    assert.equal(Number(response.headers.get('X-Blockzilla-R2-GETs')), 2);
    checks.push({ name: 'typed native miss retains the existing historical archive path', status: 200, r2Gets: 2 });
    await h.control('complete');
    const binary = await request(`/block/${legacy.slot}.bin?profile=1`);
    assert.equal(binary.status, 200);
    assert.equal(sha(Buffer.from(await binary.arrayBuffer())), legacy.bundleSha);
    assert.equal((await h.stats()).broker.events.filter(e => e.path.startsWith('/v1/finalized/')).length, 0);
    checks.push({ name: 'ordinary binary contract stays on the original bundle path', status: 200 });
    const aliasBinary = await request(`/archive/block/${legacy.slot}.bin?profile=1`);
    assert.equal(aliasBinary.status, 200);
    assert.equal(sha(Buffer.from(await aliasBinary.arrayBuffer())), legacy.bundleSha);
    assert.equal(aliasBinary.headers.get('X-Blockzilla-Auth-Cache'), 'PUBLIC');
    assert.equal(aliasBinary.headers.get('X-Blockzilla-Auth-KV-Reads'), '0');
    assert.equal(aliasBinary.headers.get('X-Blockzilla-Billable-Reads'), '0');
    assert.equal((await h.stats()).broker.events.filter(e => e.path.startsWith('/v1/finalized/')).length, 0);
    checks.push({ name: 'archive binary alias preserves the exact original bundle digest', status: 200 });
    await h.control('native-ok');
    const indexResponses = [];
    for (const prefix of ['/block', '/archive/block']) {
      const denied = await request(`${prefix}/${legacy.slot}.resolution`);
      assert.equal(denied.status, 401);
      assert.match(denied.headers.get('Cache-Control'), /no-store/);
      indexResponses.push(Buffer.from(await denied.arrayBuffer()));
    }
    assert.deepEqual(indexResponses[1], indexResponses[0]);
    assert.equal((await h.stats()).broker.events.length, 0);
    assert.equal((await h.stats()).events.length, 0);
    checks.push({ name: 'archive resolution alias keeps the authenticated index gate', status: 401 });
    const receipt = { status: 'PASS', total: checks.length, artifact: h.artifact, checks,
      fixture: { path: resolve(values.fixtures), producerGeneration: exported.producer_generation,
        variants: variants.map(f => ({ name: f.name, frameSha256: f.metadata.frame_sha256 })),
        ledger: ledger ? { path: resolve(values['ledger-fixtures']), generation: ledger.ledger_generation,
          slot: ledger.slot, bundleSha256: ledger.metadata.sha256 } : null },
      scope: 'Actual local release WASM; original synthetic native frame bytes and independently assembled wire/RPC expectations. Customer KV and billing bindings are absent. No cloud requests or deployment.' };
    await mkdir(dirname(resolve(values.receipt)), { recursive: true });
    await writeFile(resolve(values.receipt), JSON.stringify(receipt, null, 2) + '\n');
    console.log(JSON.stringify({ status: receipt.status, total: receipt.total, wasmSha256: receipt.artifact.wasmSha256 }));
  } finally { await h.close(); }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
