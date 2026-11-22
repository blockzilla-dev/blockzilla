#!/usr/bin/env node
// Actual WASM transport tests. Opaque local frames test pass-through, not native decoding.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { createFoundationFirstHarness } from './test-foundation-first-worker.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const source = { genesis_hash: '11111111111111111111111111111111', node_identity: '11111111111111111111111111111111',
  agave_revision: 'recent-worker-fixture-v1', session_id: 'recent-fixture-1' };
const slots = [470555971, 470663944, 470771932, 470879999];

const RECENT_BROKER = String.raw`
 const recentMatch=/^\/v1\/recent\/([0-9]+)$/.exec(url.pathname);
 if(recentMatch){
  const slot=Number(recentMatch[1]),spec=specs.find(s=>s.slot===slot),fixture=RECENT_FIXTURES[slot];
  const mode=state.mode,authorized=request.headers.get('Authorization')==='Bearer '+env.TEST_SECRET;
  state.events.push({path:url.pathname,method:request.method,authorized,customerKeyForwarded:false,query:Object.fromEntries(url.searchParams)});
  if(!authorized||mode==='recent-auth')return new Response(null,{status:403});
  if(mode==='recent-redirect')return new Response(null,{status:307,headers:{Location:'https://untrusted.test/leak'}});
  if(mode==='recent-timeout'){await new Promise(done=>setTimeout(done,250));return new Response(null,{status:503});}
  let body=new Uint8Array(fixture.bytes),status=200,result='recent',type='application/vnd.blockzilla.stream.v2';
  const metadata={...fixture.metadata,source:{...fixture.metadata.source},commitment:url.searchParams.get('commitment')};
  if(mode==='recent-wrong-source')metadata.source.session_id='other-source';
  if(mode==='recent-wrong-hash')metadata.blockhash=fixture.metadata.parent_blockhash;
  if(mode==='recent-wrong-parent')metadata.parent_slot=metadata.slot;
  if(mode==='recent-wrong-bank')metadata.bank_id++;
  if(mode==='recent-wrong-cursor')metadata.cursor=metadata.cursor.replace(':p1:',':p2:');
  if(mode==='recent-unavailable'||mode==='recent-pruned'){
   status=mode==='recent-pruned'?410:503;result='unavailable';type='application/json';
   body=new TextEncoder().encode(JSON.stringify({version:1,slot,reason:mode==='recent-pruned'?'not_retained':'source_unavailable'}));
  }
  if(mode.startsWith('recent-archive')||mode==='recent-false-processed-miss'){
   status=404;result='not_cached';type='application/json';
   body=new TextEncoder().encode(JSON.stringify({version:1,slot,reason:'not_cached',source:mode==='recent-archive-no-route'?null:spec.pending}));
  }
  const length=body.byteLength,digest=await sha(body);
  const headers=new Headers({'Content-Type':type,'Content-Length':String(length),'X-BZ-Foundation-Protocol':'1',
   'X-BZ-Foundation-Generation':spec.generation,'X-BZ-Foundation-Source-Prefix':spec.sourcePrefix,
   'X-BZ-Foundation-Result':result,'X-BZ-Foundation-SHA256':mode==='recent-wrong-digest'?'ac'.repeat(32):digest,
   'X-BZ-Recent-Metadata':btoa(JSON.stringify(metadata)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_'),
   'X-BZ-Recent-Blockhash':mode==='recent-archive-wrong-proof'?fixture.metadata.parent_blockhash:fixture.metadata.blockhash});
  if(mode==='recent-wrong-prefix')headers.set('X-BZ-Foundation-Source-Prefix','compact-v2/wrong');
  if(mode==='recent-missing-proof')headers.delete('X-BZ-Recent-Metadata');
  if(mode==='recent-short')body=body.subarray(0,-1);
  if(mode==='recent-long'){const next=new Uint8Array(length+1);next.set(body);body=next;}
  const bytes=body;
  const stream=new ReadableStream({start(c){if(mode==='recent-error'){c.error(Error('fixture network error'));return;}c.enqueue(mode==='recent-stall'?bytes.subarray(0,16):bytes);if(mode!=='recent-stall')c.close();},pull(){if(mode==='recent-stall')return new Promise(()=>{});}});
  const fixed=new FixedLengthStream(length);ctx.waitUntil(stream.pipeTo(fixed.writable).catch(()=>{}));
  return new Response(fixed.readable,{status,headers});
 }
`;

async function main() {
  const { values } = parseArgs({ options: { build: { type: 'string' }, receipt: { type: 'string' }, public: { type: 'boolean', default: false } } });
  assert.ok(values.build && values.receipt, '--build and --receipt are required');
  const fixtures = {};
  for (const slot of slots) {
    const descriptor = JSON.parse(await readFile(resolve(ROOT, `.codex-tmp/get-block-resolution-20261121/inputs/${slot}.descriptor.json`), 'utf8'));
    const bytes = Buffer.concat([Buffer.from('BZSTRM01'), Buffer.alloc(8), Buffer.from(`Opaque native transport fixture for ${slot}; `), Buffer.alloc(160, slot % 256)]);
    const frameSha = sha(bytes);
    fixtures[slot] = { bytes: [...bytes], sha256: frameSha, metadata: { version: 1, slot, blockhash: descriptor.blockhash,
      parent_slot: slot - 1, parent_blockhash: descriptor.previous_blockhash, bank_id: 101, source,
      cursor: `${source.session_id}:p1:${frameSha}`, frame_sha256: frameSha, commitment: 'processed' } };
  }
  const h = await createFoundationFirstHarness(values.build, {
    ownerBindings: { BZ_FOUNDATION_RECENT_SOURCE: JSON.stringify(source), ...(values.public ? { BZ_GET_BLOCK_PUBLIC: 'true' } : {}) },
    ownerTransform: text => text.replace('probeEnabled:!!command.probeEnabled,', 'probeEnabled:!!command.probeEnabled,recentDisabled:!!command.recentDisabled,recentOnly:!!command.recentOnly,')
      .replace('...env,...lookup,BZ_R2_PROBE_ENABLED:', '...env,...lookup,BZ_FOUNDATION_LOOKUP_MODE:state.recentOnly?\'recent-only\':\'all\',BZ_FOUNDATION_RECENT_SOURCE:state.recentDisabled?undefined:env.BZ_FOUNDATION_RECENT_SOURCE,BZ_R2_PROBE_ENABLED:')
      .replace("state.mode.endsWith('resolution-stall')||", "state.mode==='recent-stall'||state.mode.endsWith('resolution-stall')||")
      .replace('new worker(ctx,{...env,...lookup,', values.public
        ? 'new worker(ctx,{...env,...lookup,BZ_RPC_API_KEYS:undefined,BZ_RPC_METRICS:undefined,'
        : 'new worker(ctx,{...env,...lookup,'),
    brokerTransform: text => text.replace("const specs=", `const RECENT_FIXTURES=${JSON.stringify(fixtures)};const specs=`)
      .replace(' const rawMatch=', RECENT_BROKER + ' const rawMatch='),
  });
  if (values.public) h.request = (path, options = {}) => h.mf.dispatchFetch('https://foundation-owner.test' + path, options);
  const checks = [];
  const query = (slot, processed = false) => {
    const f = fixtures[slot], q = new URLSearchParams({ blockhash: f.metadata.blockhash, commitment: processed ? 'processed' : 'finalized', profile: '1' });
    if (processed) for (const [k, v] of Object.entries({ cursor: f.metadata.cursor, source_session: source.session_id, bank_id: String(f.metadata.bank_id) })) q.set(k, v);
    return q;
  };
  async function read(name, slot, mode, { processed = false, status = 200, gets = 0, resolves = 0, mutate, normal = false, disabled = false, streamFailure = false } = {}) {
    await h.control(mode, { rawBinary: true, recentDisabled: disabled });
    const q = query(slot, processed); if (normal) q.delete('profile'); if (mutate) mutate(q);
    const response = await h.request(`/block/${slot}.compact?${q}`), headers = Object.fromEntries(response.headers);
    if (values.public) {
      assert.equal(headers['x-blockzilla-auth-kv-reads'], '0', name);
      assert.equal(headers['x-blockzilla-billable-reads'], '0', name);
      assert.match(headers['cache-control'], /no-store/, name);
    }
    let bytes, failed = false;
    try { bytes = Buffer.from(await response.arrayBuffer()); } catch { failed = true; }
    const checkedFrameRejected = failed || response.status >= 400 || sha(bytes) !== fixtures[slot].sha256;
    if (streamFailure) assert.ok(checkedFrameRejected, name + ' must fail transport or the required client frame digest check');
    else assert.equal(failed, false, name + ' stream failure');
    assert.ok(response.status === status || streamFailure && response.status === 502, name + ': status=' + response.status);
    const recent = Number(headers['x-blockzilla-foundation-recent-http-requests']);
    const parseRejected = mode === 'recent-parse-rejected';
    assert.equal(recent, disabled || parseRejected ? 0 : 1, name);
    assert.equal(Number(headers['x-blockzilla-r2-gets']), gets, name);
    assert.equal(Number(headers['x-blockzilla-r2-heads']), 0, name);
    assert.equal(Number(headers['x-blockzilla-foundation-lookup-http-requests']), 0, name);
    assert.equal(Number(headers['x-blockzilla-foundation-resolve-http-requests']), resolves, name);
    assert.equal(headers['x-blockzilla-cache'], 'BYPASS', name);
    assert.equal(Number(headers['x-blockzilla-archive-memory-hits']), 0, name);
    assert.equal(Number(headers['x-blockzilla-archive-edge-hits']), 0, name);
    if (status === 200 && !failed && !streamFailure) {
      if (gets === 0) {
        assert.equal(sha(bytes), fixtures[slot].sha256, name);
        assert.equal(headers['content-type'], 'application/vnd.blockzilla.stream.v2');
        assert.equal(headers['x-blockzilla-source'], 'FOUNDATION_RECENT');
        assert.equal(headers['x-blockzilla-frame-sha256'], sha(bytes));
        assert.equal(headers['x-blockzilla-cursor'], fixtures[slot].metadata.cursor);
      } else {
        assert.equal(sha(bytes), h.specs.find(s => s.slot === slot).bundleSha, name);
        assert.equal(headers['content-type'], 'application/vnd.blockzilla.get-block-bundle.wincode');
        assert.equal(headers['x-blockzilla-source'], 'R2_ARCHIVE');
        assert.equal(headers['x-blockzilla-cursor'], undefined);
      }
    }
    const observed = await h.stats();
    assert.ok(observed.broker.events.every(e => e.authorized && !e.customerKeyForwarded));
    checks.push({ name, slot, status: response.status, gets, resolves, recent, streamFailure: failed,
      ...(streamFailure ? { checkedFrameRejected, requiredClientShaCheck: !failed && response.status === 200 } : {}) });
  }
  try {
    for (const slot of slots) {
      await read('finalized retained frame passes through exactly', slot, 'recent-ok');
      await read('processed exact frame passes through exactly', slot, 'recent-ok', { processed: true });
      await read('confirmed finalized miss uses exact archive bundle', slot, 'recent-archive', { gets: 2, resolves: 1 });
    }
    const slot = slots[0];
    for (const mode of ['recent-wrong-source', 'recent-wrong-hash', 'recent-wrong-parent', 'recent-wrong-digest', 'recent-wrong-prefix', 'recent-missing-proof', 'recent-auth', 'recent-redirect', 'recent-timeout', 'recent-archive-wrong-proof']) {
      await read(mode + ' has no archive read', slot, mode, { status: 502 });
    }
    for (const mode of ['recent-wrong-bank', 'recent-wrong-cursor', 'recent-false-processed-miss']) {
      await read(mode + ' has no archive fallback', slot, mode, { processed: true, status: 502 });
    }
    await read('processed retention miss is explicit', slot, 'recent-pruned', { processed: true, status: 410 });
    await read('source failure has no archive fallback', slot, 'recent-unavailable', { status: 503 });
    await read('unknown archive coverage has no speculative read', slot, 'recent-archive-no-route', { status: 404 });
    await read('disabled source has no lookup', slot, 'recent-ok', { disabled: true, status: 503 });
    for (const mutate of [q => q.delete('blockhash'), q => q.set('commitment', 'confirmed'), q => q.set('unknown', '1'), q => q.append('blockhash', q.get('blockhash'))]) {
      await read('invalid recovery identity is rejected before lookup', slot, 'recent-parse-rejected', { status: 400, mutate });
    }
    for (const mode of ['recent-short', 'recent-long', 'recent-error', 'recent-stall']) {
      await read(mode + ' cannot complete a native frame', slot, mode, { streamFailure: true });
    }
    await read('normal request does not write a result cache', slot, 'recent-ok', { normal: true });
    await new Promise(done => setTimeout(done, 100));
    const q = query(slot); q.delete('profile'); const response = await h.request(`/block/${slot}.compact?${q}`); await response.arrayBuffer();
    assert.equal(response.headers.get('X-Blockzilla-Source'), 'FOUNDATION_RECENT');
    assert.equal(response.headers.get('X-Blockzilla-Cache'), 'BYPASS');
    assert.equal((await h.stats()).broker.events.length, 2);
    checks.push({ name: 'repeat uses existing native frame and adds no Worker result cache', gets: 0, recent: 1 });
    for (const kind of ['json', 'bin']) {
      await h.control('complete', { recentOnly: true });
      const row = await h.read(slot, kind);
      assert.equal(Number(row.headers['x-blockzilla-foundation-recent-http-requests']), 0);
      assert.equal(Number(row.headers['x-blockzilla-foundation-lookup-http-requests']), 0);
      assert.equal(Number(row.headers['x-blockzilla-foundation-resolve-http-requests']), 0);
      assert.equal(Number(row.headers['x-blockzilla-r2-gets']), 3);
      assert.equal((await h.stats()).broker.events.length, 0);
      checks.push({ name: `${kind} recent-only keeps the legacy archive path and adds no Foundation calls`, gets: 3, recent: 0 });
    }
    const report = { status: 'PASS', artifact: h.artifact, checks, scope: 'Actual WASM with opaque native transport fixtures and original archive windows; native frame contents are checked by separate Foundation and live recovery tests.',
      limits: ['Recent pass-through trusts the authenticated broker checked-frame digest; recovery clients verify the original full frame and all object hashes.', 'No live deployment or hosted latency is claimed.'] };
    const path = resolve(values.receipt); await mkdir(dirname(path), { recursive: true }); await writeFile(path, JSON.stringify(report, null, 2) + '\n');
    console.log(JSON.stringify({ status: 'PASS', checks: checks.length, receipt: path, wasmSha256: h.artifact.wasmSha256 }));
  } finally { await h.close(); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(error => { console.error(error); process.exitCode = 1; });
