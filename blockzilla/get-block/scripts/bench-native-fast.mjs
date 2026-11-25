#!/usr/bin/env node
// One bounded final comparison. Credentials and locator tokens stay in memory
// or a private directory; the report has no target URLs or request headers.
import { readFile, writeFile, mkdir, access } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';
import { sampleRequest, validateJsonSample, loadSlots, loadBinaryReferences, summarize, compareContents } from './bench-get-block.mjs';
import { TransportTrace } from './diagnose-get-block-transport.mjs';

function args(argv) {
  const result = new Map();
  const allowed = ['url','baseline-url','rpc-url','slots','reference','binary-reference','output','private-output','version'];
  for (let i = 0; i < argv.length; i += 2) {
    const name = argv[i]?.replace(/^--/,'');
    if (!argv[i]?.startsWith('--') || !allowed.includes(name) || !argv[i+1] || result.has(name)) throw new Error('Invalid final benchmark arguments.');
    result.set(name,argv[i+1]);
  }
  for (const name of allowed) if (!result.has(name)) throw new Error(`Missing --${name}.`);
  return result;
}
const envUrl = value => { if (!/^@[A-Z][A-Z0-9_]*$/.test(value ?? '')) throw new Error('Use environment references for URLs.'); const url = process.env[value.slice(1)]; if (!url || new URL(url).protocol !== 'https:') throw new Error('Invalid target environment.'); return url; };
const pause = ms => new Promise(resolve => setTimeout(resolve,ms));
const count = (rows,fn) => rows.reduce((n,row)=>n+(fn(row)?1:0),0);
export function phasePlan(slots) {
  if (slots.length !== 4) throw new Error('Exactly four slots are required.');
  const task=(label,slot,phase,options={})=>({source:label==='helius'?'provider':'blockzilla',label,slot,phase,representation:'json',round:0,providerIndex:0,...options});
  const phases=[];
  const add=(name,tasks,concurrent=false)=>phases.push({name,tasks,concurrent});
  const cold=[];
  for(let round=0;round<2;round++)for(const slot of slots)for(const label of round%2?['fast','baseline','helius']:['baseline','fast','helius'])cold.push(task(label,slot,'plain_full_cold',{uncached:label!=='helius',round}));
  add('plain_full_cold',cold);
  add('resolution_download',slots.map(slot=>task('fast',slot,'resolution_download',{representation:'resolution'})));
  const hinted=[];
  for(let round=0;round<2;round++)for(const slot of slots)for(const label of round%2?['helius','fast']:['fast','helius'])hinted.push(task(label,slot,'hinted_full_cold',{uncached:label==='fast',hinted:label==='fast',round}));
  add('hinted_full_cold',hinted);
  add('source_only',slots.flatMap(slot=>[task('fast',slot,'source_only',{sourceUncached:true}),task('helius',slot,'source_only')]));
  add('cold_binary',slots.map(slot=>task('fast',slot,'cold_binary',{representation:'bin',uncached:true})));
  add('burst_index_auth_warmup',[task('fast',slots[0],'burst_index_auth_warmup',{representation:'resolution'})]);
  add('ordinary_burst',Array.from({length:16},(_,index)=>task('fast',slots[0],'ordinary_burst',{burstIndex:index})),true);
  add('ordinary_warmup',slots.map(slot=>task('fast',slot,'ordinary_warmup')));
  const hits=[];
  for(let round=0;round<4;round++)for(const slot of slots)for(const label of round%2?['helius','fast']:['fast','helius'])hits.push(task(label,slot,'response_hits',{round}));
  add('response_hits',hits);
  if(phases.reduce((n,p)=>n+p.tasks.length,0)!==109)throw new Error('The request budget changed.');
  return phases;
}
export async function main(argv) {
  const a=args(argv), slots=await loadSlots(a.get('slots')),plan=phasePlan(slots),output=resolve(a.get('output')),privateOutput=resolve(a.get('private-output'));
  try{await access(output);throw new Error('The output already exists.');}catch(error){if(error.code!=='ENOENT')throw error;}
  const ref=JSON.parse(await readFile(a.get('reference'),'utf8'));
  const digests=new Map(ref.samples.filter(s=>s.ok).map(s=>[s.slot,s.contentSha256]));
  if(slots.some(slot=>!digests.has(slot)))throw new Error('A reference is missing.');
  const binaries=await loadBinaryReferences(a.get('binary-reference'));
  const trace=new TransportTrace(),dispatchers={fast:trace.dispatcher('fast',{connections:16}),baseline:trace.dispatcher('baseline'),helius:trace.dispatcher('helius')};
  const urls={fast:envUrl(a.get('url')),baseline:envUrl(a.get('baseline-url')),helius:envUrl(a.get('rpc-url'))};
  const tokens=new Map(),samples=[],windows=[];
  const settings={providers:[{label:'helius',url:urls.helius}],blockzillaKey:process.env.BLOCKZILLA_RPC_API_KEY,timeoutMs:90000,rpcEncoding:'base64',maxTransactionVersion:1,binaryReferences:binaries};
  if(!settings.blockzillaKey)throw new Error('Worker authorization is missing.');
  await mkdir(privateOutput,{recursive:true,mode:0o700});
  const startedAt=new Date().toISOString(),started=performance.now();
  const log=data=>process.stdout.write(JSON.stringify(data)+'\n');
  log({event:'start',startedAt,requests:109,fastVersion:a.get('version')});
  const execute=async(task,deferred)=>{
    const span=trace.begin(task.label,dispatchers[task.label]);
    const fetchImplementation=async(url,options)=>{
      if(task.hinted){const changed=new URL(url);changed.searchParams.set('locator',tokens.get(task.slot));url=changed;}
      const response=await span.fetch(url,options);
      if(task.phase==='resolution_download'){
        const token=response.headers.get('X-Blockzilla-Locator');
        if(token&&/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)&&token.length<16384)tokens.set(task.slot,token);
      }
      return response;
    };
    const sample=await sampleRequest(task,{...settings,blockzillaUrl:urls[task.label],fetchImplementation,...(deferred?{deferredJsonValidation:deferred}:{})});
    sample.hinted=Boolean(task.hinted);if(task.burstIndex!==undefined)sample.burstIndex=task.burstIndex;
    sample.transport=trace.finish(span);
    // Per-request process CPU overlaps in a burst; it is not an exclusive cost.
    if(task.phase==='ordinary_burst'){delete sample.transport.clientBodyCpuMs;delete sample.transport.clientCallIncludingValidationCpuMs;}
    if(sample.representation==='json'&&!deferred){sample.contentMatchesSavedReference=sample.contentSha256===digests.get(sample.slot);if(!sample.contentMatchesSavedReference){sample.ok=false;sample.error??='saved_reference_mismatch';}}
    samples.push(sample);return sample;
  };
  try{
    for(let index=0;index<plan.length;index++){
      if(index)await pause(2200);
      const phase=plan[index],startedAt=new Date().toISOString();
      log({event:'phase_start',phase:phase.name,startedAt,requests:phase.tasks.length,concurrent:phase.concurrent});
      const deferred=phase.concurrent?[]:null;
      const rows=phase.concurrent?await Promise.all(phase.tasks.map(task=>execute(task,deferred))):[];
      if(!phase.concurrent)for(const task of phase.tasks)rows.push(await execute(task));
      const networkCompletedAt=new Date().toISOString();
      if(deferred)for(const item of deferred){try{if(!validateJsonSample(item.sample,item.chunks))item.sample.ok=false;}catch{item.sample.ok=false;item.sample.error='json_validation_error';}item.sample.contentMatchesSavedReference=item.sample.contentSha256===digests.get(item.sample.slot);if(!item.sample.contentMatchesSavedReference){item.sample.ok=false;item.sample.error??='saved_reference_mismatch';}}
      if(phase.name==='resolution_download'){
        if(tokens.size!==4)throw new Error('A signed locator is missing.');
        await writeFile(resolve(privateOutput,'locators.json'),JSON.stringify({slots,locators:Object.fromEntries(tokens)},null,2)+'\n',{flag:'wx',mode:0o600});
      }
      const workerRows=rows.filter(s=>s.source==='blockzilla'),fastRows=rows.filter(s=>s.label==='fast');
      windows.push({phase:phase.name,startedAt,networkCompletedAt,validationCompletedAt:new Date().toISOString(),requests:rows.length,fastRequests:fastRows.length,baselineRequests:count(rows,s=>s.label==='baseline'),heliusRequests:count(rows,s=>s.label==='helius'),fastFirstRequestAt:fastRows.length?fastRows.map(s=>s.startedAt).sort()[0]:null,fastLastRequestCompletedAt:fastRows.length?fastRows.map(s=>s.completedAt).sort().at(-1):null,concurrent:phase.concurrent});
      log({event:'phase_complete',phase:phase.name,completedAt:networkCompletedAt,successful:count(rows,s=>s.ok),workerGets:workerRows.reduce((n,s)=>n+(s.storage?.originGets??0),0),fills:Object.fromEntries([...new Set(fastRows.map(s=>s.cacheFill??'unreported'))].map(fill=>[fill,count(fastRows,s=>(s.cacheFill??'unreported')===fill)]))});
    }
  }finally{await Promise.allSettled(Object.values(dispatchers).map(d=>d.close()));trace.close();}
  const json=samples.filter(s=>s.representation==='json');
  const burst=samples.filter(s=>s.phase==='ordinary_burst');
  const cold=samples.filter(s=>s.label==='fast'&&s.uncached);
  const source=samples.filter(s=>s.label==='fast'&&s.sourceUncached);
  const hits=samples.filter(s=>s.label==='fast'&&s.phase==='response_hits');
  const proof={requests:samples.length,successful:count(samples,s=>s.ok),errors:count(samples,s=>!s.ok),jsonResponses:json.length,jsonMatchesSavedReference:count(json,s=>s.contentMatchesSavedReference),binaryMatchesOriginal:count(samples,s=>s.binaryMatchesReference),fastFullColdRequests:cold.length,fastFullColdThreeGetAuthBypass:count(cold,s=>s.fullyColdVerified&&s.storage?.archiveBackend==='r2'&&s.storage.r2.gets===3&&s.auth?.kvReads===1),sourceRequests:source.length,sourceIndexCached:count(source,s=>s.sourceIndexCachedVerified),sourceIndexAndAuthCached:count(source,s=>s.sourceAuthCachedVerified),responseHitRequests:hits.length,responseHitsWithZeroStorageReads:count(hits,s=>s.cache==='HIT'&&s.storage?.originReads===0),burst:{requests:burst.length,cacheCounts:Object.fromEntries([...new Set(burst.map(s=>s.cache))].map(k=>[k,count(burst,s=>s.cache===k)])),fillCounts:Object.fromEntries([...new Set(burst.map(s=>s.cacheFill??'unreported'))].map(k=>[k,count(burst,s=>(s.cacheFill??'unreported')===k)])),getAttempts:burst.reduce((n,s)=>n+(s.storage?.originGets??0),0),authKvReads:burst.reduce((n,s)=>n+(s.auth?.kvReads??0),0),authHitRequests:count(burst,s=>s.auth?.cache==='HIT'&&s.auth.kvReads===0),freshMissObserved:burst.some(s=>s.cache==='MISS'),leaderSourceReadsObserved:burst.some(s=>s.cacheFill==='LEADER'&&(s.storage?.originGets??0)>0)}};
  const report={schema:'blockzilla.native-fast-comparison.v1',startedAt,completedAt:new Date().toISOString(),durationMs:performance.now()-started,deployments:{fastVersion:a.get('version'),baselineVersion:'c757f003-018e-45db-b1b0-8a2decca8868'},plan:{requests:109,fastRequests:65,baselineRequests:8,heliusRequests:36,slots,retries:0,timeoutMs:90000,quietGapMs:2200,sequentialExceptBurst:true,burstConcurrency:16,dispatcherMaximumConnections:{fast:16,baseline:1,helius:1},providerOptions:{encoding:'base64',rewards:false,transactionDetails:'full',maxSupportedTransactionVersion:1,commitment:'finalized'}},proof,windows,groups:summarize(samples),contentChecks:compareContents(samples,['helius'],['baseline','fast']),connections:trace.connectionReport(),samples,notes:[
    'The final unprofiled deployment was selected by the owner. No stack sampling is requested by this runner. Standard request profile=1 is still used to prove full owner-cache bypass.',
    'Each target retains its dispatcher for the complete run. The burst allows16connections to avoid client serialization; actual socket setup and reuse are recorded. Extra setup during the burst is part of its measured client latency.',
    'Full cold bypasses owner application caches and reads index, hot range and signatures. A signed locator permits those three GETs to overlap; it does not remove a storage GET. Provider caches and Cloudflare storage-service caches are unknown.',
    'Resolution downloads and the burst index/auth warm request are separate paid calls. Source-only results require read/index proof, with auth HIT and KV0 classified separately from legitimate TTL misses.',
    'The ordinary burst runs before any ordinary full JSON or range warmup in this runner. A fresh final generation is required. Its actual MISS, leader, follower and read receipts determine whether the precondition held.',
    'Response-fill sharing is per isolate. The burst can reach more than one isolate or complete late enough to get a normal HIT. Real leader/follower counts are reported;16simultaneous clients do not imply15coalesced followers.',
    'Canonical JSON and binary parity are checked after each response-body timer. Burst JSON parsing and canonical hashing are deferred until all16bodies finish, so one local validation cannot stall another network read.',
    'Quiet gaps of at least2seconds separate phases. Exact subsecond windows and expected fast counts support version-filtered platform metrics. Whole-second grouping and adaptive sampling can still limit CPU precision.',
    'Encoded body bytes exclude TCP/TLS and HTTP framing. Native stream byte counters at headers can omit later source completions; expected bytes remain separate from actual buffered bytes.',
    'The original full source lengths, offsets and ETags remain unchanged. No new archive or index copy is made by this runner. URLs, credentials, request headers, signed locator tokens and block bodies are absent from this report.'
  ]};
  await mkdir(dirname(output),{recursive:true});await writeFile(output,JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
  log({event:'complete',completedAt:report.completedAt,proof});
  if(proof.errors||proof.jsonMatchesSavedReference!==100||proof.binaryMatchesOriginal!==4||proof.fastFullColdThreeGetAuthBypass!==20||proof.sourceIndexCached!==4||proof.responseHitsWithZeroStorageReads!==16||!proof.burst.freshMissObserved||!proof.burst.leaderSourceReadsObserved)process.exitCode=1;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main(process.argv.slice(2)).catch(()=>{process.stderr.write('Final comparison stopped; private error details were not printed.\n');process.exitCode=1;});
