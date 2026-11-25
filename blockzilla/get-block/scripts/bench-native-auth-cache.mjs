#!/usr/bin/env node
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { sampleRequest, validateJsonSample, loadSlots, summarize, compareContents } from './bench-get-block.mjs';
import { TransportTrace } from './diagnose-get-block-transport.mjs';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const counts=(rows,key)=>Object.fromEntries([...new Set(rows.map(key))].map(value=>[value,rows.filter(row=>key(row)===value).length]));
export function authPlan(slots){
 if(slots.length!==4)throw Error('Exactly four slots are required.');
 const task=(slot,phase,extra={})=>({source:'blockzilla',label:'fast',slot,phase,representation:'json',round:0,...extra});
 const phases=[
  {name:'runtime_warm',tasks:[task(slots[0],'runtime_warm',{uncached:true})]},
  {name:'full_cold',tasks:slots.map(slot=>task(slot,'full_cold',{uncached:true}))},
  {name:'index_auth_warmup',tasks:slots.map(slot=>task(slot,'index_auth_warmup',{representation:'resolution'}))},
  {name:'ordinary_burst',concurrent:true,tasks:Array.from({length:16},(_,burstIndex)=>task(slots[0],'ordinary_burst',{burstIndex}))},
  {name:'ordinary_other_warmup',tasks:slots.slice(1).map(slot=>task(slot,'ordinary_other_warmup'))},
  {name:'source_auth_warmup',quietBeforeMs:5200,tasks:[task(slots[0],'source_auth_warmup',{representation:'resolution'})]},
  {name:'source_only',tasks:slots.map(slot=>task(slot,'source_only',{sourceUncached:true}))},
  {name:'response_hits',tasks:Array.from({length:4},(_,round)=>slots.map(slot=>task(slot,'response_hits',{round}))).flat()},
 ];
 if(phases.flatMap(p=>p.tasks).length!==49)throw Error('Request budget changed.');return phases;
}
function parse(argv){const a=new Map(),allowed=['url','slots','reference','output','version'];for(let i=0;i<argv.length;i+=2){const k=argv[i]?.replace(/^--/,'');if(!argv[i]?.startsWith('--')||!allowed.includes(k)||!argv[i+1]||a.has(k))throw Error('Invalid auth benchmark argument.');a.set(k,argv[i+1]);}if(allowed.some(k=>!a.has(k)))throw Error('Missing auth benchmark argument.');return a;}
export async function main(argv){
 const a=parse(argv);if(!/^@[A-Z][A-Z0-9_]*$/.test(a.get('url')))throw Error('Use a URL environment reference.');
 const url=process.env[a.get('url').slice(1)];if(!url||new URL(url).protocol!=='https:')throw Error('Target environment missing.');
 const slots=await loadSlots(a.get('slots')),plan=authPlan(slots),ref=JSON.parse(await readFile(a.get('reference'),'utf8')),digests=new Map(ref.samples.filter(s=>s.ok).map(s=>[s.slot,s.contentSha256]));
 const trace=new TransportTrace(),dispatcher=trace.dispatcher('fast',{connections:16}),samples=[],windows=[];
 const settings={blockzillaUrl:url,blockzillaKey:process.env.BLOCKZILLA_RPC_API_KEY,timeoutMs:90000,rpcEncoding:'base64',maxTransactionVersion:1};if(!settings.blockzillaKey)throw Error('Worker authorization missing.');
 const execute=async(task,deferred)=>{const span=trace.begin('fast',dispatcher);const sample=await sampleRequest(task,{...settings,fetchImplementation:span.fetch,...(deferred?{deferredJsonValidation:deferred}:{})});sample.transport=trace.finish(span);if(task.burstIndex!==undefined)sample.burstIndex=task.burstIndex;if(task.phase==='ordinary_burst'){delete sample.transport.clientBodyCpuMs;delete sample.transport.clientCallIncludingValidationCpuMs;}if(sample.representation==='json'&&!deferred){sample.contentMatchesSavedReference=sample.contentSha256===digests.get(sample.slot);if(!sample.contentMatchesSavedReference){sample.ok=false;sample.error??='saved_reference_mismatch';}}samples.push(sample);return sample;};
 const startedAt=new Date().toISOString();console.log(JSON.stringify({event:'start',startedAt,requests:49,version:a.get('version')}));
 try{for(let i=0;i<plan.length;i++){
  const phase=plan[i],quietBeforeMs=i?(phase.quietBeforeMs??2200):0;if(quietBeforeMs)await sleep(quietBeforeMs);
  const start=new Date().toISOString();console.log(JSON.stringify({event:'phase_start',phase:phase.name,startedAt:start,requests:phase.tasks.length}));
  const deferred=phase.concurrent?[]:null,rows=phase.concurrent?await Promise.all(phase.tasks.map(task=>execute(task,deferred))):[];if(!phase.concurrent)for(const task of phase.tasks)rows.push(await execute(task));
  const networkCompletedAt=new Date().toISOString();if(deferred)for(const item of deferred){try{if(!validateJsonSample(item.sample,item.chunks))item.sample.ok=false;}catch{item.sample.ok=false;item.sample.error='json_validation_error';}item.sample.contentMatchesSavedReference=item.sample.contentSha256===digests.get(item.sample.slot);if(!item.sample.contentMatchesSavedReference){item.sample.ok=false;item.sample.error??='saved_reference_mismatch';}}
  windows.push({phase:phase.name,startedAt:start,networkCompletedAt,validationCompletedAt:new Date().toISOString(),requests:rows.length,quietBeforeMs,firstRequestAt:rows.map(s=>s.startedAt).sort()[0],lastRequestCompletedAt:rows.map(s=>s.completedAt).sort().at(-1),concurrent:Boolean(phase.concurrent)});
  console.log(JSON.stringify({event:'phase_complete',phase:phase.name,completedAt:networkCompletedAt,successful:rows.filter(s=>s.ok).length,kvReads:rows.reduce((n,s)=>n+(s.auth?.kvReads??0),0),authTiers:counts(rows,s=>s.auth?.tier??'UNREPORTED'),fills:counts(rows,s=>s.cacheFill??'UNREPORTED'),gets:rows.reduce((n,s)=>n+(s.storage?.originGets??0),0)}));
 }}finally{await dispatcher.close();trace.close();}
 const byPhase=name=>samples.filter(s=>s.phase===name),json=samples.filter(s=>s.representation==='json'),cold=byPhase('full_cold'),source=byPhase('source_only'),hit=byPhase('response_hits'),burst=byPhase('ordinary_burst');
 const proof={requests:samples.length,successful:samples.filter(s=>s.ok).length,jsonResponses:json.length,jsonMatchesSaved:json.filter(s=>s.contentMatchesSavedReference).length,fullColdThreeGetKvBypass:cold.filter(s=>s.fullyColdVerified&&s.storage?.r2?.gets===3&&s.auth?.kvReads===1).length,sourceIndexCached:source.filter(s=>s.sourceIndexCachedVerified).length,sourceIndexAndAuthCached:source.filter(s=>s.sourceAuthCachedVerified).length,responseHitsZeroOrigin:hit.filter(s=>s.cache==='HIT'&&s.storage?.originReads===0).length,authTierCounts:counts(samples,s=>s.auth?.tier??'UNREPORTED'),authTierReported:samples.filter(s=>s.auth?.tier).length,burst:{requests:burst.length,kvReads:burst.reduce((n,s)=>n+(s.auth?.kvReads??0),0),authTierCounts:counts(burst,s=>s.auth?.tier??'UNREPORTED'),authCacheCounts:counts(burst,s=>s.auth?.cache??'UNREPORTED'),fillCounts:counts(burst,s=>s.cacheFill??'UNREPORTED'),gets:burst.reduce((n,s)=>n+(s.storage?.originGets??0),0),freshMissObserved:burst.some(s=>s.cache==='MISS'),leaderOriginReadObserved:burst.some(s=>s.cacheFill==='LEADER'&&(s.storage?.originGets??0)>0)}};
 const report={schema:'blockzilla.native-auth-cost-verification.v1',startedAt,completedAt:new Date().toISOString(),deploymentVersion:a.get('version'),plan:{requests:49,slots,runtimeWarmJson:1,measuredColdJson:4,indexAuthWarmResolution:4,burstJson:16,otherNormalWarmJson:3,sourceAuthWarmResolution:1,sourceJson:4,responseHitJson:16,retries:0,quietGapMs:2200,sourceWarmupQuietGapMs:5200,maximumClientConnections:16},proof,windows,groups:summarize(samples),contentChecks:compareContents(samples,[],['fast']),connections:trace.connectionReport(),samples,notes:[
  'This is the approved final auth/cache/cost verification only. It does not replace or extend the prior109-call provider-latency comparison.',
  'The final deployment has a fresh response/archive generation. Full-bypass runtime/cold requests and resolution warmups run before the first ordinary JSON burst; they do not warm reusable source ranges or complete JSON responses.',
  'The burst has sixteen concurrent requests with one persistent pool allowing sixteen sockets. Its JSON validation is deferred until every network body completes. Actual leader/follower, storage and auth-tier receipts are reported.',
  'The shared positive auth expiry stays anchored to the original KV observation for five seconds. Hits do not refresh it. Legitimate TTL misses and individual L1/L2/KV paths remain visible.',
  'A5200ms quiet gap before the source-auth warm request lets any earlier five-second auth observation expire. The source phase then follows a2200ms quiet gap. Warm request costs are separate.',
  'Full profile=1 bypasses both auth tiers and owner data caches. Source-only preserves cached index/auth and bypasses source-range and response caches. Physical storage service caches remain unknown.',
  'The sixteen final response hits must have zero object reads; they can still make a legitimate KV read after auth expiry. CPU evidence uses exact phase windows and retains adaptive sample intervals.',
  'No provider, placement, retry, data-copy, profile-capture or additional data request is sent. The report contains no URL, credential, token or block body.'
 ]};
 await mkdir(dirname(resolve(a.get('output'))),{recursive:true});await writeFile(resolve(a.get('output')),JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});console.log(JSON.stringify({event:'complete',completedAt:report.completedAt,proof}));
 if(proof.requests!==49||proof.successful!==49||proof.jsonMatchesSaved!==44||proof.authTierReported!==49||proof.fullColdThreeGetKvBypass!==4||proof.sourceIndexCached!==4||proof.responseHitsZeroOrigin!==16||!proof.burst.freshMissObserved||!proof.burst.leaderOriginReadObserved)process.exitCode=1;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main(process.argv.slice(2)).catch(()=>{console.error('Auth verification stopped; private error details were not printed.');process.exitCode=1;});
