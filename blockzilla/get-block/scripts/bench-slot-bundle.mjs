#!/usr/bin/env node
import { readFile, writeFile, mkdir, access } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { sampleRequest, loadSlots, loadBinaryReferences, summarize, compareContents } from './bench-get-block.mjs';
import { TransportTrace } from './diagnose-get-block-transport.mjs';
import { parseProfile } from './profile-get-block.mjs';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const count=(rows,test)=>rows.reduce((n,s)=>n+(test(s)?1:0),0);
export function bundlePlan(slots){
 if(slots.length!==4)throw Error('Exactly four slots required.');
 const make=(label,slot,phase,extra={})=>({source:label==='helius'?'provider':'blockzilla',label,slot,phase,representation:'json',round:0,providerIndex:0,...extra});
 const phases=[{name:'runtime_warm',tasks:['bundle','baseline','helius'].map(label=>make(label,slots[0],'runtime_warm',{uncached:label!=='helius'}))}];
 const cold=[];
 for(let round=0;round<2;round++)for(const slot of slots)for(const label of round?['bundle','baseline','helius']:['baseline','bundle','helius'])cold.push(make(label,slot,'full_cold_json',{round,uncached:label!=='helius'}));
 phases.push({name:'full_cold_json',tasks:cold});
 for(let round=0;round<2;round++){
  for(const label of round?['baseline','bundle']:['bundle','baseline']){
   const warmName=`auth_warm_${label}_${round}`;
   phases.push({name:warmName,quietBeforeMs:5200,tasks:[make(label,slots[0],warmName,{round,representation:label==='baseline'?'resolution':'json'})]});
   const sourceName=`source_${label}_${round}`;
   phases.push({name:sourceName,tasks:slots.map(slot=>make(label,slot,sourceName,{round,sourceUncached:true}))});
  }
  const providerName=`source_provider_${round}`;
  phases.push({name:providerName,tasks:slots.map(slot=>make('helius',slot,providerName,{round}))});
 }
 const binary=[];for(let round=0;round<2;round++)for(const slot of slots)for(const label of round?['baseline','bundle']:['bundle','baseline'])binary.push(make(label,slot,'full_cold_binary',{representation:'bin',round,uncached:true}));
 phases.push({name:'full_cold_binary',tasks:binary});
 for(const representation of ['json','bin']){const name=`normal_warm_${representation}`;phases.push({name,tasks:slots.flatMap(slot=>['bundle','baseline'].map(label=>make(label,slot,name,{representation})))});}
 const jsonHits=[];for(let round=0;round<2;round++)for(const slot of slots)for(const label of round?['helius','baseline','bundle']:['bundle','baseline','helius'])jsonHits.push(make(label,slot,'response_hits_json',{round}));
 phases.push({name:'response_hits_json',tasks:jsonHits});
 phases.push({name:'response_hits_binary',tasks:slots.flatMap(slot=>['baseline','bundle'].map(label=>make(label,slot,'response_hits_binary',{representation:'bin'})))});
 if(phases.flatMap(p=>p.tasks).length!==119)throw Error('Request budget changed.');return phases;
}
function parse(argv){const a=new Map(),allowed=['url','baseline-url','rpc-url','slots','reference','binary-reference','output','version'];for(let i=0;i<argv.length;i+=2){const k=argv[i]?.replace(/^--/,'');if(!argv[i]?.startsWith('--')||!allowed.includes(k)||!argv[i+1]||a.has(k))throw Error('Invalid bundle benchmark arguments.');a.set(k,argv[i+1]);}if(allowed.some(k=>!a.has(k)))throw Error('Missing bundle benchmark arguments.');return a;}
function envUrl(value){if(!/^@[A-Z][A-Z0-9_]*$/.test(value??''))throw Error('Use URL environment references.');const url=process.env[value.slice(1)];if(!url||new URL(url).protocol!=='https:')throw Error('Missing URL environment.');return url;}
export function bundleSourceProof(sample){const s=sample.storage;return sample.label==='bundle'&&sample.sourceUncached===true&&sample.cache==='BYPASS'&&sample.profileMode==='source'&&sample.archiveLayout==='bundle-v1'&&s?.archiveBackend==='r2'&&s.r2?.gets===1&&s.r2.heads===0&&s.s3?.gets===0&&s.s3.heads===0&&(s.readerHttpRequests??0)===0&&s.archiveMemoryHits===0&&s.archiveEdgeHits===0;}
export async function main(argv){
 const a=parse(argv);try{await access(resolve(a.get('output')));throw Error('Output already exists.');}catch(error){if(error.code!=='ENOENT')throw error;}
 const slots=await loadSlots(a.get('slots')),plan=bundlePlan(slots),ref=JSON.parse(await readFile(a.get('reference'),'utf8')),digests=new Map(ref.samples.filter(s=>s.ok).map(s=>[s.slot,s.contentSha256]));
 const urls={bundle:envUrl(a.get('url')),baseline:envUrl(a.get('baseline-url')),helius:envUrl(a.get('rpc-url'))};
 const trace=new TransportTrace(),dispatchers=Object.fromEntries(Object.keys(urls).map(label=>[label,trace.dispatcher(label)])),samples=[],windows=[];
 const settings={providers:[{label:'helius',url:urls.helius}],blockzillaKey:process.env.BLOCKZILLA_RPC_API_KEY,timeoutMs:90000,rpcEncoding:'base64',maxTransactionVersion:1,binaryReferences:await loadBinaryReferences(a.get('binary-reference'))};if(!settings.blockzillaKey)throw Error('Worker authorization missing.');
 const startedAt=new Date().toISOString();console.log(JSON.stringify({event:'start',startedAt,requests:119,version:a.get('version')}));
 let stopped=false;
 try{for(let phaseIndex=0;phaseIndex<plan.length;phaseIndex++){
  const phase=plan[phaseIndex],quietBeforeMs=phaseIndex?(phase.quietBeforeMs??2200):0;if(quietBeforeMs)await sleep(quietBeforeMs);
  const phaseStart=new Date().toISOString(),rows=[];console.log(JSON.stringify({event:'phase_start',phase:phase.name,startedAt:phaseStart,requests:phase.tasks.length}));
  for(const task of phase.tasks){
   let archiveLayout=null,placement=null;const span=trace.begin(task.label,dispatchers[task.label]);
   const fetchImplementation=async(url,options)=>{const response=await span.fetch(url,options);const layout=response.headers.get('X-Blockzilla-Archive-Layout');if(layout&&/^[a-z0-9_-]{1,40}$/.test(layout))archiveLayout=layout;if(task.source==='blockzilla'&&(task.uncached||task.sourceUncached)){try{placement=parseProfile(response.headers.get('X-BZ-Profile')).eventsByName.worker_placement?.map(e=>e.placement)??[];}catch{placement=[];}}return response;};
   const sample=await sampleRequest(task,{...settings,blockzillaUrl:urls[task.label],fetchImplementation});sample.transport=trace.finish(span);sample.archiveLayout=archiveLayout;sample.placement=placement;
   if(sample.representation==='json'){sample.contentMatchesSavedReference=sample.contentSha256===digests.get(sample.slot);if(!sample.contentMatchesSavedReference){sample.ok=false;sample.error??='saved_reference_mismatch';}}
   if(sample.sourceUncached){sample.sourceDataReadVerified=task.label==='bundle'?bundleSourceProof(sample):sample.sourceIndexCachedVerified;sample.authHotSourceVerified=sample.sourceDataReadVerified&&sample.auth?.cache==='HIT'&&sample.auth.kvReads===0;if(task.label==='bundle')sample.storageClass=sample.sourceDataReadVerified?'bundle_source_uncached_verified':'bundle_source_uncached_unverified';}
   rows.push(sample);samples.push(sample);
   if(!sample.ok){stopped=true;break;}
  }
  const phaseEnd=new Date().toISOString();const worker=rows.filter(s=>s.source==='blockzilla');
  windows.push({phase:phase.name,startedAt:phaseStart,completedAt:phaseEnd,quietBeforeMs,requests:rows.length,bundleRequests:count(rows,s=>s.label==='bundle'),baselineRequests:count(rows,s=>s.label==='baseline'),heliusRequests:count(rows,s=>s.label==='helius'),targets:Object.fromEntries(['bundle','baseline','helius'].map(label=>{const r=rows.filter(s=>s.label===label);return[label,{requests:r.length,firstRequestAt:r.length?r[0].startedAt:null,lastRequestCompletedAt:r.length?r.at(-1).completedAt:null}];}))});
  console.log(JSON.stringify({event:'phase_complete',phase:phase.name,completedAt:phaseEnd,successful:count(rows,s=>s.ok),requests:rows.length,gets:worker.reduce((n,s)=>n+(s.storage?.originGets??0),0),kvReads:worker.reduce((n,s)=>n+(s.auth?.kvReads??0),0)}));
  if(stopped)break;
 }}finally{await Promise.allSettled(Object.values(dispatchers).map(d=>d.close()));trace.close();}
 const worker=samples.filter(s=>s.source==='blockzilla'),bundle=samples.filter(s=>s.label==='bundle'),baseline=samples.filter(s=>s.label==='baseline'),cold=samples.filter(s=>s.phase==='full_cold_json'),coldBinary=samples.filter(s=>s.phase==='full_cold_binary'),source=samples.filter(s=>s.sourceUncached),json=samples.filter(s=>s.representation==='json'),hits=samples.filter(s=>s.phase.startsWith('response_hits')&&s.source==='blockzilla');
 const explicitCold=(s,gets)=>s.fullyColdVerified&&s.storage?.archiveBackend==='r2'&&s.storage.r2.gets===gets&&s.storage.originHeads===0&&s.storage.s3.gets===0&&s.auth?.cache==='BYPASS'&&s.auth.kvReads===1;
 const proof={requests:samples.length,plannedRequests:119,stoppedEarly:stopped,successful:count(samples,s=>s.ok),jsonBodies:json.length,jsonMatchesSaved:count(json,s=>s.contentMatchesSavedReference),binaryBodies:coldBinary.length+samples.filter(s=>s.representation==='bin'&&s.phase!=='full_cold_binary').length,binaryMatchesOriginal:count(samples,s=>s.binaryMatchesReference),bundleMeasuredColdJson:count(cold,s=>s.label==='bundle'),bundleMeasuredColdJsonOneGetKvBypass:count(cold,s=>s.label==='bundle'&&explicitCold(s,1)&&s.archiveLayout==='bundle-v1'),baselineMeasuredColdJsonThreeGetKvBypass:count(cold,s=>s.label==='baseline'&&explicitCold(s,3)),bundleMeasuredColdBinaryOneGetKvBypass:count(coldBinary,s=>s.label==='bundle'&&explicitCold(s,1)&&s.archiveLayout==='bundle-v1'),baselineMeasuredColdBinaryThreeGetKvBypass:count(coldBinary,s=>s.label==='baseline'&&explicitCold(s,3)),sourceBundleVerified:count(source,s=>s.label==='bundle'&&s.sourceDataReadVerified),sourceBaselineIndexCachedVerified:count(source,s=>s.label==='baseline'&&s.sourceDataReadVerified),authHotBundleSource:count(source,s=>s.label==='bundle'&&s.authHotSourceVerified),authHotBaselineSource:count(source,s=>s.label==='baseline'&&s.authHotSourceVerified),responseHitWorkerRequests:hits.length,responseHitZeroReads:count(hits,s=>s.cache==='HIT'&&s.storage?.originReads===0),bundleRequests:bundle.length,baselineRequests:baseline.length,heliusRequests:count(samples,s=>s.label==='helius')};
 const report={schema:'blockzilla.slot-bundle-comparison.v1',startedAt,completedAt:new Date().toISOString(),deployments:{bundle:a.get('version'),baseline:'bf0bedfc-7216-4550-8e79-b671a93318f8'},plan:{requests:119,slots,bundleRequests:47,baselineRequests:47,heliusRequests:25,sequential:true,persistentPools:true,retries:0,defaultQuietGapMs:2200,authWarmQuietGapMs:5200},proof,windows,groups:summarize(samples),contentChecks:compareContents(samples,['helius'],['bundle','baseline']),connections:trace.connectionReport(),samples,notes:[
  'This is a bounded four-slot representation test. The new object for each slot is the exact original complete V1 Wincode bundle. It is an intentional data-layout comparison, not a proof of full-archive publication or a pure API/account A/B.',
  'Three runtime/client-pool warm calls are separate. Measured full-cold JSON and binary calls bypass all owner caches and require Auth BYPASS/KV1: one native R2 GET for the bundle target, three for the old target. Cloudflare storage-service and Helius cache states remain unknown.',
  'Each source group has a separate charged auth warm request after at least5.2seconds of quiet, then a2.2second gap before four measured requests. The old target uses a resolution warm request to admit its index; the bundle target has no serving index and uses one normal JSON warm request.',
  'Source-only bundle proof is one GET and zero owner data-cache hits, with auth observed separately. It must not be called an index-cache hit. The old source-only proof is two source GETs with its index cached. Actual auth TTL misses remain visible.',
  'Helius source-phase samples run after the two Worker source groups in each round; they are not a contemporaneous pair for every Worker call. Plain-cold target order alternates between rounds.',
  'Normal JSON and binary warmups are separate from response hits. Auth hot/cold conditions on hits remain visible. A response HIT proves zero object reads, not necessarily zero KV reads.',
  'Complete binary response SHA-256 values must equal saved original V1 bundles. Streamed expected source bytes at response headers are separate from actual buffered bytes and deferred source completion metrics.',
  'All URLs and credentials remain in environment variables. The report has no request header values, locator token, block body, or secret.',
  'There is no retry or post-run probe. Exact version-filtered CPU/cost windows will be collected separately, with adaptive sampling retained.'
 ]};
 await mkdir(dirname(resolve(a.get('output'))),{recursive:true});await writeFile(resolve(a.get('output')),JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});console.log(JSON.stringify({event:'complete',completedAt:report.completedAt,proof}));
 if(stopped||proof.requests!==119||proof.successful!==119||proof.bundleMeasuredColdJsonOneGetKvBypass!==8||proof.baselineMeasuredColdJsonThreeGetKvBypass!==8||proof.bundleMeasuredColdBinaryOneGetKvBypass!==8||proof.baselineMeasuredColdBinaryThreeGetKvBypass!==8||proof.sourceBundleVerified!==8||proof.sourceBaselineIndexCachedVerified!==8||proof.responseHitZeroReads!==24||proof.binaryMatchesOriginal!==32||proof.jsonMatchesSaved!==json.length)process.exitCode=1;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main(process.argv.slice(2)).catch(()=>{console.error('Slot-bundle comparison stopped. Private details were not printed.');process.exitCode=1;});
