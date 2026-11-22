#!/usr/bin/env node
import { readFile, writeFile, mkdir, access } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { sampleRequest, loadSlots, loadBinaryReferences, summarize, compareContents } from './bench-get-block.mjs';
import { bundleSourceProof } from './bench-slot-bundle.mjs';
import { TransportTrace } from './diagnose-get-block-transport.mjs';
const pause=ms=>new Promise(r=>setTimeout(r,ms));
const a=new Map();for(let i=2;i<process.argv.length;i+=2){const name=process.argv[i]?.replace(/^--/,'');if(!['url','slots','reference','binary-reference','output','version'].includes(name)||!process.argv[i+1]||a.has(name))throw Error('Invalid supplement arguments.');a.set(name,process.argv[i+1]);}
for(const name of ['url','slots','reference','binary-reference','output','version'])if(!a.has(name))throw Error('Missing supplement argument.');
if(!/^@[A-Z][A-Z0-9_]*$/.test(a.get('url')))throw Error('Use a private URL environment reference.');
try{await access(a.get('output'));throw Error('Output exists; no traffic sent.');}catch(error){if(error.code!=='ENOENT')throw error;}
const url=process.env[a.get('url').slice(1)];if(!url||new URL(url).protocol!=='https:')throw Error('Missing URL environment.');
const slots=await loadSlots(a.get('slots'));if(slots.length!==4)throw Error('Exactly four original slots required.');
const references=JSON.parse(await readFile(a.get('reference'),'utf8')),digests=new Map(references.samples.filter(s=>s.ok).map(s=>[s.slot,s.contentSha256]));
const trace=new TransportTrace(),dispatcher=trace.dispatcher('bundle'),samples=[],windows=[];
const settings={blockzillaUrl:url,blockzillaKey:process.env.BLOCKZILLA_RPC_API_KEY,timeoutMs:90000,rpcEncoding:'base64',maxTransactionVersion:1,binaryReferences:await loadBinaryReferences(a.get('binary-reference'))};
if(!settings.blockzillaKey)throw Error('Missing Worker authorization.');
const startedAt=new Date().toISOString();console.log(JSON.stringify({event:'start',startedAt,requests:10}));let stopped=false;
try{for(let round=0;round<2;round++){
 await pause(5200);const warmStart=new Date().toISOString();
 for(const [kind,list,sourceUncached]of[['auth_warm',[slots[0]],false],['binary_source',slots,true]]){
  if(kind==='binary_source')await pause(2200);
  const phase=kind+'_'+round,start=new Date().toISOString(),rows=[];console.log(JSON.stringify({event:'phase_start',phase,startedAt:start,requests:list.length}));
  for(const slot of list){let layout=null;const span=trace.begin('bundle',dispatcher);const fetchImplementation=async(url,options)=>{const r=await span.fetch(url,options);layout=r.headers.get('X-Blockzilla-Archive-Layout');return r;};
   const sample=await sampleRequest({source:'blockzilla',label:'bundle',slot,phase,round,representation:kind==='auth_warm'?'json':'bin',sourceUncached},{...settings,fetchImplementation});sample.transport=trace.finish(span);sample.archiveLayout=layout==='bundle-v1'?layout:null;
   if(kind==='auth_warm'){sample.contentMatchesSavedReference=sample.contentSha256===digests.get(slot);if(!sample.contentMatchesSavedReference){sample.ok=false;sample.error??='saved_reference_mismatch';}}
   else{sample.sourceDataReadVerified=bundleSourceProof(sample);sample.authHotSourceVerified=sample.sourceDataReadVerified&&sample.auth?.cache==='HIT'&&sample.auth.kvReads===0;sample.storageClass=sample.sourceDataReadVerified?'bundle_source_uncached_verified':'bundle_source_uncached_unverified';}
   samples.push(sample);rows.push(sample);if(!sample.ok||kind==='binary_source'&&!sample.authHotSourceVerified){stopped=true;break;}
  }
  const complete=new Date().toISOString();windows.push({phase,round,startedAt:start,completedAt:complete,requests:rows.length,firstRequestAt:rows[0]?.startedAt,lastRequestCompletedAt:rows.at(-1)?.completedAt,quietBeforeMs:kind==='auth_warm'?5200:2200});console.log(JSON.stringify({event:'phase_complete',phase,completedAt:complete,requests:rows.length,kvReads:rows.reduce((n,s)=>n+(s.auth?.kvReads??0),0),gets:rows.reduce((n,s)=>n+(s.storage?.originGets??0),0)}));if(stopped)break;
 }
 if(stopped)break;
}}finally{await dispatcher.close();trace.close();}
const binary=samples.filter(s=>s.representation==='bin');const proof={requests:samples.length,plannedRequests:10,successful:samples.filter(s=>s.ok).length,stoppedEarly:stopped,authWarmups:samples.filter(s=>s.representation==='json').length,authWarmJsonMatches:samples.filter(s=>s.contentMatchesSavedReference).length,binaryResponses:binary.length,originalBinaryMatches:binary.filter(s=>s.binaryMatchesReference).length,binaryOneGetAuthHot:binary.filter(s=>s.authHotSourceVerified).length,binaryKvReads:binary.reduce((n,s)=>n+(s.auth?.kvReads??0),0),binaryGets:binary.reduce((n,s)=>n+(s.storage?.originGets??0),0)};
const report={schema:'blockzilla.bundle-binary-source-supplement.v1',startedAt,completedAt:new Date().toISOString(),deploymentVersion:a.get('version'),slots,plan:{requests:10,rounds:2,chargedJsonWarmups:2,binarySourceCalls:8,sequential:true,retries:0,authWarmQuietMs:5200,sourceQuietMs:2200},proof,windows,groups:summarize(samples),contentChecks:compareContents(samples,[],['bundle']),connections:trace.connectionReport(),samples,notes:[
 'This is the one approved ten-call supplement to the119-call comparison, for129data calls total. It measures auth-hot binary CPU/cost directly; no provider or extra read probe is sent.',
 'Each round uses the same four original slots. Its normal JSON auth warm request is charged separately after5.2seconds of quiet; binary source reads follow2.2seconds later.',
 'All eight binary requests use profile=source: full bundle data cache and response cache bypass, auth retained. The required condition is one native R2 GET, zero HEADs, Auth HIT/KV0, and exact original full V1 binary SHA-256.',
 'Header snapshot byte counters remain separate from Origin-Expected-Bytes and deferred completion receipts. Exact complete binary delivery is verified independently.',
 'A persistent per-origin dispatcher is retained. Physical R2 cache state remains unknown. The original119-call timings and CPU windows remain unchanged.'
]};await mkdir(dirname(resolve(a.get('output'))),{recursive:true});await writeFile(a.get('output'),JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});console.log(JSON.stringify({event:'complete',completedAt:report.completedAt,proof}));if(stopped||proof.requests!==10||proof.successful!==10||proof.originalBinaryMatches!==8||proof.binaryOneGetAuthHot!==8)process.exitCode=1;
