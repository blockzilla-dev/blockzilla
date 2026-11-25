#!/usr/bin/env node
import { createRequire } from 'node:module';
import { channel } from 'node:diagnostics_channel';
import { AsyncLocalStorage } from 'node:async_hooks';
import { lookup } from 'node:dns';
import { getDefaultAutoSelectFamily, getDefaultAutoSelectFamilyAttemptTimeout } from 'node:net';
import { performance } from 'node:perf_hooks';
import { readFile, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { sampleRequest, loadSlots, summarize } from './bench-get-block.mjs';
const require = createRequire(import.meta.url);
const { Agent, buildConnector } = require('undici');
const round = v => Number.isFinite(v) ? Number(v.toFixed(3)) : null;
const safeCode = value => /^[A-Z0-9_]{1,60}$/.test(value ?? '') ? value : 'UNCLASSIFIED';

export class TransportTrace {
  constructor() {
    this.active = null; this.requests = new WeakMap(); this.sockets = new WeakMap();
    this.context = new AsyncLocalStorage();
    this.spanIds = new Map(); this.nextSpanId = 0;
    this.connections = []; this.listeners = [];
    const subscribe = (name, fn) => { channel(name).subscribe(fn); this.listeners.push([name, fn]); };
    const on = (name, fn) => subscribe(name, data => { const span = this.requests.get(data.request); if (span) fn(span, data); });
    subscribe('undici:request:create', ({ request }) => {
      let id;
      for (let i = 0; i < (request.headers?.length ?? 0); i += 2) {
        if (String(request.headers[i]).toLowerCase() === 'x-blockzilla-benchmark-trace') id = String(request.headers[i + 1]);
      }
      const span = this.spanIds.get(id) ?? this.context.getStore() ?? this.active;
      if (!span) return;
      this.requests.set(request, span); this.mark(span, 'requestCreated');
    });
    on('undici:client:sendHeaders', (span, { socket }) => {
      this.mark(span, 'requestHeadersSent');
      const c = this.sockets.get(socket);
      if (c) { span.connectionId = c.id; span.socketUse = ++c.requests; span.socketReused = c.requests > 1; span.socketReadStart = socket.bytesRead; span.socket = socket; }
    });
    on('undici:request:bodySent', span => this.mark(span, 'requestBodySent'));
    on('undici:request:headers', span => this.mark(span, 'responseHeadersParsed'));
    on('undici:request:bodyChunkReceived', (span, { chunk }) => {
      span.encodedBodyBytes += chunk.byteLength; span.encodedBodyChunks++;
      if (span.timeline.firstEncodedBodyByte == null) this.mark(span, 'firstEncodedBodyByte');
      this.mark(span, 'lastEncodedBodyChunk');
    });
    on('undici:request:trailers', span => { this.mark(span, 'encodedBodyComplete'); if (span.socket) span.socketBytesReadDelta = span.socket.bytesRead - span.socketReadStart; });
    on('undici:request:error', (span, { error }) => { span.transportErrorCode = safeCode(error?.code); this.mark(span, 'requestError'); });
  }
  mark(span, name) { span.timeline[name] = round(performance.now() - span.started); }
  dispatcher(label, { connections = 1 } = {}) {
    if (!Number.isInteger(connections) || connections < 1 || connections > 64) throw new Error('Invalid connection bound.');
    let connection;
    const connect = buildConnector({
      lookup(host, options, callback) {
        const c = connection; c.events.push({ name: 'dnsStart', atMs: round(performance.now() - c.started) });
        lookup(host, options, (...args) => {
          const [error, addresses, family] = args;
          const families = Array.isArray(addresses) ? addresses.map(row => row.family) : family ? [family] : [];
          c.events.push({ name: 'dnsComplete', atMs: round(performance.now() - c.started), families, ...(error ? { code: safeCode(error.code) } : {}) });
          callback(...args);
        });
      },
    });
    return new Agent({ connections, pipelining: 1, connect: (options, callback) => {
      const c = { id: this.connections.length + 1, label, started: performance.now(), requests: 0, events: [] };
      connection = c; this.connections.push(c);
      c.events.push({ name: 'connectStart', atMs: 0 });
      const socket = connect(options, (error, connected) => {
        c.events.push({ name: error ? 'connectError' : 'ready', atMs: round(performance.now() - c.started), ...(error ? { code: safeCode(error.code) } : {}) });
        if (connected) { c.remoteFamily = connected.remoteFamily; c.alpn = connected.alpnProtocol || null; c.tlsProtocol = connected.getProtocol?.() ?? null; c.tlsSessionReused = connected.isSessionReused?.() ?? null; }
        callback(error, connected);
      });
      this.sockets.set(socket, c);
      for (const name of ['connectionAttempt', 'connectionAttemptFailed', 'connectionAttemptTimeout']) socket.on(name, (_address, _port, family, error) => c.events.push({ name, atMs: round(performance.now() - c.started), family, ...(error ? { code: safeCode(error.code) } : {}) }));
      socket.on('connect', () => c.events.push({ name: 'tcpConnected', atMs: round(performance.now() - c.started) }));
      socket.on('secureConnect', () => c.events.push({ name: 'tlsConnected', atMs: round(performance.now() - c.started) }));
      socket.on('close', () => c.events.push({ name: 'closed', atMs: round(performance.now() - c.started) }));
      return socket;
    } });
  }
  begin(label, dispatcher) {
    const span = { label, id: String(++this.nextSpanId), started: performance.now(), cpuStart: process.cpuUsage(), timeline: {}, encodedBodyBytes: 0, encodedBodyChunks: 0 };
    this.spanIds.set(span.id, span);
    this.active = span;
    span.fetch = async (url, options) => {
      const headers = new Headers(options?.headers);
      headers.set('X-Blockzilla-Benchmark-Trace', span.id);
      const response = await this.context.run(span, () => fetch(url, { ...options, headers, dispatcher }));
      this.mark(span, 'fetchHeadersResolved');
      return { status: response.status, ok: response.ok, headers: response.headers, body: response.body ? { getReader: () => {
        const reader = response.body.getReader();
        return { releaseLock: () => reader.releaseLock(), read: async () => {
          const value = await reader.read();
          if (value.done) { this.mark(span, 'decodedBodyComplete'); const cpu = process.cpuUsage(span.cpuStart); span.clientBodyCpuMs = { user: round(cpu.user / 1000), system: round(cpu.system / 1000) }; }
          else if (value.value?.length && span.timeline.firstDecodedBodyByte == null) this.mark(span, 'firstDecodedBodyByte');
          return value;
        } };
      } } : null };
    };
    return span;
  }
  finish(span) {
    const cpu = process.cpuUsage(span.cpuStart);
    if (this.active === span) this.active = null;
    this.spanIds.delete(span.id);
    return { connectionId: span.connectionId ?? null, socketUse: span.socketUse ?? null, socketReused: span.socketReused ?? null, timelineMs: span.timeline,
      encodedBodyBytes: span.encodedBodyBytes, encodedBodyChunks: span.encodedBodyChunks, socketBytesReadDelta: span.socketBytesReadDelta ?? null,
      sentToResponseHeadersMs: round(span.timeline.responseHeadersParsed - span.timeline.requestBodySent),
      encodedBodyTransferMs: round(span.timeline.encodedBodyComplete - span.timeline.firstEncodedBodyByte),
      clientBodyCpuMs: span.clientBodyCpuMs ?? null, clientCallIncludingValidationCpuMs: { user: round(cpu.user / 1000), system: round(cpu.system / 1000) },
      ...(span.transportErrorCode ? { transportErrorCode: span.transportErrorCode } : {}) };
  }
  close() { for (const [name, fn] of this.listeners) channel(name).unsubscribe(fn); }
  connectionReport() { return this.connections.map(({ started, ...row }) => row); }
}
function envValue(value) { if (!value?.startsWith('@')) throw new Error('Use an environment reference for both target URLs.'); const v = process.env[value.slice(1)]; if (!v) throw new Error('A target environment value is missing.'); return v; }
export async function main(argv) {
  const args = new Map();
  for (let i = 0; i < argv.length; i += 2) { if (!['--url','--rpc-url','--slots','--reference','--output'].includes(argv[i]) || !argv[i+1] || args.has(argv[i])) throw new Error('Invalid diagnostic arguments.'); args.set(argv[i], argv[i+1]); }
  const slots = await loadSlots(args.get('--slots')); if (slots.length !== 4) throw new Error('Exactly four slots are required.');
  const output = args.get('--output'); if (!output) throw new Error('An output path is required.');
  const references = JSON.parse(await readFile(args.get('--reference'),'utf8'));
  const digest = new Map(references.samples.filter(s => s.ok).map(s => [s.slot,s.contentSha256]));
  const trace = new TransportTrace(); const workerDispatcher = trace.dispatcher('blockzilla'); const providerDispatcher = trace.dispatcher('helius');
  const settings = { blockzillaUrl: envValue(args.get('--url')), providers: [{ label:'helius', url:envValue(args.get('--rpc-url')) }], blockzillaKey:process.env.BLOCKZILLA_RPC_API_KEY, timeoutMs:90000, rpcEncoding:'base64', maxTransactionVersion:1 };
  const task = (slot, phase, source='blockzilla', representation='json', uncached=false, sourceUncached=false) => ({ source,label:source==='provider'?'helius':'blockzilla',slot,phase,representation,uncached,sourceUncached,round:0,providerIndex:0 });
  const plan = [];
  for (const slot of slots) { plan.push(task(slot,'initial_full_bypass','blockzilla','json',true),task(slot,'paired_provider','provider')); }
  for (const slot of slots) plan.push(task(slot,'resolution_warmup','blockzilla','resolution'));
  for (const slot of slots) plan.push(task(slot,'source_only','blockzilla','json',false,true));
  for (const slot of slots) plan.push(task(slot,'normal_response'));
  for (const slot of slots) plan.push(task(slot,'reused_connection_full_bypass','blockzilla','json',true));
  const samples = []; const startedAt = new Date().toISOString();
  process.stdout.write(JSON.stringify({event:'start',startedAt,requests:plan.length,phases:[...new Set(plan.map(t=>t.phase))]})+'\n');
  try {
    for (const t of plan) {
      const span = trace.begin(t.label, t.source==='provider'?providerDispatcher:workerDispatcher);
      const s = await sampleRequest(t,{...settings,fetchImplementation:span.fetch}); s.transport=trace.finish(span);
      if (s.representation==='json') { s.contentMatchesSavedReference=s.contentSha256===digest.get(s.slot); if (!s.contentMatchesSavedReference) { s.ok=false; s.error='saved_reference_mismatch'; } }
      samples.push(s); process.stdout.write(JSON.stringify({event:'sample',label:s.label,phase:s.phase,slot:s.slot,ok:s.ok,totalMs:round(s.totalMs),socket:s.transport.connectionId,reused:s.transport.socketReused})+'\n');
    }
  } finally { await Promise.allSettled([workerDispatcher.close(),providerDispatcher.close()]); trace.close(); }
  const report = { schema:'blockzilla.transport-diagnostic.v1',startedAt,completedAt:new Date().toISOString(),plan:{requests:24,workerRequests:20,providerRequests:4,slots,sequential:true,retries:0,dispatcherConnectionsPerOrigin:1,pipelining:1},runtime:{node:process.version,bundledUndici:process.versions.undici,dispatcherUndici:require('undici/package.json').version,autoSelectFamily:getDefaultAutoSelectFamily(),autoSelectFamilyAttemptTimeoutMs:getDefaultAutoSelectFamilyAttemptTimeout()},notes:[
    'This is an instrumented transport diagnostic, not a final latency benchmark. A concurrent platform CPU capture was planned; its actual window and outcome must be recorded separately.',
    'Node global fetch uses an instrumented Undici dispatcher with one persistent HTTP/1.1 connection per target. The original benchmark used the default global dispatcher. No address family or DNS result was forced.',
    'Socket reuse is proven only by the same live socket ID. Connection events are socket-level; each target has one sequential request in flight.',
    'encodedBodyBytes counts compressed HTTP entity chunks before fetch decompression. It excludes TCP, TLS and HTTP framing. socketBytesReadDelta is a socket counter, not encrypted wire byte accounting.',
    'Client CPU covers this Node process only. Validation-inclusive CPU is separate from CPU through decoded-body completion. Neither measures Worker CPU.',
    'A profile=1 request bypasses owner application caches; Cloudflare storage service caches and provider caches remain unknown. Zero Worker profile CPU-stage milliseconds do not prove zero CPU.',
    'No URLs, request headers, tokens, DNS addresses or response bodies are saved.'
  ],groups:summarize(samples),connections:trace.connectionReport(),samples};
  await writeFile(output,JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
  process.stdout.write(JSON.stringify({event:'complete',completedAt:report.completedAt,requests:samples.length,errors:samples.filter(s=>!s.ok).length})+'\n');
  if (samples.some(s=>!s.ok)) process.exitCode=1;
}
if (process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) main(process.argv.slice(2)).catch(()=>{process.stderr.write('Transport diagnostic failed. Private error details were not printed.\n');process.exitCode=1;});
