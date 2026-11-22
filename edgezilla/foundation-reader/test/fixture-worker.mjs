// Local test wrapper only. This file is not the deployment entry point.
import reader from '../src/index.mjs';

let mode = 'normal';
let attempts = 0;
let nativeGets = 0;
let cancellations = 0;
let bodyCompletions = 0;
let lastOptions = null;

function controlledBody(body, expected, selectedMode) {
  if (selectedMode === 'long') {
    // Inject one oversized write so FLS rejects it before a complete valid
    // prefix can reach an HTTP client. Only this bounded local fault buffers.
    return new ReadableStream({
      async start(controller) {
        const original = new Uint8Array(await new Response(body).arrayBuffer());
        const oversized = new Uint8Array(original.length + 1);
        oversized.set(original); oversized[original.length] = 255;
        bodyCompletions += 1; controller.enqueue(oversized); controller.close();
      },
    });
  }
  const upstream = body.getReader();
  let received = 0;
  let sentInitial = false;
  let tail = null;
  let delayApplied = false;
  return new ReadableStream({
    async pull(controller) {
      if (selectedMode === 'slow' && sentInitial && !delayApplied) { delayApplied = true; await new Promise(done => setTimeout(done, 180)); }
      if (tail) { const bytes = tail; tail = null; controller.enqueue(bytes); return; }
      const next = await upstream.read();
      if (next.done) {
        bodyCompletions += 1; controller.close(); return;
      }
      let bytes = next.value;
      if (selectedMode === 'short') {
        bytes = bytes.subarray(0, Math.max(0, Math.min(bytes.length, expected - 1 - received)));
        received += bytes.length;
        if (bytes.length) controller.enqueue(bytes);
        return;
      }
      if (selectedMode === 'slow' && !sentInitial) {
        sentInitial = true;
        const split = Math.min(128, bytes.length);
        if (split < bytes.length) tail = bytes.subarray(split);
        bytes = bytes.subarray(0, split);
      }
      controller.enqueue(bytes);
    },
    async cancel(reason) { cancellations += 1; await upstream.cancel(reason); },
  }, { highWaterMark: 0 });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/__fixture/mode') {
      mode = url.searchParams.get('value') ?? 'normal';
      return Response.json({ mode });
    }
    if (url.pathname === '/__fixture/stats') return Response.json({ attempts, nativeGets, cancellations, bodyCompletions, lastOptions });
    const bucket = {
      async get(key, options) {
        attempts += 1;
        lastOptions = JSON.parse(JSON.stringify(options));
        if (mode === 'throw') throw new Error('Injected local R2 error');
        nativeGets += 1;
        const object = await env.FOUNDATION_ARCHIVE.get(key, options);
        if (!object?.body) return object;
        return {
          size: mode === 'size' ? object.size + 1 : object.size,
          httpEtag: mode === 'etag' ? '"00000000000000000000000000000000"' : object.httpEtag,
          range: mode === 'range' ? { offset: options.range.offset + 1, length: options.range.length } : object.range,
          body: ['short', 'long', 'slow'].includes(mode) ? controlledBody(object.body, options.range.length, mode) : object.body,
        };
      },
    };
    return reader.fetch(request, {
      BZ_READER_SECRET: mode === 'missing-secret' ? undefined : env.BZ_READER_SECRET,
      FOUNDATION_ARCHIVE: mode === 'missing-binding' ? undefined : bucket,
    }, ctx);
  },
};
