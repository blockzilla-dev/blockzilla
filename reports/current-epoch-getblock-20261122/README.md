# Current epoch getBlock and cache checks

The public API is `https://archive.blockzilla.dev/block/<slot>.json` or `.bin`.
The same Worker keeps `getblock.blockzilla.dev` for existing clients. The
[current repair record](repair/README.md) describes the native/ledger JSON path,
checks, bounds, current deployment and retained coverage. The original failed
request and read-only diagnosis remain in
[diagnosis-before-repair.md](diagnosis-before-repair.md) and
[diagnosis.json](diagnosis.json).

The repaired target, slot 472608000, passed on the current safety version with
81 transactions, 1,326 rewards and the expected block and parent hashes. Its
normal miss used Foundation `LEDGER_COMPACT`, took 2.396 seconds and used zero
customer KV or billable reads. This was not a fully cold disk measurement.
See [the final target receipt](repair/target-final-safety-version.json).

## Public archive baseline

All **73 keyless GETs** passed on version
`1cc2931c-a23d-464b-b8ee-00b0e49d978d`, before the safety-header deployment.
The test reused four archived slots and saved references, with no provider
RPC requests or block body files. Normal fills stayed separate from hits.

| Format | Condition | Samples | Total p50 | Total p95 | Origin reads/request |
| --- | --- | ---: | ---: | ---: | ---: |
| Binary | `profile=1` bypass | 8 | 607 ms | 820 ms | 3 |
| JSON | `profile=1` bypass | 8 | 571 ms | 994 ms | 2 |
| Binary | Normal cache hit | 24 | 29 ms | 65 ms | 0 |
| JSON | Normal cache hit | 24 | 93 ms | 155 ms | 0 |

All 48 measured hits had zero origin reads. Their estimated warm marginal
**Worker request plus CPU cost was $0.339 per million**. This excludes the
base subscription, backend requests, hosting and storage. Platform CPU counts
were adaptive estimates, not exact billing. One CDG client/edge was tested.
`profile=1` bypassed Worker caches; it did not establish physically cold R2
caches or a new isolate. Profiling adds overhead.
See the [baseline report](public-cache-benchmark/README.md),
[HTTP receipts](public-cache-benchmark/http.json) and
[platform counters](public-cache-benchmark/platform-cpu.json).

## Cache safety decision

**Frontend Workers Cache is not enabled in production.** An unpromoted
version emitted a 64 KiB native ReadableStream prefix, then called
`controller.error`. A repeat was a cache HIT with the same producer UUID,
origin ray and body hash, despite a new edge ray. That failed the streaming
safety requirement. The evidence does not identify the internal fault boundary.

A separate one-request probe used the existing **Cache API**, with frontend
caching disabled. The complete good-body digest matched. The errored put
rejected, the bad key was absent, and both synthetic keys were deleted and
checked absent. This supports retaining the current streaming Cache API for
the tested error case; it is not a guarantee for every failure mode.

The acceptance and diagnostic work used **22 data requests**, separately from
the 73-request baseline. All failed attempts, including an inconclusive Python
transport diagnostic, are preserved. No probe was promoted. Temporary Version
URLs and workers.dev were disabled again. No new Worker, proxy, durable block
copy, R2 object or index was added.
See [the acceptance report](cache-live-acceptance/README.md) and
[the copied evidence manifest](cache-evidence-manifest.json).
