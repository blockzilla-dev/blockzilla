# Recent Compact V2 recovery is live

The public Worker now reads Foundation's existing retained Compact V2 blocks
first. It uses the original R2 ranges only after a checked finalized miss.
No second block store, new per-block index or block-result cache was added.

The owner's current target is low cost and adequate speed for small users.
No Helius requests or provider speed comparisons were made in this work.
Dedicated network machines for extreme B2B latency remain a separate target.

## Public route

The endpoint is on the existing owner-account Worker:
[blockzilla-get-block](https://blockzilla-get-block.cheron-augustin.workers.dev).
Use the existing API key and HTTP GET:

```text
/block/{slot}.compact?blockhash={expected_blockhash}&commitment=finalized
```

For exact processed recovery, also supply `cursor`, `bank_id` and
`source_session`. These values must identify the expected native frame.
The source pin is the same as the current Foundation producer. A processed
expiry returns an error; it does not produce a made-up archive cursor.

Recent responses have content type `application/vnd.blockzilla.stream.v2`,
`X-Blockzilla-Source: FOUNDATION_RECENT` and
`X-Blockzilla-Recovery-Format: native-bank-stream-v2`. They contain the original
`BZSTRM01` frame. The body stays in native streams outside WASM. A fixed-length
stream detects short, long, failed and stalled bodies. The client must also
check the full frame SHA, all object hashes, source, Bank and cursor before it
accepts the block or saves a cursor. A 200 status alone is not a complete frame.

For a finalized miss with an admitted archive route, the response is the
existing self-contained Wincode archive bundle. It has a distinct content
type, `X-Blockzilla-Source: R2_ARCHIVE` and
`X-Blockzilla-Recovery-Format: archive-wincode-bundle-v1`. It contains Compact V2
hot data, original signatures and the used-ID mappings. It does not claim to
reproduce native stream cursors or controls. The expected archive blockhash is
checked before range reads, then checked again against the resolved locator.

Existing `.bin` and JSON routes retain their contracts and storage path.
`BZ_FOUNDATION_LOOKUP_MODE=recent-only` prevents extra Foundation calls on those
routes. Both canary and production passed eight live compatibility checks:
four complete JSON digests and four original binary hashes. Each cold call
still used one owner index GET and two Foundation range GETs, no HEADs and no
Foundation recent, lookup or resolution HTTP calls.

## Recovery result

Both the canary and production passed **27/27 acceptance requests**. Production
version `50aaba11-468b-4c57-b1ad-ddc999ea9152` is active at 100%.

The isolated test reader saved a cursor, closed only its own stream connection
and paused. It repaired four missing block payloads through the Worker. Every
full original frame SHA and every Compact V2 object SHA matched. Replay from
the saved cursor then matched twelve original frames: four blocks, four
confirmation controls and four root controls. All four root proofs matched.
An independent reference reader supplied the expected missing-frame identities.

| Production check | Result |
| --- | --- |
| Recent payloads | 19 exact original frames; zero R2 reads |
| Finalized archive misses | 4 exact original bundles; 8 GETs and zero HEADs |
| Wrong identity or expired cursor | 4 errors; zero archive reads |
| Warm API-key checks | 8 requests; zero KV reads |
| Payload files written by the test | 0 |
| New serving copies | 0 |

The immediate finalized candidate was already rooted. This run therefore does
not prove a live unrooted rejection. Local native tests cover the root check.
No validator, native origin, production client pipe or application was stopped
for the fault. The test did not automate discovery of an unknown lost cursor
or change the running application client's recovery policy.

There are **162 passing actual-WASM checks**: 41 recent recovery, 110 existing
Foundation and 11 range-probe checks. All four local native-body fault cases
now fail stream completion. Client tests also prove that partial or wrong-hash
frames cannot advance the saved cursor. The native service passed **26 Linux
library tests**, including a real cancellation test. An aborted HTTP handler
cannot release its work permit while the blocking read still runs.

## Cost measurements

These are small, selected production cohorts, not invoice totals or capacity
tests. They bypass block-result caches. The runtime is warm except for the
separate initial startup request. OS file caches were not cleared.

| Production phase | Requests | Worker CPU mean | KV reads per call | R2 GETs per call | Variable cost per million |
| --- | ---: | ---: | ---: | ---: | ---: |
| Recent, API-key cache bypassed | 4 | 7.792 ms | 1 | 0 | **$0.962** |
| Recent, finalized lookup with cold auth | 4 | 6.840 ms | 1 | 0 | **$0.943** |
| Recent, API-key cache warm | 8 | 6.341 ms, sampled | 0 | 0 | No validated exact CPU cost |
| Archive fallback with cold auth | 4 | 18.905 ms | 1 | 2 | **$1.904** |

The priced four-request cohorts are count-matched and unsampled in the
version-filtered platform data. Warm-auth CPU used six samples weighted to
eight requests, so the strict model does not price it as a validated exact
measurement. The rejection cohort has only three platform records for four
real responses, even after a read-only retry and a wider query window. No CPU
cost is claimed for that cohort. All four functional response receipts passed.

The model includes Worker requests, CPU, observed KV reads, Foundation R2 reads
where present, and a scenario with one invocation log per request at the
configured 1% sampling rate. It uses official
[Workers](https://developers.cloudflare.com/workers/platform/pricing/),
[KV](https://developers.cloudflare.com/kv/platform/pricing/),
[R2](https://developers.cloudflare.com/r2/pricing/) and
[Logs](https://developers.cloudflare.com/workers/observability/logs/workers-logs/)
prices checked on 22 November 2026. It excludes monthly allowances, the fixed
subscription and Foundation machine/network charges. Analytics Engine is
[not currently billed](https://developers.cloudflare.com/analytics/analytics-engine/pricing/).
Its prospective per-point prices are separate; archive completion can emit
more than one point per request.

The initial startup request used 63.737 ms invocation CPU plus 24.564 ms
attributed startup CPU. Its model is $2.572 per million if every request had
that same startup cost and cold auth, including the 1% log scenario. It is
not blended into the steady recent cohorts. The feature does not establish
an all-in cost below $1 per million for every workload.

Foundation's synchronous work averaged 0.973 ms CPU for cold-auth recent reads
and 0.941 ms for warm-auth reads. The latter is about 0.26 CPU hours per million
calls. Recent payloads averaged 170,016 bytes, or about 170 GB per million
before transport overhead. Those quantities help price the existing machine
and its network; no hosting bill was assumed. The native CPU scope excludes
HTTP/header encoding and does not count work whose HTTP handler was cancelled.

Observed complete-response medians were 79 ms with cold auth and 39 ms with
warm auth. These are one Foundation test client's measurements, not a global
latency guarantee or a provider comparison. The four recent blocks differ
from the archive controls; their sizes are not a format-size comparison.

## Storage and deployment

The reader uses the producer's existing read-only `bank-v2` feed and `processed`
payload directory. It creates no projection, result database or payload spool.
SQLite is opened read-only with `query_only`; systemd also makes the source
directories read-only. Existing epoch tables supply the archive resolution.
A known archive miss needs one local 32-byte blockhash read before it can
authorize the two original Foundation range GETs.

The added persistent service is `blockzilla-recent-get-block.service`, on
loopback port 18962. It is enabled, has no test lifetime limit, and has an
eight-job bound, two-core CPU quota and 2 GiB memory maximum. Final process
RSS was about 292 MiB; cgroup memory also includes OS file cache. No dedicated
block-result RAM cache is enabled.

The Worker reaches it through three new private path patterns on the existing
`stream.blockzilla.dev` Cloudflare Tunnel. All original ingress rules remain
unchanged. No DNS record, new tunnel process or public machine port was added.
The public Worker received only the new private broker secret; its existing
S3 and locator secrets were retained. The temporary recovery test Worker was
deleted after production acceptance.

WASM SHA-256:
`abdf6f5a4a57e44fb0c9b343ced6c980f4a61e92eb20d597ef8453a4e6fc323b`.
Native binary SHA-256:
`49c6611aa0bb46607653067736a55945f8ff6f321fe77cff54e752af0ea33974`.

The validator stayed PID 1304643, invocation
`a1edd40e43404e8cb9c81a7caacfa1ee`, with zero restarts. The original processed,
Bank and origin units kept their process identities and native capacity stayed
admitted. Only the new reader had one planned restart for its cancellation
fix. Its final PID is 321829.

## Limits and operation

This serves the existing retained window. It does not extend retention or
connect the ledger-to-R2 publication handoff. The configured archive catalog
contains 12 epochs; four archived control blocks were tested here. Full
historical coverage and recovery across a long unpublished gap are not proven.

Source, session, producer generation and directories are pinned. After a native
source transition, review the new source and update the reader config and
Worker source pin together. Do not silently move a saved cursor to a new
session. Transport, source, corruption and identity errors are not archive
misses. The unchanged legacy routes remain separate archive readers.

The first two canary attempts stopped because of test harness defects: a
mixed receipt dictionary, then a root-proof search that omitted already seen
controls. Their records are retained. The second attempt's 15 valid recent
reads and exact replay are preserved, but neither failed run is presented as
full acceptance. The native build setup also had two failures before Rust
compilation; the corrected frozen-source Linux build and all tests passed.

## Evidence

- [Production recovery](production-recovery.json) and [summary](production-summary.md).
- [Production legacy compatibility](production-legacy-compatibility.json).
- [Platform CPU](production-platform-cpu.json) and [cost model](production-cost.json).
- [Production deployment](production-deployment.json) and [active state](production-final-state.json).
- [Final native health](native-health-final.json) and [service unit](blockzilla-recent-get-block.service).
- [Final Linux build](native-build-receipt-final.json) and [frozen native source](native-fix-v3-source.json).
- [Recent WASM checks](recent-worker-acceptance-v4.json), [existing checks](worker-acceptance-v4.json) and [probe checks](probe-acceptance-v4.json).
- [Canary acceptance](canary-recovery-v3.json) and [cleanup](canary-cleanup.json).
