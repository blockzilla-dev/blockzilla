# Native R2 cold-path profile and changes, 22 November 2026

The optimized read-only Worker is deployed at
https://blockzilla-get-block-native-fast.cheron-augustin.workers.dev.
The final auth-edge version is `bf0bedfc-7216-4550-8e79-b671a93318f8`;
release WASM SHA256 is
`f5b9675e07138c899fcde1752ab7ceafc67ca4b7bc66a8e7da044f7a91f0b973`.
The main public Foundation S3 API and original native full-size test are
unchanged. This task added no R2 data objects or serving indexes. It reuses
the four admitted epoch-1089 slots and their existing full-sized payloads.

## Where the cold time goes

The transport diagnostic used one socket for all 20 Worker requests. Its
first connection took 40.830 ms. It received only IPv4 addresses and made no
IPv6 fallback. The final four reused-connection requests still bypassed all
application caches and took 152.652–168.207 ms. Their pre-header profiles show
about 3–4 ms auth, 30–39 ms index lookup, then 55–61 ms for the two parallel
source ranges. They took another 35–52 ms from request send to headers outside
that recorded profile, and 6–29 ms to transfer the compressed body.
The latter waits cannot be assigned entirely to CPU or network from these
headers. A response HIT tail had about 21 ms to headers and 201 ms of encoded
body transfer on an already-reused socket.

Hosted Workers clocks advance with I/O. They do not measure CPU-only stages.
Local V8 profiles and separate version-filtered platform CPU were used for CPU.
The pre-edge-auth live run measured 35.375 ms mean CPU for plain cold JSON.
The production CPU-profile API returned no recent executions even during
active traffic; no production pprof was produced. Do not call this a complete
production flamegraph. The initial exploratory local trace included client
validation between samples and is excluded from the primary CPU comparison.

## Implemented changes

- Native WebCrypto SHA-256 checks the exact bounded resolution payload.
  Rust still checks framing, digest, identity, schemas and dictionaries.
- Checked resolution tables are parsed once and moved into block access.
  Compressed/decompressed hot buffers are freed before other reads finish.
- Hot-block decoding can run while the signature read remains in flight.
- An optional signed JSON locator starts the index and two data reads together.
  Full stored-locator equality is required before render. It still costs three
  R2 GETs. The client obtains the locator earlier; that is a separate cost.
- Concurrent ordinary response misses can share one cache fill inside an
  isolate. Only bounded plain status is shared; no I/O object, promise or Rust
  waker crosses requests. Followers use request-local timers, bounded to two
  seconds; stale fills expire after 30 seconds. Failed fills are not hits.
- Positive auth records share the existing Cache API across isolates. The
  original five-second deadline starts at the KV read. L2-to-L1 promotion
  carries only remaining lifetime and never republishes. Records are scoped
  by origin, configured namespace scope and key digest, with a 1 KiB bound.
  Invalid or negative records are never cached. Cache failures preserve a
  valid KV result. Full cold mode bypasses both auth layers.

The short-input Base58 candidate was rejected after variable repeated WASM
measurements showed no clear benefit. Requested Amsterdam/Frankfurt placement
probes were slower; their headers did not confirm target execution locations.
Both temporary Workers were deleted. Default placement remains selected.

## Separate 109-call performance run before shared edge auth

All 109 calls passed: 100 JSON results matched independent saved references
and four binary bodies matched original hashes. This run used version
`ddc5f9ff-8704-4c99-ba20-e712047ba360`. Values below are complete-response
p50/p95, from one client through CDG. Provider cache state is unknown.

| JSON mode | Optimized Worker | Helius | Worker R2 GETs |
| --- | --- | --- | --- |
| Plain, all application caches bypassed | 201.444 / 306.560 ms | 114.054 / 143.234 ms | 3 |
| Signed client hint, server caches bypassed | 162.114 / 342.777 ms | 105.586 / 304.497 ms | 3 |
| Index/auth available, data ranges forced | 121.065 / 127.174 ms | 95.459 / 132.818 ms | 2 |
| Complete response HIT | 52.512 / 230.392 ms | 94.544 / 149.215 ms | 0 |

The unchanged native baseline was 204.109 / 439.192 ms for plain cold JSON.
The hint reduced the optimized cold median by about 20%, but did not beat
Helius. Plain cold speed changed little. Cache-hit median was faster; its
observed tail was slower. The 16-request burst used four total R2 GETs, with
four leaders, four coalesced followers and eight ordinary hits. It still had
13 KV reads, which led to the final shared positive-auth layer.

Local fresh-runtime sampled active CPU fell 6.64% with native SHA/check-once.
Warm A/B ranges overlap. These samples are not production billing measurements.

## Final shared-auth verification

All 49 final calls passed: 44 full JSON results and five resolution bodies.
The sixteen concurrent requests used four object GETs, zero KV reads, nine
memory auth hits and seven shared-edge auth hits. Four source-only calls each
used two R2 GETs and zero KV reads. Sixteen complete response hits used zero
object reads, with one valid auth refresh after the original deadline. Across
all calls, including every warmup, there were 37 R2 GETs and nine KV reads.
The before/after bursts have different warmup histories and are not a controlled
latency A/B. The original 109-call timing report remains separate.

| Final mode | CPU evidence | Marginal USD per million HTTP requests |
| --- | --- | --- |
| Full cold JSON | Four unsampled calls, mean 30.019 ms | $2.480375 |
| Source-only, cached index/auth | Four unsampled calls, mean 34.251 ms | $1.705015 |
| Sixteen-request burst | Unsampled, mean 31.430 ms, KV0 | $1.0185925 |
| Complete response hits | Weighted estimate from 14 samples for 16 calls | $0.35451375 |

The burst is $1.16478875 with attributed startup, before logs and allowances.
Read and auth reuse worked, but this run did not prove a below-$1 burst.
Cold, source and burst CPU counts match the unsampled request windows.
Cache-hit CPU is adaptive sampled and must not be called exact. The conditional
blended models in the final cost report keep complete-response hit rates and
startup separate. A cache-heavy average can fall below $1; unique cold full
responses still cannot meet that target under these marginal rates.

## Cost limits

Standard R2 charges make three GETs cost $1.08/M before Worker requests, auth
and CPU. Two GETs plus one Worker request already cost $1.02/M before CPU.
Unique cold full JSON cannot meet a $1/M total target with this unchanged
object layout. Complete-response hits and repeated-request averages have
separate costs. Cost estimates use marginal published rates before account
allowances, fixed plan fees, invoice rounding and storage.

The full-index storage projection remains 33.74 GB per 432,000 indexed blocks,
about $0.506/month from eight modern samples. This task created no such index.

[109-call summary](summary.json), [raw requests](main.json),
[pre-edge-auth costs](cost-estimate.json), [placement test](placement-summary.json),
[placement cleanup](placement-cleanup.json),
[transport trace](../get-block-own-r2-20261122/transport-diagnostic-summary.json),
[CPU comparison](../get-block-native-cpu-20261122/comparison.json),
[final auth tests](../get-block-native-cpu-20261122/auth-edge-v7-wasm-tests.json),
[framing/stream tests](../get-block-native-profile-20261122/auth-edge-resolution-tests.json),
[concurrency tests](../get-block-native-profile-20261122/auth-edge-optimization-tests.json).

Sources: [R2 pricing](https://developers.cloudflare.com/r2/pricing/),
[Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/),
[KV pricing](https://developers.cloudflare.com/kv/platform/pricing/),
[Worker timers](https://developers.cloudflare.com/workers/runtime-apis/performance/),
[production profiling](https://developers.cloudflare.com/workers/observability/profiling-in-production/).

[Final 49-call summary](auth-edge-summary.json), [final CPU/costs](auth-edge-cost-estimate.json),
[final cost notes](auth-edge-cost-notes.md), and [active deployment](deployment.json).
