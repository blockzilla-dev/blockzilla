# Four-slot complete Wincode bundle test

The separate owner Worker is deployed and passed all 119 matched HTTP calls
and a separate ten-call binary source test.
The complete bundle removes two origin operations from a fully cold read.
It improves the measured cold JSON median from 255.354 to 141.284 ms in this
run, a 44.7% reduction. Helius remains faster at 118.391 ms, and the bundle
has a slower cold tail. The strict cold-latency target is not met.

No full epoch was migrated. Four additional test objects were written under
`serving/slot-bundles-test-20261122-v1` in the owner's existing Standard R2
bucket. The main Foundation-backed API and the prior native-fast deployment
are unchanged. No Foundation service or archive job was changed.

The test Worker is
[blockzilla-get-block-bundle-test](https://blockzilla-get-block-bundle-test.cheron-augustin.workers.dev),
version `8142880e-9475-4c45-b3a1-dc16b538d52f`, WASM SHA-256
`7b5b0f00ce65baef7c33adaa9fb020f34a040d5f86077a2203c92df216cab875`.
It serves only slots 470555971, 470663944, 470771932 and 470879999 in epoch 1089.

## Latency and correctness

The run made 47 bundle Worker calls, 47 previous native Worker calls and
25 Helius calls. Persistent pools and no retries were used. All 85 full JSON
bodies match the saved independent references and live Helius. All 32 binary
bodies match the exact original V1 bundle hashes. Thirty-two actual-WASM
bundle checks and ten existing-path checks passed before deployment.

Times include the complete response body. Values are p50/p95 in milliseconds.
Each cold row has two reads of each of the four selected blocks. Small sample
tails do not establish a production percentile.

| Path | Calls | p50 ms | p95 ms | Owner R2 GETs/call | Owner KV reads/call |
| --- | ---: | ---: | ---: | ---: | ---: |
| Previous native JSON, fully cold | 8 | 255.354 | 519.971 | 3 | 1 |
| One-bundle JSON, fully cold | 8 | 141.284 | 487.303 | 1 | 1 |
| Helius JSON, same blocks | 8 | 118.391 | 169.483 | — | — |
| One-bundle binary, fully cold | 8 | 126.953 | 306.075 | 1 | 1 |
| Previous native binary, fully cold | 8 | 196.070 | 375.241 | 3 | 1 |
| One-bundle JSON, response cache hit | 8 | 57.177 | 153.062 | 0 | 0.125 |
| Helius JSON, same later phase | 8 | 91.951 | 400.959 | — | — |
| One-bundle binary, response cache hit | 4 | 51.161 | 121.268 | 0 | 0.25 |

A fully cold Worker call uses `profile=1`: all application response, source,
index and auth caches are bypassed. Each bundle call used one R2 GET and one
KV read; the old path used three R2 GETs and one KV read. There were no origin
HEADs. Cloudflare's internal storage cache and Helius cache state cannot be
forced cold by this test. Helius internal storage read counts are unknown.
These are owner object API operations, not physical disk
read counts. The initial runtime/pool warm calls are separate.

All eight source-only JSON bundle calls used one R2 GET with auth cached and
zero KV reads. All eight old source-only calls used two R2 GETs with the index
and auth cached. All 24 measured Worker response-cache hits used zero R2
operations. Each target had one legitimate KV refresh in its JSON-hit phase
and one in its binary-hit phase; response-cache hits are not always auth hits.

## Read and CPU behavior

The binary path forwards the original native R2 body through an exact-length
stream. It does not decode the hot frame or copy network chunks into WASM.
It checks the admitted object length, strong ETag and R2 SHA-256 metadata on
the same GET. The upload and readback verified the complete original SHA-256.
The client-side benchmark also hashes the completed response. This does not
claim that Cloudflare performs no internal copies or that the Worker hashes
each binary body. Stream completion is separate from response headers.

JSON reads a bounded bundle, checks its delivered SHA-256 and borrows the two
outer-frame slices. It decodes the hot frame and the access data once and uses
the existing Base64 transaction renderer. JSON conversion still needs owned
values and output chunks. The actual previous blockhash is preserved.

Hosted profile clocks are I/O-gated and cannot measure CPU-only stages. The
cold JSON outlier used a reused socket: 487.303 ms total and 470.189 ms TTFB,
while its hosted profile reported 65 ms including 61 ms for R2 headers.
The same slot took 160.696 ms in round two. These numbers cannot assign the
remaining delay to network alone. Use platform CPU totals separately.

Platform invocation CPU and marginal costs are measured separately:

| Bundle path | Calls | Mean CPU ms | Core cost/M | With attributed startup/M |
| --- | ---: | ---: | ---: | ---: |
| Fully cold JSON | 8 | 30.1515 | $1.763030 | $1.763030 |
| Source JSON, cached auth | 8 | 40.945625 | $1.4789125 | $1.4789125 |
| Fully cold binary | 8 | 18.39325 | $1.527865 | $1.602765 |
| Source binary, cached auth | 8 | 6.529 | $0.790580 | $0.790580 |

These key rows have exact request-count and sample-count matches and reported
sample interval one. Source JSON pools two separate rounds with mean CPU of
28.433 and 53.45825 ms, so this small run does not establish stable CPU at scale.
CPU includes the invocation; the binary row separately shows 3.745 ms of mean
attributed startup. The initial JSON runtime warmup is also separate.
The platform counts for cache-hit phases do not match the request receipts,
so an exact cache-hit cost is not established. See [the CPU/cost notes](cost-notes.md),
[bundle platform CPU](platform-cpu-bundle.json) and
[the previous path CPU](platform-cpu-baseline.json). Local V8 sampling did not
produce a usable profile; no local CPU estimate is used.

The [separate ten-call supplement](binary-source-supplement.json) passed eight
binary source reads with auth cached and two charged auth warmups. Each binary
read used one R2 GET, zero KV reads, no source data-cache hit and the exact
original V1 hash. Both four-call platform groups are count-matched and
unsampled. Their pooled CPU is 6.529 ms; no startup was attributed to these
eight binary reads. This measured auth-cached binary condition is below $1/M
before logs, storage, fixed fees and rounding. It does not establish the same
cost for fully cold requests.

The two one-call JSON auth warmups used one KV read and zero GETs each. Across
all ten HTTP calls, cost is $0.8871/M, or $0.956102/M with attributed startup.
If both warmups are charged only to the eight desired binary deliveries,
cost is $1.108875/M binary outputs, or $1.1951275/M with startup. These different
denominators must not be mixed. The request supplement and
[its platform CPU receipt](platform-cpu-binary-source.json) remain separate
from the primary 119-call comparison. All 129 HTTP calls passed in total.

## Storage and request cost

The four complete bundles use 1,012,959 bytes. The same four original hot and
signature ranges plus current resolution objects use 1,016,409 bytes. The
bundle is 3,450 bytes smaller (0.3394%). Compared with only the same
compressed hot and signature ranges (701,292 bytes), the complete bundle adds
311,667 bytes, or 44.44%, for access data and framing. This is mainly an
operation-count change. It is not a meaningful transfer-byte reduction.

The test adds about $0.0000152/month of marginal Standard storage before
allowances and billing-unit rounding. Four PUTs cost $0.000018; four verified
readback GETs cost $0.00000144. A hypothetical replacement is a different
storage case from this temporary extra copy. Selected ranges cannot be
removed from the immutable existing epoch objects without a separate rewrite.

One GET and fresh KV auth cost $1.16/M before CPU. One GET with cached auth
costs $0.66/M before CPU and needs mean CPU below 17 ms to meet a $1/M core
total. See [the size and cost model](storage-cost-notes.md) for official rate
sources, exclusions and the four-block projection. No full-epoch migration
should use a projection from only these four blocks as a measured epoch size.

## Proposed Foundation service

The owner proposed a disk-backed service on Foundation. It can return a full
block plus access data on its local block-cache hit, or access data plus exact
bucket range identity on a miss. If it returns ordered signatures, the miss
needs only one compressed hot-block range from the existing bucket. The
browser does not need an epoch index.

A compact slot-to-used-ID list can avoid fetching/decoding the hot block first
to discover IDs. The four samples use a mean of 8,781 raw 32-bit ID bytes per block,
compared with 77,451 resolved dictionary bytes, before small headers and counts.
All four have no vote-hash entries. The host can resolve keys and signatures
while the Worker reads the hot frame if it sends the range descriptor first.
This is a proposed design; no service latency or operating cost was measured.
Read [the service design](foundation-resolution-design.md) and
[the measured data shape](resolution-service-shape.json).

## Evidence

- [Deployment and unchanged baselines](deployment.json)
- [Full object upload and readback](bundle-upload-verification.json)
- [Actual-WASM acceptance](local-acceptance-v1.json)
- [Existing-path acceptance](absent-config-acceptance-v1.json)
- [All 119 matched HTTP calls](main.json)
- [Eight auth-cached binary reads and two warmups](binary-source-supplement.json)
- [Final validation and deployment identity](validation.json)
- [Storage model](storage-cost-model.json)
- [Temporary uploader removal](uploader-cleanup.json)
