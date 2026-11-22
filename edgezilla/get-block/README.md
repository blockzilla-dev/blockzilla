# blockzilla-get-block

`blockzilla-get-block` serves Compact V2 archives from Cloudflare R2.
Foundation's query-with-signatures upload is the default storage layout. It
needs no block-access sidecar and does not change the durable archive files.

The public hostname is `https://getblock.blockzilla.dev`. Its getBlock GET
routes are free and require no API key when `BZ_GET_BLOCK_PUBLIC=true`.
These requests skip API-key storage and customer billing. The default for
other deployments is authenticated access. The original `workers.dev`
hostname remains available. The recent
stream recovery route is `GET /block/{slot}.compact`; see the
[recovery report](../../reports/recent-get-block-recovery-20261122/README.md)
for the required identity fields and the retained-window limit.

The public GET deployment is version `4d1b4d55-31f1-4e30-a287-717846eeff3c`.
It passed 232 local actual-WASM checks and nine live no-key checks. See the
[public deployment record](../../reports/public-getblock-20261122/README.md).
The [public benchmark](../../reports/public-getblock-benchmark-20261122/README.md)
separates cold origin reads, response-cache hits, platform CPU and per-million
request costs. Cache hits in this deployment still execute the Worker.

The earlier accepted production Worker version is
`50aaba11-468b-4c57-b1ad-ddc999ea9152`. Recent recovery reads use the existing
Foundation producer window. Finalized archive misses use the admitted original
archive ranges. The experiment records below describe their dated test builds.

The separate [owner native R2 test](../../reports/get-block-own-r2-20261122/README.md)
uses `wrangler.native-test.jsonc` and
`https://blockzilla-get-block-native-test.cheron-augustin.workers.dev`. It has
eight selected blocks from two partial epochs in a new owner bucket. Its four
source objects and eight resolution objects total 2,012,140 bytes. All remote
bytes, lengths and ETags match the checked local files. The source block and
signature bytes are unchanged; the new resolution records have new offsets,
source identities and the actual previous blockhash. This is not a full epoch.
At that test date, the main public API used Foundation S3 with its V11 deployment.
Native access, location and the smaller source objects can all affect this test.

The [full-sized epoch control](../../reports/get-block-own-r2-full1089-20261122/README.md)
uses `wrangler.native-full-test.jsonc` and
`https://blockzilla-get-block-native-full-test.cheron-augustin.workers.dev`.
It retains the original 63 GB epoch-1089 block/signature objects and multipart
ETags, with four selected slots indexed. All 72 control calls and 16 separate
warm-runtime calls passed. Native cold reads are faster than the current
Foundation S3 path, but still slower than Helius. Both test Workers are kept
separate from the main public deployment. The temporary copy Worker is deleted.

The [native fast profile and build](../../reports/get-block-native-fast-20261122/README.md)
is deployed separately at
`https://blockzilla-get-block-native-fast.cheron-augustin.workers.dev`, using
`wrangler.native-fast.jsonc`. It reuses the same four full-sized test slots and
adds no R2 objects. It uses native SHA-256, a checked-once dictionary decoder,
overlapping hot decode/signature reads, optional JSON locator hints and bounded
response-cache fill sharing. Plain cold JSON still loses to Helius. Cache hits
have a faster median. The final shared five-second auth cache and its original
KV-read deadline passed a separate 49-call check. See the linked report for
exact costs, sampling limits and the two unmet strict cold targets.

The [Foundation native reader](../foundation-reader/README.md) is a prepared
experiment. It keeps this public API in the owner's account and reads the
original Foundation objects through a small signed-GET Worker with a native
R2 binding. It does not copy block or signature data. The complete local
two-Worker test passes JSON/binary byte checks, source metrics, cache modes
and failure rejection. The optional transport fails rather than falling back
to S3 after a reader error.

This transport is **not deployed**. Foundation's current R2 credential is
active but cannot access the Workers deployment API (HTTP 403, code 10000).
At that test date, the public API used version
`2359b1b3-d95b-4e3b-bffc-b4161aac406f` and its direct S3 source path. No native-reader live latency result
is claimed. See the [preparation record](../../reports/get-block-native-r2-20261122/preparation.json).

The two data endpoints accept HTTP GET only:

```bash
curl -sS https://getblock.blockzilla.dev/block/470555971.bin \
  --output 470555971.bin

curl -sS 'https://getblock.blockzilla.dev/block/470555971.json?rewards=false&encoding=base64'
```

Other deployments require the existing Bearer header unless their public GET
setting is enabled. Public JSON and binary block successes have a long HTTP
cache lifetime. Errors are not cached. Compact recovery still requires its
exact block identity and retains `private, no-store` response headers.

`.bin` returns the Wincode `BlockzillaGetBlockBundleV1` wire format. It contains
a block and a block-local access blob with resolved keys, hashes and signatures.
Current-schema blocks retain their original zstd bytes. Historical full blocks
are converted to current Wincode message and metadata records, with the bundle
encoding set to `Wincode`. Thus a saved full bundle needs no historical marker. Use `access=0` to omit access data. That path copies compressed
block bytes without zstd, transaction or metadata decode. Clients of that path
must supply their own archive registries and schema selection.

`.json` returns a Solana `getBlock` JSON-RPC envelope with `jsonrpc: "2.0"`,
`id: 1`, and the full block in `result`. Full block GETs use Base64 transaction
encoding by default; `?encoding=base64` selects the same output explicitly.
Each entry has a `transaction` field of `["BASE64_SIGNED_TRANSACTION", "base64"]`,
standard RPC execution metadata and its `version` (`"legacy"`, `0`, or `1`). Explicit
`encoding=json`, `encoding=base58`, and `encoding=jsonParsed` return HTTP `400`
before storage access.

The full result includes failed transactions, loaded addresses and rewards.
Metadata retains the standard Solana RPC field encodings. Public keys remain
Base58, and inner-instruction `data` remains Base58. Block hashes also remain
Base58. The transaction encoding policy does not change the `.bin` Wincode
format. Use `rewards=false` to omit rewards. A slot absent from the admitted
index returns `result: null`; this does not prove that the chain skipped the
slot. JSON errors use a JSON-RPC envelope and an HTTP error status. Other
methods on block routes return `405` with `Allow: GET`. `POST /` supplies the
separate `getTransaction` method below. `GET /` and `GET /info` remain public.

## Four-slot complete bundle test

The separate owner canary in `wrangler.bundle-test.jsonc` serves four complete
original Wincode V1 objects with one native R2 GET per cold read. It has no
per-request resolution/index GET or HEAD. Binary bodies stay in native streams;
JSON uses a bounded bundle read and the existing Base64 renderer. The stored
access data includes the actual previous blockhash. Coverage is limited to
slots 470555971, 470663944, 470771932 and 470879999.

The canary is
`https://blockzilla-get-block-bundle-test.cheron-augustin.workers.dev`.
Use the existing API key with `GET /block/SLOT.json?rewards=false` or
`GET /block/SLOT.bin`. Add `profile=1` to bypass all Worker caches, including
auth; add `profile=source` to force a source read with auth caching available.
This test serves complete access data. It rejects `access=0` and client locator
variants. Unlisted slots return unavailable without an archive fallback.

All 119 matched HTTP calls passed. Cold JSON p50/p95 was 141.284/487.303 ms,
compared with 255.354/519.971 ms for the previous native path and
118.391/169.483 ms for Helius. Four bundles use 1,012,959 bytes, just 0.3394%
less than the same four hot/signature ranges plus current resolutions. No
full epoch was migrated. CPU, costs, source identity and cache limits are in
[the complete bundle report](../../reports/get-block-one-read-20261122/README.md).
The main API and the previous native-fast Worker are unchanged.

A separate ten-call supplement passed eight source-only binary reads with
cached auth: one GET, zero KV reads and 6.529 ms mean invocation CPU, for an
observed $0.79058/M before logs, storage, fixed fees and rounding. Its two auth
warmups are separate. Fully cold JSON is $1.76303/M; binary is $1.602765/M
including attributed startup. The cold cost target remains unmet.

The proposed Foundation disk service is separate from this deployed canary.
It can return a cached full block or a block-local resolution with signatures,
then let the owner Worker fetch one compressed range from Foundation R2.
[The design record](../../reports/get-block-one-read-20261122/foundation-resolution-design.md)
states the required slot-to-used-ID list and the unmeasured service costs.
No Foundation resolution service was deployed by this experiment.

## Per-slot resolution and client reads

The production Worker now admits a per-slot resolution object for the eight
benchmark slots in `BZ_RESOLUTION_SLOTS`. The objects are in the owner's R2
bucket, `blockzilla-get-block-index`, under an immutable serving generation.
The original block and signature objects stay in Foundation R2. Other slots
continue to use the stored registry reader. Eight published objects do not
establish full-epoch or full-history coverage.

Each resolution object contains the exact hot index row, parent slot,
blockhash, **previous blockhash**, message/metadata schema and source object
lengths and strong ETags. It also contains the block's resolved tables and
per-transaction signature counts. It does not contain compressed block bytes
or signature bytes. The previous hash follows the actual parent, including
epoch boundaries; it never substitutes `slot - 1`.

A full cold JSON or binary request uses one resolution GET and two parallel
source range GETs. There are no index or schema HEADs in this path. The source
GETs use `If-Match` and check ETag, object length and exact range. A complete
response hit still needs zero archive operations. `profile=1` bypasses all
Worker response and archive caches for the cold-read measurement.

The full binary response retains the existing V1 Wincode bundle. It joins its
small framing, the compressed hot-block stream, access framing, signature
stream and dictionary suffix. Network chunks stay in JavaScript and do not
cross WASM. Native streams apply backpressure, cancellation and exact-length
checks. The Worker does not decompress or decode the hot block in this path.
It still parses the small resolution object. This is not a claim of zero
copies inside Cloudflare or zero-copy JSON conversion. JSON needs zstd decode,
typed values and encoded output; output now uses bounded channel chunks rather
than two complete JSON buffers. The redundant decompressed frame is released
after the owned block is parsed.

A client can download the resolution object once per block and generation:

```text
GET /block/SLOT.resolution
Authorization: Bearer API_KEY
```

Save the bytes and the `X-Blockzilla-Locator` response header. Then request:

```text
GET /block/SLOT.bin?access=client&locator=LOCATOR
Authorization: Bearer API_KEY
```

The second request uses two source GETs without a resolution GET. Its distinct
`application/vnd.blockzilla.get-block-parts.v2` format contains a 64-byte header
and the original compressed block and signature windows. The header contains
`BZPART2!`, little-endian u64 slot/hot length/signature length, and SHA-256 of
the exact locator Wincode bytes. The saved resolution carries the dictionary,
signature counts, source schemas and parent hashes. The HMAC locator protects
the source ranges; it is not an API key, and every request still needs auth.
The cache key separates this format and locator from the full V1 bundle.

The first client read therefore costs one resolution download plus two source
reads. Report that first download separately; it is not free. A saved per-slot
object resolves only that block. Clients that read many blocks can instead
reuse the original epoch registries, with the optional dense slot index for
offsets and parent hashes. The measured pubkey registries for epochs 1089 and
1090 are 993,910,560 and 1,046,858,176 bytes. A browser does not need to load
those whole files for the per-slot path.

`scripts/bench-resolution-client.mjs` checks the protocol and reconstructs the
original V1 bundle byte for byte. The native `render-resolution-client` CLI
builds JSON from the two saved files and reports decode/render CPU and wall
time. This native test is separate from browser codec packaging or browser
performance.

```bash
cargo run --locked --release -p blockzilla-get-block \
  --no-default-features --features cli,worker --bin render-resolution-client -- \
  --resolution SLOT.resolution.v1.bin --parts SLOT.parts.v2.bin \
  --output SLOT.json --no-rewards
```

The measured eight resolution objects total 625,602 bytes (78,200.25 bytes per
block), a 45.1% addition to their compressed block and signature bytes. The
sample mean extrapolates to 33.78 GB, or about $0.51 per 432,000-block epoch
per month at R2 Standard rates. This is not a full-epoch size measurement.
One-time object PUTs add about $1.94 per full epoch before allowances. Index
storage and index reads belong to the owner's account; original block and
signature reads remain on Foundation's account. See the measured
[storage model](../../reports/get-block-resolution-20261121/storage-overhead.json).

Version `2359b1b3-d95b-4e3b-bffc-b4161aac406f` introduced a
bounded positive API-key check cache and faster metadata output. Enable the
auth cache with `BZ_AUTH_CACHE_SCOPE` set to the actual API-key KV namespace
ID; change the scope when that binding changes. It stores only completed,
valid, enabled records under hashed keys: at most 256 records and 128 KiB per
isolate. The five-second expiry starts before the KV read and does not slide
on a hit. Failures are not cached. The cache adds at most five seconds of
staleness after the KV check; KV propagation delay remains additional. Legacy
POST authentication still reads KV on each request.

The native-fast build also shares positive records through the Cache API.
Each edge envelope is at most 1 KiB and is scoped by origin, namespace scope
and key digest. Its original KV-start UTC time sets the five-second deadline.
A new isolate keeps only the remaining lifetime; it does not renew or
republish a hit. Disabled, invalid and negative records are not cached.
Cache failures preserve a valid KV observation. Fully cold profiling bypasses
both auth levels. This experiment deployed the edge layer on native-fast and
kept the main public V11 deployment unchanged at that time.

New builds add `X-Blockzilla-Auth-Cache-Tier: MEMORY|EDGE|KV|BYPASS` and
`X-Blockzilla-Cache-Fill: HIT|LEADER|COALESCED|FALLBACK|BYPASS`. Only plain
completed state is shared between concurrent fills; I/O objects and wakers
remain inside the request. Fill waits stop after two seconds, and stale fill
state expires after 30 seconds.

A client that already has `X-Blockzilla-Locator` from a resolution GET can use
`GET /block/SLOT.json?encoding=base64&locator=TOKEN`. The server verifies the
hint, starts all three reads together, and checks the full stored locator
before rendering. This keeps three GETs. Index download is a separate one-time
request; client-hinted server-cold is distinct from a first plain cold request.

Every successful GET reports `X-Blockzilla-Auth-Cache: HIT|MISS|BYPASS` and
`X-Blockzilla-Auth-KV-Reads: 0|1`. Authentication still precedes response-cache
lookup. The normal path reuses the index and raw-range caches described below.
The two diagnostic modes have distinct meanings:

| Query | Response cache | Index/auth caches | Source-range caches |
| --- | --- | --- | --- |
| `profile=1` | Bypass | Bypass | Bypass |
| `profile=source` | Bypass | Keep | Bypass |

An admitted full block in source mode uses two Foundation GETs when the index
is cached. An expired auth entry can still require a KV read; its receipt is
reported rather than called an auth hit. Source mode is not fully cold. The
benchmark records its index/auth warmup requests separately. Neither mode can
purge physical R2 caches or a provider's cache.

The [new same-eight-block run](../../reports/get-block-cpu-20261121/summary.json)
passed 232/232 calls, with all 112 JSON samples matching the saved references
and all eight results matching live Helius. All 90 native tests and both
release-WASM suites passed; the resolution suite has 18 checks, including
auth expiry, revocation, two-read source mode and fully cold cache bypass.

| Latest full JSON path | Samples | Full body p50 / p95 |
| --- | ---: | ---: |
| All Worker caches bypassed: three GETs and one KV read | 8 | 581.988 / 963.037 ms |
| Cached index and auth: two Foundation GETs, zero KV reads | 7 | 525.168 / 709.137 ms |
| Complete response hit | 32 | 51.724 / 94.177 ms |
| Helius repeats, provider cache state unknown | 32 | 105.454 / 157.666 ms |

All eight source-mode JSON reads used zero owner R2 GETs and two Foundation
GETs. Seven had auth hits; one had a legitimate TTL miss. The Helius requests
for the same seven blocks took 112.934 / 148.177 ms. Cold reads are still
slower. The separate current stage profile measured an arithmetic median
400 ms for the parallel Foundation ranges, versus 44 ms for index headers.

The writer now appends slices rather than copying one byte at a time after
crossing 64 KiB. It also reuses key encodings in a request-local table below
20 KiB and formats token amounts in stack buffers. Output bytes and flush
points are unchanged. Native buffered CPU improved 10.04%; the controlled
local streamed-WASM median improved 5.01% (43.666 to 41.477 ms). See the
[CPU comparison](../../reports/get-block-cpu-20261121/README.md).

The dedicated eight-call production cold CPU check measured 38.909 ms mean
invocation CPU, or $0.778 per million requests for CPU alone. Including the
separately attributed startup CPU gives $0.817. These production samples and
the controlled local comparison are separate evidence. The
[cost model](../../reports/get-block-cpu-20261121/cost-estimate.json) keeps
fully cold, cached admission and complete hits separate. No new R2 objects
were added; index size and storage cost are unchanged.

| Dedicated JSON CPU/cost check | Mean invocation CPU | Combined variable cost per million HTTP requests |
| --- | ---: | ---: |
| Fully cold | 38.909 ms | $2.658 |
| Cached index, two source reads, one auth miss in eight | 46.389 ms | $2.010 |
| Complete response hit, one auth miss in 24 | 2.461 ms | $0.370 |

The counts match the eight/eight/24 request plans. The first 16-hit metric
window contained 24 platform invocations and is kept as contextual evidence;
the separate 24-hit check matched exactly. At an assumed 80% complete-response
hit fraction, the JSON model is $0.828/M with fully cold misses or $0.698/M
with cached-admission source misses. These are conditional variable-cost
models, not all-cold costs or a whole-account invoice. Fixed fees, storage,
construction, logs and one-time admission costs remain separate. They use
all HTTP requests as the denominator. The existing billing policy still
charges only archive-backed requests; a lower cost per HTTP request does not
establish a lower cost per billable backend request.

The prior cache release was `566ecc0a-949d-417b-90cd-89c629bc9073`. JSON and
native binary now share the same source-range cache. The private key includes
the source generation, object ETag and length, path, offset and range length.
Binary cache reads and writes remain native streams. Native cache writes are
limited to 1 MiB per range and an 8 MiB queued payload per request. They run
with `waitUntil`; native stream backpressure can still affect delivery.
Checked resolution objects up to 256 KiB can also use the existing 4 MiB
immutable-byte LRU. Resolution data enters either cache only after validation.
Request I/O and live streams are not shared across independent requests.

The [shared-cache benchmark](../../reports/get-block-cache-20261121/summary.json)
passed 192/192 calls. All eight full Base64 results match Helius. Across the
24 first normal requests for three formats, each block needed one index GET,
one hot-block GET and one signature GET in total. Fourteen of the sixteen
later-format requests were response-cache misses with zero origin GETs. The
other two followed `access=0` and fetched only their missing signature range.
All 96 complete response hits used zero origin reads. Forced-origin requests
still need three GETs for a full block and two for `access=0`.

| Latest path | Worker-cache bypass p50 / p95 | Response hit p50 / p95 |
| --- | ---: | ---: |
| Base64 JSON | 613.624 / 803.644 ms | 70.798 / 276.717 ms |
| Full V1 binary | 577.724 / 1090.542 ms | 40.793 / 119.014 ms |
| Binary `access=0` | 485.805 / 1216.482 ms | 38.081 / 219.772 ms |

Helius repeats took 126.740 / 336.508 ms in this run. Cache hits have a lower
median; cold JSON is still slower. Network variation prevents attributing the
change between short runs to code alone. No new source or index objects were
published. The index storage estimate is unchanged.

The prior [Base64 benchmark](../../reports/get-block-base64-20261121/summary.json)
passed 192/192 requests on production version
`074812ac-a908-4eba-bec5-02752230eae6`. All eight full JSON results match
Helius, with exact numbers and transaction order. One client used CDG,
concurrency one, eight forced-origin samples and 32 response hits per format.

| Current path | Worker-cache bypass p50 / p95 | Response hit p50 / p95 |
| --- | ---: | ---: |
| Base64 JSON, three GETs | 525.105 / 866.116 ms | 62.347 / 97.985 ms |
| Full V1 binary, three GETs | 504.209 / 1139.346 ms | 44.101 / 73.334 ms |
| Binary `access=0`, two GETs | 433.286 / 944.827 ms | 33.748 / 71.621 ms |

Helius Base64 repeats took 96.824 / 170.813 ms. Its separate first comparison
pass took 100.634 / 186.722 ms; its cache state is unknown. All 96 Worker
response hits used zero archive operations. Cache hits are faster in this run;
cold JSON remains slower than Helius. This is not a global performance claim.
JSON uses HTTP zstd at the Worker and gzip at Helius. Body sizes are decoded
bytes. The test bypasses Worker caches, not physical caches inside R2.

The separate [cold stage profile](../../reports/get-block-base64-20261121/cold-profile-summary.json)
matched all eight JSON references and both original binary bundles. Arithmetic
median waits were 4 ms for authentication, 43 ms for index headers and 463.5 ms
for the two parallel Foundation ranges. Most source time precedes response
headers. These stage medians are from a separate pass; do not add them to, or
subtract them from, the main benchmark quantiles. Worker clocks can stay fixed
during CPU work, so zero decode time in a profile header does not mean zero CPU.

The [native Base64 client](../../reports/get-block-cold-profile-20261121/native-base64.json)
matched all eight results. Its median block decode and render CPU was 9.951 ms,
using ten local runs per block. This is native CPU, not Worker or browser CPU.
The release WASM tests also checked all 370 transaction packets and 413
signatures in one block against Helius. No new source or index objects were
published for this update. The same eight resolution objects remain in use.

The [production platform metrics](../../reports/get-block-base64-20261121/platform-cpu-v9.json)
include all eight cold JSON profile calls, with CPU p50/p95 of
52.317/138.896 ms and mean CPU of 63.513 ms. Network wait is the largest
measured part, but CPU is not zero. The mixed main window reports 143 of
144 planned Worker calls; that count difference remains unexplained. Two
bounded production stack-profile attempts returned no recent executions and
captured no profile. The local CPU profile and production metrics are separate.

At the sample mean CPU, the [marginal cold JSON cost estimate](../../reports/get-block-base64-20261121/cost-estimate.json)
is about $3.15 per million across both accounts: $2.43 on the owner's account
and $0.72 for Foundation source reads. This includes one KV auth read, one
Worker invocation, CPU and three R2 GETs. Index storage, construction, logs,
account fees, allowances and rounding are separate. The eight-block CPU mean
is a sample, not a full-history cost measurement. Current rates are from
[Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/)
and [KV pricing](https://developers.cloudflare.com/kv/platform/pricing/).

Regional placement tests reduced some source waits but increased client and
index travel time. They did not beat Helius; production retains default edge
placement. Another slot index cannot remove the two original source requests.
The temporary profiling Worker was removed after the tests.

The [prior V7 eight-block run](../../reports/get-block-resolution-20261121/main.json)
used parsed JSON transaction encoding (`encoding: "json"`). These results do
not measure the current Base64 GET policy. The V7 run passed all 192 requests: 144 Blockzilla and
48 Helius. All JSON results matched. It used the same slots and parsed JSON
options as the baseline below, one client in CDG, eight forced-origin samples
and 32 repeat samples per representation.

| Path | Worker-cache bypass p50 / p95 | Response hit p50 / p95 |
| --- | ---: | ---: |
| Full parsed JSON, three GETs | 587.651 / 894.570 ms | 54.332 / 255.557 ms |
| Full V1 binary, three GETs | 590.304 / 844.009 ms | 35.121 / 58.863 ms |
| Binary `access=0`, two GETs | 436.153 / 528.746 ms | 29.913 / 78.654 ms |
| Saved-index client parts, two GETs | 445.321 / 692.929 ms | 30.961 / 41.732 ms |

Helius repeat parsed JSON took 124.160 / 2090.599 ms. It had a high tail in
this short 32-request sample. Its cache state is unknown. The cached JSON is faster in
this sample; cold JSON remains slower. The binary
client run was a separate batch, and its times exclude index download and
local JSON conversion. All eight first index reads took 103.130 / 302.056 ms
and one GET each.
All eight repeat index reads hit with zero storage operations.
See [client receipts](../../reports/get-block-resolution-20261121/client.json).
Full cold reads now cost $1.08 per million in Standard R2 operations before
allowances: $0.36 for the owner's index and $0.72 for Foundation's source
objects. A saved-index data read costs $0.72, with its one-time index download
charged separately. Worker, KV, CPU, storage and object creation are additional.

All eight prior V7 [native local parsed JSON results](../../reports/get-block-resolution-20261121/native-client.json)
also matched Helius. Block decode took 1.576 / 2.658 ms p50/p95. Complete local
JSON conversion took 101.866 / 143.344 ms wall time and 98.657 / 141.449 ms
process CPU time, excluding network and process/file setup. These are separate
local measurements, not a measured combined download/render latency or browser
result. Clients that consume Compact V2 directly can avoid full JSON rendering.

The [prior V7 platform sample](../../reports/get-block-resolution-20261121/platform-cpu.json)
contains 208 mixed Worker HTTP requests with no runtime errors. Mean CPU was
12.0 ms per request. WASM linear-memory p99 was 5,177,344 bytes; V8 memory p99
was 21,024,064 bytes. These separate quantiles are not a total peak-memory
measurement and do not measure a browser client.

Streaming response headers report GET/HEAD attempts before the body completes.
`X-Blockzilla-Storage-Bytes-Mode: streamed-completion` means that the ordinary
byte/success counters include only completed buffered reads at header time.
`X-Blockzilla-Origin-Expected-Bytes` gives the pending source byte count. A
separate `source_range_complete` Analytics Engine point adds actual bytes and
one success after each exact source stream completes. Its request, billing
and attempt counters are zero. A cold full binary request can emit two such
points. This does not add a customer request or backend-request charge; the
points remain Analytics Engine write usage. A cache fill can finish after a
client cancels, and its completed source read is still counted. Complete response hits
overwrite the expected origin byte count with zero. A failed stream aborts
the body; it cannot change an already sent HTTP status into a JSON error.
Direct GET render errors abort even before the first chunk, so a complete
HTTP 200 error envelope cannot enter the response cache. Failed or cancelled
native streams retain attempt counts but do not add completion-byte totals;
those totals describe fully completed streams, not partial failure traffic.

## Read one transaction

The authenticated `POST /` route accepts one `getTransaction` JSON-RPC request.
Block requests retain their HTTP GET routes. JSON-RPC batches and other POST
methods are rejected.

`BZ_HTTP_GET_ONLY` must be absent or set to `false` to enable this POST route.
A deployment with `BZ_HTTP_GET_ONLY=true` continues to accept HTTP GET only.

```bash
curl -sS https://RPC_HOST/ \
  -H "Authorization: Bearer $BLOCKZILLA_RPC_API_KEY" \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"getTransaction","params":["SIGNATURE",{"encoding":"base64","maxSupportedTransactionVersion":0}]}'
```

The route accepts `json`, `base64`, and `base58`. It also accepts a legacy bare
encoding string as the second parameter. The legacy `binary` encoding returns
a bare base58 string. `jsonParsed` is rejected explicitly. Binary encoding
supports legacy and V0 transaction messages. V1 JSON is available when the
client declares support; V1 binary returns an explicit version error.
Versioned transactions require `maxSupportedTransactionVersion`. Legacy
responses omit `version` when that field is absent from the request. The archive
supports `confirmed` and `finalized`; `processed` is rejected.

Set `BZ_SIGNATURE_INDEX_URL` to the HTTPS origin of the native signature
service and `BZ_SIGNATURE_CATALOG_DIGEST` to its exact published catalog
SHA-256. Supply `BZ_SIGNATURE_INDEX_TOKEN` as a Worker secret. Do not put it
in Wrangler vars or source files. HTTP loopback origins are accepted for local
tests. `BZ_SIGNATURE_CLUSTER_ID` defaults to `mainnet-beta`.

For the live segment service, set `BZ_SIGNATURE_CATALOG_ID` to the stable
identity from its authenticated `/v2/info`. This selects `/v2/lookup` and
permits catalog changes within that identity. The service returns a bounded
candidate list with an immutable archive prefix for each candidate. The
Worker checks the full first signature and continues after a false candidate.
It can return a later exact match after a source error; if no exact match is
found, an unresolved source error remains an error. The Worker secret is the
service's read token. Keep the separate administration token with the input
producer. The separate native signature service is outside this package.
The Worker keeps its `getTransaction` compatibility module and test routes.

The native v2 service retains only the MPHF in RAM. It uses SHA-256 signature
hashes and reads each candidate slot with its eight-bit fingerprint from one
packed five-byte SSD record. It has no XOR filter. The Worker pins the catalog response, reads
`archive-v2-generation.json` from the same epoch prefix as the compact data,
checks its canonical digest and object lengths, reads the candidate block and
compares the complete first transaction signature. Secondary signer signatures
cannot identify a transaction. Failed execution and original metadata remain
in a successful response. The publication prefix must remain immutable; the
Worker does not hash entire archive objects during a request.

Publish each indexed epoch's generated manifest with its unchanged archive
objects before enabling the route. A missing or mismatched manifest, missing
signature object, corrupt block, locator failure or timeout returns an error.
If the service has partial history, a miss returns an explicit coverage error
instead of `null`. A completed response does not establish full-history index
coverage or validate an upload receipt.

Transaction requests remain uncached and return `Cache-Control: private,
no-store`. They use the existing customer authentication and request metrics.
The native locator read alone is free under the existing receipt rule. A
request becomes billable when the Worker attempts R2 or S3 archive access.

The local end-to-end test runs the release WASM with a real native locator,
local R2, and independent CAR transaction oracles:

```bash
node scripts/test-transaction-worker.mjs \
  --fixtures /ABSOLUTE/FIXTURES \
  --oracle /ABSOLUTE/RESULTS/oracle-157.ndjson \
  --oracle /ABSOLUTE/RESULTS/oracle-822.ndjson \
  --locator http://127.0.0.1:PORT \
  --catalog CATALOG_SHA256 \
  --token-file /ABSOLUTE/PRIVATE_TOKEN_FILE \
  --build /ABSOLUTE/BUILD/index.js
```

This test does not publish a Worker or modify cloud objects. It checks JSON
parity with `getBlock`, exact original CAR wire bytes, failed transactions,
version support, source bindings, incomplete coverage, false candidates,
authentication and locator failures.
Add `--all true` to check every transaction in the supplied CAR oracle files.
The default selects a bounded sample from each epoch. Full mode reports
progress every 250 checked transactions.

Original CAR log comparison is exact by default. Existing Compact V2 log
parsing removes trailing white space from source lines. Those bytes cannot be
recovered from the stored archive. `getTransaction` returns the stored log text.
For an explicit old-archive acceptance run, add
`--allow-trailing-space-projection true`. That profile permits only removal
of trailing ASCII space, tab, CR and LF. It requires equal line counts and
exact remaining text. The receipt records every changed line, its transaction
location, original text, returned text and removed suffix bytes. It reports
original CAR log parity separately from the API path, signed transaction bytes
and other checked metadata. A passing run under this profile does not establish
exact original log bytes.

Current and historical source integer encodings use bounded exact decoders.
Fixed schema marker objects select historical message and metadata grammars;
mainnet epochs 0–2 require an explicit message marker. Unsupported raw transaction
or metadata fallback records return an explicit error. For ambiguous TowerSync
instructions, the JSON renderer uses the exact shared native message serializer
and Ed25519 signature proof to select the original instruction bytes. It does
no signature-search work for messages that have no ambiguous instruction. The
whole-message candidate search is limited to 8,192 combinations. Broad live
provider comparisons remain required before a full RPC-parity or speed claim.

## Read and cache path

Authentication runs before every response-cache lookup. Complete JSON and binary
responses use the Workers Cache API. A hit needs no archive read or decode.
On a response miss, immutable index pages, registry ranges and small block or
signature ranges use a separate internal cache. A 4 MiB isolate cache retains
at most 512 small immutable byte entries. The edge cache stores ranges up to
1 MiB. A request can queue at most 8 MiB of archive cache writes. Cache writes
run through `waitUntil` after response creation.

All cache keys include the source configuration, renderer version and
`BZ_ARCHIVE_GENERATION`. This variable is required. Change it before replacing
any archive object, schema marker or derived index. Use a pinned immutable
publication prefix. The Worker does not certify the upload or establish chain
finality. An uploaded-pending-verification receipt remains pending verification.
Do not change that status because a request succeeds.

The existing sparse `archive-v2-blocks.index` works immediately. The Worker
uses the epoch's missing-row count to bound the possible row ordinals. It then
searches cached pages in that interval instead of the complete epoch index.
This needs no new cloud object. For fixed slot lookup geometry, build the
optional dense index:

```bash
cargo run --locked --release -p blockzilla-get-block --bin build-slot-index -- \
  --archive-dir /ABSOLUTE/ARCHIVE/epoch-900 --epoch 900
```

This creates `archive-v2-slot-offsets.v1.index` without replacing existing files.
The builder checks source identity and block links. It retains the source index
SHA-256 and source object lengths. Each 128-byte slot row contains the original
block and signature offsets, parent slot, blockhash and previous blockhash.
Absent rows are zero. The header is 128 bytes; a 432,000-slot epoch uses
55,296,128 bytes. The previous hash follows the actual parent reference,
including the previous-epoch tail. It never uses `slot - 1`.

Publish this derived file under the same pinned epoch prefix, then set
`BZ_SLOT_INDEX=dense` only when every served epoch has its index. The dense path
reads cached index pages and rejects invalid geometry or block identity. The
source digest is offline provenance; the Worker does not hash a whole epoch
index on each request. Keep index and source files in one immutable generation.

Registry reads collect and deduplicate IDs, join adjacent pages and run with
eight shared read permits. The planner selects pages from 64 KiB down to one
record so that each registry family needs at most 4 MiB. Adjacent missing pages
can share a range of at most 256 KiB. Smaller pages reduce unused bytes but can
need hundreds of HTTP requests. This is not a low-cost full-block read path.
The Worker limits one stored compressed block to 16 MiB,
one decoded block and zstd window to 32 MiB, signatures to 8 MiB, and total
registry ranges to 16 MiB per request. Larger records return an explicit error.
Measure actual CPU, memory, origin reads and latency before production use.
The Worker reuses object sizes returned with range reads, so index size checks
do not need another R2 HEAD request.
The Cache API stores data per data center and does not provide tiered cache
replication. See the [Cloudflare Cache API documentation](https://developers.cloudflare.com/workers/runtime-apis/cache/).

## Measure HTTP latency

```bash
cd edgezilla/get-block
npm run bench:http -- --url https://RPC_HOST \
  --slots 321000000,321000001 --rounds 5 --concurrency 1 \
  --uncached-rounds 1 --source-uncached-rounds 1 \
  --representations bin,json,bin-no-access \
  --rpc-encoding base64 \
  --rpc-endpoint provider_a=@COMPARISON_RPC_URL \
  --rpc-endpoint provider_b=@SECOND_RPC_URL \
  --max-requests 250 --output /tmp/get-block-latency.json
```

Read secrets from `BLOCKZILLA_RPC_API_KEY` and endpoint environment variables.
The report separates representations, first and repeat passes, and cache
receipts. `--uncached-rounds` uses `profile=1`, which bypasses the response and
archive byte caches. It verifies the origin-read counters. This proves a Worker
cache bypass; it does not clear R2's internal cache or a provider's cache.
The report includes first-byte and complete-body p50/p95/p99, decoded body
sizes, operation counts and errors. It compares block identities and the full
JSON result with exact numeric values. Provider order rotates between passes.
One client location does not establish global performance.

The [21 November baseline registry-reader run](../../reports/get-block-cloudflare-20261121/main.json)
used eight blocks from epochs 1089 and 1090, one client, CDG, one concurrent
request and the prior parsed JSON transaction encoding with full metadata
and rewards disabled. All 144 Blockzilla and 48 Helius requests passed. Every
block's JSON result matched both providers, including exact numbers. Solana public RPC
returned 26 HTTP 429 responses out of 48 requests; its successful samples do
not give a complete repeat distribution.

| Path | Forced origin p50 / p95 | Repeat response hit p50 / p95 |
| --- | ---: | ---: |
| Full parsed JSON | 17.901 / 44.208 s | 63.190 / 253.422 ms |
| Full binary | 21.762 / 32.471 s | 41.509 / 99.199 ms |
| Binary `access=0` | 896.146 / 1017.538 ms | 35.596 / 64.259 ms |

Each Blockzilla row has eight forced-origin samples and 32 repeat response
hits. Helius repeat JSON took 113.005 / 215.904 ms for 32 successful requests.
The cached JSON median is lower; its p95 is higher. Full cold reads are much
slower. Full JSON responses use HTTP zstd compression; Helius uses gzip.
Decoded response bytes are not wire transfer bytes.

Cold full reads used 368–1,099 object API attempts, with a mean of 676.875:
671.875 GETs and five HEADs. Cold `access=0` used three or four GETs. All repeat
response hits reported zero storage operations and bytes. The run made 15,141
origin API attempts in total. The current sparse lookup is bounded without a
new index, but random registry reads remain the main cost. See the
[proposed serving index](../../docs/design/get-block-serving-index.md).

## Local validation

Use the local profiler for short performance tests. It uses Miniflare/workerd,
the runtime used by local Wrangler, with the saved real block and local R2.
It also runs a loopback S3 control with 0, 100 and 250 ms source delays. It
does not make Foundation or provider requests. Build once, then repeat these
tests without a build or deployment. Output files must be new.

```bash
cd edgezilla/get-block
npm run bench:local -- --samples 10 --output /tmp/get-block-local.json
npm run profile:local -- --iterations 20 \
  --profile /tmp/get-block.cpuprofile --receipt /tmp/get-block-cpu.json
```

The default fixture is `/tmp/blockzilla-resolution-real-slot-fixture-20261121`.
Use `--fixture DIR` for another copy. The resolution integration test can
create it with `--fixture-out DIR` from the saved checked inputs. These local
tests use compatibility date `2026-09-10`, which the installed local runtime
supports; production uses `2026-11-21`.

The unchanged Base64 release took 46.366 ms p50 and 62.152 ms p95 for full
JSON from local R2, and 5.450/7.127 ms for binary. A 250 ms delay on each
source request gave 260.397 ms binary p50, with two active reads at once.
The ranges already overlap. These local wall times are not production CPU
or remote R2 latency. The [CPU capture](../../reports/get-block-local-profile-20261121/worker-base64-local-r2-cpu.json)
has readable WASM frames: metadata rendering accounts for 37.77% inclusive
sample weight. Base64 encoding is about 1.25% of leaf sample weight. Parent
and child sample weights overlap and must not be added.

The Rust SDK calls the same global native Worker fetch as JavaScript. The
owner index already uses a native R2 binding. Foundation's bucket is in a
different account, so it uses the supported S3 API. Switching the HTTP code
to TypeScript does not expose a different connection pool. Cloudflare manages
the connections; Node `http.Agent` and `Connection` headers are not pool
controls in Workers. See the [connection review](../../reports/get-block-base64-20261121/connection-reuse-review.json),
[R2 account guidance](https://developers.cloudflare.com/r2/examples/aws/s3mini/)
and [Workers HTTP API](https://developers.cloudflare.com/workers/runtime-apis/nodejs/http/#agent).

```bash
cargo test --locked --release -p blockzilla-get-block \
  --no-default-features --features worker --lib

BLOCKZILLA_WORKER_FIXTURE_DIR=/tmp/blockzilla-worker-fixture \
  cargo test --locked -p blockzilla-get-block --bin build-slot-index \
  tests::builds_real_archive_and_preserves_absent_slot_and_boundary_hash -- --exact

cd edgezilla/get-block
npm run build
npm run test:worker -- --fixture /tmp/blockzilla-worker-fixture
npx wrangler deploy --dry-run --config wrangler.example.toml
```

The integration test runs the actual WASM against local R2, KV and metrics. It
checks both indexes, output bytes, errors, failed transactions, cache variants,
source changes, key revocation and schema markers. The bundled local workerd
uses a test-only compatibility date of `2026-09-10`; the deployment example uses
`2026-11-21`. The fixture command needs a fresh output directory and preserves
its durable input files.

The Foundation query uploader currently excludes schema marker files from its
inventory. Publish the exact checked markers, or declare checked source schemas
with `BZ_MESSAGE_SCHEMA_OVERRIDES` (a JSON map from epoch to `current` or
`may24`) and `BZ_METADATA_SCHEMA` (`markers`, `current`, or `legacy`). A present
marker must agree with the declaration. Schema declarations form part of the
cache generation. The production configuration declares May24 messages for
epochs 0–2 and current metadata. A correct result for a recent epoch does not
prove the grammar or coverage of every older epoch.

## Cache and billing

The current offer is $1 per 1 million billable archive-backed requests. Each
authenticated HTTP request records `total_requests = 1`, but
`billable_backend_reads` is only `1` when that request actually attempts at
least one R2 or S3 archive read. Any number of archive range reads within the
same HTTP request still bills as one.

This customer price is separate from Cloudflare's operation charges. In the
baseline eight-block 21 November run, cold full blocks needed a mean of 676.875 object
operations. At the
[R2 Standard rate](https://developers.cloudflare.com/r2/pricing/), that is
$243.68 per million cold requests before allowances and billing rounding,
plus Worker, KV, CPU and
storage costs. A higher hit rate reduces both cold-read cost and customer
revenue under this offer; it does not repair the loss on each cold read.
Even a proposed five-read path costs $1.80 per million cold requests in R2
operations alone. Review the price and serving layout before commercial use.
The offer is unchanged by this deployment.

Consequences:

- a direct HTTP cache hit is free;
- unsupported methods, invalid parameters, and other failures before archive
  access are free;
- a cache miss is billable only if execution reaches R2 or S3;
- missing data and backend/decode errors are billable when storage was already
  attempted; and
- both data routes are cached; a response miss can also avoid storage when
  all required archive ranges are cached.

Every authenticated response exposes an authoritative request receipt:

- `X-Blockzilla-Cache: HIT|MISS|BYPASS|UNCACHED`
- `X-Blockzilla-Billable-Reads: 0|1`
- `X-Blockzilla-R2-Reads`, `-GETs`, `-HEADs`, and `-Bytes`
- `X-Blockzilla-S3-Reads`, `-GETs`, `-HEADs`, and `-Bytes`
- `X-Blockzilla-Archive-Memory-Hits` and `-Edge-Hits`

Each backend also exposes `-GET-Successes` and `-HEAD-Successes`. `Reads` counts
GET and HEAD attempts, including missing objects and failed calls. A successful
GET has a complete body with the exact requested length. Byte counters include
complete bodies with an incorrect length. These are object API operations,
not physical disk reads. Foundation R2 uses the S3 interface, so its operations
appear in the **S3** counters. Add both backend totals for an R2 cost estimate.
Response hits overwrite all storage counters with zero.

Authentication runs before every cache lookup. Internal cache keys contain only
the origin, renderer/schema version, archive-prefix generation, normalized slot,
representation, and relevant content options (`rewards` or `access`).
Authorization headers, API keys, customer IDs, and unrelated query parameters
never enter the shared key. Profile/debug requests bypass the cache.

The reusable internal cache object is created before receipt headers are added.
Every customer-facing direct response is normalized to
`Cache-Control: private, no-store`; it never varies on `Authorization`. The
Workers Cache API is per data center and can evict entries, so the same content
can miss—and become billable again—in another region or after eviction.

## API keys

The Worker hashes the presented key with SHA-256 and looks up the lowercase
hex digest in the `BZ_RPC_API_KEYS` KV namespace. Raw API keys are never stored
by the Worker. Each KV value has this schema:

```json
{
  "keyId": "key_acme_main",
  "customerId": "customer_acme",
  "label": "Acme production",
  "status": "enabled"
}
```

`keyId` is the stable per-key metrics index. `customerId` groups keys owned by
one customer. IDs accept 1-64 ASCII letters, digits, underscores, or hyphens;
labels accept 1-128 non-control characters. Set `status` to `disabled` to
revoke a key. KV is eventually consistent, so a cross-region change can take
time to become visible.

Generate key material locally:

```bash
cd edgezilla/get-block
npm run rpc-key:generate -- \
  --key-id key_acme_main \
  --customer-id customer_acme \
  --label "Acme production"
```

The helper prints the raw key once, plus its digest and KV JSON value. It does
not call Cloudflare or mutate a namespace. Give the raw key to the customer,
then store only the digest and JSON record through a reviewed admin or IaC
workflow. Never put raw keys in Wrangler config, KV values, source control, or
logs.

Malformed, missing, unknown, and disabled keys receive the same `401` response.
A missing or unreadable auth or metrics binding fails closed with `503`.

## Usage metrics

Every request with a valid, enabled key writes one point to the
`BZ_RPC_METRICS` Analytics Engine dataset, including free requests. Requests
rejected before authentication are not recorded.

| Column | Meaning |
| --- | --- |
| `index1` | stable `keyId` |
| `blob1` | stable `customerId` |
| `blob2` | method, such as `getBlock`, `getBlockLite`, `getBlockTime`, `getVersion`, `other`, `batch`, or `invalid` |
| `blob3` | bounded outcome, such as `ok`, `not_found`, `backend_error`, `rpc_error`, `parse_error`, `batch_rejected`, `invalid_request`, or `config_error` |
| `blob4` | cache status: `hit`, `miss`, `bypass`, or `uncached` |
| `blob5` | transport: `http_binary`, `http_json`, `json_rpc`, or `unknown` |
| `double1` | total request count (`1`) |
| `double2` | billable backend reads (`0` or `1`) |
| `double3` | HTTP status |
| `double4` | Worker handling latency through response creation in milliseconds; streamed transfer time is excluded |
| `double5` | buffered request bytes; direct GETs report `0` |
| `double6`–`double8` | R2 GET attempts, HEAD attempts, and returned bytes |
| `double9`–`double11` | S3 GET attempts, HEAD attempts, and returned bytes |
| `double12`–`double13` | archive memory hits and archive edge hits |
| `double14`–`double15` | successful R2 GETs and found R2 HEADs |
| `double16`–`double17` | successful S3 GETs and found S3 HEADs |

Account for Analytics Engine sampling in usage queries. At the current price:

```sql
SELECT
  index1 AS key_id,
  sum(_sample_interval * double1) AS total_requests,
  sum(_sample_interval * double2) AS billable_backend_reads,
  sum(_sample_interval * double2) / 1000000.0 AS estimated_usd
FROM blockzilla_rpc_metrics
WHERE index1 = 'key_acme_main'
  AND timestamp >= toDateTime('2026-07-01 00:00:00')
  AND timestamp < toDateTime('2026-08-01 00:00:00')
GROUP BY key_id
```

Analytics Engine is a sampled usage-metering system, so the query is a billing
approximation. Add an authoritative durable ledger and reconciliation process
before issuing invoices that require exact, auditable counts.

## Run locally

Inspect the native benchmark:

```bash
cargo run --locked -p blockzilla-get-block \
  --bin blockzilla-get-block -- local-bench --help
```

Build or run the Worker:

```bash
rustup target add wasm32-unknown-unknown
cargo install worker-build --locked --version 0.8.5

cd edgezilla/get-block
npm install
npm run build
npm run dev
```

`wrangler.example.toml` is a local configuration with placeholder resource IDs.
`wrangler.production.jsonc` selects the owner's Cloudflare account, its auth KV
namespace and Analytics Engine dataset. The deployed GET-only Worker is
<https://blockzilla-get-block.cheron-augustin.workers.dev>. Foundation R2 remains
in the Foundation account and is read through signed S3 requests.

```bash
npx wrangler deploy --config wrangler.production.jsonc
```

The five `BZ_S3_*` credentials are Worker secrets. The owner benchmark key is
stored only in the ignored, protected deployment directory. The KV record
contains its digest and account labels. Do not put the raw key in a command
argument or a benchmark report.

R2 mode can select the source, object prefix, and binding with
`BZ_ARCHIVE_SOURCE`, `BZ_ARCHIVE_PREFIX`, and `BZ_R2_BUCKET_BINDING`.
S3-compatible mode requires `BZ_S3_ENDPOINT`, `BZ_S3_BUCKET`, `BZ_S3_REGION`,
`BZ_S3_ACCESS_KEY_ID`, and `BZ_S3_SECRET_ACCESS_KEY`.

Store credentials as Worker secrets and grant object-read access only.

The example selects `BZ_ARCHIVE_LAYOUT=stored` and Foundation prefix
`compact-v2/blockzilla-20261004`. Keep `BZ_SLOT_INDEX=sparse` until the optional
indexes have been published. The old block-access layout remains available with
`BZ_ARCHIVE_LAYOUT=legacy-access`; it still needs all three old serving sidecars.
## Recent Compact V2 recovery

`GET /block/{slot}.compact?blockhash={expected_hash}&commitment=finalized`
first reads the existing retained Compact V2 frame on Foundation. It makes no
R2 request on a recent hit. It forwards the original native body without JSON
conversion, hot-block decoding in WASM, or a new result-cache write.

For an exact processed frame, use
`GET /block/{slot}.compact?blockhash={expected_hash}&commitment=processed&cursor={exact_cursor}&source_session={session}&bank_id={bank_id}`.
The cursor includes the expected frame SHA-256. All source, Bank and cursor
fields must match. An expired processed frame returns an explicit error.
Processed recovery never uses R2.

Only a confirmed finalized miss can use the archive path. Foundation checks
the expected blockhash against its existing epoch table before it admits
that fallback. The Worker then reads the original hot and signature ranges
and checks the resolved blockhash before it returns a body. Transport failures,
source changes, incomplete reads and identity errors do not trigger R2 reads.

The response representation is explicit:

| Source header | Content-Type | Body |
| --- | --- | --- |
| `X-Blockzilla-Source: FOUNDATION_RECENT` | `application/vnd.blockzilla.stream.v2` | Original `BZSTRM01` frame |
| `X-Blockzilla-Source: R2_ARCHIVE` | `application/vnd.blockzilla.get-block-bundle.wincode` | Complete archival Compact V2 bundle |

The archive bundle supplies block data, signatures and used-ID mappings. It
does not invent a native cursor or stream control events. A recovery client
must select its decoder from Content-Type and check the delivered full frame
or bundle before it accepts the block. Recent replies include
`X-Blockzilla-Frame-SHA256`, `X-Blockzilla-Cursor` and the Base64url JSON
`X-Blockzilla-Recent-Metadata` header. The metadata binds the complete source,
Bank, block, parent and commitment identities.

The route needs `BZ_FOUNDATION_RECENT_SOURCE`, a JSON object with exact
`genesis_hash`, `node_identity`, `agave_revision` and `session_id` fields. It
also uses the existing private Foundation URL, secret, source prefix and
generation configuration. The secret belongs in a Worker secret binding.
`BZ_FOUNDATION_LOOKUP_MODE=recent-only` enables this recovery path without
adding Foundation calls to the existing `.bin` and `.json` routes. The default
mode `all` keeps the prior Foundation-first behavior on those routes.

Operation receipts include
`X-Blockzilla-Foundation-Recent-HTTP-Requests`, the existing archive GET/HEAD
counts and the resolution POST count. A recent hit uses one private Foundation
GET, zero archive calls and zero resolution POSTs. Optional native CPU and
elapsed diagnostics use `X-Blockzilla-Recent-Native-*-Micros` headers. They are
profiling data and do not change admission or billing counters.
