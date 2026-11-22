# Public getBlock cold reads and cache hits

Measured on 22 November 2026 through Cloudflare CDG. The deployed public
Worker stayed at version `4d1b4d55-31f1-4e30-a287-717846eeff3c`. No API key,
deployment change, cache purge, new block object or new index was used.

All 338 HTTP requests passed: 193 in the main run and 145 in the paced CPU
check. The eight blocks and their JSON/binary digests matched the earlier
references. No block body was saved to a file.

## HTTP results

Times include the full response body. Each cold group has 24 requests;
each hit group has 64 requests. These are observed sample percentiles.

| Format and condition | First byte p50 | Full body p50 | Full body p95 | Storage reads per request |
| --- | ---: | ---: | ---: | ---: |
| Binary, Worker caches bypassed | 466 ms | 501 ms | 890 ms | 3 |
| Binary, response-cache hit | 25 ms | 29 ms | 36 ms | 0 |
| JSON, Worker caches bypassed | 479 ms | 532 ms | 736 ms | 3 |
| JSON, response-cache hit | 27 ms | 87 ms | 155 ms | 0 |

Each cold request made one GET to our resolution bucket and two range GETs
to Foundation's R2 bucket through its S3 API. It made no HEAD request. All
measured response hits had zero storage reads. Public requests also had zero
API-key KV reads and zero customer-billable read receipts.

The mean delivered application body was 250,710 bytes for binary and
2,863,426 bytes for JSON. These are decoded body sizes, not measured wire
bytes. The runner used one keep-alive connection and no concurrent requests.
Connection priming and cache fills have separate recorded windows.

## Worker execution and CPU

**A response-cache hit still runs our Worker.** The current implementation
uses the Cache API inside the request handler. The paced JSON group has 64
unsampled Worker invocation records for 64 cache-hit HTTP responses.

| CPU group | Mean CPU | Request estimate | Actual CPU sample records | Quality |
| --- | ---: | ---: | ---: | --- |
| Cold binary | 8.820 ms | 24 | 24 | Unsampled |
| Cold JSON | 35.797 ms | 24 | 24 | Unsampled |
| Paced binary hits | 1.628 ms | 64 | 38 | Sampled estimate |
| Paced JSON hits | 1.644 ms | 64 | 64 | Unsampled |

The paced check adds 150 ms between requests, outside each HTTP timer. Its
CPU measurements support the cost estimate; the HTTP table uses the main
run. Startup CPU was zero in all four selected CPU groups. It was measured
separately on the connection-prime requests, at about 19 ms per new isolate.
This is not an estimate of how often production isolates start.

The original fast hit groups were sampled. Their records are retained.
The original JSON-fill CPU window has only seven of eight planned records;
it must not be priced as a complete cohort. No confidence-interval claim is
made from the GraphQL confidence objects whose `isValid` flag is false.

## Variable cost per million requests

These are marginal estimates after included usage, using R2 Standard
storage operations. They include Worker requests and measured CPU, plus
storage operations. They exclude existing storage, Foundation machine and
network charges, startup frequency, and the fixed account subscription.

| Format and condition | Our account | Foundation bucket operations | Combined variable cost |
| --- | ---: | ---: | ---: |
| Cold binary | $0.8364 | $0.7200 | $1.5564 |
| Binary response hit | $0.3326 | $0 | $0.3326 |
| Cold JSON | $1.3759 | $0.7200 | $2.0959 |
| JSON response hit | $0.3329 | $0 | $0.3329 |

Formula in dollars per million requests:

`0.30 + 0.02 * mean_CPU_ms + 0.36 * mean_R2_GET_and_HEAD_count`

Our account pays for the Worker and the resolution bucket. Foundation's
account pays for its two source reads. Their free allowances are separate.
The public path performs no customer KV reads or Analytics Engine writes.
Retained invocation logs are separate: at the current 1% setting, a scenario
with one saved event per sampled request adds up to $0.006/M after the log
allowance. Actual error and extra log events can change that amount.

A modeled mix of 90% response hits and 10% of the measured cold path costs
about **$0.455/M binary** or **$0.509/M JSON**, across both accounts. The
modeled combined cost falls below $1/M above about 45.46% binary hits or
62.16% JSON hits. This is a model, not a measured 90% traffic workload.

The Workers Standard account minimum is $5/month, including 10 million
requests and 30 million CPU milliseconds. Actual invoices depend on shared
account usage, included R2 operations, and billing-unit rounding.

Prices checked on 22 November 2026:
[Workers](https://developers.cloudflare.com/workers/platform/pricing/),
[R2](https://developers.cloudflare.com/r2/pricing/).

## Scope and reproduction

Cold means `profile=1`: Worker response, index and archive range caches are
bypassed, confirmed by storage receipts. It does not mean a new Worker
isolate or physically cold R2 storage. Profiling adds work and bypasses the
normal response-cache fill work; its price is not an exact ordinary-miss
price. The normal fill requests are recorded separately and have mixed
storage conditions. Compact stream recovery remains a separate no-store
route and was not part of this JSON/binary benchmark.

Run from the repository root with the getBlock package dependencies installed:

```sh
node edgezilla/get-block/scripts/bench-public-get-block.mjs --output NEW_DIRECTORY/http.json
node edgezilla/get-block/scripts/bench-public-get-block.mjs --hits-only --pace-ms 150 --output OTHER_NEW_DIRECTORY/http.json
```

The runner is pinned to the tested eight slots and expected Worker version.
Check the live deployment before reuse. The helper's historical private-auth
`fullyColdVerified` flag does not apply to public access; use the separate
`workerColdVerified` and raw public/zero-KV receipts.

Receipts: [HTTP](http.json), [paced HTTP](paced-http.json),
[original platform CPU](platform-cpu.json), [paced platform CPU](paced-platform-cpu.json),
and [cost model](cost.json).
The [reference digests](references.json) preserve the existing independent
eight-block references without storing any block body.

Changed files: the public benchmark runner records bounded, keyless HTTP
measurements and CPU query windows; this report directory records the
measurements and cost model. Production Worker code and configuration were
not changed by this benchmark.
