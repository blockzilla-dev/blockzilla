# Owner native R2 getBlock test, 22 November 2026

The native R2 pilot is deployed in the owner account. All 232 calls passed.
The main public API remains on its Foundation S3 V11 deployment.
The pilot copies eight selected blocks from two partial epochs. Its packed
source objects and indexes occupy 2,012,140 bytes. This is not a full epoch.

The measured time includes the complete response body. All requests came
from one client through CDG. The source-only mode bypasses response and source
range caches, but retains the checked index and API-key caches. All eight
source-only JSON calls had an API-key cache hit. Fully cold mode bypasses all
Worker caches and checks the key through KV. Provider cache state is unknown.

| JSON path | Native R2 p50 / p95 | Helius p50 / p95 | Native R2 GETs |
| --- | --- | --- | --- |
| Fully cold Worker caches, eight blocks | 154.356 / 215.878 ms | 111.973 / 179.729 ms | 3 |
| Cached index and auth; source ranges fetched, eight blocks | 99.419 / 126.216 ms | 95.128 / 140.508 ms | 2 |
| Complete response cache hit, 32 calls | 46.091 / 75.257 ms | 109.028 / 150.742 ms | 0 |

The separate current Foundation S3 baseline used the same eight blocks.
Its fully cold JSON result was 811.458 / 1373.364 ms, with Helius at
111.511 / 171.131 ms in that window. The pilot p50 is about 5.26 times faster
than that Foundation path. It still loses to Helius on fully cold p50 and p95.
Native access, bucket location and much smaller packed source objects changed
together; this pilot does not isolate their effects.

The separate CPU pass used 56 valid calls and quiet phase gaps. Measured
marginal JSON cost per million requests, before account allowances, is about
$2.65 fully cold with attributed startup, $1.58 with cached index and auth,
and $0.33 for complete response and auth hits. The latter two CPU values use
unsampled subsets of five and seven calls. The report keeps actual TTL misses
and sampled whole-phase estimates separate. Three R2 GETs alone cost $1.08
per million calls; this cold read plan cannot meet a $1 per million target.

The [full-sized epoch control](../get-block-own-r2-full1089-20261122/README.md)
is complete. The original 62,977,283,190-byte epoch-1089 payload is in the
same owner bucket with matching multipart ETags and original offsets. Four
selected slots have new resolution records. The 72-call control and separate
16-call warm-runtime follow-up passed. Full-size initial cold JSON was
210.161 / 521.657 ms; its matched follow-up was 211.472 / 444.706 ms. The
packed same-four follow-up was 220.539 / 415.958 ms. The latter comparison does
not establish a large-object penalty. Neither native cold path beat Helius.
The temporary copy Worker was deleted. Source data and both read-only test
Workers are retained.

[Deployment](deployment.json), [remote upload check](upload-receipt.json),
[local Worker checks](local-resolution-tests.json), [raw main run](main.json),
[Foundation baseline](foundation-s3-baseline-summary.json),
[costs](cost-estimate.json), and [test limits](experiment-limits.md).

The canary URL is
https://blockzilla-get-block-native-test.cheron-augustin.workers.dev.
It requires the existing API key. The version is
`c3ca487a-ce71-42ba-802f-b2f7a38e234b`. The release WASM SHA256 is
`a27fbc8b0325a1f6046629d5dee07efbe2aeb8b4300d52a36718adc9ae9736c2`.
No Foundation account settings or source objects were changed.
