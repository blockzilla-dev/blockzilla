# Full-sized owner R2 epoch 1089 test

The owner account now has the original-sized block and signature payload for
epoch 1089: 62,977,283,190 bytes. The native R2 test Worker is deployed at
https://blockzilla-get-block-native-full-test.cheron-augustin.workers.dev,
version `c757f003-018e-45db-b1b0-8a2decca8868`. The main public API still uses
Foundation S3 V11. No Foundation objects or account settings were changed.

The copy retains the original offsets and multipart sizes: 64 MiB for block
parts and 128 MiB for signature parts. All 859 parts used conditional source
range GETs and native streams. Both destination multipart ETags match the
source. All eight selected compressed-block/signature windows match saved
SHA-256 values. Four new resolution objects total 315,117 bytes. Every remote
index byte, length, ETag and SHA-256 passed read-back, and all four full binary
bundles reconstruct exactly. The indexes retain the actual previous blockhash.
These are four admitted query slots; a full serving index was not generated.
The registry and other epoch files are outside this payload-copy experiment.

All 72 calls in the first control passed: eight current Foundation S3/Helius
baseline calls, 60 native JSON/index/Helius calls, and four fully cold native
binary checks. The 64 JSON results match between the paired providers; all
four binary bodies match their saved original hashes. The table gives total
response time, including the body, through CDG. Each p95 with four calls is
the largest selected observation. The first cold call was the first request
to this new read-only Worker.

| JSON mode | Native R2 p50 / p95 | Helius p50 / p95 | R2 GETs per request |
| --- | --- | --- | --- |
| Fully bypassed Worker caches, four slots | 210.161 / 521.657 ms | 105.830 / 127.618 ms | 3 |
| Index and auth cached, both data ranges forced, four slots | 168.269 / 395.866 ms | 99.417 / 122.559 ms | 2 |
| Complete response cache hit, 16 calls | 55.175 / 86.878 ms | 103.991 / 142.597 ms | 0 |

The separate current Foundation S3 baseline was 507.853 / 835.483 ms for
fully cold JSON on the same four slots; Helius was 118.066 / 163.608 ms in
that window. Native R2 reduced that cold p50 by about 59% (2.42 times faster).
It still lost to Helius on cold and forced-source reads. Native binary cold
reads were 135.687 / 271.421 ms. Binary retains Wincode and needs client decode;
its latency is not a full JSON comparison.

A separate final 16-call follow-up passed all content checks. Both runtimes
were already active; every Worker call still bypassed auth, index and source
caches, with three native R2 GETs and one KV read. Full-size cold JSON was
211.472 / 444.706 ms, versus Helius at 125.023 / 136.351 ms. The packed pilot
on the same four slots was 220.539 / 415.958 ms, versus Helius at
105.058 / 113.570 ms in its window. The large objects did not show a clear
penalty in this small comparison. Neither native path beat Helius cold.
These results stay separate from the initial 72-call control.

The 521.657 ms initial cold tail and 395.866 ms source tail contain much time
outside the pre-header profile. An unsampled single-invocation platform row
for the first cold slot records 121.200 ms CPU plus 18.120 ms startup. CPU
explains part of the delay. The slow source slot cannot be isolated from its
whole-second CPU group. The remaining delays cannot be assigned to R2,
startup, client-network delay or other waits from these headers. Production
Worker timers advance with I/O, so zero stage times are not zero CPU. See the
[CPU diagnostic](../get-block-own-r2-20261122/platform-cpu-full-epoch-diagnostic.json)
and [Worker timer behavior](https://developers.cloudflare.com/workers/runtime-apis/performance/).

The original-sized objects control logical geometry and multipart layout.
Native access, account, bucket location, runtime state and recent upload/read
history still differ from the Foundation setup. Application cache bypass
proves R2 API calls, not physical-storage coldness. Helius cache state is
unknown. Four selected slots and one client do not establish a general
provider or regional speed rank.

The full payload costs about $0.945 per full month at Standard R2 rates before
allowances and invoice rounding. The four index objects add about $0.00000473
per month. The separate eight-block pilot CPU measurements estimate JSON
costs near $2.65/M fully cold including attributed startup, $1.58/M with index
and auth hits, and $0.33/M for response and auth hits. These CPU estimates are
not per-slot measurements from this new full-sized run. Three R2 GETs alone
cost $1.08/M; the all-cold plan cannot meet a $1/M request target. The separate
full-index size projection is 33.74 GB per 432,000 indexed blocks ($0.506/month),
from eight modern samples; that full index has not been built. See the
[pilot cost evidence](../get-block-own-r2-20261122/cost-estimate.json) and
[R2 prices](https://developers.cloudflare.com/r2/pricing/).

The temporary copy Worker was deleted after verification. No data copy is
running. The two read-only owner test Workers and their R2 objects are retained.

[Deployment](deployment.json), [copy receipt](copy-receipt.json),
[verification](verification.json), [copy Worker deletion](copy-worker-delete.json),
[raw native JSON](../get-block-own-r2-20261122/full-epoch-main.json),
[raw S3 baseline](../get-block-own-r2-20261122/full-epoch-s3-baseline.json),
[raw binary](../get-block-own-r2-20261122/full-epoch-bin.json),
[copy code](copy-worker.mjs), and [controller code](copy-controller.py).

[Validated 72-call summary](../get-block-own-r2-20261122/full-epoch-summary.json) and
[separate 16-call summary](../get-block-own-r2-20261122/full-epoch-runtime-followup-summary.json).
