# Measured one-read request costs

The one-read path reduces storage operations. It does not meet the $1/M
fully cold target in the first 119-call run. These are observed marginal
component estimates before allowances, fixed fees, storage, logs and rounding.

| Cohort | Requests | GETs per request | KV reads per request | Mean invocation CPU | Cost per million | With attributed startup |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Bundle cold JSON | 8 | 1 | 1 | 30.1515 ms | $1.763030 | $1.763030 |
| Previous cold JSON | 8 | 3 | 1 | 31.63325 ms | $2.512665 | $2.512665 |
| Bundle source JSON, cached auth | 8 | 1 | 0 | 40.945625 ms | $1.4789125 | $1.4789125 |
| Previous source JSON, cached index and auth | 8 | 2 | 0 | 79.704125 ms | $2.6140825 | $2.6140825 |
| Bundle cold binary | 8 | 1 | 1 | 18.39325 ms | $1.527865 | $1.602765 |
| Previous cold binary | 8 | 3 | 1 | 17.616375 ms | $2.2323275 | $2.2961975 |

All six rows have matching platform request counts, reported sample interval
one, and matching sample sizes. The source rows combine two separate
four-request phases. Their charged auth warmups remain separate. The two
bundle source JSON rounds had mean CPU of 28.433 and 53.45825 ms. This small
run does not establish a stable CPU rate at scale.

Cold binary has a 3.745 ms mean attributed startup cost in the bundle group.
The previous binary group has 3.1935 ms. The first JSON runtime warmup is also
separate: bundle CPU was 90.735 ms plus 17.686 ms startup. Do not assign that
warmup to every cold request or omit its actual test cost.

The separate ten-call supplement measured eight source-only binary requests
with cached auth. Each used one GET, zero KV reads, and no data-cache hits.
All eight bodies matched their original full V1 hashes. The two four-request
groups had mean CPU of 6.26275 and 6.79525 ms. The pooled mean is **6.529 ms**,
which gives **$0.79058/M binary HTTP requests** before logs, storage,
allowances and rounding. Attributed startup in those eight calls is zero.
All four phase counts and the ten-call total are matched and unsampled.

The two charged JSON auth warmups used two KV reads and zero object reads.
Across all ten HTTP requests, the cost is $0.8871/M, or $0.956102/M with
attributed startup. If their full cost is charged to only the eight desired
binary outputs, the cost is **$1.108875/M binary outputs**, or
**$1.1951275/M with startup**. Keep these denominators separate. This proves
the below-$1 result for the measured binary requests with warm auth. It does
not prove a below-$1 fully cold service or a general warmup rate at scale.
The supplement ran at 11:11:02.496–11:11:13.684 UTC on the same version.
See [its cost details](binary-source-cost-estimate.json),
[its platform CPU](platform-cpu-binary-source.json), and
[its request receipt](binary-source-supplement.json).

The original estimate that removed KV cost from cold-binary CPU remains in
the JSON as a historical conditional projection. The measured supplement
replaces it for the cached-auth binary conclusion. The original 119-call
request and CPU windows remain unchanged.

All response hits in the request receipt used zero object reads. Each target
had one KV read across eight JSON hits and one across four binary hits.
Platform CPU counts did not match these cohorts: bundle JSON has seven of
eight; bundle binary has two of four; previous JSON has seven of eight; the
previous binary weighted estimate is five for four actual requests, from
three samples. A second read of the same metrics returned the same values.
The cost JSON therefore leaves matched HIT totals empty. It retains the
observed CPU means only as clearly marked illustrations. These groups do
not prove an exact cache-hit cost or a blended hit-rate target.

The request window is 22 November 2026, 11:04:53.705–11:06:07.422 UTC.
Bundle CPU uses Worker `blockzilla-get-block-bundle-test`, version
`8142880e-9475-4c45-b3a1-dc16b538d52f`. The previous path uses
`blockzilla-get-block-native-fast`, version
`bf0bedfc-7216-4550-8e79-b671a93318f8`. The queries use separate time bounds
for every phase and version. Exact and expanded whole-second bounds agree
for the selected matched rows. No extra data requests were sent for CPU
collection.

The formula per million HTTP requests is $0.30 for Worker requests, plus
$0.36 per mean object read, plus $0.50 per mean KV read, plus $0.02 per mean
CPU millisecond. Rates were checked on 22 November in
[R2 pricing](https://developers.cloudflare.com/r2/pricing/),
[Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/)
and [KV pricing](https://developers.cloudflare.com/kv/platform/pricing/).
One GET plus fresh KV already costs $1.16/M before CPU.

See [the cost details](cost-estimate.json),
[bundle CPU](platform-cpu-bundle.json),
[previous-path CPU](platform-cpu-baseline.json),
[the request receipt](main.json), and
[the separate storage model](storage-cost-model.json). Object operations are
not physical disk reads. Small platform confidence intervals are marked
invalid; this report makes no statistical confidence claim.
