# Final shared auth cache cost check

The final Worker version is `bf0bedfc-7216-4550-8e79-b671a93318f8`. The
[49-call check](auth-edge-main.json) passed. The earlier 109-call latency and
cost evidence stays separate. No stored block, signature or index data changed.

The burst made zero KV reads: nine requests used the memory auth cache and
seven used the shared edge auth cache. Its sixteen requests used four R2 GETs.
The four source requests also made zero KV reads and used two R2 GETs each.
Full cold mode still bypassed both auth caches and used one KV read plus three
R2 GETs per request. Cache hits keep the original five-second KV deadline.
The shared cache is per datacenter and can evict records. This four-slot,
one-client check does not establish a global hit rate or full epoch coverage.

[Platform CPU](platform-cpu-auth-edge.json) has matching request counts and no
sampling for cold, burst and source groups. The response-hit CPU is a weighted
estimate from fourteen samples for sixteen requests. These are small groups;
they do not establish a global workload average.

| Case | Requests | Mean CPU | Core USD per million HTTP requests | With attributed startup |
| --- | ---: | ---: | ---: | ---: |
| Cold, after separate runtime warmup | 4 | 30.019 ms | $2.4804 | $2.4804 |
| Source reads, auth hits | 4 | 34.251 ms | $1.7050 | $1.7050 |
| Concurrent burst | 16 | 31.430 ms | $1.0186 | $1.1648 |
| Response hits, weighted CPU | 16 | 1.163 ms | $0.3545 | $0.3545 |

Core costs include Worker requests, invocation CPU, actual KV reads and R2
reads. They exclude account allowances, fixed fees, stored data, rounding and
logs. Expected 1% invocation logging adds about $0.006 per million requests
if there is one event per sampled request. Actual log counts were not collected.
Warmups and index downloads have separate rows in
[the cost report](auth-edge-cost-estimate.json). The first runtime request used
78.685 ms CPU plus 17.363 ms startup; it is not hidden in a favorable cache row.

The shared auth cache removed thirteen KV reads from the sixteen-request burst
seen in the earlier run. That removes a $0.40625 KV component per million burst
requests. The runs have different runtime states and warmup schedules. Their
CPU difference cannot be assigned to the auth cache alone. The final burst
still misses the $1 target, including before logs.

Three R2 GETs, one Worker request and one fresh KV read cost $1.88 per million
requests before CPU. Thus the current full cold layout cannot reach $1 at these
rates. Two source GETs plus a Worker request already cost $1.02 before CPU or
auth. An illustrative mixture using the final weighted hit CPU needs about
69.64% complete response hits to bring cost below $1 across all HTTP requests,
or about 69.92% with expected logging. This is an estimate, not a new measured
traffic mix. Free customer cache hits do not repair a loss on charged archive
requests.

Rates were checked on 22 November 2026: [Workers](https://developers.cloudflare.com/workers/platform/pricing/),
[KV](https://developers.cloudflare.com/kv/platform/pricing/) and
[R2](https://developers.cloudflare.com/r2/pricing/). Analytics Engine use is
[not currently billed](https://developers.cloudflare.com/analytics/analytics-engine/pricing/).
