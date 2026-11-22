# Cache safety acceptance

Keep frontend Workers Cache disabled. The tests used unpromoted versions of
the same Worker, synthetic data and the exact safety Wasm artifact. The
production version stayed `1cc2931c` throughout this acceptance work. The
[later clean deployment](../repair/README.md) is recorded separately and keeps
frontend caching off.

| Check | Result | Evidence |
| --- | --- | --- |
| Complete synthetic cache fill/hit and HEAD-to-GET | Passed | [First attempt](probe-3c6c40ef-ddbf-471d-a5eb-0a1fdb4893da.json) |
| Fixed-length producer abort, three fresh attempts | Passed: body reads failed; no identity reuse | [First attempt](probe-3c6c40ef-ddbf-471d-a5eb-0a1fdb4893da.json) |
| Unknown-length producer abort | Initial MISS completed as HTTP 200; original assertion failed | [Corrected producer attempt](probe-resume-06922dfb-06c5-47e0-b851-7f8e1f2fb62e.json) |
| Repeated unknown-length errored prefix | HIT with the same UUID, origin ray, length and digest | [Node diagnostic](diagnostic-node.json) |
| Existing Cache API, frontend caching off | Good digest matched; bad put rejected; bad match absent; cleanup passed | [One-request result](cache-api-18deaee9-a10d-4352-be20-80344d101aca.json) |

The unknown-length case used native ReadableStream: enqueue 65,536 identity
bytes, then `controller.error` after 100 ms. Its repeated HIT kept producer UUID
`3bad64b1-7ff4-4aeb-8f99-31acc9461783` and body SHA-256
`bbcbec9f8d7ea83ab7a5ca228f8a8b48159e623c19233bc31a0635f52379c6f3`.
The edge ray changed. This establishes reuse of the errored synthetic prefix.
It does not identify which internal component lost the error or establish
behavior for every application stream.

The first unknown-length fixture used legacy IdentityTransformStream. It was
replaced with native ReadableStream after review; the original failed receipt
was retained. A separate three-call Python diagnostic did not retain its
HTTPError statuses and headers, so it is inconclusive. Its
[corrected classification](diagnostic-cache-commit.json) is authoritative;
[the original unclassified record](diagnostic-cache-commit-unclassified.json)
is retained as failure evidence. No successful cache-safety claim uses it.

The Cache API comparison was one invocation in unpromoted version
`18deaee9-a10d-4352-be20-80344d101aca`, with frontend cache explicitly disabled.
A complete 64 KiB positive control passed before the errored put. Both unique
preview-origin keys were deleted in finally and checked absent. The
[application receipt](application-cache-api-receipt.json) confirms every
required flag. This is a targeted atomicity check, not a universal platform
failure guarantee.

The [request journal](request-budget.json) records **22 total data requests**.
The initial limit was 60. Root explicitly raised it to 80 for bounded Node
transport diagnostics; application assertions were not weakened. No clean
candidate or probe was promoted during these tests. Version URLs and
workers.dev were disabled again. No real blocks were read for the synthetic
probes, no body files were saved, and no R2/KV data or index was changed.

[Detailed chronology](RESULTS.md), [structured results](results.json) and
[the original handoff](final-handoff.json) preserve the stopped attempts and
last verified production state. The public performance baseline is
[separate](../public-cache-benchmark/README.md): 73 requests, including 48 warm
hits, with an estimated $0.339 per million in marginal Worker request and CPU
cost. Base subscription, backend operations and storage are excluded.
