The first CPU pass keeps the full Base64 JSON bytes unchanged. It changes only
the response writer and token amount formatting in `worker.rs`.

- Append each slice once. The old channel loop copied bytes one at a time
  after it crossed the 64 KiB threshold. Async flush points remain unchanged.
- Reuse completed 32-byte key encodings in a request-local, direct-mapped
  table. The table allocates only when needed and uses at most 20 KiB. Full key
  comparisons protect against collisions. No archive object is added.
- Format token amount strings from stack buffers. The output matches the old
  formatter at all 256 decimal scales.
- Write a quoted 64-byte signature in one append. The tests match the reference
  encoder, including all-zero and high-byte signatures.

Five native writer tests passed. They cover chunk boundaries, cancellation,
cache collisions and bounds, signatures, and decimal strings.

All eight saved block results are byte-identical before and after the change.
Their canonical full-result digests match the saved Helius Base64 references.
The native buffered renderer used 20 iterations per block:

| Measurement | Before | After |
| --- | ---: | ---: |
| Median of eight block CPU medians | 10.383 ms | 9.341 ms |

This is a 10.04% reduction. Each block improved by 6.24–19.40%. The buffered
renderer measures the key and amount changes. It does not exercise the channel
append loop.

The separate append microbenchmark used an 8 KiB record that crossed the
64 KiB threshold. Its ten-round median fell from 45.833 ms to 2.629 ms for
2,000 appends per round. This 17.43× ratio applies only to that copy operation.
It is not a whole-Worker speed result.

The local release-WASM comparison uses the same real block, local R2, two
warmups, and ten streamed JSON reads per artifact. Every body is byte-identical
and matches the saved provider oracle. Each read bypasses all caches, with
three R2 GETs and zero archive cache hits.

| Local streamed WASM measurement | Before | After |
| --- | ---: | ---: |
| Median full-body wall time | 43.666 ms | 41.477 ms |
| p95 full-body wall time | 49.699 ms | 43.834 ms |
| Median time to headers | 11.490 ms | 10.095 ms |

The median full-body improvement is 5.01%. These combined release artifacts
also contain separate auth/profile changes. Production network latency,
account allowances, and R2 charges are separate from this local result.

Separate CDP captures used 20 reads each. They contain 416 samples before and
358 after. Key-encoding leaf share fell from 6.64% to 3.49%. Metadata rendering
remains the largest inclusive group, at 34.60% before and 33.54% after. Function
inlining and profiler overhead affect these shares. Use the unprofiled timing
as the speed result, not the duration of a CPU trace.

Evidence: `native-before.json`, `native-after.json`, `native-comparison.json`,
`channel-copy-comparison.json`, `channel-copy-samples.jsonl`,
`local-json-comparison.json`, and `wasm-comparison.json`. Open
`worker-before.cpuprofile` and `worker-after.cpuprofile` in DevTools for stacks.

Run the same local comparison from the repository root:

```sh
node edgezilla/get-block/scripts/compare-local-json.mjs \
  --before .codex-tmp/get-block-cold-profile-20261121/build-base64-cache-v10-final/index.js \
  --after .codex-tmp/get-block-cpu-20261121/build-v11/index.js \
  --samples 10 --warmup 2 --output /tmp/blockzilla-json-recheck.json
```

The script uses retained local fixtures. It does not build, deploy, or contact
the external archive.

The release is deployed in the owner's account as
`2359b1b3-d95b-4e3b-bffc-b4161aac406f`. All 90 native tests, both release-WASM
suites and all 18 resolution checks passed. The live same-eight-block run
passed 232/232 calls; all 112 JSON samples match the saved references, and all
eight blocks match live Helius. No source or index objects were published.

The GET key-check cache has a fixed five-second TTL, 256-entry limit and
128 KiB allocation cap. It stores completed successful records only. This
adds up to five seconds of staleness after a KV check; KV propagation is
additional. `profile=1` bypasses every application cache. `profile=source`
retains index/auth caches and forces the Foundation ranges. The modes have
separate receipts and cannot both be called fully cold.

| Live full JSON path | Samples | Full-body p50 / p95 |
| --- | ---: | ---: |
| All Worker caches bypassed | 8 | 581.988 / 963.037 ms |
| Index and auth hits, two Foundation GETs | 7 | 525.168 / 709.137 ms |
| Complete response hit | 32 | 51.724 / 94.177 ms |
| Helius repeats | 32 | 105.454 / 157.666 ms |

All eight source-mode JSON requests used two Foundation GETs and no owner R2
GET. Seven had auth hits; one had a legitimate auth TTL miss. Helius for the
same seven blocks took 112.934 / 148.177 ms. Cold reads remain slower. A
separate latest stage pass measured about 400 ms arithmetic median for the
parallel source ranges. Provider and physical R2 cache states are unknown.

Dedicated version-filtered CPU windows matched eight fully cold JSON calls,
eight source-mode JSON calls and 24 complete response hits, with zero errors.
The initial 16-hit window had 24 platform invocations and remains contextual;
the independent recheck matched 24/24. Mean invocation CPU and marginal costs
before allowances are:

| JSON path | Mean CPU | CPU cost/M | Combined variable cost/M HTTP |
| --- | ---: | ---: | ---: |
| Fully cold | 38.909 ms | $0.778 | $2.658 |
| Index cached, two source reads, actual auth misses included | 46.389 ms | $0.928 | $2.010 |
| Complete response hit | 2.461 ms | $0.049 | $0.370 |

Including separately attributed startup raises the cold CPU estimate to
$0.817/M. CPU alone is below $1 in this sample. Fully cold total cost is not.
Two R2 GETs and a Worker invocation already cost $1.02/M before CPU at the
checked Standard rates.

At an assumed 80% response-hit fraction, JSON variable-cost models are
$0.828/M with fully cold misses and $0.698/M with cached-admission source
misses. Including attributed startup gives $0.846/M and $0.709/M. Fixed fees,
index construction/storage, logs, preparation, allowances and rounding are
separate. The models use HTTP requests, not billable archive-backed requests,
as the denominator. The billing policy was not changed. The observed mixed
binary/JSON/resolution test costs about $0.866/M HTTP; it is not an all-cold
JSON result.

See `summary.json`, `platform-cpu-v11.json`, `cost-estimate.json` and
`deployment.json` for the complete receipts and limits.
