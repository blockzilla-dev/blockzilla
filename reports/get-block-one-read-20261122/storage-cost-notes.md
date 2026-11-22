# Four-block bundle storage and cost model

The four saved V1 bundles total **1,012,959 bytes**. Their SHA-256 values match
the saved source manifest and all four remote full-readback values in
[the upload receipt](bundle-upload-verification.json).
The current three-read path transfers 1,016,409
bytes for these same four blocks: 595,180 compressed hot bytes, 106,112
ordered signature bytes, and 315,117 resolution bytes. The bundle form is
3,450 bytes smaller, or 0.3394%. This experiment can test fewer operations
and fewer dependent reads. It does not make a large change to transfer size.

| Slot | Complete bundle bytes | Hot bytes | Signature bytes | Current resolution bytes |
| --- | ---: | ---: | ---: | ---: |
| 470555971 | 247,594 | 145,910 | 26,880 | 75,677 |
| 470663944 | 364,638 | 229,322 | 32,576 | 103,689 |
| 470771932 | 275,803 | 153,791 | 31,616 | 91,326 |
| 470879999 | 124,924 | 66,157 | 15,040 | 44,425 |
| Total | 1,012,959 | 595,180 | 106,112 | 315,117 |

This test adds four complete copies beside the existing owner files. It does
not replace or delete an epoch. At the published Standard rate, the added
bytes cost $0.000015194385 for a full month. Four small-object PUTs cost
$0.000018; the four verified readback GETs add $0.00000144. These are marginal
values before shared account allowances and
billing-unit rounding. They are not an invoice forecast. Standard storage
costs $0.015/GB-month; PUTs cost $4.50/M; GETs cost $0.36/M; egress is free.
See [R2 pricing](https://developers.cloudflare.com/r2/pricing/).

A hypothetical replacement for these four selected query records would use
1,012,959 bytes instead of 1,016,409 bytes. This is a byte comparison only.
The selected ranges cannot be removed from the existing immutable epoch
objects without a separate rewrite. Foundation's original files also remain.

The sample mean is 253,239.75 bundle bytes per block. At an assumed 432,000
indexed blocks, this projects to 109,399,572,000 bytes and $1.64099358/month.
The hot-plus-signature bytes in this same sample project to 75,739,536,000
bytes; the bundle adds a projected 33,660,036,000 bytes of access data and
framing. This is a projection from four selected modern blocks. It is not a
measured full epoch, a produced-block count, or a serving-coverage claim.
Do not compare the four bundle files with the whole 63 GB epoch payload.

For each million HTTP requests, the marginal formula is:

```text
$0.30 + $0.36 × mean object reads
      + $0.50 × mean KV reads
      + $0.02 × mean invocation CPU milliseconds
```

One GET and fresh KV auth cost **$1.16/M before CPU**. One GET with proved
cached auth costs **$0.66/M before CPU**. The latter needs mean CPU below
17 ms to stay below $1/M before logs, storage, fixed fees and rounding.
The published rates are in [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/)
and [KV pricing](https://developers.cloudflare.com/kv/platform/pricing/).
Analytics Engine is currently not billed, as stated in its
[pricing notice](https://developers.cloudflare.com/analytics/analytics-engine/pricing/).

Platform CPU collection is complete for the 119-call main comparison and
the separate ten-call binary source supplement. The queries use the exact
deployed version and separate JSON, binary, response-hit and warmup windows.
Cold JSON costs $1.76303/M with one GET and fresh KV auth. Cold binary costs
$1.527865/M, or $1.602765/M with attributed startup. The eight measured
binary source requests with warm auth average 6.529 ms CPU and cost
$0.79058/M. If both JSON warmups are charged to only those eight binary
outputs, the cost is $1.1951275/M including startup. Response-hit CPU counts
are incomplete or sampled, so their matched cost totals remain empty.

See [the measured cost notes](cost-notes.md),
[main comparison costs](cost-estimate.json), and
[binary source supplement costs](binary-source-cost-estimate.json).
Invocation CPU, startup CPU, adaptive sample interval and observed counts
remain separate in the linked receipts. The analysis sent no additional
Worker data requests and made no cloud writes.

The machine-readable sizes, full hashes, formulas and limits are in
[storage-cost-model.json](storage-cost-model.json). Storage operations are
object API calls. They are not proof of physical disk reads.
