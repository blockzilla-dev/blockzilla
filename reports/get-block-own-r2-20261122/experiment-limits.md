# Owner native R2 test limits

This is a separate canary in the owner's Cloudflare account. The public API
keeps Foundation S3 V11 version `2359b1b3-d95b-4e3b-bffc-b4161aac406f`.
The canary has a Standard R2 bucket with a requested WEUR location hint. The
hint does not prove physical placement. No Foundation account change or
Foundation reader deployment is part of this test.

The sample has eight selected blocks from two epochs. It is not a full epoch
or a complete archive. Four source objects occupy 1,387,245 bytes. Eight
resolution objects occupy 624,895 bytes. The total is 2,012,140 bytes. All
twelve remote objects passed byte, SHA256, length and native ETag checks in
[upload-receipt.json](upload-receipt.json). The source frames and ordered
signature bytes stay byte-identical. The new resolution records change
offsets, source lengths and ETags to match the packed objects. Resolution size
is 45.046% of source size in this selected sample; do not apply that fraction
to the full archive without a separate measurement.

The test changes several things at once: native R2 access, account, requested
bucket location and source-object layout. The original Foundation objects are
much larger. The two runs also use different time windows and unknown internal
storage caches. A measured difference belongs to this combined setup. This
test cannot show that native access alone caused the difference. The optional
same-bucket S3 control is omitted because the current owner OAuth cannot
manage API tokens. No new S3 key was created for that control.

Keep these cases separate in the result:

- Fully cold application reads: auth, index and source caches bypassed.
- Source-only reads: the index cache stays available; report auth hits and
  five-second TTL misses separately.
- Complete response hits: verify zero object operations and reader HTTP calls.
- Warmups: count their HTTP calls, R2 operations and KV reads separately.

These modes do not prove physical storage coldness. R2 counters count object
API calls. Full JSON must match Helius for the same slots and Base64 encoding.
Full binary and binary without access tables must match their saved byte
hashes. Keep Helius cache state unknown. One client, eight blocks and one run
cannot prove the fastest result across providers or regions.

The measured cost estimates are in [cost-estimate.json](cost-estimate.json).
The separate [CPU pass](cpu-pass.json) has 56 valid calls and no retries. Its
[platform CPU](platform-cpu-json.json) is filtered by canary version
`c3ca487a-ce71-42ba-802f-b2f7a38e234b` and quiet phase windows. These calls are
separate from the original 232-call latency benchmark. The following rows
have matching platform request counts and a sample interval of one:

| JSON case | Calls | Mean CPU | USD per million requests |
| --- | ---: | ---: | ---: |
| Full cold, auth bypass | 8 | 36.747 ms | $2.615 |
| Source reads with auth hits, selected subset | 5 | 27.798 ms | $1.576 |
| Response and auth hits, selected subset | 7 | 1.269 ms | $0.325 |

The full-cold value is $2.647 with attributed startup CPU. The other two rows
have no attributed startup. Means use summed CPU divided by requests. The
auth-hit subsets exclude whole seconds that contain auth misses. They have a
different block or call mixture from the complete phase. Their means do not
prove that caching alone caused the CPU difference.

The complete source phase has eight calls and one auth miss. Its estimate is
$1.645 per million requests. The complete 24-response-hit phase has two auth
misses and an adaptive sample interval of 1.091. Its $0.366 estimate is sampled,
even though its estimated count matches 24. Raw API confidence fields are
retained, but the API marks them invalid for these small cohorts. No statistical
confidence claim is made. Warmup calls and their KV reads remain separate.
Source streams can finish after response headers; their byte and success
receipts must show completion before those values are used.

A separate copy of the original epoch-1089 block and signature object geometry
is in progress. Its payload plan is 62,977,283,190 bytes, or $0.944659 per full
month before allowances and rounding. It is separate from the two-megabyte
pilot costs above. There is no full-geometry latency result yet. Copying those
two objects does not establish complete epoch query coverage or registry
coverage. See [the full-size plan](full-epoch-size-plan.json).

A separate index projection uses the eight pilot resolution objects. Their
624,895 bytes give a mean of 78,111.875 bytes per indexed block. At an assumed
432,000 indexed blocks, that is 33,744,330,000 bytes (33.74433 decimal GB), or
$0.50616495 per full month. One PUT per object would cost $1.944 for 432,000
PUTs before allowances and rounding. Build work, verification reads and retries
are separate. This is a projection from eight selected modern blocks, not a
measured epoch-wide size or coverage result. Actual block counts and sizes can
differ. The full projected index has not been generated. The full-sized payload
copy will have only four admitted resolution records. Its payload storage cost
does not include this projected index storage.

At current Standard marginal rates, three R2 reads cost $1.08 per million full
cold requests before the public Worker, KV and CPU. Thus this read plan already
exceeds a $1 target for each million archive-backed requests. Response hits have
a separate cost. Account allowances and invoice rounding can change a small
test bill, but do not establish margin at scale. See
[R2 pricing](https://developers.cloudflare.com/r2/pricing/),
[Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/)
and [KV pricing](https://developers.cloudflare.com/kv/platform/pricing/).
