# getBlock serving index

Historical design option. The owner cancelled the history-wide per-block
resolution index and its compression study. Do not build the index described
below. The current service uses existing Foundation indexes and the original
recent/archive block data. See the [current implementation](stream-getblock-resolution.md)
and [recovery acceptance](../../reports/stream-worker-recovery-20261122/README.md).

On 22 November, the owner authorized a Foundation-account native R2 reader,
with the public API and its index/auth in the owner's account. The small
reader uses signed, short-lived GETs and one conditional native R2 range read
per request. It has no cache, decoder, index copy or write operation. The
owner still issues its two source reads concurrently, checks exact identity
and range headers, and keeps network chunks in native streams for binary.

The implementation passed 99 native tests, 12 reader checks, five local
complete two-Worker checks and the existing owner suites. Cloud deployment
is blocked by the available Foundation token's Workers permissions (403,
code 10000, before upload). The public S3 path is unchanged and no live
native-reader benchmark has run. The [preparation record](../../reports/get-block-native-r2-20261122/preparation.json)
keeps this status separate from the deployed per-slot path below. Public
cross-account HTTPS adds two Worker invocations per full block at this stage;
the same two Foundation R2 GET fees remain. This is a latency test, not a
claim of lower operation cost.

Date: 21 November 2026. The per-slot path below is implemented and published
for eight benchmark slots. The epoch-packed layouts remain proposals.
The current [Blockzilla goal](../../.codex/blockzilla-goal.md) keeps
archive reads in Cloudflare and keeps derived serving data separate from the
durable Compact V2 archive.

## Implemented per-slot v1

The owner selected the three-read per-slot path. The implementation is in
[slot_resolution.rs](../../edgezilla/get-block/src/slot_resolution.rs),
[the builder](../../edgezilla/get-block/src/bin/build_slot_resolution.rs) and
[the Worker reader](../../edgezilla/get-block/src/worker/resolution.rs).
The eight derived objects are in the owner's `blockzilla-get-block-index`
bucket under `serving/foundation-resolution-20261121-v1`. Original blocks and
signatures remain in Foundation R2. The Worker has an explicit eight-slot
admission list; this is not a completed epoch or full-history publication.

The actual v1 object has a 96-byte fixed header and bounded Wincode payload,
not the proposed packed index format below. Its header supplies exact access
prefix/suffix offsets and a payload SHA-256. The payload binds source ETags and
lengths, the full hot row, parent slot, blockhash, **previous blockhash**, source
schemas, signature counts and the serialized dictionary tables. It contains
no compressed block or signature bytes. Offline construction checks the real
block header and exact parent identity, per-transaction signature counts and
all required dictionary membership. Source files are not changed.

One whole resolution GET supplies the descriptor. Two conditional source range
GETs then run in parallel. The binary path joins native streams without
decoding the hot block or copying network chunks through WASM. JSON decodes
the source bytes and emits bounded output chunks. A client can download the
resolution once, retain the Worker-issued HMAC locator, then fetch a distinct
two-part frame with two source GETs and no resolution GET. Each request still
requires customer authentication. The one-time index download is measured
separately; the index is specific to one block and immutable generation.

The eight objects total 625,602 bytes, with a mean of 78,200.25 bytes and range
44,472–106,968. They add 45.1% to the same samples' compressed block and signature
bytes. The sample mean extrapolates to 33.78 GB per 432,000 blocks, or about
$0.51 per epoch-month at R2 Standard prices before allowances and rounding.
One object PUT per block adds about $1.94 per full epoch during construction.
These are sample estimates, not measured full-history totals. See the
[storage model](../../reports/get-block-resolution-20261121/storage-overhead.json)
and [publication receipt](../../reports/get-block-resolution-20261121/main.json).

The current pubkey registries are about 994 MB and 1.047 GB for epochs 1089
and 1090. They are existing archive data, not a new index copy. A native bulk
client can download those tables once and use a small slot metadata index.
A browser that reads a few blocks needs only the per-slot objects. A separate
browser JSON codec package has not been built by this change; the native
client and protocol tests are recorded separately from browser performance.

The current full GET JSON endpoint supports only Base64 transaction bytes.
Standard RPC fields keep their required encodings. The Base64 update reused
the same eight index objects and published no block or signature copies.
Its [live benchmark](../../reports/get-block-base64-20261121/summary.json)
passed all 192 calls and matched Helius for every full JSON result. Cold JSON
p50/p95 was 525.105/866.116 ms; response hits were 62.347/97.985 ms, compared
with 96.824/170.813 ms for Helius repeats. Cold JSON remains slower.

The separate [stage profile](../../reports/get-block-base64-20261121/cold-profile-summary.json)
measured arithmetic median waits of 43 ms for index headers and 463.5 ms for
the two parallel Foundation ranges. Most source wait precedes the response
headers. A further slot-offset index would not remove these source requests.
Regional placement tests reduced some source waits but increased other travel
time; production keeps default edge placement. These tests do not establish
the bucket's physical location. Native Base64 conversion uses about 9.951 ms
median CPU in the eight-block local test; this is not Worker CPU. Worker
profile clocks can stay fixed during synchronous CPU work.

The next [shared-cache release](../../reports/get-block-cache-20261121/summary.json)
also passed 192/192 calls. JSON and binary now use the same immutable source
range keys, including source ETag, total length and exact range. Native binary
cache writes use bounded streams and `waitUntil`; cached network chunks do
not cross WASM. Index objects enter the caches only after validation. Each of
the eight blocks needed three origin GETs in total across its three first
normal formats. Fourteen of sixteen later-format responses needed no source
GET; the other two fetched only signatures after `access=0`. Forced-origin
full reads still need three GETs. Concurrent independent cache misses are not
collapsed; no request-scoped stream or I/O promise is kept in global state.

The [CPU/auth update](../../reports/get-block-cpu-20261121/summary.json) reuses
the same eight resolution objects. Successful GET key checks use a five-second
positive cache, capped at 256 records and 128 KiB. Fully cold profiling bypasses
it and the index cache. Source-only profiling retains both and forces the
two Foundation ranges. All eight full source JSON calls proved two S3 GETs
and zero owner R2 GETs; seven also proved zero KV reads. Fully cold requests
still need three GETs and one KV read. Index/auth warmups are counted separately.
The new output writer is byte-identical, with a 5.01% local WASM median gain.
The dedicated cold CPU sample costs about $0.778/M for invocation CPU alone.
This does not meet an all-in $1/M cold target: two GETs and one Worker request
already cost $1.02/M before CPU. Cold reads remain slower than Helius. No new
resolution, compressed-block or signature objects were published in this step.

## Measured problem and current code

The [pilot report](../../reports/get-block-cloudflare-20261121/main.json) reads
slot `470987967`, with 370 transactions. Its forced origin JSON read used 624
object operations: 619 GETs and five HEADs. It read 3,123,246 archive bytes and
took 17,755.155 ms. The full binary read used the same operation count and took
30,496.915 ms. These are single samples through CDG, with Worker caches bypassed.
They do not measure a physically cold R2 store or a provider's internal cache.

The response matches both comparison providers in that pilot. The large read
count comes from ID resolution, not from the JSON response size alone.

Current [stored.rs](../../edgezilla/get-block/src/worker/stored.rs) reads a hot
block and collects pubkey, recent-blockhash and vote-hash IDs from messages,
metadata, logs and rewards. It then reads registry pages and one signature
window. Adaptive pages keep each registry family within 4 MiB and all registry
reads within 16 MiB. Eight shared read permits bound concurrency. These bounds
permit this block to decode, but do not remove its hundreds of random reads.

The existing [dense slot index](../../edgezilla/get-block/src/slot_index.rs)
has a 128-byte header and 128-byte rows. It supplies block and signature
locations, parent slot and both block hashes. It does not supply block-local
key or vote-hash tables. Adding only that index cannot remove this main cost.

The old `ArchiveV2BlockAccessBlob` already supplies the required tables, but
also copies every signature. Foundation's `query-with-signatures` upload omits
that serving blob and its indexes. Do not require a rewrite of the durable
archive or restore a second signature copy as the default solution.

## Recommended first format: five cold GETs

Build two derived files under a new immutable serving generation:

```text
serving/GENERATION/epoch-N/get-block-slots.v2.index
serving/GENERATION/epoch-N/get-block-resolution.v1.zstd
```

Keep `archive-v2-blocks.zstd` and `signatures.bin` at their existing source
locations. The resolution file contains one independent zstd frame per block.
It contains only the values needed to resolve that block's IDs.

Use fixed little-endian index integers. Do not change the existing v1 index.
The proposed v2 header is 1,024 bytes. It contains:

- Magic, version, header length, row length, flags, epoch, first slot, slot count
  and present block count.
- The source generation descriptor SHA-256 and original hot-index SHA-256.
- Exact source block, signature, registry and blockhash-registry lengths, plus
  the new resolution-file length.
- Source object identifiers and bounded strong ETags. Keep variable source keys
  in an admitted immutable generation descriptor.
- Explicit message schema (`current` or `may24`), metadata schema (`current`
  or `legacy`), and hot/resolution encodings. Use defined wire codes; do not
  serialize Rust enum discriminants implicitly.

Select one schema for the complete source generation. Bind its exact marker
bytes or explicit operator declaration in the build receipt. A successful
transaction with no execution error cannot distinguish the metadata schemas.

Each slot has one 160-byte row:

| Offset | Bytes | Field |
| --- | ---: | --- |
| 0 | 52 | Exact `ArchiveV2HotBlockIndexRow` fields in their current fixed layout |
| 52 | 8 | `parent_slot` |
| 60 | 32 | `blockhash` |
| 92 | 32 | `previous_blockhash` |
| 124 | 8 | Resolution-frame offset |
| 132 | 4 | Resolution compressed length |
| 136 | 4 | Resolution decoded length |
| 140 | 2 | Resolution payload version |
| 142 | 2 | Row flags; zero for v1 payloads |
| 144 | 16 | Reserved zero bytes |

An absent row is entirely zero. A nonzero row with a zero required length is
invalid. `previous_blockhash` follows the stored parent reference, including
the previous-epoch boundary. It never means the hash of `slot - 1`.

The 52-byte hot row retains block ID, slot, compressed offset and length,
decoded length, transaction count, first transaction ordinal, first signature
ordinal and signature count. Therefore the signature request remains:

```text
offset = first_signature_ordinal * 64
length = signature_count * 64
```

The proposed Wincode resolution payload is:

```text
ServingResolutionV1 {
  version: u16, flags: u32, block_id: u32, slot: u64, blockhash: [u8; 32],
  pubkeys: Vec<ArchiveV2BlockAccessPubkey>,
  blockhashes: Vec<ArchiveV2BlockAccessBlockhash>,
  vote_hashes: Vec<ArchiveV2BlockAccessVoteHash>
}
```

Reuse the exact existing [access entry types](../../crates/compact-v2/blockzilla-archive-v2/src/v2/mod.rs):
pubkey entries contain `id: u32` and 32 bytes; recent-hash entries contain signed
`id: i32` and 32 bytes; vote entries contain `block_id: u32` and optional bank
and block-ID hashes. Keep all tables sorted and unique. Preserve negative
recent-hash IDs after resolving the exact previous tail. Raw pubkeys and nonce
hashes already present in the block need no table entry.

Reject resolution frames above 16 MiB compressed or decoded. Keep the existing
block and signature bounds. Measure combined Worker memory before selecting
production limits; separate per-buffer limits do not prove a safe total.

Do not store `signatures` or `signature_counts` here. The original signature
window supplies the bytes; `ArchiveV2HotTxRow.signature_count` supplies each
transaction's count. Assemble the existing `ArchiveV2BlockAccessBlob` in memory
from the v2 row, resolution payload, hot transaction rows and signature window.
The JSON renderer and full binary bundle can then reuse their current types.
Keep the existing Ed25519 proof for ambiguous TowerSync instruction bytes.

For a request with no Worker cache entries, the intended read sequence is:

1. GET the index header and check the admitted generation and source lengths.
2. GET the slot's index page and check its row and ranges.
3. GET the compressed hot block, resolution frame and signature window in
   parallel: three GETs, with no registry or schema-marker HEADs.

This is five archive GETs. With the header and index page already cached, a
response miss needs three archive GETs. A complete response-cache hit needs
zero archive operations. Authentication still reads KV. Generation admission,
if it needs a separate manifest fetch, is an additional operation; report it
separately. These counts are design targets, not measured results.

## Three true cold GETs without copying block or signature data

If the five-read layout is still too slow, use a deterministic per-slot object:

```text
serving/GENERATION/epoch-N/slot-S.resolution.v1.zstd
```

That object contains the checked source descriptor, schema choices, one full
v2 row and its resolution tables. Its key follows directly from the requested
slot. Fetch it once, then fetch the original hot block and signature range in
parallel. This needs three GETs even with an empty Worker cache. It does not
need a separate slot index in that path, and it does not copy signatures or
compressed blocks. Cache keys still include the exact generation.

The tradeoff is one derived object per present block: at most 432,000 objects
per full epoch, or 471,744,000 slot positions across epochs 0–1091. Measure the
build, upload and object-management cost before choosing this for all history.
An epoch-packed resolution file has much fewer objects and supports bounded
sequential publication. Start with the five-read layout and measure both.

A third option packs complete self-contained binary bundles into an epoch
object. Header, row and complete bundle need three cold range GETs. That option
copies both compressed blocks and signatures. Treat it as a separate serving
cache with an explicit storage budget; do not count it as another required
durable archive.

## Size and operation estimates

At 432,000 slots, the v2 index uses `1,024 + 432,000 * 160 = 69,121,024` bytes,
about 65.92 MiB per epoch. This is 13,824,896 bytes above the existing 128-byte
header/row index. Resolution storage must be measured from real blocks.

For `P` pubkey rows, `H` recent-hash rows and `V` vote rows, its uncompressed
payload is the fixed payload fields and vector-length prefixes, plus:

```text
sum(pubkeys)    = sum(LEB128_length(id) + 32)
sum(hashes)     = sum(encoded_i32_length(id) + 32)
sum(vote_hashes)= sum(LEB128_length(block_id) + 2 option tags + 32 * present_hashes)
```

Use Wincode `serialized_size` for exact totals. Four-byte IDs give about 36
bytes per pubkey/hash entry and up to 70 bytes per vote entry. Compression,
ID lengths and absent vote hashes change that size.

The pilot's full bundle is 217,859 bytes; its `access=0` bundle is 117,974
bytes. Their 99,885-byte difference includes the access vector's Wincode prefix.
The 413 signatures alone occupy 26,432 bytes. Removing those bytes and the
370 signature-count bytes leaves roughly 73 KB of table data and framing.
This is a sizing clue, not a measurement of the proposed payload or its zstd
size. A builder sample must supply the exact value.

For the measured 624-operation block, five operations reduce the count by
99.20%; three reduce it by 99.52%. These ratios do not predict latency. At a
complete response-cache hit fraction `h` and `Q` requests, the uncached archive
operation term is approximately `Q * (1 - h) * reads_per_miss`, before index
and resolution-cache reuse. Count S3 calls too when R2 uses its S3 endpoint.
Apply current R2, Worker CPU/request, KV and metrics prices separately.

The current customer offer charges $1 per million archive-backed requests;
complete cache hits earn no archive-request revenue. At the checked Standard
Class B rate of $0.36 per million operations, the pilot costs $224.64 per
million cold full reads in R2 operations alone. Five reads still cost $1.80;
three cost $1.08. A higher hit fraction reduces both cold-read cost and billed
archive-request revenue. It does not repair this per-cold-read price difference.
Worker execution and KV authentication also apply to response-cache hits. These
are marginal calculations before shared allowances and bill-unit rounding,
not an account invoice. See [R2 pricing](https://developers.cloudflare.com/r2/pricing/).

For an assumed 64 KiB resolution per present block and 432,000 blocks per epoch,
the added storage is 28.311552 decimal GB. At $0.015/GB-month, a complete month
costs $0.42467328 before allowances and rounding. Saving 619 operations per cold
read saves $0.00022284. The storage-only break-even is therefore about 1,906 cold
reads per epoch per month. This excludes build, upload, source reads, index
storage and Worker costs. The 64 KiB assumption is not a measured output size.

## Implementation and acceptance work

Build resolution frames from checked local Compact V2 files in bounded block
batches. Reuse the current collectors for all typed references, including logs,
loaded addresses, token balances, returns and rewards. Do not publish a partial
generation as complete. Record source/schema identities, coverage, lengths and
hashes; preserve uploaded-pending-verification status until its required checks
pass. Publish derived files under a new prefix, with conditional writes.

Add a separate Worker layout flag and cache namespace. Keep the current
registry reader as an explicit fallback; mark fallback responses so their read
counts cannot be reported as five-read results. Check exact block and parent
identity, ID coverage, signature length/counts, payload versions, schemas and
bounded offsets before rendering. Use checked source generations and strong
conditional reads. Do not change or retire the native ledger in this work.

Acceptance needs the same real slots and complete JSON comparison as the
pilot, plus early epochs, negative hashes, epoch boundaries, failed execution,
V0/V1 messages and both TowerSync encodings. Test missing, truncated, mixed and
changed generations. Then measure verified Worker-cache bypass and actual
response hits, GET/HEAD counts, bytes, CPU and memory. Report admission reads,
fallbacks and extra large-block ranges instead of hiding them in the target.

Also test 2, 8 and 32 identical concurrent requests with empty caches. Report
the sum of origin operations and bytes, per-request latency and duplicate work
against one serial miss. The current path does not combine concurrent misses
into one in-flight origin read. Do not assume that it does. Repeat after cache
eviction and from another data center. Cache entries are local to a data center
and can be evicted before their TTL; a hit in CDG does not prove a hit elsewhere.
