# Foundation direct resolution service

## Recent stream blocks

`--recent-config` also enables private `GET /v1/finalized/{slot}`, with no
query parameters. This route selects one unique rooted bank by slot. It
checks the original block frame, native root control, source and retention
authority. The caller does not supply a blockhash. Ambiguous rooted banks,
missing root proofs, changed source bindings, corrupt files and retirement
races are unavailable errors, not archive misses.

A hit uses the same original frame body and `X-BZ-Recent-Metadata` described
below, with admitted commitment `finalized`. `X-BZ-Finalized-Root` contains
the exact small root control frame in URL-safe Base64 without padding. The
raw control frame is limited to 4,096 bytes. A caller must check its source,
root event and payload binding against the block. The processed block event
stays unchanged. Foundation does not render RPC JSON or store another block
copy; the Worker converts the checked existing Compact V2 objects.
`X-BZ-Finalized-Producer-Generation` also binds the reply to the configured
native producer generation. A retained but unrooted slot returns HTTP 409
with `not_finalized`, never an archive miss.

Only a successful source read with no rooted bank returns the existing HTTP
404 `not_cached` reply and admitted archive locator (or `source: null`). An
admitted locator also has `X-BZ-Recent-Blockhash`, checked against the local
archive hash. This route uses the same authorization, protocol pins, bounded
blocking-work permits, `no-store` policy and recent-read counters. The
existing hash-pinned `/v1/recent/{slot}` contract remains unchanged.

`--recent-config /private/recent.json` enables `GET /v1/recent/{slot}`. It reads
the native producer's existing rolling window through `BankSource`. That
library opens the existing `feed.sqlite` with `SQLITE_OPEN_READ_ONLY` and
`query_only`. It checks retention, native root proof, original marker and
object hashes. The service does not start another producer, restart the
validator or origin, or create a block store, spool, result cache or index.

The private configuration has this shape:

```json
{
  "bank_source_root": "/existing/run/bank-v2",
  "payload_root": "/existing/run/processed",
  "source": {
    "genesis_hash": "<canonical native hash>",
    "node_identity": "<canonical native identity>",
    "agave_revision": "<exact revision>",
    "session_id": "<exact native session>"
  },
  "producer_generation": "<64 lowercase hex digits>"
}
```

An optional `native_archive_catalog` field can name the existing publisher's
absolute `archive.sqlite` path. The service opens it read-only, with
`query_only`, after a checked live miss. No connection or record is cached.
If configured, a missing file, descriptor or invalid record returns HTTP 503.
A missing slot row can continue to the existing historical catalog lookup.

The publisher catalog has `meta(id INTEGER PRIMARY KEY, record TEXT)` and
`finalized(slot INTEGER PRIMARY KEY, record TEXT)`. The `meta` row with ID 1
is JSON with `version: 1`, exact `source`, `producer_generation`, and
`prefix: native-stream/bank-v2/SESSION`. A finalized row contains only this
small locator:

```json
{
  "version": 1,
  "producer_generation": "<64 lowercase hex digits>",
  "metadata": {
    "version": 1,
    "slot": 100,
    "blockhash": "<canonical native hash>",
    "parent_slot": 99,
    "parent_blockhash": "<canonical parent hash>",
    "bank_id": 7,
    "source": {
      "genesis_hash": "<canonical native hash>",
      "node_identity": "<canonical native identity>",
      "agave_revision": "<exact revision>",
      "session_id": "<exact native session>"
    },
    "cursor": "<source:pSEQUENCE:frame SHA>",
    "frame_sha256": "<frame SHA>",
    "commitment": "finalized"
  },
  "root_frame_base64": "<exact original root control, URL-safe Base64 without padding>",
  "frame": {
    "key": "native-stream/bank-v2/SESSION/frames/SHA.bin",
    "etag": "\"<immutable R2 ETag>\"",
    "length": 123,
    "sha256": "<same SHA as metadata.frame_sha256>"
  }
}
```

The publisher must commit that row only after exact immutable frame upload,
full readback and matching root proof. The service checks the catalog source,
generation, canonical key, quoted ETag, bounded length, cursor and root binding.
An archived native hit returns HTTP 404 with the existing `version`, `slot`,
`reason: not_cached`, `source: null`, and the complete `native_archive` locator.
The Worker can fetch that one existing frame from R2 and use the same native
decoder. This response body is limited to 16 KiB. The normal live body remains
unchanged. There is no second JSON or binary block store.

### Optional current-ledger fallback

The optional `ledger_compact` configuration admits the existing ledger
compactor for slots at or above an explicit floor:

```json
{
  "helper": "/private/release/hivezilla-ledger-archive",
  "helper_sha256": "<64 lowercase hex digits>",
  "ledger": "/existing/real/validator/ledger",
  "minimum_slot": 472608000,
  "max_wall_ms": 8000,
  "generation": "ledger-compact-v1"
}
```

This is a field inside the recent configuration. It runs only after a checked
native miss, native archive miss and historical archive miss with no admitted
source. It never replaces the exact processed `/v1/recent` contract. The
service checks the helper SHA at startup and its file identity on each call.
On Linux, the child executes the pinned open file. A separate nonblocking
gate permits one ledger helper at a time, while other recent reads can use
the normal HTTP capacity. A busy helper returns terminal HTTP 503 with
`ledger_compact_unavailable`.

The command is `read-slot-compact --ledger PATH --slot INTEGER`. It opens
the existing ledger read-only for each call. Standard output is bounded to
12 framing bytes, 4,096 metadata bytes and a 16 MiB existing V1 bundle.
Standard error is bounded to 16 KiB. The service drains both pipes, kills and
reaps the child at the configured deadline, and retains both capacity guards
until the child exits, including after HTTP cancellation. No payload or
snapshot file is created.

A hit returns HTTP 200, `X-BZ-Foundation-Result: ledger_compact`, the existing
bundle content type, `X-BZ-Ledger-Metadata` with URL-safe Base64 helper JSON,
and the exact configured `X-BZ-Ledger-Generation`. The metadata binds the slot,
parent, canonical Base58 hashes, transaction count, complete hot row, body
SHA and length, current schemas, and explicit rooted/metadata-complete flags.
The service borrows the bundle body from its bounded stdout buffer. The
Worker checks and converts that existing bundle. This path has no native
cursor, root control frame, or R2 object identity.

Helper exit 3 is checked absence; exit 4 is HTTP 409 `not_finalized`.
Incomplete data, corrupt output, other exits and timeouts are terminal HTTP
503 `ledger_compact_unavailable`. Parent thread CPU measurements exclude
the helper child CPU; elapsed work time includes the helper wait.

Both directories must be real absolute paths. The service checks the exact
source, producer generation, declared payload root and local beam retention
authority for each request. A failed source is unavailable; stale health does
not prevent a retained-frame read. Source rollover needs an explicit new
configuration. The adapter keeps no database connection or read cursor
between requests.

Each request requires the existing private authorization and protocol headers.
The query requires `blockhash` in canonical native form and `commitment` with
`processed` or `finalized`. Processed requests also require `cursor`,
`source_session` and `bank_id`, which must identify the exact block frame.
Finalized reads require a matching original block and retained native root
proof. The returned frame keeps its original processed event unchanged.

A hit returns the original `BZSTRM01` bytes with content type
`application/vnd.blockzilla.stream.v2`, exact length, full-frame SHA-256 and
`X-BZ-Foundation-Result: recent`. `X-BZ-Recent-Metadata` contains URL-safe Base64
JSON with version, slot, blockhash, parent slot and hash, Bank ID, exact source,
cursor, frame SHA and the admitted commitment. `Cache-Control: no-store` and
`X-BZ-Foundation-Cache: BYPASS` apply. The Worker can forward this bounded body
without decoding the Compact V2 block or rendering JSON.

Only a successful native lookup that returns no finalized frame can produce
HTTP 404 with `not_cached`. That reply includes the existing pending R2 locator
when the archive catalog admits the slot. One pinned 32-byte local read checks
the known archive hash before it returns that locator. The reply includes
`X-BZ-Recent-Blockhash`; an expected-hash mismatch returns HTTP 409 before R2.
An uncovered archive slot has `source: null`. An expired processed frame is
HTTP 410. Native errors, corrupt frames, changed identities, failed health and
capacity failure are unavailable responses, not archive misses.

Recent reads hold only bounded request buffers. Their frame byte count and
hit/miss/error counters appear in `/v1/info`. Existing raw-signature and local
pread counters cover epoch resolution work; recent frames include the original
signature bytes inside the native frame. There is no raw-signature side file.

## Epoch ID resolution

This private service resolves all account and hash IDs used by one Compact V2
block from the existing local epoch tables. Each request reads those tables
again. The service reads no raw signature payload and creates no per-block
resolution index or result RAM cache.

`POST /v1/resolve` accepts a complete `ResolveRequestV1` typed ID list with
content type `application/vnd.blockzilla.resolve-ids+json`. The request binds
the slot, source row, hot-frame SHA-256, parent slot, current and previous hash
IDs, per-transaction signature counts, account IDs, blockhash IDs and vote-hash
references. The service checks the request source against its local catalog.
The caller binds that ID list and hot-frame SHA to the hot bytes it fetched.

`POST /v1/resolve-block/{slot}` accepts the exact compressed hot frame with
content type `application/vnd.blockzilla.compact-v2-hot.zstd`. It uses the
local source row, decompresses the frame, decodes the declared stored schema,
and collects the complete typed ID list before it resolves the tables. The
collector covers messages, address lookups, loaded accounts, rewards,
metadata, logs, return-program IDs and both vote-hash columns. An unsupported
raw transaction or metadata fallback fails explicitly.

Both routes return the existing Resolution V1 Wincode envelope with content
type `application/vnd.blockzilla.slot-resolution.wincode`. The envelope binds
the full source identities, source row, actual parent slot, current blockhash,
actual previous blockhash and signature counts. It contains no signature
bytes. A skipped slot does not change the parent to `slot - 1`. Legacy first
blocks use the pinned predecessor tail when required. Bank hashes and vote
block-ID hashes remain separate fields.

Data requests require these headers:

- `Authorization: Bearer <private broker token>`
- `X-BZ-Foundation-Protocol: 1`
- `X-BZ-Foundation-Generation: <catalog generation>`
- `X-BZ-Foundation-Source-Prefix: <catalog source prefix>`

Each POST also requires `X-BZ-Foundation-Read-Mode` with `normal`, `source` or
`full-cold`, its exact content type, and
`X-BZ-Foundation-Request-SHA256`, with 64 lower-case hex digits for the exact
raw request body. The service checks that SHA before it resolves IDs. Request
content encoding must be absent or `identity`. All three read modes resolve
the tables without a result cache.

A successful reply has an exact `Content-Length` and these proofs:

- Matching protocol, generation and source-prefix headers.
- `X-BZ-Foundation-Result: resolution` and
  `X-BZ-Foundation-Commitment: finalized`, under the catalog admission policy.
- `X-BZ-Foundation-Locator`, with the Locator V1 Wincode bytes in URL-safe
  Base64 without padding.
- `X-BZ-Foundation-Signatures: archive`.
- `X-BZ-Foundation-SHA256`, for the complete response body.
- `X-BZ-Foundation-Request-SHA256`, with the verified request digest echoed.
- `X-BZ-Foundation-Cache: BYPASS`.

`GET /v1/block/{slot}` returns a small typed cache miss and the source row
when that slot is admitted. Catalog startup checks local file type, path,
read-only mode, size and SHA-256; source ETags and lengths; row continuity;
and parent/hash relations. It retains the checked hot rows in RAM. Registry
files remain local read-only files. Only epochs in the explicit service
catalog are admitted. The operator supplies source trust; file availability
alone is not proof of canonical publication.

Stored hot-block schema compatibility uses the existing native decoder.
Message and metadata schemas are explicit per-epoch catalog fields. The
native sample passed May24 messages for epochs 0, 1 and 2 and Current messages
for the other selected epochs, with Current metadata. Unsupported schemas
fail explicitly. The reader supports the declared predecessor-tail format;
it does not select a format from divisibility alone.

Typed bodies have a 4 MiB limit. Selected hot frames have a 16 MiB compressed
and 32 MiB decoded limit. These request limits do not reject an epoch because
an unselected reward block is larger. The service checks general geometry for
all source rows, then applies strict bounds to the requested row.

Run the service behind HTTPS with a loopback connection from the proxy. The
private token file contains one printable token, 16 to 512 bytes long.

```sh
cargo run --release --manifest-path indexer/blockzilla-resolution-service/Cargo.toml \
  --bin blockzilla-resolution-service -- \
  --mirror-root /path/to/source-v1 \
  --catalog /path/to/catalog.json \
  --token-file /path/to/private-token \
  --listen 127.0.0.1:18961 --cache-mib 0 --max-concurrent 8
```

`--cache-mib` is a compatibility argument and must be zero. A nonzero value
is rejected. The router creates no result cache object. It checks capacity
before it reads a request body. Request and response buffers exist only while
a request is active.

`X-BZ-Foundation-CPU-Micros` uses `CLOCK_THREAD_CPUTIME_ID` around synchronous
blocking work: request SHA, decompression, hot decode, ID collection, local
resolution, response encoding and response SHA. HTTP, authorization and
runtime work outside that closure are outside this CPU scope.
`X-BZ-Foundation-Resolve-Micros` reports elapsed time, including blocking-pool
wait. Per-stage CPU and elapsed headers cover request SHA, decompression, hot
decode, collection, table resolution and encoding.

`X-BZ-Foundation-Pread-Calls` and `X-BZ-Foundation-Pread-Bytes` count local file
calls and returned bytes. They do not count R2 GETs or prove physical SSD
reads. Startup SHA verification and repeated reads can warm the OS page
cache. Authenticated `GET /v1/info` reports requests, local reads, blocking
thread CPU and zero result cache bytes.

Native validation used 111 selected blocks across epochs 0, 1, 2, 100, 300,
500, 700, 900, 1047, 1057, 1089 and 1091. All 888 loopback HTTP requests passed:
one warmup round and three timed rounds for both routes, at concurrency one
with a persistent connection. The routes returned identical response bytes
for all 444 pairs. Independent Node decoding passed all 222 exported response
bodies, including full dictionaries, source identities, signature counts and
the actual previous hash. The four original control blocks also matched their
original dictionaries, current/previous hashes and counts exactly.

The timed native results below use 333 requests per route. Times are p50/p95.

| Native measurement | Typed IDs | Raw hot frame |
| --- | ---: | ---: |
| Blocking thread CPU | 0.566 / 1.186 ms | 2.047 / 3.837 ms |
| Local HTTP completion | 0.870 / 1.508 ms | 2.384 / 4.221 ms |
| Request entity bytes | 17,700 / 31,307 | 97,018 / 229,322 |
| Response entity bytes | 78,464 / 160,115 | 78,464 / 160,115 |
| Local pread calls | 388 / 1,786 | 388 / 1,786 |
| Local pread bytes | 110,432 / 197,408 | 110,432 / 197,408 |

These are finite loopback checks with uncontrolled OS page cache. They do not
measure physical cold SSD reads, R2 reads, Cloudflare latency or sustained
capacity. The current canary catalog admits only those 12 epochs. The existing
index mirror covers epochs 0–1091; that download is not full-history serving
or validation proof. Read the [native HTTP report](../../reports/foundation-direct-resolver-20261122/native-http-benchmark.json),
[independent client checks](../../reports/foundation-direct-resolver-20261122/native-http-client-validation.json)
and [original control checks](../../reports/foundation-direct-resolver-20261122/original-control-parity.json).

The offline fixture tool writes small JSON requests and verification metrics.
It builds and checks response bytes in bounded memory, then discards them.
It creates no response or index files and starts no HTTP service or cache.
Use a bounded input with at most 512 selected frames.

```sh
cargo run --release --manifest-path indexer/blockzilla-resolution-service/Cargo.toml \
  --bin measure_direct_resolution -- \
  --manifest sample-input.json --output-dir new-fixture-directory
```

Input contains `version: 1`, `mirror_root`, `catalog`, and a `samples` array
with `slot`, `hot_frame` and optional `hot_sha256`. Sample labels are preserved.
Output is `fixtures.json` and per-slot request JSON files. It records expected
response SHA and length, exact parent and block hashes, complete ID counts,
local reads and thread CPU profiles. The output disk reserve defaults to
800 GiB. Each output uses a new path and an atomic write.

```sh
cargo test --manifest-path indexer/blockzilla-resolution-service/Cargo.toml --lib
cargo test --manifest-path indexer/blockzilla-resolution-service/Cargo.toml --bin measure_direct_resolution
```
