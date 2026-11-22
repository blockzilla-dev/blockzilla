# Foundation direct resolution service

## Recent stream blocks

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
