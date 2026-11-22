# Foundation native R2 range reader

This small Worker runs in the Foundation account and reads the existing
`solana-archive-data` bucket through a native R2 binding. The public Blockzilla
API, customer authentication, resolution indexes and billing stay in the
owner's account. This reader does not copy archive data, decode blocks, write
objects, or use KV or a response cache. Deployment and account access are
separate from this source and its local tests.

The only route is `GET /v1/range`. There is no public health or information
route. Only these paths are admitted:

```text
compact-v2/blockzilla-20261004/epoch-N/archive-v2-blocks.zstd
compact-v2/blockzilla-20261004/epoch-N/signatures.bin
```

`N` is a canonical nonnegative decimal integer. Each range is at most 16 MiB.
Offsets, lengths and complete object lengths must be safe JavaScript integers;
the complete range must fit the declared object. The reader permits only
quoted R2 MD5 or multipart ETags, for example `"55095261656b29000364d6621a28a17e-947"`.
Weak ETags are rejected.

## Signed request

Supply exactly one query value for each field:

```text
GET /v1/range?key=ENCODED_KEY&offset=N&length=N&object_length=N&etag=ENCODED_QUOTED_ETAG
X-BZ-Reader-Expires: UNIX_SECONDS
X-BZ-Reader-Signature: LOWERCASE_64_HEX_HMAC
```

The HMAC key is the literal UTF-8 value of the `BZ_READER_SECRET` Worker secret.
Use at least 32 random bytes of secret material. A caller normally sets expiry
30 seconds ahead. The reader requires a future expiry no more than 60 seconds
ahead of its clock. The header and query integers use canonical decimal
strings: `0`, or digits with no leading zero. Lengths must be positive.

HMAC-SHA256 covers these seven lines, with one LF between lines and **no final
LF**:

```text
range-v1
EXPIRES
DECODED_KEY
OFFSET
LENGTH
OBJECT_LENGTH
QUOTED_ETAG
```

Query order and percent encoding are not part of this message. The decoded
values are checked first, so newline injection, duplicate fields, extra fields,
path traversal and noncanonical numbers are rejected. MAC verification uses
`crypto.subtle.verify()`. There is no secret string comparison. The synthetic
[test vector](test/protocol-vector.json) fixes this wire contract and is not a
production credential.

Each authenticated request makes one native `R2.get()` with `range` and
`onlyIf.etagMatches`. The reader checks the returned complete object length,
quoted ETag and range metadata. A native `FixedLengthStream` passes the body
through and enforces its declared byte count. It provides backpressure and
client cancellation. Payload bytes are not buffered or passed through WASM.
This does not claim zero copies inside Cloudflare.

Successful reads return `206` with exact `ETag`, `Content-Length` and
`Content-Range` headers. All responses use `Cache-Control: private, no-store`
and include these operation receipts:

```text
X-BZ-Reader-Backend: native-r2
X-BZ-Reader-R2-GETs: 0|1
X-BZ-Reader-R2-HEADs: 0
```

The GET count is zero before a native read attempt and one after it, including
missing objects, failed conditions and backend errors. It is an API attempt
count, not a physical disk-read count. A successful response also includes
`X-BZ-Reader-Expected-Bytes`. That value describes the pending body; it does not
prove completion. `Server-Timing` covers authentication and R2 header wait.
Body completion is not known when headers are sent. A late body error aborts
the response and cannot change its HTTP status.

Errors are `400` for invalid fields, `401` for failed or expired auth, `404`
for an unknown route or missing object, `405` for methods other than GET,
`412` for a failed source condition or identity mismatch, `503` for missing
configuration, and `502` for a backend failure. Error bodies contain no
bucket name, secret, key or signature. A failed native read has no S3 fallback.

## Local checks

```bash
node edgezilla/foundation-reader/test/native-reader.test.mjs
```

Tests use Miniflare/workerd with a native local R2 bucket. They reuse the
installed Miniflare dependency in `edgezilla/get-block/node_modules` when no
local dependency is installed. `npm install` in this directory can install
the standalone test dependencies. No production credentials are used. Set
`BZ_READER_TEST_RECEIPT=/absolute/path/result.json` to save a test receipt.

The local suite passed 12 checks, including real conditional reads, exact
bytes, error receipts, streaming before EOF, client cancellation, short and
oversized body rejection, and recovery after a failed stream. This is local
validation; it is not deployment or latency evidence.

The test wrapper is `test/fixture-worker.mjs`. It is not a deployment entry
point. It adds local counters and controlled body faults around native R2.
The local runtime uses compatibility date `2026-09-10`, which the installed
workerd supports. The deployment example uses `2026-11-22`; local results do
not measure Cloudflare production latency or the cross-account HTTP hop.

The deployment entry point is `src/worker.mjs`, which exports only the
default handler. Protocol helpers and constants remain importable from
`src/index.mjs`; that module is not a Worker entry point. The local suite
starts the exact deployment entry point before it runs the instrumented tests.

The [example Wrangler config](wrangler.example.jsonc) requires the Foundation
account ID and a `BZ_READER_SECRET` secret before a deployment. Never put the
secret in `vars`, source, or a report. The owner-side adapter must use HTTPS,
reject redirects, and validate the returned identity, range and operation
receipts. Keep its existing source checks and separate owner-index operation
counts.

A local owner/reader integration can use two Miniflare Workers and an
`outboundService` route from the owner to this module. The owner still fetches
a signed HTTPS URL; the test runtime routes it to the local reader and local
R2. This does not require a weaker production URL policy or a cloud data copy.

API behavior follows the current [R2 binding reference](https://developers.cloudflare.com/r2/api/workers/workers-api-reference/),
[Web Crypto reference](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)
and [FixedLengthStream reference](https://developers.cloudflare.com/workers/runtime-apis/streams/transformstream/).
