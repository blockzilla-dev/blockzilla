# Firestrategy live stream integration handover

This handover preserves the earlier full-mode integration baseline accepted
on 22 November 2026. The current private pipe uses compact-only storage and
automatic Worker recovery. Use `/v1/blocks?projection=compact` for original
frames; full JSON block, signature and update views return HTTP 409. See the
[current acceptance](../../reports/stream-worker-recovery-20261122/README.md).
Firestrategy and Firewatch integration remains later work. Their existing
readers have not been switched to this service.

Start with a transport adapter and a reader that runs beside the existing
reader. Changing only the upstream URL will not work: the current application
readers and this service use different routes and event formats.

## Earlier full-mode integration inputs

The table describes the full-mode API. The current compact-only deployment
supplies current and historical blockhash views and original compact frames.
Applications must decode those frames to build transaction indexes.

| Application need | Available input | Integration boundary |
| --- | --- | --- |
| Current blockhash and expiry | `/v1/blockhashes` gives the current native confirmed/rooted signing selection | Keep the application's applied-Bank readiness and freshness checks. This feed has no historical replay. |
| Track known transaction signatures | `/v1/signatures` gives signatures, success/error fields and native Bank controls | Keep the application's signature index and commitment policy. |
| Build program and account activity indexes | `/v1/blocks` gives the full portable block view and original Compact V2 payload frame | Feed the application's existing decoders and index logic after format checks. |
| Reduce transferred JSON for selected activity | `/v1/updates?program=PUBKEY` or `?account=PUBKEY` | These are transaction filters. They are not account data subscriptions. |
| Track forks and confirmation | Native `block`, `confirmed`, `root` and `invalidate` events | Keep Bank identity and rollback logic. A processed block is not final. |
| Check the input service | `/v1/head` and SSE `status` events | HTTP 200 alone does not mean that input is live or signing is ready. |

This can reduce repeated block and signature polling after integration is
tested. The full block view also supplies transaction messages, account keys,
instructions and recorded execution metadata. Use the existing decoder schema;
do not treat this JSON as a Solana JSON-RPC `getBlock` response.

Account reads, account data subscriptions, simulation and transaction sending
are separate services. They are not routes on this SSE service. The native
account/ledger bridge on Foundation is separate and is not exposed through
this Hetzner API. Historical archive reads and gap repair also remain separate.
No whole-RPC replacement or measured RPC saving is established by these tests.

## Connection and authentication

```text
Foundation native producer
  → original Compact V2 frames and native Bank controls over restricted SSH
Hetzner blockzilla-client-pipe.service at 188.245.147.127
  → authenticated SSE on 127.0.0.1:18890
Mac private SSH tunnel
  → http://127.0.0.1:18890
```

The service runs on the existing Hetzner host. Foundation keeps the raw
producer role. It does not run the SSE projection or application index.
It does not require consumer ACKs for this raw stream. The separate Hetzner
process stores a bounded replay window and supplies the views.

The Mac tunnel is already installed as
`dev.blockzilla.hetzner-stream-tunnel`. The Mac must be awake and connected.
The private client commands are:

```sh
~/.local/bin/blockzilla-stream status
~/.local/bin/blockzilla-stream blockhashes
```

The CLI does not store application cursors or reconnect SSE automatically.
Its full-block and signature commands apply to full-mode deployments. For
current compact blocks, use the explicit compact route below. The tunnel and
the Hetzner source reader reconnect separately.

All HTTP requests need `Authorization: Bearer READER_TOKEN`. A reader token
is already stored privately on the Mac at
`~/.local/share/blockzilla/hetzner-stream/reader-token`. The installed command
reads this file. No credential value is included in this handover. The admin
token stays on Hetzner and the origin token stays on Foundation. Reader tokens
cannot make management writes. Credentials in query strings are rejected.

For a direct HTTP test on the Mac, the installed private curl configuration
supplies the same read header:

```sh
curl --no-buffer --fail-with-body \
  --config "$HOME/.local/share/blockzilla/hetzner-stream/curl-read.conf" \
  'http://127.0.0.1:18890/v1/blocks?projection=compact'
```

The API is private and binds only to loopback. A process on the Hetzner host
can use host loopback after it receives a reader credential. A Docker
container's `127.0.0.1` is its own network namespace; it does not reach this host
listener. The application task must select a private route and credential
mount for its container. Do not change the URL to a public IP and assume it
will connect. No new container route or application credential was installed
in this task.

## SSE contract and payload mode

Replay routes are `/v1/blocks`, `/v1/signatures`, `/v1/updates` and
`/v1/blockhash-observations`. Without a saved cursor, they start after the
current output position. That is a live join, not a historical backfill.

Block and native control records use `schema: blockzilla-sidecar-update-v1`
with these fields:

| Field | Meaning |
| --- | --- |
| `source` | Genesis hash, node identity, Agave revision and source session |
| `cursor` | Service output cursor; also the SSE `id` |
| `sourceCursor` | Original native input cursor; not the SSE resume cursor |
| `kind` | Native event kind |
| `event` | Native Bank event, including Bank identity and commitment fields |
| `invalidatedBanks` | Affected Bank identities for invalidation handling |
| `block` | Portable block projection for block/signature/update views when applicable |
| `compactFrameBase64` | Original block payload frame, on `/v1/blocks` when applicable |
| `payloadFormat` | `native-bank-compact-v2`, with the original block payload |

The current service uses `/v1/blocks?projection=compact`. It omits the expanded
`block` JSON and preserves the original `compactFrameBase64`, native controls,
source and both cursors. It keeps all logs inside the compact frame. Full-mode
services can also use this projection. On the compact-only service, default
full block output, signature views and update views return HTTP 409.

The nested native event uses its Rust schema field names, such as `bank_id`
and `observed_at_unix_ms`. The portable block uses names such as `bankId`,
`parentSlot`, `transactionCount` and `transactions`. Do not apply one naming
convention to both objects.

Signature rows include `index`, `signature`, `signatures`, `success` and `err`.
The signature view omits the full message and metadata. Use full blocks or
updates for application decoding. A transaction can have more than one
signature. A missing execution result must not be converted into success.

Block, confirmed and root records can refer to the same block payload. Apply
the event's commitment change without inserting the transaction twice. An
invalidation can omit `block` and must still be processed. Preserve source
identity, slot, Bank ID and blockhash; slot alone is not a unique fork identity.
When full bytes are present on a control event, the embedded payload frame is
the original `block` frame. Apply the separate outer native control event too.

The stream also emits `status` without a durable SSE ID. A filtered record can
emit `cursor` with `matched: false`; save that position even though no
transaction matched. `/v1/signatures` and `/v1/updates` support comma-separated
`account` and `program` filters and `failed=true|false`. Account/program filters
match any selected key; the failure condition also applies. Invalidation
controls remain visible. Full blocks cannot be filtered. Filtering reduces
the downstream view, not the Foundation raw input volume.

`/v1/blockhashes` has a separate contract. It emits `blockhash` only while
`signingReady` is true. Fields include `source`, `sourceCursor`, `commitment`,
`contextSlot`, `blockHeight`, `blockhash`, `lastValidBlockHeight` and
`observedAtMs`. It has no durable SSE ID and rejects replay parameters.
Clear the local signing selection when status becomes unavailable or the
connection becomes stale. Apply a local freshness timeout and expiry checks;
an old cached hash must not stay ready after disconnection.

Historical blockhash observations have their own replay route. They are
labelled `historicalUpdate: true` and `usableForSigning: false`. Do not use them
as current signing readiness.

## Cursor and gap handling

Save the SSE `id` in the same durable application transaction as the index
changes. Reconnect with `Last-Event-ID: SAVED_OUTPUT_CURSOR`. Output cursors have
the form `SESSION:oPOSITION:DIGEST`. The alternative query is
`after=OUTPUT_CURSOR`; if both are supplied, they must agree.

Treat repeated delivery as safe through idempotent application writes. Keep
the cursor for each logical subscription with its route, filters and source
pin. A changed filter set needs an explicit policy for earlier unmatched data.

Replay is limited to 128 MiB or 8,192 events. It has no guaranteed time span.
An initially expired or different-source cursor returns HTTP 410. If a reader
falls behind after connection, the service sends an SSE `gap` and closes.
Stop claims of continuous coverage. Preserve the last committed position and
repair from a separate source before recording a new boundary.

Foundation source, runtime and producer generations are pinned. A source
change or missing upstream replay causes explicit failed/unavailable input.
The HTTP endpoint can remain available with saved history. The service does
not silently join a new source. Recheck the live source and `/v1/head` body
before integration; the acceptance receipt is the dated baseline.

## Integration work

The existing Firestrategy Bank reader uses `/v2/banks` and finite native frame
reads. Its finalized reader uses `/v2/banks/finalized/events` and exact block
reads. The new pipe uses JSON SSE under `/v1/` and carries the original block
frame inside each applicable full-block record. Add a transport adapter. Keep
the native event validation, program decoders, application index and rollback
rules. Check the vendored SDK/decoder revision against actual frames before
selecting which components can be reused unchanged.

At the earlier baseline, the Bank identity, event, recent-blockhash and
confirmed-observation types matched the inspected Firestrategy vendor copy.
Its Chain implementation also matched at that time. Repeat this comparison
against the current revisions before integration. The beam transport modules
were absent from that vendor copy. The
existing `packages/blockzilla-decoder/src/lib.rs::decode_bank_payload` can be
evaluated for reuse with the embedded payload frame. This source comparison
does not replace a compatibility test with the current release frames.

Firestrategy's `confirmed_stream.rs::set_blockzilla_ready` expects a complete
native observation. Its blockhash and height APIs also require
`bank_ingestion::native_is_current` to check the application's own applied
database state. Do not pass the flattened sidecar blockhash JSON straight into
that readiness path. Apply and validate the matching block and native control,
reach a fresh head locally, and then publish readiness. Preserve these checks
in `services/indexer/src/transaction_watch.rs`.

The inspected application repositories were `ferno-btc` for Firestrategy and
`ferno-watcher` for Firewatch. Read each working copy's agent instructions and
check its revision before integration.

Start with these application files in the Firestrategy working copy:

- `services/indexer/src/bank_ingestion.rs`: existing Bank input and cursor state.
- `services/indexer/src/confirmed_stream.rs`: confirmed input health and signing selection.
- `services/indexer-v2/src/feed.rs`: finalized native feed contract.

Firewatch's `tools/firewatch-live-consumer/README.md` describes a different old
chunk-notice API. It also needs a transport adapter. The apps' outward SSE
routes are application outputs; do not confuse them with these input routes.
These are source-code findings, not a claim about the apps' deployed revision.
Firewatch's existing transport also rejects plain HTTP origins. A future
adapter must explicitly support the private local connection through SSH;
do not remove HTTPS checks for arbitrary remote origins.

Run one new reader beside the existing reader first. Compare program events,
signatures, failed transactions, commitment changes and index effects. Test
disconnect/replay, duplicate delivery, stale status, invalidation and HTTP 410.
Commit the app cursor only with its matching index changes. Measure local
processing delay and queue growth. Select an application cutover only after
these checks pass.
Define the initial application boundary and any required Bank dependencies
before the live join. The SSE wrapper is not the old SDK bootstrap response.

The current service allows four SSE connections total. Prefer one full-block
reader plus one current-blockhash reader for an application that needs both.
It can derive its signature index from the block data. Coordinate reader use
between Firestrategy, Firewatch and local tests. Do not increase the live
service limits as part of an initial application test.

## Earlier full-mode baseline and current references

The release passed 80 tests. The real Mac test received 96 blockhash updates,
289 signature events and 250 full block/control events. All 250 shared records
agreed on signatures and outcomes. Original frame and compact object hashes
passed. A restart of only the consumer resumed the exact next SSE positions
in 2.905 seconds. These counts include controls and repeated payloads; they are
not counts of distinct blocks. No clock-corrected latency measurement exists
for this three-host path.

The 512 MiB disk image bounds replay storage. The service has a 3 GiB memory
maximum and a two-core CPU quota. Foundation's validator and the six existing
Hetzner application containers were not restarted for this deployment.
Webhook destinations are empty; webhook UI and application indexes are later
work.

- [Operation guide](HETZNER-PIPE.md)
- [Current recovery acceptance](../../reports/stream-worker-recovery-20261122/README.md)
- [HTTP and SSE implementation](src/server.rs)
- [Event views and field selection](src/projection.rs)
- [Native Bank event types](../../crates/blockzilla-bank-stream-v2/src/lib.rs)
- [Portable block decoder](../stream-relay/decoder/src/lib.rs)

## Prompt for the Firestrategy chat

Read `hivezilla/stream-sidecar/FIRESTRATEGY-HANDOVER.md`
and the linked acceptance report. Compare this private SSE input with our
current Firestrategy ingestion and signing-readiness code. Identify which
decoders, index updates and commitment rules can be reused, and define the
smallest transport adapter. Start with a reader that runs beside the existing
one. Keep account reads, simulation and transaction sending separate. Do not
change the running validator, existing application services or stream limits.
Do not print credentials. Propose the integration and its acceptance checks
before an application cutover.
