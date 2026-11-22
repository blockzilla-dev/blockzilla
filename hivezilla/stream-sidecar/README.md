# Separate stream consumer

## Current private deployment, 22 November 2026

The live path is Foundation to the separate Hetzner consumer to the owner's
Mac. Foundation sends original Compact V2 frames through restricted SSH.
Hetzner runs in compact-only mode. It supplies authenticated current blockhash,
historical blockhash observation and original Compact V2 frame SSE views.
The Mac uses a private SSH tunnel. Webhook destinations are empty. Firestrategy
and Firewatch will build their own indexes later.

Read [the current pipe guide](HETZNER-PIPE.md) for the installed commands,
authentication, replay rules, storage limits and accepted test results.
The [Firestrategy handover](FIRESTRATEGY-HANDOVER.md) describes available inputs,
application adapters and a test plan for Firestrategy and Firewatch.
The current raw SSH input does not require an origin ACK or archive coverage
poll. Reader and admin tokens are separate. Its database resumes its own
durable cursor after restart and reports source changes or expired replay.
Automatic recovery through `https://getblock.blockzilla.dev` is enabled for
retained native frames. See the
[recovery acceptance](../../reports/stream-worker-recovery-20261122/README.md).

The sections below describe the supported HTTP/UDS input mode and general
output behavior. Their upstream ACK, coverage polling and default resource
limits do not describe the current raw SSH deployment.

## Explicit Compact-only storage mode

The deployed `--payload-mode compact-only` validates and stores original
Compact V2 Bank frames without creating or storing the portable JSON block.
It uses the same bounded typed message and metadata checks as the full
renderer. Source, frame/object hashes, native height, cursor, fork, root and
invalidation checks remain. The five-second signing freshness checks remain.
The default mode is `full` and keeps the existing expanded output.

Compact-only mode accepts `/v1/blocks?projection=compact`, current
`/v1/blockhashes` and historical `/v1/blockhash-observations`. Full block,
signature and update JSON views return HTTP 409 with a mode error. Webhook
targets are rejected at startup. No view changes silently. `/v1/head` reports
the mode, exact persisted wire/projection bytes, replay limits and boundaries.

On a checked full-mode database, startup validates the retained original
payloads, saved chain and output digests, then removes all stored portable
projections in one SQLite transaction. Native and output cursors do not change.
The conversion checks free space for the database-sized WAL and retains the
configured database, replay, memory and disk-reserve limits. It does not add
archive coverage or extend origin replay.

Before conversion, stop the service and save a consistent full-mode database
backup outside its bounded volume. A compact database cannot reopen in full
mode. To use an older executable, stop the service and restore that full-mode
backup first; do not point the older executable at compact rows. Empty compact
projection fields fail legacy JSON decoding. Keep the original source and all
saved cursor pins during this operation. Deployment and live acceptance remain
separate checks.

## HTTP/UDS input mode

This is a separate consumer process. It reads one pinned Compact V2 Bank stream.
It has no Agave RPC dependency and no Bank, AccountsDB or ledger handle. The
validator account/ledger bridge remains independent.

The producer and sidecar can use HTTP framing over a private Unix socket. The
sidecar can serve its own API through another Unix socket or loopback HTTP.
Remote upstreams require HTTPS. UDS requests retain Bearer authentication and
all source, cursor, frame and dependency checks from `blockzilla-bank-client`.

## Start

Create a private directory for the database and output socket. Start the origin
first. Root supplies the exact source identity and producer-generation pin.

```sh
blockzilla-stream-sidecar \
  --source-file /private/source.json \
  --producer-generation OPERATOR_PIN \
  --upstream-unix /private/origin.sock \
  --upstream-token-file /private/origin-token \
  --token-file /private/sidecar-token \
  --database /private/sidecar.sqlite \
  --listen-unix /private/sidecar.sock \
  --consumer-id sidecar-primary \
  --initial-after 'SOURCE_SESSION:p0:-'
```

Socket paths must be absolute, at most 100 bytes, and must not be symlinks. The
origin socket must already exist. The output socket uses an owned lock in a private parent directory. An active
listener, symlink or unowned file is rejected. A stale owned socket is removed
only when no listener is active. Normal SIGTERM exit removes only the same
socket inode. The lock file remains for safe restart.

A new database requires `--initial-after` or explicit `--join-head`. The latter
commits the current selected payload, dependencies and initial boundary; it does
not apply or claim earlier history. An existing database always resumes its own
durable cursor. It never replaces a missing replay range with a new head. Source
or producer-generation replacement requires an explicit operator transition.

Omit `--webhook-config` for an empty destination list. This is the production
default. No external webhook is configured by this package.

## Outputs

Read routes require a reader or admin token in `Authorization: Bearer ...`.
Management writes require the admin token. Use a fetch
SSE client that can set this header. Query-string credentials are not supported.

| Route | Data |
| --- | --- |
| `/v1/head` | Input readiness, usable signing selection, ACK backlog, coverage errors, subscription state and latest output cursor |
| `/v1/blockhashes` | Current usable confirmed/rooted signing hash and expiry; no transaction payloads |
| `/v1/blockhash-observations` | Historical native confirmation and root observations; replayable, not current signing readiness |
| `/v1/signatures` | Ordered signatures, success and exact failure outcomes, with Bank and commitment controls |
| `/v1/blocks` | Full portable detail projection plus the exact canonical frame as base64 |
| `/v1/blocks?projection=compact` | Original compact frame and native controls, with the expanded `block` JSON omitted; available on the current compact-only deployment |
| `/v1/updates` | Portable detail rows with optional account/program/failure filters |
| `/v1/webhooks` | Queue sizes, paused ranges and retry failures; no destination credentials |

Full blocks use the existing portable Compact V2 JSON schema. The exact frame
contains the complete original compact objects, including resolution tables. It
is not a second block codec or a JSON-RPC block claim. A confirmed/root control
still identifies its original processed payload. Invalidations preserve affected
descendant Bank identities. They do not change finalized history silently.

The optional `projection=compact` selection keeps the same source, native
events, original frame bytes, digests, output cursors and replay order. It
removes the duplicate expanded JSON block, including its rendered logs. Log
data inside the original compact frame stays intact for consumers that need
receipt evidence. The default and `projection=full` keep the existing output.
This selection is accepted only on `/v1/blocks`; block filters remain invalid.
It reduces client response bytes, not Foundation input or cached payload data.
Compact responses read durable native frames without loading the portable JSON
projection on a cache miss. With no webhook targets, native control commits also
use the original frame alone. In full mode, block intake still decodes and
stores its portable projection once; default full views and configured webhooks
keep that output. Compact-only mode checks the typed compact data and stores
the original frame without that projection. Check `/v1/head` for the active
payload mode before selecting a view.

The replay routes accept `after=OUTPUT_CURSOR` or `Last-Event-ID`. The current
`/v1/blockhashes` readiness view does not accept replay. Both cursors must agree
when present. Output cursors have the form `SESSION:oPOSITION:DIGEST`. They cover
Bank controls and coverage gaps in one durable output order. Each record also
contains its original `sourceCursor`. Coverage metadata has no fabricated Bank
hash or native invalidation. A pruned range returns HTTP 410 or an SSE `gap` and
ends the stream. A filter miss emits a small cursor record so reconnect remains
exact. `/v1/updates` and `/v1/signatures` accept `account`, `program` (comma-separated
public keys), and `failed=true|false`. Full block output is unfiltered.

Blockhash webhooks contain only native confirmed/root observations. They retain
context, expiry and observation time and are labelled historical updates that
are not current signing readiness. Late retries keep that label. Use the live
SSE readiness gate for signing.

The signing feed does not replay expired signing hashes. Status becomes
unavailable when native selection, health, source age, applied head or commit
state is unsafe. It emits status when unavailable. Webhook pressure does not
remove a valid signing selection or hold the core input cursor.

## Durable boundaries and limits

SQLite WAL uses `synchronous=FULL`. A Bank commit stores its payload/projection,
fork effects, output row, input cursor and webhook jobs in one transaction.
Coverage-gap polling stores its output rows, jobs and sparse gap frontier in one
transaction. The gap generation is pinned; the client does not learn replacements
from an HTTP response. Complete but unconfirmed retention gaps pass through as
coverage metadata, not a canonical or native invalidation assertion.

The local client ACK hook completes after this commit. A separate task coalesces
the latest committed Bank cursor and coverage-gap frontier and posts the origin
ACK. A lost response is safe to repeat. The two frontiers remain monotonic and
independent. Origin ACK means a consumer checkpoint was stored; it is not an
archive custody receipt or an instruction to unlink producer files.

Defaults are a 512 MiB / 8,192-event replay window, a 16 GiB SQLite page budget,
16 SSE clients, and sixteen in-flight upstream reads within the client's 64 MiB
frame budget. Admitted fetches are reordered before speculative decode starts.
Four decoder workers prepare at most four uncommitted block payloads. This work
cannot publish output or advance a cursor. Only the ordered FULL commit can do
that. The optional preprocessing hook is disabled by default in the client
library.

Decoded JSON and its serialized text are immutable and shared by control
commits and SSE reads. The cache retains at most 512 MiB of resident payloads.
Each running decoder reserves 512 MiB; a decoded payload must fit a 256 MiB checked
heap/text/wire estimate. A 4 GiB global charge follows each shared allocation
until its last record, worker or cache reference is dropped. A slow SSE write
holds only its bounded serialized response, not a decoded cache allocation.
Use an 8 GiB service memory limit for this mode. Outgoing responses and the
existing decoder's transient allocations also remain under that service limit.
An evicted control dependency is read from verified durable bytes. It is never
replaced with a different Bank.

Producer ACK pressure pauses
intake at 64 MiB or 256 unacknowledged events and is visible in health. Webhook
retries and output delivery remain separate. Replay removal deletes only this
sidecar's temporary copies. It does not touch the producer, ledger or archives.

## Webhooks

The optional configuration is a JSON array. Each subscription has a stable ID,
URL, view (`blockhashes`, `signatures`, `updates`, `blocks`), filters, selected native event kinds,
queue byte/event limits, and a retry limit. The default event kinds are `root`
and `invalidate`; source coverage gaps are always delivered. HTTP is permitted
only for a literal loopback address. Other destinations require HTTPS. Redirects
are not followed. An optional `token_file` supplies receiver authentication.

Delivery is at least once. The stable `X-Blockzilla-Delivery-Id` must be used for
receiver deduplication. A receiver ACK is a 2xx response with exactly one
`X-Blockzilla-Ack` header equal to that ID. An ambiguous response retries the same
body and ID. Each destination keeps its own order and retry state. Four network
requests can run at once. Network I/O never runs inside the SQLite transaction.

At queue quota, only that subscription pauses new intake. One durable skipped
output range is extended as core intake and producer ACK continue. Existing jobs
can drain. Retry exhaustion retains the failed job and pauses that subscription.
An indefinitely offline destination cannot have both infinite retention and
bounded disk. The paused range explicitly records that limit.

Use `POST /v1/webhook-jobs/DELIVERY_ID/retry` to retry a failed job. After old jobs
have drained, use `POST /v1/webhooks/ID/resume` with `{"accept_gap":true}`. This
queues the gap notice before new updates. No queued or failed job is silently
deleted. Acknowledged receipts have bounded local retention.

## Checks

Build and tests run in a dedicated Foundation job, not in the validator process.
Tests cover UDS admission, ACK receipts, sparse coverage IDs, atomic rollback,
restart, subscription quotas, stable retries to a local receiver, failed
transactions, invalidation and exact canonical frame delivery. The ignored
retained-frame test requires `BLOCKZILLA_SIDECAR_FRAME` and is run separately on
Foundation. Fixture checks do not establish continuous live acceptance. Fatal input, origin-ACK protocol/storage, coverage protocol/storage or internal
worker failures exit nonzero. The supervisor can restart from the exact committed
database. Normal webhook destination retries do not stop the service. Root owns
deployment and the continuous live watch.
