# Foundation to Hetzner to Mac

Accepted on 22 November 2026. This is the current private stream path.
Firestrategy and Firewatch will build their own indexes in later work.
Webhook destinations are empty. Their configuration UI is also later work.
Use the [Firestrategy handover](FIRESTRATEGY-HANDOVER.md) to plan application
integration from this accepted pipe.

Foundation sends the original Compact V2 frames and native Bank controls.
The separate Hetzner consumer checks the frames, saves a bounded replay window,
and supplies compact-only SSE views. The Mac connects to Hetzner through SSH.
Full JSON block, signature and update views return HTTP 409 in this mode.

```text
Foundation native producer
  → private raw stream over restricted SSH
Hetzner blockzilla-client-pipe.service
  → SSE through the owner's SSH tunnel
Mac blockzilla-stream client
```

## Mac access

The installed commands are:

```sh
~/.local/bin/blockzilla-stream status
~/.local/bin/blockzilla-stream blockhashes
```

For original compact blocks, use the explicit compact projection:

```sh
curl --no-buffer --fail-with-body \
  --config "$HOME/.local/share/blockzilla/hetzner-stream/curl-read.conf" \
  'http://127.0.0.1:18890/v1/blocks?projection=compact'
```

The CLI's full-block and signature commands apply to full-mode services. They
are unavailable on this compact-only service. Stop a reader with Ctrl-C. The
command does not create a local block archive.

The local endpoint is `http://127.0.0.1:18890`. The LaunchAgent
`dev.blockzilla.hetzner-stream-tunnel` starts the private SSH tunnel at login
and retries tunnel failures. The Mac must be awake and connected.
The API also listens only on `127.0.0.1:18890` on Hetzner.

The reader token is in the private directory
`~/.local/share/blockzilla/hetzner-stream/`. The installed command reads it
from a file and sends it in the Authorization header. It does not put the
token in a URL or command argument. Keep this directory private.

## SSE views and restart

| Route | Purpose | Replay |
| --- | --- | --- |
| `/v1/head` | Input health, source identity and current signing readiness | Status only |
| `/v1/blockhashes` | Current usable signing hash and expiry | No |
| `/v1/blockhash-observations` | Saved native confirmation and root observations | Yes |
| `/v1/blocks?projection=compact` | Original Compact V2 frame as base64 and native controls | Yes |
| `/v1/signatures` | Full mode only; current service returns HTTP 409 | Unavailable |
| `/v1/blocks` | Full JSON mode only; current service returns HTTP 409 | Unavailable |
| `/v1/updates` | Full mode only; current service returns HTTP 409 | Unavailable |

For replay, save the SSE `id` after your application commits the event.
Send that value in `Last-Event-ID` on the next request. The installed command
also accepts `--after OUTPUT_CURSOR`. The short CLI does not save an
application cursor or reconnect automatically. The application must do this.
The SSH tunnel and the Hetzner input connection have their own reconnect logic.

Output cursors and native `sourceCursor` values are different. Replay uses the
output cursor. An expired range returns HTTP 410, or an SSE gap followed by
connection close if the range expires during delivery. A client must handle
that gap. It must not silently treat a new head as continuous history.
Replay is bounded by 128 MiB or 8,192 events, not by a fixed time.

The current blockhash view does not replay old signing hashes or assign a
durable SSE ID. It includes the native source cursor in the data. It emits
status when the native selection or input is unsafe. Use the observation
route for historical blockhash events. The observation route does not prove
current signing readiness.

Block payload bytes, native event/fork state and input/output cursors are saved
in one SQLite transaction with `synchronous=FULL`. A consumer restart resumes the
saved input cursor. `--join-head` applies only to an empty database. Source,
runtime generation, producer generation and frame/object hashes are checked.
An expired input cursor or changed source gives an explicit readiness failure.
The HTTP status endpoint remains available for diagnosis. A Foundation
generation change requires an explicit operator transition; the consumer
does not silently join a new source.

## Worker recovery configuration

Automatic Worker recovery is enabled on the live compact-only consumer as of
22 November 2026. Its accepted release is
`00631e8678ad3f86afadc698d316e19404222efccb2ef1a477f735704b2b67eb`.
During the update it recovered eight blocks and sixteen original controls,
then resumed the raw stream on the same database. The separate disconnect
test recovered fifteen blocks with zero gaps or duplicates. See the
[recovery acceptance](../../reports/stream-worker-recovery-20261122/README.md).
The live block view is `/v1/blocks?projection=compact`; full JSON, signatures
and update views remain unavailable in this storage mode.

The raw SSH input can use the public Worker after a disconnect and when it
starts with a saved cursor. Configure both arguments:

```text
--recovery-worker-url https://getblock.blockzilla.dev/
--recovery-worker-api-key-file /etc/blockzilla-client-pipe/worker-api-key
```

The API key file must be a regular file owned by the service user. On Unix,
its mode must be `0600` or more restrictive. Links and shared files are rejected.
The API key is sent only to the configured Worker. The Foundation origin key
stays on Foundation.

Recovery first saves one exact target from the pinned native head. It reads
bounded metadata batches after the last committed input cursor. Missing block
frames come from the Worker's `.compact` route. Original Bank controls come
from the same Foundation metadata read. Each frame must pass source, Bank,
cursor, frame hash and object hash checks before the normal store transaction
can commit it. The native event sequence must increase by exactly one.

A failed read retries from the last committed cursor. Once the fixed target
is committed, the raw stream resumes from that cursor. Repeated delivery of
the last committed frame does not create another output event or payload.
Recovery uses the existing compact payload table; it has no second block
store, new archive object or new per-block index. Signing readiness stays
false during recovery.

An expired native window, changed source, wrong hash or archive Wincode reply
stops recovery with an explicit error. An archive block cannot supply missing
processed Bank controls or a native cursor. Recovery does not claim continuity
across such a gap.

`/v1/head` reports `workerRecovery` with the active state, fixed cursor range,
committed block and control counts, completed windows and failed attempts.
These counters start at zero for each process. The saved SQLite cursor remains
the durable recovery boundary. Check the current deployment receipt before
you assume that a running service has this optional configuration.

## Services, storage and authentication

Hetzner is `188.245.147.127`. The enabled service is
`blockzilla-client-pipe.service`, under the `blockzilla-pipe` user.
Its immutable executable and private configuration are under
`/opt/blockzilla-client-pipe-20261122/` and
`/etc/blockzilla-client-pipe/`.

The database is `/var/lib/blockzilla-client-pipe/client.sqlite` inside a new,
fully allocated 512 MiB ext4 image. It has a 320 MiB database budget, a
128 MiB / 8,192-event replay window and a 64 MiB free-space reserve. Admission
also allows for the next write. The image bounds database, WAL and temporary
file growth. A root-filesystem reserve was checked before installation.
Only this service's replay copies are retired.

The service has a 2 GiB memory high limit, a 3 GiB memory maximum, no swap,
two CPU cores of quota, four SSE connections and one shared response renderer.
The existing six application containers were kept running.

The Mac has a separate reader token. It can read the API but cannot make
management requests. The admin token stays on Hetzner. Missing or incorrect
tokens are rejected. Query-string tokens are rejected.

The Hetzner source key is restricted to the reviewed read adapter on
Foundation. It cannot start a shell or forward ports. Strict host key checking
is enabled in both SSH connections. The source private key stays on Hetzner;
the origin token stays on Foundation. No new public network port is opened.

Foundation remains a raw producer. This input mode does not post consumer ACKs,
poll archive coverage or write a webhook queue on Foundation. It reads the
pinned native head when needed to check its local state. The sidecar on
Foundation stays disabled. The validator was not restarted or reloaded.

## Earlier full-mode acceptance and current limits

The earlier full-mode release passed 45 sidecar tests, 34 SDK tests and one retained native frame
test. The real Mac test received 96 blockhash updates, 289 signature events
and 250 full block/control events. All 250 shared events agreed on signatures
and execution outcomes. Full frame and compact object hashes passed.

A restart of only the Hetzner consumer recovered and replayed the exact next
SSE positions in 2.905 seconds. The independent 120-second host check passed
25 of 25 samples. The later host check confirmed the same Foundation validator
PID, invocation and zero restarts, and the same six application containers.

These tests establish this private live path. They do not establish full
historical coverage, application index integration or public HTTPS access.
The new three-host path has no clock-corrected one-way latency measurement.
The old direct Mac reader and its clock task are disabled; their cursors are
preserved.

These full-mode counts are historical. Read the included
[current recovery acceptance](../../reports/stream-worker-recovery-20261122/README.md)
for the compact-only release, source pins and test receipts.
