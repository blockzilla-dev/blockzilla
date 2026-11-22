# Blockzilla bank client

## Persistent Mac client through SSH

Build the native receipt client with an existing target directory:

```sh
CARGO_TARGET_DIR=/path/to/existing/target cargo +stable build \
  --manifest-path crates/blockzilla-bank-client/Cargo.toml \
  --release --locked --bin blockzilla-beam
```

The client starts `/usr/bin/ssh` with strict host-key checks and the existing
SSH identity. The origin credential stays on Foundation. No TCP listener or
origin credential is installed on the Mac. Root must supply an explicit source
file, runtime and producer generation, and initial cursor:

```sh
/path/to/existing/target/release/blockzilla-beam \
  --ssh-host ubuntu@213.239.141.61 \
  --ssh-helper /home/ubuntu/live/hivezilla-validator-20260930/releases/native-ssh-beam-20261122-ba58e62fce451cf1/beam_ssh_gateway.py \
  --job /home/ubuntu/live/hivezilla-validator-20260930/jobs/native-continuous-20261121 \
  --source-file /private/client/SOURCE.json \
  --generation RUNTIME_HEX32 --producer-generation PRODUCER_HEX64 \
  --after EXACT_INITIAL_CURSOR \
  --state /private/client/cursor.json --status-file /private/client/status.json \
  --clock-file /private/client/clock.json --stop-file /private/client/STOP
```

The local output directory must be owned by the current user with mode `0700`.
Checkpoint and status files use mode `0600`. A file lock permits only one writer.
The first start requires `--after`. Later starts use the durable complete cursor.
If the same `--after` argument remains in a service definition, it must match the
stored original boundary; it never replaces the current checkpoint.

Each complete frame passes source, generation, sequence, frame and object hash
checks before its receipt cursor and counters are atomically saved and synced.
Partial SSH frames never advance that boundary. Transient failures reconnect
from the saved cursor with a backoff capped at five seconds. Expired cursors,
changed sources or generations, authentication failures and invalid frames save
a terminal status and exit with code zero. This lets a LaunchAgent configured
with `KeepAlive/SuccessfulExit=false` stop for an explicit operator decision.
The client never chooses a replacement source or current-head cursor.

Status is atomically overwritten once per second; stdout remains quiet. It
contains the current slot, receipt age, counters, rates, SSH PID, exact reconnect
boundary and first sequence after each connection. It keeps at most 4,096
latency samples for a 60-second window. It saves no block bytes, projection,
archive or remote ACK. Native control frames remain in the stream; receipt of a
processed block is not a claim that the block is finalized.

Optional clock calibration has integer millisecond fields
`server_minus_client_ms`, `uncertainty_ms`, `sampled_at_client_unix_ms` and
`valid_for_ms`. Extra diagnostic fields are accepted. Corrected latency equals
Mac receipt time minus the native observation time plus the server-minus-client
offset. Missing or stale calibration leaves corrected latency unavailable.
Initial in-flight samples from before the client starts are reported separately.
The native timestamp is set in the frozen-notification handler; the earlier
execution-to-observer queue delay is not measured. The client records receipt
after complete hash checks, before the local checkpoint sync.

There is no default lifetime limit. `--max-seconds N` gives a bounded test run.
Ctrl-C, SIGTERM or the stop file closes SSH and saves a final `STOPPED` status.
Remove the stop file before an explicit restart.

## Direct binary beam

`BankClient::beam(&exact_cursor)` reads `/v2/banks/beam` through the configured
HTTPS or private Unix transport. It returns the original Compact V2 frames in
order, including native confirmation, root and invalidation controls. Each
frame retains its existing `BZSTRM01` length header. HTTP chunks do not define
frame boundaries. Source, frame/object hashes, bounds and consecutive sequence
are checked before delivery. No transaction JSON, application database, outbox
or consumer ACK is used. The application can decode selected frames separately.

`BeamStream::cursor()` is the last complete received transport position. It is
not an application commit or archive receipt. Cancelled reads retain the partial
frame. Reconnect explicitly from the last complete position that the application
can safely repeat. Producer-owned rolling retention can discard old positions;
HTTP410 is an explicit gap, never an automatic jump to the current head. A
mid-response expiry closes the response, so reconnect must recheck that exact
position. Blockhash usability and canonical chain state require a separate
consumer of the native controls; raw transport alone does not prove them.

## Worker recovery after a disconnect

The live raw input in `blockzilla-stream-sidecar` uses these APIs automatically.
The `blockzilla-beam` receipt CLI above still uses raw SSH replay. See the
[consumer guide](../../hivezilla/stream-sidecar/HETZNER-PIPE.md) and the
[accepted recovery tests](../../reports/stream-worker-recovery-20261122/README.md).

`WorkerRecoveryClient` reads exact missing block frames through
`GET /block/{slot}.compact`. Configure its HTTPS base URL, customer API key and
the same pinned `SourceIdentity` as the stream. Keep the client between
disconnects so that it can reuse its HTTP connection pool. Healthy raw stream
reads do not call the Worker.

After a transport failure, sample the native head once. Keep that exact cursor
as the recovery target. Call `SshConfig::recovery_plan(after, until, 128)` with
the durable application cursor and that fixed target. The installed SSH helper
must support `recovery-plan`. Each finite page contains consecutive native
event metadata and the exact original small control frames. Block entries
contain no payload bytes. The plan reads the existing native feed database; it
does not need another block index or payload store.

For each entry, check `entry.notice.validate(source, durable_cursor)`. Use the
inline `entry.control` when present. For a block, call
`worker.fetch(&entry.notice)`. Then check `notice.validate_frame(&frame)` and
commit the frame, application effects and cursor in the same database
transaction. Repeat pages until the fixed target is committed. Open the raw
stream again from that exact durable cursor. A retry starts from the last
committed cursor; it must discard uncommitted page entries.

Worker reads check the full frame SHA-256, each compact object hash, complete
native event, source, cursor, Bank ID, blockhash, parent slot and parent hash.
They reject partial bodies, changed metadata and archive representations.
Partial network failures retry the same identity within a bounded deadline.
Expiry, wrong identities, corrupt frames and authentication failures stop
recovery. They never select the current head or invent controls from R2.
The application remains responsible for its chain and transaction checks.

The plan is limited to 128 events, 64 KiB per line and 4 MiB total. The client
also reserves the maximum header line from that total. It accepts a plan only
after complete EOF and successful helper exit. Two finite SSH reads and two
Worker reads can run at once. Received block bytes stay in the existing
application storage path; recovery adds no persistent block copy.

The `worker_recovery_probe` example tests an isolated reader. It reads three
frames, closes only its own SSH connection, waits two seconds, recovers through
the Worker, then checks six raw frames after resume. It uses `ClientState`,
checks every sequence and rejects duplicate cursors. Payloads stay in RAM.
Its JSON result contains only identities, hashes and counts.

```sh
cargo +stable run --manifest-path crates/blockzilla-bank-client/Cargo.toml \
  --release --locked --example worker_recovery_probe -- \
  --config /private/probe/config.json
```

The configuration and API-key files must be owned by the current user with
mode `0600`. The JSON configuration has these fields:

```json
{
  "host": "private-foundation-alias",
  "helper": "/remote/beam_ssh_gateway.py",
  "job": "/remote/native-job",
  "generation": "RUNTIME_HEX32",
  "producer_generation": "PRODUCER_HEX64",
  "source": {
    "genesis_hash": "PINNED_GENESIS",
    "node_identity": "PINNED_NODE",
    "agave_revision": "PINNED_REVISION",
    "session_id": "PINNED_SESSION"
  },
  "worker_url": "https://getblock.blockzilla.dev/",
  "worker_api_key_file": "/private/probe/worker-key.txt"
}
```

This Rust library reads the opt-in `native-bank-compact-v2` backend feed. It
uses the shared strict v2 contract. It does not link Agave, Hivezilla relay
services, or a transaction decoder. The crate is private and is not on crates.io.

The public demo is a different, processed blockhash feed. Use a backend Bearer
key and an operator-supplied `SourceIdentity` for this client. Keep the key in a
private file or server secret. The client requires an HTTPS base URL, rejects URL
credentials and query parameters, and does not follow redirects.

## Application contract

```rust,ignore
use blockzilla_bank_client::{BankClient, ClientConfig, StreamEvent};

let client = BankClient::new(ClientConfig::new(url, private_key, pinned_source))?;
let bootstrap = client.bootstrap(saved_cursor.as_deref()).await?;

// First join: commit the bootstrap boundary and its exact selected bank.
// Resume: retain current-head dependencies as proofs. Do not apply the head
// control ahead of the events at the saved cursor.
commit_bootstrap_dependencies(&bootstrap).await?;
let mut stream = client.connect(bootstrap).await?;

loop {
    match stream.next().await? {
        StreamEvent::Status(head) => update_health(head),
        StreamEvent::Bank(delivery) => {
            let decoded = delivery.decode_with(my_portable_decoder)?;
            // One database transaction: bank data, control, application effects,
            // payload dependencies, and delivery.frame.cursor.
            stream.ack(&delivery.frame.cursor, || async {
                commit_bank_and_cursor(&delivery, decoded).await
            }).await?;
        }
    }
}
```

`bootstrap(None)` explicitly joins the current head. A saved cursor is checked
against the pinned source and replay range. It is never replaced with the head.
The client fetches and checks the exact head control and processed payload.
Commit those dependencies before `connect`. On a saved resume, current-head
proofs do not authorize application effects before ordered replay reaches them.

`next()` returns validated status or bank events in order. Up to four finite GETs
run in parallel by default, including missing control dependency GETs. The bound
can be set from one to sixteen. A background task keeps notice-frame downloads
active while the application applies a delivery. Its channel holds at most that
many items. A fixed 64 MiB budget covers all notice-frame bytes being fetched or
queued; each size is reserved before GET and also limits the response body.
The one consumer frame and its one missing dependency are outside that budget,
each bounded by the protocol frame limit. State changes and dependency lookup
remain ordered on the consumer. Strict notice admission occurs before each
credentialed GET. Every full-frame digest, source, cursor, length, and bank
identity is checked. A `Delivery` includes a missing processed dependency when
the client's metadata state does not already have that payload.

`Delivery::decode_with` is the decoder hook. It receives full frame bytes for the
event and any dependency. The application must check semantic compact data,
signatures, errors, and native block height before it commits or acknowledges.
Use a bounded worker pool for CPU-heavy decoding. The transport alone does not
certify transaction contents.

Only one bank can await acknowledgement. Reading again gives `AwaitingAck`.
An out-of-order ACK gives `AckOrder` and does not call the checkpoint hook. The
hook can perform the atomic application commit, or verify that the caller has
already made it. Only a successful hook advances `stream.cursor()`. A failed
hook stops the stream and preserves the old reconnect boundary. Hooks must be
safe to repeat if the caller cancels the future after a database commit.

`next()` is safe to cancel, including during a control dependency fetch or
reconnect. The stream owns those futures and resumes them on the next call. This
permits a separate timer for application readiness. Dropping the stream cancels
the producer and all pending reads. Recovery also cancels the old producer and
discards its queued frames before reopening from the acknowledged cursor.

## Readiness and recovery

`ready_hash(now_ms)` delegates to the shared `ClientState`. A processed block
cannot supply a confirmed hash. Readiness requires the exact confirmed/root
payload, current health, the applied provider head, and valid source and
selection ages. It is unavailable before the initial SSE status, during pending
application commits, after an I/O failure, or after `force_unavailable()` until a
new validated status arrives. `selected()` exposes the native observation; keep
its bank, hash, context slot, block height, expiry, and time together.

On resume, also require that this observation matches the application's durable
bank projection before serving it. The client's metadata is not an application
snapshot. Persist a fork-aware `Chain`, transaction outcomes, and application
undo separately. Do not write processed candidates into finalized history.

Transient connection/body failures and HTTP 429/5xx retry with bounded backoff.
Reconnect starts at the acknowledged cursor and drops speculative reads. The
default is eight retries, with a 250 ms initial delay and a five-second maximum
delay. Errors remain typed after exhaustion. `ClientError::is_transient()` and
`is_terminal()` let the supervisor choose its next action. Authentication,
source, digest, and protocol errors stop processing. A replay gap stops with a
`Gap` error and optional checked head; it never starts from a new boundary.

Archive recovery, automatic source handoff, complete account bytes, transaction
submission, and wallet watches belong to later or application-specific layers.

## Checks

From this directory:

```sh
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Tests use a local HTTP server with synthetic strict v2 frames. The public
constructor still requires HTTPS. Tests check header authentication, strict
source/notice/frame admission, bounded ordered reads, bootstrap dependencies,
retry/resume, explicit gaps, cancelled reads, durable ACK failure, and processed
hash rejection. These tests do not establish live provider or indexer capacity.

## Local Unix transport and producer ACK

On Unix, `BankClient::new_unix(config, socket_path)` connects only through the
named socket. Set `config.url` to the fixed placeholder `http://localhost/`.
The socket must be an absolute non-symlink socket path of at most 100 bytes.
Requests do not fall back to TCP or a proxy. Authentication and strict Bank
admission are unchanged. `BankClient::new` continues to require remote HTTPS.

`acknowledge_coverage(consumer_id, cursor, coverage_gap_sequence)` sends a
preconfigured consumer's durable checkpoint to `/v2/banks/ack`. Call only after
application effects, cursor and outbox have committed. It checks the exact
source, consumer, cursor and independent gap frontier in the receipt. Identical
retries are idempotent. This is separate from `BankStream::ack`, which advances
the local application boundary. A producer receipt does not certify archive
custody or authorize file removal.

`coverage_gaps(after, producer_generation)` reads source-bound coverage metadata.
IDs are sparse and strictly increasing. A discarded prefix, changed generation,
wrong schema or contradictory sequence is an error. No Bank frame or hash is
fabricated for an incomplete or expired Bank. The generation comes from the
operator, not from an HTTP response.
