# Native block stream client

Typed client for the retained Bank stream. It pins the complete native source,
producer generation and cursor, validates frames and controls, and reports
expired history explicitly. It does not discover a source, infer finality from
elapsed time, or replace missing frames with archive reconstructions.

Keep source, Bank and frame identity in stored checkpoints. Resume and commit
application effects together. Full protocol details are preserved in the
private integration references; public Rust types and errors are documented
with the code.

## Public HTTPS recovery

Give the stream key to `BankClient` for `https://stream.blockzilla.dev/`.
Create the block reader with
`WorkerRecoveryClient::new_public("https://archive.blockzilla.dev/", source)`,
using the same pinned `SourceIdentity`. This Worker client sends no
Authorization header; the stream key stays with the stream client.

After a disconnect:

1. Read `stream.head()` once and keep its exact cursor as the recovery target.
2. Call `stream.recovery_plan(after, until, 128)` with the latest committed
   cursor and that fixed target.
3. Use the original control frame in each control entry. For a block entry,
   fetch its exact frame with `worker.fetch(&entry.notice)`.
4. Commit each validated frame, application output and cursor together.
5. Repeat from the committed cursor until it equals the target, then call
   `stream.beam(until)` to read the next event.

The plan uses opt-in `recovery=1` notices. Each page has a 128-event limit, a
4 MiB notice and control budget, and a 30-second deadline. A source change,
expired cursor or identity mismatch returns an error. Healthy stream reads do
not call the Worker.

## Private recovery

Use `WorkerRecoveryClient::new` with `WorkerRecoveryConfig` for deployments
that require a separate Worker key. The existing `SshConfig::recovery_plan`
path remains available for a private SSH stream. Both paths keep the same
source, cursor and atomic commit requirements.
