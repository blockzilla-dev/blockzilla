# Automatic Worker recovery

For the repository package and fresh checks against the newer upstream code,
see the [publication note](PUBLICATION.md). The deployment results below retain
their original source and artifact identities.

The Worker is available at **https://getblock.blockzilla.dev** with the existing
API keys. Automatic recovery is enabled on the live Hetzner Rust consumer.
The accepted client release is
`00631e8678ad3f86afadc698d316e19404222efccb2ef1a477f735704b2b67eb`.
The Worker keeps version `50aaba11-468b-4c57-b1ad-ddc999ea9152`.

The raw Rust client starts recovery at its last database commit. It samples
one native head and reads a bounded metadata plan from the existing Foundation
feed. Block notices contain the exact source, Bank, event, cursor and frame
hash. They contain no block payload. Original small control frames are included.
The client fetches blocks through the Worker, checks full-frame and object
hashes and all expected identities, then uses the existing atomic frame/cursor
commit. Retries keep the same target. Raw streaming resumes at the committed
target. Normal streaming makes no Worker requests.

No archive object, per-block index, second production database or result cache
was added. The metadata adapter reads the existing SQLite feed in read-only
mode. Recovery pages have at most 128 events and 4 MiB. The HTTP client reuses
one connection pool and retains the original frame bytes.

The live isolated reader recovered **15 blocks and 29 controls** after a deliberate
disconnect. It accepted 53 consecutive events, including three before the
disconnect and six after raw stream resume. It checked all native frame/object
hashes and the original control dependencies. It found zero missing sequences,
zero duplicate events and needed no additional dependency block reads. Payloads
stayed in RAM. The production pipe was not used for this fault.

The gateway passed 41 local tests. Its separate live test checked 23 ordered
metadata entries, including eight block notices without payloads and 15 original
controls. The old restricted helper remained usable. The SDK passed all 53
local tests and compiled both probe examples. Independent review found no
blocking recovery defect.

All **105 Linux tests** passed: 50 SDK tests, 54 regular consumer tests and the
separate automatic disconnect/retry/database-reopen test with an existing real
Compact V2 fixture. The activation tool passed seven focused tests, including
fallback on the same advancing database.

The live update took 5.057 seconds from preparation through acceptance, with one
controlled consumer stop/start. At startup, the production client automatically
recovered **8 blocks and 16 controls**, then resumed raw streaming. Its original
database inode, schema, source, bootstrap boundary and limits stayed fixed.
Both native and output cursors advanced. No database backup, restore or second
production payload store was used. All six application containers and other
running services stayed fixed. Foundation's validator, native workers, reader
and Tunnel kept their process identities. The Mac status command and three
later consumer checks confirmed live compact-only input, signing readiness,
zero recovery failures and zero automatic restarts.

Recovery requires access to Foundation metadata and its retained native window.
Expiry, a changed source or a hash mismatch stops recovery with an explicit
error. Archive blocks do not recreate processed control history. The installed
Mac SSE output client's reconnect behavior is outside this raw input change.

Evidence:

- [Domain checks](domain-check.json) and [domain attachment](domain-attachment.json).
- [Live SDK disconnect and recovery](live-client-recovery.json).
- [Gateway deployment](gateway-deployment.json) and [live metadata check](gateway-live-check.json).
- [Gateway source and test manifest](gateway-source-manifest.json).
- [Final Linux build](linux-final-build.json), [SDK tests](linux-sdk-tests.log),
  [consumer tests](linux-sidecar-tests.log) and [automatic recovery test](linux-automatic-recovery-fixture.log).
- [Consumer activation](consumer-activation.json), [later checks](consumer-final.json)
  and [Mac status](mac-status.json).
- [Native process check](native-after.json) and [Worker version/domain check](worker-final.json).

The release build uses a frozen source closure. It pins the existing deployed
decoder; concurrent wallet feature changes in the working tree are excluded.
The first Linux consumer snapshot caught a close-adapter type error that was
already being fixed. The second was stopped before acceptance to correct the
test control order and pin the deployed decoder. Both records are retained.
Only the complete successful final v3 build was installed. The compiler reports
one non-fatal unused-assignment warning in the input loop. No compile or test
failure remains in the accepted build.
