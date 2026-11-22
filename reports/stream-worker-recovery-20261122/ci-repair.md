# CI repair record

The initial CI repair retains runtime behavior and the six existing CI jobs.
It adds a separate recovery job. The following changes repair checks that
blocked this branch and the previous main revision. No live service was changed.

| File | Change | Local check |
| --- | --- | --- |
| `.github/workflows/ci.yml` | Add SDK, consumer and resolver checks, gateway and activation tests, and the secret-policy regression. Keep all previous checks and the full history scan. | YAML structure and preserved-job comparison |
| `.gitleaks.toml` | Add exact-path and field/value exceptions for reviewed public metadata. Keep default credential rules. | Full history: 733 commits, zero findings |
| `scripts/test_gitleaks_policy.py` | Generate temporary metadata and credential fixtures; never print credential values. | 15 metadata cases, 16 adjacent/outside-path detections, 15 wrong-format detections |
| `scripts/check-archive-v2-wire-boundary.sh` | Record the moved existing Worker dispatch and two test-only message inspections. Keep exact path/count enforcement. | Boundary check passes |
| `docs/architecture/hivezilla-validator-tunnel.md` | Link to the committed access example. | Offline link scan |
| `docs/design/get-block-serving-index.md` | Link to the two included historical receipts. | Offline link scan |
| `edgezilla/get-block/src/lib.rs` | Rustfmt 1.98.1 only. | Workspace format check |
| `edgezilla/get-block/src/worker.rs` | Rustfmt 1.98.1 only. | Workspace format check |
| `edgezilla/get-block/src/worker/foundation_first/recent.rs` | Rustfmt 1.98.1 only. | Workspace format check |
| `edgezilla/get-block/src/worker/recent_recovery.rs` | Rustfmt 1.98.1 only. | Workspace format check |
| `edgezilla/get-block/src/worker/resolution.rs` | Rustfmt 1.98.1 only. | Workspace format check |
| `hivezilla/direct-agave/src/processed.rs` | Rustfmt 1.98.1 only. | Standalone format check |
| `hivezilla/stream-relay/src/publisher.rs` | Rustfmt 1.98.1 only. | Standalone format check |
| `hivezilla/stream-relay/src/server.rs` | Rustfmt 1.98.1 only. | Standalone format check |

The full offline Markdown scan checked 1,601 links with zero errors. The
workspace and all eight standalone format checks passed. The gateway's 41
tests and the activation tool's seven tests passed. The workspace target
migration helper's six tests passed. Final GitHub checks are recorded on PR #89.

The reviewed secret-scan findings were source SHA-256 inventories, deterministic
job hashes, hashes of object names, public Worker version IDs and one literal
JSON property name. No credential finding was suppressed. Rules use exact
paths, the existing generic rule ID and anchored match/value syntax. Adjacent
credential fields on the same JSON line remain detectable.

## Linux runner follow-up

| File | Change | Validation |
| --- | --- | --- |
| `.github/workflows/ci.yml` | Install Ripgrep before the archive boundary check. | The Linux job log showed the missing command; all previous checks stay enabled. |
| `scripts/check-archive-v2-wire-boundary.sh` | Fail with a clear message if Ripgrep is missing. | Local exact path/count check passes. |
| `scripts/test_gitleaks_policy.py` | Use runtime-generated, fixed-entropy values that cannot contain default Gitleaks stopwords. Require the generic credential rule in negative cases. | Eight fresh fixture runs passed; the full committed-history scan found zero findings. |
| `hivezilla/stream-relay/examples/rust-consumer/Cargo.lock` | Record the already present decoder as a dependency of the stream crate. | Locked resolution passes; no package version changes. |
| `hivezilla/stream-sidecar/src/uds.rs` | Keep a duplicate listener FD through guard cleanup, so Linux cannot reuse the old socket inode. Strengthen the replacement test. | Format check passes; Linux CI tests the updated guard. |

The socket cleanup defect was found by the new recovery CI job. The fix keeps
owner, permission and lock checks. It adds one FD at listener startup and no
per-block work or block copy.

Extra local Rust builds exhausted local disk space before the new socket and
example tests ran. Those builds were stopped and only this task's generated
worktree target was removed. Source and shared caches were preserved. The
updated PR must pass the Linux jobs before merge.

## Archive compatibility and lock follow-up

Run `45044815324` passed the stream, recovery, Worker, Hivezilla operations,
documentation and secret checks. This includes the updated socket guard and
locked consumer example. The Rust workspace check found 26 archive
reprocessor failures with the new optional consensus fields and one archive
repair lock failure. These checks were not removed or disabled.

| File | Change | Validation |
| --- | --- | --- |
| `blockzilla/cli/src/archive_v2/registry_reprocess.rs` | Read the optional consensus tail with strict bounds and keep it during rewrites. Check the current prefix against the external block index before selecting it. Reject a damaged tail after an index-valid current prefix without older-schema fallback. | Add old/new format, field preservation, index validation and malformed-tail regressions; Linux CI must pass before merge. |
| `blockzilla/cli/src/archive_verify.rs` | Explicitly release the migration lock when its owner ends, including post-lock validation errors. Keep permission, identity and contention checks. | Add a duplicate-FD regression that also checks successor lock protection; Linux CI must pass before merge. |

The workspace format check and exact archive wire-boundary check passed.
The new Rust tests were not built locally; the Linux CI result is required.

These old formats have no outer-schema tag. An empty old shredding block can
have the same bytes as a current block with an incomplete consensus tail.
Once the current prefix matches the external index, reject a damaged tail.
The ambiguity test records this limit. Unambiguous legacy fallbacks remain
covered; this is not a claim that every old byte sequence is accepted.

Run `45047387624` passed the six other jobs again. Its CLI test program
passed 666 tests, including the former 27 failures and the new footer and
lock tests. One existing legacy test then exposed a false current-prefix
match. An empty old shredding list was read as no rewards, and its actual
rewards tag was read as one transaction, while the external index required
three. The follow-up checks slot, transaction count, row count and signature
sum before reading the tail. An index mismatch can use an exact legacy
decoder; a matching current prefix with a damaged tail still cannot. The
existing legacy regression also checks pass-1 analysis.

The lock failure is consistent with a parallel fork retaining a duplicate
open file description. This cause is an inference from the failing test and
the [Linux lock contract](https://man7.org/linux/man-pages/man2/flock.2.html).
The new test covers that lock lifetime directly. No heavy local build was
started for this follow-up.
