# CI repair record

PR #89 retains the existing runtime behavior and the six existing CI jobs.
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
