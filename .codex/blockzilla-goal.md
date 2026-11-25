# Current Blockzilla goal

Updated: 25 November 2026. The owner approved this repository split.

## Core boundary

Keep Compact V2 formats and production, archive tools, reader SDKs, getBlock,
Zillastream and three small dump examples in Blockzilla. Zillastream remains
inside this repository so live and archive data share one reader and model.
Keep small runnable sample-block benchmarks and fixtures. Full research,
benchmark results, reports and operational history are in the private records
repository. Previous goal history is preserved there.

## Separate repositories

- zillanode: application service, configurable indexing, hooks and dashboard;
  full and relay-only modes are targets. Reuse the core stream implementation.
- zilla-runtime: existing replay experiments, native execution, account changes
  and epoch snapshots. Full historical state parity is not yet established.
- hivezilla: internal archive resilience, scheduling, replication and recovery.
- agave: the validator fork, all native patches and host regression tests.
- old-faithful-tools: CAR readers, import tools, legacy adapters and CAR benchmark.
- blockzilla-indexers: specialized indexes, query applications and audits.
- blockzilla-private: full documents, research and dated evidence.

The local extraction repositories are under the sibling
`blockzilla-repositories` directory. No new remote repository or deployment has
been created by this cleanup. Agave compatibility notes stay here; patch code
must not be copied into core.

## Branches

`codex/archive-v3` preserves the V3 source at 26ffb7f0. Its package suites passed
368 tests before extraction. The new lean candidate is separate from the
original dirty cleanup checkout. The original work and a complete source
archive are preserved. Do not promote a branch to main before review and the
required integration checks.

## Acceptance target

Start a token dump live immediately while archive backfill runs. Pin exact
source identities and a common finalized boundary. Reconcile overlap, preserve
forks and failures, and commit output with both checkpoints. Restart must not
lose or duplicate accepted rows. Archive gaps and expired native history remain
explicit. The existing archive examples do not yet implement this whole target.

## Runtime target

Replay trusted signed transactions from correct genesis or a checked snapshot
with historical program and runtime rules. Skip repeated signature/PoH checks,
but preserve state-affecting execution rules and prove native/unmetered output
against a matching reference. Current experiments use some archived outcomes
and balances; they are not independent full-chain replay. Produce complete
account changes and restartable epoch snapshots only after parity checks.

## Extraction checks

The lean candidate is prepared on `codex/1.0-core`, separate from the original
`codex/1.0-cleanup` working tree. The full core workspace and all targets passed
813 tests, with four pre-existing ignored tests. The native builder CLI passed
its 17 unit tests, including processed/rooted source checks and interrupted
build handling. Earlier component checks passed 58 relay Rust tests (three
ignored), 25 JavaScript SDK tests and 14 publisher tests. The copied source
codec tests also passed before extraction.

The fixed Compact V2 sample preserves 2,969 transactions and 3,035 signatures
from its source CAR, with matching reconstructed signed bytes. It is a checked
benchmark input, not proof of chain-wide coverage. No live validator, public
service, remote repository or default branch was changed by this work.
Linux worker, host/plugin and combined live/backfill acceptance remain required
before promotion to main.
