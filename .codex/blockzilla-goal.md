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

The repositories use the `blockzilla-dev` GitHub organization. The seven new
repositories are private; Blockzilla remains public. Local checkouts use sibling
directory names listed in the root README. Agave compatibility notes stay here;
patch code must not be copied into core. Repository publication does not deploy
a service or approve a validator build.

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

The lean candidate is on `codex/1.0-core`, separate from the original dirty
`codex/1.0-cleanup` working tree. It incorporates the recorded newer main at
`841998ee915ca2ff9dc79d2734756163bc3a8e3e`, including current-epoch getBlock,
stream recovery and consensus marker/footer support.

The final core workspace and all targets passed 822 tests, with four existing
ignored tests. The getBlock Worker also compiles for wasm32-unknown-unknown.
Targeted stream checks passed: bank stream 40, bank client 53, decoder 17,
relay 58, resolver 51, getBlock 71, JavaScript SDK 30 and provider reader 12.
These scopes overlap the full core suite and are not an additive test total.
The exported CAR reader passed 63 tests; runtime compact tests passed 17.

The fixed Compact V2 sample preserves 2,969 transactions and 3,035 signatures
from its source CAR, with matching reconstructed signed bytes. It is a checked
benchmark input, not proof of chain-wide coverage. The repository split does
not change a live validator or public service. The existing Blockzilla `main`
remains unchanged until review and the required integration checks pass.
Linux worker, matched host/plugin and combined live/backfill acceptance remain
required before promotion to main. The separate Agave RC1 ledger profile has
resolved dependency metadata; its full Linux/RocksDB build is still required.
