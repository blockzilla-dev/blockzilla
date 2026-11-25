# Agave compatibility record

Reviewed: 25 November 2026.

This register records why each Agave change is required and the checks needed
before its removal. Read it before every Agave upgrade. The [manifest](manifest.json)
identifies source files and regression tests by repository and path.

## Repository boundary

The [Agave fork](https://github.com/blockzilla-dev/agave)
owns validator source, patch implementation, and Agave regression tests.
Blockzilla contains this compatibility metadata and its own client, format,
and integration tests. Do not copy Agave patches or patched validator source
into the final Blockzilla tree.

The imported native changes are committed as
[`5ae64ceb26f78c6e7a6b78932627e5978521c0ae`](https://github.com/blockzilla-dev/agave/commit/5ae64ceb26f78c6e7a6b78932627e5978521c0ae).
The native integration profile is on `main`; the separate RC1 ledger profile is
on `codex/ledger-read-v4.4.0-rc.1`. The manifest records their source identities.
Publication is not a new host build, plugin load, or deployment acceptance.

Historical patch bundle hashes remain in the manifest. Their bytes and the
long deployment records belong to the private repository. The [accepted host
record](https://github.com/blockzilla-dev/blockzilla-private/blob/main/records/.codex/reports/car-epochs-1056-1057/hybrid-1056-20261119/native-deploy-20261121/FINAL-REPORT.md)
records the earlier deployment. The private migration archive preserves the
original source bundles; do not apply those older bundles again on top of the
combined fork.

## Recorded host identity

The last recorded accepted host derives from official Agave 4.4.0 at
`9ef63128134af559561f6a91a641ec01e665c70d`, then the native-hooks fork commit
`10d5b0c72511750d4349824ec5816bd67526a803`, then the native bridge changes.
The accepted prepared source SHA-256 is
`251b5d923155da2673dadaeed777994cbfe2f5176b33948d19b608be94686b6d`.
The host and matching plugin used Rust 1.98.0. A prepared source hash is not a
Git commit, and a recorded deployment is not a current machine-health check.

The stock comparison used Agave 4.4.1 and Geyser interface 5.0.0. Two isolated
interface tests passed for Bank-specific status and block metadata callbacks.
That is not a full validator test or a deployed replacement.

## Required behavior

| ID | Why it exists | When it can leave |
| --- | --- | --- |
| `native-bank-state` | Supplies exact Bank/parent identity, native blockhash expiry, and actual confirmation. A processed or frozen Bank alone does not prove confirmation. | The selected upstream release supplies the same native values and passes the tuple, delayed-confirmation, and host-load checks. |
| `bank-dead-id` | Identifies which Bank failed when multiple Banks use one slot. Slot-only failure can invalidate the wrong branch. | The selected release includes the fix and passes same-slot Bank and descendant-invalidation checks. |
| `rpc-independent-observer` | Keeps native observations and execution-history storage available when RPC listeners are disabled. | Stock initialization supplies the same ordered events and metadata without RPC or a mandatory plugin. |
| `native-read-completeness` | Provides exact-Bank account reads and complete finalized ledger reads through Agave-owned handles. Completion records and cleanup guards reject partial or changed data. | An equivalent read path passes the account, ledger, cleanup, and restart checks, or the owner retires this API after its callers migrate. |
| `raw-shred-tap` | Records original ingress packets and accepted-repair observations for an explicit recovery policy. | Hivezilla no longer needs these observations, or a replacement proves the same packet and loss behavior. The compact block stream does not require this hook. |

The manifest points directly to the corresponding fork source and named tests.
`native-read-completeness` includes the transaction-count snapshot before
asynchronous Bank squash, marker invalidation on later writes, marker cleanup
on purge, and publication only after metadata and rewards are stored. Preserve
these parts together until the read contract has a checked replacement.

Raw-shred capture remains a Hivezilla infrastructure concern. Its external
producer/recorder tests remain in that repository; the Agave receive-hook
implementation remains in the fork. Do not remove an active recovery dependency
because Blockzilla does not consume it.

## Upstream status at review

- [Agave PR 16156](https://github.com/anza-xyz/agave/pull/16156) merged the Bank ID
  on `Dead` notifications into master on 4 November 2026. The reviewed 4.4.1
  release still has the older dispatch. A master merge is not release coverage.
- [Agave PR 16978](https://github.com/anza-xyz/agave/pull/16978) was open at this
  review. Its related local-leader notification work was not an established
  replacement for the complete observer/read contract.
- Stock Geyser 5.0.0 supplies Bank IDs for transactions, entries, block metadata,
  and ordinary Bank status. Reuse those callbacks. It does not expose the
  required native expiry callback.

Recheck upstream status at the next upgrade. Follow Agave's
[contribution rules](https://github.com/anza-xyz/agave/blob/master/CONTRIBUTING.md)
when proposing a small general fix.

## Upgrade and removal procedure

1. Select one upstream release and record its exact commit, SDK/interface
   version, and Rust compiler. Review each required behavior, including fixes
   merged upstream but absent from the selected release.
2. Check the Agave fork commit and source identity. Prepare changes inside that
   repository. A successful patch application is not proof of equivalent behavior.
3. Run the manifest's regression tests against each proposed replacement.
   Check same-slot forks, delayed confirmation, native expiry, incomplete
   metadata, cleanup races, and interrupted recovery where required.
4. Build host and plugin with the same compiler and interface. Run the actual
   plugin-manager load check. Keep RPC disabled when that is part of the contract.
5. Run the real compact writer, restart, and stream cursor/control checks.
   Keep the live-plus-archive token dump as the product acceptance goal. The
   interface-only checks do not establish that goal.
6. Record keep, port, replace, or remove for each group, with the exact commit,
   test results, measured impact, and external evidence location. Preserve a
   tested previous release for rollback.

An empty test-name array means the manifest selects all tests in the named
file. It never means that no tests are required. Build and deployment tools
live in the external Hivezilla repository. This record does not authorize a
live upgrade or certify a new host/plugin pair.

## Ledger-read profile

The ledger helper keeps the exact Agave RC1 API in the separate fork branch
[`codex/ledger-read-v4.4.0-rc.1`](https://github.com/blockzilla-dev/agave/tree/codex/ledger-read-v4.4.0-rc.1). Its optional file-cache cap, implementation
and tests are in that fork. The helper uses the sibling `agave-ledger` worktree.
Use the [fork checkout](#fork-checkout) below to create that worktree. This does not change the native-validator profile or deploy a
new host.

The source default for native capture follows newer main at Agave `a2033000`
(interface 4.3.2). Recorded deployed 4.4.0 evidence remains historical; run the
matched host/plugin check for whichever profile is selected next.

## Fork checkout

The core builds alone. The optional ledger reader needs the private Agave
repository beside the core and a separate worktree for its exact RC1 profile.
From one parent directory:

```sh
git clone --branch codex/1.0-core https://github.com/blockzilla-dev/blockzilla.git blockzilla
git clone git@github.com:blockzilla-dev/agave.git agave
git -C agave worktree add --detach ../agave-ledger origin/codex/ledger-read-v4.4.0-rc.1
```

The `agave` checkout uses the native integration profile on `main`. The
`agave-ledger` worktree uses the ledger profile. The other private repositories
have their own checkout instructions and use the same sibling directory layout.
