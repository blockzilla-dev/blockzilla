# Agave compatibility

This guide records the behavior that an Agave integration must preserve and the
checks required before an upgrade. The [manifest](manifest.json) lists required
regressions and public upstream references. It is not a deployment record.

## Source boundary

The validator source repository owns Agave changes and native regression tests.
Blockzilla owns its client, format and integration tests. Keep Agave patches and
patched validator source outside this repository.

The native plugin's public upstream revision and interface are pinned in
[`zillastream/geyser-plugin/Cargo.toml`](../geyser-plugin/Cargo.toml). The optional
ledger reader uses the API and checkout layout stated in
[`blockzilla/ledger-archive/Cargo.toml`](../../blockzilla/ledger-archive/Cargo.toml).
These are separate source profiles. Neither pin certifies a running host or a
compatible plugin binary.

## Required behavior

| ID | Why it exists | When it can leave |
| --- | --- | --- |
| `native-bank-state` | Supplies exact Bank/parent identity, native blockhash expiry, and actual confirmation. A processed or frozen Bank alone does not prove confirmation. | The selected upstream release supplies the same native values and passes the tuple, delayed-confirmation, and host-load checks. |
| `bank-dead-id` | Identifies which Bank failed when multiple Banks use one slot. Slot-only failure can invalidate the wrong branch. | The selected release includes the fix and passes same-slot Bank and descendant-invalidation checks. |
| `rpc-independent-observer` | Keeps native observations and execution-history storage available when RPC listeners are disabled. | Stock initialization supplies the same ordered events and metadata without RPC or a mandatory plugin. |
| `native-read-completeness` | Provides exact-Bank account reads and complete finalized ledger reads through Agave-owned handles. Completion records and cleanup guards reject partial or changed data. | An equivalent read path passes the account, ledger, cleanup, and restart checks, or all callers migrate away from this API. |
| `read-only-ledger-file-cap` | Bounds the optional read-only RocksDB file cache without changing primary or default behavior. | The selected API provides an equivalent limit and passes default, limit and overflow checks. |

`native-read-completeness` includes the transaction-count snapshot before
asynchronous Bank squash, marker invalidation on later writes, marker cleanup
on purge, and publication only after metadata and rewards are stored. Preserve
these parts together until the read contract has a checked replacement.

Raw-shred capture is a separate integration. The compact block stream does not
require it. If another consumer needs original ingress or accepted-repair
observations, its integration must check packet bytes, duplicate handling,
repair nonce data, bounded queues, explicit loss and unchanged Agave delivery
before that hook can be removed. The manifest retains these removal conditions.

## Public upstream references

The source review recorded in the manifest compared Agave 4.4.1 and Geyser 5.0.0.
It did not establish full validator or host/plugin compatibility.

- [Agave PR 16156](https://github.com/anza-xyz/agave/pull/16156) adds Bank identity
  to `Dead` notifications. Check that the selected release contains the change;
  a merge into the upstream development branch is not release coverage.
- [Agave PR 16978](https://github.com/anza-xyz/agave/pull/16978) concerns related
  local-leader notifications. It does not by itself establish an equivalent
  observer or native-read contract.
- The reviewed Geyser 5.0.0 interface supplies Bank IDs for transactions, entries,
  block metadata and ordinary Bank status. It does not expose the required
  native expiry callback.

Check these references again at each upgrade. Follow Agave's
[contribution rules](https://github.com/anza-xyz/agave/blob/master/CONTRIBUTING.md)
when proposing a general fix.

## Upgrade and removal checks

1. Select one upstream release and record its exact commit, SDK/interface
   version and Rust compiler. Check each required behavior, including fixes
   merged upstream but absent from the selected release.
2. Prepare required changes in the validator source repository. A successful
   patch application is not proof of equivalent behavior.
3. Run the manifest's regression checks against each proposed replacement.
   Check same-slot forks, delayed confirmation, native expiry, incomplete
   metadata, cleanup races and interrupted recovery where required. Entries
   with a path refer to this repository. Other entries specify checks for the
   matched native integration.
4. Build the host and plugin with the same compiler and interface. Run an actual
   plugin-manager load check. Keep RPC disabled when that is part of the contract.
5. Run the real compact writer, restart, and stream cursor/control checks. Run
   the [live-plus-archive acceptance check](../../RELEASE.md#first-stable-release).
   Interface-only tests do not establish that result.
6. Record whether each group is kept, ported, replaced or removed, with its exact
   source revision, test results and measured impact. Keep a tested previous
   release for rollback.

A successful library build alone does not prove host/plugin ABI compatibility.
An empty test-name list never means that no checks are required.
