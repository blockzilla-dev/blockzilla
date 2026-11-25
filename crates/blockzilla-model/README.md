# blockzilla-model

`blockzilla-model` defines the common ordered block and transaction records.
It contains no archive decoder. A format adapter validates its source and
converts records to these types. Applications can then use one callback API
without importing format-specific transaction types.

Start with the [reader SDK](../reader/blockzilla-read-sdk/README.md) and the
[small archive examples](../../examples/README.md). Compact V2 support stays in
this repository. CAR adapters live in
[old-faithful-tools](https://github.com/blockzilla-dev/old-faithful-tools).
Application indexers and their retained V3 adapter live in
[blockzilla-indexers](https://github.com/blockzilla-dev/blockzilla-indexers).
Archive V3 development remains on the separate
[`codex/archive-v3` branch](https://github.com/blockzilla-dev/blockzilla/tree/codex/archive-v3).

The block callback includes empty blocks to give an application a checkpoint
boundary. A transaction callback is also available for simple queries.
`IndexedTokenSink` keeps compact account references in flat token-balance
rows. Its `AccountResolver` resolves a public key when a sink needs it.
The Compact V2 indexed scan implements this interface; other adapters can use
resolved common records.

This model does not make an application restart-safe. The application must
commit its output and source checkpoint together, preserve source identity,
and check coverage. Live forks and finalized archive data have different
control requirements. The combined live and archive example remains a target.
