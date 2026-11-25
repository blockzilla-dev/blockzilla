# Blockzilla CLI

Read Compact V2 archives and build compact blocks from native Agave capture.
The core command tree contains:

| Command | Purpose |
| --- | --- |
| `stream` | Read an archive epoch as ordered JSON block summaries. |
| `dump-tokens` | Export recorded token balances as JSON Lines. |
| `inspect` | Show an archive's admitted identity and range. |
| `build-direct-agave-compact` | Build compact blocks from a complete native callback batch. |

```sh
cargo run --locked -p blockzilla -- --help
blockzilla stream --epoch 900 --max-blocks 5
blockzilla dump-tokens --epoch 900 --max-blocks 100 > token-balances.jsonl
blockzilla inspect --epoch 900
```

For a local archive, supply `--archive-dir /absolute/archive/path` and a stable
`--source-id`. The `stream`, `dump-tokens` and `inspect` commands use the same
archive source options. Output goes to stdout; progress goes to stderr.

The native worker uses this unchanged command contract:

```sh
blockzilla build-direct-agave-compact /normalized/input /fresh/output --level 1
```

The builder checks its source receipt, complete block geometry and source
files before publishing its output. It preserves the source session, Bank and
parent identities. Its output does not claim independent consensus, signature
verification, or complete shred evidence. Use the matching native producer and
source revision.

CAR import, migration, scheduler and application indexing commands belong to
their separate tools. Archive integrity and signature checks remain available
through the reader SDK.

The combined live-capture and archive-backfill token example is a product
acceptance target. The current `dump-tokens` command reads archives only.
