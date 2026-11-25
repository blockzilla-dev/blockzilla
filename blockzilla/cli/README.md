# Blockzilla CLI

Read Compact V2 archives and build compact blocks from native Agave capture.
The core command tree contains:

| Command | Purpose |
| --- | --- |
| `stream` | Read an archive epoch as ordered JSON block summaries. |
| `dump-tokens` | Export recorded token balances as JSON Lines. |
| `inspect` | Show an archive's admitted identity and range. |
| `compare-sdk-rpc` | Compare a saved SDK capture with finalized RPC blocks. |
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

## Compare SDK output with RPC

```sh
blockzilla compare-sdk-rpc capture.json \
  --rpc-url http://127.0.0.1:8899 --report comparison.json
```

Save decoded SDK blocks in a JSON document with `program`, `all`,
`programMatches` and `accountMatches` fields. `program` is the address used for
both the program and account filters. The three arrays contain the unfiltered,
program-filtered and account-filtered blocks. All arrays must contain the same
slots, including blocks with no matching transactions.

Each block contains `slot`, `parentSlot`, `blockhash`, `parentBlockhash`,
`transactionCount` and `transactions`. Each transaction contains its original
`index`, primary `signature`, complete `signatures`, `success`,
`topLevelPrograms`, `innerPrograms` and `innerCoverage`. Preserve these decoded
SDK values when you save the capture.

The command makes one finalized `getBlock` request per block. It compares block
and parent identities, transaction count and order, every signature, execution
status, top-level and recorded inner program references, and both filter results
(including loaded addresses). Missing execution or inner-instruction data fails
the comparison. Empty input, duplicate slots and extra filtered slots also fail.

The input and each RPC reply have a 64 MiB limit; a capture can contain at most
1,000 blocks. `--timeout-seconds` sets each request deadline (default: 30). A
matching capture produces a JSON summary on stdout and, if requested, in a new
report file. A mismatch or unavailable RPC block exits with an error and does not
write a successful report. Existing report files are never overwritten.

This compares the SDK projection with the supplied RPC node. It does not verify
cryptographic signatures, certify consensus or establish archive completeness.
