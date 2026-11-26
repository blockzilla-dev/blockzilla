# Blockzilla CLI

Read Compact V2 archives and build compact blocks from native Agave capture.
The core command tree contains:

| Command | Purpose |
| --- | --- |
| `stream` | Read an archive epoch as ordered JSON block summaries. |
| `token-dump` | Export recorded token balances as JSON Lines. |
| `wallet-dump` | Export transactions that one wallet signed. |
| `program-dump` | Export recorded outer and inner calls of one program. |
| `inspect` | Show an archive's admitted identity and range. |
| `compare-sdk-rpc` | Compare a saved SDK capture with finalized RPC blocks. |
| `build-direct-agave-compact` | Build compact blocks from a complete native callback batch. |

```sh
cargo run --locked -p blockzilla -- --help
blockzilla stream --epoch 900 --max-blocks 5
blockzilla token-dump --epoch 200 --max-blocks 20 --mint EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v > usdc.jsonl
blockzilla token-dump --archive-url https://pub-97348740d6ef467aa2f1b4b62daa98dc.r2.dev/compact-v2/blockzilla-20261004/epoch-1094 --epoch 1094 --mint EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v
blockzilla wallet-dump --epoch 1094 --key WALLET
blockzilla program-dump --epoch 1094 --key PROGRAM
blockzilla inspect --epoch 900
```

`token-dump` uses the same source options as `stream`. With no `--archive-url`,
`--origin`, or `--archive-dir`, it reads the public Foundation directory
`https://pub-97348740d6ef467aa2f1b4b62daa98dc.r2.dev/compact-v2/blockzilla-20261004/epoch-<EPOCH>`.
It writes one JSON line per recorded token balance. Each line includes the
transaction signature. The command stops when execution status or token data
is missing.
`wallet-dump` and `program-dump` take the same arguments as the example
binaries in `examples/`. Omit `--url` to read the public Foundation archive at
`https://pub-97348740d6ef467aa2f1b4b62daa98dc.r2.dev/compact-v2/blockzilla-20261004/epoch-<EPOCH>`.
The cache defaults to `.blockzilla-cache` in the current directory. Give a
local epoch directory instead of `--url` to read a local build. `--key`
selects a required signer or a program. `wallet-dump` and `program-dump`
require `--key`. These commands read archives only.

For a local archive, supply `--archive-dir /absolute/archive/path` and a stable
`--source-id`. The `stream`, `token-dump` and `inspect` commands use the same
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
acceptance target. The current `token-dump` command reads archives only.

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
