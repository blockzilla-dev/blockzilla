# Small archive examples

Run one example with a local Compact V2 epoch directory, `--epoch`, and an
immutable `--source-id`. `--key` selects a mint, required signer, or program.
For example:

```sh
cargo run -p blockzilla-dump-examples --bin wallet-dump -- /data/epoch-900 --epoch 900 --source-id my-generation --key WALLET
```

`wallet-dump` reports transactions signed by the selected wallet. It does not
claim all transactions that affect the wallet. `program-dump` includes recorded
outer and inner calls and requires complete CPI coverage. `token-dump` reports
recorded balance rows; it does not claim a complete current account snapshot.

These are archive examples. The live plus archive backfill acceptance case
remains a separate target; these commands do not implement it yet.

Token rows with unavailable mint identity remain visible as null, even when a
mint filter is selected. They are not treated as confirmed non-matches.
