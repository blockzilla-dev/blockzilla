# Small archive examples

`wallet-dump` and `program-dump` read the same archive.
Token balances use `blockzilla token-dump`.
Omit `--archive-url` on these two commands to read the public Foundation directory for
the selected epoch. Epoch 1094 is
`https://pub-97348740d6ef467aa2f1b4b62daa98dc.r2.dev/compact-v2/blockzilla-20261004/epoch-1094`.
The cache defaults to `.blockzilla-cache` in the current directory.
`--key` selects a required signer or a program.

```sh
blockzilla wallet-dump --epoch 1094 --key WALLET
blockzilla program-dump --epoch 1094 --key PROGRAM
```

The same arguments work through the example binary:

```sh
cargo run --release -p blockzilla-dump-examples --bin wallet-dump -- --epoch 1094 --key WALLET
```

A local epoch directory uses a path instead of `--archive-url`:

```sh
blockzilla wallet-dump /data/epoch-900 --epoch 900 --source-id my-generation --key WALLET
```

For a private S3-compatible bucket, such as Cloudflare R2 through its S3 API,
add `--s3-region` (`auto` for R2) and give the path-style URL. The example
signs each request with SigV4 and reads the credentials from
`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and the optional
`AWS_SESSION_TOKEN`. It never prints them:

```sh
blockzilla wallet-dump --archive-url https://ACCOUNT.r2.cloudflarestorage.com/BUCKET/PREFIX/epoch-200 --s3-region auto --epoch 200 --cache-dir /var/cache/blockzilla --key WALLET
```

`wallet-dump` reports transactions signed by the selected wallet. It does not
claim all transactions that affect the wallet. `program-dump` includes recorded
outer and inner calls and requires complete CPI coverage.

These are archive examples. The live plus archive backfill acceptance case
remains a separate target; these commands do not implement it yet.

## Speed options

- `--first-block N` and `--max-blocks N` select a block-row range. To resume
  after a stop, start at the row after the last complete block.
- `--workers N` sets the parallel decode workers. The default is the number
  of logical CPUs. `--workers 0` selects the sequential reader.
- `--read-concurrency N` reads N block ranges at the same time from a local
  archive. A NAS or disk array needs several (for example 6); local NVMe needs
  1.
- `--http-requests N` and `--http-range-mib N` set the HTTPS input window:
  concurrent range requests and the size of one request. A high-latency store
  needs more bytes in flight. Some public endpoints limit the request rate, so
  measure before you use many small ranges.
- `--stats` prints the scan receipt to standard error, with the time that each
  pipeline stage used.

Output is written with one call per block and is flushed after each block.
Each dump asks the reader only for the facts it prints:

- `wallet-dump` selects one signer (`with_required_signer`), so other signer
  keys are not resolved.
- `program-dump` reads program identities without instruction data or
  accounts (`with_instruction_programs_for`), and reads a signature only for a
  transaction that calls the program (`with_selected_primary_signatures`).
