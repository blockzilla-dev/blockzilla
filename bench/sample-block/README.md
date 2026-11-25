# Compact V2 sample block

Run a small local decode benchmark:

```sh
cargo run --release --locked -p blockzilla-sample-block-bench -- 200
```

The optional argument is the number of iterations. The default is 100.
The command checks the fixture hashes, exact Wincode roundtrip, row counts
and reconstructed signed-transaction digest before it starts the timer.

The two measurements cover:

- Full owned block decode and drop, from bytes already in memory.
- Zstd decompression followed by the same full block decode and drop.

File reads, fixture checks, signed-message reconstruction and source
conversion are outside the timer. Results are printed as JSON. Save results
outside this repository, with the build revision and machine details.

The fixture is one `WincodeArchiveV2Block` record with inline public keys and
recent hashes. It is not a complete published archive directory or a network
benchmark. Its source identity and counts are in `fixtures/manifest.json`.
The source does not include the previous blockhash; the fixture does not
prove chain continuity. It keeps the existing compact log codec rules.

The CAR importer and original CAR fixture belong in the separate legacy
repository. Running this benchmark needs neither the CAR reader nor Archive
V3.
