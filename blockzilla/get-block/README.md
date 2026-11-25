# Blockzilla getBlock

Serve Compact V2 blocks from retained native frames or immutable archives.
The Worker adapter and native resolver share the format code. The resolver
service is under `resolver/`.

```sh
cargo run --manifest-path blockzilla/get-block/resolver/Cargo.toml -- --help
cargo run -p blockzilla-get-block --bin build-slot-index -- --help
cargo run -p blockzilla-get-block --bin build-slot-resolution -- --help
```

Keep exact source, blockhash, commitment and frame identity checks. An expired
processed frame must not be replaced by reconstructed archive data. Missing,
incomplete and corrupt data are distinct outcomes. The native account/ledger
bridge is an independent API in the Agave fork.

Use `wrangler.example.toml` as the starting point for a Worker deployment. Set
your own account, storage and endpoint values in a separate deployment config.
