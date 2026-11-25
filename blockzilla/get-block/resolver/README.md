# Block resolver

Private block-local ID resolution and exact retained-frame reads for getBlock.
This service reads the existing archive dictionaries and native retained store;
it does not produce another block archive or application index.

```sh
cargo run --manifest-path blockzilla/get-block/resolver/Cargo.toml -- --help
```

Preserve source identity, expected hashes, authentication and bounded reads.
Run behind a private transport and restrict access to authorized clients.
