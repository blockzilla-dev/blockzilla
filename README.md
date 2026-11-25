# Blockzilla

Blockzilla builds, reads and serves Compact V2 blocks. Zillastream supplies native
Agave capture, retained block delivery, relays and clients in this repository.

## Contents

- `crates/`: formats, shared Solana wire codecs, reader SDKs and byte sources.
- `blockzilla/cli`: archive stream, token dump, inspect and native block builder.
- `blockzilla/builder`: native capture worker (the existing binary name is preserved).
- `blockzilla/get-block`: getBlock service and the private resolution service.
- `blockzilla/archive-gateway`: immutable archive range service.
- `zillastream/`: Geyser adapter, capture journal, relay and clients.
- `examples/`: token, required-signer wallet and program dumps.
- `bench/sample-block`: fixed Compact V2 block benchmark with checked source identity.

## Build and check

```sh
RUSTFLAGS="-C target-cpu=native" cargo test --workspace --all-targets
cargo run -p blockzilla -- --help
```

The native capture worker uses Linux filesystem notifications. Test and deploy
it with the matching Agave fork and plugin; a macOS build is not a host-load test.

The CAR reader/import tools, runtime experiments, infrastructure, application
indexers and full research records have separate repositories. Archive V3
continues on `codex/archive-v3`. The compatibility record under
`zillastream/agave-compatibility` contains revision pins and change reasons;
Agave source changes and host regression tests belong in the Agave fork.

The combined live plus archive token dump remains an acceptance target. The
small archive examples do not claim to implement live reconciliation or resume.
