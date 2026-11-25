# Contribute to Blockzilla

Small, focused pull requests are welcome. For a large change, open an issue
first so maintainers can agree on its scope and compatibility rules.

## Scope

This repository owns Compact V2, block production, archive readers, getBlock,
Zillastream and small examples. Keep application indexers, infrastructure,
operational records and general runtime experiments outside this repository.
Use Rust for native tools and process-test helpers. Do not add Python files or
Python interpreter calls. SSH adapters, key provisioning, deployment probes,
operator notifications and full benchmark tools belong in private infrastructure
repositories. Keep self-contained public tests and the fixed sample benchmark.
CI rejects deployment directories, private research records, Python files,
host service definitions and direct Rust calls to administration programs.
Public clients use HTTP or local sockets. Keep credentials and host-specific
launchers in the private infrastructure repository.

The core workspace builds without access to a private repository. Agave host
work is optional and has separate [compatibility instructions](zillastream/agave-compatibility/README.md).
Read the [code of conduct](CODE_OF_CONDUCT.md). Report security issues through
[the private reporting process](SECURITY.md).

## Prepare a change

1. Fork the repository and create a branch for one change.
2. Explain the problem and expected result. Include a small reproduction for a bug.
3. Keep existing license notices. Identify any new third-party source.
4. Add a regression test when behavior changes. For a documentation-only change,
   check the commands and links that you changed.
5. Open a pull request with the result, validation, and any compatibility impact.

Preserve exact block bytes, source identity, Bank identity, cursors and control
events. Do not infer missing history or silently accept a different wire format.
A performance change must preserve output and include a reproducible comparison.
Keep full benchmark logs and machine records out of this repository.

## Local checks

CI uses Rust 1.98.1. From the repository root:

```sh
rustup toolchain install 1.98.1 --profile minimal --component rustfmt
export RUSTUP_TOOLCHAIN=1.98.1
export RUSTFLAGS="-C target-cpu=native"
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
```

The stream crates have separate workspaces. Run the checks for the code you change:

```sh
cargo test --locked --manifest-path crates/blockzilla-bank-stream-v2/Cargo.toml
cargo test --locked --manifest-path crates/blockzilla-bank-client/Cargo.toml
cargo test --locked --manifest-path blockzilla/get-block/resolver/Cargo.toml
cargo test --locked --manifest-path zillastream/capture-core/Cargo.toml
cargo test --locked --manifest-path zillastream/relay/Cargo.toml
```

Run `cargo test --locked --manifest-path blockzilla/builder/Cargo.toml` on Linux
for a native builder change. A unit test or library build does not replace a
matched Agave host/plugin load test.

For the getBlock Worker adapter:

```sh
rustup target add wasm32-unknown-unknown --toolchain 1.98.1
RUSTFLAGS="-C target-cpu=generic" cargo check --locked -p blockzilla-get-block \
  --no-default-features --features worker --target wasm32-unknown-unknown --lib
```

Include the exact commands and results in the pull request. If a check cannot
run on your machine, state which check and why. Maintainers review changes
before merge; CI must pass. Release rules are in [RELEASE.md](RELEASE.md).
