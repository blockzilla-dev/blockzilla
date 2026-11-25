# Portable native compact decoder

This independent crate reads the current native compact projection with the
existing `blockzilla-archive-v2`, `blockzilla-compact`, and primitive Rust schemas.
It uses `ruzstd` for bounded, pure Rust Zstandard decoding. It has no Agave ABI,
network service, or JavaScript host imports. The tiny owned-buffer Wasm ABI is
private to the accompanying SDK.

Build and test with Rust 1.98 or later:

From this directory:

```sh
rustup target add wasm32-unknown-unknown
CARGO_BUILD_JOBS=4 RUSTFLAGS='-C target-cpu=native' cargo test --locked
./build-wasm.sh
```

`build-wasm.sh` builds all three SDK Wasm files with their required exports and
copies them to `../client/`. It maps build paths to generic paths so the binaries
do not contain local user or checkout names. The build does not install a
validator plugin or change a native capture process.

The JavaScript transport checks frame and object digests before calling the
decoder. This crate checks index geometry, signatures, native block identities,
transaction regions, dictionary references, loaded addresses, execution flags,
and instruction account positions. Native batches use zero-based produced-only
blockhash registries; the first parent is a separate 40-byte hash+slot tail.
No schema probing or canonical archive fallback is used.

The supported result is semantic compact transaction data. Exact signed wire
reconstruction, full RPC rendering, portable log expansion, and a shared stable
live dictionary are separate work. Do not present this projection as canonical
archive data or interpret absent inner metadata as proved absence of CPI calls.
