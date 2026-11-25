# Zillastream

Zillastream is the native capture and streaming component inside Blockzilla.
It stays in this repository so live delivery and archive backfill can share
the block model, reader, decoder and filters. Blockzilla also owns the compact
format, block builder, archive readers and `getBlock`. Hivezilla is planned as
a separate internal repository for archive resilience and infrastructure
management. Required product code currently under `hivezilla/` must move into
Blockzilla or Zillastream before that folder can leave this repository.

This directory currently contains two independent Rust crates:

- `capture-core`: capture records, the bounded SQLite journal and source
  retention. The existing Blockzilla worker uses this shared library.
- `geyser-plugin`: the native Geyser adapter. It builds
  `libhivezilla_direct_agave.so` on Linux so the existing loader and deployment
  configuration can continue to use the same filename.

The plugin identifier, callback schemas, journal format and retention rules
retain their existing names and behavior. This source move does not deploy a
plugin or restart the validator. Stream relay and client extraction is separate
work.

## Shared live and archive target

The primary acceptance example is a token dump that starts receiving live
blocks immediately, then backfills a selected archive range while live capture
continues. Both sources must use the same decode and filter path. The consumer
checks a shared finalized boundary, reconciles overlap, and commits output
with both checkpoints so it can restart without missing or duplicate rows.

Live source identity and control events remain distinct from finalized archive
identity. Backfill must not invent processed events or expired native cursors.
Missing coverage stops with an explicit gap. The full acceptance criteria are
in the [token dump example](../examples/token-dumper/README.md#target-live-capture-with-archive-backfill).
The existing archive-only `dump-tokens` command does not implement this target
yet.

The full Agave fork, patch code and Agave regression tests stay in the fork
repository. Blockzilla keeps no patch copies in its final layout. Before
changing the version, read the [compatibility record](agave-compatibility/README.md)
for the tested revision, change purposes, source/test links, upstream status
and removal criteria.

## Checks

```sh
cargo test --locked --manifest-path zillastream/capture-core/Cargo.toml
cargo test --locked --manifest-path hivezilla/direct-agave/Cargo.toml
```

The compact worker currently requires Linux filesystem mutation watches. The
capture-core checks can also run on macOS.

The Geyser plugin requires the exact matched, patched Agave host source. Use the
existing native build and host-load checks under
`hivezilla/deploy/bank-stream-v2/` or `hivezilla/deploy/agave-upgrade/` with the
new plugin manifest. The plugin's epoch test also requires
`BLOCKZILLA_TEST_BINARY` to name the tested Blockzilla builder.

A successful library build does not prove host/plugin ABI compatibility. Run
the actual plugin-manager load check against the matched host before deployment.
