# Zillastream

Zillastream is the native capture and streaming component inside Blockzilla.
It stays in this repository so live delivery and archive backfill can share
the block model, reader, decoder and filters. Blockzilla also owns the compact
format, block builder, archive readers and `getBlock`.
[Hivezilla](https://github.com/blockzilla-dev/hivezilla) is the separate private
repository for archive resilience and infrastructure management.

This directory contains the capture crates and the stream relay:

- `capture-core`: capture records, the bounded SQLite journal and source
  retention. The existing Blockzilla worker uses this shared library.
- `geyser-plugin`: the native Geyser adapter. It builds
  `libhivezilla_direct_agave.so` on Linux so the existing loader and deployment
  configuration can continue to use the same filename.
- `relay`: retained-frame delivery, the shared decoder, and Rust/JavaScript clients.

The plugin identifier, callback schemas, journal format and retention rules
retain their existing names and behavior. This source move does not deploy a
plugin or restart the validator.

## Shared live and archive target

The primary acceptance example is a token dump that starts receiving live
blocks immediately, then backfills a selected archive range while live capture
continues. Both sources must use the same decode and filter path. The consumer
checks a shared finalized boundary, reconciles overlap, and commits output
with both checkpoints so it can restart without missing or duplicate rows.

Live source identity and control events remain distinct from finalized archive
identity. Backfill must not invent processed events or expired native cursors.
Missing coverage stops with an explicit gap. The full acceptance criteria are
in the [current goal](../.codex/blockzilla-goal.md#acceptance-target).
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
cargo test --locked --manifest-path blockzilla/builder/Cargo.toml
cargo test --locked --manifest-path zillastream/relay/Cargo.toml
```

The compact worker currently requires Linux filesystem mutation watches. The
capture-core checks can also run on macOS.

The Geyser plugin requires the exact matched, patched Agave host source. Use the
native build and host-load checks in the private
[Hivezilla deployment tools](https://github.com/blockzilla-dev/hivezilla/tree/main/hivezilla/deploy)
and the [Agave fork](https://github.com/blockzilla-dev/agave) with the plugin
manifest in this repository. The plugin's epoch test also requires
`BLOCKZILLA_TEST_BINARY` to name the tested Blockzilla builder.

A successful library build does not prove host/plugin ABI compatibility. Run
the actual plugin-manager load check against the matched host before deployment.
