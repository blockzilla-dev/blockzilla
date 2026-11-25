# Blockzilla

Solana blocks in a compact format, for live streams and archive reads.

- **Compact V2** — build and read block archives.
- **Zillastream** — capture Agave blocks and deliver a live stream.
- **getBlock** — serve recent and archived blocks.
- **Reader SDK** — use block data in your own applications.

## Quick start

Requires Rust 1.98 or newer.

```sh
git clone --branch codex/1.0-core https://github.com/blockzilla-dev/blockzilla.git
cd blockzilla
RUSTFLAGS="-C target-cpu=native" cargo run --locked -p blockzilla -- --help
```

## In this repository

- [CLI](blockzilla/cli): stream, inspect, dump tokens and build archives.
- [Reader SDK](crates/reader/blockzilla-read-sdk) and [small examples](examples): token, wallet and program dumps.
- [Zillastream](zillastream) and [getBlock](blockzilla/get-block): live delivery and block reads.
- [Compact V2](crates/compact-v2) and [sample benchmark](bench/sample-block): format and performance checks.

## Related repositories

These repositories are private and require organization access.

| Repository | Purpose |
| --- | --- |
| [old-faithful-tools](https://github.com/blockzilla-dev/old-faithful-tools) | CAR readers and import tools |
| [zillanode](https://github.com/blockzilla-dev/zillanode) | Application services and indexing |
| [zilla-runtime](https://github.com/blockzilla-dev/zilla-runtime) | Replay and runtime experiments |
| [hivezilla](https://github.com/blockzilla-dev/hivezilla) | Archive resilience and infrastructure |
| [blockzilla-indexers](https://github.com/blockzilla-dev/blockzilla-indexers) | Specialized indexers |
| [agave](https://github.com/blockzilla-dev/agave) | Maintained validator source and patches |
| [blockzilla-private](https://github.com/blockzilla-dev/blockzilla-private) | Research, reports and full benchmark results |

## Development status

The 1.0 cleanup is on `codex/1.0-core`: [draft PR #90](https://github.com/blockzilla-dev/blockzilla/pull/90).
Experimental V3 work stays on [its own branch](https://github.com/blockzilla-dev/blockzilla/tree/codex/archive-v3).
The combined live token dump and archive backfill is still a development target.

For validator setup and upgrade checks, read the [Agave compatibility guide](zillastream/agave-compatibility/README.md).
