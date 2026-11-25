# Blockzilla

Compact Solana blocks for live streams and archive reads.

[Website](https://blockzilla.dev) · [Documentation](https://docs.blockzilla.dev) · [Archive status](https://status.blockzilla.dev) · [X](https://x.com/Blockzilla_sol)

[![Core checks](https://github.com/blockzilla-dev/blockzilla/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/blockzilla-dev/blockzilla/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Blockzilla produces compact blocks, serves recent and archived data, and gives
applications a shared reader API. Use it to read Solana history, consume live
blocks, or build a focused data export.

## Quick start

Requires Git, a C compiler and Rust 1.98 or newer.

```sh
git clone https://github.com/blockzilla-dev/blockzilla.git
cd blockzilla
RUSTFLAGS="-C target-cpu=native" cargo run --locked -p blockzilla -- \
  stream --epoch 200 --max-blocks 5
```

This reads five block rows from the public sample archive. No API key is needed.
Use `--help` to see the commands, or start with the [small examples](examples).

## In this repository

| Component | Purpose |
| --- | --- |
| [CLI](blockzilla/cli) | Stream, inspect, dump tokens and build archives |
| [Compact V2](crates/compact-v2) | Block format, archive layout and readers |
| [Zillastream](zillastream) | Capture Agave blocks and deliver a live stream |
| [getBlock](blockzilla/get-block) | Serve recent and archived blocks |
| [Reader SDK](crates/reader/blockzilla-read-sdk) | Read block data in your application |
| [Sample benchmark](bench/sample-block) | Reproduce format and performance checks |

The [status page](https://status.blockzilla.dev) shows archive coverage. The public
Foundation archive uses this object base URL (add `epoch-N/<file>`):

```text
https://pub-97348740d6ef467aa2f1b4b62daa98dc.r2.dev/compact-v2/blockzilla-20261004
```

[Sample index](https://pub-97348740d6ef467aa2f1b4b62daa98dc.r2.dev/compact-v2/blockzilla-20261004/epoch-200/archive-v2-blocks.index) · [Archive and reader documentation](https://docs.blockzilla.dev/read-an-archive/)

## Project status

The 1.0 release is in preparation. [Release requirements](RELEASE.md) track the
remaining checks. The combined live token dump and archive backfill is still a
development target. Experimental V3 work stays on [its own branch](https://github.com/blockzilla-dev/blockzilla/tree/format/v3).

For validator setup and upgrade checks, read the [Agave compatibility guide](zillastream/agave-compatibility/README.md).

## Contribute

Bug reports, documentation fixes and focused pull requests are welcome.
Read [CONTRIBUTING.md](CONTRIBUTING.md) to get started. Report vulnerabilities
through the [private security process](SECURITY.md).

## Support and community

Supported by the [Solana Foundation](https://solana.org/).

We are looking for sponsors to help fund development and public archive access.
Follow [@Blockzilla_sol on X](https://x.com/Blockzilla_sol) for updates, or contact
us there about sponsorship.

## License

[MIT](LICENSE). See [AUTHORS.md](AUTHORS.md) for source attribution.
