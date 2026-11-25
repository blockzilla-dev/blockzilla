# Blockzilla

Blockzilla builds, reads and serves Compact V2 blocks. Zillastream supplies native
Agave capture, retained block delivery, relays and clients in this repository.

## Contents

- `crates/`: formats, shared Solana wire codecs, reader SDKs and byte sources.
- `blockzilla/cli`: archive stream, token dump, inspect and native block builder.
- `blockzilla/builder`: native capture worker (the existing binary name is preserved).
- `blockzilla/get-block`: getBlock service, private resolver and provider range reader.
- `blockzilla/ledger-archive`: optional read-only Agave ledger-to-Compact helper.
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

## Repositories and branches

`codex/1.0-core` is the lean Blockzilla candidate. The existing `main` stays in
place until review and integration checks pass. Archive V3 continues on
[`codex/archive-v3`](https://github.com/blockzilla-dev/blockzilla/tree/codex/archive-v3).

The separate repositories are private and require organization access:

| Repository | Contents |
| --- | --- |
| [old-faithful-tools](https://github.com/blockzilla-dev/old-faithful-tools) | CAR readers, imports and CAR sample benchmark |
| [zilla-runtime](https://github.com/blockzilla-dev/zilla-runtime) | Existing native replay experiments |
| [zillanode](https://github.com/blockzilla-dev/zillanode) | Stream consumers and application services |
| [hivezilla](https://github.com/blockzilla-dev/hivezilla) | Internal archive resilience and infrastructure |
| [blockzilla-indexers](https://github.com/blockzilla-dev/blockzilla-indexers) | Specialized indexes and applications |
| [agave](https://github.com/blockzilla-dev/agave) | Validator source, patches and host regression tests |
| [blockzilla-private](https://github.com/blockzilla-dev/blockzilla-private) | Documents, research, results and migration records |

The [Agave compatibility record](zillastream/agave-compatibility/README.md)
contains revision pins, change reasons and removal checks. Zillastream stays
inside Blockzilla.

## Sibling source setup

The core workspace can build alone. The extracted projects currently use
relative Cargo paths to the core. Clone the repositories you need into one
parent directory, with these directory names:

```sh
git clone --branch codex/1.0-core git@github.com:blockzilla-dev/blockzilla.git blockzilla
git clone git@github.com:blockzilla-dev/old-faithful-tools.git old-faithful-tools
git clone git@github.com:blockzilla-dev/zilla-runtime.git zilla-runtime
git clone git@github.com:blockzilla-dev/zillanode.git zillanode
git clone git@github.com:blockzilla-dev/hivezilla.git hivezilla
git clone git@github.com:blockzilla-dev/blockzilla-indexers.git blockzilla-indexers
git clone git@github.com:blockzilla-dev/agave.git agave
git clone git@github.com:blockzilla-dev/blockzilla-private.git blockzilla-private
```

Only the optional ledger reader needs the separate `agave-ledger` worktree.
From the same parent directory, run:

```sh
git -C agave worktree add --detach ../agave-ledger origin/codex/ledger-read-v4.4.0-rc.1
```

`agave/main` contains the native integration profile. The `agave-ledger`
worktree contains the exact RC1 ledger profile. Keep their source and test
results separate. Neither profile is a new deployment acceptance.

The combined live plus archive token dump remains an acceptance target. The
small archive examples do not claim to implement live reconciliation or resume.
