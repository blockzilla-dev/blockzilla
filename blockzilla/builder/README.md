# Native Blockzilla builder

Consume the bounded Zillastream capture journal and build Compact V2 payloads.
The existing `hivezilla-direct-agave` package, executable and record names are
preserved during the repository extraction.

```sh
cargo run --manifest-path blockzilla/builder/Cargo.toml -- --help
```

The worker uses Linux filesystem notifications. Run Linux integration tests
and a matched Agave/plugin load check before deployment. Source identity,
Bank identity, retained payloads and control records must remain exact.
