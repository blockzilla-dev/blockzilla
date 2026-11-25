# Experimental Archive V3

This branch adds only the Archive V3 format, reader and Compact V2 converter to
the clean Blockzilla core. It does not include the former monorepo history,
application indexers, CAR readers, runtime experiments or benchmark reports.

- [Format](blockzilla-archive-v3/README.md): object layout and wire contracts.
- [Reader](blockzilla-archive-v3-reader/README.md): canonical local access and
  frozen prototype compatibility.
- [Converter](blockzilla-archive-v3-convert/README.md): checked V2 conversion.

```sh
RUSTFLAGS="-C target-cpu=native" cargo test --locked \
  -p blockzilla-archive-v3 -p blockzilla-archive-v3-reader \
  -p blockzilla-archive-v3-convert --all-targets
```

V3 is experimental. Source SlotMeta and nonempty consensus tails are rejected
until V3 has a checked preservation contract for them. Conversion output is
not a published archive and must not replace or delete its source. Full
historical state parity and live/backfill product acceptance remain separate.
