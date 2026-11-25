# Compact V2 reader

Read local or HTTP Compact V2 archives through bounded byte sources and the
shared Blockzilla model. The reader validates selected source bindings,
wire profiles, dictionary references and requested coverage.

Use `archive::CompactV2Archive` for ordered model scans. Lower-level readers,
cursors and projections are available for exact wire access. Absent metadata
must not be reported as known-empty data. Filters must preserve incomplete
coverage instead of silently treating it as a non-match.

The reader is independent of the CAR implementation and Archive V3. Shared
Solana wire codecs are in `blockzilla-solana-wire`; retained PoH wire profiles
are local to this crate. Small examples live at the repository's `examples/`.
