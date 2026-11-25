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

## Throughput for indexers

The reader must never be the slowest stage of an indexer. To get this:

1. Request only the facts that you use. `ScanRequest::all()` reads one
   signature per transaction and resolves every required signer. Use
   `ScanRequest::token_balances_only()` for token exports,
   `with_required_signer(key)` for one wallet, and
   `with_instruction_programs_for(programs)` with
   `with_selected_primary_signatures()` for program calls. A request without
   instruction data can use the parallel scan.
2. Use `CompactV2Archive::scan_ordered_parallel` or
   `scan_ordered_parallel_map`. The pipeline reads, decompresses and projects
   blocks on worker threads and delivers them in exact block order.
3. Keep the ordered thread small. The sink of `scan_ordered_parallel` runs on
   one thread. Put per-block work, such as filtering and encoding output, in
   the `map` function of `scan_ordered_parallel_map`: it runs on the workers,
   and `consume` only receives the results in order. Buffer output and write
   it once per block (`BufWriter`), not once per row.
4. Give the input enough parallel reads. A NAS array needs several concurrent
   reads (`PinnedLocalRangeSource::with_read_concurrency`). A high-latency
   object store needs more bytes in flight (`NetworkInputConfig`).
5. Read the receipt. `CompactV2ParallelScanReceipt::limiting_stage()` reports
   the stage that limited the scan: input, decode and projection, or the
   ordered consumer (your sink or `consume`). The receipt also has the time
   of each stage. The examples print it with `--stats`.

For example, the token dump example reads 1,000 epoch-200 blocks (676,169
transactions, 222,326 rows) from a local copy in 0.15 s with 8 workers. The
first version, with a sequential scan and one write per row, took 1.6-2.1 s.
