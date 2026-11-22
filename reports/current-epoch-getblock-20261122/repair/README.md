# Current epoch getBlock repair

Production Worker `blockzilla-get-block` runs version
`e58a69ea-3b2a-465e-bac7-b68599ee1957` at 100%. Its WASM SHA-256 is
`40966754f3e9100674efb845ebecc4c3b2eb8e776c9e2f33d3889400b23f8155`.
The core repair first ran as version `1cc2931c-a23d-464b-b8ee-00b0e49d978d`.
The current version adds error cache safety and a fresh execution header.

- [Current epoch JSON, slot 472608000](https://archive.blockzilla.dev/block/472608000.json)
- [Published archive binary, slot 470555971](https://archive.blockzilla.dev/block/470555971.bin)

The exact route `archive.blockzilla.dev/block/*` uses this Worker. The
existing archive R2 CNAME and raw object paths remain unchanged. The older
`getblock.blockzilla.dev` hostname remains available. Live streams retain
`stream.blockzilla.dev`. No archive proxy or load balancer was added. The temporary
apex `/archive/*` route was removed after the archive hostname passed.

## Read path and scope

On a JSON response-cache miss, the Worker calls Foundation's private
`/v1/finalized/{slot}` route. A retained rooted native frame is returned first.
Foundation can also return an admitted historical R2 location. For a retained
ledger block that is not in the recent window or admitted archive, Foundation
runs the existing ledger compactor's new one-slot command. The Worker checks
the Compact V2 body and renders Base64 Solana RPC JSON. Foundation does not
render or store JSON and does not upload archives.

The ledger command uses the same block loader and encoder as
`hivezilla/ledger-archive`. It opens the real ledger read-only and writes its
checked V1 bundle only to a bounded pipe. No block body, snapshot, second
archive, or per-block resolution index is created. The response has separate
ledger provenance; it invents no native cursor, Bank identity, or R2 locator.
The optional native-frame archive catalog is not enabled.

The Worker checks source and producer generations, slot, parent and block
hashes, native root proof, body SHA-256, lengths and object bounds. Lookup
timeouts, corrupt replies, unrooted blocks and helper faults fail closed with
`no-store`. A checked miss can use the existing historical Compact V2 R2
layout. Public GETs keep zero customer KV reads and zero billable reads.

This repair enables the Foundation native/ledger path for **JSON**. `.bin`
keeps the existing published-archive Wincode contract. `.compact` keeps its
exact native recovery identities and retained-window contract. Full historical
coverage, expired native replay, automatic new-epoch index admission and ledger
retirement are not acceptance results of this repair.

## Measured result

Slot 472608000 returns HTTP 200 with 81 transactions and 82 signatures:

| Field | Checked value |
| --- | --- |
| Blockhash | `DMvymXRdtFwkR26HW2rwMJpVfhsbqyypYmptq91Aasgj` |
| Previous blockhash | `ELvbqp7k1YgC2HmJYy8n7g26BvkcALtX1cwC84xqJtb6` |
| Parent slot | 472607999 |
| Transaction versions | Legacy, V0 and V1 |
| Full transaction wire and metadata | Exact ordered RPC match |
| Block rewards | All 1326 complete records match as a multiset |

Reward order differs between the ledger and comparison RPC. The test does not
claim byte-identical JSON. It found and fixed the old renderer's missing
`DeactivatedStake` and `VATDebit` reward labels. The target has 666 VATDebit
records. No value or address differences remained after the type correction.

The bounded fresh-process helper read took 2862.279 ms, with peak helper RSS
1,160,441,856 bytes. Its output bundle is 91,293 bytes, SHA-256
`c5f7ebd6e0f4ae757ac0e1ca62176e6be8628fd5076a327cae16ec32ce4bebbc`.
OS page-cache state was uncontrolled. This is not a fully cold disk benchmark.
The production RPC comparison completed in 2.948 seconds. Three subsequent
normal requests were response-cache hits with zero Foundation and R2 calls.
They were already warm; no normal cold-fill latency claim is made.

A fresh production native read at slot 472669974 used Foundation with zero
R2 reads. A historical JSON read at 470555971 matched the saved independent
provider digest and used two original S3 ranges plus one resolution request.
The canonical binary endpoint matched its saved original bundle digest.
Real response bodies stayed in process memory.

## Bounds and deployment

Foundation reader PID 2304452 uses service SHA
`6dee8f3e3993f6139a066bd9d0cdff64bc8e264bc3b8dd42a5a6938a8e43d4ab`.
Its helper is pinned by SHA and inode:
`c75dd8411289612031405d7b2c14e448b17bb52af975e4e07f61947dc4126a1e`.
One helper can run at a time. The gateway kills and reaps it after eight
seconds, including cancellation. The reader keeps its 2 GiB memory ceiling;
only its soft file limit rose to 65536, with hard limit 524288 unchanged.
Concurrent cold helper requests can return an uncached busy 503. The ledger
admission floor is 472176000, the start of the previous epoch, so retained
overlap is available before R2 publication. A checked previous-epoch read of
472607999 passed with 255 transactions, 260 signatures and the exact parent
hash expected by 472608000. Its bundle stayed in RAM.

The official SDK opens all SST files by default. A small checked SDK patch
adds an explicit read-only file-cache limit of 64. Default and primary opens
keep their original behavior. The isolated build uses Agave revision
`b6149a719f8fa84123ac3ce1e5f201af64bca8ee` and patch SHA
`115dc1a326a39e77bef40a5c4f0b9c5e23f3ecdadb6a32a433810e52debadd5a`.
No SDK checkout is vendored or changed in place. Registry versions are unchanged.
The normal official-SDK build refuses the one-slot command unless the bounded
feature is built through the documented overlay.

Read-only root-key boundaries span 436,495 slots, or 1.010405 epochs, across
epochs 1093–1094. This proves a range, not complete coverage. Ledger allocation
is 1.122 TB, with 1.172 TB available. No ledger deletion policy was changed.
The current index catalog is static through epoch 1091; automatic admission
of new published epochs was not established. Do not purge the overlap on an
assumed publication boundary.

## Checks and files

All 39 native/ledger actual-WASM checks, 35 public checks, 41 recovery checks,
eight focused host checks and the direct-route unit check passed. The service
passed 47 tests. The helper passed the SDK-option, slot/framing, read-only and
default-refusal checks. These are focused tests, not CI changes.

| File | Change and check |
| --- | --- |
| `Cargo.toml`, `Cargo.lock` | Admit the standalone lightweight native-frame crate; release WASM and host builds pass. |
| `edgezilla/get-block/Cargo.toml` | Add native-frame/Bytes dependencies and test fixtures; no full validator SDK in the Worker. |
| `edgezilla/get-block/src/worker.rs` | Foundation-first JSON, terminal errors, generation cache keys, route alias and reward types; all returned errors are no-store and each execution has a fresh Ray stamp without reading the body. Actual WASM and real RPC checks pass. |
| `worker/foundation_first.rs` | Request-local native/ledger outcomes and pinned configuration; legacy public/recovery suites pass. |
| `worker/foundation_first/finalized.rs` | Checked private HTTP protocol and bounded cancellation; wrong source/root/hash/generation and timeout checks pass. |
| `worker/foundation_first/recent.rs` | Share existing metadata validation; exact recovery behavior passes. |
| `worker/native_block.rs` | Decode original native objects and accept the real compression-effort field; raw/zstd, new rewards and corruption tests pass. |
| `worker/bundle_object.rs` | Shared checked decoder with separate local ledger IDs; epoch-boundary and Legacy/V0/V1 tests pass. |
| `worker/resolution.rs` | Authenticated alias parsing; both index paths reject anonymous requests before backend reads. |
| `scripts/test-native-finalized-worker.mjs` | Independent native/ledger RPC, binary bytes, aliases, cache sharing, errors and new reward tests; 39 pass. |
| `scripts/test-public-worker.mjs` | Shared public cache identities, fresh execution stamps, no extra backend reads and error no-store checks; 35 pass. |
| `wrangler.production.jsonc` | One production Worker, canonical route, source/helper pins, public access, disabled managed Workers Cache and disabled test URLs; live API checks pass. |
| `hivezilla/ledger-archive/Cargo.toml`, `Cargo.lock` | Explicit bounded build feature and existing-version JSON dependencies; default and overlay builds pass. |
| `ledger-archive/src/main.rs` | One-slot command and typed exits; CLI checks pass. |
| `ledger-archive/src/ledger.rs` | Strict read-only complete rooted loading and file-cache option; real target and read-only checks pass. |
| `ledger-archive/src/convert.rs` | Reuse the existing encoder for a local-ID bundle; framing/version checks pass. |
| `ledger-archive/src/slot_compact.rs` | RAM-only response, integrity metadata and bounds; five slot/framing checks and real probe pass. |
| `ledger-archive/patches/` | Small pinned SDK option; default/primary/read-only option tests pass. |
| `ledger-archive/scripts/` | Isolated reproducible overlay; graph audit finds no split Agave sources or registry changes. |
| `indexer/blockzilla-resolution-service/Cargo.toml` | Promote the already locked SQLite dependency; locked release build passes. |
| `resolution-service/src/lib.rs`, `http.rs` | Export adapters and private finalized route; auth and existing routes pass. |
| `resolution-service/src/finalized.rs`, `recent.rs` | Unique rooted selection, original frame/root bytes, checked misses and optional ledger adapter; service suite passes. |
| `resolution-service/src/native_archive.rs` | Optional checked locator reader; tested, not configured in production. |
| `resolution-service/src/ledger_compact.rs` | Pinned executable, one-child gate, bounded pipes and kill/reap; timeout/busy/cancellation tests pass. |
| `resolution-service/src/*tests.rs` | Native/ledger protocol and cleanup regressions; 47 service tests pass. |
| Package READMEs and `.codex/blockzilla-goal.md` | Record the owner’s separate archive machine, current behavior, bounds and test evidence. |

## Cleanup and corrected pilot

Seven unused getBlock Workers and the CDN Pages canary, test hostname, DNS
record and cache rule were removed after code backups and dependency checks.
One Worker in the Blockzilla getBlock family remains. Production workers.dev
and preview URLs are disabled. The website, stream Tunnel and storage data
are preserved. The exact cleanup record is in `cleanup-final-receipt.json`.

An earlier publication pilot was planned on the wrong machine. It stopped
before any uploader started: zero R2 writes and no archive state. Stopping
the controller also stopped its dependent processed/origin units. The original
controller, coordinator binary, configuration and retention policy were restored.
The unconsumed opt-in was removed only after its zero-progress/source checks.
Its historical `previous_json` value was unavailable; the prior policy was
restored with that history field set to NULL. No archive gate remains.

Validator PID 1304643 and Tunnel PID 480183 did not restart. Controller,
processed, origin and banks ended at PIDs 2108510, 2108523, 2108530 and 2128693.
The final check shows both Foundation feeds and the Hetzner client moving,
with no current input error or active recovery. The client has 34 historical
failed recovery attempts; this count did not increase during the check. This
is current health evidence, not a claim of zero interruption during the repair.

Four task-only build directories were then removed from Foundation. This freed
6,382,952,448 allocated bytes (5.94 GiB). Active executables, source overlays,
patches, records and all source data remained. The protected process identities
and retained file hashes stayed fixed. See `foundation-artifact-cleanup.json`.

## Public stream and cache acceptance

The [public stream routing repair](../../../hivezilla/deploy/public-native-stream/README.md)
is deployed and accepted. Its loopback TCP-to-Unix bridge adds no block store.
The existing Tunnel keeps the private reader rule first and exposes only the
native head, events, beam and chunk read paths. The current native Bearer key
is required. Missing, wrong, legacy and URL keys return 401. Private control
paths return 404 even with a valid key. Exact frame, cursor, chunk and object
hash checks passed. All seven protected process identities stayed fixed during
this routing repair. This does not claim browser/CORS or long-stream latency
acceptance, or that the private consumer changed transport.

The [archive benchmark](../public-cache-benchmark/README.md) separates origin
cache bypass from warm Cache API hits. The baseline used the core repair
version; all 73 requests passed. The final production safety version then
passed eight separate warm requests with full body digests, zero backend reads
and eight different execution stamps. See `cache-safety-production-proof.json`.
Cache API hits still execute the Worker. The sampled marginal request and CPU
estimate is about $0.339 per million warm requests, before the subscription,
included allowances, backend, machine, storage and network costs.

Managed Workers Cache remains explicitly disabled. A 0% synthetic test reused
an errored unknown-length stream prefix. No real block or production route was
used for that failure test. The existing Cache API rejected a failed fill and
kept no partial entry. No probe version was promoted. Full results and retained
failures are in the [cache acceptance record](../cache-live-acceptance/README.md).

The [deployment receipt](cache-safety-deployment.json) records the clean safety
version at 100%, with managed Workers Cache, workers.dev and preview URLs all
disabled. The three `cache-*-wasm.json` records cover its 115 local WASM checks.
The final safety version also returned slot 472608000 through `LEDGER_COMPACT`
with the expected hashes, 81 transactions and 1326 rewards, with no customer
KV or billable reads. See `target-final-safety-version.json`. Its single normal
miss took 2.396 seconds; it is not a fully cold storage measurement.
No CI configuration was changed.
