# hivezilla-ledger-archive

`check-ledger-range` checks one inclusive slot range in an Agave ledger and prints a report. `build-epoch-archive` writes a Compact V2 archive of one epoch. The ledger is opened read-only and is not modified.

```text
hivezilla-ledger-archive check-ledger-range <LEDGER> --start-slot N --end-slot M
hivezilla-ledger-archive build-epoch-archive <LEDGER> <OUTPUT-PARENT> \
  --epoch N --level 1 --read-threads 1
```

`check-ledger-range` applies the slot rules and prints a report.

## read-slot-compact

Read one complete rooted block with all transaction status records:

```text
hivezilla-ledger-archive read-slot-compact --ledger <LEDGER> --slot N
```

This command requires the checked `bounded-ledger-read` build below. A normal
build with the official SDK refuses this command with exit 7 before it opens
the ledger. The existing epoch commands still build with the official SDK.

Prepare a new source-only build directory with Python 3.11 or later:

```text
python3 hivezilla/ledger-archive/scripts/prepare-bounded-ledger-build.py \
  --source-root <SOURCE-ONLY-REPO> --agave-source <CLEAN-AGAVE-CHECKOUT> \
  --output <NEW-BUILD-DIRECTORY> --allow-fetch
```

`--allow-fetch` permits missing locked crate archives to be downloaded. Omit it
when the Cargo cache already contains the full graph. The script requires Agave commit
`b6149a719f8fa84123ac3ce1e5f201af64bca8ee`. It copies the SDK into an isolated
Git checkout and applies
`patches/agave-v4.4.0-rc.1-read-only-file-cap.patch` with `git apply --check`.
It points all three direct Agave dependencies at that same checkout, resolves
the overlay lock offline, and rejects registry package changes. `PREPARED.json`
records the base revision, patch SHA, manifest and lock hashes, and paths.
The shared Cargo checkout, original manifest, validator, and live limits are
not changed. The script requires 800 GiB of free build space on Foundation.

Build and run the focused checks against the recorded overlay manifest:

```text
CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_RELEASE_DEBUG=0 \
  cargo +1.98.1 test --release --locked --features bounded-ledger-read \
  --manifest-path <RECORDED-MANIFEST> bounded_sdk
CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_RELEASE_DEBUG=0 \
  cargo +1.98.1 test --release --locked --features bounded-ledger-read \
  --manifest-path <RECORDED-MANIFEST> slot_compact
CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_RELEASE_DEBUG=0 \
  cargo +1.98.1 build --release --locked --features bounded-ledger-read \
  --manifest-path <RECORDED-MANIFEST>
```

The patch adds one optional per-open file/table-cache limit. Its default is
unchanged. Primary modes ignore it. The one-slot reader sets it to 64; integer
overflow is an error. This avoids opening every SST file when the reader
starts. The three option tests check those safety rules. Before use, test the
real block in a fresh process within the service's eight-second and 2 GiB
limits. Record time and peak RSS. Keep stdout in RAM and save only metadata
and digests. Do not enable a helper that fails those limits.

The command opens a fresh `AccessType::ReadOnly` handle. It checks the root,
complete shreds, parent, transaction status, and signature order with the same
loader and encoder as the epoch command. It uses a block-local key dictionary.
Transaction recent blockhashes stay inline, so no ancestor scan is needed.
Legacy, V0, and V1 transactions use the current Compact V2 schema.

The response is built in RAM. No archive file, block copy, JSON store, or
notification is written. Errors go to stderr. Nothing goes to stdout until
the ledger read and encoding pass. The read and encoding deadline is 10 seconds.
The caller must also bound stdout reads and keep its child permit until exit.

Stdout contains exactly these parts:

1. Eight ASCII bytes: `BZLGR01!`.
2. A four-byte little-endian metadata length, at most 4096 bytes.
3. That many UTF-8 JSON bytes.
4. One `BlockzillaGetBlockBundleV1`, at most 16 MiB, with a zstd hot block and
   a complete Wincode access blob.

Metadata contains `version:1`, `slot`, `parent_slot`, Base58 `blockhash` and
`previous_blockhash`, `tx_count`, `hot`, lower-case hex `sha256`, `length`,
`message_schema:0`, `metadata_schema:0`, `rooted:true`, and
`metadata_complete:true`. `sha256` and `length` describe only the bundle.
`hot` contains all `ArchiveV2HotBlockIndexRow` fields. Its local block ID is 1,
the previous hash ID is 0, and both ordinals and the compressed offset are 0.

This is a ledger result. It has no native stream cursor, native bank identity,
root frame, or R2 object identity. Its dictionary is local to this response;
its bytes need not match a later full-epoch archive. The private service must
pin its own ledger generation before the Worker accepts the response.

Exit codes are 3 for an absent slot, 4 for a slot that is not rooted, 5 for
incomplete data or missing parent entries, 6 for missing transaction status,
7 for an I/O, validation, or encoding error, and 8 for the deadline. Only 3
and 4 are safe typed negative results. Other failures must fail closed.

## build-epoch-archive

Write one epoch from a stopped ledger or a snapshot. The ledger is opened read-only.

The epoch has 432000 slots, from `N * 432000` through `N * 432000 + 431999`. The archive is written to `<OUTPUT-PARENT>/epoch-N`. That directory is created only when the ledger still stores the first slot and a root has reached the last slot. An existing final archive file in that directory stops the command.

`--level` is the zstd effort. The default is 1. `--read-threads` is the number of parallel shred reads, from 1 to 32. The default is 1.

Each rooted block becomes one independent zstd frame in `archive-v2-blocks.zstd`. The command then writes these files in the same directory:

- `archive-v2-blocks.index`
- `signatures.bin`
- `blockhash_registry.bin`
- `vote_hash_registry.bin`
- `poh.wincode`
- `shredding.wincode`
- `registry.bin`
- `prev_blockhash_tail.bin`

A failure removes the temporary files and does not publish the index. The command prints the block count, the proven skips, the abandoned forks, the first block, the last block, the boundary hash, and the output path.

A slot is written only when it is rooted and its shreds are complete. The tool then checks that every transaction has a status, and that the parent slot and parent blockhash chain to the previous written block.

Slots with no `SlotMeta` are not written. A skip reward in the block at slot N+8 records a skip. A notarization reward alone is an error. When that footer contains both rewards, the slot is a skip only if the next rooted block jumps over it. When slot N+8 has no footer, the same parent jump records a skip. A rooted block that is not full, or a hole that the next rooted block descends from, stops the run.

A slot that has data but is not rooted is left out only when the next rooted block jumps over it and slot N+8 carries a skip reward. The same sentence is printed for that case and for a parent-jump hole: `slot N left out, rooted chain jumps to M`. A skip reward alone prints nothing.

The tool does not verify BLS vote signatures and does not recompute the bank hash. Agave already did both before it rooted the slot.

The slot rules were run on one full epoch, epoch 1077, slots 465264000–465695999. The scan finished with 432000 slots scanned and 431628 rooted blocks accepted. The other 372 slots were proven skips or abandoned forks.
