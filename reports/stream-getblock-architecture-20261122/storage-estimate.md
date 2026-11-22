# Epoch index storage for the proposed resolution service

Existing object sizes below were checked with bounded read-only Foundation R2 metadata requests on 22 November 2026. The source manifests and 36-byte hot-index headers agree with the observed sizes. No full payload was downloaded or copied. The manifests still state `canonical_publication=false` and `full_remote_readback=false`.

GB means 1,000,000,000 bytes. GiB means 1,073,741,824 bytes. The current Foundation service is a proposed design; these figures do not show that the indexes or signatures are already installed on that host.

| Storage component | Epoch 1089, GB | Epoch 1090, GB | Basis |
| --- | ---: | ---: | --- |
| Minimal existing resolution core | 1.058 | 1.111 | Measured files |
| All existing lookup/control sidecars | 1.494 | 1.569 | Measured, includes the minimal core |
| CAR SlotMeta source-preservation data | 0.295 | 0.303 | Measured, separate from indexes |
| Raw signatures | 10.799 | 12.241 | Measured payload, separate from indexes |
| New compact slot resolution | 4.020 | 4.018 | Four-block projection |
| Minimal core + compact slot resolution | 5.078 | 5.129 | Measured core + projection |
| Prior row + local signatures | 15.877 | 17.371 | One-bucket-GET capacity mode |

Epoch 1089 has 431,811 stored block rows and 156,439,236 transactions; epoch 1090 has 431,639 rows and 178,122,453 transactions. The saved final hot rows have the same strong index ETags as the current object, and their final signature ordinals match the complete signature file sizes. These counts do not prove distinct transaction-signature cardinality.

The minimal core is `registry.bin`, the hot slot/index table, blockhash registry, previous-epoch hash tail, vote-hash registry, compact format metadata and the first-seen registry identity record. `registry.mphf` and `registry_counts.bin` are not needed for ID-to-key reads. They are included in the larger all-sidecar row, with reverse blockhash lookup, seed and control records. The current dense slot index and compact used-ID sidecar are absent from Foundation R2.

The CAR SlotMeta sidecar is required by the newer CAR-preservation profile. It is separate source data, not a lookup table. The current Worker renderer and `finalized_block` reader do not query it. This report does not authorize removing it.

## New block-resolution index scenario

The exact four modern access records use a mean 8,781 raw bytes of typed 32-bit IDs and about 380 bytes of signature counts per block. These are all required references, not just account-filter IDs. The scenario adds 12 bytes per block for three family counts, eight bytes for each record offset, a small blob header, and the existing 128-byte-per-slot dense table. The dense table is 55,296,128 bytes for 432,000 slots and includes actual parent/current/previous hashes and original hot/signature ranges.

This gives about 4.02 GB of new derived data for either recent epoch. It is a projection from four blocks, not a built or compressed epoch index. The original registries remain necessary to resolve the stored IDs. A full pre-resolved object for every block would instead project to about 34.02/34.00 GB before signature bodies. That alternative already carries its own source/parent/hash descriptor; do not add the compact-ID table to it.

A host that keeps the minimal original tables plus compact slot resolution and every raw signature needs about 15.88 GB for epoch 1089 or 17.37 GB for epoch 1090, before block cache, CAR preservation, filesystem allocation, replicas, journals and build overlap. Keeping all existing lookup/control sidecars gives about 16.31/17.83 GB instead.

## Existing history, epochs 0 through 1047

The validated 5 October source inventory covers 1,048 epochs. Its exact minimal core totals 0.786947 TB (0.751 GB per epoch on average). All existing lookup/control sidecars total 1.098023 TB (1.048 GB per epoch). Raw signatures alone total 38.035457 TB. The minimal tables plus all signatures total 38.822404 TB; all lookup/control sidecars plus signatures total 39.133479 TB.

The uploader checked the 36-byte header/52-byte row format for those source inventories. Their aggregate index bytes imply 430,774,632 stored block rows. Applying the four modern block means to all rows would give an illustrative 4.013 TB of additional compact-resolution data. This is not a measured full-history size or a safe capacity forecast: older blocks, transaction counts, ID reuse, votes and short early epochs differ.

Raw signatures are the main host capacity requirement if a fully cold request must use only one total R2 GET. If Foundation has only indexes and its signature cache misses, it must fetch signatures too. That is a second global R2 GET even if the public Worker issues only the hot-block GET. A bounded signature cache is a valid capacity choice, but its cold-read count must stay explicit.

## Optional getTransaction index

This is separate from `registry.mphf`. The tested signature locator stores five-byte slot/tag rows plus an MPHF. Its one-million-key sample uses 5.339908 serialized bytes per key and 0.350760 resident MPHF bytes per key. The smaller sample was about 5.53 serialized bytes per key. For the observed transaction counts this gives a projected persisted signature index of about 0.84–0.87 GB for epoch 1089, or 0.95–0.99 GB for epoch 1090. These indexes were not built for these epochs. The count is not proof of distinct first signatures. The 36-byte build spool adds about 5.63/6.41 GB temporarily, with build RAM and segment/compaction overlap extra.

## Reproduce and inspect

Run `python3 reports/stream-getblock-architecture-20261122/storage-estimate.py` from the repository. It reads saved records only and makes no network call.

- [Exact model and byte totals](storage-estimate.json)
- [Current HEAD/header/manifest receipt](storage-current-object-metadata.json)
- [Historical measured inventory](../../hivezilla/deploy/foundation-upload/evidence/scope-20261005.json)
- [Four-block access shape](../get-block-one-read-20261122/resolution-service-shape.json)
- Signature-index format and build limits (separate design)
