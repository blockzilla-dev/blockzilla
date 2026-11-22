# Current epoch getBlock diagnosis

At 18:33 UTC on 22 November, the public JSON request for slot 472608000 returned HTTP 502. The Worker tried the epoch 1094 historical Compact V2 index and received HTTP 404. Its receipts show zero Foundation lookup, recent-read, or resolution calls. Public authentication and zero billing worked.

The ordinary JSON and binary routes do not use the native recent-frame path. Production sets `BZ_FOUNDATION_LOOKUP_MODE=recent-only`, which skips the older Foundation lookup on those routes. Only `.compact` uses the native recent reader, and that route requires the expected blockhash. The older `/v1/block/{slot}` service only returns an admitted archive locator; it does not read native frames. A checked local request for this slot returned `404 not_cached` with `source: null`. Epoch 1094 is absent from its twelve admitted epochs. Changing the mode to `all` alone cannot make this JSON request succeed.

The native feed is moving, but its retained window is small. A read-only query found 1,027 bank rows from slots 472642281 through 472643307; the latest native chain slot later advanced to 472643532. The requested slot is absent from the bank and processed databases, including the checked retirement and input-custody tables. This absence does not prove a skipped block or data loss. The active validator has `--disable-rpc`; local RPC requests were refused. Enabling RPC was not attempted.

Existing cloud metadata was checked without downloading payloads. The exact current-session prefix in `native-custody/processed-v1/` returned a complete empty R2 listing. The complete session listing under `native-stream/processed/direct-agave-live-v1/` had fourteen older sessions and no current session. The old storage registry names older sources; its three recorded archive database paths are absent. No native cold-storage service was running, and the active continuous controller has no upload or publisher configuration. These checks cover the known serving paths, not every object in the bucket.

A future recent JSON path needs a checked slot-to-rooted-identity lookup and a compatible Base64 RPC projection from the original native payload. It must preserve native source, hash, parent, and root checks. The requested older slot also needs an admitted existing archive source. A new renderer or a cache flag cannot supply missing coverage. An immediate error fix could report explicit unavailable coverage instead of an internal S3 index error, but it would not return this block.

No validator, producer, origin, reader, or tunnel was restarted or changed. The public RPC response was inspected in memory. No block payload file, R2 bundle download or second serving copy was created. The public stream head separately returned HTTP 502 from the external client; the native feed itself reported `RUNNING`. Full safe evidence is in [diagnosis.json](diagnosis.json).

An independent public mainnet RPC request with maximum transaction version 0 returned error `-32015`. One authorized follow-up with maximum version 1 returned the finalized block: blockhash `DMvymXRdtFwkR26HW2rwMJpVfhsbqyypYmptq91Aasgj`, previous blockhash `ELvbqp7k1YgC2HmJYy8n7g26BvkcALtX1cwC84xqJtb6`, parent slot 472607999 and 81 transactions. The block contains legacy, v0 and v1 transactions. This proves that the requested slot is not skipped. Neither provider response body was stored. The existing Worker Base64 renderer already has v1 support and a test for all three versions; this check did not run that test. The Worker failure response has `Cache-Control: no-store`, so this error must not enter the HTTP CDN cache.

An independent live read confirmed `RETENTION-AUTHORITY.json` uses `local-beam-v1`, with frontier `full-committed-native-feed-tip` and `consumer_ack_required: false`. The active controller starts banks with `--local-beam-retention` and the origin with `--direct-beam`. Its bounded rolling retention does not wait for verified cloud custody. This is a different contract from the older session-bound native cloud publisher. The absent current-session cloud handoff must remain explicit.

The final local check covered all nine preserved run entries and their eighteen bank/processed SQLite databases. Slot 472608000 was absent from every banks table and every checked processed event, retirement and input-custody table. The queries used read-only mode and read only metadata. No query failed. These results bound the local check to the preserved runs in the current continuous job.

| Run prefix | Bank slot range | Processed slot range | Target rows |
| --- | --- | --- | ---: |
| 1b8fc095 | 472359689–472360714 | 472359689–472360715 | 0 |
| 3b2f54e4 | 472373307–472374331 | 472373307–472374332 | 0 |
| 4a1d7014 | 472286117–472286142 | 472286115–472286143 | 0 |
| b6818e8d | 472471781–472472805 | 472471779–472472807 | 0 |
| c1739ce6 | 472643979–472645003 | 472643979–472645004 | 0 |
| d3f4cd30 | 472405219–472405833 | 472405217–472405834 | 0 |
| e5dedf00 | 472404188–472405213 | 472404188–472405214 | 0 |
| edf6cae0 | 472420550–472421582 | 472420548–472421583 | 0 |
| f9b96548 | 472465033–472466059 | 472465033–472466060 | 0 |
