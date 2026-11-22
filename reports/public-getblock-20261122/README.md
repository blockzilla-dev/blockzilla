# Public getBlock GET deployment

Deployed on 22 November 2026 to `https://getblock.blockzilla.dev`.
Worker version: `4d1b4d55-31f1-4e30-a287-717846eeff3c`.

The owner requested public and free getBlock reads. Production now sets
`BZ_GET_BLOCK_PUBLIC=true`. GET block, block-lite and compact recovery routes
ignore caller API-key headers, skip API-key storage, and make no customer
billing writes. Their billable-read receipt is zero. This setting does not
change the separate POST or resolution authentication contracts.

Known successful ordinary JSON and binary blocks have public cache headers.
Errors, diagnostic requests and client locator variants remain uncacheable.
Compact recovery keeps its exact source, Bank, cursor and hash checks and
its `private, no-store` policy. Public responses allow browser GET access.
No archive object, new block store or per-block index was added.

This deployment does not enable Workers Caching or add another CDN layer.
It does not claim that Cloudflare request charges are zero.

## Validation

| Check | Result |
| --- | --- |
| Public JSON/binary actual WASM, without customer KV or billing bindings | 29 passed |
| Public compact recovery actual WASM, without those bindings | 41 passed |
| Existing authenticated Foundation/archive actual WASM | 110 passed |
| Existing authenticated compact recovery actual WASM | 41 passed |
| Native R2 probe actual WASM | 11 passed |
| Live requests without API headers | 9 passed |
| Live configuration and binding checks | 11 passed |
| Changed Rust formatting and Git diff checks | Passed |

The public checks include missing, invalid and previously unused caller keys,
shared cache hits across those headers, exact block digests, zero billing and
key-storage receipts, CORS, errors that do not enter cache, and preserved
POST/resolution rejection. The live checks include the original binary and
JSON digests and finalized archive compact recovery. Fresh recent native
recovery was tested locally; no new live recent-frame test is claimed.
The public stream head returned HTTP 502 during identity capture. No stream
service or validator was changed for this deployment.

The deployment kept the existing domain, resource bindings, seven secret
bindings, compatibility date, limits and observability settings. The code
was built and tested before upload. The complete WASM is identified in the
[validation receipt](validation.json); live checks are in the
[public endpoint receipt](public-endpoints.json). No block bodies or secret
values are stored in these records. Full workspace CI was not used for this
change, as requested by the owner.

## File record

| File | Change |
| --- | --- |
| `edgezilla/get-block/src/rpc_access.rs` | Explicit public setting and request-local anonymous identity; stored keys cannot use that identity. |
| `edgezilla/get-block/src/worker.rs` | Public GET auth bypass, optional billing handle, zero billable receipt, cache policy, browser headers and info response. |
| `edgezilla/get-block/src/worker/recent_recovery.rs` | Optional billing handle; retained identity checks and no-store policy. |
| `edgezilla/get-block/src/worker/resolution.rs` | Optional billing for shared archive helpers; retain stream completion waits. |
| `edgezilla/get-block/src/worker/bundle_object.rs` | Optional completion metrics; retain the stream lifecycle. |
| `edgezilla/get-block/scripts/test-public-worker.mjs` | Actual WASM public-access and cache regression checks. |
| `edgezilla/get-block/scripts/test-recent-recovery-worker.mjs` | Public test mode with customer bindings removed. |
| `edgezilla/get-block/wrangler.production.jsonc` | Enable public GET access on the existing Worker. |
| `edgezilla/get-block/README.md` | Public contract, keyless examples and deployment link. |
| `.codex/blockzilla-goal.md` | Record the owner's public GET decision and tested result. |
| `reports/public-getblock-20261122/` | Record this deployment and its checks. |
