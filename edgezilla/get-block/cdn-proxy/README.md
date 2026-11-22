# Pages CDN cache canary

This isolated test checks whether a normal zone cache can serve getBlock
responses before Pages Functions run. It does not change production DNS or
the existing getBlock Worker. No block files are uploaded to Pages.

The [22 November test record](../../../reports/cdn-cache-ttl-20261122/README.md)
has 64 verified CDN hits and zero observed getBlock invocations. The test
hostname remains separate from the main API. The prototype rejects queries
and compact recovery routes, and Pages currently replaces backend JSON 502
errors with a plain-text error. It is not ready for a main API cutover.

The Pages Function uses a service binding to the existing `blockzilla-get-block`
Worker. It accepts only `GET /block/<digits>.json` and `.bin`, without a query.
It sends a new request with no caller headers. The existing response body stays
a stream. The proxy does not read, clone, tee or store it.

Each Function invocation sets a new `X-Blockzilla-Proxy-Invocation` UUID.
Upstream `Age` and `CF-Cache-Status` headers are removed. Errors and unsupported
requests have `Cache-Control: no-store`. Only a status-200 response with the
upstream public, immutable, positive `max-age` policy keeps that policy.
A response with `Set-Cookie` is uncacheable, and that header is removed.

## Deploy the isolated project

Use an account login with Pages access. From this directory:

```sh
CLOUDFLARE_ACCOUNT_ID=8df0426c80fcd1a04ed439f441db9ff8 npx wrangler@4.129.0 pages project create blockzilla-getblock-cdn-canary --production-branch main
CLOUDFLARE_ACCOUNT_ID=8df0426c80fcd1a04ed439f441db9ff8 npx wrangler@4.129.0 pages deploy public --project-name blockzilla-getblock-cdn-canary --branch main
```

The configuration binds `GET_BLOCK` to `blockzilla-get-block` in our account.
The deployment contains only `_worker.js` and a small fallback `404.html`.
Advanced mode is supported by Wrangler Direct Upload. This directory does
not enable Workers Caching or use the Cache API.

Check the returned `*.pages.dev` URL first. That checks deployment and the
binding; it does not prove that our zone cache ran before the Function.
The documented outer zone cache requires a proxied Pages custom hostname.
Use a separate canary hostname, not `getblock.blockzilla.dev`.

Register that hostname on the Pages project before adding its proxied CNAME.
Add a Cache Rule scoped to that hostname and the test block paths.
Set cache eligibility to eligible and respect the origin cache headers.
Keep query strings in the key. Do not force a TTL over `no-store`, and do not
add a whole-zone rule. Start with one admitted historical slot.

## Check cache execution

Use ordinary GET requests, not HEAD. Replace the hostname below with the
registered canary hostname:

```sh
curl --silent --show-error --dump-header - --output /dev/null https://CANARY_HOST/block/470987967.bin
curl --silent --show-error --dump-header - --output /dev/null https://CANARY_HOST/block/470987967.bin
curl --silent --show-error --dump-header - --output /dev/null https://CANARY_HOST/block/470987967.json
curl --silent --show-error --dump-header - --output /dev/null https://CANARY_HOST/block/470987967.json
```

A backend `X-Blockzilla-Cache: HIT` alone is insufficient. To show that the
proxy was skipped, require an outer `CF-Cache-Status: HIT`, the same proxy UUID
on repeated requests, and the correct complete block digest. An increasing
`Age` adds supporting evidence. Compare each digest to the original Worker
at the same no-query path. Do not save block bodies in the report.

Check a query, an unsupported path, POST and an unavailable slot. They must
stay uncacheable, and repeated error requests must get different proxy UUIDs.
An outer cache miss can still reach a warm getBlock response cache. Report
those two cache states separately. After the test, remove only the canary
rule, hostname, DNS record and Pages project that this test created.

## Cost claim to test

The intended path is **zone cache → Pages Function on miss → existing Worker**.
Pages documents that a zone-cache response can arrive before Pages Functions
run. Requests that do not invoke a Function are free under Pages pricing.
On Standard pricing, a service binding adds no second Worker request fee;
CPU time across the Function and backend is still charged on a miss.
The test record provides the measured HTTP and getBlock counter result.
Pages per-project invocation metrics were unavailable. No invoice claim is made.

Sources: [Pages caching](https://developers.cloudflare.com/pages/configuration/serving-pages/),
[Pages service bindings](https://developers.cloudflare.com/pages/functions/bindings/#service-bindings),
[Pages pricing](https://developers.cloudflare.com/pages/functions/pricing/),
[Worker service-binding pricing](https://developers.cloudflare.com/workers/platform/pricing/#service-bindings),
and [Direct Upload](https://developers.cloudflare.com/pages/get-started/direct-upload/).
