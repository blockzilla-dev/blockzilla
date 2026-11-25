# Provider range reader

This small Worker reads archive bytes through the provider account's native R2
binding. getBlock keeps API access, block decoding and resolution in the owner
account. The reader does not copy, change or cache archive objects.

`GET /v1/range` accepts one bounded byte range from the permitted Compact V2
block or signature files. Each request requires a short-lived HMAC-SHA256
signature and pins the object's length and ETag. The shared test vector fixes
the signature format. The response streams the checked range and reports native
R2 operation counts. All responses use `private, no-store`.

Set the account ID in `wrangler.example.jsonc` and supply `BZ_READER_SECRET`
as a Worker secret for deployment. The source example contains no credential.
Deployment is separate from this source port.

Run `npm test` from this directory after installing its dependencies, or use
getBlock's installed Miniflare package. The tests use local R2 fixtures and the
real deployment entry point. They do not contact a live provider bucket.
