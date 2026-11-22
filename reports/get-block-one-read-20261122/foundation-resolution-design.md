# Proposed Foundation resolution service

This is a design record. No Foundation service was deployed by this test.
The public API stays on the owner Cloudflare account.

1. A Worker response-cache hit returns the complete stored response.
2. On a miss, the Worker asks Foundation for the slot and archive generation.
3. Foundation returns a complete block plus its block-local access data if
   the block is in its local cache.
4. Otherwise, Foundation returns only the access data and a pinned descriptor
   for the compressed block range in the existing Foundation bucket.
5. The Worker reads that one range, joins the binary streams or renders JSON,
   and caches the result.

The access data must contain the raw keys and hashes for the used IDs, ordered
raw signatures, per-transaction signature counts, current blockhash, actual
previous blockhash and parent slot. It must bind these bytes to the requested
slot, schema, archive generation, source size and source ETag. A slot-minus-one
hash is not a valid substitute for the actual parent hash.

The original ID registries can remain on Foundation SSD with a bounded RAM
page/cache policy. A block in this sample uses about 1,200–2,900 pubkey IDs.
A small response does not imply one physical disk read on the host. The
service should batch nearby lookups and cache popular registry pages and
completed block resolutions. Physical disk reads and bytes per miss need
measurement. The browser needs no epoch registry. A service that has
only generic ID registries cannot know the IDs for a slot before it reads and
decodes the block. To avoid that dependency on a block-cache miss, it needs a
small slot-to-used-ID record, or a prebuilt complete per-slot resolution.
The exact four saved access blobs need 35,124 raw bytes of typed 32-bit IDs
(8,781 bytes per block) instead of 309,804 resolved dictionary bytes. Add
counts, slot/source headers, parent/hash data and range descriptors. Signature
counts add about 380 bytes per selected block. This is a four-block sample;
all four have no vote-hash entries. These sizes do not measure a complete
service index or a full epoch.

The current saved resolutions already contain the latter shape. The service
can read signatures from the original local signature file by their contiguous
range; it need not duplicate them inside each stored resolution.

A possible first-miss improvement is to send the pinned block range descriptor
in the response headers before streaming the access body. The Worker can start
the bucket range read while Foundation resolves keys and streams signatures.
This is a proposed overlap, not a measured speed gain. Streaming headers and
body separately are supported by the [Workers Streams API](https://developers.cloudflare.com/workers/runtime-apis/streams/).
With a cached descriptor, the Worker can start both requests at once.

The current cross-account source path uses the Foundation S3 endpoint. This
design does not establish a cross-account native R2 binding. The service must
have a bounded disk/cache policy and a defined unavailable-service path; an
immutable cached access record can avoid a live service call for repeated
blocks. Cache keys must include the source generation and content identity.

The existing locator HMAC binds its range descriptor. It does not authenticate
arbitrary replacement dictionary bytes from a client. The access body must
come from the trusted service and use a checked content identity before it
enters shared caches.

The four saved complete access blobs total 417,719 bytes, or 104,429.75 bytes per
block. At one million uncached service responses of this sample size, this is
about 104.43 GB of Foundation outbound access data before transport framing or
compression. Complete block-cache hits add the block payload to that host
traffic. This is a traffic projection, not a host bandwidth price.

This path can reduce cloud storage operations to one bucket GET on a miss and
zero on a complete block-cache hit at Foundation. It still has native server,
disk, outbound bandwidth, request and Worker CPU costs. Latency and total cost
need a separate measured test. The one-bundle test in this report does not
measure this service.
