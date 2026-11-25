# blockzilla-source-http

HTTP byte ranges with pinned object identities.

This crate does not depend on an archive format or reader.

Exact range reads require HTTP 206, the requested range, the expected length,
and the pinned object identity. Invalid successful responses and changed
identities are not retried.

## Retries

`HttpRangeSourceOptions::retry_policy` (`HttpRetryPolicy`) controls retries for
each HEAD, ranged GET and full GET call. The source retries after:

- a transport error before a response: connect failure, timeout, or a reset or
  closed connection;
- HTTP 429, 500, 502, 503 or 504;
- a body read error, or a body that ends before the expected length.

The budgets are nested, as in the earlier fixed policy. One call has up to
`max_attempts` body attempts; a body that fails or ends early starts the next
one at once. Each body attempt has up to `max_attempts` requests for errors
before a response and for 429 or 5xx statuses. Retry `n` of one body attempt
waits `initial_backoff * 2^n`, but not more than `max_backoff`. A numeric
`Retry-After` on 429 or 5xx sets the minimum wait. A value above
`max_backoff`, or a date, fails at once without an early retry.

The default is 3 attempts, 250 ms initial backoff and a 5 s cap. These are the
values of the earlier fixed 5xx policy, so one read can send up to nine GETs,
as before. New: errors before a response (connect failure, timeout, reset or
closed connection, DNS or TLS failure) and HTTP 429 also retry. A multi-hour
stream can use a larger budget, for example 8 attempts and a 30 s cap.

Each retry is a new request that passes all identity checks again, so a retry
cannot return different bytes. Error bodies are dropped without being read. No
partial or error body enters a cache.

## Statistics

`stats()` keeps its counters. Request counts include retries.
`server_error_retries` counts GET retries after 5xx, and
`incomplete_body_retries` counts GET retries after a body error. Body counters
include bytes consumed by the reader. `retry_stats()` counts every retry by
cause, for HEAD and GET.

## Private S3 and R2 buckets

`HttpRangeSource::with_signer` takes an `HttpRequestSigner`. The source calls it
for every attempt, after it sets its own `Range` and `Accept-Encoding` headers.
`S3SigV4Signer` implements AWS Signature Version 4 for the S3 API:

```rust,ignore
let credentials = S3Credentials::from_env()?; // AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
let source = HttpRangeSource::with_signer(
    "https://<account>.r2.cloudflarestorage.com/<bucket>/<prefix>",
    epoch,
    Arc::new(S3SigV4Signer::for_r2(credentials)), // region "auto", service "s3"
    HttpRangeSourceOptions {
        object_path_layout: HttpObjectPathLayout::FlatObjects,
        ..HttpRangeSourceOptions::default()
    },
)?;
```

Use path-style URLs. The signer sends `x-amz-content-sha256: UNSIGNED-PAYLOAD`,
because GET and HEAD requests have no body; S3 and R2 accept it.
`S3PayloadHash::EmptyBody` sends the SHA-256 of an empty body instead. The
signed headers are `host`, `range` when present, and each `x-amz-*` header
(`x-amz-date`, `x-amz-content-sha256`, and `x-amz-security-token` with a
session token). `Debug` output and errors never contain the secret key or the
session token.

HTTP sources recommend up to eight concurrent reads. Each format reader applies
its own input-buffer limit; this hint does not create threads in this crate.
