//! Authenticated transport for admitted, immutable Foundation ranges.
//! The private reader owns the native R2 binding. Body chunks stay in JS.

use super::*;
use crate::slot_resolution::SourceObjectIdentity;

const FOUNDATION_PREFIX: &str = "compact-v2/blockzilla-20261004";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const EXPIRY_SECONDS: u64 = 30;

#[derive(Clone)]
pub(super) struct Config {
    endpoint: worker::Url,
    secret: String,
}

struct RequestPlan {
    url: String,
    expires: String,
    signature: String,
}

impl Config {
    pub(super) fn from_env(
        env: &worker::Env,
        archive_prefix: &str,
    ) -> std::result::Result<Option<Self>, String> {
        let endpoint = optional_var(env, "BZ_NATIVE_READER_URL");
        let secret = optional_var(env, "BZ_NATIVE_READER_SECRET");
        match (endpoint, secret) {
            (None, None) => Ok(None),
            (Some(endpoint), Some(secret)) => {
                if archive_prefix != FOUNDATION_PREFIX {
                    return Err("native reader requires the admitted Foundation prefix".into());
                }
                Ok(Some(Self::parse(&endpoint, secret, false)?))
            }
            _ => Err("native reader URL and secret must both be configured".into()),
        }
    }

    fn parse(
        endpoint: &str,
        secret: String,
        allow_test_loopback: bool,
    ) -> std::result::Result<Self, String> {
        let mut endpoint =
            worker::Url::parse(endpoint).map_err(|_| "native reader URL is invalid".to_string())?;
        let test_loopback = cfg!(test)
            && allow_test_loopback
            && endpoint.scheme() == "http"
            && matches!(
                endpoint.host_str(),
                Some("localhost" | "127.0.0.1" | "[::1]")
            );
        if (endpoint.scheme() != "https" && !test_loopback)
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !matches!(endpoint.path(), "" | "/" | "/v1/range")
        {
            return Err("native reader URL must be a private HTTPS range endpoint".into());
        }
        if secret.len() < 32 || secret.len() > 1024 {
            return Err("native reader secret must contain 32 to 1024 UTF-8 bytes".into());
        }
        endpoint.set_path("/v1/range");
        Ok(Self { endpoint, secret })
    }

    fn plan(
        &self,
        path: &str,
        offset: u64,
        len: usize,
        identity: &SourceObjectIdentity,
        now_seconds: u64,
    ) -> std::result::Result<RequestPlan, String> {
        validate_range(path, offset, len, identity)?;
        let expires = now_seconds
            .checked_add(EXPIRY_SECONDS)
            .filter(|n| *n <= MAX_SAFE_INTEGER)
            .ok_or("native reader expiry is invalid")?;
        let signature = range_signature(&self.secret, expires, path, offset, len, identity)?;
        let expires = expires.to_string();
        let offset = offset.to_string();
        let length = len.to_string();
        let object_length = identity.length.to_string();
        let mut url = self.endpoint.clone();
        url.query_pairs_mut()
            .append_pair("key", path)
            .append_pair("offset", &offset)
            .append_pair("length", &length)
            .append_pair("object_length", &object_length)
            .append_pair("etag", &identity.etag);
        Ok(RequestPlan {
            url: url.into(),
            expires,
            signature,
        })
    }

    pub(super) async fn fetch_range(
        &self,
        source: &WorkerSource,
        path: &str,
        offset: u64,
        len: usize,
        identity: &SourceObjectIdentity,
    ) -> std::result::Result<Response, String> {
        // now_ms() is a monotonic profile clock and cannot sign Unix expiry.
        let now_seconds = (js_sys::Date::now() / 1000.0).floor();
        if !now_seconds.is_finite() || now_seconds < 0.0 {
            return Err("native reader clock is invalid".into());
        }
        let plan = self.plan(path, offset, len, identity, now_seconds as u64)?;
        let headers = Headers::new();
        headers
            .set("X-BZ-Reader-Expires", &plan.expires)
            .and_then(|_| headers.set("X-BZ-Reader-Signature", &plan.signature))
            .and_then(|_| headers.set("Accept-Encoding", "identity"))
            .and_then(|_| headers.set("Cache-Control", "no-store"))
            .map_err(|_| "native reader request headers are invalid".to_string())?;
        let mut init = RequestInit::new();
        init.with_method(Method::Get)
            .with_headers(headers)
            .with_redirect(worker::RequestRedirect::Manual);
        let request = Request::new_with_init(&plan.url, &init)
            .map_err(|_| "native reader request is invalid".to_string())?;
        source.backend_read.mark();
        source.storage_metrics.attempt_reader_http();
        let started = now_ms();
        let response = Fetch::Request(request)
            .send()
            .await
            .map_err(|_| "native reader HTTP request failed".to_string())?;
        let status = response.status_code();
        let headers = response.headers();
        let header = |name: &str| {
            headers
                .get(name)
                .map_err(|_| "native reader response headers are invalid".to_string())
        };
        let backend = header("X-BZ-Reader-Backend")?;
        let gets = header("X-BZ-Reader-R2-GETs")?;
        let heads = header("X-BZ-Reader-R2-HEADs")?;
        let attempted = validate_proof(backend.as_deref(), gets.as_deref(), heads.as_deref())?;
        if attempted {
            source
                .storage_metrics
                .attempt_get(StorageBackend::FoundationR2);
        }
        let upstream_colo = header("CF-Ray")?
            .and_then(|ray| ray.rsplit_once('-').map(|(_, colo)| colo.to_owned()))
            .filter(|colo| colo.len() <= 8 && colo.bytes().all(|b| b.is_ascii_alphanumeric()))
            .unwrap_or_default();
        source.record_elapsed(
            if path.ends_with("signatures.bin") {
                "signature_headers"
            } else {
                "block_headers"
            },
            started,
            len as u64,
            format!("native_r2_collector={upstream_colo}"),
            Some(status),
        );
        if status != 206 {
            return Err(format!("native reader range returned HTTP {status}"));
        }
        let expected = header("X-BZ-Reader-Expected-Bytes")?;
        let etag = header("ETag")?;
        let content_length = header("Content-Length")?;
        let content_range = header("Content-Range")?;
        let content_encoding = header("Content-Encoding")?;
        validate_success_headers(
            attempted,
            len,
            offset,
            identity,
            expected.as_deref(),
            etag.as_deref(),
            content_length.as_deref(),
            content_range.as_deref(),
            content_encoding.as_deref(),
        )?;
        // The caller checks complete bytes for JSON, or attaches the existing
        // native exact-length stream and deferred completion receipt for binary.
        Ok(response)
    }
}

pub(super) fn canonical_range_message(
    expires: u64,
    path: &str,
    offset: u64,
    len: usize,
    identity: &SourceObjectIdentity,
) -> std::result::Result<String, String> {
    validate_range(path, offset, len, identity)?;
    if expires > MAX_SAFE_INTEGER {
        return Err("native reader expiry is invalid".into());
    }
    Ok(format!(
        "range-v1\n{expires}\n{path}\n{offset}\n{len}\n{}\n{}",
        identity.length, identity.etag
    ))
}

pub(super) fn range_signature(
    secret: &str,
    expires: u64,
    path: &str,
    offset: u64,
    len: usize,
    identity: &SourceObjectIdentity,
) -> std::result::Result<String, String> {
    let message = canonical_range_message(expires, path, offset, len, identity)?;
    // Use literal UTF-8 key bytes, including secrets that contain hex text.
    Ok(hex_lower(&hmac_sha256(
        secret.as_bytes(),
        message.as_bytes(),
    )))
}

fn validate_range(
    path: &str,
    offset: u64,
    len: usize,
    identity: &SourceObjectIdentity,
) -> std::result::Result<(), String> {
    let suffix = path
        .strip_prefix(FOUNDATION_PREFIX)
        .and_then(|s| s.strip_prefix("/epoch-"))
        .and_then(|s| s.split_once('/'))
        .filter(|(epoch, file)| {
            canonical_integer(epoch).is_some()
                && matches!(*file, "archive-v2-blocks.zstd" | "signatures.bin")
        });
    if suffix.is_none()
        || !valid_etag(&identity.etag)
        || len == 0
        || len > MAX_ARCHIVE_RANGE_BYTES
        || identity.length > MAX_SAFE_INTEGER
        || offset > MAX_SAFE_INTEGER
        || offset
            .checked_add(len as u64)
            .is_none_or(|end| end > identity.length)
    {
        return Err("native reader range or object identity is invalid".into());
    }
    Ok(())
}

fn canonical_integer(text: &str) -> Option<u64> {
    if text.is_empty()
        || text.len() > 16
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    text.parse().ok().filter(|n| *n <= MAX_SAFE_INTEGER)
}

fn valid_etag(etag: &str) -> bool {
    if etag.len() > 128 {
        return false;
    }
    let Some(value) = etag.strip_prefix('"').and_then(|s| s.strip_suffix('"')) else {
        return false;
    };
    let (digest, parts) = value
        .split_once('-')
        .map_or((value, None), |(d, p)| (d, Some(p)));
    digest.len() == 32
        && digest.bytes().all(|b| b.is_ascii_hexdigit())
        && parts.is_none_or(|p| {
            !p.starts_with('0') && !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())
        })
}

fn validate_proof(
    backend: Option<&str>,
    gets: Option<&str>,
    heads: Option<&str>,
) -> std::result::Result<bool, String> {
    if backend != Some("native-r2") || heads != Some("0") {
        return Err("native reader R2 proof is invalid".into());
    }
    match gets {
        Some("0") => Ok(false),
        Some("1") => Ok(true),
        _ => Err("native reader R2 proof is invalid".into()),
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_success_headers(
    attempted: bool,
    len: usize,
    offset: u64,
    identity: &SourceObjectIdentity,
    expected: Option<&str>,
    etag: Option<&str>,
    length: Option<&str>,
    range: Option<&str>,
    encoding: Option<&str>,
) -> std::result::Result<(), String> {
    let length_text = len.to_string();
    let range_text = format!(
        "bytes {offset}-{}/{}",
        offset + len as u64 - 1,
        identity.length
    );
    if !attempted
        || expected != Some(length_text.as_str())
        || etag != Some(identity.etag.as_str())
        || length != Some(length_text.as_str())
        || range != Some(range_text.as_str())
        || encoding.is_some_and(|value| value != "identity")
    {
        return Err("native reader range identity or length differs".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "compact-v2/blockzilla-20261004/epoch-1090/archive-v2-blocks.zstd";
    const SECRET: &str = "foundation-reader-protocol-test-secret-0123456789";

    fn identity() -> SourceObjectIdentity {
        SourceObjectIdentity {
            length: 63_486_272_838,
            etag: "\"55095261656b29000364d6621a28a17e-947\"".into(),
        }
    }

    #[test]
    fn request_matches_independent_node_and_webcrypto_hmac_vector() {
        let config = Config::parse("https://reader.example", SECRET.into(), false).unwrap();
        let plan = config
            .plan(KEY, 15_917_107_745, 117_962, &identity(), 1_800_000_000)
            .unwrap();
        assert_eq!(plan.expires, "1800000030");
        assert_eq!(
            plan.signature,
            "32997aad9972f513740b9ecd5b5b480f261be8f69e7e76ef58e175e39bdf7b2a"
        );
        assert_eq!(
            canonical_range_message(1_800_000_030, KEY, 15_917_107_745, 117_962, &identity())
                .unwrap(),
            "range-v1\n1800000030\ncompact-v2/blockzilla-20261004/epoch-1090/archive-v2-blocks.zstd\n15917107745\n117962\n63486272838\n\"55095261656b29000364d6621a28a17e-947\""
        );
        let url = worker::Url::parse(&plan.url).unwrap();
        assert_eq!(url.path(), "/v1/range");
        let pairs = url.query_pairs().collect::<BTreeMap<_, _>>();
        assert_eq!(pairs.len(), 5);
        assert_eq!(pairs["key"], KEY);
        assert_eq!(pairs["etag"], identity().etag);
        assert_eq!(pairs["object_length"], "63486272838");
    }

    #[test]
    fn endpoint_and_source_identity_fail_closed_before_http() {
        for url in [
            "http://reader.example/v1/range",
            "https://user:pass@reader.example/v1/range",
            "https://reader.example/v1/range?x=1",
            "https://reader.example/v1/range#fragment",
            "https://reader.example/redirect",
            "http://127.0.0.1:8080/v1/range",
        ] {
            assert!(Config::parse(url, SECRET.into(), false).is_err(), "{url}");
        }
        assert!(Config::parse("http://127.0.0.1:8080", SECRET.into(), true).is_ok());
        let config =
            Config::parse("https://reader.example/v1/range", SECRET.into(), false).unwrap();
        for key in [
            "../signatures.bin",
            "compact-v2/blockzilla-20261004/epoch-01/signatures.bin",
            "compact-v2/blockzilla-20261004/epoch-1/registry.bin",
            "compact-v2/blockzilla-20261004/epoch-1/signatures.bin\n",
        ] {
            assert!(config.plan(key, 0, 1, &identity(), 1_800_000_000).is_err());
        }
        assert!(
            config
                .plan(KEY, identity().length, 1, &identity(), 1_800_000_000)
                .is_err()
        );
        assert!(config.plan(KEY, 0, 0, &identity(), 1_800_000_000).is_err());
        assert!(
            config
                .plan(
                    KEY,
                    0,
                    MAX_ARCHIVE_RANGE_BYTES + 1,
                    &identity(),
                    1_800_000_000
                )
                .is_err()
        );
        for etag in [
            "W/\"55095261656b29000364d6621a28a17e\"",
            "\"55095261656b29000364d6621a28a17e-0\"",
            "\"opaque\"",
        ] {
            let mut bad = identity();
            bad.etag = etag.into();
            assert!(config.plan(KEY, 0, 1, &bad, 1_800_000_000).is_err());
        }
    }

    #[test]
    fn proof_and_range_headers_distinguish_attempts_from_complete_bodies() {
        assert_eq!(
            validate_proof(Some("native-r2"), Some("0"), Some("0")),
            Ok(false)
        );
        assert_eq!(
            validate_proof(Some("native-r2"), Some("1"), Some("0")),
            Ok(true)
        );
        for (backend, gets, heads) in [
            (None, Some("1"), Some("0")),
            (Some("native-r2"), Some("2"), Some("0")),
            (Some("native-r2"), Some("1"), Some("1")),
        ] {
            assert!(validate_proof(backend, gets, heads).is_err());
        }
        let identity = identity();
        let valid = |attempted, expected, etag, length, range, encoding| {
            validate_success_headers(
                attempted, 10, 20, &identity, expected, etag, length, range, encoding,
            )
        };
        let range = "bytes 20-29/63486272838";
        assert!(
            valid(
                true,
                Some("10"),
                Some(&identity.etag),
                Some("10"),
                Some(range),
                None
            )
            .is_ok()
        );
        assert!(
            valid(
                false,
                Some("10"),
                Some(&identity.etag),
                Some("10"),
                Some(range),
                None
            )
            .is_err()
        );
        assert!(
            valid(
                true,
                Some("10"),
                Some(&identity.etag),
                Some("9"),
                Some(range),
                None
            )
            .is_err()
        );
        assert!(
            valid(
                true,
                Some("10"),
                Some(&identity.etag),
                Some("10"),
                Some("bytes 20-29/999"),
                None
            )
            .is_err()
        );
        assert!(
            valid(
                true,
                Some("10"),
                Some(&identity.etag),
                Some("10"),
                Some(range),
                Some("gzip")
            )
            .is_err()
        );
    }
}
