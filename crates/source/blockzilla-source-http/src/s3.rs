//! AWS Signature Version 4 for S3-compatible object stores, such as
//! Cloudflare R2.

use std::{
    collections::BTreeMap,
    ffi::OsString,
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};
use url::Url;

use blockzilla_source::{SourceError, SourceResult};

use crate::signing::{HttpRequestSigner, HttpRequestToSign};

const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const SERVICE: &str = "s3";
const R2_REGION: &str = "auto";
const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
const EMPTY_BODY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const ACCESS_KEY_ID_VARIABLE: &str = "AWS_ACCESS_KEY_ID";
const SECRET_ACCESS_KEY_VARIABLE: &str = "AWS_SECRET_ACCESS_KEY";
const SESSION_TOKEN_VARIABLE: &str = "AWS_SESSION_TOKEN";

/// Access keys for an S3-compatible object store.
///
/// `Debug` shows only the access key ID. It never shows the secret access key
/// or the session token. Errors never contain a key value.
#[derive(Clone)]
pub struct S3Credentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}

impl fmt::Debug for S3Credentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("S3Credentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl S3Credentials {
    /// Check and keep one set of keys.
    ///
    /// The access key ID must be visible ASCII without `/` or `,`. The secret
    /// must not be empty. A session token must be visible ASCII.
    pub fn new(
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        session_token: Option<String>,
    ) -> SourceResult<Self> {
        let access_key_id = access_key_id.into();
        let secret_access_key = secret_access_key.into();
        if access_key_id.is_empty()
            || !access_key_id
                .bytes()
                .all(|byte| matches!(byte, 0x21..=0x7e) && byte != b'/' && byte != b',')
        {
            return Err(protocol(
                "S3 access key ID must be non-empty visible ASCII without '/' or ','",
            ));
        }
        if secret_access_key.is_empty() {
            return Err(protocol("S3 secret access key is empty"));
        }
        if let Some(token) = &session_token
            && (token.is_empty() || !token.bytes().all(|byte| matches!(byte, 0x21..=0x7e)))
        {
            return Err(protocol("S3 session token must be non-empty visible ASCII"));
        }
        Ok(Self {
            access_key_id,
            secret_access_key,
            session_token,
        })
    }

    /// Read `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and the optional
    /// `AWS_SESSION_TOKEN`.
    ///
    /// An unset or empty `AWS_SESSION_TOKEN` gives no session token. An error
    /// names the variable. It never contains a value.
    pub fn from_env() -> SourceResult<Self> {
        Self::from_lookup(|name| std::env::var_os(name))
    }

    fn from_lookup(lookup: impl Fn(&str) -> Option<OsString>) -> SourceResult<Self> {
        let unicode = |name: &str, value: OsString| {
            value
                .into_string()
                .map_err(|_| protocol(format!("environment variable {name} is not valid Unicode")))
        };
        let required = |name: &str| {
            let value = lookup(name)
                .ok_or_else(|| protocol(format!("environment variable {name} is not set")))?;
            let value = unicode(name, value)?;
            if value.is_empty() {
                return Err(protocol(format!("environment variable {name} is empty")));
            }
            Ok(value)
        };
        let access_key_id = required(ACCESS_KEY_ID_VARIABLE)?;
        let secret_access_key = required(SECRET_ACCESS_KEY_VARIABLE)?;
        let session_token = match lookup(SESSION_TOKEN_VARIABLE) {
            Some(value) => Some(unicode(SESSION_TOKEN_VARIABLE, value)?),
            None => None,
        }
        .filter(|token| !token.is_empty());
        Self::new(access_key_id, secret_access_key, session_token)
    }

    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }

    pub fn has_session_token(&self) -> bool {
        self.session_token.is_some()
    }
}

/// Value of the `x-amz-content-sha256` header.
///
/// The source sends only GET and HEAD requests, which have no body.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum S3PayloadHash {
    /// `UNSIGNED-PAYLOAD`. This is the default. S3 and R2 accept it for GET
    /// and HEAD. The signature still covers the method, path, query, host,
    /// range and time.
    #[default]
    Unsigned,
    /// The SHA-256 of an empty body, the exact hash for a request without a
    /// body.
    EmptyBody,
}

impl S3PayloadHash {
    fn header_value(self) -> &'static str {
        match self {
            Self::Unsigned => UNSIGNED_PAYLOAD,
            Self::EmptyBody => EMPTY_BODY_SHA256,
        }
    }
}

/// AWS Signature Version 4 signer for S3 GET and HEAD requests.
///
/// Give it to [`HttpRangeSource::with_signer`](crate::HttpRangeSource::with_signer).
/// Use a path-style base URL, for example
/// `https://<account>.r2.cloudflarestorage.com/<bucket>/<prefix>`, with
/// [`HttpObjectPathLayout::FlatObjects`](crate::HttpObjectPathLayout::FlatObjects).
/// Cloudflare R2 uses the region `auto`; see [`S3SigV4Signer::for_r2`].
///
/// For each request the signer sets `x-amz-date`, `x-amz-content-sha256`,
/// `x-amz-security-token` (only with a session token) and `Authorization`.
/// It signs `host`, `range` when present, and each `x-amz-*` header. The
/// canonical request URI-encodes each path segment and each query name and
/// value (RFC 3986 unreserved characters stay as they are), and sorts the
/// query and the headers.
///
/// The signer uses the system clock. S3 rejects a signature when the clock
/// is wrong by more than about 15 minutes. `Debug` does not show secrets.
#[derive(Debug, Clone)]
pub struct S3SigV4Signer {
    credentials: S3Credentials,
    region: String,
    payload_hash: S3PayloadHash,
}

impl S3SigV4Signer {
    /// Signer for one region, for example `us-east-1`. The service is `s3`.
    pub fn new(credentials: S3Credentials, region: impl Into<String>) -> SourceResult<Self> {
        let region = region.into();
        if region.is_empty()
            || !region
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(protocol(
                "S3 region must be non-empty ASCII letters, digits, '-' or '_'",
            ));
        }
        Ok(Self {
            credentials,
            region,
            payload_hash: S3PayloadHash::default(),
        })
    }

    /// Signer for Cloudflare R2, which uses the region `auto`.
    pub fn for_r2(credentials: S3Credentials) -> Self {
        Self {
            credentials,
            region: R2_REGION.to_owned(),
            payload_hash: S3PayloadHash::default(),
        }
    }

    /// Use another `x-amz-content-sha256` value. The default is
    /// [`S3PayloadHash::Unsigned`].
    pub fn with_payload_hash(mut self, payload_hash: S3PayloadHash) -> Self {
        self.payload_hash = payload_hash;
        self
    }

    pub fn region(&self) -> &str {
        &self.region
    }

    pub fn credentials(&self) -> &S3Credentials {
        &self.credentials
    }

    fn sign_at(&self, request: &mut HttpRequestToSign<'_>, time: SystemTime) -> SourceResult<()> {
        let method = request.method;
        let url = request.url;
        let amz_date = amz_date(time)?;
        let payload_hash = self.payload_hash.header_value();
        request.set_header("x-amz-date", &amz_date)?;
        request.set_header("x-amz-content-sha256", payload_hash)?;
        if let Some(token) = &self.credentials.session_token {
            request.set_header("x-amz-security-token", token)?;
        }
        let mut headers = BTreeMap::<String, Vec<String>>::new();
        headers.insert("host".into(), vec![url_host(url)?]);
        for (name, value) in request.headers() {
            if name == "range" || name.starts_with("x-amz-") {
                let value = std::str::from_utf8(value)
                    .map_err(|_| protocol(format!("header {name} is not valid UTF-8 for SigV4")))?;
                headers
                    .entry(name.to_owned())
                    .or_default()
                    .push(value.to_owned());
            }
        }
        let canonical = CanonicalRequest {
            method: method.as_str(),
            uri: canonical_uri(url),
            query: canonical_query(url),
            headers,
            payload_hash,
        };
        let authorization = self.authorization(&canonical, &amz_date);
        request.set_header("authorization", &authorization)
    }

    fn authorization(&self, canonical: &CanonicalRequest<'_>, amz_date: &str) -> String {
        let date = &amz_date[..8];
        let scope = format!("{date}/{}/{SERVICE}/aws4_request", self.region);
        let string_to_sign = format!(
            "{ALGORITHM}\n{amz_date}\n{scope}\n{}",
            hex(&Sha256::digest(canonical.text()))
        );
        let key = signing_key(&self.credentials.secret_access_key, date, &self.region);
        let signature = hex(&hmac_sha256(&key, string_to_sign.as_bytes()));
        format!(
            "{ALGORITHM} Credential={}/{scope}, SignedHeaders={}, Signature={signature}",
            self.credentials.access_key_id,
            canonical.signed_headers()
        )
    }

    /// Build the `Authorization` value from parts that a test server received.
    #[cfg(test)]
    pub(crate) fn authorization_for_parts(
        &self,
        method: &str,
        url: &Url,
        headers: &[(&str, &str)],
        amz_date: &str,
    ) -> String {
        let mut signed = BTreeMap::<String, Vec<String>>::new();
        for (name, value) in headers {
            signed
                .entry(name.to_ascii_lowercase())
                .or_default()
                .push((*value).to_owned());
        }
        let canonical = CanonicalRequest {
            method,
            uri: canonical_uri(url),
            query: canonical_query(url),
            headers: signed,
            payload_hash: self.payload_hash.header_value(),
        };
        self.authorization(&canonical, amz_date)
    }
}

impl HttpRequestSigner for S3SigV4Signer {
    fn sign(&self, request: &mut HttpRequestToSign<'_>) -> SourceResult<()> {
        self.sign_at(request, SystemTime::now())
    }
}

struct CanonicalRequest<'a> {
    method: &'a str,
    uri: String,
    query: String,
    /// Lower-case names in sorted order, each with its values in order.
    headers: BTreeMap<String, Vec<String>>,
    payload_hash: &'a str,
}

impl CanonicalRequest<'_> {
    fn signed_headers(&self) -> String {
        self.headers
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(";")
    }

    fn text(&self) -> String {
        let mut text = format!("{}\n{}\n{}\n", self.method, self.uri, self.query);
        for (name, values) in &self.headers {
            let values = values
                .iter()
                .map(|value| value.split_ascii_whitespace().collect::<Vec<_>>().join(" "))
                .collect::<Vec<_>>()
                .join(",");
            text.push_str(name);
            text.push(':');
            text.push_str(&values);
            text.push('\n');
        }
        text.push('\n');
        text.push_str(&self.signed_headers());
        text.push('\n');
        text.push_str(self.payload_hash);
        text
    }
}

/// Host header value as the HTTP client sends it: the port only when it is not
/// the default port of the scheme.
fn url_host(url: &Url) -> SourceResult<String> {
    let host = url
        .host_str()
        .ok_or_else(|| protocol("SigV4 request URL has no host"))?;
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}

/// Decode each path segment, then URI-encode it. Keep the `/` separators.
fn canonical_uri(url: &Url) -> String {
    let path = url.path();
    let mut uri = String::with_capacity(path.len() + 8);
    for (index, segment) in path.split('/').enumerate() {
        if index != 0 {
            uri.push('/');
        }
        uri_encode_into(&percent_decode(segment), &mut uri);
    }
    if uri.is_empty() {
        uri.push('/');
    }
    uri
}

/// Decode, URI-encode and sort the query pairs. A name without `=` gets an
/// empty value.
fn canonical_query(url: &Url) -> String {
    let Some(query) = url.query() else {
        return String::new();
    };
    let mut pairs = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            let mut encoded_name = String::new();
            let mut encoded_value = String::new();
            uri_encode_into(&percent_decode(name), &mut encoded_name);
            uri_encode_into(&percent_decode(value), &mut encoded_value);
            (encoded_name, encoded_value)
        })
        .collect::<Vec<_>>();
    pairs.sort_unstable();
    pairs
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn percent_decode(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && let (Some(high), Some(low)) = (
                bytes.get(index + 1).copied().and_then(hex_value),
                bytes.get(index + 2).copied().and_then(hex_value),
            )
        {
            decoded.push((high << 4) | low);
            index += 3;
            continue;
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    decoded
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// URI-encode with RFC 3986 rules: keep `A-Z a-z 0-9 - _ . ~`, encode all
/// other bytes as `%XX` with upper-case hex.
fn uri_encode_into(bytes: &[u8], encoded: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    text
}

fn signing_key(secret_access_key: &str, date: &str, region: &str) -> [u8; 32] {
    let mut secret = Vec::with_capacity(4 + secret_access_key.len());
    secret.extend_from_slice(b"AWS4");
    secret.extend_from_slice(secret_access_key.as_bytes());
    let date_key = hmac_sha256(&secret, date.as_bytes());
    let region_key = hmac_sha256(&date_key, region.as_bytes());
    let service_key = hmac_sha256(&region_key, SERVICE.as_bytes());
    hmac_sha256(&service_key, b"aws4_request")
}

/// HMAC-SHA256 as in RFC 2104, with a 64-byte block.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_BYTES: usize = 64;
    let mut block = [0_u8; BLOCK_BYTES];
    if key.len() > BLOCK_BYTES {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|byte| byte ^ 0x36));
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(block.map(|byte| byte ^ 0x5c));
    outer.update(inner);
    let mut tag = [0_u8; 32];
    tag.copy_from_slice(&outer.finalize());
    tag
}

/// Format a time as `YYYYMMDDTHHMMSSZ` in UTC.
fn amz_date(time: SystemTime) -> SourceResult<String> {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| protocol("system clock is before 1970"))?
        .as_secs();
    let (year, month, day) = civil_from_days(seconds / 86_400);
    let second_of_day = seconds % 86_400;
    Ok(format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        second_of_day / 3_600,
        second_of_day / 60 % 60,
        second_of_day % 60
    ))
}

/// Gregorian calendar date for a day count from 1970-01-01. This is the
/// `civil_from_days` algorithm of Howard Hinnant for non-negative days.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

fn protocol(message: impl Into<String>) -> SourceError {
    SourceError::Protocol(message.into())
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, time::Duration};

    use reqwest::{
        Method,
        header::{HeaderMap, HeaderValue, RANGE},
    };

    use super::*;

    const EXAMPLE_ACCESS_KEY_ID: &str = "AKIAIOSFODNN7EXAMPLE";
    const EXAMPLE_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    fn hex_bytes(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231() {
        let large_key = [0xaa_u8; 131];
        let cases: [(&[u8], &[u8], &str); 4] = [
            // Test case 1.
            (
                &[0x0b; 20],
                b"Hi There",
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            // Test case 2.
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            // Test case 6: a key longer than one block is hashed first.
            (
                &large_key,
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            ),
            // Test case 7: a long key and a long message.
            (
                &large_key,
                b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
                "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            ),
        ];
        for (key, message, expected) in cases {
            assert_eq!(hmac_sha256(key, message).to_vec(), hex_bytes(expected));
        }
    }

    #[test]
    fn amz_date_formats_utc_calendar_dates() {
        let at = |seconds: u64| amz_date(UNIX_EPOCH + Duration::from_secs(seconds)).unwrap();
        assert_eq!(at(0), "19700101T000000Z");
        assert_eq!(at(1_369_353_600), "20130524T000000Z");
        assert_eq!(at(951_782_400), "20000229T000000Z");
        assert_eq!(at(1_709_251_199), "20240229T235959Z");
        assert_eq!(at(4_102_444_800), "21000101T000000Z");
        assert_eq!(at(1_795_609_496), "20261125T122456Z");
    }

    /// The published AWS example "GET Object" for S3 Signature Version 4,
    /// with `Range: bytes=0-9` on `examplebucket.s3.amazonaws.com`.
    #[test]
    fn signs_the_published_aws_get_object_example() {
        let credentials = S3Credentials::new(EXAMPLE_ACCESS_KEY_ID, EXAMPLE_SECRET, None).unwrap();
        let signer = S3SigV4Signer::new(credentials, "us-east-1")
            .unwrap()
            .with_payload_hash(S3PayloadHash::EmptyBody);
        let method = Method::GET;
        let url = Url::parse("https://examplebucket.s3.amazonaws.com/test.txt").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(RANGE, HeaderValue::from_static("bytes=0-9"));
        signer
            .sign_at(
                &mut HttpRequestToSign {
                    method: &method,
                    url: &url,
                    headers: &mut headers,
                },
                UNIX_EPOCH + Duration::from_secs(1_369_353_600),
            )
            .unwrap();

        assert_eq!(headers["x-amz-date"], "20130524T000000Z");
        assert_eq!(
            headers["x-amz-content-sha256"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(headers.get("x-amz-security-token").is_none());
        assert_eq!(
            headers["authorization"],
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
        assert!(headers["authorization"].is_sensitive());

        // The intermediate canonical request and its hash are also in the
        // AWS documentation.
        let canonical = CanonicalRequest {
            method: "GET",
            uri: canonical_uri(&url),
            query: canonical_query(&url),
            headers: [
                ("host", "examplebucket.s3.amazonaws.com"),
                ("range", "bytes=0-9"),
                ("x-amz-content-sha256", EMPTY_BODY_SHA256),
                ("x-amz-date", "20130524T000000Z"),
            ]
            .into_iter()
            .map(|(name, value)| (name.to_owned(), vec![value.to_owned()]))
            .collect(),
            payload_hash: EMPTY_BODY_SHA256,
        };
        assert_eq!(
            canonical.text(),
            "GET\n/test.txt\n\nhost:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\n\
             x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
             x-amz-date:20130524T000000Z\n\nhost;range;x-amz-content-sha256;x-amz-date\n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&Sha256::digest(canonical.text())),
            "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"
        );
    }

    /// An R2-style HEAD with a session token and `UNSIGNED-PAYLOAD`. The
    /// expected value comes from an independent Python `hmac` computation.
    #[test]
    fn signs_an_r2_head_with_a_session_token_and_unsigned_payload() {
        let credentials = S3Credentials::new(
            "0123456789abcdef0123456789abcdef",
            "r2-example-secret",
            Some("session/token+example=".into()),
        )
        .unwrap();
        let signer = S3SigV4Signer::for_r2(credentials);
        let method = Method::HEAD;
        let url = Url::parse(
            "https://account.r2.cloudflarestorage.com/solana-archive-data/epoch%20200/a+b.bin",
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        signer
            .sign_at(
                &mut HttpRequestToSign {
                    method: &method,
                    url: &url,
                    headers: &mut headers,
                },
                UNIX_EPOCH + Duration::from_secs(1_795_609_496),
            )
            .unwrap();
        assert_eq!(headers["x-amz-date"], "20261125T122456Z");
        assert_eq!(headers["x-amz-content-sha256"], "UNSIGNED-PAYLOAD");
        assert_eq!(headers["x-amz-security-token"], "session/token+example=");
        assert_eq!(headers["accept-encoding"], "identity");
        assert_eq!(
            headers["authorization"],
            "AWS4-HMAC-SHA256 Credential=0123456789abcdef0123456789abcdef/20261125/auto/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, \
             Signature=558542bf343c18496a727fe459bc0d4b0db24f1bfeae57a4987371d3508f795a"
        );
    }

    #[test]
    fn canonical_uri_and_query_use_rfc_3986_encoding() {
        let url = Url::parse(
            "https://host.example/bucket/a%20b/c+d~e_f.g-h/%C3%A9/x%2Fy/?versionId=2&acl&a=%2F&a=1&b=c d",
        )
        .unwrap();
        assert_eq!(
            canonical_uri(&url),
            "/bucket/a%20b/c%2Bd~e_f.g-h/%C3%A9/x%2Fy/"
        );
        assert_eq!(canonical_query(&url), "a=%2F&a=1&acl=&b=c%20d&versionId=2");
        let root = Url::parse("https://host.example").unwrap();
        assert_eq!(canonical_uri(&root), "/");
        assert_eq!(canonical_query(&root), "");
        let mut pushed = Url::parse("https://host.example/bucket/").unwrap();
        pushed
            .path_segments_mut()
            .unwrap()
            .pop_if_empty()
            .push("é [1]");
        assert_eq!(canonical_uri(&pushed), "/bucket/%C3%A9%20%5B1%5D");
        assert_eq!(url_host(&url).unwrap(), "host.example");
        assert_eq!(
            url_host(&Url::parse("http://127.0.0.1:8080/x").unwrap()).unwrap(),
            "127.0.0.1:8080"
        );
        assert_eq!(
            url_host(&Url::parse("https://host.example:443/x").unwrap()).unwrap(),
            "host.example"
        );
    }

    #[test]
    fn canonical_headers_trim_and_join_values() {
        let canonical = CanonicalRequest {
            method: "GET",
            uri: "/".into(),
            query: String::new(),
            headers: [(
                "x-amz-meta-test".to_owned(),
                vec!["  a   b  ".to_owned(), "c".to_owned()],
            )]
            .into_iter()
            .collect(),
            payload_hash: UNSIGNED_PAYLOAD,
        };
        assert_eq!(
            canonical.text(),
            "GET\n/\n\nx-amz-meta-test:a b,c\n\nx-amz-meta-test\nUNSIGNED-PAYLOAD"
        );
    }

    #[test]
    fn debug_never_shows_the_secret_or_the_session_token() {
        let credentials = S3Credentials::new(
            "AKIDVISIBLE",
            "very-secret-key",
            Some("very-secret-token".into()),
        )
        .unwrap();
        let signer = S3SigV4Signer::new(credentials.clone(), "eu-west-2").unwrap();
        for rendered in [format!("{credentials:?}"), format!("{signer:?}")] {
            assert!(rendered.contains("AKIDVISIBLE"), "{rendered}");
            assert!(rendered.contains("<redacted>"), "{rendered}");
            assert!(!rendered.contains("very-secret-key"), "{rendered}");
            assert!(!rendered.contains("very-secret-token"), "{rendered}");
        }
        assert!(credentials.has_session_token());
        assert_eq!(credentials.access_key_id(), "AKIDVISIBLE");
        assert_eq!(signer.region(), "eu-west-2");
        assert_eq!(signer.credentials().access_key_id(), "AKIDVISIBLE");
    }

    #[test]
    fn credentials_and_region_errors_do_not_contain_values() {
        let secret = "secret-value-that-must-not-leak";
        for error in [
            S3Credentials::new("", secret, None).unwrap_err(),
            S3Credentials::new("AKID/WITH/SLASH", secret, None).unwrap_err(),
            S3Credentials::new("AKID WITH SPACE", secret, None).unwrap_err(),
            S3Credentials::new("AKID", "", None).unwrap_err(),
            S3Credentials::new("AKID", secret, Some(String::new())).unwrap_err(),
            S3Credentials::new("AKID", secret, Some(format!("{secret}\n"))).unwrap_err(),
        ] {
            let rendered = error.to_string();
            assert!(rendered.contains("S3 "), "{rendered}");
            assert!(!rendered.contains(secret), "{rendered}");
            assert!(!rendered.contains("AKID"), "{rendered}");
        }
        let credentials = S3Credentials::new("AKID", secret, None).unwrap();
        for region in ["", "us/east", "us east"] {
            let error = S3SigV4Signer::new(credentials.clone(), region).unwrap_err();
            assert!(error.to_string().contains("S3 region"));
        }
        assert_eq!(S3SigV4Signer::for_r2(credentials).region(), "auto");
    }

    #[test]
    fn credentials_from_environment_name_the_missing_variable_only() {
        let lookup = |values: &[(&str, &str)]| {
            let values = values
                .iter()
                .map(|(name, value)| ((*name).to_owned(), OsString::from(*value)))
                .collect::<HashMap<_, _>>();
            move |name: &str| values.get(name).cloned()
        };
        let missing_key =
            S3Credentials::from_lookup(lookup(&[("AWS_SECRET_ACCESS_KEY", "secret-from-env")]))
                .unwrap_err()
                .to_string();
        assert!(
            missing_key.contains("AWS_ACCESS_KEY_ID is not set"),
            "{missing_key}"
        );
        assert!(!missing_key.contains("secret-from-env"));

        let missing_secret =
            S3Credentials::from_lookup(lookup(&[("AWS_ACCESS_KEY_ID", "AKIDFROMENV")]))
                .unwrap_err()
                .to_string();
        assert!(
            missing_secret.contains("AWS_SECRET_ACCESS_KEY is not set"),
            "{missing_secret}"
        );
        assert!(!missing_secret.contains("AKIDFROMENV"));

        let empty_secret = S3Credentials::from_lookup(lookup(&[
            ("AWS_ACCESS_KEY_ID", "AKIDFROMENV"),
            ("AWS_SECRET_ACCESS_KEY", ""),
        ]))
        .unwrap_err()
        .to_string();
        assert!(
            empty_secret.contains("AWS_SECRET_ACCESS_KEY is empty"),
            "{empty_secret}"
        );

        let without_token = S3Credentials::from_lookup(lookup(&[
            ("AWS_ACCESS_KEY_ID", "AKIDFROMENV"),
            ("AWS_SECRET_ACCESS_KEY", "secret-from-env"),
            ("AWS_SESSION_TOKEN", ""),
        ]))
        .unwrap();
        assert_eq!(without_token.access_key_id(), "AKIDFROMENV");
        assert!(!without_token.has_session_token());

        let with_token = S3Credentials::from_lookup(lookup(&[
            ("AWS_ACCESS_KEY_ID", "AKIDFROMENV"),
            ("AWS_SECRET_ACCESS_KEY", "secret-from-env"),
            ("AWS_SESSION_TOKEN", "token-from-env"),
        ]))
        .unwrap();
        assert!(with_token.has_session_token());
        assert!(!format!("{with_token:?}").contains("token-from-env"));
    }

    #[cfg(unix)]
    #[test]
    fn credentials_from_environment_reject_non_unicode_without_the_value() {
        use std::os::unix::ffi::OsStringExt as _;

        let error = S3Credentials::from_lookup(|name| match name {
            "AWS_ACCESS_KEY_ID" => Some(OsString::from("AKIDFROMENV")),
            "AWS_SECRET_ACCESS_KEY" => Some(OsString::from_vec(vec![0xff, b's', b'k'])),
            _ => None,
        })
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("AWS_SECRET_ACCESS_KEY is not valid Unicode"),
            "{error}"
        );
    }
}
