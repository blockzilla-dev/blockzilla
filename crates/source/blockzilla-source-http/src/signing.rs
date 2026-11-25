//! Request-signing hook for private object stores.

use reqwest::{
    Method,
    header::{
        CONNECTION, CONTENT_LENGTH, HOST, HeaderMap, HeaderName, HeaderValue, TRANSFER_ENCODING,
    },
};
use url::Url;

use blockzilla_source::{SourceError, SourceResult};

/// Adds authentication to each request that an
/// [`HttpRangeSource`](crate::HttpRangeSource) sends.
///
/// The source calls [`sign`](Self::sign) for each HEAD, ranged GET and full
/// GET attempt, after it has set all its own headers (`Accept-Encoding` and
/// `Range`). A retry is a new attempt, and the source signs it again, so a
/// time-based signature stays fresh. The source sends the request with the
/// headers that the signer leaves. A signer error stops the call without a
/// retry. A signer must not put secrets in its error messages.
pub trait HttpRequestSigner: Send + Sync {
    fn sign(&self, request: &mut HttpRequestToSign<'_>) -> SourceResult<()>;
}

/// One outgoing request, as a signer sees it.
///
/// A signer can read the method, the exact URL and the headers, and it can
/// add or replace headers. It cannot set `Host`, `Content-Length`,
/// `Transfer-Encoding` or `Connection`. The HTTP client sets `Host` from the
/// URL authority: the host, and the port only when it is not the default port
/// of the scheme.
pub struct HttpRequestToSign<'a> {
    pub(crate) method: &'a Method,
    pub(crate) url: &'a Url,
    pub(crate) headers: &'a mut HeaderMap,
}

impl HttpRequestToSign<'_> {
    /// The method in upper case, for example `GET` or `HEAD`.
    pub fn method(&self) -> &str {
        self.method.as_str()
    }

    /// The exact URL that the source sends.
    pub fn url(&self) -> &Url {
        self.url
    }

    /// The first value of one header, if it is present and is visible ASCII.
    /// The name is not case-sensitive.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name)?.to_str().ok()
    }

    /// All header fields, with lower-case names. A name with more than one
    /// value occurs one time for each value, in insertion order.
    pub fn headers(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_bytes()))
    }

    /// Add one header, or replace all values of the header with this name.
    ///
    /// The value is marked as sensitive. Errors do not contain the value.
    pub fn set_header(&mut self, name: &str, value: &str) -> SourceResult<()> {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            SourceError::Protocol("request signer used an invalid header name".into())
        })?;
        if [HOST, CONTENT_LENGTH, TRANSFER_ENCODING, CONNECTION].contains(&name) {
            return Err(SourceError::Protocol(format!(
                "request signer cannot set the {name} header"
            )));
        }
        let mut value = HeaderValue::from_str(value).map_err(|_| {
            SourceError::Protocol(format!(
                "request signer used an invalid value for the {name} header"
            ))
        })?;
        value.set_sensitive(true);
        self.headers.insert(name, value);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_view_reads_and_sets_headers_without_echoing_values() {
        let method = Method::GET;
        let url = Url::parse("https://example.test/bucket/key").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::RANGE,
            HeaderValue::from_static("bytes=0-9"),
        );
        let mut request = HttpRequestToSign {
            method: &method,
            url: &url,
            headers: &mut headers,
        };
        assert_eq!(request.method(), "GET");
        assert_eq!(request.url().as_str(), "https://example.test/bucket/key");
        assert_eq!(request.header("Range"), Some("bytes=0-9"));
        request.set_header("X-Custom", "one").unwrap();
        request.set_header("x-custom", "two").unwrap();
        assert_eq!(request.header("x-custom"), Some("two"));
        let names = request.headers().map(|(name, _)| name).collect::<Vec<_>>();
        assert_eq!(names, ["range", "x-custom"]);

        for forbidden in ["host", "Content-Length", "transfer-encoding", "connection"] {
            let error = request.set_header(forbidden, "value").unwrap_err();
            assert!(error.to_string().contains("cannot set"));
        }
        let error = request
            .set_header("x-secret", "secret-value\nsplit")
            .unwrap_err();
        assert!(error.to_string().contains("x-secret"));
        assert!(!error.to_string().contains("secret-value"));
        let error = request.set_header("bad name", "value").unwrap_err();
        assert!(error.to_string().contains("invalid header name"));
        assert!(headers.get("x-custom").unwrap().is_sensitive());
    }
}
