//! HTTP byte ranges with pinned object identities.

mod retry;
mod s3;
mod signing;

use std::{
    collections::HashMap,
    fmt,
    io::Read,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use reqwest::{
    Method, StatusCode,
    blocking::{Client, Request, Response},
    header::{
        ACCEPT_ENCODING, AUTHORIZATION, CONTENT_LENGTH, CONTENT_RANGE, ETAG, HeaderMap,
        HeaderValue, RANGE,
    },
    redirect,
};
use url::Url;

use blockzilla_source::{RangeSource, SourceError, SourceResult, validate_object_name};

use retry::RetryCause;
pub use retry::{HttpRetryPolicy, HttpRetryStats};
pub use s3::{S3Credentials, S3PayloadHash, S3SigV4Signer};
pub use signing::{HttpRequestSigner, HttpRequestToSign};

// Existing archive-gateway route contract; not a dependency on the V2 decoder.
const GENERATION_MANIFEST_FILE: &str = "archive-v2-generation.json";

const DEFAULT_MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;

/// Exact HTTP work completed by one source and all its clones.
///
/// `returned_body_bytes` counts all response-body bytes consumed by the
/// source, including partial bytes from an incomplete range attempt. Response
/// headers are excluded. HEAD responses have no body.
///
/// Request counts include all retries. [`HttpRangeSource::retry_stats`] gives
/// the retries of all causes, for HEAD and GET.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HttpRangeSourceStats {
    pub head_requests: u64,
    pub get_requests: u64,
    /// New full GET attempts made after a body read error or an incomplete
    /// response body.
    pub incomplete_body_retries: u64,
    /// New GET attempts after HTTP 500, 502, 503 or 504, with bounded backoff.
    pub server_error_retries: u64,
    pub returned_body_bytes: u64,
}

impl HttpRangeSourceStats {
    pub fn requests(self) -> u64 {
        self.head_requests.saturating_add(self.get_requests)
    }

    pub fn saturating_sub(self, earlier: Self) -> Self {
        Self {
            head_requests: self.head_requests.saturating_sub(earlier.head_requests),
            get_requests: self.get_requests.saturating_sub(earlier.get_requests),
            incomplete_body_retries: self
                .incomplete_body_retries
                .saturating_sub(earlier.incomplete_body_retries),
            server_error_retries: self
                .server_error_retries
                .saturating_sub(earlier.server_error_retries),
            returned_body_bytes: self
                .returned_body_bytes
                .saturating_sub(earlier.returned_body_bytes),
        }
    }
}

#[derive(Debug, Default)]
struct HttpRangeSourceCounters {
    head_requests: AtomicU64,
    get_requests: AtomicU64,
    incomplete_body_retries: AtomicU64,
    /// GET retries after HTTP 5xx only.
    server_error_retries: AtomicU64,
    returned_body_bytes: AtomicU64,
    transport_error_retries: AtomicU64,
    rate_limited_retries: AtomicU64,
    /// HEAD and GET retries after HTTP 5xx.
    all_server_error_retries: AtomicU64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ObservedObjectIdentity {
    Absent,
    Present {
        length: u64,
        strong_etag: Option<String>,
    },
}

/// Immutable HTTP object identity required by the persistent range cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpObjectIdentity {
    pub length: u64,
    pub strong_etag: String,
}

#[derive(Debug, Clone)]
pub struct HttpRangeSourceOptions {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_manifest_bytes: usize,
    /// Bearer tokens and signed requests must not travel over cleartext. This
    /// escape hatch is only for a trusted local development server.
    pub allow_insecure_http: bool,
    /// Path contract used to find one archive object below `base_url`.
    pub object_path_layout: HttpObjectPathLayout,
    /// Retries for each HEAD and GET call. See [`HttpRetryPolicy`] for the
    /// causes and the default.
    pub retry_policy: HttpRetryPolicy,
}

/// URL path contract for archive objects.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum HttpObjectPathLayout {
    /// Existing gateway route: `v1/epochs/<epoch>/files/<object>`.
    #[default]
    GatewayV1,
    /// Simple sample route: `<epoch>/<object>`.
    FlatEpoch,
    /// Direct epoch directory: `<object>`.
    FlatObjects,
}

impl Default for HttpRangeSourceOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(120),
            max_manifest_bytes: DEFAULT_MAX_MANIFEST_BYTES,
            allow_insecure_http: false,
            object_path_layout: HttpObjectPathLayout::default(),
            retry_policy: HttpRetryPolicy::default(),
        }
    }
}

/// Blocking HTTP Range source for the Blockzilla read gateway.
///
/// The secret is held only as an already-redacted header value or inside a
/// request signer. `Debug` never prints either. Redirects and ambient HTTP
/// proxies are disabled so a bearer token or a signed request cannot be
/// forwarded to a different origin.
#[derive(Clone)]
pub struct HttpRangeSource {
    client: Client,
    base_url: Url,
    epoch: u64,
    authorization: Option<HeaderValue>,
    signer: Option<Arc<dyn HttpRequestSigner>>,
    max_manifest_bytes: usize,
    object_path_layout: HttpObjectPathLayout,
    retry_policy: HttpRetryPolicy,
    counters: Arc<HttpRangeSourceCounters>,
    observed_objects: Arc<Mutex<HashMap<String, ObservedObjectIdentity>>>,
}

impl fmt::Debug for HttpRangeSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpRangeSource")
            .field("base_url", &self.base_url)
            .field("epoch", &self.epoch)
            .field("object_path_layout", &self.object_path_layout)
            .field(
                "authorization",
                &self.authorization.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "request_signer",
                &self.signer.as_ref().map(|_| "<redacted>"),
            )
            .field("max_manifest_bytes", &self.max_manifest_bytes)
            .field("retry_policy", &self.retry_policy)
            .field("stats", &self.stats())
            .field("retry_stats", &self.retry_stats())
            .field(
                "observed_object_count",
                &self
                    .observed_objects
                    .lock()
                    .map(|objects| objects.len())
                    .ok(),
            )
            .finish()
    }
}

impl HttpRangeSource {
    pub fn new(
        base_url: impl AsRef<str>,
        epoch: u64,
        bearer_token: Option<&str>,
    ) -> SourceResult<Self> {
        Self::with_options(
            base_url,
            epoch,
            bearer_token,
            HttpRangeSourceOptions::default(),
        )
    }

    pub fn with_options(
        base_url: impl AsRef<str>,
        epoch: u64,
        bearer_token: Option<&str>,
        options: HttpRangeSourceOptions,
    ) -> SourceResult<Self> {
        Self::build(base_url.as_ref(), epoch, bearer_token, None, options)
    }

    /// Create a source that signs each request with `signer`.
    ///
    /// For a private S3 or R2 bucket, use an [`S3SigV4Signer`] with a
    /// path-style base URL, for example
    /// `https://<account>.r2.cloudflarestorage.com/<bucket>/<prefix>`, and
    /// [`HttpObjectPathLayout::FlatObjects`]. The source signs each HEAD,
    /// ranged GET and full GET attempt, retries included, after it sets its
    /// own headers. It sends no bearer token. All other checks and options are
    /// the same as for [`with_options`](Self::with_options).
    pub fn with_signer(
        base_url: impl AsRef<str>,
        epoch: u64,
        signer: Arc<dyn HttpRequestSigner>,
        options: HttpRangeSourceOptions,
    ) -> SourceResult<Self> {
        Self::build(base_url.as_ref(), epoch, None, Some(signer), options)
    }

    fn build(
        base_url: &str,
        epoch: u64,
        bearer_token: Option<&str>,
        signer: Option<Arc<dyn HttpRequestSigner>>,
        options: HttpRangeSourceOptions,
    ) -> SourceResult<Self> {
        let mut base_url = Url::parse(base_url)
            .map_err(|error| SourceError::Protocol(format!("invalid gateway URL: {error}")))?;
        if !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(SourceError::Protocol(
                "gateway URL must not contain credentials, a query, or a fragment".into(),
            ));
        }
        if base_url.host_str().is_none() {
            return Err(SourceError::Protocol(
                "gateway URL must have an origin".into(),
            ));
        }
        match base_url.scheme() {
            "https" => {}
            "http" if options.allow_insecure_http => {}
            "http" => {
                return Err(SourceError::Protocol(
                    "cleartext HTTP is disabled; explicitly enable it only for local development"
                        .into(),
                ));
            }
            scheme => {
                return Err(SourceError::Protocol(format!(
                    "unsupported gateway URL scheme {scheme}"
                )));
            }
        }
        if options.max_manifest_bytes == 0 {
            return Err(SourceError::Protocol(
                "max_manifest_bytes must be non-zero".into(),
            ));
        }
        options.retry_policy.validate()?;
        // A base ending with a file-looking segment is still treated as a path
        // prefix. Gateway route components are appended, never URL-joined.
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }

        let authorization = match bearer_token {
            Some("") => {
                return Err(SourceError::Protocol("bearer token is empty".into()));
            }
            Some(token) => Some(HeaderValue::from_str(&format!("Bearer {token}")).map_err(
                |_| SourceError::Protocol("bearer token contains invalid header bytes".into()),
            )?),
            None => None,
        };
        let client = Client::builder()
            .connect_timeout(options.connect_timeout)
            .timeout(options.request_timeout)
            .redirect(redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|error| SourceError::Protocol(format!("build HTTP range client: {error}")))?;
        Ok(Self {
            client,
            base_url,
            epoch,
            authorization,
            signer,
            max_manifest_bytes: options.max_manifest_bytes,
            object_path_layout: options.object_path_layout,
            retry_policy: options.retry_policy,
            counters: Arc::new(HttpRangeSourceCounters::default()),
            observed_objects: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Return a shared-source snapshot. Clones contribute to the same totals.
    pub fn stats(&self) -> HttpRangeSourceStats {
        HttpRangeSourceStats {
            head_requests: self.counters.head_requests.load(Ordering::Relaxed),
            get_requests: self.counters.get_requests.load(Ordering::Relaxed),
            incomplete_body_retries: self
                .counters
                .incomplete_body_retries
                .load(Ordering::Relaxed),
            server_error_retries: self.counters.server_error_retries.load(Ordering::Relaxed),
            returned_body_bytes: self.counters.returned_body_bytes.load(Ordering::Relaxed),
        }
    }

    /// Return the retries of all causes, for HEAD and GET. Clones contribute
    /// to the same totals.
    pub fn retry_stats(&self) -> HttpRetryStats {
        HttpRetryStats {
            transport_error_retries: self
                .counters
                .transport_error_retries
                .load(Ordering::Relaxed),
            rate_limited_retries: self.counters.rate_limited_retries.load(Ordering::Relaxed),
            server_error_retries: self
                .counters
                .all_server_error_retries
                .load(Ordering::Relaxed),
            incomplete_body_retries: self
                .counters
                .incomplete_body_retries
                .load(Ordering::Relaxed),
        }
    }

    pub fn retry_policy(&self) -> HttpRetryPolicy {
        self.retry_policy
    }

    /// Perform a fresh HEAD and require an exact strong ETag and length.
    pub fn strong_identity(&self, object: &str) -> SourceResult<HttpObjectIdentity> {
        self.head_identity(object, true)?
            .ok_or_else(|| SourceError::NotFound(object.to_owned()))
    }

    fn record_head_request(&self) {
        self.counters.head_requests.fetch_add(1, Ordering::Relaxed);
    }

    fn record_get_request(&self) {
        self.counters.get_requests.fetch_add(1, Ordering::Relaxed);
    }

    fn record_retry(&self, method: &Method, cause: RetryCause) {
        let counters = self.counters.as_ref();
        let counter = match cause {
            RetryCause::Transport => &counters.transport_error_retries,
            RetryCause::RateLimited => &counters.rate_limited_retries,
            RetryCause::ServerError => {
                if *method == Method::GET {
                    counters
                        .server_error_retries
                        .fetch_add(1, Ordering::Relaxed);
                }
                &counters.all_server_error_retries
            }
            RetryCause::IncompleteBody => &counters.incomplete_body_retries,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn record_returned_body(&self, length: usize) {
        self.counters
            .returned_body_bytes
            .fetch_add(length as u64, Ordering::Relaxed);
    }

    fn bind_object_identity(
        &self,
        object: &str,
        length: u64,
        strong_etag: Option<&str>,
    ) -> SourceResult<()> {
        let mut objects = self.observed_objects.lock().map_err(|_| {
            SourceError::Protocol("HTTP object-identity binding cache is poisoned".into())
        })?;
        if let Some(observed) = objects.get_mut(object) {
            match observed {
                ObservedObjectIdentity::Absent => {
                    return Err(SourceError::Protocol(format!(
                        "object {object} became present after its absence was pinned"
                    )));
                }
                ObservedObjectIdentity::Present {
                    length: observed_length,
                    strong_etag: observed_etag,
                } => {
                    if *observed_length != length {
                        return Err(SourceError::Protocol(format!(
                            "object {object} changed size from {observed_length} to {length}"
                        )));
                    }
                    match (&*observed_etag, strong_etag) {
                        (Some(expected), Some(actual)) if expected == actual => {}
                        (Some(expected), Some(actual)) => {
                            return Err(SourceError::Protocol(format!(
                                "object {object} changed strong ETag from {expected} to {actual}"
                            )));
                        }
                        (Some(_), None) => {
                            return Err(SourceError::Protocol(format!(
                                "object {object} omitted the pinned strong ETag"
                            )));
                        }
                        (None, Some(actual)) => *observed_etag = Some(actual.to_owned()),
                        (None, None) => {}
                    }
                }
            }
        } else {
            objects.insert(
                object.to_owned(),
                ObservedObjectIdentity::Present {
                    length,
                    strong_etag: strong_etag.map(str::to_owned),
                },
            );
        }
        Ok(())
    }

    fn bind_object_absence(&self, object: &str) -> SourceResult<()> {
        let mut objects = self.observed_objects.lock().map_err(|_| {
            SourceError::Protocol("HTTP object-identity binding cache is poisoned".into())
        })?;
        match objects.get(object) {
            Some(ObservedObjectIdentity::Absent) => Ok(()),
            Some(ObservedObjectIdentity::Present { .. }) => Err(SourceError::Protocol(format!(
                "object {object} became absent after its presence was pinned"
            ))),
            None => {
                objects.insert(object.to_owned(), ObservedObjectIdentity::Absent);
                Ok(())
            }
        }
    }

    fn head_identity(
        &self,
        object: &str,
        require_strong_etag: bool,
    ) -> SourceResult<Option<HttpObjectIdentity>> {
        let url = self.object_url(object)?;
        self.request_with_retry(Method::HEAD, &url, None, |response| {
            self.head_response_identity(&response, object, require_strong_etag)
                .map_err(AttemptError::Final)
        })
    }

    fn head_response_identity(
        &self,
        response: &Response,
        object: &str,
        require_strong_etag: bool,
    ) -> SourceResult<Option<HttpObjectIdentity>> {
        if response.status() == StatusCode::NOT_FOUND {
            self.bind_object_absence(object)?;
            return Ok(None);
        }
        if response.status() != StatusCode::OK {
            return Err(SourceError::Protocol(format!(
                "HEAD for {object} returned HTTP {}",
                response.status()
            )));
        }
        let value = response.headers().get(CONTENT_LENGTH).ok_or_else(|| {
            SourceError::Protocol(format!("HEAD for {object} omitted Content-Length"))
        })?;
        let value = value.to_str().map_err(|_| {
            SourceError::Protocol(format!("HEAD for {object} has invalid Content-Length"))
        })?;
        let length = value.parse::<u64>().map_err(|_| {
            SourceError::Protocol(format!("HEAD for {object} has invalid Content-Length"))
        })?;
        let strong_etag = strong_etag(response.headers(), object)?;
        if require_strong_etag && strong_etag.is_none() {
            return Err(SourceError::Protocol(format!(
                "HEAD for {object} requires one exact strong ETag"
            )));
        }
        self.bind_object_identity(object, length, strong_etag.as_deref())?;
        Ok(Some(HttpObjectIdentity {
            length,
            strong_etag: strong_etag.unwrap_or_default(),
        }))
    }

    /// Return the validated object URL under the selected path layout.
    pub fn object_url(&self, object: &str) -> SourceResult<Url> {
        validate_object_name(object).map_err(|_| SourceError::InvalidName(object.to_owned()))?;
        let mut url = self.base_url.clone();
        {
            let mut path = url.path_segments_mut().map_err(|_| {
                SourceError::Protocol("gateway URL cannot accept path segments".into())
            })?;
            path.pop_if_empty();
            match self.object_path_layout {
                HttpObjectPathLayout::GatewayV1 => {
                    path.push("v1");
                    path.push("epochs");
                    path.push(&self.epoch.to_string());
                    if object == GENERATION_MANIFEST_FILE {
                        path.push("manifest");
                    } else {
                        path.push("files");
                        path.push(object);
                    }
                }
                HttpObjectPathLayout::FlatEpoch => {
                    path.push(&self.epoch.to_string());
                    path.push(object);
                }
                HttpObjectPathLayout::FlatObjects => {
                    path.push(object);
                }
            }
        }
        Ok(url)
    }

    /// Send one attempt. Set the source headers first, then let the signer
    /// read and sign the complete request.
    fn send_once(
        &self,
        method: &Method,
        url: &Url,
        range: Option<&HeaderValue>,
    ) -> Result<Response, SendError> {
        let mut headers = HeaderMap::with_capacity(8);
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        if let Some(range) = range {
            headers.insert(RANGE, range.clone());
        }
        if let Some(value) = &self.authorization {
            headers.insert(AUTHORIZATION, value.clone());
        }
        if let Some(signer) = &self.signer {
            signer
                .sign(&mut HttpRequestToSign {
                    method,
                    url,
                    headers: &mut headers,
                })
                .map_err(SendError::Final)?;
        }
        let mut request = Request::new(method.clone(), url.clone());
        *request.headers_mut() = headers;
        if *method == Method::HEAD {
            self.record_head_request();
        } else {
            self.record_get_request();
        }
        self.client.execute(request).map_err(|error| {
            if is_transient_transport_error(&error) {
                SendError::Transport(error)
            } else {
                SendError::Final(sanitize_http_error(error))
            }
        })
    }

    /// Send one call with the retry policy. `handle` checks each response
    /// that is not a transient status, and reads its body.
    ///
    /// The budgets are nested, as in the earlier fixed policy. One call has up
    /// to `max_attempts` body attempts. A body that fails or ends early starts
    /// the next body attempt at once. Each body attempt has up to
    /// `max_attempts` requests for transport errors and transient statuses,
    /// with `backoff(retry)` before each retry. The last request of a budget
    /// does not retry: its error, or its transient status through `handle`, is
    /// the result.
    fn request_with_retry<T>(
        &self,
        method: Method,
        url: &Url,
        range: Option<&HeaderValue>,
        mut handle: impl FnMut(Response) -> Result<T, AttemptError>,
    ) -> SourceResult<T> {
        let policy = self.retry_policy;
        let mut body_attempt = 0_u32;
        loop {
            let can_retry_body = body_attempt.saturating_add(1) < policy.max_attempts;
            // Response retries done in this body attempt.
            let mut retry = 0_u32;
            let response = loop {
                let can_retry = retry.saturating_add(1) < policy.max_attempts;
                let (cause, delay) = match self.send_once(&method, url, range) {
                    Err(SendError::Final(error)) => return Err(error),
                    Err(SendError::Transport(_)) if can_retry => {
                        (RetryCause::Transport, policy.backoff(retry))
                    }
                    Err(SendError::Transport(error)) => return Err(sanitize_http_error(error)),
                    Ok(response) => {
                        self.check_origin(&response)?;
                        let status_retry = if can_retry {
                            policy.status_retry(&response, retry)
                        } else {
                            None
                        };
                        match status_retry {
                            // Error bodies are not archive bytes. Do not
                            // allocate or drain an untrusted error body. Every
                            // new response passes all range, length and pinned
                            // identity checks again before data is consumed.
                            Some(status_retry) => {
                                drop(response);
                                status_retry
                            }
                            None => break response,
                        }
                    }
                };
                if !delay.is_zero() {
                    std::thread::sleep(delay);
                }
                self.record_retry(&method, cause);
                retry += 1;
            };
            match handle(response) {
                Ok(value) => return Ok(value),
                Err(AttemptError::Body(_)) if can_retry_body => {
                    // Start over at the original offset, at once. A partial
                    // body never enters a cache.
                    self.record_retry(&method, RetryCause::IncompleteBody);
                    body_attempt += 1;
                }
                Err(AttemptError::Body(error) | AttemptError::Final(error)) => return Err(error),
            }
        }
    }

    fn check_origin(&self, response: &Response) -> SourceResult<()> {
        if response.url().origin() != self.base_url.origin() {
            return Err(SourceError::Protocol(
                "gateway response crossed origin".into(),
            ));
        }
        Ok(())
    }

    fn full_manifest(&self, expected_length: usize) -> SourceResult<Vec<u8>> {
        if expected_length > self.max_manifest_bytes {
            return Err(SourceError::Protocol(format!(
                "manifest is {expected_length} bytes, above the {} byte limit",
                self.max_manifest_bytes
            )));
        }
        let url = self.object_url(GENERATION_MANIFEST_FILE)?;
        self.request_with_retry(Method::GET, &url, None, |mut response| {
            self.check_manifest_response(&response, expected_length)
                .map_err(AttemptError::Final)?;
            let mut bytes = Vec::new();
            let result = read_bounded_into(
                &mut response,
                expected_length,
                GENERATION_MANIFEST_FILE,
                &mut bytes,
            );
            self.record_returned_body(bytes.len());
            result.map_err(|error| body_attempt_error(error, expected_length))?;
            Ok(bytes)
        })
    }

    fn check_manifest_response(
        &self,
        response: &Response,
        expected_length: usize,
    ) -> SourceResult<()> {
        if response.status() == StatusCode::NOT_FOUND {
            self.bind_object_absence(GENERATION_MANIFEST_FILE)?;
            return Err(SourceError::NotFound(GENERATION_MANIFEST_FILE.to_owned()));
        }
        if response.status() != StatusCode::OK {
            return Err(SourceError::Protocol(format!(
                "manifest GET returned HTTP {}",
                response.status()
            )));
        }
        let response_etag = strong_etag(response.headers(), GENERATION_MANIFEST_FILE)?;
        self.bind_object_identity(
            GENERATION_MANIFEST_FILE,
            expected_length as u64,
            response_etag.as_deref(),
        )?;
        enforce_content_length(response, expected_length)
    }

    /// Read one exact range with the retry policy. `read_body` fills the
    /// destination from one checked response and returns the consumed body
    /// byte count.
    fn read_range_attempts(
        &self,
        object: &str,
        offset: u64,
        length: usize,
        mut read_body: impl FnMut(&mut Response) -> (SourceResult<()>, usize),
    ) -> SourceResult<()> {
        debug_assert!(length != 0);
        debug_assert!(object != GENERATION_MANIFEST_FILE);
        let length_u64 = u64::try_from(length).map_err(|_| {
            SourceError::Protocol("requested HTTP range length does not fit u64".into())
        })?;
        let end_exclusive = offset
            .checked_add(length_u64)
            .ok_or_else(|| SourceError::Protocol(format!("range overflow for {object}")))?;
        let end_inclusive = end_exclusive - 1;
        let url = self.object_url(object)?;
        let range = HeaderValue::from_str(&format!("bytes={offset}-{end_inclusive}"))
            .map_err(|_| SourceError::Protocol(format!("invalid range header for {object}")))?;
        self.request_with_retry(Method::GET, &url, Some(&range), |mut response| {
            self.check_range_response(
                &response,
                object,
                offset,
                end_inclusive,
                end_exclusive,
                length,
            )
            .map_err(AttemptError::Final)?;
            let (result, body_bytes) = read_body(&mut response);
            self.record_returned_body(body_bytes);
            result.map_err(|error| body_attempt_error(error, length))
        })
    }

    fn check_range_response(
        &self,
        response: &Response,
        object: &str,
        offset: u64,
        end_inclusive: u64,
        end_exclusive: u64,
        length: usize,
    ) -> SourceResult<()> {
        if response.status() == StatusCode::NOT_FOUND {
            self.bind_object_absence(object)?;
            return Err(SourceError::NotFound(object.to_owned()));
        }
        if response.status() != StatusCode::PARTIAL_CONTENT {
            return Err(SourceError::Protocol(format!(
                "range GET for {object} returned HTTP {}, expected 206",
                response.status()
            )));
        }
        enforce_content_length(response, length)?;
        let content_range = response.headers().get(CONTENT_RANGE).ok_or_else(|| {
            SourceError::Protocol(format!("range GET for {object} omitted Content-Range"))
        })?;
        let content_range = content_range.to_str().map_err(|_| {
            SourceError::Protocol(format!("range GET for {object} has invalid Content-Range"))
        })?;
        let (actual_start, actual_end, total) =
            parse_content_range(content_range).ok_or_else(|| {
                SourceError::Protocol(format!(
                    "range GET for {object} has malformed Content-Range"
                ))
            })?;
        let response_etag = strong_etag(response.headers(), object)?;
        self.bind_object_identity(object, total, response_etag.as_deref())?;
        if actual_start != offset || actual_end != end_inclusive || end_exclusive > total {
            return Err(SourceError::Protocol(format!(
                "range GET for {object} returned an unexpected Content-Range"
            )));
        }
        Ok(())
    }
}

/// One failed attempt.
enum AttemptError {
    /// Stop the call with this error.
    Final(SourceError),
    /// A body read error or a body that ended early. The policy can retry it.
    Body(SourceError),
}

enum SendError {
    /// A transport failure before a response. The policy can retry it.
    Transport(reqwest::Error),
    /// A request that cannot be built or signed, or a permanent failure.
    Final(SourceError),
}

fn body_attempt_error(error: SourceError, expected: usize) -> AttemptError {
    if is_incomplete_range_body(&error, expected) {
        AttemptError::Body(error)
    } else {
        AttemptError::Final(error)
    }
}

/// Connect failures, timeouts, and resets or closed connections before a
/// response are transient. Request-build errors are not.
fn is_transient_transport_error(error: &reqwest::Error) -> bool {
    !error.is_builder() && (error.is_request() || error.is_connect() || error.is_timeout())
}

impl RangeSource for HttpRangeSource {
    fn recommended_read_concurrency(&self) -> usize {
        8
    }

    fn size(&self, object: &str) -> SourceResult<Option<u64>> {
        Ok(self
            .head_identity(object, false)?
            .map(|identity| identity.length))
    }

    fn read_range(&self, object: &str, offset: u64, length: usize) -> SourceResult<Vec<u8>> {
        let mut bytes = Vec::new();
        self.read_range_into(object, offset, length, &mut bytes)?;
        Ok(bytes)
    }

    fn read_range_into(
        &self,
        object: &str,
        offset: u64,
        length: usize,
        destination: &mut Vec<u8>,
    ) -> SourceResult<()> {
        if length == 0 {
            let size = self
                .size(object)?
                .ok_or_else(|| SourceError::NotFound(object.to_owned()))?;
            if offset > size {
                return Err(SourceError::OutOfBounds {
                    object: object.to_owned(),
                    offset,
                    length,
                    size,
                });
            }
            destination.clear();
            return Ok(());
        }
        if object == GENERATION_MANIFEST_FILE {
            if offset != 0 {
                return Err(SourceError::Protocol(
                    "manifest only supports a complete bounded GET".into(),
                ));
            }
            *destination = self.full_manifest(length)?;
            return Ok(());
        }
        // A retry starts over at the original offset. The next response
        // repeats all range and object-identity checks.
        self.read_range_attempts(object, offset, length, |response| {
            let result = read_bounded_into(response, length, object, destination);
            (result, destination.len())
        })
    }

    fn read_range_into_slice(
        &self,
        object: &str,
        offset: u64,
        destination: &mut [u8],
    ) -> SourceResult<()> {
        let length = destination.len();
        if length == 0 {
            let size = self
                .size(object)?
                .ok_or_else(|| SourceError::NotFound(object.to_owned()))?;
            if offset > size {
                return Err(SourceError::OutOfBounds {
                    object: object.to_owned(),
                    offset,
                    length,
                    size,
                });
            }
            return Ok(());
        }
        if object == GENERATION_MANIFEST_FILE {
            if offset != 0 {
                return Err(SourceError::Protocol(
                    "manifest only supports a complete bounded GET".into(),
                ));
            }
            let bytes = self.full_manifest(length)?;
            destination.copy_from_slice(&bytes);
            return Ok(());
        }
        self.read_range_attempts(object, offset, length, |response| {
            let mut body_bytes = 0_usize;
            let result = read_bounded_into_slice(response, destination, object, &mut body_bytes);
            (result, body_bytes)
        })
    }
}

fn strong_etag(headers: &HeaderMap, object: &str) -> SourceResult<Option<String>> {
    let mut values = headers.get_all(ETAG).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(SourceError::Protocol(format!(
            "response for {object} has multiple ETag fields"
        )));
    }
    let value = value.to_str().map_err(|_| {
        SourceError::Protocol(format!("response for {object} has a non-ASCII ETag"))
    })?;
    let (weak, opaque) = match value.strip_prefix("W/") {
        Some(opaque) => (true, opaque),
        None => (false, value),
    };
    let bytes = opaque.as_bytes();
    if bytes.len() < 2
        || bytes.first() != Some(&b'"')
        || bytes.last() != Some(&b'"')
        || bytes[1..bytes.len() - 1]
            .iter()
            .any(|byte| !matches!(*byte, 0x21 | 0x23..=0x7e))
    {
        return Err(SourceError::Protocol(format!(
            "response for {object} has a malformed ETag"
        )));
    }
    Ok((!weak).then(|| value.to_owned()))
}

fn enforce_content_length(response: &Response, expected: usize) -> SourceResult<()> {
    if let Some(value) = response.headers().get(CONTENT_LENGTH) {
        let value = value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| SourceError::Protocol("invalid Content-Length".into()))?;
        if value != expected as u64 {
            return Err(SourceError::Protocol(format!(
                "response Content-Length is {value}, expected {expected}"
            )));
        }
    }
    Ok(())
}

fn is_incomplete_range_body(error: &SourceError, expected: usize) -> bool {
    match error {
        // This branch only receives errors produced while reading an already
        // validated response body. It includes transport timeouts, resets, and
        // reqwest's IncompleteBody/UnexpectedEof error.
        SourceError::Io { .. } => true,
        SourceError::ShortRead {
            expected: actual_expected,
            actual,
            ..
        } => *actual_expected == expected && *actual < expected,
        _ => false,
    }
}

fn read_bounded_into(
    response: &mut Response,
    expected: usize,
    object: &str,
    destination: &mut Vec<u8>,
) -> SourceResult<()> {
    let allocation = expected.checked_add(1).ok_or_else(|| {
        SourceError::Protocol(format!("response allocation bound overflows for {object}"))
    })?;
    destination.clear();
    if destination.capacity() < allocation {
        destination.try_reserve_exact(allocation).map_err(|error| {
            SourceError::Protocol(format!(
                "cannot reserve {allocation} bounded response bytes for {object}: {error}"
            ))
        })?;
    }
    let bound = u64::try_from(expected)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    response
        .take(bound)
        .read_to_end(destination)
        .map_err(|source| SourceError::Io {
            object: object.to_owned(),
            source,
        })?;
    if destination.len() != expected {
        return Err(SourceError::ShortRead {
            object: object.to_owned(),
            expected,
            actual: destination.len(),
        });
    }
    Ok(())
}

fn read_bounded_into_slice(
    response: &mut Response,
    destination: &mut [u8],
    object: &str,
    body_bytes: &mut usize,
) -> SourceResult<()> {
    let expected = destination.len();
    let mut read = 0_usize;
    *body_bytes = 0;
    while read < expected {
        let count = response
            .read(&mut destination[read..])
            .map_err(|source| SourceError::Io {
                object: object.to_owned(),
                source,
            })?;
        if count == 0 {
            return Err(SourceError::ShortRead {
                object: object.to_owned(),
                expected,
                actual: read,
            });
        }
        read += count;
        *body_bytes = read;
    }
    let mut extra = [0_u8; 1];
    let extra = response
        .read(&mut extra)
        .map_err(|source| SourceError::Io {
            object: object.to_owned(),
            source,
        })?;
    *body_bytes = read.saturating_add(extra);
    if extra != 0 {
        return Err(SourceError::ShortRead {
            object: object.to_owned(),
            expected,
            actual: expected.saturating_add(extra),
        });
    }
    Ok(())
}

fn parse_content_range(value: &str) -> Option<(u64, u64, u64)> {
    let value = value.strip_prefix("bytes ")?;
    let (range, total) = value.split_once('/')?;
    let (start, end) = range.split_once('-')?;
    let start = start.parse().ok()?;
    let end = end.parse().ok()?;
    let total = total.parse().ok()?;
    (start <= end && end < total).then_some((start, end, total))
}

fn sanitize_http_error(error: reqwest::Error) -> SourceError {
    // reqwest errors can contain a URL but do not include request headers.
    // Remove the URL so credentials can never become diagnostic data. Keep the
    // message generic anyway: the text is the same as before the retry policy.
    SourceError::Protocol(format!("HTTP request failed ({})", error.without_url()))
}

#[cfg(test)]
mod tests {
    use std::{io::Write as _, net::TcpListener, thread};

    use super::*;

    fn serve_once(
        expected_request_lines: Vec<&'static str>,
        responses: Vec<&'static [u8]>,
    ) -> (String, thread::JoinHandle<()>) {
        assert_eq!(expected_request_lines.len(), responses.len());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let task = thread::spawn(move || {
            for (expected, response) in expected_request_lines.into_iter().zip(responses) {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = stream.read(&mut buffer).unwrap();
                    assert_ne!(read, 0, "client closed before its request headers ended");
                    request.extend_from_slice(&buffer[..read]);
                    assert!(
                        request.len() <= 16 * 1024,
                        "request headers exceed test cap"
                    );
                }
                let request = String::from_utf8(request).unwrap();
                assert_eq!(request.lines().next(), Some(expected));
                stream.write_all(response).unwrap();
            }
        });
        (format!("http://{address}/gateway"), task)
    }

    #[test]
    fn parses_strict_content_range() {
        assert_eq!(parse_content_range("bytes 5-9/100"), Some((5, 9, 100)));
        assert_eq!(parse_content_range("bytes 9-5/100"), None);
        assert_eq!(parse_content_range("bytes 5-100/100"), None);
        assert_eq!(parse_content_range("bytes 5-9/*"), None);
    }

    #[test]
    fn debug_redacts_bearer_token() {
        let options = HttpRangeSourceOptions {
            allow_insecure_http: true,
            ..HttpRangeSourceOptions::default()
        };
        let source = HttpRangeSource::with_options(
            "http://127.0.0.1:1",
            999,
            Some("highly-secret-token"),
            options,
        )
        .unwrap();
        let rendered = format!("{source:?}");
        assert!(!rendered.contains("highly-secret-token"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn shared_stats_count_exact_head_get_and_consumed_body_bytes() {
        let (base_url, server) = serve_once(
            vec![
                "HEAD /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
                "GET /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
            ],
            vec![
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n",
                b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 1-2/4\r\nConnection: close\r\n\r\nbc",
            ],
        );
        let source = HttpRangeSource::with_options(
            base_url,
            7,
            None,
            HttpRangeSourceOptions {
                allow_insecure_http: true,
                ..HttpRangeSourceOptions::default()
            },
        )
        .unwrap();
        let clone = source.clone();
        assert_eq!(source.size("thing.bin").unwrap(), Some(4));
        assert_eq!(clone.read_range("thing.bin", 1, 2).unwrap(), b"bc");
        assert_eq!(
            source.stats(),
            HttpRangeSourceStats {
                head_requests: 1,
                get_requests: 1,
                incomplete_body_retries: 0,
                server_error_retries: 0,
                returned_body_bytes: 2,
            }
        );
        assert_eq!(clone.stats(), source.stats());
        server.join().unwrap();
    }

    #[test]
    fn flat_epoch_layout_uses_the_simple_sample_path() {
        let (base_url, server) = serve_once(
            vec!["HEAD /gateway/7/thing.bin HTTP/1.1"],
            vec![b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n"],
        );
        let source = HttpRangeSource::with_options(
            base_url,
            7,
            None,
            HttpRangeSourceOptions {
                allow_insecure_http: true,
                object_path_layout: HttpObjectPathLayout::FlatEpoch,
                ..HttpRangeSourceOptions::default()
            },
        )
        .unwrap();

        assert_eq!(source.size("thing.bin").unwrap(), Some(4));
        server.join().unwrap();
    }

    #[test]
    fn flat_objects_layout_keeps_direct_paths_and_pinned_range_checks() {
        let (base_url, server) = serve_once(
            vec![
                "HEAD /gateway/compact-v2/build-v1/epoch-200/thing.bin HTTP/1.1",
                "GET /gateway/compact-v2/build-v1/epoch-200/thing.bin HTTP/1.1",
                "GET /gateway/compact-v2/build-v1/epoch-200/thing.bin HTTP/1.1",
                "GET /gateway/compact-v2/build-v1/epoch-200/thing.bin HTTP/1.1",
            ],
            vec![
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
                b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 1-2/4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\nbc",
                b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 0-1/4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\nab",
                b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 1-2/4\r\nETag: \"v2\"\r\nConnection: close\r\n\r\nbc",
            ],
        );
        let source = HttpRangeSource::with_options(
            format!("{base_url}/compact-v2/build-v1/epoch-200"),
            200,
            None,
            HttpRangeSourceOptions {
                allow_insecure_http: true,
                object_path_layout: HttpObjectPathLayout::FlatObjects,
                ..HttpRangeSourceOptions::default()
            },
        )
        .unwrap();

        assert_eq!(
            source.strong_identity("thing.bin").unwrap(),
            HttpObjectIdentity {
                length: 4,
                strong_etag: "\"v1\"".into(),
            }
        );
        assert_eq!(source.read_range("thing.bin", 1, 2).unwrap(), b"bc");
        assert!(
            source
                .read_range("thing.bin", 1, 2)
                .unwrap_err()
                .to_string()
                .contains("unexpected Content-Range")
        );
        assert!(
            source
                .read_range("thing.bin", 1, 2)
                .unwrap_err()
                .to_string()
                .contains("changed strong ETag")
        );
        assert_eq!(source.stats().returned_body_bytes, 2);
        server.join().unwrap();
    }

    #[test]
    fn exact_range_reads_reuse_vectors_and_fill_final_slices() {
        let (base_url, server) = serve_once(
            vec![
                "GET /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
                "GET /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
                "GET /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
            ],
            vec![
                b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 0-1/6\r\nConnection: close\r\n\r\nab",
                b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 2-3/6\r\nConnection: close\r\n\r\ncd",
                b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 4-5/6\r\nConnection: close\r\n\r\nef",
            ],
        );
        let source = HttpRangeSource::with_options(
            base_url,
            7,
            None,
            HttpRangeSourceOptions {
                allow_insecure_http: true,
                ..HttpRangeSourceOptions::default()
            },
        )
        .unwrap();

        let mut reusable = Vec::with_capacity(8);
        source
            .read_range_into("thing.bin", 0, 2, &mut reusable)
            .unwrap();
        let allocation = reusable.as_ptr();
        assert_eq!(reusable, b"ab");
        source
            .read_range_into("thing.bin", 2, 2, &mut reusable)
            .unwrap();
        assert_eq!(reusable.as_ptr(), allocation);
        assert_eq!(reusable, b"cd");

        let mut direct = [0_u8; 2];
        source
            .read_range_into_slice("thing.bin", 4, &mut direct)
            .unwrap();
        assert_eq!(&direct, b"ef");
        assert_eq!(source.stats().get_requests, 3);
        assert_eq!(source.stats().returned_body_bytes, 6);
        server.join().unwrap();
    }

    #[test]
    fn direct_slice_read_rejects_overlong_http_body_without_retry() {
        let (base_url, server) = serve_once(
            vec!["GET /gateway/v1/epochs/7/files/thing.bin HTTP/1.1"],
            vec![
                b"HTTP/1.1 206 Partial Content\r\nTransfer-Encoding: chunked\r\nContent-Range: bytes 0-1/4\r\nConnection: close\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
            ],
        );
        let source = HttpRangeSource::with_options(
            base_url,
            7,
            None,
            HttpRangeSourceOptions {
                allow_insecure_http: true,
                ..HttpRangeSourceOptions::default()
            },
        )
        .unwrap();
        let mut direct = [0_u8; 2];
        let overlong = source
            .read_range_into_slice("thing.bin", 0, &mut direct)
            .unwrap_err();
        assert!(matches!(
            overlong,
            SourceError::ShortRead {
                expected: 2,
                actual: 3,
                ..
            }
        ));
        assert_eq!(source.stats().get_requests, 1);
        assert_eq!(source.stats().incomplete_body_retries, 0);
        assert_eq!(source.stats().returned_body_bytes, 3);
        server.join().unwrap();
    }

    #[test]
    fn server_error_retry_fills_vector_and_slice_without_counting_error_bodies() {
        for direct in [false, true] {
            let (base_url, server) = serve_once(
                vec!["GET /gateway/v1/epochs/7/files/thing.bin HTTP/1.1"; 2],
                vec![
                    b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\nConnection: close\r\n\r\nerror",
                    b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 1-2/4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\nbc",
                ],
            );
            let source = HttpRangeSource::with_options(
                base_url,
                7,
                None,
                HttpRangeSourceOptions {
                    allow_insecure_http: true,
                    ..HttpRangeSourceOptions::default()
                },
            )
            .unwrap();
            if direct {
                let mut bytes = [0; 2];
                source
                    .read_range_into_slice("thing.bin", 1, &mut bytes)
                    .unwrap();
                assert_eq!(&bytes, b"bc");
            } else {
                assert_eq!(source.read_range("thing.bin", 1, 2).unwrap(), b"bc");
            }
            let stats = source.stats();
            assert_eq!(stats.get_requests, 2);
            assert_eq!(stats.server_error_retries, 1);
            assert_eq!(stats.incomplete_body_retries, 0);
            assert_eq!(stats.returned_body_bytes, 2);
            assert_eq!(stats.saturating_sub(HttpRangeSourceStats::default()), stats);
            assert_eq!(stats.saturating_sub(stats), HttpRangeSourceStats::default());
            server.join().unwrap();
        }
    }

    #[test]
    fn server_error_retry_is_bounded_and_does_not_retry_protocol_errors() {
        for (response, attempts) in [
            (&b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..], 3),
            (&b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 100\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..], 1),
            (&b"HTTP/1.1 412 Precondition Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..], 1),
            (&b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 2-3/4\r\nConnection: close\r\n\r\ncd"[..], 1),
        ] {
            let (base_url, server) = serve_once(
                vec!["GET /gateway/v1/epochs/7/files/thing.bin HTTP/1.1"; attempts],
                vec![response; attempts],
            );
            let source = HttpRangeSource::with_options(base_url, 7, None, HttpRangeSourceOptions {
                allow_insecure_http: true, ..HttpRangeSourceOptions::default()
            }).unwrap();
            assert!(source.read_range_into_slice("thing.bin", 1, &mut [0; 2]).is_err());
            assert_eq!(source.stats().get_requests, attempts as u64);
            assert_eq!(source.stats().server_error_retries, (attempts - 1) as u64);
            assert_eq!(source.stats().returned_body_bytes, 0);
            server.join().unwrap();
        }
    }

    #[test]
    fn server_error_retry_keeps_the_pinned_identity() {
        let (base_url, server) = serve_once(
            vec![
                "HEAD /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
                "GET /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
                "GET /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
            ],
            vec![
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
                b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 1-2/4\r\nETag: \"v2\"\r\nConnection: close\r\n\r\nbc",
            ],
        );
        let source = HttpRangeSource::with_options(
            base_url,
            7,
            None,
            HttpRangeSourceOptions {
                allow_insecure_http: true,
                ..HttpRangeSourceOptions::default()
            },
        )
        .unwrap();
        source.strong_identity("thing.bin").unwrap();
        assert!(
            source
                .read_range("thing.bin", 1, 2)
                .unwrap_err()
                .to_string()
                .contains("changed strong ETag")
        );
        assert_eq!(source.stats().get_requests, 2);
        assert_eq!(source.stats().server_error_retries, 1);
        assert_eq!(source.stats().returned_body_bytes, 0);
        server.join().unwrap();
    }

    #[test]
    fn incomplete_range_body_retries_the_same_bound_range_and_counts_all_bytes() {
        let (base_url, server) = serve_once(
            vec![
                "HEAD /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
                "GET /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
                "GET /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
            ],
            vec![
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
                b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 1-2/4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\nb",
                b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 1-2/4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\nbc",
            ],
        );
        let source = HttpRangeSource::with_options(
            base_url,
            7,
            None,
            HttpRangeSourceOptions {
                allow_insecure_http: true,
                ..HttpRangeSourceOptions::default()
            },
        )
        .unwrap();

        assert_eq!(source.strong_identity("thing.bin").unwrap().length, 4);
        assert_eq!(source.read_range("thing.bin", 1, 2).unwrap(), b"bc");
        assert_eq!(
            source.stats(),
            HttpRangeSourceStats {
                head_requests: 1,
                get_requests: 2,
                incomplete_body_retries: 1,
                server_error_retries: 0,
                returned_body_bytes: 3,
            }
        );
        server.join().unwrap();
    }

    #[test]
    fn incomplete_range_body_retry_keeps_the_pinned_etag() {
        let (base_url, server) = serve_once(
            vec![
                "HEAD /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
                "GET /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
                "GET /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
            ],
            vec![
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
                b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 1-2/4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\nb",
                b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 1-2/4\r\nETag: \"v2\"\r\nConnection: close\r\n\r\nbc",
            ],
        );
        let source = HttpRangeSource::with_options(
            base_url,
            7,
            None,
            HttpRangeSourceOptions {
                allow_insecure_http: true,
                ..HttpRangeSourceOptions::default()
            },
        )
        .unwrap();

        assert_eq!(source.strong_identity("thing.bin").unwrap().length, 4);
        let error = source.read_range("thing.bin", 1, 2).unwrap_err();
        assert!(error.to_string().contains("changed strong ETag"));
        assert_eq!(source.stats().get_requests, 2);
        assert_eq!(source.stats().incomplete_body_retries, 1);
        assert_eq!(source.stats().returned_body_bytes, 1);
        server.join().unwrap();
    }

    #[test]
    fn incomplete_range_body_retry_is_bounded_for_direct_slices() {
        let (base_url, server) = serve_once(
            vec![
                "GET /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
                "GET /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
                "GET /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
            ],
            vec![
                b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 0-1/4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\na",
                b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 0-1/4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\na",
                b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 0-1/4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\na",
            ],
        );
        let source = HttpRangeSource::with_options(
            base_url,
            7,
            None,
            HttpRangeSourceOptions {
                allow_insecure_http: true,
                ..HttpRangeSourceOptions::default()
            },
        )
        .unwrap();
        let mut direct = [0_u8; 2];

        assert!(
            source
                .read_range_into_slice("thing.bin", 0, &mut direct)
                .is_err()
        );
        assert_eq!(source.stats().get_requests, 3);
        assert_eq!(source.stats().incomplete_body_retries, 2);
        assert_eq!(source.stats().returned_body_bytes, 3);
        server.join().unwrap();
    }

    #[test]
    fn invalid_content_range_is_not_counted_as_body_bytes() {
        let (base_url, server) = serve_once(
            vec!["GET /gateway/v1/epochs/7/files/thing.bin HTTP/1.1"],
            vec![
                b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 0-1/4\r\nConnection: close\r\n\r\nab",
            ],
        );
        let source = HttpRangeSource::with_options(
            base_url,
            7,
            None,
            HttpRangeSourceOptions {
                allow_insecure_http: true,
                ..HttpRangeSourceOptions::default()
            },
        )
        .unwrap();
        assert!(source.read_range("thing.bin", 1, 2).is_err());
        assert_eq!(
            source.stats(),
            HttpRangeSourceStats {
                head_requests: 0,
                get_requests: 1,
                incomplete_body_retries: 0,
                server_error_retries: 0,
                returned_body_bytes: 0,
            }
        );
        server.join().unwrap();
    }

    #[test]
    fn head_size_is_pinned_against_later_range_totals() {
        let (base_url, server) = serve_once(
            vec![
                "HEAD /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
                "GET /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
            ],
            vec![
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n",
                b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 1-2/5\r\nConnection: close\r\n\r\nbc",
            ],
        );
        let source = HttpRangeSource::with_options(
            base_url,
            7,
            None,
            HttpRangeSourceOptions {
                allow_insecure_http: true,
                ..HttpRangeSourceOptions::default()
            },
        )
        .unwrap();
        assert_eq!(source.size("thing.bin").unwrap(), Some(4));
        let error = source.read_range("thing.bin", 1, 2).unwrap_err();
        assert!(error.to_string().contains("changed size from 4 to 5"));
        assert_eq!(source.stats().returned_body_bytes, 0);
        server.join().unwrap();
    }

    #[test]
    fn head_absence_is_pinned_against_later_head_and_range_presence() {
        let (base_url, server) = serve_once(
            vec![
                "HEAD /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
                "HEAD /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
                "GET /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
            ],
            vec![
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
                b"HTTP/1.1 206 Partial Content\r\nContent-Length: 1\r\nContent-Range: bytes 0-0/4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\na",
            ],
        );
        let source = HttpRangeSource::with_options(
            base_url,
            7,
            None,
            HttpRangeSourceOptions {
                allow_insecure_http: true,
                ..HttpRangeSourceOptions::default()
            },
        )
        .unwrap();

        assert_eq!(source.size("thing.bin").unwrap(), None);
        let head_error = source.strong_identity("thing.bin").unwrap_err();
        assert!(
            head_error
                .to_string()
                .contains("became present after its absence was pinned")
        );
        let read_error = source.read_range("thing.bin", 0, 1).unwrap_err();
        assert!(
            read_error
                .to_string()
                .contains("became present after its absence was pinned")
        );
        assert_eq!(source.stats().returned_body_bytes, 0);
        server.join().unwrap();
    }

    #[test]
    fn head_presence_is_pinned_against_later_head_and_range_absence() {
        let (base_url, server) = serve_once(
            vec![
                "HEAD /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
                "HEAD /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
                "GET /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
            ],
            vec![
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            ],
        );
        let source = HttpRangeSource::with_options(
            base_url,
            7,
            None,
            HttpRangeSourceOptions {
                allow_insecure_http: true,
                ..HttpRangeSourceOptions::default()
            },
        )
        .unwrap();

        assert_eq!(source.strong_identity("thing.bin").unwrap().length, 4);
        let head_error = source.size("thing.bin").unwrap_err();
        assert!(
            head_error
                .to_string()
                .contains("became absent after its presence was pinned")
        );
        let read_error = source.read_range("thing.bin", 0, 1).unwrap_err();
        assert!(
            read_error
                .to_string()
                .contains("became absent after its presence was pinned")
        );
        assert_eq!(source.stats().returned_body_bytes, 0);
        server.join().unwrap();
    }

    #[test]
    fn cache_identity_rejects_missing_and_weak_etags() {
        for response in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nETag: W/\"v1\"\r\nConnection: close\r\n\r\n"
                .as_slice(),
        ] {
            let (base_url, server) = serve_once(
                vec!["HEAD /gateway/v1/epochs/7/files/thing.bin HTTP/1.1"],
                vec![response],
            );
            let source = HttpRangeSource::with_options(
                base_url,
                7,
                None,
                HttpRangeSourceOptions {
                    allow_insecure_http: true,
                    ..HttpRangeSourceOptions::default()
                },
            )
            .unwrap();
            let error = source.strong_identity("thing.bin").unwrap_err();
            assert!(error.to_string().contains("exact strong ETag"));
            server.join().unwrap();
        }
    }

    #[test]
    fn range_get_must_keep_the_pinned_strong_etag() {
        let (base_url, server) = serve_once(
            vec![
                "HEAD /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
                "GET /gateway/v1/epochs/7/files/thing.bin HTTP/1.1",
            ],
            vec![
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
                b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 1-2/4\r\nETag: \"v2\"\r\nConnection: close\r\n\r\nbc",
            ],
        );
        let source = HttpRangeSource::with_options(
            base_url,
            7,
            None,
            HttpRangeSourceOptions {
                allow_insecure_http: true,
                ..HttpRangeSourceOptions::default()
            },
        )
        .unwrap();
        assert_eq!(source.strong_identity("thing.bin").unwrap().length, 4);
        let error = source.read_range("thing.bin", 1, 2).unwrap_err();
        assert!(error.to_string().contains("changed strong ETag"));
        assert_eq!(source.stats().returned_body_bytes, 0);
        server.join().unwrap();
    }

    #[test]
    fn manifest_get_keeps_the_head_pinned_strong_etag() {
        let (base_url, server) = serve_once(
            vec![
                "HEAD /gateway/v1/epochs/7/manifest HTTP/1.1",
                "GET /gateway/v1/epochs/7/manifest HTTP/1.1",
            ],
            vec![
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\ntest",
            ],
        );
        let source = HttpRangeSource::with_options(
            base_url,
            7,
            None,
            HttpRangeSourceOptions {
                allow_insecure_http: true,
                ..HttpRangeSourceOptions::default()
            },
        )
        .unwrap();
        assert_eq!(source.size(GENERATION_MANIFEST_FILE).unwrap(), Some(4));
        assert_eq!(
            source.read_range(GENERATION_MANIFEST_FILE, 0, 4).unwrap(),
            b"test"
        );
        assert_eq!(
            source.stats(),
            HttpRangeSourceStats {
                head_requests: 1,
                get_requests: 1,
                incomplete_body_retries: 0,
                server_error_retries: 0,
                returned_body_bytes: 4,
            }
        );
        server.join().unwrap();
    }

    #[test]
    fn manifest_get_rejects_a_changed_head_pinned_strong_etag() {
        let (base_url, server) = serve_once(
            vec![
                "HEAD /gateway/v1/epochs/7/manifest HTTP/1.1",
                "GET /gateway/v1/epochs/7/manifest HTTP/1.1",
            ],
            vec![
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nETag: \"v2\"\r\nConnection: close\r\n\r\ntest",
            ],
        );
        let source = HttpRangeSource::with_options(
            base_url,
            7,
            None,
            HttpRangeSourceOptions {
                allow_insecure_http: true,
                ..HttpRangeSourceOptions::default()
            },
        )
        .unwrap();
        assert_eq!(source.size(GENERATION_MANIFEST_FILE).unwrap(), Some(4));
        let error = source
            .read_range(GENERATION_MANIFEST_FILE, 0, 4)
            .unwrap_err();
        assert!(error.to_string().contains("changed strong ETag"));
        assert_eq!(source.stats().returned_body_bytes, 0);
        server.join().unwrap();
    }

    /// One scripted reply of the test server, for one connection.
    #[derive(Clone, Copy)]
    enum Reply {
        /// Read the request head, then write these bytes and close.
        Send(&'static [u8]),
        /// Read the request head, then close with no response.
        Close,
        /// Close at once, before the request is read.
        Drop,
    }

    fn read_request_head(stream: &mut std::net::TcpStream) -> String {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).unwrap();
            assert_ne!(read, 0, "client closed before its request headers ended");
            request.extend_from_slice(&buffer[..read]);
            assert!(
                request.len() <= 16 * 1024,
                "request headers exceed test cap"
            );
        }
        String::from_utf8(request).unwrap()
    }

    /// Serve one connection for each reply, in order. The task returns each
    /// received request head, or an empty string for `Reply::Drop`.
    fn serve_replies(replies: Vec<Reply>) -> (String, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let task = thread::spawn(move || {
            let mut requests = Vec::new();
            for reply in replies {
                let (mut stream, _) = listener.accept().unwrap();
                match reply {
                    Reply::Drop => requests.push(String::new()),
                    Reply::Close => requests.push(read_request_head(&mut stream)),
                    Reply::Send(response) => {
                        requests.push(read_request_head(&mut stream));
                        stream.write_all(response).unwrap();
                    }
                }
            }
            requests
        });
        (format!("http://{address}/gateway"), task)
    }

    /// Method, request target and lower-case headers of one request head.
    fn parse_request(request: &str) -> (String, String, Vec<(String, String)>) {
        let mut lines = request.split("\r\n");
        let mut first = lines.next().unwrap().split(' ');
        let method = first.next().unwrap().to_owned();
        let target = first.next().unwrap().to_owned();
        let headers = lines
            .take_while(|line| !line.is_empty())
            .map(|line| {
                let (name, value) = line.split_once(':').unwrap();
                (name.trim().to_ascii_lowercase(), value.trim().to_owned())
            })
            .collect();
        (method, target, headers)
    }

    fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| value.as_str())
    }

    /// Retries without a wait, so the tests stay fast.
    fn fast_retry_options(max_attempts: u32) -> HttpRangeSourceOptions {
        HttpRangeSourceOptions {
            allow_insecure_http: true,
            retry_policy: HttpRetryPolicy {
                max_attempts,
                initial_backoff: Duration::ZERO,
                max_backoff: Duration::from_secs(1),
            },
            ..HttpRangeSourceOptions::default()
        }
    }

    const RANGE_BC: &[u8] = b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 1-2/4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\nbc";

    #[test]
    fn mixed_causes_use_nested_budgets_as_the_earlier_policy() {
        const SHORT_BODY: &[u8] = b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 1-2/4\r\nConnection: close\r\n\r\nb";
        const UNAVAILABLE: &[u8] =
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        // The earlier fixed policy read these bytes after 5 GETs: a short
        // body starts a new response budget for the 503 retries.
        let (base_url, server) = serve_replies(vec![
            Reply::Send(UNAVAILABLE),
            Reply::Send(SHORT_BODY),
            Reply::Send(UNAVAILABLE),
            Reply::Send(SHORT_BODY),
            Reply::Send(RANGE_BC),
        ]);
        let source =
            HttpRangeSource::with_options(base_url, 7, None, fast_retry_options(3)).unwrap();
        assert_eq!(source.read_range("thing.bin", 1, 2).unwrap(), b"bc");
        assert_eq!(source.stats().get_requests, 5);
        assert_eq!(
            source.retry_stats(),
            HttpRetryStats {
                server_error_retries: 2,
                incomplete_body_retries: 2,
                ..HttpRetryStats::default()
            }
        );
        assert_eq!(server.join().unwrap().len(), 5);
    }

    #[test]
    fn default_policy_retries_a_reset_or_closed_connection_and_returns_the_exact_bytes() {
        for first in [Reply::Drop, Reply::Close] {
            for direct in [false, true] {
                let (base_url, server) = serve_replies(vec![first, Reply::Send(RANGE_BC)]);
                let source = HttpRangeSource::with_options(
                    base_url,
                    7,
                    Some("retry-token"),
                    HttpRangeSourceOptions {
                        allow_insecure_http: true,
                        ..HttpRangeSourceOptions::default()
                    },
                )
                .unwrap();
                assert_eq!(source.retry_policy(), HttpRetryPolicy::default());
                if direct {
                    let mut bytes = [0_u8; 2];
                    source
                        .read_range_into_slice("thing.bin", 1, &mut bytes)
                        .unwrap();
                    assert_eq!(&bytes, b"bc");
                } else {
                    assert_eq!(source.read_range("thing.bin", 1, 2).unwrap(), b"bc");
                }
                let stats = source.stats();
                assert_eq!(stats.get_requests, 2);
                assert_eq!(stats.server_error_retries, 0);
                assert_eq!(stats.incomplete_body_retries, 0);
                assert_eq!(stats.returned_body_bytes, 2);
                assert_eq!(
                    source.retry_stats(),
                    HttpRetryStats {
                        transport_error_retries: 1,
                        ..HttpRetryStats::default()
                    }
                );
                let requests = server.join().unwrap();
                // Each attempt sends the same range and the same credential.
                for request in requests.iter().filter(|request| !request.is_empty()) {
                    let (method, target, headers) = parse_request(request);
                    assert_eq!(method, "GET");
                    assert_eq!(target, "/gateway/v1/epochs/7/files/thing.bin");
                    assert_eq!(header(&headers, "range"), Some("bytes=1-2"));
                    assert_eq!(
                        header(&headers, "authorization"),
                        Some("Bearer retry-token")
                    );
                }
            }
        }
    }

    #[test]
    fn rate_limited_retry_honours_retry_after_zero() {
        let (base_url, server) = serve_replies(vec![
            Reply::Send(b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 0\r\nContent-Length: 4\r\nConnection: close\r\n\r\nslow"),
            Reply::Send(RANGE_BC),
        ]);
        let source = HttpRangeSource::with_options(
            base_url,
            7,
            None,
            HttpRangeSourceOptions {
                allow_insecure_http: true,
                ..HttpRangeSourceOptions::default()
            },
        )
        .unwrap();
        assert_eq!(source.read_range("thing.bin", 1, 2).unwrap(), b"bc");
        assert_eq!(source.stats().get_requests, 2);
        assert_eq!(source.stats().server_error_retries, 0);
        // The 429 body is dropped without being read.
        assert_eq!(source.stats().returned_body_bytes, 2);
        assert_eq!(
            source.retry_stats(),
            HttpRetryStats {
                rate_limited_retries: 1,
                ..HttpRetryStats::default()
            }
        );
        assert_eq!(server.join().unwrap().len(), 2);
    }

    #[test]
    fn retry_after_waits_up_to_the_cap_and_longer_or_dated_values_fail_at_once() {
        let (base_url, server) = serve_replies(vec![
            Reply::Send(b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
            Reply::Send(RANGE_BC),
        ]);
        let source =
            HttpRangeSource::with_options(base_url, 7, None, fast_retry_options(3)).unwrap();
        let started = std::time::Instant::now();
        assert_eq!(source.read_range("thing.bin", 1, 2).unwrap(), b"bc");
        assert!(started.elapsed() >= Duration::from_secs(1));
        assert_eq!(source.retry_stats().rate_limited_retries, 1);
        server.join().unwrap();

        for response in [
            &b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..],
            &b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: Wed, 21 Oct 2015 07:28:00 GMT\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..],
            &b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..],
        ] {
            let (base_url, server) = serve_replies(vec![Reply::Send(response)]);
            let source =
                HttpRangeSource::with_options(base_url, 7, None, fast_retry_options(3)).unwrap();
            let error = source.read_range("thing.bin", 1, 2).unwrap_err().to_string();
            assert!(error.contains("expected 206"), "{error}");
            assert_eq!(source.stats().get_requests, 1);
            assert_eq!(source.retry_stats().total(), 0);
            server.join().unwrap();
        }
    }

    #[test]
    fn always_failing_server_stops_after_max_attempts_and_names_the_last_cause() {
        const SHORT_BODY: &[u8] = b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 1-2/4\r\nConnection: close\r\n\r\nb";
        const TOO_MANY: &[u8] =
            b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        const UNAVAILABLE: &[u8] =
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        // A complete chunked body that is one byte too short.
        const CHUNKED_SHORT: &[u8] = b"HTTP/1.1 206 Partial Content\r\nTransfer-Encoding: chunked\r\nContent-Range: bytes 1-2/4\r\nConnection: close\r\n\r\n1\r\nb\r\n0\r\n\r\n";
        let cases: [(Vec<Reply>, &str, HttpRetryStats); 5] = [
            (
                vec![Reply::Close; 4],
                "HTTP request failed (error sending request)",
                HttpRetryStats {
                    transport_error_retries: 3,
                    ..HttpRetryStats::default()
                },
            ),
            (
                vec![Reply::Send(TOO_MANY); 4],
                "range GET for thing.bin returned HTTP 429 Too Many Requests, expected 206",
                HttpRetryStats {
                    rate_limited_retries: 3,
                    ..HttpRetryStats::default()
                },
            ),
            (
                vec![Reply::Send(UNAVAILABLE); 4],
                "range GET for thing.bin returned HTTP 503 Service Unavailable, expected 206",
                HttpRetryStats {
                    server_error_retries: 3,
                    ..HttpRetryStats::default()
                },
            ),
            // The connection closes before Content-Length is reached.
            (
                vec![Reply::Send(SHORT_BODY); 4],
                "I/O error for thing.bin: request or response body error",
                HttpRetryStats {
                    incomplete_body_retries: 3,
                    ..HttpRetryStats::default()
                },
            ),
            (
                vec![Reply::Send(CHUNKED_SHORT); 4],
                "short range read for thing.bin: got 1 bytes, expected 2",
                HttpRetryStats {
                    incomplete_body_retries: 3,
                    ..HttpRetryStats::default()
                },
            ),
        ];
        for (replies, last_cause, retries) in cases {
            let (base_url, server) = serve_replies(replies);
            let source =
                HttpRangeSource::with_options(base_url, 7, None, fast_retry_options(4)).unwrap();
            let error = source
                .read_range("thing.bin", 1, 2)
                .unwrap_err()
                .to_string();
            assert!(error.contains(last_cause), "{error}");
            assert_eq!(source.stats().get_requests, 4);
            assert_eq!(source.retry_stats(), retries);
            assert_eq!(server.join().unwrap().len(), 4);
        }

        // A refused connection is a connect error, and it is retried too.
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = closed.local_addr().unwrap();
        drop(closed);
        let source = HttpRangeSource::with_options(
            format!("http://{address}"),
            7,
            None,
            fast_retry_options(4),
        )
        .unwrap();
        let error = source.size("thing.bin").unwrap_err().to_string();
        assert_eq!(
            error,
            "remote source protocol error: HTTP request failed (error sending request)"
        );
        assert_eq!(source.stats().head_requests, 4);
        assert_eq!(source.retry_stats().transport_error_retries, 3);
    }

    #[test]
    fn transport_retry_keeps_the_pinned_identity() {
        let (base_url, server) = serve_replies(vec![
            Reply::Send(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n"),
            Reply::Close,
            Reply::Send(b"HTTP/1.1 206 Partial Content\r\nContent-Length: 2\r\nContent-Range: bytes 1-2/4\r\nETag: \"v2\"\r\nConnection: close\r\n\r\nbc"),
        ]);
        let source =
            HttpRangeSource::with_options(base_url, 7, None, fast_retry_options(3)).unwrap();
        source.strong_identity("thing.bin").unwrap();
        let error = source.read_range("thing.bin", 1, 2).unwrap_err();
        assert!(error.to_string().contains("changed strong ETag"));
        assert_eq!(source.stats().get_requests, 2);
        assert_eq!(source.stats().returned_body_bytes, 0);
        assert_eq!(source.retry_stats().transport_error_retries, 1);
        server.join().unwrap();
    }

    #[test]
    fn head_and_manifest_calls_retry_transient_failures() {
        let (base_url, server) = serve_replies(vec![
            Reply::Close,
            Reply::Send(b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
            Reply::Send(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n"),
            Reply::Send(b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
            Reply::Send(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\nte"),
            Reply::Send(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\ntest"),
        ]);
        let source =
            HttpRangeSource::with_options(base_url, 7, None, fast_retry_options(3)).unwrap();
        assert_eq!(source.size(GENERATION_MANIFEST_FILE).unwrap(), Some(4));
        assert_eq!(
            source.read_range(GENERATION_MANIFEST_FILE, 0, 4).unwrap(),
            b"test"
        );
        assert_eq!(
            source.stats(),
            HttpRangeSourceStats {
                head_requests: 3,
                get_requests: 3,
                incomplete_body_retries: 1,
                // This counter keeps its GET-only meaning.
                server_error_retries: 0,
                returned_body_bytes: 6,
            }
        );
        assert_eq!(
            source.retry_stats(),
            HttpRetryStats {
                transport_error_retries: 1,
                rate_limited_retries: 1,
                server_error_retries: 1,
                incomplete_body_retries: 1,
            }
        );
        let requests = server.join().unwrap();
        let methods = requests
            .iter()
            .map(|request| parse_request(request).0)
            .collect::<Vec<_>>();
        assert_eq!(methods, ["HEAD", "HEAD", "HEAD", "GET", "GET", "GET"]);
    }

    #[test]
    fn one_attempt_disables_retries_and_zero_attempts_are_rejected() {
        let (base_url, server) = serve_replies(vec![Reply::Close]);
        let source =
            HttpRangeSource::with_options(base_url, 7, None, fast_retry_options(1)).unwrap();
        let error = source.read_range("thing.bin", 1, 2).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("HTTP request failed (error sending request)")
        );
        assert_eq!(source.stats().get_requests, 1);
        assert_eq!(source.retry_stats().total(), 0);
        server.join().unwrap();

        let error =
            HttpRangeSource::with_options("http://127.0.0.1:1", 7, None, fast_retry_options(0))
                .unwrap_err();
        assert!(error.to_string().contains("max_attempts must be non-zero"));
        let signer = Arc::new(S3SigV4Signer::for_r2(
            S3Credentials::new("AKID", "secret", None).unwrap(),
        ));
        let error =
            HttpRangeSource::with_signer("http://127.0.0.1:1", 7, signer, fast_retry_options(0))
                .unwrap_err();
        assert!(error.to_string().contains("max_attempts must be non-zero"));
    }

    #[test]
    fn s3_signer_headers_reach_the_server_on_every_request_and_retry() {
        const SECRET: &str = "r2-test-secret-key";
        const TOKEN: &str = "r2-test-session/token+value=";
        let (base_url, server) = serve_replies(vec![
            Reply::Send(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n"),
            Reply::Send(b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
            Reply::Send(RANGE_BC),
        ]);
        let credentials = S3Credentials::new(
            "0123456789abcdef0123456789abcdef",
            SECRET,
            Some(TOKEN.into()),
        )
        .unwrap();
        let signer = S3SigV4Signer::for_r2(credentials);
        let source = HttpRangeSource::with_signer(
            format!("{base_url}/solana-archive-data/compact-v2/epoch-200"),
            200,
            Arc::new(signer.clone()),
            HttpRangeSourceOptions {
                object_path_layout: HttpObjectPathLayout::FlatObjects,
                ..fast_retry_options(3)
            },
        )
        .unwrap();
        assert_eq!(source.strong_identity("thing.bin").unwrap().length, 4);
        assert_eq!(source.read_range("thing.bin", 1, 2).unwrap(), b"bc");
        let rendered = format!("{source:?}");
        assert!(
            rendered.contains("request_signer: Some(\"<redacted>\")"),
            "{rendered}"
        );
        assert!(
            !rendered.contains(SECRET) && !rendered.contains(TOKEN),
            "{rendered}"
        );

        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 3);
        for (index, request) in requests.iter().enumerate() {
            assert!(!request.contains(SECRET), "the secret must not travel");
            let (method, target, headers) = parse_request(request);
            assert_eq!(method, if index == 0 { "HEAD" } else { "GET" });
            assert_eq!(
                target,
                "/gateway/solana-archive-data/compact-v2/epoch-200/thing.bin"
            );
            assert_eq!(
                header(&headers, "x-amz-content-sha256"),
                Some("UNSIGNED-PAYLOAD")
            );
            assert_eq!(header(&headers, "x-amz-security-token"), Some(TOKEN));
            let amz_date = header(&headers, "x-amz-date").unwrap();
            assert_eq!(amz_date.len(), 16);
            let authorization = header(&headers, "authorization").unwrap();
            let expected_signed = if index == 0 {
                "host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
            } else {
                assert_eq!(header(&headers, "range"), Some("bytes=1-2"));
                "host;range;x-amz-content-sha256;x-amz-date;x-amz-security-token"
            };
            assert!(
                authorization.starts_with(&format!(
                    "AWS4-HMAC-SHA256 Credential=0123456789abcdef0123456789abcdef/{}/auto/s3/aws4_request, SignedHeaders={expected_signed}, Signature=",
                    &amz_date[..8]
                )),
                "{authorization}"
            );
            // Recompute the signature from what the server received: the
            // Host that the client sent, the path and the signed headers.
            let host = header(&headers, "host").unwrap();
            let url = Url::parse(&format!("http://{host}{target}")).unwrap();
            let signed = expected_signed
                .split(';')
                .map(|name| (name, header(&headers, name).unwrap()))
                .collect::<Vec<_>>();
            assert_eq!(
                authorization,
                signer.authorization_for_parts(&method, &url, &signed, amz_date)
            );
        }
        assert_eq!(source.retry_stats().server_error_retries, 1);
    }

    /// Method, URL path, `Range` and `Accept-Encoding` that a signer saw.
    type SeenRequest = (String, String, Option<String>, Option<String>);

    /// A signer that records what it sees, adds one header, or fails.
    struct RecordingSigner {
        fail: bool,
        seen: Mutex<Vec<SeenRequest>>,
    }

    impl HttpRequestSigner for RecordingSigner {
        fn sign(&self, request: &mut HttpRequestToSign<'_>) -> SourceResult<()> {
            if self.fail {
                return Err(SourceError::Protocol("test signer refused".into()));
            }
            self.seen.lock().unwrap().push((
                request.method().to_owned(),
                request.url().path().to_owned(),
                request.header("range").map(str::to_owned),
                request.header("accept-encoding").map(str::to_owned),
            ));
            let value = format!(
                "{} {}",
                request.method(),
                request.header("range").unwrap_or("-")
            );
            request.set_header("x-test-signature", &value)
        }
    }

    #[test]
    fn custom_signer_sees_the_final_source_headers_and_a_failure_sends_nothing() {
        let (base_url, server) = serve_replies(vec![Reply::Send(RANGE_BC)]);
        let signer = Arc::new(RecordingSigner {
            fail: false,
            seen: Mutex::new(Vec::new()),
        });
        let source =
            HttpRangeSource::with_signer(base_url, 7, signer.clone(), fast_retry_options(3))
                .unwrap();
        assert_eq!(source.read_range("thing.bin", 1, 2).unwrap(), b"bc");
        assert_eq!(
            *signer.seen.lock().unwrap(),
            [(
                "GET".to_owned(),
                "/gateway/v1/epochs/7/files/thing.bin".to_owned(),
                Some("bytes=1-2".to_owned()),
                Some("identity".to_owned()),
            )]
        );
        let requests = server.join().unwrap();
        let (_, _, headers) = parse_request(&requests[0]);
        assert_eq!(header(&headers, "x-test-signature"), Some("GET bytes=1-2"));
        assert_eq!(header(&headers, "authorization"), None);

        let failing = Arc::new(RecordingSigner {
            fail: true,
            seen: Mutex::new(Vec::new()),
        });
        let source =
            HttpRangeSource::with_signer("http://127.0.0.1:1", 7, failing, fast_retry_options(3))
                .unwrap();
        let error = source.read_range("thing.bin", 1, 2).unwrap_err();
        assert!(error.to_string().contains("test signer refused"));
        assert_eq!(source.stats().requests(), 0);
        assert_eq!(source.retry_stats().total(), 0);
    }
}
