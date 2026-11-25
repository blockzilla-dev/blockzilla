//! Bounded retry policy for transient HTTP failures.

use std::time::Duration;

use reqwest::{StatusCode, blocking::Response, header::RETRY_AFTER};

use blockzilla_source::{SourceError, SourceResult};

/// Bounded retry policy for transient HTTP failures.
///
/// The source sends a new request for one HEAD or GET after these causes:
///
/// - any error before a response: for example a connect failure, a timeout,
///   a reset or closed connection, a DNS or TLS failure;
/// - HTTP 429, 500, 502, 503 or 504;
/// - a response body with a read error (for example a reset or a timeout), or
///   a body that ends before the expected length.
///
/// The source does not retry other statuses, a body that is too long, or a
/// changed identity. Each new request passes all length, `Content-Range` and
/// pinned strong-ETag checks again, so a retry cannot return different bytes.
///
/// The budgets are nested, as in the earlier fixed policy. One call has up to
/// `max_attempts` body attempts; a body error starts the next one at once.
/// Each body attempt has up to `max_attempts` requests for errors before a
/// response and for transient statuses. Retry `n` of one body attempt (`n`
/// starts at 0) waits `initial_backoff * 2^n`, but not more than
/// `max_backoff`. When a 429 or 5xx response has `Retry-After` in seconds,
/// the wait is not shorter than that value. When that value is more than
/// `max_backoff`, or is not in the seconds form, the source does not retry:
/// it returns the error for that response.
///
/// The default is 3 attempts, a 250 ms initial backoff and a 5 s cap. These
/// are the values of the earlier fixed policy for HTTP 5xx responses. A
/// multi-hour stream can use a larger budget, for example 8 attempts and a
/// 30 s cap, to continue through a short outage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpRetryPolicy {
    /// Maximum requests for one source call, including the first request.
    /// It must be at least 1. The value 1 disables retries.
    pub max_attempts: u32,
    /// Wait before the first retry. Each next retry doubles the wait.
    pub initial_backoff: Duration,
    /// Maximum wait before one retry, and the largest `Retry-After` value
    /// that the source accepts.
    pub max_backoff: Duration,
}

impl Default for HttpRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(250),
            max_backoff: Duration::from_secs(5),
        }
    }
}

impl HttpRetryPolicy {
    pub(crate) fn validate(&self) -> SourceResult<()> {
        if self.max_attempts == 0 {
            return Err(SourceError::Protocol(
                "retry policy max_attempts must be non-zero".into(),
            ));
        }
        Ok(())
    }

    /// Wait before retry `retry`, where 0 is the first retry.
    pub(crate) fn backoff(&self, retry: u32) -> Duration {
        let factor = 1_u32.checked_shl(retry).unwrap_or(u32::MAX);
        self.initial_backoff
            .saturating_mul(factor)
            .min(self.max_backoff)
    }

    /// Return the cause and the wait for a retry after this response, or
    /// `None` when the status is not transient or the server asks for a
    /// longer wait than the cap.
    pub(crate) fn status_retry(
        &self,
        response: &Response,
        retry: u32,
    ) -> Option<(RetryCause, Duration)> {
        let cause = match response.status() {
            StatusCode::TOO_MANY_REQUESTS => RetryCause::RateLimited,
            StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT => RetryCause::ServerError,
            _ => return None,
        };
        let backoff = self.backoff(retry);
        match response.headers().get(RETRY_AFTER) {
            None => Some((cause, backoff)),
            Some(value) => {
                // Do not retry earlier than a server asks. Long waits, dates
                // and invalid values fail normally. They do not block this SDK
                // call for an unbounded interval.
                let seconds = value.to_str().ok()?.parse::<u64>().ok()?;
                let requested = Duration::from_secs(seconds);
                (requested <= self.max_backoff).then(|| (cause, backoff.max(requested)))
            }
        }
    }
}

/// The cause of one retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetryCause {
    Transport,
    RateLimited,
    ServerError,
    IncompleteBody,
}

/// Retry counts by cause, for one source and all its clones.
///
/// Each count is one new HEAD or GET request after a failed attempt.
/// [`HttpRangeSourceStats`](crate::HttpRangeSourceStats) keeps its GET-only
/// `server_error_retries` and `incomplete_body_retries` counters. The request
/// counts there include all retries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HttpRetryStats {
    /// New requests after a transport error before a response: connect
    /// failure, timeout, or a reset or closed connection.
    pub transport_error_retries: u64,
    /// New requests after HTTP 429.
    pub rate_limited_retries: u64,
    /// New HEAD or GET requests after HTTP 500, 502, 503 or 504.
    pub server_error_retries: u64,
    /// New GET requests after a body read error or a body that ended early.
    pub incomplete_body_retries: u64,
}

impl HttpRetryStats {
    /// All retries, for all causes.
    pub fn total(self) -> u64 {
        self.transport_error_retries
            .saturating_add(self.rate_limited_retries)
            .saturating_add(self.server_error_retries)
            .saturating_add(self.incomplete_body_retries)
    }

    pub fn saturating_sub(self, earlier: Self) -> Self {
        Self {
            transport_error_retries: self
                .transport_error_retries
                .saturating_sub(earlier.transport_error_retries),
            rate_limited_retries: self
                .rate_limited_retries
                .saturating_sub(earlier.rate_limited_retries),
            server_error_retries: self
                .server_error_retries
                .saturating_sub(earlier.server_error_retries),
            incomplete_body_retries: self
                .incomplete_body_retries
                .saturating_sub(earlier.incomplete_body_retries),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_keeps_the_earlier_fixed_values() {
        assert_eq!(
            HttpRetryPolicy::default(),
            HttpRetryPolicy {
                max_attempts: 3,
                initial_backoff: Duration::from_millis(250),
                max_backoff: Duration::from_secs(5),
            }
        );
    }

    #[test]
    fn backoff_doubles_and_stops_at_the_cap() {
        let policy = HttpRetryPolicy::default();
        let waits = (0..8)
            .map(|retry| policy.backoff(retry).as_millis())
            .collect::<Vec<_>>();
        assert_eq!(waits, [250, 500, 1_000, 2_000, 4_000, 5_000, 5_000, 5_000]);
        // Large retry numbers saturate. They do not overflow or panic.
        assert_eq!(policy.backoff(31), policy.max_backoff);
        assert_eq!(policy.backoff(32), policy.max_backoff);
        assert_eq!(policy.backoff(u32::MAX), policy.max_backoff);
        let capped = HttpRetryPolicy {
            max_attempts: 2,
            initial_backoff: Duration::from_secs(9),
            max_backoff: Duration::from_secs(1),
        };
        assert_eq!(capped.backoff(0), Duration::from_secs(1));
        let huge = HttpRetryPolicy {
            max_attempts: 2,
            initial_backoff: Duration::MAX,
            max_backoff: Duration::MAX,
        };
        assert_eq!(huge.backoff(3), Duration::MAX);
    }

    #[test]
    fn zero_attempts_are_rejected() {
        let error = HttpRetryPolicy {
            max_attempts: 0,
            ..HttpRetryPolicy::default()
        }
        .validate()
        .unwrap_err();
        assert!(error.to_string().contains("max_attempts must be non-zero"));
        HttpRetryPolicy {
            max_attempts: 1,
            ..HttpRetryPolicy::default()
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn retry_stats_total_and_difference_saturate() {
        let later = HttpRetryStats {
            transport_error_retries: 4,
            rate_limited_retries: 3,
            server_error_retries: 2,
            incomplete_body_retries: 1,
        };
        assert_eq!(later.total(), 10);
        assert_eq!(later.saturating_sub(HttpRetryStats::default()), later);
        assert_eq!(later.saturating_sub(later), HttpRetryStats::default());
        assert_eq!(HttpRetryStats::default().saturating_sub(later).total(), 0);
        let full = HttpRetryStats {
            transport_error_retries: u64::MAX,
            rate_limited_retries: 1,
            ..HttpRetryStats::default()
        };
        assert_eq!(full.total(), u64::MAX);
    }
}
