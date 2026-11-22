//! Request-local archive operation counts. These count object API calls, not
//! physical disk reads or the customer request-billing flag.

use std::{cell::Cell, rc::Rc};

#[derive(Clone, Copy)]
pub(crate) enum StorageBackend {
    R2,
    S3,
    /// A conditional R2 GET made by the private Foundation reader. Attempts
    /// enter this counter only after its authenticated HTTP proof is checked.
    FoundationR2,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct StorageSnapshot {
    pub(crate) r2_gets: u64,
    pub(crate) r2_heads: u64,
    pub(crate) r2_get_successes: u64,
    pub(crate) r2_head_successes: u64,
    pub(crate) r2_bytes: u64,
    pub(crate) s3_gets: u64,
    pub(crate) s3_heads: u64,
    pub(crate) s3_get_successes: u64,
    pub(crate) s3_head_successes: u64,
    pub(crate) s3_bytes: u64,
    pub(crate) archive_memory_hits: u64,
    pub(crate) archive_edge_hits: u64,
    pub(crate) reader_http_requests: u64,
    pub(crate) foundation_r2_gets: u64,
    pub(crate) foundation_r2_get_successes: u64,
    pub(crate) foundation_r2_bytes: u64,
    pub(crate) foundation_lookup_http_requests: u64,
    pub(crate) foundation_resolve_http_requests: u64,
    pub(crate) foundation_recent_http_requests: u64,
}

impl StorageSnapshot {
    /// Attempts include missing objects and failed calls. Success means a
    /// found HEAD or an exact complete range body. Bytes are body bytes read
    /// by this Worker, including a complete body with an incorrect length.
    pub(crate) fn headers(self) -> [(&'static str, u64); 22] {
        [
            (
                "X-Blockzilla-R2-Reads",
                self.r2_gets.saturating_add(self.r2_heads),
            ),
            ("X-Blockzilla-R2-GETs", self.r2_gets),
            ("X-Blockzilla-R2-HEADs", self.r2_heads),
            ("X-Blockzilla-R2-GET-Successes", self.r2_get_successes),
            ("X-Blockzilla-R2-HEAD-Successes", self.r2_head_successes),
            ("X-Blockzilla-R2-Bytes", self.r2_bytes),
            (
                "X-Blockzilla-S3-Reads",
                self.s3_gets.saturating_add(self.s3_heads),
            ),
            ("X-Blockzilla-S3-GETs", self.s3_gets),
            ("X-Blockzilla-S3-HEADs", self.s3_heads),
            ("X-Blockzilla-S3-GET-Successes", self.s3_get_successes),
            ("X-Blockzilla-S3-HEAD-Successes", self.s3_head_successes),
            ("X-Blockzilla-S3-Bytes", self.s3_bytes),
            ("X-Blockzilla-Archive-Memory-Hits", self.archive_memory_hits),
            ("X-Blockzilla-Archive-Edge-Hits", self.archive_edge_hits),
            (
                "X-Blockzilla-Reader-HTTP-Requests",
                self.reader_http_requests,
            ),
            ("X-Blockzilla-Foundation-R2-GETs", self.foundation_r2_gets),
            ("X-Blockzilla-Foundation-R2-HEADs", 0),
            ("X-Blockzilla-Foundation-R2-Bytes", self.foundation_r2_bytes),
            (
                "X-Blockzilla-Foundation-R2-GET-Successes",
                self.foundation_r2_get_successes,
            ),
            (
                "X-Blockzilla-Foundation-Lookup-HTTP-Requests",
                self.foundation_lookup_http_requests,
            ),
            (
                "X-Blockzilla-Foundation-Resolve-HTTP-Requests",
                self.foundation_resolve_http_requests,
            ),
            (
                "X-Blockzilla-Foundation-Recent-HTTP-Requests",
                self.foundation_recent_http_requests,
            ),
        ]
    }
}

#[derive(Clone, Default)]
pub(crate) struct StorageMetrics(Rc<Cell<StorageSnapshot>>);

impl StorageMetrics {
    pub(crate) fn attempt_foundation_recent_http(&self) {
        self.update(|value| {
            value.foundation_recent_http_requests =
                value.foundation_recent_http_requests.saturating_add(1)
        });
    }
    pub(crate) fn attempt_foundation_resolve_http(&self) {
        self.update(|value| {
            value.foundation_resolve_http_requests =
                value.foundation_resolve_http_requests.saturating_add(1)
        });
    }
    pub(crate) fn snapshot(&self) -> StorageSnapshot {
        self.0.get()
    }

    fn update(&self, apply: impl FnOnce(&mut StorageSnapshot)) {
        let mut snapshot = self.0.get();
        apply(&mut snapshot);
        self.0.set(snapshot);
    }

    pub(crate) fn attempt_get(&self, backend: StorageBackend) {
        self.update(|value| match backend {
            StorageBackend::R2 => value.r2_gets = value.r2_gets.saturating_add(1),
            StorageBackend::S3 => value.s3_gets = value.s3_gets.saturating_add(1),
            StorageBackend::FoundationR2 => {
                value.foundation_r2_gets = value.foundation_r2_gets.saturating_add(1)
            }
        });
    }

    pub(crate) fn complete_get(&self, backend: StorageBackend, bytes: usize, exact: bool) {
        self.update(|value| match backend {
            StorageBackend::R2 => {
                value.r2_bytes = value.r2_bytes.saturating_add(bytes as u64);
                value.r2_get_successes = value.r2_get_successes.saturating_add(u64::from(exact));
            }
            StorageBackend::S3 => {
                value.s3_bytes = value.s3_bytes.saturating_add(bytes as u64);
                value.s3_get_successes = value.s3_get_successes.saturating_add(u64::from(exact));
            }
            StorageBackend::FoundationR2 => {
                value.foundation_r2_bytes = value.foundation_r2_bytes.saturating_add(bytes as u64);
                value.foundation_r2_get_successes = value
                    .foundation_r2_get_successes
                    .saturating_add(u64::from(exact));
            }
        });
    }

    pub(crate) fn attempt_head(&self, backend: StorageBackend) {
        self.update(|value| match backend {
            StorageBackend::R2 => value.r2_heads = value.r2_heads.saturating_add(1),
            StorageBackend::S3 => value.s3_heads = value.s3_heads.saturating_add(1),
            StorageBackend::FoundationR2 => unreachable!("native reader has no HEAD operation"),
        });
    }

    pub(crate) fn complete_head(&self, backend: StorageBackend, found: bool) {
        self.update(|value| match backend {
            StorageBackend::R2 => {
                value.r2_head_successes = value.r2_head_successes.saturating_add(u64::from(found))
            }
            StorageBackend::S3 => {
                value.s3_head_successes = value.s3_head_successes.saturating_add(u64::from(found))
            }
            StorageBackend::FoundationR2 => unreachable!("native reader has no HEAD operation"),
        });
    }

    /// HTTP attempts are separate from confirmed R2 attempts. A failed HTTP
    /// transport can leave the backend operation count unknown.
    pub(crate) fn attempt_reader_http(&self) {
        self.update(|value| {
            value.reader_http_requests = value.reader_http_requests.saturating_add(1)
        });
    }

    /// A native Foundation lookup is an HTTP call, not an R2 operation.
    pub(crate) fn attempt_foundation_lookup_http(&self) {
        self.update(|value| {
            value.foundation_lookup_http_requests =
                value.foundation_lookup_http_requests.saturating_add(1)
        });
    }

    pub(crate) fn memory_hit(&self) {
        self.update(|value| {
            value.archive_memory_hits = value.archive_memory_hits.saturating_add(1)
        });
    }

    pub(crate) fn edge_hit(&self) {
        self.update(|value| value.archive_edge_hits = value.archive_edge_hits.saturating_add(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_attempts_failures_missing_objects_and_returned_bytes_separately() {
        let metrics = StorageMetrics::default();
        metrics.attempt_get(StorageBackend::R2); // failed network call
        metrics.attempt_get(StorageBackend::R2);
        metrics.complete_get(StorageBackend::R2, 1024, true);
        metrics.attempt_get(StorageBackend::R2);
        metrics.complete_get(StorageBackend::R2, 3, false); // wrong length
        metrics.attempt_head(StorageBackend::R2);
        metrics.complete_head(StorageBackend::R2, false); // missing schema marker
        metrics.attempt_head(StorageBackend::R2);
        metrics.complete_head(StorageBackend::R2, true);
        let result = metrics.snapshot();
        assert_eq!((result.r2_gets, result.r2_get_successes), (3, 1));
        assert_eq!((result.r2_heads, result.r2_head_successes), (2, 1));
        assert_eq!(result.r2_bytes, 1027);
        assert_eq!(result.headers()[0], ("X-Blockzilla-R2-Reads", 5));
    }

    #[test]
    fn cloned_sources_share_only_one_request_and_cache_hits_do_not_read_storage() {
        let metrics = StorageMetrics::default();
        let source = metrics.clone();
        source.attempt_get(StorageBackend::S3);
        source.complete_get(StorageBackend::S3, 64, true);
        metrics.memory_hit();
        source.edge_hit();
        let result = metrics.snapshot();
        assert_eq!(result.s3_gets, 1);
        assert_eq!(result.s3_bytes, 64);
        assert_eq!(result.archive_memory_hits, 1);
        assert_eq!(result.archive_edge_hits, 1);
        assert_eq!(result.r2_gets, 0);
        assert_eq!(
            StorageMetrics::default().snapshot(),
            StorageSnapshot::default()
        );
        assert!(
            StorageSnapshot::default()
                .headers()
                .iter()
                .all(|(_, value)| *value == 0)
        );
    }

    #[test]
    fn native_reader_transport_and_confirmed_r2_work_are_separate() {
        let metrics = StorageMetrics::default();
        metrics.attempt_reader_http(); // network error, no proof
        metrics.attempt_reader_http(); // proof: R2 GET attempted, object missing
        metrics.attempt_get(StorageBackend::FoundationR2);
        metrics.attempt_reader_http();
        metrics.attempt_get(StorageBackend::FoundationR2);
        metrics.complete_get(StorageBackend::FoundationR2, 4096, true);
        let result = metrics.snapshot();
        assert_eq!(result.reader_http_requests, 3);
        assert_eq!(result.foundation_r2_gets, 2);
        assert_eq!(result.foundation_r2_get_successes, 1);
        assert_eq!(result.foundation_r2_bytes, 4096);
        assert_eq!((result.r2_gets, result.s3_gets), (0, 0));
        assert_eq!(
            result.headers()[16],
            ("X-Blockzilla-Foundation-R2-HEADs", 0)
        );
    }
}
