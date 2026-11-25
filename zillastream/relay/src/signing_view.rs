//! Live signing observations. This view does not replay bank events.
use crate::{bank_server::STATUS_INTERVAL, server::Api};
use axum::{
    Json,
    body::Body,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use blockzilla_bank_stream_v2::{ConfirmedObservation, DEFAULT_MAX_LAG_MS, Head};
use bytes::Bytes;
use serde_json::json;
use std::fmt::Write;
use tokio::time::Instant;

#[derive(Default)]
struct SigningConnection {
    published_sequence: Option<u64>,
    ready: bool,
}

impl SigningConnection {
    fn update<'a>(&mut self, head: &'a Head) -> Option<&'a ConfirmedObservation> {
        let selected = head.latest_confirmed.as_ref().filter(|_| {
            head.status == "live"
                && head
                    .validate(&head.source, head.sampled_at_unix_ms, DEFAULT_MAX_LAG_MS)
                    .is_ok()
        });
        let newer = selected.filter(|s| {
            self.published_sequence
                .is_none_or(|previous| s.event_sequence > previous)
        });
        // After readiness is lost, wait for a new native observation. A repeat
        // or a selection behind the last published sequence cannot restore it.
        self.ready = newer.is_some()
            || (self.ready
                && selected.is_some_and(|s| Some(s.event_sequence) == self.published_sequence));
        if let Some(new) = newer {
            self.published_sequence = Some(new.event_sequence);
        }
        newer
    }
}

pub async fn events(State(api): State<Api>) -> Response {
    let Some(banks) = api.banks else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::CACHE_CONTROL, "no-store")],
            Json(json!({"error": "signing_feed_unavailable"})),
        )
            .into_response();
    };
    let store = banks.store;
    let stream = async_stream::stream! {
        let mut connection = SigningConnection::default();
        let mut last_status = None;
        let mut next_status = Instant::now();
        loop {
            let changed = store.notify.notified();
            let head = store.head();
            let observation = connection.update(&head);
            let now = Instant::now();
            let mut message = String::new();
            if now >= next_status
                || !last_status.as_ref().is_some_and(|(status, ready)| {
                    status == &head.status && *ready == connection.ready
                })
            {
                let status = json!({
                    "status": head.status,
                    "ready": connection.ready,
                    "source": head.source,
                    "sampledAtMs": head.sampled_at_unix_ms,
                });
                write!(message, "event: status\ndata: {status}\n\n").unwrap();
                last_status = Some((head.status.clone(), connection.ready));
                next_status = now + STATUS_INTERVAL;
            }
            if let Some(observation) = observation {
                let signing = json!({
                    "source": head.source,
                    "commitment": observation.commitment,
                    "contextSlot": observation.recent_blockhash.context_slot,
                    "blockHeight": observation.block_height,
                    "blockhash": observation.recent_blockhash.blockhash,
                    "lastValidBlockHeight": observation.recent_blockhash.last_valid_block_height,
                    "observedAtMs": observation.observed_at_unix_ms,
                    "sampledAtMs": head.sampled_at_unix_ms,
                    "eventCursor": observation.event_cursor,
                });
                write!(message, "event: blockhash\ndata: {signing}\n\n").unwrap();
            }
            // Emit both records from this snapshot together. A slow client
            // cannot suspend the stream between status and its observation.
            if !message.is_empty() {
                yield Ok::<Bytes, std::io::Error>(message.into());
            }
            if head.status == "failed" {
                break;
            }
            tokio::select! {
                _ = changed => {},
                _ = tokio::time::sleep_until(next_status) => {},
            }
        }
    };
    (
        [
            (header::CONTENT_TYPE, "text/event-stream; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        Body::from_stream(stream),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use blockzilla_bank_stream_v2 as v2;

    fn head(sequence: u64) -> Head {
        let source = v2::fixtures::source();
        let block = v2::fixtures::block(1, 10, 1, 9, 10);
        let control = v2::fixtures::control(&block, sequence, "confirmed", 1000);
        Head {
            schema: v2::HEAD.into(),
            profile: v2::PROFILE.into(),
            cursor: Some(control.cursor.clone()),
            earliest_after: Some(v2::cursor(&source.session_id, 0, "-")),
            source,
            status: "live".into(),
            sampled_at_unix_ms: 1000,
            source_observed_at_unix_ms: Some(1000),
            source_lag_ms: Some(0),
            latest_confirmed: Some(ConfirmedObservation::from_frame(&control).unwrap()),
        }
    }

    #[test]
    fn stale_or_older_selection_cannot_restore_readiness() {
        let mut connection = SigningConnection::default();
        let current = head(3);
        assert_eq!(connection.update(&current).unwrap().event_sequence, 3);
        assert!(connection.update(&current).is_none());
        assert!(connection.ready);

        let mut stale = current.clone();
        stale.status = "stale".into();
        assert!(connection.update(&stale).is_none());
        assert!(connection.update(&current).is_none());
        assert!(connection.update(&head(2)).is_none());
        assert!(!connection.ready);

        let mut expired = head(4);
        expired.sampled_at_unix_ms += DEFAULT_MAX_LAG_MS + 1;
        expired.source_lag_ms = Some(DEFAULT_MAX_LAG_MS + 1);
        assert!(connection.update(&expired).is_none());
        assert!(!connection.ready);

        assert_eq!(connection.update(&head(4)).unwrap().event_sequence, 4);
        assert!(connection.ready);
    }
}
