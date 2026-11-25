//! Read exact recovery notices through the authenticated stream.
use super::{MAX_RECOVERY_PLAN_BYTES, MAX_RECOVERY_PLAN_EVENTS, RecoveryEntry, RecoveryNotice};
use crate::{
    BankClient, ClientError, Head, Result, Sse, admission, header, network, now_ms, protocol,
};
use blockzilla_bank_stream_v2 as v2;
use futures_util::{StreamExt, TryStreamExt, stream};
use std::time::Duration;

const CONTROL_FRAME_MAX: usize = 16 + v2::MAX_META;

impl BankClient {
    /// Read a bounded page from the committed `after` cursor toward `until`.
    /// Sample `until` once with `head` after a disconnect. Each returned block
    /// has metadata only. The stream supplies original control frames by hash.
    /// Fetch missing blocks with `WorkerRecoveryClient::new_public` and commit
    /// each checked frame and cursor before asking for the next page.
    pub async fn recovery_plan(
        &self,
        after: &str,
        until: &str,
        max_events: usize,
    ) -> Result<Vec<RecoveryEntry>> {
        self.check_cursor(after)?;
        self.check_cursor(until)?;
        let first = v2::parse_cursor(after).map_err(admission)?.1;
        let last = v2::parse_cursor(until).map_err(admission)?.1;
        if !(1..=MAX_RECOVERY_PLAN_EVENTS).contains(&max_events)
            || first > last
            || (first == last && after != until)
        {
            return Err(protocol("invalid_recovery_window"));
        }
        if after == until {
            return Ok(Vec::new());
        }
        let end = last.min(first + max_events as u64);
        tokio::time::timeout(Duration::from_secs(30), async {
            let notices = self
                .read_recovery_notices(after, until, first, last, end)
                .await?;
            stream::iter(notices)
                .map(|wire| async move {
                    let control = if wire.event.kind == "block" {
                        None
                    } else {
                        // The admitted notice size bounds the original control
                        // read. No block URL from the notice is fetched here.
                        let frame = self
                            .fetch_bounded(&wire.notice.sha256, wire.notice.bytes)
                            .await?;
                        wire.validate(
                            &wire.notice.cursor,
                            &frame,
                            wire.event.sequence,
                            self.source(),
                        )
                        .map_err(admission)?;
                        Some(frame)
                    };
                    Ok(RecoveryEntry {
                        notice: RecoveryNotice {
                            cursor: wire.notice.cursor,
                            sha256: wire.notice.sha256,
                            event: wire.event,
                            source: self.source().clone(),
                        },
                        control,
                    })
                })
                .buffered(self.config.max_in_flight)
                .try_collect()
                .await
        })
        .await
        .map_err(|_| ClientError::Transient("public_recovery_plan_timeout".into()))?
    }

    async fn read_recovery_notices(
        &self,
        after: &str,
        until: &str,
        first: u64,
        last: u64,
        end: u64,
    ) -> Result<Vec<v2::RecoveryStreamNotice>> {
        let query = [("after", after), ("recovery", "1")];
        let mut response = self
            .retry(|| self.response_query("v2/banks/events", &query))
            .await?;
        if header(&response, "x-blockzilla-start-cursor") != Some(after)
            || header(&response, "x-blockzilla-notice-format") != Some(v2::RECOVERY_NOTICE_FORMAT)
            || response
                .headers()
                .get_all("x-blockzilla-notice-format")
                .iter()
                .count()
                != 1
            || !header(&response, "content-type")
                .is_some_and(|value| value.split(';').next() == Some("text/event-stream"))
        {
            return Err(protocol("recovery_stream_headers_mismatch"));
        }
        let mut parser = Sse::default();
        let mut notices = Vec::with_capacity((end - first) as usize);
        let mut sequence = first;
        let mut status_seen = false;
        let mut plan_bytes = 0;
        while let Some(part) = response.chunk().await.map_err(network)? {
            plan_bytes += part.len();
            if parser.pending.len() + part.len() > 2 * v2::MAX_META
                || plan_bytes > MAX_RECOVERY_PLAN_BYTES
            {
                return Err(protocol("recovery_plan_too_large"));
            }
            parser.pending.extend_from_slice(&part);
            while let Some(line_end) = parser.pending.iter().position(|&byte| byte == b'\n') {
                let line = parser.pending.split_to(line_end + 1);
                let Some((kind, id, data)) = parser.line(&line[..line_end])? else {
                    continue;
                };
                match kind.as_str() {
                    "status" if id.is_empty() => {
                        let head: Head = serde_json::from_str(&data)
                            .map_err(|_| protocol("invalid_recovery_status"))?;
                        head.validate(self.source(), now_ms(), v2::DEFAULT_MAX_LAG_MS)
                            .map_err(admission)?;
                        if head.status == "failed" {
                            return Err(ClientError::Source("source_failed".into()));
                        }
                        let floor = head.earliest_after.as_deref().and_then(cursor_sequence);
                        let latest = head.cursor.as_deref().and_then(cursor_sequence);
                        if floor.is_none_or(|floor| sequence < floor)
                            || latest.is_none_or(|latest| last > latest)
                        {
                            return Err(ClientError::Gap {
                                reason: "recovery_window_unavailable".into(),
                                head: Some(Box::new(head)),
                            });
                        }
                        status_seen = true;
                    }
                    "gap" if id.is_empty() => {
                        let value: serde_json::Value = serde_json::from_str(&data)
                            .map_err(|_| protocol("invalid_recovery_gap"))?;
                        let reason = value["error"]
                            .as_str()
                            .ok_or_else(|| protocol("invalid_gap_reason"))?
                            .to_owned();
                        let head = if value["head"].is_null() {
                            None
                        } else {
                            let head: Head = serde_json::from_value(value["head"].clone())
                                .map_err(|_| protocol("invalid_gap_head"))?;
                            head.validate(self.source(), now_ms(), v2::DEFAULT_MAX_LAG_MS)
                                .map_err(admission)?;
                            Some(Box::new(head))
                        };
                        return Err(ClientError::Gap { reason, head });
                    }
                    "chunk" if status_seen => {
                        let wire: v2::RecoveryStreamNotice = serde_json::from_str(&data)
                            .map_err(|_| protocol("invalid_recovery_notice"))?;
                        sequence += 1;
                        wire.preflight(&id, sequence, self.source())
                            .map_err(admission)?;
                        if sequence == last && wire.notice.cursor != until {
                            return Err(protocol("recovery_target_mismatch"));
                        }
                        if wire.event.kind != "block" {
                            plan_bytes += wire.notice.bytes;
                            if wire.notice.bytes > CONTROL_FRAME_MAX
                                || plan_bytes > MAX_RECOVERY_PLAN_BYTES
                            {
                                return Err(protocol("recovery_control_too_large"));
                            }
                        }
                        notices.push(wire);
                        if sequence == end {
                            return Ok(notices);
                        }
                    }
                    _ => return Err(protocol("unexpected_recovery_sse_event")),
                }
            }
        }
        Err(ClientError::Transient(
            "recovery_notice_stream_closed".into(),
        ))
    }
}

fn cursor_sequence(cursor: &str) -> Option<u64> {
    v2::parse_cursor(cursor).ok().map(|(_, seq, _)| seq)
}
