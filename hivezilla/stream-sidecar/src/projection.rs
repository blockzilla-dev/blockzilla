use crate::config::{Filter, View};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use blockzilla_bank_stream_v2::{self as v2, Frame};
use serde_json::{Value, json};

/// The compact selection changes only the downstream JSON envelope. The
/// original payload frame and its native controls keep their exact bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlockProjection {
    #[default]
    Full,
    Compact,
}

/// This is an explicit service capability, independent of an SSE query.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum PayloadMode {
    #[default]
    Full,
    CompactOnly,
}
impl PayloadMode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::CompactOnly => "compact-only",
        }
    }
}

#[derive(Clone)]
pub struct Payload {
    pub frame: Frame,
    pub json: Value,
}
pub fn decode(frame: Frame) -> Result<Payload> {
    ensure!(frame.envelope.event.kind == "block", "payload_required");
    let json: Value = serde_json::from_slice(&blockzilla_stream_decoder::decode_banks(
        &frame.wire,
        &Default::default(),
    )?)?;
    ensure!(
        json["blocks"].as_array().is_some_and(|v| v.len() == 1),
        "one_block_required"
    );
    Ok(Payload { frame, json })
}
pub fn validate_compact(frame: Frame) -> Result<Payload> {
    blockzilla_stream_decoder::validate_bank_payload(&frame)?;
    Ok(Payload {
        frame,
        json: Value::Null,
    })
}
fn matched(tx: &Value, filter: &Filter) -> bool {
    let failed = tx["success"].as_bool().map(|v| !v);
    if filter.failed.is_some_and(|v| Some(v) != failed) {
        return false;
    }
    if filter.accounts.is_empty() && filter.programs.is_empty() {
        return true;
    }
    let has = |field: &str, wanted: &[String]| {
        tx[field].as_array().is_some_and(|v| {
            v.iter().any(|key| {
                key.as_str()
                    .is_some_and(|key| wanted.iter().any(|v| v == key))
            })
        })
    };
    has("accountKeys", &filter.accounts)
        || has("topLevelPrograms", &filter.programs)
        || has("innerPrograms", &filter.programs)
}
/// The full view includes the exact canonical frame, not a second block codec.
/// JSON detail fields use the existing portable Compact V2 projection schema.
pub fn render(
    event: &Value,
    source: &v2::SourceIdentity,
    payload: &Value,
    wire: &[u8],
    cursor: &str,
    source_cursor: &str,
    affected: &Value,
    view: View,
    filter: &Filter,
) -> Result<Option<Value>> {
    render_with_block_projection(
        event,
        source,
        payload,
        wire,
        cursor,
        source_cursor,
        affected,
        view,
        filter,
        BlockProjection::Full,
    )
}

pub fn render_with_block_projection(
    event: &Value,
    source: &v2::SourceIdentity,
    payload: &Value,
    wire: &[u8],
    cursor: &str,
    source_cursor: &str,
    affected: &Value,
    view: View,
    filter: &Filter,
    block_projection: BlockProjection,
) -> Result<Option<Value>> {
    let kind = event["kind"].as_str().context("event_kind_missing")?;
    let mut value = json!({"schema":"blockzilla-sidecar-update-v1","source":source,"cursor":cursor,"sourceCursor":source_cursor,"kind":kind,"event":event,"invalidatedBanks":affected});
    if matches!(kind, "invalidate" | "coverage_gap") {
        return Ok(Some(value));
    }
    if view == View::Blockhashes {
        if !matches!(kind, "confirmed" | "root") {
            return Ok(None);
        }
        let recent = &event["recent_blockhash"];
        ensure!(recent.is_object(), "native_signing_observation_missing");
        value["blockhashObservation"] = json!({"commitment":event["commitment"],"contextSlot":recent["context_slot"],"blockHeight":event["block_height"],"blockhash":recent["blockhash"],"lastValidBlockHeight":recent["last_valid_block_height"],"observedAtMs":event["observed_at_unix_ms"],"historicalUpdate":true,"usableForSigning":false,"currentReadinessSource":"/v1/blockhashes"});
        return Ok(Some(value));
    }
    if view == View::Blocks && block_projection == BlockProjection::Compact {
        ensure!(
            filter.accounts.is_empty() && filter.programs.is_empty() && filter.failed.is_none(),
            "compact_block_projection_does_not_support_filters"
        );
        ensure!(!wire.is_empty(), "compact_block_payload_missing");
        value["compactFrameBase64"] = json!(STANDARD.encode(wire));
        value["payloadFormat"] = json!(v2::PROFILE);
        return Ok(Some(value));
    }
    let original = payload["blocks"][0]
        .as_object()
        .context("decoded_block_missing")?;
    let transactions = original
        .get("transactions")
        .and_then(Value::as_array)
        .context("transactions_missing")?;
    let selected = transactions
        .iter()
        .filter(|tx| matched(tx, filter))
        .collect::<Vec<_>>();
    if selected.is_empty()
        && (!filter.accounts.is_empty() || !filter.programs.is_empty() || filter.failed.is_some())
    {
        return Ok(None);
    }
    if view == View::Signatures {
        value["block"] = json!({"slot":original["slot"],"bankId":original["bankId"],"blockhash":original["blockhash"],"parentSlot":original["parentSlot"],"parentBlockhash":original["parentBlockhash"],"blockHeight":original["blockHeight"],"transactionCount":original["transactionCount"],"transactions":selected.iter().map(|tx|json!({"index":tx["index"],"signature":tx["signature"],"signatures":tx["signatures"],"success":tx["success"],"err":tx["err"]})).collect::<Vec<_>>()});
    } else {
        let mut block = Value::Object(original.clone());
        block["transactions"] = json!(selected);
        value["block"] = block;
        if view == View::Blocks {
            value["compactFrameBase64"] = json!(STANDARD.encode(wire));
            value["payloadFormat"] = json!(v2::PROFILE);
        }
    }
    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires a retained public Foundation Compact V2 frame"]
    fn actual_retained_frame_full_view_is_complete_and_byte_exact() {
        let path = std::env::var("BLOCKZILLA_SIDECAR_FRAME").expect("set BLOCKZILLA_SIDECAR_FRAME");
        let bytes = std::fs::read(path).unwrap();
        let frame = v2::decode(bytes.clone().into()).unwrap();
        let source = frame.source.clone();
        let cursor = frame.cursor.clone();
        let event = serde_json::to_value(&frame.envelope.event).unwrap();
        let payload = decode(frame).unwrap();
        let full = render(
            &event,
            &source,
            &payload.json,
            &bytes,
            "output",
            &cursor,
            &json!([]),
            View::Blocks,
            &Filter::default(),
        )
        .unwrap()
        .unwrap();
        let cached = crate::payload_cache::PayloadCache::new(source.clone())
            .materialize(payload.clone())
            .unwrap();
        let cached_full = render(
            &event,
            &source,
            &cached.json,
            &cached.frame.wire,
            "output",
            &cursor,
            &json!([]),
            View::Blocks,
            &Filter::default(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            cached_full, full,
            "shared payload must preserve every full-block field and exact frame"
        );
        assert_eq!(
            STANDARD
                .decode(full["compactFrameBase64"].as_str().unwrap())
                .unwrap(),
            bytes
        );
        let rows = full["block"]["transactions"].as_array().unwrap();
        assert_eq!(
            rows.len(),
            full["block"]["transactionCount"].as_u64().unwrap() as usize
        );
        assert!(!rows.is_empty());
        assert!(rows.iter().all(|tx| tx["metadata"].is_object()
            && tx["message"].is_object()
            && tx["accountKeys"].is_array()));
        let signatures = render(
            &event,
            &source,
            &payload.json,
            &payload.frame.wire,
            "output",
            &cursor,
            &json!([]),
            View::Signatures,
            &Filter::default(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            signatures["block"]["transactions"]
                .as_array()
                .unwrap()
                .len(),
            rows.len()
        );
        assert_eq!(
            rows.iter().filter(|tx| tx["success"] == false).count(),
            signatures["block"]["transactions"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|tx| tx["success"] == false)
                .count()
        );
    }
}

#[cfg(test)]
mod observation_tests {
    use super::*;
    #[test]
    fn blockhash_webhook_is_native_history_not_current_readiness() {
        let payload = v2::fixtures::block(1, 9, 1, 8, 9);
        let control = v2::fixtures::control(&payload, 2, "root", 1);
        let event = serde_json::to_value(&control.envelope.event).unwrap();
        let value = render(
            &event,
            &control.source,
            &Value::Null,
            &[],
            "output",
            &control.cursor,
            &json!([]),
            View::Blockhashes,
            &Filter::default(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(value["blockhashObservation"]["lastValidBlockHeight"], 159);
        assert_eq!(value["blockhashObservation"]["observedAtMs"], 1);
        assert_eq!(value["blockhashObservation"]["historicalUpdate"], true);
        assert_eq!(value["blockhashObservation"]["usableForSigning"], false);
        let event = serde_json::to_value(&payload.envelope.event).unwrap();
        assert!(
            render(
                &event,
                &payload.source,
                &Value::Null,
                &[],
                "output",
                &payload.cursor,
                &json!([]),
                View::Blockhashes,
                &Filter::default()
            )
            .unwrap()
            .is_none()
        );
    }
}
