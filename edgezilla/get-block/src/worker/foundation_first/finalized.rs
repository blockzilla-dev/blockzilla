//! Finalized native blocks share one compact decoder for Foundation and R2.
use super::*;

const MAX_NATIVE_FRAME_BYTES: usize = 16 + 65_536 + 16 * 1024 * 1024;
const MAX_ROOT_BYTES: usize = 4096;
const MAX_STATUS_BYTES: usize = 16 * 1024;

struct AbortUnlessHandedOff {
    controller: web_sys::AbortController,
    handed_off: bool,
}

impl Drop for AbortUnlessHandedOff {
    fn drop(&mut self) {
        if !self.handed_off {
            self.controller.abort();
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeFrameObject {
    pub(crate) key: String,
    pub(crate) etag: String,
    pub(crate) length: u64,
    pub(crate) sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeArchiveV1 {
    pub(crate) version: u16,
    pub(crate) producer_generation: String,
    pub(crate) metadata: RecentMetadata,
    pub(crate) root_frame_base64: String,
    pub(crate) frame: NativeFrameObject,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LedgerCompactMetadata {
    pub version: u16,
    pub slot: u64,
    pub parent_slot: u64,
    pub blockhash: String,
    pub previous_blockhash: String,
    pub tx_count: u32,
    pub hot: crate::slot_resolution::ResolutionHotRow,
    pub sha256: String,
    pub length: u64,
    pub message_schema: u8,
    pub metadata_schema: u8,
    pub rooted: bool,
    pub metadata_complete: bool,
}

impl LedgerCompactMetadata {
    pub(crate) fn hashes(&self) -> std::result::Result<([u8; 32], [u8; 32]), String> {
        let hash = |text: &str| -> std::result::Result<[u8; 32], String> {
            let bytes: [u8; 32] = bs58::decode(text)
                .into_vec()
                .map_err(|_| "invalid ledger block hash")?
                .try_into()
                .map_err(|_| "invalid ledger block hash length")?;
            if bytes == [0; 32] || bs58::encode(bytes).into_string() != text {
                return Err("noncanonical ledger block hash".into());
            }
            Ok(bytes)
        };
        Ok((hash(&self.blockhash)?, hash(&self.previous_blockhash)?))
    }

    pub(crate) fn validate(&self, slot: u64) -> std::result::Result<(), String> {
        if self.version != 1
            || self.slot != slot
            || slot > MAX_SAFE_INTEGER
            || self.parent_slot >= slot
            || !self.rooted
            || !self.metadata_complete
            || self.message_schema != 0
            || self.metadata_schema != 0
            || self.hot.slot != slot
            || self.hot.block_id != 1
            || self.hot.tx_count != self.tx_count
            || self.tx_count > 65_536
            || self.hot.compressed_offset != 0
            || self.hot.first_tx_ordinal != 0
            || self.hot.first_signature_ordinal != 0
            || self.hot.compressed_len == 0
            || self.hot.compressed_len > 16 * 1024 * 1024
            || self.hot.uncompressed_len == 0
            || self.hot.uncompressed_len > 32 * 1024 * 1024
            || self.hot.signature_count > 8 * 1024 * 1024 / 64
            || self.length == 0
            || self.length > MAX_BUNDLE_BYTES as u64
        {
            return Err("ledger compact block exceeds its checked identity or limits".into());
        }
        self.hashes()?;
        decode_digest(&self.sha256)?;
        Ok(())
    }
}

impl NativeArchiveV1 {
    pub(crate) fn root(&self) -> std::result::Result<Vec<u8>, String> {
        decode_root(&self.root_frame_base64)
    }

    fn validate(&self, config: &Config, slot: u64) -> std::result::Result<(), String> {
        let expected_source = config
            .finalized_source
            .as_ref()
            .ok_or("native source is disabled")?;
        let prefix = config
            .native_archive_prefix
            .as_ref()
            .ok_or("native archive is disabled")?;
        let expected_key = format!("{prefix}/frames/{}.bin", self.frame.sha256);
        if self.version != 1
            || config.native_producer_generation.as_deref()
                != Some(self.producer_generation.as_str())
            || self.frame.key != expected_key
            || self.frame.etag.is_empty()
            || self.frame.etag.len() > 128
            || !self.frame.etag.bytes().all(|b| b.is_ascii_graphic())
            || !(17..=MAX_NATIVE_FRAME_BYTES as u64).contains(&self.frame.length)
            || self.frame.sha256 != self.metadata.frame_sha256
        {
            return Err("native archive locator differs from its configured source".into());
        }
        let sha = decode_digest(&self.frame.sha256)?;
        validate_metadata(&self.metadata, slot, expected_source, &sha)?;
        self.root()?;
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Miss {
    version: u16,
    slot: u64,
    reason: String,
    #[serde(default)]
    source: Option<PendingLocatorV1>,
    #[serde(default)]
    native_archive: Option<NativeArchiveV1>,
}

fn decode_digest(value: &str) -> std::result::Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("native frame digest is not canonical SHA256".into());
    }
    let mut out = [0; 32];
    for (byte, pair) in out.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let digit = |c: u8| if c <= b'9' { c - b'0' } else { c - b'a' + 10 };
        *byte = digit(pair[0]) << 4 | digit(pair[1]);
    }
    Ok(out)
}

fn decode_root(value: &str) -> std::result::Result<Vec<u8>, String> {
    if value.is_empty() || value.len() > MAX_ROOT_BYTES.div_ceil(3) * 4 || value.contains('=') {
        return Err("native root proof exceeds its bound".into());
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "invalid native root proof encoding")?;
    if bytes.len() > MAX_ROOT_BYTES || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err("native root proof is not canonical".into());
    }
    Ok(bytes)
}

fn validate_metadata(
    metadata: &RecentMetadata,
    slot: u64,
    expected_source: &RecentSource,
    sha: &[u8; 32],
) -> std::result::Result<(), String> {
    let expected_hash: [u8; 32] = bs58::decode(&metadata.blockhash)
        .into_vec()
        .map_err(|_| "invalid finalized blockhash")?
        .try_into()
        .map_err(|_| "invalid finalized blockhash length")?;
    metadata.validate(
        &RecentRequest {
            slot,
            blockhash: metadata.blockhash.clone(),
            expected_hash,
            commitment: "finalized".into(),
            cursor: None,
            source_session: None,
            bank_id: None,
        },
        expected_source,
        sha,
    )
}

pub(crate) async fn read_native_frame(
    mut response: Response,
    length: usize,
) -> std::result::Result<Vec<u8>, String> {
    if !(17..=MAX_NATIVE_FRAME_BYTES).contains(&length) {
        return Err("native frame exceeds its bound".into());
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| "native frame body failed")?;
    if bytes.len() != length {
        return Err("native frame body length differs".into());
    }
    // The adapter validates the complete frame and every object hash before
    // it permits any JSON output. Do not hash the same bytes here a second time.
    Ok(bytes)
}

impl Config {
    pub(crate) fn native_finalized_enabled(&self) -> bool {
        self.finalized_source.is_some()
    }

    pub(super) fn configure_finalized(
        &mut self,
        env: &worker::Env,
    ) -> std::result::Result<(), String> {
        match optional_var(env, "BZ_FOUNDATION_NATIVE_FINALIZED").as_deref() {
            None | Some("false") => return Ok(()),
            Some("true") => {}
            _ => return Err("BZ_FOUNDATION_NATIVE_FINALIZED must be true or false".into()),
        }
        let source = RecentSource::parse(&required_var(env, "BZ_FOUNDATION_RECENT_SOURCE")?)?;
        let generation = required_var(env, "BZ_FOUNDATION_NATIVE_PRODUCER_GENERATION")?;
        decode_digest(&generation)?;
        let prefix = optional_var(env, "BZ_FOUNDATION_NATIVE_ARCHIVE_PREFIX");
        if let Some(prefix) = &prefix
            && prefix != &format!("native-stream/bank-v2/{}", source.session_id)
        {
            return Err("native archive prefix differs from its pinned session".into());
        }
        self.finalized_source = Some(source);
        self.native_producer_generation = Some(generation);
        self.native_archive_prefix = prefix;
        self.ledger_generation = optional_var(env, "BZ_FOUNDATION_LEDGER_GENERATION");
        if let Some(generation) = &self.ledger_generation
            && (generation.is_empty()
                || generation.len() > 128
                || !generation
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)))
        {
            return Err("invalid ledger compact generation".into());
        }
        Ok(())
    }

    pub(crate) async fn lookup_finalized(
        &self,
        source: &WorkerSource,
        slot: u64,
    ) -> std::result::Result<Outcome, String> {
        let expected_source = self
            .finalized_source
            .as_ref()
            .ok_or("native source is disabled")?;
        let (_, plan) = self.plan(slot, read_mode(source))?;
        let mut url = self.endpoint.clone();
        url.set_path(&format!("/v1/finalized/{slot}"));
        let headers = Headers::new();
        for (name, value) in plan {
            headers
                .set(name, &value)
                .map_err(|_| "invalid native lookup header")?;
        }
        headers
            .set(
                "Accept",
                &format!("{}, application/json", recent::STREAM_TYPE),
            )
            .map_err(|_| "invalid native accept header")?;
        let mut init = RequestInit::new();
        init.with_method(Method::Get)
            .with_headers(headers)
            .with_redirect(worker::RequestRedirect::Manual);
        let outgoing =
            Request::new_with_init(url.as_str(), &init).map_err(|_| "invalid native lookup")?;
        let controller =
            web_sys::AbortController::new().map_err(|_| "native cancellation failed")?;
        // Every admission failure cancels the unread upstream body. On a
        // live hit only the bounded native body may own cancellation next.
        let mut abort = AbortUnlessHandedOff {
            controller: controller.clone(),
            handed_off: false,
        };
        let signal = worker::AbortSignal::from(controller.signal());
        source.backend_read.mark();
        source.storage_metrics.attempt_foundation_recent_http();
        let started = now_ms();
        let fetch = Fetch::Request(outgoing);
        let result = future::select(
            Box::pin(fetch.send_with_signal(&signal)),
            Box::pin(worker::Delay::from(Duration::from_millis(
                self.header_timeout_ms.into(),
            ))),
        )
        .await;
        let response = match result {
            future::Either::Left((Ok(response), _)) => response,
            future::Either::Left((Err(_), _)) => {
                controller.abort();
                return Ok(Outcome::TransportFailure(TransportFailure::Network));
            }
            future::Either::Right(_) => {
                controller.abort();
                return Ok(Outcome::TransportFailure(TransportFailure::HeaderTimeout));
            }
        };
        let status = response.status_code();
        source.record_elapsed(
            "foundation_finalized_headers",
            started,
            0,
            "native_compact",
            Some(status),
        );
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .ok()
                .flatten()
                .ok_or_else(|| format!("missing finalized response header {name}"))
        };
        if header("X-BZ-Foundation-Protocol")? != PROTOCOL
            || header("X-BZ-Foundation-Generation")? != self.generation
            || header("X-BZ-Foundation-Source-Prefix")? != self.prefix
            || response
                .headers()
                .get("Content-Encoding")
                .map_err(|e| e.to_string())?
                .is_some_and(|value| value != "identity")
        {
            controller.abort();
            return Err("finalized protocol or source differs".into());
        }
        let length: usize = header("Content-Length")?
            .parse()
            .map_err(|_| "invalid finalized length")?;
        let sha = decode_digest(&header("X-BZ-Foundation-SHA256")?)?;
        let result = header("X-BZ-Foundation-Result")?;
        if status == 200 && result == "ledger_compact" && header("Content-Type")? == BUNDLE_TYPE {
            if !(1..=MAX_BUNDLE_BYTES).contains(&length)
                || self.ledger_generation.as_deref()
                    != Some(header("X-BZ-Ledger-Generation")?.as_str())
                || self.native_producer_generation.as_deref()
                    != Some(header("X-BZ-Finalized-Producer-Generation")?.as_str())
            {
                return Err("ledger compact generation or length differs".into());
            }
            let encoded = header("X-BZ-Ledger-Metadata")?;
            if encoded.is_empty() || encoded.len() > 4096 || encoded.contains('=') {
                return Err("ledger compact metadata exceeds its bound".into());
            }
            let raw = URL_SAFE_NO_PAD
                .decode(&encoded)
                .map_err(|_| "invalid ledger metadata encoding")?;
            if URL_SAFE_NO_PAD.encode(&raw) != encoded {
                return Err("ledger metadata encoding is not canonical".into());
            }
            let metadata: LedgerCompactMetadata =
                serde_json::from_slice(&raw).map_err(|_| "invalid ledger compact metadata")?;
            metadata.validate(slot)?;
            if metadata.length != length as u64 || decode_digest(&metadata.sha256)? != sha {
                return Err(
                    "ledger compact metadata differs from the delivered body identity".into(),
                );
            }
            let response = bounded_response(response, length, self.body_timeout_ms, &controller)?;
            abort.handed_off = true;
            return Ok(Outcome::LedgerCompact {
                response,
                metadata,
                length,
                digest: sha,
            });
        }
        if status == 200 && result == "recent" && header("Content-Type")? == recent::STREAM_TYPE {
            if !(17..=MAX_NATIVE_FRAME_BYTES).contains(&length)
                || Some(header("X-BZ-Finalized-Producer-Generation")?.as_str())
                    != self.native_producer_generation.as_deref()
            {
                controller.abort();
                return Err("finalized frame generation or length differs".into());
            }
            let encoded = header("X-BZ-Recent-Metadata")?;
            if encoded.len() > 4096 || encoded.contains('=') {
                controller.abort();
                return Err("finalized metadata exceeds its bound".into());
            }
            let raw = URL_SAFE_NO_PAD
                .decode(&encoded)
                .map_err(|_| "invalid finalized metadata")?;
            if URL_SAFE_NO_PAD.encode(&raw) != encoded {
                return Err("finalized metadata encoding is not canonical".into());
            }
            let metadata: RecentMetadata =
                serde_json::from_slice(&raw).map_err(|_| "invalid finalized metadata body")?;
            validate_metadata(&metadata, slot, expected_source, &sha)?;
            let root = decode_root(&header("X-BZ-Finalized-Root")?)?;
            let response = bounded_response(response, length, self.body_timeout_ms, &controller)?;
            abort.handed_off = true;
            return Ok(Outcome::Native {
                response,
                metadata,
                root,
                length,
            });
        }
        if !(1..=MAX_STATUS_BYTES).contains(&length)
            || header("Content-Type")? != "application/json"
            || !(status == 404 && result == "not_cached"
                || matches!(status, 400 | 404 | 409 | 410 | 503) && result == "unavailable")
        {
            controller.abort();
            return Err("invalid finalized lookup response framing".into());
        }
        let mut response = bounded_response(response, length, self.body_timeout_ms, &controller)?;
        let bytes = response
            .bytes()
            .await
            .map_err(|_| "finalized status body failed")?;
        if bytes.len() != length || native_hash::sha256(&bytes).await? != sha {
            return Err("finalized status body digest differs".into());
        }
        if status == 404 && result == "not_cached" {
            let miss: Miss =
                serde_json::from_slice(&bytes).map_err(|_| "invalid finalized miss body")?;
            if miss.version != 1
                || miss.slot != slot
                || miss.reason != "not_cached"
                || miss.source.is_some() && miss.native_archive.is_some()
            {
                return Err("finalized miss identity differs".into());
            }
            if let Some(record) = miss.native_archive {
                record.validate(self, slot)?;
                return Ok(Outcome::NativeArchive { record });
            }
            // The legacy validator rejects unknown fields. Keep its wire
            // contract unchanged when this endpoint has no native record.
            let legacy = serde_json::to_vec(&json!({
                "version": miss.version, "slot": slot, "reason": miss.reason, "source": miss.source
            }))
            .map_err(|_| "cannot check legacy native miss")?;
            let route = validate_not_cached(&self.prefix, &self.generation, slot, &legacy)?;
            return Ok(Outcome::NotCached { source: route });
        }
        if status == 503 {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct NativeUnavailable {
                version: u16,
                slot: u64,
                reason: String,
            }
            let value: NativeUnavailable =
                serde_json::from_slice(&bytes).map_err(|_| "invalid native unavailable body")?;
            if value.version != 1
                || value.slot != slot
                || !matches!(
                    value.reason.as_str(),
                    "recent_unavailable"
                        | "recent_capacity_unavailable"
                        | "recent_metadata_unavailable"
                        | "native_archive_metadata_unavailable"
                        | "archive_metadata_unavailable"
                        | "ledger_compact_unavailable"
                )
            {
                return Err("native unavailable identity or reason differs".into());
            }
            return Ok(Outcome::NativeUnavailable {
                status,
                reason: value.reason,
            });
        }
        let unavailable: UnavailableBody =
            serde_json::from_slice(&bytes).map_err(|_| "invalid finalized unavailable body")?;
        if unavailable.version != 1
            || unavailable.slot != slot
            || unavailable.reason.status() != status
        {
            return Err("finalized unavailable identity differs".into());
        }
        Ok(Outcome::Unavailable(unavailable.reason))
    }
}
