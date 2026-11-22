//! Opt-in, admitted complete V1 bundles. Each cold read uses one native R2 GET.
//! Binary bodies stay in JavaScript; JSON borrows the outer frame in place.
use super::*;
use crate::slot_resolution::{LocatorV1, SourceObjectIdentity};
use worker::ResponseBody;

const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 128 * 1024;
const MAX_ADMITTED_SLOTS: usize = 64;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    identity: SourceObjectIdentity,
    sha256: String,
    provenance: LocatorV1,
    #[serde(skip)]
    digest: [u8; 32],
}

impl Admission {
    fn validate(&mut self) -> std::result::Result<(), String> {
        self.identity.validate()?;
        if self.identity.length == 0 || self.identity.length > MAX_BUNDLE_BYTES as u64 {
            return Err("bundle length exceeds its bound".into());
        }
        self.digest = decode_sha256(&self.sha256)?;
        self.provenance.validate(
            &self.provenance.source_prefix,
            &self.provenance.generation,
            self.provenance.hot.slot,
        )?;
        // This experiment serves the original modern Zstd/Wincode frame.
        // Historical normalization needs a separate explicit format policy.
        if self.provenance.message_schema != 0 || self.provenance.metadata_schema != 0 {
            return Err("complete bundle experiment requires current schemas".into());
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct Config {
    bucket: Bucket,
    prefix: String,
    pub(super) generation: String,
    admitted: BTreeMap<u64, Admission>,
}

impl Config {
    pub(super) fn from_env(env: &worker::Env) -> std::result::Result<Option<Self>, String> {
        let Some(prefix) = optional_var(env, "BZ_SLOT_BUNDLE_PREFIX") else {
            return Ok(None);
        };
        let generation = required_var(env, "BZ_SLOT_BUNDLE_GENERATION")?;
        if prefix.is_empty()
            || prefix.len() > 512
            || prefix
                .split('/')
                .any(|s| s.is_empty() || s == "." || s == "..")
            || generation.is_empty()
            || generation.len() > 128
            || !generation
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err("bundle prefix or generation is invalid".into());
        }
        let raw = required_var(env, "BZ_SLOT_BUNDLE_MANIFEST")?;
        let admitted = parse_manifest(&raw)?;
        let binding = optional_var(env, "BZ_SLOT_BUNDLE_BUCKET_BINDING")
            .unwrap_or_else(|| "BZ_ARCHIVE_BUCKET".into());
        let bucket = env
            .bucket(&binding)
            .map_err(|_| format!("missing R2 binding {binding}"))?;
        Ok(Some(Self {
            bucket,
            prefix,
            generation,
            admitted,
        }))
    }

    pub(super) fn covers(&self, slot: u64) -> bool {
        self.admitted.contains_key(&slot)
    }

    fn key(&self, slot: u64) -> String {
        format!(
            "{}/epoch-{}/slot-{slot}.bundle.wincode",
            self.prefix,
            epoch_for_slot(slot)
        )
    }
}

fn parse_manifest(raw: &str) -> std::result::Result<BTreeMap<u64, Admission>, String> {
    if raw.len() > MAX_MANIFEST_BYTES {
        return Err("bundle manifest exceeds its bound".into());
    }
    let entries: Vec<Admission> =
        serde_json::from_str(raw).map_err(|e| format!("invalid bundle admission manifest: {e}"))?;
    if entries.is_empty() || entries.len() > MAX_ADMITTED_SLOTS {
        return Err("bundle admission count exceeds its bound".into());
    }
    let mut admitted = BTreeMap::new();
    for mut entry in entries {
        entry.validate()?;
        if admitted.insert(entry.provenance.hot.slot, entry).is_some() {
            return Err("bundle manifest contains a duplicate slot".into());
        }
    }
    Ok(admitted)
}

fn decode_sha256(text: &str) -> std::result::Result<[u8; 32], String> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("bundle SHA256 must contain 64 lower-case hex digits".into());
    }
    let mut digest = [0; 32];
    for (out, pair) in digest.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        *out = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    Ok(digest)
}

pub(super) fn covered(source: &WorkerSource, slot: u64) -> bool {
    source
        .slot_bundle
        .as_ref()
        .is_some_and(|config| config.covers(slot))
}

fn admission(
    source: &WorkerSource,
    slot: u64,
) -> std::result::Result<(&Config, &Admission), String> {
    let config = source
        .slot_bundle
        .as_ref()
        .ok_or("slot bundle is not configured")?;
    let entry = config
        .admitted
        .get(&slot)
        .ok_or("slot is outside the admitted bundle coverage")?;
    Ok((config, entry))
}

fn cache_key(source: &WorkerSource, config: &Config, entry: &Admission) -> Option<String> {
    if source
        .profile
        .as_ref()
        .is_some_and(ProfileHandle::source_ranges_only)
    {
        return None;
    }
    source.range_cache_key(
        &format!(
            "bundle-v1\0{}\0{}\0{}\0{}\0{}",
            config.generation,
            config.key(entry.provenance.hot.slot),
            entry.identity.etag,
            entry.identity.length,
            entry.sha256
        ),
        0,
        entry.identity.length as usize,
    )
}

async fn origin_response(
    source: &WorkerSource,
    config: &Config,
    entry: &Admission,
) -> std::result::Result<Response, String> {
    let started = now_ms();
    source.backend_read.mark();
    source.storage_metrics.attempt_get(StorageBackend::R2);
    let object = config
        .bucket
        .get(config.key(entry.provenance.hot.slot))
        .only_if(worker::Conditional {
            etag_matches: Some(entry.identity.etag.trim_matches('"').to_string()),
            ..Default::default()
        })
        .execute()
        .await
        .map_err(|e| e.to_string())?
        .ok_or("admitted slot bundle is missing")?;
    source.record_elapsed(
        "bundle_headers",
        started,
        entry.identity.length,
        "native_r2_full_object",
        Some(200),
    );
    if object.size() != entry.identity.length || object.http_etag() != entry.identity.etag {
        return Err("bundle R2 size or ETag differs from admission".into());
    }
    // R2 checked this checksum on PUT. The trusted binding returns it on the
    // same conditional GET, with no HEAD and no second storage read. Binary
    // can therefore forward the admitted object without decoding or hashing
    // its full body in the Worker. JSON also hashes the delivered bytes below.
    if object.checksum().sha256.as_deref() != Some(entry.digest.as_slice()) {
        return Err("bundle R2 SHA256 checksum is missing or differs from admission".into());
    }
    Response::from_body(
        object
            .body()
            .ok_or("bundle R2 conditional GET has no body")?
            .response_body()
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

async fn load_bytes(
    source: &WorkerSource,
    config: &Config,
    entry: &Admission,
) -> std::result::Result<Vec<u8>, String> {
    let key = cache_key(source, config, entry);
    let mut from_origin = false;
    let cached = if let Some(key) = &key {
        source
            .cached_bytes(key, entry.identity.length as usize)
            .await
    } else {
        None
    };
    let bytes = if let Some(bytes) = cached {
        bytes
    } else {
        from_origin = true;
        let response = origin_response(source, config, entry).await?;
        let (_, body) = response.into_parts();
        // The native wrapper rejects a long or short body and limits bytes
        // before Response::bytes copies the bounded body into WASM.
        let mut bounded = stream_parts::response_from_parts(
            Vec::new(),
            body,
            entry.identity.length,
            Vec::new(),
            ResponseBody::Empty,
            0,
            Vec::new(),
        )
        .map_err(|e| e.to_string())?;
        let started = now_ms();
        let bytes = bounded.bytes().await.map_err(|e| e.to_string())?;
        source.storage_metrics.complete_get(
            StorageBackend::R2,
            bytes.len(),
            bytes.len() as u64 == entry.identity.length,
        );
        source.record_elapsed(
            "bundle_body",
            started,
            bytes.len() as u64,
            "bounded_wasm_json_input",
            Some(200),
        );
        bytes
    };
    let started = now_ms();
    if bytes.len() as u64 != entry.identity.length
        || native_hash::sha256(&bytes).await? != entry.digest
    {
        return Err("bundle body size or SHA256 differs from admission".into());
    }
    source.record_elapsed(
        "bundle_sha256",
        started,
        bytes.len() as u64,
        "native_webcrypto",
        None,
    );
    // Only fully checked input enters shared data caches.
    if from_origin && let Some(key) = key {
        source.cache_bytes(key, &bytes);
    }
    Ok(bytes)
}

struct BorrowedBundle<'a> {
    hot: &'a [u8],
    access: &'a [u8],
}

fn borrowed_bundle(bytes: &[u8], slot: u64) -> std::result::Result<BorrowedBundle<'_>, String> {
    if bytes.is_empty() || bytes.len() > MAX_BUNDLE_BYTES {
        return Err("bundle frame exceeds its bound".into());
    }
    let mut input = bytes;
    if unsigned(&mut input)? != 1 || unsigned(&mut input)? != slot || byte(&mut input)? != 1 {
        return Err("bundle version, slot or hot encoding differs".into());
    }
    let hot = vector(&mut input)?;
    if byte(&mut input)? != 0 || byte(&mut input)? != 1 {
        return Err("bundle access must contain complete Wincode data".into());
    }
    let access = vector(&mut input)?;
    if hot.is_empty() || access.is_empty() || !input.is_empty() {
        return Err("bundle payload is missing or has trailing bytes".into());
    }
    Ok(BorrowedBundle { hot, access })
}

fn byte(input: &mut &[u8]) -> std::result::Result<u8, String> {
    let (&value, rest) = input.split_first().ok_or("truncated bundle frame")?;
    *input = rest;
    Ok(value)
}

fn unsigned(input: &mut &[u8]) -> std::result::Result<u64, String> {
    let mut result = 0u64;
    for index in 0..10 {
        let value = byte(input)?;
        if index == 9 && value > 1 {
            return Err("bundle integer overflows".into());
        }
        result |= u64::from(value & 127) << (index * 7);
        if value & 128 == 0 {
            if index != 0 && value == 0 {
                return Err("bundle integer is not canonical".into());
            }
            return Ok(result);
        }
    }
    Err("bundle integer exceeds its bound".into())
}

fn vector<'a>(input: &mut &'a [u8]) -> std::result::Result<&'a [u8], String> {
    let length = usize::try_from(unsigned(input)?).map_err(|_| "bundle vector exceeds usize")?;
    if length > MAX_BUNDLE_BYTES || length > input.len() {
        return Err("bundle vector exceeds its bound".into());
    }
    let (value, rest) = input.split_at(length);
    *input = rest;
    Ok(value)
}

pub(super) async fn fetch_block(
    source: &WorkerSource,
    slot: u64,
) -> std::result::Result<Option<FetchedHotBlock>, String> {
    let started = now_ms();
    let (config, entry) = admission(source, slot)?;
    let bytes = load_bytes(source, config, entry).await?;
    let fetched = decode_complete_bundle(source, slot, &bytes, &entry.provenance)?;
    source.record_elapsed(
        "bundle_fetch_total",
        started,
        bytes.len() as u64,
        "one_native_r2_get",
        None,
    );
    Ok(Some(fetched))
}

/// Decode an original compressed V1 bundle after its caller admits its locator
/// and complete delivered body identity. This helper does not fetch or hash
/// bytes. The locator names provenance, not the transport of this body.
pub(super) fn decode_complete_bundle(
    source: &WorkerSource,
    slot: u64,
    bytes: &[u8],
    locator: &LocatorV1,
) -> std::result::Result<FetchedHotBlock, String> {
    locator.validate(&locator.source_prefix, &locator.generation, slot)?;
    let frame = borrowed_bundle(bytes, slot)?;
    let row: ArchiveV2HotBlockIndexRow = locator.hot.into();
    if frame.hot.len() != row.compressed_len as usize {
        return Err("bundle hot length differs from source provenance".into());
    }
    let (decoded, block) = stored::decode_block(source, slot, &row, frame.hot)?;
    let decoded_len = decoded.len();
    drop(decoded);
    if block.header.parent_slot != locator.parent_slot {
        return Err("bundle parent differs from source provenance".into());
    }
    let access_started = now_ms();
    let access: ArchiveV2BlockAccessBlob = wincode::config::deserialize_exact(
        frame.access,
        blockzilla_primitives::bounded_wincode_leb128_config::<MAX_BUNDLE_BYTES>(),
    )
    .map_err(|e| format!("decode admitted bundle access: {e}"))?;
    validate_access_blob(&access, &row)?;
    if access.version != WINCODE_ARCHIVE_V2_BLOCK_ACCESS_VERSION
        || access.flags != 0
        || access.blockhash != locator.blockhash
        || access.previous_blockhash != locator.previous_blockhash
        || block
            .tx_rows
            .iter()
            .map(|tx| tx.signature_count)
            .ne(access.signature_counts.iter().copied())
    {
        return Err("bundle access identity or signature counts differ from provenance".into());
    }
    if access.pubkeys.len() > 65_536
        || access.blockhashes.len() > 65_536
        || access.vote_hashes.len() > 65_536
        || access.pubkeys.iter().any(|v| v.id == 0)
        || !access.pubkeys.windows(2).all(|v| v[0].id < v[1].id)
        || !access.blockhashes.windows(2).all(|v| v[0].id < v[1].id)
        || !access
            .vote_hashes
            .windows(2)
            .all(|v| v[0].block_id < v[1].block_id)
        || access
            .vote_hashes
            .iter()
            .any(|v| v.bank_hash.is_none() && v.block_id_hash.is_none())
    {
        return Err("bundle dictionaries must have unique sorted valid IDs".into());
    }
    source.record_elapsed(
        "bundle_access_decode",
        access_started,
        frame.access.len() as u64,
        "single_parse_wincode",
        None,
    );
    Ok(FetchedHotBlock {
        epoch: locator.epoch,
        index_row: ArchiveV2GetBlockIndexRow {
            block_offset: row.compressed_offset,
            block_len: row.compressed_len,
            access_offset: 0,
            access_len: frame.access.len() as u32,
        },
        row,
        decoded_len,
        block,
        access: Some(FetchedAccess::Full(access)),
        message_schema: if locator.message_schema == 0 {
            MessageSchema::Current
        } else {
            MessageSchema::May24
        },
        metadata_schema: if locator.metadata_schema == 0 {
            MetadataSchema::Current
        } else {
            MetadataSchema::Legacy
        },
    })
}

pub(super) async fn binary_response(
    source: &WorkerSource,
    slot: u64,
    ctx: &Rc<worker::Context>,
    metrics: &AnalyticsEngineDataset,
    key_record: &RpcApiKeyRecord,
) -> std::result::Result<Response, String> {
    let (config, entry) = admission(source, slot)?;
    let cache_key = cache_key(source, config, entry);
    if let Some(key) = &cache_key
        && let Ok(Some(response)) = Cache::default().get(key.clone(), false).await
        && response.status_code() == 200
        && response
            .headers()
            .get("Content-Length")
            .ok()
            .flatten()
            .as_deref()
            == Some(entry.identity.length.to_string().as_str())
    {
        source.storage_metrics.edge_hit();
        let mut response = response_with_mutable_headers(response);
        binary_headers(&mut response, source, config, entry, false)?;
        return Ok(response);
    }
    let response = origin_response(source, config, entry).await?;
    let (_, body) = response.into_parts();
    let parts = stream_parts::response_and_completion_from_parts(
        Vec::new(),
        body,
        entry.identity.length,
        Vec::new(),
        ResponseBody::Empty,
        0,
        Vec::new(),
    )
    .map_err(|e| e.to_string())?;
    let dataset = metrics.clone();
    let key_id = key_record.key_id.clone();
    let customer_id = key_record.customer_id.clone();
    ctx.wait_until(async move {
        let Ok(value) = wasm_bindgen_futures::JsFuture::from(parts.completion).await else {
            console_error!("admitted bundle stream failed or was cancelled");
            return;
        };
        let bytes = js_sys::Reflect::get(&value, &JsValue::from_str("hotBytes"))
            .ok()
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let mut doubles = [0.0; 20];
        doubles[7] = bytes;
        doubles[13] = 1.0;
        let _ = AnalyticsEngineDataPointBuilder::new()
            .indexes([key_id.as_str()])
            .blobs([
                customer_id.as_str(),
                "getBlock",
                "source_range_complete",
                "continuation",
                "http_binary",
            ])
            .doubles(doubles)
            .write_to(&dataset);
    });
    let mut response = parts.response;
    binary_headers(&mut response, source, config, entry, true)?;
    if let (Some(key), Some(cache)) = (cache_key, source.cache.as_ref())
        && entry.identity.length <= MAX_CACHED_RANGE_BYTES as u64
        && source
            .cache_write_bytes
            .get()
            .saturating_add(entry.identity.length as usize)
            <= 8 * 1024 * 1024
        && let Ok(cached) = response.cloned()
    {
        source
            .cache_write_bytes
            .set(source.cache_write_bytes.get() + entry.identity.length as usize);
        cache.context.wait_until(async move {
            if let Err(error) = Cache::default().put(key, cached).await {
                console_error!("bundle cache write failed: {error}");
            }
        });
    }
    Ok(response)
}

fn binary_headers(
    response: &mut Response,
    source: &WorkerSource,
    config: &Config,
    entry: &Admission,
    from_origin: bool,
) -> std::result::Result<(), String> {
    add_profile_headers(response.headers(), source.profile.as_ref()).map_err(|e| e.to_string())?;
    for (name, value) in [
        (
            "Content-Type",
            "application/vnd.blockzilla.get-block-bundle.wincode",
        ),
        ("Cache-Control", BLOCK_CACHE_CONTROL),
        ("ETag", entry.identity.etag.as_str()),
        ("X-Blockzilla-Body", "native-stream"),
        ("X-Blockzilla-Archive-Layout", "bundle-v1"),
        ("X-Blockzilla-Storage-Bytes-Mode", "streamed-completion"),
        ("X-Blockzilla-Bundle-Generation", config.generation.as_str()),
        ("X-Blockzilla-Bundle-SHA256", entry.sha256.as_str()),
    ] {
        response
            .headers_mut()
            .set(name, value)
            .map_err(|e| e.to_string())?;
    }
    response
        .headers_mut()
        .set(
            "X-Blockzilla-Origin-Expected-Bytes",
            &if from_origin {
                entry.identity.length
            } else {
                0
            }
            .to_string(),
        )
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_outer_frame_has_no_payload_copy_and_checks_exact_framing() {
        let frame = [1, 10, 1, 2, 0xaa, 0xbb, 0, 1, 1, 0xcc];
        let parsed = borrowed_bundle(&frame, 10).unwrap();
        assert_eq!(parsed.hot.as_ptr(), frame[4..].as_ptr());
        assert_eq!(parsed.access.as_ptr(), frame[9..].as_ptr());
        assert!(borrowed_bundle(&frame, 11).is_err());
        for end in 0..frame.len() {
            assert!(borrowed_bundle(&frame[..end], 10).is_err());
        }
        let mut extra = frame.to_vec();
        extra.push(0);
        assert!(borrowed_bundle(&extra, 10).is_err());
        let mut absent = frame;
        absent[7] = 0;
        assert!(borrowed_bundle(&absent, 10).is_err());
    }

    #[test]
    fn rejects_noncanonical_and_overflowing_frame_lengths() {
        for bytes in [
            &[0x80, 0][..],
            &[0xff; 11][..],
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2][..],
        ] {
            assert!(unsigned(&mut &bytes[..]).is_err());
        }
        let mut data = &[0xff, 0xff, 0xff, 0x7f][..];
        assert!(vector(&mut data).is_err());
        assert!(decode_sha256(&"A".repeat(64)).is_err());
        assert!(decode_sha256(&"0".repeat(63)).is_err());
        assert_eq!(decode_sha256(&"ab".repeat(32)).unwrap(), [0xab; 32]);
        assert!(parse_manifest("[]").is_err());
        assert!(parse_manifest(&" ".repeat(MAX_MANIFEST_BYTES + 1)).is_err());
    }
}
