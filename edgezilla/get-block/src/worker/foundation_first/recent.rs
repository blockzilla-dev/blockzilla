//! Read existing native frames. This module has no result cache or body decoder.
use super::*;

pub(crate) const STREAM_TYPE: &str = "application/vnd.blockzilla.stream.v2";
const MAX_FRAME_BYTES: usize = 16 + 65_536 + 16 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 4096;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecentSource {
    pub genesis_hash: String,
    pub node_identity: String,
    pub agave_revision: String,
    pub session_id: String,
}

impl RecentSource {
    pub(crate) fn parse(text: &str) -> std::result::Result<Self, String> {
        if text.len() > 2048 {
            return Err("recent source configuration exceeds its bound".into());
        }
        let value: Self =
            serde_json::from_str(text).map_err(|_| "invalid recent source configuration")?;
        hash(&value.genesis_hash)?;
        hash(&value.node_identity)?;
        if !session(&value.session_id)
            || value.agave_revision.is_empty()
            || value.agave_revision.len() > 128
            || !value.agave_revision.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err("invalid recent source configuration".into());
        }
        Ok(value)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RecentRequest {
    pub slot: u64,
    pub blockhash: String,
    pub expected_hash: [u8; 32],
    pub commitment: String,
    pub cursor: Option<String>,
    pub source_session: Option<String>,
    pub bank_id: Option<u64>,
}

impl RecentRequest {
    pub(crate) fn parse(req: &Request, raw_slot: &str) -> std::result::Result<Self, String> {
        let slot = canonical_number(
            raw_slot
                .strip_suffix(".compact")
                .ok_or("invalid compact route")?,
        )?;
        let mut values = BTreeMap::new();
        for (key, value) in req
            .url()
            .map_err(|_| "invalid compact query")?
            .query_pairs()
        {
            if !matches!(
                key.as_ref(),
                "blockhash" | "commitment" | "cursor" | "source_session" | "bank_id" | "profile"
            ) || value.len() > 512
                || values
                    .insert(key.into_owned(), value.into_owned())
                    .is_some()
            {
                return Err("unknown, repeated or oversized compact query field".into());
            }
        }
        let blockhash = values
            .remove("blockhash")
            .ok_or("compact requests require an expected blockhash")?;
        let expected_hash = hash(&blockhash)?;
        let commitment = values
            .remove("commitment")
            .unwrap_or_else(|| "finalized".into());
        let cursor = values.remove("cursor");
        let source_session = values.remove("source_session");
        let bank_id = values
            .remove("bank_id")
            .map(|s| canonical_number(&s))
            .transpose()?;
        match commitment.as_str() {
            "finalized" if cursor.is_none() && source_session.is_none() && bank_id.is_none() => {}
            "processed" => {
                let (cursor_session, _, _) = cursor_parts(
                    cursor
                        .as_deref()
                        .ok_or("processed recovery requires an exact cursor")?,
                )?;
                if source_session.as_deref() != Some(cursor_session) || bank_id.is_none() {
                    return Err(
                        "processed recovery requires matching source, cursor and Bank pins".into(),
                    );
                }
            }
            _ => return Err("invalid compact commitment or identity fields".into()),
        }
        Ok(Self {
            slot,
            blockhash,
            expected_hash,
            commitment,
            cursor,
            source_session,
            bank_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecentMetadata {
    pub version: u16,
    pub slot: u64,
    pub blockhash: String,
    pub parent_slot: u64,
    pub parent_blockhash: String,
    pub bank_id: u64,
    pub source: RecentSource,
    pub cursor: String,
    pub frame_sha256: String,
    pub commitment: String,
}

impl RecentMetadata {
    fn validate(
        &self,
        request: &RecentRequest,
        source: &RecentSource,
        delivered_digest: &[u8; 32],
    ) -> std::result::Result<(), String> {
        let (cursor_source, _, cursor_digest) = cursor_parts(&self.cursor)?;
        if self.version != 1
            || self.slot != request.slot
            || self.slot > MAX_SAFE_INTEGER
            || self.parent_slot >= self.slot
            || self.bank_id > MAX_SAFE_INTEGER
            || hash(&self.blockhash)? != request.expected_hash
            || self.source != *source
            || cursor_source != source.session_id
            || self.commitment != request.commitment
            || digest(&self.frame_sha256)? != *delivered_digest
            || cursor_digest != self.frame_sha256
        {
            return Err("recent frame metadata differs from its pinned request or source".into());
        }
        hash(&self.parent_blockhash)?;
        if request.commitment == "processed"
            && (request.cursor.as_deref() != Some(self.cursor.as_str())
                || request.source_session.as_deref() != Some(self.source.session_id.as_str())
                || request.bank_id != Some(self.bank_id))
        {
            return Err("recent processed frame differs from its exact recovery identity".into());
        }
        Ok(())
    }
}

pub(crate) enum RecentOutcome {
    Recent {
        response: Response,
        metadata: RecentMetadata,
        encoded_metadata: String,
    },
    NotCached {
        source: Option<PendingLocatorV1>,
    },
    Unavailable {
        status: u16,
        reason: String,
    },
}

enum RecentHeaders {
    Recent {
        metadata: RecentMetadata,
        encoded_metadata: String,
        length: usize,
    },
    Small {
        result: String,
        length: usize,
        digest: [u8; 32],
        archive_hash: Option<String>,
    },
}

impl Config {
    pub(crate) async fn lookup_recent(
        &self,
        source: &WorkerSource,
        request: &RecentRequest,
        expected_source: &RecentSource,
    ) -> std::result::Result<RecentOutcome, String> {
        if source.archive_prefix != self.prefix {
            return Err("Foundation recent prefix differs from configuration".into());
        }
        if request
            .source_session
            .as_deref()
            .is_some_and(|s| s != expected_source.session_id)
        {
            return Err("requested recent source differs from the configured source".into());
        }
        let (_, plan) = self.plan(request.slot, read_mode(source))?;
        let mut url = self.endpoint.clone();
        url.set_path(&format!("/v1/recent/{}", request.slot));
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("blockhash", &request.blockhash)
                .append_pair("commitment", &request.commitment);
            if let Some(cursor) = &request.cursor {
                query.append_pair("cursor", cursor);
            }
            if let Some(session) = &request.source_session {
                query.append_pair("source_session", session);
            }
            if let Some(bank) = request.bank_id {
                query.append_pair("bank_id", &bank.to_string());
            }
        }
        let headers = Headers::new();
        for (name, value) in plan {
            headers
                .set(name, &value)
                .map_err(|_| "invalid Foundation recent request header")?;
        }
        headers
            .set("Accept", &format!("{STREAM_TYPE}, application/json"))
            .map_err(|_| "invalid recent accept header")?;
        let mut init = RequestInit::new();
        init.with_method(Method::Get)
            .with_headers(headers)
            .with_redirect(worker::RequestRedirect::Manual);
        let outgoing = Request::new_with_init(url.as_str(), &init)
            .map_err(|_| "invalid Foundation recent request")?;
        let controller =
            web_sys::AbortController::new().map_err(|_| "cannot create recent cancellation")?;
        let signal = worker::AbortSignal::from(controller.signal());
        let started = now_ms();
        source.backend_read.mark();
        source.storage_metrics.attempt_foundation_recent_http();
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
            _ => {
                controller.abort();
                return Err("Foundation recent transport is unavailable".into());
            }
        };
        let status = response.status_code();
        source.record_elapsed(
            "foundation_recent_headers",
            started,
            0,
            "existing_native_frames",
            Some(status),
        );
        let metadata = match self.recent_headers(status, request, expected_source, |name| {
            response.headers().get(name).ok().flatten()
        }) {
            Ok(value) => value,
            Err(error) => {
                controller.abort();
                return Err(error);
            }
        };
        let length = match &metadata {
            RecentHeaders::Recent { length, .. } | RecentHeaders::Small { length, .. } => *length,
        };
        let mut response =
            match bounded_response(response, length, self.body_timeout_ms, &controller) {
                Ok(response) => response,
                Err(error) => {
                    controller.abort();
                    return Err(error);
                }
            };
        match metadata {
            RecentHeaders::Recent {
                metadata,
                encoded_metadata,
                ..
            } => Ok(RecentOutcome::Recent {
                response,
                metadata,
                encoded_metadata,
            }),
            RecentHeaders::Small {
                result,
                digest,
                archive_hash,
                ..
            } => {
                let body = response
                    .bytes()
                    .await
                    .map_err(|_| "Foundation recent status body failed")?;
                if body.len() != length || native_hash::sha256(&body).await? != digest {
                    return Err("Foundation recent status body digest differs".into());
                }
                if result == "not_cached" {
                    if request.commitment != "finalized" {
                        return Err("processed recovery cannot fall back to an archive".into());
                    }
                    let route =
                        validate_not_cached(&self.prefix, &self.generation, request.slot, &body)?;
                    if route.is_some()
                        && archive_hash.as_deref() != Some(request.blockhash.as_str())
                    {
                        return Err(
                            "Foundation archive miss lacks the expected blockhash proof".into()
                        );
                    }
                    Ok(RecentOutcome::NotCached { source: route })
                } else {
                    #[derive(Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct ErrorBody {
                        version: u16,
                        slot: u64,
                        reason: String,
                    }
                    let value: ErrorBody = serde_json::from_slice(&body)
                        .map_err(|_| "invalid recent unavailable body")?;
                    if value.version != 1
                        || value.slot != request.slot
                        || value.reason.is_empty()
                        || value.reason.len() > 64
                        || !value
                            .reason
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b == b'_')
                    {
                        return Err("recent unavailable body differs from request".into());
                    }
                    Ok(RecentOutcome::Unavailable {
                        status,
                        reason: value.reason,
                    })
                }
            }
        }
    }

    fn recent_headers(
        &self,
        status: u16,
        request: &RecentRequest,
        expected_source: &RecentSource,
        mut get: impl FnMut(&str) -> Option<String>,
    ) -> std::result::Result<RecentHeaders, String> {
        let need = |get: &mut dyn FnMut(&str) -> Option<String>, name: &str| {
            get(name).ok_or_else(|| format!("missing recent response header {name}"))
        };
        if need(&mut get, "X-BZ-Foundation-Protocol")? != PROTOCOL
            || need(&mut get, "X-BZ-Foundation-Generation")? != self.generation
            || need(&mut get, "X-BZ-Foundation-Source-Prefix")? != self.prefix
            || get("Content-Encoding").is_some_and(|s| s != "identity")
        {
            return Err("Foundation recent protocol or source configuration differs".into());
        }
        let length = usize::try_from(canonical_number(&need(&mut get, "Content-Length")?)?)
            .map_err(|_| "recent body length exceeds the runtime bound")?;
        let sha = digest(&need(&mut get, "X-BZ-Foundation-SHA256")?)?;
        let result = need(&mut get, "X-BZ-Foundation-Result")?;
        let content_type = need(&mut get, "Content-Type")?;
        if result == "recent"
            && status == 200
            && content_type == STREAM_TYPE
            && (17..=MAX_FRAME_BYTES).contains(&length)
        {
            let encoded_metadata = need(&mut get, "X-BZ-Recent-Metadata")?;
            if encoded_metadata.len() > MAX_METADATA_BYTES || encoded_metadata.contains('=') {
                return Err("recent metadata exceeds its bound".into());
            }
            let bytes = URL_SAFE_NO_PAD
                .decode(&encoded_metadata)
                .map_err(|_| "invalid recent metadata encoding")?;
            if URL_SAFE_NO_PAD.encode(&bytes) != encoded_metadata {
                return Err("recent metadata encoding is not canonical".into());
            }
            let metadata: RecentMetadata =
                serde_json::from_slice(&bytes).map_err(|_| "invalid recent frame metadata")?;
            metadata.validate(request, expected_source, &sha)?;
            return Ok(RecentHeaders::Recent {
                metadata,
                encoded_metadata,
                length,
            });
        }
        if length == 0
            || length > MAX_UNAVAILABLE_BYTES
            || content_type != "application/json"
            || !(result == "not_cached" && status == 404
                || result == "unavailable" && matches!(status, 400 | 404 | 409 | 410 | 503))
        {
            return Err("invalid Foundation recent response status or framing".into());
        }
        Ok(RecentHeaders::Small {
            result,
            length,
            digest: sha,
            archive_hash: get("X-BZ-Recent-Blockhash"),
        })
    }
}

fn canonical_number(text: &str) -> std::result::Result<u64, String> {
    let value: u64 = text
        .parse()
        .map_err(|_| "invalid canonical compact number")?;
    if text != value.to_string() || value > MAX_SAFE_INTEGER {
        return Err("invalid canonical compact number".into());
    }
    Ok(value)
}

fn session(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn cursor_parts(cursor: &str) -> std::result::Result<(&str, u64, &str), String> {
    let mut parts = cursor.split(':');
    let source = parts.next().ok_or("invalid recent cursor")?;
    let sequence = canonical_number(
        parts
            .next()
            .and_then(|s| s.strip_prefix('p'))
            .ok_or("invalid recent cursor")?,
    )?;
    let sha = parts.next().ok_or("invalid recent cursor")?;
    digest(sha)?;
    if !session(source) || sequence == 0 || parts.next().is_some() {
        return Err("invalid recent cursor".into());
    }
    Ok((source, sequence, sha))
}

fn hash(text: &str) -> std::result::Result<[u8; 32], String> {
    let bytes: [u8; 32] = bs58::decode(text)
        .into_vec()
        .map_err(|_| "invalid compact block hash")?
        .try_into()
        .map_err(|_| "compact block hash must have 32 bytes")?;
    if base58_32(&bytes) != text {
        return Err("compact block hash is not canonical".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> RecentSource {
        RecentSource {
            genesis_hash: base58_32(&[1; 32]),
            node_identity: base58_32(&[2; 32]),
            agave_revision: "revision-1".into(),
            session_id: "source-1".into(),
        }
    }
    fn request(processed: bool) -> RecentRequest {
        RecentRequest {
            slot: 432001,
            blockhash: base58_32(&[11; 32]),
            expected_hash: [11; 32],
            commitment: if processed { "processed" } else { "finalized" }.into(),
            cursor: processed.then(|| format!("source-1:p7:{}", "ab".repeat(32))),
            source_session: processed.then(|| "source-1".into()),
            bank_id: processed.then_some(19),
        }
    }
    fn metadata(processed: bool) -> RecentMetadata {
        RecentMetadata {
            version: 1,
            slot: 432001,
            blockhash: base58_32(&[11; 32]),
            parent_slot: 432000,
            parent_blockhash: base58_32(&[10; 32]),
            bank_id: 19,
            source: source(),
            cursor: format!("source-1:p7:{}", "ab".repeat(32)),
            frame_sha256: "ab".repeat(32),
            commitment: if processed { "processed" } else { "finalized" }.into(),
        }
    }
    fn config() -> Config {
        Config::parse(
            "https://foundation.example",
            "fixture_secret_abcdefghijklmnopqrstuvwxyz".into(),
            "compact-v2/test",
            "generation-1".into(),
            None,
            None,
            false,
        )
        .unwrap()
    }
    fn headers() -> BTreeMap<String, String> {
        [
            ("X-BZ-Foundation-Protocol", "1".into()),
            ("X-BZ-Foundation-Generation", "generation-1".into()),
            ("X-BZ-Foundation-Source-Prefix", "compact-v2/test".into()),
            ("Content-Type", STREAM_TYPE.into()),
            ("Content-Length", "200".into()),
            ("X-BZ-Foundation-SHA256", "ab".repeat(32)),
            ("X-BZ-Foundation-Result", "recent".into()),
            (
                "X-BZ-Recent-Metadata",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&metadata(false)).unwrap()),
            ),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect()
    }
    #[test]
    fn recent_only_configuration_skips_the_legacy_lookup_without_disabling_recovery() {
        assert!(archive_lookup_mode(None).unwrap());
        assert!(archive_lookup_mode(Some("all")).unwrap());
        assert!(!archive_lookup_mode(Some("recent-only")).unwrap());
        for mode in ["", "off", "recent", "RECENT-ONLY"] {
            assert!(archive_lookup_mode(Some(mode)).is_err());
        }
    }
    #[test]
    fn recent_source_requires_exact_complete_canonical_identity() {
        let valid = serde_json::to_string(&source()).unwrap();
        assert_eq!(RecentSource::parse(&valid).unwrap(), source());
        let mut value = serde_json::to_value(source()).unwrap();
        value["session_id"] = json!("bad:session");
        assert!(RecentSource::parse(&value.to_string()).is_err());
        value["session_id"] = json!("source-1");
        value["unknown"] = json!(1);
        assert!(RecentSource::parse(&value.to_string()).is_err());
    }
    #[test]
    fn metadata_binds_hash_parent_source_and_exact_processed_cursor_bank() {
        for processed in [false, true] {
            let valid = metadata(processed);
            assert!(
                valid
                    .validate(&request(processed), &source(), &[0xab; 32])
                    .is_ok()
            );
            for change in 0..9 {
                let mut wrong = valid.clone();
                match change {
                    0 => wrong.slot += 1,
                    1 => wrong.blockhash = base58_32(&[12; 32]),
                    2 => wrong.parent_slot = wrong.slot,
                    3 => wrong.parent_blockhash = "invalid".into(),
                    4 => wrong.source.session_id = "another-source".into(),
                    5 => wrong.commitment = "confirmed".into(),
                    6 => wrong.frame_sha256 = "ac".repeat(32),
                    7 => wrong.cursor = format!("another-source:p7:{}", "ab".repeat(32)),
                    _ => wrong.version = 2,
                }
                assert!(
                    wrong
                        .validate(&request(processed), &source(), &[0xab; 32])
                        .is_err(),
                    "change {change}"
                );
            }
        }
        let mut wrong = metadata(true);
        wrong.bank_id += 1;
        assert!(
            wrong
                .validate(&request(true), &source(), &[0xab; 32])
                .is_err()
        );
        let mut wrong = metadata(true);
        wrong.cursor = format!("source-1:p8:{}", "ab".repeat(32));
        assert!(
            wrong
                .validate(&request(true), &source(), &[0xab; 32])
                .is_err()
        );
    }
    #[test]
    fn recent_headers_require_protocol_digest_length_and_metadata() {
        let valid = headers();
        let config = config();
        assert!(matches!(
            config
                .recent_headers(200, &request(false), &source(), |n| valid.get(n).cloned())
                .unwrap(),
            RecentHeaders::Recent { length: 200, .. }
        ));
        for (name, value) in [
            ("X-BZ-Foundation-Protocol", "2"),
            ("X-BZ-Foundation-Generation", "other"),
            ("X-BZ-Foundation-Source-Prefix", "other"),
            ("Content-Length", "0200"),
            ("Content-Length", "0"),
            ("Content-Length", "17000000"),
            ("X-BZ-Foundation-SHA256", "bad"),
            ("X-BZ-Foundation-SHA256", &"ac".repeat(32)),
            ("Content-Type", BUNDLE_TYPE),
            ("Content-Encoding", "gzip"),
            ("X-BZ-Recent-Metadata", "bad=="),
        ] {
            let mut wrong = valid.clone();
            wrong.insert(name.into(), value.into());
            assert!(
                config
                    .recent_headers(200, &request(false), &source(), |n| wrong.get(n).cloned())
                    .is_err(),
                "{name}={value}"
            );
        }
        assert!(
            config
                .recent_headers(302, &request(false), &source(), |n| valid.get(n).cloned())
                .is_err()
        );
    }
    #[test]
    fn error_headers_allow_only_small_tagged_errors_and_explicit_misses() {
        let mut valid = headers();
        valid.insert("Content-Type".into(), "application/json".into());
        valid.insert("X-BZ-Foundation-Result".into(), "unavailable".into());
        assert!(matches!(
            config()
                .recent_headers(503, &request(false), &source(), |n| valid.get(n).cloned())
                .unwrap(),
            RecentHeaders::Small { .. }
        ));
        assert!(
            config()
                .recent_headers(500, &request(false), &source(), |n| valid.get(n).cloned())
                .is_err()
        );
        valid.insert("X-BZ-Foundation-Result".into(), "not_cached".into());
        assert!(matches!(
            config()
                .recent_headers(404, &request(false), &source(), |n| valid.get(n).cloned())
                .unwrap(),
            RecentHeaders::Small { .. }
        ));
        valid.insert("Content-Length".into(), "4097".into());
        assert!(
            config()
                .recent_headers(404, &request(false), &source(), |n| valid.get(n).cloned())
                .is_err()
        );
    }
    #[test]
    fn cursors_and_numbers_reject_aliases_controls_and_extra_fields() {
        assert_eq!(canonical_number("0").unwrap(), 0);
        for number in ["00", "+1", "-1", "9007199254740992", " 1", "1 "] {
            assert!(canonical_number(number).is_err());
        }
        assert!(cursor_parts(&format!("source-1:p1:{}", "ab".repeat(32))).is_ok());
        for cursor in [
            format!("source-1:p0:{}", "ab".repeat(32)),
            format!("source-1:p01:{}", "ab".repeat(32)),
            format!("source-1:p1:{}:extra", "ab".repeat(32)),
            format!("bad_source:p1:{}", "ab".repeat(32)),
        ] {
            assert!(cursor_parts(&cursor).is_err());
        }
    }
}
