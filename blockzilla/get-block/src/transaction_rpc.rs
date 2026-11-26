//! Shared, transport-free getTransaction request and locator validation.

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::ops::Range;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionRpcError {
    pub code: i64,
    pub message: String,
}

impl TransactionRpcError {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: message.into(),
        }
    }

    pub fn unavailable(message: impl Into<String>) -> Self {
        Self {
            code: -32000,
            message: message.into(),
        }
    }

    pub fn incomplete() -> Self {
        Self {
            code: -32004,
            message: "The signature index does not cover complete declared history".into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionEncoding {
    Json,
    Base64,
    Base58,
    LegacyBinary,
}

#[derive(Debug, Clone)]
pub struct GetTransactionParams {
    pub signature: [u8; 64],
    pub signature_text: String,
    pub encoding: TransactionEncoding,
    pub max_supported_version: Option<u8>,
}

pub fn parse_params(params: Option<&Value>) -> Result<GetTransactionParams, TransactionRpcError> {
    let params = params.and_then(Value::as_array).ok_or_else(|| {
        TransactionRpcError::invalid("getTransaction requires an array of parameters")
    })?;
    if !(1..=2).contains(&params.len()) {
        return Err(TransactionRpcError::invalid(
            "getTransaction requires a signature and an optional config",
        ));
    }
    let signature_text = params[0]
        .as_str()
        .filter(|value| value.len() <= 88)
        .ok_or_else(|| {
            TransactionRpcError::invalid("signature must be a base58 string of 64 bytes")
        })?;
    let mut signature = [0; 64];
    five8::decode_64(signature_text, &mut signature).map_err(|_| {
        TransactionRpcError::invalid("signature must be a base58 string of 64 bytes")
    })?;
    let mut result = GetTransactionParams {
        signature,
        signature_text: signature_text.into(),
        encoding: TransactionEncoding::Json,
        max_supported_version: None,
    };
    let Some(config) = params.get(1) else {
        return Ok(result);
    };
    if config.is_null() {
        return Ok(result);
    }
    if let Some(encoding) = config.as_str() {
        result.encoding = parse_encoding(encoding)?;
        return Ok(result);
    }
    let map = config.as_object().ok_or_else(|| {
        TransactionRpcError::invalid("getTransaction config must be an object or encoding string")
    })?;
    if let Some(encoding) = map.get("encoding") {
        result.encoding = parse_encoding(
            encoding
                .as_str()
                .ok_or_else(|| TransactionRpcError::invalid("encoding must be a string"))?,
        )?;
    }
    if let Some(commitment) = map.get("commitment") {
        match commitment.as_str() {
            Some("confirmed" | "finalized") => {}
            _ => {
                return Err(TransactionRpcError::invalid(
                    "archive getTransaction requires confirmed or finalized commitment",
                ));
            }
        }
    }
    if let Some(maximum) = map.get("maxSupportedTransactionVersion") {
        result.max_supported_version = Some(
            maximum
                .as_u64()
                .and_then(|value| u8::try_from(value).ok())
                .ok_or_else(|| {
                    TransactionRpcError::invalid(
                        "maxSupportedTransactionVersion must be an integer from 0 through 255",
                    )
                })?,
        );
    }
    Ok(result)
}

fn parse_encoding(encoding: &str) -> Result<TransactionEncoding, TransactionRpcError> {
    match encoding {
        "json" => Ok(TransactionEncoding::Json),
        "base64" => Ok(TransactionEncoding::Base64),
        "base58" => Ok(TransactionEncoding::Base58),
        "binary" => Ok(TransactionEncoding::LegacyBinary),
        "jsonParsed" => Err(TransactionRpcError::invalid(
            "The jsonParsed encoding is not supported by this archive RPC",
        )),
        _ => Err(TransactionRpcError::invalid(
            "encoding must be json, base64, or base58",
        )),
    }
}

pub fn check_version(
    version: &Value,
    params: &GetTransactionParams,
) -> Result<(), TransactionRpcError> {
    if version.as_str() == Some("legacy") {
        return Ok(());
    }
    let version = version
        .as_u64()
        .and_then(|value| u8::try_from(value).ok())
        .ok_or_else(|| {
            TransactionRpcError::unavailable("archive transaction version is invalid")
        })?;
    if params
        .max_supported_version
        .is_none_or(|maximum| maximum < version)
    {
        return Err(TransactionRpcError {
            code: -32015,
            message: format!(
                "Transaction version ({version}) is not supported by the requesting client. Set maxSupportedTransactionVersion to {version} or higher"
            ),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub epoch: u64,
    pub slot: u64,
    pub archive_binding: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocatorResponse {
    pub schema_version: u32,
    pub signature: String,
    pub catalog_digest: String,
    pub candidate: Option<Candidate>,
    pub coverage_complete: bool,
}

pub const MAX_LIVE_CANDIDATES: usize = 32;

/// A segment candidate carries its immutable archive namespace. Different
/// generations in one epoch can therefore be checked in the same request.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveCandidate {
    pub epoch: u64,
    pub slot: u64,
    pub archive_binding: String,
    pub archive_prefix: String,
}

impl LiveCandidate {
    pub fn candidate(&self) -> Candidate {
        Candidate {
            epoch: self.epoch,
            slot: self.slot,
            archive_binding: self.archive_binding.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveLocatorResponse {
    pub schema_version: u32,
    pub signature: String,
    pub catalog_id: String,
    pub catalog_digest: String,
    pub candidates: Vec<LiveCandidate>,
    pub coverage_complete: bool,
}

/// Prefixes are object-key namespaces, never URLs or escaped paths.
pub fn valid_archive_prefix(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && value.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        })
}

impl LiveLocatorResponse {
    /// The authenticated locator owns catalog publication. Pin its stable
    /// catalog identity while it selects a validated immutable generation.
    pub fn validate(&self, signature: &str, catalog_id: &str) -> Result<(), TransactionRpcError> {
        if self.schema_version != 2
            || self.signature != signature
            || !valid_digest(catalog_id)
            || self.catalog_id != catalog_id
            || !valid_digest(&self.catalog_digest)
            || self.coverage_complete
            || self.candidates.len() > MAX_LIVE_CANDIDATES
        {
            return Err(TransactionRpcError::unavailable(
                "signature locator response does not match the pinned request and catalog identity",
            ));
        }
        for candidate in &self.candidates {
            validate_candidate(&candidate.candidate())?;
            if !valid_archive_prefix(&candidate.archive_prefix) {
                return Err(TransactionRpcError::unavailable(
                    "signature locator archive prefix is invalid",
                ));
            }
        }
        Ok(())
    }
}

pub fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Match only first signatures and validate the complete block signature range.
pub fn find_first_signature(
    counts: impl IntoIterator<Item = u8>,
    bytes: &[u8],
    signature: &[u8; 64],
) -> Result<Option<(usize, Range<usize>)>, TransactionRpcError> {
    let invalid =
        || TransactionRpcError::unavailable("block signature bytes differ from transaction rows");
    let mut offset = 0usize;
    let mut found = None;
    for (index, count) in counts.into_iter().enumerate() {
        let length = usize::from(count) * 64;
        let next = offset
            .checked_add(length)
            .filter(|next| *next <= bytes.len())
            .ok_or_else(invalid)?;
        if count != 0 && found.is_none() && bytes[offset..offset + 64] == signature[..] {
            found = Some((index, offset..next));
        }
        offset = next;
    }
    if offset != bytes.len() {
        return Err(invalid());
    }
    Ok(found)
}

impl LocatorResponse {
    pub fn validate(&self, signature: &str, catalog: &str) -> Result<(), TransactionRpcError> {
        if self.schema_version != 1
            || self.signature != signature
            || !valid_digest(catalog)
            || self.catalog_digest != catalog
        {
            return Err(TransactionRpcError::unavailable(
                "signature locator response does not match the pinned request and catalog",
            ));
        }
        if let Some(candidate) = &self.candidate {
            validate_candidate(candidate)?;
        }
        Ok(())
    }
}

fn validate_candidate(candidate: &Candidate) -> Result<(), TransactionRpcError> {
    if candidate.slot > u64::from(u32::MAX)
        || !valid_digest(&candidate.archive_binding)
        || candidate.epoch != candidate.slot / 432_000
    {
        return Err(TransactionRpcError::unavailable(
            "signature locator candidate is invalid",
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveManifest {
    pub schema_version: u32,
    pub cluster_id: String,
    pub epoch: u64,
    pub generation_id: String,
    pub generation_digest: String,
    pub slots_per_epoch: u64,
    pub complete: bool,
    pub files: Vec<ArchiveManifestFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveManifestFile {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

/// Validate the same canonical generation digest used by the archive SDK.
/// The selected archive prefix must retain its published immutable objects.
pub fn parse_manifest(
    bytes: &[u8],
    candidate: &Candidate,
    cluster: &str,
) -> Result<ArchiveManifest, TransactionRpcError> {
    let manifest: ArchiveManifest = serde_json::from_slice(bytes)
        .map_err(|_| TransactionRpcError::unavailable("invalid archive generation manifest"))?;
    if manifest.schema_version != 1
        || manifest.epoch != candidate.epoch
        || manifest.cluster_id != cluster
        || manifest.slots_per_epoch != 432_000
        || !manifest.complete
        || manifest.generation_id.is_empty()
        || manifest.generation_id.len() > 128
        || manifest.generation_digest != candidate.archive_binding
        || !valid_digest(&manifest.generation_digest)
        || manifest.files.len() > 64
    {
        return Err(TransactionRpcError::unavailable(
            "archive generation does not match the signature index",
        ));
    }
    let mut files: Vec<_> = manifest.files.iter().collect();
    files.sort_unstable_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    if files.windows(2).any(|pair| pair[0].name == pair[1].name) {
        return Err(TransactionRpcError::unavailable(
            "archive generation has duplicate files",
        ));
    }
    let mut preimage = b"blockzilla/archive-v2-generation\0".to_vec();
    preimage.extend_from_slice(&manifest.schema_version.to_le_bytes());
    push_string(&mut preimage, &manifest.cluster_id)?;
    preimage.extend_from_slice(&manifest.epoch.to_le_bytes());
    push_string(&mut preimage, &manifest.generation_id)?;
    preimage.extend_from_slice(&manifest.slots_per_epoch.to_le_bytes());
    preimage.push(u8::from(manifest.complete));
    preimage.extend_from_slice(&(files.len() as u32).to_le_bytes());
    for file in files {
        if file.name.is_empty()
            || file.name.len() > 128
            || file.name.contains(['/', '\\'])
            || file.name == "."
            || file.name == ".."
            || file.name == "archive-v2-generation.json"
            || file.name.chars().any(char::is_control)
            || !valid_digest(&file.sha256)
        {
            return Err(TransactionRpcError::unavailable(
                "archive generation file entry is invalid",
            ));
        }
        push_string(&mut preimage, &file.name)?;
        preimage.extend_from_slice(&file.size.to_le_bytes());
        for offset in (0..64).step_by(2) {
            preimage.push(
                u8::from_str_radix(&file.sha256[offset..offset + 2], 16)
                    .expect("checked hex digest"),
            );
        }
    }
    let digest = Sha256::digest(&preimage)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if digest != manifest.generation_digest {
        return Err(TransactionRpcError::unavailable(
            "archive generation digest is invalid",
        ));
    }
    for required in [
        "archive-v2-blocks.zstd",
        "archive-v2-blocks.index",
        "archive-v2-meta.wincode",
        "registry.bin",
        "signatures.bin",
    ] {
        if !manifest.files.iter().any(|file| file.name == required) {
            return Err(TransactionRpcError::unavailable(
                "archive generation omits a required transaction object",
            ));
        }
    }
    Ok(manifest)
}

fn push_string(output: &mut Vec<u8>, value: &str) -> Result<(), TransactionRpcError> {
    let length = u32::try_from(value.len())
        .map_err(|_| TransactionRpcError::unavailable("manifest string is too large"))?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

/// Encode the resolved JSON representation with Solana's legacy/V0 wire layout.
/// JSON is produced by the shared getBlock renderer before this conversion.
pub fn encode_transaction(
    transaction: &Value,
    version: &Value,
) -> Result<Vec<u8>, TransactionRpcError> {
    let invalid = || {
        TransactionRpcError::unavailable(
            "archive transaction cannot be encoded as Solana wire bytes",
        )
    };
    let message = transaction.get("message").ok_or_else(invalid)?;
    let signatures = transaction
        .get("signatures")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    let mut output = Vec::new();
    push_short_len(&mut output, signatures.len())?;
    for signature in signatures {
        let text = signature.as_str().ok_or_else(invalid_base58)?;
        let mut bytes = [0; 64];
        five8::decode_64(text, &mut bytes).map_err(|_| invalid_base58())?;
        output.extend_from_slice(&bytes);
    }
    if version.as_u64() == Some(0) {
        output.push(0x80);
    } else if version.as_str() != Some("legacy") {
        return Err(TransactionRpcError {
            code: -32015,
            message: "Binary getTransaction encoding currently supports legacy and V0 transactions"
                .into(),
        });
    }
    for field in [
        "numRequiredSignatures",
        "numReadonlySignedAccounts",
        "numReadonlyUnsignedAccounts",
    ] {
        output.push(
            message
                .get("header")
                .and_then(|header| header.get(field))
                .and_then(Value::as_u64)
                .and_then(|value| u8::try_from(value).ok())
                .ok_or_else(invalid)?,
        );
    }
    let keys = message
        .get("accountKeys")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    push_short_len(&mut output, keys.len())?;
    for key in keys {
        output.extend_from_slice(&decode_base58_key(key)?);
    }
    output.extend_from_slice(&decode_base58_key(
        message.get("recentBlockhash").ok_or_else(invalid)?,
    )?);
    let instructions = message
        .get("instructions")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    push_short_len(&mut output, instructions.len())?;
    for instruction in instructions {
        output.push(
            instruction
                .get("programIdIndex")
                .and_then(Value::as_u64)
                .and_then(|value| u8::try_from(value).ok())
                .ok_or_else(invalid)?,
        );
        append_indices(
            &mut output,
            instruction.get("accounts").ok_or_else(invalid)?,
        )?;
        let bytes = bs58::decode(
            instruction
                .get("data")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?,
        )
        .into_vec()
        .map_err(|_| invalid())?;
        push_short_len(&mut output, bytes.len())?;
        output.extend(bytes);
    }
    if version.as_u64() == Some(0) {
        let lookups = message
            .get("addressTableLookups")
            .and_then(Value::as_array)
            .ok_or_else(invalid)?;
        push_short_len(&mut output, lookups.len())?;
        for lookup in lookups {
            output.extend_from_slice(&decode_base58_key(
                lookup.get("accountKey").ok_or_else(invalid)?,
            )?);
            append_indices(
                &mut output,
                lookup.get("writableIndexes").ok_or_else(invalid)?,
            )?;
            append_indices(
                &mut output,
                lookup.get("readonlyIndexes").ok_or_else(invalid)?,
            )?;
        }
    }
    if output.len() > 65_536 {
        return Err(invalid());
    }
    Ok(output)
}

fn invalid_base58() -> TransactionRpcError {
    TransactionRpcError::unavailable("archive contains an invalid base58 value")
}

fn decode_base58_key(value: &Value) -> Result<[u8; 32], TransactionRpcError> {
    let text = value.as_str().ok_or_else(invalid_base58)?;
    let mut bytes = [0; 32];
    five8::decode_32(text, &mut bytes).map_err(|_| invalid_base58())?;
    Ok(bytes)
}

fn append_indices(output: &mut Vec<u8>, value: &Value) -> Result<(), TransactionRpcError> {
    let values = value.as_array().ok_or_else(|| {
        TransactionRpcError::unavailable("archive instruction indices are invalid")
    })?;
    push_short_len(output, values.len())?;
    for value in values {
        output.push(
            value
                .as_u64()
                .and_then(|value| u8::try_from(value).ok())
                .ok_or_else(|| {
                    TransactionRpcError::unavailable("archive instruction index exceeds u8")
                })?,
        );
    }
    Ok(())
}

fn push_short_len(output: &mut Vec<u8>, length: usize) -> Result<(), TransactionRpcError> {
    let mut remaining = u16::try_from(length).map_err(|_| {
        TransactionRpcError::unavailable("archive vector exceeds Solana short-vector length")
    })?;
    loop {
        let next = (remaining & 0x7f) as u8;
        remaining >>= 7;
        output.push(next | if remaining != 0 { 0x80 } else { 0 });
        if remaining == 0 {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn params(config: Value) -> GetTransactionParams {
        parse_params(Some(&json!([bs58::encode([3; 64]).into_string(), config]))).unwrap()
    }

    #[test]
    fn validates_signature_config_commitment_and_version_before_io() {
        for request in [
            json!([]),
            json!(["bad"]),
            json!([7]),
            json!([bs58::encode([3; 64]).into_string(), {"encoding":"jsonParsed"}]),
            json!([bs58::encode([3; 64]).into_string(), {"commitment":"processed"}]),
            json!([bs58::encode([3; 64]).into_string(), {"maxSupportedTransactionVersion":-1}]),
        ] {
            assert_eq!(parse_params(Some(&request)).unwrap_err().code, -32602);
        }
        let legacy = params(json!({}));
        assert!(check_version(&json!("legacy"), &legacy).is_ok());
        assert_eq!(check_version(&json!(0), &legacy).unwrap_err().code, -32015);
        assert!(
            check_version(
                &json!(0),
                &params(json!({"maxSupportedTransactionVersion":0}))
            )
            .is_ok()
        );
        assert_eq!(
            check_version(
                &json!(1),
                &params(json!({"maxSupportedTransactionVersion":0}))
            )
            .unwrap_err()
            .code,
            -32015
        );
        assert_eq!(
            parse_params(Some(&json!([
                bs58::encode([3; 64]).into_string(),
                "base64"
            ])))
            .unwrap()
            .encoding,
            TransactionEncoding::Base64
        );
    }

    #[test]
    fn exact_lookup_rejects_other_signers_and_corrupt_signature_ranges() {
        let bytes = [vec![1; 64], vec![2; 64], vec![3; 64]].concat();
        assert_eq!(
            find_first_signature([2, 1], &bytes, &[3; 64]).unwrap(),
            Some((1, 128..192))
        );
        assert_eq!(
            find_first_signature([2, 1], &bytes, &[2; 64]).unwrap(),
            None
        );
        assert_eq!(
            find_first_signature([2, 1], &bytes, &[9; 64]).unwrap(),
            None
        );
        assert!(find_first_signature([2, 2], &bytes, &[1; 64]).is_err());
        assert!(find_first_signature([2], &bytes, &[1; 64]).is_err());
    }

    #[test]
    fn validates_canonical_generation_binding_and_rejects_changed_objects() {
        let digest = "5b202d0c122633d58b28b54a7df7fde1af707eb81128a16c09acb2f562956902";
        let names = [
            "registry.bin",
            "signatures.bin",
            "archive-v2-meta.wincode",
            "archive-v2-blocks.index",
            "archive-v2-blocks.zstd",
        ];
        let mut manifest = json!({"schema_version":1,"cluster_id":"mainnet-beta","epoch":1,"generation_id":"test-bound-generation","generation_digest":digest,"slots_per_epoch":432000,"complete":true,"files":names.iter().enumerate().map(|(size,name)|json!({"name":name,"size":size,"sha256":"ab".repeat(32)})).collect::<Vec<_>>()});
        let candidate = Candidate {
            epoch: 1,
            slot: 432000,
            archive_binding: digest.into(),
        };
        assert!(
            parse_manifest(
                &serde_json::to_vec(&manifest).unwrap(),
                &candidate,
                "mainnet-beta"
            )
            .is_ok()
        );
        manifest["files"].as_array_mut().unwrap().reverse();
        assert!(
            parse_manifest(
                &serde_json::to_vec(&manifest).unwrap(),
                &candidate,
                "mainnet-beta"
            )
            .is_ok()
        );
        manifest["files"][0]["size"] = json!(999);
        assert!(
            parse_manifest(
                &serde_json::to_vec(&manifest).unwrap(),
                &candidate,
                "mainnet-beta"
            )
            .is_err()
        );
        assert!(
            parse_manifest(
                &serde_json::to_vec(&manifest).unwrap(),
                &candidate,
                "testnet"
            )
            .is_err()
        );
    }

    #[test]
    fn validates_locator_signature_catalog_and_slot() {
        let digest = "a".repeat(64);
        let mut response: LocatorResponse = serde_json::from_value(json!({"schema_version":1,"signature":"requested","catalog_digest":digest,"candidate":{"slot":432000,"epoch":1,"archive_binding":"b".repeat(64)},"coverage_complete":false})).unwrap();
        assert!(response.validate("requested", &digest).is_ok());
        assert!(response.validate("another", &digest).is_err());
        response.candidate.as_mut().unwrap().epoch = 2;
        assert!(response.validate("requested", &digest).is_err());
    }

    #[test]
    fn live_locator_pins_identity_and_accepts_new_catalog_generations() {
        let id = "a".repeat(64);
        let mut response: LiveLocatorResponse = serde_json::from_value(json!({
            "schema_version":2,"signature":"requested","catalog_id":id,
            "catalog_digest":"b".repeat(64),"coverage_complete":false,
            "candidates":[
                {"epoch":1,"slot":432000,"archive_binding":"c".repeat(64),"archive_prefix":"live/segment-1"},
                {"epoch":1,"slot":432001,"archive_binding":"d".repeat(64),"archive_prefix":"live/segment-2"}
            ]
        })).unwrap();
        assert!(response.validate("requested", &id).is_ok());
        response.catalog_digest = "e".repeat(64);
        assert!(response.validate("requested", &id).is_ok());
        assert!(response.validate("changed", &id).is_err());
        assert!(response.validate("requested", &"f".repeat(64)).is_err());
        response.coverage_complete = true;
        assert!(response.validate("requested", &id).is_err());
        response.coverage_complete = false;
        response.catalog_digest = "INVALID".into();
        assert!(response.validate("requested", &id).is_err());
    }

    #[test]
    fn live_locator_rejects_bad_candidates_and_excess_work() {
        let id = "a".repeat(64);
        let mut response: LiveLocatorResponse = serde_json::from_value(json!({
            "schema_version":2,"signature":"requested","catalog_id":id,
            "catalog_digest":"b".repeat(64),"coverage_complete":false,
            "candidates":[{"epoch":1,"slot":432000,"archive_binding":"c".repeat(64),"archive_prefix":"live/segment-1"}]
        })).unwrap();
        let candidate = response.candidates[0].clone();
        response.candidates[0].slot = 1;
        assert!(response.validate("requested", &id).is_err());
        response.candidates[0] = candidate.clone();
        response.candidates[0].archive_binding = "bad".into();
        assert!(response.validate("requested", &id).is_err());
        response.candidates = vec![candidate; MAX_LIVE_CANDIDATES];
        assert!(response.validate("requested", &id).is_ok());
        response.candidates.push(response.candidates[0].clone());
        assert!(response.validate("requested", &id).is_err());
    }

    #[test]
    fn live_archive_prefixes_are_bounded_plain_object_keys() {
        for prefix in ["live/segment-1", "compact-v2/test_20261122.v3"] {
            assert!(valid_archive_prefix(prefix));
        }
        for prefix in [
            "",
            "/start",
            "end/",
            "double//slash",
            ".",
            "..",
            "safe/../bad",
            "safe/./bad",
            "safe\\bad",
            "https://example.com",
            "safe?query",
            "safe#fragment",
            "safe/%2e%2e",
            "safe\nkey",
            "non-ascii-é",
            "white space",
        ] {
            assert!(!valid_archive_prefix(prefix), "{prefix:?}");
        }
        assert!(valid_archive_prefix(&"a".repeat(1024)));
        assert!(!valid_archive_prefix(&"a".repeat(1025)));
    }

    #[test]
    fn binary_encoder_preserves_signatures_and_v0_lookup_bytes() {
        let signature = bs58::encode([3; 64]).into_string();
        let key = bs58::encode([4; 32]).into_string();
        let hash = bs58::encode([5; 32]).into_string();
        let transaction = json!({"signatures":[signature],"message":{"header":{"numRequiredSignatures":1,"numReadonlySignedAccounts":0,"numReadonlyUnsignedAccounts":0},"accountKeys":[key],"recentBlockhash":hash,"instructions":[{"programIdIndex":0,"accounts":[0],"data":bs58::encode([1,2]).into_string()}],"addressTableLookups":[{"accountKey":bs58::encode([6;32]).into_string(),"writableIndexes":[2],"readonlyIndexes":[3]}]}});
        let legacy = encode_transaction(&transaction, &json!("legacy")).unwrap();
        assert_eq!(&legacy[..65], &[vec![1], vec![3; 64]].concat());
        assert_eq!(
            &legacy[65..],
            &[
                vec![1, 0, 0, 1],
                vec![4; 32],
                vec![5; 32],
                vec![1, 0, 1, 0, 2, 1, 2]
            ]
            .concat()
        );
        let v0 = encode_transaction(&transaction, &json!(0)).unwrap();
        assert_eq!(v0[65], 0x80);
        assert_eq!(
            &v0[v0.len() - 37..],
            &[vec![1], vec![6; 32], vec![1, 2, 1, 3]].concat()
        );
        assert_eq!(
            encode_transaction(&transaction, &json!(1))
                .unwrap_err()
                .code,
            -32015
        );
    }
}
