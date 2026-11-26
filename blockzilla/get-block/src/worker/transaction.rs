//! Authenticated signature locator followed by an exact immutable archive read.

use super::*;
use crate::transaction_rpc::{
    self, GetTransactionParams, LiveLocatorResponse, LocatorResponse, TransactionEncoding,
    TransactionRpcError,
};
use futures_util::TryStreamExt;
use std::time::Duration;

const MAX_LOCATOR_BYTES: usize = 16 * 1024;
const MAX_LIVE_LOCATOR_BYTES: usize = 64 * 1024;
const MAX_MANIFEST_BYTES: usize = 128 * 1024;

#[derive(Clone)]
pub(super) struct LocatorConfig {
    url: String,
    token: String,
    catalog_pin: CatalogPin,
    cluster_id: String,
}

#[derive(Clone)]
enum CatalogPin {
    Static(String),
    Live(String),
}

struct LookupResult {
    candidates: Vec<(transaction_rpc::Candidate, Option<String>)>,
    coverage_complete: bool,
}

impl LocatorConfig {
    pub(super) fn from_env(env: &worker::Env) -> std::result::Result<Option<Self>, String> {
        let Some(base) = optional_var(env, "BZ_SIGNATURE_INDEX_URL") else {
            return Ok(None);
        };
        let mut url = worker::Url::parse(&base).map_err(|_| "invalid BZ_SIGNATURE_INDEX_URL")?;
        let local = matches!(
            url.host_str(),
            Some("127.0.0.1" | "localhost" | "[::1]" | "::1")
        );
        if (url.scheme() != "https" && !(url.scheme() == "http" && local))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !matches!(url.path(), "" | "/")
        {
            return Err("BZ_SIGNATURE_INDEX_URL must be an HTTPS origin (HTTP is allowed for loopback tests)".into());
        }
        let token = required_var(env, "BZ_SIGNATURE_INDEX_TOKEN")?;
        if !(16..=512).contains(&token.len()) || token.chars().any(char::is_control) {
            return Err("invalid BZ_SIGNATURE_INDEX_TOKEN".into());
        }
        let catalog_pin = if let Some(id) = optional_var(env, "BZ_SIGNATURE_CATALOG_ID") {
            if !transaction_rpc::valid_digest(&id) {
                return Err("BZ_SIGNATURE_CATALOG_ID must be a lowercase SHA-256 digest".into());
            }
            url.set_path("/v2/lookup");
            CatalogPin::Live(id)
        } else {
            let digest = required_var(env, "BZ_SIGNATURE_CATALOG_DIGEST")?;
            if !transaction_rpc::valid_digest(&digest) {
                return Err(
                    "BZ_SIGNATURE_CATALOG_DIGEST must be a lowercase SHA-256 digest".into(),
                );
            }
            url.set_path("/v1/lookup");
            CatalogPin::Static(digest)
        };
        let cluster_id =
            optional_var(env, "BZ_SIGNATURE_CLUSTER_ID").unwrap_or_else(|| "mainnet-beta".into());
        Ok(Some(Self {
            url: url.to_string(),
            token,
            catalog_pin,
            cluster_id,
        }))
    }

    async fn lookup(
        &self,
        params: &GetTransactionParams,
    ) -> std::result::Result<LookupResult, TransactionRpcError> {
        let headers = Headers::new();
        headers
            .set("Content-Type", "application/json")
            .map_err(locator_error)?;
        headers
            .set("Authorization", &format!("Bearer {}", self.token))
            .map_err(locator_error)?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            // Workerd supports manual/follow, but not the browser's error
            // mode. Manual plus the 200-only check never forwards this secret.
            .with_redirect(worker::RequestRedirect::Manual)
            .with_body(Some(JsValue::from_str(
                &json!({"signature": params.signature_text}).to_string(),
            )));
        let request = Request::new_with_init(&self.url, &init).map_err(locator_error)?;
        let controller = worker::AbortController::default();
        let signal = controller.signal();
        let max_bytes = match self.catalog_pin {
            CatalogPin::Static(_) => MAX_LOCATOR_BYTES,
            CatalogPin::Live(_) => MAX_LIVE_LOCATOR_BYTES,
        };
        let operation = async {
            let mut response = Fetch::Request(request)
                .send_with_signal(&signal)
                .await
                .map_err(locator_error)?;
            if response.status_code() != 200 {
                return Err(TransactionRpcError::unavailable(
                    "signature locator is unavailable",
                ));
            }
            let mut stream = response.stream().map_err(locator_error)?;
            let mut bytes = Vec::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(locator_error)?;
                if chunk.len() > max_bytes.saturating_sub(bytes.len()) {
                    return Err(TransactionRpcError::unavailable(
                        "signature locator response exceeds its size limit",
                    ));
                }
                bytes.extend(chunk);
            }
            self.parse_lookup(&bytes, &params.signature_text)
        };
        match future::select(
            Box::pin(operation),
            Box::pin(worker::Delay::from(Duration::from_secs(5))),
        )
        .await
        {
            future::Either::Left((result, _)) => result,
            future::Either::Right(_) => {
                controller.abort();
                Err(TransactionRpcError::unavailable(
                    "signature locator request timed out",
                ))
            }
        }
    }

    fn parse_lookup(
        &self,
        bytes: &[u8],
        signature: &str,
    ) -> std::result::Result<LookupResult, TransactionRpcError> {
        let invalid =
            || TransactionRpcError::unavailable("signature locator returned invalid JSON");
        match &self.catalog_pin {
            CatalogPin::Static(digest) => {
                let response: LocatorResponse =
                    serde_json::from_slice(bytes).map_err(|_| invalid())?;
                response.validate(signature, digest)?;
                Ok(LookupResult {
                    candidates: response
                        .candidate
                        .into_iter()
                        .map(|value| (value, None))
                        .collect(),
                    coverage_complete: response.coverage_complete,
                })
            }
            CatalogPin::Live(id) => {
                let response: LiveLocatorResponse =
                    serde_json::from_slice(bytes).map_err(|_| invalid())?;
                response.validate(signature, id)?;
                Ok(LookupResult {
                    candidates: response
                        .candidates
                        .into_iter()
                        .map(|value| (value.candidate(), Some(value.archive_prefix)))
                        .collect(),
                    coverage_complete: response.coverage_complete,
                })
            }
        }
    }
}

fn locator_error(_: worker::Error) -> TransactionRpcError {
    TransactionRpcError::unavailable("signature locator request failed")
}

fn rpc_error(error: TransactionRpcError) -> RpcError {
    RpcError {
        code: error.code,
        message: error.message,
    }
}

pub(super) async fn handle(
    source: &WorkerSource,
    request: &RpcRequest,
) -> std::result::Result<Value, RpcError> {
    let params = transaction_rpc::parse_params(request.params.as_ref()).map_err(rpc_error)?;
    let locator = source
        .signature_locator
        .as_ref()
        .ok_or_else(|| RpcError::internal("signature index is not configured"))?;
    let response = locator.lookup(&params).await.map_err(rpc_error)?;
    let mut failure = None;
    for (candidate, prefix) in response.candidates {
        let mut candidate_source = source.clone();
        if let Some(prefix) = prefix {
            if prefix != candidate_source.archive_prefix {
                // The optional native reader admits the configured Foundation
                // namespace. Other segment namespaces use the archive backend.
                candidate_source.native_reader = None;
            }
            candidate_source.archive_prefix = prefix;
            // This configuration binds a separate admitted resolution
            // generation. A live segment uses its own immutable archive.
            candidate_source.resolution = None;
        }
        match read_candidate(&candidate_source, &params, &candidate, &locator.cluster_id).await {
            Ok(Some(result)) => return Ok(result),
            Ok(None) => {}
            Err(error) if failure.is_none() => failure = Some(error),
            Err(_) => {}
        }
    }
    if let Some(error) = failure {
        return Err(error);
    }
    if response.coverage_complete {
        Ok(Value::Null)
    } else {
        Err(rpc_error(TransactionRpcError::incomplete()))
    }
}

async fn read_candidate(
    source: &WorkerSource,
    params: &GetTransactionParams,
    candidate: &transaction_rpc::Candidate,
    cluster_id: &str,
) -> std::result::Result<Option<Value>, RpcError> {
    verify_source(source, candidate, cluster_id)
        .await
        .map_err(rpc_error)?;
    let fetched = fetch_block(source, candidate.slot, AccessFetchMode::Full)
        .await
        .map_err(|error| RpcError::internal(format!("failed to read indexed block: {error}")))?
        .ok_or_else(|| {
            RpcError::internal("signature index points to an unavailable archive block")
        })?;
    if fetched.epoch != candidate.epoch {
        return Err(RpcError::internal(
            "signature index epoch does not match the archive block",
        ));
    }
    let Some((row, signatures, signature_index)) =
        find_exact_transaction(&fetched, &params.signature).map_err(RpcError::internal)?
    else {
        return Ok(None);
    };
    let mut message =
        decode_message(&fetched.block, &row, fetched.message_schema).map_err(RpcError::internal)?;
    let version = message_version_value(&message);
    transaction_rpc::check_version(&version, &params).map_err(rpc_error)?;
    let meta = decode_metadata(&fetched.block, &row, fetched.metadata_schema)
        .map_err(RpcError::internal)?;
    let access = match fetched.access.as_ref() {
        Some(FetchedAccess::Full(access)) => access,
        _ => return Err(RpcError::internal("transaction access data is unavailable")),
    };
    let mut resolver = Resolver::new(source, Some(access));
    vote_proof::resolve_message(
        &mut message,
        &mut resolver,
        transaction_signature_bytes(&fetched, &row, signature_index).map_err(RpcError::internal)?,
    )
    .await
    .map_err(RpcError::internal)?;
    let mut transaction = transaction_value(&mut resolver, &message, signatures, false)
        .await
        .map_err(RpcError::internal)?;
    if params.encoding == TransactionEncoding::Base64 {
        let bytes =
            transaction_rpc::encode_transaction(&transaction, &version).map_err(rpc_error)?;
        transaction = json!([BASE64.encode(bytes), "base64"]);
    }
    let meta = metadata_value(&mut resolver, meta.as_ref())
        .await
        .map_err(RpcError::internal)?;
    let mut result = json!({"slot": candidate.slot, "blockTime": rpc_block_time(fetched.block.header.block_time), "transaction": transaction, "meta": meta});
    if params.max_supported_version.is_some() {
        result["version"] = version;
    }
    Ok(Some(result))
}

async fn verify_source(
    source: &WorkerSource,
    candidate: &transaction_rpc::Candidate,
    cluster: &str,
) -> std::result::Result<(), TransactionRpcError> {
    let path = epoch_file(
        &source.archive_prefix,
        candidate.epoch,
        "archive-v2-generation.json",
    );
    let size = source
        .object_size(&path)
        .await
        .map_err(TransactionRpcError::unavailable)?
        .and_then(|size| usize::try_from(size).ok())
        .filter(|size| *size <= MAX_MANIFEST_BYTES)
        .ok_or_else(|| {
            TransactionRpcError::unavailable(
                "bound archive generation manifest is missing or too large",
            )
        })?;
    let bytes = source
        .get_cached_range(&path, 0, size)
        .await
        .map_err(TransactionRpcError::unavailable)?;
    let manifest = transaction_rpc::parse_manifest(&bytes, candidate, cluster)?;
    // The published prefix is immutable. Check exact object lengths without
    // loading or hashing epoch-sized objects in a request.
    futures_util::stream::iter(manifest.files.iter().map(|file| async move {
        let path = epoch_file(&source.archive_prefix, candidate.epoch, &file.name);
        let size = source
            .object_size(&path)
            .await
            .map_err(TransactionRpcError::unavailable)?;
        if size != Some(file.size) {
            return Err(TransactionRpcError::unavailable(
                "archive object length differs from the bound generation",
            ));
        }
        Ok(())
    }))
    .buffer_unordered(4)
    .try_collect::<Vec<_>>()
    .await?;
    Ok(())
}

fn find_exact_transaction(
    fetched: &FetchedHotBlock,
    signature: &[u8; 64],
) -> std::result::Result<Option<(ArchiveV2HotTxRow, Vec<String>, usize)>, String> {
    let access = fetched
        .access
        .as_ref()
        .ok_or_else(|| "indexed block has no signature access data".to_string())?;
    let bytes = access.signatures();
    let found = transaction_rpc::find_first_signature(
        fetched.block.tx_rows.iter().map(|row| row.signature_count),
        bytes,
        signature,
    )
    .map_err(|error| error.message)?;
    Ok(found.map(|(index, range)| {
        (
            fetched.block.tx_rows[index],
            bytes[range.clone()]
                .chunks_exact(64)
                .map(base58_bytes)
                .collect(),
            range.start / 64,
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(pin: CatalogPin) -> LocatorConfig {
        LocatorConfig {
            url: "https://locator.test".into(),
            token: "unused-test-token".into(),
            catalog_pin: pin,
            cluster_id: "mainnet-beta".into(),
        }
    }

    #[test]
    fn live_lookup_keeps_candidate_order_and_generation_prefixes() {
        let id = "a".repeat(64);
        let locator = config(CatalogPin::Live(id.clone()));
        let bytes = serde_json::to_vec(&json!({
            "schema_version":2,"signature":"requested","catalog_id":id,
            "catalog_digest":"b".repeat(64),"coverage_complete":false,
            "candidates":[
                {"epoch":1,"slot":432000,"archive_binding":"c".repeat(64),"archive_prefix":"live/first"},
                {"epoch":1,"slot":432001,"archive_binding":"d".repeat(64),"archive_prefix":"live/second"}
            ]
        })).unwrap();
        let result = locator.parse_lookup(&bytes, "requested").unwrap();
        assert_eq!(result.candidates.len(), 2);
        assert_eq!(result.candidates[0].0.slot, 432000);
        assert_eq!(result.candidates[0].1.as_deref(), Some("live/first"));
        assert_eq!(result.candidates[1].0.slot, 432001);
        assert_eq!(result.candidates[1].1.as_deref(), Some("live/second"));
        assert!(!result.coverage_complete);
        assert!(locator.parse_lookup(&bytes, "changed").is_err());
        assert!(
            config(CatalogPin::Static(id))
                .parse_lookup(&bytes, "requested")
                .is_err()
        );
    }

    #[test]
    fn static_lookup_keeps_exact_digest_pin_and_fixed_source_prefix() {
        let digest = "a".repeat(64);
        let locator = config(CatalogPin::Static(digest.clone()));
        let bytes = serde_json::to_vec(&json!({
            "schema_version":1,"signature":"requested","catalog_digest":digest,
            "candidate":{"epoch":1,"slot":432000,"archive_binding":"c".repeat(64)},
            "coverage_complete":false
        }))
        .unwrap();
        let result = locator.parse_lookup(&bytes, "requested").unwrap();
        assert_eq!(result.candidates.len(), 1);
        assert!(result.candidates[0].1.is_none());
        assert!(
            config(CatalogPin::Static("b".repeat(64)))
                .parse_lookup(&bytes, "requested")
                .is_err()
        );
        assert!(
            config(CatalogPin::Live(digest))
                .parse_lookup(&bytes, "requested")
                .is_err()
        );
    }
}
