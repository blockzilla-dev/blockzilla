//! Small source routes only. Complete ID resolutions stay on Foundation.
use super::*;
use crate::foundation_protocol::PendingLocatorV1;
const MAX_ROUTE_BYTES: usize = 4096;

fn key(source: &WorkerSource, slot: u64) -> Option<String> {
    let config = source.foundation_lookup.as_ref()?;
    source.range_cache_key(
        &format!("foundation-route-v1\0{}", config.cache_identity()),
        slot,
        0,
    )
}

pub(super) async fn cached_route(source: &WorkerSource, slot: u64) -> Option<PendingLocatorV1> {
    let key = key(source, slot)?;
    let config = source.foundation_lookup.as_ref()?;
    let memory = ARCHIVE_BYTES.with(|cache| cache.borrow_mut().get(&key));
    let bytes = if let Some(bytes) = memory {
        source.storage_metrics.memory_hit();
        bytes
    } else {
        let mut response = Cache::default().get(key.clone(), false).await.ok()??;
        let length = response
            .headers()
            .get("Content-Length")
            .ok()??
            .parse::<usize>()
            .ok()?;
        if response.status_code() != 200 || length == 0 || length > MAX_ROUTE_BYTES {
            return None;
        }
        let bytes = response.bytes().await.ok()?;
        if bytes.len() != length {
            return None;
        }
        source.storage_metrics.edge_hit();
        ARCHIVE_BYTES.with(|cache| cache.borrow_mut().insert(key, bytes.clone()));
        bytes
    };
    if bytes.len() > MAX_ROUTE_BYTES {
        return None;
    }
    let route: PendingLocatorV1 = serde_json::from_slice(&bytes).ok()?;
    route
        .validate(&source.archive_prefix, config.generation(), slot)
        .ok()?;
    Some(route)
}

pub(super) fn cache_route(source: &WorkerSource, slot: u64, route: &PendingLocatorV1) {
    let Some(config) = &source.foundation_lookup else {
        return;
    };
    if route
        .validate(&source.archive_prefix, config.generation(), slot)
        .is_err()
    {
        return;
    }
    if let (Some(key), Ok(bytes)) = (key(source, slot), serde_json::to_vec(route)) {
        if bytes.len() <= MAX_ROUTE_BYTES {
            source.cache_bytes(key, &bytes);
        }
    }
}
