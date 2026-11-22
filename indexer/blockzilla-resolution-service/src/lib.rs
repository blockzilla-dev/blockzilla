//! A read-only ID broker. No block-resolution result cache is used.
pub mod cache;
pub mod catalog;
pub mod direct;
pub mod http;
pub mod recent;

use anyhow::Result;
use blockzilla_get_block::foundation_protocol::{PendingLocatorV1, ResolveRequestV1};
use blockzilla_get_block::slot_resolution::ResolutionV1;

pub struct Resolved {
    pub resolution: ResolutionV1,
    pub pread_calls: u64,
    pub pread_bytes: u64,
}

/// Separate the immutable file catalog from HTTP and cache tests.
pub trait ResolutionCatalog: Send + Sync + 'static {
    fn source_prefix(&self) -> &str;
    fn generation(&self) -> &str;
    fn pending(&self, slot: u64) -> Result<Option<PendingLocatorV1>>;
    /// Read the admitted archived block hash without reading its payload.
    fn archived_blockhash(&self, _slot: u64) -> Result<Option<[u8; 32]>> {
        Ok(None)
    }
    fn resolve(&self, request: &ResolveRequestV1) -> Result<Resolved>;
}

impl ResolutionCatalog for catalog::Catalog {
    fn source_prefix(&self) -> &str {
        self.source_prefix()
    }
    fn generation(&self) -> &str {
        self.generation()
    }
    fn pending(&self, slot: u64) -> Result<Option<PendingLocatorV1>> {
        self.pending(slot)
    }
    fn archived_blockhash(&self, slot: u64) -> Result<Option<[u8; 32]>> {
        self.archived_blockhash(slot)
    }
    fn resolve(&self, request: &ResolveRequestV1) -> Result<Resolved> {
        self.resolve(request)
    }
}
