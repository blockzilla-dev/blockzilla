//! Sparse registry pages shared by projections of the same pinned generation.

use super::{
    ArchiveReader, CompactV2InstructionSourceError, CompactV2InstructionSourceResult, ContextIo,
    REGISTRY_KEY_BYTES, RangeSource, ScanRequest, request_needs_registry,
};
use std::sync::{Arc, Mutex};

const KEYS_PER_PAGE: usize = 512;
const RECENT_PAGES: usize = 16;
const MAX_SHARED_PAGES: usize = 1024;
const PAGE_BYTES: usize = KEYS_PER_PAGE * REGISTRY_KEY_BYTES;

#[derive(Debug)]
struct RegistryPage {
    number: usize,
    keys: Vec<[u8; REGISTRY_KEY_BYTES]>,
}

/// One bounded cache per scan. A slot lock covers its first read so simultaneous
/// misses for one page use one positional read. Separate slots read in parallel.
#[derive(Debug)]
pub(super) struct SharedRegistryPages {
    slots: Box<[Mutex<Option<Arc<RegistryPage>>>]>,
}

impl SharedRegistryPages {
    pub(super) fn for_scan<S: RangeSource>(
        reader: &ArchiveReader<S>,
        request: &ScanRequest,
    ) -> Option<Arc<Self>> {
        if !request_needs_registry(request)
            || !reader.source().prefers_small_ranges()
            || reader.registry_entries() == 0
        {
            return None;
        }
        let pages = (reader.registry_entries() as usize).div_ceil(KEYS_PER_PAGE);
        let slots = (0..pages.min(MAX_SHARED_PAGES))
            .map(|_| Mutex::new(None))
            .collect();
        Some(Arc::new(Self { slots }))
    }

    pub(super) fn retained_key_bytes(&self, resolvers: usize) -> u64 {
        // Recent pages can outlive eviction from the shared slots.
        ((self.slots.len() + resolvers * RECENT_PAGES) * PAGE_BYTES) as u64
    }

    fn page<S: RangeSource>(
        &self,
        reader: &ArchiveReader<S>,
        number: usize,
        io: &mut ContextIo,
    ) -> CompactV2InstructionSourceResult<Arc<RegistryPage>> {
        let mut slot = self.slots[number % self.slots.len()].lock().map_err(|_| {
            CompactV2InstructionSourceError::Invalid("registry page cache is poisoned".into())
        })?;
        if let Some(page) = slot.as_ref().filter(|page| page.number == number) {
            return Ok(Arc::clone(page));
        }
        // The caller validated the ID against this reader's registry length.
        let first_key = number * KEYS_PER_PAGE;
        let count = (reader.registry_entries() as usize - first_key).min(KEYS_PER_PAGE);
        // A partial read must leave the slot empty. The removed page can be
        // filled in place only when no other resolver holds a reference.
        let mut recycled = slot.take();
        if recycled.as_mut().and_then(Arc::get_mut).is_none() {
            recycled = Some(Arc::new(RegistryPage {
                number,
                keys: Vec::new(),
            }));
        }
        let mut page = recycled.expect("page supplied");
        let page_data = Arc::get_mut(&mut page).expect("page is uniquely owned");
        page_data.keys.resize(count, [0; REGISTRY_KEY_BYTES]);
        let offset = first_key as u64 * REGISTRY_KEY_BYTES as u64;
        reader.source().read_range_into_slice(
            crate::manifest::REGISTRY_FILE,
            offset,
            page_data.keys.as_flattened_mut(),
        )?;
        io.record(page_data.keys.len() * REGISTRY_KEY_BYTES)?;
        page_data.number = number;
        *slot = Some(Arc::clone(&page));
        Ok(page)
    }
}

/// Each resolver keeps its most recent page references locally. Cache hits
/// here need no locks and never copy a page between workers.
#[derive(Debug)]
pub(super) struct RegistryPageResolver {
    shared: Arc<SharedRegistryPages>,
    recent: [Option<Arc<RegistryPage>>; RECENT_PAGES],
}

impl RegistryPageResolver {
    pub(super) fn new(shared: Arc<SharedRegistryPages>) -> Self {
        Self {
            shared,
            recent: Default::default(),
        }
    }

    pub(super) fn resolve<S: RangeSource>(
        &mut self,
        reader: &ArchiveReader<S>,
        id: u32,
        io: &mut ContextIo,
    ) -> CompactV2InstructionSourceResult<[u8; REGISTRY_KEY_BYTES]> {
        let key = (id - 1) as usize;
        let number = key / KEYS_PER_PAGE;
        let slot = &mut self.recent[number % RECENT_PAGES];
        if let Some(page) = slot.as_ref().filter(|page| page.number == number) {
            return Ok(page.keys[key % KEYS_PER_PAGE]);
        }
        // Give the shared cache a chance to reuse this worker's old page.
        *slot = None;
        let page = self.shared.page(reader, number, io)?;
        let resolved = page.keys[key % KEYS_PER_PAGE];
        *slot = Some(page);
        Ok(resolved)
    }
}
