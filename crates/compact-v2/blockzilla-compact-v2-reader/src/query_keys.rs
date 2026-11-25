//! Resolve query keys once so scans can compare compact registry IDs.
use std::cell::Cell;
use std::collections::HashMap;

use crate::RangeSource;
use anyhow::{Result, ensure};
use blockzilla_archive_v2::{
    ARCHIVE_V2_PUBKEY_REGISTRY_FILE as REGISTRY, ARCHIVE_V2_PUBKEY_REGISTRY_INDEX_FILE as INDEX,
};
use blockzilla_model::{InstructionDataRequirement, ScanRequest, TokenBalanceRequirement};
use blockzilla_primitives::CompactPubkey;
use blockzilla_registry::{registry::KeyIndexRangeSource, registry::RangeBackedKeyIndex};

#[derive(Debug, Default)]
pub struct BoundQueryKeys {
    keys: Vec<([u8; 32], Option<u32>)>,
    pub read_calls: u64,
    pub read_bytes: u64,
}

struct IndexSource<'a> {
    source: &'a dyn RangeSource,
    calls: Cell<u64>,
    bytes: Cell<u64>,
}

impl IndexSource<'_> {
    fn read(&self, object: &str, offset: u64, length: usize) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.read_into(object, offset, length, &mut bytes)?;
        Ok(bytes)
    }

    fn read_into(
        &self,
        object: &str,
        offset: u64,
        length: usize,
        bytes: &mut Vec<u8>,
    ) -> Result<()> {
        self.source.read_range_into(object, offset, length, bytes)?;
        ensure!(bytes.len() == length, "short registry read");
        self.calls.set(self.calls.get() + 1);
        self.bytes.set(self.bytes.get() + length as u64);
        Ok(())
    }
}

impl KeyIndexRangeSource for &IndexSource<'_> {
    fn object_len(&self) -> Result<u64> {
        self.source
            .size(INDEX)?
            .ok_or_else(|| anyhow::anyhow!("missing registry index"))
    }
    fn read_exact_range(&self, offset: u64, length: usize) -> Result<Vec<u8>> {
        self.read(INDEX, offset, length)
    }
}

impl BoundQueryKeys {
    fn targets(request: &ScanRequest) -> Vec<[u8; 32]> {
        let mut targets = Vec::new();
        for requirement in [&request.instruction_programs, &request.instruction_data] {
            if let InstructionDataRequirement::Programs(keys) = requirement {
                targets.extend_from_slice(keys);
            }
        }
        if let TokenBalanceRequirement::Mints(keys) = &request.token_balances {
            targets.extend_from_slice(keys);
        }
        targets.extend(request.required_signer);
        targets
    }

    pub fn covers(&self, request: &ScanRequest) -> bool {
        Self::targets(request)
            .iter()
            .all(|key| self.registry_id(key).is_some())
    }

    /// Outer `None` means the key was not requested. Inner `None` means the
    /// key has no registry ID in the bound result.
    pub fn registry_id(&self, key: &[u8; 32]) -> Option<Option<u32>> {
        self.keys
            .binary_search_by(|(target, _)| target.cmp(key))
            .ok()
            .map(|position| self.keys[position].1)
    }

    /// Iterate over the unique requested keys in byte order and their IDs.
    pub fn bindings(&self) -> impl Iterator<Item = ([u8; 32], Option<u32>)> + '_ {
        self.keys.iter().copied()
    }

    pub fn bind(source: &dyn RangeSource, entries: u32, request: &ScanRequest) -> Result<Self> {
        Self::bind_keys(source, entries, Self::targets(request))
    }

    pub fn bind_with_registry(
        source: &dyn RangeSource,
        entries: u32,
        request: &ScanRequest,
        registry: Option<&[u8]>,
    ) -> Result<Self> {
        Self::bind_key_set(source, entries, Self::targets(request), registry)
    }

    /// Resolve arbitrary keys against the admitted registry in `source`.
    ///
    /// `entries` is the admitted number of 32-byte rows in `registry.bin`.
    /// When `registry.mphf` is present, this method reads the range-backed
    /// index and compares every positive result with its complete registry row.
    /// An index miss establishes absence only if the caller has admitted the
    /// index as a complete mapping of that same registry. When no index exists,
    /// this method scans the registry once with a reusable bounded buffer.
    pub fn bind_keys(
        source: &dyn RangeSource,
        entries: u32,
        keys: impl IntoIterator<Item = [u8; 32]>,
    ) -> Result<Self> {
        Self::bind_key_set(source, entries, keys, None)
    }

    fn bind_key_set(
        source: &dyn RangeSource,
        entries: u32,
        keys: impl IntoIterator<Item = [u8; 32]>,
        registry: Option<&[u8]>,
    ) -> Result<Self> {
        let mut targets: Vec<_> = keys.into_iter().collect();
        targets.sort_unstable();
        targets.dedup();
        let mut result = Self {
            keys: targets.into_iter().map(|key| (key, None)).collect(),
            ..Self::default()
        };
        if result.keys.is_empty() || entries == 0 {
            return Ok(result);
        }
        if let Some(bytes) = registry {
            ensure!(
                bytes.len() as u64 == u64::from(entries) * 32,
                "registry size mismatch"
            );
            let positions = result.key_positions();
            result.record_registry_matches(bytes, 0, positions.as_ref())?;
            return Ok(result);
        }
        let input = IndexSource {
            source,
            calls: Cell::new(0),
            bytes: Cell::new(0),
        };
        if source.size(INDEX)?.is_some() {
            let index = RangeBackedKeyIndex::load(&input)?;
            ensure!(
                index.len() == entries as usize,
                "registry index entry count mismatch"
            );
            let mut row = Vec::new();
            for (key, id) in &mut result.keys {
                *id = index.lookup(key)?;
                if let Some(value) = *id {
                    ensure!(
                        value > 0 && value <= entries,
                        "registry index ID out of range"
                    );
                    input.read_into(REGISTRY, u64::from(value - 1) * 32, 32, &mut row)?;
                    ensure!(row.as_slice() == key, "registry index key mismatch");
                }
            }
        } else {
            let positions = result.key_positions();
            let size = u64::from(entries) * 32;
            let mut offset = 0;
            let mut bytes = Vec::new();
            while offset < size {
                let length = (size - offset).min(4 << 20) as usize;
                input.read_into(REGISTRY, offset, length, &mut bytes)?;
                result.record_registry_matches(&bytes, offset / 32, positions.as_ref())?;
                offset += length as u64;
            }
        }
        result.read_calls = input.calls.get();
        result.read_bytes = input.bytes.get();
        Ok(result)
    }

    fn key_positions(&self) -> Option<HashMap<[u8; 32], usize>> {
        (self.keys.len() > 1).then(|| {
            self.keys
                .iter()
                .enumerate()
                .map(|(position, (key, _))| (*key, position))
                .collect()
        })
    }

    fn record_registry_matches(
        &mut self,
        bytes: &[u8],
        first_row: u64,
        positions: Option<&HashMap<[u8; 32], usize>>,
    ) -> Result<()> {
        for (row, key) in bytes.as_chunks::<32>().0.iter().enumerate() {
            let position = match positions {
                Some(positions) => positions.get(key).copied(),
                None => (self.keys[0].0 == *key).then_some(0),
            };
            if let Some(position) = position {
                let id = &mut self.keys[position].1;
                ensure!(id.is_none(), "duplicate query key in registry");
                *id = Some((first_row + row as u64 + 1) as u32);
            }
        }
        Ok(())
    }

    pub fn matches(&self, reference: CompactPubkey, key: &[u8; 32]) -> bool {
        match reference {
            CompactPubkey::Raw(raw) => &raw == key,
            CompactPubkey::Id(id) => self.registry_id(key) == Some(Some(id)),
        }
    }

    pub fn selected(&self, reference: CompactPubkey, keys: &[[u8; 32]]) -> Option<[u8; 32]> {
        keys.iter()
            .find(|key| self.matches(reference, key))
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SourceError, SourceResult};
    use std::sync::atomic::{AtomicU64, Ordering};

    struct MemoryRegistry {
        registry: Vec<u8>,
        index: Option<Vec<u8>>,
        registry_read_bytes: AtomicU64,
    }

    impl MemoryRegistry {
        fn new(rows: &[[u8; 32]]) -> Self {
            Self {
                registry: rows.as_flattened().to_vec(),
                index: None,
                registry_read_bytes: AtomicU64::new(0),
            }
        }

        #[cfg(not(target_arch = "wasm32"))]
        fn with_index(mut self, rows: &[[u8; 32]]) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join(INDEX);
            blockzilla_registry::registry::KeyIndex::build_from_slice(rows)
                .write(&path)
                .unwrap();
            self.index = Some(std::fs::read(path).unwrap());
            self
        }

        fn object(&self, object: &str) -> Option<&[u8]> {
            match object {
                REGISTRY => Some(&self.registry),
                INDEX => self.index.as_deref(),
                _ => None,
            }
        }
    }

    impl RangeSource for MemoryRegistry {
        fn size(&self, object: &str) -> SourceResult<Option<u64>> {
            Ok(self.object(object).map(|bytes| bytes.len() as u64))
        }

        fn read_range(&self, object: &str, offset: u64, length: usize) -> SourceResult<Vec<u8>> {
            let bytes = self
                .object(object)
                .ok_or_else(|| SourceError::NotFound(object.to_owned()))?;
            let end = offset
                .checked_add(length as u64)
                .filter(|end| *end <= bytes.len() as u64);
            let end = end.ok_or_else(|| SourceError::OutOfBounds {
                object: object.to_owned(),
                offset,
                length,
                size: bytes.len() as u64,
            })?;
            if object == REGISTRY {
                self.registry_read_bytes
                    .fetch_add(length as u64, Ordering::Relaxed);
            }
            Ok(bytes[offset as usize..end as usize].to_vec())
        }
    }

    #[test]
    fn binds_unique_keys_across_registry_ranges() {
        let first = [1; 32];
        let last = [2; 32];
        let missing = [3; 32];
        let filler = [0; 32];
        let mut rows: Vec<_> = (0..=(4u32 << 20) / 32)
            .map(|position| {
                let mut key = filler;
                key[..4].copy_from_slice(&position.to_le_bytes());
                key
            })
            .collect();
        rows[1] = first;
        *rows.last_mut().unwrap() = last;
        let source = MemoryRegistry::new(&rows);
        let result =
            BoundQueryKeys::bind_keys(&source, rows.len() as u32, [missing, last, first, first])
                .unwrap();

        assert_eq!(
            result.bindings().collect::<Vec<_>>(),
            vec![
                (first, Some(2)),
                (last, Some(rows.len() as u32)),
                (missing, None)
            ]
        );
        assert_eq!(result.registry_id(&missing), Some(None));
        assert_eq!(result.registry_id(&filler), None);
        assert!(result.matches(CompactPubkey::Id(2), &first));
        assert!(result.matches(CompactPubkey::raw(missing), &missing));
        assert_eq!(result.read_calls, 2);
        assert_eq!(result.read_bytes, (4 << 20) + 32);
    }

    #[test]
    fn exhaustive_registry_binding_rejects_duplicate_requested_rows() {
        let repeated = [1; 32];
        let source = MemoryRegistry::new(&[repeated, repeated]);
        let error = BoundQueryKeys::bind_keys(&source, 2, [repeated]).unwrap_err();
        assert_eq!(error.to_string(), "duplicate query key in registry");
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn indexed_binding_reads_only_complete_positive_registry_rows() {
        let hit = [1; 32];
        let missing = [2; 32];
        let rows = [[0; 32], hit, [3; 32]];
        let source = MemoryRegistry::new(&rows).with_index(&rows);
        let result = BoundQueryKeys::bind_keys(&source, 3, [missing, hit]).unwrap();

        assert_eq!(
            result.bindings().collect::<Vec<_>>(),
            [(hit, Some(2)), (missing, None)]
        );
        assert_eq!(source.registry_read_bytes.load(Ordering::Relaxed), 32);
        assert!(result.read_calls > 1);
        assert!(result.read_bytes > 32);
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn indexed_binding_rejects_a_result_from_the_wrong_registry() {
        let first = [1; 32];
        let second = [2; 32];
        let source = MemoryRegistry::new(&[first, second]).with_index(&[second, first]);
        let error = BoundQueryKeys::bind_keys(&source, 2, [first]).unwrap_err();
        assert_eq!(error.to_string(), "registry index key mismatch");
    }
}
