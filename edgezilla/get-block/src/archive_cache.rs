//! A byte-bounded cache for immutable archive data, never authentication state.

use std::collections::VecDeque;

pub(crate) struct ArchiveByteCache {
    entries: VecDeque<(String, Vec<u8>)>,
    bytes: usize,
    limit: usize,
    entry_limit: usize,
}

impl ArchiveByteCache {
    pub(crate) fn new(limit: usize, entry_limit: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            bytes: 0,
            limit,
            entry_limit,
        }
    }

    pub(crate) fn get(&mut self, key: &str) -> Option<Vec<u8>> {
        let index = self
            .entries
            .iter()
            .position(|(candidate, _)| candidate == key)?;
        let entry = self.entries.remove(index)?;
        let value = entry.1.clone();
        self.entries.push_back(entry);
        Some(value)
    }

    pub(crate) fn insert(&mut self, key: String, bytes: Vec<u8>) {
        let cost = key.len().saturating_add(bytes.len());
        if cost > self.limit || self.entry_limit == 0 {
            return;
        }
        if let Some(index) = self
            .entries
            .iter()
            .position(|(candidate, _)| candidate == &key)
        {
            let (key, value) = self.entries.remove(index).expect("found cache entry");
            self.bytes -= key.len() + value.len();
        }
        while self.bytes.saturating_add(cost) > self.limit || self.entries.len() >= self.entry_limit
        {
            let Some((key, value)) = self.entries.pop_front() else {
                break;
            };
            self.bytes -= key.len() + value.len();
        }
        self.bytes += cost;
        self.entries.push_back((key, bytes));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_bytes_and_evicts_the_least_recent_entry() {
        let mut cache = ArchiveByteCache::new(10, 3);
        cache.insert("a".into(), vec![1; 3]);
        cache.insert("b".into(), vec![2; 3]);
        assert_eq!(cache.get("a"), Some(vec![1; 3]));
        cache.insert("c".into(), vec![3; 3]);
        assert!(cache.get("b").is_none());
        assert!(cache.bytes <= 10);
        assert!(cache.get("a").is_some());
    }

    #[test]
    fn bounds_entry_count_and_replaces_without_duplicate_cost() {
        let mut cache = ArchiveByteCache::new(100, 1);
        cache.insert("a".into(), vec![1]);
        cache.insert("a".into(), vec![2]);
        assert_eq!(cache.bytes, 2);
        assert_eq!(cache.get("a"), Some(vec![2]));
        cache.insert("b".into(), vec![3]);
        assert!(cache.get("a").is_none());
        cache.insert("oversize".into(), vec![0; 100]);
        assert_eq!(cache.get("b"), Some(vec![3]));
    }
}
