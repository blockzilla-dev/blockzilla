use axum::body::Bytes;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

// The owner deferred Foundation RAM caching. Enable only with an explicit budget.
pub const DEFAULT_CACHE_BYTES: usize = 0;
const MAX_CACHE_ENTRIES: usize = 16_384;

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    pub generation: String,
    pub request_sha256: [u8; 32],
}

pub struct Payload {
    pub body: Bytes,
    pub sha256: String,
    pub locator: String,
}

impl Payload {
    fn charge(&self, key: &Key) -> usize {
        // Include both map keys, Arc/header allocations and map-node allowance.
        self.body.len() + self.sha256.len() + self.locator.len() + key.generation.len() * 2 + 512
    }
}

struct Entry {
    value: Arc<Payload>,
    tick: u64,
    charge: usize,
}

#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub bytes: usize,
    pub entries: usize,
    pub limit_bytes: usize,
}

/// A bounded LRU. No queues grow with cache hits, and no cache entry is written to disk.
pub struct Cache {
    entries: HashMap<Key, Entry>,
    age: BTreeMap<u64, Key>,
    tick: u64,
    stats: CacheStats,
}

impl Cache {
    pub fn new(limit_bytes: usize) -> Self {
        Self {
            entries: HashMap::new(),
            age: BTreeMap::new(),
            tick: 0,
            stats: CacheStats {
                limit_bytes,
                ..CacheStats::default()
            },
        }
    }

    pub fn get(&mut self, key: &Key) -> Option<Arc<Payload>> {
        let Some(entry) = self.entries.get_mut(key) else {
            self.stats.misses += 1;
            return None;
        };
        self.age.remove(&entry.tick);
        self.tick += 1;
        entry.tick = self.tick;
        self.age.insert(self.tick, key.clone());
        self.stats.hits += 1;
        Some(entry.value.clone())
    }

    pub fn insert(&mut self, key: Key, value: Arc<Payload>) {
        let charge = value.charge(&key);
        if self.stats.limit_bytes == 0 || charge > self.stats.limit_bytes {
            return;
        }
        if let Some(old) = self.entries.remove(&key) {
            self.age.remove(&old.tick);
            self.stats.bytes -= old.charge;
        }
        while self.stats.bytes + charge > self.stats.limit_bytes
            || self.entries.len() >= MAX_CACHE_ENTRIES
        {
            let Some((_, oldest)) = self.age.pop_first() else {
                break;
            };
            if let Some(old) = self.entries.remove(&oldest) {
                self.stats.bytes -= old.charge;
                self.stats.evictions += 1;
            }
        }
        self.tick += 1;
        self.age.insert(self.tick, key.clone());
        self.entries.insert(
            key,
            Entry {
                value,
                tick: self.tick,
                charge,
            },
        );
        self.stats.bytes += charge;
    }

    pub fn stats(&self) -> CacheStats {
        CacheStats {
            entries: self.entries.len(),
            ..self.stats
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8, generation: &str) -> Key {
        Key {
            generation: generation.into(),
            request_sha256: [n; 32],
        }
    }
    fn value(n: u8) -> Arc<Payload> {
        Arc::new(Payload {
            body: Bytes::from(vec![n; 40]),
            sha256: "a".repeat(64),
            locator: "b".repeat(32),
        })
    }

    #[test]
    fn bounded_lru_distinguishes_generation_and_request_and_reuses_bytes() {
        let a = key(1, "first");
        let b = key(2, "first");
        let c = key(3, "first");
        let v = value(1);
        let one = v.charge(&a);
        let mut cache = Cache::new(one * 2);
        cache.insert(a.clone(), v.clone());
        cache.insert(b.clone(), value(2));
        assert!(Arc::ptr_eq(&cache.get(&a).unwrap(), &v));
        assert!(cache.get(&key(1, "other")).is_none());
        cache.insert(c.clone(), value(3));
        assert!(cache.get(&b).is_none());
        assert!(cache.get(&a).is_some());
        assert!(cache.get(&c).is_some());
        assert_eq!(cache.stats().evictions, 1);
        assert!(cache.stats().bytes <= cache.stats().limit_bytes);
        for _ in 0..100_000 {
            cache.get(&a);
        }
        assert_eq!(cache.age.len(), 2);
    }

    #[test]
    fn disabled_or_oversized_entries_are_never_admitted_and_replace_is_bounded() {
        let k = key(1, "g");
        let v = value(1);
        for limit in [0, v.charge(&k) - 1] {
            let mut cache = Cache::new(limit);
            cache.insert(k.clone(), v.clone());
            assert!(cache.get(&k).is_none());
            assert_eq!(cache.stats().bytes, 0);
        }
        let mut cache = Cache::new(v.charge(&k));
        cache.insert(k.clone(), v.clone());
        cache.insert(k.clone(), value(2));
        assert_eq!(cache.stats().entries, 1);
        assert_eq!(cache.stats().evictions, 0);
        assert_eq!(cache.get(&k).unwrap().body[0], 2);
    }
}
