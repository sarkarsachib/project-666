use crate::dht::error::Result;
use crate::dht::now_secs;
use crate::types::Address;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct DHTCache {
    entries: HashMap<Address, CacheEntry>,
    max_entries: usize,
    eviction_policy: EvictionPolicy,
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub value: Vec<u8>,
    pub inserted_at: u64,
    pub accessed_at: u64,
    pub access_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionPolicy {
    LRU,
    LFU,
    TTL,
}

impl DHTCache {
    pub fn new(max_entries: usize, policy: EvictionPolicy) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            eviction_policy: policy,
        }
    }

    pub fn get(&mut self, key: &Address) -> Option<Vec<u8>> {
        let now = now_secs();
        let entry = self.entries.get_mut(key)?;
        entry.accessed_at = now;
        entry.access_count = entry.access_count.saturating_add(1);
        Some(entry.value.clone())
    }

    pub fn insert(&mut self, key: Address, value: Vec<u8>) -> Result<()> {
        let now = now_secs();
        self.entries.insert(
            key,
            CacheEntry {
                value,
                inserted_at: now,
                accessed_at: now,
                access_count: 0,
            },
        );
        self.evict_if_needed();
        Ok(())
    }

    pub fn invalidate(&mut self, key: &Address) {
        self.entries.remove(key);
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn evict_if_needed(&mut self) {
        if self.max_entries == 0 {
            self.entries.clear();
            return;
        }

        while self.entries.len() > self.max_entries {
            let victim = match self.eviction_policy {
                EvictionPolicy::LRU | EvictionPolicy::TTL => self
                    .entries
                    .iter()
                    .min_by_key(|(_, v)| v.accessed_at)
                    .map(|(k, _)| *k),
                EvictionPolicy::LFU => self
                    .entries
                    .iter()
                    .min_by_key(|(_, v)| (v.access_count, v.accessed_at))
                    .map(|(k, _)| *k),
            };

            if let Some(k) = victim {
                self.entries.remove(&k);
            } else {
                break;
            }
        }
    }
}
