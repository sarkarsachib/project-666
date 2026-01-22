use crate::dht::now_secs;
use crate::types::{Address, SystemDescriptor};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct DescriptorCache {
    entries: HashMap<Address, CachedDescriptor>,
    ttl: u64,
    max_entries: usize,
}

#[derive(Debug, Clone)]
pub struct CachedDescriptor {
    pub descriptor: SystemDescriptor,
    pub cached_at: u64,
    pub expires_at: u64,
    pub source_node: Address,
    pub replica_count: u8,
}

impl DescriptorCache {
    pub fn new(ttl: u64, max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            ttl,
            max_entries,
        }
    }

    pub fn get(&self, address: &Address) -> Option<&CachedDescriptor> {
        let entry = self.entries.get(address)?;
        if now_secs() >= entry.expires_at {
            return None;
        }
        Some(entry)
    }

    pub fn insert(&mut self, address: Address, descriptor: SystemDescriptor, source: Address) {
        let cached_at = now_secs();
        let expires_at = cached_at.saturating_add(self.ttl);
        let cd = CachedDescriptor {
            descriptor,
            cached_at,
            expires_at,
            source_node: source,
            replica_count: 1,
        };
        self.entries.insert(address, cd);

        while self.entries.len() > self.max_entries {
            if let Some(victim) = self
                .entries
                .iter()
                .min_by_key(|(_, v)| v.cached_at)
                .map(|(k, _)| *k)
            {
                self.entries.remove(&victim);
            } else {
                break;
            }
        }
    }

    pub fn invalidate(&mut self, address: &Address) {
        self.entries.remove(address);
    }

    pub fn prune_expired(&mut self) -> usize {
        let now = now_secs();
        let before = self.entries.len();
        self.entries.retain(|_, v| now < v.expires_at);
        before.saturating_sub(self.entries.len())
    }
}
