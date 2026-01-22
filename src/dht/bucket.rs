use crate::dht::error::{DHTError, Result};
use crate::dht::routing::{compare_distance, xor_distance};
use crate::dht::now_secs;
use crate::types::Address;
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct KBucket {
    pub bucket_index: usize,
    pub entries: Vec<BucketEntry>,
    pub last_updated: u64,
    pub k: usize,
}

#[derive(Debug, Clone)]
pub struct BucketEntry {
    pub address: Address,
    pub public_key: [u8; 32],
    pub socket: SocketAddr,
    pub last_seen: u64,
    pub reliability: f32,
    pub latency_ms: u32,
}

impl KBucket {
    pub fn new(bucket_index: usize, k: usize) -> Self {
        Self {
            bucket_index,
            entries: Vec::new(),
            last_updated: now_secs(),
            k,
        }
    }

    pub fn add_entry(&mut self, entry: BucketEntry) -> Result<()> {
        self.last_updated = now_secs();

        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.address == entry.address)
        {
            *existing = entry;
            return Ok(());
        }

        if self.entries.len() >= self.k {
            return Err(DHTError::BucketFull);
        }

        self.entries.push(entry);
        Ok(())
    }

    pub fn remove_entry(&mut self, address: &Address) {
        self.entries.retain(|e| &e.address != address);
        self.last_updated = now_secs();
    }

    pub fn update_entry(&mut self, address: &Address, latency_ms: u32) -> Result<()> {
        self.last_updated = now_secs();
        let now = now_secs();
        let entry = self
            .entries
            .iter_mut()
            .find(|e| &e.address == address)
            .ok_or(DHTError::UnknownPeer)?;

        entry.last_seen = now;
        entry.latency_ms = latency_ms;
        entry.reliability = (entry.reliability + 0.05).min(1.0);
        Ok(())
    }

    pub fn get_entry(&self, address: &Address) -> Option<&BucketEntry> {
        self.entries.iter().find(|e| &e.address == address)
    }

    pub fn get_all_entries(&self) -> &[BucketEntry] {
        &self.entries
    }

    pub fn is_full(&self) -> bool {
        self.entries.len() >= self.k
    }

    pub fn needs_refresh(&self, timeout_seconds: u64) -> bool {
        now_secs().saturating_sub(self.last_updated) >= timeout_seconds
    }

    pub fn sort_by_distance(&mut self, target: &Address) {
        self.entries.sort_by(|a, b| {
            let da = xor_distance(&a.address, target);
            let db = xor_distance(&b.address, target);
            compare_distance(&da, &db)
        });
    }
}

/// Determine which bucket a peer belongs to (first differing bit position).
pub fn bucket_index(my_id: &Address, peer_id: &Address) -> usize {
    let xor = xor_distance(my_id, peer_id);
    for i in 0..128 {
        if (xor[i / 8] & (0x80 >> (i % 8))) != 0 {
            return core::cmp::min(i, 159);
        }
    }
    159
}
