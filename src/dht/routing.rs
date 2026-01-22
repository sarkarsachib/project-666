use crate::dht::bucket::{bucket_index, BucketEntry, KBucket};
use crate::dht::error::Result;
use crate::types::Address;
use core::cmp::Ordering;

/// XOR-distance between two 128-bit addresses.
pub fn xor_distance(a: &Address, b: &Address) -> [u8; 16] {
    let mut result = [0u8; 16];
    for i in 0..16 {
        result[i] = a.as_bytes()[i] ^ b.as_bytes()[i];
    }
    result
}

/// Compare XOR distances in big-endian order (most significant byte first).
pub fn compare_distance(a: &[u8; 16], b: &[u8; 16]) -> Ordering {
    for i in 0..16 {
        if a[i] != b[i] {
            return a[i].cmp(&b[i]);
        }
    }
    Ordering::Equal
}

#[derive(Debug, Clone)]
pub struct RoutingTable {
    my_id: Address,
    k: usize,
}

impl RoutingTable {
    pub fn new(my_id: Address, k: usize) -> Self {
        Self { my_id, k }
    }

    pub fn add_peer(&self, buckets: &mut [KBucket], entry: BucketEntry) -> Result<()> {
        let idx = bucket_index(&self.my_id, &entry.address);
        buckets[idx].add_entry(entry)
    }

    pub fn remove_peer(&self, buckets: &mut [KBucket], address: &Address) {
        let idx = bucket_index(&self.my_id, address);
        buckets[idx].remove_entry(address);
    }

    pub fn find_closest(&self, buckets: &[KBucket], target: &Address, count: usize) -> Vec<Address> {
        let mut all = Vec::new();
        for b in buckets {
            for e in &b.entries {
                if e.address != self.my_id {
                    all.push(e.address);
                }
            }
        }

        all.sort_by(|a, b| {
            let da = xor_distance(a, target);
            let db = xor_distance(b, target);
            compare_distance(&da, &db)
        });

        all.dedup();
        all.truncate(count);
        all
    }

    pub fn all_peers(&self, buckets: &[KBucket]) -> Vec<Address> {
        let mut out = Vec::new();
        for b in buckets {
            for e in &b.entries {
                if e.address != self.my_id {
                    out.push(e.address);
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    pub fn k(&self) -> usize {
        self.k
    }
}
