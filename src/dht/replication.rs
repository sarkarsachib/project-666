use crate::types::Address;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ReplicationPolicy {
    pub replication_factor: usize,
    pub republish_interval: u64,
    pub expiration_time: u64,
}

impl ReplicationPolicy {
    pub fn should_republish(&self, last_republished: u64, current_time: u64) -> bool {
        current_time.saturating_sub(last_republished) >= self.republish_interval
    }

    pub fn should_expire(&self, created_at: u64, current_time: u64) -> bool {
        current_time.saturating_sub(created_at) >= self.expiration_time
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicationEvent {
    pub key: Address,
    pub replicas: Vec<Address>,
    pub completed: u32,
    pub failed: u32,
}

#[derive(Debug, Clone)]
pub struct ReplicationManager {
    replication_factor: usize,
    replication_nodes: HashMap<Address, Vec<Address>>,
}

impl ReplicationManager {
    pub fn new(replication_factor: usize) -> Self {
        Self {
            replication_factor,
            replication_nodes: HashMap::new(),
        }
    }

    pub fn select_replicas(&self, key: &Address, available_peers: &[Address]) -> Vec<Address> {
        let mut peers = available_peers.to_vec();
        peers.sort_by(|a, b| {
            let da = crate::dht::routing::xor_distance(a, key);
            let db = crate::dht::routing::xor_distance(b, key);
            crate::dht::routing::compare_distance(&da, &db)
        });
        peers.truncate(self.replication_factor);
        peers
    }

    pub fn mark_replicated(&mut self, key: &Address, node: Address) {
        let entry = self.replication_nodes.entry(*key).or_default();
        if !entry.contains(&node) {
            entry.push(node);
        }
    }

    pub fn get_replicas(&self, key: &Address) -> Vec<Address> {
        self.replication_nodes
            .get(key)
            .cloned()
            .unwrap_or_default()
    }
}
