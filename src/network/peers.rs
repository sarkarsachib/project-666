//! Peer tracking and management

use crate::types::Address;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Peer record with reputation tracking
#[derive(Debug, Clone)]
pub struct PeerRecord {
    pub address: Address,
    pub public_key: [u8; 32],
    pub addresses: Vec<SocketAddr>,
    pub reputation: i32,
    pub last_seen: u64,
    pub successes: u32,
    pub failures: u32,
    pub latency_ms: Vec<u32>,
}

impl PeerRecord {
    fn new(address: Address, public_key: [u8; 32]) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        PeerRecord {
            address,
            public_key,
            addresses: Vec::new(),
            reputation: 0,
            last_seen: now,
            successes: 0,
            failures: 0,
            latency_ms: Vec::new(),
        }
    }

    /// Calculate average latency
    pub fn avg_latency(&self) -> Option<u32> {
        if self.latency_ms.is_empty() {
            None
        } else {
            let sum: u32 = self.latency_ms.iter().sum();
            Some(sum / self.latency_ms.len() as u32)
        }
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        let total = self.successes + self.failures;
        if total == 0 {
            0.0
        } else {
            self.successes as f64 / total as f64
        }
    }
}

/// Peer tracker
pub struct PeerTracker {
    peers: HashMap<Address, PeerRecord>,
}

impl PeerTracker {
    /// Create a new peer tracker
    pub fn new() -> Self {
        PeerTracker {
            peers: HashMap::new(),
        }
    }

    /// Discover a new peer
    pub fn discover_peer(&mut self, address: Address, public_key: [u8; 32]) {
        self.peers.entry(address)
            .or_insert_with(|| PeerRecord::new(address, public_key));
    }

    /// Learn a socket address for a peer
    pub fn learn_socket(&mut self, address: &Address, socket: SocketAddr) {
        if let Some(peer) = self.peers.get_mut(address) {
            if !peer.addresses.contains(&socket) {
                peer.addresses.push(socket);
            }
            
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            peer.last_seen = now;
        }
    }

    /// Record a successful interaction
    pub fn record_success(&mut self, address: &Address, latency_ms: u32) {
        if let Some(peer) = self.peers.get_mut(address) {
            peer.successes += 1;
            peer.reputation += 1;
            
            // Keep only last 10 latency samples
            peer.latency_ms.push(latency_ms);
            if peer.latency_ms.len() > 10 {
                peer.latency_ms.remove(0);
            }
            
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            peer.last_seen = now;
        }
    }

    /// Record a failed interaction
    pub fn record_failure(&mut self, address: &Address) {
        if let Some(peer) = self.peers.get_mut(address) {
            peer.failures += 1;
            peer.reputation -= 2; // Failures hurt more than successes help
        }
    }

    /// Get a peer record
    pub fn get_peer(&self, address: &Address) -> Option<&PeerRecord> {
        self.peers.get(address)
    }

    /// Get the best socket address for a peer
    pub fn get_best_socket(&self, address: &Address) -> Option<SocketAddr> {
        self.peers.get(address)
            .and_then(|peer| peer.addresses.first().copied())
    }

    /// Find reliable peers above a reputation threshold
    pub fn find_reliable_peers(&self, min_reputation: i32) -> Vec<&PeerRecord> {
        self.peers.values()
            .filter(|peer| peer.reputation >= min_reputation)
            .collect()
    }

    /// Prune stale peers
    pub fn prune_stale(&mut self, stale_threshold_seconds: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.peers.retain(|_, peer| {
            now - peer.last_seen < stale_threshold_seconds
        });
    }

    /// Get all peers
    pub fn all_peers(&self) -> Vec<&PeerRecord> {
        self.peers.values().collect()
    }

    /// Get peer count
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
}

impl Default for PeerTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_discovery() {
        let mut tracker = PeerTracker::new();
        let address = Address::from_data(b"test");
        let pubkey = [42u8; 32];
        
        tracker.discover_peer(address, pubkey);
        assert_eq!(tracker.peer_count(), 1);
        
        let peer = tracker.get_peer(&address).unwrap();
        assert_eq!(peer.address, address);
        assert_eq!(peer.public_key, pubkey);
    }

    #[test]
    fn test_socket_learning() {
        let mut tracker = PeerTracker::new();
        let address = Address::from_data(b"test");
        let pubkey = [42u8; 32];
        let socket: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        
        tracker.discover_peer(address, pubkey);
        tracker.learn_socket(&address, socket);
        
        let best_socket = tracker.get_best_socket(&address);
        assert_eq!(best_socket, Some(socket));
    }

    #[test]
    fn test_reputation() {
        let mut tracker = PeerTracker::new();
        let address = Address::from_data(b"test");
        let pubkey = [42u8; 32];
        
        tracker.discover_peer(address, pubkey);
        
        tracker.record_success(&address, 100);
        tracker.record_success(&address, 150);
        assert_eq!(tracker.get_peer(&address).unwrap().reputation, 2);
        
        tracker.record_failure(&address);
        assert_eq!(tracker.get_peer(&address).unwrap().reputation, 0);
    }

    #[test]
    fn test_find_reliable_peers() {
        let mut tracker = PeerTracker::new();
        
        for i in 0..5 {
            let address = Address::from_data(&[i]);
            tracker.discover_peer(address, [i; 32]);
            
            for _ in 0..i {
                tracker.record_success(&address, 100);
            }
        }
        
        let reliable = tracker.find_reliable_peers(2);
        assert_eq!(reliable.len(), 3); // Peers with reputation >= 2
    }
}
