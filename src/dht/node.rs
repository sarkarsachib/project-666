use crate::crypto::ed25519::{PublicKey, SecretKey};
use crate::dht::bucket::{BucketEntry, KBucket};
use crate::dht::cache::{DHTCache, EvictionPolicy};
use crate::dht::error::{DHTError, Result};
use crate::dht::gossip::{GossipManager, GossipMessage};
use crate::dht::replication::ReplicationManager;
use crate::dht::routing::RoutingTable;
use crate::dht::storage::EncryptedStorage;
use crate::dht::{now_secs, BootstrapManager};
use crate::sha256;
use crate::types::Address;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, Default)]
pub struct DHTMetrics {
    pub lookups_initiated: u64,
    pub lookups_completed: u64,
    pub lookups_failed: u64,
    pub puts_processed: u64,
    pub gets_processed: u64,
    pub replications: u64,
    pub gossip_messages_sent: u64,
    pub gossip_messages_received: u64,
    pub uptime_seconds: u64,
}

#[derive(Debug, Default)]
struct MetricsAtomic {
    lookups_initiated: AtomicU64,
    lookups_completed: AtomicU64,
    lookups_failed: AtomicU64,
    puts_processed: AtomicU64,
    gets_processed: AtomicU64,
    replications: AtomicU64,
    gossip_messages_sent: AtomicU64,
    gossip_messages_received: AtomicU64,
}

impl MetricsAtomic {
    fn snapshot(&self) -> DHTMetrics {
        DHTMetrics {
            lookups_initiated: self.lookups_initiated.load(Ordering::Relaxed),
            lookups_completed: self.lookups_completed.load(Ordering::Relaxed),
            lookups_failed: self.lookups_failed.load(Ordering::Relaxed),
            puts_processed: self.puts_processed.load(Ordering::Relaxed),
            gets_processed: self.gets_processed.load(Ordering::Relaxed),
            replications: self.replications.load(Ordering::Relaxed),
            gossip_messages_sent: self.gossip_messages_sent.load(Ordering::Relaxed),
            gossip_messages_received: self.gossip_messages_received.load(Ordering::Relaxed),
            uptime_seconds: 0,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PeerTracker {
    peers: HashMap<Address, SocketAddr>,
}

impl PeerTracker {
    pub fn add(&mut self, address: Address, socket: SocketAddr) {
        self.peers.insert(address, socket);
    }

    pub fn remove(&mut self, address: &Address) {
        self.peers.remove(address);
    }

    pub fn socket(&self, address: &Address) -> Option<SocketAddr> {
        self.peers.get(address).copied()
    }

    pub fn all(&self) -> Vec<Address> {
        self.peers.keys().copied().collect()
    }

    pub fn size(&self) -> usize {
        self.peers.len()
    }
}

/// A single DHT node.
///
/// Note: this reference implementation focuses on correctness and testability.
/// Network RPCs are intentionally abstracted away and can be layered on top.
#[derive(Debug)]
pub struct DHTNode {
    pub node_id: Address,
    pub keys: (SecretKey, PublicKey),
    pub k: usize,
    pub buckets: Vec<KBucket>,
    pub storage: EncryptedStorage,
    pub routing_table: RoutingTable,
    pub peers: PeerTracker,
    pub metrics: DHTMetrics,

    gossip: RefCell<GossipManager>,
    replication: RefCell<ReplicationManager>,
    cache: RefCell<DHTCache>,
    metrics_atomic: MetricsAtomic,
    started_at: u64,
}

impl DHTNode {
    // Initialization
    pub fn new(node_id: Address, keys: (SecretKey, PublicKey), k: usize) -> Self {
        let storage_key = derive_storage_key(&keys.0);

        let mut buckets = Vec::with_capacity(160);
        for i in 0..160 {
            buckets.push(KBucket::new(i, k));
        }

        Self {
            node_id,
            keys,
            k,
            buckets,
            storage: EncryptedStorage::new(storage_key),
            routing_table: RoutingTable::new(node_id, k),
            peers: PeerTracker::default(),
            metrics: DHTMetrics::default(),
            gossip: RefCell::new(GossipManager::new(8)),
            replication: RefCell::new(ReplicationManager::new(3)),
            cache: RefCell::new(DHTCache::new(1024, EvictionPolicy::LRU)),
            metrics_atomic: MetricsAtomic::default(),
            started_at: now_secs(),
        }
    }

    pub fn bootstrap(&mut self, bootstrap_peers: Vec<(Address, SocketAddr)>) -> Result<()> {
        let bm = BootstrapManager::new(bootstrap_peers);
        bm.bootstrap(self)
    }

    // Peer management
    pub fn add_peer(&mut self, peer: Address, socket: SocketAddr) -> Result<()> {
        if peer == self.node_id {
            return Err(DHTError::InvalidInput("cannot add self as peer"));
        }

        self.peers.add(peer, socket);

        let entry = BucketEntry {
            address: peer,
            public_key: [0u8; 32],
            socket,
            last_seen: now_secs(),
            reliability: 1.0,
            latency_ms: 0,
        };

        self.routing_table.add_peer(&mut self.buckets, entry)?;
        Ok(())
    }

    pub fn remove_peer(&mut self, peer: &Address) {
        self.peers.remove(peer);
        self.routing_table.remove_peer(&mut self.buckets, peer);
    }

    pub fn find_closest(&self, target: &Address, count: usize) -> Vec<Address> {
        self.routing_table.find_closest(&self.buckets, target, count)
    }

    // Storage operations
    pub fn put(&mut self, key: Address, value: Vec<u8>, ttl: u64) -> Result<()> {
        self.metrics_atomic
            .puts_processed
            .fetch_add(1, Ordering::Relaxed);

        self.storage.insert(key, value.clone(), ttl)?;
        let _ = self.cache.borrow_mut().insert(key, value);

        let peers = self.routing_table.all_peers(&self.buckets);
        let replicas = self
            .replication
            .borrow()
            .select_replicas(&key, &peers);
        for replica in replicas {
            self.replication.borrow_mut().mark_replicated(&key, replica);
        }
        self.metrics_atomic
            .replications
            .fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    pub fn get(&self, key: &Address) -> Result<Option<Vec<u8>>> {
        self.metrics_atomic
            .gets_processed
            .fetch_add(1, Ordering::Relaxed);

        if let Some(v) = self.cache.borrow_mut().get(key) {
            return Ok(Some(v));
        }

        let v = self.storage.get(key)?;
        if let Some(ref bytes) = v {
            let _ = self.cache.borrow_mut().insert(*key, bytes.clone());
        }
        Ok(v)
    }

    pub fn delete(&mut self, key: &Address) -> Result<()> {
        self.storage.delete(key)?;
        self.cache.borrow_mut().invalidate(key);
        Ok(())
    }

    // Lookups (iterative)
    pub fn find_node(&self, target: &Address) -> Result<Vec<Address>> {
        self.metrics_atomic
            .lookups_initiated
            .fetch_add(1, Ordering::Relaxed);

        let res = self.find_closest(target, self.k);
        if res.is_empty() {
            self.metrics_atomic
                .lookups_failed
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.metrics_atomic
                .lookups_completed
                .fetch_add(1, Ordering::Relaxed);
        }
        Ok(res)
    }

    pub fn find_value(&self, key: &Address) -> Result<Option<Vec<u8>>> {
        self.find_node(key)?;
        self.get(key)
    }

    // Gossip
    pub fn receive_gossip(&mut self, from: &Address, data: &[u8]) -> Result<()> {
        let msg = GossipMessage::from_bytes(data)?;
        self.metrics_atomic
            .gossip_messages_received
            .fetch_add(1, Ordering::Relaxed);

        // If we have a public key for the sender in our routing table, register it for verification.
        if let Some(entry) = self
            .buckets
            .iter()
            .flat_map(|b| b.entries.iter())
            .find(|e| &e.address == from)
        {
            if entry.public_key != [0u8; 32] {
                self.gossip
                    .borrow_mut()
                    .register_public_key(*from, entry.public_key);
            }
        }

        let ok = self.gossip.borrow().verify_message(&msg)?;
        if !ok {
            return Err(DHTError::InvalidInput("invalid gossip signature"));
        }

        Ok(())
    }

    pub fn broadcast_gossip(&self, _data: &[u8]) -> Result<()> {
        self.metrics_atomic
            .gossip_messages_sent
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    // Maintenance
    pub fn refresh_buckets(&mut self) -> Result<()> {
        // In a complete implementation, this performs FIND_NODE on random IDs per bucket.
        for bucket in &mut self.buckets {
            bucket.last_updated = now_secs();
        }
        Ok(())
    }

    pub fn replicate_data(&mut self) -> Result<()> {
        // Replication is tracked in-memory via `ReplicationManager`.
        Ok(())
    }

    pub fn prune_expired(&mut self) {
        let _ = self.storage.prune_expired();
    }

    // Metrics
    pub fn get_metrics(&self) -> DHTMetrics {
        let mut m = self.metrics_atomic.snapshot();
        m.uptime_seconds = now_secs().saturating_sub(self.started_at);
        m
    }
}

fn derive_storage_key(secret_key: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(b"dht-storage-key");
    data.extend_from_slice(secret_key);
    sha256::digest(&data)
}
