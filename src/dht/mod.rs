//! Distributed Hash Table (DHT) and distributed address resolution primitives.
//!
//! This is a Kademlia-inspired DHT for 128-bit `.666` addresses.

pub mod bootstrap;
pub mod bucket;
pub mod cache;
pub mod error;
pub mod gossip;
pub mod lookup;
pub mod node;
pub mod replication;
pub mod routing;
pub mod storage;

pub use bootstrap::BootstrapManager;
pub use bucket::{bucket_index, BucketEntry, KBucket};
pub use cache::{DHTCache, EvictionPolicy};
pub use error::{DHTError, Result};
pub use gossip::{GossipManager, GossipMessage, GossipMessageType};
pub use lookup::{CandidateNode, LookupContext, LookupType};
pub use node::{DHTMetrics, DHTNode, PeerTracker};
pub use replication::{ReplicationEvent, ReplicationManager, ReplicationPolicy};
pub use routing::{compare_distance, xor_distance};
pub use storage::{EncryptedStorage, StorageEntry};

pub(crate) fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
