use project_666::crypto::ed25519;
use project_666::dht::{bucket_index, compare_distance, xor_distance, BucketEntry, KBucket};
use project_666::types::SystemDescriptor;
use project_666::Address;
use std::net::SocketAddr;

fn test_address(byte: u8) -> Address {
    Address::new([byte; 16])
}

#[test]
fn test_xor_distance() {
    let a = Address::new([0x00; 16]);
    let b = Address::new([0xFF; 16]);
    let dist = xor_distance(&a, &b);
    assert_eq!(dist, [0xFF; 16]);
}

#[test]
fn test_compare_distance() {
    let a = [0u8; 16];
    let mut b = [0u8; 16];
    b[15] = 1;
    assert_eq!(compare_distance(&a, &b), core::cmp::Ordering::Less);
}

#[test]
fn test_bucket_index_self() {
    let a = test_address(0x11);
    assert_eq!(bucket_index(&a, &a), 159);
}

#[test]
fn test_kbucket_operations() {
    let mut bucket = KBucket::new(0, 20);
    let entry = BucketEntry {
        address: test_address(1),
        public_key: [0; 32],
        socket: "127.0.0.1:1234".parse().unwrap(),
        last_seen: 1,
        reliability: 1.0,
        latency_ms: 10,
    };
    bucket.add_entry(entry).unwrap();
    assert!(bucket.get_entry(&test_address(1)).is_some());

    bucket.update_entry(&test_address(1), 42).unwrap();
    assert_eq!(bucket.get_entry(&test_address(1)).unwrap().latency_ms, 42);

    bucket.remove_entry(&test_address(1));
    assert!(bucket.get_entry(&test_address(1)).is_none());
}

#[test]
fn test_dht_node_id_from_public_key() {
    let seed = [9u8; 32];
    let (_sk, pk) = ed25519::generate_keypair(&seed);
    let addr = SystemDescriptor::address_from_public_key(&pk);
    assert_ne!(addr, Address::zero());
}

#[test]
fn test_kbucket_sort_by_distance() {
    let target = test_address(0xAB);
    let mut bucket = KBucket::new(0, 20);
    let socket: SocketAddr = "127.0.0.1:1234".parse().unwrap();

    for i in 0..10u8 {
        bucket
            .add_entry(BucketEntry {
                address: test_address(i),
                public_key: [0; 32],
                socket,
                last_seen: 1,
                reliability: 1.0,
                latency_ms: 0,
            })
            .unwrap();
    }

    bucket.sort_by_distance(&target);
    let first = bucket.entries[0].address;
    let mut best = bucket.entries[0].address;
    let mut best_dist = xor_distance(&best, &target);
    for e in &bucket.entries {
        let d = xor_distance(&e.address, &target);
        if compare_distance(&d, &best_dist) == core::cmp::Ordering::Less {
            best = e.address;
            best_dist = d;
        }
    }

    assert_eq!(first, best);
}
