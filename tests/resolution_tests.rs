use project_666::crypto::ed25519;
use project_666::dht::DHTNode;
use project_666::resolution::{ResolutionRequest, Resolver};
use project_666::types::{Permission, ResourceLimits, SystemDescriptor};
use project_666::Address;

fn now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[test]
fn test_descriptor_resolution_and_cache() {
    let seed = [5u8; 32];
    let (sk, pk) = ed25519::generate_keypair(&seed);
    let id = SystemDescriptor::address_from_public_key(&pk);
    let dht = DHTNode::new(id, (sk, pk), 20);

    let mut resolver = Resolver::new(dht);

    let seed2 = [6u8; 32];
    let (sk2, pk2) = ed25519::generate_keypair(&seed2);
    let created_at = now();
    let expires_at = created_at + 600;
    let descriptor = SystemDescriptor::new_unsigned(
        pk2,
        "127.0.0.1:4242".parse().unwrap(),
        vec![Permission::Any, Permission::Resolve],
        ResourceLimits::default(),
        created_at,
        expires_at,
    )
    .sign(&sk2);

    resolver.register_descriptor(descriptor.clone()).unwrap();

    let req = ResolutionRequest {
        address: descriptor.address,
        capability_filter: None,
    };

    let result = resolver.resolve(&req).unwrap();
    assert_eq!(result.descriptor.address, descriptor.address);

    // Cache hit
    let cached = resolver.check_cache(&descriptor.address).unwrap();
    assert_eq!(cached.descriptor.address, descriptor.address);
}

#[test]
fn test_descriptor_roundtrip_bytes() {
    let seed = [8u8; 32];
    let (sk, pk) = ed25519::generate_keypair(&seed);
    let created_at = now();
    let expires_at = created_at + 600;

    let descriptor = SystemDescriptor::new_unsigned(
        pk,
        "127.0.0.1:9999".parse().unwrap(),
        vec![Permission::Store],
        ResourceLimits::default(),
        created_at,
        expires_at,
    )
    .sign(&sk);

    let bytes = descriptor.to_bytes();
    let parsed = SystemDescriptor::from_bytes(&bytes).unwrap();
    assert_eq!(descriptor.address, parsed.address);
    assert!(parsed.verify());
    assert_eq!(descriptor, parsed);
}

#[test]
fn test_unregister_descriptor() {
    let seed = [10u8; 32];
    let (sk, pk) = ed25519::generate_keypair(&seed);
    let id = SystemDescriptor::address_from_public_key(&pk);
    let dht = DHTNode::new(id, (sk, pk), 20);

    let mut resolver = Resolver::new(dht);

    let addr = Address::new([0x11; 16]);
    assert!(resolver.unregister_descriptor(&addr).is_ok());
}
