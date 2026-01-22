use project_666::crypto::ed25519;
use project_666::dht::{GossipManager, GossipMessage, GossipMessageType};
use project_666::types::SystemDescriptor;
use project_666::Address;
use std::net::SocketAddr;

#[test]
fn test_gossip_message_create_and_verify() {
    let seed = [1u8; 32];
    let (sk, pk) = ed25519::generate_keypair(&seed);
    let sender = SystemDescriptor::address_from_public_key(&pk);

    let mut gm = GossipManager::new(3);
    gm.register_public_key(sender, pk);

    let msg = GossipManager::create_message(
        GossipMessageType::Heartbeat {
            peer_count: 1,
            storage_size: 2,
        },
        sender,
        &sk,
    )
    .unwrap();

    assert!(gm.verify_message(&msg).unwrap());
}

#[test]
fn test_gossip_deduplication() {
    let seed = [2u8; 32];
    let (sk, pk) = ed25519::generate_keypair(&seed);
    let sender = SystemDescriptor::address_from_public_key(&pk);

    let gm = GossipManager::new(3);

    let msg = GossipManager::create_message(
        GossipMessageType::StorageDelete {
            key: Address::new([9u8; 16]),
        },
        sender,
        &sk,
    )
    .unwrap();

    // We don't have the key registered, but should_forward is independent of signature.
    assert!(gm.should_forward(&msg));
    assert!(!gm.should_forward(&msg));
}

#[test]
fn test_gossip_serialization_roundtrip() {
    let seed = [3u8; 32];
    let (sk, pk) = ed25519::generate_keypair(&seed);
    let sender = SystemDescriptor::address_from_public_key(&pk);

    let mut gm = GossipManager::new(3);
    gm.register_public_key(sender, pk);

    let msg = GossipManager::create_message(
        GossipMessageType::PeerAdvertisement {
            peer: Address::new([4u8; 16]),
            socket: "127.0.0.1:5555".parse::<SocketAddr>().unwrap(),
        },
        sender,
        &sk,
    )
    .unwrap();

    let bytes = msg.to_bytes();
    let parsed = GossipMessage::from_bytes(&bytes).unwrap();

    assert_eq!(msg.sender, parsed.sender);
    assert!(gm.verify_message(&parsed).unwrap());
}
