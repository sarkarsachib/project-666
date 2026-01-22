use project_666::crypto::ed25519;
use project_666::dht::DHTNode;
use project_666::types::SystemDescriptor;
use project_666::Address;

#[test]
fn test_two_node_routing_table_closest() {
    let (sk1, pk1) = ed25519::generate_keypair(&[1u8; 32]);
    let id1 = SystemDescriptor::address_from_public_key(&pk1);
    let mut n1 = DHTNode::new(id1, (sk1, pk1), 20);

    let (sk2, pk2) = ed25519::generate_keypair(&[2u8; 32]);
    let id2 = SystemDescriptor::address_from_public_key(&pk2);
    let n2 = DHTNode::new(id2, (sk2, pk2), 20);

    n1.add_peer(n2.node_id, "127.0.0.1:2000".parse().unwrap())
        .unwrap();

    let closest = n1.find_closest(&Address::new([0xAA; 16]), 20);
    assert!(closest.contains(&n2.node_id));
}

#[test]
fn test_put_get_roundtrip() {
    let (sk1, pk1) = ed25519::generate_keypair(&[3u8; 32]);
    let id1 = SystemDescriptor::address_from_public_key(&pk1);
    let mut n1 = DHTNode::new(id1, (sk1, pk1), 20);

    let key = Address::new([0x42; 16]);
    n1.put(key, b"value".to_vec(), 60).unwrap();

    let got = n1.get(&key).unwrap().unwrap();
    assert_eq!(got, b"value".to_vec());
}
