//! Relay node and onion routing tests

use project_666::network::*;
use project_666::types::Address;
use project_666::ed25519;

#[test]
fn test_onion_layer_creation() {
    let layer = OnionLayer::new([1u8; 32], [2u8; 32], Address::from_data(b"hop1"));
    assert_eq!(layer.forward_key, [1u8; 32]);
    assert_eq!(layer.backward_key, [2u8; 32]);
    assert_eq!(layer.nonce_counter, 0);
}

#[test]
fn test_onion_layer_nonce() {
    let mut layer = OnionLayer::new([1u8; 32], [2u8; 32], Address::from_data(b"hop1"));
    
    let nonce1 = layer.get_nonce();
    layer.increment_nonce();
    let nonce2 = layer.get_nonce();
    
    assert_ne!(nonce1, nonce2);
    assert_eq!(layer.nonce_counter, 1);
}

#[test]
fn test_onion_packet_creation() {
    let payload = b"secret message";
    let layers = vec![
        OnionLayer::new([1u8; 32], [2u8; 32], Address::from_data(b"hop1")),
        OnionLayer::new([3u8; 32], [4u8; 32], Address::from_data(b"hop2")),
    ];
    
    let packet = OnionPacket::create(payload, &layers).unwrap();
    assert_eq!(packet.layer_count, 2);
    assert_eq!(packet.encrypted_layers.len(), 2);
}

#[test]
fn test_onion_packet_empty_layers() {
    let payload = b"test";
    let layers = vec![];
    
    let result = OnionPacket::create(payload, &layers);
    assert!(matches!(result, Err(NetworkError::InvalidHopCount)));
}

#[test]
fn test_onion_packet_single_layer() {
    let payload = b"test message";
    let layer = OnionLayer::new([42u8; 32], [43u8; 32], Address::from_data(b"hop1"));
    
    let mut packet = OnionPacket::create(payload, &[layer.clone()]).unwrap();
    assert_eq!(packet.layer_count, 1);
    
    let decrypted = packet.decrypt_layer(&layer).unwrap();
    assert_eq!(&decrypted, payload);
    assert!(packet.is_fully_decrypted());
}

#[test]
fn test_onion_packet_multi_layer() {
    let payload = b"secret message";
    let layer1 = OnionLayer::new([1u8; 32], [2u8; 32], Address::from_data(b"hop1"));
    let layer2 = OnionLayer::new([3u8; 32], [4u8; 32], Address::from_data(b"hop2"));
    let layer3 = OnionLayer::new([5u8; 32], [6u8; 32], Address::from_data(b"hop3"));
    
    let layers = vec![layer1.clone(), layer2.clone(), layer3.clone()];
    let mut packet = OnionPacket::create(payload, &layers).unwrap();
    
    assert_eq!(packet.layer_count, 3);
    
    // Decrypt layer by layer
    packet.decrypt_layer(&layer1).unwrap();
    assert_eq!(packet.layer_count, 2);
    
    packet.decrypt_layer(&layer2).unwrap();
    assert_eq!(packet.layer_count, 1);
    
    let final_payload = packet.decrypt_layer(&layer3).unwrap();
    assert_eq!(packet.layer_count, 0);
    assert_eq!(&final_payload, payload);
    assert!(packet.is_fully_decrypted());
}

#[test]
fn test_onion_packet_serialization() {
    let payload = b"test";
    let layers = vec![
        OnionLayer::new([1u8; 32], [2u8; 32], Address::from_data(b"hop1")),
        OnionLayer::new([3u8; 32], [4u8; 32], Address::from_data(b"hop2")),
    ];
    
    let packet = OnionPacket::create(payload, &layers).unwrap();
    let serialized = packet.serialize().unwrap();
    let deserialized = OnionPacket::deserialize(&serialized).unwrap();
    
    assert_eq!(packet.layer_count, deserialized.layer_count);
    assert_eq!(packet.encrypted_layers.len(), deserialized.encrypted_layers.len());
}

#[test]
fn test_onion_packet_verify_integrity() {
    let payload = b"test";
    let layers = vec![
        OnionLayer::new([1u8; 32], [2u8; 32], Address::from_data(b"hop1")),
    ];
    
    let packet = OnionPacket::create(payload, &layers).unwrap();
    assert!(packet.verify_integrity().is_ok());
}

#[test]
fn test_routing_engine_creation() {
    let local = Address::from_data(b"local");
    let engine = RoutingEngine::new(local);
    
    assert_eq!(engine.local_address(), local);
}

#[test]
fn test_routing_engine_add_route() {
    let local = Address::from_data(b"local");
    let mut engine = RoutingEngine::new(local);
    
    let dest = Address::from_data(b"destination");
    let next_hop: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
    
    engine.add_route(dest, next_hop, 1);
    assert!(engine.is_reachable(dest));
}

#[test]
fn test_routing_engine_routing_to_self() {
    let local = Address::from_data(b"local");
    let engine = RoutingEngine::new(local);
    
    let decision = engine.decide(local).unwrap();
    match decision.action {
        RoutingAction::Terminate(addr) => assert_eq!(addr, local),
        _ => panic!("Expected Terminate action"),
    }
}

#[test]
fn test_routing_engine_routing_to_peer() {
    let local = Address::from_data(b"local");
    let mut engine = RoutingEngine::new(local);
    
    let dest = Address::from_data(b"destination");
    let next_hop: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
    
    engine.add_route(dest, next_hop, 1);
    
    let decision = engine.decide(dest).unwrap();
    match decision.action {
        RoutingAction::Forward(addr) => assert_eq!(addr, next_hop),
        _ => panic!("Expected Forward action"),
    }
}

#[test]
fn test_routing_engine_no_route() {
    let local = Address::from_data(b"local");
    let engine = RoutingEngine::new(local);
    
    let dest = Address::from_data(b"unknown");
    let result = engine.decide(dest);
    
    assert!(matches!(result, Err(NetworkError::NoRoute(_))));
}

#[test]
fn test_relay_circuit_state() {
    let state = RelayCircuitState::new(1, 2, [1u8; 32], [2u8; 32]);
    
    assert_eq!(state.incoming_circuit_id, 1);
    assert_eq!(state.outgoing_circuit_id, 2);
    assert_eq!(state.nonce_counter_in, 0);
    assert_eq!(state.nonce_counter_out, 0);
}

#[test]
fn test_relay_circuit_state_nonces() {
    let mut state = RelayCircuitState::new(1, 2, [1u8; 32], [2u8; 32]);
    
    let nonce1 = state.get_forward_nonce();
    state.increment_forward();
    let nonce2 = state.get_forward_nonce();
    
    assert_ne!(nonce1, nonce2);
    
    let nonce3 = state.get_backward_nonce();
    state.increment_backward();
    let nonce4 = state.get_backward_nonce();
    
    assert_ne!(nonce3, nonce4);
}

#[test]
fn test_relay_cell_creation() {
    let cell = RelayCell::new(
        RelayCellCommand::Data as u8,
        42,
        vec![1, 2, 3, 4, 5]
    );
    
    assert_eq!(cell.command, RelayCellCommand::Data as u8);
    assert_eq!(cell.stream_id, 42);
    assert_eq!(cell.data, vec![1, 2, 3, 4, 5]);
    assert!(cell.is_recognized());
}

#[test]
fn test_relay_cell_serialization() {
    let cell = RelayCell::new(
        RelayCellCommand::Data as u8,
        100,
        vec![1, 2, 3, 4, 5]
    );
    
    let serialized = cell.serialize();
    let deserialized = RelayCell::deserialize(&serialized).unwrap();
    
    assert_eq!(cell.command, deserialized.command);
    assert_eq!(cell.stream_id, deserialized.stream_id);
    assert_eq!(cell.data, deserialized.data);
}

#[test]
fn test_relay_cell_encryption() {
    let key = [42u8; 32];
    let cell = RelayCell::new(
        RelayCellCommand::Data as u8,
        1,
        vec![1, 2, 3, 4, 5]
    );
    
    let encrypted = cell.encrypt(&key, 0).unwrap();
    let decrypted = RelayCell::decrypt(&encrypted, &key, 0).unwrap();
    
    assert_eq!(cell.command, decrypted.command);
    assert_eq!(cell.stream_id, decrypted.stream_id);
    assert_eq!(cell.data, decrypted.data);
}

#[test]
fn test_relay_cell_encryption_wrong_key() {
    let key1 = [42u8; 32];
    let key2 = [43u8; 32];
    
    let cell = RelayCell::new(
        RelayCellCommand::Data as u8,
        1,
        vec![1, 2, 3, 4, 5]
    );
    
    let encrypted = cell.encrypt(&key1, 0).unwrap();
    let result = RelayCell::decrypt(&encrypted, &key2, 0);
    
    assert!(matches!(result, Err(NetworkError::DecryptionFailed(_))));
}

#[test]
fn test_relay_node_creation() {
    let address = Address::from_data(b"relay1");
    let (secret, public) = ed25519::generate_keypair(&[1u8; 32]);
    
    let relay = RelayNode::new(address, (secret, public));
    
    assert_eq!(relay.local_address(), address);
    assert_eq!(relay.active_circuit_count(), 0);
}

#[test]
fn test_relay_node_circuit_management() {
    let address = Address::from_data(b"relay1");
    let (secret, public) = ed25519::generate_keypair(&[1u8; 32]);
    let mut relay = RelayNode::new(address, (secret, public));
    
    let state = RelayCircuitState::new(1, 2, [1u8; 32], [2u8; 32]);
    relay.add_relay_circuit(1, state);
    
    assert!(relay.is_relay_for(1));
    assert!(!relay.is_relay_for(2));
    assert_eq!(relay.active_circuit_count(), 1);
}

#[test]
fn test_relay_node_close_circuit() {
    let address = Address::from_data(b"relay1");
    let (secret, public) = ed25519::generate_keypair(&[1u8; 32]);
    let mut relay = RelayNode::new(address, (secret, public));
    
    let state = RelayCircuitState::new(1, 2, [1u8; 32], [2u8; 32]);
    relay.add_relay_circuit(1, state);
    
    relay.process_circuit_close(1).unwrap();
    
    assert!(!relay.is_relay_for(1));
    assert_eq!(relay.active_circuit_count(), 0);
}

#[test]
fn test_relay_cell_commands() {
    assert_eq!(RelayCellCommand::Begin as u8, 1);
    assert_eq!(RelayCellCommand::Data as u8, 2);
    assert_eq!(RelayCellCommand::End as u8, 3);
    assert_eq!(RelayCellCommand::Connected as u8, 4);
    assert_eq!(RelayCellCommand::Extend as u8, 6);
    assert_eq!(RelayCellCommand::ExtendReply as u8, 7);
}

#[test]
fn test_relay_cell_command_from_u8() {
    assert_eq!(RelayCellCommand::from_u8(1), Some(RelayCellCommand::Begin));
    assert_eq!(RelayCellCommand::from_u8(2), Some(RelayCellCommand::Data));
    assert_eq!(RelayCellCommand::from_u8(99), None);
}
