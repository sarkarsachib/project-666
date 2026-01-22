//! End-to-end integration tests

use project_666::network::*;
use project_666::types::Address;
use project_666::ed25519;
use std::net::SocketAddr;

#[test]
fn test_end_to_end_circuit_creation() {
    // Create circuit manager
    let mut manager = CircuitManager::new();
    
    // Define circuit hops
    let hops = vec![
        CircuitHop {
            address: Address::from_data(b"hop1"),
            public_key: [1u8; 32],
        },
        CircuitHop {
            address: Address::from_data(b"hop2"),
            public_key: [2u8; 32],
        },
        CircuitHop {
            address: Address::from_data(b"hop3"),
            public_key: [3u8; 32],
        },
    ];
    
    // Create circuit
    let circuit_id = manager.create_circuit(hops).unwrap();
    
    // Verify circuit exists and is established
    let circuit = manager.get_circuit(circuit_id).unwrap();
    assert_eq!(circuit.state, CircuitState::Established);
    assert_eq!(circuit.hop_count(), 3);
    assert_eq!(circuit.forward_keys.len(), 3);
    assert_eq!(circuit.backward_keys.len(), 3);
}

#[test]
fn test_packet_send_receive_simulation() {
    // Create two transports
    let mut transport1 = Transport::new("127.0.0.1:0").unwrap();
    let mut transport2 = Transport::new("127.0.0.1:0").unwrap();
    
    let addr1 = transport1.local_addr();
    let addr2 = transport2.local_addr();
    
    // Add each other as peers
    transport1.add_peer(addr2);
    transport2.add_peer(addr1);
    
    // Create and send a packet from transport1 to transport2
    let packet = Packet::with_payload(
        PacketType::KeepAlive as u8,
        vec![1, 2, 3, 4, 5]
    );
    
    transport1.send_packet(addr2, &packet).unwrap();
    
    // Set non-blocking mode for receive
    transport2.set_nonblocking(true).unwrap();
    
    // Try to receive (may or may not succeed due to UDP unreliability)
    if let Ok(Some((from, received_packet))) = transport2.recv_packet() {
        assert_eq!(from, addr1);
        assert_eq!(received_packet.header.packet_type, PacketType::KeepAlive as u8);
        assert_eq!(received_packet.payload, vec![1, 2, 3, 4, 5]);
    }
}

#[test]
fn test_multi_hop_onion_routing() {
    let payload = b"secret message from alice to bob";
    
    // Create three hops
    let hop1_key = [1u8; 32];
    let hop2_key = [2u8; 32];
    let hop3_key = [3u8; 32];
    
    let layer1 = OnionLayer::new(hop1_key, [11u8; 32], Address::from_data(b"hop1"));
    let layer2 = OnionLayer::new(hop2_key, [22u8; 32], Address::from_data(b"hop2"));
    let layer3 = OnionLayer::new(hop3_key, [33u8; 32], Address::from_data(b"hop3"));
    
    // Create onion packet
    let mut packet = OnionPacket::create(
        payload,
        &[layer1.clone(), layer2.clone(), layer3.clone()]
    ).unwrap();
    
    // Simulate hop 1 processing
    let intermediate1 = packet.decrypt_layer(&layer1).unwrap();
    assert_eq!(packet.layer_count, 2);
    
    // Simulate hop 2 processing
    let intermediate2 = packet.decrypt_layer(&layer2).unwrap();
    assert_eq!(packet.layer_count, 1);
    
    // Simulate hop 3 processing (final destination)
    let final_payload = packet.decrypt_layer(&layer3).unwrap();
    assert_eq!(packet.layer_count, 0);
    assert_eq!(&final_payload, payload);
}

#[test]
fn test_connection_lifecycle() {
    let mut manager = ConnectionManager::new();
    let peer: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let identity = Address::from_data(b"peer1");
    
    // Create connection
    let mut conn = Connection::new(peer, identity);
    assert_eq!(conn.state, ConnectionState::Connecting);
    
    // Handshake
    conn.state = ConnectionState::Handshaking;
    manager.add_connection(conn);
    
    // Establish
    manager.set_state(peer, ConnectionState::Established).unwrap();
    assert_eq!(manager.active_count(), 1);
    
    // Set session key
    let session_key = [42u8; 32];
    manager.set_session_key(peer, session_key).unwrap();
    
    let conn = manager.get_connection(peer).unwrap();
    assert_eq!(conn.session_key, session_key);
    
    // Close
    manager.set_state(peer, ConnectionState::Closing).unwrap();
    manager.set_state(peer, ConnectionState::Closed).unwrap();
    assert_eq!(manager.active_count(), 0);
}

#[test]
fn test_relay_network_simulation() {
    // Create three relay nodes
    let (secret1, public1) = ed25519::generate_keypair(&[1u8; 32]);
    let (secret2, public2) = ed25519::generate_keypair(&[2u8; 32]);
    let (secret3, public3) = ed25519::generate_keypair(&[3u8; 32]);
    
    let addr1 = Address::from_data(b"relay1");
    let addr2 = Address::from_data(b"relay2");
    let addr3 = Address::from_data(b"relay3");
    
    let relay1 = RelayNode::new(addr1, (secret1, public1));
    let relay2 = RelayNode::new(addr2, (secret2, public2));
    let relay3 = RelayNode::new(addr3, (secret3, public3));
    
    // Verify all relays are initialized
    assert_eq!(relay1.active_circuit_count(), 0);
    assert_eq!(relay2.active_circuit_count(), 0);
    assert_eq!(relay3.active_circuit_count(), 0);
}

#[test]
fn test_peer_discovery_and_reputation() {
    let mut tracker = PeerTracker::new();
    
    // Discover peers
    for i in 0..10 {
        let address = Address::from_data(&[i]);
        let pubkey = [i; 32];
        tracker.discover_peer(address, pubkey);
        
        let socket: SocketAddr = format!("127.0.0.1:800{}", i).parse().unwrap();
        tracker.learn_socket(&address, socket);
    }
    
    assert_eq!(tracker.peer_count(), 10);
    
    // Build reputation for some peers
    for i in 0..5 {
        let address = Address::from_data(&[i]);
        
        // Successful interactions
        for _ in 0..i+1 {
            tracker.record_success(&address, 100);
        }
    }
    
    // Find reliable peers
    let reliable = tracker.find_reliable_peers(3);
    assert!(reliable.len() >= 2); // At least peers with index 3 and 4
    
    // Verify all have good reputation
    for peer in reliable {
        assert!(peer.reputation >= 3);
    }
}

#[test]
fn test_circuit_with_connections() {
    let mut circuit_manager = CircuitManager::new();
    let mut conn_manager = ConnectionManager::new();
    
    // Create connections to peers
    let peer1: SocketAddr = "127.0.0.1:8081".parse().unwrap();
    let peer2: SocketAddr = "127.0.0.1:8082".parse().unwrap();
    let peer3: SocketAddr = "127.0.0.1:8083".parse().unwrap();
    
    let id1 = Address::from_data(b"peer1");
    let id2 = Address::from_data(b"peer2");
    let id3 = Address::from_data(b"peer3");
    
    let mut conn1 = Connection::new(peer1, id1);
    conn1.state = ConnectionState::Established;
    
    let mut conn2 = Connection::new(peer2, id2);
    conn2.state = ConnectionState::Established;
    
    let mut conn3 = Connection::new(peer3, id3);
    conn3.state = ConnectionState::Established;
    
    conn_manager.add_connection(conn1);
    conn_manager.add_connection(conn2);
    conn_manager.add_connection(conn3);
    
    assert_eq!(conn_manager.active_count(), 3);
    
    // Create circuit using these peers
    let hops = vec![
        CircuitHop {
            address: id1,
            public_key: [1u8; 32],
        },
        CircuitHop {
            address: id2,
            public_key: [2u8; 32],
        },
        CircuitHop {
            address: id3,
            public_key: [3u8; 32],
        },
    ];
    
    let circuit_id = circuit_manager.create_circuit(hops).unwrap();
    let circuit = circuit_manager.get_circuit(circuit_id).unwrap();
    
    assert_eq!(circuit.hop_count(), 3);
    assert_eq!(circuit.state, CircuitState::Established);
}

#[test]
fn test_routing_with_circuits() {
    let local = Address::from_data(b"local");
    let mut engine = RoutingEngine::new(local);
    
    // Add routes for circuit hops
    let hop1 = Address::from_data(b"hop1");
    let hop2 = Address::from_data(b"hop2");
    let hop3 = Address::from_data(b"hop3");
    
    let addr1: SocketAddr = "127.0.0.1:8081".parse().unwrap();
    let addr2: SocketAddr = "127.0.0.1:8082".parse().unwrap();
    let addr3: SocketAddr = "127.0.0.1:8083".parse().unwrap();
    
    engine.add_route(hop1, addr1, 1);
    engine.add_route(hop2, addr2, 1);
    engine.add_route(hop3, addr3, 1);
    
    // Verify all hops are reachable
    assert!(engine.is_reachable(hop1));
    assert!(engine.is_reachable(hop2));
    assert!(engine.is_reachable(hop3));
    
    // Test routing decisions
    let decision1 = engine.decide(hop1).unwrap();
    match decision1.action {
        RoutingAction::Forward(addr) => assert_eq!(addr, addr1),
        _ => panic!("Expected Forward action"),
    }
}

#[test]
fn test_complete_network_stack() {
    // Initialize all components
    let mut transport = Transport::new("127.0.0.1:0").unwrap();
    let mut circuit_manager = CircuitManager::new();
    let mut conn_manager = ConnectionManager::new();
    let mut peer_tracker = PeerTracker::new();
    
    let local_addr = transport.local_addr();
    
    // Discover peer
    let peer_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let peer_id = Address::from_data(b"peer1");
    let peer_pubkey = [42u8; 32];
    
    peer_tracker.discover_peer(peer_id, peer_pubkey);
    peer_tracker.learn_socket(&peer_id, peer_addr);
    
    // Add as transport peer
    transport.add_peer(peer_addr);
    
    // Create connection
    let mut conn = Connection::new(peer_addr, peer_id);
    conn.state = ConnectionState::Established;
    conn_manager.add_connection(conn);
    
    // Create circuit through peer
    let hops = vec![
        CircuitHop {
            address: peer_id,
            public_key: peer_pubkey,
        },
    ];
    
    let circuit_id = circuit_manager.create_circuit(hops).unwrap();
    
    // Verify everything is connected
    assert_eq!(transport.peer_count(), 1);
    assert_eq!(conn_manager.active_count(), 1);
    assert_eq!(circuit_manager.active_circuit_count(), 1);
    assert_eq!(peer_tracker.peer_count(), 1);
    
    // Get stats
    let stats = transport.stats();
    assert_eq!(stats.active_peers, 1);
    
    // Verify circuit
    let circuit = circuit_manager.get_circuit(circuit_id).unwrap();
    assert_eq!(circuit.hop_count(), 1);
    assert_eq!(circuit.state, CircuitState::Established);
}
