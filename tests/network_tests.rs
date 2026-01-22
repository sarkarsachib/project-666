//! Network transport and packet tests

use project_666::network::*;
use project_666::types::Address;

#[test]
fn test_packet_header_creation() {
    let header = PacketHeader::new(PacketType::KeepAlive as u8);
    assert_eq!(header.magic, [0x66, 0x66, 0x66, 0x01]);
    assert_eq!(header.version, 1);
    assert_eq!(header.packet_type, PacketType::KeepAlive as u8);
}

#[test]
fn test_packet_header_serialization() {
    let header = PacketHeader::new(PacketType::CircuitData as u8);
    let serialized = header.serialize();
    
    assert_eq!(serialized.len(), 32);
    
    let deserialized = PacketHeader::deserialize(&serialized).unwrap();
    assert_eq!(header.magic, deserialized.magic);
    assert_eq!(header.version, deserialized.version);
    assert_eq!(header.packet_type, deserialized.packet_type);
}

#[test]
fn test_packet_creation() {
    let packet = Packet::new(PacketType::KeepAlive as u8);
    assert_eq!(packet.header.packet_type, PacketType::KeepAlive as u8);
    assert!(packet.payload.is_empty());
}

#[test]
fn test_packet_with_payload() {
    let payload = vec![1, 2, 3, 4, 5];
    let packet = Packet::with_payload(PacketType::CircuitData as u8, payload.clone());
    assert_eq!(packet.payload, payload);
}

#[test]
fn test_packet_roundtrip() {
    let mut packet = Packet::new(PacketType::CircuitData as u8);
    packet.header.packet_id = 42;
    packet.header.sequence = 100;
    packet.payload = vec![1, 2, 3, 4, 5, 6, 7, 8];
    
    let serialized = packet.serialize().unwrap();
    let deserialized = Packet::deserialize(&serialized).unwrap();
    
    assert_eq!(packet.header.packet_type, deserialized.header.packet_type);
    assert_eq!(packet.header.packet_id, deserialized.header.packet_id);
    assert_eq!(packet.header.sequence, deserialized.header.sequence);
    assert_eq!(packet.payload, deserialized.payload);
}

#[test]
fn test_packet_checksum() {
    let packet = Packet::new(PacketType::KeepAlive as u8);
    let serialized = packet.serialize().unwrap();
    let deserialized = Packet::deserialize(&serialized).unwrap();
    
    assert!(deserialized.verify_checksum());
}

#[test]
fn test_packet_checksum_mismatch() {
    let packet = Packet::with_payload(PacketType::CircuitData as u8, vec![1, 2, 3, 4, 5]);
    let mut serialized = packet.serialize().unwrap();
    
    // Corrupt the payload
    if serialized.len() > 40 {
        serialized[40] ^= 0xFF;
    }
    
    let result = Packet::deserialize(&serialized);
    assert!(matches!(result, Err(NetworkError::ChecksumMismatch)));
}

#[test]
fn test_transport_creation() {
    let transport = Transport::new("127.0.0.1:0").unwrap();
    let local_addr = transport.local_addr();
    assert_eq!(local_addr.ip().to_string(), "127.0.0.1");
    assert!(local_addr.port() > 0);
}

#[test]
fn test_transport_peer_management() {
    let mut transport = Transport::new("127.0.0.1:0").unwrap();
    let peer = "127.0.0.1:8080".parse().unwrap();
    
    transport.add_peer(peer);
    assert_eq!(transport.peer_count(), 1);
    assert!(transport.get_peer_info(peer).is_some());
    
    let peers = transport.get_peers();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0], peer);
    
    transport.remove_peer(peer);
    assert_eq!(transport.peer_count(), 0);
}

#[test]
fn test_transport_stats() {
    let transport = Transport::new("127.0.0.1:0").unwrap();
    let stats = transport.stats();
    
    assert_eq!(stats.total_packets_sent, 0);
    assert_eq!(stats.total_packets_received, 0);
    assert_eq!(stats.active_peers, 0);
}

#[test]
fn test_transport_nonblocking() {
    let transport = Transport::new("127.0.0.1:0").unwrap();
    transport.set_nonblocking(true).unwrap();
    transport.set_nonblocking(false).unwrap();
}

#[test]
fn test_transport_timeouts() {
    let transport = Transport::new("127.0.0.1:0").unwrap();
    transport.set_recv_timeout(1000).unwrap();
    transport.set_send_timeout(1000).unwrap();
}

#[test]
fn test_reliability_manager() {
    let mut manager = ReliabilityManager::new(1000);
    let mut packet = Packet::new(PacketType::KeepAlive as u8);
    packet.header.packet_id = 42;
    
    let id = manager.send_reliable(packet);
    assert_eq!(id, 42);
    
    // ACK the packet
    manager.handle_ack(42);
    
    // Should be removed from pending
    let timeouts = manager.check_timeouts();
    assert!(!timeouts.contains(&42));
}

#[test]
fn test_peer_tracker_discovery() {
    let mut tracker = PeerTracker::new();
    let address = Address::from_data(b"peer1");
    let pubkey = [42u8; 32];
    
    tracker.discover_peer(address, pubkey);
    assert_eq!(tracker.peer_count(), 1);
    
    let peer = tracker.get_peer(&address).unwrap();
    assert_eq!(peer.address, address);
    assert_eq!(peer.public_key, pubkey);
}

#[test]
fn test_peer_tracker_socket_learning() {
    let mut tracker = PeerTracker::new();
    let address = Address::from_data(b"peer1");
    let pubkey = [42u8; 32];
    let socket: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
    
    tracker.discover_peer(address, pubkey);
    tracker.learn_socket(&address, socket);
    
    let best_socket = tracker.get_best_socket(&address);
    assert_eq!(best_socket, Some(socket));
}

#[test]
fn test_peer_tracker_reputation() {
    let mut tracker = PeerTracker::new();
    let address = Address::from_data(b"peer1");
    let pubkey = [42u8; 32];
    
    tracker.discover_peer(address, pubkey);
    
    // Record successes
    tracker.record_success(&address, 100);
    tracker.record_success(&address, 150);
    tracker.record_success(&address, 200);
    
    let peer = tracker.get_peer(&address).unwrap();
    assert_eq!(peer.successes, 3);
    assert_eq!(peer.reputation, 3);
    
    // Record failure
    tracker.record_failure(&address);
    let peer = tracker.get_peer(&address).unwrap();
    assert_eq!(peer.failures, 1);
    assert_eq!(peer.reputation, 1); // 3 - 2
}

#[test]
fn test_peer_tracker_find_reliable() {
    let mut tracker = PeerTracker::new();
    
    for i in 0..5 {
        let address = Address::from_data(&[i]);
        tracker.discover_peer(address, [i; 32]);
        
        // Give different reputation levels
        for _ in 0..i {
            tracker.record_success(&address, 100);
        }
    }
    
    let reliable = tracker.find_reliable_peers(2);
    assert_eq!(reliable.len(), 3); // Peers with reputation >= 2 (i=2,3,4)
}

#[test]
fn test_connection_creation() {
    let peer = "127.0.0.1:8080".parse().unwrap();
    let identity = Address::from_data(b"peer1");
    
    let conn = Connection::new(peer, identity);
    assert_eq!(conn.peer_address, peer);
    assert_eq!(conn.remote_identity, identity);
    assert_eq!(conn.state, ConnectionState::Connecting);
}

#[test]
fn test_connection_manager() {
    let mut manager = ConnectionManager::new();
    let peer = "127.0.0.1:8080".parse().unwrap();
    let identity = Address::from_data(b"peer1");
    
    let conn = Connection::new(peer, identity);
    manager.add_connection(conn);
    
    assert_eq!(manager.total_count(), 1);
    assert!(manager.get_connection(peer).is_some());
    assert_eq!(manager.find_by_identity(&identity), Some(peer));
}

#[test]
fn test_connection_state_transitions() {
    let mut manager = ConnectionManager::new();
    let peer = "127.0.0.1:8080".parse().unwrap();
    let identity = Address::from_data(b"peer1");
    
    let conn = Connection::new(peer, identity);
    manager.add_connection(conn);
    
    manager.set_state(peer, ConnectionState::Handshaking).unwrap();
    assert_eq!(
        manager.get_connection(peer).unwrap().state,
        ConnectionState::Handshaking
    );
    
    manager.set_state(peer, ConnectionState::Established).unwrap();
    assert_eq!(manager.active_count(), 1);
    
    manager.set_state(peer, ConnectionState::Closed).unwrap();
    assert_eq!(manager.active_count(), 0);
}

#[test]
fn test_connection_activity_update() {
    let mut manager = ConnectionManager::new();
    let peer = "127.0.0.1:8080".parse().unwrap();
    let identity = Address::from_data(b"peer1");
    
    let conn = Connection::new(peer, identity);
    let initial_activity = conn.last_activity;
    manager.add_connection(conn);
    
    // Small delay
    std::thread::sleep(std::time::Duration::from_millis(10));
    
    manager.update_activity(peer).unwrap();
    let updated_activity = manager.get_connection(peer).unwrap().last_activity;
    
    assert!(updated_activity >= initial_activity);
}
