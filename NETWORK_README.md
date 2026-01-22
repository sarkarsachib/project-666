# Project 666 - Phase 3: Network Transport & Onion Routing

This document describes the Phase 3 implementation of Project 666, which adds low-level network transport and onion routing capabilities to the protocol.

## Overview

Phase 3 implements:
- UDP-based packet transport
- Network packet structures and serialization
- Onion routing with layered encryption
- Circuit management (multi-hop paths)
- Relay node logic
- Connection lifecycle management
- Peer discovery and reputation tracking

## Module Structure

```
src/network/
├── mod.rs           # Module exports and re-exports
├── error.rs         # Network error types
├── packet.rs        # Packet structures and serialization
├── transport.rs     # UDP transport layer
├── routing.rs       # Onion routing engine
├── circuit.rs       # Circuit management
├── relay.rs         # Relay node logic
├── connection.rs    # Connection lifecycle
└── peers.rs         # Peer tracking
```

## Key Components

### 1. Packet Layer (`packet.rs`)

**Packet Header (32 bytes):**
```
Magic (4):      0x66 0x66 0x66 0x01
Version (1):    Protocol version
Type (1):       Packet type (KeepAlive, CircuitBuild, Data, etc.)
Flags (2):      Reliability, priority flags
Packet ID (4):  Unique packet identifier
Sequence (4):   Sequence number for ordering
Timestamp (8):  Unix milliseconds
Checksum (4):   CRC32 checksum
Payload (var):  Encrypted payload
Footer (4):     Total packet length
```

**Packet Types:**
- `KeepAlive` - Liveness check
- `CircuitBuildRequest` - Request to build a circuit
- `CircuitBuildReply` - Reply to circuit build
- `CircuitData` - Data flowing through circuit
- `CircuitClose` - Close a circuit
- `RelayCell` - Relay-level cell
- `PaddingCell` - Traffic analysis resistance
- `AcknowledgementCell` - Packet acknowledgement
- `ErrorCell` - Error notification

### 2. Transport Layer (`transport.rs`)

UDP-based transport with:
- Send/receive packet handling
- Peer tracking and statistics
- Non-blocking I/O support
- Configurable timeouts
- Optional reliability layer (retransmission)

**Example:**
```rust
let mut transport = Transport::new("0.0.0.0:8666")?;
transport.set_nonblocking(true)?;

let peer = "127.0.0.1:8667".parse()?;
let packet = Packet::with_payload(PacketType::KeepAlive as u8, vec![]);
transport.send_packet(peer, &packet)?;

if let Some((from, packet)) = transport.recv_packet()? {
    println!("Received packet from {}", from);
}
```

### 3. Onion Routing (`routing.rs`)

Multi-layer encryption for anonymous communication:

```rust
// Create onion layers (one per hop)
let layers = vec![
    OnionLayer::new(hop1_key, hop1_back_key, hop1_address),
    OnionLayer::new(hop2_key, hop2_back_key, hop2_address),
    OnionLayer::new(hop3_key, hop3_back_key, hop3_address),
];

// Encrypt payload through all layers
let onion_packet = OnionPacket::create(&payload, &layers)?;

// Each hop decrypts one layer
let decrypted = onion_packet.decrypt_layer(&layers[0])?;
```

**Properties:**
- Each hop can only decrypt its own layer
- Intermediate hops cannot see final destination
- Uses ChaCha20-Poly1305 AEAD for each layer
- Forward secrecy through ephemeral keys

### 4. Circuit Management (`circuit.rs`)

Manages multi-hop circuits:

```rust
let mut manager = CircuitManager::new();

// Define circuit path
let hops = vec![
    CircuitHop { address: relay1, public_key: key1 },
    CircuitHop { address: relay2, public_key: key2 },
    CircuitHop { address: relay3, public_key: key3 },
];

// Create circuit
let circuit_id = manager.create_circuit(hops)?;

// Send data through circuit
manager.touch_circuit(circuit_id)?; // Update activity

// Close circuit
manager.close_circuit(circuit_id)?;
```

**Circuit Lifecycle:**
1. `Idle` - Not yet built
2. `Building` - Waiting for hop replies
3. `Built` - All hops added
4. `Established` - Ready for data
5. `Closing` - Shutting down
6. `Closed` - Terminated

### 5. Relay Nodes (`relay.rs`)

Relay nodes forward encrypted cells:

```rust
let (secret, public) = ed25519::generate_keypair(&seed);
let mut relay = RelayNode::new(local_address, (secret, public));

// Add a relay circuit
let state = RelayCircuitState::new(
    incoming_circuit_id,
    outgoing_circuit_id,
    forward_key,
    backward_key
);
relay.add_relay_circuit(circuit_id, state);

// Process incoming cell
let (next_hop, decrypted) = relay.process_circuit_data(
    circuit_id,
    &encrypted_cell
)?;
```

**Relay Cell Structure:**
```
Command (1):    Cell command type
Stream ID (2):  Stream identifier
Recognized (2): Must be 0 after correct decryption
Digest (4):     Running hash of cells
Length (2):     Payload length
Data (var):     Cell payload
```

### 6. Connection Management (`connection.rs`)

Manages peer connections:

```rust
let mut conn_manager = ConnectionManager::new();

// Create connection
let conn = Connection::new(peer_addr, peer_identity);
conn_manager.add_connection(conn);

// State transitions
conn_manager.set_state(peer_addr, ConnectionState::Handshaking)?;
conn_manager.set_state(peer_addr, ConnectionState::Established)?;

// Update activity
conn_manager.update_activity(peer_addr)?;

// Prune stale connections
conn_manager.prune_stale(timeout_seconds);
```

**Connection States:**
- `Connecting` - Initial connection
- `Handshaking` - Key exchange in progress
- `Established` - Active connection
- `Closing` - Graceful shutdown
- `Closed` - Connection terminated

### 7. Peer Tracking (`peers.rs`)

Tracks peers with reputation:

```rust
let mut tracker = PeerTracker::new();

// Discover peer
tracker.discover_peer(peer_address, public_key);
tracker.learn_socket(&peer_address, socket_addr);

// Track interactions
tracker.record_success(&peer_address, latency_ms);
tracker.record_failure(&peer_address);

// Find reliable peers
let reliable = tracker.find_reliable_peers(min_reputation);
```

**Reputation System:**
- Success: +1 reputation
- Failure: -2 reputation
- Tracks latency history (last 10 samples)
- Success rate calculation
- Automatic pruning of stale peers

## Network Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Application Layer (Phase 4+)                                │
│ (DHT, Resolution, Services)                                 │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│ Circuit Layer (Phase 3)                                     │
│ - CircuitManager                                            │
│ - CircuitBuilder                                            │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│ Routing Layer (Phase 3)                                     │
│ - RoutingEngine                                             │
│ - OnionPacket                                               │
│ - RelayNode                                                 │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│ Transport Layer (Phase 3)                                   │
│ - Transport (UDP)                                           │
│ - Packet                                                    │
│ - ConnectionManager                                         │
└────────────────────┬────────────────────────────────────────┘
                     │
        ┌────────────▼────────────┐
        │   UDP Socket            │
        │ (std::net::UdpSocket)   │
        └─────────────────────────┘
```

## Testing

### Unit Tests

```bash
# Run all network tests
cargo test --test network_tests

# Run circuit tests
cargo test --test circuit_tests

# Run relay tests
cargo test --test relay_tests

# Run integration tests
cargo test --test integration_tests
```

### Test Coverage

- **Packet Tests**: Serialization, checksums, roundtrip
- **Transport Tests**: UDP send/receive, peer management
- **Routing Tests**: Onion encryption/decryption, path finding
- **Circuit Tests**: Creation, state transitions, closure
- **Relay Tests**: Cell processing, multi-hop forwarding
- **Integration Tests**: End-to-end circuit setup and data flow

### Benchmarks

```bash
# Run network benchmarks
cargo bench --bench network_bench
```

Benchmarks measure:
- Packet serialization throughput
- Onion encryption/decryption (3-hop, 5-hop)
- Circuit creation speed
- Relay cell processing
- Peer operations

## Performance Targets

| Operation | Target | Actual (will vary) |
|-----------|--------|-------------------|
| Packet serialization | >10,000/sec | TBD |
| Onion encryption (3-hop) | >1,000/sec | TBD |
| Circuit creation | >100/sec | TBD |
| Relay cell processing | >5,000/sec | TBD |

## Security Properties

1. **Traffic Analysis Resistance**:
   - Fixed packet sizes (where possible)
   - Padding cells for traffic shaping
   - Constant-time operations

2. **Forward Secrecy**:
   - Ephemeral circuit keys
   - Independent layer keys
   - No key reuse across circuits

3. **Unlinkability**:
   - No correlation between circuit hops
   - Encrypted at each layer
   - No identifiable patterns

4. **Integrity**:
   - AEAD for all encrypted data
   - Packet checksums (CRC32)
   - Digest chains in relay cells

## Constants

See `src/constants.rs` for network-specific constants:

- `PACKET_HEADER_SIZE`: 32 bytes
- `MAX_PACKET_SIZE`: 65536 bytes (64 KB)
- `MAX_CIRCUITS`: 10000 circuits per node
- `CIRCUIT_IDLE_TIMEOUT_SECS`: 3600 seconds (1 hour)
- `CONNECTION_IDLE_TIMEOUT_SECS`: 300 seconds (5 minutes)
- `PEER_STALE_THRESHOLD_SECS`: 3600 seconds (1 hour)

## Error Handling

All network operations return `Result<T, NetworkError>`:

```rust
pub enum NetworkError {
    // Transport errors
    SocketError(String),
    BindError(String),
    SendError(String),
    RecvError(String),
    TimeoutError,
    
    // Protocol errors
    InvalidPacketFormat,
    ChecksumMismatch,
    VersionMismatch,
    UnknownPacketType,
    
    // Routing errors
    NoRoute(Address),
    CircuitNotFound(u32),
    UnreachablePeer,
    
    // Circuit errors
    CircuitBuildFailed(u8),
    InvalidHopCount,
    MaxCircuitsExceeded,
    
    // Encryption errors
    EncryptionFailed(String),
    DecryptionFailed(String),
    AuthenticationFailed,
}
```

## Future Enhancements (Phase 4+)

- DHT integration for peer discovery
- Distributed address resolution
- Bandwidth metering and throttling
- Circuit pooling and reuse
- Advanced traffic analysis resistance
- Congestion control
- UDP hole punching for NAT traversal

## Dependencies

Phase 3 uses **zero external dependencies** for networking:
- Standard library `std::net::UdpSocket` only
- All protocol logic implemented from scratch
- Reuses Phase 1 cryptography (ChaCha20-Poly1305, Ed25519, SHA-256)

## Integration with Phase 1 & 2

- **Phase 1 (Crypto)**: Uses ChaCha20-Poly1305 for onion encryption, Ed25519 for relay identity
- **Phase 2 (Types)**: Minimal - added `Address` type and `Queue` collection
- **Phase 3 (Network)**: Complete transport, routing, and circuit management

## Status

✅ **Complete**:
- Packet structures and serialization
- UDP transport layer
- Onion routing engine
- Circuit management
- Relay node logic
- Connection lifecycle
- Peer tracking
- Comprehensive tests
- Performance benchmarks

🔄 **In Progress**:
- None (Phase 3 complete)

📋 **Next (Phase 4)**:
- DHT implementation
- Distributed address resolution
- Service discovery
- Full protocol integration

## License

MIT License - Same as Phase 1

## Authors

Project 666 Team
