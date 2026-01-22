//! Network performance benchmarks

use project_666::network::*;
use project_666::types::Address;
use std::time::Instant;

fn bench_packet_serialization(iterations: usize) -> (u128, u128) {
    let packet = Packet::with_payload(
        PacketType::CircuitData as u8,
        vec![0u8; 1024]
    );
    
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = packet.serialize().unwrap();
    }
    let serialize_duration = start.elapsed().as_micros();
    
    let serialized = packet.serialize().unwrap();
    
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = Packet::deserialize(&serialized).unwrap();
    }
    let deserialize_duration = start.elapsed().as_micros();
    
    (serialize_duration, deserialize_duration)
}

fn bench_onion_encryption(layers: usize, iterations: usize) -> (u128, u128) {
    let payload = vec![0u8; 1024];
    
    let mut layer_specs = Vec::new();
    for i in 0..layers {
        layer_specs.push(OnionLayer::new(
            [i as u8; 32],
            [(i + 100) as u8; 32],
            Address::from_data(&[i as u8])
        ));
    }
    
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = OnionPacket::create(&payload, &layer_specs).unwrap();
    }
    let encrypt_duration = start.elapsed().as_micros();
    
    let packet = OnionPacket::create(&payload, &layer_specs).unwrap();
    
    let start = Instant::now();
    for _ in 0..iterations {
        let mut pkt = packet.clone();
        for layer in &layer_specs {
            let _ = pkt.decrypt_layer(layer).unwrap();
        }
    }
    let decrypt_duration = start.elapsed().as_micros();
    
    (encrypt_duration, decrypt_duration)
}

fn bench_circuit_creation(circuits: usize) -> u128 {
    let mut manager = CircuitManager::new();
    
    let start = Instant::now();
    for i in 0..circuits {
        let hops = vec![
            CircuitHop {
                address: Address::from_data(&[i as u8, 0]),
                public_key: [i as u8; 32],
            },
            CircuitHop {
                address: Address::from_data(&[i as u8, 1]),
                public_key: [(i + 1) as u8; 32],
            },
            CircuitHop {
                address: Address::from_data(&[i as u8, 2]),
                public_key: [(i + 2) as u8; 32],
            },
        ];
        let _ = manager.create_circuit(hops).unwrap();
    }
    start.elapsed().as_micros()
}

fn bench_relay_cell_processing(iterations: usize) -> (u128, u128) {
    let key = [42u8; 32];
    let cell = RelayCell::new(
        RelayCellCommand::Data as u8,
        1,
        vec![0u8; 512]
    );
    
    let start = Instant::now();
    for i in 0..iterations {
        let _ = cell.encrypt(&key, i as u32).unwrap();
    }
    let encrypt_duration = start.elapsed().as_micros();
    
    let encrypted = cell.encrypt(&key, 0).unwrap();
    
    let start = Instant::now();
    for i in 0..iterations {
        let _ = RelayCell::decrypt(&encrypted, &key, i as u32);
    }
    let decrypt_duration = start.elapsed().as_micros();
    
    (encrypt_duration, decrypt_duration)
}

fn bench_peer_operations(peers: usize) -> (u128, u128, u128) {
    let mut tracker = PeerTracker::new();
    
    // Discover peers
    let start = Instant::now();
    for i in 0..peers {
        let address = Address::from_data(&[i as u8]);
        tracker.discover_peer(address, [i as u8; 32]);
    }
    let discover_duration = start.elapsed().as_micros();
    
    // Record successes
    let start = Instant::now();
    for i in 0..peers {
        let address = Address::from_data(&[i as u8]);
        tracker.record_success(&address, 100);
    }
    let success_duration = start.elapsed().as_micros();
    
    // Find reliable peers
    let start = Instant::now();
    let _ = tracker.find_reliable_peers(0);
    let find_duration = start.elapsed().as_micros();
    
    (discover_duration, success_duration, find_duration)
}

fn main() {
    println!("=== Project 666 Network Benchmarks ===\n");
    
    // Packet serialization
    println!("Packet Serialization (1000 iterations, 1KB payload):");
    let (ser, deser) = bench_packet_serialization(1000);
    println!("  Serialize: {} µs ({:.2} µs/op)", ser, ser as f64 / 1000.0);
    println!("  Deserialize: {} µs ({:.2} µs/op)", deser, deser as f64 / 1000.0);
    println!();
    
    // Onion encryption - 3 hops
    println!("Onion Encryption - 3 hops (100 iterations, 1KB payload):");
    let (enc, dec) = bench_onion_encryption(3, 100);
    println!("  Encrypt: {} µs ({:.2} µs/op)", enc, enc as f64 / 100.0);
    println!("  Decrypt: {} µs ({:.2} µs/op)", dec, dec as f64 / 100.0);
    println!();
    
    // Onion encryption - 5 hops
    println!("Onion Encryption - 5 hops (100 iterations, 1KB payload):");
    let (enc, dec) = bench_onion_encryption(5, 100);
    println!("  Encrypt: {} µs ({:.2} µs/op)", enc, enc as f64 / 100.0);
    println!("  Decrypt: {} µs ({:.2} µs/op)", dec, dec as f64 / 100.0);
    println!();
    
    // Circuit creation
    println!("Circuit Creation (1000 circuits, 3 hops each):");
    let duration = bench_circuit_creation(1000);
    println!("  Total: {} µs ({:.2} µs/circuit)", duration, duration as f64 / 1000.0);
    println!();
    
    // Relay cell processing
    println!("Relay Cell Processing (1000 iterations, 512B payload):");
    let (enc, dec) = bench_relay_cell_processing(1000);
    println!("  Encrypt: {} µs ({:.2} µs/op)", enc, enc as f64 / 1000.0);
    println!("  Decrypt: {} µs ({:.2} µs/op)", dec, dec as f64 / 1000.0);
    println!();
    
    // Peer operations
    println!("Peer Operations (1000 peers):");
    let (disc, succ, find) = bench_peer_operations(1000);
    println!("  Discover: {} µs ({:.2} µs/peer)", disc, disc as f64 / 1000.0);
    println!("  Record Success: {} µs ({:.2} µs/peer)", succ, succ as f64 / 1000.0);
    println!("  Find Reliable: {} µs", find);
    println!();
    
    // Throughput calculations
    println!("=== Throughput Estimates ===");
    let packet_throughput = 1_000_000.0 / (ser as f64 / 1000.0);
    println!("Packet Serialization: {:.0} packets/second", packet_throughput);
    
    let onion_throughput = 1_000_000.0 / (enc as f64 / 100.0);
    println!("Onion Encryption (3-hop): {:.0} packets/second", onion_throughput);
    
    let circuit_throughput = 1_000_000.0 / (duration as f64 / 1000.0);
    println!("Circuit Creation: {:.0} circuits/second", circuit_throughput);
    
    println!();
    println!("=== Benchmarks Complete ===");
}
