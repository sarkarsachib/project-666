//! Circuit construction and management tests

use project_666::network::*;
use project_666::types::Address;

#[test]
fn test_circuit_builder_creation() {
    let builder = CircuitBuilder::new(1);
    assert_eq!(builder.circuit_id(), 1);
    assert_eq!(builder.get_state(), CircuitBuildState::Idle);
    assert_eq!(builder.hops().len(), 0);
}

#[test]
fn test_circuit_builder_add_hop() {
    let mut builder = CircuitBuilder::new(1);
    
    let hop = CircuitHopSpec {
        address: Address::from_data(b"hop1"),
        public_key: [1u8; 32],
        handshake_data: vec![],
    };
    
    builder.add_hop(hop).unwrap();
    assert_eq!(builder.hops().len(), 1);
}

#[test]
fn test_circuit_builder_max_hops() {
    let mut builder = CircuitBuilder::new(1);
    
    // Add 10 hops (max)
    for i in 0..10 {
        let hop = CircuitHopSpec {
            address: Address::from_data(&[i]),
            public_key: [i; 32],
            handshake_data: vec![],
        };
        builder.add_hop(hop).unwrap();
    }
    
    // 11th hop should fail
    let hop = CircuitHopSpec {
        address: Address::from_data(b"too_many"),
        public_key: [11u8; 32],
        handshake_data: vec![],
    };
    
    let result = builder.add_hop(hop);
    assert!(matches!(result, Err(NetworkError::InvalidHopCount)));
}

#[test]
fn test_circuit_builder_build() {
    let mut builder = CircuitBuilder::new(42);
    
    let hop = CircuitHopSpec {
        address: Address::from_data(b"hop1"),
        public_key: [1u8; 32],
        handshake_data: vec![],
    };
    
    builder.add_hop(hop).unwrap();
    
    let request = builder.build().unwrap();
    assert_eq!(request.circuit_id, 42);
    assert_eq!(builder.get_state(), CircuitBuildState::Building);
}

#[test]
fn test_circuit_builder_handle_reply() {
    let mut builder = CircuitBuilder::new(1);
    
    let hop = CircuitHopSpec {
        address: Address::from_data(b"hop1"),
        public_key: [1u8; 32],
        handshake_data: vec![],
    };
    
    builder.add_hop(hop).unwrap();
    builder.build().unwrap();
    
    // Successful reply
    let forward_keys = vec![[1u8; 32]];
    let backward_keys = vec![[2u8; 32]];
    builder.handle_reply(forward_keys, backward_keys, 0).unwrap();
    
    assert_eq!(builder.get_state(), CircuitBuildState::Established);
    assert!(builder.is_ready());
}

#[test]
fn test_circuit_builder_failed_reply() {
    let mut builder = CircuitBuilder::new(1);
    
    let hop = CircuitHopSpec {
        address: Address::from_data(b"hop1"),
        public_key: [1u8; 32],
        handshake_data: vec![],
    };
    
    builder.add_hop(hop).unwrap();
    builder.build().unwrap();
    
    // Failed reply
    let result = builder.handle_reply(vec![], vec![], 1);
    assert!(matches!(result, Err(NetworkError::CircuitBuildFailed(1))));
    assert_eq!(builder.get_state(), CircuitBuildState::Failed);
}

#[test]
fn test_circuit_manager_creation() {
    let manager = CircuitManager::new();
    assert_eq!(manager.active_circuit_count(), 0);
}

#[test]
fn test_circuit_manager_create_circuit() {
    let mut manager = CircuitManager::new();
    
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
    
    let circuit_id = manager.create_circuit(hops).unwrap();
    assert_eq!(manager.active_circuit_count(), 1);
    
    let circuit = manager.get_circuit(circuit_id).unwrap();
    assert_eq!(circuit.id, circuit_id);
    assert_eq!(circuit.hop_count(), 3);
    assert_eq!(circuit.state, CircuitState::Established);
}

#[test]
fn test_circuit_manager_get_circuit() {
    let mut manager = CircuitManager::new();
    
    let hops = vec![CircuitHop {
        address: Address::from_data(b"hop1"),
        public_key: [1u8; 32],
    }];
    
    let circuit_id = manager.create_circuit(hops).unwrap();
    
    assert!(manager.get_circuit(circuit_id).is_some());
    assert!(manager.get_circuit(999).is_none());
}

#[test]
fn test_circuit_manager_close_circuit() {
    let mut manager = CircuitManager::new();
    
    let hops = vec![CircuitHop {
        address: Address::from_data(b"hop1"),
        public_key: [1u8; 32],
    }];
    
    let circuit_id = manager.create_circuit(hops).unwrap();
    assert_eq!(manager.active_circuit_count(), 1);
    
    manager.close_circuit(circuit_id).unwrap();
    
    let circuit = manager.get_circuit(circuit_id).unwrap();
    assert_eq!(circuit.state, CircuitState::Closed);
    assert_eq!(manager.active_circuit_count(), 0);
}

#[test]
fn test_circuit_manager_remove_circuit() {
    let mut manager = CircuitManager::new();
    
    let hops = vec![CircuitHop {
        address: Address::from_data(b"hop1"),
        public_key: [1u8; 32],
    }];
    
    let circuit_id = manager.create_circuit(hops).unwrap();
    
    manager.remove_circuit(circuit_id);
    assert!(manager.get_circuit(circuit_id).is_none());
}

#[test]
fn test_circuit_manager_max_circuits() {
    let mut manager = CircuitManager::with_max_circuits(2);
    
    let hop = vec![CircuitHop {
        address: Address::from_data(b"hop1"),
        public_key: [1u8; 32],
    }];
    
    manager.create_circuit(hop.clone()).unwrap();
    manager.create_circuit(hop.clone()).unwrap();
    
    let result = manager.create_circuit(hop);
    assert!(matches!(result, Err(NetworkError::MaxCircuitsExceeded)));
}

#[test]
fn test_circuit_manager_all_circuits() {
    let mut manager = CircuitManager::new();
    
    let hop = vec![CircuitHop {
        address: Address::from_data(b"hop1"),
        public_key: [1u8; 32],
    }];
    
    let id1 = manager.create_circuit(hop.clone()).unwrap();
    let id2 = manager.create_circuit(hop.clone()).unwrap();
    let id3 = manager.create_circuit(hop).unwrap();
    
    let all_circuits = manager.all_circuits();
    assert_eq!(all_circuits.len(), 3);
    assert!(all_circuits.contains(&id1));
    assert!(all_circuits.contains(&id2));
    assert!(all_circuits.contains(&id3));
}

#[test]
fn test_circuit_manager_touch_circuit() {
    let mut manager = CircuitManager::new();
    
    let hops = vec![CircuitHop {
        address: Address::from_data(b"hop1"),
        public_key: [1u8; 32],
    }];
    
    let circuit_id = manager.create_circuit(hops).unwrap();
    let initial_activity = manager.get_circuit(circuit_id).unwrap().last_activity;
    
    std::thread::sleep(std::time::Duration::from_millis(10));
    
    manager.touch_circuit(circuit_id).unwrap();
    let updated_activity = manager.get_circuit(circuit_id).unwrap().last_activity;
    
    assert!(updated_activity >= initial_activity);
}

#[test]
fn test_active_circuit_expiration() {
    let hops = vec![CircuitHop {
        address: Address::from_data(b"hop1"),
        public_key: [1u8; 32],
    }];
    
    let mut circuit = ActiveCircuit::new(1, hops, vec![[1u8; 32]], vec![[2u8; 32]]);
    
    // Should not be expired immediately
    assert!(!circuit.is_expired(10));
    
    // Artificially set old timestamp
    circuit.last_activity = 0;
    
    // Should be expired now
    assert!(circuit.is_expired(10));
}

#[test]
fn test_circuit_manager_prune_expired() {
    let mut manager = CircuitManager::new();
    
    let hops = vec![CircuitHop {
        address: Address::from_data(b"hop1"),
        public_key: [1u8; 32],
    }];
    
    let circuit_id = manager.create_circuit(hops).unwrap();
    
    // Artificially expire the circuit
    if let Some(circuit) = manager.get_circuit_mut(circuit_id) {
        circuit.last_activity = 0;
    }
    
    manager.prune_expired(10);
    assert!(manager.get_circuit(circuit_id).is_none());
}
