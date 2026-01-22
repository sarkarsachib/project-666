//! Circuit management and lifecycle

use crate::types::Address;
use crate::network::error::{NetworkError, Result};
use crate::network::packet::{Packet, PacketType, CircuitHopSpec};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Circuit hop information
#[derive(Clone, Debug)]
pub struct CircuitHop {
    pub address: Address,
    pub public_key: [u8; 32],
}

/// Circuit build state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitBuildState {
    Idle,
    Building,
    Built,
    Established,
    Failing,
    Failed,
    Closed,
}

/// Circuit state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitState {
    Building,
    Established,
    Closing,
    Closed,
    Failed,
}

/// Circuit builder
pub struct CircuitBuilder {
    circuit_id: u32,
    hops: Vec<CircuitHopSpec>,
    forward_keys: Vec<[u8; 32]>,
    backward_keys: Vec<[u8; 32]>,
    state: CircuitBuildState,
}

impl CircuitBuilder {
    /// Create a new circuit builder
    pub fn new(circuit_id: u32) -> Self {
        CircuitBuilder {
            circuit_id,
            hops: Vec::new(),
            forward_keys: Vec::new(),
            backward_keys: Vec::new(),
            state: CircuitBuildState::Idle,
        }
    }

    /// Add a hop to the circuit
    pub fn add_hop(&mut self, hop: CircuitHopSpec) -> Result<()> {
        if self.hops.len() >= 10 {
            return Err(NetworkError::InvalidHopCount);
        }

        self.hops.push(hop);
        Ok(())
    }

    /// Start building the circuit
    pub fn build(&mut self) -> Result<BuildRequest> {
        if self.hops.is_empty() {
            return Err(NetworkError::InvalidHopCount);
        }

        self.state = CircuitBuildState::Building;

        // Create a CircuitBuildRequest packet
        let mut packet = Packet::new(PacketType::CircuitBuildRequest as u8);
        packet.header.packet_id = self.circuit_id;

        // For now, just create a simple build request
        // In a real implementation, this would include encrypted handshake data
        let build_request = BuildRequest {
            circuit_id: self.circuit_id,
            packet,
        };

        Ok(build_request)
    }

    /// Handle a circuit build reply
    pub fn handle_reply(&mut self, forward_keys: Vec<[u8; 32]>, backward_keys: Vec<[u8; 32]>, status: u8) -> Result<()> {
        if status == 0 {
            self.forward_keys = forward_keys;
            self.backward_keys = backward_keys;
            self.state = CircuitBuildState::Established;
            Ok(())
        } else {
            self.state = CircuitBuildState::Failed;
            Err(NetworkError::CircuitBuildFailed(status))
        }
    }

    /// Check if circuit is ready
    pub fn is_ready(&self) -> bool {
        self.state == CircuitBuildState::Established
    }

    /// Get current state
    pub fn get_state(&self) -> CircuitBuildState {
        self.state
    }

    /// Get circuit ID
    pub fn circuit_id(&self) -> u32 {
        self.circuit_id
    }

    /// Get hops
    pub fn hops(&self) -> &[CircuitHopSpec] {
        &self.hops
    }
}

/// Build request
pub struct BuildRequest {
    pub circuit_id: u32,
    pub packet: Packet,
}

/// Active circuit
#[derive(Clone, Debug)]
pub struct ActiveCircuit {
    pub id: u32,
    pub hops: Vec<CircuitHop>,
    pub forward_keys: Vec<[u8; 32]>,
    pub backward_keys: Vec<[u8; 32]>,
    pub state: CircuitState,
    pub created_at: u64,
    pub last_activity: u64,
}

impl ActiveCircuit {
    /// Create a new active circuit
    pub fn new(id: u32, hops: Vec<CircuitHop>, forward_keys: Vec<[u8; 32]>, backward_keys: Vec<[u8; 32]>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        ActiveCircuit {
            id,
            hops,
            forward_keys,
            backward_keys,
            state: CircuitState::Established,
            created_at: now,
            last_activity: now,
        }
    }

    /// Update activity timestamp
    pub fn touch(&mut self) {
        self.last_activity = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// Check if circuit is expired
    pub fn is_expired(&self, timeout_seconds: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now - self.last_activity > timeout_seconds
    }

    /// Get hop count
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }
}

/// Circuit manager
pub struct CircuitManager {
    circuits: HashMap<u32, ActiveCircuit>,
    circuit_id_counter: u32,
    max_circuits: usize,
}

impl CircuitManager {
    /// Create a new circuit manager
    pub fn new() -> Self {
        CircuitManager {
            circuits: HashMap::new(),
            circuit_id_counter: 1,
            max_circuits: 1000,
        }
    }

    /// Create a new circuit manager with custom limits
    pub fn with_max_circuits(max_circuits: usize) -> Self {
        CircuitManager {
            circuits: HashMap::new(),
            circuit_id_counter: 1,
            max_circuits,
        }
    }

    /// Get next circuit ID
    fn next_circuit_id(&mut self) -> u32 {
        let id = self.circuit_id_counter;
        self.circuit_id_counter = self.circuit_id_counter.wrapping_add(1);
        id
    }

    /// Create a new circuit
    pub fn create_circuit(&mut self, hops: Vec<CircuitHop>) -> Result<u32> {
        if self.circuits.len() >= self.max_circuits {
            return Err(NetworkError::MaxCircuitsExceeded);
        }

        let circuit_id = self.next_circuit_id();

        // Check if circuit already exists (shouldn't happen with wrapping counter)
        if self.circuits.contains_key(&circuit_id) {
            return Err(NetworkError::CircuitAlreadyExists(circuit_id));
        }

        // Generate keys for each hop (in real implementation, from DH exchange)
        let mut forward_keys = Vec::new();
        let mut backward_keys = Vec::new();
        
        for _ in 0..hops.len() {
            forward_keys.push([0u8; 32]); // Placeholder
            backward_keys.push([0u8; 32]); // Placeholder
        }

        let circuit = ActiveCircuit::new(circuit_id, hops, forward_keys, backward_keys);
        self.circuits.insert(circuit_id, circuit);

        Ok(circuit_id)
    }

    /// Get a circuit
    pub fn get_circuit(&self, id: u32) -> Option<&ActiveCircuit> {
        self.circuits.get(&id)
    }

    /// Get a mutable circuit
    pub fn get_circuit_mut(&mut self, id: u32) -> Option<&mut ActiveCircuit> {
        self.circuits.get_mut(&id)
    }

    /// Close a circuit
    pub fn close_circuit(&mut self, id: u32) -> Result<()> {
        if let Some(circuit) = self.circuits.get_mut(&id) {
            circuit.state = CircuitState::Closed;
            // We could remove it immediately, but keeping it allows for cleanup
            Ok(())
        } else {
            Err(NetworkError::CircuitNotFound(id))
        }
    }

    /// Remove a circuit completely
    pub fn remove_circuit(&mut self, id: u32) {
        self.circuits.remove(&id);
    }

    /// Get all circuit IDs
    pub fn all_circuits(&self) -> Vec<u32> {
        self.circuits.keys().copied().collect()
    }

    /// Get active circuit count
    pub fn active_circuit_count(&self) -> usize {
        self.circuits.values()
            .filter(|c| c.state == CircuitState::Established)
            .count()
    }

    /// Prune expired circuits
    pub fn prune_expired(&mut self, timeout_seconds: u64) {
        let expired: Vec<u32> = self.circuits
            .iter()
            .filter(|(_, circuit)| circuit.is_expired(timeout_seconds))
            .map(|(id, _)| *id)
            .collect();

        for id in expired {
            self.circuits.remove(&id);
        }
    }

    /// Update circuit activity
    pub fn touch_circuit(&mut self, id: u32) -> Result<()> {
        if let Some(circuit) = self.circuits.get_mut(&id) {
            circuit.touch();
            Ok(())
        } else {
            Err(NetworkError::CircuitNotFound(id))
        }
    }
}

impl Default for CircuitManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_builder() {
        let mut builder = CircuitBuilder::new(1);
        assert_eq!(builder.get_state(), CircuitBuildState::Idle);

        let hop = CircuitHopSpec {
            address: Address::from_data(b"hop1"),
            public_key: [1u8; 32],
            handshake_data: vec![],
        };

        builder.add_hop(hop).unwrap();
        assert_eq!(builder.hops().len(), 1);
    }

    #[test]
    fn test_circuit_manager() {
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
        ];

        let circuit_id = manager.create_circuit(hops).unwrap();
        assert_eq!(manager.active_circuit_count(), 1);

        let circuit = manager.get_circuit(circuit_id).unwrap();
        assert_eq!(circuit.hop_count(), 2);
        assert_eq!(circuit.state, CircuitState::Established);
    }

    #[test]
    fn test_circuit_close() {
        let mut manager = CircuitManager::new();
        let hops = vec![CircuitHop {
            address: Address::from_data(b"hop1"),
            public_key: [1u8; 32],
        }];

        let circuit_id = manager.create_circuit(hops).unwrap();
        manager.close_circuit(circuit_id).unwrap();

        let circuit = manager.get_circuit(circuit_id).unwrap();
        assert_eq!(circuit.state, CircuitState::Closed);
    }

    #[test]
    fn test_max_circuits() {
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
}
