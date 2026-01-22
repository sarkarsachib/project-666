//! Relay node logic and cell processing

use crate::types::Address;
use crate::network::error::{NetworkError, Result};
use crate::network::packet::Packet;
use crate::aead;
use crate::sha256::Sha256;
use crate::ed25519::{PublicKey, SecretKey};
use std::collections::HashMap;
use std::net::SocketAddr;

/// Relay circuit state
#[derive(Clone, Debug)]
pub struct RelayCircuitState {
    pub incoming_circuit_id: u32,
    pub outgoing_circuit_id: u32,
    pub forward_key: [u8; 32],
    pub backward_key: [u8; 32],
    pub nonce_counter_in: u32,
    pub nonce_counter_out: u32,
}

impl RelayCircuitState {
    /// Create a new relay circuit state
    pub fn new(
        incoming_circuit_id: u32,
        outgoing_circuit_id: u32,
        forward_key: [u8; 32],
        backward_key: [u8; 32],
    ) -> Self {
        RelayCircuitState {
            incoming_circuit_id,
            outgoing_circuit_id,
            forward_key,
            backward_key,
            nonce_counter_in: 0,
            nonce_counter_out: 0,
        }
    }

    /// Get forward nonce
    pub fn get_forward_nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.nonce_counter_out.to_be_bytes());
        nonce
    }

    /// Get backward nonce
    pub fn get_backward_nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.nonce_counter_in.to_be_bytes());
        nonce
    }

    /// Increment forward counter
    pub fn increment_forward(&mut self) {
        self.nonce_counter_out = self.nonce_counter_out.wrapping_add(1);
    }

    /// Increment backward counter
    pub fn increment_backward(&mut self) {
        self.nonce_counter_in = self.nonce_counter_in.wrapping_add(1);
    }
}

/// Relay cell commands
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RelayCellCommand {
    Begin = 1,
    Data = 2,
    End = 3,
    Connected = 4,
    Extend = 6,
    ExtendReply = 7,
}

impl RelayCellCommand {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(RelayCellCommand::Begin),
            2 => Some(RelayCellCommand::Data),
            3 => Some(RelayCellCommand::End),
            4 => Some(RelayCellCommand::Connected),
            6 => Some(RelayCellCommand::Extend),
            7 => Some(RelayCellCommand::ExtendReply),
            _ => None,
        }
    }
}

/// Relay cell structure
#[derive(Clone, Debug)]
pub struct RelayCell {
    pub command: u8,
    pub stream_id: u16,
    pub recognized: u16,
    pub digest: [u8; 4],
    pub length: u16,
    pub data: Vec<u8>,
}

impl RelayCell {
    /// Create a new relay cell
    pub fn new(command: u8, stream_id: u16, data: Vec<u8>) -> Self {
        RelayCell {
            command,
            stream_id,
            recognized: 0,
            digest: [0u8; 4],
            length: data.len() as u16,
            data,
        }
    }

    /// Encrypt relay cell
    pub fn encrypt(&self, forward_key: &[u8; 32], nonce_counter: u32) -> Result<Vec<u8>> {
        // Serialize the relay cell
        let plaintext = self.serialize();

        // Create nonce
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&nonce_counter.to_be_bytes());

        // Encrypt with AEAD
        let (ciphertext, tag) = aead::encrypt(forward_key, &nonce, &[], &plaintext);

        // Combine ciphertext and tag
        let mut encrypted = ciphertext;
        encrypted.extend_from_slice(&tag);

        Ok(encrypted)
    }

    /// Decrypt relay cell
    pub fn decrypt(data: &[u8], forward_key: &[u8; 32], nonce_counter: u32) -> Result<Self> {
        if data.len() < 16 {
            return Err(NetworkError::DecryptionFailed("Data too short".to_string()));
        }

        // Split ciphertext and tag
        let (ciphertext, tag_bytes) = data.split_at(data.len() - 16);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(tag_bytes);

        // Create nonce
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&nonce_counter.to_be_bytes());

        // Decrypt with AEAD
        let plaintext = aead::decrypt(forward_key, &nonce, &[], ciphertext, &tag)
            .map_err(|_| NetworkError::DecryptionFailed("AEAD failed".to_string()))?;

        // Deserialize
        RelayCell::deserialize(&plaintext)
    }

    /// Check if cell is recognized (recognized field should be 0 after correct decryption)
    pub fn is_recognized(&self) -> bool {
        self.recognized == 0
    }

    /// Update digest based on cell contents
    pub fn update_digest(&mut self, key: &[u8; 32]) -> Result<()> {
        // Simple digest: SHA-256 of (key || cell_data), truncated to 4 bytes
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(&self.serialize());
        let hash = hasher.finalize();
        
        self.digest.copy_from_slice(&hash[0..4]);
        Ok(())
    }

    /// Serialize relay cell
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        data.push(self.command);
        data.extend_from_slice(&self.stream_id.to_be_bytes());
        data.extend_from_slice(&self.recognized.to_be_bytes());
        data.extend_from_slice(&self.digest);
        data.extend_from_slice(&self.length.to_be_bytes());
        data.extend_from_slice(&self.data);
        
        data
    }

    /// Deserialize relay cell
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < 11 {
            return Err(NetworkError::InvalidPacketFormat);
        }

        let command = data[0];
        let stream_id = u16::from_be_bytes([data[1], data[2]]);
        let recognized = u16::from_be_bytes([data[3], data[4]]);
        
        let mut digest = [0u8; 4];
        digest.copy_from_slice(&data[5..9]);
        
        let length = u16::from_be_bytes([data[9], data[10]]);
        
        let cell_data = if data.len() > 11 {
            data[11..].to_vec()
        } else {
            Vec::new()
        };

        Ok(RelayCell {
            command,
            stream_id,
            recognized,
            digest,
            length,
            data: cell_data,
        })
    }
}

/// Relay node
pub struct RelayNode {
    local_address: Address,
    local_keys: (SecretKey, PublicKey),
    active_circuits: HashMap<u32, RelayCircuitState>,
}

impl RelayNode {
    /// Create a new relay node
    pub fn new(address: Address, keys: (SecretKey, PublicKey)) -> Self {
        RelayNode {
            local_address: address,
            local_keys: keys,
            active_circuits: HashMap::new(),
        }
    }

    /// Process circuit build request
    pub fn process_circuit_build(
        &mut self,
        _incoming_peer: SocketAddr,
        _packet: &Packet,
    ) -> Result<Option<Packet>> {
        // In real implementation:
        // 1. Verify the request
        // 2. Perform DH key exchange
        // 3. Derive shared keys
        // 4. Store circuit state
        // 5. Return reply packet
        
        // For now, return None (not implemented)
        Err(NetworkError::NotImplemented)
    }

    /// Process circuit data (decrypt and forward)
    pub fn process_circuit_data(
        &mut self,
        circuit_id: u32,
        encrypted_cell: &[u8],
    ) -> Result<(Option<SocketAddr>, Vec<u8>)> {
        // Get circuit state
        let state = self.active_circuits.get_mut(&circuit_id)
            .ok_or(NetworkError::CircuitNotFound(circuit_id))?;

        // Decrypt the cell
        let cell = RelayCell::decrypt(
            encrypted_cell,
            &state.forward_key,
            state.nonce_counter_in
        )?;

        // Increment nonce counter
        state.increment_backward();

        // Check if this cell is for us or should be forwarded
        if cell.is_recognized() {
            // This is the final hop
            Ok((None, cell.data))
        } else {
            // Forward to next hop (in real implementation, look up next hop)
            Err(NetworkError::NotImplemented)
        }
    }

    /// Process circuit close
    pub fn process_circuit_close(&mut self, circuit_id: u32) -> Result<()> {
        self.active_circuits.remove(&circuit_id);
        Ok(())
    }

    /// Check if this node is relay for a circuit
    pub fn is_relay_for(&self, circuit_id: u32) -> bool {
        self.active_circuits.contains_key(&circuit_id)
    }

    /// Add a circuit to relay
    pub fn add_relay_circuit(&mut self, circuit_id: u32, state: RelayCircuitState) {
        self.active_circuits.insert(circuit_id, state);
    }

    /// Get active circuit count
    pub fn active_circuit_count(&self) -> usize {
        self.active_circuits.len()
    }

    /// Get local address
    pub fn local_address(&self) -> Address {
        self.local_address
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_circuit_state() {
        let state = RelayCircuitState::new(1, 2, [1u8; 32], [2u8; 32]);
        assert_eq!(state.incoming_circuit_id, 1);
        assert_eq!(state.outgoing_circuit_id, 2);
        assert_eq!(state.nonce_counter_in, 0);
        assert_eq!(state.nonce_counter_out, 0);
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
            42,
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
    fn test_relay_node_creation() {
        use crate::ed25519;
        
        let address = Address::from_data(b"relay1");
        let (secret, public) = ed25519::generate_keypair(&[1u8; 32]);
        
        let relay = RelayNode::new(address, (secret, public));
        assert_eq!(relay.local_address(), address);
        assert_eq!(relay.active_circuit_count(), 0);
    }

    #[test]
    fn test_relay_circuit_management() {
        use crate::ed25519;
        
        let address = Address::from_data(b"relay1");
        let (secret, public) = ed25519::generate_keypair(&[1u8; 32]);
        let mut relay = RelayNode::new(address, (secret, public));
        
        let state = RelayCircuitState::new(1, 2, [1u8; 32], [2u8; 32]);
        relay.add_relay_circuit(1, state);
        
        assert!(relay.is_relay_for(1));
        assert_eq!(relay.active_circuit_count(), 1);
        
        relay.process_circuit_close(1).unwrap();
        assert!(!relay.is_relay_for(1));
        assert_eq!(relay.active_circuit_count(), 0);
    }
}
