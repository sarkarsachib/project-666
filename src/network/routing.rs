//! Onion routing engine

use crate::types::Address;
use crate::network::error::{NetworkError, Result};
use crate::aead;
use std::collections::HashMap;
use std::net::SocketAddr;

/// Onion layer for encryption
#[derive(Clone, Debug)]
pub struct OnionLayer {
    pub forward_key: [u8; 32],
    pub backward_key: [u8; 32],
    pub nonce_counter: u32,
    pub hop_address: Address,
}

impl OnionLayer {
    /// Create a new onion layer
    pub fn new(forward_key: [u8; 32], backward_key: [u8; 32], hop_address: Address) -> Self {
        OnionLayer {
            forward_key,
            backward_key,
            nonce_counter: 0,
            hop_address,
        }
    }

    /// Increment nonce counter
    pub fn increment_nonce(&mut self) {
        self.nonce_counter = self.nonce_counter.wrapping_add(1);
    }

    /// Get current nonce
    pub fn get_nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.nonce_counter.to_be_bytes());
        nonce
    }
}

/// Onion packet structure
#[derive(Clone, Debug)]
pub struct OnionPacket {
    pub layer_count: u8,
    pub encrypted_layers: Vec<Vec<u8>>,
}

impl OnionPacket {
    /// Create a new onion packet with layered encryption
    pub fn create(payload: &[u8], layers: &[OnionLayer]) -> Result<Self> {
        if layers.is_empty() {
            return Err(NetworkError::InvalidHopCount);
        }

        if layers.len() > 255 {
            return Err(NetworkError::InvalidHopCount);
        }

        let mut current_payload = payload.to_vec();
        let mut encrypted_layers = Vec::new();

        // Encrypt from innermost (last hop) to outermost (first hop)
        for layer in layers.iter().rev() {
            let nonce = layer.get_nonce();
            
            // Encrypt the current payload
            let (ciphertext, tag) = aead::encrypt(
                &layer.forward_key,
                &nonce,
                &[],
                &current_payload
            );

            // Combine ciphertext and tag
            let mut encrypted = ciphertext;
            encrypted.extend_from_slice(&tag);

            encrypted_layers.push(encrypted.clone());

            // For next iteration, encrypt the entire encrypted blob + metadata
            current_payload = encrypted;
        }

        // Reverse to get correct order (outermost first)
        encrypted_layers.reverse();

        Ok(OnionPacket {
            layer_count: layers.len() as u8,
            encrypted_layers,
        })
    }

    /// Decrypt one layer of the onion
    pub fn decrypt_layer(&mut self, layer: &OnionLayer) -> Result<Vec<u8>> {
        if self.encrypted_layers.is_empty() {
            return Err(NetworkError::DecryptionFailed("No layers to decrypt".to_string()));
        }

        let encrypted = &self.encrypted_layers[0];
        
        if encrypted.len() < 16 {
            return Err(NetworkError::DecryptionFailed("Layer too small".to_string()));
        }

        // Split ciphertext and tag
        let (ciphertext, tag_bytes) = encrypted.split_at(encrypted.len() - 16);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(tag_bytes);

        let nonce = layer.get_nonce();

        // Decrypt this layer
        let plaintext = aead::decrypt(
            &layer.forward_key,
            &nonce,
            &[],
            ciphertext,
            &tag
        ).map_err(|_| NetworkError::DecryptionFailed("AEAD decryption failed".to_string()))?;

        // Remove this layer
        self.encrypted_layers.remove(0);
        self.layer_count -= 1;

        Ok(plaintext)
    }

    /// Check if all layers have been decrypted
    pub fn is_fully_decrypted(&self) -> bool {
        self.encrypted_layers.is_empty()
    }

    /// Serialize to bytes
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        
        // Layer count
        data.push(self.layer_count);
        
        // Each layer: length (4 bytes) + data
        for layer in &self.encrypted_layers {
            let len = layer.len() as u32;
            data.extend_from_slice(&len.to_be_bytes());
            data.extend_from_slice(layer);
        }
        
        Ok(data)
    }

    /// Deserialize from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(NetworkError::InvalidPacketFormat);
        }

        let layer_count = data[0];
        let mut encrypted_layers = Vec::new();
        let mut offset = 1;

        for _ in 0..layer_count {
            if offset + 4 > data.len() {
                return Err(NetworkError::InvalidPacketFormat);
            }

            let len = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            offset += 4;

            if offset + len > data.len() {
                return Err(NetworkError::InvalidPacketFormat);
            }

            let layer = data[offset..offset + len].to_vec();
            encrypted_layers.push(layer);
            offset += len;
        }

        Ok(OnionPacket {
            layer_count,
            encrypted_layers,
        })
    }

    /// Verify packet integrity
    pub fn verify_integrity(&self) -> Result<()> {
        if self.layer_count as usize != self.encrypted_layers.len() {
            return Err(NetworkError::InvalidPacketFormat);
        }
        Ok(())
    }
}

/// Routing action
#[derive(Debug, Clone)]
pub enum RoutingAction {
    Forward(SocketAddr),
    Terminate(Address),
    DropSilent,
    ErrorReply(u16),
}

/// Routing decision
#[derive(Debug, Clone)]
pub struct RoutingDecision {
    pub next_hop: Address,
    pub action: RoutingAction,
}

/// Routing table entry
#[derive(Debug, Clone)]
struct RouteEntry {
    destination: Address,
    next_hop: SocketAddr,
    metric: u32,
}

/// Routing table
struct RoutingTable {
    routes: HashMap<Address, RouteEntry>,
}

impl RoutingTable {
    fn new() -> Self {
        RoutingTable {
            routes: HashMap::new(),
        }
    }

    fn add_route(&mut self, destination: Address, next_hop: SocketAddr, metric: u32) {
        let entry = RouteEntry {
            destination,
            next_hop,
            metric,
        };
        self.routes.insert(destination, entry);
    }

    fn get_route(&self, destination: &Address) -> Option<&RouteEntry> {
        self.routes.get(destination)
    }

    fn remove_route(&mut self, destination: &Address) {
        self.routes.remove(destination);
    }
}

/// Routing engine
pub struct RoutingEngine {
    routing_table: RoutingTable,
    local_address: Address,
}

impl RoutingEngine {
    /// Create a new routing engine
    pub fn new(local_address: Address) -> Self {
        RoutingEngine {
            routing_table: RoutingTable::new(),
            local_address,
        }
    }

    /// Add a route
    pub fn add_route(&mut self, destination: Address, next_hop: SocketAddr, metric: u32) {
        self.routing_table.add_route(destination, next_hop, metric);
    }

    /// Remove a route
    pub fn remove_route(&mut self, destination: &Address) {
        self.routing_table.remove_route(destination);
    }

    /// Make a routing decision
    pub fn decide(&self, destination: Address) -> Result<RoutingDecision> {
        // Check if this is for us
        if destination == self.local_address {
            return Ok(RoutingDecision {
                next_hop: destination,
                action: RoutingAction::Terminate(destination),
            });
        }

        // Look up in routing table
        if let Some(route) = self.routing_table.get_route(&destination) {
            Ok(RoutingDecision {
                next_hop: destination,
                action: RoutingAction::Forward(route.next_hop),
            })
        } else {
            Err(NetworkError::NoRoute(destination))
        }
    }

    /// Find a path to destination (simplified)
    pub fn find_path(&self, destination: Address, max_hops: usize) -> Result<Vec<Address>> {
        if max_hops == 0 {
            return Err(NetworkError::InvalidHopCount);
        }

        // Simplified path finding - in real implementation, this would use DHT
        if let Some(_route) = self.routing_table.get_route(&destination) {
            Ok(vec![destination])
        } else {
            Err(NetworkError::NoRoute(destination))
        }
    }

    /// Check if destination is reachable
    pub fn is_reachable(&self, destination: Address) -> bool {
        destination == self.local_address || 
        self.routing_table.get_route(&destination).is_some()
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
    fn test_onion_layer() {
        let mut layer = OnionLayer::new([1u8; 32], [2u8; 32], Address::from_data(b"test"));
        
        let nonce1 = layer.get_nonce();
        layer.increment_nonce();
        let nonce2 = layer.get_nonce();
        
        assert_ne!(nonce1, nonce2);
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
    fn test_onion_packet_decryption() {
        let payload = b"secret message";
        let layer1 = OnionLayer::new([1u8; 32], [2u8; 32], Address::from_data(b"hop1"));
        let layer2 = OnionLayer::new([3u8; 32], [4u8; 32], Address::from_data(b"hop2"));
        
        let layers = vec![layer1.clone(), layer2.clone()];
        let mut packet = OnionPacket::create(payload, &layers).unwrap();

        // Decrypt first layer
        let decrypted1 = packet.decrypt_layer(&layer1).unwrap();
        assert_eq!(packet.layer_count, 1);

        // Decrypt second layer
        let decrypted2 = packet.decrypt_layer(&layer2).unwrap();
        assert_eq!(packet.layer_count, 0);
        assert!(packet.is_fully_decrypted());

        // Final decrypted payload should match original
        assert_eq!(&decrypted2, payload);
    }

    #[test]
    fn test_onion_packet_serialization() {
        let payload = b"test";
        let layers = vec![
            OnionLayer::new([1u8; 32], [2u8; 32], Address::from_data(b"hop1")),
        ];

        let packet = OnionPacket::create(payload, &layers).unwrap();
        let serialized = packet.serialize().unwrap();
        let deserialized = OnionPacket::deserialize(&serialized).unwrap();

        assert_eq!(packet.layer_count, deserialized.layer_count);
        assert_eq!(packet.encrypted_layers.len(), deserialized.encrypted_layers.len());
    }

    #[test]
    fn test_routing_engine() {
        let local = Address::from_data(b"local");
        let mut engine = RoutingEngine::new(local);

        let dest = Address::from_data(b"destination");
        let next_hop: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        engine.add_route(dest, next_hop, 1);
        assert!(engine.is_reachable(dest));

        let decision = engine.decide(dest).unwrap();
        match decision.action {
            RoutingAction::Forward(addr) => assert_eq!(addr, next_hop),
            _ => panic!("Expected Forward action"),
        }
    }

    #[test]
    fn test_routing_to_self() {
        let local = Address::from_data(b"local");
        let engine = RoutingEngine::new(local);

        let decision = engine.decide(local).unwrap();
        match decision.action {
            RoutingAction::Terminate(addr) => assert_eq!(addr, local),
            _ => panic!("Expected Terminate action"),
        }
    }
}
