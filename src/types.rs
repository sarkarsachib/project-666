//! Core types for Project 666
//!
//! This module provides the basic types used throughout the protocol.

use crate::sha256::Sha256;
use std::fmt;

/// Opaque address (16-byte hash)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address([u8; 16]);

impl Address {
    /// Create a new address from a 16-byte array
    pub fn new(bytes: [u8; 16]) -> Self {
        Address(bytes)
    }

    /// Create address from public key (SHA-256 hash, truncated to 16 bytes)
    pub fn from_public_key(public_key: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        let hash = hasher.finalize();
        
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&hash[0..16]);
        Address(addr)
    }

    /// Create address from arbitrary data
    pub fn from_data(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&hash[0..16]);
        Address(addr)
    }

    /// Get the raw bytes of this address
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Convert to byte array
    pub fn to_bytes(&self) -> [u8; 16] {
        self.0
    }

    /// Create from slice (returns None if not exactly 16 bytes)
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 16 {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(bytes);
            Some(Address(addr))
        } else {
            None
        }
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Address({})", hex::encode(&self.0))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl Default for Address {
    fn default() -> Self {
        Address([0u8; 16])
    }
}

/// Hex encoding utilities
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }

    #[allow(dead_code)]
    pub fn decode(s: &str) -> Result<Vec<u8>, &'static str> {
        if s.len() % 2 != 0 {
            return Err("Hex string must have even length");
        }

        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i+2], 16)
                    .map_err(|_| "Invalid hex character")
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_creation() {
        let bytes = [1u8; 16];
        let addr = Address::new(bytes);
        assert_eq!(addr.as_bytes(), &bytes);
    }

    #[test]
    fn test_address_from_public_key() {
        let pubkey = [42u8; 32];
        let addr = Address::from_public_key(&pubkey);
        assert_eq!(addr.as_bytes().len(), 16);
    }

    #[test]
    fn test_address_from_slice() {
        let bytes = [1u8; 16];
        let addr = Address::from_slice(&bytes).unwrap();
        assert_eq!(addr.as_bytes(), &bytes);

        // Wrong size
        assert!(Address::from_slice(&[1u8; 15]).is_none());
        assert!(Address::from_slice(&[1u8; 17]).is_none());
    }
}
