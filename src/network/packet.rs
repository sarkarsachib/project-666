//! Network packet structures and serialization

use crate::types::Address;
use crate::network::error::{NetworkError, Result};
use std::time::{SystemTime, UNIX_EPOCH};

/// Packet header (32 bytes)
#[derive(Clone, Debug)]
pub struct PacketHeader {
    pub magic: [u8; 4],
    pub version: u8,
    pub packet_type: u8,
    pub flags: u16,
    pub packet_id: u32,
    pub sequence: u32,
    pub timestamp_ms: u64,
    pub checksum: u32,
}

/// Complete packet
#[derive(Clone, Debug)]
pub struct Packet {
    pub header: PacketHeader,
    pub payload: Vec<u8>,
}

/// Packet types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Reserved = 0,
    KeepAlive = 1,
    CircuitBuildRequest = 2,
    CircuitBuildReply = 3,
    CircuitData = 4,
    CircuitClose = 5,
    RelayCell = 6,
    PaddingCell = 7,
    AcknowledgementCell = 8,
    ErrorCell = 9,
}

impl PacketType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(PacketType::Reserved),
            1 => Some(PacketType::KeepAlive),
            2 => Some(PacketType::CircuitBuildRequest),
            3 => Some(PacketType::CircuitBuildReply),
            4 => Some(PacketType::CircuitData),
            5 => Some(PacketType::CircuitClose),
            6 => Some(PacketType::RelayCell),
            7 => Some(PacketType::PaddingCell),
            8 => Some(PacketType::AcknowledgementCell),
            9 => Some(PacketType::ErrorCell),
            _ => None,
        }
    }
}

/// Packet payload types
#[derive(Clone, Debug)]
pub enum PacketPayload {
    KeepAlive,
    
    CircuitBuildRequest {
        circuit_id: u32,
        hops: Vec<CircuitHopSpec>,
    },
    
    CircuitBuildReply {
        circuit_id: u32,
        status: u8,
        forward_keys: Vec<[u8; 32]>,
        backward_keys: Vec<[u8; 32]>,
    },
    
    CircuitData {
        circuit_id: u32,
        encrypted_payload: Vec<u8>,
    },
    
    CircuitClose {
        circuit_id: u32,
        reason: u8,
    },
    
    RelayCell {
        circuit_id: u32,
        hop_index: u8,
        encrypted_cell: Vec<u8>,
    },
    
    PaddingCell {
        length: u16,
        padding: Vec<u8>,
    },
    
    AcknowledgementCell {
        packet_id: u32,
        status: u8,
    },
    
    ErrorCell {
        code: u16,
        message: String,
    },
}

/// Circuit hop specification
#[derive(Clone, Debug)]
pub struct CircuitHopSpec {
    pub address: Address,
    pub public_key: [u8; 32],
    pub handshake_data: Vec<u8>,
}

impl PacketHeader {
    /// Create a new packet header
    pub fn new(packet_type: u8) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        PacketHeader {
            magic: [0x66, 0x66, 0x66, 0x01],
            version: 1,
            packet_type,
            flags: 0,
            packet_id: 0,
            sequence: 0,
            timestamp_ms: now,
            checksum: 0,
        }
    }

    /// Serialize header to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32);
        
        // Magic (4 bytes)
        bytes.extend_from_slice(&self.magic);
        
        // Version (1 byte)
        bytes.push(self.version);
        
        // Packet type (1 byte)
        bytes.push(self.packet_type);
        
        // Flags (2 bytes, big-endian)
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        
        // Packet ID (4 bytes, big-endian)
        bytes.extend_from_slice(&self.packet_id.to_be_bytes());
        
        // Sequence (4 bytes, big-endian)
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        
        // Timestamp (8 bytes, big-endian)
        bytes.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        
        // Checksum (4 bytes, big-endian)
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        
        bytes
    }

    /// Deserialize header from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < 32 {
            return Err(NetworkError::InvalidPacketFormat);
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&data[0..4]);

        let version = data[4];
        let packet_type = data[5];
        let flags = u16::from_be_bytes([data[6], data[7]]);
        let packet_id = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let sequence = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let timestamp_ms = u64::from_be_bytes([
            data[16], data[17], data[18], data[19],
            data[20], data[21], data[22], data[23]
        ]);
        let checksum = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);

        Ok(PacketHeader {
            magic,
            version,
            packet_type,
            flags,
            packet_id,
            sequence,
            timestamp_ms,
            checksum,
        })
    }
}

impl Packet {
    /// Create a new packet
    pub fn new(packet_type: u8) -> Self {
        Packet {
            header: PacketHeader::new(packet_type),
            payload: Vec::new(),
        }
    }

    /// Create a packet with payload
    pub fn with_payload(packet_type: u8, payload: Vec<u8>) -> Self {
        Packet {
            header: PacketHeader::new(packet_type),
            payload,
        }
    }

    /// Calculate CRC32 checksum
    pub fn calculate_checksum(data: &[u8]) -> u32 {
        // Simple CRC32 implementation
        const CRC32_TABLE: [u32; 256] = generate_crc32_table();
        
        let mut crc: u32 = 0xffffffff;
        for &byte in data {
            let index = ((crc ^ byte as u32) & 0xff) as usize;
            crc = (crc >> 8) ^ CRC32_TABLE[index];
        }
        !crc
    }

    /// Verify checksum
    pub fn verify_checksum(&self) -> bool {
        // Serialize without checksum
        let mut data = self.header.serialize();
        data[24..28].copy_from_slice(&[0, 0, 0, 0]); // Zero out checksum
        data.extend_from_slice(&self.payload);
        
        // Add length footer
        let length = (data.len() + 4) as u32;
        data.extend_from_slice(&length.to_be_bytes());
        
        let calculated = Self::calculate_checksum(&data);
        calculated == self.header.checksum
    }

    /// Serialize packet to bytes
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        
        // Create header with zeroed checksum
        let mut header = self.header.clone();
        header.checksum = 0;
        data.extend_from_slice(&header.serialize());
        
        // Add payload
        data.extend_from_slice(&self.payload);
        
        // Add length footer
        let length = (data.len() + 8) as u32; // +8 for checksum and length
        data.extend_from_slice(&length.to_be_bytes());
        
        // Calculate checksum over everything
        let checksum = Self::calculate_checksum(&data);
        
        // Update checksum in header
        data[24..28].copy_from_slice(&checksum.to_be_bytes());
        
        Ok(data)
    }

    /// Deserialize packet from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < 36 {
            return Err(NetworkError::InvalidPacketFormat);
        }

        // Parse header
        let header = PacketHeader::deserialize(&data[0..32])?;

        // Verify magic
        if header.magic != [0x66, 0x66, 0x66, 0x01] {
            return Err(NetworkError::InvalidPacketFormat);
        }

        // Extract payload (everything between header and footer)
        let footer_start = data.len().saturating_sub(4);
        let payload = data[32..footer_start].to_vec();

        let packet = Packet {
            header,
            payload,
        };

        // Verify checksum
        if !packet.verify_checksum() {
            return Err(NetworkError::ChecksumMismatch);
        }

        Ok(packet)
    }
}

/// Generate CRC32 lookup table at compile time
const fn generate_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        
        table[i] = crc;
        i += 1;
    }
    
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_header_serialization() {
        let header = PacketHeader::new(PacketType::KeepAlive as u8);
        let serialized = header.serialize();
        assert_eq!(serialized.len(), 32);
        
        let deserialized = PacketHeader::deserialize(&serialized).unwrap();
        assert_eq!(header.magic, deserialized.magic);
        assert_eq!(header.version, deserialized.version);
        assert_eq!(header.packet_type, deserialized.packet_type);
    }

    #[test]
    fn test_packet_roundtrip() {
        let mut packet = Packet::new(PacketType::CircuitData as u8);
        packet.payload = vec![1, 2, 3, 4, 5];
        
        let serialized = packet.serialize().unwrap();
        let deserialized = Packet::deserialize(&serialized).unwrap();
        
        assert_eq!(packet.header.packet_type, deserialized.header.packet_type);
        assert_eq!(packet.payload, deserialized.payload);
    }

    #[test]
    fn test_checksum_validation() {
        let packet = Packet::new(PacketType::KeepAlive as u8);
        let serialized = packet.serialize().unwrap();
        let deserialized = Packet::deserialize(&serialized).unwrap();
        assert!(deserialized.verify_checksum());
    }

    #[test]
    fn test_checksum_mismatch() {
        let packet = Packet::new(PacketType::KeepAlive as u8);
        let mut serialized = packet.serialize().unwrap();
        
        // Corrupt the payload
        if serialized.len() > 32 {
            serialized[32] ^= 0xFF;
        }
        
        let result = Packet::deserialize(&serialized);
        assert!(matches!(result, Err(NetworkError::ChecksumMismatch)));
    }
}
