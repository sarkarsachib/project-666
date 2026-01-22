//! Network error types

use std::fmt;
use crate::types::Address;

/// Network error types
#[derive(Debug, Clone)]
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
    RoutingFailure(String),
    
    // Circuit errors
    CircuitAlreadyExists(u32),
    CircuitBuildFailed(u8),
    InvalidHopCount,
    MaxCircuitsExceeded,
    
    // Encryption errors
    EncryptionFailed(String),
    DecryptionFailed(String),
    AuthenticationFailed,
    
    // General errors
    InvalidState,
    NotImplemented,
    InternalError(String),
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NetworkError::SocketError(msg) => write!(f, "Socket error: {}", msg),
            NetworkError::BindError(msg) => write!(f, "Bind error: {}", msg),
            NetworkError::SendError(msg) => write!(f, "Send error: {}", msg),
            NetworkError::RecvError(msg) => write!(f, "Receive error: {}", msg),
            NetworkError::TimeoutError => write!(f, "Timeout error"),
            
            NetworkError::InvalidPacketFormat => write!(f, "Invalid packet format"),
            NetworkError::ChecksumMismatch => write!(f, "Checksum mismatch"),
            NetworkError::VersionMismatch => write!(f, "Version mismatch"),
            NetworkError::UnknownPacketType => write!(f, "Unknown packet type"),
            
            NetworkError::NoRoute(addr) => write!(f, "No route to {}", addr),
            NetworkError::CircuitNotFound(id) => write!(f, "Circuit not found: {}", id),
            NetworkError::UnreachablePeer => write!(f, "Unreachable peer"),
            NetworkError::RoutingFailure(msg) => write!(f, "Routing failure: {}", msg),
            
            NetworkError::CircuitAlreadyExists(id) => write!(f, "Circuit already exists: {}", id),
            NetworkError::CircuitBuildFailed(code) => write!(f, "Circuit build failed: {}", code),
            NetworkError::InvalidHopCount => write!(f, "Invalid hop count"),
            NetworkError::MaxCircuitsExceeded => write!(f, "Maximum circuits exceeded"),
            
            NetworkError::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
            NetworkError::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
            NetworkError::AuthenticationFailed => write!(f, "Authentication failed"),
            
            NetworkError::InvalidState => write!(f, "Invalid state"),
            NetworkError::NotImplemented => write!(f, "Not implemented"),
            NetworkError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for NetworkError {}

pub type Result<T> = std::result::Result<T, NetworkError>;
