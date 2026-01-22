//! Network transport and onion routing layer
//!
//! This module implements the low-level network transport, onion routing,
//! circuit management, and relay functionality for Project 666.

pub mod error;
pub mod packet;
pub mod transport;
pub mod routing;
pub mod circuit;
pub mod relay;
pub mod connection;
pub mod peers;

// Re-export commonly used types
pub use error::{NetworkError, Result};
pub use packet::{Packet, PacketHeader, PacketType, PacketPayload, CircuitHopSpec};
pub use transport::{Transport, TransportStats, PeerInfo, ReliabilityManager};
pub use routing::{OnionLayer, OnionPacket, RoutingEngine, RoutingAction, RoutingDecision};
pub use circuit::{CircuitBuilder, CircuitManager, ActiveCircuit, CircuitHop, CircuitState, CircuitBuildState};
pub use relay::{RelayNode, RelayCell, RelayCircuitState, RelayCellCommand};
pub use connection::{Connection, ConnectionManager, ConnectionState};
pub use peers::{PeerTracker, PeerRecord};
