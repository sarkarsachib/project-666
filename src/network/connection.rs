//! Connection management and lifecycle

use crate::types::Address;
use crate::network::error::{NetworkError, Result};
use std::net::SocketAddr;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Connection state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    Connecting,
    Handshaking,
    Established,
    Closing,
    Closed,
}

/// Connection information
#[derive(Clone, Debug)]
pub struct Connection {
    pub peer_address: SocketAddr,
    pub remote_identity: Address,
    pub state: ConnectionState,
    pub session_key: [u8; 32],
    pub created_at: u64,
    pub last_activity: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl Connection {
    /// Create a new connection
    pub fn new(peer_address: SocketAddr, remote_identity: Address) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Connection {
            peer_address,
            remote_identity,
            state: ConnectionState::Connecting,
            session_key: [0u8; 32],
            created_at: now,
            last_activity: now,
            packets_sent: 0,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    /// Check if connection is active
    pub fn is_active(&self) -> bool {
        matches!(self.state, ConnectionState::Established)
    }

    /// Check if connection is stale
    pub fn is_stale(&self, timeout_seconds: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now - self.last_activity > timeout_seconds
    }

    /// Update activity timestamp
    pub fn touch(&mut self) {
        self.last_activity = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
}

/// Connection manager
pub struct ConnectionManager {
    connections: HashMap<SocketAddr, Connection>,
    identity_map: HashMap<Address, SocketAddr>,
}

impl ConnectionManager {
    /// Create a new connection manager
    pub fn new() -> Self {
        ConnectionManager {
            connections: HashMap::new(),
            identity_map: HashMap::new(),
        }
    }

    /// Add a new connection
    pub fn add_connection(&mut self, conn: Connection) {
        let peer = conn.peer_address;
        let identity = conn.remote_identity;
        
        self.connections.insert(peer, conn);
        self.identity_map.insert(identity, peer);
    }

    /// Get a connection by peer address
    pub fn get_connection(&self, peer: SocketAddr) -> Option<&Connection> {
        self.connections.get(&peer)
    }

    /// Get a mutable connection by peer address
    pub fn get_connection_mut(&mut self, peer: SocketAddr) -> Option<&mut Connection> {
        self.connections.get_mut(&peer)
    }

    /// Find connection by identity
    pub fn find_by_identity(&self, address: &Address) -> Option<SocketAddr> {
        self.identity_map.get(address).copied()
    }

    /// Remove a connection
    pub fn remove_connection(&mut self, peer: SocketAddr) {
        if let Some(conn) = self.connections.remove(&peer) {
            self.identity_map.remove(&conn.remote_identity);
        }
    }

    /// Update activity for a connection
    pub fn update_activity(&mut self, peer: SocketAddr) -> Result<()> {
        if let Some(conn) = self.connections.get_mut(&peer) {
            conn.touch();
            Ok(())
        } else {
            Err(NetworkError::UnreachablePeer)
        }
    }

    /// Prune stale connections
    pub fn prune_stale(&mut self, timeout_seconds: u64) {
        let stale_peers: Vec<SocketAddr> = self.connections
            .iter()
            .filter(|(_, conn)| conn.is_stale(timeout_seconds))
            .map(|(peer, _)| *peer)
            .collect();

        for peer in stale_peers {
            self.remove_connection(peer);
        }
    }

    /// Get all connection addresses
    pub fn all_connections(&self) -> Vec<SocketAddr> {
        self.connections.keys().copied().collect()
    }

    /// Get count of active connections
    pub fn active_count(&self) -> usize {
        self.connections.values()
            .filter(|conn| conn.is_active())
            .count()
    }

    /// Get total connection count
    pub fn total_count(&self) -> usize {
        self.connections.len()
    }

    /// Set connection state
    pub fn set_state(&mut self, peer: SocketAddr, state: ConnectionState) -> Result<()> {
        if let Some(conn) = self.connections.get_mut(&peer) {
            conn.state = state;
            Ok(())
        } else {
            Err(NetworkError::UnreachablePeer)
        }
    }

    /// Set session key
    pub fn set_session_key(&mut self, peer: SocketAddr, key: [u8; 32]) -> Result<()> {
        if let Some(conn) = self.connections.get_mut(&peer) {
            conn.session_key = key;
            Ok(())
        } else {
            Err(NetworkError::UnreachablePeer)
        }
    }
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_creation() {
        let peer: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let identity = Address::from_data(b"test");
        
        let conn = Connection::new(peer, identity);
        assert_eq!(conn.state, ConnectionState::Connecting);
        assert_eq!(conn.peer_address, peer);
        assert_eq!(conn.remote_identity, identity);
    }

    #[test]
    fn test_connection_manager() {
        let mut manager = ConnectionManager::new();
        let peer: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let identity = Address::from_data(b"test");
        
        let conn = Connection::new(peer, identity);
        manager.add_connection(conn);
        
        assert_eq!(manager.total_count(), 1);
        assert!(manager.get_connection(peer).is_some());
        assert_eq!(manager.find_by_identity(&identity), Some(peer));
    }

    #[test]
    fn test_connection_state_transitions() {
        let mut manager = ConnectionManager::new();
        let peer: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let identity = Address::from_data(b"test");
        
        let conn = Connection::new(peer, identity);
        manager.add_connection(conn);
        
        manager.set_state(peer, ConnectionState::Handshaking).unwrap();
        assert_eq!(manager.get_connection(peer).unwrap().state, ConnectionState::Handshaking);
        
        manager.set_state(peer, ConnectionState::Established).unwrap();
        assert_eq!(manager.active_count(), 1);
    }

    #[test]
    fn test_prune_stale() {
        let mut manager = ConnectionManager::new();
        let peer: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let identity = Address::from_data(b"test");
        
        let mut conn = Connection::new(peer, identity);
        conn.last_activity = 0; // Very old
        manager.add_connection(conn);
        
        assert_eq!(manager.total_count(), 1);
        
        manager.prune_stale(10);
        assert_eq!(manager.total_count(), 0);
    }
}
