//! UDP-based transport layer

use crate::network::error::{NetworkError, Result};
use crate::network::packet::Packet;
use crate::collections::Queue;
use std::net::{UdpSocket, SocketAddr};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Peer information
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub address: SocketAddr,
    pub last_heard: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl PeerInfo {
    fn new(address: SocketAddr) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        PeerInfo {
            address,
            last_heard: now,
            packets_sent: 0,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
}

/// Transport statistics
#[derive(Debug, Clone)]
pub struct TransportStats {
    pub total_packets_sent: u64,
    pub total_packets_received: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub active_peers: usize,
    pub queue_depth: usize,
}

/// UDP-based transport
pub struct Transport {
    socket: UdpSocket,
    local_addr: SocketAddr,
    peers: HashMap<SocketAddr, PeerInfo>,
    send_queue: Queue<(SocketAddr, Packet)>,
    receive_queue: Queue<(SocketAddr, Packet)>,
    packet_id_counter: u32,
    total_packets_sent: u64,
    total_packets_received: u64,
    total_bytes_sent: u64,
    total_bytes_received: u64,
}

impl Transport {
    /// Create a new transport bound to the specified address
    pub fn new(bind_addr: &str) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr)
            .map_err(|e| NetworkError::BindError(e.to_string()))?;
        
        let local_addr = socket.local_addr()
            .map_err(|e| NetworkError::SocketError(e.to_string()))?;

        Ok(Transport {
            socket,
            local_addr,
            peers: HashMap::new(),
            send_queue: Queue::with_capacity(1000),
            receive_queue: Queue::with_capacity(1000),
            packet_id_counter: 1,
            total_packets_sent: 0,
            total_packets_received: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
        })
    }

    /// Set socket to non-blocking mode
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.socket.set_nonblocking(nonblocking)
            .map_err(|e| NetworkError::SocketError(e.to_string()))
    }

    /// Set receive timeout
    pub fn set_recv_timeout(&self, timeout_ms: u64) -> Result<()> {
        let timeout = if timeout_ms == 0 {
            None
        } else {
            Some(Duration::from_millis(timeout_ms))
        };
        
        self.socket.set_read_timeout(timeout)
            .map_err(|e| NetworkError::SocketError(e.to_string()))
    }

    /// Set send timeout
    pub fn set_send_timeout(&self, timeout_ms: u64) -> Result<()> {
        let timeout = if timeout_ms == 0 {
            None
        } else {
            Some(Duration::from_millis(timeout_ms))
        };
        
        self.socket.set_write_timeout(timeout)
            .map_err(|e| NetworkError::SocketError(e.to_string()))
    }

    /// Get the next packet ID
    fn next_packet_id(&mut self) -> u32 {
        let id = self.packet_id_counter;
        self.packet_id_counter = self.packet_id_counter.wrapping_add(1);
        id
    }

    /// Send a packet to a peer
    pub fn send_packet(&mut self, peer: SocketAddr, packet: &Packet) -> Result<usize> {
        let data = packet.serialize()?;
        let bytes_sent = self.send_to(peer, &data)?;
        
        // Update stats
        self.total_packets_sent += 1;
        self.total_bytes_sent += bytes_sent as u64;
        
        // Update peer stats
        if let Some(peer_info) = self.peers.get_mut(&peer) {
            peer_info.packets_sent += 1;
            peer_info.bytes_sent += bytes_sent as u64;
        }
        
        Ok(bytes_sent)
    }

    /// Send raw data to a peer
    pub fn send_to(&self, peer: SocketAddr, data: &[u8]) -> Result<usize> {
        self.socket.send_to(data, peer)
            .map_err(|e| NetworkError::SendError(e.to_string()))
    }

    /// Flush the send queue
    pub fn flush_send_queue(&mut self) -> Result<()> {
        while let Some((peer, packet)) = self.send_queue.pop() {
            self.send_packet(peer, &packet)?;
        }
        Ok(())
    }

    /// Receive a packet (non-blocking if configured)
    pub fn recv_packet(&mut self) -> Result<Option<(SocketAddr, Packet)>> {
        match self.recv_from() {
            Ok(Some((data, peer))) => {
                match Packet::deserialize(&data) {
                    Ok(packet) => {
                        self.total_packets_received += 1;
                        self.total_bytes_received += data.len() as u64;
                        
                        // Update peer stats
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        
                        self.peers.entry(peer)
                            .or_insert_with(|| PeerInfo::new(peer))
                            .packets_received += 1;
                        
                        if let Some(peer_info) = self.peers.get_mut(&peer) {
                            peer_info.bytes_received += data.len() as u64;
                            peer_info.last_heard = now;
                        }
                        
                        Ok(Some((peer, packet)))
                    }
                    Err(e) => Err(e),
                }
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Receive raw data from socket
    pub fn recv_from(&self) -> Result<Option<(Vec<u8>, SocketAddr)>> {
        let mut buf = vec![0u8; 65536];
        
        match self.socket.recv_from(&mut buf) {
            Ok((size, peer)) => {
                buf.truncate(size);
                Ok(Some((buf, peer)))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                Ok(None)
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                Ok(None)
            }
            Err(e) => Err(NetworkError::RecvError(e.to_string())),
        }
    }

    /// Poll for packets with timeout
    pub fn poll_packets(&mut self, timeout_ms: u64) -> Result<Vec<(SocketAddr, Packet)>> {
        let mut packets = Vec::new();
        let original_timeout = self.socket.read_timeout()
            .map_err(|e| NetworkError::SocketError(e.to_string()))?;
        
        // Set temporary timeout
        self.set_recv_timeout(timeout_ms)?;
        
        // Try to receive multiple packets
        loop {
            match self.recv_packet() {
                Ok(Some((peer, packet))) => {
                    packets.push((peer, packet));
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        
        // Restore original timeout
        if let Some(timeout) = original_timeout {
            self.socket.set_read_timeout(Some(timeout))
                .map_err(|e| NetworkError::SocketError(e.to_string()))?;
        }
        
        Ok(packets)
    }

    /// Add a peer
    pub fn add_peer(&mut self, addr: SocketAddr) {
        self.peers.entry(addr).or_insert_with(|| PeerInfo::new(addr));
    }

    /// Remove a peer
    pub fn remove_peer(&mut self, addr: SocketAddr) {
        self.peers.remove(&addr);
    }

    /// Get peer information
    pub fn get_peer_info(&self, addr: SocketAddr) -> Option<&PeerInfo> {
        self.peers.get(&addr)
    }

    /// Update peer statistics
    pub fn update_peer_stats(&mut self, addr: SocketAddr, sent: u64, received: u64) {
        if let Some(peer) = self.peers.get_mut(&addr) {
            peer.packets_sent += sent;
            peer.packets_received += received;
        }
    }

    /// Get all known peers
    pub fn get_peers(&self) -> Vec<SocketAddr> {
        self.peers.keys().copied().collect()
    }

    /// Get peer count
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Get transport statistics
    pub fn stats(&self) -> TransportStats {
        TransportStats {
            total_packets_sent: self.total_packets_sent,
            total_packets_received: self.total_packets_received,
            total_bytes_sent: self.total_bytes_sent,
            total_bytes_received: self.total_bytes_received,
            active_peers: self.peers.len(),
            queue_depth: self.send_queue.len(),
        }
    }

    /// Get local address
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

/// Reliability manager for retransmission
#[derive(Debug)]
pub struct ReliablePacket {
    pub packet: Packet,
    pub sent_time: u64,
    pub retry_count: u32,
    pub max_retries: u32,
}

pub struct ReliabilityManager {
    pending: HashMap<u32, ReliablePacket>,
    timeout_ms: u64,
}

impl ReliabilityManager {
    /// Create a new reliability manager
    pub fn new(timeout_ms: u64) -> Self {
        ReliabilityManager {
            pending: HashMap::new(),
            timeout_ms,
        }
    }

    /// Send a reliable packet
    pub fn send_reliable(&mut self, packet: Packet) -> u32 {
        let packet_id = packet.header.packet_id;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let reliable = ReliablePacket {
            packet,
            sent_time: now,
            retry_count: 0,
            max_retries: 3,
        };

        self.pending.insert(packet_id, reliable);
        packet_id
    }

    /// Handle acknowledgement
    pub fn handle_ack(&mut self, packet_id: u32) {
        self.pending.remove(&packet_id);
    }

    /// Check for timeouts
    pub fn check_timeouts(&mut self) -> Vec<u32> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let mut timeouts = Vec::new();

        for (packet_id, reliable) in &self.pending {
            if now - reliable.sent_time > self.timeout_ms {
                timeouts.push(*packet_id);
            }
        }

        timeouts
    }

    /// Retransmit a packet
    pub fn retransmit(&mut self, packet_id: u32) -> Result<Packet> {
        if let Some(reliable) = self.pending.get_mut(&packet_id) {
            if reliable.retry_count >= reliable.max_retries {
                self.pending.remove(&packet_id);
                return Err(NetworkError::TimeoutError);
            }

            reliable.retry_count += 1;
            reliable.sent_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;

            Ok(reliable.packet.clone())
        } else {
            Err(NetworkError::InvalidState)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::packet::PacketType;

    #[test]
    fn test_transport_creation() {
        let transport = Transport::new("127.0.0.1:0").unwrap();
        assert!(transport.local_addr().port() > 0);
    }

    #[test]
    fn test_peer_management() {
        let mut transport = Transport::new("127.0.0.1:0").unwrap();
        let peer = "127.0.0.1:8080".parse().unwrap();
        
        transport.add_peer(peer);
        assert_eq!(transport.peer_count(), 1);
        assert!(transport.get_peer_info(peer).is_some());
        
        transport.remove_peer(peer);
        assert_eq!(transport.peer_count(), 0);
    }

    #[test]
    fn test_reliability_manager() {
        let mut manager = ReliabilityManager::new(1000);
        let mut packet = Packet::new(PacketType::KeepAlive as u8);
        packet.header.packet_id = 42;
        
        let id = manager.send_reliable(packet);
        assert_eq!(id, 42);
        
        manager.handle_ack(42);
        assert_eq!(manager.pending.len(), 0);
    }
}
