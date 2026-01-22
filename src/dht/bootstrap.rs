use crate::dht::error::Result;
use crate::dht::node::DHTNode;
use crate::types::Address;
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct BootstrapManager {
    bootstrap_peers: Vec<(Address, SocketAddr)>,
    bootstrap_timeout_ms: u64,
}

impl BootstrapManager {
    pub fn new(bootstrap_peers: Vec<(Address, SocketAddr)>) -> Self {
        Self {
            bootstrap_peers,
            bootstrap_timeout_ms: 3_000,
        }
    }

    pub fn bootstrap(&self, node: &mut DHTNode) -> Result<()> {
        let _ = self.bootstrap_timeout_ms;
        for (addr, sock) in &self.bootstrap_peers {
            let _ = node.add_peer(*addr, *sock);
        }

        node.refresh_buckets()?;
        node.replicate_data()?;
        Ok(())
    }

    pub fn add_bootstrap_peer(&mut self, address: Address, socket: SocketAddr) {
        if !self.bootstrap_peers.iter().any(|(a, _)| a == &address) {
            self.bootstrap_peers.push((address, socket));
        }
    }

    pub fn remove_bootstrap_peer(&mut self, address: &Address) {
        self.bootstrap_peers.retain(|(a, _)| a != address);
    }
}
