use crate::crypto::{ed25519, sha256};
use crate::dht::error::{DHTError, Result};
use crate::dht::{now_ms, now_secs};
use crate::types::Address;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GossipMessage {
    pub message_type: GossipMessageType,
    pub sender: Address,
    pub version: u64,
    pub payload: Vec<u8>,
    pub signature: [u8; 64],
    pub timestamp: u64,
    pub ttl: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GossipMessageType {
    StorageUpdate { key: Address, value: Vec<u8>, ttl: u64 },
    StorageDelete { key: Address },
    PeerAdvertisement { peer: Address, socket: SocketAddr },
    Heartbeat { peer_count: u32, storage_size: u32 },
}

#[derive(Debug, Clone)]
pub struct GossipManager {
    message_cache: RefCell<HashSet<u64>>,
    seen_threshold: usize,
    broadcast_fan_out: usize,
    known_public_keys: HashMap<Address, ed25519::PublicKey>,
}

impl GossipManager {
    pub fn new(broadcast_fan_out: usize) -> Self {
        Self {
            message_cache: RefCell::new(HashSet::new()),
            seen_threshold: 1,
            broadcast_fan_out,
            known_public_keys: HashMap::new(),
        }
    }

    pub fn register_public_key(&mut self, address: Address, public_key: ed25519::PublicKey) {
        self.known_public_keys.insert(address, public_key);
    }

    pub fn create_message(
        message_type: GossipMessageType,
        sender: Address,
        secret_key: &[u8; 32],
    ) -> Result<GossipMessage> {
        let timestamp = now_secs();
        let version = now_ms();
        let payload = Vec::new();
        let ttl = 8;

        let mut msg = GossipMessage {
            message_type,
            sender,
            version,
            payload,
            signature: [0u8; 64],
            timestamp,
            ttl,
        };

        let bytes = msg.signing_bytes();
        msg.signature = ed25519::sign(secret_key, &bytes);
        Ok(msg)
    }

    pub fn verify_message(&self, msg: &GossipMessage) -> Result<bool> {
        let pk = self
            .known_public_keys
            .get(&msg.sender)
            .ok_or(DHTError::UnknownPeer)?;

        Ok(ed25519::verify(pk, &msg.signing_bytes(), &msg.signature))
    }

    pub fn should_forward(&self, msg: &GossipMessage) -> bool {
        if msg.ttl == 0 {
            return false;
        }

        let id = msg.message_id();
        let mut cache = self.message_cache.borrow_mut();
        if cache.contains(&id) {
            return false;
        }

        cache.insert(id);
        // seen_threshold is currently a boolean toggle; can be expanded later.
        let _ = self.seen_threshold;
        true
    }

    pub fn select_gossip_targets(&self, all_peers: &[Address], count: usize) -> Vec<Address> {
        let mut peers = all_peers.to_vec();
        peers.sort();
        peers.truncate(count.min(self.broadcast_fan_out));
        peers
    }
}

impl GossipMessage {
    pub fn decrement_ttl(&mut self) {
        self.ttl = self.ttl.saturating_sub(1);
    }

    pub fn message_id(&self) -> u64 {
        let digest = sha256::digest(&self.signing_bytes());
        u64::from_be_bytes(digest[..8].try_into().unwrap())
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.sender.as_bytes());
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.push(self.ttl);
        out.extend_from_slice(&encode_message_type(&self.message_type));
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.signing_bytes();
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 16 + 8 + 8 + 1 + 1 + 4 + 64 {
            return Err(DHTError::InvalidInput("gossip message too short"));
        }

        let mut idx = 0;
        let mut sender = [0u8; 16];
        sender.copy_from_slice(&data[idx..idx + 16]);
        idx += 16;

        let version = u64::from_be_bytes(data[idx..idx + 8].try_into().unwrap());
        idx += 8;
        let timestamp = u64::from_be_bytes(data[idx..idx + 8].try_into().unwrap());
        idx += 8;
        let ttl = data[idx];
        idx += 1;

        let (message_type, next_idx) = decode_message_type(data, idx)?;
        idx = next_idx;

        let payload_len = u32::from_be_bytes(data[idx..idx + 4].try_into().unwrap()) as usize;
        idx += 4;
        if data.len() < idx + payload_len + 64 {
            return Err(DHTError::InvalidInput("invalid payload length"));
        }

        let payload = data[idx..idx + payload_len].to_vec();
        idx += payload_len;

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[idx..idx + 64]);

        Ok(Self {
            message_type,
            sender: Address::new(sender),
            version,
            payload,
            signature,
            timestamp,
            ttl,
        })
    }
}

fn encode_message_type(mt: &GossipMessageType) -> Vec<u8> {
    let mut out = Vec::new();
    match mt {
        GossipMessageType::StorageUpdate { key, value, ttl } => {
            out.push(1);
            out.extend_from_slice(key.as_bytes());
            out.extend_from_slice(&ttl.to_be_bytes());
            out.extend_from_slice(&(value.len() as u32).to_be_bytes());
            out.extend_from_slice(value);
        }
        GossipMessageType::StorageDelete { key } => {
            out.push(2);
            out.extend_from_slice(key.as_bytes());
        }
        GossipMessageType::PeerAdvertisement { peer, socket } => {
            out.push(3);
            out.extend_from_slice(peer.as_bytes());
            out.extend_from_slice(&encode_socket(socket));
        }
        GossipMessageType::Heartbeat {
            peer_count,
            storage_size,
        } => {
            out.push(4);
            out.extend_from_slice(&peer_count.to_be_bytes());
            out.extend_from_slice(&storage_size.to_be_bytes());
        }
    }
    out
}

fn decode_message_type(data: &[u8], idx: usize) -> Result<(GossipMessageType, usize)> {
    if idx >= data.len() {
        return Err(DHTError::InvalidInput("missing message type"));
    }
    let t = data[idx];
    let mut i = idx + 1;
    match t {
        1 => {
            if data.len() < i + 16 + 8 + 4 {
                return Err(DHTError::InvalidInput("storage update too short"));
            }
            let key = Address::try_from(&data[i..i + 16]).map_err(DHTError::InvalidInput)?;
            i += 16;
            let ttl = u64::from_be_bytes(data[i..i + 8].try_into().unwrap());
            i += 8;
            let vlen = u32::from_be_bytes(data[i..i + 4].try_into().unwrap()) as usize;
            i += 4;
            if data.len() < i + vlen {
                return Err(DHTError::InvalidInput("storage update invalid length"));
            }
            let value = data[i..i + vlen].to_vec();
            i += vlen;
            Ok((GossipMessageType::StorageUpdate { key, value, ttl }, i))
        }
        2 => {
            if data.len() < i + 16 {
                return Err(DHTError::InvalidInput("storage delete too short"));
            }
            let key = Address::try_from(&data[i..i + 16]).map_err(DHTError::InvalidInput)?;
            i += 16;
            Ok((GossipMessageType::StorageDelete { key }, i))
        }
        3 => {
            if data.len() < i + 16 + 1 + 2 {
                return Err(DHTError::InvalidInput("peer adv too short"));
            }
            let peer = Address::try_from(&data[i..i + 16]).map_err(DHTError::InvalidInput)?;
            i += 16;
            let (socket, next) = decode_socket(data, i)?;
            Ok((GossipMessageType::PeerAdvertisement { peer, socket }, next))
        }
        4 => {
            if data.len() < i + 8 {
                return Err(DHTError::InvalidInput("heartbeat too short"));
            }
            let peer_count = u32::from_be_bytes(data[i..i + 4].try_into().unwrap());
            i += 4;
            let storage_size = u32::from_be_bytes(data[i..i + 4].try_into().unwrap());
            i += 4;
            Ok((GossipMessageType::Heartbeat { peer_count, storage_size }, i))
        }
        _ => Err(DHTError::InvalidInput("unknown gossip message type")),
    }
}

fn encode_socket(socket: &SocketAddr) -> Vec<u8> {
    let mut out = Vec::new();
    match socket.ip() {
        std::net::IpAddr::V4(ip) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            out.push(6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&socket.port().to_be_bytes());
    out
}

fn decode_socket(data: &[u8], idx: usize) -> Result<(SocketAddr, usize)> {
    if data.len() < idx + 1 + 2 {
        return Err(DHTError::InvalidInput("socket too short"));
    }

    let family = data[idx];
    let mut i = idx + 1;
    let ip = match family {
        4 => {
            if data.len() < i + 4 + 2 {
                return Err(DHTError::InvalidInput("socket v4 too short"));
            }
            let mut oct = [0u8; 4];
            oct.copy_from_slice(&data[i..i + 4]);
            i += 4;
            std::net::IpAddr::from(oct)
        }
        6 => {
            if data.len() < i + 16 + 2 {
                return Err(DHTError::InvalidInput("socket v6 too short"));
            }
            let mut oct = [0u8; 16];
            oct.copy_from_slice(&data[i..i + 16]);
            i += 16;
            std::net::IpAddr::from(oct)
        }
        _ => return Err(DHTError::InvalidInput("unknown socket family")),
    };

    let port = u16::from_be_bytes([data[i], data[i + 1]]);
    i += 2;

    Ok((SocketAddr::new(ip, port), i))
}
