use crate::crypto::{ed25519, sha256};
use crate::types::Address;
use core::fmt;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    Any = 0,
    Store = 1,
    Resolve = 2,
    Relay = 3,
}

impl Permission {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Permission::Any),
            1 => Some(Permission::Store),
            2 => Some(Permission::Resolve),
            3 => Some(Permission::Relay),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    pub max_storage_bytes: u64,
    pub max_bandwidth_bytes_per_sec: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_storage_bytes: 64 * 1024 * 1024,
            max_bandwidth_bytes_per_sec: 10 * 1024 * 1024,
        }
    }
}

/// A signed descriptor describing how to reach a node and what it offers.
#[derive(Clone, PartialEq, Eq)]
pub struct SystemDescriptor {
    pub address: Address,
    pub public_key: ed25519::PublicKey,
    pub socket: SocketAddr,
    pub capabilities: Vec<Permission>,
    pub resources: ResourceLimits,
    pub created_at: u64,
    pub expires_at: u64,
    pub signature: ed25519::Signature,
}

impl fmt::Debug for SystemDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SystemDescriptor")
            .field("address", &self.address)
            .field("socket", &self.socket)
            .field("capabilities", &self.capabilities)
            .field("resources", &self.resources)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl SystemDescriptor {
    /// Derive an opaque `.666` address from an Ed25519 public key.
    pub fn address_from_public_key(pk: &ed25519::PublicKey) -> Address {
        let digest = sha256::digest(pk);
        let mut out = [0u8; 16];
        out.copy_from_slice(&digest[..16]);
        Address::new(out)
    }

    pub fn new_unsigned(
        public_key: ed25519::PublicKey,
        socket: SocketAddr,
        capabilities: Vec<Permission>,
        resources: ResourceLimits,
        created_at: u64,
        expires_at: u64,
    ) -> Self {
        let address = Self::address_from_public_key(&public_key);
        Self {
            address,
            public_key,
            socket,
            capabilities,
            resources,
            created_at,
            expires_at,
            signature: [0u8; 64],
        }
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.address.as_bytes());
        out.extend_from_slice(&self.public_key);
        encode_socket(&mut out, &self.socket);
        out.extend_from_slice(&self.created_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());

        out.extend_from_slice(&(self.capabilities.len() as u16).to_be_bytes());
        for c in &self.capabilities {
            out.push(*c as u8);
        }

        out.extend_from_slice(&self.resources.max_storage_bytes.to_be_bytes());
        out.extend_from_slice(&self.resources.max_bandwidth_bytes_per_sec.to_be_bytes());
        out
    }

    pub fn sign(mut self, secret_key: &ed25519::SecretKey) -> Self {
        self.signature = ed25519::sign(secret_key, &self.signing_bytes());
        self
    }

    pub fn verify(&self) -> bool {
        ed25519::verify(&self.public_key, &self.signing_bytes(), &self.signature)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.signing_bytes();
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn from_bytes(mut data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 16 + 32 + 1 + 2 + 8 + 8 + 2 + 16 + 64 {
            return Err("descriptor too short");
        }

        let mut address = [0u8; 16];
        address.copy_from_slice(&data[..16]);
        data = &data[16..];

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&data[..32]);
        data = &data[32..];

        let (socket, rest) = decode_socket(data)?;
        data = rest;

        let created_at = take_u64(&mut data)?;
        let expires_at = take_u64(&mut data)?;

        let cap_count = take_u16(&mut data)? as usize;
        if data.len() < cap_count {
            return Err("invalid capabilities length");
        }
        let mut capabilities = Vec::with_capacity(cap_count);
        for &b in &data[..cap_count] {
            let cap = Permission::from_u8(b).ok_or("unknown permission")?;
            capabilities.push(cap);
        }
        data = &data[cap_count..];

        let max_storage_bytes = take_u64(&mut data)?;
        let max_bandwidth_bytes_per_sec = take_u64(&mut data)?;

        if data.len() != 64 {
            return Err("invalid signature length");
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(data);

        Ok(Self {
            address: Address::new(address),
            public_key,
            socket,
            capabilities,
            resources: ResourceLimits {
                max_storage_bytes,
                max_bandwidth_bytes_per_sec,
            },
            created_at,
            expires_at,
            signature,
        })
    }
}

fn encode_socket(out: &mut Vec<u8>, socket: &SocketAddr) {
    match socket.ip() {
        IpAddr::V4(ip) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&socket.port().to_be_bytes());
}

fn decode_socket(data: &[u8]) -> Result<(SocketAddr, &[u8]), &'static str> {
    if data.len() < 1 + 2 {
        return Err("socket too short");
    }
    let family = data[0];
    let mut rest = &data[1..];
    let ip = match family {
        4 => {
            if rest.len() < 4 + 2 {
                return Err("socket v4 too short");
            }
            let mut oct = [0u8; 4];
            oct.copy_from_slice(&rest[..4]);
            rest = &rest[4..];
            IpAddr::from(oct)
        }
        6 => {
            if rest.len() < 16 + 2 {
                return Err("socket v6 too short");
            }
            let mut oct = [0u8; 16];
            oct.copy_from_slice(&rest[..16]);
            rest = &rest[16..];
            IpAddr::from(oct)
        }
        _ => return Err("unknown socket family"),
    };

    let port = u16::from_be_bytes([rest[0], rest[1]]);
    rest = &rest[2..];

    Ok((SocketAddr::new(ip, port), rest))
}

fn take_u16(data: &mut &[u8]) -> Result<u16, &'static str> {
    if data.len() < 2 {
        return Err("unexpected eof");
    }
    let v = u16::from_be_bytes([data[0], data[1]]);
    *data = &data[2..];
    Ok(v)
}

fn take_u64(data: &mut &[u8]) -> Result<u64, &'static str> {
    if data.len() < 8 {
        return Err("unexpected eof");
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&data[..8]);
    *data = &data[8..];
    Ok(u64::from_be_bytes(b))
}
