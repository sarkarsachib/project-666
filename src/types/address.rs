use crate::constants::ADDRESS_SIZE;
use core::cmp::Ordering;
use core::fmt;
use core::fmt::Write;
use core::hash::{Hash, Hasher};

/// Opaque 128-bit address used throughout the protocol.
#[derive(Copy, Clone, Default)]
pub struct Address([u8; ADDRESS_SIZE]);

impl Address {
    pub const fn new(bytes: [u8; ADDRESS_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn zero() -> Self {
        Self([0u8; ADDRESS_SIZE])
    }

    pub fn as_bytes(&self) -> &[u8; ADDRESS_SIZE] {
        &self.0
    }

    pub fn to_bytes(self) -> [u8; ADDRESS_SIZE] {
        self.0
    }
}

impl From<[u8; ADDRESS_SIZE]> for Address {
    fn from(value: [u8; ADDRESS_SIZE]) -> Self {
        Self::new(value)
    }
}

impl TryFrom<&[u8]> for Address {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != ADDRESS_SIZE {
            return Err("invalid address length");
        }

        let mut bytes = [0u8; ADDRESS_SIZE];
        bytes.copy_from_slice(value);
        Ok(Self(bytes))
    }
}

impl PartialEq for Address {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for Address {}

impl Hash for Address {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl Ord for Address {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for Address {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn fmt_hex(bytes: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in bytes {
        let hi = (b >> 4) as usize;
        let lo = (b & 0x0f) as usize;
        f.write_char(HEX[hi] as char)?;
        f.write_char(HEX[lo] as char)?;
    }
    Ok(())
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Address(")?;
        fmt_hex(&self.0, f)?;
        f.write_str(")")
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_hex(&self.0, f)
    }
}
