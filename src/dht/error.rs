use core::fmt;

use crate::aead::AeadError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DHTError {
    BucketFull,
    UnknownPeer,
    InvalidInput(&'static str),
    Crypto(AeadError),
    Descriptor(&'static str),
    Timeout,
}

impl fmt::Display for DHTError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DHTError::BucketFull => write!(f, "bucket full"),
            DHTError::UnknownPeer => write!(f, "unknown peer"),
            DHTError::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
            DHTError::Crypto(e) => write!(f, "crypto error: {e}"),
            DHTError::Descriptor(msg) => write!(f, "descriptor error: {msg}"),
            DHTError::Timeout => write!(f, "timeout"),
        }
    }
}

impl std::error::Error for DHTError {}

impl From<AeadError> for DHTError {
    fn from(value: AeadError) -> Self {
        DHTError::Crypto(value)
    }
}

pub type Result<T> = core::result::Result<T, DHTError>;
