//! # Project 666 - Reference Implementation
//!
//! This crate started as a complete from-scratch implementation of the Phase 1
//! cryptographic primitives. It now also includes Phase 4 DHT + distributed
//! resolution building blocks.

pub mod constants;
pub mod crypto;
pub mod dht;
pub mod resolution;
pub mod types;

pub use constants::*;

// Re-export crypto modules at the crate root for the existing API.
pub use crypto::{aead, argon2, chacha20, ed25519, kdf, poly1305, sha256, utils, x25519};

// Re-export commonly used crypto types.
pub use crypto::aead::{AeadCipher, AeadError};
pub use crypto::argon2::{Argon2, Argon2Params, Argon2Variant};
pub use crypto::chacha20::ChaCha20;
pub use crypto::ed25519::{PublicKey as Ed25519PublicKey, SecretKey as Ed25519SecretKey, Signature};
pub use crypto::kdf::{derive_key, derive_keys, derive_keys_with_contexts};
pub use crypto::poly1305::Poly1305;
pub use crypto::sha256::Sha256;
pub use crypto::x25519::{diffie_hellman, generate_keypair as x25519_generate_keypair};

// Re-export commonly used protocol types.
pub use types::{Address, Permission, ResourceLimits, SystemDescriptor};
