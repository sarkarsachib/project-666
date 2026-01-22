//! # Project 666: Privacy-Preserving Communication Protocol
//!
//! This library provides a complete implementation of the Project 666 protocol,
//! including cryptographic primitives, network transport, and onion routing.
//!
//! ## Features
//!
//! - **Zero dependencies**: All algorithms and networking implemented from scratch
//! - **Constant-time**: All cryptographic operations are constant-time
//! - **RFC compliant**: Implements RFC 7539, RFC 7748, RFC 8032, and more
//! - **Onion routing**: Multi-hop encrypted relay for anonymous communication
//! - **Well-tested**: Comprehensive test vectors and edge case coverage
//!
//! ## Modules
//!
//! ### Cryptography (Phase 1)
//! - `crypto`: Cryptographic primitives
//!   - `aead`: ChaCha20-Poly1305 authenticated encryption
//!   - `argon2`: Argon2 key derivation function
//!   - `chacha20`: ChaCha20 stream cipher
//!   - `ed25519`: Ed25519 digital signatures
//!   - `kdf`: Key derivation functions
//!   - `poly1305`: Poly1305 message authentication code
//!   - `sha256`: SHA-256 hash function
//!   - `x25519`: X25519 elliptic curve Diffie-Hellman
//!   - `utils`: Constant-time utilities
//!
//! ### Core Types & Collections (Phase 2 - Partial)
//! - `types`: Core protocol types (Address)
//! - `collections`: Basic collections (Queue)
//!
//! ### Network & Routing (Phase 3)
//! - `network`: UDP transport, onion routing, circuits, relay nodes
//!   - `transport`: Low-level UDP packet transport
//!   - `packet`: Network packet structures
//!   - `routing`: Onion routing engine
//!   - `circuit`: Circuit management
//!   - `relay`: Relay node logic
//!   - `connection`: Connection lifecycle
//!   - `peers`: Peer tracking and reputation
//!
//! ## Example
//!
//! ```rust
//! use project_666::aead;
//!
//! let key = [0u8; 32];
//! let nonce = [0u8; 12];
//! let plaintext = b"Hello, Project 666!";
//!
//! let (ciphertext, tag) = aead::encrypt(&key, &nonce, &[], plaintext);
//! let decrypted = aead::decrypt(&key, &nonce, &[], &ciphertext, &tag).unwrap();
//!
//! assert_eq!(plaintext.as_slice(), &decrypted[..]);
//! ```

pub mod constants;
pub mod types;
pub mod collections;
pub mod network;
pub mod crypto;

// Re-export crypto modules at top level for backwards compatibility
pub use crypto::{aead, argon2, chacha20, ed25519, kdf, poly1305, sha256, x25519, utils};

// Re-export commonly used crypto types
pub use crypto::aead::{AeadCipher, AeadError};
pub use crypto::argon2::{Argon2, Argon2Params, Argon2Variant};
pub use crypto::chacha20::ChaCha20;
pub use crypto::ed25519::{PublicKey as Ed25519PublicKey, SecretKey as Ed25519SecretKey, Signature};
pub use crypto::kdf::{derive_key, derive_keys, derive_keys_with_contexts};
pub use crypto::poly1305::Poly1305;
pub use crypto::sha256::Sha256;
pub use crypto::x25519::{diffie_hellman, generate_keypair as x25519_generate_keypair};

// Re-export core types
pub use types::Address;
pub use collections::Queue;

// Re-export network types
pub use network::{
    NetworkError, Packet, Transport, OnionPacket, CircuitManager,
    RelayNode, ConnectionManager, PeerTracker,
};

pub use constants::*;
