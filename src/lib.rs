//! # Project 666 Cryptographic Primitives
//!
//! This library provides a complete implementation of all cryptographic primitives
//! required for the Project 666 privacy-preserving communication protocol.
//!
//! ## Features
//!
//! - **Zero dependencies**: All algorithms implemented from scratch
//! - **Constant-time**: All operations where applicable are constant-time
//! - **RFC compliant**: Implements RFC 7539, RFC 7748, RFC 8032, and more
//! - **Well-tested**: Comprehensive test vectors and edge case coverage
//!
//! ## Modules
//!
//! - `aead`: ChaCha20-Poly1305 authenticated encryption
//! - `argon2`: Argon2 key derivation function
//! - `chacha20`: ChaCha20 stream cipher
//! - `ed25519`: Ed25519 digital signatures
//! - `kdf`: Key derivation functions
//! - `poly1305`: Poly1305 message authentication code
//! - `sha256`: SHA-256 hash function
//! - `x25519`: X25519 elliptic curve Diffie-Hellman
//! - `utils`: Constant-time utilities
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

// Re-export crypto modules
pub mod aead;
pub mod argon2;
pub mod chacha20;
pub mod ed25519;
pub mod kdf;
pub mod poly1305;
pub mod sha256;
pub mod x25519;
pub mod utils;

// Re-export commonly used types
pub use aead::{AeadCipher, AeadError};
pub use argon2::{Argon2, Argon2Params, Argon2Variant};
pub use chacha20::ChaCha20;
pub use ed25519::{PublicKey as Ed25519PublicKey, SecretKey as Ed25519SecretKey, Signature};
pub use kdf::{derive_key, derive_keys, derive_keys_with_contexts};
pub use poly1305::Poly1305;
pub use sha256::Sha256;
pub use x25519::{diffie_hellman, generate_keypair as x25519_generate_keypair};

pub use constants::*;
