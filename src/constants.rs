//! Protocol constants for Project 666

/// Protocol version (major)
pub const PROTOCOL_VERSION: u8 = 1;

/// Protocol magic bytes (ASCII: "666\0")
pub const PROTOCOL_MAGIC: [u8; 4] = [0x66, 0x66, 0x66, 0x00];

// Cryptographic sizes

/// Size of opaque addresses in bytes (128 bits)
pub const ADDRESS_SIZE: usize = 16;

/// Size of cryptographic keys in bytes (256 bits)
pub const KEY_SIZE: usize = 32;

/// Size of nonces in bytes (96 bits, ChaCha20-IETF)
pub const NONCE_SIZE: usize = 12;

/// Size of authentication tags in bytes (128 bits)
pub const TAG_SIZE: usize = 16;

/// Size of SHA-256 hash output in bytes (256 bits)
pub const HASH_SIZE: usize = 32;

/// Size of Ed25519 signatures in bytes (512 bits)
pub const SIGNATURE_SIZE: usize = 64;

/// Size of public keys in bytes (256 bits)
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Size of Argon2 salt in bytes (128 bits)
pub const ARGON2_SALT_SIZE: usize = 16;

// ChaCha20 constants

/// ChaCha20 block size in bytes (512 bits)
pub const CHACHA20_BLOCK_SIZE: usize = 64;

/// ChaCha20 key size in bytes (256 bits)
pub const CHACHA20_KEY_SIZE: usize = 32;

/// ChaCha20-IETF nonce size in bytes (96 bits)
pub const CHACHA20_NONCE_SIZE: usize = 12;

/// ChaCha20 quarter round operations per block
pub const CHACHA20_ROUNDS: u8 = 20;

// Poly1305 constants

/// Poly1305 key size in bytes (256 bits)
pub const POLY1305_KEY_SIZE: usize = 32;

/// Poly1305 tag size in bytes (128 bits)
pub const POLY1305_TAG_SIZE: usize = 16;

// SHA-256 constants

/// SHA-256 block size in bytes (512 bits)
pub const SHA256_BLOCK_SIZE: usize = 64;

/// SHA-256 output size in bytes (256 bits)
pub const SHA256_OUTPUT_SIZE: usize = 32;

// Ed25519 constants

/// Ed25519 private key size in bytes (256 bits)
pub const ED25519_PRIVATE_KEY_SIZE: usize = 32;

/// Ed25519 public key size in bytes (256 bits)
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519 signature size in bytes (512 bits)
pub const ED25519_SIGNATURE_SIZE: usize = 64;

// X25519 constants

/// X25519 private key size in bytes (256 bits)
pub const X25519_PRIVATE_KEY_SIZE: usize = 32;

/// X25519 public key size in bytes (256 bits)
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;

/// X25519 shared secret size in bytes (256 bits)
pub const X25519_SHARED_SECRET_SIZE: usize = 32;

// Argon2 defaults

/// Default time cost (number of iterations)
pub const ARGON2_T_COST: u32 = 3;

/// Default memory cost in KiB (64 MiB)
pub const ARGON2_M_COST: u32 = 65540;

/// Default parallelism (number of lanes)
pub const ARGON2_P_COST: u32 = 4;

/// Argon2 block size in bytes (1024 bits)
pub const ARGON2_BLOCK_SIZE: usize = 1024;

/// Argon2 number of passes
pub const ARGON2_PASS: u32 = 3;

// Protocol limits

/// Maximum message size in bytes (64 KB)
pub const MESSAGE_MAX_SIZE: usize = 65536;

/// Maximum number of hops in a circuit
pub const CIRCUIT_MAX_HOPS: usize = 10;

/// Session timeout in seconds (1 hour)
pub const SESSION_TIMEOUT_SECS: u64 = 3600;

/// Maximum number of pending operations
pub const MAX_PENDING_OPS: usize = 1000;

// DHT constants

/// DHT key size in bytes (same as hash size)
pub const DHT_KEY_SIZE: usize = 32;

/// DHT replication factor
pub const DHT_REPLICATION: usize = 3;

/// DHT bucket size
pub const DHT_BUCKET_SIZE: usize = 20;

// Capability token constants

/// Capability token size in bytes
pub const CAPABILITY_TOKEN_SIZE: usize = 128;

/// Capability expiration buffer in seconds (5 minutes)
pub const CAPABILITY_EXPIRATION_BUFFER: u64 = 300;

// Magic bytes for different message types

/// Circuit create message type
pub const MSG_TYPE_CIRCUIT_CREATE: u8 = 0x01;

/// Circuit created message type
pub const MSG_TYPE_CIRCUIT_CREATED: u8 = 0x02;

/// Circuit extend message type
pub const MSG_TYPE_CIRCUIT_EXTEND: u8 = 0x03;

/// Circuit extended message type
pub const MSG_TYPE_CIRCUIT_EXTENDED: u8 = 0x04;

/// Data message type
pub const MSG_TYPE_DATA: u8 = 0x05;

/// Destroy message type
pub const MSG_TYPE_DESTROY: u8 = 0x06;

/// Capability token message type
pub const MSG_TYPE_CAPABILITY: u8 = 0x07;

// Network transport constants

/// Packet header size in bytes
pub const PACKET_HEADER_SIZE: usize = 32;

/// Maximum UDP packet size (64 KB - standard UDP limit)
pub const MAX_PACKET_SIZE: usize = 65536;

/// Default receive timeout in milliseconds
pub const DEFAULT_RECV_TIMEOUT_MS: u64 = 1000;

/// Default send timeout in milliseconds
pub const DEFAULT_SEND_TIMEOUT_MS: u64 = 1000;

/// Maximum number of circuits per node
pub const MAX_CIRCUITS: usize = 10000;

/// Circuit idle timeout in seconds (1 hour)
pub const CIRCUIT_IDLE_TIMEOUT_SECS: u64 = 3600;

/// Connection idle timeout in seconds (5 minutes)
pub const CONNECTION_IDLE_TIMEOUT_SECS: u64 = 300;

/// Peer stale threshold in seconds (1 hour)
pub const PEER_STALE_THRESHOLD_SECS: u64 = 3600;

/// Minimum peer reputation for reliability
pub const MIN_PEER_REPUTATION: i32 = 5;

/// Packet reliability timeout in milliseconds
pub const PACKET_RELIABILITY_TIMEOUT_MS: u64 = 5000;

/// Maximum packet retries
pub const MAX_PACKET_RETRIES: u32 = 3;
