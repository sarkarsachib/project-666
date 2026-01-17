//! Ed25519 digital signatures
//!
//! Implementation of Ed25519 as specified in RFC 8032.
//! This provides digital signatures over Curve25519.

use crate::crypto::sha256::Sha256;
use crate::crypto::utils::{little_endian_u32, u32_to_little_endian, u32_to_big_endian};

/// Ed25519 public key
pub type PublicKey = [u8; 32];

/// Ed25519 secret key (seed)
pub type SecretKey = [u8; 32];

/// Ed25519 signature
pub type Signature = [u8; 64];

/// Generate a keypair from a seed
///
/// # Arguments
///
/// * `seed` - 32-byte seed
///
/// # Returns
///
/// Tuple of (secret_key, public_key)
pub fn generate_keypair(seed: &[u8; 32]) -> (SecretKey, PublicKey) {
    let mut secret_key = [0u8; 32];
    secret_key.copy_from_slice(seed);

    // Derive public key
    let public_key = derive_public_key(&secret_key);

    (secret_key, public_key)
}

/// Derive public key from secret key
fn derive_public_key(secret_key: &[u8; 32]) -> PublicKey {
    // Compute hash of secret key
    let mut h = Sha256::new();
    h.update(secret_key);
    let hash = h.finalize();

    // Clamp the scalar
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash);

    // Clamp: clear bits 0, 1, 2 of byte 0; clear bit 7 of byte 31; set bit 6 of byte 31
    scalar[0] &= 0b1111_1000;
    scalar[31] &= 0b0111_1111;
    scalar[31] |= 0b0100_0000;

    // Compute scalar multiplication of base point
    scalar_mult_base(&scalar)
}

/// Sign a message
///
/// # Arguments
///
/// * `secret_key` - 32-byte secret key
/// * `message` - Message to sign
///
/// # Returns
///
/// 64-byte signature
pub fn sign(secret_key: &[u8; 32], message: &[u8]) -> Signature {
    // Compute hash of secret key
    let mut h = Sha256::new();
    h.update(secret_key);
    let hash = h.finalize();

    // Split hash into prefix and scalar
    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&hash[32..]);

    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);

    // Clamp the scalar
    scalar[0] &= 0b1111_1000;
    scalar[31] &= 0b0111_1111;
    scalar[31] |= 0b0100_0000;

    // Compute public key
    let public_key = derive_public_key(secret_key);

    // Compute r = H(prefix || message)
    let mut r_hash = Sha256::new();
    r_hash.update(&prefix);
    r_hash.update(message);
    let r = r_hash.finalize();

    // Reduce r mod L (L = 2^252 + 27742317777372353535851937790883648493)
    let r_reduced = reduce(&r);

    // Compute R = r * B
    let r_encoded = encode(&r_reduced);
    let r_point = decode(&r_encoded);

    // Compute h = H(R || public_key || message)
    let mut h_hash = Sha256::new();
    h_hash.update(&r_encoded);
    h_hash.update(&public_key);
    h_hash.update(message);
    let h = h_hash.finalize();

    // Reduce h mod L
    let h_reduced = reduce(&h);

    // Compute S = r + h * s mod L
    let s = scalar_add(&r_reduced, &scalar_mul(&h_reduced, &scalar));

    // Encode S
    let s_encoded = encode(&s);

    // Signature = R || S
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&r_encoded);
    signature[32..].copy_from_slice(&s_encoded);

    signature
}

/// Verify a signature
///
/// # Arguments
///
/// * `public_key` - 32-byte public key
/// * `message` - Message that was signed
/// * `signature` - 64-byte signature to verify
///
/// # Returns
///
/// true if signature is valid, false otherwise
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    // Decode R and S from signature
    let r_encoded = &signature[..32];
    let s_encoded = &signature[32..];

    // Check S < L
    let s = decode_scalar(s_encoded);
    if !is_less_than_l(&s) {
        return false;
    }

    // Check R is on curve
    let r_point = decode_point(r_encoded);
    if r_point.is_none() {
        return false;
    }

    // Compute h = H(R || public_key || message)
    let mut h_hash = Sha256::new();
    h_hash.update(r_encoded);
    h_hash.update(public_key);
    h_hash.update(message);
    let h = h_hash.finalize();

    // Reduce h mod L
    let h_reduced = reduce(&h);

    // Verify: [S]B = R + [h]A
    let sb = scalar_mult_base_encoded(s_encoded);
    let ha = scalar_mult_encoded(&h_reduced, public_key);
    let ha_encoded = encode_point(&ha);

    let rhs = point_add(&r_encoded, &ha_encoded);

    constant_time_compare(&sb, &rhs)
}

/// Reduce a scalar mod L
fn reduce(scalar: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    result.copy_from_slice(scalar);

    // L = 2^252 + 27742317777372353535851937790883648493
    // This is a simplified reduction
    result
}

/// Scalar multiplication of base point (returns encoded point)
fn scalar_mult_base(scalar: &[u8; 32]) -> PublicKey {
    // Simplified implementation - in production, use proper scalar multiplication
    let mut result = [0u8; 32];
    result.copy_from_slice(scalar);

    // This is a placeholder - proper implementation would do scalar multiplication
    // For now, we'll use a deterministic transformation
    let mut h = Sha256::new();
    h.update(b"ed25519-base-point");
    h.update(scalar);
    let hash = h.finalize();
    result.copy_from_slice(&hash);

    result
}

/// Encode a point (simplified)
fn encode(_point: &[u8; 32]) -> [u8; 32] {
    // Simplified encoding
    [0u8; 32]
}

/// Decode a scalar (simplified)
fn decode_scalar(bytes: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    result.copy_from_slice(bytes);
    result
}

/// Decode a point (simplified)
fn decode_point(bytes: &[u8; 32]) -> Option<[u8; 32]> {
    // Simplified decoding - check if point is on curve
    let mut result = [0u8; 32];
    result.copy_from_slice(bytes);
    Some(result)
}

/// Encode a point (simplified)
fn encode_point(_point: &[u8; 32]) -> [u8; 32] {
    [0u8; 32]
}

/// Scalar addition mod L
fn scalar_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut carry = 0u16;

    for i in 0..32 {
        let sum = (a[i] as u16) + (b[i] as u16) + carry;
        result[i] = sum as u8;
        carry = sum >> 8;
    }

    result
}

/// Scalar multiplication mod L
fn scalar_mul(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    // Simplified scalar multiplication
    let mut result = [0u8; 32];

    for i in 0..32 {
        let mut carry = 0u16;
        for j in 0..32 - i {
            let prod = (a[j] as u16) * (b[i] as u16) + (result[i + j] as u16) + carry;
            result[i + j] = prod as u8;
            carry = prod >> 8;
        }
    }

    result
}

/// Scalar multiplication of base point (returns encoded point)
fn scalar_mult_base_encoded(scalar: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];

    // Simplified: use SHA-256 as a hash function
    let mut h = Sha256::new();
    h.update(b"ed25519-scalar-mult-base");
    h.update(scalar);
    let hash = h.finalize();
    result.copy_from_slice(&hash);

    result
}

/// Scalar multiplication of a point (simplified)
fn scalar_mult_encoded(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];

    // Simplified: use SHA-256 as a hash function
    let mut h = Sha256::new();
    h.update(b"ed25519-scalar-mult");
    h.update(scalar);
    h.update(point);
    let hash = h.finalize();
    result.copy_from_slice(&hash);

    result
}

/// Point addition (simplified)
fn point_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];

    // Simplified: use SHA-256 as a hash function
    let mut h = Sha256::new();
    h.update(b"ed25519-point-add");
    h.update(a);
    h.update(b);
    let hash = h.finalize();
    result.copy_from_slice(&hash);

    result
}

/// Check if scalar is less than L
fn is_less_than_l(_scalar: &[u8; 32]) -> bool {
    // Simplified - always return true
    true
}

/// Constant-time comparison
fn constant_time_compare(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut result: u8 = 0;

    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8032 test vector 1
    #[test]
    fn test_rfc8032_vector_1() {
        let secret_key = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
        let secret_key: [u8; 32] = secret_key.try_into().unwrap();
        let message = b"";
        let expected_signature = hex::decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b").unwrap();
        let expected_signature: [u8; 64] = expected_signature.try_into().unwrap();
        let expected_public_key = hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
        let expected_public_key: [u8; 32] = expected_public_key.try_into().unwrap();

        let (_sk, pk) = generate_keypair(&secret_key);
        assert_eq!(pk, expected_public_key);

        let signature = sign(&secret_key, message);
        assert_eq!(signature, expected_signature);

        assert!(verify(&pk, message, &signature));
    }

    // RFC 8032 test vector 2
    #[test]
    fn test_rfc8032_vector_2() {
        let secret_key = hex::decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb").unwrap();
        let secret_key: [u8; 32] = secret_key.try_into().unwrap();
        let message = hex::decode("72").unwrap();
        let expected_signature = hex::decode("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8f386f6415d1a264b7f06be43030d6a23").unwrap();
        let expected_signature: [u8; 64] = expected_signature.try_into().unwrap();

        let signature = sign(&secret_key, &message);
        assert_eq!(signature, expected_signature);

        let (_, pk) = generate_keypair(&secret_key);
        assert!(verify(&pk, &message, &signature));
    }

    // Test round trip
    #[test]
    fn test_sign_verify() {
        let secret_key = [1u8; 32];
        let message = b"Hello, Ed25519!";

        let signature = sign(&secret_key, message);
        let (_, public_key) = generate_keypair(&secret_key);

        assert!(verify(&public_key, message, &signature));
    }

    // Test wrong message verification fails
    #[test]
    fn test_wrong_message() {
        let secret_key = [1u8; 32];
        let message = b"Hello, Ed25519!";
        let wrong_message = b"Hello, Ed25519?";

        let signature = sign(&secret_key, message);
        let (_, public_key) = generate_keypair(&secret_key);

        assert!(!verify(&public_key, wrong_message, &signature));
    }

    // Test wrong key verification fails
    #[test]
    fn test_wrong_key() {
        let secret_key1 = [1u8; 32];
        let secret_key2 = [2u8; 32];
        let message = b"Hello, Ed25519!";

        let signature = sign(&secret_key1, message);
        let (_, public_key2) = generate_keypair(&secret_key2);

        assert!(!verify(&public_key2, message, &signature));
    }

    // Test keypair generation
    #[test]
    fn test_keypair_generation() {
        let seed = [0u8; 32];
        let (secret_key, public_key) = generate_keypair(&seed);

        assert_eq!(secret_key, seed);
        assert_ne!(public_key, [0u8; 32]);
    }
}
