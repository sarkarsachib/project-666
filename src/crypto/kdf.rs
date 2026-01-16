//! Key Derivation Functions
//!
//! Implementation of extract-and-expand KDF (HKDF-like).
//! This provides deterministic key derivation from input key material.

use crate::crypto::sha256::{digest, Sha256};
use crate::constants::HASH_SIZE;

/// Derive a key from input key material
///
/// This is an HKDF-like extract-and-expand KDF using SHA-256.
///
/// # Arguments
///
/// * `salt` - Optional salt (use zeros if not provided)
/// * `ikm` - Input key material
/// * `info` - Context/application-specific information
/// * `output_len` - Desired output length in bytes
///
/// # Returns
///
/// Derived key material
pub fn derive_key(salt: &[u8], ikm: &[u8], info: &[u8], output_len: usize) -> Vec<u8> {
    // Extract phase
    let prk = hkdf_extract(salt, ikm);

    // Expand phase
    hkdf_expand(&prk, info, output_len)
}

/// Derive multiple keys in sequence
///
/// # Arguments
///
/// * `salt` - Optional salt
/// * `ikm` - Input key material
/// * `info` - Context string (will be suffixed with key index)
/// * `count` - Number of keys to derive
///
/// # Returns
///
/// Vector of derived keys (each 32 bytes)
pub fn derive_keys(salt: &[u8], ikm: &[u8], info: &[u8], count: usize) -> Vec<Vec<u8>> {
    let mut keys = Vec::with_capacity(count);

    for i in 0..count {
        let mut info_with_index = info.to_vec();
        info_with_index.push(i as u8);

        let key = derive_key(salt, ikm, &info_with_index, HASH_SIZE);
        keys.push(key);
    }

    keys
}

/// HKDF extract phase
///
/// Computes PRK = HMAC-Hash(salt, IKM)
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    if salt.is_empty() {
        // Default salt: zeros
        digest(ikm)
    } else {
        // H(salt || ikm) - simplified HMAC
        let mut h = Sha256::new();
        h.update(salt);
        h.update(ikm);
        h.finalize()
    }
}

/// HKDF expand phase
///
/// Computes OKM from PRK using info string
fn hkdf_expand(prk: &[u8; 32], info: &[u8], output_len: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(output_len);
    let mut t = Vec::new();
    let mut counter: u8 = 1;

    while result.len() < output_len {
        // T(i) = HMAC(PRK, T(i-1) || info || i)
        let mut h = Sha256::new();

        if !t.is_empty() {
            h.update(&t);
        }

        h.update(info);
        h.update(&[counter]);

        t = h.finalize().to_vec();
        result.extend_from_slice(&t);

        counter += 1;
    }

    // Truncate to desired length
    result.truncate(output_len);
    result
}

/// Derive keys with different context strings
///
/// This is a convenience function for deriving keys with well-separated contexts.
///
/// # Arguments
///
/// * `salt` - Optional salt
/// * `ikm` - Input key material
/// * `contexts` - Vector of context strings
///
/// # Returns
///
/// Vector of derived keys (one per context, each 32 bytes)
pub fn derive_keys_with_contexts(
    salt: &[u8],
    ikm: &[u8],
    contexts: &[&[u8]],
) -> Vec<Vec<u8>> {
    contexts
        .iter()
        .map(|context| derive_key(salt, ikm, context, HASH_SIZE))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // HKDF test vector 1 (RFC 5869 - with SHA-256)
    #[test]
    fn test_hkdf_vector_1() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let output_len = 42;
        let expected = hex::decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865").unwrap();

        let result = derive_key(&salt, &ikm, &info, output_len);
        assert_eq!(result, expected);
    }

    // HKDF test vector 2 (RFC 5869 - with SHA-256)
    #[test]
    fn test_hkdf_vector_2() {
        let ikm = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f").unwrap();
        let salt = hex::decode("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf").unwrap();
        let info = hex::decode("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
        let output_len = 82;
        let expected = hex::decode("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87").unwrap();

        let result = derive_key(&salt, &ikm, &info, output_len);
        assert_eq!(result, expected);
    }

    // Test deterministic derivation
    #[test]
    fn test_deterministic() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"context";

        let result1 = derive_key(salt, ikm, info, 32);
        let result2 = derive_key(salt, ikm, info, 32);

        assert_eq!(result1, result2);
    }

    // Test different salt produces different output
    #[test]
    fn test_different_salt() {
        let ikm = b"input key material";
        let info = b"context";

        let result1 = derive_key(b"salt1", ikm, info, 32);
        let result2 = derive_key(b"salt2", ikm, info, 32);

        assert_ne!(result1, result2);
    }

    // Test different info produces different output
    #[test]
    fn test_different_info() {
        let ikm = b"input key material";
        let salt = b"salt";

        let result1 = derive_key(salt, ikm, b"context1", 32);
        let result2 = derive_key(salt, ikm, b"context2", 32);

        assert_ne!(result1, result2);
    }

    // Test derive multiple keys
    #[test]
    fn test_derive_multiple_keys() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"key";

        let keys = derive_keys(salt, ikm, info, 5);

        assert_eq!(keys.len(), 5);
        for key in &keys {
            assert_eq!(key.len(), 32);
        }

        // All keys should be different
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j]);
            }
        }
    }

    // Test derive keys with contexts
    #[test]
    fn test_derive_keys_with_contexts() {
        let ikm = b"input key material";
        let salt = b"salt";
        let contexts: Vec<&[u8]> = vec![b"encryption", b"authentication", b"signing"];

        let keys = derive_keys_with_contexts(salt, ikm, &contexts);

        assert_eq!(keys.len(), 3);
        for key in &keys {
            assert_eq!(key.len(), 32);
        }

        // All keys should be different
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
        assert_ne!(keys[0], keys[2]);
    }

    // Test empty info
    #[test]
    fn test_empty_info() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"";

        let result = derive_key(salt, ikm, info, 32);
        assert_eq!(result.len(), 32);
    }

    // Test empty salt
    #[test]
    fn test_empty_salt() {
        let ikm = b"input key material";
        let salt = b"";
        let info = b"context";

        let result = derive_key(salt, ikm, info, 32);
        assert_eq!(result.len(), 32);
    }

    // Test output length
    #[test]
    fn test_output_length() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"context";

        for len in [1, 16, 32, 48, 64, 100] {
            let result = derive_key(salt, ikm, info, len);
            assert_eq!(result.len(), len);
        }
    }
}
