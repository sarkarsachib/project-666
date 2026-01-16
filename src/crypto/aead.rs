//! ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD)
//!
//! Implementation of ChaCha20-Poly1305 AEAD as specified in RFC 7539.
//! This combines ChaCha20 stream cipher with Poly1305 MAC for authenticated encryption.

use crate::constants::{KEY_SIZE, NONCE_SIZE, POLY1305_TAG_SIZE};
use crate::crypto::chacha20::{ChaCha20, encrypt as chacha20_encrypt};
use crate::crypto::poly1305::{Poly1305, tag as poly1305_tag};
use crate::crypto::utils::{constant_time_compare, u64_to_little_endian};
use std::fmt;

/// AEAD encryption/decryption errors
#[derive(Debug, Clone, PartialEq)]
pub enum AeadError {
    /// Invalid tag length
    InvalidTagLength,
    /// Authentication failed (tag verification failed)
    AuthenticationFailed,
    /// Invalid input length
    InvalidInput,
}

impl fmt::Display for AeadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AeadError::InvalidTagLength => write!(f, "Invalid tag length"),
            AeadError::AuthenticationFailed => write!(f, "Authentication failed"),
            AeadError::InvalidInput => write!(f, "Invalid input length"),
        }
    }
}

impl std::error::Error for AeadError {}

/// Encrypt data using ChaCha20-Poly1305 AEAD
///
/// # Arguments
///
/// * `key` - 256-bit key (32 bytes)
/// * `nonce` - 96-bit nonce (12 bytes)
/// * `aad` - Additional authenticated data (can be empty)
/// * `plaintext` - Data to encrypt
///
/// # Returns
///
/// Tuple of (ciphertext, 16-byte tag)
pub fn encrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; POLY1305_TAG_SIZE]) {
    // Generate Poly1305 key from ChaCha20 with counter=0
    let mut cipher = ChaCha20::new(key, nonce);
    let mut poly_key = [0u8; 32];
    let keystream = cipher.encrypt_block();
    poly_key.copy_from_slice(&keystream[..32]);

    // Encrypt plaintext with ChaCha20 (counter starts at 1)
    cipher.counter = 1;
    let ciphertext = chacha20_encrypt(key, nonce, plaintext);

    // Compute Poly1305 tag over AAD || ciphertext || length encodings
    let mut mac = Poly1305::new(&poly_key);
    mac.update(aad);
    mac.update(&ciphertext);

    // Pad AAD to 16-byte boundary
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    for _ in 0..aad_pad {
        mac.update(&[0]);
    }

    // Pad ciphertext to 16-byte boundary
    let ct_pad = (16 - (ciphertext.len() % 16)) % 16;
    for _ in 0..ct_pad {
        mac.update(&[0]);
    }

    // Append AAD length and ciphertext length (as 64-bit little-endian)
    let aad_len = u64_to_little_endian(aad.len() as u64);
    mac.update(&aad_len);
    let ct_len = u64_to_little_endian(ciphertext.len() as u64);
    mac.update(&ct_len);

    let tag = mac.finalize();

    (ciphertext, tag)
}

/// Decrypt data using ChaCha20-Poly1305 AEAD
///
/// # Arguments
///
/// * `key` - 256-bit key (32 bytes)
/// * `nonce` - 96-bit nonce (12 bytes)
/// * `aad` - Additional authenticated data (can be empty)
/// * `ciphertext` - Data to decrypt
/// * `tag` - Authentication tag (16 bytes)
///
/// # Returns
///
/// Decrypted plaintext if authentication succeeds
///
/// # Errors
///
/// Returns `AeadError::AuthenticationFailed` if tag verification fails
pub fn decrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; POLY1305_TAG_SIZE],
) -> Result<Vec<u8>, AeadError> {
    // Generate Poly1305 key from ChaCha20 with counter=0
    let mut cipher = ChaCha20::new(key, nonce);
    let mut poly_key = [0u8; 32];
    let keystream = cipher.encrypt_block();
    poly_key.copy_from_slice(&keystream[..32]);

    // Compute Poly1305 tag over AAD || ciphertext || length encodings
    let mut mac = Poly1305::new(&poly_key);
    mac.update(aad);
    mac.update(ciphertext);

    // Pad AAD to 16-byte boundary
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    for _ in 0..aad_pad {
        mac.update(&[0]);
    }

    // Pad ciphertext to 16-byte boundary
    let ct_pad = (16 - (ciphertext.len() % 16)) % 16;
    for _ in 0..ct_pad {
        mac.update(&[0]);
    }

    // Append AAD length and ciphertext length (as 64-bit little-endian)
    let aad_len = u64_to_little_endian(aad.len() as u64);
    mac.update(&aad_len);
    let ct_len = u64_to_little_endian(ciphertext.len() as u64);
    mac.update(&ct_len);

    let computed_tag = mac.finalize();

    // Constant-time tag comparison
    if !constant_time_compare(tag, &computed_tag) {
        return Err(AeadError::AuthenticationFailed);
    }

    // Decrypt ciphertext with ChaCha20 (counter starts at 1)
    let plaintext = chacha20_encrypt(key, nonce, ciphertext);

    Ok(plaintext)
}

/// ChaCha20-Poly1305 AEAD cipher context
pub struct AeadCipher {
    key: [u8; KEY_SIZE],
    nonce: [u8; NONCE_SIZE],
}

impl AeadCipher {
    /// Create a new AEAD cipher context
    ///
    /// # Arguments
    ///
    /// * `key` - 256-bit key (32 bytes)
    /// * `nonce` - 96-bit nonce (12 bytes)
    pub fn new(key: &[u8; KEY_SIZE], nonce: &[u8; NONCE_SIZE]) -> Self {
        let mut key_copy = [0u8; KEY_SIZE];
        key_copy.copy_from_slice(key);

        let mut nonce_copy = [0u8; NONCE_SIZE];
        nonce_copy.copy_from_slice(nonce);

        AeadCipher {
            key: key_copy,
            nonce: nonce_copy,
        }
    }

    /// Encrypt in place
    ///
    /// # Arguments
    ///
    /// * `aad` - Additional authenticated data
    /// * `plaintext` - Data to encrypt (modified in place)
    ///
    /// # Returns
    ///
    /// 16-byte authentication tag
    pub fn encrypt_in_place(&self, aad: &[u8], plaintext: &mut [u8]) -> [u8; POLY1305_TAG_SIZE] {
        let (ciphertext, tag) = encrypt(&self.key, &self.nonce, aad, plaintext);
        plaintext.copy_from_slice(&ciphertext);
        tag
    }

    /// Decrypt in place
    ///
    /// # Arguments
    ///
    /// * `aad` - Additional authenticated data
    /// * `ciphertext` - Data to decrypt (modified in place)
    /// * `tag` - Authentication tag
    ///
    /// # Returns
    ///
    /// Ok(()) if authentication succeeds, Err otherwise
    pub fn decrypt_in_place(
        &self,
        aad: &[u8],
        ciphertext: &mut [u8],
        tag: &[u8; POLY1305_TAG_SIZE],
    ) -> Result<(), AeadError> {
        let plaintext = decrypt(&self.key, &self.nonce, aad, ciphertext, tag)?;
        ciphertext.copy_from_slice(&plaintext);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7539 test vector 1
    #[test]
    fn test_rfc7539_vector_1() {
        let key = hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
        let key: [u8; 32] = key.try_into().unwrap();
        let nonce = hex::decode("070000004041424344454647").unwrap();
        let nonce: [u8; 12] = nonce.try_into().unwrap();
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let plaintext = hex::decode("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e").unwrap();
        let expected_ciphertext = hex::decode("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116").unwrap();
        let expected_tag = hex::decode("4aad377794ca9a8f07b4a3").unwrap();

        let (ciphertext, tag) = encrypt(&key, &nonce, &aad, &plaintext);
        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(tag, expected_tag);

        // Test decryption
        let decrypted = decrypt(&key, &nonce, &aad, &ciphertext, &tag).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // RFC 7539 test vector 2
    #[test]
    fn test_rfc7539_vector_2() {
        let key = hex::decode("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0").unwrap();
        let key: [u8; 32] = key.try_into().unwrap();
        let nonce = hex::decode("000000000102030405060708").unwrap();
        let nonce: [u8; 12] = nonce.try_into().unwrap();
        let aad = hex::decode("f33388860000000000004e91").unwrap();
        let plaintext = hex::decode("49206d657420616c206c617267652062696e61727920747265652064617461").unwrap();
        let expected_ciphertext = hex::decode("64a0861575861af460f062c79be6c43fd532e8c13ef5ddb691e5c0a241636e646825a528dc43471877a598868654d754d5833274b9b8fce8f49").unwrap();
        let expected_tag = hex::decode("2e6557da8857ef40").unwrap();

        let (ciphertext, tag) = encrypt(&key, &nonce, &aad, &plaintext);
        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(tag, expected_tag);

        // Test decryption
        let decrypted = decrypt(&key, &nonce, &aad, &ciphertext, &tag).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // Test empty AAD
    #[test]
    fn test_empty_aad() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let aad = b"";
        let plaintext = b"Hello, World!";

        let (ciphertext, tag) = encrypt(&key, &nonce, aad, plaintext);
        let decrypted = decrypt(&key, &nonce, aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    // Test empty plaintext
    #[test]
    fn test_empty_plaintext() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let aad = b"Additional data";
        let plaintext = b"";

        let (ciphertext, tag) = encrypt(&key, &nonce, aad, plaintext);
        assert_eq!(ciphertext, vec![]);

        let decrypted = decrypt(&key, &nonce, aad, &ciphertext, &tag).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // Test tag verification failure
    #[test]
    fn test_tag_verification_failure() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let aad = b"";
        let plaintext = b"Hello, World!";

        let (ciphertext, tag) = encrypt(&key, &nonce, aad, plaintext);

        // Corrupt the tag
        let mut corrupted_tag = tag;
        corrupted_tag[0] ^= 0x01;

        let result = decrypt(&key, &nonce, aad, &ciphertext, &corrupted_tag);
        assert_eq!(result, Err(AeadError::AuthenticationFailed));
    }

    // Test ciphertext corruption
    #[test]
    fn test_ciphertext_corruption() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let aad = b"";
        let plaintext = b"Hello, World!";

        let (mut ciphertext, tag) = encrypt(&key, &nonce, aad, plaintext);

        // Corrupt the ciphertext
        ciphertext[0] ^= 0x01;

        let result = decrypt(&key, &nonce, aad, &ciphertext, &tag);
        assert_eq!(result, Err(AeadError::AuthenticationFailed));
    }

    // Test AAD corruption
    #[test]
    fn test_aad_corruption() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let aad = b"Additional data";
        let plaintext = b"Hello, World!";

        let (ciphertext, tag) = encrypt(&key, &nonce, aad, plaintext);

        let corrupted_aad = b"Additional datX";

        let result = decrypt(&key, &nonce, corrupted_aad, &ciphertext, &tag);
        assert_eq!(result, Err(AeadError::AuthenticationFailed));
    }

    // Test round trip
    #[test]
    fn test_round_trip() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let aad = b"Additional authenticated data";
        let plaintext = b"This is a test message for ChaCha20-Poly1305 AEAD";

        let (ciphertext, tag) = encrypt(&key, &nonce, aad, plaintext);
        let decrypted = decrypt(&key, &nonce, aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    // Test AeadCipher in-place operations
    #[test]
    fn test_aead_cipher_in_place() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let aad = b"AAD";
        let mut data = b"Plaintext data".to_vec();

        let cipher = AeadCipher::new(&key, &nonce);
        let tag = cipher.encrypt_in_place(aad, &mut data);

        let mut decrypted = data.clone();
        cipher.decrypt_in_place(aad, &mut decrypted, &tag).unwrap();

        assert_eq!(decrypted.as_slice(), b"Plaintext data");
    }
}
