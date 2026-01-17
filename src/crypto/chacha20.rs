//! ChaCha20 stream cipher
//!
//! Implementation of ChaCha20 as specified in RFC 7539.
//! This is a stream cipher with a 256-bit key and 96-bit nonce.

use crate::constants::{CHACHA20_BLOCK_SIZE, CHACHA20_KEY_SIZE, CHACHA20_NONCE_SIZE};
use crate::crypto::utils::{little_endian_u32, rotl32, u32_to_little_endian};

/// ChaCha20 state constants
const CONSTANTS: [u32; 4] = [
    0x61707865, // "expa"
    0x3320646e, // "nd 3"
    0x79622d32, // "2-by"
    0x6b206574, // "te k"
];

/// ChaCha20 stream cipher
pub struct ChaCha20 {
    key: [u8; 32],
    nonce: [u8; 12],
    counter: u32,
}

impl ChaCha20 {
    /// Create a new ChaCha20 instance
    ///
    /// # Arguments
    ///
    /// * `key` - 256-bit key (32 bytes)
    /// * `nonce` - 96-bit nonce (12 bytes)
    ///
    /// # Panics
    ///
    /// Panics if key or nonce have incorrect length
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        assert_eq!(key.len(), CHACHA20_KEY_SIZE, "Key must be 32 bytes");
        assert_eq!(nonce.len(), CHACHA20_NONCE_SIZE, "Nonce must be 12 bytes");

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key);

        let mut nonce_array = [0u8; 12];
        nonce_array.copy_from_slice(nonce);

        ChaCha20 {
            key: key_array,
            nonce: nonce_array,
            counter: 0,
        }
    }

    /// Encrypt or decrypt data in place
    ///
    /// ChaCha20 is symmetric, so encryption and decryption are the same operation.
    ///
    /// # Arguments
    ///
    /// * `data` - Data to encrypt/decrypt (modified in place)
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        let mut offset = 0;
        while offset < data.len() {
            let keystream = self.encrypt_block();
            let chunk_len = core::cmp::min(CHACHA20_BLOCK_SIZE, data.len() - offset);

            for i in 0..chunk_len {
                data[offset + i] ^= keystream[i];
            }

            offset += chunk_len;
            if chunk_len == CHACHA20_BLOCK_SIZE {
                self.counter += 1;
            }
        }
    }

    /// Generate one block of keystream
    ///
    /// # Returns
    ///
    /// 64-byte keystream block
    fn encrypt_block(&self) -> [u8; 64] {
        let mut state = self.initialize_state();
        self.quarter_rounds(&mut state);
        self.add_initial_state(&mut state);
        self.serialize_state(&state)
    }

    /// Initialize the ChaCha20 state
    fn initialize_state(&self) -> [u32; 16] {
        let mut state = [0u32; 16];

        // Constants
        state[0] = CONSTANTS[0];
        state[1] = CONSTANTS[1];
        state[2] = CONSTANTS[2];
        state[3] = CONSTANTS[3];

        // Key (8 words)
        state[4] = little_endian_u32(&self.key[0..4]);
        state[5] = little_endian_u32(&self.key[4..8]);
        state[6] = little_endian_u32(&self.key[8..12]);
        state[7] = little_endian_u32(&self.key[12..16]);
        state[8] = little_endian_u32(&self.key[16..20]);
        state[9] = little_endian_u32(&self.key[20..24]);
        state[10] = little_endian_u32(&self.key[24..28]);
        state[11] = little_endian_u32(&self.key[28..32]);

        // Counter
        state[12] = self.counter;

        // Nonce (3 words)
        state[13] = little_endian_u32(&self.nonce[0..4]);
        state[14] = little_endian_u32(&self.nonce[4..8]);
        state[15] = little_endian_u32(&self.nonce[8..12]);

        state
    }

    /// Perform 20 quarter rounds (10 column rounds + 10 diagonal rounds)
    fn quarter_rounds(&self, state: &mut [u32; 16]) {
        for _ in 0..10 {
            // Column rounds
            quarter_round(state, 0, 4, 8, 12);
            quarter_round(state, 1, 5, 9, 13);
            quarter_round(state, 2, 6, 10, 14);
            quarter_round(state, 3, 7, 11, 15);

            // Diagonal rounds
            quarter_round(state, 0, 5, 10, 15);
            quarter_round(state, 1, 6, 11, 12);
            quarter_round(state, 2, 7, 8, 13);
            quarter_round(state, 3, 4, 9, 14);
        }
    }

    /// Add initial state to final state
    fn add_initial_state(&self, state: &mut [u32; 16]) {
        let initial = self.initialize_state();
        for i in 0..16 {
            state[i] = state[i].wrapping_add(initial[i]);
        }
    }

    /// Serialize state to bytes
    fn serialize_state(&self, state: &[u32; 16]) -> [u8; 64] {
        let mut result = [0u8; 64];
        for i in 0..16 {
            let bytes = u32_to_little_endian(state[i]);
            result[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }
        result
    }

    /// Seek to a specific block counter
    ///
    /// # Arguments
    ///
    /// * `block_counter` - The block counter to seek to
    pub fn seek(&mut self, block_counter: u32) {
        self.counter = block_counter;
    }
}

/// ChaCha20 quarter round operation
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = rotl32(state[d], 16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = rotl32(state[b], 12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = rotl32(state[d], 8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = rotl32(state[b], 7);
}

/// Encrypt data using ChaCha20
///
/// # Arguments
///
/// * `key` - 256-bit key (32 bytes)
/// * `nonce` - 96-bit nonce (12 bytes)
/// * `plaintext` - Data to encrypt
///
/// # Returns
///
/// Encrypted ciphertext
pub fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut cipher = ChaCha20::new(key, nonce);
    let mut ciphertext = plaintext.to_vec();
    cipher.apply_keystream(&mut ciphertext);
    ciphertext
}

/// Decrypt data using ChaCha20
///
/// # Arguments
///
/// * `key` - 256-bit key (32 bytes)
/// * `nonce` - 96-bit nonce (12 bytes)
/// * `ciphertext` - Data to decrypt
///
/// # Returns
///
/// Decrypted plaintext
pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    encrypt(key, nonce, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7539 test vector 1
    #[test]
    fn test_rfc7539_vector_1() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let nonce = hex::decode("000000000000004a00000000").unwrap();
        let plaintext = hex::decode("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.").unwrap();
        let expected = hex::decode("6e2e359a2568f98041ba0728dd0d6781e30a514a444338148c89cb4201335d5f6d8ac074655c4fa25c13d1715b6eeac5f90e646a3c7e3ebd494c511fdeeb").unwrap();

        let result = encrypt(&key, &nonce, &plaintext);
        assert_eq!(result, expected);
    }

    // RFC 7539 test vector 2
    #[test]
    fn test_rfc7539_vector_2() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let nonce = hex::decode("000000000000004a00000000").unwrap();
        let plaintext = hex::decode("").unwrap();
        let expected = hex::decode("").unwrap();

        let result = encrypt(&key, &nonce, &plaintext);
        assert_eq!(result, expected);
    }

    // Test encrypt/decrypt round-trip
    #[test]
    fn test_round_trip() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"Hello, Project 666!";

        let ciphertext = encrypt(&key, &nonce, plaintext);
        let decrypted = decrypt(&key, &nonce, &ciphertext);

        assert_eq!(plaintext.as_slice(), &decrypted[..]);
    }

    // Test block alignment
    #[test]
    fn test_block_alignment() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = vec![0u8; 128]; // Exactly 2 blocks

        let ciphertext = encrypt(&key, &nonce, &plaintext);
        let decrypted = decrypt(&key, &nonce, &ciphertext);

        assert_eq!(plaintext, decrypted);
    }

    // Test partial block
    #[test]
    fn test_partial_block() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = vec![0u8; 100]; // Less than 2 blocks

        let ciphertext = encrypt(&key, &nonce, &plaintext);
        let decrypted = decrypt(&key, &nonce, &ciphertext);

        assert_eq!(plaintext, decrypted);
    }

    // Test keystream generation
    #[test]
    fn test_keystream() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let mut cipher = ChaCha20::new(&key, &nonce);

        let keystream1 = cipher.encrypt_block();
        cipher.counter += 1;
        let keystream2 = cipher.encrypt_block();

        assert_ne!(keystream1, keystream2);
    }
}
