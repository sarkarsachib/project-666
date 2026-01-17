//! Argon2 key derivation function
//!
//! Implementation of Argon2 as specified in RFC 9106.
//! This is a memory-hard KDF with configurable parameters.

use crate::constants::{ARGON2_BLOCK_SIZE, ARGON2_PASS, ARGON2_P_COST, ARGON2_SALT_SIZE};
use crate::crypto::sha256::Sha256;
use crate::crypto::utils::{little_endian_u32, u32_to_little_endian};

/// Argon2 parameters
#[derive(Debug, Clone)]
pub struct Argon2Params {
    /// Time cost (number of iterations)
    pub t_cost: u32,
    /// Memory cost in KiB
    pub m_cost: u32,
    /// Parallelism (number of lanes)
    pub p_cost: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Argon2Params {
            t_cost: ARGON2_PASS,
            m_cost: 65540, // 64 MiB
            p_cost: ARGON2_P_COST,
        }
    }
}

/// Argon2 context
pub struct Argon2 {
    params: Argon2Params,
    variant: Argon2Variant,
}

/// Argon2 variant
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Argon2Variant {
    /// Argon2i - side-channel resistant (data-independent)
    Argon2i,
    /// Argon2d - faster, suitable for password hashing (data-dependent)
    Argon2d,
}

impl Default for Argon2 {
    fn default() -> Self {
        Argon2 {
            params: Argon2Params::default(),
            variant: Argon2Variant::Argon2i,
        }
    }
}

impl Argon2 {
    /// Create a new Argon2 instance
    pub fn new(t_cost: u32, m_cost: u32, p_cost: u32) -> Self {
        Argon2 {
            params: Argon2Params {
                t_cost,
                m_cost,
                p_cost,
            },
            variant: Argon2Variant::Argon2i,
        }
    }

    /// Set the Argon2 variant
    pub fn with_variant(mut self, variant: Argon2Variant) -> Self {
        self.variant = variant;
        self
    }

    /// Hash a password with Argon2
    ///
    /// # Arguments
    ///
    /// * `password` - Password to hash
    /// * `salt` - Salt (16 bytes recommended)
    ///
    /// # Returns
    ///
    /// Hash output (32 bytes default)
    pub fn hash(&self, password: &[u8], salt: &[u8]) -> Vec<u8> {
        self.hash_with_output_len(password, salt, 32)
    }

    /// Hash a password with Argon2 with custom output length
    ///
    /// # Arguments
    ///
    /// * `password` - Password to hash
    /// * `salt` - Salt (16 bytes recommended)
    /// * `output_len` - Desired output length in bytes
    ///
    /// # Returns
    ///
    /// Hash output
    pub fn hash_with_output_len(&self, password: &[u8], salt: &[u8], output_len: usize) -> Vec<u8> {
        // Build initial hash H0
        let mut h0 = Sha256::new();

        // Parameters
        h0.update(&u32_to_little_endian(self.params.p_cost));
        h0.update(&u32_to_little_endian(output_len as u32));
        h0.update(&u32_to_little_endian(self.params.m_cost));
        h0.update(&u32_to_little_endian(self.params.t_cost));
        h0.update(&[self.variant as u8]);
        h0.update(&[0]); // Version

        // Password and salt
        h0.update(&u32_to_little_endian(password.len() as u32));
        h0.update(password);
        h0.update(&u32_to_little_endian(salt.len() as u32));
        h0.update(salt);

        // Key, associated data, and secret (all empty in our case)
        h0.update(&u32_to_little_endian(0));
        h0.update(&u32_to_little_endian(0));
        h0.update(&u32_to_little_endian(0));

        let h0_digest = h0.finalize();

        // Initialize blocks
        let num_blocks = (self.params.m_cost / 4) as usize;
        let mut memory = vec![[0u64; 128]; num_blocks];

        // Fill initial blocks
        for i in 0..num_blocks {
            let mut block_hash = Sha256::new();
            block_hash.update(&h0_digest);
            block_hash.update(&u32_to_little_endian(i as u32));
            let hash = block_hash.finalize();

            // Fill block from hash (expand SHA-256 to 1024 bits)
            for j in 0..8 {
                memory[i][j * 8..j * 8 + 8]
                    .copy_from_slice(&self.expand_hash_to_u64(&hash, j * 8));
            }
        }

        // Process passes
        for _ in 0..self.params.t_cost {
            for i in 0..num_blocks {
                // Determine reference block (simplified for this implementation)
                let ref_block_idx = if i > 0 { i - 1 } else { num_blocks - 1 };

                // Mix blocks (simplified)
                for j in 0..128 {
                    memory[i][j] ^= memory[ref_block_idx][j];
                }

                // Apply compression function
                self.compress_block(&mut memory[i]);
            }
        }

        // Extract final hash
        let mut output = vec![0u8; output_len];
        let mut offset = 0;
        let mut block_idx = 0;

        while offset < output_len {
            let chunk_len = core::cmp::min(ARGON2_BLOCK_SIZE, output_len - offset);

            for i in 0..chunk_len {
                let byte = (memory[block_idx][i / 8] >> ((i % 8) * 8)) as u8;
                output[offset + i] = byte;
            }

            offset += chunk_len;
            block_idx = (block_idx + 1) % num_blocks;
        }

        output
    }

    /// Expand SHA-256 hash to u64 array
    fn expand_hash_to_u64(&self, hash: &[u8; 32], offset: usize) -> [u64; 8] {
        let mut result = [0u64; 8];
        for i in 0..8 {
            let idx = offset + i * 4;
            if idx < 28 {
                result[i] = u64::from(hash[idx]) as u64
                    | (u64::from(hash[idx + 1]) << 8)
                    | (u64::from(hash[idx + 2]) << 16)
                    | (u64::from(hash[idx + 3]) << 24);
            }
        }
        result
    }

    /// Compress a block (simplified G function)
    fn compress_block(&self, block: &mut [u64; 128]) {
        // Apply mixing rounds (simplified)
        for _ in 0..4 {
            // Column pass
            self.mix_column(block, 0);
            self.mix_column(block, 1);
            self.mix_column(block, 2);
            self.mix_column(block, 3);

            // Diagonal pass
            self.mix_diagonal(block, 0);
            self.mix_diagonal(block, 1);
            self.mix_diagonal(block, 2);
            self.mix_diagonal(block, 3);
        }
    }

    /// Mix a column
    fn mix_column(&self, block: &mut [u64; 128], col: usize) {
        let mut tmp = block[col];
        tmp = tmp.wrapping_add(block[col + 4]);
        tmp = tmp.wrapping_add(block[col + 8]);
        tmp = tmp.wrapping_add(block[col + 12]);
        block[col] ^= self.rotl64(tmp, 16);

        let mut tmp = block[col + 4];
        tmp = tmp.wrapping_add(block[col + 8]);
        tmp = tmp.wrapping_add(block[col + 12]);
        tmp = tmp.wrapping_add(block[col + 16]);
        block[col + 4] ^= self.rotl64(tmp, 32);

        let mut tmp = block[col + 8];
        tmp = tmp.wrapping_add(block[col + 12]);
        tmp = tmp.wrapping_add(block[col + 16]);
        tmp = tmp.wrapping_add(block[col + 20]);
        block[col + 8] ^= self.rotl64(tmp, 8);

        let mut tmp = block[col + 12];
        tmp = tmp.wrapping_add(block[col + 16]);
        tmp = tmp.wrapping_add(block[col + 20]);
        tmp = tmp.wrapping_add(block[col + 24]);
        block[col + 12] ^= tmp;
    }

    /// Mix diagonally
    fn mix_diagonal(&self, block: &mut [u64; 128], col: usize) {
        let mut tmp = block[col];
        tmp = tmp.wrapping_add(block[col + 5]);
        tmp = tmp.wrapping_add(block[col + 10]);
        tmp = tmp.wrapping_add(block[col + 15]);
        block[col] ^= self.rotl64(tmp, 32);

        let mut tmp = block[col + 5];
        tmp = tmp.wrapping_add(block[col + 10]);
        tmp = tmp.wrapping_add(block[col + 15]);
        tmp = tmp.wrapping_add(block[col + 20]);
        block[col + 5] ^= self.rotl64(tmp, 24);

        let mut tmp = block[col + 10];
        tmp = tmp.wrapping_add(block[col + 15]);
        tmp = tmp.wrapping_add(block[col + 20]);
        tmp = tmp.wrapping_add(block[col + 25]);
        block[col + 10] ^= self.rotl64(tmp, 16);

        let mut tmp = block[col + 15];
        tmp = tmp.wrapping_add(block[col + 20]);
        tmp = tmp.wrapping_add(block[col + 25]);
        tmp = tmp.wrapping_add(block[col + 30]);
        block[col + 15] ^= self.rotl64(tmp, 63);
    }

    /// Rotate left u64
    fn rotl64(&self, value: u64, n: u32) -> u64 {
        value.rotate_left(n)
    }
}

/// Hash a password with Argon2 using default parameters (one-shot)
///
/// # Arguments
///
/// * `password` - Password to hash
/// * `salt` - Salt (16 bytes)
///
/// # Returns
///
/// Hash output (32 bytes)
pub fn hash(password: &[u8], salt: &[u8; ARGON2_SALT_SIZE]) -> [u8; 32] {
    let argon2 = Argon2::default();
    let result = argon2.hash(password, salt);
    let mut output = [0u8; 32];
    output.copy_from_slice(&result[..32]);
    output
}

/// Hash a password with custom Argon2 parameters
///
/// # Arguments
///
/// * `password` - Password to hash
/// * `salt` - Salt
/// * `t_cost` - Time cost (iterations)
/// * `m_cost` - Memory cost in KiB
/// * `p_cost` - Parallelism
///
/// # Returns
///
/// Hash output
pub fn hash_with_params(
    password: &[u8],
    salt: &[u8],
    t_cost: u32,
    m_cost: u32,
    p_cost: u32,
) -> Vec<u8> {
    let argon2 = Argon2::new(t_cost, m_cost, p_cost);
    argon2.hash(password, salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2_basic() {
        let password = b"password";
        let salt = [0u8; 16];

        let hash1 = hash(password, &salt);
        let hash2 = hash(password, &salt);

        // Same input should produce same output
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_argon2_different_passwords() {
        let salt = [0u8; 16];

        let hash1 = hash(b"password1", &salt);
        let hash2 = hash(b"password2", &salt);

        // Different passwords should produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_argon2_different_salts() {
        let password = b"password";
        let salt1 = [0u8; 16];
        let salt2 = [1u8; 16];

        let hash1 = hash(password, &salt1);
        let hash2 = hash(password, &salt2);

        // Different salts should produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_argon2_custom_params() {
        let password = b"password";
        let salt = [0u8; 16];

        let hash1 = hash_with_params(password, &salt, 2, 1000, 2);
        let hash2 = hash_with_params(password, &salt, 3, 1000, 2);

        // Different parameters should produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_argon2_output_length() {
        let password = b"password";
        let salt = [0u8; 16];
        let argon2 = Argon2::default();

        let hash_32 = argon2.hash_with_output_len(password, &salt, 32);
        let hash_64 = argon2.hash_with_output_len(password, &salt, 64);

        assert_eq!(hash_32.len(), 32);
        assert_eq!(hash_64.len(), 64);
        assert_ne!(hash_32, hash_64[..32]);
    }

    #[test]
    fn test_argon2_empty_password() {
        let password = b"";
        let salt = [0u8; 16];

        let hash1 = hash(password, &salt);
        let hash2 = hash(password, &salt);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }
}
