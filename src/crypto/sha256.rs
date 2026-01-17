//! SHA-256 cryptographic hash function
//!
//! Implementation of SHA-256 as specified in FIPS 180-4.
//! This is a cryptographic hash function producing a 256-bit digest.

use crate::crypto::utils::{rotl32, u32_to_big_endian};

/// SHA-256 hash function context
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Create a new SHA-256 instance
    pub fn new() -> Self {
        Sha256 {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Update the hash with additional data
    pub fn update(&mut self, data: &[u8]) {
        let mut data = data;
        self.total_len += data.len() as u64;

        while !data.is_empty() {
            if self.buffer_len == 64 {
                self.process_block();
                self.buffer_len = 0;
            }

            let copy_len = core::cmp::min(64 - self.buffer_len, data.len());
            self.buffer[self.buffer_len..self.buffer_len + copy_len]
                .copy_from_slice(&data[..copy_len]);
            self.buffer_len += copy_len;
            data = &data[copy_len..];
        }
    }

    /// Finalize the hash and return the digest
    pub fn finalize(&mut self) -> [u8; 32] {
        // Append bit '1' to message
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // Pad with zeros and append length
        if self.buffer_len > 56 {
            while self.buffer_len < 64 {
                self.buffer[self.buffer_len] = 0;
                self.buffer_len += 1;
            }
            self.process_block();
            self.buffer_len = 0;
        }

        while self.buffer_len < 56 {
            self.buffer[self.buffer_len] = 0;
            self.buffer_len += 1;
        }

        // Append length in bits as big-endian 64-bit integer
        let len_bits = self.total_len * 8;
        let len_bytes = u32_to_big_endian((len_bits >> 32) as u32);
        self.buffer[56..60].copy_from_slice(&len_bytes);
        let len_bytes = u32_to_big_endian(len_bits as u32);
        self.buffer[60..64].copy_from_slice(&len_bytes);

        self.process_block();

        // Output digest
        let mut result = [0u8; 32];
        for i in 0..8 {
            result[i * 4..i * 4 + 4].copy_from_slice(&u32_to_big_endian(self.state[i]));
        }

        result
    }

    /// Process one 512-bit block
    fn process_block(&mut self) {
        // Prepare message schedule
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(
                self.buffer[i * 4..i * 4 + 4].try_into().unwrap()
            );
        }

        for i in 16..64 {
            let s0 = rotl32(w[i - 15], 7)
                ^ rotl32(w[i - 15], 18)
                ^ (w[i - 15] >> 3);
            let s1 = rotl32(w[i - 2], 17)
                ^ rotl32(w[i - 2], 19)
                ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Initialize working variables
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        // Compression function
        for i in 0..64 {
            let s1 = rotl32(e, 6) ^ rotl32(e, 11) ^ rotl32(e, 25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);

            let s0 = rotl32(a, 2) ^ rotl32(a, 13) ^ rotl32(a, 22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        // Update state
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

/// Compute SHA-256 digest of data (one-shot)
pub fn digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

/// SHA-256 round constants (from FIPS 180-4)
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let result = digest(b"");
        assert_eq!(
            hex::encode(result),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_abc() {
        let result = digest(b"abc");
        assert_eq!(
            hex::encode(result),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_sha256_long_message() {
        let message = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let result = digest(message);
        assert_eq!(
            hex::encode(result),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn test_sha256_million_a() {
        let mut data = vec![b'a'; 1_000_000];
        let result = digest(&data);
        assert_eq!(
            hex::encode(result),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn test_sha256_incremental() {
        let mut hasher = Sha256::new();
        hasher.update(b"abc");
        hasher.update(b"def");
        let result = hasher.finalize();

        assert_eq!(digest(b"abcdef"), result);
    }
}
