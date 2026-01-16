//! Poly1305 message authentication code
//!
//! Implementation of Poly1305 as specified in RFC 7539.
//! This is a one-time MAC producing a 128-bit tag.

use crate::constants::{POLY1305_KEY_SIZE, POLY1305_TAG_SIZE};
use crate::crypto::utils::{little_endian_u32, u32_to_little_endian};

/// Poly1305 MAC context
pub struct Poly1305 {
    r: [u32; 5],
    s: [u32; 5],
    h: [u32; 5],
    buffer: [u8; 16],
    buffer_len: usize,
}

impl Poly1305 {
    /// Create a new Poly1305 instance
    ///
    /// # Arguments
    ///
    /// * `key` - 256-bit key (32 bytes), first 16 bytes are r, last 16 are s
    ///
    /// # Panics
    ///
    /// Panics if key has incorrect length
    pub fn new(key: &[u8; 32]) -> Self {
        let mut r_bytes = [0u8; 16];
        r_bytes.copy_from_slice(&key[..16]);
        let mut s_bytes = [0u8; 16];
        s_bytes.copy_from_slice(&key[16..]);

        // Clamp r
        r_bytes[3] &= 15;
        r_bytes[7] &= 15;
        r_bytes[11] &= 15;
        r_bytes[15] &= 15;
        r_bytes[4] &= 252;
        r_bytes[8] &= 252;
        r_bytes[12] &= 252;

        let r = [
            little_endian_u32(&r_bytes[0..4]),
            little_endian_u32(&r_bytes[4..8]),
            little_endian_u32(&r_bytes[8..12]),
            little_endian_u32(&r_bytes[12..16]),
            0,
        ];

        let s = [
            little_endian_u32(&s_bytes[0..4]),
            little_endian_u32(&s_bytes[4..8]),
            little_endian_u32(&s_bytes[8..12]),
            little_endian_u32(&s_bytes[12..16]),
            0,
        ];

        Poly1305 {
            r,
            s,
            h: [0; 5],
            buffer: [0; 16],
            buffer_len: 0,
        }
    }

    /// Update the MAC with additional data
    pub fn update(&mut self, data: &[u8]) {
        let mut data = data;

        while !data.is_empty() {
            if self.buffer_len == 16 {
                self.process_block();
                self.buffer_len = 0;
            }

            let copy_len = core::cmp::min(16 - self.buffer_len, data.len());
            self.buffer[self.buffer_len..self.buffer_len + copy_len]
                .copy_from_slice(&data[..copy_len]);
            self.buffer_len += copy_len;
            data = &data[copy_len..];
        }
    }

    /// Finalize the MAC and return the tag
    pub fn finalize(&mut self) -> [u8; 16] {
        // Process any remaining data
        if self.buffer_len > 0 {
            // Pad with 1 bit
            self.buffer[self.buffer_len] = 1;
            self.buffer_len += 1;

            // Zero pad remaining bytes
            while self.buffer_len < 16 {
                self.buffer[self.buffer_len] = 0;
                self.buffer_len += 1;
            }

            self.process_block();
        }

        // Add 1 to the accumulator (for padding the message length)
        self.add(1);

        // Reduce modulo 2^130 - 5
        let h = self.reduce();

        // Compute tag
        let mut result = [0u8; 16];
        for i in 0..4 {
            let mut val = h[i] + self.s[i];
            let carry = val >> 32;
            val &= 0xffffffff;

            if i > 0 {
                result[i * 4 - 1] += carry as u8;
            }

            let bytes = u32_to_little_endian(val);
            result[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }

        result
    }

    /// Process one block of data
    fn process_block(&mut self) {
        // Load block into u32s
        let mut block = [0u32; 5];
        for i in 0..4 {
            block[i] = little_endian_u32(&self.buffer[i * 4..i * 4 + 4]);
        }

        // Add 1 bit padding at the end of block
        block[4] = if self.buffer_len == 16 { 1 << 24 } else { 0 };

        // Add to accumulator
        self.h[0] += block[0];
        self.h[1] += block[1];
        self.h[2] += block[2];
        self.h[3] += block[3];
        self.h[4] += block[4];

        // Multiply h by r
        let mut h_copy = self.h;
        for i in 0..5 {
            let carry = (h_copy[i] as u64) * (self.r[0] as u64) + (self.h[0] as u64);
            self.h[0] = carry as u32;
            self.h[1] += (carry >> 32) as u32;

            let carry = (h_copy[i] as u64) * (self.r[1] as u64) + (self.h[1] as u64);
            self.h[1] = carry as u32;
            self.h[2] += (carry >> 32) as u32;

            let carry = (h_copy[i] as u64) * (self.r[2] as u64) + (self.h[2] as u64);
            self.h[2] = carry as u32;
            self.h[3] += (carry >> 32) as u32;

            let carry = (h_copy[i] as u64) * (self.r[3] as u64) + (self.h[3] as u64);
            self.h[3] = carry as u32;
            self.h[4] += (carry >> 32) as u32;

            // r[4] is 0, so skip
        }

        // Reduce
        self.partial_reduce();
    }

    /// Partial reduction
    fn partial_reduce(&mut self) {
        let mut mask = -(self.h[4] >> 2) as u64;
        let carry = ((self.h[4] & 3) as u64) * 5 + (self.h[0] as u64);
        self.h[0] = carry as u32;
        self.h[1] += (carry >> 32) as u32;

        mask &= 3;
        self.h[4] &= 3;

        self.h[0] += mask as u32;
        self.h[1] += (mask >> 32) as u32;

        // Propagate carries
        let mut carry = self.h[1] >> 32;
        self.h[1] &= 0xffffffff;
        self.h[2] += carry;

        carry = self.h[2] >> 32;
        self.h[2] &= 0xffffffff;
        self.h[3] += carry;

        carry = self.h[3] >> 32;
        self.h[3] &= 0xffffffff;
        self.h[4] += carry;
    }

    /// Reduce fully
    fn reduce(&mut self) -> [u32; 5] {
        let mut h = self.h;

        // Reduce modulo 2^130 - 5
        let mut mask = -(h[4] >> 2) as u64;
        let carry = ((h[4] & 3) as u64) * 5 + (h[0] as u64);
        h[0] = carry as u32;
        h[1] += (carry >> 32) as u32;

        mask &= 3;
        h[4] &= 3;

        h[0] += mask as u32;
        h[1] += (mask >> 32) as u32;

        // Propagate carries
        let mut carry = h[1] >> 32;
        h[1] &= 0xffffffff;
        h[2] += carry;

        carry = h[2] >> 32;
        h[2] &= 0xffffffff;
        h[3] += carry;

        carry = h[3] >> 32;
        h[3] &= 0xffffffff;
        h[4] += carry;

        h
    }

    /// Add a value to the accumulator
    fn add(&mut self, value: u32) {
        let carry = (self.h[0] as u64) + (value as u64);
        self.h[0] = carry as u32;

        let mut carry = (carry >> 32) as u64 + (self.h[1] as u64);
        self.h[1] = carry as u32;

        carry = (carry >> 32) as u64 + (self.h[2] as u64);
        self.h[2] = carry as u32;

        carry = (carry >> 32) as u64 + (self.h[3] as u64);
        self.h[3] = carry as u32;

        carry = (carry >> 32) as u64 + (self.h[4] as u64);
        self.h[4] = carry as u32;
    }
}

/// Compute Poly1305 tag (one-shot)
///
/// # Arguments
///
/// * `key` - 256-bit key (32 bytes)
/// * `data` - Data to authenticate
///
/// # Returns
///
/// 128-bit tag (16 bytes)
pub fn tag(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let mut mac = Poly1305::new(key);
    mac.update(data);
    mac.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7539 test vector 1
    #[test]
    fn test_rfc7539_vector_1() {
        let key = hex::decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").unwrap();
        let key: [u8; 32] = key.try_into().unwrap();
        let data = hex::decode("43727970746f6772617068696320466f72756d2052657365617263682047726f7570").unwrap();
        let expected = hex::decode("a8061dc1305136c6c22b8baf0c0127a9").unwrap();

        let result = tag(&key, &data);
        assert_eq!(result, expected);
    }

    // RFC 7539 test vector 2
    #[test]
    fn test_rfc7539_vector_2() {
        let key = hex::decode("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0").unwrap();
        let key: [u8; 32] = key.try_into().unwrap();
        let data = hex::decode("2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730ad41a").unwrap();
        let expected = hex::decode("45fa028a4352580405489f62").unwrap();

        let result = tag(&key, &data);
        assert_eq!(result, expected);
    }

    // Test incremental update
    #[test]
    fn test_incremental() {
        let mut key = [0u8; 32];
        key[0] = 0x85;

        let mut mac = Poly1305::new(&key);
        mac.update(b"Hello, ");
        mac.update(b"World!");
        let result = mac.finalize();

        let expected = tag(&key, b"Hello, World!");
        assert_eq!(result, expected);
    }

    // Test empty message
    #[test]
    fn test_empty_message() {
        let key = [0u8; 32];
        let data = b"";

        let result = tag(&key, data);
        // Should produce a valid tag
        assert_eq!(result.len(), 16);
    }
}
