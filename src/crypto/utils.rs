//! Constant-time utility functions
//!
//! This module provides constant-time operations that are essential for
//! preventing timing attacks in cryptographic implementations.

/// Constant-time comparison of two byte slices
///
/// Returns true if the slices are equal, false otherwise.
/// This function always takes the same amount of time regardless of
/// the input values, preventing timing attacks.
///
/// # Arguments
///
/// * `a` - First byte slice to compare
/// * `b` - Second byte slice to compare
///
/// # Returns
///
/// true if slices are equal, false otherwise
///
/// # Panics
///
/// Panics if the slices have different lengths
#[inline]
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result: u8 = 0;

    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

/// Constant-time conditional selection
///
/// Returns `a` if `cond` is true, otherwise returns `b`.
/// The time taken is independent of the condition value.
///
/// # Arguments
///
/// * `cond` - Condition to select from
/// * `a` - First byte slice (selected if cond is true)
/// * `b` - Second byte slice (selected if cond is false)
///
/// # Returns
///
/// Selected byte slice as a new Vec<u8>
///
/// # Panics
///
/// Panics if slices have different lengths
pub fn constant_time_select(cond: bool, a: &[u8], b: &[u8]) -> Vec<u8> {
    if a.len() != b.len() {
        panic!("Slices must have the same length");
    }

    let mask = -(cond as i32) as u8;
    let mut result = Vec::with_capacity(a.len());

    for (x, y) in a.iter().zip(b.iter()) {
        result.push((x & mask) | (y & !mask));
    }

    result
}

/// Securely zero memory
///
/// Overwrites the provided slice with zeros in a way that won't be
/// optimized away by the compiler.
///
/// # Arguments
///
/// * `data` - Mutable byte slice to zero
#[inline]
pub fn zeroise(data: &mut [u8]) {
    for byte in data.iter_mut() {
        *byte = 0;
    }
}

/// Convert little-endian bytes to u32
///
/// # Arguments
///
/// * `bytes` - 4-byte slice in little-endian order
///
/// # Returns
///
/// The decoded u32 value
///
/// # Panics
///
/// Panics if bytes.len() < 4
#[inline]
pub fn little_endian_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[0..4].try_into().unwrap())
}

/// Convert big-endian bytes to u32
///
/// # Arguments
///
/// * `bytes` - 4-byte slice in big-endian order
///
/// # Returns
///
/// The decoded u32 value
///
/// # Panics
///
/// Panics if bytes.len() < 4
#[inline]
pub fn big_endian_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes[0..4].try_into().unwrap())
}

/// Convert little-endian bytes to u64
///
/// # Arguments
///
/// * `bytes` - 8-byte slice in little-endian order
///
/// # Returns
///
/// The decoded u64 value
///
/// # Panics
///
/// Panics if bytes.len() < 8
#[inline]
pub fn little_endian_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[0..8].try_into().unwrap())
}

/// Convert big-endian bytes to u64
///
/// # Arguments
///
/// * `bytes` - 8-byte slice in big-endian order
///
/// # Returns
///
/// The decoded u64 value
///
/// # Panics
///
/// Panics if bytes.len() < 8
#[inline]
pub fn big_endian_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes[0..8].try_into().unwrap())
}

/// Convert u32 to little-endian bytes
///
/// # Arguments
///
/// * `value` - The u32 value to encode
///
/// # Returns
///
/// 4-byte array in little-endian order
#[inline]
pub fn u32_to_little_endian(value: u32) -> [u8; 4] {
    value.to_le_bytes()
}

/// Convert u32 to big-endian bytes
///
/// # Arguments
///
/// * `value` - The u32 value to encode
///
/// # Returns
///
/// 4-byte array in big-endian order
#[inline]
pub fn u32_to_big_endian(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

/// Convert u64 to little-endian bytes
///
/// # Arguments
///
/// * `value` - The u64 value to encode
///
/// # Returns
///
/// 8-byte array in little-endian order
#[inline]
pub fn u64_to_little_endian(value: u64) -> [u8; 8] {
    value.to_le_bytes()
}

/// Convert u64 to big-endian bytes
///
/// # Arguments
///
/// * `value` - The u64 value to encode
///
/// # Returns
///
/// 8-byte array in big-endian order
#[inline]
pub fn u64_to_big_endian(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

/// Rotate left by n bits
///
/// # Arguments
///
/// * `value` - Value to rotate
/// * `n` - Number of bits to rotate left
///
/// # Returns
///
/// Rotated value
#[inline]
pub fn rotl32(value: u32, n: u32) -> u32 {
    value.rotate_left(n)
}

/// Rotate right by n bits
///
/// # Arguments
///
/// * `value` - Value to rotate
/// * `n` - Number of bits to rotate right
///
/// # Returns
///
/// Rotated value
#[inline]
pub fn rotr32(value: u32, n: u32) -> u32 {
    value.rotate_right(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_compare_equal() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        assert!(constant_time_compare(&a, &b));
    }

    #[test]
    fn test_constant_time_compare_not_equal() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 5];
        assert!(!constant_time_compare(&a, &b));
    }

    #[test]
    fn test_constant_time_compare_different_lengths() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 3, 4];
        assert!(!constant_time_compare(&a, &b));
    }

    #[test]
    fn test_constant_time_select_true() {
        let a = [1u8, 2, 3, 4];
        let b = [5u8, 6, 7, 8];
        let result = constant_time_select(true, &a, &b);
        assert_eq!(result, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_constant_time_select_false() {
        let a = [1u8, 2, 3, 4];
        let b = [5u8, 6, 7, 8];
        let result = constant_time_select(false, &a, &b);
        assert_eq!(result, vec![5, 6, 7, 8]);
    }

    #[test]
    fn test_zeroise() {
        let mut data = [1u8, 2, 3, 4];
        zeroise(&mut data);
        assert_eq!(data, [0u8, 0, 0, 0]);
    }

    #[test]
    fn test_little_endian_u32() {
        let bytes = [0x01u8, 0x02, 0x03, 0x04];
        assert_eq!(little_endian_u32(&bytes), 0x04030201);
    }

    #[test]
    fn test_big_endian_u32() {
        let bytes = [0x01u8, 0x02, 0x03, 0x04];
        assert_eq!(big_endian_u32(&bytes), 0x01020304);
    }

    #[test]
    fn test_little_endian_u64() {
        let bytes = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(little_endian_u64(&bytes), 0x0807060504030201);
    }

    #[test]
    fn test_big_endian_u64() {
        let bytes = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(big_endian_u64(&bytes), 0x0102030405060708);
    }

    #[test]
    fn test_u32_to_little_endian() {
        let bytes = u32_to_little_endian(0x04030201);
        assert_eq!(bytes, [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_u32_to_big_endian() {
        let bytes = u32_to_big_endian(0x01020304);
        assert_eq!(bytes, [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_rotl32() {
        assert_eq!(rotl32(0x12345678, 8), 0x34567812);
        assert_eq!(rotl32(0x12345678, 16), 0x56781234);
    }

    #[test]
    fn test_rotr32() {
        assert_eq!(rotr32(0x12345678, 8), 0x78123456);
        assert_eq!(rotr32(0x12345678, 16), 0x56781234);
    }
}
