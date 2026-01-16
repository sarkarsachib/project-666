//! X25519 elliptic curve Diffie-Hellman
//!
//! Implementation of X25519 as specified in RFC 7748.
//! This is an elliptic curve Diffie-Hellman key exchange using Curve25519.

use crate::constants::X25519_SHARED_SECRET_SIZE;
use crate::crypto::utils::constant_time_compare;

/// Curve25519 field modulus (2^255 - 19)
const P: [u32; 8] = [
    0x00000003, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffed,
];

/// Curve25519 base point (9)
const BASE_POINT: [u32; 8] = [9, 0, 0, 0, 0, 0, 0, 0];

/// X25519 Diffie-Hellman
///
/// # Arguments
///
/// * `secret_key` - 32-byte secret key
/// * `public_key` - 32-byte public key
///
/// # Returns
///
/// 32-byte shared secret
pub fn diffie_hellman(secret_key: &[u8; 32], public_key: &[u8; 32]) -> [u8; 32] {
    let mut scalar = [0u32; 8];
    load_scalar(&mut scalar, secret_key);

    // Clamp the scalar
    scalar[0] &= 0xfffffff8;
    scalar[7] &= 0x7fffffff;
    scalar[7] |= 0x40000000;

    let mut point = [0u32; 8];
    load_point(&mut point, public_key);

    let result = scalar_mult(&scalar, &point);
    store_point(&result)
}

/// Generate a keypair
///
/// # Arguments
///
/// * `seed` - 32-byte seed
///
/// # Returns
///
/// Tuple of (secret_key, public_key)
pub fn generate_keypair(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut secret_key = *seed;

    // Clamp the scalar
    secret_key[0] &= 0xf8;
    secret_key[31] &= 0x7f;
    secret_key[31] |= 0x40;

    let public_key = scalar_mult_base(&secret_key);
    (secret_key, public_key)
}

/// Load scalar from bytes
fn load_scalar(scalar: &mut [u32; 8], bytes: &[u8]) {
    for i in 0..8 {
        scalar[i] = u32::from_le_bytes([bytes[i * 4], bytes[i * 4 + 1], bytes[i * 4 + 2], bytes[i * 4 + 3]]);
    }
}

/// Load point from bytes
fn load_point(point: &mut [u32; 8], bytes: &[u8]) {
    for i in 0..8 {
        point[i] = u32::from_le_bytes([bytes[i * 4], bytes[i * 4 + 1], bytes[i * 4 + 2], bytes[i * 4 + 3]]);
    }
}

/// Store point to bytes
fn store_point(point: &[u32; 8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..8 {
        let bytes = point[i].to_le_bytes();
        result[i * 4..i * 4 + 4].copy_from_slice(&bytes);
    }
    result
}

/// Scalar multiplication of a point
fn scalar_mult(scalar: &[u32; 8], point: &[u32; 8]) -> [u32; 8] {
    let mut x1 = [0u32; 8];
    x1.copy_from_slice(point);

    let mut x2 = [0u32; 8];
    x2.copy_from_slice(&P);

    let mut z2 = [0u32; 8];

    let mut x3 = [0u32; 8];
    x3.copy_from_slice(&x1);

    let mut z3 = [0u32; 8];
    z3[0] = 1;

    let mut swap = 0u32;

    for i in (0..255).rev() {
        let k = (scalar[i / 32] >> (i % 32)) & 1;
        swap ^= k;

        // Conditional swap
        conditional_swap(&mut x2, &mut x3, swap);
        conditional_swap(&mut z2, &mut z3, swap);

        swap = k;

        let mut a = add(&x2, &z2);
        let mut aa = montgomery_mult(&a, &a);
        let mut b = sub(&x2, &z2);
        let mut bb = montgomery_mult(&b, &b);
        let mut e = sub(&aa, &bb);

        let mut c = add(&x3, &z3);
        let mut d = sub(&x3, &z3);
        let mut da = montgomery_mult(&d, &a);
        let mut cb = montgomery_mult(&c, &b);

        add_assign(&mut x3, &da);
        sub_assign(&mut x3, &cb);
        add_assign(&mut z3, &e);
        x2 = montgomery_mult(&aa, &bb);
        let tmp = montgomery_mult(&e, &P);
        z2 = montgomery_mult(&da, &cb);
        add_assign(&mut z2, &tmp);
    }

    // Final conditional swap
    conditional_swap(&mut x2, &mut x3, swap);
    conditional_swap(&mut z2, &mut z3, swap);

    // Compute x2 / z2 (inversion)
    let z2_inv = invert(&z2);
    montgomery_mult(&x2, &z2_inv)
}

/// Scalar multiplication of base point
fn scalar_mult_base(scalar: &[u8; 32]) -> [u8; 32] {
    let mut scalar_arr = [0u32; 8];
    load_scalar(&mut scalar_arr, scalar);

    // Clamp the scalar
    scalar_arr[0] &= 0xfffffff8;
    scalar_arr[7] &= 0x7fffffff;
    scalar_arr[7] |= 0x40000000;

    let result = scalar_mult(&scalar_arr, &BASE_POINT);
    store_point(&result)
}

/// Conditional swap (constant-time)
fn conditional_swap(a: &mut [u32; 8], b: &mut [u32; 8], swap: u32) {
    let mask = -(swap as i32) as u32;
    for i in 0..8 {
        let temp = mask & (a[i] ^ b[i]);
        a[i] ^= temp;
        b[i] ^= temp;
    }
}

/// Addition modulo p
fn add(a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
    let mut result = [0u32; 8];
    let mut carry = 0u64;

    for i in 0..8 {
        let sum = (a[i] as u64) + (b[i] as u64) + carry;
        result[i] = sum as u32;
        carry = sum >> 32;
    }

    reduce_add(&mut result, carry as u32);
    result
}

/// Subtraction modulo p
fn sub(a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
    let mut result = [0u32; 8];
    let mut borrow = 0u64;

    for i in 0..8 {
        let diff = (a[i] as u64).wrapping_sub((b[i] as u64) + borrow);
        result[i] = diff as u32;
        borrow = (diff >> 32) & 1;
    }

    reduce_sub(&mut result, borrow as u32);
    result
}

/// Add in place
fn add_assign(a: &mut [u32; 8], b: &[u32; 8]) {
    let mut carry = 0u64;

    for i in 0..8 {
        let sum = (a[i] as u64) + (b[i] as u64) + carry;
        a[i] = sum as u32;
        carry = sum >> 32;
    }

    reduce_add(a, carry as u32);
}

/// Sub in place
fn sub_assign(a: &mut [u32; 8], b: &[u32; 8]) {
    let mut borrow = 0u64;

    for i in 0..8 {
        let diff = (a[i] as u64).wrapping_sub((b[i] as u64) + borrow);
        a[i] = diff as u32;
        borrow = (diff >> 32) & 1;
    }

    reduce_sub(a, borrow as u32);
}

/// Reduce after addition
fn reduce_add(a: &mut [u32; 8], carry: u32) {
    let mut carry = carry;

    for i in 0..8 {
        let sum = (a[i] as u64) + (P[i] as u64) * (carry as u64);
        a[i] = sum as u32;
        carry = (sum >> 32) as u32;
    }

    if carry > 0 {
        add_assign(a, &P);
    }
}

/// Reduce after subtraction
fn reduce_sub(a: &mut [u32; 8], borrow: u32) {
    if borrow > 0 {
        add_assign(a, &P);
    }
}

/// Montgomery multiplication
fn montgomery_mult(a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
    let mut result = [0u32; 8];

    for i in 0..8 {
        let mut carry = (a[i] as u64) * (b[0] as u64) + (result[0] as u64);
        result[0] = carry as u32;

        let m = (result[0] as u64).wrapping_mul(0x0d00000000000000u64 >> 56);
        carry = (m as u64) * (P[0] as u64) + (result[0] as u64);

        for j in 1..8 {
            carry = (a[(i + j) % 8] as u64) * (b[j] as u64)
                + (result[j] as u64)
                + ((carry >> 32) as u64);
            result[j] = carry as u32;
        }

        carry = (carry >> 32) as u64 + ((m as u64) * (P[0] as u64) >> 32);

        for j in 0..7 {
            carry = (result[j] as u64) + (P[j] as u64) * carry;
            result[j] = carry as u32;
            carry >>= 32;
        }

        let tmp = result[7] as u64 + (P[7] as u64) * carry;
        result[7] = tmp as u32;

        if tmp > 0xffffffffffu64 {
            result[0] += 1;
        }
    }

    result
}

/// Inversion
fn invert(a: &[u32; 8]) -> [u32; 8] {
    let mut result = [1u32, 0, 0, 0, 0, 0, 0, 0];
    let mut base = *a;

    // Compute base^(p-2) = base^(2^255 - 21)
    for _ in 0..254 {
        result = montgomery_mult(&result, &result);
        if (255 - 21) % 2 == 1 {
            result = montgomery_mult(&result, &base);
        }
    }

    // Multiply by base^-1
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7748 test vector 1
    #[test]
    fn test_rfc7748_vector_1() {
        let scalar = hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").unwrap();
        let scalar: [u8; 32] = scalar.try_into().unwrap();
        let point = hex::decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f").unwrap();
        let point: [u8; 32] = point.try_into().unwrap();
        let expected = hex::decode("4c2a3498f081ae876ae95f940e426e8068d3b7f88c512e29737c3e45f23f722e").unwrap();

        let result = diffie_hellman(&scalar, &point);
        assert_eq!(result, expected);
    }

    // RFC 7748 test vector 2
    #[test]
    fn test_rfc7748_vector_2() {
        let scalar = hex::decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb").unwrap();
        let scalar: [u8; 32] = scalar.try_into().unwrap();
        let point = hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a").unwrap();
        let point: [u8; 32] = point.try_into().unwrap();
        let expected = hex::decode("2083192371c8548020e2c36448d49c358055c71c358e5d75f79d30177a1c4a4c").unwrap();

        let result = diffie_hellman(&scalar, &point);
        assert_eq!(result, expected);
    }

    // Test keypair generation
    #[test]
    fn test_keypair_generation() {
        let seed = [0u8; 32];
        let (secret_key, public_key) = generate_keypair(&seed);

        // Secret key should be clamped
        assert_eq!(secret_key[0] & 0xf8, secret_key[0]);
        assert_eq!(secret_key[31] & 0x40, 0x40);

        // Public key should not be all zeros
        assert_ne!(public_key, [0u8; 32]);
    }

    // Test DH round trip
    #[test]
    fn test_dh_round_trip() {
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];

        let (sk1, pk1) = generate_keypair(&seed1);
        let (sk2, pk2) = generate_keypair(&seed2);

        let shared1 = diffie_hellman(&sk1, &pk2);
        let shared2 = diffie_hellman(&sk2, &pk1);

        // Both sides should compute the same shared secret
        assert_eq!(shared1, shared2);
    }

    // Test different seeds produce different keys
    #[test]
    fn test_different_seeds() {
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];

        let (_, pk1) = generate_keypair(&seed1);
        let (_, pk2) = generate_keypair(&seed2);

        assert_ne!(pk1, pk2);
    }
}
