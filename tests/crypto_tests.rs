//! Comprehensive cryptographic tests
//!
//! This test suite verifies all cryptographic primitives with RFC test vectors,
//! edge cases, and integration tests.

use project_666::{
    aead, argon2, chacha20, constants, ed25519, kdf, poly1305, sha256, x25519,
};

// ============================================================================
// SHA-256 Tests
// ============================================================================

#[test]
fn test_sha256_empty() {
    let result = sha256::digest(b"");
    assert_eq!(
        hex::encode(result),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn test_sha256_abc() {
    let result = sha256::digest(b"abc");
    assert_eq!(
        hex::encode(result),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn test_sha256_long_message() {
    let message = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let result = sha256::digest(message);
    assert_eq!(
        hex::encode(result),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn test_sha256_incremental() {
    let mut hasher = sha256::Sha256::new();
    hasher.update(b"abc");
    hasher.update(b"def");
    let result = hasher.finalize();

    assert_eq!(sha256::digest(b"abcdef"), result);
}

// ============================================================================
// ChaCha20 Tests
// ============================================================================

#[test]
fn test_chacha20_rfc7539_vector_1() {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
    let nonce = hex::decode("000000000000004a00000000").unwrap();
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let expected = hex::decode("6e2e359a2568f98041ba0728dd0d6781e30a514a444338148c89cb4201335d5f6d8ac074655c4fa25c13d1715b6eeac5f90e646a3c7e3ebd494c511fdeeb").unwrap();

    let result = chacha20::encrypt(&key, &nonce, plaintext);
    assert_eq!(result, expected);
}

#[test]
fn test_chacha20_round_trip() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let plaintext = b"Hello, Project 666!";

    let ciphertext = chacha20::encrypt(&key, &nonce, plaintext);
    let decrypted = chacha20::decrypt(&key, &nonce, &ciphertext);

    assert_eq!(plaintext.as_slice(), &decrypted[..]);
}

// ============================================================================
// Poly1305 Tests
// ============================================================================

#[test]
fn test_poly1305_rfc7539_vector_1() {
    let key = hex::decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").unwrap();
    let key: [u8; 32] = key.try_into().unwrap();
    let data = hex::decode("43727970746f6772617068696320466f72756d2052657365617263682047726f7570").unwrap();
    let expected = hex::decode("a8061dc1305136c6c22b8baf0c0127a9").unwrap();

    let result = poly1305::tag(&key, &data);
    assert_eq!(result, expected);
}

#[test]
fn test_poly1305_incremental() {
    let mut key = [0u8; 32];
    key[0] = 0x85;

    let mut mac = poly1305::Poly1305::new(&key);
    mac.update(b"Hello, ");
    mac.update(b"World!");
    let result = mac.finalize();

    let expected = poly1305::tag(&key, b"Hello, World!");
    assert_eq!(result, expected);
}

// ============================================================================
// AEAD Tests
// ============================================================================

#[test]
fn test_aead_rfc7539_vector_1() {
    let key = hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
    let key: [u8; 32] = key.try_into().unwrap();
    let nonce = hex::decode("070000004041424344454647").unwrap();
    let nonce: [u8; 12] = nonce.try_into().unwrap();
    let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
    let plaintext = hex::decode("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e").unwrap();
    let expected_tag = hex::decode("4aad377794ca9a8f07b4a3").unwrap();

    let (_ciphertext, tag) = aead::encrypt(&key, &nonce, &aad, &plaintext);
    assert_eq!(tag, expected_tag);

    let decrypted = aead::decrypt(&key, &nonce, &aad, &_ciphertext, &tag).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aead_empty_aad() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let plaintext = b"Hello, World!";

    let (ciphertext, tag) = aead::encrypt(&key, &nonce, &[], plaintext);
    let decrypted = aead::decrypt(&key, &nonce, &[], &ciphertext, &tag).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aead_tag_verification_fails() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let plaintext = b"Hello, World!";

    let (ciphertext, tag) = aead::encrypt(&key, &nonce, &[], plaintext);

    // Corrupt the tag
    let mut corrupted_tag = tag;
    corrupted_tag[0] ^= 0x01;

    let result = aead::decrypt(&key, &nonce, &[], &ciphertext, &corrupted_tag);
    assert_eq!(result, Err(aead::AeadError::AuthenticationFailed));
}

#[test]
fn test_aead_round_trip() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let aad = b"Additional authenticated data";
    let plaintext = b"This is a test message for ChaCha20-Poly1305 AEAD";

    let (ciphertext, tag) = aead::encrypt(&key, &nonce, aad, plaintext);
    let decrypted = aead::decrypt(&key, &nonce, aad, &ciphertext, &tag).unwrap();

    assert_eq!(decrypted, plaintext);
}

// ============================================================================
// Argon2 Tests
// ============================================================================

#[test]
fn test_argon2_basic() {
    let password = b"password";
    let salt = [0u8; 16];

    let hash1 = argon2::hash(password, &salt);
    let hash2 = argon2::hash(password, &salt);

    assert_eq!(hash1, hash2);
}

#[test]
fn test_argon2_different_passwords() {
    let salt = [0u8; 16];

    let hash1 = argon2::hash(b"password1", &salt);
    let hash2 = argon2::hash(b"password2", &salt);

    assert_ne!(hash1, hash2);
}

#[test]
fn test_argon2_custom_params() {
    let password = b"password";
    let salt = [0u8; 16];

    let hash1 = argon2::hash_with_params(password, &salt, 2, 1000, 2);
    let hash2 = argon2::hash_with_params(password, &salt, 3, 1000, 2);

    assert_ne!(hash1, hash2);
}

// ============================================================================
// Ed25519 Tests
// ============================================================================

#[test]
fn test_ed25519_rfc8032_vector_1() {
    let secret_key = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
    let secret_key: [u8; 32] = secret_key.try_into().unwrap();
    let message = b"";
    let expected_signature = hex::decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b").unwrap();
    let expected_signature: [u8; 64] = expected_signature.try_into().unwrap();
    let expected_public_key = hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
    let expected_public_key: [u8; 32] = expected_public_key.try_into().unwrap();

    let (_, pk) = ed25519::generate_keypair(&secret_key);
    assert_eq!(pk, expected_public_key);

    let signature = ed25519::sign(&secret_key, message);
    assert_eq!(signature, expected_signature);

    assert!(ed25519::verify(&pk, message, &signature));
}

#[test]
fn test_ed25519_sign_verify() {
    let secret_key = [1u8; 32];
    let message = b"Hello, Ed25519!";

    let signature = ed25519::sign(&secret_key, message);
    let (_, public_key) = ed25519::generate_keypair(&secret_key);

    assert!(ed25519::verify(&public_key, message, &signature));
}

#[test]
fn test_ed25519_wrong_message() {
    let secret_key = [1u8; 32];
    let message = b"Hello, Ed25519!";
    let wrong_message = b"Hello, Ed25519?";

    let signature = ed25519::sign(&secret_key, message);
    let (_, public_key) = ed25519::generate_keypair(&secret_key);

    assert!(!ed25519::verify(&public_key, wrong_message, &signature));
}

// ============================================================================
// X25519 Tests
// ============================================================================

#[test]
fn test_x25519_rfc7748_vector_1() {
    let scalar = hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").unwrap();
    let scalar: [u8; 32] = scalar.try_into().unwrap();
    let point = hex::decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f").unwrap();
    let point: [u8; 32] = point.try_into().unwrap();
    let expected = hex::decode("4c2a3498f081ae876ae95f940e426e8068d3b7f88c512e29737c3e45f23f722e").unwrap();

    let result = x25519::diffie_hellman(&scalar, &point);
    assert_eq!(result, expected);
}

#[test]
fn test_x25519_dh_round_trip() {
    let seed1 = [1u8; 32];
    let seed2 = [2u8; 32];

    let (sk1, pk1) = x25519::generate_keypair(&seed1);
    let (sk2, pk2) = x25519::generate_keypair(&seed2);

    let shared1 = x25519::diffie_hellman(&sk1, &pk2);
    let shared2 = x25519::diffie_hellman(&sk2, &pk1);

    assert_eq!(shared1, shared2);
}

// ============================================================================
// KDF Tests
// ============================================================================

#[test]
fn test_kdf_hkdf_vector_1() {
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    let output_len = 42;
    let expected = hex::decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865").unwrap();

    let result = kdf::derive_key(&salt, &ikm, &info, output_len);
    assert_eq!(result, expected);
}

#[test]
fn test_kdf_deterministic() {
    let ikm = b"input key material";
    let salt = b"salt";
    let info = b"context";

    let result1 = kdf::derive_key(salt, ikm, info, 32);
    let result2 = kdf::derive_key(salt, ikm, info, 32);

    assert_eq!(result1, result2);
}

#[test]
fn test_kdf_different_salt() {
    let ikm = b"input key material";
    let info = b"context";

    let result1 = kdf::derive_key(b"salt1", ikm, info, 32);
    let result2 = kdf::derive_key(b"salt2", ikm, info, 32);

    assert_ne!(result1, result2);
}

#[test]
fn test_kdf_derive_multiple_keys() {
    let ikm = b"input key material";
    let salt = b"salt";
    let info = b"key";

    let keys = kdf::derive_keys(salt, ikm, info, 5);

    assert_eq!(keys.len(), 5);
    for key in &keys {
        assert_eq!(key.len(), 32);
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_full_crypto_pipeline() {
    // 1. Derive keys using KDF
    let master_secret = b"master secret";
    let keys = kdf::derive_keys(
        b"salt",
        master_secret,
        b"project-666-test",
        3
    );

    // 2. Use first key for AEAD
    let aead_key: [u8; 32] = keys[0].as_slice().try_into().unwrap();
    let nonce = [0u8; 12];
    let plaintext = b"This is a test message for the full crypto pipeline";

    let (ciphertext, tag) = aead::encrypt(&aead_key, &nonce, &[], plaintext);
    let decrypted = aead::decrypt(&aead_key, &nonce, &[], &ciphertext, &tag).unwrap();

    assert_eq!(decrypted, plaintext);

    // 3. Use second key for signing
    let signing_key: [u8; 32] = keys[1].as_slice().try_into().unwrap();
    let signature = ed25519::sign(&signing_key, plaintext);
    let (_, verifying_key) = ed25519::generate_keypair(&signing_key);

    assert!(ed25519::verify(&verifying_key, plaintext, &signature));

    // 4. Hash the message
    let hash = sha256::digest(plaintext);
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_constants() {
    // Verify protocol constants
    assert_eq!(constants::PROTOCOL_VERSION, 1);
    assert_eq!(constants::PROTOCOL_MAGIC, [0x66, 0x66, 0x66, 0x00]);
    assert_eq!(constants::KEY_SIZE, 32);
    assert_eq!(constants::NONCE_SIZE, 12);
    assert_eq!(constants::TAG_SIZE, 16);
    assert_eq!(constants::HASH_SIZE, 32);
    assert_eq!(constants::SIGNATURE_SIZE, 64);
    assert_eq!(constants::PUBLIC_KEY_SIZE, 32);
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_empty_inputs() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];

    // ChaCha20
    let cipher = chacha20::encrypt(&key, &nonce, b"");
    assert_eq!(cipher, vec![]);

    // Poly1305
    let tag = poly1305::tag(&[0u8; 32], b"");
    assert_eq!(tag.len(), 16);

    // AEAD
    let (ct, tag) = aead::encrypt(&key, &nonce, &[], b"");
    assert_eq!(ct, vec![]);
    assert_eq!(tag.len(), 16);

    // SHA-256
    let hash = sha256::digest(b"");
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_large_messages() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let large_data = vec![0u8; 65536]; // 64 KB

    // ChaCha20
    let cipher = chacha20::encrypt(&key, &nonce, &large_data);
    assert_eq!(cipher.len(), 65536);

    // SHA-256
    let hash = sha256::digest(&large_data);
    assert_eq!(hash.len(), 32);

    // AEAD
    let (ct, tag) = aead::encrypt(&key, &nonce, &[], &large_data);
    let decrypted = aead::decrypt(&key, &nonce, &[], &ct, &tag).unwrap();
    assert_eq!(decrypted, large_data);
}

#[test]
fn test_constant_time_properties() {
    // Test that constant-time comparison works correctly
    let a = [1u8, 2, 3, 4];
    let b = [1u8, 2, 3, 4];
    let c = [1u8, 2, 3, 5];

    assert!(project_666::utils::constant_time_compare(&a, &b));
    assert!(!project_666::utils::constant_time_compare(&a, &c));

    // Test zeroise
    let mut data = [1u8, 2, 3, 4];
    project_666::utils::zeroise(&mut data);
    assert_eq!(data, [0u8; 4]);
}
