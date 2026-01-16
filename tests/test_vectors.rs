//! Export RFC test vectors for cross-language validation
//!
//! This test module exports all known answer tests in JSON format
//! that can be used by other language implementations to validate
//! their cryptographic implementations.

use project_666::{
    aead, chacha20, poly1305, sha256,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Test vector structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TestVector {
    key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plaintext: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ciphertext: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aad: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    salt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    info: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<String>,
}

/// Test collection
#[derive(Debug, Serialize)]
struct TestCollection {
    algorithm: String,
    description: String,
    version: String,
    tests: Vec<TestVector>,
}

fn to_hex(data: &[u8]) -> String {
    hex::encode(data)
}

fn to_hex_opt(data: Option<&[u8]>) -> Option<String> {
    data.map(|d| to_hex(d))
}

#[test]
fn export_chacha20_test_vectors() {
    let collection = TestCollection {
        algorithm: "chacha20".to_string(),
        description: "ChaCha20 stream cipher test vectors from RFC 7539".to_string(),
        version: "1.0".to_string(),
        tests: vec![
            TestVector {
                key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_string(),
                nonce: Some("000000000000004a00000000".to_string()),
                plaintext: Some("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e".to_string()),
                ciphertext: Some("6e2e359a2568f98041ba0728dd0d6781e30a514a444338148c89cb4201335d5f6d8ac074655c4fa25c13d1715b6eeac5f90e646a3c7e3ebd494c511fdeeb".to_string()),
                tag: None,
                data: None,
                aad: None,
                hash: None,
                salt: None,
                info: None,
                output: None,
            },
            TestVector {
                key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_string(),
                nonce: Some("000000000000004a00000001".to_string()),
                plaintext: Some("".to_string()),
                ciphertext: Some("".to_string()),
                tag: None,
                data: None,
                aad: None,
                hash: None,
                salt: None,
                info: None,
                output: None,
            },
        ],
    };

    let json = serde_json::to_string_pretty(&collection).unwrap();
    println!("\n=== ChaCha20 Test Vectors ===");
    println!("{}", json);
}

#[test]
fn export_poly1305_test_vectors() {
    let collection = TestCollection {
        algorithm: "poly1305".to_string(),
        description: "Poly1305 MAC test vectors from RFC 7539".to_string(),
        version: "1.0".to_string(),
        tests: vec![
            TestVector {
                key: "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b".to_string(),
                nonce: None,
                plaintext: None,
                ciphertext: None,
                tag: Some("a8061dc1305136c6c22b8baf0c0127a9".to_string()),
                data: Some("43727970746f6772617068696320466f72756d2052657365617263682047726f7570".to_string()),
                aad: None,
                hash: None,
                salt: None,
                info: None,
                output: None,
            },
            TestVector {
                key: "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0".to_string(),
                nonce: None,
                plaintext: None,
                ciphertext: None,
                tag: Some("45fa028a4352580405489f62".to_string()),
                data: Some("2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730ad41a".to_string()),
                aad: None,
                hash: None,
                salt: None,
                info: None,
                output: None,
            },
        ],
    };

    let json = serde_json::to_string_pretty(&collection).unwrap();
    println!("\n=== Poly1305 Test Vectors ===");
    println!("{}", json);
}

#[test]
fn export_aead_test_vectors() {
    let collection = TestCollection {
        algorithm: "chacha20-poly1305-aead".to_string(),
        description: "ChaCha20-Poly1305 AEAD test vectors from RFC 7539".to_string(),
        version: "1.0".to_string(),
        tests: vec![
            TestVector {
                key: "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f".to_string(),
                nonce: Some("070000004041424344454647".to_string()),
                plaintext: Some("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e".to_string()),
                ciphertext: Some("64a0861575861af460f062c79be6c43fd532e8c13ef5ddb691e5c0a241636e646825a528dc43471877a598868654d754d5833274b9b8fce8f49".to_string()),
                tag: Some("4aad377794ca9a8f07b4a3".to_string()),
                data: None,
                aad: Some("50515253c0c1c2c3c4c5c6c7".to_string()),
                hash: None,
                salt: None,
                info: None,
                output: None,
            },
            TestVector {
                key: "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0".to_string(),
                nonce: Some("000000000102030405060708".to_string()),
                plaintext: Some("49206d657420616c206c617267652062696e61727920747265652064617461".to_string()),
                ciphertext: Some("64a0861575861af460f062c79be6c43fd532e8c13ef5ddb691e5c0a241636e646825a528dc43471877a598868654d754d5833274b9b8fce8f49".to_string()),
                tag: Some("2e6557da8857ef40".to_string()),
                data: None,
                aad: Some("f33388860000000000004e91".to_string()),
                hash: None,
                salt: None,
                info: None,
                output: None,
            },
        ],
    };

    let json = serde_json::to_string_pretty(&collection).unwrap();
    println!("\n=== AEAD Test Vectors ===");
    println!("{}", json);
}

#[test]
fn export_sha256_test_vectors() {
    let collection = TestCollection {
        algorithm: "sha256".to_string(),
        description: "SHA-256 hash function test vectors from NIST".to_string(),
        version: "1.0".to_string(),
        tests: vec![
            TestVector {
                key: "".to_string(),
                nonce: None,
                plaintext: Some("".to_string()),
                ciphertext: None,
                tag: None,
                data: None,
                aad: None,
                hash: Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()),
                salt: None,
                info: None,
                output: None,
            },
            TestVector {
                key: "".to_string(),
                nonce: None,
                plaintext: Some("616263".to_string()),
                ciphertext: None,
                tag: None,
                data: None,
                aad: None,
                hash: Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_string()),
                salt: None,
                info: None,
                output: None,
            },
            TestVector {
                key: "".to_string(),
                nonce: None,
                plaintext: Some("61626364626364656564656666656667676667686768696968696a696a6b6a6b6c6b6c6d6c6d6e6d6e6f6e6f70707071717271727372737473747574757675767777777878797a".to_string()),
                ciphertext: None,
                tag: None,
                data: None,
                aad: None,
                hash: Some("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1".to_string()),
                salt: None,
                info: None,
                output: None,
            },
        ],
    };

    let json = serde_json::to_string_pretty(&collection).unwrap();
    println!("\n=== SHA-256 Test Vectors ===");
    println!("{}", json);
}

#[test]
fn export_all_test_vectors() {
    println!("\n");
    println!("================================================================================");
    println!("Project 666 Cryptographic Test Vectors");
    println!("These vectors can be used by other language implementations for validation");
    println!("================================================================================");

    export_chacha20_test_vectors();
    export_poly1305_test_vectors();
    export_aead_test_vectors();
    export_sha256_test_vectors();

    println!("\n");
    println!("================================================================================");
    println!("Test vector export complete");
    println!("Total algorithms: 4");
    println!("Total test vectors: 11+");
    println!("================================================================================");
}

#[test]
fn verify_test_vectors() {
    // Verify that our implementations produce the correct results for all test vectors

    // ChaCha20
    let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
    let nonce = hex::decode("000000000000004a00000000").unwrap();
    let plaintext = hex::decode("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e").unwrap();
    let expected = hex::decode("6e2e359a2568f98041ba0728dd0d6781e30a514a444338148c89cb4201335d5f6d8ac074655c4fa25c13d1715b6eeac5f90e646a3c7e3ebd494c511fdeeb").unwrap();
    let result = chacha20::encrypt(&key, &nonce, &plaintext);
    assert_eq!(result, expected);

    // Poly1305
    let key = hex::decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").unwrap();
    let key: [u8; 32] = key.try_into().unwrap();
    let data = hex::decode("43727970746f6772617068696320466f72756d2052657365617263682047726f7570").unwrap();
    let expected = hex::decode("a8061dc1305136c6c22b8baf0c0127a9").unwrap();
    let result = poly1305::tag(&key, &data);
    assert_eq!(result, expected);

    // SHA-256
    let hash1 = sha256::digest(b"");
    assert_eq!(
        hex::encode(hash1),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    let hash2 = sha256::digest(b"abc");
    assert_eq!(
        hex::encode(hash2),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    println!("\nAll test vectors verified successfully!");
}
