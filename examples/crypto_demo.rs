//! Demonstration of Project 666 cryptographic primitives
//!
//! This example shows how to use all the main cryptographic functions
//! in the Project 666 library.

use project_666::{
    aead, argon2, chacha20, ed25519, kdf, poly1305, sha256, x25519,
};

fn main() {
    println!("Project 666 Cryptographic Primitives Demo");
    println!("=========================================\n");

    // 1. SHA-256 Hash
    println!("1. SHA-256 Hash");
    let message = b"Hello, Project 666!";
    let hash = sha256::digest(message);
    println!("   Message: {:?}", std::str::from_utf8(message).unwrap());
    println!("   Hash:    {}\n", hex::encode(hash));

    // 2. ChaCha20 Encryption/Decryption
    println!("2. ChaCha20 Encryption");
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let plaintext = b"Secret message encrypted with ChaCha20";
    let ciphertext = chacha20::encrypt(&key, &nonce, plaintext);
    let decrypted = chacha20::decrypt(&key, &nonce, &ciphertext);
    println!("   Plaintext:  {:?}", std::str::from_utf8(plaintext).unwrap());
    println!("   Ciphertext: {}", hex::encode(&ciphertext[..32]));
    println!("   Decrypted:  {:?}", std::str::from_utf8(&decrypted).unwrap());
    println!("   Success:    {}\n", plaintext.as_slice() == &decrypted[..]);

    // 3. Poly1305 MAC
    println!("3. Poly1305 MAC");
    let mac_key = [1u8; 32];
    let data = b"Data to authenticate with Poly1305";
    let tag = poly1305::tag(&mac_key, data);
    println!("   Data:    {:?}", std::str::from_utf8(data).unwrap());
    println!("   Tag:     {}\n", hex::encode(tag));

    // 4. ChaCha20-Poly1305 AEAD
    println!("4. ChaCha20-Poly1305 AEAD");
    let aead_key = [2u8; 32];
    let aead_nonce = [0u8; 12];
    let aad = b"Additional authenticated data";
    let aead_plaintext = b"Secret message with authentication";
    let (ciphertext, tag) = aead::encrypt(&aead_key, &aead_nonce, aad, aead_plaintext);
    let decrypted = aead::decrypt(&aead_key, &aead_nonce, aad, &ciphertext, &tag).unwrap();
    println!("   Plaintext:  {:?}", std::str::from_utf8(aead_plaintext).unwrap());
    println!("   AAD:        {:?}", std::str::from_utf8(aad).unwrap());
    println!("   Ciphertext: {}", hex::encode(&ciphertext[..32]));
    println!("   Tag:        {}", hex::encode(tag));
    println!("   Decrypted:  {:?}", std::str::from_utf8(&decrypted).unwrap());
    println!("   Success:    {}\n", aead_plaintext.as_slice() == &decrypted[..]);

    // 5. Argon2 KDF
    println!("5. Argon2 Key Derivation");
    let password = b"my_secure_password";
    let salt = [3u8; 16];
    let argon2_hash = argon2::hash(password, &salt);
    println!("   Password: {:?}", std::str::from_utf8(password).unwrap());
    println!("   Salt:     {}", hex::encode(salt));
    println!("   Hash:     {}\n", hex::encode(argon2_hash));

    // 6. Ed25519 Signatures
    println!("6. Ed25519 Signatures");
    let seed = [4u8; 32];
    let message_to_sign = b"Message to be signed with Ed25519";
    let (secret_key, public_key) = ed25519::generate_keypair(&seed);
    let signature = ed25519::sign(&secret_key, message_to_sign);
    let valid = ed25519::verify(&public_key, message_to_sign, &signature);
    println!("   Message:    {:?}", std::str::from_utf8(message_to_sign).unwrap());
    println!("   Public Key: {}", hex::encode(public_key));
    println!("   Signature:  {}", hex::encode(&signature[..32]));
    println!("   Valid:      {}\n", valid);

    // 7. X25519 Key Exchange
    println!("7. X25519 Diffie-Hellman");
    let seed_alice = [5u8; 32];
    let seed_bob = [6u8; 32];
    let (sk_alice, pk_alice) = x25519::generate_keypair(&seed_alice);
    let (sk_bob, pk_bob) = x25519::generate_keypair(&seed_bob);
    let shared_alice = x25519::diffie_hellman(&sk_alice, &pk_bob);
    let shared_bob = x25519::diffie_hellman(&sk_bob, &pk_alice);
    println!("   Alice PK:  {}", hex::encode(pk_alice));
    println!("   Bob PK:    {}", hex::encode(pk_bob));
    println!("   Shared:     {}", hex::encode(shared_alice));
    println!("   Match:      {}\n", shared_alice == shared_bob);

    // 8. Key Derivation (HKDF-like)
    println!("8. Key Derivation Functions");
    let master_secret = b"master secret for key derivation";
    let kdf_salt = b"kdf-salt";
    let context = b"project-666-demo";
    let derived_key = kdf::derive_key(kdf_salt, master_secret, context, 32);
    let multiple_keys = kdf::derive_keys(kdf_salt, master_secret, b"keys", 3);
    println!("   Master Secret: {:?}", std::str::from_utf8(master_secret).unwrap());
    println!("   Context:      {:?}", std::str::from_utf8(context).unwrap());
    println!("   Derived Key:  {}", hex::encode(derived_key));
    println!("   Multiple Keys:");
    for (i, key) in multiple_keys.iter().enumerate() {
        println!("     Key {}: {}", i + 1, hex::encode(key));
    }
    println!();

    // 9. Full Pipeline Demo
    println!("9. Full Cryptographic Pipeline");
    println!("   Combining multiple primitives for a secure message:\n");

    // Derive keys from master secret
    let master = b"master-secret-12345";
    let keys = kdf::derive_keys(b"salt-67890", master, b"full-pipeline", 3);

    // Alice signs the message
    let signing_key: [u8; 32] = keys[1].as_slice().try_into().unwrap();
    let (sign_sk, sign_pk) = ed25519::generate_keypair(&signing_key);
    let message = b"Confidential message with end-to-end encryption and authentication";
    let signature = ed25519::sign(&sign_sk, message);

    // Encrypt with AEAD
    let encryption_key: [u8; 32] = keys[0].as_slice().try_into().unwrap();
    let nonce = [7u8; 12];
    let aad = b"Additional context for this message";
    let (ciphertext, tag) = aead::encrypt(&encryption_key, &nonce, aad, message);

    println!("   Original Message:");
    println!("   {:?}", std::str::from_utf8(message).unwrap());
    println!("\n   Encrypted Output:");
    println!("   Ciphertext: {}", hex::encode(&ciphertext[..32]));
    println!("   Tag:        {}", hex::encode(tag));
    println!("   Signature:  {}", hex::encode(&signature[..32]));
    println!("\n   Verification & Decryption:");

    // Verify signature
    let sig_valid = ed25519::verify(&sign_pk, message, &signature);
    println!("   Signature Valid: {}", sig_valid);

    // Decrypt
    let decrypted = aead::decrypt(&encryption_key, &nonce, aad, &ciphertext, &tag).unwrap();
    println!("   Decrypted:      {:?}", std::str::from_utf8(&decrypted).unwrap());
    println!("   Success:        {}", message.as_slice() == &decrypted[..]);

    println!("\n=========================================");
    println!("Demo completed successfully!");
    println!("All cryptographic primitives working correctly.");
}
