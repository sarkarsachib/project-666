//! Performance benchmarks for cryptographic primitives
//!
//! This module provides comprehensive performance benchmarks
//! for all cryptographic operations in Project 666.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use project_666::{
    aead, chacha20, constants, ed25519, kdf, poly1305, sha256, x25519,
};

fn benchmark_chacha20(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha20");

    for size in [64, 1024, 65536].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let key = [0u8; 32];
            let nonce = [0u8; 12];
            let plaintext = vec![0u8; size];

            b.iter(|| {
                let ciphertext = chacha20::encrypt(black_box(&key), black_box(&nonce), black_box(&plaintext));
                black_box(ciphertext)
            });
        });
    }

    group.finish();
}

fn benchmark_poly1305(c: &mut Criterion) {
    let mut group = c.benchmark_group("poly1305");

    for size in [64, 1024, 65536].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let key = [0u8; 32];
            let data = vec![0u8; size];

            b.iter(|| {
                let tag = poly1305::tag(black_box(&key), black_box(&data));
                black_box(tag)
            });
        });
    }

    group.finish();
}

fn benchmark_aead(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead");

    for size in [64, 1024, 65536].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let key = [0u8; 32];
            let nonce = [0u8; 12];
            let aad = vec![0u8; size / 2];
            let plaintext = vec![0u8; size];

            b.iter(|| {
                let (ciphertext, tag) = aead::encrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&aad),
                    black_box(&plaintext),
                );
                black_box((ciphertext, tag))
            });
        });
    }

    group.finish();
}

fn benchmark_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");

    for size in [64, 1024, 65536].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let data = vec![0u8; size];

            b.iter(|| {
                let hash = sha256::digest(black_box(&data));
                black_box(hash)
            });
        });
    }

    group.finish();
}

fn benchmark_argon2(c: &mut Criterion) {
    let mut group = c.benchmark_group("argon2");

    group.bench_function("default_params", |b| {
        let password = b"password";
        let salt = [0u8; 16];

        b.iter(|| {
            let hash = argon2::hash(black_box(password), black_box(&salt));
            black_box(hash)
        });
    });

    group.bench_function("fast_params", |b| {
        let password = b"password";
        let salt = [0u8; 16];

        b.iter(|| {
            let hash = argon2::hash_with_params(black_box(password), black_box(&salt), 1, 100, 1);
            black_box(hash)
        });
    });

    group.finish();
}

fn benchmark_ed25519(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519");

    group.bench_function("keypair_generation", |b| {
        let seed = [0u8; 32];

        b.iter(|| {
            let (sk, pk) = ed25519::generate_keypair(black_box(&seed));
            black_box((sk, pk))
        });
    });

    group.bench_function("sign", |b| {
        let secret_key = [0u8; 32];
        let message = b"This is a test message for Ed25519 signing";

        b.iter(|| {
            let signature = ed25519::sign(black_box(&secret_key), black_box(message));
            black_box(signature)
        });
    });

    group.bench_function("verify", |b| {
        let secret_key = [0u8; 32];
        let message = b"This is a test message for Ed25519 verification";
        let signature = ed25519::sign(&secret_key, message);
        let (_, public_key) = ed25519::generate_keypair(&secret_key);

        b.iter(|| {
            let valid = ed25519::verify(black_box(&public_key), black_box(message), black_box(&signature));
            black_box(valid)
        });
    });

    group.finish();
}

fn benchmark_x25519(c: &mut Criterion) {
    let mut group = c.benchmark_group("x25519");

    group.bench_function("keypair_generation", |b| {
        let seed = [0u8; 32];

        b.iter(|| {
            let (sk, pk) = x25519::generate_keypair(black_box(&seed));
            black_box((sk, pk))
        });
    });

    group.bench_function("diffie_hellman", |b| {
        let secret_key1 = [0u8; 32];
        let secret_key2 = [1u8; 32];
        let (_, public_key2) = x25519::generate_keypair(&secret_key2);

        b.iter(|| {
            let shared = x25519::diffie_hellman(black_box(&secret_key1), black_box(&public_key2));
            black_box(shared)
        });
    });

    group.finish();
}

fn benchmark_kdf(c: &mut Criterion) {
    let mut group = c.benchmark_group("kdf");

    group.bench_function("derive_key", |b| {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"context";

        b.iter(|| {
            let key = kdf::derive_key(black_box(salt), black_box(ikm), black_box(info), 32);
            black_box(key)
        });
    });

    group.bench_function("derive_multiple_keys", |b| {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"key";

        b.iter(|| {
            let keys = kdf::derive_keys(black_box(salt), black_box(ikm), black_box(info), 10);
            black_box(keys)
        });
    });

    group.finish();
}

fn benchmark_utils(c: &mut Criterion) {
    let mut group = c.benchmark_group("utils");

    group.bench_function("constant_time_compare", |b| {
        let a = [1u8; 32];
        let b = [1u8; 32];

        b.iter(|| {
            let result = project_666::utils::constant_time_compare(black_box(&a), black_box(&b));
            black_box(result)
        });
    });

    group.bench_function("constant_time_select", |b| {
        let a = [1u8; 32];
        let b = [2u8; 32];

        b.iter(|| {
            let result = project_666::utils::constant_time_select(black_box(true), black_box(&a), black_box(&b));
            black_box(result)
        });
    });

    group.bench_function("zeroise", |b| {
        let mut data = [1u8; 32];

        b.iter(|| {
            project_666::utils::zeroise(black_box(&mut data));
            black_box(&data)
        });
    });

    group.finish();
}

fn benchmark_full_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_pipeline");

    group.bench_function("encrypt_sign_pipeline", |b| {
        let master_secret = b"master secret";
        let message = b"This is a test message for the full crypto pipeline";

        b.iter(|| {
            // Derive keys
            let keys = kdf::derive_keys(
                black_box(b"salt"),
                black_box(master_secret),
                black_box(b"project-666-test"),
                3
            );

            // Encrypt with AEAD
            let aead_key: [u8; 32] = keys[0].as_slice().try_into().unwrap();
            let nonce = [0u8; 12];
            let (ciphertext, tag) = aead::encrypt(
                black_box(&aead_key),
                black_box(&nonce),
                black_box(&[]),
                black_box(message)
            );

            // Sign
            let signing_key: [u8; 32] = keys[1].as_slice().try_into().unwrap();
            let signature = ed25519::sign(black_box(&signing_key), black_box(message));

            black_box((ciphertext, tag, signature))
        });
    });

    group.bench_function("decrypt_verify_pipeline", |b| {
        let master_secret = b"master secret";
        let message = b"This is a test message for the full crypto pipeline";
        let keys = kdf::derive_keys(
            b"salt",
            master_secret,
            b"project-666-test",
            3
        );

        let aead_key: [u8; 32] = keys[0].as_slice().try_into().unwrap();
        let signing_key: [u8; 32] = keys[1].as_slice().try_into().unwrap();
        let (_, verifying_key) = ed25519::generate_keypair(&signing_key);

        let nonce = [0u8; 12];
        let (ciphertext, tag) = aead::encrypt(&aead_key, &nonce, &[], message);
        let signature = ed25519::sign(&signing_key, message);

        b.iter(|| {
            // Decrypt
            let decrypted = aead::decrypt(
                black_box(&aead_key),
                black_box(&nonce),
                black_box(&[]),
                black_box(&ciphertext),
                black_box(&tag)
            ).unwrap();

            // Verify
            let valid = ed25519::verify(
                black_box(&verifying_key),
                black_box(&decrypted),
                black_box(&signature)
            );

            black_box((decrypted, valid))
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_chacha20,
    benchmark_poly1305,
    benchmark_aead,
    benchmark_sha256,
    benchmark_argon2,
    benchmark_ed25519,
    benchmark_x25519,
    benchmark_kdf,
    benchmark_utils,
    benchmark_full_pipeline
);

criterion_main!(benches);
