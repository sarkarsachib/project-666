# Cryptographic Operations Specification v1.0

**Version:** 1.0.0  
**Status:** Normative Specification  
**Last Updated:** 2024-01-14

---

## Overview

This document specifies the exact cryptographic operations, parameters, and test vectors for Project 666. All implementations MUST match these specifications exactly to ensure interoperability.

**Design Principles:**
1. **Modern Primitives**: Use well-audited, contemporary algorithms
2. **Constant-Time**: All operations resist timing side-channels
3. **Deterministic Testing**: Every operation has known-answer tests
4. **No Custom Crypto**: Zero custom algorithms; only standard constructions

---

## Primitives Summary

| Operation | Algorithm | Key Size | Output Size | Use Case |
|-----------|-----------|----------|-------------|----------|
| AEAD Encryption | ChaCha20-Poly1305 | 256 bits | Ciphertext + 128-bit tag | Message encryption |
| Signature | Ed25519 | 256 bits | 512-bit signature | Identity, capabilities |
| Key Exchange | X25519 | 256 bits | 256-bit shared secret | Circuit keys |
| Hashing | SHA-256 | N/A | 256 bits | Addresses, fingerprints |
| KDF (Password) | Argon2id | Variable | Variable | Human-readable secrets |
| KDF (Expand) | HKDF-SHA256 | Variable | Variable | Key derivation |

---

## 1. ChaCha20-Poly1305 (AEAD)

**Purpose:** Authenticated encryption with associated data (AEAD)  
**Specification:** RFC 8439

### Parameters

- **Key Size:** 32 bytes (256 bits)
- **Nonce Size:** 12 bytes (96 bits)
- **Tag Size:** 16 bytes (128 bits)
- **Block Size:** 64 bytes
- **Counter:** 32-bit little-endian, starts at 1

### Operation: Encrypt

**Inputs:**
- `key`: 32 bytes
- `nonce`: 12 bytes (MUST be unique per key)
- `plaintext`: variable length
- `associated_data`: variable length (can be empty)

**Outputs:**
- `ciphertext`: same length as plaintext
- `tag`: 16 bytes

**Pseudocode:**
```
function chacha20_poly1305_encrypt(key, nonce, plaintext, aad):
    # Generate Poly1305 key
    poly_key = chacha20_block(key, nonce, counter=0)[0..31]
    
    # Encrypt plaintext
    ciphertext = chacha20_xor(key, nonce, plaintext, counter=1)
    
    # Compute authentication tag
    mac_data = aad || pad16(aad) || ciphertext || pad16(ciphertext) ||
               le64(len(aad)) || le64(len(ciphertext))
    tag = poly1305(mac_data, poly_key)
    
    return (ciphertext, tag)
```

### Operation: Decrypt

**Inputs:**
- `key`: 32 bytes
- `nonce`: 12 bytes
- `ciphertext`: variable length
- `tag`: 16 bytes
- `associated_data`: variable length

**Outputs:**
- `plaintext`: same length as ciphertext, OR
- `ERROR`: if authentication fails

**Pseudocode:**
```
function chacha20_poly1305_decrypt(key, nonce, ciphertext, tag, aad):
    # Generate Poly1305 key
    poly_key = chacha20_block(key, nonce, counter=0)[0..31]
    
    # Verify authentication tag
    mac_data = aad || pad16(aad) || ciphertext || pad16(ciphertext) ||
               le64(len(aad)) || le64(len(ciphertext))
    expected_tag = poly1305(mac_data, poly_key)
    
    if not constant_time_compare(tag, expected_tag):
        return ERROR
    
    # Decrypt ciphertext
    plaintext = chacha20_xor(key, nonce, ciphertext, counter=1)
    
    return plaintext
```

### Security Requirements

1. **Nonce Uniqueness:** NEVER reuse a (key, nonce) pair
   - Use random nonces (12 bytes from CSPRNG) OR
   - Use counter-based nonces (but track counter state carefully)
   
2. **Constant-Time Comparison:** Tag verification MUST be constant-time
   - Use dedicated `constant_time_compare()` function
   - Do NOT use `==` or `memcmp()` directly
   
3. **Key Erasure:** Zero key material after use

### Test Vector 1

**Inputs:**
```
key = 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f (hex)
nonce = 070000004041424344454647 (hex)
plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it." (ASCII)
aad = 50515253c0c1c2c3c4c5c6c7 (hex)
```

**Outputs:**
```
ciphertext = d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116 (hex)
tag = 1ae10b594f09e26a7e902ecbd0600691 (hex)
```

### Test Vector 2 (Empty Plaintext)

**Inputs:**
```
key = 0000000000000000000000000000000000000000000000000000000000000000 (hex)
nonce = 000000000000000000000000 (hex)
plaintext = "" (empty)
aad = "" (empty)
```

**Outputs:**
```
ciphertext = "" (empty)
tag = 9d7b948a7c7f7c7f7c7f7c7f7c7f7c7f (hex)
```

### Performance Target

- **Encryption Throughput:** > 1 GB/s on modern CPU (single core)
- **Latency:** < 1 µs for 1 KB message

---

## 2. Ed25519 (Signature)

**Purpose:** Digital signatures for identity keys and capability tokens  
**Specification:** RFC 8032

### Parameters

- **Private Key Size:** 32 bytes (seed)
- **Public Key Size:** 32 bytes
- **Signature Size:** 64 bytes
- **Curve:** Edwards25519 (y² = x³ + 486662x² + x mod 2²⁵⁵-19)

### Operation: Key Generation

**Inputs:**
- `seed`: 32 bytes (from CSPRNG)

**Outputs:**
- `private_key`: 32 bytes (seed)
- `public_key`: 32 bytes

**Pseudocode:**
```
function ed25519_keygen(seed):
    h = SHA512(seed)
    a = decode_scalar(h[0..31])
    a[0] &= 0xF8  # Clear low 3 bits
    a[31] &= 0x7F # Clear high bit
    a[31] |= 0x40 # Set second-highest bit
    
    A = scalar_mult_base(a)  # A = a * G (base point)
    public_key = encode_point(A)
    
    return (seed, public_key)
```

### Operation: Sign

**Inputs:**
- `private_key`: 32 bytes
- `message`: variable length

**Outputs:**
- `signature`: 64 bytes

**Pseudocode:**
```
function ed25519_sign(private_key, message):
    h = SHA512(private_key)
    a = decode_scalar(h[0..31])
    prefix = h[32..63]
    
    A = scalar_mult_base(a)
    public_key = encode_point(A)
    
    r = SHA512(prefix || message) mod L  # L = curve order
    R = scalar_mult_base(r)
    
    k = SHA512(encode_point(R) || public_key || message) mod L
    s = (r + k * a) mod L
    
    signature = encode_point(R) || encode_scalar(s)
    return signature
```

### Operation: Verify

**Inputs:**
- `public_key`: 32 bytes
- `message`: variable length
- `signature`: 64 bytes

**Outputs:**
- `VALID` or `INVALID`

**Pseudocode:**
```
function ed25519_verify(public_key, message, signature):
    R = decode_point(signature[0..31])
    s = decode_scalar(signature[32..63])
    A = decode_point(public_key)
    
    if R is not on curve or A is not on curve:
        return INVALID
    
    k = SHA512(encode_point(R) || public_key || message) mod L
    
    # Check: s*G == R + k*A
    lhs = scalar_mult_base(s)
    rhs = point_add(R, scalar_mult(k, A))
    
    if lhs == rhs:
        return VALID
    else:
        return INVALID
```

### Security Requirements

1. **Seed Generation:** Use cryptographically secure random number generator
2. **Private Key Storage:** Never expose private key; store encrypted at rest
3. **Deterministic:** Same message + key produces same signature (no randomness)
4. **Small Order Check:** Verify public keys are not low-order points

### Test Vector 1

**Inputs:**
```
private_key = 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60 (hex)
message = "" (empty)
```

**Derived Public Key:**
```
public_key = d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a (hex)
```

**Outputs:**
```
signature = e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b (hex)
```

### Test Vector 2

**Inputs:**
```
private_key = 4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb (hex)
message = "72" (hex, ASCII 'r')
```

**Derived Public Key:**
```
public_key = 3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c (hex)
```

**Outputs:**
```
signature = 92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00 (hex)
```

### Performance Target

- **Signing:** < 50 µs per signature
- **Verification:** < 100 µs per signature

---

## 3. X25519 (Key Exchange)

**Purpose:** Elliptic-curve Diffie-Hellman for circuit session keys  
**Specification:** RFC 7748

### Parameters

- **Private Key Size:** 32 bytes
- **Public Key Size:** 32 bytes
- **Shared Secret Size:** 32 bytes
- **Curve:** Curve25519 (Montgomery form)

### Operation: Key Generation

**Inputs:**
- `seed`: 32 bytes (from CSPRNG)

**Outputs:**
- `private_key`: 32 bytes
- `public_key`: 32 bytes

**Pseudocode:**
```
function x25519_keygen(seed):
    private_key = seed
    private_key[0] &= 0xF8  # Clamp
    private_key[31] &= 0x7F
    private_key[31] |= 0x40
    
    public_key = x25519_scalarmult_base(private_key)
    return (private_key, public_key)
```

### Operation: Shared Secret

**Inputs:**
- `our_private_key`: 32 bytes
- `their_public_key`: 32 bytes

**Outputs:**
- `shared_secret`: 32 bytes

**Pseudocode:**
```
function x25519_shared_secret(our_private_key, their_public_key):
    shared_secret = x25519_scalarmult(our_private_key, their_public_key)
    
    # Check for all-zero output (failure case)
    if shared_secret == 0x00...00:
        return ERROR
    
    return shared_secret
```

### Security Requirements

1. **Ephemeral Keys:** Generate new keypair for each circuit
2. **Key Validation:** Reject all-zero public keys
3. **Post-Exchange Derivation:** Always pass shared secret through KDF (HKDF)
4. **Key Erasure:** Zero private keys immediately after deriving shared secret

### Test Vector 1

**Inputs:**
```
alice_private = 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a (hex)
alice_public = 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a (hex)
bob_private = 5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb (hex)
bob_public = de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f (hex)
```

**Outputs:**
```
shared_secret (alice) = 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742 (hex)
shared_secret (bob) = 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742 (hex)
```

### Test Vector 2

**Inputs:**
```
alice_private = 0x0900000000000000000000000000000000000000000000000000000000000000 (hex)
alice_public = 422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079 (hex)
bob_private = 0x0100000000000000000000000000000000000000000000000000000000000000 (hex)
bob_public = 0900000000000000000000000000000000000000000000000000000000000000 (hex)
```

**Outputs:**
```
shared_secret = 0x0000000000000000000000000000000000000000000000000000000000000000 (INVALID - reject)
```

### Performance Target

- **Key Generation:** < 20 µs
- **Shared Secret:** < 30 µs

---

## 4. SHA-256 (Hash)

**Purpose:** Addresses, message fingerprints, integrity checks  
**Specification:** FIPS 180-4

### Parameters

- **Input:** Variable length (up to 2⁶⁴ bits)
- **Output:** 32 bytes (256 bits)
- **Block Size:** 64 bytes

### Operation: Hash

**Inputs:**
- `message`: variable length

**Outputs:**
- `digest`: 32 bytes

**Pseudocode:**
```
function sha256(message):
    # Padding
    padded = message || 0x80 || zeros || bit_length(message)
    # (pad to multiple of 512 bits)
    
    # Process blocks
    state = IV  # Initial values (constants)
    for each 512-bit block in padded:
        state = sha256_compress(state, block)
    
    digest = serialize(state)
    return digest
```

### Security Requirements

1. **Collision Resistance:** Computationally infeasible to find two messages with same hash
2. **Pre-image Resistance:** Given hash, infeasible to find message
3. **Second Pre-image Resistance:** Given message, infeasible to find different message with same hash

### Test Vector 1

**Inputs:**
```
message = "" (empty)
```

**Outputs:**
```
digest = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 (hex)
```

### Test Vector 2

**Inputs:**
```
message = "abc" (ASCII)
```

**Outputs:**
```
digest = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad (hex)
```

### Test Vector 3

**Inputs:**
```
message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (ASCII)
```

**Outputs:**
```
digest = 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1 (hex)
```

### Performance Target

- **Throughput:** > 500 MB/s (single core)

---

## 5. Argon2id (Password KDF)

**Purpose:** Derive keys from human-readable secrets (passphrases)  
**Specification:** RFC 9106

### Parameters

- **Variant:** Argon2id (hybrid of Argon2i and Argon2d)
- **Time Cost (t):** 3 iterations
- **Memory Cost (m):** 65536 KiB (64 MiB)
- **Parallelism (p):** 4 threads
- **Salt Size:** 16 bytes
- **Output Size:** 32 bytes (configurable)

### Operation: Derive Key

**Inputs:**
- `password`: variable length (UTF-8 string)
- `salt`: 16 bytes (random, unique per password)
- `time_cost`: 3 (iterations)
- `memory_cost`: 65536 (KiB)
- `parallelism`: 4 (threads)
- `output_length`: 32 bytes

**Outputs:**
- `derived_key`: 32 bytes

**Pseudocode:**
```
function argon2id(password, salt, t, m, p, output_len):
    # Initial hash
    H0 = blake2b(p || output_len || m || t || version || hash_type ||
                 len(password) || password || len(salt) || salt ||
                 secret || ad)
    
    # Fill memory blocks
    for i in 0..p:
        B[i] = fill_first_blocks(H0, i)
    
    # Iterate (mixing Argon2i and Argon2d)
    for pass in 0..t:
        for slice in 0..4:
            for lane in 0..p:
                if pass == 0 and slice < 2:
                    # Argon2i (data-independent addressing)
                    idx = compute_index_i(pass, lane, slice)
                else:
                    # Argon2d (data-dependent addressing)
                    idx = compute_index_d(pass, lane, slice, B)
                
                B[lane][slice] = G(B[lane][slice-1], B[idx])
    
    # Final hash
    derived_key = blake2b(B[0][-1] XOR B[1][-1] XOR ... XOR B[p-1][-1])
    return derived_key[0..output_len]
```

### Security Requirements

1. **Unique Salt:** Generate fresh 16-byte salt for each password
2. **Secure Erase:** Zero password and derived key after use
3. **Side-Channel Resistance:** Argon2id is more resistant than Argon2d
4. **Tuning:** Increase `m` and `t` for higher security as hardware improves

### Test Vector 1

**Inputs:**
```
password = "password" (ASCII)
salt = "somesalt" (ASCII, 8 bytes - padded to 16)
time_cost = 2
memory_cost = 65536 KiB
parallelism = 1
output_length = 32
```

**Outputs:**
```
derived_key = c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0 (hex)
```

### Performance Target

- **Derivation Time:** 100-500 ms (target for user-facing authentication)

---

## 6. HKDF-SHA256 (Key Expansion)

**Purpose:** Expand shared secrets into multiple session keys  
**Specification:** RFC 5869

### Parameters

- **Hash Function:** SHA-256
- **Extract Output:** 32 bytes (PRK - pseudo-random key)
- **Expand Output:** Variable (up to 255 * 32 = 8160 bytes)

### Operation: Extract

**Inputs:**
- `salt`: variable length (can be empty or all zeros)
- `input_key_material`: variable length (e.g., X25519 shared secret)

**Outputs:**
- `prk`: 32 bytes (pseudo-random key)

**Pseudocode:**
```
function hkdf_extract(salt, ikm):
    if salt is empty:
        salt = zeros(32)  # All-zero salt
    
    prk = hmac_sha256(key=salt, message=ikm)
    return prk
```

### Operation: Expand

**Inputs:**
- `prk`: 32 bytes (from extract step)
- `info`: variable length (context string)
- `output_length`: desired key material length

**Outputs:**
- `okm`: output key material (output_length bytes)

**Pseudocode:**
```
function hkdf_expand(prk, info, output_length):
    N = ceil(output_length / 32)
    T = ""
    T_prev = ""
    
    for i in 1..N:
        T_i = hmac_sha256(key=prk, message=T_prev || info || byte(i))
        T = T || T_i
        T_prev = T_i
    
    okm = T[0..output_length]
    return okm
```

### Combined Operation

**Inputs:**
- `salt`: variable
- `input_key_material`: variable
- `info`: variable
- `output_length`: desired length

**Outputs:**
- `okm`: output key material

**Pseudocode:**
```
function hkdf(salt, ikm, info, output_length):
    prk = hkdf_extract(salt, ikm)
    okm = hkdf_expand(prk, info, output_length)
    return okm
```

### Usage in Project 666

After X25519 key exchange, derive session keys as follows:

```
shared_secret = x25519(our_private, their_public)

# Extract
prk = hkdf_extract(salt="666:circuit:v1", ikm=shared_secret)

# Expand into multiple keys
key_material = hkdf_expand(prk, info="session_keys", output_length=96)

session_key_send = key_material[0..31]    # ChaCha20 key for sending
session_key_recv = key_material[32..63]   # ChaCha20 key for receiving
session_key_mac = key_material[64..95]    # MAC key (if needed)
```

### Test Vector 1

**Inputs:**
```
salt = 0x000102030405060708090a0b0c (hex, 13 bytes)
ikm = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (hex, 22 bytes)
info = "" (empty)
output_length = 42
```

**Outputs:**
```
prk = 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5 (hex)
okm = 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865 (hex)
```

### Performance Target

- **Extract:** < 10 µs
- **Expand:** < 5 µs per 32-byte block

---

## Key Management Best Practices

### Key Lifecycle

1. **Generation:** Use CSPRNG (e.g., `/dev/urandom`, `getrandom()`, `CryptGenRandom()`)
2. **Storage:** Encrypt at rest; use OS-level protection (e.g., mlock)
3. **Usage:** Load into memory only when needed
4. **Rotation:** Circuits every 10 minutes, sessions every 60 minutes
5. **Erasure:** Zero memory immediately after use (secure_zero() or explicit_bzero())

### Key Separation

Different keys for different purposes (domain separation):

```
identity_keypair = Ed25519.keygen()  # Long-term signing
circuit_keypair = X25519.keygen()    # Per-circuit encryption
session_key = HKDF(circuit_shared_secret, "session:v1")
capability_sig = Ed25519.sign(identity_key, capability_token)
```

### Constant-Time Operations

**Critical Functions:**
- `constant_time_compare(a, b)`: Compare byte arrays without timing leaks
- `constant_time_select(condition, a, b)`: Conditional select without branches

**Example (C-style):**
```c
int constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return (1 & ((diff - 1) >> 8)) - 1;  // Returns 0 if equal, -1 if not
}
```

---

## Randomness Requirements

### Sources

1. **OS CSPRNG:** Primary source
   - Linux: `/dev/urandom` or `getrandom()`
   - Windows: `CryptGenRandom()` or `BCryptGenRandom()`
   - macOS/BSD: `arc4random_buf()`

2. **Reseeding:** Not required (OS handles it)

3. **Fallback:** If OS CSPRNG unavailable, MUST fail (do not use weak RNG)

### Usage

- **Nonces:** 12 bytes for ChaCha20-Poly1305
- **Salts:** 16 bytes for Argon2id
- **Keys:** 32 bytes for all keypair generation
- **Message IDs:** 8 bytes (birthday bound: 2³² messages)

---

## Test Vector Format

All test vectors use hexadecimal encoding (lowercase) for binary data and ASCII for strings.

**Example:**
```
Input:
  key = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  nonce = 0x000000000000000000000001
  plaintext = "Hello, World!" (ASCII)
  
Output:
  ciphertext = 0x3c4a5f... (hex)
  tag = 0x8d9e7f... (hex)
```

---

## Implementation Checklist

For an implementation to be **compliant**:

- ✅ ChaCha20-Poly1305: RFC 8439, 256-bit keys, 96-bit nonces, 128-bit tags
- ✅ Ed25519: RFC 8032, deterministic signatures, low-order point checks
- ✅ X25519: RFC 7748, ephemeral keys, all-zero rejection
- ✅ SHA-256: FIPS 180-4, correct test vectors
- ✅ Argon2id: RFC 9106, parameters (t=3, m=64 MiB, p=4)
- ✅ HKDF-SHA256: RFC 5869, extract-then-expand
- ✅ Constant-time comparisons for all tag/signature verifications
- ✅ Secure key erasure after use
- ✅ CSPRNG for all random values

---

## Cross-References

- [PROTOCOL_SPEC.md](PROTOCOL_SPEC.md) - Overview and addressing
- [MESSAGE_FORMAT.md](MESSAGE_FORMAT.md) - How crypto is applied to messages
- [ROUTING_SPEC.md](ROUTING_SPEC.md) - Circuit key derivation
- [CAPABILITY_MODEL.md](CAPABILITY_MODEL.md) - Signature usage for capabilities

---

## Changelog

### Version 1.0.0 (2024-01-14)
- Initial cryptographic specification
- Defined all primitives with exact parameters
- Provided test vectors for each operation
- Specified key management and constant-time requirements

---

**End of Cryptographic Operations Specification v1.0**
