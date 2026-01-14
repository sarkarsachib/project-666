# Message Format Specification v1.0

**Version:** 1.0.0  
**Status:** Normative Specification  
**Last Updated:** 2024-01-14

---

## Overview

This document specifies the exact binary wire format for all Project 666 messages. Every field is defined with byte offsets, sizes, and encoding. All integers are **big-endian** unless otherwise noted.

**Design Principles:**
1. **Fixed Headers:** All messages start with a 24-byte header
2. **Length-Prefixed:** Variable-length fields include length prefix
3. **Type Safety:** Message type in header enables validation
4. **Padding:** Messages padded to multiples of 16 bytes for traffic analysis resistance

---

## Universal Message Header (24 bytes)

Every message begins with this header:

```
Offset | Size | Field              | Type    | Description
-------|------|--------------------|---------|-----------------------------------------
0      | 4    | Magic              | uint32  | 0x36363600 ("666\0")
4      | 1    | VersionMajor       | uint8   | Protocol major version (1)
5      | 1    | VersionMinor       | uint8   | Protocol minor version (0)
6      | 2    | MessageType        | uint16  | Opcode (see opcodes below)
8      | 4    | MessageLength      | uint32  | Total bytes (header + payload)
12     | 8    | MessageID          | uint64  | Unique message identifier
20     | 4    | CRC32              | uint32  | Checksum of entire message
```

**Notes:**
- **Magic:** Always `0x36363600` (ASCII "666" + null byte)
- **Version:** Currently `0x01 0x00` (v1.0)
- **MessageLength:** Includes header (minimum 24 bytes)
- **MessageID:** Random 64-bit value (for correlation and deduplication)
- **CRC32:** CRC-32C (Castagnoli) over entire message with CRC field set to 0

### CRC32 Calculation

```pseudocode
function compute_crc32(message):
    # Zero out the CRC field (bytes 20-23)
    temp = message.copy()
    temp[20..23] = 0x00000000
    
    # Compute CRC-32C
    crc = crc32c(temp)
    return crc
```

---

## Message Types and Opcodes

| Opcode | Name                  | Section |
|--------|-----------------------|---------|
| 0x0001 | PING                  | 2.1     |
| 0x0002 | PONG                  | 2.2     |
| 0x0010 | DHT_PUT               | 3.1     |
| 0x0011 | DHT_GET               | 3.2     |
| 0x0012 | DHT_RESPONSE          | 3.3     |
| 0x0020 | CIRCUIT_CREATE        | 4.1     |
| 0x0021 | CIRCUIT_CREATED       | 4.2     |
| 0x0022 | CIRCUIT_EXTEND        | 4.3     |
| 0x0023 | CIRCUIT_EXTENDED      | 4.4     |
| 0x0024 | CIRCUIT_RELAY         | 4.5     |
| 0x0025 | CIRCUIT_DESTROY       | 4.6     |
| 0x0030 | INVOKE                | 5.1     |
| 0x0031 | RESULT                | 5.2     |
| 0x0032 | ERROR                 | 5.3     |
| 0x0040 | CAPABILITY_ISSUE      | 6.1     |
| 0x0041 | CAPABILITY_REVOKE     | 6.2     |
| 0x0042 | CAPABILITY_VERIFY     | 6.3     |
| 0x0043 | CAPABILITY_VERIFIED   | 6.4     |
| 0x0050 | DESCRIPTOR_PUBLISH    | 7.1     |
| 0x0051 | DESCRIPTOR_QUERY      | 7.2     |
| 0x0052 | DESCRIPTOR_RESPONSE   | 7.3     |

---

## 2. Connectivity Messages

### 2.1 PING (0x0001)

**Purpose:** Heartbeat, latency measurement, keepalive

**Payload (16 bytes):**
```
Offset | Size | Field              | Type    | Description
-------|------|--------------------|---------|---------------------------
24     | 8    | Timestamp          | uint64  | Unix timestamp (ms)
32     | 8    | PingID             | uint64  | Random identifier
```

**Total Size:** 40 bytes (24 header + 16 payload)

**Example:**
```hex
36 36 36 00                    # Magic
01 00                          # Version 1.0
00 01                          # MessageType = PING
00 00 00 28                    # Length = 40 bytes
12 34 56 78 9A BC DE F0        # MessageID
XX XX XX XX                    # CRC32 (computed)
00 00 01 8D 7F 3A 2B 10        # Timestamp = 1704380000000
AB CD EF 12 34 56 78 90        # PingID
```

---

### 2.2 PONG (0x0002)

**Purpose:** Response to PING

**Payload (24 bytes):**
```
Offset | Size | Field              | Type    | Description
-------|------|--------------------|---------|---------------------------
24     | 8    | RequestMessageID   | uint64  | MessageID from PING
32     | 8    | RequestTimestamp   | uint64  | Timestamp from PING
40     | 8    | ResponseTimestamp  | uint64  | Current timestamp
```

**Total Size:** 48 bytes (24 header + 24 payload)

**RTT Calculation:**
```
rtt_ms = ResponseTimestamp - RequestTimestamp
```

---

## 3. DHT Messages

### 3.1 DHT_PUT (0x0010)

**Purpose:** Store key-value pair in DHT

**Payload (variable):**
```
Offset | Size | Field              | Type       | Description
-------|------|--------------------|-----------|---------------------------------
24     | 32   | Key                | bytes[32] | SHA-256 hash (lookup key)
56     | 4    | ValueLength        | uint32    | Length of Value in bytes
60     | 4    | TTL                | uint32    | Time-to-live (seconds)
64     | N    | Value              | bytes     | Encrypted value data
64+N   | 64   | Signature          | bytes[64] | Ed25519 signature over key+value
```

**Total Size:** 128 + N + padding

**Signature Input:**
```
sign_data = Key || ValueLength || TTL || Value
signature = Ed25519.sign(publisher_private_key, sign_data)
```

**Validation:**
1. Check `ValueLength` matches actual value size
2. Check `TTL` is reasonable (1 hour to 7 days)
3. Verify signature against publisher's public key
4. Store with expiration time = current_time + TTL

---

### 3.2 DHT_GET (0x0011)

**Purpose:** Retrieve value by key

**Payload (32 bytes):**
```
Offset | Size | Field              | Type       | Description
-------|------|--------------------|-----------|---------------------------------
24     | 32   | Key                | bytes[32] | SHA-256 hash (lookup key)
```

**Total Size:** 56 bytes (24 header + 32 payload)

---

### 3.3 DHT_RESPONSE (0x0012)

**Purpose:** Return value from DHT_GET or DHT_PUT confirmation

**Payload (variable):**
```
Offset | Size | Field              | Type       | Description
-------|------|--------------------|-----------|---------------------------------
24     | 8    | RequestMessageID   | uint64    | MessageID from DHT_GET/PUT
32     | 32   | Key                | bytes[32] | Key being responded to
64     | 2    | StatusCode         | uint16    | 0=success, error codes
66     | 4    | ValueLength        | uint32    | Length of Value (0 if error)
70     | N    | Value              | bytes     | Value data (if found)
70+N   | 64   | Signature          | bytes[64] | Original publisher signature
```

**Total Size:** 134 + N + padding

**Status Codes:**
- `0x0000`: Success (value found)
- `0x0041`: Not found
- `0x0042`: Storage full
- `0x0040`: Timeout

---

## 4. Circuit Messages

### 4.1 CIRCUIT_CREATE (0x0020)

**Purpose:** Establish first hop of circuit

**Payload (96 bytes):**
```
Offset | Size | Field              | Type       | Description
-------|------|--------------------|-----------|---------------------------------
24     | 4    | CircuitID          | uint32    | Client-assigned circuit ID
28     | 32   | ClientPublicKey    | bytes[32] | X25519 ephemeral public key
60     | 32   | HandshakeData      | bytes[32] | Additional handshake context
92     | 8    | Timestamp          | uint64    | Creation timestamp (ms)
100    | 20   | Reserved           | bytes[20] | Reserved (set to 0)
```

**Total Size:** 120 bytes (24 header + 96 payload)

**Process:**
1. Client generates X25519 keypair: `(sk_client, pk_client)`
2. Client sends `pk_client` to relay
3. Relay generates its own keypair: `(sk_relay, pk_relay)`
4. Relay computes shared secret: `shared = X25519(sk_relay, pk_client)`
5. Relay derives session keys: `keys = HKDF(shared, "circuit:v1")`

---

### 4.2 CIRCUIT_CREATED (0x0021)

**Purpose:** Confirm first hop established

**Payload (96 bytes):**
```
Offset | Size | Field              | Type       | Description
-------|------|--------------------|-----------|---------------------------------
24     | 8    | RequestMessageID   | uint64    | MessageID from CIRCUIT_CREATE
32     | 4    | CircuitID          | uint32    | Circuit identifier
36     | 32   | RelayPublicKey     | bytes[32] | Relay's X25519 ephemeral public key
68     | 32   | HandshakeData      | bytes[32] | Relay's handshake context
100    | 20   | Reserved           | bytes[20] | Reserved
```

**Total Size:** 120 bytes (24 header + 96 payload)

**Process:**
1. Client receives `pk_relay`
2. Client computes shared secret: `shared = X25519(sk_client, pk_relay)`
3. Client derives same session keys: `keys = HKDF(shared, "circuit:v1")`
4. Both parties now have symmetric keys for this hop

---

### 4.3 CIRCUIT_EXTEND (0x0022)

**Purpose:** Add another hop to existing circuit

**Payload (variable, encrypted):**
```
Offset | Size | Field              | Type       | Description
-------|------|--------------------|-----------|---------------------------------
24     | 4    | CircuitID          | uint32    | Existing circuit ID
28     | 32   | NextHopAddress     | bytes[32] | .666 address of next relay
60     | 32   | ClientPublicKey    | bytes[32] | X25519 key for next hop
92     | 4    | PayloadLength      | uint32    | Length of encrypted payload
96     | N    | EncryptedPayload   | bytes     | ChaCha20-Poly1305 encrypted data
96+N   | 16   | Tag                | bytes[16] | AEAD authentication tag
```

**Total Size:** 112 + N + padding

**Encrypted Payload Contents (before encryption):**
```
Additional handshake context (32 bytes)
Timestamp (8 bytes)
```

**Encryption:**
```
key = session_key_for_current_hop
nonce = circuit_nonce[CircuitID]
plaintext = NextHopHandshake || Timestamp
(ciphertext, tag) = ChaCha20Poly1305.encrypt(key, nonce, plaintext, aad=CircuitID)
```

---

### 4.4 CIRCUIT_EXTENDED (0x0023)

**Purpose:** Confirm hop added

**Payload (variable, encrypted):**
```
Offset | Size | Field              | Type       | Description
-------|------|--------------------|-----------|---------------------------------
24     | 8    | RequestMessageID   | uint64    | MessageID from CIRCUIT_EXTEND
32     | 4    | CircuitID          | uint32    | Circuit identifier
36     | 4    | PayloadLength      | uint32    | Length of encrypted payload
40     | N    | EncryptedPayload   | bytes     | ChaCha20-Poly1305 encrypted data
40+N   | 16   | Tag                | bytes[16] | AEAD authentication tag
```

**Encrypted Payload Contents:**
```
NextRelayPublicKey (32 bytes) - X25519 public key of new hop
HandshakeData (32 bytes)
```

---

### 4.5 CIRCUIT_RELAY (0x0024)

**Purpose:** Forward encrypted payload through circuit

**Payload (variable, multi-layer encrypted):**
```
Offset | Size | Field              | Type       | Description
-------|------|--------------------|-----------|---------------------------------
24     | 4    | CircuitID          | uint32    | Circuit identifier
28     | 2    | RelayCommand       | uint16    | Inner command type
30     | 2    | StreamID           | uint16    | Multiplexing stream ID
32     | 4    | PayloadLength      | uint32    | Length of payload
36     | N    | EncryptedPayload   | bytes     | Onion-encrypted data
36+N   | 16   | Tag                | bytes[16] | Outer layer authentication tag
```

**Relay Commands:**
- `0x01`: BEGIN (start stream)
- `0x02`: DATA (stream data)
- `0x03`: END (close stream)
- `0x04`: TEARDOWN (destroy circuit)

**Onion Encryption (3 hops):**
```
# At client (encrypt 3 times, innermost first)
layer1 = ChaCha20Poly1305.encrypt(key_hop3, nonce3, plaintext, aad)
layer2 = ChaCha20Poly1305.encrypt(key_hop2, nonce2, layer1, aad)
layer3 = ChaCha20Poly1305.encrypt(key_hop1, nonce1, layer2, aad)
# Send layer3

# At relay 1 (decrypt outer layer)
layer2 = ChaCha20Poly1305.decrypt(key_hop1, nonce1, layer3, aad)
# Forward layer2 to relay 2

# At relay 2 (decrypt middle layer)
layer1 = ChaCha20Poly1305.decrypt(key_hop2, nonce2, layer2, aad)
# Forward layer1 to relay 3

# At relay 3 (decrypt inner layer)
plaintext = ChaCha20Poly1305.decrypt(key_hop3, nonce3, layer1, aad)
# Deliver plaintext to destination
```

---

### 4.6 CIRCUIT_DESTROY (0x0025)

**Purpose:** Tear down circuit

**Payload (12 bytes):**
```
Offset | Size | Field              | Type       | Description
-------|------|--------------------|-----------|---------------------------------
24     | 4    | CircuitID          | uint32    | Circuit to destroy
28     | 2    | ReasonCode         | uint16    | Why circuit is closing
30     | 2    | Reserved           | uint16    | Reserved
32     | 4    | Timestamp          | uint32    | Unix timestamp (seconds)
```

**Reason Codes:**
- `0x0000`: Normal close
- `0x0001`: Timeout
- `0x0002`: Protocol error
- `0x0003`: Relay overloaded
- `0x0004`: Authentication failed

**Total Size:** 36 bytes (24 header + 12 payload)

**Process:**
1. Sender sends CIRCUIT_DESTROY
2. Each relay receives it, erases circuit state
3. No response expected
4. Circuit resources freed immediately

---

## 5. Service Invocation Messages

### 5.1 INVOKE (0x0030)

**Purpose:** Execute service capability

**Payload (variable):**
```
Offset | Size | Field              | Type       | Description
-------|------|--------------------|-----------|---------------------------------
24     | 32   | ServiceAddress     | bytes[32] | Target .666 address
56     | 4    | CapabilityLength   | uint32    | Length of capability token
60     | C    | CapabilityToken    | bytes     | Capability token (see section 6)
60+C   | 4    | PayloadLength      | uint32    | Length of invocation payload
64+C   | P    | Payload            | bytes     | Service-specific input data
64+C+P | 8    | Timestamp          | uint64    | Invocation timestamp (ms)
72+C+P | 4    | TimeoutMs          | uint32    | Max execution time (ms)
```

**Total Size:** 76 + C + P + padding

**Validation:**
1. Verify `ServiceAddress` matches descriptor
2. Validate `CapabilityToken` (see CAPABILITY_MODEL.md)
3. Check `Payload` conforms to service descriptor schema
4. Start timeout timer

---

### 5.2 RESULT (0x0031)

**Purpose:** Return successful execution result

**Payload (variable):**
```
Offset | Size | Field              | Type       | Description
-------|------|--------------------|-----------|---------------------------------
24     | 8    | RequestMessageID   | uint64    | MessageID from INVOKE
32     | 4    | StatusCode         | uint32    | 0x0000 = success
36     | 4    | ResultLength       | uint32    | Length of result data
40     | R    | ResultData         | bytes     | Service output
40+R   | 8    | ExecutionTimeMs    | uint64    | How long execution took
48+R   | 32   | ResultHash         | bytes[32] | SHA-256(ResultData) for integrity
```

**Total Size:** 80 + R + padding

---

### 5.3 ERROR (0x0032)

**Purpose:** Return execution failure

**Payload (variable):**
```
Offset | Size | Field              | Type       | Description
-------|------|--------------------|-----------|---------------------------------
24     | 8    | RequestMessageID   | uint64    | MessageID from INVOKE
32     | 2    | ErrorCode          | uint16    | Error code (see PROTOCOL_SPEC)
34     | 2    | Reserved           | uint16    | Reserved
36     | 4    | ErrorMessageLength | uint32    | Length of error message
40     | E    | ErrorMessage       | bytes     | UTF-8 error description
40+E   | 8    | Timestamp          | uint64    | When error occurred
```

**Total Size:** 48 + E + padding

---

## 6. Capability Messages

### 6.1 CAPABILITY_ISSUE (0x0040)

**Purpose:** Create new capability token

**Payload (variable):**
```
Offset | Size | Field              | Type       | Description
-------|------|--------------------|-----------|---------------------------------
24     | 32   | IssuerAddress      | bytes[32] | Issuer's .666 address
56     | 32   | HolderPublicKey    | bytes[32] | Holder's identity public key (or 0 for bearer)
88     | 4    | PermissionsLength  | uint32    | Length of permissions field
92     | P    | Permissions        | bytes     | Permission descriptors (JSON or binary)
92+P   | 8    | IssuedAt           | uint64    | Unix timestamp (ms)
100+P  | 8    | ExpiresAt          | uint64    | Unix timestamp (ms)
108+P  | 4    | NonceRevocation    | uint32    | Revocation nonce (increment to revoke)
112+P  | 64   | IssuerSignature    | bytes[64] | Ed25519 signature over all above fields
```

**Total Size:** 176 + P + padding

**Signature Input:**
```
sign_data = IssuerAddress || HolderPublicKey || PermissionsLength || Permissions ||
            IssuedAt || ExpiresAt || NonceRevocation
signature = Ed25519.sign(issuer_private_key, sign_data)
```

**Permissions Format (JSON example):**
```json
{
  "service": "7MZUWAU2FJVXQ2KQN5DXA5I4PA4WCLV7...",
  "operations": ["read", "write"],
  "rate_limit": 100,
  "max_invocations": 1000
}
```

---

### 6.2 CAPABILITY_REVOKE (0x0041)

**Purpose:** Revoke capability token

**Payload (variable):**
```
Offset | Size | Field              | Type       | Description
-------|------|--------------------|-----------|---------------------------------
24     | 32   | IssuerAddress      | bytes[32] | Issuer's .666 address
56     | 32   | CapabilityHash     | bytes[32] | SHA-256 of capability token
88     | 4    | NewNonce           | uint32    | New revocation nonce (invalidates old)
92     | 8    | RevokedAt          | uint64    | Unix timestamp (ms)
100    | 2    | ReasonCode         | uint16    | Why revoked
102    | 64   | IssuerSignature    | bytes[64] | Ed25519 signature
```

**Reason Codes:**
- `0x01`: Manual revocation
- `0x02`: Security compromise
- `0x03`: Expired and renewed
- `0x04`: Policy violation

**Total Size:** 166 bytes + padding

---

### 6.3 CAPABILITY_VERIFY (0x0042)

**Purpose:** Check if capability is still valid

**Payload (variable):**
```
Offset | Size | Field              | Type       | Description
-------|------|--------------------|-----------|---------------------------------
24     | 4    | CapabilityLength   | uint32    | Length of capability token
28     | C    | CapabilityToken    | bytes     | Full capability token to verify
28+C   | 8    | Timestamp          | uint64    | Current timestamp (ms)
```

**Total Size:** 36 + C + padding

---

### 6.4 CAPABILITY_VERIFIED (0x0043)

**Purpose:** Return verification result

**Payload (variable):**
```
Offset | Size | Field              | Type       | Description
-------|------|--------------------|-----------|---------------------------------
24     | 8    | RequestMessageID   | uint64    | MessageID from CAPABILITY_VERIFY
32     | 32   | CapabilityHash     | bytes[32] | SHA-256 of verified token
64     | 1    | IsValid            | uint8     | 1=valid, 0=invalid
65     | 2    | StatusCode         | uint16    | Reason if invalid
67     | 8    | ExpiresAt          | uint64    | Expiration timestamp (if valid)
75     | 1    | Reserved           | uint8     | Reserved
```

**Status Codes (if invalid):**
- `0x0030`: Capability denied (signature invalid)
- `0x0031`: Capability expired
- `0x0032`: Capability revoked

**Total Size:** 76 bytes + padding

---

## 7. Descriptor Messages

### 7.1 DESCRIPTOR_PUBLISH (0x0050)

**Purpose:** Publish system descriptor to DHT

**Payload (variable):**
```
Offset | Size | Field              | Type       | Description
-------|------|--------------------|-----------|---------------------------------
24     | 32   | ServiceAddress     | bytes[32] | Service .666 address
56     | 4    | DescriptorLength   | uint32    | Length of descriptor
60     | D    | DescriptorData     | bytes     | Encrypted descriptor (see SYSTEM_DESCRIPTOR.md)
60+D   | 4    | TTL                | uint32    | Time-to-live (seconds)
64+D   | 64   | ServiceSignature   | bytes[64] | Ed25519 signature (proves ownership)
```

**Total Size:** 128 + D + padding

**Descriptor Encryption:**
```
# Descriptor is encrypted so only capability holders can read it
key = HKDF(service_identity_key, "descriptor:v1")
nonce = random(12)
(ciphertext, tag) = ChaCha20Poly1305.encrypt(key, nonce, descriptor_json, aad=ServiceAddress)
DescriptorData = nonce || ciphertext || tag
```

---

### 7.2 DESCRIPTOR_QUERY (0x0051)

**Purpose:** Request system descriptor

**Payload (32 bytes):**
```
Offset | Size | Field              | Type       | Description
-------|------|--------------------|-----------|---------------------------------
24     | 32   | ServiceAddress     | bytes[32] | Service .666 address
```

**Total Size:** 56 bytes (24 header + 32 payload)

---

### 7.3 DESCRIPTOR_RESPONSE (0x0052)

**Purpose:** Return system descriptor

**Payload (variable):**
```
Offset | Size | Field              | Type       | Description
-------|------|--------------------|-----------|---------------------------------
24     | 8    | RequestMessageID   | uint64    | MessageID from DESCRIPTOR_QUERY
32     | 32   | ServiceAddress     | bytes[32] | Service .666 address
64     | 2    | StatusCode         | uint16    | 0=success, error codes
66     | 4    | DescriptorLength   | uint32    | Length of descriptor (0 if error)
70     | D    | DescriptorData     | bytes     | Encrypted descriptor
70+D   | 64   | ServiceSignature   | bytes[64] | Ed25519 signature
```

**Total Size:** 134 + D + padding

---

## 8. Padding and Alignment

To resist traffic analysis, all messages are padded to multiples of 16 bytes.

**Padding Algorithm:**
```pseudocode
function pad_message(message):
    current_length = len(message)
    target_length = ceil(current_length / 16) * 16
    padding_length = target_length - current_length
    
    # Append padding bytes
    padding = random_bytes(padding_length)
    return message || padding
```

**Padding Removal:**
Receiver must know actual message length from `MessageLength` field in header. Ignore bytes beyond `MessageLength`.

**Traffic Shaping:**
- Minimum message size: 64 bytes (after padding)
- Maximum message size: 65536 bytes (64 KB)
- For larger payloads, split into multiple CIRCUIT_RELAY messages

---

## 9. Serialization Examples

### Example 1: PING Message

**Fields:**
- Magic: `0x36363600`
- Version: `1.0`
- MessageType: `0x0001` (PING)
- MessageLength: `40` (0x00000028)
- MessageID: `0x123456789ABCDEF0`
- CRC32: (computed)
- Timestamp: `1704380000000` (0x0000018D7F3A2B10)
- PingID: `0xABCDEF1234567890`

**Binary (hex):**
```
36 36 36 00 01 00 00 01 00 00 00 28 12 34 56 78
9A BC DE F0 XX XX XX XX 00 00 01 8D 7F 3A 2B 10
AB CD EF 12 34 56 78 90
```

### Example 2: DHT_PUT Message

**Fields:**
- Header (24 bytes)
- Key: `SHA-256("example_key")`
- ValueLength: `13`
- TTL: `3600` (1 hour)
- Value: `"Hello, World!"` (ASCII)
- Signature: (64 bytes)

**Binary Structure:**
```
[24-byte header]
[32-byte key]
[4-byte value length]
[4-byte TTL]
[13-byte value]
[64-byte signature]
[3 bytes padding to align to 16]
Total: 144 bytes
```

---

## 10. Validation Rules

For a message to be **valid**:

1. ✅ Magic bytes are `0x36363600`
2. ✅ Version is supported (major version match)
3. ✅ MessageType is recognized opcode
4. ✅ MessageLength matches actual size
5. ✅ CRC32 matches computed checksum
6. ✅ All length-prefixed fields have correct lengths
7. ✅ All signatures verify correctly
8. ✅ All encrypted payloads decrypt successfully
9. ✅ All required fields are present
10. ✅ No buffer overflows or underflows

**On Invalid Message:**
- Log error with message ID and sender
- Drop message (do not respond)
- Do not update any state
- Optional: Rate-limit sender

---

## 11. Implementation Checklist

For an implementation to be **compliant**:

- ✅ All message types implemented with exact field layouts
- ✅ Big-endian encoding for all multi-byte integers
- ✅ CRC32-C checksum validation
- ✅ Padding to 16-byte boundaries
- ✅ Length validation before parsing
- ✅ Signature verification for signed messages
- ✅ Encryption/decryption for circuit messages
- ✅ Onion routing with 3-layer encryption
- ✅ Maximum message size enforcement (64 KB)
- ✅ Graceful handling of malformed messages

---

## Cross-References

- [PROTOCOL_SPEC.md](PROTOCOL_SPEC.md) - Message type overview
- [CRYPTO_SPEC.md](CRYPTO_SPEC.md) - Signature and encryption details
- [ROUTING_SPEC.md](ROUTING_SPEC.md) - Circuit message flow
- [CAPABILITY_MODEL.md](CAPABILITY_MODEL.md) - Capability token structure
- [SYSTEM_DESCRIPTOR.md](SYSTEM_DESCRIPTOR.md) - Descriptor format

---

## Changelog

### Version 1.0.0 (2024-01-14)
- Initial message format specification
- Defined all 19 message types with byte-level layouts
- Specified padding and alignment rules
- Added validation rules and examples

---

**End of Message Format Specification v1.0**
