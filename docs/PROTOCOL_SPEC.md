# Project 666 Protocol Specification v1.0

**Version:** 1.0.0  
**Status:** Master Specification  
**Last Updated:** 2024-01-14

---

## Executive Summary

Project 666 is a privacy-preserving, capability-based communication protocol designed for secure, anonymous interaction between distributed services. It combines onion routing (inspired by Tor), object-capability security (inspired by E language), and distributed hash table (DHT) discovery to enable verifiable, sandboxed execution of remote services without revealing identity or location.

### Core Vision

Enable any service (`.666` entity) to invoke any other service via cryptographically enforced capabilities, with the following guarantees:

1. **Sender Anonymity**: Invoker identity is never revealed to the service
2. **Receiver Anonymity**: Service location is decoupled from its address
3. **Capability Enforcement**: Only operations with valid capability tokens execute
4. **Forward Secrecy**: Compromise of long-term keys doesn't decrypt past sessions
5. **Metadata Protection**: Observers cannot correlate requests across sessions
6. **Auditability**: All interactions can be verified without compromising privacy

### Core Principles

1. **Privacy by Default**: All communication is encrypted end-to-end and routed through multiple relays
2. **Zero Trust**: Every message is authenticated; no implicit permissions
3. **Capability-Based Security**: Possession of a token is authority to act
4. **Opaque Addressing**: Service addresses reveal nothing about location or implementation
5. **Language Agnostic**: Protocol can be implemented in any Turing-complete language
6. **AI Orchestrable**: Master AI can inspect state and control execution deterministically

---

## Addressing Model

### Address Format

A `.666` address is a 32-byte opaque identifier derived from a service's identity public key:

```
Address = SHA-256(IdentityPublicKey || SERVICE_DOMAIN_SEPARATOR)
```

**Constants:**
- `SERVICE_DOMAIN_SEPARATOR` = `"666:service:v1"` (UTF-8 encoded)
- Address length: 32 bytes (256 bits)

**Encoding:**
- Binary: Raw 32 bytes
- Text: Base32 encoding (52 characters, case-insensitive)
- Example: `7MZUWAU2FJVXQ2KQN5DXA5I4PA4WCLV7GMYDENBWGA3DOOJGQ7LA`

### Address Derivation

1. Generate Ed25519 identity keypair: `(sk_identity, pk_identity)`
2. Compute address: `addr = SHA-256(pk_identity || "666:service:v1")`
3. The address is public; the keypair is secret

**Properties:**
- **Uniqueness**: Collision resistance of SHA-256 (2^256 space)
- **Verifiability**: Anyone can verify `pk → addr` mapping
- **Unlinkability**: Address reveals nothing about public key structure
- **Stable Identity**: Same keypair always produces same address

### Special Addresses

- `0x0000000000000000000000000000000000000000000000000000000000000000`: Null address (invalid)
- `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF`: Broadcast address (reserved)

---

## Wire Format

All messages use a tagged length-value (TLV) structure with versioning and type discrimination.

### Message Header (24 bytes)

```
Offset | Size | Field              | Description
-------|------|--------------------|-----------------------------------------
0      | 4    | Magic              | 0x36363600 ("666\0")
4      | 2    | ProtocolVersion    | Major (1 byte) || Minor (1 byte)
6      | 2    | MessageType        | Opcode (see Message Types)
8      | 4    | MessageLength      | Total bytes including header (big-endian)
12     | 8    | MessageID          | Unique message identifier (random)
20     | 4    | CRC32              | Checksum of header + payload
```

**Magic Bytes:** `0x36 0x36 0x36 0x00` (ASCII "666" + null terminator)  
**Current Version:** `0x01 0x00` (v1.0)

### Payload Structure

After the 24-byte header, payloads are message-type specific. See [MESSAGE_FORMAT.md](MESSAGE_FORMAT.md) for detailed layouts.

---

## Message Types

All message types (opcodes) with their numeric values:

| Opcode | Name                  | Direction      | Description |
|--------|----------------------|----------------|-------------|
| 0x0001 | PING                 | Bidirectional  | Heartbeat / latency measurement |
| 0x0002 | PONG                 | Response       | Response to PING |
| 0x0010 | DHT_PUT              | To DHT         | Store key-value in DHT |
| 0x0011 | DHT_GET              | To DHT         | Retrieve value by key |
| 0x0012 | DHT_RESPONSE         | From DHT       | DHT query result |
| 0x0020 | CIRCUIT_CREATE       | To Relay       | Establish circuit leg |
| 0x0021 | CIRCUIT_CREATED      | From Relay     | Circuit leg confirmed |
| 0x0022 | CIRCUIT_EXTEND       | Through Circuit| Add hop to circuit |
| 0x0023 | CIRCUIT_EXTENDED     | Through Circuit| Hop added confirmation |
| 0x0024 | CIRCUIT_RELAY        | Through Circuit| Forward encrypted payload |
| 0x0025 | CIRCUIT_DESTROY      | Through Circuit| Tear down circuit |
| 0x0030 | INVOKE               | To Service     | Execute capability |
| 0x0031 | RESULT               | From Service   | Successful execution result |
| 0x0032 | ERROR                | From Service   | Execution failure |
| 0x0040 | CAPABILITY_ISSUE     | From Issuer    | Create new capability token |
| 0x0041 | CAPABILITY_REVOKE    | From Issuer    | Revoke existing token |
| 0x0042 | CAPABILITY_VERIFY    | To Issuer      | Verify token validity |
| 0x0043 | CAPABILITY_VERIFIED  | From Issuer    | Token verification result |
| 0x0050 | DESCRIPTOR_PUBLISH   | To DHT         | Publish system descriptor |
| 0x0051 | DESCRIPTOR_QUERY     | To DHT         | Request system descriptor |
| 0x0052 | DESCRIPTOR_RESPONSE  | From DHT       | Descriptor data |

---

## Cryptographic Operations

All cryptographic primitives are specified in detail in [CRYPTO_SPEC.md](CRYPTO_SPEC.md). Summary:

### Primitives

1. **Symmetric Encryption**: ChaCha20-Poly1305 (AEAD)
2. **Key Derivation**: Argon2id (password hashing) and HKDF-SHA256 (key expansion)
3. **Signing**: Ed25519
4. **Key Exchange**: X25519 (Diffie-Hellman)
5. **Hashing**: SHA-256

### Key Types

- **Identity Keys**: Ed25519 keypair (long-term, signs capabilities)
- **Circuit Keys**: X25519 ephemeral keys (per-circuit, forward secrecy)
- **Session Keys**: ChaCha20 keys (derived from X25519 shared secret)

### Security Requirements

- All operations MUST be constant-time to prevent side-channel attacks
- Random number generation MUST use cryptographically secure PRNG
- Key erasure MUST occur immediately after key rotation or circuit destruction

---

## State Machines

### Circuit Lifecycle

```
[INIT] --CREATE--> [BUILDING] --EXTEND--> [BUILDING] --READY--> [ACTIVE]
                                                                    |
[CLOSED] <--DESTROY-- [ACTIVE]
```

**States:**
- `INIT`: Circuit ID allocated, no relays connected
- `BUILDING`: First hop established, extending to additional hops
- `ACTIVE`: All hops ready, can relay messages
- `CLOSED`: Circuit destroyed, resources freed

**Transitions:**
- `CREATE → BUILDING`: First CIRCUIT_CREATE sent and acknowledged
- `EXTEND → BUILDING`: Adding additional hops (repeat N times)
- `READY → ACTIVE`: Final hop extended, circuit is complete
- `DESTROY → CLOSED`: CIRCUIT_DESTROY sent or timeout

**Invariants:**
- Minimum 3 hops for anonymity
- Maximum 8 hops for latency
- Circuit lifetime: 10 minutes (then rebuild)

### Session Lifecycle

```
[NEW] --HANDSHAKE--> [ESTABLISHING] --KEY_CONFIRM--> [ACTIVE]
                                                        |
[EXPIRED] <--TIMEOUT-- [ACTIVE]
```

**States:**
- `NEW`: Session ID assigned, no keys established
- `ESTABLISHING`: X25519 handshake in progress
- `ACTIVE`: Session keys derived, can exchange messages
- `EXPIRED`: Session timeout or explicit close

**Transitions:**
- Handshake completes: `NEW → ESTABLISHING → ACTIVE`
- Timeout (60 minutes): `ACTIVE → EXPIRED`
- Explicit close: `ACTIVE → EXPIRED`

**Invariants:**
- Session keys rotated every 10,000 messages or 60 minutes
- Sessions are independent of circuits (different layers)

### Capability Lifecycle

```
[ISSUED] --USE--> [ACTIVE] --EXPIRE--> [EXPIRED]
           |
       [REVOKED]
```

**States:**
- `ISSUED`: Token created, not yet used
- `ACTIVE`: Token verified and in use
- `EXPIRED`: Token reached expiration timestamp
- `REVOKED`: Token explicitly revoked by issuer

**Transitions:**
- First use: `ISSUED → ACTIVE`
- Natural expiration: `ACTIVE → EXPIRED`
- Explicit revocation: `ACTIVE/ISSUED → REVOKED`

**Invariants:**
- Revoked tokens cannot be un-revoked
- Expired tokens can be reissued with new expiration
- Tokens are bearer credentials (no binding to holder identity)

---

## System Descriptor Schema

Every `.666` service publishes a System Descriptor to the DHT, encrypted such that only capability holders can decrypt it.

**Structure:** See [SYSTEM_DESCRIPTOR.md](SYSTEM_DESCRIPTOR.md)

**Key Fields:**
- Service address (32 bytes)
- Accepted capabilities (list of capability type hashes)
- Input schema (serialization format)
- Output schema (serialization format)
- Resource limits (max message size, timeout)
- Protocol version compatibility

---

## Capability Token Model

Capabilities are unforgeable bearer tokens that grant permission to invoke a service.

**Structure:** See [CAPABILITY_MODEL.md](CAPABILITY_MODEL.md)

**Core Properties:**
- **Unforgeable**: Signed by issuer's identity key
- **Bearer**: Possession is authority (no identity binding)
- **Delegable**: Can be passed to others (permission algebra)
- **Revocable**: Issuer can invalidate at any time
- **Auditable**: Every use is logged by enforcer

---

## Resolution Flow

How a client invokes a service given its `.666` address:

1. **Lookup**: Query DHT for service's System Descriptor
   - `DHT_GET(SHA-256(service_address || "descriptor"))`
   
2. **Verify Capability**: Ensure client holds valid capability token
   - Check signature, expiration, revocation status
   
3. **Build Circuit**: Construct 3-hop onion circuit to service
   - Select relays from DHT peer list
   - Establish X25519 keys with each hop
   - Layer encryption: encrypt payload 3 times (inner → outer)
   
4. **Invoke**: Send INVOKE message through circuit
   - Message includes capability token + encrypted payload
   
5. **Receive Result**: Service responds via same circuit
   - RESULT (success) or ERROR (failure)
   
6. **Destroy Circuit**: After response or timeout
   - Send CIRCUIT_DESTROY to all hops
   - Erase circuit keys

**Timing:**
- DHT lookup: < 500ms (3 hops average)
- Circuit build: < 1s (3 relays)
- Invocation: < 2s (round-trip)
- Total: < 4s end-to-end

---

## Error Codes

All error codes are 16-bit unsigned integers:

| Code   | Name                      | Description |
|--------|---------------------------|-------------|
| 0x0000 | SUCCESS                   | Operation succeeded (not an error) |
| 0x0001 | UNKNOWN_ERROR             | Unspecified failure |
| 0x0010 | INVALID_MESSAGE           | Malformed message structure |
| 0x0011 | UNSUPPORTED_VERSION       | Protocol version mismatch |
| 0x0012 | INVALID_SIGNATURE         | Cryptographic signature verification failed |
| 0x0020 | CIRCUIT_BUILD_FAILED      | Could not establish circuit |
| 0x0021 | CIRCUIT_TIMEOUT           | Circuit took too long to respond |
| 0x0022 | CIRCUIT_DESTROYED         | Circuit was torn down unexpectedly |
| 0x0030 | CAPABILITY_DENIED         | Invalid or missing capability token |
| 0x0031 | CAPABILITY_EXPIRED        | Token past expiration timestamp |
| 0x0032 | CAPABILITY_REVOKED        | Token has been revoked by issuer |
| 0x0040 | DHT_TIMEOUT               | DHT query did not complete in time |
| 0x0041 | DHT_NOT_FOUND             | Key not found in DHT |
| 0x0042 | DHT_STORAGE_FULL          | DHT node cannot accept more data |
| 0x0050 | SERVICE_UNAVAILABLE       | Target service is not reachable |
| 0x0051 | SERVICE_OVERLOADED        | Service rejected due to load |
| 0x0052 | SERVICE_TIMEOUT           | Service did not respond in time |
| 0x0060 | DESCRIPTOR_INVALID        | System descriptor failed validation |
| 0x0061 | DESCRIPTOR_DECRYPTION     | Could not decrypt descriptor (no capability) |

**Handling:**
- Errors 0x0010-0x0012: Log and drop message
- Errors 0x0020-0x0022: Rebuild circuit
- Errors 0x0030-0x0032: Request new capability or abort
- Errors 0x0040-0x0042: Retry with exponential backoff
- Errors 0x0050-0x0052: Retry with different circuit
- Errors 0x0060-0x0061: Request descriptor update

---

## Security Properties

Formal security analysis is in [SECURITY_MODEL.md](SECURITY_MODEL.md). Summary:

### Anonymity Guarantees

1. **Sender Unlinkability**: An observer cannot determine which client initiated a request
   - Achieved via 3-hop onion routing
   - Each relay only knows previous and next hop
   
2. **Receiver Unlinkability**: An observer cannot determine which service handled a request
   - Service address is decoupled from network location
   - DHT lookups are also onion-routed
   
3. **Request Unlinkability**: An observer cannot correlate multiple requests from the same client
   - Circuits are rebuilt every 10 minutes
   - No persistent identifiers in protocol messages

### Forward Secrecy

- Circuit keys are ephemeral X25519 keys (per-circuit)
- Compromise of identity key does NOT decrypt past sessions
- Session keys are erased immediately after circuit destruction

### Capability Soundness

- Services MUST enforce capability checks before execution
- Revocation is eventual (gossip propagation < 30s)
- Capability delegation creates new signed token (audit trail)

### Metadata Protection

**What an observer learns:**
- Timing: When messages are sent (mitigated by constant-rate dummy traffic)
- Size: Message lengths (mitigated by padding to fixed sizes)

**What an observer does NOT learn:**
- Sender identity
- Receiver identity
- Message correlation
- Payload contents

---

## Version Negotiation

### Protocol Versioning

**Format:** `MAJOR.MINOR` (2 bytes in header)
- **MAJOR**: Incompatible changes (e.g., 1.x → 2.x)
- **MINOR**: Backward-compatible additions (e.g., 1.0 → 1.1)

**Current Version:** 1.0

### Negotiation Process

1. Client sends message with its protocol version
2. Server responds with supported version range
3. If overlap exists, use highest common version
4. If no overlap, server returns `UNSUPPORTED_VERSION` error

**Compatibility Rules:**
- Same MAJOR: Must interoperate
- Different MAJOR: May require translation layer or rejection

### Evolution Strategy

- New message types can be added (opcode space is 16-bit)
- New fields can be appended to existing messages (length-prefixed)
- Deprecated features marked in spec, removed after 2 major versions
- Test vectors updated with each version

---

## Cross-References

This specification references the following detailed documents:

1. [CRYPTO_SPEC.md](CRYPTO_SPEC.md) - Cryptographic operations and test vectors
2. [MESSAGE_FORMAT.md](MESSAGE_FORMAT.md) - Binary message layouts
3. [DATA_STRUCTURES.md](DATA_STRUCTURES.md) - Implementation-agnostic data structures
4. [SYSTEM_DESCRIPTOR.md](SYSTEM_DESCRIPTOR.md) - Service descriptor schema
5. [CAPABILITY_MODEL.md](CAPABILITY_MODEL.md) - Capability token specification
6. [ROUTING_SPEC.md](ROUTING_SPEC.md) - Circuit construction and onion routing
7. [DHT_SPEC.md](DHT_SPEC.md) - Distributed hash table protocol
8. [SECURITY_MODEL.md](SECURITY_MODEL.md) - Formal security analysis
9. [AI_INTEGRATION.md](AI_INTEGRATION.md) - AI orchestration interface

---

## Changelog

### Version 1.0.0 (2024-01-14)
- Initial protocol specification
- Defined addressing model (.666 addresses)
- Specified message types and wire format
- Documented cryptographic primitives
- Defined state machines for circuits, sessions, capabilities
- Established error codes and handling
- Formal security properties
- Version negotiation protocol

---

## Compliance

An implementation is **compliant** with this specification if:

1. ✅ All message types are implemented per [MESSAGE_FORMAT.md](MESSAGE_FORMAT.md)
2. ✅ Cryptographic operations match test vectors in [CRYPTO_SPEC.md](CRYPTO_SPEC.md)
3. ✅ Circuits have minimum 3 hops and maximum 8 hops
4. ✅ Capability enforcement is mandatory (no bypass)
5. ✅ Protocol version is 1.0 in header
6. ✅ Error codes match specified values
7. ✅ State machine transitions follow defined rules
8. ✅ All keys are erased after use (forward secrecy)

**Test Suite:** Cross-language test vectors are in `tests/vectors/` (to be created in Phase 1)

---

**End of Protocol Specification v1.0**
