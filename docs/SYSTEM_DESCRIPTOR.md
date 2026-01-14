# System Descriptor Specification v1.0

**Version:** 1.0.0  
**Status:** Normative Specification  
**Last Updated:** 2024-01-14

---

## Overview

A **System Descriptor** is a machine-readable document that describes a `.666` service: what it does, what capabilities it requires, what inputs it accepts, what outputs it produces, and how to invoke it.

Think of it as a contract between service and client—a formal API specification that enables:
1. **Discovery**: Clients can find services by capability
2. **Validation**: Clients can verify they have required capabilities
3. **Type Safety**: Clients know input/output schemas
4. **Resource Planning**: Clients know execution limits

**Design Principles:**
1. **Self-Describing**: Descriptor contains all information needed to invoke service
2. **Versioned**: Descriptors have semantic versions for evolution
3. **Encrypted**: Only capability holders can read descriptors (privacy)
4. **Signed**: Service identity key signs descriptor (authenticity)

---

## Format

System Descriptors are encoded as **JSON** (for human readability) or **CBOR** (for compact binary). Both formats have identical semantics.

### JSON Schema

```json
{
  "version": "1.0",
  "service": {
    "address": "<32-byte .666 address, base32>",
    "public_key": "<32-byte Ed25519 public key, hex>",
    "description": "Human-readable service description",
    "protocol_version": "1.0"
  },
  "capabilities": {
    "required": [
      {
        "type": "operation",
        "operations": ["read", "write"],
        "issuer": "<.666 address of capability issuer, base32>"
      }
    ],
    "optional": [
      {
        "type": "operation",
        "operations": ["delete"],
        "issuer": "<.666 address>"
      }
    ]
  },
  "interface": {
    "invocation_schema": {
      "type": "object",
      "properties": {
        "operation": {"type": "string", "enum": ["read", "write"]},
        "key": {"type": "string"},
        "value": {"type": "string"}
      },
      "required": ["operation", "key"]
    },
    "result_schema": {
      "type": "object",
      "properties": {
        "status": {"type": "string", "enum": ["success", "error"]},
        "data": {"type": "string"}
      },
      "required": ["status"]
    },
    "serialization": "json"
  },
  "limits": {
    "max_invocation_size": 65536,
    "max_result_size": 65536,
    "timeout_ms": 5000,
    "rate_limit": {
      "requests_per_minute": 100,
      "burst": 10
    }
  },
  "metadata": {
    "published_at": 1704380000000,
    "expires_at": 1735916000000,
    "tags": ["database", "key-value", "distributed"],
    "contact": "maintainer@example.666"
  },
  "signature": "<64-byte Ed25519 signature, hex>"
}
```

---

## Field Definitions

### 1. `version` (string, required)

**Descriptor schema version** (not service version).

- Format: `"MAJOR.MINOR"`
- Current: `"1.0"`
- Backward compatibility: Same MAJOR version must be compatible

### 2. `service` (object, required)

**Service identity and metadata.**

#### 2.1 `address` (string, required)

- Service's `.666` address (base32 encoded)
- Length: 52 characters
- Example: `"7MZUWAU2FJVXQ2KQN5DXA5I4PA4WCLV7GMYDENBWGA3DOOJGQ7LA"`

#### 2.2 `public_key` (string, required)

- Service's Ed25519 identity public key (hex)
- Length: 64 hex characters (32 bytes)
- Used to verify descriptor signature
- Must derive to `address` via: `SHA-256(public_key || "666:service:v1")`

#### 2.3 `description` (string, optional)

- Human-readable description (UTF-8)
- Max length: 1024 characters
- Example: `"Distributed key-value store with eventual consistency"`

#### 2.4 `protocol_version` (string, required)

- Project 666 protocol version service implements
- Format: `"MAJOR.MINOR"`
- Current: `"1.0"`

---

### 3. `capabilities` (object, required)

**Capabilities required to invoke service.**

#### 3.1 `required` (array, required)

List of capabilities client MUST possess to invoke service.

**Capability Object:**
```json
{
  "type": "operation",
  "operations": ["read", "write"],
  "issuer": "<.666 address of issuer>"
}
```

**Fields:**
- `type` (string): Capability type (`"operation"`, `"resource"`, `"role"`)
- `operations` (array of strings): Specific operations allowed
- `issuer` (string): `.666` address of capability issuer
- `constraints` (object, optional): Additional constraints

**Capability Types:**

1. **Operation**: Permission to perform specific actions
   - Example: `{"type": "operation", "operations": ["read", "write"]}`

2. **Resource**: Access to specific resources
   - Example: `{"type": "resource", "resources": ["/data/users/*"]}`

3. **Role**: Membership in a role
   - Example: `{"type": "role", "roles": ["admin", "moderator"]}`

#### 3.2 `optional` (array, optional)

List of capabilities that enable additional features.

Same structure as `required`, but service operates without them (with reduced functionality).

---

### 4. `interface` (object, required)

**Service API specification.**

#### 4.1 `invocation_schema` (object, required)

**JSON Schema** defining valid invocation payloads.

**Example (Key-Value Store):**
```json
{
  "type": "object",
  "properties": {
    "operation": {
      "type": "string",
      "enum": ["get", "put", "delete"]
    },
    "key": {
      "type": "string",
      "minLength": 1,
      "maxLength": 256
    },
    "value": {
      "type": "string",
      "maxLength": 65536
    }
  },
  "required": ["operation", "key"],
  "if": {
    "properties": {"operation": {"const": "put"}}
  },
  "then": {
    "required": ["value"]
  }
}
```

**Validation:**
- Client MUST validate invocation against schema before sending
- Service MAY reject invalid invocations with error code `0x0010`

#### 4.2 `result_schema` (object, required)

**JSON Schema** defining service result structure.

**Example:**
```json
{
  "type": "object",
  "properties": {
    "status": {
      "type": "string",
      "enum": ["success", "error"]
    },
    "data": {
      "type": "string"
    },
    "error_code": {
      "type": "integer"
    },
    "error_message": {
      "type": "string"
    }
  },
  "required": ["status"]
}
```

#### 4.3 `serialization` (string, required)

**Serialization format** for payloads and results.

**Options:**
- `"json"`: JSON (UTF-8 encoded)
- `"cbor"`: CBOR (binary)
- `"msgpack"`: MessagePack (binary)
- `"protobuf"`: Protocol Buffers (requires `.proto` schema)

**Recommendation:** Use `"cbor"` for binary efficiency, `"json"` for debugging.

#### 4.4 `encoding` (string, optional)

**Character encoding** (if using text serialization).

- Default: `"utf-8"`
- Options: `"utf-8"`, `"ascii"`, `"latin-1"`

---

### 5. `limits` (object, required)

**Resource limits and execution constraints.**

#### 5.1 `max_invocation_size` (integer, required)

- Maximum size of invocation payload (bytes)
- Range: 1 to 65536 (64 KB)
- Example: `65536`

#### 5.2 `max_result_size` (integer, required)

- Maximum size of result data (bytes)
- Range: 1 to 65536 (64 KB)
- Example: `65536`

#### 5.3 `timeout_ms` (integer, required)

- Maximum execution time (milliseconds)
- Range: 100 to 60000 (1 minute)
- Example: `5000` (5 seconds)

#### 5.4 `rate_limit` (object, optional)

**Rate limiting configuration.**

```json
{
  "requests_per_minute": 100,
  "burst": 10,
  "per_capability": true
}
```

**Fields:**
- `requests_per_minute` (integer): Sustained rate
- `burst` (integer): Burst allowance
- `per_capability` (boolean): Limit per capability token (true) or per service (false)

---

### 6. `metadata` (object, optional)

**Additional metadata.**

#### 6.1 `published_at` (integer, required)

- Unix timestamp (milliseconds) when descriptor was published
- Example: `1704380000000` (Jan 4, 2024)

#### 6.2 `expires_at` (integer, optional)

- Unix timestamp when descriptor expires
- After expiration, clients should request updated descriptor
- Example: `1735916000000` (Jan 3, 2025)

#### 6.3 `tags` (array of strings, optional)

- Keywords for discovery
- Max 10 tags, each max 32 characters
- Example: `["database", "key-value", "distributed"]`

#### 6.4 `contact` (string, optional)

- Contact information for service maintainer
- Example: `"maintainer@example.666"` or `"https://example.com"`

#### 6.5 `version_history` (array, optional)

- Previous descriptor versions (for changelog)
- Example: `[{"version": "0.9", "published_at": 1700000000000}]`

---

### 7. `signature` (string, required)

**Ed25519 signature** over entire descriptor (excluding `signature` field itself).

**Signing Process:**
1. Set `signature` field to empty string `""`
2. Canonicalize JSON (sorted keys, no whitespace)
3. Compute: `signature = Ed25519.sign(service_private_key, canonical_json)`
4. Encode signature as hex (128 characters)
5. Insert signature into descriptor

**Verification Process:**
1. Extract `signature` field and `public_key` field
2. Set `signature` to `""`
3. Canonicalize JSON
4. Verify: `Ed25519.verify(public_key, canonical_json, signature)`
5. Verify: `SHA-256(public_key || "666:service:v1") == address`

---

## Encryption

Descriptors are **encrypted** when stored in DHT to protect service privacy. Only capability holders can decrypt.

### Encryption Process

**Key Derivation:**
```
descriptor_key = HKDF-SHA256(
    ikm=service_identity_private_key,
    salt="666:descriptor:v1",
    info=service_address,
    length=32
)
```

**Encryption:**
```
nonce = random(12)  # Random 12-byte nonce
plaintext = canonical_json(descriptor)
(ciphertext, tag) = ChaCha20Poly1305.encrypt(
    key=descriptor_key,
    nonce=nonce,
    plaintext=plaintext,
    aad=service_address
)
encrypted_descriptor = nonce || ciphertext || tag
```

**Storage in DHT:**
```
dht_key = SHA-256(service_address || "descriptor")
dht_value = encrypted_descriptor
DHT_PUT(dht_key, dht_value, ttl=86400)  # 24 hours
```

### Decryption Process

**Prerequisites:**
- Client has valid capability token for service
- Client can derive `descriptor_key` from capability (issuer provides it)

**Decryption:**
```
nonce = encrypted_descriptor[0..11]
ciphertext = encrypted_descriptor[12..-17]
tag = encrypted_descriptor[-16..-1]

plaintext = ChaCha20Poly1305.decrypt(
    key=descriptor_key,
    nonce=nonce,
    ciphertext=ciphertext,
    tag=tag,
    aad=service_address
)

descriptor = parse_json(plaintext)
verify_signature(descriptor)
```

---

## Validation Rules

A descriptor is **valid** if:

1. ✅ `version` is `"1.0"`
2. ✅ `service.address` is valid base32 (52 chars)
3. ✅ `service.public_key` is valid hex (64 chars)
4. ✅ `service.address == SHA-256(decode_hex(public_key) || "666:service:v1")`
5. ✅ `service.protocol_version` is `"1.0"`
6. ✅ `capabilities.required` is non-empty array
7. ✅ `interface.invocation_schema` is valid JSON Schema
8. ✅ `interface.result_schema` is valid JSON Schema
9. ✅ `interface.serialization` is supported format
10. ✅ `limits.max_invocation_size` in range [1, 65536]
11. ✅ `limits.max_result_size` in range [1, 65536]
12. ✅ `limits.timeout_ms` in range [100, 60000]
13. ✅ `metadata.published_at` is valid Unix timestamp
14. ✅ `signature` is valid Ed25519 signature

**On Invalid Descriptor:**
- Client MUST NOT invoke service
- Client SHOULD log validation error
- Client MAY request updated descriptor

---

## Example Descriptors

### Example 1: Key-Value Store

```json
{
  "version": "1.0",
  "service": {
    "address": "7MZUWAU2FJVXQ2KQN5DXA5I4PA4WCLV7GMYDENBWGA3DOOJGQ7LA",
    "public_key": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    "description": "Distributed key-value store",
    "protocol_version": "1.0"
  },
  "capabilities": {
    "required": [
      {
        "type": "operation",
        "operations": ["read", "write"],
        "issuer": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      }
    ],
    "optional": []
  },
  "interface": {
    "invocation_schema": {
      "type": "object",
      "properties": {
        "operation": {"type": "string", "enum": ["get", "put"]},
        "key": {"type": "string"},
        "value": {"type": "string"}
      },
      "required": ["operation", "key"]
    },
    "result_schema": {
      "type": "object",
      "properties": {
        "status": {"type": "string"},
        "data": {"type": "string"}
      },
      "required": ["status"]
    },
    "serialization": "json"
  },
  "limits": {
    "max_invocation_size": 8192,
    "max_result_size": 8192,
    "timeout_ms": 2000,
    "rate_limit": {
      "requests_per_minute": 1000,
      "burst": 50
    }
  },
  "metadata": {
    "published_at": 1704380000000,
    "expires_at": 1735916000000,
    "tags": ["database", "key-value"]
  },
  "signature": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

### Example 2: Computation Service

```json
{
  "version": "1.0",
  "service": {
    "address": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    "public_key": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    "description": "Secure computation service (homomorphic encryption)",
    "protocol_version": "1.0"
  },
  "capabilities": {
    "required": [
      {
        "type": "operation",
        "operations": ["compute"],
        "issuer": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
      }
    ],
    "optional": [
      {
        "type": "operation",
        "operations": ["batch_compute"],
        "issuer": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
      }
    ]
  },
  "interface": {
    "invocation_schema": {
      "type": "object",
      "properties": {
        "operation": {"type": "string", "enum": ["add", "multiply"]},
        "operands": {
          "type": "array",
          "items": {"type": "number"},
          "minItems": 2,
          "maxItems": 10
        }
      },
      "required": ["operation", "operands"]
    },
    "result_schema": {
      "type": "object",
      "properties": {
        "result": {"type": "number"}
      },
      "required": ["result"]
    },
    "serialization": "cbor"
  },
  "limits": {
    "max_invocation_size": 4096,
    "max_result_size": 1024,
    "timeout_ms": 10000,
    "rate_limit": {
      "requests_per_minute": 60,
      "burst": 5
    }
  },
  "metadata": {
    "published_at": 1704380000000,
    "tags": ["computation", "privacy-preserving"]
  },
  "signature": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
}
```

---

## Lifecycle

### 1. Publication

Service operator:
1. Creates descriptor JSON
2. Signs with identity private key
3. Encrypts descriptor
4. Publishes to DHT: `DHT_PUT(SHA-256(address || "descriptor"), encrypted_descriptor)`

### 2. Discovery

Client:
1. Receives `.666` address and capability token
2. Queries DHT: `DHT_GET(SHA-256(address || "descriptor"))`
3. Decrypts descriptor using key from capability
4. Validates signature and schema
5. Checks that it possesses required capabilities

### 3. Invocation

Client:
1. Validates invocation payload against `invocation_schema`
2. Serializes using specified `serialization` format
3. Sends INVOKE message through circuit
4. Waits for RESULT (within `timeout_ms`)
5. Validates result against `result_schema`

### 4. Update

Service operator:
1. Creates new descriptor version
2. Increments version number in `metadata.version_history`
3. Publishes to DHT (overwrites old version)
4. Clients automatically fetch new version when old expires

### 5. Revocation

Service operator:
1. Sets `expires_at` to past timestamp
2. Publishes update to DHT
3. Clients will request new descriptor on next invocation
4. Old descriptor becomes invalid

---

## Implementation Checklist

For compliance:

- ✅ Parse JSON and CBOR descriptors
- ✅ Validate all required fields
- ✅ Verify signature against public key
- ✅ Verify address derivation from public key
- ✅ Validate invocation payloads against JSON Schema
- ✅ Validate results against JSON Schema
- ✅ Support JSON and CBOR serialization
- ✅ Enforce size limits (invocation, result)
- ✅ Enforce timeout
- ✅ Enforce rate limits (if specified)
- ✅ Handle descriptor expiration
- ✅ Encrypt/decrypt descriptors for DHT storage

---

## Cross-References

- [PROTOCOL_SPEC.md](PROTOCOL_SPEC.md) - Addressing and message flow
- [MESSAGE_FORMAT.md](MESSAGE_FORMAT.md) - INVOKE and RESULT messages
- [CAPABILITY_MODEL.md](CAPABILITY_MODEL.md) - Capability token structure
- [DHT_SPEC.md](DHT_SPEC.md) - Descriptor storage and retrieval

---

## Changelog

### Version 1.0.0 (2024-01-14)
- Initial system descriptor specification
- Defined JSON schema with all required fields
- Specified encryption and signature processes
- Added example descriptors and validation rules

---

**End of System Descriptor Specification v1.0**
