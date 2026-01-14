# Capability Model Specification v1.0

**Version:** 1.0.0  
**Status:** Normative Specification  
**Last Updated:** 2024-01-14

---

## Overview

Project 666 uses **object-capability security**: possession of an unforgeable token grants authority to perform operations. This model provides:

1. **Least Privilege**: Capabilities grant minimal necessary permissions
2. **Delegation**: Capabilities can be passed to others
3. **Revocation**: Issuers can invalidate capabilities
4. **Auditability**: All capability use is logged
5. **Composability**: Capabilities can be combined (permission algebra)

**Core Principle:** "If you have it, you can use it."

---

## Capability Token Structure

A capability token is a signed data structure containing:

```
CapabilityToken {
    issuer_address: bytes[32],        # .666 address of issuer
    holder_identity: bytes[32] | null, # Holder's public key (null = bearer)
    permissions: PermissionSet,        # What operations are allowed
    constraints: Constraints,          # Additional restrictions
    issued_at: uint64,                 # Unix timestamp (ms)
    expires_at: uint64,                # Unix timestamp (ms)
    revocation_nonce: uint32,          # Revocation counter
    parent_hash: bytes[32] | null,     # Hash of parent capability (for delegation)
    signature: bytes[64]               # Ed25519 signature
}
```

### Binary Format

```
Offset | Size | Field              | Description
-------|------|--------------------|-----------------------------------------
0      | 32   | IssuerAddress      | Issuer's .666 address
32     | 32   | HolderIdentity     | Holder's Ed25519 public key (or 0 for bearer)
64     | 4    | PermissionsLength  | Length of permissions field
68     | P    | Permissions        | Permission set (JSON or binary)
68+P   | 4    | ConstraintsLength  | Length of constraints field
72+P   | C    | Constraints        | Constraints (JSON or binary)
72+P+C | 8    | IssuedAt           | Unix timestamp (milliseconds)
80+P+C | 8    | ExpiresAt          | Unix timestamp (milliseconds)
88+P+C | 4    | RevocationNonce    | Revocation counter (increment to revoke)
92+P+C | 32   | ParentHash         | SHA-256 of parent capability (or 0)
124+P+C| 64   | IssuerSignature    | Ed25519 signature over all above fields
```

**Total Size:** 188 + P + C bytes

---

## Permission Set

Permissions are structured as **operations on resources**.

### JSON Format

```json
{
  "service": "7MZUWAU2FJVXQ2KQN5DXA5I4PA4WCLV7GMYDENBWGA3DOOJGQ7LA",
  "operations": ["read", "write"],
  "resources": [
    "/data/users/*",
    "/data/sessions/*"
  ],
  "max_invocations": 1000,
  "rate_limit": 100
}
```

### Fields

#### 1. `service` (string, required)

- `.666` address of the service this capability grants access to
- Format: Base32 (52 characters)

#### 2. `operations` (array of strings, required)

- List of allowed operations
- Service-specific (defined in System Descriptor)
- Examples: `["read", "write", "delete", "execute"]`

#### 3. `resources` (array of strings, optional)

- Resource paths or patterns (glob-style)
- Empty array = all resources
- Examples:
  - `["/data/users/alice"]` - Specific resource
  - `["/data/users/*"]` - All users
  - `["/data/**"]` - Everything under /data

#### 4. `max_invocations` (integer, optional)

- Maximum number of times capability can be used
- `null` or `0` = unlimited
- Example: `1000`

#### 5. `rate_limit` (integer, optional)

- Maximum invocations per minute
- `null` or `0` = no limit
- Example: `100`

---

## Constraints

Additional restrictions on capability use.

### JSON Format

```json
{
  "ip_whitelist": ["192.168.1.0/24"],
  "time_window": {
    "start": 1704380000000,
    "end": 1704466400000
  },
  "delegation_depth": 2,
  "required_context": {
    "user_agent": "Project666Client/1.0"
  }
}
```

### Fields

#### 1. `ip_whitelist` (array of strings, optional)

- CIDR ranges from which capability can be used
- Empty = any IP
- Example: `["192.168.1.0/24", "10.0.0.0/8"]`

#### 2. `time_window` (object, optional)

- Time range during which capability is valid
- `start` and `end` are Unix timestamps (ms)
- Example: `{"start": 1704380000000, "end": 1704466400000}`

#### 3. `delegation_depth` (integer, optional)

- How many times capability can be delegated
- `0` = cannot delegate
- `null` = unlimited delegation
- Example: `2`

#### 4. `required_context` (object, optional)

- Key-value pairs that must be present in invocation context
- Example: `{"user_agent": "Project666Client/1.0"}`

---

## Issuance

### Process

1. **Issuer decides** what permissions to grant
2. **Issuer creates** capability token with:
   - Holder identity (or null for bearer)
   - Permission set
   - Constraints
   - Expiration time
   - Revocation nonce (initial value: 1)
3. **Issuer signs** token with identity private key
4. **Issuer sends** token to holder (through secure channel)

### Signature Computation

```pseudocode
function sign_capability(capability, issuer_private_key):
    # Canonical encoding (deterministic)
    data = encode_canonical(
        capability.issuer_address,
        capability.holder_identity,
        capability.permissions,
        capability.constraints,
        capability.issued_at,
        capability.expires_at,
        capability.revocation_nonce,
        capability.parent_hash
    )
    
    signature = Ed25519.sign(issuer_private_key, data)
    capability.signature = signature
    return capability
```

### Example (Pseudocode)

```pseudocode
# Issuer creates capability for holder
issuer_address = "7MZUWAU2FJVXQ2KQN5DXA5I4PA4WCLV7..."
holder_public_key = "a1b2c3d4e5f6..." # Holder's Ed25519 key

capability = CapabilityToken {
    issuer_address: issuer_address,
    holder_identity: holder_public_key,
    permissions: {
        service: "7MZUWAU2FJVXQ2...",
        operations: ["read", "write"],
        resources: ["/data/users/*"],
        max_invocations: 1000,
        rate_limit: 100
    },
    constraints: {
        delegation_depth: 1
    },
    issued_at: now(),
    expires_at: now() + 30_days,
    revocation_nonce: 1,
    parent_hash: null,  # Root capability
    signature: <computed>
}

capability = sign_capability(capability, issuer_private_key)
send_to_holder(capability)
```

---

## Verification

Services MUST verify capabilities before executing operations.

### Process

1. **Extract** capability token from INVOKE message
2. **Check expiration**: `now() < expires_at`
3. **Check revocation**: Query revocation nonce from issuer
4. **Verify signature**: Ed25519.verify(issuer_public_key, data, signature)
5. **Verify issuer**: Check that issuer is authorized to grant this permission
6. **Check permissions**: Requested operation is in `operations` list
7. **Check resources**: Requested resource matches pattern
8. **Check constraints**: All constraints satisfied
9. **Update usage counter**: Decrement `max_invocations` if present

### Pseudocode

```pseudocode
function verify_capability(capability, invocation):
    # 1. Check expiration
    if now() >= capability.expires_at:
        return ERROR_CAPABILITY_EXPIRED
    
    # 2. Check revocation
    current_nonce = get_revocation_nonce(capability.issuer_address, capability_hash)
    if current_nonce != capability.revocation_nonce:
        return ERROR_CAPABILITY_REVOKED
    
    # 3. Verify signature
    issuer_public_key = get_public_key(capability.issuer_address)
    data = encode_canonical(...)
    if not Ed25519.verify(issuer_public_key, data, capability.signature):
        return ERROR_INVALID_SIGNATURE
    
    # 4. Check permissions
    if invocation.operation not in capability.permissions.operations:
        return ERROR_PERMISSION_DENIED
    
    # 5. Check resource access
    if not match_pattern(invocation.resource, capability.permissions.resources):
        return ERROR_RESOURCE_DENIED
    
    # 6. Check constraints
    if not verify_constraints(capability.constraints, invocation.context):
        return ERROR_CONSTRAINT_VIOLATED
    
    # 7. Check usage limit
    usage_count = get_usage_count(capability_hash)
    if capability.permissions.max_invocations > 0:
        if usage_count >= capability.permissions.max_invocations:
            return ERROR_USAGE_LIMIT_EXCEEDED
    
    # 8. Check rate limit
    if capability.permissions.rate_limit > 0:
        if get_rate(capability_hash) > capability.permissions.rate_limit:
            return ERROR_RATE_LIMIT_EXCEEDED
    
    # All checks passed
    increment_usage_count(capability_hash)
    return SUCCESS
```

### Revocation Check

**Centralized (Simple):**
- Query issuer: `CAPABILITY_VERIFY(capability_token)`
- Issuer responds with current revocation nonce
- If nonce mismatches, capability is revoked

**Decentralized (Scalable):**
- Issuer publishes revocation list to DHT
- Key: `SHA-256(issuer_address || "revocations")`
- Value: List of revoked capability hashes
- Clients cache revocation list (refresh every 5 minutes)

---

## Delegation

Holders can create **derived capabilities** with reduced permissions.

### Process

1. **Holder** receives capability from issuer
2. **Holder** creates new capability with:
   - Same issuer
   - New holder (delegate)
   - **Subset** of permissions
   - Stricter constraints
   - Same or earlier expiration
   - `parent_hash` = SHA-256(parent_capability)
3. **Holder** signs with holder's private key (NOT issuer's key)
4. **Holder** sends derived capability to delegate

### Permission Attenuation

Derived capabilities MUST have **equal or fewer** permissions:

- ✅ Reduce operations: `["read", "write"]` → `["read"]`
- ✅ Restrict resources: `["/data/*"]` → `["/data/users/*"]`
- ✅ Lower max_invocations: `1000` → `100`
- ✅ Lower rate_limit: `100` → `10`
- ✅ Earlier expiration: 30 days → 7 days
- ✅ Add constraints: no constraints → IP whitelist
- ❌ Add operations: `["read"]` → `["read", "write"]` (INVALID)
- ❌ Expand resources: `["/data/users/*"]` → `["/data/*"]` (INVALID)

### Verification of Delegated Capabilities

Services MUST verify **entire delegation chain**:

1. Verify current capability signature (signed by holder)
2. Retrieve parent capability via `parent_hash`
3. Verify parent capability (signed by previous holder or issuer)
4. Check that permissions were properly attenuated
5. Repeat until reaching root capability (signed by issuer)

### Example

```pseudocode
# Alice receives root capability from Issuer
root_capability = {
    issuer: "ISSUER_ADDRESS",
    holder: alice_public_key,
    permissions: {
        operations: ["read", "write"],
        resources: ["/data/*"]
    },
    expires_at: now() + 30_days,
    parent_hash: null,
    signature: <issuer_signature>
}

# Alice delegates to Bob (reduced permissions)
derived_capability = {
    issuer: "ISSUER_ADDRESS",  # Same issuer
    holder: bob_public_key,     # New holder
    permissions: {
        operations: ["read"],    # Subset
        resources: ["/data/users/*"]  # More specific
    },
    expires_at: now() + 7_days,  # Earlier expiration
    parent_hash: SHA-256(root_capability),
    signature: <alice_signature>  # Alice signs, not Issuer
}

# Service verifies:
# 1. Verify derived_capability signature with Alice's key
# 2. Retrieve root_capability via parent_hash
# 3. Verify root_capability signature with Issuer's key
# 4. Check permissions were attenuated (read ⊆ [read, write], /data/users/* ⊂ /data/*)
# 5. Accept if all checks pass
```

---

## Revocation

Issuers can invalidate capabilities.

### Methods

#### 1. **Explicit Revocation** (Immediate)

- Issuer increments revocation nonce
- Publishes new nonce to DHT or revocation service
- All capabilities with old nonce become invalid
- Propagation time: < 30 seconds

**Process:**
```pseudocode
function revoke_capability(issuer, capability_hash):
    current_nonce = get_current_nonce(issuer, capability_hash)
    new_nonce = current_nonce + 1
    set_nonce(issuer, capability_hash, new_nonce)
    publish_to_dht(SHA-256(issuer || "revocations"), [capability_hash])
```

#### 2. **Expiration** (Automatic)

- Capability includes `expires_at` timestamp
- After expiration, verification fails automatically
- No action required from issuer

#### 3. **Reissue with New Nonce** (Rotation)

- Issuer creates new capability with incremented nonce
- Old capability becomes invalid
- Holder receives new capability

### Revocation Propagation

**DHT-Based:**
```
Key: SHA-256(issuer_address || "revocations")
Value: {
    nonce: 42,
    revoked_hashes: [
        "abcd1234...",
        "ef567890..."
    ],
    timestamp: 1704380000000
}
```

**Gossip-Based:**
- Revocation messages gossiped through network
- Each node maintains revocation cache
- TTL: 24 hours

---

## Permission Algebra

Capabilities can be **combined** (if issued by same issuer).

### Union (OR)

Holder with two capabilities can use **either**:

```
cap1: operations=["read"], resources=["/data/users/*"]
cap2: operations=["write"], resources=["/data/sessions/*"]

Combined: operations=["read", "write"], resources=["/data/users/*", "/data/sessions/*"]
```

**Implementation:** Holder presents both capabilities in INVOKE message.

### Intersection (AND)

Service requires **multiple** capabilities:

```
required_caps = [
    {operations: ["read"]},
    {operations: ["admin"]}
]
```

Holder must present both to invoke.

### Attenuation (Reduction)

Create derived capability with fewer permissions (delegation).

---

## Audit Trail

All capability use MUST be logged.

### Log Entry Format

```json
{
  "timestamp": 1704380000000,
  "capability_hash": "abcd1234...",
  "issuer": "ISSUER_ADDRESS",
  "holder": "HOLDER_PUBKEY",
  "service": "SERVICE_ADDRESS",
  "operation": "read",
  "resource": "/data/users/alice",
  "result": "success",
  "circuit_id": "0x12345678"
}
```

### Log Storage

- **Local**: Each service logs capability use
- **Distributed**: Logs replicated to audit nodes
- **Encrypted**: Log entries encrypted, only auditors can decrypt

### Audit Queries

Auditors can query:
- "All uses of capability X"
- "All operations by holder Y"
- "All denied operations on resource Z"

---

## Security Properties

### 1. Unforgeable

- Capabilities are signed by issuer
- Cannot be created without issuer's private key
- Signature verification prevents forgery

### 2. Unfalsifiable

- Permissions are cryptographically bound to signature
- Cannot modify permissions without invalidating signature

### 3. Delegable

- Holders can create derived capabilities
- Permission attenuation enforced by services
- Delegation chain is verifiable

### 4. Revocable

- Issuer can invalidate capabilities
- Revocation propagates via DHT/gossip
- Eventual consistency (< 30 seconds)

### 5. Auditable

- All uses logged
- Logs are tamper-evident (Merkle trees)
- Auditors can verify compliance

---

## Implementation Checklist

For compliance:

- ✅ Parse capability token binary format
- ✅ Verify Ed25519 signatures
- ✅ Check expiration timestamps
- ✅ Query revocation nonces
- ✅ Validate permissions (operations, resources)
- ✅ Enforce constraints (IP, time window, delegation depth)
- ✅ Track usage counters and rate limits
- ✅ Support delegation (verify chain)
- ✅ Support permission attenuation
- ✅ Log all capability uses
- ✅ Publish revocations to DHT

---

## Test Scenarios

### 1. Basic Issuance and Verification

- Issuer creates capability
- Holder uses capability to invoke service
- Service verifies and executes

### 2. Expiration

- Issuer creates capability with short expiration (1 minute)
- Wait 2 minutes
- Holder attempts invocation (should fail: EXPIRED)

### 3. Revocation

- Issuer creates capability
- Holder uses it successfully
- Issuer revokes capability
- Holder attempts invocation (should fail: REVOKED)

### 4. Delegation

- Issuer grants capability to Alice (read + write)
- Alice delegates to Bob (read only)
- Bob invokes with read (should succeed)
- Bob attempts write (should fail: PERMISSION_DENIED)

### 5. Delegation Chain Verification

- Issuer → Alice → Bob → Charlie (3-level delegation)
- Charlie invokes service
- Service verifies entire chain (should succeed)

### 6. Invalid Delegation (Privilege Escalation)

- Alice receives capability (read only)
- Alice attempts to create derived capability with write
- Service rejects (permission attenuation violated)

### 7. Usage Limit

- Issuer creates capability with max_invocations=10
- Holder invokes 10 times (all succeed)
- Holder attempts 11th invocation (should fail: USAGE_LIMIT)

### 8. Rate Limit

- Issuer creates capability with rate_limit=10/min
- Holder invokes 15 times in 1 minute
- First 10 succeed, next 5 fail (RATE_LIMIT)

---

## Cross-References

- [PROTOCOL_SPEC.md](PROTOCOL_SPEC.md) - Capability token in protocol flow
- [MESSAGE_FORMAT.md](MESSAGE_FORMAT.md) - CAPABILITY_* messages
- [SYSTEM_DESCRIPTOR.md](SYSTEM_DESCRIPTOR.md) - Required capabilities
- [SECURITY_MODEL.md](SECURITY_MODEL.md) - Security analysis

---

## Changelog

### Version 1.0.0 (2024-01-14)
- Initial capability model specification
- Defined token structure and binary format
- Specified issuance, verification, delegation, revocation
- Added permission algebra and audit trail

---

**End of Capability Model Specification v1.0**
