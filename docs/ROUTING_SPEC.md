# Routing and Circuit Construction Specification v1.0

**Version:** 1.0.0  
**Status:** Normative Specification  
**Last Updated:** 2024-01-14

---

## Overview

Project 666 uses **onion routing** (similar to Tor) to provide anonymity: messages are routed through multiple intermediate relays, with each relay only knowing the previous and next hop.

**Goals:**
1. **Sender Anonymity**: Destination cannot determine sender
2. **Receiver Anonymity**: Intermediate relays don't know final destination
3. **Unlinkability**: Observers cannot correlate requests
4. **Forward Secrecy**: Compromise of keys doesn't decrypt past sessions

**Design:** 3-hop circuits with layered encryption (onion encryption).

---

## Circuit Architecture

### Components

1. **Client (Origin)**: Initiates circuit and sends requests
2. **Guard Relay (Entry)**: First hop, knows client but not destination
3. **Middle Relay**: Second hop, knows neither client nor destination
4. **Exit Relay**: Third hop, knows destination but not client
5. **Destination (Service)**: Receives request, doesn't know client

```
Client → Guard → Middle → Exit → Service
```

### Anonymity Properties

- **Guard** sees: Client identity, but not destination
- **Middle** sees: Guard and Exit, but not client or destination
- **Exit** sees: Destination, but not client
- **Service** sees: Exit relay, but not client
- **Observer** sees: Encrypted traffic between nodes

---

## Circuit Construction

### Phase 1: Relay Selection

**Selection Criteria:**
1. **Diversity**: Relays in different /16 subnets
2. **Stability**: Uptime > 99% over last 7 days
3. **Bandwidth**: Available bandwidth > 10 Mbps
4. **Reputation**: No recent failures or timeout events

**Selection Algorithm:**
```pseudocode
function select_circuit_path():
    # Query DHT for available relays
    all_relays = dht_query("relay_directory")
    
    # Filter by criteria
    eligible_relays = filter(all_relays, lambda r:
        r.uptime > 0.99 and
        r.bandwidth > 10_000_000 and
        r.reputation_score > 0.8
    )
    
    # Select guard (weighted by bandwidth)
    guard = weighted_random(eligible_relays, key=lambda r: r.bandwidth)
    
    # Select middle (different subnet, not guard)
    middle = weighted_random(
        filter(eligible_relays, lambda r:
            r.subnet != guard.subnet and r.id != guard.id
        ),
        key=lambda r: r.bandwidth
    )
    
    # Select exit (different subnet, not guard or middle)
    exit = weighted_random(
        filter(eligible_relays, lambda r:
            r.subnet != guard.subnet and
            r.subnet != middle.subnet and
            r.id != guard.id and
            r.id != middle.id
        ),
        key=lambda r: r.bandwidth
    )
    
    return [guard, middle, exit]
```

### Phase 2: Key Exchange

**Per-Hop Key Derivation:**

1. **Client ↔ Guard:**
   ```
   client_sk_guard, client_pk_guard = X25519.keygen()
   # Client sends CIRCUIT_CREATE with client_pk_guard
   # Guard responds with relay_pk_guard
   shared_secret_guard = X25519(client_sk_guard, relay_pk_guard)
   keys_guard = HKDF(shared_secret_guard, "666:circuit:hop1:v1", 64)
   key_forward_guard = keys_guard[0..31]
   key_backward_guard = keys_guard[32..63]
   ```

2. **Client ↔ Middle (via Guard):**
   ```
   client_sk_middle, client_pk_middle = X25519.keygen()
   # Client sends CIRCUIT_EXTEND (encrypted with key_forward_guard)
   # Middle responds with relay_pk_middle (via Guard)
   shared_secret_middle = X25519(client_sk_middle, relay_pk_middle)
   keys_middle = HKDF(shared_secret_middle, "666:circuit:hop2:v1", 64)
   key_forward_middle = keys_middle[0..31]
   key_backward_middle = keys_middle[32..63]
   ```

3. **Client ↔ Exit (via Guard and Middle):**
   ```
   client_sk_exit, client_pk_exit = X25519.keygen()
   # Client sends CIRCUIT_EXTEND (double-encrypted)
   # Exit responds with relay_pk_exit
   shared_secret_exit = X25519(client_sk_exit, relay_pk_exit)
   keys_exit = HKDF(shared_secret_exit, "666:circuit:hop3:v1", 64)
   key_forward_exit = keys_exit[0..31]
   key_backward_exit = keys_exit[32..63]
   ```

**Result:** Client has 3 pairs of keys (6 keys total):
- `(key_forward_guard, key_backward_guard)`
- `(key_forward_middle, key_backward_middle)`
- `(key_forward_exit, key_backward_exit)`

### Phase 3: Circuit Establishment

**Step-by-Step:**

```pseudocode
function build_circuit(client):
    # 1. Select relays
    path = select_circuit_path()  # [guard, middle, exit]
    circuit_id = random_uint32()
    
    # 2. Establish first hop (guard)
    client_sk_1, client_pk_1 = X25519.keygen()
    message = CIRCUIT_CREATE {
        circuit_id: circuit_id,
        client_public_key: client_pk_1,
        handshake_data: random(32),
        timestamp: now()
    }
    send(path[0].address, message)
    
    response = receive(timeout=2000)
    if response.type != CIRCUIT_CREATED:
        return ERROR
    
    relay_pk_1 = response.relay_public_key
    shared_1 = X25519(client_sk_1, relay_pk_1)
    keys_1 = HKDF(shared_1, "666:circuit:hop1:v1", 64)
    
    # 3. Extend to middle relay
    client_sk_2, client_pk_2 = X25519.keygen()
    plaintext = encode(path[1].address || client_pk_2 || random(32))
    
    # Encrypt with guard key
    encrypted = ChaCha20Poly1305.encrypt(
        keys_1[0..31],  # key_forward_guard
        nonce_1,
        plaintext,
        aad=circuit_id
    )
    
    message = CIRCUIT_EXTEND {
        circuit_id: circuit_id,
        encrypted_payload: encrypted
    }
    send(path[0].address, message)
    
    response = receive(timeout=2000)
    if response.type != CIRCUIT_EXTENDED:
        return ERROR
    
    # Decrypt response
    decrypted = ChaCha20Poly1305.decrypt(
        keys_1[32..63],  # key_backward_guard
        nonce_1,
        response.encrypted_payload,
        aad=circuit_id
    )
    relay_pk_2 = extract_public_key(decrypted)
    shared_2 = X25519(client_sk_2, relay_pk_2)
    keys_2 = HKDF(shared_2, "666:circuit:hop2:v1", 64)
    
    # 4. Extend to exit relay (similar process, double-encrypted)
    client_sk_3, client_pk_3 = X25519.keygen()
    plaintext = encode(path[2].address || client_pk_3 || random(32))
    
    # Encrypt with middle key, then guard key (onion layers)
    layer2 = ChaCha20Poly1305.encrypt(keys_2[0..31], nonce_2, plaintext, aad=circuit_id)
    layer1 = ChaCha20Poly1305.encrypt(keys_1[0..31], nonce_1, layer2, aad=circuit_id)
    
    message = CIRCUIT_EXTEND {
        circuit_id: circuit_id,
        encrypted_payload: layer1
    }
    send(path[0].address, message)
    
    response = receive(timeout=2000)
    # Decrypt response (peel onion layers)
    layer1 = ChaCha20Poly1305.decrypt(keys_1[32..63], nonce_1, response.encrypted_payload, aad=circuit_id)
    plaintext = ChaCha20Poly1305.decrypt(keys_2[32..63], nonce_2, layer1, aad=circuit_id)
    relay_pk_3 = extract_public_key(plaintext)
    shared_3 = X25519(client_sk_3, relay_pk_3)
    keys_3 = HKDF(shared_3, "666:circuit:hop3:v1", 64)
    
    # Circuit ready
    return Circuit {
        id: circuit_id,
        path: path,
        keys: [keys_1, keys_2, keys_3],
        nonces: [nonce_1, nonce_2, nonce_3],
        established_at: now()
    }
```

**Timing:**
- Guard handshake: ~50ms
- Middle extend: ~100ms (includes guard forward)
- Exit extend: ~150ms (includes guard + middle forward)
- **Total circuit build time:** ~300ms

---

## Onion Encryption

### Forward Direction (Client → Service)

**Layering (innermost to outermost):**

```
Plaintext → [Encrypt with Exit key] → Layer 3
         → [Encrypt with Middle key] → Layer 2
         → [Encrypt with Guard key] → Layer 1
         → Send to Guard
```

**Pseudocode:**
```pseudocode
function onion_encrypt(circuit, plaintext):
    nonce_exit = circuit.nonces[2]
    nonce_middle = circuit.nonces[1]
    nonce_guard = circuit.nonces[0]
    
    # Layer 3 (innermost)
    layer3 = ChaCha20Poly1305.encrypt(
        circuit.keys[2][0..31],  # key_forward_exit
        nonce_exit,
        plaintext,
        aad=circuit.id
    )
    
    # Layer 2
    layer2 = ChaCha20Poly1305.encrypt(
        circuit.keys[1][0..31],  # key_forward_middle
        nonce_middle,
        layer3,
        aad=circuit.id
    )
    
    # Layer 1 (outermost)
    layer1 = ChaCha20Poly1305.encrypt(
        circuit.keys[0][0..31],  # key_forward_guard
        nonce_guard,
        layer2,
        aad=circuit.id
    )
    
    # Increment nonces for next message
    circuit.nonces[0] += 1
    circuit.nonces[1] += 1
    circuit.nonces[2] += 1
    
    return layer1
```

### Relay Processing

**Each relay:**
1. Receives encrypted payload
2. Decrypts outer layer with its session key
3. Forwards inner layers to next hop

**Guard Relay:**
```pseudocode
function relay_forward_guard(message):
    circuit = get_circuit(message.circuit_id)
    
    # Decrypt outer layer
    inner = ChaCha20Poly1305.decrypt(
        circuit.key_forward,
        circuit.nonce,
        message.encrypted_payload,
        aad=message.circuit_id
    )
    
    # Forward to next hop (middle relay)
    forward_to(circuit.next_hop, CIRCUIT_RELAY {
        circuit_id: message.circuit_id,
        encrypted_payload: inner
    })
    
    circuit.nonce += 1
```

**Middle and Exit relays:** Same process (decrypt, forward).

**Exit Relay:**
```pseudocode
function relay_forward_exit(message):
    circuit = get_circuit(message.circuit_id)
    
    # Decrypt final layer
    plaintext = ChaCha20Poly1305.decrypt(
        circuit.key_forward,
        circuit.nonce,
        message.encrypted_payload,
        aad=message.circuit_id
    )
    
    # Deliver to destination service
    deliver_to_service(circuit.destination, plaintext)
    
    circuit.nonce += 1
```

### Backward Direction (Service → Client)

**Response flows back through same circuit:**

```
Service sends Response → Exit encrypts → Middle encrypts → Guard encrypts
                                                         → Client receives
```

**Client decrypts (reverse order):**
```pseudocode
function onion_decrypt(circuit, ciphertext):
    # Peel layer 1 (guard)
    layer2 = ChaCha20Poly1305.decrypt(
        circuit.keys[0][32..63],  # key_backward_guard
        circuit.nonces[0],
        ciphertext,
        aad=circuit.id
    )
    
    # Peel layer 2 (middle)
    layer3 = ChaCha20Poly1305.decrypt(
        circuit.keys[1][32..63],  # key_backward_middle
        circuit.nonces[1],
        layer2,
        aad=circuit.id
    )
    
    # Peel layer 3 (exit)
    plaintext = ChaCha20Poly1305.decrypt(
        circuit.keys[2][32..63],  # key_backward_exit
        circuit.nonces[2],
        layer3,
        aad=circuit.id
    )
    
    return plaintext
```

---

## Nonce Management

**Per-Circuit Nonces:**
- Each hop has independent nonce counter
- Forward and backward nonces are separate
- Nonces are 96-bit (12 bytes) for ChaCha20-Poly1305

**Nonce Structure:**
```
Nonce = CircuitID (4 bytes) || Direction (1 byte) || Counter (7 bytes)
```

- `CircuitID`: Unique per circuit
- `Direction`: 0x00 = forward, 0x01 = backward
- `Counter`: Increments with each message (max 2^56 messages)

**Nonce Synchronization:**
- Client and relay maintain same counter
- If nonce mismatch detected: tear down circuit (potential replay attack)

**Nonce Exhaustion:**
- After 2^32 messages, rebuild circuit (refresh keys)
- Typical circuit lifetime: 10 minutes or 10,000 messages (whichever first)

---

## Circuit Lifecycle

### States

```
[INIT] → [BUILDING] → [ACTIVE] → [CLOSING] → [CLOSED]
```

**INIT:**
- Circuit ID allocated
- Path selected
- No relays connected

**BUILDING:**
- Handshakes in progress
- Partial circuit (1-2 hops established)

**ACTIVE:**
- All 3 hops ready
- Can relay messages
- Normal operation

**CLOSING:**
- CIRCUIT_DESTROY sent
- Waiting for acknowledgment
- No new messages accepted

**CLOSED:**
- All keys erased
- Circuit removed from tables
- Resources freed

### Timeouts

- **Build timeout:** 5 seconds (if circuit not ready, abort)
- **Idle timeout:** 10 minutes (rebuild circuit if no activity)
- **Hard timeout:** 60 minutes (rebuild circuit regardless of activity)
- **Message timeout:** 30 seconds (per message response)

### Failure Handling

**If relay times out:**
1. Log failure
2. Destroy circuit: `CIRCUIT_DESTROY(reason=TIMEOUT)`
3. Select new path (exclude failed relay)
4. Rebuild circuit
5. Retry request

**If decryption fails:**
1. Log potential attack
2. Destroy circuit: `CIRCUIT_DESTROY(reason=PROTOCOL_ERROR)`
3. Do not retry immediately (rate limit)

**If service unreachable:**
1. Retry with same circuit (up to 3 attempts)
2. If still failing, rebuild circuit with different exit
3. If still failing, return error to application

---

## Circuit Pooling

**Rationale:** Building circuits is expensive (~300ms). Maintain a pool of pre-built circuits.

### Pool Management

```pseudocode
struct CircuitPool:
    circuits: Array<Circuit>
    min_size: int = 3
    max_size: int = 10
    target_age: duration = 5_minutes

function maintain_pool(pool):
    # Remove old or failed circuits
    for circuit in pool.circuits:
        if circuit.age > pool.target_age or circuit.state == CLOSED:
            destroy_circuit(circuit)
            pool.circuits.remove(circuit)
    
    # Build new circuits to reach min_size
    while len(pool.circuits) < pool.min_size:
        circuit = build_circuit()
        if circuit != ERROR:
            pool.circuits.append(circuit)
        else:
            sleep(1000)  # Back off if build fails
    
    # Proactively build up to max_size (in background)
    if len(pool.circuits) < pool.max_size:
        spawn_background_task(build_circuit_async)

function get_circuit(pool) -> Circuit:
    if pool.circuits.empty():
        # Emergency: build circuit synchronously
        return build_circuit()
    else:
        # Return least recently used circuit
        circuit = pool.circuits.pop(0)
        pool.circuits.append(circuit)  # Rotate to end
        return circuit
```

**Benefits:**
- Zero-latency circuit allocation (already built)
- Automatic circuit rotation (prevents linkability)
- Graceful degradation (falls back to sync build if pool empty)

---

## Path Selection Strategies

### Strategy 1: Bandwidth-Weighted (Default)

- Select relays with probability proportional to bandwidth
- Favors high-capacity relays
- Reduces latency

### Strategy 2: Latency-Optimized

- Prefer relays with low RTT (measured via PING)
- Minimizes end-to-end latency
- Trade-off: May sacrifice bandwidth

### Strategy 3: Geographic Diversity

- Select relays in different countries/continents
- Increases resistance to jurisdiction-based surveillance
- Trade-off: Higher latency

### Strategy 4: Guard Pinning

- Client always uses same guard relay (for 1-3 months)
- Prevents "guard discovery" attacks
- Exit and middle rotate normally

**Recommendation:** Strategy 4 (Guard Pinning) + Strategy 1 (Bandwidth-Weighted for middle/exit)

---

## Security Considerations

### Timing Attacks

**Threat:** Observer correlates request/response timing to link client and service.

**Mitigation:**
- Fixed-size cells (512 bytes) with padding
- Constant-rate transmission (dummy traffic when idle)
- Random delays (jitter) at each hop

### Traffic Confirmation Attacks

**Threat:** Adversary controls both guard and exit, correlates traffic patterns.

**Mitigation:**
- Guard pinning (reduces probability of adversary controlling guard)
- Long-lived circuits (reduces circuit build frequency)
- Dummy traffic (obfuscates traffic patterns)

### Relay Compromise

**Threat:** Adversary operates malicious relays.

**Mitigation:**
- Relay reputation system (ban misbehaving relays)
- Diversity requirements (different subnets)
- Threshold: < 20% malicious relays for 99% anonymity

### Nonce Reuse

**Threat:** Nonce reuse breaks ChaCha20-Poly1305 security.

**Mitigation:**
- Per-circuit, per-hop, per-direction nonces
- Strict counter management (monotonic increase)
- Circuit rebuild after 2^32 messages

---

## Performance Optimization

### 1. Circuit Pooling

Pre-build circuits (described above).

### 2. Path Caching

Cache relay metadata (bandwidth, latency, reputation) to avoid DHT queries on every build.

### 3. Pipeline

Send multiple requests through same circuit (multiplexing).

### 4. Parallel Circuits

Use multiple circuits simultaneously for higher throughput.

### 5. Adaptive Timeouts

Adjust timeouts based on observed relay performance.

---

## Implementation Checklist

For compliance:

- ✅ Select 3-hop paths with diversity
- ✅ Perform X25519 key exchange per hop
- ✅ Derive session keys with HKDF
- ✅ Implement onion encryption (3 layers)
- ✅ Manage per-hop nonces correctly
- ✅ Handle circuit states and transitions
- ✅ Implement timeouts (build, idle, hard, message)
- ✅ Destroy circuits on failure
- ✅ Maintain circuit pool (3-10 circuits)
- ✅ Rotate circuits every 10 minutes or 10,000 messages
- ✅ Erase keys immediately after circuit destruction

---

## Test Scenarios

### 1. Basic Circuit Build

- Select path
- Establish 3 hops
- Verify all keys derived correctly
- Send test message through circuit
- Verify correct decryption at destination

### 2. Onion Encryption/Decryption

- Build circuit
- Encrypt message (3 layers)
- Decrypt at each relay (verify correct layer removed)
- Final plaintext matches original

### 3. Circuit Timeout

- Build circuit
- Wait 15 minutes (exceed hard timeout)
- Verify circuit is destroyed and rebuilt

### 4. Relay Failure

- Build circuit
- Simulate middle relay failure (disconnect)
- Verify circuit is destroyed
- Verify new circuit is built excluding failed relay

### 5. Nonce Synchronization

- Send 1000 messages through circuit
- Verify nonces incremented correctly
- Verify no nonce reuse

### 6. Circuit Pool

- Maintain pool of 3 circuits
- Consume all 3 circuits
- Verify pool automatically rebuilds

---

## Cross-References

- [PROTOCOL_SPEC.md](PROTOCOL_SPEC.md) - Circuit state machine
- [MESSAGE_FORMAT.md](MESSAGE_FORMAT.md) - CIRCUIT_* messages
- [CRYPTO_SPEC.md](CRYPTO_SPEC.md) - X25519, ChaCha20-Poly1305, HKDF
- [DHT_SPEC.md](DHT_SPEC.md) - Relay directory lookup

---

## Changelog

### Version 1.0.0 (2024-01-14)
- Initial routing specification
- Defined 3-hop circuit architecture
- Specified onion encryption and decryption
- Added circuit lifecycle and pooling
- Specified path selection strategies

---

**End of Routing and Circuit Construction Specification v1.0**
