# Distributed Hash Table Specification v1.0

**Version:** 1.0.0  
**Status:** Normative Specification  
**Last Updated:** 2024-01-14

---

## Overview

Project 666 uses a **Distributed Hash Table (DHT)** for decentralized storage and discovery:

1. **Service Descriptors**: Where to find `.666` services
2. **Relay Directory**: List of available onion relays
3. **Capability Revocation**: Revoked capability lists
4. **Gossip Metadata**: Network health and statistics

**Design:** Kademlia-inspired DHT with XOR distance metric, k-bucket routing, and end-to-end encryption.

**Properties:**
- **Decentralized**: No central authority
- **Scalable**: O(log N) lookups
- **Resilient**: Tolerates node failures
- **Private**: All stored data is encrypted

---

## Node Architecture

### Node Identity

Every DHT node has a 256-bit **Node ID**, derived from its identity public key:

```
NodeID = SHA-256(NodePublicKey || "666:dht:v1")
```

**Properties:**
- Globally unique (collision probability negligible)
- Self-certifying (NodeID proves key ownership)
- Random distribution (uniform across 256-bit space)

### Node Information

```
struct Node:
    node_id: bytes[32]         # 256-bit identifier
    public_key: bytes[32]      # Ed25519 identity key
    address: NetworkAddress    # IP:Port or .666 address
    seen_at: uint64            # Last seen timestamp (ms)
    uptime: float              # Uptime percentage (0.0-1.0)
    bandwidth: uint64          # Available bandwidth (bytes/sec)
    storage: uint64            # Available storage (bytes)
    capabilities: Array<string># Node capabilities (["relay", "store", "bootstrap"])
```

---

## Distance Metric

DHT uses **XOR distance** for key proximity:

```
distance(a, b) = a XOR b
```

**Properties:**
- Symmetric: `distance(a, b) = distance(b, a)`
- Identity: `distance(a, a) = 0`
- Triangle inequality: `distance(a, c) ≤ distance(a, b) + distance(b, c)`

**Interpretation:**
- Smaller XOR distance = "closer" nodes
- Nodes store keys "close" to their NodeID

---

## Routing Table

Each node maintains a **routing table** with up to 256 **k-buckets** (k = 20).

### K-Bucket Structure

**Bucket[i]** contains nodes with distance in range `[2^i, 2^(i+1))`:

```
Bucket[0]:   distance = [2^0,   2^1)     (closest nodes)
Bucket[1]:   distance = [2^1,   2^2)
Bucket[2]:   distance = [2^2,   2^3)
...
Bucket[255]: distance = [2^255, 2^256)  (farthest nodes)
```

**Each bucket:**
- Holds up to k = 20 nodes
- Sorted by last seen time (most recent first)
- Eviction policy: Least Recently Seen (LRS)

### Bucket Management

**Adding Node:**
```pseudocode
function add_node(routing_table, node):
    distance = routing_table.local_id XOR node.node_id
    bucket_index = bit_position_of_msb(distance)
    bucket = routing_table.buckets[bucket_index]
    
    # Node already in bucket: update last_seen
    if node in bucket:
        bucket.move_to_front(node)
        node.seen_at = now()
        return
    
    # Bucket not full: add node
    if len(bucket) < k:
        bucket.prepend(node)
        return
    
    # Bucket full: evict LRS node
    oldest = bucket.tail()
    if ping(oldest) == SUCCESS:
        # Old node still alive: keep it, discard new node
        return
    else:
        # Old node dead: replace with new node
        bucket.remove(oldest)
        bucket.prepend(node)
```

**Bucket Split:**
- When bucket[0] (closest bucket) is full, split it into two sub-buckets
- This only happens for buckets containing the local node's range

### Lookup

**Find k closest nodes to target:**
```pseudocode
function find_closest_nodes(routing_table, target_id, k):
    candidates = []
    
    # Collect nodes from all buckets
    for bucket in routing_table.buckets:
        candidates.extend(bucket.nodes)
    
    # Sort by XOR distance from target
    candidates.sort(key=lambda node: node.node_id XOR target_id)
    
    # Return k closest
    return candidates[0:k]
```

---

## DHT Operations

### 1. PING (Heartbeat)

**Purpose:** Check if node is alive, measure latency.

**Request:**
```
PING {
    sender_id: NodeID,
    timestamp: uint64
}
```

**Response:**
```
PONG {
    sender_id: NodeID,
    request_timestamp: uint64,
    response_timestamp: uint64
}
```

**RTT Calculation:**
```
rtt = response_received_at - request_timestamp
```

---

### 2. FIND_NODE (Routing Lookup)

**Purpose:** Iteratively find k nodes closest to target.

**Request:**
```
FIND_NODE {
    sender_id: NodeID,
    target_id: NodeID,
    k: int = 20
}
```

**Response:**
```
FOUND_NODES {
    sender_id: NodeID,
    target_id: NodeID,
    nodes: Array<Node>  # Up to k closest nodes
}
```

**Iterative Lookup Algorithm:**
```pseudocode
function iterative_find_node(local_routing_table, target_id, k):
    # Start with k closest nodes from local routing table
    closest = find_closest_nodes(local_routing_table, target_id, k)
    queried = Set()
    
    while true:
        # Find unqueried node closest to target
        next_node = find_unqueried_closest(closest, queried, target_id)
        
        if next_node == null:
            # No more nodes to query
            break
        
        queried.add(next_node)
        
        # Query node for its k closest
        response = send_find_node(next_node, target_id, k)
        
        if response != null:
            # Merge results into closest set
            for node in response.nodes:
                if node not in closest:
                    closest.append(node)
            
            # Keep only k closest
            closest.sort(key=lambda n: n.node_id XOR target_id)
            closest = closest[0:k]
        
        # Termination: if no closer nodes found in last α queries (α = 3)
        if last_3_queries_didnt_improve_closeness():
            break
    
    return closest[0:k]
```

**Timing:**
- Average: 3-5 hops (log N)
- Timeout: 500ms per hop
- Total: ~1.5 seconds

---

### 3. STORE (Put Key-Value)

**Purpose:** Store encrypted data in DHT.

**Request:**
```
STORE {
    sender_id: NodeID,
    key: bytes[32],           # SHA-256 hash
    value: bytes,             # Encrypted data
    ttl: uint32,              # Time-to-live (seconds)
    signature: bytes[64]      # Ed25519 signature
}
```

**Response:**
```
STORED {
    sender_id: NodeID,
    key: bytes[32],
    status: uint16            # 0x0000 = success, error codes otherwise
}
```

**Storage Rules:**
1. Node stores key if it's among k closest to key
2. Value is encrypted (node cannot read plaintext)
3. TTL enforced: delete after expiration
4. Signature verified: ensures authenticity

**Storage Process:**
```pseudocode
function store_key_value(dht, key, value, ttl):
    # 1. Find k closest nodes to key
    closest_nodes = iterative_find_node(dht.routing_table, key, 20)
    
    # 2. Send STORE to all k nodes
    for node in closest_nodes:
        signature = Ed25519.sign(dht.identity_key, key || value || ttl)
        send_store(node, STORE {
            sender_id: dht.local_id,
            key: key,
            value: value,
            ttl: ttl,
            signature: signature
        })
    
    # 3. Wait for confirmations
    confirmations = 0
    for response in await_responses(timeout=2000):
        if response.status == SUCCESS:
            confirmations += 1
    
    # Success if majority confirms
    return confirmations >= (k / 2)
```

---

### 4. FIND_VALUE (Get Key-Value)

**Purpose:** Retrieve data from DHT.

**Request:**
```
FIND_VALUE {
    sender_id: NodeID,
    key: bytes[32]
}
```

**Response (if value found):**
```
FOUND_VALUE {
    sender_id: NodeID,
    key: bytes[32],
    value: bytes,
    signature: bytes[64]
}
```

**Response (if value not found):**
```
FOUND_NODES {
    sender_id: NodeID,
    key: bytes[32],
    nodes: Array<Node>  # Closer nodes to try
}
```

**Retrieval Process:**
```pseudocode
function find_value(dht, key):
    # 1. Check local cache
    if key in dht.local_cache:
        return dht.local_cache[key]
    
    # 2. Iterative lookup (similar to FIND_NODE)
    closest = find_closest_nodes(dht.routing_table, key, 20)
    queried = Set()
    
    while true:
        next_node = find_unqueried_closest(closest, queried, key)
        if next_node == null:
            return NOT_FOUND
        
        queried.add(next_node)
        response = send_find_value(next_node, key)
        
        if response.type == FOUND_VALUE:
            # Verify signature
            if verify_signature(response.key, response.value, response.signature):
                dht.local_cache[key] = response.value
                return response.value
        elif response.type == FOUND_NODES:
            # Merge closer nodes and continue
            for node in response.nodes:
                if node not in closest:
                    closest.append(node)
            closest.sort(key=lambda n: n.node_id XOR key)
            closest = closest[0:20]
    
    return NOT_FOUND
```

---

## Replication

**Goal:** Ensure data availability even if nodes fail.

### Replication Strategy

- Store each key on **k = 20 closest nodes**
- Periodically re-publish (every 1 hour)
- Nodes that join and become closer inherit stored keys

### Republication

**Publisher's Responsibility:**
```pseudocode
function republish_data(dht):
    for (key, value, ttl) in dht.published_keys:
        if now() - last_published[key] > 1_hour:
            store_key_value(dht, key, value, ttl)
            last_published[key] = now()
```

### Replication on Node Join

**New Node's Responsibility:**
```pseudocode
function join_dht_and_replicate(new_node):
    # 1. Bootstrap: find initial nodes
    bootstrap_nodes = query_bootstrap_servers()
    for node in bootstrap_nodes:
        add_node(new_node.routing_table, node)
    
    # 2. Populate routing table
    iterative_find_node(new_node.routing_table, new_node.local_id, 20)
    
    # 3. Request keys for which we are now one of k closest
    for i in 0..256:
        bucket = new_node.routing_table.buckets[i]
        for node in bucket:
            request_keys_in_range(node, compute_range(new_node.local_id, i))
```

---

## Bootstrap

New nodes join network via **bootstrap nodes** (well-known, stable nodes).

### Bootstrap Process

1. **Query Bootstrap Nodes:**
   - Hard-coded list of bootstrap node addresses
   - Example: `["bootstrap1.666:8080", "bootstrap2.666:8080"]`

2. **Initial Routing Table:**
   - Send FIND_NODE(local_id) to bootstrap nodes
   - Populate routing table with returned nodes

3. **Self-Lookup:**
   - Iteratively find k closest nodes to self
   - Ensures routing table is well-populated

4. **Bucket Refresh:**
   - For each bucket, perform random lookup in that bucket's range
   - Ensures full coverage of ID space

**Pseudocode:**
```pseudocode
function bootstrap_node(new_node):
    # 1. Connect to bootstrap nodes
    bootstrap_addresses = [
        "bootstrap1.666:8080",
        "bootstrap2.666:8080",
        "bootstrap3.666:8080"
    ]
    
    for address in bootstrap_addresses:
        response = send_find_node(address, new_node.local_id, 20)
        if response != null:
            for node in response.nodes:
                add_node(new_node.routing_table, node)
    
    # 2. Self-lookup (populate routing table)
    closest_to_self = iterative_find_node(new_node.routing_table, new_node.local_id, 20)
    
    # 3. Bucket refresh (ensure coverage)
    for i in 0..256:
        random_id_in_bucket = generate_random_id_in_bucket_range(i)
        iterative_find_node(new_node.routing_table, random_id_in_bucket, 20)
    
    return SUCCESS
```

---

## Data Encryption

All DHT data is **encrypted end-to-end**. Nodes cannot read stored data.

### Encryption Scheme

**Key Derivation:**
```
dht_key = HKDF-SHA256(
    ikm=publisher_secret_key,
    salt="666:dht:v1",
    info=data_key,
    length=32
)
```

**Encryption:**
```
nonce = random(12)
(ciphertext, tag) = ChaCha20Poly1305.encrypt(
    key=dht_key,
    nonce=nonce,
    plaintext=data,
    aad=data_key
)
encrypted_value = nonce || ciphertext || tag
```

**Storage:**
```
dht_storage_key = SHA-256(data_key)
STORE(dht_storage_key, encrypted_value, ttl=86400)
```

**Retrieval and Decryption:**
```
encrypted_value = FIND_VALUE(dht_storage_key)
nonce = encrypted_value[0:12]
ciphertext = encrypted_value[12:-16]
tag = encrypted_value[-16:]

plaintext = ChaCha20Poly1305.decrypt(
    key=dht_key,
    nonce=nonce,
    ciphertext=ciphertext,
    tag=tag,
    aad=data_key
)
```

**Access Control:**
- Only parties with `dht_key` can decrypt
- Capability tokens include `dht_key` for service descriptors
- DHT nodes store opaque encrypted blobs

---

## Gossip Protocol

DHT nodes **gossip** metadata for network health and statistics.

### Gossip Messages

**Node Announcement:**
```
ANNOUNCE {
    node_id: NodeID,
    address: NetworkAddress,
    public_key: bytes[32],
    capabilities: Array<string>,
    timestamp: uint64,
    signature: bytes[64]
}
```

**Relay Advertisement:**
```
RELAY_AD {
    node_id: NodeID,
    bandwidth: uint64,
    uptime: float,
    latency_avg: uint32,
    timestamp: uint64,
    signature: bytes[64]
}
```

### Gossip Propagation

**Strategy:** Epidemic broadcast
- Node receives gossip message
- Forwards to random subset of neighbors (fanout = 4)
- TTL prevents infinite loops (max 10 hops)

**Pseudocode:**
```pseudocode
function gossip_message(node, message, ttl):
    if ttl <= 0:
        return  # Stop propagation
    
    # Store message locally
    node.gossip_cache[message.id] = message
    
    # Select random neighbors (fanout = 4)
    neighbors = random_sample(node.routing_table.all_nodes(), 4)
    
    # Forward to neighbors
    for neighbor in neighbors:
        send(neighbor, message, ttl - 1)
```

**Convergence Time:**
- Fanout = 4, average path length = log₄(N)
- For N = 10,000 nodes: ~7 hops (~3.5 seconds)

---

## DHT Maintenance

### Bucket Refresh

**Periodic bucket refresh** ensures routing table stays current:

```pseudocode
function refresh_routing_table(node):
    for i in 0..256:
        bucket = node.routing_table.buckets[i]
        
        # Refresh if bucket hasn't been queried in last 1 hour
        if now() - bucket.last_refresh > 1_hour:
            # Perform random lookup in bucket's range
            random_id = generate_random_id_in_bucket_range(i)
            iterative_find_node(node.routing_table, random_id, 20)
            bucket.last_refresh = now()
```

**Frequency:** Every 10 minutes

### Data Expiration

**TTL enforcement:**

```pseudocode
function expire_old_data(node):
    for (key, value, stored_at, ttl) in node.local_storage:
        if now() - stored_at > ttl:
            node.local_storage.delete(key)
```

**Frequency:** Every 5 minutes

### Node Liveness

**Periodic pinging:**

```pseudocode
function check_node_liveness(node):
    for bucket in node.routing_table.buckets:
        for peer in bucket.nodes:
            if now() - peer.seen_at > 15_minutes:
                # Ping to check if still alive
                response = ping(peer, timeout=2000)
                if response == null:
                    bucket.remove(peer)
                else:
                    peer.seen_at = now()
```

**Frequency:** Every 5 minutes

---

## Security Considerations

### Sybil Attack

**Threat:** Adversary creates many fake nodes to dominate DHT.

**Mitigation:**
1. **Proof of Work:** Node ID requires proof of work (expensive to create many IDs)
2. **Identity Verification:** Nodes must sign messages with Ed25519 key
3. **Reputation:** Track node behavior, ban misbehaving nodes
4. **Diversity:** Ensure routing paths use diverse nodes (IP subnet diversity)

### Eclipse Attack

**Threat:** Adversary controls all nodes in victim's routing table.

**Mitigation:**
1. **Bootstrap from Multiple Sources:** Use 3+ bootstrap nodes
2. **Routing Table Diversity:** Enforce IP subnet diversity in buckets
3. **Persistent Peers:** Remember and reconnect to known-good peers
4. **Bucket Refresh:** Periodically refresh buckets (prevents stale routes)

### Data Poisoning

**Threat:** Adversary stores fake/malicious data.

**Mitigation:**
1. **Signature Verification:** All stored data must be signed
2. **Encryption:** Data is encrypted, only authorized parties can decrypt
3. **Revocation:** Capability revocation invalidates old data

### Traffic Analysis

**Threat:** Adversary observes DHT queries to infer user behavior.

**Mitigation:**
1. **Onion Routing:** All DHT queries routed through circuits
2. **Caching:** Cache frequently accessed data (reduce queries)
3. **Dummy Queries:** Periodically query random keys (traffic obfuscation)

---

## Performance Optimization

### Caching

**Local Cache:**
- Cache recently retrieved values
- TTL: 5 minutes
- LRU eviction policy

**Prefix Caching:**
- Cache partial lookup results
- Speeds up subsequent lookups

### Parallel Queries

**α-parallelism:**
- Query α = 3 nodes simultaneously during iterative lookup
- Reduces latency (from O(log N) sequential to O(log N / α))

### Bucket Shortcuts

**Shortcut Nodes:**
- Cache highly-connected nodes (hubs)
- Use as "shortcuts" during lookups

---

## Implementation Checklist

For compliance:

- ✅ Node ID derived from public key
- ✅ 256 k-buckets with k = 20 peers each
- ✅ XOR distance metric
- ✅ LRS eviction policy
- ✅ PING, FIND_NODE, STORE, FIND_VALUE operations
- ✅ Iterative lookup (terminates correctly)
- ✅ k = 20 replication
- ✅ Republication every 1 hour
- ✅ Bootstrap from multiple nodes
- ✅ End-to-end encryption of stored data
- ✅ Signature verification for stored data
- ✅ Gossip protocol (fanout = 4)
- ✅ Bucket refresh every 10 minutes
- ✅ Data expiration enforcement
- ✅ Node liveness checks

---

## Test Scenarios

### 1. Bootstrap

- New node queries bootstrap servers
- Populates routing table with initial nodes
- Performs self-lookup to discover neighbors

### 2. Store and Retrieve

- Store key-value with k = 20 replication
- Retrieve value from different node
- Verify correct decryption

### 3. Replication on Node Join

- New node joins network
- Becomes one of k closest to existing key
- Receives copy of key-value

### 4. Data Expiration

- Store key with TTL = 60 seconds
- Wait 90 seconds
- Verify key is deleted from storage

### 5. Iterative Lookup

- Perform FIND_NODE for random target
- Verify convergence (finds k closest nodes)
- Measure hop count (should be O(log N))

### 6. Node Failure

- Store key on k = 20 nodes
- Simulate 5 node failures
- Retrieve key (should still succeed: 15 replicas remaining)

---

## Cross-References

- [PROTOCOL_SPEC.md](PROTOCOL_SPEC.md) - DHT message types
- [MESSAGE_FORMAT.md](MESSAGE_FORMAT.md) - DHT_* message formats
- [DATA_STRUCTURES.md](DATA_STRUCTURES.md) - Routing table, Merkle tree
- [SYSTEM_DESCRIPTOR.md](SYSTEM_DESCRIPTOR.md) - Descriptor storage in DHT
- [ROUTING_SPEC.md](ROUTING_SPEC.md) - Onion-routed DHT queries

---

## Changelog

### Version 1.0.0 (2024-01-14)
- Initial DHT specification
- Defined Kademlia-inspired architecture
- Specified PING, FIND_NODE, STORE, FIND_VALUE operations
- Added replication, bootstrap, encryption
- Specified gossip protocol and maintenance

---

**End of Distributed Hash Table Specification v1.0**
