# Data Structures Specification v1.0

**Version:** 1.0.0  
**Status:** Normative Specification  
**Last Updated:** 2024-01-14

---

## Overview

This document specifies language-agnostic data structures required for Project 666 implementations. Each structure includes:

1. **Abstract specification**: What the structure does
2. **Interface requirements**: Required operations and complexity
3. **Implementation guidance**: Algorithms and trade-offs
4. **Invariants**: Properties that must always hold
5. **Test scenarios**: How to verify correctness

**Design Principles:**
1. **Deterministic**: Same inputs produce same outputs across implementations
2. **Efficient**: Specified complexity bounds
3. **Language Agnostic**: Can be implemented in any language
4. **Thread-Safe Guidance**: Concurrency requirements noted

---

## 1. Hash Table (Key-Value Store)

**Purpose:** Fast lookup of keys to values (DHT storage, circuit tables, capability cache)

### Abstract Specification

A hash table maps keys to values with average O(1) lookup, insert, and delete operations.

**Interface:**
```pseudocode
interface HashTable<K, V>:
    put(key: K, value: V) -> void
    get(key: K) -> V | null
    delete(key: K) -> bool
    contains(key: K) -> bool
    size() -> int
    clear() -> void
    keys() -> Iterator<K>
```

### Implementation Requirements

**Hash Function:**
- Use SipHash-2-4 with random seed (initialized at startup)
- Output: 64-bit hash value
- Resistant to hash collision attacks (DoS protection)

**Collision Resolution:**
- **Method**: Open addressing with quadratic probing
- **Probing sequence**: `h(k, i) = (h(k) + i²) mod capacity`
- **Load factor threshold**: Resize when > 75% full
- **Growth strategy**: Double capacity, rehash all entries

**Capacity:**
- Initial: 16 buckets
- Maximum: 2^32 buckets (4 billion entries)
- Always power of 2 (for fast modulo via bitmasking)

### Pseudocode Implementation

```pseudocode
struct HashTable<K, V>:
    buckets: Array<Bucket<K, V>>
    count: int
    capacity: int
    seed: uint64  # Random seed for SipHash
    
    struct Bucket:
        state: EMPTY | OCCUPIED | DELETED
        key: K
        value: V

function put(table, key, value):
    if table.count / table.capacity > 0.75:
        resize(table, table.capacity * 2)
    
    hash = siphash(key, table.seed)
    i = 0
    while true:
        index = (hash + i * i) mod table.capacity
        bucket = table.buckets[index]
        
        if bucket.state == EMPTY or bucket.state == DELETED:
            bucket.state = OCCUPIED
            bucket.key = key
            bucket.value = value
            table.count += 1
            return
        
        if bucket.state == OCCUPIED and bucket.key == key:
            bucket.value = value  # Update existing
            return
        
        i += 1
        if i > table.capacity:
            error("Hash table full (should not happen)")

function get(table, key):
    hash = siphash(key, table.seed)
    i = 0
    while i < table.capacity:
        index = (hash + i * i) mod table.capacity
        bucket = table.buckets[index]
        
        if bucket.state == EMPTY:
            return null
        
        if bucket.state == OCCUPIED and bucket.key == key:
            return bucket.value
        
        i += 1
    
    return null

function delete(table, key):
    hash = siphash(key, table.seed)
    i = 0
    while i < table.capacity:
        index = (hash + i * i) mod table.capacity
        bucket = table.buckets[index]
        
        if bucket.state == EMPTY:
            return false
        
        if bucket.state == OCCUPIED and bucket.key == key:
            bucket.state = DELETED
            table.count -= 1
            return true
        
        i += 1
    
    return false

function resize(table, new_capacity):
    old_buckets = table.buckets
    table.buckets = new Array<Bucket>(new_capacity)
    table.capacity = new_capacity
    table.count = 0
    
    for bucket in old_buckets:
        if bucket.state == OCCUPIED:
            put(table, bucket.key, bucket.value)
```

### Invariants

1. ✅ `count` always equals number of OCCUPIED buckets
2. ✅ Load factor never exceeds 75%
3. ✅ All keys are unique
4. ✅ `get(key)` after `put(key, value)` returns `value`
5. ✅ `get(key)` after `delete(key)` returns `null`

### Thread Safety

**Not thread-safe by default.** Implementations must:
- Use external locking (mutex per table), OR
- Use lock-free techniques (CAS operations), OR
- Document as single-threaded only

**Recommended:** Read-write lock (multiple readers, single writer)

### Test Scenarios

1. **Basic Operations:**
   - Insert 100 key-value pairs
   - Retrieve all 100 (verify correct values)
   - Delete 50, verify they're gone
   - Verify other 50 still present

2. **Collision Handling:**
   - Insert keys that hash to same bucket (force collisions)
   - Verify all keys retrievable

3. **Resizing:**
   - Insert 1000 keys (force multiple resizes)
   - Verify all keys still retrievable after resize

4. **Edge Cases:**
   - Insert null key (should error or use special handling)
   - Get non-existent key (should return null)
   - Delete same key twice (should return false second time)

---

## 2. Merkle Tree (Integrity Verification)

**Purpose:** Cryptographic proof of data integrity (DHT replication, audit logs)

### Abstract Specification

A Merkle tree is a binary tree where each leaf is a hash of data, and each non-leaf is a hash of its children.

**Interface:**
```pseudocode
interface MerkleTree:
    build(data: Array<bytes>) -> MerkleTree
    root() -> bytes[32]
    proof(index: int) -> MerkleProof
    verify(root: bytes[32], data: bytes, proof: MerkleProof) -> bool
```

### Implementation Requirements

**Hash Function:** SHA-256

**Tree Structure:**
- Binary tree (each node has 0 or 2 children)
- Leaves: `H(data[i])`
- Internal nodes: `H(left_child || right_child)`
- Root: Single hash at top

**Proof Size:** O(log N) hashes (for N leaves)

### Pseudocode Implementation

```pseudocode
struct MerkleTree:
    root: Node
    leaves: Array<Node>
    
    struct Node:
        hash: bytes[32]
        left: Node | null
        right: Node | null

function build(data: Array<bytes>) -> MerkleTree:
    if len(data) == 0:
        error("Cannot build tree from empty data")
    
    # Create leaf nodes
    leaves = []
    for item in data:
        node = Node(hash=SHA256(item), left=null, right=null)
        leaves.append(node)
    
    # Pad to power of 2
    while not is_power_of_2(len(leaves)):
        leaves.append(leaves[-1])  # Duplicate last leaf
    
    # Build tree bottom-up
    current_level = leaves
    while len(current_level) > 1:
        next_level = []
        for i in 0..len(current_level) by 2:
            left = current_level[i]
            right = current_level[i+1]
            parent_hash = SHA256(left.hash || right.hash)
            parent = Node(hash=parent_hash, left=left, right=right)
            next_level.append(parent)
        current_level = next_level
    
    return MerkleTree(root=current_level[0], leaves=leaves)

function root(tree: MerkleTree) -> bytes[32]:
    return tree.root.hash

struct MerkleProof:
    leaf_index: int
    leaf_hash: bytes[32]
    sibling_hashes: Array<bytes[32]>
    directions: Array<bool>  # true = sibling on right, false = left

function proof(tree: MerkleTree, index: int) -> MerkleProof:
    if index >= len(tree.leaves):
        error("Index out of bounds")
    
    proof = MerkleProof(
        leaf_index=index,
        leaf_hash=tree.leaves[index].hash,
        sibling_hashes=[],
        directions=[]
    )
    
    current = tree.leaves[index]
    current_index = index
    
    # Traverse up to root
    level_size = len(tree.leaves)
    while level_size > 1:
        # Determine sibling
        if current_index % 2 == 0:
            sibling_index = current_index + 1
            proof.directions.append(true)  # Sibling on right
        else:
            sibling_index = current_index - 1
            proof.directions.append(false)  # Sibling on left
        
        sibling = tree.leaves[sibling_index] if level_size == len(tree.leaves) else ...
        proof.sibling_hashes.append(sibling.hash)
        
        current_index = current_index / 2
        level_size = level_size / 2
    
    return proof

function verify(root: bytes[32], data: bytes, proof: MerkleProof) -> bool:
    current_hash = SHA256(data)
    
    if current_hash != proof.leaf_hash:
        return false
    
    for i in 0..len(proof.sibling_hashes):
        sibling = proof.sibling_hashes[i]
        direction = proof.directions[i]
        
        if direction:  # Sibling on right
            current_hash = SHA256(current_hash || sibling)
        else:  # Sibling on left
            current_hash = SHA256(sibling || current_hash)
    
    return current_hash == root
```

### Invariants

1. ✅ Root hash uniquely identifies tree contents
2. ✅ Changing any leaf changes root
3. ✅ Proof size is O(log N)
4. ✅ Valid proof always verifies
5. ✅ Invalid proof never verifies (with overwhelming probability)

### Test Scenarios

1. **Basic Construction:**
   - Build tree from 8 data items
   - Verify root hash is deterministic

2. **Proof Generation:**
   - Generate proof for each leaf
   - Verify all proofs are valid

3. **Tamper Detection:**
   - Build tree from 8 items
   - Modify one item
   - Verify proof fails for modified item

4. **Edge Cases:**
   - Single item tree
   - Non-power-of-2 items (requires padding)

---

## 3. Circular Buffer Queue (Message Queue)

**Purpose:** FIFO queue for pending messages (send queue, receive queue)

### Abstract Specification

A fixed-size queue with efficient enqueue and dequeue operations.

**Interface:**
```pseudocode
interface CircularQueue<T>:
    enqueue(item: T) -> bool  # false if full
    dequeue() -> T | null     # null if empty
    peek() -> T | null        # Look at front without removing
    is_full() -> bool
    is_empty() -> bool
    size() -> int
    capacity() -> int
```

### Implementation Requirements

**Storage:** Fixed-size array (allocated at creation)
**Pointers:** `head` (read position), `tail` (write position)
**Wrap-Around:** Use modulo arithmetic for circular behavior

### Pseudocode Implementation

```pseudocode
struct CircularQueue<T>:
    buffer: Array<T>
    capacity: int
    head: int  # Index of next item to dequeue
    tail: int  # Index where next item will be enqueued
    count: int # Current number of items

function new_queue(capacity: int) -> CircularQueue<T>:
    return CircularQueue(
        buffer=new Array<T>(capacity),
        capacity=capacity,
        head=0,
        tail=0,
        count=0
    )

function enqueue(queue, item: T) -> bool:
    if queue.count == queue.capacity:
        return false  # Queue full
    
    queue.buffer[queue.tail] = item
    queue.tail = (queue.tail + 1) mod queue.capacity
    queue.count += 1
    return true

function dequeue(queue) -> T | null:
    if queue.count == 0:
        return null  # Queue empty
    
    item = queue.buffer[queue.head]
    queue.head = (queue.head + 1) mod queue.capacity
    queue.count -= 1
    return item

function peek(queue) -> T | null:
    if queue.count == 0:
        return null
    return queue.buffer[queue.head]

function is_full(queue) -> bool:
    return queue.count == queue.capacity

function is_empty(queue) -> bool:
    return queue.count == 0

function size(queue) -> int:
    return queue.count
```

### Invariants

1. ✅ `count` is always in range [0, capacity]
2. ✅ `head` and `tail` are always in range [0, capacity-1]
3. ✅ Items dequeued in same order as enqueued (FIFO)
4. ✅ After `capacity` enqueues, queue is full
5. ✅ After `count` dequeues, queue is empty

### Thread Safety

**Not thread-safe by default.** For concurrent use:
- Use mutex for entire queue, OR
- Use lock-free ring buffer with atomic CAS operations

### Test Scenarios

1. **Basic Operations:**
   - Enqueue 10 items
   - Dequeue 10 items (verify order)

2. **Wrap-Around:**
   - Enqueue 10 items
   - Dequeue 5
   - Enqueue 5 more
   - Dequeue all (verify correct order)

3. **Full Condition:**
   - Fill queue to capacity
   - Try to enqueue one more (should fail)

4. **Empty Condition:**
   - Dequeue from empty queue (should return null)

---

## 4. Routing Table (DHT Node Routing)

**Purpose:** Store peer information for DHT routing (Kademlia-style)

### Abstract Specification

A routing table organizes peers by XOR distance from local node ID.

**Interface:**
```pseudocode
interface RoutingTable:
    add_peer(peer: Peer) -> void
    find_closest(target: NodeID, k: int) -> Array<Peer>
    remove_peer(peer_id: NodeID) -> bool
    get_peer(peer_id: NodeID) -> Peer | null
    size() -> int
```

### Implementation Requirements

**Structure:** K-buckets (buckets organized by distance)
- 256 buckets (one per bit position of 256-bit node ID)
- Each bucket holds up to K peers (K = 20)
- Bucket[i] contains peers with XOR distance in range [2^i, 2^(i+1))

**Distance Metric:** XOR distance
```
distance(a, b) = a XOR b
bucket_index(local_id, peer_id) = bit_position_of_msb(local_id XOR peer_id)
```

**Eviction Policy:** Least Recently Seen (LRS)
- When bucket full, ping oldest peer
- If responds, keep it; evict new peer
- If no response, replace with new peer

### Pseudocode Implementation

```pseudocode
struct RoutingTable:
    local_id: NodeID  # 256-bit identifier
    buckets: Array<KBucket>[256]
    k: int = 20  # Max peers per bucket
    
    struct KBucket:
        peers: Array<PeerEntry>
        last_updated: timestamp
    
    struct PeerEntry:
        peer_id: NodeID
        address: NetworkAddress
        last_seen: timestamp
        rtt: int  # Round-trip time (ms)

function add_peer(table, peer: Peer):
    distance = table.local_id XOR peer.peer_id
    bucket_index = bit_position_of_msb(distance)
    bucket = table.buckets[bucket_index]
    
    # Check if peer already in bucket
    for entry in bucket.peers:
        if entry.peer_id == peer.peer_id:
            entry.last_seen = now()
            entry.address = peer.address
            return
    
    # Bucket not full: add peer
    if len(bucket.peers) < table.k:
        bucket.peers.append(PeerEntry(
            peer_id=peer.peer_id,
            address=peer.address,
            last_seen=now(),
            rtt=0
        ))
        bucket.last_updated = now()
        return
    
    # Bucket full: evict LRS peer
    oldest = find_oldest(bucket.peers)
    if ping(oldest) == false:
        remove_from_array(bucket.peers, oldest)
        bucket.peers.append(PeerEntry(...))
    else:
        # Keep old peer, discard new one
        pass

function find_closest(table, target: NodeID, k: int) -> Array<Peer>:
    distances = []
    for bucket in table.buckets:
        for entry in bucket.peers:
            dist = target XOR entry.peer_id
            distances.append((dist, entry))
    
    # Sort by distance ascending
    distances.sort(key=lambda x: x[0])
    
    # Return k closest
    return [entry for (dist, entry) in distances[0..k]]

function remove_peer(table, peer_id: NodeID) -> bool:
    distance = table.local_id XOR peer_id
    bucket_index = bit_position_of_msb(distance)
    bucket = table.buckets[bucket_index]
    
    for i, entry in enumerate(bucket.peers):
        if entry.peer_id == peer_id:
            bucket.peers.remove(i)
            return true
    
    return false
```

### Invariants

1. ✅ Each bucket has at most K peers
2. ✅ Peers in bucket[i] have distance in range [2^i, 2^(i+1))
3. ✅ No duplicate peers across all buckets
4. ✅ `find_closest` returns at most k peers, sorted by distance
5. ✅ Buckets closer to local_id are more densely populated

### Test Scenarios

1. **Basic Operations:**
   - Add 100 peers
   - Verify they're distributed across correct buckets

2. **Closest Peer Lookup:**
   - Add 50 peers
   - Query for closest 10 to random target
   - Verify returned peers are actually closest

3. **Eviction:**
   - Fill a bucket (20 peers)
   - Try to add 21st peer
   - Verify eviction policy applied

4. **Edge Cases:**
   - Add peer with same ID as local node (should reject)
   - Remove non-existent peer (should return false)

---

## 5. Connection Pool (Peer Connections)

**Purpose:** Manage active network connections to peers

### Abstract Specification

A pool of reusable connections with lifecycle management.

**Interface:**
```pseudocode
interface ConnectionPool:
    get_connection(peer: Peer) -> Connection | null
    return_connection(conn: Connection) -> void
    remove_connection(peer_id: NodeID) -> void
    active_count() -> int
    max_connections() -> int
```

### Implementation Requirements

**Structure:**
- Map: `peer_id -> Connection`
- States: IDLE, ACTIVE, CLOSING, CLOSED
- Max connections: Configurable (default 1000)

**Connection Lifecycle:**
1. IDLE: Connection open, not in use
2. ACTIVE: Connection in use
3. CLOSING: Graceful shutdown in progress
4. CLOSED: Connection terminated

**Eviction Policy:** Least Recently Used (LRU)
- When pool full, close LRU idle connection

### Pseudocode Implementation

```pseudocode
struct ConnectionPool:
    connections: HashMap<NodeID, ConnectionEntry>
    max_connections: int
    lru_queue: LinkedList<NodeID>
    
    struct ConnectionEntry:
        connection: Connection
        state: IDLE | ACTIVE | CLOSING | CLOSED
        last_used: timestamp
        use_count: int

function get_connection(pool, peer: Peer) -> Connection | null:
    # Existing connection
    if peer.peer_id in pool.connections:
        entry = pool.connections[peer.peer_id]
        if entry.state == IDLE:
            entry.state = ACTIVE
            entry.last_used = now()
            entry.use_count += 1
            move_to_front(pool.lru_queue, peer.peer_id)
            return entry.connection
        elif entry.state == ACTIVE:
            return null  # Connection busy
    
    # Create new connection
    if len(pool.connections) >= pool.max_connections:
        evict_lru(pool)
    
    conn = open_connection(peer.address)
    if conn == null:
        return null
    
    entry = ConnectionEntry(
        connection=conn,
        state=ACTIVE,
        last_used=now(),
        use_count=1
    )
    pool.connections[peer.peer_id] = entry
    pool.lru_queue.append(peer.peer_id)
    return conn

function return_connection(pool, conn: Connection):
    peer_id = conn.peer_id
    if peer_id in pool.connections:
        entry = pool.connections[peer_id]
        entry.state = IDLE
        entry.last_used = now()

function evict_lru(pool):
    while len(pool.lru_queue) > 0:
        peer_id = pool.lru_queue.pop_back()
        entry = pool.connections[peer_id]
        
        if entry.state == IDLE:
            close_connection(entry.connection)
            delete pool.connections[peer_id]
            return
```

### Invariants

1. ✅ Active connections ≤ max_connections
2. ✅ ACTIVE connections are in use
3. ✅ IDLE connections are available for reuse
4. ✅ CLOSED connections are removed from pool
5. ✅ LRU queue contains only IDLE connections

### Thread Safety

**Must be thread-safe.** Use:
- Lock per connection pool, OR
- Fine-grained locking (lock per connection)

---

## 6. State Machine (Circuit/Session Lifecycle)

**Purpose:** Manage state transitions for circuits and sessions

### Abstract Specification

A state machine with defined states and transitions.

**Interface:**
```pseudocode
interface StateMachine<S, E>:
    transition(event: E) -> Result<S, Error>
    current_state() -> S
    is_terminal() -> bool
    reset() -> void
```

### Implementation Requirements

**Transition Table:** Map of (current_state, event) -> (next_state, action)

**Example: Circuit State Machine**
- States: INIT, BUILDING, ACTIVE, CLOSED
- Events: CREATE, EXTEND, READY, DESTROY, TIMEOUT
- Transitions:
  - (INIT, CREATE) -> BUILDING
  - (BUILDING, EXTEND) -> BUILDING
  - (BUILDING, READY) -> ACTIVE
  - (ACTIVE, DESTROY) -> CLOSED
  - (*, TIMEOUT) -> CLOSED

### Pseudocode Implementation

```pseudocode
struct StateMachine<S, E>:
    current_state: S
    transition_table: Map<(S, E), Transition<S>>
    
    struct Transition<S>:
        next_state: S
        action: Function | null

function transition(machine, event: E) -> Result<S, Error>:
    key = (machine.current_state, event)
    
    if key not in machine.transition_table:
        return Error("Invalid transition")
    
    trans = machine.transition_table[key]
    
    # Execute action (if any)
    if trans.action != null:
        trans.action()
    
    # Update state
    machine.current_state = trans.next_state
    return Ok(trans.next_state)

# Example: Circuit state machine
function create_circuit_state_machine() -> StateMachine:
    machine = StateMachine(current_state=INIT)
    
    machine.transition_table = {
        (INIT, CREATE): Transition(BUILDING, action=start_handshake),
        (BUILDING, EXTEND): Transition(BUILDING, action=extend_circuit),
        (BUILDING, READY): Transition(ACTIVE, action=finalize_circuit),
        (ACTIVE, DESTROY): Transition(CLOSED, action=cleanup_circuit),
        (BUILDING, TIMEOUT): Transition(CLOSED, action=cleanup_circuit),
        (ACTIVE, TIMEOUT): Transition(CLOSED, action=cleanup_circuit),
    }
    
    return machine
```

### Invariants

1. ✅ State is always valid (in defined state set)
2. ✅ Transitions are atomic
3. ✅ Invalid transitions are rejected
4. ✅ Terminal states have no outgoing transitions

---

## Cross-References

- [PROTOCOL_SPEC.md](PROTOCOL_SPEC.md) - How data structures are used
- [DHT_SPEC.md](DHT_SPEC.md) - Routing table and Merkle tree usage
- [ROUTING_SPEC.md](ROUTING_SPEC.md) - Circuit state machine

---

## Changelog

### Version 1.0.0 (2024-01-14)
- Initial data structures specification
- Defined hash table, Merkle tree, circular queue, routing table, connection pool, state machine
- Provided pseudocode implementations and test scenarios

---

**End of Data Structures Specification v1.0**
