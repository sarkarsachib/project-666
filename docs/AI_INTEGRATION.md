# AI Integration Layer Specification v1.0

**Version:** 1.0.0  
**Status:** Normative Specification  
**Last Updated:** 2024-01-14

---

## Overview

Project 666 is designed to be **orchestrated by AI**. A master AI can inspect system state, trigger actions, analyze metrics, and control execution—enabling autonomous operation, debugging, and optimization.

**Key Capabilities:**
1. **State Inspection**: Query current state of circuits, sessions, capabilities
2. **Action Triggering**: Create services, build circuits, revoke capabilities
3. **Metrics Export**: Collect performance, security, health metrics
4. **Deterministic Control**: Reproducible behavior for testing and debugging
5. **Audit Trail**: Complete log of all AI actions

**Design Principles:**
1. **Read-Only by Default**: AI reads state without side effects
2. **Explicit Actions**: AI must explicitly trigger state changes
3. **Observable**: All AI actions are logged and auditable
4. **Deterministic**: Same AI inputs produce same system behavior (where possible)
5. **Language-Agnostic**: API works across all 17 language implementations

---

## State Inspection API

AI can query system state via **JSON-RPC 2.0** over local Unix socket or HTTP.

### Endpoint

**Local:** `unix:///var/run/project666/ai.sock`  
**HTTP:** `http://localhost:6660/ai` (if enabled)

### Authentication

**API Key:** `X-API-Key: <secret_key>` header  
**Generation:** `openssl rand -hex 32`  
**Storage:** `~/.project666/ai_key`

### Protocol

**JSON-RPC 2.0**

**Request Format:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "state.get_circuits",
  "params": {}
}
```

**Response Format:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "circuits": [...]
  }
}
```

**Error Format:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32600,
    "message": "Invalid request"
  }
}
```

---

## State Query Methods

### 1. `state.get_circuits`

**Description:** List all active circuits.

**Parameters:** None

**Response:**
```json
{
  "circuits": [
    {
      "circuit_id": 12345678,
      "state": "ACTIVE",
      "path": [
        {"node_id": "abc123...", "address": "192.168.1.1:8080"},
        {"node_id": "def456...", "address": "192.168.1.2:8080"},
        {"node_id": "ghi789...", "address": "192.168.1.3:8080"}
      ],
      "established_at": 1704380000000,
      "message_count": 42,
      "bytes_sent": 102400,
      "bytes_received": 51200,
      "last_activity": 1704380120000
    }
  ]
}
```

---

### 2. `state.get_circuit`

**Description:** Get detailed information about specific circuit.

**Parameters:**
```json
{
  "circuit_id": 12345678
}
```

**Response:**
```json
{
  "circuit": {
    "circuit_id": 12345678,
    "state": "ACTIVE",
    "path": [...],
    "keys": [
      {
        "hop": 1,
        "key_forward": "...",  # Hex-encoded (if expose_keys=true)
        "key_backward": "...",
        "nonce_forward": 42,
        "nonce_backward": 37
      },
      ...
    ],
    "established_at": 1704380000000,
    "expires_at": 1704380600000,
    "message_count": 42,
    "bytes_sent": 102400,
    "bytes_received": 51200,
    "last_activity": 1704380120000,
    "latency_ms": 150
  }
}
```

**Security Note:** `keys` field only returned if `expose_keys=true` in config (disabled by default for security).

---

### 3. `state.get_sessions`

**Description:** List all active sessions.

**Parameters:** None

**Response:**
```json
{
  "sessions": [
    {
      "session_id": "session_abc123",
      "peer_address": "7MZUWAU2FJVXQ2KQN5DXA5I4PA4WCLV7...",
      "state": "ACTIVE",
      "established_at": 1704380000000,
      "expires_at": 1704383600000,
      "message_count": 128,
      "last_activity": 1704380200000
    }
  ]
}
```

---

### 4. `state.get_capabilities`

**Description:** List all capabilities held by local node.

**Parameters:** None

**Response:**
```json
{
  "capabilities": [
    {
      "capability_hash": "abcd1234...",
      "issuer": "ISSUER_ADDRESS_...",
      "holder": "HOLDER_PUBKEY_...",
      "permissions": {
        "service": "SERVICE_ADDRESS_...",
        "operations": ["read", "write"],
        "resources": ["/data/*"]
      },
      "issued_at": 1704380000000,
      "expires_at": 1735916000000,
      "revocation_nonce": 1,
      "usage_count": 42,
      "last_used": 1704380300000
    }
  ]
}
```

---

### 5. `state.get_dht_nodes`

**Description:** Get DHT routing table state.

**Parameters:** None

**Response:**
```json
{
  "local_id": "local_node_id_...",
  "buckets": [
    {
      "bucket_index": 0,
      "nodes": [
        {
          "node_id": "node_id_...",
          "address": "192.168.1.5:8080",
          "last_seen": 1704380100000,
          "rtt_ms": 25,
          "uptime": 0.995
        }
      ]
    }
  ],
  "total_nodes": 387
}
```

---

### 6. `state.get_metrics`

**Description:** Get performance and health metrics.

**Parameters:**
```json
{
  "since": 1704380000000  # Unix timestamp (optional)
}
```

**Response:**
```json
{
  "metrics": {
    "circuits": {
      "total_built": 125,
      "active": 5,
      "failed": 3,
      "avg_build_time_ms": 287,
      "avg_lifetime_seconds": 534
    },
    "messages": {
      "sent": 10543,
      "received": 8921,
      "bytes_sent": 10485760,
      "bytes_received": 8388608,
      "errors": 12
    },
    "dht": {
      "queries": 523,
      "stores": 87,
      "avg_lookup_time_ms": 456,
      "cache_hit_rate": 0.67
    },
    "capabilities": {
      "total": 15,
      "expired": 2,
      "revoked": 1,
      "usage_count": 1043
    },
    "system": {
      "uptime_seconds": 86400,
      "memory_used_bytes": 104857600,
      "cpu_usage_percent": 12.5
    }
  },
  "timestamp": 1704380600000
}
```

---

### 7. `state.get_logs`

**Description:** Query system logs.

**Parameters:**
```json
{
  "level": "info",        # "debug", "info", "warn", "error"
  "since": 1704380000000, # Unix timestamp
  "limit": 100,           # Max log entries
  "filter": "circuit"     # Filter by keyword (optional)
}
```

**Response:**
```json
{
  "logs": [
    {
      "timestamp": 1704380001234,
      "level": "info",
      "component": "circuit_builder",
      "message": "Circuit 12345678 established",
      "metadata": {
        "circuit_id": 12345678,
        "path_length": 3,
        "build_time_ms": 287
      }
    }
  ],
  "total": 1542
}
```

---

## Action API

AI can trigger actions to control system behavior.

### 1. `action.build_circuit`

**Description:** Build a new circuit.

**Parameters:**
```json
{
  "path": [
    "node_id_guard",
    "node_id_middle",
    "node_id_exit"
  ]  # Optional: If omitted, system selects path automatically
}
```

**Response:**
```json
{
  "circuit_id": 12345678,
  "state": "BUILDING",
  "estimated_completion_ms": 300
}
```

**Async Callback:** System emits event when circuit ready:
```json
{
  "event": "circuit.ready",
  "circuit_id": 12345678,
  "established_at": 1704380000000
}
```

---

### 2. `action.destroy_circuit`

**Description:** Tear down circuit.

**Parameters:**
```json
{
  "circuit_id": 12345678,
  "reason": "timeout"  # Optional
}
```

**Response:**
```json
{
  "status": "destroyed",
  "circuit_id": 12345678
}
```

---

### 3. `action.invoke_service`

**Description:** Invoke a .666 service.

**Parameters:**
```json
{
  "service_address": "7MZUWAU2FJVXQ2KQN5DXA5I4PA4WCLV7...",
  "capability_token": "...",  # Hex-encoded capability token
  "payload": {
    "operation": "read",
    "key": "example_key"
  },
  "circuit_id": 12345678,  # Optional: Use specific circuit
  "timeout_ms": 5000
}
```

**Response:**
```json
{
  "result": {
    "status": "success",
    "data": "example_value"
  },
  "execution_time_ms": 234,
  "circuit_id": 12345678
}
```

**Error Response:**
```json
{
  "error": {
    "code": "CAPABILITY_DENIED",
    "message": "Invalid capability token",
    "details": "Token signature verification failed"
  }
}
```

---

### 4. `action.issue_capability`

**Description:** Issue new capability token.

**Parameters:**
```json
{
  "issuer_private_key": "...",  # Hex-encoded Ed25519 private key
  "holder_public_key": "...",   # Hex-encoded (or null for bearer)
  "permissions": {
    "service": "7MZUWAU2...",
    "operations": ["read", "write"],
    "resources": ["/data/*"],
    "max_invocations": 1000,
    "rate_limit": 100
  },
  "constraints": {
    "delegation_depth": 1
  },
  "expires_in_seconds": 2592000  # 30 days
}
```

**Response:**
```json
{
  "capability_token": "...",  # Hex-encoded signed token
  "capability_hash": "abcd1234...",
  "issued_at": 1704380000000,
  "expires_at": 1706972000000
}
```

---

### 5. `action.revoke_capability`

**Description:** Revoke capability token.

**Parameters:**
```json
{
  "issuer_private_key": "...",
  "capability_hash": "abcd1234...",
  "reason": "security_compromise"
}
```

**Response:**
```json
{
  "status": "revoked",
  "capability_hash": "abcd1234...",
  "revoked_at": 1704380000000,
  "new_nonce": 2
}
```

---

### 6. `action.publish_descriptor`

**Description:** Publish system descriptor to DHT.

**Parameters:**
```json
{
  "service_address": "7MZUWAU2...",
  "descriptor": {
    "version": "1.0",
    "service": {...},
    "capabilities": {...},
    "interface": {...},
    "limits": {...},
    "metadata": {...}
  },
  "ttl_seconds": 86400
}
```

**Response:**
```json
{
  "status": "published",
  "dht_key": "dht_key_hash_...",
  "replicas": 18,  # Number of DHT nodes storing descriptor
  "published_at": 1704380000000
}
```

---

### 7. `action.set_config`

**Description:** Update runtime configuration.

**Parameters:**
```json
{
  "config": {
    "circuit.pool_size": 5,
    "circuit.rebuild_interval_seconds": 600,
    "dht.k": 20,
    "relay.bandwidth_limit_mbps": 100
  }
}
```

**Response:**
```json
{
  "status": "updated",
  "previous_config": {...},
  "new_config": {...}
}
```

---

## Event Stream API

AI can subscribe to real-time events.

### WebSocket Endpoint

**URL:** `ws://localhost:6660/ai/events`  
**Authentication:** `X-API-Key` header in initial HTTP upgrade request

### Event Types

```json
{
  "event": "circuit.built",
  "timestamp": 1704380000000,
  "data": {
    "circuit_id": 12345678,
    "path": [...]
  }
}
```

**Events:**
- `circuit.built` - Circuit successfully established
- `circuit.failed` - Circuit build failed
- `circuit.destroyed` - Circuit torn down
- `message.sent` - Message sent through circuit
- `message.received` - Message received
- `capability.used` - Capability token used
- `capability.revoked` - Capability token revoked
- `dht.store` - DHT key-value stored
- `dht.query` - DHT query performed
- `error` - System error occurred

### Subscription

**Subscribe to specific events:**
```json
{
  "action": "subscribe",
  "events": ["circuit.built", "circuit.destroyed"]
}
```

**Unsubscribe:**
```json
{
  "action": "unsubscribe",
  "events": ["circuit.built"]
}
```

---

## Metrics Export

System exports metrics in **Prometheus** format for monitoring.

### Endpoint

**URL:** `http://localhost:6660/metrics`  
**Format:** Prometheus text format

### Example Output

```
# HELP project666_circuits_total Total circuits built
# TYPE project666_circuits_total counter
project666_circuits_total{status="success"} 125
project666_circuits_total{status="failure"} 3

# HELP project666_circuit_build_time_seconds Circuit build time
# TYPE project666_circuit_build_time_seconds histogram
project666_circuit_build_time_seconds_bucket{le="0.1"} 5
project666_circuit_build_time_seconds_bucket{le="0.3"} 95
project666_circuit_build_time_seconds_bucket{le="0.5"} 120
project666_circuit_build_time_seconds_bucket{le="+Inf"} 128
project666_circuit_build_time_seconds_sum 35.4
project666_circuit_build_time_seconds_count 128

# HELP project666_messages_total Total messages sent/received
# TYPE project666_messages_total counter
project666_messages_total{direction="sent"} 10543
project666_messages_total{direction="received"} 8921

# HELP project666_dht_queries_total Total DHT queries
# TYPE project666_dht_queries_total counter
project666_dht_queries_total{type="find_value"} 523
project666_dht_queries_total{type="store"} 87

# HELP project666_memory_bytes Memory usage in bytes
# TYPE project666_memory_bytes gauge
project666_memory_bytes 104857600
```

---

## Deterministic Control

For testing and debugging, AI can enable **deterministic mode**.

### Configuration

```json
{
  "deterministic": {
    "enabled": true,
    "seed": 12345678,         # PRNG seed
    "timestamp": 1704380000000 # Fixed timestamp (for testing)
  }
}
```

**Effects:**
1. **Random Number Generation:** Seeded PRNG (reproducible)
2. **Timestamps:** Fixed timestamp (no wall-clock dependency)
3. **Node Selection:** Deterministic relay selection (same path every time)
4. **Nonce Generation:** Seeded nonces (reproducible)

**Use Cases:**
- Unit testing (reproducible test runs)
- Debugging (replay specific scenarios)
- Simulation (controlled environments)

**Security Warning:** NEVER use deterministic mode in production (breaks security).

---

## Audit Trail

All AI actions are logged to audit trail.

### Audit Log Format

```json
{
  "timestamp": 1704380000000,
  "action": "action.issue_capability",
  "parameters": {
    "holder_public_key": "...",
    "permissions": {...}
  },
  "result": "success",
  "user": "ai_orchestrator",
  "session_id": "session_abc123"
}
```

### Audit Log Storage

**Location:** `~/.project666/audit.log`  
**Format:** JSON Lines (one JSON object per line)  
**Rotation:** Daily (compressed after 7 days)  
**Retention:** 90 days

### Audit Query

```bash
# Query audit log
curl -H "X-API-Key: $API_KEY" \
  "http://localhost:6660/ai/audit?since=1704380000000&action=issue_capability"
```

---

## Language Bindings

AI integration API available in multiple languages.

### Python

```python
from project666 import AIClient

client = AIClient(api_key="...")

# Query state
circuits = client.get_circuits()
print(f"Active circuits: {len(circuits)}")

# Trigger action
circuit_id = client.build_circuit()
print(f"Built circuit: {circuit_id}")

# Subscribe to events
@client.on_event("circuit.built")
def on_circuit_built(event):
    print(f"Circuit {event['data']['circuit_id']} ready")

client.start_event_loop()
```

### JavaScript

```javascript
const { AIClient } = require('project666');

const client = new AIClient({ apiKey: '...' });

// Query state
const circuits = await client.getCircuits();
console.log(`Active circuits: ${circuits.length}`);

// Trigger action
const circuitId = await client.buildCircuit();
console.log(`Built circuit: ${circuitId}`);

// Subscribe to events
client.on('circuit.built', (event) => {
  console.log(`Circuit ${event.data.circuit_id} ready`);
});
```

### Rust

```rust
use project666::AIClient;

let client = AIClient::new("...");

// Query state
let circuits = client.get_circuits().await?;
println!("Active circuits: {}", circuits.len());

// Trigger action
let circuit_id = client.build_circuit(None).await?;
println!("Built circuit: {}", circuit_id);

// Subscribe to events
client.on_event("circuit.built", |event| {
    println!("Circuit {} ready", event.data.circuit_id);
});
```

---

## Security Considerations

### API Key Protection

- API keys are **sensitive secrets**
- Store in secure location (`~/.project666/ai_key` with 0600 permissions)
- Rotate regularly (every 90 days)
- Never commit to version control

### Access Control

**API key grants full control:**
- Read all system state
- Trigger any action (including destructive operations)
- Access logs and metrics

**Recommendation:** Use separate API keys for read-only vs. read-write access.

### Rate Limiting

**API requests are rate-limited:**
- 100 requests/second (burst)
- 1000 requests/minute (sustained)

**Exceeding limits:**
- HTTP 429 (Too Many Requests)
- Exponential backoff recommended

### Audit Trail Integrity

**Audit logs are tamper-evident:**
- Each log entry includes hash of previous entry (blockchain-style)
- Tampering detected by hash chain verification

---

## Performance Considerations

### Query Optimization

**Large state queries:**
- Use pagination (`limit` and `offset` parameters)
- Filter by specific criteria (avoid fetching all data)
- Cache results locally (refresh periodically)

**Example:**
```json
{
  "method": "state.get_logs",
  "params": {
    "level": "error",
    "since": 1704380000000,
    "limit": 100
  }
}
```

### Event Stream

**WebSocket connection:**
- Low overhead (persistent connection)
- Real-time updates (no polling)
- Automatic reconnection on disconnect

**Recommendation:** Use event stream for real-time monitoring, query API for on-demand data.

---

## Implementation Checklist

For compliance:

- ✅ JSON-RPC 2.0 API over Unix socket or HTTP
- ✅ API key authentication (X-API-Key header)
- ✅ All state query methods implemented
- ✅ All action methods implemented
- ✅ WebSocket event stream
- ✅ Prometheus metrics export
- ✅ Deterministic mode (for testing)
- ✅ Audit trail logging
- ✅ Rate limiting (100 req/sec burst)
- ✅ Language bindings (at least Python, JavaScript, Rust)

---

## Test Scenarios

### 1. State Inspection

- AI queries circuits, sessions, capabilities
- Verifies state matches expected values
- Checks metrics accuracy

### 2. Circuit Control

- AI builds circuit via API
- Verifies circuit established successfully
- AI destroys circuit
- Verifies circuit removed from state

### 3. Service Invocation

- AI invokes service via API
- Verifies result matches expected output
- Checks capability usage logged

### 4. Capability Management

- AI issues capability token
- AI uses token to invoke service
- AI revokes token
- Verifies revoked token rejected

### 5. Event Stream

- AI subscribes to circuit events
- System builds/destroys circuits
- Verifies AI receives events in real-time

### 6. Deterministic Mode

- Enable deterministic mode with fixed seed
- Build circuit
- Reset system, rebuild with same seed
- Verify same circuit path selected

---

## Cross-References

- [PROTOCOL_SPEC.md](PROTOCOL_SPEC.md) - System overview
- [MESSAGE_FORMAT.md](MESSAGE_FORMAT.md) - Message structures
- [CAPABILITY_MODEL.md](CAPABILITY_MODEL.md) - Capability operations
- [ROUTING_SPEC.md](ROUTING_SPEC.md) - Circuit operations
- [DHT_SPEC.md](DHT_SPEC.md) - DHT operations

---

## Changelog

### Version 1.0.0 (2024-01-14)
- Initial AI integration specification
- Defined JSON-RPC 2.0 API for state inspection and actions
- Added WebSocket event stream
- Specified Prometheus metrics export
- Added deterministic mode for testing
- Specified audit trail logging

---

**End of AI Integration Layer Specification v1.0**
