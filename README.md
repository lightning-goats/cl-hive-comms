# cl-hive-comms

**Phase 6A transport and client entry-point plugin for the cl-hive Lightning fleet stack.**

cl-hive-comms is the communication gateway that sits in front of cl-hive. It receives management commands over REST and Nostr DM transports, authenticates advisors (human or AI), enforces policy gates, and either handles requests locally or forwards coordination packets into cl-hive. It operates as a standalone plugin — cl-hive is not required.

## How It Fits

```
External Advisors (Claude, operators, dashboards)
    |
    |-- REST envelope ──────┐
    |-- Nostr DM (kind 4) ──┤
                             ▼
cl-hive-comms (Transport + Client Gateway)
    |
    |-- management schemas ──→ handled locally (authorize, policy, receipts)
    |-- coordination packets → forwarded to cl-hive via hive-inject-packet RPC
    |
cl-hive (Coordination)        <-- fleet gossip, intents, topology
    |
    |-- delegates signing -->  cl-hive-archon (Identity + Governance)
    |
cl-revenue-ops (Execution)    <-- fees, rebalancing, local policy
    |
Core Lightning
```

When comms is active, external advisors authenticate with HMAC-signed envelopes and interact with the fleet through a policy-gated schema system. Each action is danger-scored, rate-limited, replay-protected, and logged to a hash-chained receipt trail.

When comms is absent, cl-hive operates normally using direct peer-to-peer custom messages over Lightning.

## Features

- **Advisor Management** — Authorize, revoke, and discover advisors with granular permissions (`monitor`, `admin`, `policy`, `fee_policy`, `payments`, `trial`, `alias`). Each advisor gets a unique HMAC auth token for envelope signing.
- **Policy Engine** — Three presets (`conservative`, `moderate`, `aggressive`) with per-schema danger scoring (1-10). Operators can block specific schemas or require confirmation above a threshold.
- **Transport Routing** — Unified envelope format for REST and Nostr DM ingress. The router validates structure, checks clock skew, verifies HMAC signatures, enforces permissions, and evaluates danger before dispatching.
- **Replay Protection** — Monotonically increasing nonces per sender, persisted in the database. Reused nonces are rejected.
- **Rate Limiting** — Sliding window: 60 requests/min general, 5 requests/min for high-danger operations (score >= 5). Auto-evicts stale senders.
- **At-Rest Encryption** — Private keys and auth tokens encrypted in SQLite using PyNaCl SecretBox (XSalsa20-Poly1305). Key file created with 0o400 permissions on first run.
- **Hash-Chained Receipts** — Every management action produces an append-only receipt with `prev_hash → receipt_hash` linking, creating a tamper-evident audit trail.
- **Trial & Payment Tracking** — Start time-limited advisor trials (1-90 days) and record payments with daily spending caps per advisor.
- **Nostr Identity** — Auto-generates a BIP-340 x-only keypair on first run. Supports key rotation, import, and relay configuration.

## Requirements

- Core Lightning v25.02+
- `pyln-client >= 24.0`
- `PyNaCl >= 1.5.0`
- No cl-hive dependency — operates standalone

## Install

### Docker (with cl-hive)

Set `HIVE_COMMS_ENABLED=true` in your docker environment. The entrypoint loads comms automatically before cl-hive.

### Manual

```bash
# Clone next to cl-hive
git clone https://github.com/lightning-goats/cl-hive-comms.git

# Add to lightningd config (load before cl-hive)
echo "plugin=/path/to/cl-hive-comms/cl-hive-comms.py" >> ~/.lightning/config
```

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `hive-comms-db-path` | `~/.lightning/cl_hive_comms.db` | SQLite database path |
| `hive-comms-nostr-relays` | `wss://nos.lol,wss://relay.damus.io` | Comma-separated Nostr relay URLs |
| `hive-comms-policy-preset` | `moderate` | Policy preset: `conservative`, `moderate`, `aggressive` |
| `hive-comms-transport-max-skew-seconds` | `300` | Allowed timestamp skew for envelope validation |
| `hive-comms-rest-rune-required` | `false` | Require CLN rune authentication for REST ingress |
| `hive-comms-rest-rune-static` | *(empty)* | Optional static rune token for local/test mode |
| `hive-comms-nostr-allow-plaintext` | `false` | Allow plaintext JSON DM payloads (testing only) |

## Quick Start

```bash
# Check plugin status
lightning-cli hive-client-status

# Authorize an advisor with monitor + fee policy access
lightning-cli hive-client-authorize advisor="Hex Advisor" access="monitor,fee_policy"

# Set a conservative policy preset
lightning-cli hive-client-policy action="set-preset" preset="conservative"

# Start a 30-day trial for an advisor
lightning-cli hive-client-trial action=start advisor="Hex Advisor" days=30

# List all advisors
lightning-cli hive-client-discover

# View the audit trail
lightning-cli hive-client-receipts limit=20
```

## RPC Methods

### Client Management

| Method | Description |
|--------|-------------|
| `hive-client-status` | Aggregate status: identity, policy, advisor counts, payment summaries |
| `hive-client-identity` | Manage Nostr identity (get, rotate, import, set-relays) |
| `hive-client-authorize` | Create or update advisor with permissions and auth token |
| `hive-client-revoke` | Revoke advisor access and delete auth token |
| `hive-client-discover` | Search advisors by name, alias, or capability |
| `hive-client-policy` | Get/set policy preset, overrides, or reset to defaults |
| `hive-client-receipts` | Query hash-chained management receipt audit log |
| `hive-client-payments` | Record payments, view history, check daily limits |
| `hive-client-trial` | Start, stop, or list advisor trial periods |
| `hive-client-alias` | Set, get, list, or remove human-readable advisor aliases |
| `hive-client-prune` | Delete old receipts, payments, expired trials, and stale nonces |

### Transport Ingress

| Method | Description |
|--------|-------------|
| `hive-comms-rpc` | REST/marketplace envelope ingress with optional rune auth |
| `hive-comms-nostr-ingest` | Direct Nostr DM ingress (decoded payload) |
| `hive-comms-nostr-event` | Nostr event parser — decodes kind-4 DMs and routes |
| `hive-comms-send-dm` | Queue a DM for outbound Nostr publishing |
| `hive-comms-publish-event` | Publish a raw Nostr event to connected relays |
| `hive-comms-register-transport` | Register a custom transport adapter |
| `hive-comms-transports` | List all registered transports (builtin: `rest`, `nostr_dm`) |

## Transport Envelope

Both REST and Nostr DM transports use a unified management envelope:

```json
{
  "schema_type": "hive:monitor/v1",
  "schema_payload": {"action": "status"},
  "credential": {"mode": "nostr"},
  "payment_proof": {},
  "signature": "hmac-sha256:<hex>",
  "nonce": 1,
  "timestamp": 1739894400
}
```

The router enforces, in order:
1. Rate limit (60/min per sender)
2. Envelope structure validation
3. REST rune auth (if enabled)
4. Clock skew check (timestamp within configured window)
5. Sender authentication (advisor lookup + HMAC-SHA256 signature verification)
6. Permission check (advisor permissions cover the requested schema)
7. Replay guard (nonce must exceed last-seen nonce for this sender)
8. Danger evaluation (schema score checked against policy thresholds)
9. Schema execution

Supported DM content encodings: `nip44:<base64>`, `nip44:v2:<base64>`, `b64:<base64>`.

## Security

- **HMAC-SHA256 envelope signing** — timing-safe comparison via `hmac.compare_digest()`
- **At-rest encryption** — PyNaCl SecretBox for private keys and auth tokens in SQLite
- **Monotonic replay protection** — per-sender nonces persisted across restarts
- **Sliding-window rate limiting** — general (60/min) and high-danger (5/min) per sender
- **Danger scoring** — every schema scored 1-10; policy gates block or require confirmation
- **Message size cap** — 65,535 bytes max per envelope
- **DB file permissions 0o600** — owner read/write only
- **Hash-chained receipts** — tamper-evident audit trail for all management actions
- **SQLite WAL mode** with thread-local connections for concurrent access

## Database

7 tables: `nostr_state` (key-value config/state), `comms_advisors`, `comms_aliases`, `comms_advisor_auth`, `comms_trials`, `comms_payments`, `management_receipts`. Auth tokens encrypted at rest.

## Development

```bash
python3 -m pytest tests/ -q    # ~30 tests
```

## License

MIT
