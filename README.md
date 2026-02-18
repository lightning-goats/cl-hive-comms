# cl-hive-comms

Phase 6A plugin for transport/client entry-point workflows.

## Status
- Implemented as a standalone plugin (no `cl-hive` dependency).
- Local-only baseline: stateful identity, policy, advisors, trials, payments, and receipts.
- Network transport wiring (Nostr DM, REST/rune marketplace publishing) remains a follow-up.

## RPC Methods
- `hive-client-status`
- `hive-client-identity`
- `hive-client-authorize`
- `hive-client-revoke`
- `hive-client-discover`
- `hive-client-receipts`
- `hive-client-policy`
- `hive-client-payments`
- `hive-client-trial`
- `hive-client-alias`
- `hive-comms-rpc` (REST/rune-style transport ingress)
- `hive-comms-nostr-ingest` (Nostr DM ingress hook for transport wiring)
- `hive-comms-nostr-event` (Nostr event parser + DM envelope decode path)
- `hive-comms-register-transport` (register pluggable transport metadata)
- `hive-comms-transports` (list registered transports)

## Config Options
- `hive-comms-db-path` (default: `~/.lightning/cl_hive_comms.db`)
- `hive-comms-nostr-relays` (default: `wss://nos.lol,wss://relay.damus.io`)
- `hive-comms-policy-preset` (default: `moderate`)
- `hive-comms-transport-max-skew-seconds` (default: `300`)
- `hive-comms-rest-rune-required` (default: `false`)
- `hive-comms-rest-rune-static` (default: empty; optional local static token)
- `hive-comms-nostr-allow-plaintext` (default: `false`)

## Install
1. Place `cl-hive-comms.py` in your CLN plugin path.
2. Add to `lightningd` config:

```ini
plugin=/path/to/cl-hive-comms.py
hive-comms-policy-preset=moderate
```

3. Restart `lightningd`.

## Quick Start
```bash
lightning-cli hive-client-status
lightning-cli hive-client-authorize advisor="Hex Advisor" access="monitor,fee_policy"
lightning-cli hive-client-policy action="set-preset" preset="conservative"
```

## Transport Envelope
`hive-comms-rpc` and `hive-comms-nostr-ingest` accept a JSON envelope:

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

The router enforces:
- required envelope fields
- monotonic nonce replay protection per sender
- timestamp window (default ±300s)
- REST rune auth verification (when enabled)
- sender-signature verification using advisor auth token
- policy gate before schema execution

Supported DM content encodings in current transport path:
- `nip44:<base64(json-envelope)>`
- `nip44:v2:<base64(json-envelope)>`
- `b64:<base64(json-envelope)>`

Advisor auth tokens are issued via `hive-client-authorize` and must be used to sign transport envelopes.

## Development
```bash
python3 -m pytest tests -q
```
