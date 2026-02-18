# cl-hive-comms Roadmap

## Implemented Baseline
1. Standalone Phase 6A plugin entrypoint (`cl-hive-comms.py`).
2. SQLite-backed core service (`modules/comms_service.py`) with:
   - local Nostr identity bootstrap
   - advisor authorize/revoke/discover
   - alias mapping
   - policy presets and overrides
   - trial lifecycle
   - payment recording and summaries
   - hash-chained management receipts
3. Unit test suite for core flows (`tests/test_comms_service.py`).

## Next Steps
1. Transport layer completion:
   - wire real Nostr relay client subscription/publish loop
   - replace base64-backed `nip44:*` compatibility codec with full NIP-44 cryptography
   - integrate CLN commando rune checks against production rune scopes
2. Marketplace publish/subscribe integration for kinds 38380+/38900+.
3. Receipt dual-signature and CLN HSM signing integration.
4. Payment orchestration plumbing for Bolt11/Bolt12/L402/Cashu execution paths.
5. Interop hooks for `cl-hive-archon` transport and credential verifier upgrades.
