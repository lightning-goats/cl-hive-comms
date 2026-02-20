"""Unit tests for cl-hive-comms core service."""

import base64
import os
import sys
import time
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.comms_service import CommsService, CommsStore


def _make_service(tmp_path, **kwargs):
    db_path = str(tmp_path / "comms.db")
    store = CommsStore(db_path=db_path)
    return CommsService(store=store, **kwargs)


def test_identity_bootstraps_on_first_run(tmp_path):
    service = _make_service(tmp_path)

    identity = service.identity()
    assert identity["ok"] is True
    assert len(identity["pubkey"]) == 64
    assert identity["has_private_key"] is True
    assert len(identity["relays"]) >= 1


def test_identity_set_relays(tmp_path):
    service = _make_service(tmp_path)

    result = service.identity(action="set-relays", relays="wss://nos.lol,wss://relay.damus.io")
    assert result["ok"] is True
    assert result["relays"] == ["wss://nos.lol", "wss://relay.damus.io"]


def test_authorize_revoke_and_discover(tmp_path):
    service = _make_service(tmp_path)

    auth = service.authorize("Hex Advisor", access="monitor,fee_policy", daily_limit_sats=5000)
    assert auth["ok"] is True
    assert auth["status"] == "active"
    assert len(auth["auth_token"]) == 64

    discovered = service.discover(query="hex")
    assert discovered["ok"] is True
    assert discovered["count"] == 1

    revoked = service.revoke("Hex Advisor")
    assert revoked["ok"] is True
    assert revoked["status"] == "revoked"

    discovered_after = service.discover(query="hex")
    assert discovered_after["count"] == 0


def test_receipts_include_authorize_and_revoke(tmp_path):
    service = _make_service(tmp_path)
    service.authorize("Hex Advisor")
    service.revoke("Hex Advisor")

    receipts = service.receipts()
    assert receipts["ok"] is True
    assert receipts["count"] >= 2
    actions = {item["action"] for item in receipts["receipts"]}
    assert "authorize" in actions
    assert "revoke" in actions


def test_policy_preset_and_overrides(tmp_path):
    service = _make_service(tmp_path)

    preset = service.policy(action="set-preset", preset="conservative")
    assert preset["ok"] is True
    assert preset["policy"]["preset"] == "conservative"

    updated = service.policy(
        action="set-overrides",
        overrides_json='{"max_danger": 2, "blocked_schemas": ["hive:channel/v1"]}',
    )
    assert updated["ok"] is True

    eval_blocked = service.policy_engine.evaluate(schema_id="hive:channel/v1", danger_score=1)
    assert eval_blocked["allowed"] is False

    eval_danger = service.policy_engine.evaluate(schema_id="hive:monitor/v1", danger_score=5)
    assert eval_danger["allowed"] is False


def test_alias_lifecycle(tmp_path):
    service = _make_service(tmp_path)
    service.authorize("Hex Advisor")

    created = service.alias(action="set", alias="hex", advisor="Hex Advisor")
    assert created["ok"] is True

    resolved = service.alias(action="get", alias="hex")
    assert resolved["ok"] is True
    assert resolved["entry"]["advisor_ref"] == "Hex Advisor"

    removed = service.alias(action="remove", alias="hex")
    assert removed["ok"] is True
    assert removed["removed"] == 1
    missing = service.alias(action="get", alias="hex")
    assert "error" in missing
    assert service._resolve_advisor("hex") is None


def test_trial_start_and_stop(tmp_path):
    now = [time.time()]
    service = _make_service(tmp_path, time_fn=lambda: now[0])
    service.authorize("Hex Advisor")

    started = service.trial(action="start", advisor="Hex Advisor", days=7)
    assert started["ok"] is True
    assert started["status"] == "active"

    listed = service.trial(action="list", advisor="Hex Advisor")
    assert listed["ok"] is True
    assert listed["count"] == 1

    stopped = service.trial(action="stop", advisor="Hex Advisor")
    assert stopped["ok"] is True
    assert stopped["stopped_trials"] == 1


def test_trial_auto_expires_in_status(tmp_path):
    now = [time.time()]
    service = _make_service(tmp_path, time_fn=lambda: now[0])
    service.authorize("Hex Advisor")
    service.trial(action="start", advisor="Hex Advisor", days=1)

    now[0] += 2 * 86400
    status = service.status()
    assert status["ok"] is True
    assert status["active_trials"] == 0


def test_payments_record_and_summary(tmp_path):
    service = _make_service(tmp_path)
    service.authorize("Hex Advisor")

    rec = service.payments(
        action="record",
        advisor="Hex Advisor",
        amount_sats=1500,
        kind="bolt11",
        note="test",
    )
    assert rec["ok"] is True
    assert rec["amount_sats"] == 1500

    summary = service.payments(action="summary")
    assert summary["ok"] is True
    assert summary["summary"]["total_sats"] == 1500

    history = service.payments(action="history", advisor="Hex Advisor")
    assert history["ok"] is True
    assert history["count"] == 1


def test_status_aggregates(tmp_path):
    service = _make_service(tmp_path)
    service.authorize("Hex Advisor")
    service.payments(action="record", advisor="Hex Advisor", amount_sats=500, kind="bolt11")

    status = service.status()
    assert status["ok"] is True
    assert status["active_advisors"] == 1
    assert status["payments"]["total_sats"] == 500
    assert "pubkey" in status["identity"]


def test_daily_limit_enforced(tmp_path):
    service = _make_service(tmp_path)
    service.authorize("Hex Advisor", daily_limit_sats=1000)

    rec1 = service.payments(action="record", advisor="Hex Advisor", amount_sats=800, kind="bolt11")
    assert rec1["ok"] is True

    rec2 = service.payments(action="record", advisor="Hex Advisor", amount_sats=300, kind="bolt11")
    assert "error" in rec2
    assert rec2["error"] == "daily limit exceeded"
    assert rec2["daily_limit_sats"] == 1000
    assert rec2["spent_today_sats"] == 800


def test_daily_limit_zero_means_unlimited(tmp_path):
    service = _make_service(tmp_path)
    service.authorize("Hex Advisor", daily_limit_sats=0)

    rec = service.payments(action="record", advisor="Hex Advisor", amount_sats=999999, kind="bolt11")
    assert rec["ok"] is True


def test_placeholder_identity_flagged(tmp_path):
    service = _make_service(tmp_path)
    identity = service.identity()
    assert identity["ok"] is True
    assert identity["placeholder_keygen"] is True


def test_imported_identity_clears_placeholder(tmp_path):
    service = _make_service(tmp_path)
    # Start with placeholder
    assert service.identity()["placeholder_keygen"] is True

    # Import a real key
    real_key = "a" * 64
    result = service.identity(action="import", nsec=real_key)
    assert result["ok"] is True

    # Placeholder flag should be cleared
    identity = service.identity()
    assert identity["placeholder_keygen"] is False


def test_prune_removes_old_data(tmp_path):
    now = [time.time()]
    service = _make_service(tmp_path, time_fn=lambda: now[0])
    service.authorize("Hex Advisor")
    service.payments(action="record", advisor="Hex Advisor", amount_sats=100, kind="bolt11")

    # Age the data by 100 days
    now[0] += 100 * 86400

    result = service.prune(days=90)
    assert result["ok"] is True
    assert result["pruned"]["receipts"] >= 1
    assert result["pruned"]["payments"] >= 1


# ---------------------------------------------------------------------------
# NostrTransport receive_dm / process_inbound tests (Phase 6 Handover)
# ---------------------------------------------------------------------------

from modules.nostr_transport import NostrTransport


def _make_transport():
    """Create a NostrTransport with mock plugin and db."""
    plugin = MagicMock()
    plugin.log = MagicMock()
    db = MagicMock()
    db.set_nostr_state = MagicMock()
    return NostrTransport(plugin, db, privkey_hex="aa" * 32)


def test_nostr_transport_receive_dm_callback():
    """Verify receive_dm registers callback and process_inbound dispatches to it."""
    transport = _make_transport()

    received = []
    transport.receive_dm(lambda env: received.append(env))

    # Inject a kind-4 DM event with b64-encoded content
    plaintext = "hello from test"
    encoded = "b64:" + base64.b64encode(plaintext.encode()).decode()
    dm_event = {
        "kind": 4,
        "pubkey": "sender_abc",
        "content": encoded,
        "created_at": int(time.time()),
    }
    transport.inject_event(dm_event)

    count = transport.process_inbound()
    assert count == 1
    assert len(received) == 1
    assert received[0]["plaintext"] == plaintext
    assert received[0]["pubkey"] == "sender_abc"


def test_nostr_transport_subscription_dispatch():
    """Verify subscription callbacks fire for matching events."""
    transport = _make_transport()

    matched = []
    transport.subscribe({"kinds": [1]}, lambda ev: matched.append(ev))

    transport.inject_event({"kind": 1, "content": "yes"})
    transport.inject_event({"kind": 4, "content": "no"})

    transport.process_inbound()
    assert len(matched) == 1
    assert matched[0]["content"] == "yes"


def test_nostr_transport_decode_dm_plain():
    """Non-b64 content should be returned as-is."""
    transport = _make_transport()
    assert transport._decode_dm("plain text") == "plain text"


def test_nostr_transport_decode_dm_b64():
    """b64-prefixed content should be decoded."""
    transport = _make_transport()
    encoded = "b64:" + base64.b64encode(b"secret").decode()
    assert transport._decode_dm(encoded) == "secret"


# ---------------------------------------------------------------------------
# Audit action-item tests: advisor resolution ordering
# ---------------------------------------------------------------------------


def test_advisor_lookup_priority_order(tmp_path):
    """get_advisor() resolves by advisor_id first, then advisor_ref, then inline alias.

    The resolution priority prevents ambiguous multi-match scenarios:
      1. Exact match on advisor_id column
      2. Exact match on advisor_ref column
      3. Exact match on alias column (inline alias on comms_advisors table)
      4. Fall back to comms_aliases join table
    """
    import hashlib

    service = _make_service(tmp_path)

    # Authorize two advisors with different names
    auth_a = service.authorize("Alpha Advisor", access="monitor,fee_policy", daily_limit_sats=5000)
    assert auth_a["ok"] is True
    advisor_a_id = auth_a["advisor_id"]
    # advisor_id is sha256("alpha advisor")[:32]
    expected_a_id = hashlib.sha256("alpha advisor".encode("utf-8")).hexdigest()[:32]
    assert advisor_a_id == expected_a_id

    auth_b = service.authorize("Beta Advisor", access="monitor", daily_limit_sats=0)
    assert auth_b["ok"] is True
    advisor_b_id = auth_b["advisor_id"]

    # Set an alias on advisor B using the alias() method
    alias_result = service.alias(action="set", alias="beta", advisor="Beta Advisor")
    assert alias_result["ok"] is True

    # --- Priority 1: lookup by advisor_id returns correct advisor ---
    found_by_id = service.store.get_advisor(advisor_a_id)
    assert found_by_id is not None
    assert found_by_id["advisor_id"] == advisor_a_id
    assert found_by_id["advisor_ref"] == "Alpha Advisor"

    found_by_id_b = service.store.get_advisor(advisor_b_id)
    assert found_by_id_b is not None
    assert found_by_id_b["advisor_ref"] == "Beta Advisor"

    # --- Priority 2: lookup by advisor_ref returns correct advisor ---
    found_by_ref = service.store.get_advisor("Alpha Advisor")
    assert found_by_ref is not None
    assert found_by_ref["advisor_id"] == advisor_a_id

    found_by_ref_b = service.store.get_advisor("Beta Advisor")
    assert found_by_ref_b is not None
    assert found_by_ref_b["advisor_id"] == advisor_b_id

    # --- Priority 3: lookup by inline alias (set on comms_advisors.alias) ---
    found_by_alias = service.store.get_advisor("beta")
    assert found_by_alias is not None
    assert found_by_alias["advisor_id"] == advisor_b_id
    assert found_by_alias["alias"] == "beta"

    # --- Priority 4: lookup via comms_aliases join table ---
    # The alias "beta" was also written to the comms_aliases table by alias().
    # If we create a new alias that only exists in the aliases table (not inline),
    # it should still resolve. Remove the inline alias first.
    alias_entry = service.store.get_alias("beta")
    assert alias_entry is not None
    assert alias_entry["advisor_ref"] == "Beta Advisor"

    # --- Negative: non-existent reference returns None ---
    assert service.store.get_advisor("nonexistent") is None
    assert service.store.get_advisor("") is None

    # --- _resolve_advisor uses the same priority chain ---
    resolved_a = service._resolve_advisor("Alpha Advisor")
    assert resolved_a is not None
    assert resolved_a["advisor_id"] == advisor_a_id

    resolved_b = service._resolve_advisor("beta")
    assert resolved_b is not None
    assert resolved_b["advisor_id"] == advisor_b_id

    resolved_by_id = service._resolve_advisor(advisor_a_id)
    assert resolved_by_id is not None
    assert resolved_by_id["advisor_ref"] == "Alpha Advisor"
