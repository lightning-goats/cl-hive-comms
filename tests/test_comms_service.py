"""Unit tests for cl-hive-comms core service."""

import os
import sys
import time

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
