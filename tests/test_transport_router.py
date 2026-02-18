"""Unit tests for cl-hive-comms transport router."""

import hashlib
import hmac
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.comms_service import CommsService, CommsStore
from modules.transport_security import NostrDmCodec, RuneVerifier
from modules.transport_router import TransportRouter


def _make_router(tmp_path, **kwargs):
    db_path = str(tmp_path / "comms.db")
    store = CommsStore(db_path=db_path)
    service = CommsService(store=store, time_fn=kwargs.get("time_fn", time.time))

    rune_verifier = kwargs.get("rune_verifier")
    if rune_verifier is None and kwargs.get("rune_required"):
        rune_verifier = RuneVerifier(
            store=store,
            rpc=kwargs.get("rpc"),
            required=True,
            static_rune=str(kwargs.get("static_rune") or ""),
        )

    dm_codec = kwargs.get("dm_codec")
    if dm_codec is None:
        dm_codec = NostrDmCodec(allow_plaintext=bool(kwargs.get("allow_plaintext_nostr", False)))

    router = TransportRouter(
        service=service,
        store=store,
        rune_verifier=rune_verifier,
        dm_codec=dm_codec,
        local_nostr_pubkey=str(service.identity().get("pubkey") or ""),
        time_fn=kwargs.get("time_fn", time.time),
        max_clock_skew_seconds=kwargs.get("max_clock_skew_seconds", 300),
    )

    if kwargs.get("authorize_sender", True):
        service.authorize("npub1", access="admin")
        service.authorize("rest-client", access="admin")
        service.authorize("ab" * 32, access="admin")

    return service, router


def _envelope(schema_type, schema_payload, nonce, timestamp):
    return {
        "schema_type": schema_type,
        "schema_payload": schema_payload,
        "credential": {"mode": "nostr"},
        "payment_proof": {},
        "signature": "",
        "nonce": nonce,
        "timestamp": timestamp,
    }


def _advisor_token(service, sender):
    row = service.store.get_advisor(sender)
    if not row:
        row = service.store.get_advisor(str(sender))
    if not row:
        return ""
    return str(service.store.get_advisor_auth_token(str(row["advisor_id"])) or "")


def _sign_message(message, token):
    canonical = json.dumps(
        {
            "schema_type": message.get("schema_type"),
            "schema_payload": message.get("schema_payload"),
            "nonce": message.get("nonce"),
            "timestamp": message.get("timestamp"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    msg = dict(message)
    msg["signature"] = hmac.new(
        token.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return msg


def test_rejects_invalid_envelope(tmp_path):
    service, router = _make_router(tmp_path)
    res = router.handle_message(sender="npub1", message={"schema_type": "hive:monitor/v1"}, transport="rest")
    assert "error" in res
    assert "schema_payload" in res["error"]


def test_rejects_timestamp_skew(tmp_path):
    now = [time.time()]
    service, router = _make_router(tmp_path, time_fn=lambda: now[0], max_clock_skew_seconds=60)
    old = int(now[0]) - 3600
    token = _advisor_token(service, "npub1")
    msg = _sign_message(_envelope("hive:monitor/v1", {"action": "status"}, nonce=1, timestamp=old), token)
    res = router.handle_message(sender="npub1", message=msg, transport="rest")
    assert "error" in res
    assert "timestamp outside allowed skew" in res["error"]


def test_replay_nonce_rejected(tmp_path):
    now = [time.time()]
    service, router = _make_router(tmp_path, time_fn=lambda: now[0])
    token = _advisor_token(service, "npub1")

    msg1 = _sign_message(_envelope("hive:monitor/v1", {"action": "status"}, nonce=5, timestamp=int(now[0])), token)
    ok = router.handle_message(sender="npub1", message=msg1, transport="rest")
    assert ok["ok"] is True

    msg2 = _sign_message(_envelope("hive:monitor/v1", {"action": "status"}, nonce=5, timestamp=int(now[0])), token)
    denied = router.handle_message(sender="npub1", message=msg2, transport="rest")
    assert "error" in denied
    assert "nonce not monotonic" in denied["error"]


def test_invalid_sender_signature_rejected(tmp_path):
    now = int(time.time())
    service, router = _make_router(tmp_path)
    bad = _envelope("hive:monitor/v1", {"action": "status"}, nonce=1, timestamp=now)
    bad["signature"] = "00" * 32
    res = router.handle_message(sender="npub1", message=bad, transport="rest")
    assert "error" in res
    assert "invalid sender signature" in res["error"]


def test_dispatch_authorize_and_discover(tmp_path):
    now = int(time.time())
    service, router = _make_router(tmp_path)
    token = _advisor_token(service, "npub1")

    auth = router.handle_message(
        sender="npub1",
        message=_sign_message(
            _envelope(
                "hive:authorize/v1",
                {
                    "action": "authorize",
                    "advisor": "Hex Advisor",
                    "access": "monitor,fee_policy",
                    "daily_limit_sats": 1000,
                },
                nonce=1,
                timestamp=now,
            ),
            token,
        ),
        transport="rest",
    )
    assert auth["ok"] is True

    disc = router.handle_message(
        sender="npub1",
        message=_sign_message(
            _envelope(
                "hive:discover/v1",
                {"action": "search", "query": "hex"},
                nonce=2,
                timestamp=now,
            ),
            token,
        ),
        transport="rest",
    )
    assert disc["ok"] is True
    assert disc["result"]["count"] == 1


def test_policy_blocks_schema_via_router(tmp_path):
    now = int(time.time())
    service, router = _make_router(tmp_path)
    service.policy(action="set-overrides", overrides_json='{"blocked_schemas": ["hive:payments/v1"]}')
    token = _advisor_token(service, "npub1")

    blocked = router.handle_message(
        sender="npub1",
        message=_sign_message(
            _envelope("hive:payments/v1", {"action": "summary"}, nonce=1, timestamp=now),
            token,
        ),
        transport="rest",
    )
    assert "error" in blocked
    assert "schema blocked by local policy" in blocked["error"]


def test_transport_registry_and_nostr_path(tmp_path):
    now = int(time.time())
    service, router = _make_router(tmp_path)

    listed = router.list_transports()
    assert listed["ok"] is True
    names = {row["name"] for row in listed["transports"]}
    assert "rest" in names
    assert "nostr_dm" in names

    reg = router.register_transport("custom_test", enabled=False, metadata={"x": 1})
    assert reg["ok"] is True

    token = _advisor_token(service, "npub1")
    msg = _sign_message(_envelope("hive:monitor/v1", {"action": "status"}, nonce=1, timestamp=now), token)
    disabled = router.handle_message(sender="npub1", message=msg, transport="custom_test")
    assert "error" in disabled
    assert "transport disabled" in disabled["error"]


def test_rest_rune_required_blocks_without_rune(tmp_path):
    now = int(time.time())
    service, router = _make_router(tmp_path, rune_required=True, static_rune="topsecret")
    token = _advisor_token(service, "rest-client")

    denied = router.handle_message(
        sender="rest-client",
        message=_sign_message(_envelope("hive:monitor/v1", {"action": "status"}, nonce=1, timestamp=now), token),
        transport="rest",
    )
    assert "error" in denied
    assert "missing rune" in denied["error"]


def test_rest_rune_static_allows_when_valid(tmp_path):
    now = int(time.time())
    service, router = _make_router(tmp_path, rune_required=True, static_rune="topsecret")
    token = _advisor_token(service, "rest-client")

    allowed = router.handle_message(
        sender="rest-client",
        message=_sign_message(_envelope("hive:monitor/v1", {"action": "status"}, nonce=1, timestamp=now), token),
        transport="rest",
        auth={"rune": "topsecret", "method": "hive-comms-rpc"},
    )
    assert allowed["ok"] is True


def test_decode_nostr_event_and_dispatch(tmp_path):
    now = int(time.time())
    service, router = _make_router(tmp_path)
    recipient = str(service.identity().get("pubkey") or "")
    token = _advisor_token(service, "ab" * 32)
    dm_message = _sign_message(
        _envelope("hive:monitor/v1", {"action": "status"}, nonce=1, timestamp=now),
        token,
    )

    import base64

    event = {
        "kind": 4,
        "pubkey": "ab" * 32,
        "tags": [["p", recipient]],
        "content": "nip44:" + base64.b64encode(
            json.dumps(dm_message, separators=(",", ":")).encode("utf-8")
        ).decode("ascii"),
    }

    decoded = router.decode_nostr_event(event=event, sender_hint="ab" * 32)
    assert decoded["ok"] is True

    response = router.handle_message(
        sender=decoded["sender"],
        message=decoded["message"],
        transport="nostr_dm",
    )
    assert response["ok"] is True


def test_unauthorized_sender_rejected(tmp_path):
    now = int(time.time())
    _, router = _make_router(tmp_path, authorize_sender=False)
    msg = _envelope("hive:monitor/v1", {"action": "status"}, nonce=1, timestamp=now)
    msg["signature"] = "00" * 32
    res = router.handle_message(sender="unknown_sender", message=msg, transport="rest")
    assert "error" in res
    assert "unauthorized" in res["error"]


def test_insufficient_permissions_rejected(tmp_path):
    now = int(time.time())
    service, router = _make_router(tmp_path, authorize_sender=False)
    # Authorize with monitor-only permissions
    service.authorize("npub_monitor", access="monitor")
    token = _advisor_token(service, "npub_monitor")
    msg = _sign_message(
        _envelope("hive:authorize/v1", {"action": "authorize", "advisor": "test"}, nonce=1, timestamp=now),
        token,
    )
    res = router.handle_message(sender="npub_monitor", message=msg, transport="rest")
    assert "error" in res
    assert "insufficient permissions" in res["error"]


def test_identity_import_blocked_by_danger_score(tmp_path):
    now = int(time.time())
    service, router = _make_router(tmp_path)
    token = _advisor_token(service, "npub1")
    msg = _sign_message(
        _envelope("hive:identity/v1", {"action": "import", "nsec": "ab" * 32}, nonce=10, timestamp=now),
        token,
    )
    res = router.handle_message(sender="npub1", message=msg, transport="rest")
    assert "error" in res


def test_rate_limiter_blocks_flood(tmp_path):
    now = [time.time()]
    service, router = _make_router(tmp_path, time_fn=lambda: now[0])
    token = _advisor_token(service, "npub1")

    # Send 60 messages (the rate limit)
    for i in range(60):
        msg = _sign_message(
            _envelope("hive:monitor/v1", {"action": "status"}, nonce=i + 1, timestamp=int(now[0])),
            token,
        )
        res = router.handle_message(sender="npub1", message=msg, transport="rest")
        assert res.get("ok") is True, f"message {i+1} failed: {res}"

    # 61st should be rate limited
    msg = _sign_message(
        _envelope("hive:monitor/v1", {"action": "status"}, nonce=61, timestamp=int(now[0])),
        token,
    )
    res = router.handle_message(sender="npub1", message=msg, transport="rest")
    assert "error" in res
    assert "rate limit" in res["error"]


def test_oversized_message_rejected(tmp_path):
    now = int(time.time())
    service, router = _make_router(tmp_path)
    token = _advisor_token(service, "npub1")

    big_payload = {"action": "status", "data": "x" * 70000}
    msg = _sign_message(_envelope("hive:monitor/v1", big_payload, nonce=1, timestamp=now), token)
    res = router.handle_message(sender="npub1", message=msg, transport="rest")
    assert "error" in res
    assert "maximum size" in res["error"]
