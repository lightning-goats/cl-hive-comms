#!/usr/bin/env python3
"""cl-hive-comms: Phase 6A transport/client entry-point plugin."""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Dict

from pyln.client import Plugin

from modules.comms_service import CommsService, CommsStore
from modules.transport_security import NostrDmCodec, RuneVerifier
from modules.transport_router import TransportRouter
from modules.nostr_transport import NostrTransport

plugin = Plugin()
service: CommsService | None = None
router: TransportRouter | None = None
nostr_transport: NostrTransport | None = None


plugin.add_option(
    name="hive-comms-db-path",
    default="~/.lightning/cl_hive_comms.db",
    description="SQLite path for cl-hive-comms state",
)

plugin.add_option(
    name="hive-comms-nostr-relays",
    default="wss://nos.lol,wss://relay.damus.io",
    description="Comma-separated default Nostr relay URLs",
)

plugin.add_option(
    name="hive-comms-policy-preset",
    default="moderate",
    description="Policy preset (conservative|moderate|aggressive)",
)

plugin.add_option(
    name="hive-comms-transport-max-skew-seconds",
    default="300",
    description="Allowed timestamp skew for transport envelopes",
)

plugin.add_option(
    name="hive-comms-rest-rune-required",
    default="false",
    description="Require rune authentication for REST transport ingress",
)

plugin.add_option(
    name="hive-comms-rest-rune-static",
    default="",
    description="Optional static rune token for local/test REST transport auth",
)

plugin.add_option(
    name="hive-comms-nostr-allow-plaintext",
    default="false",
    description="Allow plaintext JSON Nostr DM payloads (testing only)",
)


def _parse_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return False


def _logger(message: str, level: str = "info") -> None:
    plugin.log(message, level=level)


def _require_service() -> CommsService:
    if service is None:
        raise RuntimeError("service not initialized")
    return service


def _require_router() -> TransportRouter:
    if router is None:
        raise RuntimeError("router not initialized")
    return router


def _parse_json_object(value: Any) -> Dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            data = json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) else None
    return None


def _handle_inbound_dm(envelope: Dict[str, Any]) -> None:
    """Handle incoming DM: route locally or forward to cl-hive."""
    try:
        plaintext = envelope.get("plaintext", "")
        if not plaintext:
            return
        
        # Try parsing as JSON
        try:
            payload = json.loads(plaintext)
        except json.JSONDecodeError:
            # Not JSON, ignore or forward raw? 
            # Hive protocol might be binary wrapped in base64? 
            # For now assume JSON as per spec.
            return

        if not isinstance(payload, dict):
            return

        sender = envelope.get("pubkey")

        # 1. Check if it's a management schema (local processing)
        if "schema_type" in payload:
            _require_router().handle_message(
                sender=sender,
                message=payload,
                transport="nostr_dm"
            )
            return

        # 2. Forward to cl-hive (Coordination Layer) via RPC
        # We fire-and-forget this call to avoid blocking the inbound loop
        # processing other messages.
        def _forward():
            try:
                # Add sender context if missing
                if "sender" not in payload:
                    payload["sender"] = sender
                plugin.rpc.call("hive-inject-packet", {"payload": payload, "source": "nostr"})
            except Exception:
                # cl-hive might not be running or RPC failed
                pass
        
        threading.Thread(target=_forward, daemon=True).start()

    except Exception as e:
        _logger(f"Inbound DM error: {e}", "warn")


def _inbound_loop() -> None:
    """Pump inbound messages from the transport."""
    while True:
        try:
            if nostr_transport:
                if nostr_transport._stop_event.is_set():
                    break
                nostr_transport.process_inbound()
        except Exception as e:
            _logger(f"Inbound loop error: {e}", "warn")
        try:
            if nostr_transport and nostr_transport._stop_event.wait(0.1):
                break
        except Exception:
            time.sleep(0.1)


@plugin.init()
def init(options: Dict[str, Any], configuration: Dict[str, Any], plugin: Plugin, **kwargs: Any) -> None:
    del kwargs

    db_path_opt = str(options.get("hive-comms-db-path") or "~/.lightning/cl_hive_comms.db")
    db_path = os.path.expanduser(db_path_opt)
    if not os.path.isabs(db_path):
        lightning_dir = str(configuration.get("lightning-dir") or os.path.expanduser("~/.lightning"))
        db_path = os.path.join(lightning_dir, db_path)

    relays_csv = str(options.get("hive-comms-nostr-relays") or "")
    relays = [item.strip() for item in relays_csv.split(",") if item.strip()]
    preset = str(options.get("hive-comms-policy-preset") or "moderate").strip().lower()
    max_skew = max(1, _parse_int(options.get("hive-comms-transport-max-skew-seconds"), 300))
    rune_required = _parse_bool(options.get("hive-comms-rest-rune-required"))
    static_rune = str(options.get("hive-comms-rest-rune-static") or "")
    nostr_allow_plaintext = _parse_bool(options.get("hive-comms-nostr-allow-plaintext"))

    try:
        store = CommsStore(db_path=db_path, logger=_logger)
    except Exception as exc:
        plugin.log(f"cl-hive-comms store init failed: {exc}", level="error")
        return

    global service
    try:
        service = CommsService(
            store=store,
            rpc=plugin.rpc,
            logger=_logger,
            default_relays=relays,
            policy_preset=preset,
        )
        
        # Initialize Nostr Transport
        global nostr_transport
        privkey = store.get_nostr_state("config:privkey")
        nostr_transport = NostrTransport(plugin, store, privkey_hex=privkey, relays=relays)
        nostr_transport.receive_dm(_handle_inbound_dm)
        nostr_transport.start()
        
        # Start inbound pump thread
        threading.Thread(target=_inbound_loop, daemon=True, name="comms-inbound-pump").start()

        rune_verifier = RuneVerifier(
            store=store,
            rpc=plugin.rpc,
            required=rune_required,
            static_rune=static_rune,
            logger=_logger,
        )
        dm_codec = NostrDmCodec(
            allow_plaintext=nostr_allow_plaintext,
            logger=_logger,
        )
        global router
        router = TransportRouter(
            service=service,
            store=store,
            rune_verifier=rune_verifier,
            dm_codec=dm_codec,
            local_nostr_pubkey=str(service.identity().get("pubkey") or ""),
            logger=_logger,
            max_clock_skew_seconds=max_skew,
        )
    except Exception as exc:
        plugin.log(f"cl-hive-comms initialization failed: {exc}", level="error")
        return

    plugin.log(
        "cl-hive-comms initialized "
        f"(db_path={db_path}, policy_preset={preset}, max_skew={max_skew}, "
        f"rune_required={rune_required}, nostr_allow_plaintext={nostr_allow_plaintext}, "
        f"relays={','.join(relays)})"
    )


def _require_nostr() -> NostrTransport:
    if nostr_transport is None:
        raise RuntimeError("nostr_transport not initialized")
    return nostr_transport


@plugin.method("hive-comms-send-dm")
def hive_comms_send_dm(plugin: Plugin, recipient: str, message: str) -> Dict[str, Any]:
    """Send a Nostr DM via the comms transport."""
    del plugin
    try:
        return _require_nostr().send_dm(recipient_pubkey=recipient, plaintext=message)
    except Exception as e:
        _logger(f"hive-comms-send-dm error: {e}", "warn")
        return {"error": "send_dm failed"}


@plugin.method("hive-comms-publish-event")
def hive_comms_publish_event(plugin: Plugin, event_json: str) -> Dict[str, Any]:
    """Publish a raw Nostr event."""
    del plugin
    try:
        event = _parse_json_object(event_json)
        if event is None:
            return {"error": "event_json must be valid JSON"}
        return _require_nostr().publish(event)
    except Exception as e:
        _logger(f"hive-comms-publish-event error: {e}", "warn")
        return {"error": "publish failed"}


@plugin.method("hive-client-status")
def hive_client_status(plugin: Plugin) -> Dict[str, Any]:
    del plugin
    return _require_service().status()


@plugin.method("hive-client-identity")
def hive_client_identity(
    plugin: Plugin,
    action: str = "get",
    nsec: str = "",
    relays: str = "",
) -> Dict[str, Any]:
    del plugin
    return _require_service().identity(action=action, nsec=nsec, relays=relays)


@plugin.method("hive-client-authorize")
def hive_client_authorize(
    plugin: Plugin,
    advisor: str,
    access: str = "monitor",
    daily_limit_sats: int = 0,
    note: str = "",
) -> Dict[str, Any]:
    del plugin
    return _require_service().authorize(
        advisor=advisor,
        access=access,
        daily_limit_sats=_parse_int(daily_limit_sats, 0),
        note=note,
    )


@plugin.method("hive-client-revoke")
def hive_client_revoke(plugin: Plugin, advisor: str, reason: str = "") -> Dict[str, Any]:
    del plugin
    return _require_service().revoke(advisor=advisor, reason=reason)


@plugin.method("hive-client-discover")
def hive_client_discover(
    plugin: Plugin,
    query: str = "",
    capability: str = "",
    limit: int = 20,
) -> Dict[str, Any]:
    del plugin
    return _require_service().discover(
        query=query,
        capability=capability,
        limit=_parse_int(limit, 20),
    )


@plugin.method("hive-client-receipts")
def hive_client_receipts(
    plugin: Plugin,
    advisor: str = "",
    limit: int = 50,
) -> Dict[str, Any]:
    del plugin
    return _require_service().receipts(advisor=advisor, limit=_parse_int(limit, 50))


@plugin.method("hive-client-policy")
def hive_client_policy(
    plugin: Plugin,
    action: str = "get",
    preset: str = "",
    overrides_json: str = "",
) -> Dict[str, Any]:
    del plugin
    return _require_service().policy(action=action, preset=preset, overrides_json=overrides_json)


@plugin.method("hive-client-payments")
def hive_client_payments(
    plugin: Plugin,
    action: str = "summary",
    advisor: str = "",
    amount_sats: int = 0,
    kind: str = "bolt11",
    note: str = "",
    limit: int = 100,
) -> Dict[str, Any]:
    del plugin
    return _require_service().payments(
        action=action,
        advisor=advisor,
        amount_sats=_parse_int(amount_sats, 0),
        kind=kind,
        note=note,
        limit=_parse_int(limit, 100),
    )


@plugin.method("hive-client-trial")
def hive_client_trial(
    plugin: Plugin,
    action: str = "list",
    advisor: str = "",
    days: int = 14,
    note: str = "",
    limit: int = 100,
) -> Dict[str, Any]:
    del plugin
    return _require_service().trial(
        action=action,
        advisor=advisor,
        days=_parse_int(days, 14),
        note=note,
        limit=_parse_int(limit, 100),
    )


@plugin.method("hive-client-alias")
def hive_client_alias(
    plugin: Plugin,
    action: str = "list",
    alias: str = "",
    advisor: str = "",
    limit: int = 200,
) -> Dict[str, Any]:
    del plugin
    return _require_service().alias(
        action=action,
        alias=alias,
        advisor=advisor,
        limit=_parse_int(limit, 200),
    )


@plugin.method("hive-comms-rpc")
def hive_comms_rpc(
    plugin: Plugin,
    request: Any,
    sender: str = "rest-client",
    transport: str = "rest",
    rune: str = "",
) -> Dict[str, Any]:
    del plugin
    transport_name = str(transport or "rest").strip().lower()
    if transport_name != "rest":
        return {"error": "hive-comms-rpc only accepts transport=rest"}
    payload = _parse_json_object(request)
    if payload is None:
        return {"error": "request must be a JSON object"}
    return _require_router().handle_message(
        sender=sender,
        message=payload,
        transport="rest",
        auth={"rune": rune, "method": "hive-comms-rpc"},
    )


@plugin.method("hive-comms-nostr-ingest")
def hive_comms_nostr_ingest(plugin: Plugin, sender_pubkey: str, payload: Any) -> Dict[str, Any]:
    del plugin
    message = _parse_json_object(payload)
    if message is None:
        return {"error": "payload must be a JSON object"}
    return _require_router().handle_message(
        sender=sender_pubkey,
        message=message,
        transport="nostr_dm",
    )


@plugin.method("hive-comms-nostr-event")
def hive_comms_nostr_event(plugin: Plugin, event: Any, sender_pubkey: str = "") -> Dict[str, Any]:
    del plugin
    event_obj = _parse_json_object(event)
    if event_obj is None:
        return {"error": "event must be a JSON object"}
    decoded = _require_router().decode_nostr_event(event=event_obj, sender_hint=sender_pubkey)
    if not decoded.get("ok", False):
        return decoded
    return _require_router().handle_message(
        sender=str(decoded.get("sender") or ""),
        message=decoded.get("message") or {},
        transport="nostr_dm",
        auth={"encryption": decoded.get("encryption", "")},
    )


@plugin.method("hive-client-prune")
def hive_client_prune(plugin: Plugin, days: int = 90) -> Dict[str, Any]:
    del plugin
    return _require_service().prune(days=_parse_int(days, 90))


@plugin.method("hive-comms-register-transport")
def hive_comms_register_transport(
    plugin: Plugin,
    name: str,
    enabled: bool = True,
    metadata_json: str = "{}",
) -> Dict[str, Any]:
    del plugin
    metadata = _parse_json_object(metadata_json)
    if metadata is None:
        return {"error": "metadata_json must decode to an object"}
    return _require_router().register_transport(name=name, enabled=enabled, metadata=metadata)


@plugin.method("hive-comms-transports")
def hive_comms_transports(plugin: Plugin) -> Dict[str, Any]:
    del plugin
    return _require_router().list_transports()


if __name__ == "__main__":
    plugin.run()
