#!/usr/bin/env python3
"""cl-hive-comms: Phase 6A transport/client entry-point plugin."""

from __future__ import annotations

import json
import os
from typing import Any, Dict

from pyln.client import Plugin

from modules.comms_service import CommsService, CommsStore
from modules.transport_security import NostrDmCodec, RuneVerifier
from modules.transport_router import TransportRouter

plugin = Plugin()
service: CommsService | None = None
router: TransportRouter | None = None


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
