"""Transport routing for cl-hive-comms management envelopes."""

from __future__ import annotations

import json
import re
import threading
import time
import hashlib
import hmac
from typing import Any, Callable, Dict, List, Optional

from modules.comms_service import CommsService, CommsStore
from modules.transport_security import NostrDmCodec, RuneVerifier


class ReplayGuard:
    """Monotonic nonce guard backed by nostr_state."""

    KEY_PREFIX = "replay:"

    def __init__(self, store: CommsStore):
        self.store = store

    def validate_and_update(self, sender: str, nonce: int, now_ts: int) -> bool:
        key = f"{self.KEY_PREFIX}{sender}"
        conn = self.store.get_connection()
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT value FROM nostr_state WHERE key = ?", (key,)
            ).fetchone()
            if row is not None:
                try:
                    last_nonce = int(row["value"])
                except (TypeError, ValueError):
                    last_nonce = -1
                if nonce <= last_nonce:
                    conn.execute("ROLLBACK")
                    return False
            conn.execute(
                "INSERT INTO nostr_state (key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                (key, str(nonce), now_ts),
            )
            conn.execute("COMMIT")
            return True
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def cleanup_stale(self, max_age_seconds: int = 86400, now_ts: int = 0) -> int:
        conn = self.store.get_connection()
        cursor = conn.execute(
            "DELETE FROM nostr_state WHERE key LIKE 'replay:%' AND updated_at < ?",
            (now_ts - max_age_seconds,),
        )
        return cursor.rowcount


class RateLimiter:
    """Sliding-window per-sender rate limiter."""

    MAX_TRACKED_SENDERS = 10_000

    def __init__(self, max_per_window: int = 60, window_seconds: int = 60):
        self._windows: Dict[str, list] = {}
        self._max = max(1, int(max_per_window))
        self._window = max(1, int(window_seconds))
        self._lock = threading.Lock()

    def check(self, sender: str, now: float) -> bool:
        with self._lock:
            return self._check_unlocked(sender, now)

    def _check_unlocked(self, sender: str, now: float) -> bool:
        # Evict stale senders if tracking too many
        if len(self._windows) > self.MAX_TRACKED_SENDERS:
            cutoff = now - self._window
            stale = [k for k, v in self._windows.items() if not v or v[-1] < cutoff]
            for k in stale:
                del self._windows[k]
        stamps = self._windows.setdefault(sender, [])
        cutoff = now - self._window
        stamps[:] = [t for t in stamps if t > cutoff]
        if len(stamps) >= self._max:
            return False
        stamps.append(now)
        return True


class TransportRouter:
    """Routes validated transport messages into schema handlers."""

    TRANSPORTS_KEY = "transport:registry"

    def __init__(
        self,
        service: CommsService,
        store: CommsStore,
        rune_verifier: Optional[RuneVerifier] = None,
        dm_codec: Optional[NostrDmCodec] = None,
        local_nostr_pubkey: str = "",
        logger: Optional[Callable[[str, str], None]] = None,
        time_fn: Callable[[], float] = time.time,
        max_clock_skew_seconds: int = 300,
    ):
        self.service = service
        self.store = store
        self.rune_verifier = rune_verifier
        self.dm_codec = dm_codec
        self.local_nostr_pubkey = str(local_nostr_pubkey or "")
        self._logger = logger
        self._time_fn = time_fn
        self.max_clock_skew_seconds = max(1, int(max_clock_skew_seconds))
        self.replay_guard = ReplayGuard(store=store)
        self.rate_limiter = RateLimiter(max_per_window=60, window_seconds=60)
        self.high_danger_limiter = RateLimiter(max_per_window=5, window_seconds=60)
        self._registry_lock = threading.Lock()
        self._seed_builtin_transports()

    def _log(self, message: str, level: str = "info") -> None:
        if self._logger:
            self._logger(message, level)

    def _now(self) -> int:
        return int(self._time_fn())

    def _seed_builtin_transports(self) -> None:
        with self._registry_lock:
            current = self._read_registry()
            changed = False
            for name in ("rest", "nostr_dm"):
                if name not in current:
                    current[name] = {"enabled": True, "metadata": {"builtin": True}}
                    changed = True
            if changed:
                self._write_registry(current)

    def _read_registry(self) -> Dict[str, Dict[str, Any]]:
        raw = self.store.get_nostr_state(self.TRANSPORTS_KEY)
        if not raw:
            return {}
        try:
            data = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            return {}
        if not isinstance(data, dict):
            return {}
        result: Dict[str, Dict[str, Any]] = {}
        for key, value in data.items():
            if isinstance(key, str) and isinstance(value, dict):
                result[key] = value
        return result

    def _write_registry(self, registry: Dict[str, Dict[str, Any]]) -> None:
        self.store.set_nostr_state(
            self.TRANSPORTS_KEY,
            json.dumps(registry, sort_keys=True, separators=(",", ":")),
            self._now(),
        )

    def register_transport(self, name: str, enabled: bool = True, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        clean = str(name or "").strip()
        if not re.fullmatch(r"[a-zA-Z0-9._-]{1,64}", clean):
            return {"error": "invalid transport name"}
        with self._registry_lock:
            registry = self._read_registry()
            registry[clean] = {"enabled": bool(enabled), "metadata": metadata or {}}
            self._write_registry(registry)
        return {"ok": True, "name": clean, "enabled": bool(enabled), "metadata": metadata or {}}

    def list_transports(self) -> Dict[str, Any]:
        with self._registry_lock:
            registry = self._read_registry()
        rows = []
        for name in sorted(registry.keys()):
            row = registry[name]
            rows.append(
                {
                    "name": name,
                    "enabled": bool(row.get("enabled", False)),
                    "metadata": row.get("metadata", {}),
                }
            )
        return {"ok": True, "count": len(rows), "transports": rows}

    def _is_transport_enabled(self, name: str) -> bool:
        with self._registry_lock:
            registry = self._read_registry()
        row = registry.get(name)
        if not row:
            return False
        return bool(row.get("enabled", False))

    def _danger_for_schema(self, schema_type: str, schema_payload: Dict[str, Any]) -> int:
        action = str(schema_payload.get("action") or "").strip().lower()
        if schema_type.startswith("hive:monitor/") or schema_type in ("hive:discover/v1", "hive:receipts/v1"):
            return 1
        if schema_type == "hive:identity/v1":
            if action in ("import", "rotate"):
                return 10  # Never allow via transport
            return 2
        if schema_type == "hive:alias/v1":
            if action in ("remove", "delete"):
                return 5
            return 2
        if schema_type == "hive:policy/v1":
            if action in ("reset", "set-preset"):
                return 7
            if action in ("set-overrides", "update", "set"):
                return 6
            return 2
        if schema_type == "hive:authorize/v1":
            access = str(schema_payload.get("access") or "").lower()
            if action in ("revoke", "deny"):
                return 4
            if "admin" in access:
                return 8
            return 5
        if schema_type == "hive:payments/v1":
            if action == "record":
                amount = 0
                try:
                    amount = int(schema_payload.get("amount_sats") or 0)
                except (TypeError, ValueError):
                    pass
                if amount > 100_000:
                    return 7
                if amount > 10_000:
                    return 6
                return 5
            return 2
        if schema_type == "hive:trial/v1":
            if action == "start":
                return 4
            if action == "stop":
                return 3
            return 2
        # Unknown schemas get high danger score to require explicit policy allowance
        return 9

    def _validate_message(self, message: Dict[str, Any]) -> Optional[str]:
        if not isinstance(message, dict):
            return "request must be a JSON object"
        schema_type = message.get("schema_type")
        schema_payload = message.get("schema_payload")
        signature = message.get("signature")
        nonce = message.get("nonce")
        timestamp = message.get("timestamp")

        if not isinstance(schema_type, str) or not schema_type.strip():
            return "missing schema_type"
        if not isinstance(schema_payload, dict):
            return "missing schema_payload object"
        if not isinstance(signature, str) or not signature.strip():
            return "missing signature"
        if not isinstance(nonce, int) or nonce < 0:
            return "invalid nonce"
        if not isinstance(timestamp, int) or timestamp <= 0:
            return "invalid timestamp"
        try:
            raw_size = len(json.dumps(message, separators=(",", ":")))
            if raw_size > 65535:
                return "message exceeds maximum size (65535 bytes)"
        except (TypeError, ValueError):
            return "message not serializable"
        return None

    def _authorize_rest(self, schema_type: str, auth: Optional[Dict[str, Any]]) -> Optional[str]:
        if not self.rune_verifier:
            return None
        context = auth if isinstance(auth, dict) else {}
        rune = str(context.get("rune") or "")
        method = str(context.get("method") or schema_type or "hive-comms-rpc")
        verified = self.rune_verifier.verify(rune=rune, method=method)
        if not verified.get("ok", False):
            return str(verified.get("error") or "rune verification failed")
        return None

    def _check_schema_permission(self, schema_type: str, permissions: list) -> bool:
        """Check if the given permission list allows access to this schema."""
        # Monitor schemas are always allowed for any active advisor
        if schema_type.startswith("hive:monitor/") or schema_type in ("hive:discover/v1", "hive:receipts/v1"):
            return True
        # Admin permissions grant everything
        if "admin" in permissions:
            return True
        # Map schemas to required permission keywords
        schema_permission_map = {
            "hive:authorize/v1": ["admin"],
            "hive:policy/v1": ["admin", "policy"],
            "hive:identity/v1": ["admin"],
            "hive:payments/v1": ["admin", "payments", "payment"],
            "hive:trial/v1": ["admin", "trial"],
            "hive:alias/v1": ["admin", "alias"],
        }
        required = schema_permission_map.get(schema_type, [])
        if not required:
            # Unknown schemas require admin permission
            return "admin" in permissions
        return any(p in required for p in permissions)

    def _canonical_signed_payload(self, message: Dict[str, Any]) -> str:
        envelope = {
            "schema_type": message.get("schema_type"),
            "schema_payload": message.get("schema_payload"),
            "nonce": message.get("nonce"),
            "timestamp": message.get("timestamp"),
        }
        return json.dumps(envelope, sort_keys=True, separators=(",", ":"))

    def _verify_sender_signature(self, advisor_id: str, message: Dict[str, Any]) -> bool:
        token = self.service.store.get_advisor_auth_token(advisor_id)
        if not token:
            return False
        signature = str(message.get("signature") or "").strip().lower()
        if signature.startswith("hmac-sha256:"):
            signature = signature.split(":", 1)[1]
        if not re.fullmatch(r"[0-9a-f]{64}", signature):
            return False
        canonical = self._canonical_signed_payload(message)
        expected = hmac.new(
            token.encode("utf-8"),
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(signature, expected)

    def decode_nostr_event(self, event: Dict[str, Any], sender_hint: str = "") -> Dict[str, Any]:
        if not self.dm_codec:
            return {"error": "nostr DM codec unavailable"}
        decoded = self.dm_codec.decode_event(event=event, recipient_pubkey=self.local_nostr_pubkey)
        if not decoded.get("ok", False):
            return decoded
        sender = str(decoded.get("sender_pubkey") or "")
        hint = str(sender_hint or "").strip()
        if hint and sender and hint != sender:
            return {"error": "sender mismatch between event and hint"}
        return {
            "ok": True,
            "sender": sender or hint,
            "message": decoded.get("payload") or {},
            "encryption": str(decoded.get("encryption") or ""),
        }

    def handle_message(
        self,
        sender: str,
        message: Dict[str, Any],
        transport: str = "rest",
        auth: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        now_ts = self._now()
        sender_id = str(sender or "").strip()
        if not sender_id:
            return {"error": "missing sender"}

        if not self.rate_limiter.check(sender_id, float(now_ts)):
            return {"error": "rate limit exceeded", "transport": str(transport or "rest").strip()}

        transport_name = str(transport or "rest").strip()
        if not self._is_transport_enabled(transport_name):
            return {"error": "transport disabled", "transport": transport_name}

        err = self._validate_message(message)
        if err:
            return {"error": err, "transport": transport_name}

        schema_type = str(message["schema_type"]).strip()
        schema_payload = dict(message["schema_payload"])
        nonce = int(message["nonce"])
        ts = int(message["timestamp"])

        if transport_name == "rest":
            auth_err = self._authorize_rest(schema_type=schema_type, auth=auth)
            if auth_err:
                return {"error": auth_err, "transport": transport_name}

        if abs(now_ts - ts) > self.max_clock_skew_seconds:
            return {
                "error": "timestamp outside allowed skew",
                "max_clock_skew_seconds": self.max_clock_skew_seconds,
                "transport": transport_name,
            }

        # --- Sender authorization (S1/S2/C1/C2) ---
        advisor = self.service.store.get_advisor(sender_id)
        if not advisor or advisor.get("status") != "active":
            return {"error": "unauthorized sender", "transport": transport_name}
        advisor_id = str(advisor.get("advisor_id") or "")
        if not advisor_id:
            return {"error": "unauthorized sender", "transport": transport_name}

        if not self._verify_sender_signature(advisor_id=advisor_id, message=message):
            return {"error": "invalid sender signature", "transport": transport_name}
        try:
            permissions = json.loads(str(advisor.get("permissions_json") or "[]"))
        except (TypeError, json.JSONDecodeError):
            permissions = []
        if not isinstance(permissions, list):
            permissions = []
        if not self._check_schema_permission(schema_type, permissions):
            return {"error": "insufficient permissions for schema", "transport": transport_name}

        danger = self._danger_for_schema(schema_type, schema_payload)
        if danger >= 5 and not self.high_danger_limiter.check(sender_id, float(now_ts)):
            return {"error": "rate limit exceeded for high-danger operation", "transport": transport_name}
        policy = self.service.policy_engine.evaluate(schema_id=schema_type, danger_score=danger)
        if not policy.get("allowed", False):
            return {"error": policy.get("reason") or "blocked by policy", "transport": transport_name}
        if policy.get("requires_confirmation", False):
            return {
                "error": "confirmation required by policy",
                "requires_confirmation": True,
                "transport": transport_name,
            }

        # Consume nonce only after policy evaluation passes (avoids burning nonces on rejected requests)
        if not self.replay_guard.validate_and_update(sender_id, nonce, now_ts):
            return {"error": "replay rejected: nonce not monotonic", "transport": transport_name}

        result = self.service.execute_schema(schema_type=schema_type, schema_payload=schema_payload)
        if isinstance(result, dict) and "error" in result:
            return {
                "error": str(result.get("error") or "request failed"),
                "transport": transport_name,
                "schema_type": schema_type,
                "nonce": nonce,
                "sender": sender_id,
            }

        return {
            "ok": True,
            "transport": transport_name,
            "schema_type": schema_type,
            "nonce": nonce,
            "sender": sender_id,
            "result": result,
        }
