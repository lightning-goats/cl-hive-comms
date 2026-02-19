"""Core service and persistence layer for cl-hive-comms."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_hex_len(value: str, expected_len: int) -> bool:
    if not isinstance(value, str) or len(value) != expected_len:
        return False
    return bool(re.fullmatch(r"[0-9a-fA-F]+", value))


def _now_ts(time_fn: Callable[[], float]) -> int:
    return int(time_fn())


def _normalize_relays_csv(relays: str) -> List[str]:
    if not isinstance(relays, str):
        return []
    items = [item.strip() for item in relays.split(",")]
    return [item for item in items if item]


def _parse_json_object(raw: str) -> Optional[Dict[str, Any]]:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


class CommsStore:
    """SQLite persistence for cl-hive-comms local state."""

    def __init__(self, db_path: str, logger: Optional[Callable[[str, str], None]] = None):
        self.db_path = os.path.expanduser(db_path)
        self._logger = logger
        self._local = threading.local()

    def _log(self, message: str, level: str = "info") -> None:
        if self._logger:
            self._logger(message, level)

    def _get_connection(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            db_dir = os.path.dirname(self.db_path)
            if db_dir:
                os.makedirs(db_dir, mode=0o700, exist_ok=True)
            conn = sqlite3.connect(
                self.db_path,
                isolation_level=None,
                timeout=30.0,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            self._local.conn = conn
            try:
                os.chmod(self.db_path, 0o600)
            except OSError:
                pass
        return conn

    def get_connection(self) -> "sqlite3.Connection":
        """Public accessor for thread-local DB connection (used by ReplayGuard)."""
        return self._get_connection()

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None

    def initialize(self) -> None:
        conn = self._get_connection()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS nostr_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS management_receipts (
                receipt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at INTEGER NOT NULL,
                actor TEXT NOT NULL,
                schema_id TEXT NOT NULL,
                action TEXT NOT NULL,
                params_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                receipt_hash TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_management_receipts_actor_created
            ON management_receipts(actor, created_at DESC)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS comms_advisors (
                advisor_id TEXT PRIMARY KEY,
                advisor_ref TEXT NOT NULL UNIQUE,
                alias TEXT,
                permissions_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                daily_limit_sats INTEGER NOT NULL DEFAULT 0,
                note TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_comms_advisors_status
            ON comms_advisors(status, updated_at DESC)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS comms_aliases (
                alias TEXT PRIMARY KEY,
                advisor_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(advisor_id) REFERENCES comms_advisors(advisor_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS comms_trials (
                trial_id TEXT PRIMARY KEY,
                advisor_id TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                ends_at INTEGER NOT NULL,
                status TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                FOREIGN KEY(advisor_id) REFERENCES comms_advisors(advisor_id)
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_comms_trials_advisor_status
            ON comms_trials(advisor_id, status, ends_at DESC)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS comms_payments (
                payment_id TEXT PRIMARY KEY,
                advisor_id TEXT NOT NULL,
                amount_sats INTEGER NOT NULL,
                kind TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                FOREIGN KEY(advisor_id) REFERENCES comms_advisors(advisor_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS comms_advisor_auth (
                advisor_id TEXT PRIMARY KEY,
                auth_token TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(advisor_id) REFERENCES comms_advisors(advisor_id)
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_comms_payments_advisor_created
            ON comms_payments(advisor_id, created_at DESC)
            """
        )
        conn.execute("PRAGMA optimize;")

    def get_nostr_state(self, key: str) -> Optional[str]:
        conn = self._get_connection()
        row = conn.execute(
            "SELECT value FROM nostr_state WHERE key = ?",
            (key,),
        ).fetchone()
        return str(row["value"]) if row else None

    def set_nostr_state(self, key: str, value: str, now_ts: int) -> None:
        conn = self._get_connection()
        conn.execute(
            """
            INSERT INTO nostr_state (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
            """,
            (key, value, now_ts),
        )

    def list_nostr_state(self, prefix: str = "", limit: int = 500) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        if prefix:
            safe_prefix = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            rows = conn.execute(
                "SELECT key, value, updated_at FROM nostr_state WHERE key LIKE ? ESCAPE '\\' ORDER BY key ASC LIMIT ?",
                (f"{safe_prefix}%", limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT key, value, updated_at FROM nostr_state ORDER BY key ASC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def upsert_advisor(
        self,
        advisor_id: str,
        advisor_ref: str,
        permissions_json: str,
        daily_limit_sats: int,
        status: str,
        note: str,
        now_ts: int,
    ) -> None:
        conn = self._get_connection()
        row = conn.execute(
            "SELECT created_at FROM comms_advisors WHERE advisor_id = ?",
            (advisor_id,),
        ).fetchone()
        created_at = int(row["created_at"]) if row else now_ts
        conn.execute(
            """
            INSERT INTO comms_advisors (
                advisor_id, advisor_ref, permissions_json, status,
                daily_limit_sats, note, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(advisor_id) DO UPDATE SET
                advisor_ref = excluded.advisor_ref,
                permissions_json = excluded.permissions_json,
                status = excluded.status,
                daily_limit_sats = excluded.daily_limit_sats,
                note = excluded.note,
                updated_at = excluded.updated_at
            """,
            (
                advisor_id,
                advisor_ref,
                permissions_json,
                status,
                max(0, int(daily_limit_sats)),
                note,
                created_at,
                now_ts,
            ),
        )

    def get_advisor(self, reference: str) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        row = conn.execute(
            """
            SELECT * FROM comms_advisors
            WHERE advisor_id = ? OR advisor_ref = ? OR alias = ?
            LIMIT 1
            """,
            (reference, reference, reference),
        ).fetchone()
        if row:
            return dict(row)
        alias_row = conn.execute(
            """
            SELECT a.*
            FROM comms_aliases c
            JOIN comms_advisors a ON a.advisor_id = c.advisor_id
            WHERE c.alias = ?
            LIMIT 1
            """,
            (reference,),
        ).fetchone()
        return dict(alias_row) if alias_row else None

    def list_advisors(self, status: str = "", limit: int = 200) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        if status:
            rows = conn.execute(
                """
                SELECT * FROM comms_advisors
                WHERE status = ?
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (status, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM comms_advisors
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def set_advisor_alias(self, advisor_id: str, alias: str, now_ts: int) -> None:
        conn = self._get_connection()
        conn.execute(
            "UPDATE comms_advisors SET alias = ?, updated_at = ? WHERE advisor_id = ?",
            (alias, now_ts, advisor_id),
        )

    def upsert_alias(self, alias: str, advisor_id: str, now_ts: int) -> None:
        conn = self._get_connection()
        conn.execute(
            "DELETE FROM comms_aliases WHERE advisor_id = ? AND alias != ?",
            (advisor_id, alias),
        )
        conn.execute(
            """
            INSERT INTO comms_aliases (alias, advisor_id, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(alias) DO UPDATE SET
                advisor_id = excluded.advisor_id,
                updated_at = excluded.updated_at
            """,
            (alias, advisor_id, now_ts, now_ts),
        )

    def remove_alias(self, alias: str) -> int:
        conn = self._get_connection()
        row = conn.execute(
            "SELECT advisor_id FROM comms_aliases WHERE alias = ?",
            (alias,),
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE comms_advisors SET alias = NULL WHERE advisor_id = ? AND alias = ?",
                (str(row["advisor_id"]), alias),
            )
        cursor = conn.execute(
            "DELETE FROM comms_aliases WHERE alias = ?",
            (alias,),
        )
        return cursor.rowcount

    def get_advisor_auth_token(self, advisor_id: str) -> Optional[str]:
        conn = self._get_connection()
        row = conn.execute(
            "SELECT auth_token FROM comms_advisor_auth WHERE advisor_id = ?",
            (advisor_id,),
        ).fetchone()
        return str(row["auth_token"]) if row else None

    def upsert_advisor_auth_token(self, advisor_id: str, auth_token: str, now_ts: int) -> None:
        conn = self._get_connection()
        existing = conn.execute(
            "SELECT created_at FROM comms_advisor_auth WHERE advisor_id = ?",
            (advisor_id,),
        ).fetchone()
        created_at = int(existing["created_at"]) if existing else now_ts
        conn.execute(
            """
            INSERT INTO comms_advisor_auth (advisor_id, auth_token, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(advisor_id) DO UPDATE SET
                auth_token = excluded.auth_token,
                updated_at = excluded.updated_at
            """,
            (advisor_id, auth_token, created_at, now_ts),
        )

    def delete_advisor_auth_token(self, advisor_id: str) -> None:
        conn = self._get_connection()
        conn.execute("DELETE FROM comms_advisor_auth WHERE advisor_id = ?", (advisor_id,))

    def get_alias(self, alias: str) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        row = conn.execute(
            """
            SELECT c.alias, c.advisor_id, c.created_at, c.updated_at, a.advisor_ref, a.status
            FROM comms_aliases c
            JOIN comms_advisors a ON a.advisor_id = c.advisor_id
            WHERE c.alias = ?
            LIMIT 1
            """,
            (alias,),
        ).fetchone()
        return dict(row) if row else None

    def list_aliases(self, limit: int = 500) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        rows = conn.execute(
            """
            SELECT c.alias, c.advisor_id, c.created_at, c.updated_at, a.advisor_ref, a.status
            FROM comms_aliases c
            JOIN comms_advisors a ON a.advisor_id = c.advisor_id
            ORDER BY c.alias ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def create_trial(
        self,
        trial_id: str,
        advisor_id: str,
        started_at: int,
        ends_at: int,
        status: str,
        note: str,
    ) -> None:
        conn = self._get_connection()
        conn.execute(
            """
            INSERT INTO comms_trials (trial_id, advisor_id, started_at, ends_at, status, note)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (trial_id, advisor_id, started_at, ends_at, status, note),
        )

    def list_trials(self, advisor_id: str = "", status: str = "", limit: int = 200) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        if advisor_id and status:
            rows = conn.execute(
                """
                SELECT * FROM comms_trials
                WHERE advisor_id = ? AND status = ?
                ORDER BY started_at DESC
                LIMIT ?
                """,
                (advisor_id, status, limit),
            ).fetchall()
        elif advisor_id:
            rows = conn.execute(
                """
                SELECT * FROM comms_trials
                WHERE advisor_id = ?
                ORDER BY started_at DESC
                LIMIT ?
                """,
                (advisor_id, limit),
            ).fetchall()
        elif status:
            rows = conn.execute(
                """
                SELECT * FROM comms_trials
                WHERE status = ?
                ORDER BY started_at DESC
                LIMIT ?
                """,
                (status, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM comms_trials
                ORDER BY started_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def stop_active_trials(self, advisor_id: str, now_ts: int) -> int:
        conn = self._get_connection()
        cursor = conn.execute(
            """
            UPDATE comms_trials
            SET status = 'stopped', ends_at = CASE WHEN ends_at < ? THEN ends_at ELSE ? END
            WHERE advisor_id = ? AND status = 'active'
            """,
            (now_ts, now_ts, advisor_id),
        )
        return cursor.rowcount

    def mark_expired_trials(self, now_ts: int) -> int:
        conn = self._get_connection()
        cursor = conn.execute(
            """
            UPDATE comms_trials
            SET status = 'expired'
            WHERE status = 'active' AND ends_at <= ?
            """,
            (now_ts,),
        )
        return cursor.rowcount

    def add_payment(
        self,
        payment_id: str,
        advisor_id: str,
        amount_sats: int,
        kind: str,
        note: str,
        now_ts: int,
    ) -> None:
        conn = self._get_connection()
        conn.execute(
            """
            INSERT INTO comms_payments (payment_id, advisor_id, amount_sats, kind, note, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (payment_id, advisor_id, max(0, int(amount_sats)), kind, note, now_ts),
        )

    def list_payments(self, advisor_id: str = "", limit: int = 200) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        if advisor_id:
            rows = conn.execute(
                """
                SELECT * FROM comms_payments
                WHERE advisor_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (advisor_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM comms_payments
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def sum_payments_today(self, advisor_id: str, now_ts: int) -> int:
        conn = self._get_connection()
        day_start = now_ts - 86400
        row = conn.execute(
            "SELECT COALESCE(SUM(amount_sats), 0) AS total FROM comms_payments WHERE advisor_id = ? AND created_at >= ?",
            (advisor_id, day_start),
        ).fetchone()
        return int(row["total"] or 0)

    def summarize_payments(self, now_ts: int) -> Dict[str, int]:
        conn = self._get_connection()
        day_cutoff = now_ts - 86400
        week_cutoff = now_ts - (7 * 86400)

        def _sum_since(cutoff: Optional[int] = None) -> int:
            if cutoff is None:
                row = conn.execute(
                    "SELECT COALESCE(SUM(amount_sats), 0) AS total FROM comms_payments"
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT COALESCE(SUM(amount_sats), 0) AS total FROM comms_payments WHERE created_at >= ?",
                    (cutoff,),
                ).fetchone()
            return int(row["total"] or 0)

        return {
            "total_sats": _sum_since(),
            "day_sats": _sum_since(day_cutoff),
            "week_sats": _sum_since(week_cutoff),
        }

    def add_receipt(
        self,
        actor: str,
        schema_id: str,
        action: str,
        params: Dict[str, Any],
        result: Dict[str, Any],
        now_ts: int,
    ) -> Dict[str, Any]:
        conn = self._get_connection()
        conn.execute("BEGIN IMMEDIATE")
        try:
            last = conn.execute(
                "SELECT receipt_hash FROM management_receipts ORDER BY receipt_id DESC LIMIT 1"
            ).fetchone()
            prev_hash = str(last["receipt_hash"]) if last else ""
            canonical = json.dumps(
                {
                    "created_at": now_ts,
                    "actor": actor,
                    "schema_id": schema_id,
                    "action": action,
                    "params": params,
                    "result": result,
                    "prev_hash": prev_hash,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            receipt_hash = _sha256_hex(canonical)
            cursor = conn.execute(
                """
                INSERT INTO management_receipts (
                    created_at, actor, schema_id, action, params_json, result_json, prev_hash, receipt_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now_ts,
                    actor,
                    schema_id,
                    action,
                    json.dumps(params, sort_keys=True, separators=(",", ":")),
                    json.dumps(result, sort_keys=True, separators=(",", ":")),
                    prev_hash,
                    receipt_hash,
                ),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        return {
            "receipt_id": int(cursor.lastrowid),
            "created_at": now_ts,
            "actor": actor,
            "schema_id": schema_id,
            "action": action,
            "prev_hash": prev_hash,
            "receipt_hash": receipt_hash,
            "params": params,
            "result": result,
        }

    def get_receipts(self, actor: str = "", limit: int = 100) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        if actor:
            rows = conn.execute(
                """
                SELECT * FROM management_receipts
                WHERE actor = ?
                ORDER BY receipt_id DESC
                LIMIT ?
                """,
                (actor, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM management_receipts
                ORDER BY receipt_id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        result: List[Dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["params"] = _parse_json_object(str(item.pop("params_json", "{}"))) or {}
            item["result"] = _parse_json_object(str(item.pop("result_json", "{}"))) or {}
            result.append(item)
        return result

    def count_advisors(self, status: str = "") -> int:
        conn = self._get_connection()
        if status:
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM comms_advisors WHERE status = ?",
                (status,),
            ).fetchone()
        else:
            row = conn.execute("SELECT COUNT(*) AS cnt FROM comms_advisors").fetchone()
        return int(row["cnt"] or 0)

    def count_active_trials(self) -> int:
        conn = self._get_connection()
        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM comms_trials WHERE status = 'active'"
        ).fetchone()
        return int(row["cnt"] or 0)

    def count_receipts(self) -> int:
        conn = self._get_connection()
        row = conn.execute("SELECT COUNT(*) AS cnt FROM management_receipts").fetchone()
        return int(row["cnt"] or 0)

    def prune_old_data(self, days: int = 90, now_ts: int = 0) -> Dict[str, int]:
        conn = self._get_connection()
        if now_ts <= 0:
            now_ts = _now_ts(time.time)
        cutoff = now_ts - (days * 86400)
        pruned: Dict[str, int] = {}
        conn.execute("BEGIN IMMEDIATE")
        try:
            cursor = conn.execute(
                "DELETE FROM management_receipts WHERE created_at < ?", (cutoff,)
            )
            pruned["receipts"] = cursor.rowcount
            cursor = conn.execute(
                "DELETE FROM comms_payments WHERE created_at < ?", (cutoff,)
            )
            pruned["payments"] = cursor.rowcount
            cursor = conn.execute(
                "DELETE FROM comms_trials WHERE status IN ('expired', 'stopped') AND ends_at < ?",
                (cutoff,),
            )
            pruned["trials"] = cursor.rowcount
            cursor = conn.execute(
                "DELETE FROM nostr_state WHERE key LIKE 'replay:%' AND updated_at < ?",
                (cutoff,),
            )
            pruned["replay_nonces"] = cursor.rowcount
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        return pruned


class PolicyEngine:
    """Operator policy layer for remote management actions."""

    PRESETS = {
        "conservative": {"max_danger": 4, "require_confirmation_above": 3, "blocked_schemas": []},
        "moderate": {"max_danger": 6, "require_confirmation_above": 5, "blocked_schemas": []},
        "aggressive": {"max_danger": 8, "require_confirmation_above": 7, "blocked_schemas": []},
    }

    POLICY_KEY = "policy:config"

    def __init__(
        self,
        store: CommsStore,
        time_fn: Callable[[], float] = time.time,
        logger: Optional[Callable[[str, str], None]] = None,
    ):
        self.store = store
        self._time_fn = time_fn
        self._logger = logger

    def _log(self, message: str, level: str = "info") -> None:
        if self._logger:
            self._logger(message, level)

    def _now(self) -> int:
        return _now_ts(self._time_fn)

    def _default(self, preset: str = "moderate") -> Dict[str, Any]:
        chosen = preset if preset in self.PRESETS else "moderate"
        return {
            "preset": chosen,
            "rules": dict(self.PRESETS[chosen]),
            "overrides": {},
            "updated_at": self._now(),
        }

    def get_policy(self) -> Dict[str, Any]:
        raw = self.store.get_nostr_state(self.POLICY_KEY)
        if not raw:
            default = self._default()
            self.store.set_nostr_state(
                self.POLICY_KEY,
                json.dumps(default, sort_keys=True, separators=(",", ":")),
                self._now(),
            )
            return default
        data = _parse_json_object(raw)
        if data is None:
            self._log("policy: invalid policy JSON found, resetting to default", "warn")
            default = self._default()
            self.store.set_nostr_state(
                self.POLICY_KEY,
                json.dumps(default, sort_keys=True, separators=(",", ":")),
                self._now(),
            )
            return default
        return data

    def _persist(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        policy["updated_at"] = self._now()
        self.store.set_nostr_state(
            self.POLICY_KEY,
            json.dumps(policy, sort_keys=True, separators=(",", ":")),
            policy["updated_at"],
        )
        return policy

    def set_preset(self, preset: str) -> Dict[str, Any]:
        if preset not in self.PRESETS:
            raise ValueError("invalid preset")
        base = self._default(preset)
        return self._persist(base)

    def update_overrides(self, overrides: Dict[str, Any]) -> Dict[str, Any]:
        policy = self.get_policy()
        current = policy.get("overrides", {})
        if not isinstance(current, dict):
            current = {}
        current.update(overrides)
        policy["overrides"] = current
        return self._persist(policy)

    def reset(self) -> Dict[str, Any]:
        return self.set_preset("moderate")

    def evaluate(self, schema_id: str, danger_score: int) -> Dict[str, Any]:
        policy = self.get_policy()
        rules = policy.get("rules", {})
        if not isinstance(rules, dict):
            rules = {}
        overrides = policy.get("overrides", {})
        if not isinstance(overrides, dict):
            overrides = {}

        max_danger = int(overrides.get("max_danger", rules.get("max_danger", 6)))
        confirm_above = int(
            overrides.get("require_confirmation_above", rules.get("require_confirmation_above", 5))
        )
        blocked_schemas = overrides.get("blocked_schemas", rules.get("blocked_schemas", []))
        if not isinstance(blocked_schemas, list):
            blocked_schemas = []

        if schema_id in blocked_schemas:
            return {
                "allowed": False,
                "requires_confirmation": False,
                "reason": "schema blocked by local policy",
                "max_danger": max_danger,
            }

        if int(danger_score) > max_danger:
            return {
                "allowed": False,
                "requires_confirmation": False,
                "reason": f"danger_score exceeds max_danger ({max_danger})",
                "max_danger": max_danger,
            }

        return {
            "allowed": True,
            "requires_confirmation": int(danger_score) > confirm_above,
            "reason": "",
            "max_danger": max_danger,
        }


class CommsService:
    """Phase 6A service API used by cl-hive-comms RPC methods."""

    VALID_PAYMENT_KINDS = {"bolt11", "bolt12", "l402", "cashu"}
    ALIAS_PATTERN = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")

    def __init__(
        self,
        store: CommsStore,
        rpc: Any = None,
        logger: Optional[Callable[[str, str], None]] = None,
        time_fn: Callable[[], float] = time.time,
        default_relays: Optional[List[str]] = None,
        policy_preset: str = "moderate",
    ):
        self.store = store
        self.rpc = rpc
        self._logger = logger
        self._time_fn = time_fn
        self.default_relays = default_relays or ["wss://nos.lol", "wss://relay.damus.io"]
        self.store.initialize()
        self.policy_engine = PolicyEngine(store=self.store, time_fn=time_fn, logger=logger)
        self._bootstrap_identity_if_needed()
        if not self.store.get_nostr_state(PolicyEngine.POLICY_KEY):
            try:
                self.policy_engine.set_preset(policy_preset)
            except ValueError:
                self.policy_engine.set_preset("moderate")

    def _log(self, message: str, level: str = "info") -> None:
        if self._logger:
            self._logger(message, level)

    def _now(self) -> int:
        return _now_ts(self._time_fn)

    def _create_local_identity(self) -> Dict[str, str]:
        # NOTE: This generates a placeholder identity — the pubkey is SHA256(privkey)
        # rather than a proper secp256k1 x-only derivation. This is intentional for
        # dark-launch (local-only wire format). Must be replaced with real Nostr
        # keygen before publishing to external relays. See ROADMAP.md item 1.
        privkey = secrets.token_hex(32)
        digest = _sha256_hex(privkey)
        pubkey = digest[:64]
        return {"privkey": privkey, "pubkey": pubkey, "placeholder": True}

    def _bootstrap_identity_if_needed(self) -> None:
        now_ts = self._now()
        privkey = self.store.get_nostr_state("config:privkey")
        pubkey = self.store.get_nostr_state("config:pubkey")
        relays = self.store.get_nostr_state("config:relays")
        if not privkey or not pubkey:
            identity = self._create_local_identity()
            self.store.set_nostr_state("config:privkey", identity["privkey"], now_ts)
            self.store.set_nostr_state("config:pubkey", identity["pubkey"], now_ts)
            self.store.set_nostr_state("config:identity_placeholder", "true", now_ts)
            self._log("comms: generated placeholder Nostr identity (not valid for external relay publishing)", "warn")
        elif _is_hex_len(pubkey, 66) and pubkey[:2] in ("02", "03"):
            # Migrate old compressed-style placeholder key to x-only form.
            self.store.set_nostr_state("config:pubkey", pubkey[2:], now_ts)
            self._log("comms: migrated local pubkey to x-only nostr format", "info")
        if not relays:
            self.store.set_nostr_state(
                "config:relays",
                json.dumps(self.default_relays, sort_keys=True, separators=(",", ":")),
                now_ts,
            )

    def _get_relays(self) -> List[str]:
        raw = self.store.get_nostr_state("config:relays")
        if not raw:
            return list(self.default_relays)
        try:
            value = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            return list(self.default_relays)
        if isinstance(value, list):
            return [str(item) for item in value if isinstance(item, str) and item.strip()]
        return list(self.default_relays)

    def _resolve_advisor(self, reference: str) -> Optional[Dict[str, Any]]:
        if not isinstance(reference, str) or not reference.strip():
            return None
        return self.store.get_advisor(reference.strip())

    VALID_PERMISSIONS = {"monitor", "admin", "policy", "payments", "payment", "fee_policy", "trial", "alias"}

    def _to_permissions(self, access: str) -> List[str]:
        if not isinstance(access, str):
            return ["monitor"]
        items = [item.strip() for item in access.split(",")]
        cleaned = [item for item in items if item and item in self.VALID_PERMISSIONS]
        return cleaned or ["monitor"]

    def _to_int(self, value: Any, default: int) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _record_receipt(
        self,
        actor: str,
        schema_id: str,
        action: str,
        params: Dict[str, Any],
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        return self.store.add_receipt(
            actor=actor,
            schema_id=schema_id,
            action=action,
            params=params,
            result=result,
            now_ts=self._now(),
        )

    def status(self) -> Dict[str, Any]:
        self.store.mark_expired_trials(self._now())
        payments = self.store.summarize_payments(self._now())
        identity = self.identity()
        return {
            "ok": True,
            "identity": {
                "pubkey": identity.get("pubkey", ""),
                "relays": identity.get("relays", []),
            },
            "policy": self.policy_engine.get_policy(),
            "active_advisors": self.store.count_advisors(status="active"),
            "revoked_advisors": self.store.count_advisors(status="revoked"),
            "active_trials": self.store.count_active_trials(),
            "receipts": self.store.count_receipts(),
            "payments": payments,
        }

    def identity(self, action: str = "get", nsec: str = "", relays: str = "") -> Dict[str, Any]:
        action = str(action or "get").strip().lower()
        now_ts = self._now()

        if action in ("get", "status", "show"):
            pubkey = self.store.get_nostr_state("config:pubkey") or ""
            is_placeholder = self.store.get_nostr_state("config:identity_placeholder") == "true"
            return {
                "ok": True,
                "pubkey": pubkey,
                "relays": self._get_relays(),
                "has_private_key": bool(self.store.get_nostr_state("config:privkey")),
                "placeholder_keygen": is_placeholder,
            }

        if action == "rotate":
            identity = self._create_local_identity()
            self.store.set_nostr_state("config:privkey", identity["privkey"], now_ts)
            self.store.set_nostr_state("config:pubkey", identity["pubkey"], now_ts)
            self.store.set_nostr_state("config:identity_placeholder", "true", now_ts)
            return {
                "ok": True,
                "rotated": True,
                "pubkey": identity["pubkey"],
                "relays": self._get_relays(),
                "placeholder_keygen": True,
            }

        if action == "import":
            key = str(nsec or "").strip().lower()
            if not re.fullmatch(r"[0-9a-f]{64}", key):
                return {
                    "error": "invalid nsec format",
                    "hint": "expected 64-char hex private key for current dark-launch mode",
                }
            digest = _sha256_hex(key)
            pubkey = digest[:64]
            self.store.set_nostr_state("config:privkey", key, now_ts)
            self.store.set_nostr_state("config:pubkey", pubkey, now_ts)
            self.store.set_nostr_state("config:identity_placeholder", "false", now_ts)
            return {"ok": True, "imported": True, "pubkey": pubkey, "relays": self._get_relays()}

        if action == "set-relays":
            relay_list = _normalize_relays_csv(relays)
            if not relay_list:
                return {"error": "relays cannot be empty"}
            self.store.set_nostr_state(
                "config:relays",
                json.dumps(relay_list, sort_keys=True, separators=(",", ":")),
                now_ts,
            )
            return {"ok": True, "relays": relay_list}

        return {"error": "invalid action", "valid_actions": ["get", "rotate", "import", "set-relays"]}

    def authorize(
        self,
        advisor: str,
        access: str = "monitor",
        daily_limit_sats: int = 0,
        note: str = "",
    ) -> Dict[str, Any]:
        if not isinstance(advisor, str) or not advisor.strip():
            return {"error": "advisor is required"}
        advisor_ref = advisor.strip()
        permissions = self._to_permissions(access)
        now_ts = self._now()
        advisor_id = _sha256_hex(advisor_ref.lower())[:32]
        self.store.upsert_advisor(
            advisor_id=advisor_id,
            advisor_ref=advisor_ref,
            permissions_json=json.dumps(permissions, sort_keys=True, separators=(",", ":")),
            daily_limit_sats=max(0, int(daily_limit_sats)),
            status="active",
            note=str(note or ""),
            now_ts=now_ts,
        )
        auth_token = self.store.get_advisor_auth_token(advisor_id)
        if not auth_token:
            auth_token = secrets.token_hex(32)
            self.store.upsert_advisor_auth_token(advisor_id=advisor_id, auth_token=auth_token, now_ts=now_ts)
        result = {
            "ok": True,
            "advisor_id": advisor_id,
            "advisor": advisor_ref,
            "status": "active",
            "permissions": permissions,
            "daily_limit_sats": max(0, int(daily_limit_sats)),
            "auth_token": auth_token,
        }
        receipt_result = {k: v for k, v in result.items() if k != "auth_token"}
        receipt = self._record_receipt(
            actor=advisor_id,
            schema_id="hive:authorize/v1",
            action="authorize",
            params={"access": permissions, "daily_limit_sats": max(0, int(daily_limit_sats))},
            result=receipt_result,
        )
        result["receipt_id"] = receipt["receipt_id"]
        return result

    def revoke(self, advisor: str, reason: str = "") -> Dict[str, Any]:
        row = self._resolve_advisor(advisor)
        if not row:
            return {"error": "advisor not found"}
        advisor_id = str(row.get("advisor_id") or "")
        self.store.upsert_advisor(
            advisor_id=advisor_id,
            advisor_ref=str(row.get("advisor_ref") or advisor),
            permissions_json=str(row.get("permissions_json") or "[]"),
            daily_limit_sats=int(row.get("daily_limit_sats") or 0),
            status="revoked",
            note=str(reason or row.get("note") or ""),
            now_ts=self._now(),
        )
        self.store.delete_advisor_auth_token(advisor_id)
        result = {
            "ok": True,
            "advisor_id": advisor_id,
            "advisor": str(row.get("advisor_ref") or advisor),
            "status": "revoked",
        }
        receipt = self._record_receipt(
            actor=advisor_id,
            schema_id="hive:authorize/v1",
            action="revoke",
            params={"reason": str(reason or "")},
            result=result,
        )
        result["receipt_id"] = receipt["receipt_id"]
        return result

    def discover(self, query: str = "", capability: str = "", limit: int = 20) -> Dict[str, Any]:
        if not isinstance(limit, int) or limit <= 0:
            return {"error": "limit must be positive"}
        if limit > 500:
            limit = 500
        q = str(query or "").strip().lower()
        cap = str(capability or "").strip().lower()
        rows = self.store.list_advisors(status="active", limit=limit * 5)
        matches: List[Dict[str, Any]] = []
        for row in rows:
            advisor_ref = str(row.get("advisor_ref") or "")
            alias = str(row.get("alias") or "")
            permissions_raw = str(row.get("permissions_json") or "[]")
            try:
                permissions = json.loads(permissions_raw)
            except (TypeError, json.JSONDecodeError):
                permissions = []
            if not isinstance(permissions, list):
                permissions = []
            text = " ".join([advisor_ref.lower(), alias.lower(), " ".join(map(str, permissions)).lower()])
            if q and q not in text:
                continue
            if cap and cap not in text:
                continue
            matches.append(
                {
                    "advisor_id": str(row.get("advisor_id") or ""),
                    "advisor": advisor_ref,
                    "alias": alias,
                    "permissions": permissions,
                    "source": "local",
                }
            )
            if len(matches) >= limit:
                break
        return {"ok": True, "count": len(matches), "results": matches}

    def receipts(self, advisor: str = "", limit: int = 50) -> Dict[str, Any]:
        if not isinstance(limit, int) or limit <= 0:
            return {"error": "limit must be positive"}
        if limit > 500:
            limit = 500
        actor = ""
        if advisor:
            row = self._resolve_advisor(advisor)
            if not row:
                return {"error": "advisor not found"}
            actor = str(row.get("advisor_id") or "")
        rows = self.store.get_receipts(actor=actor, limit=limit)
        return {"ok": True, "count": len(rows), "receipts": rows}

    def policy(self, action: str = "get", preset: str = "", overrides_json: str = "") -> Dict[str, Any]:
        action = str(action or "get").strip().lower()
        if action in ("get", "show"):
            return {"ok": True, "policy": self.policy_engine.get_policy()}

        if action in ("set-preset", "preset"):
            preset_name = str(preset or "").strip().lower()
            if not preset_name:
                return {"error": "preset is required"}
            try:
                policy = self.policy_engine.set_preset(preset_name)
            except ValueError:
                return {"error": "invalid preset", "valid_presets": sorted(PolicyEngine.PRESETS.keys())}
            return {"ok": True, "policy": policy}

        if action in ("set-overrides", "update", "set"):
            updates = _parse_json_object(overrides_json)
            if updates is None:
                return {"error": "overrides_json must decode to an object"}
            policy = self.policy_engine.update_overrides(updates)
            return {"ok": True, "policy": policy}

        if action == "reset":
            return {"ok": True, "policy": self.policy_engine.reset()}

        return {
            "error": "invalid action",
            "valid_actions": ["get", "set-preset", "set-overrides", "reset"],
        }

    def payments(
        self,
        action: str = "summary",
        advisor: str = "",
        amount_sats: int = 0,
        kind: str = "bolt11",
        note: str = "",
        limit: int = 100,
    ) -> Dict[str, Any]:
        action = str(action or "summary").strip().lower()
        now_ts = self._now()
        self.store.mark_expired_trials(now_ts)

        if action in ("summary", "status"):
            return {"ok": True, "summary": self.store.summarize_payments(now_ts)}

        if action == "history":
            advisor_id = ""
            if advisor:
                row = self._resolve_advisor(advisor)
                if not row:
                    return {"error": "advisor not found"}
                advisor_id = str(row.get("advisor_id") or "")
            rows = self.store.list_payments(advisor_id=advisor_id, limit=limit)
            return {"ok": True, "count": len(rows), "payments": rows}

        if action == "record":
            if not isinstance(amount_sats, int) or amount_sats <= 0:
                return {"error": "amount_sats must be positive"}
            method = str(kind or "").strip().lower()
            if method not in self.VALID_PAYMENT_KINDS:
                return {"error": "invalid kind", "valid_kinds": sorted(self.VALID_PAYMENT_KINDS)}
            row = self._resolve_advisor(advisor)
            if not row:
                return {"error": "advisor not found"}
            advisor_id = str(row.get("advisor_id") or "")
            daily_limit = int(row.get("daily_limit_sats") or 0)
            if daily_limit > 0:
                spent_today = self.store.sum_payments_today(advisor_id, now_ts)
                if spent_today + amount_sats > daily_limit:
                    return {
                        "error": "daily limit exceeded",
                        "daily_limit_sats": daily_limit,
                        "spent_today_sats": spent_today,
                        "requested_sats": amount_sats,
                    }
            payment_id = _sha256_hex(f"{advisor_id}:{method}:{amount_sats}:{now_ts}:{uuid.uuid4()}")[:32]
            self.store.add_payment(
                payment_id=payment_id,
                advisor_id=advisor_id,
                amount_sats=amount_sats,
                kind=method,
                note=str(note or ""),
                now_ts=now_ts,
            )
            result = {
                "ok": True,
                "payment_id": payment_id,
                "advisor_id": advisor_id,
                "amount_sats": amount_sats,
                "kind": method,
            }
            receipt = self._record_receipt(
                actor=advisor_id,
                schema_id="hive:payment/v1",
                action="record",
                params={"kind": method, "amount_sats": amount_sats},
                result=result,
            )
            result["receipt_id"] = receipt["receipt_id"]
            return result

        return {"error": "invalid action", "valid_actions": ["summary", "history", "record"]}

    def trial(
        self,
        action: str = "list",
        advisor: str = "",
        days: int = 14,
        note: str = "",
        limit: int = 100,
    ) -> Dict[str, Any]:
        action = str(action or "list").strip().lower()
        now_ts = self._now()
        self.store.mark_expired_trials(now_ts)

        if action in ("list", "status"):
            advisor_id = ""
            if advisor:
                row = self._resolve_advisor(advisor)
                if not row:
                    return {"error": "advisor not found"}
                advisor_id = str(row.get("advisor_id") or "")
            rows = self.store.list_trials(advisor_id=advisor_id, limit=limit)
            return {"ok": True, "count": len(rows), "trials": rows}

        if action == "start":
            if not isinstance(days, int) or days < 1 or days > 90:
                return {"error": "days must be between 1 and 90"}
            row = self._resolve_advisor(advisor)
            if not row:
                return {"error": "advisor not found"}
            advisor_id = str(row.get("advisor_id") or "")
            started_at = now_ts
            ends_at = now_ts + (days * 86400)
            trial_id = _sha256_hex(f"{advisor_id}:{started_at}:{uuid.uuid4()}")[:32]
            self.store.create_trial(
                trial_id=trial_id,
                advisor_id=advisor_id,
                started_at=started_at,
                ends_at=ends_at,
                status="active",
                note=str(note or ""),
            )
            result = {
                "ok": True,
                "trial_id": trial_id,
                "advisor_id": advisor_id,
                "status": "active",
                "days": days,
                "started_at": started_at,
                "ends_at": ends_at,
            }
            receipt = self._record_receipt(
                actor=advisor_id,
                schema_id="hive:trial/v1",
                action="start",
                params={"days": days},
                result=result,
            )
            result["receipt_id"] = receipt["receipt_id"]
            return result

        if action == "stop":
            row = self._resolve_advisor(advisor)
            if not row:
                return {"error": "advisor not found"}
            advisor_id = str(row.get("advisor_id") or "")
            stopped = self.store.stop_active_trials(advisor_id=advisor_id, now_ts=now_ts)
            result = {
                "ok": True,
                "advisor_id": advisor_id,
                "stopped_trials": stopped,
            }
            receipt = self._record_receipt(
                actor=advisor_id,
                schema_id="hive:trial/v1",
                action="stop",
                params={},
                result=result,
            )
            result["receipt_id"] = receipt["receipt_id"]
            return result

        return {"error": "invalid action", "valid_actions": ["list", "start", "stop"]}

    def alias(self, action: str = "list", alias: str = "", advisor: str = "", limit: int = 200) -> Dict[str, Any]:
        action = str(action or "list").strip().lower()
        now_ts = self._now()

        if action == "list":
            rows = self.store.list_aliases(limit=limit)
            return {"ok": True, "count": len(rows), "aliases": rows}

        if action in ("set", "upsert"):
            if not isinstance(alias, str) or not self.ALIAS_PATTERN.fullmatch(alias.strip()):
                return {"error": "invalid alias (allowed: letters, digits, '.', '_', '-')"}
            row = self._resolve_advisor(advisor)
            if not row:
                return {"error": "advisor not found"}
            advisor_id = str(row.get("advisor_id") or "")
            clean_alias = alias.strip()
            self.store.upsert_alias(clean_alias, advisor_id, now_ts)
            self.store.set_advisor_alias(advisor_id, clean_alias, now_ts)
            return {"ok": True, "alias": clean_alias, "advisor_id": advisor_id}

        if action in ("get", "resolve"):
            if not isinstance(alias, str) or not alias.strip():
                return {"error": "alias is required"}
            row = self.store.get_alias(alias.strip())
            if not row:
                return {"error": "alias not found"}
            return {"ok": True, "entry": row}

        if action in ("remove", "delete"):
            if not isinstance(alias, str) or not alias.strip():
                return {"error": "alias is required"}
            removed = self.store.remove_alias(alias.strip())
            return {"ok": True, "removed": removed}

        return {"error": "invalid action", "valid_actions": ["list", "set", "get", "remove"]}

    def prune(self, days: int = 90) -> Dict[str, Any]:
        if not isinstance(days, int) or days < 1:
            return {"error": "days must be a positive integer"}
        if days > 365:
            days = 365
        pruned = self.store.prune_old_data(days=days, now_ts=self._now())
        return {"ok": True, "days": days, "pruned": pruned}

    def execute_schema(self, schema_type: str, schema_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch a transport-delivered schema payload to local handlers."""
        if not isinstance(schema_type, str) or not schema_type.strip():
            return {"error": "invalid schema_type"}
        if not isinstance(schema_payload, dict):
            return {"error": "schema_payload must be an object"}

        schema = schema_type.strip()
        action = str(schema_payload.get("action") or "").strip().lower()

        if schema == "hive:monitor/v1":
            return self.status()

        if schema == "hive:discover/v1":
            return self.discover(
                query=str(schema_payload.get("query") or ""),
                capability=str(schema_payload.get("capability") or ""),
                limit=self._to_int(schema_payload.get("limit"), 20),
            )

        if schema == "hive:authorize/v1":
            if action in ("authorize", "grant", "upsert"):
                return self.authorize(
                    advisor=str(schema_payload.get("advisor") or ""),
                    access=str(schema_payload.get("access") or "monitor"),
                    daily_limit_sats=self._to_int(schema_payload.get("daily_limit_sats"), 0),
                    note=str(schema_payload.get("note") or ""),
                )
            if action in ("revoke", "deny"):
                return self.revoke(
                    advisor=str(schema_payload.get("advisor") or ""),
                    reason=str(schema_payload.get("reason") or ""),
                )
            return {"error": "invalid action for hive:authorize/v1"}

        if schema == "hive:receipts/v1":
            return self.receipts(
                advisor=str(schema_payload.get("advisor") or ""),
                limit=self._to_int(schema_payload.get("limit"), 50),
            )

        if schema == "hive:policy/v1":
            overrides = schema_payload.get("overrides")
            if isinstance(overrides, dict):
                overrides_json = json.dumps(overrides, sort_keys=True, separators=(",", ":"))
            else:
                overrides_json = str(schema_payload.get("overrides_json") or "")
            return self.policy(
                action=action or "get",
                preset=str(schema_payload.get("preset") or ""),
                overrides_json=overrides_json,
            )

        if schema == "hive:payments/v1":
            return self.payments(
                action=action or "summary",
                advisor=str(schema_payload.get("advisor") or ""),
                amount_sats=self._to_int(schema_payload.get("amount_sats"), 0),
                kind=str(schema_payload.get("kind") or "bolt11"),
                note=str(schema_payload.get("note") or ""),
                limit=self._to_int(schema_payload.get("limit"), 100),
            )

        if schema == "hive:trial/v1":
            return self.trial(
                action=action or "list",
                advisor=str(schema_payload.get("advisor") or ""),
                days=self._to_int(schema_payload.get("days"), 14),
                note=str(schema_payload.get("note") or ""),
                limit=self._to_int(schema_payload.get("limit"), 100),
            )

        if schema == "hive:alias/v1":
            return self.alias(
                action=action or "list",
                alias=str(schema_payload.get("alias") or ""),
                advisor=str(schema_payload.get("advisor") or ""),
                limit=self._to_int(schema_payload.get("limit"), 200),
            )

        if schema == "hive:identity/v1":
            return self.identity(
                action=action or "get",
                nsec=str(schema_payload.get("nsec") or ""),
                relays=str(schema_payload.get("relays") or ""),
            )

        return {"error": "unsupported schema_type"}
