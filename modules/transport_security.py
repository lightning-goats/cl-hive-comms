"""Transport security helpers for cl-hive-comms."""

from __future__ import annotations

import base64
import hmac
import json
import re
from typing import Any, Callable, Dict, Optional

from modules.comms_service import CommsStore


def _is_hex_with_lens(value: str, lengths: tuple[int, ...]) -> bool:
    if not isinstance(value, str) or len(value) not in lengths:
        return False
    return bool(re.fullmatch(r"[0-9a-fA-F]+", value))


class RuneVerifier:
    """Verify REST/rune authentication for secondary transport."""

    def __init__(
        self,
        store: CommsStore,
        rpc: Any = None,
        required: bool = False,
        static_rune: str = "",
        logger: Optional[Callable[[str, str], None]] = None,
    ):
        self.store = store
        self.rpc = rpc
        self.required = bool(required)
        self.static_rune = str(static_rune or "")
        self._logger = logger

    def _log(self, message: str, level: str = "info") -> None:
        if self._logger:
            self._logger(message, level)

    def _check_via_rpc(self, rune: str, method: str) -> Dict[str, Any]:
        if not self.rpc:
            return {"ok": False, "error": "rpc unavailable for rune verification"}
        try:
            if hasattr(self.rpc, "checkrune"):
                res = self.rpc.checkrune(rune=rune, method=method)
            else:
                res = self.rpc.call("checkrune", {"rune": rune, "method": method})
        except Exception as exc:
            self._log(f"checkrune failed: {exc}", "warn")
            return {"ok": False, "error": "rune verification failed"}

        if not isinstance(res, dict):
            return {"ok": False, "error": "invalid checkrune response"}

        # CLN responses vary by implementation; accept any explicit positive flag.
        if res.get("valid") is True or res.get("ok") is True:
            return {"ok": True}
        if res.get("result") == "valid":
            return {"ok": True}
        if "error" in res and res["error"]:
            return {"ok": False, "error": str(res["error"])}
        return {"ok": False, "error": "rune rejected"}

    def verify(self, rune: str, method: str) -> Dict[str, Any]:
        token = str(rune or "").strip()
        if not token:
            if self.required:
                return {"ok": False, "error": "missing rune"}
            return {"ok": True, "mode": "disabled"}

        if self.static_rune:
            if hmac.compare_digest(token, self.static_rune):
                return {"ok": True, "mode": "static"}
            return {"ok": False, "error": "invalid rune"}

        rpc_result = self._check_via_rpc(token, method)
        if rpc_result.get("ok"):
            return {"ok": True, "mode": "rpc"}
        return rpc_result


class NostrDmCodec:
    """Decode Nostr DM event content into transport envelopes."""

    def __init__(
        self,
        allow_plaintext: bool = False,
        logger: Optional[Callable[[str, str], None]] = None,
    ):
        self.allow_plaintext = bool(allow_plaintext)
        self._logger = logger

    def _log(self, message: str, level: str = "info") -> None:
        if self._logger:
            self._logger(message, level)

    def _decode_encrypted(self, content: str) -> tuple[str, str]:
        # This supports a dark-launch wire format that can be upgraded to full NIP-44
        # without changing call sites:
        # - b64:<base64(json)>
        # - nip44:<base64(json)>
        # - nip44:v2:<base64(json)>
        if content.startswith("b64:"):
            raw = content[4:]
            mode = "b64"
        elif content.startswith("nip44:v2:"):
            raw = content[9:]
            mode = "nip44:v2"
        elif content.startswith("nip44:"):
            raw = content[6:]
            mode = "nip44"
        else:
            if self.allow_plaintext:
                return content, "plaintext"
            raise ValueError("unsupported DM content encoding")

        decoded = base64.b64decode(raw.encode("ascii")).decode("utf-8")
        return decoded, mode

    def decode_event(self, event: Dict[str, Any], recipient_pubkey: str = "") -> Dict[str, Any]:
        if not isinstance(event, dict):
            return {"error": "event must be an object"}

        kind = event.get("kind")
        sender = str(event.get("pubkey") or "").strip()
        content = str(event.get("content") or "")
        tags = event.get("tags", [])

        if kind != 4:
            return {"error": "event kind must be 4 for DM"}
        if not _is_hex_with_lens(sender, (64,)):
            return {"error": "invalid sender pubkey"}
        if not isinstance(tags, list):
            return {"error": "event tags must be a list"}

        recipient_matches = False
        if recipient_pubkey:
            for tag in tags:
                if (
                    isinstance(tag, list)
                    and len(tag) >= 2
                    and str(tag[0]) == "p"
                    and str(tag[1]) == recipient_pubkey
                ):
                    recipient_matches = True
                    break
            if not recipient_matches:
                return {"error": "event not addressed to this node"}

        try:
            plaintext, mode = self._decode_encrypted(content)
        except Exception as exc:
            self._log(f"DM content decode failed: {exc}", "warn")
            return {"error": "failed to decode DM content"}

        try:
            payload = json.loads(plaintext)
        except (TypeError, json.JSONDecodeError):
            return {"error": "decoded DM payload is not valid JSON"}
        if not isinstance(payload, dict):
            return {"error": "decoded DM payload must be a JSON object"}

        return {
            "ok": True,
            "sender_pubkey": sender,
            "payload": payload,
            "encryption": mode,
        }
