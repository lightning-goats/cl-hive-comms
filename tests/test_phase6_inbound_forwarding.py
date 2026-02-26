"""Tests for Phase 6 inbound DM forwarding behavior in cl-hive-comms entrypoint."""

import importlib.util
import json
import os
import sys
from types import ModuleType
from unittest.mock import MagicMock


class _FakePlugin:
    def __init__(self):
        self.rpc = MagicMock()

    def add_option(self, **kwargs):
        return None

    def method(self, _name):
        def _decorator(fn):
            return fn
        return _decorator

    def init(self):
        def _decorator(fn):
            return fn
        return _decorator

    def log(self, message, level="info"):
        return None

    def run(self):
        return None


class _ImmediateThread:
    def __init__(self, target=None, daemon=False):
        self._target = target
        self.daemon = daemon

    def start(self):
        if self._target is not None:
            self._target()


def _load_entrypoint_module():
    original_pyln = sys.modules.get("pyln")
    original_pyln_client = sys.modules.get("pyln.client")
    fake_pyln = ModuleType("pyln.client")
    fake_pyln.Plugin = _FakePlugin
    sys.modules["pyln"] = ModuleType("pyln")
    sys.modules["pyln.client"] = fake_pyln

    try:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)
        path = os.path.join(root, "cl-hive-comms.py")
        spec = importlib.util.spec_from_file_location("cl_hive_comms_entrypoint_test", path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        return module
    finally:
        if original_pyln is None:
            sys.modules.pop("pyln", None)
        else:
            sys.modules["pyln"] = original_pyln
        if original_pyln_client is None:
            sys.modules.pop("pyln.client", None)
        else:
            sys.modules["pyln.client"] = original_pyln_client


def test_non_json_dm_is_forwarded_as_raw_packet():
    module = _load_entrypoint_module()
    module.threading.Thread = _ImmediateThread
    module.plugin.rpc.call = MagicMock()

    module._handle_inbound_dm({"plaintext": "not-json-wire", "pubkey": "peer-a"})

    module.plugin.rpc.call.assert_called_once_with(
        "hive-inject-packet",
        {"payload": {"raw_plaintext": "not-json-wire", "sender": "peer-a"}, "source": "nostr", "pubkey": "peer-a"},
    )


def test_management_schema_messages_are_routed_locally():
    module = _load_entrypoint_module()
    module.threading.Thread = _ImmediateThread
    module.plugin.rpc.call = MagicMock()
    module.router = MagicMock()

    payload = {"schema_type": "hive:monitor/v1", "op": "status"}
    module._handle_inbound_dm({"plaintext": json.dumps(payload), "pubkey": "peer-b"})

    module.router.handle_message.assert_called_once()
    module.plugin.rpc.call.assert_not_called()


def test_oversized_dm_is_dropped():
    module = _load_entrypoint_module()
    module.threading.Thread = _ImmediateThread
    module.plugin.rpc.call = MagicMock()

    oversized = "x" * (module.MAX_FORWARDED_DM_BYTES + 1)
    module._handle_inbound_dm({"plaintext": oversized, "pubkey": "peer-c"})

    module.plugin.rpc.call.assert_not_called()
