from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from sttool.registry import default_tools


class PasshackBridgeTests(TestCase):
    def test_registered_as_scoped_login_audit_tool(self) -> None:
        tool = next(item for item in default_tools() if item.tool_id == "passhack")
        self.assertEqual(tool.category, "登录面安全审计")
        self.assertFalse(tool.default_selected)
        self.assertIn("--candidates", tool.args)
        self.assertIn("--target", tool.args)

    def test_bridge_only_records_login_form_and_does_not_submit_credentials(self) -> None:
        import importlib.util

        tool = next(item for item in default_tools() if item.tool_id == "passhack")
        path = Path(tool.required_paths[0])
        spec = importlib.util.spec_from_file_location("passhack_bridge_test", path)
        self.assertIsNotNone(spec)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidates = root / "credential_audit.json"
            candidates.write_text(
                json.dumps(
                    {
                        "candidates": [
                            {"id": "one", "url": "https://example.test/login", "status": "approved_agent", "action": "agent_default_dictionary"}
                        ]
                    }
                ),
                encoding="utf-8",
            )
            args = SimpleNamespace(scope="example.test", target="https://example.test", timeout=5)
            response = SimpleNamespace(
                url="https://example.test/login",
                text='<form><input name="user"><input type="password" name="pass"></form>',
            )
            with patch.object(module.requests.Session, "get", return_value=response), patch.object(
                module.requests.Session, "post", side_effect=AssertionError("must not submit credentials")
            ):
                result = module.process_candidate(
                    {"id": "one", "url": "https://example.test/login", "status": "approved_agent", "action": "agent_default_dictionary"},
                    args,
                    candidates,
                )
            self.assertEqual(result["status"], "completed")
            self.assertIn("人工启动", result["result"])
