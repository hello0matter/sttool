from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from sttool.registry import default_tools


def load_bridge():
    tool = next(item for item in default_tools() if item.tool_id == "passhack")
    path = Path(tool.required_paths[0])
    spec = importlib.util.spec_from_file_location("passhack_bridge_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def response(*, url: str, text: str, status_code: int = 200, headers=None):
    return SimpleNamespace(
        url=url,
        text=text,
        status_code=status_code,
        headers=headers or {},
    )


class PasshackBridgeTests(TestCase):
    def test_registered_as_scoped_login_audit_tool(self) -> None:
        tool = next(item for item in default_tools() if item.tool_id == "passhack")
        self.assertEqual(tool.category, "登录面安全审计")
        self.assertFalse(tool.default_selected)
        self.assertIn("--candidates", tool.args)
        self.assertIn("--target", tool.args)

    def test_cidr_scope_allows_matching_ip_only(self) -> None:
        module = load_bridge()

        self.assertTrue(
            module.host_allowed(
                "http://10.17.200.115/login",
                "szbayy.com\n10.17.200.0/24",
                "10.17.200.115",
            )
        )
        self.assertFalse(
            module.host_allowed(
                "http://10.17.201.115/login",
                "szbayy.com\n10.17.200.0/24",
                "10.17.200.115",
            )
        )

    def test_approved_candidate_submits_at_most_policy_attempts_without_plaintext(self) -> None:
        module = load_bridge()
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidates = root / "credential_audit.json"
            candidates.write_text(
                json.dumps(
                    {
                        "policy": {"max_attempts": 2, "requests_per_minute": 60000},
                        "candidates": [
                            {
                                "id": "one",
                                "url": "https://example.test/login",
                                "status": "approved_agent",
                                "action": "agent_default_dictionary",
                                "username_candidates": ["admin"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            args = SimpleNamespace(scope="example.test", target="https://example.test", timeout=5)
            login_page = response(
                url="https://example.test/login",
                text='<form method="post"><input name="user"><input type="password" name="pass"></form>',
            )
            failed_login = response(
                url="https://example.test/login",
                text="用户名或密码错误",
            )
            with patch.object(module.requests.Session, "get", return_value=login_page), patch.object(
                module.requests.Session, "post", return_value=failed_login
            ) as submit:
                result = module.process_candidate(
                    {
                        "id": "one",
                        "url": "https://example.test/login",
                        "status": "approved_agent",
                        "action": "agent_default_dictionary",
                        "username_candidates": ["admin"],
                    },
                    args,
                    candidates,
                )

            self.assertEqual(result["status"], "completed")
            self.assertEqual(submit.call_count, 2)
            rendered = json.dumps(result, ensure_ascii=False)
            for call in submit.call_args_list:
                password = call.kwargs["data"]["pass"]
                self.assertNotIn(password, rendered)

    def test_http_429_stops_further_attempts(self) -> None:
        module = load_bridge()
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidates = root / "credential_audit.json"
            candidates.write_text(
                json.dumps(
                    {
                        "policy": {
                            "max_attempts": 5,
                            "requests_per_minute": 60000,
                            "stop_on_defense": True,
                        },
                        "candidates": [],
                    }
                ),
                encoding="utf-8",
            )
            args = SimpleNamespace(scope="example.test", target="https://example.test", timeout=5)
            login_page = response(
                url="https://example.test/login",
                text='<form method="post"><input name="user"><input type="password" name="pass"></form>',
            )
            limited = response(
                url="https://example.test/login",
                text="Too Many Requests",
                status_code=429,
            )
            with patch.object(module.requests.Session, "get", return_value=login_page), patch.object(
                module.requests.Session, "post", return_value=limited
            ) as submit:
                result = module.process_candidate(
                    {
                        "id": "one",
                        "url": "https://example.test/login",
                        "status": "approved_agent",
                        "action": "agent_default_dictionary",
                    },
                    args,
                    candidates,
                )

            self.assertEqual(result["status"], "stopped_defense")
            self.assertEqual(submit.call_count, 1)

    def test_requeues_previous_scope_skips_but_not_filter_rejections(self) -> None:
        module = load_bridge()
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidates = root / "credential_audit.json"
            export = root / "passhack.json"
            candidates.write_text(
                json.dumps(
                    {
                        "candidates": [
                            {
                                "id": "retry",
                                "url": "http://10.17.200.115/login",
                                "status": "saved",
                                "default_action": "agent_default_dictionary",
                            },
                            {
                                "id": "filtered",
                                "url": "http://10.17.200.115/not-login",
                                "status": "saved",
                                "decision_source": "candidate_filter_tightened",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            export.write_text(
                json.dumps(
                    {
                        "results": [
                            {"id": "retry", "status": "skipped_scope"},
                            {"id": "filtered", "status": "skipped_scope"},
                        ]
                    }
                ),
                encoding="utf-8",
            )

            changed = module.requeue_scope_skips(
                candidates,
                export,
                "10.17.200.0/24",
                "10.17.200.115",
            )

            self.assertEqual(changed, 1)
            rows = json.loads(candidates.read_text(encoding="utf-8"))["candidates"]
            self.assertEqual(rows[0]["status"], "approved_agent")
            self.assertEqual(rows[1]["status"], "saved")
            results = json.loads(export.read_text(encoding="utf-8"))["results"]
            self.assertEqual(results, [{"id": "filtered", "status": "skipped_scope"}])
