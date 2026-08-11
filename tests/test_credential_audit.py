from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sttool.asset_bus import AssetBus, atomic_json_write, read_json
from sttool.credential_audit import (
    append_decisions,
    candidate_path,
    discover_login_candidates,
    finish_batch_candidates,
    mark_candidates_running,
    normalize_login_candidate,
    pending_candidates,
    resolve_candidate_decisions,
)


class CredentialAuditTests(unittest.TestCase):
    def test_login_candidate_normalization_filters_static_assets(self) -> None:
        self.assertEqual(
            normalize_login_candidate("HTTPS://Example.COM/admin/login/#section"),
            "https://example.com/admin/login",
        )
        self.assertEqual(normalize_login_candidate("https://example.com/login.js"), "")
        self.assertEqual(normalize_login_candidate("https://example.com/dashboard"), "")

    def test_user_decision_preserves_usernames_and_wordlist(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            bus = AssetBus(
                run_dir / "tool_data" / "asset_bus" / "assets.json",
                "*",
                "example.com",
                approval_mode="automatic",
            )
            bus.ingest([("https://example.com/admin/login", "url")], "project_target")
            discover_login_candidates(run_dir, bus, {})
            candidate = pending_candidates(run_dir)[0]
            append_decisions(
                run_dir,
                [
                    {
                        "id": candidate["id"],
                        "action": "agent_social_dictionary",
                        "username_candidates": ["admin", "operator"],
                        "wordlist_path": "D:/wordlists/site.txt",
                    }
                ],
            )

            self.assertEqual(resolve_candidate_decisions(run_dir), 1)
            resolved = read_json(candidate_path(run_dir))["candidates"][0]
            self.assertEqual(resolved["status"], "approved_agent")
            self.assertEqual(resolved["username_candidates"], ["admin", "operator"])
            self.assertEqual(resolved["wordlist_path"], "D:/wordlists/site.txt")

    def test_timeout_uses_save_only_default(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            bus = AssetBus(
                run_dir / "tool_data" / "asset_bus" / "assets.json",
                "*",
                "example.com",
                approval_mode="automatic",
            )
            bus.ingest([("https://example.com/login", "url")], "project_target")
            discover_login_candidates(run_dir, bus, {})
            value = read_json(candidate_path(run_dir))
            value["candidates"][0]["decision_deadline_at"] = "2000-01-01T00:00:00+00:00"
            atomic_json_write(candidate_path(run_dir), value)

            self.assertEqual(resolve_candidate_decisions(run_dir), 1)
            resolved = read_json(candidate_path(run_dir))["candidates"][0]
            self.assertEqual(resolved["status"], "saved")
            self.assertEqual(resolved["decision_source"], "timeout_default")

    def test_failed_agent_batch_is_retryable_and_success_completes(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            path = candidate_path(run_dir)
            atomic_json_write(
                path,
                {
                    "candidates": [
                        {"id": "candidate-1", "status": "approved_agent"}
                    ]
                },
            )

            self.assertEqual(mark_candidates_running(run_dir, ["candidate-1"], 3), 1)
            self.assertEqual(finish_batch_candidates(run_dir, 3, False), 1)
            self.assertEqual(
                read_json(path)["candidates"][0]["status"], "approved_agent"
            )
            self.assertEqual(mark_candidates_running(run_dir, ["candidate-1"], 4), 1)
            self.assertEqual(finish_batch_candidates(run_dir, 4, True), 1)
            self.assertEqual(read_json(path)["candidates"][0]["status"], "completed")

    def test_disabling_feature_clears_pending_and_approved_tasks(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            path = candidate_path(run_dir)
            atomic_json_write(
                path,
                {
                    "policy": {"enabled": True},
                    "candidates": [
                        {"id": "pending", "status": "pending"},
                        {"id": "approved", "status": "approved_agent"},
                    ],
                },
            )
            bus = AssetBus(
                run_dir / "tool_data" / "asset_bus" / "assets.json",
                "*",
                "example.com",
            )

            discover_login_candidates(
                run_dir, bus, {"credential_audit_enabled": False}
            )

            rows = read_json(path)["candidates"]
            self.assertEqual([row["status"] for row in rows], ["saved", "saved"])
            self.assertEqual([row["action"] for row in rows], ["save_only", "save_only"])


if __name__ == "__main__":
    unittest.main()
