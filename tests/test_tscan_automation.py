from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sttool.tscan_automation import (
    filter_assets_by_scope,
    normalize_poc_urls,
    password_targets,
    read_asset_bundle,
    scope_allows_all,
    stage_status_from_result,
    target_asset_bundle,
    workflow_assets_ready,
    workflow_completed,
)


class TscanAutomationTests(unittest.TestCase):
    def test_scope_star_accepts_only_the_supplied_or_discovered_assets(self) -> None:
        bundle = {
            "ips": ["192.0.2.10", "198.51.100.7"],
            "domains": ["app.example.com", "outside.test"],
            "urls": ["https://app.example.com/login", "https://outside.test"],
        }

        self.assertTrue(scope_allows_all("*"))
        self.assertEqual(filter_assets_by_scope(bundle, "*"), bundle)

    def test_explicit_domain_and_network_scope_filters_assets(self) -> None:
        bundle = {
            "ips": ["192.0.2.10", "198.51.100.7"],
            "domains": ["app.example.com", "outside.test"],
            "urls": ["https://app.example.com/login", "https://outside.test"],
        }

        self.assertEqual(
            filter_assets_by_scope(bundle, "example.com,192.0.2.0/24"),
            {
                "ips": ["192.0.2.10"],
                "domains": ["app.example.com"],
                "urls": ["https://app.example.com/login"],
            },
        )

    def test_asset_export_merges_the_primary_target_without_duplicates(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "assets.json"
            path.write_text(
                json.dumps(
                    {
                        "ips": ["192.0.2.10"],
                        "domains": ["app.example.com", "api.example.com"],
                        "urls": [],
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                read_asset_bundle(path, "https://app.example.com/login"),
                {
                    "ips": ["192.0.2.10"],
                    "domains": ["app.example.com", "api.example.com"],
                    "urls": ["https://app.example.com/login"],
                },
            )

    def test_poc_and_password_targets_are_normalized(self) -> None:
        self.assertEqual(
            normalize_poc_urls(
                ["https://app.example.com/login"],
                ["app.example.com"],
                "https://app.example.com/login",
            ),
            [
                "https://app.example.com/login",
                "https://app.example.com",
                "http://app.example.com",
            ],
        )
        self.assertEqual(
            password_targets(["192.0.2.10", "bad", "192.0.2.10"]),
            ["192.0.2.10"],
        )

    def test_workflow_helpers_handle_target_and_completion(self) -> None:
        self.assertEqual(
            target_asset_bundle("http://192.0.2.10:8080/path"),
            {
                "ips": ["192.0.2.10"],
                "domains": [],
                "urls": ["http://192.0.2.10:8080/path"],
            },
        )
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "workflow.json"
            path.write_text('{"status":"completed"}', encoding="utf-8")
            self.assertTrue(workflow_completed(path))
            self.assertTrue(workflow_assets_ready(path))
            path.write_text(
                json.dumps(
                    {
                        "status": "running",
                        "current_step": "collision",
                        "asset_handoff": {
                            "status": "ready",
                            "phase": "pre_collision",
                        },
                    }
                ),
                encoding="utf-8",
            )
            self.assertFalse(workflow_completed(path))
            self.assertTrue(workflow_assets_ready(path))

    def test_stage_status_distinguishes_submitted_waiting_and_skipped(self) -> None:
        self.assertEqual(
            stage_status_from_result({"scan_clicked": True}, True), "submitted"
        )
        self.assertEqual(
            stage_status_from_result(
                {"reason": "AWVS API 或 API Key 尚未配置"}, True
            ),
            "waiting_configuration",
        )
        self.assertEqual(
            stage_status_from_result({"reason": "没有可导入的 IP"}, True),
            "skipped",
        )
        self.assertEqual(stage_status_from_result({}, False), "prepared")


if __name__ == "__main__":
    unittest.main()
