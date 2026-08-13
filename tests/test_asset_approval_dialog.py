from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sttool.asset_approval_dialog import (
    append_asset_decisions,
    pending_group_matches,
    pending_asset_groups,
)
from sttool.asset_bus import read_json
from sttool.project_access_dialog import asset_row_matches, asset_row_sort_key


class AssetApprovalDialogTests(unittest.TestCase):
    def test_project_asset_search_matches_value_source_and_status(self) -> None:
        item = {
            "status": "blocked",
            "type": "url",
            "value": "https://api.example.test/admin",
            "sources": ["tscan", "semantic_dirscan"],
            "reason": "user_blocked_asset",
        }

        self.assertTrue(asset_row_matches(item, "api.example"))
        self.assertTrue(asset_row_matches(item, "tscan"))
        self.assertTrue(asset_row_matches(item, "已阻止"))
        self.assertFalse(asset_row_matches(item, "192.0.2.1"))

    def test_asset_value_sort_orders_ip_addresses_numerically(self) -> None:
        rows = [
            {"value": "192.0.2.100"},
            {"value": "192.0.2.8"},
            {"value": "192.0.2.20"},
        ]

        rows.sort(key=lambda item: asset_row_sort_key(item, "value"))

        self.assertEqual(
            [item["value"] for item in rows],
            ["192.0.2.8", "192.0.2.20", "192.0.2.100"],
        )

    def test_pending_assets_are_grouped_by_host_with_sources_and_defaults(self) -> None:
        groups = pending_asset_groups(
            {
                "pending": [
                    {
                        "id": "one",
                        "group_key": "192.0.2.20",
                        "value": "192.0.2.20",
                        "type": "ip",
                        "source": "asset_commander",
                        "sources": ["asset_commander"],
                        "reason": "same_cidr",
                        "default_action": "accept",
                    },
                    {
                        "id": "two",
                        "group_key": "192.0.2.20",
                        "value": "192.0.2.20:8080",
                        "type": "endpoint",
                        "source": "fscan",
                        "sources": ["fscan"],
                        "reason": "same_cidr",
                        "default_action": "accept",
                    },
                ]
            }
        )

        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["ids"], ["one", "two"])
        self.assertEqual(groups[0]["count"], 2)
        self.assertEqual(groups[0]["sources"], ["asset_commander", "fscan"])
        self.assertEqual(groups[0]["default_action"], "accept")

    def test_pending_group_filters_support_search_type_and_source(self) -> None:
        item = {
            "group_key": "api.example.test",
            "types": ["domain", "url"],
            "sources": ["asset_commander", "tscan"],
            "reason_text": "新发现的主机",
            "examples": ["https://api.example.test/login"],
        }

        self.assertTrue(pending_group_matches(item, "login"))
        self.assertTrue(pending_group_matches(item, asset_type="url"))
        self.assertTrue(pending_group_matches(item, source="tscan"))
        self.assertFalse(pending_group_matches(item, asset_type="ip"))
        self.assertFalse(pending_group_matches(item, source="fscan"))

    def test_decision_file_merges_without_losing_previous_choices(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "decisions.json"
            append_asset_decisions(path, [{"id": "one", "action": "accept"}])
            append_asset_decisions(path, [{"id": "two", "action": "reject"}])

            value = read_json(path)

            self.assertEqual(
                {item["id"]: item["action"] for item in value["decisions"]},
                {"one": "accept", "two": "reject"},
            )


if __name__ == "__main__":
    unittest.main()
