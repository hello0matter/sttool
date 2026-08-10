from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sttool.asset_approval_dialog import (
    append_asset_decisions,
    pending_asset_groups,
)
from sttool.asset_bus import read_json


class AssetApprovalDialogTests(unittest.TestCase):
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
