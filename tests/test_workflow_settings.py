from __future__ import annotations

import unittest

from sttool.workflow_settings import (
    normalize_workflow_settings,
    normalized_reasoning_effort,
    work_mode_defaults,
)


class WorkflowSettingsTests(unittest.TestCase):
    def test_balanced_mode_preserves_delayed_agent_defaults(self) -> None:
        settings = normalize_workflow_settings({})
        self.assertEqual(settings["work_mode"], "balanced")
        self.assertTrue(settings["wait_for_asset_commander"])
        self.assertTrue(settings["wait_for_fscan"])
        self.assertEqual(settings["asset_settle_seconds"], 20)
        self.assertEqual(settings["max_agent_batches"], 8)
        self.assertTrue(settings["fscan_skip_poc"])
        self.assertTrue(settings["fscan_skip_brute"])
        self.assertEqual(settings["fscan_port_threads"], 600)
        self.assertEqual(settings["semantic_threads"], 40)
        self.assertEqual(settings["semantic_max_depth"], 2)
        self.assertTrue(settings["semantic_run_dirsearch"])
        self.assertEqual(settings["agent_stall_warn_minutes"], 15)
        self.assertFalse(settings["allow_cidr_expansion"])
        self.assertEqual(settings["new_asset_approval_mode"], "countdown_accept")
        self.assertEqual(settings["new_asset_countdown_seconds"], 10)
        self.assertTrue(settings["new_asset_popup_enabled"])
        self.assertTrue(settings["new_asset_popup_topmost"])

    def test_fast_preset_allows_early_incremental_agent(self) -> None:
        settings = work_mode_defaults("fast")
        self.assertFalse(settings["wait_for_asset_commander"])
        self.assertFalse(settings["wait_for_fscan"])
        self.assertEqual(settings["asset_settle_seconds"], 8)
        self.assertFalse(settings["semantic_run_dirsearch"])
        self.assertEqual(settings["semantic_max_depth"], 1)

    def test_changed_preset_values_are_saved_as_custom_and_clamped(self) -> None:
        settings = normalize_workflow_settings(
            {
                "work_mode": "balanced",
                "asset_settle_seconds": 9999,
                "max_agent_batches": 0,
                "coordinator_poll_seconds": 0,
                "agent_stall_warn_minutes": 9999,
            }
        )
        self.assertEqual(settings["work_mode"], "custom")
        self.assertEqual(settings["asset_settle_seconds"], 600)
        self.assertEqual(settings["max_agent_batches"], 1)
        self.assertEqual(settings["coordinator_poll_seconds"], 1)
        self.assertEqual(settings["agent_stall_warn_minutes"], 1440)

    def test_scan_controls_are_clamped_and_customized(self) -> None:
        settings = normalize_workflow_settings(
            {
                "work_mode": "balanced",
                "fscan_port_threads": 99999,
                "semantic_threads": 0,
                "semantic_max_depth": -3,
                "semantic_max_rate": 99999,
                "semantic_run_dirsearch": False,
            }
        )
        self.assertEqual(settings["work_mode"], "custom")
        self.assertEqual(settings["fscan_port_threads"], 2000)
        self.assertEqual(settings["semantic_threads"], 1)
        self.assertEqual(settings["semantic_max_depth"], 0)
        self.assertEqual(settings["semantic_max_rate"], 10000)
        self.assertFalse(settings["semantic_run_dirsearch"])

    def test_asset_approval_policy_is_normalized_and_clamped(self) -> None:
        settings = normalize_workflow_settings(
            {
                "work_mode": "balanced",
                "allow_cidr_expansion": True,
                "new_asset_approval_mode": "invalid",
                "new_asset_countdown_seconds": 1,
                "new_asset_popup_topmost": False,
            }
        )

        self.assertEqual(settings["work_mode"], "custom")
        self.assertTrue(settings["allow_cidr_expansion"])
        self.assertEqual(settings["new_asset_approval_mode"], "countdown_accept")
        self.assertEqual(settings["new_asset_countdown_seconds"], 3)
        self.assertFalse(settings["new_asset_popup_topmost"])

    def test_invalid_reasoning_effort_uses_cli_default(self) -> None:
        self.assertEqual(normalized_reasoning_effort("HIGH"), "high")
        self.assertEqual(normalized_reasoning_effort("unsupported"), "")


if __name__ == "__main__":
    unittest.main()
