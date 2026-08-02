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

    def test_fast_preset_allows_early_incremental_agent(self) -> None:
        settings = work_mode_defaults("fast")
        self.assertFalse(settings["wait_for_asset_commander"])
        self.assertFalse(settings["wait_for_fscan"])
        self.assertEqual(settings["asset_settle_seconds"], 8)

    def test_changed_preset_values_are_saved_as_custom_and_clamped(self) -> None:
        settings = normalize_workflow_settings(
            {
                "work_mode": "balanced",
                "asset_settle_seconds": 9999,
                "max_agent_batches": 0,
                "coordinator_poll_seconds": 0,
            }
        )
        self.assertEqual(settings["work_mode"], "custom")
        self.assertEqual(settings["asset_settle_seconds"], 600)
        self.assertEqual(settings["max_agent_batches"], 1)
        self.assertEqual(settings["coordinator_poll_seconds"], 1)

    def test_invalid_reasoning_effort_uses_cli_default(self) -> None:
        self.assertEqual(normalized_reasoning_effort("HIGH"), "high")
        self.assertEqual(normalized_reasoning_effort("unsupported"), "")


if __name__ == "__main__":
    unittest.main()
