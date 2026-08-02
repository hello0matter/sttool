from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sttool.run_log_dialog import (
    component_display_runtime,
    filter_component_activity,
    component_paths,
    component_runtime,
    component_summary_status,
)


class RunLogDialogTests(unittest.TestCase):
    def test_component_activity_filter_excludes_other_tools(self) -> None:
        content = "\n".join(
            (
                "[19:55:00] 工具已启动：fscan 基础探测，PID 1。",
                "[19:55:01] TscanPlus 等待 AssetCommander。",
                "[19:55:01] TscanPlus 等待 AssetCommander，当前步骤：fscan。",
                "[19:55:02] 组件状态变化：fscan 基础探测 running -> exited。",
            )
        )

        filtered = filter_component_activity(content, "fscan", "fscan 基础探测")

        self.assertIn("fscan 基础探测", filtered)
        self.assertNotIn("TscanPlus", filtered)

    def test_tscan_component_exposes_waiting_stage_and_detail(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            state_path = run_dir / "tool_data" / "tscan" / "state.json"
            state_path.parent.mkdir(parents=True)
            state_path.write_text(
                json.dumps(
                    {
                        "status": "waiting_assets",
                        "stage": "waiting_asset_commander",
                        "detail": "等待 AssetCommander 回传资产",
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                component_runtime(run_dir, "tscan_plus"),
                (
                    "waiting_assets",
                    "waiting_asset_commander",
                    "等待 AssetCommander 回传资产",
                ),
            )

    def test_component_paths_include_state_log_result_and_workdir(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            sources = component_paths(run_dir, "asset_commander")

            self.assertEqual(
                sources["workdir"], run_dir / "tool_data" / "asset_commander"
            )
            self.assertIn(
                run_dir
                / "tool_data"
                / "asset_commander"
                / "workflow_state.json",
                sources["states"],
            )
            self.assertIn(
                run_dir / "results" / "asset_commander_assets.json",
                sources["results"],
            )

    def test_fscan_component_uses_filtered_component_log(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            (run_dir / "activity.log").write_text(
                "[1] fscan started\n[2] TscanPlus waiting\n",
                encoding="utf-8",
            )

            sources = component_paths(run_dir, "fscan", "fscan 基础探测")
            component_log = run_dir / "component_logs" / "fscan.log"

            self.assertIn(component_log, sources["logs"])
            self.assertEqual(
                component_log.read_text(encoding="utf-8"), "[1] fscan started\n"
            )

    def test_stopped_process_overrides_stale_running_workflow(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            state_path = (
                run_dir / "tool_data" / "asset_commander" / "workflow_state.json"
            )
            state_path.parent.mkdir(parents=True)
            state_path.write_text(
                json.dumps(
                    {
                        "status": "running",
                        "current_step": "collision",
                        "steps": {"collision": {"status": "running"}},
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "processes": [
                            {
                                "component_id": "asset_commander",
                                "status": "stopped",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            status, stage, detail = component_display_runtime(
                run_dir, "asset_commander"
            )
            self.assertEqual(status, "stopped")
            self.assertEqual(stage, "process_stopped")
            self.assertIn("最后步骤：collision", detail)

    def test_completed_asset_workflow_explains_that_window_is_retained(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            state_path = (
                run_dir / "tool_data" / "asset_commander" / "workflow_state.json"
            )
            state_path.parent.mkdir(parents=True)
            state_path.write_text(
                json.dumps({"status": "completed", "current_step": "", "steps": {}}),
                encoding="utf-8",
            )

            status, stage, detail = component_runtime(run_dir, "asset_commander")

            self.assertEqual(status, "completed")
            self.assertEqual(stage, "")
            self.assertIn("窗口仍保留", detail)


    def test_completed_asset_summary_distinguishes_retained_window(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            state_path = (
                run_dir / "tool_data" / "asset_commander" / "workflow_state.json"
            )
            state_path.parent.mkdir(parents=True)
            state_path.write_text(
                json.dumps({"status": "completed", "current_step": "", "steps": {}}),
                encoding="utf-8",
            )

            self.assertEqual(
                component_summary_status(run_dir, "asset_commander", "running"),
                "完成（窗口保留）",
            )
            self.assertEqual(
                component_summary_status(run_dir, "asset_commander", "exited"),
                "完成",
            )


if __name__ == "__main__":
    unittest.main()
