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
    log_refresh_scroll_policy,
    render_component_state,
)


class RunLogDialogTests(unittest.TestCase):
    def test_log_refresh_follows_when_already_at_bottom(self) -> None:
        self.assertEqual(
            log_refresh_scroll_policy((0.8, 1.0), False),
            (True, 0.8),
        )

    def test_log_refresh_preserves_manual_scroll_when_not_at_bottom(self) -> None:
        self.assertEqual(
            log_refresh_scroll_policy((0.42, 0.7), False),
            (False, 0.42),
        )

    def test_log_refresh_explicit_auto_follow_wins(self) -> None:
        self.assertEqual(
            log_refresh_scroll_policy((0.1, 0.2), True),
            (True, 0.1),
        )

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

    def test_project_coordinator_exposes_incremental_state_and_batches(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            state_path = run_dir / "tool_data" / "coordinator" / "state.json"
            asset_bus = run_dir / "tool_data" / "asset_bus" / "assets.json"
            batch = run_dir / "agent_batches" / "0001" / "batch.json"
            state_path.parent.mkdir(parents=True)
            asset_bus.parent.mkdir(parents=True)
            batch.parent.mkdir(parents=True)
            state_path.write_text(
                json.dumps(
                    {
                        "status": "running",
                        "stage": "agent_running",
                        "detail": "资产代次 3；Agent 已消费到 2；当前 Agent PID 123",
                    }
                ),
                encoding="utf-8",
            )
            asset_bus.write_text(json.dumps({"generation": 3}), encoding="utf-8")
            batch.write_text(json.dumps({"batch": 1}), encoding="utf-8")

            sources = component_paths(
                run_dir, "project_coordinator", "项目增量调度/Agent"
            )

            self.assertEqual(
                component_runtime(run_dir, "project_coordinator"),
                (
                    "running",
                    "agent_running",
                    "资产代次 3；Agent 已消费到 2；当前 Agent PID 123",
                ),
            )
            self.assertEqual(
                sources["workdir"], run_dir / "tool_data" / "coordinator"
            )
            self.assertIn(asset_bus, sources["states"])
            self.assertIn(batch, sources["logs"])
            self.assertIn(run_dir / "risk_summary.md", sources["results"])
            self.assertIn(run_dir / "agent_batches", sources["results"])

    def test_project_coordinator_activity_filter_owns_asset_bus_events(self) -> None:
        content = "\n".join(
            (
                "[1] 资产总线接收 fscan 新增资产 5 条，代次 2。",
                "[2] fscan 基础探测已结束。",
                "[3] Agent 批次 1 已启动。",
            )
        )

        filtered = filter_component_activity(
            content, "project_coordinator", "项目增量调度/Agent"
        )

        self.assertIn("资产总线", filtered)
        self.assertIn("Agent 批次", filtered)
        self.assertNotIn("fscan 基础探测已结束", filtered)


    def test_semantic_component_uses_only_the_current_project_log(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            workdir = run_dir / "tool_data" / "semantic"
            current = workdir / "projects" / "current"
            old = workdir / "projects" / "old"
            (current / "runs" / "one").mkdir(parents=True)
            old.mkdir(parents=True)
            (workdir / "launcher_state.json").write_text(
                json.dumps({"last_project": "current"}),
                encoding="utf-8",
            )
            current_log = current / "gui.log"
            old_log = old / "gui.log"
            current_state = current / "runs" / "one" / "runtime_state.json"
            current_log.write_text("current log", encoding="utf-8")
            old_log.write_text("old log", encoding="utf-8")
            current_state.write_text(json.dumps({"phase": "running"}), encoding="utf-8")

            sources = component_paths(run_dir, "semantic_dirscan")

            self.assertEqual(sources["logs"], [current_log])
            self.assertIn(current_state, sources["states"])
            self.assertNotIn(old_log, sources["logs"])
            self.assertEqual(sources["results"][0], current)

    def test_semantic_bridge_state_is_rendered_for_people_not_as_raw_json(self) -> None:
        with TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "sttool_bridge_state.json"
            state_path.write_text(
                json.dumps(
                    {
                        "project": "demo",
                        "updated_at": "2026-08-02T16:10:22+08:00",
                        "targets": [
                            "http://10.17.200.115/",
                            "http://10.17.200.115:8081/",
                        ],
                        "queued_asset_targets": ["https://api.example.test/"],
                        "asset_workflow_status": "completed",
                        "asset_handoff_ready": True,
                        "candidate_count": 4,
                        "asset_candidate_count": 4,
                        "fscan_candidate_count": 0,
                        "accepted_count": 4,
                        "rejected": 0,
                        "rejected_targets": [],
                        "source_markers": {
                            "fscan_result": {"size": 1837, "mtime_ns": 123}
                        },
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            rendered = render_component_state(state_path, "semantic_dirscan")

            self.assertIn("\u8d44\u4ea7\u540c\u6b65\u6982\u89c8", rendered)
            self.assertIn("\u5df2\u7eb3\u5165\u626b\u63cf\u76ee\u6807\uff1a2 \u6761", rendered)
            self.assertIn("\u7b49\u5f85\u653e\u884c\u76ee\u6807\uff1a1 \u6761", rendered)
            self.assertIn("http://10.17.200.115:8081/", rendered)
            self.assertIn("\u6700\u7ec8 Web \u626b\u63cf\u76ee\u6807\uff1a4 \u4e2a", rendered)
            self.assertIn("AssetCommander \u5019\u9009\uff1a4 \u4e2a", rendered)
            self.assertIn("Fscan \u5019\u9009\uff1a0 \u4e2a", rendered)
            self.assertIn("\u8fc7\u6ee4\uff1a0 \u4e2a", rendered)
            self.assertNotIn('"schema_version"', rendered)

    def test_semantic_component_runtime_reconciles_asset_counts(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            state_path = (
                run_dir / "tool_data" / "semantic" / "sttool_bridge_state.json"
            )
            state_path.parent.mkdir(parents=True)
            state_path.write_text(
                json.dumps(
                    {
                        "asset_workflow_status": "completed",
                        "targets": [
                            "http://10.17.200.115/",
                            "http://10.17.200.115:8081/",
                            "https://10.17.200.115:443/",
                            "http://10.17.200.251/",
                        ],
                        "asset_candidate_count": 4,
                        "fscan_candidate_count": 0,
                        "accepted_count": 4,
                        "rejected": 0,
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                component_runtime(run_dir, "semantic_dirscan"),
                (
                    "running",
                    "directory_scan",
                    "\u6700\u7ec8 Web \u626b\u63cf\u76ee\u6807 4 \u4e2a\uff1b"
                    "AssetCommander \u5019\u9009 4 \u4e2a\uff1b"
                    "Fscan \u5019\u9009 0 \u4e2a\uff1b\u8fc7\u6ee4 0 \u4e2a",
                ),
            )

    def test_semantic_runtime_state_has_readable_progress(self) -> None:
        with TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "runtime_state.json"
            state_path.write_text(
                json.dumps(
                    {
                        "phase": "running",
                        "target": "https://example.test/",
                        "current_url": "https://example.test/admin/",
                        "current_depth": 1,
                        "completed_targets": 3,
                        "queue_size": 4,
                        "round_count": 3,
                        "wordlist": "selected-api.txt",
                    }
                ),
                encoding="utf-8",
            )

            rendered = render_component_state(state_path, "semantic_dirscan")

            self.assertIn("\u5f53\u524d\u626b\u63cf\u8fdb\u5ea6", rendered)
            self.assertIn("\u5f85\u626b\u63cf\u961f\u5217\uff1a4", rendered)
            self.assertIn("https://example.test/admin/", rendered)

    def test_coordinator_managed_vulnerability_tools_have_virtual_status(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            coordinator = run_dir / "tool_data" / "coordinator" / "state.json"
            coordinator.parent.mkdir(parents=True)
            coordinator.write_text(
                json.dumps(
                    {
                        "vuln_intel_status": "completed",
                        "vuln_intel_candidates": 3,
                        "vuln_intel_high_confidence": 2,
                        "find_gh_poc_status": "skipped_no_token",
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                component_runtime(run_dir, "vulnx"),
                (
                    "completed",
                    "vulnerability_intelligence",
                    "候选 3，高可信 2",
                ),
            )
            self.assertEqual(
                component_runtime(run_dir, "find_gh_poc"),
                (
                    "manual_required",
                    "waiting_github_token",
                    "未配置 GitHub Token；已安全跳过，不影响其他阶段",
                ),
            )
            sources = component_paths(run_dir, "find_gh_poc")
            self.assertIn(
                run_dir / "results" / "find_gh_poc.json", sources["results"]
            )


if __name__ == "__main__":
    unittest.main()
