from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sttool.asset_bus import AssetBus, parse_fscan_output
from sttool.models import ProcessRecord
from sttool.runtime import now_text, process_creation_token
from sttool.project_coordinator import (
    agent_launch_ready,
    asset_commander_ready,
    build_batch_prompt,
    component_process_alive,
    coordinator_wait_stage,
    mark_agent_batch_finished,
    render_risk_summary,
    response_text,
    tracked_process_alive,
    tscan_source_ready,
    write_agent_batch_script,
)


class ProjectCoordinatorTests(unittest.TestCase):
    def test_agent_pid_token_rejects_pid_reused_by_another_process(self) -> None:
        token = process_creation_token(os.getpid())
        self.assertTrue(tracked_process_alive(os.getpid(), token, Path.cwd()))
        self.assertFalse(tracked_process_alive(os.getpid(), token + 1, Path.cwd()))

    def test_component_process_alive_rejects_foreign_pid_token(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            record = ProcessRecord(
                component_id="fscan",
                name="fscan",
                pid=os.getpid(),
                command=["fscan.exe"],
                cwd=str(run_dir),
                started_at=now_text(),
                creation_token=process_creation_token(os.getpid()) + 1,
            )
            (run_dir / "run.json").write_text(
                json.dumps({"processes": [record.__dict__]}), encoding="utf-8"
            )

            self.assertFalse(component_process_alive(run_dir, "fscan"))

    def test_tscan_source_waits_for_sanitized_workspace_marker(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "app" / "config" / "config.db"
            database.parent.mkdir(parents=True)
            database.write_bytes(b"historical database")

            self.assertFalse(tscan_source_ready(database))
            (database.parents[1] / ".sttool_initialized").write_text(
                "ready\n", encoding="utf-8"
            )
            self.assertTrue(tscan_source_ready(database))

    def test_agent_waits_for_asset_commander_fscan_and_quiet_window(self) -> None:
        base = {
            "active_pid": 0,
            "generation": 2,
            "consumed_generation": 0,
            "asset_ready": True,
            "fscan_ready": True,
            "quiet": True,
            "batch_count": 0,
            "max_batches": 8,
        }
        for field in ("asset_ready", "fscan_ready", "quiet"):
            values = dict(base)
            values[field] = False
            self.assertFalse(agent_launch_ready(**values), field)
        self.assertTrue(agent_launch_ready(**base))

    def test_active_agent_and_consumed_generation_prevent_duplicate_launch(
        self,
    ) -> None:
        self.assertFalse(
            agent_launch_ready(
                active_pid=123,
                generation=2,
                consumed_generation=1,
                asset_ready=True,
                fscan_ready=True,
                quiet=True,
                batch_count=1,
                max_batches=8,
            )
        )
        self.assertFalse(
            agent_launch_ready(
                active_pid=0,
                generation=2,
                consumed_generation=2,
                asset_ready=True,
                fscan_ready=True,
                quiet=True,
                batch_count=1,
                max_batches=8,
            )
        )
        self.assertTrue(
            agent_launch_ready(
                active_pid=0,
                generation=3,
                consumed_generation=2,
                asset_ready=True,
                fscan_ready=True,
                quiet=True,
                batch_count=1,
                max_batches=8,
            )
        )

    def test_wait_stage_explains_current_blocker(self) -> None:
        common = {
            "active_pid": 0,
            "generation": 2,
            "consumed_generation": 0,
            "asset_ready": True,
            "fscan_ready": True,
            "quiet": True,
            "batch_count": 0,
            "max_batches": 8,
        }
        values = dict(common)
        values["asset_ready"] = False
        self.assertEqual(coordinator_wait_stage(**values)[0], "waiting_asset_commander")
        values = dict(common)
        values["fscan_ready"] = False
        self.assertEqual(coordinator_wait_stage(**values)[0], "waiting_fscan")
        values = dict(common)
        values["quiet"] = False
        self.assertEqual(coordinator_wait_stage(**values)[0], "settling_assets")
        values = dict(common)
        values["consumed_generation"] = 2
        self.assertEqual(coordinator_wait_stage(**values)[0], "waiting_new_assets")

    def test_asset_commander_must_complete_before_initial_agent(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            path = run_dir / "tool_data" / "asset_commander" / "workflow_state.json"
            path.parent.mkdir(parents=True)
            path.write_text(
                json.dumps(
                    {
                        "status": "running",
                        "asset_handoff": {"status": "ready", "phase": "pre_collision"},
                    }
                ),
                encoding="utf-8",
            )
            self.assertFalse(asset_commander_ready(run_dir))
            path.write_text(json.dumps({"status": "completed"}), encoding="utf-8")
            self.assertTrue(asset_commander_ready(run_dir))

    def test_risk_summary_and_prompt_include_every_fscan_web_url(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            bus = AssetBus(run_dir / "tool_data" / "asset_bus" / "assets.json", "*")
            assets = parse_fscan_output(
                "10.17.200.115:22\n"
                "http://10.17.200.115:81 [gateway] 200 nginx\n"
                "http://10.17.200.115:9001 [admin] 200\n"
                "https://app.example.com:443/login 200\n"
            )
            bus.ingest(assets, "fscan")

            summary = render_risk_summary(run_dir, bus, run_dir / "missing.db", "test")
            prompt = build_batch_prompt(run_dir, "base", bus, 0, 1)

            for url in (
                "http://10.17.200.115:81/",
                "http://10.17.200.115:9001/",
                "https://app.example.com/login",
            ):
                self.assertIn(url, summary)
                self.assertIn(url, prompt)
            self.assertIn("10.17.200.115:22", prompt)

    def test_finished_batch_updates_state_and_batch_metadata(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            batch_dir = run_dir / "agent_batches" / "0001"
            batch_dir.mkdir(parents=True)
            metadata_path = batch_dir / "batch.json"
            metadata_path.write_text(
                json.dumps({"batch": 1, "pid": 123, "status": "running"}),
                encoding="utf-8",
            )
            batches: list[object] = [
                {"batch": 1, "pid": 123, "run_dir": str(batch_dir), "status": "running"}
            ]

            mark_agent_batch_finished(run_dir, batches, 123)

            self.assertEqual(batches[0]["status"], "completed")
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertEqual(metadata["status"], "completed")
            self.assertTrue(metadata["completed_at"])

    def test_response_text_supports_responses_and_chat_payloads(self) -> None:
        self.assertEqual(
            response_text({"output_text": "responses result"}),
            "responses result",
        )
        self.assertEqual(
            response_text({"choices": [{"message": {"content": "chat result"}}]}),
            "chat result",
        )
        self.assertEqual(
            response_text(
                {
                    "output": [
                        {
                            "content": [
                                {"type": "output_text", "text": "first result"},
                                {"type": "output_text", "text": "second result"},
                            ]
                        }
                    ]
                }
            ),
            "first result\nsecond result",
        )

    def test_manual_mode_keeps_collecting_without_launching_agent(self) -> None:
        values = {
            "active_pid": 0,
            "generation": 2,
            "consumed_generation": 0,
            "asset_ready": True,
            "fscan_ready": True,
            "quiet": True,
            "batch_count": 0,
            "max_batches": 8,
            "auto_agent": False,
        }
        self.assertFalse(agent_launch_ready(**values))
        self.assertEqual(coordinator_wait_stage(**values)[0], "manual_agent")

    def test_agent_batch_script_applies_explicit_cli_overrides(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            batch_dir = run_dir / "agent_batches" / "0001"
            batch_dir.mkdir(parents=True)
            script_path, _pid_path = write_agent_batch_script(
                batch_dir,
                "codexx",
                "demo",
                "gpt-5.6-sol",
                "high",
            )
            script = script_path.read_text(encoding="utf-8-sig")
            self.assertIn(
                "& codexx --yolo -m 'gpt-5.6-sol' "
                "-c 'model_reasoning_effort=\"high\"' $prompt",
                script,
            )


if __name__ == "__main__":
    unittest.main()
