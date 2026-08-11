from __future__ import annotations

import json
import os
import unittest
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from sttool.agent_launcher import write_agent_batch_script
from sttool.asset_bus import AssetBus, atomic_json_write, parse_fscan_output
from sttool.credential_audit import candidate_path
from sttool.incremental_nuclei import (
    build_incremental_nuclei_command,
    initial_incremental_nuclei_urls,
    incremental_nuclei_candidates,
)
from sttool.models import ProcessRecord
from sttool.runtime import now_text, process_creation_token
from sttool.project_coordinator import (
    agent_retry_status,
    agent_launch_ready,
    apply_hot_workflow_settings,
    agent_batch_health,
    codex_session_last_activity,
    codex_session_terminal_state,
    asset_commander_ready,
    build_incremental_fscan_command,
    build_batch_prompt,
    compact_ai_summary_input,
    completed_batch_orphan_processes,
    component_process_alive,
    coordinator_wait_stage,
    incremental_fscan_candidates,
    agent_batch_terminal_state,
    asset_commander_collision_paths,
    mark_agent_batch_finished,
    schedule_agent_retry,
    semantic_dirsearch_marker,
    semantic_dirsearch_output_active,
    semantic_dirsearch_output_files,
    successful_agent_batch_count,
    render_risk_summary,
    remember_agent_process_tree,
    recover_completed_batch_orphans,
    response_text,
    terminate_remembered_agent_processes,
    tracked_process_alive,
    tscan_source_ready,
)


class ProjectCoordinatorTests(unittest.TestCase):
    def test_failed_agent_records_do_not_consume_success_limit(self) -> None:
        batches: list[object] = [
            *({"status": "completed"} for _ in range(3)),
            *({"status": "failed"} for _ in range(5)),
        ]

        completed = successful_agent_batch_count(batches)

        self.assertEqual(completed, 3)
        self.assertTrue(
            agent_launch_ready(
                active_pid=0,
                generation=64,
                consumed_generation=63,
                asset_ready=True,
                fscan_ready=True,
                quiet=True,
                batch_count=completed,
                max_batches=8,
            )
        )

    def test_three_consecutive_agent_failures_pause_retry(self) -> None:
        failure_count, retry_seconds, retry_ready = agent_retry_status(
            {"agent_failure_count": 3, "agent_retry_not_before": 0}
        )

        self.assertEqual((failure_count, retry_seconds, retry_ready), (3, 0, False))

    def test_hot_workflow_updates_live_coordinator_arguments(self) -> None:
        with TemporaryDirectory() as temporary:
            bus = AssetBus(Path(temporary) / "assets.json", "*", "example.com")
            args = SimpleNamespace(provider="codexx")

            workflow = apply_hot_workflow_settings(
                args,
                bus,
                {
                    "workflow": {
                        "work_mode": "custom",
                        "new_asset_countdown_seconds": 20,
                        "workload_countdown_seconds": 25,
                        "coordinator_poll_seconds": 7,
                        "max_agent_batches": 12,
                        "scope": "allowed.example",
                        "asset_processing_scope": "api.allowed.example",
                    },
                    "agent": {
                        "provider": "codexx",
                        "agent_model": "hot-model",
                        "reasoning_effort": "high",
                        "agent_base_url": "https://agent.example/v1",
                    },
                },
            )

            self.assertEqual(workflow["new_asset_countdown_seconds"], 20)
            self.assertEqual(args.new_asset_countdown_seconds, 20)
            self.assertEqual(args.workload_countdown_seconds, 25)
            self.assertEqual(args.poll_seconds, 7)
            self.assertEqual(args.max_agent_batches, 12)
            self.assertEqual(args.agent_model, "hot-model")
            self.assertEqual(args.reasoning_effort, "high")
            self.assertEqual(args.agent_base_url, "https://agent.example/v1")
            self.assertEqual(bus.approval_seconds, 20)
            self.assertEqual(args.scope, "allowed.example")
            self.assertEqual(bus.scope, "allowed.example")
            self.assertEqual(bus.processing_scope, "api.allowed.example")

    def test_semantic_dirsearch_output_files_and_markers_are_stable(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            semantic_state = run_dir / "tool_data" / "semantic" / "state.json"
            output = (
                semantic_state.parent
                / "projects"
                / "demo"
                / "runs"
                / "run-1"
                / "dirsearch.txt"
            )
            output.parent.mkdir(parents=True)
            output.write_text(
                "200    15B   https://app.example.test/health\n",
                encoding="utf-8",
            )

            self.assertEqual(
                semantic_dirsearch_output_files(semantic_state), [output]
            )
            marker = semantic_dirsearch_marker(run_dir, [output])
            self.assertEqual(marker[0][0], output.relative_to(run_dir).as_posix())
            self.assertEqual(marker[0][1], output.stat().st_size)
            self.assertEqual(marker[0][2], output.stat().st_mtime_ns)

    def test_semantic_dirsearch_output_active_matches_exact_output_path(self) -> None:
        output = Path("run") / "dirsearch.txt"
        matching = MagicMock()
        matching.info = {
            "name": "python.exe",
            "cmdline": ["python", "dirsearch", "-o", str(output)],
        }
        unrelated = MagicMock()
        unrelated.info = {
            "name": "python.exe",
            "cmdline": ["python", "dirsearch", "-o", "other.txt"],
        }

        with patch(
            "sttool.project_coordinator.psutil.process_iter",
            return_value=[unrelated, matching],
        ):
            self.assertTrue(semantic_dirsearch_output_active([output]))
            self.assertFalse(
                semantic_dirsearch_output_active([Path("missing") / "result.txt"])
            )

    def test_completed_batch_orphan_requires_provider_prompt_and_cwd(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            batch_dir = run_dir / "agent_batches" / "0001"
            batch_dir.mkdir(parents=True)
            prompt = batch_dir / "prompt.txt"
            prompt.write_text("prompt", encoding="utf-8")
            (batch_dir / "batch.json").write_text(
                json.dumps(
                    {
                        "provider": "codexx",
                        "started_at": "1970-01-01T00:00:10+00:00",
                        "completed_at": "1970-01-01T00:00:20+00:00",
                    }
                ),
                encoding="utf-8",
            )
            matching = MagicMock()
            matching.info = {
                "pid": 123,
                "name": "codexx.exe",
                "cmdline": ["codexx.exe", "--yolo", str(prompt)],
                "create_time": 10.5,
            }
            matching.cwd.return_value = str(run_dir)
            unrelated = MagicMock()
            unrelated.info = {
                "pid": 456,
                "name": "codexx.exe",
                "cmdline": ["codexx.exe", "--yolo", "manual prompt"],
                "create_time": 11.5,
            }
            unrelated.cwd.return_value = str(run_dir)
            reused_prompt = MagicMock()
            reused_prompt.info = {
                "pid": 789,
                "name": "codexx.exe",
                "cmdline": ["codexx.exe", "--yolo", str(prompt)],
                "create_time": 3600.0,
            }
            reused_prompt.cwd.return_value = str(run_dir)
            batch = {
                "status": "completed",
                "run_dir": str(batch_dir),
            }

            with patch(
                "sttool.project_coordinator.psutil.process_iter",
                return_value=[matching, unrelated, reused_prompt],
            ):
                matches = completed_batch_orphan_processes(batch, run_dir)

            self.assertEqual(
                matches, [{"pid": 123, "creation_token": 10_500_000}]
            )

    def test_recover_completed_batch_orphans_terminates_verified_match(self) -> None:
        batch: dict[str, object] = {"status": "completed"}
        match = {"pid": 123, "creation_token": 456}
        with (
            patch(
                "sttool.project_coordinator.completed_batch_orphan_processes",
                return_value=[match],
            ),
            patch(
                "sttool.project_coordinator.tracked_process_alive",
                return_value=True,
            ),
            patch(
                "sttool.project_coordinator.terminate_agent_process_tree"
            ) as terminate,
        ):
            recovered = recover_completed_batch_orphans([batch], Path.cwd())

        self.assertEqual(recovered, [123])
        self.assertEqual(batch["owned_processes"], [match])
        terminate.assert_called_once_with(123)

    def test_remembered_agent_processes_require_matching_creation_token(self) -> None:
        batch: dict[str, object] = {}
        remember_agent_process_tree(batch, os.getpid())
        remembered = batch.get("owned_processes")
        self.assertIsInstance(remembered, list)
        self.assertTrue(
            any(item.get("pid") == os.getpid() for item in remembered)
        )

        remembered[0]["creation_token"] = int(
            remembered[0]["creation_token"]
        ) + 1
        with unittest.mock.patch(
            "sttool.project_coordinator.terminate_agent_process_tree"
        ) as terminate:
            terminate_remembered_agent_processes(batch, Path.cwd())
        terminate.assert_not_called()

    def test_codex_completed_session_recovers_stuck_cli_wrapper(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "run"
            batch_dir = run_dir / "agent_batches" / "0001"
            sessions = root / "sessions"
            batch_dir.mkdir(parents=True)
            sessions.mkdir()
            (batch_dir / "prompt.txt").write_text("prompt", encoding="utf-8")
            session = sessions / "turn.jsonl"
            events = (
                {
                    "timestamp": "2026-08-07T13:37:51Z",
                    "type": "session_meta",
                    "payload": {"cwd": str(run_dir)},
                },
                {
                    "timestamp": "2026-08-07T13:37:52Z",
                    "payload": {"type": "agent_message", "message": str(run_dir)},
                },
                {
                    "timestamp": "2026-08-07T13:37:53Z",
                    "payload": {
                        "type": "error",
                        "message": "unexpected status 503 Service Unavailable, url: secret",
                    },
                },
                {
                    "timestamp": "2026-08-07T13:37:54Z",
                    "payload": {"type": "task_complete"},
                },
            )
            session.write_text(
                "\n".join(json.dumps(item) for item in events),
                encoding="utf-8",
            )

            self.assertEqual(
                codex_session_terminal_state(run_dir, batch_dir, sessions),
                {
                    "status": "failed",
                    "completed_at": "2026-08-07T13:37:54Z",
                    "exit_code": 1,
                    "source": "codex_session",
                    "error": "Codex provider error: 503 Service Unavailable",
                },
            )

    def test_collision_paths_find_results_and_evidence(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            project = (
                run_dir
                / "tool_data"
                / "asset_commander"
                / "workspace"
                / "demo"
            )
            evidence = project / "evidence"
            evidence.mkdir(parents=True)
            results = project / "results.csv"
            results.write_text("url,host,request_mode\n", encoding="utf-8")

            self.assertEqual(
                asset_commander_collision_paths(run_dir), ([results], [evidence])
            )

    def test_incremental_fscan_only_selects_unattempted_ips(self) -> None:
        with TemporaryDirectory() as temporary:
            bus = AssetBus(Path(temporary) / "assets.json", "*")
            bus.ingest(
                [
                    ("192.0.2.10", "ip"),
                    ("192.0.2.11", "ip"),
                    ("app.example.com", "domain"),
                ],
                "test",
            )

            self.assertEqual(
                incremental_fscan_candidates(bus, ["192.0.2.10"]),
                ["192.0.2.11"],
            )

    def test_incremental_fscan_command_is_bounded_service_detection(self) -> None:
        command = build_incremental_fscan_command(
            Path("fscan.exe"),
            Path("targets.txt"),
            Path("result.txt"),
            321,
        )

        self.assertEqual(command[:3], ["fscan.exe", "-hf", "targets.txt"])
        self.assertIn("-nobr", command)
        self.assertIn("-nopoc", command)
        self.assertEqual(command[command.index("-t") + 1], "321")
        self.assertNotIn("-h", command)

    def test_incremental_nuclei_batches_only_unattempted_urls(self) -> None:
        with TemporaryDirectory() as temporary:
            bus = AssetBus(Path(temporary) / "assets.json", "*")
            bus.ingest(
                [
                    ("https://one.example/", "url"),
                    ("https://two.example/", "url"),
                    ("192.0.2.10", "ip"),
                ],
                "test",
            )

            candidates = incremental_nuclei_candidates(
                bus, ["https://one.example/"], limit=1
            )

        self.assertEqual(candidates, ["https://two.example/"])

    def test_existing_project_seeds_nuclei_history_without_backfill(self) -> None:
        with TemporaryDirectory() as temporary:
            bus = AssetBus(Path(temporary) / "assets.json", "*")
            bus.ingest(
                [
                    ("https://existing-one.example/", "url"),
                    ("https://existing-two.example/", "url"),
                ],
                "legacy",
            )

            attempted = initial_incremental_nuclei_urls(
                bus, "https://initial.example/"
            )

        self.assertEqual(
            attempted,
            ["https://existing-one.example/", "https://existing-two.example/"],
        )

    def test_incremental_nuclei_command_uses_target_file_and_distinct_output(
        self,
    ) -> None:
        command = build_incremental_nuclei_command(
            Path("nuclei.exe"), Path("targets.txt"), Path("result.txt")
        )

        self.assertEqual(
            command,
            [
                "nuclei.exe",
                "-l",
                "targets.txt",
                "-silent",
                "-o",
                "result.txt",
            ],
        )

    def test_agent_batch_health_reports_stall_without_killing_process(self) -> None:
        with TemporaryDirectory() as temporary:
            batch_dir = Path(temporary)
            marker = batch_dir / "batch.json"
            marker.write_text("{}", encoding="utf-8")
            status, elapsed, activity = agent_batch_health(
                batch_dir, warn_minutes=5, now=marker.stat().st_mtime + 6 * 60
            )

            self.assertEqual(status, "suspected_stalled")
            self.assertEqual(activity, datetime.fromtimestamp(marker.stat().st_mtime).astimezone().isoformat(timespec="seconds"))
            self.assertGreaterEqual(elapsed or 0, 6)

    def test_codex_session_activity_tracks_progress_outside_batch_directory(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "run"
            batch_dir = run_dir / "agent_batches" / "0001"
            sessions = root / "sessions"
            batch_dir.mkdir(parents=True)
            sessions.mkdir()
            prompt = batch_dir / "prompt.txt"
            prompt.write_text("prompt", encoding="utf-8")
            session = sessions / "rollout.jsonl"
            session.write_text(
                json.dumps(
                    {
                        "type": "session_meta",
                        "payload": {"cwd": str(run_dir)},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            modified_at = prompt.stat().st_mtime + 30
            os.utime(session, (modified_at, modified_at))

            activity = codex_session_last_activity(run_dir, batch_dir, sessions)

            self.assertEqual(activity, (modified_at, session))

    def test_large_ai_summary_input_is_bounded_and_keeps_both_ends(self) -> None:
        summary = "A" * 120 + "MIDDLE" + "Z" * 120
        compact = compact_ai_summary_input(summary, max_chars=100)

        self.assertLessEqual(len(compact), 100)
        self.assertTrue(compact.startswith("A"))
        self.assertTrue(compact.endswith("Z"))
        self.assertNotIn("MIDDLE", compact)

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
            self.assertIn("vulnerability_intel.md", prompt)
            self.assertIn("vulnerability_intel.json", prompt)
            self.assertIn("PoC \u94fe\u63a5\u53ea\u662f\u4e0d\u53ef\u4fe1\u5019\u9009", prompt)
            self.assertIn("\u7981\u6b62\u81ea\u52a8\u5199\u6587\u4ef6", prompt)

    def test_agent_prompt_includes_only_approved_credential_task_and_limits(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            bus = AssetBus(
                run_dir / "tool_data" / "asset_bus" / "assets.json",
                "*",
                "example.com",
                approval_mode="automatic",
            )
            bus.ingest([("https://example.com/admin/login", "url")], "project_target")
            atomic_json_write(
                candidate_path(run_dir),
                {
                    "policy": {
                        "max_attempts": 6,
                        "requests_per_minute": 8,
                        "concurrency": 1,
                    },
                    "candidates": [
                        {
                            "id": "approved",
                            "url": "https://example.com/admin/login",
                            "status": "approved_agent",
                            "action": "agent_default_dictionary",
                            "username_candidates": ["admin"],
                            "wordlist_path": "D:/wordlists/site.txt",
                            "successful_password": "must-not-leak",
                        },
                        {
                            "id": "pending",
                            "url": "https://other.example.com/login",
                            "status": "pending",
                            "action": "agent_default_dictionary",
                        },
                    ],
                },
            )

            prompt = build_batch_prompt(run_dir, "base", bus, 0, 1)

            self.assertIn("https://example.com/admin/login", prompt)
            self.assertNotIn("https://other.example.com/login", prompt)
            self.assertIn("browser-burp-pentest / burp Skill", prompt)
            self.assertIn("每个账号最多尝试 6 次", prompt)
            self.assertIn("每分钟 8 请求", prompt)
            self.assertIn("并发不超过 1", prompt)
            self.assertIn("成功口令不得写入", prompt)
            self.assertNotIn("must-not-leak", prompt)

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

    def test_batch_status_completes_batch_without_shell_exit_file(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            batch_dir = run_dir / "agent_batches" / "0001"
            batch_dir.mkdir(parents=True)
            metadata_path = batch_dir / "batch.json"
            metadata_path.write_text(
                json.dumps({"batch": 1, "pid": 123, "status": "running"}),
                encoding="utf-8",
            )
            completed_at = "2026-08-06T18:29:05+08:00"
            (batch_dir / "batch_status.json").write_text(
                json.dumps({"status": "completed", "completed_at": completed_at}),
                encoding="utf-8",
            )
            batches: list[object] = [
                {"batch": 1, "pid": 123, "run_dir": str(batch_dir), "status": "running"}
            ]

            marker = agent_batch_terminal_state(batch_dir)
            finished = mark_agent_batch_finished(run_dir, batches, 123)

            self.assertEqual(marker, {"status": "completed", "completed_at": completed_at})
            self.assertEqual(
                finished,
                {
                    "batch": 1,
                    "pid": 123,
                    "run_dir": str(batch_dir),
                    "status": "completed",
                    "completed_at": completed_at,
                    "exit_code": 0,
                },
            )
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertEqual(metadata["status"], "completed")
            self.assertEqual(metadata["completed_at"], completed_at)
            self.assertEqual(metadata["exit_code"], 0)

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
                "-c 'model_reasoning_effort=\"high\"' $bootstrapPrompt",
                script,
            )


    def test_claude_batch_script_applies_autonomy_model_and_effort(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            batch_dir = run_dir / "agent_batches" / "0001"
            batch_dir.mkdir(parents=True)
            script_path, _pid_path = write_agent_batch_script(
                batch_dir,
                "claude",
                "demo",
                "claude-opus-4-1",
                "high",
            )
            script = script_path.read_text(encoding="utf-8-sig")
            self.assertIn(
                "& claude --dangerously-skip-permissions "
                "--model 'claude-opus-4-1' --effort 'high' $bootstrapPrompt",
                script,
            )

    def test_failed_batch_uses_exit_state_and_is_retryable(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            batch_dir = run_dir / "agent_batches" / "0001"
            batch_dir.mkdir(parents=True)
            (batch_dir / "agent_exit.json").write_text(
                json.dumps({"exit_code": 1, "error": "startup failed"}),
                encoding="utf-8",
            )
            batches: list[object] = [
                {
                    "batch": 1,
                    "pid": 123,
                    "run_dir": str(batch_dir),
                    "status": "running",
                    "generation_to": 2,
                }
            ]

            finished = mark_agent_batch_finished(run_dir, batches, 123)
            state: dict[str, object] = {}
            delay = schedule_agent_retry(state, "exit 1")

            self.assertIsNotNone(finished)
            self.assertEqual(finished["status"], "failed")
            self.assertEqual(delay, 60)
            self.assertFalse(
                agent_launch_ready(
                    active_pid=0,
                    generation=2,
                    consumed_generation=0,
                    asset_ready=True,
                    fscan_ready=True,
                    quiet=True,
                    batch_count=1,
                    max_batches=8,
                    retry_ready=False,
                )
            )
            self.assertEqual(
                coordinator_wait_stage(
                    active_pid=0,
                    generation=2,
                    consumed_generation=0,
                    asset_ready=True,
                    fscan_ready=True,
                    quiet=True,
                    batch_count=1,
                    max_batches=8,
                    retry_ready=False,
                    retry_seconds=60,
                )[0],
                "agent_backoff",
            )

    def test_agent_batch_script_uses_short_prompt_file_bootstrap(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            batch_dir = run_dir / "agent_batches" / "0001"
            batch_dir.mkdir(parents=True)
            large_prompt = "x" * 100_000
            (batch_dir / "prompt.txt").write_text(large_prompt, encoding="utf-8")

            script_path, _pid_path = write_agent_batch_script(
                batch_dir, "codex", "demo"
            )
            script = script_path.read_text(encoding="utf-8-sig")

            self.assertNotIn(large_prompt, script)
            self.assertNotIn("Get-Content -Raw", script)
            self.assertIn(str((batch_dir / "prompt.txt").resolve()), script)
            self.assertIn("& codex --yolo $bootstrapPrompt", script)
            self.assertIn("agent_exit.json", script)
            self.assertIn("exit 0", script)


if __name__ == "__main__":
    unittest.main()
