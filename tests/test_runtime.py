from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from sttool.agent_runtime import (
    agent_terminal_window_name,
    is_agent_shell_process_info,
)
from sttool.models import LaunchRequest, ProcessRecord, RunState, ToolDefinition
from sttool.registry import availability, default_tools
from sttool.runtime import (
    RuntimeManager,
    agent_cli_arguments,
    atomic_json_write,
    now_text,
    pid_alive,
    process_creation_token,
    process_record_alive,
    reconcile_component_state,
    safe_project_name,
    target_values,
)
from sttool.tool_store import ToolStore
from sttool.tscan_automation import target_for_asset_scan


class OfflineRuntimeManager(RuntimeManager):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.handles: list[subprocess.Popen] = []
        self.spawn_environments: dict[str, dict[str, str]] = {}
        self.spawn_commands: dict[str, list[str]] = {}

    def provider_health(self, provider: str) -> tuple[bool, str]:
        return True, "test"

    def _spawn(
        self,
        component_id: str,
        name: str,
        executable: str,
        args: list[str],
        cwd: str,
        new_console: bool,
        environment: dict[str, str] | None = None,
    ):
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        self.handles.append(process)
        self.spawn_environments[component_id] = dict(environment or {})
        self.spawn_commands[component_id] = [executable, *args]
        return ProcessRecord(
            component_id=component_id,
            name=name,
            pid=process.pid,
            command=[sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=cwd,
            started_at=now_text(),
            creation_token=process_creation_token(process.pid),
        )

    def _launch_agent_in_windows_terminal(
        self,
        request: LaunchRequest,
        run_dir: Path,
        script: Path,
        terminal: str,
    ) -> ProcessRecord:
        return self._spawn(
            "ai_agent",
            f"{self.provider_display_name(request.provider)} Agent",
            "powershell.exe",
            ["-NoLogo", "-ExecutionPolicy", "Bypass", "-File", str(script)],
            str(run_dir),
            True,
        )

    def cleanup(self) -> None:
        for process in self.handles:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)


class RuntimeTests(unittest.TestCase):
    def test_process_record_rejects_reused_pid_creation_token(self) -> None:
        token = process_creation_token(os.getpid())
        self.assertGreater(token, 0)
        record = ProcessRecord(
            component_id="foreign",
            name="Foreign process",
            pid=os.getpid(),
            command=[sys.executable],
            cwd=str(Path.cwd()),
            started_at=now_text(),
            creation_token=token + 1,
        )

        self.assertFalse(process_record_alive(record, Path.cwd()))

    def test_legacy_process_record_is_migrated_only_when_run_matches(self) -> None:
        record = ProcessRecord(
            component_id="legacy",
            name="Legacy process",
            pid=os.getpid(),
            command=[sys.executable],
            cwd=str(Path.cwd()),
            started_at=now_text(),
        )

        self.assertTrue(process_record_alive(record, Path.cwd()))
        self.assertEqual(record.creation_token, process_creation_token(os.getpid()))
        with TemporaryDirectory() as temporary:
            foreign = ProcessRecord(
                component_id="foreign",
                name="Foreign process",
                pid=os.getpid(),
                command=[sys.executable],
                cwd=temporary,
                started_at=now_text(),
            )
            self.assertFalse(process_record_alive(foreign, temporary))
            self.assertEqual(foreign.creation_token, 0)

    def test_stop_does_not_terminate_pid_owned_by_another_run(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            record = ProcessRecord(
                component_id="foreign",
                name="Foreign process",
                pid=os.getpid(),
                command=[sys.executable],
                cwd=str(run_dir),
                started_at=now_text(),
                creation_token=process_creation_token(os.getpid()) + 1,
            )
            state = RunState(
                run_id="run",
                project_name="demo",
                target="example.com",
                scope="example.com",
                provider="codexx",
                model="gpt-5.5",
                selected_tools=[],
                run_dir=str(run_dir),
                created_at=now_text(),
                updated_at=now_text(),
                status="running",
                processes=[record],
            )
            manager = RuntimeManager(run_dir, [], st_root=run_dir)
            batch_dir = run_dir / "agent_batches" / "0001"
            batch_dir.mkdir(parents=True)
            launch_script = batch_dir / "launch.ps1"
            launch_script.write_text("Write-Host 'legacy launch'\n", encoding="utf-8")
            (batch_dir / "launch.token").write_text("token", encoding="ascii")

            with patch("sttool.runtime.terminate_process_tree") as terminate:
                manager.stop(state)

            terminate.assert_not_called()
            self.assertEqual(state.processes[0].status, "stopped")
            self.assertFalse((batch_dir / "launch.token").exists())
            self.assertIn(
                "project is stopped",
                launch_script.read_text(encoding="utf-8-sig"),
            )
            self.assertEqual(len(list(batch_dir.glob("launch.stopped-*.ps1"))), 1)
            activity = (run_dir / "activity.log").read_text(encoding="utf-8")
            self.assertIn("PID 已被其他进程占用", activity)

    def test_refresh_preserves_explicitly_stopped_run_state(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            state = RunState(
                run_id="run",
                project_name="demo",
                target="example.com",
                scope="example.com",
                provider="codexx",
                model="gpt-5.5",
                selected_tools=[],
                run_dir=str(run_dir),
                created_at=now_text(),
                updated_at=now_text(),
                status="stopped",
                processes=[],
            )
            manager = RuntimeManager(run_dir, [], st_root=run_dir)

            refreshed = manager.refresh(state)

            self.assertEqual(refreshed.status, "stopped")
            persisted = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(persisted["status"], "stopped")

    def test_atomic_json_write_retries_transient_replace_permission_error(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.json"
            original_replace = os.replace
            attempts = 0

            def flaky_replace(source: str, destination: str | Path) -> None:
                nonlocal attempts
                attempts += 1
                if attempts < 3:
                    raise PermissionError("temporarily locked")
                original_replace(source, destination)

            with (
                patch("sttool.runtime.os.replace", side_effect=flaky_replace),
                patch("sttool.runtime.time.sleep") as sleep,
            ):
                atomic_json_write(path, {"status": "completed"})

            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8")),
                {"status": "completed"},
            )
            self.assertEqual(attempts, 3)
            self.assertEqual([call.args[0] for call in sleep.call_args_list], [0.01, 0.03])

    def test_reconcile_asset_commander_running_preserves_active_step(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            workflow_path = (
                run_dir / "tool_data" / "asset_commander" / "workflow_state.json"
            )
            workflow_path.parent.mkdir(parents=True)
            workflow_path.write_text(
                json.dumps(
                    {
                        "status": "running",
                        "current_step": "collision",
                        "steps": {
                            "collision": {"status": "running", "detail": "active"}
                        },
                    }
                ),
                encoding="utf-8",
            )

            reconcile_component_state(
                run_dir,
                "asset_commander",
                "running",
                "component process is running",
            )

            workflow = json.loads(workflow_path.read_text(encoding="utf-8"))
            self.assertEqual(workflow["status"], "running")
            self.assertEqual(workflow["process_status"], "running")
            self.assertEqual(workflow["steps"]["collision"]["status"], "running")
            self.assertEqual(workflow["steps"]["collision"]["detail"], "active")

    def test_reconcile_asset_commander_marks_stale_scan_interrupted(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            state_path = (
                run_dir / "tool_data" / "asset_commander" / "workflow_state.json"
            )
            progress_path = (
                run_dir
                / "tool_data"
                / "asset_commander"
                / "workspace"
                / "demo"
                / "scan_progress.json"
            )
            state_path.parent.mkdir(parents=True)
            progress_path.parent.mkdir(parents=True)
            state_path.write_text(
                json.dumps(
                    {
                        "status": "running",
                        "current_step": "collision",
                        "steps": {"collision": {"status": "running", "detail": ""}},
                    }
                ),
                encoding="utf-8",
            )
            progress_path.write_text(
                json.dumps({"current": 600, "total": 44160, "active": True}),
                encoding="utf-8",
            )

            reconcile_component_state(
                run_dir,
                "asset_commander",
                "interrupted",
                "process exited",
            )

            workflow = json.loads(state_path.read_text(encoding="utf-8"))
            progress = json.loads(progress_path.read_text(encoding="utf-8"))
            self.assertEqual(workflow["status"], "interrupted")
            self.assertEqual(workflow["steps"]["collision"]["status"], "interrupted")
            self.assertFalse(progress["active"])
            self.assertEqual(progress["stop_reason"], "process exited")

    def test_safe_project_name_and_target_values(self) -> None:
        self.assertEqual(safe_project_name(" 客户:A/B "), "客户_A_B")
        self.assertEqual(
            target_values("https://app.example.com:8443/a"),
            {
                "target": "https://app.example.com:8443/a",
                "target_host": "app.example.com",
                "target_domain": "example.com",
            },
        )
        self.assertEqual(
            target_values("192.168.1.0/24"),
            {
                "target": "192.168.1.0/24",
                "target_host": "192.168.1.0/24",
                "target_domain": "192.168.1.0/24",
            },
        )

    def test_atomic_json_write(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "nested" / "state.json"
            atomic_json_write(path, {"name": "测试", "count": 2})
            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8")),
                {"name": "测试", "count": 2},
            )
            self.assertFalse(list(path.parent.glob("*.tmp")))

    def test_project_round_trip(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            tool = ToolDefinition(
                tool_id="dummy",
                name="Dummy",
                category="test",
                description="test",
                executable=sys.executable,
            )
            manager = RuntimeManager(root, [tool], st_root=root)
            project_dir = manager.projects_dir / "demo"
            project_dir.mkdir()
            atomic_json_write(
                project_dir / "project.json",
                {"name": "demo", "target": "example.com"},
            )
            self.assertEqual(manager.list_projects(), ["demo"])
            self.assertEqual(
                manager.load_project("demo"),
                {"name": "demo", "target": "example.com"},
            )

    def test_legacy_codex_provider_migrates_to_codexx(self) -> None:
        base = {
            "run_id": "run",
            "project_name": "demo",
            "target": "example.com",
            "scope": "example.com",
            "provider": "codex",
            "model": "tool-model",
            "selected_tools": [],
            "run_dir": "run",
            "created_at": "2026-01-01T00:00:00+08:00",
            "updated_at": "2026-01-01T00:00:00+08:00",
            "status": "completed",
        }

        legacy = RunState.from_dict({**base, "schema_version": 1})
        current = RunState.from_dict({**base, "schema_version": 2})

        self.assertEqual(legacy.provider, "codexx")
        self.assertEqual(current.provider, "codex")

    def test_prepare_tool_moves_json_secret_to_environment(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.json"
            source.write_text(
                json.dumps({"api_key": "test-secret", "enabled": True}),
                encoding="utf-8",
            )
            tool = ToolDefinition(
                tool_id="secret-test",
                name="Secret test",
                category="test",
                description="test",
                executable=sys.executable,
                cwd="{run_dir}",
                prepare_files=((str(source), "tool/config.json"),),
                secret_env=(("STTOOL_TEST_API_KEY", str(source), "api_key"),),
            )
            manager = RuntimeManager(root, [tool], st_root=root)
            run_dir = root / "run"
            run_dir.mkdir()
            environment = manager._prepare_tool(
                tool,
                {
                    "run_dir": str(run_dir),
                    "project_dir": str(root),
                    "source_dir": str(root),
                    "st_root": str(root),
                    "target": "example.com",
                    "target_host": "example.com",
                    "target_domain": "example.com",
                },
            )
            copied = json.loads(
                (run_dir / "tool" / "config.json").read_text(encoding="utf-8")
            )
            self.assertEqual(environment, {"STTOOL_TEST_API_KEY": "test-secret"})
            self.assertEqual(copied, {"api_key": "", "enabled": True})

    def test_prepare_tool_refreshes_code_but_preserves_runtime_data_on_recovery(
        self,
    ) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_config = root / "source-config.json"
            source_script = root / "source-script.py"
            source_config.write_text('{"source": true}', encoding="utf-8")
            source_script.write_text("print('new')\n", encoding="utf-8")
            tool = ToolDefinition(
                tool_id="recovery-test",
                name="Recovery test",
                category="test",
                description="test",
                executable=sys.executable,
                cwd="{run_dir}",
                prepare_files=((str(source_config), "tool/config.json"),),
                refresh_files=((str(source_script), "tool/main.py"),),
            )
            manager = RuntimeManager(root, [tool], st_root=root)
            run_dir = root / "run"
            (run_dir / "tool").mkdir(parents=True)
            (run_dir / "tool" / "config.json").write_text(
                '{"runtime": true}', encoding="utf-8"
            )
            (run_dir / "tool" / "main.py").write_text(
                "print('old')\n", encoding="utf-8"
            )

            manager._prepare_tool(
                tool,
                {"run_dir": str(run_dir)},
                preserve_existing=True,
            )

            self.assertEqual(
                (run_dir / "tool" / "config.json").read_text(encoding="utf-8"),
                '{"runtime": true}',
            )
            self.assertEqual(
                (run_dir / "tool" / "main.py").read_text(encoding="utf-8"),
                "print('new')\n",
            )

    def test_availability_checks_required_paths(self) -> None:
        tool = ToolDefinition(
            tool_id="required",
            name="Required",
            category="test",
            description="test",
            executable=sys.executable,
            required_paths=(str(Path("missing-required-file")),),
        )
        healthy, detail = availability(tool)
        self.assertFalse(healthy)
        self.assertIn("missing-required-file", detail)

    def test_tscan_target_normalization(self) -> None:
        self.assertEqual(
            target_for_asset_scan("https://example.com/path"), "example.com"
        )
        self.assertEqual(
            target_for_asset_scan("http://example.com:8080/path"), "example.com:8080"
        )
        self.assertEqual(target_for_asset_scan("192.168.1.0/24"), "192.168.1.0/24")

    def test_tscan_registry_uses_automation_wrapper(self) -> None:
        tool = next(
            tool
            for tool in default_tools(Path(r"D:\test-st-root"))
            if tool.tool_id == "tscan_plus"
        )
        self.assertTrue(tool.sends_requests)
        self.assertTrue(any(arg.endswith("tscan_automation.py") for arg in tool.args))
        self.assertIn("{target}", tool.args)
        self.assertIn("{project_name}", tool.args)
        self.assertIn("{scope}", tool.args)
        self.assertIn("--asset-state", tool.args)
        self.assertIn("--asset-export", tool.args)
        self.assertNotIn("safe_poc_gui", {item.tool_id for item in default_tools()})

    def test_asset_commander_registry_uses_resumable_source_workflow(self) -> None:
        tool = next(
            tool
            for tool in default_tools(Path(r"D:\test-st-root"))
            if tool.tool_id == "asset_commander"
        )
        self.assertTrue(tool.sends_requests)
        self.assertTrue(tool.restart_on_recovery)
        self.assertIn("--sttool-project", tool.args)
        self.assertIn("--sttool-target", tool.args)
        self.assertIn("--sttool-scope", tool.args)
        self.assertIn("--sttool-state", tool.args)
        self.assertIn("--sttool-export", tool.args)
        self.assertIn("--sttool-asset-bus", tool.args)
        self.assertIn("{run_dir}/tool_data/asset_bus/assets.json", tool.args)
        self.assertIn("{scope}", tool.args)
        self.assertTrue(
            any(path.endswith("asset_workflow.py") for path in tool.required_paths)
        )
        self.assertIn(("OPENAI_BASE_URL", "{api_base_url}"), tool.environment)
        self.assertIn(("OPENAI_MODEL", "{model}"), tool.environment)
        self.assertIn(("OPENAI_API_KEY", "{api_key}"), tool.environment)

    def test_semantic_dirscan_registry_uses_resumable_source_bridge(self) -> None:
        tool = next(
            tool
            for tool in default_tools(Path(r"D:\test-st-root"))
            if tool.tool_id == "semantic_dirscan"
        )
        self.assertTrue(tool.sends_requests)
        self.assertTrue(tool.restart_on_recovery)
        self.assertIn("--sttool-project", tool.args)
        self.assertIn("--sttool-asset-export", tool.args)
        self.assertIn("--sttool-asset-state", tool.args)
        self.assertIn("--sttool-fscan-result", tool.args)
        self.assertIn("--sttool-auto-start", tool.args)
        self.assertTrue(
            any(path.endswith("sttool_bridge.py") for path in tool.required_paths)
        )
        self.assertTrue(
            any(
                destination.endswith("sttool_bridge.py")
                for _, destination in tool.refresh_files
            )
        )
        self.assertIn(("OPENAI_BASE_URL", "{api_base_url}"), tool.environment)
        self.assertIn(("OPENAI_API_KEY", "{api_key}"), tool.environment)

    def test_default_tools_excludes_poc_toolbox(self) -> None:
        tool_ids = {tool.tool_id for tool in default_tools(Path(r"D:\test-st-root"))}
        self.assertNotIn("safe_poc_gui", tool_ids)

    def test_only_one_shot_builtin_scanners_allow_standalone_execution(self) -> None:
        tools = {tool.tool_id: tool for tool in default_tools(Path(r"D:\test-st-root"))}

        self.assertTrue(tools["fscan"].allow_standalone)
        self.assertTrue(tools["nuclei"].allow_standalone)
        self.assertTrue(tools["vulnx"].allow_standalone)
        self.assertFalse(tools["vulnx"].sends_requests)
        self.assertTrue(tools["find_gh_poc"].allow_standalone)
        self.assertFalse(tools["find_gh_poc"].sends_requests)
        self.assertIn("--exe", tools["find_gh_poc"].args)
        self.assertTrue(tools["vulnx"].coordinator_managed)
        self.assertTrue(tools["find_gh_poc"].coordinator_managed)
        self.assertTrue(all(tool.default_selected for tool in tools.values()))
        self.assertFalse(tools["asset_commander"].allow_standalone)
        self.assertFalse(tools["semantic_dirscan"].allow_standalone)

    def test_tool_store_persists_builtin_locations_and_custom_tools(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_path = root / "tools.json"
            asset_dir = root / "portable" / "AssetCommander"
            store = ToolStore(config_path, st_root=root / "default-tools")

            store.set_location("asset_commander", str(asset_dir))
            poc_executable = root / "portable" / "find-gh-poc.exe"
            store.set_location("find_gh_poc", str(poc_executable))
            store.set_asset_collision_settings(
                {
                    "preserve_original_port": False,
                    "add_80": True,
                    "add_443": False,
                    "no_port": True,
                    "absolute_path": True,
                    "waf_header": True,
                    "force_sni": True,
                    "threads": 88,
                }
            )
            custom = store.upsert_custom(
                {
                    "name": "HTTP Probe",
                    "category": "资产验证",
                    "description": "自定义探测工具",
                    "executable": sys.executable,
                    "args": ("--target", "{target}", "--scope", "{scope}"),
                    "cwd": "{run_dir}",
                    "sends_requests": True,
                    "new_console": True,
                    "uses_shared_ai": True,
                    "allow_standalone": True,
                    "result_paths": (
                        "{run_dir}/results/probe.json",
                        "{run_dir}/reports",
                    ),
                }
            )

            reloaded = ToolStore(config_path, st_root=root / "default-tools")
            tools = {tool.tool_id: tool for tool in reloaded.tools()}
            asset = tools["asset_commander"]
            encoded_collision_config = asset.args[
                asset.args.index("--sttool-collision-config") + 1
            ]
            collision_config = json.loads(encoded_collision_config.format_map({}))
            self.assertEqual(collision_config["threads"], 88)
            self.assertTrue(collision_config["waf_header"])
            self.assertFalse(collision_config["preserve_original_port"])
            self.assertEqual(
                reloaded.location_for("asset_commander", asset),
                str(asset_dir.resolve()),
            )
            self.assertEqual(Path(asset.args[0]), asset_dir.resolve() / "main.py")
            github_poc = tools["find_gh_poc"]
            github_executable_index = github_poc.args.index("--exe") + 1
            self.assertEqual(
                Path(github_poc.args[github_executable_index]), poc_executable.resolve()
            )
            self.assertEqual(
                tools[custom.tool_id],
                custom,
            )
            self.assertIn("{target}", tools[custom.tool_id].args)
            self.assertIn("{scope}", tools[custom.tool_id].args)
            self.assertEqual(
                tools[custom.tool_id].result_paths,
                ("{run_dir}/results/probe.json", "{run_dir}/reports"),
            )
            self.assertTrue(tools[custom.tool_id].uses_shared_ai)
            self.assertTrue(tools[custom.tool_id].allow_standalone)

            reloaded.remove_custom(custom.tool_id)
            self.assertNotIn(
                custom.tool_id, {tool.tool_id for tool in reloaded.tools()}
            )

    def test_standalone_tool_run_is_kept_outside_projects(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            tool = ToolDefinition(
                tool_id="one_shot",
                name="One shot",
                category="test",
                description="test",
                executable=sys.executable,
                args=(
                    "--target", "{target}",
                    "-t", "{fscan_port_threads}",
                    "{fscan_skip_poc_flag}", "{fscan_skip_brute_flag}",
                    "--output", "{run_dir}/results/out.txt",
                ),
                cwd="{run_dir}",
                sends_requests=True,
                result_paths=("{run_dir}/results/out.txt",),
                allow_standalone=True,
            )
            manager = OfflineRuntimeManager(root, [tool], st_root=root)
            try:
                state = manager.start_standalone(
                    "one_shot",
                    "https://example.com/path",
                    authorization_confirmed=True,
                    api_base_url="https://gateway.example/v1",
                    model="tool-model",
                    workflow_settings={
                        "work_mode": "balanced",
                        "fscan_port_threads": 123,
                        "fscan_skip_poc": True,
                        "fscan_skip_brute": True,
                    },
                )

                run_dir = Path(state.run_dir)
                saved = json.loads(
                    (run_dir / "standalone.json").read_text(encoding="utf-8")
                )
                self.assertEqual(
                    run_dir.parent.parent,
                    root.resolve() / "standalone_runs",
                )
                self.assertFalse(list((root / "projects").glob("*/runs/*")))
                self.assertEqual(saved["tool_id"], "one_shot")
                self.assertEqual(saved["target"], "https://example.com/path")
                self.assertTrue(saved["authorization_confirmed"])
                self.assertEqual(
                    state.result_paths,
                    [str(run_dir / "results" / "out.txt")],
                )
                self.assertEqual(state.status, "running")
                command = manager.spawn_commands["one_shot"]
                self.assertIn("123", command)
                self.assertIn("-nopoc", command)
                self.assertIn("-nobr", command)
                self.assertNotIn("", command)
            finally:
                manager.cleanup()

    def test_standalone_network_tool_requires_authorization(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            tool = ToolDefinition(
                tool_id="one_shot",
                name="One shot",
                category="test",
                description="test",
                executable=sys.executable,
                sends_requests=True,
                allow_standalone=True,
            )
            manager = OfflineRuntimeManager(root, [tool], st_root=root)

            with self.assertRaisesRegex(Exception, "授权"):
                manager.start_standalone(
                    "one_shot",
                    "example.com",
                    authorization_confirmed=False,
                    api_base_url="https://gateway.example/v1",
                    model="tool-model",
                )
            self.assertFalse((root / "standalone_runs").exists())

    def test_codex_agent_script_uses_codexx_yolo_in_run_directory(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "run"
            run_dir.mkdir()
            (run_dir / "agent_prompt.txt").write_text(
                "default test prompt", encoding="utf-8"
            )
            manager = RuntimeManager(root, [], st_root=root / "tools")
            request = LaunchRequest(
                project_name="demo",
                target="https://example.com",
                scope="example.com",
                provider="codexx",
                model="gpt-5.5",
                selected_tools=(),
                user_prompt="default test prompt",
                authorization_confirmed=True,
            )

            script_path = manager._agent_script(request, run_dir)
            script = script_path.read_text(encoding="utf-8-sig")

            self.assertIn(f"Set-Location -LiteralPath '{run_dir}'", script)
            self.assertIn("agent_shell.pid", script)
            self.assertIn("agent_exit.json", script)
            self.assertIn(str((run_dir / "agent_prompt.txt").resolve()), script)
            self.assertIn("Set-Content -LiteralPath $agentPidPath -Value $PID", script)
            self.assertIn("Remove-Item -LiteralPath $agentPidPath", script)
            self.assertIn("& codexx --yolo $bootstrapPrompt", script)
            self.assertNotIn("Get-Content -Raw -Encoding UTF8", script)
            self.assertNotIn("--model", script)
            self.assertNotIn("--add-dir", script)
            self.assertNotIn("openai_base_url", script)
            self.assertNotIn("& codex ", script)

    def test_windows_terminal_agent_tracks_inner_powershell_pid(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "run"
            run_dir.mkdir()
            (run_dir / "agent_prompt.txt").write_text("test", encoding="utf-8")
            manager = RuntimeManager(root, [], st_root=root)
            request = LaunchRequest(
                project_name="demo",
                target="example.com",
                scope="example.com",
                provider="codex",
                model="tool-model",
                selected_tools=(),
                user_prompt="test",
                authorization_confirmed=True,
            )
            script = manager._agent_script(request, run_dir)
            captured: list[str] = []

            class Launcher:
                pid = 999999

                @staticmethod
                def poll():
                    return 0

            def fake_popen(command, **kwargs):
                captured.extend(command)
                (run_dir / "agent_shell.pid").write_text(
                    str(os.getpid()), encoding="ascii"
                )
                return Launcher()

            with patch("sttool.runtime.subprocess.Popen", side_effect=fake_popen):
                record = manager._launch_agent_in_windows_terminal(
                    request, run_dir, script, "wt.exe"
                )

            self.assertEqual(record.pid, os.getpid())
            self.assertEqual(
                captured[:4],
                ["wt.exe", "-w", agent_terminal_window_name(root), "new-tab"],
            )
            self.assertIn("--startingDirectory", captured)
            self.assertTrue(
                any(
                    Path(value).name in {"pwsh.exe", "powershell.exe"}
                    for value in captured
                )
            )
            self.assertIn(str(script), captured)

    def test_codex_agent_script_uses_local_codex_command(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "run"
            run_dir.mkdir()
            (run_dir / "agent_prompt.txt").write_text("test", encoding="utf-8")
            manager = RuntimeManager(root, [], st_root=root)
            request = LaunchRequest(
                project_name="demo",
                target="example.com",
                scope="example.com",
                provider="codex",
                model="tool-model",
                selected_tools=(),
                user_prompt="test",
                authorization_confirmed=True,
            )

            script = manager._agent_script(request, run_dir).read_text(
                encoding="utf-8-sig"
            )

            self.assertIn("& codex --yolo $bootstrapPrompt", script)
            self.assertNotIn("& codexx", script)

    def test_codex_recovery_script_resumes_without_replaying_prompt(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "run"
            run_dir.mkdir()
            (run_dir / "agent_prompt.txt").write_text("do not replay", encoding="utf-8")
            manager = RuntimeManager(root, [], st_root=root / "tools")
            request = LaunchRequest(
                project_name="demo",
                target="https://example.com",
                scope="example.com",
                provider="codexx",
                model="tool-model",
                selected_tools=(),
                user_prompt="do not replay",
                authorization_confirmed=True,
                api_base_url="https://gateway.example/v1",
                api_key="sk-tool-only",
            )

            script_path = manager._agent_script(request, run_dir, resume=True)
            script = script_path.read_text(encoding="utf-8-sig")

            self.assertIn("& codexx --yolo resume --last", script)
            self.assertNotIn("$prompt", script)
            self.assertNotIn("Get-Content", script)
            self.assertNotIn("--model", script)
            self.assertNotIn("openai_base_url", script)

    def test_large_agent_prompt_stays_out_of_windows_command_line(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "run"
            run_dir.mkdir()
            large_prompt = "x" * 100_000
            (run_dir / "agent_prompt.txt").write_text(large_prompt, encoding="utf-8")
            manager = RuntimeManager(root, [], st_root=root)
            request = LaunchRequest(
                project_name="demo",
                target="example.com",
                scope="example.com",
                provider="codexx",
                model="tool-model",
                selected_tools=(),
                user_prompt=large_prompt,
                authorization_confirmed=True,
            )

            script = manager._agent_script(request, run_dir).read_text(
                encoding="utf-8-sig"
            )

            self.assertNotIn(large_prompt, script)
            self.assertIn(str((run_dir / "agent_prompt.txt").resolve()), script)
            self.assertIn("$bootstrapPrompt", script)
            self.assertIn("exit 0", script)

    def test_agent_shell_filter_is_limited_to_current_run_scripts(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "run-a"
            other_run = Path(temporary) / "run-b"
            current = {
                "name": "pwsh.exe",
                "exe": "C:/Program Files/PowerShell/7/pwsh.exe",
                "cmdline": ["pwsh.exe", "-File", str(run_dir / "launch_agent.ps1")],
            }
            other = {
                **current,
                "cmdline": ["pwsh.exe", "-File", str(other_run / "launch_agent.ps1")],
            }
            manual = {
                **current,
                "cmdline": ["pwsh.exe", "-Command", "codexx --yolo"],
            }

            self.assertTrue(is_agent_shell_process_info(current, run_dir))
            self.assertFalse(is_agent_shell_process_info(other, run_dir))
            self.assertFalse(is_agent_shell_process_info(manual, run_dir))

    def test_preflight_rejects_invalid_api_base_url(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            manager = OfflineRuntimeManager(root, [], st_root=root)
            request = LaunchRequest(
                project_name="demo",
                target="example.com",
                scope="example.com",
                provider="codexx",
                model="gpt-5.5",
                selected_tools=(),
                user_prompt="",
                authorization_confirmed=True,
                api_base_url="not-a-url",
            )

            with self.assertRaisesRegex(Exception, "AI API URL"):
                manager.preflight(request)

    def test_provider_health_timeout_does_not_block_installed_cli(self) -> None:
        with TemporaryDirectory() as temporary:
            manager = RuntimeManager(Path(temporary), [])
            with (
                patch("sttool.runtime.shutil.which", return_value="codexx.exe"),
                patch(
                    "sttool.runtime.subprocess.run",
                    side_effect=subprocess.TimeoutExpired("codexx", 30),
                ),
            ):
                first = manager.provider_health("codexx")
                cached = manager.provider_health("codexx")

            self.assertEqual(first, (True, "已安装；登录检测超时，将在启动时验证"))
            self.assertEqual(cached, first)

    def test_preflight_accepts_explicit_agent_key_without_cli_login(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            manager = RuntimeManager(root, [], st_root=root)
            request = LaunchRequest(
                project_name="demo",
                target="example.com",
                scope="example.com",
                provider="codexx",
                model="gpt-5.5",
                selected_tools=(),
                user_prompt="",
                authorization_confirmed=True,
                agent_api_key="cli-secret",
            )

            with (
                patch("sttool.runtime.shutil.which", return_value="codexx.exe"),
                patch.object(
                    manager,
                    "provider_health",
                    return_value=(False, "CLI 未登录"),
                ) as health,
            ):
                self.assertEqual(manager.preflight(request), [])

            health.assert_not_called()

    def test_preflight_rejects_url_as_project_name(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            manager = RuntimeManager(root, [], st_root=root)
            request = LaunchRequest(
                project_name="https://api.example.test/v1",
                target="https://target.example.test",
                scope="target.example.test",
                provider="codexx",
                model="gpt-5.5",
                selected_tools=(),
                user_prompt="",
                authorization_confirmed=True,
            )
            with self.assertRaisesRegex(Exception, "\u7a33\u5b9a\u540d\u79f0"):
                manager.preflight(request)

    def test_preflight_requires_authorization_before_provider_check(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            manager = RuntimeManager(root, [], st_root=root)
            request = LaunchRequest(
                project_name="demo",
                target="example.com",
                scope="example.com",
                provider="codexx",
                model="gpt-5.5",
                selected_tools=(),
                user_prompt="",
                authorization_confirmed=False,
            )
            with self.assertRaisesRegex(Exception, "授权"):
                manager.preflight(request)

    def test_recover_restarts_persistent_components_in_same_run(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source-config.json"
            source.write_text('{"value": "source"}', encoding="utf-8")
            persistent = ToolDefinition(
                tool_id="persistent",
                name="Persistent",
                category="test",
                description="test",
                executable=sys.executable,
                cwd="{run_dir}/persistent",
                restart_on_recovery=True,
                prepare_files=((str(source), "tool/config.json"),),
            )
            one_shot = ToolDefinition(
                tool_id="one-shot",
                name="One shot",
                category="test",
                description="test",
                executable=sys.executable,
                cwd="{run_dir}/one-shot",
            )
            manager = OfflineRuntimeManager(root, [persistent, one_shot], st_root=root)
            request = LaunchRequest(
                project_name="recover-demo",
                target="https://example.com",
                scope="example.com",
                provider="codexx",
                model="gpt-5.5",
                selected_tools=("persistent", "one-shot"),
                user_prompt="recover",
                authorization_confirmed=True,
                api_base_url="https://gateway.example/v1/",
                api_key="sk-runtime-only",
            )
            state = manager.start(request)
            original_run_dir = state.run_dir
            copied = Path(state.run_dir) / "tool" / "config.json"
            copied.write_text('{"value": "runtime"}', encoding="utf-8")
            for process in manager.handles:
                process.terminate()
                process.wait(timeout=5)
            manager.refresh(state)

            recovered = manager.recover(state, authorization_confirmed=True)
            try:
                self.assertEqual(recovered.run_dir, original_run_dir)
                self.assertEqual(recovered.recovery_count, 1)
                self.assertEqual(
                    {item.component_id for item in recovered.processes},
                    {"persistent", "one-shot", "project_coordinator"},
                )
                statuses = {
                    item.component_id: item.status for item in recovered.processes
                }
                self.assertEqual(statuses["one-shot"], "exited")
                self.assertTrue(
                    pid_alive(
                        next(
                            item.pid
                            for item in recovered.processes
                            if item.component_id == "persistent"
                        )
                    )
                )
                self.assertEqual(
                    json.loads(copied.read_text(encoding="utf-8")),
                    {"value": "runtime"},
                )
                self.assertEqual(
                    recovered.recovery_history[-1]["components"],
                    ["persistent", "project_coordinator"],
                )
                coordinator_state = (
                    Path(state.run_dir) / "tool_data" / "coordinator" / "state.json"
                )
                self.assertFalse(coordinator_state.exists())
            finally:
                manager.cleanup()

    def test_recover_restarts_component_when_pid_belongs_to_other_process(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "projects" / "demo" / "runs" / "run-1"
            run_dir.mkdir(parents=True)
            tool = ToolDefinition(
                tool_id="persistent",
                name="Persistent",
                category="test",
                description="test",
                executable=sys.executable,
                cwd="{run_dir}/persistent",
                restart_on_recovery=True,
            )
            manager = OfflineRuntimeManager(root, [tool], st_root=root)
            foreign = ProcessRecord(
                component_id="persistent",
                name="Persistent",
                pid=os.getpid(),
                command=[sys.executable],
                cwd=str(run_dir),
                started_at=now_text(),
                creation_token=process_creation_token(os.getpid()) + 1,
            )
            state = RunState(
                run_id="run-1",
                project_name="demo",
                target="https://example.com",
                scope="example.com",
                provider="codexx",
                model="gpt-5.5",
                selected_tools=["persistent"],
                run_dir=str(run_dir),
                created_at=now_text(),
                updated_at=now_text(),
                status="running",
                processes=[foreign],
            )

            recovered = manager.recover(state, authorization_confirmed=True)
            try:
                persistent = next(
                    item
                    for item in recovered.processes
                    if item.component_id == "persistent"
                )
                self.assertNotEqual(persistent.pid, os.getpid())
                self.assertTrue(process_record_alive(persistent, run_dir))
                self.assertIn(
                    "persistent", recovered.recovery_history[-1]["components"]
                )
            finally:
                manager.cleanup()

    def test_recover_requires_current_authorization(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            manager = OfflineRuntimeManager(root, [], st_root=root)
            state = RunState(
                run_id="run",
                project_name="demo",
                target="example.com",
                scope="example.com",
                provider="codexx",
                model="gpt-5.5",
                selected_tools=[],
                run_dir=str(root),
                created_at=now_text(),
                updated_at=now_text(),
                status="completed",
            )
            with self.assertRaises(Exception) as raised:
                manager.recover(state, authorization_confirmed=False)
            self.assertIn("授权", str(raised.exception))

    def test_coordinator_managed_tool_is_selected_but_not_spawned_as_process(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            tool = ToolDefinition(
                tool_id="intel",
                name="Intel",
                category="test",
                description="coordinator stage",
                executable=sys.executable,
                coordinator_managed=True,
            )
            manager = OfflineRuntimeManager(root, [tool], st_root=root)
            request = LaunchRequest(
                project_name="managed",
                target="https://example.com",
                scope="*",
                provider="codexx",
                model="gpt-5.5",
                selected_tools=("intel",),
                user_prompt="test",
                authorization_confirmed=True,
            )

            state = manager.start(request)
            try:
                self.assertEqual(
                    [item.component_id for item in state.processes],
                    ["project_coordinator"],
                )
                self.assertNotIn("intel", manager.spawn_commands)
                activity = (Path(state.run_dir) / "activity.log").read_text(
                    encoding="utf-8"
                )
                self.assertIn("Intel；等待资产稳定后按代次执行", activity)
            finally:
                manager.cleanup()

    def test_start_transaction(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            tool = ToolDefinition(
                tool_id="dummy",
                name="Dummy",
                category="test",
                description="test",
                executable=sys.executable,
                cwd="{run_dir}/dummy",
                uses_shared_ai=True,
            )
            manager = OfflineRuntimeManager(root, [tool], st_root=root)
            request = LaunchRequest(
                project_name="demo",
                target="https://example.com",
                scope="*",
                provider="codexx",
                model="gpt-5.5",
                selected_tools=("dummy",),
                user_prompt="test only",
                authorization_confirmed=True,
                api_base_url="https://gateway.example/v1/",
                api_key="sk-runtime-only",
            )
            state = manager.start(request)
            try:
                self.assertEqual(state.status, "running")
                self.assertEqual(len(state.processes), 2)
                self.assertTrue(all(pid_alive(item.pid) for item in state.processes))
                prompt_path = Path(state.run_dir) / "agent_prompt.txt"
                self.assertTrue(prompt_path.is_file())
                prompt = prompt_path.read_text(encoding="utf-8")
                self.assertIn("Microsoft Playwright", prompt)
                self.assertIn("cve_triage.md", prompt)
                self.assertIn("evidence/poc_review/<CVE>/", prompt)
                self.assertIn("不要只输出可能漏洞清单", prompt)
                self.assertIn("由这些 IPv4 资产派生的对应 /24 网段", prompt)
                self.assertIn("不得扩展到无关互联网目标", prompt)
                self.assertTrue((Path(state.run_dir) / "run.json").is_file())
                project = json.loads(
                    (Path(state.run_dir) / "project.json").read_text(encoding="utf-8")
                )
                self.assertEqual(project["api_base_url"], "https://gateway.example/v1")
                self.assertEqual(state.api_base_url, "https://gateway.example/v1")
                self.assertNotIn("sk-runtime-only", json.dumps(project))
                self.assertNotIn(
                    "sk-runtime-only",
                    (Path(state.run_dir) / "launch_agent.ps1").read_text(
                        encoding="utf-8-sig"
                    ),
                )
                self.assertEqual(
                    manager.spawn_environments["project_coordinator"],
                    {
                        "PYTHONPATH": str(root.resolve()),
                        "OPENAI_BASE_URL": "https://gateway.example/v1",
                        "OPENAI_MODEL": "gpt-5.5",
                        "OPENAI_API_KEY": "sk-runtime-only",
                        "STTOOL_SHARED_AI_KEY_INJECTED": "1",
                    },
                )
                self.assertEqual(
                    manager.spawn_environments["dummy"],
                    {
                        "OPENAI_BASE_URL": "https://gateway.example/v1",
                        "OPENAI_MODEL": "gpt-5.5",
                        "OPENAI_API_KEY": "sk-runtime-only",
                    },
                )
                activity = (Path(state.run_dir) / "activity.log").read_text(
                    encoding="utf-8"
                )
                self.assertIn("工具已启动：Dummy", activity)
                self.assertIn("项目增量调度器已启动", activity)
                self.assertIn("运行实例启动完成", activity)
                self.assertNotIn("sk-runtime-only", activity)
            finally:
                manager.cleanup()
            self.assertTrue(all(not pid_alive(item.pid) for item in state.processes))

    def test_agent_cli_arguments_only_override_explicit_settings(self) -> None:
        self.assertEqual(agent_cli_arguments("codexx"), ["--yolo"])
        self.assertEqual(
            agent_cli_arguments("codex", "gpt-5.6-sol", "high"),
            [
                "--yolo",
                "-m",
                "gpt-5.6-sol",
                "-c",
                'model_reasoning_effort="high"',
            ],
        )
        self.assertEqual(
            agent_cli_arguments("claude", "claude-opus-4-1", "high"),
            [
                "--dangerously-skip-permissions",
                "--model",
                "claude-opus-4-1",
                "--effort",
                "high",
            ],
        )

    def test_codex_agent_script_applies_explicit_model_and_reasoning(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "run"
            run_dir.mkdir()
            (run_dir / "agent_prompt.txt").write_text("test", encoding="utf-8")
            manager = RuntimeManager(root, [], st_root=root)
            request = LaunchRequest(
                project_name="demo",
                target="example.com",
                scope="example.com",
                provider="codexx",
                model="summary-model",
                selected_tools=(),
                user_prompt="test",
                authorization_confirmed=True,
                agent_model="gpt-5.6-sol",
                reasoning_effort="high",
                agent_base_url="https://codex.example/v1/",
            )

            script = manager._agent_script(request, run_dir).read_text(
                encoding="utf-8-sig"
            )

            self.assertIn(
                "& codexx --yolo -m 'gpt-5.6-sol' "
                "-c 'model_reasoning_effort=\"high\"' $bootstrapPrompt",
                script,
            )
            self.assertIn(
                "$env:OPENAI_BASE_URL = 'https://codex.example/v1'", script
            )

    def test_claude_agent_script_applies_model_effort_and_resume(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "run"
            run_dir.mkdir()
            (run_dir / "agent_prompt.txt").write_text("test", encoding="utf-8")
            manager = RuntimeManager(root, [], st_root=root)
            request = LaunchRequest(
                project_name="demo",
                target="example.com",
                scope="example.com",
                provider="claude",
                model="summary-model",
                selected_tools=(),
                user_prompt="test",
                authorization_confirmed=True,
                agent_model="claude-opus-4-1",
                reasoning_effort="high",
                agent_base_url="https://claude.example/",
            )

            script = manager._agent_script(request, run_dir).read_text(
                encoding="utf-8-sig"
            )
            resumed = manager._agent_script(request, run_dir, resume=True).read_text(
                encoding="utf-8-sig"
            )

            options = (
                "claude --dangerously-skip-permissions "
                "--model 'claude-opus-4-1' --effort 'high'"
            )
            self.assertIn(f"& {options} $bootstrapPrompt", script)
            self.assertIn(f"& {options} --continue", resumed)
            self.assertIn(
                "$env:ANTHROPIC_BASE_URL = 'https://claude.example'", script
            )

    def test_project_persists_agent_and_workflow_settings(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            manager = OfflineRuntimeManager(root, [], st_root=root)
            request = LaunchRequest(
                project_name="configured",
                target="https://example.com",
                scope="*",
                provider="codex",
                model="summary-model",
                selected_tools=(),
                user_prompt="test",
                authorization_confirmed=True,
                api_key="shared-secret-token",
                agent_model="gpt-5.6-sol",
                reasoning_effort="xhigh",
                agent_base_url="https://codex.example/v1/",
                agent_api_key="agent-secret-token",
                github_token="github-secret-token",
                work_mode="fast",
                auto_agent=True,
                wait_for_asset_commander=False,
                wait_for_fscan=False,
                asset_settle_seconds=8,
                max_agent_batches=12,
                coordinator_poll_seconds=1,
                ai_summary_enabled=False,
                fscan_skip_poc=True,
                fscan_skip_brute=True,
                fscan_port_threads=321,
                semantic_threads=17,
                semantic_max_depth=4,
                semantic_run_dirsearch=False,
                semantic_max_rate=25,
            )
            state = manager.start(request)
            try:
                project = json.loads(
                    (Path(state.run_dir) / "project.json").read_text(encoding="utf-8")
                )
                self.assertEqual(project["schema_version"], 5)
                self.assertEqual(project["fscan_port_threads"], 321)
                self.assertEqual(project["semantic_threads"], 17)
                self.assertEqual(project["semantic_max_depth"], 4)
                self.assertFalse(project["semantic_run_dirsearch"])
                self.assertEqual(project["semantic_max_rate"], 25)
                self.assertEqual(project["agent_model"], "gpt-5.6-sol")
                self.assertEqual(project["reasoning_effort"], "xhigh")
                self.assertEqual(
                    project["agent_base_url"], "https://codex.example/v1"
                )
                self.assertNotIn("github-secret-token", json.dumps(project))
                self.assertNotIn("shared-secret-token", json.dumps(project))
                self.assertNotIn("agent-secret-token", json.dumps(project))
                run_value = json.loads(
                    (Path(state.run_dir) / "run.json").read_text(encoding="utf-8")
                )
                self.assertNotIn("agent-secret-token", json.dumps(run_value))
                self.assertNotIn("shared-secret-token", json.dumps(run_value))
                self.assertEqual(project["work_mode"], "fast")
                self.assertFalse(project["wait_for_asset_commander"])
                self.assertFalse(project["wait_for_fscan"])
                self.assertFalse(project["ai_summary_enabled"])
                self.assertEqual(state.max_agent_batches, 12)
                coordinator = manager.spawn_commands["project_coordinator"]
                self.assertIn("--agent-model", coordinator)
                self.assertIn("gpt-5.6-sol", coordinator)
                self.assertIn("--reasoning-effort", coordinator)
                self.assertIn("xhigh", coordinator)
                self.assertIn("--agent-base-url", coordinator)
                self.assertIn("https://codex.example/v1", coordinator)
                self.assertEqual(
                    manager.spawn_environments["project_coordinator"]["GITHUB_TOKEN"],
                    "github-secret-token",
                )
                self.assertEqual(
                    manager.spawn_environments["project_coordinator"][
                        "STTOOL_AGENT_API_KEY"
                    ],
                    "agent-secret-token",
                )
                self.assertEqual(
                    manager.spawn_environments["project_coordinator"][
                        "STTOOL_SHARED_AI_KEY_INJECTED"
                    ],
                    "1",
                )
                self.assertNotIn("github-secret-token", " ".join(coordinator))
                self.assertNotIn("shared-secret-token", " ".join(coordinator))
                self.assertNotIn("agent-secret-token", " ".join(coordinator))
                launch_script = (Path(state.run_dir) / "launch_agent.ps1").read_text(
                    encoding="utf-8-sig"
                )
                self.assertNotIn("agent-secret-token", launch_script)
                self.assertNotIn("shared-secret-token", launch_script)
                self.assertIn("--wait-asset-commander", coordinator)
                self.assertIn("false", coordinator)
                self.assertIn("--vulnx", coordinator)
                self.assertIn(str((root / "vulnx" / "vulnx.exe").resolve()), coordinator)
                self.assertIn("--find-gh-poc", coordinator)
            finally:
                manager.cleanup()

    def test_scan_settings_expand_into_fscan_and_semantic_commands(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            manager = OfflineRuntimeManager(root, [], st_root=root)
            request = LaunchRequest(
                project_name="scan-settings",
                target="10.0.0.1",
                scope="*",
                provider="codexx",
                model="summary-model",
                selected_tools=("fscan", "semantic_dirscan"),
                user_prompt="test",
                authorization_confirmed=True,
                fscan_skip_poc=True,
                fscan_skip_brute=True,
                fscan_port_threads=321,
                semantic_threads=17,
                semantic_max_depth=4,
                semantic_run_dirsearch=False,
                semantic_max_rate=25,
            )
            fscan_tool = ToolDefinition(
                tool_id="fscan",
                name="fscan",
                category="scan",
                description="",
                executable="fscan.exe",
                args=(
                    "-h", "{target_host}", "-t", "{fscan_port_threads}",
                    "{fscan_skip_poc_flag}", "{fscan_skip_brute_flag}",
                    "-o", "{run_dir}/results/fscan.txt",
                ),
                cwd="{run_dir}",
            )
            semantic_tool = ToolDefinition(
                tool_id="semantic_dirscan",
                name="semantic",
                category="scan",
                description="",
                executable="python.exe",
                args=(
                    "--threads", "{semantic_threads}",
                    "--max-depth", "{semantic_max_depth}",
                    "--max-rate", "{semantic_max_rate}",
                    "{semantic_dirsearch_flag}",
                ),
                cwd="{run_dir}",
            )
            run_dir = root / "run"
            (run_dir / "results").mkdir(parents=True)
            context = manager._run_context(request, root, run_dir)
            manager._launch_tool(fscan_tool, context)
            manager._launch_tool(semantic_tool, context)
            try:
                fscan = manager.spawn_commands["fscan"]
                semantic = manager.spawn_commands["semantic_dirscan"]
                self.assertIn("-t", fscan)
                self.assertIn("321", fscan)
                self.assertIn("-nopoc", fscan)
                self.assertIn("-nobr", fscan)
                self.assertIn("--threads", semantic)
                self.assertIn("17", semantic)
                self.assertIn("--max-depth", semantic)
                self.assertIn("4", semantic)
                self.assertIn("--max-rate", semantic)
                self.assertIn("25", semantic)
                self.assertIn("--no-dirsearch", semantic)
                self.assertNotIn("", fscan)
                self.assertNotIn("", semantic)
            finally:
                manager.cleanup()


if __name__ == "__main__":
    unittest.main()
