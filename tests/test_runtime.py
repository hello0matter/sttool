from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sttool.models import LaunchRequest, ProcessRecord, ToolDefinition
from sttool.runtime import RuntimeManager, atomic_json_write, now_text, pid_alive, safe_project_name, target_values


class OfflineRuntimeManager(RuntimeManager):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.handles: list[subprocess.Popen] = []

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
        return ProcessRecord(
            component_id=component_id,
            name=name,
            pid=process.pid,
            command=[sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=cwd,
            started_at=now_text(),
        )

    def cleanup(self) -> None:
        for process in self.handles:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)


class RuntimeTests(unittest.TestCase):
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

    def test_preflight_requires_authorization_before_provider_check(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            manager = RuntimeManager(root, [], st_root=root)
            request = LaunchRequest(
                project_name="demo",
                target="example.com",
                scope="example.com",
                provider="codex",
                model="gpt-5.5",
                selected_tools=(),
                user_prompt="",
                authorization_confirmed=False,
            )
            with self.assertRaisesRegex(Exception, "授权"):
                manager.preflight(request)

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
            )
            manager = OfflineRuntimeManager(root, [tool], st_root=root)
            request = LaunchRequest(
                project_name="demo",
                target="https://example.com",
                scope="example.com",
                provider="codex",
                model="gpt-5.5",
                selected_tools=("dummy",),
                user_prompt="test only",
                authorization_confirmed=True,
            )
            state = manager.start(request)
            try:
                self.assertEqual(state.status, "running")
                self.assertEqual(len(state.processes), 2)
                self.assertTrue(all(pid_alive(item.pid) for item in state.processes))
                self.assertTrue((Path(state.run_dir) / "agent_prompt.txt").is_file())
                self.assertTrue((Path(state.run_dir) / "run.json").is_file())
            finally:
                manager.cleanup()
            self.assertTrue(all(not pid_alive(item.pid) for item in state.processes))


if __name__ == "__main__":
    unittest.main()
