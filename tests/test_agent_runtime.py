from __future__ import annotations

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from sttool.agent_launcher import launch_agent_batch
from sttool.agent_runtime import (
    agent_terminal_window_name,
    claim_coordinator_owner,
    release_coordinator_owner,
)


class AgentRuntimeTests(unittest.TestCase):
    def test_named_terminal_window_is_stable_per_installation(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertEqual(
                agent_terminal_window_name(root),
                agent_terminal_window_name(root / "."),
            )
            self.assertNotEqual(
                agent_terminal_window_name(root),
                agent_terminal_window_name(root / "other"),
            )

    def test_coordinator_owner_prevents_duplicate_live_owner(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "run"
            owner_path = run_dir / "tool_data" / "coordinator" / "owner.json"
            owner = claim_coordinator_owner(owner_path, run_dir)
            self.assertIsNotNone(owner)
            with patch(
                "sttool.agent_runtime.coordinator_owner_matches", return_value=True
            ):
                duplicate = claim_coordinator_owner(owner_path, run_dir)
            self.assertIsNone(duplicate)
            release_coordinator_owner(owner_path, owner or {})
            self.assertFalse(owner_path.exists())

    def test_incremental_batch_uses_shared_terminal_window(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "run"
            run_dir.mkdir()
            captured: list[str] = []

            class Launcher:
                @staticmethod
                def poll():
                    return None

            def fake_which(name: str) -> str:
                if name == "wt.exe":
                    return "wt.exe"
                if name == "pwsh.exe":
                    return "pwsh.exe"
                return ""

            def fake_popen(command, **_kwargs):
                captured.extend(command)
                pid_path = run_dir / "agent_batches" / "0001" / "agent.pid"
                pid_path.write_text(str(os.getpid()), encoding="ascii")
                return Launcher()

            with (
                patch("sttool.agent_launcher.shutil.which", side_effect=fake_which),
                patch("sttool.agent_launcher.subprocess.Popen", side_effect=fake_popen),
            ):
                pid, _batch_dir = launch_agent_batch(
                    run_dir,
                    "codexx",
                    "demo",
                    1,
                    "test prompt",
                    terminal_window="STTool-Test-Agents",
                )

            self.assertEqual(pid, os.getpid())
            self.assertEqual(
                captured[:4],
                ["wt.exe", "-w", "STTool-Test-Agents", "new-tab"],
            )
            self.assertNotIn("new", captured[:4])


if __name__ == "__main__":
    unittest.main()
