from __future__ import annotations

import os
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from sttool.agent_launcher import launch_agent_batch, write_agent_batch_script
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

    def test_batch_script_uses_a_one_shot_launch_token(self) -> None:
        with TemporaryDirectory() as temporary:
            batch_dir = Path(temporary) / "run" / "agent_batches" / "0001"
            batch_dir.mkdir(parents=True)
            (batch_dir / "prompt.txt").write_text("test", encoding="utf-8")

            script_path, _pid_path = write_agent_batch_script(
                batch_dir, "claude", "demo"
            )

            script = script_path.read_text(encoding="utf-8-sig")
            token_path = batch_dir / "launch.token"
            self.assertTrue(token_path.is_file())
            self.assertIn("Move-Item -LiteralPath $launchTokenPath", script)
            self.assertIn("stale or duplicate AI launch", script)

    def test_batch_scripts_map_private_key_without_embedding_a_secret(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary) / "run" / "agent_batches"
            codex_dir = root / "0001"
            claude_dir = root / "0002"
            codex_dir.mkdir(parents=True)
            claude_dir.mkdir(parents=True)
            (codex_dir / "prompt.txt").write_text("test", encoding="utf-8")
            (claude_dir / "prompt.txt").write_text("test", encoding="utf-8")

            codex_script, _ = write_agent_batch_script(
                codex_dir, "codex", "demo"
            )
            claude_script, _ = write_agent_batch_script(
                claude_dir, "claude", "demo"
            )
            codex_text = codex_script.read_text(encoding="utf-8-sig")
            claude_text = claude_script.read_text(encoding="utf-8-sig")

            self.assertIn(
                "$env:OPENAI_API_KEY = $env:STTOOL_AGENT_API_KEY", codex_text
            )
            self.assertIn(
                "elseif ($env:STTOOL_SHARED_AI_KEY_INJECTED)", codex_text
            )
            self.assertIn(
                "$env:ANTHROPIC_API_KEY = $env:STTOOL_AGENT_API_KEY",
                claude_text,
            )
            self.assertIn(
                "if ($env:STTOOL_SHARED_AI_KEY_INJECTED)", claude_text
            )
            self.assertNotIn("test-agent-secret", codex_text)
            self.assertNotIn("test-agent-secret", claude_text)

    def test_terminal_handoff_waits_for_inner_powershell_pid(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "run"
            run_dir.mkdir()

            class Launcher:
                @staticmethod
                def poll():
                    return 0

            def fake_which(name: str) -> str:
                if name == "wt.exe":
                    return "wt.exe"
                if name == "pwsh.exe":
                    return "pwsh.exe"
                return ""

            def fake_popen(_command, **_kwargs):
                pid_path = run_dir / "agent_batches" / "0001" / "agent.pid"

                def publish_pid() -> None:
                    time.sleep(0.05)
                    pid_path.write_text(str(os.getpid()), encoding="ascii")

                threading.Thread(target=publish_pid, daemon=True).start()
                return Launcher()

            with (
                patch("sttool.agent_launcher.shutil.which", side_effect=fake_which),
                patch("sttool.agent_launcher.subprocess.Popen", side_effect=fake_popen),
            ):
                pid, _batch_dir = launch_agent_batch(
                    run_dir,
                    "claude",
                    "demo",
                    1,
                    "test prompt",
                    terminal_window="STTool-Test-Agents",
                )

            self.assertEqual(pid, os.getpid())

    def test_existing_batch_shell_is_claimed_without_second_launch(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "run"
            batch_dir = run_dir / "agent_batches" / "0001"
            batch_dir.mkdir(parents=True)
            script = batch_dir / "launch.ps1"
            script.write_text("Write-Host running", encoding="utf-8")
            with (
                patch("sttool.agent_launcher.agent_shell_pids_for_script", return_value=[43210]),
                patch("sttool.agent_launcher.subprocess.Popen") as popen,
            ):
                pid, returned_dir = launch_agent_batch(
                    run_dir, "codexx", "demo", 1, "test prompt"
                )
            self.assertEqual(pid, 43210)
            self.assertEqual(returned_dir, batch_dir)
            popen.assert_not_called()
            self.assertEqual((batch_dir / "agent.pid").read_text(encoding="ascii"), "43210")

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
