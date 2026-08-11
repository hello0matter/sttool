from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from sttool.agent_connection_test import TEST_PROMPT, test_agent_connection


class AgentConnectionTestTests(unittest.TestCase):
    def test_connection_test_passes_secret_only_in_environment(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="STTOOL_OK", stderr=""
        )
        with (
            patch("sttool.agent_connection_test.shutil.which", return_value="codexx.exe"),
            patch(
                "sttool.agent_connection_test.subprocess.run", return_value=completed
            ) as run,
        ):
            success, detail = test_agent_connection(
                "codexx",
                "gpt-test",
                "high",
                "https://api.example/v1",
                "secret-key",
            )

        self.assertTrue(success)
        command = run.call_args.args[0]
        environment = run.call_args.kwargs["env"]
        self.assertIn(TEST_PROMPT, command)
        self.assertNotIn("secret-key", command)
        self.assertEqual(environment["OPENAI_API_KEY"], "secret-key")
        self.assertEqual(environment["OPENAI_BASE_URL"], "https://api.example/v1")
        self.assertIn("STTOOL_OK", detail)

    def test_connection_test_reports_provider_failure(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="provider unavailable"
        )
        with (
            patch("sttool.agent_connection_test.shutil.which", return_value="claude.exe"),
            patch("sttool.agent_connection_test.subprocess.run", return_value=completed),
        ):
            success, detail = test_agent_connection("claude")

        self.assertFalse(success)
        self.assertIn("provider unavailable", detail)


if __name__ == "__main__":
    unittest.main()
