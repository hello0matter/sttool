from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sttool.global_search_dialog import search_project_files


class GlobalSearchTests(unittest.TestCase):
    def test_searches_project_and_run_evidence_with_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            projects = Path(temporary) / "projects"
            run_dir = projects / "demo" / "runs" / "run-1"
            run_dir.mkdir(parents=True)
            (run_dir / "activity.log").write_text(
                "普通记录\n事件ID F26081810327：目标 10.17.200.43\n",
                encoding="utf-8",
            )
            (projects / "demo" / "project.json").write_text(
                json.dumps({"name": "demo", "target": "example.test"}),
                encoding="utf-8",
            )

            hits = search_project_files(projects, "10.17.200.43")

            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].project, "demo")
            self.assertEqual(hits[0].run_id, "run-1")
            self.assertEqual(hits[0].line_number, 2)
            self.assertIn("F26081810327", hits[0].context)

    def test_does_not_search_secret_or_database_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            projects = Path(temporary) / "projects"
            project_dir = projects / "demo"
            project_dir.mkdir(parents=True)
            (project_dir / "launcher_secrets.dat").write_text(
                "secret-query", encoding="utf-8"
            )
            (project_dir / "config.db").write_text("secret-query", encoding="utf-8")
            (project_dir / "activity.log").write_text(
                "visible-query", encoding="utf-8"
            )

            self.assertEqual(search_project_files(projects, "secret-query"), [])
            self.assertEqual(len(search_project_files(projects, "visible-query")), 1)

    def test_content_scope_can_limit_search_to_logs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            projects = Path(temporary) / "projects"
            run_dir = projects / "demo" / "runs" / "run-1"
            run_dir.mkdir(parents=True)
            (run_dir / "activity.log").write_text("shared-ip", encoding="utf-8")
            (run_dir / "findings.md").write_text("shared-ip", encoding="utf-8")

            hits = search_project_files(projects, "shared-ip", content_scope="仅日志")

            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].location, "runs/run-1/activity.log")


if __name__ == "__main__":
    unittest.main()
