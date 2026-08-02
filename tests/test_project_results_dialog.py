from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sttool.models import RunState
from sttool.project_results_dialog import compact_markdown, render_project_results


class ProjectResultsDialogTests(unittest.TestCase):
    def _state(self, run_dir: Path, status: str = "running") -> RunState:
        return RunState(
            run_id="20260802-1",
            project_name="demo",
            target="https://example.test/",
            scope="*",
            provider="codexx",
            model="gpt-5.5",
            selected_tools=[],
            run_dir=str(run_dir),
            created_at="2026-08-02T10:00:00+08:00",
            updated_at="2026-08-02T10:10:00+08:00",
            status=status,
        )

    def test_empty_run_has_readable_stage_placeholder(self) -> None:
        with TemporaryDirectory() as temporary:
            content, sources = render_project_results(self._state(Path(temporary)))

        self.assertEqual(sources, [])
        self.assertIn("\u9636\u6bb5\u6210\u679c\uff08\u9879\u76ee\u4ecd\u5728\u8fd0\u884c\uff09", content)
        self.assertIn("\u5f53\u524d\u5c1a\u65e0\u53ef\u8bfb\u53d6\u7684\u9879\u76ee\u6210\u679c\u6587\u4ef6", content)

    def test_completed_run_exposes_summary_and_tool_results(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            (run_dir / "results").mkdir()
            (run_dir / "risk_summary.md").write_text(
                "# \u9879\u76ee\u98ce\u9669\u6210\u679c\u6458\u8981\n\n"
                "## \u5de5\u5177\u98ce\u9669\u7ebf\u7d22\n\n"
                "- \u5f85\u9a8c\u8bc1\u95ee\u9898\n",
                encoding="utf-8",
            )
            (run_dir / "results" / "fscan.txt").write_text(
                "10.0.0.1:80 open", encoding="utf-8"
            )

            content, sources = render_project_results(
                self._state(run_dir, status="completed")
            )

        self.assertIn("\u6700\u7ec8\u6210\u679c", content)
        self.assertIn("\u5f85\u9a8c\u8bc1\u95ee\u9898", content)
        self.assertEqual(
            {item.path.name for item in sources},
            {"risk_summary.md", "fscan.txt"},
        )

    def test_compact_markdown_folds_large_asset_sections(self) -> None:
        text = (
            "# \u6458\u8981\n\n## Web \u76ee\u6807\uff08\u5fc5\u987b\u9010\u4e2a\u68c0\u67e5\uff09\n\n"
            + "\n".join(
                f"- https://example.test/{index}" for index in range(100)
            )
        )

        compact = compact_markdown(text, max_lines=80)

        self.assertIn("\u5df2\u6298\u53e0", compact)
        self.assertLess(len(compact.splitlines()), len(text.splitlines()))


if __name__ == "__main__":
    unittest.main()
