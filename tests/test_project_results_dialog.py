from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sttool.models import RunState
from sttool.project_results_dialog import (
    compact_markdown,
    human_file_size,
    preview_url_spans,
    regenerate_pentest_report,
    render_project_results,
    source_sort_key,
)
from sttool.project_result_catalog import (
    ProjectResultSource,
    preview_result_source,
    project_result_sources,
    readable_markdown,
)


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
            (run_dir / "pentest_report.md").write_text(
                "# 渗透测试报告：demo\n\n## 1. 执行摘要\n\n- 待验证问题\n",
                encoding="utf-8",
            )
            (run_dir / "findings.json").write_text(
                '{"schema_version":1,"findings":[]}', encoding="utf-8"
            )
            (run_dir / "findings.md").write_text(
                "# 项目问题库\n", encoding="utf-8"
            )
            (run_dir / "risk_summary.md").write_text(
                "# \u9879\u76ee\u98ce\u9669\u6210\u679c\u6458\u8981\n\n"
                "## \u5de5\u5177\u98ce\u9669\u7ebf\u7d22\n\n"
                "- \u5f85\u9a8c\u8bc1\u95ee\u9898\n",
                encoding="utf-8",
            )
            (run_dir / "results" / "fscan.txt").write_text(
                "10.0.0.1:80 open", encoding="utf-8"
            )
            (run_dir / "vulnerability_intel.md").write_text(
                "# \u6f0f\u6d1e\u60c5\u62a5\u4e0e PoC \u5019\u9009\n", encoding="utf-8"
            )
            (run_dir / "results" / "vulnerability_intel.json").write_text(
                '{"candidate_count": 1}', encoding="utf-8"
            )

            content, sources = render_project_results(
                self._state(run_dir, status="completed")
            )

        self.assertIn("\u6700\u7ec8\u6210\u679c", content)
        self.assertIn("成果概览", content)
        self.assertEqual(
            {item.path.name for item in sources},
            {
                "pentest_report.md",
                "findings.md",
                "risk_summary.md",
                "vulnerability_intel.md",
                "fscan.txt",
            },
        )

    def test_catalog_includes_incremental_scans_and_hides_internal_files(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            (run_dir / "results").mkdir()
            (run_dir / "results" / "fscan.txt").write_text(
                "10.0.0.1:80", encoding="utf-8"
            )
            batch = run_dir / "tool_data" / "fscan_incremental" / "batch-0002"
            batch.mkdir(parents=True)
            (batch / "targets.txt").write_text("10.0.0.2\n10.0.0.3\n", encoding="utf-8")
            (batch / "result.txt").write_text("10.0.0.2:443", encoding="utf-8")
            tscan = run_dir / "tool_data" / "tscan"
            tscan.mkdir(parents=True)
            (tscan / "state.json").write_text('{"status":"running"}', encoding="utf-8")
            agent = run_dir / "agent_batches" / "0001"
            agent.mkdir(parents=True)
            (agent / "execution_log.md").write_text("internal", encoding="utf-8")

            sources = project_result_sources(run_dir)

        self.assertEqual(
            [source.title for source in sources],
            ["fscan 初始扫描", "fscan 第 2 轮"],
        )
        self.assertNotIn("state.json", {source.path.name for source in sources})
        self.assertNotIn("execution_log.md", {source.path.name for source in sources})

    def test_catalog_discovers_each_dirsearch_target(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            base = run_dir / "tool_data" / "semantic" / "projects" / "demo" / "runs"
            for index, target in enumerate(("http://10.0.0.1/", "https://example.test/"), start=1):
                scan = base / f"target-{index}"
                scan.mkdir(parents=True)
                (scan / "summary.json").write_text(
                    '{"target":"' + target + '"}', encoding="utf-8"
                )
                (scan / "dirsearch.txt").write_text(
                    f"200  12KB  {target}admin\n", encoding="utf-8"
                )

            sources = project_result_sources(run_dir)

        directory_sources = [source for source in sources if source.kind == "路径发现"]
        self.assertEqual(len(directory_sources), 2)
        self.assertEqual(
            {source.target for source in directory_sources},
            {"http://10.0.0.1/", "https://example.test/"},
        )

    def test_catalog_discovers_each_incremental_nuclei_batch(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            results = run_dir / "results"
            results.mkdir()
            (results / "nuclei.txt").write_text("initial hit", encoding="utf-8")
            batch = run_dir / "tool_data" / "nuclei_incremental" / "batch-0001"
            batch.mkdir(parents=True)
            (batch / "targets.txt").write_text(
                "https://one.example/\nhttps://two.example/\n", encoding="utf-8"
            )
            (batch / "result.txt").write_text("incremental hit", encoding="utf-8")

            sources = project_result_sources(run_dir)

        nuclei_sources = [source for source in sources if source.kind == "漏洞扫描"]
        self.assertEqual(
            [source.title for source in nuclei_sources],
            ["nuclei 初始扫描", "nuclei 第 1 轮扫描"],
        )
        self.assertEqual(
            nuclei_sources[1].subtitle,
            "https://one.example/ 等 2 个目标",
        )

    def test_human_previews_remove_markdown_and_dirsearch_command(self) -> None:
        markdown = "# 风险摘要\n\n| 等级 | 数量 |\n|---|---|\n| 高危 | 2 |\n"
        self.assertEqual(readable_markdown(markdown), "风险摘要\n\n等级：高危    数量：2")

        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "dirsearch.txt"
            path.write_text(
                "# Dirsearch started with internal command\n\n"
                "302  0B  http://example.test/admin -> REDIRECTS TO: /login\n",
                encoding="utf-8",
            )
            source = project_result_sources(Path(temporary))
            self.assertEqual(source, [])
            preview = preview_result_source(
                ProjectResultSource(
                    title="目录扫描",
                    subtitle="http://example.test/",
                    path=path,
                    kind="路径发现",
                    size=path.stat().st_size,
                    preview_kind="dirsearch",
                )
            )

        self.assertIn("发现路径：1 条", preview)
        self.assertIn("http://example.test/admin", preview)
        self.assertNotIn("internal command", preview)

    def test_preview_url_spans_make_clean_browser_links(self) -> None:
        text = (
            "• http://10.0.0.1/admin | 200\n"
            "说明：https://example.test/path?q=1。"
        )

        spans = preview_url_spans(text)

        self.assertEqual(
            [url for _start, _end, url in spans],
            ["http://10.0.0.1/admin", "https://example.test/path?q=1"],
        )
        self.assertEqual(
            [text[start:end] for start, end, _url in spans],
            ["http://10.0.0.1/admin", "https://example.test/path?q=1"],
        )

    def test_result_size_is_human_readable_and_numerically_sortable(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            small = ProjectResultSource(
                title="small",
                subtitle="",
                path=root / "small.txt",
                kind="test",
                size=900,
                preview_kind="plain",
            )
            large = ProjectResultSource(
                title="large",
                subtitle="",
                path=root / "large.txt",
                kind="test",
                size=2 * 1024 * 1024,
                preview_kind="plain",
            )

            ordered = sorted([large, small], key=lambda item: source_sort_key(item, "size"))

        self.assertEqual([item.title for item in ordered], ["small", "large"])
        self.assertEqual(human_file_size(small.size), "900 字节")
        self.assertEqual(human_file_size(large.size), "2.0 MB")

    def test_regenerate_report_after_manual_findings_update(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            (run_dir / "project.json").write_text(
                '{"name":"demo","target":"https://example.test/","scope":"*"}',
                encoding="utf-8",
            )
            (run_dir / "findings.json").write_text(
                '{"schema_version":1,"findings":[]}', encoding="utf-8"
            )

            markdown_path, text_path = regenerate_pentest_report(self._state(run_dir))

            self.assertTrue(markdown_path.is_file())
            self.assertTrue(text_path.is_file())
            self.assertIn("人工问题库更新", markdown_path.read_text(encoding="utf-8"))

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
