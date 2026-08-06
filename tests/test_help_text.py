from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sttool.help_text import HELP_FILENAME, build_help_text, ensure_help_document


class HelpTextTests(unittest.TestCase):
    def test_help_text_covers_core_files_states_and_tools(self) -> None:
        text = build_help_text()

        for expected in (
            "risk_summary.md",
            "pentest_report.md",
            "component_logs",
            "agent_batches",
            "AssetCommander",
            "TscanPlus",
            "工具协作 AI",
            "外部 CLI 执行器",
            "Windows DPAPI",
            "AI 执行批次",
            "fscan POC 检测",
            "增量调度如何工作",
            "metadata_only",
            "等待资产回传",
            "自动跟随最新日志",
            "回到底部",
        ):
            self.assertIn(expected, text)
        self.assertNotIn("????????", text)

    def test_ensure_help_document_writes_txt_file(self) -> None:
        with TemporaryDirectory() as temporary:
            path = ensure_help_document(Path(temporary))

            self.assertEqual(path.name, HELP_FILENAME)
            self.assertTrue(path.is_file())
            self.assertIn("STTool 使用说明", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
