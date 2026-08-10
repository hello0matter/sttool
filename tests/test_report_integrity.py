from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sttool.report_integrity import (
    normalize_external_text,
    restore_corrupted_report_files,
    snapshot_report_files,
    text_metrics,
)


class ReportIntegrityTests(unittest.TestCase):
    def test_normalize_external_text_repairs_common_mojibake_and_ansi(self) -> None:
        value = "\x1b[1;31mFTL\x1b[0m Ê§°Ü£º request failed\nFindings â€” batch"
        self.assertEqual(
            normalize_external_text(value),
            "FTL 失败： request failed\nFindings — batch",
        )

    def test_snapshot_restores_new_question_mark_corruption(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "run"
            batch_dir = run_dir / "agent_batches" / "0001"
            batch_dir.mkdir(parents=True)
            report = run_dir / "findings.md"
            report.write_text("# 正常报告\n\n- 原始内容\n", encoding="utf-8")
            snapshot_report_files(run_dir, batch_dir)
            report.write_text("# ??????\n\n????????????\n", encoding="utf-8")

            result = restore_corrupted_report_files(run_dir, batch_dir)

            self.assertEqual(result["status"], "restored")
            self.assertEqual(result["restored"], ["findings.md"])
            self.assertEqual(report.read_text(encoding="utf-8"), "# 正常报告\n\n- 原始内容\n")
            self.assertTrue(
                (batch_dir / "rejected_report_writes" / "findings.md.corrupted").is_file()
            )

    def test_snapshot_keeps_clean_addition_and_normalizes_ansi(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "run"
            batch_dir = run_dir / "agent_batches" / "0001"
            batch_dir.mkdir(parents=True)
            report = run_dir / "cve_triage.md"
            report.write_text("# CVE 排查\n", encoding="utf-8")
            snapshot_report_files(run_dir, batch_dir)
            report.write_text(
                "# CVE 排查\n\n- \x1b[31m失败\x1b[0m：仅记录错误\n",
                encoding="utf-8",
            )

            result = restore_corrupted_report_files(run_dir, batch_dir)

            self.assertEqual(result["status"], "clean")
            self.assertEqual(result["restored"], [])
            self.assertEqual(result["normalized"], ["cve_triage.md"])
            self.assertNotIn("\x1b", report.read_text(encoding="utf-8"))

    def test_text_metrics_detect_question_runs(self) -> None:
        self.assertEqual(text_metrics("abc ????? def")["question_runs"], 1)

    def test_integrity_result_is_machine_readable(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "run"
            batch_dir = run_dir / "agent_batches" / "0001"
            batch_dir.mkdir(parents=True)
            snapshot_report_files(run_dir, batch_dir)
            result = restore_corrupted_report_files(run_dir, batch_dir)
            stored = json.loads(
                (batch_dir / "report_integrity.json").read_text(encoding="utf-8")
            )
            self.assertEqual(stored, result)


if __name__ == "__main__":
    unittest.main()
