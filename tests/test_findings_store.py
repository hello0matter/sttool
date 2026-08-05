from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sttool.findings_store import (
    FindingRecord,
    load_findings,
    render_findings_markdown,
    save_findings,
    validate_finding,
)


class FindingsStoreTests(unittest.TestCase):
    def _record(self, status: str = "待验证") -> FindingRecord:
        return FindingRecord(
            finding_id="MF-TEST0001",
            title="测试未授权访问",
            severity="high",
            status=status,
            vuln_type="未授权访问",
            affected=["https://example.test/admin"],
            parameter="-",
            cvss="8.1",
            description="匿名访问疑似返回管理数据。",
            reproduction=["匿名请求 /admin", "比对登录前后响应"],
            evidence=["evidence/admin-response.txt"],
            remediation=["增加服务端鉴权和权限校验"],
        )

    def test_confirmed_finding_requires_reproduction_and_evidence(self) -> None:
        record = self._record(status="已确认")
        record.evidence = []
        self.assertIn("证据", validate_finding(record))
        record.evidence = ["evidence/proof.txt"]
        record.reproduction = []
        self.assertIn("复现", validate_finding(record))

    def test_save_round_trip_writes_json_and_readable_markdown(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            record = self._record(status="已确认")

            json_path, markdown_path = save_findings(run_dir, [record])
            loaded = load_findings(run_dir)

            self.assertTrue(json_path.is_file())
            self.assertTrue(markdown_path.is_file())
            self.assertEqual(loaded, [record])
            markdown = render_findings_markdown(loaded)
            self.assertIn("# 项目问题库", markdown)
            self.assertIn("测试未授权访问", markdown)
            self.assertIn("已确认", markdown)


if __name__ == "__main__":
    unittest.main()
