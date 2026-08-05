from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path


SEVERITIES = ("critical", "high", "medium", "low", "info")
STATUSES = ("已确认", "待验证", "已排除")


@dataclass
class FindingRecord:
    finding_id: str
    title: str
    severity: str
    status: str
    vuln_type: str
    affected: list[str]
    parameter: str
    cvss: str
    description: str
    reproduction: list[str]
    evidence: list[str]
    remediation: list[str]
    source: str = "人工问题库"

    @classmethod
    def new(cls) -> "FindingRecord":
        return cls(
            finding_id=f"MF-{uuid.uuid4().hex[:8].upper()}",
            title="",
            severity="medium",
            status="待验证",
            vuln_type="",
            affected=[],
            parameter="-",
            cvss="N/A",
            description="",
            reproduction=[],
            evidence=[],
            remediation=[],
        )

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> "FindingRecord":
        record = cls.new()
        record.finding_id = str(value.get("finding_id") or record.finding_id)
        record.title = str(value.get("title") or "").strip()
        severity = str(value.get("severity") or "medium").lower()
        record.severity = severity if severity in SEVERITIES else "medium"
        status = str(value.get("status") or "待验证")
        record.status = status if status in STATUSES else "待验证"
        record.vuln_type = str(value.get("vuln_type") or "").strip()
        record.affected = _string_list(value.get("affected"))
        record.parameter = str(value.get("parameter") or "-").strip() or "-"
        record.cvss = str(value.get("cvss") or "N/A").strip() or "N/A"
        record.description = str(value.get("description") or "").strip()
        record.reproduction = _string_list(value.get("reproduction"))
        record.evidence = _string_list(value.get("evidence"))
        record.remediation = _string_list(value.get("remediation"))
        record.source = str(value.get("source") or "人工问题库").strip()
        return record


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def findings_json_path(run_dir: Path) -> Path:
    return run_dir / "findings.json"


def load_findings(run_dir: Path) -> list[FindingRecord]:
    path = findings_json_path(run_dir)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return []
    rows = value.get("findings", []) if isinstance(value, dict) else []
    if not isinstance(rows, list):
        return []
    return [FindingRecord.from_dict(item) for item in rows if isinstance(item, dict)]


def validate_finding(record: FindingRecord) -> str:
    if not record.title.strip():
        return "请填写问题标题。"
    if not record.vuln_type.strip():
        return "请填写漏洞类型。"
    if record.status == "已确认":
        if not record.reproduction:
            return "已确认问题必须填写复现过程。"
        if not record.evidence:
            return "已确认问题必须填写证据路径或证据说明。"
    return ""


def render_findings_markdown(records: list[FindingRecord]) -> str:
    lines = [
        "# 项目问题库",
        "",
        "本文件由 STTool 的结构化问题库生成。`findings.json` 是机器可读源文件，",
        "已确认问题必须同时具备复现过程和证据；自动化工具线索应保持为“待验证”。",
        "",
        "| ID | 标题 | 风险 | 状态 | 类型 |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    if not records:
        lines.append("| - | 暂无人工整理的问题 | - | - | - |")
    for record in records:
        lines.append(
            f"| {record.finding_id} | {record.title} | {record.severity} | "
            f"{record.status} | {record.vuln_type} |"
        )
    for record in records:
        lines.extend(
            [
                "",
                f"## [{record.finding_id}] {record.title}",
                "",
                f"- 风险等级：{record.severity}",
                f"- 状态：{record.status}",
                f"- 类型：{record.vuln_type}",
                f"- CVSS：{record.cvss}",
                f"- 参数：{record.parameter}",
                f"- 来源：{record.source}",
                "",
                "### 受影响资产",
                "",
            ]
        )
        lines.extend(f"- `{item}`" for item in record.affected)
        if not record.affected:
            lines.append("- 未填写")
        lines.extend(["", "### 问题描述", "", record.description or "未填写", "", "### 复现过程", ""])
        lines.extend(f"- {item}" for item in record.reproduction)
        if not record.reproduction:
            lines.append("- 未填写")
        lines.extend(["", "### 证据", ""])
        lines.extend(f"- {item}" for item in record.evidence)
        if not record.evidence:
            lines.append("- 未填写")
        lines.extend(["", "### 修复建议", ""])
        lines.extend(f"- {item}" for item in record.remediation)
        if not record.remediation:
            lines.append("- 未填写")
    return "\n".join(lines).strip() + "\n"


def save_findings(run_dir: Path, records: list[FindingRecord]) -> tuple[Path, Path]:
    for record in records:
        error = validate_finding(record)
        if error:
            raise ValueError(f"{record.title or record.finding_id}：{error}")
    payload = {
        "schema_version": 1,
        "findings": [asdict(record) for record in records],
    }
    json_path = findings_json_path(run_dir)
    markdown_path = run_dir / "findings.md"
    temporary = json_path.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    temporary.replace(json_path)
    markdown_path.write_text(render_findings_markdown(records), encoding="utf-8")
    return json_path, markdown_path
