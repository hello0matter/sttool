from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit


ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
DIRSEARCH_LINE = re.compile(
    r"^\s*(?P<status>\d{3})\s+(?P<size>\S+)\s+(?P<url>https?://\S+)"
    r"(?:\s+->\s+REDIRECTS TO:\s*(?P<redirect>.*))?$"
)


@dataclass(frozen=True)
class ProjectResultSource:
    title: str
    subtitle: str
    path: Path
    kind: str
    size: int
    preview_kind: str
    target: str = ""
    batch: str = ""

    @property
    def label(self) -> str:
        return self.title


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _add_source(
    sources: list[ProjectResultSource],
    seen: set[Path],
    *,
    title: str,
    subtitle: str,
    path: Path,
    kind: str,
    preview_kind: str,
    target: str = "",
    batch: str = "",
    allow_empty: bool = False,
) -> None:
    normalized = path.resolve(strict=False)
    size = _file_size(path)
    if normalized in seen or not path.is_file() or (not allow_empty and size == 0):
        return
    seen.add(normalized)
    sources.append(
        ProjectResultSource(
            title=title,
            subtitle=subtitle,
            path=path,
            kind=kind,
            size=size,
            preview_kind=preview_kind,
            target=target,
            batch=batch,
        )
    )


def _read_targets(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return list(dict.fromkeys(line.strip() for line in lines if line.strip()))


def _target_summary(targets: list[str]) -> str:
    if not targets:
        return "目标未记录"
    if len(targets) == 1:
        return targets[0]
    return f"{targets[0]} 等 {len(targets)} 个目标"


def _semantic_summary(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def project_result_sources(run_dir: Path) -> list[ProjectResultSource]:
    sources: list[ProjectResultSource] = []
    seen: set[Path] = set()

    fixed = (
        ("渗透测试报告", "项目结论与修复建议", run_dir / "pentest_report.md", "报告", "markdown"),
        ("已确认问题", "人工确认的问题库", run_dir / "findings.md", "问题", "markdown"),
        ("风险摘要", "风险分布与重点结论", run_dir / "risk_summary.md", "摘要", "markdown"),
        ("CVE 排查", "候选漏洞核验情况", run_dir / "cve_triage.md", "排查", "markdown"),
        ("漏洞情报", "版本、CVE 与 PoC 候选", run_dir / "vulnerability_intel.md", "情报", "markdown"),
    )
    for title, subtitle, path, kind, preview_kind in fixed:
        _add_source(
            sources,
            seen,
            title=title,
            subtitle=subtitle,
            path=path,
            kind=kind,
            preview_kind=preview_kind,
        )

    asset_path = run_dir / "tool_data" / "asset_bus" / "assets.json"
    if not asset_path.is_file():
        asset_path = run_dir / "results" / "asset_commander_assets.json"
    _add_source(
        sources,
        seen,
        title="资产清单",
        subtitle="已发现并归类的主机、域名和地址",
        path=asset_path,
        kind="资产",
        preview_kind="assets",
    )

    tscan_database = run_dir / "tool_data" / "tscan" / "app" / "config" / "config.db"
    if tscan_database.is_file():
        from .project_coordinator import tscan_findings

        if tscan_findings(tscan_database):
            _add_source(
                sources,
                seen,
                title="Tscan 发现",
                subtitle="Tscan 已保存的漏洞与服务线索",
                path=tscan_database,
                kind="综合扫描",
                preview_kind="tscan",
            )

    main_fscan = run_dir / "results" / "fscan.txt"
    _add_source(
        sources,
        seen,
        title="fscan 初始扫描",
        subtitle="初始目标的端口与服务",
        path=main_fscan,
        kind="端口扫描",
        preview_kind="fscan",
        target="初始目标",
        batch="初始",
    )
    for path in sorted(
        (run_dir / "tool_data" / "fscan_incremental").glob("batch-*/result.txt")
    ):
        raw_batch = path.parent.name.removeprefix("batch-")
        batch_number = raw_batch.lstrip("0") or "0"
        batch = f"第 {batch_number} 轮"
        targets = _read_targets(path.parent / "targets.txt")
        _add_source(
            sources,
            seen,
            title=f"fscan {batch}",
            subtitle=_target_summary(targets),
            path=path,
            kind="端口扫描",
            preview_kind="fscan",
            target=_target_summary(targets),
            batch=batch,
        )

    nuclei_paths: set[Path] = set()
    for pattern in (
        "results/nuclei*.txt",
        "results/nuclei*.json",
        "results/nuclei*.jsonl",
        "tool_data/nuclei*/**/result*.txt",
        "tool_data/nuclei*/**/result*.jsonl",
    ):
        nuclei_paths.update(run_dir.glob(pattern))
    for path in sorted(nuclei_paths):
        if path.name == "nuclei.txt":
            batch = "初始"
            subtitle = "初始目标的模板命中与风险线索"
        else:
            raw_batch = path.parent.name.removeprefix("batch-")
            batch_number = raw_batch.lstrip("0") or raw_batch
            batch = f"第 {batch_number} 轮" if batch_number else "增量"
            subtitle = _target_summary(_read_targets(path.parent / "targets.txt"))
        _add_source(
            sources,
            seen,
            title=f"nuclei {batch}扫描",
            subtitle=subtitle,
            path=path,
            kind="漏洞扫描",
            preview_kind="nuclei",
            batch=batch,
            allow_empty=True,
        )

    semantic_runs = run_dir / "tool_data" / "semantic" / "projects"
    for scan_dir in sorted(semantic_runs.glob("*/runs/*")):
        if not scan_dir.is_dir():
            continue
        summary_path = scan_dir / "summary.json"
        summary = _semantic_summary(summary_path)
        target = str(summary.get("target") or "")
        dirsearch_path = scan_dir / "dirsearch.txt"
        if dirsearch_path.is_file() and _file_size(dirsearch_path) > 0:
            _add_source(
                sources,
                seen,
                title="目录扫描",
                subtitle=target or scan_dir.name,
                path=dirsearch_path,
                kind="路径发现",
                preview_kind="dirsearch",
                target=target,
            )
            continue
        rounds = summary.get("rounds")
        top_findings = summary.get("top_findings")
        has_discovery = bool(top_findings) or (
            isinstance(rounds, list)
            and any(isinstance(item, dict) and item.get("entries") for item in rounds)
        )
        if has_discovery:
            _add_source(
                sources,
                seen,
                title="路径发现",
                subtitle=target or scan_dir.name,
                path=summary_path,
                kind="路径发现",
                preview_kind="semantic",
                target=target,
            )
    return sources


def _clean_lines(text: str, *, limit: int = 600) -> list[str]:
    lines: list[str] = []
    seen: set[str] = set()
    for raw_line in ANSI_ESCAPE.sub("", text).splitlines():
        line = "".join(char for char in raw_line if char >= " " or char == "\t").strip()
        if not line or line in seen:
            continue
        seen.add(line)
        lines.append(line)
        if len(lines) >= limit:
            break
    return lines


def readable_markdown(text: str, *, limit: int = 500) -> str:
    output: list[str] = []
    table_rows: list[list[str]] = []

    def flush_table() -> None:
        nonlocal table_rows
        if not table_rows:
            return
        rows = [row for row in table_rows if not all(set(cell) <= {"-", ":"} for cell in row)]
        if len(rows) >= 2:
            headers = rows[0]
            for row in rows[1:]:
                pairs = [
                    f"{headers[index]}：{value}"
                    for index, value in enumerate(row)
                    if index < len(headers) and value
                ]
                if pairs:
                    output.append("    ".join(pairs))
        elif rows:
            output.append("    ".join(rows[0]))
        table_rows = []

    in_code = False
    for raw_line in ANSI_ESCAPE.sub("", text).splitlines():
        line = raw_line.strip()
        if line.startswith("```"):
            in_code = not in_code
            continue
        if line.startswith("|") and line.endswith("|"):
            table_rows.append([cell.strip().strip("`") for cell in line.strip("|").split("|")])
            continue
        flush_table()
        if not line:
            if output and output[-1]:
                output.append("")
            continue
        line = re.sub(r"^#{1,6}\s+", "", line)
        line = re.sub(r"^[-*+]\s+", "• ", line)
        line = re.sub(r"^\d+\.\s+", "", line)
        line = line.replace("**", "").replace("__", "").replace("`", "")
        if not in_code:
            line = re.sub(r"\[([^]]+)]\([^)]+\)", r"\1", line)
        output.append(line)
        if len(output) >= limit:
            output.extend(("", "其余内容已折叠，可点击“打开原始文件”查看。"))
            break
    flush_table()
    return "\n".join(output).strip()


def _source_header(source: ProjectResultSource) -> list[str]:
    try:
        modified = datetime.fromtimestamp(source.path.stat().st_mtime).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    except OSError:
        modified = "未知"
    lines = [source.title, source.subtitle]
    if source.batch:
        lines.append(f"批次：{source.batch}")
    lines.extend((f"更新时间：{modified}", ""))
    return lines


def _preview_fscan(source: ProjectResultSource, text: str) -> str:
    lines = _clean_lines(text)
    sections: dict[str, list[str]] = {}
    current = "扫描结果"
    for line in lines:
        if line.startswith("#") and "=====" in line:
            current = line.replace("#", "").replace("=", "").strip()
            sections.setdefault(current, [])
            continue
        sections.setdefault(current, []).append(line)
    result = _source_header(source)
    result.append(f"有效记录：{sum(len(items) for items in sections.values())} 条")
    for title, items in sections.items():
        if not items:
            continue
        result.extend(("", title))
        result.extend(f"• {item}" for item in items)
    return "\n".join(result).strip()


def _preview_nuclei(source: ProjectResultSource, text: str) -> str:
    lines = _clean_lines(text)
    severities: dict[str, int] = {}
    for line in lines:
        fields = re.findall(r"\[([^]]+)]", line)
        severity = fields[2].lower() if len(fields) >= 3 else "未分级"
        severities[severity] = severities.get(severity, 0) + 1
    result = _source_header(source)
    result.append(f"模板命中：{len(lines)} 条")
    if severities:
        result.append(
            "风险分布：" + "，".join(f"{key} {value}" for key, value in severities.items())
        )
    result.extend(("", "命中详情"))
    result.extend(f"• {line}" for line in lines)
    return "\n".join(result).strip()


def _preview_dirsearch(source: ProjectResultSource, text: str) -> str:
    findings: list[tuple[str, str, str, str]] = []
    for line in ANSI_ESCAPE.sub("", text).splitlines():
        match = DIRSEARCH_LINE.match(line.strip())
        if not match:
            continue
        findings.append(
            (
                match.group("status"),
                match.group("size"),
                match.group("url"),
                match.group("redirect") or "",
            )
        )
    result = _source_header(source)
    result.append(f"发现路径：{len(findings)} 条")
    if not findings:
        result.extend(("", "本轮没有保留下来的有效路径。"))
    else:
        result.extend(("", "状态    大小       地址"))
        for status, size, url, redirect in findings[:600]:
            suffix = f"  → {redirect}" if redirect else ""
            result.append(f"{status:<7} {size:<10} {url}{suffix}")
    return "\n".join(result).strip()


def _collect_asset_values(value: object, prefix: str = "") -> list[tuple[str, list[str]]]:
    groups: list[tuple[str, list[str]]] = []
    if not isinstance(value, dict):
        return groups
    for key, item in value.items():
        label = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(item, list) and all(not isinstance(entry, (dict, list)) for entry in item):
            groups.append((label, [str(entry) for entry in item]))
        elif isinstance(item, dict):
            groups.extend(_collect_asset_values(item, label))
    return groups


def _preview_assets(source: ProjectResultSource, text: str) -> str:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return "\n".join(_source_header(source) + _clean_lines(text))
    assets = value.get("assets") if isinstance(value, dict) else None
    if isinstance(assets, list):
        typed_assets: dict[str, list[str]] = {}
        for item in assets:
            if not isinstance(item, dict):
                continue
            asset_type = str(item.get("type") or "未分类")
            asset_value = str(item.get("value") or "")
            if asset_value:
                typed_assets.setdefault(asset_type, []).append(asset_value)
        groups = list(typed_assets.items())
    else:
        groups = [(name, values) for name, values in _collect_asset_values(value) if values]
    result = _source_header(source)
    result.append(f"资产记录：{sum(len(values) for _, values in groups)} 条")
    for name, values in groups:
        result.extend(("", f"{name}（{len(values)}）"))
        result.extend(f"• {value}" for value in values[:100])
        if len(values) > 100:
            result.append(f"• 其余 {len(values) - 100} 条已折叠")
    return "\n".join(result).strip()


def _preview_tscan(source: ProjectResultSource) -> str:
    from .project_coordinator import tscan_findings

    findings = tscan_findings(source.path)
    result = _source_header(source)
    result.append(f"已保存线索：{len(findings)} 条")
    result.extend(("", "发现详情"))
    for item in findings[:600]:
        detail = str(item.get("detail") or "")
        if detail:
            result.append(f"• {detail}")
    if len(findings) > 600:
        result.append(f"• 其余 {len(findings) - 600} 条已折叠")
    return "\n".join(result).strip()


def _preview_semantic(source: ProjectResultSource, text: str) -> str:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return "\n".join(_source_header(source) + _clean_lines(text))
    findings: list[dict[str, object]] = []
    for item in value.get("top_findings", []):
        if isinstance(item, dict):
            findings.append(item)
    for round_item in value.get("rounds", []):
        if isinstance(round_item, dict):
            findings.extend(item for item in round_item.get("entries", []) if isinstance(item, dict))
    result = _source_header(source)
    result.append(f"发现路径：{len(findings)} 条")
    for item in findings[:600]:
        url = str(item.get("url") or item.get("path") or "未知地址")
        status = str(item.get("status") or "-")
        size = str(item.get("size") or item.get("length") or "-")
        result.append(f"{status:<7} {size:<10} {url}")
    return "\n".join(result).strip()


def preview_result_source(source: ProjectResultSource) -> str:
    if source.preview_kind == "tscan":
        return _preview_tscan(source)
    try:
        text = source.path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"无法读取该成果：{exc}"
    if source.preview_kind == "markdown":
        return readable_markdown(text)
    if source.preview_kind == "fscan":
        return _preview_fscan(source, text)
    if source.preview_kind == "nuclei":
        return _preview_nuclei(source, text)
    if source.preview_kind == "dirsearch":
        return _preview_dirsearch(source, text)
    if source.preview_kind == "assets":
        return _preview_assets(source, text)
    if source.preview_kind == "semantic":
        return _preview_semantic(source, text)
    return "\n".join(_source_header(source) + _clean_lines(text))


def result_target_label(source: ProjectResultSource) -> str:
    if source.target:
        return source.target
    if source.subtitle:
        return source.subtitle
    try:
        parsed = urlsplit(source.path.name)
        return parsed.netloc or "项目汇总"
    except ValueError:
        return "项目汇总"
