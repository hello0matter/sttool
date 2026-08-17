from __future__ import annotations

import json
import os
import re
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk

from .activity import activity_log_path
from .models import ProcessRecord, RunState
from .runtime import process_creation_token, process_record_alive


COORDINATOR_MANAGED_COMPONENTS = {
    "vulnx": "vulnx 漏洞情报",
    "find_gh_poc": "GitHub PoC 候选搜索",
}
AI_BATCH_COMPONENT_ID = "ai_execution_batches"
AI_BATCH_COMPONENT_NAME = "AI 执行记录"


LOG_BOTTOM_THRESHOLD = 0.98
_SENSITIVE_QUERY_RE = re.compile(
    r"(?i)([?&](?:access_token|api[_-]?key|apikey|token|secret|client_secret|authorization)=)([^&\s'\"<>]+)"
)
_AUTHORIZATION_RE = re.compile(
    r"(?i)(authorization\s*[:=]\s*(?:bearer|basic)?\s*)([^\s,;]+)"
)
_KNOWN_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,})(?![A-Za-z0-9_])"
)


def redact_sensitive_text(value: str) -> str:
    text = _SENSITIVE_QUERY_RE.sub(r"\1[REDACTED]", value)
    text = _AUTHORIZATION_RE.sub(r"\1[REDACTED]", text)
    return _KNOWN_TOKEN_RE.sub("[REDACTED]", text)


def log_refresh_scroll_policy(
    view: tuple[float, float], auto_follow: bool
) -> tuple[bool, float]:
    first, last = view
    follow = auto_follow or last >= LOG_BOTTOM_THRESHOLD
    return follow, max(0.0, min(first, 1.0))


def load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def tail_text(path: Path, limit: int = 160_000) -> str:
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - limit))
            data = handle.read()
    except OSError as exc:
        return f"读取失败：{exc}"
    return redact_sensitive_text(data.decode("utf-8", errors="replace"))


def filter_component_activity(
    content: str, component_id: str, component_name: str = ""
) -> str:
    aliases = {
        "asset_commander": ("AssetCommander",),
        "semantic_dirscan": ("AI 路径发现", "semantic"),
        "fscan": ("fscan",),
        "nuclei": ("nuclei",),
        "vulnx": ("vulnx", "漏洞情报"),
        "find_gh_poc": ("find-gh-poc", "GitHub PoC"),
        "tscan_plus": ("TscanPlus",),
        "project_coordinator": (
            "自动调度器",
            "项目增量调度器",
            "资产汇总队列",
            "资产总线",
            "AI 第",
            "Agent 批次",
        ),
        "ai_agent": ("本地 Agent", "Codex Agent", "Codexx", "Codex", "Claude"),
        AI_BATCH_COMPONENT_ID: (
            "Agent 批次",
            "AI 执行记录",
            "Codex",
            "Codexx",
            "Claude",
        ),
    }.get(component_id, ())
    candidates = [component_id, component_name, *aliases]
    normalized = [candidate.casefold() for candidate in candidates if candidate.strip()]
    owners = (
        ("tscan_plus", ("tscanplus",)),
        ("asset_commander", ("assetcommander",)),
        ("semantic_dirscan", ("ai 路径发现", "semantic")),
        ("nuclei", ("nuclei",)),
        ("vulnx", ("vulnx", "漏洞情报")),
        ("find_gh_poc", ("find-gh-poc", "github poc")),
        (
            "project_coordinator",
            (
                "自动调度器",
                "项目增量调度器",
                "资产汇总队列",
                "资产总线",
                "ai 第",
                "ai 执行",
                "agent 批次",
            ),
        ),
        ("fscan", ("fscan",)),
        ("ai_agent", ("本地 agent", "codex agent", "codexx", "codex", "claude")),
    )
    selected: list[str] = []
    for line in content.splitlines():
        folded = line.casefold()
        if component_id == AI_BATCH_COMPONENT_ID and any(
            alias in folded for alias in normalized
        ):
            selected.append(line)
            continue
        owner = next(
            (
                owner_id
                for owner_id, owner_aliases in owners
                if any(alias in folded for alias in owner_aliases)
            ),
            "",
        )
        if owner:
            if owner == component_id:
                selected.append(line)
            continue
        if any(alias in folded for alias in normalized):
            selected.append(line)
    return "\n".join(selected)


def component_activity_log_path(run_dir: Path, component_id: str) -> Path:
    safe_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", component_id).strip("._")
    return run_dir / "component_logs" / f"{safe_id or 'component'}.log"


def refresh_component_activity_log(
    run_dir: Path, component_id: str, component_name: str = ""
) -> Path:
    destination = component_activity_log_path(run_dir, component_id)
    source = activity_log_path(run_dir)
    try:
        content = source.read_text(encoding="utf-8")
    except OSError:
        content = ""
    filtered = filter_component_activity(content, component_id, component_name)
    destination.parent.mkdir(parents=True, exist_ok=True)
    rendered = filtered + ("\n" if filtered else "")
    try:
        existing = destination.read_text(encoding="utf-8")
    except OSError:
        existing = ""
    if rendered != existing:
        destination.write_text(rendered, encoding="utf-8")
    return destination


def semantic_project_dir(workdir: Path) -> Path | None:
    projects_dir = workdir / "projects"
    launcher = load_json(workdir / "launcher_state.json")
    last_project = str(launcher.get("last_project") or "").strip()
    if last_project:
        candidate = projects_dir / last_project
        if candidate.is_dir():
            return candidate
    candidates = [path for path in projects_dir.iterdir() if path.is_dir()] if projects_dir.is_dir() else []
    if not candidates:
        return None

    def latest_marker(project_dir: Path) -> int:
        markers = [
            project_dir / "project.json",
            project_dir / "gui.log",
            *project_dir.glob("runs/**/runtime_state.json"),
        ]
        values: list[int] = []
        for marker_path in markers:
            try:
                values.append(marker_path.stat().st_mtime_ns)
            except OSError:
                continue
        return max(values, default=0)

    return max(candidates, key=latest_marker)


def component_paths(
    run_dir: Path, component_id: str, component_name: str = ""
) -> dict[str, list[Path] | Path]:
    component_activity = refresh_component_activity_log(
        run_dir, component_id, component_name
    )
    if component_id == AI_BATCH_COMPONENT_ID:
        workdir = run_dir / "agent_batches"
        return {
            "workdir": workdir,
            "states": sorted(workdir.glob("*/batch.json")),
            "logs": [component_activity],
            "results": [
                run_dir / "findings.md",
                run_dir / "risk_summary.md",
                run_dir / "pentest_report.txt",
                workdir,
            ],
        }
    if component_id == "asset_commander":
        workdir = run_dir / "tool_data" / "asset_commander"
        return {
            "workdir": workdir,
            "states": [workdir / "workflow_state.json"],
            "logs": [
                *workdir.glob("workspace/**/runtime.log"),
                *workdir.glob("workspace/**/fail_samples.log"),
                workdir / "AssetCommander-crash.log",
            ],
            "results": [run_dir / "results" / "asset_commander_assets.json"],
        }
    if component_id == "semantic_dirscan":
        workdir = run_dir / "tool_data" / "semantic"
        project_dir = semantic_project_dir(workdir)
        project_states = (
            list(project_dir.glob("runs/**/runtime_state.json"))
            if project_dir is not None
            else []
        )
        project_logs = (
            [project_dir / "gui.log"] if project_dir is not None else []
        )
        return {
            "workdir": workdir,
            "states": [
                workdir / "sttool_bridge_state.json",
                workdir / "launcher_state.json",
                *project_states,
            ],
            "logs": project_logs,
            "results": [
                project_dir if project_dir is not None else workdir / "projects",
                workdir / "reports",
            ],
        }
    if component_id == "tscan_plus":
        workdir = run_dir / "tool_data" / "tscan"
        own_log = workdir / "activity.log"
        return {
            "workdir": workdir,
            "states": [workdir / "state.json"],
            "logs": [own_log if own_log.is_file() else component_activity],
            "results": [workdir / "state.json"],
        }
    if component_id == "passhack":
        workdir = run_dir / "tool_data" / "passhack"
        return {
            "workdir": workdir,
            "states": [workdir / "state.json"],
            "logs": [workdir / "passhack.log", component_activity],
            "results": [run_dir / "results" / "passhack.json"],
        }
    if component_id == "project_coordinator":
        workdir = run_dir / "tool_data" / "coordinator"
        return {
            "workdir": workdir,
            "states": [
                workdir / "state.json",
                run_dir / "tool_data" / "asset_bus" / "assets.json",
            ],
            "logs": [
                component_activity,
            ],
            "results": [
                run_dir / "pentest_report.md",
                run_dir / "pentest_report.txt",
                run_dir / "findings.json",
                run_dir / "findings.md",
                run_dir / "risk_summary.md",
                run_dir / "tool_data" / "asset_bus" / "assets.json",
                run_dir / "agent_batches",
            ],
        }
    if component_id == "vulnx":
        return {
            "workdir": run_dir,
            "states": [run_dir / "results" / "vulnerability_intel.json"],
            "logs": [component_activity],
            "results": [
                run_dir / "vulnerability_intel.md",
                run_dir / "results" / "vulnerability_intel.json",
                run_dir / "results" / "vulnx.json",
            ],
        }
    if component_id == "find_gh_poc":
        return {
            "workdir": run_dir,
            "states": [
                run_dir / "results" / "find_gh_poc.json",
                run_dir / "results" / "vulnerability_intel.json",
            ],
            "logs": [component_activity],
            "results": [run_dir / "results" / "find_gh_poc.json"],
        }
    if component_id == "fscan":
        result = run_dir / "results" / "fscan.txt"
        return {
            "workdir": run_dir,
            "states": [],
            "logs": [result, component_activity],
            "results": [result],
        }
    if component_id == "nuclei":
        result = run_dir / "results" / "nuclei.txt"
        return {
            "workdir": run_dir,
            "states": [],
            "logs": [result, component_activity],
            "results": [result],
        }
    return {
        "workdir": run_dir,
        "states": [],
        "logs": [component_activity],
        "results": [run_dir / "results"],
    }


def human_status(value: object) -> str:
    text = str(value or "").strip()
    return {
        "starting": "\u542f\u52a8\u4e2d",
        "running": "\u8fd0\u884c\u4e2d",
        "waiting_assets": "\u7b49\u5f85\u8d44\u4ea7",
        "waiting": "\u7b49\u5f85\u4e2d",
        "completed": "\u5df2\u5b8c\u6210",
        "finished": "\u5df2\u5b8c\u6210",
        "done": "\u5df2\u5b8c\u6210",
        "failed": "\u5931\u8d25",
        "stopped": "\u5df2\u6682\u505c",
        "exited": "\u5df2\u9000\u51fa",
        "pending": "\u5f85\u8fd0\u884c",
        "not_selected": "未选择",
        "blocked_without_vulnx": "等待 vulnx",
        "skipped_no_token": "未配置 GitHub Token",
        "unavailable": "不可用",
        "completed_with_errors": "完成（有错误）",
        "waiting_candidates": "等待登录入口",
        "processing": "正在验证",
        "weak_password_found": "发现弱口令",
        "stopped_defense": "触发防护后停止",
    }.get(text, text or "\u672a\u77e5")


def summarize_list(
    lines: list[str],
    label: str,
    values: object,
    *,
    limit: int = 40,
) -> None:
    if not isinstance(values, list):
        return
    lines.append(f"{label}\uff1a{len(values)} \u6761")
    for item in values[:limit]:
        if isinstance(item, dict):
            value = (
                item.get("url")
                or item.get("endpoint")
                or item.get("value")
                or item.get("path")
                or item.get("name")
                or json.dumps(item, ensure_ascii=False)
            )
        else:
            value = item
        lines.append(f"  \u2022 {value}")
    if len(values) > limit:
        lines.append(
            f"  \u2026\u2026\u5176\u4f59 {len(values) - limit} \u6761\u8bf7\u6253\u5f00\u539f\u59cb\u72b6\u6001\u6587\u4ef6\u67e5\u770b"
        )


def render_component_state(path: Path, component_id: str) -> str:
    state = load_json(path)
    if not state:
        return f"{path.name}\uff1a\u72b6\u6001\u6587\u4ef6\u4e3a\u7a7a\u6216\u6682\u65f6\u65e0\u6cd5\u8bfb\u53d6\u3002"
    lines: list[str] = []
    if component_id == AI_BATCH_COMPONENT_ID:
        exit_state = load_json(path.with_name("agent_exit.json"))
        batch_status = load_json(path.with_name("batch_status.json"))
        status = str(state.get("status") or "pending")
        exit_code = exit_state.get("exit_code")
        if exit_state:
            status = "completed" if exit_code == 0 else "failed"
        elif batch_status:
            status = str(batch_status.get("status") or status)
        provider = str(state.get("provider") or "-")
        provider_name = {
            "codex": "Codex CLI",
            "codexx": "Codexx CLI",
            "claude": "Claude CLI",
        }.get(provider, provider)
        batch_number = state.get("batch") or path.parent.name
        lines.extend(
            [
                f"【AI 执行记录 {batch_number}】",
                f"执行器：{provider_name}",
                f"状态：{human_status(status)}",
                f"模型：{state.get('agent_model') or 'CLI 默认'}",
                f"推理强度：{state.get('reasoning_effort') or 'CLI 默认'}",
                f"PID：{state.get('pid') or '-'}",
                f"开始时间：{state.get('started_at') or '-'}",
                f"结束时间：{exit_state.get('completed_at') or batch_status.get('completed_at') or state.get('completed_at') or '-'}",
            ]
        )
        generation_from = state.get("generation_from")
        generation_to = state.get("generation_to")
        if generation_from is not None or generation_to is not None:
            lines.append(
                f"资产更新轮次：{generation_from if generation_from is not None else '-'}"
                f" 至 {generation_to if generation_to is not None else '-'}"
            )
        if exit_code is not None:
            lines.append(f"退出码：{exit_code}")
        error = str(
            exit_state.get("error")
            or batch_status.get("error")
            or state.get("error")
            or ""
        ).strip()
        if error:
            lines.append(f"错误摘要：{error[:1000]}")
        return "\n".join(lines)
    if component_id == "passhack":
        counts = state.get("counts")
        counts = counts if isinstance(counts, dict) else {}
        lines.extend(
            [
                "【PassHack 后台登录面审计】",
                f"状态：{human_status(state.get('status'))}",
                f"阶段：{human_status(state.get('stage'))}",
                f"说明：{state.get('detail') or '-'}",
                f"当前目标：{state.get('current_target') or '等待新入口'}",
                f"本进程已处理：{int(state.get('processed') or 0)} 条",
                f"累计结果：{int(state.get('result_total') or 0)} 条",
                f"待处理批准项：{int(state.get('approved_waiting') or 0)} 条",
                f"有效检查：{int(counts.get('completed') or 0)} 条",
                f"发现弱口令：{int(counts.get('weak_password_found') or 0)} 条",
                f"触发防护停止：{int(counts.get('stopped_defense') or 0)} 条",
                f"范围跳过：{int(counts.get('skipped_scope') or 0)} 条",
                f"失败：{int(counts.get('error') or 0)} 条",
                f"范围修复后重新排队：{int(state.get('requeued_scope_skips') or 0)} 条",
                f"更新时间：{state.get('updated_at') or '-'}",
            ]
        )
        effective_config = state.get("effective_config")
        if isinstance(effective_config, dict):
            lines.extend(
                [
                    "??????????",
                    f"?????{effective_config.get('source') or '-'}",
                    f"??????{'??' if effective_config.get('brute_enabled', True) else '??'}",
                    f"????????{int(effective_config.get('max_attempts') or 10)} ?",
                    f"????????{int(effective_config.get('requests_per_minute') or 10)} ?",
                    f"?????{int(effective_config.get('concurrency') or 1)}",
                    f"?????????{'?' if effective_config.get('stop_on_defense', True) else '?'}",
                    f"?????{effective_config.get('username_wordlist_path') or 'PassHack ????'}",
                    f"?????{effective_config.get('wordlist_path') or 'PassHack ????'}",
                ]
            )
        last_result = state.get("last_result")
        if isinstance(last_result, dict):
            lines.append(
                "最近结果："
                f"{human_status(last_result.get('status'))}；"
                f"{last_result.get('url') or '-'}；"
                f"{last_result.get('result') or last_result.get('error') or '-'}"
            )
        return "\n".join(lines)
    if component_id == "semantic_dirscan":
        if path.name == "sttool_bridge_state.json":
            lines.append("\u3010\u8d44\u4ea7\u540c\u6b65\u6982\u89c8\u3011")
            lines.append(f"\u9879\u76ee\uff1a{state.get('project') or '-'}")
            lines.append(f"\u66f4\u65b0\u65f6\u95f4\uff1a{state.get('updated_at') or '-'}")
            lines.append(
                "AssetCommander\uff1a"
                + human_status(state.get("asset_workflow_status"))
            )
            handoff = state.get("asset_handoff_ready")
            if handoff is not None:
                handoff_text = "\u662f" if handoff else "\u5426"
                lines.append(
                    f"\u8d44\u4ea7\u5df2\u653e\u884c\u7ed9\u8def\u5f84\u53d1\u73b0\uff1a{handoff_text}"
                )
            summarize_list(
                lines,
                "\u5df2\u7eb3\u5165\u626b\u63cf\u76ee\u6807",
                state.get("targets"),
            )
            summarize_list(
                lines,
                "\u7b49\u5f85\u653e\u884c\u76ee\u6807",
                state.get("queued_asset_targets"),
            )
            rejected = int(state.get("rejected") or 0)
            if any(
                key in state
                for key in (
                    "candidate_count",
                    "asset_candidate_count",
                    "fscan_candidate_count",
                    "accepted_count",
                    "rejected_targets",
                )
            ):
                targets = state.get("targets")
                target_count = len(targets) if isinstance(targets, list) else 0
                lines.append("\u76ee\u6807\u6570\u91cf\u5bf9\u8d26\uff1a")
                lines.append(
                    "  \u2022 \u6700\u7ec8 Web \u626b\u63cf\u76ee\u6807\uff1a"
                    f"{int(state.get('accepted_count') or target_count)} \u4e2a"
                )
                lines.append(
                    "  \u2022 AssetCommander \u5019\u9009\uff1a"
                    f"{int(state.get('asset_candidate_count') or 0)} \u4e2a"
                )
                lines.append(
                    "  \u2022 Fscan \u5019\u9009\uff1a"
                    f"{int(state.get('fscan_candidate_count') or 0)} \u4e2a"
                )
                lines.append(
                    "  \u2022 \u539f\u59cb\u5019\u9009\u603b\u6570\uff1a"
                    f"{int(state.get('candidate_count') or 0)} \u4e2a"
                )
                lines.append(f"  \u2022 \u8fc7\u6ee4\uff1a{rejected} \u4e2a")
                summarize_list(
                    lines,
                    "\u88ab\u8fc7\u6ee4\u76ee\u6807",
                    state.get("rejected_targets"),
                )
            elif rejected:
                lines.append(f"\u56e0\u6388\u6743\u8303\u56f4\u88ab\u8fc7\u6ee4\uff1a{rejected} \u6761")
            error = str(state.get("last_error") or "").strip()
            if error:
                lines.append(f"\u6700\u8fd1\u9519\u8bef\uff1a{error}")
            markers = state.get("source_markers")
            if isinstance(markers, dict):
                lines.append("\u6570\u636e\u6765\u6e90\uff1a")
                for name, marker in markers.items():
                    if isinstance(marker, dict):
                        lines.append(
                            f"  \u2022 {name}\uff1a{int(marker.get('size') or 0)} \u5b57\u8282\uff0c"
                            f"\u66f4\u65b0\u65f6\u95f4\u6807\u8bb0 {marker.get('mtime_ns') or '-'}"
                        )
            return "\n".join(lines)
        if path.name == "runtime_state.json":
            lines.append("\u3010\u5f53\u524d\u626b\u63cf\u8fdb\u5ea6\u3011")
            lines.append(f"\u72b6\u6001\uff1a{human_status(state.get('phase'))}")
            lines.append(f"\u76ee\u6807\uff1a{state.get('target') or '-'}")
            lines.append(f"\u5f53\u524d URL\uff1a{state.get('current_url') or '-'}")
            depth = state.get("current_depth")
            lines.append(f"\u5f53\u524d\u6df1\u5ea6\uff1a{depth if depth is not None else '-'}")
            lines.append(f"\u5df2\u5b8c\u6210\u7236\u8def\u5f84\uff1a{int(state.get('completed_targets') or 0)}")
            lines.append(f"\u5f85\u626b\u63cf\u961f\u5217\uff1a{int(state.get('queue_size') or 0)}")
            lines.append(f"\u626b\u63cf\u8f6e\u6b21\uff1a{int(state.get('round_count') or 0)}")
            lines.append(f"\u5f53\u524d\u5b57\u5178\uff1a{state.get('wordlist') or '-'}")
            overview = state.get("overview")
            if isinstance(overview, dict):
                lines.append(
                    "\u98ce\u9669\u7ebf\u7d22\uff1a"
                    f"\u9ad8\u4ef7\u503c {int(overview.get('high_value_count') or 0)}\uff0c"
                    f"\u8ba4\u8bc1\u63d0\u9192 {int(overview.get('auth_warning_count') or 0)}"
                )
            summarize_list(
                lines,
                "\u91cd\u70b9\u53d1\u73b0",
                state.get("top_findings"),
                limit=20,
            )
            return "\n".join(lines)
        if path.name == "launcher_state.json":
            return "\n".join(
                [
                    "\u3010\u542f\u52a8\u5668\u8bb0\u5f55\u3011",
                    f"\u6700\u540e\u5de5\u7a0b\uff1a{state.get('last_project') or '-'}",
                    f"\u5de5\u7a0b\u76ee\u5f55\uff1a{state.get('last_project_dir') or '-'}",
                ]
            )
    lines.append(f"\u3010\u72b6\u6001\u6982\u89c8\uff1a{path.name}\u3011")
    for key, label in (
        ("status", "\u72b6\u6001"),
        ("stage", "\u5f53\u524d\u6b65\u9aa4"),
        ("current_step", "\u5f53\u524d\u6b65\u9aa4"),
        ("detail", "\u8bf4\u660e"),
        ("error", "\u9519\u8bef"),
        ("updated_at", "\u66f4\u65b0\u65f6\u95f4"),
        ("generation", "\u8d44\u4ea7\u4ee3\u6b21"),
        ("consumed_generation", "\u5df2\u6d88\u8d39\u4ee3\u6b21"),
    ):
        value = state.get(key)
        if value in {None, ""}:
            continue
        lines.append(
            f"{label}\uff1a{human_status(value) if key == 'status' else value}"
        )
    steps = state.get("steps")
    if isinstance(steps, dict) and steps:
        lines.append("\u6b65\u9aa4\u72b6\u6001\uff1a")
        for name, value in steps.items():
            if isinstance(value, dict):
                status = human_status(value.get("status"))
                detail = str(value.get("detail") or "").strip()
                lines.append(
                    f"  \u2022 {name}\uff1a{status}"
                    + (f"\uff1b{detail}" if detail else "")
                )
    for key, label in (
        ("targets", "\u76ee\u6807"),
        ("urls", "URL"),
        ("domains", "\u57df\u540d"),
        ("ips", "IP"),
    ):
        summarize_list(lines, label, state.get(key), limit=20)
    if len(lines) == 1:
        lines.append(
            "\u8be5\u72b6\u6001\u6587\u4ef6\u6ca1\u6709\u53ef\u76f4\u63a5\u5c55\u793a\u7684\u6458\u8981\u5b57\u6bb5\uff1b"
            "\u53ef\u70b9\u51fb\u201c\u6253\u5f00\u539f\u59cb\u72b6\u6001\u201d\u67e5\u770b\u3002"
        )
    return "\n".join(lines)


def component_runtime(run_dir: Path, component_id: str) -> tuple[str, str, str]:
    if component_id == AI_BATCH_COMPONENT_ID:
        batches = sorted((run_dir / "agent_batches").glob("*/batch.json"))
        if not batches:
            return "pending", "waiting_first_batch", "尚未启动 AI 执行"
        latest = batches[-1]
        batch_states = [(item, load_json(item)) for item in batches]
        state = batch_states[-1][1]
        resolved_states: list[tuple[str, dict[str, object], dict[str, object]]] = []
        for path, item in batch_states:
            item_exit = load_json(path.with_name("agent_exit.json"))
            item_status = load_json(path.with_name("batch_status.json"))
            status = str(item.get("status") or "pending")
            terminal_status = str(item_status.get("status") or "")
            if terminal_status in {"completed", "failed"}:
                status = terminal_status
            elif status not in {"completed", "failed"} and item_exit:
                status = "completed" if item_exit.get("exit_code") == 0 else "failed"
            resolved_states.append((status, item_exit, item_status))
        status, exit_state, batch_status = resolved_states[-1]
        batch_number = state.get("batch") or latest.parent.name
        provider = str(state.get("provider") or "未知执行器")
        statuses = [item[0] for item in resolved_states]
        completed = statuses.count("completed")
        failed = statuses.count("failed")
        detail = (
            f"共 {len(batches)} 次 AI 执行记录；成功 {completed} 次，失败 {failed} 次；"
            f"最新为第 {batch_number} 次，执行器 {provider}"
        )
        error = str(
            exit_state.get("error")
            or batch_status.get("error")
            or state.get("error")
            or ""
        ).strip()
        if error:
            detail += f"；{error[:300]}"
        return status, "agent_batch", detail
    if component_id == "asset_commander":
        state = load_json(
            run_dir / "tool_data" / "asset_commander" / "workflow_state.json"
        )
        status = str(state.get("status") or "")
        stage = str(state.get("current_step") or "")
        detail = ""
        if status == "completed":
            if state.get("monitoring_asset_bus"):
                generation = int(state.get("asset_bus_generation") or 0)
                detail = (
                    "资产工作流已完成；正在监听资产汇总队列并处理新增资产；"
                    f"AI 已处理到第 {generation} 轮；窗口仍保留"
                )
            else:
                detail = "资产工作流已完成；AssetCommander 窗口仍保留，可继续手动操作"
        steps = state.get("steps")
        if stage and isinstance(steps, dict):
            step = steps.get(stage)
            if isinstance(step, dict):
                detail = str(step.get("detail") or step.get("status") or "")
        return status, stage, detail
    if component_id == "tscan_plus":
        state = load_json(run_dir / "tool_data" / "tscan" / "state.json")
        pid = int(state.get("pid") or 0)
        creation_token = int(state.get("process_creation_token") or 0)
        if (
            pid > 0
            and creation_token > 0
            and process_creation_token(pid) == creation_token
        ):
            return (
                "running",
                "window_active",
                f"TscanPlus 窗口 PID {pid} 仍在运行；自动控制已退出，恢复项目后可重新接管",
            )
        return (
            str(state.get("status") or ""),
            str(state.get("stage") or ""),
            str(state.get("detail") or state.get("error") or ""),
        )
    if component_id == "passhack":
        state = load_json(run_dir / "tool_data" / "passhack" / "state.json")
        status = str(state.get("status") or "pending")
        stage = str(state.get("stage") or "waiting_candidates")
        counts = state.get("counts")
        counts = counts if isinstance(counts, dict) else {}
        current = str(state.get("current_target") or "").strip()
        detail = str(state.get("detail") or "").strip()
        summary = (
            f"已处理 {int(state.get('processed') or 0)} 条，"
            f"有效检查 {int(counts.get('completed') or 0)} 条，"
            f"弱口令 {int(counts.get('weak_password_found') or 0)} 条，"
            f"防护停止 {int(counts.get('stopped_defense') or 0)} 条，"
            f"范围跳过 {int(counts.get('skipped_scope') or 0)} 条，"
            f"失败 {int(counts.get('error') or 0)} 条"
        )
        effective_config = state.get("effective_config")
        if isinstance(effective_config, dict) and effective_config.get("source"):
            summary += f"??? {effective_config['source']}"
        if current:
            summary += f"；当前目标 {current}"
        elif detail:
            summary += f"；{detail}"
        return status, stage, summary
    if component_id == "project_coordinator":
        state = load_json(run_dir / "tool_data" / "coordinator" / "state.json")
        detail = str(
            state.get("detail")
            or state.get("agent_launch_error")
            or state.get("error")
            or ""
        )
        return (
            str(state.get("status") or ""),
            str(state.get("stage") or ""),
            detail,
        )
    if component_id == "semantic_dirscan":
        state = load_json(
            run_dir / "tool_data" / "semantic" / "sttool_bridge_state.json"
        )
        status = str(state.get("status") or "")
        state_stage = str(state.get("stage") or "")
        state_detail = str(state.get("detail") or "")
        asset_status = str(state.get("asset_workflow_status") or "")
        queued = state.get("queued_asset_targets")
        queued_count = len(queued) if isinstance(queued, list) else 0
        error = str(state.get("last_error") or "")
        if error:
            return "failed", "asset_handoff", error
        if asset_status and asset_status != "completed":
            return "waiting_assets", "waiting_asset_commander", (
                f"等待 AssetCommander，暂存 {queued_count} 个目标"
            )
        targets = state.get("targets")
        target_count = len(targets) if isinstance(targets, list) else 0
        if any(
            key in state
            for key in (
                "asset_candidate_count",
                "fscan_candidate_count",
                "accepted_count",
                "rejected",
            )
        ):
            accepted_count = int(state.get("accepted_count") or target_count)
            asset_count = int(state.get("asset_candidate_count") or 0)
            fscan_count = int(state.get("fscan_candidate_count") or 0)
            rejected_count = int(state.get("rejected") or 0)
            runtime_status = (
                status
                if status in {"completed", "failed", "stopped", "interrupted"}
                else "running"
            )
            return (
                runtime_status,
                state_stage or "directory_scan",
                state_detail
                or f"\u6700\u7ec8 Web \u626b\u63cf\u76ee\u6807 {accepted_count} \u4e2a\uff1b"
                f"AssetCommander \u5019\u9009 {asset_count} \u4e2a\uff1b"
                f"Fscan \u5019\u9009 {fscan_count} \u4e2a\uff1b"
                f"\u8fc7\u6ee4 {rejected_count} \u4e2a",
            )
        return (
            status or "running",
            state_stage or "directory_scan",
            state_detail
            or f"\u5df2\u540c\u6b65 {target_count} \u4e2a\u626b\u63cf\u76ee\u6807",
        )
    if component_id == "vulnx":
        state = load_json(run_dir / "tool_data" / "coordinator" / "state.json")
        status = str(state.get("vuln_intel_status") or "pending")
        if status == "pending":
            return "waiting_assets", "waiting_asset_stability", "等待资产稳定后关联 CVE、KEV 与模板"
        detail = str(state.get("vuln_intel_error") or "")
        if not detail:
            detail = (
                f"候选 {int(state.get('vuln_intel_candidates') or 0)}，"
                f"高可信 {int(state.get('vuln_intel_high_confidence') or 0)}"
            )
        return status, "vulnerability_intelligence", detail
    if component_id == "find_gh_poc":
        state = load_json(run_dir / "tool_data" / "coordinator" / "state.json")
        status = str(state.get("find_gh_poc_status") or "pending")
        if status == "skipped_no_token":
            return "manual_required", "waiting_github_token", "未配置 GitHub Token；已安全跳过，不影响其他阶段"
        if status in {"pending", "not_requested"}:
            return "waiting_assets", "waiting_cve_candidates", "等待 vulnx 生成 CVE 候选"
        if status == "blocked_without_vulnx":
            return "waiting_assets", "waiting_vulnx", "已选择 find-gh-poc，但 vulnx 未选择"
        result = load_json(run_dir / "results" / "find_gh_poc.json")
        candidates = result.get("candidates")
        count = len(candidates) if isinstance(candidates, list) else 0
        return status, "github_poc_search", f"PoC 候选链接 {count} 条；只保存元数据，不执行"
    if component_id in {"fscan", "nuclei"}:
        result = run_dir / "results" / f"{component_id}.txt"
        if result.is_file():
            return "completed", "result_saved", f"结果已保存：{result.name}"
    return "", "", ""


def component_display_runtime(
    run_dir: Path, component_id: str
) -> tuple[str, str, str]:
    tool_status, stage, detail = component_runtime(run_dir, component_id)
    run_state = load_json(run_dir / "run.json")
    processes = run_state.get("processes")
    if not isinstance(processes, list):
        return tool_status, stage, detail
    for process in processes:
        if not isinstance(process, dict) or process.get("component_id") != component_id:
            continue
        process_status = str(process.get("status") or "")
        if process_status == "running":
            try:
                record = ProcessRecord.from_dict(process)
            except (TypeError, ValueError):
                record = None
            if record is not None and not process_record_alive(record, run_dir):
                process_status = "exited"
        if process_status not in {"stopped", "exited"}:
            return tool_status, stage, detail
        if component_id == "tscan_plus" and stage == "window_active":
            return tool_status, stage, detail
        if process_status == "exited" and tool_status == "completed":
            if component_id == "asset_commander":
                detail = "资产工作流已完成；项目进程已退出，结果与资产队列已保留"
            return tool_status, stage, detail
        last_state = tool_status or "unknown"
        process_label = "暂停" if process_status == "stopped" else "退出"
        stopped_detail = f"组件进程已{process_label}；工作流最后状态：{last_state}"
        if stage:
            stopped_detail += f"，最后步骤：{stage}"
        if detail:
            stopped_detail += f"，{detail}"
        return process_status, "process_stopped", stopped_detail
    return tool_status, stage, detail


def component_summary_status(
    run_dir: Path, component_id: str, process_status: str
) -> str:
    status, _stage, _detail = component_display_runtime(run_dir, component_id)
    labels = {
        "completed": "完成",
        "running": "运行",
        "waiting_assets": "等待资产",
        "failed": "失败",
        "interrupted": "中断",
        "stopped": "已暂停",
        "exited": "已退出",
    }
    label = labels.get(status)
    if label is None:
        label = "运行" if process_status == "running" else "结束"
    if (
        component_id == "asset_commander"
        and status == "completed"
        and process_status == "running"
    ):
        return "完成（窗口保留）"
    return label


class ComponentLogDialog(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Misc,
        run_dir: Path,
        component_id: str,
        component_name: str,
    ) -> None:
        super().__init__(parent)
        self.run_dir = run_dir
        self.component_id = component_id
        self.component_name = component_name
        self.sources = component_paths(run_dir, component_id, component_name)
        self._after_id: str | None = None
        self._last_content = ""
        self.follow_var = tk.BooleanVar(value=True)

        self.title(f"组件日志 - {component_name}")
        self.geometry("1180x760")
        self.minsize(900, 580)
        self.transient(parent)

        container = ttk.Frame(self, padding=14)
        container.pack(fill="both", expand=True)
        container.columnconfigure(0, weight=1)
        container.rowconfigure(2, weight=1)

        self.summary_var = tk.StringVar()
        ttk.Label(
            container,
            textvariable=self.summary_var,
            font=("Microsoft YaHei UI", 11, "bold"),
        ).grid(row=0, column=0, sticky="w", pady=(0, 8))
        ttk.Label(
            container,
            text="\u9ed8\u8ba4\u5c55\u793a\u9762\u5411\u4eba\u7684\u8fd0\u884c\u6982\u89c8\u548c\u5355\u5de5\u5177\u65e5\u5fd7\uff1b\u539f\u59cb JSON \u53ef\u5355\u72ec\u6253\u5f00\u3002",
        ).grid(row=1, column=0, sticky="w", pady=(0, 8))

        self.text = scrolledtext.ScrolledText(
            container,
            wrap="word",
            font=("Microsoft YaHei UI", 10),
            state="disabled",
        )
        self.text.grid(row=2, column=0, sticky="nsew")
        self.text.bind("<MouseWheel>", self._pause_follow, add="+")
        self.text.bind("<Prior>", self._pause_follow, add="+")
        self.text.bind("<Next>", self._pause_follow, add="+")
        self.text.vbar.bind("<ButtonPress-1>", self._pause_follow, add="+")

        actions = ttk.Frame(container)
        actions.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        ttk.Button(actions, text="打开工作目录", command=self._open_workdir).pack(
            side="left"
        )
        ttk.Button(actions, text="打开日志文件", command=self._open_log).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(
            actions,
            text="\u6253\u5f00\u539f\u59cb\u72b6\u6001",
            command=self._open_state,
        ).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="打开结果", command=self._open_result).pack(
            side="left", padx=(8, 0)
        )
        ttk.Checkbutton(
            actions,
            text="自动跟随最新日志",
            variable=self.follow_var,
        ).pack(side="left", padx=(16, 0))
        ttk.Button(actions, text="回到底部", command=self._scroll_to_end).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(actions, text="关闭", command=self._close).pack(side="right")

        self.protocol("WM_DELETE_WINDOW", self._close)
        self._refresh()

    def _existing(self, key: str) -> list[Path]:
        values = self.sources.get(key, [])
        if not isinstance(values, list):
            return []
        existing = [path for path in values if path.exists()]
        return sorted(
            existing,
            key=lambda path: path.stat().st_mtime_ns if path.exists() else 0,
        )

    def _content(self) -> str:
        refresh_component_activity_log(
            self.run_dir, self.component_id, self.component_name
        )
        sections: list[str] = []
        states = self._existing("states")
        if states:
            overview = "\n\n".join(
                render_component_state(path, self.component_id) for path in states
            )
            sections.append("===== \u8fd0\u884c\u6982\u89c8 =====\n" + overview)
        for path in self._existing("logs")[-8:]:
            if path.is_file():
                content = tail_text(path)
                sections.append(
                    f"===== \u5355\u5de5\u5177\u65e5\u5fd7\uff1a{path.name} =====\n{content}"
                )
        if states:
            sections.append(
                "\u539f\u59cb JSON \u5df2\u4ece\u4e3b\u89c6\u56fe\u9690\u85cf\u3002"
                "\u5982\u9700\u8c03\u8bd5\uff0c\u8bf7\u70b9\u51fb\u201c\u6253\u5f00\u539f\u59cb\u72b6\u6001\u201d\u3002"
            )
        if not sections:
            sections.append("\u8be5\u7ec4\u4ef6\u7684\u72b6\u6001\u6216\u65e5\u5fd7\u6587\u4ef6\u5c1a\u672a\u751f\u6210\u3002")
        return "\n\n".join(sections)

    def _refresh(self) -> None:
        if not self.winfo_exists():
            return
        status, stage, detail = component_display_runtime(
            self.run_dir, self.component_id
        )
        summary = f"{self.component_name}  |  {status or '等待状态文件'}"
        if stage:
            summary += f"  |  {stage}"
        if detail:
            summary += f"  |  {detail}"
        self.summary_var.set(summary)
        content = self._content()
        if content != self._last_content:
            follow, anchor = log_refresh_scroll_policy(
                self.text.yview(), self.follow_var.get()
            )
            self.text.configure(state="normal")
            self.text.delete("1.0", "end")
            self.text.insert("1.0", content)
            self.text.configure(state="disabled")
            self.text.update_idletasks()
            if follow:
                self.text.see("end")
            else:
                self.text.yview_moveto(anchor)
            self._last_content = content
        self._after_id = self.after(1000, self._refresh)

    def _pause_follow(self, _event: tk.Event | None = None) -> None:
        self.follow_var.set(False)

    def _scroll_to_end(self) -> None:
        self.follow_var.set(True)
        self.text.see("end")

    def _open_workdir(self) -> None:
        workdir = self.sources.get("workdir", self.run_dir)
        if isinstance(workdir, Path) and workdir.exists():
            os.startfile(workdir)

    def _open_log(self) -> None:
        logs = [path for path in self._existing("logs") if path.is_file()]
        if not logs:
            messagebox.showinfo("组件日志", "日志文件尚未生成。", parent=self)
            return
        os.startfile(logs[-1])

    def _open_state(self) -> None:
        states = [path for path in self._existing("states") if path.is_file()]
        if not states:
            messagebox.showinfo(
                "\u7ec4\u4ef6\u65e5\u5fd7",
                "\u539f\u59cb\u72b6\u6001\u6587\u4ef6\u5c1a\u672a\u751f\u6210\u3002",
                parent=self,
            )
            return
        os.startfile(states[-1])

    def _open_result(self) -> None:
        results = self._existing("results")
        if not results:
            messagebox.showinfo("组件日志", "结果尚未生成。", parent=self)
            return
        os.startfile(results[0])

    def _close(self) -> None:
        if self._after_id is not None:
            self.after_cancel(self._after_id)
        self.destroy()


class RunLogDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc, state: RunState) -> None:
        super().__init__(parent)
        self.run_dir = Path(state.run_dir)
        self.state_path = self.run_dir / "run.json"
        self._after_id: str | None = None
        self._last_log = ""

        self.title(f"项目日志 - {state.project_name} / {state.run_id}")
        self.geometry("1360x840")
        self.minsize(1050, 650)
        self.transient(parent)

        container = ttk.Frame(self, padding=16)
        container.pack(fill="both", expand=True)
        container.columnconfigure(0, weight=1)
        container.rowconfigure(1, weight=2)
        container.rowconfigure(4, weight=3)

        self.summary_var = tk.StringVar()
        ttk.Label(
            container,
            textvariable=self.summary_var,
            font=("Microsoft YaHei UI", 11, "bold"),
        ).grid(row=0, column=0, sticky="w", pady=(0, 10))

        tree_frame = ttk.Frame(container)
        tree_frame.grid(row=1, column=0, sticky="nsew", pady=(0, 12))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        columns = ("component", "status", "stage", "detail", "pid", "started")
        self.process_tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            height=10,
        )
        for column, label, width in (
            ("component", "组件", 180),
            ("status", "状态", 110),
            ("stage", "当前步骤", 190),
            ("detail", "状态详情（双击查看独立日志）", 500),
            ("pid", "PID", 85),
            ("started", "启动时间", 170),
        ):
            self.process_tree.heading(column, text=label)
            self.process_tree.column(column, width=width, minwidth=70)
        self.process_tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll = ttk.Scrollbar(
            tree_frame, orient="vertical", command=self.process_tree.yview
        )
        tree_scroll.grid(row=0, column=1, sticky="ns")
        self.process_tree.configure(yscrollcommand=tree_scroll.set)
        self.process_tree.bind("<Double-1>", self._open_component_log)
        self.process_tree.bind("<Return>", self._open_component_log)

        self.tool_activity_var = tk.StringVar()
        ttk.Label(
            container,
            textvariable=self.tool_activity_var,
            wraplength=1280,
            justify="left",
        ).grid(row=2, column=0, sticky="ew", pady=(0, 12))

        log_header = ttk.Frame(container)
        log_header.grid(row=3, column=0, sticky="ew", pady=(0, 6))
        ttk.Label(log_header, text="项目活动日志").pack(side="left")
        self.follow_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            log_header,
            text="跟随最新",
            variable=self.follow_var,
        ).pack(side="right")

        self.log_text = scrolledtext.ScrolledText(
            container,
            wrap="word",
            font=("Consolas", 10),
            state="disabled",
        )
        self.log_text.grid(row=4, column=0, sticky="nsew")
        self.log_text.bind("<MouseWheel>", self._pause_log_follow, add="+")
        self.log_text.bind("<Prior>", self._pause_log_follow, add="+")
        self.log_text.bind("<Next>", self._pause_log_follow, add="+")
        self.log_text.vbar.bind("<ButtonPress-1>", self._pause_log_follow, add="+")

        actions = ttk.Frame(container)
        actions.grid(row=5, column=0, sticky="ew", pady=(12, 0))
        ttk.Button(actions, text="打开运行目录", command=self._open_run_dir).pack(
            side="left"
        )
        ttk.Button(actions, text="打开日志文件", command=self._open_log_file).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(actions, text="回到底部", command=self._scroll_log_to_end).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(actions, text="关闭", command=self._close).pack(side="right")

        self.protocol("WM_DELETE_WINDOW", self._close)
        self._refresh()

    @staticmethod
    def _status_text(status: str) -> str:
        return {
            "starting": "启动中",
            "running": "运行中",
            "waiting_assets": "等待资产",
            "manual_required": "需手动处理",
            "completed": "已完成",
            "failed": "失败",
            "stopped": "已暂停",
            "exited": "已退出",
        }.get(status, status)

    def _load_state(self) -> RunState | None:
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
            return RunState.from_dict(value)
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            return None

    def _tool_activity(self) -> str:
        lines: list[str] = []
        for component_id, label in (
            ("asset_commander", "AssetCommander"),
            ("semantic_dirscan", "AI 路径发现"),
            ("tscan_plus", "TscanPlus"),
            ("project_coordinator", "自动调度与 AI 执行"),
            (AI_BATCH_COMPONENT_ID, AI_BATCH_COMPONENT_NAME),
        ):
            status, stage, detail = component_display_runtime(
                self.run_dir, component_id
            )
            if not any((status, stage, detail)):
                continue
            value = f"{label}：{status or 'unknown'}"
            if stage:
                value += f"，当前步骤：{stage}"
            if detail:
                value += f"，{detail}"
            lines.append(value)
        for name in (
            "fscan.txt",
            "nuclei.txt",
            "asset_commander_assets.json",
            "vulnerability_intel.json",
            "find_gh_poc.json",
        ):
            path = self.run_dir / "results" / name
            try:
                size = path.stat().st_size
            except OSError:
                continue
            lines.append(f"结果文件：{name}，{size} 字节")
        return "\n".join(lines) or "工具状态文件尚未生成。"

    def _refresh(self) -> None:
        if not self.winfo_exists():
            return
        state = self._load_state()
        if state is not None:
            self.summary_var.set(
                f"{state.project_name}  |  {state.run_id}  |  "
                f"{self._status_text(state.status)}"
            )
            selected = self.process_tree.selection()
            self.process_tree.delete(*self.process_tree.get_children())
            for process in state.processes:
                tool_status, stage, detail = component_display_runtime(
                    self.run_dir, process.component_id
                )
                status = tool_status or process.status
                self.process_tree.insert(
                    "",
                    "end",
                    iid=process.component_id,
                    values=(
                        process.name,
                        self._status_text(status),
                        stage,
                        detail,
                        process.pid,
                        process.started_at.replace("T", " ")[:19],
                    ),
                )
            process_ids = {process.component_id for process in state.processes}
            for component_id, component_name in COORDINATOR_MANAGED_COMPONENTS.items():
                if component_id not in state.selected_tools or component_id in process_ids:
                    continue
                status, stage, detail = component_display_runtime(
                    self.run_dir, component_id
                )
                self.process_tree.insert(
                    "",
                    "end",
                    iid=component_id,
                    values=(
                        component_name,
                        self._status_text(status),
                        stage,
                        detail,
                        "-",
                        "由自动调度器按资产更新轮次执行",
                    ),
                )
            if AI_BATCH_COMPONENT_ID not in process_ids:
                status, stage, detail = component_display_runtime(
                    self.run_dir, AI_BATCH_COMPONENT_ID
                )
                self.process_tree.insert(
                    "",
                    "end",
                    iid=AI_BATCH_COMPONENT_ID,
                    values=(
                        AI_BATCH_COMPONENT_NAME,
                        self._status_text(status),
                        stage,
                        detail,
                        "-",
                        "由自动调度器按资产更新轮次启动",
                    ),
                )
            for iid in selected:
                if self.process_tree.exists(iid):
                    self.process_tree.selection_add(iid)
        self.tool_activity_var.set(self._tool_activity())

        path = activity_log_path(self.run_dir)
        try:
            log = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            log = "活动日志尚未生成。\n"
        except OSError as exc:
            log = f"读取活动日志失败：{exc}\n"
        if log != self._last_log:
            follow, anchor = log_refresh_scroll_policy(
                self.log_text.yview(), self.follow_var.get()
            )
            self.log_text.configure(state="normal")
            self.log_text.delete("1.0", "end")
            self.log_text.insert("1.0", log)
            self.log_text.configure(state="disabled")
            self.log_text.update_idletasks()
            if follow:
                self.log_text.see("end")
            else:
                self.log_text.yview_moveto(anchor)
            self._last_log = log
        self._after_id = self.after(1000, self._refresh)

    def _pause_log_follow(self, _event: tk.Event | None = None) -> None:
        self.follow_var.set(False)

    def _scroll_log_to_end(self) -> None:
        self.follow_var.set(True)
        self.log_text.see("end")

    def _open_component_log(self, _event: tk.Event | None = None) -> None:
        selected = self.process_tree.selection()
        if not selected:
            return
        component_id = selected[0]
        values = self.process_tree.item(component_id, "values")
        component_name = str(values[0]) if values else component_id
        ComponentLogDialog(self, self.run_dir, component_id, component_name)

    def _open_run_dir(self) -> None:
        os.startfile(self.run_dir)

    def _open_log_file(self) -> None:
        path = activity_log_path(self.run_dir)
        if not path.is_file():
            messagebox.showinfo("项目日志", "活动日志文件尚未生成。", parent=self)
            return
        os.startfile(path)

    def _close(self) -> None:
        if self._after_id is not None:
            self.after_cancel(self._after_id)
            self._after_id = None
        self.destroy()
