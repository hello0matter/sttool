from __future__ import annotations

import argparse
import atexit
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import time

import psutil
from datetime import datetime
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from .activity import append_activity
from .agent_launcher import launch_agent_batch
from .agent_runtime import claim_coordinator_owner, release_coordinator_owner
from .asset_bus import (
    AssetBus,
    atomic_json_write,
    extract_tscan_assets,
    now_text,
    parse_asset_export,
    parse_dirsearch_output,
    parse_fscan_output,
    read_json,
    target_assets,
)
from .models import ProcessRecord
from .pentest_report import write_pentest_report
from .vulnerability_intel import generate_vulnerability_intel
from .workload_approval import (
    create_request,
    read_request,
    resolve_due_request,
    workload_counts,
    workload_total,
)
from .report_integrity import restore_corrupted_report_files
from .runtime import (
    CREATE_NEW_PROCESS_GROUP,
    CREATE_NO_WINDOW,
    pid_alive,
    process_creation_token,
    process_record_alive,
    terminate_agent_process_tree,
)


def file_marker(path: Path) -> tuple[int, int] | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    return stat.st_size, stat.st_mtime_ns


def selected_tools(run_dir: Path) -> set[str]:
    value = read_json(run_dir / "run.json")
    selected = value.get("selected_tools", [])
    return {str(item) for item in selected} if isinstance(selected, list) else set()


def asset_commander_ready(run_dir: Path) -> bool:
    state = read_json(run_dir / "tool_data" / "asset_commander" / "workflow_state.json")
    return str(state.get("status") or "").lower() == "completed"


def agent_launch_ready(
    *,
    active_pid: int,
    generation: int,
    consumed_generation: int,
    asset_ready: bool,
    fscan_ready: bool,
    quiet: bool,
    batch_count: int,
    max_batches: int,
    auto_agent: bool = True,
    retry_ready: bool = True,
) -> bool:
    return (
        auto_agent
        and retry_ready
        and active_pid <= 0
        and generation > consumed_generation
        and asset_ready
        and fscan_ready
        and quiet
        and batch_count < max(max_batches, 1)
    )


def coordinator_wait_stage(
    *,
    active_pid: int,
    generation: int,
    consumed_generation: int,
    asset_ready: bool,
    fscan_ready: bool,
    quiet: bool,
    batch_count: int,
    max_batches: int,
    auto_agent: bool = True,
    retry_ready: bool = True,
    retry_seconds: int = 0,
) -> tuple[str, str]:
    if active_pid > 0:
        return "agent_running", f"AI 进程 PID {active_pid} 正在处理当前资产"
    if not auto_agent:
        return "manual_agent", "自动 AI 执行已关闭；资产与摘要仍会持续更新"
    if not retry_ready:
        return "agent_backoff", f"AI 启动失败，等待 {max(retry_seconds, 1)} 秒后自动重试"
    if not asset_ready:
        return "waiting_asset_commander", "等待 AssetCommander 完成资产收集与碰撞"
    if not fscan_ready:
        return "waiting_fscan", "等待 fscan 执行结束并保存完整输出"
    if not quiet:
        return "settling_assets", "资产仍在增长，等待稳定后再启动 AI"
    if batch_count >= max(max_batches, 1):
        return "batch_limit_reached", "AI 执行次数已达上限，保留新增资产供人工处理"
    if generation <= consumed_generation:
        return "waiting_new_assets", "当前资产已全部处理，等待工具回传新资产"
    return "ready_for_agent", "资产已稳定，准备启动下一次 AI 执行"


def mark_agent_batch_finished(
    run_dir: Path, batches: list[object], pid: int
) -> dict[str, object] | None:
    completed_at = now_text()
    for item in reversed(batches):
        if not isinstance(item, dict) or int(item.get("pid") or 0) != pid:
            continue
        batch_dir = Path(str(item.get("run_dir") or ""))
        terminal_state = agent_batch_terminal_state(batch_dir)
        exit_state = read_json(batch_dir / "agent_exit.json")
        has_exit_state = bool(exit_state)
        if terminal_state:
            status = str(terminal_state["status"])
            completed_at = str(terminal_state.get("completed_at") or completed_at)
            default_exit_code = 0 if status == "completed" else 1
            try:
                exit_code = int(terminal_state.get("exit_code", default_exit_code))
            except (TypeError, ValueError):
                exit_code = default_exit_code
        else:
            try:
                exit_code = int(exit_state.get("exit_code") or 0)
            except (TypeError, ValueError):
                exit_code = 1
            status = "failed" if has_exit_state and exit_code != 0 else "completed"
        item.update(status=status, completed_at=completed_at, exit_code=exit_code)
        error = str(
            (terminal_state or {}).get("error") or exit_state.get("error") or ""
        ).strip()
        if error:
            item["error"] = error
        metadata_path = batch_dir / "batch.json"
        metadata = read_json(metadata_path)
        if metadata:
            metadata.update(
                status=status,
                completed_at=completed_at,
                exit_code=exit_code,
            )
            if error:
                metadata["error"] = error
            atomic_json_write(metadata_path, metadata)
        integrity = restore_corrupted_report_files(run_dir, batch_dir)
        if integrity.get("status") != "not_available":
            item["report_integrity"] = integrity
        return item
    return None


def agent_batch_terminal_state(batch_dir: Path) -> dict[str, object] | None:
    """Return a trusted terminal marker written by an AI batch."""
    value = read_json(batch_dir / "batch_status.json")
    if str(value.get("status") or "").lower() not in {"completed", "failed"}:
        return None
    return value


def agent_batch_last_activity(batch_dir: Path) -> float | None:
    """Return the newest batch-file timestamp used for stall observation."""
    try:
        timestamps = [item.stat().st_mtime for item in batch_dir.iterdir() if item.is_file()]
    except OSError:
        return None
    return max(timestamps, default=None)


def agent_batch_health(
    batch_dir: Path, warn_minutes: int, now: float | None = None
) -> tuple[str, float | None, str]:
    if warn_minutes <= 0:
        return "disabled", None, ""
    last_activity = agent_batch_last_activity(batch_dir)
    if last_activity is None:
        return "unknown", None, ""
    elapsed_minutes = max((now or time.time()) - last_activity, 0) / 60
    status = "suspected_stalled" if elapsed_minutes >= warn_minutes else "active"
    activity_text = datetime.fromtimestamp(last_activity).astimezone().isoformat(
        timespec="seconds"
    )
    return status, elapsed_minutes, activity_text


def codex_session_candidates(
    run_dir: Path,
    batch_dir: Path,
    session_root: Path | None = None,
) -> list[tuple[float, Path]]:
    """Return recent Codex sessions whose working directory matches this run."""
    root = session_root or Path.home() / ".codex" / "sessions"
    if not root.is_dir():
        return []
    try:
        started_at = (batch_dir / "prompt.txt").stat().st_mtime
    except OSError:
        return []

    candidates: list[tuple[float, Path]] = []
    try:
        paths = root.rglob("*.jsonl")
        expected_cwd = os.path.normcase(str(run_dir.resolve()))
        for path in paths:
            try:
                modified_at = path.stat().st_mtime
            except OSError:
                continue
            if modified_at < started_at:
                continue
            session_cwd = ""
            try:
                with path.open(encoding="utf-8", errors="replace") as handle:
                    for index, line in enumerate(handle):
                        if index >= 10:
                            break
                        try:
                            event = json.loads(line)
                        except (TypeError, ValueError, json.JSONDecodeError):
                            continue
                        if str(event.get("type") or "") != "session_meta":
                            continue
                        payload = event.get("payload")
                        if isinstance(payload, dict):
                            session_cwd = str(payload.get("cwd") or "")
                        break
            except OSError:
                continue
            try:
                normalized_session_cwd = os.path.normcase(
                    str(Path(session_cwd).resolve())
                )
            except (OSError, ValueError):
                continue
            if normalized_session_cwd == expected_cwd:
                candidates.append((modified_at, path))
    except OSError:
        return []
    return sorted(candidates, reverse=True)


def codex_session_last_activity(
    run_dir: Path,
    batch_dir: Path,
    session_root: Path | None = None,
) -> tuple[float, Path] | None:
    candidates = codex_session_candidates(run_dir, batch_dir, session_root)
    return candidates[0] if candidates else None


def codex_session_terminal_state(
    run_dir: Path,
    batch_dir: Path,
    session_root: Path | None = None,
) -> dict[str, object] | None:
    """Recover a completed Codex turn whose CLI wrapper did not exit."""
    for _modified_at, path in codex_session_candidates(
        run_dir, batch_dir, session_root
    ):
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = content.splitlines()
        previous_event = ""
        previous_error = ""
        for line in lines:
            try:
                event = json.loads(line)
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            payload = event.get("payload")
            if not isinstance(payload, dict):
                continue
            event_type = str(payload.get("type") or "")
            if event_type == "task_complete":
                status = "failed" if previous_event == "error" else "completed"
                result: dict[str, object] = {
                    "status": status,
                    "completed_at": str(event.get("timestamp") or now_text()),
                    "exit_code": 1 if status == "failed" else 0,
                    "source": "codex_session",
                }
                if status == "failed":
                    match = re.search(
                        r"(?i)(?:status\s+)?(\d{3}\s+[^,\n]{1,80})",
                        previous_error,
                    )
                    result["error"] = (
                        f"Codex provider error: {match.group(1)}"
                        if match
                        else "Codex provider request failed"
                    )
                return result
            if event_type in {"token_count", "agent_reasoning"}:
                continue
            previous_event = event_type
            if event_type == "error":
                previous_error = str(
                    payload.get("message") or payload.get("error") or ""
                )
    return None


def schedule_agent_retry(state: dict[str, object], reason: str) -> int:
    failure_count = int(state.get("agent_failure_count") or 0) + 1
    delays = (60, 300, 900)
    delay = delays[min(failure_count - 1, len(delays) - 1)]
    state.update(
        agent_failure_count=failure_count,
        agent_retry_not_before=time.time() + delay,
        agent_last_failure=reason,
    )
    return delay


def clear_agent_retry(state: dict[str, object]) -> None:
    state["agent_failure_count"] = 0
    state["agent_retry_not_before"] = 0
    state.pop("agent_last_failure", None)
    state.pop("agent_launch_error", None)


def component_process_alive(run_dir: Path, component_id: str) -> bool:
    value = read_json(run_dir / "run.json")
    processes = value.get("processes", [])
    if not isinstance(processes, list):
        return False
    for item in reversed(processes):
        if not isinstance(item, dict) or item.get("component_id") != component_id:
            continue
        try:
            record = ProcessRecord.from_dict(item)
        except (TypeError, ValueError):
            return False
        return process_record_alive(record, run_dir)
    return False


def tracked_process_alive(pid: int, creation_token: int, run_dir: Path) -> bool:
    if not pid_alive(pid):
        return False
    if creation_token:
        return process_creation_token(pid) == creation_token
    legacy = ProcessRecord(
        component_id="agent_batch",
        name="AI execution",
        pid=pid,
        command=[],
        cwd=str(run_dir),
        started_at="",
    )
    return process_record_alive(legacy, run_dir)


def remember_agent_process_tree(batch: dict[str, object], root_pid: int) -> None:
    """Persist verified descendants so they can be reclaimed after the wrapper exits."""
    if root_pid <= 0 or not pid_alive(root_pid):
        return
    try:
        processes = [psutil.Process(root_pid), *psutil.Process(root_pid).children(recursive=True)]
    except (psutil.Error, OSError, ValueError):
        return
    remembered = batch.get("owned_processes")
    by_pid: dict[int, dict[str, int]] = {}
    if isinstance(remembered, list):
        for item in remembered:
            if not isinstance(item, dict):
                continue
            try:
                pid = int(item.get("pid") or 0)
                creation_token = int(item.get("creation_token") or 0)
            except (TypeError, ValueError):
                continue
            if pid > 0 and creation_token > 0:
                by_pid[pid] = {"pid": pid, "creation_token": creation_token}
    for process in processes:
        try:
            pid = int(process.pid)
            creation_token = int(process.create_time() * 1_000_000)
        except (psutil.Error, OSError, ValueError):
            continue
        by_pid[pid] = {"pid": pid, "creation_token": creation_token}
    batch["owned_processes"] = list(by_pid.values())


def terminate_remembered_agent_processes(
    batch: dict[str, object] | None, run_dir: Path
) -> None:
    """Terminate only processes whose PID and creation time match this AI batch."""
    if not batch:
        return
    remembered = batch.get("owned_processes")
    if not isinstance(remembered, list):
        return
    for item in reversed(remembered):
        if not isinstance(item, dict):
            continue
        try:
            pid = int(item.get("pid") or 0)
            creation_token = int(item.get("creation_token") or 0)
        except (TypeError, ValueError):
            continue
        if tracked_process_alive(pid, creation_token, run_dir):
            terminate_agent_process_tree(pid)


def completed_batch_orphan_processes(
    batch: dict[str, object], run_dir: Path
) -> list[dict[str, int]]:
    """Find a completed batch's AI CLI after its PowerShell wrapper has exited."""
    if str(batch.get("status") or "").lower() not in {"completed", "failed"}:
        return []
    batch_dir = Path(str(batch.get("run_dir") or ""))
    prompt_path = batch_dir / "prompt.txt"
    metadata = read_json(batch_dir / "batch.json")
    provider = str(
        metadata.get("provider") or batch.get("provider") or ""
    ).lower()
    if provider not in {"codex", "codexx", "claude"} or not prompt_path.is_file():
        return []
    started_at = str(metadata.get("started_at") or batch.get("started_at") or "")
    completed_at = str(
        metadata.get("completed_at") or batch.get("completed_at") or ""
    )
    try:
        started_timestamp = datetime.fromisoformat(
            started_at.replace("Z", "+00:00")
        ).timestamp()
        completed_timestamp = datetime.fromisoformat(
            completed_at.replace("Z", "+00:00")
        ).timestamp()
    except ValueError:
        return []
    if completed_timestamp < started_timestamp:
        return []
    expected_prompts = {
        os.path.normcase(str(prompt_path.absolute())),
        os.path.normcase(str(prompt_path.resolve())),
    }
    expected_run_dir = os.path.normcase(str(run_dir.resolve()))
    matches: list[dict[str, int]] = []
    for process in psutil.process_iter(["pid", "name", "cmdline", "create_time"]):
        try:
            name = Path(str(process.info.get("name") or "")).stem.lower()
            if name != provider:
                continue
            cmdline = [str(item) for item in process.info.get("cmdline") or []]
            command_text = os.path.normcase(" ".join(cmdline))
            if not any(expected in command_text for expected in expected_prompts):
                continue
            cwd = os.path.normcase(str(Path(process.cwd()).resolve()))
            if cwd != expected_run_dir:
                continue
            create_time = float(process.info["create_time"])
            if not started_timestamp - 120 <= create_time <= completed_timestamp + 60:
                continue
            creation_token = int(create_time * 1_000_000)
            matches.append(
                {
                    "pid": int(process.info["pid"]),
                    "creation_token": creation_token,
                }
            )
        except (KeyError, TypeError, ValueError, OSError, psutil.Error):
            continue
    return matches


def recover_completed_batch_orphans(
    batches: list[object], run_dir: Path
) -> list[int]:
    """Reclaim strictly matched AI CLIs left by already completed batches."""
    recovered: list[int] = []
    for item in batches:
        if not isinstance(item, dict):
            continue
        matches = completed_batch_orphan_processes(item, run_dir)
        for process in matches:
            pid = process["pid"]
            if tracked_process_alive(pid, process["creation_token"], run_dir):
                terminate_agent_process_tree(pid)
                recovered.append(pid)
        if matches:
            remembered = item.setdefault("owned_processes", [])
            if isinstance(remembered, list):
                known = {
                    int(entry.get("pid") or 0)
                    for entry in remembered
                    if isinstance(entry, dict)
                }
                remembered.extend(
                    match for match in matches if match["pid"] not in known
                )
    return recovered


def incremental_fscan_candidates(
    bus: AssetBus, attempted_ips: list[object]
) -> list[str]:
    attempted = {str(item) for item in attempted_ips}
    candidates: list[str] = []
    for value in bus.bundle().get("ips", []):
        try:
            normalized = ipaddress.ip_address(value).compressed
        except ValueError:
            continue
        if normalized not in attempted:
            candidates.append(normalized)
    return list(dict.fromkeys(candidates))


def build_incremental_fscan_command(
    executable: Path, target_file: Path, output_file: Path, port_threads: int
) -> list[str]:
    return [
        str(executable),
        "-hf",
        str(target_file),
        "-t",
        str(max(port_threads, 1)),
        "-nobr",
        "-nopoc",
        "-o",
        str(output_file),
    ]


def launch_incremental_fscan(
    *,
    executable: Path,
    run_dir: Path,
    batch_number: int,
    targets: list[str],
    port_threads: int,
) -> dict[str, object]:
    batch_dir = (
        run_dir / "tool_data" / "fscan_incremental" / f"batch-{batch_number:04d}"
    )
    batch_dir.mkdir(parents=True, exist_ok=True)
    target_file = batch_dir / "targets.txt"
    output_file = batch_dir / "result.txt"
    log_file = batch_dir / "process.log"
    target_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
    command = build_incremental_fscan_command(
        executable, target_file, output_file, port_threads
    )
    with log_file.open("ab") as output:
        process = subprocess.Popen(
            command,
            cwd=str(run_dir),
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            creationflags=CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
            close_fds=True,
        )
    return {
        "batch": batch_number,
        "pid": process.pid,
        "creation_token": process_creation_token(process.pid),
        "targets": targets,
        "target_file": str(target_file),
        "output_file": str(output_file),
        "log_file": str(log_file),
        "command": command,
        "status": "running",
        "started_at": now_text(),
    }


def asset_commander_collision_paths(run_dir: Path) -> tuple[list[Path], list[Path]]:
    workspace = run_dir / "tool_data" / "asset_commander" / "workspace"
    if not workspace.is_dir():
        return [], []
    result_files = sorted(workspace.glob("*/results.csv"))
    evidence_dirs = sorted(
        path for path in workspace.glob("*/evidence") if path.is_dir()
    )
    return result_files, evidence_dirs


def semantic_assets(path: Path) -> list[tuple[str, str]]:
    value = read_json(path)
    targets = value.get("targets", [])
    if not isinstance(targets, list):
        return []
    return [(str(item), "url") for item in targets]


def semantic_dirsearch_output_files(semantic_state: Path) -> list[Path]:
    projects_dir = semantic_state.parent / "projects"
    if not projects_dir.is_dir():
        return []
    return sorted(projects_dir.glob("*/runs/*/dirsearch.txt"))


def semantic_dirsearch_marker(
    run_dir: Path, paths: list[Path]
) -> list[list[object]]:
    result: list[list[object]] = []
    for path in paths:
        marker = file_marker(path)
        if marker is None:
            continue
        try:
            rendered_path = path.relative_to(run_dir).as_posix()
        except ValueError:
            rendered_path = str(path)
        result.append([rendered_path, marker[0], marker[1]])
    return result


def semantic_dirsearch_output_active(paths: list[Path]) -> bool:
    targets = {os.path.normcase(os.path.normpath(str(path))) for path in paths}
    if not targets:
        return False
    for process in psutil.process_iter(["name", "cmdline"]):
        try:
            arguments = [
                os.path.normcase(os.path.normpath(str(value).strip('"')))
                for value in process.info.get("cmdline") or []
            ]
        except (psutil.Error, OSError, ValueError):
            continue
        if not any("dirsearch" in value.lower() for value in arguments):
            continue
        if any(value in targets for value in arguments):
            return True
    return False


def tscan_findings(database: Path) -> list[dict[str, str]]:
    if not database.is_file():
        return []
    findings: list[dict[str, str]] = []
    try:
        connection = sqlite3.connect(
            f"file:{database.as_posix()}?mode=ro", uri=True, timeout=1
        )
    except sqlite3.Error:
        return findings
    try:
        tables = {
            str(row[0])
            for row in connection.execute(
                "select name from sqlite_master where type='table'"
            )
        }
        for table in (
            "poccheck",
            "unauth",
            "pwdcrack",
            "dirscan",
            "swagger",
            "awvs",
            "nessus",
        ):
            if table not in tables:
                continue
            columns = [
                str(row[1])
                for row in connection.execute(f'pragma table_info("{table}")')
            ]
            lowered = {name.lower(): name for name in columns}
            candidate_keys = (
                ("target", "host", "pocvul", "title", "statuscode", "status")
                if table == "poccheck"
                else (
                    "target",
                    "url",
                    "host",
                    "vuln",
                    "pocvul",
                    "message",
                    "title",
                    "statuscode",
                    "status",
                )
            )
            candidates = [
                lowered[key]
                for key in candidate_keys
                if key in lowered
            ]
            if not candidates:
                continue
            selected = list(dict.fromkeys(candidates))
            selected_sql = ", ".join(f'"{name}"' for name in selected)
            try:
                rows = connection.execute(
                    f'SELECT {selected_sql} FROM "{table}" ORDER BY rowid DESC LIMIT 100'
                )
                for row in rows:
                    value = {
                        selected[index]: str(item or "")
                        for index, item in enumerate(row)
                    }
                    rendered = " | ".join(
                        item for item in value.values() if item.strip()
                    )
                    if rendered:
                        findings.append(
                            {"source": f"tscan:{table}", "detail": rendered}
                        )
            except sqlite3.Error:
                continue
    finally:
        connection.close()
    return findings


def render_risk_summary(
    run_dir: Path,
    bus: AssetBus,
    database: Path,
    stage: str,
) -> str:
    bundle = bus.bundle()
    records = [item for item in bus.value.get("assets", []) if isinstance(item, dict)]
    sources = {
        str(item.get("value")): ", ".join(
            str(value) for value in item.get("sources", [])
        )
        for item in records
    }
    findings = tscan_findings(database)
    collision_results, collision_evidence = asset_commander_collision_paths(run_dir)
    lines = [
        "# 项目风险成果摘要",
        "",
        f"- 生成时间：{now_text()}",
        f"- 阶段：{stage}",
        f"- 资产更新轮次：{bus.generation}",
        f"- Web URL：{len(bundle['urls'])}",
        f"- IP：{len(bundle['ips'])}",
        f"- 域名：{len(bundle['domains'])}",
        f"- 端点：{len(bundle['endpoints'])}",
        f"- 待用户确认的新资产：{bus.pending_count}",
        "",
        "## Web 目标（必须逐个检查）",
        "",
    ]
    lines.extend(
        f"- `{url}`（来源：{sources.get(url, 'unknown')}）" for url in bundle["urls"]
    )
    if not bundle["urls"]:
        lines.append("- 暂无")
    lines.extend(["", "## 非 Web 服务与端点", ""])
    lines.extend(f"- `{value}`" for value in [*bundle["ips"], *bundle["endpoints"]])
    if not bundle["ips"] and not bundle["endpoints"]:
        lines.append("- 暂无")
    lines.extend(
        [
            "",
            "## 工具风险线索（全部待验证）",
            "",
            "以下内容是工具原始标签，不代表已确认漏洞；风险等级、命中状态和模板名称均需人工复核。",
            "",
        ]
    )
    lines.extend(
        f"- **待验证自动线索 {item['source']}**：工具原始标签（未确认）：{item['detail']}"
        for item in findings
    )
    if not findings:
        lines.append("- 当前尚无已结构化的漏洞结果；版本或开放服务只能作为待验证线索。")
    lines.extend(["", "## Host/SNI 碰撞证据", ""])
    if collision_results:
        lines.extend(f"- 碰撞结果：`{path}`" for path in collision_results)
        lines.extend(f"- 原始请求/响应：`{path}`" for path in collision_evidence)
        lines.append(
            "- 复核时必须保留实际连接 IP/端口、HTTP Host、TLS SNI 和请求模式，"
            "不能把碰撞结果简化成普通 URL。"
        )
    else:
        lines.append("- 当前尚未生成 AssetCommander Host/SNI 碰撞结果。")
    lines.extend(
        [
            "",
            "## 说明",
            "",
            "本文件只汇总风险点、资产与证据线索，不套用固定渗透测试报告格式。",
            "未完成安全验证的内容不能标记为已确认漏洞。",
            "",
        ]
    )
    return "\n".join(lines)


def write_project_reports(
    *,
    run_dir: Path,
    bus: AssetBus,
    database: Path,
    stage: str,
    project_name: str,
    target: str,
    scope: str,
) -> str:
    summary = render_risk_summary(run_dir, bus, database, stage)
    (run_dir / "risk_summary.md").write_text(summary, encoding="utf-8")
    write_pentest_report(
        run_dir=run_dir,
        bus=bus,
        stage=stage,
        project_name=project_name,
        target=target,
        scope=scope,
        tscan_findings=tscan_findings(database),
    )
    return summary


def response_text(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    output_text = value.get("output_text")
    if isinstance(output_text, str) and output_text.strip():
        return output_text.strip()
    choices = value.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            message = first.get("message")
            if isinstance(message, dict):
                content = message.get("content")
                if isinstance(content, str) and content.strip():
                    return content.strip()
    output = value.get("output")
    if isinstance(output, list):
        chunks: list[str] = []
        for item in output:
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            if not isinstance(content, list):
                continue
            for part in content:
                if not isinstance(part, dict):
                    continue
                text = part.get("text")
                if isinstance(text, str) and text.strip():
                    chunks.append(text.strip())
        return "\n".join(chunks)
    return ""


AI_SUMMARY_INPUT_MAX_CHARS = 48_000
AI_SUMMARY_TIMEOUT_SECONDS = 20


def compact_ai_summary_input(
    summary: str, max_chars: int = AI_SUMMARY_INPUT_MAX_CHARS
) -> str:
    if len(summary) <= max_chars:
        return summary
    separator = (
        "\n\n[... full local summary retained; middle omitted from AI input ...]\n\n"
    )
    content_budget = max_chars - len(separator)
    if content_budget <= 0:
        return summary[:max_chars]
    head_size = content_budget * 2 // 3
    tail_size = content_budget - head_size
    return summary[:head_size] + separator + summary[-tail_size:]


def ai_enhance_summary(summary: str) -> tuple[str, str]:
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    base_url = os.environ.get("OPENAI_BASE_URL", "").strip().rstrip("/")
    model = os.environ.get("OPENAI_MODEL", "").strip()
    if not api_key or not base_url or not model:
        return summary, "项目 AI 未完整配置，已生成本地结构化摘要"
    if base_url.endswith("/responses"):
        root = base_url[: -len("/responses")]
    elif base_url.endswith("/chat/completions"):
        root = base_url[: -len("/chat/completions")]
    else:
        root = base_url
    system_prompt = (
        "你是授权安全测试项目的风险摘要助手。"
        "只归纳已有证据，不夸大，不生成固定报告模板。"
    )
    user_prompt = (
        "请基于下面的阶段性摘要生成简洁的风险分析补充。原始完整摘要会单独保留，"
        "不要重复资产清单，不要把待验证线索写成已确认漏洞：\n\n"
        + compact_ai_summary_input(summary)
    )
    attempts = (
        (
            f"{root}/responses",
            {
                "model": model,
                "instructions": system_prompt,
                "input": user_prompt,
            },
        ),
        (
            f"{root}/chat/completions",
            {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.1,
            },
        ),
    )
    errors: list[str] = []
    for endpoint, body in attempts:
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        request = Request(
            endpoint,
            data=payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=AI_SUMMARY_TIMEOUT_SECONDS) as response:
                value = json.loads(response.read().decode("utf-8"))
            content = response_text(value)
            if content:
                return (
                    summary.rstrip()
                    + "\n\n## 工具协作 AI 阶段分析\n\n"
                    + content.strip()
                    + "\n",
                    "项目 AI 已追加阶段性风险分析",
                )
            errors.append(f"{Path(endpoint).name}:empty")
        except (OSError, URLError, ValueError, KeyError, IndexError, TypeError) as exc:
            errors.append(f"{Path(endpoint).name}:{type(exc).__name__}")
    detail = ",".join(errors)
    return summary, f"项目 AI 摘要调用失败，保留本地摘要：{detail}"


def build_batch_prompt(
    run_dir: Path,
    base_prompt: str,
    bus: AssetBus,
    after_generation: int,
    batch_number: int,
) -> str:
    delta = bus.bundle(after_generation)
    all_assets = bus.bundle()
    urls = delta["urls"] if after_generation else all_assets["urls"]
    endpoints = delta["endpoints"] if after_generation else all_assets["endpoints"]
    collision_results, collision_evidence = asset_commander_collision_paths(run_dir)
    pending_rows = [
        item for item in bus.value.get("pending", []) if isinstance(item, dict)
    ]
    pending_text = (
        "\n".join(
            f"- {item.get('value')}（来源：{item.get('source')}；原因：{item.get('reason')}）"
            for item in pending_rows[:100]
        )
        or "- 当前没有待确认资产"
    )
    collision_result_text = (
        "\n".join(str(path) for path in collision_results) or "尚未生成"
    )
    collision_evidence_text = (
        "\n".join(str(path) for path in collision_evidence) or "尚未生成"
    )
    label = "新增资产增量复测" if after_generation else "资产收集稳定后的首次全量测试"
    return (
        base_prompt.rstrip()
        + "\n\n"
        + f"## STTool AI 执行记录 {batch_number}：{label}\n\n"
        + f"资产汇总队列文件：{run_dir / 'tool_data' / 'asset_bus' / 'assets.json'}\n"
        + f"fscan 完整输出：{run_dir / 'results' / 'fscan.txt'}\n"
        + f"项目风险摘要：{run_dir / 'risk_summary.md'}\n"
        + f"漏洞情报与 PoC 候选：{run_dir / 'vulnerability_intel.md'}\n"
        + f"结构化漏洞情报：{run_dir / 'results' / 'vulnerability_intel.json'}\n\n"
        + f"AssetCommander Host/SNI 碰撞结果：\n{collision_result_text}\n"
        + f"AssetCommander 原始请求/响应证据目录：\n{collision_evidence_text}\n\n"
        + "必须先完整读取 fscan 输出和漏洞情报，逐个检查下列 Web URL，不能只检查项目主 URL。"
        + "对每个 URL 分别记录页面取证、产品/版本、候选 CVE、验证状态和证据路径。"
        + "对 AssetCommander 碰撞结果必须按实际连接 IP/端口、Host 请求头、TLS SNI、请求模式"
        + "和原始请求/响应成组复核；不能脱离 Host/SNI 上下文直接访问裸 IP 后下结论。"
        + "PoC 链接只是不可信候选，不得直接下载执行；必须先核对厂商公告、受影响版本、前置条件和模板副作用，"
        + "优先使用已审查的 verified Nuclei 模板或无害请求。"
        + "禁止自动写文件、创建账号、反弹 Shell、抓取凭据、持久化和横向移动。\n"
        + "\u6240\u6709 Markdown\u3001JSON\u3001\u65e5\u5fd7\u548c\u8bc1\u636e\u7d22\u5f15\u5fc5\u987b\u4f7f\u7528 UTF-8 \u5199\u5165\uff1b\u4e0d\u8981\u901a\u8fc7\u7cfb\u7edf\u9ed8\u8ba4\u4ee3\u7801\u9875\u5199\u4e2d\u6587\u3002\n"
        + "PowerShell \u5199\u6587\u4ef6\u5fc5\u987b\u663e\u5f0f\u6307\u5b9a UTF-8\uff1b\u4f18\u5148\u4f7f\u7528 Python pathlib.write_text(encoding=\"utf-8\")\u3002\n"
        + "\u4e0d\u8981\u628a\u7ec8\u7aef\u989c\u8272\u63a7\u5236\u7801\u5199\u5165\u62a5\u544a\uff1b\u9519\u8bef\u4fe1\u606f\u9700\u5148\u53bb\u9664 ANSI \u63a7\u5236\u5e8f\u5217\u3002\n"
        + "下面的待确认资产尚未获得准入，不得测试，也不得自行扩大授权范围：\n"
        + pending_text
        + "\n\n### 本批次 Web URL\n"
        + ("\n".join(f"- {value}" for value in urls) or "- 本批次没有新增 Web URL")
        + "\n\n### 本批次非 Web 端点\n"
        + ("\n".join(f"- {value}" for value in endpoints) or "- 本批次没有新增端点")
        + "\n\n后续若工具发现新资产，只处理 AI 尚未处理的新增内容，不要重复启动相同高并发任务。\n"
    )


def agent_workload_gate(
    run_dir: Path,
    state: dict[str, object],
    bus: AssetBus,
    *,
    consumed_generation: int,
    mode: str,
    countdown_seconds: int,
    threshold: int,
    project_name: str,
    run_id: str,
) -> str:
    counts = workload_counts(bus.value, consumed_generation)
    total = workload_total(counts)
    if mode == "automatic" or total < max(threshold, 1):
        state.pop("workload_approval", None)
        return "accepted"
    request = read_request(run_dir)
    same_batch = (
        request
        and int(request.get("generation_from") or 0) == consumed_generation + 1
        and int(request.get("generation_to") or 0) == bus.generation
    )
    if not same_batch or request.get("status") not in {"pending", "decided"}:
        request = create_request(
            run_dir,
            project_name=project_name,
            run_id=run_id,
            generation_from=consumed_generation + 1,
            generation_to=bus.generation,
            counts=counts,
            mode=mode,
            countdown_seconds=countdown_seconds,
        )
        append_activity(
            run_dir,
            f"\u5927\u6279\u91cf Agent \u51c6\u5165\u63d0\u9192\uff1a\u672c\u6279\u9884\u8ba1\u5904\u7406 {total} \u6761\u8d44\u4ea7\uff0c\u5df2\u521b\u5efa\u786e\u8ba4\u8bf7\u6c42\u3002",
        )
    request = resolve_due_request(run_dir)
    state["workload_approval"] = request
    if request.get("status") in {"pending", ""}:
        return "pending"
    if request.get("decision") == "accept":
        return "accepted"
    state["agent_consumed_generation"] = bus.generation
    append_activity(run_dir, "\u7528\u6237\u9009\u62e9\u8df3\u8fc7\u672c\u6279 Agent\uff1b\u672c\u6279\u8d44\u4ea7\u6807\u8bb0\u4e3a\u5df2\u6d88\u8d39\uff0c\u4e0d\u91cd\u590d\u5f39\u7a97\u3002")
    return "rejected"


def parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise argparse.ArgumentTypeError("expected true or false")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="STTool project asset queue and delayed AI scheduler"
    )
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--scope", default="*")
    parser.add_argument("--project", required=True)
    parser.add_argument(
        "--provider", choices=("codex", "codexx", "claude"), required=True
    )
    parser.add_argument("--agent-model", default="")
    parser.add_argument(
        "--reasoning-effort",
        choices=("", "low", "medium", "high", "xhigh"),
        default="",
    )
    parser.add_argument("--agent-base-url", default="")
    parser.add_argument("--settle-seconds", type=float, default=20)
    parser.add_argument("--max-agent-batches", type=int, default=8)
    parser.add_argument("--poll-seconds", type=float, default=2)
    parser.add_argument("--agent-stall-warn-minutes", type=int, default=15)
    parser.add_argument("--auto-agent", type=parse_bool, default=True)
    parser.add_argument("--wait-asset-commander", type=parse_bool, default=True)
    parser.add_argument("--wait-fscan", type=parse_bool, default=True)
    parser.add_argument("--ai-summary", type=parse_bool, default=True)
    parser.add_argument("--vulnx", type=Path, default=None)
    parser.add_argument("--find-gh-poc", type=Path, default=None)
    parser.add_argument("--fscan-exe", type=Path, default=None)
    parser.add_argument("--fscan-port-threads", type=int, default=600)
    parser.add_argument("--allow-cidr-expansion", type=parse_bool, default=False)
    parser.add_argument(
        "--new-asset-approval-mode",
        choices=("automatic", "countdown_accept", "countdown_reject", "manual"),
        default="countdown_accept",
    )
    parser.add_argument("--new-asset-countdown-seconds", type=int, default=10)
    parser.add_argument(
        "--workload-approval-mode",
        choices=("automatic", "countdown_accept", "countdown_reject", "manual"),
        default="countdown_accept",
    )
    parser.add_argument("--workload-countdown-seconds", type=int, default=10)
    parser.add_argument("--workload-agent-threshold", type=int, default=50)
    parser.add_argument("--workload-popup-enabled", type=parse_bool, default=True)
    parser.add_argument("--workload-popup-topmost", type=parse_bool, default=True)
    parser.add_argument("--terminal-window", default="")
    return parser.parse_args()


def tscan_source_ready(database: Path) -> bool:
    return (
        database.is_file() and (database.parents[1] / ".sttool_initialized").is_file()
    )


def main() -> int:
    args = parse_args()
    run_dir = args.run_dir.resolve()
    bus_path = run_dir / "tool_data" / "asset_bus" / "assets.json"
    decisions_path = run_dir / "tool_data" / "asset_bus" / "decisions.json"
    state_path = run_dir / "tool_data" / "coordinator" / "state.json"
    asset_export = run_dir / "results" / "asset_commander_assets.json"
    fscan_path = run_dir / "results" / "fscan.txt"
    semantic_state = run_dir / "tool_data" / "semantic" / "sttool_bridge_state.json"
    tscan_database = run_dir / "tool_data" / "tscan" / "app" / "config" / "config.db"
    owner_path = state_path.parent / "owner.json"
    owner = claim_coordinator_owner(owner_path, run_dir)
    if owner is None:
        append_activity(run_dir, "检测到同一运行实例已有自动调度器，本次重复启动已退出。")
        return 0
    atexit.register(release_coordinator_owner, owner_path, owner)
    bus = AssetBus(
        bus_path,
        args.scope,
        args.target,
        approval_mode=args.new_asset_approval_mode,
        approval_seconds=args.new_asset_countdown_seconds,
        allow_cidr_expansion=args.allow_cidr_expansion,
    )
    state = read_json(state_path)
    state.setdefault("schema_version", 1)
    state.setdefault("created_at", now_text())
    state.setdefault("source_markers", {})
    state.setdefault("agent_batches", [])
    state.setdefault("agent_consumed_generation", 0)
    state.setdefault("active_agent_pid", 0)
    state.setdefault("active_agent_creation_token", 0)
    state.setdefault("agent_stall_status", "disabled")
    state.setdefault("vuln_intel_generation", 0)
    state.setdefault("vuln_intel_status", "pending")
    state.setdefault("find_gh_poc_status", "pending")
    initial_fscan_ips = [
        value for value, kind in target_assets(args.target) if kind == "ip"
    ]
    state.setdefault("incremental_fscan_attempted_ips", initial_fscan_ips)
    state.setdefault("incremental_fscan_batches", [])
    state.setdefault("active_incremental_fscan", {})
    existing_batches = state.get("agent_batches")
    recovered_orphans = recover_completed_batch_orphans(
        existing_batches if isinstance(existing_batches, list) else [], run_dir
    )
    if recovered_orphans:
        append_activity(
            run_dir,
            "自动调度器启动时回收已结束 AI 批次的遗留进程："
            + "、".join(str(pid) for pid in recovered_orphans)
            + "。",
        )
    state["agent_failure_count"] = 0
    state["agent_retry_not_before"] = 0
    state.update(
        status="running",
        stage="collecting_assets",
        workflow={
            "auto_agent": args.auto_agent,
            "wait_for_asset_commander": args.wait_asset_commander,
            "wait_for_fscan": args.wait_fscan,
            "settle_seconds": args.settle_seconds,
            "max_agent_batches": args.max_agent_batches,
            "poll_seconds": args.poll_seconds,
            "agent_stall_warn_minutes": args.agent_stall_warn_minutes,
            "ai_summary": args.ai_summary,
            "agent_model": args.agent_model,
            "reasoning_effort": args.reasoning_effort,
            "vulnx": str(args.vulnx or ""),
            "find_gh_poc": str(args.find_gh_poc or ""),
            "incremental_fscan": bool(args.fscan_exe),
            "fscan_port_threads": max(args.fscan_port_threads, 1),
            "allow_cidr_expansion": args.allow_cidr_expansion,
            "new_asset_approval_mode": args.new_asset_approval_mode,
            "new_asset_countdown_seconds": max(args.new_asset_countdown_seconds, 3),
            "workload_approval_mode": args.workload_approval_mode,
            "workload_countdown_seconds": max(args.workload_countdown_seconds, 3),
            "workload_agent_threshold": max(args.workload_agent_threshold, 1),
            "workload_popup_enabled": args.workload_popup_enabled,
            "workload_popup_topmost": args.workload_popup_topmost,
        },
        updated_at=now_text(),
    )
    bus.ingest(target_assets(args.target), "project_target")
    atomic_json_write(state_path, state)
    if args.auto_agent:
        wait_items = []
        if args.wait_asset_commander:
            wait_items.append("AssetCommander")
        if args.wait_fscan:
            wait_items.append("fscan")
        wait_text = "、".join(wait_items) or "资产稳定窗口"
        launch_policy = f"AI 将等待 {wait_text} 后自动启动"
    else:
        launch_policy = "自动 AI 执行已关闭，只持续汇总资产与风险摘要"
    append_activity(
        run_dir,
        f"自动调度器已启动：{launch_policy}；资产稳定等待 {args.settle_seconds:g} 秒，最多 {args.max_agent_batches} 次 AI 执行。",
    )

    sources = {
        "asset_commander": asset_export,
        "fscan": fscan_path,
        "semantic_dirscan": semantic_state,
        "tscan": tscan_database,
    }
    last_new = time.monotonic()
    if bus.generation:
        last_new = time.monotonic()
    while True:
        changed = False
        tools = selected_tools(run_dir)
        decision_value = read_json(decisions_path)
        decision_rows = decision_value.get("decisions")
        if not isinstance(decision_rows, list):
            decision_rows = []
        decision_added = bus.apply_decisions(
            [item for item in decision_rows if isinstance(item, dict)]
        )
        decision_stats = dict(bus.last_resolution_stats)
        expired_added = bus.resolve_due_pending(grace_seconds=2)
        expired_stats = dict(bus.last_resolution_stats)
        resolved_added = decision_added + expired_added
        resolved_accepted = int(decision_stats.get("accepted") or 0) + int(
            expired_stats.get("accepted") or 0
        )
        resolved_rejected = int(decision_stats.get("rejected") or 0) + int(
            expired_stats.get("rejected") or 0
        )
        if resolved_accepted or resolved_rejected:
            state["pending_asset_count"] = bus.pending_count
            state["last_asset_decision_at"] = now_text()
            append_activity(
                run_dir,
                "新增资产准入决策已生效："
                f"加入 {resolved_accepted} 条、排除 {resolved_rejected} 条，"
                f"当前待确认 {bus.pending_count} 条。",
            )
        if resolved_added:
            changed = True
            last_new = time.monotonic()
        markers = state.get("source_markers")
        if not isinstance(markers, dict):
            markers = {}
            state["source_markers"] = markers
        for source, path in sources.items():
            if source == "tscan" and not tscan_source_ready(path):
                state["tscan_waiting_for_workspace"] = True
                continue
            state.pop("tscan_waiting_for_workspace", None)
            marker = file_marker(path)
            rendered_marker = list(marker) if marker else None
            if markers.get(source) == rendered_marker:
                continue
            markers[source] = rendered_marker
            if marker is None:
                continue
            try:
                if source == "asset_commander":
                    assets = parse_asset_export(path)
                elif source == "fscan":
                    assets = parse_fscan_output(
                        path.read_text(encoding="utf-8", errors="replace")
                    )
                    attempted = state.get("incremental_fscan_attempted_ips")
                    if not isinstance(attempted, list):
                        attempted = []
                        state["incremental_fscan_attempted_ips"] = attempted
                    for value, kind in assets:
                        if kind == "ip" and value not in attempted:
                            attempted.append(value)
                elif source == "semantic_dirscan":
                    assets = semantic_assets(path)
                else:
                    assets = extract_tscan_assets(path)
                added = bus.ingest(assets, source)
            except Exception as exc:
                state[f"{source}_error"] = f"{type(exc).__name__}: {exc}"
                continue
            ingest_stats = dict(bus.last_ingest_stats)
            pending_added = int(ingest_stats.get("pending") or 0)
            rejected_added = int(ingest_stats.get("rejected") or 0)
            state["pending_asset_count"] = bus.pending_count
            if added:
                changed = True
                last_new = time.monotonic()
            if added or pending_added or rejected_added:
                append_activity(
                    run_dir,
                    f"资产来源 {source}：直接加入 {added} 条、待用户确认 {pending_added} 条、"
                    f"策略排除 {rejected_added} 条；资产更新轮次为 {bus.generation}。",
                )

        dirsearch_paths = semantic_dirsearch_output_files(semantic_state)
        dirsearch_marker = semantic_dirsearch_marker(run_dir, dirsearch_paths)
        dirsearch_active = semantic_dirsearch_output_active(dirsearch_paths)
        state["semantic_dirsearch_active"] = dirsearch_active
        dirsearch_source = "semantic_dirsearch_results"
        consumed_dirsearch_marker = markers.get(dirsearch_source)
        pending_dirsearch = state.get("semantic_dirsearch_pending")
        if dirsearch_marker and consumed_dirsearch_marker != dirsearch_marker:
            if (
                not isinstance(pending_dirsearch, dict)
                or pending_dirsearch.get("marker") != dirsearch_marker
            ):
                state["semantic_dirsearch_pending"] = {
                    "marker": dirsearch_marker,
                    "stable_after": time.time() + 30,
                }
            elif (
                not dirsearch_active
                and time.time() >= float(pending_dirsearch.get("stable_after") or 0)
            ):
                dirsearch_assets: list[tuple[str, str]] = []
                parse_errors: list[str] = []
                for path in dirsearch_paths:
                    try:
                        dirsearch_assets.extend(
                            parse_dirsearch_output(
                                path.read_text(encoding="utf-8", errors="replace")
                            )
                        )
                    except OSError as exc:
                        parse_errors.append(f"{path}: {type(exc).__name__}: {exc}")
                unique_assets = list(dict.fromkeys(dirsearch_assets))
                added = bus.ingest(unique_assets, dirsearch_source)
                markers[dirsearch_source] = dirsearch_marker
                state.pop("semantic_dirsearch_pending", None)
                state["semantic_dirsearch_stats"] = {
                    "files": len(dirsearch_paths),
                    "accepted_assets": len(unique_assets),
                    "assets_added": added,
                    "updated_at": now_text(),
                    "errors": parse_errors,
                }
                if added:
                    changed = True
                    last_new = time.monotonic()
                append_activity(
                    run_dir,
                    "dirsearch 输出已稳定并完成软 200 去噪："
                    f"保留 {len(unique_assets)} 条，"
                    f"新增资产 {added} 条，资产更新轮次为 {bus.generation}。",
                )
        elif not dirsearch_marker:
            state.pop("semantic_dirsearch_pending", None)

        incremental_batches = state.get("incremental_fscan_batches")
        if not isinstance(incremental_batches, list):
            incremental_batches = []
            state["incremental_fscan_batches"] = incremental_batches
        active_incremental = state.get("active_incremental_fscan")
        if not isinstance(active_incremental, dict):
            active_incremental = {}
            state["active_incremental_fscan"] = active_incremental
        incremental_pid = int(active_incremental.get("pid") or 0)
        incremental_token = int(active_incremental.get("creation_token") or 0)
        incremental_alive = bool(
            incremental_pid
            and tracked_process_alive(incremental_pid, incremental_token, run_dir)
        )
        if incremental_pid and not incremental_alive:
            output_file = Path(
                str(active_incremental.get("output_file") or "")
            )
            added = 0
            if output_file.is_file():
                try:
                    added = bus.ingest(
                        parse_fscan_output(
                            output_file.read_text(
                                encoding="utf-8", errors="replace"
                            )
                        ),
                        "fscan_incremental",
                    )
                except (OSError, ValueError) as exc:
                    active_incremental["error"] = (
                        f"{type(exc).__name__}: {exc}"
                    )
            active_incremental["status"] = (
                "completed" if output_file.is_file() else "failed"
            )
            active_incremental["completed_at"] = now_text()
            active_incremental["assets_added"] = added
            for batch in reversed(incremental_batches):
                if not isinstance(batch, dict):
                    continue
                if int(batch.get("batch") or 0) != int(
                    active_incremental.get("batch") or 0
                ):
                    continue
                batch.update(active_incremental)
                break
            if active_incremental["status"] == "failed":
                attempted = state.get("incremental_fscan_attempted_ips")
                if not isinstance(attempted, list):
                    attempted = []
                failed_targets = {
                    str(value)
                    for value in active_incremental.get("targets") or []
                }
                state["incremental_fscan_attempted_ips"] = [
                    value for value in attempted if str(value) not in failed_targets
                ]
                state["incremental_fscan_retry_not_before"] = time.time() + 60
            if added:
                changed = True
                last_new = time.monotonic()
            append_activity(
                run_dir,
                "fscan 新增 IP 补探测第 "
                f"{active_incremental.get('batch')} 轮已结束：处理 "
                f"{len(active_incremental.get('targets') or [])} 个 IP，"
                f"新增资产 {added} 条，结果位于 {output_file}。",
            )
            state["active_incremental_fscan"] = {}
            active_incremental = {}
            incremental_pid = 0

        initial_fscan_ready = (
            "fscan" not in tools
            or (
                fscan_path.is_file()
                and not component_process_alive(run_dir, "fscan")
            )
        )
        attempted = state.get("incremental_fscan_attempted_ips")
        if not isinstance(attempted, list):
            attempted = []
            state["incremental_fscan_attempted_ips"] = attempted
        candidates = incremental_fscan_candidates(bus, attempted)
        state["incremental_fscan_pending_ips"] = candidates
        retry_not_before = float(
            state.get("incremental_fscan_retry_not_before") or 0
        )
        if (
            not incremental_pid
            and candidates
            and initial_fscan_ready
            and time.time() >= retry_not_before
            and "fscan" in tools
            and args.fscan_exe is not None
            and args.fscan_exe.is_file()
        ):
            batch_number = len(incremental_batches) + 1
            try:
                batch = launch_incremental_fscan(
                    executable=args.fscan_exe,
                    run_dir=run_dir,
                    batch_number=batch_number,
                    targets=candidates,
                    port_threads=args.fscan_port_threads,
                )
            except OSError as exc:
                state["incremental_fscan_error"] = (
                    f"{type(exc).__name__}: {exc}"
                )
                state["incremental_fscan_retry_not_before"] = time.time() + 60
                append_activity(
                    run_dir,
                    "fscan 新增 IP 补探测启动失败："
                    f"{type(exc).__name__}: {exc}；60 秒后重试。",
                )
            else:
                incremental_batches.append(batch)
                state["active_incremental_fscan"] = batch
                attempted.extend(
                    value for value in candidates if value not in attempted
                )
                state["incremental_fscan_pending_ips"] = []
                state.pop("incremental_fscan_error", None)
                state.pop("incremental_fscan_retry_not_before", None)
                incremental_pid = int(batch["pid"])
                atomic_json_write(state_path, state)
                append_activity(
                    run_dir,
                    f"后台启动 fscan 新增 IP 补探测第 {batch_number} 轮，"
                    f"本轮 {len(candidates)} 个 IP；仅识别端口和服务，"
                    "不执行 POC 或口令检测。",
                )
        if changed:
            state["asset_generation"] = bus.generation
            state["last_new_asset_at"] = now_text()
            write_project_reports(
                run_dir=run_dir,
                bus=bus,
                database=tscan_database,
                stage="资产增量收集中",
                project_name=args.project,
                target=args.target,
                scope=args.scope,
            )
            state["summary_status"] = "已刷新本地阶段性风险摘要"

        active_pid = int(state.get("active_agent_pid") or 0)
        active_creation_token = int(state.get("active_agent_creation_token") or 0)
        batches = state.get("agent_batches")
        if not isinstance(batches, list):
            batches = []
            state["agent_batches"] = batches
        active_batch = next(
            (
                item
                for item in reversed(batches)
                if isinstance(item, dict)
                and int(item.get("pid") or 0) == active_pid
            ),
            None,
        )
        active_batch_dir = (
            Path(str(active_batch.get("run_dir") or ""))
            if active_batch
            else Path()
        )
        terminal_state = (
            agent_batch_terminal_state(active_batch_dir) if active_batch else None
        )
        active_alive = bool(
            active_pid
            and tracked_process_alive(active_pid, active_creation_token, run_dir)
        )
        if active_alive and active_batch:
            remember_agent_process_tree(active_batch, active_pid)
        if active_pid and terminal_state and active_alive:
            terminate_agent_process_tree(active_pid)
            active_alive = tracked_process_alive(
                active_pid, active_creation_token, run_dir
            )
        if active_pid and not active_alive:
            finished_pid = active_pid
            terminate_remembered_agent_processes(active_batch, run_dir)
            finished = mark_agent_batch_finished(run_dir, batches, finished_pid)
            state["active_agent_pid"] = 0
            state["active_agent_creation_token"] = 0
            active_pid = 0
            if finished and finished.get("status") == "failed":
                exit_code = int(finished.get("exit_code") or 1)
                delay = schedule_agent_retry(state, f"AI 退出码 {exit_code}")
                append_activity(
                    run_dir,
                    f"AI 执行记录 PID {finished_pid} 启动或运行失败（退出码 {exit_code}），{delay} 秒后重试当前资产。",
                )
            else:
                generation_to = int((finished or {}).get("generation_to") or 0)
                state["agent_consumed_generation"] = max(
                    int(state.get("agent_consumed_generation") or 0), generation_to
                )
                clear_agent_retry(state)
                integrity = (finished or {}).get("report_integrity") if finished else None
                if isinstance(integrity, dict):
                    restored = integrity.get("restored") or []
                    normalized = integrity.get("normalized") or []
                    if restored:
                        append_activity(
                            run_dir,
                            "\u0041I \u8f93\u51fa\u62a5\u544a\u5b58\u5728\u7f16\u7801/\u4e71\u7801\u635f\u574f\uff0c\u5df2\u9694\u79bb\u635f\u574f\u526f\u672c\u5e76\u6062\u590d\u6279\u6b21\u524d\u7248\u672c\uff1a"
                            + ", ".join(str(item) for item in restored),
                        )
                    elif normalized:
                        append_activity(
                            run_dir,
                            "\u0041I \u8f93\u51fa\u62a5\u544a\u5df2\u81ea\u52a8\u6e05\u7406 ANSI \u63a7\u5236\u7801\u6216\u5e38\u89c1\u4e71\u7801\uff1a"
                            + ", ".join(str(item) for item in normalized),
                        )
                append_activity(
                    run_dir,
                    f"AI 执行记录 PID {finished_pid} 已结束并记录完成，等待新资产。",
                )

        active_pid = int(state.get("active_agent_pid") or 0)
        if active_pid:
            batch_dir = Path(str(active_batch.get("run_dir") or "")) if active_batch else Path()
            warn_minutes = max(int(args.agent_stall_warn_minutes), 0)
            stall_status, elapsed_minutes, activity_text = agent_batch_health(
                batch_dir, warn_minutes
            )
            if (
                stall_status == "suspected_stalled"
                and args.provider in {"codex", "codexx"}
            ):
                session_activity = codex_session_last_activity(run_dir, batch_dir)
                if session_activity is not None:
                    session_modified_at, session_path = session_activity
                    session_elapsed = max(time.time() - session_modified_at, 0) / 60
                    if session_elapsed < warn_minutes:
                        stall_status = "active"
                        elapsed_minutes = session_elapsed
                        activity_text = datetime.fromtimestamp(
                            session_modified_at
                        ).astimezone().isoformat(timespec="seconds")
                        state["agent_session_path"] = str(session_path)
                        state.pop("agent_stall_warning_at", None)
            state["agent_stall_status"] = stall_status
            if activity_text:
                state["agent_last_activity_at"] = activity_text
            if stall_status == "suspected_stalled":
                recovered_terminal = (
                    codex_session_terminal_state(run_dir, batch_dir)
                    if args.provider in {"codex", "codexx"}
                    else None
                )
                if recovered_terminal is not None:
                    atomic_json_write(
                        batch_dir / "batch_status.json", recovered_terminal
                    )
                    append_activity(
                        run_dir,
                        f"AI 执行记录 {active_pid} 的 Codex 会话已明确结束，"
                        "但 CLI 外壳未退出；正在回收该批次并按结果继续调度。",
                    )
                    terminate_agent_process_tree(active_pid)
                    terminate_remembered_agent_processes(active_batch, run_dir)
                    state["agent_stall_status"] = "recovering"
                    atomic_json_write(state_path, state)
                    time.sleep(max(args.poll_seconds, 1))
                    continue
                previous_warning = str(state.get("agent_stall_warning_at") or "")
                warning_due = not previous_warning
                if previous_warning:
                    try:
                        warning_due = time.time() - datetime.fromisoformat(
                            previous_warning
                        ).timestamp() >= 300
                    except ValueError:
                        warning_due = True
                if warning_due:
                    state["agent_stall_warning_at"] = now_text()
                    append_activity(
                        run_dir,
                        f"AI 执行记录 {active_pid} 疑似停滞：执行文件已有 "
                        f"{elapsed_minutes:.1f} 分钟未更新；保留进程不自动结束，"
                        "请检查模型/CLI 网络与 AI 窗口。",
                    )
        else:
            state["agent_stall_status"] = "disabled"
            state.pop("agent_last_activity_at", None)
            state.pop("agent_stall_warning_at", None)

        asset_ready = (
            not args.wait_asset_commander
            or "asset_commander" not in tools
            or asset_commander_ready(run_dir)
        )
        initial_fscan_gate_ready = (
            not args.wait_fscan
            or "fscan" not in tools
            or (
                fscan_path.is_file()
                and not component_process_alive(run_dir, "fscan")
            )
        )
        incremental_fscan_ready = (
            "fscan" not in tools
            or (
                not state.get("active_incremental_fscan")
                and not state.get("incremental_fscan_pending_ips")
            )
        )
        fscan_ready = initial_fscan_gate_ready and incremental_fscan_ready
        quiet = time.monotonic() - last_new >= max(args.settle_seconds, 1)
        consumed = int(state.get("agent_consumed_generation") or 0)
        retry_not_before = float(state.get("agent_retry_not_before") or 0)
        retry_seconds = max(int(retry_not_before - time.time()), 0)
        retry_ready = retry_seconds <= 0
        should_launch = agent_launch_ready(
            active_pid=active_pid,
            generation=bus.generation,
            consumed_generation=consumed,
            asset_ready=asset_ready,
            fscan_ready=fscan_ready,
            quiet=quiet,
            batch_count=len(batches),
            max_batches=args.max_agent_batches,
            auto_agent=args.auto_agent,
            retry_ready=retry_ready,
        )
        workload_gate_status = "not_needed"
        if should_launch:
            workload_gate_status = agent_workload_gate(
                run_dir,
                state,
                bus,
                consumed_generation=consumed,
                mode=args.workload_approval_mode,
                countdown_seconds=max(args.workload_countdown_seconds, 3),
                threshold=max(args.workload_agent_threshold, 1),
                project_name=args.project,
                run_id=run_dir.name,
            )
            should_launch = workload_gate_status == "accepted"
        if should_launch:
            summary = write_project_reports(
                run_dir=run_dir,
                bus=bus,
                database=tscan_database,
                stage="阶段性" if batches else "首次资产稳定",
                project_name=args.project,
                target=args.target,
                scope=args.scope,
            )
            if bus.generation > int(state.get("vuln_intel_generation") or 0):
                if "vulnx" not in tools:
                    state["vuln_intel_status"] = "not_selected"
                    state["find_gh_poc_status"] = (
                        "blocked_without_vulnx"
                        if "find_gh_poc" in tools
                        else "not_selected"
                    )
                    state["vuln_intel_candidates"] = 0
                    state["vuln_intel_high_confidence"] = 0
                    state["vuln_intel_generation"] = bus.generation
                    append_activity(
                        run_dir,
                        "漏洞情报阶段未勾选 vulnx，本代资产跳过 CVE/PoC 联动。",
                    )
                else:
                    state.update(
                        stage="vulnerability_intelligence",
                        detail="资产已稳定，正在关联产品版本、CVE、KEV、公开 PoC 与 Nuclei 模板。",
                        vuln_intel_status="running",
                        find_gh_poc_status=(
                            "running" if "find_gh_poc" in tools else "not_selected"
                        ),
                        updated_at=now_text(),
                    )
                    atomic_json_write(state_path, state)
                    append_activity(
                        run_dir,
                        f"开始生成漏洞情报，处理资产更新第 {bus.generation} 轮；PoC 仅收集元数据，不自动执行。",
                    )
                    try:
                        intel = generate_vulnerability_intel(
                            run_dir,
                            args.vulnx or Path("__missing_vulnx__"),
                            args.find_gh_poc if "find_gh_poc" in tools else None,
                        )
                    except Exception as exc:
                        state["vuln_intel_status"] = "failed"
                        state["find_gh_poc_status"] = "failed"
                        state["vuln_intel_error"] = f"{type(exc).__name__}: {exc}"
                        state["vuln_intel_candidates"] = 0
                        append_activity(
                            run_dir,
                            f"漏洞情报生成失败：{type(exc).__name__}: {exc}；AI 仍按已有证据继续。",
                        )
                    else:
                        state["vuln_intel_status"] = str(
                            intel.get("status") or "completed"
                        )
                        tool_status = intel.get("tool_status")
                        if isinstance(tool_status, dict):
                            state["find_gh_poc_status"] = str(
                                tool_status.get("find_gh_poc") or "completed"
                            )
                        state["vuln_intel_candidates"] = int(
                            intel.get("candidate_count") or 0
                        )
                        state["vuln_intel_high_confidence"] = int(
                            intel.get("high_confidence_count") or 0
                        )
                        state["vuln_intel_updated_at"] = str(
                            intel.get("generated_at") or now_text()
                        )
                        state.pop("vuln_intel_error", None)
                        append_activity(
                            run_dir,
                            "漏洞情报已生成："
                            f"候选 {state['vuln_intel_candidates']}，"
                            f"带本地证据与模板线索 {state['vuln_intel_high_confidence']}；"
                            "未知 PoC 保持禁用。",
                        )
                    state["vuln_intel_generation"] = bus.generation
            if args.ai_summary:
                enhanced, ai_status = ai_enhance_summary(summary)
            else:
                enhanced = summary
                ai_status = "全局设置已关闭工具协作 AI 摘要优化"
            (run_dir / "risk_summary.md").write_text(enhanced, encoding="utf-8")
            write_pentest_report(
                run_dir=run_dir,
                bus=bus,
                stage="阶段性" if batches else "首次资产稳定",
                project_name=args.project,
                target=args.target,
                scope=args.scope,
                tscan_findings=tscan_findings(tscan_database),
            )
            state["summary_status"] = ai_status
            base_prompt = (run_dir / "agent_prompt.txt").read_text(
                encoding="utf-8", errors="replace"
            )
            batch_number = len(batches) + 1
            prompt = build_batch_prompt(
                run_dir, base_prompt, bus, consumed, batch_number
            )
            try:
                pid, batch_dir = launch_agent_batch(
                    run_dir,
                    args.provider,
                    args.project,
                    batch_number,
                    prompt,
                    args.agent_model,
                    args.reasoning_effort,
                    args.agent_base_url,
                    args.terminal_window,
                )
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
                state["agent_launch_error"] = error
                delay = schedule_agent_retry(state, error)
                append_activity(
                    run_dir,
                    f"AI 执行记录 {batch_number} 启动失败：{exc}；{delay} 秒后重试。",
                )
            else:
                clear_agent_retry(state)
                batch = {
                    "batch": batch_number,
                    "generation_from": consumed + 1,
                    "generation_to": bus.generation,
                    "pid": pid,
                    "run_dir": str(batch_dir),
                    "started_at": now_text(),
                    "status": "running",
                }
                batch_metadata_path = batch_dir / "batch.json"
                batch_metadata = read_json(batch_metadata_path)
                if batch_metadata:
                    batch_metadata.update(
                        generation_from=consumed + 1,
                        generation_to=bus.generation,
                    )
                    atomic_json_write(batch_metadata_path, batch_metadata)
                batches.append(batch)
                state["active_agent_pid"] = pid
                state["active_agent_creation_token"] = process_creation_token(pid)
                state["active_agent_generation"] = bus.generation
                state["stage"] = "agent_running"
                state.pop("agent_launch_error", None)
                append_activity(
                    run_dir,
                    f"资产已稳定，启动第 {batch_number} 次 AI 执行，处理资产更新第 {consumed + 1}-{bus.generation} 轮。",
                )

        retry_not_before = float(state.get("agent_retry_not_before") or 0)
        retry_seconds = max(int(retry_not_before - time.time()), 0)
        retry_ready = retry_seconds <= 0
        stage, stage_detail = coordinator_wait_stage(
            active_pid=int(state.get("active_agent_pid") or 0),
            generation=bus.generation,
            consumed_generation=int(state.get("agent_consumed_generation") or 0),
            asset_ready=asset_ready,
            fscan_ready=fscan_ready,
            quiet=quiet,
            batch_count=len(batches),
            max_batches=args.max_agent_batches,
            auto_agent=args.auto_agent,
            retry_ready=retry_ready,
            retry_seconds=retry_seconds,
        )
        if workload_gate_status == "pending":
            stage = "awaiting_workload_approval"
            stage_detail = "\u7b49\u5f85\u7528\u6237\u786e\u8ba4\u5927\u6279\u91cf Agent \u51c6\u5165\uff1b\u540e\u53f0\u8d44\u4ea7\u53d1\u73b0\u4e0e\u5de5\u5177\u4efb\u52a1\u7ee7\u7eed\u8fd0\u884c\u3002"
        state.update(
            status="running",
            stage=stage,
            asset_generation=bus.generation,
            asset_counts={key: len(value) for key, value in bus.bundle().items()},
            pending_asset_count=bus.pending_count,
            readiness={
                "asset_commander": asset_ready,
                "fscan": fscan_ready,
                "quiet": quiet,
                "auto_agent": args.auto_agent,
                "wait_for_asset_commander": args.wait_asset_commander,
                "wait_for_fscan": args.wait_fscan,
                "incremental_fscan_running": bool(
                    state.get("active_incremental_fscan")
                ),
                "incremental_fscan_pending": len(
                    state.get("incremental_fscan_pending_ips") or []
                ),
                "initial_fscan_gate": initial_fscan_gate_ready,
            },
            detail=(
                f"{stage_detail}；资产更新轮次 {bus.generation}；"
                f"AI 已处理到第 {state.get('agent_consumed_generation', 0)} 轮；"
                f"当前 AI 进程 PID {state.get('active_agent_pid', 0) or '无'}；"
                f"AI 运行状态 {state.get('agent_stall_status', 'disabled')}；"
                f"待确认新资产 {bus.pending_count} 条；"
                "fscan 新增 IP 补探测 "
                f"{'运行中' if state.get('active_incremental_fscan') else '空闲'}"
            ),
            updated_at=now_text(),
        )
        atomic_json_write(state_path, state)
        time.sleep(max(args.poll_seconds, 1))


if __name__ == "__main__":
    raise SystemExit(main())
