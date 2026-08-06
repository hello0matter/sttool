from __future__ import annotations

import argparse
import atexit
import json
import os
import sqlite3
import time
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
    parse_fscan_output,
    read_json,
    target_assets,
)
from .models import ProcessRecord
from .pentest_report import write_pentest_report
from .vulnerability_intel import generate_vulnerability_intel
from .runtime import (
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
        return "agent_running", f"Agent PID {active_pid} 正在处理当前批次"
    if not auto_agent:
        return "manual_agent", "自动 Agent 已关闭；资产与摘要仍会持续更新"
    if not retry_ready:
        return "agent_backoff", f"Agent 启动失败，等待 {max(retry_seconds, 1)} 秒后自动重试"
    if not asset_ready:
        return "waiting_asset_commander", "等待 AssetCommander 完成资产收集与碰撞"
    if not fscan_ready:
        return "waiting_fscan", "等待 fscan 执行结束并保存完整输出"
    if not quiet:
        return "settling_assets", "资产仍在增长，等待安静窗口后再启动 Agent"
    if batch_count >= max(max_batches, 1):
        return "batch_limit_reached", "Agent 批次已达上限，保留新增资产供人工处理"
    if generation <= consumed_generation:
        return "waiting_new_assets", "当前资产已全部消费，等待工具回传新资产"
    return "ready_for_agent", "资产已稳定，准备启动下一个 Agent 批次"


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
        name="Agent batch",
        pid=pid,
        command=[],
        cwd=str(run_dir),
        started_at="",
    )
    return process_record_alive(legacy, run_dir)


def semantic_assets(path: Path) -> list[tuple[str, str]]:
    value = read_json(path)
    targets = value.get("targets", [])
    if not isinstance(targets, list):
        return []
    return [(str(item), "url") for item in targets]


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
            candidates = [
                lowered[key]
                for key in (
                    "target",
                    "url",
                    "host",
                    "vuln",
                    "pocvul",
                    "message",
                    "title",
                    "status",
                )
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
    lines = [
        "# 项目风险成果摘要",
        "",
        f"- 生成时间：{now_text()}",
        f"- 阶段：{stage}",
        f"- 资产代次：{bus.generation}",
        f"- Web URL：{len(bundle['urls'])}",
        f"- IP：{len(bundle['ips'])}",
        f"- 域名：{len(bundle['domains'])}",
        f"- 端点：{len(bundle['endpoints'])}",
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
    lines.extend(["", "## 工具风险线索", ""])
    lines.extend(f"- **{item['source']}**：{item['detail']}" for item in findings)
    if not findings:
        lines.append("- 当前尚无已结构化的漏洞结果；版本或开放服务只能作为待验证线索。")
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
    label = "新增资产增量复测" if after_generation else "资产收集稳定后的首次全量测试"
    return (
        base_prompt.rstrip()
        + "\n\n"
        + f"## STTool Agent 批次 {batch_number}：{label}\n\n"
        + f"统一资产总线：{run_dir / 'tool_data' / 'asset_bus' / 'assets.json'}\n"
        + f"fscan 完整输出：{run_dir / 'results' / 'fscan.txt'}\n"
        + f"项目风险摘要：{run_dir / 'risk_summary.md'}\n"
        + f"漏洞情报与 PoC 候选：{run_dir / 'vulnerability_intel.md'}\n"
        + f"结构化漏洞情报：{run_dir / 'results' / 'vulnerability_intel.json'}\n\n"
        + "必须先完整读取 fscan 输出和漏洞情报，逐个检查下列 Web URL，不能只检查项目主 URL。"
        + "对每个 URL 分别记录页面取证、产品/版本、候选 CVE、验证状态和证据路径。"
        + "PoC 链接只是不可信候选，不得直接下载执行；必须先核对厂商公告、受影响版本、前置条件和模板副作用，"
        + "优先使用已审查的 verified Nuclei 模板或无害请求。"
        + "禁止自动写文件、创建账号、反弹 Shell、抓取凭据、持久化和横向移动。\n\n"
        + "### 本批次 Web URL\n"
        + ("\n".join(f"- {value}" for value in urls) or "- 本批次没有新增 Web URL")
        + "\n\n### 本批次非 Web 端点\n"
        + ("\n".join(f"- {value}" for value in endpoints) or "- 本批次没有新增端点")
        + "\n\n后续若工具发现新资产，只处理尚未消费的增量，不要重复启动相同高并发任务。\n"
    )


def parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise argparse.ArgumentTypeError("expected true or false")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="STTool project asset bus and delayed Agent coordinator"
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
    state_path = run_dir / "tool_data" / "coordinator" / "state.json"
    asset_export = run_dir / "results" / "asset_commander_assets.json"
    fscan_path = run_dir / "results" / "fscan.txt"
    semantic_state = run_dir / "tool_data" / "semantic" / "sttool_bridge_state.json"
    tscan_database = run_dir / "tool_data" / "tscan" / "app" / "config" / "config.db"
    owner_path = state_path.parent / "owner.json"
    owner = claim_coordinator_owner(owner_path, run_dir)
    if owner is None:
        append_activity(run_dir, "检测到同一运行实例已有项目协调器，本次重复启动已退出。")
        return 0
    atexit.register(release_coordinator_owner, owner_path, owner)
    bus = AssetBus(bus_path, args.scope)
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
        launch_policy = f"Agent 将等待 {wait_text} 后自动启动"
    else:
        launch_policy = "自动 Agent 已关闭，只持续汇总资产与风险摘要"
    append_activity(
        run_dir,
        f"项目增量调度器已启动：{launch_policy}；资产稳定等待 {args.settle_seconds:g} 秒，最多 {args.max_agent_batches} 个批次。",
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
                elif source == "semantic_dirscan":
                    assets = semantic_assets(path)
                else:
                    assets = extract_tscan_assets(path)
                added = bus.ingest(assets, source)
            except Exception as exc:
                state[f"{source}_error"] = f"{type(exc).__name__}: {exc}"
                continue
            if added:
                changed = True
                last_new = time.monotonic()
                append_activity(
                    run_dir,
                    f"资产总线接收 {source} 新增资产 {added} 条，代次 {bus.generation}。",
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
        if active_pid and terminal_state and active_alive:
            terminate_agent_process_tree(active_pid)
            active_alive = tracked_process_alive(
                active_pid, active_creation_token, run_dir
            )
        if active_pid and not active_alive:
            finished_pid = active_pid
            finished = mark_agent_batch_finished(run_dir, batches, finished_pid)
            state["active_agent_pid"] = 0
            state["active_agent_creation_token"] = 0
            active_pid = 0
            if finished and finished.get("status") == "failed":
                exit_code = int(finished.get("exit_code") or 1)
                delay = schedule_agent_retry(state, f"Agent 退出码 {exit_code}")
                append_activity(
                    run_dir,
                    f"Agent 批次 PID {finished_pid} 启动或运行失败（退出码 {exit_code}），{delay} 秒后重试当前资产。",
                )
            else:
                generation_to = int((finished or {}).get("generation_to") or 0)
                state["agent_consumed_generation"] = max(
                    int(state.get("agent_consumed_generation") or 0), generation_to
                )
                clear_agent_retry(state)
                append_activity(
                    run_dir,
                    f"Agent 批次 PID {finished_pid} 已结束并记录完成，等待新资产。",
                )

        active_pid = int(state.get("active_agent_pid") or 0)
        if active_pid:
            batch_dir = Path(str(active_batch.get("run_dir") or "")) if active_batch else Path()
            stall_status, elapsed_minutes, activity_text = agent_batch_health(
                batch_dir, max(int(args.agent_stall_warn_minutes), 0)
            )
            state["agent_stall_status"] = stall_status
            if activity_text:
                state["agent_last_activity_at"] = activity_text
            if stall_status == "suspected_stalled":
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
                        f"Agent 批次 {active_pid} 疑似停滞：批次文件已有 "
                        f"{elapsed_minutes:.1f} 分钟未更新；保留进程不自动结束，"
                        "请检查模型/CLI 网络与 Agent 窗口。",
                    )
        else:
            state["agent_stall_status"] = "disabled"
            state.pop("agent_last_activity_at", None)
            state.pop("agent_stall_warning_at", None)

        tools = selected_tools(run_dir)
        asset_ready = (
            not args.wait_asset_commander
            or "asset_commander" not in tools
            or asset_commander_ready(run_dir)
        )
        fscan_ready = (
            not args.wait_fscan
            or "fscan" not in tools
            or (fscan_path.is_file() and not component_process_alive(run_dir, "fscan"))
        )
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
                        f"开始生成漏洞情报，处理资产代次 {bus.generation}；PoC 仅收集元数据，不自动执行。",
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
                            f"漏洞情报生成失败：{type(exc).__name__}: {exc}；Agent 仍按已有证据继续。",
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
                    f"Agent 批次 {batch_number} 启动失败：{exc}；{delay} 秒后重试。",
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
                    f"资产已稳定，启动 Agent 批次 {batch_number}，消费资产代次 {consumed + 1}-{bus.generation}。",
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
        state.update(
            status="running",
            stage=stage,
            asset_generation=bus.generation,
            asset_counts={key: len(value) for key, value in bus.bundle().items()},
            readiness={
                "asset_commander": asset_ready,
                "fscan": fscan_ready,
                "quiet": quiet,
                "auto_agent": args.auto_agent,
                "wait_for_asset_commander": args.wait_asset_commander,
                "wait_for_fscan": args.wait_fscan,
            },
            detail=(
                f"{stage_detail}；资产代次 {bus.generation}；"
                f"Agent 已消费到 {state.get('agent_consumed_generation', 0)}；"
                f"当前 Agent PID {state.get('active_agent_pid', 0) or '无'}；"
                f"Agent 健康状态 {state.get('agent_stall_status', 'disabled')}"
            ),
            updated_at=now_text(),
        )
        atomic_json_write(state_path, state)
        time.sleep(max(args.poll_seconds, 1))


if __name__ == "__main__":
    raise SystemExit(main())
