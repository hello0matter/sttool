from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from .activity import append_activity
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
from .runtime import (
    agent_cli_arguments,
    pid_alive,
    process_creation_token,
    process_record_alive,
)


CREATE_NEW_CONSOLE = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
CREATE_NEW_PROCESS_GROUP = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)


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
) -> bool:
    return (
        auto_agent
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
) -> tuple[str, str]:
    if active_pid > 0:
        return "agent_running", f"Agent PID {active_pid} 正在处理当前批次"
    if not auto_agent:
        return "manual_agent", "自动 Agent 已关闭；资产与摘要仍会持续更新"
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


def mark_agent_batch_finished(run_dir: Path, batches: list[object], pid: int) -> None:
    completed_at = now_text()
    for item in reversed(batches):
        if not isinstance(item, dict) or int(item.get("pid") or 0) != pid:
            continue
        item["status"] = "completed"
        item["completed_at"] = completed_at
        batch_dir = Path(str(item.get("run_dir") or ""))
        metadata_path = batch_dir / "batch.json"
        metadata = read_json(metadata_path)
        if metadata:
            metadata.update(status="completed", completed_at=completed_at)
            atomic_json_write(metadata_path, metadata)
        break


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
        "请优化下面的项目风险成果摘要，保留全部 Web 目标和证据状态：\n\n" + summary
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
            with urlopen(request, timeout=60) as response:
                value = json.loads(response.read().decode("utf-8"))
            content = response_text(value)
            if content:
                return content + "\n", "项目 AI 已优化风险摘要"
            errors.append(f"{Path(endpoint).name}:empty")
        except (OSError, URLError, ValueError, KeyError, IndexError, TypeError) as exc:
            errors.append(f"{Path(endpoint).name}:{type(exc).__name__}")
    detail = ",".join(errors)
    return summary, f"项目 AI 摘要调用失败，保留本地摘要：{detail}"


def powershell_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def write_agent_batch_script(
    batch_dir: Path,
    provider: str,
    project_name: str,
    agent_model: str = "",
    reasoning_effort: str = "",
) -> tuple[Path, Path]:
    prompt_path = batch_dir / "prompt.txt"
    script_path = batch_dir / "launch.ps1"
    pid_path = batch_dir / "agent.pid"
    if provider in {"codex", "codexx"}:
        options = " ".join(
            item if item in {"--yolo", "-m", "-c"} else powershell_quote(item)
            for item in agent_cli_arguments(provider, agent_model, reasoning_effort)
        )
        invocation = f"& {provider} {options} $prompt"
    else:
        invocation = "& claude $prompt"
    script = (
        "$ErrorActionPreference = 'Stop'\n"
        "$utf8 = [System.Text.UTF8Encoding]::new()\n"
        "[Console]::InputEncoding = $utf8\n"
        "[Console]::OutputEncoding = $utf8\n"
        "$OutputEncoding = $utf8\n"
        f"$Host.UI.RawUI.WindowTitle = {powershell_quote(f'STTool {project_name} - {provider} 增量批次')}\n"
        f"Set-Content -LiteralPath {powershell_quote(str(pid_path))} -Value $PID -Encoding ascii\n"
        "try {\n"
        f"Set-Location -LiteralPath {powershell_quote(str(batch_dir.parents[1]))}\n"
        f"$prompt = Get-Content -Raw -Encoding UTF8 -LiteralPath {powershell_quote(str(prompt_path))}\n"
        f"{invocation}\n"
        "} finally {\n"
        f"Remove-Item -LiteralPath {powershell_quote(str(pid_path))} -Force -ErrorAction SilentlyContinue\n"
        "}\n"
    )
    script_path.write_text(script, encoding="utf-8-sig")
    return script_path, pid_path


def launch_agent_batch(
    run_dir: Path,
    provider: str,
    project_name: str,
    batch_number: int,
    prompt: str,
    agent_model: str = "",
    reasoning_effort: str = "",
) -> tuple[int, Path]:
    batch_dir = run_dir / "agent_batches" / f"{batch_number:04d}"
    batch_dir.mkdir(parents=True, exist_ok=True)
    (batch_dir / "prompt.txt").write_text(prompt, encoding="utf-8")
    script, pid_path = write_agent_batch_script(
        batch_dir, provider, project_name, agent_model, reasoning_effort
    )
    try:
        pid_path.unlink()
    except FileNotFoundError:
        pass
    shell = shutil.which("pwsh.exe") or "powershell.exe"
    terminal = shutil.which("wt.exe")
    if terminal:
        command = [
            terminal,
            "-w",
            "new",
            "new-tab",
            "--title",
            f"STTool {project_name} - {provider} 批次 {batch_number}",
            "--startingDirectory",
            str(run_dir),
            shell,
            "-NoLogo",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
        ]
        launcher = subprocess.Popen(
            command, cwd=run_dir, creationflags=CREATE_NEW_PROCESS_GROUP
        )
    else:
        launcher = subprocess.Popen(
            [shell, "-NoLogo", "-ExecutionPolicy", "Bypass", "-File", str(script)],
            cwd=run_dir,
            creationflags=CREATE_NEW_PROCESS_GROUP | CREATE_NEW_CONSOLE,
        )
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        try:
            pid = int(pid_path.read_text(encoding="ascii").strip())
        except (OSError, UnicodeError, ValueError):
            pid = 0
        if pid and pid_alive(pid):
            metadata = {
                "batch": batch_number,
                "pid": pid,
                "creation_token": process_creation_token(pid),
                "provider": provider,
                "agent_model": agent_model.strip(),
                "reasoning_effort": reasoning_effort,
                "started_at": now_text(),
                "prompt": str(batch_dir / "prompt.txt"),
                "script": str(script),
            }
            atomic_json_write(batch_dir / "batch.json", metadata)
            return pid, batch_dir
        if launcher.poll() is not None:
            break
        time.sleep(0.1)
    raise RuntimeError("Agent 终端已启动，但未检测到批次 PowerShell 进程")


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
        + f"项目风险摘要：{run_dir / 'risk_summary.md'}\n\n"
        + "必须先完整读取 fscan 输出，逐个检查下列 Web URL，不能只检查项目主 URL。"
        + "对每个 URL 分别记录页面取证、产品/版本、候选 CVE、验证状态和证据路径。\n\n"
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
    parser.add_argument("--settle-seconds", type=float, default=20)
    parser.add_argument("--max-agent-batches", type=int, default=8)
    parser.add_argument("--poll-seconds", type=float, default=2)
    parser.add_argument("--auto-agent", type=parse_bool, default=True)
    parser.add_argument("--wait-asset-commander", type=parse_bool, default=True)
    parser.add_argument("--wait-fscan", type=parse_bool, default=True)
    parser.add_argument("--ai-summary", type=parse_bool, default=True)
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
    bus = AssetBus(bus_path, args.scope)
    state = read_json(state_path)
    state.setdefault("schema_version", 1)
    state.setdefault("created_at", now_text())
    state.setdefault("source_markers", {})
    state.setdefault("agent_batches", [])
    state.setdefault("agent_consumed_generation", 0)
    state.setdefault("active_agent_pid", 0)
    state.setdefault("active_agent_creation_token", 0)
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
            "ai_summary": args.ai_summary,
            "agent_model": args.agent_model,
            "reasoning_effort": args.reasoning_effort,
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
            local_summary = render_risk_summary(
                run_dir, bus, tscan_database, "资产增量收集中"
            )
            (run_dir / "risk_summary.md").write_text(local_summary, encoding="utf-8")
            state["summary_status"] = "已刷新本地阶段性风险摘要"

        active_pid = int(state.get("active_agent_pid") or 0)
        active_creation_token = int(state.get("active_agent_creation_token") or 0)
        batches = state.get("agent_batches")
        if not isinstance(batches, list):
            batches = []
            state["agent_batches"] = batches
        if active_pid and not tracked_process_alive(
            active_pid, active_creation_token, run_dir
        ):
            append_activity(
                run_dir,
                f"Agent 批次 PID {active_pid} 已结束，协调器将记录完成状态并等待新资产。",
            )
            mark_agent_batch_finished(run_dir, batches, active_pid)
            state["active_agent_pid"] = 0
            state["active_agent_creation_token"] = 0
            active_pid = 0

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
        )
        if should_launch:
            summary = render_risk_summary(
                run_dir,
                bus,
                tscan_database,
                "阶段性" if batches else "首次资产稳定",
            )
            if args.ai_summary:
                enhanced, ai_status = ai_enhance_summary(summary)
            else:
                enhanced = summary
                ai_status = "全局设置已关闭工具协作 AI 摘要优化"
            (run_dir / "risk_summary.md").write_text(enhanced, encoding="utf-8")
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
                )
            except Exception as exc:
                state["agent_launch_error"] = f"{type(exc).__name__}: {exc}"
                append_activity(run_dir, f"Agent 批次 {batch_number} 启动失败：{exc}")
            else:
                batch = {
                    "batch": batch_number,
                    "generation_from": consumed + 1,
                    "generation_to": bus.generation,
                    "pid": pid,
                    "run_dir": str(batch_dir),
                    "started_at": now_text(),
                    "status": "running",
                }
                batches.append(batch)
                state["active_agent_pid"] = pid
                state["active_agent_creation_token"] = process_creation_token(pid)
                state["agent_consumed_generation"] = bus.generation
                state["stage"] = "agent_running"
                state.pop("agent_launch_error", None)
                append_activity(
                    run_dir,
                    f"资产已稳定，启动 Agent 批次 {batch_number}，消费资产代次 {consumed + 1}-{bus.generation}。",
                )

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
                f"当前 Agent PID {state.get('active_agent_pid', 0) or '无'}"
            ),
            updated_at=now_text(),
        )
        atomic_json_write(state_path, state)
        time.sleep(max(args.poll_seconds, 1))


if __name__ == "__main__":
    raise SystemExit(main())
