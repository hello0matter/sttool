from __future__ import annotations

import json
import ipaddress
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

from .activity import append_activity
from .models import (
    LaunchRequest,
    ProcessRecord,
    RunState,
    StandaloneRunState,
    ToolDefinition,
    normalize_provider,
)
from .registry import DEFAULT_ST_ROOT, availability


CREATE_NEW_CONSOLE = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
CREATE_NEW_PROCESS_GROUP = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class LaunchError(RuntimeError):
    pass


def now_text() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def atomic_json_write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def reconcile_component_state(
    run_dir: str | Path,
    component_id: str,
    process_status: str,
    detail: str,
) -> None:
    root = Path(run_dir)
    state_paths = {
        "asset_commander": root
        / "tool_data"
        / "asset_commander"
        / "workflow_state.json",
        "semantic_dirscan": root
        / "tool_data"
        / "semantic"
        / "sttool_bridge_state.json",
        "tscan_plus": root / "tool_data" / "tscan" / "state.json",
    }
    path = state_paths.get(component_id)
    if path is None or not path.is_file():
        return
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return
    if not isinstance(value, dict):
        return

    timestamp = now_text()
    value["process_status"] = process_status
    value["process_status_detail"] = detail
    value["process_status_updated_at"] = timestamp
    if component_id == "asset_commander":
        if value.get("status") not in {"completed", "failed"}:
            value["status"] = process_status
            current_step = str(value.get("current_step") or "")
            steps = value.get("steps")
            if (
                process_status in {"interrupted", "stopped"}
                and current_step
                and isinstance(steps, dict)
            ):
                step = steps.get(current_step)
                if isinstance(step, dict) and step.get("status") == "running":
                    step.update(
                        status="interrupted",
                        detail=detail,
                        interrupted_at=timestamp,
                    )
        for progress_path in (
            root / "tool_data" / "asset_commander" / "workspace"
        ).glob("**/scan_progress.json"):
            try:
                progress = json.loads(progress_path.read_text(encoding="utf-8"))
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                continue
            if isinstance(progress, dict):
                progress.update(
                    active=False,
                    updated_at=timestamp,
                    stop_reason=detail,
                )
                atomic_json_write(progress_path, progress)
    elif value.get("status") not in {"completed", "failed"}:
        value["status"] = process_status
        value["stage"] = process_status
        value["detail"] = detail
    value["updated_at"] = timestamp
    atomic_json_write(path, value)


def safe_project_name(value: str) -> str:
    cleaned = re.sub(r"[<>:\"/\\|?*\x00-\x1f]", "_", value.strip())
    cleaned = re.sub(r"\s+", "_", cleaned).strip("._ ")
    return cleaned[:80] or "project"


def target_values(target: str) -> dict[str, str]:
    raw = target.strip()
    if "/" in raw and "://" not in raw:
        try:
            ipaddress.ip_network(raw, strict=False)
        except ValueError:
            pass
        else:
            return {"target": raw, "target_host": raw, "target_domain": raw}
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname or raw.split("/")[0].split(":")[0]
    labels = host.rstrip(".").split(".")
    domain = ".".join(labels[-2:]) if len(labels) >= 2 else host
    return {"target": raw, "target_host": host, "target_domain": domain}


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes

        process = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not process:
            return False
        try:
            code = ctypes.c_ulong()
            if not ctypes.windll.kernel32.GetExitCodeProcess(process, ctypes.byref(code)):
                return False
            return code.value == 259
        finally:
            ctypes.windll.kernel32.CloseHandle(process)
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def terminate_process_tree(pid: int) -> None:
    if not pid_alive(pid):
        return
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            creationflags=CREATE_NO_WINDOW,
            timeout=15,
            check=False,
        )
        return
    try:
        os.killpg(pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        pass


class RuntimeManager:
    def __init__(
        self,
        app_dir: Path,
        tools: Iterable[ToolDefinition],
        st_root: Path = DEFAULT_ST_ROOT,
    ) -> None:
        self.app_dir = app_dir.resolve()
        self.projects_dir = self.app_dir / "projects"
        self.tools = {item.tool_id: item for item in tools}
        self.st_root = st_root.resolve()
        self._provider_health_cache: dict[str, tuple[float, bool, str]] = {}
        self._provider_health_locks = {
            "codex": threading.Lock(),
            "codexx": threading.Lock(),
            "claude": threading.Lock(),
        }
        self.projects_dir.mkdir(parents=True, exist_ok=True)

    def provider_health(self, provider: str) -> tuple[bool, str]:
        provider = provider.lower()
        if provider not in {"codex", "codexx", "claude"}:
            return False, "不支持的 AI CLI"
        cached = self._provider_health_cache.get(provider)
        if cached is not None and time.monotonic() - cached[0] < 60:
            return cached[1], cached[2]
        command_name = provider
        if shutil.which(command_name) is None:
            return False, f"未安装 {command_name} CLI"

        health_lock = self._provider_health_locks[provider]
        if not health_lock.acquire(blocking=False):
            if cached is not None:
                return cached[1], cached[2]
            return True, "已安装；登录状态检测中"

        health_action = "auth" if provider == "claude" else "login"
        command = f"& {command_name} {health_action} status *> $null; exit $LASTEXITCODE"
        try:
            try:
                result = subprocess.run(
                    ["powershell.exe", "-NoLogo", "-NoProfile", "-Command", command],
                    capture_output=True,
                    creationflags=CREATE_NO_WINDOW,
                    timeout=30,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                status = (True, "已安装；登录检测超时，将在启动时验证")
            except OSError as exc:
                status = (False, f"登录检测失败: {exc}")
            else:
                status = (
                    (True, "已安装并登录")
                    if result.returncode == 0
                    else (False, f"{command_name} CLI 未登录或配置无效")
                )
            self._provider_health_cache[provider] = (time.monotonic(), *status)
            return status
        finally:
            health_lock.release()

    def preflight(self, request: LaunchRequest) -> list[ToolDefinition]:
        if not request.project_name.strip():
            raise LaunchError("请填写项目名称")
        if not request.target.strip():
            raise LaunchError("请填写目标")
        if not request.scope.strip():
            raise LaunchError("请填写授权范围")
        if not request.authorization_confirmed:
            raise LaunchError("必须确认已获得该目标的测试授权")
        parsed_api_url = urlsplit(request.api_base_url.strip())
        if (
            parsed_api_url.scheme not in {"http", "https"}
            or not parsed_api_url.netloc
            or parsed_api_url.username is not None
            or parsed_api_url.password is not None
        ):
            raise LaunchError("AI API URL 必须是有效的 HTTP/HTTPS 地址，且不能包含账号密码")

        selected: list[ToolDefinition] = []
        for tool_id in request.selected_tools:
            tool = self.tools.get(tool_id)
            if tool is None:
                raise LaunchError(f"未知工具: {tool_id}")
            available, reason = availability(tool)
            if not available:
                raise LaunchError(f"{tool.name}: {reason}")
            selected.append(tool)

        healthy, message = self.provider_health(request.provider)
        if not healthy:
            raise LaunchError(message)
        return selected

    @contextmanager
    def _launch_lock(self):
        lock_path = self.projects_dir / ".launch.lock"
        for _attempt in range(2):
            try:
                fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                break
            except FileExistsError:
                try:
                    lock = json.loads(lock_path.read_text(encoding="utf-8"))
                    owner_pid = int(lock.get("pid", 0))
                except (OSError, ValueError, json.JSONDecodeError):
                    owner_pid = 0
                if owner_pid and pid_alive(owner_pid):
                    raise LaunchError("另一个启动事务正在执行，请稍后再试")
                lock_path.unlink(missing_ok=True)
        else:
            raise LaunchError("无法获取启动锁")

        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"pid": os.getpid(), "created_at": now_text()}, handle)
                handle.flush()
                os.fsync(handle.fileno())
            yield
        finally:
            lock_path.unlink(missing_ok=True)

    def _new_run_dir(self, project_name: str) -> tuple[str, Path, Path]:
        project_dir = self.projects_dir / safe_project_name(project_name)
        runs_dir = project_dir / "runs"
        runs_dir.mkdir(parents=True, exist_ok=True)
        prefix = datetime.now().strftime("%Y%m%d-%H%M%S")
        for sequence in range(1, 1000):
            run_id = f"{prefix}-{sequence:02d}"
            run_dir = runs_dir / run_id
            try:
                run_dir.mkdir()
                return run_id, project_dir, run_dir
            except FileExistsError:
                continue
        raise LaunchError("无法分配新的运行目录")

    def _new_standalone_dir(self, tool_id: str) -> tuple[str, Path]:
        runs_dir = self.app_dir / "standalone_runs" / safe_project_name(tool_id)
        runs_dir.mkdir(parents=True, exist_ok=True)
        prefix = datetime.now().strftime("%Y%m%d-%H%M%S")
        for sequence in range(1, 1000):
            run_id = f"{prefix}-{sequence:02d}"
            run_dir = runs_dir / run_id
            try:
                run_dir.mkdir()
                return run_id, run_dir
            except FileExistsError:
                continue
        raise LaunchError("无法分配单独执行目录")

    def _format(self, value: str, context: dict[str, str]) -> str:
        return value.format_map(context)

    def _prepare_tool(
        self,
        tool: ToolDefinition,
        context: dict[str, str],
        preserve_existing: bool = False,
    ) -> dict[str, str]:
        cwd = Path(self._format(tool.cwd, context))
        cwd.mkdir(parents=True, exist_ok=True)
        secret_sources: dict[Path, list[tuple[str, str]]] = {}
        for environment_name, source, json_key in tool.secret_env:
            secret_sources.setdefault(Path(source).resolve(), []).append(
                (environment_name, json_key)
            )
        environment: dict[str, str] = {}
        for source, destination in tool.prepare_files:
            destination_path = Path(self._format(destination, context))
            if not destination_path.is_absolute():
                destination_path = Path(context["run_dir"]) / destination_path
            destination_path.parent.mkdir(parents=True, exist_ok=True)
            source_path = Path(source).resolve()
            if source_path in secret_sources:
                value = json.loads(source_path.read_text(encoding="utf-8"))
                if not isinstance(value, dict):
                    raise LaunchError(f"密钥配置不是 JSON 对象: {source_path}")
                for environment_name, json_key in secret_sources[source_path]:
                    secret = str(value.get(json_key, ""))
                    if os.environ.get(environment_name) or secret:
                        environment[environment_name] = os.environ.get(environment_name) or secret
                    value[json_key] = ""
                if not (preserve_existing and destination_path.exists()):
                    atomic_json_write(destination_path, value)
            elif preserve_existing and destination_path.exists():
                continue
            elif source_path.is_dir():
                shutil.copytree(source_path, destination_path, dirs_exist_ok=True)
            else:
                shutil.copy2(source_path, destination_path)
        for source, destination in tool.refresh_files:
            destination_path = Path(self._format(destination, context))
            if not destination_path.is_absolute():
                destination_path = Path(context["run_dir"]) / destination_path
            destination_path.parent.mkdir(parents=True, exist_ok=True)
            source_path = Path(source).resolve()
            if source_path.is_dir():
                shutil.copytree(source_path, destination_path, dirs_exist_ok=True)
            else:
                shutil.copy2(source_path, destination_path)
        return environment


    def _build_prompt(self, request: LaunchRequest, run_dir: Path, selected: list[ToolDefinition]) -> str:
        tool_lines = (
            "\n".join(f"- {tool.name}: {tool.description}" for tool in selected)
            or "- 未选择额外 GUI 工具"
        )
        extra = request.user_prompt.strip() or (
            "按界面取证、版本识别、CVE 快速排查、安全验证、自动化扫描和结果整理的顺序推进。"
        )
        today = datetime.now().astimezone().date().isoformat()
        scope_note = ""
        if request.scope.strip() == "*":
            scope_note = (
                "授权解释：* 表示当前项目目标、所选工具发现或回传的项目资产，"
                "以及由这些 IPv4 资产派生的对应 /24 网段均在本项目授权范围内；"
                "所选工具可以继续消费这些资产，但不得扩展到无关互联网目标。\n"
            )
        return f"""你正在协助执行一个已获授权的渗透测试项目。不要只输出可能漏洞清单；对能够安全验证的项目，应完成实际验证并保存证据。

项目名称：{request.project_name}
目标：{request.target}
授权范围：{request.scope}
{scope_note}当前日期：{today}
本次运行目录：{run_dir}
工具根目录：{self.st_root}

本次已启动的工具：
{tool_lines}

必须遵循的工作流：
1. 先读取本次运行目录中的 project.json、scope.txt、activity.log 和各工具状态文件，确认目标、授权范围、已有结果和当前等待步骤。所有请求严格限制在授权范围内。
2. 如果目标有 Web 界面，优先使用 Microsoft Playwright 打开页面并进行界面取证：保存截图，读取可见文本和 DOM，查看响应头、Cookie 属性、页面源代码、静态资源、网络请求、接口路径、版本号、产品名、框架和暴露的管理入口。不得仅凭截图猜测漏洞。
3. 在大范围扫描前先做“可直接验证漏洞”快速排查。根据界面、响应、指纹和版本证据确认产品及可能的补丁水平，再联网检索截至 {today} 的厂商公告、CVE/NVD、CISA KEV 和高质量技术资料。将候选项写入 cve_triage.md，至少包含：CVE、受影响条件、当前证据、补丁条件、验证方式、验证状态和来源。
4. 优先验证与当前产品、版本、组件和暴露端点高度匹配的 CVE。先做非破坏性探测；若可用一个安全请求或无副作用标记完成验证，就先验证该项，再进入常规自动化扫描。不得把“版本可能受影响”直接写成“漏洞已确认”。
5. 如需公开 PoC 或验证工具，只能下载到本次运行目录的 evidence/poc_review/<CVE>/。记录来源 URL、版本或 commit、文件哈希和依赖；先完整审查源码、参数、网络行为、文件写入、命令执行和清理逻辑，再决定是否执行。禁止直接运行未审查脚本、未知二进制文件或来源不明的一键利用工具。
6. 在明确属于授权范围且 PoC 经审查后，可以执行最小影响验证：单目标、低并发、可回滚，只证明漏洞存在。禁止破坏或修改业务数据、拒绝服务、持久化、创建后门、批量扩散、窃取凭据或使用反向 Shell。若验证不可避免会修改系统、执行危险命令或影响可用性，先记录阻塞原因并请求人工确认。
7. CVE 快速排查完成后，再联动 AssetCommander、TscanPlus、路径发现、fscan、nuclei、AWVS、Nessus 等工具推进资产发现、端口与服务识别、目录/API 发现、POC 验证和报告整理。避免对同一资产重复高并发发包，持续读取工具状态，不要在等待时重复启动相同任务。
8. 对每个已确认问题保存最小复现请求/响应、截图、时间、目标、前置条件和清理情况。持续维护 findings.md；未确认项必须标为“待验证”或“可能受影响”，已确认项必须说明证据链。
9. 所有新增结果、命令记录、下载文件和报告写入本次运行目录。发现范围外资产、第三方平台域名或高风险下一步时停止对该对象发包并记录原因。

用户补充要求：
{extra}
"""

    @staticmethod
    def _ps_quote(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    def _agent_script(
        self,
        request: LaunchRequest,
        run_dir: Path,
        *,
        resume: bool = False,
    ) -> Path:
        prompt_path = run_dir / "agent_prompt.txt"
        script_path = run_dir / "launch_agent.ps1"
        pid_path = run_dir / "agent_shell.pid"
        run_quote = self._ps_quote(str(run_dir))
        prompt_quote = self._ps_quote(str(prompt_path))
        pid_quote = self._ps_quote(str(pid_path))
        title = self._ps_quote(
            f"STTool {request.project_name} - "
            f"{self.provider_display_name(request.provider)}"
        )
        if request.provider in {"codexx", "codex"}:
            command_name = request.provider
            invocation = (
                f"& {command_name} --yolo resume --last"
                if resume
                else f"& {command_name} --yolo $prompt"
            )
        else:
            invocation = "& claude --continue" if resume else "& claude $prompt"
        prompt_setup = (
            ""
            if resume
            else f"$prompt = Get-Content -Raw -Encoding UTF8 -LiteralPath {prompt_quote}\n"
        )
        script = (
            "$ErrorActionPreference = 'Stop'\n"
            f"$agentPidPath = {pid_quote}\n"
            "Set-Content -LiteralPath $agentPidPath -Value $PID -Encoding ascii\n"
            "$agentExitCode = 1\n"
            "try {\n"
            "$utf8 = [System.Text.UTF8Encoding]::new()\n"
            "[Console]::InputEncoding = $utf8\n"
            "[Console]::OutputEncoding = $utf8\n"
            "$OutputEncoding = $utf8\n"
            f"$Host.UI.RawUI.WindowTitle = {title}\n"
            f"Set-Location -LiteralPath {run_quote}\n"
            f"{prompt_setup}"
            f"{invocation}\n"
            "$agentExitCode = $LASTEXITCODE\n"
            "} finally {\n"
            "Remove-Item -LiteralPath $agentPidPath -Force -ErrorAction SilentlyContinue\n"
            "}\n"
            "exit $agentExitCode\n"
        )
        script_path.write_text(script, encoding="utf-8-sig")
        return script_path

    def _launch_agent_in_windows_terminal(
        self,
        request: LaunchRequest,
        run_dir: Path,
        script: Path,
        terminal: str,
    ) -> ProcessRecord:
        pid_path = run_dir / "agent_shell.pid"
        try:
            pid_path.unlink()
        except FileNotFoundError:
            pass
        title = (
            f"STTool {request.project_name} - "
            f"{self.provider_display_name(request.provider)}"
        )
        shell = shutil.which("pwsh.exe") or "powershell.exe"
        command = [
            terminal,
            "-w",
            "new",
            "new-tab",
            "--title",
            title,
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
            command,
            cwd=str(run_dir),
            creationflags=CREATE_NEW_PROCESS_GROUP,
            close_fds=True,
        )
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            try:
                shell_pid = int(pid_path.read_text(encoding="ascii").strip())
            except (FileNotFoundError, OSError, UnicodeError, ValueError):
                shell_pid = 0
            if shell_pid and pid_alive(shell_pid):
                return ProcessRecord(
                    component_id="ai_agent",
                    name=f"{self.provider_display_name(request.provider)} Agent",
                    pid=shell_pid,
                    command=command,
                    cwd=str(run_dir),
                    started_at=now_text(),
                )
            time.sleep(0.1)
        if launcher.poll() is None:
            terminate_process_tree(launcher.pid)
        raise LaunchError("Windows Terminal 已启动，但未检测到 Agent 终端进程")

    def _spawn(
        self,
        component_id: str,
        name: str,
        executable: str,
        args: list[str],
        cwd: str,
        new_console: bool,
        environment: dict[str, str] | None = None,
    ) -> ProcessRecord:
        flags = CREATE_NEW_PROCESS_GROUP | (CREATE_NEW_CONSOLE if new_console else 0)
        process = subprocess.Popen(
            [executable, *args],
            cwd=cwd,
            creationflags=flags,
            close_fds=True,
            env={**os.environ, **(environment or {})},
        )
        return ProcessRecord(
            component_id=component_id,
            name=name,
            pid=process.pid,
            command=[executable, *args],
            cwd=cwd,
            started_at=now_text(),
        )

    def _run_context(
        self,
        request: LaunchRequest,
        project_dir: Path,
        run_dir: Path,
    ) -> dict[str, str]:
        return {
            **target_values(request.target),
            "run_dir": str(run_dir),
            "project_dir": str(project_dir),
            "source_dir": str(self.app_dir),
            "st_root": str(self.st_root),
            "project_name": request.project_name.strip(),
            "scope": request.scope.strip(),
            "api_base_url": request.api_base_url.strip().rstrip("/"),
            "model": request.model.strip(),
            "api_key": request.api_key.strip(),
        }

    def _launch_tool(
        self,
        tool: ToolDefinition,
        context: dict[str, str],
        preserve_existing: bool = False,
    ) -> ProcessRecord:
        executable = self._format(tool.executable, context)
        tool_context = {
            **context,
            "tool_dir": str(Path(executable).parent),
        }
        environment = self._prepare_tool(
            tool, tool_context, preserve_existing=preserve_existing
        )
        if tool.uses_shared_ai:
            for name, value in (
                ("OPENAI_BASE_URL", context["api_base_url"]),
                ("OPENAI_MODEL", context["model"]),
                ("OPENAI_API_KEY", context["api_key"]),
            ):
                if value:
                    environment[name] = value
        for name, value in tool.environment:
            formatted = self._format(value, tool_context)
            if formatted:
                environment[name] = formatted
        return self._spawn(
            tool.tool_id,
            tool.name,
            executable,
            [self._format(item, tool_context) for item in tool.args],
            self._format(tool.cwd, tool_context),
            tool.new_console,
            environment,
        )

    def start_standalone(
        self,
        tool_id: str,
        target: str,
        authorization_confirmed: bool,
        api_base_url: str,
        model: str,
        api_key: str = "",
    ) -> StandaloneRunState:
        tool = self.tools.get(tool_id)
        if tool is None:
            raise LaunchError(f"未知工具: {tool_id}")
        if not tool.allow_standalone:
            raise LaunchError(f"{tool.name} 未启用单独执行")
        normalized_target = target.strip()
        if not normalized_target:
            raise LaunchError("请填写本次执行目标")
        if tool.sends_requests and not authorization_confirmed:
            raise LaunchError("必须确认已获得该目标的测试授权")
        available, reason = availability(tool)
        if not available:
            raise LaunchError(f"{tool.name}: {reason}")

        with self._launch_lock():
            run_id, run_dir = self._new_standalone_dir(tool.tool_id)
            (run_dir / "results").mkdir()
            context = {
                **target_values(normalized_target),
                "run_dir": str(run_dir),
                "project_dir": str(run_dir),
                "source_dir": str(self.app_dir),
                "st_root": str(self.st_root),
                "project_name": f"standalone_{tool.tool_id}",
                "scope": normalized_target,
                "api_base_url": api_base_url.strip().rstrip("/"),
                "model": model.strip(),
                "api_key": api_key.strip(),
            }
            executable = self._format(tool.executable, context)
            result_context = {
                **context,
                "tool_dir": str(Path(executable).parent),
            }
            result_paths = []
            for template in tool.result_paths:
                path = Path(self._format(template, result_context))
                if not path.is_absolute():
                    path = run_dir / path
                result_paths.append(str(path))

            created_at = now_text()
            state = StandaloneRunState(
                run_id=run_id,
                tool_id=tool.tool_id,
                tool_name=tool.name,
                target=normalized_target,
                run_dir=str(run_dir),
                created_at=created_at,
                updated_at=created_at,
                status="starting",
                authorization_confirmed=authorization_confirmed,
                result_paths=result_paths,
            )
            state_path = run_dir / "standalone.json"
            atomic_json_write(state_path, state.to_dict())
            (run_dir / "target.txt").write_text(
                normalized_target + "\n", encoding="utf-8"
            )
            append_activity(
                run_dir,
                f"单独执行 {tool.name}，目标 {normalized_target}。",
            )
            record: ProcessRecord | None = None
            try:
                record = self._launch_tool(tool, context)
                state.process = record
                state.status = "running" if pid_alive(record.pid) else "completed"
                state.updated_at = now_text()
                atomic_json_write(state_path, state.to_dict())
                append_activity(run_dir, f"工具已启动，PID {record.pid}。")
            except Exception as exc:
                if record is not None and pid_alive(record.pid):
                    terminate_process_tree(record.pid)
                state.process = record
                state.status = "failed"
                state.error = str(exc)
                state.updated_at = now_text()
                atomic_json_write(state_path, state.to_dict())
                append_activity(run_dir, f"单独执行启动失败：{exc}")
                if isinstance(exc, LaunchError):
                    raise
                raise LaunchError(f"单独执行启动失败: {exc}") from exc
            return state

    def refresh_standalone(self, state: StandaloneRunState) -> StandaloneRunState:
        if state.status in {"failed", "stopped"} or state.process is None:
            return state
        next_status = "running" if pid_alive(state.process.pid) else "completed"
        if next_status == state.status:
            return state
        previous = state.status
        state.status = next_status
        state.process.status = "running" if next_status == "running" else "exited"
        state.updated_at = now_text()
        atomic_json_write(Path(state.run_dir) / "standalone.json", state.to_dict())
        append_activity(state.run_dir, f"单独执行状态变化：{previous} -> {next_status}。")
        return state

    def _launch_agent(
        self,
        request: LaunchRequest,
        run_dir: Path,
        *,
        resume: bool = False,
    ) -> ProcessRecord:
        script = self._agent_script(request, run_dir, resume=resume)
        if sys.platform == "win32" and request.provider in {"codex", "codexx"}:
            terminal = shutil.which("wt.exe")
            if terminal:
                return self._launch_agent_in_windows_terminal(
                    request, run_dir, script, terminal
                )
            append_activity(
                run_dir,
                "未找到 Windows Terminal（wt.exe），本次 Agent 回退到系统控制台。",
            )
        shell = shutil.which("pwsh.exe") or "powershell.exe"
        return self._spawn(
            "ai_agent",
            f"{self.provider_display_name(request.provider)} Agent",
            shell,
            ["-NoLogo", "-ExecutionPolicy", "Bypass", "-File", str(script)],
            str(run_dir),
            True,
        )

    @staticmethod
    def provider_display_name(provider: str) -> str:
        return {
            "codexx": "Codexx",
            "codex": "Codex",
            "claude": "Claude",
        }.get(provider, provider)

    def _request_for_state(
        self,
        state: RunState,
        authorization_confirmed: bool,
        api_key: str = "",
    ) -> tuple[LaunchRequest, list[str]]:
        run_dir = Path(state.run_dir)
        value: dict[str, object] = {}
        try:
            loaded = json.loads((run_dir / "project.json").read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                value = loaded
        except (OSError, json.JSONDecodeError):
            pass
        requested_tools = [
            str(item) for item in value.get("selected_tools", state.selected_tools)
        ]
        skipped_tools = [tool_id for tool_id in requested_tools if tool_id not in self.tools]
        selected_tools = tuple(
            tool_id for tool_id in requested_tools if tool_id in self.tools
        )
        try:
            schema_version = int(value.get("schema_version", 1))
        except (TypeError, ValueError):
            schema_version = 1
        return (
            LaunchRequest(
                project_name=str(value.get("name", state.project_name)),
                target=str(value.get("target", state.target)),
                scope=str(value.get("scope", state.scope)),
                provider=normalize_provider(
                    value.get("provider", state.provider), schema_version
                ),
                model=str(value.get("model", state.model)),
                selected_tools=selected_tools,
                user_prompt=str(value.get("user_prompt", "")),
                authorization_confirmed=authorization_confirmed,
                api_base_url=str(value.get("api_base_url", state.api_base_url)),
                api_key=api_key,
            ),
            skipped_tools,
        )

    def start(self, request: LaunchRequest) -> RunState:
        with self._launch_lock():
            selected = self.preflight(request)
            run_id, project_dir, run_dir = self._new_run_dir(request.project_name)
            (run_dir / "results").mkdir()
            append_activity(
                run_dir,
                f"创建运行实例 {run_id}，目标 {request.target.strip()}。",
            )
            context = {
                **target_values(request.target),
                "run_dir": str(run_dir),
                "project_dir": str(project_dir),
                "source_dir": str(self.app_dir),
                "st_root": str(self.st_root),
                "project_name": request.project_name.strip(),
                "scope": request.scope.strip(),
                "api_base_url": request.api_base_url.strip().rstrip("/"),
                "model": request.model.strip(),
                "api_key": request.api_key.strip(),
            }
            created_at = now_text()
            state = RunState(
                run_id=run_id,
                project_name=request.project_name.strip(),
                target=request.target.strip(),
                scope=request.scope.strip(),
                provider=request.provider,
                model=request.model.strip(),
                selected_tools=list(request.selected_tools),
                run_dir=str(run_dir),
                created_at=created_at,
                updated_at=created_at,
                status="starting",
                api_base_url=request.api_base_url.strip().rstrip("/"),
            )
            state_path = run_dir / "run.json"
            atomic_json_write(state_path, state.to_dict())

            project_value = {
                "schema_version": 2,
                "name": request.project_name.strip(),
                "target": request.target.strip(),
                "scope": request.scope.strip(),
                "provider": request.provider,
                "model": request.model.strip(),
                "api_base_url": request.api_base_url.strip().rstrip("/"),
                "selected_tools": list(request.selected_tools),
                "user_prompt": request.user_prompt,
                "last_run_id": run_id,
                "updated_at": now_text(),
            }
            atomic_json_write(project_dir / "project.json", project_value)
            atomic_json_write(run_dir / "project.json", project_value)
            (run_dir / "scope.txt").write_text(request.scope.strip() + "\n", encoding="utf-8")
            prompt = self._build_prompt(request, run_dir, selected)
            (run_dir / "agent_prompt.txt").write_text(prompt, encoding="utf-8")
            append_activity(
                run_dir,
                "项目配置已保存；准备启动所选工具和本地 Agent。",
            )

            started: list[ProcessRecord] = []
            try:
                for tool in selected:
                    append_activity(run_dir, f"正在启动工具：{tool.name}。")
                    record = self._launch_tool(tool, context)
                    started.append(record)
                    append_activity(
                        run_dir, f"工具已启动：{tool.name}，PID {record.pid}。"
                    )

                agent_name = self.provider_display_name(request.provider)
                append_activity(run_dir, f"正在启动本地 Agent：{agent_name}。")
                agent_record = self._launch_agent(request, run_dir)
                started.append(agent_record)
                append_activity(
                    run_dir,
                    f"本地 Agent 已启动：{agent_name}，PID {agent_record.pid}。",
                )
                state.processes = started
                atomic_json_write(state_path, state.to_dict())
                time.sleep(0.8)
                dead = [item.name for item in started if not pid_alive(item.pid)]
                if dead:
                    raise LaunchError(f"组件启动后立即退出: {', '.join(dead)}")
                for item in started:
                    if item.component_id == "asset_commander":
                        reconcile_component_state(
                            run_dir,
                            item.component_id,
                            "running",
                            f"组件进程 PID {item.pid} 正在运行",
                        )
            except Exception as exc:
                append_activity(run_dir, f"启动失败，正在回滚已启动组件：{exc}")
                for item in reversed(started):
                    terminate_process_tree(item.pid)
                state.processes = started
                state.status = "failed"
                state.error = str(exc)
                state.updated_at = now_text()
                atomic_json_write(state_path, state.to_dict())
                if isinstance(exc, LaunchError):
                    raise
                raise LaunchError(f"启动事务已回滚: {exc}") from exc

            state.status = "running"
            state.updated_at = now_text()
            atomic_json_write(state_path, state.to_dict())
            append_activity(run_dir, "运行实例启动完成。")
            return state

    def recover(
        self,
        state: RunState,
        authorization_confirmed: bool,
        api_base_url: str | None = None,
        model: str | None = None,
        api_key: str = "",
    ) -> RunState:
        with self._launch_lock():
            run_dir = Path(state.run_dir).resolve()
            append_activity(run_dir, "收到恢复实例请求，正在检查现有组件。")
            request, skipped_tools = self._request_for_state(
                state, authorization_confirmed, api_key
            )
            if api_base_url is not None or model is not None:
                request = LaunchRequest(
                    project_name=request.project_name,
                    target=request.target,
                    scope=request.scope,
                    provider=request.provider,
                    model=request.model if model is None else model,
                    selected_tools=request.selected_tools,
                    user_prompt=request.user_prompt,
                    authorization_confirmed=request.authorization_confirmed,
                    api_base_url=(
                        request.api_base_url
                        if api_base_url is None
                        else api_base_url
                    ),
                    api_key=api_key,
                )
            recovery_request = LaunchRequest(
                project_name=request.project_name,
                target=request.target,
                scope=request.scope,
                provider=request.provider,
                model=request.model,
                selected_tools=tuple(
                    tool_id
                    for tool_id in request.selected_tools
                    if self.tools[tool_id].restart_on_recovery
                ),
                user_prompt=request.user_prompt,
                authorization_confirmed=request.authorization_confirmed,
                api_base_url=request.api_base_url,
                api_key=api_key,
            )
            selected = self.preflight(recovery_request)
            self.refresh(state)
            project_dir = run_dir.parent.parent
            context = self._run_context(request, project_dir, run_dir)
            active_components = {
                process.component_id
                for process in state.processes
                if pid_alive(process.pid)
            }
            recoverable = [
                tool
                for tool in selected
                if tool.restart_on_recovery and tool.tool_id not in active_components
            ]
            restart_agent = "ai_agent" not in active_components
            if not recoverable and not restart_agent:
                append_activity(run_dir, "恢复取消：常驻工具和 Agent 仍在运行。")
                raise LaunchError("没有需要恢复的组件；常驻工具和 Agent 仍在运行")

            started: list[ProcessRecord] = []
            try:
                for tool in recoverable:
                    append_activity(run_dir, f"正在恢复工具：{tool.name}。")
                    record = self._launch_tool(
                        tool, context, preserve_existing=True
                    )
                    started.append(record)
                    append_activity(
                        run_dir, f"工具已恢复：{tool.name}，PID {record.pid}。"
                    )
                if restart_agent:
                    agent_name = self.provider_display_name(request.provider)
                    append_activity(
                        run_dir, f"正在恢复本地 Agent 会话：{agent_name}。"
                    )
                    record = self._launch_agent(request, run_dir, resume=True)
                    started.append(record)
                    append_activity(
                        run_dir,
                        f"本地 Agent 会话已恢复：{agent_name}，PID {record.pid}。",
                    )
                time.sleep(0.8)
                dead = [item.name for item in started if not pid_alive(item.pid)]
                if dead:
                    raise LaunchError(f"恢复组件启动后立即退出: {', '.join(dead)}")
                for item in started:
                    if item.component_id == "asset_commander":
                        reconcile_component_state(
                            run_dir,
                            item.component_id,
                            "running",
                            f"组件进程 PID {item.pid} 正在运行",
                        )
            except Exception as exc:
                append_activity(run_dir, f"恢复失败：{exc}")
                for item in reversed(started):
                    terminate_process_tree(item.pid)
                raise

            replaced_ids = {item.component_id for item in started}
            state.processes = [
                process
                for process in state.processes
                if process.component_id not in replaced_ids
            ] + started
            state.project_name = request.project_name.strip()
            state.target = request.target.strip()
            state.scope = request.scope.strip()
            state.provider = request.provider
            state.model = request.model.strip()
            state.api_base_url = request.api_base_url.strip().rstrip("/")
            state.selected_tools = list(request.selected_tools)
            state.recovery_count += 1
            state.recovery_history.append(
                {
                    "recovered_at": now_text(),
                    "components": [item.component_id for item in started],
                    "skipped_removed_tools": skipped_tools,
                }
            )
            state.status = "running"
            state.error = ""
            state.updated_at = now_text()
            atomic_json_write(run_dir / "run.json", state.to_dict())
            append_activity(
                run_dir,
                "恢复完成：" + "、".join(item.name for item in started) + "。",
            )
            return state

    def refresh(self, state: RunState) -> RunState:
        previous_state_status = state.status
        running = 0
        for process in state.processes:
            if process.status == "stopped":
                continue
            previous_status = process.status
            if pid_alive(process.pid):
                process.status = "running"
                running += 1
            else:
                process.status = "exited"
            if process.status != previous_status:
                append_activity(
                    state.run_dir,
                    f"组件状态变化：{process.name}（PID {process.pid}）"
                    f" {previous_status} -> {process.status}。",
                )
                if process.status == "exited":
                    reconcile_component_state(
                        state.run_dir,
                        process.component_id,
                        "interrupted",
                        f"组件进程 PID {process.pid} 已退出，保留断点供恢复",
                    )
        if state.status != "failed":
            state.status = "running" if running else "completed"
        if state.status != previous_state_status:
            append_activity(
                state.run_dir,
                f"实例状态变化：{previous_state_status} -> {state.status}。",
            )
        state.updated_at = now_text()
        atomic_json_write(Path(state.run_dir) / "run.json", state.to_dict())
        return state

    def stop(self, state: RunState) -> RunState:
        append_activity(state.run_dir, "收到停止实例请求。")
        for process in reversed(state.processes):
            if pid_alive(process.pid):
                append_activity(
                    state.run_dir,
                    f"正在停止组件：{process.name}，PID {process.pid}。",
                )
                terminate_process_tree(process.pid)
            process.status = "stopped"
            reconcile_component_state(
                state.run_dir,
                process.component_id,
                "stopped",
                "实例已由 STTool 停止，保留断点供恢复",
            )
        state.status = "stopped"
        state.updated_at = now_text()
        atomic_json_write(Path(state.run_dir) / "run.json", state.to_dict())
        append_activity(state.run_dir, "实例已停止。")
        return state

    def list_runs(self) -> list[RunState]:
        states: list[RunState] = []
        for path in self.projects_dir.glob("*/runs/*/run.json"):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                states.append(RunState.from_dict(value))
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                continue
        return sorted(states, key=lambda item: item.created_at, reverse=True)

    def load_project(self, name: str) -> dict[str, object]:
        path = self.projects_dir / safe_project_name(name) / "project.json"
        if not path.is_file():
            return {}
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def list_projects(self) -> list[str]:
        names = []
        for path in self.projects_dir.glob("*/project.json"):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                names.append(str(value.get("name") or path.parent.name))
            except (OSError, json.JSONDecodeError):
                names.append(path.parent.name)
        return sorted(set(names), key=str.casefold)
