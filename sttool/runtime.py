from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

from .models import LaunchRequest, ProcessRecord, RunState, ToolDefinition
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


def safe_project_name(value: str) -> str:
    cleaned = re.sub(r"[<>:\"/\\|?*\x00-\x1f]", "_", value.strip())
    cleaned = re.sub(r"\s+", "_", cleaned).strip("._ ")
    return cleaned[:80] or "project"


def target_values(target: str) -> dict[str, str]:
    raw = target.strip()
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
        self.projects_dir.mkdir(parents=True, exist_ok=True)

    def provider_health(self, provider: str) -> tuple[bool, str]:
        provider = provider.lower()
        if provider not in {"codex", "claude"}:
            return False, "不支持的 AI CLI"
        if shutil.which(provider) is None:
            return False, f"未安装 {provider} CLI"

        command = (
            "& codex login status *> $null; exit $LASTEXITCODE"
            if provider == "codex"
            else "& claude auth status *> $null; exit $LASTEXITCODE"
        )
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoLogo", "-NoProfile", "-Command", command],
                capture_output=True,
                creationflags=CREATE_NO_WINDOW,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, f"登录检测失败: {exc}"
        if result.returncode != 0:
            return False, f"{provider} CLI 未登录或配置无效"
        return True, "已安装并登录"

    def preflight(self, request: LaunchRequest) -> list[ToolDefinition]:
        if not request.project_name.strip():
            raise LaunchError("请填写项目名称")
        if not request.target.strip():
            raise LaunchError("请填写目标")
        if not request.scope.strip():
            raise LaunchError("请填写授权范围")
        if not request.authorization_confirmed:
            raise LaunchError("必须确认已获得该目标的测试授权")

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

    def _format(self, value: str, context: dict[str, str]) -> str:
        return value.format_map(context)

    def _prepare_tool(self, tool: ToolDefinition, context: dict[str, str]) -> dict[str, str]:
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
            if source_path.is_dir():
                shutil.copytree(source_path, destination_path, dirs_exist_ok=True)
            elif source_path in secret_sources:
                value = json.loads(source_path.read_text(encoding="utf-8"))
                if not isinstance(value, dict):
                    raise LaunchError(f"密钥配置必须是 JSON 对象: {source_path}")
                for environment_name, json_key in secret_sources[source_path]:
                    secret = str(value.get(json_key, ""))
                    if os.environ.get(environment_name) or secret:
                        environment[environment_name] = os.environ.get(environment_name) or secret
                    value[json_key] = ""
                atomic_json_write(destination_path, value)
            else:
                shutil.copy2(source_path, destination_path)
        return environment

    def _build_prompt(self, request: LaunchRequest, run_dir: Path, selected: list[ToolDefinition]) -> str:
        tool_lines = "\n".join(f"- {tool.name}: {tool.description}" for tool in selected) or "- 未选择额外 GUI 工具"
        extra = request.user_prompt.strip() or "按资产发现、路径发现、验证和结果整理的顺序推进。"
        return f"""你正在协助执行一个已获授权的渗透测试项目。

项目名称：{request.project_name}
目标：{request.target}
授权范围：{request.scope}
本次运行目录：{run_dir}
工具根目录：{self.st_root}

本次已启动的工具：
{tool_lines}

工作要求：
1. 严格限制在授权范围内，不攻击范围外资产，不执行破坏性操作。
2. 先读取本次运行目录中的 project.json 和 scope.txt，再开始工作。
3. 复用工具根目录中已有工具；所有新增结果、命令记录和报告写入本次运行目录。
4. 先做低风险发现与验证，对可能造成数据修改、拒绝服务或持久化的操作必须先征得人工确认。
5. 持续维护 findings.md，记录证据、复现条件、风险和下一步。

用户补充要求：
{extra}
"""

    @staticmethod
    def _ps_quote(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    def _agent_script(self, request: LaunchRequest, run_dir: Path) -> Path:
        prompt_path = run_dir / "agent_prompt.txt"
        script_path = run_dir / "launch_agent.ps1"
        model_arg = ""
        if request.model.strip():
            model_arg = f" --model {self._ps_quote(request.model.strip())}"
        run_quote = self._ps_quote(str(run_dir))
        root_quote = self._ps_quote(str(self.st_root))
        prompt_quote = self._ps_quote(str(prompt_path))
        title = self._ps_quote(f"STTool {request.project_name} - {request.provider}")
        if request.provider == "codex":
            invocation = (
                f"& codex --cd {run_quote} --add-dir {root_quote}"
                f" --sandbox danger-full-access --ask-for-approval never{model_arg} $prompt"
            )
        else:
            invocation = (
                f"& claude --add-dir {root_quote} --permission-mode auto{model_arg} $prompt"
            )
        script = (
            "$ErrorActionPreference = 'Stop'\n"
            f"$Host.UI.RawUI.WindowTitle = {title}\n"
            f"Set-Location -LiteralPath {run_quote}\n"
            f"$prompt = Get-Content -Raw -LiteralPath {prompt_quote}\n"
            f"{invocation}\n"
            "exit $LASTEXITCODE\n"
        )
        script_path.write_text(script, encoding="utf-8-sig")
        return script_path

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

    def start(self, request: LaunchRequest) -> RunState:
        with self._launch_lock():
            selected = self.preflight(request)
            run_id, project_dir, run_dir = self._new_run_dir(request.project_name)
            (run_dir / "results").mkdir()
            context = {
                **target_values(request.target),
                "run_dir": str(run_dir),
                "project_dir": str(project_dir),
                "source_dir": str(self.app_dir),
                "st_root": str(self.st_root),
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
            )
            state_path = run_dir / "run.json"
            atomic_json_write(state_path, state.to_dict())

            project_value = {
                "schema_version": 1,
                "name": request.project_name.strip(),
                "target": request.target.strip(),
                "scope": request.scope.strip(),
                "provider": request.provider,
                "model": request.model.strip(),
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

            started: list[ProcessRecord] = []
            try:
                for tool in selected:
                    environment = self._prepare_tool(tool, context)
                    executable = self._format(tool.executable, context)
                    args = [self._format(item, context) for item in tool.args]
                    cwd = self._format(tool.cwd, context)
                    record = self._spawn(
                        tool.tool_id,
                        tool.name,
                        executable,
                        args,
                        cwd,
                        tool.new_console,
                        environment,
                    )
                    started.append(record)

                script = self._agent_script(request, run_dir)
                started.append(
                    self._spawn(
                        "ai_agent",
                        f"{request.provider.title()} Agent",
                        "powershell.exe",
                        ["-NoLogo", "-ExecutionPolicy", "Bypass", "-File", str(script)],
                        str(run_dir),
                        True,
                        None,
                    )
                )
                state.processes = started
                atomic_json_write(state_path, state.to_dict())
                time.sleep(0.8)
                dead = [item.name for item in started if not pid_alive(item.pid)]
                if dead:
                    raise LaunchError(f"组件启动后立即退出: {', '.join(dead)}")
            except Exception as exc:
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
            return state

    def refresh(self, state: RunState) -> RunState:
        running = 0
        for process in state.processes:
            if process.status == "stopped":
                continue
            if pid_alive(process.pid):
                process.status = "running"
                running += 1
            else:
                process.status = "exited"
        if state.status != "failed":
            state.status = "running" if running else "completed"
        state.updated_at = now_text()
        atomic_json_write(Path(state.run_dir) / "run.json", state.to_dict())
        return state

    def stop(self, state: RunState) -> RunState:
        for process in reversed(state.processes):
            if pid_alive(process.pid):
                terminate_process_tree(process.pid)
            process.status = "stopped"
        state.status = "stopped"
        state.updated_at = now_text()
        atomic_json_write(Path(state.run_dir) / "run.json", state.to_dict())
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
