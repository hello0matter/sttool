from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

from .agent_runtime import (
    agent_terminal_window_name,
    powershell_quote,
    prompt_file_bootstrap,
)
from .asset_bus import atomic_json_write, now_text
from .runtime import (
    agent_cli_arguments,
    pid_alive,
    process_creation_token,
)


CREATE_NEW_CONSOLE = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
CREATE_NEW_PROCESS_GROUP = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)


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
    exit_path = batch_dir / "agent_exit.json"
    bootstrap = powershell_quote(prompt_file_bootstrap(prompt_path))
    if provider in {"codex", "codexx"}:
        options = " ".join(
            item if item in {"--yolo", "-m", "-c"} else powershell_quote(item)
            for item in agent_cli_arguments(provider, agent_model, reasoning_effort)
        )
        invocation = f"& {provider} {options} $bootstrapPrompt"
    else:
        invocation = "& claude $bootstrapPrompt"
    script = (
        "$ErrorActionPreference = 'Stop'\n"
        "$utf8 = [System.Text.UTF8Encoding]::new($false)\n"
        "[Console]::InputEncoding = $utf8\n"
        "[Console]::OutputEncoding = $utf8\n"
        "$OutputEncoding = $utf8\n"
        f"$Host.UI.RawUI.WindowTitle = {powershell_quote(f'STTool {project_name} - {provider} 增量批次')}\n"
        f"$agentPidPath = {powershell_quote(str(pid_path))}\n"
        f"$agentExitPath = {powershell_quote(str(exit_path))}\n"
        "Set-Content -LiteralPath $agentPidPath -Value $PID -Encoding ascii\n"
        "$agentExitCode = 1\n"
        "$agentError = ''\n"
        "try {\n"
        f"Set-Location -LiteralPath {powershell_quote(str(batch_dir.parents[1]))}\n"
        f"$bootstrapPrompt = {bootstrap}\n"
        f"{invocation}\n"
        "$agentExitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }\n"
        "} catch {\n"
        "$agentError = ($_ | Out-String).Trim()\n"
        "if ($null -ne $LASTEXITCODE) { $agentExitCode = [int]$LASTEXITCODE }\n"
        "} finally {\n"
        "$exitState = @{ exit_code = $agentExitCode; completed_at = (Get-Date).ToString('o'); error = $agentError } | ConvertTo-Json -Compress\n"
        "[System.IO.File]::WriteAllText($agentExitPath, $exitState, [System.Text.UTF8Encoding]::new($false))\n"
        "Remove-Item -LiteralPath $agentPidPath -Force -ErrorAction SilentlyContinue\n"
        "}\n"
        "exit 0\n"
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
    terminal_window: str = "",
) -> tuple[int, Path]:
    batch_dir = run_dir / "agent_batches" / f"{batch_number:04d}"
    batch_dir.mkdir(parents=True, exist_ok=True)
    launch_lock = batch_dir / "launching.lock"
    try:
        descriptor = os.open(
            launch_lock,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
        )
    except FileExistsError as exc:
        try:
            stale = time.time() - launch_lock.stat().st_mtime > 30
        except OSError:
            stale = False
        if stale:
            launch_lock.unlink(missing_ok=True)
            return launch_agent_batch(
                run_dir,
                provider,
                project_name,
                batch_number,
                prompt,
                agent_model,
                reasoning_effort,
                terminal_window,
            )
        raise RuntimeError(f"Agent 批次 {batch_number} 正在由另一个协调器启动") from exc
    os.close(descriptor)
    try:
        (batch_dir / "prompt.txt").write_text(prompt, encoding="utf-8")
        script, pid_path = write_agent_batch_script(
            batch_dir, provider, project_name, agent_model, reasoning_effort
        )
        try:
            pid_path.unlink()
        except FileNotFoundError:
            pass
        (batch_dir / "agent_exit.json").unlink(missing_ok=True)
        shell = shutil.which("pwsh.exe") or "powershell.exe"
        terminal = shutil.which("wt.exe")
        if terminal:
            window_name = terminal_window or agent_terminal_window_name(
                Path(__file__).resolve().parents[1]
            )
            command = [
                terminal,
                "-w",
                window_name,
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
                    "terminal_window": window_name if terminal else "",
                    "status": "running",
                }
                atomic_json_write(batch_dir / "batch.json", metadata)
                return pid, batch_dir
            if launcher.poll() is not None:
                break
            time.sleep(0.1)
        raise RuntimeError("Agent 终端已启动，但未检测到批次 PowerShell 进程")
    finally:
        launch_lock.unlink(missing_ok=True)
