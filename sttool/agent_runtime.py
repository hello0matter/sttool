from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

import psutil


def powershell_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def agent_terminal_window_name(app_dir: str | Path) -> str:
    marker = str(Path(app_dir).resolve()).replace("/", "\\").casefold()
    digest = hashlib.sha256(marker.encode("utf-8")).hexdigest()[:10]
    return f"STTool-Agents-{digest}"


def prompt_file_bootstrap(prompt_path: str | Path) -> str:
    path = Path(prompt_path).resolve()
    return (
        f"请先完整读取 UTF-8 文件 {path}，并严格遵循其中全部要求继续工作。"
        "不要跳过或概括该文件；所有结果继续写入文件中指定的项目运行目录。"
    )


def _normalized(value: object) -> str:
    return str(value or "").replace("/", "\\").casefold()


def is_agent_shell_process_info(info: dict[str, Any], run_dir: str | Path) -> bool:
    name = _normalized(info.get("name"))
    executable = _normalized(info.get("exe"))
    if not any(
        shell in name or shell in executable for shell in ("powershell", "pwsh")
    ):
        return False
    path = Path(run_dir)
    markers = {
        _normalized(path).rstrip("\\"),
        _normalized(path.resolve()).rstrip("\\"),
    }
    command = _normalized(" ".join(str(item) for item in info.get("cmdline") or []))
    for marker in markers:
        if not marker or marker not in command:
            continue
        initial_script = f"{marker}\\launch_agent.ps1"
        batch_marker = f"{marker}\\agent_batches\\"
        if initial_script in command or (
            batch_marker in command and "\\launch.ps1" in command
        ):
            return True
    return False


def agent_shell_pids_for_run(run_dir: str | Path) -> list[int]:
    matches: list[int] = []
    for process in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            info = process.info
            if is_agent_shell_process_info(info, run_dir):
                matches.append(int(info["pid"]))
        except (psutil.Error, OSError, TypeError, ValueError):
            continue
    return sorted(set(matches))


def coordinator_owner_matches(owner: dict[str, Any], run_dir: str | Path) -> bool:
    try:
        pid = int(owner.get("pid") or 0)
        creation_token = int(owner.get("creation_token") or 0)
    except (TypeError, ValueError):
        return False
    if pid <= 0 or creation_token <= 0:
        return False
    try:
        process = psutil.Process(pid)
        actual_token = int(process.create_time() * 1_000_000)
        command = _normalized(" ".join(process.cmdline()))
    except (psutil.Error, OSError, ValueError):
        return False
    path = Path(run_dir)
    markers = {_normalized(path), _normalized(path.resolve())}
    return (
        actual_token == creation_token
        and any(marker and marker in command for marker in markers)
        and "sttool.project_coordinator" in command
    )


def claim_coordinator_owner(owner_path: Path, run_dir: Path) -> dict[str, Any] | None:
    owner_path.parent.mkdir(parents=True, exist_ok=True)
    current = {
        "pid": os.getpid(),
        "creation_token": int(psutil.Process().create_time() * 1_000_000),
        "run_dir": str(run_dir.resolve()),
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    payload = json.dumps(current, ensure_ascii=False, indent=2).encode("utf-8")
    for _attempt in range(3):
        try:
            descriptor = os.open(
                owner_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            )
        except FileExistsError:
            try:
                existing = json.loads(owner_path.read_text(encoding="utf-8-sig"))
            except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
                try:
                    fresh_claim = time.time() - owner_path.stat().st_mtime < 5
                except OSError:
                    fresh_claim = False
                if fresh_claim:
                    return None
                existing = {}
            if isinstance(existing, dict) and coordinator_owner_matches(
                existing, run_dir
            ):
                return None
            try:
                owner_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                time.sleep(0.05)
            continue
        try:
            os.write(descriptor, payload)
        finally:
            os.close(descriptor)
        return current
    return None


def release_coordinator_owner(owner_path: Path, owner: dict[str, Any]) -> None:
    try:
        existing = json.loads(owner_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        return
    if not isinstance(existing, dict):
        return
    try:
        same_owner = int(existing.get("pid") or 0) == int(
            owner.get("pid") or 0
        ) and int(existing.get("creation_token") or 0) == int(
            owner.get("creation_token") or 0
        )
    except (TypeError, ValueError):
        return
    if not same_owner:
        return
    try:
        owner_path.unlink()
    except FileNotFoundError:
        pass
