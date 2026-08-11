from __future__ import annotations

import os
import shutil
import subprocess

from .runtime import (
    CREATE_NO_WINDOW,
    agent_base_url_environment,
    agent_cli_arguments,
)


TEST_PROMPT = "只回复 STTOOL_OK，不调用任何工具。"


def test_agent_connection(
    provider: str,
    model: str = "",
    reasoning_effort: str = "",
    base_url: str = "",
    api_key: str = "",
    timeout: int = 90,
) -> tuple[bool, str]:
    executable = shutil.which(provider)
    if not executable:
        return False, f"未安装或找不到 {provider} CLI"

    command = [
        executable,
        *agent_cli_arguments(provider, model, reasoning_effort),
        TEST_PROMPT,
    ]
    if executable.lower().endswith((".cmd", ".bat")):
        command = ["cmd.exe", "/d", "/s", "/c", *command]

    environment = os.environ.copy()
    environment.update(agent_base_url_environment(provider, base_url))
    key = api_key.strip()
    if provider == "claude":
        environment.pop("OPENAI_API_KEY", None)
        if key:
            environment["ANTHROPIC_API_KEY"] = key
    elif key:
        environment["OPENAI_API_KEY"] = key

    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=environment,
            creationflags=CREATE_NO_WINDOW,
            timeout=max(timeout, 1),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, f"实际请求超过 {timeout} 秒，已停止等待"
    except OSError as exc:
        return False, f"无法启动 {provider} CLI：{exc}"

    output = "\n".join(
        line.strip()
        for line in f"{result.stdout}\n{result.stderr}".splitlines()
        if line.strip()
    )
    if key:
        output = output.replace(key, "***")
    summary = output[-600:] if output else "CLI 未返回文字"
    if result.returncode == 0:
        return True, f"实际请求成功（退出码 0）\n{summary}"
    return False, f"实际请求失败（退出码 {result.returncode}）\n{summary}"


__all__ = ["test_agent_connection"]
