from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from sttool.app import LauncherApp
from sttool.registry import availability
from sttool.runtime import RuntimeManager
from sttool.tool_store import ToolStore


APP_DIR = Path(__file__).resolve().parent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="STTool penetration-test project launcher")
    parser.add_argument("--doctor", action="store_true", help="check tools and AI CLI login state")
    parser.add_argument("--list-tools", action="store_true", help="print registered tools as JSON")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if (
        sys.platform == "win32"
        and not args.doctor
        and not args.list_tools
        and Path(sys.executable).name.lower() != "pythonw.exe"
    ):
        pythonw = Path(sys.executable).with_name("pythonw.exe")
        if pythonw.is_file():
            subprocess.Popen(
                [str(pythonw), str(Path(__file__).resolve())],
                cwd=APP_DIR,
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
                close_fds=True,
            )
            return 0
    tool_store = ToolStore(APP_DIR / "tools.json")
    tools = tool_store.tools()
    manager = RuntimeManager(APP_DIR, tools, st_root=tool_store.st_root)
    if args.list_tools:
        print(json.dumps([
            {
                "id": tool.tool_id,
                "name": tool.name,
                "category": tool.category,
                "available": availability(tool)[0],
                "detail": availability(tool)[1],
                "path": tool_store.location_for(tool.tool_id, tool),
            }
            for tool in tools
        ], ensure_ascii=False, indent=2))
        return 0
    if args.doctor:
        if tool_store.load_error:
            print(f"[FAIL] 工具配置: {tool_store.load_error}")
        for tool in tools:
            healthy, detail = availability(tool)
            print(f"[{'OK' if healthy else 'FAIL'}] {tool.name}: {detail}")
        for provider in ("codexx", "codex"):
            healthy, detail = manager.provider_health(provider)
            display = manager.provider_display_name(provider)
            print(f"[{'OK' if healthy else 'FAIL'}] {display}: {detail}")
        return 0

    app = LauncherApp(manager, tools, tool_store)
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
