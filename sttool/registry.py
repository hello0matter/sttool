from __future__ import annotations

import shutil
import sys
from pathlib import Path

from .models import ToolDefinition


DEFAULT_ST_ROOT = Path(r"D:\tmp\anjian\pj\st")


def _pythonw() -> str:
    candidate = Path(sys.executable).with_name("pythonw.exe")
    return str(candidate if candidate.exists() else Path(sys.executable))


def default_tools(st_root: Path = DEFAULT_ST_ROOT) -> tuple[ToolDefinition, ...]:
    asset = st_root / "tmp" / "AssetCommander"
    semantic = st_root / "tmp" / "semantic-recursive-dirscan"
    asset_python = asset / ".venv" / "Scripts" / "pythonw.exe"
    if not asset_python.exists():
        asset_python = asset / ".venv" / "Scripts" / "python.exe"

    return (
        ToolDefinition(
            tool_id="asset_commander",
            name="AssetCommander",
            category="资产发现",
            description="资产面发现与项目化结果管理",
            executable=str(asset_python),
            args=(str(asset / "main.py"),),
            cwd="{run_dir}/tool_data/asset_commander",
            default_selected=True,
            prepare_files=((str(asset / "config.json"), "tool_data/asset_commander/config.json"),),
        ),
        ToolDefinition(
            tool_id="semantic_dirscan",
            name="AI 路径发现",
            category="路径发现",
            description="semantic-recursive-dirscan 工程 GUI",
            executable=_pythonw(),
            args=("{run_dir}/tool_data/semantic/semantic_recursive_dirscan.py", "--gui"),
            cwd="{run_dir}/tool_data/semantic",
            default_selected=True,
            prepare_files=(
                (str(semantic / "semantic_recursive_dirscan.py"), "tool_data/semantic/semantic_recursive_dirscan.py"),
                (str(semantic / "config.json"), "tool_data/semantic/config.json"),
                (str(semantic / "dict"), "tool_data/semantic/dict"),
            ),
            secret_env=(("OPENAI_API_KEY", str(semantic / "config.json"), "ai_api_key"),),
        ),
        ToolDefinition(
            tool_id="fscan",
            name="fscan 基础探测",
            category="自动扫描",
            description="对目标主机执行基础端口和服务探测",
            executable=str(st_root / "fscan" / "fscan.exe"),
            args=("-h", "{target_host}", "-o", "{run_dir}/results/fscan.txt"),
            cwd="{run_dir}",
            sends_requests=True,
            new_console=True,
        ),
        ToolDefinition(
            tool_id="nuclei",
            name="nuclei 模板扫描",
            category="自动扫描",
            description="对目标 URL 执行本地 nuclei 模板检查",
            executable=str(st_root / "nuclei" / "nuclei.exe"),
            args=("-u", "{target}", "-o", "{run_dir}/results/nuclei.txt"),
            cwd="{run_dir}",
            sends_requests=True,
            new_console=True,
        ),
        ToolDefinition(
            tool_id="tscan_plus",
            name="TscanPlus",
            category="专项工具",
            description="综合渗透测试 GUI",
            executable=str(st_root / "TscanPlus_Win_Amd64" / "TscanPlus_Win_Amd64.exe"),
            cwd=str(st_root / "TscanPlus_Win_Amd64"),
        ),
        ToolDefinition(
            tool_id="safe_poc_gui",
            name="POC 工具箱",
            category="专项工具",
            description="本地 POC 管理与验证 GUI",
            executable=str(st_root / "POC工具箱" / "POC工具箱.exe"),
            cwd=str(st_root / "POC工具箱"),
        ),
    )


def command_available(command: str) -> bool:
    path = Path(command)
    if path.is_absolute() or path.parent != Path("."):
        return path.is_file()
    return shutil.which(command) is not None


def availability(tool: ToolDefinition) -> tuple[bool, str]:
    if not command_available(tool.executable):
        return False, f"入口不存在: {tool.executable}"
    for source, _destination in tool.prepare_files:
        if not Path(source).exists():
            return False, f"依赖文件不存在: {source}"
    for _environment_name, source, _json_key in tool.secret_env:
        if not Path(source).is_file():
            return False, f"密钥配置不存在: {source}"
    return True, "可用"
