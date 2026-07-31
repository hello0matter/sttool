from __future__ import annotations

import shutil
import sys
from pathlib import Path

from .models import ToolDefinition


DEFAULT_ST_ROOT = Path(r"D:\tmp\anjian\pj\st")
BUILTIN_TOOL_IDS = (
    "asset_commander",
    "semantic_dirscan",
    "fscan",
    "nuclei",
    "tscan_plus",
)


def default_locations(st_root: Path = DEFAULT_ST_ROOT) -> dict[str, str]:
    return {
        "asset_commander": str(st_root / "tmp" / "AssetCommander"),
        "semantic_dirscan": str(st_root / "tmp" / "semantic-recursive-dirscan"),
        "fscan": str(st_root / "fscan" / "fscan.exe"),
        "nuclei": str(st_root / "nuclei" / "nuclei.exe"),
        "tscan_plus": str(st_root / "TscanPlus_Win_Amd64" / "TscanPlus_Win_Amd64.exe"),
    }


def builtin_location_kind(tool_id: str) -> str:
    return "directory" if tool_id in {"asset_commander", "semantic_dirscan"} else "file"


def _pythonw() -> str:
    candidate = Path(sys.executable).with_name("pythonw.exe")
    return str(candidate if candidate.exists() else Path(sys.executable))


def default_tools(
    st_root: Path = DEFAULT_ST_ROOT,
    locations: dict[str, str] | None = None,
) -> tuple[ToolDefinition, ...]:
    resolved_locations = default_locations(st_root)
    resolved_locations.update(
        {
            tool_id: str(path).strip()
            for tool_id, path in (locations or {}).items()
            if tool_id in BUILTIN_TOOL_IDS and str(path).strip()
        }
    )
    asset = Path(resolved_locations["asset_commander"])
    semantic = Path(resolved_locations["semantic_dirscan"])
    fscan = Path(resolved_locations["fscan"])
    nuclei = Path(resolved_locations["nuclei"])
    tscan = Path(resolved_locations["tscan_plus"])
    tscan_automation = Path(__file__).with_name("tscan_automation.py")
    asset_main = asset / "main.py"
    asset_workflow = asset / "asset_workflow.py"
    asset_handoff = asset / "asset_handoff.py"
    semantic_bridge = semantic / "sttool_bridge.py"
    asset_python = asset / ".venv" / "Scripts" / "pythonw.exe"
    if not asset_python.exists():
        asset_python = asset / ".venv" / "Scripts" / "python.exe"

    return (
        ToolDefinition(
            tool_id="asset_commander",
            name="AssetCommander",
            category="资产发现",
            description="按可恢复源码工作流执行资产发现与项目化结果管理",
            executable=str(asset_python),
            args=(
                str(asset_main),
                "--sttool-project",
                "{project_name}",
                "--sttool-target",
                "{target}",
                "--sttool-scope",
                "{scope}",
                "--sttool-state",
                "{run_dir}/tool_data/asset_commander/workflow_state.json",
                "--sttool-export",
                "{run_dir}/results/asset_commander_assets.json",
                "--sttool-collision-config",
                "{\"preserve_original_port\":true,\"add_80\":true,\"add_443\":true,\"no_port\":true,\"absolute_path\":false,\"waf_header\":false,\"force_sni\":false,\"threads\":150}",
            ),
            cwd="{run_dir}/tool_data/asset_commander",
            default_selected=True,
            sends_requests=True,
            required_paths=(str(asset_main), str(asset_workflow), str(asset_handoff)),
            restart_on_recovery=True,
            prepare_files=((str(asset / "config.json"), "tool_data/asset_commander/config.json"),),
            environment=(
                ("OPENAI_BASE_URL", "{api_base_url}"),
                ("OPENAI_MODEL", "{model}"),
                ("OPENAI_API_KEY", "{api_key}"),
            ),
            result_paths=(
                "{run_dir}/results/asset_commander_assets.json",
                "{run_dir}/tool_data/asset_commander/workflow_state.json",
            ),
            uses_shared_ai=True,
        ),
        ToolDefinition(
            tool_id="semantic_dirscan",
            name="AI 路径发现",
            category="路径发现",
            description="接收固定工具资产并按工程断点自动继续的 semantic-recursive-dirscan GUI",
            executable=_pythonw(),
            args=(
                "{run_dir}/tool_data/semantic/semantic_recursive_dirscan.py",
                "--gui",
                "--sttool-project",
                "{project_name}",
                "--sttool-target",
                "{target}",
                "--sttool-scope",
                "{scope}",
                "--sttool-state",
                "{run_dir}/tool_data/semantic/sttool_bridge_state.json",
                "--sttool-asset-export",
                "{run_dir}/results/asset_commander_assets.json",
                "--sttool-asset-state",
                "{run_dir}/tool_data/asset_commander/workflow_state.json",
                "--sttool-fscan-result",
                "{run_dir}/results/fscan.txt",
                "--sttool-auto-start",
            ),
            cwd="{run_dir}/tool_data/semantic",
            default_selected=True,
            sends_requests=True,
            required_paths=(str(semantic / "semantic_recursive_dirscan.py"), str(semantic_bridge)),
            restart_on_recovery=True,
            prepare_files=(
                (str(semantic / "config.json"), "tool_data/semantic/config.json"),
                (str(semantic / "dict"), "tool_data/semantic/dict"),
            ),
            refresh_files=(
                (str(semantic / "semantic_recursive_dirscan.py"), "tool_data/semantic/semantic_recursive_dirscan.py"),
                (str(semantic_bridge), "tool_data/semantic/sttool_bridge.py"),
            ),
            secret_env=(("OPENAI_API_KEY", str(semantic / "config.json"), "ai_api_key"),),
            environment=(
                ("OPENAI_BASE_URL", "{api_base_url}"),
                ("OPENAI_MODEL", "{model}"),
                ("OPENAI_API_KEY", "{api_key}"),
            ),
            result_paths=(
                "{run_dir}/tool_data/semantic/projects",
                "{run_dir}/tool_data/semantic/reports",
                "{run_dir}/tool_data/semantic/sttool_bridge_state.json",
            ),
            uses_shared_ai=True,
        ),
        ToolDefinition(
            tool_id="fscan",
            name="fscan 基础探测",
            category="自动扫描",
            description="对目标主机执行基础端口和服务探测",
            executable=str(fscan),
            args=("-h", "{target_host}", "-o", "{run_dir}/results/fscan.txt"),
            cwd="{run_dir}",
            sends_requests=True,
            new_console=True,
            result_paths=("{run_dir}/results/fscan.txt",),
            allow_standalone=True,
        ),
        ToolDefinition(
            tool_id="nuclei",
            name="nuclei 模板扫描",
            category="自动扫描",
            description="对目标 URL 执行本地 nuclei 模板检查",
            executable=str(nuclei),
            args=("-u", "{target}", "-o", "{run_dir}/results/nuclei.txt"),
            cwd="{run_dir}",
            sends_requests=True,
            new_console=True,
            result_paths=("{run_dir}/results/nuclei.txt",),
            allow_standalone=True,
        ),
        ToolDefinition(
            tool_id="tscan_plus",
            name="TscanPlus",
            category="综合检测",
            description="等待资产回传后联动信息收集、资产探测、POC 检测和密码检测",
            executable=_pythonw(),
            args=(
                str(tscan_automation),
                "--exe",
                str(tscan),
                "--target",
                "{target}",
                "--project",
                "{project_name}",
                "--scope",
                "{scope}",
                "--state",
                "{run_dir}/tool_data/tscan/state.json",
                "--asset-state",
                "{run_dir}/tool_data/asset_commander/workflow_state.json",
                "--asset-export",
                "{run_dir}/results/asset_commander_assets.json",
            ),
            cwd="{run_dir}",
            sends_requests=True,
            required_paths=(str(tscan), str(tscan_automation)),
            restart_on_recovery=True,
            result_paths=("{run_dir}/tool_data/tscan/state.json",),
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
    for required_path in tool.required_paths:
        if not Path(required_path).exists():
            return False, f"依赖路径不存在: {required_path}"
    for source, _destination in tool.prepare_files:
        if not Path(source).exists():
            return False, f"依赖文件不存在: {source}"
    for source, _destination in tool.refresh_files:
        if not Path(source).exists():
            return False, f"依赖文件不存在: {source}"
    for _environment_name, source, _json_key in tool.secret_env:
        if not Path(source).is_file():
            return False, f"密钥配置不存在: {source}"
    return True, "可用"
