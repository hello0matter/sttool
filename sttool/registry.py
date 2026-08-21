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
    "vulnx",
    "find_gh_poc",
    "tscan_plus",
    "tscan_client",
    "passhack",
)


def default_locations(st_root: Path = DEFAULT_ST_ROOT) -> dict[str, str]:
    return {
        "asset_commander": str(st_root / "tmp" / "AssetCommander"),
        "semantic_dirscan": str(st_root / "tmp" / "semantic-recursive-dirscan"),
        "fscan": str(st_root / "fscan" / "fscan.exe"),
        "nuclei": str(st_root / "nuclei" / "nuclei.exe"),
        "vulnx": str(st_root / "vulnx" / "vulnx.exe"),
        "find_gh_poc": str(st_root / "find-gh-poc" / "find-gh-poc.exe"),
        "tscan_plus": str(st_root / "TscanPlus_Win_Amd64" / "TscanPlus_Win_Amd64.exe"),
        "tscan_client": str(st_root / "TscanClient_Win" / "TscanClient_Win.exe"),
        "passhack": str(st_root / "tmp" / "passhack"),
    }


def builtin_location_kind(tool_id: str) -> str:
    return "directory" if tool_id in {"asset_commander", "semantic_dirscan", "passhack"} else "file"


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
    vulnx = Path(resolved_locations["vulnx"])
    find_gh_poc = Path(resolved_locations["find_gh_poc"])
    tscan_client = Path(resolved_locations["tscan_client"])
    tscan = Path(resolved_locations["tscan_plus"])
    tscan_automation = Path(__file__).with_name("tscan_automation.py")
    github_poc_search = Path(__file__).with_name("github_poc_search.py")
    passhack_root = Path(resolved_locations["passhack"])
    passhack_bridge = passhack_root / "passhack_bridge.py"
    passhack_source = passhack_root / "passhack.py"
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
                "{processing_scope}",
                "--sttool-state",
                "{run_dir}/tool_data/asset_commander/workflow_state.json",
                "--sttool-export",
                "{run_dir}/results/asset_commander_assets.json",
                "--sttool-asset-bus",
                "{run_dir}/tool_data/asset_bus/assets.json",
                "--sttool-allow-cidr-expansion",
                "{allow_cidr_expansion}",
                "--sttool-collision-config",
                "{{\"preserve_original_port\":true,\"add_80\":true,\"add_443\":true,\"no_port\":true,\"absolute_path\":false,\"waf_header\":false,\"force_sni\":false,\"threads\":150}}",
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
                "{processing_scope}",
                "--sttool-state",
                "{run_dir}/tool_data/semantic/sttool_bridge_state.json",
                "--sttool-asset-export",
                "{run_dir}/results/asset_commander_assets.json",
                "--sttool-asset-state",
                "{run_dir}/tool_data/asset_commander/workflow_state.json",
                "--sttool-fscan-result",
                "{run_dir}/results/fscan.txt",
                "--sttool-asset-bus",
                "{run_dir}/tool_data/asset_bus/assets.json",
                "--sttool-auto-start",
                "--threads",
                "{semantic_threads}",
                "--max-depth",
                "{semantic_max_depth}",
                "--max-rate",
                "{semantic_max_rate}",
                "{semantic_dirsearch_flag}",
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
            default_selected=True,
            executable=str(fscan),
            args=(
                "-h",
                "{target_host}",
                "-t",
                "{fscan_port_threads}",
                "{fscan_skip_poc_flag}",
                "{fscan_skip_brute_flag}",
                "-o",
                "{run_dir}/results/fscan.txt",
            ),
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
            default_selected=True,
            executable=str(nuclei),
            args=("-u", "{target}", "-o", "{run_dir}/results/nuclei.txt"),
            cwd="{run_dir}",
            sends_requests=True,
            new_console=True,
            result_paths=("{run_dir}/results/nuclei.txt",),
            allow_standalone=True,
        ),
        ToolDefinition(
            tool_id="vulnx",
            name="vulnx 漏洞情报",
            category="漏洞情报",
            description="按 CVE、产品或版本检索 CVSS、EPSS、KEV、公开 PoC 与 Nuclei 模板元数据；不执行 PoC",
            executable=str(vulnx),
            args=(
                "--silent",
                "--json",
                "--disable-update-check",
                "--output",
                "{run_dir}/results/vulnx.json",
                "search",
                "--limit",
                "20",
                "{target}",
            ),
            cwd="{run_dir}",
            result_paths=("{run_dir}/results/vulnx.json",),
            default_selected=True,
            allow_standalone=True,
            coordinator_managed=True,
        ),
        ToolDefinition(
            tool_id="find_gh_poc",
            name="GitHub PoC 候选搜索",
            category="漏洞情报",
            description="通过 trickest/find-gh-poc 搜索 GitHub 候选仓库；只保存链接，不克隆、不执行 PoC，需 GITHUB_TOKEN 或 GH_TOKEN",
            executable=_pythonw(),
            args=(
                str(github_poc_search),
                "--exe",
                str(find_gh_poc),
                "--query",
                "{target}",
                "--output",
                "{run_dir}/results/find_gh_poc.json",
            ),
            cwd="{run_dir}",
            required_paths=(str(github_poc_search), str(find_gh_poc)),
            environment=(("GITHUB_TOKEN", "{github_token}"),),
            result_paths=("{run_dir}/results/find_gh_poc.json",),
            default_selected=True,
            allow_standalone=True,
            coordinator_managed=True,
        ),
        ToolDefinition(
            tool_id="tscan_plus",
            name="TscanPlus",
            category="综合检测",
            description="后台运行 TscanClient，等待资产回传后联动端口、Web 指纹和 POC 检测",
            default_selected=True,
            executable=_pythonw(),
            args=(
                str(Path(__file__).with_name("tscan_client.py")),
                "--client-exe",
                str(tscan_client),
                "--target",
                "{target}",
                "--project",
                "{project_name}",
                "--scope",
                "{processing_scope}",
                "--state",
                "{run_dir}/tool_data/tscan/state.json",
                "--asset-bus",
                "{run_dir}/tool_data/asset_bus/assets.json",
            ),
            cwd="{run_dir}",
            sends_requests=True,
            required_paths=(str(tscan_client), str(Path(__file__).with_name("tscan_client.py"))),
            restart_on_recovery=True,
            result_paths=("{run_dir}/tool_data/tscan/state.json",),
            alternate_executable=_pythonw(),
            alternate_args=(
                str(tscan_automation), "--exe", str(tscan), "--target", "{target}",
                "--project", "{project_name}", "--scope", "{processing_scope}",
                "--state", "{run_dir}/tool_data/tscan/state.json",
                "--asset-state", "{run_dir}/tool_data/asset_commander/workflow_state.json",
                "--asset-export", "{run_dir}/results/asset_commander_assets.json",
                "--asset-bus", "{run_dir}/tool_data/asset_bus/assets.json",
            ),
            alternate_required_paths=(str(tscan), str(tscan_automation)),
        ),
        ToolDefinition(
            tool_id="passhack",
            name="PassHack 登录面审计",
            category="登录面安全审计",
            description="消费 STTool 已批准的登录入口，识别登录表单并按明确审批策略执行受限验证；结果脱敏回流工程",
            executable=_pythonw(),
            args=(
                "{run_dir}/tool_data/passhack/passhack_bridge.py",
                "--run-dir", "{run_dir}",
                "--scope", "{processing_scope}",
                "--target", "{target}",
                "--candidates", "{run_dir}/tool_data/credential_audit/credential_audit.json",
                "--state", "{run_dir}/tool_data/passhack/state.json",
                "--export", "{run_dir}/results/passhack.json",
            ),
            cwd="{run_dir}/tool_data/passhack",
            default_selected=False,
            sends_requests=True,
            required_paths=(str(passhack_bridge), str(passhack_source)),
            refresh_files=(
                (str(passhack_bridge), "tool_data/passhack/passhack_bridge.py"),
                (str(passhack_source), "tool_data/passhack/passhack.py"),
            ),
            restart_on_recovery=True,
            result_paths=(
                "{run_dir}/tool_data/passhack/state.json",
                "{run_dir}/results/passhack.json",
            ),
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
