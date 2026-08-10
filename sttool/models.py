from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .workflow_settings import (
    DEFAULT_WORK_MODE,
    normalize_workflow_settings,
    normalized_reasoning_effort,
)


DEFAULT_API_BASE_URL = "https://api.1314mc.net/v1"


def normalize_provider(value: object, schema_version: int = 2) -> str:
    provider = str(value or "codexx").lower()
    if schema_version < 2 and provider == "codex":
        return "codexx"
    return provider


@dataclass(frozen=True)
class ToolDefinition:
    tool_id: str
    name: str
    category: str
    description: str
    executable: str
    args: tuple[str, ...] = ()
    cwd: str = "{source_dir}"
    default_selected: bool = False
    sends_requests: bool = False
    new_console: bool = False
    required_paths: tuple[str, ...] = ()
    restart_on_recovery: bool = False
    prepare_files: tuple[tuple[str, str], ...] = ()
    refresh_files: tuple[tuple[str, str], ...] = ()
    secret_env: tuple[tuple[str, str, str], ...] = ()
    environment: tuple[tuple[str, str], ...] = ()
    result_paths: tuple[str, ...] = ()
    uses_shared_ai: bool = False
    allow_standalone: bool = False
    coordinator_managed: bool = False


@dataclass(frozen=True)
class LaunchRequest:
    project_name: str
    target: str
    scope: str
    provider: str
    model: str
    selected_tools: tuple[str, ...]
    user_prompt: str
    authorization_confirmed: bool
    api_base_url: str = DEFAULT_API_BASE_URL
    api_key: str = field(default="", repr=False, compare=False)
    agent_model: str = ""
    reasoning_effort: str = ""
    agent_base_url: str = ""
    agent_api_key: str = field(default="", repr=False, compare=False)
    github_token: str = field(default="", repr=False, compare=False)
    work_mode: str = DEFAULT_WORK_MODE
    auto_agent: bool = True
    wait_for_asset_commander: bool = True
    wait_for_fscan: bool = True
    asset_settle_seconds: int = 20
    max_agent_batches: int = 8
    coordinator_poll_seconds: int = 2
    agent_stall_warn_minutes: int = 15
    ai_summary_enabled: bool = True
    fscan_skip_poc: bool = True
    fscan_skip_brute: bool = True
    fscan_port_threads: int = 600
    semantic_threads: int = 40
    semantic_max_depth: int = 2
    semantic_run_dirsearch: bool = True
    semantic_max_rate: int = 0
    allow_cidr_expansion: bool = False
    new_asset_approval_mode: str = "countdown_accept"
    new_asset_countdown_seconds: int = 10
    new_asset_popup_enabled: bool = True
    new_asset_popup_topmost: bool = True
    workload_approval_mode: str = "countdown_accept"
    workload_countdown_seconds: int = 10
    workload_agent_threshold: int = 50
    workload_popup_enabled: bool = True
    workload_popup_topmost: bool = True


@dataclass
class ProcessRecord:
    component_id: str
    name: str
    pid: int
    command: list[str]
    cwd: str
    started_at: str
    status: str = "running"
    exit_code: int | None = None
    creation_token: int = 0

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ProcessRecord":
        return cls(**value)


@dataclass
class StandaloneRunState:
    run_id: str
    tool_id: str
    tool_name: str
    target: str
    run_dir: str
    created_at: str
    updated_at: str
    status: str
    authorization_confirmed: bool
    process: ProcessRecord | None = None
    result_paths: list[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["schema_version"] = 1
        return value


@dataclass
class RunState:
    run_id: str
    project_name: str
    target: str
    scope: str
    provider: str
    model: str
    selected_tools: list[str]
    run_dir: str
    created_at: str
    updated_at: str
    status: str
    processes: list[ProcessRecord] = field(default_factory=list)
    recovery_count: int = 0
    recovery_history: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""
    api_base_url: str = DEFAULT_API_BASE_URL
    agent_model: str = ""
    reasoning_effort: str = ""
    agent_base_url: str = ""
    work_mode: str = DEFAULT_WORK_MODE
    auto_agent: bool = True
    wait_for_asset_commander: bool = True
    wait_for_fscan: bool = True
    asset_settle_seconds: int = 20
    max_agent_batches: int = 8
    coordinator_poll_seconds: int = 2
    agent_stall_warn_minutes: int = 15
    ai_summary_enabled: bool = True
    fscan_skip_poc: bool = True
    fscan_skip_brute: bool = True
    fscan_port_threads: int = 600
    semantic_threads: int = 40
    semantic_max_depth: int = 2
    semantic_run_dirsearch: bool = True
    semantic_max_rate: int = 0
    allow_cidr_expansion: bool = False
    new_asset_approval_mode: str = "countdown_accept"
    new_asset_countdown_seconds: int = 10
    new_asset_popup_enabled: bool = True
    new_asset_popup_topmost: bool = True
    workload_approval_mode: str = "countdown_accept"
    workload_countdown_seconds: int = 10
    workload_agent_threshold: int = 50
    workload_popup_enabled: bool = True
    workload_popup_topmost: bool = True

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["schema_version"] = 7
        return value

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RunState":
        schema_version = int(value.get("schema_version", 1))
        fields = {
            key: item
            for key, item in value.items()
            if key in cls.__dataclass_fields__ and key != "processes"
        }
        fields["provider"] = normalize_provider(fields.get("provider"), schema_version)
        fields["reasoning_effort"] = normalized_reasoning_effort(
            fields.get("reasoning_effort")
        )
        fields.update(normalize_workflow_settings(fields))
        fields["processes"] = [
            ProcessRecord.from_dict(item) for item in value.get("processes", [])
        ]
        return cls(**fields)
