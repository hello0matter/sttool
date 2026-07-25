from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


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
    prepare_files: tuple[tuple[str, str], ...] = ()
    secret_env: tuple[tuple[str, str, str], ...] = ()


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

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ProcessRecord":
        return cls(**value)


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
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["schema_version"] = 1
        return value

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RunState":
        fields = {
            key: item
            for key, item in value.items()
            if key in cls.__dataclass_fields__ and key != "processes"
        }
        fields["processes"] = [
            ProcessRecord.from_dict(item) for item in value.get("processes", [])
        ]
        return cls(**fields)
