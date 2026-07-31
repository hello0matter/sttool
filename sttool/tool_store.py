from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import asdict, fields, replace
from pathlib import Path
from typing import Any

from .models import ToolDefinition
from .registry import (
    BUILTIN_TOOL_IDS,
    DEFAULT_ST_ROOT,
    builtin_location_kind,
    default_locations,
    default_tools,
)


TUPLE_FIELDS = {
    "args",
    "required_paths",
    "prepare_files",
    "refresh_files",
    "secret_env",
    "environment",
    "result_paths",
}
TOOL_FIELDS = {item.name for item in fields(ToolDefinition)}
ASSET_COLLISION_DEFAULTS = {
    "preserve_original_port": True,
    "add_80": True,
    "add_443": True,
    "no_port": True,
    "absolute_path": False,
    "waf_header": False,
    "force_sni": False,
    "threads": 150,
}


def _atomic_json_write(path: Path, value: object) -> None:
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


def _tool_from_dict(value: dict[str, Any]) -> ToolDefinition:
    normalized = {key: item for key, item in value.items() if key in TOOL_FIELDS}
    for key in TUPLE_FIELDS:
        if key in normalized:
            normalized[key] = tuple(
                tuple(item) if isinstance(item, list) else item
                for item in normalized[key]
            )
    return ToolDefinition(**normalized)


class ToolStore:
    def __init__(self, path: Path, st_root: Path = DEFAULT_ST_ROOT) -> None:
        self.path = path.resolve()
        self.st_root = st_root.resolve()
        self.load_error = ""
        self._value = self._load()

    def _load(self) -> dict[str, Any]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"schema_version": 1, "locations": {}, "custom_tools": [], "builtin_settings": {}}
        except (OSError, json.JSONDecodeError) as exc:
            self.load_error = f"读取工具配置失败: {exc}"
            return {"schema_version": 1, "locations": {}, "custom_tools": [], "builtin_settings": {}}
        if not isinstance(value, dict):
            self.load_error = "工具配置根节点必须是 JSON 对象"
            return {"schema_version": 1, "locations": {}, "custom_tools": []}
        locations = value.get("locations", {})
        custom_tools = value.get("custom_tools", [])
        builtin_settings = value.get("builtin_settings", {})
        return {
            "schema_version": 1,
            "locations": locations if isinstance(locations, dict) else {},
            "custom_tools": custom_tools if isinstance(custom_tools, list) else [],
            "builtin_settings": builtin_settings if isinstance(builtin_settings, dict) else {},
        }

    def _save(self) -> None:
        _atomic_json_write(self.path, self._value)

    def tools(self) -> tuple[ToolDefinition, ...]:
        tools = list(default_tools(self.st_root, self._value["locations"]))
        settings = self.asset_collision_settings()
        for index, tool in enumerate(tools):
            if tool.tool_id != "asset_commander":
                continue
            args = list(tool.args)
            marker = args.index("--sttool-collision-config") + 1
            args[marker] = json.dumps(settings, ensure_ascii=False, separators=(",", ":"))
            tools[index] = replace(tool, args=tuple(args))
        seen = {tool.tool_id for tool in tools}
        for value in self._value["custom_tools"]:
            if not isinstance(value, dict):
                continue
            try:
                tool = _tool_from_dict(value)
            except (TypeError, ValueError):
                continue
            if tool.tool_id not in seen:
                tools.append(tool)
                seen.add(tool.tool_id)
        return tuple(tools)

    def is_builtin(self, tool_id: str) -> bool:
        return tool_id in BUILTIN_TOOL_IDS

    def location_kind(self, tool_id: str) -> str:
        return builtin_location_kind(tool_id) if self.is_builtin(tool_id) else "file"

    def location_for(self, tool_id: str, tool: ToolDefinition | None = None) -> str:
        if self.is_builtin(tool_id):
            locations = default_locations(self.st_root)
            locations.update(self._value["locations"])
            return str(locations[tool_id])
        return tool.executable if tool is not None else ""

    def set_location(self, tool_id: str, path: str) -> None:
        if not self.is_builtin(tool_id):
            raise ValueError(f"不是内置工具: {tool_id}")
        value = str(Path(path).resolve())
        self._value["locations"][tool_id] = value
        self._save()

    def reset_location(self, tool_id: str) -> None:
        self._value["locations"].pop(tool_id, None)
        self._save()

    def asset_collision_settings(self) -> dict[str, Any]:
        saved = self._value["builtin_settings"].get("asset_commander", {})
        result = dict(ASSET_COLLISION_DEFAULTS)
        if isinstance(saved, dict):
            result.update({key: saved[key] for key in result.keys() & saved.keys()})
        result["threads"] = max(1, min(500, int(result["threads"])))
        return result

    def set_asset_collision_settings(self, value: dict[str, Any]) -> None:
        normalized = dict(ASSET_COLLISION_DEFAULTS)
        for key in normalized:
            if key == "threads":
                normalized[key] = max(1, min(500, int(value.get(key, 150))))
            else:
                normalized[key] = bool(value.get(key, normalized[key]))
        self._value["builtin_settings"]["asset_commander"] = normalized
        self._save()

    def _next_custom_id(self, name: str) -> str:
        slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_") or "tool"
        base = f"custom_{slug}"[:64]
        used = {tool.tool_id for tool in self.tools()}
        if base not in used:
            return base
        for index in range(2, 1000):
            candidate = f"{base}_{index}"
            if candidate not in used:
                return candidate
        raise ValueError("无法生成唯一工具 ID")

    def upsert_custom(self, values: dict[str, Any], tool_id: str = "") -> ToolDefinition:
        resolved_id = tool_id or self._next_custom_id(str(values.get("name", "")))
        if resolved_id in BUILTIN_TOOL_IDS:
            raise ValueError("不能覆盖内置工具")
        tool = ToolDefinition(
            tool_id=resolved_id,
            name=str(values.get("name", "")).strip(),
            category=str(values.get("category", "自定义")).strip() or "自定义",
            description=str(values.get("description", "")).strip(),
            executable=str(values.get("executable", "")).strip(),
            args=tuple(str(item) for item in values.get("args", ()) if str(item)),
            cwd=str(values.get("cwd", "{run_dir}")).strip() or "{run_dir}",
            default_selected=bool(values.get("default_selected", False)),
            sends_requests=bool(values.get("sends_requests", True)),
            new_console=bool(values.get("new_console", True)),
            restart_on_recovery=bool(values.get("restart_on_recovery", False)),
            result_paths=tuple(
                str(item) for item in values.get("result_paths", ()) if str(item)
            ),
            uses_shared_ai=bool(values.get("uses_shared_ai", False)),
            allow_standalone=bool(values.get("allow_standalone", False)),
        )
        if not tool.name or not tool.executable:
            raise ValueError("工具名称和入口不能为空")
        custom_tools = self._value["custom_tools"]
        replacement = asdict(tool)
        for index, value in enumerate(custom_tools):
            if isinstance(value, dict) and value.get("tool_id") == resolved_id:
                custom_tools[index] = replacement
                break
        else:
            custom_tools.append(replacement)
        self._save()
        return tool

    def remove_custom(self, tool_id: str) -> None:
        if self.is_builtin(tool_id):
            raise ValueError("内置工具不能删除")
        self._value["custom_tools"] = [
            value
            for value in self._value["custom_tools"]
            if not isinstance(value, dict) or value.get("tool_id") != tool_id
        ]
        self._save()
