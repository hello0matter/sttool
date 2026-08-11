from __future__ import annotations

from pathlib import Path

from .activity import append_activity
from .asset_bus import AssetBus, atomic_json_write, now_text, read_json
from .models import RunState
from .workflow_settings import normalize_workflow_settings, normalized_reasoning_effort
from .workload_approval import update_pending_request_policy


def apply_global_settings_to_runs(
    projects_dir: Path,
    states: list[RunState],
    settings: dict[str, object],
    *,
    api_base_url: str = "",
    model: str = "",
    agent_profiles: dict[str, dict[str, str]] | None = None,
) -> list[RunState]:
    workflow = normalize_workflow_settings(settings)
    profiles = agent_profiles or {}
    updated_projects: set[Path] = set()
    for state in states:
        run_dir = Path(state.run_dir).resolve()
        changed_fields: list[str] = []
        for field, value in workflow.items():
            if field not in RunState.__dataclass_fields__:
                continue
            if getattr(state, field) != value:
                setattr(state, field, value)
                changed_fields.append(field)
        global_values = _global_values_for_state(
            state,
            api_base_url=api_base_url,
            model=model,
            profiles=profiles,
        )
        for field, value in global_values.items():
            if getattr(state, field) != value:
                setattr(state, field, value)
                changed_fields.append(field)
        if changed_fields:
            state.updated_at = now_text()
            atomic_json_write(run_dir / "run.json", state.to_dict())
            append_activity(
                run_dir,
                "已热更新全局设置：" + "、".join(changed_fields) + "。",
            )

        _write_hot_settings(run_dir, state, workflow)
        asset_path = run_dir / "tool_data" / "asset_bus" / "assets.json"
        if asset_path.is_file():
            AssetBus(asset_path, state.scope, state.target).update_approval_policy(
                approval_mode=str(workflow["new_asset_approval_mode"]),
                approval_seconds=int(workflow["new_asset_countdown_seconds"]),
                allow_cidr_expansion=bool(workflow["allow_cidr_expansion"]),
                processing_scope=str(workflow["asset_processing_scope"]),
            )
        update_pending_request_policy(
            run_dir,
            mode=str(workflow["workload_approval_mode"]),
            countdown_seconds=int(workflow["workload_countdown_seconds"]),
        )
        _update_json(run_dir / "project.json", {**workflow, **global_values})
        updated_projects.add(run_dir.parent.parent)

    updated_projects.update(path.parent for path in projects_dir.glob("*/project.json"))
    for project_dir in updated_projects:
        project_path = project_dir / "project.json"
        project = read_json(project_path)
        if not project:
            continue
        updates = dict(workflow)
        if api_base_url.strip():
            updates["api_base_url"] = api_base_url.strip().rstrip("/")
        if model.strip():
            updates["model"] = model.strip()
        project_provider = str(project.get("provider") or "codexx")
        profile_name = "claude" if project_provider == "claude" else "codex"
        updates.update(profiles.get(profile_name, {}))
        _update_json(project_path, updates)
    return states


def _global_values_for_state(
    state: RunState,
    *,
    api_base_url: str,
    model: str,
    profiles: dict[str, dict[str, str]],
) -> dict[str, object]:
    values: dict[str, object] = {
        "api_base_url": api_base_url.strip().rstrip("/") or state.api_base_url,
        "model": model.strip() or state.model,
    }
    profile_name = "claude" if state.provider == "claude" else "codex"
    if profile_name not in profiles:
        return {
            **values,
            "agent_model": state.agent_model,
            "reasoning_effort": state.reasoning_effort,
            "agent_base_url": state.agent_base_url,
        }
    profile = profiles[profile_name]
    return {
        **values,
        "agent_model": str(profile.get("agent_model") or ""),
        "reasoning_effort": normalized_reasoning_effort(
            profile.get("reasoning_effort")
        ),
        "agent_base_url": str(profile.get("agent_base_url") or "")
        .strip()
        .rstrip("/"),
    }


def _write_hot_settings(
    run_dir: Path,
    state: RunState,
    workflow: dict[str, object],
) -> None:
    path = run_dir / "tool_data" / "coordinator" / "hot_settings.json"
    agent = {
        "provider": state.provider,
        "agent_model": state.agent_model,
        "reasoning_effort": state.reasoning_effort,
        "agent_base_url": state.agent_base_url,
    }
    previous = read_json(path)
    if previous.get("workflow") == workflow and previous.get("agent") == agent:
        return
    atomic_json_write(
        path,
        {
            "schema_version": 1,
            "updated_at": now_text(),
            "workflow": workflow,
            "agent": agent,
        },
    )


def _update_json(path: Path, updates: dict[str, object]) -> None:
    value = read_json(path)
    if not value:
        return
    value.update(updates)
    atomic_json_write(path, value)


__all__ = ["apply_global_settings_to_runs"]
