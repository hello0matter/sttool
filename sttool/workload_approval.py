from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .asset_bus import atomic_json_write, read_json


APPROVAL_MODES = {"automatic", "countdown_accept", "countdown_reject", "manual"}
REQUEST_FILE = "workload_approval.json"
HISTORY_FILE = "workload_approval_history.json"


def request_path(run_dir: Path) -> Path:
    return run_dir / "tool_data" / "coordinator" / REQUEST_FILE


def history_path(run_dir: Path) -> Path:
    return run_dir / "tool_data" / "coordinator" / HISTORY_FILE


def workload_counts(value: dict[str, Any], after_generation: int) -> dict[str, int]:
    counts = {"ips": 0, "domains": 0, "endpoints": 0, "urls": 0}
    mapping = {"ip": "ips", "domain": "domains", "endpoint": "endpoints", "url": "urls"}
    for item in value.get("assets", []):
        if not isinstance(item, dict):
            continue
        if item.get("included") is False:
            continue
        try:
            generation = int(item.get("first_generation") or 0)
        except (TypeError, ValueError):
            generation = 0
        if generation <= after_generation:
            continue
        bucket = mapping.get(str(item.get("type") or ""))
        if bucket:
            counts[bucket] += 1
    return counts


def workload_assets(value: dict[str, Any], after_generation: int) -> list[dict[str, Any]]:
    """Return the allowed AssetBus delta as a stable, editable batch snapshot."""
    rows: list[dict[str, Any]] = []
    for item in value.get("assets", []):
        if not isinstance(item, dict):
            continue
        try:
            generation = int(item.get("first_generation") or 0)
        except (TypeError, ValueError):
            generation = 0
        if generation <= after_generation:
            continue
        kind = str(item.get("type") or "")
        asset_value = str(item.get("value") or "")
        if kind not in {"ip", "domain", "endpoint", "url"} or not asset_value:
            continue
        sources = item.get("sources")
        if not isinstance(sources, list):
            source = str(item.get("source") or "")
            sources = [source] if source else []
        rows.append(
            {
                "type": kind,
                "value": asset_value,
                "sources": [str(source) for source in sources if str(source)],
                "first_generation": generation,
                "included": True,
            }
        )
    return rows


def included_assets(request: dict[str, Any]) -> list[dict[str, Any]]:
    assets = request.get("assets")
    if not isinstance(assets, list):
        return []
    return [
        item
        for item in assets
        if isinstance(item, dict) and item.get("included") is not False
    ]


def workload_total(counts: dict[str, int]) -> int:
    return sum(max(int(value), 0) for value in counts.values())


def _deadline(seconds: int) -> str:
    return (datetime.now().astimezone() + timedelta(seconds=max(seconds, 3))).isoformat(timespec="seconds")


def create_request(
    run_dir: Path,
    *,
    project_name: str,
    run_id: str,
    generation_from: int,
    generation_to: int,
    counts: dict[str, int],
    mode: str,
    countdown_seconds: int,
    assets: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    normalized_mode = mode if mode in APPROVAL_MODES else "countdown_accept"
    default_action = "reject" if normalized_mode == "countdown_reject" else "accept"
    deadline = "" if normalized_mode == "manual" else _deadline(countdown_seconds)
    asset_selection_enabled = assets is not None
    snapshot = [dict(item) for item in (assets or []) if isinstance(item, dict)]
    if snapshot:
        counts = workload_counts({"assets": snapshot}, -1)
    value = {
        "schema_version": 2,
        "request_id": uuid.uuid4().hex,
        "kind": "agent_batch",
        "status": "pending",
        "project_name": project_name,
        "run_id": run_id,
        "generation_from": generation_from,
        "generation_to": generation_to,
        "counts": counts,
        "total": workload_total(counts),
        "original_total": len(snapshot) if snapshot else workload_total(counts),
        "assets": snapshot,
        "asset_selection_enabled": asset_selection_enabled,
        "default_action": default_action,
        "decision_deadline_at": deadline,
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    }
    atomic_json_write(request_path(run_dir), value)
    return value


def read_request(run_dir: Path) -> dict[str, Any]:
    return read_json(request_path(run_dir))


def read_history(run_dir: Path) -> list[dict[str, Any]]:
    value = read_json(history_path(run_dir))
    rows = value.get("requests")
    return [item for item in rows if isinstance(item, dict)] if isinstance(rows, list) else []


def update_pending_request_policy(
    run_dir: Path,
    *,
    mode: str,
    countdown_seconds: int,
) -> bool:
    value = read_request(run_dir)
    if not value or value.get("status") not in {"pending", ""}:
        return False
    normalized_mode = mode if mode in APPROVAL_MODES else "countdown_accept"
    value["default_action"] = (
        "reject" if normalized_mode == "countdown_reject" else "accept"
    )
    if normalized_mode == "manual":
        value["decision_deadline_at"] = ""
    elif normalized_mode == "automatic":
        value["decision_deadline_at"] = datetime.now().astimezone().isoformat(
            timespec="seconds"
        )
    else:
        value["decision_deadline_at"] = _deadline(countdown_seconds)
    value["policy_updated_at"] = datetime.now().astimezone().isoformat(
        timespec="seconds"
    )
    atomic_json_write(request_path(run_dir), value)
    return True


def decide_request(run_dir: Path, action: str, decided_by: str = "user") -> dict[str, Any]:
    value = read_request(run_dir)
    if not value or value.get("status") not in {"pending", ""}:
        return value
    normalized = "accept" if str(action).strip().lower() in {"accept", "yes", "y", "\u7acb\u5373\u542f\u52a8", "\u542f\u52a8"} else "reject"
    if (
        normalized == "accept"
        and value.get("asset_selection_enabled") is True
        and not included_assets(value)
    ):
        normalized = "reject"
        value["decision_reason"] = "all_assets_excluded"
    value.update(
        status="decided",
        decision=normalized,
        decided_by=decided_by,
        decided_at=datetime.now().astimezone().isoformat(timespec="seconds"),
    )
    atomic_json_write(request_path(run_dir), value)
    history = read_history(run_dir)
    request_id = str(value.get("request_id") or "")
    history = [
        item
        for item in history
        if str(item.get("request_id") or "") != request_id
    ]
    history.append(dict(value))
    atomic_json_write(
        history_path(run_dir),
        {
            "schema_version": 1,
            "updated_at": value["decided_at"],
            "requests": history[-1000:],
        },
    )
    return value


def update_asset_inclusion(
    run_dir: Path,
    keys: set[tuple[str, str]],
    *,
    included: bool,
) -> dict[str, Any]:
    value = read_request(run_dir)
    if not value or value.get("status") not in {"pending", ""}:
        return value
    assets = value.get("assets")
    if not isinstance(assets, list):
        return value
    for item in assets:
        if not isinstance(item, dict):
            continue
        key = (str(item.get("type") or ""), str(item.get("value") or ""))
        if key in keys:
            item["included"] = included
    counts = workload_counts({"assets": assets}, -1)
    value["counts"] = counts
    value["total"] = workload_total(counts)
    value["selection_updated_at"] = datetime.now().astimezone().isoformat(
        timespec="seconds"
    )
    atomic_json_write(request_path(run_dir), value)
    return value


def synchronize_request_assets(
    run_dir: Path, assets: list[dict[str, Any]]
) -> dict[str, Any]:
    value = read_request(run_dir)
    if not value or value.get("status") not in {"pending", "", "decided"}:
        return value
    previous = value.get("assets")
    inclusion = {
        (str(item.get("type") or ""), str(item.get("value") or "")): item.get(
            "included"
        )
        is not False
        for item in previous
        if isinstance(item, dict)
    } if isinstance(previous, list) else {}
    snapshot: list[dict[str, Any]] = []
    for item in assets:
        row = dict(item)
        key = (str(row.get("type") or ""), str(row.get("value") or ""))
        row["included"] = inclusion.get(key, True)
        snapshot.append(row)
    counts = workload_counts({"assets": snapshot}, -1)
    if previous == snapshot and value.get("counts") == counts:
        return value
    value["assets"] = snapshot
    value["counts"] = counts
    value["total"] = workload_total(counts)
    value["original_total"] = len(snapshot)
    value["assets_synchronized_at"] = datetime.now().astimezone().isoformat(
        timespec="seconds"
    )
    atomic_json_write(request_path(run_dir), value)
    return value


def resolve_due_request(run_dir: Path, now: float | None = None) -> dict[str, Any]:
    value = read_request(run_dir)
    if not value or value.get("status") not in {"pending", ""}:
        return value
    if value.get("countdown_paused_at"):
        return value
    deadline = str(value.get("decision_deadline_at") or "")
    try:
        current_time = time.time() if now is None else now
        due = bool(deadline) and datetime.fromisoformat(deadline).timestamp() <= current_time
    except (TypeError, ValueError, OSError, OverflowError):
        due = False
    if not due:
        return value
    return decide_request(run_dir, str(value.get("default_action") or "accept"), "timeout_default")


__all__ = [
    "APPROVAL_MODES",
    "HISTORY_FILE",
    "REQUEST_FILE",
    "create_request",
    "decide_request",
    "history_path",
    "read_history",
    "read_request",
    "request_path",
    "resolve_due_request",
    "update_pending_request_policy",
    "update_asset_inclusion",
    "synchronize_request_assets",
    "included_assets",
    "workload_assets",
    "workload_counts",
    "workload_total",
]
