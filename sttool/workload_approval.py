from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .asset_bus import atomic_json_write, read_json


APPROVAL_MODES = {"automatic", "countdown_accept", "countdown_reject", "manual"}
REQUEST_FILE = "workload_approval.json"


def request_path(run_dir: Path) -> Path:
    return run_dir / "tool_data" / "coordinator" / REQUEST_FILE


def workload_counts(value: dict[str, Any], after_generation: int) -> dict[str, int]:
    counts = {"ips": 0, "domains": 0, "endpoints": 0, "urls": 0}
    mapping = {"ip": "ips", "domain": "domains", "endpoint": "endpoints", "url": "urls"}
    for item in value.get("assets", []):
        if not isinstance(item, dict):
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
) -> dict[str, Any]:
    normalized_mode = mode if mode in APPROVAL_MODES else "countdown_accept"
    default_action = "reject" if normalized_mode == "countdown_reject" else "accept"
    deadline = "" if normalized_mode == "manual" else _deadline(countdown_seconds)
    value = {
        "schema_version": 1,
        "request_id": uuid.uuid4().hex,
        "kind": "agent_batch",
        "status": "pending",
        "project_name": project_name,
        "run_id": run_id,
        "generation_from": generation_from,
        "generation_to": generation_to,
        "counts": counts,
        "total": workload_total(counts),
        "default_action": default_action,
        "decision_deadline_at": deadline,
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    }
    atomic_json_write(request_path(run_dir), value)
    return value


def read_request(run_dir: Path) -> dict[str, Any]:
    return read_json(request_path(run_dir))


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
    value.update(
        status="decided",
        decision=normalized,
        decided_by=decided_by,
        decided_at=datetime.now().astimezone().isoformat(timespec="seconds"),
    )
    atomic_json_write(request_path(run_dir), value)
    return value


def resolve_due_request(run_dir: Path, now: float | None = None) -> dict[str, Any]:
    value = read_request(run_dir)
    if not value or value.get("status") not in {"pending", ""}:
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
    "REQUEST_FILE",
    "create_request",
    "decide_request",
    "read_request",
    "request_path",
    "resolve_due_request",
    "update_pending_request_policy",
    "workload_counts",
    "workload_total",
]
