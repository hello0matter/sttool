from __future__ import annotations

import hashlib
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .asset_bus import AssetBus, atomic_json_write, now_text, read_json


CANDIDATE_FILE = "credential_audit.json"
DECISION_FILE = "credential_audit_decisions.json"
ACTIONS = {"save_only", "agent_default_dictionary", "agent_social_dictionary"}
_LOGIN_MARKERS = (
    "login",
    "signin",
    "sign-in",
    "logon",
    "后台",
    "登录",
)
_LOGIN_ROUTE_NAMES = {"auth", "authenticate", "oauth", "sso"}
_ADMIN_ENTRY_NAMES = {"admin", "manager", "console"}
_STATIC_SUFFIXES = {
    ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".gz",
    ".7z", ".rar", ".mp3", ".mp4", ".webm", ".log", ".txt", ".xml",
    ".json", ".yaml", ".yml", ".sql", ".bak",
}


def candidate_path(run_dir: Path) -> Path:
    return run_dir / "tool_data" / "credential_audit" / CANDIDATE_FILE


def decision_path(run_dir: Path) -> Path:
    return run_dir / "tool_data" / "credential_audit" / DECISION_FILE


def normalize_login_candidate(value: str) -> str:
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    path = parsed.path or "/"
    if Path(path).suffix.lower() in _STATIC_SUFFIXES:
        return ""
    segments = [item.casefold() for item in path.split("/") if item]
    if any(Path(segment).suffix.lower() in _STATIC_SUFFIXES for segment in segments[:-1]):
        return ""
    route_names = {
        Path(segment).stem.strip("-_.")
        for segment in segments
    }
    haystack = path.casefold()
    has_login_marker = any(marker in haystack for marker in _LOGIN_MARKERS)
    has_login_route = bool(route_names & _LOGIN_ROUTE_NAMES)
    last_segment = Path(segments[-1]) if segments else None
    is_admin_entry = bool(
        last_segment
        and not last_segment.suffix
        and last_segment.name in _ADMIN_ENTRY_NAMES
    )
    if not (has_login_marker or has_login_route or is_admin_entry):
        return ""
    normalized_path = path.rstrip("/") or "/"
    return urlunsplit(
        (parsed.scheme.lower(), parsed.netloc.lower(), normalized_path, parsed.query, "")
    )


def discover_login_candidates(
    run_dir: Path,
    bus: AssetBus,
    workflow: dict[str, object],
) -> dict[str, Any]:
    path = candidate_path(run_dir)
    value = read_json(path)
    candidates = value.get("candidates")
    if not isinstance(candidates, list):
        candidates = []
    by_id = {
        str(item.get("id") or ""): item
        for item in candidates
        if isinstance(item, dict) and item.get("id")
    }
    enabled = bool(workflow.get("credential_audit_enabled", True))
    default_action = str(
        workflow.get("credential_audit_default_action") or "save_only"
    )
    if default_action not in ACTIONS:
        default_action = "save_only"
    countdown = max(int(workflow.get("credential_audit_countdown_seconds") or 20), 3)
    policy = {
        "enabled": enabled,
        "default_action": default_action,
        "countdown_seconds": countdown,
        "wordlist_path": str(workflow.get("credential_audit_wordlist_path") or ""),
        "max_attempts": int(workflow.get("credential_audit_max_attempts") or 10),
        "requests_per_minute": int(
            workflow.get("credential_audit_requests_per_minute") or 10
        ),
        "concurrency": int(workflow.get("credential_audit_concurrency") or 1),
        "stop_on_defense": bool(
            workflow.get("credential_audit_stop_on_defense", True)
        ),
    }
    previous_policy = value.get("policy")
    policy_changed = previous_policy != policy
    changed = policy_changed
    for item in by_id.values():
        if (
            item.get("status") in {"pending", "approved_agent"}
            and not normalize_login_candidate(str(item.get("url") or ""))
        ):
            item.update(
                status="saved",
                action="save_only",
                decision_source="candidate_filter_tightened",
                decided_at=now_text(),
            )
            changed = True
    if not enabled:
        for item in by_id.values():
            if item.get("status") in {"pending", "approved_agent"}:
                item.update(
                    status="saved",
                    action="save_only",
                    decision_source="feature_disabled",
                    decided_at=now_text(),
                )
                changed = True
    elif policy_changed:
        deadline = (
            datetime.now().astimezone() + timedelta(seconds=countdown)
        ).isoformat(timespec="seconds")
        for item in by_id.values():
            if item.get("status") == "pending":
                item.update(
                    default_action=default_action,
                    decision_deadline_at=deadline,
                    wordlist_path=policy["wordlist_path"],
                )
    if enabled:
        for item in bus.value.get("assets", []):
            if not isinstance(item, dict) or item.get("type") != "url":
                continue
            url = normalize_login_candidate(str(item.get("value") or ""))
            if not url:
                continue
            identity = hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]
            if identity in by_id:
                continue
            created_at = now_text()
            by_id[identity] = {
                "id": identity,
                "url": url,
                "status": "pending",
                "source": ", ".join(map(str, item.get("sources", []))),
                "asset_generation": int(item.get("first_generation") or 0),
                "created_at": created_at,
                "decision_deadline_at": (
                    datetime.now().astimezone() + timedelta(seconds=countdown)
                ).isoformat(timespec="seconds"),
                "default_action": default_action,
                "username_candidates": [],
                "wordlist_path": policy["wordlist_path"],
            }
            changed = True
    if changed:
        value = {
            "schema_version": 1,
            "updated_at": now_text(),
            "policy": policy,
            "candidates": list(by_id.values())[-5000:],
        }
        atomic_json_write(path, value)
    return value


def pending_candidates(run_dir: Path) -> list[dict[str, Any]]:
    value = read_json(candidate_path(run_dir))
    rows = value.get("candidates")
    if not isinstance(rows, list):
        return []
    return [
        item
        for item in rows
        if isinstance(item, dict) and str(item.get("status") or "") == "pending"
    ]


def append_decisions(run_dir: Path, decisions: list[dict[str, object]]) -> None:
    path = decision_path(run_dir)
    value = read_json(path)
    rows = value.get("decisions")
    if not isinstance(rows, list):
        rows = []
    by_id = {
        str(item.get("id") or ""): item
        for item in rows
        if isinstance(item, dict) and item.get("id")
    }
    for decision in decisions:
        identity = str(decision.get("id") or "")
        action = str(decision.get("action") or "")
        if identity and action in ACTIONS:
            by_id[identity] = {
                **decision,
                "id": identity,
                "action": action,
                "decided_at": decision.get("decided_at") or now_text(),
            }
    atomic_json_write(
        path,
        {
            "schema_version": 1,
            "updated_at": now_text(),
            "decisions": list(by_id.values())[-5000:],
        },
    )


def resolve_candidate_decisions(run_dir: Path, now: float | None = None) -> int:
    path = candidate_path(run_dir)
    value = read_json(path)
    rows = value.get("candidates")
    if not isinstance(rows, list):
        return 0
    decision_value = read_json(decision_path(run_dir))
    decisions = decision_value.get("decisions")
    if not isinstance(decisions, list):
        decisions = []
    decision_by_id = {
        str(item.get("id") or ""): item
        for item in decisions
        if isinstance(item, dict)
    }
    current = time.time() if now is None else now
    changed = 0
    for item in rows:
        if not isinstance(item, dict) or item.get("status") != "pending":
            continue
        if item.get("countdown_paused_at"):
            continue
        identity = str(item.get("id") or "")
        decision = decision_by_id.get(identity)
        action = str((decision or {}).get("action") or "")
        source = str((decision or {}).get("decision_source") or "user")
        if action not in ACTIONS:
            deadline = str(item.get("decision_deadline_at") or "")
            try:
                due = bool(deadline) and datetime.fromisoformat(deadline).timestamp() <= current
            except (TypeError, ValueError, OSError, OverflowError):
                due = False
            if not due:
                continue
            action = str(item.get("default_action") or "save_only")
            source = "timeout_default"
        item.update(
            status="saved" if action == "save_only" else "approved_agent",
            action=action,
            decision_source=source,
            decided_at=str((decision or {}).get("decided_at") or now_text()),
            username_candidates=list((decision or {}).get("username_candidates") or []),
            wordlist_path=str(
                (decision or {}).get("wordlist_path") or item.get("wordlist_path") or ""
            ),
        )
        changed += 1
    if changed:
        value["updated_at"] = now_text()
        atomic_json_write(path, value)
    return changed


def approved_agent_candidates(run_dir: Path) -> list[dict[str, Any]]:
    value = read_json(candidate_path(run_dir))
    rows = value.get("candidates")
    if not isinstance(rows, list):
        return []
    return [
        item
        for item in rows
        if isinstance(item, dict)
        and str(item.get("status") or "") == "approved_agent"
    ]


def mark_candidates_running(
    run_dir: Path, candidate_ids: list[str], batch_number: int
) -> int:
    path = candidate_path(run_dir)
    value = read_json(path)
    rows = value.get("candidates")
    if not isinstance(rows, list):
        return 0
    selected = set(candidate_ids)
    changed = 0
    for item in rows:
        if (
            isinstance(item, dict)
            and str(item.get("id") or "") in selected
            and item.get("status") == "approved_agent"
        ):
            item.update(status="agent_running", agent_batch=batch_number)
            changed += 1
    if changed:
        value["updated_at"] = now_text()
        atomic_json_write(path, value)
    return changed


def finish_batch_candidates(run_dir: Path, batch_number: int, success: bool) -> int:
    path = candidate_path(run_dir)
    value = read_json(path)
    rows = value.get("candidates")
    if not isinstance(rows, list):
        return 0
    changed = 0
    for item in rows:
        if (
            isinstance(item, dict)
            and item.get("status") == "agent_running"
            and int(item.get("agent_batch") or 0) == batch_number
        ):
            item["status"] = "completed" if success else "approved_agent"
            if success:
                item["completed_at"] = now_text()
            else:
                item.pop("agent_batch", None)
            changed += 1
    if changed:
        value["updated_at"] = now_text()
        atomic_json_write(path, value)
    return changed


__all__ = [
    "ACTIONS",
    "append_decisions",
    "approved_agent_candidates",
    "candidate_path",
    "discover_login_candidates",
    "finish_batch_candidates",
    "mark_candidates_running",
    "normalize_login_candidate",
    "pending_candidates",
    "resolve_candidate_decisions",
]
