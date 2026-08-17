from __future__ import annotations

from typing import Final


DEFAULT_WORK_MODE: Final = "balanced"
REASONING_EFFORTS: Final = ("", "low", "medium", "high", "xhigh")

CREDENTIAL_AUDIT_DEFAULTS: Final = {
    "asset_processing_scope": "",
    "credential_audit_enabled": True,
    "credential_audit_project_override": False,
    "credential_audit_default_action": "save_only",
    "credential_audit_countdown_seconds": 20,
    "credential_audit_popup_enabled": True,
    "credential_audit_popup_topmost": True,
    "credential_audit_wordlist_path": "",
    "credential_audit_max_attempts": 10,
    "credential_audit_requests_per_minute": 10,
    "credential_audit_concurrency": 1,
    "credential_audit_stop_on_defense": True,
}

WORK_MODE_LABELS: Final = {
    "balanced": "平衡模式",
    "fast": "快速侦察",
    "deep": "深度发现",
    "cautious": "低速谨慎",
    "manual": "手动优先",
    "custom": "自定义",
}

WORK_MODE_PRESETS: Final = {
    "balanced": {
        "auto_agent": True,
        "wait_for_asset_commander": True,
        "wait_for_fscan": True,
        "asset_settle_seconds": 20,
        "max_agent_batches": 8,
        "coordinator_poll_seconds": 2,
        "agent_stall_warn_minutes": 15,
        "ai_summary_enabled": True,
        "fscan_skip_poc": True,
        "fscan_skip_brute": True,
        "fscan_port_threads": 600,
        "semantic_threads": 40,
        "semantic_max_depth": 2,
        "semantic_run_dirsearch": True,
        "semantic_max_rate": 0,
        "allow_cidr_expansion": False,
        "new_asset_approval_mode": "countdown_accept",
        "new_asset_countdown_seconds": 10,
        "new_asset_popup_enabled": True,
        "new_asset_popup_topmost": True,
        "workload_approval_mode": "countdown_accept",
        "workload_countdown_seconds": 10,
        "workload_agent_threshold": 50,
        "workload_popup_enabled": True,
        "workload_popup_topmost": True,
    },
    "fast": {
        "auto_agent": True,
        "wait_for_asset_commander": False,
        "wait_for_fscan": False,
        "asset_settle_seconds": 8,
        "max_agent_batches": 8,
        "coordinator_poll_seconds": 1,
        "agent_stall_warn_minutes": 15,
        "ai_summary_enabled": True,
        "fscan_skip_poc": True,
        "fscan_skip_brute": True,
        "fscan_port_threads": 600,
        "semantic_threads": 30,
        "semantic_max_depth": 1,
        "semantic_run_dirsearch": False,
        "semantic_max_rate": 0,
        "allow_cidr_expansion": False,
        "new_asset_approval_mode": "countdown_accept",
        "new_asset_countdown_seconds": 10,
        "new_asset_popup_enabled": True,
        "new_asset_popup_topmost": True,
        "workload_approval_mode": "countdown_accept",
        "workload_countdown_seconds": 10,
        "workload_agent_threshold": 50,
        "workload_popup_enabled": True,
        "workload_popup_topmost": True,
    },
    "deep": {
        "auto_agent": True,
        "wait_for_asset_commander": True,
        "wait_for_fscan": True,
        "asset_settle_seconds": 30,
        "max_agent_batches": 16,
        "coordinator_poll_seconds": 2,
        "agent_stall_warn_minutes": 30,
        "ai_summary_enabled": True,
        "fscan_skip_poc": False,
        "fscan_skip_brute": False,
        "fscan_port_threads": 600,
        "semantic_threads": 60,
        "semantic_max_depth": 3,
        "semantic_run_dirsearch": True,
        "semantic_max_rate": 0,
        "allow_cidr_expansion": False,
        "new_asset_approval_mode": "countdown_accept",
        "new_asset_countdown_seconds": 10,
        "new_asset_popup_enabled": True,
        "new_asset_popup_topmost": True,
        "workload_approval_mode": "countdown_accept",
        "workload_countdown_seconds": 10,
        "workload_agent_threshold": 50,
        "workload_popup_enabled": True,
        "workload_popup_topmost": True,
    },
    "cautious": {
        "auto_agent": True,
        "wait_for_asset_commander": True,
        "wait_for_fscan": True,
        "asset_settle_seconds": 60,
        "max_agent_batches": 4,
        "coordinator_poll_seconds": 5,
        "agent_stall_warn_minutes": 30,
        "ai_summary_enabled": True,
        "fscan_skip_poc": True,
        "fscan_skip_brute": True,
        "fscan_port_threads": 300,
        "semantic_threads": 20,
        "semantic_max_depth": 1,
        "semantic_run_dirsearch": False,
        "semantic_max_rate": 50,
        "allow_cidr_expansion": False,
        "new_asset_approval_mode": "countdown_accept",
        "new_asset_countdown_seconds": 10,
        "new_asset_popup_enabled": True,
        "new_asset_popup_topmost": True,
        "workload_approval_mode": "countdown_accept",
        "workload_countdown_seconds": 10,
        "workload_agent_threshold": 50,
        "workload_popup_enabled": True,
        "workload_popup_topmost": True,
    },
    "manual": {
        "auto_agent": False,
        "wait_for_asset_commander": True,
        "wait_for_fscan": True,
        "asset_settle_seconds": 20,
        "max_agent_batches": 8,
        "coordinator_poll_seconds": 3,
        "agent_stall_warn_minutes": 15,
        "ai_summary_enabled": False,
        "fscan_skip_poc": True,
        "fscan_skip_brute": True,
        "fscan_port_threads": 300,
        "semantic_threads": 20,
        "semantic_max_depth": 1,
        "semantic_run_dirsearch": False,
        "semantic_max_rate": 50,
        "allow_cidr_expansion": False,
        "new_asset_approval_mode": "countdown_accept",
        "new_asset_countdown_seconds": 10,
        "new_asset_popup_enabled": True,
        "new_asset_popup_topmost": True,
        "workload_approval_mode": "countdown_accept",
        "workload_countdown_seconds": 10,
        "workload_agent_threshold": 50,
        "workload_popup_enabled": True,
        "workload_popup_topmost": True,
    },
}


def normalized_reasoning_effort(value: object) -> str:
    effort = str(value or "").strip().lower()
    return effort if effort in REASONING_EFFORTS else ""


def work_mode_defaults(mode: object) -> dict[str, object]:
    normalized = str(mode or DEFAULT_WORK_MODE).strip().lower()
    if normalized not in WORK_MODE_PRESETS:
        normalized = DEFAULT_WORK_MODE
    return {
        "work_mode": normalized,
        **WORK_MODE_PRESETS[normalized],
        **CREDENTIAL_AUDIT_DEFAULTS,
    }


def normalize_workflow_settings(value: object) -> dict[str, object]:
    source = value if isinstance(value, dict) else {}
    requested_mode = str(source.get("work_mode") or DEFAULT_WORK_MODE).strip().lower()
    base_mode = (
        requested_mode if requested_mode in WORK_MODE_PRESETS else DEFAULT_WORK_MODE
    )
    result = work_mode_defaults(base_mode)

    bool_fields = (
        "auto_agent",
        "wait_for_asset_commander",
        "wait_for_fscan",
        "ai_summary_enabled",
        "fscan_skip_poc",
        "fscan_skip_brute",
        "semantic_run_dirsearch",
        "allow_cidr_expansion",
        "new_asset_popup_enabled",
        "new_asset_popup_topmost",
        "workload_popup_enabled",
        "workload_popup_topmost",
        "credential_audit_enabled",
        "credential_audit_project_override",
        "credential_audit_popup_enabled",
        "credential_audit_popup_topmost",
        "credential_audit_stop_on_defense",
    )
    int_ranges = {
        "asset_settle_seconds": (1, 600),
        "max_agent_batches": (1, 100),
        "coordinator_poll_seconds": (1, 60),
        "agent_stall_warn_minutes": (0, 1440),
        "fscan_port_threads": (1, 2000),
        "semantic_threads": (1, 200),
        "semantic_max_depth": (0, 10),
        "semantic_max_rate": (0, 10000),
        "new_asset_countdown_seconds": (3, 3600),
        "workload_countdown_seconds": (3, 3600),
        "workload_agent_threshold": (1, 100000),
        "credential_audit_countdown_seconds": (3, 3600),
        "credential_audit_max_attempts": (1, 1000),
        "credential_audit_requests_per_minute": (1, 600),
        "credential_audit_concurrency": (1, 20),
    }
    approval_mode = str(
        source.get("new_asset_approval_mode")
        or result.get("new_asset_approval_mode")
        or "countdown_accept"
    ).strip().lower()
    if approval_mode not in {"automatic", "countdown_accept", "countdown_reject", "manual"}:
        approval_mode = "countdown_accept"
    result["new_asset_approval_mode"] = approval_mode
    workload_mode = str(
        source.get("workload_approval_mode")
        or result.get("workload_approval_mode")
        or "countdown_accept"
    ).strip().lower()
    if workload_mode not in {"automatic", "countdown_accept", "countdown_reject", "manual"}:
        workload_mode = "countdown_accept"
    result["workload_approval_mode"] = workload_mode
    credential_action = str(
        source.get("credential_audit_default_action")
        or result["credential_audit_default_action"]
    ).strip().lower()
    if credential_action not in {
        "save_only",
        "agent_default_dictionary",
        "agent_social_dictionary",
    }:
        credential_action = "save_only"
    result["credential_audit_default_action"] = credential_action
    result["credential_audit_wordlist_path"] = str(
        source.get("credential_audit_wordlist_path")
        or result["credential_audit_wordlist_path"]
    ).strip()
    result["asset_processing_scope"] = str(
        source.get("asset_processing_scope")
        if source.get("asset_processing_scope") is not None
        else result["asset_processing_scope"]
    ).strip()
    baseline = work_mode_defaults(base_mode)
    customized = requested_mode == "custom"
    for field in bool_fields:
        if field in source:
            result[field] = bool(source[field])
            customized = (
                customized or result[field] != baseline[field]
            )
    for field, (minimum, maximum) in int_ranges.items():
        if field not in source:
            continue
        try:
            number = int(source[field])
        except (TypeError, ValueError):
            continue
        result[field] = max(minimum, min(maximum, number))
        customized = customized or result[field] != baseline[field]
    customized = customized or result["new_asset_approval_mode"] != WORK_MODE_PRESETS[base_mode]["new_asset_approval_mode"]
    customized = customized or result["workload_approval_mode"] != WORK_MODE_PRESETS[base_mode]["workload_approval_mode"]
    customized = customized or result["credential_audit_default_action"] != baseline["credential_audit_default_action"]
    customized = customized or result["credential_audit_wordlist_path"] != baseline["credential_audit_wordlist_path"]
    customized = customized or result["asset_processing_scope"] != baseline["asset_processing_scope"]
    if customized:
        result["work_mode"] = "custom"
    return result
