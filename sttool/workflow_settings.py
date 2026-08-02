from __future__ import annotations

from typing import Final


DEFAULT_WORK_MODE: Final = "balanced"
REASONING_EFFORTS: Final = ("", "low", "medium", "high", "xhigh")

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
        "ai_summary_enabled": True,
    },
    "fast": {
        "auto_agent": True,
        "wait_for_asset_commander": False,
        "wait_for_fscan": False,
        "asset_settle_seconds": 8,
        "max_agent_batches": 8,
        "coordinator_poll_seconds": 1,
        "ai_summary_enabled": True,
    },
    "deep": {
        "auto_agent": True,
        "wait_for_asset_commander": True,
        "wait_for_fscan": True,
        "asset_settle_seconds": 30,
        "max_agent_batches": 16,
        "coordinator_poll_seconds": 2,
        "ai_summary_enabled": True,
    },
    "cautious": {
        "auto_agent": True,
        "wait_for_asset_commander": True,
        "wait_for_fscan": True,
        "asset_settle_seconds": 60,
        "max_agent_batches": 4,
        "coordinator_poll_seconds": 5,
        "ai_summary_enabled": True,
    },
    "manual": {
        "auto_agent": False,
        "wait_for_asset_commander": True,
        "wait_for_fscan": True,
        "asset_settle_seconds": 20,
        "max_agent_batches": 8,
        "coordinator_poll_seconds": 3,
        "ai_summary_enabled": False,
    },
}


def normalized_reasoning_effort(value: object) -> str:
    effort = str(value or "").strip().lower()
    return effort if effort in REASONING_EFFORTS else ""


def work_mode_defaults(mode: object) -> dict[str, object]:
    normalized = str(mode or DEFAULT_WORK_MODE).strip().lower()
    if normalized not in WORK_MODE_PRESETS:
        normalized = DEFAULT_WORK_MODE
    return {"work_mode": normalized, **WORK_MODE_PRESETS[normalized]}


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
    )
    int_ranges = {
        "asset_settle_seconds": (1, 600),
        "max_agent_batches": (1, 100),
        "coordinator_poll_seconds": (1, 60),
    }
    customized = requested_mode == "custom"
    for field in bool_fields:
        if field in source:
            result[field] = bool(source[field])
            customized = (
                customized or result[field] != WORK_MODE_PRESETS[base_mode][field]
            )
    for field, (minimum, maximum) in int_ranges.items():
        if field not in source:
            continue
        try:
            number = int(source[field])
        except (TypeError, ValueError):
            continue
        result[field] = max(minimum, min(maximum, number))
        customized = customized or result[field] != WORK_MODE_PRESETS[base_mode][field]
    if customized:
        result["work_mode"] = "custom"
    return result
