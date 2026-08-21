"""Automatic Windows UI Automation fallback for TscanPlus.

This module is deliberately separate from the Playwright adapter.  TscanPlus
embeds WebView2, and some installations ignore WebView2 DevTools policies.
UIA talks to the application's accessibility tree without moving the mouse or
requiring the Tscan window to be foreground.
"""

from __future__ import annotations

import re
import time
import ctypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


@dataclass
class UiaStageResult:
    name: str
    status: str
    submitted_targets: list[str]
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "submitted_targets": self.submitted_targets,
            "detail": self.detail,
            "controller": "windows_uia",
        }


def _normalise_targets(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        value = str(value).strip()
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _normalise_host_targets(values: list[str]) -> list[str]:
    hosts: list[str] = []
    for value in _normalise_targets(values):
        parsed = urlsplit(value if "://" in value else f"//{value}")
        host = (parsed.hostname or "").strip(".")
        if host:
            hosts.append(host)
    return _normalise_targets(hosts)


def _control_text(control: Any) -> str:
    try:
        return " ".join(
            part
            for part in (
                str(control.window_text() or ""),
                str(control.element_info.name or ""),
                str(control.element_info.automation_id or ""),
            )
            if part
        ).strip()
    except Exception:
        return ""


def _descendants(window: Any) -> list[Any]:
    try:
        return list(window.descendants())
    except Exception:
        return []


def _find(window: Any, patterns: tuple[str, ...], control_type: str | None = None) -> Any:
    lowered = tuple(pattern.lower() for pattern in patterns)
    for control in _descendants(window):
        try:
            if control_type and str(control.element_info.control_type) != control_type:
                continue
        except Exception:
            continue
        text = _control_text(control).lower()
        if any(pattern in text for pattern in lowered):
            return control
    return None


def _invoke(control: Any) -> None:
    """Invoke a UIA control without pyautogui or foreground activation."""
    try:
        control.invoke()
        return
    except Exception:
        pass
    try:
        control.iface_invoke.Invoke()
        return
    except Exception as exc:
        raise RuntimeError(f"控件不支持后台 Invoke：{_control_text(control)}") from exc


def _set_value(control: Any, value: str) -> None:
    # UIA's ValuePattern is preferred and does not synthesize mouse input.
    try:
        control.set_edit_text(value)
        return
    except Exception:
        pass
    try:
        control.iface_value.SetValue(value)
        return
    except Exception:
        pass
    raise RuntimeError(f"无法写入 Tscan 控件: {_control_text(control)}")


def _attach(pid: int, timeout: float) -> tuple[Any, bool]:
    try:
        from pywinauto import Application
    except ImportError as exc:
        raise RuntimeError("未安装 pywinauto，无法启用 Windows UIA 兜底") from exc
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            app = Application(backend="uia").connect(process=pid, timeout=2)
            windows = app.windows()
            if windows:
                window = windows[0]
                was_minimized = bool(window.is_minimized())
                # WebView2 exposes only its outer shell while minimized. Restore
                # without activating it so the accessibility tree can hydrate.
                if window.is_minimized():
                    ctypes.windll.user32.ShowWindow(window.handle, 4)  # SW_SHOWNOACTIVATE
                    time.sleep(0.4)
                return window, was_minimized
        except Exception as exc:
            last_error = exc
        time.sleep(0.5)
    raise RuntimeError(f"无法通过 UIA 接管 TscanPlus PID {pid}: {last_error or '窗口未找到'}")


def _select_tab(window: Any, names: tuple[str, ...]) -> bool:
    # Prefer real buttons.  WebView2 exposes some navigation labels as plain
    # Text elements; invoking those is not a confirmed state change.
    tab = (
        _find(window, names, "Button")
        or _find(window, names, "TabItem")
        or _find(window, names)
    )
    if tab is None:
        return False
    _invoke(tab)
    time.sleep(0.25)
    return True


def _dismiss_welcome(window: Any) -> bool:
    if _find(window, ("免责声明", "使用许可", "我同意所有条款")) is None:
        return False
    agreement = _find(window, ("我同意所有条款",), "CheckBox")
    if agreement is not None:
        try:
            checked = bool(agreement.get_toggle_state())
        except Exception:
            checked = True
        if not checked:
            try:
                agreement.toggle()
            except Exception:
                _invoke(agreement)
    confirm = _find(window, ("同意并继续", "确认"), "Button")
    if confirm is None:
        return False
    _invoke(confirm)
    time.sleep(0.75)
    return True


def _select_path(window: Any, path: tuple[tuple[str, ...], ...]) -> bool:
    for names in path:
        if not _select_tab(window, names):
            return False
    return True


def _target_box(window: Any) -> Any:
    for control in _descendants(window):
        try:
            if str(control.element_info.control_type) not in {"Edit", "Document"}:
                continue
        except Exception:
            continue
        text = _control_text(control).lower()
        if any(word in text for word in ("目标", "ip", "域名", "url", "地址")):
            return control
    # WebView2 accessibility trees sometimes expose placeholder-less editors.
    for control in _descendants(window):
        try:
            if str(control.element_info.control_type) in {"Edit", "Document"}:
                return control
        except Exception:
            pass
    return None


def _stage(
    window: Any,
    name: str,
    path: tuple[tuple[str, ...], ...],
    targets: list[str],
    buttons: tuple[str, ...],
) -> UiaStageResult:
    targets = _normalise_targets(targets)
    if not targets:
        return UiaStageResult(name, "skipped", [], "本轮没有匹配资产")
    if not _select_path(window, path):
        return UiaStageResult(name, "not_started", targets, "未找到对应 Tscan 标签")
    box = _target_box(window)
    if box is None:
        return UiaStageResult(name, "not_started", targets, "未找到目标输入框")
    _set_value(box, "\n".join(targets))
    button = _find(window, buttons, "Button") or _find(window, buttons)
    if button is None:
        return UiaStageResult(name, "not_started", targets, "未找到启动按钮")
    _invoke(button)
    return UiaStageResult(name, "submitted", targets, "已通过 Windows UIA 自动提交")


def dispatch_uia_stages(
    pid: int,
    target: str,
    assets: dict[str, list[str]],
    *,
    timeout: float = 20.0,
) -> dict[str, Any]:
    """Submit the safe discovery stages through Tscan's accessibility tree."""
    window, was_minimized = _attach(pid, timeout)
    _dismiss_welcome(window)
    plan = (
        (
            "port_scan",
            (("信息收集",),),
            _normalise_host_targets(assets.get("ips", [])),
            ("查询", "Scan", "开始扫描"),
        ),
        (
            "web_fingerprint",
            (("资产探测",), ("URL指纹识别", "Web指纹", "URL探测")),
            assets.get("urls", []),
            ("Scan", "开始", "扫描"),
        ),
        (
            "subdomain_enumeration",
            (("资产探测",), ("域名探测", "域名枚举")),
            assets.get("domains", []),
            ("Start", "开始", "扫描"),
        ),
        (
            "directory_enumeration",
            (("资产探测",), ("目录扫描", "目录枚举")),
            assets.get("urls", []),
            ("Check", "开始", "扫描"),
        ),
        (
            "jsfinder",
            (("资产探测",), ("JsFinder",)),
            assets.get("urls", []),
            ("Check", "开始", "扫描"),
        ),
        (
            "swagger",
            (("资产探测",), ("Swagger",)),
            assets.get("urls", []),
            ("Check", "开始", "扫描"),
        ),
        (
            "waf_detection",
            (("资产探测",), ("WAF识别", "WAF检测")),
            assets.get("urls", []),
            ("Check", "开始", "扫描"),
        ),
    )
    results: dict[str, dict[str, Any]] = {}
    try:
        for name, tabs, values, buttons in plan:
            try:
                results[name] = _stage(window, name, tabs, values, buttons).as_dict()
            except Exception as exc:
                results[name] = UiaStageResult(name, "failed", _normalise_targets(values), str(exc)).as_dict()
        return {
            "controller": "windows_uia",
            "target": target,
            "stages": results,
            "page_title": str(window.window_text() or "TscanPlus"),
        }
    finally:
        if was_minimized:
            try:
                ctypes.windll.user32.ShowWindow(window.handle, 6)  # SW_MINIMIZE
            except Exception:
                pass


__all__ = ["dispatch_uia_stages"]
