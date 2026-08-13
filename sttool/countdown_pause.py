from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable

import tkinter as tk

from .asset_bus import atomic_json_write, read_json


def _shift_deadline(item: dict[str, object], elapsed: timedelta) -> None:
    deadline_text = str(item.get("decision_deadline_at") or "")
    if not deadline_text:
        return
    try:
        deadline = datetime.fromisoformat(deadline_text)
    except ValueError:
        return
    item["decision_deadline_at"] = (deadline + elapsed).isoformat(timespec="seconds")


def set_countdown_paused(
    path: Path,
    paused: bool,
    *,
    collection: str | None = None,
    pending_only: bool = False,
) -> dict[str, object]:
    value = read_json(path)
    if not value:
        return value
    rows: list[dict[str, object]]
    if collection:
        raw_rows = value.get(collection)
        rows = [item for item in raw_rows if isinstance(item, dict)] if isinstance(raw_rows, list) else []
    else:
        rows = [value]
    now = datetime.now().astimezone()
    changed = False
    for item in rows:
        if pending_only and str(item.get("status") or "") != "pending":
            continue
        paused_at = str(item.get("countdown_paused_at") or "")
        if paused:
            if not paused_at:
                item["countdown_paused_at"] = now.isoformat(timespec="seconds")
                changed = True
            continue
        if not paused_at:
            continue
        try:
            started = datetime.fromisoformat(paused_at)
            if started.tzinfo is None:
                started = started.astimezone()
            elapsed = max(now - started, timedelta())
        except ValueError:
            elapsed = timedelta()
        _shift_deadline(item, elapsed)
        item.pop("countdown_paused_at", None)
        changed = True
    if changed:
        value["updated_at"] = now.isoformat(timespec="seconds")
        atomic_json_write(path, value)
    return value


class HoverCountdownPause:
    """Pause persisted countdowns while the pointer is inside a dialog."""

    def __init__(self, window: tk.Toplevel, on_change: Callable[[bool], None]) -> None:
        self.window = window
        self.on_change = on_change
        self.paused = False
        self._job: str | None = window.after(200, self._poll_pointer)

    def _poll_pointer(self) -> None:
        if not self.window.winfo_exists():
            return
        pointer_x = self.window.winfo_pointerx()
        pointer_y = self.window.winfo_pointery()
        left = self.window.winfo_rootx()
        top = self.window.winfo_rooty()
        inside = (
            left <= pointer_x < left + self.window.winfo_width()
            and top <= pointer_y < top + self.window.winfo_height()
        )
        if inside != self.paused:
            self.paused = inside
            self.on_change(inside)
        self._job = self.window.after(200, self._poll_pointer)

    def resume(self) -> None:
        if self._job is not None:
            try:
                self.window.after_cancel(self._job)
            except tk.TclError:
                pass
            self._job = None
        if self.paused:
            self.paused = False
            self.on_change(False)


__all__ = ["HoverCountdownPause", "set_countdown_paused"]
