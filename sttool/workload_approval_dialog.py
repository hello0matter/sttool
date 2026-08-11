from __future__ import annotations

import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import ttk
from typing import Callable

from .workload_approval import decide_request


class WorkloadApprovalDialog(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Misc,
        *,
        request: dict[str, object],
        run_dir: Path,
        topmost: bool,
        on_close: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self.run_dir = run_dir
        self.request = request
        self.on_close = on_close
        self._closed = False
        self.title("需要确认：下一批 AI 执行待处理资产较多")
        self.geometry("760x430")
        self.minsize(680, 380)
        self.configure(bg="#111827")
        self.protocol("WM_DELETE_WINDOW", self._hide_with_default)
        if topmost:
            self.attributes("-topmost", True)

        banner = tk.Frame(self, bg="#9f1239", padx=18, pady=16)
        banner.pack(fill="x")
        tk.Label(
            banner,
            text="下一批 Codex/Claude 将处理较多新增资产，可能增加耗时和 API 消耗",
            bg="#9f1239",
            fg="white",
            font=("Microsoft YaHei UI", 14, "bold"),
        ).pack(anchor="w")
        self.countdown_label = tk.Label(
            banner,
            text="",
            bg="#9f1239",
            fg="#fff4cc",
            font=("Microsoft YaHei UI", 10, "bold"),
        )
        self.countdown_label.pack(anchor="w", pady=(6, 0))

        body = ttk.Frame(self, padding=18)
        body.pack(fill="both", expand=True)
        counts = request.get("counts") if isinstance(request.get("counts"), dict) else {}
        lines = [
            f"\u9879\u76ee\uff1a{request.get('project_name', '')}    \u8fd0\u884c\uff1a{request.get('run_id', '')}",
            f"\u8d44\u4ea7\u66f4\u65b0\u8f6e\u6b21\uff1a{request.get('generation_from', 0)} - {request.get('generation_to', 0)}",
            f"\u9884\u8ba1\u5904\u7406\u8d44\u4ea7\uff1a{request.get('total', 0)} \u6761",
            "\u6570\u91cf\u660e\u7ec6\uff1a" + "\u3001".join(
                f"{label} {counts.get(key, 0)}"
                for key, label in (("ips", "IP"), ("domains", "\u57df\u540d"), ("endpoints", "\u7aef\u70b9"), ("urls", "URL"))
                if counts.get(key, 0)
            ),
        ]
        ttk.Label(
            body,
            text="\n".join(lines)
            + "\n\n后台资产发现、fscan、Tscan、dirsearch 和报告整理不会因本窗口暂停。\n本窗口只决定是否启动下一批 Codex/Claude AI 执行。",
            justify="left",
            wraplength=700,
        ).pack(anchor="w", fill="x")

        actions = ttk.Frame(self, padding=(18, 0, 18, 18))
        actions.pack(fill="x")
        ttk.Button(actions, text="跳过本次 AI 执行", command=lambda: self._submit("reject")).pack(side="left")
        ttk.Button(actions, text="\u9690\u85cf\u63d0\u9192\uff08\u6309\u9ed8\u8ba4\u7b56\u7565\uff09", command=self._hide_with_default).pack(side="right")
        ttk.Button(actions, text="立即启动本次 AI 执行", command=lambda: self._submit("accept")).pack(side="right", padx=(0, 8))
        self.after(100, self._make_noticeable)
        self.after(250, self._tick_countdown)

    def _make_noticeable(self) -> None:
        try:
            self.deiconify()
            self.lift()
            self.bell()
            self.focus_force()
        except tk.TclError:
            pass

    def _remaining(self) -> int | None:
        deadline = str(self.request.get("decision_deadline_at") or "")
        if not deadline:
            return None
        try:
            return max(0, int(datetime.fromisoformat(deadline).timestamp() - time.time()))
        except (TypeError, ValueError, OSError):
            return 0

    def _tick_countdown(self) -> None:
        if self._closed:
            return
        remaining = self._remaining()
        if remaining is None:
            self.countdown_label.configure(text="等待人工确认，不会自动启动下一批 AI 执行。")
        else:
            default_text = "\u542f\u52a8" if self.request.get("default_action") == "accept" else "\u8df3\u8fc7"
            self.countdown_label.configure(text=f"{remaining} 秒后按默认策略：{default_text}本次 AI 执行。")
            if remaining <= 0:
                self._close_only()
                return
        self.after(250, self._tick_countdown)

    def _submit(self, action: str) -> None:
        decide_request(self.run_dir, action, "user")
        self._close_only()

    def _hide_with_default(self) -> None:
        default_action = str(self.request.get("default_action") or "accept")
        decide_request(self.run_dir, default_action, "hidden_default")
        self._close_only()

    def _close_only(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.on_close:
            self.on_close()
        self.destroy()


__all__ = ["WorkloadApprovalDialog"]
