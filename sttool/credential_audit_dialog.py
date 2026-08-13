from __future__ import annotations

import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Callable

from .credential_audit import append_decisions
from .countdown_pause import HoverCountdownPause, set_countdown_paused


_ACTION_TEXT = {
    "save_only": "仅保存待办，不执行口令验证",
    "agent_default_dictionary": "交给 Agent：使用默认字典",
    "agent_social_dictionary": "交给 Agent：生成社工字典",
}


class CredentialAuditDialog(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Misc,
        *,
        project_name: str,
        run_dir: Path,
        candidates: list[dict[str, object]],
        topmost: bool,
        on_close: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self.run_dir = run_dir
        self.candidates = candidates
        self.on_close = on_close
        self._closed = False
        self.default_action = str(candidates[0].get("default_action") or "save_only")
        if self.default_action not in _ACTION_TEXT:
            self.default_action = "save_only"
        self.action_var = tk.StringVar(value=_ACTION_TEXT[self.default_action])
        self.usernames_var = tk.StringVar()
        self.wordlist_var = tk.StringVar(
            value=str(candidates[0].get("wordlist_path") or "")
        )

        self.title(f"发现登录入口，需要确认 - {project_name}")
        self.geometry("860x590")
        self.minsize(760, 520)
        self.configure(bg="#111827")
        self.protocol("WM_DELETE_WINDOW", self._submit_default)
        if topmost:
            self.attributes("-topmost", True)

        banner = tk.Frame(self, bg="#9f1239", padx=18, pady=16)
        banner.pack(fill="x")
        tk.Label(
            banner,
            text="发现登录入口：口令验证可能触发验证码、限流或账号锁定",
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
        ttk.Label(body, text=f"本次发现 {len(candidates)} 个登录入口").pack(anchor="w")
        urls = tk.Text(body, height=8, wrap="none")
        urls.pack(fill="both", expand=True, pady=(6, 12))
        urls.insert("1.0", "\n".join(str(item.get("url") or "") for item in candidates))
        urls.configure(state="disabled")

        form = ttk.Frame(body)
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)
        ttk.Label(form, text="处理方式").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Combobox(
            form,
            textvariable=self.action_var,
            values=tuple(_ACTION_TEXT.values()),
            state="readonly",
        ).grid(row=0, column=1, columnspan=2, sticky="ew", padx=(14, 0), pady=4)
        ttk.Label(form, text="候选用户名").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=self.usernames_var).grid(
            row=1, column=1, columnspan=2, sticky="ew", padx=(14, 0), pady=4
        )
        ttk.Label(form, text="字典文件").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=self.wordlist_var).grid(
            row=2, column=1, sticky="ew", padx=(14, 8), pady=4
        )
        ttk.Button(form, text="浏览...", command=self._browse).grid(row=2, column=2, pady=4)
        ttk.Label(
            body,
            text=(
                "用户名可用逗号、分号或空格分隔。Agent 会先识别真实登录请求，再调用 Burp MCP/Skill；"
                "遇到验证码、HTTP 429 或锁定提示立即停止，成功口令不会写入报告和日志。"
            ),
            wraplength=800,
        ).pack(anchor="w", fill="x", pady=(10, 0))

        actions = ttk.Frame(self, padding=(18, 0, 18, 18))
        actions.pack(fill="x")
        ttk.Button(
            actions, text="仅保存待办", command=lambda: self._submit("save_only")
        ).pack(side="left")
        ttk.Button(actions, text="按所选方式处理", command=self._submit_selected).pack(
            side="right"
        )
        self.after(100, self._make_noticeable)
        self.after(250, self._tick_countdown)
        self._hover_pause = HoverCountdownPause(
            self,
            lambda paused: self._set_countdown_paused(paused),
        )

    def _browse(self) -> None:
        value = filedialog.askopenfilename(parent=self, title="选择口令字典")
        if value:
            self.wordlist_var.set(value)

    def _make_noticeable(self) -> None:
        try:
            self.deiconify()
            self.lift()
            self.bell()
            self.focus_force()
        except tk.TclError:
            pass

    def _remaining(self) -> int | None:
        deadlines = [str(item.get("decision_deadline_at") or "") for item in self.candidates]
        deadlines = [item for item in deadlines if item]
        if not deadlines:
            return None
        try:
            return max(0, int(datetime.fromisoformat(min(deadlines)).timestamp() - time.time()))
        except (TypeError, ValueError, OSError):
            return 0

    def _tick_countdown(self) -> None:
        if self._closed:
            return
        remaining = self._remaining()
        if getattr(self, "_hover_pause", None) and self._hover_pause.paused:
            remaining_text = "" if remaining is None else f"，剩余 {remaining} 秒"
            self.countdown_label.configure(
                text=f"鼠标位于窗口内：倒计时已暂停{remaining_text}；移出后继续，"
                f"到时默认：{_ACTION_TEXT[self.default_action]}。"
            )
        elif remaining is None:
            self.countdown_label.configure(
                text=f"默认动作：始终等待人工确认；当前选择为 {_ACTION_TEXT[self.default_action]}。"
            )
        else:
            self.countdown_label.configure(
                text=f"{remaining} 秒后按全局默认方式：{_ACTION_TEXT[self.default_action]}。"
            )
            if remaining <= 0:
                self._close_only()
                return
        self.after(250, self._tick_countdown)

    def _set_countdown_paused(self, paused: bool) -> None:
        value = set_countdown_paused(
            self.run_dir / "tool_data" / "credential_audit" / "credential_audit.json",
            paused,
            collection="candidates",
            pending_only=True,
        )
        candidates = value.get("candidates")
        if isinstance(candidates, list):
            self.candidates = [
                item for item in candidates
                if isinstance(item, dict) and item.get("status") == "pending"
            ]

    def _submit_selected(self) -> None:
        reverse = {label: action for action, label in _ACTION_TEXT.items()}
        self._submit(reverse.get(self.action_var.get(), "save_only"))

    def _submit_default(self) -> None:
        self._submit(self.default_action, "hidden_default")

    def _submit(self, action: str, source: str = "user") -> None:
        self._hover_pause.resume()
        usernames = [
            item.strip()
            for item in self.usernames_var.get().replace(";", ",").replace(" ", ",").split(",")
            if item.strip()
        ]
        append_decisions(
            self.run_dir,
            [
                {
                    "id": str(item.get("id") or ""),
                    "action": action,
                    "decision_source": source,
                    "username_candidates": usernames[:100],
                    "wordlist_path": self.wordlist_var.get().strip(),
                }
                for item in self.candidates
            ],
        )
        self._close_only()

    def _close_only(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.on_close:
            self.on_close()
        self.destroy()


__all__ = ["CredentialAuditDialog"]
