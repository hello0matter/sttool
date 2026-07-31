from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from urllib.parse import urlsplit

from .models import DEFAULT_API_BASE_URL


class AISettingsDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc, api_base_url: str, model: str, api_key: str) -> None:
        super().__init__(parent)
        self.result: dict[str, str] | None = None
        self.title("工具协作 AI 设置")
        self.resizable(False, False)
        self.transient(parent)
        self.protocol("WM_DELETE_WINDOW", self.destroy)

        self.api_base_url_var = tk.StringVar(value=api_base_url or DEFAULT_API_BASE_URL)
        self.model_var = tk.StringVar(value=model or "gpt-5.5")
        self.api_key_var = tk.StringVar(value=api_key)
        self.show_key_var = tk.BooleanVar(value=False)

        content = ttk.Frame(self, padding=18)
        content.pack(fill="both", expand=True)
        content.columnconfigure(0, weight=1)

        ttk.Label(
            content,
            text="用于工具间信息汇总、传递与结果优化，不影响本地 Codex/Codexx。",
            wraplength=520,
        ).grid(row=0, column=0, sticky="w", pady=(0, 12))

        self.api_base_url_entry = self._field(
            content, 1, "OpenAI 兼容 API Base URL", self.api_base_url_var
        )
        self._field(content, 3, "默认模型", self.model_var)
        ttk.Label(content, text="API Key").grid(row=5, column=0, sticky="w", pady=(0, 5))
        key_row = ttk.Frame(content)
        key_row.grid(row=6, column=0, sticky="ew", pady=(0, 14))
        key_row.columnconfigure(0, weight=1)
        self.key_entry = ttk.Entry(key_row, textvariable=self.api_key_var, show="*", width=54)
        self.key_entry.grid(row=0, column=0, sticky="ew")
        ttk.Checkbutton(
            key_row,
            text="显示",
            variable=self.show_key_var,
            command=self._toggle_key,
        ).grid(row=0, column=1, padx=(8, 0))

        actions = ttk.Frame(content)
        actions.grid(row=7, column=0, sticky="e")
        ttk.Button(actions, text="取消", command=self.destroy).pack(side="left")
        ttk.Button(actions, text="保存", command=self._save).pack(side="left", padx=(8, 0))

        self.bind("<Escape>", lambda _event: self.destroy())
        self.bind("<Return>", lambda _event: self._save())
        self.update_idletasks()
        x = parent.winfo_rootx() + max(20, (parent.winfo_width() - self.winfo_width()) // 2)
        y = parent.winfo_rooty() + max(20, (parent.winfo_height() - self.winfo_height()) // 3)
        self.geometry(f"+{x}+{y}")
        self.grab_set()
        self.api_base_url_entry.focus_set()

    @staticmethod
    def _field(parent: ttk.Frame, row: int, label: str, variable: tk.StringVar) -> ttk.Entry:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=(0, 5))
        entry = ttk.Entry(parent, textvariable=variable, width=62)
        entry.grid(row=row + 1, column=0, sticky="ew", pady=(0, 14))
        return entry

    def _toggle_key(self) -> None:
        self.key_entry.configure(show="" if self.show_key_var.get() else "*")

    def _save(self) -> None:
        api_base_url = self.api_base_url_var.get().strip().rstrip("/")
        parsed = urlsplit(api_base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            messagebox.showerror(
                "工具协作 AI 设置",
                "API Base URL 必须是有效的 HTTP/HTTPS 地址",
                parent=self,
            )
            return
        model = self.model_var.get().strip()
        if not model:
            messagebox.showerror(
                "工具协作 AI 设置", "默认模型不能为空", parent=self
            )
            return
        self.result = {
            "api_base_url": api_base_url,
            "model": model,
            "api_key": self.api_key_var.get().strip(),
        }
        self.destroy()
