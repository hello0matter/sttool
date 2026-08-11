from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk


class ProjectScopeDialog(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Misc,
        *,
        target: str,
        scope: str,
        processing_scope: str,
        require_confirmation: bool = False,
    ) -> None:
        super().__init__(parent)
        self.target = target.strip()
        self.result: dict[str, str] | None = None
        self.confirmed_var = tk.BooleanVar(value=not require_confirmation)
        self.title("项目范围")
        self.geometry("720x590")
        self.minsize(620, 500)
        self.transient(parent)
        self.protocol("WM_DELETE_WINDOW", self.destroy)

        body = ttk.Frame(self, padding=16)
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1)
        body.rowconfigure(2, weight=1)
        body.rowconfigure(7, weight=1)

        ttk.Label(
            body,
            text="授权范围",
            font=("Microsoft YaHei UI", 11, "bold"),
        ).grid(row=0, column=0, sticky="w")
        ttk.Label(
            body,
            text="每行一个域名、IP、CIDR 或 URL。这里决定哪些目标依法允许测试。",
        ).grid(row=1, column=0, sticky="w", pady=(3, 6))
        self.scope_text = self._text_box(body, 2, scope)
        ttk.Button(
            body,
            text="授权范围使用主要目标",
            command=lambda: self._replace(self.scope_text, self.target),
        ).grid(row=3, column=0, sticky="w", pady=(7, 14))

        ttk.Separator(body).grid(row=4, column=0, sticky="ew", pady=(0, 14))
        ttk.Label(
            body,
            text="自动处理范围",
            font=("Microsoft YaHei UI", 11, "bold"),
        ).grid(row=5, column=0, sticky="w")
        ttk.Label(
            body,
            text=(
                "从授权资产中进一步限制值得自动扫描的区域。域名包含其子域名；"
                "留空表示不额外限制，主要目标始终保留。"
            ),
            wraplength=660,
        ).grid(row=6, column=0, sticky="nw", pady=(3, 6))
        self.processing_scope_text = self._text_box(body, 7, processing_scope)
        ttk.Button(
            body,
            text="自动处理范围使用主要目标",
            command=lambda: self._replace(self.processing_scope_text, self.target),
        ).grid(row=8, column=0, sticky="w", pady=(7, 8))

        if require_confirmation:
            ttk.Checkbutton(
                body,
                text="我确认修改后的授权范围仍已获得安全测试授权",
                variable=self.confirmed_var,
            ).grid(row=9, column=0, sticky="w", pady=(4, 8))

        actions = ttk.Frame(body)
        actions.grid(row=10, column=0, sticky="e", pady=(8, 0))
        ttk.Button(actions, text="取消", command=self.destroy).pack(side="right")
        ttk.Button(actions, text="保存", command=self._save).pack(
            side="right", padx=(0, 8)
        )

        self.grab_set()
        self.scope_text.focus_set()

    @staticmethod
    def _text_box(parent: ttk.Frame, row: int, value: str) -> tk.Text:
        frame = ttk.Frame(parent)
        frame.grid(row=row, column=0, sticky="nsew")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        widget = tk.Text(
            frame,
            height=6,
            wrap="word",
            relief="solid",
            borderwidth=1,
            font=("Microsoft YaHei UI", 10),
        )
        widget.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=widget.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        widget.configure(yscrollcommand=scrollbar.set)
        widget.insert("1.0", value)
        return widget

    @staticmethod
    def _replace(widget: tk.Text, value: str) -> None:
        widget.delete("1.0", "end")
        if value:
            widget.insert("1.0", value)

    def _save(self) -> None:
        scope = self.scope_text.get("1.0", "end").strip()
        if not scope:
            messagebox.showerror("项目范围", "授权范围不能为空。", parent=self)
            return
        if not self.confirmed_var.get():
            messagebox.showerror(
                "项目范围", "请先确认修改后的授权范围仍已获得授权。", parent=self
            )
            return
        self.result = {
            "scope": scope,
            "asset_processing_scope": self.processing_scope_text.get(
                "1.0", "end"
            ).strip(),
        }
        self.destroy()


__all__ = ["ProjectScopeDialog"]
