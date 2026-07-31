from __future__ import annotations

import tkinter as tk
from tkinter import ttk


class AssetCommanderSettingsDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc, settings: dict[str, object]) -> None:
        super().__init__(parent)
        self.result: dict[str, object] | None = None
        self.title("AssetCommander 碰撞设置")
        self.geometry("560x430")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        frame = ttk.Frame(self, padding=18)
        frame.pack(fill="both", expand=True)
        ttk.Label(
            frame,
            text="这些设置会在项目启动和恢复时传给 AssetCommander，并实际应用到 collision。",
            wraplength=510,
        ).pack(anchor="w", pady=(0, 14))

        self.vars: dict[str, tk.BooleanVar] = {}
        labels = (
            ("preserve_original_port", "保留原端口"),
            ("add_80", "补齐 80"),
            ("add_443", "补齐 443"),
            ("no_port", "无端口"),
            ("absolute_path", "绝对路径"),
            ("waf_header", "注入 WAF 绕过头"),
            ("force_sni", "强同步 SNI"),
        )
        grid = ttk.Frame(frame)
        grid.pack(fill="x")
        for index, (key, label) in enumerate(labels):
            variable = tk.BooleanVar(value=bool(settings.get(key)))
            self.vars[key] = variable
            ttk.Checkbutton(grid, text=label, variable=variable).grid(
                row=index // 2, column=index % 2, sticky="w", padx=(0, 28), pady=8
            )

        concurrency = ttk.Frame(frame)
        concurrency.pack(fill="x", pady=(18, 0))
        ttk.Label(concurrency, text="并发数（1-500）").pack(side="left")
        self.threads = tk.IntVar(value=int(settings.get("threads", 150)))
        ttk.Spinbox(
            concurrency,
            from_=1,
            to=500,
            textvariable=self.threads,
            width=10,
        ).pack(side="left", padx=(12, 0))

        actions = ttk.Frame(frame)
        actions.pack(fill="x", side="bottom")
        ttk.Button(actions, text="取消", command=self.destroy).pack(side="right")
        ttk.Button(actions, text="保存并应用", command=self._save).pack(
            side="right", padx=(0, 8)
        )

    def _save(self) -> None:
        self.result = {key: value.get() for key, value in self.vars.items()}
        self.result["threads"] = max(1, min(500, int(self.threads.get())))
        self.destroy()
