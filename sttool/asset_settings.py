from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk


class AssetCommanderSettingsDialog(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Misc,
        settings: dict[str, object],
        location: str,
    ) -> None:
        super().__init__(parent)
        self.result: dict[str, object] | None = None
        self.location_result: str | None = None
        self.title("AssetCommander 工具与碰撞设置")
        self.geometry("680x520")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        frame = ttk.Frame(self, padding=18)
        frame.pack(fill="both", expand=True)
        ttk.Label(
            frame,
            text=(
                "工具目录和碰撞设置都会保存到本机。项目启动或恢复时，"
                "STTool 会从此目录启动 AssetCommander，并把下面的设置实际应用到 collision。"
            ),
            wraplength=630,
        ).pack(anchor="w", pady=(0, 12))

        ttk.Label(
            frame,
            text="AssetCommander 工具目录（应包含 main.py）",
        ).pack(anchor="w")
        location_row = ttk.Frame(frame)
        location_row.pack(fill="x", pady=(6, 14))
        self.location = tk.StringVar(value=location)
        ttk.Entry(location_row, textvariable=self.location).pack(
            side="left", fill="x", expand=True
        )
        ttk.Button(
            location_row,
            text="浏览…",
            command=self._browse_location,
        ).pack(side="left", padx=(8, 0))

        ttk.Separator(frame).pack(fill="x", pady=(0, 12))
        ttk.Label(frame, text="碰撞参数").pack(anchor="w", pady=(0, 4))

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
                row=index // 2,
                column=index % 2,
                sticky="w",
                padx=(0, 28),
                pady=8,
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

    def _browse_location(self) -> None:
        current = Path(self.location.get().strip() or ".")
        initial = current if current.is_dir() else current.parent
        selected = filedialog.askdirectory(
            parent=self,
            title="选择 AssetCommander 工具目录",
            initialdir=str(initial),
        )
        if selected:
            self.location.set(selected)

    def _save(self) -> None:
        raw_location = self.location.get().strip()
        if not raw_location:
            messagebox.showerror(
                "工具目录",
                "请选择 AssetCommander 工具目录。",
                parent=self,
            )
            return
        location = Path(raw_location).expanduser()
        if not location.is_dir():
            messagebox.showerror(
                "工具目录",
                f"目录不存在：{location}",
                parent=self,
            )
            return
        if not (location / "main.py").is_file():
            messagebox.showerror(
                "工具目录",
                f"所选目录中没有 main.py：{location}",
                parent=self,
            )
            return
        self.location_result = str(location.resolve())
        self.result = {key: value.get() for key, value in self.vars.items()}
        self.result["threads"] = max(1, min(500, int(self.threads.get())))
        self.destroy()
