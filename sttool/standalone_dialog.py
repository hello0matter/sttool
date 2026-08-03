from __future__ import annotations

import os
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

from .models import StandaloneRunState, ToolDefinition
from .runtime import LaunchError, RuntimeManager


class StandaloneToolDialog(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Misc,
        manager: RuntimeManager,
        tool: ToolDefinition,
        initial_target: str = "",
        api_base_url: str = "",
        model: str = "",
        api_key: str = "",
        github_token: str = "",
    ) -> None:
        super().__init__(parent)
        self.manager = manager
        self.tool = tool
        self.api_base_url = api_base_url
        self.model = model
        self.api_key = api_key
        self.github_token = github_token
        self.state: StandaloneRunState | None = None
        self.result_by_item: dict[str, Path] = {}

        self.title(f"单独执行 - {tool.name}")
        self.geometry("820x560")
        self.minsize(700, 480)
        self.transient(parent)

        container = ttk.Frame(self, padding=18)
        container.pack(fill="both", expand=True)
        container.columnconfigure(0, weight=1)
        container.rowconfigure(5, weight=1)

        ttk.Label(
            container,
            text=tool.name,
            font=("Microsoft YaHei UI", 14, "bold"),
        ).grid(row=0, column=0, sticky="w")
        ttk.Label(container, text="目标 / URL / IP / CIDR").grid(
            row=1, column=0, sticky="w", pady=(14, 5)
        )
        self.target_var = tk.StringVar(value=initial_target)
        target_entry = ttk.Entry(container, textvariable=self.target_var)
        target_entry.grid(row=2, column=0, sticky="ew")

        self.authorization_var = tk.BooleanVar(value=False)
        authorization = ttk.Checkbutton(
            container,
            text="我确认已获得该目标的测试授权",
            variable=self.authorization_var,
        )
        authorization.grid(row=3, column=0, sticky="w", pady=(10, 12))
        if not tool.sends_requests:
            authorization.state(["disabled"])

        self.status_var = tk.StringVar(value="等待执行")
        ttk.Label(container, textvariable=self.status_var).grid(
            row=4, column=0, sticky="w", pady=(0, 6)
        )

        self.results_tree = ttk.Treeview(
            container,
            columns=("status", "path"),
            show="headings",
            selectmode="browse",
        )
        self.results_tree.heading("status", text="状态")
        self.results_tree.heading("path", text="独立结果位置")
        self.results_tree.column("status", width=100, minwidth=80)
        self.results_tree.column("path", width=620, minwidth=280)
        self.results_tree.grid(row=5, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(
            container,
            orient="vertical",
            command=self.results_tree.yview,
        )
        scrollbar.grid(row=5, column=1, sticky="ns")
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        self.results_tree.bind("<Double-1>", lambda _event: self._open_result())

        actions = ttk.Frame(container)
        actions.grid(row=6, column=0, sticky="ew", pady=(12, 0))
        self.run_button = ttk.Button(
            actions,
            text="执行一次",
            command=self._start,
        )
        self.run_button.pack(side="left")
        ttk.Button(actions, text="打开所选结果", command=self._open_result).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(actions, text="打开执行目录", command=self._open_run_dir).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(actions, text="关闭", command=self.destroy).pack(side="right")

        target_entry.focus_set()

    def _start(self) -> None:
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("单独执行", "请填写本次执行目标。", parent=self)
            return
        if self.tool.sends_requests and not self.authorization_var.get():
            messagebox.showerror(
                "单独执行",
                "必须确认已获得该目标的测试授权。",
                parent=self,
            )
            return
        if self.state is not None and self.state.status == "running":
            messagebox.showinfo("单独执行", "当前独立任务仍在运行。", parent=self)
            return
        self.run_button.state(["disabled"])
        self.status_var.set("正在启动")

        def worker() -> None:
            try:
                state = self.manager.start_standalone(
                    self.tool.tool_id,
                    target,
                    self.authorization_var.get(),
                    self.api_base_url,
                    self.model,
                    self.api_key,
                    self.github_token,
                )
                error = ""
            except (LaunchError, OSError, ValueError) as exc:
                state = None
                error = str(exc)
            self.after(0, lambda: self._started(state, error))

        threading.Thread(target=worker, daemon=True).start()

    def _started(self, state: StandaloneRunState | None, error: str) -> None:
        if error:
            self.status_var.set(f"启动失败：{error}")
            self.run_button.state(["!disabled"])
            messagebox.showerror("单独执行失败", error, parent=self)
            return
        assert state is not None
        self.state = state
        self._refresh()

    def _refresh(self) -> None:
        if self.state is None:
            return
        self.manager.refresh_standalone(self.state)
        status = {
            "starting": "正在启动",
            "running": "运行中",
            "completed": "已结束",
            "failed": "失败",
            "stopped": "已停止",
        }.get(self.state.status, self.state.status)
        pid_text = f"，PID {self.state.process.pid}" if self.state.process else ""
        self.status_var.set(f"{status}{pid_text} | {self.state.run_dir}")
        self.results_tree.delete(*self.results_tree.get_children())
        self.result_by_item = {}
        paths = [Path(value) for value in self.state.result_paths]
        if not paths:
            paths = [Path(self.state.run_dir)]
        for path in paths:
            item = self.results_tree.insert(
                "",
                "end",
                values=("已生成" if path.exists() else "等待生成", str(path)),
            )
            self.result_by_item[item] = path
        if self.state.status == "running":
            self.after(1000, self._refresh)
        else:
            self.run_button.state(["!disabled"])

    def _open_result(self) -> None:
        selected = self.results_tree.selection()
        path = self.result_by_item.get(selected[0]) if selected else None
        if path is None:
            messagebox.showinfo("独立结果", "请先选择结果位置。", parent=self)
            return
        if path.exists():
            os.startfile(path)
            return
        parent = path.parent
        while parent != parent.parent and not parent.exists():
            parent = parent.parent
        if parent.exists():
            os.startfile(parent)

    def _open_run_dir(self) -> None:
        if self.state is None:
            messagebox.showinfo("独立执行", "当前还没有独立执行记录。", parent=self)
            return
        os.startfile(self.state.run_dir)
