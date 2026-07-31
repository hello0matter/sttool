from __future__ import annotations

import glob
import os
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

from .models import RunState, ToolDefinition
from .runtime import RuntimeManager, target_values
from .standalone_dialog import StandaloneToolDialog
from .window_control import focus_process_window


class _ResultContext(dict[str, str]):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


class ToolDetailsDialog(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Misc,
        tool: ToolDefinition,
        runs: list[RunState],
        selected_state: RunState | None = None,
        source_dir: Path | None = None,
        st_root: Path | None = None,
        manager: RuntimeManager | None = None,
        api_base_url: str = "",
        model: str = "",
        api_key: str = "",
    ) -> None:
        super().__init__(parent)
        self.tool = tool
        self.runs = [state for state in runs if tool.tool_id in state.selected_tools]
        self.run_by_label = {
            self._run_label(state): state for state in self.runs
        }
        self.result_by_item: dict[str, Path] = {}
        self.source_dir = source_dir or Path.cwd()
        self.st_root = st_root or self.source_dir
        self.manager = manager
        self.api_base_url = api_base_url
        self.model = model
        self.api_key = api_key

        self.title(f"工具详情与结果 - {tool.name}")
        self.geometry("920x620")
        self.minsize(720, 500)
        self.transient(parent)

        container = ttk.Frame(self, padding=18)
        container.pack(fill="both", expand=True)
        container.columnconfigure(0, weight=1)
        container.rowconfigure(6, weight=1)

        ttk.Label(
            container,
            text=tool.name,
            font=("Microsoft YaHei UI", 14, "bold"),
        ).grid(row=0, column=0, sticky="w")
        ttk.Label(
            container,
            text=(
                f"{tool.category}  |  "
                f"{'会发送网络请求' if tool.sends_requests else '本地工具'}  |  "
                f"{'使用工具协作 AI' if tool.uses_shared_ai else '不使用工具协作 AI'}"
            ),
        ).grid(row=1, column=0, sticky="w", pady=(4, 10))
        ttk.Label(
            container,
            text=tool.description or "未填写工具说明",
            wraplength=840,
            justify="left",
        ).grid(row=2, column=0, sticky="ew", pady=(0, 12))
        ttk.Label(
            container,
            text=f"入口：{tool.executable}\n工作目录：{tool.cwd}",
            wraplength=840,
            justify="left",
        ).grid(row=3, column=0, sticky="ew", pady=(0, 12))

        run_row = ttk.Frame(container)
        run_row.grid(row=4, column=0, sticky="ew", pady=(0, 10))
        ttk.Label(run_row, text="运行实例").pack(side="left", padx=(0, 8))
        self.run_var = tk.StringVar()
        self.run_box = ttk.Combobox(
            run_row,
            textvariable=self.run_var,
            values=list(self.run_by_label),
            state="readonly",
            width=70,
        )
        self.run_box.pack(side="left", fill="x", expand=True)
        self.run_box.bind("<<ComboboxSelected>>", lambda _event: self._refresh_results())

        ttk.Label(container, text="结果位置（双击打开）").grid(
            row=5, column=0, sticky="w", pady=(0, 5)
        )
        columns = ("status", "path")
        self.results_tree = ttk.Treeview(
            container,
            columns=columns,
            show="headings",
            selectmode="browse",
        )
        self.results_tree.heading("status", text="状态")
        self.results_tree.heading("path", text="文件或目录")
        self.results_tree.column("status", width=100, minwidth=80)
        self.results_tree.column("path", width=720, minwidth=300)
        self.results_tree.grid(row=6, column=0, sticky="nsew")
        results_scrollbar = ttk.Scrollbar(
            container,
            orient="vertical",
            command=self.results_tree.yview,
        )
        results_scrollbar.grid(row=6, column=1, sticky="ns")
        self.results_tree.configure(yscrollcommand=results_scrollbar.set)
        self.results_tree.bind("<Double-1>", lambda _event: self._open_result())

        actions = ttk.Frame(container)
        actions.grid(row=7, column=0, sticky="ew", pady=(12, 0))
        ttk.Button(actions, text="打开工具位置", command=self._open_tool_location).pack(
            side="left"
        )
        if tool.allow_standalone and manager is not None:
            ttk.Button(actions, text="单独执行", command=self._open_standalone).pack(
                side="left", padx=(8, 0)
            )
        ttk.Button(actions, text="打开工具面板", command=self._open_tool_panel).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(actions, text="打开所选结果", command=self._open_result).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(actions, text="打开运行目录", command=self._open_run_dir).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(actions, text="关闭", command=self.destroy).pack(side="right")

        initial = selected_state if selected_state in self.runs else None
        if initial is None and self.runs:
            initial = self.runs[0]
        if initial is not None:
            self.run_var.set(self._run_label(initial))
        self._refresh_results()

    @staticmethod
    def _run_label(state: RunState) -> str:
        return f"{state.project_name} | {state.run_id} | {state.status}"

    def _selected_run(self) -> RunState | None:
        return self.run_by_label.get(self.run_var.get())

    def _result_paths(self, state: RunState) -> list[Path]:
        run_dir = Path(state.run_dir)
        project_dir = run_dir.parent.parent
        context = _ResultContext({
            **target_values(state.target),
            "run_dir": str(run_dir),
            "project_dir": str(project_dir),
            "source_dir": str(self.source_dir),
            "st_root": str(self.st_root),
            "project_name": state.project_name,
            "scope": state.scope,
            "tool_dir": str(Path(self.tool.executable).parent),
        })
        paths: list[Path] = []
        for template in self.tool.result_paths:
            formatted = template.format_map(context)
            formatted_path = Path(formatted)
            if not formatted_path.is_absolute():
                formatted = str(run_dir / formatted_path)
            matches = [Path(item) for item in glob.glob(formatted)]
            paths.extend(matches or [Path(formatted)])
        return paths

    def _refresh_results(self) -> None:
        self.results_tree.delete(*self.results_tree.get_children())
        self.result_by_item = {}
        state = self._selected_run()
        if state is None:
            self.results_tree.insert(
                "", "end", values=("无实例", "该工具还没有关联的运行实例")
            )
            return
        paths = self._result_paths(state)
        if not paths:
            self.results_tree.insert(
                "", "end", values=("未配置", "请在工具编辑器中添加结果位置")
            )
            return
        for path in paths:
            item = self.results_tree.insert(
                "",
                "end",
                values=("已生成" if path.exists() else "等待生成", str(path)),
            )
            self.result_by_item[item] = path

    def _open_tool_location(self) -> None:
        path = Path(self.tool.executable)
        target = path if path.is_dir() else path.parent
        if target.exists():
            os.startfile(target)
            return
        messagebox.showerror("工具位置", f"位置不存在：{target}", parent=self)

    def _open_tool_panel(self) -> None:
        state = self._selected_run()
        if state is None:
            messagebox.showinfo("工具面板", "该工具还没有关联的运行实例。", parent=self)
            return
        process = next(
            (
                item
                for item in reversed(state.processes)
                if item.component_id == self.tool.tool_id
            ),
            None,
        )
        if process is None:
            messagebox.showinfo("工具面板", "该实例没有此工具的进程记录。", parent=self)
            return
        opened, message = focus_process_window(process.pid)
        if not opened:
            messagebox.showinfo("工具面板", message, parent=self)

    def _open_standalone(self) -> None:
        if self.manager is None:
            return
        state = self._selected_run()
        StandaloneToolDialog(
            self,
            self.manager,
            self.tool,
            initial_target=state.target if state is not None else "",
            api_base_url=self.api_base_url,
            model=self.model,
            api_key=self.api_key,
        )

    def _open_result(self) -> None:
        selected = self.results_tree.selection()
        path = self.result_by_item.get(selected[0]) if selected else None
        if path is None:
            messagebox.showinfo("工具结果", "请先选择一个结果位置。", parent=self)
            return
        if path.exists():
            os.startfile(path)
            return
        parent = path.parent
        while parent != parent.parent and not parent.exists():
            parent = parent.parent
        if parent.exists():
            os.startfile(parent)
        messagebox.showinfo(
            "工具结果",
            f"结果尚未生成，已打开最近的现有目录。\n\n预期位置：{path}",
            parent=self,
        )

    def _open_run_dir(self) -> None:
        state = self._selected_run()
        if state is None:
            messagebox.showinfo("运行目录", "该工具还没有关联的运行实例。", parent=self)
            return
        os.startfile(state.run_dir)
