from __future__ import annotations

import os
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

from .models import LaunchRequest, RunState, ToolDefinition
from .registry import availability
from .runtime import LaunchError, RuntimeManager, safe_project_name


BG = "#f4f5f7"
PANEL = "#ffffff"
TEXT = "#20242a"
MUTED = "#667085"
ACCENT = "#176b51"
DANGER = "#b42318"


class LauncherApp(tk.Tk):
    def __init__(self, manager: RuntimeManager, tools: tuple[ToolDefinition, ...]) -> None:
        super().__init__()
        self.manager = manager
        self.tools = tools
        self.tool_vars: dict[str, tk.BooleanVar] = {}
        self.run_states: dict[str, RunState] = {}
        self._busy = False

        self.title("STTool 渗透项目总控台")
        width = min(1180, self.winfo_screenwidth() - 80)
        height = min(760, self.winfo_screenheight() - 100)
        left = max(20, (self.winfo_screenwidth() - width) // 2)
        top = max(20, (self.winfo_screenheight() - height) // 2)
        self.geometry(f"{width}x{height}+{left}+{top}")
        self.minsize(min(980, width), min(650, height))
        self.configure(bg=BG)
        self._configure_style()
        self._build_ui()
        self._load_runs()
        self._refresh_health()
        self.after(2000, self._tick)

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", font=("Microsoft YaHei UI", 10), background=BG, foreground=TEXT)
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Panel.TLabel", background=PANEL, foreground=TEXT)
        style.configure("Muted.TLabel", background=PANEL, foreground=MUTED)
        style.configure("Title.TLabel", background=BG, foreground=TEXT, font=("Microsoft YaHei UI", 18, "bold"))
        style.configure("Accent.TButton", background=ACCENT, foreground="white", padding=(16, 9))
        style.map("Accent.TButton", background=[("active", "#125541"), ("disabled", "#98a2b3")])
        style.configure("Danger.TButton", foreground=DANGER)
        style.configure("Treeview", rowheight=30, background=PANEL, fieldbackground=PANEL)
        style.configure("Treeview.Heading", font=("Microsoft YaHei UI", 9, "bold"))
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", padding=(16, 8))

    def _build_ui(self) -> None:
        header = ttk.Frame(self, padding=(24, 18, 24, 10))
        header.pack(fill="x")
        ttk.Label(header, text="渗透项目总控台", style="Title.TLabel").pack(side="left")
        self.health_label = ttk.Label(header, text="CLI 检测中", foreground=MUTED)
        self.health_label.pack(side="right", pady=5)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=24, pady=(0, 20))
        self.launch_tab = ttk.Frame(self.notebook, padding=16, style="Panel.TFrame")
        self.runs_tab = ttk.Frame(self.notebook, padding=16, style="Panel.TFrame")
        self.tools_tab = ttk.Frame(self.notebook, padding=16, style="Panel.TFrame")
        self.notebook.add(self.launch_tab, text="项目启动")
        self.notebook.add(self.runs_tab, text="运行实例")
        self.notebook.add(self.tools_tab, text="工具清单")
        self._build_launch_tab()
        self._build_runs_tab()
        self._build_tools_tab()

    @staticmethod
    def _field(parent: ttk.Frame, row: int, label: str, variable: tk.StringVar, width: int = 42) -> ttk.Entry:
        ttk.Label(parent, text=label, style="Panel.TLabel").grid(row=row, column=0, sticky="w", pady=(0, 5))
        entry = ttk.Entry(parent, textvariable=variable, width=width)
        entry.grid(row=row + 1, column=0, sticky="ew", pady=(0, 14))
        return entry

    def _build_launch_tab(self) -> None:
        self.launch_tab.columnconfigure(0, weight=1, uniform="launch")
        self.launch_tab.columnconfigure(1, weight=1, uniform="launch")
        left = ttk.Frame(self.launch_tab, padding=(8, 6, 24, 8), style="Panel.TFrame")
        right = ttk.Frame(self.launch_tab, padding=(24, 6, 8, 8), style="Panel.TFrame")
        left.grid(row=0, column=0, sticky="nsew")
        right.grid(row=0, column=1, sticky="nsew")
        left.columnconfigure(0, weight=1)
        right.columnconfigure(0, weight=1)

        self.project_var = tk.StringVar()
        self.target_var = tk.StringVar()
        self.scope_var = tk.StringVar()
        self.provider_var = tk.StringVar(value="codex")
        self.model_var = tk.StringVar(value="gpt-5.5")
        self.auth_var = tk.BooleanVar(value=False)

        ttk.Label(left, text="项目配置", style="Panel.TLabel", font=("Microsoft YaHei UI", 12, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 14))
        ttk.Label(left, text="项目名称", style="Panel.TLabel").grid(row=1, column=0, sticky="w", pady=(0, 5))
        project_box = ttk.Combobox(left, textvariable=self.project_var, values=self.manager.list_projects())
        project_box.grid(row=2, column=0, sticky="ew", pady=(0, 14))
        project_box.bind("<<ComboboxSelected>>", lambda _event: self._load_project())
        self._field(left, 3, "主要目标（URL、域名或 IP）", self.target_var)
        self._field(left, 5, "授权范围", self.scope_var)

        ttk.Label(left, text="补充任务", style="Panel.TLabel").grid(row=7, column=0, sticky="w", pady=(0, 5))
        self.prompt_text = tk.Text(left, width=1, height=8, wrap="word", relief="solid", borderwidth=1, font=("Microsoft YaHei UI", 10))
        self.prompt_text.grid(row=8, column=0, sticky="nsew", pady=(0, 12))
        left.rowconfigure(8, weight=1)
        ttk.Checkbutton(
            left,
            text="我确认已获得上述范围的安全测试授权",
            variable=self.auth_var,
        ).grid(row=9, column=0, sticky="w")

        ttk.Label(right, text="AI Agent", style="Panel.TLabel", font=("Microsoft YaHei UI", 12, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 14))
        provider_row = ttk.Frame(right, style="Panel.TFrame")
        provider_row.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        ttk.Radiobutton(provider_row, text="Codex CLI", value="codex", variable=self.provider_var, command=self._provider_changed).pack(side="left", padx=(0, 18))
        ttk.Radiobutton(provider_row, text="Claude CLI", value="claude", variable=self.provider_var, command=self._provider_changed).pack(side="left")
        self._field(right, 2, "模型", self.model_var, width=30)

        ttk.Separator(right).grid(row=4, column=0, sticky="ew", pady=(2, 16))
        ttk.Label(right, text="随项目启动", style="Panel.TLabel", font=("Microsoft YaHei UI", 12, "bold")).grid(row=5, column=0, sticky="w", pady=(0, 10))
        tool_frame = ttk.Frame(right, style="Panel.TFrame")
        tool_frame.grid(row=6, column=0, sticky="nsew")
        right.rowconfigure(6, weight=1)
        for index, tool in enumerate(self.tools):
            available, reason = availability(tool)
            variable = tk.BooleanVar(value=tool.default_selected and available)
            self.tool_vars[tool.tool_id] = variable
            box = ttk.Checkbutton(tool_frame, text=tool.name, variable=variable)
            box.grid(row=index, column=0, sticky="w", pady=3)
            if not available:
                box.state(["disabled"])
            detail = tool.description if available else reason
            ttk.Label(tool_frame, text=detail, style="Muted.TLabel", wraplength=260).grid(row=index, column=1, sticky="w", padx=(12, 0), pady=3)

        action = ttk.Frame(right, style="Panel.TFrame")
        action.grid(row=7, column=0, sticky="ew", pady=(18, 0))
        self.start_button = ttk.Button(action, text="启动新实例", style="Accent.TButton", command=self._start)
        self.start_button.pack(side="left")
        ttk.Button(action, text="打开项目目录", command=self._open_project_dir).pack(side="left", padx=(10, 0))
        self.launch_status = ttk.Label(right, text="每次启动都会创建独立运行目录", style="Muted.TLabel")
        self.launch_status.grid(row=8, column=0, sticky="w", pady=(12, 0))

    def _build_runs_tab(self) -> None:
        self.runs_tab.columnconfigure(0, weight=1)
        self.runs_tab.rowconfigure(1, weight=1)
        actions = ttk.Frame(self.runs_tab, style="Panel.TFrame")
        actions.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        ttk.Button(actions, text="刷新", command=self._refresh_runs).pack(side="left")
        ttk.Button(actions, text="打开运行目录", command=self._open_selected_run).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="停止实例", style="Danger.TButton", command=self._stop_selected_run).pack(side="right")

        columns = ("project", "run_id", "provider", "status", "components", "created")
        self.run_tree = ttk.Treeview(self.runs_tab, columns=columns, show="headings", selectmode="browse")
        headings = {"project": "项目", "run_id": "实例", "provider": "Agent", "status": "状态", "components": "组件", "created": "启动时间"}
        widths = {"project": 150, "run_id": 155, "provider": 90, "status": 90, "components": 260, "created": 170}
        for column in columns:
            self.run_tree.heading(column, text=headings[column])
            self.run_tree.column(column, width=widths[column], minwidth=70)
        self.run_tree.grid(row=1, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(self.runs_tab, orient="vertical", command=self.run_tree.yview)
        scrollbar.grid(row=1, column=1, sticky="ns")
        self.run_tree.configure(yscrollcommand=scrollbar.set)
        self.run_tree.tag_configure("running", foreground=ACCENT)
        self.run_tree.tag_configure("failed", foreground=DANGER)

    def _build_tools_tab(self) -> None:
        self.tools_tab.columnconfigure(0, weight=1)
        self.tools_tab.rowconfigure(1, weight=1)
        ttk.Label(
            self.tools_tab,
            text="首批纳管工具。自动扫描项只有在明确勾选后才会随项目启动。",
            style="Muted.TLabel",
        ).grid(row=0, column=0, sticky="w", pady=(0, 12))
        columns = ("name", "category", "state", "mode", "path")
        tree = ttk.Treeview(self.tools_tab, columns=columns, show="headings")
        for column, text, width in (
            ("name", "工具", 170),
            ("category", "类别", 110),
            ("state", "检测", 100),
            ("mode", "启动方式", 110),
            ("path", "入口", 540),
        ):
            tree.heading(column, text=text)
            tree.column(column, width=width)
        tree.grid(row=1, column=0, sticky="nsew")
        for tool in self.tools:
            available, reason = availability(tool)
            tree.insert("", "end", values=(tool.name, tool.category, "可用" if available else reason, "独立控制台" if tool.new_console else "GUI", tool.executable))

    def _provider_changed(self) -> None:
        self.model_var.set("gpt-5.5" if self.provider_var.get() == "codex" else "")
        self._refresh_health()

    def _refresh_health(self) -> None:
        provider = self.provider_var.get()

        def worker() -> None:
            healthy, detail = self.manager.provider_health(provider)
            self.after(0, lambda: self.health_label.configure(text=f"{provider.title()}: {detail}", foreground=ACCENT if healthy else DANGER))

        threading.Thread(target=worker, daemon=True).start()

    def _request(self) -> LaunchRequest:
        selected = tuple(tool_id for tool_id, variable in self.tool_vars.items() if variable.get())
        return LaunchRequest(
            project_name=self.project_var.get(),
            target=self.target_var.get(),
            scope=self.scope_var.get(),
            provider=self.provider_var.get(),
            model=self.model_var.get(),
            selected_tools=selected,
            user_prompt=self.prompt_text.get("1.0", "end").strip(),
            authorization_confirmed=self.auth_var.get(),
        )

    def _start(self) -> None:
        if self._busy:
            return
        request = self._request()
        self._busy = True
        self.start_button.state(["disabled"])
        self.launch_status.configure(text="正在预检并启动...", foreground=MUTED)

        def worker() -> None:
            try:
                state = self.manager.start(request)
            except LaunchError as exc:
                self.after(0, lambda: self._start_finished(None, str(exc)))
            except Exception as exc:
                self.after(0, lambda: self._start_finished(None, f"意外错误: {exc}"))
            else:
                self.after(0, lambda: self._start_finished(state, ""))

        threading.Thread(target=worker, daemon=True).start()

    def _start_finished(self, state: RunState | None, error: str) -> None:
        self._busy = False
        self.start_button.state(["!disabled"])
        if error:
            self.launch_status.configure(text=error, foreground=DANGER)
            messagebox.showerror("启动失败", error)
            return
        assert state is not None
        self.run_states[self._state_key(state)] = state
        self.launch_status.configure(text=f"实例 {state.run_id} 已完整启动", foreground=ACCENT)
        self._refresh_runs()
        self.notebook.select(self.runs_tab)

    def _load_runs(self) -> None:
        self.run_states = {
            self._state_key(state): state for state in self.manager.list_runs()
        }
        self._refresh_runs()

    @staticmethod
    def _state_key(state: RunState) -> str:
        return f"{safe_project_name(state.project_name)}::{state.run_id}"

    def _refresh_runs(self) -> None:
        for state in list(self.run_states.values()):
            self.manager.refresh(state)
        selected = self.run_tree.selection()
        selected_id = selected[0] if selected else ""
        self.run_tree.delete(*self.run_tree.get_children())
        for state in sorted(self.run_states.values(), key=lambda item: item.created_at, reverse=True):
            state_key = self._state_key(state)
            components = ", ".join(f"{item.name}:{'运行' if item.status == 'running' else '结束'}" for item in state.processes)
            self.run_tree.insert(
                "",
                "end",
                iid=state_key,
                values=(state.project_name, state.run_id, state.provider.title(), self._status_text(state.status), components, state.created_at.replace("T", " ")[:19]),
                tags=(state.status,),
            )
        if selected_id and self.run_tree.exists(selected_id):
            self.run_tree.selection_set(selected_id)

    @staticmethod
    def _status_text(status: str) -> str:
        return {"starting": "启动中", "running": "运行中", "completed": "已结束", "failed": "失败", "stopped": "已停止"}.get(status, status)

    def _selected_state(self) -> RunState | None:
        selected = self.run_tree.selection()
        return self.run_states.get(selected[0]) if selected else None

    def _stop_selected_run(self) -> None:
        state = self._selected_state()
        if state is None:
            messagebox.showinfo("停止实例", "请先选择一个运行实例")
            return
        if not messagebox.askyesno("停止实例", f"确定停止 {state.project_name} / {state.run_id} 的全部进程吗？"):
            return
        self.manager.stop(state)
        self._refresh_runs()

    def _open_selected_run(self) -> None:
        state = self._selected_state()
        if state is None:
            messagebox.showinfo("打开目录", "请先选择一个运行实例")
            return
        os.startfile(state.run_dir)

    def _open_project_dir(self) -> None:
        name = self.project_var.get().strip()
        if not name:
            messagebox.showinfo("打开目录", "请先填写或选择项目名称")
            return
        path = self.manager.projects_dir / safe_project_name(name)
        path.mkdir(parents=True, exist_ok=True)
        os.startfile(path)

    def _load_project(self) -> None:
        value = self.manager.load_project(self.project_var.get())
        if not value:
            return
        self.target_var.set(str(value.get("target", "")))
        self.scope_var.set(str(value.get("scope", "")))
        provider = str(value.get("provider", "codex"))
        self.provider_var.set(provider)
        self.model_var.set(str(value.get("model", "gpt-5.5" if provider == "codex" else "")))
        selected = set(value.get("selected_tools", []))
        for tool_id, variable in self.tool_vars.items():
            variable.set(tool_id in selected)
        self.prompt_text.delete("1.0", "end")
        self.prompt_text.insert("1.0", str(value.get("user_prompt", "")))
        self.auth_var.set(False)

    def _tick(self) -> None:
        try:
            self._refresh_runs()
        finally:
            self.after(2000, self._tick)
