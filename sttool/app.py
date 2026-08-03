from __future__ import annotations

import json
import os
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .ai_settings import AISettingsDialog
from .asset_settings import AssetCommanderSettingsDialog
from .models import (
    DEFAULT_API_BASE_URL,
    LaunchRequest,
    RunState,
    ToolDefinition,
    normalize_provider,
)
from .registry import availability
from .project_results_dialog import ProjectResultsDialog
from .run_log_dialog import RunLogDialog, component_summary_status
from .runtime import LaunchError, RuntimeManager, project_name_is_url, safe_project_name
from .secret_store import (
    SecretStoreError,
    load_secret_values,
    save_secret_values,
    update_secret_value,
)
from .tool_details import ToolDetailsDialog
from .tool_editor import ToolEditorDialog
from .tool_store import ToolStore
from .workflow_settings import (
    normalize_workflow_settings,
    normalized_reasoning_effort,
)


BG = "#f4f5f7"
PANEL = "#ffffff"
TEXT = "#20242a"
MUTED = "#667085"
ACCENT = "#176b51"
DANGER = "#b42318"


class LauncherApp(tk.Tk):
    def __init__(
        self,
        manager: RuntimeManager,
        tools: tuple[ToolDefinition, ...],
        tool_store: ToolStore,
    ) -> None:
        super().__init__()
        self.manager = manager
        self.tools = tools
        self.tool_store = tool_store
        self.tool_vars: dict[str, tk.BooleanVar] = {}
        self.run_states: dict[str, RunState] = {}
        self._busy = False
        self.launcher_settings_path = self.manager.app_dir / "launcher_settings.json"
        self.launcher_secrets_path = self.manager.app_dir / "launcher_secrets.dat"
        launcher_settings = self._load_launcher_settings()
        project_names = self.manager.list_projects()
        initial_project = str(launcher_settings.get("last_project") or "")
        if not initial_project and len(project_names) == 1:
            initial_project = project_names[0]
        self.api_base_url_var = tk.StringVar(
            value=str(
                launcher_settings.get("api_base_url")
                or os.environ.get("OPENAI_BASE_URL")
                or DEFAULT_API_BASE_URL
            )
        )
        self.default_model = str(launcher_settings.get("model") or "gpt-5.5")
        legacy_agent_model = str(launcher_settings.get("agent_model") or "")
        legacy_effort = normalized_reasoning_effort(
            launcher_settings.get("reasoning_effort")
        )
        self.codex_agent_model = str(
            launcher_settings.get("codex_agent_model") or legacy_agent_model
        )
        self.codex_reasoning_effort = normalized_reasoning_effort(
            launcher_settings.get("codex_reasoning_effort") or legacy_effort
        )
        self.codex_agent_base_url = str(
            launcher_settings.get("codex_agent_base_url") or ""
        )
        self.claude_agent_model = str(
            launcher_settings.get("claude_agent_model") or ""
        )
        self.claude_reasoning_effort = normalized_reasoning_effort(
            launcher_settings.get("claude_reasoning_effort")
        )
        self.claude_agent_base_url = str(
            launcher_settings.get("claude_agent_base_url") or ""
        )
        self.workflow_settings = normalize_workflow_settings(
            launcher_settings.get("workflow")
        )
        self.secret_load_error = ""
        try:
            secret_values = load_secret_values(self.launcher_secrets_path)
        except SecretStoreError as exc:
            secret_values = {}
            self.secret_load_error = str(exc)
        self.api_key = secret_values.get("shared_ai_api_key", "")
        self.github_token = secret_values.get("github_token", "")

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
        if initial_project and not project_name_is_url(initial_project):
            self.project_var.set(initial_project)
            self._load_project()
        self._load_runs()
        self._refresh_health()
        if self.tool_store.load_error:
            self.after(
                0,
                lambda: messagebox.showwarning(
                    "工具配置",
                    self.tool_store.load_error,
                    parent=self,
                ),
            )
        if self.secret_load_error:
            self.after(
                0,
                lambda: messagebox.showwarning(
                    "工具协作 AI 设置",
                    self.secret_load_error,
                    parent=self,
                ),
            )
        self.after(2000, self._tick)

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            ".", font=("Microsoft YaHei UI", 10), background=BG, foreground=TEXT
        )
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Panel.TLabel", background=PANEL, foreground=TEXT)
        style.configure("Muted.TLabel", background=PANEL, foreground=MUTED)
        style.configure(
            "Title.TLabel",
            background=BG,
            foreground=TEXT,
            font=("Microsoft YaHei UI", 18, "bold"),
        )
        style.configure(
            "Accent.TButton", background=ACCENT, foreground="white", padding=(16, 9)
        )
        style.map(
            "Accent.TButton",
            background=[("active", "#125541"), ("disabled", "#98a2b3")],
        )
        style.configure("Danger.TButton", foreground=DANGER)
        style.configure(
            "Treeview", rowheight=30, background=PANEL, fieldbackground=PANEL
        )
        style.configure("Treeview.Heading", font=("Microsoft YaHei UI", 9, "bold"))
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", padding=(16, 8))

    def _build_ui(self) -> None:
        header = ttk.Frame(self, padding=(24, 18, 24, 10))
        header.pack(fill="x")
        ttk.Label(header, text="渗透项目总控台", style="Title.TLabel").pack(side="left")
        header_settings = ttk.Frame(header)
        header_settings.pack(side="right")
        self.health_label = ttk.Label(
            header_settings, text="CLI 检测中", foreground=MUTED
        )
        self.health_label.pack(anchor="e")
        ttk.Button(
            header_settings,
            text="全局设置",
            command=self._open_ai_settings,
        ).pack(anchor="e", pady=(6, 0))

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
    def _field(
        parent: ttk.Frame, row: int, label: str, variable: tk.StringVar, width: int = 42
    ) -> ttk.Entry:
        ttk.Label(parent, text=label, style="Panel.TLabel").grid(
            row=row, column=0, sticky="w", pady=(0, 5)
        )
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
        self.scope_var = tk.StringVar(value="*")
        self.provider_var = tk.StringVar(value="codexx")
        self.auth_var = tk.BooleanVar(value=False)

        ttk.Label(
            left,
            text="项目配置",
            style="Panel.TLabel",
            font=("Microsoft YaHei UI", 12, "bold"),
        ).grid(row=0, column=0, sticky="w", pady=(0, 14))
        ttk.Label(left, text="项目名称（稳定名称，不要填写 URL）", style="Panel.TLabel").grid(
            row=1, column=0, sticky="w", pady=(0, 5)
        )
        project_box = ttk.Combobox(
            left, textvariable=self.project_var, values=self.manager.list_projects()
        )
        project_box.grid(row=2, column=0, sticky="ew", pady=(0, 14))
        project_box.bind("<<ComboboxSelected>>", lambda _event: self._load_project())
        self._field(left, 3, "主要目标（URL、域名或 IP）", self.target_var)
        self._field(left, 5, "授权范围", self.scope_var)

        ttk.Label(left, text="补充任务", style="Panel.TLabel").grid(
            row=7, column=0, sticky="w", pady=(0, 5)
        )
        self.prompt_text = tk.Text(
            left,
            width=1,
            height=8,
            wrap="word",
            relief="solid",
            borderwidth=1,
            font=("Microsoft YaHei UI", 10),
        )
        self.prompt_text.grid(row=8, column=0, sticky="nsew", pady=(0, 12))
        left.rowconfigure(8, weight=1)
        ttk.Checkbutton(
            left,
            text="我确认已获得上述范围的安全测试授权",
            variable=self.auth_var,
        ).grid(row=9, column=0, sticky="w")

        ttk.Label(
            right,
            text="AI Agent",
            style="Panel.TLabel",
            font=("Microsoft YaHei UI", 12, "bold"),
        ).grid(row=0, column=0, sticky="w", pady=(0, 14))
        provider_row = ttk.Frame(right, style="Panel.TFrame")
        provider_row.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        ttk.Radiobutton(
            provider_row,
            text="Codexx CLI",
            value="codexx",
            variable=self.provider_var,
            command=self._provider_changed,
        ).pack(side="left", padx=(0, 18))
        ttk.Radiobutton(
            provider_row,
            text="Codex CLI",
            value="codex",
            variable=self.provider_var,
            command=self._provider_changed,
        ).pack(side="left", padx=(0, 18))
        ttk.Radiobutton(
            provider_row,
            text="Claude CLI",
            value="claude",
            variable=self.provider_var,
            command=self._provider_changed,
        ).pack(side="left")

        ttk.Separator(right).grid(row=2, column=0, sticky="ew", pady=(2, 16))
        ttk.Label(
            right,
            text="随项目启动",
            style="Panel.TLabel",
            font=("Microsoft YaHei UI", 12, "bold"),
        ).grid(row=3, column=0, sticky="w", pady=(0, 10))
        self.tool_frame = ttk.Frame(right, style="Panel.TFrame")
        self.tool_frame.grid(row=4, column=0, sticky="nsew")
        right.rowconfigure(4, weight=1)
        self._render_tool_choices()

        action = ttk.Frame(right, style="Panel.TFrame")
        action.grid(row=5, column=0, sticky="ew", pady=(18, 0))
        self.start_button = ttk.Button(
            action, text="启动新实例", style="Accent.TButton", command=self._start
        )
        self.start_button.pack(side="left")
        ttk.Button(action, text="打开项目目录", command=self._open_project_dir).pack(
            side="left", padx=(10, 0)
        )
        self.launch_status = ttk.Label(
            right, text="每次启动都会创建独立运行目录", style="Muted.TLabel"
        )
        self.launch_status.grid(row=6, column=0, sticky="w", pady=(12, 0))

    def _render_tool_choices(self) -> None:
        selected = {
            tool_id: variable.get() for tool_id, variable in self.tool_vars.items()
        }
        for child in self.tool_frame.winfo_children():
            child.destroy()
        self.tool_vars = {}
        for index, tool in enumerate(self.tools):
            available, reason = availability(tool)
            checked = selected.get(tool.tool_id, tool.default_selected) and available
            variable = tk.BooleanVar(value=checked)
            self.tool_vars[tool.tool_id] = variable
            box = ttk.Checkbutton(self.tool_frame, text=tool.name, variable=variable)
            box.grid(row=index, column=0, sticky="w", pady=3)
            if not available:
                box.state(["disabled"])
            detail = tool.description if available else reason
            ttk.Label(
                self.tool_frame,
                text=detail,
                style="Muted.TLabel",
                wraplength=260,
            ).grid(row=index, column=1, sticky="w", padx=(12, 0), pady=3)

    def _build_runs_tab(self) -> None:
        self.runs_tab.columnconfigure(0, weight=1)
        self.runs_tab.rowconfigure(1, weight=1)
        actions = ttk.Frame(self.runs_tab, style="Panel.TFrame")
        actions.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        ttk.Button(actions, text="刷新", command=self._refresh_runs).pack(side="left")
        ttk.Button(actions, text="打开运行目录", command=self._open_selected_run).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(
            actions,
            text="项目成果",
            command=self._open_project_results,
        ).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="项目日志", command=self._open_run_log).pack(
            side="left", padx=(8, 0)
        )
        self.recover_button = ttk.Button(
            actions, text="恢复实例", command=self._recover_selected_run
        )
        self.recover_button.pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="新实例重跑", command=self._load_selected_as_new).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(
            actions,
            text="停止实例",
            style="Danger.TButton",
            command=self._stop_selected_run,
        ).pack(side="right")

        columns = ("project", "run_id", "provider", "status", "components", "created")
        self.run_tree = ttk.Treeview(
            self.runs_tab, columns=columns, show="headings", selectmode="browse"
        )
        headings = {
            "project": "项目",
            "run_id": "实例",
            "provider": "Agent",
            "status": "状态",
            "components": "组件",
            "created": "启动时间",
        }
        widths = {
            "project": 150,
            "run_id": 155,
            "provider": 90,
            "status": 90,
            "components": 260,
            "created": 170,
        }
        for column in columns:
            self.run_tree.heading(column, text=headings[column])
            self.run_tree.column(column, width=widths[column], minwidth=70)
        self.run_tree.grid(row=1, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(
            self.runs_tab, orient="vertical", command=self.run_tree.yview
        )
        scrollbar.grid(row=1, column=1, sticky="ns")
        self.run_tree.configure(yscrollcommand=scrollbar.set)
        self.run_tree.tag_configure("running", foreground=ACCENT)
        self.run_tree.tag_configure("failed", foreground=DANGER)
        self.run_tree.bind("<Double-1>", lambda _event: self._open_run_log())

    def _build_tools_tab(self) -> None:
        self.tools_tab.columnconfigure(0, weight=1)
        self.tools_tab.rowconfigure(2, weight=1)
        ttk.Label(
            self.tools_tab,
            text="工具位置和自定义工具保存在本机 tools.json。",
            style="Muted.TLabel",
        ).grid(row=0, column=0, sticky="w", pady=(0, 12))

        actions = ttk.Frame(self.tools_tab, style="Panel.TFrame")
        actions.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        ttk.Button(actions, text="详情与结果", command=self._show_tool_details).pack(
            side="left"
        )
        ttk.Button(actions, text="添加工具", command=self._add_tool).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(actions, text="编辑", command=self._edit_tool).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(actions, text="删除", command=self._delete_tool).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(
            actions, text="重置内置位置", command=self._reset_tool_location
        ).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="打开位置", command=self._open_tool_location).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(actions, text="刷新检测", command=self._reload_tools).pack(
            side="right"
        )

        columns = ("name", "category", "state", "mode", "path")
        self.tools_tree = ttk.Treeview(
            self.tools_tab,
            columns=columns,
            show="headings",
            selectmode="browse",
        )
        for column, text, width in (
            ("name", "工具", 170),
            ("category", "类别", 110),
            ("state", "检测", 100),
            ("mode", "启动方式", 110),
            ("path", "入口", 540),
        ):
            self.tools_tree.heading(column, text=text)
            self.tools_tree.column(column, width=width)
        self.tools_tree.grid(row=2, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(
            self.tools_tab,
            orient="vertical",
            command=self.tools_tree.yview,
        )
        scrollbar.grid(row=2, column=1, sticky="ns")
        self.tools_tree.configure(yscrollcommand=scrollbar.set)
        self.tools_tree.bind("<Double-1>", lambda _event: self._show_tool_details())
        self._refresh_tools_tree()

    def _refresh_tools_tree(self) -> None:
        selected = self.tools_tree.selection()
        selected_id = selected[0] if selected else ""
        self.tools_tree.delete(*self.tools_tree.get_children())
        for tool in self.tools:
            available, reason = availability(tool)
            self.tools_tree.insert(
                "",
                "end",
                iid=tool.tool_id,
                values=(
                    tool.name,
                    tool.category,
                    "可用" if available else reason,
                    "独立控制台" if tool.new_console else "GUI",
                    self.tool_store.location_for(tool.tool_id, tool),
                ),
            )
        if selected_id and self.tools_tree.exists(selected_id):
            self.tools_tree.selection_set(selected_id)

    def _reload_tools(self) -> None:
        self.tools = self.tool_store.tools()
        self.manager.tools = {tool.tool_id: tool for tool in self.tools}
        self._render_tool_choices()
        self._refresh_tools_tree()

    def _selected_tool(self) -> ToolDefinition | None:
        selected = self.tools_tree.selection()
        if not selected:
            messagebox.showinfo("工具清单", "请先选择一个工具。", parent=self)
            return None
        tool_id = selected[0]
        return next((tool for tool in self.tools if tool.tool_id == tool_id), None)

    def _add_tool(self) -> None:
        dialog = ToolEditorDialog(self)
        self.wait_window(dialog)
        if dialog.result is None:
            return
        try:
            tool = self.tool_store.upsert_custom(dialog.result)
        except (OSError, ValueError) as exc:
            messagebox.showerror("添加失败", str(exc), parent=self)
            return
        self._reload_tools()
        self.tools_tree.selection_set(tool.tool_id)

    def _show_tool_details(self) -> None:
        tool = self._selected_tool()
        if tool is None:
            return
        ToolDetailsDialog(
            self,
            tool,
            self.manager.list_runs(),
            selected_state=self._selected_state(),
            source_dir=self.manager.app_dir,
            st_root=self.manager.st_root,
            manager=self.manager,
            api_base_url=self.api_base_url_var.get().strip(),
            model=self.default_model,
            api_key=self.api_key,
            github_token=self.github_token,
            github_token_saver=self._save_github_token_from_tool,
        )

    def _save_github_token_from_tool(self, token: str) -> None:
        values = update_secret_value(
            self.launcher_secrets_path, "github_token", token
        )
        self.github_token = values.get("github_token", "")

    def _edit_tool(self) -> None:
        tool = self._selected_tool()
        if tool is None:
            return
        if self.tool_store.is_builtin(tool.tool_id):
            if tool.tool_id == "asset_commander":
                dialog = AssetCommanderSettingsDialog(
                    self,
                    self.tool_store.asset_collision_settings(),
                    self.tool_store.location_for(tool.tool_id, tool),
                )
                self.wait_window(dialog)
                if dialog.result is not None and dialog.location_result is not None:
                    try:
                        self.tool_store.set_location(
                            tool.tool_id, dialog.location_result
                        )
                        self.tool_store.set_asset_collision_settings(dialog.result)
                    except (OSError, ValueError) as exc:
                        messagebox.showerror("保存失败", str(exc), parent=self)
                        return
                    self._reload_tools()
                    self.tools_tree.selection_set(tool.tool_id)
                return
            current = Path(self.tool_store.location_for(tool.tool_id, tool))
            if self.tool_store.location_kind(tool.tool_id) == "directory":
                value = filedialog.askdirectory(
                    parent=self,
                    title=f"选择 {tool.name} 目录",
                    initialdir=str(current if current.is_dir() else current.parent),
                )
            else:
                value = filedialog.askopenfilename(
                    parent=self,
                    title=f"选择 {tool.name} 入口",
                    initialdir=str(current.parent),
                    filetypes=(("可执行文件", "*.exe"), ("所有文件", "*.*")),
                )
            if not value:
                return
            try:
                self.tool_store.set_location(tool.tool_id, value)
            except OSError as exc:
                messagebox.showerror("保存失败", str(exc), parent=self)
                return
            self._reload_tools()
            self.tools_tree.selection_set(tool.tool_id)
            return

        dialog = ToolEditorDialog(self, tool)
        self.wait_window(dialog)
        if dialog.result is None:
            return
        try:
            self.tool_store.upsert_custom(dialog.result, tool.tool_id)
        except (OSError, ValueError) as exc:
            messagebox.showerror("保存失败", str(exc), parent=self)
            return
        self._reload_tools()
        self.tools_tree.selection_set(tool.tool_id)

    def _delete_tool(self) -> None:
        tool = self._selected_tool()
        if tool is None:
            return
        if self.tool_store.is_builtin(tool.tool_id):
            messagebox.showinfo(
                "不能删除", "内置工具可以修改位置，但不能删除。", parent=self
            )
            return
        if not messagebox.askyesno(
            "删除工具", f"确定删除 {tool.name} 吗？", parent=self
        ):
            return
        try:
            self.tool_store.remove_custom(tool.tool_id)
        except (OSError, ValueError) as exc:
            messagebox.showerror("删除失败", str(exc), parent=self)
            return
        self._reload_tools()

    def _reset_tool_location(self) -> None:
        tool = self._selected_tool()
        if tool is None:
            return
        if not self.tool_store.is_builtin(tool.tool_id):
            messagebox.showinfo("工具清单", "自定义工具没有内置默认位置。", parent=self)
            return
        try:
            self.tool_store.reset_location(tool.tool_id)
        except OSError as exc:
            messagebox.showerror("重置失败", str(exc), parent=self)
            return
        self._reload_tools()
        self.tools_tree.selection_set(tool.tool_id)

    def _open_tool_location(self) -> None:
        tool = self._selected_tool()
        if tool is None:
            return
        path = Path(self.tool_store.location_for(tool.tool_id, tool))
        target = path if path.is_dir() else path.parent
        if not target.exists():
            messagebox.showerror("路径不存在", str(target), parent=self)
            return
        os.startfile(target)

    def _provider_changed(self) -> None:
        self._refresh_health()

    def _refresh_health(self) -> None:
        provider = self.provider_var.get()

        def worker() -> None:
            healthy, detail = self.manager.provider_health(provider)
            self.after(
                0,
                lambda: self.health_label.configure(
                    text=f"{self._provider_text(provider)}: {detail}",
                    foreground=ACCENT if healthy else DANGER,
                ),
            )

        threading.Thread(target=worker, daemon=True).start()

    def _agent_settings_for_provider(self, provider: str) -> tuple[str, str, str]:
        if provider == "claude":
            return (
                self.claude_agent_model,
                self.claude_reasoning_effort,
                self.claude_agent_base_url,
            )
        return (
            self.codex_agent_model,
            self.codex_reasoning_effort,
            self.codex_agent_base_url,
        )

    def _request(self) -> LaunchRequest:
        selected = tuple(
            tool_id for tool_id, variable in self.tool_vars.items() if variable.get()
        )
        provider = self.provider_var.get()
        agent_model, reasoning_effort, agent_base_url = (
            self._agent_settings_for_provider(provider)
        )
        return LaunchRequest(
            project_name=self.project_var.get(),
            target=self.target_var.get(),
            scope=self.scope_var.get(),
            provider=provider,
            model=self.default_model,
            selected_tools=selected,
            user_prompt=self.prompt_text.get("1.0", "end").strip(),
            authorization_confirmed=self.auth_var.get(),
            api_base_url=self.api_base_url_var.get(),
            api_key=self.api_key,
            agent_model=agent_model,
            reasoning_effort=reasoning_effort,
            agent_base_url=agent_base_url,
            github_token=self.github_token,
            work_mode=str(self.workflow_settings["work_mode"]),
            auto_agent=bool(self.workflow_settings["auto_agent"]),
            wait_for_asset_commander=bool(
                self.workflow_settings["wait_for_asset_commander"]
            ),
            wait_for_fscan=bool(self.workflow_settings["wait_for_fscan"]),
            asset_settle_seconds=int(self.workflow_settings["asset_settle_seconds"]),
            max_agent_batches=int(self.workflow_settings["max_agent_batches"]),
            coordinator_poll_seconds=int(
                self.workflow_settings["coordinator_poll_seconds"]
            ),
            ai_summary_enabled=bool(self.workflow_settings["ai_summary_enabled"]),
        )

    def _start(self) -> None:
        if self._busy:
            return
        request = self._request()
        self._save_launcher_settings()
        self._busy = True
        self.start_button.state(["disabled"])
        self.launch_status.configure(text="正在预检并启动...", foreground=MUTED)

        def worker() -> None:
            try:
                state = self.manager.start(request)
            except LaunchError as exc:
                error = str(exc)
                self.after(0, lambda error=error: self._start_finished(None, error))
            except Exception as exc:
                error = f"意外错误: {exc}"
                self.after(0, lambda error=error: self._start_finished(None, error))
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
        self.launch_status.configure(
            text=f"实例 {state.run_id} 已完整启动", foreground=ACCENT
        )
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
        for state in sorted(
            self.run_states.values(), key=lambda item: item.created_at, reverse=True
        ):
            state_key = self._state_key(state)
            component_values = [
                f"{item.name}:{component_summary_status(Path(state.run_dir), item.component_id, item.status)}"
                for item in state.processes
            ]
            process_ids = {item.component_id for item in state.processes}
            component_values.extend(
                f"{tool.name}:{component_summary_status(Path(state.run_dir), tool.tool_id, 'running')}"
                for tool in self.tools
                if tool.coordinator_managed
                and tool.tool_id in state.selected_tools
                and tool.tool_id not in process_ids
            )
            components = ", ".join(component_values)
            self.run_tree.insert(
                "",
                "end",
                iid=state_key,
                values=(
                    state.project_name,
                    state.run_id,
                    self._provider_text(state.provider),
                    self._status_text(state),
                    components,
                    state.created_at.replace("T", " ")[:19],
                ),
                tags=(state.status,),
            )
        if selected_id and self.run_tree.exists(selected_id):
            self.run_tree.selection_set(selected_id)

    @staticmethod
    def _provider_text(provider: str) -> str:
        return RuntimeManager.provider_display_name(provider)

    @staticmethod
    def _status_text(state: RunState) -> str:
        value = {
            "starting": "启动中",
            "running": "运行中",
            "completed": "已结束",
            "failed": "失败",
            "stopped": "已停止",
        }.get(state.status, state.status)
        if state.recovery_count:
            return f"{value}(恢复{state.recovery_count})"
        return value

    def _selected_state(self) -> RunState | None:
        selected = self.run_tree.selection()
        return self.run_states.get(selected[0]) if selected else None

    def _recover_selected_run(self) -> None:
        if self._busy:
            return
        state = self._selected_state()
        if state is None:
            messagebox.showinfo(
                "恢复实例",
                "请先选择一个历史或异常结束的运行实例",
            )
            return
        confirmed = messagebox.askyesno(
            "恢复实例",
            (
                f"将在原运行目录恢复 {state.project_name} / {state.run_id}。\n\n"
                "会重新启动已结束的常驻 GUI 工具和 AI Agent；"
                "fscan、nuclei 等一次性任务不会自动重复。\n"
                "已有结果、断点和工程文件都会保留。\n\n"
                f"授权范围仍为：{state.scope}\n"
                "请确认当前授权仍然有效。"
            ),
        )
        if not confirmed:
            return
        self._busy = True
        self.recover_button.state(["disabled"])

        def worker() -> None:
            try:
                recovered = self.manager.recover(
                    state,
                    authorization_confirmed=True,
                    api_key=self.api_key,
                    github_token=self.github_token,
                )
            except LaunchError as exc:
                error = str(exc)
                self.after(0, lambda error=error: self._recover_finished(None, error))
            except Exception as exc:
                error = f"意外错误: {exc}"
                self.after(0, lambda error=error: self._recover_finished(None, error))
            else:
                self.after(
                    0,
                    lambda recovered=recovered: self._recover_finished(recovered, ""),
                )

        threading.Thread(target=worker, daemon=True).start()

    def _recover_finished(self, state: RunState | None, error: str) -> None:
        self._busy = False
        self.recover_button.state(["!disabled"])
        if error:
            messagebox.showerror("恢复失败", error)
            return
        assert state is not None
        self.run_states[self._state_key(state)] = state
        self._refresh_runs()
        messagebox.showinfo(
            "恢复完成",
            (
                f"实例 {state.run_id} 已在原运行目录恢复，"
                f"第 {state.recovery_count} 次恢复。"
            ),
        )

    def _load_selected_as_new(self) -> None:
        state = self._selected_state()
        if state is None:
            messagebox.showinfo("新实例重跑", "请先选择一个历史运行实例")
            return
        path = Path(state.run_dir) / "project.json"
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            messagebox.showerror("新实例重跑", f"读取历史配置失败: {exc}")
            return
        if not isinstance(value, dict):
            messagebox.showerror("新实例重跑", "历史项目配置格式无效")
            return
        self._apply_project_value(value)
        legacy_url_name = project_name_is_url(self.project_var.get())
        if legacy_url_name:
            self.project_var.set("")
        self.notebook.select(self.launch_tab)
        detail = (
            "历史项目名称是 URL，已自动清空。请填写不会随目标或 AI 线路变化的稳定项目名称，"
            "重新确认授权后再启动。"
            if legacy_url_name
            else "历史配置已载入。请重新确认授权复选框，再点击“启动完整项目”。"
        )
        messagebox.showinfo("新实例重跑", detail)

    def _stop_selected_run(self) -> None:
        state = self._selected_state()
        if state is None:
            messagebox.showinfo("停止实例", "请先选择一个运行实例")
            return
        if not messagebox.askyesno(
            "停止实例", f"确定停止 {state.project_name} / {state.run_id} 的全部进程吗？"
        ):
            return
        self.manager.stop(state)
        self._refresh_runs()

    def _open_selected_run(self) -> None:
        state = self._selected_state()
        if state is None:
            messagebox.showinfo("打开目录", "请先选择一个运行实例")
            return
        os.startfile(state.run_dir)

    def _open_project_results(self) -> None:
        state = self._selected_state()
        if state is None:
            messagebox.showinfo("\u9879\u76ee\u6210\u679c", "\u8bf7\u5148\u9009\u62e9\u4e00\u4e2a\u8fd0\u884c\u5b9e\u4f8b")
            return
        ProjectResultsDialog(self, state)

    def _open_run_log(self) -> None:
        state = self._selected_state()
        if state is None:
            messagebox.showinfo("项目日志", "请先选择一个运行实例")
            return
        RunLogDialog(self, state)

    def _open_project_dir(self) -> None:
        name = self.project_var.get().strip()
        if not name:
            messagebox.showinfo("打开目录", "请先填写或选择项目名称")
            return
        path = self.manager.projects_dir / safe_project_name(name)
        if project_name_is_url(name) and not (path / "project.json").is_file():
            messagebox.showwarning(
                "打开目录",
                "项目名称不能填写目标 URL 或 AI Base URL；请先改成稳定名称。",
            )
            return
        path.mkdir(parents=True, exist_ok=True)
        os.startfile(path)

    def _apply_project_value(self, value: dict[str, object]) -> None:
        self.project_var.set(str(value.get("name", self.project_var.get())))
        self.target_var.set(str(value.get("target", "")))
        self.scope_var.set(str(value.get("scope") or "*"))
        try:
            schema_version = int(value.get("schema_version", 1))
        except (TypeError, ValueError):
            schema_version = 1
        provider = normalize_provider(value.get("provider", "codexx"), schema_version)
        if provider not in {"codexx", "codex", "claude"}:
            provider = "codexx"
        self.provider_var.set(provider)
        if value.get("api_base_url"):
            self.api_base_url_var.set(str(value["api_base_url"]))
        if value.get("model"):
            self.default_model = str(value["model"])
        if "agent_model" in value or "reasoning_effort" in value or "agent_base_url" in value:
            model = str(value.get("agent_model") or "")
            effort = normalized_reasoning_effort(value.get("reasoning_effort"))
            base_url = str(value.get("agent_base_url") or "")
            if provider == "claude":
                self.claude_agent_model = model
                self.claude_reasoning_effort = effort
                self.claude_agent_base_url = base_url
            else:
                self.codex_agent_model = model
                self.codex_reasoning_effort = effort
                self.codex_agent_base_url = base_url
        if "work_mode" in value:
            self.workflow_settings = normalize_workflow_settings(value)
        selected = set(value.get("selected_tools", []))
        for tool_id, variable in self.tool_vars.items():
            variable.set(tool_id in selected)
        self.prompt_text.delete("1.0", "end")
        self.prompt_text.insert("1.0", str(value.get("user_prompt", "")))
        self.auth_var.set(False)

    def _load_project(self) -> None:
        value = self.manager.load_project(self.project_var.get())
        if value:
            self._apply_project_value(value)
            self._save_launcher_settings()

    def _load_launcher_settings(self) -> dict[str, object]:
        try:
            value = json.loads(self.launcher_settings_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return value if isinstance(value, dict) else {}

    def _open_ai_settings(self) -> None:
        dialog = AISettingsDialog(
            self,
            api_base_url=self.api_base_url_var.get(),
            model=self.default_model,
            api_key=self.api_key,
            codex_agent_model=self.codex_agent_model,
            codex_reasoning_effort=self.codex_reasoning_effort,
            codex_agent_base_url=self.codex_agent_base_url,
            claude_agent_model=self.claude_agent_model,
            claude_reasoning_effort=self.claude_reasoning_effort,
            claude_agent_base_url=self.claude_agent_base_url,
            github_token=self.github_token,
            workflow_settings=self.workflow_settings,
        )
        self.wait_window(dialog)
        if dialog.result is None:
            return
        try:
            save_secret_values(
                self.launcher_secrets_path,
                {
                    "shared_ai_api_key": str(dialog.result["api_key"]),
                    "github_token": str(dialog.result["github_token"]),
                },
            )
        except SecretStoreError as exc:
            messagebox.showerror("STTool 全局设置", str(exc), parent=self)
            return
        self.api_key = str(dialog.result["api_key"])
        self.github_token = str(dialog.result["github_token"])
        self.api_base_url_var.set(str(dialog.result["api_base_url"]))
        self.default_model = str(dialog.result["model"])
        self.codex_agent_model = str(dialog.result["codex_agent_model"])
        self.codex_reasoning_effort = normalized_reasoning_effort(
            dialog.result["codex_reasoning_effort"]
        )
        self.codex_agent_base_url = str(dialog.result["codex_agent_base_url"])
        self.claude_agent_model = str(dialog.result["claude_agent_model"])
        self.claude_reasoning_effort = normalized_reasoning_effort(
            dialog.result["claude_reasoning_effort"]
        )
        self.claude_agent_base_url = str(dialog.result["claude_agent_base_url"])
        self.workflow_settings = normalize_workflow_settings(dialog.result["workflow"])
        self._save_launcher_settings()

    def _save_launcher_settings(self) -> None:
        value = {
            "schema_version": 3,
            "api_base_url": self.api_base_url_var.get().strip().rstrip("/"),
            "model": self.default_model,
            "codex_agent_model": self.codex_agent_model,
            "codex_reasoning_effort": self.codex_reasoning_effort,
            "codex_agent_base_url": self.codex_agent_base_url,
            "claude_agent_model": self.claude_agent_model,
            "claude_reasoning_effort": self.claude_reasoning_effort,
            "claude_agent_base_url": self.claude_agent_base_url,
            "workflow": self.workflow_settings,
            "last_project": self.project_var.get().strip(),
        }
        temporary = self.launcher_settings_path.with_suffix(".json.tmp")
        try:
            temporary.write_text(
                json.dumps(value, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            temporary.replace(self.launcher_settings_path)
        except OSError:
            temporary.unlink(missing_ok=True)

    def _tick(self) -> None:
        try:
            self._refresh_runs()
        finally:
            self.after(2000, self._tick)
