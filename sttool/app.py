from __future__ import annotations

import json
import os
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .ai_settings import AISettingsDialog
from .asset_approval_dialog import AssetApprovalDialog, pending_asset_groups
from .credential_audit import pending_candidates
from .credential_audit_dialog import CredentialAuditDialog
from .workload_approval import read_request
from .workload_approval_dialog import WorkloadApprovalDialog
from .asset_bus import read_json
from .asset_settings import AssetCommanderSettingsDialog
from .help_text import ensure_help_document
from .global_search_dialog import GlobalSearchDialog
from .models import (
    DEFAULT_API_BASE_URL,
    LaunchRequest,
    RunState,
    ToolDefinition,
    normalize_provider,
)
from .registry import availability
from .project_results_dialog import ProjectResultsDialog
from .project_access_dialog import ProjectAccessDialog
from .project_scope_dialog import ProjectScopeDialog
from .run_log_dialog import RunLogDialog, component_summary_status
from .runtime import (
    LaunchError,
    RuntimeManager,
    project_authorization_confirmed,
    project_name_is_url,
    safe_project_name,
)
from .secret_store import (
    SecretStoreError,
    load_secret_values,
    save_secret_values,
    update_secret_value,
)
from .tool_details import ToolDetailsDialog
from .tool_editor import ToolEditorDialog
from .tool_store import ToolStore
from .tool_network import normalize_tool_network
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
        self._loaded_run_config_key = ""
        self._busy = False
        self._closing = False
        self._applying_project_value = True
        self._project_save_lock = threading.Lock()
        self._project_dirty = False
        self._asset_approval_dialogs: dict[str, AssetApprovalDialog] = {}
        self._asset_approval_snooze_until: dict[str, float] = {}
        self._workload_approval_dialogs: dict[str, WorkloadApprovalDialog] = {}
        self._workload_approval_snooze_until: dict[str, float] = {}
        self._credential_audit_dialogs: dict[str, CredentialAuditDialog] = {}
        self._credential_audit_snooze_until: dict[str, float] = {}
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
        self.tool_network_settings = normalize_tool_network(
            launcher_settings.get("tool_network")
        )
        self.secret_load_error = ""
        try:
            secret_values = load_secret_values(self.launcher_secrets_path)
        except SecretStoreError as exc:
            secret_values = {}
            self.secret_load_error = str(exc)
        self.api_key = secret_values.get("shared_ai_api_key", "")
        self.codex_api_key = secret_values.get("codex_api_key", "")
        self.claude_api_key = secret_values.get("claude_api_key", "")
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
        self._applying_project_value = False
        self.protocol("WM_DELETE_WINDOW", self._on_close)
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
        header_actions = ttk.Frame(header_settings)
        header_actions.pack(anchor="e", pady=(6, 0))
        ttk.Button(
            header_actions,
            text="？ 使用说明",
            command=self._open_help,
        ).pack(side="left")
        ttk.Button(
            header_actions,
            text="全局设置",
            command=self._open_ai_settings,
        ).pack(side="left", padx=(8, 0))
        ttk.Button(
            header_actions,
            text="全局搜索",
            command=self._open_global_search,
        ).pack(side="left", padx=(8, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=24, pady=(0, 20))
        self.launch_tab = ttk.Frame(self.notebook, padding=16, style="Panel.TFrame")
        self.runs_tab = ttk.Frame(self.notebook, padding=16, style="Panel.TFrame")
        self.tools_tab = ttk.Frame(self.notebook, padding=16, style="Panel.TFrame")
        self.notebook.add(self.launch_tab, text="项目配置")
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
        self.provider_var = tk.StringVar(value="codexx")
        self.auth_var = tk.BooleanVar(value=False)
        self.auth_text_var = tk.StringVar()
        self.auth_var.trace_add("write", self._authorization_changed)
        self._authorization_changed()
        self.target_var.trace_add("write", self._target_changed)
        self.launch_scope = ""
        self.launch_processing_scope = ""
        self.scope_summary_var = tk.StringVar(value="尚未设置授权范围")

        ttk.Label(
            left,
            text="项目配置",
            style="Panel.TLabel",
            font=("Microsoft YaHei UI", 12, "bold"),
        ).grid(row=0, column=0, sticky="w", pady=(0, 14))
        ttk.Label(left, text="项目名称（稳定名称，不要填写 URL）", style="Panel.TLabel").grid(
            row=1, column=0, sticky="w", pady=(0, 5)
        )
        self.project_box = ttk.Combobox(
            left, textvariable=self.project_var, values=self.manager.list_projects()
        )
        self.project_box.grid(row=2, column=0, sticky="ew", pady=(0, 14))
        self.project_box.bind("<<ComboboxSelected>>", lambda _event: self._load_project())
        self.project_box.bind("<FocusOut>", self._project_name_edited)
        self.project_box.bind("<Return>", self._project_name_edited)
        self._field(left, 3, "主要目标（URL、域名或 IP）", self.target_var)
        scope_row = ttk.LabelFrame(left, text="项目范围", padding=10)
        scope_row.grid(row=5, column=0, sticky="ew", pady=(0, 14))
        scope_row.columnconfigure(0, weight=1)
        ttk.Label(
            scope_row,
            textvariable=self.scope_summary_var,
            wraplength=360,
        ).grid(row=0, column=0, sticky="w")
        ttk.Label(
            scope_row,
            text=(
                "授权范围决定能否测试；自动处理范围进一步限制哪些授权资产进入扫描。"
            ),
            wraplength=360,
        ).grid(row=1, column=0, sticky="w", pady=(5, 0))
        ttk.Button(
            scope_row, text="编辑项目范围", command=self._edit_launch_scope
        ).grid(row=0, column=1, rowspan=2, sticky="e", padx=(12, 0))

        ttk.Label(left, text="补充任务", style="Panel.TLabel").grid(
            row=6, column=0, sticky="w", pady=(0, 5)
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
        self.prompt_text.grid(row=7, column=0, sticky="nsew", pady=(0, 12))
        self.prompt_text.bind("<<Modified>>", self._prompt_changed)
        self.prompt_text.edit_modified(False)
        left.rowconfigure(7, weight=1)
        ttk.Checkbutton(
            left,
            textvariable=self.auth_text_var,
            variable=self.auth_var,
        ).grid(row=8, column=0, sticky="w")

        ttk.Label(
            right,
            text="AI 执行器（外部 CLI，三选一）",
            style="Panel.TLabel",
            font=("Microsoft YaHei UI", 12, "bold"),
        ).grid(row=0, column=0, sticky="w", pady=(0, 14))
        provider_row = ttk.Frame(right, style="Panel.TFrame")
        provider_row.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        ttk.Radiobutton(
            provider_row,
            text="Codexx CLI 执行器",
            value="codexx",
            variable=self.provider_var,
            command=self._provider_changed,
        ).pack(side="left", padx=(0, 18))
        ttk.Radiobutton(
            provider_row,
            text="Codex CLI 执行器",
            value="codex",
            variable=self.provider_var,
            command=self._provider_changed,
        ).pack(side="left", padx=(0, 18))
        ttk.Radiobutton(
            provider_row,
            text="Claude CLI 执行器",
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
        for column in range(3):
            action.columnconfigure(column, weight=1, uniform="launch-actions")
        self.start_button = ttk.Button(
            action, text="启动新实例", style="Accent.TButton", command=self._start
        )
        self.start_button.grid(row=0, column=0, sticky="ew")
        ttk.Button(
            action, text="保存项目配置", command=self._save_project
        ).grid(row=0, column=1, sticky="ew", padx=(10, 0))
        ttk.Button(
            action, text="打开项目目录", command=self._open_project_dir
        ).grid(row=0, column=2, sticky="ew", padx=(10, 0))
        self.launch_status = ttk.Label(
            right, text="编辑中的修改不会影响运行实例；点击保存后才应用", style="Muted.TLabel"
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
            variable.trace_add("write", self._project_field_changed)
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
        ttk.Button(actions, text="准入与任务", command=self._open_project_access).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(actions, text="项目范围", command=self._edit_selected_scope).pack(
            side="left", padx=(8, 0)
        )
        self.recover_button = ttk.Button(
            actions, text="恢复实例", command=self._recover_selected_run
        )
        self.recover_button.pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="新实例重跑", command=self._load_selected_as_new).pack(
            side="left", padx=(8, 0)
        )
        self.pause_button = ttk.Button(
            actions,
            text="暂停工程",
            command=self._stop_selected_run,
        )
        self.pause_button.pack(side="right", padx=(8, 0))
        ttk.Button(
            actions,
            text="删除工程",
            style="Danger.TButton",
            command=self._delete_selected_project,
        ).pack(side="right")

        columns = ("project", "run_id", "provider", "status", "components", "created")
        self.run_tree = ttk.Treeview(
            self.runs_tab, columns=columns, show="headings", selectmode="browse"
        )
        headings = {
            "project": "项目",
            "run_id": "实例",
            "provider": "AI 执行器",
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
        self.run_tree.bind("<<TreeviewSelect>>", self._run_selection_changed)
        self.pause_status_var = tk.StringVar(value="")
        ttk.Label(
            self.runs_tab,
            textvariable=self.pause_status_var,
            style="Muted.TLabel",
            wraplength=980,
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(8, 0))

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
            workflow_settings=self.workflow_settings,
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
        self._schedule_project_autosave()

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

    def _agent_settings_for_provider(
        self, provider: str
    ) -> tuple[str, str, str, str]:
        if provider == "claude":
            return (
                self.claude_agent_model,
                self.claude_reasoning_effort,
                self.claude_agent_base_url,
                self.claude_api_key,
            )
        return (
            self.codex_agent_model,
            self.codex_reasoning_effort,
            self.codex_agent_base_url,
            self.codex_api_key,
        )

    def _request(self) -> LaunchRequest:
        selected = tuple(
            tool_id for tool_id, variable in self.tool_vars.items() if variable.get()
        )
        provider = self.provider_var.get()
        agent_model, reasoning_effort, agent_base_url, agent_api_key = (
            self._agent_settings_for_provider(provider)
        )
        return LaunchRequest(
            project_name=self.project_var.get(),
            target=self.target_var.get(),
            scope=self.launch_scope,
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
            agent_api_key=agent_api_key,
            github_token=self.github_token,
            work_mode=str(self.workflow_settings["work_mode"]),
            tscan_backend=str(self.workflow_settings.get("tscan_backend", "gui")),
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
            fscan_skip_poc=bool(self.workflow_settings["fscan_skip_poc"]),
            fscan_skip_brute=bool(self.workflow_settings["fscan_skip_brute"]),
            fscan_port_threads=int(self.workflow_settings["fscan_port_threads"]),
            semantic_threads=int(self.workflow_settings["semantic_threads"]),
            semantic_max_depth=int(self.workflow_settings["semantic_max_depth"]),
            semantic_run_dirsearch=bool(self.workflow_settings["semantic_run_dirsearch"]),
            semantic_max_rate=int(self.workflow_settings["semantic_max_rate"]),
            allow_cidr_expansion=bool(
                self.workflow_settings["allow_cidr_expansion"]
            ),
            new_asset_approval_mode=str(
                self.workflow_settings["new_asset_approval_mode"]
            ),
            new_asset_countdown_seconds=int(
                self.workflow_settings["new_asset_countdown_seconds"]
            ),
            new_asset_popup_enabled=bool(
                self.workflow_settings["new_asset_popup_enabled"]
            ),
            new_asset_popup_topmost=bool(
                self.workflow_settings["new_asset_popup_topmost"]
            ),
            workload_approval_mode=str(
                self.workflow_settings["workload_approval_mode"]
            ),
            workload_countdown_seconds=int(
                self.workflow_settings["workload_countdown_seconds"]
            ),
            workload_agent_threshold=int(
                self.workflow_settings["workload_agent_threshold"]
            ),
            workload_popup_enabled=bool(
                self.workflow_settings["workload_popup_enabled"]
            ),
            workload_popup_topmost=bool(
                self.workflow_settings["workload_popup_topmost"]
            ),
            asset_processing_scope=self.launch_processing_scope,
            credential_audit_enabled=bool(
                self.workflow_settings["credential_audit_enabled"]
            ),
            credential_audit_project_override=bool(
                self.workflow_settings["credential_audit_project_override"]
            ),
            credential_audit_default_action=str(
                self.workflow_settings["credential_audit_default_action"]
            ),
            credential_audit_countdown_seconds=int(
                self.workflow_settings["credential_audit_countdown_seconds"]
            ),
            credential_audit_popup_enabled=bool(
                self.workflow_settings["credential_audit_popup_enabled"]
            ),
            credential_audit_popup_topmost=bool(
                self.workflow_settings["credential_audit_popup_topmost"]
            ),
            credential_audit_wordlist_path=str(
                self.workflow_settings["credential_audit_wordlist_path"]
            ),
            credential_audit_max_attempts=int(
                self.workflow_settings["credential_audit_max_attempts"]
            ),
            credential_audit_requests_per_minute=int(
                self.workflow_settings["credential_audit_requests_per_minute"]
            ),
            credential_audit_concurrency=int(
                self.workflow_settings["credential_audit_concurrency"]
            ),
            credential_audit_stop_on_defense=bool(
                self.workflow_settings["credential_audit_stop_on_defense"]
            ),
        )

    def _start(self) -> None:
        if self._busy:
            return
        if not self._save_project(show_message=False):
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
            return
        assert state is not None
        self.run_states[self._state_key(state)] = state
        self.launch_status.configure(
            text=f"实例 {state.run_id} 已完整启动", foreground=ACCENT
        )
        self._refresh_runs()
        self.notebook.select(self.runs_tab)

    def _load_runs(self) -> None:
        try:
            states = self.manager.apply_workflow_settings(
                self.workflow_settings,
                api_base_url=self.api_base_url_var.get(),
                model=self.default_model,
                agent_profiles=self._global_agent_profiles(),
            )
        except OSError as exc:
            states = self.manager.list_runs()
            self.after(
                0,
                lambda error=str(exc): messagebox.showwarning(
                    "全局设置同步未完成",
                    f"启动时无法更新部分工程文件：{error}",
                    parent=self,
                ),
            )
        self._roll_forward_legacy_coordinators(states)
        self.run_states = {self._state_key(state): state for state in states}
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

    def _refresh_asset_approval_dialogs(self) -> None:
        for key, dialog in list(self._asset_approval_dialogs.items()):
            try:
                exists = bool(dialog.winfo_exists())
            except tk.TclError:
                exists = False
            if not exists:
                self._asset_approval_dialogs.pop(key, None)
        for state in self.run_states.values():
            key = self._state_key(state)
            if state.status != "running" or not state.new_asset_popup_enabled:
                continue
            if state.new_asset_approval_mode == "automatic":
                continue
            if key in self._asset_approval_dialogs:
                continue
            if time.monotonic() < self._asset_approval_snooze_until.get(key, 0):
                continue
            bus_value = read_json(
                Path(state.run_dir) / "tool_data" / "asset_bus" / "assets.json"
            )
            if not pending_asset_groups(bus_value):
                continue

            def closed(state_key: str = key) -> None:
                self._asset_approval_dialogs.pop(state_key, None)
                self._asset_approval_snooze_until[state_key] = time.monotonic() + 30

            dialog = AssetApprovalDialog(
                self,
                project_name=state.project_name,
                run_id=state.run_id,
                run_dir=Path(state.run_dir),
                pending_value=bus_value,
                topmost=state.new_asset_popup_topmost,
                on_close=closed,
            )
            self._asset_approval_dialogs[key] = dialog

    def _refresh_workload_approval_dialogs(self) -> None:
        for key, dialog in list(self._workload_approval_dialogs.items()):
            try:
                exists = bool(dialog.winfo_exists())
            except tk.TclError:
                exists = False
            if not exists:
                self._workload_approval_dialogs.pop(key, None)
        for state in self.run_states.values():
            key = self._state_key(state)
            if state.status != "running" or not state.workload_popup_enabled:
                continue
            if state.workload_approval_mode == "automatic":
                continue
            if key in self._workload_approval_dialogs:
                continue
            if time.monotonic() < self._workload_approval_snooze_until.get(key, 0):
                continue
            request = read_request(Path(state.run_dir))
            if not request or request.get("status") not in {"pending", ""}:
                continue

            def closed(state_key: str = key) -> None:
                self._workload_approval_dialogs.pop(state_key, None)
                self._workload_approval_snooze_until[state_key] = time.monotonic() + 30

            dialog = WorkloadApprovalDialog(
                self,
                request=request,
                run_dir=Path(state.run_dir),
                topmost=state.workload_popup_topmost,
                on_close=closed,
            )
            self._workload_approval_dialogs[key] = dialog

    def _refresh_credential_audit_dialogs(self) -> None:
        for key, dialog in list(self._credential_audit_dialogs.items()):
            try:
                exists = bool(dialog.winfo_exists())
            except tk.TclError:
                exists = False
            if not exists:
                self._credential_audit_dialogs.pop(key, None)
        for state in self.run_states.values():
            key = self._state_key(state)
            if (
                state.status != "running"
                or not state.credential_audit_enabled
                or not state.credential_audit_popup_enabled
                or key in self._credential_audit_dialogs
                or time.monotonic() < self._credential_audit_snooze_until.get(key, 0)
            ):
                continue
            candidates = pending_candidates(Path(state.run_dir))
            if not candidates:
                continue

            def closed(state_key: str = key) -> None:
                self._credential_audit_dialogs.pop(state_key, None)
                self._credential_audit_snooze_until[state_key] = time.monotonic() + 30

            dialog = CredentialAuditDialog(
                self,
                project_name=state.project_name,
                run_dir=Path(state.run_dir),
                candidates=candidates,
                topmost=state.credential_audit_popup_topmost,
                on_close=closed,
            )
            self._credential_audit_dialogs[key] = dialog

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
            "stopped": "已暂停",
            "interrupted": "已中断",
        }.get(state.status, state.status)
        if state.recovery_count:
            return f"{value}(恢复{state.recovery_count})"
        return value

    def _selected_state(self) -> RunState | None:
        selected = self.run_tree.selection()
        return self.run_states.get(selected[0]) if selected else None

    def _run_selection_changed(self, _event=None) -> None:
        """Load the selected run's saved project configuration into the form."""
        state = self._selected_state()
        if state is None:
            return

        key = self._state_key(state)
        if getattr(self, "_loaded_run_config_key", "") == key:
            return

        path = Path(state.run_dir) / "project.json"
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(value, dict):
            return

        self._apply_project_value(value)
        self._loaded_run_config_key = key
        self.launch_status.configure(
            text=f"当前配置来自实例：{state.project_name} / {state.run_id}",
            foreground=MUTED,
        )

    def _recover_selected_run(self) -> None:
        if self._busy:
            return
        state = self._selected_state()
        if state is None:
            self.pause_status_var.set("请先选择一个历史或异常结束的运行实例。")
            return
        self._busy = True
        self.recover_button.state(["disabled"])
        self.pause_status_var.set(
            f"正在恢复实例 {state.run_id}；已有结果、断点和文件会保留…"
        )
        selected_tools = None
        if self._loaded_run_config_key == self._state_key(state):
            selected_tools = tuple(
                tool_id
                for tool_id, variable in self.tool_vars.items()
                if variable.get()
            )

        def worker() -> None:
            try:
                recovered = self.manager.recover(
                    state,
                    authorization_confirmed=True,
                    api_base_url=self.api_base_url_var.get(),
                    model=self.default_model,
                    api_key=self.api_key,
                    agent_api_key=self._agent_settings_for_provider(state.provider)[3],
                    github_token=self.github_token,
                    selected_tools=selected_tools,
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
            self.pause_status_var.set(f"恢复失败：{error}")
            return
        assert state is not None
        self.run_states[self._state_key(state)] = state
        self._refresh_runs()
        self.pause_status_var.set(
            f"恢复完成：实例 {state.run_id} 已在原运行目录恢复，"
            f"第 {state.recovery_count} 次恢复。"
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
        self.launch_status.configure(text=detail, foreground=MUTED)

    def _stop_selected_run(self) -> None:
        if self._busy:
            return
        state = self._selected_state()
        if state is None:
            self.pause_status_var.set("请先选择一个运行实例。")
            return
        project_key = safe_project_name(state.project_name)
        active_states = [
            item
            for item in self.run_states.values()
            if safe_project_name(item.project_name) == project_key
            and item.status in {"starting", "running"}
        ]
        if not active_states:
            self.pause_status_var.set("该工程当前没有正在运行的实例。")
            return
        self._busy = True
        self.pause_button.state(["disabled"])
        self.pause_status_var.set("正在后台暂停工程；界面仍可使用，请稍候…")

        def report(message: str) -> None:
            self.after(
                0,
                lambda message=message: self.pause_status_var.set(message),
            )

        def worker() -> None:
            stopped_states: list[RunState] = []
            errors: list[str] = []
            for active_state in active_states:
                try:
                    stopped_states.append(
                        self.manager.stop(active_state, progress=report)
                    )
                except Exception as exc:
                    errors.append(f"实例 {active_state.run_id}：{exc}")
            self.after(
                0,
                lambda: self._pause_finished(stopped_states, errors),
            )

        threading.Thread(target=worker, daemon=True).start()

    def _pause_finished(
        self,
        stopped_states: list[RunState],
        errors: list[str],
    ) -> None:
        self._busy = False
        self.pause_button.state(["!disabled"])
        for state in stopped_states:
            self.run_states[self._state_key(state)] = state
        self._refresh_runs()
        if errors:
            self.pause_status_var.set(
                "暂停流程已结束，但部分实例停止失败；请查看项目日志后重试："
                + "；".join(errors)
            )
            return
        count = len(stopped_states)
        self.pause_status_var.set(
            f"暂停完成：已彻底停止 {count} 个实例；状态、结果和文件均已保留。"
        )

    def _delete_selected_project(self) -> None:
        if self._busy:
            return
        state = self._selected_state()
        if state is None:
            messagebox.showinfo("删除工程", "请先选择要删除的工程")
            return
        project_states = [
            item
            for item in self.run_states.values()
            if safe_project_name(item.project_name) == safe_project_name(state.project_name)
        ]
        project_dir = self.manager.projects_dir / safe_project_name(state.project_name)
        detail = (
            f"工程：{state.project_name}\n"
            f"运行实例：{len(project_states)} 个\n"
            f"本地目录：{project_dir}\n\n"
            "删除后，该工程的全部状态、扫描结果、证据、日志、工具数据和配置都无法恢复。"
        )
        if not messagebox.askyesno("删除工程", detail + "\n\n确定继续吗？"):
            return
        if not messagebox.askyesno(
            "再次确认删除",
            f"这是最后一次确认。是否永久删除工程“{state.project_name}”？",
        ):
            return
        try:
            self.manager.delete_project(state.project_name)
        except OSError as exc:
            messagebox.showerror("删除失败", f"无法完整删除工程目录：{exc}")
            return
        project_key = safe_project_name(state.project_name)
        for dialogs in (
            self._asset_approval_dialogs,
            self._workload_approval_dialogs,
            self._credential_audit_dialogs,
        ):
            for key, dialog in list(dialogs.items()):
                if not key.startswith(f"{project_key}::"):
                    continue
                dialogs.pop(key, None)
                try:
                    dialog.destroy()
                except tk.TclError:
                    pass
        self._asset_approval_snooze_until = {
            key: value
            for key, value in self._asset_approval_snooze_until.items()
            if not key.startswith(f"{project_key}::")
        }
        self._workload_approval_snooze_until = {
            key: value
            for key, value in self._workload_approval_snooze_until.items()
            if not key.startswith(f"{project_key}::")
        }
        self.run_states = {
            key: item
            for key, item in self.run_states.items()
            if safe_project_name(item.project_name) != project_key
        }
        self.project_box.configure(values=self.manager.list_projects())
        if safe_project_name(self.project_var.get()) == project_key:
            self.project_var.set("")
        self._refresh_runs()
        messagebox.showinfo("删除完成", f"工程“{state.project_name}”及其本地文件已删除。")

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

    def _open_project_access(self) -> None:
        state = self._selected_state()
        if state is None:
            messagebox.showinfo("准入与任务", "请先选择一个运行实例")
            return
        ProjectAccessDialog(self, state)

    def _edit_selected_scope(self) -> None:
        if self._busy:
            return
        state = self._selected_state()
        if state is None:
            messagebox.showinfo("项目范围", "请先选择一个运行实例")
            return
        dialog = ProjectScopeDialog(
            self,
            target=state.target,
            scope=state.scope,
            processing_scope=state.asset_processing_scope,
            require_confirmation=True,
        )
        self.wait_window(dialog)
        if dialog.result is None:
            return
        scope = dialog.result["scope"]
        processing_scope = dialog.result["asset_processing_scope"]
        self._busy = True
        progress = tk.Toplevel(self)
        progress.title("正在更新项目范围")
        progress.geometry("420x130")
        progress.resizable(False, False)
        progress.transient(self)
        progress.protocol("WM_DELETE_WINDOW", lambda: None)
        ttk.Label(
            progress,
            text="正在重新检查现有资产并更新后续任务，请稍候...",
            padding=(20, 22, 20, 10),
        ).pack(fill="x")
        bar = ttk.Progressbar(progress, mode="indeterminate")
        bar.pack(fill="x", padx=20, pady=(0, 20))
        bar.start(12)
        progress.update_idletasks()
        progress.lift()

        def worker() -> None:
            try:
                self.manager.update_project_scopes(
                    state,
                    scope=scope,
                    processing_scope=processing_scope,
                )
            except (OSError, ValueError) as exc:
                error = str(exc)
            else:
                error = ""
            self.after(
                0,
                lambda: self._scope_update_finished(state, progress, error),
            )

        threading.Thread(target=worker, daemon=True).start()

    def _scope_update_finished(
        self,
        state: RunState,
        progress: tk.Toplevel,
        error: str,
    ) -> None:
        self._busy = False
        try:
            progress.destroy()
        except tk.TclError:
            pass
        if error:
            messagebox.showerror("项目范围", error, parent=self)
            return
        self.run_states[self._state_key(state)] = state
        self._refresh_runs()
        self.pause_status_var.set(
            "项目范围已更新：新范围已用于后续资产准入、增量扫描和 AI 执行；"
            "已发出的请求无法撤回。"
        )

    def _project_name_edited(self, _event: tk.Event[tk.Misc]) -> None:
        self._mark_project_dirty()

    def _project_field_changed(self, *_args: object) -> None:
        self._mark_project_dirty()

    def _prompt_changed(self, _event: tk.Event[tk.Misc]) -> None:
        if not self.prompt_text.edit_modified():
            return
        self.prompt_text.edit_modified(False)
        self._mark_project_dirty()

    @staticmethod
    def _autosave_ready(request: LaunchRequest) -> bool:
        return bool(
            request.project_name.strip()
            and not project_name_is_url(request.project_name)
            and request.target.strip()
            and request.scope.strip()
        )

    def _schedule_project_autosave(self) -> None:
        self._mark_project_dirty()

    def _mark_project_dirty(self) -> None:
        if self._applying_project_value or not hasattr(self, "launch_status"):
            return
        self._project_dirty = True
        self.launch_status.configure(
            text="有未保存修改；不会影响运行实例，点击“保存项目配置”后应用",
            foreground=MUTED,
        )

    def _save_project(self, show_message: bool = True) -> bool:
        if self._busy:
            return False
        request = self._request()
        if not self._autosave_ready(request):
            message = "请先填写项目名称、主要目标和授权范围。"
            if show_message:
                messagebox.showwarning("保存项目配置", message, parent=self)
            self.launch_status.configure(text=message, foreground=DANGER)
            return False
        try:
            states = self._persist_project_snapshot(request)
        except (LaunchError, OSError, ValueError) as exc:
            if show_message:
                messagebox.showerror("保存项目配置失败", str(exc), parent=self)
            self.launch_status.configure(text=f"保存失败：{exc}", foreground=DANGER)
            return False
        self._project_dirty = False
        self._save_launcher_settings()
        self.project_box.configure(values=self.manager.list_projects())
        for state in states:
            self.run_states[self._state_key(state)] = state
        if states:
            self._refresh_runs()
        detail = f"项目配置已保存，已应用到 {len(states)} 个现有运行实例。"
        self.launch_status.configure(text=detail, foreground=ACCENT)
        return True

    def _persist_project_snapshot(self, request: LaunchRequest) -> list[RunState]:
        with self._project_save_lock:
            return self.manager.update_project_configuration(
                request,
                tool_network=self.tool_network_settings,
            )

    def _on_close(self) -> None:
        if self._closing:
            return
        if self._busy:
            messagebox.showinfo(
                "操作进行中",
                "当前正在启动、保存或暂停操作。请等待操作完成后再关闭主界面。",
                parent=self,
            )
            return
        if self._project_dirty and not messagebox.askyesno(
            "未保存项目配置",
            "当前项目配置有未保存修改。\n\n点击“是”保存并应用，点击“否”直接关闭并丢弃修改？",
            parent=self,
        ):
            self._save_launcher_settings()
            self.destroy()
            return
        if self._project_dirty and not self._save_project(show_message=False):
            return
        active_states = [
            state
            for state in self.run_states.values()
            if state.status in {"starting", "running"}
        ]
        if not active_states:
            self._finish_close()
            return

        if not messagebox.askyesno(
            "暂停运行中的工程",
            f"当前有 {len(active_states)} 个运行实例正在工作。\n\n"
            "关闭主界面前会先暂停全部实例，停止其组件并保留断点。\n"
            "是否继续关闭？",
            parent=self,
        ):
            return

        self._closing = True
        self._busy = True
        self.pause_button.state(["disabled"])
        self.launch_status.configure(
            text="正在暂停全部运行实例，完成后关闭主界面…", foreground=MUTED
        )

        def worker() -> None:
            errors: list[str] = []
            stopped: list[RunState] = []
            for state in active_states:
                try:
                    stopped.append(self.manager.stop(state))
                except Exception as exc:
                    errors.append(f"{state.project_name}/{state.run_id}：{exc}")
            self.after(0, lambda: self._close_after_pause(stopped, errors))

        threading.Thread(target=worker, daemon=True).start()

    def _close_after_pause(
        self, stopped: list[RunState], errors: list[str]
    ) -> None:
        for state in stopped:
            self.run_states[self._state_key(state)] = state
        self._refresh_runs()
        if errors:
            self._closing = False
            self._busy = False
            self.pause_button.state(["!disabled"])
            self.launch_status.configure(
                text="部分实例暂停失败，主界面保持打开，请查看项目日志。",
                foreground=DANGER,
            )
            messagebox.showwarning(
                "暂停未完成",
                "以下实例未能完全暂停，主界面不会关闭：\n" + "\n".join(errors),
                parent=self,
            )
            return
        self._finish_close()

    def _finish_close(self) -> None:
        self._save_launcher_settings()
        self.destroy()

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
        previous = self._applying_project_value
        self._applying_project_value = True
        try:
            self.project_var.set(str(value.get("name", self.project_var.get())))
            self.target_var.set(str(value.get("target", "")))
            self.launch_scope = str(value.get("scope") or "").strip()
            self.launch_processing_scope = str(
                value.get("asset_processing_scope") or ""
            ).strip()
            self._refresh_scope_summary()
            try:
                schema_version = int(value.get("schema_version", 1))
            except (TypeError, ValueError):
                schema_version = 1
            provider = normalize_provider(
                value.get("provider", "codexx"), schema_version
            )
            if provider not in {"codexx", "codex", "claude"}:
                provider = "codexx"
            self.provider_var.set(provider)
            selected = set(value.get("selected_tools", []))
            for tool_id, variable in self.tool_vars.items():
                variable.set(tool_id in selected)
            self.prompt_text.delete("1.0", "end")
            self.prompt_text.insert("1.0", str(value.get("user_prompt", "")))
            self.prompt_text.edit_modified(False)
            self.auth_var.set(project_authorization_confirmed(value))
            self._project_dirty = False
        finally:
            self._applying_project_value = previous

    def _authorization_changed(self, *_args: object) -> None:
        if self.auth_var.get():
            text = "已确认获得上述范围的安全测试授权（会随项目配置保存）"
        else:
            text = "尚未确认安全测试授权（启动前必须确认）"
        self.auth_text_var.set(text)
        self._schedule_project_autosave()

    def _target_changed(self, *_args: object) -> None:
        if self.auth_var.get():
            self.auth_var.set(False)
        self._schedule_project_autosave()

    def _edit_launch_scope(self) -> None:
        dialog = ProjectScopeDialog(
            self,
            target=self.target_var.get(),
            scope=self.launch_scope,
            processing_scope=self.launch_processing_scope,
        )
        self.wait_window(dialog)
        if dialog.result is None:
            return
        scope = dialog.result["scope"]
        processing_scope = dialog.result["asset_processing_scope"]
        if scope != self.launch_scope or processing_scope != self.launch_processing_scope:
            self.auth_var.set(False)
        self.launch_scope = scope
        self.launch_processing_scope = processing_scope
        self._refresh_scope_summary()
        self._schedule_project_autosave()

    def _refresh_scope_summary(self) -> None:
        scope_count = len(
            [line for line in self.launch_scope.splitlines() if line.strip()]
        )
        processing_count = len(
            [
                line
                for line in self.launch_processing_scope.splitlines()
                if line.strip()
            ]
        )
        processing_text = (
            f"自动处理 {processing_count} 条规则"
            if processing_count
            else "自动处理范围不额外限制"
        )
        self.scope_summary_var.set(
            f"授权 {scope_count} 条规则；{processing_text}"
            if scope_count
            else "尚未设置授权范围"
        )

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
            codex_api_key=self.codex_api_key,
            claude_agent_model=self.claude_agent_model,
            claude_reasoning_effort=self.claude_reasoning_effort,
            claude_agent_base_url=self.claude_agent_base_url,
            claude_api_key=self.claude_api_key,
            github_token=self.github_token,
            workflow_settings=self.workflow_settings,
            tool_network_settings=self.tool_network_settings,
        )
        self.wait_window(dialog)
        if dialog.result is None:
            return
        try:
            save_secret_values(
                self.launcher_secrets_path,
                {
                    "shared_ai_api_key": str(dialog.result["api_key"]),
                    "codex_api_key": str(dialog.result["codex_api_key"]),
                    "claude_api_key": str(dialog.result["claude_api_key"]),
                    "github_token": str(dialog.result["github_token"]),
                },
            )
        except SecretStoreError as exc:
            messagebox.showerror("STTool 全局设置", str(exc), parent=self)
            return
        self.api_key = str(dialog.result["api_key"])
        self.codex_api_key = str(dialog.result["codex_api_key"])
        self.claude_api_key = str(dialog.result["claude_api_key"])
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
        self.tool_network_settings = normalize_tool_network(
            dialog.result.get("tool_network")
        )
        self._save_launcher_settings()
        try:
            updated = self._apply_global_workflow_settings()
        except OSError as exc:
            messagebox.showwarning(
                "全局设置已保存",
                f"全局设置已经保存，但无法热更新部分工程文件：{exc}",
                parent=self,
            )
            return
        messagebox.showinfo(
            "全局设置已应用",
            (
                f"工作流设置已同步到 {updated} 个现有运行实例。\n\n"
                "弹窗策略、倒计时和自动调度参数已热更新；"
                "已经启动的外部扫描进程和 AI 会话不会被强制重启。\n"
                "工具代理与附加请求头将在恢复项目、下一轮增量任务或新启动工具时生效。"
            ),
            parent=self,
        )

    def _open_help(self) -> None:
        path = ensure_help_document(self.manager.app_dir)
        os.startfile(path)

    def _open_global_search(self) -> None:
        GlobalSearchDialog(self)

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
            "tool_network": self.tool_network_settings,
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

    def _close_approval_dialogs(self) -> None:
        for dialogs in (
            self._asset_approval_dialogs,
            self._workload_approval_dialogs,
            self._credential_audit_dialogs,
        ):
            for key, dialog in list(dialogs.items()):
                dialogs.pop(key, None)
                try:
                    dialog.destroy()
                except tk.TclError:
                    pass
        self._asset_approval_snooze_until.clear()
        self._workload_approval_snooze_until.clear()
        self._credential_audit_snooze_until.clear()

    def _apply_global_workflow_settings(self) -> int:
        states = self.manager.apply_workflow_settings(
            self.workflow_settings,
            api_base_url=self.api_base_url_var.get(),
            model=self.default_model,
            agent_profiles=self._global_agent_profiles(),
            tool_network=self.tool_network_settings,
        )
        self._roll_forward_legacy_coordinators(states)
        self.run_states = {self._state_key(state): state for state in states}
        self._close_approval_dialogs()
        self._refresh_runs()
        self._refresh_asset_approval_dialogs()
        self._refresh_workload_approval_dialogs()
        self._refresh_credential_audit_dialogs()
        return len(states)

    def _roll_forward_legacy_coordinators(self, states: list[RunState]) -> None:
        failures: list[str] = []
        for state in states:
            if state.status != "running":
                continue
            if not self.manager.coordinator_is_running(state):
                continue
            if self.manager.coordinator_supports_hot_settings(state):
                continue
            try:
                self.manager.restart_coordinator_for_hot_settings(
                    state,
                    api_key=self.api_key,
                    agent_api_key=self._agent_settings_for_provider(state.provider)[3],
                    github_token=self.github_token,
                )
            except (LaunchError, OSError) as exc:
                failures.append(f"{state.project_name}/{state.run_id}: {exc}")
        if failures:
            messagebox.showwarning(
                "部分工程热更新待处理",
                "以下运行实例的内部协调器未能滚动更新：\n" + "\n".join(failures),
                parent=self,
            )

    def _global_agent_profiles(self) -> dict[str, dict[str, str]]:
        return {
            "codex": {
                "agent_model": self.codex_agent_model,
                "reasoning_effort": self.codex_reasoning_effort,
                "agent_base_url": self.codex_agent_base_url,
            },
            "claude": {
                "agent_model": self.claude_agent_model,
                "reasoning_effort": self.claude_reasoning_effort,
                "agent_base_url": self.claude_agent_base_url,
            },
        }

    def _tick(self) -> None:
        try:
            self._refresh_runs()
            self._refresh_asset_approval_dialogs()
            self._refresh_workload_approval_dialogs()
            self._refresh_credential_audit_dialogs()
        finally:
            self.after(2000, self._tick)
