from __future__ import annotations

import socket
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from urllib.parse import urlsplit

from .agent_connection_test import test_agent_connection
from .models import DEFAULT_API_BASE_URL
from .tool_network import normalize_tool_network
from .workflow_settings import (
    WORK_MODE_LABELS,
    normalize_workflow_settings,
    normalized_reasoning_effort,
    work_mode_defaults,
)


WORKLOAD_APPROVAL_LABELS = {
    "automatic": "\u81ea\u52a8\u542f\u52a8\uff08\u4e0d\u5f39\u7a97\uff09",
    "countdown_accept": "\u5f39\u7a97\u63d0\u9192\uff0c\u5012\u8ba1\u65f6\u540e\u542f\u52a8",
    "countdown_reject": "\u5f39\u7a97\u63d0\u9192\uff0c\u5012\u8ba1\u65f6\u540e\u8df3\u8fc7",
    "manual": "\u59cb\u7ec8\u7b49\u5f85\u4eba\u5de5\u786e\u8ba4",
}

ASSET_APPROVAL_LABELS = {
    "automatic": "自动加入（不弹窗）",
    "countdown_accept": "弹窗提醒，倒计时后自动加入",
    "countdown_reject": "弹窗提醒，倒计时后自动排除",
    "manual": "始终等待人工确认（不自动处理）",
}

TOOL_NETWORK_MODE_LABELS = {
    "direct": "直连",
    "http": "HTTP 代理",
    "socks5": "SOCKS5 优先（兼容 HTTP 降级）",
}

TSCAN_BACKEND_LABELS = {
    "cli": "后台 CLI（无窗口，推荐）",
    "gui": "GUI 自动化（完整页面和菜单）",
}


CREDENTIAL_AUDIT_LABELS = {
    "save_only": "仅保存待办，不自动验证",
    "agent_default_dictionary": "交给 Agent：默认字典",
    "agent_social_dictionary": "交给 Agent：社工字典",
}


class AISettingsDialog(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Misc,
        api_base_url: str,
        model: str,
        api_key: str,
        *,
        codex_agent_model: str = "",
        codex_reasoning_effort: str = "",
        codex_agent_base_url: str = "",
        codex_api_key: str = "",
        claude_agent_model: str = "",
        claude_reasoning_effort: str = "",
        claude_agent_base_url: str = "",
        claude_api_key: str = "",
        github_token: str = "",
        workflow_settings: dict[str, object] | None = None,
        tool_network_settings: dict[str, object] | None = None,
        dialog_title: str = "STTool 全局设置",
    ) -> None:
        super().__init__(parent)
        self.result: dict[str, object] | None = None
        self._scroll_canvases: list[tk.Canvas] = []
        self.title(dialog_title)
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        window_width = min(900, max(screen_width - 80, 700))
        window_height = min(860, max(screen_height - 120, 560))
        self.geometry(f"{window_width}x{window_height}")
        self.minsize(min(700, window_width), min(560, window_height))
        self.transient(parent)
        self.protocol("WM_DELETE_WINDOW", self.destroy)

        workflow = normalize_workflow_settings(workflow_settings)
        tool_network = normalize_tool_network(tool_network_settings)
        self.api_base_url_var = tk.StringVar(value=api_base_url or DEFAULT_API_BASE_URL)
        self.model_var = tk.StringVar(value=model or "gpt-5.5")
        self.api_key_var = tk.StringVar(value=api_key)
        self.show_key_var = tk.BooleanVar(value=False)
        self.codex_agent_model_var = tk.StringVar(value=codex_agent_model)
        self.codex_reasoning_effort_var = tk.StringVar(
            value=normalized_reasoning_effort(codex_reasoning_effort) or "CLI 默认"
        )
        self.codex_agent_base_url_var = tk.StringVar(value=codex_agent_base_url)
        self.codex_api_key_var = tk.StringVar(value=codex_api_key)
        self.show_codex_key_var = tk.BooleanVar(value=False)
        self.claude_agent_model_var = tk.StringVar(value=claude_agent_model)
        self.claude_reasoning_effort_var = tk.StringVar(
            value=normalized_reasoning_effort(claude_reasoning_effort) or "CLI 默认"
        )
        self.claude_agent_base_url_var = tk.StringVar(value=claude_agent_base_url)
        self.claude_api_key_var = tk.StringVar(value=claude_api_key)
        self.show_claude_key_var = tk.BooleanVar(value=False)
        self.github_token_var = tk.StringVar(value=github_token)
        self.show_github_token_var = tk.BooleanVar(value=False)
        self.work_mode_var = tk.StringVar(
            value=WORK_MODE_LABELS[str(workflow["work_mode"])]
        )
        self.tscan_backend_var = tk.StringVar(
            value=TSCAN_BACKEND_LABELS[str(workflow.get("tscan_backend", "gui"))]
        )
        self.tscan_auto_update_var = tk.BooleanVar(
            value=bool(workflow.get("tscan_auto_update", True))
        )
        self.auto_agent_var = tk.BooleanVar(value=bool(workflow["auto_agent"]))
        self.wait_asset_var = tk.BooleanVar(
            value=bool(workflow["wait_for_asset_commander"])
        )
        self.wait_fscan_var = tk.BooleanVar(value=bool(workflow["wait_for_fscan"]))
        self.ai_summary_var = tk.BooleanVar(value=bool(workflow["ai_summary_enabled"]))
        self.settle_seconds_var = tk.IntVar(value=int(workflow["asset_settle_seconds"]))
        self.max_batches_var = tk.IntVar(value=int(workflow["max_agent_batches"]))
        self.poll_seconds_var = tk.IntVar(
            value=int(workflow["coordinator_poll_seconds"])
        )
        self.agent_stall_warn_minutes_var = tk.IntVar(
            value=int(workflow["agent_stall_warn_minutes"])
        )
        self.fscan_skip_poc_var = tk.BooleanVar(value=bool(workflow["fscan_skip_poc"]))
        self.fscan_skip_brute_var = tk.BooleanVar(value=bool(workflow["fscan_skip_brute"]))
        self.fscan_port_threads_var = tk.IntVar(value=int(workflow["fscan_port_threads"]))
        self.semantic_threads_var = tk.IntVar(value=int(workflow["semantic_threads"]))
        self.semantic_max_depth_var = tk.IntVar(value=int(workflow["semantic_max_depth"]))
        self.semantic_run_dirsearch_var = tk.BooleanVar(value=bool(workflow["semantic_run_dirsearch"]))
        self.semantic_max_rate_var = tk.IntVar(value=int(workflow["semantic_max_rate"]))
        self.allow_cidr_expansion_var = tk.BooleanVar(
            value=bool(workflow["allow_cidr_expansion"])
        )
        self.new_asset_approval_var = tk.StringVar(
            value=ASSET_APPROVAL_LABELS[str(workflow["new_asset_approval_mode"])]
        )
        self.new_asset_countdown_var = tk.IntVar(
            value=int(workflow["new_asset_countdown_seconds"])
        )
        self.new_asset_popup_enabled_var = tk.BooleanVar(
            value=bool(workflow["new_asset_popup_enabled"])
        )
        self.new_asset_popup_topmost_var = tk.BooleanVar(
            value=bool(workflow["new_asset_popup_topmost"])
        )
        self.workload_approval_var = tk.StringVar(
            value=WORKLOAD_APPROVAL_LABELS[str(workflow["workload_approval_mode"])]
        )
        self.workload_countdown_var = tk.IntVar(
            value=int(workflow["workload_countdown_seconds"])
        )
        self.workload_agent_threshold_var = tk.IntVar(
            value=int(workflow["workload_agent_threshold"])
        )
        self.workload_popup_enabled_var = tk.BooleanVar(
            value=bool(workflow["workload_popup_enabled"])
        )
        self.workload_popup_topmost_var = tk.BooleanVar(
            value=bool(workflow["workload_popup_topmost"])
        )
        self.credential_audit_enabled_var = tk.BooleanVar(
            value=bool(workflow["credential_audit_enabled"])
        )
        self.credential_audit_project_override_var = tk.BooleanVar(
            value=bool(workflow["credential_audit_project_override"])
        )
        self.credential_audit_default_action_var = tk.StringVar(
            value=CREDENTIAL_AUDIT_LABELS[
                str(workflow["credential_audit_default_action"])
            ]
        )
        self.credential_audit_countdown_var = tk.IntVar(
            value=int(workflow["credential_audit_countdown_seconds"])
        )
        self.credential_audit_popup_enabled_var = tk.BooleanVar(
            value=bool(workflow["credential_audit_popup_enabled"])
        )
        self.credential_audit_popup_topmost_var = tk.BooleanVar(
            value=bool(workflow["credential_audit_popup_topmost"])
        )
        self.credential_audit_wordlist_var = tk.StringVar(
            value=str(workflow["credential_audit_wordlist_path"])
        )
        self.credential_audit_max_attempts_var = tk.IntVar(
            value=int(workflow["credential_audit_max_attempts"])
        )
        self.credential_audit_requests_per_minute_var = tk.IntVar(
            value=int(workflow["credential_audit_requests_per_minute"])
        )
        self.credential_audit_concurrency_var = tk.IntVar(
            value=int(workflow["credential_audit_concurrency"])
        )
        self.credential_audit_stop_on_defense_var = tk.BooleanVar(
            value=bool(workflow["credential_audit_stop_on_defense"])
        )
        self.tool_network_mode_var = tk.StringVar(
            value=TOOL_NETWORK_MODE_LABELS[str(tool_network["mode"])]
        )
        self.tool_proxy_host_var = tk.StringVar(value=str(tool_network["host"]))
        self.tool_proxy_port_var = tk.IntVar(value=int(tool_network["port"]))
        self.tool_header_name_var = tk.StringVar(value=str(tool_network["header_name"]))
        self.tool_header_value_var = tk.StringVar(value=str(tool_network["header_value"]))

        content = ttk.Frame(self, padding=16)
        content.pack(fill="both", expand=True)
        notebook = ttk.Notebook(content)
        notebook.pack(fill="both", expand=True)
        self._build_agent_tab(notebook, "codex")
        self._build_agent_tab(notebook, "claude")
        self._build_shared_ai_tab(notebook)
        self._build_vulnerability_intel_tab(notebook)
        self._build_tool_network_tab(notebook)
        self._build_workflow_tab(notebook)

        actions = ttk.Frame(content)
        actions.pack(fill="x", pady=(14, 0))
        ttk.Button(actions, text="取消", command=self.destroy).pack(side="right")
        ttk.Button(actions, text="保存全局设置", command=self._save).pack(
            side="right", padx=(0, 8)
        )

        self.bind("<Escape>", lambda _event: self.destroy())
        self.bind("<MouseWheel>", self._scroll_with_mousewheel, add="+")
        self.bind("<Button-4>", self._scroll_with_mousewheel, add="+")
        self.bind("<Button-5>", self._scroll_with_mousewheel, add="+")
        self.update_idletasks()
        x = parent.winfo_rootx() + max(
            20, (parent.winfo_width() - self.winfo_width()) // 2
        )
        y = parent.winfo_rooty() + max(
            20, (parent.winfo_height() - self.winfo_height()) // 3
        )
        self.geometry(f"+{x}+{y}")
        self.grab_set()

    def _add_scrollable_tab(
        self, notebook: ttk.Notebook, title: str
    ) -> ttk.Frame:
        page = ttk.Frame(notebook)
        page.rowconfigure(0, weight=1)
        page.columnconfigure(0, weight=1)
        notebook.add(page, text=title)

        background = ttk.Style(self).lookup("TFrame", "background") or "#f0f0f0"
        canvas = tk.Canvas(
            page,
            background=background,
            borderwidth=0,
            highlightthickness=0,
        )
        scrollbar = ttk.Scrollbar(page, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        tab = ttk.Frame(canvas, padding=18)
        window = canvas.create_window((0, 0), window=tab, anchor="nw")
        tab.bind(
            "<Configure>",
            lambda _event, target=canvas: target.configure(
                scrollregion=target.bbox("all")
            ),
        )
        canvas.bind(
            "<Configure>",
            lambda event, target=canvas, item=window: target.itemconfigure(
                item, width=event.width
            ),
        )
        self._scroll_canvases.append(canvas)
        return tab

    def _scroll_with_mousewheel(self, event: tk.Event) -> str | None:
        widget = self.winfo_containing(event.x_root, event.y_root)
        canvas = next(
            (
                item
                for item in self._scroll_canvases
                if widget is not None and self._is_descendant(widget, item)
            ),
            None,
        )
        if canvas is None:
            return None
        top, bottom = canvas.yview()
        if top <= 0.0 and bottom >= 1.0:
            return None
        if getattr(event, "num", None) == 4:
            units = -3
        elif getattr(event, "num", None) == 5:
            units = 3
        else:
            delta = int(getattr(event, "delta", 0))
            units = -3 if delta > 0 else 3 if delta < 0 else 0
        if units:
            canvas.yview_scroll(units, "units")
            return "break"
        return None

    @staticmethod
    def _is_descendant(widget: tk.Misc, ancestor: tk.Misc) -> bool:
        current: tk.Misc | None = widget
        while current is not None:
            if current == ancestor:
                return True
            parent_name = current.winfo_parent()
            if not parent_name:
                break
            try:
                current = current._nametowidget(parent_name)
            except KeyError:
                break
        return False

    def _build_agent_tab(self, notebook: ttk.Notebook, provider: str) -> None:
        is_claude = provider == "claude"
        title = "Claude CLI" if is_claude else "Codex / Codexx CLI"
        tab = self._add_scrollable_tab(notebook, title)
        tab.columnconfigure(0, weight=1)
        if is_claude:
            description = (
                "Claude 是外部 CLI 执行器，不是 STTool 内置 AI。可单独配置模型、"
                "推理强度、Base URL 和 API Key；Key 仅用 Windows DPAPI 加密保存。"
            )
            model_var = self.claude_agent_model_var
            effort_var = self.claude_reasoning_effort_var
            base_url_var = self.claude_agent_base_url_var
            key_var = self.claude_api_key_var
            show_key_var = self.show_claude_key_var
            models = ("", "sonnet", "opus", "haiku")
            url_label = "Anthropic API Base URL（可选，留空使用 CLI 配置）"
            efforts = ("CLI 默认", "low", "medium", "high")
        else:
            description = (
                "Codex/Codexx 是外部 CLI 执行器，不是 STTool 内置 AI。可单独配置模型、"
                "推理强度、Base URL 和 API Key；Key 仅用 Windows DPAPI 加密保存。"
            )
            model_var = self.codex_agent_model_var
            effort_var = self.codex_reasoning_effort_var
            base_url_var = self.codex_agent_base_url_var
            key_var = self.codex_api_key_var
            show_key_var = self.show_codex_key_var
            models = ("", "gpt-5.5", "gpt-5.6-sol")
            url_label = "OpenAI 兼容 API Base URL（可选，留空使用 CLI 配置）"
            efforts = ("CLI 默认", "low", "medium", "high", "xhigh")
        ttk.Label(tab, text=description, wraplength=660).grid(
            row=0, column=0, sticky="w", pady=(0, 18)
        )
        ttk.Label(tab, text="AI 模型（可编辑，留空使用 CLI 默认）").grid(
            row=1, column=0, sticky="w", pady=(0, 5)
        )
        ttk.Combobox(tab, textvariable=model_var, values=models).grid(
            row=2, column=0, sticky="ew", pady=(0, 16)
        )
        ttk.Label(tab, text="推理强度").grid(
            row=3, column=0, sticky="w", pady=(0, 5)
        )
        ttk.Combobox(
            tab,
            textvariable=effort_var,
            values=efforts,
            state="readonly",
        ).grid(row=4, column=0, sticky="ew", pady=(0, 16))
        self._field(tab, 5, url_label, base_url_var)
        ttk.Label(tab, text="API Key（可选；留空使用 CLI 自身登录）").grid(
            row=7, column=0, sticky="w", pady=(0, 5)
        )
        key_row = ttk.Frame(tab)
        key_row.grid(row=8, column=0, sticky="ew")
        key_row.columnconfigure(0, weight=1)
        key_entry = ttk.Entry(key_row, textvariable=key_var, show="*", width=54)
        key_entry.grid(row=0, column=0, sticky="ew")
        ttk.Checkbutton(
            key_row,
            text="显示",
            variable=show_key_var,
            command=lambda: key_entry.configure(show="" if show_key_var.get() else "*"),
        ).grid(row=0, column=1, padx=(8, 0))
        test_row = ttk.Frame(tab)
        test_row.grid(row=9, column=0, sticky="ew", pady=(16, 0))
        test_status_var = tk.StringVar(value="尚未测试")
        if is_claude:
            providers = (("claude", "测试 Claude"),)
        else:
            providers = (("codex", "测试 Codex"), ("codexx", "测试 Codexx"))
        for cli_provider, label in providers:
            button = ttk.Button(test_row, text=label)
            button.configure(
                command=lambda selected=cli_provider, control=button: self._test_agent(
                    selected,
                    model_var,
                    effort_var,
                    base_url_var,
                    key_var,
                    test_status_var,
                    control,
                )
            )
            button.pack(side="left", padx=(0, 8))
        ttk.Label(test_row, textvariable=test_status_var).pack(side="left", padx=(6, 0))

    def _test_agent(
        self,
        provider: str,
        model_var: tk.StringVar,
        effort_var: tk.StringVar,
        base_url_var: tk.StringVar,
        key_var: tk.StringVar,
        status_var: tk.StringVar,
        button: ttk.Button,
    ) -> None:
        base_url = base_url_var.get().strip().rstrip("/")
        if not self._valid_optional_url(base_url):
            messagebox.showerror(
                "测试 AI 执行器",
                "Base URL 必须留空或填写有效的 HTTP/HTTPS 地址",
                parent=self,
            )
            return
        effort = effort_var.get()
        if effort == "CLI 默认":
            effort = ""
        model = model_var.get().strip()
        api_key = key_var.get().strip()
        button.configure(state="disabled")
        status_var.set("正在执行最小实际请求……")

        def worker() -> None:
            result = test_agent_connection(
                provider,
                model,
                effort,
                base_url,
                api_key,
            )
            try:
                self.after(
                    0,
                    lambda: self._finish_agent_test(
                        provider, result, status_var, button
                    ),
                )
            except tk.TclError:
                return

        threading.Thread(target=worker, daemon=True).start()

    def _finish_agent_test(
        self,
        provider: str,
        result: tuple[bool, str],
        status_var: tk.StringVar,
        button: ttk.Button,
    ) -> None:
        success, detail = result
        button.configure(state="normal")
        status_var.set("测试成功" if success else "测试失败")
        dialog = messagebox.showinfo if success else messagebox.showerror
        dialog(f"{provider} 实际请求测试", detail, parent=self)

    def _build_shared_ai_tab(self, notebook: ttk.Notebook) -> None:
        tab = self._add_scrollable_tab(notebook, "工具协作 AI")
        tab.columnconfigure(0, weight=1)
        ttk.Label(
            tab,
            text=(
                "用于工具间信息汇总、传递与风险摘要优化。该 OpenAI 兼容配置独立于本地 "
                "Codex/Codexx/Claude；API Key 使用 Windows DPAPI 加密保存。"
            ),
            wraplength=660,
        ).grid(row=0, column=0, sticky="w", pady=(0, 16))
        self._field(tab, 1, "OpenAI 兼容 API Base URL", self.api_base_url_var)
        self._field(tab, 3, "工具协作模型", self.model_var)
        ttk.Label(tab, text="API Key").grid(row=5, column=0, sticky="w", pady=(0, 5))
        key_row = ttk.Frame(tab)
        key_row.grid(row=6, column=0, sticky="ew")
        key_row.columnconfigure(0, weight=1)
        self.key_entry = ttk.Entry(
            key_row, textvariable=self.api_key_var, show="*", width=54
        )
        self.key_entry.grid(row=0, column=0, sticky="ew")
        ttk.Checkbutton(
            key_row,
            text="显示",
            variable=self.show_key_var,
            command=lambda: self.key_entry.configure(
                show="" if self.show_key_var.get() else "*"
            ),
        ).grid(row=0, column=1, padx=(8, 0))

    def _build_vulnerability_intel_tab(self, notebook: ttk.Notebook) -> None:
        tab = self._add_scrollable_tab(notebook, "漏洞情报")
        tab.columnconfigure(0, weight=1)
        ttk.Label(
            tab,
            text=(
                "find-gh-poc 使用 GitHub GraphQL API，建议配置个人访问 Token。Token 仅通过"
                "自动调度器进程环境和一次性临时文件传递，不进入项目、日志或命令行。"
            ),
            wraplength=660,
        ).grid(row=0, column=0, sticky="w", pady=(0, 16))
        ttk.Label(tab, text="GitHub Token（GITHUB_TOKEN）").grid(
            row=1, column=0, sticky="w", pady=(0, 5)
        )
        token_row = ttk.Frame(tab)
        token_row.grid(row=2, column=0, sticky="ew")
        token_row.columnconfigure(0, weight=1)
        self.github_token_entry = ttk.Entry(
            token_row, textvariable=self.github_token_var, show="*", width=54
        )
        self.github_token_entry.grid(row=0, column=0, sticky="ew")
        ttk.Checkbutton(
            token_row,
            text="显示",
            variable=self.show_github_token_var,
            command=lambda: self.github_token_entry.configure(
                show="" if self.show_github_token_var.get() else "*"
            ),
        ).grid(row=0, column=1, padx=(8, 0))
        ttk.Label(
            tab,
            text="留空时该阶段会显示“等待配置”，不会把整个项目判定为失败。",
        ).grid(row=3, column=0, sticky="w", pady=(12, 0))

    def _build_tool_network_tab(self, notebook: ttk.Notebook) -> None:
        tab = self._add_scrollable_tab(notebook, "工具网络")
        tab.columnconfigure(1, weight=1)
        tab.columnconfigure(3, weight=1)
        ttk.Label(
            tab,
            text=(
                "只影响 STTool 启动的扫描/取证工具，不修改 Windows 系统代理，也不修改 "
                "Codex、Codexx 或 Claude CLI。直连会清除子进程继承的代理环境；"
                "SOCKS5 使用远程 DNS；对不支持 SOCKS5 的工具，STTool 会在同一地址和端口尝试 HTTP 代理兼容模式。"
                "已经运行的外部工具不会被强制重启，恢复项目或下一轮工具进程会使用新设置。"
            ),
            wraplength=700,
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 16))
        ttk.Label(tab, text="网络模式").grid(row=1, column=0, sticky="w", padx=(0, 12), pady=5)
        ttk.Combobox(
            tab,
            textvariable=self.tool_network_mode_var,
            values=tuple(TOOL_NETWORK_MODE_LABELS.values()),
            state="readonly",
        ).grid(row=1, column=1, columnspan=2, sticky="ew", pady=5)
        ttk.Label(tab, text="代理地址").grid(row=2, column=0, sticky="w", padx=(0, 12), pady=5)
        ttk.Entry(tab, textvariable=self.tool_proxy_host_var).grid(row=2, column=1, columnspan=2, sticky="ew", pady=5)
        ttk.Label(tab, text="代理端口").grid(row=3, column=0, sticky="w", padx=(0, 12), pady=5)
        ttk.Spinbox(tab, from_=1, to=65535, textvariable=self.tool_proxy_port_var, width=10).grid(row=3, column=1, sticky="w", pady=5)
        ttk.Button(tab, text="测试代理端口", command=self._test_tool_proxy).grid(row=3, column=2, sticky="e", pady=5)
        ttk.Separator(tab).grid(row=4, column=0, columnspan=3, sticky="ew", pady=14)
        ttk.Label(tab, text="附加请求头名称").grid(row=5, column=0, sticky="w", padx=(0, 12), pady=5)
        ttk.Entry(tab, textvariable=self.tool_header_name_var).grid(row=5, column=1, columnspan=2, sticky="ew", pady=5)
        ttk.Label(tab, text="附加请求头值").grid(row=6, column=0, sticky="w", padx=(0, 12), pady=5)
        ttk.Entry(tab, textvariable=self.tool_header_value_var).grid(row=6, column=1, columnspan=2, sticky="ew", pady=5)
        ttk.Label(
            tab,
            text=(
                "名称或值任意一项留空时，不会附加任何请求头。例如名称 flag、值 xiaoxiong。"
                "PassHack、nuclei 和 STTool 原生 HTTP 会直接使用；"
                "其他 GUI/闭源工具若不支持自定义请求头，应让它们经过可注入该请求头的中间代理。"
                "原始端口扫描（如 fscan 的 TCP 探测）不属于 HTTP，代理和请求头不会作用于该部分。"
            ),
            wraplength=700,
        ).grid(row=7, column=0, columnspan=3, sticky="w", pady=(12, 0))

    def _test_tool_proxy(self) -> None:
        reverse = {label: mode for mode, label in TOOL_NETWORK_MODE_LABELS.items()}
        mode = reverse.get(self.tool_network_mode_var.get(), "direct")
        if mode == "direct":
            messagebox.showinfo("工具网络", "当前为直连模式，不需要测试代理端口。", parent=self)
            return
        host = self.tool_proxy_host_var.get().strip()
        try:
            port = int(self.tool_proxy_port_var.get())
            with socket.create_connection((host, port), timeout=3):
                pass
        except (OSError, TypeError, ValueError) as exc:
            messagebox.showerror("工具网络", f"代理端口连接失败：{exc}", parent=self)
            return
        messagebox.showinfo(
            "工具网络",
            f"已连接 {host}:{port}。这只确认端口可达，不代表上游线路和请求头注入一定成功。",
            parent=self,
        )

    def _build_workflow_tab(self, notebook: ttk.Notebook) -> None:
        tab = self._add_scrollable_tab(notebook, "调度方式")
        tab.columnconfigure(0, weight=0)
        tab.columnconfigure(1, weight=1)
        tab.columnconfigure(2, weight=0)
        tab.columnconfigure(3, weight=1)
        ttk.Label(
            tab,
            text=(
                "预设会调整 AI 的启动时机和新增资产处理节奏；下列细项会真正传给自动调度器。"
                "平衡模式默认等待 AssetCommander 与 fscan 完成后再启动 AI。"
            ),
            wraplength=660,
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 16))
        ttk.Label(tab, text="工作模式").grid(row=1, column=0, sticky="w", padx=(0, 12))
        mode_box = ttk.Combobox(
            tab,
            textvariable=self.work_mode_var,
            values=tuple(WORK_MODE_LABELS.values()),
            state="readonly",
        )
        mode_box.grid(row=1, column=1, sticky="ew", pady=(0, 14))
        mode_box.bind("<<ComboboxSelected>>", self._mode_changed)
        ttk.Label(tab, text="Tscan 执行方式").grid(
            row=1, column=2, sticky="w", padx=(18, 8)
        )
        ttk.Combobox(
            tab,
            textvariable=self.tscan_backend_var,
            values=tuple(TSCAN_BACKEND_LABELS.values()),
            state="readonly",
            width=28,
        ).grid(row=1, column=3, sticky="ew", pady=(0, 14))
        ttk.Label(
            tab,
            text="CLI 不显示窗口；GUI 才有 Tscan 页面和右键菜单。切换不会强制重启当前实例。",
            wraplength=680,
        ).grid(row=2, column=2, columnspan=2, sticky="w", padx=(18, 0), pady=(0, 10))
        ttk.Checkbutton(
            tab,
            text="每次启动 Tscan 自动检查并更新（默认开启）",
            variable=self.tscan_auto_update_var,
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(0, 10))

        checks = ttk.LabelFrame(tab, text="启动条件", padding=12)
        checks.grid(row=3, column=0, columnspan=4, sticky="ew", pady=(0, 14))
        ttk.Checkbutton(
            checks, text="自动启动新增资产的 AI 执行", variable=self.auto_agent_var
        ).grid(row=0, column=0, sticky="w", pady=3)
        ttk.Checkbutton(
            checks,
            text="等待 AssetCommander 完整结束（不只等待提前资产移交）",
            variable=self.wait_asset_var,
        ).grid(row=1, column=0, sticky="w", pady=3)
        ttk.Checkbutton(
            checks,
            text="等待 fscan 完整输出后再启动 AI",
            variable=self.wait_fscan_var,
        ).grid(row=2, column=0, sticky="w", pady=3)
        ttk.Checkbutton(
            checks,
            text="使用工具协作 AI 优化阶段性风险摘要",
            variable=self.ai_summary_var,
        ).grid(row=3, column=0, sticky="w", pady=3)

        tuning = ttk.LabelFrame(tab, text="增量调度参数", padding=12)
        tuning.grid(row=4, column=0, columnspan=4, sticky="ew")
        tuning.columnconfigure(1, weight=1)
        self._spin_field(
            tuning, 0, "获准资产无新增等待（秒）", self.settle_seconds_var, 1, 600
        )
        self._spin_field(
            tuning, 1, "单项目最大 AI 执行次数", self.max_batches_var, 1, 100
        )
        self._spin_field(
            tuning, 2, "自动调度器刷新间隔（秒）", self.poll_seconds_var, 1, 60
        )
        self._spin_field(
            tuning,
            3,
            "AI 停滞告警（分钟，0=关闭）",
            self.agent_stall_warn_minutes_var,
            0,
            1440,
        )
        ttk.Label(
            tuning,
            text="仅记录疑似等待模型/CLI 的状态，不会自动结束或重启 AI。",
            wraplength=680,
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(6, 0))

        approval = ttk.LabelFrame(
            tab, text="新增主机与 C 段资产准入（全局默认策略）", padding=12
        )
        approval.grid(row=5, column=0, columnspan=4, sticky="ew", pady=(14, 0))
        approval.columnconfigure(1, weight=1)
        ttk.Checkbutton(
            approval,
            text="允许同一 C 段发现的其他 IP 进入候选队列（默认关闭）",
            variable=self.allow_cidr_expansion_var,
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=3)
        ttk.Label(approval, text="新增主机默认处理").grid(
            row=1, column=0, sticky="w", pady=4
        )
        ttk.Combobox(
            approval,
            textvariable=self.new_asset_approval_var,
            values=tuple(ASSET_APPROVAL_LABELS.values()),
            state="readonly",
        ).grid(row=1, column=1, sticky="ew", padx=(16, 0), pady=4)
        self._spin_field(
            approval,
            2,
            "弹窗倒计时（秒）",
            self.new_asset_countdown_var,
            3,
            3600,
        )
        ttk.Checkbutton(
            approval,
            text="发现待确认资产时显示醒目弹窗",
            variable=self.new_asset_popup_enabled_var,
        ).grid(row=3, column=0, columnspan=2, sticky="w", pady=3)
        ttk.Checkbutton(
            approval,
            text="资产确认弹窗置顶并响铃提醒",
            variable=self.new_asset_popup_topmost_var,
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=3)
        ttk.Label(
            approval,
            text=(
                "授权范围决定能不能测试；本开关和弹窗只决定发现的新主机是否值得继续耗时。"
                "“*”不再代表自动扫描任意 C 段：目标本身自动允许，扩展主机先进入候选队列。"
                "同一已批准主机的新端口和新路径会继续自动增量处理，不反复弹窗。"
            ),
            wraplength=680,
        ).grid(row=5, column=0, columnspan=2, sticky="w", pady=(8, 0))
        workload = ttk.LabelFrame(
            tab, text="下一批 AI 执行确认（待处理资产较多时）", padding=12
        )
        workload.grid(row=7, column=0, columnspan=4, sticky="ew", pady=(14, 0))
        workload.columnconfigure(1, weight=1)
        ttk.Label(workload, text="超过阈值时默认处理").grid(
            row=0, column=0, sticky="w", pady=4
        )
        ttk.Combobox(
            workload,
            textvariable=self.workload_approval_var,
            values=tuple(WORKLOAD_APPROVAL_LABELS.values()),
            state="readonly",
        ).grid(row=0, column=1, sticky="ew", padx=(16, 0), pady=4)
        self._spin_field(
            workload, 1, "AI 执行确认倒计时（秒）", self.workload_countdown_var, 3, 3600
        )
        self._spin_field(
            workload, 2, "触发确认的待处理资产数", self.workload_agent_threshold_var, 1, 100000
        )
        ttk.Checkbutton(
            workload, text="待处理资产超过阈值时显示确认弹窗",
            variable=self.workload_popup_enabled_var,
        ).grid(row=3, column=0, columnspan=2, sticky="w", pady=3)
        ttk.Checkbutton(
            workload, text="\u5f39\u7a97\u7f6e\u9876\uff08\u59cb\u7ec8\u663e\u793a\u5728\u6700\u524d\uff09",
            variable=self.workload_popup_topmost_var,
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=3)
        ttk.Label(
            workload,
            text="该确认只控制是否启动下一批 Codex/Claude；资产发现、扫描器和报告整理继续运行。",
            wraplength=680,
        ).grid(row=5, column=0, columnspan=2, sticky="w", pady=(6, 0))

        credential = ttk.LabelFrame(
            tab, text="登录入口口令安全检测", padding=12
        )
        credential.grid(row=8, column=0, columnspan=4, sticky="ew", pady=(14, 0))
        credential.columnconfigure(1, weight=1)
        ttk.Checkbutton(
            credential,
            text="发现获准 URL 中的登录入口时创建安全检测待办",
            variable=self.credential_audit_enabled_var,
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=3)
        ttk.Checkbutton(
            credential,
            text="使用本项目参数覆盖 PassHack GUI 默认配置",
            variable=self.credential_audit_project_override_var,
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=3)
        ttk.Label(credential, text="倒计时后的默认处理").grid(
            row=2, column=0, sticky="w", pady=4
        )
        ttk.Combobox(
            credential,
            textvariable=self.credential_audit_default_action_var,
            values=tuple(CREDENTIAL_AUDIT_LABELS.values()),
            state="readonly",
        ).grid(row=2, column=1, columnspan=2, sticky="ew", padx=(16, 0), pady=4)
        self._spin_field(
            credential, 3, "确认弹窗倒计时（秒）", self.credential_audit_countdown_var, 3, 3600
        )
        ttk.Checkbutton(
            credential,
            text="发现登录入口时显示醒目弹窗",
            variable=self.credential_audit_popup_enabled_var,
        ).grid(row=4, column=0, columnspan=3, sticky="w", pady=3)
        ttk.Checkbutton(
            credential,
            text="登录入口确认弹窗置顶并响铃提醒",
            variable=self.credential_audit_popup_topmost_var,
        ).grid(row=5, column=0, columnspan=3, sticky="w", pady=3)
        ttk.Label(credential, text="基础字典路径（可选）").grid(
            row=6, column=0, sticky="w", pady=4
        )
        ttk.Entry(credential, textvariable=self.credential_audit_wordlist_var).grid(
            row=6, column=1, sticky="ew", padx=(16, 8), pady=4
        )
        ttk.Button(
            credential, text="浏览...", command=self._browse_credential_wordlist
        ).grid(row=6, column=2, pady=4)
        self._spin_field(
            credential, 7, "每账号最大尝试数", self.credential_audit_max_attempts_var, 1, 1000
        )
        self._spin_field(
            credential, 8, "每分钟最大请求数", self.credential_audit_requests_per_minute_var, 1, 600
        )
        self._spin_field(
            credential, 9, "并发数", self.credential_audit_concurrency_var, 1, 20
        )
        ttk.Checkbutton(
            credential,
            text="遇到验证码、HTTP 429 或账号锁定提示立即停止",
            variable=self.credential_audit_stop_on_defense_var,
        ).grid(row=10, column=0, columnspan=3, sticky="w", pady=3)
        ttk.Label(
            credential,
            text=(
                "默认读取 PassHack GUI 保存的 STTool 默认配置；勾选项目覆盖后，才使用本页字典、尝试数和速率。"
                "新配置从后台处理下一条登录入口开始生效，不会中断正在发送的一次请求。"
            ),
            wraplength=680,
        ).grid(row=11, column=0, columnspan=3, sticky="w", pady=(8, 0))

        scan = ttk.LabelFrame(tab, text="扫描工具参数（按工作模式预设）", padding=12)
        scan.grid(row=12, column=0, columnspan=4, sticky="ew", pady=(14, 0))
        scan.columnconfigure(1, weight=1)
        ttk.Checkbutton(
            scan,
            text="fscan 跳过 POC 检测（降低侵入性）",
            variable=self.fscan_skip_poc_var,
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=3)
        ttk.Checkbutton(
            scan,
            text="fscan 跳过口令爆破（降低侵入性）",
            variable=self.fscan_skip_brute_var,
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=3)
        self._spin_field(
            scan, 2, "fscan 端口并发数", self.fscan_port_threads_var, 1, 2000
        )
        self._spin_field(scan, 3, "路径发现线程数", self.semantic_threads_var, 1, 200)
        self._spin_field(
            scan, 4, "路径发现最大深度", self.semantic_max_depth_var, 0, 10
        )
        ttk.Checkbutton(
            scan,
            text="路径发现同时运行 dirsearch 扫描",
            variable=self.semantic_run_dirsearch_var,
        ).grid(row=5, column=0, columnspan=2, sticky="w", pady=3)
        self._spin_field(
            scan,
            6,
            "路径发现最大请求速率（每秒，0=不限速）",
            self.semantic_max_rate_var,
            0,
            10000,
        )
        ttk.Label(
            scan,
            text=(
                "balanced/fast 默认降低并发与扫描深度；deep 模式允许 POC、"
                "口令检测及更深的路径发现。请按授权范围选择。"
            ),
            wraplength=680,
        ).grid(row=7, column=0, columnspan=2, sticky="w", pady=(8, 0))

    @staticmethod
    def _field(
        parent: ttk.Frame, row: int, label: str, variable: tk.StringVar
    ) -> ttk.Entry:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=(0, 5))
        entry = ttk.Entry(parent, textvariable=variable, width=62)
        entry.grid(row=row + 1, column=0, sticky="ew", pady=(0, 14))
        return entry

    @staticmethod
    def _spin_field(
        parent: ttk.Frame,
        row: int,
        label: str,
        variable: tk.IntVar,
        minimum: int,
        maximum: int,
    ) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=4)
        ttk.Spinbox(
            parent,
            from_=minimum,
            to=maximum,
            textvariable=variable,
            width=10,
        ).grid(row=row, column=1, sticky="w", padx=(16, 0), pady=4)

    def _mode_changed(self, _event: object = None) -> None:
        reverse = {label: mode for mode, label in WORK_MODE_LABELS.items()}
        mode = reverse.get(self.work_mode_var.get(), "balanced")
        if mode == "custom":
            return
        preset = work_mode_defaults(mode)
        self.auto_agent_var.set(bool(preset["auto_agent"]))
        self.wait_asset_var.set(bool(preset["wait_for_asset_commander"]))
        self.wait_fscan_var.set(bool(preset["wait_for_fscan"]))
        self.ai_summary_var.set(bool(preset["ai_summary_enabled"]))
        self.settle_seconds_var.set(int(preset["asset_settle_seconds"]))
        self.max_batches_var.set(int(preset["max_agent_batches"]))
        self.poll_seconds_var.set(int(preset["coordinator_poll_seconds"]))
        self.agent_stall_warn_minutes_var.set(
            int(preset["agent_stall_warn_minutes"])
        )
        self.fscan_skip_poc_var.set(bool(preset["fscan_skip_poc"]))
        self.fscan_skip_brute_var.set(bool(preset["fscan_skip_brute"]))
        self.fscan_port_threads_var.set(int(preset["fscan_port_threads"]))
        self.semantic_threads_var.set(int(preset["semantic_threads"]))
        self.semantic_max_depth_var.set(int(preset["semantic_max_depth"]))
        self.semantic_run_dirsearch_var.set(bool(preset["semantic_run_dirsearch"]))
        self.semantic_max_rate_var.set(int(preset["semantic_max_rate"]))
        self.allow_cidr_expansion_var.set(bool(preset["allow_cidr_expansion"]))
        self.new_asset_approval_var.set(
            ASSET_APPROVAL_LABELS[str(preset["new_asset_approval_mode"])]
        )
        self.new_asset_countdown_var.set(
            int(preset["new_asset_countdown_seconds"])
        )
        self.new_asset_popup_enabled_var.set(
            bool(preset["new_asset_popup_enabled"])
        )
        self.new_asset_popup_topmost_var.set(
            bool(preset["new_asset_popup_topmost"])
        )
        self.workload_approval_var.set(
            WORKLOAD_APPROVAL_LABELS[str(preset["workload_approval_mode"])]
        )
        self.workload_countdown_var.set(int(preset["workload_countdown_seconds"]))
        self.workload_agent_threshold_var.set(int(preset["workload_agent_threshold"]))
        self.workload_popup_enabled_var.set(bool(preset["workload_popup_enabled"]))
        self.workload_popup_topmost_var.set(bool(preset["workload_popup_topmost"]))
        self.credential_audit_enabled_var.set(bool(preset["credential_audit_enabled"]))
        self.credential_audit_project_override_var.set(
            bool(preset["credential_audit_project_override"])
        )
        self.credential_audit_default_action_var.set(
            CREDENTIAL_AUDIT_LABELS[str(preset["credential_audit_default_action"])]
        )
        self.credential_audit_countdown_var.set(
            int(preset["credential_audit_countdown_seconds"])
        )
        self.credential_audit_popup_enabled_var.set(
            bool(preset["credential_audit_popup_enabled"])
        )
        self.credential_audit_popup_topmost_var.set(
            bool(preset["credential_audit_popup_topmost"])
        )
        self.credential_audit_wordlist_var.set(
            str(preset["credential_audit_wordlist_path"])
        )
        self.credential_audit_max_attempts_var.set(
            int(preset["credential_audit_max_attempts"])
        )
        self.credential_audit_requests_per_minute_var.set(
            int(preset["credential_audit_requests_per_minute"])
        )
        self.credential_audit_concurrency_var.set(
            int(preset["credential_audit_concurrency"])
        )
        self.credential_audit_stop_on_defense_var.set(
            bool(preset["credential_audit_stop_on_defense"])
        )

    def _browse_credential_wordlist(self) -> None:
        value = filedialog.askopenfilename(parent=self, title="选择基础口令字典")
        if value:
            self.credential_audit_wordlist_var.set(value)

    @staticmethod
    def _valid_optional_url(value: str) -> bool:
        if not value:
            return True
        parsed = urlsplit(value)
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)

    def _save(self) -> None:
        api_base_url = self.api_base_url_var.get().strip().rstrip("/")
        if not self._valid_optional_url(api_base_url):
            messagebox.showerror(
                "STTool 全局设置",
                "工具协作 API Base URL 必须是有效的 HTTP/HTTPS 地址",
                parent=self,
            )
            return
        codex_base_url = self.codex_agent_base_url_var.get().strip().rstrip("/")
        claude_base_url = self.claude_agent_base_url_var.get().strip().rstrip("/")
        if not self._valid_optional_url(codex_base_url):
            messagebox.showerror(
                "STTool 全局设置",
                "Codex/Codexx Base URL 必须留空或填写有效的 HTTP/HTTPS 地址",
                parent=self,
            )
            return
        if not self._valid_optional_url(claude_base_url):
            messagebox.showerror(
                "STTool 全局设置",
                "Claude Base URL 必须留空或填写有效的 HTTP/HTTPS 地址",
                parent=self,
            )
            return
        model = self.model_var.get().strip()
        if not model:
            messagebox.showerror("STTool 全局设置", "工具协作模型不能为空", parent=self)
            return
        network_reverse = {
            label: mode for mode, label in TOOL_NETWORK_MODE_LABELS.items()
        }
        tool_network = normalize_tool_network(
            {
                "mode": network_reverse.get(
                    self.tool_network_mode_var.get(), "direct"
                ),
                "host": self.tool_proxy_host_var.get(),
                "port": self.tool_proxy_port_var.get(),
                "header_name": self.tool_header_name_var.get(),
                "header_value": self.tool_header_value_var.get(),
            }
        )
        reverse = {label: mode for mode, label in WORK_MODE_LABELS.items()}
        workflow = normalize_workflow_settings(
            {
                "work_mode": reverse.get(self.work_mode_var.get(), "balanced"),
                "tscan_backend": {
                    label: mode for mode, label in TSCAN_BACKEND_LABELS.items()
                }.get(self.tscan_backend_var.get(), "gui"),
                "tscan_auto_update": self.tscan_auto_update_var.get(),
                "auto_agent": self.auto_agent_var.get(),
                "wait_for_asset_commander": self.wait_asset_var.get(),
                "wait_for_fscan": self.wait_fscan_var.get(),
                "ai_summary_enabled": self.ai_summary_var.get(),
                "asset_settle_seconds": self.settle_seconds_var.get(),
                "max_agent_batches": self.max_batches_var.get(),
                "coordinator_poll_seconds": self.poll_seconds_var.get(),
                "agent_stall_warn_minutes": self.agent_stall_warn_minutes_var.get(),
                "fscan_skip_poc": self.fscan_skip_poc_var.get(),
                "fscan_skip_brute": self.fscan_skip_brute_var.get(),
                "fscan_port_threads": self.fscan_port_threads_var.get(),
                "semantic_threads": self.semantic_threads_var.get(),
                "semantic_max_depth": self.semantic_max_depth_var.get(),
                "semantic_run_dirsearch": self.semantic_run_dirsearch_var.get(),
                "semantic_max_rate": self.semantic_max_rate_var.get(),
                "allow_cidr_expansion": self.allow_cidr_expansion_var.get(),
                "new_asset_approval_mode": {
                    label: mode for mode, label in ASSET_APPROVAL_LABELS.items()
                }.get(self.new_asset_approval_var.get(), "countdown_accept"),
                "new_asset_countdown_seconds": self.new_asset_countdown_var.get(),
                "new_asset_popup_enabled": self.new_asset_popup_enabled_var.get(),
                "new_asset_popup_topmost": self.new_asset_popup_topmost_var.get(),
                "workload_approval_mode": {
                    label: mode for mode, label in WORKLOAD_APPROVAL_LABELS.items()
                }.get(self.workload_approval_var.get(), "countdown_accept"),
                "workload_countdown_seconds": self.workload_countdown_var.get(),
                "workload_agent_threshold": self.workload_agent_threshold_var.get(),
                "workload_popup_enabled": self.workload_popup_enabled_var.get(),
                "workload_popup_topmost": self.workload_popup_topmost_var.get(),
                "credential_audit_enabled": self.credential_audit_enabled_var.get(),
                "credential_audit_project_override": (
                    self.credential_audit_project_override_var.get()
                ),
                "credential_audit_default_action": {
                    label: action for action, label in CREDENTIAL_AUDIT_LABELS.items()
                }.get(self.credential_audit_default_action_var.get(), "save_only"),
                "credential_audit_countdown_seconds": self.credential_audit_countdown_var.get(),
                "credential_audit_popup_enabled": self.credential_audit_popup_enabled_var.get(),
                "credential_audit_popup_topmost": self.credential_audit_popup_topmost_var.get(),
                "credential_audit_wordlist_path": self.credential_audit_wordlist_var.get(),
                "credential_audit_max_attempts": self.credential_audit_max_attempts_var.get(),
                "credential_audit_requests_per_minute": self.credential_audit_requests_per_minute_var.get(),
                "credential_audit_concurrency": self.credential_audit_concurrency_var.get(),
                "credential_audit_stop_on_defense": self.credential_audit_stop_on_defense_var.get(),
            }
        )
        codex_effort = self.codex_reasoning_effort_var.get()
        claude_effort = self.claude_reasoning_effort_var.get()
        self.result = {
            "api_base_url": api_base_url,
            "model": model,
            "api_key": self.api_key_var.get().strip(),
            "codex_agent_model": self.codex_agent_model_var.get().strip(),
            "codex_reasoning_effort": "" if codex_effort == "CLI 默认" else codex_effort,
            "codex_agent_base_url": codex_base_url,
            "codex_api_key": self.codex_api_key_var.get().strip(),
            "claude_agent_model": self.claude_agent_model_var.get().strip(),
            "claude_reasoning_effort": "" if claude_effort == "CLI 默认" else claude_effort,
            "claude_agent_base_url": claude_base_url,
            "claude_api_key": self.claude_api_key_var.get().strip(),
            "github_token": self.github_token_var.get().strip(),
            "workflow": workflow,
            "tool_network": tool_network,
        }
        self.destroy()
