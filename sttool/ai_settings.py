from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from urllib.parse import urlsplit

from .models import DEFAULT_API_BASE_URL
from .workflow_settings import (
    WORK_MODE_LABELS,
    normalize_workflow_settings,
    normalized_reasoning_effort,
    work_mode_defaults,
)


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
        claude_agent_model: str = "",
        claude_reasoning_effort: str = "",
        claude_agent_base_url: str = "",
        github_token: str = "",
        workflow_settings: dict[str, object] | None = None,
    ) -> None:
        super().__init__(parent)
        self.result: dict[str, object] | None = None
        self.title("STTool 全局设置")
        self.geometry("780x720")
        self.minsize(720, 660)
        self.transient(parent)
        self.protocol("WM_DELETE_WINDOW", self.destroy)

        workflow = normalize_workflow_settings(workflow_settings)
        self.api_base_url_var = tk.StringVar(value=api_base_url or DEFAULT_API_BASE_URL)
        self.model_var = tk.StringVar(value=model or "gpt-5.5")
        self.api_key_var = tk.StringVar(value=api_key)
        self.show_key_var = tk.BooleanVar(value=False)
        self.codex_agent_model_var = tk.StringVar(value=codex_agent_model)
        self.codex_reasoning_effort_var = tk.StringVar(
            value=normalized_reasoning_effort(codex_reasoning_effort) or "CLI 默认"
        )
        self.codex_agent_base_url_var = tk.StringVar(value=codex_agent_base_url)
        self.claude_agent_model_var = tk.StringVar(value=claude_agent_model)
        self.claude_reasoning_effort_var = tk.StringVar(
            value=normalized_reasoning_effort(claude_reasoning_effort) or "CLI 默认"
        )
        self.claude_agent_base_url_var = tk.StringVar(value=claude_agent_base_url)
        self.github_token_var = tk.StringVar(value=github_token)
        self.show_github_token_var = tk.BooleanVar(value=False)
        self.work_mode_var = tk.StringVar(
            value=WORK_MODE_LABELS[str(workflow["work_mode"])]
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

        content = ttk.Frame(self, padding=16)
        content.pack(fill="both", expand=True)
        notebook = ttk.Notebook(content)
        notebook.pack(fill="both", expand=True)
        self._build_agent_tab(notebook, "codex")
        self._build_agent_tab(notebook, "claude")
        self._build_shared_ai_tab(notebook)
        self._build_vulnerability_intel_tab(notebook)
        self._build_workflow_tab(notebook)

        actions = ttk.Frame(content)
        actions.pack(fill="x", pady=(14, 0))
        ttk.Button(actions, text="取消", command=self.destroy).pack(side="right")
        ttk.Button(actions, text="保存全局设置", command=self._save).pack(
            side="right", padx=(0, 8)
        )

        self.bind("<Escape>", lambda _event: self.destroy())
        self.update_idletasks()
        x = parent.winfo_rootx() + max(
            20, (parent.winfo_width() - self.winfo_width()) // 2
        )
        y = parent.winfo_rooty() + max(
            20, (parent.winfo_height() - self.winfo_height()) // 3
        )
        self.geometry(f"+{x}+{y}")
        self.grab_set()

    def _build_agent_tab(self, notebook: ttk.Notebook, provider: str) -> None:
        is_claude = provider == "claude"
        tab = ttk.Frame(notebook, padding=18)
        tab.columnconfigure(0, weight=1)
        notebook.add(tab, text="Claude Agent" if is_claude else "Codex / Codexx")
        if is_claude:
            description = (
                "只控制项目中选择 Claude CLI 时的模型、推理强度与可选 Base URL。"
                "凭据仍使用 Claude CLI 自己的登录或环境配置，不写入项目文件。"
            )
            model_var = self.claude_agent_model_var
            effort_var = self.claude_reasoning_effort_var
            base_url_var = self.claude_agent_base_url_var
            models = ("", "sonnet", "opus", "haiku")
            url_label = "Anthropic API Base URL（可选，留空使用 CLI 配置）"
            efforts = ("CLI 默认", "low", "medium", "high")
        else:
            description = (
                "只控制项目中选择 Codex 或 Codexx CLI 时的模型、推理强度与可选 Base URL。"
                "凭据和模型线路仍可继续由 CLI 自身配置；留空不会覆盖。"
            )
            model_var = self.codex_agent_model_var
            effort_var = self.codex_reasoning_effort_var
            base_url_var = self.codex_agent_base_url_var
            models = ("", "gpt-5.5", "gpt-5.6-sol")
            url_label = "OpenAI 兼容 API Base URL（可选，留空使用 CLI 配置）"
            efforts = ("CLI 默认", "low", "medium", "high", "xhigh")
        ttk.Label(tab, text=description, wraplength=660).grid(
            row=0, column=0, sticky="w", pady=(0, 18)
        )
        ttk.Label(tab, text="Agent 模型（可编辑，留空使用 CLI 默认）").grid(
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

    def _build_shared_ai_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=18)
        tab.columnconfigure(0, weight=1)
        notebook.add(tab, text="工具协作 AI")
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
        tab = ttk.Frame(notebook, padding=18)
        tab.columnconfigure(0, weight=1)
        notebook.add(tab, text="漏洞情报")
        ttk.Label(
            tab,
            text=(
                "find-gh-poc 使用 GitHub GraphQL API，建议配置个人访问 Token。Token 仅通过"
                "协调器进程环境和一次性临时文件传递，不进入项目、日志或命令行。"
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

    def _build_workflow_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=18)
        tab.columnconfigure(1, weight=1)
        notebook.add(tab, text="调度方式")
        ttk.Label(
            tab,
            text=(
                "预设会调整 Agent 的启动时机和增量节奏；下列细项会真正传给项目协调器。"
                "平衡模式默认等待 AssetCommander 与 fscan 完成后再启动 Agent。"
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

        checks = ttk.LabelFrame(tab, text="启动条件", padding=12)
        checks.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 14))
        ttk.Checkbutton(
            checks, text="自动启动增量 Agent", variable=self.auto_agent_var
        ).grid(row=0, column=0, sticky="w", pady=3)
        ttk.Checkbutton(
            checks,
            text="等待 AssetCommander 完整结束（不只等待提前资产移交）",
            variable=self.wait_asset_var,
        ).grid(row=1, column=0, sticky="w", pady=3)
        ttk.Checkbutton(
            checks,
            text="等待 fscan 完整输出后再启动 Agent",
            variable=self.wait_fscan_var,
        ).grid(row=2, column=0, sticky="w", pady=3)
        ttk.Checkbutton(
            checks,
            text="使用工具协作 AI 优化阶段性风险摘要",
            variable=self.ai_summary_var,
        ).grid(row=3, column=0, sticky="w", pady=3)

        tuning = ttk.LabelFrame(tab, text="增量调度参数", padding=12)
        tuning.grid(row=3, column=0, columnspan=2, sticky="ew")
        tuning.columnconfigure(1, weight=1)
        self._spin_field(
            tuning, 0, "资产稳定等待（秒）", self.settle_seconds_var, 1, 600
        )
        self._spin_field(
            tuning, 1, "单项目最大 Agent 批次数", self.max_batches_var, 1, 100
        )
        self._spin_field(
            tuning, 2, "协调器刷新间隔（秒）", self.poll_seconds_var, 1, 60
        )

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
        reverse = {label: mode for mode, label in WORK_MODE_LABELS.items()}
        workflow = normalize_workflow_settings(
            {
                "work_mode": reverse.get(self.work_mode_var.get(), "balanced"),
                "auto_agent": self.auto_agent_var.get(),
                "wait_for_asset_commander": self.wait_asset_var.get(),
                "wait_for_fscan": self.wait_fscan_var.get(),
                "ai_summary_enabled": self.ai_summary_var.get(),
                "asset_settle_seconds": self.settle_seconds_var.get(),
                "max_agent_batches": self.max_batches_var.get(),
                "coordinator_poll_seconds": self.poll_seconds_var.get(),
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
            "claude_agent_model": self.claude_agent_model_var.get().strip(),
            "claude_reasoning_effort": "" if claude_effort == "CLI 默认" else claude_effort,
            "claude_agent_base_url": claude_base_url,
            "github_token": self.github_token_var.get().strip(),
            "workflow": workflow,
        }
        self.destroy()
