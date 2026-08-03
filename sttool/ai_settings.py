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
        agent_model: str = "",
        reasoning_effort: str = "",
        workflow_settings: dict[str, object] | None = None,
    ) -> None:
        super().__init__(parent)
        self.result: dict[str, object] | None = None
        self.title("STTool 全局设置")
        self.geometry("720x660")
        self.minsize(680, 620)
        self.transient(parent)
        self.protocol("WM_DELETE_WINDOW", self.destroy)

        workflow = normalize_workflow_settings(workflow_settings)
        self.api_base_url_var = tk.StringVar(value=api_base_url or DEFAULT_API_BASE_URL)
        self.model_var = tk.StringVar(value=model or "gpt-5.5")
        self.api_key_var = tk.StringVar(value=api_key)
        self.show_key_var = tk.BooleanVar(value=False)
        self.agent_model_var = tk.StringVar(value=agent_model)
        self.reasoning_effort_var = tk.StringVar(
            value=normalized_reasoning_effort(reasoning_effort) or "CLI 默认"
        )
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
        self._build_agent_tab(notebook)
        self._build_shared_ai_tab(notebook)
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

    def _build_agent_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=18)
        tab.columnconfigure(0, weight=1)
        notebook.add(tab, text="本地 Agent")
        ttk.Label(
            tab,
            text=(
                "控制项目中启动的 Codex/Codexx/Claude CLI。留空或选择“CLI 默认”时，"
                "不会追加模型、API URL、API Key 或推理强度参数，继续使用 CLI 自己的配置。"
            ),
            wraplength=620,
        ).grid(row=0, column=0, sticky="w", pady=(0, 18))
        ttk.Label(tab, text="Agent 模型（可编辑，留空使用 CLI 默认）").grid(
            row=1, column=0, sticky="w", pady=(0, 5)
        )
        ttk.Combobox(
            tab,
            textvariable=self.agent_model_var,
            values=("", "gpt-5.5", "gpt-5.6-sol"),
        ).grid(row=2, column=0, sticky="ew", pady=(0, 16))
        ttk.Label(tab, text="推理强度").grid(row=3, column=0, sticky="w", pady=(0, 5))
        ttk.Combobox(
            tab,
            textvariable=self.reasoning_effort_var,
            values=("CLI 默认", "low", "medium", "high", "xhigh"),
            state="readonly",
        ).grid(row=4, column=0, sticky="ew")

    def _build_shared_ai_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=18)
        tab.columnconfigure(0, weight=1)
        notebook.add(tab, text="工具协作 AI")
        ttk.Label(
            tab,
            text=(
                "用于工具间信息汇总、传递与风险摘要优化。该配置独立于本地 "
                "Codex/Codexx/Claude；API Key 仍保存在系统加密密钥文件中。"
            ),
            wraplength=620,
        ).grid(row=0, column=0, sticky="w", pady=(0, 16))
        self.api_base_url_entry = self._field(
            tab, 1, "OpenAI 兼容 API Base URL", self.api_base_url_var
        )
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
            command=self._toggle_key,
        ).grid(row=0, column=1, padx=(8, 0))

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
            wraplength=620,
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

    def _toggle_key(self) -> None:
        self.key_entry.configure(show="" if self.show_key_var.get() else "*")

    def _save(self) -> None:
        api_base_url = self.api_base_url_var.get().strip().rstrip("/")
        parsed = urlsplit(api_base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            messagebox.showerror(
                "STTool 全局设置",
                "API Base URL 必须是有效的 HTTP/HTTPS 地址",
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
        effort = self.reasoning_effort_var.get()
        self.result = {
            "api_base_url": api_base_url,
            "model": model,
            "api_key": self.api_key_var.get().strip(),
            "agent_model": self.agent_model_var.get().strip(),
            "reasoning_effort": "" if effort == "CLI 默认" else effort,
            "workflow": workflow,
        }
        self.destroy()
