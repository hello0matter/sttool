from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .models import ToolDefinition


class ToolEditorDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc, tool: ToolDefinition | None = None) -> None:
        super().__init__(parent)
        self.result: dict[str, object] | None = None
        self.title("编辑自定义工具" if tool else "添加自定义工具")
        self.geometry("720x760")
        self.minsize(620, 680)
        self.transient(parent)
        self.grab_set()

        self.name_var = tk.StringVar(value=tool.name if tool else "")
        self.category_var = tk.StringVar(value=tool.category if tool else "自定义")
        self.description_var = tk.StringVar(value=tool.description if tool else "")
        self.executable_var = tk.StringVar(value=tool.executable if tool else "")
        self.cwd_var = tk.StringVar(value=tool.cwd if tool else "{run_dir}")
        self.default_selected_var = tk.BooleanVar(value=tool.default_selected if tool else False)
        self.sends_requests_var = tk.BooleanVar(value=tool.sends_requests if tool else True)
        self.new_console_var = tk.BooleanVar(value=tool.new_console if tool else True)
        self.restart_var = tk.BooleanVar(value=tool.restart_on_recovery if tool else False)
        self.uses_shared_ai_var = tk.BooleanVar(
            value=tool.uses_shared_ai if tool else False
        )
        self.allow_standalone_var = tk.BooleanVar(
            value=tool.allow_standalone if tool else False
        )

        container = ttk.Frame(self, padding=18)
        container.pack(fill="both", expand=True)
        container.columnconfigure(0, weight=1)
        container.rowconfigure(11, weight=1)
        container.rowconfigure(13, weight=1)

        self._entry(container, 0, "名称", self.name_var)
        self._entry(container, 2, "类别", self.category_var)
        self._entry(container, 4, "说明", self.description_var)

        ttk.Label(container, text="入口程序").grid(row=6, column=0, sticky="w", pady=(0, 5))
        executable_row = ttk.Frame(container)
        executable_row.grid(row=7, column=0, sticky="ew", pady=(0, 12))
        executable_row.columnconfigure(0, weight=1)
        ttk.Entry(executable_row, textvariable=self.executable_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(executable_row, text="浏览", command=self._browse_executable).grid(row=0, column=1, padx=(8, 0))

        self._entry(container, 8, "工作目录", self.cwd_var)
        ttk.Label(container, text="参数（每行一项）").grid(row=10, column=0, sticky="w", pady=(0, 5))
        self.args_text = tk.Text(container, height=6, wrap="none", font=("Consolas", 10))
        self.args_text.grid(row=11, column=0, sticky="nsew", pady=(0, 12))
        if tool:
            self.args_text.insert("1.0", "\n".join(tool.args))

        ttk.Label(container, text="结果位置（每行一项，支持运行目录占位符）").grid(
            row=12, column=0, sticky="w", pady=(0, 5)
        )
        self.results_text = tk.Text(
            container, height=5, wrap="none", font=("Consolas", 10)
        )
        self.results_text.grid(row=13, column=0, sticky="nsew", pady=(0, 12))
        if tool:
            self.results_text.insert("1.0", "\n".join(tool.result_paths))

        flags = ttk.Frame(container)
        flags.grid(row=14, column=0, sticky="ew", pady=(0, 14))
        for index, (text, variable) in enumerate(
            (
                ("默认勾选", self.default_selected_var),
                ("会发送网络请求", self.sends_requests_var),
                ("独立控制台", self.new_console_var),
                ("恢复时重启", self.restart_var),
                ("使用工具协作 AI", self.uses_shared_ai_var),
                ("允许单独执行", self.allow_standalone_var),
            )
        ):
            ttk.Checkbutton(flags, text=text, variable=variable).grid(
                row=index // 3,
                column=index % 3,
                sticky="w",
                padx=(0, 18),
                pady=(0, 6),
            )

        actions = ttk.Frame(container)
        actions.grid(row=15, column=0, sticky="e")
        ttk.Button(actions, text="取消", command=self.destroy).pack(side="right")
        ttk.Button(actions, text="保存", command=self._save).pack(side="right", padx=(0, 8))

        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.wait_visibility()
        self.focus_set()

    @staticmethod
    def _entry(parent: ttk.Frame, row: int, label: str, variable: tk.StringVar) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=(0, 5))
        ttk.Entry(parent, textvariable=variable).grid(row=row + 1, column=0, sticky="ew", pady=(0, 12))

    def _browse_executable(self) -> None:
        value = filedialog.askopenfilename(
            parent=self,
            title="选择工具入口程序",
            filetypes=(("可执行文件", "*.exe"), ("所有文件", "*.*")),
        )
        if value:
            self.executable_var.set(value)

    def _save(self) -> None:
        name = self.name_var.get().strip()
        executable = self.executable_var.get().strip()
        if not name or not executable:
            messagebox.showerror("无法保存", "工具名称和入口程序不能为空。", parent=self)
            return
        self.result = {
            "name": name,
            "category": self.category_var.get().strip() or "自定义",
            "description": self.description_var.get().strip(),
            "executable": executable,
            "args": tuple(
                line.strip()
                for line in self.args_text.get("1.0", "end").splitlines()
                if line.strip()
            ),
            "cwd": self.cwd_var.get().strip() or "{run_dir}",
            "default_selected": self.default_selected_var.get(),
            "sends_requests": self.sends_requests_var.get(),
            "new_console": self.new_console_var.get(),
            "restart_on_recovery": self.restart_var.get(),
            "result_paths": tuple(
                line.strip()
                for line in self.results_text.get("1.0", "end").splitlines()
                if line.strip()
            ),
            "uses_shared_ai": self.uses_shared_ai_var.get(),
            "allow_standalone": self.allow_standalone_var.get(),
        }
        self.destroy()
