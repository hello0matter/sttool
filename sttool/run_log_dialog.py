from __future__ import annotations

import json
import os
import re
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk

from .activity import activity_log_path
from .models import RunState


def load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def tail_text(path: Path, limit: int = 160_000) -> str:
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - limit))
            data = handle.read()
    except OSError as exc:
        return f"读取失败：{exc}"
    return data.decode("utf-8", errors="replace")


def filter_component_activity(
    content: str, component_id: str, component_name: str = ""
) -> str:
    aliases = {
        "asset_commander": ("AssetCommander",),
        "semantic_dirscan": ("AI 路径发现", "semantic"),
        "fscan": ("fscan",),
        "nuclei": ("nuclei",),
        "tscan_plus": ("TscanPlus",),
        "ai_agent": ("本地 Agent", "Codex Agent", "Codexx", "Codex"),
    }.get(component_id, ())
    candidates = [component_id, component_name, *aliases]
    normalized = [candidate.casefold() for candidate in candidates if candidate.strip()]
    owners = (
        ("tscan_plus", ("tscanplus",)),
        ("asset_commander", ("assetcommander",)),
        ("semantic_dirscan", ("ai 路径发现", "semantic")),
        ("nuclei", ("nuclei",)),
        ("fscan", ("fscan",)),
        ("ai_agent", ("本地 agent", "codex agent", "codexx", "codex")),
    )
    selected: list[str] = []
    for line in content.splitlines():
        folded = line.casefold()
        owner = next(
            (
                owner_id
                for owner_id, owner_aliases in owners
                if any(alias in folded for alias in owner_aliases)
            ),
            "",
        )
        if owner:
            if owner == component_id:
                selected.append(line)
            continue
        if any(alias in folded for alias in normalized):
            selected.append(line)
    return "\n".join(selected)


def component_activity_log_path(run_dir: Path, component_id: str) -> Path:
    safe_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", component_id).strip("._")
    return run_dir / "component_logs" / f"{safe_id or 'component'}.log"


def refresh_component_activity_log(
    run_dir: Path, component_id: str, component_name: str = ""
) -> Path:
    destination = component_activity_log_path(run_dir, component_id)
    source = activity_log_path(run_dir)
    try:
        content = source.read_text(encoding="utf-8")
    except OSError:
        content = ""
    filtered = filter_component_activity(content, component_id, component_name)
    destination.parent.mkdir(parents=True, exist_ok=True)
    rendered = filtered + ("\n" if filtered else "")
    try:
        existing = destination.read_text(encoding="utf-8")
    except OSError:
        existing = ""
    if rendered != existing:
        destination.write_text(rendered, encoding="utf-8")
    return destination


def component_paths(
    run_dir: Path, component_id: str, component_name: str = ""
) -> dict[str, list[Path] | Path]:
    component_activity = refresh_component_activity_log(
        run_dir, component_id, component_name
    )
    if component_id == "asset_commander":
        workdir = run_dir / "tool_data" / "asset_commander"
        return {
            "workdir": workdir,
            "states": [workdir / "workflow_state.json"],
            "logs": [
                *workdir.glob("workspace/**/runtime.log"),
                *workdir.glob("workspace/**/fail_samples.log"),
                workdir / "AssetCommander-crash.log",
            ],
            "results": [run_dir / "results" / "asset_commander_assets.json"],
        }
    if component_id == "semantic_dirscan":
        workdir = run_dir / "tool_data" / "semantic"
        return {
            "workdir": workdir,
            "states": [
                workdir / "sttool_bridge_state.json",
                workdir / "launcher_state.json",
                *workdir.glob("projects/**/runtime_state.json"),
            ],
            "logs": [*workdir.glob("projects/**/gui.log")],
            "results": [workdir / "projects", workdir / "reports"],
        }
    if component_id == "tscan_plus":
        workdir = run_dir / "tool_data" / "tscan"
        own_log = workdir / "activity.log"
        return {
            "workdir": workdir,
            "states": [workdir / "state.json"],
            "logs": [own_log if own_log.is_file() else component_activity],
            "results": [workdir / "state.json"],
        }
    if component_id == "fscan":
        result = run_dir / "results" / "fscan.txt"
        return {
            "workdir": run_dir,
            "states": [],
            "logs": [result, component_activity],
            "results": [result],
        }
    if component_id == "nuclei":
        result = run_dir / "results" / "nuclei.txt"
        return {
            "workdir": run_dir,
            "states": [],
            "logs": [result, component_activity],
            "results": [result],
        }
    return {
        "workdir": run_dir,
        "states": [],
        "logs": [component_activity],
        "results": [run_dir / "results"],
    }


def component_runtime(run_dir: Path, component_id: str) -> tuple[str, str, str]:
    if component_id == "asset_commander":
        state = load_json(
            run_dir / "tool_data" / "asset_commander" / "workflow_state.json"
        )
        status = str(state.get("status") or "")
        stage = str(state.get("current_step") or "")
        detail = ""
        if status == "completed":
            detail = "资产工作流已完成；AssetCommander 窗口仍保留，可继续手动操作"
        steps = state.get("steps")
        if stage and isinstance(steps, dict):
            step = steps.get(stage)
            if isinstance(step, dict):
                detail = str(step.get("detail") or step.get("status") or "")
        return status, stage, detail
    if component_id == "tscan_plus":
        state = load_json(run_dir / "tool_data" / "tscan" / "state.json")
        return (
            str(state.get("status") or ""),
            str(state.get("stage") or ""),
            str(state.get("detail") or state.get("error") or ""),
        )
    if component_id == "semantic_dirscan":
        state = load_json(
            run_dir / "tool_data" / "semantic" / "sttool_bridge_state.json"
        )
        asset_status = str(state.get("asset_workflow_status") or "")
        queued = state.get("queued_asset_targets")
        queued_count = len(queued) if isinstance(queued, list) else 0
        error = str(state.get("last_error") or "")
        if error:
            return "failed", "asset_handoff", error
        if asset_status and asset_status != "completed":
            return "waiting_assets", "waiting_asset_commander", (
                f"等待 AssetCommander，暂存 {queued_count} 个目标"
            )
        targets = state.get("targets")
        target_count = len(targets) if isinstance(targets, list) else 0
        return "running", "directory_scan", f"已同步 {target_count} 个扫描目标"
    if component_id in {"fscan", "nuclei"}:
        result = run_dir / "results" / f"{component_id}.txt"
        if result.is_file():
            return "completed", "result_saved", f"结果已保存：{result.name}"
    return "", "", ""


def component_display_runtime(
    run_dir: Path, component_id: str
) -> tuple[str, str, str]:
    tool_status, stage, detail = component_runtime(run_dir, component_id)
    run_state = load_json(run_dir / "run.json")
    processes = run_state.get("processes")
    if not isinstance(processes, list):
        return tool_status, stage, detail
    for process in processes:
        if not isinstance(process, dict) or process.get("component_id") != component_id:
            continue
        process_status = str(process.get("status") or "")
        if process_status not in {"stopped", "exited"}:
            return tool_status, stage, detail
        last_state = tool_status or "unknown"
        stopped_detail = f"组件进程已{process_status}；工作流最后状态：{last_state}"
        if stage:
            stopped_detail += f"，最后步骤：{stage}"
        if detail:
            stopped_detail += f"，{detail}"
        return process_status, "process_stopped", stopped_detail
    return tool_status, stage, detail


class ComponentLogDialog(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Misc,
        run_dir: Path,
        component_id: str,
        component_name: str,
    ) -> None:
        super().__init__(parent)
        self.run_dir = run_dir
        self.component_id = component_id
        self.component_name = component_name
        self.sources = component_paths(run_dir, component_id, component_name)
        self._after_id: str | None = None
        self._last_content = ""

        self.title(f"组件日志 - {component_name}")
        self.geometry("1180x760")
        self.minsize(900, 580)
        self.transient(parent)

        container = ttk.Frame(self, padding=14)
        container.pack(fill="both", expand=True)
        container.columnconfigure(0, weight=1)
        container.rowconfigure(2, weight=1)

        self.summary_var = tk.StringVar()
        ttk.Label(
            container,
            textvariable=self.summary_var,
            font=("Microsoft YaHei UI", 11, "bold"),
        ).grid(row=0, column=0, sticky="w", pady=(0, 8))
        ttk.Label(
            container,
            text="状态文件、组件日志和结果预览会自动刷新。",
        ).grid(row=1, column=0, sticky="w", pady=(0, 8))

        self.text = scrolledtext.ScrolledText(
            container,
            wrap="none",
            font=("Consolas", 10),
            state="disabled",
        )
        self.text.grid(row=2, column=0, sticky="nsew")

        actions = ttk.Frame(container)
        actions.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        ttk.Button(actions, text="打开工作目录", command=self._open_workdir).pack(
            side="left"
        )
        ttk.Button(actions, text="打开日志文件", command=self._open_log).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(actions, text="打开结果", command=self._open_result).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(actions, text="关闭", command=self._close).pack(side="right")

        self.protocol("WM_DELETE_WINDOW", self._close)
        self._refresh()

    def _existing(self, key: str) -> list[Path]:
        values = self.sources.get(key, [])
        if not isinstance(values, list):
            return []
        return [path for path in values if path.exists()]

    def _content(self) -> str:
        refresh_component_activity_log(
            self.run_dir, self.component_id, self.component_name
        )
        sections: list[str] = []
        for path in self._existing("states"):
            sections.append(
                f"===== 状态：{path} =====\n"
                + json.dumps(load_json(path), ensure_ascii=False, indent=2)
            )
        for path in self._existing("logs")[-8:]:
            if path.is_file():
                content = tail_text(path)
                sections.append(f"===== 日志：{path} =====\n{content}")
        if not sections:
            sections.append("该组件的状态或日志文件尚未生成。")
        return "\n\n".join(sections)

    def _refresh(self) -> None:
        if not self.winfo_exists():
            return
        status, stage, detail = component_display_runtime(
            self.run_dir, self.component_id
        )
        summary = f"{self.component_name}  |  {status or '等待状态文件'}"
        if stage:
            summary += f"  |  {stage}"
        if detail:
            summary += f"  |  {detail}"
        self.summary_var.set(summary)
        content = self._content()
        if content != self._last_content:
            follow = self.text.yview()[1] >= 0.98
            self.text.configure(state="normal")
            self.text.delete("1.0", "end")
            self.text.insert("1.0", content)
            self.text.configure(state="disabled")
            if follow:
                self.text.see("end")
            self._last_content = content
        self._after_id = self.after(1000, self._refresh)

    def _open_workdir(self) -> None:
        workdir = self.sources.get("workdir", self.run_dir)
        if isinstance(workdir, Path) and workdir.exists():
            os.startfile(workdir)

    def _open_log(self) -> None:
        logs = [path for path in self._existing("logs") if path.is_file()]
        if not logs:
            messagebox.showinfo("组件日志", "日志文件尚未生成。", parent=self)
            return
        os.startfile(logs[-1])

    def _open_result(self) -> None:
        results = self._existing("results")
        if not results:
            messagebox.showinfo("组件日志", "结果尚未生成。", parent=self)
            return
        os.startfile(results[0])

    def _close(self) -> None:
        if self._after_id is not None:
            self.after_cancel(self._after_id)
        self.destroy()


class RunLogDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc, state: RunState) -> None:
        super().__init__(parent)
        self.run_dir = Path(state.run_dir)
        self.state_path = self.run_dir / "run.json"
        self._after_id: str | None = None
        self._last_log = ""

        self.title(f"项目日志 - {state.project_name} / {state.run_id}")
        self.geometry("1360x840")
        self.minsize(1050, 650)
        self.transient(parent)

        container = ttk.Frame(self, padding=16)
        container.pack(fill="both", expand=True)
        container.columnconfigure(0, weight=1)
        container.rowconfigure(1, weight=2)
        container.rowconfigure(4, weight=3)

        self.summary_var = tk.StringVar()
        ttk.Label(
            container,
            textvariable=self.summary_var,
            font=("Microsoft YaHei UI", 11, "bold"),
        ).grid(row=0, column=0, sticky="w", pady=(0, 10))

        tree_frame = ttk.Frame(container)
        tree_frame.grid(row=1, column=0, sticky="nsew", pady=(0, 12))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        columns = ("component", "status", "stage", "detail", "pid", "started")
        self.process_tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            height=10,
        )
        for column, label, width in (
            ("component", "组件", 180),
            ("status", "状态", 110),
            ("stage", "当前步骤", 190),
            ("detail", "状态详情（双击查看独立日志）", 500),
            ("pid", "PID", 85),
            ("started", "启动时间", 170),
        ):
            self.process_tree.heading(column, text=label)
            self.process_tree.column(column, width=width, minwidth=70)
        self.process_tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll = ttk.Scrollbar(
            tree_frame, orient="vertical", command=self.process_tree.yview
        )
        tree_scroll.grid(row=0, column=1, sticky="ns")
        self.process_tree.configure(yscrollcommand=tree_scroll.set)
        self.process_tree.bind("<Double-1>", self._open_component_log)
        self.process_tree.bind("<Return>", self._open_component_log)

        self.tool_activity_var = tk.StringVar()
        ttk.Label(
            container,
            textvariable=self.tool_activity_var,
            wraplength=1280,
            justify="left",
        ).grid(row=2, column=0, sticky="ew", pady=(0, 12))

        log_header = ttk.Frame(container)
        log_header.grid(row=3, column=0, sticky="ew", pady=(0, 6))
        ttk.Label(log_header, text="项目活动日志").pack(side="left")
        self.follow_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            log_header,
            text="跟随最新",
            variable=self.follow_var,
        ).pack(side="right")

        self.log_text = scrolledtext.ScrolledText(
            container,
            wrap="word",
            font=("Consolas", 10),
            state="disabled",
        )
        self.log_text.grid(row=4, column=0, sticky="nsew")

        actions = ttk.Frame(container)
        actions.grid(row=5, column=0, sticky="ew", pady=(12, 0))
        ttk.Button(actions, text="打开运行目录", command=self._open_run_dir).pack(
            side="left"
        )
        ttk.Button(actions, text="打开日志文件", command=self._open_log_file).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(actions, text="关闭", command=self._close).pack(side="right")

        self.protocol("WM_DELETE_WINDOW", self._close)
        self._refresh()

    @staticmethod
    def _status_text(status: str) -> str:
        return {
            "starting": "启动中",
            "running": "运行中",
            "waiting_assets": "等待资产",
            "manual_required": "需手动处理",
            "completed": "已完成",
            "failed": "失败",
            "stopped": "已停止",
            "exited": "已退出",
        }.get(status, status)

    def _load_state(self) -> RunState | None:
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
            return RunState.from_dict(value)
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            return None

    def _tool_activity(self) -> str:
        lines: list[str] = []
        for component_id, label in (
            ("asset_commander", "AssetCommander"),
            ("semantic_dirscan", "AI 路径发现"),
            ("tscan_plus", "TscanPlus"),
        ):
            status, stage, detail = component_display_runtime(
                self.run_dir, component_id
            )
            if not any((status, stage, detail)):
                continue
            value = f"{label}：{status or 'unknown'}"
            if stage:
                value += f"，当前步骤：{stage}"
            if detail:
                value += f"，{detail}"
            lines.append(value)
        for name in ("fscan.txt", "nuclei.txt", "asset_commander_assets.json"):
            path = self.run_dir / "results" / name
            try:
                size = path.stat().st_size
            except OSError:
                continue
            lines.append(f"结果文件：{name}，{size} 字节")
        return "\n".join(lines) or "工具状态文件尚未生成。"

    def _refresh(self) -> None:
        if not self.winfo_exists():
            return
        state = self._load_state()
        if state is not None:
            self.summary_var.set(
                f"{state.project_name}  |  {state.run_id}  |  "
                f"{self._status_text(state.status)}"
            )
            selected = self.process_tree.selection()
            self.process_tree.delete(*self.process_tree.get_children())
            for process in state.processes:
                tool_status, stage, detail = component_display_runtime(
                    self.run_dir, process.component_id
                )
                status = tool_status or process.status
                self.process_tree.insert(
                    "",
                    "end",
                    iid=process.component_id,
                    values=(
                        process.name,
                        self._status_text(status),
                        stage,
                        detail,
                        process.pid,
                        process.started_at.replace("T", " ")[:19],
                    ),
                )
            for iid in selected:
                if self.process_tree.exists(iid):
                    self.process_tree.selection_add(iid)
        self.tool_activity_var.set(self._tool_activity())

        path = activity_log_path(self.run_dir)
        try:
            log = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            log = "活动日志尚未生成。\n"
        except OSError as exc:
            log = f"读取活动日志失败：{exc}\n"
        if log != self._last_log:
            follow = self.follow_var.get() or self.log_text.yview()[1] >= 0.98
            self.log_text.configure(state="normal")
            self.log_text.delete("1.0", "end")
            self.log_text.insert("1.0", log)
            self.log_text.configure(state="disabled")
            if follow:
                self.log_text.see("end")
            self._last_log = log
        self._after_id = self.after(1000, self._refresh)

    def _open_component_log(self, _event: tk.Event | None = None) -> None:
        selected = self.process_tree.selection()
        if not selected:
            return
        component_id = selected[0]
        values = self.process_tree.item(component_id, "values")
        component_name = str(values[0]) if values else component_id
        ComponentLogDialog(self, self.run_dir, component_id, component_name)

    def _open_run_dir(self) -> None:
        os.startfile(self.run_dir)

    def _open_log_file(self) -> None:
        path = activity_log_path(self.run_dir)
        if not path.is_file():
            messagebox.showinfo("项目日志", "活动日志文件尚未生成。", parent=self)
            return
        os.startfile(path)

    def _close(self) -> None:
        if self._after_id is not None:
            self.after_cancel(self._after_id)
            self._after_id = None
        self.destroy()
