from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import messagebox, simpledialog, ttk

from .asset_bus import AssetBus, read_json
from .models import RunState
from .workload_approval import decide_request, read_history, read_request


_ASSET_STATUS = {
    "allowed": "已允许",
    "pending": "待确认",
    "rejected": "排除记录",
    "blocked": "已阻止",
}

_TASK_STATUS = {
    "pending": "待确认",
    "decided": "已决定",
    "running": "运行中",
    "completed": "已完成",
    "failed": "失败",
}

_DECISIONS = {
    "accept": "允许",
    "reject": "跳过",
    "exclude": "排除",
    "manual_add": "人工加入",
}

_DECISION_SOURCES = {
    "user": "确认弹窗",
    "timeout_default": "倒计时默认",
    "hidden_default": "隐藏时默认",
    "project_access_manager": "准入与任务管理",
}

_ASSET_DECISION_SOURCES = {
    "countdown": "倒计时默认决定",
    "user": "人工决定",
    "project_access_manager": "准入与任务管理",
}


def asset_row_matches(item: dict[str, object], query: str) -> bool:
    needle = query.strip().casefold()
    if not needle:
        return True
    values = [
        _ASSET_STATUS.get(str(item.get("status") or ""), ""),
        item.get("type", ""),
        item.get("value", ""),
        item.get("source", ""),
        item.get("reason", ""),
        item.get("scope_status", ""),
    ]
    sources = item.get("sources")
    if isinstance(sources, list):
        values.extend(sources)
    decision = item.get("latest_decision")
    if isinstance(decision, dict):
        values.extend(decision.values())
    return needle in " ".join(str(value) for value in values).casefold()


class ProjectAccessDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc, state: RunState) -> None:
        super().__init__(parent)
        self.state = state
        self.run_dir = Path(state.run_dir)
        self.asset_path = self.run_dir / "tool_data" / "asset_bus" / "assets.json"
        self.asset_rows: dict[str, dict[str, object]] = {}
        self.all_asset_rows: list[dict[str, object]] = []
        self.asset_search_var = tk.StringVar()
        self.task_rows: dict[str, dict[str, object]] = {}
        self.title(f"准入与任务管理 - {state.project_name} / {state.run_id}")
        width = min(1180, self.winfo_screenwidth() - 100)
        height = min(720, self.winfo_screenheight() - 140)
        self.geometry(f"{width}x{height}")
        self.minsize(900, 560)

        tabs = ttk.Notebook(self)
        tabs.pack(fill="both", expand=True, padx=14, pady=14)
        self.asset_tab = ttk.Frame(tabs, padding=10)
        self.task_tab = ttk.Frame(tabs, padding=10)
        tabs.add(self.asset_tab, text="资产准入")
        tabs.add(self.task_tab, text="AI 执行批次")
        self._build_asset_tab()
        self._build_task_tab()
        self._refresh_all()

    def _build_asset_tab(self) -> None:
        self.asset_tab.columnconfigure(0, weight=1)
        self.asset_tab.rowconfigure(2, weight=1)
        actions = ttk.Frame(self.asset_tab)
        actions.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Button(actions, text="刷新", command=self._refresh_assets).pack(side="left")
        ttk.Button(actions, text="添加资产", command=self._add_asset).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(actions, text="修改所选", command=self._edit_asset).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(actions, text="允许 / 恢复", command=self._allow_asset).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(actions, text="排除后续处理", command=self._exclude_asset).pack(
            side="left", padx=(8, 0)
        )

        search = ttk.Frame(self.asset_tab)
        search.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        search.columnconfigure(1, weight=1)
        ttk.Label(search, text="搜索").grid(row=0, column=0, padx=(0, 8))
        ttk.Entry(search, textvariable=self.asset_search_var).grid(
            row=0, column=1, sticky="ew"
        )
        ttk.Button(search, text="选择当前结果", command=self._select_visible_assets).grid(
            row=0, column=2, padx=(8, 0)
        )
        ttk.Button(search, text="清空", command=lambda: self.asset_search_var.set("")).grid(
            row=0, column=3, padx=(8, 0)
        )
        self.asset_search_var.trace_add("write", lambda *_args: self._render_asset_rows())

        columns = ("status", "type", "value", "source", "reason", "time")
        self.asset_tree = ttk.Treeview(
            self.asset_tab, columns=columns, show="headings", selectmode="extended"
        )
        headings = {
            "status": "状态",
            "type": "类型",
            "value": "资产",
            "source": "来源",
            "reason": "原因 / 决策",
            "time": "时间",
        }
        widths = {
            "status": 80,
            "type": 65,
            "value": 250,
            "source": 110,
            "reason": 155,
            "time": 145,
        }
        for column in columns:
            self.asset_tree.heading(column, text=headings[column])
            self.asset_tree.column(column, width=widths[column], minwidth=50)
        self.asset_tree.grid(row=2, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(
            self.asset_tab, orient="vertical", command=self.asset_tree.yview
        )
        scrollbar.grid(row=2, column=1, sticky="ns")
        self.asset_tree.configure(yscrollcommand=scrollbar.set)

    def _build_task_tab(self) -> None:
        self.task_tab.columnconfigure(0, weight=1)
        self.task_tab.rowconfigure(1, weight=1)
        actions = ttk.Frame(self.task_tab)
        actions.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Button(actions, text="刷新", command=self._refresh_tasks).pack(side="left")
        ttk.Button(actions, text="允许当前批次", command=lambda: self._decide_task("accept")).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(actions, text="跳过当前批次", command=lambda: self._decide_task("reject")).pack(
            side="left", padx=(8, 0)
        )

        columns = ("kind", "status", "range", "count", "decision", "source", "time")
        self.task_tree = ttk.Treeview(
            self.task_tab, columns=columns, show="headings", selectmode="browse"
        )
        headings = {
            "kind": "记录类型",
            "status": "状态",
            "range": "资产更新轮次",
            "count": "资产数",
            "decision": "决定",
            "source": "决定来源",
            "time": "时间",
        }
        widths = {
            "kind": 105,
            "status": 85,
            "range": 115,
            "count": 70,
            "decision": 85,
            "source": 130,
            "time": 145,
        }
        for column in columns:
            self.task_tree.heading(column, text=headings[column])
            self.task_tree.column(column, width=widths[column], minwidth=50)
        self.task_tree.grid(row=1, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(
            self.task_tab, orient="vertical", command=self.task_tree.yview
        )
        scrollbar.grid(row=1, column=1, sticky="ns")
        self.task_tree.configure(yscrollcommand=scrollbar.set)

    def _asset_bus(self) -> AssetBus:
        return AssetBus(self.asset_path, self.state.scope, self.state.target)

    def _refresh_all(self) -> None:
        self._refresh_assets()
        self._refresh_tasks()

    def _refresh_assets(self) -> None:
        value = read_json(self.asset_path)
        history_rows = value.get("decision_history")
        latest_history: dict[tuple[str, str], dict[str, object]] = {}
        if isinstance(history_rows, list):
            for history in history_rows:
                if not isinstance(history, dict):
                    continue
                latest_history[
                    (str(history.get("type") or ""), str(history.get("value") or ""))
                ] = history
        rows: list[dict[str, object]] = []
        for status, key in (
            ("allowed", "assets"),
            ("pending", "pending"),
            ("rejected", "rejected"),
            ("blocked", "blocked_assets"),
        ):
            entries = value.get(key)
            if not isinstance(entries, list):
                continue
            for item in entries:
                if not isinstance(item, dict):
                    continue
                decision = latest_history.get(
                    (str(item.get("type") or ""), str(item.get("value") or "")),
                    {},
                )
                rows.append({"status": status, **item, "latest_decision": decision})
        self.all_asset_rows = rows
        self._render_asset_rows()

    def _render_asset_rows(self) -> None:
        if not hasattr(self, "asset_tree"):
            return
        rows = [
            item
            for item in self.all_asset_rows
            if asset_row_matches(item, self.asset_search_var.get())
        ]
        self.asset_rows = {}
        self.asset_tree.delete(*self.asset_tree.get_children())
        for index, item in enumerate(rows):
            identity = f"{item['status']}:{index}"
            self.asset_rows[identity] = item
            sources = item.get("sources")
            source = ", ".join(map(str, sources)) if isinstance(sources, list) else str(
                item.get("source") or ""
            )
            timestamp = str(
                item.get("decided_at")
                or item.get("blocked_at")
                or item.get("first_seen_at")
                or item.get("seen_at")
                or item.get("discovered_at")
                or ""
            )
            decision = item.get("latest_decision")
            decision_text = ""
            if isinstance(decision, dict) and decision:
                source_text = _ASSET_DECISION_SOURCES.get(
                    str(decision.get("decision_source") or ""),
                    str(decision.get("decision_source") or ""),
                )
                action_text = _DECISIONS.get(
                    str(decision.get("action") or ""),
                    str(decision.get("action") or ""),
                )
                decision_text = f"{source_text}：{action_text}"
            self.asset_tree.insert(
                "",
                "end",
                iid=identity,
                values=(
                    _ASSET_STATUS[str(item["status"])],
                    item.get("type", ""),
                    item.get("value", ""),
                    source,
                    decision_text
                    or item.get("reason")
                    or item.get("scope_status")
                    or "",
                    timestamp.replace("T", " ")[:19],
                ),
            )

    def _selected_assets(self) -> list[dict[str, object]]:
        selected = self.asset_tree.selection()
        if not selected:
            messagebox.showinfo("资产准入", "请先选择资产", parent=self)
            return []
        return [self.asset_rows[item] for item in selected if item in self.asset_rows]

    def _select_visible_assets(self) -> None:
        self.asset_tree.selection_set(self.asset_tree.get_children())

    def _add_asset(self) -> None:
        value = simpledialog.askstring(
            "添加资产", "填写 URL、域名、IP 或 IP:端口：", parent=self
        )
        if not value:
            return
        try:
            self._asset_bus().add_manual_asset(value)
        except ValueError as exc:
            messagebox.showerror("添加失败", str(exc), parent=self)
            return
        self._refresh_assets()

    def _edit_asset(self) -> None:
        items = self._selected_assets()
        if not items:
            return
        if len(items) != 1:
            messagebox.showinfo("修改资产", "修改操作一次只能选择一条资产", parent=self)
            return
        item = items[0]
        old_value = str(item.get("value") or "")
        new_value = simpledialog.askstring(
            "修改资产", "填写修改后的资产：", initialvalue=old_value, parent=self
        )
        if not new_value or new_value.strip() == old_value:
            return
        try:
            bus = self._asset_bus()
            bus.replace_manual_asset(
                old_value,
                str(item.get("type") or ""),
                new_value,
            )
        except ValueError as exc:
            messagebox.showerror("修改失败", str(exc), parent=self)
            return
        self._refresh_assets()

    def _allow_asset(self) -> None:
        items = self._selected_assets()
        if not items:
            return
        errors: list[str] = []
        try:
            bus = self._asset_bus()
            pending = [
                {"id": item["id"], "action": "accept"}
                for item in items
                if item.get("status") == "pending" and item.get("id")
            ]
            if pending:
                bus.apply_decisions(pending)
            for item in items:
                if item.get("status") == "pending":
                    continue
                try:
                    bus.restore_asset(
                        str(item.get("value") or ""), str(item.get("type") or "")
                    )
                except ValueError as exc:
                    errors.append(f"{item.get('value', '')}：{exc}")
        except ValueError as exc:
            errors.append(str(exc))
        self._refresh_assets()
        if errors:
            messagebox.showerror("部分资产允许失败", "\n".join(errors[:20]), parent=self)

    def _exclude_asset(self) -> None:
        items = self._selected_assets()
        if not items:
            return
        bus = self._asset_bus()
        errors: list[str] = []
        for item in items:
            try:
                bus.exclude_asset(
                    str(item.get("value") or ""), str(item.get("type") or "")
                )
            except ValueError as exc:
                errors.append(f"{item.get('value', '')}：{exc}")
        self._refresh_assets()
        if errors:
            messagebox.showerror("部分资产排除失败", "\n".join(errors[:20]), parent=self)

    def _refresh_tasks(self) -> None:
        rows: list[dict[str, object]] = []
        current = read_request(self.run_dir)
        history = read_history(self.run_dir)
        history_ids = {str(item.get("request_id") or "") for item in history}
        if current and (
            current.get("status") in {"pending", ""}
            or str(current.get("request_id") or "") not in history_ids
        ):
            rows.append({"kind": "当前确认", **current})
        rows.extend({"kind": "确认历史", **item} for item in history)
        coordinator = read_json(
            self.run_dir / "tool_data" / "coordinator" / "state.json"
        )
        batches = coordinator.get("agent_batches")
        if isinstance(batches, list):
            rows.extend(
                {"kind": "AI 执行批次", **item}
                for item in batches
                if isinstance(item, dict)
            )
        self.task_rows = {}
        self.task_tree.delete(*self.task_tree.get_children())
        for index, item in enumerate(rows):
            identity = f"task:{index}"
            self.task_rows[identity] = item
            generation_from = item.get("generation_from", "-")
            generation_to = item.get("generation_to", "-")
            self.task_tree.insert(
                "",
                "end",
                iid=identity,
                values=(
                    item.get("kind", ""),
                    _TASK_STATUS.get(
                        str(item.get("status") or ""), item.get("status", "")
                    ),
                    f"{generation_from} - {generation_to}",
                    item.get("total", ""),
                    _DECISIONS.get(
                        str(item.get("decision") or ""), item.get("decision", "")
                    ),
                    _DECISION_SOURCES.get(
                        str(item.get("decided_by") or ""), item.get("decided_by", "")
                    ),
                    str(
                        item.get("decided_at")
                        or item.get("started_at")
                        or item.get("created_at")
                        or ""
                    ).replace("T", " ")[:19],
                ),
            )

    def _decide_task(self, action: str) -> None:
        request = read_request(self.run_dir)
        if not request or request.get("status") not in {"pending", ""}:
            messagebox.showinfo("AI 执行批次", "当前没有等待确认的 AI 执行批次", parent=self)
            return
        decide_request(self.run_dir, action, "project_access_manager")
        self._refresh_tasks()


__all__ = ["ProjectAccessDialog", "asset_row_matches"]
