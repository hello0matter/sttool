from __future__ import annotations

import tkinter as tk
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from tkinter import ttk
from typing import Callable

from .asset_bus import atomic_json_write, now_text, read_json


_REASON_LABELS = {
    "same_cidr": "与目标同一 C 段的新 IP",
    "new_host": "新发现的主机或域名",
    "authorized_new_host": "授权范围内的新主机",
}


def pending_group_matches(
    item: dict[str, object],
    query: str = "",
    asset_type: str = "",
    source: str = "",
) -> bool:
    types = [str(value) for value in item.get("types", [])]
    sources = [str(value) for value in item.get("sources", [])]
    if asset_type and asset_type not in types:
        return False
    if source and source not in sources:
        return False
    needle = query.strip().casefold()
    if not needle:
        return True
    values = [
        item.get("group_key", ""),
        item.get("reason_text", ""),
        *types,
        *sources,
        *item.get("examples", []),
    ]
    return needle in " ".join(map(str, values)).casefold()


def pending_asset_groups(value: dict[str, object]) -> list[dict[str, object]]:
    rows = value.get("pending")
    if not isinstance(rows, list):
        return []
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for item in rows:
        if not isinstance(item, dict):
            continue
        identity = str(item.get("id") or "")
        if not identity:
            continue
        group_key = str(item.get("group_key") or item.get("value") or identity)
        grouped[group_key].append(item)
    result: list[dict[str, object]] = []
    for group_key, items in sorted(grouped.items()):
        sources = sorted(
            {
                str(source)
                for item in items
                for source in (
                    item.get("sources")
                    if isinstance(item.get("sources"), list)
                    else [item.get("source")]
                )
                if source
            }
        )
        types = sorted({str(item.get("type") or "") for item in items})
        examples = [str(item.get("value") or "") for item in items[:3]]
        reasons = sorted({str(item.get("reason") or "new_host") for item in items})
        deadlines = sorted(
            str(item.get("decision_deadline_at") or "")
            for item in items
            if item.get("decision_deadline_at")
        )
        default_action = (
            "reject"
            if all(str(item.get("default_action") or "accept") == "reject" for item in items)
            else "accept"
        )
        result.append(
            {
                "group_key": group_key,
                "ids": [str(item["id"]) for item in items],
                "count": len(items),
                "sources": sources,
                "types": types,
                "examples": examples,
                "reasons": reasons,
                "reason_text": "、".join(
                    _REASON_LABELS.get(reason, reason) for reason in reasons
                ),
                "deadline_at": deadlines[0] if deadlines else "",
                "default_action": default_action,
            }
        )
    return result


def append_asset_decisions(
    path: Path,
    decisions: list[dict[str, object]],
) -> None:
    value = read_json(path)
    existing = value.get("decisions")
    if not isinstance(existing, list):
        existing = []
    by_id = {
        str(item.get("id") or ""): item
        for item in existing
        if isinstance(item, dict) and item.get("id")
    }
    for item in decisions:
        identity = str(item.get("id") or "")
        action = str(item.get("action") or "")
        if not identity or action not in {"accept", "reject"}:
            continue
        by_id[identity] = {
            "id": identity,
            "action": action,
            "decided_at": item.get("decided_at") or now_text(),
            "decision_source": item.get("decision_source") or "launcher_popup",
        }
    atomic_json_write(
        path,
        {
            "schema_version": 1,
            "updated_at": now_text(),
            "decisions": list(by_id.values())[-5000:],
        },
    )


class AssetApprovalDialog(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Misc,
        *,
        project_name: str,
        run_id: str,
        run_dir: Path,
        pending_value: dict[str, object],
        topmost: bool,
        on_close: Callable[[], None],
    ) -> None:
        super().__init__(parent)
        self.project_name = project_name
        self.run_id = run_id
        self.run_dir = run_dir
        self.decisions_path = run_dir / "tool_data" / "asset_bus" / "decisions.json"
        self.groups = pending_asset_groups(pending_value)
        self.search_var = tk.StringVar()
        self.type_filter_var = tk.StringVar(value="全部类型")
        self.source_filter_var = tk.StringVar(value="全部来源")
        self.on_close = on_close
        self.checked: dict[str, bool] = {
            str(item["group_key"]): str(item["default_action"]) == "accept"
            for item in self.groups
        }
        self.title(f"发现新资产，需要确认 - {project_name}")
        width = min(1020, max(self.winfo_screenwidth() - 120, 760))
        height = min(680, max(self.winfo_screenheight() - 160, 520))
        left = max(20, (self.winfo_screenwidth() - width) // 2)
        top = max(20, (self.winfo_screenheight() - height) // 3)
        self.geometry(f"{width}x{height}+{left}+{top}")
        self.minsize(760, 520)
        self.protocol("WM_DELETE_WINDOW", self._hide_with_default)
        if topmost:
            self.attributes("-topmost", True)

        banner = tk.Frame(self, bg="#b42318", padx=18, pady=14)
        banner.pack(fill="x")
        tk.Label(
            banner,
            text="⚠ 发现新的主机级资产，继续测试会增加扫描时间和请求量",
            bg="#b42318",
            fg="white",
            font=("Microsoft YaHei UI", 14, "bold"),
        ).pack(anchor="w")
        self.countdown_label = tk.Label(
            banner,
            text="",
            bg="#b42318",
            fg="#fff4cc",
            font=("Microsoft YaHei UI", 10, "bold"),
        )
        self.countdown_label.pack(anchor="w", pady=(6, 0))

        body = ttk.Frame(self, padding=16)
        body.pack(fill="both", expand=True)
        ttk.Label(
            body,
            text=(
                f"项目：{project_name}    运行：{run_id}\n"
                "后台现有任务不会暂停；只有勾选加入的主机才会进入后续 fscan、Tscan、"
                "dirsearch 和 Agent 增量流程。取消勾选后，倒计时结束会自动排除该主机。"
            ),
            wraplength=920,
        ).pack(fill="x", anchor="w", pady=(0, 12))

        filters = ttk.Frame(body)
        filters.pack(fill="x", pady=(0, 8))
        ttk.Label(filters, text="搜索").pack(side="left")
        ttk.Entry(filters, textvariable=self.search_var).pack(
            side="left", fill="x", expand=True, padx=(6, 12)
        )
        ttk.Label(filters, text="类型").pack(side="left")
        types = sorted(
            {str(value) for item in self.groups for value in item.get("types", [])}
        )
        ttk.Combobox(
            filters,
            textvariable=self.type_filter_var,
            values=("全部类型", *types),
            state="readonly",
            width=11,
        ).pack(side="left", padx=(6, 12))
        ttk.Label(filters, text="来源").pack(side="left")
        sources = sorted(
            {str(value) for item in self.groups for value in item.get("sources", [])}
        )
        ttk.Combobox(
            filters,
            textvariable=self.source_filter_var,
            values=("全部来源", *sources),
            state="readonly",
            width=18,
        ).pack(side="left", padx=(6, 0))

        columns = ("choice", "host", "kind", "source", "reason", "count", "example")
        table = ttk.Frame(body)
        table.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(
            table, columns=columns, show="headings", selectmode="extended"
        )
        headings = {
            "choice": "加入？",
            "host": "主机 / IP",
            "kind": "资产类型",
            "source": "发现来源",
            "reason": "关联原因",
            "count": "明细数",
            "example": "示例",
        }
        widths = {
            "choice": 65,
            "host": 170,
            "kind": 85,
            "source": 130,
            "reason": 165,
            "count": 65,
            "example": 270,
        }
        for column in columns:
            self.tree.heading(column, text=headings[column])
            self.tree.column(column, width=widths[column], minwidth=55, stretch=column == "example")
        scrollbar = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="left", fill="y")
        self.tree.bind("<Button-1>", self._toggle_row)
        for variable in (self.search_var, self.type_filter_var, self.source_filter_var):
            variable.trace_add("write", lambda *_args: self._render_rows())
        self._render_rows()

        actions = ttk.Frame(self, padding=(16, 0, 16, 16))
        actions.pack(fill="x")
        ttk.Button(actions, text="所选允许", command=lambda: self._set_selected(True)).pack(side="left")
        ttk.Button(actions, text="所选排除", command=lambda: self._set_selected(False)).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(actions, text="当前结果允许", command=lambda: self._set_visible(True)).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(actions, text="当前结果排除", command=lambda: self._set_visible(False)).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(
            actions,
            text="隐藏提醒（仍按全局默认执行）",
            command=self._hide_with_default,
        ).pack(side="right")
        ttk.Button(
            actions,
            text="应用当前选择",
            command=lambda: self._submit("user"),
        ).pack(side="right", padx=(0, 8))

        self.after(100, self._make_noticeable)
        self.after(250, self._tick_countdown)

    def _make_noticeable(self) -> None:
        try:
            self.deiconify()
            self.lift()
            self.bell()
            self.focus_force()
        except tk.TclError:
            return

    def _render_rows(self) -> None:
        selected = set(self.tree.selection())
        self.tree.delete(*self.tree.get_children())
        for item in self.groups:
            if not pending_group_matches(
                item,
                self.search_var.get(),
                "" if self.type_filter_var.get() == "全部类型" else self.type_filter_var.get(),
                "" if self.source_filter_var.get() == "全部来源" else self.source_filter_var.get(),
            ):
                continue
            key = str(item["group_key"])
            self.tree.insert(
                "",
                "end",
                iid=key,
                values=(
                    "☑" if self.checked.get(key, True) else "☐",
                    key,
                    ", ".join(item["types"]),
                    ", ".join(item["sources"]),
                    item["reason_text"],
                    item["count"],
                    " | ".join(item["examples"]),
                ),
            )
        self.tree.selection_set(
            [identity for identity in selected if self.tree.exists(identity)]
        )

    def _toggle_row(self, event: tk.Event[tk.Misc]) -> None:
        if self.tree.identify_column(event.x) != "#1":
            return
        row = self.tree.identify_row(event.y)
        if not row:
            return
        self.checked[row] = not self.checked.get(row, True)
        self._render_rows()

    def _set_selected(self, accepted: bool) -> None:
        for key in self.tree.selection():
            self.checked[key] = accepted
        self._render_rows()

    def _set_visible(self, accepted: bool) -> None:
        for key in self.tree.get_children():
            self.checked[key] = accepted
        self._render_rows()

    def _seconds_remaining(self) -> int | None:
        remaining: list[int] = []
        now = datetime.now().astimezone()
        for item in self.groups:
            deadline_text = str(item.get("deadline_at") or "")
            if not deadline_text:
                continue
            try:
                deadline = datetime.fromisoformat(deadline_text)
            except ValueError:
                continue
            if deadline.tzinfo is None:
                deadline = deadline.astimezone()
            remaining.append(max(int((deadline - now).total_seconds()), 0))
        return min(remaining) if remaining else None

    def _tick_countdown(self) -> None:
        if not self.winfo_exists():
            return
        seconds = self._seconds_remaining()
        if seconds is None:
            self.countdown_label.configure(text="当前策略：始终等待人工确认，不会自动加入。")
        elif seconds <= 0:
            self.countdown_label.configure(text="倒计时结束，正在应用当前勾选结果……")
            self._submit("countdown_popup")
            return
        else:
            checked_count = sum(self.checked.values())
            self.countdown_label.configure(
                text=f"{seconds} 秒后自动应用当前选择：加入 {checked_count} 个主机，排除 {len(self.checked) - checked_count} 个主机。"
            )
        self.after(500, self._tick_countdown)

    def _submit(self, source: str) -> None:
        decisions: list[dict[str, object]] = []
        for item in self.groups:
            accepted = self.checked.get(str(item["group_key"]), True)
            for identity in item["ids"]:
                decisions.append(
                    {
                        "id": identity,
                        "action": "accept" if accepted else "reject",
                        "decided_at": now_text(),
                        "decision_source": source,
                    }
                )
        append_asset_decisions(self.decisions_path, decisions)
        self._finish()

    def _hide_with_default(self) -> None:
        self._finish()

    def _finish(self) -> None:
        try:
            self.on_close()
        finally:
            self.destroy()
