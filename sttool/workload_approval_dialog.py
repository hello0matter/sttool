from __future__ import annotations

import ipaddress
import tkinter as tk
from pathlib import Path
from tkinter import ttk
from typing import Callable

from .workload_approval import decide_request, read_request, update_asset_inclusion
from .countdown_pause import (
    HoverCountdownPause,
    countdown_remaining_seconds,
    set_countdown_paused,
)


TYPE_LABELS = {"": "全部类型", "ip": "IP", "domain": "域名", "endpoint": "端点", "url": "URL"}


def row_sources(item: dict[str, object]) -> list[str]:
    sources = item.get("sources")
    if isinstance(sources, list):
        return [str(value) for value in sources if str(value)]
    source = str(item.get("source") or "")
    return [value.strip() for value in source.split(",") if value.strip()]


def workload_row_matches(
    item: dict[str, object], query: str, asset_type: str, source: str
) -> bool:
    if asset_type and str(item.get("type") or "") != asset_type:
        return False
    sources = row_sources(item)
    if source and source not in sources:
        return False
    needle = query.strip().casefold()
    if not needle:
        return True
    return needle in " ".join(
        [str(item.get("value") or ""), str(item.get("type") or ""), *sources]
    ).casefold()


def workload_row_sort_key(item: dict[str, object], column: str) -> object:
    if column == "included":
        return 0 if item.get("included") is not False else 1
    if column == "type":
        return TYPE_LABELS.get(str(item.get("type") or ""), "")
    if column == "source":
        return ", ".join(row_sources(item)).casefold()
    value = str(item.get("value") or "")
    try:
        return (0, int(ipaddress.ip_address(value)))
    except ValueError:
        return (1, value.casefold())


class WorkloadApprovalDialog(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Misc,
        *,
        request: dict[str, object],
        run_dir: Path,
        topmost: bool,
        on_close: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self.run_dir = run_dir
        self.request = request
        self.on_close = on_close
        self._closed = False
        self.rows = [item for item in request.get("assets", []) if isinstance(item, dict)] if isinstance(request.get("assets"), list) else []
        self.visible_rows: dict[str, dict[str, object]] = {}
        self.search_var = tk.StringVar()
        self.type_var = tk.StringVar(value="全部类型")
        self.source_var = tk.StringVar(value="全部来源")
        self.summary_var = tk.StringVar()
        self.sort_column = "included"
        self.sort_reverse = False

        self.title("确认下一批 AI 处理资产")
        width = min(1120, self.winfo_screenwidth() - 100)
        height = min(720, self.winfo_screenheight() - 120)
        self.geometry(f"{width}x{height}")
        self.minsize(860, 560)
        self.protocol("WM_DELETE_WINDOW", self._hide_with_default)
        if topmost:
            self.attributes("-topmost", True)

        banner = tk.Frame(self, bg="#9f1239", padx=18, pady=14)
        banner.pack(fill="x")
        tk.Label(banner, text="请确认哪些资产进入下一批 Codex/Claude", bg="#9f1239", fg="white", font=("Microsoft YaHei UI", 14, "bold")).pack(anchor="w")
        self.countdown_label = tk.Label(banner, text="", bg="#9f1239", fg="#fff4cc", font=("Microsoft YaHei UI", 10, "bold"))
        self.countdown_label.pack(anchor="w", pady=(5, 0))

        body = ttk.Frame(self, padding=14)
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1)
        body.rowconfigure(3, weight=1)
        ttk.Label(body, textvariable=self.summary_var, font=("Microsoft YaHei UI", 11, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 8))

        filters = ttk.Frame(body)
        filters.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(filters, text="类型").pack(side="left")
        type_box = ttk.Combobox(filters, textvariable=self.type_var, values=tuple(TYPE_LABELS.values()), state="readonly", width=10)
        type_box.pack(side="left", padx=(6, 14))
        ttk.Label(filters, text="来源").pack(side="left")
        sources = sorted({source for item in self.rows for source in row_sources(item)}, key=str.casefold)
        source_box = ttk.Combobox(filters, textvariable=self.source_var, values=("全部来源", *sources), state="readonly", width=24)
        source_box.pack(side="left", padx=(6, 14))
        ttk.Label(filters, text="搜索").pack(side="left")
        ttk.Entry(filters, textvariable=self.search_var).pack(side="left", fill="x", expand=True, padx=(6, 0))
        ttk.Button(filters, text="选择当前结果", command=self._select_visible).pack(side="left", padx=(8, 0))

        actions = ttk.Frame(body)
        actions.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        ttk.Button(actions, text="所选本批排除", command=lambda: self._set_selected(False)).pack(side="left")
        ttk.Button(actions, text="所选恢复", command=lambda: self._set_selected(True)).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="当前结果全部排除", command=lambda: self._set_visible(False)).pack(side="left", padx=(18, 0))
        ttk.Button(actions, text="当前结果全部恢复", command=lambda: self._set_visible(True)).pack(side="left", padx=(8, 0))

        columns = ("included", "type", "value", "source")
        self.tree = ttk.Treeview(body, columns=columns, show="headings", selectmode="extended")
        labels = {"included": "本批处理", "type": "类型", "value": "资产", "source": "来源"}
        widths = {"included": 90, "type": 80, "value": 600, "source": 220}
        for column in columns:
            self.tree.heading(column, text=labels[column], command=lambda value=column: self._sort(value))
            self.tree.column(column, width=widths[column], minwidth=60)
        self.tree.grid(row=3, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        scrollbar.grid(row=3, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)

        footer = ttk.Frame(self, padding=(14, 0, 14, 14))
        footer.pack(fill="x")
        ttk.Button(footer, text="跳过本次 AI", command=lambda: self._submit("reject")).pack(side="left")
        ttk.Button(footer, text="稍后提醒", command=self._snooze).pack(side="right")
        ttk.Button(footer, text="按表格启动本次 AI", command=lambda: self._submit("accept")).pack(side="right", padx=(0, 8))

        for variable in (self.search_var, self.type_var, self.source_var):
            variable.trace_add("write", lambda *_args: self._render())
        self._render()
        self.after(100, self._make_noticeable)
        self.after(250, self._tick_countdown)
        self._hover_pause = HoverCountdownPause(
            self,
            lambda paused: self._set_countdown_paused(paused),
        )
        self.after(1000, self._refresh_request)

    def _filtered_rows(self) -> list[dict[str, object]]:
        asset_type = next((key for key, label in TYPE_LABELS.items() if label == self.type_var.get()), "")
        source = "" if self.source_var.get() == "全部来源" else self.source_var.get()
        rows = [item for item in self.rows if workload_row_matches(item, self.search_var.get(), asset_type, source)]
        rows.sort(key=lambda item: workload_row_sort_key(item, self.sort_column), reverse=self.sort_reverse)
        return rows

    def _render(self) -> None:
        if not hasattr(self, "tree"):
            return
        rows = self._filtered_rows()
        self.visible_rows.clear()
        self.tree.delete(*self.tree.get_children())
        for index, item in enumerate(rows):
            iid = str(index)
            self.visible_rows[iid] = item
            self.tree.insert("", "end", iid=iid, values=("进入" if item.get("included") is not False else "已排除", TYPE_LABELS.get(str(item.get("type") or ""), item.get("type", "")), item.get("value", ""), ", ".join(row_sources(item))))
        included = [item for item in self.rows if item.get("included") is not False]
        type_counts = {kind: sum(1 for item in included if item.get("type") == kind) for kind in ("ip", "domain", "endpoint", "url")}
        detail = "、".join(f"{TYPE_LABELS[kind]} {count}" for kind, count in type_counts.items() if count)
        self.summary_var.set(f"本批 AI 保留 {len(included)} / 共 {len(self.rows)} 条资产" + (f"（{detail}）" if detail else ""))

    def _save_inclusion(self, rows: list[dict[str, object]], included: bool) -> None:
        keys = {(str(item.get("type") or ""), str(item.get("value") or "")) for item in rows}
        if not keys:
            return
        self.request = update_asset_inclusion(self.run_dir, keys, included=included)
        for item in self.rows:
            if (str(item.get("type") or ""), str(item.get("value") or "")) in keys:
                item["included"] = included
        self._render()

    def _set_selected(self, included: bool) -> None:
        self._save_inclusion([self.visible_rows[iid] for iid in self.tree.selection() if iid in self.visible_rows], included)

    def _set_visible(self, included: bool) -> None:
        self._save_inclusion(list(self.visible_rows.values()), included)

    def _select_visible(self) -> None:
        self.tree.selection_set(self.tree.get_children())

    def _sort(self, column: str) -> None:
        if self.sort_column == column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = column
            self.sort_reverse = False
        self._render()

    def _make_noticeable(self) -> None:
        try:
            self.deiconify()
            self.lift()
            self.bell()
            self.focus_force()
        except tk.TclError:
            pass

    def _remaining(self) -> int | None:
        return countdown_remaining_seconds(self.request)

    def _tick_countdown(self) -> None:
        if self._closed:
            return
        remaining = self._remaining()
        default_text = "按当前表格启动" if self.request.get("default_action") == "accept" else "跳过"
        if getattr(self, "_hover_pause", None) and self._hover_pause.paused:
            remaining_text = "" if remaining is None else f"，剩余 {remaining} 秒"
            self.countdown_label.configure(
                text=f"鼠标位于窗口内：倒计时已暂停{remaining_text}；移出后继续，到时默认{default_text}本次 AI。"
            )
        elif remaining is None:
            self.countdown_label.configure(text="默认动作：始终等待人工确认；其他工具继续运行。")
        else:
            self.countdown_label.configure(text=f"{remaining} 秒后默认{default_text}本次 AI；其他工具继续运行。")
            if remaining <= 0:
                self._close_only()
                return
        self.after(250, self._tick_countdown)

    def _set_countdown_paused(self, paused: bool) -> None:
        self.request = set_countdown_paused(
            self.run_dir / "tool_data" / "coordinator" / "workload_approval.json",
            paused,
        )
        self._render()

    def _refresh_request(self) -> None:
        if self._closed:
            return
        latest = read_request(self.run_dir)
        if latest and latest.get("status") in {"pending", ""}:
            assets = latest.get("assets")
            if isinstance(assets, list) and assets != self.request.get("assets"):
                self.request = latest
                self.rows = [item for item in assets if isinstance(item, dict)]
                self._render()
        elif latest:
            self._hover_pause.resume()
            self._close_only()
            return
        self.after(1000, self._refresh_request)

    def _submit(self, action: str) -> None:
        self._hover_pause.resume()
        decide_request(self.run_dir, action, "user")
        self._close_only()

    def _hide_with_default(self) -> None:
        self._hover_pause.resume()
        decide_request(self.run_dir, str(self.request.get("default_action") or "accept"), "hidden_default")
        self._close_only()

    def _snooze(self) -> None:
        self._hover_pause.resume()
        self._close_only()

    def _close_only(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.on_close:
            self.on_close()
        self.destroy()


__all__ = ["WorkloadApprovalDialog", "workload_row_matches", "workload_row_sort_key"]
