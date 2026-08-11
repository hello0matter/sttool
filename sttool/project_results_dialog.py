from __future__ import annotations

import json
import os
import re
import shutil
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from .asset_bus import AssetBus
from .findings_dialog import FindingsDialog
from .models import RunState
from .pentest_report import write_pentest_report
from .project_result_catalog import (
    ProjectResultSource,
    preview_result_source,
    project_result_sources,
    result_target_label,
)


FINAL_RUN_STATUSES = {"completed", "failed", "stopped", "exited"}
PREVIEW_URL = re.compile(r"https?://[^\s|<>\"']+")
URL_TRAILING_PUNCTUATION = ".,;:!?)]}，。；：！？）】"


def preview_url_spans(text: str) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    for match in PREVIEW_URL.finditer(text):
        url = match.group(0).rstrip(URL_TRAILING_PUNCTUATION)
        if url:
            spans.append((match.start(), match.start() + len(url), url))
    return spans


def human_file_size(size: int) -> str:
    value = max(size, 0)
    for unit in ("字节", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:,} {unit}" if unit == "字节" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size:,} 字节"


def source_sort_key(source: ProjectResultSource, column: str) -> object:
    if column == "name":
        return source.title.casefold()
    if column == "target":
        return result_target_label(source).casefold()
    if column == "kind":
        return source.kind.casefold()
    if column == "size":
        return source.size
    if column == "updated":
        try:
            return source.path.stat().st_mtime
        except OSError:
            return 0.0
    return source.title.casefold()


def compact_markdown(text: str, *, max_lines: int = 260) -> str:
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text.strip()

    output: list[str] = []
    section_lines = 0
    omitted = 0
    asset_section = False
    for line in lines:
        if line.startswith("## "):
            if omitted:
                output.append(
                    f"- \u2026\u2026\u672c\u8282\u53e6\u6709 {omitted} \u884c\uff0c"
                    "\u70b9\u51fb\u201c\u6253\u5f00\u6e17\u900f\u6d4b\u8bd5\u62a5\u544a\u201d\u6216\u76f4\u63a5\u6253\u5f00\u9009\u4e2d\u6587\u4ef6\u67e5\u770b\u3002"
                )
                omitted = 0
            section_lines = 0
            asset_section = any(
                token in line
                for token in (
                    "Web \u76ee\u6807",
                    "\u975e Web \u670d\u52a1",
                    "\u8d44\u4ea7",
                    "\u7aef\u70b9",
                )
            )
            output.append(line)
            continue
        section_lines += 1
        section_limit = 35 if asset_section else 90
        if section_lines <= section_limit and len(output) < max_lines:
            output.append(line)
        else:
            omitted += 1

    if omitted:
        output.append(
            f"- \u2026\u2026\u5176\u4f59 {omitted} \u884c\u5df2\u6298\u53e0\uff0c"
            "\u70b9\u51fb\u201c\u6253\u5f00\u6e17\u900f\u6d4b\u8bd5\u62a5\u544a\u201d\u6216\u76f4\u63a5\u6253\u5f00\u9009\u4e2d\u6587\u4ef6\u67e5\u770b\u3002"
        )
    return "\n".join(output).strip()


def regenerate_pentest_report(state: RunState) -> tuple[Path, Path]:
    run_dir = Path(state.run_dir)
    try:
        project = json.loads((run_dir / "project.json").read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        project = {}
    if not isinstance(project, dict):
        project = {}
    bus = AssetBus(
        run_dir / "tool_data" / "asset_bus" / "assets.json",
        str(project.get("scope") or state.scope or "*"),
    )
    from .project_coordinator import tscan_findings

    database = run_dir / "tool_data" / "tscan" / "app" / "config" / "config.db"
    return write_pentest_report(
        run_dir=run_dir,
        bus=bus,
        stage=f"人工问题库更新 / {state.status}",
        project_name=str(project.get("name") or state.project_name),
        target=str(project.get("target") or state.target),
        scope=str(project.get("scope") or state.scope or "*"),
        tscan_findings=tscan_findings(database),
    )


def render_project_results(state: RunState) -> tuple[str, list[ProjectResultSource]]:
    run_dir = Path(state.run_dir)
    sources = project_result_sources(run_dir)
    stage = (
        "\u6700\u7ec8\u6210\u679c"
        if state.status in FINAL_RUN_STATUSES
        else "\u9636\u6bb5\u6210\u679c\uff08\u9879\u76ee\u4ecd\u5728\u8fd0\u884c\uff09"
    )
    lines = [
        f"{state.project_name} - {stage}",
        "",
        f"运行实例：{state.run_id}",
        f"当前状态：{state.status}",
        f"目标：{state.target}",
        f"授权范围：{state.scope}",
        f"更新时间：{state.updated_at}",
        "",
    ]
    if not sources:
        lines.extend(
            [
                "当前结论",
                "\u5f53\u524d\u5c1a\u65e0\u53ef\u8bfb\u53d6\u7684\u9879\u76ee\u6210\u679c\u6587\u4ef6\u3002"
                "\u5de5\u5177\u53ef\u80fd\u4ecd\u5728\u7b49\u5f85\u8d44\u4ea7\u3001\u8fd0\u884c\u4e2d\uff0c"
                "\u6216\u672c\u8f6e\u5c1a\u672a\u5f62\u6210\u98ce\u9669\u7ebf\u7d22\u3002",
                "\u53ef\u70b9\u51fb\u201c\u5237\u65b0\u201d\u6301\u7eed\u67e5\u770b\uff1b"
                "\u5355\u4e2a\u5de5\u5177\u7684\u6267\u884c\u8fc7\u7a0b\u8bf7\u5230\u201c\u9879\u76ee\u65e5\u5fd7\u201d\u4e2d\u67e5\u770b\u3002",
            ]
        )
        return "\n".join(lines), sources

    counts: dict[str, int] = {}
    for source in sources:
        counts[source.kind] = counts.get(source.kind, 0) + 1
    lines.extend(("成果概览", ""))
    lines.extend(f"• {kind}：{count} 项" for kind, count in counts.items())
    lines.extend(("", "请在上方选择成果，下方会显示对应内容。"))
    return "\n".join(lines).strip() + "\n", sources


class ProjectResultsDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc, state: RunState) -> None:
        super().__init__(parent)
        self.state = state
        self.run_dir = Path(state.run_dir)
        self.sources: list[ProjectResultSource] = []
        self.preview_urls_by_tag: dict[str, str] = {}
        self.preview_link_press: tuple[str, int, int] | None = None
        self.source_sort_column = ""
        self.source_sort_descending = False
        self.source_heading_labels: dict[str, str] = {}
        self.title(
            f"\u9879\u76ee\u6210\u679c - {state.project_name} / {state.run_id}"
        )
        self.geometry("1320x820")
        self.minsize(920, 620)
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

        source_frame = ttk.Frame(container)
        source_frame.grid(row=1, column=0, sticky="nsew", pady=(0, 10))
        source_frame.columnconfigure(0, weight=1)
        source_frame.rowconfigure(0, weight=1)

        source_scrollbar = ttk.Scrollbar(source_frame, orient="vertical")
        self.source_tree = ttk.Treeview(
            source_frame,
            columns=("name", "target", "kind", "size", "updated"),
            show="headings",
            height=10,
            selectmode="browse",
            yscrollcommand=source_scrollbar.set,
        )
        source_scrollbar.configure(command=self.source_tree.yview)
        for column, label, width in (
            ("name", "成果", 220),
            ("target", "目标 / 批次", 520),
            ("kind", "来源", 110),
            ("size", "大小", 100),
            ("updated", "更新时间", 145),
        ):
            self.source_heading_labels[column] = label
            self.source_tree.heading(
                column,
                text=label,
                command=lambda value=column: self._sort_source_tree(value),
            )
            self.source_tree.column(column, width=width, minwidth=80)
        self.source_tree.grid(row=0, column=0, sticky="nsew")
        source_scrollbar.grid(row=0, column=1, sticky="ns")
        self.source_tree.bind("<<TreeviewSelect>>", self._preview_selected_source)
        self.source_tree.bind(
            "<Double-1>", lambda _event: self._open_selected_source()
        )

        self.text = scrolledtext.ScrolledText(
            container,
            wrap="word",
            font=("Microsoft YaHei UI", 10),
            state="disabled",
        )
        self.text.grid(row=2, column=0, sticky="nsew")
        self.text.bind("<ButtonPress-1>", self._preview_link_pressed)
        self.text.bind("<ButtonRelease-1>", self._preview_link_released)
        self.text.bind("<Motion>", self._preview_link_motion)
        self.text.bind("<Leave>", lambda _event: self.text.configure(cursor="xterm"))

        actions = ttk.Frame(container)
        actions.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        ttk.Button(
            actions, text="\u5237\u65b0", command=self._refresh
        ).pack(side="left")
        ttk.Button(
            actions,
            text="问题管理",
            command=self._manage_findings,
        ).pack(side="left", padx=(8, 0))
        ttk.Button(
            actions,
            text="打开原始文件",
            command=self._open_selected_source,
        ).pack(side="left", padx=(8, 0))
        ttk.Button(
            actions,
            text="导出报告",
            command=self._export_report,
        ).pack(side="left", padx=(8, 0))
        ttk.Button(
            actions,
            text="\u6253\u5f00\u6210\u679c\u76ee\u5f55",
            command=self._open_run_dir,
        ).pack(side="left", padx=(8, 0))
        ttk.Button(
            actions, text="\u5173\u95ed", command=self.destroy
        ).pack(side="right")
        self._refresh()

    def _refresh(self) -> None:
        overview, self.sources = render_project_results(self.state)
        stage = (
            "\u6700\u7ec8\u6210\u679c"
            if self.state.status in FINAL_RUN_STATUSES
            else "\u9636\u6bb5\u6210\u679c"
        )
        self.summary_var.set(
            f"{stage} \u00b7 \u72b6\u6001 {self.state.status} \u00b7 "
            f"\u5df2\u53d1\u73b0 {len(self.sources)} \u4e2a\u6210\u679c\u6587\u4ef6"
        )
        self._populate_source_tree()
        if self.sources:
            self.source_tree.selection_set("0")
            self.source_tree.focus("0")
            self.source_tree.see("0")
            self._show_preview(preview_result_source(self.sources[0]))
        else:
            self._show_preview(overview)

    def _populate_source_tree(self, selected_path: Path | None = None) -> None:
        self.source_tree.delete(*self.source_tree.get_children())
        selected_iid = ""
        for index, source in enumerate(self.sources):
            try:
                updated = source.path.stat().st_mtime
                updated_text = datetime.fromtimestamp(updated).strftime(
                    "%Y-%m-%d %H:%M"
                )
            except OSError:
                updated_text = "未知"
            self.source_tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    source.title,
                    result_target_label(source),
                    source.kind,
                    human_file_size(source.size),
                    updated_text,
                ),
            )
            if selected_path is not None and source.path == selected_path:
                selected_iid = str(index)
        if selected_iid:
            self.source_tree.selection_set(selected_iid)
            self.source_tree.focus(selected_iid)
            self.source_tree.see(selected_iid)

    def _sort_source_tree(self, column: str) -> None:
        selected = self._selected_source()
        if self.source_sort_column == column:
            descending = not self.source_sort_descending
        else:
            descending = column in {"size", "updated"}
        self.source_sort_column = column
        self.source_sort_descending = descending
        for heading, label in self.source_heading_labels.items():
            self.source_tree.heading(heading, text=label)
        direction = "▼" if descending else "▲"
        self.source_tree.heading(
            column,
            text=f"{self.source_heading_labels[column]} {direction}",
        )
        self.sources.sort(
            key=lambda source: source_sort_key(source, column),
            reverse=descending,
        )
        self._populate_source_tree(selected.path if selected is not None else None)

    def _show_preview(self, content: str) -> None:
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", content)
        self.preview_urls_by_tag = {}
        for index, (start, end, url) in enumerate(preview_url_spans(content)):
            tag = f"preview_url_{index}"
            self.preview_urls_by_tag[tag] = url
            self.text.tag_add(tag, f"1.0 + {start} chars", f"1.0 + {end} chars")
            self.text.tag_configure(tag, foreground="#0563c1", underline=True)
        self.text.configure(state="disabled")

    def _preview_url_at(self, x: int, y: int) -> str:
        index = self.text.index(f"@{x},{y}")
        for tag in self.text.tag_names(index):
            url = self.preview_urls_by_tag.get(tag)
            if url:
                return url
        return ""

    def _preview_link_pressed(self, event: tk.Event) -> None:
        url = self._preview_url_at(event.x, event.y)
        self.preview_link_press = (url, event.x, event.y) if url else None

    def _preview_link_released(self, event: tk.Event) -> str | None:
        pressed = self.preview_link_press
        self.preview_link_press = None
        if pressed is None:
            return None
        url, start_x, start_y = pressed
        if (
            abs(event.x - start_x) <= 4
            and abs(event.y - start_y) <= 4
            and self._preview_url_at(event.x, event.y) == url
        ):
            self._open_preview_url(url)
            return "break"
        return None

    def _preview_link_motion(self, event: tk.Event) -> None:
        cursor = "hand2" if self._preview_url_at(event.x, event.y) else "xterm"
        self.text.configure(cursor=cursor)

    def _open_preview_url(self, url: str) -> None:
        try:
            os.startfile(url)
        except OSError as exc:
            messagebox.showerror(
                "打开地址",
                f"无法使用默认浏览器打开：\n{url}\n\n{exc}",
                parent=self,
            )

    def _preview_selected_source(self, _event: tk.Event | None = None) -> None:
        source = self._selected_source()
        if source is not None:
            self._show_preview(preview_result_source(source))

    def _manage_findings(self) -> None:
        dialog = FindingsDialog(self, self.run_dir)
        self.wait_window(dialog)
        if not dialog.result_saved:
            return
        try:
            regenerate_pentest_report(self.state)
        except OSError as exc:
            messagebox.showerror("结构化问题库", f"问题库已保存，但刷新报告失败：{exc}", parent=self)
        self._refresh()

    def _primary_source(self) -> ProjectResultSource | None:
        for name in ("pentest_report.md", "pentest_report.txt", "risk_summary.md"):
            source = next((item for item in self.sources if item.path.name == name), None)
            if source is not None:
                return source
        return None

    def _export_report(self) -> None:
        source = self._primary_source()
        if source is None:
            messagebox.showinfo("项目成果", "当前还没有可导出的报告。", parent=self)
            return
        suffix = source.path.suffix or ".md"
        destination = filedialog.asksaveasfilename(
            parent=self,
            title="导出渗透测试报告",
            defaultextension=suffix,
            initialfile=f"{self.state.project_name}_{self.state.run_id}_渗透测试报告{suffix}",
            filetypes=(("Markdown", "*.md"), ("文本文件", "*.txt"), ("所有文件", "*.*")),
        )
        if not destination:
            return
        try:
            shutil.copy2(source.path, destination)
        except OSError as exc:
            messagebox.showerror("导出报告", f"导出失败：{exc}", parent=self)
            return
        messagebox.showinfo("导出报告", f"报告已导出到：\n{destination}", parent=self)

    def _selected_source(self) -> ProjectResultSource | None:
        selection = self.source_tree.selection()
        if not selection:
            return None
        try:
            return self.sources[int(selection[0])]
        except (IndexError, TypeError, ValueError):
            return None

    def _open_selected_source(self) -> None:
        source = self._selected_source()
        if source is None:
            messagebox.showinfo(
                "\u9879\u76ee\u6210\u679c",
                "\u8bf7\u5148\u9009\u62e9\u4e00\u4e2a\u6210\u679c\u6587\u4ef6\u3002",
                parent=self,
            )
            return
        os.startfile(source.path)

    def _open_run_dir(self) -> None:
        os.startfile(self.run_dir)
