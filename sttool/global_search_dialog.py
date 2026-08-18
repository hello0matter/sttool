from __future__ import annotations

import os
import threading
import tkinter as tk
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk

from .run_log_dialog import redact_sensitive_text


MAX_FILE_BYTES = 8 * 1024 * 1024
SEARCH_LIMIT = 500
SKIP_NAMES = {"launcher_secrets.dat", "config.db", "config.db-shm", "config.db-wal"}
SKIP_DIRS = {".git", ".venv", "__pycache__", "app", "build", "dist", "node_modules", "venv"}
TEXT_SUFFIXES = {
    ".json", ".jsonl", ".log", ".md", ".txt", ".csv", ".yaml", ".yml",
    ".xml", ".html", ".htm", ".ini",
}


@dataclass(frozen=True)
class SearchHit:
    project: str
    run_id: str
    location: str
    path: Path
    line_number: int
    context: str
    modified_at: str


def _context(line: str, query: str, limit: int = 700) -> str:
    text = redact_sensitive_text(" ".join(line.strip().split()))
    if len(text) <= limit:
        return text
    index = text.casefold().find(query.casefold())
    start = max(index - 220, 0) if index >= 0 else 0
    prefix = "..." if start else ""
    return prefix + text[start : start + limit] + "..."


def _identity(path: Path, projects_dir: Path) -> tuple[str, str, str]:
    parts = path.relative_to(projects_dir).parts
    project = parts[0] if parts else "未知项目"
    run_id = ""
    if "runs" in parts:
        index = parts.index("runs")
        if index + 1 < len(parts):
            run_id = parts[index + 1]
    return project, run_id, "/".join(parts[1:]) or path.name


def _searchable(path: Path) -> bool:
    if path.name in SKIP_NAMES or path.suffix.casefold() in {".db", ".sqlite", ".sqlite3"}:
        return False
    return path.suffix.casefold() in TEXT_SUFFIXES or path.name == "scope.txt"


def _content_scope_matches(path: Path, scope: str) -> bool:
    name = path.name.casefold()
    parts = {part.casefold() for part in path.parts}
    if scope == "仅日志":
        return path.suffix.casefold() == ".log" or name in {"activity.log", "fscan.txt", "nuclei.txt"}
    if scope == "仅成果与报告":
        return bool(
            parts & {"results", "evidence", "component_logs", "agent_batches"}
            or any(token in name for token in ("finding", "report", "risk_summary", "cve"))
        )
    if scope == "仅配置与状态":
        return bool(
            name in {"project.json", "run.json", "scope.txt"}
            or "state" in name
            or "status" in name
        )
    return True


def _candidate_files(root: Path) -> list[Path]:
    candidates: list[Path] = []
    for current, directories, files in os.walk(root):
        directories[:] = [name for name in directories if name.casefold() not in SKIP_DIRS]
        current_path = Path(current)
        candidates.extend(current_path / name for name in files)
    return candidates


def search_project_files(
    projects_dir: Path,
    query: str,
    *,
    project_filter: str = "",
    content_scope: str = "全部记录",
    limit: int = SEARCH_LIMIT,
) -> list[SearchHit]:
    """Search readable project evidence while excluding secrets and databases."""
    needle = query.strip().casefold()
    if not needle or not projects_dir.is_dir():
        return []
    hits: list[SearchHit] = []
    selected_root = projects_dir
    if project_filter and project_filter != "全部项目":
        candidate = projects_dir / project_filter
        if candidate.is_dir():
            selected_root = candidate
    for path in _candidate_files(selected_root):
        if not _searchable(path) or not _content_scope_matches(path, content_scope):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            content = path.read_text(encoding="utf-8", errors="replace")
            modified = datetime.fromtimestamp(path.stat().st_mtime).strftime(
                "%Y-%m-%d %H:%M"
            )
        except OSError:
            continue
        project, run_id, location = _identity(path, projects_dir)
        for line_number, line in enumerate(content.splitlines(), 1):
            if needle not in line.casefold():
                continue
            hits.append(
                SearchHit(
                    project=project,
                    run_id=run_id,
                    location=location,
                    path=path,
                    line_number=line_number,
                    context=_context(line, needle),
                    modified_at=modified,
                )
            )
            if len(hits) >= limit:
                return hits
    return hits


class GlobalSearchDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(parent)
        self.projects_dir = parent.manager.projects_dir
        self.hits: list[SearchHit] = []
        self.searching = False
        self.search_token = 0
        self.title("全局搜索 - 项目、实例、日志和成果")
        self.geometry("1280x780")
        self.minsize(960, 600)
        self.transient(parent)
        root = ttk.Frame(self, padding=14)
        root.pack(fill="both", expand=True)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(2, weight=1)

        query_row = ttk.Frame(root)
        query_row.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        query_row.columnconfigure(0, weight=1)
        self.query_var = tk.StringVar()
        entry = ttk.Entry(query_row, textvariable=self.query_var)
        entry.grid(row=0, column=0, sticky="ew")
        entry.bind("<Return>", lambda _event: self._search())
        ttk.Button(query_row, text="搜索", command=self._search).grid(row=0, column=1, padx=(8, 0))
        ttk.Button(query_row, text="清空", command=self._clear).grid(row=0, column=2, padx=(8, 0))
        project_names = sorted(
            (path.name for path in self.projects_dir.iterdir() if path.is_dir()),
            key=str.casefold,
        ) if self.projects_dir.is_dir() else []
        self.project_var = tk.StringVar(value="全部项目")
        ttk.Combobox(
            query_row,
            textvariable=self.project_var,
            values=("全部项目", *project_names),
            state="readonly",
            width=18,
        ).grid(row=0, column=3, padx=(12, 0))
        self.scope_var = tk.StringVar(value="全部记录")
        ttk.Combobox(
            query_row,
            textvariable=self.scope_var,
            values=("全部记录", "仅日志", "仅成果与报告", "仅配置与状态"),
            state="readonly",
            width=16,
        ).grid(row=0, column=4, padx=(8, 0))
        self.status_var = tk.StringVar(
            value="可搜索：IP、域名、URL、事件 ID、漏洞编号、工具名、错误内容和告警关键词"
        )
        ttk.Label(root, textvariable=self.status_var, style="Muted.TLabel").grid(
            row=1, column=0, sticky="w", pady=(0, 8)
        )

        pane = ttk.Panedwindow(root, orient="vertical")
        pane.grid(row=2, column=0, sticky="nsew")
        top = ttk.Frame(pane)
        top.columnconfigure(0, weight=1)
        top.rowconfigure(0, weight=1)
        bottom = ttk.Frame(pane)
        bottom.columnconfigure(0, weight=1)
        bottom.rowconfigure(0, weight=1)
        pane.add(top, weight=3)
        pane.add(bottom, weight=2)
        scroll = ttk.Scrollbar(top, orient="vertical")
        self.tree = ttk.Treeview(
            top,
            columns=("project", "run", "location", "line", "modified", "context"),
            show="headings",
            yscrollcommand=scroll.set,
        )
        scroll.configure(command=self.tree.yview)
        for column, label, width in (
            ("project", "项目", 150), ("run", "运行实例", 155),
            ("location", "位置", 280), ("line", "行", 55),
            ("modified", "更新时间", 130), ("context", "匹配内容", 560),
        ):
            self.tree.heading(column, text=label)
            self.tree.column(column, width=width, minwidth=50)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        self.tree.bind("<<TreeviewSelect>>", self._show_selected)
        self.tree.bind("<Double-1>", lambda _event: self._open_file())
        self.preview = scrolledtext.ScrolledText(
            bottom, wrap="word", font=("Microsoft YaHei UI", 10), state="disabled"
        )
        self.preview.grid(row=0, column=0, sticky="nsew")
        actions = ttk.Frame(root)
        actions.grid(row=3, column=0, sticky="ew", pady=(8, 0))
        ttk.Button(actions, text="打开原始文件", command=self._open_file).pack(side="left")
        ttk.Button(actions, text="打开运行目录", command=self._open_run).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="复制路径", command=self._copy_path).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="关闭", command=self.destroy).pack(side="right")
        entry.focus_set()

    def _clear(self) -> None:
        self.query_var.set("")
        self.tree.delete(*self.tree.get_children())
        self._set_preview("")
        self.status_var.set("可搜索：IP、域名、URL、事件 ID、漏洞编号、工具名、错误内容和告警关键词")

    def _search(self) -> None:
        query = self.query_var.get().strip()
        if not query or self.searching:
            return
        self.searching = True
        self.search_token += 1
        token = self.search_token
        self.status_var.set("正在搜索项目文件，请稍候...")
        self.tree.delete(*self.tree.get_children())
        self._set_preview("")

        def worker() -> None:
            hits = search_project_files(
                self.projects_dir,
                query,
                project_filter=self.project_var.get(),
                content_scope=self.scope_var.get(),
            )
            self.after(0, lambda: self._finish(token, query, hits))

        threading.Thread(target=worker, daemon=True).start()

    def _finish(self, token: int, query: str, hits: list[SearchHit]) -> None:
        if token != self.search_token:
            return
        self.searching = False
        self.hits = hits
        for index, hit in enumerate(hits):
            self.tree.insert(
                "", "end", iid=str(index),
                values=(hit.project, hit.run_id or "项目配置", hit.location,
                        hit.line_number, hit.modified_at, hit.context),
            )
        suffix = "（已达到显示上限，请缩小关键词）" if len(hits) >= SEARCH_LIMIT else ""
        self.status_var.set(f"搜索“{query}”：找到 {len(hits)} 条匹配{suffix}")
        if hits:
            self.tree.selection_set("0")
            self.tree.focus("0")
            self._show_selected()

    def _selected(self) -> SearchHit | None:
        selection = self.tree.selection()
        if not selection:
            return None
        try:
            return self.hits[int(selection[0])]
        except (IndexError, ValueError):
            return None

    def _set_preview(self, text: str) -> None:
        self.preview.configure(state="normal")
        self.preview.delete("1.0", "end")
        self.preview.insert("1.0", text)
        self.preview.configure(state="disabled")

    def _show_selected(self, _event: tk.Event[tk.Misc] | None = None) -> None:
        hit = self._selected()
        if hit is None:
            self._set_preview("")
            return
        try:
            lines = hit.path.read_text(encoding="utf-8", errors="replace").splitlines()
            start = max(hit.line_number - 4, 1)
            end = min(hit.line_number + 4, len(lines))
            context = "\n".join(
                f"{number:>6}: {redact_sensitive_text(lines[number - 1])}"
                for number in range(start, end + 1)
            )
        except OSError as exc:
            context = f"读取失败：{exc}"
        self._set_preview(
            f"文件：{hit.path}\n项目：{hit.project}\n运行实例：{hit.run_id or '项目配置'}\n"
            f"匹配行：{hit.line_number}\n\n{context}"
        )

    def _open_file(self) -> None:
        hit = self._selected()
        if hit is None:
            messagebox.showinfo("全局搜索", "请先选择一条搜索结果", parent=self)
            return
        os.startfile(hit.path)

    def _open_run(self) -> None:
        hit = self._selected()
        if hit is None:
            messagebox.showinfo("全局搜索", "请先选择一条搜索结果", parent=self)
            return
        parts = hit.path.parts
        if "runs" in parts:
            index = parts.index("runs")
            path = Path(*parts[: index + 2])
        else:
            path = hit.path.parent
        if path.is_dir():
            os.startfile(path)

    def _copy_path(self) -> None:
        hit = self._selected()
        if hit is None:
            messagebox.showinfo("全局搜索", "请先选择一条搜索结果", parent=self)
            return
        self.clipboard_clear()
        self.clipboard_append(str(hit.path))
        self.update_idletasks()
