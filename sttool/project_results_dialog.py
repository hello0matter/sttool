from __future__ import annotations

import json
import os
import shutil
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from .asset_bus import AssetBus
from .findings_dialog import FindingsDialog
from .models import RunState
from .pentest_report import write_pentest_report


FINAL_RUN_STATUSES = {"completed", "failed", "stopped", "exited"}


@dataclass(frozen=True)
class ProjectResultSource:
    label: str
    path: Path
    kind: str
    size: int


def _safe_file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _result_label(run_dir: Path, path: Path) -> str:
    try:
        relative = path.relative_to(run_dir)
    except ValueError:
        relative = path
    labels = {
        "pentest_report.md": "渗透测试报告（Markdown）",
        "pentest_report.txt": "渗透测试报告（TXT）",
        "risk_summary.md": "\u9879\u76ee\u98ce\u9669\u6210\u679c\u6458\u8981",
        "findings.json": "结构化问题库（JSON）",
        "findings.md": "结构化问题库（Markdown）",
        "cve_triage.md": "CVE \u5feb\u901f\u6392\u67e5",
        "vulnerability_intel.md": "\u6f0f\u6d1e\u60c5\u62a5\u4e0e PoC \u5019\u9009",
        "vulnerability_intel.json": "\u7ed3\u6784\u5316\u6f0f\u6d1e\u60c5\u62a5",
        "vulnx.json": "vulnx \u72ec\u7acb\u67e5\u8be2\u7ed3\u679c",
        "find_gh_poc.json": "GitHub PoC \u5019\u9009\u67e5\u8be2",
        "fscan.txt": "fscan \u7aef\u53e3\u4e0e\u7ad9\u70b9\u7ed3\u679c",
        "nuclei.txt": "nuclei \u6a21\u677f\u7ed3\u679c",
        "asset_commander_assets.json": "AssetCommander \u8d44\u4ea7\u7ed3\u679c",
    }
    return f"{labels.get(path.name, path.name)}  \u00b7  {relative}"


def project_result_sources(run_dir: Path) -> list[ProjectResultSource]:
    candidates: list[tuple[str, Path]] = [
        ("report", run_dir / "pentest_report.md"),
        ("report", run_dir / "pentest_report.txt"),
        ("summary", run_dir / "risk_summary.md"),
        ("finding", run_dir / "findings.json"),
        ("finding", run_dir / "findings.md"),
        ("triage", run_dir / "cve_triage.md"),
        ("intel", run_dir / "vulnerability_intel.md"),
        ("intel", run_dir / "results" / "vulnerability_intel.json"),
        ("intel", run_dir / "results" / "vulnx.json"),
        ("intel", run_dir / "results" / "find_gh_poc.json"),
        ("tool", run_dir / "results" / "fscan.txt"),
        ("tool", run_dir / "results" / "nuclei.txt"),
        ("asset", run_dir / "results" / "asset_commander_assets.json"),
        ("tool", run_dir / "tool_data" / "tscan" / "state.json"),
    ]
    for pattern, kind in (
        ("agent_batches/**/findings.md", "finding"),
        ("agent_batches/**/cve_triage.md", "triage"),
        ("agent_batches/**/*.md", "agent"),
    ):
        candidates.extend((kind, path) for path in sorted(run_dir.glob(pattern)))

    seen: set[Path] = set()
    sources: list[ProjectResultSource] = []
    for kind, path in candidates:
        normalized = path.resolve(strict=False)
        if normalized in seen or not path.is_file():
            continue
        seen.add(normalized)
        sources.append(
            ProjectResultSource(
                label=_result_label(run_dir, path),
                path=path,
                kind=kind,
                size=_safe_file_size(path),
            )
        )
    return sources


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
        f"# {state.project_name} - {stage}",
        "",
        f"- \u8fd0\u884c\u5b9e\u4f8b\uff1a{state.run_id}",
        f"- \u5f53\u524d\u72b6\u6001\uff1a{state.status}",
        f"- \u76ee\u6807\uff1a{state.target}",
        f"- \u6388\u6743\u8303\u56f4\uff1a{state.scope}",
        f"- \u66f4\u65b0\u65f6\u95f4\uff1a{state.updated_at}",
        "",
    ]
    if not sources:
        lines.extend(
            [
                "## \u5f53\u524d\u7ed3\u8bba",
                "",
                "\u5f53\u524d\u5c1a\u65e0\u53ef\u8bfb\u53d6\u7684\u9879\u76ee\u6210\u679c\u6587\u4ef6\u3002"
                "\u5de5\u5177\u53ef\u80fd\u4ecd\u5728\u7b49\u5f85\u8d44\u4ea7\u3001\u8fd0\u884c\u4e2d\uff0c"
                "\u6216\u672c\u8f6e\u5c1a\u672a\u5f62\u6210\u98ce\u9669\u7ebf\u7d22\u3002",
                "\u53ef\u70b9\u51fb\u201c\u5237\u65b0\u201d\u6301\u7eed\u67e5\u770b\uff1b"
                "\u5355\u4e2a\u5de5\u5177\u7684\u6267\u884c\u8fc7\u7a0b\u8bf7\u5230\u201c\u9879\u76ee\u65e5\u5fd7\u201d\u4e2d\u67e5\u770b\u3002",
            ]
        )
        return "\n".join(lines), sources

    lines.extend(["## \u6210\u679c\u6587\u4ef6", ""])
    for source in sources:
        size_text = (
            "\uff08\u7a7a\u6587\u4ef6\uff09"
            if source.size == 0
            else f"\uff08{source.size:,} \u5b57\u8282\uff09"
        )
        lines.append(f"- {source.label} {size_text}")

    primary = next(
        (item for item in sources if item.path.name == "pentest_report.md"), None
    )
    if primary is None:
        primary = next(
            (item for item in sources if item.path.name == "pentest_report.txt"), None
        )
    if primary is None:
        primary = next((item for item in sources if item.path.name == "risk_summary.md"), None)
    if primary is None:
        primary = next((item for item in sources if item.size > 0), sources[0])
    lines.extend(
        ["", f"## \u6c47\u603b\u9884\u89c8\uff1a{primary.path.name}", ""]
    )
    if primary.size == 0:
        lines.append(
            "\u8be5\u6210\u679c\u6587\u4ef6\u5f53\u524d\u4e3a\u7a7a\uff1b"
            "\u8fd9\u4e0d\u4ee3\u8868\u5de5\u5177\u6ca1\u6709\u8fd0\u884c\uff0c"
            "\u53ef\u5728\u9879\u76ee\u65e5\u5fd7\u67e5\u770b\u5176\u72b6\u6001\u548c\u7b49\u5f85\u539f\u56e0\u3002"
        )
    else:
        try:
            content = primary.path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            content = f"\u8bfb\u53d6\u6210\u679c\u6587\u4ef6\u5931\u8d25\uff1a{exc}"
        lines.append(compact_markdown(content))
    return "\n".join(lines).strip() + "\n", sources


class ProjectResultsDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc, state: RunState) -> None:
        super().__init__(parent)
        self.state = state
        self.run_dir = Path(state.run_dir)
        self.sources: list[ProjectResultSource] = []
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

        self.source_tree = ttk.Treeview(
            container,
            columns=("name", "kind", "size"),
            show="headings",
            height=7,
            selectmode="browse",
        )
        for column, label, width in (
            ("name", "\u6210\u679c\u6587\u4ef6\uff08\u53cc\u51fb\u6253\u5f00\uff09", 850),
            ("kind", "\u7c7b\u578b", 120),
            ("size", "\u5927\u5c0f", 130),
        ):
            self.source_tree.heading(column, text=label)
            self.source_tree.column(column, width=width, minwidth=80)
        self.source_tree.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        self.source_tree.bind(
            "<Double-1>", lambda _event: self._open_selected_source()
        )
        self.source_tree.bind("<Return>", lambda _event: self._open_selected_source())

        self.text = scrolledtext.ScrolledText(
            container,
            wrap="word",
            font=("Microsoft YaHei UI", 10),
            state="disabled",
        )
        self.text.grid(row=2, column=0, sticky="nsew")

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
            text="\u6253\u5f00\u9009\u4e2d\u6210\u679c",
            command=self._open_selected_source,
        ).pack(side="left", padx=(8, 0))
        ttk.Button(
            actions,
            text="\u6253\u5f00\u6e17\u900f\u6d4b\u8bd5\u62a5\u544a",
            command=self._open_primary,
        ).pack(side="left", padx=(8, 0))
        ttk.Button(
            actions,
            text="导出报告",
            command=self._export_report,
        ).pack(side="left", padx=(8, 0))
        ttk.Button(
            actions,
            text="打开证据目录",
            command=self._open_evidence_dir,
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
        content, self.sources = render_project_results(self.state)
        stage = (
            "\u6700\u7ec8\u6210\u679c"
            if self.state.status in FINAL_RUN_STATUSES
            else "\u9636\u6bb5\u6210\u679c"
        )
        self.summary_var.set(
            f"{stage} \u00b7 \u72b6\u6001 {self.state.status} \u00b7 "
            f"\u5df2\u53d1\u73b0 {len(self.sources)} \u4e2a\u6210\u679c\u6587\u4ef6"
        )
        self.source_tree.delete(*self.source_tree.get_children())
        for index, source in enumerate(self.sources):
            self.source_tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    source.label,
                    source.kind,
                    f"{source.size:,} \u5b57\u8282",
                ),
            )
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", content)
        self.text.configure(state="disabled")

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

    def _open_evidence_dir(self) -> None:
        path = self.run_dir / "evidence"
        path.mkdir(parents=True, exist_ok=True)
        os.startfile(path)

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

    def _open_primary(self) -> None:
        primary = self._primary_source()
        if primary is None:
            messagebox.showinfo(
                "\u9879\u76ee\u6210\u679c",
                "\u9879\u76ee\u6e17\u900f\u6d4b\u8bd5\u62a5\u544a\u5c1a\u672a\u751f\u6210\u3002",
                parent=self,
            )
            return
        os.startfile(primary.path)

    def _open_run_dir(self) -> None:
        os.startfile(self.run_dir)
