from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk

from .findings_store import (
    SEVERITIES,
    STATUSES,
    FindingRecord,
    load_findings,
    save_findings,
)


class FindingsDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc, run_dir: Path) -> None:
        super().__init__(parent)
        self.run_dir = run_dir
        self.records = load_findings(run_dir)
        self.current_index: int | None = None
        self.result_saved = False
        self.title("结构化问题库")
        self.geometry("1380x860")
        self.minsize(1050, 700)
        self.transient(parent)

        container = ttk.Frame(self, padding=12)
        container.pack(fill="both", expand=True)
        container.columnconfigure(1, weight=1)
        container.rowconfigure(1, weight=1)

        ttk.Label(
            container,
            text="人工问题库：已确认问题必须填写复现过程和证据，工具命中请先保持待验证。",
            font=("Microsoft YaHei UI", 11, "bold"),
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))

        left = ttk.Frame(container)
        left.grid(row=1, column=0, sticky="nsw", padx=(0, 12))
        left.rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(
            left,
            columns=("title", "severity", "status"),
            show="headings",
            selectmode="browse",
        )
        for column, label, width in (
            ("title", "问题标题", 250),
            ("severity", "风险", 80),
            ("status", "状态", 90),
        ):
            self.tree.heading(column, text=label)
            self.tree.column(column, width=width, minwidth=60)
        self.tree.grid(row=0, column=0, columnspan=3, sticky="nsew")
        self.tree.bind("<<TreeviewSelect>>", self._selection_changed)
        ttk.Button(left, text="新增", command=self._new).grid(row=1, column=0, sticky="ew", pady=(8, 0))
        ttk.Button(left, text="复制", command=self._duplicate).grid(row=1, column=1, sticky="ew", padx=6, pady=(8, 0))
        ttk.Button(left, text="删除", command=self._delete).grid(row=1, column=2, sticky="ew", pady=(8, 0))

        form = ttk.Frame(container)
        form.grid(row=1, column=1, sticky="nsew")
        form.columnconfigure(0, weight=1)
        form.columnconfigure(1, weight=1)
        form.rowconfigure(9, weight=1)

        self.title_var = tk.StringVar()
        self.severity_var = tk.StringVar(value="medium")
        self.status_var = tk.StringVar(value="待验证")
        self.type_var = tk.StringVar()
        self.cvss_var = tk.StringVar(value="N/A")
        self.parameter_var = tk.StringVar(value="-")
        self._entry(form, 0, 0, "问题标题", self.title_var, columnspan=2)
        self._combo(form, 2, 0, "风险等级", self.severity_var, SEVERITIES)
        self._combo(form, 2, 1, "状态", self.status_var, STATUSES)
        self._entry(form, 4, 0, "漏洞类型", self.type_var)
        self._entry(form, 4, 1, "CVSS", self.cvss_var)
        self._entry(form, 6, 0, "参数", self.parameter_var)
        ttk.Label(form, text="受影响资产（每行一个）").grid(row=6, column=1, sticky="w")
        self.affected_text = tk.Text(form, height=3, wrap="word")
        self.affected_text.grid(row=7, column=1, sticky="ew", pady=(4, 8))

        notebook = ttk.Notebook(form)
        notebook.grid(row=9, column=0, columnspan=2, sticky="nsew", pady=(4, 8))
        self.description_text = self._text_tab(notebook, "问题描述")
        self.reproduction_text = self._text_tab(notebook, "复现过程（每行一步）")
        self.evidence_text = self._text_tab(notebook, "证据（每行一个路径或说明）")
        self.remediation_text = self._text_tab(notebook, "修复建议（每行一项）")

        actions = ttk.Frame(container)
        actions.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(12, 0))
        ttk.Button(actions, text="保存当前编辑", command=self._save_current).pack(side="left")
        ttk.Button(actions, text="保存问题库并刷新报告", command=self._save_all).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="关闭", command=self.destroy).pack(side="right")

        self._refresh_tree()
        if self.records:
            self.tree.selection_set("0")
            self.tree.focus("0")
        else:
            self._new()

    @staticmethod
    def _entry(parent: ttk.Frame, row: int, column: int, label: str, variable: tk.StringVar, columnspan: int = 1) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=column, columnspan=columnspan, sticky="w")
        ttk.Entry(parent, textvariable=variable).grid(
            row=row + 1,
            column=column,
            columnspan=columnspan,
            sticky="ew",
            padx=(0, 8) if column == 0 and columnspan == 1 else 0,
            pady=(4, 8),
        )

    @staticmethod
    def _combo(parent: ttk.Frame, row: int, column: int, label: str, variable: tk.StringVar, values: tuple[str, ...]) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=column, sticky="w")
        ttk.Combobox(parent, textvariable=variable, values=values, state="readonly").grid(
            row=row + 1,
            column=column,
            sticky="ew",
            padx=(0, 8) if column == 0 else 0,
            pady=(4, 8),
        )

    @staticmethod
    def _text_tab(notebook: ttk.Notebook, title: str) -> scrolledtext.ScrolledText:
        frame = ttk.Frame(notebook, padding=8)
        text = scrolledtext.ScrolledText(frame, wrap="word", font=("Microsoft YaHei UI", 10))
        text.pack(fill="both", expand=True)
        notebook.add(frame, text=title)
        return text

    @staticmethod
    def _lines(widget: tk.Text) -> list[str]:
        return [line.strip() for line in widget.get("1.0", "end").splitlines() if line.strip()]

    @staticmethod
    def _set_text(widget: tk.Text, value: str | list[str]) -> None:
        widget.delete("1.0", "end")
        widget.insert("1.0", "\n".join(value) if isinstance(value, list) else value)

    def _refresh_tree(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for index, record in enumerate(self.records):
            self.tree.insert("", "end", iid=str(index), values=(record.title or "（未命名）", record.severity, record.status))

    def _selection_changed(self, _event: tk.Event[tk.Misc] | None = None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        index = int(selection[0])
        if self.current_index is not None and self.current_index != index:
            self._capture_current()
        self.current_index = index
        record = self.records[index]
        self.title_var.set(record.title)
        self.severity_var.set(record.severity)
        self.status_var.set(record.status)
        self.type_var.set(record.vuln_type)
        self.cvss_var.set(record.cvss)
        self.parameter_var.set(record.parameter)
        self._set_text(self.affected_text, record.affected)
        self._set_text(self.description_text, record.description)
        self._set_text(self.reproduction_text, record.reproduction)
        self._set_text(self.evidence_text, record.evidence)
        self._set_text(self.remediation_text, record.remediation)

    def _record_from_form(self, original: FindingRecord) -> FindingRecord:
        return FindingRecord(
            finding_id=original.finding_id,
            title=self.title_var.get().strip(),
            severity=self.severity_var.get(),
            status=self.status_var.get(),
            vuln_type=self.type_var.get().strip(),
            affected=self._lines(self.affected_text),
            parameter=self.parameter_var.get().strip() or "-",
            cvss=self.cvss_var.get().strip() or "N/A",
            description=self.description_text.get("1.0", "end").strip(),
            reproduction=self._lines(self.reproduction_text),
            evidence=self._lines(self.evidence_text),
            remediation=self._lines(self.remediation_text),
            source=original.source,
        )

    def _capture_current(self) -> FindingRecord | None:
        if self.current_index is None:
            return None
        record = self._record_from_form(self.records[self.current_index])
        self.records[self.current_index] = record
        return record

    def _save_current(self) -> bool:
        record = self._capture_current()
        if record is None:
            return True
        if not record.title or not record.vuln_type:
            messagebox.showwarning("结构化问题库", "问题标题和漏洞类型不能为空。", parent=self)
            return False
        if record.status == "已确认" and (not record.reproduction or not record.evidence):
            messagebox.showwarning(
                "结构化问题库",
                "已确认问题必须填写复现过程和证据；否则请先保持为“待验证”。",
                parent=self,
            )
            return False
        self._refresh_tree()
        self.tree.selection_set(str(self.current_index))
        return True

    def _new(self) -> None:
        if self.current_index is not None and not self._save_current():
            return
        self.records.append(FindingRecord.new())
        self._refresh_tree()
        index = len(self.records) - 1
        self.tree.selection_set(str(index))
        self.tree.focus(str(index))
        self.tree.see(str(index))
        self._selection_changed()

    def _duplicate(self) -> None:
        if self.current_index is None or not self._save_current():
            return
        source = self.records[self.current_index]
        duplicate = FindingRecord.from_dict(source.__dict__)
        duplicate.finding_id = FindingRecord.new().finding_id
        duplicate.title = f"{source.title}（副本）"
        self.records.append(duplicate)
        self._refresh_tree()
        index = len(self.records) - 1
        self.tree.selection_set(str(index))
        self._selection_changed()

    def _delete(self) -> None:
        if self.current_index is None:
            return
        if not messagebox.askyesno("结构化问题库", "确定删除当前问题吗？", parent=self):
            return
        del self.records[self.current_index]
        self.current_index = None
        self._refresh_tree()
        if self.records:
            index = min(len(self.records) - 1, 0)
            self.tree.selection_set(str(index))
            self._selection_changed()

    def _save_all(self) -> None:
        if not self._save_current():
            return
        try:
            save_findings(self.run_dir, self.records)
        except (OSError, ValueError) as exc:
            messagebox.showerror("结构化问题库", str(exc), parent=self)
            return
        self.result_saved = True
        messagebox.showinfo(
            "结构化问题库",
            "findings.json 和 findings.md 已保存。关闭窗口后项目报告会自动刷新。",
            parent=self,
        )
