from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any

from .asset_bus import atomic_json_write, now_text


REPORT_FILES = (
    "findings.md",
    "cve_triage.md",
    "risk_summary.md",
    "pentest_report.md",
    "pentest_report.txt",
    "vulnerability_intel.md",
)
ANSI_ESCAPE_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
QUESTION_RUN_RE = re.compile(r"\?{3,}")
MOJIBAKE_MARKERS = (
    "Ã",
    "Â",
    "â€",
    "å",
    "æ",
    "ç",
    "è",
    "é",
    "ï¼",
    "ï½",
    "ã€",
    "ðŸ",
    "Ê",
    "£",
    "°",
    "§",
    "Ü",
    "�",
)


def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE_RE.sub("", text)


def _mojibake_score(text: str) -> int:
    return sum(text.count(marker) for marker in MOJIBAKE_MARKERS)


def _repair_line(line: str) -> str:
    best = line
    best_score = _mojibake_score(line)
    if best_score == 0:
        return line
    for source_encoding in ("cp1252", "latin1"):
        for target_encoding in ("utf-8", "gb18030"):
            try:
                candidate = line.encode(source_encoding).decode(target_encoding)
            except (UnicodeEncodeError, UnicodeDecodeError):
                continue
            candidate_score = _mojibake_score(candidate)
            if candidate_score < best_score:
                best = candidate
                best_score = candidate_score
    return best


def normalize_external_text(text: str) -> str:
    cleaned = strip_ansi(text)
    lines = cleaned.splitlines(keepends=True)
    return "".join(_repair_line(line) for line in lines)


def text_metrics(text: str) -> dict[str, int]:
    return {
        "question_runs": len(QUESTION_RUN_RE.findall(text)),
        "replacement_chars": text.count("�"),
        "mojibake_score": _mojibake_score(text),
        "ansi_sequences": len(ANSI_ESCAPE_RE.findall(text)),
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(131_072):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot_report_files(run_dir: Path, batch_dir: Path) -> dict[str, Any]:
    backup_dir = batch_dir / "report_backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    for name in REPORT_FILES:
        source = run_dir / name
        record: dict[str, Any] = {"name": name, "existed": source.is_file()}
        if source.is_file():
            destination = backup_dir / name
            shutil.copy2(source, destination)
            try:
                text = source.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                record["valid_utf8"] = False
            else:
                record["valid_utf8"] = True
                record["metrics"] = text_metrics(text)
            record["sha256"] = _sha256(source)
        records.append(record)
    manifest = {
        "schema_version": 1,
        "created_at": now_text(),
        "files": records,
    }
    atomic_json_write(backup_dir / "manifest.json", manifest)
    return manifest


def _is_deteriorated(before: dict[str, int], after: dict[str, int]) -> bool:
    return (
        after["question_runs"] > before.get("question_runs", 0)
        or after["replacement_chars"] > before.get("replacement_chars", 0)
        or after["mojibake_score"] > before.get("mojibake_score", 0) + 8
    )


def restore_corrupted_report_files(run_dir: Path, batch_dir: Path) -> dict[str, Any]:
    backup_dir = batch_dir / "report_backups"
    manifest_path = backup_dir / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"status": "not_available", "restored": [], "normalized": []}
    records = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(records, list):
        return {"status": "not_available", "restored": [], "normalized": []}

    quarantine = batch_dir / "rejected_report_writes"
    restored: list[str] = []
    normalized_files: list[str] = []
    details: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        name = str(record.get("name") or "")
        if name not in REPORT_FILES:
            continue
        current = run_dir / name
        if not current.is_file():
            continue
        try:
            original_text = current.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            original_text = ""
            invalid_utf8 = True
        else:
            invalid_utf8 = False
        normalized_text = normalize_external_text(original_text)
        if normalized_text != original_text and not invalid_utf8:
            current.write_text(normalized_text, encoding="utf-8")
            normalized_files.append(name)
        after_metrics = text_metrics(normalized_text)
        before_metrics = record.get("metrics") if isinstance(record.get("metrics"), dict) else {}
        corrupted = invalid_utf8 or _is_deteriorated(before_metrics, after_metrics)
        if not record.get("existed"):
            corrupted = corrupted or any(after_metrics.values())
        if not corrupted:
            continue
        quarantine.mkdir(parents=True, exist_ok=True)
        rejected = quarantine / f"{name}.corrupted"
        shutil.copy2(current, rejected)
        backup = backup_dir / name
        if record.get("existed") and backup.is_file():
            shutil.copy2(backup, current)
        else:
            current.unlink(missing_ok=True)
        restored.append(name)
        details.append(
            {
                "name": name,
                "invalid_utf8": invalid_utf8,
                "before": before_metrics,
                "after": after_metrics,
                "quarantine": str(rejected),
            }
        )
    result = {
        "schema_version": 1,
        "status": "restored" if restored else "clean",
        "checked_at": now_text(),
        "restored": restored,
        "normalized": normalized_files,
        "details": details,
    }
    atomic_json_write(batch_dir / "report_integrity.json", result)
    return result


__all__ = [
    "REPORT_FILES",
    "normalize_external_text",
    "restore_corrupted_report_files",
    "snapshot_report_files",
    "strip_ansi",
    "text_metrics",
]
