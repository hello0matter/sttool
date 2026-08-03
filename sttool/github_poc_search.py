from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
from pathlib import Path

from .asset_bus import atomic_json_write, now_text


def parse_find_gh_poc_output(text: str, query: str) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    for line in text.splitlines():
        cve_id, separator, url = line.partition(" - ")
        if not separator or not url.strip():
            continue
        value = {"cve_id": cve_id.strip().upper(), "url": url.strip(), "query": query}
        if value not in candidates:
            candidates.append(value)
    return candidates


def search_github_pocs(executable: Path, query: str, token: str) -> dict[str, object]:
    report: dict[str, object] = {
        "schema_version": 1,
        "generated_at": now_text(),
        "query": query,
        "status": "completed",
        "execution_policy": "metadata_only",
        "candidates": [],
    }
    if not executable.is_file():
        report["status"] = "unavailable"
        report["error"] = f"find-gh-poc executable not found: {executable}"
        return report
    if not token.strip():
        report["status"] = "skipped_no_token"
        report["detail"] = (
            "Set GITHUB_TOKEN or GH_TOKEN in the STTool process environment; "
            "the token is never written to project files or command arguments."
        )
        return report

    with tempfile.TemporaryDirectory(prefix="sttool-find-gh-poc-") as temporary:
        root = Path(temporary)
        token_path = root / "token.txt"
        raw_path = root / "results.txt"
        token_path.write_text(token.strip(), encoding="utf-8")
        try:
            completed = subprocess.run(
                [
                    str(executable),
                    "-token-file",
                    str(token_path),
                    "-query-string",
                    query,
                    "-o",
                    str(raw_path),
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=180,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            report["status"] = "failed"
            report["error"] = f"{type(exc).__name__}: {exc}"
            return report
        if completed.returncode != 0:
            report["status"] = "failed"
            report["error"] = (
                completed.stderr.strip()
                or completed.stdout.strip()
                or f"exit code {completed.returncode}"
            )[-1200:]
            return report
        raw = raw_path.read_text(encoding="utf-8", errors="replace") if raw_path.is_file() else ""
        report["candidates"] = parse_find_gh_poc_output(raw, query)
    report["candidate_count"] = len(report["candidates"])
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Safe metadata-only wrapper for trickest/find-gh-poc"
    )
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--query", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    token = os.environ.get("GITHUB_TOKEN", "").strip() or os.environ.get(
        "GH_TOKEN", ""
    ).strip()
    report = search_github_pocs(args.exe, args.query.strip(), token)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    atomic_json_write(args.output, report)
    return 1 if report.get("status") == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
