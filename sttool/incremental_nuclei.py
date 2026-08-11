from __future__ import annotations

import subprocess
from pathlib import Path

from .asset_bus import AssetBus, now_text, target_assets
from .runtime import (
    CREATE_NEW_PROCESS_GROUP,
    CREATE_NO_WINDOW,
    process_creation_token,
)


INCREMENTAL_NUCLEI_BATCH_SIZE = 200


def initial_incremental_nuclei_urls(bus: AssetBus, target: str) -> list[str]:
    existing_urls = [str(value) for value in bus.bundle().get("urls", [])]
    if existing_urls:
        return existing_urls
    return [value for value, kind in target_assets(target) if kind == "url"]


def incremental_nuclei_candidates(
    bus: AssetBus,
    attempted_urls: list[object],
    *,
    limit: int = INCREMENTAL_NUCLEI_BATCH_SIZE,
) -> list[str]:
    attempted = {str(item) for item in attempted_urls}
    candidates = [
        str(value)
        for value in bus.bundle().get("urls", [])
        if str(value) not in attempted
    ]
    return list(dict.fromkeys(candidates))[: max(limit, 1)]


def build_incremental_nuclei_command(
    executable: Path, target_file: Path, output_file: Path
) -> list[str]:
    return [
        str(executable),
        "-l",
        str(target_file),
        "-silent",
        "-o",
        str(output_file),
    ]


def launch_incremental_nuclei(
    *,
    executable: Path,
    run_dir: Path,
    batch_number: int,
    targets: list[str],
) -> dict[str, object]:
    batch_dir = (
        run_dir / "tool_data" / "nuclei_incremental" / f"batch-{batch_number:04d}"
    )
    batch_dir.mkdir(parents=True, exist_ok=True)
    target_file = batch_dir / "targets.txt"
    output_file = batch_dir / "result.txt"
    log_file = batch_dir / "process.log"
    target_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
    command = build_incremental_nuclei_command(executable, target_file, output_file)
    with log_file.open("ab") as output:
        process = subprocess.Popen(
            command,
            cwd=str(run_dir),
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            creationflags=CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
            close_fds=True,
        )
    return {
        "batch": batch_number,
        "pid": process.pid,
        "creation_token": process_creation_token(process.pid),
        "targets": targets,
        "target_file": str(target_file),
        "output_file": str(output_file),
        "log_file": str(log_file),
        "command": command,
        "status": "running",
        "started_at": now_text(),
    }
