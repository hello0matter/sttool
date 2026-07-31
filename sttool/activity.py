from __future__ import annotations

import threading
from datetime import datetime
from pathlib import Path


ACTIVITY_LOG_NAME = "activity.log"
_WRITE_LOCK = threading.Lock()


def activity_log_path(run_dir: str | Path) -> Path:
    return Path(run_dir) / ACTIVITY_LOG_NAME


def append_activity(run_dir: str | Path, message: str) -> None:
    timestamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message.strip()}\n"
    path = activity_log_path(run_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _WRITE_LOCK, path.open("a", encoding="utf-8") as handle:
        handle.write(line)
        handle.flush()
