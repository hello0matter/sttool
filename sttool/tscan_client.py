"""Headless TscanClient adapter used by the STTool Tscan component.

The GUI build is a WebView2 application and cannot always expose a reliable
CDP endpoint.  TscanClient uses the same Tscan data/configuration but runs as
an ordinary child process, so this adapter keeps the STTool asset bus and
resume semantics without requiring a visible window or mouse automation.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

if __package__ in {None, ""}:
    from sttool.asset_bus import atomic_json_write
    from sttool.tool_network import proxy_url, settings_from_environment
    from sttool.tscan_automation import (
        filter_assets_by_scope,
        now_text,
        read_asset_bus_bundle,
        target_asset_bundle,
    )
else:
    from .asset_bus import atomic_json_write
    from .tool_network import proxy_url, settings_from_environment
    from .tscan_automation import (
        filter_assets_by_scope,
        now_text,
        read_asset_bus_bundle,
        target_asset_bundle,
    )


MODULES = ("port", "url", "poc")
POLL_SECONDS = 5.0


def _append_client_activity(state_path: Path, message: str) -> None:
    """Write a clearly labelled CLI event beside the legacy Tscan log."""
    try:
        run_dir = state_path.parents[2]
        line = (
            f"[{datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S')}] "
            f"TscanClient：{message.strip()}\n"
        )
        for path in (run_dir / "activity.log", state_path.parent / "activity.log"):
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(line)
    except (OSError, IndexError):
        pass


def _read_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _write_lines(path: Path, values: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(dict.fromkeys(values)) + ("\n" if values else ""), encoding="utf-8")


def _client_proxy() -> str:
    value = proxy_url(settings_from_environment())
    return value.replace("socks5h://", "socks5://", 1)


def _targets(bundle: dict[str, list[str]], workdir: Path) -> dict[str, Path]:
    paths = {
        "hosts": workdir / "hosts.txt",
        "urls": workdir / "urls.txt",
    }
    _write_lines(paths["hosts"], [*bundle.get("ips", [])])
    _write_lines(paths["urls"], [*bundle.get("urls", [])])
    return paths


def _module_args(module: str, paths: dict[str, Path], workdir: Path) -> list[str] | None:
    if module == "port":
        return ["-m", "port", "-hf", str(paths["hosts"]), "-o", str(workdir / "port.txt")]
    if module in {"url", "poc"}:
        if not paths["urls"].read_text(encoding="utf-8").strip():
            return None
        return ["-m", module, "-uf", str(paths["urls"]), "-o", str(workdir / f"{module}.txt")]
    return None


def _run_batch(
    client_exe: Path,
    workdir: Path,
    bundle: dict[str, list[str]],
    generation: int,
    state_path: Path,
    state: dict[str, object],
) -> dict[str, object]:
    paths = _targets(bundle, workdir)
    proxy = _client_proxy()
    results: dict[str, object] = {}
    for module in MODULES:
        args = _module_args(module, paths, workdir)
        if args is None:
            results[module] = {"status": "skipped", "reason": "本轮没有匹配资产"}
            continue
        command = [str(client_exe), "-pr", f"STTool-{generation}", "-nocolor", *args]
        if proxy:
            command.extend(["-proxy", proxy])
        state["current_module"] = module
        state["stage"] = f"running_{module}"
        state["status"] = "running"
        state["detail"] = f"TscanClient 正在执行第 {generation} 轮 {module} 阶段"
        state["updated_at"] = now_text()
        atomic_json_write(state_path, state)
        _append_client_activity(state_path, f"启动 {module} 阶段（第 {generation} 轮）")
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                cwd=client_exe.parent,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
        except OSError as exc:
            results[module] = {"status": "failed", "error": str(exc)}
            _append_client_activity(state_path, f"{module} 启动失败：{exc}")
            continue
        log_path = workdir / f"{module}.log"
        log_path.write_text(completed.stdout or "", encoding="utf-8")
        results[module] = {
            "status": "completed" if completed.returncode == 0 else "failed",
            "returncode": completed.returncode,
            "result": str(workdir / f"{module}.txt"),
            "log": str(log_path),
            "elapsed_seconds": round(time.monotonic() - started, 2),
        }
        state["updated_at"] = now_text()
        atomic_json_write(state_path, state)
        _append_client_activity(
            state_path,
            f"{module} 阶段结束，退出码 {completed.returncode}",
        )
    return results


def run(args: argparse.Namespace) -> int:
    state_path = args.state.resolve()
    workdir = state_path.parent / "client"
    workdir.mkdir(parents=True, exist_ok=True)
    previous = _read_json(state_path)
    consumed = int(previous.get("asset_bus_generation") or 0)
    state: dict[str, object] = {
        "schema_version": 3,
        "controller": "tscan_client",
        "status": "starting",
        "stage": "waiting_assets",
        "detail": "TscanClient 后台适配器正在等待获准资产",
        "created_at": previous.get("created_at") or now_text(),
        "updated_at": now_text(),
        "exe": str(args.client_exe.resolve()),
        "target": args.target,
        "project": args.project,
        "scope": args.scope,
        "asset_bus_generation": consumed,
        "stage_batches": previous.get("stage_batches", []),
        "modules": list(MODULES),
        "error": "",
        "current_module": "",
    }
    atomic_json_write(state_path, state)
    if not args.client_exe.is_file():
        state.update(status="failed", error=f"TscanClient executable not found: {args.client_exe}", updated_at=now_text())
        atomic_json_write(state_path, state)
        return 1

    initial = True
    try:
        while True:
            generation, bundle = read_asset_bus_bundle(
                args.asset_bus.resolve(), args.target, after_generation=0 if initial else consumed
            )
            bundle = filter_assets_by_scope(bundle, args.scope)
            if initial and not any(bundle.values()):
                bundle = filter_assets_by_scope(target_asset_bundle(args.target), args.scope)
            if generation > consumed or initial:
                if any(bundle.values()):
                    batch_number = len(state["stage_batches"]) + 1
                    batch_dir = workdir / f"batch-{batch_number:04d}"
                    state["stage"] = "processing_batch"
                    state["status"] = "running"
                    state["detail"] = (
                        f"TscanClient 已获取第 {batch_number} 轮获准资产，"
                        "准备执行 port/url/poc"
                    )
                    state["updated_at"] = now_text()
                    atomic_json_write(state_path, state)
                    _append_client_activity(
                        state_path,
                        f"开始第 {batch_number} 轮，获准资产："
                        f"{len(bundle['ips'])} IP / {len(bundle['urls'])} URL",
                    )
                    results = _run_batch(
                        args.client_exe.resolve(),
                        batch_dir,
                        bundle,
                        batch_number,
                        state_path,
                        state,
                    )
                    batches = state["stage_batches"]
                    if not isinstance(batches, list):
                        batches = []
                        state["stage_batches"] = batches
                    batches.append({"batch_id": f"client-{batch_number}", "generation": generation, "assets": bundle, "stages": results})
                    state.update(
                        stage="monitoring",
                        status="running",
                        current_module="",
                        detail="TscanClient 后台阶段已完成，等待新增获准资产",
                    )
                consumed = max(consumed, generation)
                initial = False
                state["asset_bus_generation"] = consumed
                state["updated_at"] = now_text()
                atomic_json_write(state_path, state)
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        state.update(status="stopped", stage="stopped", detail="TscanClient 已停止", updated_at=now_text())
        atomic_json_write(state_path, state)
        return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the authorized TscanClient workflow for STTool")
    parser.add_argument("--client-exe", type=Path, required=True)
    parser.add_argument("--target", default="")
    parser.add_argument("--project", default="")
    parser.add_argument("--scope", default="*")
    parser.add_argument("--state", type=Path, default=Path("tscan_state.json"))
    parser.add_argument("--asset-bus", type=Path, default=Path("asset_bus.json"))
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(run(parse_args()))
