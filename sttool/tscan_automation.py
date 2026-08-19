from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import winreg
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import psutil
from playwright.sync_api import Locator, Page, sync_playwright

from sttool.tool_network import webview_proxy_argument


CREATE_NEW_PROCESS_GROUP = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
POLICY_PATH = r"Software\Policies\Microsoft\Edge\WebView2\AdditionalBrowserArguments"
POLICY_NAME = "TscanPlus_Win_Amd64.exe"
DEFAULT_EXE = Path(r"D:\tmp\anjian\pj\st\TscanPlus_Win_Amd64\TscanPlus_Win_Amd64.exe")

PASSWORD_CRACK = "\u5bc6\u7801\u7834\u89e3"
POC_CHECK = "POC\u68c0\u6d4b"
PORT_FINGERPRINT = "\u7aef\u53e3\u6307\u7eb9"
ENABLE_PROXY = "\u5f00\u542f\u4ee3\u7406"
WEB_FINGERPRINT = "Web\u6307\u7eb9"
PORT_SCAN = "\u7aef\u53e3\u626b\u63cf"
FINGERPRINT_IDENTIFICATION = "\u6307\u7eb9\u8bc6\u522b"
ONLY_ONE_ACCOUNT = "\u4ec5\u7834\u89e3\u4e00\u4e2a\u8d26\u6237"
ASSET_WAIT_SECONDS = 1.0
CDP_START_TIMEOUT_SECONDS = 90.0
DISCOVERY_STALL_RECOVERY_SECONDS = 600.0
STAGE_RETRY_DELAY_SECONDS = 60.0
STAGE_RETRY_LIMIT = 3
RETRYABLE_STAGE_STATUSES = {"failed", "not_started"}
DISCOVERY_STOP_METHODS = {
    "ipscan": "IpScanStop",
    "urlscan": "UrlScanStop",
    "subdomain": "SubDomainStop",
    "dirscan": "DirScanStop",
    "jsfinder": "JsFinderStop",
}


_TSCAN_RUNTIME_TABLES = {
    "awvs",
    "bypass",
    "cyber",
    "dirscan",
    "hostcrack",
    "icpinfo",
    "info",
    "ipscan",
    "jsfinder",
    "nessus",
    "poccheck",
    "pwdcrack",
    "subdomain",
    "swagger",
    "unauth",
    "urlscan",
}
_TSCAN_PROJECT_RESET_FIELDS = {
    "TaskDomain": "",
    "TaskIp": "",
    "TaskUrl": "",
    "IpScanTarget": "",
    "UrlScanTarget": "",
    "SubDomainTarget": "",
    "PocTarget": "",
    "PwdTarget": "",
    "CyberTarget": "",
    "DirTarget": "",
    "JsTarget": "",
    "BypassTarget": "",
    "HostTargetIp": "",
    "HostTargetSub": "",
    "IpScanResume": "",
    "UrlScanResume": "",
    "SubDomainResume": "",
    "PocResume": "",
    "PwdResume": "",
    "DirResume": "",
    "JsResume": "",
    "InfoResume": "",
    "DirAsset": "",
    "VulInfo": "",
    "AssertNum": 0,
    "VulNum": 0,
    "Status": "",
}


def sanitize_tscan_database(path: Path) -> None:
    if not path.is_file():
        return
    connection = sqlite3.connect(path)
    try:
        tables = {
            str(row[0])
            for row in connection.execute(
                "select name from sqlite_master where type='table'"
            )
        }
        for table in sorted(_TSCAN_RUNTIME_TABLES & tables):
            connection.execute(f'DELETE FROM "{table}"')
        if "sqlite_sequence" in tables:
            placeholders = ",".join("?" for _ in _TSCAN_RUNTIME_TABLES)
            connection.execute(
                f"DELETE FROM sqlite_sequence WHERE name IN ({placeholders})",
                tuple(sorted(_TSCAN_RUNTIME_TABLES)),
            )
        if "project" in tables:
            columns = {
                str(row[1])
                for row in connection.execute('pragma table_info("project")')
            }
            updates = [
                (name, value)
                for name, value in _TSCAN_PROJECT_RESET_FIELDS.items()
                if name in columns
            ]
            if updates:
                assignments = ", ".join(f'"{name}" = ?' for name, _value in updates)
                connection.execute(
                    f'UPDATE "project" SET {assignments}',
                    tuple(value for _name, value in updates),
                )
        connection.commit()
    finally:
        connection.close()
    for suffix in ("-wal", "-shm"):
        try:
            Path(str(path) + suffix).unlink()
        except FileNotFoundError:
            pass


def _copy_or_link(source: Path, destination: Path, *, private: bool = False) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        return
    if private:
        shutil.copy2(source, destination)
        return
    try:
        os.link(source, destination)
    except OSError:
        shutil.copy2(source, destination)


def prepare_tscan_workspace(source_exe: Path, state_path: Path) -> Path:
    source_root = source_exe.resolve().parent
    workspace = state_path.resolve().parent / "app"
    workspace.mkdir(parents=True, exist_ok=True)
    unique_name = f"TscanPlus_{state_path.parents[2].name}.exe"
    runtime_exe = workspace / unique_name
    _copy_or_link(source_exe.resolve(), runtime_exe)

    (workspace / "Awvs").mkdir(parents=True, exist_ok=True)
    for directory_name in ("config", "ToolKit"):
        source_directory = source_root / directory_name
        if not source_directory.is_dir():
            continue
        for source in source_directory.rglob("*"):
            relative = source.relative_to(source_root)
            destination = workspace / relative
            if source.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            lower_name = source.name.lower()
            toolkit_result = relative.as_posix().lower() == "toolkit/fscan/result.txt"
            private = (
                toolkit_result
                or lower_name.startswith("config.db")
                or lower_name.startswith("config.yaml")
                or lower_name.endswith(".tmp")
            )
            if lower_name in {"config.db-wal", "config.db-shm"}:
                continue
            _copy_or_link(source, destination, private=private)
            if toolkit_result:
                destination.write_text("", encoding="utf-8")
    (workspace / "ScreenShot").mkdir(exist_ok=True)
    database = workspace / "config" / "config.db"
    initialized = workspace / ".sttool_initialized"
    if not initialized.exists():
        sanitize_tscan_database(database)
        initialized.write_text(now_text() + "\n", encoding="utf-8")
    return runtime_exe


def now_text() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def atomic_json_write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        for attempt, delay in enumerate((0.0, 0.02, 0.05, 0.1, 0.25, 0.5, 1.0)):
            if delay:
                time.sleep(delay)
            try:
                os.replace(temporary, path)
                break
            except PermissionError:
                if attempt == 6:
                    raise
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def read_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def scope_allows_all(scope: str) -> bool:
    return scope.strip() == "*"


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value.strip() for value in values if value.strip()))


def _host_from_value(value: str) -> str:
    raw = value.strip()
    if not raw:
        return ""
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    return (parsed.hostname or "").strip(".").lower()


def _scope_rules(scope: str) -> tuple[list[ipaddress._BaseNetwork], list[str]]:
    networks: list[ipaddress._BaseNetwork] = []
    domains: list[str] = []
    for token in re.split(r"[\s,;]+", scope.strip()):
        if not token or token == "*":
            continue
        host = _host_from_value(token)
        try:
            network_value = token.split("://", 1)[-1].split("/", 1)
            if len(network_value) == 2 and host:
                networks.append(
                    ipaddress.ip_network(
                        f"{host}/{network_value[1]}", strict=False
                    )
                )
                continue
            networks.append(ipaddress.ip_network(host, strict=False))
            continue
        except ValueError:
            pass
        if host:
            domains.append(host)
    return networks, _unique(domains)


def _host_allowed(host: str, scope: str) -> bool:
    if scope_allows_all(scope):
        return True
    networks, domains = _scope_rules(scope)
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return any(host == domain or host.endswith(f".{domain}") for domain in domains)
    return any(address in network for network in networks)


def target_asset_bundle(target: str) -> dict[str, list[str]]:
    host = _host_from_value(target)
    ips: list[str] = []
    domains: list[str] = []
    urls: list[str] = []
    endpoints: list[str] = []
    if host:
        try:
            ipaddress.ip_address(host)
            ips.append(host)
        except ValueError:
            domains.append(host)
    if target.strip().lower().startswith(("http://", "https://")):
        urls.append(target.strip())
    parsed = urlsplit(target if "://" in target else f"//{target}")
    try:
        port = parsed.port
    except ValueError:
        port = None
    if host and port is not None:
        endpoints.append(f"{host}:{port}")
    return {
        "ips": ips,
        "domains": domains,
        "endpoints": endpoints,
        "urls": urls,
    }


def read_asset_bundle(path: Path, target: str = "") -> dict[str, list[str]]:
    value = read_json(path)
    fallback = target_asset_bundle(target)
    bundle: dict[str, list[str]] = {}
    for key in ("ips", "domains", "endpoints", "urls"):
        raw_values = value.get(key, [])
        values = raw_values if isinstance(raw_values, list) else []
        bundle[key] = _unique([*fallback[key], *(str(item) for item in values)])
    return bundle




def read_asset_bus_bundle(
    path: Path,
    target: str = "",
    after_generation: int = 0,
) -> tuple[int, dict[str, list[str]]]:
    value = read_json(path)
    generation = int(value.get("generation") or 0)
    fallback = target_asset_bundle(target) if after_generation <= 0 else {
        "ips": [],
        "domains": [],
        "endpoints": [],
        "urls": [],
    }
    result = {key: list(values) for key, values in fallback.items()}
    mapping = {
        "ip": "ips",
        "domain": "domains",
        "endpoint": "endpoints",
        "url": "urls",
    }
    assets = value.get("assets", [])
    if isinstance(assets, list):
        for item in assets:
            if not isinstance(item, dict):
                continue
            if int(item.get("first_generation") or 0) <= after_generation:
                continue
            key = mapping.get(str(item.get("type") or ""))
            asset_value = str(item.get("value") or "")
            if key and asset_value:
                result[key].append(asset_value)
    return generation, {key: _unique(values) for key, values in result.items()}


def read_asset_bus_generation_range(
    path: Path, generation_from: int, generation_to: int
) -> dict[str, list[str]]:
    value = read_json(path)
    result = {"ips": [], "domains": [], "endpoints": [], "urls": []}
    mapping = {
        "ip": "ips",
        "domain": "domains",
        "endpoint": "endpoints",
        "url": "urls",
    }
    assets = value.get("assets", [])
    if not isinstance(assets, list):
        return result
    for item in assets:
        if not isinstance(item, dict):
            continue
        generation = int(item.get("first_generation") or 0)
        if not generation_from <= generation <= generation_to:
            continue
        key = mapping.get(str(item.get("type") or ""))
        asset_value = str(item.get("value") or "")
        if key and asset_value:
            result[key].append(asset_value)
    return {key: _unique(values) for key, values in result.items()}


def merge_asset_bundles(*bundles: dict[str, list[str]]) -> dict[str, list[str]]:
    return {
        key: _unique(
            [value for bundle in bundles for value in bundle.get(key, [])]
        )
        for key in ("ips", "domains", "endpoints", "urls")
    }


def filter_assets_by_scope(
    bundle: dict[str, list[str]], scope: str
) -> dict[str, list[str]]:
    result = {"ips": [], "domains": [], "endpoints": [], "urls": []}
    for value in bundle.get("ips", []):
        host = _host_from_value(value)
        try:
            ipaddress.ip_address(host)
        except ValueError:
            continue
        if _host_allowed(host, scope):
            result["ips"].append(host)
    for value in bundle.get("domains", []):
        host = _host_from_value(value)
        if not host:
            continue
        try:
            ipaddress.ip_address(host)
            continue
        except ValueError:
            pass
        if _host_allowed(host, scope):
            result["domains"].append(host)
    for value in bundle.get("endpoints", []):
        host = _host_from_value(value)
        parsed = urlsplit(f"//{value.strip()}")
        try:
            port = parsed.port
        except ValueError:
            port = None
        if host and port is not None and _host_allowed(host, scope):
            result["endpoints"].append(f"{host}:{port}")
    for value in bundle.get("urls", []):
        host = _host_from_value(value)
        if host and _host_allowed(host, scope):
            result["urls"].append(value.strip())
    return {key: _unique(values) for key, values in result.items()}


def normalize_poc_urls(
    urls: list[str], domains: list[str], primary_target: str = ""
) -> list[str]:
    values = list(urls)
    if primary_target.strip().lower().startswith(("http://", "https://")):
        values.insert(0, primary_target.strip())
    for domain in domains:
        values.extend((f"https://{domain}", f"http://{domain}"))
    normalized: list[str] = []
    for value in values:
        raw = value.strip()
        if not raw:
            continue
        if "://" not in raw:
            raw = f"http://{raw}"
        parsed = urlsplit(raw)
        if parsed.scheme in {"http", "https"} and parsed.hostname:
            normalized.append(raw)
    return _unique(normalized)


def awvs_site_targets(urls: list[str], primary_target: str = "") -> list[str]:
    primary = primary_target.strip()
    primary_parsed = urlsplit(primary)
    primary_origin = ""
    if primary_parsed.scheme in {"http", "https"} and primary_parsed.hostname:
        primary_origin = _url_origin(primary_parsed)

    targets: list[str] = []
    seen_origins: set[str] = set()
    for value in normalize_poc_urls(urls, [], ""):
        parsed = urlsplit(value)
        origin = _url_origin(parsed)
        if not origin or origin in seen_origins:
            continue
        seen_origins.add(origin)
        if origin == primary_origin:
            targets.append(primary.split("#", 1)[0].split("?", 1)[0])
        else:
            targets.append(f"{origin}/")
    return targets


def dispatched_awvs_targets(
    state: dict[str, object], primary_target: str = ""
) -> set[str]:
    dispatched: set[str] = set()
    batches = state.get("stage_batches")
    if not isinstance(batches, list):
        return dispatched
    for batch in batches:
        if not isinstance(batch, dict):
            continue
        assets = batch.get("assets")
        if not isinstance(assets, dict):
            continue
        urls = assets.get("urls")
        if not isinstance(urls, list):
            continue
        dispatched.update(
            awvs_site_targets([str(value) for value in urls], primary_target)
        )
    return dispatched


def _url_origin(parsed) -> str:
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    try:
        port = parsed.port
    except ValueError:
        return ""
    default_port = (parsed.scheme == "http" and port in {None, 80}) or (
        parsed.scheme == "https" and port in {None, 443}
    )
    authority = host if default_port else f"{host}:{port}"
    return f"{parsed.scheme}://{authority}"


def web_fingerprint_targets(urls: list[str], domains: list[str], target: str) -> list[str]:
    values: list[str] = []
    for value in normalize_poc_urls(urls, domains, target):
        parsed = urlsplit(value)
        if not parsed.hostname:
            continue
        host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        try:
            port = parsed.port
        except ValueError:
            port = None
        default = (parsed.scheme == "http" and port == 80) or (
            parsed.scheme == "https" and port == 443
        )
        values.append(host if port is None or default else f"{host}:{port}")
    return _unique(values)


PASSWORD_SERVICE_PORTS = {
    21, 22, 23, 25, 110, 143, 445, 1433, 1521, 3306, 3389, 5432,
    5900, 6379, 9200, 11211, 27017,
}
UNAUTHORIZED_SERVICE_PORTS = PASSWORD_SERVICE_PORTS | {
    53, 111, 135, 139, 161, 389, 873, 1080, 2049, 2375, 2181,
    5000, 5601, 7001, 8080, 8081, 8443, 9000, 9090, 15672,
}


def service_targets(endpoints: list[str], allowed_ports: set[int]) -> list[str]:
    targets: list[str] = []
    for value in endpoints:
        host = _host_from_value(value)
        parsed = urlsplit(f"//{value.strip()}")
        try:
            port = parsed.port
        except ValueError:
            port = None
        if not host or port not in allowed_ports:
            continue
        targets.append(host)
    return _unique(targets)


def password_targets(endpoints: list[str]) -> list[str]:
    return service_targets(endpoints, PASSWORD_SERVICE_PORTS)


def unauthorized_targets(endpoints: list[str]) -> list[str]:
    return service_targets(endpoints, UNAUTHORIZED_SERVICE_PORTS)


def endpoints_without_web_evidence(
    endpoints: list[str], urls: list[str]
) -> list[str]:
    web_endpoints: set[tuple[str, int]] = set()
    for value in urls:
        parsed = urlsplit(value if "://" in value else f"//{value}")
        host = (parsed.hostname or "").lower()
        try:
            port = parsed.port
        except ValueError:
            port = None
        if host and port is None and parsed.scheme in {"http", "https"}:
            port = 443 if parsed.scheme == "https" else 80
        if host and port is not None:
            web_endpoints.add((host, port))

    result: list[str] = []
    for value in endpoints:
        parsed = urlsplit(f"//{value.strip()}")
        host = (parsed.hostname or "").lower()
        try:
            port = parsed.port
        except ValueError:
            port = None
        if host and port is not None and (host, port) not in web_endpoints:
            result.append(value)
    return _unique(result)


def build_stage_plan(
    target: str, assets: dict[str, list[str]]
) -> dict[str, list[str]]:
    ips = assets.get("ips", [])
    domains = assets.get("domains", [])
    endpoints = assets.get("endpoints", [])
    urls = assets.get("urls", [])
    service_endpoints = endpoints_without_web_evidence(endpoints, urls)
    explicit_web_targets = normalize_poc_urls(urls, [], target)
    endpoint_hosts = {_host_from_value(value) for value in endpoints}
    identification_only = [
        value for value in ips if _host_from_value(value) not in endpoint_hosts
    ]
    return {
        "asset_targets": _unique(
            [target_for_asset_scan(target), *domains, *ips]
        ),
        "web_targets": explicit_web_targets,
        "awvs_targets": awvs_site_targets(urls, target),
        "fingerprint_targets": web_fingerprint_targets(urls, [], target),
        "subdomain_targets": root_domains(domains),
        "unauthorized_targets": unauthorized_targets(service_endpoints),
        "password_targets": password_targets(service_endpoints),
        # Nessus is intentionally deferred until it has an explicit configured
        # second-stage policy. Basic asset identification must not fan out into
        # a costly scan of every newly discovered host.
        "nessus_targets": [],
        "deferred_nessus_targets": _unique([*domains, *ips]),
        "identification_only": _unique(identification_only),
    }


def retryable_stage_names(result: dict[str, object]) -> list[str]:
    stages = result.get("stages")
    if not isinstance(stages, dict):
        return []
    return [
        str(name)
        for name, value in stages.items()
        if isinstance(value, dict)
        and str(value.get("status") or "") in RETRYABLE_STAGE_STATUSES
    ]


def stage_batch_record(
    *,
    batch_id: str,
    generation_from: int,
    generation_to: int,
    assets: dict[str, list[str]],
    result: dict[str, object],
    now: float | None = None,
) -> dict[str, object]:
    pending = retryable_stage_names(result)
    return {
        "batch_id": batch_id,
        "generation_from": generation_from,
        "generation_to": generation_to,
        "dispatched_at": now_text(),
        "assets": {key: list(values) for key, values in assets.items()},
        "result": result,
        "pending_stages": pending,
        "retry_count": 0,
        "next_retry_at": (now if now is not None else time.time())
        + STAGE_RETRY_DELAY_SECONDS
        if pending
        else 0.0,
        "retry_attempts": [],
    }


def retry_batch_due(
    batches: list[object], now: float | None = None
) -> dict[str, object] | None:
    current = time.time() if now is None else now
    for value in batches:
        if not isinstance(value, dict):
            continue
        pending = value.get("pending_stages")
        if not isinstance(pending, list) or not pending:
            continue
        if int(value.get("retry_count") or 0) >= STAGE_RETRY_LIMIT:
            continue
        if float(value.get("next_retry_at") or 0.0) <= current:
            return value
    return None


def record_stage_retry(
    batch: dict[str, object],
    result: dict[str, object],
    now: float | None = None,
) -> None:
    current = time.time() if now is None else now
    retry_count = int(batch.get("retry_count") or 0) + 1
    pending = retryable_stage_names(result)
    attempts = batch.get("retry_attempts")
    if not isinstance(attempts, list):
        attempts = []
        batch["retry_attempts"] = attempts
    attempts.append(
        {
            "attempt": retry_count,
            "attempted_at": now_text(),
            "stages": list(result.get("stages", {})),
            "result": result,
        }
    )
    batch["retry_count"] = retry_count
    batch["pending_stages"] = pending
    batch["next_retry_at"] = (
        current + STAGE_RETRY_DELAY_SECONDS
        if pending and retry_count < STAGE_RETRY_LIMIT
        else 0.0
    )
    if pending and retry_count >= STAGE_RETRY_LIMIT:
        batch["retry_exhausted_at"] = now_text()


def restore_dispatched_automation(
    previous: dict[str, object],
) -> tuple[bool, object, object]:
    automation = previous.get("automation")
    stages = previous.get("stages", {})
    batches = previous.get("stage_batches")
    dispatched = bool(previous.get("automation_dispatched", False))
    if not isinstance(batches, list) or not batches:
        return dispatched, automation, stages
    dispatched = True
    if isinstance(automation, dict) and isinstance(stages, dict) and stages:
        return dispatched, automation, stages
    for value in reversed(batches):
        if not isinstance(value, dict):
            continue
        result = value.get("result")
        if not isinstance(result, dict):
            continue
        automation = result
        result_stages = result.get("stages")
        if isinstance(result_stages, dict):
            stages = result_stages
        break
    return dispatched, automation, stages


def reconcile_interrupted_stage_retry(state: dict[str, object]) -> bool:
    active_batch_id = str(state.get("active_batch_id") or "")
    match = re.fullmatch(r"(.+)-retry-(\d+)", active_batch_id)
    if match is None:
        return False
    batch_id, attempt_text = match.groups()
    attempt = int(attempt_text)
    batches = state.get("stage_batches")
    stages = state.get("stages")
    if not isinstance(batches, list) or not isinstance(stages, dict):
        return False
    for value in batches:
        if not isinstance(value, dict) or str(value.get("batch_id") or "") != batch_id:
            continue
        retry_count = int(value.get("retry_count") or 0)
        if attempt <= retry_count:
            return False
        pending = value.get("pending_stages")
        if not isinstance(pending, list) or not pending:
            return False
        recovered_stages: dict[str, object] = {}
        for name in (str(item) for item in pending):
            stage = stages.get(name)
            recovered_stages[name] = (
                stage
                if isinstance(stage, dict)
                else {
                    "status": "failed",
                    "error": "Tscan 窗口在该阶段完成前关闭",
                }
            )
        result: dict[str, object] = {
            "batch_id": active_batch_id,
            "requested_stages": list(pending),
            "stages": recovered_stages,
            "interrupted": True,
        }
        record_stage_retry(value, result)
        state["automation"] = result
        state["stages"] = recovered_stages
        state["active_batch_id"] = ""
        return True
    return False


def migrate_stage_batch_retries(
    batches: list[object],
    asset_bus: Path,
    scope: str,
    now: float | None = None,
) -> bool:
    current = time.time() if now is None else now
    changed = False
    for value in batches:
        if not isinstance(value, dict) or isinstance(value.get("assets"), dict):
            continue
        result = value.get("result")
        if not isinstance(result, dict):
            continue
        try:
            generation_from = int(value.get("generation_from") or 0)
            generation_to = int(value.get("generation_to") or 0)
        except (TypeError, ValueError):
            continue
        assets = filter_assets_by_scope(
            read_asset_bus_generation_range(
                asset_bus, generation_from, generation_to
            ),
            scope,
        )
        pending = retryable_stage_names(result)
        value.update(
            assets=assets,
            pending_stages=pending,
            retry_count=0,
            next_retry_at=(current + STAGE_RETRY_DELAY_SECONDS if pending else 0.0),
            retry_attempts=[],
            retry_state_migrated_at=now_text(),
        )
        changed = True
    return changed


def refresh_stage_batch_scope(
    batches: list[object], scope: str, now: float | None = None
) -> bool:
    current = time.time() if now is None else now
    changed = False
    for value in batches:
        if not isinstance(value, dict):
            continue
        assets = value.get("assets")
        if not isinstance(assets, dict):
            continue
        filtered = filter_assets_by_scope(assets, scope)
        normalized = {
            key: list(assets.get(key, []))
            for key in ("ips", "domains", "endpoints", "urls")
        }
        if filtered == normalized and value.get("processing_scope") == scope:
            continue
        value["assets"] = filtered
        value["processing_scope"] = scope
        result = value.get("result")
        pending = retryable_stage_names(result) if isinstance(result, dict) else []
        plan = build_stage_plan("", filtered)
        pending = [
            name
            for name in pending
            if name not in {"asset_discovery", "subdomain_enumeration"}
            or plan[
                "asset_targets" if name == "asset_discovery" else "subdomain_targets"
            ]
        ]
        value["pending_stages"] = pending
        value["retry_count"] = 0
        value["next_retry_at"] = (
            current + STAGE_RETRY_DELAY_SECONDS if pending else 0.0
        )
        value["retry_attempts"] = []
        value.pop("retry_exhausted_at", None)
        value["scope_refreshed_at"] = now_text()
        changed = True
    return changed


def root_domains(domains: list[str]) -> list[str]:
    values: list[str] = []
    for domain in domains:
        labels = _host_from_value(domain).split(".")
        if len(labels) >= 2:
            values.append(".".join(labels[-2:]))
    return _unique(values)


def workflow_completed(path: Path) -> bool:
    return str(read_json(path).get("status", "")).lower() == "completed"


def workflow_assets_ready(path: Path) -> bool:
    value = read_json(path)
    if str(value.get("status") or "").lower() == "completed":
        return True
    handoff = value.get("asset_handoff")
    return isinstance(handoff, dict) and str(
        handoff.get("status") or ""
    ).lower() in {"ready", "final"}


def process_alive(pid: int | None) -> bool:
    if not pid or pid <= 0:
        return False
    try:
        process = psutil.Process(pid)
        return process.is_running() and process.status() != psutil.STATUS_ZOMBIE
    except (psutil.Error, OSError, ValueError):
        return False


def process_creation_token(pid: int | None) -> int:
    if not pid or pid <= 0:
        return 0
    try:
        return int(psutil.Process(pid).create_time() * 1_000_000)
    except (psutil.Error, OSError, ValueError):
        return 0


def tscan_process_alive(pid: int | None, creation_token: int, executable: Path) -> bool:
    if not process_alive(pid):
        return False
    if creation_token:
        return process_creation_token(pid) == creation_token
    try:
        actual_executable = Path(psutil.Process(int(pid)).exe()).resolve()
    except (psutil.Error, OSError, ValueError):
        return False
    return actual_executable == executable.resolve()


def terminate_tscan_process_tree(pid: int) -> None:
    if not process_alive(pid):
        return
    subprocess.run(
        ["taskkill.exe", "/PID", str(pid), "/T", "/F"],
        capture_output=True,
        check=False,
    )


def append_activity(state_path: Path, message: str) -> None:
    try:
        run_dir = state_path.parents[2]
        timestamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{timestamp}] TscanPlus：{message.strip()}\n"
        for path in (run_dir / "activity.log", state_path.parent / "activity.log"):
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(line)
                handle.flush()
    except (OSError, IndexError):
        pass


def webview_environment(port: int, run_dir: Path) -> dict[str, str]:
    environment = os.environ.copy()
    proxy_argument = webview_proxy_argument()
    arguments = " ".join(
        item
        for item in (
            f"--remote-debugging-port={port}",
            "--remote-allow-origins=*",
            "--force-renderer-accessibility",
            proxy_argument,
        )
        if item
    )
    environment["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = arguments
    environment["WEBVIEW2_USER_DATA_FOLDER"] = str(
        run_dir / "tool_data" / "tscan" / "webview2_data"
    )
    return environment


def update_stage(
    state_path: Path,
    state: dict[str, object],
    stage: str,
    detail: str,
    status: str = "running",
) -> None:
    state.update(status=status, stage=stage, detail=detail, updated_at=now_text())
    atomic_json_write(state_path, state)
    append_activity(state_path, detail)


def target_for_asset_scan(target: str) -> str:
    raw = target.strip()
    if not raw or "://" not in raw:
        return raw
    parsed = urlsplit(raw)
    if not parsed.hostname:
        return raw
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    try:
        port = parsed.port
    except ValueError:
        port = None
    return f"{host}:{port}" if port else host


def free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def run_elevated_registry_command(command: str) -> None:
    encoded = base64.b64encode(command.encode("utf-16le")).decode("ascii")
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            f"Start-Process powershell.exe -Verb RunAs -Wait -PassThru "
            f"-ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand','{encoded}' "
            "| Select-Object -ExpandProperty ExitCode",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    output = result.stdout.strip().splitlines()
    exit_code = output[-1].strip() if output else ""
    if result.returncode != 0 or exit_code != "0":
        detail = result.stderr.strip() or result.stdout.strip() or "管理员授权失败"
        raise RuntimeError(f"无法临时配置 WebView2 调试策略：{detail}")


class BrowserPolicy:
    def __init__(self, port: int, executable_name: str = POLICY_NAME) -> None:
        self.executable_name = executable_name
        self.value = (
            f"--remote-debugging-port={port} --remote-allow-origins=* "
            "--force-renderer-accessibility"
        )
        self.entries: list[tuple[int, int, bool, tuple[object, int] | None]] = []
        self.elevated = False
        self.elevated_previous: tuple[bool, tuple[object, int] | None] = (False, None)
        self.elevated_key_existed = False

    def _apply(self, *, elevated: bool) -> None:
        command_entries: list[str] = []
        for root, view_flag in ((winreg.HKEY_CURRENT_USER, winreg.KEY_WOW64_64KEY),):
            access = winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE | view_flag
            previous = None
            existed = False
            try:
                key = winreg.CreateKeyEx(root, POLICY_PATH, 0, access)
                try:
                    try:
                        previous = winreg.QueryValueEx(key, self.executable_name)
                        existed = True
                    except FileNotFoundError:
                        pass
                    winreg.SetValueEx(key, self.executable_name, 0, winreg.REG_SZ, self.value)
                finally:
                    winreg.CloseKey(key)
            except OSError:
                if not elevated:
                    raise
                try:
                    key = winreg.OpenKey(
                        root, POLICY_PATH, 0, winreg.KEY_QUERY_VALUE | view_flag
                    )
                    self.elevated_key_existed = True
                    try:
                        self.elevated_previous = (
                            True,
                            winreg.QueryValueEx(key, self.executable_name),
                        )
                    finally:
                        winreg.CloseKey(key)
                except (FileNotFoundError, OSError):
                    self.elevated_previous = (False, None)
                escaped = self.value.replace("'", "''")
                command_entries.append(
                    "$p='HKCU:" + POLICY_PATH + "'; "
                    f"New-Item -Path $p -Force | Out-Null; "
                    f"New-ItemProperty -Path $p -Name '{self.executable_name}' "
                    f"-Value '{escaped}' -PropertyType String -Force | Out-Null"
                )
                continue
            self.entries.append((root, view_flag, existed, previous))
        if command_entries:
            run_elevated_registry_command("; ".join(command_entries))
            self.elevated = True

    def __enter__(self) -> "BrowserPolicy":
        try:
            self._apply(elevated=False)
        except OSError:
            self._apply(elevated=True)
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        commands: list[str] = []
        for root, view_flag, existed, previous in reversed(self.entries):
            access = winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE | view_flag
            try:
                key = winreg.OpenKey(root, POLICY_PATH, 0, access)
            except OSError:
                key = None
            if key is not None:
                try:
                    if existed and previous is not None:
                        winreg.SetValueEx(key, self.executable_name, 0, previous[1], previous[0])
                    else:
                        winreg.DeleteValue(key, self.executable_name)
                finally:
                    winreg.CloseKey(key)
        if self.elevated:
            existed, previous = self.elevated_previous
            restore = (
                f"New-ItemProperty -Path $p -Name '{self.executable_name}' "
                f"-Value '{str(previous[0]).replace(chr(39), chr(39) * 2)}' "
                "-PropertyType String -Force | Out-Null"
                if existed and previous is not None
                else f"Remove-ItemProperty -Path $p -Name '{self.executable_name}' "
                "-ErrorAction SilentlyContinue"
            )
            cleanup = (
                ""
                if self.elevated_key_existed
                else "; if ((Get-Item -Path $p -ErrorAction SilentlyContinue).Property.Count -eq 0) "
                "{ Remove-Item -Path $p -Force -ErrorAction SilentlyContinue }"
            )
            commands.append("$p='HKCU:" + POLICY_PATH + "'; " + restore + cleanup)
            run_elevated_registry_command("; ".join(commands))


def wait_for_cdp(port: int, timeout: float = 20.0) -> str:
    deadline = time.monotonic() + timeout
    endpoint = f"http://127.0.0.1:{port}/json/list"
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urlopen(endpoint, timeout=1) as response:
                pages = json.load(response)
            for page in pages:
                if page.get("type") == "page" and page.get("url") == "http://wails.localhost/":
                    return endpoint
        except Exception as exc:
            last_error = exc
        time.sleep(0.25)
    raise RuntimeError(f"Tscan WebView2 CDP did not start on port {port}: {last_error}")


def visible(locator: Locator, timeout: float = 2.5) -> Locator:
    deadline = time.monotonic() + timeout
    while True:
        for index in range(locator.count()):
            candidate = locator.nth(index)
            if candidate.is_visible():
                return candidate
        if time.monotonic() >= deadline:
            raise RuntimeError("visible Tscan control not found")
        time.sleep(0.05)


def set_native_value(locator: Locator, value: str) -> None:
    locator.evaluate(
        """(element, value) => {
          const prototype = element instanceof HTMLTextAreaElement
            ? HTMLTextAreaElement.prototype
            : HTMLInputElement.prototype;
          const setter = Object.getOwnPropertyDescriptor(prototype, 'value').set;
          setter.call(element, value);
          element.dispatchEvent(new Event('input', { bubbles: true }));
          element.dispatchEvent(new Event('change', { bubbles: true }));
        }""",
        value,
    )


def switch_state(page: Page, label: str, enabled: bool | None = None) -> dict[str, bool]:
    return page.evaluate(
        """({ label, enabled }) => {
          const visible = (element) => {
            const rect = element.getBoundingClientRect();
            const style = getComputedStyle(element);
            return rect.width > 0 && rect.height > 0
              && style.display !== 'none' && style.visibility !== 'hidden';
          };
          for (const button of document.querySelectorAll('button')) {
            if (!visible(button) || (button.innerText || '').trim() !== label) continue;
            const buttonRect = button.getBoundingClientRect();
            const switches = [...document.querySelectorAll('[role="switch"]')]
              .filter(visible)
              .map((control) => {
                const rect = control.getBoundingClientRect();
                const vertical = Math.abs(
                  (rect.top + rect.height / 2) - (buttonRect.top + buttonRect.height / 2)
                );
                const horizontal = Math.abs(rect.left - buttonRect.right);
                return { control, vertical, distance: vertical * 10 + horizontal };
              })
              .filter((item) => item.vertical <= Math.max(30, buttonRect.height));
            switches.sort((left, right) => left.distance - right.distance);
            const control = switches[0]?.control;
            if (!control) continue;
            const current = control.getAttribute('aria-checked') === 'true';
            if (enabled !== null && current !== enabled) control.click();
            return { found: true, enabled: current };
          }
          return { found: false, enabled: false };
        }""",
        {"label": label, "enabled": enabled},
    )


def set_switch(page: Page, label: str, enabled: bool) -> bool:
    result = switch_state(page, label, enabled)
    if not result["found"]:
        raise RuntimeError(f"Tscan switch not found for {label}")
    if result["enabled"] != enabled:
        page.wait_for_timeout(200)
    verified = switch_state(page, label)
    if not verified["found"] or verified["enabled"] != enabled:
        raise RuntimeError(f"Tscan switch did not change for {label}")
    return bool(verified["enabled"])


def try_set_switch(page: Page, label: str, enabled: bool) -> bool | None:
    if not switch_state(page, label)["found"]:
        return None
    return set_switch(page, label, enabled)


def click_tab(page: Page, name: str) -> None:
    tab = visible(page.locator(f'.n-tabs-tab[data-name="{name}"]'))
    safe_click(page, tab)
    try:
        page.wait_for_function(
            """(name) => {
              const tabs = [...document.querySelectorAll(`.n-tabs-tab[data-name="${name}"]`)];
              return tabs.some((tab) => tab.getAttribute('aria-selected') === 'true'
                || tab.classList.contains('n-tabs-tab--active'));
            }""",
            name,
            timeout=2500,
        )
    except Exception:
        page.wait_for_timeout(250)


def set_labeled_input(page: Page, label: str, value: str) -> bool:
    return bool(
        page.evaluate(
            """({ label, value }) => {
              const visible = (element) => {
                const rect = element.getBoundingClientRect();
                const style = getComputedStyle(element);
                return rect.width > 0 && rect.height > 0
                  && style.display !== 'none' && style.visibility !== 'hidden';
              };
              const button = [...document.querySelectorAll('button')].find(
                (element) => visible(element)
                  && (element.innerText || '').trim() === label
              );
              if (!button) return false;
              const buttonRect = button.getBoundingClientRect();
              const inputs = [...document.querySelectorAll('input[type="text"]')]
                .filter(visible)
                .map((input) => {
                  const rect = input.getBoundingClientRect();
                  const vertical = Math.abs(
                    (rect.top + rect.height / 2)
                    - (buttonRect.top + buttonRect.height / 2)
                  );
                  return { input, vertical, distance: vertical * 10 + Math.abs(rect.left - buttonRect.right) };
                })
                .filter((item) => item.vertical <= Math.max(35, buttonRect.height));
              inputs.sort((left, right) => left.distance - right.distance);
              const input = inputs[0]?.input;
              if (!input) return false;
              const setter = Object.getOwnPropertyDescriptor(
                HTMLInputElement.prototype, 'value'
              ).set;
              setter.call(input, value);
              input.dispatchEvent(new Event('input', { bubbles: true }));
              input.dispatchEvent(new Event('change', { bubbles: true }));
              return true;
            }""",
            {"label": label, "value": value},
        )
    )


def backend_progress(page: Page, method: str, project: str = "Default") -> object:
    return page.evaluate(
        """async ({ method, project }) => {
          const app = window.go?.main?.App;
          if (!app || typeof app[method] !== 'function') return null;
          return await app[method](project);
        }""",
        {"method": method, "project": project},
    )


def progress_acknowledged(value: object) -> bool:
    if value is True:
        return True
    if not isinstance(value, dict):
        return False
    status = str(value.get("status") or "").lower()
    return (
        status in {"running", "completed", "done", "finished"}
        or bool(value.get("runId"))
        or int(value.get("total") or 0) > 0
    )


def wait_for_stage_ack(
    page: Page,
    button: Locator,
    progress_method: str = "",
    timeout: float = 10.0,
) -> tuple[bool, object]:
    deadline = time.monotonic() + timeout
    snapshot: object = None
    while time.monotonic() < deadline:
        if progress_method:
            try:
                snapshot = backend_progress(page, progress_method)
            except Exception as exc:
                snapshot = {"error": str(exc)}
            if progress_acknowledged(snapshot):
                return True, snapshot
        try:
            if button.is_disabled():
                return True, snapshot
        except Exception:
            pass
        page.wait_for_timeout(350)
    return False, snapshot


def modal_requires_retry(dismissed: tuple[str, ...]) -> bool:
    return any(item.startswith("文件大小限制提醒：") for item in dismissed)


def configure_textarea_scan(
    page: Page,
    top_tab: str,
    sub_tab: str,
    placeholder: str,
    targets: list[str],
    button_name: str,
    start_scan: bool,
    progress_method: str = "",
) -> dict[str, object]:
    click_tab(page, top_tab)
    click_tab(page, sub_tab)
    normalized = _unique(targets)
    target_box = visible(page.locator(f'textarea[placeholder*="{placeholder}"]'))
    set_native_value(target_box, "\n".join(normalized))
    panel = target_box.locator(
        "xpath=ancestor::*[contains(concat(' ', normalize-space(@class), ' '), ' n-tab-pane ')][1]"
    )
    scope = panel if panel.count() else page
    button = visible(scope.get_by_role("button", name=button_name, exact=True))
    clicked = False
    retry_clicked = False
    dismissed_modals: tuple[str, ...] = ()
    acknowledged = False
    snapshot: object = None
    reason = ""
    if not normalized:
        reason = "没有可导入的目标"
    elif start_scan:
        dismissed_modals = safe_click(page, button)
        clicked = True
        if modal_requires_retry(dismissed_modals):
            acknowledged, snapshot = wait_for_stage_ack(
                page,
                button,
                progress_method=progress_method,
                timeout=1.5,
            )
            if not acknowledged:
                dismissed_modals += safe_click(page, button)
                retry_clicked = True
        if not acknowledged:
            acknowledged, snapshot = wait_for_stage_ack(
                page, button, progress_method=progress_method
            )
        if not acknowledged:
            reason = "已点击启动，但 Tscan 未在 10 秒内确认任务进入运行状态"
    return {
        "target_count": len(normalized),
        "clicked": clicked,
        "retry_clicked": retry_clicked,
        "dismissed_modals": list(dismissed_modals),
        "acknowledged": acknowledged,
        "progress": snapshot,
        "reason": reason,
    }

def configure_information_collection(
    page: Page, target: str, start_scan: bool
) -> dict[str, object]:
    click_tab(page, "Info")
    target_box = visible(page.locator('input[placeholder*="域名或公司名或IP地址"]'))
    info_target = target_for_asset_scan(target)
    set_native_value(target_box, info_target)
    options = {
        "port_scan": try_set_switch(page, PORT_SCAN, True),
        "web_fingerprint": try_set_switch(page, WEB_FINGERPRINT, True),
        "proxy": try_set_switch(page, ENABLE_PROXY, False),
    }
    clicked = False
    if start_scan and info_target:
        safe_click(
            page, visible(page.get_by_role("button", name="查询", exact=True))
        )
        clicked = True
        page.wait_for_timeout(300)
    return {"target": info_target, "options": options, "query_clicked": clicked}


def configure_asset_discovery(
    page: Page, targets: list[str], start_scan: bool
) -> dict[str, object]:
    click_tab(page, "AssetDetect")

    target_box = visible(page.locator('textarea[placeholder*="IPv4"]'))
    scan_target = "\n".join(_unique(targets))
    set_native_value(target_box, scan_target)

    web_radio = visible(page.locator('input[type="radio"][value="web"]'))
    if not web_radio.is_checked():
        safe_click(page, web_radio)

    set_labeled_input(page, "\u7ebf\u7a0b", "200")

    options = {
        "password_crack": set_switch(page, PASSWORD_CRACK, False),
        "poc_check": set_switch(page, POC_CHECK, False),
        "port_fingerprint": set_switch(page, PORT_FINGERPRINT, True),
        "proxy": set_switch(page, ENABLE_PROXY, False),
    }

    scan_clicked = False
    acknowledged = False
    snapshot: object = None
    if start_scan and scan_target:
        scan_button = visible(page.get_by_role("button", name="Scan", exact=True))
        safe_click(page, scan_button)
        scan_clicked = True
        acknowledged, snapshot = wait_for_stage_ack(
            page, scan_button, progress_method="IsIpScanRunning"
        )

    return {
        "targets": _unique(targets),
        "profile": "web",
        "thread_count": 200,
        "options": options,
        "scan_clicked": scan_clicked,
        "acknowledged": acknowledged,
        "progress": snapshot,
        "reason": ""
        if acknowledged or not scan_clicked
        else "已点击启动，但 Tscan 未确认端口扫描进入运行状态",
    }


def select_available_pocs(page: Page) -> dict[str, object]:
    result = page.evaluate(
        """async () => {
          const visible = (element) => {
            const rect = element.getBoundingClientRect();
            const style = getComputedStyle(element);
            return rect.width > 0 && rect.height > 0
              && style.display !== 'none' && style.visibility !== 'hidden';
          };
          const text = (element) =>
            (element?.innerText || element?.textContent || '').replace(/\s+/g, ' ').trim();
          const delay = (milliseconds) => new Promise(
            (resolve) => window.setTimeout(resolve, milliseconds)
          );
          const targetBox = [...document.querySelectorAll('textarea')].find(
            (element) => visible(element)
              && String(element.getAttribute('placeholder') || '').includes('Url')
          );
          const pane = targetBox?.closest('.n-tab-pane');
          const empty = {
            category_count: 0,
            selected_categories: 0,
            total_pocs: 0,
            selected_pocs: 0,
            all_selected: false,
            header_clicked: false,
            individual_clicks: 0,
            missing_categories: []
          };
          if (!pane) return empty;
          const tables = [...pane.querySelectorAll('.n-data-table')]
            .filter(visible)
            .map((table) => ({
              table,
              header: table.querySelector(
                '.n-data-table-th--selection [role="checkbox"]'
              ),
              rect: table.getBoundingClientRect()
            }))
            .filter((entry) => entry.header && visible(entry.header))
            .sort((left, right) => left.rect.left - right.rect.left);
          const selectionTable = tables[0]?.table;
          const header = tables[0]?.header;
          if (!selectionTable || !header) return empty;
          const categories = () => [...selectionTable.querySelectorAll('tbody tr')]
            .map((row) => {
              const checkbox = [...row.querySelectorAll('[role="checkbox"]')]
                .find(visible);
              const label = text(row);
              const count = Number((label.match(/\((\d+)[^\d)]*\)/) || [])[1] || 0);
              return { checkbox, label, count };
            })
            .filter((entry) => entry.checkbox && entry.count > 0);
          let headerClicked = false;
          if (header.getAttribute('aria-checked') !== 'true') {
            header.click();
            headerClicked = true;
            await delay(300);
          }
          let individualClicks = 0;
          for (const category of categories()) {
            if (category.checkbox.getAttribute('aria-checked') !== 'true') {
              category.checkbox.click();
              individualClicks += 1;
            }
          }
          for (let attempt = 0; attempt < 30; attempt += 1) {
            const current = categories();
            if (current.length && current.every(
              (category) => category.checkbox.getAttribute('aria-checked') === 'true'
            )) break;
            await delay(100);
          }
          const current = categories();
          const selected = current.filter(
            (category) => category.checkbox.getAttribute('aria-checked') === 'true'
          );
          return {
            category_count: current.length,
            selected_categories: selected.length,
            total_pocs: current.reduce((sum, category) => sum + category.count, 0),
            selected_pocs: selected.reduce((sum, category) => sum + category.count, 0),
            all_selected: current.length > 0 && selected.length === current.length,
            header_clicked: headerClicked,
            individual_clicks: individualClicks,
            missing_categories: current
              .filter((category) => category.checkbox.getAttribute('aria-checked') !== 'true')
              .map((category) => category.label)
          };
        }"""
    )
    if not isinstance(result, dict):
        return {
            "category_count": 0,
            "selected_categories": 0,
            "total_pocs": 0,
            "selected_pocs": 0,
            "all_selected": False,
            "header_clicked": False,
            "individual_clicks": 0,
            "missing_categories": [],
        }
    return {
        "category_count": int(result.get("category_count") or 0),
        "selected_categories": int(result.get("selected_categories") or 0),
        "total_pocs": int(result.get("total_pocs") or 0),
        "selected_pocs": int(result.get("selected_pocs") or 0),
        "all_selected": bool(result.get("all_selected")),
        "header_clicked": bool(result.get("header_clicked")),
        "individual_clicks": int(result.get("individual_clicks") or 0),
        "missing_categories": [
            str(item)
            for item in result.get("missing_categories", [])
            if str(item).strip()
        ],
    }


def select_unauthorized_services(page: Page) -> dict[str, object]:
    result = page.evaluate(
        """async () => {
          const visible = (element) => {
            const rect = element.getBoundingClientRect();
            const style = getComputedStyle(element);
            return rect.width > 0 && rect.height > 0
              && style.display !== 'none' && style.visibility !== 'hidden';
          };
          const normalizedText = (element) =>
            (element?.innerText || element?.textContent || '').replace(/\s+/g, ' ').trim();
          const delay = (milliseconds) => new Promise(
            (resolve) => window.setTimeout(resolve, milliseconds)
          );
          const pane = [...document.querySelectorAll('.n-tab-pane')].find(
            (element) => visible(element)
              && element.querySelector('textarea[placeholder*="支持 IP/域名/网段"]')
          ) || document;
          const enabled = (element) => element
            && visible(element)
            && element.getAttribute('aria-disabled') !== 'true'
            && !element.hasAttribute('disabled');
          const serviceRows = () => [...pane.querySelectorAll('tbody tr')]
            .filter(visible)
            .map((row) => ({
              row,
              checkbox: [...row.querySelectorAll('[role="checkbox"]')].find(enabled),
              service: normalizedText(row)
            }))
            .filter((entry) => entry.checkbox);
          const header = [...pane.querySelectorAll('thead [role="checkbox"]')].find(enabled);
          let headerClicked = false;
          if (header && header.getAttribute('aria-checked') !== 'true') {
            header.click();
            headerClicked = true;
            await delay(300);
          }
          let individualClicks = 0;
          for (const entry of serviceRows()) {
            if (entry.checkbox.getAttribute('aria-checked') !== 'true') {
              entry.checkbox.click();
              individualClicks += 1;
            }
          }
          if (individualClicks) await delay(300);
          const rows = serviceRows();
          const selectedRows = rows.filter(
            (entry) => entry.checkbox.getAttribute('aria-checked') === 'true'
          );
          const mqtt = rows.find((entry) => entry.service.toUpperCase().includes('MQTT'));
          return {
            available: rows.length,
            selected: selectedRows.length,
            header_clicked: headerClicked,
            individual_clicks: individualClicks,
            mqtt_found: Boolean(mqtt),
            mqtt_selected: Boolean(
              mqtt && mqtt.checkbox.getAttribute('aria-checked') === 'true'
            ),
            missing_services: rows
              .filter((entry) => entry.checkbox.getAttribute('aria-checked') !== 'true')
              .map((entry) => entry.service)
          };
        }"""
    )
    if not isinstance(result, dict):
        return {
            "available": 0,
            "selected": 0,
            "header_clicked": False,
            "individual_clicks": 0,
            "mqtt_found": False,
            "mqtt_selected": False,
            "missing_services": [],
        }
    return {
        "available": int(result.get("available") or 0),
        "selected": int(result.get("selected") or 0),
        "header_clicked": bool(result.get("header_clicked")),
        "individual_clicks": int(result.get("individual_clicks") or 0),
        "mqtt_found": bool(result.get("mqtt_found")),
        "mqtt_selected": bool(result.get("mqtt_selected")),
        "missing_services": [
            str(item)
            for item in result.get("missing_services", [])
            if str(item).strip()
        ],
    }


def configure_unauthorized_check(
    page: Page, targets: list[str], start_scan: bool
) -> dict[str, object]:
    click_tab(page, "VulCheck")
    click_tab(page, "UnAuth")
    normalized = _unique(targets)
    target_box = visible(page.locator('textarea[placeholder*="支持 IP/域名/网段"]'))
    set_native_value(target_box, "\n".join(normalized))
    services = select_unauthorized_services(page)
    panel = target_box.locator(
        "xpath=ancestor::*[contains(concat(' ', normalize-space(@class), ' '), ' n-tab-pane ')][1]"
    )
    scope = panel if panel.count() else page
    button = visible(scope.get_by_role("button", name="开始", exact=True))
    clicked = False
    acknowledged = False
    snapshot: object = None
    reason = ""
    if not normalized:
        reason = "没有可导入的域名/IP"
    elif not services["available"]:
        reason = "未找到可选择的未授权检测服务"
    elif start_scan:
        safe_click(page, button)
        clicked = True
        acknowledged, snapshot = wait_for_stage_ack(
            page, button, progress_method="IsUnAuthRunning"
        )
        if not acknowledged:
            reason = "已点击启动，但 Tscan 未在 10 秒内确认未授权检测进入运行状态"
    if services["missing_services"]:
        missing = "、".join(services["missing_services"])
        warning = f"仍有未选服务：{missing}"
        reason = f"{reason}；{warning}" if reason else warning
    return {
        "target_count": len(normalized),
        "services": services,
        "clicked": clicked,
        "acknowledged": acknowledged,
        "progress": snapshot,
        "reason": reason,
    }


def configure_poc_check(
    page: Page, targets: list[str], start_scan: bool
) -> dict[str, object]:
    click_tab(page, "VulCheck")
    click_tab(page, "PocCheck")
    target_box = visible(page.locator('textarea[placeholder*="Url地址每行一个"]'))
    normalized = _unique(targets)
    set_native_value(target_box, "\n".join(normalized))
    fingerprint_match = try_set_switch(page, "Poc匹配指纹", True)
    poc_selection = select_available_pocs(page)
    selected_pocs = int(poc_selection["selected_pocs"])
    clicked = False
    reason = ""
    if start_scan and normalized and poc_selection["all_selected"]:
        check_button = visible(page.get_by_role("button", name="Check", exact=True))
        safe_click(page, check_button)
        clicked = True
        acknowledged, snapshot = wait_for_stage_ack(
            page, check_button, progress_method="GetPocCheckProgressSnapshot"
        )
        if not acknowledged:
            reason = "已点击启动，但 Tscan 未确认 POC 任务进入运行状态"
    elif not normalized:
        reason = "没有可导入的 HTTP/HTTPS URL"
    elif not selected_pocs:
        reason = "没有可用的 POC 分类，可能受许可证限制"
    elif not poc_selection["all_selected"]:
        missing = "、".join(poc_selection["missing_categories"])
        missing_label = missing or "未知分类"
        reason = f"POC 分类未全量选中，未启动检测：{missing_label}"
    return {
        "targets": normalized,
        "selected_pocs": selected_pocs,
        "poc_selection": poc_selection,
        "fingerprint_match": fingerprint_match,
        "check_clicked": clicked,
        "acknowledged": locals().get("acknowledged", False),
        "progress": locals().get("snapshot"),
        "reason": reason,
    }


def configure_password_crack(
    page: Page, targets: list[str], start_scan: bool
) -> dict[str, object]:
    click_tab(page, "VulCheck")
    click_tab(page, "PwdCrack")
    target_box = visible(page.locator('textarea[placeholder*="支持逗号或换行分隔"]'))
    normalized = _unique(targets)
    set_native_value(target_box, "\n".join(normalized))
    options = {
        "fingerprint_identification": try_set_switch(
            page, FINGERPRINT_IDENTIFICATION, True
        ),
        "only_one_account": try_set_switch(page, ONLY_ONE_ACCOUNT, True),
    }
    clicked = False
    reason = ""
    if start_scan and normalized:
        crack_button = visible(page.get_by_role("button", name="Crack", exact=True))
        safe_click(page, crack_button)
        clicked = True
        acknowledged, snapshot = wait_for_stage_ack(
            page, crack_button, progress_method="GetPwdCrackProgressSnapshot"
        )
        if not acknowledged:
            reason = "已点击启动，但 Tscan 未确认密码检测进入运行状态"
    elif not normalized:
        reason = "没有可导入的 IP"
    return {
        "targets": normalized,
        "options": options,
        "crack_clicked": clicked,
        "acknowledged": locals().get("acknowledged", False),
        "progress": locals().get("snapshot"),
        "reason": reason,
    }


def required_inputs_configured(page: Page, placeholders: list[str]) -> bool:
    return bool(
        page.evaluate(
            """(placeholders) => {
              const visible = (element) => {
                const rect = element.getBoundingClientRect();
                const style = getComputedStyle(element);
                return rect.width > 0 && rect.height > 0
                  && style.display !== 'none' && style.visibility !== 'hidden';
              };
              return placeholders.every((placeholder) =>
                [...document.querySelectorAll('input')].some((element) =>
                  visible(element)
                  && element.getAttribute('placeholder') === placeholder
                  && String(element.value || '').trim().length > 0
                )
              );
            }""",
            placeholders,
        )
    )


def classify_connection_feedback(message: str) -> tuple[bool | None, str]:
    normalized = message.strip()
    lowered = normalized.lower()
    if any(
        keyword in lowered
        for keyword in (
            "refused",
            "failed",
            "failure",
            "timeout",
            "timed out",
            "unreachable",
            "unauthorized",
            "forbidden",
            "invalid key",
            "连接失败",
            "连接错误",
            "无法连接",
            "超时",
            "未授权",
            "密钥无效",
        )
    ):
        return False, normalized
    if any(
        keyword in lowered
        for keyword in (
            "success",
            "connected",
            "connection ok",
            "连接成功",
            "测试成功",
        )
    ):
        return True, normalized
    return None, normalized


def connection_feedback(page: Page) -> tuple[bool | None, str]:
    texts = page.evaluate(
        """() => [...document.querySelectorAll(
          '.n-message, .n-notification, .n-alert, [role="alert"]'
        )].filter((element) => {
          const rect = element.getBoundingClientRect();
          const style = getComputedStyle(element);
          return rect.width > 0 && rect.height > 0
            && style.display !== 'none' && style.visibility !== 'hidden';
        }).map((element) => (element.innerText || '').trim()).filter(Boolean)"""
    )
    message = " | ".join(str(item) for item in texts) if isinstance(texts, list) else ""
    return classify_connection_feedback(message)


def wait_for_connection_feedback(
    page: Page, timeout_ms: int = 5000, poll_ms: int = 200
) -> tuple[bool | None, str]:
    deadline = time.monotonic() + max(timeout_ms, 0) / 1000
    last_message = ""
    while True:
        connected, message = connection_feedback(page)
        if message:
            last_message = message
        if connected is not None:
            return connected, message
        if time.monotonic() >= deadline:
            return None, last_message
        page.wait_for_timeout(max(poll_ms, 50))


def configure_awvs_scan(
    page: Page, targets: list[str], start_scan: bool
) -> dict[str, object]:
    click_tab(page, "VulCheck")
    click_tab(page, "AwvsScan")
    # AWVS crawls from a site entry. Never submit individual paths or static
    # resources, including when retrying a batch written by an older version.
    normalized = awvs_site_targets(targets)
    target_box = visible(page.locator('textarea[placeholder*="请输入目标URL"]'))
    set_native_value(target_box, "\n".join(normalized))
    configured = required_inputs_configured(
        page,
        ["https://127.0.0.1:3443", "请输入AWVS API Key"],
    )
    connection_tested = False
    clicked = False
    acknowledged = False
    snapshot: object = None
    feedback = ""
    reason = ""
    if not normalized:
        reason = "没有可导入的 HTTP/HTTPS URL"
    elif not configured:
        reason = "AWVS API 或 API Key 尚未配置"
    elif start_scan:
        safe_click(
            page,
            visible(page.get_by_role("button", name="连接测试", exact=True)),
        )
        connection_tested = True
        connected, feedback = wait_for_connection_feedback(page)
        if connected is not True:
            reason = feedback or "AWVS 连接测试未确认成功，不启动扫描"
        else:
            start_button = visible(
                page.get_by_role("button", name="开始扫描", exact=True)
            )
            safe_click(page, start_button)
            clicked = True
            acknowledged, snapshot = wait_for_stage_ack(page, start_button)
            if not acknowledged:
                reason = "已点击启动，但 Tscan 未确认 AWVS 任务进入运行状态"
    return {
        "target_count": len(normalized),
        "submitted_targets": normalized,
        "configured": configured,
        "connection_tested": connection_tested,
        "connection_feedback": feedback,
        "scan_clicked": clicked,
        "acknowledged": acknowledged,
        "progress": snapshot,
        "reason": reason,
    }


def configure_nessus_scan(
    page: Page, targets: list[str], start_scan: bool
) -> dict[str, object]:
    click_tab(page, "VulCheck")
    click_tab(page, "Nessus")
    normalized = _unique(targets)
    target_box = visible(page.locator('textarea[placeholder*="仅支持IP或域名"]'))
    set_native_value(target_box, "\n".join(normalized))
    configured = required_inputs_configured(
        page,
        [
            "https://127.0.0.1:8834",
            "请输入Nessus Access Key",
            "请输入Nessus Secret Key",
        ],
    )
    connection_tested = False
    clicked = False
    acknowledged = False
    snapshot: object = None
    feedback = ""
    reason = ""
    if not normalized:
        reason = "没有可导入的域名或 IP"
    elif not configured:
        reason = "Nessus API、Access Key 或 Secret Key 尚未配置"
    elif start_scan:
        safe_click(page, visible(page.get_by_role("button", name="测试", exact=True)))
        connection_tested = True
        connected, feedback = wait_for_connection_feedback(page)
        if connected is not True:
            reason = feedback or "Nessus 连接测试未确认成功，不启动扫描"
        else:
            start_button = visible(
                page.get_by_role("button", name="开始扫描", exact=True)
            )
            safe_click(page, start_button)
            clicked = True
            acknowledged, snapshot = wait_for_stage_ack(page, start_button)
            if not acknowledged:
                reason = "已点击启动，但 Tscan 未确认 Nessus 任务进入运行状态"
    return {
        "target_count": len(normalized),
        "configured": configured,
        "connection_tested": connection_tested,
        "connection_feedback": feedback,
        "scan_clicked": clicked,
        "acknowledged": acknowledged,
        "progress": snapshot,
        "reason": reason,
    }

def stage_status_from_result(
    result: object, start_scan: bool
) -> str:
    if not isinstance(result, dict):
        return "submitted" if start_scan else "prepared"
    reason = str(result.get("reason") or "")
    if reason:
        if result.get("clicked") or any(
            result.get(key)
            for key in ("scan_clicked", "check_clicked", "crack_clicked")
        ):
            return "not_started"
        if any(
            keyword in reason
            for keyword in ("配置", "连接", "API", "Key", "License")
        ):
            return "waiting_configuration"
        return "skipped"
    if not start_scan:
        return "prepared"
    click_keys = (
        "clicked",
        "query_clicked",
        "scan_clicked",
        "check_clicked",
        "crack_clicked",
    )
    if any(result.get(key) is True for key in click_keys):
        if result.get("acknowledged") is False:
            return "not_started"
        return "submitted"
    return "skipped"


def dismiss_transient_messages(page: Page) -> int:
    return int(
        page.evaluate(
            """() => {
              let closed = 0;
              for (const selector of [
                '.n-message .n-base-close',
                '.n-notification .n-base-close',
                '.n-message .n-message__close',
                '.n-notification .n-notification__close'
              ]) {
                for (const button of document.querySelectorAll(selector)) {
                  const rect = button.getBoundingClientRect();
                  if (rect.width > 0 && rect.height > 0) {
                    button.click();
                    closed += 1;
                  }
                }
              }
              return closed;
            }"""
        )
        or 0
    )


def dismiss_blocking_modals(page: Page) -> tuple[str, ...]:
    dismissed = page.evaluate(
        """() => {
          const visible = (element) => {
            const rect = element.getBoundingClientRect();
            const style = getComputedStyle(element);
            return rect.width > 0 && rect.height > 0
              && style.display !== 'none' && style.visibility !== 'hidden';
          };
          const normalizedText = (element) =>
            (element?.innerText || element?.textContent || '').replace(/\s+/g, ' ').trim();
          const dialogs = [...new Set(document.querySelectorAll(
            '[role="dialog"], .n-dialog, .n-modal, .n-card.n-modal'
          ))];
          const dismissed = [];
          for (const dialog of dialogs) {
            if (!visible(dialog)) continue;
            const text = normalizedText(dialog);
            if (text.includes('\u662f\u5426\u6e05\u9664\u5df2\u6709\u6570\u636e')) {
              const keep = [...dialog.querySelectorAll('button')].find(
                (button) => visible(button)
                  && normalizedText(button) === '\u4fdd\u7559'
              );
              if (keep) {
                keep.click();
                dismissed.push('\u5df2\u6709\u626b\u63cf\u6570\u636e\uff1a\u4fdd\u7559');
                continue;
              }
            }
            if (text.includes('\u6587\u4ef6\u5927\u5c0f\u9650\u5236\u63d0\u9192')) {
              const acknowledge = [...dialog.querySelectorAll('button')].find(
                (button) => visible(button)
                  && normalizedText(button) === '\u6211\u77e5\u9053\u4e86'
              );
              if (acknowledge) {
                acknowledge.click();
                dismissed.push('\u6587\u4ef6\u5927\u5c0f\u9650\u5236\u63d0\u9192\uff1a\u6211\u77e5\u9053\u4e86');
                continue;
              }
            }
            if (!text.includes('\u5c0f\u5c0f\u652f\u6301\u4e00\u4e0b')) continue;
            const decline = [...dialog.querySelectorAll('button')].find(
              (button) => visible(button) && normalizedText(button) === '\u6682\u65f6\u4e0d\u7528'
            );
            if (decline) {
              decline.click();
              dismissed.push('\u5c0f\u5c0f\u652f\u6301\u4e00\u4e0b\uff1a\u6682\u65f6\u4e0d\u7528');
              continue;
            }
            const close = dialog.querySelector(
              '.n-base-close, .n-dialog__close, .n-card-header__close, '
              + 'button[aria-label="\u5173\u95ed"], [aria-label="\u5173\u95ed"]'
            );
            if (close && visible(close)) {
              close.click();
              dismissed.push('\u5c0f\u5c0f\u652f\u6301\u4e00\u4e0b\uff1a\u5173\u95ed');
            }
          }
          return dismissed;
        }"""
    )
    if not isinstance(dismissed, list):
        return ()
    return tuple(str(item) for item in dismissed if str(item).strip())

def safe_click(page: Page, locator: Locator) -> tuple[str, ...]:
    dismiss_transient_messages(page)
    dismiss_blocking_modals(page)
    locator.scroll_into_view_if_needed()
    locator.click(force=True)
    page.wait_for_timeout(180)
    dismissed = dismiss_blocking_modals(page)
    if dismissed:
        page.wait_for_timeout(180)
    dismiss_transient_messages(page)
    return dismissed

def dispatch_stages_on_page(
    page: Page,
    target: str,
    assets: dict[str, list[str]],
    start_scan: bool,
    state_path: Path,
    state: dict[str, object],
    batch_id: str,
    only_stages: set[str] | None = None,
) -> dict[str, object]:
    stages: dict[str, dict[str, object]] = {}

    def run_stage(name: str, detail: str, callback) -> None:
        if only_stages is not None and name not in only_stages:
            return
        update_stage(state_path, state, name, detail)
        try:
            result = callback()
        except Exception as exc:
            stages[name] = {"status": "failed", "error": str(exc)}
            append_activity(state_path, f"{detail}失败：{exc}")
        else:
            stage_status = stage_status_from_result(result, start_scan)
            stages[name] = {"status": stage_status, "result": result}
            reason = result.get("reason") if isinstance(result, dict) else ""
            if reason:
                append_activity(state_path, f"{detail}：{reason}")
            else:
                append_activity(state_path, f"{detail}：{stage_status}")
        state["stages"] = stages
        state["active_batch_id"] = batch_id
        atomic_json_write(state_path, state)

    def run_routed_stage(
        name: str, detail: str, targets: list[str], callback
    ) -> None:
        if only_stages is not None and name not in only_stages:
            return
        if targets:
            run_stage(name, detail, callback)
            return
        reason = "本轮没有匹配该模块的资产，已跳过"
        stages[name] = {
            "status": "skipped",
            "result": {"target_count": 0, "reason": reason},
        }
        append_activity(state_path, f"{detail}：{reason}")
        state["stages"] = stages
        state["active_batch_id"] = batch_id
        atomic_json_write(state_path, state)

    plan = build_stage_plan(target, assets)
    if only_stages is None:
        previous_awvs_targets = dispatched_awvs_targets(state, target)
        plan["awvs_targets"] = [
            value
            for value in plan["awvs_targets"]
            if value not in previous_awvs_targets
        ]
    asset_targets = plan["asset_targets"]
    poc_targets = plan["web_targets"]
    awvs_targets = plan["awvs_targets"]
    fingerprint_targets = plan["fingerprint_targets"]
    unauthorized_check_targets = plan["unauthorized_targets"]
    crack_targets = plan["password_targets"]
    nessus_targets = plan["nessus_targets"]
    subdomain_targets = plan["subdomain_targets"]
    state["asset_routing_plan"] = plan
    run_stage(
        "information_collection",
        "正在配置 TscanPlus 信息收集",
        lambda: configure_information_collection(page, target, start_scan),
    )
    run_stage(
        "asset_discovery",
        f"已导入 {len(asset_targets)} 个目标，正在启动资产探测",
        lambda: configure_asset_discovery(page, asset_targets, start_scan),
    )
    run_routed_stage(
        "web_fingerprint",
        f"已导入 {len(fingerprint_targets)} 个端点，正在启动 Web 指纹",
        fingerprint_targets,
        lambda: configure_textarea_scan(
            page,
            "AssetDetect",
            "UrlScan",
            "不加http前缀",
            fingerprint_targets,
            "Scan",
            start_scan,
            "GetUrlScanProgressSnapshot",
        ),
    )
    run_routed_stage(
        "subdomain_enumeration",
        f"已导入 {len(subdomain_targets)} 个根域名，正在启动域名枚举",
        subdomain_targets,
        lambda: configure_textarea_scan(
            page,
            "AssetDetect",
            "SubDomain",
            "枚举较依赖网络",
            subdomain_targets,
            "Start",
            start_scan,
            "GetSubDomainProgressSnapshot",
        ),
    )
    run_routed_stage(
        "directory_enumeration",
        f"已导入 {len(poc_targets)} 个 URL，正在启动目录枚举",
        poc_targets,
        lambda: configure_textarea_scan(
            page,
            "AssetDetect",
            "DirEnum",
            "Url地址每行一个,前缀为http/https:",
            poc_targets,
            "Check",
            start_scan,
            "GetDirScanProgressSnapshot",
        ),
    )
    run_routed_stage(
        "jsfinder",
        f"已导入 {len(poc_targets)} 个 URL，正在启动 JsFinder",
        poc_targets,
        lambda: configure_textarea_scan(
            page,
            "AssetDetect",
            "JsFinder",
            "Url地址每行一个,前缀为http/https:",
            poc_targets,
            "Check",
            start_scan,
            "GetJsFinderProgressSnapshot",
        ),
    )
    run_routed_stage(
        "swagger",
        f"已导入 {len(poc_targets)} 个 URL，正在启动 Swagger 检测",
        poc_targets,
        lambda: configure_textarea_scan(
            page,
            "AssetDetect",
            "Swagger",
            "输入Swagger文档地址",
            poc_targets,
            "Check",
            start_scan,
        ),
    )
    run_routed_stage(
        "waf_detection",
        f"已导入 {len(poc_targets)} 个 URL，正在启动 WAF 识别",
        poc_targets,
        lambda: configure_textarea_scan(
            page,
            "AssetDetect",
            "WafDetect",
            "输入目标 URL",
            poc_targets,
            "Check",
            start_scan,
        ),
    )
    run_routed_stage(
        "poc_check",
        f"已导入 {len(poc_targets)} 个 URL，正在启动 POC 检测",
        poc_targets,
        lambda: configure_poc_check(page, poc_targets, start_scan),
    )
    run_routed_stage(
        "unauthorized_check",
        f"已导入 {len(unauthorized_check_targets)} 个已识别服务主机，正在启动未授权检测",
        unauthorized_check_targets,
        lambda: configure_unauthorized_check(
            page, unauthorized_check_targets, start_scan
        ),
    )
    run_routed_stage(
        "password_crack",
        f"已导入 {len(crack_targets)} 个已识别登录服务主机，正在启动密码检测",
        crack_targets,
        lambda: configure_password_crack(page, crack_targets, start_scan),
    )
    run_routed_stage(
        "dump_all",
        f"已导入 {len(poc_targets)} 个 URL，正在启动 DumpAll 检测",
        poc_targets,
        lambda: configure_textarea_scan(
            page,
            "VulCheck",
            "DumpAll",
            "请输入目标URL进行漏洞检测和dump",
            poc_targets,
            "开始检测",
            start_scan,
        ),
    )
    run_routed_stage(
        "awvs_scan",
        f"已导入 {len(awvs_targets)} 个站点入口，正在测试连接并启动 AWVS",
        awvs_targets,
        lambda: configure_awvs_scan(page, awvs_targets, start_scan),
    )
    run_routed_stage(
        "nessus_scan",
        f"已导入 {len(nessus_targets)} 个域名/IP，正在测试连接并启动 Nessus",
        nessus_targets,
        lambda: configure_nessus_scan(page, nessus_targets, start_scan),
    )
    try:
        click_tab(page, "AssetDetect")
    except Exception as exc:
        append_activity(
            state_path,
            f"批次阶段结果已保存，但返回资产页失败：{exc}",
        )
    status_counts: dict[str, int] = {}
    for value in stages.values():
        status = str(value.get("status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
    return {
        "batch_id": batch_id,
        "requested_stages": sorted(only_stages) if only_stages is not None else [],
        "routing_plan": plan,
        "stages": stages,
        "stage_status_counts": status_counts,
        "asset_counts": {key: len(values) for key, values in assets.items()},
    }


def automate(
    port: int,
    target: str,
    assets: dict[str, list[str]],
    start_scan: bool,
    state_path: Path,
    state: dict[str, object],
    batch_id: str = "initial",
) -> dict[str, object]:
    os.environ["NO_PROXY"] = "127.0.0.1,localhost"
    endpoint = wait_for_cdp(port)
    with sync_playwright() as playwright:
        browser = playwright.chromium.connect_over_cdp(f"http://127.0.0.1:{port}")
        if not browser.contexts or not browser.contexts[0].pages:
            raise RuntimeError("Tscan WebView2 page was not found")
        page = browser.contexts[0].pages[0]
        page.wait_for_load_state("domcontentloaded")
        result = dispatch_stages_on_page(
            page,
            target,
            assets,
            start_scan,
            state_path,
            state,
            batch_id,
        )
        result.update(
            cdp_endpoint=endpoint,
            page_url=page.url,
            page_title=page.title(),
        )
        return result

def asset_commander_selected(state_path: Path) -> bool:
    try:
        run_state = read_json(state_path.parents[2] / "run.json")
    except IndexError:
        return True
    selected = run_state.get("selected_tools")
    if not isinstance(selected, list):
        return True
    return "asset_commander" in selected


def wait_for_asset_bundle(
    asset_state: Path,
    asset_export: Path,
    asset_bus: Path,
    target: str,
    scope: str,
    child_pid: int,
    state_path: Path,
    state: dict[str, object],
) -> dict[str, list[str]] | None:
    if not asset_commander_selected(state_path):
        update_stage(
            state_path,
            state,
            "asset_fallback",
            "本实例未选择 AssetCommander，TscanPlus 使用主目标继续",
        )
        _generation, bus_bundle = read_asset_bus_bundle(asset_bus, target)
        return filter_assets_by_scope(
            merge_asset_bundles(target_asset_bundle(target), bus_bundle),
            scope,
        )

    last_detail = ""
    while tscan_process_alive(
        child_pid,
        int(state.get("process_creation_token") or 0),
        Path(str(state.get("exe") or "")),
    ):
        workflow = read_json(asset_state)
        workflow_status = str(workflow.get("status", "waiting")).lower()
        if workflow_assets_ready(asset_state) and asset_export.is_file():
            _generation, bus_bundle = read_asset_bus_bundle(asset_bus, target)
            bundle = filter_assets_by_scope(
                merge_asset_bundles(
                    read_asset_bundle(asset_export, target),
                    bus_bundle,
                ),
                scope,
            )
            counts = {key: len(values) for key, values in bundle.items()}
            state["asset_counts"] = counts
            state["asset_workflow_status"] = workflow_status
            handoff = workflow.get("asset_handoff")
            state["asset_handoff"] = handoff if isinstance(handoff, dict) else {}
            update_stage(
                state_path,
                state,
                "assets_received",
                "AssetCommander 稳定资产已发布："
                f"{counts['ips']} IP / {counts['domains']} 域名 / {counts['urls']} URL",
            )
            return bundle

        current_step = str(workflow.get("current_step", "") or "")
        if workflow_status == "failed":
            error = str(workflow.get("error", "") or "未知错误")
            detail = f"AssetCommander 失败，TscanPlus 保持等待恢复：{error}"
        elif current_step:
            detail = f"TscanPlus 等待 AssetCommander 回传资产，当前步骤：{current_step}"
        else:
            detail = "TscanPlus 正在等待 AssetCommander 回传 IP、域名和 URL"
        if detail != last_detail:
            state["asset_workflow_status"] = workflow_status
            update_stage(
                state_path,
                state,
                "waiting_asset_commander",
                detail,
                status="waiting_assets",
            )
            last_detail = detail
        time.sleep(ASSET_WAIT_SECONDS)
    return None


def monitor_process(
    child: subprocess.Popen[bytes] | None,
    pid: int,
    state: dict[str, object],
) -> int:
    if child is not None:
        return int(child.wait())
    while tscan_process_alive(
        pid,
        int(state.get("process_creation_token") or 0),
        Path(str(state.get("exe") or "")),
    ):
        time.sleep(1.0)
    return 0


def collect_module_progress(page: Page) -> dict[str, object]:
    methods = {
        "ipscan": "GetIpScanProgressSnapshot",
        "urlscan": "GetUrlScanProgressSnapshot",
        "subdomain": "GetSubDomainProgressSnapshot",
        "dirscan": "GetDirScanProgressSnapshot",
        "jsfinder": "GetJsFinderProgressSnapshot",
        "poccheck": "GetPocCheckProgressSnapshot",
        "pwdcrack": "GetPwdCrackProgressSnapshot",
    }
    return page.evaluate(
        """async (methods) => {
          const app = window.go?.main?.App;
          const result = {};
          for (const [name, method] of Object.entries(methods)) {
            try { result[name] = await app[method]('Default'); }
            catch (error) { result[name] = { error: String(error) }; }
          }
          try { result.ipscanRunning = await app.IsIpScanRunning('Default'); }
          catch (error) { result.ipscanRunning = false; }
          try { result.unauthRunning = await app.IsUnAuthRunning('Default'); }
          catch (error) { result.unauthRunning = false; }
          return result;
        }""",
        methods,
    )


def progress_summary(progress: dict[str, object]) -> str:
    active: list[str] = []
    for name in (
        "ipscan",
        "urlscan",
        "subdomain",
        "dirscan",
        "jsfinder",
        "poccheck",
        "pwdcrack",
    ):
        value = progress.get(name)
        if not isinstance(value, dict):
            continue
        status = str(value.get("status") or "")
        if status != "running":
            continue
        percent = value.get("percent")
        overlay = value.get("overlayPercent")
        shown = overlay if overlay not in {None, ""} else percent
        active.append(f"{name}={shown or 0}%")
    if progress.get("ipscanRunning") and not any(
        item.startswith("ipscan=") for item in active
    ):
        active.append("ipscan=运行标志已开启/进度快照为空")
    if progress.get("unauthRunning"):
        active.append("unauth=running")
    return "，".join(active) or "未检测到活动中的 Tscan 内部任务"


def progress_has_active_tasks(progress: dict[str, object]) -> bool:
    for value in progress.values():
        if isinstance(value, dict) and str(value.get("status") or "").lower() == "running":
            return True
    return any(
        bool(progress.get(name))
        for name in ("ipscanRunning", "unauthRunning")
    )


def stalled_discovery_modules(
    progress: dict[str, object],
    last_changed: dict[str, float],
    now: float,
    threshold: float = DISCOVERY_STALL_RECOVERY_SECONDS,
) -> list[str]:
    return [
        name
        for name in DISCOVERY_STOP_METHODS
        if isinstance(progress.get(name), dict)
        and str(progress[name].get("status") or "").lower() == "running"
        and now - last_changed.get(name, now) >= threshold
    ]


def stop_discovery_modules(page: Page, modules: list[str]) -> list[str]:
    methods = [DISCOVERY_STOP_METHODS[name] for name in modules]
    result = page.evaluate(
        """async (methods) => {
          const app = window.go?.main?.App;
          const stopped = [];
          for (const method of methods) {
            try { await app[method](); stopped.push(method); } catch (_) {}
          }
          return stopped;
        }""",
        methods,
    )
    stopped_methods = result if isinstance(result, list) else []
    return [
        name
        for name, method in DISCOVERY_STOP_METHODS.items()
        if method in stopped_methods
    ]


def exhausted_stage_retries(batches: list[object]) -> list[str]:
    stages: list[str] = []
    for value in batches:
        if not isinstance(value, dict) or not value.get("retry_exhausted_at"):
            continue
        pending = value.get("pending_stages")
        if not isinstance(pending, list):
            continue
        for name in pending:
            stage = str(name)
            if stage and stage not in stages:
                stages.append(stage)
    return stages


def monitoring_state(
    progress: dict[str, object], batches: list[object] | None = None
) -> tuple[str, str, str]:
    summary = progress_summary(progress)
    if progress_has_active_tasks(progress):
        return "running", "monitoring", f"TscanPlus 任务监控：{summary}"
    exhausted = exhausted_stage_retries(batches or [])
    if exhausted:
        return (
            "manual_required",
            "retry_exhausted",
            "TscanPlus 以下阶段自动重试 3 次后仍未确认启动："
            + "、".join(exhausted)
            + "；已停止自动重试，窗口保持待机并继续接收新增资产",
        )
    return (
        "waiting_assets",
        "standby",
        "TscanPlus 当前批次已无活动内部任务；"
        "窗口保持待机，等待项目新增资产。"
        "CPU 占用较低是正常状态",
    )


def monitor_tscan_process(
    child: subprocess.Popen[bytes] | None,
    pid: int,
    port: int,
    state_path: Path,
    state: dict[str, object],
    target: str,
    scope: str,
    asset_bus: Path,
    start_scan: bool,
) -> int:
    last_rendered = ""
    last_markers: dict[str, tuple[object, ...]] = {}
    last_changed: dict[str, float] = {}
    last_log_at = 0.0
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.connect_over_cdp(
                f"http://127.0.0.1:{port}"
            )
            page = browser.contexts[0].pages[0]
            existing_batches = state.get("stage_batches")
            if isinstance(existing_batches, list):
                migrated = migrate_stage_batch_retries(
                    existing_batches, asset_bus, scope
                )
                scope_refreshed = refresh_stage_batch_scope(existing_batches, scope)
                if migrated or scope_refreshed:
                    detail = (
                        "已为旧版 TscanPlus 批次恢复资产快照和阶段重试状态"
                        if migrated
                        else "已按当前自动处理范围刷新 TscanPlus 历史批次和待重试资产"
                    )
                    append_activity(state_path, detail)
                    atomic_json_write(state_path, state)
            while tscan_process_alive(
                pid,
                int(state.get("process_creation_token") or 0),
                Path(str(state.get("exe") or "")),
            ):
                dismissed_modals = dismiss_blocking_modals(page)
                if dismissed_modals:
                    append_activity(
                        state_path,
                        "已关闭 TscanPlus 阻塞弹窗："
                        + "，".join(dismissed_modals),
                    )
                progress = collect_module_progress(page)
                now = time.monotonic()
                health: dict[str, str] = {}
                for name, value in progress.items():
                    if not isinstance(value, dict):
                        continue
                    marker = (
                        value.get("status"),
                        value.get("done"),
                        value.get("total"),
                        value.get("overlayDone"),
                        value.get("overlayTotal"),
                    )
                    if marker != last_markers.get(name):
                        last_markers[name] = marker
                        last_changed[name] = now
                    status = str(value.get("status") or "")
                    if status == "running" and now - last_changed.get(name, now) > 120:
                        health[name] = "suspected_stalled"
                ip_snapshot = progress.get("ipscan")
                if (
                    progress.get("ipscanRunning")
                    and isinstance(ip_snapshot, dict)
                    and str(ip_snapshot.get("status") or "") == "idle"
                ):
                    health["ipscan"] = "running_flag_without_progress_snapshot"

                consumed_generation = int(state.get("asset_bus_generation") or 0)
                generation, delta = read_asset_bus_bundle(
                    asset_bus,
                    after_generation=consumed_generation,
                )
                delta = filter_assets_by_scope(delta, scope)
                pending_assets = generation > consumed_generation and any(delta.values())
                stalled_modules = stalled_discovery_modules(
                    progress, last_changed, now
                )
                if pending_assets and stalled_modules:
                    stopped = stop_discovery_modules(page, stalled_modules)
                    if stopped:
                        append_activity(
                            state_path,
                            "发现类子任务长时间无进度且有新增资产等待，已仅暂停："
                            + "、".join(stopped)
                            + "；TscanPlus 主程序与其他任务继续保留。",
                        )
                        progress = collect_module_progress(page)
                batches = state.get("stage_batches")
                if not isinstance(batches, list):
                    batches = []
                    state["stage_batches"] = batches
                retry_dispatched = False
                retry_batch = retry_batch_due(batches)
                if retry_batch is not None and not progress_has_active_tasks(progress):
                    pending_stages = {
                        str(value)
                        for value in retry_batch.get("pending_stages", [])
                    }
                    retry_assets = retry_batch.get("assets")
                    if pending_stages and isinstance(retry_assets, dict):
                        retry_id = (
                            f"{retry_batch.get('batch_id', 'asset-batch')}-retry-"
                            f"{int(retry_batch.get('retry_count') or 0) + 1}"
                        )
                        append_activity(
                            state_path,
                            "TscanPlus 仅重试上次失败或未确认启动的阶段："
                            + "、".join(sorted(pending_stages)),
                        )
                        try:
                            retry_result = dispatch_stages_on_page(
                                page,
                                target,
                                retry_assets,
                                start_scan,
                                state_path,
                                state,
                                retry_id,
                                pending_stages,
                            )
                        except Exception:
                            partial_stages = state.get("stages")
                            recovered = {
                                name: (
                                    partial_stages[name]
                                    if isinstance(partial_stages, dict)
                                    and isinstance(partial_stages.get(name), dict)
                                    else {
                                        "status": "failed",
                                        "error": "Tscan 窗口在该阶段完成前关闭",
                                    }
                                )
                                for name in pending_stages
                            }
                            retry_result = {
                                "batch_id": retry_id,
                                "requested_stages": sorted(pending_stages),
                                "stages": recovered,
                                "interrupted": True,
                            }
                            record_stage_retry(retry_batch, retry_result)
                            state["automation"] = retry_result
                            state["active_batch_id"] = ""
                            atomic_json_write(state_path, state)
                            raise
                        else:
                            record_stage_retry(retry_batch, retry_result)
                            state["automation"] = retry_result
                            state["active_batch_id"] = ""
                            atomic_json_write(state_path, state)
                        progress = collect_module_progress(page)
                        retry_dispatched = True
                if (
                    pending_assets
                    and not retry_dispatched
                    and not progress_has_active_tasks(progress)
                ):
                    batch_id = f"asset-generation-{generation}"
                    append_activity(
                        state_path,
                        "TscanPlus 检测到新增资产，准备执行增量批次："
                        f"{len(delta['ips'])} IP / {len(delta['domains'])} 域名 / "
                        f"{len(delta['endpoints'])} 端点 / {len(delta['urls'])} URL。",
                    )
                    batch_result = dispatch_stages_on_page(
                        page,
                        target,
                        delta,
                        start_scan,
                        state_path,
                        state,
                        batch_id,
                    )
                    batches.append(
                        stage_batch_record(
                            batch_id=batch_id,
                            generation_from=consumed_generation + 1,
                            generation_to=generation,
                            assets=delta,
                            result=batch_result,
                        )
                    )
                    state["asset_bus_generation"] = generation
                    state["automation"] = batch_result
                    atomic_json_write(state_path, state)
                    progress = collect_module_progress(page)

                summary = progress_summary(progress)
                monitor_status, monitor_stage, monitor_detail = monitoring_state(
                    progress, batches
                )
                rendered = json.dumps(
                    {
                        "progress": progress,
                        "health": health,
                        "asset_bus_generation": state.get("asset_bus_generation", 0),
                        "monitor_status": monitor_status,
                        "monitor_stage": monitor_stage,
                        "monitor_detail": monitor_detail,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
                state.update(
                    status=monitor_status,
                    stage=monitor_stage,
                    detail=monitor_detail,
                    module_progress=progress,
                    module_health=health,
                    updated_at=now_text(),
                )
                if rendered != last_rendered:
                    atomic_json_write(state_path, state)
                    last_rendered = rendered
                log_interval = 30 if progress_has_active_tasks(progress) else 300
                if now - last_log_at >= log_interval:
                    message = f"任务进度：{summary}"
                    if health:
                        message += f"；健康提示：{health}"
                    append_activity(state_path, message)
                    last_log_at = now
                time.sleep(2.0)
    except Exception as exc:
        state.update(
            status="manual_required",
            stage="connection_lost",
            detail=f"TscanPlus 窗口或 WebView 连接中断，保留待重试阶段：{exc}",
            updated_at=now_text(),
            error=str(exc),
        )
        atomic_json_write(state_path, state)
        append_activity(state_path, str(state["detail"]))
        return 1
    return monitor_process(child, pid, state)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Launch and orchestrate the authorized TscanPlus workflow"
    )
    parser.add_argument("--exe", type=Path, default=DEFAULT_EXE)
    parser.add_argument("--target", default="")
    parser.add_argument("--project", default="")
    parser.add_argument("--scope", default="*")
    parser.add_argument("--state", type=Path, default=Path("tscan_state.json"))
    parser.add_argument("--asset-state", type=Path, default=Path("asset_workflow_state.json"))
    parser.add_argument("--asset-export", type=Path, default=Path("asset_commander_assets.json"))
    parser.add_argument("--asset-bus", type=Path, default=Path("asset_bus.json"))
    parser.add_argument("--prepare-only", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source_exe = args.exe.resolve()
    state_path = args.state.resolve()
    previous = read_json(state_path)
    interrupted_retry_recovered = reconcile_interrupted_stage_retry(previous)
    previous_exe = Path(str(previous.get("exe") or ""))
    child_pid = int(previous.get("pid") or 0)
    child_creation_token = int(previous.get("process_creation_token") or 0)
    automation_dispatched, restored_automation, restored_stages = (
        restore_dispatched_automation(previous)
    )
    if (
        previous_exe.is_file()
        and tscan_process_alive(child_pid, child_creation_token, previous_exe)
    ):
        exe = previous_exe.resolve()
    elif source_exe.is_file():
        exe = prepare_tscan_workspace(source_exe, state_path)
    else:
        exe = source_exe
    state: dict[str, object] = {
        "schema_version": 2,
        "status": "starting",
        "stage": "starting",
        "detail": "正在启动 TscanPlus",
        "created_at": previous.get("created_at") or now_text(),
        "updated_at": now_text(),
        "exe": str(exe),
        "target": args.target,
        "project": args.project,
        "scope": args.scope,
        "pid": None,
        "process_creation_token": child_creation_token,
        "cdp_port": None,
        "automation": restored_automation,
        "automation_dispatched": automation_dispatched,
        "stages": restored_stages,
        "asset_counts": previous.get("asset_counts", {}),
        "asset_bus_generation": int(previous.get("asset_bus_generation") or 0),
        "stage_batches": previous.get("stage_batches", []),
        "error": "",
    }
    atomic_json_write(state_path, state)
    if interrupted_retry_recovered:
        append_activity(
            state_path,
            "已恢复上次中断的阶段重试结果，仅保留仍失败或未确认启动的阶段",
        )
    if not exe.is_file():
        state.update(status="failed", updated_at=now_text(), error=f"Tscan executable not found: {exe}")
        atomic_json_write(state_path, state)
        return 1

    child: subprocess.Popen[bytes] | None = None
    port = int(previous.get("cdp_port") or 0)
    reattached = False
    try:
        if tscan_process_alive(child_pid, child_creation_token, previous_exe) and port:
            try:
                wait_for_cdp(port, timeout=2.0)
            except RuntimeError:
                append_activity(
                    state_path,
                    f"发现旧 TscanPlus 进程 PID {child_pid} 无法接管，先关闭后重新启动",
                )
                terminate_tscan_process_tree(child_pid)
                child_pid = 0
                child_creation_token = 0
            else:
                reattached = True
                state.update(
                    pid=child_pid,
                    process_creation_token=child_creation_token,
                    cdp_port=port,
                )
                update_stage(
                    state_path,
                    state,
                    "reattached",
                    f"已重新接管仍在运行的 TscanPlus，PID {child_pid}",
                )

        if not reattached:
            if not state["automation_dispatched"]:
                state["automation"] = None
                state["stages"] = {}
            port = free_local_port()
            state["cdp_port"] = port
            atomic_json_write(state_path, state)
            run_dir = state_path.parents[2]
            state["cdp_launch"] = {
                "method": "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS_POLICY",
                "port": port,
                "user_data_folder": str(
                    run_dir / "tool_data" / "tscan" / "webview2_data"
                ),
            }
            atomic_json_write(state_path, state)
            try:
                with BrowserPolicy(port, exe.name):
                    child = subprocess.Popen(
                        [str(exe)],
                        cwd=exe.parent,
                        creationflags=CREATE_NEW_PROCESS_GROUP,
                        close_fds=True,
                        env=webview_environment(port, run_dir),
                    )
                    child_pid = child.pid
                    child_creation_token = process_creation_token(child_pid)
                    state.update(
                        pid=child_pid,
                        process_creation_token=child_creation_token,
                        updated_at=now_text(),
                    )
                    update_stage(
                        state_path,
                        state,
                        "waiting_webview2",
                        f"TscanPlus 已启动，等待 WebView2/CDP 就绪，最长 {int(CDP_START_TIMEOUT_SECONDS)} 秒",
                    )
                    wait_for_cdp(port, timeout=CDP_START_TIMEOUT_SECONDS)
            except Exception:
                if tscan_process_alive(child_pid, child_creation_token, exe):
                    append_activity(
                        state_path,
                        f"TscanPlus 启动或 CDP 接管失败，清理未接管进程 PID {child_pid}",
                    )
                    terminate_tscan_process_tree(child_pid)
                child_pid = 0
                child_creation_token = 0
                state.update(pid=None, process_creation_token=0, updated_at=now_text())
                atomic_json_write(state_path, state)
                raise

        if not state["automation_dispatched"]:
            assets = wait_for_asset_bundle(
                args.asset_state.resolve(),
                args.asset_export.resolve(),
                args.asset_bus.resolve(),
                args.target,
                args.scope,
                child_pid,
                state_path,
                state,
            )
            if assets is None:
                state.update(
                    status="completed",
                    stage="closed_while_waiting",
                    detail="TscanPlus 在等待资产期间已关闭",
                    updated_at=now_text(),
                )
                atomic_json_write(state_path, state)
                return 0
            automation = automate(
                port,
                args.target,
                assets,
                not args.prepare_only,
                state_path,
                state,
            )
            bus_generation, _bus_bundle = read_asset_bus_bundle(
                args.asset_bus.resolve(), args.target
            )
            stage_batches = state.get("stage_batches")
            if not isinstance(stage_batches, list):
                stage_batches = []
            stage_batches.append(
                stage_batch_record(
                    batch_id="initial",
                    generation_from=1 if bus_generation else 0,
                    generation_to=bus_generation,
                    assets=assets,
                    result=automation,
                )
            )
            state.update(
                automation=automation,
                automation_dispatched=True,
                stages=automation["stages"],
                asset_bus_generation=bus_generation,
                stage_batches=stage_batches,
            )

        stages = state.get("stages", {})
        counts: dict[str, int] = {}
        waiting: list[str] = []
        failed: list[str] = []
        if isinstance(stages, dict):
            for name, value in stages.items():
                status = str(value.get("status") or "unknown") if isinstance(value, dict) else "unknown"
                counts[status] = counts.get(status, 0) + 1
                if status == "waiting_configuration":
                    waiting.append(name)
                elif status == "failed":
                    failed.append(name)
        detail = (
            "TscanPlus 阶段调度完成："
            f"已提交 {counts.get('submitted', 0)}，"
            f"未确认启动 {counts.get('not_started', 0)}，"
            f"等待配置 {counts.get('waiting_configuration', 0)}，"
            f"跳过 {counts.get('skipped', 0)}，"
            f"失败 {counts.get('failed', 0)}"
        )
        if waiting:
            detail += "；等待配置：" + ", ".join(waiting)
        if failed:
            detail += "；失败阶段：" + ", ".join(failed)
        if args.prepare_only:
            detail = "TscanPlus 核心扫描阶段已完成界面准备，未点击扫描按钮"
        update_stage(state_path, state, "running", detail)
        exit_code = monitor_tscan_process(
            child,
            child_pid,
            port,
            state_path,
            state,
            args.target,
            args.scope,
            args.asset_bus.resolve(),
            not args.prepare_only,
        )
        if exit_code == 0:
            state.update(status="completed", updated_at=now_text(), exit_code=0)
        else:
            state.update(
                status="manual_required",
                updated_at=now_text(),
                exit_code=exit_code,
            )
        atomic_json_write(state_path, state)
        return int(exit_code)
    except Exception as exc:
        state.update(
            status="manual_required",
            stage="manual_required",
            detail=f"自动操作未完成，TscanPlus 保持打开供手动继续：{exc}",
            updated_at=now_text(),
            error=str(exc),
        )
        atomic_json_write(state_path, state)
        append_activity(state_path, str(state["detail"]))
        if tscan_process_alive(
            child_pid,
            int(state.get("process_creation_token") or 0),
            Path(str(state.get("exe") or "")),
        ):
            monitor_process(child, child_pid, state)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
