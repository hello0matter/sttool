from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time
import winreg
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen

import psutil
from playwright.sync_api import Locator, Page, sync_playwright


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
        os.replace(temporary, path)
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
    if host:
        try:
            ipaddress.ip_address(host)
            ips.append(host)
        except ValueError:
            domains.append(host)
    if target.strip().lower().startswith(("http://", "https://")):
        urls.append(target.strip())
    return {"ips": ips, "domains": domains, "urls": urls}


def read_asset_bundle(path: Path, target: str = "") -> dict[str, list[str]]:
    value = read_json(path)
    fallback = target_asset_bundle(target)
    bundle: dict[str, list[str]] = {}
    for key in ("ips", "domains", "urls"):
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
        "urls": [],
    }
    result = {key: list(values) for key, values in fallback.items()}
    mapping = {"ip": "ips", "domain": "domains", "url": "urls"}
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


def merge_asset_bundles(*bundles: dict[str, list[str]]) -> dict[str, list[str]]:
    return {
        key: _unique(
            [value for bundle in bundles for value in bundle.get(key, [])]
        )
        for key in ("ips", "domains", "urls")
    }


def filter_assets_by_scope(
    bundle: dict[str, list[str]], scope: str
) -> dict[str, list[str]]:
    result = {"ips": [], "domains": [], "urls": []}
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


def password_targets(ips: list[str]) -> list[str]:
    targets: list[str] = []
    for value in ips:
        host = _host_from_value(value)
        try:
            ipaddress.ip_address(host)
        except ValueError:
            continue
        targets.append(host)
    return _unique(targets)


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
    arguments = (
        f"--remote-debugging-port={port} "
        "--remote-allow-origins=* --force-renderer-accessibility"
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


class BrowserPolicy:
    def __init__(self, port: int, executable_name: str = POLICY_NAME) -> None:
        self.executable_name = executable_name
        self.value = (
            f"--remote-debugging-port={port} --remote-allow-origins=* "
            "--force-renderer-accessibility"
        )
        self.entries: list[tuple[int, int, bool, tuple[object, int] | None]] = []

    def __enter__(self) -> "BrowserPolicy":
        last_error: OSError | None = None
        view_flags = (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY)
        for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            for view_flag in view_flags:
                access = winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE | view_flag
                try:
                    key = winreg.CreateKeyEx(root, POLICY_PATH, 0, access)
                except OSError as exc:
                    last_error = exc
                    continue
                try:
                    try:
                        previous = winreg.QueryValueEx(key, self.executable_name)
                        existed = True
                    except FileNotFoundError:
                        previous = None
                        existed = False
                    winreg.SetValueEx(key, self.executable_name, 0, winreg.REG_SZ, self.value)
                    self.entries.append((root, view_flag, existed, previous))
                finally:
                    winreg.CloseKey(key)
        if not self.entries:
            raise RuntimeError(f"cannot configure WebView2 browser arguments: {last_error}")
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        for root, view_flag, existed, previous in reversed(self.entries):
            access = winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE | view_flag
            try:
                key = winreg.OpenKey(root, POLICY_PATH, 0, access)
            except FileNotFoundError:
                continue
            try:
                if existed and previous is not None:
                    winreg.SetValueEx(key, self.executable_name, 0, previous[1], previous[0])
                else:
                    try:
                        winreg.DeleteValue(key, self.executable_name)
                    except FileNotFoundError:
                        pass
            finally:
                winreg.CloseKey(key)


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


def select_available_pocs(page: Page) -> int:
    result = page.evaluate(
        """() => {
          const visible = (element) => {
            const rect = element.getBoundingClientRect();
            const style = getComputedStyle(element);
            return rect.width > 0 && rect.height > 0
              && style.display !== 'none' && style.visibility !== 'hidden';
          };
          const enabled = [...document.querySelectorAll('[role="checkbox"]')]
            .filter((element) => visible(element)
              && element.getAttribute('aria-disabled') !== 'true'
              && !element.hasAttribute('disabled'));
          if (!enabled.length) return { available: 0, selected: 0 };
          const selectedBefore = enabled.filter(
            (element) => element.getAttribute('aria-checked') === 'true'
          ).length;
          for (const element of enabled) {
            if (element.getAttribute('aria-checked') !== 'true') element.click();
          }
          return { available: enabled.length, selected: selectedBefore };
        }"""
    )
    page.wait_for_timeout(250)
    selected = page.evaluate(
        """() => [...document.querySelectorAll('[role="checkbox"]')].filter((element) => {
          const rect = element.getBoundingClientRect();
          const style = getComputedStyle(element);
          return rect.width > 0 && rect.height > 0
            && style.display !== 'none' && style.visibility !== 'hidden'
            && element.getAttribute('aria-disabled') !== 'true'
            && element.getAttribute('aria-checked') === 'true';
        }).length"""
    )
    return int(selected or result.get("selected", 0))


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
    selected_pocs = select_available_pocs(page)
    clicked = False
    reason = ""
    if start_scan and normalized and selected_pocs:
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
    return {
        "targets": normalized,
        "selected_pocs": selected_pocs,
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
    normalized = _unique(targets)
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
) -> dict[str, object]:
    stages: dict[str, dict[str, object]] = {}

    def run_stage(name: str, detail: str, callback) -> None:
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

    asset_targets = _unique(
        [target_for_asset_scan(target), *assets["domains"], *assets["ips"]]
    )
    poc_targets = normalize_poc_urls(assets["urls"], assets["domains"], target)
    fingerprint_targets = web_fingerprint_targets(
        assets["urls"], assets["domains"], target
    )
    crack_targets = password_targets(assets["ips"])
    nessus_targets = _unique([*assets["domains"], *assets["ips"]])
    subdomain_targets = root_domains(assets["domains"])
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
    run_stage(
        "web_fingerprint",
        f"已导入 {len(fingerprint_targets)} 个端点，正在启动 Web 指纹",
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
    run_stage(
        "subdomain_enumeration",
        f"已导入 {len(subdomain_targets)} 个根域名，正在启动域名枚举",
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
    run_stage(
        "directory_enumeration",
        f"已导入 {len(poc_targets)} 个 URL，正在启动目录枚举",
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
    run_stage(
        "jsfinder",
        f"已导入 {len(poc_targets)} 个 URL，正在启动 JsFinder",
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
    run_stage(
        "swagger",
        f"已导入 {len(poc_targets)} 个 URL，正在启动 Swagger 检测",
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
    run_stage(
        "waf_detection",
        f"已导入 {len(poc_targets)} 个 URL，正在启动 WAF 识别",
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
    run_stage(
        "poc_check",
        f"已导入 {len(poc_targets)} 个 URL，正在启动 POC 检测",
        lambda: configure_poc_check(page, poc_targets, start_scan),
    )
    run_stage(
        "unauthorized_check",
        f"已导入 {len(nessus_targets)} 个域名/IP，正在启动未授权检测",
        lambda: configure_unauthorized_check(page, nessus_targets, start_scan),
    )
    run_stage(
        "password_crack",
        f"已导入 {len(crack_targets)} 个 IP，正在启动密码检测",
        lambda: configure_password_crack(page, crack_targets, start_scan),
    )
    run_stage(
        "dump_all",
        f"已导入 {len(poc_targets)} 个 URL，正在启动 DumpAll 检测",
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
    run_stage(
        "awvs_scan",
        f"已导入 {len(poc_targets)} 个 URL，正在测试连接并启动 AWVS",
        lambda: configure_awvs_scan(page, poc_targets, start_scan),
    )
    run_stage(
        "nessus_scan",
        f"已导入 {len(nessus_targets)} 个域名/IP，正在测试连接并启动 Nessus",
        lambda: configure_nessus_scan(page, nessus_targets, start_scan),
    )
    click_tab(page, "AssetDetect")
    status_counts: dict[str, int] = {}
    for value in stages.values():
        status = str(value.get("status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
    return {
        "batch_id": batch_id,
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


def monitoring_state(progress: dict[str, object]) -> tuple[str, str, str]:
    summary = progress_summary(progress)
    if progress_has_active_tasks(progress):
        return "running", "monitoring", f"TscanPlus 任务监控：{summary}"
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
                if (
                    generation > consumed_generation
                    and any(delta.values())
                    and not progress_has_active_tasks(progress)
                ):
                    batch_id = f"asset-generation-{generation}"
                    append_activity(
                        state_path,
                        "TscanPlus 检测到新增资产，准备执行增量批次："
                        f"{len(delta['ips'])} IP / {len(delta['domains'])} 域名 / "
                        f"{len(delta['urls'])} URL。",
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
                    batches = state.get("stage_batches")
                    if not isinstance(batches, list):
                        batches = []
                        state["stage_batches"] = batches
                    batches.append(
                        {
                            "batch_id": batch_id,
                            "generation_from": consumed_generation + 1,
                            "generation_to": generation,
                            "dispatched_at": now_text(),
                            "result": batch_result,
                        }
                    )
                    state["asset_bus_generation"] = generation
                    state["automation"] = batch_result
                    atomic_json_write(state_path, state)
                    progress = collect_module_progress(page)

                summary = progress_summary(progress)
                monitor_status, monitor_stage, monitor_detail = monitoring_state(progress)
                rendered = json.dumps(
                    {
                        "progress": progress,
                        "health": health,
                        "asset_bus_generation": state.get("asset_bus_generation", 0),
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
                if now - last_log_at >= log_interval or health:
                    message = f"任务进度：{summary}"
                    if health:
                        message += f"；健康提示：{health}"
                    append_activity(state_path, message)
                    last_log_at = now
                time.sleep(2.0)
    except Exception as exc:
        append_activity(state_path, f"进度监控降级为进程监控：{exc}")
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
    previous_exe = Path(str(previous.get("exe") or ""))
    child_pid = int(previous.get("pid") or 0)
    child_creation_token = int(previous.get("process_creation_token") or 0)
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
        "automation": previous.get("automation"),
        "automation_dispatched": bool(previous.get("automation_dispatched", False)),
        "stages": previous.get("stages", {}),
        "asset_counts": previous.get("asset_counts", {}),
        "asset_bus_generation": int(previous.get("asset_bus_generation") or 0),
        "stage_batches": previous.get("stage_batches", []),
        "error": "",
    }
    atomic_json_write(state_path, state)
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
                pass
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
            state["automation"] = None
            state["automation_dispatched"] = False
            state["stages"] = {}
            port = free_local_port()
            state["cdp_port"] = port
            atomic_json_write(state_path, state)
            with BrowserPolicy(port, exe.name):
                run_dir = state_path.parents[2]
                state["cdp_launch"] = {
                    "method": "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
                    "port": port,
                    "user_data_folder": str(
                        run_dir / "tool_data" / "tscan" / "webview2_data"
                    ),
                }
                atomic_json_write(state_path, state)
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
                {
                    "batch_id": "initial",
                    "generation_from": 1 if bus_generation else 0,
                    "generation_to": bus_generation,
                    "dispatched_at": now_text(),
                    "result": automation,
                }
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
        state.update(status="completed", updated_at=now_text(), exit_code=exit_code)
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
