from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import subprocess
import tempfile
import time
import winreg
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen

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
    result = subprocess.run(
        ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
        capture_output=True,
        text=True,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return str(pid) in result.stdout


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
    def __init__(self, port: int) -> None:
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
                        previous = winreg.QueryValueEx(key, POLICY_NAME)
                        existed = True
                    except FileNotFoundError:
                        previous = None
                        existed = False
                    winreg.SetValueEx(key, POLICY_NAME, 0, winreg.REG_SZ, self.value)
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
                    winreg.SetValueEx(key, POLICY_NAME, 0, previous[1], previous[0])
                else:
                    try:
                        winreg.DeleteValue(key, POLICY_NAME)
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


def visible(locator: Locator) -> Locator:
    for index in range(locator.count()):
        candidate = locator.nth(index)
        if candidate.is_visible():
            return candidate
    raise RuntimeError("visible Tscan control not found")


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
    visible(page.locator(f'.n-tabs-tab[data-name="{name}"]')).click(force=True)
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
    acknowledged = False
    snapshot: object = None
    reason = ""
    if not normalized:
        reason = "没有可导入的目标"
    elif start_scan:
        button.click(force=True)
        clicked = True
        acknowledged, snapshot = wait_for_stage_ack(
            page, button, progress_method=progress_method
        )
        if not acknowledged:
            reason = "已点击启动，但 Tscan 未在 10 秒内确认任务进入运行状态"
    return {
        "target_count": len(normalized),
        "clicked": clicked,
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
        visible(page.get_by_role("button", name="查询", exact=True)).click(force=True)
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
        web_radio.click(force=True)

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
        scan_button.click(force=True)
        scan_clicked = True
        acknowledged, snapshot = wait_for_stage_ack(
            page, scan_button, progress_method="IsIpScanRunning"
        )

    return {
        "targets": _unique(targets),
        "profile": "web",
        "thread_count": 100,
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
          if (!selectedBefore) enabled[0].click();
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
        check_button.click(force=True)
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
        crack_button.click(force=True)
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
    reason = ""
    if not normalized:
        reason = "没有可导入的 HTTP/HTTPS URL"
    elif not configured:
        reason = "AWVS API 或 API Key 尚未配置"
    elif start_scan:
        visible(page.get_by_role("button", name="连接测试", exact=True)).click(
            force=True
        )
        connection_tested = True
        page.wait_for_timeout(800)
        start_button = visible(
            page.get_by_role("button", name="开始扫描", exact=True)
        )
        start_button.click(force=True)
        clicked = True
        acknowledged, snapshot = wait_for_stage_ack(page, start_button)
        if not acknowledged:
            reason = "已点击启动，但 Tscan 未确认 AWVS 任务进入运行状态"
    return {
        "target_count": len(normalized),
        "configured": configured,
        "connection_tested": connection_tested,
        "scan_clicked": clicked,
        "acknowledged": locals().get("acknowledged", False),
        "progress": locals().get("snapshot"),
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
    reason = ""
    if not normalized:
        reason = "没有可导入的域名或 IP"
    elif not configured:
        reason = "Nessus API、Access Key 或 Secret Key 尚未配置"
    elif start_scan:
        visible(page.get_by_role("button", name="测试", exact=True)).click(force=True)
        connection_tested = True
        page.wait_for_timeout(800)
        start_button = visible(
            page.get_by_role("button", name="开始扫描", exact=True)
        )
        start_button.click(force=True)
        clicked = True
        acknowledged, snapshot = wait_for_stage_ack(page, start_button)
        if not acknowledged:
            reason = "已点击启动，但 Tscan 未确认 Nessus 任务进入运行状态"
    return {
        "target_count": len(normalized),
        "configured": configured,
        "connection_tested": connection_tested,
        "scan_clicked": clicked,
        "acknowledged": locals().get("acknowledged", False),
        "progress": locals().get("snapshot"),
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
        if any(keyword in reason for keyword in ("配置", "API", "Key", "License")):
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


def automate(
    port: int,
    target: str,
    assets: dict[str, list[str]],
    start_scan: bool,
    state_path: Path,
    state: dict[str, object],
) -> dict[str, object]:
    os.environ["NO_PROXY"] = "127.0.0.1,localhost"
    endpoint = wait_for_cdp(port)
    with sync_playwright() as playwright:
        browser = playwright.chromium.connect_over_cdp(f"http://127.0.0.1:{port}")
        if not browser.contexts or not browser.contexts[0].pages:
            raise RuntimeError("Tscan WebView2 page was not found")
        page = browser.contexts[0].pages[0]
        page.wait_for_load_state("domcontentloaded")
        stages: dict[str, dict[str, object]] = {}

        def run_stage(name: str, detail: str, callback) -> None:
            previous_stages = state.get("stages", {})
            if isinstance(previous_stages, dict):
                previous = previous_stages.get(name, {})
                if isinstance(previous, dict) and previous.get("status") in {
                    "submitted",
                    "prepared",
                }:
                    stages[name] = previous
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
            atomic_json_write(state_path, state)

        asset_targets = _unique(
            [target_for_asset_scan(target), *assets["domains"], *assets["ips"]]
        )
        poc_targets = normalize_poc_urls(assets["urls"], assets["domains"], target)
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
            f"已导入 {len(poc_targets)} 个 URL，正在启动 Web 指纹",
            lambda: configure_textarea_scan(
                page,
                "AssetDetect",
                "UrlScan",
                "不加http前缀",
                poc_targets,
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
            lambda: configure_textarea_scan(
                page,
                "VulCheck",
                "UnAuth",
                "支持 IP/域名/网段",
                nessus_targets,
                "开始",
                start_scan,
                "IsUnAuthRunning",
            ),
        )
        run_stage(
            "password_crack",
            f"已导入 {len(crack_targets)} 个 IP，正在启动密码检测",
            lambda: configure_password_crack(page, crack_targets, start_scan),
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
            "cdp_endpoint": endpoint,
            "page_url": page.url,
            "page_title": page.title(),
            "stages": stages,
            "stage_status_counts": status_counts,
            "asset_counts": {key: len(values) for key, values in assets.items()},
        }


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
        return filter_assets_by_scope(target_asset_bundle(target), scope)

    last_detail = ""
    while process_alive(child_pid):
        workflow = read_json(asset_state)
        workflow_status = str(workflow.get("status", "waiting")).lower()
        if workflow_assets_ready(asset_state) and asset_export.is_file():
            bundle = filter_assets_by_scope(
                read_asset_bundle(asset_export, target), scope
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


def monitor_process(child: subprocess.Popen[bytes] | None, pid: int) -> int:
    if child is not None:
        return int(child.wait())
    while process_alive(pid):
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


def monitor_tscan_process(
    child: subprocess.Popen[bytes] | None,
    pid: int,
    port: int,
    state_path: Path,
    state: dict[str, object],
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
            while process_alive(pid):
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
                summary = progress_summary(progress)
                rendered = json.dumps(
                    {"progress": progress, "health": health},
                    ensure_ascii=False,
                    sort_keys=True,
                )
                state.update(
                    status="running",
                    stage="monitoring",
                    detail=f"TscanPlus 任务监控：{summary}",
                    module_progress=progress,
                    module_health=health,
                    updated_at=now_text(),
                )
                if rendered != last_rendered:
                    atomic_json_write(state_path, state)
                    last_rendered = rendered
                if now - last_log_at >= 30 or health:
                    message = f"任务进度：{summary}"
                    if health:
                        message += f"；健康提示：{health}"
                    append_activity(state_path, message)
                    last_log_at = now
                time.sleep(2.0)
    except Exception as exc:
        append_activity(state_path, f"进度监控降级为进程监控：{exc}")
    return monitor_process(child, pid)


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
    parser.add_argument("--prepare-only", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    exe = args.exe.resolve()
    state_path = args.state.resolve()
    previous = read_json(state_path)
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
        "cdp_port": None,
        "automation": previous.get("automation"),
        "automation_dispatched": bool(previous.get("automation_dispatched", False)),
        "stages": previous.get("stages", {}),
        "asset_counts": previous.get("asset_counts", {}),
        "error": "",
    }
    atomic_json_write(state_path, state)
    if not exe.is_file():
        state.update(status="failed", updated_at=now_text(), error=f"Tscan executable not found: {exe}")
        atomic_json_write(state_path, state)
        return 1

    child: subprocess.Popen[bytes] | None = None
    child_pid = int(previous.get("pid") or 0)
    port = int(previous.get("cdp_port") or 0)
    reattached = False
    try:
        if process_alive(child_pid) and port:
            try:
                wait_for_cdp(port, timeout=2.0)
            except RuntimeError:
                pass
            else:
                reattached = True
                state.update(pid=child_pid, cdp_port=port)
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
            with BrowserPolicy(port):
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
                state.update(pid=child_pid, updated_at=now_text())
                atomic_json_write(state_path, state)
                wait_for_cdp(port)

        if not state["automation_dispatched"]:
            assets = wait_for_asset_bundle(
                args.asset_state.resolve(),
                args.asset_export.resolve(),
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
            state.update(
                automation=automation,
                automation_dispatched=True,
                stages=automation["stages"],
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
            child, child_pid, port, state_path, state
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
        if process_alive(child_pid):
            monitor_process(child, child_pid)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
