from __future__ import annotations

import json
import os
from pathlib import Path


DEFAULT_TOOL_NETWORK = {
    "mode": "direct",
    "host": "127.0.0.1",
    "port": 7891,
    "header_name": "",
    "header_value": "",
}
_PROXY_KEYS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)


def normalize_tool_network(value: object) -> dict[str, object]:
    source = value if isinstance(value, dict) else {}
    mode = str(source.get("mode") or "direct").strip().lower()
    if mode not in {"direct", "http", "socks5"}:
        mode = "direct"
    host = str(source.get("host") or "127.0.0.1").strip() or "127.0.0.1"
    try:
        port = int(source.get("port") or 7891)
    except (TypeError, ValueError):
        port = 7891
    port = max(1, min(65535, port))
    header_name = str(source.get("header_name") or "").strip()
    header_value = str(source.get("header_value") or "").strip()
    if any(char in header_name or char in header_value for char in ("\r", "\n")):
        header_name = ""
        header_value = ""
    if not header_name or not header_value:
        header_name = ""
        header_value = ""
    return {
        "mode": mode,
        "host": host,
        "port": port,
        "header_name": header_name,
        "header_value": header_value,
    }


def load_tool_network(app_dir: Path) -> dict[str, object]:
    try:
        value = json.loads((app_dir / "launcher_settings.json").read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return dict(DEFAULT_TOOL_NETWORK)
    return normalize_tool_network(value.get("tool_network") if isinstance(value, dict) else None)


def _proxy_host(settings: dict[str, object]) -> tuple[dict[str, object], str]:
    normalized = normalize_tool_network(settings)
    host = str(normalized["host"])
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return normalized, host


def proxy_url(settings: dict[str, object]) -> str:
    normalized, host = _proxy_host(settings)
    mode = str(normalized["mode"])
    if mode == "direct":
        return ""
    scheme = "socks5h" if mode == "socks5" else "http"
    return f"{scheme}://{host}:{int(normalized['port'])}"


def http_fallback_proxy_url(settings: dict[str, object]) -> str:
    normalized, host = _proxy_host(settings)
    if str(normalized["mode"]) == "direct":
        return ""
    return f"http://{host}:{int(normalized['port'])}"


def tool_environment(
    settings: dict[str, object],
    base: dict[str, str] | None = None,
) -> dict[str, str]:
    environment = dict(os.environ if base is None else base)
    for key in _PROXY_KEYS:
        environment.pop(key, None)
    normalized = normalize_tool_network(settings)
    url = proxy_url(normalized)
    fallback_url = http_fallback_proxy_url(normalized)
    if url:
        if str(normalized["mode"]) == "socks5":
            # Generic tools often understand HTTP_PROXY but not SOCKS URLs.
            environment["HTTP_PROXY"] = fallback_url
            environment["HTTPS_PROXY"] = fallback_url
            environment["ALL_PROXY"] = url
        else:
            environment["HTTP_PROXY"] = url
            environment["HTTPS_PROXY"] = url
            environment["ALL_PROXY"] = url
    environment["STTOOL_TOOL_NETWORK_MODE"] = str(normalized["mode"])
    environment["STTOOL_TOOL_PROXY_URL"] = url
    environment["STTOOL_TOOL_HTTP_FALLBACK_PROXY_URL"] = fallback_url
    environment["STTOOL_HTTP_HEADER_NAME"] = str(normalized["header_name"])
    environment["STTOOL_HTTP_HEADER_VALUE"] = str(normalized["header_value"])
    return environment


def settings_from_environment() -> dict[str, object]:
    url = os.environ.get("STTOOL_TOOL_PROXY_URL", "").strip()
    mode = os.environ.get("STTOOL_TOOL_NETWORK_MODE", "direct").strip().lower()
    host = "127.0.0.1"
    port = 7891
    if url:
        from urllib.parse import urlsplit

        parsed = urlsplit(url)
        host = parsed.hostname or host
        port = parsed.port or port
        if parsed.scheme.startswith("socks"):
            mode = "socks5"
        elif parsed.scheme:
            mode = "http"
    return normalize_tool_network(
        {
            "mode": mode,
            "host": host,
            "port": port,
            "header_name": os.environ.get("STTOOL_HTTP_HEADER_NAME", ""),
            "header_value": os.environ.get("STTOOL_HTTP_HEADER_VALUE", ""),
        }
    )


def _socks5_available() -> bool:
    try:
        __import__("socks")
    except ImportError:
        return False
    return True


def apply_session_network(session: object) -> None:
    settings = settings_from_environment()
    url = proxy_url(settings)
    if str(settings["mode"]) == "socks5" and not _socks5_available():
        url = http_fallback_proxy_url(settings)
    if url and hasattr(session, "proxies"):
        session.proxies.update({"http": url, "https": url})
    header_name = str(settings["header_name"])
    header_value = str(settings["header_value"])
    if header_name and header_value and hasattr(session, "headers"):
        session.headers[header_name] = header_value


def cli_network_args(tool: str) -> list[str]:
    settings = settings_from_environment()
    url = (
        http_fallback_proxy_url(settings)
        if tool == "dirsearch" and str(settings["mode"]) == "socks5"
        else proxy_url(settings)
    )
    name = str(settings["header_name"])
    value = str(settings["header_value"])
    args: list[str] = []
    if tool == "nuclei":
        if url:
            args.extend(["-proxy", url])
        if name and value:
            args.extend(["-H", f"{name}: {value}"])
    elif tool == "dirsearch":
        if url:
            args.extend(["--proxy", url])
        if name and value:
            args.extend(["--header", f"{name}: {value}"])
    return args


def webview_proxy_argument() -> str:
    settings = settings_from_environment()
    url = proxy_url(settings)
    if not url:
        return ""
    # Chromium accepts socks5:// rather than requests' socks5h:// spelling.
    return "--proxy-server=" + url.replace("socks5h://", "socks5://", 1)


__all__ = [
    "DEFAULT_TOOL_NETWORK",
    "apply_session_network",
    "cli_network_args",
    "http_fallback_proxy_url",
    "load_tool_network",
    "normalize_tool_network",
    "proxy_url",
    "settings_from_environment",
    "tool_environment",
    "webview_proxy_argument",
]
