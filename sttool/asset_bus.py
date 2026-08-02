from __future__ import annotations

import ipaddress
import json
import os
import re
import sqlite3
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit, urlunsplit


ASSET_TYPES = ("ip", "domain", "endpoint", "url")
_FSCAN_URL_RE = re.compile(r"https?://[^\s\[\]<>]+", re.IGNORECASE)
_HOST_PORT_RE = re.compile(
    r"(?<![\w.-])(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9][A-Za-z0-9.-]*):(?P<port>\d{1,5})(?!\d)"
)
_DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_-])"
)


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


def _host(value: str) -> str:
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
        host = _host(token)
        try:
            suffix = token.split("://", 1)[-1].split("/", 1)
            candidate = f"{host}/{suffix[1]}" if len(suffix) == 2 else host
            networks.append(ipaddress.ip_network(candidate, strict=False))
            continue
        except ValueError:
            pass
        if host:
            domains.append(host)
    return networks, list(dict.fromkeys(domains))


def asset_allowed(value: str, scope: str) -> bool:
    if scope.strip() == "*":
        return True
    host = _host(value)
    if not host:
        return False
    networks, domains = _scope_rules(scope)
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return any(host == domain or host.endswith(f".{domain}") for domain in domains)
    return any(address in network for network in networks)


def normalize_asset(value: str, asset_type: str = "") -> tuple[str, str] | None:
    raw = value.strip().strip("'\";,)")
    if not raw:
        return None
    if raw.lower().startswith(("http://", "https://")):
        parsed = urlsplit(raw)
        if not parsed.hostname:
            return None
        scheme = parsed.scheme.lower()
        host = parsed.hostname.lower()
        try:
            port = parsed.port
        except ValueError:
            return None
        default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        netloc = host if port is None or default else f"{host}:{port}"
        path = parsed.path or "/"
        return urlunsplit((scheme, netloc, path, parsed.query, "")), "url"
    host = _host(raw)
    if not host:
        return None
    parsed = urlsplit(f"//{raw}")
    try:
        port = parsed.port
    except ValueError:
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not _DOMAIN_RE.fullmatch(host):
            return None
        kind = "endpoint" if port is not None else "domain"
    else:
        host = address.compressed
        kind = "endpoint" if port is not None else "ip"
    if asset_type in ASSET_TYPES and asset_type != "url":
        kind = asset_type
    return (f"{host}:{port}" if port is not None else host), kind


def target_assets(target: str) -> list[tuple[str, str]]:
    normalized = normalize_asset(target)
    if normalized is None:
        return []
    value, kind = normalized
    assets = [(value, kind)]
    host = _host(value)
    if host:
        try:
            ipaddress.ip_address(host)
            assets.append((host, "ip"))
        except ValueError:
            assets.append((host, "domain"))
    return list(dict.fromkeys(assets))


def parse_fscan_output(content: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for match in _FSCAN_URL_RE.finditer(content):
        normalized = normalize_asset(match.group(0))
        if normalized is not None:
            found.append(normalized)
    for match in _HOST_PORT_RE.finditer(content):
        normalized = normalize_asset(match.group(0), "endpoint")
        if normalized is not None:
            found.append(normalized)
            host = _host(normalized[0])
            if host:
                try:
                    ipaddress.ip_address(host)
                    found.append((host, "ip"))
                except ValueError:
                    found.append((host, "domain"))
    return list(dict.fromkeys(found))


def parse_asset_export(path: Path) -> list[tuple[str, str]]:
    value = read_json(path)
    result: list[tuple[str, str]] = []
    for key, kind in (("ips", "ip"), ("domains", "domain"), ("urls", "url")):
        entries = value.get(key, [])
        if not isinstance(entries, list):
            continue
        for entry in entries:
            normalized = normalize_asset(str(entry), kind)
            if normalized is not None:
                result.append(normalized)
    return list(dict.fromkeys(result))


def _split_values(value: object) -> list[str]:
    if value is None:
        return []
    return [item.strip() for item in re.split(r"[\s,;]+", str(value)) if item.strip()]


def extract_tscan_assets(path: Path) -> list[tuple[str, str]]:
    if not path.is_file():
        return []
    result: list[tuple[str, str]] = []
    try:
        connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True, timeout=1)
    except sqlite3.Error:
        return []
    try:
        tables = {
            str(row[0])
            for row in connection.execute("select name from sqlite_master where type='table'")
        }
        for table in tables - {"project", "sqlite_sequence", "proxy", "info"}:
            columns = [str(row[1]) for row in connection.execute(f'pragma table_info("{table}")')]
            lowered = {name.lower(): name for name in columns}
            useful = {
                key: lowered[key]
                for key in (
                    "url",
                    "target",
                    "host",
                    "ip",
                    "ips",
                    "domain",
                    "subdomain",
                    "port",
                    "ports",
                    "protocol",
                )
                if key in lowered
            }
            if not useful:
                continue
            selected = list(dict.fromkeys(useful.values()))
            try:
                selected_sql = ", ".join(f'"{name}"' for name in selected)
                rows = connection.execute(
                    f'SELECT {selected_sql} FROM "{table}"'
                )
                for row in rows:
                    values = {name.lower(): row[index] for index, name in enumerate(selected)}
                    for key in ("url", "target"):
                        for item in _split_values(values.get(key)):
                            if item.lower().startswith(("http://", "https://")):
                                normalized = normalize_asset(item)
                                if normalized is not None:
                                    result.append(normalized)
                    hosts: list[str] = []
                    for key in ("host", "ip", "ips", "domain", "subdomain"):
                        hosts.extend(_split_values(values.get(key)))
                    ports = _split_values(values.get("port")) + _split_values(values.get("ports"))
                    protocol = str(values.get("protocol") or "").strip().lower()
                    for host_value in hosts:
                        normalized_host = normalize_asset(host_value)
                        if normalized_host is None:
                            continue
                        result.append(normalized_host)
                        for port in ports:
                            endpoint = normalize_asset(f"{_host(host_value)}:{port}", "endpoint")
                            if endpoint is not None:
                                result.append(endpoint)
                            if protocol in {"http", "https"}:
                                url = normalize_asset(f"{protocol}://{_host(host_value)}:{port}/")
                                if url is not None:
                                    result.append(url)
            except sqlite3.Error:
                continue
    finally:
        connection.close()
    return list(dict.fromkeys(result))


class AssetBus:
    def __init__(self, path: Path, scope: str) -> None:
        self.path = path
        self.scope = scope
        self.value = read_json(path)
        if not self.value:
            self.value = {
                "schema_version": 1,
                "generation": 0,
                "created_at": now_text(),
                "updated_at": now_text(),
                "assets": [],
            }

    @property
    def generation(self) -> int:
        return int(self.value.get("generation") or 0)

    def ingest(self, assets: Iterable[tuple[str, str]], source: str) -> int:
        records = self.value.get("assets")
        if not isinstance(records, list):
            records = []
            self.value["assets"] = records
        by_key = {
            (str(item.get("type")), str(item.get("value"))): item
            for item in records
            if isinstance(item, dict)
        }
        accepted: list[tuple[str, str]] = []
        rejected: list[tuple[str, str]] = []
        for raw_value, raw_type in assets:
            normalized = normalize_asset(raw_value, raw_type)
            if normalized is None:
                continue
            (accepted if asset_allowed(normalized[0], self.scope) else rejected).append(normalized)
        new_keys = [
            item
            for item in dict.fromkeys(accepted)
            if (item[1], item[0]) not in by_key
        ]
        next_generation = self.generation + 1 if new_keys else self.generation
        timestamp = now_text()
        for value, kind in dict.fromkeys(accepted):
            key = (kind, value)
            record = by_key.get(key)
            if record is None:
                record = {
                    "value": value,
                    "type": kind,
                    "first_seen_at": timestamp,
                    "last_seen_at": timestamp,
                    "first_generation": next_generation,
                    "sources": [source],
                    "scope_status": "allowed",
                }
                records.append(record)
                by_key[key] = record
            else:
                record["last_seen_at"] = timestamp
                sources = record.get("sources")
                if not isinstance(sources, list):
                    sources = []
                    record["sources"] = sources
                if source not in sources:
                    sources.append(source)
        if rejected:
            rejected_log = self.value.get("rejected")
            if not isinstance(rejected_log, list):
                rejected_log = []
                self.value["rejected"] = rejected_log
            for value, kind in dict.fromkeys(rejected):
                rejected_log.append(
                    {
                        "value": value,
                        "type": kind,
                        "source": source,
                        "seen_at": timestamp,
                        "scope_status": "rejected",
                    }
                )
        if new_keys:
            self.value["generation"] = next_generation
            self.value["last_new_asset_at"] = timestamp
        self.value["updated_at"] = timestamp
        atomic_json_write(self.path, self.value)
        return len(new_keys)

    def bundle(self, after_generation: int = 0) -> dict[str, list[str]]:
        result = {"ips": [], "domains": [], "endpoints": [], "urls": []}
        mapping = {"ip": "ips", "domain": "domains", "endpoint": "endpoints", "url": "urls"}
        for item in self.value.get("assets", []):
            if not isinstance(item, dict):
                continue
            if int(item.get("first_generation") or 0) <= after_generation:
                continue
            key = mapping.get(str(item.get("type")))
            value = str(item.get("value") or "")
            if key and value:
                result[key].append(value)
        return {key: list(dict.fromkeys(values)) for key, values in result.items()}
