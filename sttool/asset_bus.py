from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import tempfile
import time
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urlsplit, urlunsplit


ASSET_TYPES = ("ip", "domain", "endpoint", "url")
ASSET_BUS_SCHEMA_VERSION = 1
_FSCAN_URL_RE = re.compile(r"https?://[^\s\[\]<>]+", re.IGNORECASE)
_HOST_PORT_RE = re.compile(
    r"(?<![\w.-])(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9][A-Za-z0-9.-]*):(?P<port>\d{1,5})(?!\d)"
)
_DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_-])"
)
_NON_WEB_SERVICE_PORTS = {
    21,
    22,
    23,
    25,
    110,
    143,
    445,
    1080,
    1433,
    1521,
    3306,
    3389,
    5432,
    5900,
    6379,
    11211,
    27017,
}
_HTTP_EVIDENCE_RE = re.compile(
    r"(?:\[[^]\r\n]+\]\s*)?(?:HTTP/\d(?:\.\d)?\s+)?[1-5]\d{2}(?:\s|$)",
    re.IGNORECASE,
)
_DIRSEARCH_RESULT_RE = re.compile(
    r"^\s*(?P<status>\d{3})\s+"
    r"(?P<size>\d+(?:\.\d+)?(?:B|KB|MB|GB))\s+"
    r"(?P<url>https?://\S+)",
    re.IGNORECASE,
)
DIRSEARCH_REPEATED_SIGNATURE_LIMIT = 20


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
        for attempt, delay in enumerate((0.0, 0.01, 0.03, 0.1, 0.25)):
            if delay:
                time.sleep(delay)
            try:
                os.replace(temporary, path)
                break
            except PermissionError:
                if attempt == 4:
                    raise
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def read_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
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


def asset_allowed(value: str, scope: str, target: str = "") -> bool:
    normalized_scope = scope.strip()
    host = _host(value)
    if not host:
        return False
    if normalized_scope == "*":
        target_host = _host(target)
        if not target_host:
            return True
        try:
            target_address = ipaddress.ip_address(target_host)
        except ValueError:
            return host == target_host or host.endswith(f".{target_host}")
        try:
            return ipaddress.ip_address(host) == target_address
        except ValueError:
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
    for line in content.splitlines():
        for match in _FSCAN_URL_RE.finditer(line):
            normalized = normalize_asset(match.group(0))
            if normalized is None:
                continue
            parsed = urlsplit(normalized[0])
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            evidence = line[match.end() :]
            if port not in _NON_WEB_SERVICE_PORTS or _HTTP_EVIDENCE_RE.search(
                evidence
            ):
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


def parse_dirsearch_output(
    content: str,
    repeated_signature_limit: int = DIRSEARCH_REPEATED_SIGNATURE_LIMIT,
) -> list[tuple[str, str]]:
    """Return uncommon dirsearch hits while suppressing soft-200 response walls."""
    rows: list[tuple[tuple[str, str], str]] = []
    for line in content.splitlines():
        match = _DIRSEARCH_RESULT_RE.match(line)
        if match is None:
            continue
        signature = (match.group("status"), match.group("size").upper())
        rows.append((signature, match.group("url")))
    signature_counts = Counter(signature for signature, _url in rows)
    limit = max(int(repeated_signature_limit), 1)
    found: list[tuple[str, str]] = []
    for signature, url in rows:
        if signature_counts[signature] >= limit:
            continue
        normalized = normalize_asset(url, "url")
        if normalized is not None:
            found.append(normalized)
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
    def __init__(
        self,
        path: Path,
        scope: str,
        target: str = "",
        *,
        approval_mode: str = "automatic",
        approval_seconds: int = 10,
        allow_cidr_expansion: bool = True,
        processing_scope: str = "",
    ) -> None:
        self.path = path
        self.scope = scope
        self.target = target
        self.approval_mode = (
            approval_mode
            if approval_mode
            in {"automatic", "countdown_accept", "countdown_reject", "manual"}
            else "countdown_accept"
        )
        self.approval_seconds = max(3, min(3600, int(approval_seconds)))
        self.allow_cidr_expansion = bool(allow_cidr_expansion)
        self.processing_scope = str(processing_scope or "").strip()
        self.value = read_json(path)
        if not self.value:
            self.value = {
                "schema_version": ASSET_BUS_SCHEMA_VERSION,
                "generation": 0,
                "created_at": now_text(),
                "updated_at": now_text(),
                "assets": [],
                "pending": [],
                "rejected": [],
                "decision_history": [],
                "blocked_assets": [],
                "filtered_assets": [],
            }
        elif int(self.value.get("schema_version") or 0) == 2:
            # Version 2 only added optional records. Keep the wire version compatible
            # with existing tool bridges that already ignore unknown fields.
            self.value["schema_version"] = ASSET_BUS_SCHEMA_VERSION
            self.value.setdefault("blocked_assets", [])
            self.value.setdefault("decision_history", [])
            self.value.setdefault("filtered_assets", [])
            atomic_json_write(self.path, self.value)
        self.last_ingest_stats = {"added": 0, "pending": 0, "rejected": 0}
        self.last_resolution_stats = {"added": 0, "accepted": 0, "rejected": 0}

    @property
    def generation(self) -> int:
        return int(self.value.get("generation") or 0)

    @property
    def pending_count(self) -> int:
        pending = self.value.get("pending")
        return len([item for item in pending if isinstance(item, dict)]) if isinstance(pending, list) else 0

    def _reload(self) -> None:
        latest = read_json(self.path)
        if latest:
            self.value = latest

    def update_approval_policy(
        self,
        *,
        approval_mode: str,
        approval_seconds: int,
        allow_cidr_expansion: bool,
        processing_scope: str | None = None,
        reset_pending_deadlines: bool = True,
    ) -> bool:
        self._reload()
        normalized_mode = (
            approval_mode
            if approval_mode
            in {"automatic", "countdown_accept", "countdown_reject", "manual"}
            else "countdown_accept"
        )
        normalized_seconds = max(3, min(3600, int(approval_seconds)))
        normalized_cidr = bool(allow_cidr_expansion)
        normalized_processing_scope = (
            self.processing_scope
            if processing_scope is None
            else str(processing_scope or "").strip()
        )
        changed = (
            self.approval_mode != normalized_mode
            or self.approval_seconds != normalized_seconds
            or self.allow_cidr_expansion != normalized_cidr
            or self.processing_scope != normalized_processing_scope
        )
        self.approval_mode = normalized_mode
        self.approval_seconds = normalized_seconds
        self.allow_cidr_expansion = normalized_cidr
        self.processing_scope = normalized_processing_scope
        self._apply_processing_scope()
        if reset_pending_deadlines:
            deadline = (
                datetime.now().astimezone()
                + timedelta(seconds=self.approval_seconds)
            ).isoformat(timespec="seconds")
            for item in self._records(self.value, "pending"):
                item["default_action"] = (
                    "reject" if self.approval_mode == "countdown_reject" else "accept"
                )
                if self.approval_mode == "manual":
                    item.pop("decision_deadline_at", None)
                elif self.approval_mode == "automatic":
                    item["decision_deadline_at"] = now_text()
                else:
                    item["decision_deadline_at"] = deadline
        self.value["approval_policy"] = {
            "mode": self.approval_mode,
            "countdown_seconds": self.approval_seconds,
            "allow_cidr_expansion": self.allow_cidr_expansion,
            "wildcard_scope_semantics": "target_auto_expansion_requires_policy",
            "processing_scope": self.processing_scope,
        }
        self.value["updated_at"] = now_text()
        atomic_json_write(self.path, self.value)
        return changed

    def _processing_allowed(self, value: str) -> bool:
        if not self.processing_scope:
            return True
        normalized_target = {item for item, _kind in target_assets(self.target)}
        normalized = normalize_asset(value)
        if normalized is not None and normalized[0] in normalized_target:
            return True
        return asset_allowed(value, self.processing_scope, self.target)

    def _authorization_allowed(self, value: str) -> bool:
        normalized_target = {item for item, _kind in target_assets(self.target)}
        normalized = normalize_asset(value)
        if normalized is not None and normalized[0] in normalized_target:
            return True
        if self.scope.strip() == "*":
            return True
        return asset_allowed(value, self.scope, self.target)

    def update_scopes(self, *, scope: str, processing_scope: str) -> None:
        normalized_scope = str(scope or "").strip()
        if not normalized_scope:
            raise ValueError("授权范围不能为空")
        self._reload()
        self.scope = normalized_scope
        self.processing_scope = str(processing_scope or "").strip()
        self._apply_processing_scope()
        self.value["approval_policy"] = {
            **dict(self.value.get("approval_policy") or {}),
            "processing_scope": self.processing_scope,
        }
        self.value["updated_at"] = now_text()
        atomic_json_write(self.path, self.value)

    def _apply_processing_scope(self) -> None:
        timestamp = now_text()
        filtered = self._records(self.value, "filtered_assets")
        filtered_keys = {
            (str(item.get("type")), str(item.get("value"))) for item in filtered
        }
        for container in ("assets", "pending"):
            retained: list[dict[str, object]] = []
            for item in self._records(self.value, container):
                value = str(item.get("value") or "")
                authorization_allowed = self._authorization_allowed(value)
                processing_allowed = self._processing_allowed(value)
                if authorization_allowed and processing_allowed:
                    retained.append(item)
                    continue
                reason = (
                    "outside_authorization_scope"
                    if not authorization_allowed
                    else "outside_processing_scope"
                )
                key = (str(item.get("type") or ""), value)
                if key not in filtered_keys:
                    filtered.append(
                        {
                            **item,
                            "filtered_at": timestamp,
                            "scope_status": reason,
                            "reason": reason,
                        }
                    )
                    filtered_keys.add(key)
            self.value[container] = retained
        self.value["filtered_assets"] = filtered[-5000:]

    @staticmethod
    def _records(value: dict[str, object], key: str) -> list[dict[str, object]]:
        records = value.get(key)
        if not isinstance(records, list):
            records = []
            value[key] = records
        return [item for item in records if isinstance(item, dict)]

    def _same_target_cidr(self, value: str) -> bool:
        target_host = _host(self.target)
        candidate_host = _host(value)
        try:
            target_address = ipaddress.ip_address(target_host)
            candidate_address = ipaddress.ip_address(candidate_host)
        except ValueError:
            return False
        if target_address.version != 4 or candidate_address.version != 4:
            return False
        if target_address == candidate_address:
            return False
        return candidate_address in ipaddress.ip_network(
            f"{target_address}/24", strict=False
        )

    def _pending_record(
        self,
        value: str,
        kind: str,
        source: str,
        reason: str,
        timestamp: str,
    ) -> dict[str, object]:
        identity = hashlib.sha256(
            f"{kind}\0{value}".encode("utf-8")
        ).hexdigest()[:20]
        host = _host(value) or value
        record: dict[str, object] = {
            "id": identity,
            "group_key": host,
            "value": value,
            "type": kind,
            "source": source,
            "sources": [source],
            "discovered_at": timestamp,
            "last_seen_at": timestamp,
            "reason": reason,
            "scope_status": "pending_confirmation",
            "decision": "pending",
            "default_action": (
                "reject" if self.approval_mode == "countdown_reject" else "accept"
            ),
        }
        if self.approval_mode != "manual":
            deadline = datetime.now().astimezone() + timedelta(
                seconds=self.approval_seconds
            )
            record["decision_deadline_at"] = deadline.isoformat(timespec="seconds")
        return record

    @staticmethod
    def _update_sources(record: dict[str, object], source: str, timestamp: str) -> None:
        record["last_seen_at"] = timestamp
        sources = record.get("sources")
        if not isinstance(sources, list):
            sources = []
            record["sources"] = sources
        if source not in sources:
            sources.append(source)

    def ingest(self, assets: Iterable[tuple[str, str]], source: str) -> int:
        self._reload()
        records = self._records(self.value, "assets")
        self.value["assets"] = records
        pending = self._records(self.value, "pending")
        self.value["pending"] = pending
        rejected_log = self._records(self.value, "rejected")
        self.value["rejected"] = rejected_log
        by_key = {
            (str(item.get("type")), str(item.get("value"))): item
            for item in records
        }
        pending_by_key = {
            (str(item.get("type")), str(item.get("value"))): item
            for item in pending
        }
        rejected_by_key = {
            (str(item.get("type")), str(item.get("value")), str(item.get("source"))): item
            for item in rejected_log
        }
        blocked_keys = {
            (str(item.get("type")), str(item.get("value")))
            for item in self._records(self.value, "blocked_assets")
        }
        known_hosts = {
            _host(str(item.get("value") or "")) for item in records
        }
        known_hosts.discard("")
        accepted: list[tuple[str, str]] = []
        accepted_reasons: dict[tuple[str, str], str] = {}
        queued = 0
        rejected = 0
        timestamp = now_text()
        for raw_value, raw_type in dict.fromkeys(assets):
            normalized = normalize_asset(raw_value, raw_type)
            if normalized is None:
                continue
            value, kind = normalized
            key = (kind, value)
            if key in blocked_keys:
                rejected_key = (kind, value, source)
                if rejected_key not in rejected_by_key:
                    record = {
                        "value": value,
                        "type": kind,
                        "source": source,
                        "seen_at": timestamp,
                        "scope_status": "blocked_by_user",
                        "reason": "user_blocked_asset",
                    }
                    rejected_log.append(record)
                    rejected_by_key[rejected_key] = record
                    rejected += 1
                continue
            if source != "project_target" and not self._processing_allowed(value):
                filtered = self._records(self.value, "filtered_assets")
                if not any(
                    (str(item.get("type")), str(item.get("value"))) == key
                    for item in filtered
                ):
                    filtered.append(
                        {
                            "value": value,
                            "type": kind,
                            "source": source,
                            "seen_at": timestamp,
                            "scope_status": "outside_processing_scope",
                            "reason": "outside_processing_scope",
                        }
                    )
                    self.value["filtered_assets"] = filtered[-5000:]
                    rejected += 1
                continue
            existing = by_key.get(key)
            if existing is not None:
                self._update_sources(existing, source, timestamp)
                continue
            host = _host(value)
            same_known_host = bool(host and host in known_hosts)
            in_scope = asset_allowed(value, self.scope, self.target)
            same_cidr = self._same_target_cidr(value)
            decision = "accept"
            reason = "authorized_new_host"
            if source == "project_target" or same_known_host:
                decision = "accept"
                reason = "project_target" if source == "project_target" else "known_host_detail"
            elif same_cidr and not self.allow_cidr_expansion:
                decision = "reject"
                reason = "cidr_expansion_disabled"
            elif not in_scope and self.scope.strip() != "*":
                decision = "reject"
                reason = "outside_explicit_scope"
            elif self.approval_mode == "automatic":
                decision = "accept"
                reason = "automatic_policy"
            else:
                decision = "pending"
                reason = "same_cidr" if same_cidr else "new_host"

            if decision == "accept":
                accepted.append(normalized)
                accepted_reasons[key] = reason
                if host:
                    known_hosts.add(host)
                continue
            if decision == "pending":
                pending_key = (kind, value)
                record = pending_by_key.get(pending_key)
                if record is None:
                    record = self._pending_record(
                        value, kind, source, reason, timestamp
                    )
                    pending.append(record)
                    pending_by_key[pending_key] = record
                    queued += 1
                else:
                    self._update_sources(record, source, timestamp)
                continue
            rejected_key = (kind, value, source)
            record = rejected_by_key.get(rejected_key)
            if record is None:
                record = {
                    "value": value,
                    "type": kind,
                    "source": source,
                    "seen_at": timestamp,
                    "scope_status": "rejected",
                    "reason": reason,
                }
                rejected_log.append(record)
                rejected_by_key[rejected_key] = record
                rejected += 1
            else:
                record["seen_at"] = timestamp
                record["reason"] = reason

        new_keys = [
            item
            for item in dict.fromkeys(accepted)
            if (item[1], item[0]) not in by_key
        ]
        next_generation = self.generation + 1 if new_keys else self.generation
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
                    "reason": accepted_reasons.get(key, "allowed"),
                }
                records.append(record)
                by_key[key] = record
            else:
                self._update_sources(record, source, timestamp)
        if new_keys:
            self.value["generation"] = next_generation
            self.value["last_new_asset_at"] = timestamp
        self.value["schema_version"] = ASSET_BUS_SCHEMA_VERSION
        self.value["updated_at"] = timestamp
        self.value["approval_policy"] = {
            "mode": self.approval_mode,
            "countdown_seconds": self.approval_seconds,
            "allow_cidr_expansion": self.allow_cidr_expansion,
            "wildcard_scope_semantics": "target_auto_expansion_requires_policy",
            "processing_scope": self.processing_scope,
        }
        atomic_json_write(self.path, self.value)
        self.last_ingest_stats = {
            "added": len(new_keys),
            "pending": queued,
            "rejected": rejected,
        }
        return len(new_keys)

    def add_manual_asset(self, raw_value: str, asset_type: str = "") -> tuple[str, str]:
        normalized = normalize_asset(raw_value, asset_type)
        if normalized is None:
            raise ValueError("资产格式无效，请填写 URL、域名、IP 或 IP:端口")
        value, kind = normalized
        if self.scope.strip() != "*" and not asset_allowed(value, self.scope, self.target):
            raise ValueError("该资产不在当前明确授权范围内")
        if not self._processing_allowed(value):
            raise ValueError("该资产不在当前自动处理范围内")
        self._reload()
        records = self._records(self.value, "assets")
        key = (kind, value)
        if any(
            (str(item.get("type")), str(item.get("value"))) == key
            for item in records
        ):
            return normalized
        self.value["blocked_assets"] = [
            item
            for item in self._records(self.value, "blocked_assets")
            if (str(item.get("type")), str(item.get("value"))) != key
        ]
        self.value["pending"] = [
            item
            for item in self._records(self.value, "pending")
            if (str(item.get("type")), str(item.get("value"))) != key
        ]
        timestamp = now_text()
        generation = self.generation + 1
        records.append(
            {
                "value": value,
                "type": kind,
                "first_seen_at": timestamp,
                "last_seen_at": timestamp,
                "first_generation": generation,
                "sources": ["user_manual"],
                "scope_status": "allowed_by_user",
            }
        )
        history = self._records(self.value, "decision_history")
        history.append(
            {
                "value": value,
                "type": kind,
                "action": "manual_add",
                "decision_source": "project_access_manager",
                "decided_at": timestamp,
            }
        )
        self.value.update(
            assets=records,
            generation=generation,
            last_new_asset_at=timestamp,
            updated_at=timestamp,
            decision_history=history[-1000:],
        )
        atomic_json_write(self.path, self.value)
        return normalized

    def exclude_asset(self, raw_value: str, asset_type: str = "") -> bool:
        normalized = normalize_asset(raw_value, asset_type)
        if normalized is None:
            raise ValueError("资产格式无效")
        value, kind = normalized
        target_keys = set(target_assets(self.target))
        if normalized in target_keys:
            raise ValueError("主要目标不能从项目中排除；请新建或删除工程")
        self._reload()
        key = (kind, value)
        records = self._records(self.value, "assets")
        pending = self._records(self.value, "pending")
        removed = any(
            (str(item.get("type")), str(item.get("value"))) == key
            for item in [*records, *pending]
        )
        self.value["assets"] = [
            item
            for item in records
            if (str(item.get("type")), str(item.get("value"))) != key
        ]
        self.value["pending"] = [
            item
            for item in pending
            if (str(item.get("type")), str(item.get("value"))) != key
        ]
        blocked = self._records(self.value, "blocked_assets")
        if not any(
            (str(item.get("type")), str(item.get("value"))) == key
            for item in blocked
        ):
            blocked.append(
                {
                    "value": value,
                    "type": kind,
                    "blocked_at": now_text(),
                    "reason": "user_blocked_asset",
                }
            )
        history = self._records(self.value, "decision_history")
        history.append(
            {
                "value": value,
                "type": kind,
                "action": "exclude",
                "decision_source": "project_access_manager",
                "decided_at": now_text(),
            }
        )
        self.value["blocked_assets"] = blocked[-2000:]
        self.value["decision_history"] = history[-1000:]
        self.value["updated_at"] = now_text()
        atomic_json_write(self.path, self.value)
        return removed

    def restore_asset(self, raw_value: str, asset_type: str = "") -> tuple[str, str]:
        normalized = normalize_asset(raw_value, asset_type)
        if normalized is None:
            raise ValueError("资产格式无效")
        self._reload()
        key = (normalized[1], normalized[0])
        self.value["blocked_assets"] = [
            item
            for item in self._records(self.value, "blocked_assets")
            if (str(item.get("type")), str(item.get("value"))) != key
        ]
        atomic_json_write(self.path, self.value)
        return self.add_manual_asset(*normalized)

    def replace_manual_asset(
        self,
        old_value: str,
        old_type: str,
        new_value: str,
    ) -> tuple[str, str]:
        normalized = normalize_asset(new_value)
        if normalized is None:
            raise ValueError("修改后的资产格式无效")
        if self.scope.strip() != "*" and not asset_allowed(
            normalized[0], self.scope, self.target
        ):
            raise ValueError("修改后的资产不在当前明确授权范围内")
        self.exclude_asset(old_value, old_type)
        return self.add_manual_asset(*normalized)

    def apply_decisions(self, decisions: Iterable[dict[str, object]]) -> int:
        self.last_resolution_stats = {"added": 0, "accepted": 0, "rejected": 0}
        self._reload()
        pending = self._records(self.value, "pending")
        decision_by_id: dict[str, dict[str, object]] = {}
        for item in decisions:
            identity = str(item.get("id") or "")
            action = str(item.get("action") or "").lower()
            if identity and action in {"accept", "reject"}:
                decision_by_id[identity] = item
        pending_ids = {str(item.get("id") or "") for item in pending}
        decision_by_id = {
            identity: item
            for identity, item in decision_by_id.items()
            if identity in pending_ids
        }
        if not decision_by_id:
            return 0
        return self._resolve_pending(
            pending,
            lambda item: decision_by_id.get(str(item.get("id") or "")),
            resolution_source="user",
        )

    def resolve_due_pending(self, grace_seconds: int = 0) -> int:
        self.last_resolution_stats = {"added": 0, "accepted": 0, "rejected": 0}
        self._reload()
        pending = self._records(self.value, "pending")
        now = datetime.now().astimezone()
        due_by_id: dict[str, dict[str, object]] = {}
        for item in pending:
            deadline_text = str(item.get("decision_deadline_at") or "")
            if not deadline_text:
                continue
            try:
                deadline = datetime.fromisoformat(deadline_text)
            except ValueError:
                continue
            if deadline.tzinfo is None:
                deadline = deadline.astimezone()
            if deadline + timedelta(seconds=max(grace_seconds, 0)) > now:
                continue
            identity = str(item.get("id") or "")
            if identity:
                due_by_id[identity] = {
                    "id": identity,
                    "action": item.get("default_action") or "accept",
                    "decided_at": now_text(),
                }
        if not due_by_id:
            return 0
        return self._resolve_pending(
            pending,
            lambda item: due_by_id.get(str(item.get("id") or "")),
            resolution_source="countdown",
        )

    def _resolve_pending(
        self,
        pending: list[dict[str, object]],
        resolver: Callable[[dict[str, object]], dict[str, object] | None],
        *,
        resolution_source: str,
    ) -> int:
        records = self._records(self.value, "assets")
        rejected_log = self._records(self.value, "rejected")
        history = self._records(self.value, "decision_history")
        by_key = {
            (str(item.get("type")), str(item.get("value"))): item
            for item in records
        }
        retained: list[dict[str, object]] = []
        accepted_rows: list[dict[str, object]] = []
        rejected_count = 0
        timestamp = now_text()
        for item in pending:
            decision = resolver(item)
            if not isinstance(decision, dict):
                retained.append(item)
                continue
            action = str(decision.get("action") or "").lower()
            if action not in {"accept", "reject"}:
                retained.append(item)
                continue
            history.append(
                {
                    "id": item.get("id"),
                    "group_key": item.get("group_key"),
                    "value": item.get("value"),
                    "type": item.get("type"),
                    "source": item.get("source"),
                    "action": action,
                    "decision_source": resolution_source,
                    "decided_at": decision.get("decided_at") or timestamp,
                    "reason": item.get("reason"),
                }
            )
            if action == "accept":
                accepted_rows.append(item)
            else:
                rejected_log.append(
                    {
                        "value": item.get("value"),
                        "type": item.get("type"),
                        "source": item.get("source"),
                        "seen_at": timestamp,
                        "scope_status": "rejected_by_decision",
                        "reason": "user_or_policy_rejected",
                    }
                )
                rejected_count += 1
        new_rows = [
            item
            for item in accepted_rows
            if (str(item.get("type")), str(item.get("value"))) not in by_key
        ]
        next_generation = self.generation + 1 if new_rows else self.generation
        for item in accepted_rows:
            key = (str(item.get("type")), str(item.get("value")))
            record = by_key.get(key)
            source = str(item.get("source") or "asset_approval")
            if record is None:
                record = {
                    "value": item.get("value"),
                    "type": item.get("type"),
                    "first_seen_at": item.get("discovered_at") or timestamp,
                    "last_seen_at": timestamp,
                    "first_generation": next_generation,
                    "sources": list(item.get("sources") or [source]),
                    "scope_status": "allowed_by_decision",
                }
                records.append(record)
                by_key[key] = record
            else:
                self._update_sources(record, source, timestamp)
        self.value["pending"] = retained
        self.value["assets"] = records
        self.value["rejected"] = rejected_log[-2000:]
        self.value["decision_history"] = history[-1000:]
        if new_rows:
            self.value["generation"] = next_generation
            self.value["last_new_asset_at"] = timestamp
        self.value["updated_at"] = timestamp
        atomic_json_write(self.path, self.value)
        self.last_resolution_stats = {
            "added": len(new_rows),
            "accepted": len(accepted_rows),
            "rejected": rejected_count,
        }
        return len(new_rows)

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
