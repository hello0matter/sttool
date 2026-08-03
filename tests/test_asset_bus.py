from __future__ import annotations

import json
import os
import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from sttool.asset_bus import (
    AssetBus,
    atomic_json_write,
    extract_tscan_assets,
    normalize_asset,
    parse_asset_export,
    parse_fscan_output,
)


class AssetBusTests(unittest.TestCase):
    def test_atomic_json_write_retries_transient_replace_lock(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "assets.json"
            original_replace = os.replace
            attempts = 0

            def flaky_replace(source: str, destination: str | Path) -> None:
                nonlocal attempts
                attempts += 1
                if attempts < 3:
                    raise PermissionError("temporarily locked")
                original_replace(source, destination)

            with (
                patch("sttool.asset_bus.os.replace", side_effect=flaky_replace),
                patch("sttool.asset_bus.time.sleep") as sleep,
            ):
                atomic_json_write(path, {"generation": 1})

            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8")),
                {"generation": 1},
            )
            self.assertEqual(attempts, 3)
            self.assertEqual(
                [call.args[0] for call in sleep.call_args_list],
                [0.01, 0.03],
            )

    def test_fscan_parser_keeps_all_web_urls_and_open_endpoints(self) -> None:
        content = """10.17.200.115:22
http://10.17.200.115:81 [gateway] 200 nginx
https://app.example.com:443/login 200
"""
        assets = parse_fscan_output(content)
        self.assertIn(("10.17.200.115:22", "endpoint"), assets)
        self.assertIn(("10.17.200.115", "ip"), assets)
        self.assertIn(("http://10.17.200.115:81/", "url"), assets)
        self.assertIn(("https://app.example.com/login", "url"), assets)

    def test_bus_deduplicates_and_tracks_generation_and_sources(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "assets.json"
            bus = AssetBus(path, "*")
            self.assertEqual(
                bus.ingest(
                    [
                        ("http://10.17.200.115:9001", "url"),
                        ("10.17.200.115", "ip"),
                    ],
                    "fscan",
                ),
                2,
            )
            self.assertEqual(bus.generation, 1)
            self.assertEqual(
                bus.ingest([("http://10.17.200.115:9001/", "url")], "tscan"),
                0,
            )
            self.assertEqual(bus.generation, 1)
            record = next(
                item
                for item in bus.value["assets"]
                if item["value"] == "http://10.17.200.115:9001/"
            )
            self.assertEqual(record["sources"], ["fscan", "tscan"])
            self.assertEqual(
                bus.bundle(),
                {
                    "ips": ["10.17.200.115"],
                    "domains": [],
                    "endpoints": [],
                    "urls": ["http://10.17.200.115:9001/"],
                },
            )

    def test_explicit_scope_rejects_unrelated_tscan_history(self) -> None:
        with TemporaryDirectory() as temporary:
            bus = AssetBus(Path(temporary) / "assets.json", "10.17.200.0/24")
            added = bus.ingest(
                [
                    ("10.17.200.115", "ip"),
                    ("boengg.top", "domain"),
                ],
                "tscan",
            )
            self.assertEqual(added, 1)
            self.assertEqual(bus.bundle()["domains"], [])
            self.assertEqual(bus.value["rejected"][0]["value"], "boengg.top")

    def test_asset_export_and_tscan_database_are_parsed(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            export = root / "export.json"
            export.write_text(
                json.dumps(
                    {
                        "ips": ["192.0.2.10"],
                        "domains": ["app.example.com"],
                        "urls": ["https://app.example.com:443/login"],
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                parse_asset_export(export),
                [
                    ("192.0.2.10", "ip"),
                    ("app.example.com", "domain"),
                    ("https://app.example.com/login", "url"),
                ],
            )

            database = root / "config.db"
            connection = sqlite3.connect(database)
            connection.execute(
                "create table subdomain (SubDomain text, Ips text, Ports text)"
            )
            connection.execute(
                "insert into subdomain values (?, ?, ?)",
                ("api.example.com", "192.0.2.20", "80,443"),
            )
            connection.execute(
                "create table urlscan (Url text, Host text, Port text, Protocol text)"
            )
            connection.execute(
                "insert into urlscan values (?, ?, ?, ?)",
                ("http://192.0.2.20:8080", "192.0.2.20", "8080", "http"),
            )
            connection.commit()
            connection.close()
            assets = extract_tscan_assets(database)
            self.assertIn(("api.example.com", "domain"), assets)
            self.assertIn(("192.0.2.20", "ip"), assets)
            self.assertIn(("192.0.2.20:80", "endpoint"), assets)
            self.assertIn(("http://192.0.2.20:8080/", "url"), assets)

    def test_normalize_url_removes_default_port_and_fragment(self) -> None:
        self.assertEqual(
            normalize_asset("HTTPS://Example.COM:443/a#section"),
            ("https://example.com/a", "url"),
        )


if __name__ == "__main__":
    unittest.main()
