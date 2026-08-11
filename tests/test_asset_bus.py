from __future__ import annotations

import json
import os
import sqlite3
import unittest
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from sttool.asset_bus import (
    AssetBus,
    atomic_json_write,
    extract_tscan_assets,
    normalize_asset,
    parse_asset_export,
    parse_dirsearch_output,
    parse_fscan_output,
    read_json,
)


class AssetBusTests(unittest.TestCase):
    def test_asset_manager_excludes_reingest_and_can_restore_asset(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "assets.json"
            bus = AssetBus(path, "*", "example.com", approval_mode="automatic")
            bus.ingest([("example.com", "domain")], "project_target")
            bus.add_manual_asset("api.example.net")

            removed = bus.exclude_asset("api.example.net", "domain")
            readded = bus.ingest([("api.example.net", "domain")], "tscan")

            self.assertTrue(removed)
            self.assertEqual(readded, 0)
            self.assertNotIn("api.example.net", bus.bundle()["domains"])
            self.assertEqual(
                read_json(path)["blocked_assets"][0]["value"], "api.example.net"
            )

            restored = bus.restore_asset("api.example.net", "domain")

            self.assertEqual(restored, ("api.example.net", "domain"))
            self.assertIn("api.example.net", bus.bundle()["domains"])
            self.assertEqual(read_json(path)["blocked_assets"], [])

    def test_asset_manager_rejects_primary_target_exclusion(self) -> None:
        with TemporaryDirectory() as temporary:
            bus = AssetBus(Path(temporary) / "assets.json", "*", "example.com")
            bus.ingest([("example.com", "domain")], "project_target")

            with self.assertRaisesRegex(ValueError, "主要目标"):
                bus.exclude_asset("example.com", "domain")

    def test_hot_policy_update_resets_existing_pending_countdown(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "assets.json"
            bus = AssetBus(
                path,
                "*",
                "example.com",
                approval_mode="countdown_accept",
                approval_seconds=5,
            )
            bus.ingest([("example.com", "domain")], "project_target")
            bus.ingest([("new.example.net", "domain")], "asset_commander")

            bus.update_approval_policy(
                approval_mode="countdown_reject",
                approval_seconds=20,
                allow_cidr_expansion=False,
            )

            pending = read_json(path)["pending"][0]
            remaining = (
                datetime.fromisoformat(pending["decision_deadline_at"])
                - datetime.now().astimezone()
            ).total_seconds()
            self.assertGreaterEqual(remaining, 18)
            self.assertLessEqual(remaining, 20)
            self.assertEqual(pending["default_action"], "reject")
            self.assertEqual(bus.approval_seconds, 20)
            self.assertFalse(bus.allow_cidr_expansion)

    def test_dirsearch_parser_suppresses_repeated_soft_200_wall(self) -> None:
        repeated = "\n".join(
            f"200    32KB  https://app.example.test/fake-{index}"
            for index in range(20)
        )
        content = (
            repeated
            + "\n401   143B   https://app.example.test/models"
            + "\n401   143B   https://app.example.test/responses"
            + "\n200    15B   https://app.example.test/health"
        )

        self.assertEqual(
            parse_dirsearch_output(content),
            [
                ("https://app.example.test/models", "url"),
                ("https://app.example.test/responses", "url"),
                ("https://app.example.test/health", "url"),
            ],
        )

    def test_read_json_accepts_utf8_bom_status_files(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "batch_status.json"
            path.write_text('{"status":"completed"}', encoding="utf-8-sig")

            self.assertEqual(read_json(path), {"status": "completed"})

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

    def test_fscan_parser_does_not_promote_non_web_services_to_urls(self) -> None:
        content = """http://192.0.2.10:6379
http://192.0.2.11:25
http://192.0.2.12:1080
"""

        assets = parse_fscan_output(content)

        self.assertNotIn(("http://192.0.2.10:6379/", "url"), assets)
        self.assertNotIn(("http://192.0.2.11:25/", "url"), assets)
        self.assertNotIn(("http://192.0.2.12:1080/", "url"), assets)
        self.assertIn(("192.0.2.10:6379", "endpoint"), assets)
        self.assertIn(("192.0.2.11:25", "endpoint"), assets)
        self.assertIn(("192.0.2.12:1080", "endpoint"), assets)

    def test_fscan_parser_keeps_nonstandard_web_port_with_http_evidence(self) -> None:
        assets = parse_fscan_output(
            "http://192.0.2.20:8005 [403 Forbidden] 403 kngx/1.10.2\n"
            "http://192.0.2.21:6379 [200 OK] 200 nginx\n"
        )

        self.assertIn(("http://192.0.2.20:8005/", "url"), assets)
        self.assertIn(("http://192.0.2.21:6379/", "url"), assets)

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

    def test_rejected_assets_are_deduplicated_by_value_type_and_source(self) -> None:
        with TemporaryDirectory() as temporary:
            bus = AssetBus(Path(temporary) / "assets.json", "example.com")

            bus.ingest([('outside.test', 'domain')], "tscan")
            bus.ingest([('outside.test', 'domain')], "tscan")
            bus.ingest([('outside.test', 'domain')], "asset_commander")

            self.assertEqual(len(bus.value["rejected"]), 2)
            self.assertEqual(
                {item["source"] for item in bus.value["rejected"]},
                {"tscan", "asset_commander"},
            )

    def test_stale_bus_reloads_disk_before_writing(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "assets.json"
            first = AssetBus(path, "example.com")
            first.ingest([("outside.test", "domain")], "tscan")
            stale = AssetBus(path, "example.com")

            value = json.loads(path.read_text(encoding="utf-8"))
            value["rejected"] = []
            atomic_json_write(path, value)

            stale.ingest([("app.example.com", "domain")], "semantic_dirscan")

            current = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(current["rejected"], [])
            self.assertEqual(
                [item["value"] for item in current["assets"]],
                ["app.example.com"],
            )

    def test_wildcard_scope_queues_new_host_instead_of_auto_authorizing_it(self) -> None:
        with TemporaryDirectory() as temporary:
            bus = AssetBus(
                Path(temporary) / "assets.json",
                "*",
                "https://app.example.com/",
                approval_mode="countdown_accept",
                allow_cidr_expansion=False,
            )
            bus.ingest([("https://app.example.com/", "url")], "project_target")

            added = bus.ingest(
                [("api.other.test", "domain")], "asset_commander"
            )

            self.assertEqual(added, 0)
            self.assertEqual(bus.bundle()["urls"], ["https://app.example.com/"])
            self.assertEqual(bus.pending_count, 1)
            self.assertEqual(bus.value["pending"][0]["reason"], "new_host")

    def test_cidr_expansion_switch_blocks_same_c_segment_by_default(self) -> None:
        with TemporaryDirectory() as temporary:
            bus = AssetBus(
                Path(temporary) / "assets.json",
                "*",
                "10.17.200.115",
                approval_mode="countdown_accept",
                allow_cidr_expansion=False,
            )
            bus.ingest([("10.17.200.115", "ip")], "project_target")

            bus.ingest([("10.17.200.99", "ip")], "asset_commander")

            self.assertEqual(bus.pending_count, 0)
            self.assertEqual(bus.value["rejected"][0]["reason"], "cidr_expansion_disabled")

    def test_approved_cidr_candidate_promotes_entire_selected_host_group(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "assets.json"
            bus = AssetBus(
                path,
                "*",
                "10.17.200.115",
                approval_mode="countdown_accept",
                allow_cidr_expansion=True,
            )
            bus.ingest([("10.17.200.115", "ip")], "project_target")
            bus.ingest(
                [
                    ("10.17.200.99", "ip"),
                    ("10.17.200.99:8080", "endpoint"),
                    ("http://10.17.200.99:8080/", "url"),
                ],
                "asset_commander",
            )
            decisions = [
                {"id": item["id"], "action": "accept"}
                for item in bus.value["pending"]
            ]

            added = bus.apply_decisions(decisions)

            self.assertEqual(added, 3)
            self.assertEqual(bus.pending_count, 0)
            self.assertIn("10.17.200.99", bus.bundle()["ips"])
            self.assertIn("10.17.200.99:8080", bus.bundle()["endpoints"])
            self.assertIn("http://10.17.200.99:8080/", bus.bundle()["urls"])
            self.assertEqual(bus.generation, 2)

    def test_countdown_default_can_accept_or_reject_without_ui(self) -> None:
        for mode, expected_added, expected_rejected in (
            ("countdown_accept", 1, 0),
            ("countdown_reject", 0, 1),
        ):
            with self.subTest(mode=mode), TemporaryDirectory() as temporary:
                path = Path(temporary) / "assets.json"
                bus = AssetBus(
                    path,
                    "*",
                    "example.com",
                    approval_mode=mode,
                    approval_seconds=3,
                )
                bus.ingest([("example.com", "domain")], "project_target")
                bus.ingest([("new.example.net", "domain")], "asset_commander")
                value = read_json(path)
                value["pending"][0]["decision_deadline_at"] = "2000-01-01T00:00:00+00:00"
                atomic_json_write(path, value)

                added = bus.resolve_due_pending()

                self.assertEqual(added, expected_added)
                self.assertEqual(bus.pending_count, 0)
                self.assertEqual(bus.last_resolution_stats["rejected"], expected_rejected)

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
