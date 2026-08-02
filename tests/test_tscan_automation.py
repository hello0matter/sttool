from __future__ import annotations

import json
import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sttool.tscan_automation import (
    classify_connection_feedback,
    filter_assets_by_scope,
    normalize_poc_urls,
    password_targets,
    prepare_tscan_workspace,
    read_asset_bundle,
    read_asset_bus_bundle,
    scope_allows_all,
    stage_status_from_result,
    target_asset_bundle,
    web_fingerprint_targets,
    workflow_assets_ready,
    workflow_completed,
)


class TscanAutomationTests(unittest.TestCase):

    def test_asset_bus_and_web_fingerprint_targets_keep_fscan_ports(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "assets.json"
            path.write_text(
                json.dumps(
                    {
                        "generation": 3,
                        "assets": [
                            {
                                "value": "http://10.17.200.115:9001/",
                                "type": "url",
                                "first_generation": 2,
                            },
                            {
                                "value": "10.17.200.115",
                                "type": "ip",
                                "first_generation": 1,
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            generation, bundle = read_asset_bus_bundle(path, after_generation=1)
            self.assertEqual(generation, 3)
            self.assertEqual(bundle["urls"], ["http://10.17.200.115:9001/"])
            self.assertEqual(bundle["ips"], [])
            self.assertEqual(
                web_fingerprint_targets(
                    [
                        "http://10.17.200.115:9001/",
                        "https://app.example.com:443/login",
                    ],
                    [],
                    "",
                ),
                ["10.17.200.115:9001", "app.example.com"],
            )


    def test_tscan_workspace_is_isolated_and_clears_historical_targets(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            (source / "config" / "Pocs").mkdir(parents=True)
            (source / "Awvs").mkdir()
            (source / "Awvs" / "historical-report.html").write_text(
                "old report", encoding="utf-8"
            )
            (source / "ToolKit" / "Fscan").mkdir(parents=True)
            (source / "ToolKit" / "Fscan" / "fscan.exe").write_bytes(b"tool")
            source_result = source / "ToolKit" / "Fscan" / "result.txt"
            source_result.write_text("old result", encoding="utf-8")
            exe = source / "TscanPlus_Win_Amd64.exe"
            exe.write_bytes(b"fake")
            (source / "config" / "Pocs" / "demo.yaml").write_text(
                "name: demo", encoding="utf-8"
            )
            database = source / "config" / "config.db"
            connection = sqlite3.connect(database)
            connection.execute(
                "create table project (Project text, SubDomainTarget text, Status text, AssertNum integer)"
            )
            connection.execute(
                "insert into project values ('Default', 'boengg.top', '???', 9)"
            )
            connection.execute("create table subdomain (SubDomain text)")
            connection.execute("insert into subdomain values ('old.example.com')")
            connection.commit()
            connection.close()
            state_path = root / "run" / "tool_data" / "tscan" / "state.json"

            runtime_exe = prepare_tscan_workspace(exe, state_path)

            self.assertTrue(runtime_exe.is_file())
            self.assertNotEqual(runtime_exe, exe)
            runtime_database = runtime_exe.parent / "config" / "config.db"
            connection = sqlite3.connect(runtime_database)
            project = connection.execute(
                "select SubDomainTarget, Status, AssertNum from project"
            ).fetchone()
            rows = connection.execute("select count(*) from subdomain").fetchone()[0]
            connection.close()
            self.assertEqual(project, ("", "", 0))
            self.assertEqual(rows, 0)
            source_connection = sqlite3.connect(database)
            source_project = source_connection.execute(
                "select SubDomainTarget, Status, AssertNum from project"
            ).fetchone()
            source_connection.close()
            self.assertEqual(source_project, ("boengg.top", "???", 9))
            self.assertEqual(list((runtime_exe.parent / "Awvs").iterdir()), [])
            runtime_result = runtime_exe.parent / "ToolKit" / "Fscan" / "result.txt"
            self.assertEqual(runtime_result.read_text(encoding="utf-8"), "")
            runtime_result.write_text("run only", encoding="utf-8")
            self.assertEqual(source_result.read_text(encoding="utf-8"), "old result")

    def test_scope_star_accepts_only_the_supplied_or_discovered_assets(self) -> None:
        bundle = {
            "ips": ["192.0.2.10", "198.51.100.7"],
            "domains": ["app.example.com", "outside.test"],
            "urls": ["https://app.example.com/login", "https://outside.test"],
        }

        self.assertTrue(scope_allows_all("*"))
        self.assertEqual(filter_assets_by_scope(bundle, "*"), bundle)

    def test_explicit_domain_and_network_scope_filters_assets(self) -> None:
        bundle = {
            "ips": ["192.0.2.10", "198.51.100.7"],
            "domains": ["app.example.com", "outside.test"],
            "urls": ["https://app.example.com/login", "https://outside.test"],
        }

        self.assertEqual(
            filter_assets_by_scope(bundle, "example.com,192.0.2.0/24"),
            {
                "ips": ["192.0.2.10"],
                "domains": ["app.example.com"],
                "urls": ["https://app.example.com/login"],
            },
        )

    def test_asset_export_merges_the_primary_target_without_duplicates(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "assets.json"
            path.write_text(
                json.dumps(
                    {
                        "ips": ["192.0.2.10"],
                        "domains": ["app.example.com", "api.example.com"],
                        "urls": [],
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                read_asset_bundle(path, "https://app.example.com/login"),
                {
                    "ips": ["192.0.2.10"],
                    "domains": ["app.example.com", "api.example.com"],
                    "urls": ["https://app.example.com/login"],
                },
            )

    def test_poc_and_password_targets_are_normalized(self) -> None:
        self.assertEqual(
            normalize_poc_urls(
                ["https://app.example.com/login"],
                ["app.example.com"],
                "https://app.example.com/login",
            ),
            [
                "https://app.example.com/login",
                "https://app.example.com",
                "http://app.example.com",
            ],
        )
        self.assertEqual(
            password_targets(["192.0.2.10", "bad", "192.0.2.10"]),
            ["192.0.2.10"],
        )

    def test_workflow_helpers_handle_target_and_completion(self) -> None:
        self.assertEqual(
            target_asset_bundle("http://192.0.2.10:8080/path"),
            {
                "ips": ["192.0.2.10"],
                "domains": [],
                "urls": ["http://192.0.2.10:8080/path"],
            },
        )
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "workflow.json"
            path.write_text('{"status":"completed"}', encoding="utf-8")
            self.assertTrue(workflow_completed(path))
            self.assertTrue(workflow_assets_ready(path))
            path.write_text(
                json.dumps(
                    {
                        "status": "running",
                        "current_step": "collision",
                        "asset_handoff": {
                            "status": "ready",
                            "phase": "pre_collision",
                        },
                    }
                ),
                encoding="utf-8",
            )
            self.assertFalse(workflow_completed(path))
            self.assertTrue(workflow_assets_ready(path))

    def test_stage_status_distinguishes_submitted_waiting_and_skipped(self) -> None:
        self.assertEqual(
            stage_status_from_result({"scan_clicked": True}, True), "submitted"
        )
        self.assertEqual(
            stage_status_from_result(
                {"reason": "AWVS API 或 API Key 尚未配置"}, True
            ),
            "waiting_configuration",
        )
        self.assertEqual(
            stage_status_from_result({"reason": "没有可导入的 IP"}, True),
            "skipped",
        )
        self.assertEqual(stage_status_from_result({}, False), "prepared")

    def test_connection_feedback_requires_explicit_success(self) -> None:
        self.assertEqual(
            classify_connection_feedback("dial tcp: connection refused"),
            (False, "dial tcp: connection refused"),
        )
        self.assertEqual(
            classify_connection_feedback("连接成功"),
            (True, "连接成功"),
        )
        self.assertEqual(
            classify_connection_feedback("正在测试连接"),
            (None, "正在测试连接"),
        )

    def test_connection_failure_waits_for_configuration(self) -> None:
        self.assertEqual(
            stage_status_from_result(
                {"reason": "AWVS 连接测试未确认成功，不启动扫描"},
                True,
            ),
            "waiting_configuration",
        )


if __name__ == "__main__":
    unittest.main()
