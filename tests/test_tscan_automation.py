from __future__ import annotations

import json
import os
import sqlite3
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sttool.tscan_automation import (
    CDP_START_TIMEOUT_SECONDS,
    classify_connection_feedback,
    dismiss_blocking_modals,
    filter_assets_by_scope,
    modal_requires_retry,
    monitoring_state,
    normalize_poc_urls,
    password_targets,
    prepare_tscan_workspace,
    process_creation_token,
    read_asset_bundle,
    read_asset_bus_bundle,
    scope_allows_all,
    select_available_pocs,
    select_unauthorized_services,
    stage_status_from_result,
    target_asset_bundle,
    tscan_process_alive,
    web_fingerprint_targets,
    workflow_assets_ready,
    workflow_completed,
)


class ModalPage:
    def __init__(self, result: object):
        self.result = result
        self.script = ""

    def evaluate(self, script: str) -> object:
        self.script = script
        return self.result


class TscanAutomationTests(unittest.TestCase):
    def test_tscan_process_identity_rejects_reused_pid(self) -> None:
        token = process_creation_token(os.getpid())
        executable = Path(sys.executable)

        self.assertGreaterEqual(CDP_START_TIMEOUT_SECONDS, 60)
        self.assertTrue(tscan_process_alive(os.getpid(), token, executable))
        self.assertFalse(tscan_process_alive(os.getpid(), token + 1, executable))
        self.assertTrue(tscan_process_alive(os.getpid(), 0, executable))
        self.assertFalse(
            tscan_process_alive(os.getpid(), 0, executable.with_name("foreign.exe"))
        )

    def test_monitoring_state_explains_idle_cpu_as_standby(self) -> None:
        self.assertEqual(
            monitoring_state(
                {
                    "ipscan": {"status": "idle"},
                    "pwdcrack": {"status": "idle"},
                    "ipscanRunning": False,
                    "unauthRunning": False,
                }
            ),
            (
                "waiting_assets",
                "standby",
                "TscanPlus 当前批次已无活动内部任务；"
                "窗口保持待机，等待项目新增资产。"
                "CPU 占用较低是正常状态",
            ),
        )
        status, stage, detail = monitoring_state(
            {"pwdcrack": {"status": "running", "percent": 33.93}}
        )
        self.assertEqual((status, stage), ("running", "monitoring"))
        self.assertIn("pwdcrack=33.93%", detail)

    def test_support_modal_prefers_decline_and_never_opens_external_page(self) -> None:
        page = ModalPage(["\u5c0f\u5c0f\u652f\u6301\u4e00\u4e0b\uff1a\u6682\u65f6\u4e0d\u7528"])

        dismissed = dismiss_blocking_modals(page)

        self.assertEqual(
            dismissed,
            ("\u5c0f\u5c0f\u652f\u6301\u4e00\u4e0b\uff1a\u6682\u65f6\u4e0d\u7528",),
        )
        self.assertIn("\u5c0f\u5c0f\u652f\u6301\u4e00\u4e0b", page.script)
        self.assertIn("\u6682\u65f6\u4e0d\u7528", page.script)
        self.assertIn(".n-base-close", page.script)
        self.assertNotIn("\u597d\u7684\uff0c\u53bb\u770b\u770b", page.script)

    def test_dump_size_modal_is_acknowledged_and_requires_one_retry(self) -> None:
        page = ModalPage(["\u6587\u4ef6\u5927\u5c0f\u9650\u5236\u63d0\u9192\uff1a\u6211\u77e5\u9053\u4e86"])

        dismissed = dismiss_blocking_modals(page)

        self.assertEqual(
            dismissed,
            ("\u6587\u4ef6\u5927\u5c0f\u9650\u5236\u63d0\u9192\uff1a\u6211\u77e5\u9053\u4e86",),
        )
        self.assertTrue(modal_requires_retry(dismissed))
        self.assertIn("\u6587\u4ef6\u5927\u5c0f\u9650\u5236\u63d0\u9192", page.script)
        self.assertIn("\u6211\u77e5\u9053\u4e86", page.script)

    def test_support_modal_does_not_retry_original_action(self) -> None:
        self.assertFalse(
            modal_requires_retry(
                ("\u5c0f\u5c0f\u652f\u6301\u4e00\u4e0b\uff1a\u6682\u65f6\u4e0d\u7528",)
            )
        )

    def test_poc_selection_uses_the_poc_category_header(self) -> None:
        page = ModalPage(
            {
                "category_count": 9,
                "selected_categories": 9,
                "total_pocs": 8797,
                "selected_pocs": 8797,
                "all_selected": True,
                "header_clicked": True,
                "individual_clicks": 0,
                "missing_categories": [],
            }
        )

        result = select_available_pocs(page)

        self.assertEqual(
            result,
            {
                "category_count": 9,
                "selected_categories": 9,
                "total_pocs": 8797,
                "selected_pocs": 8797,
                "all_selected": True,
                "header_clicked": True,
                "individual_clicks": 0,
                "missing_categories": [],
            },
        )
        self.assertIn("textarea", page.script)
        self.assertIn(".n-data-table-th--selection", page.script)
        self.assertIn("category_count", page.script)
        self.assertIn("all_selected", page.script)

    def test_unauthorized_service_selection_includes_mqtt(self) -> None:
        page = ModalPage(
            {
                "available": 46,
                "selected": 46,
                "header_clicked": True,
                "individual_clicks": 1,
                "mqtt_found": True,
                "mqtt_selected": True,
                "missing_services": [],
            }
        )

        result = select_unauthorized_services(page)

        self.assertEqual(
            result,
            {
                "available": 46,
                "selected": 46,
                "header_clicked": True,
                "individual_clicks": 1,
                "mqtt_found": True,
                "mqtt_selected": True,
                "missing_services": [],
            },
        )
        self.assertIn("thead [role=\"checkbox\"]", page.script)
        self.assertIn("tbody tr", page.script)
        self.assertIn("MQTT", page.script)

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
            connection.execute("create table info (Project text, Tab text)")
            connection.execute("insert into info values ('Default', 'book.szbayy.com:3143')")
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
            info_rows = connection.execute("select count(*) from info").fetchone()[0]
            connection.close()
            self.assertEqual(project, ("", "", 0))
            self.assertEqual(rows, 0)
            self.assertEqual(info_rows, 0)
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
