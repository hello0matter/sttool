from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from sttool.tscan_automation import (
    awvs_site_targets,
    build_stage_plan,
    CDP_START_TIMEOUT_SECONDS,
    BrowserPolicy,
    classify_connection_feedback,
    configure_awvs_scan,
    dismiss_blocking_modals,
    dispatched_awvs_targets,
    dispatch_stages_on_page,
    filter_assets_by_scope,
    modal_requires_retry,
    monitoring_state,
    migrate_stage_batch_retries,
    normalize_poc_urls,
    password_targets,
    prepare_cdp_executable,
    prepare_tscan_workspace,
    process_creation_token,
    read_asset_bundle,
    read_asset_bus_bundle,
    read_asset_bus_generation_range,
    refresh_stage_batch_scope,
    reconcile_interrupted_stage_retry,
    record_stage_retry,
    retry_batch_due,
    retryable_stage_names,
    restore_dispatched_automation,
    scope_allows_all,
    select_available_pocs,
    select_unauthorized_services,
    stalled_discovery_modules,
    stage_status_from_result,
    stage_batch_record,
    target_asset_bundle,
    tscan_process_alive,
    web_fingerprint_targets,
    webview_environment,
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
    def test_webview_environment_isolated_per_run(self) -> None:
        with TemporaryDirectory() as temporary:
            environment = webview_environment(52041, Path(temporary))

        self.assertIn("--remote-debugging-port=52041", environment["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"])
        self.assertEqual(
            environment["WEBVIEW2_USER_DATA_FOLDER"],
            str(Path(temporary) / "tool_data" / "tscan" / "webview2_data"),
        )

    def test_browser_policy_restores_existing_value_without_elevation(self) -> None:
        key = MagicMock()
        with (
            patch("sttool.tscan_automation.winreg.CreateKeyEx", return_value=key),
            patch("sttool.tscan_automation.winreg.OpenKey", return_value=key),
            patch("sttool.tscan_automation.winreg.QueryValueEx", return_value=("old", 1)),
            patch("sttool.tscan_automation.winreg.SetValueEx") as set_value,
            patch("sttool.tscan_automation.winreg.CloseKey"),
        ):
            with BrowserPolicy(52041, "TscanTest.exe"):
                pass

        self.assertEqual(set_value.call_count, 4)
        self.assertEqual(
            set_value.call_args_list[0].args[3:],
            (1, "--remote-debugging-port=52041 --remote-allow-origins=* --force-renderer-accessibility"),
        )
        self.assertEqual(
            set_value.call_args_list[1].args[3:],
            (1, "--remote-debugging-port=52041 --remote-allow-origins=* --force-renderer-accessibility"),
        )
        self.assertEqual(set_value.call_args_list[2].args[3:], (1, "old"))
        self.assertEqual(set_value.call_args_list[3].args[3:], (1, "old"))

    def test_browser_policy_force_machine_covers_clone_and_original_names(self) -> None:
        with patch(
            "sttool.tscan_automation.run_elevated_registry_command"
        ) as run_elevated:
            with BrowserPolicy(
                52042,
                "TscanClone.exe",
                force_machine=True,
                additional_executable_names=("TscanOriginal.exe",),
            ):
                pass

        self.assertEqual(run_elevated.call_count, 2)
        self.assertIn("RegistryHive]::LocalMachine", run_elevated.call_args_list[0].args[0])
        self.assertIn("HKCU:", run_elevated.call_args_list[0].args[0])
        self.assertIn("Remove-ItemProperty", run_elevated.call_args_list[0].args[0])
        self.assertIn("TscanClone.exe", run_elevated.call_args_list[0].args[0])
        self.assertIn("TscanOriginal.exe", run_elevated.call_args_list[0].args[0])

    def test_elevated_registry_command_uses_hidden_noninteractive_powershell(self) -> None:
        completed = MagicMock(returncode=0, stdout="0\n", stderr="")
        with (
            patch("sttool.tscan_automation.subprocess.run", return_value=completed) as run,
            patch("sttool.tscan_automation.ctypes.windll.shell32.IsUserAnAdmin", return_value=1),
        ):
            from sttool.tscan_automation import run_elevated_registry_command

            run_elevated_registry_command("Write-Output ok")

        command = run.call_args.args[0]
        self.assertIn("-WindowStyle", command)
        self.assertIn("Hidden", command)
        self.assertIn("-NonInteractive", command)
        self.assertEqual(run.call_args.kwargs["creationflags"], 0x08000000)

    def test_script_help_runs_outside_repository_working_directory(self) -> None:
        script = Path(__file__).resolve().parents[1] / "sttool" / "tscan_automation.py"
        with TemporaryDirectory() as temporary:
            environment = dict(os.environ)
            environment.pop("PYTHONPATH", None)
            result = subprocess.run(
                [sys.executable, str(script), "--help"],
                cwd=temporary,
                capture_output=True,
                text=True,
                timeout=15,
                env=environment,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_prepare_cdp_executable_uses_new_policy_identity(self) -> None:
        with TemporaryDirectory() as temporary:
            source = Path(temporary) / "TscanPlus_run.exe"
            source.write_bytes(b"tscan")

            result = prepare_cdp_executable(source)

            self.assertEqual(result.name, "TscanPlus_run_cdp.exe")
            self.assertEqual(result.read_bytes(), b"tscan")
            self.assertEqual(prepare_cdp_executable(result), result)

    def test_interrupted_retry_preserves_successes_and_retries_only_failures(self) -> None:
        state = {
            "active_batch_id": "asset-generation-6-retry-1",
            "stages": {
                "waf_detection": {"status": "submitted"},
                "poc_check": {"status": "not_started"},
            },
            "stage_batches": [
                {
                    "batch_id": "asset-generation-6",
                    "pending_stages": ["waf_detection", "poc_check", "dump_all"],
                    "retry_count": 0,
                    "retry_attempts": [],
                }
            ],
        }

        self.assertTrue(reconcile_interrupted_stage_retry(state))
        batch = state["stage_batches"][0]
        self.assertEqual(batch["retry_count"], 1)
        self.assertEqual(batch["pending_stages"], ["poc_check", "dump_all"])
        self.assertEqual(
            batch["retry_attempts"][0]["result"]["stages"]["dump_all"]["status"],
            "failed",
        )
        self.assertEqual(state["active_batch_id"], "")
        self.assertFalse(reconcile_interrupted_stage_retry(state))

    def test_batch_history_prevents_full_redispatch_after_wrapper_restart(self) -> None:
        old_result = {
            "batch_id": "asset-generation-6",
            "stages": {
                "swagger": {"status": "submitted"},
                "jsfinder": {"status": "not_started"},
            },
        }
        dispatched, automation, stages = restore_dispatched_automation(
            {
                "automation_dispatched": False,
                "automation": None,
                "stages": {"partial_restart_stage": {"status": "submitted"}},
                "stage_batches": [
                    {"batch_id": "asset-generation-6", "result": old_result}
                ],
            }
        )

        self.assertTrue(dispatched)
        self.assertIs(automation, old_result)
        self.assertEqual(stages, old_result["stages"])

    def test_incomplete_uia_batch_is_retried_after_wrapper_restart(self) -> None:
        dispatched, automation, stages = restore_dispatched_automation(
            {
                "automation_dispatched": True,
                "automation": {
                    "controller": "windows_uia",
                    "stages": {"port_scan": {"status": "not_started"}},
                },
                "stages": {"port_scan": {"status": "not_started"}},
                "stage_batches": [{"result": {"controller": "windows_uia"}}],
            }
        )

        self.assertFalse(dispatched)
        self.assertIsNone(automation)
        self.assertEqual(stages, {})

    def test_new_tscan_run_still_requires_initial_dispatch(self) -> None:
        self.assertEqual(
            restore_dispatched_automation(
                {
                    "automation_dispatched": False,
                    "automation": None,
                    "stages": {},
                    "stage_batches": [],
                }
            ),
            (False, None, {}),
        )

    def test_dispatch_stage_filter_does_not_repeat_submitted_modules(self) -> None:
        with TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "tool_data" / "tscan" / "state.json"
            state: dict[str, object] = {}
            assets = {
                "ips": [],
                "domains": ["app.example.com"],
                "endpoints": [],
                "urls": ["https://app.example.com/"],
            }
            with (
                patch(
                    "sttool.tscan_automation.configure_textarea_scan",
                    return_value={"clicked": True, "acknowledged": True},
                ) as configure_textarea,
                patch("sttool.tscan_automation.configure_asset_discovery") as asset,
                patch("sttool.tscan_automation.configure_poc_check") as poc,
                patch("sttool.tscan_automation.click_tab"),
            ):
                result = dispatch_stages_on_page(
                    object(),
                    "https://app.example.com/",
                    assets,
                    True,
                    state_path,
                    state,
                    "retry-1",
                    {"jsfinder"},
                )

            self.assertEqual(result["requested_stages"], ["jsfinder"])
            self.assertEqual(list(result["stages"]), ["jsfinder"])
            self.assertEqual(configure_textarea.call_count, 1)
            self.assertEqual(configure_textarea.call_args.args[2], "JsFinder")
            asset.assert_not_called()
            poc.assert_not_called()

    def test_old_stage_batch_recovers_exact_generation_assets(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "assets.json"
            path.write_text(
                json.dumps(
                    {
                        "generation": 7,
                        "assets": [
                            {
                                "value": "old.example.com",
                                "type": "domain",
                                "first_generation": 4,
                            },
                            {
                                "value": "api.example.com",
                                "type": "domain",
                                "first_generation": 5,
                            },
                            {
                                "value": "https://api.example.com/",
                                "type": "url",
                                "first_generation": 6,
                            },
                            {
                                "value": "later.example.com",
                                "type": "domain",
                                "first_generation": 7,
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            batch = {
                "batch_id": "asset-generation-6",
                "generation_from": 5,
                "generation_to": 6,
                "result": {
                    "stages": {
                        "swagger": {"status": "submitted"},
                        "jsfinder": {"status": "not_started"},
                    }
                },
            }

            self.assertEqual(
                read_asset_bus_generation_range(path, 5, 6),
                {
                    "ips": [],
                    "domains": ["api.example.com"],
                    "endpoints": [],
                    "urls": ["https://api.example.com/"],
                },
            )
            self.assertTrue(
                migrate_stage_batch_retries(
                    [batch], path, "example.com", now=100.0
                )
            )
            self.assertEqual(batch["pending_stages"], ["jsfinder"])
            self.assertEqual(batch["next_retry_at"], 160.0)
            self.assertNotIn("later.example.com", batch["assets"]["domains"])
            self.assertFalse(
                migrate_stage_batch_retries(
                    [batch], path, "example.com", now=200.0
                )
            )

    def test_stage_retry_tracks_only_failed_and_unconfirmed_stages(self) -> None:
        result = {
            "stages": {
                "asset_discovery": {"status": "failed"},
                "swagger": {"status": "submitted"},
                "jsfinder": {"status": "not_started"},
                "nessus_scan": {"status": "skipped"},
            }
        }
        assets = {
            "ips": [],
            "domains": ["app.example.com"],
            "endpoints": [],
            "urls": ["https://app.example.com/"],
        }

        batch = stage_batch_record(
            batch_id="asset-generation-2",
            generation_from=2,
            generation_to=2,
            assets=assets,
            result=result,
            now=100.0,
        )

        self.assertEqual(
            retryable_stage_names(result), ["asset_discovery", "jsfinder"]
        )
        self.assertEqual(batch["assets"], assets)
        self.assertIsNone(retry_batch_due([batch], now=159.0))
        self.assertIs(retry_batch_due([batch], now=160.0), batch)

        record_stage_retry(
            batch,
            {
                "stages": {
                    "asset_discovery": {"status": "submitted"},
                    "jsfinder": {"status": "not_started"},
                }
            },
            now=160.0,
        )
        self.assertEqual(batch["pending_stages"], ["jsfinder"])
        self.assertEqual(batch["retry_count"], 1)
        self.assertNotIn("swagger", batch["retry_attempts"][0]["stages"])

    def test_scope_refresh_filters_existing_batch_and_resets_retries(self) -> None:
        batch = {
            "assets": {
                "ips": [],
                "domains": ["app.example.com", "unrelated.test"],
                "endpoints": [],
                "urls": [
                    "https://app.example.com/",
                    "https://unrelated.test/",
                ],
            },
            "result": {
                "stages": {
                    "asset_discovery": {"status": "failed"},
                    "dump_all": {"status": "failed"},
                }
            },
            "pending_stages": ["asset_discovery", "dump_all"],
            "retry_count": 3,
            "retry_exhausted_at": "2026-08-08T13:54:18+08:00",
            "retry_attempts": [{"attempt": 1}],
        }

        self.assertTrue(
            refresh_stage_batch_scope([batch], "example.com", now=100.0)
        )

        self.assertEqual(batch["assets"]["domains"], ["app.example.com"])
        self.assertEqual(
            batch["assets"]["urls"], ["https://app.example.com/"]
        )
        self.assertEqual(batch["processing_scope"], "example.com")
        self.assertEqual(
            batch["pending_stages"], ["asset_discovery", "dump_all"]
        )
        self.assertEqual(batch["retry_count"], 0)
        self.assertEqual(batch["next_retry_at"], 160.0)
        self.assertEqual(batch["retry_attempts"], [])
        self.assertNotIn("retry_exhausted_at", batch)
        self.assertFalse(
            refresh_stage_batch_scope([batch], "example.com", now=200.0)
        )

    def test_stage_retry_stops_after_limit(self) -> None:
        batch = {
            "pending_stages": ["poc_check"],
            "retry_count": 2,
            "next_retry_at": 0.0,
            "retry_attempts": [],
        }

        record_stage_retry(
            batch,
            {"stages": {"poc_check": {"status": "failed"}}},
            now=200.0,
        )

        self.assertEqual(batch["retry_count"], 3)
        self.assertEqual(batch["pending_stages"], ["poc_check"])
        self.assertEqual(batch["next_retry_at"], 0.0)
        self.assertIn("retry_exhausted_at", batch)
        self.assertIsNone(retry_batch_due([batch], now=999.0))

    def test_only_stalled_discovery_modules_are_recoverable(self) -> None:
        progress = {
            "jsfinder": {"status": "running"},
            "dirscan": {"status": "running"},
            "poccheck": {"status": "running"},
        }

        self.assertEqual(
            stalled_discovery_modules(
                progress,
                {"jsfinder": 0.0, "dirscan": 500.0, "poccheck": 0.0},
                700.0,
            ),
            ["jsfinder"],
        )

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

    def test_monitoring_state_reports_exhausted_stage_retries(self) -> None:
        status, stage, detail = monitoring_state(
            {"ipscan": {"status": "idle"}, "ipscanRunning": False},
            [
                {
                    "pending_stages": ["poc_check", "dump_all"],
                    "retry_count": 3,
                    "retry_exhausted_at": "2026-08-08T13:54:18+08:00",
                }
            ],
        )

        self.assertEqual((status, stage), ("manual_required", "retry_exhausted"))
        self.assertIn("poc_check、dump_all", detail)
        self.assertIn("已停止自动重试", detail)

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

    def test_existing_scan_data_modal_keeps_results(self) -> None:
        page = ModalPage(["\u5df2\u6709\u626b\u63cf\u6570\u636e\uff1a\u4fdd\u7559"])

        dismissed = dismiss_blocking_modals(page)

        self.assertEqual(dismissed, ("\u5df2\u6709\u626b\u63cf\u6570\u636e\uff1a\u4fdd\u7559",))
        self.assertIn("\u662f\u5426\u6e05\u9664\u5df2\u6709\u6570\u636e", page.script)
        self.assertIn("\u4fdd\u7559", page.script)
        self.assertNotIn("normalizedText(button) === '\u6e05\u9664'", page.script)
        self.assertFalse(modal_requires_retry(dismissed))

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
            "endpoints": [],
            "urls": ["https://app.example.com/login", "https://outside.test"],
        }

        self.assertTrue(scope_allows_all("*"))
        self.assertEqual(filter_assets_by_scope(bundle, "*"), bundle)

    def test_explicit_domain_and_network_scope_filters_assets(self) -> None:
        bundle = {
            "ips": ["192.0.2.10", "198.51.100.7"],
            "domains": ["app.example.com", "outside.test"],
            "endpoints": ["192.0.2.10:22", "198.51.100.7:6379"],
            "urls": ["https://app.example.com/login", "https://outside.test"],
        }

        self.assertEqual(
            filter_assets_by_scope(bundle, "example.com,192.0.2.0/24"),
            {
                "ips": ["192.0.2.10"],
                "domains": ["app.example.com"],
                "endpoints": ["192.0.2.10:22"],
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
                    "endpoints": [],
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
            password_targets(
                ["192.0.2.10:22", "192.0.2.11:80", "192.0.2.10:6379"]
            ),
            ["192.0.2.10"],
        )

    def test_awvs_targets_collapse_paths_and_static_assets_by_origin(self) -> None:
        self.assertEqual(
            awvs_site_targets(
                [
                    "http://book.example:3143/Booking/Welcome",
                    "http://book.example:3143/js/app.js?v=1",
                    "http://book.example:3143/admin/login",
                    "https://10.0.0.2/static/main.css",
                    "https://10.0.0.2/api/users?id=1",
                    "http://10.0.0.2/index.html",
                ],
                "http://book.example:3143/Booking/Welcome?from=project",
            ),
            [
                "http://book.example:3143/Booking/Welcome",
                "https://10.0.0.2/",
                "http://10.0.0.2/",
            ],
        )

    def test_awvs_configuration_normalizes_legacy_path_targets_at_dispatch(self) -> None:
        page = MagicMock()
        target_box = MagicMock()
        with (
            patch("sttool.tscan_automation.click_tab"),
            patch("sttool.tscan_automation.visible", return_value=target_box),
            patch("sttool.tscan_automation.set_native_value") as set_value,
            patch(
                "sttool.tscan_automation.required_inputs_configured",
                return_value=True,
            ),
        ):
            result = configure_awvs_scan(
                page,
                [
                    "http://10.17.200.52/login/../js/sm3.js?v=1",
                    "http://10.17.200.52/admin/login",
                    "https://10.17.200.52/static/app.js",
                ],
                False,
            )

        set_value.assert_called_once_with(
            target_box,
            "http://10.17.200.52/\nhttps://10.17.200.52/",
        )
        self.assertEqual(
            result["submitted_targets"],
            ["http://10.17.200.52/", "https://10.17.200.52/"],
        )

    def test_incremental_awvs_targets_do_not_repeat_unrelated_primary_site(self) -> None:
        self.assertEqual(
            awvs_site_targets(
                ["https://new.example/assets/app.js"],
                "https://primary.example/application",
            ),
            ["https://new.example/"],
        )

    def test_dispatched_awvs_targets_are_deduplicated_across_batches(self) -> None:
        state: dict[str, object] = {
            "stage_batches": [
                {
                    "assets": {
                        "urls": [
                            "https://app.example/js/old.js",
                            "https://api.example/v1/users",
                        ]
                    }
                }
            ]
        }

        self.assertEqual(
            dispatched_awvs_targets(state, "https://app.example/portal"),
            {"https://app.example/portal", "https://api.example/"},
        )

    def test_stage_plan_routes_unknown_ips_to_identification_only(self) -> None:
        plan = build_stage_plan(
            "192.0.2.10",
            {
                "ips": ["192.0.2.10", "192.0.2.11"],
                "domains": [],
                "endpoints": ["192.0.2.11:6379"],
                "urls": [],
            },
        )

        self.assertEqual(plan["identification_only"], ["192.0.2.10"])
        self.assertEqual(plan["password_targets"], ["192.0.2.11"])
        self.assertEqual(plan["web_targets"], [])
        self.assertEqual(plan["fingerprint_targets"], [])
        self.assertEqual(plan["nessus_targets"], [])
        self.assertEqual(
            plan["deferred_nessus_targets"], ["192.0.2.10", "192.0.2.11"]
        )

    def test_stage_plan_does_not_route_confirmed_web_ports_to_service_checks(self) -> None:
        plan = build_stage_plan(
            "https://app.example.com/",
            {
                "ips": [],
                "domains": ["app.example.com"],
                "endpoints": [
                    "app.example.com:8080",
                    "app.example.com:8443",
                    "app.example.com:6379",
                ],
                "urls": [
                    "http://app.example.com:8080/",
                    "https://app.example.com:8443/",
                ],
            },
        )

        self.assertEqual(plan["unauthorized_targets"], ["app.example.com"])
        self.assertEqual(plan["password_targets"], ["app.example.com"])

    def test_workflow_helpers_handle_target_and_completion(self) -> None:
        self.assertEqual(
            target_asset_bundle("http://192.0.2.10:8080/path"),
            {
                "ips": ["192.0.2.10"],
                "domains": [],
                "endpoints": ["192.0.2.10:8080"],
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
