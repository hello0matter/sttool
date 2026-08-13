from __future__ import annotations

import json
import time
import unittest
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from sttool.asset_bus import AssetBus
from sttool.workload_approval import (
    create_request,
    decide_request,
    read_request,
    read_history,
    resolve_due_request,
    update_pending_request_policy,
    update_asset_inclusion,
    workload_assets,
    workload_counts,
    workload_total,
)


class WorkloadApprovalTests(unittest.TestCase):
    def _run_dir(self, temporary: str) -> Path:
        run_dir = Path(temporary)
        (run_dir / "tool_data" / "coordinator").mkdir(parents=True)
        return run_dir

    def test_counts_only_include_assets_after_consumed_generation(self) -> None:
        value = {
            "assets": [
                {"type": "ip", "first_generation": 1},
                {"type": "domain", "first_generation": 2},
                {"type": "endpoint", "first_generation": 3},
                {"type": "url", "first_generation": 3},
                {"type": "unknown", "first_generation": 3},
            ]
        }
        counts = workload_counts(value, 1)
        self.assertEqual(counts, {"ips": 0, "domains": 1, "endpoints": 1, "urls": 1})
        self.assertEqual(workload_total(counts), 3)

    def test_request_snapshot_and_exclusions_update_live_counts(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = self._run_dir(temporary)
            snapshot = workload_assets(
                {
                    "assets": [
                        {"type": "ip", "value": "10.0.0.1", "first_generation": 1, "sources": ["fscan"]},
                        {"type": "url", "value": "https://example.test/", "first_generation": 2, "sources": ["tscan"]},
                    ]
                },
                1,
            )
            request = create_request(
                run_dir,
                project_name="demo",
                run_id="run-1",
                generation_from=2,
                generation_to=2,
                counts={},
                mode="manual",
                countdown_seconds=10,
                assets=snapshot,
            )
            self.assertEqual(request["total"], 1)
            self.assertEqual(request["assets"][0]["value"], "https://example.test/")

            updated = update_asset_inclusion(
                run_dir,
                {("url", "https://example.test/")},
                included=False,
            )
            self.assertEqual(updated["total"], 0)
            decided = decide_request(run_dir, "accept")
            self.assertEqual(decided["decision"], "reject")
            self.assertEqual(decided["decision_reason"], "all_assets_excluded")

    def test_create_request_manual_has_no_deadline(self) -> None:
        with TemporaryDirectory() as temporary:
            request = create_request(
                self._run_dir(temporary),
                project_name="demo",
                run_id="run-1",
                generation_from=1,
                generation_to=2,
                counts={"ips": 2, "domains": 0, "endpoints": 0, "urls": 0},
                mode="manual",
                countdown_seconds=10,
            )
            self.assertEqual(request["status"], "pending")
            self.assertEqual(request["decision_deadline_at"], "")
            self.assertEqual(request["default_action"], "accept")

    def test_hot_policy_update_resets_pending_request_countdown(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = self._run_dir(temporary)
            create_request(
                run_dir,
                project_name="demo",
                run_id="run-1",
                generation_from=1,
                generation_to=2,
                counts={"ips": 100, "domains": 0, "endpoints": 0, "urls": 0},
                mode="countdown_accept",
                countdown_seconds=5,
            )

            changed = update_pending_request_policy(
                run_dir,
                mode="countdown_reject",
                countdown_seconds=20,
            )

            request = read_request(run_dir)
            remaining = (
                datetime.fromisoformat(request["decision_deadline_at"])
                - datetime.now().astimezone()
            ).total_seconds()
            self.assertTrue(changed)
            self.assertGreaterEqual(remaining, 18)
            self.assertLessEqual(remaining, 20)
            self.assertEqual(request["default_action"], "reject")

    def test_decide_request_accept_and_reject(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = self._run_dir(temporary)
            create_request(
                run_dir,
                project_name="demo",
                run_id="run-1",
                generation_from=1,
                generation_to=2,
                counts={"ips": 1, "domains": 1, "endpoints": 0, "urls": 0},
                mode="countdown_accept",
                countdown_seconds=10,
            )
            accepted = decide_request(run_dir, "accept")
            self.assertEqual(accepted["decision"], "accept")
            self.assertEqual(read_request(run_dir), accepted)

            accepted["status"] = "pending"
            (run_dir / "tool_data" / "coordinator" / "workload_approval.json").write_text(
                json.dumps(accepted), encoding="utf-8"
            )
            rejected = decide_request(run_dir, "reject")
            self.assertEqual(rejected["decision"], "reject")

    def test_decisions_are_preserved_in_management_history(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = self._run_dir(temporary)
            create_request(
                run_dir,
                project_name="demo",
                run_id="run-1",
                generation_from=1,
                generation_to=2,
                counts={"ips": 80, "domains": 0, "endpoints": 0, "urls": 0},
                mode="countdown_accept",
                countdown_seconds=20,
            )

            decided = decide_request(run_dir, "reject", "project_access_manager")

            self.assertEqual(read_history(run_dir), [decided])

    def test_due_request_uses_default_accept_or_reject(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = self._run_dir(temporary)
            request = create_request(
                run_dir,
                project_name="demo",
                run_id="run-1",
                generation_from=1,
                generation_to=2,
                counts={"ips": 100, "domains": 0, "endpoints": 0, "urls": 0},
                mode="countdown_accept",
                countdown_seconds=3,
            )
            due = resolve_due_request(run_dir, now=time.time() + 10)
            self.assertEqual(due["status"], "decided")
            self.assertEqual(due["decision"], "accept")
            self.assertEqual(due["decided_by"], "timeout_default")
            self.assertEqual(request["default_action"], "accept")

            request = create_request(
                run_dir,
                project_name="demo",
                run_id="run-1",
                generation_from=3,
                generation_to=4,
                counts={"ips": 100, "domains": 0, "endpoints": 0, "urls": 0},
                mode="countdown_reject",
                countdown_seconds=3,
            )
            due = resolve_due_request(run_dir, now=time.time() + 10)
            self.assertEqual(due["decision"], "reject")
            self.assertEqual(request["default_action"], "reject")

    def test_manual_request_never_resolves_by_timeout(self) -> None:
        with TemporaryDirectory() as temporary:
            run_dir = self._run_dir(temporary)
            create_request(
                run_dir,
                project_name="demo",
                run_id="run-1",
                generation_from=1,
                generation_to=2,
                counts={"ips": 100, "domains": 0, "endpoints": 0, "urls": 0},
                mode="manual",
                countdown_seconds=3,
            )
            value = resolve_due_request(run_dir, now=time.time() + 3600)
            self.assertEqual(value["status"], "pending")
            self.assertNotIn("decision", value)


class AgentWorkloadGateTests(unittest.TestCase):
    def _bus(self, run_dir: Path, total: int) -> AssetBus:
        bus = AssetBus(run_dir / "assets.json", "*", target="https://example.test")
        bus.ingest(
            [(f"https://host-{index}.example.test/path", "url") for index in range(total)],
            "test",
        )
        return bus

    def test_gate_creates_pending_request_and_reuses_it(self) -> None:
        from sttool.project_coordinator import agent_workload_gate

        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            (run_dir / "tool_data" / "coordinator").mkdir(parents=True)
            bus = self._bus(run_dir, 3)
            state: dict[str, object] = {}
            result = agent_workload_gate(
                run_dir,
                state,
                bus,
                consumed_generation=0,
                mode="manual",
                countdown_seconds=10,
                threshold=2,
                project_name="demo",
                run_id="run-1",
            )
            self.assertEqual(result, "pending")
            first = read_request(run_dir)
            self.assertEqual(first["status"], "pending")
            result = agent_workload_gate(
                run_dir,
                state,
                bus,
                consumed_generation=0,
                mode="manual",
                countdown_seconds=10,
                threshold=2,
                project_name="demo",
                run_id="run-1",
            )
            self.assertEqual(result, "pending")
            self.assertEqual(read_request(run_dir)["request_id"], first["request_id"])

    def test_gate_reject_marks_generation_consumed_and_new_generation_can_prompt(self) -> None:
        from sttool.project_coordinator import agent_workload_gate

        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            (run_dir / "tool_data" / "coordinator").mkdir(parents=True)
            bus = self._bus(run_dir, 3)
            state: dict[str, object] = {}
            agent_workload_gate(
                run_dir, state, bus, consumed_generation=0, mode="manual", countdown_seconds=10,
                threshold=2, project_name="demo", run_id="run-1",
            )
            decide_request(run_dir, "reject")
            result = agent_workload_gate(
                run_dir, state, bus, consumed_generation=0, mode="manual", countdown_seconds=10,
                threshold=2, project_name="demo", run_id="run-1",
            )
            self.assertEqual(result, "rejected")
            self.assertEqual(state["agent_consumed_generation"], bus.generation)

            bus.ingest([("https://new.example.test/path", "url")], "test")
            state = {}
            result = agent_workload_gate(
                run_dir, state, bus, consumed_generation=bus.generation - 1, mode="manual", countdown_seconds=10,
                threshold=1, project_name="demo", run_id="run-1",
            )
            self.assertEqual(result, "pending")
            self.assertNotEqual(read_request(run_dir)["generation_to"], 1)

    def test_gate_allows_automatic_and_small_batches(self) -> None:
        from sttool.project_coordinator import agent_workload_gate

        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            (run_dir / "tool_data" / "coordinator").mkdir(parents=True)
            bus = self._bus(run_dir, 3)
            self.assertEqual(
                agent_workload_gate(
                    run_dir, {}, bus, consumed_generation=0, mode="automatic", countdown_seconds=10,
                    threshold=2, project_name="demo", run_id="run-1",
                ),
                "accepted",
            )
            self.assertEqual(
                agent_workload_gate(
                    run_dir, {}, bus, consumed_generation=0, mode="manual", countdown_seconds=10,
                    threshold=10, project_name="demo", run_id="run-1",
                ),
                "accepted",
            )

    def test_gate_skips_when_scope_refresh_removes_all_approved_assets(self) -> None:
        from sttool.project_coordinator import agent_workload_gate

        with TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            (run_dir / "tool_data" / "coordinator").mkdir(parents=True)
            bus = self._bus(run_dir, 3)
            state: dict[str, object] = {}
            agent_workload_gate(
                run_dir, state, bus, consumed_generation=0, mode="manual",
                countdown_seconds=10, threshold=2, project_name="demo", run_id="run-1",
            )
            decide_request(run_dir, "accept")
            bus.update_scopes(scope="example.test", processing_scope="no-match.invalid")

            result = agent_workload_gate(
                run_dir, state, bus, consumed_generation=0, mode="manual",
                countdown_seconds=10, threshold=2, project_name="demo", run_id="run-1",
            )

            self.assertEqual(result, "rejected")
            self.assertEqual(state["agent_consumed_generation"], bus.generation)


if __name__ == "__main__":
    unittest.main()
