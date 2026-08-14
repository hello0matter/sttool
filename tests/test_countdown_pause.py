from __future__ import annotations

import unittest
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from sttool.asset_bus import atomic_json_write, read_json
from sttool.countdown_pause import countdown_remaining_seconds, set_countdown_paused


class CountdownPauseTests(unittest.TestCase):
    def test_remaining_seconds_stays_frozen_while_paused(self) -> None:
        now = datetime.now().astimezone().replace(microsecond=0)
        item = {
            "decision_deadline_at": (now + timedelta(seconds=20)).isoformat(),
            "countdown_paused_at": now.isoformat(),
        }

        self.assertEqual(
            countdown_remaining_seconds(item, now=now + timedelta(seconds=10)),
            20,
        )

    def test_single_request_pause_is_persisted_and_deadline_is_shifted(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "request.json"
            deadline = datetime.now().astimezone() + timedelta(seconds=10)
            atomic_json_write(path, {"status": "pending", "decision_deadline_at": deadline.isoformat(timespec="seconds")})

            paused = set_countdown_paused(path, True)
            self.assertTrue(paused["countdown_paused_at"])
            paused_at = datetime.fromisoformat(str(paused["countdown_paused_at"]))
            paused["countdown_paused_at"] = (paused_at - timedelta(seconds=7)).isoformat(timespec="seconds")
            atomic_json_write(path, paused)

            resumed = set_countdown_paused(path, False)
            shifted = datetime.fromisoformat(str(resumed["decision_deadline_at"]))
            self.assertNotIn("countdown_paused_at", resumed)
            self.assertGreaterEqual((shifted - deadline).total_seconds(), 6)

    def test_collection_pause_only_changes_pending_rows(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "items.json"
            deadline = (datetime.now().astimezone() + timedelta(seconds=10)).isoformat(timespec="seconds")
            atomic_json_write(path, {"candidates": [{"id": "a", "status": "pending", "decision_deadline_at": deadline}, {"id": "b", "status": "saved", "decision_deadline_at": deadline}]})

            set_countdown_paused(path, True, collection="candidates", pending_only=True)
            rows = read_json(path)["candidates"]

            self.assertIn("countdown_paused_at", rows[0])
            self.assertNotIn("countdown_paused_at", rows[1])


if __name__ == "__main__":
    unittest.main()
