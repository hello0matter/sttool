from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from sttool.tscan_uia import (
    _dismiss_welcome,
    _invoke,
    _normalise_host_targets,
    _normalise_targets,
    _select_path,
)


class TscanUiaTests(unittest.TestCase):
    def test_normalise_targets_deduplicates_without_reordering(self) -> None:
        self.assertEqual(_normalise_targets([" a ", "a", "", "b"]), ["a", "b"])

    def test_normalise_host_targets_strips_url_parts(self) -> None:
        self.assertEqual(
            _normalise_host_targets(
                ["http://10.17.98.140/", "10.17.98.140", "https://example.test:8443/a"]
            ),
            ["10.17.98.140", "example.test"],
        )

    def test_normalise_host_targets_keeps_project_target_as_fallback(self) -> None:
        self.assertEqual(
            _normalise_host_targets(["http://10.17.98.140/"]),
            ["10.17.98.140"],
        )

    def test_invoke_uses_uia_pattern_without_mouse_input(self) -> None:
        control = MagicMock()
        control.invoke.side_effect = RuntimeError("not available")
        _invoke(control)
        control.iface_invoke.Invoke.assert_called_once_with()
        control.click_input.assert_not_called()

    def test_invoke_fails_without_falling_back_to_mouse_input(self) -> None:
        control = MagicMock()
        control.invoke.side_effect = RuntimeError("not available")
        control.iface_invoke.Invoke.side_effect = RuntimeError("not available")
        with self.assertRaises(RuntimeError):
            _invoke(control)
        control.click_input.assert_not_called()

    @patch("sttool.tscan_uia.time.sleep")
    @patch("sttool.tscan_uia._invoke")
    @patch("sttool.tscan_uia._find")
    def test_dismiss_welcome_accepts_terms_before_confirming(
        self, find: MagicMock, invoke: MagicMock, _sleep: MagicMock
    ) -> None:
        marker = MagicMock()
        agreement = MagicMock()
        agreement.get_toggle_state.return_value = 0
        confirm = MagicMock()
        find.side_effect = [marker, agreement, confirm]

        self.assertTrue(_dismiss_welcome(MagicMock()))

        agreement.toggle.assert_called_once_with()
        invoke.assert_called_once_with(confirm)

    @patch("sttool.tscan_uia._select_tab")
    def test_select_path_requires_each_navigation_level(self, select_tab: MagicMock) -> None:
        select_tab.side_effect = [True, True]

        self.assertTrue(
            _select_path(
                MagicMock(),
                (("资产探测",), ("目录扫描", "目录枚举")),
            )
        )

        self.assertEqual(
            select_tab.call_args_list,
            [
                unittest.mock.call(unittest.mock.ANY, ("资产探测",)),
                unittest.mock.call(unittest.mock.ANY, ("目录扫描", "目录枚举")),
            ],
        )


if __name__ == "__main__":
    unittest.main()
