from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from sttool.tscan_uia import _invoke, _normalise_targets


class TscanUiaTests(unittest.TestCase):
    def test_normalise_targets_deduplicates_without_reordering(self) -> None:
        self.assertEqual(_normalise_targets([" a ", "a", "", "b"]), ["a", "b"])

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


if __name__ == "__main__":
    unittest.main()
