from __future__ import annotations

import unittest

from sttool.window_control import collect_process_tree


class WindowControlTests(unittest.TestCase):
    def test_collect_process_tree_includes_nested_gui_process(self) -> None:
        self.assertEqual(
            collect_process_tree(
                100,
                [
                    (100, 50),
                    (101, 100),
                    (102, 101),
                    (200, 50),
                ],
            ),
            {100, 101, 102},
        )


if __name__ == "__main__":
    unittest.main()
