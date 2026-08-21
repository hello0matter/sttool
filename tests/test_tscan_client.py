from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from sttool.tscan_client import _module_args, _targets


class TscanClientTests(unittest.TestCase):
    def test_targets_only_feed_ip_hosts_and_urls(self) -> None:
        with TemporaryDirectory() as temporary:
            paths = _targets(
                {"ips": ["10.0.0.1"], "endpoints": ["10.0.0.1:8080"], "urls": ["http://10.0.0.1/"]},
                Path(temporary),
            )
            self.assertEqual(paths["hosts"].read_text(encoding="utf-8"), "10.0.0.1\n")
            self.assertEqual(paths["urls"].read_text(encoding="utf-8"), "http://10.0.0.1/\n")

    def test_module_args_skip_web_modules_without_urls(self) -> None:
        with TemporaryDirectory() as temporary:
            paths = _targets({"ips": ["10.0.0.1"], "urls": []}, Path(temporary))
            self.assertIsNone(_module_args("url", paths, Path(temporary)))
            self.assertIsNone(_module_args("poc", paths, Path(temporary)))
            self.assertIn("-hf", _module_args("port", paths, Path(temporary)))


if __name__ == "__main__":
    unittest.main()
