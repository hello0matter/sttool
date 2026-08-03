from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sttool.github_poc_search import parse_find_gh_poc_output, search_github_pocs


class GithubPocSearchTests(unittest.TestCase):
    def test_parser_keeps_links_as_metadata_only_candidates(self) -> None:
        candidates = parse_find_gh_poc_output(
            "CVE-2026-63030 - https://github.com/example/poc\n"
            "CVE-2026-63030 - https://github.com/example/poc\n",
            "cve-2026-63030",
        )

        self.assertEqual(
            candidates,
            [
                {
                    "cve_id": "CVE-2026-63030",
                    "url": "https://github.com/example/poc",
                    "query": "cve-2026-63030",
                }
            ],
        )

    def test_missing_token_is_a_safe_skip(self) -> None:
        with TemporaryDirectory() as temporary:
            executable = Path(temporary) / "find-gh-poc.exe"
            executable.write_bytes(b"test")

            report = search_github_pocs(executable, "CVE-2026-63030", "")

        self.assertEqual(report["status"], "skipped_no_token")
        self.assertEqual(report["execution_policy"], "metadata_only")
        self.assertEqual(report["candidates"], [])


if __name__ == "__main__":
    unittest.main()
