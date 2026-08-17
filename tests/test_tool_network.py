from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from sttool.tool_network import (
    apply_session_network,
    cli_network_args,
    http_fallback_proxy_url,
    normalize_tool_network,
    proxy_url,
    tool_environment,
    webview_proxy_argument,
)


class ToolNetworkTests(unittest.TestCase):
    def test_socks_proxy_uses_remote_dns_and_exports_header(self) -> None:
        settings = normalize_tool_network(
            {
                "mode": "socks5",
                "host": "127.0.0.1",
                "port": 7891,
                "header_name": "flag",
                "header_value": "xiaoxiong",
            }
        )
        environment = tool_environment(settings, {"HTTP_PROXY": "old"})
        self.assertEqual(proxy_url(settings), "socks5h://127.0.0.1:7891")
        self.assertEqual(
            http_fallback_proxy_url(settings), "http://127.0.0.1:7891"
        )
        self.assertEqual(environment["HTTPS_PROXY"], "http://127.0.0.1:7891")
        self.assertEqual(environment["ALL_PROXY"], "socks5h://127.0.0.1:7891")
        self.assertEqual(
            environment["STTOOL_TOOL_HTTP_FALLBACK_PROXY_URL"],
            "http://127.0.0.1:7891",
        )
        self.assertEqual(environment["STTOOL_HTTP_HEADER_NAME"], "flag")
        self.assertEqual(environment["STTOOL_HTTP_HEADER_VALUE"], "xiaoxiong")

    def test_direct_mode_removes_inherited_proxy(self) -> None:
        environment = tool_environment(
            {"mode": "direct"},
            {"HTTP_PROXY": "http://old", "all_proxy": "socks5://old", "KEEP": "1"},
        )
        self.assertNotIn("HTTP_PROXY", environment)
        self.assertNotIn("all_proxy", environment)
        self.assertEqual(environment["KEEP"], "1")

    def test_nuclei_receives_proxy_and_header_arguments(self) -> None:
        with patch.dict(
            os.environ,
            {
                "STTOOL_TOOL_NETWORK_MODE": "http",
                "STTOOL_TOOL_PROXY_URL": "http://127.0.0.1:8080",
                "STTOOL_HTTP_HEADER_NAME": "flag",
                "STTOOL_HTTP_HEADER_VALUE": "xiaoxiong",
            },
            clear=False,
        ):
            self.assertEqual(
                cli_network_args("nuclei"),
                [
                    "-proxy",
                    "http://127.0.0.1:8080",
                    "-H",
                    "flag: xiaoxiong",
                ],
            )
            self.assertEqual(
                webview_proxy_argument(),
                "--proxy-server=http://127.0.0.1:8080",
            )

    def test_dirsearch_uses_http_fallback_for_socks_configuration(self) -> None:
        with patch.dict(
            os.environ,
            {
                "STTOOL_TOOL_NETWORK_MODE": "socks5",
                "STTOOL_TOOL_PROXY_URL": "socks5h://127.0.0.1:7891",
                "STTOOL_HTTP_HEADER_NAME": "",
                "STTOOL_HTTP_HEADER_VALUE": "",
            },
            clear=False,
        ):
            self.assertEqual(
                cli_network_args("dirsearch"),
                ["--proxy", "http://127.0.0.1:7891"],
            )

    def test_native_session_falls_back_to_http_without_socks_dependency(self) -> None:
        session = type("Session", (), {"proxies": {}, "headers": {}})()
        with (
            patch.dict(
                os.environ,
                {
                    "STTOOL_TOOL_NETWORK_MODE": "socks5",
                    "STTOOL_TOOL_PROXY_URL": "socks5h://127.0.0.1:7891",
                    "STTOOL_HTTP_HEADER_NAME": "",
                    "STTOOL_HTTP_HEADER_VALUE": "",
                },
                clear=False,
            ),
            patch("sttool.tool_network._socks5_available", return_value=False),
        ):
            apply_session_network(session)
        self.assertEqual(
            session.proxies,
            {
                "http": "http://127.0.0.1:7891",
                "https": "http://127.0.0.1:7891",
            },
        )
        self.assertEqual(session.headers, {})

    def test_incomplete_custom_header_is_not_exported_or_applied(self) -> None:
        settings = normalize_tool_network(
            {"header_name": "flag", "header_value": ""}
        )
        environment = tool_environment(settings, {})
        self.assertEqual(environment["STTOOL_HTTP_HEADER_NAME"], "")
        self.assertEqual(environment["STTOOL_HTTP_HEADER_VALUE"], "")
        with patch.dict(os.environ, environment, clear=True):
            self.assertNotIn("-H", cli_network_args("nuclei"))

    def test_newlines_disable_custom_header(self) -> None:
        settings = normalize_tool_network(
            {"header_name": "flag", "header_value": "x\r\nInjected: yes"}
        )
        self.assertEqual(settings["header_name"], "")
        self.assertEqual(settings["header_value"], "")


if __name__ == "__main__":
    unittest.main()
