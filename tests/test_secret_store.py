from __future__ import annotations

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sttool.secret_store import (
    load_api_key,
    load_secret_values,
    save_api_key,
    save_secret_values,
    update_secret_value,
)


@unittest.skipUnless(os.name == "nt", "Windows DPAPI only")
class SecretStoreTests(unittest.TestCase):
    def test_api_key_round_trip_is_encrypted_at_rest(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "launcher_secrets.dat"
            secret = "sk-test-global-secret"

            save_api_key(path, secret)

            self.assertNotIn(secret.encode("utf-8"), path.read_bytes())
            self.assertEqual(load_api_key(path), secret)
            save_api_key(path, "")
            self.assertFalse(path.exists())

    def test_multiple_secrets_are_encrypted_and_legacy_api_key_is_preserved(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "launcher_secrets.dat"
            save_api_key(path, "legacy-shared-key")
            self.assertEqual(
                load_secret_values(path),
                {"shared_ai_api_key": "legacy-shared-key"},
            )

            save_secret_values(
                path,
                {
                    "shared_ai_api_key": "shared-key",
                    "github_token": "github-token",
                },
            )

            encrypted = path.read_bytes()
            self.assertNotIn(b"shared-key", encrypted)
            self.assertNotIn(b"github-token", encrypted)
            self.assertEqual(
                load_secret_values(path),
                {
                    "shared_ai_api_key": "shared-key",
                    "github_token": "github-token",
                },
            )
            self.assertEqual(load_api_key(path), "shared-key")

    def test_updating_github_token_preserves_shared_ai_key(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "launcher_secrets.dat"
            save_secret_values(path, {"shared_ai_api_key": "shared-key"})

            values = update_secret_value(path, "github_token", "github-token")

            self.assertEqual(
                values,
                {
                    "shared_ai_api_key": "shared-key",
                    "github_token": "github-token",
                },
            )
            self.assertEqual(load_secret_values(path), values)

            values = update_secret_value(path, "github_token", "")
            self.assertEqual(values, {"shared_ai_api_key": "shared-key"})
            self.assertEqual(load_secret_values(path), values)


if __name__ == "__main__":
    unittest.main()
