from __future__ import annotations

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sttool.secret_store import load_api_key, save_api_key


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


if __name__ == "__main__":
    unittest.main()
