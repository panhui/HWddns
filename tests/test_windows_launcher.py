import os
import tempfile
import unittest
from unittest.mock import patch

import windows_launcher


class WindowsLauncherTests(unittest.TestCase):
    def test_configuration_created_once_and_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.dict(os.environ, {"LOCALAPPDATA": folder}):
                path, port, host = windows_launcher.configure()
                self.assertEqual(port, 6006)
                self.assertEqual(host, "0.0.0.0")
                self.assertTrue(path.exists())
                self.assertTrue((path.parent / "data").is_dir())
                original_key = os.environ["DATA_KEY"]
                path.write_text(path.read_text().replace("ADMIN_PASSWORD=Qwer1234",
                                                        "ADMIN_PASSWORD=Changed123"), encoding="utf-8")
                _, _, host = windows_launcher.configure()
                self.assertEqual(os.environ["DATA_KEY"], original_key)
                self.assertEqual(os.environ["ADMIN_PASSWORD"], "Changed123")
                self.assertEqual(host, "0.0.0.0")
                path.write_text(path.read_text().replace("HOST=0.0.0.0\n", ""), encoding="utf-8")
                _, _, host = windows_launcher.configure()
                self.assertEqual(host, "0.0.0.0")
                path.write_text(path.read_text() + "HOST=127.0.0.1\n", encoding="utf-8")
                _, _, host = windows_launcher.configure()
                self.assertEqual(host, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
