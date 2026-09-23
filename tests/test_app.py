import importlib
import os
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

from cryptography.fernet import Fernet


class PanelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        os.environ.update(DATA_DIR=cls.temp.name, ADMIN_PASSWORD="Qwer1234",
                          APP_SECRET="test-secret-long-enough", DATA_KEY=Fernet.generate_key().decode(),
                          TZ="Asia/Shanghai")
        cls.panel = importlib.import_module("app")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        with self.panel.db() as con:
            con.execute("DELETE FROM tasks")
            con.execute("DELETE FROM settings")
        self.client = self.panel.app.test_client()
        self.assertEqual(self.client.post("/login", data={"password": "Qwer1234"}).status_code, 302)
        with self.client.session_transaction() as session:
            self.csrf = session["csrf"]

    def test_login_and_csrf(self):
        self.assertEqual(self.panel.app.test_client().get("/").status_code, 302)
        self.assertEqual(self.client.post("/settings", data={"ak": "x"}).status_code, 403)

    def test_task_lifecycle_and_log(self):
        response = self.client.post("/settings", data={"csrf": self.csrf, "ak": "AK", "sk": "SK", "region": "cn-north-4"})
        self.assertEqual(response.status_code, 302)
        with self.panel.db() as con:
            stored = con.execute("SELECT * FROM settings").fetchone()
            self.assertNotIn("AK", stored["ak"])
            self.assertNotIn("SK", stored["sk"])
        future = (datetime.now(self.panel.TZ) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M")
        response = self.client.post("/tasks/new", data={"csrf": self.csrf, "domain": "home.example.com",
                                                        "ip": "203.0.113.10", "schedule": "once", "run_at": future})
        self.assertEqual(response.status_code, 302)
        with self.panel.db() as con:
            task_id = con.execute("SELECT id FROM tasks").fetchone()[0]
        with patch.object(self.panel, "set_record", return_value=("203.0.113.9", "updated")) as cloud:
            response = self.client.post(f"/tasks/{task_id}/run", data={"csrf": self.csrf})
            self.assertEqual(response.status_code, 302)
            cloud.assert_called_once_with("AK", "SK", "cn-north-4", "home.example.com", "203.0.113.10")
        page = self.client.get(f"/tasks/{task_id}/logs").get_data(as_text=True)
        self.assertIn("203.0.113.9", page)
        self.assertIn("203.0.113.10", page)
        response = self.client.post(f"/tasks/{task_id}/delete", data={"csrf": self.csrf})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get(f"/tasks/{task_id}/logs").status_code, 404)

    def test_invalid_ip_rejected(self):
        future = (datetime.now(self.panel.TZ) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M")
        response = self.client.post("/tasks/new", data={"csrf": self.csrf, "domain": "home.example.com",
                                                        "ip": "not-an-ip", "schedule": "daily", "run_at": future})
        self.assertEqual(response.status_code, 200)
        self.assertIn("请输入有效的 IPv4", response.get_data(as_text=True))

    def test_due_task_runs_once(self):
        with self.panel.db() as con:
            con.execute("INSERT INTO settings VALUES (1,?,?,?)", (
                self.panel.FERNET.encrypt(b"AK").decode(),
                self.panel.FERNET.encrypt(b"SK").decode(), "cn-north-4"))
            task_id = con.execute("INSERT INTO tasks (domain,ip,schedule,run_at,next_run_at,created_at) VALUES (?,?,?,?,?,?)",
                                  ("home.example.com", "203.0.113.10", "once", "2020-01-01T00:00:00+00:00",
                                   "2020-01-01T00:00:00+00:00", self.panel.utcnow())).lastrowid
        with patch.object(self.panel, "set_record", return_value=("203.0.113.9", "updated")) as cloud:
            self.assertTrue(self.panel.execute_task(task_id))
            self.assertFalse(self.panel.execute_task(task_id))
            cloud.assert_called_once()
        with self.panel.db() as con:
            task = con.execute("SELECT status,next_run_at FROM tasks WHERE id=?", (task_id,)).fetchone()
            self.assertEqual((task["status"], task["next_run_at"]), ("done", None))


if __name__ == "__main__":
    unittest.main()
