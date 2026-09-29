import importlib
import os
import socket
import sqlite3
import tempfile
import time
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

    def test_login_persists_for_30_days_and_logout(self):
        with self.client.session_transaction() as session:
            self.assertTrue(session.permanent)
        self.assertEqual(self.client.post("/login", data={"password": "Qwer1234"}).status_code, 302)
        cookie = self.client.get_cookie("session")
        self.assertIsNotNone(cookie.expires)
        self.assertAlmostEqual(cookie.expires.timestamp() - time.time(), 30 * 86400, delta=5)
        reopened = self.panel.app.test_client()
        reopened.set_cookie("session", cookie.value)
        current = time.time()
        with patch("time.time", return_value=current + 29 * 86400):
            self.assertEqual(reopened.get("/").status_code, 200)
        with patch("time.time", return_value=current + 31 * 86400):
            self.assertEqual(reopened.get("/").status_code, 302)
        with self.client.session_transaction() as session:
            csrf = session["csrf"]
        self.assertEqual(self.client.post("/logout", data={"csrf": csrf}).status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 302)

    def test_ip_check_auth_validation_and_ipv6(self):
        self.assertEqual(self.panel.app.test_client().get("/ip-check").status_code, 302)
        self.assertEqual(self.client.post("/ip-check", data={"ip": "127.0.0.1", "port": "443"}).status_code, 403)
        page = self.client.get("/ip-check").get_data(as_text=True)
        self.assertIn('value="58611"', page)
        self.assertIn('value="58610-58639"', page)
        self.assertIn("IP 地址或域名", page)
        self.assertNotIn('placeholder="例如', page)
        with patch.object(self.panel, "tcp_reachable", return_value=(True, "TCP 连接成功")) as probe:
            for address, port in [("bad..domain", "443"), ("127.0.0.1", "0"),
                                  ("127.0.0.1", "65536"), ("127.0.0.1", "bad")]:
                response = self.client.post("/ip-check", data={"csrf": self.csrf, "ip": address, "port": port})
                self.assertEqual(response.status_code, 200)
                self.assertIn('alert error', response.get_data(as_text=True))
            probe.assert_not_called()
            response = self.client.post("/ip-check", data={"csrf": self.csrf,
                "ip": " 2001:db8::1 ", "port": "443"})
            probe.assert_called_once_with("2001:db8::1", 443, attempts=1, timeout=1)
            self.assertIn('class="result-status up"', response.get_data(as_text=True))
            probe.reset_mock()
            response = self.client.post("/ip-check", data={"csrf": self.csrf,
                "ip": " Service.Example.Com. ", "port": "58611"})
            self.assertIn('class="result-status up"', response.get_data(as_text=True))
            probe.assert_called_once_with("service.example.com", 58611, attempts=1, timeout=1)

    def test_ip_range_check_validation_and_results(self):
        self.assertEqual(self.client.post("/ip-check", data={"mode": "range", "ip": "127.0.0.1",
                                                          "ports": "58610-58639"}).status_code, 403)
        with patch.object(self.panel, "scan_tcp_ports", return_value=[
                (58610, False, "连接拒绝"), (58611, True, "TCP 连接成功")]) as scan:
            for address, ports in [("bad..domain", "58610-58611"), ("127.0.0.1", "58611"),
                                   ("127.0.0.1", "58612-58610"), ("127.0.0.1", "0-1"),
                                   ("127.0.0.1", "65535-65536"), ("127.0.0.1", "1-257")]:
                response = self.client.post("/ip-check", data={"csrf": self.csrf, "mode": "range",
                                                               "ip": address, "ports": ports})
                self.assertEqual(response.status_code, 200)
                self.assertIn('alert error', response.get_data(as_text=True))
            scan.assert_not_called()
            response = self.client.post("/ip-check", data={"csrf": self.csrf, "mode": "range",
                                                           "ip": " 2001:db8::1 ", "ports": "58610-58611"})
            scan.assert_called_once_with("2001:db8::1", 58610, 58611)
            page = response.get_data(as_text=True)
            self.assertIn("1 / 2", page)
            self.assertIn('class="port-grid"', page)
            self.assertEqual(page.count('class="port-item '), 2)
            self.assertIn('class="port-item up"', page)
            self.assertIn('class="port-item down"', page)
            self.assertNotIn("连接拒绝", page)
            self.assertIn("58611", page)
            scan.reset_mock()
            response = self.client.post("/ip-check", data={"csrf": self.csrf, "mode": "range",
                "ip": " Service.Example.Com. ", "ports": "58610-58611"})
            self.assertIn("service.example.com", response.get_data(as_text=True))
            scan.assert_called_once_with("service.example.com", 58610, 58611)

    def test_ip_check_real_tcp_open_and_closed_port(self):
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            port = server.getsockname()[1]
            data = {"csrf": self.csrf, "ip": "127.0.0.1", "port": str(port)}
            page = self.client.post("/ip-check", data=data).get_data(as_text=True)
            self.assertIn('class="result-status up"', page)
        page = self.client.post("/ip-check", data=data).get_data(as_text=True)
        self.assertIn('class="result-status down"', page)
        with self.panel.db() as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM tasks").fetchone()[0], 0)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM logs").fetchone()[0], 0)

    def test_task_lifecycle_and_log(self):
        response = self.client.post("/settings", data={"csrf": self.csrf, "ak": "AK", "sk": "SK", "region": "cn-north-4"})
        self.assertEqual(response.status_code, 302)
        with self.panel.db() as con:
            stored = con.execute("SELECT * FROM settings").fetchone()
            self.assertNotEqual(stored["ak"], "AK")
            self.assertNotEqual(stored["sk"], "SK")
            self.assertEqual(self.panel.FERNET.decrypt(stored["ak"].encode()), b"AK")
            self.assertEqual(self.panel.FERNET.decrypt(stored["sk"].encode()), b"SK")
        future = (datetime.now(self.panel.TZ) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M")
        response = self.client.post("/tasks/new", data={"csrf": self.csrf, "domain": "home.example.com",
                                                        "ip": "203.0.113.10", "schedule": "once", "run_at": future})
        self.assertEqual(response.status_code, 302)
        with self.panel.db() as con:
            task_id = con.execute("SELECT id FROM tasks").fetchone()[0]
            self.assertIsNone(con.execute("SELECT last_probe_reachable FROM tasks WHERE id=?", (task_id,)).fetchone()[0])
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(self.client.get(f"/tasks/{task_id}/edit").status_code, 200)
        with patch.object(self.panel, "set_record", return_value=("203.0.113.9", "updated")) as cloud:
            response = self.client.post(f"/tasks/{task_id}/run", data={"csrf": self.csrf})
            self.assertEqual(response.status_code, 302)
            cloud.assert_called_once_with("AK", "SK", "cn-north-4", "home.example.com", "203.0.113.10", "A")
        page = self.client.get(f"/tasks/{task_id}/logs").get_data(as_text=True)
        self.assertIn("203.0.113.9", page)
        self.assertIn("203.0.113.10", page)
        self.assertIn("清空日志", page)
        self.assertEqual(self.client.post(f"/tasks/{task_id}/logs/clear").status_code, 403)
        self.assertEqual(self.client.post(f"/tasks/{task_id}/logs/clear",
                                          data={"csrf": self.csrf}).status_code, 302)
        with self.panel.db() as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM logs WHERE task_id=?", (task_id,)).fetchone()[0], 0)
            self.assertIsNotNone(con.execute("SELECT id FROM tasks WHERE id=?", (task_id,)).fetchone())
        response = self.client.post(f"/tasks/{task_id}/delete", data={"csrf": self.csrf})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get(f"/tasks/{task_id}/logs").status_code, 404)

    def test_invalid_ip_rejected(self):
        future = (datetime.now(self.panel.TZ) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M")
        response = self.client.post("/tasks/new", data={"csrf": self.csrf, "domain": "home.example.com",
                                                        "ip": "not-an-ip", "schedule": "daily", "run_at": future})
        self.assertEqual(response.status_code, 200)
        self.assertIn("请输入有效的目标 IP", response.get_data(as_text=True))

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

    def test_probe_healthy_and_failover(self):
        self.assertEqual(self.client.get("/tasks/probe/new").status_code, 200)
        response = self.client.post("/tasks/probe/new", data={"csrf": self.csrf,
            "probe_domain": "service.example.com", "probe_port": "443",
            "domain": "home.example.com", "record_type": "CNAME",
            "ip": "backup.example.com", "interval_minutes": "5"})
        self.assertEqual(response.status_code, 302)
        with self.panel.db() as con:
            task_id = con.execute("SELECT id FROM tasks").fetchone()[0]
            self.assertIsNone(con.execute("SELECT last_probe_reachable FROM tasks WHERE id=?", (task_id,)).fetchone()[0])
            self.assertEqual(con.execute("SELECT probe_targets FROM tasks WHERE id=?", (task_id,)).fetchone()[0],
                             "backup.example.com")
        self.assertIn("尚未探测", self.client.get("/").get_data(as_text=True))
        self.assertEqual(self.client.get(f"/tasks/{task_id}/edit").status_code, 200)
        with patch.object(self.panel, "tcp_reachable", return_value=(True, "ok")), \
             patch.object(self.panel, "set_record") as cloud:
            self.assertTrue(self.panel.execute_task(task_id))
            cloud.assert_not_called()
        with self.panel.db() as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM logs WHERE task_id=?", (task_id,)).fetchone()[0], 0)
            task = con.execute("SELECT last_run_at,next_run_at,last_probe_reachable FROM tasks WHERE id=?", (task_id,)).fetchone()
            self.assertIsNotNone(task["last_run_at"])
            self.assertIsNotNone(task["next_run_at"])
            self.assertEqual(task["last_probe_reachable"], 1)
            con.execute("INSERT INTO settings VALUES (1,?,?,?)", (
                self.panel.FERNET.encrypt(b"AK").decode(),
                self.panel.FERNET.encrypt(b"SK").decode(), "cn-north-4"))
        self.assertIn("最近一次探测连通", self.client.get("/").get_data(as_text=True))
        with patch.object(self.panel, "tcp_reachable", side_effect=[(False, "连接超时"), (True, "ok")]) as probe, \
             patch.object(self.panel, "set_record", return_value=("primary.example.com.", "updated")) as cloud:
            self.assertTrue(self.panel.execute_task(task_id, manual=True))
            self.assertEqual(probe.call_count, 2)
            probe.assert_any_call("backup.example.com", 443, attempts=1, timeout=1)
            cloud.assert_called_once_with("AK", "SK", "cn-north-4", "home.example.com", "backup.example.com", "CNAME")
        with self.panel.db() as con:
            log = con.execute("SELECT * FROM logs WHERE task_id=? ORDER BY id DESC", (task_id,)).fetchone()
            self.assertEqual(log["old_ip"], "primary.example.com.")
            self.assertIn("探测不通", log["message"])
            self.assertEqual(con.execute("SELECT last_probe_reachable FROM tasks WHERE id=?", (task_id,)).fetchone()[0], 0)
            con.execute("INSERT INTO logs (task_id,executed_at,old_ip,new_ip,result,message) VALUES (?,?,?,?,?,?)",
                        (task_id, self.panel.utcnow(), "—", "—", "healthy", "旧版探测正常记录"))
        self.panel.init_db()
        with self.panel.db() as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM logs WHERE task_id=?", (task_id,)).fetchone()[0], 1)
        self.assertIn("最近一次探测不通", self.client.get("/").get_data(as_text=True))
        with patch.object(self.panel, "tcp_reachable", side_effect=[(False, "连接超时"), (True, "ok")]), \
             patch.object(self.panel, "set_record", side_effect=ValueError("DNS 不可用")):
            self.assertFalse(self.panel.execute_task(task_id, manual=True))
        with self.panel.db() as con:
            self.assertEqual(con.execute("SELECT last_probe_reachable FROM tasks WHERE id=?", (task_id,)).fetchone()[0], 0)
        response = self.client.post(f"/tasks/{task_id}/edit", data={"csrf": self.csrf,
            "probe_domain": "new.example.com", "probe_port": "443", "domain": "home.example.com",
            "record_type": "CNAME", "ip": "backup.example.com", "interval_minutes": "5"})
        self.assertEqual(response.status_code, 302)
        with self.panel.db() as con:
            self.assertIsNone(con.execute("SELECT last_probe_reachable FROM tasks WHERE id=?", (task_id,)).fetchone()[0])

    def test_probe_targets_follow_order_and_preserve_dns_when_all_down(self):
        targets = "203.0.113.10\n203.0.113.11\n203.0.113.12"
        response = self.client.post("/tasks/probe/new", data={"csrf": self.csrf,
            "probe_domain": "service.example.com", "probe_port": "58611",
            "domain": "home.example.com", "record_type": "A",
            "targets": targets, "interval_minutes": "5"})
        self.assertEqual(response.status_code, 302)
        with self.panel.db() as con:
            task = con.execute("SELECT * FROM tasks").fetchone()
            task_id = task["id"]
            self.assertEqual(task["ip"], "203.0.113.10")
            self.assertEqual(task["probe_targets"], targets)
            con.execute("INSERT INTO settings VALUES (1,?,?,?)", (
                self.panel.FERNET.encrypt(b"AK").decode(),
                self.panel.FERNET.encrypt(b"SK").decode(), "cn-north-4"))
        page = self.client.get("/").get_data(as_text=True)
        self.assertIn("共 3 个备用目标", page)
        self.assertIn("data-task-modal", page)
        self.assertNotIn('class="stats"', page)
        with patch.object(self.panel, "tcp_reachable", side_effect=[
                (False, "down"), (False, "down"), (True, "ok")]) as probe, \
             patch.object(self.panel, "set_record", return_value=("203.0.113.9", "updated")) as cloud:
            self.assertTrue(self.panel.execute_task(task_id))
            self.assertEqual([call.args[0] for call in probe.call_args_list],
                             ["service.example.com", "203.0.113.10", "203.0.113.11"])
            cloud.assert_called_once_with("AK", "SK", "cn-north-4", "home.example.com", "203.0.113.11", "A")
        with self.panel.db() as con:
            log = con.execute("SELECT new_ip,message FROM logs WHERE task_id=? ORDER BY id DESC", (task_id,)).fetchone()
            self.assertEqual(log["new_ip"], "203.0.113.11")
            self.assertIn("已选择可连接的备用目标 203.0.113.11", log["message"])
        with patch.object(self.panel, "tcp_reachable", side_effect=[(False, "down")] * 4) as probe, \
             patch.object(self.panel, "set_record") as cloud:
            self.assertFalse(self.panel.execute_task(task_id, manual=True))
            self.assertEqual(probe.call_count, 4)
            cloud.assert_not_called()
        with self.panel.db() as con:
            log = con.execute("SELECT new_ip,result,message FROM logs WHERE task_id=? ORDER BY id DESC", (task_id,)).fetchone()
            self.assertEqual((log["new_ip"], log["result"]), ("—", "error"))
            self.assertIn("全部备用目标均不通，未修改解析", log["message"])

    def test_probe_targets_validation_and_modal_forms(self):
        ajax = {"X-Requested-With": "XMLHttpRequest"}
        self.assertIn('name="targets"', self.client.get("/tasks/probe/new", headers=ajax).get_data(as_text=True))
        base = {"csrf": self.csrf, "probe_domain": "service.example.com", "probe_port": "443",
                "domain": "home.example.com", "record_type": "A", "interval_minutes": "5"}
        for targets in ("", "not-an-ip", "203.0.113.10\n203.0.113.10",
                        "\n".join(f"203.0.113.{number}" for number in range(10, 21))):
            response = self.client.post("/tasks/probe/new", data={**base, "targets": targets}, headers=ajax)
            self.assertEqual(response.status_code, 422)
            self.assertIn('role="alert"', response.get_data(as_text=True))
        response = self.client.post("/tasks/probe/new", data={**base,
            "targets": "203.0.113.10\n203.0.113.11"}, headers=ajax)
        self.assertEqual(response.json["redirect"], "/")
        with self.panel.db() as con:
            task_id = con.execute("SELECT id FROM tasks").fetchone()[0]
        edit = self.client.get(f"/tasks/{task_id}/edit", headers=ajax).get_data(as_text=True)
        self.assertIn("203.0.113.10\n203.0.113.11", edit)
        response = self.client.post(f"/tasks/{task_id}/edit", data={**base,
            "targets": "203.0.113.11\n203.0.113.10"}, headers=ajax)
        self.assertEqual(response.json["redirect"], "/")
        with self.panel.db() as con:
            task = con.execute("SELECT ip,probe_targets FROM tasks WHERE id=?", (task_id,)).fetchone()
            self.assertEqual(tuple(task), ("203.0.113.11", "203.0.113.11\n203.0.113.10"))
        scheduled = self.client.get("/tasks/new", headers=ajax).get_data(as_text=True)
        self.assertIn('name="run_at"', scheduled)
        self.assertNotIn('name="targets"', scheduled)

    def test_scheduled_task_modal_create_edit_and_validation(self):
        ajax = {"X-Requested-With": "XMLHttpRequest"}
        future = (datetime.now(self.panel.TZ) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M")
        form = {"csrf": self.csrf, "domain": "home.example.com", "record_type": "A",
                "ip": "203.0.113.10", "schedule": "once", "run_at": future}
        invalid = self.client.post("/tasks/new", data={**form, "ip": "invalid"}, headers=ajax)
        self.assertEqual(invalid.status_code, 422)
        self.assertIn('role="alert"', invalid.get_data(as_text=True))
        created = self.client.post("/tasks/new", data=form, headers=ajax)
        self.assertEqual(created.json["redirect"], "/")
        with self.panel.db() as con:
            task_id = con.execute("SELECT id FROM tasks").fetchone()[0]
        edit = self.client.get(f"/tasks/{task_id}/edit", headers=ajax).get_data(as_text=True)
        self.assertIn("home.example.com", edit)
        changed = self.client.post(f"/tasks/{task_id}/edit", data={**form,
            "ip": "203.0.113.11"}, headers=ajax)
        self.assertEqual(changed.json["redirect"], "/")
        with self.panel.db() as con:
            self.assertEqual(con.execute("SELECT ip FROM tasks WHERE id=?", (task_id,)).fetchone()[0],
                             "203.0.113.11")

    def test_pause_stops_automatic_run(self):
        future = (datetime.now(self.panel.TZ) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M")
        self.client.post("/tasks/new", data={"csrf": self.csrf, "domain": "home.example.com",
            "ip": "203.0.113.10", "record_type": "A", "schedule": "daily", "run_at": future})
        with self.panel.db() as con:
            task_id = con.execute("SELECT id FROM tasks").fetchone()[0]
            con.execute("UPDATE tasks SET next_run_at='2020-01-01T00:00:00+00:00' WHERE id=?", (task_id,))
        self.assertEqual(self.client.post(f"/tasks/{task_id}/toggle", data={"csrf": self.csrf}).status_code, 302)
        with patch.object(self.panel, "set_record") as cloud:
            self.assertFalse(self.panel.execute_task(task_id))
            cloud.assert_not_called()
        with self.panel.db() as con:
            self.assertEqual(con.execute("SELECT enabled FROM tasks WHERE id=?", (task_id,)).fetchone()[0], 0)
        self.client.post(f"/tasks/{task_id}/toggle", data={"csrf": self.csrf})
        with self.panel.db() as con:
            self.assertEqual(con.execute("SELECT enabled FROM tasks WHERE id=?", (task_id,)).fetchone()[0], 1)

    def test_existing_database_migrates(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "legacy.sqlite3")
            con = sqlite3.connect(path)
            con.execute("""CREATE TABLE tasks (id INTEGER PRIMARY KEY, domain TEXT NOT NULL,
                ip TEXT NOT NULL, schedule TEXT NOT NULL, run_at TEXT NOT NULL,
                next_run_at TEXT, status TEXT NOT NULL, last_run_at TEXT, created_at TEXT NOT NULL)""")
            con.execute("INSERT INTO tasks VALUES (1,'v6.example.com','2001:db8::1','daily',?,?, 'pending',NULL,?)",
                        (self.panel.utcnow(), self.panel.utcnow(), self.panel.utcnow()))
            con.commit()
            con.close()
            with patch.object(self.panel, "DB", path):
                self.panel.init_db()
                with self.panel.db() as upgraded:
                    row = upgraded.execute("SELECT kind,record_type,enabled,last_probe_reachable FROM tasks WHERE id=1").fetchone()
                    self.assertEqual(tuple(row), ("scheduled", "AAAA", 1, None))
                    upgraded.execute("INSERT INTO tasks (domain,ip,schedule,run_at,next_run_at,created_at,status,kind,probe_domain,probe_port,interval_minutes) VALUES (?,?,?,?,?,?,'pending','probe',?,?,?)",
                        ("home.example.com", "203.0.113.10", "daily", self.panel.utcnow(),
                         self.panel.utcnow(), self.panel.utcnow(), "service.example.com", 443, 5))
                self.panel.init_db()
                with self.panel.db() as upgraded:
                    self.assertEqual(upgraded.execute("SELECT probe_targets FROM tasks WHERE kind='probe'").fetchone()[0],
                                     "203.0.113.10")


if __name__ == "__main__":
    unittest.main()
