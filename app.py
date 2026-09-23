import ipaddress
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from zoneinfo import ZoneInfo

from cryptography.fernet import Fernet
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from waitress import serve

from dns import set_record
from probe import tcp_reachable

DATA = Path(os.environ.get("DATA_DIR", "/data"))
DATA.mkdir(parents=True, exist_ok=True)
DB = DATA / "hwddns.sqlite3"
TZ = ZoneInfo(os.environ.get("TZ", "Asia/Shanghai"))
PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
SECRET = os.environ.get("APP_SECRET", "")
KEY = os.environ.get("DATA_KEY", "")
if not PASSWORD or not SECRET or not KEY:
    raise RuntimeError("请设置 ADMIN_PASSWORD、APP_SECRET 和 DATA_KEY")
FERNET = Fernet(KEY.encode())

app = Flask(__name__)
app.secret_key = SECRET
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
if os.environ.get("COOKIE_SECURE") == "1":
    app.config["SESSION_COOKIE_SECURE"] = True


@contextmanager
def db():
    con = sqlite3.connect(DB, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY CHECK(id=1), ak TEXT NOT NULL,
            sk TEXT NOT NULL, region TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL, ip TEXT NOT NULL,
            schedule TEXT NOT NULL CHECK(schedule IN ('once','daily')),
            run_at TEXT NOT NULL, next_run_at TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            last_run_at TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
            executed_at TEXT NOT NULL, old_ip TEXT,
            new_ip TEXT NOT NULL, result TEXT NOT NULL, message TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_tasks_due ON tasks(next_run_at, status);
        CREATE INDEX IF NOT EXISTS idx_logs_task ON logs(task_id, executed_at DESC);
        """)
        columns = {row["name"] for row in con.execute("PRAGMA table_info(tasks)")}
        additions = {
            "kind": "TEXT NOT NULL DEFAULT 'scheduled'",
            "record_type": "TEXT NOT NULL DEFAULT 'A'",
            "enabled": "INTEGER NOT NULL DEFAULT 1",
            "probe_domain": "TEXT",
            "probe_port": "INTEGER",
            "interval_minutes": "INTEGER",
        }
        for name, definition in additions.items():
            if name not in columns:
                con.execute(f"ALTER TABLE tasks ADD COLUMN {name} {definition}")
        con.execute("UPDATE tasks SET record_type='AAAA' WHERE instr(ip, ':') > 0 AND record_type='A'")
        con.execute("CREATE INDEX IF NOT EXISTS idx_tasks_enabled_due ON tasks(enabled, next_run_at)")
        # A restart may interrupt a cloud request. Rechecking DNS is safe because
        # set_record is idempotent and prevents a task from staying stuck forever.
        con.execute("UPDATE tasks SET status='pending' WHERE status='running'")


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def local_time(value):
    if not value:
        return "—"
    return datetime.fromisoformat(value).astimezone(TZ).strftime("%Y-%m-%d %H:%M")


app.jinja_env.filters["localtime"] = local_time


def login_required(fn):
    @wraps(fn)
    def inner(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return inner


@app.before_request
def csrf_guard():
    if request.method == "POST" and request.endpoint != "login":
        if not session.get("authenticated") or not secrets.compare_digest(
                request.form.get("csrf", ""), session.get("csrf", "")):
            abort(403)


@app.context_processor
def globals_for_template():
    return {"csrf": session.get("csrf", ""), "tz_name": str(TZ)}


@app.get("/health")
def health():
    return "ok"


_login_attempts = {}
_login_lock = threading.Lock()


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        address = request.remote_addr or "unknown"
        now = time.monotonic()
        with _login_lock:
            recent = [t for t in _login_attempts.get(address, []) if now - t < 300]
            if len(recent) >= 10:
                flash("尝试次数过多，请五分钟后再试", "error")
                return render_template("login.html"), 429
            recent.append(now)
            _login_attempts[address] = recent
        if secrets.compare_digest(request.form.get("password", ""), PASSWORD):
            session.clear()
            session["authenticated"] = True
            session["csrf"] = secrets.token_urlsafe(32)
            with _login_lock:
                _login_attempts.pop(address, None)
            return redirect(url_for("index"))
        flash("密码错误", "error")
    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
@login_required
def index():
    with db() as con:
        tasks = con.execute("SELECT * FROM tasks ORDER BY id DESC").fetchall()
        configured = con.execute("SELECT 1 FROM settings WHERE id=1").fetchone() is not None
        recent = con.execute("SELECT l.*, t.domain FROM logs l JOIN tasks t ON t.id=l.task_id ORDER BY l.id DESC LIMIT 8").fetchall()
    return render_template("index.html", tasks=tasks, configured=configured, recent=recent)


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        ak = request.form.get("ak", "").strip()
        sk = request.form.get("sk", "").strip()
        region = request.form.get("region", "cn-north-4").strip()
        if not region or not all(c.isalnum() or c == "-" for c in region):
            flash("区域格式无效", "error")
        else:
            with db() as con:
                old = con.execute("SELECT * FROM settings WHERE id=1").fetchone()
                if not old and (not ak or not sk):
                    flash("首次设置需填写 AK 和 SK", "error")
                else:
                    con.execute("INSERT OR REPLACE INTO settings VALUES (1,?,?,?)", (
                        FERNET.encrypt(ak.encode()).decode() if ak else old["ak"],
                        FERNET.encrypt(sk.encode()).decode() if sk else old["sk"], region))
                    flash("云账号设置已保存", "success")
                    return redirect(url_for("settings"))
    with db() as con:
        row = con.execute("SELECT region FROM settings WHERE id=1").fetchone()
    return render_template("settings.html", region=row["region"] if row else "cn-north-4", configured=bool(row))


def parse_domain(value):
    domain = value.strip().rstrip(".").lower()
    if len(domain) > 253 or not domain or any(
            len(label) > 63 or not label or label[0] == "-" or label[-1] == "-" or
            not all(c.isalnum() or c == "-" for c in label)
            for label in domain.split(".")) or "." not in domain:
        raise ValueError("请输入有效的完整域名，例如 home.example.com")
    return domain


def parse_target(form, domain):
    kind = form.get("record_type", "A").upper()
    if kind not in ("A", "AAAA", "CNAME"):
        raise ValueError("请选择 A、AAAA 或 CNAME 记录")
    raw = form.get("ip", "").strip()
    if kind == "CNAME":
        target = parse_domain(raw)
        if target == domain:
            raise ValueError("CNAME 目标不能与解析域名相同")
    else:
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise ValueError("请输入有效的目标 IP 地址") from exc
        if (kind == "A" and address.version != 4) or (kind == "AAAA" and address.version != 6):
            raise ValueError(f"{kind} 记录的目标地址类型不匹配")
        target = str(address)
    return kind, target


def parse_task(form):
    domain = parse_domain(form.get("domain", ""))
    kind, target = parse_target(form, domain)
    schedule = form.get("schedule", "once")
    if schedule not in ("once", "daily"):
        raise ValueError("执行频率无效")
    try:
        naive = datetime.fromisoformat(form.get("run_at", ""))
        if naive.tzinfo is not None:
            raise ValueError()
        run_at = naive.replace(tzinfo=TZ)
        if run_at <= datetime.now(TZ):
            raise ValueError()
    except ValueError as exc:
        raise ValueError("请选择未来的执行日期和时间") from exc
    return domain, target, kind, schedule, run_at.astimezone(timezone.utc).isoformat(timespec="seconds")


def parse_probe_task(form):
    probe_domain = parse_domain(form.get("probe_domain", ""))
    domain = parse_domain(form.get("domain", "").strip() or probe_domain)
    kind, target = parse_target(form, domain)
    try:
        port = int(form.get("probe_port", ""))
        interval = int(form.get("interval_minutes", ""))
    except ValueError as exc:
        raise ValueError("请输入有效的探测端口和执行间隔") from exc
    if not 1 <= port <= 65535:
        raise ValueError("端口需在 1 到 65535 之间")
    if not 1 <= interval <= 1440:
        raise ValueError("执行间隔需在 1 到 1440 分钟之间")
    return domain, target, kind, probe_domain, port, interval


@app.route("/tasks/new", methods=["GET", "POST"])
@login_required
def new_task():
    if request.method == "POST":
        try:
            domain, target, kind, schedule, run_at = parse_task(request.form)
            with db() as con:
                con.execute("INSERT INTO tasks (domain,ip,record_type,schedule,run_at,next_run_at,created_at) VALUES (?,?,?,?,?,?,?)",
                            (domain, target, kind, schedule, run_at, run_at, utcnow()))
            flash("任务已创建", "success")
            return redirect(url_for("index"))
        except ValueError as exc:
            flash(str(exc), "error")
    return render_template("task_form.html", task=None, kind="scheduled",
                           suggested=datetime.now(TZ).replace(second=0, microsecond=0) + timedelta(hours=1))


@app.route("/tasks/probe/new", methods=["GET", "POST"])
@login_required
def new_probe_task():
    if request.method == "POST":
        try:
            domain, target, kind, probe_domain, port, interval = parse_probe_task(request.form)
            now = utcnow()
            with db() as con:
                con.execute("""INSERT INTO tasks
                    (domain,ip,record_type,schedule,run_at,next_run_at,created_at,kind,probe_domain,probe_port,interval_minutes)
                    VALUES (?,?,?,'daily',?,?,?,'probe',?,?,?)""",
                    (domain, target, kind, now, now, now, probe_domain, port, interval))
            flash("探测任务已创建，将很快开始首次探测", "success")
            return redirect(url_for("index"))
        except ValueError as exc:
            flash(str(exc), "error")
    return render_template("task_form.html", task=None, kind="probe", suggested=None)


@app.route("/tasks/<int:task_id>/edit", methods=["GET", "POST"])
@login_required
def edit_task(task_id):
    with db() as con:
        task = con.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
    if not task:
        abort(404)
    if request.method == "POST":
        try:
            if task["kind"] == "probe":
                domain, target, kind, probe_domain, port, interval = parse_probe_task(request.form)
                next_run = utcnow()
                with db() as con:
                    cur = con.execute("""UPDATE tasks SET domain=?,ip=?,record_type=?,probe_domain=?,probe_port=?,interval_minutes=?,
                        next_run_at=?,status='pending' WHERE id=? AND status!='running'""",
                        (domain, target, kind, probe_domain, port, interval, next_run, task_id))
            else:
                domain, target, kind, schedule, run_at = parse_task(request.form)
                with db() as con:
                    cur = con.execute("""UPDATE tasks SET domain=?,ip=?,record_type=?,schedule=?,run_at=?,next_run_at=?,status='pending'
                        WHERE id=? AND status!='running'""",
                        (domain, target, kind, schedule, run_at, run_at, task_id))
            if not cur.rowcount:
                raise ValueError("任务正在执行，请稍后重试")
            flash("任务已更新", "success")
            return redirect(url_for("index"))
        except ValueError as exc:
            flash(str(exc), "error")
    return render_template("task_form.html", task=task, kind=task["kind"],
                           suggested=datetime.fromisoformat(task["run_at"]).astimezone(TZ) if task["kind"] == "scheduled" else None)


def claim_task(task_id, manual=False):
    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        task = con.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if not task or task["status"] == "running":
            return None
        if not manual and (not task["enabled"] or not task["next_run_at"] or task["next_run_at"] > utcnow()):
            return None
        con.execute("UPDATE tasks SET status='running' WHERE id=?", (task_id,))
        return dict(task)


def execute_task(task_id, manual=False):
    task = claim_task(task_id, manual)
    if not task:
        return False
    old_ip = "—"
    new_value = task["ip"]
    result = "error"
    message = ""
    try:
        if task["kind"] == "probe":
            reachable, detail = tcp_reachable(task["probe_domain"], task["probe_port"])
            if reachable:
                result = "healthy"
                new_value = "—"
                message = f"探测正常：{task['probe_domain']}:{task['probe_port']} 可连接，未修改解析"
            else:
                message = f"探测不通（{detail}）；"
        if result != "healthy":
            with db() as con:
                setting = con.execute("SELECT * FROM settings WHERE id=1").fetchone()
            if not setting:
                raise ValueError("请先设置华为云 AK 和 SK")
            old_ip, action = set_record(FERNET.decrypt(setting["ak"].encode()).decode(),
                                        FERNET.decrypt(setting["sk"].encode()).decode(),
                                        setting["region"], task["domain"], task["ip"], task["record_type"])
            result = "success"
            message += {"created": "已创建解析记录", "updated": "已更新解析记录", "unchanged": "解析值无变化"}[action]
    except Exception as exc:
        # SDK exceptions may contain request metadata. Keep only the short error message.
        message += str(exc)[:500] or type(exc).__name__
    now = utcnow()
    if task["kind"] == "probe":
        candidate = (datetime.fromisoformat(now) + timedelta(minutes=task["interval_minutes"])).isoformat(timespec="seconds")
        next_run = task["next_run_at"] if manual and task["next_run_at"] and task["next_run_at"] > now else candidate
        status = "error" if result == "error" else "pending"
    elif task["schedule"] == "daily":
        next_local = datetime.fromisoformat(task["run_at"]).astimezone(TZ)
        while next_local <= datetime.now(TZ):
            next_local += timedelta(days=1)
        next_run = next_local.astimezone(timezone.utc).isoformat(timespec="seconds")
        status = "pending" if result == "success" else "error"
    else:
        next_run = None if not manual or task["next_run_at"] is None else task["next_run_at"]
        status = "done" if result == "success" else "error"
    with db() as con:
        con.execute("INSERT INTO logs (task_id,executed_at,old_ip,new_ip,result,message) VALUES (?,?,?,?,?,?)",
                    (task_id, now, old_ip, new_value, result, message))
        con.execute("UPDATE tasks SET next_run_at=?,status=?,last_run_at=? WHERE id=?",
                    (next_run, status, now, task_id))
    return result in ("success", "healthy")


@app.post("/tasks/<int:task_id>/run")
@login_required
def run_task(task_id):
    with db() as con:
        if not con.execute("SELECT 1 FROM tasks WHERE id=?", (task_id,)).fetchone():
            abort(404)
    ok = execute_task(task_id, manual=True)
    flash("执行成功" if ok else "执行失败或任务正在执行，请查看日志", "success" if ok else "error")
    return redirect(url_for("task_logs", task_id=task_id))


@app.post("/tasks/<int:task_id>/toggle")
@login_required
def toggle_task(task_id):
    with db() as con:
        cur = con.execute("UPDATE tasks SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id=?", (task_id,))
    if not cur.rowcount:
        abort(404)
    flash("任务状态已更新", "success")
    return redirect(url_for("index"))


@app.post("/tasks/<int:task_id>/delete")
@login_required
def delete_task(task_id):
    with db() as con:
        cur = con.execute("DELETE FROM tasks WHERE id=? AND status!='running'", (task_id,))
    flash("任务和日志已删除" if cur.rowcount else "任务不存在或正在执行", "success" if cur.rowcount else "error")
    return redirect(url_for("index"))


@app.get("/tasks/<int:task_id>/logs")
@login_required
def task_logs(task_id):
    with db() as con:
        task = con.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if not task:
            abort(404)
        logs = con.execute("SELECT * FROM logs WHERE task_id=? ORDER BY id DESC LIMIT 200", (task_id,)).fetchall()
    return render_template("logs.html", task=task, logs=logs)


def scheduler_loop():
    while True:
        try:
            with db() as con:
                due = con.execute("SELECT id FROM tasks WHERE enabled=1 AND next_run_at <= ? AND status!='running' ORDER BY next_run_at LIMIT 20", (utcnow(),)).fetchall()
            for row in due:
                execute_task(row["id"])
        except Exception:
            app.logger.exception("Scheduler error")
        time.sleep(10)


init_db()
if __name__ == "__main__":
    threading.Thread(target=scheduler_loop, daemon=True).start()
    serve(app, host="0.0.0.0", port=6006, threads=8)
