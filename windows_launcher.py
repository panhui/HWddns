"""Windows desktop launcher for the bundled local HWddns server."""

import os
import queue
import secrets
import socket
import sys
import tempfile
import threading
import time
import tkinter as tk
import traceback
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path
from tkinter import messagebox

from cryptography.fernet import Fernet


def config_path():
    local = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    return local / "HWddns" / "config.env"


def configure():
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    defaults = {
        "ADMIN_PASSWORD": "Qwer1234",
        "APP_SECRET": secrets.token_urlsafe(48),
        "DATA_KEY": Fernet.generate_key().decode(),
        "TZ": "Asia/Shanghai",
        "PORT": "6006",
    }
    try:
        with path.open("x", encoding="utf-8") as out:
            for key, value in defaults.items():
                out.write(f"{key}={value}\n")
    except FileExistsError:
        pass
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key in defaults:
            values[key] = value.strip()
    for key in ("ADMIN_PASSWORD", "APP_SECRET", "DATA_KEY"):
        if not values.get(key):
            raise ValueError(f"配置文件缺少 {key}: {path}")
    for key, value in values.items():
        os.environ[key] = value
    data = path.parent / "data"
    data.mkdir(exist_ok=True)
    os.environ["DATA_DIR"] = str(data)
    port = int(values.get("PORT", "6006"))
    if not 1 <= port <= 65535:
        raise ValueError("PORT 必须在 1 到 65535 之间")
    return path, port


def is_running(port):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=0.3) as response:
            return response.read(64) == b"HWddns ok"
    except (OSError, urllib.error.URLError):
        return False


def self_test():
    configure()
    import app
    client = app.app.test_client()
    assert client.get("/health").data == b"HWddns ok"
    assert client.post("/login", data={"password": os.environ["ADMIN_PASSWORD"]}).status_code == 302
    with client.session_transaction() as user_session:
        user_session["authenticated"] = True
        user_session["csrf"] = "test"
    assert client.get("/").status_code == 200
    assert client.get("/tasks/probe/new").status_code == 200
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    errors = queue.Queue()

    def run_backend():
        try:
            app.start_server(host="127.0.0.1", port=port)
        except Exception:
            errors.put(traceback.format_exc())

    threading.Thread(target=run_backend, daemon=True).start()
    for _ in range(50):
        if not errors.empty():
            raise RuntimeError(errors.get_nowait())
        if is_running(port):
            return
        time.sleep(0.2)
    raise RuntimeError("服务未在 10 秒内启动")


def main():
    if "--self-test" in sys.argv:
        try:
            self_test()
        except Exception as exc:
            error = Path(tempfile.gettempdir()) / "hwddns-self-test-error.txt"
            error.write_text(traceback.format_exc(), encoding="utf-8")
            raise SystemExit(1) from exc
        return
    try:
        path, port = configure()
    except Exception as exc:
        messagebox.showerror("HWddns 启动失败", str(exc))
        return
    url = f"http://127.0.0.1:{port}"
    if is_running(port):
        webbrowser.open(url)
        messagebox.showinfo("HWddns", "面板已经在运行，已在浏览器中打开。")
        return

    root = tk.Tk()
    root.title("HWddns · 华为云解析管理")
    root.geometry("410x230")
    root.resizable(False, False)
    root.configure(bg="#f5f7fb")
    tk.Label(root, text="HWddns", font=("Microsoft YaHei UI", 22, "bold"),
             fg="#ed3045", bg="#f5f7fb").pack(pady=(25, 7))
    status = tk.StringVar(value="正在启动本地面板…")
    tk.Label(root, textvariable=status, font=("Microsoft YaHei UI", 11),
             fg="#344054", bg="#f5f7fb").pack()
    tk.Label(root, text=f"{url}  ·  首次密码 Qwer1234", font=("Microsoft YaHei UI", 9),
             fg="#68778a", bg="#f5f7fb").pack(pady=(8, 15))
    tk.Button(root, text="打开管理面板", command=lambda: webbrowser.open(url),
              font=("Microsoft YaHei UI", 10), padx=14, pady=5).pack()
    tk.Label(root, text="保持此窗口打开，定时任务才会继续运行。", font=("Microsoft YaHei UI", 9),
             fg="#8994a3", bg="#f5f7fb").pack(pady=(14, 0))

    errors = queue.Queue()

    def run_backend():
        try:
            import app
            app.start_server(host="127.0.0.1", port=port)
        except Exception as exc:
            log_path = path.parent / "startup-error.log"
            log_path.write_text(traceback.format_exc(), encoding="utf-8")
            errors.put(f"{exc}\n详细信息：{log_path}")

    threading.Thread(target=run_backend, daemon=True).start()
    attempts = 0

    def check_startup():
        nonlocal attempts
        if not errors.empty():
            messagebox.showerror("HWddns 启动失败", errors.get_nowait())
            root.destroy()
            return
        if is_running(port):
            status.set("面板正在运行")
            webbrowser.open(url)
            return
        attempts += 1
        if attempts >= 50:
            messagebox.showerror("HWddns 启动失败", f"无法启动本地面板。配置文件：{path}")
            root.destroy()
            return
        root.after(200, check_startup)

    root.after(200, check_startup)
    root.mainloop()


if __name__ == "__main__":
    main()
