"""TCP reachability check from the machine running the panel."""

import socket
import time


def tcp_reachable(host, port, attempts=2, timeout=3):
    last_error = ""
    for attempt in range(attempts):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True, "TCP 连接成功"
        except OSError as exc:
            last_error = str(exc)[:160]
            if attempt + 1 < attempts:
                time.sleep(1)
    return False, last_error or "TCP 连接失败"
