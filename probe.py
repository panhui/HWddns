"""TCP reachability check from the machine running the panel."""

import socket
import time
from concurrent.futures import ThreadPoolExecutor


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


def scan_tcp_ports(host, start_port, end_port):
    """Check a bounded port range concurrently, returning results in port order."""
    ports = range(start_port, end_port + 1)
    with ThreadPoolExecutor(max_workers=min(16, len(ports))) as executor:
        checks = executor.map(lambda port: tcp_reachable(host, port, attempts=1, timeout=1), ports)
        return [(port, reachable, detail) for port, (reachable, detail) in zip(ports, checks)]
