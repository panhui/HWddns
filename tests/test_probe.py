import socket
import unittest

from probe import scan_tcp_ports, tcp_reachable


class ProbeTests(unittest.TestCase):
    def test_tcp_port_reachability(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        try:
            reachable, _ = tcp_reachable("127.0.0.1", port, attempts=1, timeout=0.5)
            self.assertTrue(reachable)
        finally:
            server.close()
        unreachable, _ = tcp_reachable("127.0.0.1", port, attempts=1, timeout=0.5)
        self.assertFalse(unreachable)

    def test_tcp_port_range_results_stay_in_order(self):
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(2)
            port = server.getsockname()[1]
            start = port - 1 if port > 1 else port
            results = scan_tcp_ports("127.0.0.1", start, port)
            self.assertEqual([item[0] for item in results], list(range(start, port + 1)))
            self.assertTrue(results[-1][1])


if __name__ == "__main__":
    unittest.main()
