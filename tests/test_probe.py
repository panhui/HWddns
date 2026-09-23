import socket
import unittest

from probe import tcp_reachable


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


if __name__ == "__main__":
    unittest.main()
