"""Exercise the network cut on real, separately owned client sockets."""
import asyncio
import contextlib
import errno
from pathlib import Path
import socketserver
import subprocess
import sys
import threading
import unittest
from unittest.mock import Mock

from ha_peer_links import Links, copy_stream, routes


CLIENT = """
import socket, sys
links = {}
for line in sys.stdin:
    op, key, port = line.split()
    try:
        if op == "connect":
            links[key] = socket.create_connection(("127.0.0.1", int(port)), timeout=3)
        s = links[key]
        s.sendall(b"x")
        print(s.recv(1).decode() or "closed", flush=True)
    except (ConnectionError, TimeoutError):
        print("closed", flush=True)
"""


class Echo(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            while self.rfile.read(1):
                self.wfile.write(str(self.server.node).encode())
        except ConnectionError:
            return


class HalfCloseTests(unittest.IsolatedAsyncioTestCase):
    async def test_disconnected_half_close_preserves_other_socket_errors(self):
        reader = asyncio.StreamReader()
        reader.feed_eof()
        writer = Mock(spec=asyncio.StreamWriter)
        writer.can_write_eof.return_value = True
        writer.write_eof.side_effect = OSError(errno.ENOTCONN, "disconnected")
        await copy_stream(reader, writer)
        writer.write_eof.assert_called_once()
        failure = OSError(errno.EIO, "I/O failure")
        writer.write_eof.side_effect = failure
        with self.assertRaises(OSError) as caught:
            await copy_stream(reader, writer)
        self.assertIs(caught.exception, failure)


class PeerLinksTests(unittest.TestCase):
    def test_advertised_endpoints_and_installed_listeners_are_distinct(self):
        nodes = [{"role": "data", "id": f"data-{n}", "node_id": n} for n in range(1, 4)]
        roster = [{"node_id": n, "endpoint": f"https://localhost:{8000+n}"} for n in range(1, 4)]
        configs = {n["id"]: {"replication": {"peers": roster, "listener": {
            "listen": f"0.0.0.0:{9000+n['node_id']}"}}} for n in nodes}
        self.assertEqual(routes(nodes, configs)[1], (("localhost", 8001), ("127.0.0.1", 9001)))
        roster[0]["endpoint"] = "https://127.0.0.1:9002"
        with self.assertRaisesRegex(ValueError, "separate"):
            routes(nodes, configs)

    @unittest.skipUnless(Path("/proc/self/net/tcp").is_file(), "Linux socket ownership witness")
    def test_cut_breaks_existing_and_new_minority_links_and_preserves_the_majority(self):
        with contextlib.ExitStack() as stack:
            endpoints, clients = {}, {}
            for node in (1, 2, 3):
                server = stack.enter_context(socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo))
                server.node = node
                backend = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .02})
                backend.start()
                stack.callback(backend.join)
                stack.callback(server.shutdown)
                endpoints[node] = (("127.0.0.1", 0), server.server_address)
                client = stack.enter_context(subprocess.Popen(
                    [sys.executable, "-I", "-S", "-u", "-c", CLIENT], stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, text=True))
                stack.callback(client.stdin.close)
                clients[node] = client
            links = stack.enter_context(Links(endpoints))
            ports = {n: server.sockets[0].getsockname()[1] for n, server in zip(endpoints, links.servers)}

            def send(src, dst, command):
                client = clients[src]
                client.stdin.write(f"{command} {dst} {ports[dst]}\n")
                client.stdin.flush()
                return client.stdout.readline().strip()

            for src, dst in ((1, 2), (1, 3), (2, 1), (2, 3)):
                self.assertEqual(send(src, dst, "connect"), str(dst))
            closed = links.call(links.cut(1, {n: c.pid for n, c in clients.items()}))
            self.assertEqual(closed, 3)
            self.assertEqual(send(2, 3, "ping"), "3")
            for src, dst in ((1, 2), (1, 3), (2, 1)):
                self.assertEqual(send(src, dst, "ping"), "closed")
                self.assertEqual(send(src, dst, "connect"), "closed")
            self.assertEqual(send(3, 2, "connect"), "2")
            result = links.call(links.heal())
            self.assertEqual(result["unidentified"], 0)
            self.assertEqual([(r["source"], r["target"], r["count"]) for r in result["rejected"]],
                             [(1, 2, 2), (1, 3, 2), (2, 1, 2)])
            self.assertEqual(send(2, 3, "ping"), "3")
            for src, dst in ((1, 2), (1, 3), (2, 1)):
                self.assertEqual(send(src, dst, "connect"), str(dst))


if __name__ == "__main__":
    unittest.main()
