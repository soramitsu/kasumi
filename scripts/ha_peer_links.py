"""Opaque TCP links between the installed Data peer endpoints and their TLS listeners."""
import asyncio
import errno
import ipaddress
import os
from pathlib import Path
import sys
import threading
from urllib.parse import urlsplit

from domain_run import require


def socket_address(value):
    uri = urlsplit("//" + value)
    require(uri.hostname and uri.port and not uri.path and not uri.username
            and not uri.password and not uri.query and not uri.fragment, "invalid peer listener")
    return str(ipaddress.ip_address(uri.hostname)), uri.port


def routes(nodes, configs):
    links = {}
    for node in nodes:
        if node["role"] != "data":
            continue
        config = configs[node["id"]]["replication"]
        peer = next(row for row in config["peers"] if row["node_id"] == node["node_id"])
        url = urlsplit(peer["endpoint"])
        require(url.scheme == "https" and url.hostname and not url.username and not url.password
                and url.path in ("", "/") and not url.query and not url.fragment,
                "invalid advertised peer endpoint")
        front = (url.hostname, url.port or 443)
        backend = socket_address(config["listener"]["listen"])
        if backend[0] in ("::", "0.0.0.0"):
            backend = ("::1" if backend[0] == "::" else "127.0.0.1", backend[1])
        links[node["node_id"]] = (front, backend)
    fronts = {front for front, _ in links.values()}
    require(len(links) == len(fronts) == 3 and fronts.isdisjoint(back for _, back in links.values()),
            "the three advertised Data peer endpoints must be separate from their installed TLS listeners")
    return links


def proc_address(value):
    host, port = value.split(":")
    raw = bytes.fromhex(host)
    if sys.byteorder == "little":
        raw = b"".join(raw[i:i+4][::-1] for i in range(0, len(raw), 4))
    addr = ipaddress.ip_address(raw)
    return str(getattr(addr, "ipv4_mapped", None) or addr), int(port, 16)


def address(value):
    addr = ipaddress.ip_address(value[0])
    return str(getattr(addr, "ipv4_mapped", None) or addr), value[1]


def socket_owner(client, listener, pids):
    """Match the connecting socket's four-tuple to an FD of an owned process."""
    for family in ("tcp", "tcp6"):
        table = Path("/proc/self/net", family)
        if not table.is_file():
            continue
        with table.open() as rows:
            next(rows)
            for row in rows:
                fields = row.split()
                if (fields[3] == "01" and int(fields[1].rsplit(":", 1)[1], 16) == client[1]
                        and proc_address(fields[1]) == client
                        and proc_address(fields[2]) == listener):
                    inode = "socket:[" + fields[9] + "]"
                    for node, pid in pids.items():
                        for fd in Path("/proc", str(pid), "fd").iterdir():
                            try:
                                if os.readlink(fd) == inode:
                                    return node
                            except FileNotFoundError:
                                continue
                    return None
    return None


async def copy_stream(reader, writer):
    while block := await reader.read(65536):
        writer.write(block)
        await writer.drain()
    if writer.can_write_eof():
        try:
            writer.write_eof()
        except OSError as error:
            # A peer can disconnect between the final read and shutdown(SHUT_WR).
            if error.errno != errno.ENOTCONN:
                raise


class Links:
    """Own all relay sockets and apply a cut on their event loop before acknowledging it."""

    def __init__(self, endpoints):
        self.endpoints = endpoints
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, name="kasumi-peer-links")
        self.error = None
        self.servers = []
        self.active = {}
        self.isolated = None
        self.pids = {}
        self.blocked = {}
        self.unidentified = 0
        self.open_limit = 256

    def call(self, command):
        return asyncio.run_coroutine_threadsafe(command, self.loop).result()

    def __enter__(self):
        self.thread.start()
        try:
            self.call(self.start())
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, *_):
        try:
            self.call(self.stop())
        finally:
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join()
            self.loop.close()

    async def start(self):
        backends = {(str(ipaddress.ip_address(host)), port) for _, (host, port) in self.endpoints.values()}
        for node, (front, _) in self.endpoints.items():
            server = await asyncio.start_server(
                lambda r, w, n=node: self.accept(n, r, w), *front)
            self.servers.append(server)
            require(all(address(sock.getsockname()) not in backends for sock in server.sockets),
                    "advertised Data address resolves to an installed listener")

    def accept(self, node, reader, writer):
        if len(self.active) >= self.open_limit:
            writer.close()
            self.error = RuntimeError("peer relay connection limit reached")
            return
        task = self.loop.create_task(self.forward(node, reader, writer))
        self.active[task] = node, writer

        def done(finished):
            writer.close()
            self.active.pop(finished, None)
            if not finished.cancelled():
                error = finished.exception()
                if error is not None:
                    self.error = error

        task.add_done_callback(done)

    def blocked_link(self, node, writer):
        if self.isolated is None:
            return False
        src = socket_owner(address(writer.get_extra_info("peername")),
                           address(writer.get_extra_info("sockname")), self.pids)
        if src is None:
            self.unidentified += 1
            return True
        if self.isolated in (src, node) and src in self.endpoints and src != node:
            pair = (src, node)
            self.blocked[pair] = self.blocked.get(pair, 0) + 1
            return True
        return False

    async def forward(self, node, reader, writer):
        upstream = None
        pumps = []
        try:
            if self.blocked_link(node, writer):
                return
            remote, upstream = await asyncio.open_connection(*self.endpoints[node][1])
            pumps = [asyncio.create_task(copy_stream(reader, upstream)),
                     asyncio.create_task(copy_stream(remote, writer))]
            await asyncio.gather(*pumps)
        except (ConnectionError, TimeoutError):
            pass
        finally:
            for pump in pumps:
                pump.cancel()
            writer.close()
            if upstream is not None:
                upstream.close()
            if pumps:
                await asyncio.gather(*pumps, return_exceptions=True)

    async def cut(self, isolated, pids):
        require(self.isolated is None and isolated in self.endpoints
                and self.endpoints.keys() <= pids.keys(), "invalid peer cut")
        require(Path("/proc/self/net/tcp").is_file(), "peer attribution requires native Linux procfs")
        self.isolated, self.pids = isolated, pids.copy()
        # Inspect both pooled HTTP/2 streams and new connections. An existing
        # connection between the two majority members keeps its original socket.
        previous = [task for task, (node, writer) in self.active.items()
                    if not writer.is_closing() and self.blocked_link(node, writer)]
        for task in previous:
            self.active[task][1].close()
            task.cancel()
        await asyncio.gather(*previous, return_exceptions=True)
        return len(previous)

    async def heal(self):
        require(self.isolated is not None, "no active peer cut")
        self.isolated = None
        return {"rejected": [{"source": a, "target": b, "count": count}
                             for (a, b), count in sorted(self.blocked.items())],
                "unidentified": self.unidentified}

    async def stop(self):
        for server in self.servers:
            server.close()
        tasks = list(self.active)
        for task in tasks:
            self.active[task][1].close()
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for server in self.servers:
            await server.wait_closed()
        if self.error is not None:
            raise RuntimeError("peer link failed") from self.error
