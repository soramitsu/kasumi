"""Exercise package provenance, service drains and semantic replay with stand-in binaries."""
import json
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest

import domain_run
import release_gate
import repeatable_assembly as owned
import run_package_smoke as smoke
from test_domain_runs import TARGET
from test_oci_image import ImageFixture


# The package owns the two loopback listeners. The test controller never serves
# requests or manufactures a daemon receipt on their behalf.
PRODUCT = r'''
from pathlib import Path
import http.server, json, shutil, signal, socket, ssl, sys, threading
args = sys.argv[1:]
if args[0] == "init":
    root = Path(args[3])
    root.mkdir()
    (root / "profiles").mkdir()
    for name in ("key.pem", "leaf.pem"):
        shutil.copyfile(IDENTITY / name, root / name)
    network = json.loads(Path(args[args.index("--network") + 1]).read_text())
    (root / "kasumi.json").write_text(json.dumps({
        "mcp": {"tls": {"certificate": str(root / "leaf.pem")}}, "network": network}))
    (root / "token").write_text("private-package-probe-token")
    (root / "profiles/mcp.json").write_text(json.dumps({
        "mcp_endpoint": network["mcp_public_url"], "server_ca": str(root / "leaf.pem"),
        "bearer_file": str(root / "token"), "identity": {"certificate": str(root / "leaf.pem"),
                                                        "private_key": str(root / "key.pem")}}))
elif args[0] == "serve":
    config = Path(args[1])
    root = config.parent
    port = int(json.loads(config.read_text())["network"]["mcp_listen"].split(":")[-1])
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["content-length"])))
            if self.headers["Authorization"] != "Bearer private-package-probe-token":
                self.send_error(403)
                return
            reply = json.dumps({"jsonrpc":"2.0", "id":request["id"],
                                "result":{"tools":[{"name":"kasumi_get"}]}}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(root / "leaf.pem", root / "key.pem")
    ctx.load_verify_locations(root / "leaf.pem")
    ctx.verify_mode = ssl.CERT_REQUIRED
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    tcp = socket.socket()
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("127.0.0.1", port + 1))
    tcp.listen()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    server.serve_forever(.02)
elif args[-1] == "collections":
    root = Path(args[1]).parents[1]
    port = int(json.loads((root / "kasumi.json").read_text())["network"]["native_listen"].split(":")[-1])
    with socket.create_connection(("127.0.0.1", port), timeout=2): pass
    print(json.dumps({"ok":True, "result":{"collections":[]}}))
else:
    sys.exit(2)
'''


@unittest.skipUnless(shutil.which("openssl"), "package MCP probe needs a generated TLS identity")
class PackageSmokeTests(ImageFixture):
    def setUp(self):
        super().setUp()
        tls = self.root / "tls"
        tls.mkdir()
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                        "-keyout", str(tls / "key.pem"), "-out", str(tls / "leaf.pem"),
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                       check=True, capture_output=True)
        for name, (binary, _) in self.binaries.items():
            binary.write_text("#!" + sys.executable + "\nfrom pathlib import Path\nIDENTITY = Path("
                              + repr(str(tls)) + ")\n# " + name + "\n" + PRODUCT)
            self.binaries[name] = binary, release_gate.sha256(binary)
        self.functional["python_executable"] = {"sha256": release_gate.sha256(sys.executable)}
        (self.evidence / "evidence.json").write_text(json.dumps(self.functional))
        self.package = self.pack("smoke-package")

    def run_package(self, attempt):
        for _ in range(32):
            # The package binds after unpack and init. Keep its listeners out
            # of the OS ephemeral client-port pool during that interval.
            port = 18000 + secrets.randbelow(12000)
            with socket.socket() as first, socket.socket() as second, socket.socket() as third:
                try:
                    for offset, listener in enumerate((first, second, third)):
                        listener.bind(("127.0.0.1", port + offset))
                except OSError:
                    continue
                break
        else:
            self.fail("could not reserve adjacent loopback ports for the package test")
        output = self.root / "runs" / attempt
        output.parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory() as private:
            params = {"package": str(self.package), "package_sha256": release_gate.sha256(self.package),
                      "private_root": str(Path(private).resolve()), "base_port": port,
                      "python": str(Path(sys.executable).resolve())}
            with domain_run.Run(smoke.KIND, smoke.RUNNER, smoke.MODULES, self.evidence, output,
                                self.root, attempt, params, domain_run.QUALIFYING) as run:
                smoke.execute(run, params)
        return output

    def test_package_restart_and_semantic_receipts(self):
        custody = self.run_package("package-1")
        key = "package:" + TARGET
        delivered = {key: {"id": key, "file": owned.ref(self.root, self.package)}}
        candidates = {TARGET: {"primary": {"functional": owned.ref(self.root, self.evidence / "evidence.json")}}}

        def accept():
            record, identity, configs = self.gate(custody,
                {"report": owned.ref(self.root, custody / "report.json")},
                {key: delivered[key]["file"]["sha256"]})
            return self.accept(record, identity, configs, delivered, candidates)

        self.assertEqual(accept(), ("package-smoke", "runs/package-1/outcome.json"))
        self.assertFalse(any(p.name in ("key.pem", "token") for p in custody.rglob("*")))
        alternate = self.pack("changed-package")
        delivered[key]["file"] = owned.ref(self.root, alternate)
        with self.assertRaisesRegex(ValueError, "smoked another package"):
            accept()
        delivered[key]["file"] = owned.ref(self.root, self.package)

        def substitute(report):
            by_id = {item["id"]: item for item in report["processes"]}
            by_id["native-2"]["log"] = by_id["native-1"]["log"]
        self.rewrite(custody, substitute)
        with self.assertRaisesRegex(ValueError, "original stdout"):
            accept()

    def test_non_candidate_executable_fails_before_init(self):
        self.package = self.pack("changed-binary", **{"bin/kasumid": (b"wrong", 0o755)})
        with self.assertRaisesRegex(ValueError, "differs from the selected candidate"):
            self.run_package("package-failure")
        output = self.root / "runs/package-failure"
        report = json.loads((output / "report.json").read_text())
        self.assertEqual([item["id"] for item in report["processes"]], ["unpack"])
        self.assertEqual(json.loads((output / "outcome.json").read_text())["status"], "failed")
