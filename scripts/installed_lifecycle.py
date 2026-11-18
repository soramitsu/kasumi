"""Private-installation probes that publish only public identities and verified observations."""

import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import ssl
import time
from urllib.parse import urlsplit

from domain_run import require
import gate_process
import process_ha_topology as topology
import repeatable_assembly as owned


def read(path):
    return owned.read(Path(path))


def token(profile):
    p = read(profile)
    raw = Path(p["bearer_file"]).read_bytes().strip()
    parts = raw.split(b".")
    require(len(parts) == 3, "invalid compact credential")
    header, claims = [
        json.loads(base64.urlsafe_b64decode(v + b"=" * (-len(v) % 4)))
        for v in parts[:2]
    ]
    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "kid": header.get("kid"),
        "sub": claims.get("sub"),
        "iat": claims.get("iat"),
        "exp": claims.get("exp"),
        "cnf": claims.get("cnf"),
        "family_id": claims.get("kasumi_family"),
        "tenant": claims.get("tenant"),
        "resource": claims.get("kasumi_resource"),
        "principal": p["principal"],
        "client_thumbprint": base64.urlsafe_b64encode(
            bytes.fromhex(
                topology.certificate(p["identity"]["certificate"])["leaf_sha256"]
            )
        )
        .decode()
        .rstrip("="),
    }


def snapshot(root):
    root = Path(root)
    c = read(root / "kasumi.json")
    tenants = c["tenants"]
    require(
        c["mode"] == "standalone"
        and len(tenants) == 1
        and not c.get("replication")
        and not c["serving_authorities"],
        "fixture substitution or external serving provider",
    )
    t = tenants[0]
    rings = {}
    for name, provider in (
        ("application", t["keys"]),
        ("custody", t["custody_keys"]),
        ("control", c["control"]["keys"]),
        ("control-custody", c["control"]["custody_keys"]),
        ("security", c["security_audit"]["keys"]),
    ):
        require(
            provider["kind"] == "file",
            "standalone offline installation reached an external provider",
        )
        ring = read(provider["path"])
        rings[name] = {
            "id": ring["id"],
            "active": ring["active"],
            "generations": sorted(map(int, ring["versions"])),
        }
    profiles = {
        k: read(root / "profiles" / (k + ".json"))
        for k in ("default", "operator", "mcp", "control")
    }
    return {
        "mode": c["mode"],
        "tenant": t["tenant"],
        "initial_incarnation": t["incarnation"],
        "serving": t["serving"],
        "source_keys": t["keys"],
        "rings": rings,
        "tls": {
            k: topology.certificate(c[k]["tls"]["certificate"])["leaf_sha256"]
            for k in ("mcp", "native", "admin")
        },
        "profiles": profiles,
        "policy": t["initial_policy"],
        "limits": t["initial_limits"],
        "auth_kind": c["auth"]["source"]["kind"],
    }


def request(root, method, path):
    root = Path(root)
    p = read(root / "profiles/mcp.json")
    url = urlsplit(p["mcp_endpoint"])
    require(
        url.scheme == "https" and url.hostname == "localhost" and url.port,
        "MCP endpoint is not the new loopback installation",
    )
    context = ssl.create_default_context(cafile=p["server_ca"])
    con = http.client.HTTPSConnection(
        url.hostname, url.port, context=context, timeout=15
    )
    try:
        con.connect()
        cert = hashlib.sha256(con.sock.getpeercert(binary_form=True)).hexdigest()
        con.request(
            method,
            path,
            body=b"{}" if method == "POST" else None,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
        response = con.getresponse()
        body = response.read(65537)
        require(len(body) <= 65536, "unbounded local discovery response")
        return {
            "metadata": json.loads(body)
            if response.status == 200 and path.startswith("/.well-known/")
            else None,
            "status": response.status,
            "challenge": response.getheader("WWW-Authenticate"),
            "leaf_sha256": cert,
            "body_sha256": hashlib.sha256(body).hexdigest(),
        }
    finally:
        con.close()


def discovery(root):
    return {
        p: request(root, "POST" if p == "/mcp" else "GET", p)
        for p in (
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
            "/mcp",
        )
    }


def replace(path, data):
    tmp = path.with_name(path.name + ".release-probe-pending")
    with tmp.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)


def invalid_tls(root, receipt, log):
    root = Path(root)
    receipt = Path(receipt)
    log = Path(log)
    c = read(root / "kasumi.json")
    role = Path(c["mcp"]["tls"]["certificate"])
    require(
        role.is_relative_to(root) and not role.is_symlink(),
        "TLS probe scope differs from its new private installation",
    )
    original = role.read_bytes()
    pin = topology.certificate(role)["leaf_sha256"]
    r = read(receipt)
    pid = r["process_group"]

    def hup():
        require(
            r["name"] == "daemon"
            and gate_process.leader_identity(pid)
            == {"group": pid, "birth": r["leader_birth"]},
            "original private daemon is no longer running",
        )
        os.kill(pid, signal.SIGHUP)

    initial = log.stat().st_size
    try:
        replace(role, b"not a certificate\n")
        hup()
        until = time.monotonic() + 30
        while time.monotonic() < until:
            with log.open("rb") as stream:
                stream.seek(initial)
                recent = stream.read(1 << 20)
            if b"tls_reload_failed" in recent:
                break
            time.sleep(0.1)
        else:
            raise ValueError("daemon did not reject the invalid replacement")
        live = request(root, "GET", "/.well-known/oauth-protected-resource/mcp")
        require(
            live["leaf_sha256"] == pin,
            "server lost the last good certificate after rejection",
        )
    finally:
        replace(role, original)
        hup()
    return {
        "pid": pid,
        "birth": r["leader_birth"],
        "log_offset": initial,
        "old_leaf": pin,
        "served": live["leaf_sha256"],
        "restored": topology.certificate(role)["leaf_sha256"],
    }


def observe(op, args):
    if op == "external-config":
        return external_configuration(*args)
    if op == "external-discovery":
        return external_discovery(*args)
    if op == "installation":
        return snapshot(*args)
    if op == "token":
        return token(*args)
    if op == "discovery":
        return discovery(*args)
    if op == "invalid-tls":
        return invalid_tls(*args)
    if op == "profile":
        return read(args[0])
    if op == "operator-backup":
        root = Path(args[0])
        require(
            root.stat().st_mode & 0o077 == 0
            and all(
                not p.is_symlink() and p.stat().st_mode & 0o077 == 0
                for p in root.rglob("*")
            ),
            "operator backup contains a public or redirected file",
        )
        return {"private": True, "files": sum(p.is_file() for p in root.rglob("*"))}
    raise ValueError("unknown installed probe")


def external_configuration(root, port):
    root = Path(root)
    source = read(root / "kasumi.json")
    port = int(port)
    require(
        1024 <= port <= 65535, "external issuer needs a free unprivileged loopback port"
    )
    issuer = f"https://localhost:{port}"
    ca = Path(read(root / "profiles/mcp.json")["server_ca"]).read_text()
    source["auth"]["issuer"] = issuer
    source["auth"]["source"] = {
        "kind": "external_oauth",
        "jwks_uri": issuer + "/keys",
        "trusted_ca_pem": ca,
    }
    path = root / "oauth-qualification.json"
    with path.open("x") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(source, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    return {
        "config": str(path),
        "issuer": issuer,
        "jwks_uri": issuer + "/keys",
        "sha256": owned.sha256(path),
    }


def external_discovery(root, port):
    """Observe both metadata aliases while the configured local HTTPS issuer serves its keyset."""
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from threading import Thread

    root = Path(root)
    port = int(port)
    config = read(root / "oauth-qualification.json")
    profile = read(root / "profiles/mcp.json")
    issuer = f"https://localhost:{port}"
    jwks = {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "use": "sig",
                "kid": "discovery-probe",
                "x": "11qYAYKxCrfVS_7TyWgdWO6BvXBe6dCftmCSrC5Ice8",
            }
        ]
    }
    counts = []

    class Issuer(BaseHTTPRequestHandler):
        def do_GET(self):
            counts.append(self.path)
            if self.path != "/keys":
                self.send_error(404)
                return
            value = json.dumps(jwks).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(value)))
            self.end_headers()
            self.wfile.write(value)

        def log_message(self, *args):
            pass

    with HTTPServer(("127.0.0.1", port), Issuer) as server:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(
            config["mcp"]["tls"]["certificate"], config["mcp"]["tls"]["private_key"]
        )
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = http.client.HTTPSConnection(
                "localhost",
                port,
                context=ssl.create_default_context(cafile=profile["server_ca"]),
                timeout=15,
            )
            try:
                client.request("GET", "/keys")
                response = client.getresponse()
                require(
                    response.status == 200 and json.loads(response.read(1024)) == jwks,
                    "configured issuer did not serve its installed keyset",
                )
            finally:
                client.close()
            urls = discovery(root)
        finally:
            server.shutdown()
            thread.join(5)
        require(
            not thread.is_alive() and counts == ["/keys"],
            "issuer worker did not terminate or retained another request",
        )
    return {
        "issuer": issuer,
        "jwks_uri": config["auth"]["source"]["jwks_uri"],
        "issuer_requests": counts,
        "metadata": urls,
    }
