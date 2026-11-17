#!/usr/bin/env python3
"""One authenticated MCP ``tools/list`` against an installed loopback endpoint.

Run as an owned child of a smoke runner. Exit status zero means the installed
endpoint answered over mutual TLS 1.3 with its pinned leaf certificate and
listed the document read tool. Standard output is one JSON summary; it never
contains the bearer token or key material.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
from pathlib import Path
import ssl
import sys
from urllib.parse import urlsplit

PROTOCOL = "2026-07-28"
TOOL = "kasumi_get"
MAX_BODY = 2 << 20


def require(value, message):
    if not value:
        raise ValueError(message)


def probe(installation, mapped):
    """``installation`` is the path the profile names; ``mapped`` is where it is readable."""
    def local(path):
        relative = Path(path).relative_to(installation)
        return str(Path(mapped) / relative)

    profile = json.loads(Path(local(Path(installation) / "profiles/mcp.json")).read_text())
    config = json.loads(Path(local(Path(installation) / "kasumi.json")).read_text())
    url = urlsplit(profile["mcp_endpoint"])
    require(url.scheme == "https" and url.hostname == "localhost" and url.port
            and not url.username and not url.query and not url.fragment,
            "MCP endpoint must be installed loopback TLS")
    certificate = Path(local(config["mcp"]["tls"]["certificate"])).read_text()
    pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).hexdigest()
    token = Path(local(profile["bearer_file"])).read_text()
    require(0 < len(token) <= 16384 and not any(c.isspace() for c in token),
            "invalid private token file")
    context = ssl.create_default_context(cafile=local(profile["server_ca"]))
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(local(profile["identity"]["certificate"]),
                            local(profile["identity"]["private_key"]))
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": {
        "io.modelcontextprotocol/protocolVersion": PROTOCOL,
        "io.modelcontextprotocol/clientInfo": {"name": "kasumi-smoke-probe", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {}}}}
    connection = http.client.HTTPSConnection("localhost", url.port, context=context, timeout=10)
    try:
        connection.connect()
        observed = hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()
        require(connection.sock.version() == "TLSv1.3" and observed == pin,
                "installed MCP TLS leaf differs from its pinned certificate")
        connection.request("POST", url.path or "/mcp", body=json.dumps(request), headers={
            "Authorization": "Bearer " + token, "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": PROTOCOL,
            "MCP-Method": "tools/list"})
        response = connection.getresponse()
        body = response.read(MAX_BODY + 1)
    finally:
        connection.close()
    require(response.status == 200 and len(body) <= MAX_BODY, "MCP request did not succeed")
    reply = json.loads(body)
    tools = sorted(tool["name"] for tool in reply.get("result", {}).get("tools", []))
    require(reply.get("id") == 1 and "error" not in reply and TOOL in tools,
            "MCP discovery lacks document reads")
    return {"status": response.status, "tls": "TLSv1.3", "certificate_sha256": observed,
            "tools": tools}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--installation", required=True)
    parser.add_argument("--mapped", required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(probe(args.installation, args.mapped), sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, ssl.SSLError, http.client.HTTPException) as error:
        print("MCP probe failed: " + type(error).__name__ + ": " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
