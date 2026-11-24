#!/usr/bin/env python3
"""Observe the RustSec advisory database's main branch over authenticated HTTPS."""
from __future__ import annotations

import datetime as dt
import email.utils
import hashlib
import http.client
import json
import re
import ssl

SCRIPT = "scripts/advisory_upstream.py"
HOST = "api.github.com"
PATH = "/repos/RustSec/advisory-db/git/ref/heads/main"
REF = "refs/heads/main"
MAX_BODY = 16 << 10
CLOCK_TOLERANCE = dt.timedelta(minutes=5)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def observe():
    # No redirect, user-chosen remote, proxy, local Git configuration or HTTP
    # alternate can select another source. The native trust store verifies TLS.
    connection = http.client.HTTPSConnection(HOST, timeout=30, context=ssl.create_default_context())
    try:
        connection.connect()
        cert_hash = hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()
        connection.request("GET", PATH, headers={"Accept": "application/vnd.github+json",
                           "User-Agent": "kasumi-dependency-review", "Cache-Control": "no-cache",
                           "X-GitHub-Api-Version": "2022-11-28"})
        response = connection.getresponse()
        body = response.read(MAX_BODY + 1)
        require(response.status == 200, f"advisory upstream returned HTTP {response.status}")
        require(len(body) <= MAX_BODY, "advisory upstream response exceeds its bound")
        return {"url": "https://" + HOST + PATH, "tls_peer_sha256": cert_hash,
                "http_date": response.getheader("Date"), "response": json.loads(body),
                "observed_at": dt.datetime.now(dt.timezone.utc).isoformat()}
    finally:
        connection.close()


def verify(observation, expected_commit, *, started_at, checked_at, max_age_hours):
    """Recheck the original HTTPS observation at the scanner's actual start time."""
    require(isinstance(observation, dict) and set(observation) == {
        "url", "tls_peer_sha256", "http_date", "response", "observed_at"}
        and observation["url"] == "https://" + HOST + PATH
        and isinstance(observation["tls_peer_sha256"], str)
        and re.fullmatch("[0-9a-f]{64}", observation["tls_peer_sha256"]),
        "advisory upstream source or TLS identity differs")
    response = observation["response"]
    require(isinstance(response, dict) and response.get("ref") == REF
            and isinstance(response.get("object"), dict) and response["object"].get("type") == "commit"
            and isinstance(expected_commit, str) and re.fullmatch("[0-9a-f]{40}", expected_commit)
            and response["object"].get("sha") == expected_commit,
            "advisory upstream branch differs from scanned Git commit")
    started, observed, checked = map(dt.datetime.fromisoformat,
                                    (started_at, observation["observed_at"], checked_at))
    require(isinstance(observation["http_date"], str), "upstream response lacks its HTTP date")
    server_date = email.utils.parsedate_to_datetime(observation["http_date"])
    require(all(value.tzinfo is not None for value in (started, observed, checked, server_date))
            and started <= observed <= checked and abs(observed - server_date) <= CLOCK_TOLERANCE
            and checked - observed <= dt.timedelta(hours=max_age_hours),
            "advisory upstream observation is stale or outside the review")
    return expected_commit


if __name__ == "__main__":
    print(json.dumps(observe(), sort_keys=True, separators=(",", ":")))
