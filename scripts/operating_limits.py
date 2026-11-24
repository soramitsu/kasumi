"""Render the measured operating limits of the selected native reference deployment."""
from os.path import relpath
from urllib.parse import quote

import verify_release_acceptance as acceptance

KINDS = ("capacity-standalone", "capacity-ha", "concurrency", "benchmark-matrix", "ha-soak")
GATES = {f"{kind}:{acceptance.REFERENCE}" for kind in KINDS}
METRICS = ("rss_bytes", "allocated_disk_bytes", "maintenance_workspace_bytes")


def measurement(root, data):
    count = 0
    total = 0
    smallest = None
    largest = 0
    expected = acceptance.uint(data["requested_operations"], "requested operations", 1)
    for seq, item in enumerate(acceptance.rows(root, data["samples"])):
        acceptance.require(item["sequence"] == seq and item["status"] == "passed" and seq < expected,
                           "latency sample is missing, out of order, or failed")
        value = acceptance.uint(item["elapsed_ns"], "latency in nanoseconds", 1)
        count += 1
        total += value
        smallest = value if smallest is None else min(smallest, value)
        largest = max(largest, value)
    acceptance.require(count == expected == data["successful_operations"] == data["attempted_operations"]
                       and data["failed_operations"] == data["unattempted_operations"] == 0,
                       "incomplete workload measurement for operating limits")
    return f"{count:,} | {smallest:,} | {total // count:,} | {largest:,}"


def render(root, gates, source, *, report_dir=None):
    records = {}
    lines = ["# Measured operating limits", "", f"Source commit \x60{source['commit']}\x60, tree \x60{source['tree']}\x60.", "",
             f"The native reference target was \x60{acceptance.REFERENCE}\x60. Capacity and latency figures describe the recorded workloads.", "",
             "| Test | Host | Reserved CPUs | Reserved RAM (bytes) | Reserved disk (bytes) | Elapsed (s) | Original evidence |",
             "| --- | --- | ---: | ---: | ---: | ---: | --- |"]
    for kind in KINDS:
        identifier = f"{kind}:{acceptance.REFERENCE}"
        ref = gates[identifier]["evidence"]
        gate = acceptance.json_reference(root, ref)
        identity = gate["identity"]
        acceptance.require(gate["status"] == "passed" and gate["id"] == identifier and
                           identity["source_commit"] == source["commit"] and identity["source_tree"] == source["tree"],
                           "operating limits require a passing gate on the selected source")
        host = gate["host"]
        reservation = host["reservation"]
        elapsed = (acceptance.timestamp(gate["finished_at"]) - acceptance.timestamp(gate["started_at"])).total_seconds()
        acceptance.require(elapsed > 0 and acceptance.attempt_index.ID.fullmatch(host["id"]), "invalid measured host or interval")
        if kind == "ha-soak":
            acceptance.check_soak(root, gate["details"], elapsed)
        records[kind] = gate["details"]
        uri = quote(relpath(root / ref["path"], report_dir or root))
        lines.append(f"| {kind} | {host['id']} | {reservation['cpu_count']} | {reservation['memory_bytes']:,} | "
                     f"{reservation['disk_bytes']:,} | {elapsed:.3f} | [SHA-256 \x60{ref['sha256']}\x60]({uri}) |")
    selections = {"capacity-standalone": ("operations", "id"), "capacity-ha": ("operations", "id"),
                  "concurrency": ("workloads", "name"), "benchmark-matrix": ("cases", "id"),
                  "ha-soak": ("maintenance", "id")}
    for kind, (field, key) in selections.items():
        actual = acceptance.unique(records[kind][field], key, kind)
        acceptance.require(actual.keys() == acceptance.SCENARIOS[kind], "missing operating limits scenarios: " + kind)
    for kind in ("capacity-standalone", "capacity-ha"):
        details = records[kind]
        corpus = details["corpus"]
        lines.extend(["", "## " + ("Standalone capacity" if kind == "capacity-standalone" else "HA capacity"), "",
                      f"{corpus['documents']:,} documents occupied {corpus['canonical_bytes']:,} canonical bytes. "
                      f"The gzip-9 measurement produced {corpus['compression']['output_bytes']:,} bytes.", "",
                      "Observed peaks and admitted ceilings are in bytes. RSS is the largest sampled process RSS. "
                      "Disk and maintenance workspace use the largest sampled node allocation.", "",
                      "| Operation | Samples | Peak RSS / ceiling | Peak disk / ceiling | Peak workspace / ceiling | Retained-read budget |",
                      "| --- | ---: | ---: | ---: | ---: | ---: |"])
        for op in sorted(details["operations"], key=lambda item: item["id"]):
            peaks = dict.fromkeys(METRICS, 0)
            count = 0
            previous = -1
            for sample in acceptance.rows(root, op["resources"]):
                elapsed = acceptance.number(sample["elapsed_seconds"], "resource observation time")
                acceptance.require(elapsed > previous, "resource observations are unordered")
                previous = elapsed
                count += 1
                for key in METRICS:
                    value = acceptance.uint(sample[key], key)
                    acceptance.require(value <= op["limits"][key], "observed resource exceeds admitted limit")
                    peaks[key] = max(peaks[key], value)
            acceptance.require(count >= 2, "insufficient resource samples for measured limits")
            cells = " | ".join(f"{peaks[key]:,} / {op['limits'][key]:,}" for key in METRICS)
            lines.append(f"| {op['id']} | {count:,} | {cells} | {op['read_retention_budget_bytes']:,} |")
    lines.extend(["", "## Concurrent workloads", "", "Latency is measured in nanoseconds per successful operation.", "",
                  "| Workload | Workers | Peak in flight | Operations | Minimum | Mean | Maximum |",
                  "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"])
    for work in sorted(records['concurrency']['workloads'], key=lambda item: item['name']):
        lines.append(f"| {work['name']} | {work['workers']} | {work['peak_inflight']} | {measurement(root, work['measurement'])} |")
    lines.extend(["", "## Benchmark matrix", "", "Latency is measured in nanoseconds per successful operation.", "",
                  "| Mode | Tenants | Documents | Workload | Operations | Minimum | Mean | Maximum |",
                  "| --- | ---: | ---: | --- | ---: | ---: | ---: | ---: |"])
    for case in sorted(records['benchmark-matrix']['cases'], key=lambda item: (item['mode'], item['tenants'])):
        for work in sorted(case['workloads'], key=lambda item: item['name']):
            lines.append(f"| {case['mode']} | {case['tenants']:,} | {case['documents']:,} | {work['name']} | {measurement(root, work)} |")
    soak = records['ha-soak']
    last = None
    heartbeats = 0
    for sample in acceptance.rows(root, soak['heartbeats']):
        acceptance.require(sample['unexpected_errors'] == sample['integrity_mismatches'] == 0, "soak recorded a failure")
        last = sample
        heartbeats += 1
    acceptance.require(last is not None and last['elapsed_seconds'] >= soak['duration_seconds'] >= acceptance.SOAK_SECONDS,
                       "operating limits require a full-duration soak")
    lines.extend(["", "## HA soak", "", f"The measured interval was {soak['duration_seconds']:,} seconds. "
                  f"{heartbeats:,} heartbeats recorded {last['successful_operations']:,} successful operations. "
                  f"The run observed {len(soak['maintenance'])} maintenance events, zero unexpected errors and zero integrity mismatches.", ""])
    return "\n".join(lines).encode()
