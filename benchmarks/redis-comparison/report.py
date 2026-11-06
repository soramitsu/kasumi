#!/usr/bin/env python3
"""Render results.jsonl from run.py as markdown tables.

  report.py RESULTS.jsonl [--label NAME]

Prints one throughput/latency/resource table per client count, a startup and
recovery table, and a disk table. Every row keeps the load average that was
recorded around it, because the host is shared, and Kasumi rows name the
compaction work their node database did during the case.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def number(value, digits=0):
    if value is None:
        return "–"
    if digits == 0:
        return f"{value:,.0f}"
    return f"{value:,.{digits}f}"


def mib(value):
    return "–" if value is None else f"{value / (1 << 20):,.0f}"


def compaction(entry):
    """Kasumi only: the cycle and phases around the case and what it reclaimed."""
    summary = entry.get("compaction")
    if not summary:
        return "–"
    if not summary["active"]:
        return "none"
    text = (f"cycle {number(summary['cycle_before'])}→{number(summary['cycle_after'])}, "
            f"{summary['phase_before']}→{summary['phase_after']}")
    if summary["reclaimed_bytes"] or summary["relocated_bytes"]:
        text += f", {mib(summary['reclaimed_bytes'])} MiB reclaimed"
    if summary["relocated_bytes"]:
        text += f", {mib(summary['relocated_bytes'])} MiB relocated"
    return text


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("results")
    parser.add_argument("--label", default=None)
    arguments = parser.parse_args(argv)
    entries = [json.loads(line) for line in Path(arguments.results).read_text().splitlines() if line.strip()]
    host = next((entry for entry in entries if entry.get("phase") == "host"), {})
    if arguments.label:
        print(f"### {arguments.label}\n")
    if host:
        print(f"Host: {host.get('platform')} ({host.get('cpus')} CPUs), {host.get('redis_server', '')}. "
              f"Load average at start: {host.get('load_average')}.\n")
    cases = [entry for entry in entries if entry.get("phase") in ("workload", "load")]
    for clients in sorted({entry["clients"] for entry in cases}):
        print(f"#### {clients} client{'s' if clients != 1 else ''}\n")
        print("| System | Workload | ops/s | docs/s | p50 µs | p99 µs | p99.9 µs | server CPU µs/op | "
              "peak RSS MiB | disk write amp | errors | load avg before→after | compaction during the case |")
        print("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |")
        for entry in cases:
            if entry["clients"] != clients:
                continue
            server = entry.get("server", {})
            amplification = entry.get("write_amplification_physical")
            print("| {system} | {workload} | {ops} | {docs} | {p50} | {p99} | {p999} | {cpu} | {rss} | {amp} | "
                  "{errors} | {before}→{after} | {compaction} |".format(
                      system=entry["system"], workload=entry["workload"],
                      ops=number(entry["throughput_ops_per_second"]),
                      docs=number(entry["items_per_second"]),
                      p50=number(entry["p50_microseconds"]), p99=number(entry["p99_microseconds"]),
                      p999=number(entry["p999_microseconds"]),
                      cpu=number(entry.get("server_cpu_microseconds_per_operation"), 1),
                      rss=mib(server.get("peak_rss_bytes_sampled")),
                      amp="–" if amplification is None else f"{amplification:.2f}",
                      errors=entry["errors"],
                      before=entry["load_average_before"][0], after=entry["load_average_after"][0],
                      compaction=compaction(entry)))
        print()
    restarts = [entry for entry in entries if entry.get("phase") in
                ("cold-start-empty", "install", "graceful-restart", "crash-recovery")]
    if restarts:
        print("#### Startup and recovery (spawn to first authenticated read)\n")
        print("| System | Phase | seconds | shutdown seconds | RSS after MiB | load avg |")
        print("| --- | --- | ---: | ---: | ---: | --- |")
        for entry in restarts:
            seconds = entry.get("seconds", entry.get("first_ready_seconds_kasumictl"))
            print(f"| {entry['system']} | {entry['phase']} | {number(seconds, 2)} | "
                  f"{number(entry.get('shutdown_seconds'), 2)} | {mib(entry.get('rss_bytes_after'))} | "
                  f"{entry.get('load_average', ['–'])[0]} |")
        print()
    idle = [entry for entry in entries if entry.get("phase") == "idle"]
    if idle:
        print("#### Idle after load\n")
        print("| System | CPU % | disk bytes written | RSS MiB | load avg |")
        print("| --- | ---: | ---: | ---: | --- |")
        for entry in idle:
            print(f"| {entry['system']} | {entry['cpu_percent']:.2f} | {entry['disk_bytes_written']:,} | "
                  f"{mib(entry['rss_bytes_after'])} | {entry['load_average_before'][0]} |")
        print()
    disks = [entry for entry in entries if entry.get("phase") == "disk-usage"]
    if disks:
        print("#### Disk usage after the workloads\n")
        print("| System | data directory MiB | logical dataset MiB | ratio |")
        print("| --- | ---: | ---: | ---: |")
        for entry in disks:
            ratio = entry["data_directory_bytes"] / entry["logical_dataset_bytes"]
            print(f"| {entry['system']} | {mib(entry['data_directory_bytes'])} | "
                  f"{mib(entry['logical_dataset_bytes'])} | {ratio:.2f} |")
        print()
    failures = [entry for entry in entries if entry.get("phase") == "failed"]
    for entry in failures:
        print(f"**{entry['system']} failed:** `{entry['error'][-500:]}`\n")


if __name__ == "__main__":
    main()
