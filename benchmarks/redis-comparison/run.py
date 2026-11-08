#!/usr/bin/env python3
"""Reproducible Kasumi vs Redis comparison. See benchmarks/REDIS-COMPARISON.md.

  run.py --kasumi-bin DIR --driver PATH --work DIR --output DIR [options]

Every selected system is installed fresh under --work, started, timed to its
first authenticated call and loaded. Then each workload and client count runs
on every system back to back, with kasumi-bench-compare, so drifting host load
affects the systems alike; idle servers stay resident. Around each run it samples
the server process: CPU seconds, resident memory (peak sampled every 250 ms),
bytes written to files and to the device, and the machine load average. After
the workloads it times a graceful restart and a crash (SIGKILL) recovery, each
until the first successful authenticated read of a loaded key.

Systems:
  kasumi          standalone kasumid: durable commits, TLS 1.3 + mTLS + pinned
                  certificate + bearer token, encrypted storage, mutation audit
  kasumi-audited  as kasumi, with strict_read_audit on the collection
  redis-always    redis-server: AOF appendfsync always, TLS 1.3 + mTLS, ACL user
  redis-everysec  as redis-always with appendfsync everysec

Around each Kasumi case it also reads the node database's storage maintenance
figures from the metrics endpoint (with the installation's Control profile):
the compaction cycle and phase, and the bytes reclaimed and relocated during
the case. A cycle that runs inside a case slows its writes several-fold, so
compare Kasumi builds only on cases with the same compaction activity, or
pin it with --compact-before.

Results: one JSON line per case in OUTPUT/results.jsonl, plus OUTPUT/summary.md.
Nothing written here contains credentials or document bodies.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import platform
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent.parent / "scripts"))
import procstat  # noqa: E402
import dev_standalone  # noqa: E402

WORKLOADS = ["point-read", "point-write", "mixed", "batch-read", "batch-write", "range-scan"]
WRITE_WORKLOADS = {"point-write", "mixed", "batch-write"}
SYSTEMS = ["kasumi", "kasumi-audited", "redis-always", "redis-everysec"]


def free_port_block(start: int, count: int) -> int:
    """The first port >= start with `count` consecutive free loopback ports."""
    port = start
    while port + count < 65535:
        try:
            for offset in range(count):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                    probe.bind(("127.0.0.1", port + offset))
            return port
        except OSError:
            port += count
    raise RuntimeError("no free port block")


def openssl() -> str:
    for candidate in ("/opt/homebrew/opt/openssl@4/bin/openssl", "/opt/homebrew/opt/openssl@3/bin/openssl",
                      shutil.which("openssl")):
        if candidate and os.access(candidate, os.X_OK):
            return candidate
    raise RuntimeError("openssl not found")


def make_tls(directory: Path) -> dict:
    """A private P-256 CA, a localhost server certificate and a client certificate."""
    directory.mkdir(mode=0o700)
    tool = openssl()

    def run(*arguments):
        subprocess.run([tool, *arguments], check=True, capture_output=True, cwd=directory)

    (directory / "ca.ext").write_text(
        "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
        "subjectKeyIdentifier=hash\n")
    (directory / "server.ext").write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n"
        "authorityKeyIdentifier=keyid\n")
    (directory / "client.ext").write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=clientAuth\nauthorityKeyIdentifier=keyid\n")
    for name in ("ca", "server", "client"):
        run("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", f"{name}.key")
    run("req", "-new", "-key", "ca.key", "-subj", "/CN=redis-comparison-ca", "-out", "ca.csr")
    run("x509", "-req", "-in", "ca.csr", "-signkey", "ca.key", "-days", "30", "-sha256",
        "-extfile", "ca.ext", "-out", "ca.pem")
    for name in ("server", "client"):
        run("req", "-new", "-key", f"{name}.key", "-subj", f"/CN={'localhost' if name == 'server' else 'bench'}",
            "-out", f"{name}.csr")
        run("x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
            "-days", "30", "-sha256", "-extfile", f"{name}.ext", "-out", f"{name}.pem")
    for path in directory.iterdir():
        path.chmod(0o600)
    return {name: str(directory / f"{name}.pem") for name in ("ca", "server", "client")} | {
        "server_key": str(directory / "server.key"), "client_key": str(directory / "client.key")}


class Server:
    """One running server process with a restart recipe."""

    def __init__(self, name, command, env, log, cwd=None):
        self.name = name
        self.command = command
        self.env = env
        self.log = log
        self.cwd = cwd
        self.process = None

    def start(self):
        with open(self.log, "ab") as log:
            self.process = subprocess.Popen(self.command, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                            env=self.env, cwd=self.cwd, start_new_session=True)
        return self.process.pid

    @property
    def pid(self):
        return self.process.pid

    def alive(self):
        return self.process is not None and self.process.poll() is None

    def stop(self, sig=signal.SIGTERM, timeout=600):
        """Signal and reap; returns seconds until exit."""
        started = time.monotonic()
        if not self.alive():
            return 0.0
        self.process.send_signal(sig)
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            raise RuntimeError(f"{self.name} did not exit within {timeout}s after {sig!r}")
        return time.monotonic() - started


class Harness:
    def __init__(self, arguments):
        self.arguments = arguments
        self.work = Path(arguments.work).resolve()
        self.output = Path(arguments.output).resolve()
        self.driver = str(Path(arguments.driver).resolve())
        self.results = self.output / "results.jsonl"
        self.port = arguments.base_port
        # Kasumi system -> (kasumictl, Control client configuration, environment)
        self.observers = {}

    # ------------------------------------------------------------ recording

    def record(self, entry):
        entry["recorded_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self.results.open("a") as output:
            output.write(json.dumps(entry, sort_keys=True) + "\n")
        brief = {key: entry.get(key) for key in ("system", "phase", "workload", "clients",
                                                    "throughput_ops_per_second", "p50_microseconds",
                                                    "p99_microseconds", "errors", "seconds")}
        print(json.dumps({k: v for k, v in brief.items() if v is not None}), flush=True)

    def drive(self, base, workload, clients, extra=(), timeout=None):
        output = self.work / f"driver-{time.monotonic_ns()}.json"
        command = [self.driver, *base, "--workload", workload, "--clients", str(clients),
                   "--keys", str(self.arguments.keys), "--value-bytes", str(self.arguments.value_bytes),
                   "--duration-seconds", str(self.arguments.duration),
                   "--warmup-seconds", str(self.arguments.warmup),
                   "--batch-size", str(self.arguments.batch_size),
                   "--scan-limit", str(self.arguments.scan_limit),
                   "--load-batch", str(self.arguments.load_batch),
                   "--timeout-seconds", str(self.arguments.call_timeout),
                   "--output", str(output), *extra]
        completed = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
        if completed.returncode != 0:
            raise RuntimeError(f"driver {workload} failed: {completed.stderr.decode(errors='replace')[-3000:]}")
        report = json.loads(output.read_text())
        output.unlink()
        return report

    def storage(self, system):
        """The node database's `kasumi_storage_*` figures, or None for Redis."""
        observer = self.observers.get(system)
        if observer is None:
            return None
        kasumictl, control, environment = observer
        completed = dev_standalone.run([kasumictl, "--config", control, "metrics"], env=environment)
        if completed.returncode != 0:
            return {"error": completed.stderr.decode(errors="replace")[-500:]}
        figures = {"observed_at": time.time()}
        for line in completed.stdout.decode(errors="replace").splitlines():
            name, _, value = line.rpartition(" ")
            if line.startswith("kasumi_storage_"):
                try:
                    figures[name.removeprefix("kasumi_storage_")] = float(value)
                except ValueError:
                    pass
        return figures

    def compact(self, system):
        """Apply --compact-before to a Kasumi case: request a cycle, and with
        `finish` wait until the node database has consumed the request and is idle."""
        mode = self.arguments.compact_before
        if mode == "none" or system not in self.observers:
            return None
        kasumictl, control, environment = self.observers[system]
        cycle = self.storage(system).get("compaction_cycle", 0)
        started = time.monotonic()
        requested = dev_standalone.run([kasumictl, "--config", control, "compact"], env=environment)
        if requested.returncode != 0:
            raise RuntimeError("compaction request failed: " + requested.stderr.decode(errors="replace")[-1000:])
        if mode == "start":
            return {"mode": mode}
        fresh_after = time.monotonic()
        confirmed_idle = False
        while time.monotonic() - started < self.arguments.recovery_timeout:
            time.sleep(1)
            observing = time.monotonic()
            figures = self.storage(system)
            # Requests can join a running cycle, or find no older files to
            # compact. Neither requires the cycle counter to advance.
            # Maintenance clears requested after consuming the request. Metrics
            # are a worker's cached copy, so require two fresh idle publications
            # after the request returns. One old status could have been captured
            # before the request and published afterwards by that worker.
            # Compare age with elapsed time BEFORE asking for metrics: response
            # latency must not make an old publication look fresh.
            age = figures.get("status_age_seconds")
            fresh = isinstance(age, (int, float)) and 0 <= age <= observing - fresh_after
            if (fresh and figures.get("compaction_requested") == 0
                    and figures.get('compaction_phase{phase="idle"}') == 1):
                if not confirmed_idle:
                    confirmed_idle = True
                    fresh_after = time.monotonic()
                    continue
                return {"mode": mode, "seconds": time.monotonic() - started,
                        "cycle_before": cycle, "cycle_after": figures.get("compaction_cycle"),
                        "fresh_idle_publications": 2}
            if (figures.get('compaction_phase{phase="idle"}') != 1
                    or figures.get("compaction_requested") != 0):
                confirmed_idle = False
                fresh_after = time.monotonic()
        raise RuntimeError(f"requested compaction did not finish within {self.arguments.recovery_timeout} s")

    @staticmethod
    def compaction(before, after):
        """What the node database's compaction did between two observations."""
        if not before or not after or "error" in before or "error" in after:
            return None

        def phase(figures):
            return next((name for name in ("idle", "evacuating", "reclaiming", "packing")
                         if figures.get(f'compaction_phase{{phase="{name}"}}') == 1), None)

        summary = {
            "cycle_before": before.get("compaction_cycle"), "cycle_after": after.get("compaction_cycle"),
            "phase_before": phase(before), "phase_after": phase(after),
            "reclaimed_bytes": after.get("reclaimed_bytes_total", 0) - before.get("reclaimed_bytes_total", 0),
            "relocated_bytes": after.get("relocated_bytes_total", 0) - before.get("relocated_bytes_total", 0),
        }
        summary["active"] = (summary["cycle_before"] != summary["cycle_after"]
                             or summary["phase_before"] != "idle" or summary["phase_after"] != "idle"
                             or summary["reclaimed_bytes"] > 0 or summary["relocated_bytes"] > 0)
        return summary

    def measured(self, system, server, base, workload, clients, phase="workload", extra=()):
        requested = self.compact(system) if phase == "workload" else None
        storage_before = self.storage(system)
        load_before = procstat.load_average()
        before = procstat.sample(server.pid)
        with procstat.PeakSampler(server.pid) as peak:
            report = self.drive(base, workload, clients, extra)
        after = procstat.sample(server.pid)
        cost = procstat.delta(before, after)
        storage_after = self.storage(system)
        entry = {**report, "driver_system": report["system"], "system": system, "phase": phase,
                 "resource_window": "whole_driver_invocation_including_warmup",
                 "server": {**cost, "rss_bytes_after": after["rss_bytes"],
                            "footprint_bytes_after": after["footprint_bytes"],
                            "peak_rss_bytes_sampled": peak.peak_rss,
                            "peak_footprint_bytes_sampled": peak.peak_footprint,
                            "lifetime_peak_footprint_bytes": after["peak_footprint_bytes"]},
                 "load_average_before": load_before, "load_average_after": procstat.load_average()}
        if storage_before is not None:
            entry["storage_before"], entry["storage_after"] = storage_before, storage_after
            entry["compaction"] = self.compaction(storage_before, storage_after)
        if requested is not None:
            entry["compact_before"] = requested
        operations = report["operations"] or 1
        entry["server_cpu_microseconds_per_operation"] = cost["cpu_seconds"] * 1e6 / operations
        if report["logical_bytes_written"]:
            entry["write_amplification_physical"] = cost["disk_bytes_written"] / report["logical_bytes_written"]
            entry["write_amplification_logical"] = cost["logical_bytes_written"] / report["logical_bytes_written"]
        self.record(entry)
        if report["errors"]:
            raise RuntimeError(f"{system} {workload} reported errors: {report.get('first_error')}")
        return entry

    def probe(self, base, ping, started, timeout):
        report = self.drive(base, "probe", 1,
                            ["--probe-ping", "true" if ping else "false",
                             "--probe-timeout-seconds", str(int(timeout))], timeout=timeout + 60)
        return time.monotonic() - started, report

    # ------------------------------------------------------------ systems

    def kasumi(self, system, cleanup):
        directory = self.work / system
        directory.mkdir(mode=0o700)
        (directory / "tmp").mkdir(mode=0o700)
        port = free_port_block(self.port, 3)
        self.port = port + 3
        selected = dev_standalone.ports(port)
        environment = dev_standalone.children(directory)
        binaries = Path(self.arguments.kasumi_bin).resolve()
        installation = directory / "installation"
        inputs = {
            "directory-policy": {"extent_bytes": 10485760, "max_entries": 32768},
            "file-allocation-policy": {"maximum_extra_extent_bytes": 1048576},
            "network": dev_standalone.network(selected),
            "tenant-audit-placements": {"__kasumi_control": {"kind": "local_replica_only"},
                                        "default": {"kind": "local_replica_only"}},
        }
        for name, value in inputs.items():
            dev_standalone.private_write(directory / f"{name}.json", value)
        started = time.monotonic()
        init = dev_standalone.run([binaries / "kasumid", "init", "--mode", "standalone", installation,
                                   *[part for name in inputs for part in (f"--{name}", directory / f"{name}.json")],
                                   "--tenant", "default"], env=environment)
        if init.returncode != 0:
            raise RuntimeError("kasumid init failed: " + init.stderr.decode(errors="replace")[-3000:])
        init_seconds = time.monotonic() - started
        if self.arguments.kasumi_cache_bytes is not None:
            configuration = installation / "kasumi.json"
            settings = json.loads(configuration.read_text())
            settings["persistent_disk"]["native_storage"]["byte_limit"] = self.arguments.kasumi_cache_bytes
            configured = installation / "kasumi-benchmark.json"
            dev_standalone.private_write(configured, settings)
            configured.replace(configuration)
        profile = installation / "profiles/default.json"
        server = Server(system, [str(binaries / "kasumid"), "serve", str(installation / "kasumi.json")],
                        environment, directory / "server.log")
        started = time.monotonic()
        cleanup.callback(server.stop)
        server.start()
        # Wait for an authenticated call before creating the collection.
        deadline = time.monotonic() + 600
        while True:
            if not server.alive():
                raise RuntimeError(f"kasumid serve exited; see {directory / 'server.log'}")
            status, document = dev_standalone.data(binaries, profile, "collections", env=environment)
            if status == 0 and document and document.get("ok"):
                break
            if time.monotonic() > deadline:
                raise RuntimeError(f"kasumid not ready: {document}")
            time.sleep(0.1)
        first_ready = time.monotonic() - started
        # Metrics and compaction requests answer only the Control tenant's
        # profile, so its credential is renewed too.
        control_profile = installation / "profiles/control.json"
        watchers = []
        with (directory / "credential.log").open("ab") as log:
            for renewed in (profile, control_profile):
                watchers.append(subprocess.Popen(
                    [str(binaries / "kasumid"), "credential", "watch", str(renewed)],
                    stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True, env=environment))
                cleanup.callback(self.stop_watcher, watchers[-1])
        # Collections are the tenant operator's to create; the data profile
        # is the application's and cannot administer.
        admin = directory / "admin-client.json"
        dev_standalone.private_write(admin, dev_standalone.admin_client(
            dev_standalone.read_json(installation / "profiles/operator.json")))
        control = directory / "control-client.json"
        dev_standalone.private_write(control, dev_standalone.admin_client(dev_standalone.read_json(control_profile)))
        self.observers[system] = (binaries / "kasumictl", control, environment)
        definition = directory / "bench.collection.json"
        dev_standalone.private_write(definition, {
            "name": "bench", "write_mode": "mutable", "retention_class": "operational",
            "strict_read_audit": system == "kasumi-audited",
            "schema": {"type": "object", "properties": {"n": {"type": "integer"}, "v": {"type": "integer"},
                                                         "pad": {"type": "string"}}},
            "indexes": [{"name": "n", "fields": [{"path": "/n", "kind": "number"}]}],
        })
        created = dev_standalone.run([binaries / "kasumictl", "--config", admin, "create-collection", definition],
                                     env=environment)
        if created.returncode != 0:
            raise RuntimeError("create-collection failed: " + created.stderr.decode(errors="replace")[-3000:])
        base = ["--system", "kasumi", "--profile", str(profile), "--collection", "bench"]
        info = {"init_seconds": init_seconds, "first_ready_seconds_kasumictl": first_ready,
                "data_directory": str(installation / "data"), "installation": str(installation)}
        return server, base, info, watchers

    def redis(self, system, cleanup):
        directory = self.work / system
        directory.mkdir(mode=0o700)
        data = directory / "data"
        data.mkdir(mode=0o700)
        tls = make_tls(directory / "tls")
        port = free_port_block(self.port, 1)
        self.port = port + 1
        password = secrets.token_hex(32)
        password_file = directory / "password"
        password_file.write_text(password + "\n")
        password_file.chmod(0o600)
        fsync = "always" if system == "redis-always" else "everysec"
        configuration = directory / "redis.conf"
        configuration.write_text("\n".join([
            "bind 127.0.0.1", "port 0", f"tls-port {port}",
            f"tls-cert-file {tls['server']}", f"tls-key-file {tls['server_key']}",
            f"tls-ca-cert-file {tls['ca']}", "tls-auth-clients yes", 'tls-protocols "TLSv1.3"',
            f"dir {data}", "appendonly yes", f"appendfsync {fsync}", 'save ""',
            "daemonize no", f"logfile {directory / 'redis.log'}",
            "user default off", f"user bench on >{password} ~* &* +@all", "",
        ]))
        configuration.chmod(0o600)
        server = Server(system, [self.arguments.redis_server, str(configuration)], dict(os.environ),
                        directory / "redis.stdout")
        base = ["--system", "redis", "--redis-endpoint", f"127.0.0.1:{port}", "--redis-ca", tls["ca"],
                "--redis-cert", tls["client"], "--redis-key", tls["client_key"], "--redis-user", "bench",
                "--redis-password-file", str(password_file), "--redis-index", "true"]
        started = time.monotonic()
        cleanup.callback(server.stop)
        server.start()
        return server, base, {"data_directory": str(data), "appendfsync": fsync, "started": started}, []

    # ------------------------------------------------------------ flow

    def setup_system(self, system):
        """Install, start and load one system; returns its running state."""
        print(f"== {system}", flush=True)
        with contextlib.ExitStack() as cleanup:
            if system.startswith("kasumi"):
                server, base, info, watchers = self.kasumi(system, cleanup)
                # Kasumi's readiness was observed with kasumictl during install.
                self.record({"system": system, "phase": "install", **info,
                             "load_average": procstat.load_average()})
            else:
                server, base, info, watchers = self.redis(system, cleanup)
                seconds, _ = self.probe(base, True, info.pop("started"), 120)
                self.record({"system": system, "phase": "cold-start-empty", "seconds": seconds, **info,
                             "load_average": procstat.load_average()})
            state = {"system": system, "server": server, "base": base, "info": info, "watchers": watchers}
            self.measured(system, server, base, "load", self.arguments.load_clients, phase="load")
            if self.arguments.idle_seconds:
                self.idle(system, server)
            state["cleanup"] = cleanup.pop_all()
            return state

    def idle(self, system, server):
        """CPU and memory of a loaded server that receives no requests."""
        before = procstat.sample(server.pid)
        load_before = procstat.load_average()
        time.sleep(self.arguments.idle_seconds)
        after = procstat.sample(server.pid)
        cost = procstat.delta(before, after)
        self.record({"system": system, "phase": "idle", "seconds": self.arguments.idle_seconds,
                     "cpu_percent": 100 * cost["cpu_seconds"] / self.arguments.idle_seconds,
                     "disk_bytes_written": cost["disk_bytes_written"],
                     "rss_bytes_after": after["rss_bytes"], "footprint_bytes_after": after["footprint_bytes"],
                     "load_average_before": load_before, "load_average_after": procstat.load_average()})

    def finish_system(self, state):
        """Disk usage, then a graceful restart and a crash recovery."""
        system, server, base = state["system"], state["server"], state["base"]
        arguments = self.arguments
        self.record({"system": system, "phase": "disk-usage",
                     "data_directory_bytes": procstat.directory_bytes(state["info"]["data_directory"]),
                     "logical_dataset_bytes": arguments.keys * (arguments.value_bytes + 11)})
        if arguments.skip_restart:
            return
        for kind, sig in (("graceful-restart", signal.SIGTERM), ("crash-recovery", signal.SIGKILL)):
            shutdown = server.stop(sig)
            started = time.monotonic()
            server.start()
            seconds, _ = self.probe(base, False, started, arguments.recovery_timeout)
            after = procstat.sample(server.pid)
            self.record({"system": system, "phase": kind, "seconds": seconds,
                         "shutdown_seconds": shutdown, "rss_bytes_after": after["rss_bytes"],
                         "footprint_bytes_after": after["footprint_bytes"],
                         "load_average": procstat.load_average()})

    @staticmethod
    def stop_watcher(watcher):
        if watcher.poll() is None:
            watcher.send_signal(signal.SIGINT)
            try:
                watcher.wait(timeout=30)
            except subprocess.TimeoutExpired:
                watcher.kill()
                watcher.wait()

    @staticmethod
    def stop_system(state):
        # ExitStack attempts every cleanup even if one process fails to stop.
        state["cleanup"].close()

    def retain_failure_logs(self, system):
        directory = self.work / system
        logs = [directory / "server.log", *sorted((directory / "tmp").glob("kasumi-daemon-*.log"))]
        retained = []
        for source in logs:
            if source.is_file():
                destination = self.output / system / source.name
                destination.parent.mkdir(mode=0o700, exist_ok=True)
                shutil.copy2(source, destination)
                retained.append(str(destination.relative_to(self.output)))
        return retained

    def run(self):
        self.work.mkdir(mode=0o700)
        self.output.mkdir(parents=True, exist_ok=True)
        self.record({"phase": "host", "platform": platform.platform(), "machine": platform.machine(),
                     "cpus": os.cpu_count(), "python": platform.python_version(),
                     "redis_server": subprocess.run([self.arguments.redis_server, "--version"],
                                                    capture_output=True, text=True).stdout.strip()
                     if self.arguments.redis_server else None,
                     "arguments": {k: v for k, v in vars(self.arguments).items()},
                     "load_average": procstat.load_average()})
        failures = []

        def failed(state_or_system, error):
            system = state_or_system if isinstance(state_or_system, str) else state_or_system["system"]
            failures.append(system)
            self.record({"system": system, "phase": "failed", "error": str(error)[-3000:]})

        running = []
        try:
            for system in self.arguments.systems:
                try:
                    running.append(self.setup_system(system))
                except Exception as error:  # keep the other systems' evidence
                    failed(system, error)
            # Every system runs each case back to back, so drifting host load
            # affects them alike. Idle servers stay resident meanwhile.
            for workload in self.arguments.workloads:
                for clients in self.arguments.clients:
                    for state in running:
                        if state.get("failed"):
                            continue
                        try:
                            self.measured(state["system"], state["server"], state["base"], workload, clients)
                        except Exception as error:
                            state["failed"] = True
                            failed(state, error)
            for state in running:
                if not state.get("failed"):
                    try:
                        self.finish_system(state)
                    except Exception as error:
                        failed(state, error)
        finally:
            for state in running:
                try:
                    self.stop_system(state)
                except Exception as error:
                    failed(state, error)
        for system in dict.fromkeys(failures):
            try:
                logs = self.retain_failure_logs(system)
                self.record({"system": system, "phase": "diagnostics", "logs": logs})
            except OSError as error:
                self.record({"system": system, "phase": "diagnostics", "error": str(error)})
        import report
        with (self.output / "summary.md").open("w") as summary, contextlib.redirect_stdout(summary):
            report.main([str(self.results)])
        if not self.arguments.keep_work:
            shutil.rmtree(self.work, ignore_errors=True)
        return 1 if failures else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--kasumi-bin", required=True, help="directory with kasumid and kasumictl")
    parser.add_argument("--driver", required=True, help="kasumi-bench-compare executable")
    parser.add_argument("--redis-server", default=shutil.which("redis-server"))
    parser.add_argument("--work", required=True, help="new directory for installations and data")
    parser.add_argument("--output", required=True, help="directory for results.jsonl")
    parser.add_argument("--systems", default=",".join(["kasumi", "redis-always", "redis-everysec"]))
    parser.add_argument("--workloads", default=",".join(WORKLOADS))
    parser.add_argument("--clients", default="1,16")
    parser.add_argument("--load-clients", type=int, default=16)
    parser.add_argument("--keys", type=int, default=100_000)
    parser.add_argument("--value-bytes", type=int, default=1024)
    parser.add_argument("--duration", type=int, default=20)
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--scan-limit", type=int, default=50)
    parser.add_argument("--load-batch", type=int, default=100)
    parser.add_argument("--base-port", type=int, default=47100)
    parser.add_argument("--recovery-timeout", type=int, default=1800)
    parser.add_argument("--call-timeout", type=int, default=60,
                        help="Kasumi per-call deadline in seconds, including SDK resends")
    parser.add_argument("--kasumi-cache-bytes", type=int,
                        help="override Kasumi's persistent native cache cap for a memory comparison")
    parser.add_argument("--idle-seconds", type=int, default=10,
                        help="measure each loaded server's idle CPU for this long (0 skips)")
    parser.add_argument("--compact-before", choices=["none", "start", "finish"], default="none",
                        help="before each Kasumi workload case, request a compaction cycle (start) "
                             "or request one and wait until it completes (finish)")
    parser.add_argument("--skip-restart", action="store_true")
    parser.add_argument("--keep-work", action="store_true")
    arguments = parser.parse_args(argv)
    if arguments.kasumi_cache_bytes is not None and arguments.kasumi_cache_bytes < 0:
        parser.error("--kasumi-cache-bytes must be nonnegative")
    arguments.systems = [s for s in arguments.systems.split(",") if s]
    arguments.workloads = [w for w in arguments.workloads.split(",") if w]
    arguments.clients = [int(c) for c in arguments.clients.split(",") if c]
    unknown = set(arguments.systems) - set(SYSTEMS)
    if unknown or set(arguments.workloads) - set(WORKLOADS):
        parser.error(f"unknown systems/workloads: {unknown | (set(arguments.workloads) - set(WORKLOADS))}")
    if not arguments.redis_server and any(s.startswith("redis") for s in arguments.systems):
        parser.error("redis-server not found; pass --redis-server")
    os.umask(0o077)
    return Harness(arguments).run()


if __name__ == "__main__":
    sys.exit(main())
