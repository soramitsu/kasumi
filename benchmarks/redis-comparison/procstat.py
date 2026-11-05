"""Server-side process observations for the Redis comparison.

Each sample reads one live process: resident memory, physical footprint
(macOS), cumulative CPU seconds, and cumulative bytes it wrote to files
(logical) and to the device (physical). Differences between two samples give
the cost of the workload that ran between them. macOS uses proc_pid_rusage;
Linux uses /proc. Nothing here reads arguments, environment or payloads.
"""
from __future__ import annotations

import ctypes
import os
import sys
import threading
import time


class _RusageInfoV4(ctypes.Structure):
    _fields_ = [("ri_uuid", ctypes.c_uint8 * 16)] + [
        (name, ctypes.c_uint64)
        for name in (
            "ri_user_time", "ri_system_time", "ri_pkg_idle_wkups", "ri_interrupt_wkups",
            "ri_pageins", "ri_wired_size", "ri_resident_size", "ri_phys_footprint",
            "ri_proc_start_abstime", "ri_proc_exit_abstime", "ri_child_user_time",
            "ri_child_system_time", "ri_child_pkg_idle_wkups", "ri_child_interrupt_wkups",
            "ri_child_pageins", "ri_child_elapsed_abstime", "ri_diskio_bytesread",
            "ri_diskio_byteswritten", "ri_cpu_time_qos_default", "ri_cpu_time_qos_maintenance",
            "ri_cpu_time_qos_background", "ri_cpu_time_qos_utility", "ri_cpu_time_qos_legacy",
            "ri_cpu_time_qos_user_initiated", "ri_cpu_time_qos_user_interactive",
            "ri_billed_system_time", "ri_serviced_system_time", "ri_logical_writes",
            "ri_lifetime_max_phys_footprint", "ri_instructions", "ri_cycles", "ri_billed_energy",
            "ri_serviced_energy", "ri_interval_max_phys_footprint", "ri_runnable_time",
        )
    ]


class _Timebase(ctypes.Structure):
    _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]


if sys.platform == "darwin":
    _LIBSYSTEM = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    _TIMEBASE = _Timebase()
    _LIBSYSTEM.mach_timebase_info(ctypes.byref(_TIMEBASE))
    # ri_user_time/ri_system_time are Mach absolute-time ticks on Apple silicon.
    _TICK_SECONDS = _TIMEBASE.numer / _TIMEBASE.denom / 1e9


def sample(pid: int) -> dict:
    """One observation of a live process, or raise OSError when it is gone."""
    if sys.platform == "darwin":
        info = _RusageInfoV4()
        if _LIBSYSTEM.proc_pid_rusage(pid, 4, ctypes.byref(info)) != 0:
            raise OSError(ctypes.get_errno(), f"proc_pid_rusage({pid}) failed")
        return {
            "rss_bytes": info.ri_resident_size,
            "footprint_bytes": info.ri_phys_footprint,
            "peak_footprint_bytes": info.ri_lifetime_max_phys_footprint,
            "cpu_seconds": (info.ri_user_time + info.ri_system_time) * _TICK_SECONDS,
            "logical_bytes_written": info.ri_logical_writes,
            "disk_bytes_written": info.ri_diskio_byteswritten,
            "disk_bytes_read": info.ri_diskio_bytesread,
        }
    with open(f"/proc/{pid}/stat") as stat:
        fields = stat.read().rsplit(")", 1)[1].split()
    ticks = os.sysconf("SC_CLK_TCK")
    status = {}
    with open(f"/proc/{pid}/status") as source:
        for line in source:
            key, _, value = line.partition(":")
            status[key] = value.strip()
    io = {}
    with open(f"/proc/{pid}/io") as source:
        for line in source:
            key, _, value = line.partition(":")
            io[key] = int(value)
    kib = lambda key: int(status.get(key, "0 kB").split()[0]) * 1024
    return {
        "rss_bytes": kib("VmRSS"),
        "footprint_bytes": kib("VmRSS"),
        "peak_footprint_bytes": kib("VmHWM"),
        "cpu_seconds": (int(fields[11]) + int(fields[12])) / ticks,
        "logical_bytes_written": io["wchar"],
        "disk_bytes_written": io["write_bytes"],
        "disk_bytes_read": io["read_bytes"],
    }


def delta(before: dict, after: dict) -> dict:
    return {
        "cpu_seconds": after["cpu_seconds"] - before["cpu_seconds"],
        "logical_bytes_written": after["logical_bytes_written"] - before["logical_bytes_written"],
        "disk_bytes_written": after["disk_bytes_written"] - before["disk_bytes_written"],
        "disk_bytes_read": after["disk_bytes_read"] - before["disk_bytes_read"],
    }


class PeakSampler:
    """Sample resident memory every `interval` seconds while a workload runs."""

    def __init__(self, pid: int, interval: float = 0.25):
        self.pid = pid
        self.interval = interval
        self.peak_rss = 0
        self.peak_footprint = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        while not self._stop.is_set():
            try:
                current = sample(self.pid)
            except OSError:
                return
            self.peak_rss = max(self.peak_rss, current["rss_bytes"])
            self.peak_footprint = max(self.peak_footprint, current["footprint_bytes"])
            self._stop.wait(self.interval)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join()


def load_average() -> list[float]:
    return [round(value, 2) for value in os.getloadavg()]


def directory_bytes(path: str) -> int:
    """Allocated bytes under `path` (st_blocks), following no symlinks."""
    total = 0
    for root, directories, files in os.walk(path):
        for name in files + directories:
            try:
                total += os.lstat(os.path.join(root, name)).st_blocks * 512
            except FileNotFoundError:
                pass
    return total


if __name__ == "__main__":
    print(sample(int(sys.argv[1])))
    time.sleep(0)
