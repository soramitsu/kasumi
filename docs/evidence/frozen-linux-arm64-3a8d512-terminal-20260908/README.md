# Frozen Linux ARM64 3a8d512: failed functional checkpoint

Rust 1.97.1, native ARM64 VZ Debian 13 VM, 2 CPU, 16 GiB provisioned RAM;
actual build container CPU2, 15 GiB memory and no additional swap. The pinned
build image and actual container creation, running and terminal records are retained.

Workspace: **545 passed, 1 failed, 2 ignored** across 45 completed groups.
The three-node runtime test failed at runtime.rs:4177 while reopening the restored
installation: `Database already open. Cannot acquire lock.` Its server test group
had 82 passes and one failure. This failure is not waived.

All other gates passed, including workspace doctests, strict workspace Clippy,
fixture-free native client drivers and production server binaries. Production
build took 611.140 seconds on this observed shared host. This is a functional
measurement, not a performance claim. The failed workspace prevented packaging;
no candidate, repeated package comparison or packaged release artifacts were produced.

Every gate has its raw log, exact command, source/tree/lock identity, compiled
feature graph, executable hashes and before/after visible cgroup records. The
container exited1 with PID0 and OOMKilledfalse. The cumulative cgroup memory peak
was 15,979,606,016 bytes under a 16,106,127,360-byte limit, with no recorded OOM
or swap. Those counters include cache and are not isolated per-test measurements.

`summary.json` points to the preserved source archive, complete target directory,
and the copied evidence archive. All copied log/resource hashes were checked
against the frozen runner record. The source archive remains outside Git to
avoid embedding another complete historical repository inside its own evidence.
`copied-files.json` binds the retained files. The public copy of
`host-demo-overlap-processes.txt` redacts unrelated project names, local paths
and command arguments, retaining the observed process and resource columns.
Its entry in `copied-files.json` hashes the redacted copy; it is not a byte-for-byte
copy of the original host observation. Failed gates and preparatory-copy
limitations remain explicit.

An independent source review found an archive worker could upgrade its storage
owner before registering shutdown-tracked work. A separate patch is under
validation. This source observation does not prove it was the sole owner behind
the Linux lock failure; corrected-source regression and runtime gates remain due.
