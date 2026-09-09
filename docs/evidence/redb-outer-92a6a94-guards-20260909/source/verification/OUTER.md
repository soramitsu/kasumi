# Private Linux verification owner

Status: source implementation only. No Docker daemon, image build, container,
loop device, mount, VM, Rust build, upstream test, or fuzzer was executed while
writing this harness. Python 3.12 ran the 14 preparation/ownership guard tests
successfully. An earlier invocation used the host's Python 3.9 and failed six
preparation-test checks because `hashlib.file_digest` requires Python 3.11+;
seven new ownership tests passed in that failed invocation. The original tool
output retains those failures; there is no reconstructed raw-log artifact.
These Python results establish only the guards they exercise.

`outer.py launch` requires root in the dedicated Debian Linux reference VM,
Python 3.11+, systemd with cgroup-v2 delegation, Docker/BuildKit, util-linux,
e2fsprogs, and Git already installed. It never installs host tools. The backing
owner directory must already be a canonical root-owned mode-0700 directory on
ext4, without links, whitespace, or mount-list separators. The source checkout
must be clean and at the exact full commit provided. Compute the expected SHA-256
of that commit's unmodified `git archive --format=tar` independently, then invoke:

```
python3 -B verification/outer.py launch \
  --parent /opt/kasumi-verification \
  --source /opt/redb-frozen \
  --commit FULL_COMMIT_SHA \
  --archive-sha256 EXPECTED_ARCHIVE_SHA256
```

The launcher creates one UUID directory and one transient systemd service. Its
8 GiB memory/no-swap limit includes the observer, private Docker daemon, managed
containerd processes, BuildKit jobs, and offline containers. The service delegates
CPU/memory/PID controllers; Docker uses only its declared child cgroup. Both the
builder and offline containers receive the same explicit cgroup parent. Unsupported
host configuration or flags fail rather than selecting another backend.

The owner preallocates a fixed 40 GiB regular file, records its inode/device,
attaches that exact file to one loop device, formats only the checked fresh
binding, and mounts private ext4 with nodev/nosuid. Docker data/exec roots, its
client config, source archive/context, targets, Cargo home, temporary workspace,
corpus, crash artifacts, and raw logs are beneath that filesystem. A private
socket replaces the shared Docker daemon. No shared image, target, cache, mount,
container, or global pruning command is used. The fixed image is retained even
on success. A full filesystem fails the gate; bounded owner status remains in
the external private directory.

Preparation has the original 30-minute deadline. The test phase has 45 minutes,
fuzz compilation 20 minutes, and fuzz smoke 90 seconds for its declared 60-second
libFuzzer run. These deadlines include their phase setup and inner input/artifact
checks. A systemd runtime deadline covers blocking preparation and observer loss;
individual process-group deadlines remain independently recorded. The launcher
also verifies the service and its entire cgroup have stopped, even if the Docker
client already exited. It does not infer container drain from client exit.

Each offline container is selected by immutable image ID, has no network,
a read-only root, no capabilities, no-new-privileges, and exact private bind
mounts. Its UUID label, full container ID, image, cgroup parent, memory limits,
and every mount must match. `/opt/verification/advisory-db/db.lock` is the sole
writable advisory path. The inner verifier checks all prepared source, vendor,
advisory contents/timestamps, and tool executable hashes before and after each
phase. It initializes Cargo home using only the prepared registry index and
vendor configuration. It retains Cargo artifact features, executable hashes,
all test summaries, the actual `value_too_large` success, and the actual fuzzer
executable, corpus, and crashes. No upstream scope is filtered or relaxed.

The copied `gate_process.py` is byte-identical to Kasumi's source helper with
SHA-256 `6c8b255e5a69aa8985da8d70f5baa73337bcaeac7098bd756c4d6cc6472e58de`.
It supervises local CLI process groups. The outer owner separately inspects and
stops the declared container, drains the daemon group and delegated descendants,
then synchronizes and detaches only the verified private filesystem/device.
Resource receipts include raw parent cgroup memory current/peak/events/stat and
PID counts at observation boundaries; peaks are cumulative, not independently
reset per phase. They include filesystem use and host/kernel/tool hashes.
This is not evidence of non-overlap, performance isolation, or measured capacity.

SIGKILL, observer death, or uncertain cleanup cannot manufacture success. The
owner image, metadata, and any uncertain mount remain for inspection. A same-boot
cleanup-only command can stop the original verified unit, prove its recorded
cgroup empty, and detach its exact loop binding:

```
python3 -B verification/outer.py recover /opt/kasumi-verification/RUN_UUID
```

This never resumes preparation or a failed phase. Boot changes, unexpected mount
aliases, unknown allocation outcomes, residual mounts, or identity substitutions
retain failure and require inspection. It never deletes images or unrelated
files. In particular, residual Docker overlay mounts after forced daemon death
may make unmount fail; this remains an explicit undrained cleanup failure rather
than authorizing recursive unmounts or deletion.

The Linux integration gate remains required: prove the chosen installed Docker
version honors the declared cgroup parent for preparation, exact loop/UUID
inspection works, source/advisory timestamps survive image construction, normal
and forced-stop paths drain, and a genuinely offline full test/fuzz run passes.
Until that executes, the runner is not validated for production acceptance.

Run only the unprivileged guard suite locally:

```
python3.12 -B -m unittest discover -s verification -p 'test_*.py' -v
```

The ownership tests cover wrong owner/version/source IDs, path aliases/modes,
container image/isolation/cgroup/mount substitutions, loop inode/device/extent
substitutions, bounded atomic status replacement, and archive traversal/link/
duplicate rejection. They do not mock a successful Docker or test lifecycle.
