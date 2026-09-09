# Frozen dispatch preparation

This is source-only preparation. No VM command, container, native binary, or
Cargo process has been launched by this preparation.

Script: `/tmp/kasumi-small-native-vm-dispatch.py`

SHA-256: `c4a1f230bdc8a83418675aa58283627b80a78bc5537480bd620a11b96987de0a`

Validation so far: Python 3.12 AST parsing and five pure mock guard tests passed.
The tests prevent subprocess creation and exercise preserved/existing-container
preflight, exact environment admission, duplicate/changed environment rejection,
and read-only source mount validation. They did not execute the real dispatch.
The default invocation prints static configuration and performs no preflight or
mutation. Real execution requires root review and the explicit native lane grant.

After that grant, copy the reviewed script without altering it:

```sh
limactl copy /tmp/kasumi-small-native-vm-dispatch.py kasumi-production-arm64:/tmp/kasumi-small-native-vm-dispatch.py
```

Then execute inside the already running VM as root:

```sh
limactl shell --workdir / kasumi-production-arm64 sudo /usr/bin/python3 /tmp/kasumi-small-native-vm-dispatch.py --execute --expected-script-sha c4a1f230bdc8a83418675aa58283627b80a78bc5537480bd620a11b96987de0a
```

The actual dispatch must retain its host process/session identity and be polled
to terminal. Do not impose a host timeout shorter than the script's original
1500-second deadline plus its bounded cleanup interval. A host interruption or
SIGKILL cannot prove that container cleanup ran; inspect the retained exact
container ID/name and private dispatch receipt before any subsequent work.

The script exclusively creates
`/opt/kasumi-acceptance/3a8d512-small-standalone-001` with mode 0700. This parent is
the only writable host mount, mapped to `/results`; the native diagnostic uses
`/results/run`. Source, build output, and the reviewed runner are read-only bind
mounts. The parent contains actual installation keys, credential files, raw logs,
and private Docker inspections. Do not print or archive its contents wholesale.

Inputs are pinned in source: exact local Unix Docker socket, existing image ID,
runner SHA, completed build-report SHA, source commit, and input binary hashes.
The native runner independently verifies the build graph and copies/hashes each
binary before execution. No image pull, mutating retry, automatic resume,
container removal, or evidence deletion is performed.

Preflight records all existing container IDs as preserved context and rejects
only active containers. It does not change the three previously exited
containers. The created container must report exactly one instance of each
required environment setting: `GIT_CONFIG_COUNT=1`,
`GIT_CONFIG_KEY_0=safe.directory`, `GIT_CONFIG_VALUE_0=/source`, and
`PYTHONDONTWRITEBYTECODE=1`. The host-side client environment does not assign
`HOME` or inherit a remote Docker endpoint.

Each Docker/Git client has a private process session with a bounded original
deadline and verified drain before its output is read or hashed. Container
creation/start are each dispatched once. Lost create acknowledgment is resolved
only by inspection of the recorded unique name plus owner label and image; an
unverifiable or absent container remains an explicit uncertain failure. Cleanup
may stop/kill a previously verified immutable ID even if a later inspection is
temporarily unavailable. Its final state must confirm no running/paused/restarting
process and PID zero. Any forced container stop fails the diagnostic.

Create and terminal inspections are preserved exactly in private command-output
files with SHA-256 hashes. Container logs are collected privately only after
terminal drain. The stdout summary contains only status, the private receipt
path, and the cleanup boolean. SIGINT/SIGTERM handlers record cancellation and
defer all cleanup to ordinary control flow.

The original failed functional checkpoint remains failed. This diagnostic
contains 129 documents and does not establish 3 GiB capacity, HA correctness,
source-unavailable distributed recovery, performance, endurance, or production
release acceptance.
