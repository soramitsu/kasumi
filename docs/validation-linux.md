# Linux validation evidence

The refreshed Linux gate passed on frozen source
`28aeb80168d3ab02a0eec7bf2a0163a7cb99dbfd74adf596e849de17e1fa3c1d`:

- **188 workspace test entries passed**, with zero failures and two explicitly
  ignored external-service tests.
- Strict workspace Clippy with every feature and target, formatting, and all
  **six Python driver tests** passed.
- The separate actual OpenBao integration passed, bringing the Linux Rust total
  to **189 passing entries**.
- The current macOS storage test binary also passed the real MinIO fixture
  against the pinned Linux container.

The [machine-readable gate record](../benchmarks/results/linux-validation-20260905-listener/evidence.json)
contains the exact command, immutable image ID, process IDs, source hashes,
exit status, counts and log hashes. The source fingerprint was unchanged before
and after the run and matches the
[188-entry macOS workspace gate](../benchmarks/results/macos-validation-20260905-listener/evidence.json).
The complete [Linux output](../benchmarks/results/linux-validation-20260905-listener/full-gate.log)
includes every test and the real-service invocation.

## Environment and command

Validation uses only the dedicated local `kasumi-validation` Colima profile:
six CPUs, 16 GiB VM RAM, and a 40 GiB data disk. This run used macOS
Virtualization.Framework and virtiofs. The VM reports Ubuntu 24.04.4 LTS,
Linux `6.8.0-117-generic`, `aarch64`, and Docker 29.5.2. The Debian 12 container
uses Rust/Cargo 1.94.1 and immutable image ID
`sha256:67b357ce730a064aab665277d0dfaece94ab2ca0407ba4fe818b9f2d7fb40861`.

The container has six CPUs and a 14 GiB memory limit, with no additional swap
allowance. It reuses `target/linux-validation` and the existing Cargo registry
mount. Cargo runs offline with its native jobserver. The command is:

```sh
docker \
  --host unix:///Users/takemiyamakoto/.colima/kasumi-validation/docker.sock \
  --config /Users/takemiyamakoto/dev/kasumi/target/docker-validation-client \
  run --rm --cpus 6 --memory 14g --memory-swap 14g \
  --mount type=bind,source=/Users/takemiyamakoto/dev/kasumi,target=/workspace \
  --mount type=bind,source=/Users/takemiyamakoto/dev/kasumi/target/linux-cargo-registry,target=/usr/local/cargo/registry \
  -e CARGO_NET_OFFLINE=true \
  -e CARGO_TARGET_DIR=/workspace/target/linux-validation -w /workspace \
  sha256:67b357ce730a064aab665277d0dfaece94ab2ca0407ba4fe818b9f2d7fb40861 bash -c \
  'bash scripts/validate_linux.sh && cargo fmt --all --check && python3 -m unittest discover -s scripts -p "test_*.py"'
```

The gate ran in a detached OS session under `caffeinate`, with regular-file logs
and persistent status updates. It completed in 271.44 seconds using the warm
Cargo target and registry. The macOS gate ran concurrently on the host; bounded
process observations recorded Linux linker progress. The run was not restarted
and the source was not modified. These build observations are not database
performance measurements.

## Lifecycle and security coverage

The current gate verifies that a connection reset queued before startup and an
injected accepted-socket setup failure both produce an audit record without
stopping the TLS listener. A subsequent authenticated TLS request succeeds.
Listener-level accept I/O failures still drain active requests before exit.
These tests exercise the connection-local `TCP_NODELAY` failure observed during
the retained sixth matrix; they do not replace the required million-document
rerun of that matrix.

It also verifies durable denials at every embedded API boundary,
including sealed tenants and standalone restore before a database exists.
Repeated audit opens share one durable sequence; cloned writer handles cannot
bypass ownership, and uncertain persistence fences later writers until recovery.
Canceled denial/audit work is drained before immediate file reopen. The audit
store has separate encryption and key authorization from customer tenants.
Network adapters preserve those engine records without duplicating them.

It also includes the Raft storage-ownership drain, canceled blocking
persistence, same-store group fencing, terminal key-store shutdown, and repeated
immediate database reopening with receipts and retained plaintext handles.
It also covers work-registration lifetime, successful request completion during
listener shutdown, and nested TLS connection draining after an injected accept
I/O error. See the [shutdown investigation](shutdown-investigation.md) for the
precise reproductions and their limits.

Existing coverage includes three-node partitions and recovery, quorum read
barriers, concurrent historical pagination, native/MCP lost-response resolution,
exact queries, multilingual indexing, authentication, authorization, audits,
key rotation and backup/restore. This software gate does not establish that the
full million-document capacity matrix passes. In particular, the retained
[fourth matrix](../benchmarks/results/release-matrix-macos-arm64-20260905-04/matrix.json)
records both a read deadline failure and an immediate-reopen ownership failure;
passing focused lifecycle tests must not erase those observations or stand in
for a fresh full-size run.

## Actual services and cleanup

OpenBao 2.6.2 ran on Linux during the full script. Its integration covers
Transit encryption/decryption, key rotation, encrypted backups and warm-state
revocation. The fetcher verifies the Linux arm64 release archive against
`1b408e01f3565ac0cbcb88d637dca271d0515148fb72efdeff4473a34fa50c4e` before
extracting its regular `bao` member to a fixed destination.

The [current MinIO evidence](../benchmarks/results/linux-validation-20260905-listener/minio-evidence.json)
and [test output](../benchmarks/results/linux-validation-20260905-listener/minio-live.log)
record a macOS arm64 client against the official Linux arm64 container. The
client was built by the passing macOS gate above; its SHA-256 is
`0c6b41dd14fd540a7cd5bcd72989f1b94efc0a1ebe756b89abf285f84404d967`.
The immutable MinIO image is
`minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e`.
The fixture verifies TLS, SigV4, encrypted round-trip, create-only writes and
access denial with temporary credentials and bounded container resources.
Its source and executable hashes were unchanged across the run. This is
interoperability evidence for those implementations, not a claim of testing a
Linux MinIO client, a live HashiCorp Vault deployment, or every S3 provider.

Both fixture containers exited and the Docker inventory was empty. The
validation wrapper and clients exited; only the dedicated `kasumi-validation`
profile was stopped before benchmarking. The profile and VM stop are recorded
in [cleanup evidence](../benchmarks/results/linux-validation-20260905-listener/colima-stop.log).
Other profiles remained stopped and were not modified.

## Retained earlier evidence

The [previous 186-entry embedded-audit gate](../benchmarks/results/linux-validation-20260905-embedded-audit/)
remains available. The [earlier 177-entry shutdown gate](../benchmarks/results/linux-validation-20260905-shutdown/)
remains available. The [earlier 167-entry gate](../benchmarks/results/linux-validation-20260905-barrier/)
and its subsequent Python guard supplement remain available. Earlier
[157-entry, MinIO and static systemd evidence](../benchmarks/results/linux-validation-20260905-final/)
and [initial attempts](../benchmarks/results/linux-validation-20260905/)
are retained as history. They do not replace the refreshed gate.

The unchanged `deploy/kasumi.service` previously passed `systemd-analyze verify`
with Debian systemd 252.39 and the Linux executable at its declared path. No
service was installed or started. That check covers unit syntax and executable
references; production boot, filesystem guarantees and KMS configuration remain
properties of the selected deployment.
