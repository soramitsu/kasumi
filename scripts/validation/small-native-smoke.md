# Small standalone native diagnostic

`scripts/small_native_smoke.py` exercises an existing, fixture-free production
build with 129 documents, each 1024 canonical bytes. It does not compile software
or establish release acceptance, HA correctness, 3 GiB capacity, performance or
endurance. A passing diagnostic of a failed functional checkpoint does not
change that checkpoint's failed result.

The runner initializes a new private standalone installation, waits for protected
readiness over pinned TLS 1.3 with mTLS, creates a collection, loads and verifies
the entire corpus, renews its credential, and reads an exact document through
MCP. It then creates and verifies an encrypted filesystem backup, restarts and
verifies the corpus, performs stopped-instance local recovery, and verifies the
new generation through native and MCP access. The still-unexpired old resource
credential must receive an explicit native authorization denial; a connection
failure, timeout or missing driver journal cannot pass that check. A final
successful read confirms the rejection did not alter the recovered corpus.

Local recovery uses the exact authenticated checkpoint, independent source
purpose and installed source key provider. Its outcome must be `finished` with
`exclusive_local_installation` fencing scope. This diagnostic does not claim
that another independently running copy is fenced. Credential rotation,
revocation, renewal watcher endurance, operator key recovery, S3 and recovery
crash injection remain separate gates.

## Inputs and execution

Use Python 3.11 or newer, Git, and the same Unix architecture and runtime libraries
as the supplied native binaries. An isolated Linux reference environment with
outbound networking disabled provides the offline boundary. The runner uses
loopback endpoints, removes inherited proxy variables, and makes no external
service requests; it does not itself install a host firewall or network namespace.

Provide the completed `scripts/release_gate.py` report and its actual
`kasumid`, `kasumictl` and `kasumi-bench-capacity` binaries. The report must bind
the exact source commit, Git tree, `Cargo.lock` SHA-256 and Rust 1.97.1 toolchain.
Both the production and network-driver compilation gates must have passed,
with nonempty actual compiled-feature inventories and no fixture features.
The runner copies and hashes each executable before running that private copy.
Pending, interrupted or missing build evidence is rejected. The overall
functional run may be `failed`, and that status remains explicit in the result.

The current runner requires the exact source objects in a Git repository. It
reads the lockfile and collection schema from that commit, without changing the
checkout. An extracted source directory alone is rejected; there is no fallback
that accepts an unverified `--source` label. Read-only mounts of the source
repository and build output are supported.

Provide `--directory-policy` pointing at the explicitly qualified directory policy
for the filesystem used by this diagnostic. Its two positive integer fields are
`extent_bytes` and `max_entries`; this runner supplies no production defaults and
does not establish filesystem qualification. It retains the exact input bytes and
hash and requires the generated installation to contain the same policy. Use
only binaries built from the current required-policy API; historical checkpoints
remain historical evidence and are not accepted through a compatibility path.
The runner reserves three loopback ports before `kasumid init`, supplies them in
the required strict `--network` file, retains that file in provenance, and
checks the generated configuration and profiles. It does not rewrite endpoints
after immutable Control genesis.

```sh
python3 /opt/kasumi-tools/small_native_smoke.py \
  --binaries "$RELEASE_BINARIES" \
  --build-evidence "$BUILD_EVIDENCE" \
  --directory-policy /etc/kasumi/directory-policy.json \
  --source "$RELEASE_COMMIT" \
  --repository "$SOURCE_REPOSITORY" \
  --output "$NEW_EVIDENCE_DIRECTORY" \
  --execution-description 'Native Linux in the recorded isolated validation environment; outbound networking disabled'
```

The description must match the actual environment. The parent directory must
exist. Output must be a new absolute directory outside the repository. Default
command, readiness and graceful stop timeouts are 180, 90 and 90 seconds;
overrides are recorded in `timeouts_seconds` and must be within 1–600 seconds.
Native endpoints are allocated from three temporarily held loopback sockets.
Because the binaries cannot inherit those sockets, a later bind race fails the
run and is retained rather than retried with another configuration.

## Evidence and owned cleanup

The output directory is mode 0700 and **contains real installation keys and
credentials**. Keep it private and do not publish or archive it wholesale as
public release evidence. Initial and final inventories contain file metadata
and SHA-256 hashes rather than file contents. Review even these inventories and
logs before sharing. The installation and completed backups remain available
after success or failure; the runner does not delete recovery evidence.

`evidence.json` records the runner hash, source and build identities, original
functional result, actual platform and Python/OpenSSL versions, exact executable
hashes, commands, return codes, separate stdout/stderr hashes, corpus results,
TLS leaf pins, readiness observations and cleanup outcomes. The copied build
report and lockfile live under `provenance/`. The native driver independently
records its own executable/configuration hashes and full-corpus digest. The
runner checks those bindings and compares the digest across lifecycle changes.

Every subprocess, including read-only Git commands, receives a private process
session and a bounded wait. SIGINT, SIGTERM, timeout and failed commands trigger
cleanup of only the process groups created by this runner. Forced termination,
incomplete process drain or log synchronization errors fail the diagnostic.
Stopping a leader does not count as draining a surviving descendant. SIGKILL of
the runner itself cannot execute cleanup; inspect its recorded owned PIDs and
isolated environment before any subsequent run. Never kill a process by name or
repurpose an existing installation to recover this diagnostic.

Mutating CLI requests are not retried with new identities. Backup creation and
local recovery persist their own exact command/session identities. If a command
times out or local recovery remains incomplete, this runner fails and preserves
the installation and original request; explicit operator diagnosis and resume
are separate actions, not a retroactive passing result.

## Runner checks

The pure tests mock every subprocess and HTTP call. They open no network
listeners and execute no Kasumi binary or Cargo command:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s scripts -p test_small_native_smoke.py -v
```

These counterexamples check build provenance, exact corpus vectors, authorization
failure classification, local recovery scope, private atomic files, readiness
and owned process cleanup. They do not replace the first actual Linux diagnostic.
