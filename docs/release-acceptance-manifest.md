# Final release acceptance manifest

`scripts/verify_release_acceptance.py` is a read-only layer above candidate
packaging. It checks the first-release evidence contract; it does not build,
run workloads, manufacture receipts, remove failed attempts, or grant waivers.
The approved scope remains [the release plan](first-release-plan.md) and
[G01–G14](first-release-goals.md).

**No final release can currently pass this verifier.** The domain-adapter
registry is deliberately empty. None of the existing domain runners produces
all the evidence needed for its final-release gate. An opaque report saying
“passed,” a list of successful scenario names, or an arbitrary frozen source
file used as a purported runner is rejected. The structural validators and
their counterexample tests are implementation progress, not closure of G11,
qualification evidence, or permission to close the release goal.

## Invocation and custody

Run Python 3.11 or newer from the exact, clean final source checkout:

```sh
python3 scripts/verify_release_acceptance.py /absolute/evidence/acceptance.json \
  --repository /absolute/frozen-checkout
```

The evidence bundle belongs outside the checkout. Keep its original failed
and interrupted attempts. Stop all writers before verification and preserve the
bundle immutably afterward. Success is reported to stdout; rejection exits 1
and does not rewrite any input. There is no reduced, force, historical,
fixture, emulation, missing-gate, or shorter-soak acceptance mode.

The returned manifest SHA256 belongs to the exact bytes parsed. Every observed
file reference is rehashed before success, including transitive functional
logs, process receipts, resource records, source files, and executables. The
clean Git source and source identity are checked again. Concurrent changes
reject verification. These checks do not replace exclusive evidence custody
or authenticate a dishonest evidence producer.

## Canonical schema

The only accepted top-level schema is `kasumi-release-acceptance-v1`, with
exactly these fields:

| Field | Meaning |
| --- | --- |
| `schema` | The literal schema identifier above. |
| `source` | Exact clean Git commit/tree, Git archive, source inventory, lockfile, complete vendor inventory, and installed configuration files. |
| `candidates` | Exactly three native platform entries, each with primary functional evidence and an independent production compilation. |
| `gates` | The fixed 27 domain gates below, each binding its identifier to a hashed receipt. |
| `artifacts` | The fixed 25 deliverables below. |
| `attempts` | Every retained attempt, including failed/interrupted attempts and every selected result. |

Identifiers must be nonempty and unique. Duplicate JSON keys, nonfinite
numbers, booleans used as integer sample counts, unsupported fields in typed
records, and unsupported schema versions are rejected. JSON documents are
limited to 16 MiB; sample streams use JSONL with a 1 MiB maximum line. Counts
must fit unsigned 64-bit integers. No compatibility decoders are provided.

A file reference has exactly `path`, `sha256`, and `bytes`. Paths are canonical
POSIX relative paths inside the bundle, with no absolute paths, `..`, `./`,
backslashes, repeated separators, or symlink components. The file must exist,
be regular, and match both SHA256 and byte length. The source archive and
package readers reject links, special files, duplicate members, and escaping
paths without extracting the package. Hashes use lowercase hexadecimal.

`source` has `commit`, `tree`, `archive`, `files`, `lockfile_sha256`,
`patches_sha256`, and `configurations`. `archive` is the original `git archive
--format=tar` of the claimed commit. `files` is the `release_gate.py` inventory
of `{sha256, bytes, executable}` by source-relative filename and must match the
actual Git archive. `patches_sha256` hashes every inventory entry below
`vendor/`, including patch manifests and retained dependency source. Each
configuration has exactly `id` and a `file` reference. Keep private material
under the installation/evidence owner's controls; do not publish credentials.

Every domain receipt carries this exact `identity` object:

```text
source_commit
source_tree
source_archive_sha256
source_files_sha256
lockfile_sha256
patches_sha256
configurations_sha256
```

The last digest hashes `{configuration_id: actual_file_sha256}`. Aggregate
hashes use UTF-8 JSON with sorted keys, separators `,` and `:`, and no nonfinite
values. The executing verifier, package verifier, functional runner, and
process helper must themselves match the frozen source inventory.

## Native candidates and independent builds

The platform identifiers are exactly:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `aarch64-apple-darwin`

Each primary build reuses `package_release.verify_evidence`. Its complete
19-gate roster and commands come from frozen `release_gate.functional_gates`:
toolchain, formatting, Python checks, patch provenance, all retained patched
dependency variants, full workspace/all features/all targets, doctests,
strict Clippy, network feature isolation/build, and fixture-free production
feature isolation/build. All 57 native functional gates must pass. Native
executable headers and actual `kasumid`, `kasumictl`, and `kasumi-authority`
hashes are checked.

The rmcp gates include all new terminal-ownership regressions and six upstream
protocol/header/JSON/discovery suites. This minimum functional roster does not
by itself complete dependency review or qualify untested upstream features.

A candidate has `platform`, `primary`, and `independent`. Its `primary` object
has `functional` (reference to the original `evidence.json`), `host`, `build_id`,
`build_root`, `environment_id`, and `fresh_build_root: true`. The independent
field references a separate typed production-compilation receipt. That receipt
requires the same source/lock/toolchain, the exact fixture-free Cargo production
command, retained compiler dependency/features inventory, drained process,
actual binaries, and byte-for-byte equality with the primary binaries. Its
`build_id`, absolute `build_root`, and `environment_id` must differ from the
primary. It may use the same physical host. It need not rerun the full test
suite, and a copied primary output is not an independent compilation.

Every native execution records physical and execution architecture, an explicit
non-emulated claim, the original `release_host.py` preflight, an operator or
hypervisor attestation, and a reservation covering its start through finish.
The reservation identifies CPUs, at least 15 GiB effective memory, and at least
64 GiB disk. Record physical architecture as `aarch64` or `x86_64`, including
macOS ARM64. Host claims and reservations require real operator/host evidence;
the verifier cannot infer physical architecture from a guest's `uname` alone.
Shared-host and software-only failure-domain limits must be published.

Functional evidence records the original absolute Python path and SHA256 and
retains its executable bytes under `tools/python`. Both Python gates must bind
their actual dispatched executable to that identity. Verification reconstructs
commands from the recorded interpreter, so it does not need the originating
host's interpreter path to exist locally. Missing interpreter identities are
rejected; earlier evidence must be rerun against the final source.

The process helper resolves an executable once against the child's working
directory and PATH, preserves its invoked basename, records its bytes' SHA256,
and dispatches that selected path. It checks the identity again after the
original process group drains. Interpreter libraries, Rustup-selected toolchain
children, container dispatch, and domain-specific executable inventories still
need their complete production runner bindings; this process record alone does
not establish those identities.

## Fixed domain gates

Gate identifiers are `kind:platform`. The following placement is mandatory:

| Platforms | Required kinds |
| --- | --- |
| All three native platforms | `installed`, `package-smoke`, `repeatable-assembly` |
| Both native Linux platforms | `oci-smoke`, `systemd-smoke` |
| Native Linux ARM64 reference deployment | `correctness`, `providers`, `ha-faults`, `recovery`, `audit-retention`, `backup-cleanup`, `key-retention`, `observability`, `capacity-standalone`, `capacity-ha`, `benchmark-matrix`, `concurrency`, `ha-soak`, `dependency-review` |

`SCENARIOS` in the frozen verifier defines each complete scenario roster.
Recovery covers crashes and cancellation in all preparation, materialization,
initialization, source-fencing, activation, confirmation, route-publication,
permanent-stop, issuer-drain, gate-closure, worker/storage-drain, exact-deletion,
parent-sync, and durable-evidence phases. It also requires absent source quorum,
separate source/target authorization, one activation winner, forward completion,
physical bindings, and unrelated-file isolation.

A domain receipt has `schema`, `id`, `status`, `identity`, `binaries`,
`configuration_ids`, `runner`, `started_at`, `finished_at`, `host`, `processes`,
`topology`, `scenarios`, `details`, and `artifacts`. The binary map must equal
the actual qualified platform candidate. Configuration IDs must exist in the
source-bound configuration inventory. A scenario has `id`, `status`,
`iterations`, `failures`, `unattempted`, and a log reference. Archive outage,
late upload, and repeated namespace cleanup require at least three iterations.
These fields describe the required structure; they are insufficient to pass
without a registered semantic adapter.

HA gates require nine distinct owned processes: three each for data, Control,
and authority, with three separate group identities and nine distinct TLS
certificate hashes. Each process must reference the appropriate candidate
daemon bytes. Lease outages must exceed the recorded lease lifetime; recovery
must demonstrate less than a source quorum and exactly one activation winner.
Real provider evidence must identify actual owned OpenBao and MinIO processes,
versions, and executable hashes.

## Workload completeness

The structural workload validators enforce:

- All 15 combinations of raw/local/replicated/text/network and 1/100/1,000
  tenants, each with exactly one million documents. Non-raw cases require
  production providers. Each named workload needs at least 1,000 attempted and
  successful operations, zero failed/unattempted operations, and every numbered
  latency sample. Network cases require both gRPC and MCP, reads, writes, mixes,
  and complete query pages. Text cases retain all four language/search variants.
- Concurrent read/write, backup/write, snapshot/write, and membership/write
  workloads, each with at least two workers and measured concurrent operations,
  plus the same full sample accounting.
- Standalone and HA corpora **strictly exceeding 3 GiB**. Every required
  snapshot, compaction, restart, filesystem/S3 backup/restore, retained-read,
  and HA follower-replacement operation needs exhaustive contiguous integrity
  batches of at most 256 documents, matching hashes, complete bytes, and
  multiple actual RSS/disk/workspace samples within recorded limits.
- A full-corpus `gzip-9` compression measurement whose output/input ratio is at
  least 0.75, suitable for the existing printable-ASCII capacity corpus. This
  explicit gate threshold is not an entropy proof. Maintenance workspace and
  retained-read budget must each be at most one quarter of the measured corpus.
- A genuine **86,400-second** HA soak, bounded by wall time and a retained process
  of at least that duration. Heartbeats begin at zero, have no gap above 60
  seconds, show continued successful workload, and end at the actual duration.
  Unexpected errors and integrity mismatches must remain zero. Credential
  renewal, archival, backup, and membership maintenance must occur during it.
- Archive segments no larger than 8 MiB, maintenance at 75% toward 50%, measured
  crossings of all permanent-history lifetime categories, key-retention pages
  no larger than 256, and complete current-epoch readiness above 128 groups.

Latency sample rows contain `sequence`, `elapsed_ns`, and `status`. A
measurement declares `name`, `requested_operations`, `attempted_operations`,
`successful_operations`, `failed_operations`, `unattempted_operations`, and
the raw `samples` file. Missing/truncated/duplicate samples cannot be replaced
by a percentile summary. The existing benchmark report's summaries and
fixture-based matrix do not satisfy this contract.

## Process and failed-attempt evidence

Every owned process has an ID plus `receipt`, `log`, and `executable` file
references. Its receipt carries `gate_process.py` ownership/drain fields and
an additional `executable: {path, sha256}` identity measured at dispatch.
`command[0]` must equal that absolute executed path, and the hash must match
the retained executable. Successful gates reject timeout, interruption,
forced cleanup, uncertain census, surviving children, or nonzero outcomes.
Domain adapters must additionally reconstruct and compare the exact command,
arguments, configuration files, artifacts, and service inventory they own.

The existing generic process runner does not yet record this extra dispatch
identity for domain/rebuild attempts. Extend the actual runner; do not retrofit
claims into historical receipts. Process groups do not prove custody of
daemonized or remote services. Domain adapters must preserve those services'
actual terminal outcomes too.

Each permanent attempt occupies `attempts/<id>/attempt.json`. The manifest
indexes every on-disk attempt receipt. It has schema/id/status, evidence,
start/finish, and processes. Failed/interrupted attempts may retain nonzero
outcomes, but their custody must be terminal and drained. They cannot be
selected as successful gates. Every selected primary, independent build, and
domain result must appear in the attempt index. The verifier never deletes,
rewrites, or upgrades a failed attempt. Evidence custody must also preserve
attempts outside the bundle; a local verifier cannot discover withheld history.

## Deliverables and remaining adapters

The fixed artifact roster includes source/checksums/license/notice,
contribution/security/installation/maintenance/recovery/operating-limits
documents, both systemd units, and each platform's package, dependency SBOM,
and third-party notices. It also requires both Linux OCI images and image
SBOMs. Packages must contain the exact candidate binaries and source-bound
legal/systemd files, the delivered dependency SBOM/notices, and candidate-bound
provenance. Delivered source must exactly match the frozen inventory.
Checksums cover every other delivered file exactly once. Smoke receipts must
bind the actual package/image/unit digests; repeat assembly must produce
distinct files with identical package and source hashes.

Before enabling any domain adapter, implement and review its actual runner,
fixed executable/argument/configuration/artifact contract, and semantic parser.
Required work includes the installed full lifecycle, real providers, complete
HA faults/recovery/deletion, retention races, exhaustive resource/integrity
measurements, complete production benchmark samples/concurrency, full soak,
advisory dispositions, and actual package/OCI/systemd smoke. OCI adapters must
verify the image's platform, manifest/layer identities, contained candidate
binaries, and matching OS/image SBOM; hashing an arbitrary archive is
insufficient. Dependency review must parse the actual advisory scan and every
disposition rather than accept an opaque “reviewed” report. Independent-build
collection must bind compiler outputs to its recorded command and isolated
environment, not only assert an inventory.

Tests intentionally use synthetic temporary fixtures to challenge validators.
They do not produce or commit a populated acceptance manifest. The empty
adapter registry ensures incomplete domain integration cannot accidentally
turn those structural checks into a production release claim.
