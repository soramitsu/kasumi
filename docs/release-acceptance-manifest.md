# Final release acceptance manifest

`scripts/verify_release_acceptance.py` is a read-only layer above candidate
packaging. It checks the first-release evidence contract; it does not build,
run workloads, manufacture receipts, remove failed attempts, or grant waivers.
The approved scope remains [the release plan](first-release-plan.md) and
[G01–G14](first-release-goals.md).

**Release acceptance remains open.** The verifier registers all 19 domain
adapters. Each checks a native run against its scenarios and the selected
candidate, configuration and artifact identities. The current qualification
results and outstanding placements are recorded in the
[release integration ledger](first-release-integration-20261118.md).

| Area | Registered domain IDs |
| --- | --- |
| Installed software and artifacts | `installed`, `package-smoke`, `oci-smoke`, `systemd-smoke`, `repeatable-assembly` |
| Data, operations and security | `correctness`, `concurrency`, `observability`, `backup-cleanup`, `audit-retention`, `key-retention`, `providers`, `dependency-review` |
| Capacity, fault recovery and endurance | `capacity-standalone`, `capacity-ha`, `benchmark-matrix`, `ha-faults`, `recovery`, `ha-soak` |

The verifier takes the domain IDs from its scenario registry. The attempt
index restricts OCI and systemd smoke to Linux. A passing unit test or
source build supplies only the evidence it actually observed.

## Invocation and custody

Run Python 3.11 or newer from the exact, clean final source checkout using an
isolated interpreter with site imports and bytecode writes disabled. Leave
`PYTHONPYCACHEPREFIX` unset. The verifier rejects an existing local Python
bytecode cache before importing its helpers, including timestamp-valid and
unchecked-hash `.pyc` files:

```sh
python3 -I -S -B scripts/verify_release_acceptance.py /absolute/evidence/acceptance.json \
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
values. The executing verifier, package verifier, functional runner, process
helper, native assembly input parser, and permanent attempt-index reader must
themselves match the frozen source inventory and load from the verifier's source
directory.

## Native candidates and independent builds

The platform identifiers are exactly:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `aarch64-apple-darwin`

Each primary build reuses `package_release.verify_evidence`. The frozen
`release_gate.functional_gates` defines its 22 commands, covering
toolchain, formatting, Python checks, patch provenance, all retained patched
dependency variants, full workspace/all features/all targets, doctests,
strict Clippy, network feature isolation/build, and fixture-free production
feature isolation/build. All 66 native functional gate results must pass.
The acceptance manifest also requires 27 target results across 19 domains.
The verifier checks native executable headers and the actual `kasumid`,
`kasumictl` and `kasumi-authority` hashes.

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
The verifier reconstructs the independent package, feature, and target inventory
from the retained Cargo JSON compiler-artifact log. It requires exactly the three
production binary emissions at `build_root/target/release/<name>` and checks the
retained binary references under `target/release/`. A declared inventory or
copied binary without the original owned compiler transcript is rejected.

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

For the Linux ARM64 `ha-faults` run, allocate a local advertised HTTPS endpoint
and a separate `replication.listener.listen` socket for each of the three Data
voters. Keep the advertised URLs and certificate pins in the enrolled peer
roster. The runner binds those advertised endpoints and passes the original
TLS streams to the installed listeners. The runner must be able to read the
socket descriptors of the nine processes it starts. During the cut it records
the two blocked outbound paths from the isolated leader and incoming traffic
from the new majority, polls the isolated member's protected administration
endpoint, verifies a committed majority write, then checks the original
member's applied index after reconnection.

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
  multiple actual RSS/disk/workspace samples within recorded limits. Each operation
  references its original installed `verify` events and integrity journal. The
  verifier replays each prefix and binds the complete observed digest to the
  measured corpus, driver, platform and integrity file.
- A full-corpus `gzip-9` compression measurement whose output/input ratio is at
  least 0.75. Reference the capacity driver's original `measure` events journal.
  The verifier matches its seed, document count, canonical size and measured output
  to the submitted totals. Maintenance workspace and
  retained-read budget must each be at most one quarter of the measured corpus.
- A genuine **86,400-second** HA soak, bounded by wall time and a retained process
  of at least that duration. Heartbeats begin at zero, have no gap above 60
  seconds, show continued successful workload, and end at the actual duration.
  Unexpected errors and integrity mismatches must remain zero. Credential
  renewal, archival, backup, and membership maintenance must occur during it.
  Configure the HA installation's external OAuth issuer to refresh the workload
  profile's private bearer file before each 1,500-second session rotation.
  The runner takes a baseline and uses `kasumid credential observe <database-profile>`
  to authenticate the exact bearer against the pinned native listener at each
  rotation. The retained profile digest stays constant. Success requires a
  different bearer digest and a later expiration after every renewal.
- Archive segments no larger than 8 MiB, maintenance at 75% toward 50%, measured
  historical count crossings and the permanent backup-session floor, key-retention pages
  no larger than 256, and complete current-epoch readiness above 128 groups.

The audit-retention component collector runs the installed nine-process
observation and the frozen engine, Raft and Authority tests on native Linux ARM64. Use
the admitted topology, fresh enrolled profiles for one tenant incarnation
and a new custody directory outside the functional evidence. The audit plan
uses schema `kasumi-audit-replica-v1` and absolute `data_profile` and
`operator_profile` paths. The installation stage runs first so it can use the
enrolled credentials while they are fresh. An ordinary failure in either
stage preserves its receipts and allows the independent stage to run.

```sh
python3 -I -B -S scripts/observe_audit_retention.py collect \
  --evidence "$functional" --custody "$new_custody" --journal "$journal" \
  --attempt-id "$attempt" --topology "$nine_member_plan" --plan "$audit_plan"
python3 -I -B -S scripts/observe_audit_retention.py replay \
  --evidence "$functional" --custody "$transported_custody"
```

Replay checks both original reports against the supplied functional tree,
recomputes their observations from original process output and checks the
combined report. It records measured archival, outage, replica and replacement
scenarios and the measured command, receipt, lifecycle and incarnation counts.
The Authority witness enrolls distinct tenants, drains and reopens the encrypted
database, verifies every incarnation against its original receipt, and replays the
first and last enrollments. The historical Authority manifest before commit
`04f8c199` capped receipts at 100,000 and required each accepted incarnation
to have a receipt. The other former limits are 4,096 commands, 100,000
mutation receipts and 10,000 lifecycle intents. Each count must exceed its
own limit. The backup-session entry carries `acceptance_floor: 100001`,
the observed distinct count and its original log reference. Its count must
meet or exceed that floor. The full gate requires the cold-kill, reopen,
authenticated replay and pagination evidence specified in G11. The floor counts
permanent sessions of both outcomes, including at least 257 failed or aborted
sessions. The prospective workload profile sets the mix. The current qualifying
runner owns a fresh installation and records the entire initial population before
its planned kills. A cold continuation of an interrupted development attempt
provides separate recovery evidence. Allow up to 14 days for the complete
session process on the measured ARM64 deployment. The combined
report retains `qualification: component` until all five witnesses qualify.

The concurrency producer runs all nine separately enrolled processes on native
Linux ARM64. Start it from the frozen source with the same isolated interpreter
and attempt journal as the other domain runners.

```sh
python3 -I -B -S scripts/run_concurrency.py --evidence "$functional" \
  --journal "$journal" --attempt-id "$attempt" --output "$output" \
  --topology "$nine_member_plan" --plan "$concurrency_plan"
```

Use plan schema `kasumi-concurrency-plan-v1`. Supply `data_profile` and
`operator_profile` as absolute paths to installed profiles for the same tenant
incarnation. The operator profile selects the current data leader's
administrative endpoint. Supply a fresh `collection` name and a registered
backup `destination`. The runner creates the declared collection, verifies
both document versions after atomic writes, reads coherent snapshots, checks
the new physical Raft snapshot position, creates and verifies a backup
checkpoint and commits a fresh membership log entry for the enrolled voters.
The fixed workloads retain complete original session replies, operation times,
maintenance receipts and the nine original process drains.

The observability runner uses this same admitted topology on the native ARM64
reference. Its measurement checks protected data-node health, capacity, over
128 healthy local groups and a fresh coverage epoch after an applied membership
change. It resolves a new backup through its durable status and verifies the
checkpoint, then compares private recovery records with protected HTTP responses
through activation and completion. It also replays the seven frozen server
cases that exercise denials, archive outages, issuer replacement and redaction.

```sh
python3 -I -B -S scripts/run_installed_observability.py --evidence "$functional" \
  --topology "$topology" --plan "$observability_plan" --journal "$journal" \
  --attempt-id "$attempt" --output "$new_output"
```

The plan uses schema `kasumi-installed-observability-v1`. Set `observer_profile`
to a Control administrative credential for the observed data endpoint and
`operator_profile` to the measured tenant operator on the same data leader.
`control_profile` names the separate Control quorum. `destination` selects an
installed backup alias. `recovery_request` is the absolute path to an original
`RecoveryStart` for this disposable qualification tenant. The runner advances
that operation to completion. The observed node hosts at least 129 tenants
and the measured tenant appears on its bounded detail page. Profile and input
paths are absolute. The runner preserves startup and membership-settling
failures with their original process receipts.

Latency sample rows contain `sequence`, `elapsed_ns`, and `status`. A
measurement declares `name`, `requested_operations`, `attempted_operations`,
`successful_operations`, `failed_operations`, `unattempted_operations`, and
the raw `samples` file. Missing/truncated/duplicate samples cannot be replaced
by a percentile summary. The existing benchmark report's summaries and
fixture-based matrix do not satisfy this contract.

### Running the native benchmark matrix

On the native Linux ARM64 reference host, run the following command from the
frozen source export. The functional evidence must contain the production
benchmark driver built with the `installed-embedded` feature.

```sh
python3 -I -B -S scripts/run_benchmark_matrix_owned.py \
  --evidence /release/functional --journal /release/runs \
  --output /release/runs/matrix-01 --attempt-id matrix-01 \
  --plans /release/matrix-inputs
```

The runner creates the raw cases itself. Supply one plan per installed case
using `local`, `replicated`, `text` and `network` at 1, 100 and 1,000 tenants.
Each filename follows the pattern `local-1.json`. A local plan has this shape.

```json
{
  "mode": "local",
  "documents": 1000000,
  "operations": 1000,
  "nodes": [{"path": "/release/local-1/kasumi.json", "sha256": "<SHA-256 of those bytes>"}],
  "tenants": {"bench-0000": {"administrator": "bench-admin", "application": "bench-app"}},
  "load": {"attempts": 6, "budget_milliseconds": 300000, "initial_backoff_milliseconds": 250,
           "maximum_backoff_milliseconds": 8000, "maximum_affected_batches": 8}
}
```

Use dedicated enrolled storage with a fresh `docs` collection name. Each
plan must name the exact installed tenants and their existing principals. The
runner opens the production node and its enrolled application and custody key
providers. The administrator creates the collection. The application must have
read and write grants. For replicated cases supply the three distinct enrolled
data-voter configurations and their live authority dependencies. The runner
checks the effective voters on each tenant. It drains all opened nodes after
each case and preserves their data and original failed operations.

A network plan also names a `network` object with the absolute path and
SHA-256 of a network-driver configuration. Use the owned node's loopback
endpoints and both `grpc` and `mcp` cases, named for their protocols.
Each case lists a dedicated write body, a complete-page query on `docs` and
a matching credential for every installed tenant. In sorted tenant order use
document IDs `"0"`, `"1"` and so on. Keep secret values in their private
credential files. The driver checks the tenant claim and uses normal TLS and
server authorization for every wire operation.

#### Corpus load and uncertain batches

The plan's `load` object fixes, before the run, how the driver resolves an
uncertain corpus batch. `attempts` counts sends per batch, including the first
(2 to 8). `budget_milliseconds` is one budget per batch, from its first
dispatch, for its sends, lookups and backoff sleeps (20,000 to 900,000). The
backoff starts at `initial_backoff_milliseconds`, doubles, and is capped at
`maximum_backoff_milliseconds` (10 to 60,000, below the budget).
`maximum_affected_batches` bounds the batches whose first attempt ends
uncertain (at most 40, about 1% of a case's batches). The verifier rejects
release evidence outside these ceilings.

Each tenant loads its tenant-strided ordinals in batches of 256 with `absent`
preconditions. Before the first dispatch the driver retains the exact batch,
its request digest, the idempotency key `<attempt>-load-<sequence>` and the
receipt scope. The scope is the tenant, the installed incarnation from the node
configuration (checked against the serving generation) and the application
principal. On `UNKNOWN_OUTCOME` or `UNAVAILABLE` the driver first looks up the
retained receipt. While the outcome stays unknown it resends the identical
batch under the same identity until the attempt limit or the budget runs out.
Only a retained receipt that matches the scope, digest and every target version
settles a disputed batch. A refusal on resend never settles the earlier
attempt. A definitive rejection, a mismatched receipt or an exhausted limit
fails the case after the batch's record is synced. The 10 s native write
deadline is unchanged. After a disputed batch settles, the driver reads every
target and records its committed version and canonical body SHA-256.

`load-batches.jsonl` holds one ordered row per logical batch. Each row has the
batch identity, every send, lookup and backoff with its outcome and elapsed
time, and the resolution. A disputed row also has the retained receipt and
the per-target effects. The resolution is `acknowledged on first attempt`,
`receipt found before resend` or `commit confirmed after resend`. These labels
claim no more than the evidence shows. An empty lookup can race the original
proposal, and an identical resend returns the stored outcome whichever attempt
applied.

`case.json` uses schema `kasumi-installed-embedded-v2` and reports a `load`
summary. The adapter and the final verifier recompute it from the records and
require exact equality, with explicit zeros on a clean run. The summary covers
batches, documents and canonical bytes, first-attempt deadline misses and their
rate, and affected batches. It also covers both resolutions, resends, lookups,
the unresolved count, first-attempt and end-to-end batch p50/p99/max, load wall
time and committed documents per second. The verifiers require one terminal
success per logical batch and exact tenant-strided coverage of 1,000,000
documents and 1,024,000,000 canonical bytes. They enforce every declared
bound: the send limit, the budget, the affected-batch limit, and each backoff
sleeping at least its doubled and capped delay. For each
disputed batch they rebuild the request digest from the batch identity. They
match its scope, digest, revision and full target-version map, and check one
effect per target at that revision with the original body. A duplicate counter
cannot replace that evidence: a replay can advance the audit revision without
applying the documents twice. The timed workloads keep their first-attempt
rule, with 1,000 successful samples and no failed or unattempted operation
each. A run on a shared development host is labelled as such; release
qualification still needs the reserved native reference host.

The driver runs kasumi-server's `NodeRuntime` in-process, so no `kasumid`
process appears in this domain. The final verifier instead requires every
matrix process to be the exact `kasumi-bench-network` executable from the
candidate's primary functional evidence. That evidence's `network-driver` gate
must have compiled every package of its `production` gate, which emitted the
qualified `kasumid`, with identical features. Its only additional package is
the driver's own. The adapter also rebuilds each command and requires the
executable hash the driver reports for itself. The domains that run `kasumid`
qualify the daemon's own bytes.

## Process and failed-attempt evidence

Every owned process has an ID plus `receipt`, `log`, and `executable` file
references. Its receipt carries `gate_process.py` ownership/drain fields and
an additional `executable: {path, sha256}` identity measured at dispatch.
`command[0]` must equal that absolute executed path, and the hash must match
the retained executable. Successful gates reject timeout, interruption,
forced cleanup, uncertain census, surviving children, or nonzero outcomes.
Domain adapters must additionally reconstruct and compare the exact command,
arguments, configuration files, artifacts, and service inventory they own.

The owned repeatable-assembly runner retains the executable selected at dispatch
and rejects a process receipt whose command or executable differs from its
retained preflight bytes. Its verifier also rejects a substituted retained
executable or `command[0]` that differs from the selected absolute path. Every
other domain and independent rebuild also requires its original process
identity and command check. Historical receipts retain their original scope. Process groups do not prove custody of daemonized or
remote services. Domain adapters must preserve those services' actual terminal
outcomes too. Each native Python launcher must
also rule out execution of stale or unchecked bytecode. The final verifier
enforces its own isolated cache-free invocation; `-B` alone cannot establish
which imported code ran.

Each native attempt is admitted into `attempts/index.jsonl` before its owned
launcher dispatches. The append-only writer holds a file lock, uses canonical
hash-chained rows, and syncs each admission to disk. Its terminal row binds
the immutable `attempts/<id>/attempt.json` receipt and the original launcher
outcome. Admitted output directories are disjoint: no attempt may run inside
another attempt's retained output tree or contain it. The verifier enumerates
every entry in `attempts/` before and after receipt checks, replays the entire
index, and requires its exact attempt IDs
and receipt hashes in the manifest. A missing, truncated, reordered,
duplicated, or unfinished admission rejects acceptance. An extra file,
symlink, attempt directory without a regular terminal receipt, or directory
omitted from the manifest also rejects. A receipt has schema/id/status, evidence,
an additional unqualified domain observation for a successful assembly,
start/finish, and processes. Failed/interrupted attempts may retain nonzero
outcomes, but their custody must be terminal and drained. They cannot be
selected as successful gates. Every selected primary, independent build, and
domain result must appear in the attempt index. The verifier never deletes,
rewrites, or upgrades a failed attempt. Evidence custody must also preserve
attempts outside the bundle; a local verifier cannot discover withheld history.
Independent custody and a separately published journal head remain required to
detect removal of the entire index or a rewritten complete history before
bundle collection. The owned assembly launcher and domain admission code record
attempts before dispatch. Every selected native run must have its own admission
and terminal receipt in the same journal.

Its successful attempt also retains `domain-observation.json` as an additional
hash-bound journal reference. This exact native observation binds the original
launcher, inner report, target, and both package/source assembly outputs. Its
status is `unqualified`. The registered repeatable-assembly adapter separately
checks the selected primary input and both assemblies. Host identity,
reservation and the final domain receipt are required for acceptance. The
journal retains the launcher's original outcome and observation hashes.

## Deliverables and native evidence

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

The installed runner calls `check_native_admin_readback` to check retained
`kasumictl` policy, schema, and policy readbacks against independently pinned
admin-client bytes, tenant/incarnation, exact policy/grants and limits, and
collection definitions. It requires three distinct candidate-executable
processes whose `--config` and request-file arguments are the verified local
files, and rejects changed policy/schema epochs or nonmonotonic revisions.
For transported native evidence the runner verifies the original path against
the retained input bytes. Revision numbers may advance during strict read
auditing. The installed-domain verifier also checks original dispatch order,
the native TLS endpoint, process lifetimes and the pinned release intent.
Admission requires
`ReadSchema {"selection":"all"}` and the exact complete collection set; named
reads and the retired untagged request cannot establish inventory admission.

A release needs recorded results for the installed lifecycle, real providers,
HA faults and recovery, retention races, resource and integrity measurements,
the benchmark matrix and concurrency, and the full soak. OCI evidence binds
the image platform, manifest and layers, contained binaries and OS/image SBOM.
Dependency review binds the advisory scan and each disposition. Independent
builders supply their compiler transcript and source-bound environment.
The final manifest selects completed native attempts for the frozen source.
