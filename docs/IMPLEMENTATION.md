# Kasumi v1 implementation ledger

> Historical evidence for the former redb-backed implementation. The active
> storage design and its current qualification state are in
> [native-kv-goal.md](native-kv-goal.md); results below do not validate the new
> physical format.

The original v1 design agreed on 2026-09-05 was implemented and its software
acceptance evidence completed. Its macOS/Linux gates passed 188 workspace
entries per platform, strict Clippy/formatting, six Python checks and actual
OpenBao/MinIO fixtures. The [final results](../benchmarks/RESULTS.md) cover all
15 required cases with 99,000 successful operations, zero failures and zero
unattempted operations. Twelve byte-identical embedded benchmark cases retain
their original source identity; three corrected-network cases passed separately,
including shutdown and verified recovery. This is software acceptance within
documented fault models and host qualifications, not a production deployment
or performance SLA.

First-release [conditional transaction and coherent snapshot additions](transactions.md)
now extend this baseline. The evidence below remains attached to its recorded
source and does not certify these later changes.

Evidence below has run on macOS with Rust 1.94.1 unless stated otherwise.
Software fault models and loopback fixtures are distinct from actual hardware
power-loss or independent-failure-domain measurements.

## Milestone 1 — durable core

Implemented: exact JSON types; offline JSON Schema 2020-12 validation;
default-deny RBAC; atomic multi-collection batches, CAS and principal-scoped
receipts; persistent maps of shared immutable documents; deterministic quotas;
encrypted redb immediate/two-phase durability; durable votes/logs; authenticated
chunked snapshots and replay before readiness. Bootstrap policy and deployment
bindings are persisted, and duplicate live group ownership is rejected.
New database and backup/generation directories explicitly sync their parent
entries. An incremental serialized-state budget bounds documents, schemas,
receipts and audits together below snapshot/backup format limits.

Passing evidence includes authenticated-ciphertext/identity tampering, fresh
nonces, injected write/fsync boundaries, OpenRaft storage conformance,
maximum-size log payload recovery and snapshot chunk transport. Real SIGKILL
subprocess tests recover acknowledged documents, receipts and original policy.
Engine tests cover partial-batch rejection, unique-value swaps, receipts before
validation, strict audit failure, snapshot integrity and receipt expiry.

The current completed combined validation used source
`28aeb80168d3ab02a0eec7bf2a0163a7cb99dbfd74adf596e849de17e1fa3c1d`:
188 workspace entries on
[macOS](../benchmarks/results/macos-validation-20260905-listener/evidence.json)
and [Linux](../benchmarks/results/linux-validation-20260905-listener/evidence.json),
with strict all-feature/all-target workspace Clippy, formatting, six Python
tests and one additional actual OpenBao test per platform. The
[MinIO fixture](../benchmarks/results/linux-validation-20260905-listener/minio-evidence.json)
used the matching macOS test binary against a pinned Linux container.
The preceding shutdown source `fffa308b…` passed 177 entries per platform;
its original manifests remain retained without relabeling their source.

Earlier combined validation passed on frozen source: 167 workspace test entries on
[macOS](../benchmarks/results/macos-validation-20260905-barrier/evidence.json) and
[Linux](../benchmarks/results/linux-validation-20260905-barrier/evidence.json),
with strict all-feature/all-target workspace Clippy, formatting and two Python
driver tests. Linux also passed the separate actual OpenBao test. These gates
bind source fingerprint
`a36dd4e69700ea7e20aec5784106c0034f306d50edfec8939ad2b46ba439a63f`.
Earlier 157-test gates and their fingerprints remain retained in the platform
[macOS](validation-macos.md) and [Linux](validation-linux.md) histories.

## Milestone 2 — replication and security

Implemented: OpenRaft pinned to 0.9.25; one group per tenant; explicit three-voter
placement across configured independent domains; quorum reads and persisted
writes with complete local application; a separate durable control group;
manual learner/replacement transitions; TLS 1.3 and pinned mTLS peers; Transit
leases; mandatory tenant/service auditing; filesystem/S3 encrypted backups;
suspended restore with a fresh incarnation and permanent retirement of the
source before control-route replacement.

Passing evidence:

- Partitions, minority isolation, delayed replication, leader loss, snapshot
  catch-up after log purge, total restart and voter replacement.
- Full three-server restored-generation lifecycle with independently elected
  source, target and control leaders, matching restored-bootstrap hashes, refusal
  to initialize with a missing target, route convergence and total restart.
- Four-runtime spare catch-up and three-voter replacement through the actual
  administrative/control APIs, including rejection of a two-voter placement.
- Staged tenant provisioning through durable control approvals, preparation on
  every voter, matching bootstrap checks, explicit initialization and topology
  CAS activation. Initial control/tenant bootstrap mismatches are rejected before
  initialization and on authenticated Raft traffic; restored groups also bind
  their immutable snapshot digest.
- Pinned mTLS replication, TLS 1.2/no-certificate/foreign-CA/wrong-pin rejection,
  and rejected source/group identity spoofing.
- Warm-state key denial, historical-key revocation, delayed probes, suspend-aware
  expiry and owned-key/state release; required read/auth/denial audit failures.
- **Real OpenBao 2.6.2** TLS Transit interoperability: ordinary/derived keys,
  generate/decrypt/rewrap, wrapping-key rotation, historical backup dependency
  denial, and revocation sealing a warm store.
- **Real MinIO** pinned release over TLS/SigV4: encrypted upload/download/decrypt,
  create-only overwrite rejection, wrong credentials, wrong trust, missing
  objects and bounded downloads. These temporary services used no user accounts.

The shared node governor provides admission/backpressure, query cancellation and
result-release fences. Committed application never consults local RSS to choose
its replicated outcome. See [admission](admission.md),
[administration](administration.md), and [compatibility](COMPATIBILITY.md).

The combined gates cover management deadlines, response fences, bootstrap
agreement, recovery and shutdown ownership. Live OpenBao and the macOS-client
MinIO fixture passed with the common audit changes on the current frozen source,
as recorded in their manifests.
Vault itself and externally operated S3 services have not been tested. Audit
storage is bounded and fail-closed; automatic archival/pruning is not implemented
or claimed.

## Milestone 3 — queries and interfaces

Implemented: typed JSON Pointer predicates; missing/null separation; exact
arithmetic and explicit-scale half-even averages; sort, projection and bounded
grouping; persistent structured/unique indexes; Tantivy/Lindera Unicode, English
and Japanese terms/phrases/prefix/fuzzy search; bounded historical cursors.
Incremental changes share unchanged documents/collections. Text commit/reload
finishes before publication, and historical readers remain stable.

The common authorized engine is exposed through embedded Rust, tonic/Protobuf
and the official Rust MCP SDK with 2026-07-28 only. JSON stays exact through UTF-8
JSON Protobuf fields and MCP serialization. Native/admin services use separate
mTLS endpoints. MCP protected-resource metadata and requests use configured
OAuth issuer/audience/JWKS/signature/expiry/type/scopes without token passthrough.
The administrative CLI covers schemas, policy, quotas, keys, backup/restore and
membership. Authorized leader-node hints refer only to configured pinned nodes.

Passing evidence includes indexed/reference comparisons, numeric/schema edge
cases, multilingual/fuzzy fixtures, incremental updates and historical readers;
shared native/MCP authorization, cross-tenant and invalid-token rejection,
strict audits, exact-number round trips, discovery and legacy-MCP rejection.
A real process fixture exercises both native gRPC and current MCP over TLS with
real OpenBao and signed tokens. See the [API guide](api.md) for exact request
shapes and [acceptance checklist](release-checklist.md) for the full mapping.
A release-fence test rejects payloads prepared
before a policy change or actual key denial.
New acceptance regressions also overlap historical pages with atomic writers
and policy revocation, and deliberately discard native/MCP responses after
dispatch before resolving retained receipts and retrying the same operation.

The final adapter/engine checks passed on both supported validation platforms.
Independent third-party MCP certification is not claimed.

## Milestone 4 — release validation

Implemented: benchmark executables separating raw map, owned/shared embedded
access, local durable writes, three-voter durable writes, indexed text, native
RPC and MCP. The full-matrix driver records stable source/executable hashes,
workload/sample counts, host load, RAM and recovery, and rejects source changes
or competing work unless host load is explicitly disclosed.

Preliminary macOS release measurements exist for approximately one million
1 KiB documents across 1, 100 and 1,000 tenants for raw/local cases. They predate
final integration and were collected during development; they are not final
comparative performance evidence. The map-sharing experiment measures only map
copy costs, not an end-to-end database multiplier. No Redis speedup or launch SLA
is asserted.

The first frozen-source matrix passed raw/local one-tenant cases and stopped
at a replicated balanced-workload quorum read. Its failure and partial report
are retained. [The investigation](read-barrier-investigation.md) distinguishes
the unrecorded original trigger from proven scheduler-blocking snapshot code and
the former one-probe read failure behavior. The revised harness preserves partial
workload samples and failed-attempt counts, continues independent cases, and
returns nonzero when any case fails; it never retries a measured operation.

The third matrix passed the raw/local/replicated one-tenant cases, including all
six replicated workloads at one million documents and verified recovery. Its
driver then stopped with a broken output pipe after the task continuation.
The fourth matrix used regular-file logging and a detached wrapper with retained
PID/exit-status evidence. Its replicated balanced workload hit the five-second
read-quorum deadline after 10 successful operations, and recovery then failed
because shutdown had retained the redb file lock. The run was explicitly stopped
before corrective edits. The [shutdown investigation](shutdown-investigation.md)
records the worker-lifetime defect and deterministic immediate-reopen regressions.
Those fixes do not establish the cause of the separate quorum availability miss.
Earlier results and execution failures are preserved. The final cohort below
provides every required case without substituting these interrupted attempts.

The [fifth matrix](../benchmarks/results/release-matrix-macos-arm64-20260905-05/execution.json)
passed the raw/local one-tenant cases. All six replicated workloads and verified
recovery were checkpointed, but final cleanup was explicitly interrupted before
implementing the confirmed embedded denial-audit fix.
Its terminal manifest preserves unchanged before/after source fingerprints.
Refreshed gates passed on both platforms, followed by the later measurement
records below. Finite fail-closed availability
misses remain measured capacity findings unless evidence demonstrates a contract
defect; no launch latency SLA is imposed retrospectively.


The [sixth matrix](../benchmarks/results/release-matrix-macos-arm64-20260905-06/matrix.json)
attempted all 15 cases on `a3205990…`. Fourteen passed; the 1,000-tenant network
server exited before readiness with `Invalid argument (os error 22)`, leaving
that network workload unmeasured. An isolated queued-reset TCP fixture reproduces
the same macOS error from `TCP_NODELAY`; the listener propagated that accepted-
connection error to whole-node shutdown. The original failure did not record
its syscall, so the original trigger remains inferred. The targeted correction
keeps connection setup failure within its bounded, audited connection task.
Fresh full platform gates now pass. The [release build](../benchmarks/results/macos-validation-20260905-listener/release-build.json)
proves that `kasumi-bench` is byte-identical to run06, while the server and
loopback fixture incorporate the listener correction. The
[network supplement](../benchmarks/results/network-rerun-macos-arm64-20260905-listener/RUN_NOTES.md)
repeated all three network counts successfully, including recovery. The final
1,000-tenant server shut down in 1.608 seconds and recovered with verified reads
in 52.016 seconds on this shared macOS host.

The [cohort manifest](../benchmarks/results/release-cohort-macos-arm64-20260905-listener/cohort.json)
and [capacity view](../benchmarks/results/release-cohort-macos-arm64-20260905-listener/capacity.json)
bind all fifteen selected cases to their original raw records. All 99 workloads
completed 1,000 successful operations each. The report separates raw/shared/owned
access, local and quorum durability, authenticated RPC/MCP, and indexed text;
it includes p50/p99, throughput, memory, recovery and resident-voter overhead.
The portable reporting tools are archived with the evidence. No software
milestone remains open; the final [acceptance checklist](release-checklist.md)
records requirement-by-requirement closure.

The pinned Linux container gates, strict lint and real-service checks have
passed, with commands and fingerprints retained. The systemd template passed
static verification, and the tested runtime lifecycle covers the documented
restore, activation, restart and membership workflow. [Operations](operations.md)
documents their boundaries and retention limits.

## Release rule

Do not mark the full goal complete until the required implementation and
verification are finished. Keep untested guarantees and environment-dependent
claims explicit. Fault models establish software behavior; deployment storage
and real failure domains must honor the contracts on which durability depends.
