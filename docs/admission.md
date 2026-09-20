# Node memory admission and query cancellation

`AdmissionConfig` controls a `MemoryCore` containing shared memory measurements
and aggregate reservations. Each `NodeAdmission` attaches its runtime startup
inventory to that core. The control database, tenants, and security audit within
one runtime use the exact same `NodeAdmission` facade. `Database::new` derives
that facade from its mandatory `SecurityAudit` before starting workers; there is
no deferred installation or implicit default. Explicit bootstrap and custody
arguments must match the audit facade before storage or startup work begins.
Sharing a memory core does not make different runtime facades interchangeable.

The default high-water mark is half physical RAM, reduced by Linux cgroup memory
ceilings. The low-water mark is seven eighths of high water. The workspace budget
defaults to the smaller of one quarter of high water and 512 MiB, with 64 active
operations. An explicit high-water mark is checked against detected host/container
capacity at startup; a larger value is rejected, and an explicit value cannot
bypass a failed capacity probe. This is startup validation, not a promise that
the host or container ceiling cannot subsequently change. Linux reads process resident pages from
`/proc/self/statm`; macOS uses `MACH_TASK_BASIC_INFO`. Production Linux must mount
the applicable cgroup hierarchy for automatic ceiling discovery; an explicit
`high_water_bytes` may impose a smaller operator limit for unusual mount layouts.

The byte budget includes governor bookkeeping, resident reservations and active
workspaces. A fixed ledger holds at most `max_reservations` charges (4096 in newly
generated default policy), including zero-byte charges. Each runtime facade has
`max_snapshot_startups` inventory slots (64 by default). The core also has
`max_startup_scopes` retained startup-scope slots (64 by default). These numeric policy
fields and the enclosing runtime admission object are required in serialized
configuration; missing fields and unknown aliases are rejected. Programmatic
`Default` is a policy for new callers, not a configuration migration.

The core admits its fixed bookkeeping before allocating the ledger or starting
the RSS sampler. A facade separately admits its inline storage and complete
startup inventory. `required_bookkeeping_bytes` exposes the checked workspace
estimate for sizing a total budget. `reserve_resident` charges bytes and a ledger
slot without consuming an operation slot; reservations retain the core rather
than a runtime facade. Snapshot diagnostics separate bookkeeping and resident
bytes from the total. Inventory storage remains charged through cancelled drains;
completed failure reports retain their envelope until the facade is destroyed.
The last core owner joins the actual sampler before releasing its accounting
storage. Sampler panic permanently fences admission and retains its original
payload until join. Native qualification of these workspace estimates remains
required.

The startup-scope foundation reserves fixed resource cells before invoking an
inert resource builder. Actual children may start only after their adapter is
retained in a charged cell. Cancellation leaves the original handles and typed
outcomes available to repeated drain; shared report views retain their scope's
charges. A slot is reusable only after the closed resource census positively
completes, and generation tags prevent an old drain from retiring its replacement.
Current server resource/diagnostic adapters and whole-process drain integration
remain unfinished. Arbitrary panic payloads have no measured diagnostic envelope;
they remain owned and Retained rather than being reported as bounded completion.

`MemoryCore::installed` now provides one strongly retained process core. Reuse
requires exact equality of every policy field, refuses an already failed sampler,
and never replaces that failed core with a fresh budget. Concurrent installation
fails with a busy result instead of allocating a queued waiter.
`NodeAdmission::from_memory` creates a fresh runtime facade on an existing core.
Adopting installed selection at every production entry point, mandatory disk
metadata admission and explicit process-level sampler drain are still being
implemented under the
[installed-storage admission plan](installed-storage-admission-plan.md).

RSS probes run every 250 ms. Measurements older than one second are refreshed
synchronously at admission and query result release. Age is measured from probe
start with the same suspend-aware monotonic clock used for key leases. Probe
failure or a probe taking longer than the maximum age denies admission. Reaching
high water pauses incoming proposals and point/structured/text reads and cancels
active query evaluation; admission resumes below low water. Retained cursors are
discarded by the one-second tenant maintenance loop during pressure.

The gate runs before a client proposes a command. Replication and committed
application never consult RSS to decide a command's business outcome. An admitted
write keeps its reservation in the actual proposal task even if its caller times
out or disconnects; its uncertain outcome must still be resolved by receipt. A
replica that cannot materialize committed state must stop serving and recover.

Queries have a five-second deadline and four workers per tenant, in addition to
the shared governor. Cooperative checkpoints cover candidate traversal, scans,
array membership, sorting comparisons, grouping, projection, term expansion, and
text scorers. FST traversal checks cancellation even between matching terms.
Timeout, caller cancellation, key sealing, or node pressure cancels query work.
The worker retains its generation, concurrency permit, and reservation until it
actually exits. Result release checks cancellation, fresh memory status, current
key access, replica availability, and current tenant policy. Required successful
read audits still persist before this release gate.

| Memory/work category | Current bounds/accounting |
| --- | --- |
| Documents and schemas | Deterministic tenant/document/collection/schema quotas; full resident usage appears in RSS. |
| Proposal workspace | Three times configured maximum batch bytes plus 64 KiB framing per copy; reservation persists through actual Raft completion. |
| Text writers | An additional 15,000,000-byte writer-buffer allowance on relevant client proposals; sequential collection writers use the configured Tantivy buffer. |
| Structured/search queries | Candidate/group/result limits plus reserved candidate, sort, group and output workspace; cancellation checkpoints and a deadline. |
| Cursor results | Tenant byte/count/age quotas plus a shared reservation of three times maximum result bytes; continuation pages reserve a separate copy allowance. Old generations are released after evaluation. |
| Receipts and audits | Permanent command identities and outcomes in encrypted point-addressed tables under byte quotas; bounded reads and audit hot/archive budgets. Required audit failure prevents its associated release. |
| Wrapped-key dependencies | At most 1024 retained keys and an exact catalog quota of 2 MiB minus 16 KiB, enforced before persistence; reserved header space keeps accepted key changes backup-compatible. |
| Staged indexes and old generations | Structural sharing plus RSS observation; transient allocator usage is **not** measured exactly by reservations. |
| Backup/recovery and incoming committed replication | Existing format/snapshot/log caps and observed RSS; these are **not** bounded by client query/workspace reservations. Recovery is not made ready before reconstruction. |

Reservations are conservative workload estimates, not an allocation tracker.
RSS includes resident indexes, search readers/writers, receipts, audits, and pinned
generations, but sampling and individual library calls can overshoot high water.
This mechanism does not guarantee freedom from OS OOM, impose a hard per-tenant
physical RAM cap, or change the requirement that configured datasets and indexes
fit in replica RAM. Capacity measurements must include rebuilds, snapshots,
concurrent tenant groups, and the embedding application's own allocations.

`Limits.max_snapshot_bytes` separately bounds the exact canonical serialized
tenant state, including document envelopes, collection/schema metadata, receipts,
audit records, policy and limits. Its default is 1.5 GiB; the quota is a checked
64-bit resource setting without a fixed aggregate format ceiling. A small revision-width reserve lets rejected
commands advance without exceeding that quota. Cached counters update only
changed entries and rebuild during recovery; snapshot output is checked against
the exact count. Oversized effects are rejected before index materialization.
A rejected receipt and audit are retained when they fit; exhausted required audit
storage returns `AUDIT_UNAVAILABLE` with no document effects.

Aggregate backups use bounded chunks and paged manifests. Each encrypted object
has a 32 MiB plaintext cap; destinations also allow authenticated bundle framing. Restore adds incarnation/pending
metadata and a completion audit. Keep headroom for these records: if the new
identity metadata cannot fit the tenant quota, preparation fails before publishing
a bootstrap. Increase the source quota before making that backup. If completion
auditing exhausts a previously prepared tenant's quota, it stays suspended until
an authorized quota increase allows finalization.

Evidence is in `kasumi-engine` admission unit/integration tests and
`kasumi-query` cancellation tests: real RSS, hysteresis, slow/failed probes,
suspend without monitor progress, release after suspend, retained cursor charges,
detached worker charge/permit lifetime, cancellation during query evaluation, and
real Raft application while new client admission is blocked.

Explicit embedded/local deployments use the authenticated durable
`engine.deployment = local-v1` binding to capture locally committed generations
without a distributed read barrier. Replicated and manually constructed groups
retain quorum barriers regardless of their currently visible membership. A
partition can never downgrade a replicated tenant to local read semantics.
