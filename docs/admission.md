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

The native disk-cache redesign uses one growable resident reservation per cache;
cached objects borrow byte credit without consuming individual ledger slots.
Its configured byte ceiling includes payloads, pages, hash backing, retained
reader versions, provider overhead and unused admitted credit. All fitting
objects remain cached; frequency and recency affect eviction only under pressure.

The generated server profile (`kasumid init --mode standalone` and
`kasumid example-config`) derives its aggregate reservation cap from the disks
of the installation it describes. The cap is a 2 GiB payload for request work,
retained sources and the native cache, plus what an idle runtime holds: the
installed metadata of the persistent and scratch disks, each lease with its
allocation fee, and five 64 MiB audit units (the audit-maintenance escrow and
its protected floor, two units each, and the service security-audit
workspace). A fresh standalone installation therefore reports at least 2 GiB free
(`max_inflight_bytes` minus the reported `reserved_bytes`) at idle. Ordinary
work still leaves the 128 MiB maintenance floor free, and retained sources and
the cache leave the work reserve described below. The generated persistent disk
allows 100,000 files, 10,000 subdirectories, 1,024 open files and 256 open
directories, which quote about 118 MB. The generated total is therefore about
2.42 GiB: 2,601,562,764 bytes for an installation path of 35 characters, plus
17 bytes per further character. Each file or subdirectory slot adds about
0.5 KB of quote (two preallocated ledger banks, rounded up to powers of two),
each open-file slot 67 KB and each open-directory slot 53 KB. To raise a cap,
raise `max_inflight_bytes` by the added quote as well, or the payload pays for
it. Reaching a cap refuses that operation with a storage-full error before any
effect. Installations measured on 2026-10-20 held under ten files and
directories each and a few dozen descriptors. The earlier profile allowed one
million files, one million subdirectories and 4,096 handles of each kind
inside a fixed 2 GiB total: their 1.51 GB quote left about 0.38 GB free at
idle. On the BoI journal convoy (two strict reads and three writes per step, a
fresh instance per point, two interleaved 45-second rounds, 2026-10-20), the
generated profile served 9.5 to 16.2 calls per second from one to sixteen
sessions and refused at most four reads per run; the earlier sizing on the same
binary served 5.1 to 15.2 and, at sixteen sessions, refused about 355 attempts
per run and failed 8 to 10 reads after their retries. The 1 GiB
ceiling per persistent group and 512 MiB per scratch cache share the total;
they are not independently reserved allocations.

The total must fit below the RSS high-water mark, which defaults to half of
host or container memory, so the generated profile needs about 4.9 GiB
(5.2 GB) of memory instead of 4 GiB. On a smaller host `kasumid init` fails
with an error that names both figures and the memory the generated profile
needs, and `kasumid serve` logs `admission_exceeds_high_water` with both
figures before `daemon_failed`. For an existing configuration, lower
`max_inflight_bytes` together with the disk caps whose metadata it covers, set
`high_water_bytes` up to the detected memory, or add memory.

Existing installations keep the values written at their initialization. To
adopt this sizing, stop the daemon and set `persistent_disk.max_persistent_files`
to 100000, `persistent_disk.max_persistent_subdirectories` to 10000,
`persistent_disk.max_open_files` to 1024, `persistent_disk.max_open_directories`
to 256 and `admission.max_inflight_bytes` to 2602000000, which covers any
installation path up to 4,096 characters. The installation must hold fewer
files and subdirectories than the new caps. Alternatively, keep the old caps
and raise `max_inflight_bytes` to 4000000000, which needs about 7.5 GiB of
memory. Run `kasumid check-config` on the edited file before starting it.

`cache_work_reserve_bytes` and `cache_work_reserve_slots` keep optional cache
growth out of shared capacity needed for required work. Null resolves to
`min(total / 4, 64 MiB)` and `max(1, min(max_reservations / 4, 64))`, respectively;
the generated profile explicitly selects 64 MiB and 64 slots. Both add to any
installed audit-maintenance protection. Ordinary required workspace admission
is unchanged, and optional cache retention never borrows the audit thread's
protected escrow. The reserve preserves bounded read and maintenance room; it
does not guarantee that every maximum-size write or concurrent operation fits.
Retained source and document charges, including the grant every proposal
admits, must leave that same reserve free, and a proposal admits its grant
while its own workspace is held: with default limits a strict read and its
audit hold about 70 MB, more than one reserve. Optional cache credit therefore
leaves the reserve three times, so that a cache warmed while idle cannot by
itself refuse the next request's grant. Before this, a cache that reached the
retained-source floor refused every proposal until it shrank.
Cache growth, metadata replacement and pressure behavior are under validation
in the [disk-cache evidence record](evidence/disk-backed-cache-20260930/README.md).

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

Each local application proposer, including a strict read audit, also admits its
committed entry's Engine selection capacity before proposing: the next Cell and
a planned decode workspace sized by the ordinary source envelope, under the same
retained-source rules (cache-work reserve plus installed protection) that apply
would otherwise use. The database proposal gate keeps at most one such grant
outstanding, and the Entry sink spends it instead of reserving after commit.
Concurrent reads can therefore reject a request with `ResourceExhausted` or
`AuditUnavailable`, but cannot fail a committed entry and close the tenant.
A strict read whose audit admission refuses before proposing returns
`ResourceExhausted`: nothing was proposed and the read is withheld, so the
caller backs off and retries. A snapshot read pre-admits its maximum workspace
(three result limits plus three document limits) for evaluation, then keeps only
its evaluation's logical peak, which covers the response, through its audit and
release; the transport charges response encoding to its own fence. Queued strict
reads holding their maximum had left no room for the gate holder's grant. `AuditUnavailable`, which the transport reports
as UNAVAILABLE and clients resend until their deadline, remains for an audit
whose durability could not be confirmed.
Entries without a local gated proposer (startup replay, covered reconstruction,
metadata or membership entries and replicated followers) still reserve while
applying.

An unscoped proposer also admits an 8 MiB native escrow under the rule its
committed entry's native KV leases would otherwise meet after commit: a free
ledger slot, the byte cap and the RSS high-water mark, but not the installed
protection, which native Resident traffic shares by design. While that entry
applies, every installed native lease taken on the applying thread (the
command's own registered reads such as mutation receipt lookups, the Entry sink
planner's reader and point workspace, the queued source reader, the publication
write and the selected capture) is drawn from the escrow instead of being
admitted. Unspent bytes return when the apply ends; leases that outlive
it, such as the selected reader, keep exactly their own bytes and one ledger
slot charged until the last is released. Concurrent native traffic or RSS
pressure after the proposal can therefore refuse new requests, but not the
committed apply. An apply whose native peak exceeds the escrow admits the excess
as before, and audit-maintenance applies keep using the maintenance escrow.
Two native bounds are counts, not memory, and stay admitted while applying:
storage census slots (capacity `max_reservations`; every owner registered
outside an escrow also holds its own ledger charge, so they run out only after
ledger slots) and the 256 snapshot pins of a node database (one per live
selected Generation, which includes every in-flight request's Generation and
every snapshot lease, and one per transient planner or capture reader).

The standalone writer's own storage work runs outside any committed apply and
spends no escrow: the journal append before an entry commits, and the periodic
snapshot (every 5000 entries) that builds beside later appends. Admission may
refuse either, and a refusal does not close the tenant. Only a typed proof that
the refused operation had no effect counts: an admission refusal for native
memory, a disk allowance or a census slot, returned before any reader, writer,
file or transaction exists; an Engine `ResourceExhausted`; a registered write
whose denial Store settled, or whose native begin was refused for capacity; and
a routine read refusal Store retires, other than a bound violation. I/O
failures, corruption, unknown commits and every other error still fence the
writer. A refused append is a definite rejection. Nothing reached the journal,
the writer keeps its position, and the proposer returns `ResourceExhausted`, so
the same idempotency key can retry. A refused snapshot build is deferred. The
published snapshot, the applied state and the journal stay as they were. Staged
chunks are crash-equivalent and removed by the next build or open, and the next
periodic snapshot covers every retained entry. A refused purge keeps the chunks
it already committed with their purge cursor and leaves the rest for a later
snapshot. Retired custody snapshots still fence on any failure.

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
| Proposal workspace | Three times configured maximum batch bytes plus 64 KiB framing per copy; a read audit, complete before admission, counts its own encoded command instead of the maximum batch, and a mutation batch counts its own encoded command within the fixed 8 MiB request envelope instead of the envelope. Neither follows the tenant's current budget, so a replay of a committed identity is still admitted after the budget is lowered. Reservation persists through actual Raft completion. |
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
fit in replica RAM while application document and query-index state remain
resident. The native cache cutover alone does not complete that application
redesign. Capacity measurements must include rebuilds, snapshots,
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
real Raft application while new client admission is blocked, and committed
strict read audits that apply after concurrent readers exhaust ordinary capacity
(`kasumi-engine/tests/strict_read_apply_capacity.rs`).

Explicit embedded/local deployments use the authenticated durable
`engine.deployment = local-v1` binding to capture locally committed generations
without a distributed read barrier. Replicated and manually constructed groups
retain quorum barriers regardless of their currently visible membership. A
partition can never downgrade a replicated tenant to local read semantics.
