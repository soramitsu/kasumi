# Proposed bounded custody staging

> Historical proposal written for the former redb backend. The native
> Kasumi engine and its current qualification are described in
> [native-kv-goal.md](native-kv-goal.md).

Status: **batching proposed and unimplemented**. Terminal staging now permanently
rejects finish after a failed push. Retained transaction/database/spool primitives
and fixed cache entry admission are applied and have focused passing evidence;
production adoption, batching and complete memory admission remain unimplemented.
This document does not qualify the release or close
the first-release goal. Work is restricted to `/Users/mtakemiya/dev/kasumi` on
`master`. No backwards-compatibility mode, alternate decoder, relaxed durability,
or unadmitted production fallback is proposed.

## Evidence and open qualification

The native debug-profile capacity workload remains **4,200 command receipts and
8,400 audit records**. Its counts, snapshot-size assertions, reopen verification,
profile, and deadline must not be reduced or changed to hide cost.

The original full Raft test run failed during raw encrypted-spool appends. Gate28
then identified APFS speculative allocation beyond the admitted file extent.
Its trace, source inventories, and instrumented sources are preserved under
`target/installed-disk-validation/`. A paced native probe reproduced the extra
allocation; pre-sizing the admitted ciphertext slot before writing avoided the
overage in that probe. The successor source retains the strict allocation fence
before and after the ciphertext write. This is a separate correctness fix, not
the batching proposal below.

During successor gate29, the test remained active after roughly eight minutes.
`target/installed-disk-validation/29-custody-sample.txt` showed the command-staging
path `custody_records::Builder::command -> EncryptedTable::insert -> redb commit`,
including the durable synchronization and growth-settlement work. Source confirms
that every call to `EncryptedTable::insert` opens and commits its own transaction.
That makes a complete staging pass perform 12,600 row commits, besides table
creation and other snapshot work. Additional capture/decode passes can repeat
that cost. This observation is not a benchmark of a batching implementation.

Gate29 ultimately produced no terminal test result. Its runner failed during its
process-liveness probe before writing the normal receipt. Independent recovery
confirmed process drain and unchanged source; its original signal history was
not recorded. It remains failed/unresolved in the
[development evidence](evidence/installed-disk-main-20260920/README.md).

Engine gate52 identified a second consumer of the same staging bottleneck:
`public_restore_admits_resident_state_without_charging_permanent_stream_as_ram`
exceeded its unchanged 60-second backup-verification deadline. The workload has
512 permanent terminal rows, each retaining a 256-chunk manifest. The live sample
passes through snapshot decoding, `staged_terminal::Builder::push`, and individual
durable redb commits. Source performs two independent inserts per terminal row,
for its identity and ordinal. This is diagnostic evidence, not a measurement of
the proposed batching implementation. Keep this case's workload, deadline and
production admission constraints unchanged in its successor.

A separate correctness fix sets a failure latch before terminal-row validation,
head advancement or either durable insert and clears it only after both inserts
succeed. A failure permanently rejects further pushes and finish, so matching
head metadata cannot publish a partially written row. Development attempt 72
passes all eight terminal-row tests, including a real second-insert duplicate
failure after the identity row commits and rejection after a valid prefix.
This does not implement the admitted batch writer or qualify its performance.

## Smallest streaming change

Introduce an owned, unpublished encrypted-table writer in
`crates/kasumi-store/src/scratch_table.rs`, with dedicated tests in
`scratch_table_tests.rs`. It owns the original `EncryptedTable` and an optional
`redb::RetainedWriteTransaction` in a registered aggregate, with the matching
`RetainedDatabase`. Redb transactions own their backing Arcs and do not require a
self-referential borrow. Do not expose a raw redb transaction or backend to custody
callers. Register and admit the actual aggregate before database construction or
the initial table-creation transaction.

The writer inserts borrowed records directly into the current transaction. It
retains no whole-history vector and no separate batch of cloned payloads. Begin
with fixed limits of **256 rows and 1 MiB of total encoded key/value bytes per
transaction**, committing before either limit would be exceeded. Keep the custody
per-record limit of 64 KiB and validate individual lengths before opening or
mutating a transaction. Count keys and values with checked arithmetic; a row cap
also bounds metadata for very small records.

Every batch uses the existing default durable commit, mandatory `StorageAdmission`,
physical owner, and settlement protocol. Do not reintroduce `Durability::None`,
defer all durability to close, loosen an allocation check, or replace an I/O error
with a capacity denial. Standalone point `insert` can retain its immediate
one-operation transaction semantics.

The engine terminal-row builder must use the same owned writer foundation with
an explicit profile that preserves its existing 2 MiB record ceiling. The custody
profile's 64 KiB row bound and 1 MiB transaction bound cannot silently become new
terminal-row rejection limits. Include the identity and ordinal encodings in the
checked workspace/byte estimate. Admit a transaction large enough for a valid
maximum-sized row before allocating it; commit smaller batches earlier as needed.
Every failed push must permanently disqualify the builder from successful finish,
including failure after the identity insert but before the ordinal insert. The
authenticated head alone is insufficient proof that both records were persisted.

For rows small enough that the byte cap does not bind, one pass needs 17 command
commits and 33 audit commits rather than 12,600. Larger records cause earlier
commits. This is a bound derived from the proposed limits, not a measured speedup.

`custody_records::Builder` owns two writers. `finish` first commits both final
partial batches and obtains their tables, then performs the existing complete
count/byte, audit linkage, original-receipt, ordering, and digest validation.
Only successful validation returns `Arc<Records>`. A validation or insertion
failure permanently disqualifies that builder from returning records, even if
some private batches were already committed. Duplicate detection must work both
inside a pending batch and against earlier committed batches. No private staging
commit publishes live custody state or advances a durable applied cursor.

## Mandatory memory admission

There is currently **no exact parent memory reservation for these custody table
builders**. `SnapshotBufferOwner` reserves transfer-cell workspace: its 256 KiB
buffer allowance is not a custody-table allowance. The 64 MiB reservation in
`kasumi-engine/src/snapshot_api.rs` belongs to a different public engine snapshot
API. Raft capture and envelope decode create custody tables directly; neither
allowance may silently be reused to justify batching.

Add a mandatory trusted staging-memory capability at the store/Raft boundary,
implemented by the installed node governor without importing engine into store
or Raft. The capability must acquire a checked lease before the first table,
transaction, or associated allocation is constructed. An opaque `Arc<()>`, an
optional parameter, or a production default that skips admission is insufficient.
Fixture-only implementations must remain explicitly restricted to tests.

The store should define and validate the requested workspace estimate, so the
installer cannot accidentally charge only the record payload. Its checked
calculation must include:

- Two redb caches with their existing 8 MiB soft byte targets and all actual
  payload, entry, stripe, lock and owner memory. `set_cache_size` is not a hard
  bound on payload retained by page guards or the complete cache owner.
- Two pairs of retained plaintext/ciphertext spool buffers, plus keys and owner
  metadata.
- Bounded input decoding, parsed receipt/event, canonical re-encoding, linkage
  checks, and digest workspace.
- Both pending transactions' uncommitted page sets, freed-page and deferred-reclaim
  metadata, table paths, commit preparation, and settlement workspace. A 1 MiB
  payload cap does not itself prove a 1 MiB transaction memory bound.
- Retained allocator/region metadata as a function of each table's admitted
  `max_disk_bytes`, including applicable debug-profile metadata during native
  qualification. The current table disk quota is computed from the head's
  expandable durable byte limit and is not a fixed resident-memory bound.
- The retained work inventory, error/drain records, and lease bookkeeping.

The precise conservative coefficients require auditing redb's allocation
structures; this document does **not** supply a proved constant. A helper such as
`required_workspace(max_disk_bytes, max_batch_rows, max_batch_bytes)` should reject
overflow and unsupported policy before allocation. Preserve the distinction
between an admitted workspace estimate and an allocator/RSS guarantee.

The reviewed fixed-cache successor passes in development attempt 121. Its
[checked collection component](evidence/installed-disk-main-20260920/redb-fixed-cache-metadata-components/README.md)
bounds only the maps and queues from the enforced stripe entry caps and pinned
native collection geometry. Page payload, retained guards, synchronization,
allocator/region and transaction structures still require separate accounting.
In particular, `process_freed_pages` currently flattens all eligible historical
page lists into a temporary vector and then extends the transaction's deferred
reclaim vector. Attempt 132 now validates selected page-list shapes before either
namespace is removed and explicitly observes extraction close; its 134 vendor
cases pass. These checks do not bound that vector or traversal. A small current
batch does not bound this history. A future
bounded-prefix reclaim design must retain unselected pages, preserve the reader
horizon and post-publication release order, and provide reserved maintenance
progress; existing two-commit compaction cannot be assumed to drain arbitrary
backlog under that design.

Separate the lifetime of table-resident memory from transient transaction work.
The resident lease follows the exact `Records`/table owner until its actual final
close; successful `Builder::finish` cannot release it. Transient workspace follows
the blocking worker through final commit or abort and physical cleanup. A cancelled
async waiter cannot return either charge while that owner still exists. A shared
governor core and retained-reservation plumbing are prerequisites; see
`installed-storage-admission-plan.md` for the broader memory-owner foundation.

Mandatory capability propagation includes these production paths:

- `custody_records.rs`: builder construction, capture, finish, and retained records.
- `snapshot_custody.rs`: capture of custody records.
- `snapshot_codec.rs`: authenticated envelope decode and staged builder cleanup.
- `storage.rs`: snapshot capture, startup/reopen, and install blocking workers.
- `custody_machine.rs` and custody snapshot storage: closed-group capture, startup,
  load/decode, publication, and any nested staging tables.
- Raft installation interfaces in `lib.rs`, their engine/server installers, and
  `kasumi-engine/src/admission.rs`: provide the installed capability and retain its
  actual work/charge ownership. Update all direct test call sites explicitly.

Multiple capture/decode builders or retained snapshots can coexist. Do not infer
a global single-builder bound from the install gate or charge one shared allowance
twice. Admission must account for every actual resident owner and active worker.

## Finish, error, cancellation, and panic ownership

Give the writer explicit `finish` and `abort/close` paths. Close temporary table
guards before the borrowed terminal attempt. On normal completion, commit the final
partial transaction before exposing its table. On failure, abort any still-live
transaction and close the private table; preserve the original error together
with any abort or close error in the owning drain report. A close that reports
retained ownership must retain the table and its memory lease for observation.
Only a busy phase that has not entered physical cleanup may be retried; an
entered/uncertain terminal or close phase is never replayed. After positive
settlement, `dispose_settled` requires the matching borrowed retained database
and retires the actual transaction while keeping its original outcome cells.
This permits the next writer without losing the previous diagnostic. Both
database-close phases must be inspected: physical settlement alone does not mean
shutdown returned success.

Order fallback field destruction as transaction, table, then memory lease. That
ordering is necessary but does not establish successful drain: redb's
`WriteTransaction::drop` intentionally skips abort while unwinding and discards
abort errors. A panic-safe worker owner must retain the writer before entering
fallible work, catch the panic while that owner remains available, and drive or
retain cleanup with the original panic payload and physical failure. Do not
implement a destructor that silently swallows cleanup errors and calls it closed.

Existing `StorageHandle`/`StorageLease` keeps tracked durable-store ownership alive
when a blocking task outlives its waiter. It does not automatically charge custody
scratch memory or retain scratch cleanup errors. The staged writer, memory lease,
actual worker completion, and repeat-safe cleanup outcome must be part of the
same retained work owner before cancellation can detach the waiter. This task-owner
foundation is a prerequisite to production batching, not optional follow-up.

## Required validation

1. Keep the original 4,200/8,400 capacity and reopen workload under its original
   native profile and deadline. Record a fresh terminal result and actual process
   drain; preserve every earlier failure/timeout unchanged.
2. Cross both row and byte batch limits with varied record sizes; verify canonical
   values, counts, ordering, final digest, and reopen behavior against the existing
   semantics. Check final partial and empty batches.
3. Reject duplicate keys within one batch and across a commit boundary. Reject a
   malformed terminal record or mismatched head without exposing any `Records` or
   changing live custody state.
4. Deny memory before the first staging allocation/file; prove charged bytes and
   physical ownership remain unchanged. Retain resident charges across finished
   records and concurrent retained snapshots, and release only after actual close.
5. Inject pre-publication capacity denial, payload/header I/O failure, settlement
   failure, abort failure, and close failure. Preserve exact original failures and
   existing owner fences, including allocation-free publication boundaries.
6. Cancel or panic while a real batch worker is blocked before commit and during
   cleanup. Confirm the actual transaction, file, lease, and failure remain owned;
   retries must resume cleanup without premature charge release or false drain.
7. Verify transaction/metadata peak estimates at both limits and supported disk
   quota boundaries. The fixed cache setting alone is not adequate evidence.

Production batching still requires complete memory plans and registered actual
worker/database custody. The passing primitives alone do not satisfy those
dependencies or authorize relabeling an existing allowance as a complete bound.
