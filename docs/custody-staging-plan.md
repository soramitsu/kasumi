# Proposed bounded custody staging

Status: **proposed and unimplemented**. This document records a performance finding
and a production design; it does not qualify the current implementation or close
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

At the time this proposal was written, gate29 had no terminal outcome. Its native
qualification remains open; the authoritative eventual outcome belongs in its
gate result and release evidence, not an inferred success in this document.

## Smallest streaming change

Introduce an owned, unpublished encrypted-table writer in
`crates/kasumi-store/src/scratch_table.rs`, with dedicated tests in
`scratch_table_tests.rs`. It owns the original `EncryptedTable` and an optional
`redb::WriteTransaction`; redb transactions already own their backing Arcs and
do not require a self-referential borrow. Do not expose a raw redb transaction or
backend to custody callers.

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

- Two 8 MiB redb cache payload budgets and their entry, stripe, lock, and owner
  metadata. `set_cache_size` bounds cache payload, not all redb memory.
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
guards before consuming a transaction. On normal completion, commit the final
partial transaction before exposing its table. On failure, abort any still-live
transaction and close the private table; preserve the original error together
with any abort or close error in the owning drain report. A close that reports
retained ownership must retain the table and its memory lease for retry.

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

Implementation is deferred until the memory and task-owner prerequisites are
concrete and the current frozen-source gates have reached terminal outcomes.
