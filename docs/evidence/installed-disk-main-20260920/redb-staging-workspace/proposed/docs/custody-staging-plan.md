# Proposed bounded custody staging

Status: **batching proposed and unimplemented**. Terminal staging now permanently
rejects finish after a failed push; the batching, memory and task-owner design
below remains unimplemented. This document does not qualify the release or close
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


# Source-derived redb staging workspace audit

Status: partial structural derivation, not a qualified total workspace constant.
This is target-only work against the current main repository. No Cargo or actual
source edit was made. The authorized native LRU proof is separately recorded.
The original 4,200/8,400 custody workload, engine 512×256 workload, all deadlines,
quotas and point-insert durability remain unchanged.

## A concrete bound violation, corrected separately

The original LRU invalidation queue has no finite bound in terms of disk size,
live cache bytes, row count or batch bytes. The three-key exact native reproducer
and proposed nonallocating repair are in cache-review.md, cache.patch and
native-receipt.json. Do not publish any cache metadata envelope until that repair
or an equivalent bounded queue implementation is adopted and qualified.

## Actual storage shapes

The installed scratch table selects an 8 MiB redb payload cache. PagedCachedFile
has 131 read stripes and 131 separately Arc-owned write stripes. Each LRU has a
hash map and a VecDeque of u64 offsets; each page payload is an Arc<[u8]>.
The write-cache map includes None entries while WritablePage owns the payload.
WritablePage returns that same Arc on Drop. CheckedBackend and its real physical
StorageAdmission owner remain independently retained.

The cache setting is a soft payload target: read() allocates a miss before
insertion/eviction, write() explicitly permits overshoot when stripe locks are
busy or writable pages are borrowed, and borrowed PageImpl/AccessGuard values
can outlive cache eviction. Therefore 8 MiB plus entry overhead is not a safe total
heap bound. The unpublished writer must forbid escaping table/page guards,
parallel table mutation, external readers and savepoints before a smaller
single-worker pinned-page bound can be used. Those restrictions belong to the
new writer contract, not a new limit on ordinary point-table operations.

EncryptedSpool itself retains 65,536 plaintext bytes and 65,576 ciphertext bytes,
plus its real key/charge/owner/mutex metadata. These two buffers are per table,
not shared between the custody command and audit tables. The resident lease
must cover them and redb's installed structures until actual table destruction.

TransactionalMemory retains Allocators and, under debug_assertions, three maps:
all allocated PageNumbers, open dirty PageNumbers, and read PageNumber reference
counts. Emptying a map does not prove its retained allocation was freed. The
allocated-pages set scales with the whole installed file, not the current batch.
PageNumber serializes to 8 bytes, but its in-memory struct has u32,u32,u8 fields;
all heap formulas must use size_of::<PageNumber>(), never serialized_size().

A transaction creates 64 cache-line-aligned UncommittedShard mutex/hash sets in
one Arc-owned UncommittedPages object, plus user/system namespaces, PageTracker
owners, freed vectors, the transaction guard and savepoint state. The new writer
must not create savepoints. User PageTracker tracking can then disable after
the first mutation, but the shared uncommitted set is always required and cannot
be treated as optional debug data.

## Checked region/bitmap shape formula

Let D be the admitted redb logical extent cap, P=4,096, N=ceil(D/P), Q=2^20,
R=ceil(N/Q), and O=21 buddy orders. Ignoring file/region header occupancy here
increases the usable-page bound conservatively. Physical ciphertext growth is
still separately admitted by the real ScratchDisk and is not D.

For a BtreeBitmap with current count n and maximum count q:

- h(q) starts at 1 and repeatedly replaces q by ceil(q/64) until q≤64.
- n[0]=n; n[i+1]=ceil(n[i]/64), for i=0..h(q)-2.
- W(n,q)=sum ceil(n[i]/64) is the actual u64-word element count.
- EncBitmap(n,q)=4+8*h(q)+8*W(n,q) is its exact serialized byte length.
- HeapBitmap includes a Vec<U64GroupedBitmap> with h(q) live elements, each
  U64GroupedBitmap's Vec<u64> backing, all vector capacities/allocator overhead,
  and any overlapping old/new backing during resize. EncBitmap is not that heap.

For a region with n≤Q pages, there are O bitmaps at
n[o]=floor(n/2^o), q[o]=floor(Q/2^o), o=0..20. Its exact serialized size is
8+4*O+sum EncBitmap(n[o],q[o]). Even a small trailing region has the full padded
height/order metadata; this must not be estimated as only n/8 bytes.

The optimistic RegionTracker has 21 bitmaps for max(1,000,R) region slots, each
padded for MAX_REGIONS=2^20. Its encoded size is
4+4*O+O*EncBitmap(max(1,000,R),2^20). The initial 1,000 slots are real even for a
single tiny file. Allocators.region_allocators owns one BuddyAllocator per region.

allocator-shape.py implements these exact checked-shape relationships in a
non-admitting audit calculator, with outputs in allocator-shape.json:

| D | N upper bound | Buddy word payload | All buddy serialized bytes | Tracker serialized bytes |
| --- | ---: | ---: | ---: | ---: |
|64MiB|16,384|4,360|4,896|4,036|
|256MiB|65,536|16,824|17,360|4,036|
|1GiB|262,144|66,728|67,264|4,036|
|8GiB|2,097,152|532,848|533,920|4,036|
|1TiB|268,435,456|68,204,544|68,341,760|4,036|

These are component counts/serialized payloads, never proposed total memory caps.
They omit vector spare capacity, object layouts, maps, native locks, allocation
headers, working copies and error backing. They must not be charged as the whole
transaction or substituted for the current workload's explicit limits.

## Commit peaks that payload batching does not remove

reserve_allocator_state serializes every region to obtain lengths, retains a
Vec<usize> of region lengths, then allocates zero-filled values and inserts them
into the system tree. try_save_allocator_state holds the original Allocators and
constructs a complete second Allocators through to_vec/from_bytes, before applying
deferred reclamation to the copy. The original and prepared copy coexist.

BuddyAllocator::to_vec retains a Vec<Vec<u8>> of all serialized order bitmaps
while building its final output. Each bitmap serialization likewise retains
serialized level vectors while building its result. RegionTracker performs its
own temporary serializations. A formula must sum simultaneously live buffers and
collection headers, including realloc overlap; multiplying only the final byte
length by an unexplained constant is not a proof.

process_freed_pages builds a local deferred Vec<PageNumber>, then extends the
transaction's deferred_reclaim while that source vector remains alive. Freed
pages from previous commits stay physically allocated until this transaction
publishes, so reclamation work may scale with N even for a one-row transaction.
User/system freed vectors and per-Btree local_freed vectors also coexist at some
boundaries. Preserve the copied source vector term; consuming the iterator or
streaming into the retained vector would be a separate optimization.

Table root updates use BTreeMap<String,...>; active tables use a BTreeMap of names.
A dedicated one-table writer can bound user table count, but system allocator/
freed/allocated tables must be included. LeafBuilder stores pairs of slices;
BranchBuilder stores child/checksum tuples and slice keys, and deletion can own
copied keys and leaf data in OwnedEntryBuffer. Normal insert follows a tree path
and can split/copy old pages. Commit-time system-table deletion is also in scope,
even when the public writer only inserts. Its temporary memory cannot be bounded
solely by bytes submitted in this batch.

## Shape-to-byte API proposal

Do not expose an unqualified numeric required_workspace yet. Implement a vendor
internal, checked ScratchWorkspacePlan for the restricted writer profile, with
separate resident and transient fields and component breakdowns. Its inputs are
D, cache target, maximum encoded key/value sizes, batch row/byte limits, and the
exact build/debug layout. Store's public profile chooses supported constants and
passes the same physical/memory owner; users cannot supply an arbitrary byte
estimate or omit admission.

Required resident component expression:

  table/spool/database/guard/native-lock fixed layouts
  + two spool buffers and allocation headers
  + 131 read-stripe layouts + 131 Arc write-stripe layouts
  + retained cache map/queue capacity envelopes + Arc page payload envelope
  + HeapAllocators(D)
  + debug map capacity envelopes (including whole-file allocated pages)
  + admitted owner/lease/retained terminal outcome bookkeeping.

Required active transaction component expression:

  concrete retained WriteTransaction/guard/namespace/lock layouts
  + 64 aligned uncommitted shards and their map capacity envelopes
  + open-table/root-update string/BTreeMap envelopes
  + all simultaneous allocated/freed/deferred/local page-number vectors
  + one additional HeapAllocators(D) prepared commit copy
  + maximum simultaneous allocator serialization/zero-fill buffers
  + path/split/deletion scratch and borrowed page overshoot
  + caller's bounded encode/decode/input workspace and exact outcome custody.

Sum both resident table owners plus both concurrently pending transaction
components for custody's two writers. Finishing batches may release transaction
workspace only after actual retained-terminal settlement/destruction. Finished
Records retain both resident leases through real table close and backing release.
For terminal rows, use the existing 2 MiB row limit plus both index encodings; the
custody 64 KiB / 1 MiB profile is not an alternate terminal limit. No whole-history Vec
is introduced.

Useful finite cardinalities: every live nonoverlapping page occupies at least
one base-page slot, so live allocated/uncommitted sets have at most N entries.
Across page orders, the entire possible PageNumber key universe is at most 2N;
this conservative bound is useful when summing retained high-water capacities
across 64 shards. Cache offset keys occupy at most N+1 starts including the header.
After the LRU fix, each queue has one live registration per map key. Do not sum
only current len after eviction; each stripe can retain capacity from a previous
peak. Debug maps and cache capacities belong to resident lifetime, not the next
short batch lease.

## Remaining coefficients and the next bounded implementation

A complete conservative numeric total is still not justified by the current
source. The audited toolchain is rustc 1.97.1 on aarch64-apple-darwin, but local
rust-src is absent. Std HashMap/BTreeMap/Vec allocation geometry is not specified
by the stable collection API. Pin and audit that toolchain's actual geometry or
replace the affected containers with explicitly bounded storage; do not guess
HashMap overhead, assume len==capacity, or call allocator-shape output total RAM.
The existing 8 MiB payload target likewise needs a proven restricted-worker bound
for pinned/overshoot pages and a path/deletion scratch bound before it is usable.

The next concrete vendor slice should add type-local layout/shape helpers (using
size_of of the real private types), capacity/peak instrumentation for each listed
container and buffer, and tests at region growth/commit-copy/reclaim boundaries.
The helper must reject overflow/unsupported policy before constructing a table.
Then establish the single-worker insert/commit scratch cardinalities and turn
those checked envelopes into mandatory leases. Peak observations validate a
source-derived bound; they cannot by themselves certify a worst-case coefficient.
Run debug and optimized shapes explicitly; never switch the native gate profile
to omit debug maps or raise the existing total budget to conceal missing terms.

Source inventory and hashes are in workspace-source-manifest.json. This audit
closes the LRU metadata counterexample with a concrete patch, but intentionally
does not label batching memory admission implemented or qualified.
