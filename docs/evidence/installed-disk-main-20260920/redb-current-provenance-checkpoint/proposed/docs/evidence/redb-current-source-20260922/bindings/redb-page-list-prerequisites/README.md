# PageList validation and extraction-close prerequisites

Status: target-only, uncompiled and unexecuted. This is a canonical record and
publication-safety prerequisite. It does not implement bounded-prefix reclaim,
a fixed reclaim-memory envelope, automatic maintenance, or a total workspace
bound. Root owns actual source integration and Cargo. No actual source was edited.

## Concrete current gap

process_freed_pages flattens every eligible DATA_FREED_TABLE and
SYSTEM_FREED_TABLE record into a new local Vec<PageNumber>, then extends the
transaction's deferred_reclaim Vec. Both capacities can coexist. A long-lived
reader/savepoint can accumulate historical records far beyond a later tiny
transaction's row/byte profile. The writer's per-record capacities bound each
encoded record, not the accumulated memory or work. That Vec behavior remains
unchanged in this prerequisite and must not be described as fixed memory.

The current PageList decoder trusts its u16 length before indexing. The system
extract iterator also has no automatic transaction poison target. It must be
explicitly closed before publication, especially if a later bounded-prefix
implementation stops before exhaustion; Drop discards the close result.

## Changes prepared

PageListKind supplies the one canonical capacity for each family: Data=400
entries and System=200. Their exact serialized buffers remain 3,202 and 1,602
bytes. PageList::checked requires the corresponding exact buffer size and a
nonzero count no larger than that capacity. Invalid input returns inline
StorageError::InvalidPageList (also represented in Error). It does not allocate
a diagnostic String. Unused padding is unconstrained because legitimate
insert_reserve initialization only initializes the length area and used entries.
No alternate compact/short/oversized record decoder or compatibility alias exists.

All current producers directly use the named capacities:

* store_data_freed_pages_for: Data=400.
* write_allocated_pages_entry: Data=400.
* store_system_freed_pages: System=200.

No current writer emits a zero-count record: each enters its insert loop only
with a nonempty page collection and writes at least one entry. No writer shape
change was needed. Recovery/debug/savepoint readers now request a checked view
with the exact family, so the unchecked PageList len/get surface is removed.
This validates shape/count; full page-number encoding, duplicate/overlap and
allocator reachability validation remain separate obligations.

process_freed_pages validates BOTH eligible namespaces while holding its existing
system-namespace lock, before extracting either. It produces two small inline
validated-range tokens containing table definition, kind, exact root and horizon.
Extraction rejects a changed table root and consumes only its validated range.
Thus a malformed SYSTEM record cannot be discovered only after valid DATA
records have already been removed. This adds one read pass over the existing
eligible history; it does not add a collection or claim bounded traversal. Future
prefix adoption must bound that selected range and its separately admitted cursor
workspace.

Extraction explicitly closes its iterator. A successful scan followed by a close
failure returns that original error unchanged and poisons the transaction. A
prior iteration error remains the primary result rather than being replaced by
close's repeated PreviousIo. The allocated-page purge also validates its selected
range and explicitly closes; savepoint purge validates before its existing
explicit close. Header ordering, allocator-copy preparation, deferred physical
freeing, growth admission and abort settlement are unchanged.

## Prepared regressions

1. Both record families accept a partly used canonical buffer with nonzero
   unused padding and a fully used buffer, with zero observed decoder allocations.
   Empty/one-byte/compact/zero-count/over-capacity/cross-family buffers reject
   without allocation.
2. A malformed later DATA record or malformed SYSTEM record rejects before any
   selected DATA/SYSTEM record is removed. The transaction is poisoned, real abort
   restores its prior namespace, explicit matching transaction disposal releases
   the writer, and both retained database close phases must succeed.
3. Early close after one real extracted SYSTEM entry requires a COW allocation.
   The fixture first consumes the exact currently free page count, then injects
   an original I/O error after actual grown-file synchronization. It checks the
   original error payload identity, actual growth and sync, owner/transaction
   fences, retained abort outcome and refused disposal. The exact error,
   transaction, matching database and file remain in fixed test custody; dropping
   an uncertain owner is not used as cleanup evidence.

These three tests are unexecuted. The early-close fixture deliberately exercises
an early exit through the same finalization helper without enabling a production
prefix limit. Full vendor/admission/cache/retained terminal checks, strict lint,
and relevant store no-allocation/rollback checks remain coordinated root gates.

## Prefix and maintenance dependency

Leaving unselected eligible records intact is visibility-safe if their pages stay
allocated. Only selected page IDs enter the prepared allocator copy and are freed
after the winning-header protocol. Savepoints are already represented in the
live-read horizon. try_shrink sees the live allocator before deferred release,
so retained pending pages cannot be trimmed out. Repair visits remaining freed
records and retains their pages.

This does not prove progress. A fixed prefix can accumulate maintenance debt
under sustained writes. compact currently performs only two cleanup commits;
a prefix implementation cannot silently keep implying that those drain arbitrary
historical debt. Before adoption it needs an explicit progress/debt contract,
a separately admitted cleanup owner and workspace, and reserved physical space
for COW paths, allocator-state construction and system bookkeeping. Maintenance
itself creates system bookkeeping, so its net progress and reserved headroom need
source-derived bounds. No hidden all-history loop, raised disk/memory limit or
longer deadline is introduced here.

The generic BtreeExtractIf::latch_error currently discards a secondary error from
its own attempt to close after an iteration error. This package preserves the
primary error and any directly observed close failure; it does not claim to
recover that already-discarded generic secondary outcome or an arbitrary panic
payload. A broader retained iterator/drain protocol is a distinct prerequisite
if production custody requires both actual generic phases.
