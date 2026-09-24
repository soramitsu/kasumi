# Retained redb terminal boundary prerequisite

Status: **prepared only; not applied, compiled, or executed**. Work is confined to
`/Users/mtakemiya/dev/kasumi` on `master`. Exact base/proposed identities are in
`manifest.json`; source facts refer to the pending source on top of `600c0ca`.

## Scope and behavior

`WriteTransaction::retain` moves the exact transaction into inline
`RetainedWriteTransaction` state. It borrows the transaction for normal table work
only before terminal entry. The mutable terminal call cannot coexist with a table
guard borrowing that transaction. Before any terminal effects, the owner records
Commit or Abort and marks the underlying consuming-API drop flag so fallback Drop
cannot replay an abort. That flag is never treated as proof of cleanup.

Commit calls the actual existing `commit_inner_helper` by mutable borrow. Abort
calls the actual existing `abort_inner` by mutable borrow. Each actual invocation
has one fixed original-outcome cell. `catch_unwind` records the original boxed
panic payload without stringification, and leaves the transaction in the owner.
The API is present only under std with `panic=unwind`; it supplies no compatibility
implementation under no_std or panic=abort.

Successful commit returns `Settled`. CapacityDenied or TransactionPoisoned enters
one rollback and preserves the original commit refusal independently of that
rollback's actual success, error, or panic. Successful abort/rollback returns
`Settled`; any other error or unwind remains `Retained`. All uncertain paths leave
the existing allocator-state latch armed, refusing reuse of the uncertain
allocator. A repeated commit, abort, or report only borrows the first accepted
operation and original outcomes. In particular, abort after an uncertain commit
cannot replay cleanup or create a second successful terminal path.

**Settled describes only the transaction terminal operation.** It does not report
Complete drain, dispose of the transaction, close the database/backend, prove
bounded diagnostic backing, or authorize charge release. No consuming disposal or
close is added here. Even a successful transaction still owns its transaction
slot/backing until the caller disposes of that state and independently closes its
database/backend. Existing consuming `Database::close` is not a retained panic
boundary and remains a separate prerequisite for complete table cleanup.

**The wrapper is not self-retaining.** The production staging owner must reserve
its real backing, register the wrapper in its fixed census before dispatch, and
keep the exact wrapper and all charges through caller cancellation and Retained
outcomes. Dropping a wrapper, including through caller unwinding, is not cleanup
evidence. There is no mem::forget, detached reaper, synthetic task outcome, guessed
memory coefficient, or independently allocated fallback governor. The wrapper
has fixed observation cells but errors/panic payloads may own unbounded backing;
this patch does not establish their admission bound.

## Meaningful tests prepared, all unrun

Eight unit tests operate on real admitted redb databases backed by temporary files:

1. Commit and abort preserve the first terminal operation, cannot replay or resume
   mutations, retain the same transaction object during the call, then dispose and
   explicitly close/reopen; an aborted second key remains absent.
2. An actual table retain callback panics, poisoning its transaction; commit keeps
   TransactionPoisoned and independently proves its successful rollback.
3. Actual growth admission fails during insertion; commit retains CapacityDenied,
   records successful rollback, and leaves the prior committed row intact.
4. Actual backend sync returns an I/O error carrying an identifiable original
   object; the transaction, error, and identity remain retained without another
   backend call during terminal retries.
5. Actual abort settlement fails OwnerFailed and cannot become CapacityDenied.
6. Capacity refusal followed by failed rollback settlement preserves both original
   error objects in separate cells.
7. The backend panics **after the winning header is really written and synced**.
   The same original panic and transaction remain retained, no terminal replay
   occurs, and a separate crash-image copy recovers the newly committed row. This
   positively demonstrates why an interrupted commit cannot be assumed aborted.
8. A panic in actual rollback settlement preserves the first CapacityDenied and
   the exact separate rollback panic payload.

The five uncertain cases are installed in a **fixed five-slot test-only census**
which retains their actual transaction, Database and tempfile for the rest of the
test process. Each positively checks explicit Database::close returns Busy and
backend close has not run. This is unresolved ownership, not cleanup success.
The test census is not a production adapter or a memory-bound claim. Static
process teardown is not reported as drain evidence.

## First-release adoption remains mandatory

This is a vendor prerequisite, not an optional production safe-mode switch. The
existing consuming upstream APIs remain for dependency behavior and its existing
tests; that does not authorize a Kasumi production bypass. The eventual supported
Kasumi boundary must directly adopt the retained terminal owner and update every
supported caller together. No compatibility overload, retry fallback, decoder or
migration is part of this patch.

Current unconverted production redb terminal call sites are:

| Caller | Consuming commits | Required integration |
| --- | --- | --- |
| `crates/kasumi-store/src/node_database.rs:73` | central begin_write boundary | Return/install the retained admitted owner; migrate its supported callers together. |
| `crates/kasumi-store/src/lib.rs` | 331, 381, 951 | Initial/wrapped-key catalog and ordinary store write. |
| `crates/kasumi-store/src/scratch_table.rs` | 126, 146, 165 | Table creation, point insertion and removal; raw Database bypass also needs direct adoption. |
| `crates/kasumi-store/src/storage_domains.rs` | 200, 358 | Paired domain initialization/publication. |
| `crates/kasumi-store/src/storage_domains/catalog_initialization.rs` | 341 | Initial catalog publication. |
| `crates/kasumi-store/src/read_view.rs` | 37 | Table replacement publication. |
| `crates/kasumi-store/src/live_trust.rs` | 121 | Verifier/trust persistence. |
| `crates/kasumi-store/src/single_catalog.rs` | 350 | Single-domain catalog publication. |

These are twelve production commit calls across seven files plus the central
transaction acquisition boundary. The broader raw search is preserved in
`kasumi-callers-search.txt`, including tests and unrelated task abort methods; it
is not misrepresented as a production redb call count. All these callers remain
unconverted by this vendor-only proposal.

## Validation and remaining work

Only target-file Rust formatting/syntax parsing, exact source hash comparison and
`git apply --check` are authorized/performed here. No Cargo build or test pass is
claimed. Root must compile and run the eight tests and existing redb transaction,
admission and failure tests on the exact integrated source, with default and
all-feature supported builds, and run strict Clippy/format checks. Validate actual
panic and fault branches rather than inferring them from prepared tests.

The audited transaction/cache/allocator memory formula, fixed charged production
staging owner, original diagnostic admission, explicit retained database/backend
close and snapshot decoder/shutdown adoption remain open. No staging batch is
enabled. The original 512-by-256 / 60-second / 80 MiB restore and the original
384 MiB / 40-by-768 KiB backup workload must remain unchanged; this prerequisite
is not a reason to rerun those unchanged expensive cases before batching exists.
