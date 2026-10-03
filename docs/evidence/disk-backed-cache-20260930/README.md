# Native cache and ordered directory development checkpoint

Date: 2026-09-30. The [full disk-backed storage goal](../../disk-backed-cache-goals.md)
remains active. This checkpoint establishes native foundations, not a
production disk-backed document/query engine.

## Verified work

- A byte-bounded native cache keeps every fitting value, charges owners,
  directory storage, allocation allowances and reader pins, and uses frequency
  and recency admission under pressure.
- Core/Database reads, durable write publication, obsolete-version pruning,
  compaction identity relocation, bounded refill and sealed-facade behavior
  exercise that cache.
- Immutable directory pages support ordered point/successor lookup, snapshot
  roots, and sorted streaming construction with admitted workspace smaller
  than the resulting directory.
- Cache-enabled crash matrices inject failure before, after and during every
  backend commit and compaction effect.

## Initial native-cache development checks

All commands ran locally with Rust 1.97.1 and locked offline dependencies.
The persistent build lane for this goal is `target/disk-backed-cache`; reuse
it for subsequent iterations.

| Command (prefix Cargo commands with `CARGO_TARGET_DIR=target/disk-backed-cache`) | Result |
| --- | --- |
| `cargo test -p kasumi-kv --lib --locked --offline` | 166 passed |
| `cargo test -p kasumi-kv --test crash_recovery --test owner_fencing --test transaction_rollback --test commit_allocation --locked --offline` | 30 passed: 9 crash/recovery, 9 owner fencing, 8 rollback, 4 allocation |
| `cargo test -p kasumi-kv --lib cache --locked --offline` | 23 passed after lint cleanup |
| `cargo test -p kasumi-kv --lib directory::tests --locked --offline` | 8 passed after lint cleanup |
| `cargo clippy -p kasumi-kv --all-targets --locked --offline -- -D warnings` | Passed |
| `cargo fmt -p kasumi-kv -- --check` | Passed |
| Scoped `git diff --check` | Passed |

The full 166-case and 30-case runs preceded structural lint cleanup: a named
warm-up item replaced a complex tuple, an equivalent nested condition became
a let chain, test declarations moved to the end of the directory module, and
exports were formatted. The final 31 focused cases, strict Clippy and formatting
cover the resulting source. The [selected final hashes](selected-final.sha256)
were unchanged across final focused validation. The
[earlier library-run hashes](library-run-selected.sha256) record the selected
source before that cleanup. These are selected-file pins, not a frozen
workspace or release qualification. Full raw logs are retained in the chat's
tool outputs rather than archived here.

Earlier development attempts exposed and corrected replacement-at-capacity
eviction, rejected-write cache candidates, refill retry, sealed-facade work,
writer snapshot retirement and tombstone work accounting. A concurrent merge
also temporarily introduced a test calling the removed `retain_in` API; the
current prefix tests use `retain_prefix`. The first strict Clippy pass failed
on type complexity, a collapsible condition and test-module placement; those
were repaired before its passing run. Two checks queued behind another
workspace build were explicitly terminated before moving to the persistent
lane; they produced no test result.

## Directory integration development checkpoint

The next source adds incremental COW updates, an owner-bound directory page
cache, append-only physical arenas and a selected directory/replay anchor in
the mirrored superblock. Native cache keys retain full equality identities even
when their hashes collide. The installed NodeDisk group owner recognizes
`.kvdir` arenas with independent counters and its descriptor cache.

Regression coverage exercises balanced splits and deletion to an empty tree,
old snapshots, constant mutation workspace as the directory grows, private
mutations leaving caches unchanged, zero repeated page I/O for fitting cached
trees, restart through fresh arena owners, admission denial, owner expiry during
I/O, unknown creation/confirmation/synchronization results, canonical root
encoding, strict old-format rejection and adjacent-root rollback rejection.

The [selected source pin](directory-integration-selected.sha256) covers the
native components and the changed NodeDisk group owner. These remain development
checks of selected source, not a frozen workspace or release qualification.

The first strict Clippy run reported larger enum variants after adding the
directory commit fields, plus two manual divisibility expressions in a new test.
The root-selection variants retain their small, fixed, inline metadata with a
documented local lint allowance; boxing would add fallible allocations to the
recovery path. The test now uses `is_multiple_of`. The [library-run source
pin](directory-library-run-selected.sha256) preserves the pre-lint source.

| Command (same persistent Cargo target and locked offline dependencies) | Result |
| --- | --- |
| `cargo test -p kasumi-kv --lib --locked --offline` | 199 passed |
| `cargo test -p kasumi-kv --test crash_recovery --test owner_fencing --test transaction_rollback --test commit_allocation --locked --offline` | 30 passed: 9 crash/recovery, 9 owner fencing, 8 rollback, 4 allocation |
| `cargo test -p kasumi-store --lib node_file::segment_group --locked --offline` | 18 passed; one subprocess helper ignored |
| `cargo test -p kasumi-kv --lib root:: --locked --offline` | 30 passed after lint adjustment |
| `cargo test -p kasumi-kv --lib directory::tests::cow_mutations_and_snapshots_match_ordered_model --locked --offline` | Passed after lint adjustment |
| `cargo clippy -p kasumi-kv --all-targets --locked --offline -- -D warnings` | Passed after the documented adjustment |
| `cargo fmt -p kasumi-kv -- --check` | Passed |
| Scoped `git diff --check` and selected-file SHA-256 verification | Passed |

Store validation required a cold dependency build in the persistent lane; native
validation waited for that build rather than using another target directory.
The library run preceded the lint-only root annotations and equivalent test
divisibility expressions. Integration and the 31 focused checks, strict Clippy
and formatting ran on the adjusted source. Source pins distinguish these
versions; full command output remains in the chat tool outputs.

## Composed native directory checkpoint

The internal `DiskState` now composes prepared segmented operations, immutable
directory publication, exact commit-bound replay and a shared page/value cache.
The canonical root and every directory edge carry full SHA-256 identities;
retired formats are rejected. Group/store types share one backend contract,
census streams names, and the checked adapter validates owner lifetime around
every backend operation and streamed callback. Close remains callable after
owner failure.

The full library run passes **239 tests**. This includes nine composition tests
covering atomic multi-table state and old roots, immediate residency of fitting
writes (including table-only and delete-only commits), bounded pressure and
refill after budget growth, a 4 MiB value population reopened under a 3 MiB
native admission allowance, retryable allocation denial after prepare, every
commit effect before/after failure, owner checks on cache hits, publication
panic classification, and a recovered commit followed by a later abandoned
segment. The allowance test measures the native admission ledger, not process
RSS; its in-memory test backend intentionally stands in for disk.

Additional tests prove that COW reads may reuse committed cache hits without
admitting private intermediate pages, final split siblings are warmed, fallback
page reads cannot falsely report full residency, retained writer staging stays
at its charged 64 KiB capacity, and cursor-close failures cannot be hidden by a
census callback error.

| Command (same persistent Cargo target and locked offline dependencies) | Result / retained output |
| --- | --- |
| `cargo test -p kasumi-kv --lib --locked --offline` | 239 passed; [log](native-composition-library.log) |
| `cargo test -p kasumi-kv --test crash_recovery --test owner_fencing --test transaction_rollback --test commit_allocation --locked --offline` | 30 passed: 9 crash/recovery, 9 owner fencing, 8 rollback, 4 allocation; [log](native-composition-integrations.log) |
| `cargo test -p kasumi-store --lib node_file::segment_group --locked --offline` | 21 passed; one intentionally ignored subprocess helper; [log](store-group-boundary.log) |
| `cargo clippy -p kasumi-kv --all-targets --locked --offline -- -D warnings` | Passed; [log](native-composition-clippy.log) |
| `cargo fmt -p kasumi-kv -- --check` | Passed after formatting one new test literal |

The [library-run pin](composition-library-selected.sha256) covers 20 selected
source files. The [final pin](composition-final-selected.sha256) differs only
in formatting a test `Operation::Delete` literal in `segment.rs`; the 30 integration
tests, strict Clippy and formatting passed on that final source. Store group validation preceded the
final private-cache-view and composition-only changes; the shared store boundary
and its tests were unchanged. These pins are selected-source development
evidence, not a frozen checkout or production release qualification.

Earlier focused attempts exposed two stale small-segment placement assertions
after increasing commit metadata, a missing replay-root fixture field, an
outdated arena test backend method, private panic-constructor visibility, and a
String/Arc mismatch in a new sizing test. These were corrected before the full
239-case passing run. The final formatting check initially reported the test
literal noted above. A preliminary 19-case composition run and 85-case directory
run also passed; their logs remain alongside the full run. No failed run is
represented as final-source qualification.

## Internal snapshot and whole-file reclamation checkpoint

The internal `DiskState` now owns an admitted snapshot registry with a fixed
256-slot limit. Each independently acquired snapshot consumes one slot and one
admitted allocation; clones share both until the final clone drops. Reads check
exact registry identity, not just a matching group ID. Captures deduplicate
roots within the same bound. Strict epoch validation remains available, while
reclamation coverage validation permits retired pins and newly acquired pins of
the already-scanned current root. This allows bounded reclamation to progress
despite current-reader churn without admitting uncaptured historical roots.

An uncached, resumable directory walker retains bounded admitted page/path
workspace. Each scan considers at most 128 candidate files and checks the selected
tree and every captured pinned tree. Root publication changes invalidate the
proof. Garbage is published to both root slots before exact unlink and parent
synchronization; only successful unlink allows the record to be forgotten.
Reopen re-proves recorded garbage before unlinking, including references through
child arenas. Retiring cache identities preserves output guards and their byte
charges until the final guard drops. Failure releases scan scratch, and snapshot
reservation owner failure fences later writes even if subsequent owner checks
would otherwise recover.

| Command (same persistent Cargo target and locked offline dependencies) | Result / retained output |
| --- | --- |
| `cargo test -p kasumi-kv --lib --locked --offline` | 272 passed in 43.50 s; [log](reclamation-library.log) |
| `cargo test -p kasumi-kv --test crash_recovery --test owner_fencing --test transaction_rollback --test commit_allocation --locked --offline` | 30 passed: 9 crash/recovery, 9 owner fencing, 8 rollback, 4 allocation; [log](reclamation-integrations.log) |
| `cargo clippy -p kasumi-kv --all-targets --locked --offline -- -D warnings` | Passed; [log](reclamation-clippy.log) |
| `cargo fmt -p kasumi-kv -- --check` | Passed; [empty success log](reclamation-format.log) |
| Selected-file SHA-256 verification | All 25 entries verified; [source pin](reclamation-selected.sha256) |

The [initial focused run](reclamation-focused-initial.log) ran 38 tests: 35 passed
and three failed because the fixtures had not forced a segment roll, leaving
the segment they expected to reclaim protected as active. After correcting the
fixtures, the [focused rerun](reclamation-focused.log) passed all 38. An eighth
reclamation regression covering more than 128 garbage files and a cache-pruning
regression were then added before the full 272-case run. That full run includes
the snapshot, walker and reclamation regressions, including unlink/forget fault
injection, restart revalidation, bounded admission and retained output charges.
The failed log is retained; it is not represented as passing evidence.

This is a selected-source checkpoint for the internal snapshot/reclamation
stage, not a frozen checkout or qualification of later maintenance changes.
The earlier store group-owner run remains separate evidence; it was not rerun
as part of this checkpoint. Reclamation here removes only wholly unreachable
files. Partially live file evacuation, full compaction and the live
Core/application cutover remain open, as do goals C01–C07.

## Streamed maintenance development checkpoint

The internal state machine now rotates the segment and arena appenders, then
evacuates records through explicit maintenance commits. Each relocation streams
an immutable value through 64 KiB windows and preserves its logical batch
sequence. Directory-only commits copy paths while preserving table birth and
row versions. Root-only replay validates every operation without retaining the
decoded operation keys. Segment version 3 replaces version 2 directly.

Maintenance reads bypass demand admission and frequency training. Published
pages are retained only when they fit without evicting useful entries. A hot
relocated value keeps both immutable addresses when they fit; pressure moves
the cached identity while preserving output guards and unrelated cached data.
Reclamation still requires proof over the selected root and all relevant pins.

| Command (same persistent Cargo target and locked offline dependencies) | Result / retained output |
| --- | --- |
| `cargo test -p kasumi-kv --lib --locked --offline` | 310 passed in 51.70 s; [log](maintenance-library.log) |
| `cargo test -p kasumi-kv --test crash_recovery --test owner_fencing --test transaction_rollback --test commit_allocation --locked --offline` | 30 passed: 9 crash/recovery, 9 owner fencing, 8 rollback, 4 allocation; [log](maintenance-integrations.log) |
| `cargo test -p kasumi-store --lib node_file::segment_group --locked --offline` | 21 passed; one intentionally ignored subprocess helper; [log](maintenance-store-group.log) |
| `cargo clippy -p kasumi-kv --all-targets --locked --offline -- -D warnings` | Passed; [log](maintenance-clippy.log) |
| `cargo fmt -p kasumi-kv -- --check` | Passed; [empty success log](maintenance-format.log) |
| Selected-file SHA-256 verification and `git diff --check` | Passed; [29-file source pin](maintenance-library-selected.sha256) |

The full run includes a six MiB value relocated and recovered after an unknown
publication under a three MiB native admission allowance. That is an admission
ledger test, not a process RSS measurement; the in-memory backend and test inputs
stand in for disk and callers. Other regressions cover concurrent foreground
changes on both sides of the cursor, preserved old/current cache hits, original
output charges after reclamation, before/after-effect failure and restart,
root-only replay corruption checks, source changes during a streamed copy,
and retryable denial at 32 allocation reservation points.

The [first focused attempt](maintenance-focused-initial.log) stopped at a missing
test result type annotation. The [next run](maintenance-focused.log) passed 30
of 31 tests; the arena fixture incorrectly expected an empty namespace even
though the in-memory backend always lists its root file. Comparing the unchanged
namespace corrected that fixture. The [first full run](maintenance-library-initial.log)
passed 309 of 310 tests; a root corruption fixture still treated version 3 as
unsupported after the format advanced to version 3. The test now derives an
unsupported version from the current constant. Its [source pin](maintenance-library-initial-selected.sha256)
is retained separately. The allocation-denial composition test was expanded
before the [three passing repair checks](maintenance-repair-tests.log) and the
final 310-case run. No failed or earlier-source run is presented as final-source
qualification.

This remains an internal maintenance foundation. One entry-sized work unit can
synchronously copy up to `MAX_VALUE_BYTES`; it is not a latency or byte-per-call
guarantee. Per-record COW also leaves unused pages inside partially live output
arenas, so production compaction requires leaf batching, dense page packing and
bounded temporary disk growth. The [follow-up plan](../../disk-compaction-followup.md)
defines those implementation and qualification steps. The live Core and
application cutovers and goals C01–C07 remain open.

## Leaf-batched maintenance and shared residency checkpoint

The internal maintenance path now borrows keys from one admitted, validated
directory leaf and relocates a bounded batch before rewriting the leaf and its
ancestor path once. Plans have a 512-record ceiling and target 1 MiB of encoded
records; one larger value may exceed that target up to `MAX_VALUE_BYTES`.
Sources are checked before destination writes and streamed through 64 KiB
windows. Fresh leaves without old locations can be skipped without publication.
Logical row and table versions, old snapshots and foreground cursor semantics
remain covered by the tests. Segment format version 4 directly rejects version 3.

Physical relocation now retains old and new cache identities over one shared
immutable payload. Each identity's directory metadata remains charged; payload
and lease charges survive until the final alias or reader releases them. The
new composed regression keeps a 512 KiB value and both snapshot lookups under a
700 KiB cache limit, with pointer-identical output allocations, no eviction and
zero storage reads for both snapshots after compaction. It then reclaims the
old physical files and checks the surviving lookup and reader-held allocation.
Four additional native cache regressions exercise alias chains, rehash, pruning,
clear, cross-thread final release and budget shrink. All 45 focused cache/page
cache and compaction checks passed in the
[focused sharing run](leaf-batch-shared-cache-initial.log).

Normal preparation now reserves fixed streamed replay workspace plus exact
returned-location backing, independently of borrowed payload size. A 6 MiB
normal write, relocation and reopen fit a 3 MiB native admission allowance.
This is a ledger measurement, not process RSS: the in-memory disk stand-in and
caller inputs are outside that allowance. Abort additionally verifies the exact
prepared batch, end position, operation count and digest before discarding any
bytes. Damaged synchronized bytes, resealed substitutions, fewer or extra
records and publication-record substitutions fence the writer and preserve
evidence. The [28 focused recovery checks](leaf-batch-strict-abort.log) passed.

The 1,200-row structural workload has height two and seven leaves. Compaction
performs seven maintenance commits and writes 14 directory pages while copying
4,800 value bytes. The historical per-record path formula would write 2,402
pages for those 1,201 entries (including the table marker); that comparison is
an operation-count baseline, not a measured device benchmark. The same test
checks completion and exact old/current reads.

The [selected-source pin](leaf-batch-selected.sha256) covers 31 files. The earlier
310-case checkpoint remains historical evidence. Commands use the persistent
`CARGO_TARGET_DIR=target/disk-backed-cache` lane and locked offline dependencies.

| Command | Result / retained output |
| --- | --- |
| `cargo test -p kasumi-kv --lib --locked --offline -- --show-output` | 343 passed in 122.66 s; [log and workload counters](leaf-batch-library.log) |
| `cargo test -p kasumi-kv --test crash_recovery --test owner_fencing --test transaction_rollback --test commit_allocation --locked --offline` | 30 passed: 9 crash/recovery, 9 owner fencing, 8 rollback, 4 allocation; [log](leaf-batch-integrations.log) |
| `cargo test -p kasumi-store --lib node_file::segment_group --locked --offline` | 21 passed in 38.94 s; one intentionally ignored subprocess helper; [log](leaf-batch-store-group.log) |
| `cargo clippy -p kasumi-kv --all-targets --locked --offline -- -D warnings` | Passed after payload sharing; [log](leaf-batch-clippy.log) |
| `cargo fmt -p kasumi-kv -- --check` | Passed; [empty success log](leaf-batch-format.log) |
| Selected-source hashes, whitespace/newlines and scoped `git diff --check` | Passed; [verification record](leaf-batch-verification.log) |

Earlier leaf-batch attempts are retained. The
[first focused compilation](leaf-batch-focused-initial.log) used a nonexistent
test fault-operation variant. The [next run](leaf-batch-focused.log) passed 38
of 39 cases; its large-value fixture exposed normal-write replay workspace
over-reservation before compaction started. The
[six fixed-workspace checks](leaf-batch-fixed-workspace.log) passed after the
reservation correction. Subsequent review found the exact-prefix abort gap and
the redundant cache payload allocation, both corrected before the final pin.
The [initial strict Clippy run](leaf-batch-clippy-initial.log) passed before
payload sharing and is not represented as validation of that later change.

At this checkpoint, leaf batching did not densely pack sparse leaf/internal pages
or ensure reclamation progress under continuous foreground publication. The
[density design](../../disk-compaction-followup.md) and
[reclamation continuation proposal](../../disk-reclamation-followup.md) remain
unimplemented. Successful directory callback counters are not device I/O
measurements; header/root/namespace work and unknown partial failed effects
remain outside those counters. The batch byte target does not establish a
strict latency or byte-per-call limit for a permitted large value. These are
selected-source development checks, not a frozen workspace, production Core
cutover, complete process-memory bound or release qualification. C01–C07 remain
open.

## Adjacent-page density checkpoint

The internal compaction state machine now follows value evacuation with a
bottom-up directory packing pass. Each operation validates two adjacent pages
and their paths, packs their ordered records, and rebuilds the union of the paths
in one directory-only publication. It handles cross-parent neighbors, longer
separators, empty branch removal and terminal unary-root collapse. Fixed buffers
and three ancestor carry slots bound workspace; the maximum append count for
height `h` is `2 + 4(h - 1) + 1`. No whole-directory map is built.

The continuation is an admitted logical key. Deleting that key or shrinking the
root cannot strand a physical-path cursor. A foreground publication dirties the
current pass; only density restarts afterward, preserving completed evacuation
and its frozen cutoffs. A clean pass is required before reclamation. Continuous
writes can prevent completion, so this is not a foreground-compatible GC proof.

The 1,200-row workload still evacuates seven leaves with seven commits, 14 page
appends and 4,800 copied value bytes. Density then uses six commits and 15 page
appends to reduce the reachable directory from eight pages to five. These are
structural callback counts, not device or latency measurements. The height-five
uneven/max-key fixture matches streaming `DirectoryBuilder` page counts at every
reachable level. Other checks cover preserved old roots and logical versions,
every mutation reservation, before/after append and sync failures, publication
faults, exact cursor deletion, root collapse, and retry without repeated value
evacuation. A 12 MiB value dataset with maximum-length keys compacts under a
3 MiB native admission allowance; caller inputs and the in-memory disk stand-in
are outside that ledger, so this is not an RSS measurement.

Commands use the persistent `CARGO_TARGET_DIR=target/disk-backed-cache` lane.
The [selected-source pin](density-selected.sha256) covers 35 files.

| Command | Result / retained output |
| --- | --- |
| Focused packing and composed density tests | 22 passed in 187.95 s; [log](density-focused.log) |
| `cargo test -p kasumi-kv --lib --locked --offline -- --show-output` | 365 passed in 222.74 s; [log and workload counters](density-library.log) |
| `cargo test -p kasumi-kv --test crash_recovery --test owner_fencing --test transaction_rollback --test commit_allocation --locked --offline` | 30 passed: 9 crash/recovery, 9 owner fencing, 8 rollback, 4 allocation; [log](density-integrations.log) |
| `cargo test -p kasumi-store --lib node_file::segment_group --locked --offline` | 21 passed in 52.88 s; one intentionally ignored subprocess helper; [log](density-store-group.log) |
| `cargo clippy -p kasumi-kv --all-targets --locked --offline -- -D warnings` | Passed after three test-style corrections; [log](density-clippy.log) |
| `cargo fmt -p kasumi-kv -- --check` | Passed; [empty success log](density-format.log) |
| Selected-source hashes, whitespace/newlines and scoped `git diff --check` | Passed; [verification record](density-verification.log) |

The [initial focused run](density-focused-initial.log) passed 14 cases before
the additional edge and fault fixtures were added. The
[first strict Clippy attempt](density-clippy-initial.log) rejected three style
issues in the new test fixtures: one manual range check and two byte arrays.
Those were corrected before the selected-source pin and full library run.

At this checkpoint, review also found a separate C03 gap: obsolete cached COW pages inside partially
live arenas can prevent current pages from being retained even when the current
and pinned page union fits. The older shared-value case had spare page headroom;
it does not prove residency under this churn. Bounded page/value cache
reconciliation remains required. Density packing likewise does not bound
partially live arena garbage or temporary disk growth. The live Core and
application cutovers, complete process-memory bounds and final release checks
remain open; none of C01–C07 is closed by this checkpoint.

## Resident-cache reconciliation checkpoint

Explicit warm-up and compaction now reconcile the resident cache before refill.
A bounded slot cursor tolerates structural changes and conditionally removes
only the exact inspected identity/payload. Page membership uses the cached
minimum key and one validated path per selected/pinned root. Value identities
carry trusted key lengths, allowing a 5,180-byte envelope read and checksum
verification against the cached payload. Neither proof builds an all-key map.
The unique root union is rechecked before each serialized step, so dropped pins
and reclaimed files cannot leave a stale continuation. Ordinary current-reader
churn does not prevent completion. Unproved entries survive failures; retryable
proof errors reset the pass, while corruption and I/O failures fence the owner.

After pruning and optional metadata shrink, policy-neutral refill retains
current and pinned data without evicting the existing hot set. Physical copies
of one immutable logical key/version share a payload even after a cold cache
start. All identities, metadata and retained output guards remain charged.
Cache reconciliation does not authorize file deletion.

The reproduced [original failure](residency-obsolete-initial.log) performed six
extra reads even though the current and pinned trees fit exactly in a
104,536-byte cache. Three obsolete intermediate pages occupied the space. That
regression now passes with zero extra storage reads and no pressure eviction.
A separate cold-refill regression retains both relocation addresses for one
512 KiB version under a 700 KiB cache budget, verifies pointer-identical outputs,
and reads both snapshots without storage I/O. Other cases cover overwrite/delete
history, pin drop, budget growth, output-guard lifetimes, 256 duplicate pin slots,
small-step completion amid reader churn, admission failures, malformed cached
pages/value envelopes, and proof I/O failures.

The [selected-source pin](residency-selected.sha256) covers 43 files. Commands
use the persistent `CARGO_TARGET_DIR=target/disk-backed-cache` build lane.

| Command | Result / retained output |
| --- | --- |
| Extended cache, page/value proof and composed residency tests | 83 passed in 22.09 s before the final adjacent-header regression; [development log](residency-extended.log) |
| `cargo test -p kasumi-kv --lib --locked --offline -- --show-output` | 406 passed in 234.64 s; [log](residency-library.log) |
| `cargo test -p kasumi-kv --test crash_recovery --test owner_fencing --test transaction_rollback --test commit_allocation --locked --offline` | 30 passed: 9 crash/recovery, 9 owner fencing, 8 rollback, 4 allocation; [log](residency-integrations.log) |
| `cargo test -p kasumi-store --lib node_file::segment_group --locked --offline` | 21 passed in 45.58 s; one intentionally ignored subprocess helper; [log](residency-store-group.log) |
| `cargo clippy -p kasumi-kv --all-targets --locked --offline -- -D warnings` | Passed; [log](residency-clippy.log) |
| `cargo fmt -p kasumi-kv -- --check` | Passed; [empty success log](residency-format-check.log) |
| Selected-source hashes, whitespace/newlines and scoped `git diff --check` | Passed; [verification record](residency-verification.log) |

The [first focused compilation](residency-focused-initial.log) failed because
two existing maintenance-adapter fixtures lacked the new optional retention
signal; it also reported an unused import. The subsequent
[22 focused checks](residency-focused.log) passed before the broader fixtures.
The [first strict Clippy run](residency-clippy-initial.log) rejected an unread
restart field and three nested-if style issues; these were fixed before the
43-file pin. Review also found and fixed the skipped-candidate retry bug, cold
alias duplication and a valid predecessor payload that resembles a malformed
second header. A deterministic adjacent-record fixture now verifies that exactly
one fully valid envelope is accepted without treating arbitrary predecessor
bytes as corruption. The full run includes all these repairs. During development,
a disk-full edit was retried after removing only 15 superseded incremental
compiler sessions in this lane, retaining the newest session for every crate.

The structural workload still uses seven evacuation commits/14 page appends
and six density commits/15 appends, reducing reachable pages from eight to five.
These counts are not device or latency benchmarks. Reconciliation has bounded
memory but not a strict byte/time bound: a unit can checksum a 40 MiB value,
probe the configured pin count times maximum tree height, or rehash resident
metadata. Immediate full residency during arbitrary foreground publication
still needs the proposed publication candidate mechanism. The live Core,
encrypted application records, query indexes, configuration and final capacity
and release qualification remain open. C01–C07 remain active.

## Remaining scope

The public Core now uses `DiskState`, with incremental COW mutation, a shared
page/value cache, physical arena backing, exact root/commit/replay binding,
admitted snapshot pinning, whole-file reclamation and streamed maintenance.
Installed persistent and encrypted scratch adapters have been switched to the
group API; their integration validation is still in progress below. Native
constructors require an explicit cache allocation from their embedding owner.
Foreground publication must still preserve full residency whenever the selected
and pinned data fit. Addressable encrypted application documents, persistent
query and text indexes, collection reservations, memory and namespace capacity
qualification, streaming startup/restore, full feature integration and final
performance and release gates remain unfinished. See the
[implementation design](../../disk-backed-storage-design.md).

## Public Core and installed-backend cutover (in progress)

The current source replaces the public Core's resident key directory and old
single-file backend with DiskState and SegmentGroupBackend. Historical source
pins above do **not** validate this cutover. No production milestone is closed.

Development evidence so far:

- `core-cutover-library.log`: 356 passed, 3 fixture failures. The new log sync
  order has a separate Directory record before Commit; two 1 MiB per-reservation
  ceilings excluded the fixed ~2.38 MiB rollback workspace. Corrected the sync
  matrix and raised those ceilings to 4 MiB, still below their 8 MiB neighboring
  values, preserving the no-value-materialization assertion.
- `core-cutover-lifecycle.log`: 9 passed, 1 test expected the wrong backend call
  count after a positively NotEntered attempt; corrected expected invocations
  to two without replaying any entered close.
- `core-cutover-integration-compile.log`: failed because new fixture imports
  preceded module docs. `core-cutover-integration-compile-retry.log`: all five
  native test executables compiled after moving imports.
- `core-cutover-native.log`: 369 library tests passed in 87.33 s. The allocation
  executable was interrupted with SIGINT after runtime review found a close
  race and revised Core. It produced no allocation result. Its exact owned
  temporary group was removed afterward. This is not a complete native gate.
- `core-cutover-integrations.log`: 8 crash/recovery tests passed, 1 output-slot
  fixture failed because its capacity omitted transient directory traversal.
  An initial high-water-cap revision also failed (`core-cutover-output-retry.log`):
  optional cache copies can fall back to the output buffer under pressure. The
  corrected fixture finds the minimum required slot allowance, verifies retained
  outputs add exact live charges, requires a second read to deny at that cap, and
  verifies dropping the output permits retry. Its focused rerun passes in
  `core-cutover-output-retry-2.log`.
- `core-cutover-owner-rollback.log`: failure observations retained. CheckedGroup
  returns an I/O error carrying OwnerFailed when the admission owner fails after
  sync; the corrected test requires that exact cause. A settled retained writer
  keeps its snapshot charge until explicit disposal; the corrected test verifies
  both that charge and its release. Neither correction loosens failure fencing.
- `core-cutover-store-compile.log`: the first installed library compile found an
  internal aggregate-close callback visibility error; that narrow visibility was
  corrected without changing close semantics.

Later source also fixes snapshot admission racing close, validates exact output
buffer capacity, avoids quadratic prior-create scans for consecutive table
writes, and makes committed_position report the published replay boundary.
These edits require their own final checks; no historical passing count is
claimed as validation of them. Legacy contiguous-header and resident-index
fixtures are replaced by segmented crash matrices and public lifecycle tests.

Focused review follow-ups now pass: 13 Core lifecycle/accounting cases in
`core-cutover-lifecycle-retry.log`, the exact post-sync owner-failure case in
`core-cutover-owner-retry.log`, and retained-writer disposal accounting in
`core-cutover-rollback-retry.log`. Strict native all-target Clippy passes in
`core-cutover-native-clippy.log`. `core-cutover-native-selected.sha256` pins
49 native source/config files before the next full run.

`core-cutover-native-final.log` records 372 library tests, 9 crash/recovery
tests, 9 fencing tests and 8 rollback tests passing. Its allocation executable
was intentionally interrupted after reviewing that fixture's accounting, so
the command's overall exit status is failure and it is not a complete native
gate. The post-run selected-source comparison found only
`tests/commit_allocation.rs` changed; all 48 other selected files matched. The
fixture now balances backing-directory allocations and destruction, keeps
native census callbacks measured, and distinguishes small snapshot retirement
from the large staging lease that ends commit measurement. The four allocation
cases are being rerun against `core-cutover-allocation-retry-selected.sha256`.

Installed library tests compiled after correcting numeric fixture types
(`core-cutover-store-test-compile-retry.log`). The first `node_file::` run
(`core-cutover-store-node-file.log`) exposed a process-restart failure and a
self-deadlock: a census callback reentered group admission while the visitor
held the same group's state write lock. The hung test executable was stopped
with SIGINT after capturing its stack. Both persistent and scratch census
visitors now invoke callbacks outside their state locks and reject namespace
changes using bounded cursors and checked epochs.

The first installed retry failed compilation with ENOSPC
(`core-cutover-store-node-file-retry.log`). The subsequent
`core-cutover-store-node-file-retry-2.log` records 46 passes, two failures and
two intentionally ignored subprocess helpers. All new census reentry/ABA
regressions and the process-exit recovery case pass. The failures counted a
temporary ancestor-walk descriptor closed by owner verification; the corrected
fixtures preserve exact resource/charge and eventual owned-close assertions.
Their rerun remains pending.

`core-cutover-store-scratch.log` records 41 passes and three failures. Two
fixtures encountered a typed RegistryBusy while registering their shared
test device; the test-only helper now retries that condition without changing
production registration or quotas. The third fails singleton catalog
initialization before allocating the scratch snapshot and remains under
investigation. These partial runs do not qualify installed storage.

## Foreground publication residency (under validation)

Foreground commits now mark cached identities on actual evolving mutation
paths, prove their reachability against current and pinned roots after durable
publication, and remove only obsolete identities before non-evicting refill.
An intrusive candidate chain requires no operations-times-height allocation.
Proof buffers and root capture are admitted before private effects; abort
cleanup does not invoke admission callbacks or alter the prior hot set.

`publication-focused-initial.log` records 32 focused passes, including
exact-limit replacements/deletes, pinned versions, retained outputs, redirected
paths after separator changes and root collapse. The subsequent
`publication-native-selected.sha256` pins 54 files for the first full release
run in `publication-native-release.log`. Its library phase records 390 passes
and four failures. Two reveal a hidden per-read arena-header reservation after
durable publication. The arena now retains one charged 4 KiB header buffer;
concurrent reuse and poisoned-lock cases were added. Two historical warm-up
fixtures now explicitly pin obsolete versions until the cleanup they test.
These three changed files require a new source pin and rerun. The first full
run completed with all four allocation cases passing in 1,532.57 seconds, nine
crash/recovery cases passing in 3.62 seconds, nine owner-fencing cases passing in
1.35 seconds and eight rollback cases passing in 1.88 seconds. Its overall exit
status remains 101 because of the four library failures. These results validate
the pinned executable, not the subsequent fixes or automatic warm-up source.

This checkpoint does not establish automatic cold-open warm-up, refill after
historical-pin release or shared memory pressure, application document/index
residency, or C03 completion. The automatic driver is separately designed in
the implementation document and remains unimplemented at this checkpoint.

## Automatic residency and installed worker checkpoint

The next source adds bounded native warm-up scheduling and one admitted,
tracked worker per installed NodeStore. Preparation leaves the worker dormant;
the serving runtime's successful handoff activates it. Shutdown retains and
drains the exact supervisor and blocking child, including canceled shutdown and
failed-runtime cases. A completed cache-limited pass parks without repeated
scans. Provider refusal preserves the refused item for bounded retry with
backoff, including capacity released inside the denying provider call.

`automatic-native-library.log` records 409 passes and one failure: an explicit
warm-up fixture expected optional metadata trim to hide its admission denial.
Required warm-up trim now returns retryable CapacityDenied and preserves the
continuation. The corrected fixture requires that behavior, unchanged backing,
healthy ownership and completion after pressure is released.
`automatic-native-library-retry.log` records **410 passes in 8.59 seconds**;
`automatic-native-clippy.log` and `automatic-native-format.log` pass strict
all-target native Clippy and package formatting. All 56 files in
`automatic-native-final-selected.sha256` matched after those checks. The
allocation/crash/fencing/rollback results in the prior section belong to the
older executable; those suites have not yet been rerun on this source.

Installed evidence is narrower than a complete store gate:

- `automatic-store-catalog-diagnostic.log`: the previously failing shared-budget
  catalog case passes alone. Its earlier failure remains unexplained; no
  production catalog fix or quota increase is claimed.
- `automatic-store-scratch.log`: 44 passes. `automatic-store-node-file.log`:
  48 passes and two intentionally ignored subprocess helpers. These directly
  invoked the executable from the first automatic store build, pinned by
  `automatic-store-selected.sha256`; subsequent native warm-up changes are
  not validated by that executable.
- `automatic-store-worker.log`: three passes and six timeouts. The cold-reopen
  fixture inherited a zero-byte cache from test configuration, so the worker
  correctly remained Disabled. The fixture now explicitly configures 8 MiB.
- `automatic-store-worker-retry.log`: all nine worker lifecycle cases pass in
  1.79 seconds under `automatic-store-retry-selected.sha256`. Two native
  cfg(test)-only files changed during that dependency build; they were not
  compiled into the store executable. The installed worker runtime did not
  change after this passing run.

The installed capacity audit found a structural C01 gap: each unique cached
payload currently consumes a global governor slot and additional wrapper
charges. The default 4,096 shared slots can stop a large small-record cache
well before its byte limit. The proposed aggregate chunk admission pool is
recorded as **unimplemented** in the design document. Passing native cache and
worker tests does not qualify large installed full residency. Server activation
hooks still require compilation and lifecycle validation, and C01–C07 remain open.

`automatic-server-check.log` preserves the first all-target server compile
failure: two target-journal create/open calls omitted the newly required
NodeStorageConfig argument. They now obtain it from their exact retained disk
owner. The target shutdown fixture also lacked the new parent-ready field;
that field and a generation handoff/drain regression have been added. This
failed build provides no server test result.

## Aggregate cache credit (implementation in progress)

The C01 implementation uses **one growable reservation per cache**, using the
governor's in-place resize capability instead of the earlier multi-chunk proposal.
Opaque byte handles return credit only after their final allocation retires.
Optional cache admission leaves shared required-work headroom, adds existing
audit protection, and bypasses audit thread-local escrow. Native cache accounting
includes the complete provider charge and admitted unused credit. Rehash retains
both backings under aggregate plus temporary optional-cache admission.

`aggregate-native-compile-selected.sha256` pins 58 files for the first production
native library compile. `aggregate-native-check.log` records one borrow-checker
error in rehash error accounting and an unused production import. That failed
check does not validate the new pool. The real-governor workload and concurrent
last-reader release tests are implemented separately but have not run yet.
All C01–C07 criteria remain open.

After the rehash borrow correction, `aggregate-server-check.log` records a
successful `cargo check -p kasumi-server --all-targets --locked --offline` in
2 minutes 39 seconds. This also compiles the new native pool and installed
provider path. `aggregate-server-selected.sha256` pins 664 source/config files;
the sole post-run mismatch is the engine's new cfg(test)-only workload file,
which was not compiled as a dependency of this server check. Existing store and
engine dead-code/unused-import warnings remain in the log. This is compilation
evidence, not a passing strict Clippy gate or a server lifecycle test result.

The first aggregate library test build, pinned by
`aggregate-native-selected.sha256`, failed on three tests still calling
`Arc::ptr_eq` after the byte handle became opaque. The corrected tests use
`CachedBytes::ptr_eq`. The subsequent
`aggregate-native-library-retry.log`, under
`aggregate-native-retry-selected.sha256`, records **400 passes and 19 failures
in 18.15 seconds**. All seven new pool cases and both canonical lease cases
passed, including 16,385 cached values sharing one reservation. This is not a
passing library gate.

The failing fixtures assumed per-object reservations, immediate exact refunds,
or a budget excluding provider overhead. Exact-fit cases now remove unused
aggregate credit from their fixture limit and include the complete provider
charge; retained-reader cases distinguish released allocation credit from
quantized provider credit. Fault injection now targets actual pool growth,
required workspace and overlapping metadata replacement, preserving retry,
owner-health and zero-read assertions. Separately, source review found that an
early metadata-shrink failure could leave the pool's internal limit changed
while the public configuration kept its old limit. All failed resize paths now
restore the previous internal limit, with a regression for both metadata trim
sites. `aggregate-native-repaired-selected.sha256` pins the ensuing native
rerun; its result is recorded separately below when complete.

`aggregate-native-library-repaired.log` records **420 passes in 16.72 seconds**
on the repaired pin, whose 59 files matched after the run. This includes the
new resize-error restoration regression and every previously failing fixture.
A subsequent read-only review identified a narrower owner-expiry edge: a
rounded capacity-refusal callback may expire the physical owner before an
exact retry enters the retained governor token. The final owner check already
prevented retained allocation/publication, but the retry and refusal
classification still require fresh physical-owner checks. That correction and
its regression will have a separate source pin and validation result.

`aggregate-owner-native-selected.sha256` pins 59 native files after the owner
correction. Every provider reserve/grow attempt now checks the original physical
owner before and after the call, including refusals, already-exact requests and
second fallbacks. Temporary metadata overlap has the same rule. Three new
regressions cover nine refusal/expiry scenarios and require unchanged payload
custody, correct failure classification and cleanup without owner callbacks.

`aggregate-engine-selected.sha256` pins 664 source/config files for the installed
admission selector. Besides the two native-cache workload/lifetime tests and
five new provider cases, three configuration cases cover invalid bounds,
resolved defaults and a full-byte work reserve. The audit-scope fixture uses an
explicit 512 MiB total: its two independent 128 MiB audit allowances plus
bookkeeping cannot fit the smaller fixed-capacity default. This is a fixture
correction, not a change to runtime capacity or weaker admission assertions.

`aggregate-engine-admission.log` is an **interrupted debug run**, not a passing
selector: twelve cases completed successfully, and the 16,513-row workload was
interrupted during its initial seed commit with SIGINT (Cargo exit 101). A short
local sample showed active directory mutation and checksum work. The seed's
row-wise immutable-page updates require substantial repeated page hashing;
this unoptimized setup was not a performance measurement or a diagnosed
correctness failure. The identical pinned source and all thirteen cases are
rerun in `aggregate-engine-admission-optimized-kv.log` with
`cargo test -p kasumi-engine --lib admission::disk_memory:: --config
'profile.test.package.kasumi-kv.opt-level=3' --locked --offline -- --nocapture`,
using the same persistent target. This changes native dependency optimization,
not the workload size, assertions, Cargo files or runtime capacity.

The KV-only optimized attempt was interrupted during test-binary compilation
(Cargo exit 130), before any test result. Source inspection confirmed the SHA-256
software compression functions live in the separately compiled `sha2` package;
optimizing only `kasumi-kv` does not optimize that hot path. The next identical
selector, `aggregate-engine-admission-optimized-native.log`, adds
`--config 'profile.test.package.sha2.opt-level=3'` to the command above. Both
interrupted logs are retained, and neither is claimed as a passing check.

The optimized-native selector **passes all 13 cases in 91.57 seconds**. All 664
files in `aggregate-engine-selected.sha256` still matched after the run. The
16,513-row real-filesystem workload reached Resident with **16,604 entries**
(rows plus 91 directory pages), **zero evictions**, and **20,779,032 charged
cache bytes** under its 64 MiB cache ceiling. That total comprises 9,183,552
cached payload bytes, 11,537,272 metadata bytes, 54,088 unused admitted bytes,
and 4,120 provider bytes; no payloads were externally pinned. Live governor
reservations rose from **7 to 9** under the 128-slot cap (one aggregate cache
reservation and retained warm-up custody). Cold warming fetched exactly 16,513
row payloads and made 182 directory reads. Two complete point-read passes made
**zero further segment or directory reads**; repeated parked polls added no
work/I/O, and final close/drop returned admitted bytes and slots to baseline.

This validates the real MemoryCore provider and a bounded fixture filesystem
adapter, not the production encrypted NodeStore path or process RSS. Fixture
inputs, paths and its fixed descriptor table are outside the native ledger.
The elapsed time includes data creation, warming, reads and the parallel small
tests; it is not a production latency/throughput measurement. Current-source
store/server lifecycle checks, allocation/crash integration reruns and the
application document/index cutover remain outstanding.

`aggregate-owner-native-library.log` records **423 passes in 13.05 seconds**,
including all three new refusal/expiry regressions. Strict all-target native
Clippy and package formatting pass in `aggregate-owner-native-clippy.log` and
`aggregate-owner-native-format.log`. The 59-file native pin and 664-file installed
pin both still match after these checks. The aggregate pool therefore has a
passing native library/lint checkpoint and a passing real-governor cardinality
checkpoint. Allocation, crash/recovery, fencing and rollback integration tests
are being rerun on this exact source; older integration results remain scoped
to their earlier pins. Store/server lifecycle qualification and C01–C07 closure
remain outstanding.

The current-source native integration rerun is complete in
`aggregate-owner-native-integrations.log`: **30 passes** (four commit-allocation,
nine crash/recovery, nine owner-fencing and eight rollback cases). The allocation
binary took 1,360.54 seconds and retained its 65,536-put workload; the other
binaries took 2.07, 1.06 and 1.88 seconds respectively. All 59 files in
`aggregate-owner-native-selected.sha256` still match. These allocation fixtures
disable caching, so they qualify staging/commit work rather than cache retention.

`aggregate-allocation-native-selected.sha256` adds the separate cache allocator
integration file to that unchanged native source (60 files). The test tracks
16,513 fitting values through aggregate growth, metadata overlap, clear and
cross-thread final-reader retirement, with no fixture heap allowance. Its result
is **one pass in 0.02 seconds** in `aggregate-cache-allocation.log`; release
compilation took 11.96 seconds. Strict all-target native Clippy and package
formatting pass in `aggregate-cache-allocation-clippy.log` and
`aggregate-cache-allocation-format.log`. The allocator measures requested Layout
bytes, not allocator-internal overhead or RSS. Provider callbacks sample every
refund; no measured allocation exceeds its admitted charge, and zero admission
coincides with zero tracked heap after the last guard retires on another thread.
This also exercises metadata overlap using at most two provider slots, one
steady aggregate slot, and cleanup after physical-owner expiry without new
owner callbacks. `aggregate-prerequisite-selected.sha256` pins
665 source/config files for the next application/store/server checks. Relative
to the earlier installed-governor pin, production changes are confined to the
mutation acceptance ordering and three store test-only declaration gates; the
other additions are focused test coverage. The callback publication protocol
and lending query source in the design document remain unimplemented.

`aggregate-mutation-acceptance.log` retains the first application regression
run on that pin: **one pass, six failures and one intentionally ignored
100,000-row capacity cohort**. All six failures occur in scratch-table setup
with storage-capacity denial, before the new text rejection assertions; three
are pre-existing tests using the same fixture. The build completed in 1 minute
43 seconds, and the failed selector ran for 0.99 seconds. It does not validate
the acceptance-ordering fix. The shared fixture admission is under diagnosis;
existing unrelated `security_audit_jobs.rs` warnings are retained in the log.

Installed store lifecycle checks now pass on the prerequisite pin.
`aggregate-store-worker.log` records **nine passes in 1.21 seconds** after an
82-second build using the same KV/SHA2 test-profile optimization settings. This
covers dormant preparation, activation, cold refill, both shared-pressure retry
paths, parked-budget growth, retained native failure and cancellation during
shutdown. The same executable is reused in `aggregate-store-spool.log`
(**19 passes in 7.02 seconds**) and `aggregate-store-node-file.log`
(**48 passes, two ignored subprocess helpers, in 32.19 seconds**). The 665-file
pin still matched after all three selectors. Server runtime handoff and the
application regression fixture correction remain separate pending checks.

The application fixture diagnosis found a reservation-slot limit: it retains
one initialized encrypted terminal group, then needs a 33rd live reservation
while initializing its separate receipt group. The shared fixture now allows
64 slots, preserving the 64 MiB byte cap and all snapshot/receipt/audit quota
assertions. Only `mutation_apply_tests.rs` changes relative to the prerequisite
pin; `aggregate-fixture-retry-selected.sha256` pins the corrected 665 files.
The ignored 100,000-row cohort remains unqualified, including its additional
physical file owners as it grows.

`aggregate-server-cache-workers.log` is an **interrupted run**, not a passing
server selector. Compilation completed in 7 minutes 44 seconds; the target
generation handoff case passed, while the node-runtime handoff case remained
parked in an async wait. A one-second local sample showed an idle current-thread
runtime and RSS samplers, with no active native storage work. Root interrupted
that test process with SIGINT (Cargo exit 101) to add bounded stage diagnostics.
The original prerequisite source remains the compiled source for this run: the
sole later pin mismatch is the engine's cfg(test)-only fixture file, which is
not compiled into this server dependency. An unregistered publication-helper
draft is also outside this executable. Existing engine/vendor warnings and the
linker's compact-unwind size warning are retained. This run supplies no node
handoff/shutdown success result.

`aggregate-mutation-acceptance-retry.log` now records **seven passes and one
ignored capacity cohort in 3.12 seconds**, after a 6.53-second rebuild on the
fixture-retry pin. All three new checks pass: a quota-rejected text replacement
leaves the writer usable and both original receipts replayable; invalid text,
typed and unique-index input remains a deterministic rejection; a deliberately
stale text writer produces an outer failure without selecting a receipt. This
qualifies the focused acceptance-ordering prerequisite, not the proposed atomic
application/custody callback protocol.

`aggregate-server-stage-diagnostic-selected.sha256` pins 666 files for the node
worker rerun with 30-second initialization/open/shutdown timeouts and stage
markers. Relative to the fixture-retry pin, only that cfg(test) node lifecycle
fixture changes; the added publication-helper draft is unregistered and is not
compiled. Diagnostic output and outcome are retained separately.

`aggregate-server-node-worker-diagnostic.log` records **one failure in 30.01
seconds**, after a 34.52-second rebuild. The bounded diagnostic identifies
`initialize_standalone` as the pending stage; the node runtime and its cache
workers have not yet been created. This is a prerequisite initialization wait,
not evidence of a cache-worker drain failure. More precise initialization
diagnostics are pending; no node lifecycle pass is claimed.

`aggregate-server-signer.log` retains an **interrupted 13-case selector** using
the diagnostic server executable. Four cases passed, two shutdown-ownership
fixtures reached their 15-second timeouts, and seven cases remained pending.
Root interrupted only that verified test process with SIGINT (exit 130) after
it remained idle for over two minutes. The unfinished selector is not a pass.
The new cache-worker case was not selected. The initializer/drain wait is under
diagnosis before either server selector is qualified.

`aggregate-server-inner-diagnostic-selected.sha256` pins 666 files for the next
node-only run. Only cfg(test) stage output in `standalone.rs` and retained-drain
error output in `startup_owner.rs` differ from the prior diagnostic pin; no
runtime behavior, quota, workload or ownership ordering changes.

`aggregate-server-inner-diagnostic.log` records another **one failure in 30.01
seconds**, after a 1-minute-47-second rebuild. Standalone initialization creates
the Control catalogs, then local database opening fails. Its local resource
drain finishes, while the outer drain repeatedly retains the node with native
close settlement `DrainedWithFailure`. The original opening error is still
hidden behind cleanup; the next diagnostic will expose that error. This is
distinct from proving a native close retry is safe; no retry rule is changed.

Using that same executable, the previously timed-out signer case
`verifier_shutdown_joins_renewal_after_setup_owner_is_dropped` passes alone in
0.72 seconds in `aggregate-server-signer-drain-diagnostic.log`. This narrows the
signer failures toward inter-test coordination but does not qualify the earlier
parallel selector or identify its cause.

`aggregate-server-signer-serial-diagnostic.log` then runs all thirteen signer
cases on that executable with `--test-threads=1`: **13 pass in 13.91 seconds**.
This preserves all workloads, cancellation and ownership assertions. The
default-parallel hang remains open and must be diagnosed separately; serial
success is not substituted for the required parallel repository gate.

`aggregate-server-target-drain.log` on the inner-diagnostic executable records
**six passes and two failures in 1.86 seconds**. Both failures occur while
initializing the fixture security audit, with an encrypted-batch `InvalidData`
error, before starting its target/cache worker. The previously passing cache
worker case passes alone again in **1.66 seconds** in
`aggregate-server-target-cache-isolated.log`. This intermittent fixture-storage
failure remains unqualified. `aggregate-server-startup-owner.log` passes all
eight startup-owner cases in **1.09 seconds**, including exact handle/error
retention and failed handoff.

`aggregate-server-original-diagnostic-selected.sha256` pins 667 files. It adds
original opening-error output to standalone initialization and borrowed native
close diagnostics to `node_database.rs` (test/test-utils only). It also records
the new unregistered `apply_failure.rs` draft, which is not part of the server
executable, like `apply_publication.rs`. Neither draft is compiled or qualified.

`aggregate-server-original-diagnostic.log` records **one failure in 30.01
seconds**, after a 40.41-second rebuild. The original Control opening error is
a failed durable domain transaction during first Raft membership initialization.
Closing the fenced node reports native `Core(OwnerFailed)` and backend `Other`;
the exact failing physical invariant is not yet known.

`aggregate-server-signer-parallel-diagnostic.log` reproduces the parallel wait
on that executable and now exposes actual physical failures: three cases pass,
one signer-trust commit fails with `InvalidData`, two shutdown fixtures time out,
and seven cases remain pending while failed node openings stay in drain custody.
Root took a one-second local process sample and interrupted only that verified
test process (SIGINT, exit 130). This supersedes the tentative inter-test
coordination hypothesis: the retained initialization failures explain the wait,
but their underlying storage cause is still under investigation.

`aggregate-server-fence-diagnostic-selected.sha256` pins the next 667-file
diagnostic run. Only `node_disk.rs` and `storage_domains.rs` change from the prior
pin: test-only first-fence caller output and borrowed original commit-error
output. Ownership rules and workload assertions remain unchanged.

The fence diagnostic again fails the single node fixture in **30.01 seconds**
after a **37.39-second** rebuild. It exposes `CommitError(Io(InvalidData))` with
no `fail_locked` transition output, narrowing the investigation to physical
accounting branches that set the failed phase directly. The next 667-file pin,
`aggregate-server-extent-diagnostic-selected.sha256`, changes only test-only
`FileOwner::observe` diagnostics to record the original extent/EOF and promise
counters before those branches modify the ledger. No bound has been relaxed.

`aggregate-server-extent-diagnostic.log` identifies the physical mismatch after
a **40.05-second** rebuild. A native `.kvdir` file has exact expected EOF
**434,176 bytes**, equal to both recorded and reserved lengths, but its allocated
extent is **466,944 bytes**: **32,768 bytes** above the admitted physical bytes.
The allocation unit is 4,096 bytes, the prior pending promise is 32,768 bytes,
and the EOF-change flag is false. The single node fixture again times out in
**30.01 seconds** because the correctly fenced failed opening stays retained.
This establishes an inadequate pre-I/O physical extent allowance, not a cache
worker hang or changed EOF. A bounded allowance that also covers overwrites is
being designed; no runtime fix or passing lifecycle claim is made yet.

`local-extent-probe.json` and `local-extent-batch-probe.json` record simplified
raw append/fsync probes on this volume. Four 128-page runs and six batch-size
variants did not reproduce allocation beyond rounded EOF. They do not override
the server observation or establish a safe allowance. The focused regression
therefore uses the observed scalar values in the real accounting path through
a test-only allocation observation, alongside real-file lifecycle checks.

The selected fix is a required standing regular-file allocation policy. It
charges rounded EOF plus rounded `maximum_extra_extent_bytes` for each inode;
live growth uses reserved EOF, while settlement and census use actual EOF.
Closed and empty files retain the allowance. Namespace plans quote the same
amount before creation. The fixture selects 1 MiB explicitly; strict boundary
fixtures select zero explicitly. Neither value is a production qualification.
Source and validation results for this change are recorded below as they run.

`file-allocation-selected.sha256` pins 669 source files, including the required
server/CLI policy, store accounting, eight focused regressions, and smoke scripts.
`file-allocation-smoke-python.log` records **18 passing Python tests**. The first
Rust attempt, `file-allocation-focused.log`, stops at a compile-time borrow
conflict in the exclusive reclaim path (`file.rs`); no Rust tests ran at this
pin. A narrower descriptor-borrow lifetime is being applied before retrying.

`file-allocation-retry-selected.sha256` includes the reclaim borrow correction
and accounting of observed allocation on wrong-EOF shrink failures. The focused
retry passes **8 tests in 0.27 seconds** after a **39.26-second** rebuild. The
broader `node_disk::` run then records **168 passes, 1 failure in 3.95 seconds**:
an existing failed-parent-sync fixture still expected an empty inode to consume
zero disk promises. Its assertion is updated to require the retained standing
allowance. `file-allocation-namespace-selected.sha256` pins that test-only update;
the implementation remains unchanged from the passing focused retry.

The namespace retry records **167 passes, 2 failures in 3.60 seconds**. The
updated failed-parent-sync case passes. Two previously passing census fixtures
fail under default test parallelism: a direct constructor call races the shared
registry's try-lock, and a post-close raw descriptor-number assertion can see a
newly reused descriptor. These test races remain under review; serial execution
is not substituted for parallel qualification.

The first two backup selector attempts (`file-allocation-backup.log` and
`file-allocation-backup-corrected.log`) matched no tests and provide no coverage.
The correct module selector in `file-allocation-backup-filesystem.log` passes
**26 tests in 41.21 seconds**, including the real-process restart at full disk
and inode limits followed by publication using a retained terminal-file reserve.

`file-allocation-server-node.log` passes the previously failing node cache-worker
handoff/drain fixture: **1 pass in 19.34 seconds**, after a **5m04s** rebuild.
This server executable uses `file-allocation-namespace-selected.sha256`; the
physical allowance fixes its first-Control-publication failure without changing
handoff assertions or hiding a retained failed owner. Existing engine warnings
and the linker compact-unwind warning remain recorded.

The first workspace formatting check finds only unformatted existing
`NodeStore` call sites in `standalone_operator.rs`; formatting that file is
included in the next source pin. Census test race corrections and the
empty-installation-lock fixture expectation are test-only updates after this
server build. Runs of this existing executable still refer to its original pin.

On the same server executable, `file-allocation-server-signer-parallel.log`
passes **13 tests in 4.84 seconds**, and
`file-allocation-server-target-parallel.log` passes **8 tests in 2.35 seconds**,
both at default parallelism. The preliminary `file-allocation-server-signer.log`
selector matched zero tests and provides no coverage.

`file-allocation-final-selected.sha256` pins 669 files after the census test
race fixes, empty-lock charge assertion update, and formatting. The census
retirement test now observes unique socket peers attached to the same `File`
fields: peers must block while their owners exist and reach EOF before owner
credit retires. Two fixture-unique cursor checks distinguish a retired inode
from a recycled descriptor number. Original failure/outstanding-stream checks
remain. The retained-failure reopen retries only typed registry contention.

On the final pin, `file-allocation-node-disk-final.log` passes **169 tests in
4.28 seconds** with default parallelism, including all eight new allowance
cases and corrected census retirement/cancellation fixtures.
`file-allocation-fmt-final.log` passes the full workspace formatting check.

`file-allocation-server-storage-final.log` passes **2 standalone storage tests
in 0.08 seconds** after a **1m54s** rebuild. The new CLI missing-policy test in
`file-allocation-server-policy-final.log` then aborts with a test-thread stack
overflow before its assertions: the async CLI command embeds the large
initialization future even for a rejected argument shape. It is being moved to
the repository's existing explicit-stack runtime fixture pattern. No CLI policy
pass is claimed for that aborted run; other selectors run separately.

Separate final-executable selectors pass: persistent-disk configuration **8 in
0.08 seconds**, node worker handoff **1 in 12.09 seconds**, parallel signer **13
in 4.47 seconds**, and parallel target shutdown **8 in 2.32 seconds**. Their
`file-allocation-server-*-final.log` files refer to the final pin before the CLI
test-harness-only fix. `file-allocation-cli-stack-selected.sha256` pins that
single-file harness correction for the CLI retry.

`file-allocation-server-policy-retry.log` passes both required-policy CLI tests
(**2 passes in 0.00 seconds**, rebuild **53.53 seconds**) on the explicit-stack
fixture pin. Rejection still creates no installation, and the strict bounded
reader preserves explicit zero/selected values while rejecting malformed or
unknown fields. No production CLI path changed in this correction.

The first strict three-package Clippy attempt stops on an existing nested
conditional in `scratch_group::Owner::drop`; no native close/retention rule is
changed. The equivalent let-chain form is pinned in
`file-allocation-clippy-selected.sha256` for the retry. The selected packages
are store, server and benchmark, with all features/targets and `--no-deps -- -D
warnings`; this is not the final full-workspace release gate. Dependency
warnings from the existing audit-job work and vendored transport remain visible.

The Clippy retry reaches all three packages and stops on an existing complex
boxed future type in the backup-destination test fixture. Private type aliases
preserve its exact signature and behavior; the lint-only correction is pinned
in `file-allocation-lint-final-selected.sha256`. The full workspace diff and
format checks pass in `file-allocation-diff-check.log` and
`file-allocation-fmt-complete.log` before this scoped-formatted alias correction.

`file-allocation-clippy-final.log` passes strict Clippy for **kasumi-store,
kasumi-server and kasumi-bench, all features and targets**, in **1m38s**. This
compiles the updated daemon/config CLI and benchmark caller as well as their
library/test targets. The existing engine and vendored dependency warnings are
visible; they are outside the selected-package `--no-deps` lint gate. This pass
does not substitute for the full-workspace release gate or production memory /
filesystem qualification.

`file-allocation-spool-final.log` passes **4 retained-spool tests in 0.35
seconds**, after an **8.54-second** rebuild on the lint-final pin. These preserve
original sync errors/panic payloads, encrypted file separation, and key/buffer
retirement before extent credit following the equivalent cleanup conditional
change. `file-allocation-fmt-qualified.log` passes full workspace formatting on
that pin, and all 669 selected source hashes were checked unchanged. All C01–C07
goals remain open; the next production work is the prepared application/custody
publication protocol and snapshot-aware document/query cutover described in the
design. Production filesystem and whole-process memory qualification remain open.

## C04 application publication callback (in progress)

The canonical backend API now prepares an application response and bounded
application writes before invoking the synchronous publisher. Engine reducers
retain a private Generation through the callback and select it only after
success; Authority supplies prepared writes to the adapter's joint
application/custody transaction. Immutable point-history rows still stage in
bounded row/index commits, with selected heads hiding future rows. The document
maps and query indexes remain resident; this is a prerequisite for their
subsequent durable-root conversion.

`c04-publication-diagnostic-check.log` records a library-only `cargo check` for
kasumi-raft, kasumi-authority and kasumi-engine with all features, locked and
offline, using the persistent target directory. It passed in **29.56 seconds**.
Raft lifecycle edits were still in progress during that run, so this is compile
feedback only, **not source-pinned validation**. It reports two new unused panic
inspection warnings and three pre-existing engine audit-job warnings. No test
executed in this diagnostic run.

`c04-publication-selected.sha256` pins the next **672 source files**.
`c04-publication-raft.log` records the first Raft library test build with the
`apply_publication` selector and the normal optimized KV/SHA-2 test overrides.
It failed before running tests: embedding the retained `StartedGroup` in the
startup owner's state introduced an auto-trait `Send` evaluation cycle through
OpenRaft's snapshot channel types (`E0275`, four call sites). The retained
cleanup holder needs an admitted type-erased boundary, not a higher recursion
limit. Review also identified that a delivered owner's existing global registry
entry must remain while its group ownership fence is active, since the node
admission inventory contains only weak owner references. This failed build does
not validate either correction.

`c04-publication-owner-selected.sha256` pins the corrected **672 source files**.
The cleanup holder is boxed within its admitted workspace before cleanup effects
and type-erased without another allocation when retained. The existing global
startup enrollment remains a strong root while the exact group ownership token
is active. Opaque apply failures conservatively keep `Retained` status: worker
completion alone is not positive evidence that error-owned native children have
drained. A positive native-census bridge remains future work.

On that pin, `c04-publication-raft-owner.log` passes **16 tests in 0.12 seconds**
after a **15.64-second** rebuild. Eleven callback-protocol cases retain exact
responses, original independent failures and interrupted/repeated-call state;
five actual-worker cases cover metadata application writes, covered replay,
failed joint-commit crash recovery, cursor/membership fencing and a canceled
waiter whose callback error and Send-only panic survive actual worker drain.
`c04-publication-authority.log` passes **5 tests in 1.77 seconds** after a
**1m14s** build: callback refusal, metadata, private partial-write discard,
maintenance capacity, and original effect/maintenance decoding failures.
`c04-publication-fmt.log` passes full workspace formatting. These results do not
close C04 or qualify whole-process memory or the release gate.

The broader checks on that source exposed additional failures:

- `c04-publication-engine-mutation.log`: **11 passed, 1 failed, 1 ignored**.
  Exact local retry attempted to insert a physically staged receipt twice.
  The fixture staging branches now reuse only a complete, byte-identical pair,
  matching the durable branch; mismatches and either missing half still fail.
- `c04-publication-engine-recovery.log`: the new rejection test failed during
  tenant construction because its policy lacked an administrator. The fixture
  now has a valid separate administrator while its command actor remains denied.
- `c04-publication-engine-audit.log`: the new prune test failed during setup.
  `c04-publication-audit-denial-diagnostic.log`, on
  `c04-publication-fixture-diagnostic-selected.sha256`, records **32/32 live
  reservation slots**, 54,004,507 used bytes within 67,108,864, and an 86,264-byte
  charged request. The temporary diagnostic was removed; only this fixture's
  slot allowance changes to 40, retaining its 64 MiB byte cap.
- `c04-publication-raft-all.log`: the broader all-feature/all-target run
  reached **12 failing library cases** and was terminated during the remaining
  100,000-record capacity case. It is incomplete; integration targets did not
  run. `c04-publication-raft-failures.log` directly reruns those 12 cases from
  that executable and reproduces all 12 failures. Failures include cleanup
  panic custody, missing signed initialization/first-membership facts in
  fixtures, and stale snapshot sizing assumptions. These logs do not qualify
  the corrections.

Cleanup now retains the raw cleanup future and an independent, pre-admitted
strong owner of the actual group. An async generator may unwind its own locals
before an outer catcher observes the panic; keeping only that generator was
insufficient. A new production-path regression also checks that the exact
group's drop sentinel remains untouched. The group owner and overlapping future
allocations are included in startup admission before cleanup begins.

`c04-publication-engine-fixtures-selected.sha256` pins the next engine retry.
Subsequent Raft test-only snapshot fixture repairs need their own source pin.

The engine retry build completed in **42.03 seconds**, but the source-file-name
selector in `c04-publication-engine-mutation-retry.log` matched **zero tests**.
It is compilation evidence only. The resulting executable was then run with
the actual module/test selectors in `c04-publication-engine-focused-retry.log`:
**15 passed, 5 failed, 1 ignored in 4.98 seconds**. Candidate privacy, exact
callback retry, deterministic/revision-only rejection, metadata and recovery
publication cases pass, as do both complete-pair fixture replay tests. Four
durable history fixtures and the audit fixture still fail during setup on
storage capacity; their intended replay/prune assertions have not run. The
100,000-receipt cohort remains explicitly ignored in this run.

`c04-publication-raft-fixtures-selected.sha256` pins the Raft fixture corrections
and cleanup custody fix. `c04-publication-raft-fixtures.log` compiled in **41.51
seconds**, selected **118 library cases**, and recorded **117 passes** before
the process was terminated during the remaining large permanent-custody capacity
case. The separate 100,000-seed case was explicitly filtered out. This is an
**incomplete suite**, with no integration-target result. Passing cases include
both cleanup-panic regressions, signed first-membership purge/reopen, exact
projection/coverage byte boundaries, current-format snapshot validation, joint
snapshot publication crash boundaries and the 16 publication protocol/worker
checks. No failing case was reported before termination.

A local stack sample of the long-running capacity case showed command-table
batch commit, generation warming, and admitted encrypted directory-page loading.
It establishes active work, not a deadlock or a cause for the entire runtime.
The profile leaves the encryption dependencies unoptimized. No timing or whole
capacity qualification is claimed. Separate inspection found a refill-denial
flag that does not stop commit warming; that potential pressure-path improvement
remains unimplemented and was not established as the sampled bottleneck.

The fixture receipt and terminal writers now commit each new row/index pair
in one bounded `EncryptedTableBatch`, matching the durable pair transaction.
`c04-publication-engine-admission-diagnostic-selected.sha256` pins this change
with a temporary scalar-only memory-denial diagnostic for the five remaining
setup failures. The diagnostic changes no admission decisions and must be
removed before final validation.

That diagnostic build took **1m09s**; all five selected cases failed during
setup in **2.00 seconds**. The four receipt/terminal cases reproduced the
32/32-slot denial at 54,004,507 used bytes (86,264 charged bytes requested).
Audit then hit 40/40 slots at 54,875,251 used bytes (8,408 charged bytes
requested). Both stayed below the 64 MiB byte cap. The next fixture correction
gives these three helpers 128 slots for installed owners, replacement tables,
transactions and cache overlap, retaining the byte cap. This is explicit
bounded test headroom, not a measured minimum or production capacity claim.

`c04-publication-fixtures-final-selected.sha256` pins **673 files** after the
diagnostic is removed. `c04-publication-engine-final.log` passes **21 tests,
with 1 explicit capacity-cohort ignore, in 6.28 seconds** after a **1m03s**
build. All five previously blocked setup fixtures reach and pass their intended
assertions, including encrypted reopen and audit publication refusal/exact
retry. The selected second-insert failure case also passes. The only source
differences from the Raft fixture pin are the five Engine staging/fixture files;
Raft and its Store/KV dependencies match that earlier pin. The pre-existing
Engine audit-job dead-code warnings remain; no strict Engine Clippy pass is
claimed.

`c04-publication-authority-all.log` built the 74-test all-feature Authority
library in **1m22s**, then recorded **21 passes and 52 failures** before
termination with one test still unresolved. Captured failure bodies were not
printed before termination, so their causes remain unclassified; the full
parallel suite is not qualified. The same executable's basic quorum case
passes in isolation (**1 pass in 18.18 seconds**,
`c04-publication-authority-quorum-isolated.log`). Its expected partition read
deadlines are logged. This single isolated pass does not explain or waive the
other parallel failures; representative serialized diagnostics follow.

The first final formatting check (`c04-publication-final-fmt.log`) failed on
three Raft test files formatted individually with an older style edition.
Workspace `cargo fmt --all` corrected them without a semantic change.
`c04-publication-formatted-selected.sha256` records the resulting source;
`c04-publication-formatted-fmt.log` passes the full workspace check. Earlier
test logs retain their original pins; this formatting result does not claim a
functional rerun of the changed test files.

`c04-publication-authority-paths-isolated.log` runs five exact cases serially
from the same Authority executable: **1 passed, 4 failed in 97.98 seconds**.
Exact target preparation passes. Actual target materialization fails opening
a replica with `tenant audit placement unavailable`. Three subsequent fixtures
fail at initial Authority open with a live-group ownership conflict; the
relationship to the prior failed startup is under investigation. These
failures cannot be dismissed as parallel contention, and the callback's broader
operational qualification remains open.

The ordinary rejection case passes in a fresh process (**1 pass in 5.57
seconds**, `c04-publication-authority-rejection-isolated.log`). Investigation
identified two distinct causes in the serial sequence. The target phase
fixture omitted explicit local-replica audit placement; the production replay
check correctly refused it. The shared fixture now installs that capability
for fresh and reopened target stores. Separately, the live-group registry uses
a custody-store address as its key. Retained startup/failure owners could keep
the boolean fence alive after the store allocation died, allowing a new store
at the same address to inherit a false duplicate-open conflict. The planned
correction pins the exact, already charged store identity in the preadmitted
failure slot until positive drain. Its focused regression and affected-path
reruns are still required; the fresh-process pass does not qualify that fix.

`c04-publication-identity-selected.sha256` pins **674 files** including that
correction and the explicit target audit fixture installation. The failure
slot's size-based admission covers its inline identity owner; binding retains
the exact custody-store Arc before effects, and positive shutdown clears the
fence and drops that owner without waiting for the diagnostic slot to die.
`c04-publication-identity-raft.log` passes **41 focused tests in 2.37 seconds**
after a **29.27-second** build, covering actual-store identity custody,
same-store duplicate/reclaim, unrelated-store independence, charge lifetime,
startup/cleanup panic and cancellation, and callback/crash boundaries. The
affected Authority paths are being rebuilt and rerun on this pin.

`c04-publication-identity-authority.log` finishes with **10 passes and 1 failure
in 289.30 seconds**, after a **1m02s** build. Quorum loss, target preparation,
three actual target materializations through initialization and repeated restart,
subsequent maintenance/rejection fixtures, and all five direct publisher checks
pass in the same process. The remaining signer-directive case reports a
5-second acknowledgement timeout/`UnknownOutcome` while staging a signer
generation. The fresh-process rerun reproduces that failure in **17.00 seconds**
(`c04-publication-identity-signer-isolated.log`). Its cause remains under
investigation; no timeout increase or success inference is applied.

`c04-publication-identity-fmt.log` passes workspace formatting, and all **674
source hashes** match after the targeted Raft run. The larger parallel Authority
suite, interrupted capacity cohorts, full workspace/release checks and process
memory/performance qualification remain open.

`c04-publication-callers-check.log` passes the all-feature, all-target
`cargo check` for `kasumi-server` and `kasumi-bench` on that identity pin in
**4m13s**. It includes the three existing Engine audit-job dead-code warnings.
This is caller compilation coverage, not a test or strict Clippy result.

`c04-publication-signer-diagnostic-selected.sha256` pins the same **674 files**
with temporary test-only timing at the Authority mutation lock, maintenance
reducer, roster freeze, response encoding and publication. The signer case
passes in **32.48s**, after a **5.51s** build
(`c04-publication-signer-diagnostic.log`). Each replica freezes the unchanged
roster three times for staging: each freeze takes approximately **0.67–0.72s**,
reduction **2.10–2.16s**, and successful publication completes within
**2.24–2.32s** of entering apply. Lock waits are small in this run. This proves
repeated expensive preparation, but does not establish the exact cause of the
earlier acknowledgement timeouts. Deadlines and assertions are unchanged.
The diagnostics have been removed; all 674 files exactly match the preceding
identity pin again. A prepared roster reused within the same mutation guard
is the next change; that change requires its own source pin and regressions.

`c04-publication-warm-roster-selected.sha256` pins **675 files** after removing
the diagnostics and implementing two changes. Signer staging now consumes one
prepared roster inside the same mutation guard, retaining the original
coverage-before-certificate rejection order and activation's outer-error
boundary. Native commit warming stops on a refused page before optional disk
fallback; required reachability proofs and final put visibility checks remain.
An adjacent fix preserves fatal admission-quote errors instead of masking them
as capacity pressure. These edits do not change memory limits or deadlines.

`c04-publication-warm-kv.log` passes **430 native library tests in 6.31s** after
an optimized **1m12s** build. The seven new cases cover refusal without extra
page I/O for different tree sizes, fitting-tree residency, quote/owner/digest
failure, pressured old snapshots and final batch visibility, disabled-cache
publication and durable reopen after warming failure. Existing exact-fit and
retained-version cache regressions also pass. All **675 source hashes** match
after this run. Native integration and the affected Authority checks follow;
this is not full-runtime memory or performance qualification.

`c04-publication-warm-roster-authority.log` passes **10 selected tests in
228.16s**, after a **15.79s** build, using the recorded native/SHA test-profile
optimizations and serial test execution. The previously failing signer
directive case passes, as does the broader roster coverage/freeze test spanning
Authority, Control and prepared targets. Eight direct publisher cases include
three new prepared-roster regressions: refusal leaves the authoritative head
and receipt absent; fresh publication and exact replay preserve the canonical
roster digest and valid snapshot; coverage rejection ordering and activation's
outer failure remain unchanged. Expected lease-freeze and shutdown refusals are
retained in the log. This pass does not explain every failure in the earlier
parallel suite or establish a throughput comparison.

`c04-publication-warm-roster-fmt.log` passes workspace formatting; the diff
whitespace check also passes. The optimized five-target native integration run
in `c04-publication-warm-kv-integration.log` is **still running** at this
checkpoint, after a **53.56s** build. The cross-thread cache-allocation case and
the 65,536-operation admission-denial/exact-retry case have passed. The other
serialized allocation cases and remaining integration targets are unresolved;
do not count the run as a suite pass. A local sample shows active private
directory reads in the large commit path. This fixture disables cache retention,
so optional commit warming is not the sampled path. A sampled fixture directory
contained roughly 2.38 GB of logical files; this intermediate observation is
not a peak-disk or throughput measurement.

That same native integration process subsequently completed successfully:
**31 tests pass** across cache allocation (1, **0.01s**), commit allocation
(4, **1208.83s**), crash recovery (9, **4.34s**), owner fencing (9, **1.99s**)
and transaction rollback (8, **1.94s**). The original log retains the long
allocation-test progress messages. All **61 native/workspace source hashes**
matched the original warm/roster pin while that binary ran. Engine/query source
edits started during the native-only tests and do not enter their dependency
graph. This is focused native qualification; large-batch COW amplification and
the application memory/capacity matrix remain open.

`c04-publication-warm-kv-clippy.log` passes strict native Clippy for all features
and all targets (`--no-deps -- -D warnings`) in **10.50s**, with the same native
source and persistent target directory.

## C04 lending document source (validation in progress)

`c04-lending-source-selected.sha256` pins **680 files** for the initial source
tranche. Canonical query, indexed-candidate and ordered-seek entry points now
take a collection-scoped `DocumentSource`; there is no production map overload.
The initial Engine adapter retains the exact `Generation`, checks live/archive
versions, and merges logical headers with same-version hydration deduplication.
Source identity and the captured index owner are checked across loans. Queries
hold IDs, versions, sort keys and scores between reads, then reload exact
versions for row output. Borrowed row/projection serialization checks the wire
limit before cloning bodies. Snapshot and lease-scan body reads also use loans.

The storage error type remains distinct from typed query errors. The initial
resident adapter uses `Infallible`, and Engine conversions are available only
for that case. Installing a fallible disk source must first wire the retained
worker/error owner; these tests cannot qualify that future cleanup boundary.
Ordinary shared point reads and asynchronous archive hydration remain on their
current retained-body path. The source does not replace resident document maps
or secondary/text indexes, install an admitted header cursor, or fix variable
sort/group/decimal/JSON workspace accounting. C01–C07 remain open.

The first query compile in `c04-lending-query.log` found four fixture type
inference errors from `imbl::OrdMap`'s convertible iterator keys. Explicit
`String` key types fix those; no production behavior was changed for that
repair. Initial formatting also found one export-order change, now corrected.
The next source pin, `c04-lending-checked-selected.sha256` (**680 files**), adds
an independent expected-version check before dispatching archived references.
Its query run (`c04-lending-query-checked.log`) builds in **14.14s**, then passes
**46 tests and fails 1 in 3.08s**: the prior ordered-seek volume fixture allowed
only eight cancellation checks, fewer than the newly required checks around
two source loans. The final fixture uses a page-size-derived allowance of
seventeen checks (six per borrowed body, one per visited index entry including
lookahead, and query entry/exit). This allowance is independent of collection
size; production cancellation checks and deadlines are unchanged.

`c04-lending-final-selected.sha256` pins **680 files** after these repairs;
`c04-lending-final-fmt.log` passes workspace formatting, and the diff whitespace
check passes. Runtime verification of this final pin is in progress.

`c04-lending-engine-source.log` compiles the production adapter and worker
callers successfully in **4m14s**, but all six new adapter tests fail at their
shared fixture constructor: its empty policy has no required administrator.
No record-read assertions execute in that run. The fixture now supplies the
required administrator grant; production policy validation is unchanged.
`c04-lending-qualified-selected.sha256` pins the resulting **680 files**.
`c04-lending-query-final.log` passes **all 47 query tests in 5.37s**, after a
**4.10s** build, including ten new lending-source cases and the repaired bounded
ordered-seek fixture. The selected Engine unit/integration run remains in
progress in `c04-lending-engine-selected.log`.

That Engine selection builds in **1m07s** and passes **nine library cases in
13.20s**: six new adapter tests plus three text-index preparation/publication
regressions. It then passes **four contract tests and fails one in 62.45s**.
Real Raft query pagination, concurrent coherent snapshots, snapshot admission
and authorization rejection, and revocation of retained leases pass. The
unique-index swap case fails before querying, during its first mutation's
scratch receipt-table initialization. Cargo stops before the history, ordered
seek and schema targets; those results are not implied by this run.

The contract and schema fixtures used 32 reservation slots for the same
terminal/receipt group overlap previously diagnosed above as requiring a 33rd
reservation. Their constructors now match the passing mutation fixture's
bounded 64-slot allowance, keeping the **64 MiB byte cap**, production limits,
deadlines and quota assertions unchanged. This is an evidence-backed fixture
correction, not a newly measured minimum or peak for these cases.
`c04-lending-fixture-selected.sha256` pins the resulting **680 files**;
`c04-lending-fixture-fmt.log` passes workspace formatting.

`c04-lending-query-authority-clippy.log` passes strict Clippy for Query and
Authority, all features and all targets (`--no-deps -- -D warnings`), in
**2m19s**. The unchanged Engine dependency emits three existing dead-code
warnings from `security_audit_jobs.rs`; this does not qualify strict Engine or
workspace Clippy. No production source changed during that check.

`c04-lending-engine-fixture.log` builds in **12.22s** and passes all five
remaining/repaired integration cases: the unique-index swap with a retained
old generation (**2.06s**), archive reads/deduplication/leases through restart
(**40.73s**), bounded ordered-seek pages over **10,005 documents** with current
epoch and authorization fencing (**79.00s**), and both atomic structured/text
schema-publication cases (**3.40s** together). The combined selections cover
**18 distinct Engine tests**; the earlier failed attempts remain recorded above.
All **680 hashes** match the latest fixture pin after this run. Server and
benchmark all-target caller compilation is running in
`c04-lending-callers-check.log`. This tranche does not establish a disk-backed
document/index implementation or a whole-process memory bound.

`c04-lending-callers-check.log` completes successfully in **3m04s** for server
and benchmark packages, all features and all targets, locked and offline in the
persistent target directory. Existing Engine and vendored `rmcp` dead-code
warnings remain; this is a compile check, not strict workspace Clippy. The
current source stays at the **680-file fixture pin**. Focused source semantics,
the native integration selection and caller compilation are complete for this
tranche. Durable document/index cutover, source decode/workspace admission,
bounded cursors, retained fallible-worker custody and full release/capacity
qualification remain open.

## C04 ordered index inputs (qualification in progress)

The canonical index build/update/uniqueness APIs now accept ordered row loans
and replayable old/final document pairs. Engine adapters borrow exact live and
archive roots; catalog updates explicitly select unchanged, delta, rebuild or
removal. A changed root without a journal no longer triggers a silent rebuild.
Two-phase preparation validates all collections before any shared text writer
advances. The text builder no longer collects and sorts a full ID vector.
Structured postings, unique maps, Tantivy storage and row directories remain
resident, and variable allocation admission remains open. This is another C04
source prerequisite, not completion of a disk-backed document/index store.

Initial production checks use the existing `target/disk-backed-cache` directory,
locked and offline. `c04-index-input-lib-check.log` passes
`cargo check -p kasumi-query --lib` in **1m00s**;
`c04-index-input-engine-check.log` passes
`cargo check -p kasumi-engine --lib --all-features` in **1m49s**. The latter
retains the same three existing `security_audit_jobs.rs` dead-code warnings.
These checks precede the final test fixtures and review repairs; they are not
final-source test or strict Engine Clippy qualification.

Review found a publication-boundary requirement introduced by stronger input
checks: corrupt scope, versions, captured definitions or prior unique mappings
must stop application as an outer failure. They must not become permanent
mutation or staged rejection receipts. Ordinary unique conflicts remain
deterministic rejection outcomes. The caller correction and focused failure
regressions are being completed before the final source pin and tests.

`c04-index-input-query-selected.sha256` pins **684 files** for the first full
query run. `c04-index-input-query.log` passes **all 55 tests in 3.46s**, after
a **10.56s** build, including five new ordered-input cases and three new text
loan cases. Coverage includes decode/pair lifetimes, atomic unique swaps,
archive transitions, source error ownership, ordering/scope/replay checks and
rejection of a later collection before an earlier shared text writer advances.

`c04-index-input-selected.sha256` pins **684 files** after the Engine corruption
publication repair. Only `mutation_apply_tests.rs` differs from the query pin;
query code and dependencies retain their tested hashes. Mutation and staged
paths now propagate `Corruption` before selecting any permanent outcome; ordered
application also catches nested corruption from private schema preparation.
Unique conflicts keep their existing deterministic outcomes. The new Engine
regressions check unchanged publisher/generation/receipt/terminal state and a
valid retry on the same text writer after removing the injected inconsistency.
`c04-index-input-fmt.log` passes workspace formatting, and `git diff --check`
passes. Focused Engine validation is running in
`c04-index-input-engine-unit.log`.

That Engine selection passes **all 18 tests in 18.76s**, after a **4m34s**
build. It includes six prior document-source cases, six new index adapters,
the two new corruption/publication cases, three existing text validation and
publication regressions, and recovery seal/exact-replay behavior. The unchanged
test-only `RecordFault.panic` warning joins the three existing library warnings.
The four-target integration selection is running in
`c04-index-input-engine-integration.log`.

The integration selection builds in **25.84s** and passes three contract checks
(**7.59s**) and archive/uniqueness/hydration through restart (**53.90s**). The
schema target passes three atomic publication/rejection cases and fails the
32-collection encrypted restart/full-restore case: `schema_activation.rs:1556`
reports **backup verification deadline expired** at the existing **60,000 ms**
restore timeout. The four schema cases finish in **295.69s**. Cargo stops before
the staged target, so it is not counted as run. A brief local stack sample
during this case shows active backup verification writing encrypted scratch
tables and committing native state; that observation alone does not establish
the cause of the deadline failure. The failed log is retained, and investigation
continues without increasing the timeout or production limits.

`c04-index-input-staged.log` separately runs the two staged cases, building in
**1.37s** and failing both in **6.79s**. One fails scratch-table setup with
`storage capacity denied`; the other fails snapshot restoration at the fixture
boundary. These use the same **32-slot / 64 MiB** constructor as the previously
diagnosed receipt/terminal overlap. The common staged constructor and this
case's restore constructor now use **64 slots**, matching the passing mutation,
contract and schema fixtures; the **64 MiB** cap and quota assertions are
unchanged. The retry is pending, so the restore failure is not yet attributed
solely to fixture capacity.

Read-only tracing locates the sampled restore work in
`StagedSnapshot::new`, which constructs structural lookup tables before
`validate_documents` invokes the new lending APIs. All 32 fixture collections
are empty. The short sample locates work; it does not measure its share of total
runtime. A bounded-write repair is in progress: use the existing
`EncryptedTableBatch` capacity and ownership contract for offset/group entries,
flush at record-kind boundaries before references to earlier kinds are read,
and commit the final batch before exposing the completed private index. No
deadline, input, byte or batch limit is increased.

The first strict query lint run, `c04-index-input-query-clippy.log`, rejects one
byte-slice spelling in the replay digest. Replacing `[b'\n']` with the equivalent
`*b"\n"` fixes it without changing the digest bytes.
`c04-index-input-query-clippy-final.log` then passes Query Clippy for all features
and all targets (`--no-deps -- -D warnings`) in **7.20s**. The post-lint query
test rerun is recorded separately in `c04-index-input-query-final.log`.

That post-lint query run passes **55 tests in 4.21s**, after a **5.20s** build.
No query source changes follow this result.

`c04-index-input-batched-selected.sha256` pins **685 files** after structural
snapshot batching, its three new failure/boundary tests, the staged fixture
correction and the byte-slice lint repair. `c04-index-input-batched-fmt.log`
passes workspace formatting; the diff whitespace check also passes.
`c04-index-input-callers-check.log` passes server and benchmark compilation for
all features and targets in **4m22s**, retaining the previously noted Engine and
vendored `rmcp` warnings. This is not strict Engine/workspace lint qualification.
All **685 hashes** match before the combined Engine unit/integration retry in
`c04-index-input-batched-engine.log`.

That combined attempt builds in **2m00s**, then the library selection passes
**23 tests and fails 4 in 175.66s**. All three new batch tests and the original
18 adapter/publication tests pass. Four broader snapshot-validation tests fail
at scratch-table creation with **storage capacity denied**, before their
intended validation assertions. Their six shared-pattern constructors also use
the obsolete **32-slot / 64 MiB** fixture allowance. All six now use **64 slots**
with the byte cap unchanged, so negative-only cases must also rerun rather than
counting an early capacity rejection as semantic evidence. Cargo stops before
all integration targets. The failed attempt remains recorded; the revised
fixture run is pending.

`c04-index-input-fixtures-selected.sha256` pins the **685-file** fixture repair;
formatting and whitespace checks pass. Its retry,
`c04-index-input-fixtures-engine.log`, builds in **29.70s** and passes five
snapshot-validation cases, including the positive baseline and semantic
substitution checks, in a six-case run lasting **342.71s**. Only the ownership
case fails: it observes **7 files** but expects **3**. The native tables each
own root, segment and directory files, so the former one-file-table assertion
is obsolete. That assertion now compares retained files with the image baseline
while preserving exact image-only byte/file and final-zero drain assertions.
The provenance fixture also releases an unused initial proof before independent
malformed candidates. This shortens an unnecessary overlap rather than raising
capacity. Cargo again stops before integration targets; those remain pending.


`c04-index-input-final-selected.sha256` pins **685 files** after the two
snapshot-fixture repairs. Formatting and whitespace checks pass. The source
hashes match during the run. `c04-index-input-final-engine.log` builds in
**45.42s** and passes both changed snapshot cases (**37.92s**), all three
contract cases (**12.91s**), archive/uniqueness/hydration through restart
(**81.60s**), and three schema publication/rejection cases. The encrypted
32-collection restore still fails at the unchanged **60,000 ms** verification
deadline. The schema target totals **555.16s**; that includes setup, restart,
other tests and cleanup and is not a measured verification duration. Cargo
again stops before staged integration. A brief sample late in this attempt
observes active Raft publication and native storage reads, rather than the
structural index constructor; its 11 observations do not attribute total
runtime or locate the earlier deadline failure.

`c04-index-input-final-staged.log` separately passes both staged transaction
cases in **15.09s**, after a **1.19s** build. With the unchanged passing query
source, the selected coverage is now **55 query tests** and **36 distinct Engine
checks passing**, with **one Engine restore failure remaining**. This is not a
clean integration gate or complete C04 qualification. All earlier failures are
retained.

Read-only tracing finds a redundant full pass in `ValidatedApplicationSnapshot::relocate`:
when a verified image has no history archive records, relocation still copies
its unchanged bytes and rebuilds its structural and semantic indexes. Existing
validation proves zero archive metadata bytes and no dangling archived rows in
that case. A narrowly scoped no-op path is being implemented, preserving the
original image/proof and the live check/admission callbacks. Its tests and the
unchanged restore deadline remain pending; it is not yet credited with fixing
the timeout. Additional semantic scratch batching would not affect the empty
document/history/staging loops in this fixture and is not being added here.


`c04-relocation-selected.sha256` pins **685 files** after the no-history
relocation path and its two new tests. `c04-relocation-fmt.log` passes formatting
and whitespace checks. The corresponding `c04-relocation-engine.log` builds in
**3m15s** and passes both new tests in **27.78s**: exact image/header/summary and
file/byte custody, plus original typed errors and complete proof cleanup when
the initial check, admission or final check fails. The encrypted 32-collection
restart/restore retry is still running at its original **60,000 ms** deadline.


That relocation retry **fails** the same encrypted restart/restore case at
`schema_activation.rs:1556` with **backup verification deadline expired**. The
single integration case totals **456.40s**; this includes setup, restart and
cleanup, and does not measure the verification phase alone. No timeout, input,
cache-policy or optimization-profile limit was changed. The two relocation unit
tests remain passing evidence for preservation and cleanup; they do not prove
that the redundant pass caused the timeout or that removing it fixes restore.
All **685 source hashes** still match after the run.

This checkpoint has **55 query tests and 38 distinct Engine checks passing**,
plus the outstanding encrypted restore deadline failure. Query strict lint and
the earlier server/benchmark caller check remain recorded on their exact
source selections. Engine/workspace strict lint and full release gates are not
qualified. The archive-bearing history restore regression was identified but
not rerun for the no-archive branch; its existing rewrite path is unchanged.

Before another long restore retry, obtain phase-level evidence distinguishing
session/graph verification, structural/semantic indexing, relocation, genesis
materialization and publication. The generic deadline message and brief stack
samples do not establish that attribution. The separate pre-existing target
causal-accumulator issue and query-workspace accounting gaps are recorded in the
implementation design; neither is repaired by this checkpoint. C01–C07 and the
overall goal remain **active/open**. Full document/index disk cutover and a
whole-runtime memory bound are not claimed.


The next source selection, `c04-restore-phases-selected.sha256`, pins **686
files**, including fixed-field DEBUG phase timers and four helper tests, a direct
32-empty-collection structural-index timing/ownership fixture, and the separate
causal cursor correction in both restore paths. The new Engine dev dependency
reuses locked `tracing-subscriber` 0.3.23; offline metadata resolution changed
only the Engine package dependency edge. General daemon/dependency logging is
unchanged. `KASUMI_TEST_RESTORE_TRACE=1` enables the exact diagnostic target for
the selected integration test and fixed numeric timings for the direct fixture.

The new timers keep the original deadline, and distinguish a dropped waiter
from a worker still holding its resources. `unfinished` records an early exit,
not a rollback result. No input, provider errors or credentials are emitted.
Independent source review found no change to authorization, deadline checks,
resource drop order or publication serialization. `c04-restore-phases-unit.log`
is the focused qualification run; results are pending. No cache/deadline budget
or crypto/optimization-profile changes were made.


`c04-restore-phases-unit.log` builds in **3m11s** and reports **8 passing,
2 failing** tests in **42.59s**. All four diagnostic helpers, existing worker
reservation retention after timeout, both indexed causal regressions, and the
32-collection structural fixture pass. The direct fixture measures capture
**11ms**, structural construction **15,155ms**, lookups **101ms**, and teardown
**162ms**. Those are local observations, not a complete restore attribution or
performance qualification.

Both Builder cases fail in `Builder::new` before testing their rows, with
`storage capacity denied`. Their 32-slot providers must fund two native tables
and retain cache headroom; the analogous snapshot fixtures already use 64
slots. The two new Builder fixtures and the existing earlier-seal fixture now
use **64 slots with the same 64 MiB total cap**. No production admission limit
is changed. The original failed log and source selection remain retained.


`c04-restore-phases-fixtures-selected.sha256` pins the **686 files** after
those fixture changes. `c04-restore-phases-engine.log` builds in **40.54s** and
passes **all 11 focused unit tests in 92.60s**, including both Builder
regressions and the existing earlier-seal rejection. The direct structural
fixture reports capture **13ms**, construction **32,190ms**, lookups **423ms**,
and teardown **37ms** in this run. Variability from the prior 15,155ms
construction observation is material; neither observation is an isolated
performance qualification. The same command then starts the selected encrypted
restart/restore integration with its original **60,000ms** deadline and the
opt-in fixed-field phase subscriber. Its result is pending.


The traced integration **fails** at the unchanged deadline after **432.87s**
total test runtime. Unlike prior attempts, this run locates the failure:
restore gate/access/session, manifest/pages/chunks, freeze and framing
inspection finish with **59,388ms remaining**. `snapshot.structural_index`
then remains active until the waiter expires at **60,006ms** total restore
time. The structural guard ends `unfinished` at **60,916ms**, and the actual
blocking worker at **60,935ms**, after its waiter stopped. No semantic-section,
relocation, genesis or publication phase began. This attributes this attempt's
timeout to structural construction; it does not prove other paths are fast.
All **686 source hashes** still match after completion.

A phase-triggered `/usr/bin/sample` request for two seconds at 10ms intervals
returned **89 observations** of the structural worker. All worker observations
were within `PendingIndex::flush` / native `DiskState::commit_inner`: 52 under
prior-value lookup and 37 under `DirectoryMutator::set`. The stacks include
encrypted spool block switching, flush/encrypt and load/decrypt via directory
page/header reads. The sample is local at
`/tmp/kasumi-restore-structural.sample.txt`; it is a short interval, not a
whole-run CPU or I/O attribution. Combined with the direct fixture, it supports
measuring redundant native page copies next, without removing authentication
checks or changing cipher/profile settings.

The source emits one private 16 KiB leaf/path copy per operation. Scratch
`WriteTransaction` uses nested `BTreeMap`s, so the structural fixture's
interleaved point/group insertion calls reach native commit as sorted distinct
16-row batches. A native counter fixture will measure this amplification and
old/current/reopened snapshot parity before a bounded leaf-batch optimization.


`c04-native-batch-baseline-selected.sha256` pins **687 files** for the native
measurement fixture. `c04-native-batch-baseline.log` builds in **57.01s** and
passes its one case in **0.02s**. A 16-row sorted insertion transaction whose
result is one leaf performs **32 directory page reads, 16 page appends, one
arena sync, and 64 backend reads** before validation. The held old snapshot
sees no inserted rows, current and crash-reopened roots retain all rows, and
all admitted memory drains. Source hashes match at completion.

The next implementation is deliberately limited to a root that is empty or
already a leaf. At most 16 strictly increasing distinct borrowed edits are
merged into admitted page buffers before any append. If the result does not
fit, the existing sequential editor handles the original operation order;
higher trees likewise retain that path. A successful fitting batch appends
one immutable page. No header authentication, crypto or durable publication
checks are removed. Native publication charges its fixed edit descriptors
before preparing the log and marks prior values against the unchanged run
root, valid because keys are distinct. The broader multi-leaf sorted-delta
editor remains unimplemented. This optimization is not yet qualified.


`c04-native-batch-selected.sha256` pins **689 files** with the root-leaf
editor, native commit integration and nine focused helper/transaction tests.
Independent reviews found no blocker in fixed pre-effect admission, canonical
framing, empty/no-op generation handling, zero-append fallback, cache candidate
marking, pin retention or durable publication order. `c04-native-batch-tests.log`
runs all native unit tests plus crash recovery, owner fencing and transaction
rollback integrations; results are pending.


`c04-native-batch-tests.log` builds in **31.63s** and passes **439 native
unit tests in 91.30s**, plus **26 integration tests**: crash recovery 9
(**10.39s**), owner fencing 9 (**3.14s**), and transaction rollback 8
(**1.95s**). The unchanged 16-row fitting fixture now measures **2 page reads,
one page append, one arena sync, and 4 backend reads**, versus baseline
32/16/1/64. Old/current and crash-reopened values agree; fitting current and
pinned snapshots cause no serving reads or pressure evictions in the fixture.
All **689 source hashes** match after the run. The expensive allocation
integrations and whole-runtime/release gates have not been rerun here.


The same native batch selection passes `cargo fmt --all --check`
(`c04-native-batch-fmt.log`, **17.64s**) and strict native all-feature/all-target
Clippy with `--no-deps -- -D warnings` (`c04-native-batch-clippy.log`,
**22.56s** Cargo time). `c04-native-batch-engine.log` now repeats the 11
focused Engine checks and encrypted restore with the unchanged 60,000ms
deadline, the same KV/SHA test profile overrides and phase diagnostics. Its
completed result is **11 unit passes and one integration failure**, detailed
below. No full Engine/workspace strict-lint qualification is
claimed; the recorded unrelated audit warnings remain.


The optimized Engine selection builds in **2m41s** and passes all **11
focused unit checks in 51.66s**. The 32-empty-collection structural fixture
measures capture **14ms**, construction **3,714ms**, lookups **90ms**, and
teardown **37ms**, compared with prior construction observations of 15,155ms
and 32,190ms. This demonstrates a local improvement, subject to the previously
observed timing variability. The encrypted integration **fails** separately,
so the direct measurement does not qualify full restore performance.

`c04-native-batch-engine.log` reports the selected encrypted restart/restore
test failing with `backup verification deadline expired` after **341.73s**
total test runtime. The complete runner takes **555.04s** and exits **101**;
that includes compilation and the 11 unit checks, not just restore execution.
The original **60,000ms** restore deadline is unchanged. Structural inspection
and semantic admission finish with **59,288ms remaining**, then
`snapshot.structural_index` starts. The blocking-wait guard ends `unfinished`
after **59,306ms**, and `restore.local_total` ends `unfinished` at **60,005ms**.
No snapshot semantic-validation section, relocation, genesis or publication
phase begins. After the waiter has stopped, the structural-index guard ends
`unfinished` after **64,162ms** and the blocking-worker guard after **64,180ms**
of their respective lifetimes.

Those guard events locate this attempt's deadline failure and show that the
worker outlives its waiter; they do **not** independently prove complete resource
teardown, successful rollback, or release of every reservation. Exact teardown
remains an ownership/census assertion, such as the separate direct fixture's
verified drain. The root-leaf optimization improves the measured native
amplification and direct construction but is insufficient for this installed
full-restore path. Taller-tree editing and the remaining structural work need
separate measurement; this result does not attribute all remaining cost to
either one.

All **689 hashes** in `c04-native-batch-selected.sha256` were rechecked and
match after the completed Engine run. Current native qualification is **439
unit tests plus 26 crash/ownership/rollback integration tests**, formatting and
strict native all-feature/all-target Clippy; focused Engine qualification is
**11 passing unit checks**, with the full encrypted restore failure retained.
No timeout, cache/input/admission budget, or crypto/optimization profile was
changed. Expensive native allocation integrations, whole-runtime memory bounds,
Engine/workspace strict lint and full release gates remain unqualified on this
selection. C01–C07 and the overall large-cache goal remain **active/open**.

### C04 bounded leaf-prefix editing: native and selected Engine qualification

The next editor handles a maximal sorted prefix routed to one existing leaf,
including leaves below internal pages. `try_set_leaf_batch` accepts at most
16 strictly increasing distinct borrowed edits and returns the new private
root plus the consumed count. A successful prefix contains at least two edits.
One validated descent identifies its leaf; the merged leaf and all affected
ancestor separators must fit before the first append. A changed prefix copies
the leaf and each selecting ancestor once. No-op prefixes retain their pages
and advance the generation. A single routed edit, leaf overflow, an empty
nonroot leaf, or ancestor separator overflow delegates to the ordinary editor
before any append. Corruption and operational failures remain errors rather
than optional fallback.

Native commit consumes only the accepted prefix, then evaluates the remaining
ordered edits against the resulting private root. Original operation order,
intervening table creation and absolute prepared-value positions are preserved.
Existing authentication, ownership, admission, synchronization and durable
publication rules remain in force. This is a bounded same-leaf optimization;
the proposed general multi-leaf delta editor remains unimplemented.

`c04-leaf-prefix-kv-selected.sha256` pins **64 native source and Cargo
configuration files**. This pin deliberately excludes concurrently changing
Engine fixtures and is not a whole-workspace or Engine selection. All 64
hashes match after the native test run. `c04-leaf-prefix-kv-tests.log` builds in
**21.59s** and passes **444 native unit tests in 75.45s**, plus **26 integration
tests**: crash recovery 9 (**5.59s**), owner fencing 9 (**1.32s**), and transaction
rollback 8 (**1.96s**). The complete runner exits **0** after **106.01s**.

New and extended cases exercise height-two and height-three paths, maximal
prefix consumption across leaf boundaries, changed global minima, no-op
prefixes, fallback without page effects, ancestor separator growth, descendant
corruption, and append/sync failure fencing. Old roots retain model parity.
The native transaction cases retain more-than-16 operation ordering and
intervening table creation coverage, and add a multi-leaf current/pinned
snapshot and crash-reopen check with complete admission drain.

Counters are captured before validation reads. The original 16-row root-leaf
fixture remains at **2 directory page reads, one append, one arena sync and
4 backend reads**. Sixteen sorted updates within one leaf of a height-two tree
measure **38 directory page reads, two appends, one arena sync and 92 backend
reads**. The two appends copy the leaf and its selecting root once. Fitting old
and current snapshots then serve every checked value with **zero backend
reads and zero pressure evictions**; crash-reopened values match and admitted
memory drains. Remaining reads are measured work, not eliminated by this
copy reduction, and these fixtures do not establish whole-runtime memory or
restore performance.

Strict native all-feature/all-target Clippy with `--no-deps -- -D warnings`
passes in **12.44s** Cargo time (**12.55s** runner time), recorded in
`c04-leaf-prefix-kv-clippy.log`. `cargo fmt --all --check` also passes
(`c04-leaf-prefix-fmt.log`, **13.70s** runner time).

Source review corrects the full schema-restore workload estimate: schema reads
and activation-status lookup require per-collection release audits even when
ordinary strict-read auditing is disabled. The pre-backup calls predict
**131 audit records**, alongside one header, 32 collections and one activation:
**165 records and 330 structural point/group rows**. The completed installed
snapshot-layout trace below confirms the predicted record population. The
32-empty-collection fixture has only 33 records and 66 index rows, so its
3.714s prior construction measurement does not represent the installed
integration's workload. Corrected isolated activation/audit and larger
structural fixtures, followed by the full encrypted restore, pass on the
prefix-editor source as recorded below. No restore deadline,
input/cache/admission bound,
authentication check or crypto/optimization profile was weakened. C01–C07
remain **active/open**; expensive allocation, whole-runtime and full release
qualification remain incomplete.

`c04-leaf-prefix-engine-selected.sha256` then pins all **689 source/config
files** for the corrected Engine fixtures and fixed-field numeric diagnostics.
The run in `c04-leaf-prefix-engine.log` builds in **3m47s** and passes all
**13 selected Engine unit tests in 172.59s**. The isolated activation fixture
confirms **165 records, 48,656 framed bytes and 330 index entries**; its index
keys total **9,515 bytes** and values **5,063 bytes** before native framing.
Command application takes **1,293ms**, capture **283ms**, structural indexing
**39,916ms**, content verification **5,532ms** and teardown **337ms**. Exact
point/group contents and disk/admission drain checks pass. This models the
pre-backup command and mandatory release-audit matrix; the installed backup's
own layout trace remains the authority for its captured population.

The unchanged 32-collection fixture measures capture **36ms**, index **6,987ms**,
verification **121ms** and teardown **338ms**. The new 256-collection fixture
measures **16/63,537/4,261/86ms**, respectively, with complete point/group
verification and drain. These elapsed observations are not normalized
benchmarks and do not establish an isolated causal speedup across different
runs. The completed full encrypted integration result follows; it retains the
original **60,000ms** restore deadline.

`c04-leaf-prefix-engine.log` completes with **13 unit passes and one selected
encrypted restart/full-restore integration pass**. The integration takes
**389.49s** including its setup, backup and restart lifecycle. The complete
runner exits **0** after **790.33s**, including the **3m47s** build and
**172.59s** unit selection. All **689 hashes** in
`c04-leaf-prefix-engine-selected.sha256` still match after completion.

The actual restore itself succeeds in **25,066ms**, with **34,933ms remaining**
from its unchanged **60,000ms** deadline. Its captured layout contains exactly
**165 records and 48,656 framed bytes**: kind 0 header **1**, kind 2 collection
**32**, kind 12 activation **1**, and kind 14 audit **131**. These counts and
total framed bytes match the isolated activation/audit fixture; all other kinds
are empty. The 330 structural point/group rows therefore represent the actual
installed workload rather than the earlier empty-collection approximation.

Structural-index construction succeeds in **18,937ms**. Its **23 batch commits**
sum to **17,846ms**, and index setup takes **437ms**; these nested timings are
components of structural construction, not additional restore phases to add
to it. Semantic setup takes **682ms**. Application validation totals
**19,675ms**, within graph verification's **19,825ms**. Relocation wait takes
**0ms** at timer resolution, genesis wait **100ms**, publication wait **518ms**,
prepared-start **3,896ms**, and maintenance audit **500ms**. All these selected
phase guards end successfully. The prior timeout logs remain retained.

This is a passing source-pinned restore regression with its original deadline,
not a controlled performance comparison. The isolated corrected fixture takes
**39,916ms** for construction while installed construction takes **18,937ms**
in the same runner, and the earlier observations also vary substantially.
Neither a universal speedup nor an end-to-end throughput bound follows from
these elapsed times. The native **444 unit plus 26 integration** tests, strict
native Clippy and formatting results above remain the selected native gates;
this Engine pass adds the 13 focused checks and this one complete restore case.
Expensive allocation, whole-runtime memory, Engine/workspace strict-lint and
full release qualification remain incomplete. **C01–C07 and the overall
large-cache goal remain active/open.**

### C04 query-workspace ownership: query and selected Engine qualification

The next slice installs `QueryWorkspace::ensure_peak(total_bytes)` and an
explicit `QueryMemory<W>` ledger on canonical query execution and indexed
candidate planning. Checked logical live/peak counters separate surviving input
and output from scratch. A scope preserves its enclosing baseline, restores
logical scratch after normal/error/unwind destruction, and rejects retained
output exceeding its already-admitted allowance. Admission denial and integer
overflow preserve the previous counters and provider allowance. Logical
releases never shrink the physical peak, and consuming provider handoff keeps
that allowance with its output owner.

The infallible `empty` constructor lets a payload and its existing admission
owner be grouped before the first fallible claim. Tests require payload
destruction before provider destruction when that claim is denied. Sequential
queries preserve earlier retained outputs as a baseline; denial occurs before
document loans. Canonical indexed planning returns an owned candidate vector,
while the maintained indexes remain resident. Allocating scalar validation and
candidate construction follow the provisional admission claim.

`c04-query-workspace-query-selected.sha256` pins **18 query source/config
files**, and all hashes match after the query test run. This is a query-only
selection and does not pin or qualify the concurrently updated Engine paths.
`c04-query-workspace-query-tests.log` builds in **2m28s**, passes all **65 query
unit tests in 26.67s**, and exits **0** after **175.56s** total runner time.
`c04-query-workspace-query-clippy.log` passes strict all-feature/all-target query
Clippy with `--no-deps -- -D warnings` in **10.82s** Cargo time (**11.09s** runner
time). These are the completed gates for this slice.

Engine integration passes the selected custody and behavior checks
recorded below. It grows the
same operation reservation only above its actual existing charge. Owning
request/selected-input wrappers and intact worker outputs retain memory through
fallible preparation, async hydration, cancellation and final access checks.
New hydrated input IDs/metadata retain their allowance, while archived body
reservations keep separate custody. Output handoff preserves the peak through
`retain_workspace`; the new lease and worker failure/cancellation regressions
pass on the final custody selection. This mechanism adds no eviction policy and does
not change the requirement to keep all fitting data resident.

The byte estimates remain **provisional**: the prior fixed query estimate,
128 bytes per candidate and three times serialized output do not bound every
variable ID, sort/group key, overlapping container, decimal temporary or
decoded JSON allocation. `imbl` traversal/clone costs and JSON-pointer scratch
still need explicit admission. Opaque Tantivy scorer/search allocations and
Lindera/tokenizer allocations require separate bounds and measurement.
Ordered-seek ledger coverage, durable document/index storage and whole-runtime
qualification are also unfinished. The prior successful encrypted restore and
native checks retain their own source selections; they do not qualify these
new Engine changes. **C01–C07 and the overall large-cache goal remain open.**

The first Engine qualification attempt is pinned by
`c04-query-workspace-engine-selected.sha256` (**692 files**).
`c04-query-workspace-engine.log` exits **101** after **193.71s** during
compilation; **no tests run**. Contract and mutation-application fixtures still
called the canonical query API without its new memory argument. New custody
fixtures also attempted to call private `publish_generation` and used ambiguous
`imbl` key conversions. These are retained compilation failures, not test
passes or evidence that the production ownership paths are qualified.

The repair changes tests only. Contracts, schema-activation, common and
mutation-application fixtures now use explicit query providers bounded at
**64 MiB** and pass their ledgers to the canonical API. The scan-custody fixture
constructs its selected owner directly without private publication, and
ambiguous keys now use explicit `String` values. Production code is unchanged
after the initial Engine pin. The rerun uses the new **692-file** selection
`c04-query-workspace-engine-fixed-selected.sha256` and records output in
`c04-query-workspace-engine-fixed.log`; its completed result follows. No Engine
pass is claimed at this checkpoint, and all goals remain open.

The second attempt builds in **5m06s** and runs the selected **20 unit tests**:
**16 pass and four fail in 16.38s**. The complete runner exits **101** after
**323.15s**. The selected integration binaries compile, but **no integration
tests run**, because the unit target fails first. The failures are setup errors
in new fixtures: two service-workspace cases omit the required tenant
administrator grant, and two scan-custody cases use document version 4 with
source revision 0. Their rejection preserves the existing policy and captured
source-version invariants; it does not exercise the intended custody assertions.

The next repair again changes tests only. Service fixtures provide a valid
administrator/read grant. Scan-worker fixtures reuse the actual lease-retention
fixture and selector, preserving valid revision/version/epoch relationships
and keeping the scratch owner alive. Runtime budgets and deadlines are
unchanged. The exact same 20-unit-plus-integration selection reruns on
`c04-query-workspace-engine-custody-selected.sha256` (**692 files**), with output
in `c04-query-workspace-engine-custody.log`. The completed result follows;
the two earlier failed attempts remain recorded.

The final custody run **passes**. `c04-query-workspace-engine-custody.log`
builds in **1m27s** and passes all **20 selected unit tests in 14.46s**, all
**six selected contract integrations in 83.60s**, the **one archived-prefix
and restart integration in 104.43s**, and **two schema integrations in 9.18s**.
The full runner exits **0** after **299.19s**. All **692 hashes** in the final
Engine selection match after testing; all **18 query selection hashes** still
match as well.

Passing custody cases cover same-slot prepaid/grown allowance, denial and
cancellation, successful and failed uncollected query outputs, abandoned-output
shutdown, prior point/query output baselines, selected input surviving lease
expiry, cancelled page preparation, and completed scans retained after lease
expiry. The final scan fixture uses the real lease-retention fixture and
selector with its private scratch owner alive; it does not bypass captured
revision/version or epoch checks. Contract, archive/restart and schema cases
cover Raft query pagination, coherent snapshots and release authority, atomic
unique swaps, archived logical reads and shared text/structured publication.

`cargo fmt --all --check` also **passes**, recorded in
`c04-query-workspace-fmt.log` (**11.84s** runner time, exit **0**). The Engine
692-file and query 18-file selections match before that check. Final selected
gates are **65 query unit tests, 20 Engine unit tests, nine Engine integrations,
strict query Clippy and formatting**. No Engine/workspace strict-Clippy or
release pass is claimed; the existing audit dead-code warnings remain. Variable
allocation estimates, opaque Tantivy/Lindera allocations, ordered-seek ledger
coverage, durable document/index cutover and whole-runtime memory bounds remain
open. These selected passes qualify the ownership foundation while preserving
the requirement for full residency below the bound. **C01–C07 and the overall
large-cache goal remain active/open.**

### C04 typed query allocations and page-clone admission: selected query and Engine passes

The following source slice replaces selected portions of the provisional
query/output multipliers with claims before allocation. Selected-vector and
sort-vector backing, copied IDs and String sort keys, borrowed `imbl` iterator
stacks, row JSON output and Engine page copies now have separate charges.
Selected IDs/keys release their logical credit after destruction; the selected
Vec remains charged until its consuming iterator drops. Recursive planner,
group/aggregate and numeric allocations remain separately provisional.

The typed JSON clone walk borrows the pinned serde_json representation. It counts
nested strings and arbitrary-precision number lexemes, array Vec backing,
object keys and a conservative maximum BTreeMap node per entry. Empty clones
use the pinned Rust empty-map fast path. Nonempty allocation requests round to
the next power of two plus 64 bytes of declared policy slack; checked overflow
fails before cloning. This is a destination-clone bound with policy overhead,
not a census of source spare capacity, allocator internals or process RSS.
Overlapping projection paths clone independently and each receives its full
claim. Explicit map insertion removes the standard iterator collector/sort
buffer, and a bounded stack pointer decoder avoids per-token heap replacements.

Engine page preparation admits the selected row range and all copied aggregates
while the full result remains owned. Fresh cursor handoff retains the complete
grown peak. Continuations retain the old full-result charge independently from
their new page ledger. New fixtures cover long String sort keys with tiny
projections, many small JSON members, overlapping projections, candidate output
backing, exact page admission/denial, concurrent continuations and cancellation
or panic during pending release. A counting allocator checks that sizing itself
allocates nothing and that actual typed-clone requested-heap peaks fit their
quotes, including broad maps and retained empty source roots.

`c04-typed-output-query-selected.sha256` pins **20 query source/config files**,
all matching after the run. `c04-typed-output-query.log` builds in **15.41s**,
passes all **71 query unit tests in 12.86s** and both **counting-allocator
integration tests in 0.01s**, and exits **0** after **28.39s** runner time.
The initial strict query Clippy attempt in
`c04-typed-output-query-clippy.log` **fails in 6.60s** with all 20 source hashes
still matching. It reports explicit `drop(pilot)` and `drop(single)` calls on
test-only `FixtureWorkspace` ledgers with no Drop implementation. Removing only
those two redundant drops preserves the explicit response destruction and
leaves production source unchanged. The failed log remains retained.
`c04-typed-output-query-clippy-fixed.log` **passes** in **6.91s** Cargo time
(**7.09s** runner time), with all **20 hashes** in its fixed selection matching.
`c04-typed-output-query-final.log` builds in **7.74s**, passes all **71 unit tests
in 12.22s** and both **allocator integrations in 0.01s**, and exits **0** after
**20.09s** runner time. All **20 hashes** in
`c04-typed-output-query-final-selected.sha256` match after testing.

Final review confirms bounded request metadata does not depend on the removed
row-output wire multiplier: sort/group/aggregate kind vectors have separate
preconstruction claims, and projection/group/alias duplicate checks use bounded
slice comparisons. These changes are already in the passing frozen query
selection; no further source edit is needed. Predicate-validation temporaries
remain part of the explicitly provisional planner term.

`c04-typed-output-format.log` records **passing** `cargo fmt --all --check` in
**12.27s**, with all **695 hashes** in its source/config selection matching.
This is the initial formatting selection; the corrected-source check follows.
The
preceding 65-query and 20-unit/nine-integration Engine passes belong to the
earlier workspace ownership selection and do not qualify these new Engine
page changes.

This slice does not close recursive candidate/text-tree accounting, group and
aggregate construction, decimal parsing/comparison/formatting, or opaque
Tantivy/Lindera allocation bounds. Cursor token, Arc and map metadata remain
partially estimated. The raw service API returns an unwrapped response, so the
new typed page ledger is not transferred automatically through API return or
network egress. Existing native response fences provide fixed encoding
allowances; MCP adds decoded-tree and encoded-body claims, but these do not
establish complete typed page or network-drain custody. Embedded callers have
no automatic outer fence. Ordered-seek admission, durable document/index
cutover and whole-runtime qualification remain open. No cache eviction policy
changes: fitting data must remain fully resident. **C01–C07 and the overall
large-cache goal remain active/open.**

The follow-up egress design is recorded in the implementation design and is
**not implemented or qualified here**. It proposes a canonical private-field
`AdmittedOutput<T>` with payload-before-charge destruction, admitted adapter
conversion without raw extraction, and owner-backed transport bytes surviving
frame clones. Completed Engine charges stay immutable and preserve their peak;
adapter encoding grows an independently live response fence. Successful public
handoff releases the work registration while retaining bytes/ledger custody.
Native protobuf/codec staging admission and MCP materialized-byte ownership
need held-response/frame, failure, cancellation, denial and drain tests before
the current egress gap can close.

The initial Engine run uses `c04-typed-output-engine-selected.sha256`
(**695 source/config files**) and `c04-typed-output-engine.log`. It builds in
**5m53s** and passes its **23 selected unit tests in 18.69s**, all **six selected
contract integrations in 114.95s**, the **one archived-prefix/restart integration
in 64.84s**, and **two schema integrations in 4.79s**. The initial runner exits
**0** after **557.41s**, and all **695 source hashes** match after completion.
These are passing regressions on the source before the operation-count fix;
the then-missing saturated-slot case below prevents this initial run from
qualifying the subsequent correction.

Independent review finds a material slot-lifetime regression not covered by
those unit passes. The fresh page owner retains its ordinary operation count
through strict `self.release`; the submitted audit needs another ordinary slot.
At the last available slot, the new path can refuse an audit that the prior
path admitted after releasing the query's operation count. The applied fix
calls `full.cursor_reservation()` immediately after page cloning, before audit
release, even for the final page. Its retained byte charge stays unchanged and
continuation behavior stays unchanged. The new owner-level regression verifies
an audit-sized reservation is refused while the one available operation is
occupied, then admitted after handoff with identical byte and ledger-slot
counts; it also checks unchanged continuation behavior. The actual strict
Database regression holds **63 of 64 ordinary operation counts** after setup,
then checks fresh cursor and final pages and their durable `authorized_release`
audit events, including captured data revisions and the operation census.

The corrected source is frozen in
`c04-typed-output-engine-release-slot-selected.sha256` (**695 files**).
`c04-typed-output-engine-release-slot.log` **passes** after a **1m31s** build:
all **25 selected unit tests pass in 19.82s**, all **six contract integrations
pass in 57.65s**, the **one archived-prefix/restart integration passes in
64.81s**, and **two schema integrations pass in 4.69s**. The runner exits **0**
after **238.18s**. Both new saturation regressions pass. All **695 hashes** match
after the run, and the final **20-file query selection** still matches.
Independent read-only review finds no blocker in the handoff or new tests.
The preceding 557.41s initial Engine pass remains explicitly pre-fix evidence.

Completed selected gates are **71 query unit tests, two counting-allocator
integrations, strict query Clippy, 25 Engine unit tests and nine Engine
integrations**. Final `cargo fmt --all --check` **passes in 13.52s**, with exit
**0**, in `c04-typed-output-format-release-slot.log`. All **695 hashes** in
`c04-typed-output-format-release-slot-selected.sha256` match, qualifying
formatting on the corrected source. No Engine/workspace strict-Clippy or full release
pass is claimed; existing audit dead-code warnings remain. These selected
passes do not close provisional allocation terms, egress ownership, ordered
seeks, durable document/index cutover or whole-runtime memory qualification.
**C01–C07 and the overall large-cache goal remain active/open.**

### C04 admitted public outputs and transport custody: implementation and selected validation

The next slice implements the previously proposed output owner. Canonical
`Database::query`, `read_snapshot`, `read_snapshot_page` and `scan_snapshot_page`
returns now use `AdmittedOutput<T>`. Private payload-first fields retain the
physical peak admission through public handoff and destruction. Borrowed access
and serialization remain available; there is no raw extraction or owner-clone
API. Shared charge backing is admitted before allocation. Completed operation
counts are released before strict audits, and work registrations last through
the public final audit but do not keep shutdown open for client-owned results.

The initial Engine check is pinned in
`c04-admitted-output-engine-core-selected.sha256` (**556 source/config files**,
excluding server and benchmark files being changed independently).
`c04-admitted-output-engine-core.log` builds in **6m48s**, passes **29 selected
unit tests in 44.71s**, and exits **0** after **453.24s** runner time with all
**556 hashes matching**. This initial pass does not qualify the continuation
repair described next.

Independent review found two continuation handoff issues. Its new page ledger
kept the last ordinary operation slot through strict audit, and moving its
sole new charge into the outgoing response could release that charge before
the still-live request on a final authorization error. The corrected owner
retains a separate shared page/request charge, distinct from the old cursor's
full-result charge, and releases the completed operation count before audit.
Preparation is idempotent. New tests exercise final error destruction and an
actual cursor continuation with **63 of 64** operation counts occupied,
including a new durable audit at the original captured revision. The same
fixture preserves fresh pages and all three snapshot read/page cases.

The corrected run uses `c04-admitted-output-engine-final-selected.sha256`
(**556 files**). `c04-admitted-output-engine-final.log` builds in **2m40s**,
passes all **30 unit tests in 38.15s**, **six contract integrations in 103.46s**,
the **archived-prefix/restart integration in 88.24s**, and **two schema
integrations in 8.26s**. The runner exits **0** after **398.44s** and all
**556 source hashes match**. Coverage includes held public query/continuation
and snapshot outputs across full fixture shutdown, independent final-drop
drain, Arc-admission denial, cancellation/unwind destruction and cross-thread
handoff after the worker token is cancelled. Existing audit dead-code warnings
remain; no Engine/workspace strict-lint pass is claimed.

Native RPC keeps each original admitted source intact while quoting protobuf
vectors/strings and exact JSON buffers before conversion. The independent live
response fence also covers codec staging/growth and fixed wrappers. A bounded
JSON writer rejects a serializer that grows between sizing and encoding.
`NativeData::service()` now supplies the required body wrapper: the shared
owner stays in HTTP extensions and the lazy body, and accompanies every emitted
data frame through `Bytes::from_owner`. MCP retains the source through SDK
conversion and bounded terminal materialization, then shares custody between
response extensions and emitted bytes. Keeping both parts and body owners
covers either destruction order. Memory custody does not renew authorization
or move the existing release boundaries.

Transport fixtures use a real document with a roughly **13 KiB** string and
nested values, decode and compare its payload, and hold both last-frame clones
and detached response parts. Other fixtures cover adapter growth denial,
serialization-length changes without buffer growth, and the concrete pinned
unary/terminal wrapper inventory within a **4096-byte policy allowance**.
That allowance is not a process-RSS or arbitrary-streaming guarantee. Transport
compiler/runtime results are recorded separately below once completed.

These four paths do not complete public egress accounting. Point reads,
`get_shared` clone custody, collection listings, change feeds and other outputs
remain open. The follow-on design records those concrete gaps, including the
change-feed operation slot and raw after-image Arcs. Durable document/index
cutover, provisional query allocation terms and whole-runtime capacity and
release gates remain open. Full residency below the configured bound remains
mandatory. **C01–C07 and the large-cache goal remain active/open.**

The first all-feature/all-target caller check of Engine, Server and Bench
fails in the new transport test code. In both two-order ownership fixtures,
the first loop iteration moves the token `String` into its request header,
so the second cannot use it. It also reports a redundant test-only `to_bytes`
import. `c04-admitted-output-callers-check.log` exits **101** after **477.93s**,
with all **698 hashes** in its source/config selection matching. No transport
tests run in this check. The repair borrows the token in both headers and
removes the unused import; production behavior, node budgets and deadlines
are unchanged. The failed evidence is retained. The corrected compiler and
runtime results follow separately.

`c04-admitted-output-callers-check-fixed.log` **passes** the same all-feature,
all-target Engine/Server/Bench check in **4m43s** Cargo time (**284.03s** runner
time, exit **0**). All **698 source hashes** in the corrected selection match.
The remaining emitted warnings are the existing Engine audit and vendored rmcp
dead-code warnings; the new unused import is removed. This compiler pass does
not substitute for transport runtime tests.

`c04-admitted-output-server-tests.log` is an **incomplete, failed broad run**.
It builds in **21m58s** and reports **28 passes and three failures** before the
runner deliberately interrupts its own test process during the unrelated
`private_native_control_route_can_raise_a_full_audit_budget` stress case.
A read-only process sample confirmed active durable writes and foreground
maintenance rather than a deadlock. The run exits **101** after **3411.29s**
with **698/698 selected hashes matching**. It neither completes the 52 selected
library tests nor reaches the selected TLS integration. The interrupted test
is unqualified, not a pass. The three observed failures are the two new held
HTTP output fixtures and the existing native pool replay/routing case; their
captured panic details were not emitted before interruption. A narrowed run
uses the identical compiled binary and unchanged source with uncaptured
assertions to diagnose those failures and exercise all MCP credential-release
tests. No budget, deadline, cache policy or production source is changed to
shorten the selection. Follow-up results are recorded separately.

`c04-admitted-output-targeted-diagnosis.log` completes that unchanged-binary
selection: **17 pass, three fail in 270.84s**, exit **101**, **698/698 hashes
matching**. The existing routing/replay case passes without changing its
deadlines or source; the earlier failure's cause is not established. The native
ownership fixture observes one operation instead of zero, and MCP finishes
with exactly **4096 extra reserved bytes**. Source inspection identifies the
completed authentication audit job's retained handle reservation: replying does
not reap it, and reaping normally occurs on a subsequent dispatch or shutdown.
This is separate ownership from either response charge. A test-only quiescent
boundary joins those exact jobs and pauses audit maintenance during the census;
the real durable authentication path is preserved. The fixtures also isolate
the unified native cache's measured provider charge, allowing fitting cache
growth during authentication while requiring unchanged cache state during
response disposal and exactly two response reservations to retire.

The third failure is the small-integer fixture's initial direct query, which
now correctly refuses its source workspace within the existing **256 MiB**
budget before reaching the intended MCP decoded-tree refusal. Its repair
keeps **1000 documents** and the full result page, with **500 integers per
document**. It measures the retained source charge, admits all pre-decode
representations, then deliberately leaves **1 MiB** less than the decoded tree
requires. The greater-than-24-times tree/wire ratio, exact decoded-tree error,
successful unpressured phase and final charge drain remain required. This
changes test payload/headroom calculations, not a runtime budget. Corrected
runtime results are still pending.

`c04-admitted-output-server-fixed.log` **passes all 19 selected tests in
290.28s**, after **4m27s** compilation; the runner exits **0** after **558.03s**
with **698/698 selected hashes matching**. This selection covers the two real
HTTP ownership fixtures, adapter growth denial, fixed JSON writer and wrapper
inventory, native routing/replay, and all MCP credential-release tests including
the repaired integer-heavy source/tree test. Both native and MCP keep exactly
their two source/adapter reservations through either HTTP parts/frame disposal
order and release them after the final owner, with zero operation counts after
completed audit jobs are reaped. The only changes after diagnosis are test code
and the `test-utils` audit quiescence helper; production budgets, deadlines,
audit lifecycle and cache policy are unchanged. The earlier failures and
incomplete broad run remain evidence, not passes. The pinned-TLS integration,
strict server lint and final formatting checks follow separately.

`c04-admitted-output-tls.log` passes the pinned TLS 1.3/native HTTP/2 integration
in **0.30s**, after **2m06s** compilation (**126.68s** runner, exit **0**,
**698/698 selected hashes matching**). This qualifies the existing registered
service path, before the public-construction correction below.

Final API review finds a public bypass of that path: external embedders can
construct the public generated server with `NativeData` directly, or invoke its
raw RPC trait and extract a protobuf payload without retained custody. Existing
runtime registrations use the wrapper, but that alone does not enforce the
canonical public API. The correction makes the raw handler crate-private and
exposes only an opaque `native_data_service` factory that includes the admitted
HTTP wrapper. Runtime registration and the external TLS integration migrate to
that factory. Compile-fail documentation will reject public raw-handler use and
wrapping the opaque service as a generated raw RPC implementation. Qualification
of this final public boundary is pending; the preceding 19-test and TLS passes
remain explicitly earlier-source evidence.

`c04-admitted-output-public-boundary.log` compiles the new factory and callers
in **5m36s**, then finishes **17 passes and two failures in 194.94s** (runner
**532.05s**, exit **101**, **698/698 hashes matching**). Both nonempty HTTP
ownership fixtures and routing pass; the native fixture now constructs the
public factory. Two previously passing MCP byte-census fixtures differ by the
same **60,688 bytes**, with opposite signs: `exact_response_charges...` measures
**25,693,904** against **25,754,592**, while `terminal_body_is_materialized...`
ends at **129,026,075** against baseline **128,965,387**. These are exact
accounting assertion failures, not credited passes. Background workspace
movement is under investigation; no budget or assertion tolerance is increased.
Cargo does not reach the TLS integration after the library failures.

The first public-factory doctest run, `c04-admitted-output-public-docs.log`,
passes handler privacy but fails its second compile-fail example because the
generated server's constructor accepts an unconstrained type. Constructing that
unused container is not a usable RPC service. The example now also registers
the container with tonic's router, where the RPC implementation bound is
enforced. The failed run exits **101** after **9.95s**, with **698/698 hashes
matching**; it is retained.

The two MCP fixtures now hold the existing test-only audit maintenance guard
through their isolated censuses. Their authentication audit is captured and
their successful get is non-strict; neither path dispatches a new SecurityAudit
job while holding that guard. Credential revocation writes to the shared native
store directly, so only the cache's exact measured provider charge is excluded
from response comparisons. All response byte formulas, zero-operation checks,
live-reservation counts and final-drop drain remain exact; final body disposal
also requires unchanged cache statistics. Fixed-field diagnostic snapshots
record raw ledger/cache values and formula components. This establishes a
deterministic ownership test boundary without claiming that the original
60,688-byte discrepancy has been independently reproduced and attributed.
Corrected selected runtime, doctest and lint results follow separately.

`c04-admitted-output-public-docs-fixed.log` **passes both compile-fail API
checks in 0.85s**, after **2m56s** library compilation (**182.35s** runner,
exit **0**, **698/698 selected hashes matching**). External code cannot name
the raw handler or register the opaque HTTP service as a raw generated RPC
implementation. The final census/TLS run selects the two changed fixtures and
the previously unreached integration; the other 17 public-boundary checks keep
their earlier recorded passing evidence.

`c04-admitted-output-final-census-tls.log` **passes both corrected census
fixtures in 21.35s** and the public-factory TLS integration in **0.11s**,
after **3m22s** compilation (**223.92s** runner, exit **0**, **698/698 selected
hashes matching**). The exact-response trace reserves **25,754,592 bytes**:
**25,362,432** fixed workspace, **16,448** source buffer, **329,536** decoded
tree, **25,056** SDK body and **21,120** terminal body/owner. The live count
goes **20 → 21 → 20**, with **zero operations** throughout; final reserved
bytes return exactly to **128,965,387**. The revoked-credential terminal case
also returns to that baseline and count. This fixture has no retained native
cache credit, so normalized and raw reserved-byte comparisons coincide; cache
statistics remain unchanged while the delivered body is destroyed. These are
admission/custody observations, not RSS bounds or full-fit cache qualification.

`c04-admitted-output-server-clippy.log` passes
`cargo clippy -p kasumi-server --all-features --all-targets --locked --offline --no-deps -- -D warnings`
in **4m01s** Cargo time (**241.88s** runner, exit **0**, **698/698 selected
hashes matching**). This is strict lint for the server package; existing Engine
and vendored dependency warnings remain. It is not an Engine or whole-workspace
strict-lint pass.

`c04-admitted-output-final-fmt.log` passes `cargo fmt --all --check` in
**4.64s** (exit **0**, **698/698 selected hashes matching**).

The selected four-output custody qualification is complete: corrected Engine
evidence is **30 unit tests and nine integrations**; final public-boundary
runtime evidence consists of **17 passing checks on the earlier boundary
source**, then **two corrected census checks and the TLS integration on later
source**, alongside **two passing compile-fail API checks**, strict server
Clippy and final formatting. There is no single final 19-test runtime run.
Earlier failures, the incomplete broad run and earlier-source passes remain
recorded above. These checks cover query and the three snapshot read/page
outputs; they do not qualify all public egress, full-fit cache behavior, RSS,
the complete release or durable document/index storage. The separate change-feed
ownership implementation is now applied but remains unqualified. All C01–C07
remain open.

### C04 admitted change-feed pages: implementation, qualification in progress

The canonical Engine feed method now returns `AdmittedOutput<ChangeFeedPage>`.
Public event after-images own their `Document`; internal committed records
continue to share document Arcs. The SDK constructs the owned public value
directly, preserving the wire representation. This prevents a cheap internal
document-handle clone from escaping the page's retained admission.

Feed construction quotes cursor strings/set nodes, the bounded event vector,
iterator workspace and each document clone before allocating them. Borrowed
wire sizing rejects oversized events before copying their fields. The private
read owner holds request, page and captured generation ahead of its charge and
work registration. It releases the completed operation count before strict
audit, retains its own charge through release failures, and carries registration
through the outer audit. Native feed conversion uses the admitted source and
independent response fence through the public service's HTTP body/frame owner.

The source is frozen for focused qualification. Added tests cover clone denial,
independent owned after-images, retained output through shutdown, strict audit
with one available operation slot, measured clone allocations and a real
nonempty native feed frame in both HTTP parts/frame destruction orders. The
synthetic feed state uses canonical per-record/envelope accounting and passes
`validate_restored` during setup. Existing restart, retention-gap, filtering,
literal-number and SDK/native feed checks remain required.

The request-size allowance and three-times-result physical floor remain
provisional. Holding an admitted output's peak is not a process-RSS guarantee
or count-once source-document accounting. No runtime budget, deadline, persisted
record, cache admission or eviction policy changes in this slice. Full
residency below the bound and all C01–C07 remain open. Results follow below.

`c04-feed-output-engine.log` fails compilation of the new unit fixture: its
literal sequence key infers `i32`, which cannot collect into the feed's `u64`
ordered map. No selected tests run. The runner exits **101** after **363.94s**,
with **699/699 source/config hashes matching**. The repair explicitly types
that synthetic key as `1u64`; production code and test budgets are unchanged.

`c04-feed-output-engine-fixed.log` passes the **three new unit tests in
25.14s** and **two existing history integrations in 39.61s**, after **2m51s**
compilation. The runner exits **0** after **236.04s**, with **699/699 selected
hashes matching**. This covers typed-clone refusal and final drain, independent
after-images, strict audit with 63 of 64 operation slots occupied, held output
after shutdown, plus durable restart, resumption, retention gaps, scoped tails
and actual deletion records. Existing Engine audit dead-code warnings remain.
Allocator, SDK and native feed qualification follows separately.

`c04-feed-output-allocation.log` passes all **three counting-allocator tests in
0.02s**, after **37.70s** compilation (**37.84s** runner, exit **0**,
**20/20 query-source/config hashes matching**). The new feed quote performs no
heap allocation, bounds the fixture's measured owned cursor/after-image clone
peak, and drains to zero after disposal. This measures requested allocations
under the pinned container policy; it does not prove process RSS or retained
source capacities.

`c04-feed-output-client.log` passes **four SDK feed tests in 0.01s**, after
**3m14s** compilation (**195.10s** runner, exit **0**, **699/699 selected hashes
matching**). Literal values, cursor gaps and original positions, filtered commit
metadata, and after-image identity/version rejection retain their existing
behavior with the owned public document constructor.

A separate public-cancellation regression is now installed. It drives the real
feed future until its strict audit child is admitted behind the ordered proposal
gate, then drops only the feed waiter. It requires the source and boxed release
future to retire while the child keeps its original operation charge and work
registration. The final census joins the real child and drains its fixed registry;
cache growth is measured separately. Successful audit publication changes logical
state but installs no retained non-cache admission owner in this fixture, so its
expected final ledger delta is exactly the registry's measured metadata. This
is a test of actual admission ownership, not proof that audit state heap is fully
accounted. The new cancellation and native transport run follows separately.

`c04-feed-output-transport-cancellation.log` passes the **public Engine
cancellation test in 12.80s** and **all three selected native/SDK tests in
54.65s**, after **18m58s** compilation (**1206.62s** runner, exit **0**,
**699/699 selected hashes matching**). Cancelling the gated read releases exactly
the two source/release reservations, leaves the original audit operation owned,
and keeps work drain pending until its real completion. Registry acknowledgement
then matches the exact final non-cache census, and the durable audit exists.
The real native feed frame retains both source and adapter charges in either
parts/frame destruction order and retires exactly two reservations at the final
owner. Existing native archive/feed scope and SDK literal/admission behavior
also pass. Existing Engine/rmcp warnings and Apple's large `__eh_frame` linker
warning remain. Compilation was active on a busy shared host; no runtime budget,
deadline, job-count override or source change was used to shorten the run.

Strict lint for Types, Query, Client and Server and final formatting remain
the selected slice's final checks. Engine/workspace strict lint and complete
release, source-accounting and disk-backed document/index gates remain open.

`c04-feed-output-clippy.log` passes strict all-feature/all-target Clippy for
Types, Query, Client and Server (`--no-deps -D warnings`) in **5m57s** Cargo
time (**357.79s** runner, exit **0**, **699/699 selected hashes matching**).
Existing Engine and vendored rmcp dependency warnings remain; this is not an
Engine/workspace strict-lint pass. `c04-feed-output-fmt.log` passes whole-workspace
formatting in **13.31s**, exit **0**, with **699/699 selected hashes matching**.

The selected feed-output slice is qualified by the separate runs above: four
Engine unit cases, two history integrations, three allocator cases, four SDK
feed cases and three native/SDK cases, followed by selected strict lint and
formatting. The initial compiler failure is retained. The request/physical
floor and broader source-accounting limits still apply. This closes neither
the complete public-output inventory nor any C01–C07 goal.

### C04 point outputs and shared documents: selected qualification

The next applied slice changes `Database::get` to
`AdmittedOutput<Document>` and `get_shared` to immutable `SharedDocument`.
The lower handle exposes borrowed document access, serialization and owner
cloning; it has no raw-Arc extraction, mutation or ownerless deserialization.
Its provider trait is an explicit trusted accounting contract, not a Rust proof
about arbitrary third-party implementations. The SDK bridge transfers its
existing real admitted document owner into the same handle without cloning the
body; this does not add a typed SDK Get network endpoint.

Engine point preparation now registers cancellation before the consistency
barrier, retains the selected source and cold read cache, and preclaims the
registration/output-owner backing. Owned reads claim the typed document clone
before allocating. Shared cold reads move their decoded chunk cache and its
actual reservations into the returned owner; hot handles retain their selected
document without pinning an entire generation. The completed read operation
retires before strict audit, while the private owner and registration remain
through final release and the outer audit. Native and MCP Get retain the original
admitted source through conversion and terminal frame disposal.

Six focused Engine ownership tests are installed, including actual public
cancellation of both point variants while their strict audit is queued. Unlike
feed, point release has two nested boxed futures: the cancellation test requires
exactly three source/release reservations to retire while the independent audit
child stays owned. Other checks cover hot/cold shutdown retention, source and
owner-allocation denial, historical identity, last-clone cross-thread drain,
strict audit capacity, measured clone backing, SDK custody and real native/MCP
frames. Public callers borrow the new outputs; control topology's separate
decoded allocation remains an open ownership item.

The existing point floor and cold decoder/container allowances remain
provisional. Repeated shared reads do not yet reuse a canonical per-allocation
source credit, and this wrapper is not full source-capacity or RSS accounting.
The planned aggregate document pool, durable document/index replacement and
all C01–C07 remain open. The installed source is frozen for caller compilation
and focused qualification; results follow separately.

`c04-point-output-callers-check.log` passes the all-feature/all-target compiler
check for Types, Query, Client, Engine, Server and Bench in **5m38s** Cargo time
(**338.69s** runner, exit **0**, **702/702 selected hashes matching**).
Existing Engine audit and vendored rmcp warnings remain. This is caller/type
validation; point runtime and negative public-API checks remain pending.

`c04-point-output-engine.log` passes all **six new point ownership unit tests**
in **63.99s** and **eight selected integrations** across contracts, control,
embedded audit, history, response release and shutdown. The runner takes
**700.23s**, including **6m57s** compilation, exits **0**, and verifies
**702/702 selected source hashes unchanged**. The integrations cover strict
audit slots, authorization and historical shared values, key revocation,
control reopen, embedded denials, archive/restart, actual response fencing and
immediate reopen with retained plaintext. This confirms the selected Engine
boundary, not complete source accounting or disk-backed document serving.
Lower API, SDK and transport qualification and final selected lint/formatting
remain pending.

`c04-point-output-types-doc.log` passes all **three compile-fail shared-document
API checks** in **0.36s** (**89.47s** runner, exit **0**, **702/702 selected hashes
matching**). Raw document-Arc extraction, mutation through the handle and
ownerless deserialization are rejected. This checks the public API surface;
the trusted provider accounting contract remains a provider responsibility.

`c04-point-output-server.log` passes all **19 selected Server tests** in
**177.29s**, after **10m18s** compilation (**796.25s** runner, exit **0**,
**702/702 selected hashes matching**). The selection includes six real response
ownership/admission cases (both new point transports, prior query/feed paths
and adapter-growth denial) plus all 13 MCP credential/terminal-body cases.
The new point tests exercise detached parts and frame destruction in both
orders; the corrected MCP census includes the retained point source. Expiry,
revocation, policy changes and dispatched-mutation uncertainty remain enforced.
Existing Engine/rmcp warnings and Apple's large `__eh_frame` linker warning
remain. The SDK bridge, allocation checks and final selected lint/formatting
are still pending; no full Server, workspace or release pass is claimed.

`c04-point-output-allocation.log` passes all **four Query counting-allocator
checks** in **0.01s** (**31.51s** runner, exit **0**, **702/702 selected hashes
matching**). The new document quote makes no allocation and bounds the measured
destination clone peak; page/feed clone and small-wire object-node cases still
pass. These tests measure requested heap, not RSS or arbitrary retained source
capacity.

`c04-point-output-client.log` passes the **SDK shared-document bridge case**
(**104.18s** runner, exit **0**, **702/702 selected hashes matching**).
It uses the real literal decoder/resource owner, preserves document identity
without a body copy or new reservation, retains admission after the original
call ends, and drains after the last cross-thread handle. This does not add or
qualify a typed SDK Get network endpoint. All selected point runtime/API tests
above now pass; strict selected lint and final formatting follow separately.

`c04-point-output-clippy.log` passes strict all-feature/all-target Clippy for
Types, Query, Client and Server (`--no-deps -D warnings`) in **6m24s** Cargo
time (**384.58s** runner, exit **0**, **702/702 selected hashes matching**).
Existing Engine and rmcp dependency warnings remain; Engine/workspace strict
lint is still open. `c04-point-output-fmt.log` passes whole-workspace formatting
in **17.39s**, exit **0**, with **702/702 selected hashes matching**.

The selected point-output slice is qualified by the separate runs above:
six Engine unit cases, eight integrations, three compile-fail API cases,
four allocator cases, one SDK bridge case and 19 Server cases, plus selected
strict lint and formatting. All use the same selected 702-file source.
No complete public-output inventory, source-capacity, full-fit cache, durable
document/index or full release gate is closed; all C01–C07 remain open.

### C04 aggregate document pool: applied test-only component

The reviewed pool patch (`bcdf1b13920eb1d5be7c18df0f79e40e6587b5de1764f20179307eb163bb0396`)
is applied and formatted. The pool, source-admission origin and constructor
remain `cfg(test)`; no production document producer, wire format, cache
membership or serving path uses them. One growable Resident reservation owns
the pool and every inline document credit. Admission preserves both native
cache-work headroom and ordinary protected bytes/slots. Compact document clones
are quoted before allocation; arbitrary source spare capacity is not adopted.

Private handles share their physical payload and credit. Final concurrent
release frees the payload Arc and document backing before credit reuse; the
last pool handle frees its Arc and synchronization backing before refunding
the sole reservation. The control quote includes a conservative 4 KiB allowance
per Mutex/Condvar, qualified against actual construction, wait/reacquisition
and destruction on this host. These are requested-heap measurements and policy
allowances, not an exact RSS or arbitrary platform guarantee.

`c04-document-pool-component.log` passes **39 tests**: all **11 new pool cases**,
all **17 existing SnapshotWork cases**, and all **11 native-cache admission
cases**. Runtime takes **0.35s**, after **5m54s** compilation (**354.56s** runner,
exit **0**, **705/705 selected source/config hashes matching**). Tests include
4,096 documents under a four-slot governor, factory-first disposal, concurrent
growth/retirement, denial and unwind, both byte/slot protection floors, compact
clones from sources with spare capacity, allocation-free aliases, and actual
allocator-gated final destruction. Existing audit warnings remain.

`c04-document-pool-allocation.log` passes all **four Query counting-allocator
tests** in **0.01s** (**6.69s** runner). Strict all-feature/all-target Query Clippy
passes in **32.19s**, and whole-workspace formatting passes in **17.86s**.
All three runs exit **0** and verify the same **705/705 selected hashes**.
This completes the component's selected checks; Engine/workspace strict lint
and broader release qualification remain open.

Runtime activation additionally requires admitted
startup/decode context, owned wire DTOs separate from runtime handles, all
document producers using the same pool, and local admission failures staying
outside deterministic replicated rejection receipts. Durable document/index
serving and full residency below the bound remain unimplemented at this layer;
all C01–C07 remain open.

### C04 retained fallible query-source worker: selected runtime checks pass

The reviewed patch (`275e91ae21d217d16cebbe11b6e0a6f48663c3218742e6a4d1cc26f8174b26af`)
is applied. Its adapter and existing-grant preparation API remain `cfg(test)`;
production `QueryWork` is unchanged. It borrows the exact QueryMemory provider
and cancellation token, adding one Resident metadata reservation with ordinary
protection and no second operation count. Source failures remain their original
owned type. Selected sources and registrations stay owned until positive cleanup.

Successful claim transfers worker cancellation authority under the control
lock, so dropping a delivery or draining a stale report cannot cancel an
already handed-off result. A pre-claim drain still prevents claim; caller and
pressure cancellation remain effective afterward. Separately admitted snapshot
workers preserve their existing cancellation behavior. Preparation catches
unwind only around checks borrowing the plan, returning that exact plan and
original opaque panic payload after local ticket/metadata rollback. Concrete
allocation remains an audited infallible field move. Arbitrary panic/error
heap sizes are not qualified by the fixed metadata quote.

Nine regressions use a real installed encrypted read view, covering
same-grant growth after claim, cancellation, original read/close diagnostics,
run unwind, byte/slot refusal, foreign providers, pre-start cleanup and actual
stale memory-sampler panic. The close-error fixture reports a prior native read
failure, not an injected physical close fault. Its resident header/index and
fixed source quote are deliberately limited fixtures.

`c04-source-worker-component.log` passes all **48 selected tests** in **16.66s**:
all **nine worker cases**, all **17 existing SnapshotWork cases**, all **11 pool
cases** and all **11 native-cache admission cases**. Compilation takes **11m21s**;
the runner takes **698.21s**, exits **0**, and verifies **707/707 selected source
hashes matching**. Existing audit warnings remain. Selected lint and final
formatting are pending; no Engine/workspace strict-warning pass is claimed.

`c04-source-worker-clippy.log` then fails in **506.22s**, exit **101**, with
**707/707 selected hashes matching**. It enables `-D clippy::all` for Engine
and Query across features/targets; this is not the all-Rust-warning release
gate. It finds a collapsible test-only close-error condition in the new worker
fixture and an immediately invoked test closure in the earlier restore-phase
fixture. Both are corrected without changing production behavior or audit
warnings. The earlier 48-test pass is pre-correction evidence; the affected
tests and lint require a new source-pinned run.

Production activation requires an admitted per-Database registry of
exact worker identities and preparation obligations, sealed before drain,
plus actual aggregate source ownership and typed service failure handoff.
It also requires an exact selected storage snapshot: opening a fresh current
view cannot serve an older Generation/root/index identity. The current store
has no independent selected-view fork; diagnostic facade clones share one
reader's failure/close state. A future child must preserve the actual native
SnapshotPin while retaining independent admitted snapshot backing, descendants,
census identity and close outcomes. These are integration prerequisites, not
features established by the component tests.
All C01–C07 remain open.

### C04 logical page codec and metadata boundary: applied, qualification pending

The reviewed codec patch (`8944d80069ca1f3177b2cb6dee5a8672493e723d32f8ef0f0b4a8597d86fad75`)
and metadata/genesis patch (`486611c2f7d85c346fd97e85430fc63b70b3f8f2b135913ba4f45b5efd3c36f0`)
are applied with the two test-only lint corrections above. Formatting and
diff whitespace checks pass; the new **711-file selection** is frozen for
caller compilation and subsequent focused qualification. No runtime result
is claimed for this selection yet.

The test-only logical codec uses fixed 16 KiB pages, a 104-byte header and
88-byte leaf/branch descriptors. Four checked totals distinguish live/archive
counts, live body bytes and archived map-entry bytes. Borrowed validation
checks identity, generation, level, full-page digest, order, ranges, totals
and canonical padding. Encoding rejects invalid input before changing the
caller-owned fixed buffer. Review caught mutable validated Page metadata;
all its fields are now private with copy accessors. Six tests cover local
format and allocation behavior only. There is no page I/O, manifest, editor,
cache, durable publication or production source activation in this component.

The production metadata slice adds borrowed observations from one captured
Generation and migrates selected Server metadata consumers. Configuration-only
validation now uses the canonical empty genesis metadata and the same snapshot
quota check without constructing a serving engine or indexes. Validation still
uses bounded metadata scratch; it is not allocation-free or a new admission
proof. Control seeding and runtime constructor semantics remain unchanged.
Three new tests cover coherent unaudited observations, real invalid-name/policy/
limit cases, and the constructor's exact snapshot-size threshold.

Raw Generation state/index visibility remains open in this slice. Control
topology and enrollment document reads need concrete admitted decoding and
transformation ownership; external fixture callers also need migration before
field narrowing. No replacement raw state getter, ownerless source factory,
compatibility fallback or runtime pool activation is added. The whole cache
must still retain everything that fits; all C01–C07 remain open.

`c04-primary-metadata-callers-check.log` passes the Types, Query, Client,
Engine, Server and Bench all-feature/all-target check in **466.60s**, exit **0**,
with **711/711 selected hashes matching**. Existing Engine audit and rmcp
dependency warnings remain. This is compilation evidence, not runtime or
strict-warning qualification.

The independently reviewed visibility companion
(`46b40475093b0d2f5001a7d12a721fbccbbc1eabed80e3a8186105c31767ad6c`)
is subsequently applied. `Generation.indexes`, its resident document-source
adapter and its factory are now crate-private. Six external fixture queries
use one test-utils observation helper that binds source, indexes and limits
to the same captured Generation and retains the caller's real query workspace
through the assertion. Existing snapshot-coherence assertions are unchanged.
Raw `Generation.state` remains public pending the admitted Control semantic
observations and remaining fixture migrations. Formatting and diff whitespace
checks pass; the new 711-file selection is frozen for component testing.
The prior caller check predates this seven-file visibility change.

`c04-primary-metadata-component.log` subsequently runs **61 tests** on that
711-file selection: **59 pass and two fail**. The runner exits **101** after
**1408.19s** (compilation **23m16s**, tests **11.64s**), with **711/711 hashes
matching**. All 48 selected worker/pool/cache-admission tests and all four
restore-phase tests pass, including both earlier test-lint corrections. Two
genesis validation tests and five codec tests pass. This is a failed run,
not a qualified 61-test selection.

The metadata fixture's document mutation initializes a second encrypted scratch
table for receipts. The existing mutation fixture already documents that this
setup needs a 33rd lease; the new metadata fixture supplied 32. The correction
keeps **64 MiB / 32 slots**, replaces that unrelated mutation with an ordered
policy update, and compares the genesis, collection-created and policy-updated
generations. It still checks borrowed pointer identity, immutable old metadata
and absence of observation-driven revisions/audits. It no longer claims to
exercise document mutations. Production metadata code is unchanged.

The malformed-page test cleared only the low byte of encoded `used = 286`,
producing 256. That is an in-range boundary with nonzero record bytes beyond it,
so `Padding` is the correct rejection. The test expectation is corrected and
a separate high-byte clear produces 30, asserting `Length` below the 104-byte
header. Production codec behavior is unchanged. Both corrected tests require
runtime requalification.

### Exact native snapshot forks and borrowed Control validation: applied

The independently reviewed native patch
`bb4a7b100fcda7c4d9395680f763dbc868831a1a61bfa61a7f889ee940e6e299`
is now applied. `ReadTransaction::fork` and `RetainedReadTransaction::fork`
preserve the actual selected native pin in an independently charged private
snapshot backing. Ordinary read/write captures, tables, ranges and value guards
use that same ownership representation. The last alias frees its Arc backing,
then the snapshot, then retires the actual lease. Forks consume a new backing
reservation but share the original root-pin reservation. Parent/child close
accounting is independent; there is no current-root fallback.

This adds one workspace lease to every ordinary read/write capture or fork.
The native 64-bit quote is 256 bytes; the installed Store provider adds its
actual lease-box and governor overhead, so 256 is not the total governor cost.
Existing limits are unchanged. Nine new native tests cover old-root reads
through updates/deletes/compaction, both close orders, descendant ownership,
pre-effect byte/slot denial, admission rollback, sealing and owner-failure
races, and actual backing deallocation before refund. No runtime pass is yet
claimed. Registered/encrypted paired-view forks are a separate pending layer.

The reviewed Control patch
`8e57977ffd4c4312f9dfa2d4c977f659c00a096367a75870e1acd9227011e2fc`
and test-import correction
`ece9a092914ae6166bd754cf33fa98f8048722d3217231cad4c9194208b1c3ae`
are also applied. Canonical borrowed topology validation avoids temporary
topology/voter copies, preserving global checks, exact error order and the
unchanged-topology behavior for an absent voter-override route. Enrollment
digests stream the same serde bytes directly into SHA-256 without constructing
the complete serialized Vec. The digest format and returned String are
unchanged. Six regression tests are added. Typed output ownership, parser
scratch admission and retained proposal ownership remain open.

Formatting and whitespace checks pass. The new **713-file selection** is frozen
for the native suite, Types topology tests and 24 selected Store ownership/
admission regressions. Corrected Engine tests, existing coherence integrations,
Server tests and selected lint gates still need to run. All C01–C07 remain open;
no durable document/index or full-cache-residency completion is claimed.

`c04-selected-fork-native-suite.log` now passes the complete native
all-feature/all-target selection: **453 unit tests**, one cache-allocation
test, four commit-allocation tests, nine crash-recovery tests, nine owner-fencing
tests and eight transaction-rollback tests (**484 total**). The runner exits
**0** after **1138.70s**, with **713/713 source/config hashes matching**.
The commit-allocation executable retains its original large workloads and
limits; its four tests take **921.75s**. All nine new native fork tests pass.
This verifies native storage ownership and durability behavior on this source;
it does not activate disk-backed document/index sources or the decoded cache.

`c04-control-borrowed-types.log` passes all **seven** selected topology tests
in **61.85s**, exit **0**, again with **713/713 hashes matching**. The Server
digest tests and Store/Engine callers still require their selected runs.

`c04-selected-fork-store-regressions.log` subsequently fails **two of 24**
selected Store tests: **22 pass**, runner **326.70s**, exit **101**, with
**713/713 hashes matching**. `owned_reader_point_and_range_bytes_keep_exact_credit_after_close`
expects 45,272 bytes but observes 45,968. The three native outputs each retain
an additional 232 bytes from the existing `AdmittedValue` policy (its handle
size plus 192 bytes). The routine-failure fixture targets the obsolete smaller
reservation amount, so its injected denial never occurs. These are stale exact
output-charge expectations; the native fork patch did not change that output
allocation policy. Correcting the fixtures and rerunning is required; no
passing Store regression selection is claimed here.

The independently reviewed Store selected-view fork companion
`c7d8695d221f903a9818422e1afabf88afdf2eda736d89d9ccb1fcbe4bb0eace`
is now applied. One independently registered sibling reader forks the exact
selected native pin, including for a paired encrypted view. `ForkQueued`
prevents a concurrently recovered census facade from starting a current-root
read. Parent/child close, actual database-owner identity, current domain access
and pre/post-fork key expiry remain explicit. Ten new tests and the existing
Store regression selection are pending on this later source.

The reviewed URL-only workspace candidate
`6944a5f2fa837fd03eab508fcf033be34d55d87e0c0d41990b7055b4135f2240`
is also applied for qualification. Its allocation-free quote is derived from
the pinned Rust, URL, IDNA, ICU and SmallVec implementations; special-scheme
host parsing keeps long path lengths out of the Unicode normalization bound.
It is deliberately conservative, particularly for Unicode hosts. It does not
reserve memory or activate a typed Control owner. Cold/warm parser allocator
measurements, fixture classification, strict lint and runtime call-site
admission are still unqualified.

The corrected metadata fixture now checks collection creation's policy/schema
increments and zero document data epoch; the later policy update advances only
policy. Its original 64 MiB / 32-slot provider is unchanged. These test-only
assertions and the codec expectation correction still require the Engine rerun.

The reviewed test-only native-output correction
`6dfb024fadda0672358b87d9fef2da4248402dd027335cc9bf02de897ed01133`
is applied. Three fixture sites use the actual native handle/allowance plus
Store lease-box charge, retaining the existing provider token accounting.
The hypothetical duplicate ciphertext allocation stays separate. Limits,
workloads and exact drain/slot assertions are unchanged. The later **717-file
selection** is frozen for the next qualification queue.

On that selection, `c04-control-url-workspace-types.log` passes **nine** tests
in **27.64s**, and `c04-control-url-workspace-allocator.log` passes its isolated
allocator test in **40.84s** (test runtime **0.54s**). Both exit **0** with
**717/717 hashes matching**. The allocator test covers cold first parse,
Unicode/ACE/percent-hosts, invalid inputs, growth boundaries, long paths and
an observed 4,104-byte ICU sort allocation. Every measured parse returns to
zero tracked live bytes; successful quote calculation allocates zero.

| Parser probe | Quote bytes | Measured peak requested bytes |
| --- | ---: | ---: |
| Plain HTTPS | 640 | 26 |
| Cold/warm Unicode host | 3,106,688 | 107 |
| ASCII ACE host | 189,952 | 30 |
| Percent-encoded Unicode host | 6,154,240 | 99 |
| 655,373-byte path/query/fragment input | 8,388,736 | 3,932,238 |
| Unicode host with long path/query | 4,679,552 | 393,372 |
| ACE host with long path/query | 1,205,760 | 393,402 |

The quote is a source-derived conservative admission policy, not measured RSS
or an exact parser cost; its Unicode estimates substantially exceed these
observations. These passes qualify the component on pinned dependencies, not
whole-topology memory or its still-unwired production admission. Store, Engine,
Server and lint gates in the later queue remain pending.

`c04-selected-view-fork-store.log` then passes **33 of 34** tests and fails
the targeted native-output denial fixture again. All **ten new registered/
encrypted fork tests pass**, as do the repaired exact output-credit and
low-headroom checks. The runner exits **101** after **240.26s**, with
**717/717 hashes matching**. The queue stops before Engine/Server/lint.

The isolated temporary fixture trace in `c04-native-output-denial-trace.log`
also fails (**43.23s**, exit **101**, **717/717 hashes matching**) and reveals
an exact charge collision: table verification's required two-byte output
requests 4,346 bytes; its optional cached copy requests **4,450 bytes**, equal
to the later required 106-byte encrypted-row output. The optional copy consumes
the single-shot fault, correctly falls back to an uncached read, and the later
required output succeeds. The fixture must keep matching-byte refusal armed
through the operation and explicitly disarm afterward. This preserves the real
capacity-denial path without relying on reservation call counts or changing
production cache behavior. Temporary prints are diagnostic evidence only and
must be removed before the next qualification.

The independently reviewed persistent-refusal fixture correction
`2cec89048d03b6ea74de33a896bf1f996051ec3d745f8fe6dc38009ed1fad660`
is applied and all temporary prints are removed. Both targeted tests disarm
the refusal immediately after their real operation returns, before inspecting
or releasing its error. `c04-native-output-denial-corrected.log` passes all
**four** selected native-output/duplicate-charge/catalog-denial/point-denial
checks in **38.60s**, exit **0**, with **717/717 hashes matching**. Their
tests take **3.13s**; no limits, workloads or expected failure types change.
This later run resolves the remaining failed fixture. The preceding 33 passes
and these four passes are separate source selections, not a newly claimed
single 34-test suite. The Engine/Server/coherence/lint/format queue is now
running on the corrected 717-file selection.

`c04-fork-control-engine-component.log` passes all **61** selected Engine
tests in **575.41s**, exit **0**, with **717/717 hashes matching**. Compilation
takes **9m30s** and tests **5.05s**. This includes the corrected metadata and
malformed-page fixtures, all 48 selected worker/pool/cache-admission checks,
four restore-phase checks, two genesis validators and all six page-codec tests.
The earlier 59/61 failed run remains separate evidence. Existing Engine audit
dead-code warnings remain; this is not a strict-warning or full-workspace pass.
The four schema/transaction coherence integrations run next.

`c04-primary-metadata-integrations.log` passes all **four** selected Engine
integrations in **34.51s**, exit **0**, with **717/717 hashes matching**.
The two contracts tests verify no partial failed-batch effects and atomic
unique-index swaps with coherent old generations. The two schema tests verify
atomic multi-index publication and simultaneous text/structured-index
publication after existing-document validation. These tests use the new private
source/index boundary through the exact-generation fixture helper. Server
tests and lint/format are still pending.

`c04-primary-metadata-server.log` passes all **six** selected Server tests in
**731.54s**, exit **0**, with **717/717 hashes matching**. Compilation takes
**12m10s** and tests **0.92s**. The selection covers lifecycle configuration,
the secret-free operator example, three streaming enrollment-digest cases and
explicit-tenant dispatch. Apple ld reports its existing large unwind-section
warning; Engine audit/dependency warnings remain. Engine/Query Clippy,
strict affected-package Clippy and formatting are still pending on this frozen
selection. The next Control ownership and plaintext workspace patches remain
unapplied, so these passes do not qualify those later changes.

The frozen 717-file queue completes successfully. Engine/Query Clippy with
`-D clippy::all` passes in **178.29s**; strict KV/Types/Query/Server/Store
Clippy with `-D warnings` passes in **308.12s**; whole-workspace formatting
passes in **6.46s**. Each exits **0** with **717/717 hashes matching**, and a
final independent hash comparison matches all 717 files before the next edits.
The existing Engine audit warnings remain outside the strict-package selection;
this is not an Engine/workspace strict-warning or full-release pass.

The following independently reviewed patches are now applied:

- Plaintext-get workspace quote and unchanged decode-boundary extraction,
  `16957bd976892190117648b545d09f753abcdd84342110e8f3f5e7514d3b89ca`.
  The pure checked helper covers deterministic key/AAD/decryption/field-copy
  backing; actual callers must admit it before use. It does not yet wire a
  selected primary reader or bound arbitrary diagnostics.
- Local typed Control topology ownership,
  `2694702973815b2041ddd30abe4f12551f6ca59243afc4f4a957cb30e93ee2c9`.
  Installed Database admission precedes decode/validation; independent DTOs and
  opaque original failures retain their grants. Only borrowing management,
  startup-route and configured-enrollment consumers migrate. Consuming command
  and proposal producers remain unchanged and explicitly open.
- Supplemental Server failure/route tests,
  `d886830e4651d25bc05044d1885a6be3c44d6260ac2168f90dfd767990f7889b`.
  Real Control writes supply validation and decode failures for the two error
  adapters, with a quiescent ownership census. The existing resident fixture
  also rejects approval while its route is present without changing the
  approval row. No fixture budget or deadline changes.

Checksums, apply-checks and `git diff --check` pass before qualification.
The focused Store/Types/Engine/Server/lint/format queue now pins **722** source
and configuration files. Runtime results for these new changes are pending.
No document/index serving, whole-database fit or cache-goal completion is claimed.

`c04-plaintext-workspace-store.log` passes all **39** selected Store tests in
**147.89s**, exit **0**, with **722/722 hashes matching**. Compilation takes
**1m20s** and tests **66.78s**. All three new plaintext workspace cases pass,
including first-decode/maximum-name allocation observations and authenticated
malformed fields, tampering and pre-decrypt size rejection. The selection also
reruns all ten exact-fork cases and the affected read ownership, output denial,
expiry and corruption regressions. This qualifies the deterministic plaintext
buffer quote on pinned code with the documented child-only backtrace setting;
it does not qualify arbitrary diagnostics or install a primary document reader.
Types/Engine/Server/lint/format checks remain pending on this same frozen source.

`c04-local-control-types.log` passes all **ten** selected arithmetic/topology/
URL unit checks in **22.98s**, and `c04-local-control-allocator.log` passes
its isolated topology allocation corpus in **34.11s** (test runtime **0.04s**).
Both exit **0** with **722/722 hashes matching**. The latter exercises real
borrowed decoding and validation across container growth, positional input,
duplicates and malformed diagnostics; the sizing traversal allocates nothing
and decoded/error backing is released after drop. Earlier separate URL tests
provide cold-parser evidence; this topology test does not claim cold URL/RSS or
whole-runtime coverage. Engine ownership/integration and Server checks follow.

`c04-local-control-engine.log` passes all **four** new ownership tests in
**223.30s**, exit **0**, with **722/722 hashes matching**. Tests take **0.01s**
after **3m43s** compilation. Exact admission refusal precedes decode, outputs
retain their own allowance through cross-thread final release, and cancellation,
validation/serde errors and consuming failure-owner downcasts preserve custody.
`c04-local-control-integration.log` then passes both existing Control
integrations in **19.50s**, with **722/722 hashes matching**; their runtime is
**13.42s**. Added assertions preserve selected version/data, no local read audit
or revision, no old Generation pin, and independent output lifetime through
shutdown/reopen. Server consumer tests and final lint/format remain pending.

`c04-local-control-server.log` aborts on its first selected test with a stack
overflow/SIGABRT in the modified dormant-resident enrollment fixture. The runner
exits **101** after **506.89s**, with **722/722 hashes matching**; compilation
takes **8m26s**. The three-test process does not finish, and the later lint/format
queue does not run. The abort does not identify the exact overflowing frame.
The added direct approval future increases the nested fixture state; a reviewed
test-only repair will box large fixture calls using existing conventions, while
preserving all actions/assertions and all stack-size, budget and deadline
settings. The separately selected new classification case is being checked on
the original source before applying that repair. Earlier component passes are
retained evidence, not a claim that the Server selection passed.

The isolated `c04-local-control-server-classification-original.log` then passes
the new real-Control error-adapter test on unchanged source: **18.82s**, exit
**0**, **722/722 hashes matching**, with test runtime **13.22s**. Its genuine
opaque failure classification and exact retained-credit assertions pass. The
stack repair is therefore narrowed to the failing shared dormant-resident
fixture; speculative boxing in the already passing classification case is
excluded. Runtime/startup and dormant-resident completion remain unverified.

The focused test-only repair
`f19417dfc2fdba2c76edb15143635ce4252790c6bea851f9fc3dbdcf2eea66f2`
boxes the newly added approval future and the shared dormant fixture at both
callers. The passing classification case remains unchanged. After checksum,
apply-check and whitespace checks, `c04-local-control-server-repaired.log`
passes all **four** selected tests in **239.65s**, exit **0**, with **722/722
hashes matching**. Compilation takes **2m33s** and tests **85.72s**. This
resolves the observed abort for both dormant-resident callers and also verifies
the new classification test and real runtime TLS/Control startup/reopen path.
It does not establish which precise original stack frame overflowed. Stack
size, admission, deadlines and assertions are unchanged. The remaining
Engine/Query and strict affected-package lint plus formatting checks now run
on the repaired frozen source.

`c04-local-control-engine-clippy.log` passes Engine/Query Clippy with
`-D clippy::all` in **136.64s**, exit **0**, with **722/722 hashes matching**.
The three library/four test Engine audit dead-code warnings remain; this is
not its strict-warning gate. `c04-local-control-strict-clippy.log` then fails
in **27.29s**, exit **101**, with **722/722 hashes matching**: Clippy interprets
`8 * size_of::<usize>()` as a manual bit count. The expression actually quotes
eight pointer words. Replacing it with `size_of::<[usize; 8]>()` preserves the
allowance and states its purpose directly. On that corrected selection,
`c04-local-control-strict-clippy-repaired.log` passes Types/Store/Server
all-target strict Clippy in **74.24s**, and `c04-local-control-fmt.log` passes
workspace formatting in **3.72s**. Both exit **0** with **722/722 hashes
matching**. The original failure remains recorded. No workspace release pass
or cache-goal completion is claimed.

The reviewed selected-application proof patch
`6766069019ae499cc2b8cf270c31aa639631dff06e7987cb385ad630f9672a24`
is now applied after checksum, apply and whitespace checks. The new Raft
helper validates canonical bootstrap/applied/snapshot metadata from the exact
supplied paired view, using one caller-owned workspace grant and preserving
original failure custody. The existing bootstrap manifest and decoder move
from Engine to Store without changing their format. The proof distinguishes
reconstructed older application state from newer durable coverage and retains
the complete actual identity. It does not authenticate body chunks, retain
the native view, publish primary objects or enable document eviction; those
remain producer responsibilities. The new **728-file** qualification starts
with eight focused identity, failure and allocator tests, then affected Raft
and Engine bootstrap regressions, caller checks, Clippy and formatting.

`c04-selected-application-proof.log` compiles and passes both isolated
allocation tests, but all six storage fixtures stop during initialization:
the new fixture omitted the required paired Raft node/group identity rows.
The runner exits **101** after **36.53s**, with **728/728 hashes matching**.
The production identity guard correctly rejects this setup before selection.
The fixture now includes `initial_storage_identity(1, "selected-proof")` in
the same initial custody batch as its bootstrap commitment. No production
guard, limit or assertion changes. `c04-selected-application-proof-initialized.log`
then passes all **eight** tests in **18.17s**, exit **0**, with **728/728
hashes matching**; compilation takes **11.40s**, tests **6.62s**. Affected
Raft/Engine regressions and caller/lint/format checks remain in progress.

`c04-selected-application-raft-regressions.log` passes all **34** selected
Raft regressions in **1949.42s**, exit **0**, with **728/728 hashes matching**.
Tests take **1949.16s**. This includes the unchanged 100,000-row authenticated
uncommitted-tail fixture, both recovery passes, canonical custody streaming,
snapshot coverage and atomic publication regressions. The long-running tail
test made CPU progress and completed without a restart, reduced workload,
increased budget or timeout change. These are correctness checks, not a
production performance measurement. The same frozen selection proceeds to
Engine bootstrap tests and caller/lint/format gates; C01–C07 remain open.

`c04-selected-application-bootstrap.log` then passes all **seven** selected
Engine bootstrap checks in **139.80s**, exit **0**, with **728/728 hashes
matching**. Compilation takes **1m44s** and tests **35.25s**. The cases cover
canonical manifest rejection, paired identity, corrupt body/custody refusal,
and local/replicated reopen behavior. Caller checks and lint/format gates are
still running on that frozen selection.

`c04-selected-application-callers.log` passes the Engine/Server all-target
caller check in **131.70s**. `c04-selected-application-engine-clippy.log`
passes Engine/Query Clippy with `-D clippy::all` in **50.55s**; existing audit
dead-code warnings remain. Both exit **0**, with **728/728 hashes matching**.
`c04-selected-application-strict-clippy.log` then exits **101** after
**59.29s**, also with **728/728 matching**. It reports a large selection error
value (including the fixture wrapper), a redundant fixture `Ok(...?)`, and a
test lock that needs a lexical scope before its later await. Formatting did
not run in that queue.

The selection failure now destroys unexposed partial metadata while the
original error and complete peak workspace grant remain alive, then returns
only the original error and grant. This adds no allocation during refusal,
does not shrink failure credit, and preserves borrowed original-error
classification. The regression checks now assert the actual held peak and
absence of successful shrinking. The fixture expression and test lock scope
are repaired, and formatting fixes the earlier fixture identity insertion.
A new nine-test selection reruns all eight proof/allocator cases and the
affected publication test, followed by strict Raft/Store Clippy and formatting.
The original failed run is retained; this repair is not yet qualified.

The repaired selection passes **all nine tests** in
`c04-selected-application-repaired-tests.log`: **18.44s**, exit **0**,
**728/728 hashes matching** (compilation **12.23s**, tests **6.12s**).
`c04-selected-application-strict-clippy-repaired.log` then passes strict
Raft/Store all-target Clippy in **18.10s**, and
`c04-selected-application-fmt.log` passes workspace formatting in **10.88s**.
Both exit **0**, with **728/728 hashes matching**. The earlier 34 Raft and
seven Engine bootstrap passes precede this failure-representation repair;
they are not presented as reruns of that changed source. Existing Engine
audit warnings and the full workspace release gates remain open.

After independently verifying all 728 final source hashes, the next reviewed
patches apply together with checksum, combined apply and whitespace checks:

- Local Control selection and admitted enrollment digest:
  `a45c7d6f497dc7fea414a25f5c639d952ddc77721559857f961afaa8ee9bbe4a`.
  Fixed-role local observations keep their actual immutable document/output
  ownership, and approval decoding/hashing keeps its grant through failure or
  the final compact digest. Existing provisional document-body floors remain.
- Raft application-source lifecycle hooks:
  `2631c0b467e478b1eb0678c3d0e44c3fd1fc24828acde12d05dae52296db8bcb`.
  Prebound startup custody seals consumers, validates reconstruction at serving
  handoff, and requires positive source drain after writers stop. The Engine
  source registry is still a separate unapplied candidate.
- Concrete file-key factory stages and sizing:
  `7c7f6e3ceb589ab72b1c6d7ed2a9210fdb19dc11d5cf3438ce2ad7e13a43ee61`.
  A bounded zeroizing input is read once, quoted at its actual size before
  decoding, then consumed by the same implementation as `FileKeyProvider::open`.
  This adds sizing plumbing; admitted Server factory integration remains open.

The new **734-file** frozen selection begins with the existing and new Store
file-key tests, then Raft source/startup checks, Engine Control tests and
integration, affected Server approval/runtime tests, caller checks, package
Clippy and workspace formatting. No new pass or cache-goal completion is yet
claimed for this batch. Synthetic fixtures are the only key material used.

`c04-file-key-factory-store.log` passes all **eight** Store tests in **51.52s**
(build **49.99s**, tests **1.42s**). `c04-source-hook-raft.log` passes all
**35** selected Raft tests in **137.50s** (build **2m12s**, tests **4.83s**).
Both exit **0** with **734/734 hashes matching**. The following
`c04-control-selection-engine.log` exits **101** in **270.59s**, also with
**734/734 matching**: five of six checks pass. The semantic decoder fixture
expects `invalid tenant incarnation` from Display, but the original typed error
correctly includes its `InvalidArgument` prefix. An equivalent later assertion
for `Corruption` has the same mistake.

The focused test-only repair
`ee272d0cf4bf1fd4de5ac2469f32f90c2008604ece1e85f9222196e04d4fd22c`
asserts the original typed message separately and that the wrapper delegates
Display unchanged. No production code, limits or classifications change.
`c04-control-selection-engine-display-repaired` starts a new 734-file pin and
reruns those six tests before the pending Control integration, Server, caller,
Clippy and formatting checks. The earlier failed evidence is preserved.

The repaired six-test Engine selection passes in **44.31s**, exit **0**,
with **734/734 hashes matching** (build **38.91s**, tests **5.17s**).
`c04-control-selection-integration.log` then passes one of two integrations
and fails the same Display-only mistake in its new missing-installed-topology
assertion, exiting **101** in **14.20s**, **734/734 matching**. The fixture now
checks the typed `Corruption` code and message separately and compares wrapper
Display with that exact original typed error. No production behavior or limit
changes. `c04-control-selection-integration-display-repaired.log` passes both
integrations in **20.00s**, exit **0**, **734/734 matching** (build **5.45s**,
tests **14.44s**). The remaining Server and caller/lint/format checks continue.

`c04-control-selection-server.log` stops at compilation: its migrated startup
call uses `ControlPlane` without an in-scope import (`E0433`, runtime.rs).
The runner exits **101** after **236.52s**, with **734/734 hashes matching**;
no Server test result is claimed. The call now uses the existing fully qualified
Engine Control type. Review also identifies the same typed-error Display
expectation in the new approval fixture; it now separately checks the message
and delegated original Display before its first test run.
`c04-control-selection-server-repaired` starts a fresh source pin and reruns
the selected Server checks, then the remaining caller/lint/format queue.

`c04-control-selection-server-repaired.log` passes all **six** selected tests
in **521.75s**, exit **0**, with **734/734 hashes matching**. Compilation takes
**7m41s** and tests **60.44s**. This includes both concrete approval ownership
checks, both dormant enrollment cancellation/access checks, readiness error
classification, and the real local TLS runtime serving/reopen case. The Apple
linker reports its previously observed compact-unwind section warning; existing
dependency/audit warnings also remain. Caller checks and package lint/format
gates continue; this pass does not qualify the pending source registry or the
complete application cache.

`c04-control-source-hook-callers.log` passes the Engine/Server all-feature,
all-target compilation check in **235.16s**, exit **0**, with **734/734
hashes matching**. Existing Engine audit and dependency dead-code warnings
remain; selected Clippy and formatting checks continue.

`c04-control-source-hook-engine-clippy.log` passes Engine/Query Clippy with
`-D clippy::all` in **111.75s**; the existing audit dead-code warnings remain.
`c04-control-source-hook-strict-clippy.log` passes Raft/Store/Server Clippy with
`-D warnings` in **404.21s**. `c04-control-source-hook-fmt.log` passes workspace
formatting in **12.40s**. All three exit **0**, with **734/734 hashes matching**;
an independent comparison of every final hash also matches. This closes the
selected batch after its recorded fixture/import repairs. Earlier Store/Raft
and Engine tests have their own matching pins; they are not claimed as reruns
of the later unrelated fixture/import edits. Engine/workspace strict-warning
and complete release gates remain open.

The next reviewed routine-read diagnostic patch applies after checksum and
clean apply/whitespace checks:
`e1814f97691e0d8302367075ebf4c90f6858547bb55568ed5dd5ba381b3c8d05`.
Every queued reader preadmits its shared original report before native work.
Known routine body/output capacity failures can release positively disposed
native census custody while their exact immutable error reports and credit
remain alive. Unknown I/O, panic, acquisition or close outcomes remain retained.
Report permission and acknowledgment are atomic and nonblocking; held report
guards do not force cleanup to wait. Final report/credit destruction ordering
uses separate owners, including concurrent last drops. Native begin/fork/table
capacity failures still need a distinct cleanup proof before C01 can close.
The Engine source lifecycle and consuming topology producers remain separate,
unapplied candidates.

The new **736-file** source selection starts focused routine/fork/production
reader checks, then the full Store unit suite because every queued reader's
backing ownership changes, selected Raft proof and Engine worker checks, strict
Store/Raft Clippy and workspace formatting. No pass is yet claimed for this
selection; C01–C07 remain open.

`c04-routine-read-focused-store.log` passes **64 of 66** checks and exits
**101** in **173.15s**, with **736/736 hashes matching** (build **1m08s**,
tests **104.98s**). All seven new report/retirement regressions pass, as do
the selected exact forks, body/output capacity cleanup, unknown close and
production reader ownership checks. Two existing catalog denial fixtures fail:
one no longer reaches its expected typed-decoder admission error, and the
other reaches a registered begin failure without its expected table error.
Their exact injection boundaries are under diagnosis after introducing the
independent report grant. No production fault or fixture-only cause is inferred
from these assertions alone. The full Store suite and remaining queue did not
run after this failure.

`c04-routine-read-catalog-diagnostic.log` runs only those two fixtures on a
separately pinned diagnostic-only selection. Both fail in **41.76s**, exit
**101**, with **736/736 hashes matching** (build **40.57s**, tests **1.10s**).
The first has stage `catalog bytes` and original outer output
`OutOfMemory`, before the typed decoder. The second has native begin
`TransactionError(Core(OwnerFailed))`, before table verification. These
observations establish that the old headroom/ordinal injections select the
wrong allocation boundaries after independent report/native backing admission.

The reviewed test-only repair
`da7db97fe2715e79d5745d89898854a6c9cf9ff1719d39cef25b0148321f059a`
keeps the original **256 MiB / 4,096-slot** provider limits and required failure
semantics. The typed fixture rejects the exact canonical typed-catalog quote;
the table fixture rejects the existing two-byte native table-tag output quote.
Each asserts exactly one targeted refusal; the table fixture additionally
requires a successful native begin before its original Tables error and
retained-child/failed-opening assertions. New fixture wrapper metadata is
preadmitted under the same provider. Temporary diagnostic output is removed.
`c04-routine-read-focused-store-targeted` starts the corrected focused run;
the full Store and remaining dependency checks remain pending until terminal
results. No production error classification changed in this repair.

`c04-routine-read-focused-store-targeted.log` now passes **all 66** focused
checks in **110.56s**, exit **0**, with **736/736 hashes matching** (build
**31.76s**, tests **78.70s**). Both repaired fixtures reach their exact refusal
boundaries and preserve their original diagnostic/census expectations. The
full Store suite has started on the same corrected selection; its result and
the remaining dependency queue are pending.

While the full Store run remains active, independent source review finalized
three **unapplied** candidates for the following Engine/Server qualification:

- Selected-source lifecycle v4,
  `b52e89b6960864a8085f7442290c63c154537eb717c22d0a642c0b84a2ed4020`:
  19 files and 15 prepared regressions. The final refinement rejects an
  in-flight non-frozen covered capture settling after the actual readiness
  handoff; its test uses actual persisted Entry/Bootstrap proofs. Snapshot
  installation and encrypted Reopen are exercised through Database/Raft hooks.
- Concrete topology producer/receiver ownership,
  `bf5ba2e9cf7c31d222b92109afe252b048fcab1cdb4d4cd36357222c67150923`:
  independently reviewed payload/grant transfer through actual proposal work,
  including cancellation and empty-map failure headroom. Membership and
  generic returned-Error ownership remain separate, unqualified corridors.
- Fixed primary serving/journal codecs,
  `594fd7e6f7a5753fbb50a42e9faef5d114b7b25df5682a270dc0e043025adb63`:
  five files, seven fixed layouts and 11 prepared tests. Independent packing
  reproduces each golden digest. The existing primary module remains test-only;
  actual object staging, activation and disk document serving are not claimed.

Their combined read-only applicability/strict-whitespace check passes against
the current repository. No Cargo pass or live installation is claimed for
these candidates. Exact source-Arc deallocation credit and retained-generation
publication room remain open C01/C06 requirements. The full Store run also had
a one-second read-only stack sample of its own test process while a backup
substitution case was slow; that case subsequently passes. The sample is not a
performance qualification or evidence about unrelated processes.


`c04-routine-read-full-store.log` finishes with **618 passed, 13 failed and
four ignored**, exit **101**, in **1,728.74s** (tests **1,723.41s**), with
**736/736 hashes matching**. The dependency queue stops before its Raft,
Engine-worker, lint and formatting steps. Six failures are confirmed obsolete
fixture assumptions: three segment-census assertions omit the standing
file-allocation allowance, two raw-byte scans read a segmented directory as a
file, and one permission check expects file mode on that directory. Their
repairs must retain the current format's full encryption, extent, permission
and ownership checks. Seven writer/capacity cases remain unclassified pending
exact native begin, terminal, rollback and disposal observations; their failing
phases alone do not justify changing production classification.

A reviewed diagnostic-only patch
`b622d27710b1228ce64f9a13d578d1b11e9aa602b6c0632d64950336ba4b61ec`
adds original typed observations to those existing assertion failures without
changing their budgets, stages or pass conditions. The separately pinned
`c04-store736-capacity-diagnostics` run selects only these seven failures.
The independently reviewed early-read acquisition/table cleanup candidate
`4a696cf36e7bf50e05933239fcbb2610d754a12fa24656ec50ea8d80c7fd48db`
remains unapplied and uncompiled; it does not claim to establish any write
rollback or disposal outcome. C01–C07 and release qualification remain open.


`c04-store736-capacity-diagnostics.log` confirms all seven selected failures
in **66.61s**, exit **101**, with **736/736 hashes matching** (build **1m00s**,
tests **5.64s**). Both staging fixtures refuse native acquisition before their
intended row-staging boundary. The other five reach commit with successful
begin/body/outer observations, then retain the original
`CommitError(Io(StorageFull))`; rollback and disposal remain `NotEntered`.
The segmented backend currently admits individual writes and converts this
refusal through an I/O result, so a safe production correction requires a
complete pre-effect transaction-space claim or an independently proved whole
rollback. Matching a generic I/O kind is not sufficient. No write outcome is
reclassified based on these fixtures.

Early-read patch `4a696cf…48db` is now applied after checksum and strict
applicability checks. `c04-early-read-native.log` stops at compilation after
**24.23s**, with **736/736 hashes matching**: two existing closed-fork test
assertions still expect the old raw error type. Their repair inspects the exact
original `DatabaseClosed` error and additionally asserts that it has no clean
capacity witness. The corrected selection starts
`c04-early-read-native-callers-repaired`, followed by the selected Store reader
checks; no pass is yet claimed.


`c04-early-read-native-callers-repaired.log` passes **13/13** native fork and
acquisition checks in **39.43s**, exit **0**, with **736/736 hashes matching**.
The following Store selection passes **70/71**, exit **101**, in **214.50s**
(build **2m00s**, tests **93.72s**), with **736/736 matching**. Its sole failure
is the new missing/wrong-typed-table fixture: the physical group still has its
Prepared envelope, so Existing opening correctly refuses before any native
table observation. The fixture now deliberately publishes the actual physical
Ready envelope around its malformed native table set before close/reopen. No
native error observation or cleanup permission is fabricated.

The independently reviewed test-only disk-layout migration
`a9627793dc8f10f902484d9fddcbc001a09d6bd78a5f3f8b052bccdeaddb4f7c`
is also applied. `c04-store-layout-and-early-negative-repaired.log` passes all
**seven** selected checks in **104.39s**, exit **0**, with **736/736 hashes
matching** (build **46.68s**, tests **57.60s**). This covers the six confirmed
layout/accounting mismatches and both real missing/wrong-typed table branches
within the repaired new reader test. The five write-commit capacity failures
remain open; the full Store suite is not passing.

The reviewed staging-injection fixture patch
`9eaf4e0fe0d283ebed8bc7550b7063f93240a8f170c1d140f7fe4030c63234ed`
is now applied. A test-only semantic scope targets the actual binding insert
on its exact installed provider after begin/table verification; both native
chunk and exact fallback reservations are refused and recorded. Fixed fault
metadata is preclaimed under the same **256 MiB / 4,096-slot** limits, scoped
to its originating thread and restored on unwind. Existing installed-workflow,
typed denial, real abort/disposal, full-refund and retry assertions remain.
`c04-binding-staging-targeted` selects the binding writer regressions plus the
complete-install staging failure; selected Raft proof checks follow. Results
remain pending.


`c04-binding-staging-targeted.log` stops at compilation after **40.26s**, exit
**101**, with **736/736 hashes matching**. A fixture helper removed with the
old headroom measurement still serves a later owner-failure test. Restoring
that exact helper changes no assertions or production behavior.
`c04-binding-staging-targeted-helper-repaired.log` passes **8/8** binding
writer/install checks in **72.63s**, exit **0**, with **736/736 matching**
(build **1m07s**, tests **5.44s**). The two formerly premature denials now reach
actual row staging and exercise successful abort/disposal and retry.
`c04-early-read-raft-proof.log` then passes **8/8** selected proof checks in
**99.60s**, exit **0**, with **736/736 matching** (build **1m26s**, tests
**13.34s**). Native/Store/Raft strict Clippy and workspace formatting start on
this later selection. These focused passes do not close the five outstanding
segmented write-capacity failures or the full Store/release gates.


`c04-early-read-strict-clippy.log` passes Native/Store/Raft all-feature,
all-target Clippy with **`-D warnings`** in **49.07s**; the workspace format
check passes in **7.72s**. Both exit **0**, with **736/736 hashes matching**.
`git diff --check` also passes. These close the selected early-read and fixture
qualification checks, not the still-failing full Store or release gates.

A separate unapplied native transaction-space planning draft has strict static
applicability and formatting checks but no compilation/runtime result. Its
segment/arena arithmetic compares planned ranges to actual writer-state
positions in prepared tests. Its canonical mirrored-root helper validates exact
root identity without reentering a group lock. The complete installed disk
claim, consumption and settlement corridor remains under implementation; no
write-capacity outcome is reclassified. Independent static modeling finds that
the current half-byte directory splitter can produce a three-entry/one-entry
split with highly unequal separator widths. A native regression and isolated
repair are being prepared before assuming logarithmic height growth or closing
large-batch space policy. No model-only result is reported as native execution.


The actual native regression now reproduces that defect:
`c04-directory-split-red.log` fails **0/1** with **“level 0 split 3+1”** in
**21.08s**, exit **101**, with **737/737 source hashes matching**. The test-only
artifact is `57cd432531951cc4e7ef69e6ffb1bb36715ee687d54341d71fb77777567a3aad`.
The independently reviewed repair
`b31507724aab2afe72711910558b55a738a8935182e45a7c6b7de1819ac7a7a5`
tracks the exact remaining record count and preserves at least two records on
each side of a split. It changes neither encoding nor the bulk builder and
adds no allocation. `c04-directory-split-repaired.log` passes **84/84** directory
checks in **69.04s** (build **43.39s**, tests **25.37s**), exit **0**, with
**737/737 matching**. Coverage includes descending maximum keys, mixed-width
separator growth during deletion, root collapse and old immutable snapshots.
The complete native test suite is running separately as
`c04-directory-split-native-full`; no full-suite pass is yet claimed. The
transaction-space bound still requires independent proof and qualification for
arbitrary existing trees, including unary branches left by deletion. The five
Store write-capacity failures and all C01–C07 remain open.


`c04-directory-split-native-full.log` completes successfully in **643.53s**,
exit **0**, with **737/737 hashes matching**: **459 unit tests**, one cache
allocation case, four commit-allocation cases, nine crash-recovery cases, nine
owner-fencing cases and eight rollback cases. The large allocation integration
selection takes **549.39s**; its original workload and budgets are unchanged.
There are no native documentation tests. This is the full native package test
suite, not a full Store or workspace release pass.

A further actual-mutator regression is applied from
`79c44b6d0441c13abf2489cf8472e781caf88179a62c25d97c849d6c66af394d`.
It starts with a positively observed sparse tree with unary nonroot paths,
executes 351 edits through collapse and regrowth, and compares each prefix with
the independently derived historical-lineage bound. Its selected test,
Native/Store/Raft strict lint and formatting are queued separately. The revised
unapplied native planner `bcdf662d…021e3` uses that checked logarithmic-bin bound
and includes canonical per-file native-header minima. It is independently
reviewed but remains uncompiled and does not yet reserve or consume disk quota.


`c04-directory-sparse-bound.log` passes its actual sparse-tree regression in
**6.76s** (test **1.60s**), exit **0**, with **737/737 matching**. Native/Store/Raft
strict all-feature/all-target Clippy passes in **20.81s**, and workspace formatting
passes in **6.78s**, both exit **0** with every selected hash matching. This
qualifies the split repair and its separate sparse-history regression. The
actual scalar planner remains unapplied pending the installed claim foundation.

Five previously frozen and independently reviewed artifacts are now integrated:
source lifecycle v4 (`b52e89b6…4020`), admitted topology producers
(`bf5ba2e9…23`), primary fixed codecs (`594fd7e6…adb63`), exact canonical metadata
capacity (`bbe58231…f9f`) and encrypted primary staging (`97b381e5…58b8`). All
**44/44** combined changed files match the separately composed review tree.
The new selection contains **752** source/config files. Qualification starts
with Types canonical JSON in both normal and preserve-order configurations,
then Engine source/topology/primary tests and the explicit Engine preserve-order
schema-staging case. No compilation/runtime result is yet claimed on this
selection. Primary staging remains under the dormant test-only primary module:
real encrypted chunks, immutable reads and positive fresh-attempt cleanup do not
yet implement ordinary durable document/index serving. C01 strict outer-allocation
credit tails, C06 retained-history publication headroom, the five Store
write-capacity failures and all C01–C07/release gates remain open.


The **752-file** Types canonical selections pass **7/7** each: default in
**7.49s**, preserve-order in **33.02s**, both exit **0**, every hash matching.
`c04-source-topology-engine.log` then stops at compilation in **79.77s**,
exit **101**, **752/752 matching**: the SourceFailure wrapper's original
`dyn Error` provides both Debug and Display formatting. An explicit
`std::fmt::Display::fmt` call repairs that ambiguity while preserving its
actual original source.

`c04-source-topology-engine-display-repaired.log` stops at test compilation
in **185.26s**, exit **101**, with **752/752 matching**: the prototype's
TenantEngine extension was outside the module that owns its five private
fields. Its PrimaryApplyGuard and constructor now reside in the owning state
module under `cfg(test)`, with private fields and immutable roots/scope
accessors. The stage still holds an exclusive continuous mutable borrow of
the real guard; no caller-supplied lock or public authority constructor is added.

`c04-source-topology-engine-authority-repaired.log` compiles and runs **44**
selected tests: **23 pass, 21 fail**, test **25.73s**, runner **305.06s**, exit
**101**, with **752/752 matching**. Every failure is the shared fixture's
`tenant needs an administrator` rejection before the intended source/staging
behavior. Its initial and wrong-incarnation snapshot fixtures now use a valid
synthetic owner grant, matching existing fixture practice without weakening
production validation. The same selection reruns separately as
`c04-source-topology-engine-admin-fixture-repaired`. Existing staged audit-job
dead-code warnings remain untouched. No Engine pass is yet claimed.


`c04-source-topology-engine-admin-fixture-repaired.log` passes **44/44**
selected Engine tests in **101.33s** (tests **81.66s**), exit **0**, with
**752/752 source hashes matching**. This qualifies the selected source lifecycle,
topology input, primary codec and encrypted staging behavior. The explicit
Engine preserve-order staging case and maintenance/bootstrap/publication/control
selections run separately; no ordinary primary serving or release completion is
claimed.


`c04-source-primary-canonical-preserve-order.log` passes the explicit Engine
schema/archive staging case with **1/1** tests in **196.97s** (tests **3.73s**),
exit **0**, with **752/752 matching**. This checks exact canonical metadata
identity with `serde_json/preserve_order` enabled at the Engine boundary.

The installed transaction-claim foundation, native scalar planner, scratch
claim and raw filesystem test adapters are assembled in a separate temporary
review tree. Independent static review required three installed fixes: fence
actual protected-root corruption, prevent removal of a claimed parent even for
zero-file reservations, and preflight the complete namespace-counter range.
The fixture decoder now uses its actual admission provider inside the allocator
measurement. Focused regressions accompany those changes; none has yet run.
No generic I/O `StorageFull` is reclassified, and the five recorded Store
commit-capacity failures remain open pending actual activation and testing.


`c04-source-topology-maintenance.log` runs **10** selected checks: **9 pass,
1 fails** with an unlabelled `deadline has elapsed`, in **164.40s** (tests
**162.79s**), exit **101**, **752/752 hashes matching**. The failed case is
`admitted_full_backup_cancelled_caller_retains_exact_state_stream_producer_until_release`.
The existing test has distinct producer-entry and shutdown waits; this output
does not establish which boundary expired. Its original durations remain
unchanged. Later bootstrap/publication/control queue entries did not run.

Seven reviewed storage artifacts are now applied: installed claim foundation
`c15cccad…37e`, native planner v3 `6afbeb38…bfd0`, minimum regression
`80eb4016…998`, actual directory-bound test `f1f611a9…79b`, three-finding repair
`0444d271…6a5`, raw fixture v2 `78d91e4b…4e0` and scratch claim
`2c1fbaf7…790`. All **50/50** composed changed files matched before compilation.
The new selection contains **764** source/config files. Native commit activation
remains unapplied; the new claims do not yet change ordinary commit admission.
`c04-transaction-foundation-native.log` stops at a missing test-only `ReplayStart`
import in **4.18s**, exit **101**, with **764/764 matching**. The direct import is
repaired and the same selection reruns with a fresh evidence label.


`c04-transaction-foundation-native-import-repaired.log` passes **10/10** native
space-planning checks in **15.02s** (tests **1.13s**), exit **0**, **764/764 hashes
matching**. These include actual segment/arena append comparisons, mirrored-root
selection, canonical header minima and real mutation bounds through sparse
history. They qualify planning only; ordinary commit activation is still absent.
The backup producer deadline diagnostic `3e0544f1…274e1` is applied after this
native run. It exposes early caller completion and identifies the existing
15s/5s/30s waits without changing them. Installed/scratch claim tests now run
separately against the updated selection.


`c04-transaction-foundation-store.log` stops at compilation in **20.05s**, exit
**101**, **764/764 matching**: two capacity expressions borrowed the guarded
State while mutably borrowing its ledger fields. Evaluating the same checked
counts first repairs the borrow overlap. The repaired run
`c04-transaction-foundation-store-borrows-repaired.log` compiles and runs **25**
cases: **20 pass, five fail**, **27.01s** (tests **1.99s**), exit **101**,
**764/764 matching**. All five failures are a real scratch filename construction
panic: the 15-byte prefix was copied into a 14-byte slice. The buffer length,
hex offsets and terminating NUL now derive from the prefix constant. The same
25-test selection reruns without changing its limits or assertions.


`c04-transaction-foundation-store-name-repaired.log` passes **25/25** installed
NodeDisk/group and encrypted scratch claim tests in **9.44s** (tests **1.77s**),
exit **0**, with **764/764 matching**. Coverage includes real quota transfer,
reusable descriptor rights, pristine cancellation, actual corrupt roots,
namespace ownership, partial native acquisition and retained original failures.
These are foundation tests; their run precedes native activation.

Ordinary native commit activation `aa66ab21…8921` is now applied, together with
six actual public-transaction regressions `44e8a165…4d7c`. Reservation occurs
before private writes; a complete private prefix must settle before exact
prepared-log rollback, and durable root publication precedes final claim
settlement. The durability observer selects from a crash copy so the test cannot
synchronize the original image. Planner modules are now production code. The
**765-file** qualification starts with the six orchestration cases, then the
five original Store capacity failures. No activation runtime pass is yet claimed.


`c04-transaction-activation-native.log` passes **6/6** actual native/public
transaction cases in **8.28s** (tests **0.03s**), exit **0**, **765/765 matching**.
`c04-transaction-activation-store-denial.log` passes **5/5** previously failing
installed Store capacity cases in **12.67s** (tests **4.55s**), exit **0**, every
selected hash matching. These verify retryable pre-effect commit refusal and
retirement/retry across the existing catalog, singleton, binding and table
paths. They do not reclassify entered I/O failures: the native tests separately
retain original raw StorageFull/UnknownCommit errors and crash-selected versions.
The complete native package suite now runs on this selection. Full Store,
backup deadline diagnosis, strict lint and release qualification remain open.


`c04-transaction-activation-native-full.log` passes the complete native package
suite in **218.56s**, exit **0**, with **765/765 hashes matching**: **475 unit
cases**, one cache-allocation case, four commit-allocation cases, nine crash
cases, nine owner-fencing cases and eight rollback cases. There are no ignored
native cases or documentation tests. Commit allocation takes **187.56s** with
the original 65,536-row/40 MiB workloads, admission thresholds and 4 KiB slack.
This qualifies the selected native package, not full Store/Engine or whole-runtime
memory. The failed backup-cancellation test now runs with its added boundary
diagnostics and the activated claim path.


`c04-backup-producer-deadline-diagnostic.log` fails **0/1** in **132.72s**
(tests **5.52s**), exit **101**, **765/765 matching**. The new diagnostic exposes
an early backup caller `UnknownOutcome` before actual state-stream producer
entry, not an elapsed producer/shutdown wait. The public message reports that
admitted publication did not release complete proof. A test-only original-error
and Raft-metrics diagnostic (`c1e9a0bb…e84`) is applied to distinguish the underlying
failure; production responses and deadlines remain unchanged.

`c04-transaction-activation-strict-clippy.log` fails in **28.30s**, exit **101**,
**765/765 matching**, for an eight-argument file-effect helper, the enlarged
inline group phase and one nested conditional. The helper now groups its scalar
execution inputs, and the conditional is collapsed. The phase deliberately stays
inside preadmitted group backing, with a documented local large-enum exception;
boxing during an ownership transition would add a fallible allocation. The
repaired strict all-feature/all-target Native/Store check passes in **14.05s**,
exit **0**, **765/765 matching**. These source changes postdate the full native
run; full Store and affected-path verification remain open.


`c04-backup-publication-original-diagnostic.log` fails **0/1** in **31.47s**
(tests **5.30s**), exit **101**, **765/765 matching**. The underlying public
error is `write task failed`; Raft is stopped on a retained apply failure at
log index 2 with index 1 last applied. This evidence rules out attributing the
failure to the producer-entry timeout. A test-utils-only borrowed inspection of
the existing original apply slot (`a1e8cadb…fc80`) now exposes its actual cause
without draining or moving custody. The exact case reruns separately.

The workspace format check initially fails in **8.85s**, exit **1**, on three
format-only changes (import ordering and two line wraps). After those repairs,
`c04-transaction-activation-fmt-repaired.log` passes in **4.03s**, exit **0**;
each run has **765/765 matching**. The later retained-apply diagnostic is not
included in that formatting result.


`c04-backup-retained-apply-diagnostic.log` fails **0/1** in **108.98s**
(tests **5.55s**), exit **101**, with **765/765 matching**. The borrowed
retained original is `ResourceExhausted: document source retention budget
exhausted`. Source preparation fails before the publication callback: ordinary
backup/proposal admission does not reserve the stricter mandatory successor
source capacity. The existing backup intent and admitted Raft entry prevent a
claimed rollback, so public `UnknownOutcome` remains unchanged. This is an
admission defect, not a producer-entry timeout or authorization mismatch. No
exact byte, slot or RSS deficit was measured; the original error identifies
the concrete admission route. Correcting prospective source funding remains
open without larger budgets or longer deadlines. The full Store suite now
runs against the 765-file selection including all transaction-claim repairs.


`c04-transaction-activation-scripts.log` runs **286** Python tests and fails
with **three fixture errors** in **88.47s** (tests **87.657s**), exit **1**.
The selected 765 Rust/Cargo/smoke-script hashes match; that selection does not
pin the complete Python source. The acceptance fixtures attempted admission
without first creating their required canonical journal. Their existing helper
now calls `attempt_index.create` with a synthetic fixed journal/host identity;
production validation and rejection assertions are unchanged.
`c04-transaction-activation-script-fixture-repaired.log` pins all **45 Python
source files**, passes **29/29** acceptance tests in **2.22s** (tests **1.813s**),
exit **0**, with **45/45 matching**. The complete Python suite reruns on this
same explicitly selected script source.


`c04-transaction-activation-store-full.log` completes **665** Store cases:
**660 pass, one fails, four subprocess helpers are ignored**, in **777.79s**
(tests **758.58s**), exit **101**, **765/765 matching**. The remaining failure
is the exact settled extent assertion in
`admitted_growth_pins_the_newest_segment_and_capacity_denial_has_no_effect`:
observed **5,271,552** bytes versus expected **6,320,128**. The five original
ordinary commit-capacity failures and the prior staging/layout failures pass.
The 1 MiB extent difference is being traced against the standing allocation
allowance; no relaxed assertion, larger budget or production correction is
claimed yet. This is not a complete Store pass.

The independently reviewed source allocation-tail foundation is now applied.
Original artifacts are source handles/binding `e5e2dd1f…8bd5`, canonical opaque
`DrainIssueRef` `d1fd03af…fbd9`, and paired original-failure owner
`6ccdb933…b5fb`. The first two compose as `8345cda6…addd` with the remaining-gap
comment updated. A final comment names all concrete source owners.
Paired strong/weak handles retain real source credit through final allocation
retirement; their credit Arc frees before its reservation refunds. The actual
Raft hook moves its source out of the erased binding Box before releasing it.
The public diagnostic handle preserves exact error identity, prevents raw Weak
escape and frees its issue Arc before destroying the original error.
Seven Engine allocator-boundary cases and a Types concurrent-final-drop test
are included; they are not yet passing evidence. Enclosing anyhow boxes and
report/collection allocations remain open accounting obligations. No C01–C07
closure is claimed. Qualification starts against **768 Rust/Cargo/smoke files**.


`c04-transaction-activation-scripts-repaired.log` passes all **286 Python
cases** in **66.32s** (tests **66.048s**), exit **0**, with **45/45 matching**
script source hashes. `git diff --check` also passes before the source-tail
qualification. These do not substitute for Rust or release acceptance.

The initial source-tail Types checks pass on **768/768 matching**:
`c01-source-tails-types.log` **2/2** in **28.18s**;
`c01-source-tails-allocator.log` **1/1** in **21.03s** (test **0.01s**);
`c01-source-tails-opaque-doc.log` **1/1** compile-fail boundary in **3.92s**
(test **0.39s**). The allocator case observes actual system deallocation before
original error destruction, with raced final clones. Engine owners and the
binding allocator cases are not qualified by these Types results.

The Store test-only correction `9bbff97b…8421` now records the created empty
segment's exact initial extent and checks `before - initial + final` after
settlement. Its initial standing allowance is **1,048,576** bytes; final charge
is **1,056,768**, giving the actual **5,271,552** total. Physical allocation,
file pinning, no-effect denial, budgets and production accounting remain
unchanged. The exact case reruns on the later 768-file selection.


`c04-segment-standing-allowance-repaired.log` passes the exact remaining
Store extent case **1/1** in **106.05s** (test **0.14s**), exit **0**, with
**768/768 matching**. This later selection includes diagnostic-handle changes;
the preceding 660-pass full Store run is not recast as a full pass for this
source. Engine source/allocator cases, Raft source custody and workspace caller
compilation now run sequentially on the warm Cargo lane.


`c01-source-tails-engine.log` fails compilation in **191.37s**, exit **101**,
with **768/768 matching**: one local-startup fixture still compared paired
Cell handles through `Arc::ptr_eq`. It now uses `CellRef::ptr_eq`. The new
Strong identity helper is test-only while all its existing consumers are
test-only. The unused top-level Arc import in `security_audit_jobs.rs` is removed
as the direct consequence of its canonical `DrainIssueRef` return-type update;
its previously staged substantive code and other existing warnings are unchanged.
The focused Engine run retries under a new evidence label. The initial queue
stopped before Raft and workspace caller checks; no Engine test pass is claimed.


`c01-source-tails-engine-callers-repaired.log` fails compilation in **75.91s**,
exit **101**, **768/768 matching**. Moving Arc out of the production imports
exposed six audit fixture uses inherited through `super::*`; the same Arc
import now lives explicitly in that test module. This is the corresponding
canonical-API test import repair, not suppression of the three pre-existing
audit dead-code warnings. The Engine selector retries again; no runtime
case was executed by either failed compilation.


`c01-source-tails-engine-test-import-repaired.log` passes **29/29** Engine
cases in **206.90s** (compile **1m41s**, tests **105.55s**), exit **0**, with
**768/768 matching** source/config hashes. This includes all seven actual
allocator-boundary cases, 15 selected-source lifecycle cases and seven primary
staging cases. The source, native view, actual Raft binding and original failure
owners retain charges until allocation retirement, including weak tails and
concurrent final drops. Existing unrelated audit and fixture warnings remain.
Raft custody and workspace-wide callers are not qualified by this Engine run.


`c01-source-tails-raft.log` passes all **11/11** source-custody cases in
**113.10s** (tests **0.01s**), exit **0**, **768/768 matching**. Workspace
caller and lint qualification remains open for that source.

The reviewed prospective selected-source foundation is applied from immutable
Raft/Authority patch `4e8e7e66…a4724` and Store/Engine patch `5e2cf0a0…0192`.
All 23 disjoint before/after file hashes and strict patch checks match. The
actual producer supplies record identities and complete canonical metadata
quotes before publication; Engine owns the source grant and queued read report
before commit. Planned capture verifies exact domains and record bytes before
a candidate generation is visible. Queued activation atomically rejects a
recovered reader that already selected an older root. Existing access checks,
budgets and deadlines are unchanged. Native snapshot capacity is still acquired
after publication; permanent current/next lanes, history funding and the
snapshot-installation handoff remain open. These changes are not yet runtime
evidence that the backup failure is fixed. Qualification starts with the new
**771-file** selection.


`c06-prospective-selection-raft.log` runs five cases with **four passing and
one failing**, **35.44s** (tests **6.58s**), exit **101**, **771/771 matching**.
The actual callback, selected-record/domain mismatch, covered-entry replay and
covered-snapshot cases pass. The wire-shape quote fixture fails during decoder
preflight with `invalid type: byte array, expected a bounded canonical metadata
record at line 1 column 26`. This is being traced before any change to accepted
metadata shapes or quote coefficients. The sequential queue stopped; the six
independent Store queued-view cases now run separately.


`c06-prospective-selection-store.log` passes all **six** queued paired-view
cases in **36.51s** (tests **5.71s**), exit **0**, **771/771 matching**.
This includes exact queued owner identity, post-publication root capture,
revoked domain access, no-registration capacity denial, original unknown
cancellation custody, and rejection of a recovered early-begun reader.
These checks do not reserve a native snapshot pin before publication.


The number correction `e179ef1f…34b6` is applied after independent source
review against the vendored arbitrary-precision parser. Preflight counts its
bytes-channel synthetic number marker; allocation-free prospective quotation
also counts the extra two nodes and numeric-string backing for decimals,
exponents and out-of-range integers. Literal marker object keys retain their
existing semantics. The original failure fixture is unchanged and a separate
number-boundary/4,096-digit case prevents unrelated overquotation from hiding
an underestimate. No quote coefficients or configured budgets were raised.
`c06-prospective-selection-raft-number-repaired.log` passes **6/6** cases in
**24.55s** (tests **7.42s**), exit **0**, **771/771 matching**. Engine, backup
and workspace caller checks follow on this corrected source.


`c06-prospective-selection-engine.log` fails compilation in **133.07s**,
exit **101**, **771/771 matching**. Two lifecycle fixtures still bound
RootPreparation immutably after capture began consuming its queued reader.
Only those `covered`/`exact` local bindings now use `mut`; the retry has a fresh
evidence label. No Engine runtime case, backup check or caller check ran in
this stopped queue.


`c06-prospective-selection-engine-mut-repaired.log` passes **31/31** cases
in **206.02s** (tests **97.95s**), exit **0**, **771/771 matching**. All
seven allocator-boundary checks and seven encrypted staging cases pass, along
with selected-source lifecycle and the three prospective callback cases. Real
producer source denial preserves the prior durable cursor and candidate
generation, retains its original refusal and permits a later funded retry.
Missing or repeated preparation cannot publish the candidate. The original
backup regression runs next with its unchanged configured limits/deadline.


`c06-prospective-selection-backup.log` **fails 0/1** in **7.19s** (tests
**6.36s**), exit **101**, **771/771 matching**. The actual retained original
still reports document-source retention exhaustion, now inside the required
prospective publication callback. The Raft log is admitted but application
publication refuses; public UnknownOutcome remains correct. Reducing the
unconditional metadata floor did not fix this regression. No larger budget,
timeout or relaxed assertion is introduced. A temporary test-only diagnostic
records the exact requested/charged bytes, resident reading, cache/protected
headroom and origin/slot counts at refusal; it is preserved as an artifact and
will be removed after that focused run. Permanent current/next source and
history funding remain open.


`c06-backup-source-headroom-diagnostic.log` reproduces **0/1 failure** in
**55.95s** (tests **4.72s**), exit **101**, **771/771 matching**. The exact
refusal is the **8,192-byte Cell reservation**, before metadata quotation is
reserved. Already charged **432,668,443** bytes plus the request, protected
ordinary work **134,217,728** and cache-work headroom **67,108,864** requires
**634,003,227**, exceeding the **588,277,190** cap by **45,726,037**.
The sample is usable and unpressured: resident **48,054,272**, high water
**68,719,476,736**; **33/4,096** live slots plus the requested/protected slots
would require only **102**. This observed failure is the byte/headroom equation,
not exhausted slots or RSS pressure. Existing source charges are just **10,136**
bytes across three slots. The temporary fixed-field diagnostic is removed by
its exact before/after hash; original admission code is restored. Source
publication capacity must be owned before ordinary operations can occupy this
room; quote reduction alone cannot provide it. No headroom is reduced and no
configured cap is increased.


The selected-primary reader **v2** `2028aca8…c6bb` and reviewed fixed-object
staging `9d32335d…ffb7c` are applied with exact before/after file checks and
strict patch validation. Reader v1 is superseded without being applied. The
reader keeps original failures typed and noncloneable, with no Error-trait
blanket boxing route. It binds selector, catalog, manifest, pages and overflow
to one encrypted snapshot, checks current access even for no-I/O misses, and
preserves restored version zero. The staging extension journals fixed pages
and manifests with their exact object/counter updates in one four-operation
transaction; bounded abort rejects impossible progress and malformed local
page framing before removing journals. Fourteen new reader/codec/allocation
checks and six fixed-staging cases are prepared. These remain **cfg(test)**
components: production resident adapters, atomic primary selection, transitive
reference validation, disk indexes and full-fitting-cache integration remain
open. The combined source/staging qualification starts with **776** pinned
Rust/Cargo/smoke files; no runtime pass is claimed yet.


`c04-selected-primary-reader.log` fails compilation in **48.27s**, exit
**101**, **776/776 matching**: the reader fixtures live in the source registry
test module and could not import three namespace constants restricted to the
primary-tree parent module. The canonical internal constants now have crate
visibility; no format, ownership, access check or production export changed.
The same selector retries with a fresh evidence label. No runtime case ran.


`c04-selected-primary-reader-namespace-repaired.log` passes **51/51**
cases in **349.15s** (tests **262.69s**), exit **0**, **776/776 matching**.
This includes all 14 new reader/catalog/decoder-allocation checks, six fixed
staging cases, seven existing encrypted staging cases, seven source allocator
cases and 17 source lifecycle/prospective-publication cases. Actual encrypted
old pins, current access changes, zero-version restoration, complete-wire
admission refusal, exact original error/panic retention, journal resumption
and impossible/corrupt cleanup refusal all pass. The two decoder observations
fit their real preclaimed grants and retire measured allocations. These are
component checks; production document/index/cache cutover and the independently
failed backup-publication availability gate remain open. Workspace caller
compilation, Clippy and formatting now run sequentially on this selection.


`c04-selected-primary-callers.log` passes all-feature/all-target workspace
compilation in **248.25s**, exit **0**, **776/776 matching**. Existing Engine
audit/test and vendored rmcp dead-code warnings remain. The following
`c04-selected-primary-clippy.log` fails in **150.79s**, exit **101**,
**776/776 matching** on one collapsible nested conditional in Raft
selected-metadata scalar quotation. It is changed to the equivalent let-chain;
no quote, codec or configured limit changes. Workspace Clippy retries under
a fresh label. The stopped queue did not run formatting, and this Clippy
command denies `clippy::all`, not all compiler warnings.


`c04-selected-primary-clippy-scalar-repaired.log` fails in **58.07s**,
exit **101**, **776/776 matching**, on two further Engine style lints:
the last selected handle's nested retirement condition and an equivalent
reservation-origin boolean match. Both are simplified without changing
release ordering, origin classification or admission equations. A fresh full
workspace Clippy run follows; the earlier 51 runtime cases remain evidence
for their recorded pre-style-repair source, not a final-source rerun.


`c04-selected-primary-clippy-core-repaired.log` fails in **337.71s**,
exit **101**, **776/776 matching**. Its 21 diagnostics include intentionally
inline read failures/routes, two equivalent style rewrites and a test mutex
whose explicit drop Clippy did not recognize before await. The mutex now ends
in a lexical scope, the count/conditional expressions are simplified, and
targeted size-lint exceptions explain why these fixed inline owners avoid
adding separately admitted heap allocations. No Error-trait boxing conversion
is introduced. Existing unrelated warnings remain unchanged.

The independently reviewed fresh-catalog artifact `95903a9d…4c57f` is applied
with all eight exact after hashes matching before those style repairs. Three
new files define dense membership and bounded construction/cleanup. First
finish binds actual same-pin inventory and Building attempt records; append
and cleanup each use three-operation atomic progress. Nine new tests are
prepared. Production activation, full accepted-producer/transitive closure,
measured growing-count memory and actual crash/restart qualification remain
open. Qualification now includes the catalog plus the affected existing
source/staging/reader cases on the corrected **779-file** selection.


`c04-primary-catalog-and-source.log` passes **60/60** tests in **826.69s**
(tests **656.36s**), exit **0**, **779/779 matching**. All nine new catalog
cases and the prior 51 source/reader/staging/allocation cases pass together,
including real byte/slot refusal, exact same-pin verification, mapping COW
and independently resumed bounded cleanup. The unused catalog re-export is
removed by the subsequent bulk artifact; existing unrelated audit warnings
remain. Runtime growth-memory and actual crash/restart catalog qualification,
production activation and the backup publication-capacity gate remain open.

The reviewed fresh collection builder `8e1f0c5f…c9b18` is applied with exact
seven-file after checks and all pinned dependencies matching. It uses a fixed
64-level frontier and actual staged DTO/page/manifest writes, derives row
versions and totals from the observed stream, and preserves restored version
zero. Typed failures retain independent input/staging/panic owners. Checks
cover quote traversal and chunk writes; serde's internal synchronous scans
are not claimed to have bounded cancellation latency. Eleven new tests are
prepared. This physical builder remains under cfg(test), with no accepted
projection or publication authority.

Review corrected an isolated draft assumption before application: archived
indexed values stream through ordinary serde, and this pinned JSON Map is a
BTreeMap. Existing archive sorter workspace remains zero; direct body-length
counting likewise adds no duplicate sorter charge. Quote tests measure the
actual compiled writer path. No JSON feature, memory limit or headroom changed.


`c04-catalog-bulk-fmt.log` passes whole-workspace formatting in **19.06s**,
exit **0**, **783/783 matching**. The eleven new builder/workspace checks
now run on this selection. A separate deeper-frontier regression remains
in preparation and is not included in this initial selector.


`c04-primary-bulk.log` passes **11/11** cases in **306.34s** (tests
**131.04s**), exit **0**, **783/783 matching**. Actual frontier allocation
and final deallocation stay under their installed grant; refusal precedes
allocation/source visitation, cancellation interrupts a multi-chunk DTO, and
independent callback/source error and panic originals survive. Empty and
two-level live/archive streams preserve observed versions and exact totals.
The compiled writer measurement confirms its actual quote path.

The reviewed deeper-frontier successor `f47259cc…6a08` and native pin
foundation `5497a3c2…0725` are applied with all eight exact after hashes.
The first adds one real encrypted recursive-spill/framing test; it does not
claim accepted-generation semantics. The native change funds actual registry,
pin and rights allocation retirement, and adds protected two-lane tickets
and exact history transfers within the existing fixed registry. Fourteen
new native tests are prepared. Native constructors quote their changed layout;
K=256, cache budgets, headroom and on-disk encodings are unchanged. No public
Core/Database/Store protected capture or source-byte guarantee is activated.
The next qualification pins **787** files; earlier passes remain evidence
for their exact recorded selections.


`c06-native-protected-pins.log` passes **489/489** native unit tests and
**31/31** integration tests in **808.49s**, exit **0**, **787/787 matching**.
The integration cases cover cache and commit allocation, crash recovery,
owner fencing and transaction rollback. All fourteen added rights/allocation
cases pass. This qualifies the native foundation and ordinary allocation
retirement changes; it does not qualify Core/Database/Store protected capture,
source-byte lanes, history-byte handoff or backup publication availability.
The deeper real encrypted primary-frontier regression now runs separately
on this same source selection.


`c04-primary-bulk-frontier.log` passes the exact deeper-frontier case
**1/1** in **515.65s** (test **28.27s**), exit **0**, **787/787 matching**.
The actual builder spills recursively during insertion and traverses its 49
leaf, two interior and one root pages; final root collapse adds no object.
The fixture deliberately shares one real archived DTO across generated IDs
to isolate page framing. It does not claim full stream identity, hydration,
accepted projection provenance or production activation. Existing unrelated
audit/test warnings remain. Native strict Clippy follows separately.


`c06-native-protected-pins-clippy.log` fails in **24.95s**, exit **101**,
**787/787 matching**, on one test-only `err().expect()` style lint. It is
replaced with `expect_err()` without changing the cancellation assertion or
native behavior. Strict native lint qualification will run again.

The independently reviewed zero-version consistency patch `c85c07f1…2c8b4`
is applied with four exact after hashes. The Engine and Query index adapters
now accept the version-zero lower boundary already permitted by snapshot and
primary codecs. Engine revision upper bounds, live document identity checks
and replay consistency remain. Two new tests exercise actual index build and
delta preparation plus canonical indexed validation/full restore. Runtime
qualification is pending; this does not close the accepted-producer or
production storage cutover gates.


`c04-primary-components-clippy.log` fails in **386.29s**, exit **101**,
**787/787 matching**, on three test-only lints: two allocator-witness closures
return the deliberately inline typed builder failure, and the catalog capacity
probe spells out ceiling division. Scoped size-lint exceptions retain the real
failure ownership without adding a heap box; the arithmetic uses `div_ceil`.
No runtime storage, admission or configured bounds change. Existing unrelated
warnings remain. The two version-zero regressions and existing mixed-stream
builder case run next on this corrected source.


`c04-zero-version-parity.log` passes **3/3** cases in **126.27s** (tests
**28.48s**), exit **0**, **787/787 matching**. Both added regressions and the
existing mixed live/archive builder test pass. Version zero survives actual
index build, exact old/new delta preparation, indexed snapshot validation and
the full restore validator's runtime index rebuild. Invalid live IDs and
future live/archive versions still refuse. Workspace Clippy retries separately
after the test-only lint repairs; these results do not close storage activation.


`c04-primary-components-clippy-repaired.log` passes all-feature/all-target
workspace Clippy in **163.32s**, exit **0**, **787/787 matching**. This command
denies `clippy::all`; the existing unrelated Engine audit/test and vendored
rmcp dead-code warnings remain. It is not a whole-workspace `-D warnings`
pass. Native strict Clippy and workspace formatting run separately next.


`c06-native-protected-pins-clippy-repaired.log` passes strict native Clippy
(`-D warnings`) in **24.90s**, exit **0**, **787/787 matching**.
`c04-primary-components-fmt.log` passes workspace formatting in **14.37s**,
exit **0**, **787/787 matching**.

The independently reviewed semantic accepted-owner artifact
`1337bd54…6c628` is applied with all seven exact after hashes. It retains the
actual apply guard, previous/final candidate and moved existing changed-ID map
through source capture and visible publication. No new candidate/body/index
funding, receipt authority or primary serving activation is claimed. Six new
semantic cases and existing ordered producer regressions require qualification.
The new selection contains **789** source/config files.


`c04-accepted-owner-semantic.log` fails compilation in **18.89s**, exit
**101**, **789/789 matching**: the recovery owner local named `apply` shadows
the existing reducer function. Renaming that local to `apply_owner` preserves
the intended call and ownership. No behavioral test ran in this attempt.


`c04-accepted-owner-semantic-repaired.log` passes **6/6** new semantic
cases in **135.71s** (tests **4.25s**), exit **0**, **789/789 matching**.
Actual delta allocation, rejection/replay, definition changes, unchanged-epoch
archive placement, scope/position substitution and apply-guard custody pass.
Existing ordered producer and recovery/retirement integration checks follow.


`c04-accepted-owner-mutations.log` reports **13 passed, 1 failed, 1 ignored**
in **10.52s**, exit **101**, **789/789 matching**. The captured-source
corruption fixture sets a document version to zero, which the corrected restore
contract now permits. Whether that fixture also requires independent captured
text-index version consistency is under review; no failure is waived. The
sequential qualification stops before recovery, audit and integrations.

The independently reviewed constructor-owned quote artifact `c0dcd41b…bae52c`
is applied with all 26 exact after hashes. It includes both temporary CachedBytes
workspace copies, provider-token overhead and actual prior-read format ceilings.
Nine prepared tests require runtime qualification. No source pool, prepaid read,
cache activation, byte-limit change or backup availability fix is claimed.


Constructor-owned quote qualification: `c06-source-read-quotes-native.log`
passes **1/1** in **31.82s**, and `c06-source-read-quotes-store.log` passes
**4/4** in **83.10s** (tests **1.07s**), both exit **0**, **795/795 matching**.
Actual native capture requests, encrypted reader retention, key-ID growth
refusal, unknown-provider refusal and zero-cache encrypted read peaks pass.
The four Engine quote cases remain pending.


`c04-zero-version-query-regressions.log` passes all **71/71** Query unit
tests in **35.63s** (tests **3.52s**), exit **0**, **795/795 matching**.
The generic index-adapter lower-bound correction preserves this query suite.
The Engine corruption fixture and ordered-seek lower-bound parity are under
separate review; no broader restore/serving completion is claimed.


`c06-source-read-quotes-engine.log` compiles in **306.86s**, exit **0**,
**795/795 matching**, but its mistyped module selector runs **zero tests**.
It is compilation evidence only. The correct `quote_tests` module runs under
a separate evidence label; no four-case pass is inferred from this attempt.


`c06-source-read-quotes-engine-selected.log` passes **4/4** intended
Engine quote cases in **3.33s** (tests **2.45s**), exit **0**, **795/795
matching**. All nine quote cases have now passed across their three selected
runs. No admission pool or publication-availability claim follows.

The reviewed zero-version follow-ups `da9037db…bc7ec` and
`9f50d599…50c62` are applied with all three exact after hashes. The mutation
corruption fixture now injects a real ID/key mismatch: resident text indexes
do not store document versions, so the old zero case depended solely on the
invalid lower-bound assumption. New real restored-state mutation coverage keeps
Version(0) equality preconditions, receipts and retained text-reader behavior.
Ordered seek now permits zero-version documents while preserving the original
revision upper bound and its distinct positive continuation-revision contract.
The actual admitted worker regression and repaired mutation suite are pending.


`c04-zero-version-consumers.log` passes **8/8** matching zero-boundary
cases in **121.53s** (tests **29.71s**), exit **0**, **796/796 matching**.
The new restored zero-version mutation/text-reader and admitted ordered-seek
worker regressions both pass, alongside existing selected zero-boundary cases.
The repaired complete mutation module and remaining accepted-owner producer
checks now run separately.


The repaired accepted-owner producer checks pass on **796/796 matching**:
`c04-accepted-owner-mutations-repaired.log` has **15 passed, 1 ignored** in
**6.73s**, recovery publication **1/1** in **0.72s**, and tenant audit **5/5**
in **6.05s**; all exit **0**. The explicit 100,000-row capacity cohort remains
ignored under its existing marker. `c04-accepted-owner-route.log` aborts with
**stack overflow / SIGABRT** in **26.47s**, exit **101**, **796/796 matching**.
This is not a passing recovery integration. The existing phase-split fixture
requires investigation; no stack/budget/timeout increase has been applied.
The sequential runner stops before the retirement integration.

Reviewed retained-native artifact `cc93581f…5592c` is applied against the
exact quote dependency with all thirteen after hashes verified. It preowns
real native backing/tickets, captures the actual committed root, and retains
original failures through explicit cancellation/close. Canonical retained
reader, fork, source-request and history disposal now observe actual final
native failure before releasing Database custody. The new API is not activated
in Store/Engine source acquisition and does not prepay source bytes. Nineteen
new cases and the ordinary read/fork/close matrix remain pending.


`c06-retained-native-source-read.log` passes **19/19** new real native
cases in **32.97s**, exit **0**, **801/801 matching**. An unused test-only
Provider import is removed before broader validation. Capture/handoff allocates
no new backing, final native failure remains observable with Database custody,
and committed history exchange stays separate from disposal failures. The
ordinary read/fork/close and relevant integration matrix follows.


`c06-retained-native-matrix.log` reports **507 passed, 2 failed** native
unit cases in **36.31s**, exit **101**, **801/801 matching**. Integrations did
not run. Two earlier destructor assertions expected partial/all lane clearing
after mismatch/poison; strict final rights retirement now intentionally leaves
both lanes occupied in the failed registry. Corrected assertions require both
retained lanes, latched native failure and unchanged epoch, preserving original
error/lease checks. No production cleanup criterion is weakened.

Crash-path and binary-prologue analysis identifies the actual recovery startup
overflow in `scratch_group::Owner::new` through array `from_fn`/`try_from_fn`,
before accepted application. The minimal `af9c91f2…fe715f` change uses const
None initialization of the same inline array; layout, admission and destruction
are unchanged. Only this constructor is changed. Runtime and rebuilt-prologue
qualification remain pending; the default stack and fixture are unchanged.


`c06-retained-native-matrix-repaired.log` passes **509/509** native unit
tests plus **27/27** selected cache-allocation, crash-recovery, owner-fencing
and transaction-rollback integrations in **42.06s**, exit **0**, **801/801
matching**. This includes the nineteen added source-read cases and ordinary
reader/fork/retirement coverage on the repaired source. The unchanged expensive
commit-allocation matrix remains evidence from its prior recorded selection.
Store consumers and changed enclosing read-report layout still require their
selected checks; source-byte funding/activation and C01–C07 remain open.


The retained Store reader matrix passes all **40** selected cases on
**801/801 matching** source, each exit **0**: routine diagnostics **8/8**
(**94.56s**), registered reader forks **7/7** (**2.85s**), paired view forks
**10/10** (**6.57s**), view workspace **3/3** (**5.90s**), retirement owners
**8/8** (**2.12s**), and exact reader quotes **4/4** (**1.96s**). The quote
checks cover the enlarged actual registered reader/report layout. Evidence
labels are `c06-retained-read-store-routine`, `-store-fork`, `-view-fork`,
`-view-workspace`, `-store-owners`, and `-store-quotes`. Engine integration and
the recovery startup constructor candidate remain pending.


`c04-accepted-owner-route-const-array.log` reaches the recovery test without
stack abort but **fails** in **359.78s** (runtime **119.49s**), exit **101**,
**801/801 matching**. The shared lifecycle fixture's physical open reports
`node startup Failed retained registered opening StorageOwnerId { index: 0,
generation: 549 }`; original typed custody diagnostics are under investigation.
The rebuilt binary removes the former FileOwner-array from_fn/try_from_fn
helper frames; Owner::new itself still has a 701,952-byte prologue. This is
confirmation of the narrow constructor change, not a passing recovery case
or a whole-thread peak bound. No stack, budget or timeout increase is applied.


Independently reviewed warm-pin retry artifact `104268dd…0d7e35` is applied
with all four exact after hashes. It preserves real output pin high-water
observations across unfinished automatic/manual passes and individual bounded
pruning items. A released output can request refill after earlier local denial;
unchanged oversized passes still park. Five prepared deterministic regressions
include same-call prune/refuse/release and proof-only no-spin cases. No budget,
cache default, provider headroom or work-limit change is made. Runtime follows.


`c02-warm-pin-release-matrix.log` passes **514/514** native unit tests
and **27/27** selected integrations in **49.30s**, exit **0**, **802/802
matching**. This includes all five new warm-release cases, both drivers,
same-call prune/refuse/release, and unchanged oversized parking. Crash, owner,
rollback and cache-allocation checks also pass; application serving remains open.

Invocation-bound Entry receipt artifact `bfe2a303…aafbd1` is applied with all
twenty exact after hashes. The actual source-enabled Engine Entry path consumes
an opaque receipt bound to its live stack expectation and exact callback plan
before capture/publication. The real sink binds source pair, producer/context,
ordered application and custody effects, and response. Plain publication stays
distinct. No source-byte pool, candidate funding, primary effect verification,
bootstrap/snapshot integration or cache-goal completion is claimed. Runtime
and additional positive CoveredReplay/retirement-field cases are pending.


`c04-invocation-receipt-raft.log` passes **5/5** new encrypted receipt
cases in **156.65s** (tests **5.34s**), exit **0**, **804/804 matching**.
The actual lifetime-generic dyn publisher compiles; identity rejection, reentry,
plan/effect binding and zero-allocation witnesses pass. A redundant test-only
WriteOp import is removed afterward. Positive CoveredReplay consumption and
concrete retirement substitution follow-ups remain prepared work.

Temporary opening diagnostic artifact `d5d32dd7…22e7cc9` is applied to the
lifecycle fixture and a cold failure helper. It only borrows typed original
opening/native/child reports, releases each report lock before the next, and
panics without cleanup, retry, acknowledgment or parameter changes. The next
recovery run will identify the failure hidden by the facade Display.


`c04-invocation-receipt-lifetimes.log` passes all **5/5** intended
compile-fail lifetime/ownership cases in **51.60s**, exit **0**, **805/805
matching**. Follow-up `c25a00d9…01bf3ce` is applied with both exact test-file
hashes. Its two added encrypted cases positively consume changed/empty
CoveredReplay receipts and reject concrete seed/retirement-field substitutions
before effects. Existing Engine quote coverage now reports actual fixed owner
layouts outside its allocation observer. Runtime qualification follows.


The complete selected-application Raft matrix now passes **21/21** in
**24.66s**, and existing publisher custody checks pass **11/11** in **0.73s**;
both exit **0**, **805/805 matching**. Evidence labels are
`c04-invocation-receipt-selection-matrix` and `c04-invocation-receipt-publisher`.
The seven receipt cases include the two added positive replay/retirement-field
checks; earlier selected-proof, plan and allocation witnesses also pass. Engine
source/caller qualification and the typed recovery diagnosis follow separately.


`c04-invocation-receipt-engine-quotes.log` passes **4/4** actual Engine
quote/allocation cases in **411.17s** (tests **1.84s**), exit **0**, **805/805
matching**. The complete enlarged reader/plan shapes remain covered under
the installed provider with unchanged limits. Compiler warnings are the
pre-existing security-audit items; broader source lifecycle tests follow.

The successful quote run records target layouts in bytes: expectation **72**,
challenge **72**, receipt **216**, plan **312**, RootPreparation **456**,
PublicationPreparation **472**, SourceRoots **128**; the constructor-derived
Cell allowance remains **8,192**. These are actual target measurements, not
portable constants or a whole-thread stack peak estimate.


Engine selected-source lifecycle checks pass **17/17** in **21.20s**, and
actual allocation-tail checks pass **7/7** in **6.53s**; both exit **0**,
**805/805 matching**. Labels are `c04-invocation-receipt-engine-sources` and
`c04-invocation-receipt-engine-tails`. Including the four quote checks, all
**28** selected Engine source/ownership cases pass on this source. Missing and
repeated callback rejection, real startup/restore, old-root forks, retained
failures and actual deallocation custody remain covered. This does not close
source-byte standing capacity or the still-failing broader recovery route.


`c04-invocation-receipt-recovery-diagnostic.log` **fails** in **195.29s**
(runtime **174.87s**), exit **101**, **805/805 matching**. This run does not
reach the instrumented opening failure. Instead, original recovery-phase
resolution times out at `recovery_control.rs:2398`, following read-quorum
unavailability during release after a recovery proposal (node 1 follows an
uncommitted term-2 vote, with no current leader). The earlier retained-opening
failure remains undiagnosed, not repaired. No retry/resubmission, timeout, stack
or capacity adjustment is inferred from this run. The sequential qualification
runner stops before retirement integration.


Required Engine receipt callers pass on **805/805 matching** source, all exit
**0**: accepted owner **6/6** (**7.12s**), mutations **15 passed, 1 ignored**
(**7.60s**), recovery publication **1/1** (**1.33s**), and tenant audit **5/5**
(**7.01s**). Labels are `c04-invocation-receipt-accepted`, `-mutations`,
`-recovery-unit`, and `-audit`. The existing ignored 100,000-row capacity cohort
is unchanged. Authority callers and retirement integration remain pending.


`c04-invocation-receipt-authority.log` passes all **8/8** Authority publication
callers in **247.04s** (tests **14.24s**), exit **0**, **805/805 matching**.
Their plain-publication/refusal paths retain original behavior under the required
trait migration. The complete caller tranche passes **35 active cases**, with
the existing large-capacity mutation cohort still ignored. Retirement integration
is run separately from the failing recovery route.


`c04-invocation-receipt-retirement.log` passes the actual retirement/snapshot
recovery contract **1/1** in **42.57s** (test **1.17s**), exit **0**,
**805/805 matching**. The full recovery route's retained-opening and latest
quorum-resolution timeout failures remain separate open investigations; this
passing contract does not establish their resolution.


`c04-invocation-receipt-fmt.log` passes workspace formatting in **18.70s**,
exit **0**, **805/805 matching**. Fresh strict component/workspace lint remains
pending after the next temporary recovery diagnostic is settled.

The next native source-funding design is frozen at
`/tmp/kasumi-bound-source-funding-design-v1/design.md`, SHA-256
`8922cc4938141c5448fd74671475824214d327bcfcbb11ed9b5015ca2616b185`.
Independent review and root approve isolated implementation of its native-only
first slice. It binds actual providers and two publication accounts to real
rights/backing/pin construction and history exchange. The Store bridge remains
test-only. Complete reader/census capacity, canonical scratch, descriptors,
Generation escape, preaccept capacity and candidate funding remain prerequisites;
no production availability or cache goal is closed by this design.


Temporary recovery-resolution diagnostic `e502060e…bfe0d5` is applied with
both exact after hashes. It preserves the original 10-second timeout, leader
reselection, permanent-outcome read, effect consumption and resolution commands.
Fixed progress counters and the first moved actual wire error are retained;
all-node metrics and explicitly unverified local phase observations print only
after timeout. The existing opening diagnostic remains for the same run. No
speculative leader fix, additional command or relaxed bound is introduced.


`c04-invocation-receipt-recovery-resolution-diagnostic.log` **fails** in
**166.43s** (runtime **142.61s**), exit **101**, **806/806 matching**. The
unchanged timeout expires inside the first ResolveWrite: one leader/phase/resolve
attempt, selected node 1/term 1, no returned uncertain error. Every local exact
phase remains present without an outcome (applied index 46/revision 47). At
timeout the nodes have diverging election terms and no peer replication progress;
all running-state reports are Ok. Twelve vote requests returned with no dropped
probe observations. These local snapshots are diagnostic, not quorum authority.
The transport/append/proposal path needs investigation; no cached-leader or
startup correction is inferred, and the prior opening failure remains open.

`c04-invocation-receipt-components-clippy.log` fails strict component lint in
**110.10s**, exit **101**, **806/806 matching**. The Store read-quote test's
explicit lock-guard drop is not recognized by `await_holding_lock`. The repair
uses a lexical scope around the same assertion before the later async fixture
close; no behavior, admission, or capacity changes are made. Fresh qualification
uses a separate evidence label.

The ordinary primary COW design is frozen at
`/tmp/kasumi-primary-cow-integration-design-v1/design.md`, SHA-256
`b8364c57c0b2106e910b9d0d1e91f82ca455cfddb2d0646154b739d229c3d993`.
Root and independent review approve isolated implementation of only its
test-only first slice: accepted borrow, full baseline proof, existing-live-key
path copying, pending incremental journal/abort, and frozen delta verification.
Its no-alias proof checks disjoint fresh allocation intervals and distinct
reachable cardinality; its one-row completeness check exhausts the pinned
shared-node map diff. Five-effect publication, CoveredReplay reconstruction,
committed retirement and production activation remain separate prerequisites.

`c04-invocation-receipt-components-clippy-scope.log` passes strict
all-feature/all-target Clippy for KV, Query, Store and Raft in **83.46s**,
exit **0**, **806/806 matching**, after the lexical test-guard repair.
Workspace lint and the focused Store quote checks follow separately.

`c04-invocation-receipt-store-quotes-scope.log` compiles in **52.40s**,
exit **0**, **806/806 matching**, but runs **zero tests** because its module
filter names the source file rather than the declared module. It is not test
qualification. The corrected `storage_domains::read_memory_quote::tests`
filter uses a fresh evidence label.

`c04-invocation-receipt-store-quotes-scoped.log` passes all **4/4** Store
read-quote cases in **3.78s** (tests **2.09s**), exit **0**, **806/806
matching**. This qualifies the lexical guard repair while retaining allocation,
provider identity, key-length and encrypted zero-cache fallback coverage.

`c04-invocation-receipt-scope-fmt.log` passes workspace formatting in
**12.89s**, exit **0**, **806/806 matching**, including the lexical quote-test
repair and current recovery diagnostics.

`c04-invocation-receipt-workspace-clippy.log` passes workspace
all-feature/all-target Clippy with `-D clippy::all` in **351.31s**, exit **0**,
**806/806 matching**. Existing Engine security-audit and vendored rmcp
dead-code warnings remain; this is not a workspace `-D warnings` claim.

Temporary Append/key-lease probe `9ecfdd6a…cc0ca1` is applied after strict
base/dependency/after hash checks for all three diagnostic files. It retains
32 scalar event slots and one first observed non-success, never overwrites a
pending call, and forwards original requests/results unchanged. It reports
returned or dropped futures separately, with fixed error text and explicit
omission counts. Key-lease failure classes are read only on the existing
timeout path. Timeouts, limits, commands and production code are unchanged;
the next run is diagnostic, not proof of a repair.

`c04-invocation-receipt-recovery-append-diagnostic.log` **fails** in
**293.93s** (runtime **281.64s**), exit **101**, **807/807 matching**. This
run passes the earlier resolution point, so it emits no timeout Append/key-lease
report; that does not establish a replication repair. It reaches the retained
opening failure at node **2**, `create=false`: physical acquisition returns
`InvalidData`, before native opening (original `NotEntered`, opening phase
`Prepared`), with no child or local startup error and `existing_verified=false`.
Partial close independently returns `Io(Other)`; native fence returns Ok.
The original acquisition and cleanup failures remain separately retained.
Investigation now targets physical acquisition, rather than the later native
source-retirement observer. Limits, timeouts and commands remain unchanged.

`c04-recovery-append-probe-clippy.log` passes the all-feature Engine lifecycle
target with `-D clippy::all` in **154.38s**, exit **0**, **807/807 matching**.
The existing Engine dead-code warnings remain. The diagnostic compiles and
passes its applicable lint gate; the recovery behavior remains failed above.

`c04-recovery-append-probe-fmt.log` passes workspace formatting in **15.21s**,
exit **0**, **807/807 matching**. The new diagnostic's source and lint are
qualified; no recovery success or complete cache behavior is claimed.

Temporary physical-acquisition probe `b4468cbd…540fb5` is applied with all
three before/after hashes and thirteen dependency/log pins matching. Its
`test-utils`-only failure output uses already observed metadata at the exact
cursor/open enrollment comparisons, plus static acquisition substages. It
adds no owner fields, extra stat/read, retry, reconciliation or changed
predicate. `AccountedFile.bytes` is the standing charged ceiling; pending is
its unmaterialized part, not an additional charge. The original error and
independent close outcomes remain unchanged. One further run will distinguish
an actual metadata mismatch from other acquisition paths; no repair is inferred.

`c04-recovery-acquisition-diagnostic.log` **fails** in **579.40s** (runtime
**474.78s**), exit **101**, **807/807 matching**. It emits no physical
acquisition failure marker and reaches a later control-leader wait at
`lifecycle.rs:315`. All three nodes report applied index 76, with divergent
election terms 38/39 and no reported peer replication progress. The bounded
Append probe counts 2693 starts, 1776 successes, seven higher-vote results,
55 transport errors and 855 dropped futures; 2661 observations were replaced
after completion and none omitted because all slots were pending. The first
non-success is an early 151 ms dropped future. Source inspection confirms this
exact route does not invoke router isolation or blocked links. Its node-close
paths unregister peers before shutdown and reopen/register nodes sequentially;
`raft peer unavailable` identifies an absent registration. Later occurrences
are consistent with those lifecycle gaps, but the unlabelled leader-wait call
requires further attribution. They are not by themselves evidence of an
unintended transport failure. This run does not reproduce or explain the earlier
`InvalidData` acquisition result and does not qualify recovery. No timeout,
capacity or physical enrollment predicate is changed.

`c04-recovery-acquisition-store-clippy.log` passes all-feature/all-target Store
Clippy with `-D warnings` in **113.47s**, exit **0**, **807/807 matching**.
This qualifies the diagnostic build/lint surface; the recovery test remains
failed as recorded above.

Native source funding artifact `4f8fee60…0da21` is applied after root verifies
the frozen patch/manifest/README, all **27** live before/after hashes, and
**13** source/dependency pins. Its two logical assignments use the real
installed MemoryCore and native retained constructors. The shared allocation
owner preserves Store's actual two-box retirement order. Explicit no-backend
cleanup and final controller cleanup retain original failure observations
until positive disposal. Ten native protocol cases, eight real-provider cases,
one four-allocation lifetime case and three privacy doctests are prepared;
runtime qualification starts on the resulting **814-file** selection. The
Store bridge is test-only; registered reader/census funding, encrypted content
qualification and production SourceRoots activation remain open.

`c04-native-source-funding-kv.log` compiles the new native substrate and passes
**9/10** tests in **53.17s**, exit **101**, **814/814 matching**. The failed
test helper expects the wrong existing error envelope: `From<CoreError>`
maps `CoreError::Io` directly to `StorageError::Io`, preserving the original
`io::Error`. Root corrects only that match arm, keeping exact original-pointer
and pending-credit assertions. No production error handling is changed.

`c04-native-source-funding-kv-envelope.log` passes all **10/10** native
funding protocol cases in **28.88s**, exit **0**, **814/814 matching**, after
the test-envelope correction. Real MemoryCore arithmetic and allocation-tail
qualification follow separately; these adversarial-provider cases do not
establish the complete Store reader or production serving corridor.

`c04-native-source-funding-engine.log` fails compilation in **90.14s**,
exit **101**, **814/814 matching**. The fixed-bank quote has a missing `?`
on a nested checked addition. Root adds error propagation at that expression;
the quote's components, allowance and reservation policy are unchanged.

`c04-native-source-funding-privacy.log` passes all **3/3** compile-fail privacy
doctests in **12.01s**, exit **0**, **814/814 matching**. The compiler rejects
external construction of the pool installer, child permit and bound funding
owner through their private fields.

Test-only peak-window artifact `ee329605…4d57ea5` extends the real-provider
allocator window through both funded preparations, so the measured peak covers
the bank, rights, both accounts and both backing/pin pairs. Existing ledger,
capture and cleanup assertions remain. Its one before/after hash and Store
dependency match; the Engine dependency differs only by the exact missing-`?`
compile repair recorded above, verified byte-for-byte against the frozen base.
No quote or allowance changes are made.

Source-pinned recovery follow-up `f07f0930…a1a3b4` distinguishes the two
possible close/reopen checkpoints without choosing one from an unlabelled
panic. The last retained `peer unavailable` result occurs before the approximate
final ten-second leader wait; its retained final interval instead contains
successful reachability, higher votes and dropped futures. Thus the log does
not establish a missing target after all nodes reopen. A deterministic test of
the separate pending-allocation enrollment predicate will use an existing
physical-observation hook, with no cluster run or predicate change. Such a
test can establish the refusal mechanism, but cannot identify delayed APFS
allocation as the cause of the earlier failure.

`c04-native-source-funding-engine-peak.log` passes all **9/9** selected Engine
cases in **293.74s** (tests **2.13s**), exit **0**, **814/814 matching**.
Eight use the actual installed MemoryCore/registered opening and retained native
constructors. The ninth gates four actual allocation deallocations before
credit/ticket release. The measured two-reader peak is within the unchanged
bank quote; exact byte/native-slot refusals, history transfer, busy sealing,
foreign provider rejection and opening-close custody pass. Existing Engine
dead-code warnings remain. These results qualify the native first slice,
not encrypted content serving or complete registered-reader funding.

`c04-native-source-funding-native-regressions.log` passes **524/524** KV unit
tests and **27/27** selected cache-allocation, crash-recovery, owner-fencing and
transaction-rollback integrations in **66.44s**, exit **0**, **814/814 matching**.
This retains ordinary read/protected-pin/warm-up behavior alongside the new
native funding protocol.

Test-only pending enrollment artifact `61bc3ee0…76c8c9` is applied after exact
before/after and seven dependency hash checks. Its two tests cover four cases:
unchanged versus smaller prior allocation observations, through both reopen
and directory iteration. The existing observation hook changes only the recorded
allocation observation at verified real EOF. The tests require the same physical
inode/EOF/blocks and paid ceiling; only pending differs. They preserve current
refusal predicates and inspect retained credit/fencing before explicit teardown.

`c04-pending-only-enrollment.log` fails Store unit-test compilation in
**141.63s**, exit **101**, **814/814 matching**. The existing
`disk_memory_tests` helper reaches the former private `RetireLease`/lease field,
which moved behind opaque KV `ResidentAllocation` in the funding extraction.
No enrollment test ran. The repair will observe the actual allocation during
its constructor using the existing Store test allocator, preserving the original
deallocation-before-credit assertions without exposing the token owner.

`c04-native-source-funding-kv-clippy.log` passes all-target native KV Clippy
with `-D warnings` in **59.24s**, exit **0**, **814/814 matching**. Store's
unit-test helper repair and the remaining component lint/quote checks are
tracked separately.

`c04-native-source-funding-fmt.log` passes workspace formatting in **43.73s**,
exit **0**, **814/814 matching**.

Store test repair `69b34a0f…7c4b9d` is applied with both exact before/after
hashes and five dependency pins. The allocator records the actual token
allocation's address during the closed constructor, requiring one allocation
of the exact size and no retirement. The existing deallocation gates, denial,
credit/slot lifetime and panic-original assertions remain. No production
interface, allocation owner or feature is exposed for the tests.

The registered Store source-funding design is frozen as `3a2e117a…60deea`
after root and independent source review. Its scoped implementation may add
actual metadata grants, protected census cells and registered source-reader
custody. A fenced retained history transfer preserves the old reader ID;
explicit census/source-control retirement breaks the intentional governor
custody cycle even after user facades disappear. It does not yet authorize an
encrypted loan, ordinary Active reader or production source selection.

`c04-native-source-funding-store-lease.log` passes all **3/3** existing
Store opaque-lease allocation/denial/panic cases in **340.32s**, exit **0**,
**814/814 matching**. The repaired constructor observer sees the exact retained
token allocation, and the actual deallocation-before-credit/field-unwind
assertions pass. The Store unit-test target now compiles; focused enrollment
and read-quote qualification can run without changing their assertions.

`c04-pending-only-enrollment-observer.log` passes **2/2** tests (four actual
open/cursor cases) in **2.09s**, exit **0**, **814/814 matching**. Exact prior
observations reopen/iterate successfully; a simulated smaller prior allocation
at unchanged inode/EOF/blocks/ceiling deterministically refuses and fences
without refunding paid or pending accounting. This qualifies the predicate,
not a natural filesystem reproduction or diagnosis of the earlier cluster run.

`c04-native-source-funding-store-quotes.log` passes all **4/4** actual Store
read-quote cases in **3.41s**, exit **0**, **814/814 matching**, retaining
zero-cache fallback, key-length/provider identity and temporary overlap checks.

Test-only accepted COW artifact `09ca49e8…56ab57` is applied after root verifies
all **11** before/after files, frozen manifest/patch and **39** dependencies.
Its private accepted owner supplies the original apply guard, previous/candidate
generations and complete actual map diff. Baseline verification checks the full
accepted graph on one frozen pin; existing-key edits copy only the affected
path and leave their pending attempt unselected. Abort removes pending objects
in bounded steps without following old retire targets. Ten prepared cases begin
qualification on the resulting **821-file** selection. Production publication,
serving, committed retirement and actual unknown-commit/crash coverage remain
open.

`c04-primary-cow-accepted.log` fails compilation in **89.18s**, exit **101**,
**821/821 matching**; no COW tests ran. Eight diagnostics identify a missing
retention-trait import, test-only helper visibility across sibling modules, and
a traversal cursor mutation while its local frame bounds are borrowed by a
validated page. A minimal isolated correction will keep those bounds immutable,
scope helpers only to their owning stage modules, and import the existing trait.
The compiler also identifies one redundant test import. No production serving
or journal semantics are changed by the planned repair.

`c04-native-source-funding-components-clippy.log` passes all-feature/all-target
Clippy for KV, Query, Store and Raft with `-D warnings` in **107.31s**, exit
**0**, **821/821 matching**. It includes the Store allocator-observer repair
and pending-only enrollment tests. Engine COW qualification remains separate
and has not yet passed compilation.

`c04-source-funding-store-default-clippy.log` fails in **33.11s**, exit
**101**, **821/821 matching**. A pre-existing production scoped-read failure
field references `Any` through an import available only with tests/test-utils.
Root adds its direct unconditional `std::any::Any` import in the owning module.
This fixes default-feature compilation without changing its panic custody,
layout or accounting; the all-feature gate could not expose that missing import.

`c04-source-funding-store-default-import.log` reaches Store lint but fails
`-D warnings` in **32.18s**, exit **101**, **821/821 matching**: the crate-private
segment-group `path()` accessor is used only by the already gated physical
fixture. Root applies the same `cfg(test or test-utils)` gate to that accessor;
the stored path and production physical operations are unchanged.

`c04-source-funding-store-default-gate.log` passes production/default-feature
Store library Clippy with `-D warnings` in **23.57s**, exit **0**,
**821/821 matching**, after the direct import and fixture-accessor gate fixes.
The diagnostic-disabled physical-acquisition branches compile in this selection.

Minimal test-only COW compile correction `36d8df61…0869a` is applied after
root verifies all four before/after files, the frozen patch/manifest and eight
dependency pins. The retained-source trait is imported, four helpers are scoped
to their owning stage modules, and the validated page borrows immutable local
frame bounds while only the stored traversal cursor advances. No accepted
identity checks, journal effects, capacity or production paths change.
`c04-primary-cow-compile-corrected.log` begins the ten-case qualification on
the resulting **821-file** selection; a started run is not a passing result.

`c04-primary-cow-compile-corrected.log` compiles and runs all ten COW tests in
**147.71s** (test runtime **45.33s**), exit **101**, **821/821 matching**.
Nine pass. The cross-collection DTO-alias test fails while seeding its archived
arm, before reaching the corruption check: its shared mutation helper supplied
`Precondition::Any`, which the actual append-only producer correctly rejects.
Root changes only this test's two creates to explicit `Precondition::Absent`.
Both mutable and append-only arms use valid accepted creates; the physical alias,
complete inventory and expected rejection checks remain unchanged.
`c04-primary-cow-absent-seed.log` starts the corrected ten-case selection.

`c04-primary-cow-absent-seed.log` passes **10/10** tests in **113.46s**
(test runtime **50.54s**), exit **0**, **821/821 matching**. Both live and
archived cross-collection alias arms now reach and pass their intended refusal
checks through valid accepted fixture input. The remaining tests cover exact
accepted/source identity, complete row-diff checks, bounded unselected path
staging/abort, original cancellation, inventories, real allocation retirement
and installed slot denial. These are test-only component results; unknown
commit/restart and production publication remain open.

`c04-primary-cow-existing-regressions.log` begins the existing primary
stage/catalog/bulk/reader and accepted-owner/mutation selections, **66** listed
tests on the same **821-file** source.

`c04-primary-cow-existing-regressions.log` finishes in **115.93s** (test runtime
**114.92s**), exit **101**, **821/821 matching**: **63 pass, two fail, one
pre-existing ignored test**. The two failures are the mixed two-level builder
and large encrypted DTO/abort tests. Both report a committed domain transaction
whose access expires before acknowledgement; no rollback is inferred. Their
`#[tokio::test]` executors are single-threaded, and synchronous storage work
keeps those executors occupied beyond the unchanged 60-second key lease. Store
renewal is an ordinary Tokio task scheduled every 20 seconds, so it cannot run
during that synchronous interval on these runtimes.

Root changes only those two test attributes to a two-worker Tokio runtime,
allowing the actual renewal task to run while the test performs synchronous
storage work. No lease/timeout, capacity, authorization check, storage behavior
or assertion is changed. `c04-primary-cow-renewal-runtime.log` starts the same
66-test regression selection against this **821-file** source. This harness
correction does not diagnose the separate full recovery-route failures.

`c04-primary-cow-renewal-runtime.log` finishes in **169.13s** (test runtime
**121.87s**), exit **101**, **821/821 matching**: **64 pass, one fails, one
remains ignored**. Both tests with corrected executors pass after running more
than 60 seconds. The recursive three-level frontier test, still on the default
single-thread executor, now exceeds the lease and reports the same postcommit
access-expiry error. Root applies the identical two-worker test-runtime change
to that test only. `c04-primary-cow-renewal-frontier.log` starts the same
regression selection. Original failed evidence and production lease behavior
are retained.

`c04-primary-cow-renewal-frontier.log` passes the full selected regression
matrix in **163.23s** (test runtime **130.69s**), exit **0**, **821/821 matching**:
**65 pass, zero fail, one pre-existing ignored test**. All three corrected long
tests pass after exceeding 60 seconds with real key renewal enabled. The ignored
case remains the explicit 100,000-row permanent-receipt capacity cohort; it was
not newly disabled. The existing encrypted primary reader, bounded staging,
catalog, bulk frontier, accepted-owner and mutation checks are covered by this
selection. Engine Clippy starts separately as `c04-primary-cow-engine-clippy.log`
with `-D clippy::all`; existing audit dead-code warnings remain outside that gate.

`c04-primary-cow-engine-clippy.log` fails in **207.53s**, exit **101**,
**821/821 matching**, with three test-only lints: a retirement worker uses
`join().ok().expect()`, and the document accessor `Replacement::new(&self)`
triggers two constructor-naming conventions. Root removes the redundant `ok()`
and renames the accessor to `new_document` at all six callers. The affected
files are formatted; ownership, assertions, effects and production paths are
unchanged. `c04-primary-cow-engine-clippy-corrected.log` starts the same lint
gate on the corrected **821-file** source.

`c04-primary-cow-engine-clippy-corrected.log` passes Engine all-feature/all-target
Clippy with `-D clippy::all` in **51.98s**, exit **0**, **821/821 matching**.
The four pre-existing audit dead-code warnings remain; this is not a
`-D warnings` release pass. `c04-primary-cow-format.log` passes whole-workspace
format checking in **10.33s**, exit **0**, on the same matching selection.
`c04-primary-cow-lint-regressions.log` starts the ten new COW cases and actual
source-allocation retirement test affected by the small lint corrections.

`c04-primary-cow-lint-regressions.log` passes **11/11** tests in **69.52s**
(test runtime **44.08s**), exit **0**, **821/821 matching**: the ten COW
component cases and the actual native bank/account Arc/backend-Box retirement
test. This validates the small naming and worker-join corrections. The earlier
65-case regression selection and these eleven cases are separate runs;
production primary serving, unknown-commit/restart and complete Store source
funding remain open.


### C04 unknown staging recovery: first runtime qualification

The root applied the source-reviewed three-file test artifact
`/tmp/kasumi-primary-cow-unknown-staging-v1/primary-cow-unknown-staging-v1.patch`
(SHA-256 `cc6b160ec8013f96fa269d34099db9f5d958b2c7acba40df1122c1e80544c30d`)
after checking its manifest, all 59 dependency pins, exact live before hashes,
strict apply and reconstructed after hashes. It adds an actual native
finish-after-durable-commit fault at pending publication and first chunk
publication, with retained original error/claim, same-MemoryCore native funding,
authentic bootstrap/replay, complete batch inspection and bounded abort.
This remains a synthetic durable-image test and does not prove installed
filesystem power-loss behavior or complete synthetic/diagnostic heap accounting.

`c04-primary-cow-unknown-staging.log` compiled and then FAILED: zero passed,
one failed, 92.97 seconds including compilation, 5.38 seconds in the test;
all 822 selected source/config pins matched. The observed failure was
`covered reconstruction gained a serving capability`. This was a test
expectation error: the publisher's CoveredReplay branch includes equality,
whereas the selected-source covered flag means the expected Entry identity
is not the current durable Entry identity. Replaying seed positions 1/2
under durable position 3 is covered; replaying the identical SetPolicy at
position 3 reaches an exact source, which the unchanged reader accepts.
The proposed correction will check intermediate refusal and exact-current
success separately. Neither the initial static review nor the failed run
qualifies the new two-arm recovery case. C01–C07 remain open.


`c04-primary-cow-fixture-regressions.log` then PASSED all ten existing COW
cases after the shared constructor refactor: 46.50 seconds overall, 44.90
seconds in tests, all 822 pins matched. This does not waive the failed new
unknown-staging expectation or qualify its second arm.

The root next applied the 18-file registered source funding artifact
`/tmp/kasumi-registered-source-funding-v1/registered-source-funding-v1.patch`
(SHA-256 `e188f85339ff51f27ffc4cddfd699551f54944449f7649605fdd12bc8b083d27`),
checking the frozen manifest, all eight additional dependencies, live before
hashes, strict patch application and resulting hashes. It funds registered
control, metadata bank, two protected reader assignments and independently
admitted historical reports through the actual MemoryCore. Census construction
preclaims the real parent/child identity; native and local exchange outcomes
remain distinct. Construction/operator entry is still test-only/test-utils;
there is no encrypted read loan, SourceRoots integration or production cache
activation. Seventeen prepared new cases, default-feature builds, lint and
regressions remain unqualified until their recorded root runs.


`c01-registered-source-census.log` FAILED during compilation in 31.13
seconds with all 830 pins matching; no selected tests ran. Eight diagnostics
identified module visibility for `drain_source_owners` and
`advance_source_exchange`, plus two overlapping ReaderState field borrows in
the fixture operator. An unused `SourceControlClaim` re-export was also
reported. These are retained as failed compilation evidence. The correction
must preserve the existing private protocol and guard lifetimes.


The four-file compiler correction
`/tmp/kasumi-registered-source-compile-fix-v1/registered-source-compile-fix-v1.patch`
(SHA-256 `44660e57b37c260361b08d6167ce9560a6f459a44714b96b15d0988afb2f68ef`)
was peer reviewed and applied with all manifest/before/after/dependency hashes
verified. It restricts visibility to the actual ancestors, removes unused
re-exports and splits disjoint ReaderState field borrows without changing
lock order or runtime behavior. `c01-registered-source-census-compile-corrected.log`
PASSED twelve tests: eight source census cases plus four existing exact
read-memory-quote cases. Runtime was 1.24 seconds, 52.22 seconds including
compilation, with 830/830 selected hashes matching. The deliberate panic
messages are caught fault inputs in passing cases, not process failures.

The one-file exact-replay fixture correction
`/tmp/kasumi-primary-cow-replay-exact-fix-v1/primary-cow-replay-exact-fix-v1.patch`
(SHA-256 `5f794858b039b08511bdf6a10407ec6c850889907752346b262f88410e517778`)
is also applied after its independent review and eight dependency-pin checks.
It requires covered intermediate source rejection and, after replay reaches
the exact original Entry, the matching producer proof and old canonical v2 DTO.
Its corrected runtime qualification remains pending.


`c01-registered-source-default-clippy.log` FAILED in 30.84 seconds with
830/830 source/config pins matching. The default Store library produced 37
dead-code diagnostics for metadata/census construction fields and helpers used
only by the gated fixture operator, plus three Clippy style diagnostics.
This is not a default-feature qualification. The correction must use deliberate
feature boundaries and preserve retained provider/grant lifetimes; a blanket
warning allowance or production activation is not a substitute. All-feature
census/quote tests above remain their own passing selection.


`c01-registered-source-store-regressions.log` ran 125 selected Store census,
opening, encrypted-fork and routine-diagnostic cases: 123 passed, one failed,
one pre-existing ignored, 81.60 seconds overall / 77.19 seconds in tests,
830/830 pins matching. The only failure was
`production_tenant_get_accepts_maximum_writer_value`, whose synchronous maximum
record write on the default single-thread Tokio test runtime exceeded the
actual 60-second key lease before the following read. The read correctly
returned `tenant is sealed: key-access lease unavailable or expired`.
The actual renewal task runs every 20 seconds and cannot progress while that
single runtime thread executes the synchronous write. The root changed only
this test to two Tokio workers, matching the previously qualified long primary
fixtures. No lease, timeout, budget or security check changed. Its rerun remains
required; this failed run is retained.


The root applied the source-reviewed three-file unknown-abort artifact
`/tmp/kasumi-primary-cow-unknown-abort-v1/primary-cow-unknown-abort-v1.patch`
(SHA-256 `c2d1c39d7bd6487bdcdd4c23467823874b063bbeac95b05d9740028726239bdd`)
after exact manifest/before/after checks and all 60 dependencies. Its one test
has three independently built arms, selected by decoded durable progress:
nonfinal chunk cleanup (two effects), final chunk/resource removal (four),
and terminal pending settlement (two). The actual original native uncertainty
and charged proposed operations survive crash-image inspection. Fixed old
DTO/page/manifest Inventory records are compared without mutation exemptions,
in addition to old physical contents and unchanged selector/custody. Zero
allowance and already-settled resume must publish no batch. This is prepared
synthetic coverage; runtime qualification remains pending.

The first combined Engine qualification selection includes this abort test,
the corrected unknown-staging test, ten existing COW tests, and the initial
registered/native source funding and allocation cases. The separate two-case
contention successor is not yet applied: its root application helper rejected
the dependency-pin JSON shape before any mutation. It will be applied only
after the active source-pinned Cargo run finishes.


`c04-primary-cow-registered-source-qualification.log` compiled and ran thirty
Engine cases: 29 passed, one failed, 497.52 seconds overall / 87.48 seconds in
tests, with all 831 selected hashes matching. Passing cases include all eight
initial registered source funding tests, the new five-target actual allocator
retirement case, all eight prior native funding cases and its allocator case,
and both new recovery tests (two unknown-staging arms and three unknown-abort
arms). The corrected replay distinction, actual preserved old documents and
inventories, unknown batches, positive reopened cleanup and final original
error identity all passed in these synthetic fixtures. Nine of ten existing
COW cases also passed.

The sole failure was the existing
`primary_cow_actual_accepted_path_is_unselected_and_abort_is_separately_bounded`:
its default single-thread Tokio runtime ran synchronous staging long enough
that the real key lease expired before commit acknowledgement. The original
`batch committed but key access was lost before acknowledgment; outcome unknown`
was retained. The root changed only that test to two workers with an explanatory
comment, preserving the real renewal worker, lease duration and all limits.
The broader selection must pass again before an overall pass is claimed.

After Cargo completed, the root applied the reviewed contention successor
`/tmp/kasumi-registered-source-contention-v1/registered-source-contention-v1.patch`
(SHA-256 `66f06ecc610ea66e0febfee7efcd1067341f0ab00a43f90db1c951eca0f5446e`),
verifying its two files and fourteen dependency pins, then the nine-file
experimental feature boundary correction
`/tmp/kasumi-registered-source-cfg-v1/registered-source-cfg-v1.patch`
(SHA-256 `caaef49177835fc78ff25dbd70b3318552563ae94e89ea63d0285d72d858bc1d`),
verifying its ten dependencies and composed before/after hashes. The complete
unactivated metadata/provider/reader/census path now compiles only for tests or
`test-utils`; ordinary default reader and census layouts stay canonical for
that configuration. Actual quotes continue to use compiled owning types.
Three style corrections and original failure-observation order are preserved.
Default lint, both new contention cases, updated allocation quotes and the
runtime correction remain pending on this source. C01–C07 remain open.


`c01-registered-source-default-cfg-corrected.log` PASSED strict default-feature
Store library Clippy (`-D warnings`) in 29.92 seconds with 831/831 hashes
matching. The coherent experimental boundary fixes the earlier default graph
failure without warning allowances. All-feature/test qualification is separate.


`c01-registered-source-store-clippy.log` FAILED strict all-feature/all-target
Store Clippy in 82.39 seconds, 831/831 pins matching. Its only two diagnostics
are test-only `drop_non_drop` calls on `SourceControlClaim`. The correction
will end those claim scopes explicitly while retaining the no-facade evidence;
no empty destructor or lint allowance is needed. Default Store strict lint
above remains a separate pass.


`c04-registered-source-engine-clippy.log` FAILED Engine all-feature/all-target
Clippy (`-D clippy::all`) in 284.56 seconds with 831/831 matching pins. Its
only errors were two test-only `drop_non_drop` calls on `PrimaryCandidate`
in the unknown-staging and unknown-abort fixtures. The existing security-audit
dead-code warnings remain separate. Lexical scope corrections are being
prepared; the new recovery runtime passes above are unchanged evidence.

After that Cargo invocation ended, the root applied the reviewed one-file
Store claim-scope correction
`/tmp/kasumi-source-control-test-scope-v1/source-control-test-scope-v1.patch`
(SHA-256 `153b61102538faa7a780808bcbde7aeee2e9bb82eacdfd663f1f17fae8689414`),
verifying its manifest, before/after file and two dependency pins. It replaces
explicit drops with lexical claim scopes while preserving original error
identity and no-facade cleanup assertions. Corrected strict Store lint is
running separately; no production ownership or warning allowance changed.


`c01-registered-source-store-clippy-scope-corrected.log` PASSED strict
all-feature/all-target Store Clippy (`-D warnings`) in 54.59 seconds with
831/831 matching source/config hashes. The lexical claim scopes correct both
test diagnostics without changing the production protocol or adding allowances.


`c01-registered-source-store-regressions-runtime-corrected.log` PASSED:
128 active tests, zero failures and one pre-existing ignored case in 84.01
seconds (35.28 seconds test runtime), 831/831 hashes matching. This covers
registered census state, actual owning-layout quotes, ordinary storage opening,
encrypted forks and routine diagnostic custody. The maximum writer-value case
passes with the real lease renewal running on two Tokio workers. No lease,
admission, capacity or timeout was increased.

The next test-only primary COW publication design is frozen at
`/tmp/kasumi-primary-cow-publication-design-v1/design.md`
(SHA-256 `d9d29308db9a3ac78586b2788668522ea4fd5877d6a4ea924ab3b44d621a80a2`).
Root and independent review verified all 37 copied/live source pins. The design
requires five atomic primary effects alongside canonical custody writes, exact
captured-source graph verification, overlapping funded baseline shells, and
positive temporary-reader cleanup before visible publication. Final effect
ownership survives the actual publisher finish. Review added an actual paired
prior/current custody-cursor check before staging and an actual producer-origin
Advance guard before source preparation: next-index comparison alone cannot
exclude a canonical durable advance whose visibility failed. Implementation
is authorized only in isolated scratch; this is not runtime qualification or
production activation. C01–C07 remain open.


`c01-registered-source-metadata-privacy.log` PASSED both all-feature Store
compile-fail checks for `SourceMetadataInstall` and `SourceMetadataPermit` in
36.68 seconds (0.71 seconds doctest runtime), 831/831 hashes matching. External
callers cannot directly construct either protocol authority. This qualifies
that API boundary, not complete source funding or production activation.


`c01-registered-source-engine-default-check.log` PASSED the default-feature
Engine library check in 112.39 seconds, 831/831 source hashes matching. The
matching Engine provider callback is correctly excluded with the experimental
Store protocol. Two pre-existing security-audit dead-code warnings remain;
this is compilation evidence, not a strict-warning pass.


After the default check ended, the root applied the reviewed Engine lexical
scope repair `/tmp/kasumi-cow-input-test-scope-v1/cow-input-test-scope-v1.patch`
(SHA-256 `765394e06e0a52fed4a708c1017e5d0d79b81c4dc3b56bb63eeef522ccc0279f`),
verifying its manifest, two before/after files and three dependency pins.
Both candidate borrows now end lexically before the unchanged owned authority
and prepared-application cleanup. All fault identity, physical-state and
reopen assertions remain. The corrected 32-case combined Engine selection
is running on the composed source; no pass is assumed from source review.


`c04-registered-source-engine-scope-runtime-corrected.log` PASSED all 32
selected Engine cases in 347.16 seconds (60.95 seconds test runtime), with
831/831 source/config hashes matching. This includes both new actual
contention cases, all ten registered funding lifecycle cases, both actual
allocation-retirement cases, the eight native funding cases, ten earlier COW
preparation/abort cases, and both recovery tests with five fault boundaries.
The real committed native result survives local marker contention without
reentry, and partial queue registration retains actual report/credit/original
through cleanup. The existing accepted-path COW case now passes with actual
key renewal on two workers. Expected caught-panic output is part of the fault
fixtures. No budget, lease or timeout was increased; source/candidate
activation and full-memory accounting remain open. Corrected Engine lint
is being checked separately.


`c04-registered-source-engine-clippy-scope-corrected.log` PASSED Engine
all-feature/all-target Clippy (`-D clippy::all`) in 125.92 seconds with
831/831 matching hashes. Both new test lifetime diagnostics are corrected.
The four pre-existing security-audit dead-code warnings remain; this does
not claim a whole-workspace `-D warnings` pass or release qualification.


`c04-registered-source-fmt-final.log` PASSED workspace formatting in
12.21 seconds with 831/831 matching source/config hashes. This completes the
selected formatting gate for the registered source/recovery slice, alongside
the separately recorded Store and Engine tests/lints. Full release, whole
workspace strict warnings and C01–C07 completion remain open.


The root then applied the separately frozen three-file Raft origin foundation
`/tmp/kasumi-raft-primary-origin-v1/raft-primary-origin-v1.patch`
(SHA-256 `1cb767930fedb2ac3e111dd0242243b9bf51f668d82001c95376e11062c47d4e`),
verifying its manifest, all before/after hashes and nineteen copied/live
dependency pins. The private origin comes from actual PreparedApplied and
is bound into the existing plan fingerprint in every build. Test/test-utils
gets an advancing-only guard and fixed canonical cursor read specification.
A real-sink regression checks replay refusal before application writes while
retaining a valid exact replay read; two older replay cases gain assertions.
This foundation does not activate the pending Engine primary publication
path. Fresh Raft and actual Engine layout qualification are required; earlier
831-file passes above precede this three-file change.


`c04-primary-cow-raft-origin.log` PASSED all 33 selected Raft
selection/receipt/publication cases in 92.99 seconds (5.98 seconds runtime),
831/831 source/config hashes matching. The new actual Advance→CoveredReplay
refusal case passes, including absent supplied application writes, unchanged
canonical cursor and a still-serving exact replay proof. Existing older-entry
and snapshot replay assertions also pass. Actual enclosing Engine owner
quotations and lifecycle regressions are being qualified separately; no
Engine COW publication activation is included in this three-file foundation.


`c04-primary-cow-origin-engine-quotes.log` PASSED all 28 selected Engine
source lifecycle, constructor quotation and actual allocation-retirement
cases in 191.20 seconds (17.62 seconds runtime), with 831/831 matching hashes
after the Raft origin change. The allocation-free quote, real capture peak,
provider-bound retained amount, original error aliases and final strong/weak
backing retirement all pass. This is the actual enclosing-owner regression
gate for the new plan field, separate from the 33 Raft cases. The pending
COW final-effects implementation is still absent from live source.

The runtime prints actual compiled owner sizes: expectation 72, challenge 72,
receipt 216, plan 312, RootPreparation 456, PublicationPreparation 472 and
SourceRoots 128 bytes, with `cell_bytes()` 8,192. These match the earlier
receipt-layout run: the added origin fits existing layout space on this target.
The measured quote and lifetime checks, rather than an assumed size, establish
this target-specific pass. They do not qualify opaque outer error allocations.


`c04-primary-cow-raft-origin-default-clippy.log` PASSED strict default
Raft library Clippy (`-D warnings`) in 53.38 seconds, 831/831 matching hashes.
The private origin/fingerprint change has no default-build dead-code or
feature-boundary failure. All-feature/all-target lint is separate.


`c04-primary-cow-raft-origin-allfeature-clippy.log` PASSED strict
all-feature/all-target Raft Clippy (`-D warnings`) in 34.29 seconds with
831/831 matching hashes. Both default and experimental API configurations
now pass their selected lint gates. Workspace formatting is checked next.


`c04-primary-cow-raft-origin-fmt.log` PASSED workspace formatting in
7.80 seconds with 831/831 matching hashes. The separately applied Raft origin
foundation now has 33 selected Raft runtime passes, 28 Engine owner/lifetime
passes, default and all-feature/all-target strict Raft lint, and formatting.
This is selected qualification of the foundation only; the larger Engine
COW final-publication artifact is still being independently source-reviewed
in scratch and has not been applied or compiled.


The root applied the source-reviewed nine-file Engine publication slice
`/tmp/kasumi-primary-cow-publication-v1/primary-cow-publication-v1.patch`
(SHA-256 `d33c574ecda07d3ac356745610ece0a86ca7b335309f7d3f2d21c9745562b32d`;
manifest `9127a77f0d0abc7992b1cd6a5766101d4a66c0a1a242c763f0dd491d235c9973`).
Before mutation, every 831-file pin from the preceding format run matched,
as did all nine before states; all nine after hashes matched after applying.
A read-only root application record is retained at
`/tmp/kasumi-primary-cow-publication-root-application-v1`. The author's final
56 dependency copies/pins were also verified against that pre-application
record and the composed source; the additional unchanged `rust-toolchain.toml`
is explicitly checked outside the runner's 831-file set. Three new files
raise the runtime source/config selection to 834.

The private test path publishes five final primary effects with the canonical
cursor, verifies the captured graph, closes temporary readers before visibility
and retains final effect ownership through actual publisher finish. Review
corrected current-pin GC/journal binding, preserved a sealed baseline
constructor, and ensured all handle checks precede ownership transfer. Eight
new tests cover sequential publication, replay/refusal, mapping substitution,
actual allocation retirement and final UnknownCommit/reopen. Production
activation, complete failure injection, index atomicity and C01–C07 remain open.

`c04-primary-cow-final-publication.log` FAILED compilation in 38.92 seconds,
834/834 matching hashes; no runtime cases ran. Both errors are in the new
cancellation fixture: a private `admission::QueryCancellation` import and
nonexistent `new()` constructor. The narrow repair uses the existing public
`kasumi_query::QueryCancellation::default()` API without changing cancellation
semantics, leases, resource limits or timeouts.


After the failed compiler invocation ended, root applied the reviewed one-line
repair `/tmp/kasumi-cow-publication-cancellation-fix-v1/cow-publication-cancellation-fix-v1.patch`
(SHA-256 `74aa439d04233d97552b39baece791eb9588720f22ba832d4ccd9c728d8171ea`),
verifying the manifest, before/after file and five dependency pins. The
corrected 20-case COW selection is running on 834 pinned source/config files.
The failed compiler evidence above is preserved.


`c04-primary-cow-final-publication-constructor-corrected.log` compiled and
ran all 20 selected cases: **19 passed, one failed** in 99.09 seconds
(56.16 seconds runtime), with 834/834 matching source/config hashes. Both
sequential real publications, old snapshot, typed cancellation/final-grant
refusal, predecessor/replay rejection, captured mapping substitution, actual
final-effect allocation retirement and final UnknownCommit/reopen passed,
along with all twelve earlier COW/recovery cases. This is not an overall pass.

The only failure is the publisher admission-refusal fixture's asserted error
type. Saturating the actual ledger denies the Entry producer's native custody
read before its SelectionPreparer callback. The installed provider maps that
denial to `std::io::ErrorKind::OutOfMemory`; the actual publisher retains this
I/O error together with the backend call marker. The fixture expected an
Engine `ResourceExhausted` error instead. The repair will assert the concrete
retained I/O kind, preserving all five-effect, visibility and unchanged-state
checks. It does not remap production errors, relax capacity or accept arbitrary
error text. Required postcommit-close/panic injections remain separate open
coverage; they are not established by these passing cases.


After that completed run, root applied the independently reviewed one-file
correction `/tmp/kasumi-cow-publication-native-denial-fix-v1/cow-publication-native-denial-fix-v1.patch`
(SHA-256 `07558d347d572595a23e405e88c6e73181dce97e1244ac4fa2b12511cc4e8db2`;
manifest `ec450816895ae37f16aba7fc03e36c839e3e3a585024779b916ab15c6e12d06f`).
The manifest, all five live dependency pins and exact before/after hashes match.
The assertion now requires the actual retained root `std::io::Error` and exact
`OutOfMemory` kind. All original proposed-effect, visibility, selector, pending
epoch and cleanup checks remain. The corrected combined 20-case run is pending;
no production error, memory limit or lease policy changed.


`c04-primary-cow-final-publication-native-denial-corrected.log` PASSED all
20 selected COW preparation, publication and recovery tests in 97.32 seconds
(58.10 seconds runtime), with 834/834 source/config hashes matching. The typed
native admission original now passes alongside the unchanged five-effect,
no-visibility, selector/pending-epoch and cleanup assertions. All eight new
publication cases and all twelve earlier COW/recovery cases pass together.
Caught-panic diagnostics belong to existing fault fixtures. This qualifies the
test-only component path; postcommit-close/panic injections, real installed
crash qualification, production command/response provenance, completion-owner
lifetime, all edit kinds, source capacity and index/document activation remain
open. All-feature Engine lint and default compilation follow separately.


`c04-primary-cow-final-publication-clippy.log` PASSED all-feature/all-target
Engine Clippy (`-D clippy::all`) in 123.20 seconds with 834/834 matching
source/config hashes. The four pre-existing audit dead-code warnings remain
unchanged. This is the selected component lint gate, not a whole-workspace
strict-warning or release pass. Default Engine compilation is pending.


`c04-primary-cow-final-publication-default-check.log` PASSED default-feature
Engine library compilation in 33.56 seconds with 834/834 matching hashes.
The custody cursor helper and new primary components remain correctly test-only;
two pre-existing audit dead-code warnings remain. Workspace formatting follows.


`c04-primary-cow-final-publication-fmt.log` PASSED workspace formatting in
6.43 seconds with 834/834 matching hashes. The composed test-only publication
slice now has all 20 selected runtime cases, all-feature/all-target Engine
Clippy, default Engine compilation and formatting qualified on matching source.
The separately recorded Raft producer and Engine constructor/lifetime gates
remain prior, unchanged-component evidence. No full workspace, release or
production disk-serving claim follows.

Independent next-slice source review is retained at
`/tmp/kasumi-primary-production-next-review-v1/recommendation.md`
(SHA-256 `3976784d77bcfd66e0bf04add0881e603c6fdf0045ccceea64a92aebb9e48d3f`,
21 copied source pins). The finite next production dependency is one private
ordinary-command owner retaining the actual accepted reducer result, borrowed
context and its own encoded response. Before decode/staging, checking raw
command bytes against the supplied digest binds only those bytes and digest;
full log/previous/membership validation remains the actual adapter and
invocation-bound receipt obligation. It must preserve specialized command,
metadata, deterministic rejection and frozen no-generation behavior. The actual
Raft adapter finishes publication after Engine returns, so a separate retained
completion owner is mandatory before promoting primary effects to production.
No ordinary envelope has been implemented or qualified by this review.


The dispatcher-wide refinement of the recommendation is retained separately
at `/tmp/kasumi-primary-production-next-review-v2/recommendation.md`
(SHA-256 `b61d1b51defbe1b8131e2209b824e6245fae4eeda575a0267a25f3c9c3e4c3fc`;
manifest `5e45f869ab387c830b008ff12b0ef23cb9766b98be269ac9995c31aca9a643c2`).
Root verified both report versions and their 21 saved pins. All 20 code pins
still match live source; only the goals document's later lint/default-pass
notes differ, and that exact difference was reviewed. Original v1 remains at
its recorded hash.

The implementation design is frozen at
`/tmp/kasumi-ordered-command-envelope-design-v1/design.md`
(SHA-256 `a0cc37c2519bd54de661fbff3dff2c24fbd34c8874110203aa1d71586e68549e`;
manifest `aaecb3c24087069736b457c6927fa55a26f53fc7b73babc61528124d5426ca27`).
Root verified all 41 saved dependencies against their pins and checked live
differences, with only separately recorded goals progress allowed. Root and
independent review require typed early digest failure, frozen-state guard
custody, no raw-parts envelope constructor, and successful specialized-prefix
dispatch tests. Implementation is authorized in isolated scratch; no live
code or runtime qualification is claimed by this design.


Root prepared a disjoint test contribution for the pending envelope slice at
`/tmp/kasumi-ordered-specialized-dispatch-v1/ordered-specialized-dispatch-v1.patch`
(SHA-256 `acb4796baab1d4e6596efbc935c4a43b11b8a4e690c14831ba1fc7a3093a1df1`;
manifest `e2dbd3d2e6da418fcbcf289dcd3a304bad6e93a1d815494d17b86c25d7bc6024`).
The three isolated test edits and eight copied source pins are read-only.
Rustfmt and apply-check against the untouched live base pass; independent
source review cleared them for composition into the pending implementation.
Recovery and audit refusal/retry tests now call the public backend dispatcher
in scratch. The target canonical-decoding test additionally publishes its
initially expected a deterministic Forbidden response through that dispatcher using the
existing response-capture fixture. It does not claim installed target authority,
signed activation, native sink durability, live application or runtime success.


A separate narrow native-cache design is frozen at
`/tmp/kasumi-native-value-read-into-design-v1/design.md`
(SHA-256 `8de93af3aa657ab663ca848a12e060610468f4ef804765e62266049b0f687c3a`;
manifest `2cbe905ee2a898190a3f57ceef492f2c20845d59415707ccda3f2798398f5ab5`).
Root checked all three artifact hashes and twenty saved/live source pins;
independent source review cleared the scope. The proposed normal-policy helper
returns an existing/new retained payload or directly fills the already-admitted
output, eliminating the redundant temporary WORKSPACE payload in
`value_admitted`. Both admitted point and ordered-read callers are in scope.
Cached length/CRC checks precede copying, owner errors never become misses,
loader failures never cause duplicate I/O, and successful direct loads gain
the previously missing counter updates. Existing zero-copy readers and numeric
quotes remain unchanged. No broad retained-source loan, descriptor capacity,
protected postcommit read availability or application cache activation follows.
Implementation is authorized only in isolated scratch; runtime is pending.


Root applied the frozen twelve-file ordinary-command envelope
`/tmp/kasumi-ordered-command-envelope-v1/ordered-command-envelope-v1.patch`
(SHA-256 `e70f7771ac91577245f7386dc4bce63d693653e374de4671e4a57256b0bc64b6`;
manifest `ae7efa617aff37db03dcc73b4d5ac434760e2670bed021b1c35efd159f3a4d09`).
All 834 source/config hashes from the preceding publication-format run matched
before mutation, along with all 46 saved/live dependency pins and twelve
exact before/after states. Three new files raise the selection to 837. The
read-only root application record is
`/tmp/kasumi-ordered-command-envelope-root-application-v1`.

The actual Command dispatcher now checks raw bytes/digest before all prefix
routing. Ordinary canonical preparation owns its borrowed context, actual
reducer response/retirement and accepted-or-frozen apply owner together.
The COW tests use this production factory with outer input ownership. Six
new cases cover typed early refusal/allocation-free successful digest binding,
real-sink accepted/rejected/idempotent responses, full-context receipt refusal,
and separately scoped frozen-state guard ownership. The specialized dispatcher
test contribution above is composed. Runtime, default compilation and lint
remain pending; root has started the combined selected Engine gate. No primary
activation, completion-owner handoff, candidate funding or cache bound is
established by applying this ownership change.

`c04-ordered-command-envelope.log` compiled the exact 837-file selection and
ran 61 cases in 88.16 seconds (58.52 seconds test runtime): 59 passed, one
failed, one pre-existing permanent-receipt capacity cohort ignored. All six
new input/publication cases pass. The sole failure is the root-contributed
target canonical-prefix assertion: its expected_bytes=1/maximum_bytes=2 input
fails the terminal-reserve minimum in input.digest() before authority checking,
producing InvalidArgument rather than the asserted Forbidden. Preserve the
failure; a narrow exact-code/message fixture correction is being prepared.

`c04-ordered-command-envelope-retirement.log` ran the two actual retirement
integration cases in 27.72 seconds (17.85 seconds test runtime), also 837/837
matching. The custody-seed encrypted reopen passes. The full seal/restart case
fails at retirement.rs:281 in archive_history, before retirement, with the
public UnknownOutcome write-task error. Its original failure has not yet been
identified. Neither successful component tests nor this wrapper error establish
the full retirement route; source investigation precedes any rerun.

Root applied the separately reviewed target fixture correction
`/tmp/kasumi-ordered-target-rejection-fix-v1/ordered-target-rejection-fix-v1.patch`
(SHA-256 `02634ce56930159b1d0eb5263b8eed0b4140702aa9668d8bbfe3bde2844a3e87`;
manifest `6859bfe5f2c1d16b2b503ca8e14324fdb3a34f3d87fd333ea69cc83de00b749f`).
All 837 prior source/config hashes and eight saved/live dependencies matched
before application. The correction asserts both InvalidArgument and the exact
terminal-reserve validation message, preserving revision/audit/unchanged-target
checks. It changes no production behavior or fixture budget.

`c04-ordered-command-envelope-target-corrected.log` PASSED all 60 active
selected cases in 82.80 seconds (62.79 seconds runtime), with one pre-existing
ignored capacity cohort and all 837 hashes matching. Actual target layout
observations are PreparedOrderedCommand=432, AcceptedGeneration=64,
ApplyOwner=32 and AppliedResponse=360 bytes. This is production command-owner
and existing test-primary coverage; the distinct retirement integration failure
above remains open. Root started the all-feature/all-target Engine lint gate.

`c04-ordered-command-envelope-clippy.log` PASSED all-feature/all-target Engine
Clippy with `-D clippy::all` in 20.65 seconds and 837/837 matching hashes.
The existing four audit dead-code warnings remain. Default compilation and
formatting will be checked on the composed follow-up selection.

The reviewed failure-only retirement diagnostic was applied from
`/tmp/kasumi-retirement-archive-diagnostic-v1/retirement-archive-diagnostic-v1.patch`
(SHA-256 `b24ed699d40aebd5e7863f0706980f8f9a1291e1fc2ba7cbdf9629353da79438`;
manifest `fa4195877410d35be382528846ea5b2578f6d9cf1c4fdafaae0576d35256443b`).
All 837 prior hashes and ten saved/live dependencies matched. It borrows the
existing retained original without draining custody, and prints only on failure.
`c04-retirement-archive-original-diagnostic.log` FAILS in 12.78 seconds
(5.64 seconds runtime), with 837/837 matching. The actual retained
ApplyPublicationFailure has no protocol violation, publication ResourceExhausted
with `document source retention budget exhausted`, and the backend's Failed
witness. Raft is fenced at term 1, log 5, applied 4. This identifies admission,
not which source request failed; it does not establish equality with the separate
C06 backup deficit. No timeout, lease or capacity adjustment was made.

Root applied the ten-file native value read-into implementation
`/tmp/kasumi-native-value-read-into-v1/native-value-read-into-v1.patch`
(SHA-256 `117be14fb9dd0b7e07f131e3e07fdda5944e850f30e097fca06a3099e804677d`;
manifest `1925ca8e137fde53bfa0c4b220b970825f0dac2083515a66c00c830cecd99c57`).
All 837 previous hashes, 23 saved/live dependencies and exact before/after states
matched. Two new test files raise the selection to 839. The root record is
`/tmp/kasumi-native-value-read-into-root-application-v1`.
Normal demand cache policy and existing zero-copy APIs are unchanged. Optional
retention refusal now directly fills the admitted output; loader errors never
retry, owner/length/CRC failures propagate, and successful direct loads update
both counters once. Numerical aggregate quotes remain conservative and unchanged;
their existing Store witness checks the new exact peak separately.

`c01-native-value-read-into.log` compiles and runs eleven focused cases in
9.44 seconds (0.02 seconds runtime), with 839/839 matching: ten pass, one fails.
The failing cache-hit lifetime fixture expects zero provider credit while the
cache still owns 65,616 bytes of aggregate backing after its payload aliases
are dropped. Correct final-owner retirement must be asserted; this is not
permission to change production cache retention. All real admitted point/next,
corruption, output-after-close and zero-allocation pressure cases pass. Root
started the encrypted Store quote selection; broader qualification is pending.

The narrow test-only final-owner correction is preserved at
`/tmp/kasumi-native-value-read-into-tail-test-v1/native-value-read-into-tail-test-v1.patch`
(SHA-256 `05da3846830a5e8d9faacc2c4e12232a891d6a6f05f49f13f738d87edba8af57`;
manifest `99f79fbcdf4655213be55206763c2177a07c417d3dfbcad709dfc33b4f5d9b30`).
Root verified all 839 current hashes and five saved/live dependencies before
applying it. The test now drops the actual cache owner, checks exact guard-only
pool backing, proves no refund on the first alias, and zero after the last.

`c01-native-value-read-into-regressions.log` PASSED all 534 native unit tests and
27 selected cache-allocation, crash-recovery, owner-fencing and rollback
integration tests in 14.25 seconds, with 839/839 matching hashes. The four
encrypted Store quote cases also PASS in
`c01-native-value-read-into-store-quotes.log` (16.93 seconds, 3.71 seconds runtime,
839/839 matching). They observe the exact smaller value peak while keeping the
unchanged conservative quote. `c04-ordered-command-envelope-native-default-check.log`
PASSES default Engine compilation in 7.60 seconds with 839/839 matching and the
two existing audit warnings. The latter two checks precede only the native test
correction and temporary diagnostic edits; no production native change follows.

The second reviewed, failure-only source-admission diagnostic came from
`/tmp/kasumi-retirement-source-admission-diagnostic-v1/retirement-source-admission-diagnostic-v1.patch`
(SHA-256 `2b9ef195420a3f83fca0dbe4810be8ddddd4487fcd65b9072665b44af1e63be5`;
manifest `f523301c72d854eac7bb1114b2270a9b6d89f39e66091d1173b4961f62de79d8`).
All 839 prior hashes and fourteen saved/live dependencies matched. The fixed
ledger observations are copied at the exact failed admission and printed only
after releasing its lock, without changing the predicate or original error.

`c04-retirement-source-admission-diagnostic.log` FAILS in 27.23 seconds
(6.19 seconds runtime), with 839/839 matching. The refused request is the
8,192-byte canonical planned source cell, before proof admission; compiled
RootPreparation=456 and Cell=1,240. Charged=559,351,738; with the request this is
559,359,930. Required cache headroom=67,108,864 raises the obligation to
626,468,794 versus configured maximum=588,277,056, a deficit of 38,191,738.
Ordinary protected bytes are zero in this case. The ledger has 35 live slots of
4,096 with free slots, two operations of 64, resident=47,693,824 below
high=68,719,476,736, pressured=false and usable=true. Charge origins are ordinary
operation 495,783,936 across four charges, other ordinary 61,118,554 across 26,
and document source 19,744 across five; other origins are zero. This establishes
late mandatory publication-capacity failure, not slot or RSS exhaustion. It is
the same category as the separately recorded C06 backup failure, with distinct
amounts and no protected ordinary headroom here. No limit, lease or timeout was
changed, and the read-into optimization does not provide standing capacity.

Both temporary diagnostic patches were then removed by verified reverse
application, restoring the exact pre-diagnostic three-file hashes. Logs and
frozen artifacts remain, with removal custody at
`/tmp/kasumi-retirement-diagnostics-removal-v1`. No further retirement rerun is
justified without a capacity implementation. Strict composed native/Store/Engine
lint is running; all C01–C07 goals remain open.

`c01-native-read-into-composed-clippy.log` PASSED all-feature/all-target
kasumi-kv, kasumi-store and kasumi-engine Clippy with `-D clippy::all` in
41.70 seconds, with 839/839 matching hashes and the existing four audit
dead-code warnings. `c01-native-read-into-composed-fmt.log` PASSED workspace
formatting in 2.42 seconds on the same matching 839-file selection.
`c04-ordered-command-native-composed.log` then PASSED all 60 active selected
Engine mutation, accepted-owner, primary/COW publication, specialized dispatch
and recovery cases in 82.93 seconds (60.95 seconds runtime), with one existing
ignored permanent-receipt capacity cohort and 839/839 matching. This checks the
production native read change together with the production ordinary envelope;
the distinct archival publication-capacity failure remains open.

The causal analysis is frozen at
`/tmp/kasumi-retirement-source-capacity-cause-v1/report.md`
(SHA-256 `9c1742243c5022ae0e01a50dc2864eee492d6436bfb44acf78834afa64307ed5`;
manifest `5d72efce118e939706b11eaa3fc48db012c79a09df479316b937cac8c8081597`).
Root reviewed its arithmetic and actual archive/source call path, and verified
all fourteen saved source/evidence copies against their recorded originals.
Source preparation and its 8 KiB quote are unchanged from the pre-envelope
source. This identifies the measured reservation failure without certifying
every whole-workload allocation or claiming that the archive was rolled back.

Root also reviewed the frozen, source-only broader encrypted point-loan design
at `/tmp/kasumi-encrypted-source-point-loan-design-v1/design.md`
(SHA-256 `4544650d8f49f49a318c85ac1e4caf098dbac33ac3644985fd56bc0d7318bea1`;
manifest `8a7e5c3b598bfd5d62fb3c843b0da9ead2bbb46ef5c8701d191fafe63d4ee550`).
All 37 saved dependencies verify; live differences are the four reviewed narrow
read-into code/comment files and, at review time, the temporary source diagnostic
which has since been removed. The separate review note
`/tmp/kasumi-encrypted-source-point-loan-review-v1/review.md`
(`a90740b42741b5ce45fc2663963d0121232f80dd3288e91fb0c6ac16988769ba`)
qualifies its final sentence: only point-buffer/decode admission can be prepared
up front; cold descriptors retain separate admission. The broader native/Store
loan is not implemented or authorized by the successful narrow cache tests.

The next concrete completion-owner design is frozen at
`/tmp/kasumi-apply-completion-handoff-design-v3/design.md`
(SHA-256 `3a9ba6a59aed102fefdedff3aea97b2498e144c20fc5ddeb76b8a2cdcfb37025`;
manifest `e91b437621162bb11b8d9519b26d3a7b6788ac6ac07f5cb1a43e6df574d61cb2`).
Root verified the final design/manifest, all 26 saved/live production pins,
the final peer review (`52089d5f0a76a438d1ecee61756088abc113cf3e6fba0756936599fa7cd28a59`)
and the exact retained-failure caller review
(`0c922116a80b301e7395b70d8d6b93b2b3fb8b4e99e7e800efea2495255af38f`).
V1 and v2 remain unchanged. No temporary diagnostic source is included.

The proposed first payload is the real production RootPreparation stored before
queuing, captured in place, and retained with the exact SelectedApplication
through the actual outer Raft finish. It specifies constructor-owned standing
credit, fixed response/original observations, atomic failure/unsettled detection,
canonical Single/Ordinary borrowed report inspection without compatibility
fallback, all three construction paths, startup's actual serialized no-reentry
contract, and independent wake registration for cleanup contention. This is a
source-reviewed implementation outline, not implemented or runtime-qualified
custody. It does not fund dynamic publication capacity, arbitrary candidate or
error payloads, promote COW effects, or activate document/index eviction. All
seven goals remain active/open. The final live code/config remains identical
to all 839 hashes from the successful composed Engine run above.

The 2026-10-02 continuation classifies the preceding turn as **progress**:
production command ownership and the direct admitted native read path changed,
their selected runtime/lint/format gates passed, and exact archival admission
evidence determines the required capacity work. Root rechecked all 839 current
code/config hashes and the frozen v3 design before authorizing its isolated
Engine/Raft implementation and disjoint real-resource tests. No completion or
blocked status was set.

The goals document was consolidated from 789 to 210 lines so present production
status is separate from historical partial passes. Its central requirement,
seven closure criteria, budget rules and complete workload matrix are preserved
verbatim. The exact prior text is retained after an archive header in
[`disk-backed-cache-progress-20261002.md`](../../disk-backed-cache-progress-20261002.md),
with original SHA-256
`f720f2e891ec86c687e26feb4ecc6da2fcf07e03550f288d56209381afd21237`.
Relative source links remain valid at the same documentation level. No historical
open obligation, failure or qualification was removed, and no goal was closed.


### 2026-10-02: production ordinary source completion integration

The reviewed completion owner is now applied in production code. The frozen
32-file composition is `/tmp/kasumi-ordinary-source-completion-v1`:
patch SHA-256 `3b7f285772448f433aae97c35fe5968bfe155cee85b01bb2e6ea25213fc154f2`,
manifest `e9266cdef07793b87a93f9f3568571089313736d093c4dda02a55bfe6cd7b507`.
Root verified saved dependencies and exact before/after hashes, applied the
10-file Raft checkpoint first, then the remaining 21 Engine and one Authority
files. Six added Rust files raise the selected code/config count from 839 to
845. Application receipts are retained at
`/tmp/kasumi-ordinary-source-completion-raft-root-application-v1` and
`/tmp/kasumi-ordinary-source-completion-composed-root-application-v1`.

The actual Engine completion allocation holds RootPreparation before queuing
and SelectedApplication through the outer Raft finish. Its standing constructor
quote covers the actual cell, reservation and erased binding allocations. All
three Engine construction paths pair source and completion installation. The
required publisher hook checks the exact installed identity and invocation;
Raft retains the actual response and independent original sink, action,
backend, finish and cleanup observations before acknowledging success. Final
source drain follows stopped writers. Single-error and ordinary reports use
one canonical borrowed inspection API; no compatibility alias is retained.
Cleanup requires positive source ownership/closure evidence. A counted selected
handle is constructed before capture wake callbacks, avoiding a numeric owner
without a corresponding resource if a wake unwinds.

Source review is retained at
`/tmp/kasumi-ordinary-source-completion-peer-review-v1/review.md`
(`82e611140da0532f13cc7cf0fad0cf5eb7e72f5cf1c47bd78bc29ddbb308cd1f`).
The separate one-file mutex-scope correction
`/tmp/kasumi-completion-pending-unlock-v1/pending-unlock.patch`
(`33e82ae5ce02894a855095f5878c2392d66f0319a21b5f879b247f21e118707d`)
releases pending-drain custody before destroying the registered waker. Root
verified and applied it after the initial Raft qualification, with a separate
receipt. Fixed first-wake-panic custody covers entered wake callbacks; arbitrary
waker clone/drop destructors remain outside that narrow guarantee.

`c04-ordinary-completion-raft-checkpoint-check.log` PASSES Raft all-feature,
all-target compilation in 16.25 seconds with 842/842 matching hashes. The
following `c04-ordinary-completion-raft-checkpoint-tests.log` is **interrupted,
not a full-suite pass**: 157 of 159 tests emitted passing results, including
all six new completion protocol tests, with no individual failed-test result.
Root stopped its own test process at 666.37 seconds while the unchanged
`retirement_recovery_crosses_former_seed_count_ceiling_without_promoting_a_tail`
and `permanent_custody_exceeds_former_count_and_snapshot_ceilings_and_reopens`
were still running. The runner exited 101 with 842/842 matching source hashes.
Both test completions remain unverified. Their source-only cost review is
`/tmp/kasumi-completion-raft-long-tests-source-review-v1/report.md`
(`530a7fde0a631ce734831ec2356a5ed128c271d527ce18d3764ea0b13e25dd01`):
neither enters the new completion path. The review identifies substantial
crypto, scratch I/O, repeated validation and memory-backend copying, without
claiming a measured bottleneck, deadlock diagnosis or runtime result.

The first integrated Engine/Raft/Authority all-feature/all-target check
(`c04-ordinary-completion-integrated-check.log`) FAILS at 98.82 seconds with
845/845 matching: the new ordered-command code omitted the anyhow Context
trait import. Root applied the two-import-only correction preserved at
`/tmp/kasumi-completion-import-fix-v1/imports.patch`
(`8268ddd47265de3220337c834fdcff4d973d4306d363ac804c12b25a385ade1f`),
including cfg(test) on the now test-only PreparedOrderedCommand import.
The retry (`c04-ordinary-completion-integrated-check-v2.log`) FAILS at 54.35
seconds, 845/845 matching: four new test expect_err calls require Debug on the
successful AppliedResponse type. Production compilation reached the existing
audit dead-code warnings; this does not constitute an all-target pass.

This slice does not fund mandatory current/next source capacity, arbitrary
candidate/error payloads, or activate disk-backed document/index serving. The
new Raft protocol fixture uses a fixture allocation owner rather than proving
installed MemoryCore admission; actual Engine constructor/tail tests provide a
separate, narrower qualification. The retained startup-census cancellation case
must not be read as positive joined shutdown after facade loss. All C01–C07
remain open, and the documented large full-resident cache requirement is
unchanged.

The test-only explicit-error-match correction is frozen at
`/tmp/kasumi-completion-test-error-match-v1/completion-test-error-match-v1.patch`
(`7affab45652a1a6bb214291b49f0d8132579f71ecd7792ac504fb4cb158b74b0`).
Root checked exact saved/live/dependency hashes and retained the application
receipt. It preserves original error ownership and assertions without adding
Debug to a production response API. The third integrated check,
`c04-ordinary-completion-integrated-check-v3.log`, PASSES Engine/Raft/Authority
all-feature/all-target compilation in 43.64 seconds with 845/845 matching.
Warnings include the existing audit fields and one newly unused test-only
retirement-witness observation, to be resolved before the final focused gates.
This check does not yet qualify runtime behavior.

The separate workspace caller audit is
`/tmp/kasumi-completion-caller-audit-v1/report.md`
(`21dfa4241f32770043a053777706756d1b6c5dd6c032d14a7e164ca630279ae0`):
no concrete production completion/report migration omission was found across
15 workspace crates and 826 Rust files. It is source-only evidence. The focused
regression selection is pinned at
`/tmp/kasumi-ordinary-completion-regression-selection-v1/selection.md`
(`2fe5e0de23f341a53ef91f1834d8b3c19cc4acbe565d21174f9d33daadf74026`),
with source-counted unions of 70 Engine, 57 Raft and eight Authority cases.
Runtime counts and outcomes, rather than source counts, control qualification.

`c04-ordinary-completion-engine-new-tests.log` PASSES all 11 new Engine tests
(37.84 seconds runtime, 243.87 seconds including compilation), with 845/845
matching source hashes. This includes actual source retention through outer
finish, real write-waiter cancellation, unchanged-source Frozen publication,
checkpoint failures, independent wake panic custody and actual allocation-tail
checks. The recorded scope caveats above still apply.

After that run exited, root applied the four-line positive cleanup assertion
from `/tmp/kasumi-completion-cleanup-witness-v1/completion-cleanup-witness-v1.patch`
(`8d279da0ed586ed0377dcbb210d84b16e46415beabf881043b470ef73d08f629`),
verifying exact before/after/dependency hashes. The existing last-selected-owner
test now also requires the actual completion to be Settled with no preparation,
queued reader, selected cell or retirement witness. This meaningfully uses the
previously unused test observation instead of suppressing its warning. The
composition is undergoing the focused Engine/Raft/Authority regression gate.

The focused composition run (`c04-ordinary-completion-composed-regressions.log`)
FAILS overall: Authority passes all eight selected tests; Engine passes 69 of
70, including all 11 completion tests and the stronger settled-owner assertion.
The existing foreign-core constructor test fails a whole-admission-ledger
stability assertion: reserved bytes after=121,680,972 versus before=121,656,020.
The expected foreign-core error itself matched. Cargo stopped before executing
the 57 selected Raft tests. Engine runtime was 116.40 seconds; total run 426.64
seconds, with 845/845 matching. This is not a 135-test pass.

The unchanged-source exact constructor recheck
(`c04-ordinary-completion-constructor-failure-recheck.log`) also FAILS, now with
reserved bytes after=121,612,524 versus before=121,680,972. Runtime 2.36 seconds,
runner 4.31 seconds, 845/845 matching. Opposite charge movement warrants a
source-based investigation of independently active fixture owners, without
assuming a completion leak or weakening the before-effects requirement.

The separately executed final-source Raft selection
(`c04-ordinary-completion-final-raft-regressions.log`) PASSES all 57 tests in
3.09 seconds (4.27 seconds including Cargo), with 845/845 matching. This includes
new completion protocol, original error custody, existing plain publication,
real storage publication and startup/source lifecycle regressions. Zero-test
Authority/Engine harnesses in this command are not additional coverage. The
constructor failure remains open while strict component lint runs.

`c04-ordinary-completion-composed-clippy.log` FAILS solely on the new completion
fixture's needless `Ok(helper(...)?)` wrapper, after 147.62 seconds with 845/845
matching hashes. Existing audit warnings remain. The default three-component
library check (`c04-ordinary-completion-default-check.log`) PASSES in 43.24
seconds, 845/845 matching, but exposes nine new Raft dead-code warnings: report
payload access, borrowed views and inspection wake machinery are unreachable
outside test/test-utils entry points. The original Single/Ordinary report types
are already unconditional public exports; ordinary Error::source intentionally
cannot lend report-locked originals. A canonical production inspection entry
point is therefore required rather than suppressing these warnings.

Root applied the reviewed test-only correction from
`/tmp/kasumi-construction-quiescence-v1/construction-quiescence-v1.patch`
(`fe4d413db1ec7ade01b0a869921907181b5e89a335496b1fef0fb0a2abaa3063`),
with exact two-file before/after checks, 14 dependency pins and a separate root
receipt. The constructor fixture's actual audit maintenance performs encrypted
pending-record reads even when empty, on a blocking worker independent of the
rejected constructor call. Existing audit quiescence guards now enclose every
original byte/slot/disk/key assertion, then release before shutdown. The dormant
cache-warmer premise is asserted. No equality was relaxed, cache disabled, cap
increased, sleep inserted or production constructor changed. Numerical delta
attribution to individual allocations remains unmeasured. The second file
returns the same completion helper Result directly to resolve the Clippy error.
Runtime verification of these corrections remains pending here.

The next standing-source-capacity design is frozen at
`/tmp/kasumi-standing-source-capacity-design-v2/design.md`
(`c2ebc23250d68d09102b8a46e5968addd5fc0a769191aba2d147c71669dae047`),
with root-verified 42 saved/live dependencies. V1 and its corrective review are
preserved. Final source review is
`/tmp/kasumi-standing-source-capacity-review-v2/review.md`
(`dbbde4ed13ab9b91c49cf0f9c8fd8c6e228e53f1b7e208906b197ee1b4be7d87`).
This remains a design, not implementation or capacity evidence. It separates
closed internal validation/apply borrows from future history-funded public
escapes: a new admission refusal must not silently skip any of eight existing
continuity checks. It also retains the real census/bank/governor custody cycle
and requires explicit post-worker drain; facade disappearance is not collection.
The useful implementation sequence is the production borrower migration, one
shared actual prepared encrypted planner/capture path, then complete standing
capacity/history exchange and proved precommit/recovery coverage on all replicas.
A pair of prepaid Cells or an unused shadow bank would not fix mandatory source
availability. No C01–C07 goal closes from this design.

The canonical production report interface is applied from
`/tmp/kasumi-completion-production-report-v1/canonical-report-api.patch`
(`ca70f3e0c5ac38cc9f2f762a4b62e3739d8fd8b9be205d8d3f7afc38c9e49f0c`;
manifest `fb05d7cc3baf86d090bf5e57161d6baf4f1cde03dc14c75e3a4042e581112dd8`).
Root verified exact five-file before/after states, seven dependency pins and the
composed caller audit. SnapshotBufferOwner and RaftGroup now unconditionally
expose `try_with_retained_apply_report`; all seven calls across three Engine
fixtures use that canonical API, and the old fixture name is absent from
workspace Rust. The callback, report custody and state/layout are unchanged.
Documentation distinguishes Busy from absence and prohibits waiting for a
worker/drain while borrowing its report. There is no compatibility alias.

`c04-ordinary-completion-final-fmt.log` PASSES workspace formatting in 3.36
seconds with 845/845 matching. On that same final selection,
`c04-ordinary-completion-final-tests.log` PASSES all 13 selected Engine tests
(20.96 seconds) and all 57 selected Raft tests (1.95 seconds), total 65.00 seconds
including compilation, 845/845 matching. Engine includes all 11 completion
cases, the corrected foreign-core constructor test with unchanged exact
assertions, and the renamed real-context-substitution report caller. This
qualifies the corrections; it is not a rerun of the full 135-test union. The
other 57 Engine tests and eight Authority tests passed before the subsequent
wrapper visibility/caller-name and test-only corrections, at their recorded
source pins. Known backup/archive capacity failures and both interrupted large
Raft cases remain open. Final strict lint/default checks are pending here.

`c04-ordinary-completion-final-clippy.log` PASSES all-feature/all-target
Engine/Raft/Authority Clippy with `--no-deps -- -D clippy::all` in 33.91 seconds,
845/845 matching. Only the four preexisting audit dead-code warnings remain;
this is not the repository-wide `-D warnings` release gate. The final default
library check (`c04-ordinary-completion-final-default-check.log`) PASSES in
7.29 seconds, 845/845 matching. All nine newly exposed default Raft warnings
are gone through real production API reachability; no lint suppression was
introduced. Its two Engine audit warnings predate this work.

This continuation is **progress**: production ordinary source completion,
paired installation, original-outcome custody and canonical production report
inspection are implemented and have the focused final checks above. All final
checks use the same 845 selected code/config files, with no live Rust/Cargo
mutations during any build/test process. Earlier failed and interrupted runs
are retained. The constructor fixture race is resolved by an actual existing
quiescence boundary; it does not change production cache policy or budgets.

All C01–C07 goals remain active/open. The application still serves resident
all-document maps and resident structured/text indexes. Complete standing
source capacity, prepared encrypted source loans, primary production serving,
full-residency/over-budget feature parity and final release/workload gates are
not implemented or certified by these completion checks. The next production
prerequisite follows the source-reviewed v2 borrower/read/capacity sequence;
no extra shadow bank, larger cap, revised lease/deadline, compatibility path or
reinterpreted archival success has been introduced.


## Closed validation borrows and directory read-into (2026-10-02)

The preceding continuation was **progress**, not completion. This continuation
implements the next closed-borrow prerequisite and removes another unnecessary
native read allocation. All C01–C07 remain open; the large-cache/full-residency
contract is unchanged. Initial inspection matched all 845 previously selected
source/config files. The combined implementation adds three Rust files, bringing
the selection to 848. Root alone runs Cargo in the existing warm target; no live
Rust/Cargo edits occur while a build or test process is active.

The initial Engine artifact is
`/tmp/kasumi-closed-validation-baseline-v1/closed-validation-baseline-v1.patch`
(SHA-256 `2b6e963e5d4346f49beb6b2289bd3c5901ef5ddf9bc9332ec6f1aa7a179d881d`;
manifest `8419ff0df299936bf621248de718b4ad084162a3d3689e9905f9064146da3e27`).
Root verified 229 saved/live dependencies and all 12 before/after files. The
source-only caller review is preserved at
`/tmp/kasumi-validation-baseline-caller-review-v1/review.md`
(`671f75a4ee5ae7b443659d272a0e35fe5b1cd7e228b8c19a806d3c2dbf2d558a`).

All eight continuity checks now borrow one exact prior Generation. Only actual
uninitialized-engine construction can supply absence; access/acquisition/poison
failures cannot. Standalone validation captures once before input; the streaming
worker owns its capture before framing inspection. Restore owns the actual
ApplyOwner through publication, and ordered retirement derives its seed from
that owner's prior. Bootstrap paths and the nested fixture snapshot serializer
also use their held prior. Public history admission remains unchanged. The
streaming worker's cancellation lifetime is source-reviewed, not newly qualified
by an explicit async cancellation test.

`c04-closed-validation-baseline-tests.log` FAILS compilation in 41.74 seconds,
847/847 matching, before any runtime case: the new test file lacks a required
SnapshotFixture trait import and has one Arc/`?` coercion error. The applied
three-hunk test-only correction is
`/tmp/kasumi-validation-test-compile-fix-v2/validation-test-compile-fix-v2.patch`
(`4ff243ed13b5c1ec7da3d529fb2a7b22214f4916c52c7e8c6c1c85a531f94659`).
It also replaces err().expect() with an explicit match. The earlier frozen
err-match-only v1 was never applied.

`c04-closed-validation-baseline-tests-repaired.log` compiles but FAILS 3/14
cases in 61.41 seconds (runtime 5.79), 848/848 matching. All eight permanent
history groups and actual prepared-restore ownership pass. One failure is a
test's formatted-error expectation, repaired by exact typed code/message
assertions in patch `9abea278d23107f781881421afee80b709ff15916f08a646f4984d3be7bb2e5f`
(`/tmp/kasumi-validation-foreign-error-v1/validation-foreign-error-v1.patch`).
The other two reveal a missed production borrower: prepare_command_ordered
calls check_operation_access, which still reacquires public generation while
holding ApplyOwner. The tests' zero-public-escape assertions are retained.

The production follow-up
`/tmp/kasumi-ordered-access-borrow-v1/ordered-access-borrow-v1.patch`
(`5e7ce1d67050942958bbaf4542dc55c48c6756f72fbf5ddf76c791ac97737d8d`;
manifest `314e146d8f1f04ff17b3b5c6bc3453bdf54d8b60cea26fb79a25fab11633ce8d`)
shares the access predicate over the exact held prior, preserving fresh current
access/presence checks, target activation and restricted restore-completion
checks. Service preflight captures once outside apply. Ten saved/live dependencies
and the one-file before/after matched. `c04-closed-validation-ordered-access-tests.log`
then PASSES all 14 cases in 67.89 seconds (runtime 7.66), 848/848 matching. No
probe was loosened to permit a public generation call under ordered apply.

The native artifact
`/tmp/kasumi-directory-read-into-v1/directory-read-into-v1.patch`
(`afe5c240270394db67b829f7fdcc5261938d2bc777fb07dc30631be663319fc8`;
manifest `e2a53ac6800429182025d50b1a4f6eada39f61a6d4bed37b7f77b517d443bdb6`)
changes five files after 20 saved/live dependency checks. Normal directory reads
use existing load_or_read_into demand policy: fitting pages remain retained;
optional retention refusal fills the already-admitted page. Cached length/digest
and owner checks precede copying. Backend capacity and I/O errors remain original
loader errors, with no second read. The shared-output page helper is now used only
by existing test fixtures. Numerical aggregate quotes remain conservative and
unchanged; comments and the actual encrypted Store allocation witness distinguish
them from the smaller current peak.

`c01-directory-read-into-regressions.log` FAILS one of 539 unit tests in 22.15
seconds (runtime 6.24), 848/848 matching; the other 538 pass, and Cargo stops
before integrations. The new cold-read allocator assertion observes two
allocations. The first `c01-directory-read-into-lock-diagnostic.log` was accidentally
launched after an artifact precheck refused application; it simply repeats the
original failure in 2.03 seconds and contains no applied diagnostic.

After actual diagnostic patch
`7194c68e6fcec9449bfde929d0ec460e71be6a947613f06d249d6449fa68894b`
(`/tmp/kasumi-directory-read-into-lock-diagnostic-v1/`),
`c01-directory-read-into-lock-diagnostic-applied.log` PASSES in 8.91 seconds,
848/848 matching. Each zero-cache, tiny-cache and provider-refusal arm observes
one allocation on the first cache-control mutex access and one on the fixture's
first expiry-control mutex access. Initializing those controls performs zero
page reads, leaves cache statistics empty and provider credit unchanged. The
subsequent still-cold directory read has exactly zero allocations and zero extra
workspace requests. This measures fixed first-use control backing separately;
it is not a complete process/control-allocation accounting proof.

The final test-only setup patch
`a403166f9d095bae01200efc03a6aeaa500d5fc5b3aaa099b3aa2754cd9c8a58`
(`/tmp/kasumi-directory-read-into-lock-setup-v1/`) removes diagnostic printing and
phase counters, preserving control-only initialization, cold data, all exact
zero assertions and unchanged budgets. `c01-directory-read-into-final-regressions.log`
PASSES 539 native unit and 27 selected allocation/crash/owner-fencing/rollback
integration cases in 34.52 seconds, 848/848 matching. The fitting multilevel
600-row directory retains every page and repeated reads perform no backend I/O.

`c01-directory-read-into-store-quotes.log` PASSES all four real encrypted Store
quote cases in 14.11 seconds (runtime 1.34), 848/848 matching. They prove the
current two-lease directory peak and absence of both former temporary payload
requests while retaining the conservative quote. This precedes only the later
Engine access/test corrections and native test-only control setup; it is not
qualification of encrypted prepared loans or standing postcommit availability.

Complete encrypted prepared planner/capture ownership, public history funding,
all-replica capacity admission, primary/index disk serving and end-to-end memory
qualification remain open. Existing archive/backup capacity failures, broader
recovery failures and two interrupted large Raft cases remain unresolved. No cap,
headroom, lease, deadline, compatibility reader or cache eviction policy changed.


### Broader Engine failures and exact preceding-source comparison

`c04-closed-validation-final-engine-regressions.log` FAILS: 70/80 pass,
10 fail, in 214.35 seconds (runtime 213.05), 848/848 matching. All 14 new
validation-baseline cases and the selected ordinary-completion and ordered-command
cases pass. Four snapshot-bundle cases fail during install_storage_access at the
shared fixture, before their bundle semantics, with scratch capacity denied. The
metadata-restore case fails its second fixture mutation with scratch broken-pipe
and retained close custody, before restore validation. The application-backup
negative hides its actual error behind a Control-state substring assertion.
Local reopen reports document-source retention exhaustion; serving expiry retains
shutdown custody before reopen. Replicated reopen reports an unlabelled timeout.
The large public restore reaches backup verification's unchanged deadline.
No claim that these failures are harmless or repaired follows from the narrower
14-case success.

Root compared five representative failures with the exact preceding 845-source
selection. All 17 changed/new paths in this tranche were saved with their current
hashes; immutable original files reconstructed the prior selection, including
removing only the three newly added files temporarily. Every prior hash matched.
After the test, the finally path restored the full 848-source candidate and
verified every candidate hash. The save/restore receipt is
`/tmp/kasumi-closed-borrow-baseline-comparison-v1/restored.json`.
No Git reset, staging, alternate target or limit adjustment was used.

`c04-closed-borrow-prior845-failure-comparison.log` FAILS all five selected cases
in 263.37 seconds (runtime 31.30), 845/845 matching, with the same failure forms:
application-backup Control-state assertion, metadata-restore scratch broken pipe,
Control archive-transfer fixture capacity denial, local-reopen source retention
exhaustion and serving-expiry retained shutdown. These five failure forms predate
this tranche. The comparison does not qualify the remaining five failures or
supply a fix. The fixture source review is saved at
`/tmp/kasumi-snapshot-bundle-failure-review-v1/review.md`
(SHA-256 `c2798a4b9a9c768eeda6a098e6eb4b84e2fa68ebce2eb99e37ef0e98db7eb7da`).

The failure-only local/serving diagnostic
`/tmp/kasumi-reopen-failure-diagnostic-v1/reopen-failure-diagnostic-v1.patch`
(SHA-256 `4616085278214682504d1ea3ff24cba52c498ae68e98bbde0153cde3119ad2b8`)
adds context to three local startup/administration boundaries and prints the
original serving drain report on the existing failing assertion. All original
assertions, limits and deadlines remain unchanged. Root verified ten dependencies
and both before/after files before application. Runtime diagnosis is pending.


The first affected component Clippy run,
`c04-closed-validation-final-component-clippy.log`, FAILS in 47.89 seconds,
848/848 matching, on one new test-only needless borrow in snapshot_bundle's
fixture helper. Root removed the redundant reference; exact before/after and
patch are saved in `/tmp/kasumi-validation-clippy-borrow-fix-v1/` (patch SHA-256
`3d15575b976a46ee280b79c6fdc1c853c3b87ff9df7e1c82d69362ef97617ce5`).
The existing security-audit dead-code warnings remain separate from this lint.

Additional failure-only diagnostics are applied after saved/live dependency and
before/after verification: replicated phase context v2 (six dependencies, patch
`912fb3de45c34de5f5838e56d131020ce98c1d7b9fe7608c3e8f4b321e44afef`, manifest
`cc025945db3ddebe62e3f810c06b0391abf1fe460218f2594cda9fd777266b0f`), and
capacity diagnostics v2 (14 dependencies, patch
`5c7b1ff3c4be085098801552f008f35a5df03796f20b4eb0b1c187403b089bba`, manifest
`88efcebc51d6b404a745448fdcc3a8515dd07c4ce59b931dce3f09341559c79a`).
Artifacts are `/tmp/kasumi-replicated-reopen-phase-context-v2/` and
`/tmp/kasumi-capacity-failure-diagnostics-v2/`. Their v1 artifacts were not applied.
The provider emits scalar refusal state after unlocking, ignores stderr-write
failure and returns the original OutOfMemory error. The codec assertion preserves
its predicate and shows the original error. None changes successful behavior,
limits, deadlines or assertions.

Source review of the large restore confirms each 60-second deadline begins inside
its own prepare_snapshot_restore call, after row construction and snapshot capture.
Its prior timeout cannot be explained as setup consuming that deadline; worker
scheduling and verification still need measurement. The metadata scratch fixture
uses an isolated device owner; evidence does not support a shared installed-device
poison explanation.


`c04-closed-validation-failure-diagnostics.log` FAILS all nine selected cases in
257.85 seconds (runtime 57.18), 848/848 matching. The diagnostics narrow the
failure stages without changing their outcomes:

- Six exact TestDiskMemory refusals have **32/32 live reservation slots**, below
  the unchanged 67,108,864-byte cap. Metadata/codec each request 82,192 bytes,
  charged 86,304, with 4,767,283 used plus 24,184 bookkeeping; prospective total
  is 4,877,771. The four bundle fixtures each request 143,432, charged 147,544,
  with 55,186,739 used plus 24,184 bookkeeping; prospective total is 55,358,467.
  This proves slot exhaustion for these observed refusals, not byte pressure.
  Concurrent output identifies exact provider pointers; the two small-footprint
  errors have identical measurements, so pointer-to-test attribution is not
  independently claimed beyond the two failing metadata/codec fixtures.
- Codec's original failure is also scratch setup broken pipe with retained close,
  before its expected Control-state rejection. The original capacity cause's
  conversion into later broken pipe still needs tracing; the assertion remains.
- Local reopen fails **initial Database startup**, not reopen, with document-source
  retention exhaustion.
- Serving expiry's full shutdown report contains OpenRaft runtime storage failure
  plus a retained original Raft apply failure. The original apply report needs
  inspection before choosing a repair; Retained remains Retained.
- Replicated reopen times out waiting for replacement voters to apply the
  collection revision and membership, **before its first close**. It is not yet
  evidence of a reopen failure. The exact replica/retained apply stage remains
  unresolved.

No cap, reservation count, deadline or assertion changed. These measurements are
not repaired tests and do not close any goal. The separate large public-restore
verification timeout was not rerun in this diagnostic selection.


### Restore publication retirement order

Source review identified a real new ownership issue: PreparedTenantRestore's
publish destructuring moved ApplyOwner into a later local, which dropped before
candidate/installation cleanup on errors. The applied two-file fix leaves the
owner in the partially moved box until moved locals and all preceding fields
retire. Artifact `/tmp/kasumi-restore-publish-drop-order-v1/` has patch SHA-256
`78955710bc1f1a8bc88742c94f3cfd7000db1f11303fc9802f6dc9cd49287d57` and manifest
`09598675adb105a30424f96461f73a38c1e05b5fde429e015de36e6219b5fea7`.
Root verified all 17 saved/live dependencies and both before/after files.

The regression prepares an actual restore, seals the real Store before publishing,
and observes a weak candidate index owner plus the exact apply mutex after the
installation/write fields retire. It preserves the real sealed-access error.
`c04-restore-publish-drop-order-negative-control.log` deliberately restores only
the old moved-owner binding while retaining the new regression. It FAILS exactly
as intended: candidate_retired=true with apply_lock=Available, expected Held.
Runtime 8.32 seconds, total 469.74 seconds, 848/848 matching. The finally path
restored the fixed production state exactly (SHA-256
`c37d4ad19ba12bb92843694bf1ea0f5f85b810502219b95d7ef2354da4b7368b`), with receipt
`/tmp/kasumi-restore-publish-negative-control-v1/restored.json`.
This proves the regression detects the original error; fixed-source runtime and
final component gates are still pending. No other actionable issue was found in
the scoped borrower/async/ordered-access source review.

Next failure-only retained-apply inspection is prepared but **not applied** at
`/tmp/kasumi-retained-apply-failure-observation-v1/` (manifest
`347fe6308b03741f6132083c4cd3021e92d63ebcbc954f357b3890866e1fae3e`). It borrows
actual reports without retrying, clearing or waiting under that borrow. A separate
scratch workspace repair is being prepared after source tracing showed that a
provider capacity refusal marks an entered transaction failed, and its subsequent
finish call replaces the original refusal with BrokenPipe. Neither pending
artifact is counted as a repair or a passing qualification.


## Implementation continuation and refined completion milestones (2026-10-02)

The user requested finishing the implementation and refining its goals. The goal
API returned no current goal, so a new unbudgeted active goal was set explicitly
around complete full residency below the accounted bound, canonical disk documents
and indexes, precommit capacity, feature/security/lifecycle preservation, and final
C01–C07 evidence. The goal document now divides remaining production work into
M01–M07 with concrete activation and acceptance gates; all C goals remain open.

`c04-restore-publish-final-owner-regressions.log` PASSES all 32 selected cases in
198.27 seconds (runtime 95.75), 848/848 matching. This includes all 15 validation-
baseline cases, the actual failed-publication retirement regression, ordered input
and ordinary completion checks. Root reaped the process and verified every current
selected file against that successful run before applying new changes. The broader
70/80 run is still failed; the successful selection does not replace it.

The retained-apply diagnostic artifact is now applied after verifying its nine
saved/live dependencies and three files. The separate source-reviewed scratch
workspace artifact `/tmp/kasumi-scratch-workspace-denial-v1/` is also applied:
patch `1b38c21c84dcf6d3edf0d10685dcd68c4c74998b3b7a8a3ac14a12c3526e907b`, manifest
`3ecee71cc1e1e8a9981432aeb48e72772b101c698099502e936f3f5dddb426ca`, 20 dependencies,
four files including one new test module, making 849 source/config files. Runtime
qualification and its original-source negative control are in progress. Budgets,
slot counts and deadlines remain unchanged.


The first scratch negative control failed compilation only:
`c04-scratch-workspace-denial-negative-control.log` (37.46 seconds, 849/849).
The new test called is_capacity_denied on CommitError instead of its public
StorageError field. Root corrected only that assertion to error.0.is_capacity_denied();
current test SHA-256 is `7983737bc61f2ba1c344f31cb900efe6bdaa39e6768a98188aa179658ed3808c`.

`c04-scratch-workspace-denial-negative-control-repaired.log` then FAILS exactly
the intended runtime assertion in 151.47 seconds (runtime 1.77), 849/849: after
actual encrypted segment preparation and 32/32 slot pressure, commit returns
BrokenPipe instead of typed CapacityDenied. The deliberately observed first
request here is 4,296 bytes, charged 8,408, with 3,749,115 used plus 24,184
bookkeeping under the unchanged 64 MiB cap. This exercises the same entered-
transaction failure path at a different workspace request than the original
82,192-byte metadata fixture refusal. The fixed scratch owner was restored
exactly (SHA `3f924b4e1301be9bf179251df35ec2a5b08e7a82bcd9e169a34c7611a13c398a`).
Its positive scratch/read-quote selection is now running.

The one-file header-order production fix
`/tmp/kasumi-snapshot-header-before-lineage-v1/` is applied after eight dependency
checks: patch `f7f86f1678a7a06989c499778615d9d962de2121d1f1c6c71221efadd3327476`,
manifest `e8b5b00acb570a064f54fe4a80b368156f2e0fbcc050f9938ec3ee9a4a6e4972`.
Structural indexing remains first, and the same complete header checks now reject
invalid application input before constructing unnecessary lineage scratch. Later
validation passes remain intact; the existing Control-state negative is its
pending runtime gate. This is not a replacement for any validation predicate.


`c04-scratch-workspace-denial-regressions.log` PASSES all 56 selected Store
scratch/read-quotation tests in 258.99 seconds (runtime 178.64), 849/849 matching.
The new real encrypted rollback/retry/drain regression passes with the fix;
the existing retained native-failure case still refuses workspace as OwnerFailed.
The larger-than-cache scratch streaming case also completes successfully. This
qualifies the narrow error/rollback repair, not the separate 32-slot fixture
availability problem or complete encrypted prepared-read integration.

`c04-retained-apply-and-header-regressions.log` completes with **1 pass and 2
failures** in 535.19 seconds (runtime 76.37), 849/849 matching. The application
backup rejection test now passes with header validation before lineage staging.
The serving-expiry failure reports the actual ordinary apply ordinal 2: the
domain transaction committed, then access expired before acknowledgment; sink
failed, action/backend/finish returned, cleanup refused Retained, and final drain
returned. This identifies a failure-custody/lifecycle obligation, not permission
to acknowledge an expired request or discard an unknown outcome. The replicated
case failed earlier this time, at the initial leader's linearizable barrier,
before membership changes or close. Its prior membership timeout remains recorded;
neither run demonstrates an actual reopen failure cause or repair.

Explicit empty namespace replacement v3 is applied from
`/tmp/kasumi-empty-namespace-replacement-v3/`: patch
`9cc640c30cb7cd99dcc0cfd439309c950f02fbb16dca380fbe365daf0b37d678`, manifest
`85457ad5caffd4c4b44a10b598b5226f87895ec818aa5ad953dcc8a25e39a342`. Root verified
22 changed files and 11 saved/live dependencies; one new Engine module makes the
selection 850 files. V1 was rejected before application because it also changed
private custody enumeration used by permanent-history validation. V2 preserved
that interface; v3 strengthens the paired rollback test to require the actual
closed native source's DatabaseClosed error. Neither v1 nor v2 was applied.
Independent v3 source review found no actionable issue (review SHA
`1fd1c07b36e3f6738db01634b2e04d4c22304d1282888e354d5ca5e9b0903c09`).

Empty replacements actively clear the named namespace in the paired transaction;
omitted namespaces remain unchanged. Existing identity/duplicate/overlap checks,
atomic metadata publication and pinned roots remain. All public callers use the
canonical replacement API. Four zero-row Engine installation paths no longer
create an otherwise unused encrypted source table. Runtime qualification is in
progress at the existing caps/slots; target write admission and nonempty mandatory
source publication still require their own capacity integration.

`c04-empty-namespace-store-regressions.log` PASSES all 23 selected Store cases
in 411.71 seconds (runtime 245.84), 850/850 matching. Both new explicit-empty
tests pass, as do pinned streamed publication, cross-namespace isolation and
protected bootstrap identity. The broad namespace filter also included a long
filesystem backup cleanup case, which completed successfully. This is Store
qualification; the four original Engine bundle fixtures still require execution.

The fixture terminal owner is now deferred until an actual new terminal row
needs staging. Applied `/tmp/kasumi-lazy-fixture-terminal-owner-v2/`: patch
`7add0fc621e0ca739c41078f709e99c9d81e3c1bd1265b85aa53ac29a695b1ba`, manifest
`0da43f52557d978b17a2fbd0d53a6043dda09e4737e38f0288047399b35907f4`, three files,
13 dependencies. Root rejected v1's private fixture_owner visibility before
application because a sibling staging-capacity test still calls it; v2 keeps
the original visibility and pins those callers. Early missing-prefix validation
and both accepted/resource-rejected terminal staging paths remain intact. The
existing metadata restore now also verifies that collection creation uses no
scratch files or bytes. Its 64 MiB/32-slot limits are unchanged. Engine runtime
qualification of this and the original four bundle fixtures is in progress.

`c04-empty-and-deferred-fixture-engine-regressions.log` completes **17/18** in
162.01 seconds (runtime 8.25), 850/850 matching. All four previously failing
bundle cases now pass at their unchanged bounds, alongside the terminal tests
including both new lazy-owner regressions. The metadata test passes collection
creation and mutation, then fails at its real restore decode: the existing public
mapping reports Corruption/invalid tenant snapshot. A provider diagnostic records
32/32 slots, requested 82,192 bytes, charged 86,304, used 4,767,283, under 64 MiB.
This remaining overlap is not qualified as fixed. The `staging_capacity_tests`
filter matches no test module in this executable; the report claims only the 18
cases actually listed in the log.

Public restore phase diagnostics are applied from
`/tmp/kasumi-public-restore-phase-v1/` (patch
`b2610d85a7d1c34517f80012d1473fe1f751b0f8cf850844ddfc3960340590ae`, manifest
`94e7c994baf8dbbba994aaec212d350774bc1753be06586988dbdbb45cae3f28`; three files,
18 dependency/evidence pins). Existing fixed-label VerificationPhase now covers
public wait/framing/decode/discard and terminal setup/batches. The existing large
restore test enables those diagnostics only with KASUMI_TEST_RESTORE_TRACE=1.
Source shows 512 terminal rows require 64 bounded scratch batch publications,
but current evidence does not establish which phase consumes the deadline.

Root also applied `/tmp/kasumi-replica-barrier-borrow-v1/` (patch
`a0b830231b5d3e0cced5c1e14d93755a97e2743e3e04255612ec65dc4f95411a`, manifest
`fd9fa8543e1b57101ace74207ee523061dc609aca1cdf4ec396a34c9eeb0224d`; one file,
four dependencies). The fixture copies the current leader before awaiting its
barrier, making the metrics read-lock lifetime explicit. On timeout it preserves
the elapsed cause and lazily adds cloned metrics and actual retained apply reports
for each node. This is a pending candidate repair/diagnostic, not a passing
replication claim. Barrier and election deadlines are unchanged.

The first prepared encrypted point session is applied from
`/tmp/kasumi-prepared-point-session-v2/`: manifest
`3017418871897d4529517d8655fac0caf1f31d40e0508777117eecdb6172618d`, patch
`98f068b429e48dda3a81c863ea1433dd28d07ec40b3fcf12d3cf0297a8cb966a`. Fourteen
changed/new files and 23 saved/live dependencies were verified; the selection
now contains 852 files. V1 was refused by the application helper before changes
because it recorded dependency hashes without saved source copies. V2 supplies
those exact copies, verified against both the peer review and live source, with
identical implementation bytes. Peer review SHA:
`3d8f126857bdac2a498b2b247dbd604921b6afcdbd46980ee68c4d7cbdf7d0c9`.

The native workspace reuses admitted directory/output backing through the actual
registered reader. A consuming paired Store session provides zeroizing borrowed
plaintext with current access/identity/authentication checks. The real
PreparedSelectionPlan::for_applied caller uses it with bounds selected from its
Advance/replay branch. The quote accounts for simultaneous directory, output,
plaintext and AAD, including actual provider overhead. Seven new regressions and
existing plan/quote/security checks are undergoing runtime validation. This
activates one M02 slice; wider control preparation, post-durable capture, complete
source/history funding and precommit capacity remain open. No standing pool or
alternative fallback path is activated.

`c04-prepared-point-session-native-store-raft.log` fails compilation in 92.38
seconds, 852/852 matching: the new prepared-point module omitted std::io. Root
reaped the entire command before adding that import. The repaired command,
`c04-prepared-point-session-native-store-raft-import-fixed.log`, completes in
92.52 seconds with 852/852 matching: native 1/1 and Raft 22/22 pass; Store passes
10/13. Real registered encrypted reuse/overlap, snapshots/rotation, denial cleanup,
malformed authentication and both existing selected replay branches pass. Two new
cache/access tests fail early with InvalidInput; the old long-field allocation
census requires a copied field that the shared borrowed parser no longer copies.
Those three failures are under investigation; no full slice qualification is
claimed and the original allocation/accounting obligations remain.

The test-only repair `/tmp/kasumi-prepared-point-test-repair-v1/` is applied:
patch `678439199341bcf2fa1fb189dc504e2369858cb74fa4347f8c898f736a9f0c14`, manifest
`f2cc57b84e61505392d2187f32c215453abcd72e2f541099676f4a78f656f782`, two files and
12 saved/live dependencies. The new cache fixture now installs the same bounded
8 MiB allowance its NodeStore requests; formerly its installed policy allowed
zero and correctly rejected construction. This changes no existing fixture cap
or production policy. The long-field census still requires full admitted AEAD
plaintext allocation and all original budget/security checks; it now also
rejects a redundant payload-sized field copy. Runtime rerun is pending.

`c04-public-restore-phase-observation.log` fails compilation in 167.26 seconds,
852/852 matching: root's new replica diagnostic needs the anyhow::Context trait
import. The import was added after the command was reaped. No restore runtime
or phase timing came from this failed command.

The committed-expiry bridge and final ownership census are now applied together.
Bridge `/tmp/kasumi-trusted-committed-expiry-v2/`: patch
`488be8abdd1d15b565531fd77bc600c4e535522901b4d985e7e4481d21484d60`, manifest
`886c62c73c3142c239e9adc3c974eff4860618fa53f579d982426cd092b21a44`, eight files
and 15 dependencies. Lifecycle `/tmp/kasumi-expiry-lifecycle-v1/`: patch
`64a8abbd944f7e0fae3c03e35601cc48f4f2a30f7b15dbebd886d60588a7b27d`, manifest
`0b0f4490ccf261508580b5d4326a41f1b75ecaec9efabb08246a2f5b44170a76`, four files
and ten dependencies, explicitly based on the bridge. Independent source reviews
are `1d26115d44764a904a9f35b6b1d465e6e0149b99a56883e1abbdfbc97d2e3146` and
`daec9ae8757cc1f87d5ff22442f4cfdd7e2752e01d94816cb5b2d7bd8370f43c`.

Only the actual Store path after a successful paired native commit can mint the
opaque access-denied disposition. The original error remains charged, inspectable
and failed; arbitrary errors or similar context text cannot mint it. Ownership
can retire only after every other producer returned, actual completion/source
drain succeeded and the buffer owner completes a fresh census. Independent
startup/source failures remain retained. The serving test still demands Complete
shutdown, denied late acknowledgments and exact reopened data; when the original
ordinary apply diagnostic is present, it now verifies that exact report and both
stable issue identities. Store crash/reopen and opaque-error negative regressions
cover the bridge. Runtime qualification of the coherent change is in progress.

### Prepared encrypted reads and typed expiry lifecycle: first integrated rerun

`c04-prepared-reads-and-expiry-lifecycle-regressions.log` pins all 852 selected
code/config files unchanged. The integrated Engine selection compiled and ran
11 cases: **8 pass, 3 fail**, 53.81 s runtime / 580.09 s runner including the
build. Four actual source-quote tests, three staged-capacity rules and the
unrelated-expiry-cause rejection pass. Cargo stopped after this failed target;
the selected Store/Raft tests were not executed by this command.

The staged point-capacity case reaches the same real 64 MiB / 32-slot scratch
setup refusal: requested 82,192, charged 86,304, used 4,767,283 bytes, 32/32
reservations. The native constructor-owned write-workspace candidate is still
unapplied and unqualified at this checkpoint.

The replica barrier still fails before its first close. New failure-only
diagnostics show node 1 a Candidate in term 37 with log 0 and no applied log;
nodes 2–4 remain Learners in term 0 without logs or membership. All four actual
retained-apply reports are absent. Copying the metrics leader before awaiting
removes the borrowed-watch-guard hazard, but does not establish a replication
repair. The exact transport/election route remains under investigation.

The serving expiry case now passes its Complete-close and strict original-error
assertions and reaches physical reopen. It fails in the new acquisition's
`existing-census`, reported as a retained **new failed opening** at
`service_serving_tests.rs:168`. This is not evidence that old registry entries
may be discarded or that retention checks should be relaxed. The original
physical acquisition result must be inspected to diagnose it. The complete
expiry/reopen test therefore remains failing.

The next command, `c04-prepared-reads-expiry-and-public-restore-observation`,
uses the same source, `--no-fail-fast`, and the opt-in fixed restore-phase
tracing. Exactly one Engine test is selected so its global tracing subscriber
and phase timings are attributable. Its Store/Raft selections independently
check the prepared-read corrections and typed committed-expiry bridge even if
large restore fails. This entry records a pending run, not a pass.

### Prepared read corrections and typed committed-expiry bridge qualified

`c04-prepared-reads-expiry-and-public-restore-observation.log` finishes with
**13/13 Store and 18/18 Raft checks passing** on all 852 unchanged selected
files. This includes the corrected installed full-fit cache fixtures and
plaintext allocation census, actual committed-expiry token production, strict
completion drain predicates, retained originals and negative unrelated-error
cases. Expected injected panic output belongs to passing custody tests.

The sole Engine case fails earlier than the previously observed restore
preparation deadline: `snapshot_bundle.rs:1149` reports `backup verification
deadline expired` from the source's public snapshot capture. No public restore
phase begins. The 64 terminal-staging batches during fixture construction
total 268306 ms (range 721–15024 ms); those timings do **not** measure
restore verification. Engine runtime is 502.16 s and total runner time 514.10 s.
This retains a concrete capture deadline failure and supplies no successful
large restore qualification or justification to increase its 60 s deadline.

`c07-python-tooling-regressions-current.log` separately passes all **286**
Python tests (104.88 s runner; 45/45 selected script files unchanged). This is
tooling validation, not a Rust/workload or release qualification.

After both commands exited, native directory write-workspace v2 was applied
from manifest `34ae3d92c9696e1e293e77315627c1eacd130a8586280b17d67f8361129c996b`,
patch `2eeed8f8d93c4f6f2e5c7f17685d8a4d77c02c5bb3d740ac2dac9e3904ad4225`
(17 files,26 exact dependencies). Root source review found two missing mutable
slice borrows in v1 before application; v2 corrects both. Independent review
`0596d277a4f2ba49fb6c3f995480c88bb8b50fff3f57ced914cd6016e183b78e`
found no actionable ownership/admission issue. Runtime qualification remains
pending. This replaces the method-time directory scratch grants with one real
operation-specific buffer owner admitted before private effects, retaining the
unchanged cache policy, bounds and corruption/durability checks.

The unused audit job scaffolding cleanup and failure-only serving opening
reporter were also applied with exact source/dependency checks. They do not
change audit persistence/error producers or reinterpret physical reopen
failures. The replica vote trace v1 was refused before mutation because its
frozen dependency copies were not at the manifest-relative paths required by
the application verifier; no replica trace source from that artifact was applied.

### Native write workspace first runtime and test follow-through

`c04-directory-write-workspace-native-regressions.log` compiles the native
refactor and passes **539/542** unit tests (9.77 s runtime /55.76 s runner;
852/852 unchanged source/config pins). All production workspace/fault/cache
cases passed except three test migration omissions: one packing continuation
test reused the newly operation-specific Pack workspace for deletion; the
transaction claim test still expected a post-prepare memory grant; and density
fault coverage still required an arbitrary count of more than ten refusals
from the former multiple-grant topology. None is classified as repaired until
the updated tests execute.

After reaping the run, root applied the test-only follow-through candidate
`/tmp/kasumi-native-workspace-test-followthrough-v1` (patch
`513b9540aad116f55173ea022fa98b64d0dcba3c558b32db2cab7b417bb66266`,
manifest `e4901bf783263c6073bd843e273745022d7f42a6808f7a8426b81e601c01abee`).
The continuation now constructs the actual Edits owner after retiring Pack.
The real transaction-claim backend separately verifies that post-prepare
pressure is never consumed during successful publication, and that an early
refusal has no claim/private effects and retries with the prior state intact.
The density test measures the successful path's real request count, refuses
every position independently and requires every mandatory request to be
exercised, replacing a hardcoded refusal threshold. Caps, rows, physical
assertions, old-root correctness and retry/drain requirements remain.
The complete native rerun is pending.

Replica trace v2 was subsequently applied with the same patch bytes as v1,
after its 12 frozen dependency copies were restored under verified manifest-
relative paths. The failure-only serving original-report diagnostic and opt-in
actual file-close extent observer are also applied. Observer source review
`dd2b0afb3db0905f430d37dd8e3c1e98ad32a06764f4a2abf5ca644730c5b5fc`
found no actionable issue. Its two read-only nofollow samples surround only
a successful real DATA close and precede parent retirement; it never updates
enrollment, adopts a changed extent or replaces the original outcome. An
observed pair does not rule out later allocation drift.

The first native test follow-through passes542/543. Its remaining assertion
incorrectly classified every `reserve_workspace` call as mandatory: two belong
to the existing optional `warm_maintenance_pages` phase after durable publication.
Root preserved that behavior and changed the fault sweep to assert every actual
request position is refused exactly once, requiring both preparation rejection
and successful publication with optional warming refusal. Every branch still
checks cursor/version correctness, same-owner retry and zero final charge.
Patch `1ac0485b983c6ece7ce7b7c50e5a9465b7aaf526d9d21199a6f4b76d34e991b6`
contains this test-only correction; the complete native rerun is pending.

The M03 goal now distinguishes leader proposal, incoming RPC preacceptance,
pre-StateMachine startup and pre-final-chunk snapshot installation. Source-backed
design `e7273cbc63c24386de995580b02474daa396b1903525780ffc2bb374829a7204`
(23 exact source copies in `/tmp/kasumi-m03-predecessor-growth-admission-v1`)
shows existing503/outer transport errors can retry before local acceptance; it
does not implement the actor-consistent ticket or prove standing capacity.

### Native directory write workspace qualified at unit scope

`c04-directory-write-workspace-native-final.log` passes **543/543 native unit
tests**,34.52 s runtime /109.27 s runner, all852 selected code/config files
unchanged. This includes operation-specific workspace constructors, real
transaction-claim publication under late refusal, early denial without effects
and same-owner retry, exhaustive actual density request refusal, all native
full-fit/pressure/cache/refill cases, immutable-root and compaction/failure
coverage. No broader Engine, encrypted physical backend, integration or release
claim is inferred from this unit result. Earlier failed runs remain retained.

The pending `c04-native-workspace-engine-and-operational-regressions` command
uses `KASUMI_TEST_REPLICA_TRACE=1 KASUMI_TEST_FILE_CLOSE_TRACE=1` and
`--no-fail-fast --nocapture`. It selects the two real encrypted scratch pressure
cases, metadata/staged point fixture failures, four previously repaired snapshot
bundle cases, actual audit cancellation/panic tests, and the serving/replica
reopen cases. The source is frozen during compilation/runtime.

### Prepared capture handoff v2 source review

The frozen candidate at `/tmp/kasumi-prepared-capture-handoff-v2` has patch
`d8f7ee871daf55250e889034c4132b4d6ba982b0f630cf8614c9be12bc11c6c9`
and manifest `12a3b7f2a627991bea4862fd08e8d335a85bee3664aeb922af2d19856b576260`.
Independent review `9e2bd8f4d549394aec17d36e38bc9535ddfde0c904c901e2da0b9adae7dc7f84`
verified all 83 frozen copies and found no remaining actionable production
finding. Root reviewed the actual buffer ownership, canonical borrowed decoder,
quote overlap and retirement paths. Application and runtime checks are pending
the current operational run; this review is not a test result.

V1 remains unapplied: a point-workspace destructor panic could replace the
original capture failure or interrupt queued-reader cancellation. V2 records the
body outcome first, catches actual retirement independently, preserves both
originals and continues cancellation. Unknown retirement still reports Retained.
The new fault tests target the real installed reservation by provider, slot and
generation; they do not substitute a fake grant or change capacity. The next
M02 slices are earlier control-planning reuse and a bounded installed terminal
scan sharing the canonical decrypt implementation. M03 still requires complete
standing/history funding and every local preacceptance/recovery boundary.

### Native workspace operational result and next candidates

`c04-native-workspace-engine-and-operational-regressions.log` completed with
**6/10 Engine and 1/2 Store checks passing**, zero matching Raft tests,
714.37 s runner and 852/852 unchanged pins. Engine runtime was 78.15 s; Store
runtime was 1.82 s. The expiry case passes its intended failures, Complete
shutdown and fresh physical reopen. The opt-in close observer prints no extent
anomaly in this run. This does not explain or qualify away the earlier physical
allocation mismatch; no enrollment reconciliation or rejection relaxation was
applied.

The two metadata/staged failures still exhaust 32 reservation slots, now at a
143,432-byte early directory-workspace request. The real Store pressure case
exposes a separate late 8,336-byte request: the arena's header grant is acquired
after private segment synchronization. Audit maintenance fails during its real
record-generation setup at the ordinary 60-second key lease, before reaching
the intended publication panic. Replica vote traces prove requests reach both
followers and advance votes; response deadlines and repeated elections prevent
the initial barrier. Recorded Engine handling precedes durable vote save and
does not prove timely persistence or response delivery.

`c04-prior-binary-isolated-replica-barrier.log` runs only that replica case from
the exact already-built executable. Its JSON sidecar pins binary SHA
`7e109b65360fe05d06c67dafbf3640f42353fbe451c21a07fc074a5c15e203d9`
and the original 852-source build selection. It is explicitly not current-source
qualification. It fails after 38.23 s at replacement-membership convergence:
the initial barrier succeeds, two nodes apply the uniform membership at log 5,
two remain at joint membership log 4, with election churn and no retained apply
failure. The changed failing phase is timing evidence, not a repaired result.

After reaping that run, root applied the reviewed prepared-capture handoff v2,
then terminal-scan v1 (12 files, 29 exact dependencies; patch
`740d115de38d29fcf5d3198905ecee36485b6b56cd39d7a7758b925d42b6bcf5`,
manifest `2e99e93ecddde15a7d4386f990cb48e77c94491e528cd4147b4e060e228bcb28`).
The scan shares one registered root and actual encrypted backing; its source
reduces the exact 512-row route from 2,560 to 1,024 point reads. Throughput is
not yet measured. Engine source review
`9994105237ecf96fe30939ab986a662531391ba6147a0956e3594c8610f0d1dc`
found no acceptance gap. A separately identified prepublication backing-Drop
panic custody repair remains pending before full M02 validation.

Arena write-header v2 is applied (patch
`be7830934d9f399d2fb32cbf4da09a95d099c83b5b63b268cd3e954a014dec02`,
manifest `369b28d682df441ca3748d89b9cb0b1245bb67f4c476ff3827792c03136677b1`).
Its real fixed buffer is charged in the arena constructor and reused under the
writer lock, removing the late header grant. V1 was never applied: independent
review caught a missing owner recheck after waiting for that lock. V2 restores
it and adds a deterministic owner-transition/no-effect test. Independent v2
review `56593fed323f8152e61bd61c0c86d4d5242abad975da493ef80dd0b7ab517f57`
found no remaining issue. The original encrypted pressure test is unchanged.

Test-only operational fixture adjustments (patch
`2ab5486bc8fcbbecce7b21dd3045d061c124bf7f48df81f18126b62a5fca2d2f`)
retire the fully observed independent expiry branch and assert its exact memory
baseline before the separate completion branch. The audit cancellation fixture
uses its existing ordinary lease on a controlled clock during real setup I/O;
its rows, archive limits, cancellation deadlines and panic assertions remain.
The separate committed-expiry tests still advance their clocks and enforce
expiry. None of these pending candidates is a passing operational result.

`c04-arena-owned-header-native-regressions` is now running with all 860 selected
code/config files frozen. Root alone runs Cargo; other changes remain isolated.

The arena-header native gate completed: **545/545 passed**, 13.85 s test
runtime /62.78 s runner, 860/860 unchanged pins. It includes the constructor
refusal, post-lock owner change, first/automatic/forced roll pressure cases and
the full prior native cache, snapshot, transaction and maintenance suite.

Root then applied the reviewed Store point-retirement helper (eight files,
15 exact dependencies; patch
`ee6ca51088a2e7890229b435347be6d91c978abd6af6596227dbd26a69e5c511`,
manifest `434550f40d95418b29d0ba3137eabe34872cbe403840578f54b748ec5ee8ba01`).
Explicit finish keeps the original result outside the actual backing destructor
catch and records the exact panic in the same registered reader before settling
it. Successful transfer keeps backing outside settlement; a settlement error
followed by a destructor panic retains both originals. Three actual lease-Drop
regressions are included. This does not classify the caught panic as successful
resource retirement. Engine's dependent pre-Cell custody change remains pending.

`c04-prepared-capture-terminal-scan-store-raft` is running on 861 frozen source/
config files. It selects the existing and new prepared-point/transfer/retirement
checks, single-domain sessions, selected-application proof checks and both real
encrypted scratch pressure regressions. Runtime results are pending.

That first compile gate failed before running tests (274.13 s; 861/861 pins).
The single-domain test fixture returned `Result<(), DrainFailure>` from an
`anyhow::Result` helper and passed `&Vec` where `Into<Vec<u8>>` requires a slice
or owned vector. Root applied only the missing `?; Ok(())` conversion and
`as_slice()` argument (patch
`9f219d17cc719b2422ab5f2d6ec6b97fbfba1172ece0b04d59ae85147230a555`).
No runtime result is inferred from that failed compile.

The separately reviewed Engine incoming-point custody v1 is now applied
(five files, 35 dependencies; patch
`0988ec02a9b31bd14711099d8108dfa91c32482cd5b947d59a7ad9ae99a2c094`,
manifest `5b4f35ef2cfbecd1bbd7978d4ae3a12b7259eac949aa31fad1c4bdcc163690ed`).
Both actual preparers keep incoming backing outside early errors and callback
panic unwinding until its registered Cell owns it. Failed retirement preserves
both originals through the Store marker, which Cell drain treats as unknown.
Independent review
`b10c7679ce5eb23bcc126200fab50836b32c049e5519d25dc040dcec5cf1d85f`
found no actionable source issue. New tests use actual Entry-produced leases
for foreign identity, sealed preparation, real constructor refusal and duplicate
queue cleanup; runtime qualification remains pending.

Opt-in vote-save observation is also applied (patch
`f69e248b6e43e24c7ec1e4daae771f5881e4daa2340cd22a90c8d04503d212a4`).
It separates submission, entry into the actual Store write, that write's return
and the original async wait's return. It never changes vote persistence or its
result. No phase timing is claimed yet.

`c04-prepared-handoff-scan-and-pressure-current` now runs the combined selected
Store/Raft/Engine gate on 862 frozen source/config files. Replica timing and the
large capture case are deliberately separate later checks after compilation;
their previous failures remain open.

That attempt stopped during Engine test compilation: ten `&Vec<u8>` arguments
in the new terminal-scan fixture did not satisfy `Into<Vec<u8>>`. No tests ran
(385.40 s runner; 862/862 unchanged pins). The fixture-only repair uses owned
generated keys and slices of retained byte vectors, with no assertion or
production change (patch
`222979c5bf3a351cea600fd5dff7d118fb0c6689decf6a194e1838979d98a179`,
manifest `913dd91a79dcf7ced261096fe968d667c72c9efa5ababb29edc694caa7941ecb`).

The reviewed opt-in metadata lease inventory is applied (two files, 25 exact
dependencies; patch
`2e9c3a3121038b1115e442bf65a8096514a0f173d3c5cdc39ceb4db2dec55364`,
manifest `dbeb3baba62ceb4fbe642008822e1ef5a6333e7a8e6f7db514a258700f32d157`).
`KASUMI_TEST_METADATA_LEASE_TRACE=1` observes actual successful reservations,
cache charge changes and destructor refunds after releasing the fixture ledger.
It adds no shadow pool, changes no limit and preserves the original results.
The actual lease identity field is included in the concrete allocation quote.
Fixed receipt-builder phase labels permit an inventory at the first refusal;
neither this observer nor a scalar slot count justifies releasing a still-needed
old receipt generation.

`c04-prepared-handoff-scan-and-pressure-repaired` now reruns the selected gate
with 862 frozen source/config files. Metadata inventory, exact replica timing
and large capture/restore qualification remain separate pending runs.

That integrated run completed on unchanged 862/862 pins: Engine **113/114**
(147.17 s), Raft **24/24** (6.04 s), Store **16/17** (6.15 s), runner 310.51 s.
Both installed terminal scan tests pass, including exact-root isolation,
canonical tamper rejection and final-row settlement. Both actual encrypted
scratch pressure cases pass; the constructor-owned header removes the original
late post-sync grant. Staged capacity and both audit cancellation/panic tests
also pass with their original limits and assertions.

The Engine failure is an actual unwind classification regression in the incoming
backing wrapper: the Queued checkpoint had transferred backing but returned a
SourcePanic error instead of the original unwind. Root applied the reviewed
repair (patch `9abebf06c37306ac2cc356da460b1c5729982bc08419bdf974c3357609358283`,
manifest `18901a0d7b1fc083285ed3406d28ce9afa93ea2982cd272083fc18f2f8f7e009`).
After clean retirement or transfer it resumes the exact original payload;
independent retirement panic still keeps both originals in the combined marker.
A new real Entry-produced backing test checks the original allocation address
and exact admission baseline. Runtime validation remains pending.

The Store failure occurs only at the final test attempt to explicitly retire an
already retired native reader. The existing assertions proved both original
native failure and independent backing-Drop payload. The fixture correction
(patch `3289cce3e5128c9326bd3b6454d7bbf594de955f920faa112e09968152d75175`)
asserts absent native registration, zero reader census and exact byte/slot
baseline after dropping that diagnostic. Production retirement is unchanged.

`c04-metadata-actual-lease-inventory` was intentionally interrupted during
compilation (38.79 s, exit -2, 862/862 pins): selecting only Engine changed Cargo
feature unification and needlessly rebuilt the graph. No tests ran. The following
`c04-metadata-actual-lease-inventory-matched-graph` uses the same three-package
feature selection as the preceding binary, with
`KASUMI_TEST_METADATA_LEASE_TRACE=1`. The exact metadata test fails in 1.27 s
(2.30 s runner; 862/862 unchanged pins). Its saved analysis reconciles every
successful lease and refund without mismatches: 32 live slots, 4,756,651 charged
bytes, 14 preexisting and 18 new receipt-setup owners. Requested 143,432 bytes
is the **new directory encrypted-file backing**, not DirectoryWriteWorkspace
as earlier inferred from size alone. Native directory workspace was already
admitted. The old generation remains legitimately owned. The completed root
validation scope remains live while new files are prepared; its actual lifetime
is the next narrowly identified improvement, without changing limits.

`c04-replica-actual-vote-save-timing` runs the exact replica test alone with
`KASUMI_TEST_REPLICA_TRACE=1`: failure after 31.41 s /32.18 s runner, unchanged
862/862 pins. The initial barrier succeeds. At replacement-membership timeout,
all three replacement voters have the uniform membership and applied log 5,
with no retained apply failure; removed node 2 remains on joint log 4. Engine
metadata publication advances revision, whereas the fixture compares against
the earlier collection-command revision. That stale expected revision is a
separate concrete test issue from the prior initial-election timeouts. Saved
vote timing observations preserve real durable writes and their results;
neither trace timing nor this failure authorizes earlier acknowledgment or
longer deadlines.

The reviewed wider M02 control planner is applied: 23 files, 36 saved exact
dependencies, patch
`7cbec65a6eecc1a6552bba7fd841283a3156de31617f6afc64814ddd409efaee`,
manifest `1b34419b9c805c088802f3cdad57087311e78d5df1fbd534a5b885e8663e6913`.
One actual paired registered root now performs directory extent preflight,
canonical control validation and selection planning. Buffers are sized from
required records; only covered snapshot replay sizes its extra proof records.
The plan quotes real replacement overlap and transfers actual backing before
publication. Length probes are allocation bounds; authenticated loans retain
all identity, security and content checks. Peer review
`dd5a48f76b7fc0dcacbaf123f65642f992f3fccd418687f174ecd4685d1a90cc`
found no source issue in its stated scope. Runtime checks are pending, and
standing source funding, historical transfer and production activation remain
open.


The completed scratch-root validation is now scoped before new encrypted-file
backing admission (two source files, 19 saved dependencies; patch
`b97b8ec1539e091f6e3106ebe71965171d965bc3cf5da14302bd2b72758f9d3f`,
manifest `60dd503b632a82999904f38138a85a672ce977b0a19cfef2fcef11c19255fd61`).
It preserves the same lock, validation predicates and error order, then retires
the actual two root-slot arrays and their lease before preparing new files.
Both old and replacement receipt generations remain owned. The added regression
requires two free slots for two actual files and preserves atomic refusal with
one slot. Independent source review
`7a6118f22f0c8519cf9269fc1dffe920408de6033411ef6c02719d4fc981bc25`
found no actionable issue. Runtime is part of the following integrated check.

The replica fixture now derives the metadata revision from the committed
replacement-membership log and checks unchanged collection contents, instead
of waiting for the obsolete collection-command revision. After shutdown it
retains each actual final applied position and requires exact equality on that
replica's reopen (patch
`67fbe3b207eccd3becb080ae7df090c6f332e7ab5c3b94cf626ff24d5f8dabb6`,
manifest `9e402ec3106fa7b3d510ca3e3f595680657fd381671683d73b0f8c55f6936ed6`).
This corrects the semantic expectation without extending deadlines or reducing
membership. It does not repair any independent initial-election failure.

`c04-control-planner-and-retirement-current` is running on 865 frozen
source/config files. Compilation passed. Engine reaches 23/24 and native 16/16;
the remaining Engine metadata failure is later than its previous refusal.
Three new Raft planner tests pass, while four old synthetic fault fixtures lack
the installed physical owner now required by actual planner backing. Their
explicit-owner fixture correction is frozen and awaiting application. The
100,000-row Raft retirement-seed qualification is still running; Store and final
runner/source-pin results remain pending.

The separate `c04-metadata-post-validation-lifetime` diagnostic executes the
exact already-built Engine test binary with
`KASUMI_TEST_METADATA_LEASE_TRACE=1`. The executable sidecar records SHA
`15e6ee7c8ea6fdc6e70365b211a4e89bf43c600ff37a96385b6173f4cb3af478`
and its matching 865-file build selection. No source or executable changed.
The exact metadata test still fails (1.25 s test / 1.27 s runner), now during the
first receipt point write after table construction completes: requested 12,544
bytes / charged 16,664, with 32 live reservations and 4,887,300 charged bytes.
Saved analysis reconciles all actual lease identities and refunds with zero
mismatches. Nine commit-time owners overlap 23 steady owners. Source tracing
identifies scratch-root validation as the refused owner; the still-live proof,
write, rollback and generation owners cannot simply be released. Consolidating
the directory traversal shell and its page buffer under one actual fully quoted
lease is being implemented separately. The long Raft check was running at the
same time; this is ownership/failure evidence, not a performance measurement.


The 865-file integrated run completed with Engine23/24, native16/16 and
Store42/42 (8.99s Store;952.43s runner;865/865 unchanged pins). Engine's original
unwind and exact payload regression pass, as do Store's transferred retirement
assertion and scratch-root two-slot regression. Raft reported41 passing cases
and four synthetic-owner fixture failures before its100,000-row case was
explicitly interrupted. The exact PID, source diagnosis and interrupted phase
are saved in `c04-control-planner-large-seed-interruption.json`. A live sample
showed the first recovery scan repeatedly loading committed/snapshot metadata
for every uncommitted tail row after fixture construction. This is not a
completed large-case result or a whole-process memory qualification.

Four reviewed artifacts are now applied in dependency order:

- Bounded retained-log inventory: manifest
  `1bd7ba55a32589f43451e2f8bb5d8727135d7db7381ded189809a552e544e42e`,
  patch `775e12a88114489bd9187e401ad11858cd8d2f7b648bc72434472e90e03041ca`,
  three files and24 dependencies. Streaming authenticated header validation
  replaces Kasumi's per-entry BTreeMap/full header collection; reads and cleanup
  enumerate bounded numeric ranges. Independent review
  `d2719e8ead5bf6e0d367cbfb7ca3d684d2bcef4c3ea43c727e08faad0b989025`.
  Vendor term-boundary metadata and requested/accepted Entry outputs remain open.
- Explicit installed physical ownership for four control fault fixtures:
  manifest `af0b1dcc87a33e919526ae2438fd35344b47fa95220b491f7994d93732a0c4fc`,
  patch `3290761fe4bcd240cd54d2181fa4fd50b67f822159deb0ac2806dfd6fa745a1b`,
  one file and12 dependencies. Keeps the existing FaultBackend, crash counts,
  failure loops and assertions. Review
  `2963bea02acb3bdac51e580d85ab2254c83968ca25e0bbeacc595d17bde64944`.
- Protected encrypted source bridge: manifest
  `33d48ea8508adb6dfa0b3a101bb8add4ba7bb73b4a21f8f4411613ddc70550ac`,
  patch `02c9e251b518de4234c6150b49eb29fa358e1d17b4483017a7e2539e2efb76e6`,
  15files and38 dependencies; review
  `6623245abf1337d0de220921e03f1f592b563fd779991812c79fa6fca4dac314`.
  Uses real preowned backing and exact captured/history owner through canonical
  encrypted loans, including current expiry. Producer remains test/test-utils
  gated; this is a prerequisite for production source activation, not M03 closure.
- Gate-stable retirement scan coverage: manifest
  `b31724efce142fa3f645fa07a1806086e7d97cf408f0ce424c0f2fbd98ff2e13`,
  patch `7136b16a59600330f9f6a573b05e013a1139a877971484779664b2e5d1016dcd`,
  one file and six dependencies explicitly composed from the preceding artifacts.
  The first authenticated well-formed seed key lazily resolves coverage once.
  All rows still authenticate, validate key shape and recheck access; covered
  candidates retain the complete original validator. The existing control gate
  excludes concurrent committed/snapshot publication. Independent source review
  found no actionable issue. The unchanged100,000-row case must rerun.

All saved before/after/dependency hashes were checked at application. Initial
helper attempts to apply fixture/bridge patches refused because their saved
sources use `sources/dependencies`; no partial source changes occurred. The
helper now recognizes that directory and still verifies every saved hash and
live dependency. No runtime result is inferred for these four new changes.


DirectoryReadWorkspace aggregation v1 is now applied (seven files, 49 exact
saved dependencies; manifest
`75e9192253931a14c103cf89325c5cd280cbd2a879c5988ee43467d666ad38b5`,
patch `b04932e80f82cf6105727147643279fd2ba0c61e5639984158f11e56672803a2`).
One constructor lease covers its traversal and actual page allocation, retained
until both retire. Shared membership/warming algorithms and current owner checks
are unchanged. Prepared point quotes now count that grant once. Partial-denial
fixtures still deny the actual native output, using three free slots for four
requests within their unchanged 128-slot limit. Exact constructor byte-bound
and single-grant tests were added. Independent review
`7fd27d09ebd93dff62be2538019e72dc62045d169870a721e48a6d6f7390a286`
verified all 63 saved snapshots and found no actionable issue. This addresses
one observed metadata peak; later retained-cache overlap remains to be tested.

`c04-protected-points-log-inventory-workspace` runs the combined selected gate.
Its expanded runner pins 1,528 source/config files, including all vendor Rust and
manifests, the selected toolchain and Cargo configuration in addition to the
previous crate selection. The unchanged large seed test is explicitly skipped
in this focused gate and will run separately after compilation and short checks.
No prior interrupted large case is counted as passed.


### Integrated 1,528-file checks and remaining failure locations

All runs below use the warm `target/disk-backed-cache` lane, the same four-crate
all-feature library graph and the recorded KV/SHA2 profile settings. Every run
completed with all 1,528 source/config pins unchanged. These are focused checks;
none closes a production or whole-process qualification gate.

- `c04-protected-points-log-inventory-workspace`: compilation failed because the
  new protected-source fixture returned the drain result instead of its declared
  anyhow result. The next artifact preserves the shutdown failure with `?` and
  returns `Ok(())`; no assertion changed.
- `c04-protected-points-log-inventory-workspace-repaired`: Engine25/25,
  native27/27, Raft11/12 and Store34/35; 175.01s including148s compilation.
  All three real protected encrypted source bridge tests and the four original
  Raft fault fixtures pass. Raft's remaining fixture incorrectly expected local
  provider revocation alone to invalidate an already issued ManualClock lease;
  it now performs the actual failed refresh before checking rejection, then
  restores authority, refreshes and reads the same entry. Store's remaining
  assertions expected five workspace grants after the canonical aggregation
  reduced the actual quote to four. Both corrections pass the later selection.
- `c04-metadata-directory-workspace-aggregate`: metadata fails its intended final
  assertion after2.23s. The exact first refusal is69680 requested/73800 charged,
  at32slots/2,890,364bytes. The accompanying analysis JSON reconstructs every
  live lease with no mismatches. Completed fixture handles were still retaining
  the original receipt table; retiring them after successful replacement fixes
  that overlap, without retiring a needed source or changing limits.
- `c04-replica-exact-membership-revision-reopen`: replacement membership and full
  close complete. The first existing-replica reopen fails `ResourceExhausted:
  document source retention budget exhausted` (16.48s test,17.52s runner).
  `KASUMI_TEST_REPLICA_TRACE=1` was enabled. This proves the corrected membership
  expectation progresses, not replica recovery. No physical failure marker was
  observed; the exact refused source grant remains to identify.
- `c04-large-capture-terminal-scan-integrated`: unchanged512terminal rows,
  256-chunk manifests and60,000ms verification deadline. Source snapshot capture
  completes; public restore framing finishes937ms, then restore decode expires
  after17of64 terminal batches. Wait reports60002ms unfinished and decode60974ms
  unfinished. Test116.97s/runner117.80s, exit101.
  `KASUMI_TEST_RESTORE_TRACE=1` was enabled. Fixture/capture progress is distinct
  from decode throughput; no controlled benchmark claim is made.
- `c04-metadata-lifetime-proof-and-bounded-reads`: all13selected primary tests,
  native16/16, Raft8/8 and Store3/3 pass;125.49s including85s compilation.
  This covers the exact-root header successor, native proof grant/denial cases,
  bounded limited reads (including two nearly32MiB entries), corrected refresh
  semantics and actual four-slot prepared quote. Engine13/15: metadata still
  fails, and the broad filter selects the serving-expiry/proof case, which fails
  at its initial backup checkpoint before expiry. The latter retains an apply
  failure atlog4/applied3; its original cause requires inspection.
- `c04-metadata-after-completed-fixture-lifetime`: isolated repeat with
  `KASUMI_TEST_METADATA_LEASE_TRACE=1` fails2.53s/runner3.16s. First refusal now
  requests4351/charges8471 at32slots/2,894,460bytes, attempt944. The saved analysis
  JSON reconciles all leases. Original fixture receipt IDs are gone; the three
  live table cores are the current restored generation, the restored-bootstrap
  decode and its verifier's redundant decode of the same immutable image. The
  required repair reuses the actual decoded views through full semantic
  validation. The unchanged32-slot/64MiB bounds and intended `QuotaExceeded`
  assertion remain the gate.

Applied artifacts after the earlier five, in recorded dependency order:

- Correct fixture result propagation. Manifest `9b0a58c2530e7e51cdc316941d5f45ad1fb8f2835fcd56ae5400dc05a19d2287`;
  patch `5f0d8fff10e3c574bea6f4c6721b1ba6262c650928e98ec467ec459f5db0e661`.
- Actual cache identity proof and directory workspace share one constructor lease, retained through final allocation release. Manifest `4bc08b1038eb3d71c2656174f1fdc91bec6d466c6be30c2e33c210bd546e6c33`;
  patch `ec1f0da15271e7d3b28b8250cc2ed135fe6996bb5ce6e406d4a5c960b09ebd3b`.
- Two exact prepared point peak assertions follow the four-grant quote; v2 explicitly composes the proof dependency. Manifest `3d992be9a898f017a59e0e1590df5a5e19b5a322341bab118d5157ae8c5d8534`;
  patch `8dbf5c1c2541a320f0cdc4a19725358790d6ecae86c4c08dafc12cfd9f5f5b03`.
- Release completed original fixture handles after successful restore. Manifest `cae5676aa62ea65cb13cddba04b9cca61b51dc25a5273818ee768bd2c2fb9944`;
  patch `aa4bc4455ddebbc4aa6e6940e8eceb79fbfb3b4b6bd8c871f3ac4f1aea3366f8`.
- Failed and recovered current custody refresh exercise the real lease semantics. Manifest `2e6659fe45b9f010f90dc44d468951f0aaffd3c96824a057c9338c8346340d54`;
  patch `00d3a602ff777e221354414af5ab54932e859385ca53a2368d15fa92cb3cef4d`.
- Limited reads return a64-entry/48MiB prefix, accept one legal maximum first record and preserve exact reads and all authenticated commitments. Manifest `88408d18c48463a2c7c6f80c4485739e53e715f01a912a97f17c17837bebef0e`;
  patch `1e5998525b74b0e05deaa019f3663eaa16205b3ebf5f408b63e8b19f9a1dad3b`.
- Header-only exact selected-root successor uses bounded tree descent without document payload loans or ancestry vectors; v2 pins the composed metadata fixture. Manifest `34330c548dcea3bd34159ee12659f897cb8accd141fd31da9e8a70d79c44b0d2`;
  patch `f7eedb6cc75aa64ca35de5b26e4877c0dad068ece2c24b7f93ac638a20cf7773`.

Saved before/after/dependency sources were verified at each application; root
receipts remain under each `/tmp` artifact. No stale dependency bypass was used.
The protected bridge, selected primary corridor and source funding producers
still include test-only paths. Passing these checks does not activate M03/M04.

`c04-large-seed-shared-coverage` now runs the original100,000-row recovery case
separately. Its earlier interrupted attempts remain failed/incomplete evidence.
The other interrupted permanent-custody capacity case remains unqualified.


`c04-large-seed-shared-coverage` completed **1/1 PASS**,820.97s test/822.88s
runner, exit0,1528/1528 unchanged pins. The original100,000 authenticated
uncommitted tail rows and all retirement/close assertions remain unchanged.
Local process samples observed bounded fixture insertion and then the first
recovery scan; a final sample overlapped process exit and contained no stacks.
These diagnostic samples are not throughput or installed-memory evidence.
The permanent-custody capacity test is the one remaining interrupted large case.

Root applied the opt-in source refusal trace (manifest
`22c825c1d4d376dd2aae784b52e85fdf561de02526a1d4312603561bf16bd1fc`, patch
`1ed5a474450afde8e5f84430dbba5e1049541afc17c3ef338464baf6a52bfa27`;
1file/6deps), then decoded-owner reuse v2 (manifest
`41bd34b067c511dcb0b2a9264a0602f01d1bf83eae4a6bbca51771a4740a121b`, patch
`dc3ba6285fb4b2b2b7c475221941105f330da46a51adea68999ff42f47a0401a`;
2files/8deps). Reuse only changes test-only bootstrap verification, sharing
actual already-decoded views through unchanged full semantic validation; the
other verifier retains its original initialization-before-decode order.
Wrong-state/footer rejection tests were strengthened. Independent source review
`97b611515aa0358bec5c8806d9a47fb7a85be99f6dcef6aa5ee3d1c3f13100fc`
found no actionable issue. One initial helper invocation used a nonexistent
patch filename and made no changes; the verified `change.patch` applied next.

`c04-reuse-metadata-and-reopen-refusal` is running the exact metadata case,
full verifier regressions and replica reopen baseline. Both
`KASUMI_TEST_SOURCE_GRANT_TRACE=1` and `KASUMI_TEST_REPLICA_TRACE=1` are enabled.
The initial-source shape correction is deliberately not applied in this baseline.


`c04-reuse-metadata-and-reopen-refusal` completed Engine4/5,158.73s runner
including100s compilation;1528/1528 unchanged pins. The exact metadata case and
all three full-verifier regressions pass. Replica recovery failed earlier in
initial election after58.44s; it reached no source refusal. Preserve this timing
failure separately from first-reopen capacity. The isolated follow-up
`c04-isolated-reopen-source-refusal`, with only
`KASUMI_TEST_SOURCE_GRANT_TRACE=1`, reached first reopen and failed23.95s test /
25.28s runner,1528/1528 unchanged pins. Exact locked refusal:

- Caller `application_sources.rs:469:37`, requested528bytes, current265194343,
  limit454059462; live24/4096slots and a free slot.
- DocumentSource charges0bytes/0slots. Cache headroom67108864bytes/64slots;
  ordinary protection134217728bytes/4slots. Resident0, high1073741824,
  usable=true, pressured=false.
- Requested total including required headroom/protection466521463 exceeds the
  cap by12462001bytes. This is the initial registry, before selected-record
  proof planning. The initial-plan change below is not evidence of its repair.

Three further source artifacts are applied with all exact saved/live hashes:

- Initial actual-root selection plan v2: manifest
  `35cb727022311c165c5e8edca476a4176aa89defa86b71901b18d9ca08675a51`, patch
  `e37f52359286dfa27bcabdc0f9933076d9711dbd5c99cd0494e6f584843f6dc5`,
  five files/25deps. One paired registered view probes exact directory extents
  and authenticates the initial bootstrap/commitment/cursor rows; Snapshot adds
  coverage/manifest rows. Later capture checks exact record hashes/absence and
  unchanged canonical semantic validation. Four tests cover actual pressure,
  small roots, snapshot/race and noncanonical cursor rejection. Root source
  review found no issue. v2 only corrects an obsolete comment relative to v1;
  it explicitly composes trace/reuse AFTER source.
- History-only abort v1: manifest
  `2d5ded70e02e7eb8b5304e40da6030fb8d3ed3fdc5276a7ca60ccd73bb85d17a`, patch
  `0b6c5c1bf9fb2d061e9da5b8cf3830f8fcf243feefdb87864b8c927ae2b78bfe`,
  15files/30deps. Exact provider refusal and positive native/metadata/census
  cancellation restore the still-captured source without closing it. Freeze
  moves after admission into exchange guards. Native-entered or unknown cleanup
  cannot become a clean refusal; original failure and independent panic remain
  owned. Five real Engine tests and an adversarial native protocol case added.
  Peer review `2c9339764614c0282889b385d2048a9d94f2d3b1d24854ae12ea59985dacea29`
  verified58savedcopies. Producer remains in its existing test-utils corridor;
  full source-cohort activation is still required.
- Existing backup fixture failure diagnostics now borrow the retained apply
  report as well as metrics. Manifest
  `b71d076d86e099afc6de01a177217fecc4cd4902a417bd3236f6c6d7cd29af0e`, patch
  `1566f0bf10d13b879878697523634252fc5a7c83d82aac2cf6d5d32be6b60977`,
  one file/four deps, cfg(test) only. It does not move, reset or retry the owner
  and leaves the public unknown-outcome response unchanged.

`c04-history-abort-initial-plan-and-backup-cause` is running their focused gate,
with1530pinned source/config files and SOURCE_GRANT_TRACE=1. The large restore
profile remains a separate unchanged workload; no initial-plan/cancellation
result is inferred before this run completes.


`c04-history-abort-initial-plan-and-backup-cause` completed Engine29/30,
native11/11, Raft3/3 and Store8/8;336.32s runner including311s compilation,
1530/1530 unchanged pins. All five actual history-abort regressions, the native
adversarial refusal case, prior funding checks and all four new initial-plan
cases pass. The sole failure remains serving-expiry backup fixture setup.
Its exact retained report now identifies ordinaryordinal3, response retained,
no violation/wake panic; sink original is `ResourceExhausted: document source
retention budget exhausted`; action/backend/finish returned; cleanup refused
Retained; drain not entered. The actual cell grant at application_sources.rs626
requests9216bytes with433968186 charged,588277281 limit,67108864 cache headroom
and134217728 ordinary protection. Source charges12600bytes/4slots, live38/4096
and sampled RSS227835904 below64GiB. This is a verified mandatory late source
cell acquisition after acceptance, requiring M03; it is before expiry behavior.

`c04-large-restore-decode-profile` runs the unchanged512-row/256-chunk/60s case
alone with RESTORE_TRACE=1. The v3 runner adds existing vendor Cargo.lock files
to the source scope (1535pins), preparing for actual vendor worker/actor unit
tests. A separate local sampler verifies the exact root runner/Cargo/test PID
chain and waits for the restore-decode phase before sampling. No caps, counts,
deadlines or optimization settings were changed for this diagnostic run.

`c04-large-restore-decode-profile` finished with the original deadline failure:
244.26 s test / 245.37 s runner, 1,535/1,535 unchanged pins. Framing took 3,838 ms;
decode remained unfinished after 58,052 ms, with six of 64 batches completed.
The exact runner/Cargo/test process chain and phase observation are retained in
`c04-large-restore-decode-profile-observation.json`. The actual decode sample
SHA256 is `8f58f5644156705b8cb3bd6670e73285e9843b69785ced006159b7c2fd21ba5c`;
2,344 of 2,377 active worker samples were in the two staged-terminal batch
insertions. Repeated typed table opening inside each insert is a concrete repair
candidate; authentication, semantic checks, batch limits and the 60 s deadline
remain required. Host load was 177.44/161.54/138.57 with 38,469.44 MiB system swap
in use. These observations explain why this run cannot qualify representative
latency or attribute system swap to Kasumi; the test still failed.

Root applied bounded Raft apply v1: manifest
`fbdb580cbe030a1d4757a6bae7cf855b1a2faf7d4c26f016477053a43510c221`, patch
`1919f9e65484c2613878e2c4857d0f4afa4080cf4e961e0273701f65695a3237`,
19 changed/new files and 59 exact dependency snapshots. Commit-only traffic uses
one pending range; the actual worker retains one applied-result batch until the
core consumes and acknowledges it. Non-apply boundaries and incoming snapshot
custody preserve committed-range ordering and canceled-waiter ownership. This
slice does not fund opaque response bytes, bound arbitrary non-apply ingress,
or replace the protocol term-boundary vector. Narrow test-shape review SHA256
`50981c838362fff8e7c3a42684d06cc126252a00de7ad353d21d4f9e7b6ff0b8` found no
actionable source issue; it is not runtime evidence.

`c04-bounded-vendor-apply-v1` starts actual vendor worker/actor unit tests using
the existing vendor lock, Rust 1.97.1, offline/locked serde+storage-v2 features,
and the same warm target. Its 1,540 source/config pins include vendor lockfiles.
The four-crate Kasumi graph alone would compile these changes but would not
execute their vendor unit tests.

The first vendor gate failed compilation at 94.70 s, with 1,540/1,540 unchanged
pins: two denied redundant `std::fmt` qualifications and one unused CommandSeq
import. Root's exact two-file lint correction has manifest
`3a2c1866efac34e6d5de0ea1f97389bae1a4687c202b8d1cd57f66e8c3a35518` and patch
`d7becebfa69e75d9c84b13a9e9df60996cf710637f2dbb3696ec34b3d8a879bf`.
`c04-bounded-vendor-apply-v1-lints` then passes all nine new actual worker/cell/actor
checks (0.06 s tests / 69.75 s runner including compilation), 1,540/1,540 pins.
`c04-bounded-vendor-ownership-v1` passes all 14 existing worker custody, incoming
snapshot and shutdown regressions (0.14 s tests / 0.49 s runner), 1,542/1,542
pins after the unrelated Engine admission artifact below. No deadlines, legal
entry sizes, durability conditions or retained-owner assertions were relaxed.

Root applied ordinary-protection headroom v1: manifest
`77aa341d22c6c536e289ee098f4b5d9184e4db944611f2de30de3de76860dfa4`, patch
`a329066ec16ef5c708d448c739850bd1166f6a2128e455d18b4b6792f4606bd8`,
six files/25 exact dependencies. Production ordinary protection now preserves
the same complete byte/slot/cache-work floor as source and cache admission,
substituting proposed total protection exactly once before mutation. Defaults
are unchanged. The original 384 MiB + device-metadata fixture is explicitly
invalid: independent 64 MiB audit, 128 MiB maintenance escrow, 128 MiB ordinary
protection and 64 MiB cache-work floors consume that entire base, before actual
constructor costs. It remains an actual negative installation/rollback test.
The positive replica fixture separately declares 128 MiB workload capacity and
adds canonical fixed constructor/device/floor quotes. This is a different valid
configuration, not a repair proven under the original cap or M03 completion.
Source-only independent review
`1032549bacab8f8e31a3b034e048ccc46e9c9c317c304954fe0e3a9b984f74f7`
found no actionable issue. `c04-ordinary-protection-budget-v1` starts the four-crate
all-feature library gate for actual refusal/rollback, fixed source-owner quotes,
audit maintenance and native cache admission on 1,542 pinned source/config files.

`c04-ordinary-protection-budget-v1` completes at 247.79 s including 246 s
compilation, with 1,542/1,542 unchanged pins. Engine passes 18/19; the other three
crates have zero matching tests. New actual byte/slot refusal and rollback,
canonical fixture planning, invalid legacy-budget installation, and native cache
checks pass. The older eight-slot audit-maintenance fixture now correctly fails
installation: three existing owners plus four ordinary-protected slots and the
default two-slot cache-work floor require nine slots. Its original invalid config
must remain a negative case; a positive scenario needs a declared valid slot
plan and must still prove that saturated operations leave four actual resident
slots. Do not weaken the production floor or call that a same-cap repair.
The `application_sources_tests` filter did not match the actual module name;
fixed source-constructor ledger assertions still need `application_sources::tests`.
The sole compiler warning is the test-only fixed-quote helper's overly broad
`test-utils` cfg; its precise cfg(test) correction is staged in the reviewed
source-capacity producer artifact.

`c04-replica-explicit-workload-budget-v1` now runs the original full membership,
close and fresh-reopen scenario alone under the separately declared valid fixture
budget. Counts, membership, durability checks and timeouts remain unchanged.
This run is not evidence under the previous invalid cap.

`c04-replica-explicit-workload-budget-v1` passes the full original scenario:
1/1 Engine test, 25.86 s test / 26.90 s runner, 1,542/1,542 unchanged source/config
pins. Exact state and membership checks succeed through replacement membership,
complete shutdown and all fresh replica reopens. This qualifies this scenario
under the separately declared valid constructor/workload plan. It does not turn
the original invalid cap into a passing result, establish complete M03 admission,
or qualify the final disk document/index production implementation.

The broader protocol gate `c04-bounded-vendor-all-unit-v1` passes all 228 vendor
library tests with serde+storage-v2, offline/locked and the existing warm target:
1.02 s tests / 1.55 s runner, 1,542/1,542 unchanged source/config pins. This adds
the existing engine/log matching and protocol unit suite to the nine new and
14 earlier ownership regressions; it still does not bound the residual
term-boundary vector or provide Engine byte admission for every response.

`c04-source-fixed-owner-quotes-v1` executes the correct nested source module:
91/93 Engine tests pass, 114.62 s tests / 115.95 s runner, 1,542/1,542 unchanged
pins. The canonical constructor ledger assertions pass, along with source,
primary-stage and cleanup cases. Two older assertions fail: covered planning
still requires a full 2 MiB format-maximum allocation after actual-row preflight
replaced that policy; duplicate callback cleanup expects ten point slots rather
than comparing the actual pre-producer baseline (observed eight retired).
These failures are preserved. Root's test-only exact-owner artifact (manifest
`c5355b09c63a143e63584d3774b7e9c63212f7c4fdbac8e8c73683d834badd7a`, patch
`1623515c3084a8f316224438939adee7dbc508ee9f5631b9e0eff7c33a19f6ac`, two
files/six dependencies) replaces those stale assumptions with actual baseline
retirement, complete prepared-backing coverage and a real covered capture whose
owners return to the original byte/slot baseline. Production behavior is
unchanged. Source-only peer review
`1c03173ee6a44b010558797830897a1bdfc9f20e74f29e42ec5cfa16629678cd`
found no actionable issue. Runtime checks remain pending, together with the
Raft planning-session tests that measure actual overlap.

Root also applied the test-only audit slot fixture v2 (manifest
`94f75322fe4f08de885ef432d8e4256b5adc781d4fe32e5a4cd46b7a1b0396bc`, patch
`2ce23652d8397125f91ff8631ad6a6f64fff883ab334c5aa47cea6cc88841243`, one
file/nine dependencies). The original eight-slot configuration is an exact
atomic refusal test; the positive slot count derives from actual constructor
owners, escrow, separate protection floors and one declared work slot. It still
fills ordinary capacity and proves four real resident slots plus slot-free
scoped native escrow. Root caught the v1 negative test's incorrect error string;
v2 preserves the exact original `node maintenance headroom unavailable` message.
Source-only review `ce768f6331b04a106da2f9d4978304b1034e63a1c4e78a756beb9a5143ac99c0`
found no further issue. No production caps or floors changed.

Root applied registered source-capacity producer v5: manifest
`7df8e82eb714cd5692c2d7477a4f4c9e33bad1ec6289f4413c1f4e31675c3366`, patch
`28c7c921def71009dc3aa5e69cad9bf244c2023635e779d00a8b5845f3d6bc65`,
22 files/56 exact dependencies. It explicitly composes the applied headroom and
exact-owner test changes. This exposes the canonical actual registered capacity
producer, prepared reader/cancellation ownership, and same-backing protected
old/current point loans through the original strict decoder and history protocol.
It activates no unused SourceRoots bank or accepted-entry guarantee; the actual
Engine Cell/DTO lane assignment and full ingress envelope remain in progress.
The four real producer/history/loan regressions are added but not yet executed.
Source-only peer review of identical production bytes and the cfg(test) fix is
`334ebd5885c07ba0d019ac18ff28886960e9ed23a113d5fe76496ddf20c332b7`;
v5 changes only the saved dependency for the applied exact-owner test repair.
`c04-source-producer-default-check-v5` checks the four-crate library graph without
test features on 1,544 pins, specifically to catch production cfg omissions.

The scratch retained-Table artifact is still unapplied. Its first revision's
per-batch grant introduced a second-unwind risk: invoking a retirement callback
while already unwinding can abort the process. The next revision must retain the
actual still-charged lease in preallocated, owner-held custody without invoking
that callback during the first unwind. Earlier source reviews covered ordinary
cancellation and consuming Result paths, not this combined unwind condition.
No performance or runtime success is claimed for the unapplied artifact.

The default-feature producer check fails at 28.34 s, 1,544/1,544 unchanged pins:
source_capacity used ErrorKind directly where anyhow requires an Error; three
Registered let-else patterns also become irrefutable without fixture variants.
Root applied the precise two-file correction (manifest
`427241c621fdc22c2d7f56fa6b2c0487b54e1e56dd597a917fe57e2933c744a1`, patch
`8b6e98f1739b03c9e4962ec8421dd86db7147c80c8310b8e300fa13cbeb62032`, nine
dependencies). It constructs the actual io::Error and uses exhaustive matches
with cfg-limited rejecting Fixture arms; no production fallback is introduced.

Root applied scratch batch table reuse v3 (manifest
`40c4cf46b999176cd0598f2718fb2d7fa0c6f5654c519f648b836e0792e14d58`, patch
`7ba244388bf38e164aa107821ad6d37cbe628cf181745e33874bfc9013f5f5c7`, three
files/24 exact dependencies against producer v5). Each batch retains one actual
typed Table and drops it before commit. A distinct exact per-batch grant accounts
for its shell/name and a preallocated retirement link. Failed-live batches do
not share an assumed writer-gate credit. Current owner/access checks, duplicate
checks and the 16-entry/4 MiB limits remain. During an existing unwind the actual
still-charged lease/link moves to its fenced scratch facade without a callback
or allocation; final unknown native close retains that list with the database.
Normal consuming error paths preserve the original error and retirement panic.
Nine new actual tests cover cold catalog reads, limits/duplicates, owner failures,
independent live grants and both ordinary and nested unwind cleanup. Final source
review `e95080b4f70677e5990084f2fe27caaf5889761ad30c135284a67448bceb2ca4`
supersedes the narrower v2 review; runtime checks remain pending.

`c04-producer-scratch-and-fixture-v1` starts the four-crate all-feature library
gate on 1,544 pins for new producer owners, all scratch table tests, unchanged
32-slot metadata restore, the two source-fixture corrections, audit slot tests
and Raft planning sessions with measured overlap. It retains the existing warm
target and test optimization settings. The large restore case remains a separate
next gate so fixture setup and contention do not obscure its result.

`c04-producer-scratch-and-fixture-v1` stops at compilation, 74.06 s with
1,544/1,544 unchanged pins: one older physical-failure fixture directly created
ScratchTableDatabase without its new actual admission owner and retained-link
field. The exact one-file fixture correction (manifest
`370b2eb6ff74befecc70c7a37cd55d51653fe8c6a91782bda7a25a0da999b05c`, patch
`5b22736fb7626ca2fbaa06e1e5e232d83a191914f54476a3862dfcd840d59a8a`, seven
dependencies) supplies that fixture's real owner clone and initially empty list.
All original physical-failure assertions remain.

`c04-source-producer-default-check-corrected-v5` passes the four-crate normal
library graph in 31.71 s with 1,544/1,544 unchanged pins. Its one warning is the
fixture-only acknowledge_source_control method remaining visible in normal
builds. Root applied its exact cfg scope (manifest
`0b2bb1148a9ac4bdf57d85736c5bd378349f34939f1db8737c89f9c1c9dd51f1`, patch
`9c3855a824ec1676f939d26064a1dd77c4613b7da55a610fd3224de247561a79`, one
file/one dependency). No production acknowledgment path or fallback is added.

Root applied the ordinary source envelope v2 prerequisite: manifest
`28d7b6f5609d80e09af67de2d87a26ce19d09d4808de8da316b0d74d853572b1`, patch
`001c1a633ddcac08f15ca975acef99f26527f8a80a45f9fcb7ec7d27bb6a87af`, six
files/26 dependencies explicitly composed after the producer compile correction.
Borrowed canonical bootstrap/membership shapes are streamed without a DTO clone
or encoded Vec; the pair-bound quote covers final ordinary records, scalar
width growth and existing format ceilings. It neither reserves capacity nor
certifies a predecessor. Covered replay and snapshot shapes remain explicitly
excluded until their separate accepted/recovery ownership is funded. Actual
planner backing is separate from this final-row envelope. Root source review
found no actionable issue; runtime verification is pending.

`c04-producer-scratch-and-envelope-v2` now compiles and runs the combined focused
gate on 1,546 pins: previous scratch/producer/metadata/audit/source regressions,
plus ordinary-envelope and canonical allocation/plan tests. Normal-feature
warning cleanliness and the unchanged large restore deadline still need their
subsequent checks.

`c04-producer-scratch-and-envelope-v2` completes in 197.79 s including compilation,
with 1,546/1,546 unchanged pins. Engine passes 9/9: both source-fixture corrections,
the six audit cases (including exact invalid-slot refusal and valid saturation),
and metadata restore within unchanged 32-slot/64 MiB limits. Raft passes 20/21:
canonical number/allocation, maximum control record and actual planning overlap
checks pass. The first small membership can fit already-owned scalar-width slack,
so requiring refusal for that shape was an invalid test assumption. The second
large joint-membership refusal remains required. Native has zero matching tests.

Store passes 31/36 in that gate. The retained-table cold-read test, exact limits,
duplicate/current-owner checks and existing-unwind retained lease case pass.
Five failures remain: two old direct backend-close tests each measure one
allocation instead of zero; new commit/cancellation fault tests do not reach
the intended batch retirement lease; and the failed-live batch test observes
three actual slots instead of two. These failures are not large-restore success
evidence. Preserve the zero-allocation assertions and identify actual leases
before adjusting any fault target or ownership census.

The initial producer file-stem filter selected no new Engine producer tests.
The corrected module filter in `c04-production-source-capacity-v5` runs all four:
three pass, while exact-root selection fails during fixture initialization with
`initial bootstrap manifest requires its raft node and group`. The full gate
takes 2.56 s (1.58 s Engine), 1,546/1,546 unchanged pins. Production bootstrap
validation must remain intact; this test needs its actual canonical initial
storage identity before it can exercise source selection.

Root applied the peer-reviewed one-file membership test correction (manifest
`d721ab6667025c19e9b72ab43af5aaf56c804252345a11c6eda456afa2b0823e`, patch
`ff5f31841764e5e462737325f6217890f9789e06998631c6ceb93875e879a2b4`, five
dependencies). Both entries retain no-effect checks and actual expansion before
publication. Only the second deliberately larger joint shape must exceed the
preceding envelope; exact membership authority remains separate from a capacity
quote. No production behavior changes.

`c04-source-producer-normal-clean-v5` passes the normal four-crate library check
without warnings in 16.37 s, 1,546/1,546 unchanged pins. This verifies the producer
APIs with fixture features disabled after the acknowledgment cfg correction.
`c04-scratch-close-zero-allocation-isolated-v1` now reruns the two exact existing
backend-close allocation checks serially on that source to distinguish a stable
close-path allocation from parallel test interaction. No cleanup assertion,
budget, deadline or production policy is relaxed.

The serial close check fails both original tests (0.47 s tests / 27.01 s runner,
1,546/1,546 unchanged pins), reproducing one allocation in each. A temporary
first-allocation backtrace in `c04-scratch-close-allocation-trace-v1` identifies
the same 64-byte allocation in both: lazy macOS pthread-mutex backing for the
test-only `TestDiskMemory::point_drop_panic` lock in `TestDiskLease::drop`.
It is not an allocation from the production scratch close path or the trace
environment lookup. That diagnostic runs only the Store feature graph, takes
98.87 s including compilation (0.33 s tests), and preserves 1,546/1,546 pins.
The extra backtrace work is diagnostic overhead, not a performance result.
The observer was restored byte-for-byte afterward to
`29f873fb18668f9dcf92e3e2dff24e9d5ce3e0221f1845e0b630ce570b24207f`;
the diagnostic variant was
`b73b8de46d126ff9c2ec91c4f7b2e422828c1e574fe8ad3e4414d176f3901f30`.

Root applied the peer-reviewed source-selection fixture v2 (manifest
`50b80e5dae07404a85c6751cdc4d358f7f46b7870e76e2882159066c3ad0c054`, patch
`7119d43b03d1eeda07adbabd00be63f32965f5221f66a1133aea4e2d14d5952c`, one
file/eight dependencies). It initializes the real paired bootstrap/raft identity,
preserves write-once rejection using a complete paired overwrite proposal, then
corrupts a mutable applied row. The new exact encrypted root must retain the
canonical decode error while the prior pinned root remains valid. V1 was not
applied: its incomplete overwrite proposal would hit earlier shape validation.
Review `5cc7f09e1b5d76b581ef25b141830e804f18ec4133cd778e5948e6ec5f8c4b5e`
found no actionable issue; runtime verification follows.

Root also applied the scratch exact-fixture repair (manifest
`51240459b73b0739dc58950efb704b13082f83c7d2750fe17a207c444ce1b2e2`, patch
`eaf4836562b237bc275c092e37287c232302b3b70e355c1b5fcb27c9b37a7411`, one
file/12 dependencies). Fault injection now targets the actual batch grant before
transient table probes, then continues through the real production open path.
The retained-batch census independently establishes the native transaction's two
real grants and requires each live failed batch to retain those plus its distinct
shell/name/link grant. Exact byte symmetry and final baseline remain required.
This changes neither production batch ownership nor the zero-allocation checks.

Root applied the fixture fault-mutex warmup (manifest
`9c94ba3debcbe3eed71466fd0ed4de8e0a7944c925f697693c4cc6bb5ac965e7`, patch
`56ba70ab4b56214c2ee5dca8fcbd7f17ab8617405be5af8f792d5e48bbc63c2e`, one
file/five dependencies). The existing test-only fault mutex is initialized beside
the existing ledger mutex during construction, before any lease can retire.
No production close behavior, fault callback or allocation assertion changes.
Source review `81a77caf19dda48c18bb2a8165a5e015bc4ed5e1da6e4f4ec7b62efa4d851a4b`
found no actionable issue. `c04-scratch-source-envelope-corrections-v1` now runs
all scratch table tests, the four real source-capacity tests and the ordinary
envelope tests on the composed source with 1,546 pins.

`c04-current-format-check-v1` passes `cargo fmt --all --check` in 10.11 s with
1,546/1,546 unchanged pins. This checks the current workspace; further production
integration still requires final qualification on its own source.

`c04-scratch-source-envelope-corrections-v1` passes all selected tests:
4/4 Engine source-capacity cases (2.69 s), 6/6 Raft ordinary-envelope cases
(2.87 s), and 36/36 Store scratch-table cases (24.12 s); native selects none.
The runner takes 146.78 s including compilation, with 1,546/1,546 unchanged pins.
This closes all six failures from the earlier scratch/producer selections and
the small-membership test assumption while preserving production validation,
limits, real fault payloads and exact cleanup assertions.

`c04-large-restore-retained-table-v1` now runs the original large restore case
alone with `KASUMI_TEST_RESTORE_TRACE=1`, the same warm four-crate test graph,
512 terminal rows, 256-chunk manifests, budget and 60,000 ms verification
deadline. It measures whether the retained-table change improves the actual
decode path; the passing small tests do not establish this operational result.

`c04-large-restore-retained-table-v1` fails the unchanged restore deadline:
114.82 s Engine / 115.44 s runner, 1,546/1,546 unchanged pins. Source capture
completes; restore framing takes 864 ms and decode expires at 59,239 ms after
20/64 completed terminal batches. Those completed decode batches total 27,460 ms
(216–5,383 ms each). The separate fixture-construction batches complete 64/64
in 28,516 ms total; those are not restore timings. A late attempted process sample
finds no live test process and captures no stack. No improvement ratio or causal
performance claim follows from comparing runs under different host contention.

`c04-large-restore-retained-table-profile-v2` repeats this still-failing scenario
for diagnosis, with the same source, parameters and trace. Its wrapper samples
only the actual descendant Engine test process three seconds at 10 ms intervals,
four seconds after the decode phase begins; it records that observation and
sample hash. Sampling overhead and host load are diagnostic context, not a
representative latency or Kasumi-attributed memory measurement.

`c04-large-restore-retained-table-profile-v2` also fails the unchanged deadline:
117.64 s Engine / 118.22 s runner, with 1,546/1,546 unchanged pins. Framing takes
1,040 ms; decode expires at 59,049 ms after 29/64 completed terminal batches.
Those batches total 30,620 ms (94–3,128 ms each). The diagnostic process sample
is `/tmp/kasumi-large-restore-retained-table-sample-v2.txt`, SHA-256
`061b138843673778d1faeeaeaf26b88780a825ef35ad916feb75f4ce7a433f3a`.
Its active worker has 40 samples in terminal `Builder::push`: 23 insert, nine
begin-batch, seven commit, one validation; 39/40 reach `EncryptedSpool::block`.
Native directory reads authenticate a 4 KiB header then a 16 KiB page through
the spool's single 64 KiB plaintext block cache. Alternating distant header and
page accesses repeatedly decrypt a full block. The finite candidate uses a
private 4 KiB native layout while retaining the sequential 64 KiB layout, with
matching actual buffers and pre-effect memory/disk claims. All authentication
and owner checks remain required. The sample's one-time 38.4 MiB footprint is
not whole-workload memory qualification; host load and sampling affect timing.

Root applied `kasumi-native-spool-layout-v1`: manifest
`37f79e2b1fdaeabd72ff68020838576a36a1e8f775e0feab54b1af09728984c4`, patch
`0d5ab9a33b27f0b569a96f8f3b7ad70b19dd1b68f2539c4a1b51efa74a1e50eb`,
five files and 20 verified saved dependencies. Independent source review
`f0357095ee4f9492ed2f9002ae03ace23d01051fd9ae2e207510045f66bae045`
finds no actionable issue. All native ordinary/prepared spools now use the same
private immutable 4 KiB geometry; sequential images retain 64 KiB. Physical
claims and actual crypto-memory quotes change together; the actual 64 KiB
resize stack remains charged. New tests exercise measured authenticated reads,
cache-hit owner checks, truncate/regrow zeroing, corruption/reordering, and
prepared real claims. `c04-native-spool-layout-v1` now runs these plus existing
spool, scratch-table and scratch-claim tests on 1,547 pinned files. This start
entry is not a runtime result or a claim that large restore now meets its deadline.

`c04-native-spool-layout-v1` passes all 62 selected Store tests in 13.57 s
(139.96 s runner including compilation), with 1,547/1,547 unchanged pins.
The three other crates select no tests. This includes all new native-layout
checks and the existing spool, scratch-table and scratch-claim checks.
The controlled cold-read test authenticates 62,040 bytes for three native
header/page alternations versus 393,456 bytes for the sequential-layout control;
these are actual successful ciphertext-read counts, not a latency estimate.
`c04-large-restore-native-layout-v1` now runs the original large restore alone
with the same trace, budget, 512 rows, 256-chunk manifests and deadline.

`c04-large-restore-native-layout-v1` passes the unchanged test: 62.20 s
Engine / 62.70 s runner including fixture creation, with 1,547/1,547 unchanged
pins. Actual public restore framing takes 879 ms; decode 33,930 ms; discard
32 ms; the complete wait 34,842 ms, leaving 25,157 ms of the original deadline.
All 64 terminal batches complete (18,221 ms total, 122–601 ms each). The
unchanged 512-row/256-chunk/budget/deadline case is now a focused pass. The
successful controlled ciphertext-byte test supports the specific read-amplification
repair; differing host load prevents a general wall-clock speedup claim.

Root applied `kasumi-constructor-source-envelope-v1`: manifest
`243347f695f93d200f2df7b279f1a7f2dc2eac47b23e0b1a4b8439f2577a55dc`, patch
`08dd28bcc2f81e0a9db77a48684cce1f50b8616912481d815202d2f1ad569a15`,
14 files and 32 saved dependencies. Production source review
`a7b004d133dd13837abe2a37f8ca50e2f3e0b9bbb659952a87ad30d9771ec296` and
narrow test review
`68c8e5ce4420bb695a048b4d9ee65ba2267789bb2e6519c0a073710643c8ebb1`
find no actionable issue. It folds current metadata and the entire retained
suffix on one registered root, including accepted uncommitted membership shape,
returns the actual point backing/workspace, and preserves exact reconstruction
seeds independently of monotone shape maxima. This is preparation, not actor
predecessor authority; full LogStore validation and production adoption remain
required. Runtime tests have not yet run on this new source.

`c04-constructor-source-envelope-v1` passes all 18 selected tests: four
Engine capacity tests (1.45 s), 11 Raft tests including five constructor and six
ordinary-envelope cases (3.49 s), and three Store same-root scans (2.55 s).
Native selects none. Runner 65.62 s including compilation, with 1,550/1,550
unchanged pins. Production startup/actor adoption remains open.

The first attempt to apply cohort v2 stopped before any file mutation: the
strict application helper did not recognize the artifact's `dependencies/`
snapshot directory. The helper now validates that directory under the same
exact saved/live SHA requirements. A subsequent regression command had already
started under label `c04-source-cohort-custody-v2` on the 1,550-file constructor
baseline. That label is misleading: its source pins are authoritative and it
contains **no cohort v2 code**. Preserve this as baseline regression evidence;
any cohort acceptance requires a separately named run after successful application.

The misleadingly named baseline run `c04-source-cohort-custody-v2` passes
93/93 Engine application-source regressions (86.72 s) and 11/11 Raft
envelope cases (4.27 s), 91.65 s runner, 1,550/1,550 unchanged pins. It selects
no Store/native tests and contains no cohort code, as noted above.

Root then successfully applies `kasumi-source-cohort-custody-v2`, manifest
`29e3df77fc7ba4a9aa64816c0104eb9eb5ec606294ef689fdc9ff3d51c1aedd8`, patch
`25d1f634dc0645a88bef8dde719a4d8961a423fce73b2beaa2813790882b560e`,
21 files/67 saved dependencies. The exact constructor composition is reviewed in
`a4939e584b80afdd4accb4885995aa61bae0d245d80cdb34126ed9eaf1ce9144`.
It installs actual two-lane Engine credit, native source rights, historical
replacement ownership, reusable backing and complete close/census custody.
The installer is still unwired in DatabaseConstruction. The correctly named
`c04-source-cohort-custody-applied-v2` runs 1,555 source/config pins. Normal
compilation reports seven dead-code warnings from the pending installer and
three test-only helper methods; activation/scoping must resolve them without
blanket allowances. Runtime qualification is in progress.

`c04-source-cohort-custody-applied-v2` completes with two failures: Engine
101/102 pass (106.19 s), Raft 11/11 pass (4.49 s), Store 0/1 (0.26 s), native
none. Runner 205.09 s including compilation; 1,555/1,555 pins unchanged.
The Engine partial-construction fixture expects one retained lane-bank slot,
but its ordinary-class saturation also occupies the independent cache-work
slot floor, so one freed ordinary slot cannot admit the first DocumentSource
grant. The Store close-contention fixture reads `capacity.pool` after queueing
without installing, so it has no actual pool to lock. Corrections must reach
those real intended boundaries and preserve the original-error, exact-memory,
census and cleanup assertions. These are failed evidence, not cohort acceptance.

`c04-cohort-format-check-v1` passes workspace formatting in 3.31 s with
1,555/1,555 unchanged pins. Root applies the Engine partial-admission correction
(manifest `59b07880b2f9946e3e512279d0744c92bb0dfc8304e5bef4a9f865f6060a1a32`,
patch `cd19c8cf502670fe1f1816eea5e55a47ccf5213044f2bf8dfbbdf1c463f0e048`,
three files/10 dependencies): saturate the actual DocumentSource class, release
one admitted slot, retain the bank, then exercise transient refusal with original
identity and exact cleanup assertions unchanged. It also scopes three genuinely
unit-only methods to tests. The Store close fixture is not fixed by calling install:
its TestDiskMemory provider has no actual source metadata capability. Its replacement
must use the installed Engine provider, not a made-up success grant.

Root also applies the independently inspected incoming-membership fold
(manifest `08106b01c37239bd1831f378ec85886e3caf5add261974414daf372c44b59205`,
patch `bda4c80610df58bcacfbf905b46a5bee3e1f488cf35cc85f6d1b4d49cbf22ce0`,
two files/10 dependencies). `with_entries` uses the existing monotone quote for
every intermediate incoming membership, so a smaller final configuration cannot
hide an earlier larger shape. It changes neither the exact reconstruction seed
nor retained-lookup bounds, and grants no acceptance authority. The new regression
checks allocation-free folding and both real canonical publications. Runtime
validation follows together with the corrected cohort fixtures.

`c04-cohort-partial-and-incoming-v1` passes both selected regressions:
Engine partial construction 0.99 s, Raft intermediate-membership coverage
1.44 s, runner 51.85 s including compilation, 1,555/1,555 unchanged pins.
The Engine test now reaches the intended second admission and retains the actual
first grant until exact complete cleanup; original-error identity and byte/slot
baseline checks pass. Three unit-only methods are correctly scoped; five normal
build warnings remain from the still-unwired constructor path. The Store close
fixture still needs replacement by the real installed-provider test.

Root applies single-domain protected points v2 (v1 remains unapplied): manifest
`449abc28115a4f3e3200a8bb2f17468ad805fed35a538c070d3deebfa5bf8453`, patch
`d11fb7ab64aad9d69c0f58d04d8e30249e5f92c8eec98ce5d74eb60b03f04a1e`,
seven files/30 exact saved dependencies after constructor/cohort composition.
Scoped peer review `07b90c7301befa0e63c187ce0a1774465c1e032a7d564e494b726124dad76612`
and root source inspection find no actionable nominal binding/loan/retirement
issue. Authority-shaped callers now prepare actual one-domain backing and queue
source capacity through their real registered node; the positive test seals the
application Store first and uses custody alone. Protected old/current roots share
one admitted backing and retain provider/native/Store identity, current expiry
and canonical point authentication. Existing single-session callers retain their
same finish/error ownership, with the additional actual Store handle quoted.
This is not the required Raft exact-ID provider or actor cutover.

Root applies the actual report-lock fixture (manifest
`eac5945b438b819f1018127904a54df88245f24c02147895466b693097ea2834`, patch
`e84e1a6c02aba4886f27b186a8aa7b4851af2064a52fecff65b99337d753bed5`,
three files/18 saved dependencies). Review
`af1278d0d99da2cfb3a2b3fcb6fb9407cb37bb6d28019a5523743024852652a2`
finds no actionable issue. An actual installed Engine provider supplies the pool;
a narrowly scoped test helper holds its real report guard during consuming close.
The Store test now checks its actual Unsupported refusal and exact original
address through retained closure, then explicitly acknowledges it using the
existing test-only census API. No production provider/policy fallback is added.
`c04-single-domain-cohort-fixtures-v1` validates both changes and their related
point/cohort/constructor cases on 1,557 pins.

`c04-single-domain-cohort-fixtures-v1` passes all 23 selected checks:
10/10 Engine (5.28 s), 6/6 Raft constructor/envelope cases (3.22 s), and
7/7 Store (1.76 s); native selects none. Runner 74.33 s including compilation,
1,557/1,557 unchanged pins. Both formerly failing cohort fixtures now reach
and pass their actual intended boundaries. Single-domain pressure/expiry and
identity checks pass; ordinary single-point growth, original-error plus retirement
panic and unsupported source-provider refusal also pass. The five normal build
warnings still identify unwired production constructor paths. This is component
acceptance, not completed preacceptance capacity or disk-document serving.

`c04-current-native-all-unit-v1` fails one of 551 native unit tests:
550 pass, 3.19 s test time, 17.51 s runner including compilation, 1,557/1,557
unchanged pins. The only failure is the final `denials > 6` assertion in
`capacity_denial_after_prepare_aborts_and_allows_retry`. Its actual retry,
old-root and unfenced-state assertions do not fail. Prepared directory and
publication backing have changed the number of mandatory admissions; ordinal
count no longer demonstrates a post-prepare boundary. The replacement must
observe actual backend mutation calls, exercise real pre-effect refusal and
retry, and deny all new memory admissions after effects while verifying durable
publication, retained roots and fresh reopen. No production capacity, workload
or durability requirement is relaxed. Keep this failed run independently.

Root applies the native effect-boundary fixture (manifest
`c2409152f136675255c80a0e047c243bc1e416ec4b674acc1e1d4f5670279c77`,
patch `d0de9dbf72e1551e311bd3bf80681e0f0c25378c1077971b6e910fffa4e6f830`,
two test-only files/17 dependencies). Independent scoped review
`864b19d33c01d57035381475de60fb229ea49c0d3024a6b4c0d65d3588be514a`
finds no issue in the phase observation and durability assertions. Compilation
then catches an `&Vec` argument where `Operation::put` requires a slice or owned
value; `c04-native-commit-admission-v1` fails compilation in 1.82 s, with all
1,558 pins unchanged and no tests executed. The one-line slice correction is
applied separately (manifest
`663139d6ad3ad4f6acb78e6f2667e8d806158c738c46604ed646dd0f29ce8398`).

`c04-native-commit-admission-v2` passes both replacement tests in 0.08 s,
7.56 s runner including compilation, 1,558/1,558 unchanged pins. Every mandatory
refusal in the injection sweep occurs before actual backend mutation, preserves
the old durable root on crash reopen and allows retry. Denying every new workspace
and cache admission after the first actual backend effect still publishes the
256 KiB replacement durably: no late mandatory workspace request occurs, real
optional cache growth is refused, retained old roots remain valid, fresh reopen
selects the replacement, and all measured leases return to zero.

`c04-current-native-all-unit-v2` passes **552/552** native unit tests in
2.75 s, 2.86 s runner, 1,558/1,558 unchanged pins. This closes the stale
allocation-count regression on current native source. The new phase-based checks
preserve refusal/retry and add durable reopen coverage; the failure above remains
recorded. This is not application document/index serving or final release acceptance.

`c04-native-commit-format-v1` passes workspace formatting in 2.42 s with
1,558/1,558 unchanged source/config pins. All root Cargo commands are reaped
before the next production integration artifact is applied.

Root reviews the non-standalone cohort receiver checkpoint (manifest
`b2c8a0dc3601048660c1f2ca2e3ee9c9cb03555c07e19e49c6ae485b62121071`)
in review `815467192d3bc4aae8dc863c6a3194cc1dca60598c2d02fff021b7cd06a22cd3`.
It remains unapplied: lane growth must move provider callbacks outside the lane
mutex, and acceptance must retain a real drain obligation with a final sealing
check. The implementation owner accepts both findings. Actual prior-control DTO
coverage, prospective snapshots and actor adoption are also still incomplete.

Root applies the exact publication/source-capture prerequisite (manifest
`926aa0854927413932c5351c2a4fd4787db3925ca9c90910292e6ef9a55abaa5`, patch
`f5c974a7101812f675cd2ae35938432e3ee0a993c3ce69646f35fa72bf830f85`,
nine files/37 dependencies). A consuming successful native commit can retain
its existing writer token through capture; ordinary commit and failure paths
retain their prior behavior. Actual paired namespace replacement and sole-domain
publication use this guard. Root review caught shared prepared-source reuse
across concurrent writers in the earlier draft; the frozen version requires
exclusive mutable source ownership and checks its phase before mutation and
again under the writer guard. Provider/native identity is checked separately
from the exact Store binding enforced by point workspaces. Source capture and
original publication failures stay owned by the actual caller/registered source.
`c04-log-source-publication-v1` is running focused native, Engine-funded Store
and existing domain tests on 1,560 source/config pins. This prerequisite does
not activate the disk-backed protocol log-ID provider or the actor gate.

`c04-log-source-publication-v1` passes all **25 selected tests**: three
Engine-funded source publication cases (1.88 s), four native writer/capture
cases (0.05 s, including nine crash scenarios in each commit mode), and all
18 selected existing Store domain tests (23.00 s). Raft selects none. Runner
80.13 s including compilation, 1,560/1,560 unchanged pins. The same-node different
domain reuse check rejects the already captured source before writes. The
native prepared capture creates no new allocation/grant under full admission,
and the captured root stays readable after the queued writer publishes its
replacement. The five normal Engine warnings still refer to the unwired cohort;
this passing prerequisite does not remove them or complete M03/M05.

`c04-log-source-native-all-unit-v1` passes **555/555** native unit tests
on the writer-guard source, 2.92 s tests and 14.85 s runner including compilation,
1,560/1,560 unchanged pins. The successful held-writer path, ordinary commit,
capacity refusal and all existing native unit regressions pass. Native/Store
strict all-target Clippy is being checked separately; this is not final workspace
or operational qualification.

The corrected capture seam has scoped peer review
`5d5deab2cd8dd1e50a5273bcd13d3ebb8986f70a6fa77d7dee0cbc56092a0306`;
no further source finding after exclusive source ownership and phase checks.
`c04-log-source-native-store-clippy-v1` fails in 10.72 s, 1,560 unchanged pins:
five unnecessary references in the native packing reader and 31 explicit drops
of the now-nonowning `DirectoryMutator` in tests. These diagnostics predate the
writer-guard source and stem from the earlier workspace refactor. Root applies
an eight-file mechanical cleanup (manifest
`2ca8e1b23748e91be05f46d4991773560234df69fa9cd1ce6f1635cf89801b1b`, patch
`419845af31b48fa186557c585c5083c24022f90164bff5586913cebe8d631cc9`).
It preserves all assertions and actual workspace-owner drops; ordinary borrow
lifetimes now end at last use. Strict Clippy is rerun on this source.

`c04-native-store-clippy-v2` clears native diagnostics but fails four Store
lints in 17.99 s, 1,560/1,560 unchanged pins: a nested cancellation conditional,
two large inline source-error results and one test-only close-observation type.
Root applies the three-file Store cleanup (manifest
`35d3292aed3def163f5520cae74ca5a0ee06f9c955a8c1c58e6fc748f0ea7557`, patch
`1c5107cf1d48dc25dc17066a9d02406ad5d2adb078eb5b25c87fc6d5663eba8e`).
The conditional is flattened and a named test-only tuple type replaces repetition.
The two source error methods retain their actual inline failure ownership with
narrow, explained `result_large_err` allowances: boxing would introduce allocation
on a protected failure path. No error is discarded and no behavior or capacity
is relaxed. The strict gate is rerun separately on the resulting source.

`c04-native-store-clippy-v3` passes strict all-feature, all-target Clippy
for `kasumi-kv` and `kasumi-store`, with `--no-deps -- -D warnings`:
37.62 s runner, 1,560/1,560 unchanged source/config pins. The previous two
failed lint gates stay recorded. Engine's pending constructor warnings and the
full workspace/release checks are not covered by this pass.

The constructor/receiver review v2 remains unapplied. It now owns the actual
lane/transient grants outside callback-sensitive mutexes, restores them on
refusal/unwind, and counts preparation/acceptance obligations before invoking
providers. Drain cannot close the cohort while those obligations survive;
final handoff checks sealing again. Root's source review finds the two v1 issues
addressed in this delta; targeted regressions are written but not yet run.
The source-capacity Entry gate must deny actual DocumentSource acquisition and
observe encrypted point admissions. Denying *all* Resident acquisition would
also deny currently separate native write scratch/physical work. Source-only
success must not be reported as completed accepted-writer/candidate/output
funding or all of M03/C05.

`c04-native-after-lint-all-unit-v1` requalifies current native source after
the mechanical cleanup: **555/555** unit tests pass, 2.55 s tests,
9.64 s runner including compilation, 1,560/1,560 unchanged pins. No native
runtime behavior was changed to clear the lints. The passing native/Store
strict all-target check above applies to the same resulting source.

`c04-source-publication-format-v1` fails formatting only in 2.43 s, with
1,560/1,560 unchanged pins: the earlier mechanical reference cleanup left one
multiline `reader.load` call that rustfmt now wants on one line. Root applies
that sole formatting change (manifest
`a6faba1bff195d67609588105179d0c311beaa10fcbda5f8c452738f19296ed3`,
patch `25302bf8805a2eaa04e7cf7746c23054ca48b8bf57f5be2b9ffa9a79e84377ca`).
`c04-source-publication-format-v2` passes workspace formatting in 2.46 s with
all 1,560 source/config pins unchanged. No runtime behavior changes.

The next integration is split explicitly: M03 activates actual constructor,
protected prior-control planner and actor/snapshot capacity ownership together.
The exact disk-backed protocol log-ID provider remains a separate, open M05
cutover; the existing ID representation can remain during this intermediate
source checkpoint, without becoming a supported fallback. Failed/unknown flush
must keep the actual capacity token and original error visible to shutdown;
a separate drain shell does not establish custody. Source-shape high-water
maxima must survive even when no byte growth is needed, while replay seeds
advance only after actual successful publication/capture. These are implementation
requirements under review, not passing runtime evidence or closed goals.

`c04-permanent-custody-capacity-current-v1` reaches a definite setup failure
instead of remaining interrupted: 0.04 s test, 17.69 s runner including compilation,
1,560/1,560 unchanged pins. The synthetic backend fixture lacks the installed
physical disk required by the prepared control planner and panics before building
its 4,200-command workload. This does not establish a workload capacity failure.
Root applies the two-test-file fixture correction (manifest
`2c9d4aece8b372fd5df433a5cbe63678fcc8430313360c5da419d98867261343`,
patch `587bb4f309681e60e91bfb6ce2ae4114554e9e906072470ab1c9f92ba26ce949`).
The existing fault-backend physical-owner helper is exposed within the test crate;
initialization and crash reopen use the same real installed NodeDisk and the same
256 MiB/4,096-slot memory provider as scratch. FaultBackend bytes remain the
actual database backend. All record counts, configured snapshot bounds, replay
and crash-reopen assertions remain unchanged. The corrected focused run is
`c04-permanent-custody-capacity-physical-v2`; outcome is pending.

`c04-permanent-custody-capacity-physical-v2` PASSES the previously interrupted
permanent-custody test: 351.71 s test / 358.24 s runner including compilation,
1,560/1,560 unchanged source/config pins. Its original 4,200 commands, more than
8,192 audit events, image larger than the former 2 MiB ceiling, rejection of an
explicit 2 MiB transfer budget, 64 MiB publication/reload, exact crash-reopen
head/receipt and replay/substitution checks all pass. This closes the specific
missing completion on current source after repairing the fixture's physical
owner. It is a synthetic fault-backend regression, not a whole-process RSS or
production performance qualification; affected checks still need final-source
qualification.

Root reviews the frozen, non-standalone control-source envelope v1 (manifest
`556cf8b0b0660d22d05c778415cc7b2ab98b40ec5e99b901ee587531ff2943b5`, patch
`22af2146fe83243182eb98f9eefdcf5003fb5e19f5667c726a855a0cc8e03b9d`).
Review `041efdeb2282181efa6599d6e3b5f27dea97e9c3f47a19ede5c9e5a303cccad9`
finds a constructor regression: its unconditional SEEDS scan decodes and sizes
orphan physical rows that canonical recovery deliberately ignores beyond coverage.
Required coverage is actual accepted retirement headers, including uncommitted
ones, plus any exact permanent boundary/snapshot seed. The implementation owner
confirms the finding and is preparing v2 with finite irrelevant-tail and required
corruption tests. The earlier peer no-finding review remains historical, superseded
on this point; v1 is not applied and no runtime result is claimed.

`c04-custody-physical-format-v1` passes workspace formatting after the
fixture correction in 9.75 s, with 1,560/1,560 unchanged source/config pins.
The separate current Raft all-feature/all-target strict Clippy gate is now running;
it is a component check, not final workspace acceptance.

`c04-current-raft-all-target-clippy-v1` fails two preexisting Raft lints
in 56.35 s, 1,560/1,560 unchanged pins: a nested batch-admission conditional
and the eight-argument target-serving test fixture after physical-owner addition.
Root applies a two-file mechanical correction (manifest
`903edeed3900c4d24dce3ea03019e44b1c6d57be16fa8d761b5b97bb22f44a64`, patch
`98fbfc81287fb2594e2ec877426b5527a57f924265c29141c4f19c3404df0c5d`).
The conditional retains identical short-circuit/error/break behavior; a named
test-only TargetServingKeys groups the same application and custody key owners
at both helper call sites. No allocation, budget, assertion or storage behavior
is changed. The strict Raft gate is rerun separately on this resulting source.

`c04-current-raft-all-target-clippy-v2` passes strict all-feature, all-target
Clippy for `kasumi-raft`, `--no-deps -- -D warnings`, in 14.26 s, with
1,560/1,560 unchanged source/config pins. The preceding failed lint gate remains
recorded. The focused retained-log and prebound-membership tests are being run
against the mechanical cleanup; this does not cover the pending actor/source
integration or close final workspace qualification.

`c04-raft-lint-affected-tests-v1` passes **9/9** selected Raft tests:
54.28 s test / 100.15 s runner including compilation, 1,560/1,560 unchanged
pins. Authenticated streamed inventory, corruption rejection, exact range and
bounded-prefix reads (including full-size legal entries), and the target prebound
membership apply/purge/reopen scenario pass after the mechanical lint cleanup.
Other crates selected zero tests. These results do not include pending protected
planner/control-envelope/actor code.

`c04-raft-source-lint-format-v1` passes workspace formatting in 5.87 s,
with 1,560/1,560 unchanged source/config pins. All live-source Cargo sessions are
reaped before the following isolated qualification.

Root creates a local source copy at `/tmp/kasumi-source-cohort-validation-v1`
(1,845 files including source assets; base-pins.json
`5a3ed1ed10f58746f6eb06c530273c183f72ecb7c7f2e2372d6da5cbbc3a024f`).
It is neither a Git worktree nor production activation. Cargo reuses the same
absolute persistent target `/Users/takemiyamakoto/dev/kasumi/target/disk-backed-cache`;
no clean, new target or serialized job override is used. This permits testing
the complete constructor/receiver composition while the actual actor and snapshot
consumer are still unfinished, without adding a temporary production fallback.

The exact 34-file/52-dependency composition is applied **only to that isolated
source copy**: manifest
`93489236eee2dd23645a283cd68f214084fe188358d64bb2db6c7ac745409b01`, patch
`b36b5d69f356c1a768cd266bedfa26eeb5f2e34b54d6f0f28221b28da6272932`.
Root verifies all saved BEFORE/dependency/AFTER bytes and strict patch application.
It includes protected planner v2 and corrected control-envelope v2 (manifest
`c3e8ee767446388a89d6a39377fcb7dd2b749b7440fe2a28fbcb8344cdee5596`).
The constructor now selects seeds using actual retained retirement headers and
exact permanent boundary/snapshot coverage; it does not decode orphan seed rows.
The focused isolated gate is `c04-isolated-source-cohort-composed-v1`. Its source
pins describe the isolated tree, not the unchanged live implementation. Runtime
outcome is pending; full actor/snapshot ingress and production activation remain
open.

`c04-isolated-source-cohort-composed-v1` fails compilation in 91.71 s,
1,563/1,563 unchanged isolated source/config pins. One new receipt test calls
unwrap_err on a result whose successful AppliedResponse deliberately has no
Debug implementation; no runtime test executes. Root applies the test-only
`.err().expect(...)` correction in the isolated tree (manifest
`bba7a58e73a07da7bfada3e346df75508812fba340857357294ef7afb80f6eed`, patch
`c809ce7175d1b368bb41f947c3add2b63aded44b2f601e5bddcee71397eeffc1`).
The same original error and omitted/repeated-planning assertions remain; no
production response API changes. The rerun is
`c04-isolated-source-cohort-composed-v2`, still isolated qualification only.

`c04-isolated-source-cohort-composed-v2` fails Engine test compilation in
40.45 s, with 1,563/1,563 unchanged isolated pins; no runtime tests execute.
The nested Other fixture still implements the old SelectionPreparer signature,
one new cohort error assertion likewise requires Debug on the success response,
and a projection test has an unused old planner import. The implementation owner
is supplying the narrow test-only migration; the Other fixture must still run
actual canonical planning/publication while deliberately omitting the Engine
preparer, preserving the original invocation-mismatch assertion.

Root applies the three test-only isolated fixture corrections (manifest
`e84d1a774391f18d34e7799b3af27be7d6ce43d8fda983f834ebd88a909bf273`, patch
`ed8be6eb2dc8d0b14f93a04302e04f9a0dbd2647b836a97bc887a214030811f7`).
The corrected Other adapter still performs actual canonical planning/publication
and drops its actual point workspace, while omitting the Engine callback as the
negative test requires. Original failure assertions remain unchanged. The next
isolated gate, `c04-isolated-source-cohort-composed-v3`, includes that callback
negative case as well as the original focused selection.

`c04-isolated-source-cohort-composed-v3` PASSES **34 selected tests**:
16 Engine checks in 3.94 s and 18 Raft checks in 4.17 s, with zero selected
native/Store tests. Runner 52.98 s including 44.73 s compilation;
1,563/1,563 unchanged isolated source/config pins. Actual constructor adoption,
protected Entry Advance and CoveredReplay under DocumentSource refusal, phase-scoped
zero new point grants, callback-safe growth, counted Ready-token drain, original
control failure, and corrected orphan/required-seed coverage pass. Both preceding
compilation failures and their narrow corrections remain recorded. This qualifies
the composed component in the isolated tree only: live actor acceptance, prepared
snapshot handoff and full production activation remain open. Existing application
source/ordinary completion/custody/plan cases are being checked separately in
`c04-isolated-source-cohort-ownership-v1` against the same isolated source.

`c04-isolated-source-cohort-ownership-v1` passes 108/111 Engine checks
(108.92 s) and 42/42 Raft checks (11.16 s), but fails three actual Engine/Raft
startup scenarios: selected_sources_real_local_startup_publishes_entry_and_drains_surviving_generation,
selected_sources_actual_snapshot_install_and_encrypted_reopen_preserve_identity,
and selected_sources_covered_capture_cannot_settle_after_serving_handoff.
Runner 120.87 s, 1,563/1,563 unchanged isolated pins. All report retained startup/apply
failure before their intended checks; the log does not yet inspect the exact
original sink error. Missing actor/snapshot adoption is an explicit integration
gap, but the failure must be attributed through that original owner before claiming
its cause. The passing component selection does not override these failures.

Fixed actor-capacity primitive v1 was reviewed but not applied. Root review
`1b8bd2b6384e79d7027ead6ff18f3f5d1d0c16449fcaff82bdae8f5a3cc3c25f`
finds blocking shutdown behind a held report and a completion-phase observation
which can refer to a later slot occupant. V2 fixes held-report close but its
claimed exact-ID replacement was absent; peer review catches this, and both
v1/v2 remain immutable and unapplied. V3 actually uses nonblocking close and
filters both completion checks by the original obligation ID, adding held-report
and subsequent-occupant regressions. Root applies v3 only to the isolated tree:
manifest `c6e255cc701b93eda66315a63a46919fa8fe4ffa2215b2b15feaf40785aedaae`,
patch `d9dfc9aee693cc50bbf08cdab6f35732796c094a252e627749298191fe48af73`,
three files/19 matching dependencies. The ten vendor primitive tests are running
as `c04-isolated-actor-capacity-v3`. Actual actor/SourceRoots/shutdown caller
integration remains separate and open.

`c04-isolated-actor-capacity-v3` fails vendor compilation in 13.86 s,
1,565/1,565 unchanged isolated pins: four fully qualified size_of calls violate
OpenRaft's existing deny(unused_qualifications). No runtime tests execute.
Root first applies the separately pinned transparent Kasumi/vendor token handoff
in the isolated tree (two files/14 dependencies, manifest
`65264df192e79c5833da29fae2bba2ed67b94697b3334c5989a34730d1b2c670`, patch
`b10f040850ae0daef28f07141e2ed1209e7857f38c0239cb688f8ef5f57344ec`).
It transfers the existing token allocation and adds actual Engine funding/drain
coverage; that test has not run yet. Root then applies the four-qualification-only
vendor correction (manifest
`158e0f6df3bb6a7a84ae0aac36f8b5c17c1a77b901b791f94993f23f4312f23a`, patch
`9460ca18d591bb59397685739f51d2ba981aa00a29b805e180e1fe15948b6956`).
No ownership behavior changes. Vendor primitive rerun is
`c04-isolated-actor-capacity-v4`; no live application or actor activation.

`c04-isolated-actor-capacity-v4` PASSES all **10** fixed-slot vendor tests,
0.00 s tests / 38.69 s runner including compilation, 1,565/1,565 unchanged
isolated source/config pins. Both completion orders and concurrent completion,
accepted/producer cancellation, original append/flush errors, token/funding
retirement panic ownership, held-report nonblocking close and exact subsequent
occupant identity checks pass. This remains a primitive pass, not actor ingress.

Root applies a two-file isolated startup diagnostic (manifest
`3340581c23a0d4e792c38c6bd1d1ebde3ccbb418afe88de73e7c44047733e18d`, patch
`b4ac47f9f9da6d6fddb68f1e32c81784e429f40ce1e1335328fc253607c2a1f0`).
A cfg(test) alias of the actual SnapshotBufferOwner permits canonical borrowed
inspection of the retained original after local startup returns Err. It neither
transfers, acknowledges, retries nor clears that error. The three startup tests
and two real token/Engine-slot handoff checks now run together in
`c04-isolated-capacity-handoff-startup-diagnostic-v1`. The same results and
assertions are preserved; all changes remain in the isolated source copy.

`c04-isolated-capacity-handoff-startup-diagnostic-v1` passes the two new
handoff tests (one Engine, one Raft), and still fails all three actual startup
scenarios. Engine 1/4 in 3.61 s, Raft 1/1 in 0.00 s; runner 89.17 s including
compilation, 1,565/1,565 unchanged isolated source/config pins. The existing
borrowed diagnostic exposes the retained original in all three cases:
`ordinary source plan exceeds funded shape`. Initialization introduces real
membership after bootstrap constructor preparation. Its actual actor-side
prospective-entry growth is required before acceptance; this identifies the
startup boundary without changing capacity or treating snapshot checks as run.
The token tests prove one allocation is transferred and the actual Engine root
obligation survives both append/flush completion orders. They do not establish
actor ingress or final shutdown integration.

Root applies the required actor-slot constructor port to the isolated tree:
manifest `fe2c72079901404944c62181078e3372afc4f67815a5221c8162d55646fc3648`,
patch `b28e88f36519a8d317735c354a6b8d878dd49a4c95be0d443b5a0499cd863209`,
five files/13 matching dependencies. A first invocation named a nonexistent
patch file and made no changes; the strict application then used the actual
`change.patch`. The port quotes the concrete provider Arc and actual fixed
slot/funding allocations before construction. Focused layout/constructor/token
checks run as `c04-isolated-actor-slot-constructor-v1`. Actual adapter calls,
provider-before-slot shutdown and prepared snapshot integration remain pending.

`c04-isolated-actor-slot-constructor-v1` fails compilation in 16.19 s,
1,565/1,565 unchanged isolated pins. The new production Engine method refers
directly to `openraft`, which is only an Engine dev dependency. No runtime test
executes. Its public Raft capacity port needs the explicit crate boundary fixed;
the unused concrete-provider factory warning also remains until actor adoption.
The implementation owner is preparing a narrow correction. This failure does
not alter the preceding token/slot primitive passes on their recorded source.

Continuation inspection finds no live Cargo/rustc process and all 1,565 pins
of the last isolated constructor run unchanged. The preceding turn was progress:
it identified the original startup failure, verified two handoffs, applied the
constructor port and exposed its normal-build dependency failure. Interrupted
agent drafts are resumed from their actual saved files.

Root review rejects the v1 owned-control-gate accounting claim: an inline
Mutex/Condvar size does not bound private platform backing, and parent snapshot
credit does not prove the canonical registry/gate's final lifetime. V1 stays
unapplied. The v2 behavioral prerequisite explicitly retains that accounting
gate, adds a conservative synchronization allowance and measures actual
construction/wait/retirement. Root applies five files/nine dependencies only in
the isolated tree (manifest
`d8626ca35294980008102f2e2ce466177ce6857fef224b42618f978cc3baee47`, patch
`b5c084ae879b74b3719d091c5696e7f060d93ba91f483a85857838be6a58ab5b`).
`c04-isolated-canonical-control-gate-v2` passes four Raft tests in 0.03 s,
33.80 s runner, 1,567/1,567 unchanged pins. It does not prove installed gate
credit or snapshot handoff adoption.

Root also finds the initial competing-writer assertion could pass before the
writer attempted its lock. A separate test-only waiter witness now proves the
actual maintenance path waits on the same canonical gate before exclusion is
asserted. Root applies the two-file repair (manifest
`55b9820e154596c8b84fb81afcb688feec51997d775bd051911ac75de416cf47`, patch
`94aff766b17bc2d1bde5c3067bd279deaa5690f698b2208dac989e8300e3b6e0`).
`c04-isolated-canonical-control-witness-v1` passes all four tests in 0.03 s,
9.16 s runner, 1,567/1,567 unchanged pins. The behavioral evidence now includes
that deterministic witness; actual accounting and prepared snapshot custody
remain open.

The actor-slot repair is applied only to the isolated tree: seven files/13
matching dependencies, manifest
`bbecb995ac7ff682f03cb8c06b2bfacabe65cd9e0c6f569be68305af2dcb309b`, patch
`0adeff65eec12d186086a34116057aeb33ada5b34c2a22ffff5bb3ec0c4082d0`.
It exports the explicit Raft slot type, counts the inactive slot until actual
funding retirement, wraps the actual grant before later fallible checks, and
preallocates independently charged custody for an original retirement panic.
Root drain and vendor shutdown inspect the same retained original. Broader
arbitrary original-error/backtrace accounting remains open. Focused actual
reservation tests run as `c04-isolated-actor-slot-repair-v1`.

`c04-isolated-actor-slot-repair-v1` PASSES nine selected tests (Engine eight,
Raft one), 57.05 s runner including compilation, 1,567/1,567 unchanged pins.
Actual grants, counted empty-slot lifetime, retry and shared original retirement
failure are covered. This is not actor acceptance or snapshot activation.

Root applies the actual ordinary actor provider only to the isolated tree:
26 files/16 dependencies, manifest
`d5d5d318bb67f1e70e3e9e84621c6f207c64afa6f058ede325f07d9b7893aa97`,
patch `9746e58559c0b2fda5b6e863902d1509ec68d51b4011f2b44e2b8afffb4e0057`.
The callback/enrollment repair follows (five files/two dependencies, manifest
`34869e020d58c65ba1f1fd6267cff83f96e201736e4f824d3cbd12edf5eb3861`,
patch `2036e2fad56bff21c1bf241e7a6afcdc33d5c9579d245731b1b24bd0a61e76d1`).
It rechecks sealing under the slot-owner lock and moves actual funding retirement
outside that lock, preserving an observable closing state.

Explicit Authority/Custody fixed capacity is prequoted in the existing snapshot
constructor. It never substitutes for missing Engine source bindings and does
not claim to fund native writes or candidates. Root composes its four-file/eight-
dependency artifact with actor and callback changes: manifest
`cfab42f8e5e179066f0c4f42fbe0a1ca6f2819585bf92c80ab26125018cc76e2`, patch
`67df5698861096f60efbc2f7acd2bc9efb0bda33134ffbf1a2ac58864db8ccf1`.
The explicit Authority service constructor follows (two files/four dependencies,
manifest `d3797c5a5f3d36f7374667bb9ea57fb181daf3fe156daea2ad2bc3e9289edc59`,
patch `8c238f504beeff05497e50dd9d12aac867a6a8601911aa84fd40a2f348f2060c`).

`c04-isolated-actual-actor-startup-v1` FAILS compilation in 17.15 s,
1,571/1,571 unchanged pins. `RaftLogStorageExt::blocking_append` still constructs
`LogFlushed` without the required capacity half. No selected test runs. The
companion makes the production extension accept a real guard and explicitly
names the feature-gated fixture setup helper; 22 files/four dependencies,
manifest `b7bacc9863bb7f22c307ddeb34e77389e056a2cb079d015603219358411af048`,
patch `787451dfd91a75a095483001f671263b94a43dd6838c98addf7a5f40d3100e3c`.

Snapshot certificate v1 stays unapplied after peer review found replaceable
backend/table ownership and loss of per-schema maxima under equal aggregate
byte bounds. Corrected v2 binds the exact replacement descriptors/backend and
returns the validated grown envelope. Its first strict application rejected a
known Authority constructor change in `lib.rs` without mutating the tree; root
explicitly composes that change (ten files/11 dependencies, manifest
`1d88b08908fa858e6a4c3d73f8ead4076a9d1a4e9b1a05c50e2b67a1e66f4294`, unchanged
patch `ad2b6b2282df6758034eef773571b7f577cb91809b71100b9f2bb21eb55ecb0e`).
The vote corridor follows (three files/nine dependencies, manifest
`be91f326224ea6a962502d0c1c2f1d25b86c7597a073db065fa6b9468627cec6`, patch
`00c6d870dbc43fa9665922a5d2aabf3acf34d22019ce0fe7626c2bb33a9d0550`).
It separates vote-only I/O from snapshot-conflicting control writes and orders
conflicting control admission before I/O admission. Actual owned restore and
snapshot actor barrier remain open. The composed selection is now
`c04-isolated-actual-actor-startup-v2`; gate/registry and arbitrary error backing
accounting remain explicit production blockers.

`c04-isolated-actual-actor-startup-v2` FAILS test compilation in 108.31 s,
1,573/1,573 unchanged pins: two ordinary read views use a nonexistent `finish`
method and one vote fixture supplies an applied context instead of an Entry.
The first proposed `drop(view)` correction is not applied; root requires actual
`view.close()?` so original retirement failures propagate. The applied one-file
correction has manifest
`51b130b5d007e184dd6cd1adb7666af7a49e2635808a601846ba3a88c71845c9`, patch
`ad5e6addccd560050a9ccdf0d2685aca66a9ab046eb3b1f3e3d65185656d157f`.
Its claimed Entry edit silently missed the renamed helper; v3 still FAILS that
same type mismatch in 65.77 s, 1,573/1,573 unchanged pins. Root's exact-call
correction supplies the actual Blank Entry, with an asserted single replacement
(manifest `80b4762389ebf4f32228df97217a4530d5935bfa40092c6d2ba319a6981327d5`,
patch `c4db0a029c2a4260154906b2d350edc539efe909b400b9c107e206d27428e7a3`).

`c04-isolated-actual-actor-startup-v4` executes the intended checks: **Engine
2/3 PASS, Raft 9/9 PASS**, 72.19 s runner, 1,573/1,573 unchanged pins. Real local
startup and covered handoff now pass. Actual snapshot/reopen advances beyond
startup and fails `protected source requires an actual producer plan` during
installation; that is the remaining prepared-snapshot receiver gap. Passing
Raft coverage includes all three explicit-role cases, both startup-owner cases,
three exact snapshot-certificate cases (including real nonempty replacement
tables), and higher-term vote save/read while real purge waits on the held gate.
These are not full snapshot actor handoff or final source activation.

Root applies separately funded original diagnostics and positive internal-refusal
slot closure (13 files/four dependencies, manifest
`b27bd907fbaaff370843eac0abcfaa3d593f14a5c6fbe53431afc61dd3cdc090`, patch
`98b810ec88827911938aa0d87e083a4a0c78db452b5ad054963c3fc7d0b7a1f5`).
`c04-isolated-actual-actor-refusal-v1` FAILS vendor test compilation in 10.89 s,
1,573 unchanged pins: two direct RaftInner fixtures lack capacity shutdown state.
Their explicit fixture adoption follows (manifest
`6dbd94d2fde1a4d9eef825fd8d2ae956890bd2589ecb9613cec3ba4177846176`, patch
`ddbdf81815e06354533aaf3bdc3dddc230abd16e956280690b0862915b4941a2`).
`c04-isolated-actual-actor-refusal-v2` PASSES **14 vendor tests**, 32.61 s runner,
1,575/1,575 unchanged pins, including actual internal noop refusal, joined actor
shutdown and original diagnostic lifetime. Arbitrary original error backing
and remote refusal cleanup are not qualified by this focused pass.

The exact owned-Send backend restore migration is applied in the isolated tree:
24 files/19 dependencies, manifest
`ffbde5c48c5bc02fb00f12dfae5bc1f4b144197a50050d6246ec65c43147117c`, patch
`5c9e1e4aceae0e330299b4771f4e794ae78475575f9917642c03844f41220657`.
It retains the actual concrete backend and lifecycle Arc and uses the same
borrowed/owned backend exclusion. Native staging retirement and synchronization
backing charges remain separate required gates.

Root replaces the uncharged control-gate HashMap with private charged handles
and individually reclaimable list nodes; the exact persistent admission provider
funds the gate, shared lease owner and registry node before allocation. Weak tails
retain charge; the last handle removes the actual node and callbacks occur
outside the registry lock. It preserves the actual store Arc against address
reuse. The source is explicitly composed over the owned-restore migration:
five files/seven dependencies, manifest
`a0e02ea4e806d147b47c3560e7931f6dc369a0c3117b583581a095b2a1d6d729`, patch
`e77db4b14b1fad6e07f34f0f508e761ad2239dec2d6a4d92ef20cc99ce0bc5c9`.
Payload/store destruction panic conservatively retains registry credit and
still requires typed failure/drain integration; no whole-memory claim is made.
Actual quote, pressure/refusal/retry and final-permit retirement tests run with
owned-restore tests in `c04-isolated-owned-restore-funded-gate-v1`, including
Authority compilation. The canonical borrowed snapshot ABI draft remains
unapplied until its worker, actor and concrete backend companions are complete.


The owned-restore/control-gate selection preserves every failed attempt:
`c04-isolated-owned-restore-funded-gate-v1` fails compilation (50.90 s): the
tracked backend bridge has not adopted the Arc-owned restore API and a gate
Debug derive requires a non-Debug TenantStore. The explicit tracked-handle bridge
retains the original backend lease through restoration (manifest
`cf97242a9be68a73ad09b4fd16fdb39619fd1bde4d226374ca69c06eb0a68b4f`); the Debug
correction is `4123cdc0b3a73d69ce6484b5c859846fc1449b2f567c5691b1e681aa5b3d4373`.
The once-only received-spool freeze foundation is also applied (manifest
`611b0a0decd4f8aade650aac8a87f87c523eed649c38e794693d326c5131247f`).

v2 fails compilation in 27.61 s: a diagnostic fixture references an absent owner,
a deliberate unwind fixture needs AssertUnwindSafe around the new provider, and
Engine seal cleanup still expects the previous poisoned mutex API. Corrections
are the actual shared poisoned seal gate
`73e3a0b6a241f0876882c0b8ad2c3a3920ed0e8a2d3386c745c9a4b9e20d53c4`, deliberate
unwind fixture `dc63f9c062fc762e40695b67d2fbc0e5c2c151406a8e2fa54eb123c49498e51c`
and real diagnostic charge fixture
`c4174e4799cbe482af305aadbaf30a08bc6a40014cef3bb1a2866a1b05a14ea7`.
The exact retained SnapshotImage native-close foundation follows (manifest
`113f61c40b82747839e9602878caefa487cf3427b9ac71d0b9f061334d8b360f`).
v3 fails compilation in 123.66 s because a test witness still returns `&()`;
its correction returns the actual new apply guard (manifest
`bc8f357ae72a40e4188e4beea94559f64c66b8956d33c0d9efab2830013fc428`).
All three attempts retain 1,576/1,576 unchanged pins.

v4 executes **Engine 2 PASS, Raft 11/16 PASS, Store 3 PASS** in 323.91 s,
1,576/1,576 unchanged pins. Authority compiles. Passing checks cover shared
backend exclusion, owned restore custody, startup callbacks, frozen spool
handoff and positive/failed original SnapshotImage retirement. The intended
actual Engine cross-thread test was NOT selected: its precise name is
`validation_baseline_real_prepared_restore_holds_one_checked_apply_owner` and
must run explicitly. Four Raft failures use synthetic fixtures without an
installed persistent disk; gate admission now uses the mandatory ScratchDisk's
actual shared NodeDiskMemory provider (production construction enforces the
same provider). The fifth failure counted destruction of a provider lease
created outside observation; the test now observes its actual creation and
retirement together and includes the concrete provider quote. This two-file
correction is manifest
`6550f6e99077be24c3e514017c4af0efc25881b294be46f85ab913049352b042`, patch
`8181b3886dd4ee8a0b1d97c8137e19a0b9994edf694c85ba7ac97ca2cd9d1d36`.
v5 **PASSES all eight selected Raft tests**, 30.63 s, 1,576/1,576 unchanged pins:
five canonical gate and three fixed-role checks. Other crates compile with zero
selected tests. This does not qualify snapshot actor activation, synchronization
backing, arbitrary error allocations, or typed gate-destructor failure drain.

The snapshot source receiver v1 is deliberately unapplied: review found grant
retirement outliving its counted obligation and missing positive queued-source
cleanup. Receiver v2 fixes both: an independently prequoted failure owner keeps
the original cleanup panic, the actual grant retires while still counted, and
explicit candidate retirement cancels the exact queued reader/returns its point
loan and observes native disposition. Its manifest is
`baf1f7f58018f2922766d426e2d9ce0ed721f7f6869bdb3e54b107c162e29c39`, patch
`17bab279e4bfac573b1144d99911f6ea71e6897669e5b7344a618fb471276200`.
The focused peer review resolves both original blockers (review
`1dd59437b7cae3ba1a17a0c887125bf44ece3eca5643919eb98ecf697644cbf1`).

Root composes receiver v2 with mutable backend publication/native staging
retirement, monotonic publication-start state, candidate-only Engine source
retirement, fixed snapshot provider, and the received-spool shutdown-latch fix.
The exact 29-file/19-dependency composition is manifest
`8d6534d6f80c5cfc1c7f5f568d4f28b1196b740f9fa8d5dddcb46182062131ff`, patch
`99dcda7d08d7eeaaca27c720443d50053a5240bdacec86e6478f321db045ccdb`.
`c04-isolated-source-restore-cancellation-v1` executes **Authority 1 PASS,
Engine 5 PASS, Raft 6/7 PASS**, 192.69 s, 1,576/1,576 unchanged pins.
The actual Engine cross-thread prepared restore test now runs and passes, as do
native staging retention, exact queued-source cancellation, counted grant
callback/reentry, original grant panic custody, and freeze after a completed
transport shutdown. Raft's new context-identity allocation assertion fails with
72 retained bytes: the fixture supplies Reopen, so it measures the intended
invalid-mode error allocation rather than valid incoming-install comparison.
Root changes only this test's context to Install (manifest
`198f99b5a5dcff68da2fb9ded58840bd6a8a8b116e417e756c4239a4eb1dc756`, patch
`2c7a758b4f300aab057c3b4fbad22cdd4e813073b2fcf7523924b850d74ecafd`).
`c04-isolated-source-restore-cancellation-v2` **PASSES the exact formerly failing
Raft test**, 10.14 s, 1,576/1,576 unchanged pins. The production identity function,
no-allocation assertion and negative Reopen/body/metadata checks stay intact.

The native precommit audit remains an explicit M03 gate (plan hash
`91458696a1be1a2a58762126d94cdd2363f694792f8e44d968de22853e3d6e1b`, source pins
`521437f96d211579639cbeece733cb4cb957532c42033b6bd80cbb84c7ae0ff2`). Native
write workspace and exact physical transaction claims are currently acquired
inside commit, and a retained WriteTransaction monopolizes the shared node
writer. Holding it across actor handoff would prevent SaveVote progress. The
required extension is a separately admitted, node-bound publication allowance
that coexists with votes and transfers already funded subsets into current-root
transactions without a fresh ordinary grant. It must cover every old/new
namespace row, all conflict-deletion chunks, encryption/materialization backing
and final replacement publication; source DTO quotes alone cannot authorize it.
No snapshot activation or complete memory claim is made from these component
passes. Production document/index cutover and full-residency qualification also
remain open.

`c04-isolated-source-restore-regression-v1` PASSES all **15 selected Engine
source-cohort/actor-slot/startup checks**, 7.77 s, 1,576/1,576 unchanged pins.
No other crate has a selected test. This reruns the affected ordinary source
path after the restore funding/retirement changes, without changing its limits.

The retained closed-custody body, exact decoded-envelope ownership and distinct
ClosedSnapshot source certificate are composed with explicitly recorded known
mutable-restore dependency changes: 12 files/17 dependencies, manifest
`69c4a65dba42d69d350fd48e3ae33588795afa5c40218b213adfe5ae0da8c7c6`, patch
`9116869d69417255f72aac4726b9788ef1ad3512a42c6262adb24b00356996b6`.
An Engine receiving a custody snapshot uses this actual paired-store producer
certificate; it cannot fall back to a fixed provider or fabricated empty append.
The certificate merges control/membership capacity shapes without advancing the
application replay seed or minting a successor application-source loan.

`c04-isolated-closed-snapshot-body-v1` FAILS compilation in 37.41 s,
1,578/1,578 unchanged pins: retirement code names KV's disposition enum although
KV is only a Raft dev-dependency. Store now exposes the actual close outcome and
disposition in its public image API; Raft consumes those types through Store
(manifest `05a71fc58f8c529314866a8b9aa9398d1a04e398ff5291379ea219ac2526726e`,
patch `645687e1bd257e6267c0784c41d8b2f0140b5a1a0f73baa28d34c83a2231735a`).
v2 compiles but FAILS both selected tests during retirement-control fixture
setup: `synthetic backend fixture has no installed physical disk`, 192.95 s,
1,578/1,578 unchanged pins. Neither reaches its intended body assertions.
Root installs the missing real NodeDisk fixture owner using canonical
`fixture_on_disk`, retaining the original injected FaultBackend, memory caps
and assertions (manifest
`22b3ed08409d8e507c2720fea04b2ff326aac615d39f0803f80f04ba3a588308`, patch
`4b7091a81bce7c6c7039d1494229c6b648fc19c212690630571d65a599b8ab60`).

The Application body/positive native-retirement/explicit-role/log-binding
checkpoint and closed aggregate are composed over current tested APIs in seven
files/16 dependencies (manifest
`ebf303e1d945d6187d3e7573290fd8c308dc5a2ae51163a35e01128d141a5ca8`, patch
`28a786c28e325025603b7ac89ba74e1196dc4137962e909e31623d58d736b2b3`).
One earlier role-call three-way attempt refused a formatting conflict without
mutating the tree; root explicitly moved the exact current capacity-factory
block ahead of StateMachine construction, preserving all prior API changes.
The composed Application/Custody selection is
`c04-isolated-all-snapshot-bodies-v1`. This still excludes the mandatory vendor
borrowed snapshot ABI and tracked-child activation. The actor successor has an
explicit source-ready wake and joined-shutdown corridor, but remains unapplied
until its concrete companions compose; native precommit funding remains open.

`c04-isolated-all-snapshot-bodies-v1` FAILS compilation in 24.36 s,
1,579/1,579 unchanged pins: the composed retirement helper calls a nonexistent
`DrainReport::merge_result`. Root replaces it with the actual `merge` on an Err,
preserving merge-before-next-callback semantics (manifest
`ce6dd9f5b7a3dcec39efac4a89ee1390b08ca879af6024a4d0e536c0596b2333`, patch
`610b27b3f8b1c37d40631556cec744e570d54b3cb4094d5a42a5363295e78f0e`).
The first source-ready companion application names a nonexistent patch file and
is rejected before mutation. Consequently v2's two wake-test filters select no
tests; do not infer wake coverage from this run.
`c04-isolated-all-snapshot-bodies-v2` PASSES **all nine selected Raft body and
certificate tests**, 294.33 s, 1,579/1,579 unchanged pins. Both corrected real
custody fixtures now reach and pass the intended cancellation/publication,
exact-producer/no-allocation/foreign-gate and failure-retention assertions.
Application staging retention, Send ownership and original retirement-panic
identity also pass. Other crates compile with zero selected tests.

Root then correctly composes/applies the actual separate snapshot-capacity
waiter, the original control/snapshot guard retirement capsule, and positive
backend candidate destructor retirement. The 11-file/12-dependency composition
has manifest `3d5427ea33c08e6566d4d4ed0d8516ddbabf1c3ca89dc56454d990a64048bf91`,
patch `9fcc28a28a08f522d1d22e0719b82331bd21abd0b5dddbac0d84c883fafb8a49`.
The identical already-applied report correction and physical-fixture-only delta
are explicitly mapped to their frozen predecessor manifests. The registered
waiter is distinct from drain waiting, registration precedes probing, and an
unsuccessful Pending probe does not wake itself. A Ready token enters the actual
body before source binding can fail. Candidate destruction occurs once after
positive native staging retirement; unknown publication/drop keeps its original
outcome and independent lifetime/lease custody. The exact original canonical
and snapshot guards can move into an inline final-retirement capsule, retaining
them if an arbitrary backend destructor panics. These checks run in
`c04-isolated-snapshot-final-retirement-v1`; tracked-child/vendor ABI integration
and complete diagnostic funding remain open.


`c04-isolated-snapshot-final-retirement-v1` completes in 247.41 s,
1,579/1,579 stable pins: Engine **1 PASS**, Raft **5 PASS / 1 FAIL**.
Actual candidate destructor ordering, original unwind identity, tracked lease and
staging retention pass. The fixed snapshot capacity waiter reports 64 live/peak
bytes at its first registration. The exact backtrace-only rerun
`c04-isolated-fixed-snapshot-wake-diagnostic-v1` reproduces that original failure
in 1.55 s on the same pins, at the first `register_snapshot_capacity_waiter`.
Root initializes the actual Raft and Engine waiter mutexes inside their charged
constructors, rather than warming the test or changing its quote/assertions
(manifest `9e316d05a6f9760bb07a1b0c5cc996d141f421b9e8a9c2ddb1b5acef502e9347`,
patch `16d003062e22ce3af32c5c1427d47a61b775bfa215e1eca8d45af3efd58a859b`).

The next 15-file/23-dependency composition adds the real tracked snapshot body
child, preservation of Complete-with-errors cleanup reports, and the physical
publication allowance foundation (manifest
`9c6d6cc9211c3469e341b21adb68b4419411862c8d5b463d4bfd54f6663d2593`, patch
`c14f831add32d1c02f6b3caa47fa3fc7c7ae64595859a99faf4fb7bb34ccfd15`).
`c04-isolated-snapshot-child-native-v1` PASSES **41 checks** in 243.70 s,
1,582/1,582 stable pins: Engine 1, Raft 6, Store 34. All four actual child cases
pass, including canceled polling, no restaging, original refusal only after
candidate destruction, and the same native cleanup issue retained through final
Complete census. Fixed constructor heap bound and allocation-free registration
both pass. All eight new native allowance tests and 26 existing transaction,
namespace and managed-directory regressions pass. This is foundation evidence;
no canonical snapshot Ready yet owns complete native publication capacity.

The next 13-file/30-dependency composition joins the private group allowance
consumer, bounded selected-primary query adapter, retained decoder and actual
snapshot seed/update owner (manifest
`479416128484527289bae7ee86ba6bdbcf2d56e72ca94f4149e5ae17ef4f82da`, patch
`f98d3c267861ec20c8c11d6bda45c91da62ca775978f704dfe286ac10bd3e4b7`).
It is under `c04-isolated-native-primary-decoder-v1`, 1,585 source/config pins.
The group consumer protects promised entry capacity across ordinary commits,
validates each exact current root, and closes actual descriptors before returning
slice rights. Actual-batch geometry/workspace and paired Store publication are
still required. The adapter does not consult resident document maps, but atomic
primary/index production cutover and a full-fit decoded cache remain open.

`c04-isolated-native-primary-decoder-v1` FAILS compilation in 101.40 s,
1,585/1,585 stable pins. The Engine test-only `CollectionRecords` implementation
names the ownership-carrying `ReadFailure`, which intentionally does not implement
`std::error::Error`; the trait requires that bound. No selected tests ran. Store
and Raft production code compiled. The correction must preserve the actual
failure and its native reader/grant custody, not stringify or discard it.

The associated query failure bounds are corrected to the actual required
Debug/Display/Send/Sync capabilities; no Error implementation is added to the
ownership-carrying primary failure. Existing original-failure identity tests use
a non-Error source failure. The first composition refuses missing saved dependency
files before any mutation; a successor copies all three exact hash-matching
inputs with unchanged manifest/patch. The five-file composition includes the
original inline seed and receiving/frozen cancellation (manifest
`e3627aae32f5ff605bbd0be698217315e3bae3a06e86b89f947a9faacf5ebecb`, patch
`786e80146766795b4795f598cc46b019f12e2f9331f9e3ee74af13931295aa68`).
`c04-isolated-native-primary-decoder-v2` FAILS compilation in 14.29 s on
1,585 unchanged pins: the Prepared branch is handled by an earlier if but is
still required by Rust's exhaustive match. Root moves the same branch inside
the match, with no fallback or changed cleanup behavior (manifest
`5a89f8cf52de201aba5bc052d61f83b963b68a00569f487363712970767ee1a5`, patch
`3d684ee8b67a7edc63f1637b6692806fdb4548b5ffbb994e713a60dc0d4ee116`).
The same selection plus query custody regressions runs as v3.

`c04-isolated-native-primary-decoder-v3` FAILS compilation in 94.62 s,
1,585/1,585 stable pins: the existing retained `SnapshotOperation` facade requires
StdError diagnostics, while the now more general query input trait does not.
Root states that capability explicitly on the two existing QuerySourceWork
operation implementations (manifest
`9fe22ba1a06cd212297403d8e55c071a2332be539ee153504cadc2317d216a89`, patch
`383bb18d41f4bce06d6c2e4f816483830b97ac37754cd398a72ffaa399a51733`).
The original primary ReadFailure remains typed and non-erasable. Its future
QuerySourceOwner still needs a retained cleanup/diagnostic facade; this repair
neither provides nor claims that integration. v4 adds all existing
`query_source_work::tests` to the prior combined selection.

`c04-isolated-native-primary-decoder-v4` reaches runtime: **41 PASS / 2 FAIL**
in 157.29 s, 1,585/1,585 stable pins. Engine 24/26, Query 5/5, Raft 8/8,
Store 4/4. The complete group consumer tests pass: occupied metadata slots
cannot trigger a new grant during actual publication; positive retirement closes
real cache descriptors; pristine reuse returns original rights; an ordinary
native commit proceeds while parked and stale root reuse fails; live original
custody prevents premature close and unknown drop retains space through census.
Both actual retained-decoder tests, both receiving/frozen cancellation tests and
all four prepared-child tests pass. Generic query original-failure custody also
passes with non-Error source failures.

The primary adapter's positive query encounters an archived row requiring bounded
hydration, which correctly returns existing Unavailable; the remaining three
adapter tests and selected-primary primitives pass. The retained worker's old
negative fixture fails before its target because protecting every unused slot
would spend the mandatory cache-work floor. Root preserves that setup as an
explicit negative policy check, then occupies actual ordinary slot/byte grants
at the unchanged capacity to exercise original-source metadata refusal. Original
identity, grant, registration, cleanup and no-leak assertions remain
(manifest `a9092336635020d43adb760413432f14f2e7333e4770f71e07c7a099c53a7759`,
patch `bf13ff1c5f0411f60dcc1f4fa440ccbfc064c1904c15d7af6713eb6a6f8257b3`).


`c04-isolated-primary-query-fixtures-v1` records **17 PASS / 1 FAIL** in
69.31 s, 1,585/1,585 stable pins. Actual slot/byte-pressure ownership tests pass.
The primary query now correctly selects the disk-backed indexed live row and
rejects unhydrated archive content; its remaining assertion used a field name
instead of the established literal JSON-pointer projection key. The two-file
fixture composition is manifest
`41d553744235499b4a7164610409e44f540dde2b901fb741c923d6176f4e6bf8`, patch
`289f9221e78b8149ebf42c64173e01b924f5dae5c5e68776967e42bf890717ef`.
Root verifies the existing query implementation and document-source regression
before correcting only that key (manifest
`737b75e1c58df41005f16bc6aa1ff35c570d6074cd5c73f678b8f1dbd485c4db`, patch
`8e2df4d81c3dc65d5ffa89f4457b0ac0a661cdb8c053cc74716d7b462495fd74`).
`c04-isolated-primary-query-projection-v1` **PASSES 1** in 26.39 s,
1,585/1,585 stable pins. No production document/cache cutover is claimed.

Native actual-operation inventory/geometry is applied in isolation (six files,
manifest `a413c91971fa1300a3c8fd23c620214b76fe6e812ef0a1b63f0f1d1059096957`,
patch `098a736552538180a858cc8ccbe1be010bc499b63f89b1d66f739ab33c7ddd13`).
It folds actual encrypted operations into fixed descriptors and derives native
writer geometry with one reusable tail slack per kind. It is not an allowance
or proof of accepted publication.

The mandatory publication protocol and Store backend bridge compose 32 files
(manifest `1901723176b5e79f4d1c7ccf401a0949157b246e0828cfb4300cd727c5e1ef56`,
patch `2121a14b1ac71cfaf8f38e7487c71e62d88a12f78e1f27ce833aad5ba5627a23`).
The actual backend binds namespace incarnation and publication generation,
converts logical geometry using the installed disk allocation policy, and
returns or retains the original physical rights after real descriptor closure.
Wrappers forward their original backend; unsupported scratch/fixture backends
explicitly refuse. No ordinary transaction fallback is introduced. Focused
inventory and actual canonical backend validation runs as
`c04-isolated-native-publication-backend-v1`; reusable native workspace and
whole snapshot producer inventory/cleanup remain separate open obligations.


`c04-isolated-native-publication-backend-v1` FAILS compilation in 8.43 s,
1,587/1,587 stable pins. The fixed descriptor decoder's closure needs an explicit
usize index; root adds only that annotation (manifest
`e928e51d979e105d15b4207d1f39c741528f571ca692f04d6b6b38a200db48b4`, patch
`96585b8df0e12ae54d6f9be72c835fa4418dd82e69ed214f9920e62fca240363`).
Peer review also finds opaque validation-credit destruction under the group
lock. Positive release now removes the actual retired owner, releases the lock,
then destroys it; stale abandonment cannot fence its replacement generation
(manifest `beceecdb3dc69e65d22f07cf51e980c6c543669642d7d84b5b89b948e89855cf`,
patch `b0bac65b9d7cb9935ec587e8ffad31c5e78ac08d2db839649a9017e49ae65347`).

The coherent mandatory snapshot API checkpoint applies 46 files in isolation
(manifest `14c2bc175aefc4250b20746caada66fdd227abb75a04ee553e1e4ad7fba8677a`,
patch `5e592ec14e6f90198e0b1e09dacc1d4130f49eeacfa33a6dcc379594b902b729`).
It preserves the actor decision and original received body across preparation,
installation and cancellation. Preparation explicitly refuses before decoding
while the complete native producer is unbound; no successful activation is
claimed. The historical consuming installer is test-only and explicitly named
fixture_install_snapshot. This checkpoint also preserves actual conflicting-log
ownership, fixed incoming-constructor funding and higher-term-vote progress.

`c04-isolated-native-canonical-snapshot-v1` FAILS compilation in 56.86 s,
1,593/1,593 stable pins. Vendor errors are nine denied unused qualifications and
one missing conversion from StorageIOError to the original owned StorageError
for shutdown. Store's fixture helper selects the new Arc trait forwarding
method rather than its concrete helper; root switches to explicit concrete UFCS
(manifest `affe4a5779da52657fb651106dc0d498878611f379725bddf2b7c83ae9bfddf0`,
patch `e646bced1f6bb0175a38b29b56913efcc117f804617bc9b0838c113bf4c7844d`).
No selected tests ran; correction and composed revalidation remain required.

The ten-file actual encrypted producer applies separately in isolation (manifest
`321cfec7a360dbaa2d1bfc7cd5b9c7da330fbb752891daafec73232cdcf9d48f`, patch
`57b40ee84ddedbfd7ee926a047b60b4d540f4ec5afdb3d496928dea24a7df87f`).
It inventories deduplicated old/new ciphertext through bounded encrypted staging,
retains exact store/node/key identity, stages exactly one final atomic image and
supports inventoried cleanup batches. Repeated execution borrows the same frozen
image with typed original source/consumer errors. It holds no native writer
while parked. Actual preclaimed native execution and cleanup-plan integration
remain open; fixture ordinary writes are not accepted-path evidence.


Vendor compile corrections and the actual streamed segment component compose in
14 files (manifest `6d653ac06947da72c76ed39084a678ab484232904b33570a84bb312609fe1f19`,
patch `28fbd45ed930e2283ddf3583824b05fbd74d1d00e2eb5e018a5b9b67ac17ffbf`).
The segment component retains actual value-location and codec workspace before
execution, borrows repeated ciphertext passes, and reuses the canonical commit
codec. Changed preflight rejects before effects; effectful source failure/panic
retains the original diagnostic and fences its original writer. Complete Core
directory/proof/cache/counter funding still needs integration.

`c04-isolated-native-canonical-producer-v1` refuses the command before compilation
in 0.71 s (1,602 stable pins): vendored openraft is a separate workspace, so its
dev tests cannot be selected with -p from the Kasumi workspace. The corrected
Kasumi command is v2; vendor tests run separately with the established manifest,
serde/storage-v2 features and shared warm target.

`c04-isolated-native-canonical-producer-v2` FAILS compilation in 61.54 s,
1,602/1,602 stable pins. Vendor production code compiles. Store needs the two
staging methods visible to their parent and a production retained-spool close
path instead of the test-only receiving-spool helper. No selected tests run.
The companion correction also must retain actual reader and unknown constructor
custody before reporting staging retirement; those findings remain open.

`c04-isolated-canonical-snapshot-actor-v1` FAILS vendor test compilation in
31.79 s, 1,602/1,602 stable pins: one missing PendingSnapshot import and six
strict unused-qualification errors in test-only code. The production fix did
not prove vendor test compilation; no constructor or actor runtime pass is
claimed by this attempt.


The vendor test-only compile correction applies (manifest
`948b363a9e8299b7c1fc376892f01cb2112853e7785e0662e889709d0f11eaa2`, patch
`98a4fd4fc2d96c53f264017719a673c3c7cfa79e458ecdd35bae2877c604ce52`).
`c04-isolated-canonical-snapshot-actor-v2` reaches runtime: **13 PASS / 2 FAIL**
in 33.78 s, 1,602/1,602 stable pins. Actual constructor funding/deallocation,
worker ownership, capacity wake with ticks disabled, and covered shutdown tests
have scoped passes. The new constructor measurement's first decision/wake still
allocates 64 bytes, violating its unchanged zero-allocation assertion. The
higher-vote preparation test does not grant the expected vote. Both failures
remain open; passing cases do not establish the complete actor corridor.

Producer reader/constructor custody and native reusable cache proof compose in
nine files (manifest `ede6c0e44e2b8a1af19d4fc0e4a0b8463014625aab37e2d14c41bef6b95fdde6`,
patch `7086b463e2c33510537d80e573c1458c03765c71ee0f3c95d5775e3e3d8018aa`).
The producer uses the production retained-spool close API and keeps original
failed reader/constructor ownership in its report. Absent fields do not prove
positive cleanup. Actual typed table-constructor Complete can settle; unproved
spool constructor failures remain Retained. Precise pristine/positive spool
refusal is still needed for the final retryability gate.
The native proof now owns real cache-proof and pin-vector backing in advance,
refreshes that same capture for intervening retained roots, and shares factoring
with ordinary commit. These changes run in
`c04-isolated-native-canonical-producer-v3`, adding actual capture and ordinary
publication failure regressions to inventory/stream/producer/backend/canonical
snapshot checks. No activation or final-source pass is inferred yet.


`c04-isolated-native-canonical-producer-v3` completes in 396.59 s with
1,602/1,602 stable pins: **40 PASS / 15 FAIL**. All ten Store checks pass:
four real frozen producer/replay/identity checks and six actual publication
allowance/backend tests, including saturated ordinary registrations. KV passes
eight of nine: all actual inventory checks, retained-pin refresh and effectful
source failure/panic pass; streamed codec reopen rejects its commit record.
The shared finish path uses the empty returned-value vector length instead of
the actual prepared operation count. This is a real codec defect requiring
repair, not a fixture/limit change.

Raft passes 22/36, including both new actual canonical refusal/cancellation tests.
The intended snapshot-conflict tests did not run: the path-attributed parent
module's plain `mod tests` selected storage/tests.rs and duplicated its larger
suite. Fourteen synthetic-backend fixtures lack the installed physical owner
required by control planning and fail before their intended assertions. Preserve
those setup failures for M01; they cannot supply conflict-protocol evidence.
Root pins the actual intended test file explicitly (manifest
`c42abf36073b8dbcd5fb87d14c90398ad8702e3af0021c9b5bc9d594eece3075`, patch
`c96e4adf3958b1405dff930d44e08639674e07b22806899231b06db166f5dd6b`).

The next nine-file composition includes that test-module correction, first-use
synchronization/actual vote-lease fixes, tracked Raft cleanup producer and exact
Store/native source trait adapter (manifest
`4a081c7ee8890a3afa68dc8ec9ffff55867956325f541ec6bad1fc594fde1dc3`, patch
`58688b97137117aa1e001c8730656bb39491fc9dfde178ab91b4485d20f417cd`).
`c04-isolated-canonical-snapshot-actor-v3` **PASSES all 15** in 19.26 s,
1,603/1,603 stable pins. The actual constructor initializes its state semaphore
and both Notify wait-list locks within its quoted retained funding. First real
decision, waiter registration, polling, wake and Waker retirement allocate zero
under the unchanged strict test. The higher-vote test waits the configured
committed leader lease while holding the same prepared body, then preserves all
vote-grant, durable-vote, cancellation and no-install-effects assertions.
Actual last-Arc retirement, source-capacity wake with ticks disabled, worker
custody and joined shutdown pass. Complete native snapshot execution is still
unbound; these passes are not a successful-install result.


The actual streamed operation-count correction applies in three files (manifest
`c764ef414068c848c260df51c53291e3c796b6f58172fa7848b86560270ce097`, patch
`f4afe3de34ef3a6ccb516ca2455753b3c35ed75af6ab0fe46b04c972d4f80d81`).
Ordinary preparation validates its actual value-location count; streamed
preparation validates the retained workspace's count. The shared canonical
commit encodes the actual prepared identity count. The original streamed
codec/reopen assertion is unchanged, with a new malformed ordinary count
pre-effect refusal check. The corrected actual conflict tests and Raft cleanup
producer tests join revalidation in `c04-isolated-native-canonical-producer-v4`.
The attempted singular publication_failure filter matches no existing ordinary
failure module (its actual name is publication_failures); ordinary failure
coverage requires the correct selection or the full native suite on this source.


`c04-isolated-native-canonical-producer-v4` FAILS compilation in 51.97 s,
1,603/1,603 stable pins: the Raft cleanup producer needs a qualified anyhow::bail
macro. Root applies only that correction (manifest
`757cd3a940d5e773a2f86b9b2018977870bb9c452e1bb66d6002db24a8307791`, patch
`3ac07f86e5e97f3fb8f3046547a4a467b57c1a5c34a2169a09fa720d2b647e2e`).
`c04-isolated-native-canonical-producer-v5` **PASSES 32** in 175.22 s,
1,603/1,603 stable pins: 14 native, eight Raft and ten Store tests. The real
streamed canonical codec reopens correctly, malformed ordinary operation counts
refuse before effects, and the correctly selected snapshot conflict and cleanup
producer tests pass. The actual ordinary publication_failures selection runs.
No canonical successful-install or production document/index cutover is claimed.

The shared ordinary cache-proof and commit codec changes justify the complete
native unit suite on the exact same compiled unified-feature test binary.
`c04-isolated-native-full-consumer-foundation-v1` **PASSES all 565** in
6.85 s, 1,603/1,603 stable pins, with no ignored or filtered tests. The original
555-test live baseline remains separate. The complete prepared native consumer
and its Store/Raft integration are still pending; this foundation result does
not qualify their future source or whole-process memory.


The actual caller-owned spool setup component applies in eight files (manifest
`f2ef4e4aa4460ef7d758593b152c8b5b9b0e3a6f7137754389e0370d25001e5a`, patch
`901c755397adeeae04c46a113d44bc2e80414ea9eb2c83bed8dc9e2ea13673e9`).
`c04-isolated-spool-constructor-custody-v1` **PASSES all 32 selected Store tests**
in 276.18 s, 1,607/1,607 stable pins. Actual pre-effect refusal, post-open failure,
unwind, one-shot close, retained spool and ordinary encrypted spool behavior are
covered. Canonical legacy constructor convergence and actual producer integration
remain separate obligations at this checkpoint.

The coherent native/Store consumer, exact final-writer capture capability,
mandatory Raft/Engine/Authority hook and typed producer spool setup compose in
33 files (manifest
`9fa7bc211ae5c868c388ab1df97be2e0753dfb11cc7a02760600576a39ad5a8d`, patch
`f0296b4ccb7e788d67b0e50773e070808ecdc7d5719005fc030e84c463f697f9`).
Its manifest preserves every contributing artifact and reviewed base update.
The composition helper's v4 adds exact recognition of a previously composed
artifact's verified after-image when another known overlay is already present;
all hashes and clean three-way merges remain mandatory. The earlier composition
attempt refused an unrecognized chained base before any source mutation.

The native owner retains actual reusable codec/directory/cache-proof work,
original physical generation and batch/file/root counter headroom. The Store
registered child retains original errors and callbacks outside report locks;
paired store mutation gates cover key identity through each actual commit. The
final source token borrows the original committed writer and exact installed
stores. Native source capture precedes writer release; semantic Engine binding
follows it. Review corrects temporarily loaned native owner progress reporting
and false success on batch-counter overflow. Canonical actor successful install
remains unbound pending the shared Raft executor. Focused source-pinned checks
run as `c04-isolated-native-consumer-source-capture-v1`; no result is claimed yet.


`c04-isolated-native-consumer-source-capture-v1` FAILS compilation in 250.63 s,
1,614/1,614 stable pins. The Authority backend owns the independent application
TenantStore, whereas root's new hook selected a CustodyStore capability method.
No selected runtime tests run. Root adds an explicit exact-application method
through the same committed-writer token; its actual Store callback test accepts
the original application and rejects custody substitution. No role fallback.

That three-file fix composes with two original native unknown-entry regressions
and the test-only physical owner correction (nine files, manifest
`3f10dd09e4d3fb4937030f1ce999c8f974f08ff4aca86559476847f1c75da655`, patch
`f8df2dc86cbfb27926fe47c2425a6c97e61a7b0f6a73e0b42392d6369f7979b3`).
The native Core already fenced original failed physical callbacks; its facade now
also retains the actual writer independently of the later publication-start flag.
Injected-backend fixtures explicitly install persistent accounting beside their
caller-held scratch directory with the same existing provider. They keep the
original injected database bytes, limits, deadlines and assertions. The helper
supplies no production fallback. Revalidation v2 includes the original fourteen
previously setup-failing Raft apply/custody cases, at their correct module paths.


`c04-isolated-native-consumer-source-capture-v2` **PASSES all 38 selected tests**
in 136.79 s, 1,614/1,614 stable pins: eight native, 19 Raft and 11 Store. The
real native multi-batch consumer/reopen, fitting cache, exact original writer,
unknown physical failure custody, paired final publication with intervening
votes, key-rotation cancellation and exact Authority application-token checks
pass. The original fourteen Raft apply/custody scenarios now reach and pass
their assertions with actual physical accounting installed; their former setup
failures remain above. Canonical successful snapshot install is still not active.

The preallocated native directory run applies separately (two files, manifest
`9b3f566c784fbd4910b58decf2968c998557a1bd6bc28b540645234d4870ecc3`, patch
`93e6f4c1f670c9cfed096dfae9b2cc4d477c267317ca427635777ea5cf70850e`).
It keeps at most 16 copied bounded keys and scalar value locations, borrows
ciphertext from the original source, and uses canonical same-leaf batching with
one-record fallback. Repeated/descending keys flush the run to preserve exact
order. Conservative physical geometry and native atomic limits are unchanged.
The focused directory/Store rerun is `c04-isolated-native-publication-directory-batch-v1`.


`c04-isolated-native-publication-directory-batch-v1` **PASSES all 16 selected
checks** in 108.96 s, 1,614/1,614 stable pins: ten native and six Store. The
actual 32-row sorted publication uses two leaf writes with no new workspace
reservation; repeated/descending keys preserve sequential last-write semantics.
The actual paired producer, votes and identity checks still pass on that source.
Complete native unit revalidation follows on the exact compiled test binary as
`c04-isolated-native-full-publication-consumer-v1`.


`c04-isolated-native-full-publication-consumer-v1` **PASSES all 575 native unit
tests** in 6.34 s, 1,614/1,614 stable pins; no ignored or filtered tests. This
includes the full prepared consumer and directory batching source. It remains
separate from final canonical actor and production application cutover evidence.

Canonical spool constructor convergence composes the existing fixture helper in
nine files (manifest
`8a0dd0dfd7ecb8bb868c294fd68dbd719797c7fc61bb78117d28052a8884f75f`, patch
`58a4a77a4e5f6e09821f41d0147f02546f4db846545eb82b373b7e86e5895eea`).
Both public ordinary constructor names now use the same typed setup primitive
and bounded census owner. Actual data returns to that registered owner before
fallible disposal; original constructor/close errors remain retained there.
The separately preclaimed native transaction corridor keeps its original
physical rights and has no ordinary fallback. Focused validation runs as
`c04-isolated-spool-constructor-convergence-v1`; no pass is claimed yet.


`c04-isolated-spool-constructor-convergence-v1` FAILS compilation in 28.03 s,
1,616/1,616 stable pins. The new facade's mutable Deref receiver conflicts with
an inline immutable len borrow in one production scratch-group call and four
existing tests. The three-file successor evaluates the same length first
(manifest `a8b8940c5903413f7c5ab662ec16a5635de8e40a3f013d16a3934e9153fb15af`,
patch `30021103e807d8ac3ed8878e10aa65456e0dbfde38e1c012dd591c95094b88e7`).
No assertions or limits change. The exact selected rerun is v2.


`c04-isolated-spool-constructor-convergence-v2` **PASSES all 37 selected Store
tests** in 171.51 s, 1,616/1,616 stable pins. Canonical ordinary/native setup,
original failures, data/census retirement and actual producer checks pass.
Subsequent source review finds the public SpoolData DerefMut capability would
permit exchanging whole native backing between facades with different retained
registrations. Removing that public whole-backing capability remains required;
these runtime passes do not qualify that API ownership escape.

Canonical snapshot native activation composes ten files (manifest
`5fdcb506e3252db5f834d671636180b975052eaccfa054eec620eac791fd33c7`, patch
`3657e531a9188ac7b01ebf2e520aed87fad3d84bedd7a121231e54b100f1fd55`).
The exact shared producer lives in the original seed before fallible preparation,
then shares charged ownership with its original body and conflict executor.
Actual immutable endpoint headers are fully validated before Ready and read
through their same prepared view afterward. Both body capacity paths require
the actual shared native owner Prepared and bound. Final capture holds the
committed writer; semantic backend publication follows writer release. Closed
and application staging explicitly check their exact tracked store roles.
The unconditional unbound refusal is removed only with this actual integration.
Positive actor tests use real file-backed NodeStore, not a synthetic unsupported
physical backend. Their budgets/assertions remain unchanged. Validation starts
as `c04-isolated-canonical-native-snapshot-install-v1`, including the existing
Engine actual install/encrypted-reopen case. No successful result is claimed yet.


`c04-isolated-canonical-native-snapshot-install-v1` finishes **8 PASS / 3 FAIL**
in 149.22 s, 1,617/1,617 stable pins. Six Store producer checks and two Raft
context/refusal checks pass. Both new positive actor fixtures fail with
`snapshot buffer inventory exhausted`; they allocate replacement bytes while
the original one-slot facade still holds its cell. The Engine actual
install/encrypted-reopen test fails with `required internal source preparation
refused before acceptance`; the responsible source report is under diagnosis.
No limits or assertions are relaxed and no successful activation is claimed.

The next composition applies eleven files and nine checked dependencies
(manifest `16cffda3e1d993a1e851ff98565181d574b1adafbb38102a18fc5c3ed48631f6`,
patch `2475396e6ac29d153c505d62faab8ee1691f71f280ad7798559fbc9436429585`).
It removes public whole-spool backing mutation, converts positive direct-child
fixtures to actual native preparation, retains original shared retirement
failures in the registered cell, and explicitly cancels/drops the original
buffer before acquiring another on the same one-slot owner. Original malformed
body paths and fixture budgets remain intact. The selected rerun is
`c04-isolated-canonical-native-snapshot-fixtures-v2`.

The M04/M05/M06 source audit is frozen in
`/tmp/kasumi-m04-integration-scope-v1`, manifest
`1badbd15dfa03a9d4c37ded083489fc0acde0776b459da14a4ca7d2bfa400954`, plan
`d96d97e2d777e4932fda80a4204e64579b41d3c770bd06e0c9f7beb264e227eb`, with
47 saved dependencies. The actual ordinary path is CompletionLoan publication,
not only state publication. Existing primary edits support just one live
replacement; decoded pooling is not cache membership; all index kinds and
serialized runtime maps remain resident. The goals now give concrete shared
cutover gates and retain every unsupported operation as an open requirement.


`c04-isolated-canonical-native-snapshot-fixtures-v2` FAILS compilation in
41.91 s, 1,617/1,617 stable pins. Six existing layout-test assertions still
access fields through the removed public Deref; production compilation reaches
Raft successfully. The one-file companion uses the same private backing accessor
already available to these descendant tests (manifest
`eff89b8cadaea6796580aa48fa3808c8d1f6bb3fd7a14ea37a74c587eba4dcef`, patch
`d420ce8001d4f9324a1bb535954bb8d8a7ac33f41f7a0b4abc01b5ce408ae5dd`).
All measured fields, assertions and limits are unchanged. Rerun v3 is in progress.


`c04-isolated-canonical-native-snapshot-fixtures-v3` compiles and finishes
**25 PASS / 5 FAIL** in 140.04 s, 1,617/1,617 stable pins. All 18 selected Store
spool checks pass; the public whole-backing capability is removed. Seven Raft
checks pass. Four actual actor cases now reach strict metadata validation and
reject prose snapshot IDs; the companion uses the same canonical UUID generator
as production (manifest
`e73dd819f6ed4f27b0c39f70e76ba278701e53477de75ec904846a10d2232498`, patch
`8992eb693d73ef1c6165fe71933f37639e7b9bb3b81439f5e299927f6fa8ccbf`).
The positive direct-child cancellation test does not observe its expected
canonical writer waiter; that setup is being traced without weakening the
assertion. One-slot exhaustion is resolved; successful installation remains open.

The exact Engine diagnostic companion applies one test file (manifest
`bfdb9410763a8ef14bbc1c56e6d27fd5593d4651e9ffe522a61f9c2235994db5`, patch
`285e41961b9ecddb6e688633d8a66f3f9de28fdbc9998637536479cad1cb1d11`).
`c04-isolated-canonical-native-snapshot-refusal-v2` FAILS compilation in 6.66 s,
1,617/1,617 stable pins: a borrowed report error is incorrectly required to have
static trait-object lifetime. No runtime diagnostic result is claimed.

The general primary editor prerequisite applies three files with six checked
dependencies (manifest
`a3cc945369c75ac94c5cfbfb1e7326f63256a55df28f2f00712d6b00eef14748`, patch
`cb2ae262bdde32390d07ccd4a98789e7259f664dae3e31fa710ad9bbe1826979`).
It adds exact insert/replace/delete and branch separator edits against validated
pages, bounded two-page splitting and empty-page results. Both output partitions
are validated before either changes. Caller-owned buffers and original input
keys remain borrowed, with no temporary entry vector. It remains under the
existing test-only primary module gate; trusted journal, general COW publication
and application activation remain separate requirements. Validation is pending.


The canonical-ID v1 application was refused before mutation because its manifest
named a saved dependency not included in the artifact directory. The complete
v2 artifact adds that exact verified dependency copy without changing manifest
or patch hashes; v2 applies successfully. No hash requirement was relaxed.

The borrowed-diagnostic and actual-wait setup companion applies two files
(manifest `856ec3df9a1b078abe002c3921c19634ee9f94e3567cab0ffe6adfeab533d674`,
patch `1dd5aab8f232cf4b1603531c659511a84ed8090942b6705384a322bdbb1ed887`).
The diagnostic prints the borrowed outer refusal and only downcasts its concrete
static source. The direct child now reaches Pending through the original fixed
capacity blocker, then pauses the retry that will produce the original Ready
result. Its canonical writer-wait, task identity, destruction and returned-token
assertions are unchanged.

The closed-publication authority component applies six files/four dependencies
(manifest `e0d70f3b04d6db4bfd7336668bd4bd97b25e07faacf010b7adf51132c4b33073`,
patch `c48aac9a2026b25c18850aec6dcbcc7a6bcd3598c66718de3018afdf9f50da87`).
The producer explicitly stages a custody-only final inventory and postlude;
conflict-prefix batches still require the original pair. Application sealing
remains before final publication. Custody identity and keys remain mandatory,
and the final source capability cannot authorize application access. Actual
file-backed tests cover final/cleanup after application sealing, custody
revocation before effects, and refusal of revoked paired prefixes or application
cleanup under closed authority. The combined actor, Engine diagnostic, child,
closed Store and primary-editor selection runs as
`c04-isolated-canonical-native-snapshot-closure-v4` on 1,619 pins.


`c04-isolated-canonical-native-snapshot-closure-v4` compiles and finishes with
**26 observed passes, one Engine failure and one interrupted Raft case** in
369.29 s, 1,619/1,619 stable pins. All eight new primary page edits and six
existing logical codec cases pass. All three closed Store publication cases
pass. Nine Raft cancellation/retirement/Ready cases pass, including the original
canonical-writer wait assertion. The Engine diagnostic identifies the actual
phase as target incoming snapshot installation, with the original refusal
`snapshot source certificate belongs to another storage pair`.

The remaining conflict/final/cleanup fixture stalls before install: after Ready
it calls the control-gated get_log_state while its prepared snapshot owns that
same gate. A one-second native process sample confirms LogStore::mutate →
ControlGate::acquire → Condvar wait. The exact stalled Raft test process is
terminated so the runner can finish the independent Store checks; this is not a
passing Raft target. The correction observes the same actual retained last-ID
under its scalar mutex while Ready holds control, preserving the assertion and
normal deferred-read policy. Both the sample and failing run remain evidence.


The actor observation and actual closed Authority fixture compose in one file
(manifest `367d1d71d1713a65bf89f1f4f1b2290c30bd1c842db5a1ed5f0ebe84c596b092`,
patch `e52a7354d162acaa89113e76811a994f98430cbfdd8dede3e80f497538f9964f`).
The saved native sample is `c04-isolated-canonical-native-snapshot-closure-v4-deadlock.sample.txt`
(SHA-256 `5375544e1b34888b42102f6f381390e23af637c89d2b705f395e164ae71aef54`).

The target receiver fixture repair applies two files/eight dependencies
(manifest `5a145ab78af7af70244138497898229cb21a5f4130739a379739d03c78a59427`,
patch `07aec299ad2474d2def3e9a1a3484f70549e64cd837f0eb078f9ecf2ba705c9d`).
Both direct cross-node snapshot fixtures now transfer the original bytes into
target.begin_receiving_snapshot, check exact transferred length, flush, and join
the source transfer before dropping it. This matches the actual network route;
no storage-pair check is relaxed and no source owner is rebound to the target.

`c04-isolated-canonical-native-snapshot-closure-v5` FAILS compilation in 35.24 s,
1,619/1,619 stable pins: the new closed fixture's envelope cleanup takes an
immutable reference although its real backend close requires mutation. The
one-file correction passes a mutable reference to that same owner (manifest
`a093d7d1d02edc87b5448082074f28bc92511902f1038e9659da4186c28ea213`, patch
`6859fe190ea2ff07aeb92dead85e7e0456d229629630325b8cfb3aab035b19c1`).

The reducer-origin document journal applies eleven files/eleven dependencies
(manifest `046f58d7d3be2c9c796ee17f8dfd4019e768b1fd14a38268f56e526513073dcf`,
patch `284a22a90f157233de9ef9e646e937b89d4694c7b710cde6bef19208bef41cc0`).
Successful ordinary, staged, archive and recovery reducers now record their
actual effects into the same original ordered-ID allocation moved through
AcceptedGeneration. Post-hoc batch, staged, archive and topology-ID reconstruction
is removed. Rejected private attempts discard their journal; replay stays empty.
This semantic provenance change neither bounds the remaining large journal nor
activates primary disk serving. The combined canonical snapshot and accepted
journal selection runs as `c04-isolated-canonical-native-snapshot-journal-v6`.


`c04-isolated-canonical-native-snapshot-journal-v6` FAILS compilation in 17.33 s,
1,619/1,619 stable pins: the second closed-fixture installed envelope still
passed an immutable reference to the corrected cleanup helper. The one-file
v3 repair makes that actual binding/reference mutable (manifest
`376cf9acf80eb51dd91ac6c8b7edd37efc3f965fc81d153576bd6380425bdf1a`, patch
`6c4b0fde591425a8a5709a59a3d1f6a89180297c361023b50a6a922fa7c6d07e`).
An incomplete v2 draft failed its source assertion and produced an empty
artifact; it was never applied and provides no validation evidence.

`c04-isolated-canonical-native-snapshot-journal-v7` PASSES all **24 selected
checks** in 177.64 s, 1,619/1,619 stable pins: Engine ten (including actual
snapshot installation/encrypted reopen and accepted reducer journal), Raft
eleven (including closed Authority publication and actual prepared children),
and Store three closed-publication checks. Source ownership, the control gate,
one-slot fixtures and original workload assertions remain unchanged. This is
an isolated integration result, not live promotion or complete disk serving.

The after-Ready denial companion applies two files/three dependencies (manifest
`b32bb24c250d1de14790a2f63597f7c54a6de9118c82e9cb74cd5d6d8d9d8a7e`, patch
`90832e2ec9d3e5b340d8f20499e06b0edb091b06d672459f8116b17696035245`).
The same fixed test memory provider denies all new mandatory installed grants
across threads after actual Ready, and counts attempted grants. Optional cache
growth retains its existing refusal contract. The actual actor must install and
clean up with zero denied attempts; Engine's separate provider remains an
additional gate.

The opaque accepted publication inventory applies four files/eight dependencies
(manifest `30c766a6763ff30572f04fa84ed822f80969d6f68dc5800b4fc28462190365d4`,
patch `c32a8db28f162b27691a1406ba375621af9015e398151f7c3c577939e9459ed4`).
It borrows the actual accepted predecessor, final candidate and reducer-origin
journal under the same command guard. Repeated ordered old/new traversal and
collection Preserve/Edit/Rebuild/Remove actions allocate no replacement ID
inventory. Definitions, archive transitions and foreign guards have focused
fixtures. This does not yet activate the primary publisher or bound the actual
remaining staged/archive maps. The combined denial/inventory selection runs as
`c04-isolated-after-ready-denial-inventory-v1` on 1,621 source/config pins.


`c04-isolated-after-ready-denial-inventory-v1` PASSES all **18 selected checks**
in 282.40 s, 1,621/1,621 stable pins: Engine four (three opaque inventory checks
and actual install/encrypted reopen), Raft eleven and Store three. The actual
conflict/final/cleanup and closed Authority actor cases complete with zero
attempted mandatory installed grants during the denied interval. This fixed
provider proof does not replace the separate Engine governor or native physical
promise gates.

The logical index-key codec applies four files/five dependencies (manifest
`45fbac914f55dc37706a1b3694938f49f1d7183735dd9e12ab335404d68a6ee0`, patch
`e923949e37e9bc2abbaf41365189df1f6fb79dda5cbc4dde358271dc561e2310`).
Fixed normalized decimal keys preserve the pinned parser's actual grammar.
The external tuple comparator consumes and authenticates both complete streams
before returning order, so an early differing prefix cannot hide corruption.
Its fixed workspace does not limit legal stored string lengths. I/O ownership,
physical index trees and service activation remain separate requirements.

The shared primary frontier applies five files/eight dependencies (manifest
`96cc2535233816a5bcb69c7f1ef5913b2288d6ed12780fd27c6d1ed4deb307cd`, patch
`bea0ff83900ade364376ab275a7ffd58e35e5a1b7732361e1edfaf38926da8ab`).
The fresh builder delegates to the same admitted fixed frontier and canonical
page writer; ordered edits can carry exact unchanged subtrees at their actual
levels after flushing lower pending output. The combined key codec, shared
frontier and existing bulk builder selection runs as
`c04-isolated-index-key-primary-frontier-v1` on 1,625 pins.


`c04-isolated-index-key-primary-frontier-v1` PASSES all **16 selected checks**
in 465.38 s, 1,625/1,625 stable pins: eleven Engine bulk/frontier cases and five
query key cases. The encrypted frontier fixture retains the exact old middle
subtree with exactly five new pages. Existing allocation, deallocation,
callback-panic and recursive spill assertions pass. Decimal grammar/order,
long strings, all UTF-8 chunk boundaries, full-stream authentication and original
tail read errors pass. No serving catalog or index publication is activated.

The constant-space atomic-image inventory applies four files/six dependencies
(manifest `dadba8280dc329e2313d6cb4d4c723e8cf8a2d53149081d01a142ba35445d6f4`,
patch `93f6b94b29b04afeb90f0ddf2b304f6b6cf3018b4b1273f2850bc7ab07f9e749`).
It packs private chunks while preserving ordinary operation/byte limits,
rejects an invalid individual operation before changing the current chunk, and
binds aggregate u64 counts/bytes plus ordered exact descriptors. The existing
aggregate inventory now also checks total logical bytes. Peer review found no
blocker in this inventory scope; native framing overhead and actual atomic
commit/replay remain required and are not included in these operation-byte
counts.

`c04-isolated-native-image-inventory-v1` PASSES **13 selected checks** in
178.40 s, 1,627/1,627 stable pins: ten native inventory checks and three existing
Engine accepted-inventory checks. The five new native cases stream 100,000 rows
and more than 96 MiB through bounded chunks, keep ordinary oversize refusal,
preserve inventory on invalid input, and reject incomplete/reordered/changed
chunks or forged totals. These are inventory tests, not a large snapshot
installation or native atomic-image activation claim.

The next atomic-image protocol contract is frozen at
`/tmp/kasumi-native-atomic-image-protocol-v1` (manifest
`54de37faa0a5f2ead21ee1f2c6b60c78a01adddf993604ec5c72346f309238a0`, plan
`9c790b4619bd2054343943a2077aa6f15ea937cb54a06ed1e65a9fd94e50d9af`).
One final synchronous writer acquisition builds from the actual current root;
no writer is held while Ready is parked. Begin/private chunk/end records share
one sequence and never select intermediate roots. One final commit and source
capture publish the complete candidate. Strict coherent format revision,
streamed replay, crash/abort rules and complete physical framing are required.
The conservative geometry issue remains open.

The streamed-record inventory companion applies five files/four dependencies
(manifest `3d5c8a9f293cb7ee7e29d341139e8238b26bb7c50990ccd73585915213a2f4f8`,
patch `a431db8316fea4f4c246b8e3258ff63b2f82e1f1186b850235b657d478e0117b`).
The canonical ordinary inventory now accepts a validated header and bounded
value windows. Only an exact completed record advances its original parent;
partial values, decoder failures and extra bytes cannot mutate the batch.
The image packer consequently hashes each value once. Golden digest and failed
record/length cases accompany the existing inventory regressions. This is the
native replay digest prerequisite; no on-disk image record is emitted yet.

The actual decoded primary cache applies eight files/thirteen dependencies
(manifest `f902a87ba8ccecc2a96b2ec3a6c3fb5124b6ec4e28f7a06aec98989849664be7`,
patch `621f5b5d2e35207d8508d684d8d1c3bfb47a72f3f905e584f8a3c12211e76e66`).
SelectedPrimary uses exact source-cell identities for metadata, pages and
live/archive payloads, shared aggregate credits, pressure-only demand eviction,
scans that do not evict, and a finite warm cursor. Same descriptors in a newly
captured source do not inherit authorization to hide a corrupt/missing current
graph. Trusted cross-source sharing, scheduling, refill wake, collection floors,
query cleanup census and service activation remain open.

The logical index page codec applies three files/four dependencies (manifest
`5ff0a11b0c680449a75bb11e2811fa206b23ffb4ca574aa822f3050165d8dfc7`, patch
`2ca1b6592c3913d898487f6ba53c70a437b58d9d4f77e520a76971cb8d8f5e4c`).
It validates fixed 16 KiB Values/Unique/Postings/Presence framing and exact
scope/tree/object/level/digest identity, with external arbitrary-length logical
key references. Framing alone grants no ordered cursor or publication authority;
authenticated keys, separator/range proofs and mandatory real catalog binding
remain required.

The combined cache/source lifetime, index framing and streamed inventory
selection runs as `c04-isolated-primary-cache-index-record-stream-v1` on 1,633
source/config pins. Final validation and live promotion remain pending.


`c04-isolated-primary-cache-index-record-stream-v1` finishes with **82 passes
and one failure** in 512.56 s, 1,633/1,633 stable pins: Engine65/66, native15/15,
query1/1, Raft1/1. All four decoded cache fixtures, index framing checks,
streamed-record golden/partial-value cases and selected allocation/source
lifetime regressions pass. The actual Engine snapshot scenario installs the
new source but fails its immediate bootstrap-source `closed` assertion after
dropping the held bootstrap Generation. The exact old owner is being traced;
the earlier passing install evidence does not close this newly reproduced gate.

The exact same compiled/source-pinned Engine case fails again in
`c04-isolated-snapshot-bootstrap-retirement-repro-v1` (7.56 s,
1,633/1,633 stable pins). No assertions, capacity limits or deadlines changed.
The optional cache is not assumed to be the cause without original owner and
native failure evidence.

`c04-isolated-native-full-image-record-v1` PASSES **all 583 native unit tests**
in 4.78 s, 1,633/1,633 stable pins, after the image inventory and streamed
record grammar changes. This is the full native suite on this isolated source;
large atomic-image commit/replay and live promotion remain open.

The ordered primary editor applies six files/fourteen dependencies (manifest
`5cec5f85062fe83a320cd4ca9d1cc4424f9b4356b0478182c21754065c7fc99a`, patch
`3301f8ad51c5e97bdcefee539f47eacc244b2b7a08a4995919477525e24efdb5`).
One unselected attempt binds actual accepted old/new journal pairs across
collections, retains fixed old-page work and the shared frontier, carries exact
unchanged subtrees and retires each touched original page/DTO once. It stages
insert/delete/archive transitions and verifies resulting manifests/counters on
one frozen view. It has no final selector publisher. Complete graph/retirement
verification and atomic primary/index catalog publication remain required.

The exact-source index reader applies four files/nine dependencies (manifest
`c926e4b323d097fac8f1c33ddd450254a77d45b6ad537a623ef519e095725d40`, patch
`2db19606a2d3bb509b8aa86449dd3d109b5ef08a4f14458651ce7b800064e914`).
It borrows the actual SelectedPrimary reader/reservation, quotes fixed page/key
workspaces, authenticates complete external separators, checks strict order and
child ranges, and preserves original failures/access/cancellation. The opener
remains fixture-only until the actual complete catalog producer and mandatory
Manifest binding exist. The ordered editor/index-source selection runs as
`c04-isolated-ordered-primary-index-source-v1` on 1,637 pins.


`c04-isolated-ordered-primary-index-source-v1` finishes with **31 passes and
one failure** in 169.50 s, 1,637/1,637 stable pins. All five encrypted ordered
index reader cases pass, as do three of four new ordered-edit cases and the
selected one-ID COW/inventory regressions. The actual archive edit reaches
incremental cancellation but fails `primary incremental abort inventory differs`.
The original error and cleanup assertion are retained; no final primary/index
publisher is activated.

The cache-rehash, complete catalog framing and original bootstrap diagnostic
compose in six files/thirteen dependencies (manifest
`d84809dbe8c440cab9cd2e93ed6fd72e7c2e1d1115966abd5f29983d7098e9bd`, patch
`d79127916d85013f58442dc7bd4b265f78e604fb2b5fc065f2a6cbf08312e9b0`).
The known exact index-reader test suffix is preserved alongside the cache
regression's append-only suffix; neither body is selected over the other.

Inputs are the original-owner diagnostic (manifest
`fca82b4e557b692622cc32aa902e73c055521295cc47b823f7c8e85e413b224d`, patch
`5adcaeca9dd6d8df9b20290f53a2befbee00506c31f09d6897618c3ae2454b65`),
cache retirement rehash correction (manifest
`b37f52c80cb736e4ebb8f697989e6775b0feb0f441e873ad7c87b10810fee4fe`, patch
`0c77654b651390aeff2dc31fe3d700524ed8d76e1f2e8c769aa62d6d2c1032db`),
and catalog codec (manifest
`230511fcbdf485bfd7d8bb7db081bf883f1951939c6134fdc0045d06fed478b7`, patch
`212b273a9772fab2623f08a29f20bdb849a5a98d70cf1310b8e49b0530aa18c5`).
The diagnostic retains the same immediate retirement assertion and reports
actual selected/native owner fields plus original error chains. The cache fix
uses an overflow-checked layout generation to restart removal after rehash,
with a deterministic two-thread regression and credit destruction outside
locks. The catalog binds exact definitions/epoch and all structured, presence,
unique and text roles; a real producer and mandatory Manifest reference remain
required before serving. The selection runs as
`c04-isolated-cache-rehash-catalog-retirement-diagnostic-v1` on 1,639 pins.


`c04-isolated-cache-rehash-catalog-retirement-diagnostic-v1` PASSES 11 checks
in 159.22 s on 1,639 stable pins: five cache checks including concurrent rehash
retirement, five catalog codec checks, and one actual snapshot check. The latter
pass is not a repair claim. The standalone original-owner diagnostic then FAILS
in `c04-isolated-bootstrap-retirement-original-diagnostic-v2`, 8.88 s on the
same 1,639 pins. It reports one last Generation owner before drop, zero handles
and inflight loans, no view/protected owner, native_retained=true and
cache_installed=false. The original close error is a registered native read
failing at finish. Source finish currently treats opening-lock contention as a
real retained failure; a precise contention retry and deterministic regression
are under repair. The immediate-close assertion remains unchanged.

The next composition applies 22 files/12 dependencies (manifest
`b48d17b626690801ec7b5139fe0cf93393fe35c4212eb2c0bb0e77549c757c24`, patch
`18985c157764ffa0579b1876af0a864971c5f30470d639d3839bf4fbb21fc837`).
It includes required per-loan Point/Scan intent through every DocumentSource
implementation/caller, exact same-source catalog reads with real staged unique
definitions, the narrow Archived inventory admission for incremental abort, and
parent-derived generation ceilings in ordered editing. Original reader resources
restore access mode on success, failure and caught unwind. Catalog opening remains
fixture-only pending the actual mandatory Manifest/catalog producer.
`c04-isolated-read-intent-catalog-ordered-repairs-v1` runs on 1,641 pins.


The first read-intent composition fails compilation in 63.22 s on 1,641 stable
pins: two generic `with_record::<()>` fixture calls omitted the mandatory intent.
The mechanical correction retains Point semantics (manifest
`cda2b8147814abf7744617aa2c32972b2ea22849c8a96db0c998df819efc53f4`, patch
`6d68c73fafefa695c47db914935f6b3a761d42c7ab7e1d48d38c3334fcb5cdda`).
The bounded ordered graph verifier/general primary inventory applies five
files/14 dependencies (manifest
`174563d3140cb6e252a03d36771d9f92f45f18cc8b6c7c228faa65162e742821`, patch
`9d0de9b04b55d318936fb92c2fa6b93cb3636c25dff16dfef1dcdf64b6d047ec`).
Peer review found no additional blocker in its documented proof scope.
`c04-isolated-read-intent-catalog-ordered-verify-v2` PASSES 20 checks in
185.65 s, 1,643/1,643 stable pins (Engine19, Query1). Archive cancellation,
original callback ownership and actual DTO/retirement corruption refusal pass.
The inventory cannot publish a source until complete index catalogs join.

The exact source-finish contention repair applies three files/six dependencies
(manifest `15c13e068c6f300c7a92de5f365898c2a1f8417376c0682a3d5ce452ea080d5b`,
patch `c99a5f98eb5cb0bac3686801e291124814fcf2dd718dcc6fd38421a533e853cc`).
Only an actual opening try_lock miss sets its stack-local retry witness.
Captured/historical source finishes release the reader lock before yielding;
unknown native close outcomes are not retried by phase. Deterministic fixtures
hold the actual opening mutex until the worker witnesses contention, require
noncompletion under that lock, then prove native/census/memory retirement.
The parent-generation proof also applies two files/two dependencies (manifest
`148374bc447c430b72a67c79abb557c4a52065d97f617d354b9d68d93a455717`, patch
`7e9cd89adcbb2b0b1373280ec06bcc3db978612facb86f81f7e478694e8778ce`).
It rejects a child11 beneath parent10 even when Manifest20 would admit the
former inherited-ceiling bug.

`c04-isolated-source-finish-contention-parent-proof-v1` PASSES 15 checks in
94.02 s on 1,643 stable pins. The previously failing exact standalone snapshot
case also PASSES unchanged in `c04-isolated-bootstrap-retirement-fixed-standalone-v1`
(8.54 s, 1,643 stable pins). These repair the identified contention defect;
final integrated qualification and live promotion remain open.

Native image segment/replay implementation applies eight files/nine dependencies
(manifest `bb75dd5e64e7a46b63c5c09c0d2f8bd7e550f535bfc3b8e1d1559bbf9cc904ac`,
patch `a59f03caf67f0d46ebadf45bb88362bdc45a9eba53d8e6afe17e472dc9ae5e9a`).
The isolated canonical format is version5 with explicit version4 rejection.
ImageBegin and exact chunk trailers share one sequence and raw transcript;
root-only replay streams logical value digests into fixed inventory state.
Only ImageCommit validates the complete inventory and final directory.
Ordinary writers cannot enter an outstanding image. The original bounded
location workspace is reused per chunk; exact image commit reconstruction
extends torn-tail checking. Native DiskState/Store consumer wiring and full
image physical quotes are not yet activated.
`c04-isolated-native-image-segment-v1` runs on 1,646 pins, with actual 100,000-row
and >96 MiB segment fixtures, injected write/sync failures, torn commits, and
resealed corruption cases. No service-level large-image claim follows from them.


### 2026-10-03: native image and query ownership integration

`c04-isolated-native-image-segment-v1` finished with eight passing checks and
 two fixture failures in 218.85 s on 1,646 stable pins. The empty-root fixture
used an uninitialized genesis superblock; the torn-commit fixture reused a
backend whose crash operation mutates its original durable bytes. Both fixtures
were corrected without changing rejection or atomicity assertions. Independent
review also found image-start panic fencing missing; the actual entry now
retains the original panic and fences uncertain work. The repair's manifest is
`2bab545f7ea2c073e94b79e5fc2c9158f08fa79717ac7a32530dc4bbe6df85cc`.

`c04-isolated-image-panic-query-cleanup-index-input-v2` PASSES 28 checks in
79.22 s on 1,650 stable pins. These include actual segment images with 100,000
rows and more than 96 MiB, write/sync failures, torn commits, resealed corruption,
original panic ownership, bounded borrowed index values and actual query cleanup.
The segment fixtures do not exercise a production Core/Store image consumer.

`c04-isolated-native-full-image-v2` finished with 589 passing checks and one
failure in 5.03 s on 1,650 stable pins. The unknown-record-kind fixture used tag9,
which is now the canonical ImageChunkEnd kind. Manifest
`78b3fd101ada7783b913c2f8588eafdab3e825e31a0b2e6d6a8e1cf5046947ea`
changes only that deliberately unknown tag to 0xff. Its exact rejection check
subsequently passes; the full native suite must be rerun on final source.

`c04-isolated-source-work-rebuild-v3` finished with exit101 after 841.16 s on
1,651 unchanged pins. The accepted Rebuild implementation's Create, Replace,
ActivateSchema and independent tamper checks pass, together with the selected
SnapshotWork/QuerySourceWork tests. One invalid fixture expected an archived
schema replacement to succeed; the actual reducer correctly returns Conflict
because those definitions are sealed. The narrow replacement test preserves
that rejection and unchanged source/epoch. The actual snapshot test did not
finish: a five-second sample of its original process showed the same lock cycle
throughout. Installer publication held native Core and waited in
RegisteredNodeOpening::physical_identity for OpeningState; concurrent audit
read held OpeningState and waited in begin_read_retained for Core. Only that
deadlocked test process was terminated; the runner then completed the other
crate selections, including both checksum-valid unknown-field rejection tests.
This run is a failure, not a timeout pass or repaired retirement result.

The lock-order repair retains the exact NodeSegmentGroup in its existing
DatabaseOwner, whose inline size is already charged, and publishes availability
only on actual native Ready. Physical identity still verifies the same live
directory and root descriptors; it no longer takes OpeningState. Existing seal
and failure checks remain. Manifest
`52e0b7f1333f8a8ac45644f2e643793fdac836dab603ada3e80976bedc211a58`,
patch `e6a0f7138ad2d4b608a47f8f2b6a121b9cdc6e9dd7def8cc4a3ffbd05338a8c4`,
two files/five dependencies; deterministic held-lock and availability tests await
validation. Independent transition/descriptor review found no blocker.

The isolated image/catalog/lifecycle composition applies 13 files/24 dependencies
(manifest `92b55ad766c06ef9391d2bcd528664917d804512e8bb4f6b93715290905cc034`,
patch `ae698faa903a84471f068803e924e635874d7710743c75f3bcbee3d38c776578`).
It includes the narrow archived-seal fixture, exact preserved/new collection
catalog proofs, metadata-only accepted generations with zero staged graph
objects, deferred exact-source query opening, and complete image boundary and
physical framing inventory. Component validation is pending. No final primary
publisher is enabled without all structured, unique and text index roles.
All C01–C07 remain open and no isolated code has been promoted to the live tree.


`c04-isolated-catalog-index-identity-image-plan-v4` failed compilation in 57.33 s
on 1,654 unchanged pins: referenced-catalog sibling access needed the existing
member reader's visibility widened to pub(super), and the staged index cleanup
namespace is an owned String requiring as_str for literal matches. The narrow
two-file repair preserves semantics (manifest
`8f6b045ab17550a9458d05bb84d3b933ea28b78606a0d961a034a01b7b654979`).

`c04-isolated-catalog-index-identity-image-plan-v5` PASSES 33 and FAILS one fixture
in 154.14 s on 1,654 stable pins. Engine22, native8 and Store3 pass, including
actual snapshot installation, create/replace/schema rebuilds, archived sealing,
referenced catalog verification, metadata-only publication inventory, deferred
query opening, full image inventory and the two physical-identity regressions.
The failed inventory fixture used 1,025 bytes for an IndexCatalog, whose actual
canonical width is HEADER_BYTES + N*INDEX_BYTES. Its narrow correction uses a
real one-index width and adds explicit rejection of 1,025 bytes; manifest
`acb59b0c86d59e05a33e9bcdb659d7f4867ceb913d42e0c71d049ff38e7477c5`.

Staged index resources were rebased onto the actual referenced-catalog cleanup
without discarding either path: manifest
`90f06acb5df18ecb917c21c8f13fa75b1dba13d777fbf112300740cffa1a4f94`.
The strengthened private-release artifact (seven files/ten dependencies,
manifest `866c61a0e8f2b4a4ebd8328b38a316e84be49a9e026bdea077f23ce77fbb78a8`)
retains Releasing/Released inventory, durable progress and exact live counts,
never reuses object IDs, and validates the actual committed predecessor before
incremental release. Its production entrance still requires point-COW tokens
and independent complete index-span proof.

The per-Database source-work census now applies six files/six dependencies,
manifest `c27c5c515810486dd90d3fc71817a3a942d130e89f63e2c049d2901369feed68`.
It is allocated from actual configured inflight capacity during construction;
preparation tickets precede callbacks, and shutdown seals/drains only its exact
SnapshotWork reports. Query/refill service activation remains separate.

Native Core image publication now applies nine files/eight dependencies,
manifest `107c45b421e7b435e08a806a2faa6eee5e074b66eb1e959c9e56d94c02bb3e60`,
patch `d809d0ad4f0bfe4c2d771efcefe7b047360e5e8374313c9b2a52c7c68c395ea0`.
The actual native consumer plans the full stream from its current root under
one writer, applies bounded chunks to private directory roots, synchronizes
those pages, publishes one final ImageCommit and retains the writer for exact
source capture. Cache reconciliation/refill happens once after the image.
Global strict key order permits refill from the exact final root with fixed
key/inventory backing. Ordinary batch limits remain unchanged. Real Core tests
cover 100,000 rows, 100 MiB, votes, old snapshots, reopen, denied mandatory grants
and original non-Error source failures before/after entry. The selection
`c04-isolated-native-image-census-index-release-v1` is running on 1,660 pins;
no test success or production Store integration is claimed yet.


`c04-isolated-native-image-census-index-release-v1` finished with 29 passing
checks and one fixture failure in 163.43 s on 1,660 stable pins. All13 Engine
checks pass, including the local census and private index release. Native13 pass,
including actual 100,000-row and 100 MiB image publication/reopen, with one
failure at fixture database.close: the positively canceled publication still
owned its DatabaseInner. Store3 identity checks pass. The narrow fixture repair
drops that completed owner before close; it does not ignore Busy. The same
follow-up adds the full-fit first-read test and early nested-image inventory
rejection (manifest `a45db51a03f4c37074714a52cf108ca1bf5482c4f4d77332675219d02abcfba1`).

`c04-isolated-native-image-consumer-full-v2` PASSES **all596 native tests** in
25.04 s (runner61.12 s) on 1,660 unchanged pins. All four new actual consumer
checks pass, including every fitting row/directory hot on first read without
loads, uncached loads or eviction. This closes the current native component
regression gate, not the encrypted service or release gates.

The source census/refill composition applies seven files/seven dependencies,
manifest `0d384ddd4332dd28e5651eb299b897db1db6b076dd4d60465214fcd6b8b5b5dc`.
It corrects the reviewed concurrent-drain wake issue by broadcasting after
unlock, with both waiters deterministically enrolled before preparation ends.
Actual inert query plans and finite source-owned refill use the same census.
`c04-isolated-scoped-query-finite-refill-v1` PASSES30 and FAILS one pressure
fixture in 243.52 s on 1,661 stable pins. Full-fit, unstarted cancellation,
original source failure, deferred reads, cleanup and census checks pass.
Under optional-capacity saturation the refill progress is None rather than
Pressure, meaning claim returned an original failure. This remains unresolved;
no cache bound or expected terminal result has been relaxed.

The canonical Store final-image bridge applies seven files/twelve dependencies,
manifest `5215c3c1d926c84c416184fe66e9fc93328472a0c5fd5fad51abb01c19c67407`.
KSPUB002 distinguishes ordinary frames from the single final image and its
private chunks. The original encrypted spool and one admitted ciphertext buffer
supply every nested replay. One native writer/capture receipt advances the
visible final ordinal. Real encrypted operation/byte-bound tests are added.
The operation-count fixture's scratch quota must be derived from actual native
append costs before qualification; an unproven proposed 2 GiB adjustment is
explicitly rejected and has not been applied.

Additional isolated artifacts now under qualification: native real-directory
crash/reopen injections (`43ef581b812ad13ec6fc54d3f576e71f7240036b0ab7c3e33243922b12423695`);
bounded unsorted index point-COW (`e1eaef006c5c4357543715fbd097ef11846171db59b541943070ccd47d5caabc`);
exact owning-Database primary source preparation (`c64b933d56b447dc9ee1dfea47675119bc7e62cfa402c5e8ecbadc553dfbdbc4`);
and actual cache-headroom release events (`88d061900079e306fecd710563bb71c58ace7a48c122b009680ef51f803b22b5`).
The combined selection `c04-isolated-store-image-point-cow-refill-diagnostic-v1`
is running on 1,665 pins. Despite its label, the proposed borrowed refill
failure diagnostic was not applied: its saved test dependency differed after
owned-source preparation, and the exact pin check correctly refused it before
mutation. A reviewed composition is required for that diagnostic. No diagnostic
result is claimed by this running selection.


`c04-isolated-store-image-point-cow-refill-diagnostic-v1` finished with a
compile failure in 270.46 s on 1,665 stable pins. The new service factory needed
`crate::Generation`; the two owned-source fixtures used `?` for a DrainFailure
without a TestError conversion. Narrow name/positive-drain fixture corrections
preserve all assertions (manifests
`973abc698d7d80c7b8697149bfb3a15f490d6b64a6c670c6b065b77177cb5c24` and
`c21d28eaff2d8e4a2246f10ca4e42c129a371eaa9c0fa75ae6abe720a3e83c89`).
The second artifact composes the exact borrowed refill diagnostic through the
recorded predecessor hashes; no source failure is replaced or discarded.

The Store operation-count fixture now uses a derived scratch quota (manifest
`e57841f66f86b3c68760b44ce578cbe7dac33082ac5d171c1bd89e42b6422e95`).
Its fresh insert-only tree's actual entry widths and half-page split occupancy
bound height to three for 65,541 edits. The quota includes seven copied pages
per edit, arena headers, exact encrypted record widths and both root slots.
It changes no production limit, ordinary batch bound or native physical promise.
The earlier unproven 2 GiB proposal remains rejected.

`c04-isolated-store-image-point-cow-refill-diagnostic-v2` is still running on
1,665 pins. Engine10 pass, including bounded point-COW, actual owned sources,
all cache-relief tests and actual encrypted snapshot install/reopen; the refill
pressure case fails with the original typed `ResourceExhausted: document source
retention budget exhausted`. Native2 pass: all actual log/directory/root failure
sites reopen old or complete, and unordered/duplicate image keys refuse before
any physical slice. Store's small publication checks pass while the two large
encrypted image cases continue. This is an interim report, not a completed run.


During that same v2 run the large byte-count Store case FAILED at native image
commit/source capture. The original exclusive-open mismatch records unchanged
inode, binding, standing charge (1,187,840 B), EOF/reserved length (139,264 B) and
settled state. Represented allocation changes from 172,032 B to 139,264 B;
pending changes from 1,015,808 B to 1,048,576 B. No acquisition predicate is
relaxed and no late census/retry is substituted. The operation-count case is
still running. A three-second local sample shows real operation staging/native
compaction and encrypted image replay work, not a mutex cycle; the raw sample
is kept only in /tmp. The unchanged byte case is rerun in
`c04-isolated-store-image-close-trace-v1` using the existing opt-in
`KASUMI_TEST_FILE_CLOSE_TRACE=1` on the exact same binary and 1,665 source pins.

The next reviewed but UNAPPLIED cohort is frozen as
`e2e1fc346d9ba15870ee67d2b99b991bac8172287facdcc64f604f10e0d08e11`
(patch `14af35d24b0b883f14e421a5aec5db5d8592c85392808ce57ea02924ee55400b`,
29 files/23 dependencies). It composes the canonical 192-byte owning-edge
inventory, actual accepted structured Rebuild producer, narrow pre-acquisition
Pressure result preserving the original refusal, independently admitted point
scratch for protected-source borrowing, and shared existing text schema/analyzer
kernel. The text kernel removes duplicated schema construction; it does not
activate disk text or claim bounded Tantivy search. Both active runners must
finish before this source cohort changes.


`c04-isolated-store-image-close-trace-v1` PASSES the unchanged encrypted
byte-bound test in286.98 s (runner286.99 s), all1,665 pins unchanged. It emits no
native-close extent delta. This does not repair or explain the prior physical
enrollment failure; the exact original mismatch remains an operational gate.

`c04-isolated-store-image-point-cow-refill-diagnostic-v2` is now reaped with
exit101 in1,514.46 s, all1,665 pins unchanged. Engine10 pass/one pressure failure,
native2 pass and Store10 pass/one byte-image failure were observed. The remaining
65,539-operation case was interrupted while still staging, after two local
samples demonstrated per-tombstone scratch transactions/compaction work. Root
sent SIGTERM only to its verified Store test PID. Its workload is **unqualified**;
interruption is not a pass or a timeout repair. The unchanged workload will run
again after bounded staging, with no cache/quota/row-count/assertion relaxation.

The composed integration artifact is now APPLIED ONLY TO THE ISOLATED COHORT:
manifest `eeeacda31d0fe807b582452f81b0f07b26adbe04fbc8232a31f5a67744be4235`,
patch `401cba35cd1cdf9cec6e0b1ec218dbe8c195490eefbeb7d64ca5f7c469229fd2`,
33files/28dependencies. Besides the previously recorded29-file composition,
it adds bounded16-tombstone staging with the exact fixed-key workspace in the
initial quote, a real mixed Put/Delete/dedup boundary test and borrowed original
publication diagnostics in the large fixtures. The source remains BuildingBatch
on any staging failure; every Put/replacement/end flush preserves producer order.
`c04-isolated-index-owner-rebuild-refill-point-text-v1` is running on1,668 pins.

Independent review then found a key-state read guard held across a potentially
full tombstone flush. That flush rechecks domain keys, so a waiting key writer
could prevent its reentrant read. The narrow frozen correction computes the
fixed physical key in a lexical block before pushing/flushing (manifest
`c9502e56ba029e765f6a6d66482c8cbcb72599c50c5872ff0663304f23152e69`). It is
not yet applied while the current source-pinned selection runs; no promotion or
large workload rerun occurs before this correction.


`c04-isolated-index-owner-rebuild-refill-point-text-v1` compiled, then Engine
ABORTED with stack overflow in the actual empty structured-Rebuild case.
Runner154.40 s, exit101, all1,668 pins unchanged. Two exact owner-codec and two
real prospective protected-source checks passed before the abort. Query3 shared
text lending regressions and Store1 mixed tombstone flush-order test pass.
Unreported concurrent Engine tests have no completion claim. The large inline
Builder/span arrays are being moved to prospectively admitted heap backing;
no thread-stack override will substitute for fixing production stack use.

The tombstone lexical key-guard correction above is now APPLIED after reaping
that run. All new code remains isolated. The exact index-span proof is frozen
but not applied (manifest
`091307fe550ad21dc3b6c50c90087fd9c2c377e4927ff9ea7e95fce98f3a1d9a`).
Root review found a fallible replacement reader acquisition after taking the
verified source out of StageFailure custody. The agent will acquire replacement
first, then use infallible replace; the original pin must stay owned on failure.
The proof will also consume the same heap-backed root span to avoid inline copies.


The next isolated composition is applied: manifest
`b4c693f81c2d40f75fcfec21130ab7b4cec67bb69ce0e9dbd5f8eaaf2405c870`,
patch `37c1697a5172ae5191fe0ca594d91a7e95fd07b4fe838692e3eef75c7140330e`,
11 files / 19 dependencies. It combines the admitted heap-backed Rebuild repair,
sealed same-attempt root edit refusal, exact fresh index-span closure, its
replacement-source custody repair and heap-shape guard, and separately admitted
protected primary borrowing. These are component capabilities; no production
primary/index serving gate is removed. The original stack abort remains above.

`c04-isolated-index-span-heap-protected-borrow-v1` is running on 1,671 pins,
including the lexical tombstone key-lock correction. No stack override or
fixture bounds change is used. Results remain pending until the runner exits.

The mandatory primary/index Manifest join has a concrete dependency contract:
closed primary draft, exact index start/end, complete all-role catalog, reserved
successor Manifest ordinal, then an independent final-source graph and inventory
proof. Fresh baseline/restore retains its own accepted provenance; an ordinary
Preserve cannot be reclassified as Rebuild. Sparse sharing authenticates the
original selected role/path without rewriting old creating-edge inventory.
Implementation and final qualification remain open. The goals now list these
exit gates explicitly, along with protected query preparation and finite refill.


Two complete unit suites pass on the same 1,671-pin source used by the compiling
integration selection. The native binary produced/confirmed by that Cargo
selection passes **598/598** in 67.09 s (runner 67.14 s), log
`c02-isolated-native-regression-index-span-cohort-v1`. The query binary passes
**83/83** in 6.05 s (runner 6.09 s), log
`c05-isolated-query-regression-shared-kernel-v1`. Both runners exit zero and
retain all 1,671 hashes. They do not establish full application serving or
final release qualification.

The larger branch/Released index-span test remains running in the original
integration selection. The other four span tests and both actual Rebuild cases
have passed, including zero/64 declarations on the normal stack. All four finite
refill checks pass; the original pre-acquisition capacity refusal remains lent
from its exact owner, and released ballast permits full refill. Three protected
primary borrow checks pass. The ordinary/sealed fixture fails before its second
phase because it attempts cohort construction after its first ordinary root;
the correction uses two distinct actual installations and preserves both refusal
assertions. It remains unapplied until the running selection is reaped.

Reviewed next composition (UNAPPLIED): manifest
`58fc58b7810b1bc10bead0d23f38a7faf06fa3b522ca0337e8ab02d7e1970ed9`,
patch `98f9944f9c69631b46c402a65064e856faf2b1b43b2039188487a541861a5702`,
12 files / 13 dependencies. It includes that fixture correction, original-owner
prospective preparation with six failure/cancellation/reentrancy cases, canonical
native-file kind/ordinal diagnostics and the encrypted text Directory v2.
The Directory's first failure now becomes visible under its state mutex before
another writer can enter partial state; handle acquisition and close share that
gate. All six original/saved upstream dependency hashes were checked. The bare
atomic-read Vec, writer peak and permanent analyzer dictionary still require the
actual enclosing producer's complete lifetime/accounting proof before activation.


`c04-isolated-index-span-heap-protected-borrow-v1` is reaped: Engine22 pass /
one fixture-setup failure in871.57 s; Query3 and Store1 pass. Runner942.27 s,
exit101, **1,671/1,671** stable. The large branch/Released proof passes unchanged;
all five span checks and all three structured Rebuild checks pass. Its two local
samples showed first actual semantic lookup and then abort cleanup; no deadlock
or reduced assertion was used. Samples stay in /tmp, outside public evidence.

The next19-file/19-dependency composition is APPLIED ONLY IN ISOLATION:
manifest `cff56cefa7353cdc3fca45048015d28342602afc78778d3693cd8fd65ca5ee8e`,
patch `200c3eec299435ef712b2d75886ce27e09f5964b471fb32353e545e243647872`.
It adds the already reviewed prospective/text/fixture composition and accepted
primary draft. The latter has distinct actual Baseline and Rebuild input and
records primary_end before any Manifest. It does not activate serving or create
a complete publication proof. Text ResourceKind/import work is not yet included.
`c04-isolated-primary-draft-text-directory-prospective-v1` now runs on1,677 pins,
selecting the full snapshot-work module, four protected borrow checks, three
accepted primary draft cases and three encrypted text Directory cases.


`c04-isolated-primary-draft-text-directory-prospective-v1` fails compilation,
runner88.86 s/exit101, all1,677 pins stable. No selected test ran. Two exact errors:
AcceptedPrimaryDraft calls the private SourceRootsRef::ptr_eq, and the Tantivy
0.26.1 TopDocs builder in the new Directory fixture needs order_by_score before
it implements Collector. Narrow corrections retain the identity check and
ranked-result assertion. This run does not qualify the prospective owner hook,
new draft constructor or text Directory.

The 24-file/17-dependency primary/index/text/query join is APPLIED ONLY IN
ISOLATION: manifest
`8ae50e95203320590efa82f2877f7d3c326e7278eef0b763cd3959c6e6f88916`, patch
`b42c3afa02cd9a115bf59c7c90ae8055ac7924b80ec09e482acc48cc90c5c787`.
It includes the two narrow compile corrections, the typed accepted-primary to
structured-index join, protected prospective reads, an actual work-census panic
retention case, encrypted text resource kinds and private text-file import.
The import produces an unverified segment, not publication authority. Writer
peak, permanent analyzer ownership, text metadata and complete semantic graph
proof remain required before activation.

`c04-isolated-primary-index-text-prospective-join-v1` fails compilation before
tests: runner54.43 s, exit101, **1,681/1,681** source pins unchanged. The sixteen
errors are in the new text-import fixture: unresolved sibling helper functions
and an absent `Fixture::select` method. Correct the fixture against its actual
storage/selected-source APIs while preserving old-pin and abort assertions.
No test or production-completion claim follows from this selection.

The next 16-file/14-dependency source, point-workspace and text metadata cohort
is APPLIED ONLY IN ISOLATION: manifest
`9557899ab016da537bb3f5fe70e399785a89c7012796f4297b57451d9aaa801e`, patch
`ed412ecbb6bb0a478a5b39ec274697ca93fc10fc5cdc6295123208e47ca89d5b`.
The ordinary-reader rebase preserves the already-applied collection module and
text-file namespaces; it does not change the reader repair. The final collection
check closes its old reader in place, retaining actual backing after failure.
Text metadata distinguishes exact u64 row/segment identities and live/deleted
physical segments, with explicit refusal by the still-structured graph proof.

`c04-isolated-final-source-point-text-join-v2` fails compilation before tests:
runner27.41 s/exit101, **1,683/1,683** stable. The import fixture attempted to
move a Vec and its borrowed parsed view into one drop tuple. The one-file
correction drops the view first, preserving the assertions and payload lifetime:
manifest `f6af95423235b65896f348f5194092e9fe24b7bf22af8cd8ba4184da5405bd13`,
patch `86dfd6c6462f8e9f0ada368c849c48c9ad2baf2c471e16b77de106b3d416487a`.

`c04-isolated-final-source-point-text-join-v3` then compiles and runs Engine56:
**55 pass / 1 fail**, tests49.10 s, runner153.09 s/exit101, all1,683 pins stable.
Passes include all31 source-work/census checks, all5 actual prospective source
checks, all3 final primary/index joins, all3 accepted collection drafts, both
ordinary reusable-point cases, all4 protected borrow cases, all3 encrypted text
Directory cases, both actual text imports, and both exact text metadata codecs.
The new text row-map cleanup fails because its abort decoder recognizes only
the four structured tree tags. The pending repair uses the canonical IndexKind
decoder; it preserves unknown-tag and page identity/digest rejection. No claim
of an overall pass follows from this run.

The unchanged larger branch/Released ordinal case also passes with the reusable
point backing: `c04-isolated-index-span-reusable-point-v1`, **1/1**, tests777.99 s,
runner778.00 s/exit0, **1,683/1,683** stable. A local sample showed real abort
cleanup; raw samples remain outside public evidence. This run overlapped the
large Store workload, so it is not an isolated latency comparison. That Store
selection remains running; its byte-bound case has passed, but neither the
unfinished selection nor the previous intermittent mismatch is marked closed.


The next mandatory Manifest/text-runtime integration cohort is **FROZEN,
UNAPPLIED AND UNTESTED**: 92 files and 22 dependencies, manifest
`29602abc5c6bab9fba2a7006b7d94c333d7e629f07b3bc2b3e3290d4c6719e04`, patch
`d599ddc427dc4f1e3bfc3a5f7de3169aef8b8065b431456d15b0b6563f1831dd`.
It combines required KSPCOL02 collection manifests, original selected index
baselines, structured old-graph retirement, bounded collection preferences,
the canonical text abort-kind decoder, exact document prequotes, vendored
Japanese dictionary profiling and explicit text runtime ownership. The private
synchronous text producer writes actual encrypted files and exact metadata;
complete text graph proof, selected query parity, writer/finalizer peak
qualification and production activation remain open. Eight saved upstream
library files and eleven saved pending-dependency snapshots matched their
recorded hashes. Narrow registration rebases retain all test modules, and the
old-graph rebase preserves the already-selected equivalent match-arm order.
The two earlier composition conflicts were not applied. This artifact is not
evidence of compilation or a passing test.

The latest reviewed composition supersedes that pending artifact but is still
**UNAPPLIED AND UNCOMPILED**: 117 files and 31 dependencies, manifest
`b34ffb3e11c43a319ee982017da95366e775fb85a5f3045b403048d8ba75a0cf`, patch
`0c59495acc45391a5a2ed7bed5e542c106f623e129124c16f693837f1aa036d7`.
It adds the shared text-query builder, charged runtime/weak registry, actual
initializer work census, exact operation cancellation, sparse structured edits,
canonical carried-object authentication and original protected-source loans.
The preceding v15 composition parsed all 70 changed crate Rust files without
syntax errors; this is not a compilation or behavior check. Text reader lifetime
closure, complete semantic proof, merge/ranking parity and full-fit idle runtime
ownership remain activation gates.

The unchanged optimized Store test binary builds successfully in the existing
target directory: `c04-isolated-store-images-release-build-v1`, runner210.52 s,
exit0, **1,683/1,683** pins unchanged. Its large-image selection
`c04-isolated-large-store-images-release-v1` passes the byte-bound case and
continues the operation-bound case. The duplicate debug selection
`c04-isolated-large-store-images-batched-tombstones-v1` was explicitly interrupted
to stop competing with that optimized run: runner4,089.96 s, child exit-2,
**1,683/1,683** pins unchanged. Its byte case passed; its operation case did not
finish and is not qualified. Samples showed actual encrypted staging work.
Neither these partial runs nor the successful build closes the earlier exact
physical-allocation mismatch.

The pending composition also includes an independent encrypted-spool sync bit.
It skips only a repeated sync of the same already-synchronized file, marks every
accepted write/resize before native entry, and clears only after a positive sync
or the existing synchronized shrink. Native arena synchronization visits only
the active arena; no claim of repeatedly syncing all historical arenas is made.
Failure fencing, original errors, durable shrink and final close remain required
checks, followed by the unchanged large-image workload on the amended source.

The optimized large-image selection was subsequently interrupted to apply that
concrete sync repair: runner1,188.16 s, child exit-2, **1,683/1,683** pins stable.
The byte case passed; the operation case remained unfinished. Preserve both
interruptions and rerun the original inputs, assertions and limits.

Applying v16 initially failed the patch syntax check before changing any source:
an upstream file without a terminal newline needed the standard diff marker.
The regenerated patch preserves every saved before/after byte and is now
**APPLIED ONLY IN ISOLATION**: 117 files/31 dependencies, manifest
`ca10e17520750a6c4d3a56dc87acc189050b4bfc8aeae576208f71063dd1ec75`, patch
`780d296e15a5323cae950d4d581499aefa4dd83b8f575e16cc9cb6cb4b295465`.
`c04-isolated-mandatory-text-runtime-spool-v1` starts focused Query, Engine and
Store checks on **1,743** source/config pins. The retirement-target mirror,
one-key final publication count correction, journal-reader ownership and deferred
weak-upgrade release are still separate pending artifacts.

`c04-isolated-mandatory-text-runtime-spool-v1` fails compilation with five E0624
errors, runner76.20 s/exit101, **1,743/1,743** stable. The sibling stage components
need the existing manifest/selector/gc/incremental methods visible within their
existing stage parent. The four-file correction changes only those visibilities
and removes one unused query import: manifest
`2b38dfd60b475265ca4a3cff80fb17627a6e59d0809d8c65791d9de523d95701`, patch
`854469f958825c7e2d3d0d14dd1d10543638faee43322c4557424e182b294898`.

The unchanged focused selection then **PASSES all 50 checks** in
`c04-isolated-mandatory-text-runtime-spool-v2`: Engine34/34 in236.43 s,
Query11/11 in3.69 s, Store5/5 in0.82 s; runner288.39 s/exit0,
**1,743/1,743** stable. This includes the previously failing text row-map cleanup,
all actual runtime registry cases, sparse unique swaps, canonical carried-key
roles, complete old-graph retirement and actual encrypted text producer metadata.
The five new sync checks preserve original failure and panic fencing. This is
component qualification only; it does not qualify the unfinished large-image
operation case, text writer peak or production cutover.

The next 28-file/16-dependency cohort is **APPLIED ONLY IN ISOLATION**: manifest
`edab52418c85d7d8f92f809098e68388e6d9b21c5ee3a0ea48b4345471009dcf`, patch
`e1a274b5cb2c019c70a6e0c8cc384bc3fd90531f882983e6bde4b4d7cc6748ed`.
It contains reciprocal retirement records with atomic paired cleanup, the actual
one-key publisher's required catalog count, deferred weak-upgrade credit release
outside registry locks, and vendored OwnedBytes with an optional external lifetime
owner. Original upstream license whitespace is preserved byte for byte. The
published OwnedBytes archive hash and five included upstream files match the
saved provenance; its root LICENSE/AUTHORS come from the separately recorded VCS
commit. The vendor inventory preserves the existing Japanese dictionary patch.
All Query unit tests and focused Engine retirement/registry cases now run on
**1,748** pins. The new ownership path increases inline OwnedBytes size; previous
reader/writer memory-envelope qualification cannot be assumed to transfer.


The 1,748-pin ownership selection now has these completed results:

- `c04-isolated-query-owned-lifetime-all-v1`: **95/95 Query tests pass**,
  tests7.32 s, runner58.78 s/exit0.
- `c04-isolated-ownedbytes-lifetime-v1`: **15/15 unit tests pass**,
  tests0.01 s, doctests0, runner81.00 s/exit0.
- `c04-isolated-text-runtime-real-allocation-v1`: **1/1 passes**, tests1.88 s,
  runner85.86 s/exit0. Embedded bytes47,524,744; requested heap peak278,508;
  retained heap275,308; admitted total52,988,594. The test checks zero-allocation
  preflight, prior admission, 256 allocation-free clones and final allocation
  retirement before the original grant. It does not measure RSS or writer peak.
- `c04-isolated-retirement-runtime-lifetime-v1`: **15 pass / 1 fail**,
  tests35.40 s, runner217.65 s/exit101. Registry, reciprocal retirement, corrupt
  mirror and unknown-outcome paired cleanup checks pass. The unknown final
  publication fixture expects three objects where the required catalog makes
  four; this failed evidence remains retained.

The one-file fixture correction preserves the actual five-effect unknown final
publication, reopen, original claim and no-abort assertions: manifest
`988970e6183d280e86b2ef64882a36051b412dd0bc9a0228681bbf17ad0d1bc7`, patch
`f4e3579205470702b4314c1909f83f08696988dd0082bb661b23714444e74005`.
`c04-isolated-mandatory-unknown-publication-v2` **passes1/1**, tests7.55 s,
runner43.65 s/exit0, **1,748/1,748** stable.

`c04-isolated-vendor-runtime-lifetime-selection-v1` **fails**, runner0.09 s/exit1,
**1,748/1,748** stable: the first OpenRaft inventory mismatch is its memstore
source. Read-only comparison finds **42 existing inventoried OpenRaft files**
with changed bytes. Their inventory entries were deliberately preserved while
adding the separately reviewed dictionary and OwnedBytes patches. These older
OpenRaft changes need review and regression evidence before their inventory can
be updated. This failure is not cured by a bulk hash refresh.

`c04-isolated-store-clean-sync-release-build-v1` **builds successfully**,
runner181.24 s/exit0, **1,748/1,748** stable. The unchanged large-image operation
workload still needs completion on the amended source; no build-only pass or
previously interrupted run qualifies it.

The six-file sparse retirement-set proof is now **APPLIED ONLY IN ISOLATION**:
manifest `7d6dc722bee3cf389e91c7999e4746e027a74d6646b300f1c75e3dbff3f6955d`,
patch `36345cbafaed156adc02f85af8577595be8adbb4bea873f49ab6407a2637f5b4`,
nine exact dependencies. It compares every original structured owning edge with
its next role/scalar path and reciprocal retirement ordinal. The read-only proof
preserves original inventory; final graph closure and service activation remain
separate gates. Its actual sparse swap/missing mirror/preserved-target check
runs on **1,750** pins.


`c04-isolated-sparse-retire-set-v1` **passes1/1**, tests372.22 s,
runner427.12 s/exit0, **1,750/1,750** stable. The actual unique-swap fixture
verifies preserved shared keys, missing inverse records and substitution of a
preserved target, then completes real durable abort. Sampling during the long
cleanup showed both Released and ordinary resource-removal branches; it was not
evidence of a completed test until the passing terminal result.

The unchanged large encrypted Store selection runs as
`c04-isolated-large-store-images-clean-sync-v1`. Its **422-pin Store dependency
closure** is derived recursively from locked offline Cargo metadata, including
all eight local packages, root manifest/lock and toolchain/config. Every pin
exactly matches the preceding successful optimized build's1,748-pin manifest;
the executable hash is retained separately. This isolates Store evidence from
unrelated Engine/Query edits without omitting a Store dependency. The binary's
inputs, assertions,65,539-operation workload and8MiB staging cache are unchanged.
This run remains unfinished until its terminal result; component-only scope
cannot qualify Engine serving.

The next **18-file/18-dependency** cohort is **APPLIED ONLY IN ISOLATION**:
manifest `c607d55b09113a831589dc1e1531697039a5e10d7e63a3bc707db34e8434d79c`,
patch `54e53d201d93b0b2aefb43ab63b33eda3633727387ec6a282cb4b0937844c720`.
All changed files are outside the running Store dependency closure. It joins
actual sparse primary/index edits to the required catalog and Manifest, adds the
fixture-only encrypted journal reader with exact handle/byte/error lifetime
ownership, and retains charged analyzer data between queries through a shared
external idle owner. The journal reader's raw SegmentReader visitor is explicitly
test-only; arbitrary parsed clones and production abandonment are unqualified.
The source registrations and five dependency diffs were reviewed before a strict
conflict-free merge; every original artifact and saved dependency is retained.
`c04-isolated-sparse-journal-idle-v1` runs focused Engine checks on **1,757** pins.
The earlier long branch/Released graph case is excluded from this iteration and
requires final-source requalification after the common graph refactor.


`c04-isolated-sparse-journal-idle-v1` **fails compilation**, E0271 at the
journal range quote's `try_fold`, runner65.89 s/exit101, **1,757/1,757** stable.
The one-file correction resolves the checked initial allocation before folding
checked additions; no allowance or failure predicate changes: manifest
`49d9aad1faaad119f3d4569c4df5e88254a0f18f301584a15732f6442416578a`, patch
`023b4f31f92a4fd56cae346320f8d14e5b865565bc821882b71c457feda637dd`.

Review also found that an earlier pressure observation could outlive an actual
release of memory. Idle extraction now rechecks the exact request against the
current ledger while holding the idle cell, and destroys removed data only after
both locks release. The three-file correction and original-release race test are
applied in isolation: reviewed composition manifest
`b1775f2fc3cef4fc751aa3072299d15e70f4aa47478ed399ad679893d9906931`, patch
`f6df37f0835d12127c4215539ae5091ca3dcfb1422912ecc21de27ddaef6e131`.
The unchanged focused selection runs again as
`c04-isolated-sparse-journal-idle-v2` on **1,757** pins.


A read-only OpenRaft review inventory identifies the exact scope: **42 changed
existing files and11 added files**, with5,415 diff lines for existing files.
Every existing file's recorded prior hash matches its current Git HEAD blob;
those before/after bytes and additions are saved for review. No vendor inventory
has been refreshed, and saving this review input is not review completion.

`c04-isolated-large-store-images-clean-sync-v1` **passes 2/2**, tests
1,525.91 s, runner 1,525.92 s/exit 0, **422/422** stable dependency pins.
Both actual encrypted images exceed the ordinary bound, including the unchanged
65,539-operation workload and 8 MiB staging cache. This terminal result replaces
the unfinished status of this run only. Earlier interrupted runs and the
original exact physical-allocation mismatch remain preserved and unqualified.

The still-running `c04-isolated-sparse-journal-idle-v2` selection has exposed
five idle-owner failures. The real analyzer load outlasts the RSS sample's
freshness period, and publication incorrectly treated retaining already-charged
data as a new admission. The pending correction preserves all five original
tests and adds an explicit fake-clock stale-sample case; fresh-admission checks
are unchanged. The 16,513-row/91-directory-page fixture, journal ownership
checks, and actual text baseline/physical-statistics fixture have passed in this
run; its aggregate result remains pending the actual sparse Manifest case.
One read-only sample of that remaining case reached graph ownership writes
through real Store/native lookup; a sample is not a terminal test result.

`c04-isolated-sparse-journal-idle-v2` terminates **63 passed / 5 failed**,
tests 1,488.97 s, runner 1,571.12 s/exit 101, **1,757/1,757** stable.
The actual sparse ordered swap, mandatory catalog, final corruption rejection
and real abort all pass. The five failures are exactly the idle-retention cases
described above. A second read-only sample reached the later abort phase and
both Released and ordinary removal branches; the passing terminal result now
qualifies this component on those original bytes.

Root review of the changed OpenRaft protocol, worker and ownership paths is
ongoing. `c04-isolated-openraft-reviewed-unit-v1` **passes all 251 unit tests**,
tests 1.02 s, runner 1.24 s/exit 0, **1,757/1,757** stable. This is the actual
vendored library with serde/storage-v2; no inventory hash has been changed and
this result alone is not a complete upstream/platform qualification.

The next **30-file/21-dependency** root-reviewed cohort is **APPLIED ONLY IN
ISOLATION**, manifest
`26479711402cacca210405fcfd5c6459eccbb46842b0654126aaa230b126bf1b`, patch
`d7c74ef68dcc0ebffbeb7c117d317fefe3092582301018596859d7b542803df7`.
It includes the unchanged-test idle correction; same-Core budget resize/events;
actual post-publication wake with reentrant guard checks; bounded preliminary
graph pins; separately prepared current-source custody; the synchronous text
writer session; and positive raw-handle exclusivity including caller-created
Weak references. Exact constituent before/after files and dependencies remain
in the composed artifact. No production serving activation is claimed.
`c04-isolated-idle-budget-source-text-v1` runs focused Engine checks on
**1,763** pins. The previously passing long sparse/branch/full-fit workloads
remain final-source requalification gates after further graph changes.


`c04-isolated-idle-budget-source-text-v1` fails compilation with E0505:
the publication fixture kept a future borrowing SourceRoots across the explicit
root drop. Runner34.08 s/exit101,1,763/1,763 stable. The one-line explicit future
drop correction is preserved: manifest
`861fca1f46716c5f5dabe754ffa58fc9feab63892a629d34f3cae8d71f6fbb50`,
patch`0c1ff6a592117c320cd297f5692700107146efc7c4c0cc607e23713350cc2ba5`.
No assertions, caps or implementation behavior changed.
`c04-isolated-idle-budget-source-text-v2` **passes112/112**, tests98.68 s,
runner136.15 s/exit0, **1,763/1,763** stable. This includes all five original
idle failures, the explicit stale-sample case, same-Core budget resize/events,
private-current reads and original actual-publication reentrant-waker checks.

The next22-file/18-dependency cohort is **APPLIED ONLY IN ISOLATION**,
manifest`a2e7e4f25f985d9e694bf2c396cac9163ffbb612d223fde4ccc11226123e8cf7`,
patch`60c13291537199858c3f47ca15876f81f8e4a554f5c2b45c3fa5f31f1faf9941`.
It contains prepared current-reader staging/final proof/abort, scratch control
and byte-view ownership, persistent journal destructive-call entry, and resident
text merge reference tests. `c04-isolated-prepared-stage-scratch-text-v1`
finishes **25 passed/1 failed**, tests90.11 s, runner131.67 s/exit101,
**1,766/1,766** stable. The installed-cohort fixture incorrectly selected an
initial root before installing the cohort and fails with `source cohort must
precede first selected root`. The separate actual accepted mandatory-baseline
fixture and all selected text ownership tests pass. Cargo stops before Query;
this combined run contains no Query test result.

`c04-isolated-text-resident-merge-v1` separately **passes2/2**, tests0.30 s,
runner3.07 s/exit0, **1,766/1,766** stable. The actual resident implementation
retains mixed-deletion physical statistics, removes wholly empty segments, merges
at the default eight-segment boundary, and preserves old snapshot score bits
across24 subsequent updates. These are reference semantics, not disk-serving
parity. Baseline import must retain physical text semantics; schema rebuild's
existing fresh-live behavior is a separate operation.

The reviewed OpenRaft inventory is deliberately updated **ONLY IN ISOLATION**:
42 replacements and11 additions, with558 unchanged predecessor records.
Metadata/evidence artifact manifest
`4d85c658a728893f7c970f34875953c1268f173744fd890fc9c474ca11cf48d0`, patch
`9e2ab295f0c9c6c66a527523afa3a259a59e31ac8fcfb7a64db067a0002fff33`,
9 changed metadata/evidence files and611 exact vendor dependency pins.
The [development review checkpoint](../openraft-capacity-bounded-apply-review-20261003/README.md)
retains the prior checkpoint, exact53-file delta and actual251-test library run.
`c04-isolated-reviewed-vendor-integrity-v1` **passes18 verifier tests and the
complete exact dependency selection check**, runner0.53 s/exit0, **960/960**
stable vendor/metadata/proof/config pins. All8 selected patched packages verify.
The historical mismatch remains recorded above; this closes only its reviewed
integrity correction, not upstream platform or Kasumi release qualification.


The next12-file/13-dependency cohort is applied in isolation: manifest
`7d9621c767468950aec93e264fca69b394c2e56fca787db4669d478cb96f4517`, patch
`0b6c3686a355593d0ae5261c0c0cb217952df303426bdb777b80ae693e711d6a`.
It corrects only the canonical-cohort fixture order, adds the scratch owner's
persistent actual-native-close fence, advances a separately bounded revision on
every visible Generation swap (including a shared SourceCell), and adds the
Database-borrowed finite refill session. Its six real tests cover initial full
fit, finite pressure/release, budget changes, same-cell publication, final exact
Generation checks, dropped entered work and original diagnostic custody.
`c04-isolated-refill-revision-fences-v1` **passes25/25**, tests22.17 s,
runner69.30 s/exit0, **1,767/1,767** stable. This corrects the previously failed
prepared-stage fixture; canonical ordinary-open rejection is unchanged. The
session remains test-only until service task backing/shutdown, primary cache
pressure reconciliation and the document/index publisher are integrated.

`c04-isolated-text-resident-baseline-v2` **passes3/3**, tests0.35 s,
runner2.83 s/exit0, **1,767/1,767** stable. Its added exact reference test proves
that a clean rebuild of the same live documents changes score bits relative to
a mixed-deletion accepted snapshot. This is a concrete baseline-import gate.

Review found a synchronous relief callback under the document-pool mutex.
Deferred dispatch preserves the exact original Reservation shrink, restores its
provider, unlocks, then wakes. Its four-file/two-dependency artifact is applied:
manifest`1387c1d2e94e6402aaa17caf68ca6ad83858df4e8d5692e8b029370d1709bd40`,
patch`95ebf6f671bb2510c80c1bf4145365c9a17b07d0a5fbfd5b35d9c1ec0029acf1`.
The corresponding `c04-isolated-document-pool-relief-v1` selection finishes
**38 passed/11 failed**, tests6.56 s, runner54.96 s/exit101,
**1,767/1,767** stable. Ten pool cases refuse their initial pool constructor;
one still expects two bookkeeping grants instead of the actual three. The two
new reentrant-waker tests therefore did not reach their target action. Admission
and finite-refill checks pass. The proposed fixture correction derives slots
from actual constructor ownership and keeps both obsolete totals as negative
cases; byte/work/protected floors must remain unchanged. Correction is pending.

Prepared old-source ownership and root's actual synchronous text allocation
observer are applied as16files/13deps, manifest
`6366b7f60e346a8f18f7079b7dcbfff4af25610e5359238bac0948eb936d61d0`, patch
`d949db305e9f83992c89c4e208eb257709651b8a8ff9fa4f60d3cba642d4387d`.
One preaccepted counted old reader and its actual point backing serve every
baseline graph loan; no per-collection native fork/source Cell is needed.
The allocator observer tracks only allocations created inside its exact thread
scope, ignores preexisting frees, and conservatively counts realloc overlap.
It uses the actual synchronous Session APIs and encrypted scratch, including
finalization and parsed traversal. Four finite English/Japanese payloads use the
initially attempted128MiB work envelope; this cannot prove an arbitrary-document upper
bound, async merging, whole-process RSS or disk text publication. The focused
`c04-isolated-old-source-text-allocation-v1` runs on **1,772** pins.

That run is now terminal: **9 passed / 1 failed**, tests20.26s, runner61.11s,
exit101, all1,772pins stable. Three protected old-source tests, four existing
baseline tests, the mandatory current baseline and the actual observer unit
passed. The Session matrix was refused before any peak assertion with the
original `ResourceExhausted` diagnostic. No allocation bound was established.

Two reviewed corrections were applied to the isolated source. The pool topology
fixture accounts for its actual facade, startup inventory and shared idle owner
plus the pool/work grants. Its former insufficient caps remain negative cases;
byte floors and saturation assertions are unchanged. Artifact manifest
`d1018a705b05e0496575a7303c17c7d1ae5cb6a0221aec070866f5b2e071a2d0`, patch
`c153d45b3ed465e2be4866d9714c5709295b439b2ae477aadaecdd8b535bf3e0`.
The root Session matrix retains the original128MiB refusal as an explicit
unchanged-ledger negative check and uses the existing producer's32MiB work
allowance, without raising node limits. Manifest
`cc054d9b329dce952a110eb3735fdb9ccade02b90dd05d16bef32d4cc5bc9d1b`, patch
`d9d3631efd4251aa8cd5b8268a757273ed709f143962eb59c8f09e82a334857f`.

`c04-isolated-pool-slots-text-allocation-v2` is terminal **15 passed / 1 failed**,
tests7.96s, runner22.92s, exit101, all1,772pins stable. Every selected pool test
passed, including both actual reentrant relief callbacks. The sole failure was
`observer lost an actual allocation`; the previous thread-local observer could
not account for native worker frees before address reuse. The peak assertion
remains strict, and this failure is not allocation qualification.

The next reviewed20-file/15-dependency cohort combines actual budget
reconciliation, prepared Ordered sources, accepted physical text snapshot loans
and an observer correction. Manifest
`4297aa6193faad53164d903d24e96179375c490f4ef49404b493621b3902d645`, patch
`a00a1040f64464413da9db1bbf75a8ea33f8d7501e0f40927f8c3983cc9b6618`.
The observer now serializes System allocation operations with its fixed
allocation-free pointer table, tracks frees/reallocations of its original
allocations on all threads, and uses UnsafeCell for synchronized mutable state.
It still observes new allocations only on the synchronous producer thread;
asynchronous writer/merge allocation qualification remains separate. A new
actual cross-thread drop/address-reuse regression accompanies the correction.

The first selected run, `c04-isolated-reconcile-ordered-text-loan-v1`, stopped
at compilation: unresolved import `tantivy::SegmentId` in the new borrowed
snapshot module. Runner1.62s, exit101, **1,774/1,774pins stable**; no tests ran.
The export-path correction is pending. No implementation in these cohorts has
been promoted to the live checkout, and all C goals remain open.

The exact Tantivy export correction (manifest
`a93bb6ebe3d55e2729747a00c51d9cd61d7f874fa36259fafe691fcba4e767cb`, patch
`28559fd9421e13376d08e8e342232c5221f356b4ddb8c684306def3357233f87`)
uses the pinned public `tantivy::index::SegmentId`. The resulting
`c04-isolated-reconcile-ordered-text-loan-v2` is terminal **6 passed / 2 failed**,
tests39.54s, runner139.11s, exit101, all1,774pins stable. All four collection
protection tests pass. The actual synchronous Session matrix passes all four
payloads with complete observations: requested peaks15,390,084;15,519,563;
20,228,003;15,529,164bytes, each below the unchanged33,554,432byte allowance.
This measures new producer-thread allocations and cross-thread retirement of
those allocations; it is not full asynchronous/RSS qualification. One observer
fixture retained176bytes of lazily initialized barrier parking backing. The
canonical-custody fixture failed with the original `primary applied cursor absent`:
bootstrap has no advancing command cursor. The filter in this run did not select
the six refill-session cases; no refill rerun is claimed here.

The reviewed8-file/11-dependency protected-baseline cohort (manifest
`18552d2521ea856fc78b75e7f5b79aa4101621d9888fb42f6ad42574016c26c9`, patch
`08ab9a0252f0d4fa358e161c79013461101de783a582a593cb7e72b9e365077c`) adds
preaccepted unbound selected-reader capacity and exact actual-receipt baseline
capture. It fixes the cursor fixture by publishing an actual authorized command
before capture, and warms only the cross-thread test's barrier controls before
observing the32actual payload transfers. The real Session matrix is unchanged.
Its first run `c04-isolated-protected-baseline-refill-v1` stopped at compilation:
private `current_generation` access and a command move while borrowed. Runner12s,
exit101, all1,776pins stable. The exact two-file correction uses the existing
access-fenced `generation()` and drops prepared before command without cloning;
manifest`ea19d79d2085a662657fa9031ed08a32df8dfffa93265831c0b2f3540e184534`,
patch`2f76eacf4039641aaa095ff2bab5b140ed52d7f11aee7116935dd5b3b6c167a4`.
`c04-isolated-protected-baseline-refill-v2` then passes **14/14**, tests56.54s,
runner87.81s, exit0, all1,776pins stable. This includes all six actual finite
refill-session cases, late binding under full ordinary byte refusal, actual
canonical custody, protected indexed baseline receipt capture followed by indexed
Edit final proof and complete abort, and both actual allocator-observer tests.
The test does not yet publish the second Edit or activate production serving.

`c04-isolated-text-physical-loan-v1` is terminal **3 passed / 1 failed**,
tests0.63s, runner5.42s, exit101, all1,774pins stable. The unchanged late-merge
case could not reopen its original `.del` path: the old scoring reader survived,
but Tantivy GC had removed the raw directory entry. The reviewed correction
retains original raw FileSlice controls for seven fixed component roles when
each immutable snapshot is constructed; there is no file-byte or row-map copy.
Manifest`92638a09ffceac9a7e52ace7db525a8ad0011a1a8541d3f0c2ca813981727951`,
patch`ce6a9adc8c34904e7f687c391ccb969b74946137c322ec83f7911b05aaf81276`;
five exact saved upstream dependencies were independently checked. The unchanged
`c04-isolated-text-physical-loan-v2` passes **4/4**, tests0.32s, runner4.24s,
exit0, all1,776pins stable, including raw-footer reopen, deletion state, live row
identity and exact old score bits after a real default merge. Additional retained
descriptor/history accounting and bounded encrypted import remain open.


The actual same-Core cache reclaimer is applied in the isolated nine-file,
seven-dependency cohort: manifest
`fa3330da4516348f8ac15aa9ac89fadf89d735cfaf92930e8c104ae43b3c3512`, patch
`e982cbe634f47ff35cacd214b64887ddc407334926b9fd420b4073fefdb5f468`.
The fixed weak registry, exact original request and one measured-release retry
retain active loans and dispatch callbacks outside the membership/ledger locks.
Slot contention, cancellation and scan/refill requests cannot trigger eviction.
The primary component remains test-only until the complete production join.
`c04-isolated-primary-reclaimer-v1` stopped at E0596: mutable exclusive access
inside a match guard; runner 37.91 s, exit 101, all 1,777 pins stable. The exact
one-file correction moves the check into the arm body, manifest
`4f7095146e9329eeb1e03e3bbcdd6563bf086d10ed4f5463763b7449e7ae9ccd`, patch
`b38e0e7a193165b994e95c5befc6b0dfe0507eda089322995efcc825fdf3909c`.
`c04-isolated-primary-reclaimer-v2` then passes **41/41**, tests 15.44 s,
runner 74.98 s, exit 0, **1,777/1,777** stable. Its selection includes actual
new/growth/same-pool pressure, registry bounds, callback reentry and original
request priority, all six refill-session cases and collection protection.
This is component qualification, not production activation.

The next applied artifacts are awaiting a coherent focused selection:

- Finite cache victim sampling and explicit optional frequency priority:
  manifest `56d5f38375d6db0b665fbcf1b901aa76a820879960308c317ba806de08324a94`,
  patch `fcf948844b7a6d58ce4ad2e0f51c3a9ba22c820179d0a668df6e66e833c99459`.
  Eight files/five dependencies; initial-directory probe bounds replace repeated
  whole-directory minimum searches. Cold demand cannot evict hotter entries;
  optional admission cannot evict another cache or the idle analyzer.
- Encrypted physical text baseline import:
  manifest `8f2bb2e6b8af7c15552f9e4f310f8e9e4395d8bbfe785f73c2e17551425c9ec4`,
  patch `b9d4c44b76e66437626c9aa4ec42233943bd3759ef9f6a1976ef682fa2e09f19`.
  Six files/twelve dependencies; distinct KSTSEG02 metadata preserves original
  physical segments and deletion masks. Its incomplete span cannot publish text
  roots; complete statistics, memory accounting and verification remain open.
- Actual protected Ordered publication receipt consumer:
  manifest `96085f44f4c5de7465d5b40005451f32ed7bb930231347f3ad37c53d33f88216`,
  patch `851bd63787b8ab70c46a58499bd52f05865446ed09801bbf87b9c9bfe0b8e7a7`.
  Six files/thirteen dependencies; the original immutable complete proof and
  apply guard survive the metadata-only commit and exact selected readback.
  The separate final captured-reader access check uses manifest
  `a51569a831595fb4db0a5d2254cb24a7013139ffd9809e84969ed05eed0ac8e1`, patch
  `c3520f6eaadf231d9777f55b5e30570ced48446c4691871a0bc39c6a38c357a6`.


Before compiling that batch, exact fixture-only corrections used the existing
access-fenced `generation()` method (manifest
`41f37cb96b6781badce27715a1bde83ab040becdc82fddc0a2c5981e742e85cf`, patch
`c9ea370817b824d39240ed807d199ca74eda2ef0def906ac1e15963d3575d22e`) and
separate prepared/command/source-work destruction (manifest
`7f80e4c89f106fc044c75082e6056a3f1a42bd631c304c8764b7cb414fcbc5af`, patch
`eac2b85692f18507d8dfa5bacc9cadd0399440ed4c20c6652bcc1249afb5eecb`).
All original assertions remained unchanged.
`c04-isolated-cache-sampling-physical-publication-v1` passes **27/27**, tests
59.49 s, runner 109.93 s, exit 0, **1,783/1,783** stable. This includes the
actual protected indexed Edit commit/selected receipt and successor baseline,
the unchanged protected baseline→Edit proof/abort fixture, all three encrypted
physical text imports, actual 1,024-entry finite sampling and hot-demand
priority, same-Core reclamation, six refill sessions, pool and collection
protection. Complete text statistics/proof, preaccepted operation work and
production service activation remain open.

A subsequent one-file visibility correction restricts physical import to its
actual private stage/index caller, matching its PrimaryResources argument:
manifest `a7cff981418d339b429d462eef13aa5b2f3f3eb6dc29f13cbd661cbcbddaee54`,
patch `8a99a4c7b3531aae45ecffd5b2306fef129ff6c9990f5b46f41806656aea8704`.
It is applied for the next source-pinned selection; no additional pass is claimed.


Root review corrected two large-cache work costs. Already sorted collection
protection tables now use binary search for per-entry accounting (manifest
`6eae25dacec24a88bc1b48e73da3305ba43c12bb4f044531a8fc7dde20ac8ae6`, patch
`d556147d24fd2a26fa623cf25d7bceddabbc4e0ba41cd53d5ee6f4f19a913ddf`).
Lookup now bounds tombstone traversal by maximum actual insertion displacement,
recomputed on rehash (manifest
`2b89d2938391c2a9b96c3928ed3bec3ddf07ce02f851a528c79827b68aa996ce`, patch
`20370bff6ca00899d308332ff32cf9858718433153832d433e1623232203155a`).
The actual pool fixture retains one of 1,024 entries, churns every directory
bucket, checks 4,096 misses by actual probe counters, then refills fitting data.
`c04-isolated-cache-churn-lookup-v1` stopped at E0624 in its sibling fixture's
private removal method; runner 8.28 s, exit 101, all 1,783 pins stable. The method
was restricted to its actual parent cache module (`pub(super)`), without an
external API, manifest
`17460af4f5ff82c3e1faa989c00dffb45a8e1ff8c1d1ecc3f1162591c41bdb40`, patch
`274d03306777850cbcbbb5a2443ecd250b449ff3a9f5747f936a54f473e03a1f`.
`c04-isolated-cache-churn-lookup-v2` passes **6/6**, tests 5.76 s, runner 33.06 s,
exit 0, **1,783/1,783** stable: churn, sampling and all four collection-policy
cases. Its extra retirement-name filter selected no additional case; this is
not a complete retirement suite pass.

The shared text planner now requests matching borrowed physical terms instead
of native SegmentReaders. The resident implementation retains its identical
FST traversal, original failure and cancellation behavior; the disk adapter can
use its bounded physical-term tree. Expansion deduplication and 64/256 limits
remain in the shared planner. Artifact manifest
`d327b85e6be5398388d12edc0d51f60129a4541efbb241a3ba446328c1b459fd`, patch
`c8954a9e2608449dce2d0263e851dce4eafb061066963f80e1828460a2e374a2`, two files
and four saved dependencies. Applied in isolation; Query qualification pending.
The physical import passes above remain valid for their exact source, but whole
native merged-file reads cannot establish a RAM bound. Bounded live components,
physical deleted-term statistics, a live term-to-component posting directory,
and a shared logical merge policy are now explicit production prerequisites.


`c04-isolated-text-matching-term-loan-v1` now passes the full Query unit
selection: **99/99**, tests 3.75 s, runner 5.43 s, exit 0, **1,783/1,783** stable.
The original typed token/statistics failure checks and the renamed original
term-loan failure check pass, as do all existing text/reference regressions.
This qualifies the common planner/resident adapter refactor; the disk physical
term source and bounded component scoring still require implementation.


`c04-isolated-cache-lookup-retirement-v1` passes **2/2**, tests 4.93 s,
runner 17.24 s, exit 0, **1,783/1,783** stable. It selects the actual
concurrent-rehash source-retirement and hot-demand-history scan regressions.
A subsequent independent source review found all insertion sites update the
lookup displacement bound and rehash recomputes it under the same lock;
deletion conservatively preserves it. No extra execution is claimed by review.

The actual primary command factory now owns prospective primary resources,
Ordered page/frontier/collection backing, and original current/old/capture
owners before invoking the candidate reducer. Nine files/thirteen dependencies,
manifest `75bc6c26ebe357e336f2720ad63b371537cbd27cfba10df983f32a878ba6e80b`,
patch `2335a8b2fbf7c8c511d5f3869e21c5db6dabf2ba5f6cd3bb5d0b92a1923c9be4`.
The collection bound is now O(1): Mutate cannot create collections, so the
minimum of operation and previous-collection counts safely bounds touched
collections. The original quadratic draft was corrected before compilation,
manifest `4aab745b06df2ac3f5ba1ce330b610688efd88af500dc581f6755bdb1856c159`,
patch `bfe4a1d3b1274d5a474fee9c7969e3d5c4f280813582e3b55a0ae3985779257c`;
the existing-collection refinement uses manifest
`5a50f4312a10835619c8c34c875654d4080bcdedeb94ec380272322928b26259`, patch
`61356356e98345d8c4acf9bfe19734738d40954a5744423d9eb2e4596ea9eb3b`.
`c04-isolated-primary-command-workspace-v1` stopped at E0521: an inferred
closure-local guard reborrow escaped into the staged owner. No tests ran;
runner 17.50 s, exit 101, **1,784/1,784** stable. The correction transfers the
exact original guard from its Option receiver without lifetime erasure, manifest
`227aa01b98bcdb9d439423a3f1ae3711d7d8f6931b9e9e53e89a94be2212f84a`, patch
`9b4ca7c61fde4020d6d9dfab0a4f74a0b1337793191712a59eb9701ca4e52410`.
The second selection compiles and is still running; no final pass is claimed.
Its input is `AppliedEntryContext` plus committed command bytes. This is a
before-candidate workspace result, not admission before durable Raft acceptance.
Complete candidate, journal, index and replica/recovery capacity remain open.


`c04-isolated-primary-command-workspace-v2` finishes **47 passed / 2 failed**,
tests 719.61 s, runner 765.17 s, exit 101, **1,784/1,784** stable. Both actual
protected indexed Edit/receipt fixtures pass. Both catalog failures stop one
cleanup unit before their intended catalog row: the collection helper now
stages Definition, the mandatory one-chunk IndexCatalog, then Manifest, after
one phase-transition unit. The original three-unit fixture stopped at Manifest.
The narrow correction uses four units and asserts the precise target ordinal
and zero cleanup cursor before corrupt-row refusal; no production abort code
or strict corruption/progress/old-pin assertions changed. One file/four deps,
manifest `7b1e2746208b18486563c941ea97fbbc2b8eeb7e574dfd013c94f6977edbb6ae`,
patch `15aa0220e2d871c270c5699ad8c21653e6daecda998945f72c47c587ca67f233`.

The next coherent cohort applies these reviewed, hash-verified artifacts:

- Canonical bounded text forest: seven files/twelve dependencies, manifest
  `bfb7cbcad4563be4d655c24275da97bf99096cdac78f6c875b57e68f2b4efeb4`, patch
  `2c063ea8a3289acf40b1d01454df6f8a211ce1945b3b130c957a0680a2b01c2d`.
  Actual clean full builds populate six additional disk roles: live term rows,
  group totals/members, row groups, group statistics and deterministic group
  order. KSTROT02 has one canonical 1,088-byte header and rejects old framing.
  Its descriptors are unverified; original-history baseline population, sparse
  updates, logical merges and whole-graph/ordinal proof remain open.
- Encrypted physical-statistics spool: five files/nine dependencies, manifest
  `c912aa5284f3081aa8d60723e9f6cab176aed56534c43397a3ee7d283593ce57`, patch
  `464b73d0e30cf696001d9c6785ef86d97e22d0742bf1cf0a5ae2c30de0cd8b51`.
  Fixed admitted transport retains original writer/cleanup diagnostics; parsed
  native readers require separate qualified ownership. The replay contract
  clarification uses manifest
  `07538e82c301cf3b60a01a13f8750316361c491b7bf47f7b25d6cc7f9a5de08d`, patch
  `e6f2a62f25e88fa525c7c239250ed4253a7291053f9210fad5b1f6200d5442cb`: visitor
  effects remain private until final digest/census verification succeeds.
- Bounded-component semantic experiment: two files/four dependencies, manifest
  `99658bb5e2d9d7e9439a65d16a7f020e3d3f85bc05527056067784dfee4add5a`, patch
  `7f3b18775bed1d044349ba808e8451798ec4ebc837146887ee84826892959e41`.
  Each native live component is built separately while the original physical
  statistics and term union supply scoring/expansion semantics. This is a finite
  semantic experiment, not a disk-serving or universal memory-bound claim.
- Async primary refill worker: six files/eight dependencies, manifest
  `a3a5f03a8cae5ab677255b4e86a329dd0dbe09b9570b0338721decc7781974bb`, patch
  `c4b175eaf20c0187011ec43e88bd2fc3f9ff0a74c4b16bfb1c40be7d1cb6b830`.
  The Database/global census owns exact run/cleanup futures, Session, task and
  original diagnostics before first poll; a separately funded run-waker proxy
  retains escaped executor tails. Cleanup excludes its own immutable ID.
  Complete failures require explicit acknowledgement; unknown cleanup remains
  retained. All-role warm-up and automatic canonical service activation remain
  required, so primary completion does not expose Database initial completion.

`c04-isolated-text-bounded-score-parity-v1` passes the full Query unit selection:
**101/101**, tests 10.57 s, runner 14.89 s, exit 0, **1,788/1,788** stable.
The two new experiments preserve exact score bits for three analyzers, arrays,
multiple fields, normalization, terms/phrase/prefix/fuzzy modes and mixed
deletions, plus deleted-only expansion refusal. The finite limit fixtures do
not establish arbitrary candidate-cap parity. Engine worker/census, spool,
forest and corrected catalog qualification is now running on the same pins.


`c04-isolated-refill-text-forest-catalog-v1` stops before tests at two compile
errors: the sibling spool fixture could not access its private module, and
`wait_for_change(&self)` required Sync for a Session retaining an original
Send-only panic. Runner 40.15 s, exit 101, **1,788/1,788** stable. The narrow
correction keeps the spool module crate-private and gives the sole session
owner an exclusive `&mut self` wait. Original panic traits are unchanged; no
unsafe Send/Sync or erased ownership was added. Two files/three dependencies,
manifest `f6124dfce7a2de08815168bf98a5b86fd4bae8771d64f40c1f44c5352e895ac2`,
patch `427e119cf7c5bab63508386d2c17f31b3b05702282523d2d1b92a4f6bdb1acfa`.
The corrected selection compiles and is running 54 checks.


`c04-isolated-refill-text-forest-catalog-v2` passes **54/54**, tests 175.20 s,
runner 223.58 s, exit 0, **1,788/1,788** stable. It includes six async worker
cases, six finite Sessions, existing source-work/census regressions, all four
encrypted statistics-spool cases, typed text-forest codecs, actual expanded
full/empty producer and retained producer-error cases, and both corrected
catalog cleanup cases. The separately named forest preparation-refusal fixture
was outside the selected prefixes; it is queued explicitly in the next run.

The next reviewed composition adds these concrete owners and paths:

- Prepared fixed structured-index point backing, manifest
  `95a59a5fe1ea612ebe227bc312c5774176538f9b18301ab42a1836c5346baa16`, patch
  `730048655563d8776f6c23c4277f2086a9d4aaad77a58aebd3a2ef89bcf6efbb`.
  Six files/ten deps. The actual before-candidate owner lends one exact Box
  serially through full/sparse builders, restores it before original errors or
  unwinds, and keeps the grant outside its Box control. Declaration/result/span
  and baseline/proof allocation, plus actual local acceptance, remain open.
- Shared deterministic text merge selection, manifest
  `63be4f34f97a509c4a6b35e8dd0a8c5b0a522b5bbdd77058cd973deeef7292a0`, patch
  `fcd59b4f06f201e6660c3ee4ad7e2255f1cff67f34d21061aff0bcc9bc41de60`.
  Four files/five deps plus four saved/current Tantivy source hashes verified.
  Resident selection orders equal physical sizes by live count and identity;
  fixed-state disk Layers follows the same pinned thresholds. This deliberately
  resolves the old unspecified tie; it does not reproduce every random native
  schedule. Actual disk group edits/statistic retirement remain unimplemented.
- Original-source raw structured index cache, manifest
  `a209677dd3c59ce7e65a3b76e4bd70243945f1ce7ce04ad72d15dbb17e7980ec`, patch
  `3db922976382b39fb88177139a961ef9d8b563f5cfe1fda14aa5b6fcb9ae4f00`.
  Eight files/nine deps. Exact namespace/key/source membership uses the same
  PrimaryCache/DocumentPool and reclaimer; fixed byte Boxes and retained pooled
  controls remain charged. Every loan rechecks access and complete existing
  framing/hash/range rules. Scan intent does not train demand frequency.

The strict composition uses manifest
`29068cb2dff767edbab0714cfefd17041ab4b92c7ea7cfd7d1388a925b781737`, patch
`42d16f1cd98e0ba3abdd57512168d20d14854d1ea6b8f384572bb5f0e27a0ab8`,
eighteen files/twenty-three dependencies. The only older base is the exact
previously reviewed forest value-kind addition in the point editor; its
nonoverlapping work-owner changes merge without selecting conflicting lines.
`c04-isolated-shared-text-merge-v1` passes **105/105** Query unit tests,
tests 3.93 s, runner 8.12 s, exit 0, **1,791/1,791** stable. This includes
actual native-policy comparisons at group/size thresholds, explicit tie
refinement, invalid order/overflow refusal and a 100,000-group constant-state
classifier. Focused Engine cache/point/producer qualification is running.

Root review identified a separate refill liveness requirement: source-work
census availability can increase while external completed-report aliases keep
all byte/slot grants charged. Existing byte/operation headroom observations do
not establish that event. Qualification must show an actual full-census Pressure
pass resumes after global/local census release with those aliases retained,
and that relief racing the post-pass checkpoint is not lost. Preserve finite
idle behavior; do not replace the missing event with a timer or self-wake loop.
This finding is not an observed test failure or a production activation claim.


`c04-isolated-index-cache-prepared-point-v1` finishes **29 passed / 1 failed**,
tests 133.79 s, runner 197.49 s, exit 101, **1,791/1,791** stable. All four new
raw index-cache checks pass: stable no-new-read residency, original/new source
corruption isolation, access recheck on hits, and exact retained-loan credit.
Existing logical/catalog/source validation, actual indexed publication/capture,
full/sparse structured producers and explicit text-forest preparation-refusal
also pass. The new point pressure test fails before its intended body: its
total-ledger remainder was requested through reserve_document_source, which
additionally preserves ordinary/cache headroom. The one-line fixture correction
uses the established reserve_resident origin for the same exact remainder; no
cap, bytes or pointer/error/panic/refusal assertion changes. Manifest
`33f0007abc8831db26972be8e7628c519af3324ece789ee8ce0c72a7bd4915eb`, patch
`60b413b804fb841c55e847825dee1caccfebe1ebb0cab9bcd39bf54fb2731ece`.

Independent original physical-statistics loans use captured idx/term FileSlices
and independent footer/composite/term views; original SegmentReader caches are
never populated by this operation. Only primitive borrowed statistics escape.
The spool now consumes this loan and rechecks access after final native reads
and after complete replay. Five files/seven dependencies plus five saved/current
upstream hashes, manifest
`d0f77a2dd9d5f5dc244e1f116d919db6f610ad241c567d251633d8a67aaee103`, patch
`cc5d6b5d07a0460c7c9b2a18349069711e63b3cfabce644da35122dbb615038a`.
Parsed native allocation qualification and actual baseline consumption remain
separate gates. `c04-isolated-independent-text-stats-v1` stops at E0277 before
tests: native Incompatibility does not implement std::error::Error. Runner
1.14 s, exit 101, all 1,791 pins stable. The narrow correction uses Tantivy's
existing OpenReadError::IncompatibleIndex conversion, retaining the exact
original native value instead of formatting it away. Manifest
`4e737603f9d2693c1fbb6c9d19a4c199059fb81d988e547d509dd35c37bfacdf`, patch
`f6e9c189e32578ce6c9c488b42ce79602c1bc9880938800340754fa95cd07ec2`.
`c04-isolated-independent-text-stats-v2` passes the full Query selection:
**106/106**, tests 3.78 s, runner 6.00 s, exit 0, **1,791/1,791** stable.
This includes old captured physical totals/df after native merge/file retirement
and original typed visitor/check failure identity.

`c04-isolated-point-pressure-stats-spool-v1` passes **6/6**, tests 4.05 s,
runner 36.10 s, exit 0, **1,791/1,791** stable. The actual original prepared
point Box/grant survives saturated ordinary capacity, nested refusal, original
error and original panic. All five encrypted spool checks pass, including the
new completion-access regression. No production activation is claimed.

The goal list is consolidated into current component status and unresolved
production gates. Its removed detailed status/history paragraphs are preserved
verbatim in docs/disk-backed-cache-progress-20261003.md; prior failures, evidence
scopes and open obligations remain recorded. All seven goals stay open.

Finite structured warming is applied in the isolated cohort: seven files/eight
dependencies, manifest `49c95359c011239f0f0d9ca6fa59505d5d6d98c2b1f0f7f76e900b96d2656c33`,
patch `5c6013787c7b23e13c324ac0294a5321979c7bb50b055094cdcd625f2f0aeded`.
The exact selected catalog mints the bounded role table; 128 canonical frames
traverse Values and nested Postings. The original admitted cursor is restored
before returning any failure or original unwind. Completion explicitly retains
a separate text_pending signal. This is not all-role or service activation.
`c04-isolated-structured-index-warm-v1` stops before tests with two E0277 errors:
the test's erased pointer cast incorrectly infers anyhow AsRef<()>. Runner
15.91 s, exit 101, 1,792/1,792 unchanged. The successor specifies the original
error trait-object pointee and preserves both identity assertions; manifest
`4552281cff27153cfb25a4d6dbe19800c46095f7618582ee76940654ac6fa29e`, patch
`0463fa0b06133bc9939e366a498ee498cdeb546bbfbe5928f57df1f21a8de597`.

`c04-isolated-structured-index-warm-v2` passes **4/4**, tests 5.44 s,
runner 38.44 s, exit 0, **1,792/1,792** stable. The actual encrypted fixtures
cover all catalog-minted structured roles and nested postings, a zero-new-read
second pass, missing nested-page original failure custody, terminal pressure
followed by real-release refill, and current access checks after completion.
Work/Session phase integration and text/native completion remain open.

Prepared structured ownership is applied for qualification: manifest
`757cd46c0282ba6d6c07a5a1999a6dbb8e88a313a84a5352354846e806af0bda`, patch
`50594bb1a77b8da47e53662c4155b9730e46c65179c3751ccc88ffbc0f2623b1`,
13 files/15 dependencies. The command factory derives the maximum actual old/new
declaration count for its changed collections. It allocates declaration, graph
and path scratch, catalog wire, temporary final roots and per-collection old/new
root vectors and proof grants before candidate construction. All-old-first binding
uses an admitted fixed collection directory. Actual full, sparse, retirement and
final readback paths serially loan the same concrete work. Returned root vectors
retain their original grant and actual capacity. Missing/loaned/consumed work
refuses without an ordinary allocation fallback. This preparation still receives
a committed input; it does not close admission before durable local acceptance.

During the still-running prepared-structured selection, 15 of 17 fixtures had
reported passes, including the actual prepared indexed receipt. The two remaining
full-span and sparse-Manifest checks consumed about two cores. A one-second macOS
process sample observed active encrypted/native index reads and hash validation,
not a waiting-lock stall. This is qualitative diagnostic evidence only, not a
completed test or throughput result. Sample SHA256 `815cc1efb756a126910a1690ca279e27b7c4237cbe17d740de38d2ada3d7f640`.


`c04-isolated-prepared-structured-v1` has completed: **17/17 PASS**, tests
1,550.49 s, runner 1,589.48 s, exit 0, **1,793/1,793** unchanged. This includes
both complete full-span and sparse-Manifest graph checks and the actual prepared
indexed Edit receipt. The running sample above remains intermediate diagnostic
evidence. This duration is not a production performance qualification.

The next reviewed changes are applied only to the isolated cohort:

- Canonical original-history text Baseline: seven files/13 dependencies,
  manifest `47b73749aabd753c092f37a7730e0724a2f4458f4e5b9859004d0eaf25d9e5b8`,
  patch `13663ac0dcb0a02eea2f4df375df75e8349e7c2f52c04fa8848bbf91d96c7716`.
  Bounded live components retain original row holes, physical/group statistics
  and deleted-only terms through the encrypted, fully verified statistics spool.
- Typed text ownership edges: two files/two dependencies, manifest
  `edff250e8cc92576b89ce03e9870a1c16f409109cb6cf58af83c2426ba2edc9a`, patch
  `1b10d13cccbb5810cc17aee4d34408a9c051f839aaf938432fd839bd1f94c55b`.
- Physical text graph: four files/12 dependencies, manifest
  `ba0e2befbd59db7506b966ba4bdbd47bd5747c603d0872f4c5cd32f084ffc419`, patch
  `f9a98370949f34620bf053deeade6ab16f8e98d3d15282e8dafcd5cacd93aba7`.
  This verifies exact typed header/page/key/component/file closure, reciprocal
  row identity, owning marks and every live/released ordinal. It retains the
  original owners and deliberately grants no publication or text-semantic proof.
- Pure Japanese lattice preflight: five files/seven dependencies, manifest
  `6106a1b2299597ae4798a8d466fa2e4c794a66cec9030fcfd809b4a65e12a211`, patch
  `9627648918f70fe7d4a7db07995eb204fcf171564caf5b89164f00da218f7f88`.
  All four saved and current upstream tokenizer files match the reviewed hashes.
  The runtime retains the same immutable dictionary Arcs and original grant.
  Fresh normal-mode lattice backing only is bounded; writer, output and parser
  allocation qualification remains open.
- Deliberate Lindera inventory update: two files/three dependencies, manifest
  `eaa1ef9a307e813f325fffee33ffa865062c1194a0b3e2d8ffebf1b39b1169b7`, patch
  `eb35d4bacaa853e483126262b698b85a904743b61517d78405cd0d45a61f5047`.
  Exactly two existing Lindera source entries, one new source entry and the
  explanatory vendor README record change. All unrelated source inventories,
  package identities, published checksums and support entries remain equal.
- Typed census capacity and sealed actual-worker wakes: seven files/eight
  dependencies, manifest
  `f309408ffef5030dc3ed80739607f4aef6211d0bc03cc3c7d88a57ac6246193a`, patch
  `70faa9b3b42493eb26443370ac71331e8de13378d57bb636d66a909ec73a88f0`.
  Local/global fullness is captured at the actual failed slot acquisition.
  Global releases borrow only the original private Tokio worker registration;
  output claim and unpublished-ticket destruction dispatch no arbitrary Waker.
  The clarification-only successor is manifest
  `5bcfe8a59b356f33902810e03bec603cef1a97ab607427a2a2f7b8365e5bc947`, patch
  `8755b17e8344259377bbf9f0be56fcc1258f9a9d24c18852d7910774cb74066e`.
  Autonomous global-census wake qualification belongs to that actual worker;
  memory-byte checkpoint races and sampler final-owner self-join are separate.

`c04-isolated-lattice-preflight-v1` stops before compilation: Cargo cannot test
this non-workspace dependency's dev-dependencies through root `-p`. Runner
0.25 s, exit 101, **1,798/1,798** stable. The successor invokes the vendored
manifest with its existing locked dependency graph and the same warm target.
No lockfile, assertion, test payload or resource limit is changed.


`c04-isolated-lattice-preflight-v2` passes **3/3** native prefix/lattice checks,
tests 0.35 s, runner 29.80 s, exit 0, **1,798/1,798** unchanged. The deliberate
vendor inventory verifier also succeeds for all eight selected packages.
`c04-isolated-lattice-runtime-query-v1` passes **107/107** Query tests, tests
3.81 s, runner 21.17 s, exit 0, **1,798/1,798** unchanged. This qualifies the
original runtime dictionary ownership/preflight helper, not combined native
writer/parser peak admission.

Selected structured queries are applied after independent review of their
catalog authority, source/error/cancellation custody and candidate accounting:
11 files/15 dependencies, original manifest
`6dc0d81fbd4fe3635523b3d778abf29f0a7e1f9f8e481051a241a7ca42137495`, patch
`927cce2c97106019f918f9044c70537d6ac8f3b99eb04c6c884765c400945887`.
The exact dependency-only composition records the already reviewed census test
addition, manifest `54256f928514f521bcf7df1190a12ad5a6f65a025b9b8f4d782f2e4718d8a7a3`;
the adapter patch is unchanged. Selected sources use same-Manifest Values and
Presence roots and their owned postings, preserving shared predicate validation
and candidate caps. Arbitrary query strings stay borrowed. Selected text remains
an explicit refusal until its backend is verified; production activation stays open.

`c04-isolated-selected-structured-query-v1` stops before tests with E0277: the
new SourceMarker fixture lacks the Display bound required by CollectionRecords.
Runner 1.35 s, exit 101, **1,801/1,801** unchanged. The correction adds only that
Display implementation, retaining the same marker and identity assertions:
manifest `d6c0a8109194f6a5d88571fe06cfcb21809b8c156fc177dd195266e9d9db47ea`, patch
`04d02db390307586b3382942f571c86a5ae5d877a9091dacebe09ec8003de630`.
`c04-isolated-selected-structured-query-v2` passes **110/110** Query tests,
tests 3.84 s, runner 6.76 s, exit 0, **1,801/1,801** stable, including selected
boolean/array/decimal/range/cap parity with deliberately empty resident memberships,
no primary scan for indexed predicates, and original typed source failure identity.

`c04-isolated-text-graph-selected-census-v1` stops before Engine tests with six
compile errors: five fixture KasumiError-to-TestError conversions and the original
WriterCredit governor-check KasumiError-to-anyhow return conversion. Runner
59.46 s, exit 101, **1,801/1,801** unchanged. The narrow successor wraps those
same original errors using the existing anyhow conversion; no source authority,
assertion or resource limit changes. Manifest
`a7b66ec65b37c2e7b9e990387234aaaf56e225536735d9ddcfe2ebb101d25ddf`, patch
`d95acb117d2fafa028187f74ba898db79130e3745516644e432c92aaf14531ff`.
`c04-isolated-text-graph-selected-census-v2` finishes **74 passed / 1 failed**,
tests 766.50 s, runner 809.19 s, exit 101, **1,801/1,801** unchanged. The failure
is the original-history fixture's asserted Stats branch at
`primary_stage_index_text_canonical_baseline_tests.rs:191`: the supplied term
set still fits a leaf. Keep the split assertion and derive a corpus from the
actual page capacity; the original failure remains in this run's log. All three
physical text-graph checks, the actual selected query adapter, independent
census-capacity worker wakes, cancellation and source-custody checks pass on
this selection. This does not establish original-history qualification or
production activation.

The next reviewed text/private-reader composition is applied in isolation:
manifest `506d59965a8c8e33548b95becc47a022ac42fcc07d0e5afa290c4728c18373b9`,
patch `8fd3324e74c511762e7a0ac374944525fc161d33d2bd5624b4510886871e5537`,
17 files/20 dependencies. It composes exact original-statistics proof, repeated
counter error identity, a preaccepted same-Cell private descendant, and native
component term/TF/position/norm equivalence. The only external source change is
the recorded governor error conversion. All five saved Tantivy 0.26.1 native
reader sources match their current pinned files. Semantic publication, complete
native allocation admission and positive consumer-file retirement remain gates.

`c04-isolated-text-runtime-allocation-v1` passes **1/1**, tests 2.09 s, runner
5.97 s, exit 0, **1,801/1,801** stable. Embedded bytes are 47,524,744; requested
heap peak is 278,548 and retained heap is 275,348 against a 52,988,594 total
admitted quote. Clone sharing allocates nothing and the original grant retires
only after the final clone. These are requested-allocation observations, not RSS
or a combined writer/parser bound.

`c04-isolated-text-stat-private-v1` stops before tests: seven compile errors,
runner 33.21 s, exit 101, **1,807/1,807** stable. One incorrect Tantivy trait
import accounts for six errors; the statistics fixture also reaches a module
outside its restricted visibility. The import-only correction uses the actual
locked `tantivy::postings::Postings`: manifest
`1808f634cb02c99e0130d32a4d4fc81a74672904fd7a20ea56fa99ab64007a34`, patch
`9489df911950e6e118d1afcc5f07bc817e832b57fdd9acf0d94ce8fbde72b98e`.

The historical split fixture correction is applied, manifest
`f07c3c9d503daa6e3d4cc2a0c9c0534bc4c239c106bee9b9f0eaa6d75c4c353e`, patch
`2667a8bd18aa961ebd0fc15dec9c24c4ee5e7909bc6319527f3e2e25bc86db54`.
The actual fixed page holds 40 entries; the former corpus had 16 statistics
keys. Adding the minimum 13 unique numeric terms to the deleted historical row
requires 42 keys and a real split. The same two live rows, row hole, two groups,
four physical documents, branch assertion, deleted-term statistics and live-term
absence remain checked; expected physical tokens now follow that exact corpus.

Combined primary/structured refill and explicit capacity-refusal provenance are
applied as one reviewed composition: manifest
`b545b413583244ffe8db9e2fb39d6c9d8e4206badb939d130c262a0b00107321`, patch
`843608b8d18f85413b36e79dbfe0b91f372c59c86373d91a3819b63966232449`,
11 files/13 dependencies. Original artifacts are
`ff9fdb0940b45b2d74b0ad8607c8b789c4e4ae3a108316b84c3769c3fa057903`
and `03377db4e93ba1d6784d312dfb29d3b8e268c99472130eed438c40c598f3e378`.
Both cursors and their catalog census precede actual work start; only exact
per-reader refused offers mark this pass incomplete. A typed entered ledger
refusal retains the complete original reader until positive cleanup. Native or
callback ResourceExhausted errors are not classified by public error code.
Output explicitly reports PrimaryAndStructured with text_pending, not whole
database completion. The original same-Core fixture now checks primary entries
plus the actual emitted index-record census. Qualification is pending.

The fixture-visibility correction is applied: manifest
`38ff94c243172980242c34006d4aaf9a3edf4af0ca2923af9f70047e60f9930a`, patch
`16d023bda52d8f9e9b2e7f8226d3923995f59fa65db6d23c99b0a5b7d9f733f9`.
Only the prospective counter type/factory becomes crate-visible. Mutation,
visitation and close stay index-private, with test-only adapters for the
original error-identity check.

The RSS callback ownership repair is applied: manifest
`b616fde29b1641e56ec5bf2bdd9e9b8bc2bb78af9ac6a0999a73ec0e2eeb9fde`, patch
`0c937c513f38566bfa346b81f7bbad4401011d0c1d72e194eda4ad69dd33a96b`.
The sampler publishes RSS and cancellation observations without invoking
arbitrary relief wakers. The existing owned async waits recheck actual levels
on an inline timer, accounted in their concrete future. Unchanged samples do
not become capacity events; final MemoryCore disposal still joins its actual
sampler. Three actual pinned Tokio 1.53.1 timer sources match the recorded
evidence. This does not close the separate byte-relief/checkpoint race.

`c04-isolated-text-private-refill-sampler-v1` finishes **55/55 passed**, tests
924.68 s, runner 973.04 s, exit 0, **1,807/1,807** unchanged. This includes the
expanded real-branch history corpus, independent original-stat proof, all four
private-descendant checks, component equivalence, exact original counter error,
primary/structured finite phases and per-source pressure provenance, sampler
ownership, and existing shutdown checks. A one-second qualitative stack sample
during the long history case showed original-stat counter production/native
point writes using CPU; it is not an allocation or performance qualification.
The complete run qualifies these isolated components, not production activation.

The reviewed original journal read/control envelope and same-Cell serial native
consumer are applied next. Envelope manifest
`07d8dfba13e5d33904bcf54f9c468eadc26ef36f47db67978896feb7970e1619`, patch
`57cc2ed31c86cae88137475cd90b7a6b3af5c2cf74bb4b8b308406762dbe6497`;
consumer manifest `9f95fd3bcd8b92d034e636fe221a7cb4987de56c38a443aef215856a759ae589`,
patch `84288cb29963397adbc056821543dec7e89143594ddb0405fff841538193888a`.
Actual file/range controls debit the original prospective envelope, never a new
provider reservation under source serialization. Native parsed readers, raw
handle Weak aliases and OwnedBytes tails must positively join before releasing
the original private-source child; serial rebind uses the same prepared backing.
Caller-supplied parsed/read allowances are still subject to native allocation
qualification. The 1 MiB helper allowance is only for explicitly small existing
test fixtures, not a production default or accepted-input cap.

`c04-isolated-text-journal-private-v1` stops before tests with one fixture type
error: OwnedBytes requires `Range<usize>` rather than `RangeFull`. Runner
19.09 s, exit 101, **1,809/1,809** stable. The exact full-range spelling is
corrected to `0..bytes.len()`; manifest
`cb07f232984f3fadb7f40d15895da323e89e9c4d0056d685e9b1be4cd47e31b9`, patch
`f51aaec5d8569a85e401b44b9f3b63f39033309575abc8b0fe55f2b5de333e9f`.
The unchanged assertions run in `c04-isolated-text-journal-private-v2`: **12/12
passed**, tests 198.52 s, runner 232.77 s, exit 0, **1,809/1,809** stable.
Actual prepared-current native reads reuse the same source and original
reservation; raw Weak and OwnedBytes tails prevent premature refresh/release.
The original one-byte refusal retains its exact diagnostic and closes safely.
This is ownership qualification, not a universal native parsed-memory bound.

Selected disk-backed ordered seek is reviewed and applied: manifest
`1cbb45da72da7cda1bd587a55a62619c4fa946e3a8424836c8d11c7e13e02591`, patch
`e4038516316e522d2e604892d41f06d99c14e150e5bf7218fa5630244d1f6786`,
11 files/17 exact dependencies. Closed normalized bounds retain the shared
request validation; forward/reverse descent uses the same selected catalog.
The complete stored tuple is authenticated before its body-key fingerprint
comparison, including long keys and virtual prefix endpoints. Limit+1 lookahead
does not hydrate the extra document. It adds no persistent cursor or native pin
and does not consult resident memberships. Existing service output/decimal
allocation qualification is not broadened by the added fixed plan allowance.
Full Query and actual encrypted Engine qualification follow on frozen source.

`c04-isolated-selected-ordered-query-v1` passes **113/113** Query tests, tests
3.91 s, runner 8.25 s, exit 0, **41/41** Query source/config pins unchanged.
This includes all earlier query cases plus the independent scalar tuple oracle
and selected pagination/error parity. The entire isolated checkout stayed
frozen; the runner's Query manifest has narrower coverage than the following
Engine manifest, so this is not reported as an 1,812-file pin result.
`c04-isolated-selected-ordered-engine-v1` starts with **1,812** frozen pins for
actual encrypted ordered/catalog/query checks.

`c04-isolated-selected-ordered-engine-v1` stops before tests with five compiler
errors from one fixture's explicit anyhow return forcing the wrong async result
type. Runner 36.28 s, exit 101, **1,812/1,812** unchanged. The original unexpected
source-failure diagnostic is converted through existing TestError::From; manifest
`66fac119bdd96064c38608735709af18b4b980cc0c4defebe94d3ca3464897cb`, patch
`f1de2bb25c6f1845eef83971d27f637c97203a5ef810a22006b6defb55a05b24`.
`c04-isolated-selected-ordered-engine-v2` passes **11/11**, tests 12.21 s, runner
74.87 s, exit 0, **1,812/1,812** unchanged. Actual encrypted selected pagination
and its catalog/query regressions pass; resident production routing remains open.

Independent accepted-row/native-component and complete LiveTerms verification
is reviewed and applied: manifest
`c38d52d93929a3854b634364e1ea9f386bbb7cb0b95baa590dba75730a3e706f`, patch
`2916add9769eae6156c96a198abff261390873f6d9dcfc959e2cde5ee8188e8e`,
6 files/12 exact dependencies. It reconstructs each accepted row through the
shared native kernel, verifies exact term sets, frequencies, positions, norms
and IDs, then checks each LiveTerms edge and the complete row/term census.
Original physical graph/statistics and source identity stay retained for final
replay. The result grants no publication authority or pending-text clearance.
Native writer/parser and scratch transaction allocation admission remains open.

Root review found that proof failure retirement could hold its owner mutex while
reservation release invokes a reentrant relief callback. The applied successor
uses a nonblocking close entrance: busy returns no positive completion and
retains the exact original owner. Manifest
`a799fa2832c6a95adbcd0dbbd24c7fc3a3f855006ebce08bc898964cb2b95b0d`, patch
`d3f3273bb668d2c4ada0b79831d62477c9000150807a2b742036ed29fbefecb3`.
The actual invalid-LiveTerms fixture now registers a real memory-relief callback
holding the same original error and reenters close during retirement. Its
outer close must complete, the nested close must refuse positive completion,
and a later repeated close must succeed. Qualification starts in
`c04-isolated-text-baseline-components-v1` on **1,814** frozen pins.

A local recovery checkpoint preserves the current isolated source outside `/tmp`:
`target/disk-backed-cache/source-checkpoints/component-proof-1814-v1/`.
The 6,414,084-byte source archive has SHA-256
`ae325bb8580fcca2e6c6d2db8493cfb0bdf1f84e2e933ba2b04a7003d8a480f1`.
All **1,814/1,814** manifest entries were checked in the archive without
extracting or changing the active source. The pin manifest and exact four
apply/compose/check helpers are saved with it. This recovery copy is ignored
build-lane storage, not a live-source promotion or final qualification result.

`c04-isolated-text-baseline-components-v1` passes **2/2**, tests 875.40 s,
runner 911.81 s, exit 0, **1,814/1,814** unchanged. This qualifies the actual
accepted-row component/LiveTerms proof and original invalid-edge failure through
reentrant cleanup. It does not clear pending text or grant publication authority.

After that run was reaped, retained-reader continuation was applied: manifest
`e329d13868fede290bc21e1554a5a1030cb10bab281080d90fefd93ba58f210d`, patch
`8dac3f9f8e4fadc15811d7ae317209305024203fc56b47f28d9d8b16bb1f39b4`,
eight files/seven exact dependencies. Only the source's private receiver can
restore its original reader; it preserves the peak grant and first diagnostic.
A reviewed guard requires both manifest and reader before classifying a retained
pause as resumable: manifest
`ca3f2919003f735507fc28bb8fc0bbd3e85df6422593ebd68e3295dbf6e48d7f`, patch
`dec760a9896481cc902237c78c9b27ab8418ce3314013b26e967a5a066d0da1b`.
The same attempt's actual ledger headroom is captured before optional refusal.
This reader component alone does not qualify the worker/session wait protocol.

The staged text cursor was independently reviewed and applied: manifest
`605d1300bc5f05a0dfdab73ec7586b8c8dcd11dbd37e2ea06a2bb1d31625778f`, patch
`306925304f311b1665a379219ae3d63ed9ef3b1afec61d6dd0d85ebab8e91f9d`,
three files/four exact dependencies. It uses the original bounded point workspace
and a complete fixed text tuple, so subsequent COW deletion cannot invalidate a
continuation by releasing its old key object. It introduces no publication
capability. Three retained-refill and two text-cursor fixtures start together in
`c04-isolated-retained-refill-text-cursor-v1` on **1,816** frozen pins.

`c04-isolated-retained-refill-text-cursor-v1` passes **5/5**, tests 321.05 s,
runner 376.02 s, exit 0, **1,816/1,816** unchanged. This covers original-source
pressure/resume and cancellation, exact original funding diagnostics, and actual
text leaf crossing with released COW continuations and root collapse.

The next reviewed cohort joins retained worker steps, declaration-only metadata,
bounded ID headers, real logical-group retirement and baseline close reentry.
Composition manifest `b466b326ca1fa2bf5325216ed62f4617477d1f50ddd4664d4df7661c7d9ef79e`,
patch `f6dcb85f1cdb836a625d34130c022e329e4e5c47a376a02f7fb9145dbc9b2f56`,
19 files/29 dependencies. The known append-only reader-test predecessor is
explicitly recorded by the composer; no assertions are discarded. Inputs:

- Retained steps: manifest `41cab48aa48168ecfa019ea03ed4b0b24c0c937456a5a4164a1997b72a3657b6`,
  patch `8d09d98270cddcae7a704e8cc1df82b5a14d83801e58d4a11646dcf7794fcd0d`.
- Exact operation grant becomes Resident after both censuses own the work:
  manifest `47cc2f96963e0a25c4425b87f15779940f63ee9bbf5be3bc8b2f2a50c9bb0a58`,
  patch `b1dfc49b4e52af934510d6ab5499adf8146a2c38b3480aa70285dcd1e9573b3d`.
  All bytes remain charged; a paused refill must not occupy an operation slot.
- Selected metadata and bounded ID pages: manifest
  `606bb45367f611c46962146e35edf34377a525c11d945e6311fdb0184c4dd2ff`,
  patch `e715b577128be7730c83170e47c0cd2a725379be176b6c35c1db8a6b904f16ce`.
  Original accepted validator/generation custody remains; there is no installer
  or claim that resident generation memory has been released. Saved and current
  imbl 7.0.1 map source match `7cc646cbd17c88d3c25e7ca93d746e4d3c441ab9e4513e607089e9bd8ce3c76e`.
- Logical group retirement: manifest
  `2090ac82499516e4ea9f4c041b07a4fe7f00e26b8c3d5a112f779efff705f089`,
  patch `5c5380a32eb6233ea449cf6c45857e7289a76d1fab2ac1ae99a8022c259d8bcc`.
  Mixed groups retain physical statistics; empty groups subtract their original
  counts and remove deleted-only terms through actual bounded point COW.
- Baseline close reentry: manifest
  `2f10c10c9b42392beb7384b3842b7616f02c075b94c581dc9af33f5f13465a4a`,
  patch `3e1aba78419c2a4704b6e0eb4bc1e7afcd8a2b6eab5bfc7904e68de86ad45c8c`.
  Busy and absent failures have distinct internal outcomes; nested successful
  cleanup cannot turn an unfinished original baseline into a positive close.

Full Query qualification starts as `c04-isolated-selected-metadata-query-v1`
with all **1,823** Engine-scope source/config pins. Focused actual Engine checks
follow only after that run is reaped. No production activation is claimed.

`c04-isolated-selected-metadata-query-v1` stops before tests with three inference
errors from two fixture ID `.into()` expressions collected into imbl maps.
Runner 2.06 s, exit 101, **1,823/1,823** stable. Exact String construction uses
`.to_owned()`; manifest `48d53f44b396b92c33fb1bb38a373afb7e036ab88cb927aa5f982184eb6a2daa`,
patch `5d89a84920d8ec304c422759583b8d8efa6a1343af503ee060be501efeb51ad4`.
The unchanged suite passes in `c04-isolated-selected-metadata-query-v2`:
**116/116**, tests 3.94 s, runner 7.41 s, exit 0, **1,823/1,823** stable.

`c04-isolated-retained-metadata-groups-v1` then stops before Engine tests with
one fixture usize/u64 mismatch. Runner 40.00 s, exit 101, **1,823/1,823** stable.
The bounded PAGE_CAPACITY term ordinal is converted with `u64::try_from`:
manifest `3d475bca1b574aba629528b58c396746806aa6710a1e48e322929d855bc59ca0`,
patch `571d04d2d7d260a974d3cb29009f556cb5857fc27ea0040cba078553d37bb40c`.

Root independently repaired analogous freeze/import/full-build failure cleanup:
manifest `800f54c06a413c8ac11976f6a7a81bc268eb5e4126bfd8935b53025bb7c818e9`,
patch `6d7476d37f14306d2b63b000373df942f7a48b454c8661c40041b67b6ff001d1`,
five files/three dependencies. Each original mutex uses nonblocking close;
internal absent/unfinished/complete outcomes stay distinct through aggregation.
The original native close remains unchanged and must positively return. Three
existing entered-failure fixtures now attach actual MemoryCore relief callbacks
which reenter the aggregate close, require unfinished while busy, preserve the
original root-cause address, and allow outer/repeated close to complete. Existing
failure, custody, partial inventory and original credit assertions remain.
`c04-isolated-retained-metadata-groups-v2` starts all 12 focused checks on the
same **1,823** source/config path set, frozen through process reaping.

`c04-isolated-retained-metadata-groups-v2` passes **12/12**, tests 749.84 s,
runner 797.74 s, exit 0, **1,823/1,823** stable. This includes all three actual
retained-step checks, selected metadata/ID pages, full mixed/empty group
retirement and reentrant failure cleanup. The long group fixture completed
without changing its workload or assertions.

The next reviewed composition is manifest
`cfe96ba4743ef32815fae2b1e753eca919d66f9835c22d3d0a7a56188d52b55c`, patch
`36163368b7e4aa19013ed23c6107d535f8b1b8cb05be51b3c930f878813d97b8`,
nine files/13 dependencies. It joins:

- Parent-owned refill child: manifest
  `b984089d6fe8d759153b3cbf7c73462e1631ad390c6f12ca29eba65de9d8b35f`, patch
  `06175d28a692e78e213bc3e72f4336421655140d27ebea17890669d6414658eb`.
  One inline local child uses its actual parent's global census entry, preserves
  unique identities and original diagnostic custody, and consumes no ordinary
  operation slot. Complete Session integration remains pending.
- Parent visitor unlock: manifest
  `073e670ed9b8003bfcae532d8d796da5d32241a357efb9df75ef26ade1456ceb`, patch
  `b5c9ed1f48faf32be4a4c71158ef611b20f179a4a6744be775da8877fa89c1ee`.
  Nested report dispatch occurs after both parent guards leave, preserving the
  original report. An actual deferred child callback reenters the parent.
- Explicit resident merge rounds: manifest
  `3f4b30be1930f85e3c8d843787a52fe30da7e470286810956967171417ee3c17`, patch
  `23c186f9228b39ab394d76cf550e30b4a0d24baffd3ee3dff7c50cbe3747ddad`.
  Mutation disables automatic merging; complete committed rounds repeat until
  no candidates remain. A real 160,000-row/15-segment fixture executes two
  rounds, then zero, verifies every current row and keeps the old searcher.
  Five pinned native source files and their exact hashes are saved in the
  artifact's external dependency manifest, SHA-256
  `78554bf0c736f3d7770f08d60b9389a45bdb6c81046418baea01043127acc06e`.
  This explicitly refines scheduling and proves no native allocation bound.
- Original spool reuse: manifest
  `8829316937d96ea5ccd5bea0df8badd9f94a37649ced5ba9e68ed77787afb75a`, patch
  `f197a9d4d61fd88f47ff8f049b15c07e8b13d4b53e4c5de2adcf01fcbb939d9a`.
  Only a fully replayed, uniquely joined spool can reset. It retains its exact
  native owner, file identity and credit; old physical tails are excluded by
  the authenticated logical stream. Inner native admission remains M03 work.

`c04-isolated-text-merge-rounds-query-v1` passes **117/117**, tests 4.00 s,
runner 8.43 s, exit 0, **1,824/1,824** stable.

The bounded merge/chunk composition is manifest
`047eb9f9834b9a97ecb61d3925b7a3390ffde9884569da7d4f1c9e8b4f2dc2f0`, patch
`62d5a5dd06f643a913b7cef12111783715729ac2fc1be30a574031e149ecd166`,
five files/ten dependencies. The first composition attempt correctly refused
the newly changed merge-policy dependency. The accepted composition explicitly
names the reviewed resident-round predecessor; it bypasses no pin checks.

- Merge coordinator: manifest
  `a023088e74c5ee0659ed223091dbb7f66c839382fe41ae8b0c1921542eccf239`, patch
  `b6b14c50eee4b4bef950bd70b83d5b6d0342aaec7dc4fe87ef6d2beaf7f78ee0`.
  Temporary encrypted plans use the original attempt inventory. Every round
  captures actual one-row component statistics, joins its reader before primary
  mutation, removes old contributions before replay, moves exact memberships,
  and drains every temporary object. The policy derives a fixed 14-layer bound.
  No sparse carry, graph/publication authority or native peak bound is granted.
- Real multi-chunk spool fixture: manifest
  `8af8ef0a076cbf43623e3b1ab888225d4979237edc6f9ba21579315ce0bcde38`, patch
  `d8c3ff09ce1b34ce57284afb782b37dcee6bbff2aff600b2f21d5ca6a100ddfe`.
  Thousands of actual deleted-only terms cross at least four 64 KiB native
  chunks. The same 2/1/0/2 round assertions require zero records for the empty
  stream, then successful longer replay with unchanged file/owner/key inventory.

`c04-isolated-parent-child-spool-merge-v1` starts the focused Engine selection
on **1,825** source/config pins, frozen through reaping.

That first run stops before tests with two visibility/name-resolution errors:
the parent scope cannot call its child's private completion method, and the
new merge fixture omits the existing graph type's module qualifier. Runner
43.86 s, exit 101, **1,825/1,825** stable. The exact two-line correction has
manifest `169fe2669c197e337645787c984e5241af29a8b5365ead6b2fa5be8a2cbcc9b8`,
patch `7d6ae1cb190c4c479c38dc80bbfff041fcc5a0518deedef8afb829a67fc124ec`;
the child method is visible only to its parent module.

A reviewed typed-cancellation correction also applies before the rerun:
manifest `f92cf199bdfcb955e4c02e194957a7fd6de8f20696a63bb1ea35a0135bd40f45`,
patch `babe54de83c7dc98e263893b649d5c5f6562133abb2769023b06c19005edbfe6`.
Cancellation and ledger refusal can share the public ResourceExhausted code;
the known cancellation call now retains its original Error as a Plan failure,
so the Session will retry only actual typed admission refusal. Its new fixture
checks the original grant identity/bytes and that source preparation never ran.
`c04-isolated-parent-child-spool-merge-v2` starts the same selection, plus that
new cancellation fixture, on **1,825** frozen pins.

The runner completed with **53 passed / 1 failed**, tests 2,683.22 s, runner
2,816.99 s, exit 101, **1,825/1,825** stable. Its terminal handle had expired on
the next observation; the completed runner log and absence of the exact test
process establish termination. All parent/child, cancellation, original generic
work/census, and real logical merge checks pass, including final graph closure
and released-object census. The multi-chunk spool test fails its unchanged
original-credit assertion: reserved bytes are **139,488,316**, expected
**139,363,708**, a **124,608-byte** excess. This remains a real qualification
failure pending attribution and repair; the exact assertion, chunks, terms,
rounds and configured allowances remain intact.

A newer recovery checkpoint preserves all **1,825/1,825** verified archive pins:
`target/disk-backed-cache/source-checkpoints/parent-child-merge-1825-v1/`.
The 6,361,999-byte archive has SHA-256
`1fb13de5d3994a56b01a38d769a042fd30ef41a0fa511929169d302ca4e93c7e`.
It was created while the run was active and retains that fact in its metadata;
this is a recovery copy only, with no live-source promotion.

Selected lease pages now enter qualification through composition manifest
`8ab7af3b40d2e80a9bd1a032a2f710d53e953e07451ea63eb94d82b28eeac41c`, patch
`9e11fc23f80ec56f55687f1a19d30a34314b44e384d78fcc4e45919fd59289a0`,
six files/17 exact saved dependencies. Inputs:

- Page work/capture: manifest
  `73ceee8dc800a02873cac8f58954c1e35054d8c678dc21dfe4f21c45159da4f4`, patch
  `27d461422df843fd48d0bb03db81229711147890ec63eaea2c6ae2e868514813`.
  The actual prospective SnapshotWork retains its original source, request,
  cancellation, grant and typed failure. Bounded point/scan DTOs and ID headers
  load from the exact selected source. Selected lease backing has immutable
  shared original credit and no resident ID directory; its production installer
  remains withheld pending complete metadata/index/source publication. Archive
  metadata funding is explicit; the fixture installer refuses nonempty archive
  manifests rather than claiming their old resident accounting is sufficient.
  Removal paths move original owners out before releasing credit or invoking
  clocks. Final page validation rechecks expiry, authorization and both entry
  and current-generation identity after callbacks.
- Finite removal and authorization ordering: manifest
  `51e1dd414488c25df9d46d237ae3afdb9ae50874c54d60362fd6c5d02522f7f1`, patch
  `bb30c007afdbee0ced36fd8a7592bc67f641c2277c00a3904e947cd658a07ac7`.
  Clock traversal and credit-release removal are bounded by their initial
  census; callbacks cannot extend either pass indefinitely. Discovery
  authorization still precedes lease-ID lookup, outside the entries mutex.
  Actual clock/relief callbacks replenish leases to exercise these boundaries.

`c04-isolated-selected-lease-pages-v1` starts the new selected lease fixtures
and existing lease retention suite on **1,828** source/config pins. Resident
open/refresh/select is still a production cutover gate, not a fallback design.

`c04-isolated-selected-lease-pages-v1` stops before tests because an existing
resident fixture still reads the relocated `root.ids` field. Runner 90.18 s,
exit 101, **1,828/1,828** stable. The fixture now requires the actual Resident
backing and makes its unchanged 128-ID assertion through that field:
manifest `fc4165ebc231e25a2c7bba6780a944e818c3ad669640733fe90f880ee8f6a3db`,
patch `7627487ebaa65237a28ae88dc3d4dcefc6d25811994de63af8fb89401af410fb`.
No production branch or assertion is changed. The same selection restarts as
`c04-isolated-selected-lease-pages-v2`, with **1,828** frozen pins.

That selection completes **9 passed / 1 failed**, tests 7.77 s, runner 47.32 s,
exit 101, **1,828/1,828** stable. The selected page fixture checks Complete
before claiming its output; the actual SnapshotWork contract intentionally
reports Retained while the output remains owned. The three finite removal/
callback tests and six existing lease tests pass. Preserve this failure until
the correctly ordered fixture demonstrates both successful claim and complete
retirement; do not relax the required Complete result.

The retained parented Session and explicit selected Query mode are composed as
manifest `a703ade24c0d80ad10be0e2b7e53b500e54fb269f704e86a563a5141d7f42cac`,
patch `8ffabdeca1f27cf56c0a3bca9fa3ce30e8df89b91c58fcba2261512a6e173af6`,
11 files/19 dependencies. Inputs:

- Retained Session manifest
  `9a7cc79b908a579cdc1fa1c74b56d6cf62c2beae0819110b1ccdb0715ec7f888`, patch
  `c2fe18c75ec881dbe3ae4a894d3573e0dc0374f159bf8fff7a62694c9211fa36`.
  The canonical worker uses its original parent and one local sequential child.
  Capacity waits retain the actual unentered source/Plan or entered work, its
  grant and cursor. Refusal observations precede the wait and own cleanup;
  shutdown positively retires that same attempt. The generic ordinary-child
  census regression retains its assertions through an explicit fixture route.
  This still reports PrimaryAndStructured, with no native/text completion claim.
- Selected Query mode manifest
  `1e7abdf6360e30440828b4ec1d2bd81c16cd04a4670af618b6d4deaab5201eb7`, patch
  `1f106388227889ebf9b00151d0d45208598922064f9eeea3a6d27f700c7e5655`.
  Prepared selected metadata rejects resident IDs, text snapshots, updates and
  unique-Delta validation before iterating providers. Source binding rejects a
  resident source paired with selected metadata. No installer is enabled.

`c04-isolated-parented-session-query-v1` passes **117/117** Query tests, tests
4.27 s, runner 9.83 s, exit 0, **1,829/1,829** stable. The selected lease's
retained-report diagnostic has manifest
`5fb2c7ac3842c7a8ea104a825f1c38f3bbc8c039ff2f82ded667515c80a30904`, patch
`dfb31b030a239c4568d3fe9262be61089e0ff259736a203f86634c1b3981bfa0`.
It prints original borrowed diagnostics only before the unchanged assertion.
`c04-isolated-parented-session-lease-diagnostic-v1` starts the retained Session,
worker, child and reader-step checks plus that exact lease test on **1,829**
frozen source/config pins.

`c04-isolated-parented-session-lease-diagnostic-v1` completes **30 passed /
1 failed**, tests 19.96 s, runner 92.38 s, exit 101, **1,829/1,829** stable.
All retained Session/worker/child/reader checks pass. The diagnostic confirms
the sole lease failure is its first successful page (`disruption=0`, no
corruption), with no original read, cleanup, panic or join diagnostic.
The fixture checks completion before claiming its still-owned output.

The correction has manifest
`6558d90aaf47e982c5fede547bc9db76bdb562c0ce55e80f2437e358d2498fc3`, patch
`cb2c97ca05562ade4bd9141521da5e8152b3593a52a99dbc7d269f9348ae63d4`.
It moves the unchanged unconditional Complete assertion after the existing
claim and result checks, before census removal. Claim itself requires positive
cleanup; cancellation and original typed failure still require Complete.
No production code, input, budget or result assertion is relaxed.
`c04-isolated-selected-lease-pages-v3` starts the same ten selected/legacy
lease checks on **1,829** frozen pins.

The corrected selection passes **10/10**, tests 6.69 s, runner 18.05 s,
exit 0, **1,829/1,829** stable. All original page, corruption, cancellation,
expiry, replacement and reentrant removal assertions execute. This qualifies
the isolated selected-page operation; metadata installation, archive credit
and production lease cutover remain separate requirements.

The spool's original-credit diagnostic has manifest
`d7f1ae67ce6cf0dceaad20f75aa3ad63171b9e0a6a041d32a818c126de7308d7`, patch
`26454efed054bada166ea49a0d4ffb2e0d7ba661605cdd9c7261469a9f5df963`,
four files/three dependencies. Its test-only observers enumerate actual live
ledger origins without allocating, sampling or reclaiming. It additionally
requires unchanged original spool slot/id/bytes and leaves the aggregate
assertion, real multi-chunk workload and configured capacity unchanged.
`c04-isolated-text-spool-credit-diagnostic-v1` runs that exact fixture on
**1,829** frozen pins.

The latest recovery checkpoint is
`target/disk-backed-cache/source-checkpoints/retained-session-selected-lease-1829-v1/`.
All **1,829/1,829** archived pins verify. The 6,357,565-byte archive has SHA-256
`ee84df0d0967d31e81ab569888c08f2df9f3234ba5cbeee35c0a97fc555d139d`.
Its metadata records the current diagnostic as running and the separate prior
117 Query, 30 refill and ten lease passes. This is recovery custody only,
without live-source promotion or a final qualification claim.

An independent native close observer (`c04-native-close-extent-observer-v1.py`,
SHA-256 `629bf06b01e31eb9da88569908f17337e555cdefd74d41bb7b96a8377e4baec9`)
checks 18 actual macOS file lifecycles at the observed failure EOFs, with
4/8/64 KiB writes and per-write/final fsync. It observes **zero allocation
transitions** between fsync, close and reopen. This does not reproduce or
explain the two Kasumi enrollment mismatches; strict enrollment and its
original synthetic drift refusal remain unchanged. The temporary files are
removed after observation; this is diagnostic evidence only.

The first spool attribution run was deliberately interrupted after recording
the prepared/collected owners: runner 585.70 s, exit 101 (SIGINT of the exact
test process), **1,829/1,829** stable. It is incomplete, not a test result.
It had already localized the 124,608-byte increase to six OtherOrdinary slots;
the original spool slot/id/346,112-byte credit remained unchanged.

Source inspection exposed repeated decryption of the same 64 KiB scratch
chunk for every small record. The bounded replay repair has manifest
`e0e0371844a26948c86f1bd799191bbe9ae80069fada2c6e2acd8c69ae013b89`, patch
`1a92f577f39e9198f67755c40efafaa88f51e272ed2f85d348f18682a3df75e9`.
It buffers one chunk only after positive writer termination. Compile-time size
checks prove the original disjoint Writer/BufWriter quotes cover the buffer
and control; no allowance or grant changes. Consumed position is separate from
prefetch, preserving the complete prefix/hash and final access checks.

Exact slot attribution has manifest
`5fea6639f79b949ed3ec09a74fa7a477369d9496f6b86360daaf2bfbb79878db`, patch
`a22e10fbbdd44576a852510a3aeb0a0b04de052f56156da89ad82816e44d2c22`.
The allocation-free 128-slot fixture census refuses overflow rather than
truncating evidence. Schema streaming preflight has manifest
`776582a2dd58c228f635456f89bb76440fa603e0368e95b8def8778e559b6708`, patch
`ebb6b90b2b8603be6e5199124b0baee01c98c14acd57f8da13672ae7d219f11b`.
It hashes/counts exact serde_json output without first allocating a schema Vec;
the existing 256 KiB limit and hash remain unchanged. It does not fund native
compiled validators or their hidden runtime caches.

These three inputs compose as manifest
`0ced9eca455533f81266e624415304145e25d4044b59562551a8ddfc46235970`, patch
`dabc57f8ff479656310fc6d78fe95929b3903e1448a519b34f3adc901fb8d789`,
four files/11 dependencies. `c04-isolated-buffered-spool-diagnostic-v1`
completes **6 passed / 1 failed**, tests 10.21 s, runner 79.61 s, exit 101,
**1,829/1,829** stable. Corruption, final access, cleanup and reset unwind
checks pass. The original aggregate equality still fails by exactly 124,608.
The actual scratch census grows from three to five files. The six new slots
are four × 24,672 and two × 12,960 bytes; every original slot and the spool's
original credit survive unchanged. This is mandatory native file-owner growth,
not optional cache retention. Its preaccepted-capacity obligation remains open;
classification alone is not a repair. A direct prepared sequential encrypted
spool is being implemented to remove the unnecessary native table/file growth.

The selected native-status and complete Baseline catalog inputs compose as
manifest `0905d2a2f1dff637fd1034440d0a80764e4ab2406d7546f7034805e229d9862a`,
patch `f70e560b16e08ff739369bc69bde69d79dce9196731a40e8377ba0ca467ba264`,
18 files/15 dependencies:

- Native status: manifest
  `7d6d65a6422f364031485ae2180e2c1edef4ff4ad8c84a153225f7ca56c7403c`, patch
  `9a79f3099fe00754403e914d000c50c8c2d71a3081b570a32166c7e412df7468`.
  The original ordinary/protected selected reader checks its actual open native
  pin, domain, governor and access around a fresh status call on the paired node.
  No new snapshot is acquired, and a surviving facade is insufficient.
- All-role Baseline catalog: manifest
  `869e731f6b731c010fb97d9b98351ac8cc8362ea79cc16a318b1a0998f6b65d1`, patch
  `054ad496d5a87f7bc82b80e5577d2c6e36f57335737d4495e38a66a94776bc2a`.
  The actual accepted structured and text owners produce a mandatory catalog
  and Manifest with exact separate intervals and complete live/released census.
  Final-source verification repeats semantic/physical checks. Shared text
  declarations use one canonical owner. The result remains explicitly
  Unverified with no selected/publication conversion while native allocation
  admission is unqualified.

`c04-isolated-schema-stream-preflight-query-v1` starts the complete Query suite
on **1,832** source/config pins. Native and Baseline fixtures follow on this
same source; no production goal is closed by these additions.

The complete Query selection passes **119/119**, tests 3.84 s, runner 6.46 s,
exit 0, **1,832/1,832** stable. The first native/catalog selection fails compilation
on three type/visibility errors before executing tests. Their exact correction
has manifest `142e6cd7e155946faa2238e9cfec8668ae1a1d5c44aa39f6f1e24bd6a4254f33`,
patch `38f01d80be879a781991c71f21b492d1452caa5a8efdc65d9de39c1200316d10`.
The successor `c04-isolated-selected-native-baseline-catalog-v2` compiles in
48.04 s and reports all **five native status checks passed**, then aborts with
a stack overflow in the positive complete Baseline component fixture. Runner
66.99 s, exit 101/SIGABRT, **1,832/1,832** stable. This is not a seven-test pass.

Sanitized relevant crash frames are retained in
`c04-baseline-stack-overflow-frames-v1.json`. The fault is in
`DiskState::create` called through the actual encrypted table/directory producer,
before the new all-role join executes. Disassembly of this exact binary shows
its async component fixture reserving 0x938c0 stack bytes and native creation
reserving a further 0x3db70. This localizes oversized coexisting frames; it does
not qualify the all-role join or justify increasing thread stack or capacity.

The disjoint-frame correction has manifest
`deeb3d20fb363184f6664e5416ce739723967a873c1d90dc16d5cf2307df81be`, patch
`a8b635457262d0f6da9960b683d168260ec5e8c2d7c268ade17fb0affc780719`.
It moves the complete-catalog phase into a non-inlined test helper, preserving
every workload and assertion on the normal thread stack.
`c04-isolated-baseline-disjoint-frames-v1` is running on **1,832** frozen pins;
no outcome is claimed yet. The original two-component selection took 875.40 s.

A second independent native observer checks append, explicit EOF, shrink and
repeated overwrite lifecycles with fsync and the installed SDK's F_FULLFSYNC.
`c04-native-close-extent-observer-v2.py` observes **zero post-sync transitions
in 16 cases** at the two failing EOF sizes. Its script SHA-256 is
`e8ae67ba55d6a92dda81345976610b29e41917b9aebbdba4aa5afa0fe863a7e7`.
This again does not reproduce the actual encrypted owner mismatch and does not
authorize reconciliation or weakening strict enrollment. All temporary files
are removed, and Kasumi policy is unchanged.

The next reviewed, unapplied composition is
`/tmp/kasumi-spool-events-schema-heap-cohort-v1`, manifest
`f0d345f19c505fc9619294c47cf1f0d9e99f7103b83d3b63b0392b0a1b2ab62e`,
patch `d6bc0a233a2d4318b56893d7e5081914da7c1f6cbe9e4ece31b44c5283966fd6`,
263 files/22 dependencies. The current running source remains frozen.

Its direct-spool v2 input (`918d096390f28679f3aca75e6efe919142db01a6c494ccf0b508aa14ef49cd18`)
installs the actual registered setup receipt before constructor entry; public
retirement refuses caller-owned facades without consuming their data. Four
Store tests exercise typed failure, original panic and uncertain close custody.
The unchanged multi-chunk regression now also saturates every ordinary slot
after preparation and requires constant exact original/aggregate credits and
actual file count. The earlier v1 was never applied: its public retirement
could falsely report caller-owned data drained, and a failed constructor could
leave no receipt in the Engine owner. Both findings are preserved here.

Native warmer events (`00795529c320dd50199d36337ba5ce286ee3a7174ccfeaf0a813654969bed295`)
join the original supervisor outcome as well as its checked notification
revision, without stopping or acknowledging it. This covers early dispatch
failure and runtime loss even when no status callback ran. Fixed controls are
in the existing Worker quote; no second task or timer is introduced.

The component evidence heap (`a226c66579f501a2dc70bdaa24ae71c4ceb5b828734620b76fa34d65bf7279e7`)
is explicitly funded in the original prospective component reservation. Its
small owner retains that grant outside the Box until nested backing is freed.
It changes neither semantic proof nor limits and is not a universal stack proof.

The owned schema/probe composition
(`fd573c1af824897fc5c0776d18d6588e419146ae669c9aa2815eae081a95ffe5`)
retains exact published jsonschema/referencing sources and a Weak-only pending
cell diagnostic. Root verified every one of the 188 and 57 upstream source
files against the published .crate checksums, reviewed all eleven code deltas,
and verified all 250 proposed file hashes. The external native test plan
manifest is `97ad0993493b9eac46ca161924941a69ec3eb7b2d4e56de44fa1b3f78b134340`;
its derived test lock still requires real Cargo resolution and exact production
runtime-closure verification. No native tests or memory qualification are
claimed. Source inspection also shows that regex pool capacity bounds stacks,
not caches retained after concurrent use. The production gate therefore needs
a closed serialized owner or a proven concurrency bound; a CPU-count formula
and a cloned Arc are insufficient.
