# Bounded compaction: leaf batches and directory density

Status: **leaf batching and adjacent-page density implemented and component-tested;
cache reconciliation, reclamation progress and production Core cutover open**.
Updated 2026-09-30. This plan extends the internal maintenance foundation in
[the storage design](disk-backed-storage-design.md); it does not qualify that
foundation for production workloads or close the [cache goals](disk-backed-cache-goals.md).

## Historical per-record checkpoint

The earlier `DiskState::compact_step` relocated one record and rewrote its entire
directory path per commit. That checkpoint established durability, version
preservation, streamed copying and snapshot retention, but was too expensive
for small rows.
For a tree of height `h`, each row appends approximately `h * 16 KiB` of directory
pages, plus its log records and mirrored-root publication. One million rows at
height three can append roughly 48 GiB of directory pages before the final
reclamation phase. Intermediate private/committed paths become garbage, but
garbage collection ran only after the complete key scan. Value-only
`copied_bytes` does not report this cost.

The current leaf batching removes the per-row path and synchronization multiplier.
A separate adjacent-page density phase now follows evacuation, packing leaves
and internal pages before garbage collection. Merely copying sparse pages into
new arenas was insufficient; the new phase redistributes or merges their records.

## Implementation boundaries and remaining work

1. **Read one admitted leaf plan — implemented internally.** The reader returns
   one validated leaf buffer, its immutable reference and bounded ancestor
   path. The plan and relocation descriptors have a hard 512-record ceiling.
   Table/key slices borrow the leaf buffer; only the retained continuation key
   is copied, with its admission reserved before effects. The selected-root
   lock covers preparation and publication. Both segment and directory-arena
   cutoffs are frozen before rotating the appenders.
2. **Prepare a bounded streamed maintenance batch — implemented internally.**
   A batch targets 1 MiB of encoded records and enforces operation-count,
   transaction-byte and value-size limits independently. One oversized record
   may exceed that target, up to `MAX_VALUE_BYTES`. Large-value leaves split
   into subsets. All source records are preflighted before any relocation
   writes, then streamed through 64 KiB windows with their logical batch
   sequences preserved. The operation prefix is synchronized once per batch.
   A page-only batch uses one directory-only marker.
3. **Rewrite the leaf and ancestors once — implemented internally.** A bounded
   destination map replaces physical locations while preserving untouched values,
   table birth sequences and row sequences. The validated leaf and each ancestor
   are copied once per batch, followed by page sync, exact-root commit and root
   publication. An already fresh leaf without old value locations is skipped
   without a maintenance commit. The cursor advances only after publication or
   a verified skip; admission denial leaves the key eligible for retry.
4. **Pack bounded neighboring ranges — implemented internally.** An admitted
   adjacent-page plan feeds one atomic replacement of both paths, including
   pairs across parent boundaries. Leaves and then internal levels are packed
   in separate bounded sweeps. Logical records and old snapshot roots remain
   unchanged. The density checkpoint below covers the internal implementation;
   `DirectoryBuilder` remains
   the comparison for reachable page density, not a whole-tree replacement of
   a newer root from a stale snapshot.

The internal batch encoding uses segment format version 4 and rejects version 3
directly, without a fallback reader, dual writer or migration path. Root-only
replay validates operations, logical versions, byte/count bounds and digests
without retaining decoded keys. Maintenance abort supports the bounded batch
count instead of the historical single-operation cap. The source-pinned
component checkpoint below does not qualify the production compaction contract.

Normal prepared-batch abort also now uses root-only replay bounded by the
prepared operation count. Its admission reserves fixed replay workspace plus
exact returned value-location backing, independently of borrowed payload size.
This replaces full decoded-record replay reservation: a focused check found a
1.8 MiB normal write over-reserving more than a 16 MiB allowance. The correction
is implemented. Abort now verifies the exact synchronized batch, end position,
operation count and digest before discarding bytes, rejecting damaged or
substituted prefixes in the same streamed pass. Native component validation is
recorded in the [leaf-batch checkpoint](evidence/disk-backed-cache-20260930/README.md#leaf-batched-maintenance-and-shared-residency-checkpoint).

## Adjacent-page density implementation — internal

`directory_pack.rs` implements directory-only adjacent-page packing, and
`disk_density.rs` composes it into bounded leaf and internal-level sweeps after
evacuation. The selected-source density checkpoint passes 365 native library
tests, including the added builder comparisons, cursor/root-collapse cases and
failure/admission checks. Its final focused run passes 22 cases. This improves
reachable page density; it does not by itself solve temporary disk growth,
unreachable pages in partly live arenas, periodic GC progress or the production
Core cutover.

### Admitted adjacent-page plan

The reader selects two consecutive pages at the same tree level from the current
selected root while the owner's state lock is held. The plan owns their exact root,
immutable references, two validated input buffers, range bounds and the union
of their two fixed-height paths. Output/scratch buffers, replacement descriptors
and the retained continuation key are admitted before effects. Record keys borrow
the input buffers; no all-key map or page body per ancestor is retained. Two
16 KiB input pages bound the records directly, independently of the single-leaf
relocation operation limit of 512. Mutation adds one input scratch page and one
output page, for four simultaneously charged page buffers plus fixed scratch.

Adjacency is proved from the paths, not merely ordered key ranges. Under one
parent, the child indices are consecutive. Across parents, the paths diverge at
consecutive children of the lowest common ancestor, then follow the rightmost
child on the left path and the leftmost child on the right path down to the
selected level. Exact digests, bounds, levels, generations and subtree counts
are revalidated before appending, excluding omitted intervening subtrees.

Combined records are packed by encoded bytes into one page when they fit,
otherwise two, filling the left page until the next whole record would exceed
capacity. Every leaf key/logical value and internal child reference/subtree count
is preserved. An already packed pair returns a verified no-change result without
publication. A final page without a right neighbor is an explicit terminal plan.
If its root is unary, the plan instead requests a directory-only normalization:
checked child promotion with a new root generation and no page appends. The
continuation still ends the level, and no empty neighbor is fabricated. These
directory-only operations do not relocate values.

### One publication for both paths

Both old page references are replaced or removed in one private root. Divergent
ancestor branches are rebuilt bottom-up with updated minimum-key separators and
subtree counts. Both child-range replacements are applied together at the lowest
common ancestor, then each shared ancestor is copied once. Cross-parent pairs
therefore have one root publication; their paths are not independently published.

Empty ancestors disappear through an empty replacement. Internal levels retain
uniform depth, and unary roots collapse after validation of the promoted child.
Longer replacement separators can split ancestors even when leaf count decreases.
Each divergent single-child replacement has at most two output carries; their
common ancestor and the shared path use fixed arrays of three carries. With page
payload `P` and maximum encoded branch record `M`, the format satisfies `3M <= P`.
Even four incoming carries give at most `P + 4M` parent bytes; after two greedy
outputs, fewer than `6M - P <= P` bytes remain. Three outputs therefore suffice
and the bound remains stable along shared ancestors. Simultaneous carry arrays
and helper copies are admitted before effects.

For tree height `h`, one operation appends at most `2 + 4(h - 1) + 1` pages: up
to two packed outputs, at most four outputs per ancestor depth across both paths,
and one possible new root. This is a structural bound, not measured device I/O.
Path metadata and scratch depend on maximum height and page size, not population.

One version-4 `DirectoryOnly` preparation binds the work. New pages are
synchronized before the matching root commit and exact-root publication. The
existing exact prepared-prefix abort verification, owner failure fencing and
unknown-commit handling apply. Admission denial leaves the continuation unchanged.
Old snapshot roots remain immutable and keep their original physical pages.
Maintenance uses raw bounded source reads and the existing non-evicting,
policy-neutral warming for the newly published pages.

### Bounded sweeps and continuation

Density has its own phase and cursor after evacuation and before reclamation;
the evacuation phase's fresh-arena skip does not skip freshly copied sparse
pages. Level zero packs leaf pairs, followed by bottom-up internal-level sweeps.
Internal sweeps pack child-reference records without rewriting their subtrees,
addressing sparse internal levels as well as leaf counts.

The admitted continuation is an inclusive logical lower bound at the selected
level. A merged one-page result keeps its minimum eligible for the next neighbor.
Two outputs advance to the right output's minimum; an unchanged pair advances to
the original right minimum. A missing right neighbor ends the level. Every next
step reselects the page containing the first remaining leaf key at or above the
bound from the current root; no physical path survives a publication. A removed
level returns no plan, and the sweep checks the current root height as it proceeds.
The cursor advances only after successful publication or a verified skip.

The owner lock covers each preparation through publication, allowing foreground
writes between bounded steps. Density records the expected selected generation
and advances it after its own commits. A different observed generation marks an
unfinished pass dirty. The pass continues from its logical cursor; at the end,
a dirty pass restarts density at level zero while preserving completed evacuation
and its frozen file cutoffs. Only a pass without an intervening foreground
publication sets `density_complete` and proceeds to GC. A foreground publication
after density completes but before the whole compaction finishes resets density
before reclamation resumes. After a fully completed compaction, a later foreground
generation starts a new compaction cycle with new cutoffs.

Reported evacuation completion, density pairs/commits, pass count/restarts and
clean density completion distinguish these states. Continual foreground writes
can keep dirtying passes, so this recurrence does not promise density or GC
completion under continuous writes. The density checkpoint includes composed
generation/retry and fault tests. Periodic GC still requires the separate proof and
scheduling work below; its proposed continuation rule is unimplemented.

### Density coverage and continuing acceptance checks

- Pack sparse neighbors within one parent and across different parents, including
  empty and unary intermediate branches and a lowest common ancestor several
  levels above the pair.
- Use maximum-length and uneven keys, including longer replacement separators
  that force an ancestor split. Verify ordering, subtree counts, logical versions,
  unchanged neighboring subtrees and every retained old root.
- Run mass deletion in trees of height at least three. Compare reachable leaf
  and internal-page counts against streaming `DirectoryBuilder` output, recording
  the chosen packing rule's limits and the separate physical arena overhead.
- Exercise every continuation case above with foreground inserts, updates and
  deletes; test already dense pairs, merged underfull outputs and terminal pages
  for bounded progress without lost or repeatedly skipped ranges.
- Inject admission denial and failures at each append, page sync, preparation,
  commit and root publication. Verify cursor retry, exact abort-prefix handling,
  old-snapshot reads, charged output guards and bounded simultaneous allocation.

## Foreground progress, snapshots and reclamation

The implemented cursor reads each next range from the current selected root.
New inserts behind the cursor and updates to earlier keys are safe because all subsequent allocation
IDs exceed the frozen cutoffs. Never restart the entire evacuation solely because
a foreground commit advances the root. Reads from old snapshots continue to
follow their original roots and retain their exact physical files. Cached old
and new identities must remain hot when their charged memory fits; maintenance
must not admit cold scan data under pressure.

Periodic reclamation progress remains open and the following scheduling/proof
proposal is unimplemented. Reclamation currently follows evacuation and a clean
density pass. Scheduling it between bounded batches or output-arena cohorts could
limit temporary disk growth, but the existing reachability proof is invalidated
by any root publication, so interleaving its scan with continual writes can starve it.
Do not silently weaken that check. Before claiming foreground-compatible GC
progress, prove a cutoff-aware continuation rule: later publications may only
preserve/remove old candidate references or add references above the cutoff.
That proof must also cover pins acquired at intermediate published roots.
Otherwise document and bound the write-quiescent reclamation interval required
by the existing exact-root proof. Unlink still requires a complete proof over
the selected root and relevant pins, followed by the durable garbage protocol.
The [reclamation continuation proposal](disk-reclamation-followup.md) specifies
the bounded publication and intermediate-pin coverage design; it is unimplemented.

Snapshots can intentionally retain old files. Report those retained bytes and
distinguish successful evacuation from files that remain pinned. Admit source
retention, destination growth, fixed work buffers and pending garbage within
their respective budgets before effects. Pinned files must not be credited as
free space or deleted to make room for the destination.

## Metrics and acceptance checks

The current step reports processed entries, copied value bytes, maintenance
commits, verified fresh-leaf skips, evacuation completion, density pairs/commits,
pass counts/restarts, clean density completion and confirmed directory-page
read/write and arena-sync deltas. Page counters include repeated validation and private pages;
they exclude cache hits and arena-header payloads. Arena syncs include header
syncs and rolls, but exclude mirrored-root and namespace syncs. These are
successful backend callback counts, not device bytes: a later owner/digest check
can reject a successful callback, and a failed callback may have unknown partial
effects. Standalone intent recovery is excluded.

The remaining measurement work must cover source bytes read, value bytes written,
directory pages read/written, log/root bytes written, sync counts, live directory
pages, reclaimed files/bytes,
snapshot-retained bytes and peak temporary disk usage. Report copied values
separately from total maintenance I/O. The work unit is a rotation, leaf batch or
verified skip, density plan/pass transition, or reclamation step. The 1 MiB batch target does not bound latency
when one permitted value can be 40 MiB. A strict byte-per-call promise
would additionally require resumable value-copy ownership and cancellation.

Required focused checks before the Core cutover:

- Many small rows in multi-level trees: directory writes and durable publications
  scale with processed leaf batches, not row count. Include maximum-length keys
  and byte-limited batches of large values under a smaller memory allowance.
- Mass deletion and uneven keys: leaf and internal-page counts fall toward a
  densely built reference, with bounded temporary growth and no all-key map.
- Foreground inserts, updates and deletes on both sides of the cursor, including
  between subsets of one leaf; old and current snapshots keep exact versions.
- Faults before/after relocation writes, page sync, log commit, root publication
  and garbage unlink; retryable admission denial skips no key. Replay and abort
  retain fixed admitted workspace even for large streamed maintenance batches.
- Periodic GC and continuous foreground writes: demonstrate progress under the
  chosen proof/scheduling rule, including pins acquired and released mid-scan.
- Fitting hot caches keep old and current versions resident through relocation;
  pressured maintenance scans preserve the useful hot set and all memory charges.

Keep source-pinned workload evidence, failed runs and material limitations. The
earlier passing per-record checkpoint remains historical evidence. Focused leaf-batch checks exposed a normal-write
workspace over-reservation; the correction and strict prepared-prefix checks
are covered by the 343-case native suite. Shared payload ownership also keeps
a 512 KiB relocated value and both snapshot lookups resident under a 700 KiB
cache bound. The source pin, structural workload counts, scoped validation and
retained failed attempts are in the checkpoint above. Its 343 native, 30 integration
and 21 store-boundary passes predate the density implementation and do not validate
the current density source.

The subsequent [35-file density source pin](evidence/disk-backed-cache-20260930/density-selected.sha256)
has [365 passing native library tests](evidence/disk-backed-cache-20260930/density-library.log)
in 222.74 seconds, a [22-case focused run](evidence/disk-backed-cache-20260930/density-focused.log)
in 187.95 seconds, and [30 native integration passes](evidence/disk-backed-cache-20260930/density-integrations.log).
[Strict native all-target Clippy](evidence/disk-backed-cache-20260930/density-clippy.log)
and [package formatting](evidence/disk-backed-cache-20260930/density-format.log)
pass. The [initial Clippy failure](evidence/disk-backed-cache-20260930/density-clippy-initial.log)
is retained; three test-style corrections preceded the passing check. The
1,200-row workload evacuates 4,800 value bytes in seven commits with 14 directory
page writes, then performs six density commits with 15 page writes, reducing
reachable pages from eight to five. These are structural callback measurements,
not device-byte or performance qualification.

The new, separate `disk_residency_tests.rs` regression is not included in that
source pin or its validation. The known C03 gap remains: obsolete cached page
identities inside partly live arenas can prevent full residency of a current
and pinned working set that fits. Bounded page and value reconciliation still
needs implementation and validation. Reachable page packing does not establish
complete arena-space recovery, periodic GC progress under continuous writes,
full cache residency under arbitrary publication churn, or production qualification.
