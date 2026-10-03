# Bounded reclamation across foreground publications

Status: **proposed and unimplemented**. Updated 2026-09-30.
This is the next reclamation design for the internal disk state, not evidence
that production compaction is ready. Directory density has its separate
[follow-up plan](disk-compaction-followup.md); the broader
[storage design](disk-backed-storage-design.md) and
[cache goals](disk-backed-cache-goals.md) remain open.

## Current restart condition

`Reclamation` in `disk_reclaim.rs` resets on every superblock generation change.
`ReclaimScan::matches` in `reclaim.rs` also requires the original generation and
exact `DirectoryCommit`. This is safe, but repeated foreground commits, or even
allocation publications preserving the selected directory, can prevent a bounded
scan from finishing. Existing current-reader churn coverage does not demonstrate
progress under intervening writes.

The current `SnapshotPins::validate_coverage` accepts captured roots and the
scanned current root. Merely substituting the newest current root would miss
pins acquired at intermediate publications. Merely accepting a greater
generation would not prove that those publications preserved reachability.

## Frozen files and the invariant

Freeze exclusive file-ID limits at the start of a reclamation cycle:

- Segment candidates have IDs below the selected commit's replay-start segment.
- Directory candidates have IDs below the newest confirmed directory arena.

Keep the existing structural exclusions for current appenders, replay anchors,
pending allocation intents and selected root arenas. Future allocation IDs never
regress or get reused. New writes may use the active files at the limits; those
files are excluded from this cycle. Reclamation therefore does not need to force
a roll just to establish its limits.

For each bounded candidate cohort, capture its initial selected root `R0` and
the existing public pins `P`. Let `old(R)` mean the candidate files reachable
from root `R`. Every certified subsequent data publication must satisfy:

```text
old(R_next) is a subset of old(R_previous)
```

Consequently, every selected root and newly acquired snapshot during that
cohort references candidate files only from `old(R0)`. A complete scan of `R0`
and `P` remains conservative despite later writes and pin churn. A file found
reachable may become dead during the scan; keep it until another cohort/cycle.
No live-reference set for all files, keys or versions is needed.

## Smallest bounded state change

Keep one active cohort and the existing maximum of 128 candidate files, reference
bitmap, admitted root capture and one bounded directory walker. Freeze the cycle
limits independently of publication generation, and retain its candidate cursor
until those finite limits are exhausted. Each later cohort captures the then
current root and pins, rather than extending the preceding root history.

Add an owner-local coverage object containing an incarnation-bound cohort nonce,
the fixed limits, the exact initial and latest certified `DirectoryCommit`, and
the latest observed superblock publication identity. Nonces must not wrap or be
reused within an owner. This object is volatile and opaque: generation numbers
or a caller-supplied boolean are not a substitute for its publication chain.

Add one fixed coverage-nonce field to each admitted snapshot slot. Account for
that larger fixed registry allocation, the coverage object and any temporary
mutation witness before allocation or effects. Do not allocate a list of roots
for intervening commits. Existing capture capacity remains bounded by the
configured public pin count; internal scan roots consume no public pin slots.

## Certify publications at their construction boundary

The first implementation should certify only the existing normal-write and
leaf-maintenance construction paths. Seed an opaque mutation witness from the
exact selected root and active coverage object. Bind its output root and prepared
batch identity before installation. Check these properties while already
building the private tree, without a second whole-tree traversal:

- Normal puts use locations returned by that prepared batch, in files at or
  above the frozen segment limit. Deletes only remove records; table operations
  introduce no value references. Unchanged records and subtrees come from the
  witness's selected source root or its own private successors.
- Leaf maintenance validates the leaf against that same selected root. It keeps
  untouched row references and logical versions, and substitutes only the exact
  prepared destinations at or above the segment limit.
- Every newly appended directory page belongs to an arena at or above the
  directory limit. Existing child references come from the validated source
  paths. Splits, ancestor copying and root collapse preserve that provenance.
- A future density primitive needs its own equivalent witness over both
  validated source paths. Its ability to accept arbitrary page references must
  not implicitly authorize a coverage update.

Every serialized root publication must pass through the coverage owner.
Allocation reserve/confirm, garbage-record and forget transitions advance its
publication identity only while preserving the exact selected commit and
monotonic allocation state. A data installation consumes the witness matching
its exact previous and next roots. Advance coverage only after durable
publication succeeds, before another snapshot can be acquired. A failure with
unknown effects fences the owner; reopen establishes a new identity.

A missing witness, predecessor mismatch or unrecognized publication invalidates
the cohort. It must not silently renew an old proof with a new generation.
Arbitrary old-root installation, physical-location import or rollback is outside
this certificate: invalidating GC does not make resurrection of already deleted
files safe. Such operations require their own safe storage protocol before they
can be allowed at all.

## Cover intermediate pins without retaining their roots

Under the same outer owner lock that serializes publication, capture the existing
pins and activate coverage for `R0`. The pin registry tracks the exact current
root covered by that nonce. A new acquisition receives the nonce only when its
root exactly matches that registered current root; advancing this root requires
the certified publication path above. Clones retain their slot and nonce.

At proof sealing and before each unlink, each live slot must either match a root
in the captured set or carry this still-valid cohort nonce. Thus a pin acquired
at `R1`, followed by publications of `R2` and `R3`, stays covered by the scan of
`R0` even while its root is neither current nor explicitly captured. New pins
cannot obtain coverage by presenting only a generation in a numeric range.

On the next cohort, existing pins with a previous nonce are captured normally;
their old stamp conveys no new authority. Pin retirement can leave a conservative
extra scanned root and never restarts the active scan. Retain the capture and
coverage object through the complete authorized garbage drain.

## Protect scan sources and preserve exact retirement checks

Root copies alone do not retain their files. The single reclamation authority
must own the scan capture until the cohort ends and prevent any other unlink
path from bypassing it. Drain previously recorded garbage before starting a new
candidate cohort. During collection and walking, permit no concurrent garbage
drain; foreground construction and evacuation may append immutable data only.
After walking, only this cohort's proved-unreferenced candidates may be unlinked.
They are absent from every scan source, so those sources remain readable even
if all corresponding public pins retired earlier. A future second reclamation
authority would need explicit internal retention rather than this exclusivity.

Keep `Superblock::retire_directory_files`'s exact publication and commit checks.
After completing all captured walks, recheck the gap-free coverage object and
live pin slots under the owner lock. Only the reclamation module can then derive
`ReachabilityProof` values bound to the actual current commit and publication.
This is a proof consequence, not a general stale-proof rebinding API.

Publish the existing durable garbage list, then carry the same coverage authority
across foreground publications while unlinking and forgetting one file per
bounded unit. Recheck structural retirement guards against the current root.
Preserve mirror validation, unlink synchronization, cache pruning and confirmed
forget semantics. If coverage is lost after garbage publication, stop unlinking
and re-prove the recorded list; never remove durable intent without unlink proof.

## Recovery, progress and limits

Coverage nonces and mutation witnesses do not survive close or crash. Reopen
retains the current exact-root, bounded-memory revalidation of recorded garbage
before any unlink. Do not serialize a trusted reachability certificate or change
the segment/root format for this volatile continuation design. If implementation
later needs an on-disk change, specify the direct first-release replacement;
there is no legacy reader or dual-format fallback to add here.

A cycle can finish under continual certified writes because its candidate ID
range, initial tree per cohort and captured pin set are finite. Each scheduled
step advances an existing probe/walker/drain cursor rather than restarting on a
publication. Interleave a bounded reclamation budget with foreground or
compaction batches; the guarantee still requires that those steps get scheduled.
Newly allocated files enter a later cycle. Report cycle completion separately
from an assertion that no garbage remains, which continual writes cannot ensure.

Old snapshots may legitimately retain files indefinitely. Files reachable at a
cohort's initial capture can also survive that cohort after becoming dead.
These are retention and conservative-proof limits, not scan starvation. Record
cycle/cohort IDs, examined limits, work, completed cohorts, invalidation reasons,
reclaimed files/bytes and snapshot-retained bytes. Bounded memory and progress do
not alone establish bounded temporary disk use or sufficient reclamation rate.

## Required evidence before replacing the current checks

- Alternate a one-unit scan step with a successful foreground write over a tree
  requiring many steps and more than one candidate cohort. Prove finite cycle
  completion, retained cursor progress and actual old-file reclamation.
- Pin several intermediate roots, advance repeatedly, retire and clone pins,
  and fill all public pin slots. Verify every live snapshot remains readable and
  GC needs no extra public slot or growing publication history.
- Retire all captured public pins while the walker is partway through their
  roots. Verify internal source protection through completion and garbage drain.
- Exercise allocation-only publications, aborted preparations and foreground
  writes between garbage publication, unlink and forget. Include mutations on
  both sides of compaction cursors and logical-version-preserving relocation.
- Reject missing/foreign witnesses, a skipped predecessor, wrong cutoff, an old
  physical destination, mismatched pin provenance, nonce overflow and stale-owner
  proofs. A checksum-valid generation increase is not sufficient coverage.
- Inject admission denial and before/after faults at coverage setup, preparation,
  page sync, commit, root publication, garbage publication, unlink and forget.
  Verify exact-prefix abort, fencing, retry cursors, durable evidence and lease
  release. Reopen must reject recorded garbage reaching any child page or value.
- Run with fitting and pressured caches. Scans must retain fixed admitted state,
  leave useful hot data resident when it fits, and avoid admitting cold scan
  traffic under pressure. Measure temporary disk growth separately from memory.
