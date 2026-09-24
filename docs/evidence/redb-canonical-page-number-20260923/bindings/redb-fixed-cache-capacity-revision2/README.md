# Fixed cache entry capacity proposal

Status: target-only, formatted and git-apply checked, NOT compiled or executed.
No actual Rust source or Cargo run changed. Exact before/proposed hashes are in
manifest.json. Parent owns source integration and qualification. The adjacent
redb-workspace-estimator package is independent frozen component evidence.

## Behavior

Each read stripe permits

  R = max(1, ceil(ceil(cache_bytes / page_bytes) / 131))

entries. Each write stripe permits W=R+MAX_BTREE_DEPTH+4. All arithmetic that can
overflow is checked before constructing stripes. These are metadata capacities;
payload still follows the original soft byte target. The original8MiB scratch
cache setting, disk-growth admission, record limits, batch limits and deadlines
are untouched. Default scratch R=16 and W=148. With the pinned native collection
geometry, retained read/write hash/queue layout requests are bounded independently
of the lifetime's visited disk offsets; the much looser ~668MB terminal universe
bound is no longer the relevant cache metadata cardinality.

Read insertion evicts an existing entry first if its stripe is full. Existing
Arc-backed readers remain valid; this bounds cache metadata, not externally
retained page payload. Read promotion from committed write buffers and the
cache-only clean-read test path use the same entry preflight. Byte counters and
cache_metrics evictions follow the actual removed entries.

Write insertion first inspects its stripe before invalidating a cached read,
changing byte counters, allocating a new Arc payload or inserting a map key.
An existing key needs no extra slot. A full stripe with an available buffer
flushes one page; its original I/O error and owner fence remain untouched if the
flush fails. If every slot is borrowed, preflight changes only the transaction's
cache-denial latch and returns inline CacheCapacityDenied. It does not allocate,
change queue priority, alter cached Arc identities, or call the backend. Native
stripe locks are materialized during construction so first denial cannot create
an OS mutex allocation. The test override is cfg(test) only and can only lower
capacity; production cannot select it.

## Selected-page rollback and distinct outcome

CacheCapacityDenied is deliberately distinct from physical CapacityDenied. The
latter retains its no-physical-effect admission meaning. A new-page cache refusal
can happen after the allocator selected a page and performed already-admitted
file growth. The new-page allocation branch undoes exactly that page's buddy
allocation and debug registration under the original state lock. It does not
insert the rejected page in PageTracker or UncommittedPages. The admitted layout
and real file growth stay retained/accounted; actual abort synchronizes and
settles that extent. It does not pretend the filesystem was unchanged or release
physical bytes merely because memory capacity was denied.

The active transaction latch prevents a later successful commit, even if the
caller catches the error or a test resets the entry limit. Fresh allocating
operations reject the latch before allocation; existing in-place operations may
still touch private uncommitted data, which the refused transaction must abort.
Both consuming and retained commit handle the new refusal as preparation failure.
The retained owner keeps original cache refusal and actual rollback failure or
panic separately; it never replays either terminal operation.

Revision 2 is based on actual source after root's positive-settlement disposal
patch 2933c5a6b379bf61146a9a88b01f912f4ec5018d7182346307a341009f6bb434.
The Option transaction and matching RetainedDatabase witness, disposal outcomes,
and transactions.rs final writer-guard field ordering are preserved. The only
production terminal changes remain capacity_error() and rollback classification.
The positive cache test retains the original cache error through explicit
matching dispose_settled(), actual writer reuse, and actual database close.
The consuming API test remains deliberately separate.

## Meaning of depth+4

The named internal workspace covers the128-depth bound plus four pages: insert
can retain the inserted leaf and up to two new split siblings; root/direct-header
preparation needs one additional page. Checksum finalization and in-place descent
hold an ancestor PageMut at each depth plus the leaf, which fits within the same
allowance. These phases do not all coexist, so summing the four slots is
conservative for those concrete paths. This is a selected cache-capacity policy,
NOT a complete audited proof that every generic redb callback or arbitrarily many
concurrent external table guards fits. Such caller-owned guards can exhaust the
capacity and receive the explicit error. The unpublished staging writer still
needs restricted callback/reader/savepoint/guard ownership, a maximum page-payload
bound and an admitted workspace. This patch does not claim total RAM or RSS is
bounded by8MiB or that the complete first-release memory goal is finished.

## Revision 2 selection correction

Revision 1's preflight inferred a slot from a successful flush result even when
that result was zero bytes. The existing borrowed-entry selection could return
None with an available second-chance buffer left in the same stripe. This could
admit a new entry beyond the intended cap.

The write selector now performs at most two full queue passes. An ineligible
borrowed entry rotates without losing/recreating its queue registration or flag.
The first visit clears each eligible entry's second chance, and its next visit
can select it. Thus an eligible entry cannot be hidden by repeated removal and
reinsertion of an ineligible entry. Borrowed pages never become eviction targets.
Preflight independently checks that the stripe length is below its capacity
after flush before returning Ok; a successful zero-byte result cannot authorize
an insertion into a full stripe. Original eviction I/O still propagates first.

A direct LRU regression covers A borrowed/no-second-chance and B available/second-
chance, plus a bounded all-borrowed scan. A real PagedCachedFile regression uses
actual hold/flush/return calls to produce the former bad ordering, then inserts C.
It checks one physical flush, exactly two entries, exact buffered bytes, and all
three payloads. Revision 1 and its manifest remain byte-for-byte unchanged.

## Focused regressions prepared

1. Actual cached-file all-borrowed denial: zero observed allocations, no backend
   writes, unchanged read/write byte counters, unchanged read Arc identity and
   write entry count; dropping the original guard permits one exact eviction
   and replacement.
2. Long same-stripe write/read traversal: every byte round-trips while write
   and read entry caps hold through commit promotion and repeated misses.
3. Failed eviction after the backend wrote bytes: exact original io::Error
   payload survives, write accounting/entry remain, next access sees OwnerFailed,
   and the cause never becomes a capacity refusal.
4. Real Database retained commit after new-page denial following actual admitted
   growth: allocated-page count returns exactly to its preceding value; abort
   settles the actual file, earlier private rows do not publish, original row
   survives and a new transaction can commit.
5. Same retained denial with failed or panicked abort: original terminal-error
   identity, original panic Arc identity and exact transaction/database/file
   custody survive repeat observation. Bounded static fixture custody retains
   the actual failed resources instead of calling Drop cleanup evidence.
6. Consuming commit also refuses the latched cache denial and permits a new
   transaction only after real successful abort.

All eight are unexecuted until the parent's coordinated vendor gate. Required
follow-up: full vendor library/admission/retained terminal tests, relevant store
no-allocation/publication cases, strict lint, and cache profile/workspace peak
qualification. Capacity does not supply a mandatory memory lease by itself.
