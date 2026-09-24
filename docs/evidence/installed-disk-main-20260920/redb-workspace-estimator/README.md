# Pinned redb workspace components and next implementation boundary

Status: checked component source and native component evidence; **not a complete
redb pre-admission estimator**. No actual Rust source or Cargo build was changed
or run by this package. Root separately applied the earlier LRU repair.

## Frozen inputs and evidence

The host is aarch64-apple-darwin, rustc 1.97.1, commit
8bab26f4f68e0e26f0bb7960be334d5b520ea452. Exact immutable Rust sources are saved
under rust-source with URL/hash manifests. The std lockfile pins hashbrown
0.17.1; the downloaded crate matches its SHA256
ed5909b6e89a2db4456e54cd5f673791d7eca6732202bbf2a9cc504fe2f9b84a.
Native source includes exact field declarations extracted from current redb
private types (provenance in layout-extraction.json). It does not substitute
serialized sizes for actual field layouts.

Six native tests pass in both debug and optimized builds: checked overflow,
Vec/VecDeque growth, HashMap churn, BTree node/split layout, Arc alignment and
Weak lifetime, and actual private-layout/allocator component reporting. Four
process groups exited normally within their explicit 60-second limits and were
confirmed drained. All 52 vendor Rust source hashes remained identical during
the run. Full commands, input hashes, logs and process receipts are in
native-receipt.json. This is not a vendor test, transaction execution, worst-case
redb peak observation, allocator-footprint proof, or RSS qualification.

## Implementable checked component source

native/geometry.rs implements fallible checked requested-allocation geometry:

* Vec/VecDeque: every capacity/reserve request must be bounded by n (not merely
  len). Pinned RawVec doubles prior capacity, honors the requested minimum, and
  has initial minima 8/4/1 by element size. max(2n,min) covers retained capacity;
  counting two such allocations covers realloc coexistence.
* HashMap/HashSet: deleted-bucket churn can resize while entries exceed only half
  of usable capacity. Therefore the capacity input is 2n, not n. The source's
  7/8 load, power-of-two buckets, control-group bytes and alignment are explicit.
  Group width is8 for this aarch64 NEON target (16 for x86 SSE2). Keys, values,
  AtomicBool and Option layouts use real types. Count old+new tables during
  resize; clear does not remove retained capacity.
* Arc: extend the two-usize counter header by the real payload Layout and pad
  to its alignment. The aligned payload test also proves the allocation remains
  after strong0 while a Weak exists; charge lifetime must cover that tail.
* BTree nodes: pinned B=6 means11 keys/values and12 internal pointers. The helper
  bounds all repr(Rust) padding instead of assuming field order. Nodes are
  bounded by live entries plus insertion split ancestors/root; string/value
  backing must be charged separately.

Heap returns both requested bytes and allocation count. `charge(allowance)` is
checked, but the caller must supply an explicitly qualified allocator allowance.
The engine's existing4096-per-allocation policy can be shown separately; it is
not evidence that libc/platform metadata or RSS has a universal4096-byte bound.

native/allocator.rs uses those geometry helpers and actual BtreeBitmap,
U64GroupedBitmap and BuddyAllocator layouts. It counts growing bitmap vectors,
all live region allocators, the region tracker, the full prepared allocator copy,
serialized level images, serialized bitmap images and headers, the final buddy
image, region-length inventory and zero-filled allocator-table input. It includes
mutually exclusive reserve/save temporary maxima together conservatively.

| Original policy | redb extent D | Allocator resident requested bytes / blocks | Simultaneous allocator commit bytes / blocks |
|---|---:|---:|---:|
| Custody64MiB state, per table |603,979,776|93,920 /171|435,464 /374|
| Terminal1.5GiB snapshot |12,952,010,752|1,640,112 /369|5,015,104 /770|

At the existing4096 allowance, these allocator components alone are794,336 /
1,967,368 bytes for custody resident/commit, and3,151,536 /8,169,024 for terminal.
These are **not table totals**. Custody has two table owners and potentially two
simultaneously pending transactions. The disk formula stays8*policy+64MiB;
no existing quota, row limit, batch workload or deadline changes.

Native sizes: PageNumber12/alignment4; bitmap24; grouped bitmap32; buddy32;
Allocators48; BtreeHeader48/alignment16; PageImpl40 debug or32 optimized;
cache key/value entries32; (PageNumber,u64)24; checksum child-option64.
On this host a first Mutex lock requested a64-byte native allocation; a first
uncontended RwLock write requested none. Pinned pthread Mutex uses OnceBox, and
Condvar similarly initializes native backing on notification/wait. Sizeof(Mutex)
is not the total allocation, and initialization races need separate treatment.
This is why actual constructor preparation must remain serialized and warmed.

## Why a disk-sized cache estimate is not a practical policy

The earlier LRU fix bounds registration count by live map entries. It does not
shrink historical map/queue capacities. Cache offsets are page-aligned; therefore
at most ceil((ceil(D/4096)+1)/131) distinct offsets can land in a stripe. Applying
the pinned geometry gives the valid but very loose component calculation saved
in disk-universe-components.json:

* Custody per table:40,136,304 requested cache metadata bytes;80,272,608 allowing
  all old/new map/queue realloc overlap simultaneously.
* Terminal:667,817,040 metadata bytes;1,335,634,080 with overlap. Payload, fixed
  owners, debug maps, transaction collections and native locks are still extra.

Neither number should silently become a new memory budget. The useful next slice
is a hard cache-entry capacity with eviction/preflight before growth, derived
from the existing cache policy plus explicitly justified live internal guards.
It bounds retained metadata independently of lifetime traversal of D. It does
not make the8MiB payload setting a hard total-heap bound.

## Restricted profile and mutation owners

The new unpublished writer must expose encoded insert/finish only: one named
`staged` table, one worker, no escaping raw Database/WriteTransaction/Table/
AccessGuard, no concurrent readers, savepoints, callbacks or arbitrary table
names. Ordinary NodeStore and EncryptedTable point APIs are not thereby qualified.
Custody preserves256rows/1MiB submitted encoded bytes and existing64KiB records;
validated names permit256-byte command keys, while audit keys are8bytes.
Terminal preserves its2MiB row ceiling and both67-byte identity/16-byte ordinal
keys plus their actual encoded values. A1MiB ordinary batch target must flush
before a single larger valid row and admit that row with both index operations;
it must not reject a valid2MiB row or call its payload its full memory charge.

Source-based mutation owner inventory that the final estimator must include:

1. Cache Arc payloads, cache map/queue capacities,262 stripe containers,131 write
   stripe Arcs/native mutexes, and a miss allocation before eviction. PageImpl,
   AccessGuard, WritablePage and cached roots can pin payload after eviction.
2. WriteTransaction/RetainedWriteTransaction, transaction guard, user/system
   namespace BTreeMaps and name strings, two PageTrackers, shared free vectors,
  64 aligned uncommitted shard maps/native locks, savepoint-state fixed shell.
3. User and system local_freed vectors coexist with their shared destination.
   process_freed_pages additionally keeps local deferred source while extending
   deferred_reclaim. delete_table collects all pages before freeing them.
   The allocator state table is deleted/recreated on every commit, even for
   insert-only user workloads; DATA/SYSTEM_FREED extraction is also mandatory.
4. Insert descent keeps ancestor pages; branch splitting keeps the inserted
   leaf guard and new siblings. finalize_dirty_checksums recursively holds a
   writable ancestor and a Vec<Option<(usize,PageNumber,Checksum)>> at each level.
   PagePath visitation clones path vectors down recursion (sum of depths, not
   one path). MAX_BTREE_DEPTH128 bounds checked traversal paths, but the new
   writer must prove generated insert/checksum paths preserve that invariant.
5. System extraction's leaf-run rewrite holds at most one parent's child run,
   ending on a non-packing large leaf. OwnedEntryBuffer has data+range deque,
   temporary retained ranges, builder slice entries, replacement planning ranges,
   split-key Vecs and removed-leaf page lists. Branch fanout includes checksums
   and page IDs; use actual encoded header/keys, never just4096/key length.
6. Full allocator copy/serialization above; debug allocated_pages scales with
   D, while read reference and open-dirty maps retain peak capacities. Debug
   coefficients must not disappear from native gates by switching profile.
7. Store Owner/Backend/NodeDatabase and Spool buffers65,536+65,576, original-key
   owner, lease wrappers, worker/task/census/report ownership. Upstream Row/
   Receipt parsing, cloning and JSON encoding need their own structural bounds.
   Arbitrary user callback captures, custom errors and panic payloads are not
   bounded by encoded row bytes and cannot be hidden in a fixed constant.

## Concrete pre-admission API/order to implement next

First close cache entry cardinality with an actual before-allocation error path.
Then retain a small nonallocating commit census: actual user/system freed-page
counts, pending reclaim count, current extent/region count, cache high-water
classes, and table generation. A batch preflight under the private writer gate
can combine current admitted state with the checked worst-case path/split count
for at most256 rows and the exact encoded input. It must reserve transaction
workspace before creating the transaction or encoding extra owned input; validate
that the generation did not change, and keep the lease through actual retained
commit/abort destruction. Read-only preparation uses the already admitted
resident cache; it must not allocate an uncharged Vec to calculate the bound.

This avoids budgeting N entries in every transaction vector when actual pending
reclaim derives only from the preceding private commit. It is a proposed census,
not an existing proof: system free-list feedback, allocator-snapshot retry and
path/split maxima still need exact source-derived cardinality bounds or checked
collection caps before pushes/reserves. Any denied cap must preserve the private
builder's failed state and original typed terminal/abort custody; no partial
Records exposure, post-admission, silent truncation or fence weakening.

Proposed final envelope, once those terms are qualified, is:

  resident table = fixed real owners + spool + bounded cache metadata/payload
    + allocator resident/growth + persistent debug maps + owner/lease census
  transaction = concrete transaction owners + bounded page sets/free vectors
    + mutation and cursor scratch + extra allocator-copy/serialization component
    + bounded caller encoded/decode buffers + typed terminal custody

Charge both simultaneous custody tables/transactions on the exact shared core.
Do not sum component values as a complete estimate while the listed terms remain
unqualified. Admission must check existing total reservations AND current RSS
high-water; even a component below2GiB does not establish a2GiB installation fits.

## Qualification tests required after implementation

Use tiny cache stripes with all entries borrowed: typed denial before allocation,
unchanged counters and no backend call; retry after guard drop; original I/O
failure when eviction writes fail; long invalidate/reinsert cap reuse. Test a
maximum valid2MiB terminal row, all256 custody rows/1MiB encoded batch, duplicate
failure, allocator region expansion/retry, both free-list extraction stages,
and cancellation/panic during retained commit/abort. Assert original output and
all leases survive failed/retained outcomes, and release only after actual Arc,
Box, mutex and page backing destruction. Keep4,200/8,400 and512×256 production
workload coverage and original deadlines. Native layout/allocator observations
validate source coefficients; they do not replace these behavioral gates.
