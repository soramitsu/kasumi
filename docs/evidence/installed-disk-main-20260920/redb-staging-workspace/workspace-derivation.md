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
