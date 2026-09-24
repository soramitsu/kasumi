# Bounded LRU registration prerequisite

Target-only correction; actual source remains unchanged. The existing LRU queue
can grow without bound while containing only three live page keys. remove only
rotates two queue entries, leaving old registrations. Reinsertion makes those
old registrations live again. Choose each removed key outside the next two queue
positions: the sweep requeues both still-live keys, while insertion adds one more
registration. Disk extent, live keys, cache payload and batch sizes stay fixed.

The prepared correction removes every registration for the removed key with
VecDeque::retain. It preserves other keys' relative priority and second-chance
flags. Payload accounting, cache counters, write/flush durability and admission
are untouched. This scan is O(queue length) per invalidation, so it trades the
previous approximate cleanup for a bounded, allocation-free metadata invariant.
Insertion/replacement and second-chance eviction maintain one registration per
live key; no compatibility cleanup mode is added.

Authorized isolated native evidence executes the exact old/proposed LRU module
and exact vendored integer hasher with identical tests. Only unused PageNumber
aliases use a stub. No Cargo or actual source compilation occurred.

- Before: 2 pass, 1 fail. After 10,000 remove/reinsert cycles, three live pages
  retain 10,003 queue entries and capacity16,384.
- Proposed: all3 pass. The same sequence retains three entries, capacity4.
- Both runs pass the unchanged live-page eviction/second-chance behavior test.
- The harness's exact removal path allocates zero times through the observed
  native System allocator; all256 populated entries are removed while counted.

Four compiler/test process groups exited normally and were confirmed drained;
60-second per-process deadlines were unused. Exact source hashes, command lines,
logs and rustc version are in native-receipt.json. This is a focused extracted
module result, not a full vendor, publication-boundary or workspace gate. The
vendor patch adds two behavioral tests; the allocator observer remains solely in
the isolated harness to avoid a second global allocator in redb's test binary.
