# kasumi-kv

Kasumi's native Rust key-value engine. It owns its transactional disk format,
ordered directory, snapshots, cache, recovery, and reclamation. It uses no
embedded database library.

## Disk format and commits

One database is a file group under an owned directory. `root.kvroot` contains
two checksummed 4 KiB superblock slots. Create-only files use never-reused
identifiers and deterministic names: `0000000000000001.kvseg` for a value-log
segment and `0000000000000001.kvdir` for a directory arena. The group contract
also recognizes checkpoint files; the current Core rejects roots carrying a
checkpoint reference from the retired storage path.

The current root magic is `KASUMI-KVROOT003`, the segment magic is
`KASUMI-KVSEG0004`, and directory pages use `KASUMI-KVDIR0002` inside
`KASUMI-KVARENA01` arenas. Segment and arena files each have a 64 MiB bound.
Segments have a 64-byte header; arenas have a 4 KiB header followed by immutable
16 KiB directory pages. Page references include their SHA-256 digest. Directory
leaves hold table markers and ordered keys with value locations, lengths,
versions, and checksums. Values remain in log segments rather than a resident
map of the whole database.

`Core::commit(&[Operation])` applies one batch atomically across named tables.
The serialized writer performs these durability steps:

1. Reserve the batch's physical extents, new names, and descriptor rights, and
   acquire mandatory commit/abort workspace before its first effect.
2. Append and synchronize the operation records, then build and synchronize
   the new immutable directory pages.
3. Append and synchronize a directory preparation record, then a batch commit
   carrying the directory root, operation digest, and commit chain.
4. Publish the root to its parity slot and synchronize it, then mirror it to
   the other slot and synchronize again. Settle the physical reservation
   before reporting success.

Operation records may span segments; an individual value never does. Record
checksums bind their group, physical position, batch, and preceding commit.
Segment and arena creation first publishes an allocation intent in the root,
then establishes the file and durable name before confirming it. Identifiers
are never reused after an uncertain effect.

## Recovery and failure outcomes

Opening synchronizes and selects the newest intact root, checks the expected
group incarnation, and repairs an incomplete mirror. It checks the directory
census, resolves allocation intents, validates the root's exact log commit,
and replays any later complete batches. An interrupted uncommitted tail is
discarded only after the replay rules prove it cannot contain a committed
batch. Recovery adopts disk roots without reconstructing every key in memory.

The selected root's initial directory path is checked before opening returns.
Each later descent verifies page digests, and value reads verify their
checksums before returning bytes. Opening is not a full scan of every live
page and value. Detected corruption, uncertain I/O, admission owner failure,
and callback panics fence the exact live Core, including its existing
snapshots. Reopen must determine an uncertain commit's outcome; callers cannot
infer rollback from an error. `CapacityDenied` remains retryable only when no
batch was published and any private log effects were proved aborted.

The first release has no migration or fallback reader. It rejects the former
single-file payload, earlier segmented formats, and retired root layouts.
The store's `NodeSegmentGroup` surrounds each native file with the
`KASUMI-NODE-SEG1` envelope and rejects the older single-file node layout.

## Ownership and admission

Native synchronization admission follows Rust 1.97.1's reviewed pthread and
inline futex implementations. On pthread Unix targets, the constructor grant
includes each mutex and condition variable's platform backing and allocation
allowance, and initializes it before concurrent aliases escape. These controls
retire before their original grant is refunded. Normal macOS, Linux, and Windows
targets are covered; unreviewed synchronization backends fail compilation rather
than receiving a zero backing quote. This is a platform boundary, not a claim
that every Rust target is supported.

The production constructors accept an already owned `SegmentGroupBackend`,
`StorageAdmission`, explicit group incarnation, and `CacheConfig`.
`Core::create_with_backend` strictly initializes an empty group;
`Core::open_with_backend` strictly opens an existing one. KV does not establish
filesystem namespace ownership itself. The embedding owner supplies exact
installed directory/file identities, private regular files, parent durability,
growth admission, and observed descriptor close. Kasumi Store supplies that
boundary through `NodeSegmentGroup` and `NodeDisk`; record encryption belongs
to the embedding store.

`StorageAdmission` charges resident workspace, outputs, and optional cache
credit. `SegmentGroupBackend::reserve_transaction` owns the complete physical
promise for a foreground batch; `finish_transaction` settles consumed rights,
and `cancel_transaction` is permitted only for an untouched reservation.
Successful create and unlink include parent directory synchronization.

Direct Core and Builder constructors return `NativeOpenFailure<B>` inline.
`Body` retains the original `CoreError`; `Cleanup` retains a successful body
result and its separate cleanup failure. The original sized backend remains
inline until one combined shell grant admits its body and authoritative cell.
First and retry close outcomes remain distinct; only an actual `NotEntered`
outcome permits another close attempt. Owning failures do not implement
`std::error::Error`, so they cannot silently enter an allocating error wrapper.

Native close and owned-resource disposal are separate observations. After
native drain, `Core::into_disposal` and `Database::into_disposal` retain the exact
owners until explicit `dispose` confirms actual controls, body, and original
grants retired. The retained opening and database report ordinary `Disposed`
or `FailedDisposed` only after that positive boundary. Their observations
preserve original errors and panic payloads without replaying native effects.
Returned value guards retain their memory charge until final drop.

`CoreError` records a commit disposition alongside its original inline cause.
Callers borrow the cause with `cause`, `io_error`, or `panic`; an unknown commit
keeps the same original I/O error or panic payload and cannot qualify as a clean
capacity refusal. Error source traversal borrows these original owners.

## Snapshots and cache

`Core::snapshot()` pins an immutable directory root. Later overwrites,
deletions, table creation, and compaction preserve that snapshot's ordered
view. Pins belong to the exact Core owner, even when group IDs match. The
bounded registry has 256 slots; cloning a snapshot shares its slot and adds
no allocation. Protected source rights also use registry capacity.

The table facade provides typed byte-table transactions, ordered ranges,
admitted value guards, and prepared reads into caller-owned workspace. It
serializes writers and stages a bounded batch before the durable Core commit.
A staging capacity denial rolls back the whole staged writer and releases its
gate; uncertain ownership retains the transaction for terminal custody.

`CacheConfig::byte_limit` bounds retained value and directory-page allocations,
including metadata and evicted payloads still held by readers. Zero disables
retention. Reads above the bound use disk and separately admitted request
buffers. The cache verifies complete physical identities and does not replace
snapshot or owner checks. Fitting writes are retained, while bounded warm-up
passes can populate current and pinned roots after reopen. Warm-up reports
whether it completed and whether the live set is fully resident.

## Maintenance and limits

Compaction incrementally rotates the appenders, relocates old live values,
packs sparse directory pages, and proves file reachability across current and
pinned roots. Only a complete, still-current proof can publish garbage. Each
unlink requires the selected mirrored root and confirmed parent synchronization
before its garbage record and disk charge are released. Recovery rechecks
recorded garbage before finishing an interrupted reclaim operation.

The table facade advances bounded maintenance before a new write after at
least 1 MiB of append growth. `Core::compact()` synchronously finishes a cycle
using bounded steps, so its total duration can scale with the dataset. Old
snapshots retain reachable files; compaction can proceed while they remain
open. Temporary copies and retained generations still require admitted disk
headroom. Provider pressure can return a retryable capacity denial.

| Native Core bound | Limit |
| --- | --- |
| Table name | 1 KiB, nonempty |
| Key | 4 KiB |
| Value | 40 MiB |
| Table/key/value bytes in one batch | 96 MiB |
| Operations in one batch | 65,536 |
| Log segment / directory arena | 64 MiB each |
| Directory page | 16 KiB |

The encrypted tenant record limit is 32 MiB; the larger physical value bound
allows its envelope. Maintenance work counts are not wall-clock bounds: one
oversized value can require copying up to the native value limit in a step.
Capacity, recovery duration, sustained overwrite performance, and soak
qualification remain part of the broader production release gates.

## Verification

The native tests exercise whole-generation recovery at each injected commit
effect, torn durable writes, owner callback panics, cache visibility after
failed publication, multi-table snapshots and ordered iteration, capacity
rollback, and close custody. Compaction and reclamation tests inject failures
at relocation, publication, unlink, and garbage-forget boundaries, including
held snapshots and values larger than maintenance workspace. Allocation tests
check cache and transaction accounting, and restart tests check that opening
above admitted memory does not rebuild a resident key map.

Run the focused native checks:

```sh
cargo test -p kasumi-kv --locked
cargo clippy -p kasumi-kv --all-targets --locked -- -D warnings
```

The complete repository gate is in [CONTRIBUTING.md](../../CONTRIBUTING.md).
