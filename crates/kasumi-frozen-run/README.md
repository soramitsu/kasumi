# Kasumi sorted runs and live indexes

For a writable index, open `LiveDb` on its own local directory on Linux or
macOS. It accepts ordered binary puts and deletes in one transaction. A
successful `commit` returns its durable sequence. Writes use a checksummed,
sequence-numbered WAL frame per batch and synchronize the file before return.
Reads combine the current write buffer and immutable levels, including
replacements and deletes. The same engine is accessible through
[`kasumi_kv::compact`](../kasumi-kv/README.md#compact-live-indexes)
and the [Node-API binding](../kasumi-live-node/README.md).

The write buffer flushes when its conservative change estimate or physical WAL
reaches the persisted budget. New databases default to 4 MiB. For a storage
lane with a different memory/recovery budget, use
`LiveDb::create_with_buffer(path, bytes)` with 512 KiB through 16 MiB. A
larger budget reduces inline merge frequency at the cost of a larger live
WAL and longer recovery. Version-2 directories retain their original 512
KiB budget and remain in their original format. One atomic batch can exceed
the trigger. On flush, a new
compressed file absorbs any occupied lower tiers, like carries in a binary
counter. Each level indexes its own pieces on disk. An explicit `checkpoint()`
also merges the remaining tiers and retires obsolete files. Reads take the
newest value for a key; a delete survives merges until no older level could
still contain that key. Both the old and new files can consume space while
a merge runs. Commits that trigger a merge wait for its completion.

An exclusive lock covers each database directory for the lifetime of the
handle. A checksummed manifest identifies the current immutable files and WAL.
The writer synchronizes the new files and their names before replacing and
syncing the manifest, then unlinks the retired files. Reopen validates the
selected roots and WAL, replays complete frames, and repairs an incomplete
final append. After an uncertain I/O error, reopen and check the sequence and
data before retrying. A valid database directory must be controlled by its
owner, including its parent at creation. Copy logical rows to migrate between
this format and other databases.

## Smaller files with Zstandard blocks

A database or sealed run can trade CPU for disk by letting the writer use
Zstandard. It is opt-in and chosen once: `LiveDb::create_with_codec(path,
budget, BlockCodec::Zstd)` for a live database, `seal_with_codec(path, rows,
BlockCodec::Zstd)` for a sealed run, and a trailing `zstd` on
`kasumi-live-transfer import` or `import-filtered`. A live database records
the choice in its manifest, as it does its write buffer, and every flush,
merge, checkpoint and bulk import writes with it; `LiveDb::block_codec`
reports it. To change an existing database, export it and import it into a
new directory with the other codec.

Each block still picks canonical or prefix-coded rows as before, then keeps
the Zstandard form of those bytes when it is smaller than the LZ4 form, at a
fixed level of 7. Blocks that Zstandard does not shorten stay LZ4. Without the
option nothing changes: LZ4 runs and manifests are written byte for byte as
before, and this version reads every earlier file.

Measured through `kasumi-live-transfer import` and the `cold-lookup` example:

| | LZ4 | Zstandard |
| --- | ---: | ---: |
| Stats fixture, 16,387 rows: level file | 151,318 B | 67,879 B (55% smaller) |
| 800,000 synthetic rows of hexadecimal text: level file | 438.1 MB | 244.9 MB (44% smaller) |
| Same rows: CPU to import | 5.2 s | 12.1 s |
| Same rows: CPU per lookup of an uncached block | 53 µs | 71 µs |

The saving depends on the data. Text that LZ4 cannot shorten, such as
hexadecimal or decimal digits, gains the most; rows that are already random
bytes gain nothing. To estimate it for an existing database before choosing,
pipe `kasumi-live-transfer export-read-only DIRECTORY` into
`benchmarks/indexer-kv/codec-probe.py`. A lookup served from a block the reader
already holds costs the same under either codec.

A Zstandard run has directory and footer magic `KSFRDIR3` / `KSFRIDX3`. It is
the version 2 layout with one more flag: bit 30 of a block's stored-length
word marks a Zstandard frame, alongside bit 31 for prefix coding. A Zstandard
database's manifest begins `KSLIVE04` and carries the codec after the write
buffer. Readers from before this codec refuse both, so keep a build that can
read them for as long as the files exist. A frame is authenticated like any
block before it is expanded. A block must be exactly one frame of the current
Zstandard format, and it is expanded into a buffer of exactly its
authenticated length, so a frame that would expand further fails. Each thread
that reads or writes Zstandard blocks keeps one decompression and one
compression context; the compression context is released after an oversized
row.

## Read-only frozen runs

A frozen run stores an immutable, strictly sorted stream of binary keys and values for finalized history. The owner supplies the history cutoff and publishes the expected SHA-256 digest through its own trusted manifest. It can then open independent readers against the same file.

```rust
use kasumi_frozen_run::{FrozenRun, seal};
use std::{io, ops::Bound};

fn example(path: &std::path::Path) -> io::Result<()> {
    let root = seal(path, [(b"block/001", b"first"), (b"block/002", b"later")])?;
    let mut run = FrozenRun::open(path, root)?;
    assert_eq!(run.get(b"block/001")?.as_deref(), Some(&b"first"[..]));
    run.visit_reverse(Bound::Unbounded, Bound::Included(b"block/002"), 1, |key, _| {
        assert_eq!(key, b"block/002");
        Ok(())
    })?;
    Ok(())
}
```

The writer streams into a private temporary file in the destination directory. It synchronizes the file, publishes the new name without replacing an existing file, and synchronizes the parent directory. If that final synchronization fails, the new name may already exist. A consumer can verify it using the independently retained root. Live commits, pinning, finality and manifest publication belong to the owner.

Version 2 tries two LZ4 representations per multirow block: canonical length-prefixed rows, and rows with each key encoded as its shared prefix length with the preceding key plus its new suffix. The writer selects the smaller physical representation, including its metadata. The reader still opens version 1 files. Prefix history starts empty in every block and is checked and expanded back to complete rows before caching. A canonical block typically contains at most 32 KiB. A single larger row gets its own block. Keys may be up to 4 KiB, and values up to 32 MiB. The authenticated directory binds each compressed block's digest, encoded and decoded byte lengths, and first and last key. Opening verifies the directory, its strictly disjoint ascending bounds and the exact file extents. The directory is limited to 64 MiB encoded and 262,144 blocks. The retained index contains one descriptor and its two keys per block. Owners can shard datasets that exceed these limits.

Queries binary-search the directory and the decoded block's row offsets. A reader verifies each accessed compressed block before decompression, validates its decoded length, checks every row boundary and key order, and checks its first and last key against the directory. A forward scan over unbounded endpoints verifies every block. Range callbacks receive borrowed bytes in order, with at most the requested number of callbacks. If an I/O or integrity error occurs after a verified block, the callback may already have received earlier rows.

Each reader retains 64 direct-mapped small blocks. Their combined byte buffers and row-offset backing fit within 4 MiB. They coexist with at most one oversized decoded row (32 MiB value plus at most 4 KiB key, six header bytes and one row offset). Loading a block also uses one temporary compressed buffer bounded by its codec's compression bound for its authenticated input length. A prefix-coded block can additionally use at most 43,690 intermediate bytes before expansion into its 32 KiB canonical buffer. `get` returns an owned value. `FrozenRun::get_ref` and `LiveDb::get_ref` borrow the verified bytes until the next operation on the reader. A live lookup keeps up to two recently used pieces for each ordinary level and three for the imported bulk level, in addition to the current piece. Oversized decoded rows are released when a piece moves into that cache. The deepest ordinary tier can keep five additional authenticated indexes. Each extra piece releases all decoded blocks and is limited to 512 KiB including its inline descriptor and index allocations. The recent-piece deque has a separate fixed number of slots and can hold spare capacity. Each level also keeps the branch nodes at the top of its piece index once it has read and authenticated them: at most 1,024 branches and 128 KiB of their split keys, about 250 KiB per level. A lookup that leaves the retained pieces then reads only the nodes below the kept ones: the single leaf for a level of up to about 1,000 pieces (4 GiB of rows), and a few more for a larger level, whose memo holds every branch near the root and the paths of its earliest lookups below that. Every piece reads through its level's descriptor by absolute position, so retained pieces open no additional file descriptors.

For an offline bulk migration, `LiveDb::load_sorted` atomically initializes an
empty database from strictly increasing binary rows. It builds one immutable
base in a streaming pass, bounded by one 4 MiB piece plus one legal oversized
row and the logarithmic piece index. The source and any I/O errors must
propagate through the iterator. Reopen after a failure to resolve publication.
The first successful import gets sequence 1. Later ordinary writes flush into
younger tiers, preserving the base until full compaction.

`kasumi-live-transfer import NEW_DIRECTORY` reads a raw sorted stream on
stdin. It requires a fresh path under an existing directory. It rejects empty
sources, keys above 4096 bytes, values above 32 MiB, duplicate or unordered
keys, truncation and checksum errors. The format starts with `KSRKRAW1`, then
repeats a big-endian u32 key size, key bytes, a big-endian u32 value size and
value bytes. A sentinel key size of 0xffffffff precedes the big-endian u64
row count, u64 total key/value byte count, and SHA-256 of all length-prefixed
row bytes. End-of-file must follow the trailer. After syncing and closing the
database, the command reopens it, scans every row, compares its digest and
count with the source, and probes point and descending index reads. Its JSON
receipt is printed only after all checks succeed. Repeat independent
verification using `kasumi-live-transfer verify DIRECTORY ROWS STATE_SHA256`.

An imported base retains up to three previously visited pieces alongside the
current piece. This avoids repeatedly decoding the sparse indexes when a
worker alternates between a document, its metadata counter and a secondary
index. Older cached pieces release their oversized-row buffers when the
cursor switches pieces. The on-disk format is unchanged.

To stream the complete current rows from a sealed live database, run
`kasumi-live-transfer export-read-only DIRECTORY > rows.raw`. The reader takes
the directory lock to exclude writers. It opens the manifest, levels and WAL
read-only, validates complete WAL frames, and rejects a torn tail. Level
indexes are checked on open and level pieces are authenticated as visited.
The transfer format requires at least one row, so exporting an empty database
fails without producing a partial stream. It does not
initialize an interrupted database, reclaim stale files or apply a repair.
The count, byte total, sequence and SHA-256 are printed to stderr. The Rust
`ReadOnlyLiveDb` API also supports point reads and bounded forward scans.

For an opt-in filtered import, run `kasumi-live-transfer import-filtered NEW_DIRECTORY EXPECTED_ROWS`
with the same sorted stream on stdin. Use its exact row count. The importer checks the trailer,
the count, and every row before publishing. The immutable bulk level includes a blocked Bloom
filter of about ten bits per row (64-byte buckets, capped at 256 MiB). Its root authenticates
both the exact tree and the complete filter. A negative test skips the tree lookup. A positive
test uses the ordinary exact lookup. WAL updates and newer levels take precedence, and full
compaction rebuilds the filter from its merged output.

Root node tag 2 contains the ordinary tree link followed by a link to the filter.
The filter uses 64-byte buckets. The first eight bytes of SHA-256(key), interpreted
as little-endian u64 modulo the bucket count, select the bucket. The low nine bits
in each of the next seven little-endian u16 values select the bit positions within
it, least-significant bit first. Both links and all filter bytes are authenticated.
The `verify` and `export-read-only` commands check membership of every physical
filtered key, including shadowed rows, as they scan. Consumers must check the
complete stream trailer before accepting output. Full compaction counts surviving
rows and retained tombstones before sizing the rebuilt filter. At the maximum
size the old and replacement filters can occupy 512 MiB together during compaction.

A filter-aware reader can open both formats. Earlier readers reject the filtered root. Keep a
separate verified legacy database for rollback when choosing this import mode. The default
`import` command continues to produce the legacy format. Both produce the same sorted logical
export for the same source rows.
