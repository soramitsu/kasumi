# Kasumi frozen runs

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

Each reader retains 64 direct-mapped small blocks. Their combined byte buffers and row-offset backing fit within 4 MiB. They coexist with at most one oversized decoded row (32 MiB value plus at most 4 KiB key, six header bytes and one row offset). Loading a block also uses one temporary compressed buffer bounded by the LZ4 compression bound for its authenticated input length. A prefix-coded block can additionally use at most 43,690 intermediate bytes before expansion into its 32 KiB canonical buffer. Exact point reads return an owned value.
