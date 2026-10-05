# Canonical node group and existing-only recovery

A production `NodeStore` path names one enrolled directory containing
`root.kvroot` and the native segment, checkpoint and directory-arena files.
Even when the configured path ends in `.kv`, it names this directory. Every
file has a 4096-byte `KASUMI-NODE-SEG1` outer envelope; native KV bytes follow
that envelope. Single-file node formats, raw redb files and older native KV
formats have no migration or fallback reader.

## Files and envelopes

The root file is exactly 12,288 bytes: its envelope followed by two 4096-byte
native root slots. Other files use sixteen lowercase hexadecimal digits for
a nonzero identifier followed by `.kvseg`, `.kvckpt` or `.kvdir`, for example
`0000000000000001.kvseg`. Other spellings and extra entries are rejected.
File identifiers are allocated through native KV's durable intents; the
physical owner also refuses an identifier at or below the highest identifier
it has observed for that file kind.

| Bytes | Meaning |
| --- | --- |
| 0..16 | ASCII `KASUMI-NODE-SEG1` |
| 16..32 | Non-nil installed node store UUID, in UUID byte order |
| 32 | Kind: 1 root, 2 segment, 3 checkpoint, 4 directory arena |
| 33 | State: 1 Prepared, 2 Ready |
| 34..40 | Required zero bytes |
| 40..48 | File identifier as a little-endian `u64`; zero only for the root |
| 48..80 | SHA-256 of bytes 0..48 |
| 80..4096 | Required zero bytes |

The root uses Prepared during creation and Ready after initialization. A
complete data-file envelope must be Ready and must match the kind and
identifier in its filename. The envelope checksum detects damage and incomplete
publication; it is **not cryptographic authentication**. Callers supply the
expected UUID from their already owned installation, configuration or
authenticated recovery journal. Reading a candidate envelope to choose its
expected UUID does not establish this authority. Encryption, exact storage
purpose, independent custody binding and authenticated bootstrap state remain
separate requirements.

## Creation and strict reopen

The production constructors require the installed persistent `NodeDisk`,
`ScratchDisk` and an explicit `NodeStorageConfig`. Persistent and scratch
storage must use the same installed memory admission. The configuration chooses
native cache bytes and the number of cached data descriptors within the
installed owner's limits; `cached_files` must be between 1 and 4096. The root
descriptor is retained separately from that data descriptor cache.

`NodeStore::create_new(path, node_store_id, persistent_disk, scratch, config)`
creates an exclusive new directory and its root file below an existing enrolled
parent. The caller durably chooses the non-nil UUID before creating the group
and retains responsibility for partial or uncertain initialization.

`NodeStore::initialize_owned_empty(path, expected_group, node_store_id,
persistent_disk, scratch, config)` requires a journal-owned directory containing
only an empty `root.kvroot`. `NodeGroupIdentity` binds both the exact directory
and root inode; both are checked through the acquired owners before writing.
A different directory, substituted root, extra entry or nonempty root is refused.
`NodeGroupIdentity::read` provides a physical observation and grants no creation
or cleanup authority.

Creation admits root growth, writes and synchronizes the Prepared envelope and
parent, initializes native KV, and commits the required node tables. Registered
startup publishes Ready only after its matching table transaction reports a
successful commit and complete disposal. It synchronizes the root and parent
before returning success. A failure can leave Prepared state or an uncertain
Ready publication. It never authorizes truncation, recreation or reinitializing
a partial group. The original creator retains exact physical custody and cleanup
responsibility.

`NodeStore::open_existing(path, expected_id, persistent_disk, scratch, config)`
requires an existing directory and an exact-length root with a complete Ready
envelope matching the caller's UUID. The physical owner checks every directory
entry, private single-link regular-file identity, canonical filename and
envelope before handing the group to native KV. Installed directory ancestry
and file bindings are checked against the retained `NodeDisk` census. Symlinks,
hard links, foreign identities, unsupported fields, subdirectories and unknown
entries are refused. The root remains exclusively owned while data descriptors
are opened through the same installed namespace owner. After an eviction, a
data-file acquisition must reach the same recorded inode and envelope state.

Physical acquisition classifies the group without repairing its envelopes.
Native KV then verifies its own root identity and format, replays committed
records, and may perform recognized recovery work such as root mirroring,
discarding an uncommitted tail or finishing recorded garbage disposal.
Existing-table verification runs through the same registered opening. A later
table, tenant or bootstrap rejection does not authorize opening a different
format or recreating the group.

## Interrupted data creation and ownership

Creating a data file durably creates its empty name before its first native KV
mutation writes and synchronizes the envelope. Reopen recognizes an interrupted
envelope only when the file is at most 4096 bytes and every visible byte is zero
or the corresponding byte of that file's exact expected Ready envelope. Its
native payload length is zero. Reads do not complete it; the next write or
nonzero resize completes and synchronizes the envelope before any payload byte.
This recognition does not apply to a partial root envelope or to unsupported
older formats. Zeros or malformed envelope bytes beyond the first 4096 bytes
are rejected.

Payload offsets exclude the outer envelope. Checked I/O adds its 4096 bytes,
rejects arithmetic beyond signed 64-bit file limits, checks reads including
empty reads against EOF, and refuses writes that leave a hole. Growth requires
admission before its effect. Resize drains concurrent checked operations before
shrinking. Descriptor eviction settles growth and closes the exact owner;
a failed close retains that owner in its cache slot and fences the group.
Group close seals admission and observes every retained descriptor. Only close
that never entered can be retried; entered failures retain their original
outcome and custody for the failed-owner protocol. Uncertain physical effects
retain their charges and require drain and an accepted fresh disk census before
strict reopen.

## Independently authorized cleanup

`NodeStore::claim_cleanup(path, expected_id, persistent_disk, config)` returns
`NodeSegmentGroupCleanup` after verifying a recognized Prepared or Ready group
and every entry. It does not open native KV or initialize or repair the group.
The guard exposes the exact `NodeGroupIdentity`, directory identity and optional
root identity while retaining physical ownership. Its `delete` removes verified
data files, then the root, then the empty directory, with the required parent
synchronization after each namespace effect. An empty directory left by an
interrupted cleanup can be claimed without a root; its caller must still own
the original cleanup authorization and directory identity.

This guard grants no permission to stop or delete a generation. Permanent stop,
issuer drain, admission closure and actual worker/storage drain remain caller
preconditions. Failed deletion fences the group and disk and retains uncertain
charges; after drain and a fresh census, cleanup can claim the remaining names.
An empty or torn root from initial creation requires the original journal-owned
cleanup protocol and is not treated as a supported envelope.

The [production physical owner](../crates/kasumi-store/src/node_file/segment_group.rs)
and [registered startup](../crates/kasumi-store/src/storage_opening/startup.rs)
define these operations. The
[segment-group regressions](../crates/kasumi-store/src/node_file/segment_group_tests.rs)
cover exact envelopes and names, old-format and foreign-file rejection without
mutation, journal-owned initialization, interrupted data creation, descriptor
budgets, failed close/unlink custody and cleanup restart. These source references
are not a claim that current repository or release gates have passed; verified
status remains in the [release ledger](production-release.md).
