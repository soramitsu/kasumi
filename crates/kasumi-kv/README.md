# kasumi-kv

Kasumi's native byte-key transaction log. It uses no embedded database library.

## Disk format

Two 4 KiB checksummed commit headers occupy offsets 0 and 4096 of the backend
payload. The active transaction log normally begins at offset 8192. Every frame
contains a generation, prior end offset, operation count, bounded payload size,
and checksums for its header, payload, and individual values. A commit writes
and synchronizes the whole frame, then writes and synchronizes the alternate
commit header. A failed write or sync fences the live core; the caller must
reopen the same owned backend to learn the outcome. Recovery selects the newest
valid header and validates **all** committed frames. A valid newest header with
corrupt committed data fails closed instead of falling back to old state.

Compaction writes a complete snapshot of live tables and keys to a shadow
extent after the active log, synchronizes it, and publishes an alternate header
pointing to the shadow. Only then does it copy the snapshot into the front
extent. It synchronizes the front copy, publishes its header, then truncates
the shadow tail. Reopening a published shadow finishes the front relocation.
Each copy may contain multiple bounded frames, and values move through an
8 KiB buffer with their checksums verified. A failed physical effect fences
the live core; reopening selects and verifies the durable header.

The payload is a Kasumi-specific format. It rejects redb files and earlier
Kasumi payload versions. This first release has no migration path. The
embedding store owns the surrounding node-file envelope.

## API and admission

`StorageBackend` supplies exact-offset `len`, `read`, `write`, `set_len`,
`sync_data`, and explicit `close`. `StorageAdmission` checks the physical owner
and reserves resident index/workspace and physical growth before allocation or
I/O. `Core::create_with_backend` creates an empty payload or reopens an existing
one; strict create/open constructors are also available.

`Core::commit(&[Operation])` publishes one atomic batch across named ordered
tables. `Core::snapshot()` pins a generation. `get_admitted`, `next_admitted`,
and `ReadSnapshot::next_key_admitted` return owned bytes with resident leases.
The index stores only keys, generations, value offsets, lengths, and checksums;
value bytes stay on the backend. One mutex serializes commits and backend I/O.
Old index versions remain while a snapshot may need them, then are pruned.
Resident index nodes consume byte credits from admitted 64 KiB chunks, which
keeps the physical owner's reservation count bounded as the key count grows.
Unused chunks return to admission when their credits are no longer needed.
`Core::compact()` requests reclamation when no snapshots are active. Before a
new commit, the core also checks for reclamation after at least 1 MiB of new
log bytes; it compacts when the active log is at least twice the live snapshot
size. This work happens before the user commit starts, so a maintenance error
cannot change an already published commit result.

The tenant API's plaintext value limit is 32 MiB. The physical core accepts up
to 40 MiB per value and 96 MiB per frame to fit encrypted envelopes and batch
metadata. The table facade supplies byte-table transactions and ordered range
iteration. The retained facade records one-shot opening, terminal, and close
outcomes for physical ownership.

## Current limits

The shadow copy requires temporary physical headroom equal to the live
snapshot size. Disk admission may deny compaction near quota; a denial leaves
the original committed log readable, and later writes remain subject to their
own growth admission. Long-lived snapshots defer reclamation. The embedding
node owner is responsible for exclusive file ownership, envelope identity,
and its durability assumptions. The format and maintenance path still require
broader capacity, soak, and performance qualification before a production
release.

Run `cargo test -p kasumi-kv --locked` and
`cargo clippy -p kasumi-kv --all-targets --locked -- -D warnings`.
