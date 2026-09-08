# Streaming snapshot contract

The first-release format carries bounded semantic records, rather than one
serialized tenant value. Unsupported earlier JSON and postcard snapshot images
are rejected. `Limits.max_snapshot_bytes` is a checked `u64` resource quota;
there is no 2 GiB format ceiling. Documents, requests, transactions, individual
records, results and admitted node work retain independent bounds.

Tenant images begin with `KASUMIT2`. Every record has an eight-byte big-endian
payload length followed by canonical JSON. Records explicitly identify metadata,
collections, documents, archive references, command receipts, staged metadata and
chunks, change-feed headers and individual changes, history archives, schema and
retirement records, audit events and Control history. Payloads cannot exceed
32 MiB. Records must follow the specified category/key order, with contiguous
indices for sequence members. The terminal zero-length record carries checked
64-bit record and byte counts and SHA-256 over the preceding image. The decoder
rejects missing or inconsistent trailers, unordered/duplicate records, embedded
records in metadata, noncanonical JSON, unsupported formats and trailing bytes.
AEAD-encrypted storage/backup envelopes and authenticated transport bind this
image to its trusted origin; an unkeyed digest alone is not authority.

Persistent ordered document maps and primary-ID roots are shared between live
and leased generations. Snapshot serialization does not allocate a sorted copy
of every document ID. The accounting cache measures this exact record format and
updates affected records when commands commit. Coherent point/scan leases keep
only the shared read roots, definitions and required history references. Their
budget covers metadata plus old document/reference versions and conservative
persistent-tree path retention caused by concurrent writes. Budget or node
pressure expires the lease with `CursorExpired`; a lease never changes revision.

Raft images use `KASUMIS2`: a bounded metadata record, consecutive data records of
at most 64 KiB, and a final byte count, record count and digest. Snapshot transfer
uses encrypted scratch files and runs filesystem/crypto work on blocking workers.
Each scratch file has an ephemeral random key and authenticated 64 KiB slots;
plaintext scratch files and persisted scratch keys do not exist. Immutable image
handles offer independent readers and constant-size clones. Durable staging
writes bounded encrypted chunks and publishes their manifest together with the
matching custody/applied position. Interrupted publication preserves the previous
recoverable image or the complete new one. `RaftLimits` supplies the installed
per-group transfer budget (64 GiB by default), separately from the tenant quota.

Full backups publish data chunks, then pages of at most 256 chunk descriptors,
then a constant-size final root. Pages form an immutable reverse chain with
ciphertext digests on every edge. Verification first checks that chain into an
encrypted fixed-slot spool, then traverses it forward while checking chunk
counts, lengths, hashes, origin, key dependencies and the final resident digest.
Resident state is decoded into unpublished state from its encrypted spool.
Genesis/bootstrap persistence and Raft restore also consume streaming readers.
Every cold-history dependency is verified before a backup proof or restored
bootstrap can be published. A single encrypted backup object is limited to
32 MiB; that is not the size limit of an aggregate backup.

The source generation and decoded replacement state remain resident where needed
for correctness. Streaming removes serialized copies proportional to tenant size;
it does not make the database disk-resident or eliminate index rebuild memory.
Capacity and endurance release gates must be run against final release binaries.
