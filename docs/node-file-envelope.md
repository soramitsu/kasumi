# Canonical node file and existing-only recovery

Every production node file uses one 4096-byte outer envelope followed by the
redb payload. Raw redb files and older formats have no decoder or migration.
The exact envelope is:

| Bytes | Meaning |
| --- | --- |
| 0..16 | ASCII `KASUMI-NODE-0001` |
| 16..32 | Non-nil node store UUID, in UUID byte order |
| 32 | Initialization state: 1 prepared, 2 ready |
| 33..4064 | Required zero bytes |
| 4064..4096 | SHA-256 of bytes 0..4064 |

The magic and checksum discriminate the format and detect incomplete header
publication. They are **not cryptographic authentication**. The caller must
supply an expected UUID from its already owned installation/configuration or
authenticated recovery journal. Reading a candidate header to choose its
expected UUID defeats this contract. Existing tenant encryption, exact storage
purpose, independent custody binding and bootstrap authentication remain required.

`NodeStore::create_new(path, node_store_id, scratch)` creates an exclusive new
inode; its parent must already exist. The caller durably chooses the UUID and
owns creation before calling it. `initialize_owned_empty(path, expected_file,
node_store_id, scratch)` instead requires the exact empty single-link inode that
the caller already recorded in its installation or recovery journal. It checks
that identity and emptiness under the same exclusive descriptor lock before any
write. Neither operation adopts an existing populated or partial file.

Creation persists a prepared envelope, initializes and durably commits the redb
tables, then synchronizes the payload, ready envelope and parent directory before
success. Cancellation or failure can leave a prepared file or an uncertain ready
publication. The original creator retains cleanup responsibility and its exact
physical identity. A retry never truncates, recreates or automatically resumes
such a file. Once ready publication completed, later operations can use strict
reopen. Uncertain publication must be resolved from the original owned identity;
an error does not prove absence.

`NodeStore::open_existing(path, expected_id, scratch)` acquires an exclusive
lock on the existing owner-only, regular, single-link descriptor. It checks the
complete canonical ready header, expected UUID and supported length before any
redb constructor runs. All redb I/O uses that exact descriptor through an offset
backend; it does not reopen the pathname or release the lock between validation
and recovery. The backend checks offset arithmetic against signed 64-bit file
limits, preserves the outer header on resizing and rejects writes beyond the
allocated payload. Closing redb drains current descriptor operations and closes
the actual descriptor even if an internal reader retains a backend owner.

Unrelated raw redb files, different UUIDs, truncated/unsupported envelopes and
incomplete initialization are rejected without changing their bytes. A recognized
owned node payload may undergo normal redb crash recovery before a later table,
tenant or bootstrap check rejects logical contents. This permission is limited
to the recognized installed store; `RepairAborted` never permits falling back to
writable opening of an unrecognized file. The envelope adds fixed framing only;
it does not establish persistent disk admission or hard RSS bounds.

`NodeStore::claim_cleanup(path, expected_id)` performs no redb open or mutation.
It accepts only a complete canonical Prepared or Ready envelope under the same
private single-link descriptor lock and returns `NodeFileCleanup`. This guard
exposes the held `FileIdentity` and retains physical custody through the caller's
exact unlink and parent synchronization. It grants no authority to stop/delete:
permanent stop, issuer drain, gate closure and actual worker/storage ownership
drain remain caller preconditions. Empty or torn headers require the separate
original journal-bound inode protocol; they are never interpreted as a format
fallback. A source regression checks both states, byte-exact rejection and the
held inode lock even after its path moves.

Caller reconciliation is required after this initial core source checkpoint.
Standalone/general node files need a configured random durable UUID. HA target
generations use the permanently journaled Control incarnation, tenant, target
incarnation and physical verifier identity. These inputs exist even when an
early Stop precedes materialization; the full original target origin remains a
separate authenticated logical binding. Local restored generations use the
original installation, local operation and target incarnation. Shared named
`node_store_ids` helpers define versioned, length-framed SHA-256 derivations into
UUIDv8 values. They exclude paths, mutable membership, TLS certificates and the
candidate header. Target journal and signer-verifier files have distinct domains.

The focused source tests are `node_file::tests::` (nine ordinary tests and one
explicit subprocess helper). They cover byte-exact clean/unclean unrelated-file
rejection, actual process-exit recovery, wrong UUIDs and inodes, partial headers,
canonical fields/checksum, checked offset I/O, actual descriptor close, and path
substitution between validation and redb handoff. These source tests have not yet
been compiled or executed. The child exits only after an immediate durable
transaction and its parent owns kill/wait cleanup with a finite deadline.
