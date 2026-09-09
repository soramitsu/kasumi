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

Caller reconciliation is required after this initial core source checkpoint.
Standalone/general node files need a configured random durable UUID. HA target
generations derive their UUID from immutable retained target origin and physical
verifier identity; local restored generations derive it from the original local
operation and target incarnation. Create and reopen must use shared named
derivation helpers, never paths, mutable membership or the candidate header.

The focused source tests are `node_file::tests::` (eight ordinary tests and one
explicit subprocess helper). They cover byte-exact clean/unclean unrelated-file
rejection, actual process-exit recovery, wrong UUIDs and inodes, partial headers,
canonical fields/checksum, checked offset I/O, actual descriptor close, and path
substitution between validation and redb handoff. These source tests have not yet
been compiled or executed. The child exits only after an immediate durable
transaction and its parent owns kill/wait cleanup with a finite deadline.
