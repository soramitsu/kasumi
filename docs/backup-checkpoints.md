# Verified full-backup checkpoints

A checkpoint records the exact captured logical database generation and the complete encrypted object graph that Kasumi verified. It is evidence of a completed administrative operation. It does not grant serving authority, certify source retirement, or authorize disaster failover.

## Engine and native SDK contracts

The engine exposes:

```rust,ignore
Database::backup_checkpoint(context, &dyn BackupDestination)
Database::verify_backup_checkpoint(context, &dyn BackupDestination, backup_id)
Database::backup_checkpoint_named(context, "approved-destination")
Database::verify_backup_checkpoint_named(context, "approved-destination", backup_id)
```

These methods return `kasumi_engine::VerifiedBackupCheckpoint`. Its fields and constructor are private. It has no deserializer. The read-only getters are `tenant()`, `source_incarnation()`, `revision()`, `resident_sha256()`, `backup_id()` (a UUID), `manifest_ciphertext_sha256()`, `key_lineage_digest()`, and `checkpoint()`.

The separate administrative listener exposes `CreateBackupCheckpoint` and `VerifyBackupCheckpoint`. Each request requires a verified bearer token, current global tenant Admin authority, and the native listener's TLS 1.3 mutual authentication. The payload selects an installed destination alias; it cannot provide a tenant override, path, URL, or key-provider configuration. These operations are absent from the data and MCP interfaces.

`KasumiAdminClient::create_backup_checkpoint(bearer, &CreateBackupCheckpoint { destination })` and `verify_backup_checkpoint(bearer, &VerifyBackupCheckpoint { destination, backup_id })` return a separate `kasumi_client::VerifiedBackupCheckpoint` with the same getters. Only the authenticated, CA-validated, hostname-validated and leaf-pinned SDK connection can construct that proof. Neither proof type supports public construction or arbitrary deserialization. The public `FullBackupCheckpoint` type is a serializable observation record, and its `validate()` method checks shape only. Trust in the SDK proof includes the operator's selection of the authenticated Kasumi endpoint.

`Database::backup` returns the UUID from this same verified pipeline.

## What is verified

Creation captures one coherent committed generation, streams its resident state into bounded encrypted chunks, copies its archived dependencies, and publishes the encrypted full manifest last. Every publication is read back. It then uses the same complete-graph verifier used by administrative readback and empty-target restore before producing the proof.

The verifier checks:

- authenticated manifest identity, source tenant, incarnation, revision and full-database kind;
- every resident chunk's immutable object identity, authenticated ciphertext, plaintext length and digest, and the whole resident-state digest;
- decoded tenant-state structural, schema, index and accounting invariants, including permanent command identities;
- every referenced historical manifest and chunk, with exact retained document identities, versions, digests, encoded lengths and structured index values;
- access to every actual authenticated wrapped-key catalogue in that graph.

`key_lineage_digest` is the canonical `staged_digest` of `("kasumi.full-backup-key-catalogs.v1", sorted_unique_catalogue_digests)`. Each catalogue digest hashes its authenticated canonical serialized key catalogue, including active key identity and wrapped dependencies. No plaintext keys are included. The manifest ciphertext digest separately binds the concrete manifest/object graph. Rotation during or before publication can therefore add catalogue identities without silently omitting an older archive key dependency.

Missing objects fail with Unavailable; invalid objects or a historical subset presented as a full backup fail closed. Verification never substitutes currently live document bodies for missing backup objects. Restores keep their distinct empty-target authorization, source-policy check and deterministic configured archive-alias rebinding; they use the same graph integrity checks.

## Authority, cancellation and bounds

The engine requires current global Admin authority and a coherent quorum barrier. Readback rechecks policy epoch, tenant key access and cancellation around storage I/O and before release. Native adapters retain a response fence across the operation and encoding and check current administrative authority at acknowledgement. A later consumer must compare the proof's tenant/incarnation/revision with its own durable runtime fencing evidence; a checkpoint is not that fence.

Each create or verification operation has a five-minute deadline, bounded object reads, query admission and retained byte reservations. Storage waits are cancellation aware. Large resident decoding, schema/index verification and destruction run in owned blocking workers. Deadline expiry stops awaiting those workers, but their byte reservations and live-work registrations remain held until actual completion, so shutdown cannot release the database while retained work still owns it. CPU primitives and final restore disk persistence are not preemptible.

A creation timeout can leave immutable published objects and returns UnknownOutcome. A readback timeout does not change backup contents. Automatic orphan cleanup and a client-selected permanent backup-creation identity are not implemented. Backups use checked 64-bit resident lengths, 8 MiB chunks, bounded pages of 256 chunk descriptors, and a constant-size authenticated root. Encrypted scratch spools avoid tenant-sized serialized buffers; decoded state and indexes remain subject to node admission. This implementation does not establish capacity or recovery-time objectives for 10,000 tenants, independent fencing when the source quorum is unavailable, or Linux release qualification.
