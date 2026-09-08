# kasumi-store

Encrypted redb records shared by local execution and Raft persistence. A successful
batch uses immediate durability and redb two-phase commit. Record namespaces,
user keys, and values are encrypted with XChaCha20-Poly1305 before entering redb;
physical keys use a tenant-bound HMAC. Nonces come from OS randomness and never
reuse Raft indexes. The catalog retains only tenant identity, key identifiers,
and wrapped key material.

`TenantStore::open` opens one shared store per tenant and starts a 20-second
fresh-decrypt renewal task plus a one-second expiry watcher. Different tenant
opens have separate gates. Consumers holding resident plaintext must subscribe
to `seal_notifications()` and check `check_access()` before releasing results.
The 60-second lease uses Linux CLOCK_BOOTTIME or macOS mach_continuous_time and
is measured from probe start. Every retained key is freshly decrypted on each
probe. Probe failure currently seals conservatively, including transient errors
and the five-second timeout. A late probe cannot undo an explicit seal.

Sealing blocks admission before waiting for an in-flight disk operation, sends
an eviction notification, and zeroizes owned cached keys. An operation committed
during lease expiry reports an unknown outcome. Explicit `refresh_lease` can
restore key access, but the engine must independently recover resident state
before admitting traffic. Previously returned plaintext belongs to the caller.

The Transit adapter requires an HTTPS origin, TLS 1.3, server trust, runtime-only
credentials, and a configured per-tenant wrapping key. It supports Vault/OpenBao
`datakey/plaintext`, `decrypt`, and `rewrap`, including derivation context and
namespace headers. It disables redirects and bounds response bodies to 64 KiB.
Rewrap verifies that the unwrapped data-key bytes did not change before publishing
a replacement catalog. Old backup objects retain their original wrapping versions.

## Logical backups

`encrypt_backup(revision, snapshot)` encrypts one logical engine snapshot, with
an authenticated format/UUID/source-tenant/revision/size manifest, retained wrapped
key dependencies, and an internal SHA-256 digest. It never restores raw Raft
identity. `EncryptedBackup::from_bytes` bounds parsing; its metadata remains
untrusted until `decrypt(source_tenant, provider)` authenticates the manifest and
freshly decrypts all referenced keys. Importers also compare the requested backup
UUID with `id()` before restoring into a new suspended database incarnation.

`FilesystemBackupDestination` publishes create-only files using file fsync,
no-clobber persistence, and parent-directory fsync. `S3BackupDestination` uses
TLS 1.3, SigV4 signed payloads and session credentials, signed If-None-Match for
create-only publication, bounded GET bodies, and no redirects. Callers must gate
result release again after awaiting either destination. Individual backup objects have a 32 MiB plaintext cap (`MAX_BACKUP_OBJECT_BYTES`);
aggregate backups use paged manifests and bounded chunks without a 2 GiB format
ceiling. `EncryptedSpool` and `SnapshotImage` provide encrypted scratch storage
and immutable streaming readers. Store records have a 32 MiB cap and transaction
batches a 64 MiB cap. See [streaming snapshots](../../docs/streaming-snapshots.md).

## Verification

Run `cargo test -p kasumi-store` and
`cargo clippy -p kasumi-store --all-targets --features test-utils -- -D warnings`.
Tests cover atomic reopen, every injected commit/fdatasync failure position,
all-or-nothing key-catalog replacement, expiry during fsync, corrupted/swapped
ciphertext, missing backup dependencies, filesystem roundtrip, rotation, bounded
suspend-aware leases, concurrent delayed probes and seals, and a background
expiry with no incoming request.

Transit tests use a local TLS 1.3 compatibility server with authenticated wrapping,
fresh decrypts, context/namespace assertions, and denial, timeout, redirect,
TLS 1.2, untrusted CA, malformed-key, and oversized-response failures. S3 signing
matches the [published AWS test vector](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html)
and a local TLS fixture checks create-only PUT/GET, signed session credentials,
body bounds, and rejected signatures. These fixtures are supplemented by actual
OpenBao 2.6.2 and MinIO tests; see [service evidence](../../docs/COMPATIBILITY.md).
Vault and externally operated S3 deployment interoperability remain unverified.
The failure backend models synchronized bytes surviving power loss. Physical
power-cut validation of the selected filesystem/device stack remains an operator
deployment responsibility and is not established by these software tests.

`test-utils` exposes `LocalKeyProvider`, `ManualClock`, `FaultBackend`, and
`NodeStore::open_with_backend` for engine and Raft fault tests. The test key
provider is not available in a default production build or selectable by server
configuration.

## Independent application and custody storage

Engine and Raft openers require `Arc<TenantStorageSet>`. Create it with
`TenantStorageSet::open(node, tenant, application_provider, custody_provider)`.
Both providers are explicit. The installed catalogs must have distinct identities,
wrapping policies and actual key bytes. Their immutable encrypted binding prevents
a substituted application/control pair. The same node transaction can publish
application and custody records together, retaining both key-access guards through
fsync and reporting an unknown outcome if access expires after commitment.

`CustodyStore::open(node, tenant, custody_provider)` opens only an already installed
control domain. It inspects wrapped application catalog identity without creating
an application provider or decrypting application keys. It grants no application
data authority. Native tenant and control configuration therefore requires a
separate `custody_transit` setting. Test embeddings can explicitly use
`test_utils::with_custody(existing_application_store, distinct_test_provider)`;
this feature is unavailable to native configuration.


## Actual S3 interoperability

An opt-in test runs the official MinIO release `RELEASE.2025-09-07T16-13-09Z`,
pinned to registry manifest
`sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e`.
The tag/digest was pulled from the official `minio/minio` Docker repository.
The test creates one container with 512 MiB/1 CPU, read-only root, dropped
capabilities, TLS-only loopback S3, and ephemeral credentials; it removes its
container on completion or unwinding. It never uses an implicit Docker context.

Set `KASUMI_MINIO_DOCKER_HOST` to an explicitly approved local Unix socket,
`KASUMI_MINIO_DOCKER_CONFIG` to an isolated Docker client directory, and
`KASUMI_MINIO_WORKDIR` to a temporary directory shared with that VM. Pre-pull the
exact pinned image through that same explicit socket/config, then run:

```
cargo test -p kasumi-store --lib actual_minio -- --ignored
```

The test passed against the real MinIO server: signed bucket creation,
authenticated encrypted upload/download/decryption, exact number and Japanese
payload preservation, create-only overwrite rejection, unknown-object rejection,
wrong-credential rejection, untrusted-CA rejection, and bounded download. This
proves protocol interoperability, not the durability configuration of an external
S3 deployment; the disposable fixture intentionally stores objects in tmpfs.
The normal suite also covers a published SigV4 reference vector and TLS fixtures.

Database creation synchronizes the redb directory entry after its durable initial
transaction. Newly created directory ancestors are also synchronized, including
filesystem backup roots. This closes the first-write namespace durability gap;
actual power-loss guarantees still require the documented filesystem/device stack.
