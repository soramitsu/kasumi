# Compatibility

## Deployed persisted formats

[CONTRIBUTING.md](../CONTRIBUTING.md) keeps old-format decoders out of the
tree, with one exception: a live deployment (BOI) serves a standalone store
that commit `12140939` first wrote and later builds (`cf9959f1` when this was
written) have served since. Every later build must open that store as it is,
give the same answers and keep writing, compacting, snapshotting and
reopening it, with no migration. A change may not renumber, remove,
reinterpret or refuse anything listed here; a new field needs a value the
deployed bytes already imply. Formats no deployment wrote (`KASUMI-KVROOT001`
through `004`, redb files, single-file nodes) stay refused.

The [deployed-format fixtures](../tests/deployed-format/README.md) are that
store in small, written by those commits' own `kasumid`: killed while its
root listed garbage, recovered and stopped cleanly, then served by
`cf9959f1`.

| Pinned representation | Test |
| --- | --- |
| `KASUMI-KVROOT005` root slots: format version 4, directory format tag at 20..24 (zero, Fixed), group at 24..40, retired checkpoint bytes 64..128, sealed segment at 128, garbage count at 152 and records from 160, directory commit at 2208..2384, compaction cycle at 2384..4080, CRC-32C last | `kasumi-kv` `tests/deployed_format.rs`: `root_slots_keep_the_deployed_layout_and_garbage_tags` |
| Root garbage tags 1 (segment) and 3 (directory arena), and reopening a root that lists them | the same, `the_killed_group_opens_and_the_clean_stop_after_it_kept_its_keys` and `deployed_groups_open_compact_write_and_reopen_with_the_same_rows` |
| `KASUMI-KVSEG0004` segments with the relocation and maintenance records of a deployed compaction cycle, `KASUMI-KVARENA01` arenas, Fixed 16 KiB `KASUMI-KVDIR0002` directory pages; a Fixed group stays Fixed after the current code compacts and writes it | `segments_and_fixed_directory_arenas_keep_the_deployed_headers` and the reopen test above |
| `KASUMI-NODE-SEG1` store envelope kinds 1 root, 2 segment, 4 directory arena | `kasumi-store` `tests/deployed_format.rs`: `every_deployed_node_file_has_its_ready_envelope_of_kind_1_2_or_4` |
| Tenant audit archive objects and chain, file keyrings, the `KSMBND01` backup destination marker | the other tests in `kasumi-store` `tests/deployed_format.rs` |
| Engine snapshots: embedded `KASUMID1` (`LocalSnapshotArchive::Embedded`, written by `12140939`) and by-reference `KASUMIL1` (written by `cf9959f1`), each followed by a journal tail | `kasumi-server` `runtime::deployed_format_tests` |
| `TenantState`: the tenant's receipt head, schema activations and audit retention; Control's `backup_binding_head` over its kind 24 records, one per verified backup; serialized `Policy` and `Limits` (`deny_unknown_fields`) | the same tests, against the writing build's readback |
| Encrypted records and wrapped keys of the node, Control, tenant, custody and security stores; documents, structured, unique, multikey, decimal and text indexes and 22 queries; permanent mutation receipts; bootstrap manifests; credential family records; installation marker, `kasumi.json` and client profiles | the same tests |

The document object collector adds one application namespace,
`engine.document.blob-links`, that no deployed build wrote or reads. It is
derived state: a restore clears it and the collector rebuilds it from the
published manifests, so a deployed store needs no migration and a build
without the collector opens a store that has it. Body and blob rows keep
their keys and bytes.

Each `kasumi-server` test serves a copy with the current runtime, compares
every answer with what the writing build recorded, then writes, snapshots,
runs a compaction cycle, stops, checks the root, envelope and directory bytes
it left and reopens. Not covered: a restore of a deployed backup, staged
transactions, lifecycle and retirement records, and replicated groups.

### Filesystem backup-session terminals

An outstanding intent or outcome has a preallocated reserve inode large enough
for the maximum encrypted record. Publication writes and synchronizes the
record, then renames that inode. The `KSMSES01` reader requires the entire
original fixed extent. New `KSMSES02` publications release the zero padding
after the rename and keep the original ciphertext and digest. A restart at
the rename can see either the full record or its exact compact length.
A later write in the same session authenticates any full v2 record before
reclaiming its padding. A session with a v1 intent can publish a v2 outcome.

## Service compatibility evidence

### OpenBao Transit

The opt-in integration test ran successfully on 2026-09-05 with the official
[OpenBao v2.6.2 release](https://github.com/openbao/openbao/releases/tag/v2.6.2),
Darwin ARM64. The downloaded archive SHA-256 was
`4e495376174accc0e014d31e9901f518a974f966850c839f626347eaac05fd52`.
This verifies the adapter against an actual server. That run used OpenBao's development mode, as described in its
[installation documentation](https://openbao.org/docs/install/).

```sh
bao_binary="$(python3 scripts/fetch_openbao.py)"
KASUMI_OPENBAO_BIN="$bao_binary" \
  cargo test -p kasumi-store --test openbao_live -- --ignored
```

The test starts an isolated TLS loopback server, creates ordinary and derived
AES-256 wrapping keys, and issues scoped child tokens. It verifies generation,
fresh decryption, context isolation, KEK rotation, rewrapping retained state,
backup restoration after rotation, historical decryption-version denial and
warm-state sealing after the child token is revoked. The child is terminated
afterward; no token helper or system trust store is changed, and tokens are not
printed. The fetch script installs nothing globally and verifies pinned hashes
before extracting the binary into the warm Cargo target directory.

This does not establish OpenBao service durability, HA behavior, HSM behavior or
Vault interoperability. Production key-service deployment is an independent
operational responsibility. Vault remains covered by wire-compatible fixtures
until a live Vault test is recorded.

### S3-compatible backup storage

The SigV4 implementation matches an AWS published signing vector. Local TLS
tests validate signed PUT/GET, session tokens, create-only object writes,
integrity checks, size limits, and TLS validation.

The opt-in real MinIO test passed on 2026-09-05 using official release
`RELEASE.2025-09-07T16-13-09Z`, with the Docker registry manifest pinned to
`sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e`.
It verifies signed bucket creation, encrypted upload/download/decryption,
create-only overwrite rejection, wrong credentials, untrusted TLS certificates,
missing objects and bounded downloads. The temporary local container is capped
at 512 MiB and one CPU and is removed afterward. That run used tmpfs and establishes
protocol interoperability, not a remote storage service's durability.

Use the explicit local Docker socket/config and pinned-image instructions in
[the storage README](../crates/kasumi-store/README.md#actual-s3-interoperability):

```sh
cargo test -p kasumi-store --lib actual_minio --locked -- --ignored
```

Externally operated S3 services remain untested. Their TLS 1.3 support, SigV4
behavior, consistency and durable-storage configuration need deployment-specific
verification.

### First-release provider qualification

On each Linux target, use the accepted native functional run, the official OpenBao 2.6.2 archive for its architecture, an offline uncompressed OCI-layout tar of the pinned MinIO release, and an isolated test runtime configuration selecting a tenant Transit key and an S3 destination. The OCI export must include the published multiarchitecture index and the native manifest, config and layers. The runner verifies the original index digest, reads the final native executable through its verified image layers and binds its digest to each service process.

```sh
python3 -I -B -S scripts/run_providers.py \
  --evidence "$FUNCTIONAL" --journal "$JOURNAL" --output "$ATTEMPT_DIR" \
  --attempt-id "$ATTEMPT_ID" --openbao "$OPENBAO_ARCHIVE" \
  --minio "$MINIO_OCI_ARCHIVE" --runtime "$TEST_RUNTIME_JSON"
```

The candidate daemon validates the test configuration. The two store test binaries from the same native build exercise actual Transit and S3 operations, rejected former credentials, successful refresh and ciphertext readback across service restarts. The runner retains the separate service and test process receipts. On the approved Linux host, run the standalone MinIO test as well to cover the pinned image's container entry point and its container resource limits. For the native runner, retain the enclosing host's enforced limits and resource measurements with the host receipt.

The macOS ARM64 OpenBao subtest can run against its official Darwin archive. The combined macOS-client/remote-Linux-MinIO case requires independently bound Linux service receipts and remains open.
