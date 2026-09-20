# Standalone installation

Build the production binary without fixture features, then initialize an absolute directory that does not already exist:

```sh
cargo +1.97.1 build --release -p kasumi-server --bin kasumid
target/release/kasumid init --mode standalone /var/lib/kasumi --tenant default
target/release/kasumid serve /var/lib/kasumi/kasumi.json
```

Initialization creates private directories and files, an exclusive installation identity, independent application/custody/Control/security wrapping keyrings, an Ed25519 issuer, TLS identities, and two client profiles. It provisions the Control and application catalogs, authenticated bootstrap, reserved Control schema and initial topology while holding exclusive storage ownership. It drains those owners before publishing the configuration and completion marker. A failed initialization leaves an incomplete private directory; initialization never adopts or overwrites it.

Listeners default to loopback: MCP on 9443, native data on 9444, and native administration on 9445. The initial MCP endpoint and certificate pin are committed in Control topology. Changing that endpoint requires a corresponding authorized topology update; editing only the configuration is insufficient. A stopped endpoint-configuration command remains to be implemented.

Established standalone runtime and operator opens require the existing application/custody catalogs, authenticated bootstrap and exact configured incarnation. Missing bootstrap or Control topology is an error, never permission to create a new genesis from configuration defaults. The completion marker binds the immutable Control incarnation; unsupported marker formats are rejected explicitly.

The required non-nil `database_id` identifies the main physical node file. Init
persists this random UUID in private `data/initialization.json` before creating
the inode. The final `data/installation.json` must match that intent and the
configured ID. An existing node must have a complete canonical node-file
envelope with the expected ID before the storage engine may recover it. Raw,
partial, missing or differently identified files are rejected. Restored local
generations derive their separate file IDs from the retained installation,
recovery operation and target incarnation; active runtime and stopped operator
opens use the same derivation. The UUID envelope does not replace encrypted
tenant catalog authentication or permanent recovery fencing.

The generated configuration includes a required `scratch_disk` object with an
absolute private `directory` at `data/scratch`, `max_bytes` of 68719476736
(64 GiB), and `min_free_bytes` of 268435456 (256 MiB). Configure these values for
the installation's workload and disk. The parent directory must exist. All
snapshot transfer, backup verification, restore staging and temporary point
indexes share this one owner, including auxiliary trust stores and replacement
generations. Images and background workers retain their charges until they
actually drain. Encrypted physical extents count toward the aggregate budget;
per-operation format and request bounds still apply. These are resource settings,
not a fixed aggregate backup-format ceiling. Reopening the same live scratch
directory with different budgets is rejected.

The scratch governor also checks fresh filesystem free space while reserving
outstanding writes across scratch owners on that filesystem. It does not reserve
persistent database, index, WAL, backup destination or archive space. External
processes can consume disk after a check, so storage failures remain possible.
Protected health and metrics expose the scratch charges and filesystem sample.

The native endpoints require TLS 1.3, a client certificate issued by the installed CA, an exact installed server certificate pin, and a bearer token. `profiles/default.json` names the database credential; `profiles/control.json` names the separate Control administrator credential. Each token is bound to one explicit incarnation and purpose. A Control token cannot access the document API.

MCP accepts preconfigured local bearer tokens over TLS. Supply `Authorization: Bearer <token from profiles/default.token>` and the current MCP protocol headers. Its protected-resource metadata does not advertise an OAuth authorization server. An actual external OAuth deployment uses the separate `auth.source.kind = "external_oauth"` configuration variant.

Local credentials expire after one hour. Keep each client credential file renewed:

```sh
kasumid credential watch /var/lib/kasumi/profiles/default.json
kasumid credential watch /var/lib/kasumi/profiles/control.json
```

The watcher saves a renewal identity before dispatch and atomically replaces the token file after a verified native response. It retries uncertain transport outcomes with the same identity. A restarted watcher renews immediately. Clients must reread token files per request. Renewal does not extend any existing request's deadline. Stopping a watcher does not revoke its family; use the explicit revocation command.

Create a credential from a private Control profile and a JSON specification:

```sh
kasumid credential create /var/lib/kasumi/profiles/control.json /path/create-credential.json /var/lib/kasumi/profiles/application.json
kasumid credential status /var/lib/kasumi/profiles/control.json FAMILY_UUID
kasumid credential revoke /var/lib/kasumi/profiles/control.json FAMILY_UUID
```

The specification contains `family_id`, `principal`, `tenant`, `resource`, `scopes`, and `lifetime_seconds` (1–3600, default 3600). Use a new UUID for `family_id`. Read the exact resource from the generated tenant profile. Scopes are `read`, `write`, `admin`, and `audit`; current database RBAC still determines effective access. Reusing a family UUID with different specifications is rejected. Revocation is permanent and fences already-running requests at their subsequent authorization or response-release checks. Revoking the credential used for the operation can suppress its own acknowledgement; another Control credential can inspect the durable result.

# Operator maintenance

Stop the standalone server and drain clients before the following commands. They require exclusive installation and database ownership and record their operations in encrypted security storage:

```sh
kasumid maintenance rotate-wrapping-keys /var/lib/kasumi/kasumi.json
kasumid maintenance rotate-signer /var/lib/kasumi/kasumi.json
kasumid maintenance rotate-certificates /var/lib/kasumi/kasumi.json
kasumid backup-operator-keys /var/lib/kasumi/kasumi.json /secure/offline/kasumi-keys
kasumid verify-operator-keys /secure/offline/kasumi-keys
kasumid recover-administrator /var/lib/kasumi/kasumi.json /var/lib/kasumi/recovered
```

Wrapping-key rotation retains previous generations and rewraps installed catalogs. Signer rotation retains previous verification keys. Certificate rotation retains the CA, replaces server and generated client keys and certificates, commits the new local Control certificate pin, and updates profiles inside the installation's `profiles` directory. Update any copied/external profiles using the returned pins before reconnecting. A failed rotation leaves a durable started event and can be rerun while the server remains stopped.

Administrator recovery issues new private profiles for administrators in the current policies. It does not silently replace policy or change existing credential-family outcomes. It requires the installed encryption and signing keys. Run the renewal watcher for recovered profiles before their one-hour lifetime expires.

The `operator` directory contains plaintext wrapping keys, signing keys, and the CA private key. It is separate from ordinary encrypted data backups. The key-backup command copies the exact installed file keyrings, signer, and CA material, including file keyrings stored outside the default operator directory. It publishes an owner-only manifest after copying every dependency and verifies every digest and wrapping-key generation inventory. Retain the returned manifest digest independently with key escrow; verification compares against this inventory and does not authenticate an untrusted replacement inventory. The command requires local file keyrings; external KMS keys require their provider’s backup procedure. Store this backup separately on a trusted encrypted host. Retain all generations needed by completed data backups. These facilities protect data against storage disclosure while trusting the host running Kasumi; possession of the operator keys and stopped installation is administrative authority.

# Local data recovery

The generated installation installs the filesystem backup destination `local` beneath `backups`. Create and verify a full backup using the native administrative backup API and retain the exact returned `FullBackupCheckpoint`. Retain the source application wrapping keyring separately. Verification requires every encrypted dependency; a root object alone is not a complete backup.

Stop the installed server before restoring. Prepare a JSON request containing a fresh `operation_id`, `tenant`, `expected_active_incarnation`, a fresh `target_incarnation`, the exact verified `checkpoint`, the exact source `source_purpose`, `source_keys`, `source_principal`, installed `destination`, and `phase_timeout_ms` (1–600000). For standalone backups, `source_purpose` contains `kind: "Standalone"`, the original `installation_id`, `tenant`, and `incarnation`. `source_keys` uses the same file-keyring configuration shape as the source tenant's `keys`. `source_principal` must have administrator authority in the backed-up policy.

```sh
kasumid local-recovery start /var/lib/kasumi/kasumi.json /secure/restore-request.json
kasumid local-recovery status /var/lib/kasumi/kasumi.json OPERATION_UUID
kasumid local-recovery resume /var/lib/kasumi/kasumi.json OPERATION_UUID
kasumid local-recovery stop /var/lib/kasumi/kasumi.json OPERATION_UUID
```

`start` durably records the request and runs its phases. Retry with exactly the same operation and inputs, or use `resume` after interruption. Each invocation obtains fresh independently bound source and target authorization from exclusive local operator ownership. No expired source bearer token is required. The encrypted coordinator retains original phase identities and exact inputs and resolves their results on resume.

Materialization writes an isolated `data/generations/<target-incarnation>/node.redb`. Completion precedes the atomic activation decision. Activation permanently retires the former local generation and selects one target; from that point recovery proceeds forward. `stop` is accepted before activation, persists the target's permanent stop, drains storage ownership, and deletes only files bearing the matching generation binding. Unrelated files prevent cleanup and remain untouched. The original `data/node.redb` retains installation, Control, security, and permanent recovery records and is never deleted by this cleanup.

The target's private audit cache has a durable directory identity and a separate ownership record for every staged or published archive object. These records remain in the original security store after cleanup. Publication records its intent before creating a named staging file and records that file's inode before writing ciphertext. Cleanup checks the recorded identities and final ciphertext digests, processes at most 256 files per pass, and synchronizes each deletion. It rejects replaced directories, replaced files, symbolic links, and unrecorded entries. Shared source caches, installed external archive destinations, and completed backups remain outside this deletion scope.

A pending operation prevents the installed server from starting. A finished operation publishes a fresh private database profile in `profiles/recovery-<operation-id>.json`; run its renewal watcher and use it after restarting the same listener. Existing credentials remain bound to their original resource and cannot access the restored incarnation. Key rotation and stopped-instance administrator recovery select the committed active generation. Missing activated storage causes startup to fail instead of recreating an empty database.

Local recovery fences only the exclusively owned installation. It does not attest that an independently running copy or a distributed source quorum has stopped. Distributed recovery requires the Control recovery coordinator and its issuer fencing evidence.

## Protected service audit

Protected health, readiness and Prometheus routes share the administrative TLS
listener. See [node observations](observability.md) for their authorization,
readiness conditions, available metrics and scraper configuration.

The separate administrative listener exposes service authentication, key maintenance,
backup, and recovery audit records only to a current Control administrator. Tenant
administrator credentials do not grant access. The server checks the original
credential and current Control policy again after encoding every response.

```sh
kasumid audit status /var/lib/kasumi/profiles/control.json
kasumid audit export /var/lib/kasumi/profiles/control.json /secure/audit-request.json /secure/audit-page.json
kasumid audit archives /var/lib/kasumi/profiles/control.json /secure/archive-request.json /secure/archive-page.json
kasumid audit verify /var/lib/kasumi/profiles/control.json STREAM_UUID ARCHIVE_INDEX
```

For the first export or archive page, the request is `{"cursor":null,"limit":256}`.
The CLI fixes its exact stream and exclusive end using the status response, then
persists those inputs in an owner-only `*.audit-attempt.json` beside the output
before dispatching the page request. After transport failure, repeat the same
command with that journal and a renewed credential from the same family. A changed
endpoint, resource, trust configuration, or request is rejected. Page outputs must
have an absolute path beneath an existing owner-only directory. A published page
is never overwritten.

For the next export page, set `cursor` to `{"stream_id":STREAM_UUID,
"next_sequence":NEXT_SEQUENCE,"through_sequence":ORIGINAL_END}` from the prior
page and choose a new output path. Archive cursors use `next_index` and
`through_index`. Stop when the next position equals the exclusive end. Both retain
the original range while new audit events are written or hot records are archived.
Export limits are 1–1024 records; archive limits are 1–256 segments. A response is
at most 1 MiB and may contain fewer records to satisfy that bound.

The Rust SDK provides `security_audit_status`, `export_security_audit`,
`security_audit_archives`, and `verify_security_audit_archive` on
`KasumiAdminClient`. Its page `.cursor()` returns the next exact cursor or `None`
at completion. The client rejects changed stream/end positions, missing sequence
numbers, and oversized responses. Archive listing reports dependencies; the
verification method returns a `VerifiedSecurityAuditArchive` only after the
server reads and authenticates the exact encrypted segment. These observations
are not a grant to delete archives or retire their wrapping keys.

## Backup sessions

Create a backup with the generated application administrator profile:

```sh
kasumid backup create /var/lib/kasumi/profiles/default.json local /secure/full-backup.json
```

The parent directory must already be private and owned by the operator. Keep the
checkpoint together with its `*.backup-attempt.json` journal. Retry the same
command after an uncertain result to resolve the original session. The
[backup session runbook](backup-sessions.md#operator-commands) documents status,
verification, permanent abort outcomes, bounded cleanup passes, and key retention.
Use the resulting checkpoint as the exact source checkpoint in a stopped local
recovery request.
