# Standalone installation

Standalone mode uses a serialized local journal and durable application commits.
It does not start Raft, elect a leader, send heartbeats, or wait for a quorum.
Use this mode for a single-machine installation. Existing standalone installations
retain their encrypted journal, snapshots, identities, and receipts when reopened;
do not reinitialize them to adopt this execution path. Replicated installations
cannot be reopened as standalone.

Each local journal entry and its commit cursor share one durable transaction;
the application state is applied before the write succeeds. A mutation of at
most 16 operations and 64 KiB also publishes its applied state in that same
transaction, so it costs one durable commit; other entries, larger batches
included, publish in a second commit after the journal entry. If anything the
mutation writes ahead of its publication would precede that transaction, the
journal entry commits first, by itself. Snapshot serialization
can overlap later writes, and compaction is triggered by journal growth rather
than a consensus timer. Idle audit maintenance checks the retained backlog before
acquiring command or archive capacity. Retired standalone custody also uses the
local writer. Administrative `status` reports `"mode":"standalone"`.

Build the production binary without fixture features, then initialize an absolute directory that does not already exist:

```sh
cargo +1.97.1 build --release -p kasumi-server --bin kasumid
target/release/kasumid init --mode standalone /var/lib/kasumi --directory-policy /etc/kasumi/directory-policy.json --file-allocation-policy /etc/kasumi/file-allocation-policy.json --network /etc/kasumi/standalone-network.json --tenant-audit-placements /etc/kasumi/tenant-audit-placements.json --tenant default
target/release/kasumid serve /var/lib/kasumi/kasumi.json
```

Initialization creates private directories and files, an exclusive installation identity, independent application/custody/Control/security wrapping keyrings, an Ed25519 issuer, TLS identities, and two client profiles. It provisions the Control and application catalogs, authenticated bootstrap, reserved Control schema and initial topology while holding exclusive storage ownership. It drains those owners before publishing the configuration and completion marker. A failed initialization leaves an incomplete private directory; initialization never adopts or overwrites it.

Supply an explicit private `--network` JSON file before installation, for example `{"mcp_listen":"127.0.0.1:9443","mcp_public_url":"https://localhost:9443/mcp","native_listen":"127.0.0.1:9444","admin_listen":"127.0.0.1:9445"}`. The four fields are required, unknown fields are rejected, and the listener ports must be nonzero and distinct. Standalone TLS identities currently cover `localhost` and `127.0.0.1`, so the MCP public URL must be `https://localhost:<mcp-listen-port>/mcp`. The selected endpoint and certificate pin are committed together in original Control topology, configuration, and generated profiles. Changing the endpoint later requires an authorized topology update; editing only the configuration is insufficient.

Supply a required owner-only `--tenant-audit-placements` JSON file with exactly
one entry for `__kasumi_control` and one for the selected application tenant.
This example explicitly chooses local replica only for both groups:

```json
{
  "__kasumi_control": {"kind": "local_replica_only"},
  "default": {"kind": "local_replica_only"}
}
```

Each entry may instead select `{"kind":"external","destination":{...}}` with
an installed filesystem or S3 destination. The groups choose independently; see
[tenant audit retention](tenant-audit-retention.md) for destination details.
The file must be a regular file with owner-only permissions, at most 64 KiB.
Missing entries, duplicate rows, unknown fields and obsolete shapes are rejected
before creating installation files. Initialization records the supplied choices
in `tenant_audit_placements`; later staged tenants must provide their own explicit
`audit_placement` in the [staging request](standalone-tenant-enrollment.md).

Established standalone runtime and operator opens require the existing application/custody catalogs, authenticated bootstrap and exact configured incarnation. Missing bootstrap or Control topology is an error, never permission to create a new genesis from configuration defaults. The completion marker binds the immutable Control incarnation; unsupported marker formats are rejected explicitly.

The required non-nil `database_id` identifies the main physical node file. Init
persists this random UUID in private `data/initialization.json` before creating
the inode. The final `data/installation.json` must match that intent and the
configured ID. An existing node must have a canonical storage group with a
complete root envelope and the expected incarnation before the storage engine
may recover it. Raw, partial, missing or differently identified groups are
rejected. Restored local generations derive their separate group IDs from the retained installation,
recovery operation and target incarnation; active runtime and stopped operator
opens use the same derivation. The UUID envelope does not replace encrypted
tenant catalog authentication or permanent recovery fencing.

The generated configuration requires `persistent_disk`. Its explicit `roots` map
contains the installation's `data` and `backups` directories. Private roots
cannot overlap each other or `scratch`. An installed node may add roots on other
filesystems; see [more than one filesystem](operations.md#persistent-storage-on-more-than-one-filesystem). The initial
limits are `max_bytes: 137438953472` (128 GiB),
`maintenance_reserve_bytes: 1073741824` (1 GiB),
`min_free_bytes: 268435456` (256 MiB), `max_open_files: 4096`,
`max_open_directories: 4096`, `max_persistent_files: 1000000`,
`max_persistent_subdirectories: 1000000`, `census_work_per_step: 1000000`,
`max_depth: 64`, and `max_name_bytes: 255`. The subdirectory count excludes the
explicitly configured roots. Census work is limited per step; it is not the
full-job file or directory count. All three namespace/work fields are required.
The bounded startup census must finish before storage admission opens. Database,
recovery generation, local archive and backup files use this retained owner;
configuration never derives a persistent root from a database path. Install every
root explicitly before opening it and use the same root map and budgets when
initializing auxiliary stores. Unsupported or missing configuration is rejected.

`persistent_disk.native_storage` is also required. The generated profile sets
`byte_limit: 1073741824` (1 GiB) and `cached_files: 64`. These are per-group
ceilings for the native page/value cache and cached file descriptors; retained
versions and cache metadata count toward the byte limit. Every group shares
the installed memory provider, so these ceilings do not grant separate physical
memory allowances. A store may request a smaller share. Choose installation
budgets together with request, query and maintenance headroom; the generated
values have not yet completed capacity/performance qualification. Writes remain
durable even when all reads can be served from memory. Full residency through
foreground writes and bounded startup warming are still being integrated; see
the [active storage goals](disk-backed-cache-goals.md).

The generated configuration includes a required `scratch_disk` object with an
absolute private `directory` at `scratch`, `max_bytes` of 68719476736
(64 GiB), `min_free_bytes` of 268435456 (256 MiB), and `native_cache_bytes` of
536870912 (512 MiB). The cache ceiling applies to each scratch table's pages and
values, including metadata and retained versions. Fitting contents remain in
memory; larger tables read misses from encrypted disk. Every table also uses the
same installed memory provider, so concurrent tables cannot exceed the shared
memory budget. Setting `native_cache_bytes` to zero explicitly disables cache
retention. Configure these values for the installation's workload, memory and
disk. The parent directory must exist. All
snapshot transfer, backup verification, restore staging and temporary point
indexes share this one owner, including auxiliary trust stores and replacement
generations. Images and background workers retain their charges until they
actually drain. Encrypted physical extents count toward the aggregate budget;
per-operation format and request bounds still apply. These are resource settings,
not a fixed aggregate backup-format ceiling. Reopening the same live scratch
directory with different budgets is rejected.

Persistent and scratch owners on one filesystem share its outstanding-growth
accounting and fresh free-space checks, while maintaining separate installed
capacity limits. Each filesystem holding a persistent root keeps its own accounting and checks. The persistent maintenance reserve remains unavailable to
foreground growth. External processes can consume disk after a check, so storage
failures remain possible.
Protected health and metrics expose the scratch charges and filesystem sample.

The native endpoints require TLS 1.3, a client certificate issued by the installed CA, an exact installed server certificate pin, and a bearer token. A new installation writes four profiles. Each native profile has its own credential family, principal and client certificate, and its family is bound to that certificate: its tokens carry the certificate's thumbprint (`cnf.x5t#S256`, RFC 8705) and are refused from any other certificate, on every request (docs/credential-lifetime.md):

| Profile | Principal | Scopes | Certificate | Use |
| --- | --- | --- | --- | --- |
| `profiles/default.json` | `application` | read, write | `profiles/client.pem` | Documents through the native API and `kasumictl --profile`. Renews itself. |
| `profiles/operator.json` | `administrator` | read, admin, audit | `profiles/operator-client.pem` | The tenant's collections, schema activation (which reads what it asserts), policy, limits and backups. Cannot write documents. |
| `profiles/control.json` | `administrator` | read, write, admin, audit | `profiles/control-client.pem` | Control: credentials, topology, service audit, metrics. |
| `profiles/mcp.json` | `application` | read, write | none | MCP only: its token is for the separate MCP audience and unbound, since MCP takes no client certificate. The Control profile renews it. |

The tenant policy grants `application` read and write and `administrator` read, admin and audit, so neither credential can do the other's work however its token is scoped. Each token is bound to one explicit incarnation and purpose. A Control token cannot access the document API. Give the application only `default.json` and its files; keep `operator.json`, `control.json` and their certificates and tokens out of the application's reach, for example under another operating-system account. Separate files under one account do not keep them apart.

Administer the tenant through the operator profile, for example `kasumictl --profile /var/lib/kasumi/profiles/operator.json create-collection invoices.json`. `kasumictl --profile` selects administration for an administrative command and the data CLI for any other; `--config <client.json>` still takes an explicit admin client file.

### Installations from before the split

An installation initialized before this change has one generated tenant credential: `profiles/default.json` is the tenant `administrator` with read, write, admin and audit, and every profile shares `profiles/client.pem`. It keeps working unchanged. To give it the layout above, stop `kasumid` and the `profiles/default.json` watcher, then run:

```sh
kasumid maintenance split-credentials /var/lib/kasumi/kasumi.json
```

The command removes document write from the tenant policy's tenant-wide `administrator` grant and grants `application` read and write; other grants are kept. It creates the application and operator families and the operator's and the Control profile's own client certificates, publishes `profiles/operator.json`, rewrites `profiles/default.json` and its token for the application (same certificate, so a client that rereads the token moves over without changes), moves `profiles/control.json` to its own certificate (its credential is unchanged), removes the stopped watcher's renewal journal and revokes the old family. It journals the new families in `profiles/credential-split.json` first, so rerunning it after any interruption finishes the same split; on an installation that is already split it changes nothing. Afterwards start `kasumid`, restart the `default.json` watcher, start one for `operator.json`, and move any administrative tooling that used `default.json` or its token (an `admin-client.json`, backup commands) to `operator.json`. Until it runs, the old installation keeps the old risk: whoever holds the application's credential administers the tenant.

### Installations from before certificate binding

An installation initialized before certificate binding accepts its native tokens from any admitted client certificate and on MCP. It keeps working unchanged. To bind it, stop `kasumid` and every credential watcher of a profile in `profiles/`, then run:

```sh
kasumid maintenance bind-credentials /var/lib/kasumi/kasumi.json
```

For every profile in `profiles/` whose family is native and unbound, the command creates a family with the same specification bound to the certificate that profile presents, publishes its token and profile in place, removes a stopped watcher's renewal journal of the old family and revokes the old family. It writes `profiles/mcp.json` and `profiles/mcp.token` with an MCP credential for the application's principal, then sets `auth.mcp_audience` and `auth.require_certificate_binding` in `kasumi.json`. It journals every family in `profiles/credential-binding.json` first, so rerunning it after any interruption finishes the same migration; on a binding installation it changes nothing. Afterwards start `kasumid` and the watchers (the MCP watcher with the Control profile), and give MCP clients `profiles/mcp.token`. Profiles outside `profiles/`, and copies of profiles, still name unbound families that the binding installation now refuses: issue them bound credentials with `credential create` and revoke the old families. Until the command runs, the installation keeps the old risk: a copied token works from any certificate the CA issued, and a native token works on MCP.

### Client certificate admission

A new installation's native and administrative listeners admit a client certificate only if the installation CA issued it (chain, validity and client-authentication usage, as before) and its SHA-256 pin is listed in `tls/client-pins.json`. Both listeners name that file as `client_certificate_pins` in `kasumi.json`; the installer lists the three generated client certificates under their names (`client`, `operator-client`, `control-client`). An unlisted certificate fails the TLS handshake before any request is read. MCP takes no client certificate and is unaffected.

```sh
kasumid client-certificate list /var/lib/kasumi/kasumi.json
kasumid client-certificate enroll /var/lib/kasumi/kasumi.json /path/new-client.pem reporting
kasumid client-certificate remove /var/lib/kasumi/kasumi.json /path/old-client.pem
kasumid client-certificate remove /var/lib/kasumi/kasumi.json SHA256_PIN_HEX
```

`enroll` accepts only a certificate the listeners would verify anyway: issued by their `client_ca`, currently valid, for client authentication. `remove` takes the certificate or its 64-digit pin. Both edit the file only. Send `kasumid` SIGHUP (or restart it) to apply them: the reload rereads certificates, keys, CAs and allowlists together, and a missing or malformed allowlist refuses the whole reload and keeps the previous generation (a TLS reload failure is logged as `tls_reload_failed`). The same file fails startup. After a reload, every new handshake is checked against the new list, and sessions cannot resume across it. Connections that were already established drain within the listener's drain limit, so in-flight work may finish: removal is not instantaneous request revocation. When a certificate is compromised, remove it and also revoke the credential families that used it (`kasumid credential revoke`).

`maintenance rotate-certificates` admits each replacement client certificate before installing it and retires the certificates it replaced, by name, once the profiles are updated. `maintenance split-credentials` admits the certificates it creates.

A listener that names no allowlist checks the CA only, as an installation from before this change does; such an installation keeps working unchanged. A named file that lists nothing admits no one. To turn admission on for an older installation, run `kasumid client-certificate enable /var/lib/kasumi/kasumi.json`: it lists the certificate of every profile in `profiles/` in `tls/client-pins.json`, then names that file on both listeners. Rerunning it after an interruption finishes the same change. Enroll any other client certificate (copied profiles, scrapers, other hosts) first, then restart `kasumid`, which enforces the list from then on. Until then the older installation keeps the CA-only risk: any certificate the CA ever issued is admitted until it expires.

If the list no longer admits the certificates you administer with, the listeners still serve everyone listed, and the file is local: `enroll` the certificate again and send SIGHUP. No network authentication is involved.

Generated client profiles use current `format: 2` with an explicit `principal`.
Rust applications load them through `kasumi_client::ClientProfile`, compare the
exact profile-file SHA-256 and database binding against their separately signed
runtime, and reread the separate bearer file for each request. See the
[native client example](api.md#native-grpc). Earlier client-profile files are
rejected; issue current credentials and profiles before changing a consumer to
this format. This does not alter an installed tenant or its stored documents.

MCP accepts preconfigured local bearer tokens over TLS. Supply `Authorization: Bearer <token from profiles/mcp.token>` and the current MCP protocol headers. MCP tokens have their own audience (`auth.mcp_audience`): MCP refuses native tokens, and the native listeners refuse MCP tokens. A Control administrator issues further MCP credentials with `credential create` and a request whose `audience` is `mcp`. On an installation from before audience separation, MCP takes the application's native token (`profiles/default.token`) until `maintenance bind-credentials` runs. Both OAuth protected-resource discovery URLs return 404, and authentication challenges contain only `Bearer`. Discovery metadata and `resource_metadata` challenges are advertised when an external OAuth provider is installed through `auth.source.kind = "external_oauth"`.

Local credentials expire after one hour. Keep each client credential file renewed:

```sh
kasumid credential watch /var/lib/kasumi/profiles/default.json
kasumid credential watch /var/lib/kasumi/profiles/operator.json
kasumid credential watch /var/lib/kasumi/profiles/control.json
kasumid credential watch /var/lib/kasumi/profiles/mcp.json /var/lib/kasumi/profiles/control.json
```

An MCP token cannot reach the administrative listener, so the Control profile, the second argument, renews it.

The watcher saves a renewal identity before dispatch and atomically replaces the token file after a verified native response. It retries uncertain transport outcomes with the same identity. A restarted watcher renews immediately. A credential that expired while kasumid was down recovers online with the same identity when kasumid returns, if it is the family's latest credential, the family is unrevoked, and it expired less than 24 hours ago ([credential lifetime](credential-lifetime.md#online-recovery-of-credentials-that-expired-during-an-outage)). Otherwise the watcher exits and names `recover-existing-credentials`. Clients must reread token files per request. Renewal does not extend any existing request's deadline. Stopping a watcher does not revoke its family; use the explicit revocation command.

Create a credential from a private Control profile and a JSON specification:

```sh
kasumid credential create /var/lib/kasumi/profiles/control.json /path/create-credential.json /var/lib/kasumi/profiles/reporting.json /path/reporting-client.pem /path/reporting-client-key.pem
kasumid credential status /var/lib/kasumi/profiles/control.json FAMILY_UUID
kasumid credential revoke /var/lib/kasumi/profiles/control.json FAMILY_UUID
```

The certificate and key name the client certificate the new profile presents. A native credential is bound to it: the CLI sets `client_certificate_sha256` to its SHA-256, or checks that the request already names it. On a binding installation a native credential without a binding is refused, so the administrator names the recipient's certificate and never binds the credential to its own connection. Enroll a new certificate in the client pin allowlist first. An MCP request (`"audience": "mcp"`) takes no certificate.

The specification contains `family_id`, `principal`, `tenant`, `resource`, `scopes`, and `lifetime_seconds` (1–3600, default 3600). Use a new UUID for `family_id`. Read the exact resource from the generated tenant profile. Scopes are `read`, `write`, `admin`, and `audit`; current database RBAC still determines effective access. Reusing a family UUID with different specifications is rejected. Revocation is permanent and fences already-running requests at their subsequent authorization or response-release checks. Revoking the credential used for the operation can suppress its own acknowledgement; another Control credential can inspect the durable result.

# Snapshot archive form

A standalone tenant's periodic snapshot (every 5,000 journal entries) stores its
logical state and refers to the audit archive chain that state depends on. Two
forms exist:

| Form | Written by | Read by | Archive chain |
|---|---|---|---|
| `KASUMIL1` (by reference) | `serve` by default | this release and later, when the tenant reopens its own snapshot | verified in place in `tenant-audit-archives/` |
| `KASUMID1` (embedded) | `serve --local-snapshot-archive embedded`, and every earlier release | every release | copied into each snapshot |

```sh
kasumid serve /var/lib/kasumi/kasumi.json [--local-snapshot-archive reference|embedded] [--storage-compaction-growth-percent 101-200]
```

Options may come in any order. `serve` logs the form it stores in its
`serve_options` event. Every other `kasumid` command (maintenance rotations,
credential and administrator recovery, local recovery, tenant staging, the
audit-cache move) keeps each tenant's stored form: it converts nothing in
either direction, so it is safe at any point below.

With `KASUMIL1` the tenant archive cache, `tenant-audit-archives/` under the
persistent directory (or the configured `tenant_audit_cache`), is part of what
a reopen needs. Never delete or move files there by hand; use
`kasumid maintenance move-tenant-audit-cache`. A missing or corrupt segment
makes that tenant's reopen fail closed, rewriting nothing, until the segment is
restored from the tenant's external archive destination or a copy of the
persistent directory.

For a deliberate two-step rollout, first install this release with
`--local-snapshot-archive embedded`: stored snapshots stay `KASUMID1` and going
back is a plain binary swap. Then drop the option, and each tenant's next
snapshot is `KASUMIL1`.

To roll back to a release that cannot read `KASUMIL1`:

1. Start `serve` once with `--local-snapshot-archive embedded`. Each tenant that
   reopens from a `KASUMIL1` snapshot appends one Blank entry (its revision
   advances by one) and durably publishes a `KASUMID1` snapshot before it
   serves, logging `embedded_snapshot_replaced_reference`. This needs free disk
   for one embedded snapshot per such tenant and runs outside the bootstrap
   gate, so other tenants open meanwhile. If capacity refuses it, the tenant
   serves on its `KASUMIL1` snapshot and logs `embedded_snapshot_not_published`.
2. Wait until every tenant serves and has logged the conversion, with no
   `embedded_snapshot_not_published`. Only then stop and install the older
   release.

A release that cannot read `KASUMIL1` refuses such a tenant at open
(`unsupported tenant snapshot bundle format`) and rewrites nothing: reinstall
this release and repeat step 1. A crash during the conversion leaves the
`KASUMIL1` snapshot current until the `KASUMID1` one is published, and this
release reopens either.

# Operator maintenance

Stop the standalone server and drain clients before the following commands. They require exclusive installation and database ownership and record their operations in encrypted security storage:

```sh
kasumid maintenance rotate-wrapping-keys /var/lib/kasumi/kasumi.json
kasumid maintenance rotate-signer /var/lib/kasumi/kasumi.json
kasumid maintenance rotate-certificates /var/lib/kasumi/kasumi.json
kasumid maintenance move-tenant-audit-cache /var/lib/kasumi/kasumi.json /var/lib/kasumi/data/tenant-audit-archives
kasumid backup-operator-keys /var/lib/kasumi/kasumi.json /secure/offline/kasumi-keys
kasumid verify-operator-keys /secure/offline/kasumi-keys
kasumid recover-administrator /var/lib/kasumi/kasumi.json /var/lib/kasumi/recovered
```

Wrapping-key rotation retains previous generations and rewraps installed catalogs. Signer rotation retains previous verification keys. Certificate rotation retains the CA, replaces server and generated client keys and certificates, commits the new local Control certificate pin, and updates profiles inside the installation's `profiles` directory. Update any copied/external profiles using the returned pins before reconnecting. A failed rotation leaves a durable started event and can be rerun while the server remains stopped.

The tenant audit cache move copies the installed cache to the configured
`tenant_audit_cache`, verifies every local archive chain in the copy, switches
the stored placements and only then removes the old directory. Its procedure,
resume and rollback are in [operations](operations.md#moving-the-tenant-audit-archive-cache).

`kasumid maintenance export-service-audit` and `prune-service-audit` export
and prune a service audit that already refuses records; see
[recovering a node whose audit refuses records](#recovering-a-node-whose-audit-refuses-records).

Administrator recovery issues new private profiles for administrators in the current policies. It does not silently replace policy or change existing credential-family outcomes. It requires the installed encryption and signing keys. Run the renewal watcher for recovered profiles before their one-hour lifetime expires.

The `operator` directory contains plaintext wrapping keys, signing keys, and the CA private key. It is separate from ordinary encrypted data backups. The key-backup command copies the exact installed file keyrings, signer, and CA material, including file keyrings stored outside the default operator directory. It publishes an owner-only manifest after copying every dependency and verifies every digest and wrapping-key generation inventory. Retain the returned manifest digest independently with key escrow; verification compares against this inventory and does not authenticate an untrusted replacement inventory. The command requires local file keyrings; external KMS keys require their provider’s backup procedure. Store this backup separately on a trusted encrypted host. Retain all generations needed by completed data backups. These facilities protect data against storage disclosure while trusting the host running Kasumi; possession of the operator keys and stopped installation is administrative authority.

# Local data recovery

The first release uses `KASUMI-KVROOT005`; development roots through ROOT004
are unsupported. Create fresh storage with this build. See the
[first-release format](operations.md#first-release-storage-format-kasumi-kvroot005).

The generated installation installs the filesystem backup destination `local` beneath `backups`. Create and verify a full backup using the native administrative backup API and retain the exact returned `FullBackupCheckpoint`. Retain the source application wrapping keyring separately. Verification requires every encrypted dependency; a root object alone is not a complete backup.

Stop the installed server before restoring. Prepare a JSON request containing a fresh `operation_id`, `tenant`, `expected_active_incarnation`, a fresh `target_incarnation`, the exact verified `checkpoint`, the exact source `source_purpose`, `source_keys`, `source_principal`, installed `destination`, and `phase_timeout_ms` (1–600000). For standalone backups, `source_purpose` contains `kind: "Standalone"`, the original `installation_id`, `tenant`, and `incarnation`. `source_keys` uses the same file-keyring configuration shape as the source tenant's `keys`. `source_principal` must have administrator authority in the backed-up policy.

```sh
kasumid local-recovery start /var/lib/kasumi/kasumi.json /secure/restore-request.json
kasumid local-recovery status /var/lib/kasumi/kasumi.json OPERATION_UUID
kasumid local-recovery resume /var/lib/kasumi/kasumi.json OPERATION_UUID
kasumid local-recovery stop /var/lib/kasumi/kasumi.json OPERATION_UUID
```

`start` durably records the request and runs its phases. Retry with exactly the same operation and inputs, or use `resume` after interruption. Each invocation obtains fresh independently bound source and target authorization from exclusive local operator ownership. No expired source bearer token is required. The encrypted coordinator retains original phase identities and exact inputs and resolves their results on resume.

Materialization writes an isolated `data/generations/<target-incarnation>/node.kv`. Completion precedes the atomic activation decision. Activation permanently retires the former local generation and selects one target; from that point recovery proceeds forward. `stop` is accepted before activation, persists the target's permanent stop, drains storage ownership, and deletes only files bearing the matching generation binding. Unrelated files prevent cleanup and remain untouched. The original `data/node.kv` retains installation, Control, security, and permanent recovery records and is never deleted by this cleanup.

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
kasumid audit prune /var/lib/kasumi/profiles/control.json /secure/audit-page-last.json THROUGH_INDEX /secure/audit-prune.json
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
`security_audit_archives`, `verify_security_audit_archive` and
`prune_security_audit` on `KasumiAdminClient`. Its page `.cursor()` returns the
next exact cursor or `None` at completion; an export requested without a cursor
first fixes its range from a status response. The client rejects changed
stream/end positions, missing sequence numbers, and oversized responses. Archive
listing reports dependencies; the verification method returns a
`VerifiedSecurityAuditArchive` only after the server reads and authenticates the
exact encrypted segment. Listing and verification delete nothing, and no command
retires the archives' wrapping keys.

Events that identify no client are counted rather than recorded one by one:
TLS connections to a listener that takes no client certificate (MCP), failed
TLS handshakes, refused tokens, and requests refused before any identity is
verified, such as a bad MCP `Origin`. In each minute the first such event of
each kind from each peer address is recorded, for up to 64 addresses, and
events from further addresses share one entry per kind. When the minute
ends, one `events_counted` record per entry carries the exact number of the
other events and the first and last times they were observed. These records
stop at 75% of the hot budget, where archiving starts; above it such events
are only counted, which keeps the rest of the hot log for authentications,
accepts with a client certificate and administrative records while archives
cannot drain. Counts not yet written are lost if the process crashes.
Releases that predate `events_counted` records cannot read them: they refuse
to open a service audit whose hot log holds one. Archives are pruned only by
an operator, as described below: once `archive_bytes` is used, the hot log
cannot drain, and when it is full every request that needs a record fails
with `audit_unavailable` until archives are pruned or the budget is raised.
Alert well before that on `kasumi_service_audit_archive_bytes` and
`kasumi_service_audit_archive_budget_bytes`.

### Pruning exported archives

Archives are pruned only after they are exported. A Control administrator
prunes them online; the operator of a stopped installation can also prune them
offline ([recovering a node whose audit refuses records](#recovering-a-node-whose-audit-refuses-records)).
To prune online:

1. Export the whole range with `kasumid audit export`, page by page, and keep
   every page somewhere safe.
2. Optionally run `kasumid audit verify` on each segment to prune.
3. Run `kasumid audit prune` with the last export page and `THROUGH_INDEX`.
   Segments below that index are pruned. The newest segment is never pruned,
   so `THROUGH_INDEX` is at most `archive_segments - 1` from `audit status`.

The CLI builds the request from the page's own anchors and journals it in an
`*.audit-attempt.json` beside the output before dispatch, like a page request.
After an uncertain outcome, repeat the same command: it resends the journaled
request, and a request whose range is already pruned prunes nothing more and
reports zero segments. A published result is never overwritten.

Before anything is deleted, the server checks the request:

- The export must reach past the last pruned record. Its previous-record
  digest, snapshot head and captured tail must match stored history.
- The pruned roots must chain to each other and to the first retained root.
- The last pruned segment is read and authenticated, and its last record's
  exact digest becomes the anchor of retained history.
- The original credential and the current Control policy are checked again
  immediately before the commit, so a credential revoked while the archives
  were read refuses the prune itself.

The checks prove that the export agrees with stored history at its end. They
do not prove that every earlier page was saved, so keep the pages.

The prune and one `archive_pruned` audit record commit together. The record
carries the administrator's principal, tenant and request id, the first
retained index and sequence, the digest of the last pruned record, and the
number of segments and ciphertext bytes pruned. Other records stop 8 KiB short
of the hot budget, so this record fits even after they are refused.

Every pruned root stays in the security store, and `audit archives` still
lists it. `audit verify` of a pruned index reports `not_found`; verifying the
first retained index still checks its link to the pruned predecessor's root.
`audit status` reports the pruning in `retired`:

| Field | Meaning |
| --- | --- |
| `index` | First retained segment. |
| `sequence` | First retained record. |
| `record_sha256` | Digest of the last pruned record, record `sequence - 1`. |
| `deleting_from` | First pruned object not yet deleted, or `null` when deletion is complete. |

A new export starts at `retired.sequence`, anchored by `retired.record_sha256`.
That digest is the `sha256` of the last pruned record in your export, so the
saved pages and the retained history can be checked to meet exactly. A cursor
that still needs a pruned record fails with `cursor_expired`; start a new
export. A cursor whose next record is the first retained one continues.

Objects are deleted 64 at a time, each only while its bytes still match its
root. `archive_bytes` drops only after a chunk's deletions are durable. A
prune request deletes for up to about 10 seconds; the maintenance worker
deletes the rest, and `retired.deleting_from` shows what is left. After a
crash or a failed deletion, the pruning stays committed and deletion resumes on
the next maintenance turn. A new prune waits for an earlier one's deletions.

Only filesystem destinations are pruned: the default `audit-archives/`
directory or an external `filesystem` destination. With an S3 destination the
prune is refused with `unavailable` before anything changes; raise
`archive_bytes` instead.

Set `security_audit.prune_minimum_age_days` in the runtime configuration to
refuse any prune that would remove a record younger than that many days. The
default 0 disables the floor. Every pruned record's timestamp is checked,
because timestamps follow the host clock and need not increase with sequence.
Changing the floor needs the configuration file and a restart, not just a
credential.

Releases that predate pruning refuse to open a service audit whose hot log
holds an `archive_pruned` record. Once that record is archived they open
again, but they cannot export pruned history or resume an interrupted
deletion.

### Recovering a node whose audit refuses records

`kasumid audit prune` cannot rescue a node whose audit already refuses
records. The CLI's own TLS accept and authentication need records before the
request runs, and kasumid cannot even record its own start. Stop kasumid, then
export and prune offline:

```sh
kasumid maintenance export-service-audit /var/lib/kasumi/kasumi.json /secure/audit-request.json /secure/audit-export
kasumid maintenance prune-service-audit /var/lib/kasumi/kasumi.json /secure/audit-export/page-00000041.json THROUGH_INDEX /secure/audit-prune.json
```

Like the other `maintenance` commands, both take the stopped installation's
exclusive ownership and refuse to run while kasumid holds it. Unlike most of
them, they also run while a local recovery is pending, because completing that
recovery records audit events too. Their outputs need absolute paths beneath
an existing owner-only directory, and are never overwritten.

`export-service-audit` takes the request of `kasumid audit export`;
`{"cursor":null,"limit":1024}` starts a new export. It writes every page of that
range into a new owner-only directory, `page-00000000.json` onwards, in the
format of `kasumid audit export`. Without a cursor, the export starts at the
first retained record and ends at the last record when the command starts. The
command prints the number of pages and records, the last page, and the
`audit status` from its start. `THROUGH_INDEX` is at most that status's
`archive_segments - 1`. The export reads only and records nothing, so it runs
on a full log. If it stops early, run it again into a new directory, from the
start or from the last page's cursor.

`prune-service-audit` builds the request from the page as `kasumid audit prune`
does, and runs the same checks before anything is deleted: the export's
anchors, the chain of the pruned roots, the last pruned segment, and
`prune_minimum_age_days`. The stopped installation's exclusive ownership
stands in for the Control credential and is checked again just before the
commit. The `archive_pruned` record names principal `offline-operator` and the
Control tenant, and it fits in the 8 KiB of the hot log reserved for it. The
result is published to the output in the format of `kasumid audit prune`.

The command then deletes every pruned object and archives the hot log as the
maintenance worker does, down to half its budget, so kasumid starts with room
to record. It prints the result and the final status. If the freed archive bytes cannot hold the hot log's
next segment, it fails after the prune has committed. Then either prune
through a later index with a new output, or raise `archive_bytes`. After a
crash, repeat the command with a new output: a range already pruned prunes
nothing more, and deletion and archiving resume.

Raising the budgets is the other way out, for example before the pages can be
stored safely. Raise `archive_bytes`, and also `hot_bytes` if the hot log is
full, then restart. Once the hot log drains, export and prune, then lower the
budgets again. Reopening requires the bytes in use to fit them.

## Backup sessions

Create a backup with the generated tenant operator profile:

```sh
kasumid backup create /var/lib/kasumi/profiles/operator.json local /secure/full-backup.json
```

The parent directory must already be private and owned by the operator. Keep the
checkpoint together with its `*.backup-attempt.json` journal. Retry the same
command after an uncertain result to resolve the original session. The
[backup session runbook](backup-sessions.md#operator-commands) documents status,
verification, permanent abort outcomes, bounded cleanup passes, and key retention.
Use the resulting checkpoint as the exact source checkpoint in a stopped local
recovery request.

The first-release directory owner requires `persistent_disk.max_open_directories`
explicitly; the generated installed policy uses 256 directory owners alongside
1,024 file owners. There is no default or legacy field alias. The inode ledger
uses one physical-identity key space for files and directories. The generated
100,000-file and 10,000-subdirectory limits bound census work and the separately
retained regular-file and subdirectory counts; they are not a combined
file/directory admission cap. Their admitted metadata sizes the generated
admission total ([node memory admission](admission.md)).

The required `--directory-policy` file contains exactly `extent_bytes` and `max_entries`, both positive integers. The generated persistent disk configuration retains these explicit values; there is no production default. `extent_bytes` is a per-directory allocated-byte ceiling reserved before managed file namespace effects. `max_entries` limits positive membership changes; deletion retains cleanup access. Supply values qualified for the installed filesystem and supported namespace operations. Numeric validation alone does not establish that qualification. This target proposal has not yet established a supported filesystem growth bound, so production namespace admission remains a release blocker.

The required `--file-allocation-policy` file contains exactly
`maximum_extra_extent_bytes`, an integer from zero through `i64::MAX`. There is
no production default. Kasumi reserves the filesystem-unit-rounded allowance
for each regular file in addition to its rounded logical length, including
empty and closed files. Census reconstructs this standing promise; deletion
releases it after verified retirement. Supply a bound qualified for allocation
above EOF across the supported filesystem operations. Zero explicitly asserts
that no extra allocation occurs. The allowance consumes disk budget, not cache
memory, and does not change the permitted logical EOF.
