# Using Kasumi

Embedded Rust, native gRPC and MCP use the same policy, mutation, query and
receipt implementation. A tenant is selected by trusted embedding context or
verified OAuth claims. A document request contains a collection and ID; it does
not choose a tenant or gain permissions from a tool description.

Use [runtime administration](administration.md) to create schemas/indexes, manage
policy, provision tenants, back up/restore or change membership. Network clients
use the separate native administrative endpoint; these operations are absent
from MCP. Embedded callers use the authorized administrative Rust methods.

## Embedded Rust

The workspace crates are `kasumi-types`, `kasumi-store` and `kasumi-engine`.
Enable `serde_json`'s `arbitrary_precision` feature in the embedding application
and parse exact numeric input from its original JSON text. Constructing a value
through an `f64` first has already lost precision.

Storage installation and reopening are separate operations. Retain the exclusive
node and installation owners through any cancelled acquisition and await
`NodeStore::shutdown` after the tenant and consensus workers drain. Shutdown
closes new access, joins initializers and explicitly closes the durable database;
a retained drain result requires the same owner to remain alive for retry.
A fresh physical node uses
`NodeStore::create_new(path, installed_database_id, persistent_disk, scratch_disk)`;
an installed node uses `NodeStore::open_existing` with the same immutable identity
and explicit `Arc<NodeDisk>` and `Arc<ScratchDisk>` owners. Construct `NodeDisk`
from an explicit `NodeDiskConfig` and completed bounded census of preinstalled
private roots on one filesystem. Database paths never enroll their parent
implicitly. Persistent roots must be disjoint from each other and from scratch. Missing files, catalogs and genesis records never authorize repair
or initialization during ordinary startup.

| Domain | Fresh installation | Existing installation |
| --- | --- | --- |
| Service audit catalog | `TenantStore::initialize_catalog(..., StorageAccess::security_audit())` | `TenantStore::open_existing(..., StorageAccess::security_audit())` |
| Audit stream | `SecurityAudit::initialize(store, retention_budget, admission)` | `SecurityAudit::open(store, retention_budget, admission)` |
| Application and custody catalogs | `TenantStorageSet::initialize_catalogs(node, tenant, application_provider, custody_provider, access)` | `TenantStorageSet::open_existing` with the same arguments |
| Standalone database | `open_local_with_incarnation` with its explicit initial policy, limits and incarnation | `open_existing_local` with its installed incarnation |

Both application and custody providers are required and must use independent
wrapping policies and actual keys. Production single-catalog constructors accept
only service audit, signer trust and target journal purposes. Application and
custody domains always use the paired storage owner. The secure standalone CLI
owns initialization of its installation, Control topology, credentials and client
profiles; see [standalone operation](standalone.md).

`TransitConfig` contains an HTTPS `endpoint`, `mount`, `key_name`, an explicit
renewable `credential` source, a required nonempty `ca_pem` bundle, optional
`namespace`, and `derived`
matching the Transit key. Use a different key and authority for each application,
custody and service domain. Every primary and historical Transit provider uses
only that pinned CA bundle; system certificate roots are disabled. Installed
Transit configuration requires an absolute `ca_certificate` path.
`FileCredentialSource` reads the installed private
credential path for requests; a constructor-time token snapshot or environment
fallback is not a credential source. The provider performs fresh decrypt probes
for retained key dependencies. See [Transit compatibility and permissions](COMPATIBILITY.md).
The audit domain remains separately accessible after a customer key is revoked;
its configured hot/archive budgets and required audit writes still apply.

`initial_policy` contains explicit grants; the default policy denies everyone.
On reopen, persisted bootstrap and policy remain authoritative. Changing the
function arguments cannot change an existing tenant's grants or deployment mode.
Keep one live database per store and share its `Arc` among callers.

The trusted embedding application authenticates the caller before constructing
`RequestContext { authorization, principal, tenant, scopes, request_id }`, or
`RequestContext::trusted(tenant, principal, scopes)` for an already authenticated
service identity with a fresh request ID. Its scopes are a `BTreeSet<Action>`;
current tenant/collection grants must also allow the action.
Create a collection once with an admin-authorized context using
`database.administer(context, Operation::CreateCollection(definition)).await`.
The `CollectionDefinition` JSON for the examples below is:

```json
{
  "name": "docs",
  "write_mode": "mutable",
  "retention_class": "operational",
  "schema": {"type": "object", "properties": {"amount": {"type": "number"}}},
  "indexes": [{"name": "amount", "fields": [{"path": "/amount", "kind": "number"}]}]
}
```

The same definition can be supplied to native `CreateCollection` or saved as the
JSON file used by `kasumictl create-collection`. With an authorized `context` and
that existing collection:

```rust
use kasumi_types::{Filter, MutationBatch, QueryRequest};

// Parse exact numbers from JSON text; an f64 would already have lost precision.
let body: serde_json::Value = serde_json::from_str(r#"{"amount": 9007199254740993.123456789}"#)?;
let batch = MutationBatch::with_key("invoice-creation-42").insert("docs", "invoice-42", body);
let receipt = database.mutate(context.clone(), batch).await?;
let document = database.get(&context, "docs", "invoice-42").await?; // Option<AdmittedOutput<Document>>
let large = database
    .query(&context, QueryRequest::new("docs").filter(Filter::new().gte("/amount", 10)))
    .await?;
let outcome = database.operation_receipt(&context, "invoice-creation-42").await?;
```

The same batch as JSON is
`{"idempotency_key":"invoice-creation-42","operations":[{"op":"put","collection":"docs","id":"invoice-42","body":{"amount":9007199254740993.123456789},"expected":"absent"}]}`.
See the [query language](query-language.md) for every query and write form.

`get` returns `None` for a missing document; a missing collection or denied
access is an error. A present document is an `AdmittedOutput<Document>` containing
an owned document and its retained memory charge. Borrow the document through `as_ref()` or dereference;
there is no raw owned extraction. `get_shared` returns an optional immutable
`kasumi_types::SharedDocument`, avoiding a JSON-body clone. Cloning this handle
retains the same document and admission owner, including decoded archive
custody for a cold read; it does not expose an `Arc<Document>`. Deliberately
deep-cloning a borrowed `Document`, or serializing it into another allocation,
creates caller-owned memory requiring separate accounting.

Both methods use the same authorization, consistency, key-access and audit
checks. Previously returned owned/shared plaintext cannot be recalled after
revocation, and retaining a result does not renew authority. Completed point
reads release their operation count and work registration before public
handoff. A held result therefore does not keep shutdown waiting for that read,
but its memory charge remains until the owned result or last shared clone drops.
This point-ownership implementation and its SDK bridge pass the selected
Engine, API, SDK, allocation and transport checks in the
[evidence ledger](evidence/disk-backed-cache-20260930/README.md).
These establish no performance result or complete retained-source memory bound.
Hot-source and archive-decoder sizing still include provisional allowances.

Before closing, await `database.shutdown()`: it stops admission, drains Raft
storage workers and pending query/proposal work, stops the key monitors, and
releases owned keys and resident state. A canceled shutdown can be awaited again. To reopen the same
node file, shut down every database using it, then await the shared
`audit.shutdown()`. Drop all database, tenant-store, audit and node-store handles
before reopening. Previously returned document handles can remain alive.
Network deployments should use `kasumid`'s configured runtime, which
also provides the separate control/security stores and shared admission limits.

## Native gRPC

The authoritative wire schema is
[`kasumi.proto`](../crates/kasumi-client/proto/kasumi.proto), package `kasumi.v1`.
Rust applications should start with the high-level `kasumi_client::Kasumi`
handle. It reads the bearer file for every operation, applies a default deadline
(30 seconds) and bounded response decoding, and returns ordinary owned values:

```rust
use kasumi_client::prelude::*;
use serde_json::json;

let db = Kasumi::from_profile("/var/lib/kasumi/profiles/default.json").await?;
db.mutate(&MutationBatch::new().insert("invoices", "inv-1", json!({"status": "open", "amount": 42})))
    .await?;
let invoice: Option<Document> = db.get("invoices", "inv-1").await?;
let page = db
    .query(&QueryRequest::new("invoices").filter(Filter::new().eq("/status", "open")).limit(20))
    .await?;
let next = db.next_page(&page).await?; // None at the end
match db.query(&QueryRequest::new("invoices").filter(Filter::new().eq("/note", "x"))).await {
    Err(error) if error.code() == Some(ErrorCode::IndexRequired) => { /* declare an index */ }
    other => { other?; }
}
```

`insert`, `upsert`, `replace`, `patch` and `delete` write one document;
`collections` lists schemas and indexes. `get_as::<T>` and
`QueryPage::decode::<T>` deserialize bodies into application types. The same
operations, coherent snapshots and receipt resolution are available to scripts
and other languages through `kasumictl --profile`; see the
[command-line client](#command-line-client). `ClientError::code()` returns Kasumi's own error code, which is more
specific than the gRPC status. `mutate` resends the identical batch after
`UNKNOWN_OUTCOME` or `UNAVAILABLE` until its deadline; the idempotency key makes
that safe. A resend can be refused before the database looks up its receipt,
for example by admission or an expired credential, so once an attempt was
uncertain any later failure is reported as `UNKNOWN_OUTCOME` with the later
reason. All attempts within one mutation use the same credential snapshot
to preserve the original principal. Credential renewal is observed by the next
operation. `Kasumi` talks to one endpoint; replicated deployments with several
members use the routing `KasumiClientPool`.

Generate clients for other languages with the normal Protobuf toolchain, or use
`kasumi_client::proto::kasumi_data_client::KasumiDataClient` directly.
The low-level `KasumiClient` (also `Kasumi::client()`) exposes `get`, `query`,
`read_snapshot`, `mutate`, staged transactions and read leases with explicit
bearer tokens, decode limits and deadlines, constructed with
`KasumiClient::connect(&KasumiClientConfig)`. The required configuration contains
the HTTPS `endpoint`, `identity` (`kasumi_transport::TlsIdentity`),
`trusted_ca_pem` and nonempty `server_certificate_pins`. There is no unchecked
channel constructor. Every method takes the
current bearer token explicitly. The client preserves structured native status
errors and performs no implicit retries or redirects.

For an already admitted decoded document,
`AdmittedResponse<Document>::into_shared_document()` transfers the existing SDK
owner into a `SharedDocument` without cloning the body.

For an installed standalone credential, applications can load the exact private
profile through `kasumi_client::ClientProfile`, without linking the server crate:

```rust
let (profile, profile_sha256) = kasumi_client::ClientProfile::load_with_sha256(
    std::path::Path::new(profile_path),
)?;
ensure!(profile_sha256 == signed_profile_sha256, "profile pin differs");
profile.require_database_binding(
    signed_tenant,
    signed_incarnation,
    signed_principal,
    signed_family_id,
)?;
let client = kasumi_client::KasumiClient::connect(&profile.connection(false)?).await?;
let bearer = profile.bearer()?; // Reread for each request after credential renewal.
```

`Kasumi::from_profile` performs the same load without the binding checks; use
the explicit form when an independently signed runtime pins the profile.

The current profile has `format: 2` and requires `principal`, `tenant`,
`family_id`, a database or Control `resource`, TLS identity and CA file paths,
native endpoint, certificate pin, and a separate renewable bearer file. The
loader hashes the exact owner-only profile bytes read from one regular inode;
callers compare the digest and all expected binding fields with an independently
signed runtime. A profile digest alone does not authenticate the files named by
the profile or qualify a release. Native TLS verifies the installed CA, client
identity and server leaf pin. The native service verifies current bearer claims,
credential family, resource, scopes and policy on each operation. Format 1
profiles are rejected; issue current profiles before using this API.
Connect to the native data endpoint using TLS 1.3 and an approved client
certificate. In Rust, `kasumi_transport::grpc_channel` takes the HTTPS origin,
`TlsIdentity`, trusted CA PEM and a set of SHA-256 server leaf-certificate pins.
It returns the channel accepted by the generated client.
The server listeners, peer transport and SDK use this one shared implementation;
the SDK does not depend on `kasumi-server` or storage internals.

Every call also supplies `authorization: Bearer <access token>` metadata.
Kasumi verifies signed JWT access tokens against its configured issuer, audience,
JWKS and allowed algorithms/types (`at+jwt` in the example configuration).
Claims `sub`, `tenant`, mandatory signed `kasumi_resource`, and space-delimited `scope` select the principal, tenant, exact incarnation/purpose and scopes. See [credential resources and lineage](credential-resources-lineage.md); there is no token fallback across incarnations. Data scopes are `kasumi:read` and `kasumi:write`; administrative calls
require `kasumi:admin` and their current policy grants. A service certificate
alone does not grant document access.

| RPC | Request | Result |
| --- | --- | --- |
| `Get` | `collection`, `id` | Optional document: ID, version and exact UTF-8 `body_json` bytes; absent when the document does not exist |
| `Query` | UTF-8 `query_json` bytes ([query language](query-language.md)) | Snapshot revision, rows or aggregate groups as JSON bytes, and optional cursor |
| `ReadSnapshot` | UTF-8 `request_json` bytes: document keys and queries | One coherent generation as UTF-8 `response_json`, including read assertions' source versions/epochs |
| `ReadRestoreLineage` | Expected current incarnation and an existing collection | Opaque authenticated historical commitments under current collection Read permission |
| `Mutate` | UTF-8 `batch_json` bytes, using the batch shape above | Revision and per-document versions |
| `AdmitMutationCapacity` | UTF-8 `request_json`: exact `expected_incarnation` and complete future `batch` with current Snapshot assertion | Exact input digest and current tenant, incarnation, revision, policy and schema epochs |
| `Collections` | Empty message | Authorized collection definitions as JSON bytes |
| `Receipt` | `idempotency_key` | Committed receipt, rejected database error, or no retained outcome |
| `BeginStagedTransaction` | `BeginStagedTransaction` as UTF-8 JSON | Reserved permanent identity and upload budget |
| `AppendStagedChunk` | `AppendStagedChunk` as UTF-8 JSON | Durably accepted invisible chunk |
| `FinalizeStagedTransaction` | `StagedTransactionRef` as UTF-8 JSON | One atomic commit revision, empty versions map |
| `StopStagedTransaction` | Full original `BeginStagedTransaction` plus fresh `admission` assertions as UTF-8 JSON | Original permanent status, released only under current attempt authority |
| `StagedTransactionStatus` | `StagedTransactionRef` as UTF-8 JSON | Manifest, received chunk indexes, expiry and permanent outcome |
| `OpenSnapshotLease` | `OpenSnapshotLease` as UTF-8 JSON | Principal-bound lease and coherent snapshot identity |
| `ReadSnapshotPage` | `ReadSnapshotPage` as UTF-8 JSON | Named documents/absence in `SnapshotReadResponse` |
| `ScanSnapshotPage` | `ScanSnapshotPage` as UTF-8 JSON | ID-ordered documents, collection epoch and `next_after_id` |
| `CloseSnapshotLease` | `lease_id` | Empty response |

`AdmitMutationCapacity` uses the Data listener and the caller's existing per-collection read/write grants. It checks the complete future Put/Delete batch against the hard 256-operation and 512-read bounds, current tenant operation/batch/document limits, installed schema, and immutable history rules. It executes no proposed write and reserves no future tenant storage. Applications call it for both the complete effect/phase batch and retained-intent batch before publishing a security intent or barrier, then retain the original business read assertions and returned Snapshot epoch assertion for atomic dispatch. Only an unknown applying version may be conservatively sized as `u64::MAX` and later replaced with its real native revision; that substitution belongs to the application owner. Limits changes advance the policy epoch and invalidate prior capacity admissions. Patch expansion requires retained source custody, so this admission endpoint requires complete resulting originals.


Do not convert these JSON byte fields through Protobuf's double-valued
`Struct`. Native errors carry the Kasumi error code in structured status details.
An authorized `kasumi-leader-node-id` hint refers to the operator-approved node
map; it is not a redirect URL. Tenant and control groups can have different
leaders. Follow [routing and outcomes](administration.md#routing-and-outcomes).

## Conditional transactions and immutable collections

`CollectionDefinition.write_mode` and `CollectionDefinition.retention_class`
are required v1 fields; `MutationBatch.read_set` is optional. A conditional batch verifies all its read dependencies against one
pre-write state, then atomically applies writes across that tenant's collections.
Reads from a separate earlier `get` or `query` are not automatically dependencies.
Use `Database::read_snapshot` or native `ReadSnapshot` to capture coherent inputs,
and `SnapshotReadResponse::read_assertions()` to fence them in the subsequent batch.

For expiry decisions, set the required `ReadSnapshotRequest.time_bounds` field to
`Some(ReadTimeBounds { not_before_ms, not_after_ms })`. Both millisecond bounds
are inclusive. A bounded read runs on the current Raft leader after a
linearizable barrier and returns `trusted_leader_time_ms: Some(...)` only when
the returned generation is still current and the leader's command admission
clock lies inside the bounds. A follower, inverted bounds, changed generation,
or clock outside the bounds rejects the read. Ordinary reads set
`time_bounds: None` and receive `trusted_leader_time_ms: None`; snapshot-lease
pages do not provide a time witness. For an active lease expiring at `E`, use
`[0, E-1]` after rejecting `E = 0`, and require the same document version as
the initial read. Use `[E, u64::MAX]` to prove expiry. The native client validates
the response witness against the requested bounds before decoding documents.

See [transaction contracts](transactions.md) for the exact assertion shapes,
closed trusted admission-time bounds, immutable collection rules and bounded
snapshot behavior.

For larger inputs, open a read lease and collect bounded pages from that lease.
Deduplicate the common snapshot assertion; retain every document and collection
dependency. Split the complete write/read set into `StagedChunk` values and build
`StagedManifest::from_chunks(&chunks)`. Begin with a stable transaction ID and
upload TTL, then append every chunk and finalize using
`StagedTransactionRef { transaction_id, manifest_digest }`, where the digest is
`staged_digest(&manifest)?.0`. All SDK calls take the current bearer token and
the typed request by reference; `close_snapshot_lease` takes the lease ID.

Unknown outcomes are resolved with the same principal, transaction ID and
manifest using status or identical finalize. Terminal identities never expire
or silently evict; the explicit permanent record quota must have capacity before
begin accepts upload payload. See [large transaction contracts](large-transactions-plan.md)
for resource limits, expiry, cancellation and snapshot lease invalidation.

## Command-line client

`kasumictl --profile <profile.json>` is a complete data client for scripts and
for languages without a native client. Run it as a subprocess, pass JSON
arguments inline, as `@path` or as `-` for standard input, and read exactly one
JSON document from standard output. It uses the same `kasumi_client` handles
as Rust applications: point reads, queries and writes go through `Kasumi`;
snapshots and receipt resolution go through `KasumiClientPool`. Pass only file
paths: the bearer file named by the profile is reread for each operation, and no
credential is accepted as an argument or environment variable.

```sh
kasumictl --profile <profile.json> [<option>...] <command> [<argument>...]
```

Options come before the command, in any order. A command line whose first
argument is `--profile` or another option below is a data command; any other is
administrative. Standard input can supply only one JSON argument per call.

| Command | Success `result` |
| --- | --- |
| `get <collection> <id>` | `{"document": {"id", "version", "body"}}`, or `{"document": null}` for a proven-absent document |
| `query <collection> [<filter>] [<flags>]`, `query --json <query> [--all]` | `{"revision", "rows", "aggregates", "more"}`; `more` reports another page, and `--all` reads every page of one snapshot into memory |
| `put`, `patch`, `delete` with `[--if absent\|any\|<version>] [--key <key>]` | As `mutate`, for a one-document batch |
| `mutate <batch>` | `{"idempotency_key", "request_digest", "receipt": {"revision", "versions"}}` |
| `read-snapshot <request>` | `{"snapshot": <SnapshotReadResponse>, "read_assertions": [...]}` |
| `resolve-mutation <batch> [--scope <scope>]` | `{"outcome", "idempotency_key", "request_digest", "scope"}` plus `receipt` when committed or `error` when rejected |
| `collections` | `{"collections": [<CollectionDefinition>...]}` |

`mutate` takes the complete typed `MutationBatch`, so one batch from standard
input can create documents with `"expected": "absent"`, update others at an
exact observed `{"version": n}`, carry `read_set` assertions, and apply all of
them atomically under the caller's `idempotency_key`. `request_digest` is
`MutationBatch::digest()`, the identity a retained receipt is matched against.
`receipt.versions` maps each `/collection/id` the batch wrote to the revision it
now has; both segments are JSON Pointer escaped (`~` as `~0`, `/` as `~1`). A
`put`, `patch` or `delete` without `--key` uses a fresh key, which its result
and failures report.

`read-snapshot` takes the native `ReadSnapshotRequest` (`documents`, `queries`
and an explicit `time_bounds`) and reads every named document from one
coherent generation: each entry has its exact `version` and body, or `null` for
proven absence. `read_assertions` is
`SnapshotReadResponse::read_assertions()`: the snapshot identity plus each
observed version or absence, ready to use as the `read_set` of the next batch.
The expected incarnation is the profile's database incarnation.

`resolve-mutation` takes the complete original batch, not only its key, and
reads the retained outcome without dispatching anything. It verifies the
receipt's request digest and its scope. Idempotency keys and their outcomes
belong to the principal that wrote them, so the lookup always uses the
profile's tenant and principal: the scope defaults to the profile's tenant,
incarnation and principal, and
`--scope '{"tenant":...,"incarnation":...,"principal":...}'` may differ only in
`incarnation`, to name the original incarnation after a restore; any other
difference is `invalid_request`. `outcome` is `committed` with the original
`receipt`, `rejected` with the retained `error` (classified as in the table
below), or `unknown` when no outcome is retained. `unknown` is never evidence
that the batch did not commit: resend the identical batch or resolve again
later, and never build a different batch for the same operation. A retained
outcome under the same key for a different batch or scope is a `conflict`. A
failed lookup, whatever its class, describes only the lookup and leaves the
batch as unresolved as before. Resolve every uncertain batch before the
application's credential changes principal: a new principal neither finds the
old outcomes nor replays the old keys. Receipts are permanent within the
tenant's `max_mutation_receipt_bytes` budget; see
[transaction contracts](transactions.md#atomic-read-dependencies).

Options are checked before anything connects:

| Option | Check |
| --- | --- |
| `--profile <path>` | Required. The installed client profile; it and its bearer file must be readable, owner-only files |
| `--expect-profile-sha256 <hex>` | SHA-256 of the exact profile bytes, as `ClientProfile::load_with_sha256` reads them |
| `--expect-tenant`, `--expect-incarnation`, `--expect-principal`, `--expect-family-id` | Given together; `ClientProfile::require_database_binding` compares them with the profile |
| `--timeout-ms <n>` | One deadline for the whole invocation, 1 to 3600000 (default 30000), starting when the arguments are parsed. It bounds reading `@path` and standard input, loading the profile, connecting and every request; an uncertain write is resent unchanged until it elapses, and nothing new is sent after it |

Supply the expected values from the application's own trusted configuration;
a profile cannot vouch for itself. A data command also requires a database
profile.

Success prints `{"ok":true,"result":...}` and exits 0. Failure prints
`{"ok":false,"error":{"class":...,"code":...,"message":...}}`, where `code` is
the database's own error code or `null`. Every failure of a `put`, `patch`,
`delete`, `mutate` or `resolve-mutation` whose batch was parsed adds
`idempotency_key`. The document is one line followed by a newline, and nothing
else is written to standard output.

| Exit | `class` | Meaning and next step |
| --- | --- | --- |
| 1 | `internal` | Unexpected client or response failure, or `CORRUPTION` on a read |
| 2 | `invalid_request` | The command line, a JSON argument or the request is invalid (`INVALID_ARGUMENT`, `SCHEMA_VIOLATION`, `INDEX_REQUIRED`), including arguments that are not UTF-8, a second `-`, standard input not closed before the deadline, or a `--scope` for another tenant or principal. Local mistakes are reported before the profile is read |
| 3 | `profile_rejected` | The profile or its bearer file is missing, unreadable, not owner-only or malformed, the profile is not a database credential, or it differs from an `--expect-*` check; nothing connected |
| 4 | `unauthorized` | The server refused the credential, or current policy refuses the operation (`UNAUTHORIZED`, `FORBIDDEN`). This includes any write to an `append_only` collection other than an absent create. `code: null` means the bearer file could not be read for the call itself |
| 5 | `not_found` | A collection, or the document a `patch` needs, does not exist (`NOT_FOUND`) |
| 6 | `conflict` | Definite rejection (`CONFLICT`, `ALREADY_EXISTS`) not proven to be a failed precondition: the idempotency key already identifies a different batch, or the receipt check below did not finish before the deadline. Either way this batch did not apply; for compare-and-set, read again and build a new batch with a new key |
| 7 | `precondition_failed` | Definite rejection of exactly this batch, proven by its retained receipt: a document precondition (including an absent create over an existing ID), read assertion, unique index or archived identity conflicted with current state. Resending gives the same rejection; read again and build a new batch with a new key |
| 8 | `resource_exhausted` | A size, quota or client decode limit was exceeded (`QUOTA_EXCEEDED`, `RESOURCE_EXHAUSTED`), including a new key once the receipt budget is full |
| 9 | `unavailable` | Nothing was applied: a read failed (`UNAVAILABLE`, `AUDIT_UNAVAILABLE`, `CURSOR_EXPIRED`, `SEALED`, transport, deadline), or a write was refused before the server accepted it (`SEALED`) or was never sent (connection refused, deadline); retry later. For `resolve-mutation` only the lookup failed |
| 10 | `uncertain` | A write may have been applied: `UNKNOWN_OUTCOME`, `UNAVAILABLE`, `AUDIT_UNAVAILABLE` or `CORRUPTION` on a write, a lost or unverifiable reply, the deadline, or any failure of a resend after an uncertain attempt. Resend the identical batch or `resolve-mutation` it |

A write's failure is definite only when the request was never sent, or when
the server refused it with a database code before accepting it. The server
reports any failure after it accepted a write as `UNKNOWN_OUTCOME`, and the
client reports any failure that follows an uncertain attempt the same way.
After every failure of a sent write, `kasumictl` reads that exact batch's
retained receipt on the same connection, within what remains of the deadline:
a committed receipt prints the normal success document, a retained rejection
prints that rejection's class, and a key retained for a different batch is
`conflict`. Otherwise the attempt's own class stands. Kasumi reports both a
failed precondition and a reused key as `CONFLICT`; reuse is never retained,
so it stays `conflict`. A command that stops unexpectedly, such as by a panic,
still prints its document: `uncertain` for a write, `internal` otherwise. Any
other exit status, such as termination by a signal, has no document; treat an
interrupted write as `uncertain`.

In an `append_only` collection, an absent create over an existing ID fails its
precondition and is `precondition_failed`, exactly as in a mutable collection;
any other write there is `unauthorized`.

### Calling it from another language

- Start `kasumictl` with an argument list, not a shell. Write the JSON argument
  to standard input and close it; give the subprocess its own timeout a few
  seconds longer than `--timeout-ms`.
- Read standard output to its end and parse exactly one document. The exit
  status and `error.class` always agree; branch on either.
- Store the exact bytes of every batch before sending it, keyed by its
  idempotency key, and resend or resolve with those bytes. `request_digest`
  covers the canonical batch: object key order and whitespace do not matter,
  but the spelling of every number does, so `10.5` and `10.50`, or `1.5e-7` and
  `0.00000015`, are different batches, and the second one conflicts with the
  first's key. Never rebuild a batch from parsed values.
- Parse output without losing precision. Numbers keep their exact decimal text;
  in Python use `json.loads(text, parse_float=decimal.Decimal)`. JavaScript's
  `JSON.parse` rounds integers above 2^53 and every decimal to a binary float,
  so use a lossless parser or carry amounts as strings.
- After `uncertain` (10), resend the identical batch or `resolve-mutation` it
  until it is `committed` or `rejected`; `unknown` settles nothing.
- For compare-and-set, treat `conflict` (6) and `precondition_failed` (7) the
  same way: the batch did not apply, so read again and build a new batch with a
  new key.
- After `unavailable` (9) for a write, nothing was applied and the same batch
  can be sent again later.

### Sessions

A program that issues many commands keeps one `session` instead of starting a
process per command. The session checks the profile once and keeps its
connection, so a command costs one round trip rather than a process start,
profile check and TLS handshake. The bearer file is still read for every call,
so a rotated credential takes effect at once.

```sh
kasumictl --profile "$PROFILE" $PINS session
```

Each line of standard input is one request; each answer is one line on
standard output, in order:

```json
{"id": 7, "argv": ["mutate", "-"], "input": "{\"idempotency_key\":\"op-1\",…}", "timeout_ms": 30000}
{"id": 7, "status": 0, "document": {"ok": true, "result": {…}}}
```

`argv` holds the command words of a single invocation, without options. `input`
is the text of its `-` argument, because standard input carries the requests.
`timeout_ms` bounds that request and defaults to `--timeout-ms`. `status` and
`document` are exactly the exit status and document of the same command run
alone. Requests run one at a time; `id` is returned unchanged. If the profile
is rejected, the session answers once with `"id": null` and exits with
`profile_rejected`. It exits 0 when standard input closes. A session that ends
before answering a request leaves that write `uncertain`, exactly like an
interrupted process. Resend the identical batch or `resolve-mutation` it.

A command journal records an intent, claims work by compare-and-set and writes
a permanent receipt together with the claim's completion:

```sh
PINS="--expect-profile-sha256 $PROFILE_SHA256 --expect-tenant default
  --expect-incarnation $INCARNATION --expect-principal $PRINCIPAL --expect-family-id $FAMILY_ID"
kasumictl --profile "$PROFILE" $PINS read-snapshot - <<'JSON'
{"documents":[{"collection":"intents","id":"op-1"},{"collection":"claims","id":"op-1"},
 {"collection":"receipts","id":"op-1"}],"queries":[],"time_bounds":null}
JSON
# Build the batch from the snapshot: its read_assertions become read_set, an
# absent claim is created with "expected":"absent", an observed claim is
# updated with {"version": n}. Keep the exact batch until it is resolved.
kasumictl --profile "$PROFILE" $PINS mutate - < finish-op-1.json
# After an uncertain outcome:
kasumictl --profile "$PROFILE" $PINS resolve-mutation - < finish-op-1.json
```

## MCP 2026-07-28

Use the configured HTTPS `/mcp` endpoint and its access token. With an installed
external OAuth provider, protected-resource metadata is available at
`/.well-known/oauth-protected-resource/mcp` and
`/.well-known/oauth-protected-resource`; the configured authorization server
issues the token. Local standalone installations use preconfigured local bearer
tokens: both discovery URLs return 404, and authentication challenges contain
only `Bearer`. Kasumi does not pass the caller's token to Transit or peers.

The current endpoint is stateless. Each request supplies protocol and client
metadata; legacy initialization/session flows are rejected. An authenticated
`tools/list` request returns current input schemas filtered by token scopes;
listed tools still check the current tenant/collection policy when called.
The five available tool definitions are:

| Tool | Arguments |
| --- | --- |
| `kasumi_collections` | `{}` |
| `kasumi_get` | `{"collection":"docs","id":"invoice-42"}`; returns `null` when absent |
| `kasumi_query` | A [query](query-language.md), e.g. `{"collection":"docs","filter":{"/amount":{"gte":10}}}` |
| `kasumi_mutate` | The same mutation batch used by Rust/native |
| `kasumi_receipt` | `{"idempotency_key":"invoice-creation-42"}` |

Receipt reads return `null` when no record is retained. A retained response is
`{"scope":{"tenant":"...","incarnation":"...","principal":"..."},"request_digest":"<canonical batch SHA-256>","outcome":{"Ok":...}}` or the
same wrapper with `{"Err":...}`. Native gRPC supplies the same `request_digest`
and original `scope` beside its committed/rejected outcome. Clients must compare that digest with
the complete original typed `MutationBatch`; a matching principal/key or set of
document IDs alone cannot establish which body produced the outcome. Compare the
scope with the namespace retained with the original invocation as well. A restored
receipt keeps its original incarnation; current target authorization remains
separately required to read it.

For example, the HTTP request headers for a tool call are:

```http
POST /mcp HTTP/1.1
Host: kasumi.example
Authorization: Bearer <access token>
Content-Type: application/json
Accept: application/json, text/event-stream
MCP-Protocol-Version: 2026-07-28
MCP-Method: tools/call
MCP-Name: kasumi_get
```

Its JSON body is:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "kasumi_get",
    "arguments": {"collection": "docs", "id": "invoice-42"},
    "_meta": {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      "io.modelcontextprotocol/clientInfo": {"name": "invoice-agent", "version": "1"},
      "io.modelcontextprotocol/clientCapabilities": {}
    }
  }
}
```

Successful tool values appear in `result.structuredContent`. Tool failures use
`result.isError: true` and a structured Kasumi error. Authentication/protocol
failures can instead be HTTP or JSON-RPC errors. Retained receipt outcomes are
`{"Ok": <receipt>}` or `{"Err": <database error>}`; `null` means no retained
receipt. Receipt lookup requires write authorization for that principal's
operation, not merely read access to a document.

## Queries, pages and retries

The [query language](query-language.md) is shared by every interface. A query
for a declared numeric `/amount` index:

```json
{
  "collection": "docs",
  "filter": {"/amount": {"gte": 10.25}},
  "sort": ["/amount"],
  "select": ["/amount"],
  "limit": 100
}
```

Filters map JSON Pointer fields to a value (equality) or to operators (`eq`,
`ne`, `gt`, `gte`, `lt`, `lte`, `in`, `nin`, `exists`, `contains`), combined
with `and`, `or` and `not`. Index fields declare their scalar type: `number`
uses exact JSON numbers, `decimal` uses decimal strings, and nothing is coerced.
Undeclared fields require explicit `allow_scan: true` and remain subject to
candidate/work limits. Queries with `aggregate` return groups instead of rows.
Text queries add `"search":{"index":"description_ja","query":"東京"}`.

For another page, resubmit the identical query with its returned `cursor`.
Every page reads the first page's snapshot for up to 60 seconds and stays
within `limit` rows and `max_result_bytes`. Expiry, failover, changed policy or
incarnation returns `CURSOR_EXPIRED`; current access is checked on every page
and can instead deny access immediately. For results too large or too slow for
one snapshot cursor, `"paging": "seek"` walks a unique index with stateless
cursors; see [seek paging](query-language.md#seek-paging).

After a lost response or `UNKNOWN_OUTCOME`, resolve the existing receipt or retry
the **same principal, idempotency key and identical batch**. Do not generate a
new key to discover whether the first write happened. Mutation receipts are
retained permanently within explicit storage budgets and are included in
snapshots/backups. An absent receipt
alone does not prove that an uncertain write failed. CAS forms for `expected`
are `"any"` (the default), `"absent"`, and `{"version":42}`.

Closed control commitments and issuer epoch stops are documented in [control-lifecycle.md](control-lifecycle.md). These endpoints do not yet execute the physical target recovery runner.
