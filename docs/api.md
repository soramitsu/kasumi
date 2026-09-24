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
renewable `credential` source, optional `namespace` and `ca_pem`, and `derived`
matching the Transit key. Use a different key and authority for each application,
custody and service domain. `FileCredentialSource` reads the installed private
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
`RequestContext { authorization, principal, tenant, scopes, request_id }`. Its scopes are a
`BTreeSet<Action>`; current tenant/collection grants must also allow the action.
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
let batch: kasumi_types::MutationBatch = serde_json::from_str(r#"{
  "idempotency_key": "invoice-creation-42",
  "read_set": [],
  "operations": [{
    "op": "put", "collection": "docs", "id": "invoice-42",
    "body": {"amount": 9007199254740993.123456789},
    "expected": {"kind": "absent"}
  }]
}"#)?;
let receipt = database.mutate(context.clone(), batch).await?;
let document = database.get(&context, "docs", "invoice-42").await?;
let outcome = database.operation_receipt(&context, "invoice-creation-42").await?;
```

`get_shared` returns an immutable `Arc<Document>` with the same authorization,
consistency and audit checks, avoiding a JSON-body clone. Previously returned
owned/shared plaintext cannot be recalled after revocation. Before closing,
await `database.shutdown()`: it stops admission, drains Raft storage workers and
pending query/proposal work, stops the key monitors, and releases owned keys and
resident state. A canceled shutdown can be awaited again. To reopen the same
node file, shut down every database using it, then await the shared
`audit.shutdown()`. Drop all database, tenant-store, audit and node-store handles
before reopening. Previously returned document handles can remain alive.
Network deployments should use `kasumid`'s configured runtime, which
also provides the separate control/security stores and shared admission limits.

## Native gRPC

The authoritative wire schema is
[`kasumi.proto`](../crates/kasumi-client/proto/kasumi.proto), package `kasumi.v1`.
Generate clients with the normal Protobuf toolchain or use
`kasumi_client::proto::kasumi_data_client::KasumiDataClient`.
The independent `kasumi-client` crate also provides a typed `KasumiClient`
wrapper for `query`, `read_snapshot`, `mutate`, staged transactions and read
leases, constructed with
`KasumiClient::connect(&KasumiClientConfig)`. The required configuration contains
the HTTPS `endpoint`, `identity` (`kasumi_transport::TlsIdentity`),
`trusted_ca_pem` and nonempty `server_certificate_pins`. There is no unchecked
channel constructor. Every method takes the
current bearer token explicitly. The client preserves structured native status
errors and performs no implicit retries or redirects.
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
| `Get` | `collection`, `id` | Document ID, version and exact UTF-8 `body_json` bytes |
| `Query` | UTF-8 `query_json` bytes | Snapshot revision, rows, JSON aggregate bytes and optional cursor |
| `ReadSnapshot` | UTF-8 `request_json` bytes: document keys and queries | One coherent generation as UTF-8 `response_json`, including read assertions' source versions/epochs |
| `ReadRestoreLineage` | Expected current incarnation and an existing collection | Opaque authenticated historical commitments under current collection Read permission |
| `Mutate` | UTF-8 `batch_json` bytes, using the batch shape above | Revision and per-document versions |
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

Do not convert these JSON byte fields through Protobuf's double-valued
`Struct`. Native errors carry the Kasumi error code in structured status details.
An authorized `kasumi-leader-node-id` hint refers to the operator-approved node
map; it is not a redirect URL. Tenant and control groups can have different
leaders. Follow [routing and outcomes](administration.md#routing-and-outcomes).

## Conditional transactions and immutable collections

`MutationBatch.read_set`, `CollectionDefinition.write_mode`, and
`CollectionDefinition.retention_class` are required v1 fields. A conditional batch verifies all its read dependencies against one
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

## MCP 2026-07-28

Use the configured HTTPS `/mcp` endpoint and an OAuth access token for that
protected resource. Protected-resource metadata is available at
`/.well-known/oauth-protected-resource/mcp`; its configured authorization server
issues the token. Kasumi does not pass the caller's token to Transit or peers.

The current endpoint is stateless. Each request supplies protocol and client
metadata; legacy initialization/session flows are rejected. An authenticated
`tools/list` request returns current input schemas filtered by token scopes;
listed tools still check the current tenant/collection policy when called.
The five available tool definitions are:

| Tool | Arguments |
| --- | --- |
| `kasumi_collections` | `{}` |
| `kasumi_get` | `{"collection":"docs","id":"invoice-42"}` |
| `kasumi_query` | The query object below |
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

Here is a query for a declared numeric `/amount` index:

```json
{
  "collection": "docs",
  "filter": {"op": "compare", "field": "/amount", "comparison": "gte", "value": 10.25},
  "sort": [{"field": "/amount", "direction": "asc"}],
  "projection": ["/amount"],
  "limit": 100
}
```

Index fields declare their scalar type. `number` uses exact JSON numbers;
`decimal` uses decimal strings. There is no implicit coercion. Undeclared scans
require explicit `allow_scan: true` and remain subject to candidate/work limits.
Aggregates use `alias` and `function` (`count`, `sum`, `min`, `max`, `avg`).
`sum`, `min`, `max` and `avg` require a numeric `field`; `avg` also requires an
explicit `scale` from 0 to 1000 and rounds half-even. `count` returns a JSON
integer; the other numeric results use decimal strings. An empty numeric group
has sum `"0"` and min/max/avg `null`. Missing fields remain different from JSON null.

Text queries select a declared text index, for example
`"text":{"index":"description_ja","query":"東京","mode":"terms"}`.
Other modes are `phrase`, `prefix` and `fuzzy`; fuzzy distance is bounded to two,
with independent term-expansion/work caps. Declare Unicode, English or Japanese
analysis in the collection's index definition through the administrative API.

For another page, resubmit the identical query with its returned `cursor`.
The cursor continues that historical snapshot for up to 60 seconds. Expiry,
failover, changed policy or incarnation returns `CURSOR_EXPIRED`; current access
is checked on every page and can instead deny access immediately.

After a lost response or `UNKNOWN_OUTCOME`, resolve the existing receipt or retry
the **same principal, idempotency key and identical batch**. Do not generate a
new key to discover whether the first write happened. Receipts are retained for
24 hours by default and are included in snapshots/backups. An absent receipt
alone does not prove that an uncertain write failed. CAS forms are
`{"kind":"any"}`, `{"kind":"absent"}`, and
`{"kind":"version","version":42}`.

Closed control commitments and issuer epoch stops are documented in [control-lifecycle.md](control-lifecycle.md). These endpoints do not yet execute the physical target recovery runner.
