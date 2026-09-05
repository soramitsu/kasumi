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

Open a node's security audit with an independently protected service Transit
key, then share that audit across the node's tenants. Each tenant uses its own
customer Transit key. These functions accept operator-provided configuration;
the caller obtains tokens from its secret source:

```rust
use std::{path::Path, sync::Arc};
use kasumi_engine::{Database, SecurityAudit, SECURITY_TENANT, open_local};
use kasumi_store::{NodeStore, TenantStore, TransitConfig, TransitKeyProvider};
use kasumi_types::{Limits, Policy};

async fn open_node(
    path: &Path,
    security_transit: TransitConfig,
) -> anyhow::Result<(Arc<NodeStore>, Arc<SecurityAudit>)> {
    let node = NodeStore::open(path)?;
    let provider = Arc::new(TransitKeyProvider::new(security_transit)?);
    let store = TenantStore::open(node.clone(), SECURITY_TENANT.into(), provider).await?;
    let audit = SecurityAudit::open(store, 100_000)?;
    Ok((node, audit))
}

async fn open_tenant(
    node: Arc<NodeStore>,
    audit: Arc<SecurityAudit>,
    transit: TransitConfig,
    initial_policy: Policy,
) -> anyhow::Result<(Arc<Database>, Arc<TenantStore>)> {
    let provider = Arc::new(TransitKeyProvider::new(transit)?);
    let store = TenantStore::open(node, "acme".into(), provider).await?;
    let database = open_local(store.clone(), initial_policy, Limits::default(), audit).await?;
    Ok((database, store))
}
```

`TransitConfig` has `endpoint` (HTTPS origin), `mount`, `key_name`, `token`,
optional `namespace` and `ca_pem`, and `derived` matching the Transit key. Use a
different `key_name` for every tenant. The adapter performs fresh decrypt probes
for all retained key dependencies; simply supplying a cached plaintext key is
not equivalent. See [Transit compatibility and permissions](COMPATIBILITY.md).
The security audit must use a separate service wrapping key and authorization,
so revoking a customer key does not prevent durable access-denial records. Its
record limit is explicit; required audit failure blocks the associated operation.

`initial_policy` contains explicit grants; the default policy denies everyone.
On reopen, persisted bootstrap and policy remain authoritative. Changing the
function arguments cannot change an existing tenant's grants or deployment mode.
Keep one live database per store and share its `Arc` among callers.

The trusted embedding application authenticates the caller before constructing
`RequestContext { principal, tenant, scopes, request_id }`. Its scopes are a
`BTreeSet<Action>`; current tenant/collection grants must also allow the action.
Create a collection once with an admin-authorized context using
`database.administer(context, Operation::CreateCollection(definition)).await`.
The `CollectionDefinition` JSON for the examples below is:

```json
{
  "name": "docs",
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
[`kasumi.proto`](../crates/kasumi-server/proto/kasumi.proto), package `kasumi.v1`.
Generate clients with the normal Protobuf toolchain or use
`kasumi_server::rpc::proto::kasumi_data_client::KasumiDataClient`.
Connect to the native data endpoint using TLS 1.3 and an approved client
certificate. In Rust, `kasumi_server::tls::grpc_channel` takes the HTTPS origin,
`TlsIdentity`, trusted CA PEM and a set of SHA-256 server leaf-certificate pins.
It returns the channel accepted by the generated client.

Every call also supplies `authorization: Bearer <access token>` metadata.
Kasumi verifies signed JWT access tokens against its configured issuer, audience,
JWKS and allowed algorithms/types (`at+jwt` in the example configuration).
Claims `sub`, `tenant` and space-delimited `scope` select the principal, tenant
and scopes. Data scopes are `kasumi:read` and `kasumi:write`; administrative calls
require `kasumi:admin` and their current policy grants. A service certificate
alone does not grant document access.

| RPC | Request | Result |
| --- | --- | --- |
| `Get` | `collection`, `id` | Document ID, version and exact UTF-8 `body_json` bytes |
| `Query` | UTF-8 `query_json` bytes | Snapshot revision, rows, JSON aggregate bytes and optional cursor |
| `Mutate` | UTF-8 `batch_json` bytes, using the batch shape above | Revision and per-document versions |
| `Collections` | Empty message | Authorized collection definitions as JSON bytes |
| `Receipt` | `idempotency_key` | Committed receipt, rejected database error, or no retained outcome |

Do not convert these JSON byte fields through Protobuf's double-valued
`Struct`. Native errors carry the Kasumi error code in structured status details.
An authorized `kasumi-leader-node-id` hint refers to the operator-approved node
map; it is not a redirect URL. Tenant and control groups can have different
leaders. Follow [routing and outcomes](administration.md#routing-and-outcomes).

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
