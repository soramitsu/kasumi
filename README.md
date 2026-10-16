<p align="center">
  <img src="design/brand/kasumi-logo-with-katakana.svg?v=2" alt="KASUMI — カスミ" width="480">
</p>

<h1 align="center">Kasumi</h1>

<p align="center">
  <strong>A durable JSON database for applications that care about the next write.</strong><br>
  Rust-native, multi-tenant, encrypted, and ready for services, gRPC clients, and MCP agents.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="Apache 2.0 license"></a>
  <a href="Cargo.toml"><img src="https://img.shields.io/badge/rust-1.97.1-orange.svg" alt="Rust 1.97.1"></a>
  <a href="docs/api.md"><img src="https://img.shields.io/badge/API-Rust%20%7C%20gRPC%20%7C%20MCP-7c3aed.svg" alt="Rust, gRPC and MCP APIs"></a>
</p>

Kasumi is a self-hosted document database for teams building systems where a
retry, restart, or replica failure must not turn into duplicate or ambiguous
state. Store JSON documents, validate them with schemas, query them through
typed indexes or English/Japanese full-text search, and commit related changes
as one durable operation.

The same policy and data model works in an embedded Rust application, a
standalone server, a three-voter OpenRaft deployment, native gRPC, and MCP.
Embedded and standalone databases commit locally without running Raft; replicated
deployments use Raft across their configured voters.
Kasumi does not implement the Redis protocol; its APIs are designed around
explicit receipts, authorization, and recoverable operations.

## Why teams use Kasumi

- **Retries are part of the model.** Every mutation has an idempotency key and a
  durable receipt. Resend the same batch after an uncertain network outcome and
  Kasumi resolves the original operation instead of applying it twice.
- **JSON without fuzzy semantics.** JSON Schema, exact numeric values, JSON
  Pointer field paths, conditional writes, aggregates, cursor paging, and
  declared indexes keep application behavior predictable as data grows.
- **One atomic boundary for a workflow.** Update an order, reserve inventory,
  and clear a cart in one batch. Preconditions and read assertions reject the
  whole batch when the state you observed is no longer true.
- **Isolation you can operate.** Tenants have separate policy, credentials,
  encrypted storage, audit records, and (in replicated mode) Raft groups.
  Network access uses TLS 1.3, mTLS, pinned server certificates, and bearer
  credentials.
- **A useful interface for people and agents.** Use the Rust SDK for services,
  <code>kasumictl</code> for scripts and debugging, native Protobuf for other
  languages, or MCP for an authorized agent workflow.

## Quickstart: run a local standalone database

The commands below build Kasumi, create a local installation, and start the
server on loopback. The policy numbers are for a disposable development
installation; qualify storage and memory limits for a real deployment. The
installation command intentionally requires explicit policy files so capacity
choices are visible and reviewable. Use a fresh <code>DEMO</code> directory for
each install because Kasumi never overwrites an existing installation. If one
of the example ports is busy, change all three listener ports and the MCP URL
together in <code>network.json</code>.

~~~sh
git clone https://github.com/soramitsu/kasumi.git
cd kasumi

cargo +1.97.1 build --release --locked -p kasumi-server --bins

DEMO="/tmp/kasumi-demo"
mkdir -p "$DEMO"
umask 077

cat > "$DEMO/directory-policy.json" <<'JSON'
{"extent_bytes":10485760,"max_entries":32768}
JSON

cat > "$DEMO/file-allocation-policy.json" <<'JSON'
{"maximum_extra_extent_bytes":1048576}
JSON

cat > "$DEMO/network.json" <<'JSON'
{
  "mcp_listen": "127.0.0.1:9443",
  "mcp_public_url": "https://localhost:9443/mcp",
  "native_listen": "127.0.0.1:9444",
  "admin_listen": "127.0.0.1:9445"
}
JSON

cat > "$DEMO/tenant-audit-placements.json" <<'JSON'
{
  "__kasumi_control": {"kind":"local_replica_only"},
  "default": {"kind":"local_replica_only"}
}
JSON

target/release/kasumid init --mode standalone "$DEMO/installation" \
  --directory-policy "$DEMO/directory-policy.json" \
  --file-allocation-policy "$DEMO/file-allocation-policy.json" \
  --network "$DEMO/network.json" \
  --tenant-audit-placements "$DEMO/tenant-audit-placements.json" \
  --tenant default
~~~

Start the server in one terminal:

~~~sh
DEMO="/tmp/kasumi-demo"
target/release/kasumid serve "$DEMO/installation/kasumi.json"
~~~

The installation writes owner-only client profiles under
<code>$DEMO/installation/profiles/</code>. Before writing data, create a
collection with an authorized tenant administrator. The generated
<code>profiles/default.json</code> contains the administrative endpoint and
trust material for the default tenant. <code>kasumictl example-config</code>
prints the small client template; copy the matching endpoint, certificate, CA,
pin, and token paths from that profile into
<code>$DEMO/admin-client.json</code>, then keep the file owner-only.

For a local demo, this derives the administrative config from the generated
profile:

~~~sh
DEMO="/tmp/kasumi-demo"
python3 - "$DEMO/installation/profiles/default.json" "$DEMO/admin-client.json" <<'PY'
import json
import pathlib
import sys

profile = json.loads(pathlib.Path(sys.argv[1]).read_text())
member = next(iter(profile["administrative_members"].values()))
admin = {
    "endpoint": member["endpoint"],
    "identity": profile["identity"],
    "server_ca": profile["server_ca"],
    "server_certificate_pins": sorted(member["certificate_pins"]),
    "token_file": profile["bearer_file"],
}
pathlib.Path(sys.argv[2]).write_text(json.dumps(admin, indent=2) + "\n")
PY
chmod 600 "$DEMO/admin-client.json"
~~~

Save this collection definition as <code>$DEMO/invoices.collection.json</code>:

~~~json
{
  "name": "invoices",
  "write_mode": "mutable",
  "retention_class": "operational",
  "strict_read_audit": false,
  "schema": {
    "type": "object",
    "properties": {
      "status": {"type": "string"},
      "amount": {"type": "number"}
    }
  },
  "indexes": [
    {"name": "status", "fields": [{"path": "/status", "kind": "string"}]},
    {"name": "amount", "fields": [{"path": "/amount", "kind": "number"}]}
  ]
}
~~~

Create it once through the separate administrative endpoint:

~~~sh
DEMO="/tmp/kasumi-demo"
target/release/kasumictl --config "$DEMO/admin-client.json" create-collection "$DEMO/invoices.collection.json"
~~~

The full schema and operator workflow are in the
[standalone guide](docs/standalone.md) and
[administration guide](docs/administration.md).

Once a collection named <code>invoices</code> exists, the data profile is ready
for a first write:

~~~sh
DEMO="/tmp/kasumi-demo"
PROFILE="$DEMO/installation/profiles/default.json"

target/release/kasumictl --profile "$PROFILE" \
  put invoices inv-1 '{"status":"open","amount":42}' --if absent --key invoice:inv-1

target/release/kasumictl --profile "$PROFILE" \
  query invoices '{"/status":"open"}' --sort -/amount --limit 20

target/release/kasumictl --profile "$PROFILE" get invoices inv-1
~~~

<code>kasumictl</code> prints JSON Lines, accepts inline JSON,
<code>@file.json</code>, or standard input, and can follow every page with
<code>--all</code>. Use <code>--key</code> for a stable idempotency key when a
script may retry across process restarts. Credentials expire after one hour;
keep a profile renewed while the server is running:

~~~sh
DEMO="/tmp/kasumi-demo"
PROFILE="$DEMO/installation/profiles/default.json"
target/release/kasumid credential watch "$PROFILE"
~~~

For a production-shaped installation, use the complete [standalone installation
guide](docs/standalone.md), including filesystem qualification, key backup,
credential rotation, backups, and recovery.

## A Rust application in a few lines

Add the client crate to a Rust service in this workspace, then point it at the
generated profile:

~~~toml
[dependencies]
kasumi-client = { path = "crates/kasumi-client" }
serde_json = "1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
~~~

~~~rust
use kasumi_client::prelude::*;
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let profile = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/var/lib/kasumi/profiles/default.json".into());
    let db = Kasumi::from_profile(profile).await?;

    // Insert, query, and decode ordinary owned Rust values.
    db.upsert("invoices", "inv-rust", json!({
        "status": "open",
        "amount": 42,
        "customer": {"name": "Ada"}
    })).await?;

    let page = db.query(
        &QueryRequest::new("invoices")
            .filter(Filter::new().eq("/status", "open").gte("/amount", 10))
            .sort_desc("/amount")
            .select(["/amount", "/customer/name"])
            .limit(20),
    ).await?;

    for row in page.rows() {
        println!("{}: {}", row.id, row.body);
    }

    Ok(())
}
~~~

<code>Kasumi</code> rereads the bearer file for each operation, applies a
bounded decode budget and a 30-second default deadline, and retries uncertain
mutations with the original idempotency key. Follow another page with
<code>db.next_page(&page).await?</code>, or collect every page with
<code>db.query_all(&QueryRequest::new("invoices")).await?</code> into caller
memory. Pass the generated profile path as the program's first argument. See
the [native API guide](docs/api.md).

## Patterns that make applications safer

### Commit a workflow once

The batch below updates multiple collections atomically. If the connection
drops after dispatch, resend the same batch or let <code>Kasumi::mutate</code>
resolve it; the stable key prevents a second application.

~~~rust
let checkout = MutationBatch::with_key("checkout:order-1001")
    .insert("orders", "1001", json!({"total": 42, "status": "paid"}))
    .replace("stock", "sku-7", json!({"count": 3}), 18)
    .delete("carts", "cart-55");

let receipt = db.mutate(&checkout).await?;
println!("committed revision {}", receipt.revision);
~~~

Every precondition is checked against one write state. A failed version check,
schema validation, uniqueness constraint, quota, or authorization check rejects
the entire batch.

### Query the same data from JSON

Rust, native gRPC, and MCP accept the same typed query shape:

~~~json
{
  "collection": "invoices",
  "filter": {"/status": "open", "/amount": {"gte": 10, "lt": 100}},
  "sort": ["-/amount"],
  "select": ["/amount", "/customer/name"],
  "limit": 20
}
~~~

Field paths are JSON Pointers. Filtering, sorting, or grouping on a hot path
requires a declared index; an undeclared field returns <code>INDEX_REQUIRED</code>
unless the request explicitly opts into a bounded scan. For large ordered
walks, use seek paging, which keeps no server-side cursor. The same query
language also supports named aggregates and full-text indexes such as
<code>{"index":"description_ja","query":"東京 タワー"}</code>.

### Let an agent use a narrow data surface

Kasumi's MCP endpoint exposes the same authorized core data operations as the SDK:
<code>kasumi_collections</code>, <code>kasumi_get</code>, <code>kasumi_query</code>,
<code>kasumi_mutate</code>, and <code>kasumi_receipt</code>. Calls use the
installed bearer credential and current MCP protocol headers; administrative
operations stay on the separate native administrative endpoint. See the
[MCP API details](docs/api.md).

## Deployment modes

| Mode | What it gives you |
| --- | --- |
| Embedded Rust | Direct access to the engine with application-owned authentication and lifecycle. |
| Standalone | One-voter local installation with generated TLS identities, profiles, encrypted storage, audit, backups, and recovery tools. |
| Replicated | Three initial voters in independent failure domains, one Raft group per tenant, quorum-persisted writes, and a separate Control group for routing and operator metadata. |

Successful writes publish their document and index generations together.
Snapshot cursors are identity-, policy-, incarnation-, query-, and
leadership-bound; seek cursors walk a unique index without a retained snapshot.
Mutation receipts retain the original tenant, incarnation, principal, and
command identity in encrypted point-addressed storage under explicit byte
budgets.

## Workspace

| Crate | Responsibility |
| --- | --- |
| [kasumi-types](crates/kasumi-types) | Canonical JSON wire types, policy, commands, queries, and limits |
| [kasumi-kv](crates/kasumi-kv) | Transactional durable byte-key storage core |
| [kasumi-store](crates/kasumi-store) | Encrypted records, key leases, snapshots, and backup objects |
| [kasumi-raft](crates/kasumi-raft) | OpenRaft 0.9.25, durable state, and quorum barriers |
| [kasumi-query](crates/kasumi-query) | Schemas, persistent indexes, and Tantivy/Lindera search |
| [kasumi-engine](crates/kasumi-engine) | Ordered application, authorization, recovery, and control metadata |
| [kasumi-client](crates/kasumi-client) | Typed Rust client, native Protobuf bindings, and response admission |
| [kasumi-transport](crates/kasumi-transport) | TLS 1.3, mTLS, CA validation, and certificate pinning |
| [kasumi-server](crates/kasumi-server) | Standalone runtime, native service, MCP, and operator CLI |

Rust 1.97.1 is pinned in <code>rust-toolchain.toml</code>. Linux is the
production target; macOS supports development and embedded validation. Keep one
warm Cargo target directory per active worktree and use focused checks while
iterating:

~~~sh
cargo test -p kasumi-types -p kasumi-kv -p kasumi-store -p kasumi-query
cargo test -p kasumi-raft -p kasumi-engine -p kasumi-server
cargo clippy --workspace --all-targets --no-deps -- -D warnings
~~~

Read the [API guide](docs/api.md), [query language](docs/query-language.md),
[operations guide](docs/operations.md), and
[benchmark reproduction guide](benchmarks/README.md) for deeper workflows.

## Project status and boundaries

The first production release is still being implemented; no source revision is
release-qualified yet. The [release ledger](docs/production-release.md) records
verified progress and remaining gates, and the [acceptance checklist](docs/release-checklist.md)
lists the evidence still required. Historical benchmark results are useful for
reproducing development behavior, not a production SLA.

The current engine keeps datasets and indexes within configured resident-memory
budgets and does not silently evict or spill plaintext to disk. The larger
disk-backed cache redesign is tracked in the [active storage goals](docs/disk-backed-cache-goals.md)
and is not yet qualified. Redis compatibility, cross-tenant transactions, and
intra-tenant sharding are outside v1.

Kasumi is licensed under [Apache-2.0](LICENSE). For security reports, see
[SECURITY.md](SECURITY.md).
