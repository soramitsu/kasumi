# Kasumi

Kasumi is a Rust document database for multi-tenant applications. Documents and
indexes reside in immutable memory generations; encrypted redb storage and
OpenRaft provide persistence and ordered writes. JSON Schema validation, atomic
batches, CAS, idempotency receipts, typed queries, and English/Japanese search
share one authorization layer across Rust, native gRPC, and MCP.

**Status:** the original v1 baseline passed software acceptance gates.
Both macOS and Linux passed 188 workspace tests, strict lint/formatting and live
service checks. The [measured results](benchmarks/RESULTS.md) cover all 15 required
cases: 99,000 successful operations at 1, 100 and 1,000 tenants. They preserve
source and executable identities, earlier failures and shared-host limitations.
The [acceptance checklist](docs/release-checklist.md) maps every agreed requirement
to implementation and evidence. No Redis multiplier or production SLA is claimed.
New first-release [conditional transaction contracts](docs/transactions.md) and
[large atomic transactions/read leases](docs/large-transactions-plan.md)
extend that recorded baseline. Their focused regression tests do not replace
the baseline's full platform and performance gates for the changed source.

## Deployment contracts

- **Embedded/local:** one voter. Successful writes follow durable persistence
  and complete local application. Reopening uses persisted bootstrap permissions.
- **Replicated:** three initial voters in independent failure domains, one Raft
  group per tenant. Writes require quorum persistence and local application;
  fresh reads establish a quorum barrier. Partitions never trigger a downgrade.
- Routing and operator metadata use a separate control group. Tenant policies
  remain inside their tenant group and are checked again during ordered apply.

Each successful batch publishes its matching document and index generation
together. Cursors continue a historical snapshot for at most 60 seconds and are
bound to identity, policy, incarnation, query, and leadership term. Receipts are
scoped to the principal and retained for 24 hours, including in snapshots.
Staged transactions keep permanent terminal identities, publish all effects in
one generation and support up to 100,000 mutations within explicit byte budgets.
Read leases provide bounded coherent point and ID-ordered collection pages.

## Workspace

| Crate | Responsibility |
| --- | --- |
| `kasumi-types` | Exact JSON wire types, policy, commands, query expressions, limits |
| `kasumi-store` | Encrypted redb, Transit keys and leases, filesystem/S3 backups |
| `kasumi-raft` | OpenRaft 0.9.25, durable storage adapters and quorum barriers |
| `kasumi-query` | Offline schemas, persistent structured indexes, Tantivy/Lindera |
| `kasumi-engine` | Ordered application, shared API, bootstrap, restore, control metadata |
| `kasumi-client` | Shared native Protobuf and a secure typed query/transaction/read lease client |
| `kasumi-transport` | Shared TLS 1.3, mTLS, CA validation and server certificate pinning |
| `kasumi-server` | OAuth, TLS/mTLS, native Protobuf, MCP and administrative runtime |
| `kasumi-bench` | Reproducible latency, memory and recovery measurements across API layers |

Rust 1.94 or newer is required. Linux is the production target; macOS supports
development and embedded validation. Keep a warm Cargo target directory:

```sh
cargo test -p kasumi-types -p kasumi-store -p kasumi-query
cargo test -p kasumi-raft -p kasumi-engine -p kasumi-server
cargo clippy --workspace --all-targets --no-deps -- -D warnings
```

See the [Rust/native/MCP API guide](docs/api.md),
[acceptance checklist](docs/release-checklist.md),
[storage contracts](crates/kasumi-store/README.md),
[replication tests](crates/kasumi-raft/README.md), and
[query semantics](crates/kasumi-query/README.md). Native Protobuf carries JSON as
UTF-8 bytes so exact numbers do not pass through `double`.

## Security boundaries

Network endpoints require TLS 1.3, users and agents present validated access
tokens, and service/peer listeners require client certificates. Each tenant has
its own customer Transit wrapping key. A replica independently probes every
resident key version and fences access on denial or lease expiry. Persisted
data and backups use authenticated envelope encryption with fresh nonces.

The host OS and embedding application are trusted. Returned plaintext cannot
be recalled. Datasets and indexes must fit configured RAM budgets; Kasumi does
not silently evict or spill to disk. Hardened hosts must disable plaintext swap
and process dumps. Restore uses an empty target, creates a new incarnation, and
remains suspended until explicit activation.

Redis compatibility, cross-tenant transactions, and intra-tenant sharding are
outside v1. Benchmarks must distinguish a raw hash-map lookup from an authorized
database read and from durable local or replicated writes.

See [administrative commands](docs/administration.md),
[operations and recovery](docs/operations.md), and
[benchmark reproduction](benchmarks/README.md) for the implemented workflows.
