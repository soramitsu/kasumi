# Operating Kasumi

Linux is the server target. Use the locked source and dependency versions from
the release evidence; deployment is gated by [the implementation ledger](IMPLEMENTATION.md).
The repository supplies a [systemd unit template](../deploy/kasumi.service),
not an installed or running production service. Validate the template on the
chosen distribution before enabling it.

## Build and configuration

```sh
cargo build --release --locked -p kasumi-server --bins
target/release/kasumid example-config > node.example.json
target/release/kasumictl example-config > client.example.json
```

Edit copies of these templates with operator-approved endpoints, identities,
failure domains and credential references. `check-config` validates structure
without contacting external services or reading secret environment values.
Startup then verifies credentials, decrypts persisted state, reconstructs
documents/indexes and establishes control metadata before opening data service.
A listening TLS endpoint alone is not evidence that a particular tenant has
quorum or can serve a fresh read.

Run as a dedicated unprivileged account. Place its database and generation
directories on a persistent local filesystem whose flush semantics and storage
hardware honor durability requests. Do not copy an open redb file as a logical
backup. Use the administrative backup operation. Do not run two processes
against the same writable database path or open a replica's files under a second
Raft identity.

For embedded shutdown, await `Database::shutdown()` before releasing the database
handle. It stops admission, drains Raft storage work and query/proposal jobs,
joins key-renewal monitors, seals resident state and clears cursors. Then drop all
caller-owned `Database`, `TenantStore` and `NodeStore` handles before reopening the
file. Previously returned document handles may remain with the trusted caller.
Server shutdown drains TLS connections before closing its databases. A caller
that cancels a shutdown future must await shutdown again to finish cleanup;
merely requesting Raft core shutdown is insufficient to release storage workers.

redb's file backend calls Rust's `File::sync_data`. In the pinned Rust 1.94.1
implementation this uses `fdatasync` on Linux and `F_FULLFSYNC` on Apple targets;
`sync_all` uses the corresponding full sync. These flush costs belong in durable
write measurements. They still depend on the filesystem/device honoring them.
See [the pinned Rust implementation](https://raw.githubusercontent.com/rust-lang/rust/1.94.1/library/std/src/sys/fs/unix.rs).

The unit expects `/usr/local/bin/kasumid`, `/etc/kasumi/node.json` and an
operator-created `/etc/kasumi/secrets.env`. Keep the secret file root-owned and
mode 0600. It contains the named Transit/S3 credential variables referenced by
the JSON, never tokens in command-line arguments. Certificate private keys
must be readable only by the service account and its trusted operator. The
unit confines persistent writes to `/var/lib/kasumi`; choose backup/generation
paths beneath it or explicitly adapt that allowlist.

The template disables process core files and service swap, drops capabilities,
and restricts filesystem writes. These are systemd settings; verify support and
effective values on the host. Disable host plaintext swap and hibernation in
hardened deployments, including crash/kdump collectors that can capture memory.
`vm.swappiness=0` alone does not disable swap. The OS and embedding application
are trusted and previously released plaintext cannot be recalled.
Sources: [systemd execution settings](https://raw.githubusercontent.com/systemd/systemd/v259/man/systemd.exec.xml),
[systemd memory controls](https://raw.githubusercontent.com/systemd/systemd/v259/man/systemd.resource-control.xml),
[Linux swappiness semantics](https://docs.kernel.org/admin-guide/sysctl/vm.html#swappiness).

## Placement, networking and credentials

Local mode has one voter and survives recoverable local crashes with intact
durable storage. Replicated mode has three voters per tenant and a separate
three-voter control group. Give each voter an independent power/storage/network
failure domain. Merely assigning different strings to three processes on one
host provides no such independence.

Replicated server groups use a 250 ms heartbeat interval, randomized elections
between 1.5 and 3 seconds, and a 30-second snapshot-install timeout. The replicated
benchmark uses the same explicit profile. Public reads still have a five-second
quorum deadline and writes have a ten-second response deadline; neither deadline
changes whether Raft has committed an operation. Election timing affects failure
detection and availability, and does not relax quorum or persistence requirements.
Within the read deadline, a failed quorum-confirmation round may be followed by
a fresh round when OpenRaft specifically reports insufficient quorum. A successful
fresh quorum and complete local application are still required. A changed term,
forwarding decision, fatal state, or key seal stops the barrier instead of using
an earlier confirmation. This is bounded server work and is included in measured
API latency.

Restrict the peer listener to approved cluster peers, and native/admin
listeners to clients with the configured mTLS trust. MCP uses the separate
TLS 1.3 endpoint with verified OAuth. Tokens must match the configured issuer,
audience, algorithm, expiry, type and scopes; document permissions remain in
the tenant's policy. Do not forward tokens to an inferred peer URL. Map
authorized leader-node hints to the operator-configured endpoints.

Keep Transit reachable independently from a tenant's data plane. Give every
tenant a distinct wrapping key and protect control/security records with their
own keys. Replicas perform their own decrypt probes for all resident key
versions. A decrypt denial seals immediately; delayed probes cannot extend
the access lease beyond 60 seconds from their suspend-aware start time.
Renewing or replacing credentials does not automatically resurrect a sealed
resident generation: restore valid Transit authorization and restart/recover
the affected replica, preserving its durable state and Raft identity.

Certificate configuration is loaded at startup. Existing approved node identities,
including their complete peer-pin sets, are immutable through the current native
administrative API. Editing an existing pin in configuration makes startup fail
against durable control metadata; `approve_peer_pool` cannot change it. Do not
edit database records to bypass this check or assume that reissuing a certificate
with the same public key retains its pin: pins hash the entire leaf certificate.

For a replicated peer certificate replacement, configure a new operator-approved
node ID, endpoint and certificate pin in the bounded peer pool, approve that new
identity, add it as a learner and wait for catch-up. Replace one voter at a time
through the documented [membership workflow](administration.md#membership-replacement),
then publish each group's final control route. Tenant and control memberships
must be handled separately; preserve three independent final failure domains and
quorum throughout. This is member replacement, not in-place pin rotation. Retain
the old approved node entry in configuration; current topology approval does not
remove existing identities. Never restart two voters together during this work.

A tenant Transit wrapping-key rotation must retain decryption of every version
required by live stores and retained backups. Rewrapping current stores does not
rewrite old backup bundles. Data-key rotation/rewrapping uses the separately
audited administrative commands described in [administration](administration.md).

## Memory, work and retained metadata

Size replicas for resident documents, structured indexes, Tantivy writers and
readers, historical pages, receipts, audit records, and recovery/maintenance
workspace. Configure a node RSS high-water mark below the host or cgroup
memory ceiling, with headroom for committed materialization and the OS. The
shared governor rejects new work, cancels bounded query work and checks result
release under pressure. It does not change an already committed replicated
command's deterministic outcome. A replica that cannot materialize that command
must recover before serving again.

The [admission document](admission.md) describes defaults, estimates and their
limits. RSS sampling is not exact allocator accounting. A hard cgroup memory
ceiling can terminate a process if estimates or reserved headroom are exhausted;
keep it above the admission threshold. Set backup destination byte ceilings and
inflight byte budgets together: maintenance currently reserves four times the
destination limit. Prepared restore generations consume additional resident
memory and are capped per tenant.

Cursors expire after at most 60 seconds, and any failover/incarnation change
requires a new query. Each page checks current access. Receipt retention is
24 hours by default and is included in snapshots. Receipts are scoped to the
authenticated principal; changing principal does not resolve another user's
operation.

Required tenant audits survive Raft log compaction as state, and separately
protected service records cover authentication and sealed-tenant events. They
exclude document bodies, query values and tokens. Strict successful-read
auditing persists authorization to release a particular revision; it does not
claim the client received the bytes. Audit quotas block associated successful
operations when exhausted, while denials remain enforced. Capacity must include
audit growth. There is currently no automatic audit deletion or export-and-prune
policy; preserve records and increase an authorized quota within the overall
state/RAM budget before exhaustion. Do not delete redb records manually.

## Recovery procedures

After one replica crashes, restart it with the same path, identity, deployment
binding and permitted key dependencies. It replays durable state and rebuilds
indexes before readiness. Leave the other two voters serving during recovery.
Test a fresh authorized point read/query and resolve any uncertain writes by
their existing idempotency keys. A successful read on the old isolated leader
must not be accepted as fresh data.

After a total restart, start the original voters with unchanged durable stores
and bootstrap identities. They recover persisted membership and elect leaders.
Do not rerun initialization with fewer voters or replace persisted permissions
from a new configuration file. Missing quorum stays unavailable until enough
original members recover, or an explicit backup recovery creates a new
incarnation. Keep source evidence intact while investigating.

For a failed disk/member, add an approved spare, wait for learner catch-up, then
change the three-voter membership and publish its final control route. For
logical backup recovery, restore to empty new generation stores, verify every
target, complete the durable restore audit, retire the old source and publish
the route before explicit activation. The exact multi-leader commands and
failure handling are in [administration](administration.md). Source retirement
is permanent; a failed route CAS after retirement is resolved by inspecting and
retrying controlled activation, never by resuming the old source.

`UNKNOWN_OUTCOME` means use the same principal, idempotency key and identical
batch to resolve/retry a mutation. Never issue a new key merely because a
response was lost. A missing receipt after its retention window does not prove
the operation never committed. External backup/rotation effects also require
artifact/status inspection after a timeout.

For ciphertext/integrity errors, stop using the affected store and preserve it.
Restore an authenticated logical backup into a new incarnation or replace the
replica from healthy quorum state. Do not bypass authentication, discard
required key versions, or treat corrupted records as missing documents.

## Release validation and drills

Run the workspace checks and opt-in real-service compatibility tests described
in [compatibility](COMPATIBILITY.md). The Linux container recipe pins its Rust
base image; keep a warm target directory for each platform. Record the host,
kernel, source fingerprint, executable hashes, command, exit status and actual
test output with each release. The release benchmark scripts disclose dataset,
sample counts, authentication/durability layers and recovery measurement.

Before serving a production workload, repeat partition, full restart, member
replacement and backup/restore drills on its actual failure domains and storage.
Exercise warm-state Transit denial and restoration after wrapping-key rotation.
Check strict-read audit failure and node pressure using the same policies and
budgets as production. The repository's loopback/VM tests establish software
behavior; they do not measure a selected provider's network, storage or power
failure characteristics.
