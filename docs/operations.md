# Operating Kasumi

Linux is the server target. Use the locked source and dependency versions from
the release evidence; deployment is gated by [the implementation ledger](IMPLEMENTATION.md).
The repository supplies a [systemd unit template](../deploy/kasumi.service),
not an installed or running production service. Validate the template on the
chosen distribution before enabling it.

## Build and configuration

```sh
cargo build --release --locked -p kasumi-server --bins
target/release/kasumid example-config --directory-policy /etc/kasumi/directory-policy.json --file-allocation-policy /etc/kasumi/file-allocation-policy.json > node.example.json
target/release/kasumictl example-config > client.example.json
```

Edit copies of these templates with operator-approved endpoints, identities,
failure domains and credential references. `check-config` validates structure
without contacting external services or reading secret files.
Startup then verifies credentials, decrypts persisted state, reconstructs
documents/indexes and establishes control metadata before opening data service.
A listening TLS endpoint alone is not evidence that a particular tenant has
quorum or can serve a fresh read.

Run as a dedicated unprivileged account. Place its database and generation
directories on a persistent local filesystem whose flush semantics and storage
hardware honor durability requests. Do not copy an open Kasumi database file as a logical
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

The Kasumi node backend synchronizes the owned file after transaction writes.
The host filesystem and device must honor those flush requests. These costs belong in durable
write measurements. They still depend on the filesystem/device honoring them.
See [the pinned Rust implementation](https://raw.githubusercontent.com/rust-lang/rust/1.97.1/library/std/src/sys/fs/unix.rs).

The unit expects `/usr/local/bin/kasumid`, `/etc/kasumi/node.json` and an
operator-created credential files beneath `/etc/kasumi/credentials`. Keep these
files owned by the service account and mode 0600. Configuration uses absolute
`token_file` paths, an exhaustive `bearer_files` map keyed by authority partition,
and one `credentials_file` JSON bundle for S3. Every authority partition needs
its own token file because JWT resources name one exact partition. Missing,
extra, duplicate or noncanonical partition keys are rejected; the old single
`bearer_file` authority setting is unsupported.
Publish renewed credentials using a new private file, sync it, atomically rename
it over the installed path and sync the parent directory. Every finite pooled
operation reads one fresh snapshot after anchoring its original deadline and
retains it across endpoint retries. The next operation reads renewed credentials;
missing or malformed replacements fail closed. Environment
variables and constructor-time secret snapshots are not supported. Certificate private keys
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

## Running kasumid

`kasumid serve <configuration.json> [options]` runs the node; `kasumid serve
--help` lists the options, which may appear in any order:

- `--local-snapshot-archive reference|embedded` (default `reference`). How a
  standalone group stores the snapshot it reopens from. `reference` (format
  KASUMIL1) names the tenant audit archive chain the node already keeps under
  `tenant-audit-archives/`, so a snapshot holds only the tenant's logical state.
  `embedded` (KASUMID1) copies the whole chain into every snapshot: on a tenant
  with an 8 GB archive, every snapshot then writes 8 GB. Releases before
  KASUMIL1 read only KASUMID1. To install one, first serve once with
  `--local-snapshot-archive embedded` and wait until every tenant serves: each
  by-reference snapshot is rewritten embedded (log `stored an embedded snapshot
  in place of its by-reference snapshot`), which needs free disk for one
  embedded snapshot per tenant. Then stop and install the older binary without
  running other commands of this one in between: every other kasumid command
  keeps the by-reference form. With `reference`, never delete or move files in
  `tenant-audit-archives/`: a reopen verifies the chain there and fails closed
  if a segment is missing, until it is restored.
- `--storage-compaction-growth-percent 101-200` (default 150). A compaction
  cycle starts once retained storage files reach this percentage of what the
  last cycle left. Lower values compact earlier and need less free disk at a
  cycle's peak; higher values rewrite less often.

Startup is visible. Each phase (`counting persistent files`, `opening the node
database`, `opening tenant <name> (i/n)`, `starting tenant <name>`, ...) is a
JSON `startup_phase` event with its elapsed time, `effective_admission` reports
the memory high-water mark the node enforces, and `storage_placement` reports the
free space on the persistent and scratch filesystems. Scratch spools snapshot
builds and restores (tens of GB for a large tenant), so put
`scratch_disk.directory` on a different volume from the persistent data; the
daemon warns (`scratch_shares_persistent_filesystem`) when they share one. Under systemd the
[unit template](../deploy/kasumi.service) uses `Type=notify`: `systemctl status
kasumi` shows the current phase, dependent units ordered `After=kasumi.service`
start only once the node serves (`READY=1`), and each phase may take up to 30
minutes before systemd fails the start.

A failed start logs `daemon_failed` with typed `failure_classes` (for example
`io_storage_full`, `json_syntax`, `io_address_in_use`) and a `diagnostic_path`:
a private (0600) file holding the full error chain. It is written to
`KASUMI_DIAGNOSTIC_DIRECTORY`, else systemd's `LogsDirectory=` (the template
uses `/var/log/kasumi`), else the temporary directory, which `PrivateTmp=yes`
discards when the unit stops. If a failed open or a shutdown drain keeps native
owners retained for 60 seconds, kasumid logs
`daemon_exit_with_retained_owners` and exits non-zero rather than staying
"active" while retrying; the store then recovers on the next start exactly as
after a crash.

Node status from the command line uses an admin client profile (`kasumictl
example-config` shows its shape) and exits non-zero unless the endpoint
answered 200:

```sh
kasumictl --config /etc/kasumi/admin-client.json health
kasumictl --config /etc/kasumi/admin-client.json ready
kasumictl --config /etc/kasumi/admin-client.json metrics
```

`kasumictl --config /etc/kasumi/admin-client.json compact` asks every node
database to start a compaction cycle at its next maintenance step, below the
growth threshold if need be, and clears a deferral backoff (otherwise a
capacity-rejected cycle waits up to hours or a restart). It prints which
databases accepted.

`kasumid credential inspect <profile>` prints, offline and without verifying
the token, when a profile's bearer expires. `credential watch` renews each
credential at a random point between 50% and 70% of its remaining lifetime and
retries every 3 to 8 seconds while the daemon is unavailable, so credentials
issued together do not renew in the same second. A credential that expired
while the daemon was down cannot renew itself: stop kasumid and run
`kasumid recover-existing-credentials` for those profiles.

## Placement, networking and credentials

Local mode uses durable local commits without Raft and survives recoverable
local crashes with intact durable storage. Replicated mode has three voters per
tenant and a separate three-voter control group. Give each voter an independent power/storage/network
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
Renewing or replacing credentials never resurrects a sealed resident generation.
The runtime detaches and fully drains that instance, then retries fresh authority
admission for the exact installed incarnation. After valid Transit authorization
and serving authority return, it opens a new engine over the existing durable
state. Retained old database/store handles remain permanently closed. A retired
source reopens only its independent custody route.

SIGHUP reloads MCP, native and administrative TLS in `kasumid`, and native TLS
in `kasumi-authority`. Complete certificate/key/CA candidates are validated before
any replacement. Invalid candidates retain the previous listener generations and
record failure. Successful publication atomically changes each listener and
signals old connections to drain within its configured drain timeout. Standalone
MCP certificate changes first commit the new pin to Control topology. Install
corresponding new pins in client profiles before retiring the previous pins.
Replication identity changes use the separate membership workflow below.

Existing approved replication node identities,
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
requires a new query. Each page checks current access. Mutation receipts are
permanent within the tenant's `max_mutation_receipt_bytes` budget and are
included in snapshots; once the budget is exhausted, new idempotency keys are
refused with `QUOTA_EXCEEDED`. Receipts are scoped to the authenticated
principal; changing principal does not resolve another user's operation.

Required tenant audits survive Raft log compaction as state, and separately
protected service records cover authentication and sealed-tenant events. They
exclude document bodies, query values and tokens. Strict successful-read
auditing persists authorization to release a particular revision; it does not
claim the client received the bytes. Audit quotas block associated successful
operations when exhausted, while denials remain enforced. Capacity must include
audit growth. There is currently no automatic audit deletion or export-and-prune
policy; preserve records and increase an authorized quota within the overall
state/RAM budget before exhaustion. Do not delete storage records manually.

## Persistent storage on more than one filesystem

`persistent_disk.roots` may name directories on different filesystems. Each
root is one filesystem: startup refuses a root whose tree reaches into another
filesystem, and roots may not nest, not even when the inner directory is a
mount point. Mount the other filesystem outside every root and install it as
its own root. Kasumi keeps separate accounts for every filesystem that holds a
root:

- outstanding promises (reserved growth not yet allocated);
- the `min_free_bytes` floor, checked against a fresh free-space sample of that
  filesystem;
- the free space a reservation must find.

A reservation is charged to the filesystem of the root it writes in. A full `/`
then no longer refuses growth on a second volume, and the reverse holds too.
`max_bytes`, `maintenance_reserve_bytes` and the namespace limits stay one total
for the node. A file is never renamed from one filesystem to another; such a
publication is refused before it has any effect. One node's roots can span at
most eight filesystems. Each extra filesystem adds one device registration of a
few KiB to the installed metadata, so `admission` needs no change.

Kasumi identifies a filesystem by its device number, as it already does for
scratch. Filesystems that share one free-space pool behind different device
numbers, such as btrfs subvolumes of one pool, are accounted as separate
filesystems, each against the whole pool's free space. Their promises are then
not summed. Put such roots in one subvolume, or on filesystems with separate
space.

With several filesystems, protected health JSON lists them in
`persistent_disk.filesystems`: device, root labels, pending bytes (all owners
and this owner), floor, available, total, used and admission readiness. The
scalar `filesystem_*` fields, and their Prometheus gauges, then describe the
filesystem with the least headroom, so readiness covers every filesystem.

These can live on the second filesystem:

- The tenant audit archive cache, through `tenant_audit_cache`. It holds the
  immutable encrypted segments that the audit chains and by-reference
  snapshots depend on. Move an existing cache only with the procedure below.
- New filesystem backup destinations and external filesystem audit
  destinations, in directories beneath the new root. An existing backup
  destination is bound to its directory's device and inode. Enroll a new
  destination on the new filesystem (`kasumid enroll-backup-destination`)
  instead of moving its files.

`database_path`, `data/generations` and the scratch directory keep their
locations. A minimal configuration fragment:

```json
"persistent_disk": {
  "roots": {
    "backups": "/var/lib/kasumi/backups",
    "data": "/var/lib/kasumi/data",
    "volume": "/data/kasumi"
  }
},
"tenant_audit_cache": "/data/kasumi/tenant-audit-archives"
```

Only the changed keys are shown; every other `persistent_disk` field stays as
installed. Create each root before startup as a directory owned by the service
account with mode 0700. The systemd template confines writes to
`/var/lib/kasumi`, so add the new root to its `ReadWritePaths`.
`tenant_audit_cache` must be a normalized absolute path strictly inside an
installed root, outside `data/generations`, and apart from every other
configured database, archive and backup directory. Omit it for the default
location, which is `tenant-audit-archives` beside `node.kv`. It applies to
Control and to the tenants stored in `database_path`'s node. Tenants restored
into local generations keep their caches inside their generation directories.

### Moving the tenant audit archive cache

Each tenant store records which cache directory holds its archive. A
configuration that names another directory fails startup before creating that
directory. The error names both directories and the command below. Never copy,
move or delete the cache by hand: every reopen depends on it. The command needs
a standalone installation. For a replicated member, set `tenant_audit_cache` on
a new member before it first starts, and replace the old member through the
membership workflow. For a standalone node:

1. Stop `kasumid`.
2. Mount the second filesystem outside `/var/lib/kasumi/data`, and create its
   root with `install -d -m 0700 -o kasumi -g kasumi /data/kasumi`.
3. In `kasumi.json`, add the root (`"volume": "/data/kasumi"`) and
   `"tenant_audit_cache": "/data/kasumi/tenant-audit-archives"`. Keep every
   existing root. Run `kasumid check-config /var/lib/kasumi/kasumi.json`.
4. Run the move. Its second argument is the directory that holds the cache now;
   for a default installation that is the one beside `node.kv`:

   ```sh
   kasumid maintenance move-tenant-audit-cache /var/lib/kasumi/kasumi.json /var/lib/kasumi/data/tenant-audit-archives
   ```

5. Start `kasumid`.

The command needs the stopped installation's exclusive operator ownership. It
works in two steps and prints a JSON report:

1. It copies every object into the new directory through the same exact
   publication as a new segment: a staging name, file and directory sync, a
   create-only rename, and a full readback compared with the source digest.
   Every placement still names the old directory during this step. Then
   Control and every local tenant open as at startup. Each authenticates its
   whole archive chain in the new copy, from the head back to the stream's
   first segment, decrypting every segment. Only then does the command record
   the verified move in security storage. Opening a tenant here writes nothing:
   a by-reference snapshot stays by reference, as with
   `serve --local-snapshot-archive reference`, instead of being rewritten in
   the embedded form that would copy the archive into `node.kv`.
2. It confirms that every source object still equals its copy. It then
   rewrites each store's placement to the new directory and deletes each source
   object while it still equals its copy. It also deletes the staging names of
   interrupted publications; their records are still in the hot audit set.
   Finally it removes the old directory and clears the record.

If the command is interrupted, run it again with the same arguments; it
resumes. If it reports that the source changed after verification, run it
again: it copies and verifies once more. After a completed move, the same
command reports `already_installed` and changes nothing. The new filesystem
needs room for a full copy, because the old directory is freed only at the end.
The node file's filesystem still needs its ordinary floor and a little more:
the command records its progress and audit events in the node's security
storage.
The command reads every object several times and opens every local tenant as
startup does, so plan for longer than one restart.

Before step 2 begins, reverting the configuration restores the original
installation. The unused copies stay in the new directory; a later move to it
reuses them, and a later move anywhere else discards the stale record. To move the cache back after a completed move, configure the old
location again (omit `tenant_audit_cache` for the default), make sure its parent
is still inside an installed root, and run the command with the new directory as
the source.

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

### First-release storage format `KASUMI-KVROOT005`

The first release writes `KASUMI-KVROOT005` group roots. Development formats
`KASUMI-KVROOT001` through `KASUMI-KVROOT004` are rejected; no compatibility
reader or migration is included. This applies to tenant, Control, signer and
journal groups. Create fresh storage with the release build. Never edit root
slots or delete `.kvdir` or `.kvseg` files by hand: directory pages remain
referenced by the selected tree and pinned snapshots, and segments by the
replay anchor. ROOT005 persists an exact frozen evacuation worklist and a
finite Packing budget, so writes and reopen cannot restart completed work.

The new build reclaims storage on its own. Each group's persisted cycle moves
live values and leaves out of old files and unlinks files no root or snapshot
references, driven by every write and by the node worker. Retained size
oscillates between the last cycle's baseline `B` and about `max(2B, B + 256
MiB)` by default; keep at least `B` of free space, because evacuation needs
room to copy before anything is freed and defers (without failing writes) on a
full disk. Watch `kasumi_local_group_storage_*` and the health `storage`
object ([observability](observability.md)); a growing
`maintenance_deferrals_total{class="capacity"}` with a phase stuck in
`evacuating` means the disk needs headroom.

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
