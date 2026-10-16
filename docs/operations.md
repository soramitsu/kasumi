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
state/RAM budget before exhaustion. Do not delete storage records manually.

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
`KASUMI-KVROOT001` through `KASUMI-KVROOT004` are rejected at startup; the
runtime has no compatibility reader. This applies to tenant, Control, signer
and journal groups. Create fresh storage with the release build; the only
exception is the one-time upgrade below. Never edit root slots or delete
`.kvdir` or `.kvseg` files by hand: directory pages remain referenced by the
selected tree and pinned snapshots, and segments by the replay anchor. ROOT005
persists an exact frozen evacuation worklist and a finite Packing budget, so
writes and reopen cannot restart completed work.

#### One-time upgrade of the `KASUMI-KVROOT003` installation

```sh
kasumid maintenance upgrade-storage-root /var/lib/kasumi/kasumi.json /secure/root-upgrade-save
```

This first-release command upgrades, in place and keeping its data, the BPNG
standalone installation that a `KASUMI-KVROOT003` build wrote, so that it can
run reclamation. Delete the command (and `kasumi_kv::RootUpgradePlan` and
`kasumi_store::StorageRootUpgrade`) once that installation is upgraded; no
other installation needs it. ROOT005 differs from ROOT003 only in the root
magic and in the compaction record at bytes 2384..4080, which ROOT003 had to
keep zero and which decodes as the empty (genesis) record. Segments
(`KASUMI-KVSEG0004`), arenas (`KASUMI-KVARENA01`), directory pages
(`KASUMI-KVDIR0002`) and file envelopes (`KASUMI-NODE-SEG1`) are unchanged.

The installation must be stopped; run the command as the user that owns it.
Do not start the release build on the ROOT003 roots first: it refuses them,
and its failed startup keeps retrying its cleanup instead of exiting. The
command takes the installation the way the other offline operators do
(exclusive persistent-disk ownership and the installation lock) and opens no
encrypted store. It then:

1. validates every group root, `data/node.kv/root.kvroot` and the root of each
   local generation `data/generations/<uuid>/node.kv/root.kvroot` (a standalone
   installation keeps Control, audit, credentials and tenants in these
   groups): the envelope and its node identity, the ROOT003 rules (format
   version 4, a zero compaction region), the canonical ROOT005 encoding of
   each valid slot, and that the strict ROOT005 reader will select exactly the
   root a ROOT003 reader selects now, with the genesis compaction record. Any
   failure refuses the whole run before anything is written;
2. saves each root that needs work to `SAVE_DIR` (absolute, created owner-only
   if missing, outside every storage root of the installation), owner-only and
   synchronized, and refuses if `SAVE_DIR` already holds a different copy;
3. rewrites, on the same inode, the magic byte and checksum of each valid
   ROOT003 slot; a torn slot only gets the new magic and stays invalid. The
   slot the selection does not read is written first, each write is
   synchronized, and the file is read back and verified.

It prints a JSON summary with one entry per root: `path`, `outcome`
(`upgraded`, `resumed`, `already ROOT005`, or `unpublished` for a generation
root whose creation never wrote an envelope), the treatment of each slot,
`slots_changed`, the selected `generation`, slot and mirror state,
`sha256_before`, `sha256_after`, and the saved copy (`written`, `matches` or
`stale`). If the command is interrupted, rerun it with the same arguments; it
completes the remaining slot writes from the slots themselves and checks them
against the saved copy. A rerun with nothing left to do reports
`already ROOT005` and writes nothing. Keep the output and `SAVE_DIR`.

Then start the release build and watch the health `storage` object: against
the empty baseline the first cycle is due at once, and it moves live values
out of old files and unlinks them. Until the release build first starts,
`SAVE_DIR` can restore the previous build: copy each saved file back over its
root in place (`dd if=SAVED of=ROOT conv=notrunc,fsync`, keeping the inode)
and start the ROOT003 build, which otherwise refuses the upgraded roots. Once
the release build has run, its maintenance rewrites roots and unlinks files,
so the saved copies no longer describe the data and must not be restored.

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
