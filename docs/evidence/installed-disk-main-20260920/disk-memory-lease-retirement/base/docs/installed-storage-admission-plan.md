# Installed storage memory and directory admission

**Status: mandatory installed storage memory integrated in pending source;
directory accounting and complete qualification remain open.** The shared core,
fixed reservation ledger, direct resident admission and separately charged
runtime startup inventory now exist. Production runtime entry points select the
installed core and construct their facade before opening either disk. Required
lower-layer admission charges persistent, scratch, device and registration
metadata for its actual retained lifetime. Database construction verifies the
exact physical memory owner before bootstrap and Raft startup; the implicit
process fallback and late-install APIs are removed. Scoped admission tests and
workspace checks are recorded in the
[development evidence](evidence/installed-disk-main-20260920/README.md).
These source-specific diagnostics do not establish native resource limits or
directory guarantees. The remaining slices implement those requirements for
[the first release](first-release-plan.md).

Pending source now also provides exact-policy installed MemoryCore selection and
rejects reuse after terminal sampler failure. Explicit process shutdown and
production startup-resource adapters remain unfinished. NodeDisk retains a fixed namespace
digest with each enrolled inode: unknown final-leaf absence may return NotFound
after parent verification, while enrolled disappearance, raw rename and physical
substitution fence the owner. Successful publication updates the existing digest
before fallible durability checks. Publication preparation now holds the owner
state lock during physical path validation. These changes do not provide the
still-missing directory census; their source-specific validation
belongs in the development evidence.

The mandatory memory stack replaces the old constructors and migrates all
supported callers together. Installed scratch ownership is strongly retained:
dropping a public handle does not pretend its registry allocation disappeared.
NodeStore checks persistent/scratch core identity before physical mutation;
engine construction checks the same core against its admission facade. Fixture
planners preserve original payload, RSS and operation limits while adding only
the actual new physical metadata and lease charges. Production constructors make
one attempt; explicitly test-only registry contention retries reuse the same
configuration and governor. No compatibility constructor or default is provided.

Work only in `/Users/mtakemiya/dev/kasumi` on `master`. Do not create or use other
branches, worktrees, or external build/output directories. Coordinate Rust edits
and builds with the active integration owner; put build output and new evidence
under the main workspace's `target`. This document itself authorizes no build.

This is the first release. Replace affected production APIs and configuration
directly, updating every caller. Do not add compatibility overloads, configuration
aliases, optional admission, inferred roots, uncharged production constructors, or
fallback interpretation of missing newly required policy. Explicit values in new
installation generators are installation policy, not migration defaults.

## Current implementation and concrete gaps

The following observations describe the source inspected on 2026-09-20:

The table preserves the pre-foundation gap inventory; its current-behavior column
is historical. The admission-core, snapshot-inventory, disk-metadata and runtime
ordering gaps are superseded by the integrated work above. Directory work,
complete process custody and native measurements remain open. Prepared patches
under `target` alone are not implemented evidence; applied changes and terminal
diagnostics have separate receipts.

| Area | Current behavior | Missing requirement |
| --- | --- | --- |
| `kasumi-store/src/node_disk.rs` | A strong process-lifetime registry retains installed owners, root locks, charges and the per-inode `HashMap` ledger. | Retained heap allocations have no reservation against node memory admission. |
| `node_disk/file.rs` | Preparation reserves ledger/live-map capacity and allocates names, paths, owner storage and the budget mutex before physical creation. Publication/reclaim execution uses inline I/O errors. | `try_reserve` establishes allocation success and cardinality bounds, not a node memory reservation. Publication path preparation currently occurs before taking the owner state lock, so its simultaneous workspace also needs a bound. |
| `node_disk/census.rs` | Traversal is bounded; regular-file extents are charged and enrolled. Reconciliation constructs a replacement ledger while retaining the previous one. | Roots and descendant directory extents are not enrolled. Census maps, cursor stack, copied names and replacement-ledger peak are uncharged memory. |
| `NodeDiskConfig` | Bounds census work, retained entries, open files, path depth and component length. | No directory extent/entry policy; no complete admitted metadata envelope. |
| `kasumi-engine/src/admission.rs` | `NodeAdmission::reserve` charges bytes and an operation slot. `Reservation::retain` releases the operation slot while keeping bytes. | No direct installed-metadata reservation that consumes zero operation slots from acquisition onward. |
| Runtime restart | Data and authority runtime opening, and standalone installation, currently open NodeDisk before constructing their NodeAdmission. | The disk may already have allocated its census before admission exists. A replacement runtime creates a new governor while the retained disk still belongs to the old lifetime. |
| Snapshot startup inventory | `SnapshotStartups` holds `Vec<Weak<SnapshotBufferOwner>>`; per-owner charges are said to cover entries. | Removing owners releases their reservations but retains vector capacity. Its allocation needs an independent charge. The startup registry is permanently sealed by drain and cannot simply become shared process-lifetime runtime state. |
| Governor bookkeeping | The admission charge `HashMap` retains capacity after reservations disappear. | Capacity needs a bounded base charge; vanished individual reservations cannot cover it. |
| Directory callers | Archive/destination setup and session directories use raw creation/sync; recovery paths also create/remove directories. | Those operations and parent-directory mutations from managed file operations need the same physical owner. |

`kasumi-engine` already depends on `kasumi-store`. Importing the engine governor
into store would create a dependency cycle. `kasumi-serving` also cannot import
engine to solve it. Its existing `BackgroundWorkBudget` demonstrates passing an
opaque retained charge down the dependency graph, but does not itself provide a
general storage memory governor.

## Slice A: shared memory ownership and admitted metadata

### Mandatory lower-level interface

Define a small public interface in store, implemented by engine. A possible shape
is below; exact naming is an implementation choice:

```rust
pub trait NodeDiskMemoryAdmission: Send + Sync {
    fn reserve_installed(
        self: std::sync::Arc<Self>,
        bytes: u64,
    ) -> std::io::Result<Box<dyn Send + Sync>>;
}
```

`NodeDisk::open` must require `Arc<dyn NodeDiskMemoryAdmission>`. The opaque returned
object owns the real reservation, rather than copying its byte count. Store keeps
both the governor identity and the charge. A store `test-utils` implementation may
provide an explicitly bounded deterministic governor with observable charge
lifetime; it must not be selectable by production configuration.

The `Arc<Self>` receiver permits the shared engine core itself to implement the
trait and return a reservation retaining that core. Repeated trait-object
coercions of the same core preserve its physical Arc identity. Avoid allocating a
fresh identity-bearing adapter for each runtime facade.

### Separate resource identity from runtime lifecycle

Extract a shared memory-governor core from `NodeAdmission`. Move configuration,
resolved byte limits, RSS source/sampling, clock, reservation identifiers and
charge accounting into that core. Keep snapshot-startup registration and its
typed drain report on each runtime facade.

The recommended policy is one installed process memory core, because the current
memory source measures process RSS. New runtime facades reuse it; conflicting
installed memory policy in the same process is an error. If multiple independent
installed-node governors per process are required instead, their shared aggregate
reservation authority must be specified before claiming process-wide admission.
Creating independent full-capacity governors is not a substitute.

Do not reuse the complete old NodeAdmission object: its snapshot-startup registry
may already be sealed. Do not create a new independent core on runtime restart:
that would let replacement work spend capacity without the retained disk's charge.
Reservations and workspace handoff checks should compare the shared resource
identity, while startup fences remain specific to the runtime facade.

The NodeDisk registry must require matching disk policy and the same memory-core
identity on reuse. Return the existing charged owner. Do not duplicate its full
charge temporarily or transfer it to a new governor while allocations survive.
Existing-root reuse must still verify the retained physical binding. New-owner
preparation must reserve its metadata envelope before allocating roots, census
collections or registration state. Design lookup/preparation ordering explicitly;
do not move an uncharged initial census in front of the governor check.

### Installed reservations are not in-flight operations

Add a direct installed/resident reservation operation in engine. It must check
fresh memory availability and the shared byte limits, but neither increment nor
depend on the 64 in-flight operation slots. A `reserve` followed by `retain` still
temporarily consumes an operation slot and is not the desired implementation.

Installed metadata must contribute to the total reserved-byte/RSS pressure checks
used by new work. Keep it charged through runtime replacement, failed startup,
pause, failed census and retained errors. It is released only after the covered
allocations disappear; closing a database does not free a strongly registered
NodeDisk ledger.

Policy recommendation: initially use one combined reservation byte limit, expose
installed bytes separately in snapshots, and document that the total includes
installed metadata and retained results. If renaming the misleading existing
`max_inflight_bytes` policy to express that total, update configuration directly
without accepting both spellings. A distinct installed-memory sublimit is an
optional explicit policy decision, not permission to omit installed bytes from
the shared total.

Bound and account the core's own reservation-table capacity. A fixed admitted base
and maximum reservation count are simpler than assigning its retained allocation
to individual reservations that may disappear. Include this base in the shared
budget calculation without introducing a self-owning reservation cycle.

### Fixed metadata envelope

Add a checked `NodeDisk::required_metadata_bytes(&NodeDiskConfig)` calculation.
Reserve its full result before storage-owner allocation. Retain the envelope for
the installed owner's lifetime; do not return it merely because a hash map has
few live entries. This fixed-envelope approach is the recommended bounded first
implementation. Dynamic capacity charging can be a later direct redesign.

The calculation must include at least:

1. Two complete inode ledgers, including directory entries once implemented:
   reconciliation keeps the old ledger while constructing the new one.
2. Live-map capacity, weak registration records, and maximum simultaneously
   retained file/directory handles.
3. Handle Arc/mutex storage, native mutex initialization, cloned root/name strings,
   relative paths and prepared component CStrings. Bound complete paths using
   depth and name limits, including separators and terminators.
4. Root configuration/path/CString copies, physical-root registry entries and
   ancestor-lock descriptor bookkeeping. Include actual configured root-path
   lengths and checked root-count/depth products.
5. Census cursor stack, directory-iteration workspace, bounded copied entry names,
   and temporary verification/preparation state.
6. Container capacity/headroom and allocator overhead, including the replacement
   peak rather than just `len * size_of::<Entry>()`.

Serialize preparation before its allocations, or reserve a separately bounded
preparation slot. `prepare_file` is currently serialized by owner state;
`prepare_publication` prepares paths before that lock. Its descriptor-owner limit
alone does not bound arbitrarily many callers holding clones and preparing paths.
Preserve the established drop ordering when changing that sequence: release the
state lock before a registered FileOwner destructor; provisional raw-descriptor
close may remain serialized under that lock.

These are conservative workspace estimates, consistent with current NodeAdmission
semantics. Hash-table cardinality, sampled RSS and byte estimates are not exact
allocator accounting or an OOM-proof guarantee. State the estimate and validate
measured peaks. Do not present a presumed hash-table layout as a portable proof.

Recalculate installation/example policy before choosing constants. The current
one-million-entry census limit, two ledgers, 4,096 handles and 64-component paths
can consume much of the default 512 MiB reservation budget. Deny an impossible
installation before allocation rather than silently reducing coverage.

### Snapshot-startup inventory

Give `SnapshotStartups.owners` its own bounded facade base reservation against the
shared core. Reserve before vector allocation/growth and enforce an explicit
startup-registration limit. An owner's child-buffer reservation covers its actual
child resources; it cannot cover unused vector capacity retained by a facade.

On sealed, completed startup drain, release the vector allocation itself and then
its base charge. If any startup remains retained, keep both inventory and charge.
A complete terminal failure can remain in the typed report without retaining an
otherwise unused inventory allocation. New facades receive fresh startup fences
while sharing the same memory core and existing installed-storage charge.

## Slice B: directory ownership and namespace accounting

### Recommended policy and API

Add explicit installed directory-extent and directory-entry allowances. Require
them in first-release configuration. Reserve each enrolled directory's full
namespace allowance; retain the unused part in DeviceDisk promises. A filesystem
allocation unit is not, by itself, a demonstrated maximum directory-growth bound.
Document the supported extent model and qualification evidence.

Recommended over-limit policy: a census records actual existing usage and permits
verified read/cleanup while denying growth, matching the current regular-file
approach. It must not drop excess usage to the configured allowance. A stricter
startup rejection policy is possible but must be chosen explicitly.

Extend the existing handle limit to include directory owners, with names/docs
updated directly, or introduce a separate mandatory directory-handle limit.
Whichever policy is chosen, raw session directory descriptors must no longer sit
outside handle admission or the drain predicate.

Use an opaque owner with an API along these lines:

```text
open_directory(installed_root, relative) -> NodeDiskDirectory
create_directory(parent_owner, single_name, work) -> NodeDiskDirectory
directory.sync_all()
delete_directory(exclusive_empty_directory_owner)
```

Opening an installed root is explicit. Creating/deleting that root through the
descendant API is forbidden. Do not add an adopting `create_dir_all`: existing
components must already be enrolled; absent components require admitted creation.
Directory identities grant physical custody, not authorization to reclaim a
generation or bypass its permanent stop/worker-drain requirements.

Each handle retains the actual directory/parent descriptors and prepared exact
binding. File owners retain parent custody, so deleting a directory cannot race a
managed child file. Directory owners and cursors count toward drain. Ledger entries
distinguish regular files and directories and survive descriptor closure.

### Accounting transition

Census enrolls roots and every descendant directory. Existing file `O_CREAT`,
rename and unlink also mutate directory extents; updating only mkdir/rmdir would
leave the contract incomplete. Cross-directory publication updates both parents;
same-parent publication deduplicates their accounting.

For each namespace mutation:

1. Prepare memory, handle slots, names, error representation and ledger capacity.
2. Under owner serialization, verify health, shared-device admission, enrolled
   parent identities, exact path binding and namespace reservation.
3. Mark affected entries unsettled before the first physical mutation.
4. Perform descriptor-relative mutation; verify identities/extents and sync the
   relevant inode and affected parents.
5. Update prepared/existing bookkeeping without allocation. For deletion, close
   the final actual descriptor before advertising drain or returning its credit.

A definite create-only conflict can roll back unused admission. Uncertain I/O or
unexpected physical growth retains the observed charge and fences the owner. Only
actual drain plus fresh census resolves uncertainty. A missing path alone cannot
authorize a credit or cleanup-complete result. Post-publication failure returns
must remain nonallocating, as in the existing file execution boundary.

Use the real allocated/observed extent in directory settlement. Do not subtract
an assumed block on deletion, infer extent from entry count alone, or let a raw
writer silently enroll an unknown object. Directory-size checks cannot prove a
complete namespace inventory when unrelated entries fit in existing allocation;
any stronger namespace-count guarantee needs bounded enumeration or equivalent
retained membership verification, and corresponding admission/test coverage.

## Exact implementation scope and ordering

### Memory slice

- `crates/kasumi-store/src/node_disk.rs`: mandatory memory owner, charge lifetime,
  registry identity checks and metadata requirement calculation.
- New `crates/kasumi-store/src/node_disk/memory.rs`: interface/charge planning if
  separation improves review.
- `crates/kasumi-store/src/node_disk/{census.rs,file.rs,tests.rs}`: charged census
  peak, bounded preparation, counters and counterexamples.
- `crates/kasumi-store/src/{lib.rs,test_utils.rs}`: exports and bounded test-only
  memory owner; update every constructor caller.
- `crates/kasumi-engine/src/admission.rs`, optionally new
  `admission_storage.rs`: shared core, runtime facade, installed reservations,
  inventory capacity ownership and store-interface implementation.
- `crates/kasumi-server/src/persistent_disk.rs`: mandatory installed governor
  propagation and explicit installation policy.
- `crates/kasumi-server/src/{runtime.rs,authority_runtime.rs,standalone.rs,signer_runtime.rs}`:
  construct/reuse admission before disk opening and retain the proper facade/core.

Do not start the directory/configuration slice until the memory slice has a stable
source checkpoint and coordinated checks. Do not add a store-to-engine dependency.

### Directory successor

- New `crates/kasumi-store/src/node_disk/directory.rs`, plus
  `node_disk.rs`, `node_disk/{census.rs,file.rs,tests.rs}` and `lib.rs`.
- `crates/kasumi-store/src/audit_archive.rs`: archive directory creation/sync.
- `crates/kasumi-store/src/backup.rs`: destination directory creation.
- `crates/kasumi-store/src/backup_sessions_fs.rs`: replace raw directory handles,
  mkdir/sync operations and enumeration custody.
- `crates/kasumi-server/src/local_recovery.rs`: generation parent/directory setup,
  directory removal and durable absence resolution.
- `crates/kasumi-server/src/local_recovery_archives.rs`: archive directory creation
  and removal under the retained journal identity.
- `crates/kasumi-server/src/target_runtime.rs`: generation-root setup and
  absent-file cleanup synchronization.
- `crates/kasumi-server/src/{standalone.rs,signer_runtime.rs}`: distinguish explicit
  top-level installer creation before the first census from descendant mutations
  after enrollment. Operator material outside installed persistent roots requires
  its own explicit scope; do not infer new roots from its paths.
- Update installation generators, examples and all relevant fixtures for the
  final mandatory policies. Keep private-root enforcement intact.

Re-audit raw file mutations alongside directory adoption: earlier archive and
installation migrations changed some callers, and an outdated path inventory must
not authorize either duplicate migration or a remaining bypass.

## Test and qualification map

| Test | Required observation |
| --- | --- |
| Metadata denial before startup | A bounded governor denies before roots/census collections/owner maps are allocated or a storage inode is created. No partial registry owner is published. |
| Census replacement peak | Old ledger and replacement workspace remain covered simultaneously; cancellation/failure preserves the old owner/charge and releases only abandoned temporary allocations. |
| Cardinality and path bounds | Maximum root/entry/handle/depth/name products are checked before allocation; overflow and impossible envelopes fail without partial mutation. |
| Installed reservation versus operation slots | Filling all 64 operation slots does not itself block a separately affordable installed reservation. Installed reservation changes byte counters and zero operation slots. Byte/RSS denial still applies. |
| Runtime replacement | The retained disk remains charged to the same core; a new facade sees that charge, has a fresh startup fence, and cannot replace the governor identity or policy. |
| Failed startup and pause | Facade cancellation/close does not release memory owned by a retained NodeDisk, old census ledger, error owner or unfinished startup. |
| Startup vector capacity | Dropped buffer owners do not uncharge retained vector capacity; retained drain keeps the base charge; sealed completed drain frees the vector before releasing the charge. |
| Governor bookkeeping | Empty logical charge tables do not leave uncharged retained capacity; reservation-count/base-envelope limits are enforced. |
| Directory census | Roots, nested directories and regular files are charged exactly once; repeated census retains identity rules and covers replacement memory. |
| Namespace admission | Directory entry/extent/handle/memory denial occurs before mkdir or file-name creation/rename. Other persistent/scratch owners cannot spend reserved parent growth capacity. |
| File-induced parent growth | File creation, same-parent rename, cross-parent rename and unlink settle all affected directory entries without double counting. |
| Identity substitution/raw mutation | A substituted directory, changed parent binding or unknown raw object cannot be adopted. Extent checks and any claimed namespace membership/count checks have distinct counterexamples. |
| Retained child custody | A live child file, directory handle or cursor prevents directory deletion and drained reconciliation; cloned facades do not manufacture physical drain. |
| Irreversible failure | Inject after successful mkdir, rename, truncate, unlink and rmdir, and at relevant sync/verification steps. Preserve charges, actual descriptor custody/drain and the failed owner until census. |
| Nonallocating execution | Count allocations over the real prepared mutation boundary, including successful settlement and failure return/destructor paths. Assertions remain exactly zero. |
| Already absent cleanup | A retry cannot declare completion or return credit from absence alone; the exact admitted parent and required sync/census must resolve uncertainty. |
| Configuration/API closure | Missing admission/new required policy, old aliases and uncharged production constructors are rejected. Test-only bounded governors cannot enter production configuration. |
| Resource qualification | Measure ledger/census peaks and directory allocation on supported filesystems under the release corpus. Record estimate limits and unexpected-growth dispositions; do not infer success from unit tests alone. |

Run checks only after a coordinated stable source checkpoint. Preserve failed
logs, command/source identity, real process deadlines and actual process-group
drain. Do not mark the first-release memory/directory requirements complete from
this proposal or from an implementation that omits caller adoption or qualification.
