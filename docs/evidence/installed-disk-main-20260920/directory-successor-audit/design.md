# Proposed next implementation: admitted directory parents

Status: read-only design against the applied metadata/caller stack on master. Unimplemented. No Cargo/build or Rust source changes were made for this audit. This is a direct first-release API/configuration change; no aliases, optional owner, implicit governor, raw-directory adoption, or compatibility path.

## Conclusion and smallest coherent unit

Implement directory enrollment and a prepared affected-parent transition inside NodeDisk first, and route ALL existing managed file create/rename/unlink through it in the same slice. An isolated mkdir wrapper would leave ordinary file operations capable of consuming unreserved directory storage. Keep this store-level foundation synchronous; migrate the three store filesystem destinations after they have an actual retained blocking-worker owner. Server generation cleanup is the next caller slice and must retain its existing journal authorization and actual worker-drain prerequisites.

Current rename already synchronizes both the source and destination directory (file.rs). The defect is not a missing second-parent fsync: both parents are unaccounted, raw descriptors do not enter the drain predicate, and newly created ancestors can be outside NodeDisk durability/identity custody. Do not redo the now-applied mandatory memory governor slice.

## Verified current gaps

* `node_disk/census.rs::census` visits/syncs directories but inserts only regular files into `accounted`; configured root extents are also omitted. `max_census_entries` currently bounds traversal work, including dot entries, rather than an exact inode count.
* `census::parent` checks each traversed directory's mode/device but has no retained directory enrollment to match. `file::verify_parent` compares only the final parent with its retained FD. Replacing an intermediate ancestor and moving the original final parent back underneath it can preserve that final identity. NamespaceBinding hashes root identity and component names, not every ancestor inode.
* Create syncs the new file and immediate parent; rename syncs old/new parents; unlink syncs the immediate parent. None pre-admits or observes parent extents, pending promises, or directory membership. Same-parent rename currently syncs two FDs for the same parent.
* `backup_sessions_fs::Directory(File, Arc<NodeDisk>, PathBuf)` creates descendants with raw mkdirat, retains uncounted FDs, and opens a raw fdopendir cursor. NodeDisk `open_files == 0` therefore does not prove these resources drained. The successor predicate is zero file owners, zero directory/cursor owners and zero actual worker permits. Its directory NotFound and raw sync paths cannot distinguish an enrolled directory disappearing from an unknown name.
* FilesystemAuditArchive::open and FilesystemBackupDestination::new create directories after disk binding/census. Local recovery/archive setup and target_runtime do the same; target_runtime uses create_dir_all. File fsync plus leaf-parent fsync does not retrospectively prove durable creation of every ancestor.
* Archive publish/read and backup put/get/session methods directly await spawn_blocking JoinHandles. Cancellation drops the waiter/handle while actual blocking work may continue. A held Arc<NodeDisk> or parent FD protects allocation lifetime but does not provide a discoverable operation census or stop a later file open after an apparent zero-handle observation.

## A. Concrete store foundation

### Policy and accounting

Add mandatory `max_directory_bytes: u64` (per-directory namespace extent allowance) and `max_directory_entries: u64` (non-dot immediate children). Add mandatory `max_open_directories: u32`, counting independent directory owners and enumeration cursors; preserve the existing max_open_files/file-owner allowance and its original 4,096 production coverage. Each file owner's already-accounted parent FD remains inside that file-owner envelope but contributes retained child custody. Keep configured root/ancestor lock descriptors in their already-admitted installed base; opening an operational root handle consumes a directory slot. A prepared mutation's temporary FDs must be included in the bounded preparation peak, not silently counted as unlimited handles. Retain existing total disk bytes, maintenance reserve, free-space and census-work policies.

For each directory, reserve its full configured namespace allowance: `charged = max(observed_allocated_bytes, allowance)`, `pending = charged - observed_allocated_bytes`. Directory logical st_size is not a regular-file sparse reservation and must not use `extent()`'s file-length rounding formula. When an existing directory exceeds its allowance, retain the entire observed extent, allow verified reads/authorized cleanup, and deny growth; do not clamp or silently enroll less. Reconciliation measures again only after actual drain.

Do not choose numeric defaults from the filesystem allocation unit or this audit. A configured cap plus a post-I/O fence is a useful bounded disposition, but is NOT proof the filesystem cannot allocate beyond the pre-admitted allowance. Before claiming strict physical pre-admission, qualify a directory-growth upper bound/control on each supported filesystem or explicitly keep that release gate open. st_blocks accounting also does not quantify all filesystem-global B-tree/journal metadata. Document the supported accounting model; do not hide this distinction with a constant.

Census must enroll roots and every directory with kind, physical identity, parent identity/binding (roots have no managed parent), observed extent, full allowance/promise, immediate child count, and settled state. Rename AccountedFile to an inode entry with an explicit file/directory variant. Each regular-file entry also retains its parent identity. Check all roots plus descendants against existing bounded traversal/ledger capacity; preserve the traversal budget's current semantics unless deliberately replacing that public policy. Account roots separately in the maximum ledger formula.

For strict raw-namespace detection, retain parent membership through the inode ledger and compare a bounded enumeration against enrolled children before namespace mutation (and during an explicit directory verification/emptiness check). Extent/count alone misses a raw child that fits existing allocation, a removed child replaced with another, and an ancestor substitution. Return borrowed bounded entry names from the cursor so verification can remain allocation-free where required. A scan over the bounded ledger is a valid first implementation; do not add an uncharged index. Its potentially quadratic cost must be measured before qualification. OS advisory ownership cannot prevent an arbitrary external process racing the verified syscall; preserve the existing private-root/cooperative-owner assumptions and fence detected changes.

### Canonical synchronous API

Suggested direct interface (names may be adjusted together, never kept as aliases):

    disk.open_directory(root_label, relative) -> io::Result<NodeDiskDirectory>
    parent.open_child(name) -> io::Result<Option<NodeDiskDirectory>>
    parent.create_child(name, DiskWork) -> io::Result<NodeDiskDirectory>
    directory.sync_all() -> io::Result<()>
    directory.entries(limit) -> io::Result<NodeDiskDirectoryCursor>
    disk.delete_directory(exclusive_empty_directory) -> io::Result<()>

Use empty relative only for explicit opening of the configured root. Descendant create/delete cannot create or remove a configured root. Known directory absence/substitution fences; unknown absence is healthy only after verifying the enrolled parent/ancestry. `create_child` is exclusive; create-or-open callers first call open_child and then create_child, handling only a proved create-only race. There is no create_dir_all or path-based adoption of a raw directory.

Directory/file owners retain physical parent custody; deleting a directory must reject live child file/directory owners or cursors. Avoid a global registry of strong operational directory handles, which would make drain impossible. The existing installed root owner remains strong; per-inode directory entries survive operational FD closure. A directory owner retains its exact descriptor and a prepared ancestry chain. During traversal, match EACH directory inode to the retained `(parent identity, binding, kind)` entry, not just the final parent's FD.

### One internal prepared transition

Introduce a private prepared namespace mutation used by file create, file publish/rename, file unlink, directory mkdir and directory rmdir. It owns a fixed array of at most two affected parent identities/FDs, deduplicated by physical identity. Parent slots come from the existing ledger; new child slot, live handle capacity, paths, CStrings, Arc storage, directory stream buffers needed for membership verification, and inline errors are prepared before the physical effect.

Under NodeDisk serialization: verify core/device/phase, exact enrolled ancestry and membership, growth admission, handle quota, and ledger slots; mark every affected parent plus a new/deleted/moved child unsettled. Execute descriptor-relative syscall. Immediately after success update in-memory name/parent binding without allocation; preserve that new binding even if later durability fails. Observe affected directory extents, sync child where applicable and every distinct affected parent, verify enrollment again, and settle existing entries without allocation. A no-replace rename's source and destination parents BOTH participate. A same-parent rename participates once.

For mkdir, prepare and reserve the new directory's own full allowance before mkdirat, then observe/sync its FD and parent. For rmdir, verify empty enrolled membership and exclusive physical custody, call unlinkat(AT_REMOVEDIR), sync the exact retained parent and close the actual final child FD before returning its disk/promise/handle credit. For file unlink preserve the current close-before-credit rule while also settling its parent. Known absence after uncertain mutation is not success or credit: the failed/unsettled owner stays fenced until actual drain and fresh census. Preserve actual original inline io::Error; no formatted diagnostic or map growth after an irreversible syscall.

This transition must preserve current Paused behavior: already admitted operation completion/drain is allowed; fresh growth/dispatch is not. Failed shared-device/owner state forbids credit. Do not hold state while dropping a registered owner that recursively locks state; provisional raw descriptors and prepared uninitialized owners remain distinct.

### Memory/limits delta

Update `required_metadata_bytes` before allocating the new structures. Cover two `(roots + bounded descendant entries)` ledgers of the new inode entry, the live owner index including directory variants, maximum operational directory/cursor owners and their actual FD/path storage, each file's retained parent custody, and fixed two-parent/prepared-child mutation peak. Enumeration DIR allocation and replacement-census cursor peak remain included. Reuse the same mandatory memory lease/core and fixed installed envelope; do not allocate a new governor or per-call adapter. Formula values are checked estimates requiring platform peak qualification, as today. Update installed/example policies deliberately from actual revised formulas; never reduce original 1M/4096 coverage to fit the old budget.

## B. Worker owner prerequisite for async destination adoption

Before routing the async archive/backup wrappers through the new owner API, introduce/reuse a bounded runtime-owned filesystem work scope. Required semantics are concrete:

1. The exact same memory core admits scope inventory and task/capture overhead BEFORE task allocation, and payload/result workspace has its existing real operation reservation. A directory metadata envelope does not implicitly pay for copied ciphertext or arbitrary result Vecs.
2. Register an actual worker slot and acquire a NodeDisk operation permit before dispatch; publish/retain the JoinHandle before any cancellation await. The permit remains until the actual closure has finished and all captured operational FDs/cursors are closed. It prevents reconciliation even during gaps between file opens.
3. Cancellation may abandon a reply but not remove the worker from its owner's inventory. Seal blocks new dispatch; drain joins every actual handle, retains original panic/I/O outcome, and preserves discoverable custody across cancelled/retried drain. A completed handle's stored result is still charged until consumed/destroyed.
4. A draining future borrows the retained scope; it must not mem::take the only handles into itself. Do not treat abort requested, timeout, Arc drop or zero file/directory handle counts alone as completion.
5. Persistent NodeDisk is shared across runtime restarts, so keep runtime worker-scope closing state separate from installed owner state. NodeDisk tracks active permits for pause/reconcile; the enclosing runtime/startup owner retains/drains the scope. No store -> engine dependency is needed: a store-level scope uses the mandatory resource interface and kasumi_types::drain; engine/server installs it in its existing owned-resource graph.

For a first implementation, synchronous `*_blocking` calls may run under an already explicit retained worker owner. Do not add a second spawn merely to adopt directories. The filesystem async trait implementation must require an installed scope or be directly replaced; no detached fallback path. Arbitrary panic/error payload bounds remain a separate qualification issue: preserve them and keep their funding/custody, never claim a small slot covers unbounded payload.

## C. Caller adoption and exact file scope

Foundation together:
- `crates/kasumi-store/src/node_disk.rs`: mandatory policies, inode ledger, directory-handle/active-operation drain counters, API and snapshots.
- `node_disk/census.rs`: root/descendant enrollment, parent linkage, bounded membership cursor.
- NEW `node_disk/directory.rs`: opaque directory/cursor and prepared affected-parent transition.
- `node_disk/file.rs`: file create/publish/unlink delegation, retained parent custody, exact ancestor verification; preserve existing winning-boundary zero-allocation behavior.
- `node_disk/memory.rs`, `node_disk/tests.rs`, `lib.rs`, `test_utils.rs`: new formula, exports, explicit policies and regression fixtures.
- Configuration generators/examples and every explicit NodeDiskConfig construction: mandatory new fields, same original file workloads and limits; recalculate metadata-only allowance deltas.

Store caller layer, after worker scope is real:
- `audit_archive.rs`: replace root create/check/raw parent sync with enrolled directory handle; retain handle in destination, adopt workers without payload cloning outside an actual reservation.
- `backup.rs`: same destination construction and all six blocking wrappers.
- `backup_sessions_fs.rs`: replace raw Directory, mkdirat, raw cursor and sync; retain authenticated abort/GC proof rules unchanged. Existing absence fences remain.
- New small filesystem-worker scope module only if no current bounded owner can be reused; add it to actual NodeStore/tenant/runtime close ownership, not just to a local future.

Then server descendant callers:
- `local_recovery.rs`: generations/target directory creation and exact empty rmdir; pause/drain and permanent stop/journal proof remain mandatory.
- `local_recovery_archives.rs`: admitted archive directory creation/removal under retained journal identity; never infer cleanup authority from physical ownership.
- `target_runtime.rs`: replace create_dir_all and raw root fsync/unknown file absence cleanup; an enrolled missing file must not become healthy cleanup merely through `target_file_exists == false`.
- `standalone.rs`/`signer_runtime.rs`: distinguish explicit installer top-level directories created before FIRST census from enrolled descendant mutation. No inferred extra roots for external operator material.
- Runtime/startup resource owners: install/seal/join filesystem scopes before directory/file reclamation and retained installation-lock release.

## D. Boundary test map

1. Census with root, nested directories and regular files: exact charged/pending totals, each inode once, immediate memberships; repeat drained census; failure/cancellation preserves original ledger/charge and closes temporary cursor FDs.
2. Deny bytes, directory entries, handles, memory, ledger overflow and free-space before create/mkdir/rename; inode names and physical extents unchanged. Default production count/depth coverage stays unchanged.
3. File create grows parent; same-parent rename settles one parent; cross-parent rename settles both, transfers immediate child counts; unlink retains any surviving parent allocation; another NodeDisk/ScratchDisk cannot spend directory promises.
4. Inject immediately after mkdir/rename/unlink/rmdir and each child/source-parent/destination-parent sync. Successful name movement updates binding immediately; exact original error retained, credits withheld, owner fenced until actual drain+census. Keep the existing per-file zero-allocation assertions and add the directory counterparts.
5. Unknown absent child stays healthy after parent verification; known disappeared child/parent fences. Replace intermediate ancestor then move the original final directory underneath replacement: must fence despite final inode matching. Unknown raw child within unchanged st_blocks, count-preserving substitution, unexpected symlink and foreign-device directory also fence.
6. A live child file, directory clone, cursor or admitted worker permit blocks directory deletion/reconciliation; close actual descriptors before decrement/credit. Configured roots cannot be removed. Genuine empty directory deletion frees only observed/retained directory charge after parent sync and final FD close.
7. Pause a blocking closure before its first file open; cancel its async waiter; observe reconciliation/cleanup remains blocked, then let it finish and prove one actual join and released work/capture charge. Repeat cancellation during drain and panic-after-publication, retaining original issue identity. Sealed scope rejects a fresh worker while a fresh runtime scope on the same core/disk remains separate.
8. End-to-end archive/session creation and stopped generation cleanup: fresh nested creation survives reopen; delete retries resolve exact parent durability; existing stop/abort authorization and deadlines/workloads unchanged. Test merely dropping a runtime is insufficient to claim physical drain.
9. Supported-filesystem qualification: large names/cardinalities, repeated same/cross-parent rename, delete churn and filesystem pressure; record actual allocated directory extent and peak memory. An unexpected over-cap extent is a failing qualification/fenced owner, not a test to relax.

No current gate proves this proposal, filesystem worst-case allocation, or worker-drain implementation. Implement and validate from a coordinated source checkpoint only after the active test cohort drains.
