# Proposed filesystem job ownership

Status: **proposed and unimplemented**. This document records a read-only audit
and an implementation proposal. It is not evidence that the ownership gaps are
fixed or that any release gate passes. No Rust source edits or builds were made
for this audit.

Implementation must happen in `/Users/mtakemiya/dev/kasumi` on `master` only.
This is the first release: replace the affected contracts directly. Do not add
compatibility constructors, optional production owners, uncharged defaults,
registry fallbacks, migrations, or detached cleanup/reaper tasks.

## Current gaps

The following filesystem destination methods await a locally held
`spawn_blocking` handle. Cancelling their caller drops that handle while the
blocking child can continue. The closures retain some resources, but no installed
owner retains the exact handle and its original terminal outcome for typed drain.

| File | Methods | Audit location |
| --- | --- | --- |
| `crates/kasumi-store/src/audit_archive.rs` | `FilesystemAuditArchive::{publish, read}` | Direct dispatches near lines 761 and 767 |
| `crates/kasumi-store/src/backup.rs` | `FilesystemBackupDestination::{session_put, session_get, session_objects, session_delete, put, get}` | Direct dispatches near lines 407, 417, 426, 440, 449 and 479 |

Line numbers describe the audited source and may move. The named methods are the
integration boundaries.

Holding an `Arc<NodeDisk>` does not fence a census. `NodeDisk::pause` and
`NodeDisk::reconcile` check open files, but an accepted blocking child can still
be queued or paused before opening its first file. A zero-open-files observation
therefore does not prove that filesystem work has stopped. Original I/O errors
and `JoinError` panic outcomes can also disappear after caller cancellation.

Several engine operations have a separate handle-ownership gap:

* `full_backup.rs::publish_full_backup` starts the producer near line 216 and
  awaits it only near line 295. Cancellation or a destination error before that
  await detaches the handle. Dropping the channel receiver eventually unblocks
  `blocking_send`, and `StreamWork` retains its reservation and work registration,
  but neither fact preserves the actual join or panic outcome.
* `full_backup.rs::copy_audit_dependencies` starts an audit-cache read near line
  455. Its cancellation branch near line 473 discards the handle.
* `backup_verify.rs::VerificationDeadline::blocking` passes a blocking handle
  directly into a timeout near line 181. The handle and its eventual error are
  lost when the deadline expires. Callers include complete-graph verification,
  `backup_restore.rs` materialization, and `backup_checkpoints.rs` finalization.
  The existing expired-restore-worker test proves charge retention while the
  child runs; it does not prove retained join/outcome custody.

Those engine operations remain a separate follow-up to the store slice below.
The store slice alone does not fix their independent blocking children.

## Existing ownership to preserve

`SecurityAudit::{maintain, verify_archive, export_page}` execute under retained
`security_audit_jobs::run_owned` jobs. The automatic security audit worker is
retained and joined by `SecurityAudit::shutdown`. Database audit preparation has
its retained `database_workers::BlockingChild` and supervisor. These paths must
not be described as unowned merely because they contain a nested blocking call.

The remaining direct dispatches found in `tenant_audit.rs` and
`snapshot_bundle.rs` were test helpers. Synchronous archive
`publish_blocking`/`read_blocking` are valid when an independently retained parent
owns that blocking work. They must not acquire an unnecessary nested async
worker as part of this change.

`BlockingChild<T>` is not a drop-in generic replacement: its drain currently
observes join failure but drops successful `T`, which could itself be an
unclaimed `Result::Err`. A general filesystem owner must preserve both levels.

## Smallest store implementation slice

Introduce `kasumi_store::FilesystemIoOwner`, shared by filesystem archive and
backup destinations belonging to one exclusive runtime/startup scope. Append a
required `Arc<FilesystemIoOwner>` to both destination constructors. Do not permit
production construction without an explicit owner.

The owner constructor receives an explicitly retained reservation/capacity token.
`kasumi_serving::BackgroundWorkBudget` is a possible reusable basis; store already
depends on serving. This token must represent a real installed node reservation,
not an `Arc<()>` outside an explicit test fixture. The implementation must expose
the required bounded metadata/workspace size so the trusted installer can reserve
it before construction. A full metadata-governor redesign is not a prerequisite
for this slice, but its own child slots and buffers must be charged.

Use a fixed slot table. Reserve a free slot, byte capacity, and the disk job guard
synchronously before spawning or cloning large inputs. A bounded-capacity
rejection starts no child and is an ordinary `ResourceExhausted` result; it must
not poison the owner.

Retain the actual blocking `JoinHandle` in custody. One option is to add a direct
`BackgroundWork::start_blocking_result` operation with the existing custody
semantics. An equivalent store-specific implementation is acceptable. An async
reaper which merely awaits a separately detachable blocking handle is not the
required ownership boundary.

Keep the custody graph acyclic:

* The completion cell holds phase and outcome, not a handle or runtime back
  reference. Custody holds the exact child handle.
* Closures capture the required disk, directory, observer and work buffers,
  rather than the enclosing filesystem owner.
* Runtime/startup resources retain their filesystem owner directly. `NodeDisk`
  must not hold that owner; an owner already retains the disk.
* Strong process custody begins only when actual work is accepted. A newly
  constructed unused owner must drop normally.

Each accepted call returns a waiter/reply channel. Cancelling that waiter leaves
the slot, actual handle, disk guard and byte owner in custody. A result channel
alone is not custody for the child.

Latch original I/O errors and actual `JoinError` outcomes once as shared
`Arc<DrainIssue>` evidence. Await handles in place during drain; publish each
terminal outcome before removing its slot or awaiting the next child. Cancellation
of drain must leave both unjoined handles and already recorded outcomes available
to a subsequent drain. Repeated drain reports the same original evidence and
must not fabricate success after a failure.

Unexpected I/O failure or panic closes further admission so retained terminal
evidence remains bounded. Expected request rejections and known create-only
conflicts remain normal operation responses rather than infrastructure failures.
That classification must be explicit: do not erase an uncertain publication or
physical failure by converting it to an expected conflict.

## Fence queued work in NodeDisk

Add a `pending_filesystem_jobs` count under the same `NodeDisk` state lock used by
pause and reconciliation. Acquire a bounded RAII job guard before dispatch and
retain it through actual join and disposition of the worker output. Both pause
and reconciliation must require:

```text
open_files == 0 && pending_filesystem_jobs == 0
```

The guard closes the pre-open gap: a queued child prevents an idle census even
when it has not opened a `NodeDiskFile`. Admission and the census check must use
the same synchronization boundary; separate atomic checks would leave a race.
The guard must neither release physical charges nor imply that an uncertain
write has been reconciled.

## Buffer and output reservations

The constructor reservation must cover fixed slots/task metadata and the bounded
transient workspace of accepted children. Audit publication clones up to one
8 MiB ciphertext segment and can hold a readback at the same time. Backup
`put`/`session_put` retain their input bytes. `session_delete` clones a bounded
page of at most 256 objects. Perform admission before these clones or allocations.

Successful outputs require a separate, explicit lifetime transfer:

| Operation | Output that can outlive the child |
| --- | --- |
| Archive `read` | Ciphertext byte vector |
| Backup `get` | Encrypted object byte vector |
| Backup `session_get` | Optional encrypted record/object byte vector |
| Backup `session_objects` | Bounded object page and its owned metadata |

Releasing a child slot when a reply is delivered must not release the output's
memory charge. The safest direct first-release contract is a charged byte/page
output that carries the same reservation lease until consumption/drop. An
explicit, verified handoff to an already retained caller reservation is another
possible implementation. The current bare `Vec<u8>` return type does not prove
that handoff. Do not claim that task-metadata custody alone completes memory
accounting for returned buffers. S3 implementations and trait callers must follow
any directly replaced charged-output contract as well.

Outputs can release their filesystem job guard after the actual child is joined
when they contain only inert data; their byte reservation must remain. Outputs
which retain an open file or other physical owner must retain that owner's fence
until it is actually closed.

## Constructor and installation integration

Replace dispatches in the eight store methods listed above with the shared owner.
Keep the synchronous archive methods available to already-owned blocking parents.

In `kasumi-server`, the concrete integration points are:

1. `runtime.rs::NodeRuntime::open_owned`: `NodeAdmission` already exists before
   the destination map is opened near line 1138. Reserve/create the filesystem
   scope there and register it with startup resources before work can start.
2. `administration.rs::DestinationConfig::open`: thread the required owner into
   filesystem backup construction.
3. `audit_destination.rs::AuditDestinationConfig::open` and
   `RuntimeConfig::install_tenant_audit_archive`: pass it into external archive
   and local cache construction.
4. `runtime.rs::SecurityAuditConfig::destination`: pass the owner into default
   and configured security audit archives.
5. `local_recovery_archives.rs::observed_archives`: supply the scope to the
   filesystem cache carrying the durable publication observer.
6. Authority runtime, standalone initialization/operator, and target/recovery
   constructors must pass the same explicit scope appropriate to their owned
   resources. Fixture helpers must remain explicit test APIs.

Fresh partial provisioning on a live node needs a newly owned scope on the same
installed `NodeDisk`, with its own admitted capacity. Cleanup may drain that scope;
it must never globally close a borrowed live runtime's scope. Shared archive and
backup destinations within one exclusive scope should share its bounded owner.

Two current construction shortcuts need direct contract changes:

* `TenantStore::tenant_audit_archive` lazily opens a local cache without a
  `NodeAdmission`. Prefer requiring explicitly installed placement before use.
  Alternatively, require the filesystem owner when constructing the tenant
  store. Do not manufacture an uncharged owner in this getter.
* `kasumi-engine::SecurityAudit::{initialize, open}` construct default archives
  internally. They need explicit owner plumbing in addition to the server's
  archive-opening helpers.

## Shutdown and startup-error ordering

An observed recovery archive retains a publication observer which can write to
the security `TenantStore`. Filesystem drain therefore must finish before that
store closes. Conversely, sealing the shared filesystem owner before the audit
worker finishes would reject the worker's necessary publication/readback.

Split security audit shutdown into reusable worker drain and final store close:
the proposed `SecurityAudit::drain_workers` seals its own job admission, joins its
worker/jobs and retains the original report, while leaving the store usable by
already accepted filesystem observers. Final `shutdown` reuses that drain and
then closes the store. It must remain cancellation-safe and repeat-safe.

The required outer order is:

1. Stop listeners, target/administrative producers and groups.
2. Drain retained unpublished startup work while its borrowed storage is live.
3. Drain security audit workers/jobs without closing their store.
4. Seal and drain the owned filesystem scope, including queued pre-open children.
5. Close audit stores, journals, remaining stores and exclusively owned
   `NodeStore`s only when the necessary prior drains prove completion.

Apply this order in both `startup_resources.rs::Resources::close` and
`runtime.rs::NodeRuntime::shutdown`, with corresponding authority/operator paths.
Store owned filesystem scopes explicitly alongside the existing owned resources.
Preserve original drain failures through the existing `DrainReport` merging;
resource completion does not erase a worker's failure. A retained child prevents
claiming the enclosing scope fully drained.

## Required regression tests

Use real spawned blocking children and explicit synchronization barriers/hooks.
Elapsed time, a dropped waiter, a weak-count change, or a work-registration count
alone is not proof that the actual handle joined.

1. Pause a child before its first file open, cancel its caller, and prove that
   `NodeDisk::pause`/`reconcile` cannot establish idle despite zero open files.
2. Cancel the first drain waiter while the real child is paused. A second drain
   must wait for and join the same handle.
3. Cause a real disk failure after caller cancellation. Repeated drain must
   preserve the same original shared issue, including its typed underlying error.
4. Panic inside the actual blocking child. Preserve the original `JoinError` and
   payload; retain the associated bounded custody until outcome observation.
5. Pause publication after writing but before final synchronization, cancel the
   caller, then release and drain. Verify the exact final/pending state and prove
   no later write occurs after drain completion.
6. Deliver a read result and a session object page. Their transferred memory
   charges must survive child completion and last until the outputs are dropped.
7. Fill every admitted slot. The next call must reject before spawning or cloning
   a large input; the capacity rejection must not poison the owner.
8. Drop public destination and owner facades while a child is blocked. Actual
   handle, resources and reservation must remain in independent custody.
9. Share one owner across archive and backup and drain both. Separately prove that
   draining a newly owned scope does not close another borrowed live scope.
10. Fail startup while observed archive work is paused. Cleanup must join it
    before closing the security journal/store used by its publication observer.

Existing `backup_sessions_fs.rs::test_sync` points and NodeDisk parent-sync fault
hooks can exercise actual filesystem failures. Add hooks only where needed to
control the real child, rather than substituting a detached mock timer.

The follow-up engine slice additionally needs cancelled producer, cancelled
audit-cache read, and expired verification-child tests that preserve actual
failure/panic outcomes through typed drain. Existing reservation-retention tests
are useful but do not substitute for these ownership tests.

## Limits of this proposed slice

This plan does not qualify the release, redesign the full memory governor, fix
all remaining directory accounting, or implement the independent engine child
owners. Those remain separate work. The store slice is complete only when every
accepted child is owned before dispatch, its resources and original outcomes
survive caller/drain cancellation, shutdown has the correct dependency order,
and the regression tests above pass under coordinated validation.
