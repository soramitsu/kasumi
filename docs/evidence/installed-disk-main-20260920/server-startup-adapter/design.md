# Server startup adapter: bounded ownership design

Status: **proposed and unimplemented**. Read-only audit of the integrated source in the sole master checkout `/Users/mtakemiya/dev/kasumi`, 2026-09-20. First-release direct replacement; no compatibility wrappers or fallback registry. Root reported workspace check 78 and formatting 79 passed; store 80 and engine 81 are separate behavioral validation. This document adds no qualification claim and was prepared without Rust builds or source edits. `source-inventory.json` records the exact inspected working-tree bytes; HEAD alone does not identify the integrated, uncommitted source.

## Recommendation

Keep `RuntimeStorage` as the immutable, reusable policy/core/disk-factory context. Introduce one admitted, retained **operation context** per open/installation, with one exact runtime facade and a fixed acquisition/cleanup inventory. Prepare it synchronously before the server allocates credential wrappers, boxes the opening future, allocates channels, or spawns work. Enroll its actual owner in `MemoryCore::prepare_startup_scope` before activation.

Use one ordered coordinator resource per operation initially. `StartupScope::poll_drain` polls every resource cell even when another cell is pending or retained. Separate independent resource cells do not impose the shutdown dependency ordering required by `Resources`. The coordinator must own and enforce that ordering, including retaining the installation lock last.

Do not implement `StartupResource for Resources`, nor wrap a `DrainFailure` in a fixed-size error and call it bounded. The current `Resources`, nested opening futures, and leaf diagnostic allocations do not satisfy that trait's ownership and accounting contract. A supervisor handle alone also does not independently retain resources that exist only inside the supervisor's future.

The next implementable prerequisite is the driver-ownership kernel described below. Its completion is not permission to wire opaque production resources into `StartupScope`. The smallest subsequent production conversion is target-journal installation, whose successful result is `()`, avoiding live-runtime publication until that separate handoff is designed.

## What the integrated code currently proves

* `RuntimeStorage::installed`, `facade`, `require_admission`, `open_persistent`, and `open_scratch` preserve exact policy/core identity. Owned runtime constructors now create their facade before opening physical disks. Reuse the same context and facade; do not create a second governor for cleanup.
* `startup_owner::begin` retains actual Tokio handles in a process-global registry. Cancellation of the calling `open` waiter does not detach the constructor. A buffered oneshot is not transfer: `Ticket::claim` performs synchronous publication, and rejected/abandoned results are cleaned by the retained task.
* `Resources::close` preserves original `DrainFailure` issues, distinguishes Complete from Retained, and drains fresh admission startup children before their borrowed storage closes. Borrowed nodes only join initializers; they are never globally shut down by partial provisioning.
* The integrated engine foundation admits a fixed core census and scope/resource allocations before activation. It keeps actual cells through canceled drains, uses a pre-admitted proxy waker, retains original direct-poll panic payloads, and releases the census slot only after Complete. `StartupReport` borrows the original retained diagnostics and keeps their owner/charges alive.

These are complementary pieces, not a completed server adapter.

## Gaps requiring direct replacement

| Existing surface | Concrete gap | Replacement requirement |
| --- | --- | --- |
| `startup_owner::{Registry, tasks, Kind, begin, open, drain}` | Six global `Vec<JoinHandle<Result<()>>>` registries; channel/future/task/handoff allocations have no admission; drain does not seal new opens. | Exact-core fixed scope census plus a typed operation receipt. Kind may remain a diagnostic label, never an ownership namespace. No static registry fallback. |
| `Registry::failure: Option<anyhow::Error>` | `get_or_insert` loses later independent failures; `take` clears prior outcomes after one observation. | Fixed outcome locations retaining every original admitted issue through cancellation and repeated observation; no observation-triggered clearing. |
| `Resources::default` and public `Vec::push` fields | Unbounded inventory/report; actual partial owners remain inside the fallible opening task. | Typed plan derives exact capacities from validated configuration; preallocated slots and retained acquisition results exist outside that task. Distinct owned/borrowed fields remain explicit. |
| `startup_preparation::capture` | Boxes immediately without a reservation; catches a poll panic but returns an anyhow wrapper, after which the caught future drops. | Admit the actual boxed future/captures before allocation. Retain a poisoned future and original payload without repolling. Independent resource cells may be drained, but uncertainty never becomes Complete. |
| `startup_owner::{Runtime::close, finish}` | Each close returns another boxed future; `finish` owns a growable merged report and retries on a timer. | Actual close futures and terminal outcomes retained in fixed coordinator cells. Readiness comes from actual completion; Retained returns a retained report and explicit retry remains possible. No detached timed cleanup loop or elapsed-time completion. |
| `Handoff<T>` / `Ticket<T>` | Handoff storage allocated only after opening; moving the runtime can leave the startup scope without an admitted normal owner. | Allocate result/publication state before activation; perform one synchronous claim with an explicit retained owner transfer or keep the same lifecycle owner. |
| `serving_owner::{Registration, Job, serve, drain}` | Separate global growable registry/report, with a 4096-byte registration allowance that does not itself prove all backing. | Must be accounted in live-runtime handoff. A startup adapter cannot report all resources released merely because `serve` accepted an object. This is a separate required conversion, not hidden inside this slice. |

`kasumi_types::drain::{DrainReport, DrainFailure}` currently owns `Vec`, `BTreeMap`, Arc issue allocations and arbitrary `anyhow::Error` payloads. Counting issues or reserving `size_of::<DrainFailure>()` cannot establish their backing. Likewise, `sizeof(JoinHandle)` does not measure a Tokio task or an arbitrary panic payload. The foundation's own task tests explicitly use the existing named task-workspace estimate and do not qualify allocator-layout guarantees.

## Proposed operation lifecycle

Proposed names below are design names, not currently exported APIs.

1. A synchronous entry point validates caller-owned input and selects `RuntimeStorage`. It derives an `OperationPlan` without cloning variable input. It creates the one fresh facade for an exclusively owned runtime, or records an explicitly borrowed facade for an operation on a live runtime. Exact policy/core checks precede disk acquisition and child activation.
2. Admit/enroll a scope and prepare one `OpeningCoordinator` with a fixed arena. Its trusted layout plan covers copied config/path/string capacities, owned credential/provider backing or a proven originating lease, result/publication storage, proxy notification state, actual future boxes, task workspace, diagnostic backing, and all fixed slot arrays. `Arc` header size alone does not cover the captured credential closure.
3. Allocate inert state only after admission. The coordinator owns the acquisition arena independently of the future that drives initialization. A constructor which can start a child before returning its facade must put the actual handle and result destination in that retained arena before its first suspension. Registering only the eventually returned `Arc<NodeStore>`/runtime is too late.
4. Activation installs any actual task handle synchronously, with no await or fallible application step between spawn and handle custody. The driver may hold a reference to the arena, but must not be its sole owner. Driver output is a fixed control enum; the original operation error/result remains in its admitted owner rather than moving into an anyhow task result.
5. The caller owns an `Opening<T>` receipt before it awaits readiness. Canceling its waiter drops only that waiter. No resource/future/actual handle leaves the coordinator. A ready-but-unclaimed result stays in the preallocated publication cell. An abandoned receipt selects cleanup without dropping the owner.
6. An installer returning `()` reports success only after its acquisition owners and driver have actually completed/drained. Completed failure preserves original diagnostic identity and charges until the last report drops. A joined handle is not by itself a successful operation.
7. A runtime-returning constructor requires an additional publication protocol: either the admitted coordinator remains the runtime's lifecycle owner, or ownership moves atomically to a separately admitted serving owner. There must never be a gap with only a caller's future retaining live physical owners. Do not mark the startup scope Complete while it still holds usable runtime resources.

The synchronous preparation API must expose a cleanup receipt even when preparation fails after scope enrollment. The existing foundation deliberately leaves an enrolled incomplete scope reachable from the core. Returning only an ordinary error and losing the receipt is not a rollback strategy. Inert failures with no physical ownership can be drained explicitly; poisoned allocation/future cases remain retained.

Do not create nested scopes/governors for helpers. Pass the exact context plus reserved slot ranges to nested provisioning/catalog/verifier helpers. Fresh-owned admission is enrolled once; a borrowed runtime facade must never enter the fresh-owned-admissions shutdown set.

### Locking and ordering

`ResourceHandle::activate`, `StartupScope::poll_drain`, and report visitation hold the scope state mutex. Activation must be short and synchronous. A polled driver must not recursively call `prepare` or `activate` on that same scope. Use the coordinator's already allocated arena for later acquisitions, with an explicit lock order; do not move the actual future out of its retained cell to avoid a borrow checker constraint.

The coordinator retains each in-flight leaf close future and polls the dependency stages in order. Preserve the existing sequence: authority/custody/database groups, then fresh facade startup census, then audit/journal/catalog/verifier and borrowed initializer work, with exclusively owned node close gated on dependent-resource completion. Keep the standalone lock until all dependent work is proven closed. The exact leaf dependency contract must determine whether a stage can advance after Retained; placing all owners in separate foundation cells does not prove that.

A canceled outer drain loses no previously joined failures and no later unfinished handle. Original outcomes remain in fixed cells. Completed leaf resources may free their work buffers only after their diagnostics and any borrowed report view no longer depend on those allocations.

### Claimed runtimes and aggregate drains

`MemoryCore::startup_scope_at` is a bounded lookup, not an atomic whole-core shutdown or a filter for unclaimed constructors. The current foundation has no claimed-runtime phase, transfer API, or core-wide admission seal.

For installer-only scopes, an exact receipt can directly drain its scope. For live runtimes, keep initializer-only cleanup separate from normal runtime shutdown. A partial tenant operation must not walk the entire shared core and close another claimed runtime. If claimed runtime ownership stays in the scope, `max_startup_scopes` becomes a bound on those live lifecycle owners as well; document and test that policy impact rather than treating a claimed scope as free.

Any aggregate shutdown needs an explicit admitted operation domain that seals its own new starts and visits its exact fixed scope IDs/generations. Process-wide traversal is valid only after the corresponding start admission is stopped and live serving owners have been handled. No global reset, automatic process registry healing, or inferred all-core completion.

## Exact entry-point migration map

| File / current entry points | Required adapter boundary |
| --- | --- |
| `runtime.rs`: `NodeRuntime::open`, `open_using`, `open_using_storage`, `open_owned`, `drain_startups` | Prepare receipt/context before credential `Arc` and opening future. `open_owned` consumes the retained context's exact facade/arena. Static drain becomes exact operation/domain drain; live-runtime publication remains a distinct phase. |
| `authority_runtime.rs`: `AuthorityRuntime::open`, `open_using_storage`, `open_owned`, `drain_startups` | Same, preserving readiness and authority owner ordering. |
| `data_node_enrollment.rs`, `authority_node_enrollment.rs`: `initialize[_with_storage]`, owned initializer and enrolled runtime handoff | Fresh facade belongs to retained context; installed markers and returned runtime remain owned through publication failure. |
| `signer_runtime.rs`: `initialize[_with_storage]`, `initialize_owned`, `drain_initializations`, internal verifier open/open-store helpers | Preplan node/catalog/verifier owners. Nested open consumes the parent slots and facade; stale signer fencing stays intact. |
| `target_journal_installation.rs`: `initialize[_with_storage]`, `initialize_owned`, `drain_initializations` | First production candidate after prerequisites: fixed one fresh facade/node/catalog/journal plus preparation and drain state; no live-runtime success handoff. |
| `standalone_operator.rs`: `run`, `OperatorState::open`, retain helpers, `finish`; `standalone.rs` initialization/operation wrappers and `drain_operations` | Replace generic future-taking `run` with plan/context-first operation entry. Future must not already contain uncharged copied config/result state. Preserve exact installed lock ownership. |
| `standalone_tenant_staging.rs` stage/status; `local_recovery.rs` start/resume/status/stop wrappers | Each receives its prepared operation context, with exact cleanup receipt. Retained target/recovery resources require their actual leaf owner contracts. |
| `configured_tenant_enrollment.rs`: selected proposal/open-enrollment; `administration.rs` tenant-enrollment drain | Serialization currently precedes its request reservation; moving it into a planned operation must admit before allocation. Borrowed admission/node remains borrowed. Administration drains only its enrollment domain. |
| `node_provision.rs`, `standalone_tenant_preparation.rs`, runtime/catalog/custody preparation helpers | Replace local `Resources::default` with assigned parent arena slots; every returned child acquires a destination before it can start. |
| `startup_owner.rs::TestRegistry` and cancellation/publication tests; CLI constructor/drain callers | Tests explicitly select their independent core/domain; no cfg bypass of production ownership. CLI retains a receipt outside the selected/cancelable waiter and drains that exact operation. |

A final implementation inventory must include direct `Resources::default` users in target-runtime failure/monitor paths, even where they bypass `startup_owner::open`; excluding them from this first installer slice is explicit, not evidence they already satisfy the adapter.

## Next implementable prerequisite package: retained driver ownership kernel

Implement a small server `startup_driver` module, using the integrated engine foundation, before touching the broad constructor call graph. This is a **prerequisite package**, not the production Resources adapter:

* A fixed driver state owns the prepared opening future, independent result/acquisition state, original actual `JoinHandle`, terminal fixed `DriverExit`, publication decision and joined outcome. The trusted plan specifies concrete backing types, not a caller-provided arbitrary byte estimate.
* Driver task output contains only a fixed control outcome. Typed operation errors remain in their original admitted result owner. The worker cannot carry the only resource owner. Keep an original `JoinError` on unexpected task panic/cancellation and return Retained unless its diagnostic envelope and physical state are proved; do not render it to a string or synthesize successful completion.
* An explicit receipt is created before activation. Tests cancel its ready waiter, cancel drain after one joined outcome, abandon a buffered successful result, and reject publication. All paths inspect the same original handle/result state. There is no global registry, first-error-only slot, detached reaper or compatibility `open(kind, future)` entry point.
* Initially exercise concrete fixed-size test operation/result types and an actual retained blocking/async child. Admission denial must precede builder execution and spawn. This proves the ownership mechanism without pretending arbitrary existing `anyhow`/`DrainFailure` results fit it.
* Package the actual task workspace/accounting evidence separately. Existing `BACKGROUND_WORK_SLOT_BYTES` is an estimate, not proof of Tokio's allocation layout. The kernel must not be advertised as production-memory-qualified merely because those ownership tests pass. A poll-in-place driver could avoid another spawned task allocation, but changing autonomous constructor progress requires an explicit design decision; do not silently alter current behavior.

Candidate files: new `crates/kasumi-server/src/startup_driver.rs` and focused tests, minimal server module declaration, and only narrowly required engine foundation accessors if typed receipt observation cannot be implemented with an already retained coordinator handle. No wholesale change to `StartupResource` accepting opaque errors. No production entrypoint should switch until the following blocking prerequisites are satisfied.

### Blocking prerequisites for first production installer conversion

1. Typed charged leaf diagnostics for the chosen path, including catalog initializer, journal/catalog shutdown and node close. An original leaf report must provide a bounded/charged view or carry its originating reservation; fixed parent slots retain that view. Arbitrary external error/panic payloads remain explicitly Retained. No adapter converts an opaque `DrainFailure` into a claimed bounded result.
2. Independently retained acquisition results for each async leaf constructor, not just an opening future containing local `Resources`.
3. Exact future/provider/result/task backing accounting before allocation. Include copied config and closure backing, not just headers.
4. Target-journal specific fixed plan and ordered close state, followed by direct replacement of that entrypoint and its static kind drain. Other old entrypoints remain explicitly unconverted until their own direct migration; they are not fallback implementations of the new API.

After that fixed installer passes, extend to signer installation, then runtime publication with an admitted normal serving owner. Do not begin NodeRuntime's full dynamic inventory before the fixed installer establishes the contract.

## Required regression evidence

* Exhaust operation census and resident budget: no credential wrapper/future box/child/file acquisition occurs, no slot-generation mutation on denied admission beyond the documented reservation behavior, and no partially enrolled scope becomes unreachable.
* Pause the actual child after admission, cancel the caller, verify handle/resource/charge retention, then drain and prove real completion. Pausing preflight alone is insufficient.
* Join two distinct fixed failures before a later paused child; cancel the drain; retry and observe both same originals plus the eventual third outcome. Report clones keep their diagnostics and reservations alive; completed resources do not erase failures.
* Exercise prepared-but-not-activated, active preparation, ready-but-unclaimed, failed publication and claimed phases independently. No send into a channel counts as transfer.
* Throw from activation/direct poll and panic an actual child. Preserve original payload/handle outcome, never repoll the poisoned future, never report Complete merely because the driver joined. Keep concrete physical owner custody independently testable.
* For eventual runtime handoff, drain abandoned startups while a different claimed runtime on the same core remains usable. Shutdown one facade does not seal another. Test old-scope ID reuse with generation checks and exact replacement ownership after positive close/join proof.
* For borrowed tenant enrollment, cancellation closes newly created groups/catalogs only; the existing node, admission and other tenant runtimes remain usable.
* For first target-journal conversion, verify active ownership prevents a competing open, canceled initialization/drain retains that fence, actual drain permits canonical existing reopen, and original initialization/drain failures survive repeated reports. Installed NodeDisk/ScratchDisk memory remains resident and is not mislabeled leaked operation memory.

Use actual gates/handles and original outcome identity. No timeout as completion proof, sleeps to guess admission, relaxed fixture ceilings, raw file replacement to evade owner fences, or fabricated successful checks.
