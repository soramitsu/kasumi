# Fixed startup scope foundation — prepared, unapplied, uncompiled

This package implements the approved mechanical foundation only. It does not
migrate NodeRuntime, startup_owner, serving_owner, Resources, or operator callers.
It supplies no adapter for an existing DrainFailure/anyhow outcome and makes no
claim that the existing server startup paths are now bounded or qualified.

## Concrete ownership

The exact MemoryCore contains a fixed, pre-admitted strong census. The new
required `max_startup_scopes` policy defaults to 64 only when constructing a new
policy; serde omission fails and exact installed policy comparison includes it.
The core's bookkeeping formula charges the census backing before allocation.

`prepare_startup_scope` reserves a generation-tagged census slot, then admits the
scope Arc, fixed resource/terminal-observation array and proxy-waker owner before
allocation. Reservation/allocation denial returns that unused slot. No child or
physical work is started by scope creation. The core strongly retains every
published scope; public Arc/future cancellation cannot erase it. An intentionally
retained scope/reservation/core cycle is retired only after the closed scope's
actual resource census reports Complete. Generation checks prevent repeated old
drains from removing a new scope that reused the same slot.

A typed resource adapter validates a typed plan and computes its retained backing
layout. The scope adds the actual sized resource allocation and reserves the exact
core before calling its inert builder. Only an installed resource handle permits
activation. Fixed cells retain original resource/handle/outcome state through
Pending, cancellation, Retained, direct poll panic and activation panic. Neither
an outer supervisor JoinError nor an arbitrary nested anyhow context can produce
a completion claim; no such conversion API exists.

`StartupResource` is a trusted ownership-adapter contract, not a validation of an
arbitrary implementation. Inert construction, measured captured heap/future/result
backing, bounded diagnostics, independently retained acquisition results and
positive physical cleanup are mandatory. No production adapter has been supplied
because those proofs are still missing for current owners. An opaque unexpected
panic keeps its exact payload and poisoned resource enrolled, is never repolled,
and remains Retained; its arbitrary payload is explicitly *unmeasured*, not
presented as a bounded diagnostic. No guessed diagnostic-byte allowance is used.

Reports share the original scope instead of allocating/cloning an issue Vec.
Their visitors borrow the original typed diagnostics from fixed resource cells.
Report clones keep the scope and all resource charges alive after census retirement;
final report/resource-handle Drop returns their charges. They do not expose an
uncharged independently cloned original report or an owned diagnostic wrapper.

Resources receive a pre-admitted proxy waker rather than a drain caller's task
waker. A cancelled drain clears its current caller waiter while exact child
handles retain the proxy. No core accounting/census lock is held across polling,
awaits, resource drop, or report access. Scope mutation/poll locks are synchronous
and adapters/visitors must not recursively enter the same scope. A per-scope async
drain gate serializes actual polling. There is no detached reaper, global Vec,
hidden reset or core-wide permanent startup seal.

Core lookup is bounded and nonallocating, but deliberately does not claim that a
concurrently changing whole core has drained. A later admitted shutdown traversal
must define and close its exact lifecycle set; this package does not add that
policy or fabricate an aggregate completion result.

## Test coverage proposed

The fixture adapter starts real Tokio child handles only after its owner is in a
charged cell. Its application failure is a fixed inline typed error. Its named
Tokio task bookkeeping allowance is the existing BACKGROUND_WORK_SLOT_BYTES
workspace estimate, distinct from the exactly sized fixed diagnostic. As elsewhere
in admission, this is not allocator-layout or RSS-overshoot proof.

The two new tests exercise:

- Two actual child failures with one still pending; cancel the drain after the
  first original failure is observed, drop public handles, and recover the exact
  retained scope from the core census.
- Original typed error object addresses preserved through completion/repeated
  drains; no reported Complete while an actual child is pending.
- Fresh scope creation after completed retirement; repeating an old drain cannot
  remove the successor's generation-tagged census entry.
- Report clones retaining every admitted charge after resource/caller drop, then
  exact return to the pre-scope accounting baseline after final report drop.
- Scope capacity, resource capacity and one-byte-under-budget rejection before
  the inert builder runs; existing owner/charge state remains unchanged.
- Closing prevents subsequent activation and cancellation clears the caller's
  waker reference without losing the child's retained wake path.

Existing policy tests gain startup-scope omission, overflow and exact-policy
conflict cases. No permanent intentionally leaked opaque-panic fixture is added.

## Remaining work before production wiring

Current Resources uses growable inventories and current DrainReport owns unbounded
Vec/BTreeMap/opaque payloads. Opening/result/cleanup futures and credential/config
captures also need explicit admitted plans. The same exact per-open NodeAdmission
must be prepared before first startup allocation and passed into owned constructors.
Resource acquisition adapters must register actual partial owners outside fallible
supervisor futures. Concrete adapters must establish that Complete leaves no
fallible physical cleanup to Drop and retain every diagnostic's originating charge.

Only after those adapters are proved can startup/serving registries be replaced.
The existing TargetReplica/TargetServingReplica detached Drop gap remains open.
This package does not silently bridge those paths or promise first-release readiness.

## Validation and integration

Only rustfmt stdin parsing, actual-source hash checks and git apply --check have
run. No Rust source was edited, no Cargo build/test ran, and no pass is inferred.
Before applying, stack the admission.rs edits explicitly with the separately
prepared MemoryCore/NodeDisk admission-provider layer and preserve both manifests.
After review/application, run workspace check and strict Clippy, targeted
admission::startup::tests and admission::installed::tests, then all admission unit
tests including serialized-policy and exact bookkeeping fixtures. Scope report
and panic adapter qualification remains separate from these proposed mechanics.
