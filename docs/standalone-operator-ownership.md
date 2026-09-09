# Standalone operator ownership

This first-release change replaces the internal raw operator tuple with one
`OperatorState`. It retains the installation lock, claimed node, security store,
audit writer, credentials, opened application/custody stores and databases through
the complete operation. Local recovery uses the same owner. No compatibility
operator function remains.

The public initialization, administrator recovery, wrapping-key rotation,
signing-key rotation, certificate rotation and operator-key backup functions use
the existing `LocalOperator` registry. Caller cancellation abandons the reply, not
the accepted operation. `standalone::drain_operations` is the single local operator
drain entry point; callers stop admission before invoking it. The registry's
acknowledged handoff receives only results whose resource work already drained.

Acquisition records the installation lock immediately, and records each node
before the first asynchronous catalog open. Failed acquisition drains the same
pending resources before releasing its lock. Returned pairs enter the retained
scope before archive validation or engine open. Operational generation nodes enter
that scope before resolving the next tenant. Control remains one database within
the operator operation, including repeated local recovery publication attempts.

Initialization retains resources from its first installation lock. Its immutable
preparation marker precedes node creation. All failure exits drain pending work;
configuration and the completion marker publish only after the resource drain.
An interrupted or failed initialization leaves its own incomplete directory and
never adopts another directory. Resource fields drop before the installation lock.

The new tests use real private installation files, file keyrings, encrypted
catalogs and exclusive NodeStore opens. They are source-only and **UNRUN**:

- `every_standalone_operator_retains_real_installation_through_cancelled_reply_and_drain`
  covers all five administrator/key operations, cancels the reply and first drain,
  rejects both installation-lock and node-file reopen while paused, then joins and
  reopens the same encrypted catalogs.
- `cancelled_initialization_remains_joinable_before_its_first_catalog_publication`
  pauses after physical node creation, cancels the caller and first drain, and
  checks final installation publication plus immediate physical reopen.
- `singleton_open_failure_drains_node_before_releasing_operator_lock` supplies a
  distinct valid keyring that cannot decrypt the existing catalog. A checkpoint
  verifies the failure reached physical node acquisition rather than validation.
- `early_control_pair_error_retains_and_drains_both_catalogs` injects a failure
  after the pair handoff and verifies immediate physical and Control reopen.
- `early_initialization_audit_error_drains_without_publishing_completion` fails
  after the real security audit writer starts; no completion artifact is permitted,
  and the exact prepared node must be reopenable.

The existing failed-profile-publication and local recovery cancellation/reopen
regressions remain. Test pause registries key the exact path and acquisition phase;
no production listener or fixture storage capability is added. Pause controllers
release on test failure, and tests that cancel the shared registry drain serialize
with the existing local recovery drain regression.

The fresh security singleton uses `TenantStore::initialize_catalog`, requiring the
separate explicit-singleton lifecycle patch during integration. This branch does
not retain `TenantStore::open` as a fallback. Rust 1.97.1 direct rustfmt and diff
whitespace checks are the only validation performed here. Cargo, Clippy, runtime,
TLS, platform and process-crash gates remain unrun.

## Remaining drain work

This patch preserves exact owners across ordinary early errors and caller/drain
cancellation. It does not fix lower-level failure reporting: TenantStore and
SecurityAudit shutdown still discard worker join errors; Database can flatten
blocking-worker panic into normal completion; LiveTrustBackgroundWork erases its
join result; OpenRaft 0.9.25 hides core failure and removes its ticker join handle
before awaiting it. The existing `Resources::close` has those unit-returning leaf
dependencies. The separately reviewed canonical typed drain outcome work must
distinguish a fully joined failure from an incomplete drain before changing the
startup retry loop. No full terminal-failure propagation, process-crash cleanup,
or final production acceptance is claimed by this source patch.
