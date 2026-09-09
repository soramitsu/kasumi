# Shutdown owner drain checkpoint

Base: `099b2247ebc95970164c2ddad4da0e74301a523e`. This checkpoint is source-only.
Direct Rust 1.97.1 rustfmt and `git diff --check` have run. No Cargo check, tests,
native listeners, or production build have run for this source. Functional
results must be recorded against its eventual source/tree/lockfile and actual
executable hashes. The original Linux database-lock failure remains unresolved
until the frozen combined functional cohort passes; source analysis does not
prove these were its only remaining owners.

The tenant audit worker, target serving monitor, outer target runtime, and
generation owners now remain reachable across cancelled shutdown waits.
Target replica close borrows the retained owner until Database shutdown has
finished and releases its phase registration before scope drain. Partially
opened target stores and the independent target journal drain their own key
workers before their owners can disappear.

Serving and target-phase renewals have explicit close/wake/join operations.
Each task is also registered against the exact live signer verifier object,
so failed setup cannot hide a renewal that holds encrypted verifier storage.
Task creation and handle installation occur under the same local lock that
closes registration. Close callbacks run outside that lock, and cancelled
drains retain the original handles. Weak registration entries are pruned on
registration and drain. This changes process ownership only; it supplies no
new signing authority, protocol evidence, deadline, or storage decoder.

The following deterministic tests are added, each with a 15-second failure
watchdog. The watchdog does not change a production operation's deadline.

| Package | Exact test filter |
| --- | --- |
| kasumi-engine | `service::audit_maintenance_service::tests::tenant_audit_worker_keeps_its_owner_through_cancelled_shutdown` |
| kasumi-serving | `live_trust::background_tests::task_installation_is_atomic_with_close_and_cancelled_drain_retains_ownership` |
| kasumi-server | `target_runtime::shutdown_tests::target_monitor_and_outer_owner_survive_cancelled_shutdown_until_journal_reopens` |
| kasumi-server | `signer_runtime::tests::renewal_shutdown_keeps_its_handle_through_cancelled_join_and_verifier_reopen` |
| kasumi-server | `signer_runtime::tests::verifier_shutdown_joins_renewal_after_setup_owner_is_dropped` |

The actual workers pause after acquiring strong ownership and before their
next admission check. Cancellation/retry must remain pending until the pause
is released. The encrypted tests then require immediate file reopening with
no timing sleep or lock retry. The verifier registration test also checks that
the task-installation factory runs under the close lock and cannot run after
close. Renewal ownership tests retain the existing 1,000 ms lease cap and use
the existing test clock to isolate ownership from unrelated host scheduling.

Required combined follow-up gates include the full engine `security_audit`
filter, engine shutdown integration test, authority target materialization
tests (the borrowed-close API callers), and the original real TLS fixture:
`runtime::lifecycle_tests::three_runtime_nodes_replicate_with_control_quorum_over_audited_pinned_mtls`.
Run the five exact tests above with `--locked -j 1 -- --exact --test-threads=2`,
then the relevant broader gates, strict Clippy, formatting and fixture-free
production checks when the shared validation lane is explicitly returned.

A separate read-only peer review found no actionable production cancellation
defect in the registration, retained handle, or phase-registration ordering.
Its request for bounded deterministic-test watchdogs was incorporated. This
review is not a substitute for compilation or functional evidence.

The first combined functional run at frozen `711b32d` passed the verifier
registration group and engine security-audit group, then failed the new tenant
worker fixture before its shutdown assertions: its empty initial policy was
rejected with `InvalidArgument: tenant needs an administrator`. The raw failed
run remains preserved at `/tmp/kasumi-receipt-worker-711b32d`. The fixture now
installs an explicit tenant-wide `owner` grant with Read and Admin, matching the
valid policy used by the adjacent archival fixture. No production policy rule,
shutdown assertion, deadline, or resource limit changed. The other four new
shutdown fixtures do not construct a tenant policy. This correction has only
direct formatting and diff checks; its functional rerun is still required.
