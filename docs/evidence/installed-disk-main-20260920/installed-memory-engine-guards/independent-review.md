# Independent review of engine memory guards

Status: target-only design and source review; no Rust build, source application, or release qualification. Reviewed the partial guards patch with SHA-256 9ccd9cec1c2e991ea2e52c71c05e22976f66b33e0edc4021a56472410dbeaa71 and current canonical source on master.

## Actionable findings

1. The new `restore_local` guard names `stores.application()`, but its parameter is `targets`. This is a compile error. Use `targets.application()`.
2. The unchecked public `Database::new(engine, running_group, store, audit)` remains outside the guards. It can pair storage with an unrelated audit/core and a snapshot owner registered with a different facade. Making it fallible only after taking a running group does not prove cleanup of that group. This is an intentionally incomplete patch until constructor ownership is replaced.
3. The README's `initialize_replicated` statement needs correction: that function already accepts `&Database`, not raw stores. It can inherit the invariant once all Database construction is checked; it does not independently require an additional admission/context argument.
4. There are now ten direct `Database::new` call sites, plus one fixture-clock construction call, rather than nine. The added `database_worker_outcome_tests` fixture must migrate too.

The proposed `MemoryCore::require_store_memory` comparison is otherwise appropriate: coercing a clone of the exact core Arc does not create an adapter or new governor. It compares both the persistent and scratch owner. `TenantStorageSet::install` already requires application and custody catalogs to share the exact NodeStore. The inserted SecurityAudit checks precede default archive creation and writer/head work; bootstrap checks precede the relevant durable publication or child dispatch.

## Recommended canonical constructor boundary

Remove the public API that accepts an already-running RaftGroup. Keep public bootstrap/open/restore entry points as the supported construction boundary. Use one private checked construction value that owns the exact TenantStorageSet and SecurityAudit before bootstrap persistence or child creation. It derives its facade only from that audit and validates both physical owners immediately. A distinct facade on the same core can be valid for a later runtime, but the live audit, snapshot startup owner, maintenance owner and new database must all use the one facade selected for this construction.

After bootstrap/authentication work prepares the engine, a private prepared value also owns that exact engine and the selected clock pair. Its local/replicated start methods create the SnapshotBufferOwner from the retained facade, then call RaftGroup with their own exact stores and engine. A private finishing function consumes those same parts and the successful group and cannot be called by external embeddings. Do not accept a substitutable store, audit, snapshot owner or backend at this final step. No public unchecked alias or post-start fallback remains.

Move every fallible fixture clock check before Raft startup: purpose/exact store checks and `clock.now_ms()` currently also occur in `new_fixture_with_epoch_clock` after the group has started. Preserve the same checks and original errors in preparation. The direct fixture callers can use the private prepared start boundary; the integration admission test can use the canonical fixture bootstrap and retrieve its exact group through `database.raft_group()` for the committed-work bypass assertion. Preserve each fixture's maintenance enablement, clocks, original workload, and payload cap.

This context enforces memory identity; it is not yet the bounded startup custody adapter. The existing retained Raft startup owner must still own startup cancellation and failure. Database monitor allocation/worker admission, arbitrary diagnostics, post-start archive installation/target checks, and detached target Drop cleanup remain separate unresolved lifetime work. Do not claim that an identity check or a completed outer task proves those resources drained.

## Caller inventory

- `bootstrap.rs`: prepare_replicated_restore, open_replicated_inner, start_prepared production and fixture-default arms; fixture-clock arm calls its separate constructor.
- `bootstrap_target_quorum.rs`: open_target_replica.
- `bootstrap_target_serving.rs`: open_serving_target.
- `audit_maintenance_service.rs`: two lifecycle/maintenance fixtures.
- `database_worker_outcome_tests.rs`: actual worker outcome fixture.
- `tests/admission.rs`: reserved-capacity denial with committed Raft bypass.

## Required validation for the implementation

Use two actual cores with identical policies: reject a foreign audit/store pairing before archive root/head/bootstrap keys, snapshot startup registration, or worker creation changes. Assert the original disk health and each core's charges are unchanged. Test both physical owners, not only one. A fresh facade on the same core should be accepted only with the audit opened on that facade and the prior runtime positively drained. Preserve original error identity on startup failure and repeated drain. Keep the admission test's real committed-work bypass and all existing worker/cancellation regressions. The private constructor must no longer let a caller supply an independently created snapshot owner or running group.
