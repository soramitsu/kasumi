# Journal and audit-maintenance memory binding

Status: proposed, target-only, uncompiled. Actual Rust source is frozen for root's validation. This package is a first-release direct guard change; no compatibility mode or fallback.

`guards.patch` SHA-256: `6372349411401e7550b1f9e3e314198aea8551106813f7b965db58dbdc6173b3`.

The four-file patch uses the existing `MemoryCore::require_store_memory` identity check, which requires the supplied core to own both installed persistent and scratch storage. It does not compare equivalent policies as if they were interchangeable owners.

* `TargetJournal::open_inner` checks before `owner_gate`, reservation, head read or head write. Both public create/open entry points share this boundary. Its private owner-gate helper remains the existing deterministic concurrency-test seam, not another public constructor.
* `TenantEngine::install_audit_maintenance` requires installed snapshot storage and exact memory ownership before apply locking, generation inspection or `NodeAuditMaintenance::install`. The missing-storage and mismatch errors are typed Conflict.
* Every current production caller installs storage first: ordinary restored/replicated/local bootstrap, target-serving bootstrap and target-quorum bootstrap. The three direct engine fixture call sites also do so. No caller reordering or optional guard is required.

Three new tests exercise actual MemoryCore and physical storage: missing storage rejects without a pool; foreign equal-policy core rejects both new journal head creation and uncached existing reopen; foreign equal-policy maintenance rejects while the actual same-core pool installs and reuses exactly one workspace. Journal tests confirm no head mutation and unchanged charges/physical census on rejection; maintenance confirms no installed pool, unchanged charges/physical census, and exact positive workspace delta. Resources then undergo actual explicit shutdown. The existing journal fixture retains its unchanged policy solely so the foreign core receives exactly identical configuration; no budget is raised.

Validation performed: rustfmt through stdin on proposed copies, `git apply --check`, source/type inspection. No Rust build or test execution. `manifest.json` records exact current-source and proposed hashes. `prepare.py` reproduces this target-only package from those current sources and writes only below this directory. Do not apply if the recorded baselines differ.
