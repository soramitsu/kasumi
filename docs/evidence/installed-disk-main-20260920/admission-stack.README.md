# Verified admission patch stack

Base: `master` at `b2876ef782f0f5afde2d60edd234559fc6ce600f`. This receipt describes the unapplied stack verified before root installation; no builds or tests were run by this verifier.

Order is A → B → C → D → E. Apply each original patch once. `admission-stack.combined.patch` is an equivalent review/check artifact, not an additional layer.

| Layer | Patch | SHA256 |
| --- | --- | --- |
| A | `memory-core-foundation/foundation.patch` | `bb4062d4dc6e1e0de628253d0af750d88b05beadc31d752a14a1b5d531f8a890` |
| B | `database-admission-engine.patch` | `6ba83067ffbc4079fbc765f949a496ef689f59ecb8cfd2f4afa4444d568a22c3` |
| C | `database-admission-engine-fixtures.patch` | `86ff7adb1a5648b1c80efca62d251ff2fd8758db6c887fce8cfb3850e6ff3feb` |
| D | `database-admission-server.patch` | `c8c24ae2af2c9957d278f9e15152ac7b47e8cac1d54b245f57e7dca23fd185f9` |
| E | `server-admission-bookkeeping.patch` | `39564e7c4dbd8eb0921fe01642262232d8d345148f38d4cb98597054c6beb67d` |

All 48 file inputs and outputs match their owning manifests. All hunks were applied to strings in memory at their exact positions with no fuzz or offset; the final combined diff passed `git apply --check`. Source and index were clean before and after verification. The source manifests and patches were also unchanged while being verified.

The six overlapping paths are:

- `crates/kasumi-engine/src/audit_maintenance_service.rs`: B → C
- `crates/kasumi-engine/src/service.rs`: B → C
- `crates/kasumi-engine/tests/admission.rs`: B → C
- `crates/kasumi-engine/tests/backup_checkpoint.rs`: B → C
- `crates/kasumi-server/src/mcp_credential_tests.rs`: D → E
- `crates/kasumi-server/src/runtime.rs`: D → E

The JSON manifest records every actual, intermediate, and final file hash. Independent engine-fixture review is complete with no actionable defect.

Post-application targets, in useful diagnostic order (root selects scheduling and retains original deadlines/process-group evidence):

- Compile all direct API consumers and required configuration fields: `cargo check --locked --workspace --all-targets --all-features`.
- Run deterministic shared-core accounting, RSS, startup inventory, report, and actual sampler lifetime tests first: `cargo test --locked -p kasumi-engine --all-features --lib admission::tests:: -- --test-threads=1`.
- Run every changed engine unit fixture and constructor consumer, including worker, snapshot, lease, audit, proposal, and bootstrap modules: `cargo test --locked -p kasumi-engine --all-features --lib -- --test-threads=1`.
- Run directly changed engine integration targets: committed Raft bypass, clock binding, encoded response admission, production backup budgets, and custody identity/reopen: `cargo test --locked -p kasumi-engine --all-features --test admission --test fixture_epoch_clock --test response_release --test backup_checkpoint --test retirement -- --test-threads=1`.
- Exercise authority target materialization fixture after mandatory audit facade conversion: `cargo test --locked -p kasumi-authority --all-features --lib -- --test-threads=1`.
- Exercise server configuration omission, startup/custody, API, MCP, readiness, signer, serving-owner and runtime fixture conversions: `cargo test --locked -p kasumi-server --all-features --lib -- --test-threads=1`.
- Enforce workspace lint after all new field/API consumers compile: `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`.
- Enforce repository formatting on installed source: `cargo fmt --all -- --check`.

The early admission-filter run can be followed by the full engine library target without treating the filtered run as full engine qualification. Exact new regressions include `reserved_capacity_rejects_proposals_and_queries_but_committed_raft_work_still_applies`, `fixture_epoch_rejects_a_different_audit_facade_before_bootstrap`, and `runtime_config_requires_explicit_admission`; the foundation also retains both deterministic RSS pressure cases and adds twelve accounting/lifetime cases.

The shared-core foundation’s documented limitation remains: admission census cancellation/Retained behavior is not newly exercised here through a pending actual Raft constructor. Existing Raft lifecycle tests and this stack’s constructor integrations provide related coverage, but they must not be represented as that missing end-to-end case or as native platform/release qualification.
