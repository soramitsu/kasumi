# Prepared actual-startup census integration

Prepared only, unapplied and uncompiled. All six files are based on the installed A–E stack including the two root Clippy initializer fixes. Actual source was not edited. The manifest records precise input and proposed hashes; Rust parsing/formatting through stdin and `git apply --check` passed.

The existing Raft-local `LocalStartupGate` is moved into a module present only for `cfg(test)` or the explicit `test-utils` feature. The hook stays at the same local-initialization boundary, after actual OpenRaft creation and router registration. Its observer stays behind `dyn Any + Send + Sync` to avoid recursive SnapshotData Send proof. The existing Raft regression uses the extracted control and retains its original typed error/assertions. Nothing in runtime configuration selects the hook.

The new engine unit test obtains the actual SnapshotBufferOwner from NodeAdmission, starts a real RaftGroup::local on fixture storage, cancels construction after gate entry, and cancels a confirmed-pending node census. It asserts that the node stays sealed and retains exactly the owner charge and bookkeeping envelope while the claim/router remain live. After the gate returns its original typed error, the resumed census must establish Complete, retain the same issue through repeated drains, release the actual owner charge, retain the completed report envelope until facade destruction, and permit an actual group to reopen the same storage through a fresh facade sharing the same core. No DrainReport is manually seeded.

Run after application using the root's normal deadline, source freeze and process-group evidence:

- `cargo test --locked -p kasumi-engine --all-features --lib admission::startup_integration_tests::cancelled_local_startup_and_node_census_keep_actual_group_and_charges_until_join -- --exact --test-threads=1`
- `cargo test --locked -p kasumi-raft --all-features --lib startup_owner_tests::cancelled_local_initialization_drains_real_group_and_breaks_router_cycle -- --exact --test-threads=1`
- `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`

The typed Retained path remains open: the current actual-group gate produces an ordinary initializer error, which is Complete after its real children join. An actual direct poll panic intentionally preserves a poisoned future indefinitely; this patch does not introduce permanently leaked real groups merely to obtain a Retained test. A future test must drive an unresolved production custody path that can later be meaningfully drained, without promoting a seeded report into evidence.

The concurrent read-only MemoryCore review found no additional actionable defect in fixed-ledger admission/reuse, charge-kind transitions, exact-core handoff, startup-inventory serialization, failure-report charging, or final sampler join ownership. This is bounded review evidence, not a complete release or platform qualification.
