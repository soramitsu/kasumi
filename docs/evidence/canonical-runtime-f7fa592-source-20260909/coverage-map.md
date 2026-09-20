# Canonical runtime recovery fixture — frozen source review

Commit: f7fa592d7e2237acf403956b5bbb65eb945996eb
Tree: d47af1a463fd4c6d48285f0236d3c5aaac4f4466
Worktree: /tmp/kasumi-canonical-runtime-fixture
Branch: codex/canonical-runtime-fixture

Parent chain: 0ef62e0 (target immutable/operational fix), b1a9b11 (cherry-pick of 524d752 canonical management core), 3b07704 (6995711 compilation corrections), 03acfce (8f081a0 provisioning borrows).

Only f7fa592 needs cherry-picking onto a matching root integration. Human author/committer: 武宮誠 <t@soramitsu.co.jp>; Assisted-by: Codex.

## Actual verification

Rustfmt 1.97.1 was run while editing, then `rustfmt +1.97.1 --edition 2024 --check` passed on all three final modified Rust files. `git diff --check` passed; final worktree clean and source/tree unchanged. No Cargo, Rust compiler, native processes, container commands, integration tests, or runtime checks were executed. No release gate is claimed passed.

The new helper intentionally calls the cold-initialization patch's fresh-only `TenantStorageSet::initialize_catalogs` API. That sibling patch is a compile prerequisite not present in this frozen branch. The compiler remains authoritative for further integration issues.

## Coverage mapping

| Previous assertion | Canonical source replacement |
| --- | --- |
| Source real pinned TLS replication and durable document mutation | Original assertions retained. Canonical non-spare case additionally enrolls source in a separate three-voter issuer and uses actual renewable issuer-issued serving capability, installed durable signer verifiers, and bound source JWT. |
| Separate Control group | Original replicated Control group retained and configured with an actual immutable lifecycle root. Native lifecycle/recovery adapters read and sign this group's real quorum observations. |
| PrepareRestore from actual encrypted filesystem backup | Original Backup + checkpoint verification retained. Three separately encrypted TargetRecoveryRuntime journals and independent target/source keys are explicitly initialized; typed Control RecoveryStart dispatches actual materialization to pinned native target endpoints. |
| A single prepared replica cannot initialize | Advance one durable coordinator step at a time; exactly one retained materialization must still have phase Materialize and no initialization; any initialization requires all three materialization receipts. |
| Isolated target leader completion fails without changing pending_restore | Obtain only currently owned target replica handles, verify target readiness, capture exact pending_restore on all three, isolate every target Raft route to its own ID, and require an actual ensure_linearizable quorum error. Drop borrowed Arcs before phase transitions. Advance native coordinator until a target dispatch fails, assert exact unresolved phase ID/outcome and Complete phase, compare every currently owned replica's pending_restore exactly, restore peers and verify the same immutable pending phase record remains. |
| Old prepared-target Status leader hint | Prepared targets are no longer a management selection. Replace with quorum-ready target metrics for injection and authenticated canonical Control status/read_phase preserving exact prepared operation and outcome. Fresh ordinary Status is tested after activation. |
| Planned source retirement and durable retirement on every source | Canonical installed source-application and source-custody native clients use distinct JWT files/resource kinds. Coordinator persists retirement and issuer fencing receipts. Existing per-source durable ControlLog retired checks retained. |
| Source response release fence | New regression prepares and executes source Status once before recovery; retains its exact original response fence across source retirement/fencing, target activation and route publication; original fence must reject afterward. |
| Target activation and route publication | Coordinator must finish with retirement, source fence, activation, route publication and every target confirmation. Original registry replacement wait retained. There are exactly three target configurations/voters; no manufactured fourth activation. |
| Resume/read restored document; source isolation | Original target resume/read retained with target-bound JWT context; original source JWT must fail against old source and every activated registry. Fresh target-bound Management Status resolves actual target on every node and pending_restore is null. |
| Restart follows durable replacement and does not resurrect source | Explicitly stop target listeners and drain all actual target owners, stop original daemons, reopen original source/Control configurations and exact target journals/configs/files under fresh issuer boots. Original source token stays rejected. Each target's exact committed TargetExecutionState/activation fact must remain unchanged after restart. |
| Peer trust approval and staged beta/mismatched onboarding | Original Control peer-pool CAS/authorization, provisioning, mismatched replica/bootstrap rejection, no partial two-voter group, and unrelated target document isolation assertions retained. See production prerequisite below. |
| Spare-node source/Control maintenance | Entire separate four-node catch-up/replacement branch retained. Only required management test API calls changed to execute_for_test. This branch is not turned into a target fourth-voter fixture. |
| Initial bootstrap mismatch/peer traffic rejection | Both original Control-policy and tenant-limit mismatch branches retained. |

## Exact remaining prerequisites and limitations

1. **Production dormant tenant enrollment remains missing.** In the core runtime, adding fresh configured beta/mismatched tenants on restart acquires access and unconditionally opens existing storage before Management PrepareTenant has an explicit enrollment opportunity. New source files must be initialized by an authorized production enrollment path, then opened strictly. The fixture preserves these assertions and is expected to fail there until that path is implemented; it neither ignores the test nor recreates missing catalogs. This also affects analogous earlier local runtime onboarding, which root owns.
2. **Fresh pair API patch required.** The new helper's sole fresh issuer-pair creation uses `initialize_catalogs`; strict existing target/restart opening stays in the production target owner. Integrate cold_initialization's API patch before compilation.
3. **No runtime result exists.** Transport scheduling, phase sequencing, fixture budgets/deadlines, ownership drains, and all behavioral assertions require the final combined compiler/tests. Source review does not establish that they pass.
4. **This is a planned-recovery fixture.** It does not replace source-unavailable recovery, crash/cancellation at every durable phase, physical permanent cleanup/deletion, full voter replacement on a restored target, signer/certificate rotation, 3 GiB capacity, or endurance gates.
5. **Explicit separate target owner installation.** The helper opens real TargetRecoveryRuntime objects after observing the current source/Control leaders and freezes their actual endpoints/configuration. They own independent files and share only the installed node registry/cluster/audit/verifier. On restart, it explicitly reopens the same target installations; it does not prove automatic daemon-owned target config startup. The production owner implementation is used; only the outer fixture orchestrates installation/lifetime.
6. **Issuer signing fixture boundary.** The issuer is a real three-voter encrypted Raft service with TLS Raft/native transport and real receipts. Its operational signer uses the existing immutable FixtureAuthority signing owner; data/target verifier stores are durable. This does not claim production authority executable enrollment or signer rotation validation.
7. **No intentional source/Control leader-loss during recovery.** Their endpoints are selected from real quorum-ready leaders before freezing dispatch configuration. The target group loses quorum intentionally; broader safe-endpoint leader-change behavior remains a separate release gate.

## Final file hashes (SHA-256)

- Cargo.lock unchanged: e5f0f6216f6fea4e1a2055a06095ae20463e9c87b33ab3976b2a9d4527f6c578
- crates/kasumi-server/src/runtime.rs: b8a58ff73dddb3b786bbace728b1c0362b9e4bfe98b35942581a30b01967e000
- crates/kasumi-server/src/runtime_recovery_tests.rs: 39f52c7c59c6b40cf2abf69dccb90111090c2d5405031630a33694057e47133d
- crates/kasumi-server/src/target_runtime.rs: d7ea4252ead96bc74ad98b3437edec2de85ba28fe8e266487b4a7520751cb232

Primary test: runtime::lifecycle_tests::three_runtime_nodes_replicate_with_control_quorum_over_audited_pinned_mtls. Shared helper updates also affect runtime_catches_up_spare_and_replaces_three_voters_through_admin_control and the two initial bootstrap mismatch tests.
