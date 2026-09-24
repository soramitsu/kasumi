# Checked Database construction — target only

Status: prepared, virtual application verified, Rustfmt parsed and formatted every proposed file; not compiled or tested. All actual source remains unchanged by this task.

Patch SHA-256: `05d511887c479d3ac8e94e64a39d6c81ce6b905d78d6c538bfa9e313d54849b2`.

## Stack and scope

This ten-file patch stacks after the corrected engine guards `efeca43aa014510d6b078c5562bc7271cb85683d5b0b158e8ccf295c5695ed86`, the mandatory store memory API, and the rebased MemoryCore disk provider. `manifest.json` records exact before/proposed hashes and whether each baseline is actual source or the guard layer. `validation.json` records a full `git apply --check` and application into the target-only validation tree with every resulting hash checked. No actual Rust file was formatted or applied.

The broad engine disk fixture migration is still required: old existing fixture calls in unchanged surrounding code do not yet supply mandatory memory/path arguments. This patch does not provide that migration or pretend the combined workspace currently compiles. The new focused test already uses the proposed mandatory APIs and explicit ScratchDiskConfig paths.

## Resulting construction contract

The public constructor accepting an already-running RaftGroup is removed, as is the fixture-clock constructor that could fail after receiving a running group. Public bootstrap/open/restore functions remain the supported construction APIs. No compatibility alias or unchecked public overload remains.

A private DatabaseConstruction owns the exact TenantStorageSet, SecurityAudit and prepared clocks. Its constructor compares the audit core with both actual physical owners of both the security store and application store. TenantStorageSet's existing exact-NodeStore invariant covers its custody domain. Entry points retain this checked context before bootstrap writes or target child dispatch. Existing explicit audit-facade checks remain.

The local and replicated start methods create SnapshotBufferOwner through that audit's exact facade, pass their own stores and the same engine to Raft, then finish privately and without another Result check or suspension. The finish method uses the retained stores and audit; it accepts neither a substitutable store nor an externally selected facade/snapshot owner. Fixture purpose/time checks and paired clock creation precede bootstrap persistence and Raft startup. The previous post-start purpose/pointer check becomes structural because this context starts the group using its own exact store.

All ten former Database::new calls and the one fixture-clock branch are covered. The admission integration test now uses canonical open_fixture and obtains that Database's exact group for the committed-work bypass. Its payload cap, capacity fill, denial codes and actual Raft write assertions are unchanged. Private worker fixtures keep their prepared engine and maintenance mode, but replace fake snapshot owners with the actual facade's charged owner. The maintenance fixture now checks that exactly this owner remains charged after successful shutdown while Database/group handles still exist, then drops those handles and retains the zero-payload assertion. The later disk fixture layer must add only its exact installed metadata baseline.

## Ownership limits

This is a memory-identity construction boundary, not a bounded runtime startup adapter. Cancelled Raft startup remains in the existing SnapshotBufferOwner registry with actual handles and backing resources. A caller's future can still drop its construction context and its audit/facade references; the future StartupContext must retain the full resource inventory independently. This patch does not qualify sole-owner public-bootstrap cancellation.

The existing target wrapper spawns, detached Drop cleanup, post-start target checks, restore archive installation and maintenance-audit failure handling are unchanged. No new post-start fallible branch was added, no error was reclassified, and no unretained reaper was introduced. Database monitor allocations/tasks and arbitrary diagnostics still require their separate admitted ownership work. Do not claim this patch closes those gaps.

## Validation to run after integration

- Workspace all-target/all-feature check, strict Clippy and formatting.
- New `service::construction::tests::foreign_equal_policy_core_is_rejected_before_bootstrap_or_raft_startup` test. It creates two actual isolated disk/store/audit installations with two real MemoryCores under one identical policy, rejects the cross-pair before any deployment/bootstrap/Raft identity appears, and checks stable reservations and disk health. The exact pairing remains accepted. All actual store/audit work is explicitly drained; installed metadata intentionally remains process-retained.
- Existing `fixture_epoch_clock` integration tests (purpose, credential/lease expiry and permanent receipt semantics).
- Admission integration tests, both audit maintenance worker cases and worker outcome/cancelled shutdown tests.
- Existing replicated, target, restore and startup-cancellation integration cases after their mandatory memory fixtures are migrated.

Independent peer review of the production/caller draft `6738fe59...` found no introduced visibility, move, ownership or caller-semantic defect within the stated limits. The final revision adds the focused foreign-core regression and must be reviewed/compiled separately.

Final peer review corrected the new regression to explicitly disjoint `persistent/` and sibling `scratch/` roots before any census. The superseded 6090eb40 patch is preserved byte-exact under `revisions/6090eb40`. Production and caller changes are unchanged from the independently reviewed draft.
