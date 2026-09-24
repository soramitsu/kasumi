# Independent bounded engine source fixture review

Read-only review of target `engine-fixture-callers/proposed/crates/kasumi-engine/src/snapshot_bundle.rs` (`admitted_pair` and the two public API tests) and `admission_startup_tests.rs`, while the author's proposal was not yet frozen. No source edits or builds.

No actionable ownership/accounting defect found in this scope. The admitted pair plans two actual isolated persistent/scratch installations (sixteen independent metadata leases) on one already-created facade, adding no second bookkeeping allowance. The existing 80 MiB operation allowance and canonical default total minus original bookkeeping remain the precise denial boundary after permanent metadata is excluded. Held capacity is released before retrying a healthy operation through the same core. Live scratch-file and zero-operation checks continue to test the intended denial boundary.

The startup regression drops FixtureStorage's facade Arc before checking weak-facade disappearance and the core-only baseline. It retains explicit directories and physical storage across the cancelled constructor's real join and replacement facade, and correctly expects core bookkeeping plus installed metadata to persist after runtime facade release. Original error identity and repeat-safe completion assertions remain intact. Duplicate adjacent baseline assertions in the second public snapshot test were noted as harmless cleanup, not a defect.

This receipt does not qualify compilation/runtime behavior or other paths in the author's pending engine source proposal.
