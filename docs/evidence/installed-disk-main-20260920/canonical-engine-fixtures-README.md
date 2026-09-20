# Gate 52 canonical fixture diagnosis

Prepared only. No actual Rust source edits or Rust builds were performed for this package. `manifest.json` records before/proposed hashes; `fixtures.patch` passes `git apply --check`, and every proposed file was parsed/formatted through rustfmt stdin.

The original failure evidence remains in `52-engine-lib.log`: 184 passed, 13 failed, one ignored, 631.38 seconds. Root owns the terminal process-group and unchanged-source receipts. This patch addresses three fixture boundaries, not that entire failed run.

## Prepared fixes

1. `state::restore_budget_tests::restored_identity_metadata_is_validated_before_bootstrap_persistence`: the test cloned only `TenantState` after a mutation created a permanent receipt. Its corruption-capable codec emitted the nonempty receipt head without the selected receipt rows. Clone the complete `Generation` for the recoverable candidate. The original resident-state budget calculation, 20-byte margin, document payload and expected QuotaExceeded result remain unchanged; receipts retain their separate bound.
2. `state::snapshot_bundle::tests::control_archive_transfer_uses_exact_reserved_domain_without_application_authority`: `TenantEngine::new` plus `install_storage_access` never supplied an authenticated bootstrap digest. The implicit fixture-only digest path is intentionally restricted to LocalFixture purpose, while this store correctly has NodeControl purpose. All bundle fixtures now capture their canonical genesis and call `from_bootstrap` before storage installation. No Control/application authorization rule changes.
3. `state::staging::capacity_tests::permanent_staged_point_capacity_transfers_to_outcome_and_can_expand_without_identity_reuse`: `expire_active` and `replace_record` build transient terminal overlays. The test incorrectly called published-state validation before `Pending::prepare` extracts terminal rows into the permanent owner. Exercise the same prepare/persist transfer as ordered apply, validate the resulting owner and resident state, and check the unchanged terminal outcome through that owner. Preserve the original Begin quota, exact terminal-capacity denial, maximum-counter exercise, and later 3-GiB expanded limit.

## Unresolved production findings

`state::snapshot_bundle::tests::public_restore_admits_resident_state_without_charging_permanent_stream_as_ram` still requires admitted staging batching. Root's `52-engine-sample.txt` sampled the real per-row redb commits at Builder::push. The 512-row workload, 60-second deadline, 80-MiB payload budget, and byte-below-required denial remain untouched. No unchanged retry is proposed.

The two archive cases share a different production problem:

- `state::snapshot_bundle::tests::replacement_receives_complete_chain_and_restart_uses_local_dependencies` verifies that a logical snapshot without its archive dependencies is rejected, then attempts the complete transfer.
- `state::tenant_audit::tests::uncertain_publication_keeps_hot_prefix_and_apply_never_recontacts_external_archive` verifies that uncertain external publication has not published the local cache, then retries the same preparation.

Both exercise legitimate absent archive reads. `FilesystemAuditArchive::read_file` calls strict `NodeDisk::open_file`; `PreparedFile::execute` fences the owner for a non-create ENOENT, and subsequent operations return the original generic Other phase error. The earlier logical candidate validation also performs the absent read, so merely replacing assertion reads would conceal the real issue and would not repair the snapshot path.

The present ledger cannot prove that an absent path was never enrolled. `NodeDisk::State.accounted` and census `Totals.accounted` retain only `(device, inode) -> AccountedFile` extents. Closed files' root/relative paths disappear with `FileOwner`; live owners alone are insufficient. Preserve missing-known-file and ancestor/mutation fences.

A separately reviewed production fix needs charged persistent path bindings populated by census, retained through descriptor close, and atomically updated with create/publication/reclamation under the existing ownership lock. A distinct optional-open API may return None only after stable verified ancestors, a leaf ENOENT, and proof that the path has no retained binding. Any known missing binding or inconsistent identity must continue to fence. Memory sizing, namespace failure custody, hard-link/collision handling, and native regressions are part of that change. This package does not implement it.

## Focused validation after application

Run the three fully qualified tests above and the snapshot bundle Control transfer case under the normal frozen-source/process-drain gate. Broaden to the relevant engine suites only after the remaining production fixes are ready; do not label a filtered gate full qualification. The archive failures and permanent-stream timeout remain open evidence.
