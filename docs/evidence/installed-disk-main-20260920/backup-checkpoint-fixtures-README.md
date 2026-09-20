# Gate 53 backup checkpoint correction

This is a target-only proposed patch against the actual canonical source after
root's installed-core/fixture resolver and namespace revision 2 applications.
No Rust source was edited, no patch was applied and no build or test was run.
The manifest records exact actual/proposed hashes, original evidence hashes,
rustfmt stdin parsing and `git apply --check`.

Gate 53 exited 101 after 425.58 seconds with an unchanged inventoried source and
a drained process group. Its admission integration target passed 2 tests, then
backup_checkpoint passed 9 and failed 3 in 401.11 seconds. Later requested
integration targets were not run. Original log and receipt remain untouched.

## Findings and correction

1. `restore_hands_off_verified_workspace_with_production_and_destination_reserves`
   measured 354,870,784 payload bytes versus an expected 354,211,328. The exact
   659,456 difference is the restored Database's proposal registry:
   `32 * 16 KiB + (4 * 32 KiB + 4096)`. `restore_local` performs the mandatory
   `maintenance_audit(..., "restore", "started", ...)` after constructing the
   Database; this goes through `submit` and `Jobs::prepare`. The original
   fixture baseline includes only the source Database's registry. The new
   `Jobs::required_bytes` helper is the same formula formerly inline in prepare;
   a test-utils-only Database query exposes that exact policy for the fixture.
   The assertion adds only this known charge after restore and explicitly
   asserts its release after successful shutdown while the group facade is
   still retained. `open_local` does not send that restore audit proposal, so
   its original snapshot-owner-only assertion is unchanged. The final exact
   return to the original baseline remains. The 512 MiB payload cap, two
   128 MiB reserves, 64 MiB + 1 rejection, workload and 60-second timeout remain.

2. `missing_corrupt_resident_or_cold_dependency_and_history_subset_never_yield_proof`
   externally removed an enrolled backup file and recreated its path with
   `std::fs::write`. A physical inode/extent mismatch correctly fails NodeDisk
   validation before backup decryption, producing Unavailable rather than the
   asserted Corruption. The old filesystem destination's `try_exists` precheck
   allowed the first absent read to bypass the owner; root is independently
   correcting that production hole. The fixture now wraps the real destination
   with one exact session/object read fault. It delegates the original bounded
   read, then returns None or flips one final ciphertext byte in the same buffer.
   All unrelated responses and source errors propagate. Each awaited fault
   phase must actually read the selected object (the observation counter is
   consumed after each phase), and exact Unavailable/Corruption codes remain.
   Final healthy verification and the historical-subset NotFound case remain.
   This models missing/corrupt remote backup data rather than bypassing strict
   local inode custody. No production fence or error mapping changes.

3. `archived_audit_backup_is_self_contained_and_source_unavailable_restore_preserves_exact_chain`
   originally reached an Other error at cache publication after a failed reopen.
   The newly missing cache leaf was absent during the fresh census, so the old
   unconditional NotFound fence prevented valid publication of that known
   authenticated dependency. Root's separately applied namespace correction
   handles this production distinction between an absent unenrolled leaf and a
   disappeared enrolled leaf. This patch leaves that entire restart sequence
   intact: shutdown/drop, raw cache deletion, fresh open, mandatory missing
   dependency rejection, canonical cache publication and successful reopen.
   Its earlier source-fault phases also removed a live enrolled file and then
   republished it. Namespace revision 2 must reject that local tampering; those
   phases now use the exact-object missing/corrupt read wrapper, followed by the
   untouched healthy source. Completed graph identity, wrong target key rejection,
   source shutdown, exact retained archive chain and portable restore checks stay.

## Verification still required

Run the three named cases against the merged source and then the whole
`kasumi-engine --all-features --test backup_checkpoint` target serially with its
original test workloads/deadlines. Run normal workspace check/strict Clippy.
This patch is uncompiled, and no pass is inferred from static analysis.
Independent filesystem read/unlink known-leaf regression tests belong to root's
separate production correction. Existing NodeDisk memory fixture migration will
need to rebase on this proposal if applied; it must preserve these exact charges.
