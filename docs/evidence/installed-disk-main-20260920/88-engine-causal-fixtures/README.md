# Run 88 engine integration fixture corrections

Target-only proposal on `/Users/mtakemiya/dev/kasumi` `master`, based on the source after root's `96-corrections-applied.json`. No actual source edits, Cargo invocation, compilation, or tests were performed. The root's active 96–99 runners remain untouched.

`corrections.patch` contains four test-only source files. `history-lifecycle-recovery.patch` contains the original three assigned files. `schema-generation-release.patch` contains only the additional schema lifetime fix, for independent composition with the root's schema successor. Do not apply both the aggregate and component patches. `manifest.json` records exact base/proposed hashes and patch hashes. `static-checks.json` and `check-*.stdout/stderr` preserve successful apply-check, diff-size, and proposed-only rustfmt checks. The base already includes the reviewed resident-payload accounting corrections.

## 1. Missing backup dependency fences the installed owner

Observed: `88-engine-integrations.log:128–130`, `history.rs:960`, the post-rejection `target.get("engine.bootstrap", b"manifest")` returned `installed storage owner failed`.

The fixture removes an already enrolled backup session object directly through `std::fs::remove_file`, then resumes managed reads against the unchanged census. This is an actual ownership violation: `node_disk/file.rs` permits NotFound without fencing only when the exact complete name was never enrolled and its parent is still rooted. An enrolled missing leaf calls `NodeDisk::fail_locked`, which also fails its device promise owner. The subsequent target read correctly refuses storage access. This error is not a malformed-backup result that may be ignored.

`FilesystemBackupDestination::new_fixture` resolves its anchor through `NodeDisk::fixture_for_path`. That method finds the existing parent physical installation, so source, cold directory, backup directory and restore targets in this test share the same actual `physical.storage.persistent`; a new backup governor must not be invented.

The proposal establishes deliberate external corruption while the real owner is paused with zero open managed files, then recounts before managed use resumes. The helper first asserts that the owner is Open, so it cannot clear a failure produced by a previous admitted read. The same boundary brackets the deliberate removal of all source cold objects, corrupting the backup dependency, restoring its bytes, and removing it. Each negative target retains and explicitly shuts down its application/custody/audit/node owners, so subsequent offline edits cannot overlap live file custody. The original successful restore, source-independence proof, all four negative cases, encrypted custody reopen, and both absent bootstrap/Raft identity assertions remain. No production ownership code changes.

Unchanged workload: 12 rows with 900,000-byte payloads, two six-row staged chunks, real multiple-chunk archive and resident export, 300,000ms restore deadline, existing object and memory limits.

## 2. Audit count includes the initialized topology read

Observed: `88-engine-integrations.log:151–156`, `lifecycle.rs:1001`, expected 2 but actual 3.

The fixture installs genesis topology/current at version 1. It then calls `ControlPlane::require_initialized`; that calls `Database::collections`, which releases the nonempty topology collection through its strict read audit. The fixture next replays the exact genesis `LifecycleControl::Install`. Its idempotent result still emits a committed lifecycle audit in generic ordered apply. Thus two records precede BeginPolicyChange; BeginPolicyChange contributes the third.

The proposed test checks the two initialization records' exact action, collection and outcome, captures their full serialized contents and retention cursors, and then requires BeginPolicyChange to append exactly one record. It checks the unchanged prefix and pruning cursor, sequence increment, event identity, principal, original request ID, action, committed outcome, returned revision, timestamp presence and absent collection. This verifies phase contribution instead of replacing one unexplained total with another. Existing 128KiB hot audit budget, 8MiB state limit, both 60,000-byte records, 2,000-attempt capacity loop, reserved completion audit, authority transition and encrypted restart assertions remain unchanged.

## 3. Genesis topology requires version CAS

Observed: `88-engine-integrations.log:160–162` and `174–176`, recovery expired-completion and uncertain-activation-forward tests failed at `common/recovery_control.rs:1435` with a document precondition conflict.

`Fixture::configured` now installs the exact required topology document in Control genesis. `exercise_route_publication` still tried `Precondition::Absent`. The proposal requires installed state rather than calling the old provisioning helper, reads actual topology through the existing finite current-leader quorum read helper, preserves its other routes/nodes, adds the intended source route and request node descriptors, and replaces with `Precondition::Version(installed.version)`. It asserts the source tenant was absent before setup. All later stale-version, wrong-incarnation, unrelated-route preservation, restart and exact publication checks remain.

## 4. Prepared phase read used the caller's stale leader

Observed: `88-engine-integrations.log:166–172`, planned-retirement and uncertain-activation-cleanup tests failed at `common/recovery_control.rs:2060` with read quorum unavailable.

`prepare_next(f, _db, ...)` explicitly ignores the passed database. It tracks actual leadership through `f.leader()` while preparing/resolving the one original phase. Its caller `commit_next_control_for` then reads that phase through the older caller database, which may now be a follower. `commit_next_intent` contains the same defect.

Both helpers now capture one original phase-read context and select the actual current leader before their single phase read. The original prepared phase ID, frozen command, dispatch limit, requested administrative credential duration and one-shot mutation remain. No failed lifecycle command is retried, no errors are broadened/accepted, and no timeout is enlarged. The existing Fixture leader selection retains its existing 10s bound. An election after selection can still fail visibly; this correction does not claim to solve every distributed race.

## 5. Schema reopen kept its old file owner alive

Observed: `88-engine-integrations.log:231–233`, `schema_activation.rs:637`, exclusive open returned `operation would block` in `encrypted_schema_lookup_checks_current_fences_without_rewriting_original_effect`.

The test keeps `before: Arc<Generation>` alive across shutdown and reopen. `Generation.receipts` owns a durable receipt view, whose DurableRows retains `Arc<TenantStore>`, which retains the old NodeStore/database/file. `TenantStore::shutdown` documents that caller-held store/node owners must also be released before reopen; it only fences/joins its own background work. `NodeDisk` correctly rejects an exclusive second open of a live inode with WouldBlock. The test has already copied every needed snapshot field and exercised its stale-fence assertion before shutdown. Explicitly dropping `before` at that point releases the surplus owner. No sleep/retry or weakening of exclusive ownership is added.

## 6. Schema restore deadline remains unresolved

Observed: `88-engine-integrations.log:227–229`, `schema_activation.rs:814`, independent restore returned `backup verification deadline expired` with the original 60,000ms source deadline and 32 collections. No patch changes this test's deadline or its workload.

The log identifies the deadline boundary, not which verification phase consumed it. The later run88 native sample captured the separate 100,001-schema fixture, not this restore. Source diagnosis shows that restore passes the one deadline through backup session reading, historical independent snapshot validation, relocation and genesis construction. `snapshot_index` and `snapshot_validation` issue individual `EncryptedTable::insert/set` operations, each of which begins and durably commits a redb transaction (`scratch_table.rs:136–166`). This is a concrete performance cost and the same batching prerequisite already documented in `staging-batch-design/design.md`; it is not proof that it caused this particular deadline. Root's prepared run98 preserves the original failing restore and can provide a successor observation. Do not rerun the unchanged large workload repeatedly or infer a passing result from source inspection. The retained-terminal prerequisite does not make batching or its memory admission complete.

## Validation limits

All checks here are static. These proposals require root review, integration when actual source is unfrozen, and the relevant original workload tests. The current source failure semantics and all existing explicit limits/deadlines remain intact. `source-evidence.txt` preserves the relevant implementation excerpts with source hashes for review.
