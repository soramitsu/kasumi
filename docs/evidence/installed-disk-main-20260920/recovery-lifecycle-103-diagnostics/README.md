# Run103 lifecycle routing correction and original-cause diagnostics

Target-only proposal for /Users/mtakemiya/dev/kasumi master. Unapplied, uncompiled, no Cargo or test execution. All prior fixture corrections and original workloads remain. No deadline, election setting, sleep, retry, accepted error or assertion is changed.

Run103 completed with40PASS2FAIL across history5, lifecycle12PASS2FAIL, schema12 (one separately known restore failure filtered), staged11. The original receipt says exit101, no timeout/signals, process group drained and inventoried source unchanged. inputs.json binds that original log/result/source inventory; these evidence files remain untouched.

## Concrete routing defect at recovery_control.rs:1004

complete_recovery retains db selected at source line298. At983–984, prepare_next twice independently calls f.leader(), whose existing bounded selection requires local current_leader identity and a successful linearizable barrier. The immediate next unresolved-phase assertion at1004 reads through the earlier cached db. That handle can now be a follower, even though both preparations completed successfully against actual leadership. This is the same structural issue already corrected in commit_next_intent and commit_next_control_for, not evidence that those earlier changes failed.

The proposed fixture captures one original phase-read RequestContext, reselects using the unchanged Fixture::leader helper and issues exactly one recovery_phase read for the same ambiguous phase. It retains the equality assertions on node sequence and exact target request, and still requires that the permanent original phase has no outcome. The request is neither regenerated nor retried. Original db custody and all later behavior remain intact. The log's generic Unavailable is consistent with cached-follower routing but does not itself prove which Raft cause occurred; the diagnostic below supplies that distinction if it recurs.

## UnknownOutcome at recovery_control.rs:217 remains unresolved

The first explicit prepare_recovery_dispatch fails with the generic message produced by recovery_service::unknown. That function currently discards every original Display cause. The identical result can represent the existing10s proposal timeout, task JoinError, worker Raft/encode/decode failure, post-write release failure, or post-write phase observation failure. The log contains no original cause, term or leadership evidence. It is unsound to infer stale routing or accept/retry that result as success.

The proposal adds static semantic stage labels to all eight unknown adapters and prints the original Display cause before returning the identical public ErrorCode::UnknownOutcome and message. It also traces the original Raft barrier error and local RaftMetrics before returning the identical Unavailable/read quorum unavailable error. Both traces are gated by cfg(any(test,feature="test-utils")); integration tests compile the library without cfg(test), while run103/next targeted run use --all-features. Normal builds without that explicit test feature neither format nor print the diagnostics. These temporary traces can allocate; they are not a production diagnostics design or part of the measured physical no-allocation boundary.

The labels distinguish post-write uncertainty from initial operation admission. In recovery_write, the final reducer-result ? remains unchanged after the outer worker error conversion. No term, credential lifetime, authorization check, reservation, worker retention or uncertainty semantics is weakened. The initial preparation still unwraps and fails on UnknownOutcome, now with original-cause evidence.

## Review/validation boundary and next run

Read-only apply-check and proposed-only rustfmt-check are recorded in manifest.json. Three files, one fixture routing correction plus two diagnostic files. No Rust compilation or behavioral test has been performed for this package. The test feature's tracing should be removed or replaced only after the captured original cause is understood.

Root can run the two original failed lifecycle tests under the next bounded source-frozen runner with --nocapture and unchanged test settings. Cargo accepts one substring filter per invocation, so use two explicit commands if selecting by exact full name:

- recovery_control::recovery_expired_completion_resolves_its_exact_positive_fact_before_activation
- recovery_control::recovery_journal_persists_before_dispatch_rejects_substitution_and_recovers_ambiguous_control_commit

Preserve each original process result, raw output, source inventory and actual drain. A successful rerun can validate the fixture correction for that run; it cannot reconstruct the missing cause of the earlier UnknownOutcome. Persistent failures must be classified from their newly retained stage/cause, without broader retries or deadline changes.
