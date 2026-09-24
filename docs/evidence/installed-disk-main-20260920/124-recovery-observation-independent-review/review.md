# Independent current-leader fixture review

Result: no actionable blocker found in the frozen one-file patch. Static review only; no Cargo, native probe, test execution, or actual source mutation.

The run124 failure records node 1 as a healthy Follower in term 3 with current_leader 3 at the original unresolved-phase read. The proposal captures the same owner RequestContext before selecting one current leader through the existing bounded helper, then performs the same single recovery_phase(context, operation_id, unresolved_phase_id) read and exact outcome-is-none assertion. It adds no read retry, success substitution, changed request identity, new authorization after waiting, or deadline extension. Leader selection still requires a linearizable barrier; a subsequent leadership change can still fail the read.

Fixture.nodes strongly retains all original Database instances and Fixture.physical retains the original physical resources. The newly selected Arc is an existing cluster member and is carried into the existing CompletionFixture continuation. No database, audit facade, memory core, scratch owner, store, or signed fact is reconstructed. The original local Arc merely remains a duplicate reference until normal scope exit.

The common preparation path serves planned retirement, both uncertain activation outcomes, and expired completion. The diff leaves the exact peer-retry command/deadline equality, phase IDs, completion predecessor/quorum, signatures, planned source retirement checks, expiry-window construction, and later expired-fact resolution assertions unchanged. Capturing authorization before the leader wait preserves rather than refreshes its finite expiry. The separate bootstrap election failure remains unresolved by this patch.

Reviewed source: recovery_control.rs preparation/continuation and prepare_next, lifecycle.rs Fixture fields, leader(), and context_for(). Evidence: 124-lifecycle-handoff.log. Public production behavior is unchanged because this is integration fixture code only. Runtime success is not claimed.
