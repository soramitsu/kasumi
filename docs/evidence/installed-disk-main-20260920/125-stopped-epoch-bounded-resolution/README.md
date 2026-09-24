# Resolve the exact stopped-epoch rejection after observed route movement

Status: target-only fixture proposal, ready for independent review. No actual source application, Cargo, test, binary execution, or debugger invocation was performed. The old conditional run109 package is preserved unchanged.

## Evidence and scope

The terminal run125 completed all six exact drain/witness observations, including the complete post-restart interval, then failed at the original final Conflict assertion. Its original proposal diagnostic records local node 1, admitted term 1, and a current healthy Raft core at term 2, Follower, with no current leader and persisted vote (2, 3). The original failure is UnknownOutcome from the leader-change check. This establishes the real role/term movement that the run109 candidate required. Run116's earlier forwarding failure did not establish this evidence and was not treated as doing so. The immutable run125 command/result and log hashes are in observed-input-hashes.json.

The new proposal changes only the final new-intent rejection portion of this one fixture. It does not change production admission, proposal handling, receipt persistence, reducer ordering, error classification, Raft settings, clocks, workload, or configured deadlines. Every byte before that portion and after it remains identical, including all six exact drain/witness checks, same-identity replay, snapshot, restart and lifetime assertions.

## Exact identity and bounded wait

Construct the same late signed request once from the original intent arguments, and capture the original verified RequestContext once. The first current-leader selection stays in the same position before the mutation. One outer five-second timeout then covers every execution and every additional leader selection. Each execution clones only those original values. It creates no fresh permanent command identity or refreshed verified authorization.

UnknownOutcome and Unavailable are never accepted as the expected result. They are eligible for same-identity resolution only when the executing node's term, leader or role changed between snapshots around the actual execution, and every fixture RaftGroup passes check_access both before and after that execution. A consistently stale route therefore fails immediately. A known failed actual store, core, state machine, group ownership or snapshot-custody owner fails at those checkpoints. Other public error codes also fail. A successful acceptance panics. Only Conflict with the exact reducer message `control epoch permanently stopped` satisfies this part of the test; an unrelated Conflict cannot pass it.

The final reducer rejection has no successful receipt of its own: lifecycle_state.rs returns the application Conflict when the committed epoch-stop identity exists. Receipt absence alone would not establish rejection. Re-executing this same signed identity allows the actual healthy leader to return that precise reducer result.

The production public API retains its ordinary per-call accepted-request deadline. This fixture does not pass or renew any replacement production deadline. The single five-second outer timeout bounds the entire caller-side resolution sequence, including the Fixture::leader helper's internally longer wait, and is no longer than the original service call's five-second accepted-request deadline. It does not bound physical lifetime of already accepted children or preempt a synchronous call. On cancellation, the existing accepted_request registry and Raft storage ownership retain dispatched work; cancellation is not rollback or evidence that no effect occurred. No task, detached reaper, special admission route, or ownership bypass is added. Successful resolution still reaches the original close/drain.

## Limits and next gate

Raft metrics and check_access are observation-time checks, not an atomic proof that route movement was the sole cause of every possible concurrent sanitized error. The public error mapper intentionally does not carry the original causal type. This fixture refuses known owner/core failures and stable-route errors; it does not change production diagnostics or clear failures. A future failure that passes these observations still needs its preserved original diagnostic to establish the cause. This proposal is justified by run125's original concrete movement and the existing permanent-identity resolution contract; it is not a claimed production consensus fix.

Static checks prove exact baseline matching, unchanged bytes outside the late-intent region, single context/intent construction and single outer timeout. Proposed formatting and git apply --check pass. No compiler or runtime result is claimed. After root review/application and coordinated source-gate ownership, run the original stopped-epoch test with all original workload and deadlines. Do not lengthen the timeout or accept unresolved uncertainty if it fails.
