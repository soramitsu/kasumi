# Authority request ownership during shutdown

This source checkpoint changes authority request lifetime and internal signer
APIs directly. It contains no compatibility overload or fallback. It is not
evidence of complete authority, worker or physical storage drain: compilation,
tests and native execution have not run.

An admitted public request now owns both its existing bounded semaphore slot
and an owned read guard from the authority's request-owner lock. Acquisition is
synchronous and rechecks admission closure after acquiring the guard. The
original permit moves into detached ordinary, lifecycle and maintenance jobs,
then into their returned response fences. It is never reacquired while moving
between these phases. The native adapter retains the fence through encoding and
response release as before; the fence now also retains the drain owner and
capacity until it is actually dropped.

Shutdown closes request admission, waits for exclusive ownership of the request
lock, and only then takes the proposal lock and shuts down Raft. It cannot pass
an admitted job that has not yet reached the proposal mutex. Cancelling a
shutdown waiter leaves the closed admission state and original read owners
intact. Another shutdown waits for those same owners; it neither reopens
admission nor reconstructs requests. Admission and fence/barrier checks reject
the closed authority, including already-issued fences that still hold a guard.
Keeping a failed or expired fence alive continues to retain its owner; an elapsed
deadline is not proof that the actual owner was dropped.

## Entry-point classification

| Entry points | Ownership |
| --- | --- |
| Discover, acquire, receipt, ordinary/lifecycle command, lifecycle receipt, control/target stop observation, lifecycle lease, authority maintenance | One native capacity permit and request read guard, transferred through any detached worker into the returned AuthorityResponseFence. |
| Authorize signer maintenance, observe Control signer | One native permit and guard retained by the administrative or Control observation fence. |
| Signing maintenance and signer coverage | Their returned fences retain the original administrative fence; no second slot. |
| Commit signer directive, read signer directive, replace operational signer | Require the already-verified administrative fence for this exact authority owner. No fresh context, deadline or slot is substituted. A committed directive retains that same fence while it remains live publication authorization; the read returns historical status under the supplied live fence. |
| Initialize installed Raft membership | A locally retained native permit/guard covers the complete initialization future. It does not bypass closed admission. |
| Pinned peer authorization, synchronous maintenance readiness, installation of maintenance/publication transport | A synchronous request read owner, without a native slot. Consensus callbacks must not be starved when all public slots are occupied. Readiness rechecks closure before its durable resource-floor effect. |
| Immutable installation/bootstrap getters and static storage initialization | No live request. Storage initialization has its separate exclusive installation ownership contract. |

`commit_signer_directive` and `signer_directive` now accept
`Arc<AuthorityAdministrativeFence>` instead of a bare RequestContext. The server
passes its existing authenticated fence. Both verify the exact authority owner;
the directive keeps the original context and current-authorization fence, which
also retain the original credential invocation and term. Tests that start a
separate invocation explicitly acquire its administrative fence first.

Existing ordinary and lifecycle accepted-write release failures still become
UnknownOutcome; the receipt identity and original inputs are unchanged. Moving
that mapping from a release helper's boolean argument to its accepted call site
avoids widening the private helper signature while preserving the same mapping.

## Regression sources and limits

The two new tests use the existing actual three-member encrypted authority
fixture, its Raft group, bounded native admission and real returned fences:

- `service::tests::request_drain_tests::authority_shutdown_retains_admitted_jobs_and_returned_fences_after_waiter_cancellation`
  holds an admitted permit before dispatching the real `execute_owned` method,
  retains a returned receipt fence, polls and drops the first shutdown future,
  and proves its replacement remains pending until both exact owners finish.
  New admission, initialization, peer checks and old fence release reject closure.
  The scheduling gate is manufactured inside the test; this is not process-death
  or network-cancellation evidence.
- `service::tests::request_drain_tests::original_signer_authorization_is_reused_when_all_native_slots_are_occupied`
  fills all native slots and verifies that peer checks and signer sub-operations
  using the original authorization still reach their real result. It also
  rejects substituting that fence onto another authority instance.

The signer-directive restart regression now starts shutdown, verifies retained
permissions are fenced while shutdown is pending, drops those exact permissions
and response fence, then requires shutdown completion before reopen. Existing
tests explicitly drop retained response owners after their final assertions,
including the native TLS source response whose signer is rotated. No timeout or
fencing assertion was weakened.

Rust 1.97.1 rustfmt and Git whitespace checks are source validation only. All new
tests, the complete authority suite, server authority/lifecycle TLS tests,
workspace compilation and strict Clippy remain UNRUN. This patch still relies
on the separate Raft/storage owner drains; OpenRaft 0.9.25's suppressed terminal
core result and lower-level audit/store/signer JoinError reporting remain open.
The serving-loop owner must still stop ingress, drain listeners, invoke shutdown
and retain the runtime if its drain is cancelled or fails.
