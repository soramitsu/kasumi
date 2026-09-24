# Exact stop-drain fixture assertions and failure diagnostics

Scope: one test file, master checkout only. This strengthens the fixture's proof and captures unexpected routing/storage state. It is not a claimed fix for a production leader failure. No retry, deadline increase, election setting change, additional API request, replacement context, clock adjustment, accepted UnknownOutcome, or source fallback is introduced.

## Evidence and causal limits

Immutable run109 failed at the final late mutation: UnknownOutcome instead of required Conflict, after the original proposal path reported `authority proposal leader changed`. The old diagnostic combines term change, loss of local leadership and fatal running_state; that message alone cannot select a correct resolver or show that a mutation did not commit.

Immutable run116 failed earlier at issuer_tests.rs:284, the positive stop observation at fake clock2000. The original error is `has to forward request to: None, None`. It never reached the late mutation and emitted no proposal-route diagnostic. The same run passed the separate historical signer read. This establishes a failed cached route during stop verification; it does not prove the exact election transition, a failed storage owner, or that the stop reducer accepted a late operation.

lifecycle_service.rs verify_control_stop first requires the actual quorum barrier, loads the exact stored stop, constructs control/{request_sha256}, and requires a local elapsed witness. Its response fence runs another barrier before the second witness check. service.rs require_drain_witness discards witnesses from other terms and starts an unseen exact identity at the current elapsed time. A new serving process starts with an empty map. Consequently selecting a different leader only at clock2000 could create a new witness that must wait another full1000ms; the patch does not do that.

The four existing `is_err` checks at clocks0/999 and restarted1000/1999 could accept an unrelated route or storage failure. Such a result would fail to establish the intended witness even though the test continued. This is the concrete fixture defect addressed here. The fake clock implements LeaseClock; Raft election timers use Tokio's real elapsed time. The old final-mutation comment is corrected accordingly. Automatic elections remain enabled and all heartbeat/election settings remain unchanged.

## Proposed assertions

The synchronous inspector receives each of the same six completed API results. It returns the exact result unchanged and makes no API call. Each negative observation must be the exact Unavailable error with `exact fence drain has not completed; retry the same identity`. All six observations must have the exact witness tuple for the original serving term, start0 or restart1000, and current fake time. Positive observations must still return Ok; the original signature verification, historical receipt equality, late mutation Conflict, snapshot checks and shutdown remain.

Only an unexpected outcome/witness formats a diagnostic. It includes the original result error, selected local node, exact witness identity, clock and expected/observed tuple, and every actual member's Raft metrics plus group.check_access result. Mutex custody is released before diagnostics; each metrics watch guard is cloned and released before checking access, so the diagnostic does not hold a metrics guard across another access check. Ordinary success does not allocate a diagnostic or inspect other members.

These diagnostics can distinguish a never-established witness, a different observed term/start, a cached route loss, and a visible storage/running-state failure. A successor may still fail with the real routing error; that must remain a failure. The earlier bounded resolver proposal remains unsubstantiated and is not included.

## Static validation

Proposed file only was formatted with rustfmt. git apply --check passed against the exact copied base. Actual source was unchanged. Code outside the new inspector and named test is byte-identical. The complete original ordered context construction sites, six stop-verification calls, await sites, clock-store values and existing Duration::from_secs values are preserved. No Cargo, test, or binary execution occurred. Root owns integration and the next coordinated gate.
