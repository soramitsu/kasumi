# Independent review: stopped-epoch fixture current-leader route

Verdict: no blocking finding in this bounded fixture patch. Static review only; no Cargo, compilation, test, or actual-source edit was performed.

The immutable patch `92e8267f31bd4114698f74d2eeca31d9c79ada4850c4d2580bc55de16883a3c7` changes one test's route selection immediately before its new late-intent mutation. Run 105 reports four passed tests and one failure: `control_epoch_stop_preserves_exact_identity_replay_and_restarts_full_drain` expected Conflict but observed UnknownOutcome. The preserved cause is `authority proposal leader changed` from `service.rs:441`; it is not evidence that the stopped-epoch reducer accepted the late intent.

The fixture retains a service Arc selected immediately after reopening, then performs stop-drain checks and a receipt read before the late intent. A service Arc identifies a replica, not permanent leadership. `tests.rs:275` already provides a bounded 30-second current-leader helper, requiring both local metrics leadership and a successful linearizable barrier. The patch uses this existing helper before the new one-shot mutation. Its request context is captured before waiting, so the route selection does not reissue or refresh the authorization. No true failed mutation is retried.

Production `execute_lifecycle` still has its original five-second accepted-request deadline and `write_proposal` still retains its five-second timeout and exact leader-change behavior. The late request and original Conflict assertion remain byte-for-byte unchanged. `lifecycle_state.rs:130` still rejects a new intent whose epoch-stop receipt exists. The earlier identity, replay, lease drain, persisted stop, restart, snapshot, and accepted-revision assertions are preserved.

This removes the known stale replica reference from fixture setup; it does not guarantee an election cannot occur after the helper returns. Any such real failure remains visible. There is no broad accepted-error classifier, ignored error, operation retry, deadline extension, workload reduction, or production change. Runtime verification remains the parent's next coordinated gate.
