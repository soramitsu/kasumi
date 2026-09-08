# Distributed Control recovery coordinator

The replicated Control coordinator freezes an operation's source, checkpoint,
source storage purpose digest, target incarnation, three physical target voters,
materialization placement, installed issuer partition, and dispatch configuration
digest. Generic document writes cannot modify its records. Operation heads and
individual phase entries are bounded typed records in canonical Control
snapshots; historical application backups reject these Control records.

The current executable slice prepares the replacement at the independent issuer,
commits a Control materialization intent, and dispatches existing native target
materialization on each installed voter. All three signed facts must agree on the
same original bootstrap before the journal advances to `initialize`. It then
commits separate initialization and completion intents, starts every voter under
each exact current intent, initializes only through the designated voter, and
requires a signed current-quorum completion proof. Historical startup replies
from an earlier phase cannot satisfy a new phase. A completion retry can use
another installed voter with the same original command and absolute deadline;
the unresolved prior attempt remains retained.

**Source retirement/fencing, activation confirmation, and route publication are
not yet dispatched by this coordinator.** `resume` returns an explicit
unavailable error at these phases. This slice is not a complete disaster recovery
workflow or a release acceptance result.

A pre-activation `stop` permanently retains the stop identity, obtains the issuer's
permanent target stop, commits a separate local cleanup intent, and requests
cleanup from each target. `stopped` requires exact signed evidence from all three
voters, including the complete installed issuer drain and physical verifier set.
Target incarnation identities remain bound after cleanup and cannot be reused by
another operation or configuration alias. A committed activation must proceed
forward; the later activation slice must preserve this invariant.

## Installed dispatch

`control.lifecycle.recovery` is an explicit nullable setting. A configured value
contains `routes`, a bounded map of names to `RecoveryRoute`. Each route installs:

- The exact tenant, source incarnation, and authenticated source storage purpose
  digest.
- A serving authority alias, approved member endpoints and endpoint-specific
  trust, and a separate issuer administrator credential file.
- Three `RecoveryMember` entries containing the physical `LifecycleNode`, target
  replication placement, and pinned mTLS `AdminClientConfig` with the Control
  resource credential file.
- An explicit optional source client configuration for planned retirement.

The complete route and issuer configuration have a canonical digest. Request
bodies cannot provide arbitrary dispatch URLs. Credentials are read from private
files per invocation. Issuer administration, target Control administration, and
planned source access use independently installed credential sources.

## Native API and CLI

The `KasumiRecoveryControl` gRPC service and Rust `KasumiRecoveryClient` expose
`start`, `status`, `resume`, `stop`, and `read_phase`. Every call requires actual
mTLS and a current administrator credential bound to this exact Control
incarnation. There is no RPC for arbitrary phase preparation or fabricated
outcome insertion. Status and phase replies retain the original credential and
policy/quorum release fences through serialization.

```sh
kasumid control-recovery configuration-digest /private/node.json city
kasumid control-recovery start /private/control-profile.json /private/start.json /private/start-attempt.json
kasumid control-recovery status /private/control-profile.json OPERATION_UUID
kasumid control-recovery resume /private/control-profile.json OPERATION_UUID 2
kasumid control-recovery phase /private/control-profile.json OPERATION_UUID PHASE_UUID
kasumid control-recovery stop /private/control-profile.json OPERATION_UUID /private/stop-attempt.json
```

The start request contains an explicit operation UUID. The CLI durably writes the
exact start request or generated stop command identity before network dispatch.
An existing attempt must match the endpoint, trust, credential family/resource,
and original inputs. Repeating the same start or stop resolves its retained
identity. `resume` performs at most 16 journal or dispatch steps per call.
Inspect `last_phase` and `pending_phase`, then follow `previous_phase` references
for bounded historical reads.

## Deadlines, interruption, and remaining gaps

The journal commits phase inputs before remote effects. Receipt lookup resolves
an ambiguous original issuer command; Control phase resolution reads the exact
actual replicated commitment. A failure cannot manufacture a completion.
Prepared phases retain their original credential expiry and work deadline.
Native target requests carry an immutable absolute dispatch cap. Narrowing a
Control invocation retains its original elapsed clock anchor and revocation
checks; refreshing a credential cannot extend an existing invocation.

An expired target materialization is admitted through a fresh committed
`resume_materialize` phase bound to the exact original `TargetOrigin`. Its old
phase entry remains unresolved history, and the original intent's expiry and
bootstrap bytes do not change. Expired cleanup work likewise needs a fresh
`stop_local` admission. Initialization can also receive a fresh committed admission after its original
work cap expires; its bootstrap and exact voter set remain unchanged. Completion
keeps its original permanent Control intent. After that intent expires, fresh
inspection evidence must resolve the original completion and be accepted by the
issuer; that path remains incomplete. Other unresolved remote phase kinds
currently require explicit original outcome resolution, and automatic recovery
after their original admission expires remains an implementation gap.

The native integration test uses real mTLS with separate replicated Control and
issuer groups and an intentionally unavailable target endpoint. It verifies
issuer preparation, Control phase commitment, durable unresolved dispatch, and
stop preparation. The replicated journal tests verify restart and three-voter
signed materialization/cleanup facts, current-phase startup, designated
initialization, and completion using explicit cryptographic fixtures.
Actual encrypted target execution has separate target-runner tests. These checks
do not substitute for the planned final multi-process recovery acceptance run.
