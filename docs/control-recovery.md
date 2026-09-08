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

Planned recovery then resolves the original retirement through its independently
installed source connection and verifies the exact accepted receipt through the
native source verification operation. Source-unavailable recovery skips this
step and never records a planned retirement claim. Both paths commit an exact
source-incarnation and authority-epoch fence at the installed issuer before
advancing to activation. A retirement request retains its original absolute cap;
a prepared request whose cap expires can resolve an accepted outcome but cannot
be dispatched again as a new effect.

Activation commits a separate Control intent bound to the exact signed target
completion and retained source fence. The coordinator resolves or installs that
immutable intent at the issuer before submitting its original activation command.
The issuer enforces the full source drain. Once the permanent winner is retained,
every voter starts under a fresh finite activation phase naming that same winner.
The coordinator requires signed local activation evidence from every voter before
advancing to route publication; startup replies cannot satisfy confirmation.

Route publication freezes the exact current topology version and source/target
incarnations, then commits the topology compare-and-set and permanent phase outcome
in one Control Raft apply. Approved endpoints, certificate pins and failure domains
must match the frozen target voters. A stale version produces a permanent rejected
outcome; a fresh phase can use the current authorized topology. An expired pending
publication is explicitly superseded by its next finite phase in the same journal.
Replays return the original result without changing later topology, including after
restart. `finished` requires the issuer winner, every local confirmation, and this
atomic publication.

The remaining unknown-completion cases and full process acceptance gates below
still prevent treating this implementation as a completed release acceptance result.

A pre-activation `stop` permanently retains the stop identity. If an issuer
activation was dispatched, the coordinator first commits a `stop_activation`
phase naming that unchanged original command. Its signed issuer outcome resolves
the original phase atomically in the journal. An activated outcome proceeds
forward, even when stopping was requested. Only an exact permanent negative
outcome permits target cleanup. An expired activation without an observed outcome
also requires this ordered resolution; expiry alone never proves failure.

When cleanup is authorized, the coordinator obtains the issuer's permanent target
stop, commits a separate local cleanup intent, and requests cleanup from each target. `stopped` requires exact signed evidence from all three
voters, including the complete installed issuer drain and physical verifier set.
Target incarnation identities remain bound after cleanup and cannot be reused by
another operation or configuration alias. A committed activation must proceed
forward.

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
- Explicit optional application and custody source client configurations for
  planned retirement, with distinct credential files.

The complete route and issuer configuration have a canonical digest. Request
bodies cannot provide arbitrary dispatch URLs. Credentials are read from private
files per invocation. Issuer administration, target Control administration, and
planned application retirement, and retained source custody use independently
installed credential sources. An accepted retirement can be verified using
custody authority even if the former application credential is unavailable.

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
keeps its original permanent Control intent and target dispatch cap. After expiry,
a fresh `inspect_target` intent starts all three voters solely for observation.
The leader signs a positive observation of the exact original committed fact;
another voter can receive the identical finite inspection request on retry. Control
retains that distinct signature and atomically resolves the original pending Complete
by point reference to its permanent inspection outcome. Issuer activation accepts
an explicit `CommittedCompletion::Resolved` proof after checking the inspection
signature, original fact, materializations, and source drain. It does not convert
the inspection into an original completion signature or renew an old capability.

A missing original completion remains `UnknownOutcome`. No signed negative
completion outcome or fresh mutation path is installed yet; time passing alone
cannot authorize either. Other unresolved remote phase kinds require exact
original outcome resolution, and automatic recovery after their original admission
expires remains an implementation gap.

Planned start requests freeze a `retirement_id` and `source_backup_destination`.
The latter names the independently installed source destination and can differ
from the target reader's backup alias. After target completion, the coordinator
persists the exact retirement request with its finite phase deadline before
source dispatch. Target materialization therefore cannot consume a retirement
deadline that has not been admitted yet. An already prepared retirement keeps
that original cutoff on every replay; an expired uncommitted request cannot be
replaced by extending it.

The native integration test uses real mTLS with separate replicated Control and
issuer groups and an intentionally unavailable target endpoint. It verifies
issuer preparation, Control phase commitment, durable unresolved dispatch, and
stop preparation. The replicated journal tests verify restart and three-voter
signed materialization/cleanup facts, current-phase startup, designated
initialization, completion, exact source fencing, uncertain activation resolution,
three-voter local confirmation, and forward progress after restart using explicit
cryptographic fixtures. The planned-source dispatch helper is exercised by the real TLS native
backup/retirement test, including recovery using only custody authority and
rejection of the former application token. A complete coordinator-driven planned
recovery with all target processes remains an acceptance gate.
Actual encrypted target execution has separate target-runner tests. These checks
do not substitute for the planned final multi-process recovery acceptance run.
