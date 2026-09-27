# Initial membership inspection

This first-release contract separates the original initial-membership execution
from a later read-only inspection. It does not qualify G09, authorize live
rollout, or provide an earlier-state decoder.

## Original execution

Every voter consumes its own accepted Start marker and owns its actual Raft
child. The designated voter consumes a separate Initialize marker while keeping
that original child. Its journal permanently associates the Initialize marker
with the original Start prebind and custody owner. Each request retains its
original absolute dispatch cap. Existing status APIs require the continuously
owned original child and never reopen it from journal bytes.

Control freezes the exact Initialize attempt and all three positive original
Start references when it commits the first Initialize effect marker. The new
required fields are `initialization_attempt` and `initialization_starts`.
Snapshots reject an omitted field, an incomplete frozen set, an extra Initialize
marker, or a head that hides or replaces the original marker.

## Fresh inspection

After that Initialize dispatch expires without a resolved reply, Control may
commit `InspectInitialMembership`. The input binds the original lifecycle
intent, exact three signed materializations, all three original Start records,
and the separate original Initialize record, including attempt identities and
deadlines. Original Start resolution must precede Initialize preparation; the
inspection intent must follow the original Initialize effect marker.

A current Control Admin request, installed Control signing root, installed issuer
and finite phase lease authorize the inspection. The receiver obtains fresh
installed-Control reads of the fresh inspection intent and all four original
phase records. The fresh intent commits the complete historical-input digest;
its historical original intent must match the immutable accepted journal bytes.
The original ObserveIntent API continues to reject expired authorization.
Each voter checks its accepted Start bytes and local prebind before opening a
new child under the inspection phase. The new child has no original Start
owner. Ordinary tenant serving and new application, lifecycle or membership
proposals remain forbidden. Existing consensus replay and elections remain
necessary for observing the persisted quorum.

After all three inspection children open, the designated Initialize voter
executes `InspectInitialAssociation`. Its installed target signer attests the
exact accepted Initialize-to-Start journal association, custody binding and
original committed/applied first membership fact under the fresh inspection
intent. This local attestation makes no leadership claim and grants no
execution permit. Control retains the exact positive phase in the required
`initialization_association` head; only a later independently accepted inspection
intent clears that head. Historical association records remain verifiable.

`InspectInitialMembership` then carries that signed association to an installed
started voter. A positive result requires that voter to be the actual current
leader. It verifies the original node's signature and same inspection intent,
performs a fresh linearizable barrier over the exact installed voters and
endpoints, and corroborates the same first fact against its own authenticated
original Start and local history. Its installed signer signs the status including
the exact original association. Current phase, storage, Control originals, quorum
term and immutable first fact are checked again through response release.

An unresolved read can route to another installed started voter with the same
request bytes, command identity and absolute cap, even after the read's effect
marker. It cannot change the association or renew the original Initialize cap.
Missing records, changed history or insufficient current quorum remain
unresolved. Snapshot validation checks the association head, causal revision,
exact current inspection intent and identical packet across routed reads.

The coordinator retains the positive typed status and resolves the original
Initialize with `InitialMembershipObserved { inspection_phase }`. It does not
manufacture an `Initialized` execution reply or repeat BeginEffect/Execute for
the original Initialize. The new observation is usable as established membership
evidence for the subsequent Complete phase.

## Scope still open

The original designated custodian must remain reachable to retrieve a fresh
association. Its permanent loss before that attestation remains an availability
limitation. A portable snapshot or replacement-child ownership cannot substitute
for the original local association.

An actual shutdown/reopen fixture is distinct from operating-system process
crash qualification. The nine-process HA topology, phase-boundary crash matrix,
immutable release qualification remain separate acceptance gates. The current
other-leader native development fixture must pass before this source design is
counted as executed evidence; retained earlier designated-leader results describe
their own source checkpoints.
