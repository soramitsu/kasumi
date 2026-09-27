# Initial membership inspection

This first-release contract separates original initialization execution from a
later read-only inspection. G09 and immutable release qualification remain open.
There are no predecessor decoders, state migrations, or compatibility RPCs.

## Original execution and committed cause

Every voter consumes its own accepted Start marker and owns its actual Raft
child. The designated voter consumes a separate Initialize marker while keeping
that original child. The exact original intent, Control root, accepted designated
Start and separate Initialize records, and three signed materializations form
`TargetInitializationAssociation`. It describes the original accepted cause; it
does not claim that an effect has already happened or predict an applied hash.

Only the task holding the one-use Initialize permit and actual original child
can create the bounded signing proof. The proof rechecks original accepted
journal/custody binding, independently current original Control authority and the
absolute request cap. The installed target signer signs the cause **before** the
membership proposal. The consumed proof submits one typed first membership entry
carrying those canonical signed bytes. OpenRaft assigns its protocol first log
identity; it does not accept a caller-selected committed position.

The native entry adapter requires an explicit initialization field. Its only
permitted non-null value is a bounded, verified signed cause on the first
membership. A narrow vendored `initialize_with_entry` path retains that typed
entry through the existing pristine-log/vote, voter, task-capacity and election
checks. Invalid non-membership input is rejected. Regular membership changes,
blank entries and application commands carry no initialization cause. The former
separate initialization metadata command is removed.

Before log flush, every target verifies the cause's installed signer, Control
root, bootstrap, exact voters, and original local prebind; the designated node
also verifies its exact accepted Start identity. Missing, invalid and substituted
causes cannot append a target first entry. Actual state-machine apply writes the
immutable first-membership fact, local Start association, committed cause, anchor
and applied cursor in **one custody transaction**. Target membership without its
cause is rejected. Ordinary groups carry an explicit Ordinary state and cannot
be upgraded into target initialization history.

The actual first entry's header/hash binds membership and cause together. Fresh
inspection uses a distinct `TargetInitialMembershipPosition` for the real first
log identity, rather than an application-command position. Positive Initialize
acknowledgement and historical status require actual committed/applied coverage.
A crash after quorum persistence but before local apply leaves the original
entry available for ordinary replay. A crash after atomic apply but before
journal terminal publication leaves the same permanent first fact and cause.
Neither path reconstructs execution ownership or repeats Initialize.

Consensus-only entries advance the logical snapshot cursor without application
effects. Snapshots require explicit association state, preserve the exact first
entry and actual position, and cannot erase, downgrade, substitute or retrofit a
cause onto previously applied ordinary membership. Log purge retains the atomic
fact. Absent committed membership, insufficient current quorum, corrupt state or
an unavailable signed cause remains UnknownOutcome; fresh inspection cannot
invent a missing entry, retry the original effect or renew original authority.

Control freezes `initialization_attempt` and all three positive original
`initialization_starts` at the original Initialize BeginEffect. Snapshots reject
missing fields, an incomplete frozen set and substituted original markers.

## Fresh inspection

After the original dispatch expires unresolved, independently installed Control
and issuer authority may grant `InspectInitialMembership`. Its input digest binds
the original intent, all three signed materializations, three original Start
records and the exact separate Initialize record, including original identities
and deadlines. The original ObserveIntent API still rejects expired authority.
Historical records identify a cause; they never renew its execution authority.

A fresh read-only Start validates the node's own original accepted Start and
prebind before opening an actual replica. The coordinator may route the exact
packet and absolute cap around an unavailable node. Two successful current Starts
from the unchanged three installed voters suffice to attempt inspection. The new
children have no original Start owner and cannot propose application, lifecycle
or membership mutations. Existing replay, vote persistence and elections remain
available under independently installed authority.

`InspectInitialMembership` carries the exact historical input to an available
started member. A positive result requires that member to be the actual current
leader, a fresh linearizable barrier over the exact installed voter/endpoints,
its own original Start association and the locally retained quorum-committed
cause. The cause must match the accepted original designated Start and Initialize
identities. The current observer signs the cause, its actual commit position,
current term and applied/committed coverage with the fresh inspection identity.
All these boundaries are checked again through response release and by the
native client and coordinator, including the independently installed Control root.
No RPC to the original designated node is required.

Unresolved reads can route among current started voters with identical packet,
command identity and absolute cap. Missing cause, changed history or insufficient
quorum remains unknown. A positive typed status causally resolves the original
Initialize as `InitialMembershipObserved { inspection_phase }`. It neither
manufactures an execution reply nor repeats original BeginEffect/Execute.

## Evidence and remaining scope

The prior [other-leader checkpoint](evidence/g09-initial-inspection-leader-development-20260927/README.md)
passed Finished, owner drain and serving reopen in 479.01 seconds; that historical
source still required the designated node for a fresh association. The new
[replicated-cause development lane](evidence/g09-replicated-initial-association-development-20260927/README.md)
records the current cutover and its exact completed and pending checks separately.

Actual owner shutdown/reopen is distinct from an operating-system process crash.
The atomic-entry implementation is under focused development verification in
[evidence/g09-atomic-initial-entry-development-20260927](evidence/g09-atomic-initial-entry-development-20260927/README.md).
Actual OS-process injection/replay, the full phase-boundary crash matrix,
nine-process HA topology and frozen immutable release cohort remain acceptance
gates. Earlier evidence retains the historical separate-command crash window.
