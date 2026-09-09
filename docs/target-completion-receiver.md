# Target completion receiver implementation record

This staged implementation starts from validation source `e17a5eb`, reconciles
the prepared terminal publication source `e18bdd9`, and carries the reviewed
exact completion protocol from `c8c5edb`. It is not release validation.

The target owns a distinct encrypted point and ordinal table. A bounded resident
head selects its immutable prefix; bytes persisted ahead of the applied position
remain invisible and can be reused only by exact original replay. Target facts
bind the installed physical origin, Control incarnation, original attempt, actual
applying command and position. Canonical snapshot record kind 22 carries these
rows; verified replacement tables and checkpoint catalog writes publish with the
same application/custody snapshot and applied cursor transaction as staged
terminal kind 21.

`max_target_resolution_bytes` charges both permanent row/index bytes, keys and
framing. It is independent of the application snapshot envelope. Snapshot spools
admit their checked combined size on the installed scratch owner; indexed backup
verification subtracts the exact target stream span when checking the application
quota. This accounting does not provide persistent node disk admission.

The receiver increment supplies executable PrepareComplete, ResolveComplete and
typed budget maintenance source through the target consensus envelope, owned
native work, runtime routing and SDK verification. Complete first commits its
capacity reservation under the same original phase and dispatch cap. Preparation
and terminal observations are signed only through an actual current target quorum
proof, with retained original request, storage and signing fences. Exact positive
outcome reads remain available without another hot audit append. Resolve may seal
only the exact expired attempt; a committed completion returns its positive fact.
Already activated targets admit only their exact dedicated maintenance phase and
retain the independently committed activation winner.

The current head records the initial table budget and last budget operation;
snapshots validate every historical completion predecessor and budget
compare-and-set with bounded encrypted per-origin cursors. Both target terminal
storage and canonical snapshot formats replace the preceding development format
directly (`KASUMI_TARGET_V2`, `KASUMIT4`). No preceding decoder is retained.

A distinct `InspectCompletionAttempt` phase recovers a positive original
preparation after a lost reply, including after the original credential and
dispatch cap expire. Its input binds the original intent, quorum input and
unchanged dispatch cap; its signed observation includes the exact original
applying position. The phase requires a later current Control revision and its
own finite authorization. A selected active attempt or selected terminal point
can supply the original fact; unpublished physical rows remain invisible.
Absence returns `UnknownOutcome`. This phase cannot propose consensus mutations,
create an original preparation observation, authorize a successor, or change the
activation winner. Current quorum, original request, storage and signing fences
remain held through response encoding and release.

Six source prefix/accounting tests accompany the existing eight pure transition
tests and three positive-status protocol/signature tests. The prefix visibility
test also covers status lookup before and after logical publication. The Control
coordinator freezes an explicit Prepare request and retains its signed result or
a later positive status in a phase record. Only that persisted evidence supplies
the exact Resolve input. Typed references preserve the original Prepare/Complete
request and deadline while recording their positive observation or committed-or-
sealed terminal outcome. A Committed terminal must match the subsequent positive
activation inspection; a Sealed outcome remains visible and cannot advance to
activation. Three pure coordinator phase fixtures cover lost Prepare replies,
causal ordering/substitution, and sealed outcome isolation; the existing replicated
recovery fixture now includes explicit Prepare and positive terminal phases.
All of these added/changed tests remain unexecuted in this source checkpoint.

No automatic Control successor is enabled. If the first Resolve itself expires
with an unknown outcome, this coordinator keeps that phase unavailable. A distinct
fresh terminal-only observation must recover a positive exact retained original
resolver fact before this outage boundary is usable; absence cannot authorize a
new resolver identity or deadline. Namespace reclamation, physical
disk ownership and capacity, receiver/status native crash tests, and the linked
Control successor remain open. Public full-snapshot restore still charges three
times the complete logical stream for resident admission; separating permanent
point-row spans from that admission estimate is also required before claiming
sustainable unlimited terminal-history recovery.

Only direct Rust 1.97.1 rustfmt and whitespace checks have been run for this
source. Compilation and all functional tests require the scheduled frozen
validation cohort; earlier prepared-prefix check evidence is not evidence for
this combined source.
