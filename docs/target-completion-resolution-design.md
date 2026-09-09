# Exact terminal resolution of an expired Complete

This is an implementation design and source dependency checkpoint. The negative
resolver is not installed in the native runner or Control coordinator yet.
Its transition and signature regressions have been written but have not run.

## Ordered target contract

A Complete input contains the exhaustive original materializations and an
explicit nullable predecessor. The initial attempt uses `null`. A successor
names the exact permanent sealed fact, including the physical target origin,
immutable Control incarnation, original command, first resolution command,
authoritative Control revision, and digest. There is no numeric global floor.

Before dispatching Complete, the target Raft group commits a prepared attempt
with its original Control intent, absolute dispatch cap, actual applying
position, and reserved terminal and audit capacity. Retrying the exact prepare
returns that first fact, including after Complete has committed. Preparing
another attempt while the current one is unresolved fails.

ResolveComplete requires a fresh, independently authorized Control phase bound
to that exact prepared attempt. Its ordered target transition records one of:

- `committed`: the original Complete actually won, with its original fact.
- `sealed`: the original dispatch cap elapsed and the target permanently makes
  that attempt inapplicable in the same apply stream used by Complete.

A sealed target head advances to the exact terminal reference. A later Complete
can be prepared only when its input names that reference and its Control and
target applying positions are later. An original command authorized before
expiration still fails when its apply is ordered after the seal. Absence of a
receipt never produces a sealed outcome.

Fresh resolution observations retain the first permanent fact. Reusing the
same Control revision requires the exact original intent and dispatch cap;
a different observation command requires a strictly later Control revision.
The observation uses a signature purpose distinct from completion, inspection,
and budget maintenance. Signed historical facts do not provide live admission.

## Storage and capacity contract

Permanent terminal records belong in an encrypted point-addressed immutable
prefix with exact by-identity and ordinal entries. Only the selected logical
head makes a physical row visible. The head has checked 64-bit record and byte
counts and a root digest; physical rows beyond it are not committed evidence.
The native prefix must publish together with the corresponding applying
position and bounded active head, including during snapshot install and reopen.
Snapshot rank 22 is reserved for the terminal rows.

The current target keeps only its origin, Control incarnation, latest exact seal,
and at most one active prepared attempt. It does not add a permanent resident
map. A restored incarnation retains historical prefix evidence through explicit
lineage and starts a separate current target head.

`max_target_resolution_bytes` is a required expandable 64-bit terminal-table
budget, separate from the application snapshot envelope. Generic SetLimits
cannot change it. Typed current-Control maintenance must bind the exact target,
expected budget, new budget and permanent maintenance operation identity. An
old maintenance replay returns its first outcome without reapplying it over a
later change. Increases must be able to fund their own terminal record; decreases
must preserve all selected rows and active completion reserves.

The prepared attempt is at most 64 KiB, each Control intent at most 16 KiB, and
terminal records at most 256 KiB. Preparing reserves 768 KiB for terminal/index
framing and completion evidence, plus two bounded hot audit events. Complete
consumes one event while its unresolved head retains the other for resolution.
The prefix writer must check its actual row/index/framing cost against the
retained reserve before dispatch can be acknowledged. Audit and resident
completion reservations must also be enforced against unrelated writes.

This budget does not implement node physical disk admission. Existing target
lifetime history limits are unchanged and remain an independent release gap.

## Remaining implementation and gates

The source checkpoint contains the types, pure transition reducer, canonical
Complete input migration, signature verification and regression sources. The
reducer is currently compiled only by engine unit tests. Required remaining work
is the typed durable prefix, selected publication and snapshot validation hooks,
actual reserve accounting, native PrepareComplete/ResolveComplete/maintenance
operations, and the linked fresh Control successor. No negative resolution is
advertised as available before those paths are installed and tested.

Validation must cover actual encrypted target quorum replay, snapshots, crashes
between physical row writes and selected publication, exhaustion, old commands
already authorized before the seal, exact maintenance replay, different target
UUIDs and physical verifier identities, and source/target activation invariants.
A committed global activation always continues forward. Earlier positive
inspection tests do not substitute for these negative-resolution gates.
