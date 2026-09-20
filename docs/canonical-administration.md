# Canonical management and recovery boundary

This source checkpoint removes the obsolete management restore command family,
its private generation descriptor, its derived file identity and its alternate
Serving-to-RestorePreparation opener. Recovery belongs to the independently
credentialed Control coordinator and installed target runner, or the exclusive
stopped standalone coordinator. There are no aliases or decoders for the removed
management commands, status incarnation selector, configuration limit or internal
restore-readiness route.

A native management request now prepares one invocation. It borrows the actual
registered database whose incarnation matches the committed Control route; the
reserved Control database remains separately selected by verified Control
credentials. Authorization, execution and encoded response release retain that
same database, original request context and engine response fence. Provisioning
also retains its selected configured owner through execution and release rather
than looking it up again after admission. Neither selection opens storage,
constructs a provider nor transfers shutdown ownership.

Administrative reconciliation owns only original configured generations. It
never infers a replacement directory or creates a target from a route. The target
runner exclusively opens and registers its journal-owned generation. Target
serving installs configured backup/archive aliases before publication and retains
the returned serving owner before any fallible post-open operation, so cleanup
can drain it after an alias or transport failure. Retired-source detachment
compares the exact database Arc and cannot remove a different registered target.
Protected local observation follows the actual registered incarnation.

Fresh tenant enrollment uses the closed enrollment-readiness protocol. A restored,
retired or incomplete generation cannot attest fresh enrollment readiness. The
wire response no longer carries the old restore-specific flag.

## Validation and outstanding fixture integration

Direct Rust 1.97.1 rustfmt and Git whitespace checks passed. No compiler or Rust
test has run on this checkpoint. The earlier frozen 1ff2fe2 workspace check does
not contain these changes and cannot validate them.

The wire regression rejects every removed operation as an unknown variant and
rejects an incarnation override on otherwise valid status. The existing local
runtime test retains real backup verification, key rotation and response-release
policy revocation; its obsolete restore rejection now occurs at wire decoding.
All these Rust assertions are unrun.

The replicated runtime fixture has now been converted in source (f7fa592) to
actual issuer/Control/target services and independent source application, custody,
Control, issuer and target credentials. Its assertions retain actual encrypted
backup, all-voter preparation before initialization, quorum-loss completion
refusal, source retirement, target activation/route publication, source isolation,
daemon restart and tenant/peer provisioning. An admitted source Status fence
survives through the route change and must reject release afterward. No compiler
or Rust runtime test has run on this combined source.

Configured HA tenant enrollment now has an explicit source implementation: a typed
Control proposal precedes one recorded catalog/bootstrap creation, and startup
keeps unrecorded configuration templates dormant. The existing onboarding and
mismatched-voter assertions remain. See [configured tenant enrollment](configured-tenant-enrollment.md)
for exact ownership, the required new ledger format, unrun regression sources and
remaining partial-abort/standalone gaps. [Explicit Control genesis](explicit-control-genesis.md)
now installs the reserved state and binds its original encrypted bootstrap during
HA enrollment; its validation gates remain unrun. The immutable issuer signing
fixture and explicit outer target-owner restart boundaries are still recorded in
the [coverage map and erratum](evidence/canonical-runtime-f7fa592-source-20260909/README.md).
No earlier branch pass or removed assertion replaces these open acceptance gates.

The deleted private generation path tests exercised a removed file-creation API.
Canonical node-envelope, target journal and standalone generation tests retain
their own physical identity and cleanup contracts. They do not by themselves
prove a complete coordinator-driven process recovery. Final combined functional,
strict, native recovery and resource gates remain required.
