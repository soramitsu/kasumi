# Authority target corrections after run 91

Status: target-only candidate, not applied or built. All reads/writes took place in
`/Users/mtakemiya/dev/kasumi`, checked on `master` at
`600c0ca2b2c4c22b89b44ccd932eca02272c70f1`. The base files include the root's pending
installed-memory stack; the manifest binds the exact current bytes. No source
outside `target` was edited and no Cargo build/test was run by this agent.

## Findings

The original `91-authority-memory-callers.log` has three target-materialization
close failures at `target_materialization_tests.rs:801`. Each is a typed
`DrainFailure` with `Complete`, one `OpenRaft runtime[0]` issue, an original
state-machine Storage error and no other runtime child failure. Two report a
Store/Write failure after the durable transaction committed but the access fence
closed before acknowledgement. The third reports the exact sealed/expired lease
Store/Write failure. The test helper incorrectly required clean `Ok(())` for all
immediate-fence drains.

`TargetReplica::close` closes the shared lifecycle gate before awaiting
`Database::shutdown`. The gate controls both new requests and storage access;
closing it must remain immediate. Moving gate closure after drain would leave
`TargetOperationScope` / operation clones with authority during shutdown, even
if Database independently stopped its own admission. `TargetOperationScope::close`
and natural original expiry can also close that gate. The expired-inspection test
explicitly advances its captured clock beyond the lease deadline before its last
close. A complete drain with an original access-fenced error is therefore a
permitted unclean terminal outcome; it must not be converted to success in
production. This candidate leaves the production shutdown order and all retained
errors unchanged.

The fourth failure is the 20-second `assert_operational` timeout. Vendored
OpenRaft `add_learner` uses `ChangeMembers::AddNodes`; Membership::change preserves
existing node metadata for AddNodes. The fixture calls add_learner for an existing
voter with a new address, then waits for an update that this API explicitly does
not perform. The candidate uses `ChangeMembers::SetNodes` for that same voter.
This in-process fixture retains the same physical owners and tests operational
metadata, not TLS address authorization or replacement-node admission. The
original learner, voter set, suspension/restart behavior and 20-second deadlines
remain intact.

## Candidate behavior and boundaries

The close fixture accepts only two cases: clean success repeated as success, or
an unclean complete drain repeated with the same original DrainIssue Arc. The
latter must contain precisely one original typed OpenRaft issue; no core,
core-join, ticker, snapshot-builder, replication, auxiliary or incoming-snapshot
failure is accepted. Its actual state-machine child must have returned a storage
error, and the complete Store/Write diagnostic must exactly match one of the two
observed closed-access messages. The current Raft adapter converts the underlying
cause into an untyped I/O message, so only that leaf uses exact diagnostic
comparison. There is no substring matching or arbitrary `Complete` waiver.

Original failures are printed in the test output, preserving the observed unclean
outcome. The helper also asserts fenced original phase, inaccessible Raft and both
storage domains, then retains the original scope drain and asserts its operation
slot is idle. The serving target fixture uses the same exact diagnostic contract
for its deliberate expiry at the end of its workload. No health/reopen assertion,
operation, payload, fixture capacity or deadline is removed.

One adversarial classifier test is prepared: wrong verb, wrong subject, unrelated
I/O failure, and a prefixed string containing the expected phrase are all rejected.
Existing actual three-member target tests exercise real drain/restart paths.
OpenRaft is added solely to authority's dev dependencies for typed child inspection
and SetNodes; Cargo.lock adds its existing package to authority's dependency list.
No production dependency, compatibility alias, API fallback or storage migration
is introduced.

## Static checks performed

- `git apply --check target/installed-disk-validation/91-target-authority-corrections/corrections.patch`: exit 0.
- Rust 1.97.1 `rustfmt --edition 2024 --config skip_children=true --check` on both proposed Rust files: exit 0.
- Exact base/proposed file hashes and patch SHA-256 are in `manifest.json`.

## Required next validation

Apply only after root's frozen runs have drained and the base hashes still match.
Run the whole authority suite with `--nocapture` to preserve original diagnostics,
plus workspace locked check, format and strict Clippy. A new failure is evidence
to diagnose; do not expand the allowed terminal inventory speculatively. None of
these prepared changes or static checks qualifies the release.
