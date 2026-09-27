# G09 initial membership inspection development checkpoint, 2026-09-27

This is changing-source local development evidence, **not an immutable release
cohort or G09 qualification**. It uses the existing main checkout and warm
default Cargo target on native macOS ARM64 with Rust
`1.97.1 (8bab26f4f 2026-07-14)`. The base commit is
`aa2343538c571d54d204ef479a3b0000ad5ff49f`; the source changes are initially dirty.
The earlier [initial membership checkpoint](../g09-initial-membership-development-20260927/README.md)
and its hashes remain historical evidence, without being relabeled for this source.

## Verified current-source commands

Commands run from the repository root against the scoped source recorded in
`source.sha256`, using the locked dependency graph and warm target. The table
records terminal zero-exit results, without counting overlapping earlier attempts.

| Command | Result | Log |
| --- | --- | --- |
| `cargo test --locked -p kasumi-server --lib three_runtime_nodes_inspect_expired_initialize_after_owned_target_restart -- --nocapture` | 1/1, 453.44 s | [native full restart/expiry recovery](native-restart-to-finished-final.log) |
| `cargo test --locked -p kasumi-engine --lib initial_membership_inspection_tests` | 6/6, 1.38 s | [inspection reducers](reducer-final.log) |
| `cargo test --locked -p kasumi-engine --lib target_journal::open_tests` | 18/18, 4.39 s | [journal regressions](target-journal-final.log) |
| `cargo test --locked -p kasumi-server --lib three_runtime_nodes_resolve_lost_start_and_initialize_over_protected_tls` | 1/1, 81.91 s | [original continuous-owner lost replies](lost-start-initialize-final.log) |

**26 distinct cases across four commands pass.** Scoped formatting and
`git diff --check` also pass. The final two server cases ran the same development
test executable hash; the reducer and journal cases likewise share their final
engine executable hash.

The full native run passed the restart/expiry boundary at 203.96 seconds and
reached durable Finished at 414.58 seconds. All original nodes were signaled together; their sequential join waits took
139.34 ms, 7.42 ms and 3.20 ms. Original facade Weak references disappeared.
The test completed its ordinary serving reopen and retained activation-fact
checks. This run showed completed owner drain without a retained-owner leak.
It does not establish the cause of every earlier timeout or wholly graceful TLS
shutdown under all conditions.

## Contract and boundary

The new required first-release Control fields freeze the exact original
Initialize attempt and all three positive Start records at Initialize's
`BeginEffect`. No second marked Initialize can be admitted. The new explicit
`InspectInitialMembership` phase has a fresh installed Control intent and issuer
authority, and commits a digest of the complete original accepted history.
The original execution caps, accepted inputs and markers remain unchanged.

The target freshly authenticates the inspection intent and reads all four exact
original phase records through installed Control. `ObserveIntent` still rejects
expired original authorization. Accepted historical bytes do not recreate that
authorization, a one-use execution permit, or the original Start child owner.
Each target authenticates its local prebind before opening a new read-only
inspection child. A positive observation requires the original designated voter
to be the actual leader of the reopened exact quorum, a fresh linearizable
barrier, and its exact accepted Initialize-to-Start association plus the original
committed/applied first-membership fact. The installed signer uses a distinct
status domain and rechecks current authority/history through response release.

Control retains the typed signed inspection result and resolves original
Initialize through an exact `InitialMembershipObserved { inspection_phase }`
cause link. It does not synthesize an `Initialized` reply. An expired inspection
may be followed only by a freshly authorized read-only inspection of the same
original cause; it cannot reopen original execution permission. Full contract:
[initial membership inspection](../../target-initial-membership-inspection.md).

## Native acceptance scope

The new native test uses actual installed Control, issuer and target services,
pinned mutual TLS, encrypted materialization, journals and owned Raft children.
It discards an actual successful Initialize reply, shuts down the target services
and their child owners, asserts every old Weak database owner is gone, and
reopens new target runtimes on the same journals and endpoints. Reopening alone
creates no child, and the original status API cannot claim continuity of the
original owner. The test waits for the original absolute cap using real time.

The fresh phase opens three new read-only children. The test may elect the
original designated observer in the existing quorum to exercise the interim
leader restriction. It verifies the exact old first fact, prebinds, Start/Initialize
markers and cause link; replacement children have no original Start owner and
cannot propose new membership or application mutations. The old journal remains
`AcceptedOnly`; positive recovery comes from the new typed inspection.

The extended fixture then continues through full recovery, Control member
failover, target quorum partition/heal, source retirement/fencing, activation and
confirmations, replacement-route publication, restored-document reads and source
context rejection. Its final checks require actual owner drain, restart from the
original operator configurations, retained activation facts and ordinary serving.
The original full fixture permits at most one completed abandoned-target-call
diagnostic with the exact `backup verification deadline expired` message. It
forbids retained owners; a pass is not a claim of zero drain diagnostics.

## Retained earlier attempts

These attempts are separate evidence and are not counted as final-source passes.
All native entries use the same test filter,
`three_runtime_nodes_inspect_expired_initialize_after_owned_target_restart`.
The test evolved from a restart-to-Complete boundary into full recovery/reopen.

| Attempt | Observed result | Retained log |
| --- | --- | --- |
| First five Control reducer cases | 5/5, 1.36 s, before the sixth expired-inspection case | [reducer-first-five.log](reducer-first-five.log) |
| Original native inspection implementation | 0/1, 309.46 s; correctly rejected expired original `ObserveIntent` | [native-original-expiry-rejected.log](native-original-expiry-rejected.log) |
| Corrected current-authority restart-to-Complete case | 1/1, 178.70 s; stopped at Complete | [native-restart-to-complete.log](native-restart-to-complete.log) |
| Extended full recovery, original fixture drain wait | 0/1, 454.27 s; reached Finished at 437.43 s, then timed out joining original node owners at 15 s | [native-finished-drain-timeout.log](native-finished-drain-timeout.log) |
| First rerun with derived drain wait | 0/1, 183.49 s; a five-second Control phase read timed out before initial inspection | [native-control-read-timeout.log](native-control-read-timeout.log) |
| Full continuation with bounded Control reads | 0/1, 307.17 s; restart/expiry inspection passed at 307.04 s, then an assertion reread sealed source serving state | [native-source-generation-sealed.log](native-source-generation-sealed.log) |

The first failure was repaired by authenticating the fresh inspection intent and
its exact committed historical-input digest. Original `ObserveIntent` expiry
checks were retained. The drain failure exposed a fixture wait shorter than the
two sequential configured listener budgets: connections and HTTP/2 streams each
have ten seconds. The fixture now derives 35 seconds from those two budgets plus
15 seconds for actual Raft/storage/audit owner cleanup. Production drain,
authorization and dispatch deadlines are unchanged. The test still requires all
joins to succeed and all original facade owners to disappear. Per-node timings
identify whether the owners actually finish inside that bound.

The listener policy may cancel remaining task IDs after a drain timeout and then
actually join them. Successful runtime joins prove every retained connection and
stream inventory is joined before physical owners are released; they do not
prove wholly graceful TLS shutdown. An independent read-only source review found
no actionable issue in the fresh authority/cause-link or retained drain path.

The later Control-read failure is retained. Its fixture phase observations now
use the same 20-second installed-pool read budget as existing status observations;
the surrounding 180-second stage bound and original execution caps are unchanged.
This permits the installed pool's bounded leader retries for immutable reads,
without retrying ambiguous effects.

The next run passed the complete restart/expiry boundary, then exposed an old
fixture assertion that reread the source engine generation after its independent
serving authority sealed. Its retained source status call succeeded. The fixture
now compares that status with the exact immutable source incarnation already
captured before backup. Source authority remains sealed; no lease or credential
was renewed to make the assertion pass.

## Remaining qualification

The fixture performs actual controlled shutdown/reopen, not an operating-system
process kill. It does not cover every pending-phase crash point. A current leader
other than the original designated Initialize voter remains an explicit
availability limitation; it yields unresolved status. The target contract still
needs independently authenticated original-association resolution under legitimate
leader failover. The nine-process HA topology, full crash matrix, exact deletion,
segmented native KV release, frozen combined source cohort, live BPNG deployment
and physical-device acceptance remain separate gates. G09 remains open.

Historical `*.binary.sha256` files record the actual development test executable
at each attempt; the warm target may later overwrite that path. They are not
immutable, signed release artifacts or substitute release pins.

## Integrity

`source.sha256` is a scoped development source inventory relative to the repository
root, including the current inspection changes and the unchanged authority/drain
boundaries reviewed here. It is not a complete immutable source release manifest.
`source-state.txt` records the observed base commit, toolchain and paths.
`logs.sha256` covers every retained raw log relative to this evidence directory.
`evidence.sha256` additionally covers the README and evidence metadata. All three
manifests were checked after the final runs. Cargo.lock SHA-256 is
`0e3d0606a21b7471003c0bc10101363392225095d486d5084e89c2d559954c17`.
