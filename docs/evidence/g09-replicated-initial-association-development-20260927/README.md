# G09 quorum-retained original initialization cause — development lane

This lane is local source and fixture work. It is not a qualified release,
operating-system process-crash acceptance, nine-process HA acceptance, or live
BPNG deployment. The prior original-custodian-dependent source remains preserved
in `../g09-initial-inspection-leader-development-20260927/`.

## Contract under verification

An original one-use Initialize execution signs its accepted designated Start and
separate Initialize identities plus exact first-membership fact. A bounded closed
Raft metadata command commits this cause; a positive execution/history response
requires local atomic application. Mandatory association state and anchor rows,
explicit snapshot fields, immutable apply positions and signature checks reject
missing, downgraded and substituted metadata. Original first membership before
association commitment remains **UnknownOutcome**, with no journal reconstruction,
retry, or reinitialization path.

The interim original-node association RPC and Control head are removed. Fresh
inspection can use two available members of the unchanged installed quorum,
read the committed cause on its elected leader, and resolve the exact original
attempt while preserving original caps and markers. The native fixture keeps
node1's actual listener/runtime down through this positive read, then restores
node1 separately to continue full recovery.

A concrete snapshot cursor gap was found and corrected during this lane:
consensus metadata advanced Raft's cursor without advancing the logical snapshot
revision. The explicit backend `apply_metadata` contract advances the cursor for
blank/membership/initialization metadata without application effects. Tenant and
authority backends implement it; byte-only test backends explicitly have no
logical cursor. Snapshot/purge/reopen checks are required before final recording.

## Retained checkpoints and completed checks so far

- `source-before.json` / `source-before.tar.gz`: pre-cutover source bytes;
  HEAD `065e5719a693313275a7a6ccf31c4b58db9ee826` when captured.
- External HEAD advanced during this work to
  `6e15fb50921fcd6a7504536ddb5423fa2b1019fd`. This agent did not commit.
  Source bytes and observed HEAD are tracked separately; no new HEAD is qualified.
- `cutover-check.log`: production `cargo check --locked -p kasumi-server`
  passed in 41.26 seconds before the subsequent snapshot cursor correction.
- `engine-inspection-second.log`: focused reducer **9/9** passed in 1.73 seconds.
- `native-lost-replies-first.log`: actual native lost Start + Initialize responses
  **1/1** passed in **67.92 seconds**, before storage-negative/snapshot extensions.
  Its executable hash is in `native-lost-replies-first.binary.sha256`.
- `raft-snapshot-first.log`: first-membership snapshot install/reopen/substitution
  **1/1** passed in 0.16 seconds with explicit Pending state.
- `source-metadata-candidate.json` / `.tar.gz`: 563-file source candidate captured
  before the last authority backend implementation and client root check.

Failures and intermediate checks are deliberately retained: the first producer
compile exposed private helper visibility, the first reducer run passed 8/9 with
an obsolete error-wording expectation (the invalid snapshot was still rejected),
and the first metadata backend compile identified the authority implementation
that also needed the required method. These are development diagnostics, never
qualification passes.

## Current candidate results

The current candidate has **563 captured source/manifests** in
`source-current-candidate.json` / `.tar.gz`. Before native execution and after
its full result, all 563 bytesets matched. The source observation remains separate
from the checkout's externally changed HEAD.

| Check | Result | Log |
|---|---:|---|
| Focused recovery reducer | 9/9, 1.57 s | `engine-inspection-metadata.log` |
| Target journal, including Pending without a cause | 18/18, 4.36 s | `journal-current.log` |
| Required explicit snapshot association field | 1/1 | `raft-explicit-snapshot-state.log` |
| First-membership snapshot install/reopen/substitution | 1/1 | `raft-snapshot-current.log` |
| Node1 unavailable through expired-cause inspection, then Finished/drain/reopen | 1/1, 480.22 s | `native-node1-down-first.log` |
| Same-executable lost Start/Initialize, storage corruption and snapshot/purge | 1/1, 80.83 s | `native-lost-replies-current.log` |
| Default production server check | passed, 38.12 s | `production-current-check.log` |
| Scoped formatting and diff whitespace | 42 Rust files, passed | `scoped-format-current.json`, `diff-current.log` |

Native node1-down milestones: all original owners are actually shut down; old
Weak references disappear; only targets 2/3 reopen before fresh inspection; actual
TCP connection to node1 fails. The original absolute deadline really expires and
original ObserveIntent remains unavailable. Node2 observes the exact retained
signed cause and actual commit position under a current quorum, with node1 still
down, at **178.45 s**. Both original Start/Initialize identities, markers and caps
stay unchanged. New children lack original execution ownership and cannot propose
application/lifecycle/membership mutations. Node1 reopens only after this read.
Recovery reaches **Finished at 434.41 s**; original owners join at 437.62 s in
**84.783 ms /3.583 µs /1.125 µs**. Ordinary serving reopen completes in the same
passing run, total 480.22 s. The test uses the normal worker stack.

The same-current-executable lost Start/Initialize, storage-negative and actual
snapshot/purge regression **passes 1/1 in 80.83 s**. This gives **31 distinct cases
across six focused test commands**, plus the default production check and scoped
format/diff gates. The earlier extended case passed 1/1 in 75.25 s on its recorded
prior candidate.
Five actual metadata corruption negatives and missing/downgraded/uncovered
snapshot causes were rejected. All three target snapshots retained the exact
signed cause after its original Raft log headers were purged.

## Remaining qualification limits

This is controlled target runtime/child shutdown and reopen, not an OS process
crash or physical-host failure. Control and issuer services remain independently
available. The unchanged target quorum runs with two members only through the
inspection boundary; node1 returns for later recovery phases. The first-membership
before association commitment window remains UnknownOutcome and needs a separate
atomic first-entry design if release qualification requires it. Phase-boundary
OS crash coverage, nine-process HA, exact deletion, immutable release pins and
the frozen release cohort are not established by this lane. **G09 remains open.**

## Evidence integrity

`native-node1-down-first.binary.sha256` and
`native-lost-replies-current.binary.sha256` identify the same unchanged executable.
`source-before-current-native.verification.json`,
`source-after-node1-down.verification.json` and
`source-after-final-regression.verification.json` retain all 563 matches and the
separate observed HEAD. `evidence.sha256` seals every file in this directory other
than itself. Prior checkpoint archives, first-run failures and intermediate logs
are retained; no commit, release pin, allocation or production authority is created.
