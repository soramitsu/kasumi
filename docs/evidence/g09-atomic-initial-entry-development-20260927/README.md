# Atomic original initialization entry — development, in progress

This lane advances G09 after the sealed replicated-cause checkpoint. It is not
an immutable release or completed G09/OS-process qualification.

The pre-edit archive captures 992 source/manifest files including the vendored
OpenRaft implementation. `historical-checkpoint.json` records the previous
sealed evidence manifest without modifying it. The current native candidate
captures 993 files including the new typed entry adapter. HEAD observations are
separate from those actual source bytes; no Git commit was made by this agent.

## Current implementation

The actual original Initialize owner signs its accepted cause before submitting
one membership entry. The typed entry carries that cause through replication;
its first-membership fact, exact cause and cursor are written atomically on
apply. The separate metadata command and Pending target state are retired.
Original ownership, two distinct accepted markers and original caps remain
required. Inspection has no Initialize or write path. The new vendored initializer
retains the existing engine's pristine state and local voter checks.

## Results retained so far

- Production `cargo check --locked -p kasumi-server`: passed (`check-03.log`).
- Inspection reducers: 9/9 in 1.51s (`engine-first.log`).
- Updated journal suite: 19/19 in 3.14s, including missing/invalid/substituted
  original cause rejected before append (`journal-atomic-negatives.log`).
- Snapshot installation/reopen/substitution: 1/1 in 0.14s.
- Explicit entry format plus removed command rejection: 1/1 in 0.02s.
- Explicit snapshot association field: 1/1 in 0.02s.
- Protected TLS lost Start and Initialize replies: 1/1 in 72.47s; includes actual
  storage corruption rejection and snapshots/purge on all three targets.
- Same-executable expired Initialize/node1 unavailable case: **1/1 in 473.72s**.
  Positive original-cause inspection with node1 down was reached at 193.514s,
  Finished at 420.457s, original owner joins at 428.121s (81.483ms, 1.841ms, 1.792µs),
  and ordinary serving reopen passed. This remains controlled owner shutdown.
- Exact current reducers rerun from the final engine executable: **9/9 in 1.56s**.
- Production current server check: passed in 27.46s. Current Raft all-target
  compilation passed in 11.23s; scoped formatting of 23 files and diff checks passed.
- OpenRaft current production-feature library: **219/219**; API/lifecycle/
  membership **13+23+41=77/77**. Earlier focused 2+3 cases overlap these cohorts.
  The first API filter ran 0 cases and is retained as a non-evidence attempt.

The initial two production compile attempts failed on new import placement/trait
imports and are preserved. The 18-case intermediate journal run is historical;
the added preappend negative makes the later cohort 19 cases.

## Source identity and evidence limits

All 993 captured source/manifest files matched after the complete native run.
The server executable was unchanged across both native cases:
`2d89db332d84f155fc91e22e01bbe9a3ee71a49f0b4af96cfea2b93e2273b7eb`.
`source-after-full-native.json` records the check against observed HEAD
`6e15fb50921fcd6a7504536ddb5423fa2b1019fd`. A subsequent formatter changed only
cfg(test) assertion layout in two files; the exact delta and formatted files are
retained separately. It was not relabeled as the original candidate's bytes.
The native source archive is the authority for the executed candidate.

The final distinct scoped cases total 33 Kasumi cases plus 296 upstream cases;
those cases do not constitute all workspace, fault, platform or release gates.
The fixture-generated upstream trace was moved out of the vendor source tree and
retained compressed. The old dependency inventory remains historical and the
README now states that explicitly. No predecessor decoder or migration was added.

## Remaining

Actual OS-process crash/restart is separate from the controlled owner shutdown
used by the existing fixture. The existing fixture shares one physical root and
in-memory runtime handles and cannot honestly stand in for nine independent
processes. A separate-root process runner is being constructed independently.
The new OpenRaft source input requires dependency-review/inventory and upstream
qualification; its old custody checkpoint is historical. No clean/frozen cohort,
phase-matrix acceptance, exact deletion or deployment result is asserted.
