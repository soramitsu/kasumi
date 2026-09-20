# First-release integration: prepared compiler gate

Status: **UNRUN**. This is a frozen execution plan and source review, not a test
result. The full production release objective and release checklist remain open.

Frozen source is `1ff2fe2691bb3adfe74da762b3a64204c941ebfd`, tree
`10eb44a92929ad9bfd6ca764f464d628225d3ef4`, in
`/tmp/kasumi-first-release-t6-check`. The byte-exact `plan.json` SHA-256 is
`7edb1d3822cca4ea7db29a26e525119adbcbd558cb971859cfbc0e30a7e2d227`.
It preserves the 900-second workspace compiler and 300-second formatting
deadlines, Rust 1.97.1, one build job, offline locked dependencies and owned
process/source evidence. The older fb7e478 compiler plan was never executed and
is superseded. The failed 64c14aa store compilation remains a failure; adding
its missing trait import does not establish a successful successor result.

The assembled source now includes permanent encrypted ordinary mutation receipt
rows and T6 snapshots, strict original node/authority bootstrap reopening,
explicit finite-grant HA enrollment, fresh catalog preparation with synchronous
recipient handoff, continuous physical ownership during enrollment, and the
bounded retirement-seed scan. These changes have been formatted and reviewed;
their new Rust tests and combined compilation have not run.

The original store functional cohort's twenty required regressions remain
required, along with the new catalog ownership tests, permanent receipt gates,
retirement ambiguity/count tests, and native recovery continuation. A compiler
pass alone would not establish these functional claims. The seven actual Python
preparation guard passes are recorded separately under
`../redb-harness-7f47aa7-guards-20260909/`.

Later startup ownership and activated-target operational membership corrections
are being developed in separate worktrees and are excluded from this frozen
attempt. Foreign ordered-seek work in the primary checkout is preserved and is
also excluded; it must be reconciled before final-source release gates.

`management-removal-review.md` is the preserved read-only implementation map for
removing obsolete one-credential restore management operations. It also records
the target routing/maintenance dependencies that must be replaced. It is not an
implementation or successful recovery result. Persistent disk admission, other
permanent tables, full recovery cleanup, platform builds, real 3 GiB exercises,
the million-document matrix, real 24-hour HA soak and usable final release
artifacts remain required.
