# Prepared strict startup and continuation gates

All three plans in this directory are **unrun**. They bind frozen source and
original per-command deadlines; they are preparation, not acceptance evidence.
Shared host ownership must be explicitly returned after the already-running
foreign cohorts drain before any of these plans starts.

- `7dc2f27`: canonical node envelope, strict UUID/custody checks, explicit
  initialization, resize serialization and read bounds. Store all-target check,
  complete library tests with16 exact required regressions, then strict store
  lint. This supersedes the unrun `3fbefa5` plan after two source-review defects
  were corrected. The intentionally ignored crash helper runs only as an owned
  child of its actual tests. Broader workspace callers are outside this plan.
- `19c3746`: merged main evidence and the native issuer fixture private-directory
  correction. All crate/manifests/lock sources match `d37e33e`. Rerun the failed
  native issuer test and then four previously unrun native Control/lineage/lease/
  strict-workspace gates. Earlier failed results remain failed.
- `fb7e478`: first combined all-target/all-feature compile and format check of
  strict node, standalone, target journal, audit-head and caller changes. This
  includes source-review fixes and test adapters but does not claim functionality.
  Cold HA/authority enrollment, composite-open cancellation ownership and
  permanent ordinary receipt storage are still separate work.

The source worktrees and their plans remain immutable during execution. These
plans use the existing source-bound runner and process-custody helper, one build
job and one test thread. Every eventual result must retain original logs,
executables, source/lock hashes and exact owned-process drain. Failed gates stop
their cohort; preparation does not authorize reporting skipped gates as passed.
