# OpenRaft capacity and bounded-apply development review

Status: reviewed source checkpoint; **not release qualified**. This review
advances the September 27 inventory only after inspecting the exact 42 changed
files and 11 added files. All other 558 predecessor records remain unchanged.
The complete new inventory contains 611 regular files with original permissions.

The change adds preacceptance capacity ownership and typed capacity refusal,
separate append/flush completion, prepared snapshot acceptance/cancellation,
counted snapshot-constructor funding, and bounded state-machine apply batches.
The worker retains a contiguous committed range and waits for consumption of
each actual reply prefix before loading the next bounded batch. Snapshot barriers
retain preceding apply work and original preparation/body/cleanup outcomes.
Higher votes remain processable during preparation; refusal must not advance
matching, conflict, or acceptance. Unknown outcomes retain original custody.

The review covered production paths, all new source files, changed tests and
callers, and the actual memstore snapshot preparation implementation. Closed
internal controls retain their funding through final control destruction. The
new constructor test measures actual heap requests and first-decision allocation;
it does not establish whole-process RSS or platform-wide qualification.

The actual OpenRaft library suite passed 251/251 tests using Rust 1.97.1, serde
and storage-v2, locked/offline dependencies and the persistent target directory.
The saved log and 1,757 source pins are unchanged before/after that run.
Every inventoried Rust/Cargo input represented in those pins matches this
checkpoint; the complete inventory additionally covers other workspace files
and permissions. Historical test results remain scoped to their earlier source.

`reviewed-delta.json` records only the 42 reviewed replacements and 11 additions.
`reviewed-existing.diff` preserves the inspected 42-file diff; added source is
identified by exact inventory hash. The predecessor checkpoint remains unchanged
and is referenced from `custody-checkpoint.json`. No bulk refresh authorizes an
unreviewed vendor change. Licenses, notices, package versions and lockfiles remain
canonical.

Remaining gates include the complete upstream feature/platform selection, all
Kasumi final-source tests/lints and dependency checks, actual process crashes,
nine-process HA acceptance and the 24-hour soak. This checkpoint authorizes exact
source integrity verification; it does not qualify production cache cutover.
