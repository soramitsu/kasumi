# Typed startup cleanup audit

Prepared, unapplied and uncompiled. `manifest.json` contains the exact before/proposed hashes for all 12 files. Rustfmt stdin parsing and `git apply --check` passed; actual source was unchanged by this work.

## Scoped finding and patch

Direct `RaftGroup`/`CustodyRaftGroup` shutdown results now propagate through Database, RetiredCustody, IndependentAuthority, NodeRuntime, AuthorityRuntime, target Generation cleanup, StartupResources and serving close aggregators with the correct Complete/Retained distinction. Their normal typed propagation merges original issue Arcs. Independent review of StartupResources/StartupOwner/ServingOwner close behavior found no new completion misclassification.

Several startup/recovery error paths still converted cleanup failure to a formatted string before attaching it to the preparation error. This discarded original `DrainIssue` objects. `startup_owner::finish` now returns `DrainResult` directly; its retry schedule and ownership behavior are unchanged. It returns only after positive completion and includes retained-child observations gathered before that completion.

Seventeen formatting sites now attach the actual `DrainFailure` as typed context. Authority node enrollment merges the report instead of wrapping it as a new issue. Direct matches, the local target wrapper and standalone result combiner accept the canonical typed result, and the retired-custody path no longer probes an anyhow value for a typed fallback. No aliases or compatibility overloads are introduced.

The existing actual child-panic regression now checks that another completed drain preserves the same original issue Arc, and that combining an original preparation I/O error with the typed cleanup failure keeps both downcastable. The cancellation regression continues to check original unfinished worker custody and issue identity after resumed cleanup.

## Validation needed

- Workspace check and strict Clippy for all targets/features, to catch direct API fallout.
- Server `startup_owner::tests` (actual child panic, cancelled drain, acknowledged handoff).
- Server startup preparation, enrollment, retired-source and local recovery failure-cleanup tests affected by these call paths.

No test was run by this agent. Root owns the gate schedule and terminal/drain evidence.

## Separate unresolved findings

1. Server `startup_owner::Registry` retains only `Option<anyhow::Error>`. Both `begin` and `drain_tasks` use `get_or_insert`, dropping later joined failures. `drain_tasks` then takes the error, so a repeated drain returns success and no longer reports the original issue. Administration's startup-registry drain records that opaque value as a fresh local issue. A coherent follow-up needs a retained report, canonical typed registry drain API, and multiple-child/cancel/repeated-drain regression. Its task/report admission must also be addressed; this patch does not invent an uncharged enlarged registry.
2. Engine `TargetReplica::Drop` and `TargetServingReplica::Drop` spawn unretained cleanup jobs. Those jobs log failures and release captured owners even if a database returns Retained. Explicit `close` correctly keeps its registration on Retained, so the abandoned-facade path needs a real retained cleanup owner/registry. Adding another detached reaper would not fix custody. This patch leaves that separate ownership work open.
