# Restart census geometry and approved replacement policy

Current source conflates `max_census_entries` with a total census-entry budget and retained file admission. `node_disk/census.rs` increments work before skipping `.` and `..`, while file admission can still allow fewer than that numerical limit. Let F be regular file entries, D be nonroot directory entries and R be configured roots, assuming every admitted directory is traversed once, dot entries are returned once each, and depth/name/identity validation succeeds. Returned entries including dots but excluding EOF are:

    F + D + 2(D + R) = F + 3D + 2R

Even one root, no child directories and F=N-1 files yields N+1 returned entries. Thus an otherwise permitted namespace can fail the same configuration's next census. The frozen directory ledger's 2N+R retained slots alone does not cure this inconsistent traversal limit. Permanent session directory and record retention makes deleting historical identities an invalid workaround.

Root approved the following first-release replacement for the assembly agent; it is NOT yet present in the audited current source:

* At most N logical regular files and N logical nonroot directories; R roots are separate.
* Retained banks keep their existing geometry of 2N+R. Existing RAM, handle, depth, name and deadline limits are unchanged.
* The existing numerical N becomes explicit per-step work rather than an inconsistent total-job traversal cap. Replace configuration fields and every supported caller directly; no legacy alias, optional default or compatibility branch.
* A full job's hard operation bound follows from the admitted geometry. EOF adds one readdir call for each of D+R directories, so all calls are F+4D+3R, bounded by 5N+3R. The prior F+3D+2R expression deliberately excludes EOF; these expressions measure different things.

The geometry calculation is conditional on a fixed, verified namespace and one traversal, not permission to ignore concurrent mutation, corruption, cancellation, native close failures or deadlines. Each bounded step must preserve the exact cursor/ancestry stack, bank allocations, progress and original outcomes in an admitted owner. Full admission remains closed until the complete census and required terminal synchronization/close settle. Repeated root scans without conserved progress do not establish the bound. Error/EOF/step charging must be made explicit by the implementation; the successful-tree arithmetic is not a maximum number of arbitrary retry operations.

Caller consequences: count `sessions`, every session UUID child, every `objects` child, audit archive directories, generation directories and prepared crash remnants. Per-session tombstones are permanent. Admission must reject a new namespace before effects when its directory/file slots cannot fit, while preserving already admitted exact cleanup and diagnosis. Reconciliation must distinguish externally introduced unowned entries from managed pending creation. No implicit adoption or deletion of identity-bearing history is authorized by the revised counts.

This document derives logical traversal counts only. It supplies no physical directory extent bound, allocator coefficient, total memory bound, libc directory-buffer bound, runtime throughput guarantee or full release qualification. Those remain separate implementation and evidence obligations.
