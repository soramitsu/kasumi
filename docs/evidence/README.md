# Development evidence

Dated development evidence is an ignored local archive. Logs, symbol dumps,
candidate source copies, checksum inventories and session notes belong here or
in external artifact storage, rather than in Git.

Keep maintained documentation, reproduction scripts and regression fixtures in
the repository. Metadata required by a build or release verifier belongs beside
the verifier's maintained inputs; dependency review receipts live in
`vendor/reviews/`.

Older documentation may name dated paths beneath this directory. Those paths
refer to local historical artifacts and are not supplied by a fresh checkout.
Previously committed evidence remains available in Git history. Preserve useful
results in concise maintained documentation, with an artifact location and
checksum when the full evidence must remain available.

The release-candidate workflow uploads run evidence as CI artifacts. Archive
required evidence externally before those artifacts expire. Local files beneath
this directory are also subject to removal by commands such as `git clean -X`.

Put routine benchmark output in the ignored `benchmarks/results/local/`
directory. Reviewed benchmark cohorts referenced by the published results
remain versioned separately.
