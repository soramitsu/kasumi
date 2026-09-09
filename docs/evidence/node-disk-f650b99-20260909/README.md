# Persistent extent owner focused validation

Frozen source `f650b991558c7535d1c49bee28f1b3d0f401829b`, tree
`dd3286ece3b09b7125909a2596a356f1edd86037`, passes store all-target/all-feature
compilation and23 focused tests on Rust1.97.1/macOS ARM64:13 NodeDisk,
2 shared Device and8 existing Scratch tests. The exact required names, commands,
per-gate durations, selected feature graph and executable hashes are retained
in `evidence.json`. Four owned process groups drained and all source/tree/lock
hashes remained unchanged.

Coverage includes bounded descriptor census and cancellation, retained
closed-file/sparse/unused-growth charges, metadata limits, foreground versus
maintenance reserve, sole-owner reclamation, path substitution, last-owner
reopen sequencing and shared scratch/persistent filesystem promises. Retained
Device identity and per-registration pending contributions prevent a dropped
owner from clearing poison or silently releasing an outstanding promise.

This is an unwired primitive, not production persistent disk admission.
The production redb dependency is unchanged; creation, open/repair, ordinary
writes, close, compaction, archive/backup ownership and daemon configuration
still need integration. Strict full integration, upstream redb/fuzz, all final
platforms and actual3GiB capacity remain open. Tests use documented synthetic
free-space/device seams only under cfg(test); source review and focused tests
do not establish hostile external-writer isolation or physical host durability.

Raw records are byte-for-byte hashed by `preservation.json`. Actual executable
copies remain at their hashed paths in the original output directory. No
native database service or final release artifact ran in this cohort.
