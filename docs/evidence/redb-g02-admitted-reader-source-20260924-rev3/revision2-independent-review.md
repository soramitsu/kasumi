# Independent review: G11 redb source rebind revision 2

**DO NOT APPLY** `candidate.patch` as submitted. The source and patch-history
binding is technically complete for the current `/Users/mtakemiya/dev/kasumi`
`master` working tree, but this exact candidate explicitly says that it is
**unapproved** and requires a separately accepted successor before application.
This review neither approves a G11 release gate nor authorizes a scanner receipt
from the current candidate. I did not edit tracked source, apply the patch, run
Cargo or a scanner, or create another repository, branch or worktree.

The reviewed candidate patch is SHA-256
`68088c385e30aeb466ef4460538120a9369dc64f071a4f142eb266d28003e5b4`.
`git apply --check` passes on the current master working tree. It changes only
`vendor/patch-manifest.json` and adds the four original G02 patch files, the
five-file integration patch and `provenance.json` under
`docs/evidence/redb-g02-admitted-reader-source-20260924-rev2`. Independent
read-only reconstruction of each added evidence file from the patch reproduces
the six proposed files byte for byte. The proposed manifest SHA-256 is
`779ab2f0a45ed527a85c60ad6e8527091c883b5f4d07487913d6670f8996de45`;
the proposed provenance SHA-256 is
`72303e711bd3df8a653b1ce2d525694ce622863e1d984ef3e8f4e48db6bdfa7f`.

I parsed the old and proposed JSON with duplicate-key rejection and compared
their inventories. The proposed manifest changes exactly 21 existing redb file
records and adds `src/retained_read_transaction.rs` and
`src/retained_read_transaction_tests.rs`, yielding 112 redb records. Every
proposed SHA-256, byte count and mode matches the live file. Every provenance
file entry matches the proposed manifest and records the correct prior hash or
absence. Redb's package identities and published-crate digest, the other five
vendor inventories and all support-file records are unchanged. The source-only
candidate verifier passes under the bundled Python 3.12 runtime and confirms
the complete 999-file vendor roster; this is a projected check, not execution
of the official verifier after application.

Each of the four retained G02 patch files is byte-identical to its original
target artifact and matches its declared vendor-path headers. Per-file artifact
mapping in the proposed provenance matches those headers, including the two
overlaps at `src/lib.rs` and `src/tree_store/page_store/page_manager.rs`. Their
union is exactly the 23 changed redb paths. The other 18 changed/new files
match their final staged G02 copies. For the five staged-to-live differences,
I independently compared staged and live bytes, hashes and exact unified diffs.
The integration patch SHA-256 is
`c7fdf4690f3c81547b0ce52bd285d0843ef486acbc3d9a02abc25083960885e1`.
It contains the two `cached_file.rs` corrections, the `db.rs` and
`transaction_tracker.rs` rustdoc changes, the `multimap_table.rs` Clippy
allowance, and all three `retained_read_transaction.rs` corrections omitted by
revision 1. The source history is complete for this scoped rebind; diagnostic
logs cited under `target/` are supplemental and are not durable release
receipts. The two new reader files are still untracked and must be included in
any committed source set.

The remaining blocker is in the candidate's own review semantics.
`provenance.json` has status
`proposed-source-rebind-only-unapproved-revision2`; its `review_limit` says
independent source approval **and a separately accepted successor** are
required before application. The README repeats that this candidate is
unapproved and unapplied. The official
`scripts/check_dependency_patches.py::verify_review` validates the provenance
digest and source hashes but does not examine approval status or the change
artifacts. Applying this exact patch would therefore make the official
source-only checker accept a checkpoint that still declares itself unapproved.

Prepare a new, immutable successor. It can preserve the four exact G02 patch
bytes, the integration patch, and all 23 source records. Add this independent
review to durable evidence, change the provenance and README to describe a
**reviewed source-only rebind** with G11 and native/release qualification still
open, and remove the requirement for a further accepted successor once the
successor is independently reviewed. Recompute the provenance, manifest and
candidate hashes and obtain a final independent check of those exact bytes.
Only after that should the coordinator apply it on master, run the official
source-only verifier, focused Python regressions and locked Cargo selection,
then retry the diagnostic scanner probe. The default system `python3` here is
3.9 and lacks `tomllib`; use the bundled Python 3.12 runtime for the verifier.
