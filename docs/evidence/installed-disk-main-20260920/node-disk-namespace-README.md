# NodeDisk retained namespace correction — proposed, not applied

This four-file proposal fixes a current failure in archive lookup: a missing object whose name was never enrolled returned ENOENT and fenced the entire disk. The retained ledger previously recorded inode and extent only, so simply exempting ENOENT would also hide disappearance of an enrolled file.

`NamespaceBinding` is a fixed 32-byte SHA-256 digest, with separate root/child domains and explicit component lengths. The root digest includes the physical root device and inode. Census traversal carries the prefix digest in each bounded cursor. Prepared file acquisition/publication computes the same binding before physical mutation. Accounted entries and live owners retain the fixed binding; no second path allocation or namespace map is introduced.

The canonical `open_file` now returns ordinary `NotFound` only for an unrecognized final-leaf binding after repeating root/ancestor checks and comparing the current parent inode with the prepared parent. Known missing names, invalid ancestry, inode substitution and unexpected present names still fence admission without releasing any charge. A live inode at another enrolled name is rejected before the harmless second-owner `WouldBlock` path.

Publication preparation takes the state guard before physical root/ancestor validation and seals admission on failure. The local guard drops before the input file owner on early return.

Create and publication check whether the destination binding is enrolled before mutation. A known target must still be the expected private regular inode; otherwise admission is fenced. A verified existing target returns `AlreadyExists` without mutation. Verification compares physical length exactly with the retained `actual_len`, requires it within `reserved_len`, and requires physical extent within retained bytes. A settled target must also match the full durable extent/pending record. An unsettled live target may retain unused reservation or admitted materialization not yet reflected in pending promises, so its actual extent need not equal the larger reservation. The check never alters or releases those promises. Successful rename immediately updates both the live owner and its existing ledger slot before any fallible sync or verification. Shrink retains the binding; durable reclamation removes it. A drained fresh census rebuilds names and extents together.

All lookups are bounded by the existing `max_census_entries`. The proposal scans the existing ledger to find a binding instead of allocating a second index. This adds O(enrolled files) work on create, publish, and final-leaf ENOENT. A different performance index would require separately admitted retained capacity; it is not smuggled into this correctness slice.

The fixed fields increase `AccountedFile`, `FileOwner`, and census `Cursor` by 32 bytes each, subject to final Rust layout qualification. The separately prepared installed metadata envelope must include those sizes in both retained/replacement ledgers, handle capacity, and census stack. The planned type-based formula already accounts for these categories; its copied-shape estimate must be regenerated when rebased. This proposal does not implement the broader memory governor wiring or directory extent/identity census. It preserves the current parent checks and strengthens the gap between path preparation and unknown final-leaf absence.

Thirteen new regressions cover:

- Unknown missing nested leaf leaves admission healthy and allows subsequent create/reopen/reclaim.
- Missing censused and closed-created names retain charges and fence until actual drain/census.
- Raw rename fences lookup through the old and new names with live and closed owners.
- Admitted rename makes the old name unknown; durable reclaim removes the new binding.
- A raw-deleted enrolled target cannot be recreated or published over.
- Verified live target conflicts remain healthy and preserve the existing file.
- Parent replacement after preparation cannot produce a healthy missing result.
- Parent replacement before preparation cannot conceal a known missing leaf.
- Missing or symlinked publication ancestors seal admission during preparation.
- Replaced publication roots seal admission before mutation.
- Replaced private source ancestors fail publication without allocation.
- Raw target growth, including growth within an unused reservation, cannot become a healthy conflict.
- Unused reservations and actual admitted growth remain healthy conflicts without releasing pending capacity.

The existing injected post-rename failures now also assert that the retained ledger already names the destination. Allocation measurements surround actual prepared execution in the new absence/create/rename/error cases. Existing physical I/O, close, shrink and reclamation allocation tests remain unchanged.

Validation performed: rustfmt on these four target-only copies; exact current/base SHA comparison; `git apply --check` against the workspace. No Cargo build or test was run, and no actual Rust source was edited. Root coordinates application and behavioral validation. There is no compatibility path or format alias.

## Revision receipt

Revision 1 is preserved in full under `revisions/v1/`, including its exact patch, all base/proposed files, manifest, README and applicability result. `revision-2-followup.patch` is the review correction from revision 1 to the current proposal. `revision-2-receipt.json` records the old/current/follow-up hashes and exact per-file intermediate hashes. The current `namespace.patch` remains the complete patch against actual unchanged source.
