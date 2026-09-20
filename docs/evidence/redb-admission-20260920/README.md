# redb physical-admission prerequisite evidence

This checkpoint adds an isolated `vendor/redb-4.2.0` fork. Kasumi still resolves
the registry dependency: there is no dependency override or production constructor
bypass in this commit. The root manifest only excludes the standalone vendor crate
from the Kasumi workspace. This is not G02 acceptance or release approval.

## Source and scope

`vendor/redb-4.2.0/KASUMI_PATCH.md` records the required admission and close APIs,
the publication boundary, and the remaining NodeDisk/NodeAdmission obligations.
Every constructor requires admission; the old durability-selection APIs and
volatile transaction publication paths have been removed. Actual backend access
and the required admission owner must be derived from the same retained NodeDisk
file capability during integration.

The published crate checksum is
`de6c3b63e007e90ce536ec2ae4690826136a20ec8dbbbb400daef1bb999d2e36`, matching
Kasumi's existing Cargo.lock. Its retained `.cargo_vcs_info.json` identifies upstream
commit `23b6ba05473b13e69ed4db82f4b5bc07f0c33be9`. The missing derive companion was
restored from that exact upstream commit. The companion archive checksum is
`3aabc11f3779daebfc463b077e4c63779c384adb4ea3a4a947f03ac3cc6a244f`.

`provenance.json` inventories every original and fork file with SHA-256 hashes.
`published-to-fork.patch` is the complete patch against the published package.
`capture_provenance.py` regenerates both after verifying the two archive hashes.
Both upstream licenses, authorship, original manifests, and the upstream instructions
are retained. Both standalone Cargo.lock files are committed for repeatability.

## Validation at the admission checkpoint

Host validation uses Rust 1.97.1, one Cargo build job, locked offline dependencies,
and a target directory outside Kasumi's build directories. Logs contain the raw
outputs, including failed attempts. JSON result files record exact final-stage
commands and statuses. The names of earlier logs containing `final` describe
attempts, not successful acceptance.

| Evidence | Result and meaning |
| --- | --- |
| `53-focused-tests.log` | All 17 physical admission/publication/close/compaction counterexamples passed. |
| `54-recovery-basic-tests.log` | All 112 basic tests and 5 admitted integrity tests passed after the unclean-open verification fix. |
| `56-final-all-features-tests.log` | Broad run: 423 tests and 6 doctests passed; two old setup/expectation fixtures failed. These failures are retained. |
| `65-winning-root-rejection.log` | The old one-phase rollback expectation was replaced with refusal of a corrupted acknowledged root; the corrected test passed. |
| `66-integrity-failure.log` | The live integrity-check fixture now explicitly closes its setup database; the corrected test passed. |
| `73-no-std-panic-abort-check.log` | The supported no-std configuration compiled. The preceding probe in log 67 omitted required panic-abort and correctly failed. |
| `76-checkpoint-derive-tests.log` | All 19 companion tests passed. |
| `77-checkpoint-derive-clippy.log` | Companion all-target Clippy passed with warnings denied. |
| `79-default-strict-clippy.log`, `80-allfeatures-strict-clippy.log` | Main crate all-target Clippy passed with warnings denied for both default and all-feature configurations. |
| `78-checkpoint-derive-fmt.log`, `81-checkpoint-fmt.log` | Both crates passed format checks. |

The broad run plus the two corrected tests cover 425 tests and 6 doctests. This is
a composite validation record, not a claim that log 56 was green. After its source
snapshot, only the two test fixtures and a conditional test import changed; no
production implementation changed. `final-runtime-inputs.json` identifies the
log 55/56 inputs, `checkpoint-runtime-inputs.json` identifies the first fixture
correction snapshot, and `admission-checkpoint-inputs.json` identifies this commit's
runtime inputs.

The focused tests include construction refusal before extension, denial caught by
the caller still forcing whole-transaction rollback, pinned old roots, metadata
preparation denial before the winner, fault injection through header publication
and sync, exactly-once owner fencing/close, retained extents after both abort forms,
busy explicit close, stored versus borrowed savepoints, read-only close, and heap
allocation counters covering success, uncertain winner failure, rollback, and Drop.
Repeated write/delete/close/reopen cycles test allocation and extent plateaus.
Compaction tests a one-byte allowance followed by a larger retry that physically
shrinks the file under the retained physical cap.

The repair-at-capacity fixture verifies that repair respects the current physical
extent and preserves committed rows. Its geometry fits existing space; it does not
claim to force a repair-time CapacityDenied. Commit-preparation denial and zero-cap
initial construction refusal have separate forced counterexamples.

## Unpassed workflows and remaining integration

The retained upstream AGENTS.md requires: "Always run `just test` and confirm it
passes before telling the user you are done." It also requires `just test_all` for
the companion and `just fuzz_ci` for transaction changes. All three were attempted
(logs 29, 30, and 48) and failed with exit 127 because `just` is absent. Podman,
cargo-deny, and cargo-fuzz were also unavailable in the host inventory. The required
container, license/advisory audit, and fuzz workflows have **not passed**. Host checks
are useful evidence, not a substitute for those gates.

This checkpoint still contains inherited upstream TypeName legacy matching and
one-phase-header recovery interpretation. The user forbids backwards compatibility;
the parent has requested their removal as a separate reviewed commit after preserving
this checkpoint. They are not accepted production release behavior.

The real NodeDisk adapter still must prove nonallocating identity checks, writes,
sync/settlement, shrink, close, and owner-failure callbacks after publication and
during destruction. Preparation memory, full-tree discovery work, and scan CPU also
need charged NodeAdmission envelopes. Compaction limits relocation bytes and retained
candidate paths, but still scans the tree. Postwinning physical I/O uncertainty
returns OwnerFailed; it cannot be treated as recoverable CapacityDenied.
