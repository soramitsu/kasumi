# Installed storage development diagnostics on master

All commands ran in `/Users/mtakemiya/dev/kasumi`, branch `master`, at base
`c283fa4a2c2344fd359d1d58ea49a1664de72088` with pending implementation changes.
These are development diagnostics, not a clean final-source release checkpoint.
The initial inventory covers store Rust source, redb runtime Rust source, and
the root and store manifests; later inventory scopes are described below.
These inventories do not certify the complete repository or binaries.

| Attempt | Command scope | Terminal result |
| --- | --- | --- |
| 01 | Store all-target/all-feature check | Failed: obsolete integration fixture constructor plus warnings |
| 02 | Same compile successor | Passed |
| 03 | Same compile after owned publication changes | Passed |
| 04 | Complete store library, all features, one test thread | 73 passed, 101 failed, 2 ignored |
| 05 | Same complete library successor | 170 passed, 4 failed, 2 ignored |
| 06 | Same complete library successor | **174 passed, 0 failed, 2 ignored** |
| 07 | Workspace all-target/all-feature check | Failed: duplicate ordered-seek module declaration |
| 08 | Same workspace check successor | Failed: four server integration/caller errors |
| 09 | Store all-target/all-feature strict Clippy | Failed: test module preceded production items |
| 10 | Same strict Clippy successor | **Passed** |
| 11 | Complete store library after prepared namespace changes | 180 passed, 1 failed, 2 ignored |
| 12 | Same complete library successor | **181 passed, 0 failed, 2 ignored** |
| 13 | Workspace all-target/all-feature check | Failed: recursive test-observer Send obligation |
| 14 | Same workspace check successor | Failed: server future layout exceeded compiler query depth |
| 15 | Store all-target/all-feature strict Clippy after namespace changes | **Passed** |
| 16 | Complete Python tooling unittest discovery | **84 passed** |
| 17 | Workspace all-target/all-feature check after synchronous startup admission | Failed: retirement backup-request future exceeded compiler query depth |
| 18 | Same workspace check after admitted backup-future boundary | **Passed** |
| 19 | Complete Raft library, all features, one test thread | 39 passed, 34 failed |
| 20 | Actual snapshot-child shutdown integration | **1 passed** |
| 21 | Node startup-owner inventory and charge lifetime | **1 passed** |
| 22 | Backup future admission, cancellation and original-error regressions | **3 passed** |
| 23 | Readiness coverage, epoch/freshness and retained probe regressions | **12 passed** |
| 24 | Installed marker/lock physical ownership regressions | **2 passed** |
| 25 | Actual protected TLS observability lifecycle, including 131 assigned groups | **1 passed** |
| 26 | Isolated cancelled-write/actual-child shutdown regression | **1 passed** |
| 27 | Isolated custody-capacity regression with backtrace | Failed: encrypted spool append returned InvalidData |
| 28 | Same custody-capacity case with nonallocating failure trace | Failed: physical allocation exceeded admitted extent |
| 29 | Same custody-capacity case after scratch EOF preparation | **Failed/unresolved: no terminal test result after the 1,200-second deadline; runner failed before its original receipt** |
| 30 | Complete store library after scratch EOF preparation | **183 passed, 0 failed, 2 ignored** |
| 32 | Workspace all-target/all-feature strict Clippy | Failed: four Raft enum/type/constructor lints |
| 33 | Same strict Clippy successor | Failed: one authority and eight engine lints |
| 34 | Workspace formatting check | **Passed** |
| 35 | Focused Raft snapshot-buffer ownership tests | **8 passed, but inventoried source changed; not a fixed-source pass** |
| 37 | Workspace all-target/all-feature strict Clippy successor | Failed: one engine fixture lint and thirteen server lints |
| 38 | Partial Raft regression, excluding only the separately failed capacity case | **Failed overall: 72 library tests passed; cluster 6 passed, 1 failed; later integration targets unrun** |
| 39 | Same strict Clippy successor | Failed: two server test lints |
| 40 | TLS listener lifecycle tests after inventory/limits cleanup | **4 passed** |
| 41 | Same strict Clippy successor | Failed: five engine test lints |
| 42 | Strict Clippy with keep-going across all workspace targets/features | Failed: two Raft test lints and one unnecessary mutable binding in an engine test |
| 43 | Same strict Clippy successor | **Passed** |
| 44 | Workspace formatting check after lint fixes | **Passed** |
| 45 | All four Raft integration targets after typed fatal-shutdown expectation fix | **18 passed** |
| 46 | Strict workspace Clippy after fatal-shutdown test correction | **Passed** |
| 47 | Workspace formatting after fatal-shutdown test correction | **Passed** |

The attempts with original terminal records (01–28, 30, 32–35 and 37–47) completed
within their original deadlines, sent no termination signals, and drained their
process groups. Their inventoried source stayed unchanged **except attempt 35**,
whose original receipt records `inventoried_source_unchanged: false`.
Attempt 29 is a separate
failed recovery case described below: its original timeout and signal fields
were not persisted, so those claims do not extend to it. Raw logs, result records,
before/after hashes and the exact runner source are retained unchanged;
`raw-sha256.json` verifies those evidence bytes. The two
ignored cases are the subprocess crash helper (exercised by its parent test) and
the external real-MinIO test. MinIO qualification did not run in these commands.

The workspace checks additionally inventory Rust files throughout the workspace
and OpenRaft vendor tree, member manifests and Cargo.lock. This remains a scoped
inventory, not complete source/binary qualification. Attempts 13, 14, 17 and 18
inventory all workspace and vendor Rust source/manifests plus the root lockfile;
attempt 16 inventories Python tooling and dependency-manifest inputs. Earlier
workspace attempts remain terminal failures; attempt 18 passes their combined
compile successor. This does not execute the newly added integration tests.
Attempt 09 was corrected by moving the unchanged test module after production
items, without lint suppression.

Attempt 04 exposed private-directory fixture setup and one lazy Darwin test
mutex allocation. Fixtures now create directories with private permissions at
birth; the test-only mutex is prepared before the measured I/O boundary. Neither
production permission checks nor zero-allocation assertions were weakened.

Attempt 05 exposed four outdated fixture expectations. The archive placement
fixture now installs one shared physical owner before nested archive enrollment
and explicitly closes the database before reopening. The permissions fixture
removes its deliberately invalid symlink before another root census. Offset I/O
tests now verify valid shrinking before intentionally failing owner admission;
substitution tests require a failed owner to remain fenced until actual
descriptor drain and explicit census, and verify stale backends stay closed.

Attempt 11's seven new namespace-boundary cases passed. One older fixture still
attempted managed deletion after permanently poisoning the shared device ledger.
Its successor verifies rejected deletion, retained nonzero charges and inode,
actual descriptor drain and continued shared-admission failure after census.
The production fence remains unchanged. Attempt 12 passes all 181 enabled cases.
The added namespace preparation reserves hash-table capacity, names, paths,
handle allocation and initial mutex setup before file creation. Publication and
reclaim success, failure and definite-conflict boundaries retain zero-allocation
assertions, with uncertain charges preserved.

The passing cohort includes mandatory NodeStore admission, per-inode charge
settlement, create-only durable publication, exact cleanup, explicit database
close, bounded encrypted scratch tables and zero-allocation physical boundaries.
Directory extents, admission of retained metadata, verification of the integrated
server marker writers, cancellation-safe archive jobs and complete combined/native release
qualification remain unfinished. G01–G14 remain open.

Attempt 13 was corrected by erasing only the test observer's concrete Raft/router
types. Attempt 14 led to synchronous startup-future admission and boxing before
returning a nongeneric claimant future. Attempt 17 reached the retirement backup
request and exposed another excessive future-layout depth. No recursion-limit
increase or test omission qualifies these failures. Attempt 18 directly bounds
the backup-session future, charges its exact size before construction and boxes
it before running the work. All workspace targets and features now compile.
Attempt 16's 84 cases include
the 18 dependency-gate tests; they are not additional to the total.

Attempt 19 is a terminal failure. Its first custody-capacity error was followed by
many scratch-device admission failures; attempt 26 passes one affected snapshot
case in isolation, and attempt 27 reproduces the initial error during an ordinary
encrypted spool append before encrypted-table construction. Investigation remains
open; the device failure fence has not been weakened. Later attempts 20–25
(shutdown, admission, backup future, readiness, markers and TLS) pass on the
corrected source. The complete Raft successor and original combined qualification
cohort remain required.

Attempt 28 measures the first failure: a ciphertext file of 1,114,792 bytes had
2,101,248 physically allocated bytes against a reservation of 1,183,744 bytes.
The previous allocation was 1,052,672 bytes and the filesystem unit was 4,096
bytes. This demonstrates excess physical allocation during an EOF-extending
scratch write. Its exact instrumented source is retained alongside the log and
matches the before/after inventory. The production correction prepares the
admitted ciphertext EOF at the actual flush, verifies the resulting allocation,
then writes within EOF and verifies again. Unused reservation paths do not
resize the file. Unexpected excess still fails and retains the owner fence;
logical pre-sizing is not a claim of a universal filesystem allocation guarantee.
Attempt 30 passes the full store library and both added raw-spool regressions:
12,600 interleaved record appends with authenticated readback, and unchanged
ciphertext after unused reservation settlement or denied resize. The custody
successor, attempt 29, failed to produce a terminal test result; its isolated
snapshot counterpart cannot replace the complete Raft cohort. All six focused
integration gates passed afterward.

Attempt 29 had a 1,200-second deadline. Its log records compilation and the start
of `custody_capacity_tests::permanent_custody_exceeds_former_count_and_snapshot_ceilings_and_reopens`,
but no terminal test result. The runner exited with status 1 after its
`os.killpg(process.pid, 0)` liveness probe raised `PermissionError: [Errno 1]
Operation not permitted`. It failed before writing `29-result.json` or its normal
after-source inventory. Neither missing file has been reconstructed.

The separately preserved `29-recovery-result.json` records failed/unresolved test
outcome, unknown test exit code, and recovery 1,309.774 seconds after the original
source inventory. An independent fresh process inventory found neither process
group 31804 nor the observed cargo/test PIDs; `29-runner-failure-audit.json`
preserves that post-failure audit. The recovery source inventory is byte-identical
to the original inventory. These observations establish drain and unchanged
inventoried source at recovery; they do not establish successful test completion.
The original timeout boolean and signal list were never persisted. `test29.py`
preserves the intended deadline/termination code, but that code must not be
reported as an observed signal history or as evidence that no signals were sent.

All eight available attempt-29 inputs are preserved byte-for-byte: the test log,
runner source, runner stderr, process audit, recovery receipt, original and
recovery inventories, and `29-custody-sample.txt`. The sample is a live diagnostic
stack sample of PID 31834, not a terminal test result, process-drain proof, or a
complete causal diagnosis. Its original generated text is unchanged. The
unresolved custody case and complete Raft successor remain required with their
original deadlines.

Attempt 32 reports a large spool-containing enum variant, callback type
complexity and two eight-argument constructors. These lint failures are retained;
the scoped store Clippy passes do not certify whole-workspace strict lint.

Attempt 33 is another terminal strict-lint failure: one authority lint and eight
engine lints. Attempt 34 passes the formatting check on unchanged inventoried
source. Attempt 37 still fails strict workspace lint, with one identical-branches
lint in an engine lifecycle fixture and thirteen server lints. None of these
records qualifies strict workspace lint as passing.

Attempt 35's log records eight passing snapshot-buffer ownership tests, including
actual blocked-child cancellation, retained panic/I/O outcomes, repeated drain,
fixed-slot custody and unused-owner release. However, six files changed during
the run's engine/authority mechanical edits:

* `crates/kasumi-authority/src/signer_coverage_state.rs`
* `crates/kasumi-engine/src/ordered_seek_service.rs`
* `crates/kasumi-engine/src/recovery_attempts.rs`
* `crates/kasumi-engine/src/service.rs`
* `crates/kasumi-engine/src/target_resolution.rs`
* `crates/kasumi-engine/src/test_utils.rs`

Comparison of the complete before/after inventories confirms that these are the
only changed paths; the inventoried Raft scope stayed unchanged. That narrower
observation does not override the original failed source-identity condition.
Attempt 35 is a diagnostic test result, **not a fixed-source qualifying pass**.
It requires replacement by a coordinated successor Raft regression on unchanged
inventoried source; no future successor result is asserted here.

The four attempts' twenty raw artifacts are preserved byte-for-byte: each runner
(`run33.py`, `run34.py`, `run35.py`, `run37.py`), command log, original result, and
before/after inventories. Their original result fields are unchanged, including
attempt 35's false source-identity flag. Numbering gaps imply no executed or
passing gate; no result for attempts 36 or 38 is manufactured by this update.

Attempt 43 passes strict workspace lint across all targets and features on the
unchanged pending source inventory. Earlier strict-lint failures remain preserved.
The three existing rmcp dependency dead-code warnings remain visible in the raw
log; this command does not substitute for each dependency’s standalone gates.

Attempt 40 passes all four TLS listener lifecycle cases on unchanged inventoried
source, including actual request drain on accept failure and listener continuation
after socket setup/reset failures. Its Darwin linker unwind-table size warning
is retained in the log; this is not final release binary qualification.

Attempt 38 deliberately excludes only the separately failed custody-capacity case;
it cannot qualify that requirement. All 72 selected library cases pass on unchanged
inventoried source, including all snapshot-buffer and startup-owner regressions.
The cluster target then passes six cases and fails its fatal-snapshot test because
its final shutdown still expected success after an injected storage failure. The
new typed drain correctly retained the original worker failure with Complete
resource completion. Remaining read-barrier, shutdown and storage-conformance
integration targets did not execute in this attempt. This failure is preserved;
its successor must assert the original typed failure and actual drain rather than
suppressing it. The complete Raft and release qualifications remain open.

Attempt 45 passes the seven cluster, five read-barrier, one shutdown and five
storage-conformance tests. Its corrected fatal-snapshot test requires a typed
Complete drain, original shared snapshot/state-machine storage failure, stable
issue identity on repeated shutdown and immediate reopen/replay without retry.
The production error is retained. Combined with attempt 38 this covers the selected
72 library cases and 18 integration cases; the excluded custody-capacity test
and complete final-source release qualification remain open.

Attempts 46 and 47 pass strict workspace lint and formatting after the fatal
shutdown test correction, with unchanged inventoried source and actual process
drain. This source is a development checkpoint; none of these diagnostics closes
a release workstream or replaces the remaining custody/native/installed gates.

Checkpoint whitespace audit 48 records the full staged check as failed on 2,136
whitespace reports, all inside preserved raw evidence or pinned OpenRaft vendor
files. A separately recorded check of the remaining authored paths passes. Those
exact evidence/vendor bytes were retained; no source, test or qualification gate
was waived by this whitespace-only distinction.
