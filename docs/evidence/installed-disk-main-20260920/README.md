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
| 49 | Shared memory-core admission unit tests | **24 passed** |
| 50 | Workspace all-target/all-feature compilation after canonical Database admission | **Passed** |
| 51 | Strict workspace Clippy after memory-core integration | Failed: two test initializer lints |
| 52 | Complete engine library after shared admission integration | **184 passed, 13 failed, 1 ignored** |
| 53 | Admission and backup/retirement/response integration targets | **Failed: admission 2 passed; backup 9 passed, 3 failed; three later targets unrun** |
| 55 | Workspace formatting after fixed startup-scope integration | **Passed** |
| 56 | Strict workspace Clippy after initializer correction | **Passed** |
| 57 | Immediate replay of the first nine engine failures | **0 passed, 9 failed** |
| 58 | Workspace compilation after canonical typed Raft drain API | Failed: one local startup cleanup return mismatch |
| 59 | Same compilation with keep-going after local cleanup correction | Failed: Raft integration return-type fallout and one Generation fixture reference |
| 60 | Same compilation after caller and fixture corrections, including typed server startup cleanup | **Passed** |
| 61 | Ten corrected engine failures and seven proposal-ownership regressions | **17 passed** |
| 62 | Actual cancelled local-Raft startup and cancelled node census | **1 passed** |
| 63 | Full store library after retained namespace binding correction | **196 passed, 0 failed, 2 ignored** |
| 64 | Installed core, admission/startup and two corrected archive-cache cases | **32 passed** |
| 65 | Server admission consumers, readiness, credentials and typed startup cleanup | **37 passed, 9 failed** |
| 66 | Raft typed-drain library and all integration targets; prior custody-capacity failure excluded | **90 passed** |
| 67 | Strict workspace Clippy after scope/fixture integration | Failed: one backup cleanup manual-inspect lint |
| 68 | Previously unrun epoch, response-release and retirement integration targets | **13 passed, 1 failed** |
| 69 | Backup filesystem leaf ownership and session lifecycle | **8 passed** |
| 70 | Full backup checkpoint successor after exact charge and remote-read fixture corrections | **11 passed, 1 failed** |
| 71 | Server successor with canonical MCP registry, serving close and signer fixtures | **46 passed** |
| 72 | Terminal-row failure fencing and final backup reopen correction | **9 passed** |
| 73 | Workspace compilation after fixed startup-scope foundation | **Passed** |
| 74 | Admission/core/actual startup and corrected clock target | **35 passed** |
| 75 | Strict workspace Clippy after backup cleanup expression correction | **Passed** |
| 76 | Workspace formatting on the lint-corrected source | **Passed** |

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

The shared-memory/API stack was applied on `master` after checkpoint `b2876ef`.
Its five prepared layers and all 48 actual/intermediate/final file hashes were
verified before application. The application receipt matches every proposed
output; subsequent formatting made no changes. This is pending development
source, not a clean release candidate. Database construction now derives its
mandatory governor from the security audit. The lazy process fallback and late
admission setter are removed, and serialized runtime admission is required.

Attempt 49 passes all 24 admission unit tests, including fixed-ledger capacity,
resident ownership through replacement facades, strict configuration, retained
failure-report charges, actual sampler join and original panic retention. Attempt
50 passes workspace compilation across all targets and features. Attempt 51 fails
strict lint on two newly added test initializers; its log is preserved. Those two
initializers were rewritten without changing policy values, and attempt 56 passes
strict workspace lint. All four attempts recorded unchanged source and actual
process-group drain, without timeouts or signals. The original three rmcp
dependency warnings remain visible. Broader consumer tests, actual cancelled
startup census coverage, installed process-core selection and mandatory storage
metadata admission remain unfinished at this point.

Attempt 52 is the full engine-library failure, not a partial pass. Its 184 passing
cases include the real cancelled local-Raft startup and cancelled node census
regression: actual child ownership, charge retention, repeated typed failure and
fresh-facade reopen are exercised. The permanent 100,000-receipt capacity case is
ignored and remains required separately. Attempt 57 replays the first nine
observed failures with immediate diagnostics while attempt 52 was still running;
it is not an independent performance measurement. Both attempts retain unchanged
source, actual process-group drain, no runner timeout and no termination signals.

The failures include stale audit reopen/owner setup, shutdown expectations that
discarded real completed errors, cancellation before proposal-child admission,
missing permanent point-history views and missing bootstrap identity in fixtures.
Corrections preserve the original quotas, deadlines and workloads. Three cases
remain production blockers: two archive-cache lookups incorrectly fence a disk
on an unknown missing leaf, and public restore exceeds its unchanged verification
deadline while staging permanent terminal rows through individual durable
commits. The live stack sample is diagnostic evidence, not a complete performance
diagnosis. Neither extending the deadline nor reducing the workload qualifies
the public restore requirement.

Raft and custody shutdown now return the shared typed drain result directly.
Database, authority and custody cleanup merge its original issues and distinguish
Complete from Retained. Server startup cleanup likewise retains the typed report
as error context rather than formatting it into a string. Attempts 58 and 59
preserve compilation failures exposed by this direct API replacement. Attempt 60
passes workspace compilation with all targets/features after the callers and
Generation fixture were corrected. All three attempts record unchanged source,
actual process drain and no timeouts or signals. Their passes do not establish
behavioral success for the pending engine corrections or close a release goal.

Attempt 61 passes the ten corrected engine failures and all seven proposal-owner
regressions, with unchanged inventoried source and actual process drain, without
timeout or signals. Its `admission::startup_tests` selector matches no test;
the actual module is `admission::startup_integration_tests`. Therefore this
attempt supplies no new startup-census result; attempt 52 is the prior passing
observation, and a correctly selected successor remains required after the typed
Raft API changes. The two archive-binding failures, public restore deadline and
ignored permanent-receipt capacity case were not selected and remain open.

Attempt 62 uses the unchanged gate61 engine test executable, records its SHA-256,
and selects the correct startup-integration module. The actual cancelled startup
and census case passes, with unchanged source/binary and actual process drain,
without timeout or signals. It runs concurrently with attempt 53 and supplies no
independent performance measurement.

Attempt 53 passes both admission integration cases, then reports nine passing
backup cases and three failures. Archived-audit restore returns a generic storage
error, the destructive missing/corrupt-object fixture receives Unavailable where
it expected Corruption, and the restore-budget fixture observes 659,456 more
reserved bytes than its expected total. These findings require diagnosis; they
are not waived by changing expected results or increasing the payload cap.
Cargo stops after the failed backup target, leaving fixture_epoch_clock,
response_release and retirement unrun. The original receipt records unchanged
source, actual process drain and no timeout or signals. Follow-up source changes
and validation must identify which defects are production behavior and which are
stale fixture ownership/accounting assumptions.

The installed-core/fixture-budget foundation and namespace correction were then
applied after every before/after file hash matched its manifest; formatting changed
no proposed bytes. The namespace revision retains a 32-byte digest of root identity
and framed path components with each enrolled inode. Unknown missing final leaves
return NotFound only after parent verification. Missing enrolled names, raw rename,
substituted ancestry and unauthorized target growth fence the owner. Admitted
publication updates the existing binding immediately after physical rename,
before any fallible durability step. Target checks preserve legitimate unused or
partially materialized growth reservations without releasing their charges.

Attempt 63 passes all 196 enabled store cases, including 13 new namespace
regressions and the existing allocation-free physical mutation checks. The two
ignored cases are unchanged: the subprocess helper is exercised by its parent,
and actual MinIO qualification remains unrun. Source stayed unchanged and the
process group drained without timeout or signals. Mandatory metadata admission,
directory accounting, archive-consumer regressions and final qualification remain
open; the store pass alone does not close them.

Attempt 64 passes all 30 admission/core/startup cases and both archive-cache
failures from attempt 52. It checks exact policy equality, same-core reuse across
sealed facades, denial after actual sampler panic without replacing the core,
registry contention before independent construction, and the fixture helper's
unchanged one-byte capacity boundary. Its actual startup-census case also passes.
Source remains unchanged and the process group drains without timeout or signals.
The public restore deadline failure and mandatory installed storage wiring remain
open.

Attempt 65 passes 37 server cases, including the eight canonical startup-owner
tests, and fails nine credential/serving/signer fixtures. The two MCP failures
attempt to attach the same Raft group to a second node membership observer when
constructing another router; the fixture now retains one registry across those
requests, preserving the production observer identity fence. Serving-owner
reopen failures and signer ownership/cleanup expectations still require their
exact lifecycle corrections. The receipt records unchanged source, actual process
drain and no timeout or termination signals. The linker unwind-table size warning
is preserved and is not final binary qualification.

Backup filesystem read and unlink no longer short-circuit on raw path existence.
They pass absence through the retained NodeDisk namespace owner, accept unknown
or admitted-deleted leaves only while that owner remains healthy, and preserve
the original NotFound error when an enrolled leaf disappears. Repeated cleanup
keeps its previous idempotence after admitted deletion. Attempt 69 passes both
new ownership tests and six existing session publication, synchronization,
historical-purpose and cleanup tests on unchanged source, with actual process
drain and no timeout or signals. Directory census/accounting remains open.

Attempt 70 passes eleven backup cases, including archived-audit restore, bounded
captured/historical verification, remote missing/corrupt dependency detection and
the exact second Database proposal-registry charge. The remaining restore-budget
case reaches its reopen phase and fails because it initializes an already
initialized catalog. The fixture must use the existing-catalog and existing-custody
APIs at that phase; its original budget, document and release assertions remain
required. The receipt records unchanged source, actual process-group drain and
no timeout or signals. This full target remains failed until its corrected
reopen case passes; the other eleven observations do not qualify the complete
release.

Attempt 71 passes all 46 selected server cases after the fixture corrections,
including the nine failures from attempt 65. Serving tests close the actual
NodeStore after joining its worker and reopen through the same installed disk
owners and managed installation lock. A destructor panic still reports Retained
unknown ownership; specific already-closed physical files can reopen. Signer
fixtures enroll/delete their intentionally empty file through its owner, and
prove old sealed facades stay unusable while a fresh drained replacement works.
The MCP registry now belongs to the fixture lifetime across router creation.
Original workload, production identity fences, repeated issue identity and
credential/deadline checks remain. Source was unchanged and the process group
drained without timeout or signals. The linker unwind-table warning remains
preserved; full server and binary qualification remain open.

Attempt 72 passes eight terminal-row cases and the corrected restore-budget
reopen case. Existing catalog and custody APIs replace initialization only in
the already-created target's reopen phase, preserving exact payload charges,
retained proposal metadata, data verification and return-to-baseline assertions.
The full attempt 70 remains a failed historical run; its eleven passing cases
and this focused successor are scoped observations, not one new full-target pass.

Terminal staging now sets a failure latch before any fallible push work and
clears it only after identity and ordinal inserts both succeed. Repeated push
and finish reject a failed builder. The new actual second-insert regression
retains a durable identity and the already-advanced matching head, then proves
no view can be returned; another regression rejects finish after a valid prefix
followed by a validation failure. Original push errors and record ceilings remain
unchanged. Attempt 72 records unchanged source, actual process-group drain and
no timeout or signals. Batching and its memory/task ownership remain unimplemented.

Attempt 66 passes 72 selected Raft library cases and all 18 integration cases
(seven cluster, five read-barrier, one shutdown and five storage-conformance).
This exercises the direct typed drain API after shared admission integration,
including original fatal-snapshot outcomes, canceled startup/snapshot children,
repeat-safe shutdown and physical reopen. The original failed/unresolved
4,200-command/8,400-audit capacity case is explicitly excluded and remains required.
Source stayed unchanged; the process group drained without timeout or signals.
This is a partial development regression, not complete Raft/release qualification.

Attempt 68 executes all three integration targets left unrun by attempt 53.
All ten retirement tests and the response-release test pass; the clock target
passes two and fails its stale expectation that an ordinary receipt disappears
after 24 hours. The first-release contract requires permanent identity/outcome
retention. Its correction preserves original 59,999ms/60,000ms expiry checks and
the full simulated day, then requires exact receipt/digest retention, exact retry,
conflicting same-key rejection, unchanged data, and a distinct new command's
success. Attempt 68 stays failed. Source remained unchanged and the process
group drained without timeout or signals.

The reviewed fixed startup-scope foundation was applied with exact before/after
hashes after attempt 68 drained. Required max_startup_scopes policy admits a fixed
strong core census. Each scope reserves fixed resource cells before its inert
builder; actual resource handles and original typed observations survive canceled
drains and shared report views retain their charges. Generation tags prevent an
old completed scope from retiring a reused census slot. Existing server resource
and diagnostic adapters, aggregate process drain, and unmeasured arbitrary panic
payloads remain explicitly unqualified. Attempt 73 passes all-target/all-feature
workspace compilation with unchanged source and actual process drain, without
timeout or signals. An unrelated host Cargo build was observed concurrently;
these are compile diagnostics, not performance measurements. Behavioral tests
and lint of this foundation were not run in attempt 73.

Attempt 74 passes all 32 admission/core/startup cases and all three clock
integration cases. The two new scope tests retain actual children and original
fixed typed errors through canceled drain/caller drop, preserve resource charges
through cloned reports, require actual completion before slot reuse, and prove
capacity/byte denial occurs before the inert builder. Exact installed policy
checks include the new mandatory startup-scope field. The clock correction keeps
permanent receipts while leases and original credentials expire at their original
boundaries. Source stayed unchanged and the actual process group drained without
timeout or signals. Formatting attempt 55 passes on the same source with the same
drain guarantees. These scoped mechanics tests do not qualify the absent runtime
adapters or the unresolved capacity, platform and final-artifact gates.

Attempt 67 fails strict lint on one backup cleanup error-observation expression.
The successor replaces map_err returning the same error with inspect_err, keeping
the original I/O error and the exact owner-failure signal. Attempt 67 records
unchanged source and actual process drain without timeout or signals; its original
failure is preserved. No lint is suppressed.

Successors 75 and 76 pass strict all-target/all-feature workspace Clippy and
formatting after the backup error-observation correction. Both preserve unchanged
inventoried source and actual process-group drain without timeout or signals.
The existing three rmcp dependency warnings remain visible. This closes the
checkpoint's scoped lint/format checks, not the release's final combined test,
capacity, native-platform, external-service or artifact qualification.
