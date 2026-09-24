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
| 77 | Workspace compilation after mandatory installed disk-memory integration | Failed: eleven diagnostics across three targets; source corrections preserved |
| 78 | Same workspace compilation after required caller corrections | **Passed** |
| 79 | Workspace formatting after mandatory memory integration | **Passed** |
| 80 | Complete store library after mandatory metadata and publication-lock correction | **215 passed, 0 failed, 2 ignored** |
| 81 | Engine memory/core/startup, explicit snapshot codec, admission and epoch cohort | **50 passed** |
| 82 | Server memory sharing, readiness, credentials, signer and startup cleanup | **49 passed** |
| 83 | Raft library and all integration targets after mandatory memory migration; prior custody-capacity failure excluded | **90 passed** |
| 84 | Complete authority library/integration caller regression | **Failed: timed out at 1,200 seconds during queued activation shutdown; one earlier coverage test failed and later tests did not complete** |
| 85 | Strict workspace Clippy | Failed: needless borrow in the store census caller |
| 86 | Engine library caller regression invocation | Failed before compilation/tests: Cargo rejects `test --keep-going` |
| 87 | Admission, complete backup checkpoint, epoch clock, response release and retirement integration targets | **28 passed** |
| 88 | Fourteen remaining engine integration targets, original workloads and deadlines | **72 passed, 22 failed across six targets; all fourteen targets completed** |
| 89 | Corrected engine library invocation; prior 512-by-256 restore failure excluded | **210 passed, 5 failed, 1 ignored, 1 filtered out** |
| 90 | Isolated replay of attempt 84's coverage failure using its exact test binary | **1 passed; full-suite failure remains unexplained** |
| 91 | Complete authority successor with explicit fence release and uncaptured diagnostics | **53 passed, 8 failed; queued-activation hang regression passes; later integration targets unrun** |
| 92 | Strict workspace Clippy after file retirement and fixture corrections | **Passed** |
| 93 | Complete store library after complete file resource retirement | **220 passed, 0 failed, 2 ignored** |
| 94 | Engine library successor after five exact fixture corrections; prior large restore failure excluded | **215 passed, 0 failed, 1 ignored, 1 filtered out** |
| 95 | Workspace formatting after file retirement and fixture corrections | **Passed** |
| 96 | Four authority availability failures with original-cause diagnostics | **3 passed, 1 failed later at exact stopped-epoch rejection** |
| 97 | Four target materialization successors and one narrow shutdown classifier | **3 passed, 2 failed** |
| 98 | Complete contracts, guarded staging, schema activation and staged transactions successors | **50 passed, 8 failed across schema/staged targets** |
| 99 | Complete admission/core/startup cohort after cancellation backing retirement correction | **34 passed** |
| 100 | Strict all-target/all-feature workspace Clippy after fixture corrections | **Passed** |
| 101 | Workspace formatting after fixture corrections | **Passed** |
| 102 | Actual retained redb commit/abort terminal tests | **5 passed, 3 failed** |
| 103 | History, lifecycle, schema and staged integration successors | **40 passed, 2 failed; one prior restore failure remains filtered and required** |
| 104 | Complete admission cohort and canonical snapshot codec tests | **49 passed** |
| 105 | Three authority successor cases and two precise close classifiers | **4 passed, 1 failed** |
| 106 | Complete store library including allocation-before-credit lease retirement | **223 passed, 0 failed, 2 ignored** |
| 107 | Complete vendor redb library after original-I/O, cache and retained-close prerequisites | **120 passed** |
| 108 | Complete engine library with snapshot ownership foundation; prior large restore excluded | **232 passed, 1 failed, 1 ignored, 1 filtered out** |
| 109 | Complete authority caller regression and doctests | **61 passed, 2 failed; zero doctests** |
| 110 | Complete store library after retained memory and vendor corrections | **223 passed, 0 failed, 2 ignored** |
| 111 | Strict all-target/all-feature workspace Clippy | **Passed** |
| 112 | Workspace formatting | **Passed** |
| 113 | Two recovery lifecycle failures with original-cause diagnostics | **1 passed, 1 failed** |
| 114 | Complete store library with borrowed spool close and actual backing retirement | **226 passed, 0 failed, 2 ignored** |
| 115 | Exact serving-expiry cleanup and negative cause classifier | **3 passed** |
| 116 | Stopped-epoch route diagnostic and signer-history read successor | **1 passed, 1 failed earlier during stop verification** |
| 117 | Expired recovery completion with original leader diagnostics | **Failed: native test stack overflow and SIGABRT** |
| 118 | Strict workspace Clippy after cache/disposal, handoff and exact stop-drain assertions | **Passed** |
| 119 | Workspace formatting after cache/disposal and completion handoff | **Passed** |
| 120 | Exact attempt-117 binary under LLDB | **Diagnostic only: test passed; debugger exited 1 because no stopped process remained for a backtrace** |
| 121 | Complete vendor redb library after fixed cache capacity and witnessed disposal | **131 passed** |
| 122 | Complete store library after cache and disposal dependency changes | **226 passed, 0 failed, 2 ignored** |
| 123 | Lifecycle completion handoff compilation | **Passed; no runtime test executed** |
| 124 | Complete lifecycle integration target after completion handoff | **12 passed, 2 failed; no ignored or filtered cases** |
| 125 | Exact stopped-epoch drain/witness assertions | **Failed at final rejection; all six drain observations passed** |
| 126 | Vendor page-list prerequisite compilation | **Failed before any test executed** |
| 127 | Complete store library after page-list dependency changes | **226 passed, 0 failed, 2 ignored** |
| 128 | Lifecycle vote diagnostic and current-leader phase-read compilation | **Passed; no runtime test executed** |
| 129 | Complete lifecycle integration target with the exact attempt-128 binary | **12 passed, 2 failed; no ignored or filtered cases** |
| 130 | Strict workspace Clippy after page-list and lifecycle changes | **Passed** |
| 131 | Workspace formatting after page-list and lifecycle changes | **Passed** |
| 132 | Complete vendor redb library after page-list compile corrections | **134 passed, 0 failed** |
| 133 | Original stopped-epoch case with bounded same-identity resolution | **1 passed, 0 failed, 62 filtered out** |
| 134 | Complete authority library after stopped-epoch resolution | **62 passed, 1 failed; no ignored or filtered cases** |
| 135 | Lifecycle single-write diagnostic compilation | **Failed before testing: temporary metrics receiver lifetime** |
| 136 | Lifecycle diagnostic after receiver lifetime correction | **Compiled; no runtime test executed** |
| 137 | Both original uncertain-activation cases after route/diagnostic changes | **0 passed, 2 failed at first reopen; 12 filtered out** |
| 138 | Lifecycle stale-route alias retirement compilation | **Compiled; no runtime test executed** |
| 139 | Both original uncertain-activation cases after alias retirement | **2 passed, 0 failed; 12 filtered out** |
| 140 | Original failing activation-maintenance case with exact local confirmation | **1 passed, 0 failed; 62 filtered out** |
| 141 | Other original activation helper case with exact local confirmation | **1 passed, 0 failed; 62 filtered out** |
| 142 | Canonical format4 and bounded DATA400 reclamation compilation | **Failed before testing: 11 errors and one warning** |
| 143 | Complete vendor library after canonical-format compile correction | **142 passed, 0 failed; no ignored or filtered cases** |
| 144 | Complete vendor library with bounded allocation-history purge | **148 passed, 0 failed; no ignored or filtered cases** |
| 145 | Ten public vendor targets, default features | **255 passed, 2 failed; cursor target has zero enabled cases** |
| 146 | Original upstream-layout rejection with exact diagnostic | **0 passed, 1 failed; four filtered** |
| 147 | Both original public fixture cases after corrections | **2 passed, 0 failed; 112 filtered across two targets** |
| 148 | Ten public vendor targets with cursor/API5 enabled | **296 passed, 0 failed; no ignored or filtered cases** |
| 149 | Complete vendor library after checked allocator length planning | **155 passed, 0 failed; no ignored or filtered cases** |
| 150 | Strict workspace Clippy after canonical reclamation and length planning | **Passed** |
| 151 | Complete vendor library after one-buffer allocator encoding | **162 passed, 0 failed; no ignored or filtered cases** |
| 152 | Complete store library after canonical reclamation and encoder changes | **226 passed, 0 failed; 2 ignored** |
| 153 | Strict vendor all-target/all-feature Clippy | **Failed: API5 trait import and unchecked stripe conversion** |
| 154 | Same strict vendor command after compile correction | **Failed: 41 test-only strict lint errors** |
| 155 | Same strict vendor command after explicit test syntax/conversion corrections | **Passed** |
| 156 | Complete all-feature vendor library with retained database opening | **197 passed, 0 failed; no ignored or filtered cases** |
| 157 | Complete all-feature vendor library with canonical allocator-key rejection | **204 passed, 0 failed; no ignored or filtered cases** |
| 158 | Strict vendor Clippy after opening and allocator-key changes | **Passed** |
| 159 | Strict workspace Clippy after opening and allocator-key changes | **Passed** |
| 160 | Workspace and standalone vendor formatting | **Passed** |
| 161 | Ten public vendor integration targets with experimental cursor/API5 | **296 passed** |
| 162 | Full all-feature vendor library after canonical allocator payload validation | **211 passed** |
| 163 | Strict all-target/all-feature vendor Clippy after payload validation | **Passed** |
| 164 | Original ten public vendor targets after payload validation | **296 passed** |
| 165 | Existing verifier regressions and exact reviewed source/Cargo selection | **18 tests and seven package selections passed** |

Attempt 125 completes both original drain windows, with all six exact witness
assertions passing, then encounters `UnknownOutcome` at the final late-intent
rejection. The original proposal diagnostic captures local node 1 changing from
admitted term 1 to healthy term 2/Follower with no current leader. Its group drains
in 80.045 seconds with unchanged source, no outer timeout and no runner signals.
The subsequent fixture correction captures one original signed request and verified
context, and resolves only after observed executing-node term, leader or role
movement. Every actual group must pass access checks before and after execution.
One five-second caller timeout covers all calls and additional leader selection;
only the exact stopped-epoch Conflict satisfies the assertion. These observations
do not prove an atomic sole cause or bound already accepted children's lifetimes.
Attempt 133 passes this successor in 9.69 seconds of test execution and 85.802
seconds overall. Its log captures the actual healthy term/role movement and
original `UnknownOutcome` before the same request resolves to the exact rejection.
The original final close succeeds. Source stays unchanged and the owned group
drains with no outer timeout or runner signals. Broader authority qualification
remains required.

Attempt 126 fails compilation before testing: adding Copy to the page-list key
makes an existing closure FnMut, requiring its binding to be mutable. A new test
also needs an explicitly qualified panic macro. Both failures are preserved with
the exact corrective patch. Attempt 132 then passes all 134 vendor library cases
in 53.534 seconds, with unchanged source, actual group drain and no timeout or
signals. The three new cases validate page-list shape without allocation, reject
malformed selected ranges before either namespace is removed, and retain the
original real extraction-close I/O failure with uncertain transaction/database
custody. Selection and deferred reclaim still scale with historical backlog.
Attempt 127 passes all 226 enabled store cases in 88.756 seconds, with both ignored
cases still required separately. Its source inventory is unchanged, its owned
process group drains, and no timeout or runner signal occurs.
Attempt 128 compiles the lifecycle successor in 34.582 seconds with unchanged
source, process drain and no timeout or signals. A 32-slot vote probe retains
bounded request/return/drop observations and publishes them only if the original
leader wait fails. It forwards original arguments and results, with unchanged
transport TTL and election settings. The recovery fixture captures the original
context before selecting the current leader for its original phase read. Runtime
qualification and new-binary frame inspection are recorded separately below.

Attempt 129 completes all fourteen original lifecycle cases in 400.04 seconds of
test execution and 402.974 seconds overall: 12 pass and two fail. Both the full
source inventory and the exact attempt-128 binary remain unchanged, the owned
process group drains, and no outer timeout or runner signal occurs. There is no
stack overflow. The earlier fresh-bootstrap failure is not reproduced; this does
not establish its cause or a specific fix.

The first failure is the initial next_recovery_dispatch observation at original
common/recovery_control.rs line 253, after Start and duplicate/alias assertions.
It reaches the node cached before those calls: healthy node 1, now Follower in
term 5 with no current leader. The single read still returns Unavailable and the
original assertion fails. The second failure is commit_next_intent at original
line 1776, called by the confirming-intent phase at line 997 after resolving the
activation winner. Its original single write returns UnknownOutcome at the
ten-second caller deadline. No exact pending child stage or route metrics were
captured at that failure; leadership movement, commit absence and physical-owner
failure must not be inferred from that error alone. Target-only current-route
and diagnostic successors preserve the original calls, identities and deadlines.

Attempts 130 and 131 pass strict workspace Clippy and formatting in 128.564 and
1.757 seconds. Each records unchanged source, actual owned-process drain and no
timeout or signals. Existing dependency warnings remain visible in the lint log.

Attempt 134 completes all 63 authority cases in 768.69 seconds of test execution
and 770.377 seconds overall: 62 pass and one fails. Source remains unchanged, the
owned process group drains, and no outer timeout or runner signal occurs. The
activation-maintenance case fails at target_materialization_tests.rs line 1325,
when journal.record_activation rechecks the original leader-bound activation
proof after confirming the other voters. Its original linearizable barrier
reports that it must forward without a known leader; the authority denial is
wrapped as UnknownOutcome. The exact signed activation had already been obtained
before those confirmations. A proposed selected-voter local confirmation uses
that same signed fact and operation before projection, with its actual persisted
application and authority checks; this successor is now applied. This is
not a passing authority gate or an atomic diagnosis of the underlying route change.

Attempts 140 and 141 pass both original tests using the changed activation helper.
The new local proof asserts the same activation fact and selected observer, and
is explicitly dropped before the original target drain. Original successful
leader-proof signing, forged-proof rejection, other-voter confirmation, journal
replay/reopen, corruption rejection and ordinary serving assertions remain. A
later persisted applied-term change can still invalidate proof reuse; no new
issuer winner or fresh authorization is introduced. Test/overall times are
65.12/74.521 and 55.94/56.387 seconds. Both source inventories remain unchanged,
both process groups drain, and neither runner sends signals or times out.

Attempt 135 fails with E0716 before testing: the diagnostic borrows a temporary
metrics receiver across its next statement. Its two-line correction binds the
receiver inside the existing scalar-capture block, which ends before the original
write await. Attempt 136 compiles in 3.186 seconds. Its exact binary
`0f393accc494917f40fb35c4cee06bd88d20532bda6b9ca88eca06a74537dc2f`
then runs both original uncertain-activation cases in 137. Both fail at the first
reopen with the actual NodeFile exclusive lock returning operation-would-block.
The route refresh had shadowed the original database Arc; the existing drop
released only its replacement. Neither case reaches the original attempt-129
failures or the new write diagnostic. The 22.661-second run retains unchanged
source/binary and drains without outer timeout or signals.

The correction explicitly retires the old routing Arc before binding its
replacement. The fixture retains the actual databases during selection, and the
replacement follows the original drop/close/reopen boundary. No lock retry or
deadline extension is added. Attempt 138 compiles in 2.549 seconds; attempt 139
passes both original cases in 109.67 seconds of test execution and 112.434 seconds
overall against exact binary
`4ad75c3d3586d0464e9326ff32b9f38aae1c84a991b16a52087ef80f02d498de`.
Source and binary remain unchanged, the group drains, and no timeout or signals
occur. The confirming-intent timeout does not recur, so its cause remains open.

Separate attempt-136 static inspection covers ten changed or adjacent functions.
Preparation, continuation and outer frames are 634,752, 681,504 and 110,368 bytes;
both box adapters remain separate 64-byte calls. The intent poll and failure
closure use 68,944 and 1,616 bytes. Named outer/adapter/continuation/intent/failure
frames total 862,496 bytes, excluding generic adapters, runtime, formatting,
filesystem and other callees. This is a component sum, not a whole-thread bound.
The later alias-retirement binary is separately identified above and is not
retroactively assigned the previous binary's frame evidence.

The fourteen-file canonical format4/DATA400 patch is now applied. Attempt 142
fails compilation in 6.582 seconds, with unchanged source, actual process drain,
no outer timeout and no signals. Its eleven errors cover incomplete dirty-marker
signature changes in unrelated user-table methods, an accidentally deleted public
statistics method, and a missing test trait import; an unused test import also
warns. No test executes. The fixed DATA prefix, direct prepared-system exclusion,
older-format rejection and explicit close remain unqualified on this successor
until the compile corrections and required fault/public integration gates pass.
Attempt 143 then passes all 142 vendor library tests after restoring unrelated
TableNamespace, statistics/debug and trait-import code. Its 42.052-second run
(36.13 seconds testing) keeps source unchanged and drains process group 80225
without runner signals or timeout. The library includes canonical rejection,
actual extraction-close I/O custody, reader horizons, abort preservation and
cold-reopen prefix tests. Two now-unused internal helpers produce warnings.
Public integration/fault gates remain open; this scoped pass is not final acceptance.
Attempt 144 adds bounded allocation-history removal before DATA reclamation and
removes the two obsolete internal helpers. All 148 vendor library cases pass in
36.99 test seconds (42.612 seconds total), with unchanged source and process group
83974 drained without timeout or signals. Both prefix namespaces are validated
before removal; retained eligible allocation debt blocks DATA free. The six added
cases cover five cold-reopen batches, savepoint/reader horizons, exact restoration,
malformed prefixes and original allocation-close I/O custody. This does not supply
protected allocator capacity, whole-transaction memory bounds or complete
independent multi-cause close/panic custody.
Attempt 145 dispatches all ten public targets: basic111PASS, canonical4PASS/1FAIL,
admitted-integrity5PASS, failed-integrity1PASS, corrupt-descent1PASS, crash1PASS,
cursor0enabled, integration108PASS/1FAIL, multimap20PASS, concurrency4PASS. Total
255PASS/2FAIL, 235.203 seconds, source unchanged and process group85407 drained
without signals or timeout. The corruption fixture looks for serialized version3
although the sole writer now uses4. Attempt146 keeps the original canonical
assertion and records the actual returned error: noncanonical region-header count
130, encountered before version decoding. Its original upstream header has the
two-phase bit set. The 7.705-second diagnostic drains group395 without signals,
timeout or source changes. Rejection is working; the expected error provenance
in the fixture was wrong. Attempt147 passes both corrected original cases in
8.768 seconds, retaining unchanged source and actual process-group939 drain,
without timeout or signals. Attempt148 then passes all 296 cases with cursor/API5
enabled: basic112, canonical5, admitted-integrity5, failed-integrity1,
corrupt-descent1, crash1, cursor37, integration109, multimap21, concurrency4.
The 277.981-second run keeps inventoried source unchanged and drains process
group1001 without timeout or signals. This qualifies the affected public paths
on this source; physical maintenance reserve and whole-process limits remain open.
Attempt149 applies allocation-free checked encoded-length helpers to reservation
planning and passes all 155 vendor library cases, including seven new geometry,
overflow, exact-byte and allocation-count cases. The 52.601-second run
(47.78testing) keeps source unchanged and drains group2392 with no timeout or
signals. Original serializer/decoder bodies remain byte-identical. The existing
per-region scalar Vec and actual serialization/COW buffers remain; this pass
does not establish an allocation-free complete reservation or total RSS bound.
Attempt 150 passes strict workspace Clippy in 121.918 seconds; three existing rmcp
dependency dead-code warnings remain visible. Its source is unchanged and
process group 4925 drains without timeout or signals. Attempt 151 applies the
independently reviewed one-buffer allocator encoder and passes all 162 vendor
library cases in 50.900 seconds (44.99 testing). Group 6794 drains, source remains
unchanged and no timeout or signals occur. All seven new encoder cases pass:
canonical byte equality, guarded output, unchanged short/long/invalid refusals,
zero allocations during encoding and exactly one allocation for collected output.
Old nested serializers remain only as test reference algorithms. The full
prepared allocator copy, final output, COW workspace and protected maintenance
reserve remain open; these results do not establish the total memory bound.
Attempt 152 passes all 226 enabled store library cases in 171.622 seconds
(126.72 testing); two existing cases remain ignored. Group 8965 drains.
Attempt 153 fails in 11.943 seconds: API5 requires the ReadableTable trait at
four fixture calls, and the stripe-count cast fails the crate's strict lint.
Attempt 154 fixes those, then fails on 41 test-only lints in 5.194 seconds.
Groups 9468 and 9706 drain. The second correction keeps exact pointer-identity
assertions through explicit pointer construction, checks bounded fixture casts,
retains failure matches with let-else and unwraps each history row in an explicit
fold. No lint suppression, case removal, cap change or assertion weakening is
introduced. Attempt 155 passes all-target/all-feature vendor Clippy in 10.502
seconds and group 10423 drains.

Attempt 156 integrates retained opening revision 3 and passes all 197 all-feature
vendor library cases in 108.533 seconds (94.66 testing). Group 12025 drains.
All eleven new actual-backend cases pass, covering preparation without I/O,
initialization/callback unwinds, simultaneous original I/O and fence-hook panic,
bootstrap body/commit/rollback failures, actual transaction disposal, preserved
failure phases and close waiting for accepted readers/writers. Native fixtures
retain uncertain resources in fixed process-static slots. The opening proxy keeps
the same underlying admission object and catches its once-only failure-hook panic
before the original I/O result can be lost. The repair callback directly requires
Send + Sync. Complete production census/adoption and resource bounds remain open.
Attempts 152–156 keep inventoried source unchanged and have no timeout or runner
signals. Their raw evidence is included in the opening/namespace archive append.
Attempt 157 applies the six-file canonical allocator-key patch composed with the
retained opening owner. The obsolete variant, tags 0–2 decoding and tag-0 writer
are removed. All 204 all-feature library cases pass in 101.610 seconds
(89.79 testing); group 15787 drains. Seven new cases cover canonical syntax,
clean/unclean and read-only unchanged-file rejection, malformed transaction
stamps, integrity refusal, successful stale-snapshot repair and raw leaf/branch
geometry/cycles. Full allocator payload/layout and complete traversal resource
bounds remain open. Attempt 158 passes strict all-target/all-feature vendor
Clippy in 12.196 seconds and group 16262 drains. Both runs keep source unchanged
and have no timeout or runner signals.

Attempt 159 passes strict all-target/all-feature workspace Clippy in 175.315
seconds; three existing rmcp dependency warnings remain visible. Attempt 160
runs both workspace and standalone vendor formatting checks in 2.229 seconds;
both phases exit zero. Attempt 161 passes the original ten public vendor targets
with experimental cursor/API5 enabled: basic 112, canonical format 5, admitted
integrity 5, failed integrity 1, corrupt descent 1, crash consistency 1, cursor 37,
integration 109, multimap 21 and concurrency 4, totaling 296 in 346.368 seconds.
Groups 16859, 17763 and 17971 drain. All three runs preserve inventoried source
and have no timeout or runner signals. They do not qualify unfinished production
census/adoption, allocator workspace, fault/performance or release gates.

Attempt 162 applies the five-file payload validation package, patch SHA-256
`6b2e9c49d20f1fee3d345c764a9566bd929eeee30ea9c9dbc3d6742edf414235`,
after exact-base and source-derived root review. All 211 all-feature vendor unit
cases pass in 136.457 seconds (125.54 testing). All-order producer allocation,
free, shrink and extension fixtures substantiate canonical tail/summary checks;
retained tracker capacity and current-versus-stale contraction cases also pass.
The malformed native case exercises 16 clean/unclean fixtures through consuming,
read-only and retained openings without repair callbacks or changed file bytes.
The raw branch case now rejects canonical separators that misroute an equal key.
Attempt 163 passes strict vendor Clippy in 11.983 seconds. Its inherited scope
label mentions the earlier key prerequisite; its exact source inventory includes
the applied payload successor. Attempt 164 passes all 296 tests in the original
ten public targets with cursor/API5 in 341.737 seconds (253.60 for integration).
All three runs have unchanged inventoried source, no timeout/signals and actual
drain of groups 24263, 26707 and 27344. Their raw files are included in the payload
append. Reachable-root allocation correspondence, tracker false-full
consistency, PageNumber canonicalization, full traversal/decoder memory, protected
maintenance and total native memory/workspace remain unqualified.

Attempt 165 integrates only the reviewed vendor inventory/provenance successor
and immutable supporting evidence. The new policy SHA-256 is
`390a5dc4fe90d800fb4255d9f77eaf5f816a2671635a1f68c2445f1f68e87fbd`;
new provenance is
`2dace2b24932576a9c6a7ee061041ba836ec4aeaff1fc000b24a8e808ef65ed7`.
Root review verifies 109 actual files, both original removals and 134 copied
historical/gate bindings. Proposal status remains immutable; its later adoption
decision is recorded separately. The exact unchanged verifier had already passed
its source checks on the frozen target copy and refused stale provenance, a
missing payload file and an altered mode. The actual root run passes all 18
existing synthetic tests and all seven source/Cargo package selections in 1.184
seconds using Python 3.12.14. Its expanded before/after inventory includes vendor
metadata, reviewed provenance and verifier source. Group 38305 drains with no
timeout/signals and unchanged inputs. Other five vendor roots remain unchanged;
only the vendor README support record changes alongside redb. This is exact
current-source dependency verification, not final release acceptance.

The unapplied managed namespace package preserves its parser failure, compile
failure and native 43-pass/four-failure trial. Correcting Darwin's retained inode
link-count assumption and the fixture's absolute ancestor depth yields native03:
47 pass, five inherited device cases filtered, 1.29 seconds testing, all five
groups drained and 1,729 inputs unchanged. Root review then identifies new generic
parent acquisitions outside PendingDirectory; the separate four-file generic
correction routes them through prepublished custody and removes its extra
verification walk. Its native01 passes all prior 47 cases plus two new cases in
2.29 seconds, five filtered, with 1,731 inputs and binaries unchanged; groups
14226, 14227, 14239, 14257 and 14261 drain. The scoped review approves that
correction while leaving ordinary root/Drop close contracts, aggregate admission,
the 44 caller sites, physical filesystem bounds and whole-process memory open.

Attempt 124 passes the formerly overflowing expired-completion case and five
other recovery cases. It fails a fresh control fixture's initial ten-second
leader wait: node 1 is Candidate at term 50, while both peers have persisted its
term-50 vote but remain Learners without initial logs. All three report healthy
running state. This does not establish whether vote responses were received in
time. The other failure occurs during the uncertain-activation case's preparation:
the original phase read is sent to node 1 after it has become a healthy term-3
Follower with node 3 as current leader. It fails before that test's activation
fault. No native stack overflow occurs in this successor. The full failed cohort,
including both original error paths, is preserved; it is not a passing lifecycle
gate. Its group drains in 366.676 seconds with unchanged inventoried source, no
outer timeout and no runner signals.

The exact stop-drain fixture assertions are applied only after that cohort drains.
Their four negative observations now require the actual incomplete-drain error;
all six observations require the original term/start/last witness. They preserve
the API requests, contexts, clocks, late Conflict and deadlines. Failure-only
diagnostics retain the actual result and inspect per-member metrics/access state.
This strengthens the fixture's proof without claiming to fix its route failure.
Attempt 118 passes strict workspace lint on these applied assertions in 118.734
seconds, with unchanged source and actual group drain. The three existing rmcp
dependency warnings remain visible in its raw log.

Attempts 119, 122 and 123 finish in 1.711, 107.300 and 57.206 seconds,
respectively. All record unchanged inventoried source, actual process-group
drain, no outer timeout and no runner signals. The store result retains both
ignored cases as unqualified. Compilation produces a new lifecycle binary for
the separate static-frame and runtime checks; it does not settle attempt 117.

Attempt 121 passes all eleven retained transaction tests, five retained database
close tests and eight new cache admission/selection regressions. Its owned group
drained in 49.305 seconds with unchanged inventoried source, no timeout and no
runner signals. Disposal requires the matching borrowed retained database and
keeps original terminal/rollback observations after the actual transaction is
retired. Cache refusal preserves selected-page rollback, admitted file growth,
original I/O and uncertain abort custody. The mixed borrowed/second-chance
regression requires an actual eviction before a new slot is admitted. Both
successful database-close phases are asserted independently. This is a vendor
default-feature development gate; production aggregate adoption remains open.

The rejected first cache revision, independently reviewed successor and required
clean-close assertion correction are all preserved. The fixed cardinality permits
a checked collection-metadata component; that calculation excludes payloads,
retained guards, transaction collections and allocator/RSS behavior. It is not a
total workspace reservation. The source application is recorded separately in
`121-cache-applied.json`; disposal and recovery handoff have their own receipts.

Attempt 120 did not reproduce the native stack overflow. The exact prior binary's
test passed in 101.81 seconds under LLDB; the subsequent backtrace command failed
because the inferior had already exited. The debugger therefore exited 1 after
107.071 seconds. Its later process-kill command was not executed. LLDB created
separate debugger, debugserver and inferior process groups; the independent
terminal census confirms all three were absent. The late descendant watcher
itself failed its initial assertion after those processes had exited, sent no
signals and supplies no continuous-monitoring evidence.

Static disassembly of that same hashed binary shows a 1,349,120-byte recovery
completion poll frame calling a 312,256-byte expired-resolution poll frame under
a 71,600-byte outer frame. This establishes stack pressure, not the exact crash
instruction. The applied handoff returns the preparation poll frame before
polling expiry resolution and preserves the same live fixture, database, request,
keys, assertions and deadlines. No stack-size increase was made.

The new attempt-123 binary has SHA-256
`c8e9e7dc2ac7b878f9462a4b683469119fa78154682f8c131f6065f17f2cf85f`.
Its static disassembly shows preparation at 623,632 bytes, continuation at
681,136, outer orchestration at 109,760 and unchanged expiry at 312,256. The
outer now polls those phases separately. Outer plus expiry and its 64-byte Box
adapter total 422,080 bytes; the old three named frames totaled 1,732,976 bytes
before adapters. These are measured frame compositions, not a whole-thread stack
bound or runtime pass. Exact prologues, call edges and unchanged before/after
binary/source hashes are in `123-lifecycle-static-stack/`.

The frozen `directory-parent-transitions/` candidate is archived **unapplied and
not merge-ready**. Its native module probe and 17 mocked Python checks pass, but
complete Rust callers, a usable whole-server 2 GiB configuration, raw directory
operations and supported-filesystem pre-effect allocation bounds remain open.
Its four-times table calculation is an estimate, not a verified bound on pinned
hashbrown growth and allocation overlap; the numeric calculation must not be
promoted into that claim. Source, failed attempts and receipts are preserved,
with 949 native probe/dependency binaries retained only under target and listed
by exact digest.

The separate frozen `directory-cursor/` successor is also **unapplied and not
merge-ready**. Its eleven cursor tests pass in native attempt 06, with unchanged
source and exact before/after executable hash; all four command groups drain.
The cursor retains its counted directory owner through actual stream close,
checks namespace generation and exact child bindings, and preserves original
close failure without replay. It is a standalone module probe, with omitted
unrelated test modules and no integrated backup caller execution. Managed child
mkdir/rmdir, qualified physical growth bounds, fixed map backing and whole-server
memory fit remain open. Earlier compile failures and attempt 05's missing
executable-hash evidence are preserved, not retroactively upgraded.

Further source review identifies an inherited restart-limit mismatch: file
creation checks the file count against `max_census_entries`, while census consumes
that limit for every native directory entry, including dot entries and directories.
The retained ledger intentionally funds up to `2N + R` entries, but a replacement
census permits only `N + R` distinct entries and at most `N` raw traversal steps.
An admitted runtime namespace can therefore exceed what the same configuration
can recount. Fixed map backing does not resolve this semantic gap. Managed
namespace adoption must establish bounded, restartable census progress and honest
policy limits without concealing the problem by lowering file capacity or raising
the existing resource budget.

The frozen fixed-map successor passes 25 standalone native cases, including real
last-Weak-allocation retirement. It remains unapplied. Two inode banks and two
live-owner banks are preallocated after admission, and partial candidates reset
before lock release on error or unwind. Pinned table geometry and requested
allocations establish a 1,331,916,340-byte metadata-owner charge; they do not prove
whole-server RSS or a usable 2 GiB configuration. The inherited policy mismatch
is reproduced separately with N=8: all seven managed file creations succeed, but
reconciliation fails its census work limit and retains the prior charge/entries.
That diagnostic intentionally exits with failure. Required separate file,
subdirectory and per-step limits are being implemented with retained resumable
census custody; the original numeric file capacity is preserved.

The page-list/cursor append verifies all 2,158 prior entries and adds 506, for
2,664 verified raw entries. Seven selected native binaries remain under target
with exact omission hashes; 416 external dependency/toolchain inventory entries
are preserved without rereading those external bytes. Root independently verified
the complete resulting archive. Later terminal attempts append new receipts
without changing any existing evidence.

The subsequent static-frame append preserves those entries and adds 94, for
2,758 verified entries. The exact attempt-128 binary remains
`631110f244e868c72e9966ec5af1df0d484b63bb8c26ffcde3d8c00a730ec098`.
Its separated outer/expiry/adapter frames total 422,464 bytes. Probe construction
has 86,144 bytes across four named helper frames; it does not reconstruct the
32-slot array during RPC sends. These are selected static frame compositions,
not whole-thread bounds. Attempt 129 separately verifies that exact binary before
and after running the original fourteen-case lifecycle target.
The terminal append for attempts 129–131 preserves every earlier archive entry
and adds sixteen, bringing the verified raw manifest to 2,774 entries. Their
runtime failures remain preserved alongside the successful lint and format checks.
The fixed-bank append preserves all 2,774 entries and adds 417, for 3,191 verified
raw entries, including terminal attempt 134. Five selected native binaries remain
under target with exact omission hashes; external dependency inventories are
preserved without rereading external bytes. The lifecycle/reclamation append
preserves all 3,191 entries and adds 154, for **3,345 verified raw entries**. It
includes terminal attempts 135–141, both failed attempts, the exact applied
corrections, selected static frame evidence and canonical reclamation reviews.
A second complete verification adds nothing. The raw manifest SHA-256 is
`6878c076c688dcb6db6e2ede0fef5fc7c3b257944e20eb3b32bbbf532c1d95c4`.
The canonical/census append then preserves all 3,345 entries and adds634, for
**3,979 verified raw entries**. It includes terminal142–147, all failed bytes,
compile/public fixture corrections, bounded allocation purge and reviews, and the
frozen census candidate/native evidence. A second complete verification adds
nothing. Its raw manifest SHA-256 is
`e0d48fe552dc7cae13be01b81501cf83306381c995c94321006ac72f508b9646`.
Four local native binaries (8,522,256 bytes) remain omitted with exact hashes;
416 supplied external binary fingerprints are preserved without rereading their
paths. The later148 run and unfinished candidates were excluded from that append.
The allocator append preserves all 3,979 entries and adds 62, for **4,041 verified
raw entries**. It contains terminal 148–151, both applied allocator packages,
their reviews and the source-pinned protected-maintenance design. A second full
verification adds nothing. Its raw manifest SHA-256 is
`14a442c9a9e80e31d3e8bbb9cc4338537f83805df18902720d2abe99a309a997`.
This append copies no native binaries or external dependency bytes. The design
is explicitly unimplemented; unfinished namespace and opening successors remain
outside this append.

The opening/namespace append preserves all 4,041 entries and adds 900, for
**4,941 verified raw entries**. It includes terminal 152–161, failures 153/154,
the two vendor lint corrections, retained opening revisions and reviews,
canonical allocator-key packages/review, and the unapplied managed namespace
packages with their failed and successful native evidence. Six local native
binaries totaling 13,493,328 bytes are omitted with exact hashes; 416 external
binary inventory entries remain fingerprints only. A second complete verification
adds nothing. The raw manifest SHA-256 is
`03010867d2f05775287ece46fbc3688ec8f231f0a429f853fdf53e81461616fe`.
The initial archive-generator failure selected a package directory in a run-file
glob; it wrote no archive entries. Its script and diagnostic are preserved with
the corrected generator. Unfinished storage census, aggregate/session adoption
and payload-validation candidates are excluded.

The allocator payload append preserves all 4,941 entries and adds 39, for
**4,980 verified raw entries**. It includes the frozen payload package, root
review, exact application receipt and terminal runs 162–164. A second complete
verification adds nothing. No native binary or external dependency bytes are
copied. The raw manifest SHA-256 is
`2470453a84a8b6f20efeef67eb750c60e3a1cd321f8df7ebd5036db0bb5aa827`.
The unfinished storage census, backup-session admission and dependency provenance
successors remain outside this append.

The provenance append preserves all 4,980 entries and adds 180, for **5,160
verified raw entries**. It includes the frozen provenance/policy proposal,
preparation and negative-check results, root adoption review, prior drift reports
and terminal 165. Target source/verification scratch copies and unfinished census
or namespace successors are excluded. No native or external dependency bytes are
copied. A second full verification adds nothing. The raw manifest SHA-256 is
`c5920b77dfc114a8047329ca47b3d47829a1d1dc6e355663acd9fd0816f03c68`.

The census/session append preserves all 5,160 entries and adds 1,229, for
**6,389 verified raw entries**. Its eleven frozen packages include original and
corrected storage-census candidates, backup namespace/session candidates, their
scoped independent/root reviews and the source-pinned canonical PageNumber audit.
Six completed native attempts retain their terminal/drain evidence: original
census 8-pass then 4-pass/2-fail, the stale-executable qualification failure,
fresh-candidate census/provider 33-pass, namespace compile failure, namespace
65-pass and corrected claim-path 67-pass. Preparation, launcher and test-name
parser failures remain alongside their distinct successors. The successful
namespace harness excludes three authenticated GC methods and five device tests;
full workspace and production integration are not inferred from it.

The append verifies 1,233 selected input files. Eight native files totaling
355,202,784 bytes are hashed and omitted; 416 supplied external inventory
fingerprints are preserved without opening their referenced paths. Cargo
assemblies, dependency-cache directories and unfinished combined/custody/decoder
successors are excluded. The append receipt is
`storage-census-sessions-append-receipts/566c45aee7bec710011f.json`; the raw manifest
SHA-256 is `0474a63b10ff4129af22e13a5d61e77008373cc419bd6dabd7f3656f30c5e529`.

The next append freezes the original and five revised combined storage/namespace
packages, their original failure and success transcripts, four file-custody
candidates, and scoped independent reviews. It preserves all 6,389 prior entries
and adds 2,804, for **9,193 verified raw entries**. The 2,808 selected inputs
match their pinned hashes before and after copying. Eight local native executable
files totaling 176,603,688 bytes are hashed but omitted; Cargo assemblies and
caches are excluded. The append receipt is
`storage-composition-append-receipts/772829aaa6b43c0697cd.json`, and the new
raw-manifest SHA-256 is
`dd1b5e7e971479dedd916142f8ec832130b9548559525247fefa3b2daf26f6ff`.
The second complete verification added zero entries. These candidate receipts
do not establish production integration or release qualification.

Attempts 114–117 preserve unchanged inventoried source and actual process-group
drain. Their outer runners sent no signals and did not time out. Attempt 117's
test process itself aborted on stack overflow; its empty runner-signals list is
not evidence of a normal child exit. Elapsed times are 107.215, 96.164, 68.889 and
60.315 seconds. These test workloads ran sequentially within this task.

Attempt 114 passes all three new borrowed-spool cases within the full enabled
store cohort. Actual final sync precedes injected uncertain return/panic; the
original cause moves once into the real retained Database observation while the
same spool, descriptor and charge remain. The allocation test pauses actual
key/plaintext/ciphertext deallocation separately and proves competing disk growth
cannot reuse credit until backing retirement, with zero allocations on successful
first/repeated close. Production NodeDatabase and scratch Backend migration are
still open. Attempt 115 passes both actual serving-expiry cases and the exact
Store/Write negative classifier after corrected final cleanup.

Attempt 116's signer-history read passes. The stopped-epoch case fails earlier
at `issuer_tests.rs:284`, during stop verification after the fixture clock reaches
2000: the actual quorum path reports forwarding to no current leader. The later
mutation never executes, so this run does not establish its prior generic route
failure's cause. A prepared bounded-resolution candidate remains unapplied and
conditional on further evidence. This compilation also exposes an invalid
`test-utils` cfg on the new authority diagnostic; that crate supports test cfg
only; the applied successor uses `cfg(test)`. Attempt 117 records a native stack
overflow; attempt 120 and the static frame evidence above distinguish what the
diagnostic did and did not establish. Neither original failure is waived.

Attempts 107–113 all record unchanged inventoried workspace/vendor Rust and
manifests, actual process-group drain, and no outer timeout or termination
signals. Their elapsed times are 39.298, 683.523, 898.231, 278.537, 324.879,
1.728 and 210.517 seconds. Concurrent compilation, Cargo locks and an unrelated
host build were observed; these are development checks, not isolated performance
measurements. The archive verifies 1,418 immutable raw entries at this checkpoint.

Attempt 107 passes all eight retained transaction cases, all five actual retained
database-close cases, the six-method original-I/O matrix, and bounded LRU queue
tests. Returned shutdown and backend-close errors remain distinct; uncertainty
retains the actual database and file lock. Production NodeDatabase/transaction
adoption, resident workspace bounds and borrowed scratch-backend closure remain
open at this checkpoint. This vendor run uses its default feature set.

Attempt 108 passes all 17 new snapshot-work ownership tests, including canceled
waiters, original panic/output custody, executor reentry and actual allocation
retirement. Its only enabled failure is the backup serving-expiry test's ordinary
cleanup path: actual shutdown is Complete with the original expired-access
Store/Write errors from the core and state-machine worker. The fixture still
expects a clean result there. The prior 512-by-256 restore deadline failure remains
excluded and required; the 100,000-row permanent-history case remains ignored.
The snapshot primitive still lacks production adapters, preparation fencing,
shutdown integration and a complete admitted workspace bound.

Attempt 109 passes the materialization/restart and precise replication-close
cases, but the stopped-epoch mutation again returns UnknownOutcome. Its generic
route diagnostic alone does not distinguish leader/term changes from a Raft
running-state failure. A signer-history read also observes Unavailable after an
expired new effect. Attempt 113's journal/ambiguous-control-commit case passes;
its expired-completion case times out in the original ten-second leader helper.
The exact call site and three replicas' metrics were not captured in that run.
These failures remain preserved; a passing successor cannot explain an earlier
failure without its own causal evidence.

The next pending source adds complete current Raft metrics to test diagnostics,
uses the current leader for the exact historical signer read, and routes the
successful controlled serving-expiry path through typed expired-owner cleanup.
That cleanup requires Complete, original shared issue identity, exact Store/Write
causes and absence of unrelated task failures. It also adds borrowed spool-close
custody and three actual-resource tests; production backend adoption remains
separate. `114-corrections-applied.json` and the spool module-order receipt bind
these applications. Their runtime results are not claimed here.

Attempt 103 completes in 816.445 seconds: history passes 5/5, lifecycle 12/14,
schema activation 12 selected cases and staged transactions 11/11. Both real
crash tests, exact snapshot quota comparisons and retained-generation reopen
now pass in their applicable targets. Two lifecycle failures remain: a later
fresh phase-read observes unavailable quorum and a completion-request preparation
observes UnknownOutcome. No retries, outcome substitutions or deadline changes
have been introduced to hide them. The unchanged schema restore's prior 60-second
failure remains excluded and required pending bounded staging implementation.

Attempt 105 completes in 337.686 seconds with both actual materialization cases
and both exact close classifiers passing. The stopped-epoch mutation still fails;
its original-cause diagnostic identifies a changed proposal leader. A reviewed
fixture successor captures its original authorization context, selects the current
leader with the existing bounded helper and submits the mutation once, retaining
the original Conflict assertion. Both 103 and 105 preserve unchanged inventoried
source, actual process-group drain and no outer timeout or termination signals.

Attempts 102, 104 and 106 preserve unchanged inventoried workspace/vendor Rust and
manifests, actual process-group drain and no timeout or termination signals.
Their elapsed times are 17.575, 172.459 and 136.595 seconds; compilation overlapped
and waited on Cargo locks, so these are development results, not isolated
performance measurements. Attempt 102 exposes two fixture reopen calls using
4096-byte defaults against their actual 512-byte databases and a production
backend path that replaces the original I/O error with OwnerFailed. All three
failures remain preserved; the original diagnostic must survive while later
access stays fenced. The retained terminal API has not been adopted by production
callers and does not establish transaction-memory or database-close guarantees.

Attempt 104 includes the real canonical completion-history record regression:
kind 23 contributes to resident materialization and snapshot quota, and kind 21
terminal rows still count toward that quota. The renamed fixture helper
authenticates complete framing and applies this existing accounting contract.
Attempt 106 exercises all three new opaque lease tests through the actual store
allocator. Pausing System.dealloc prevents byte/slot reuse, token-destructor
unwind retains one-time retirement, and the provider's existing allocation
allowance/layout remain unchanged. Native debug/optimized extracted tests and
the failing counterfactual are separately preserved. Their eleven development
executables remain under target; this documentation archive retains exact source,
receipts and hashes, with explicit binary omissions recorded in
`terminal-successors-probe-binary-omissions.json`.

`102-corrections-applied.json` and `102-reviewed-successors-applied.json` bind the
reviewed source applications to exact before/after hashes. They include explicit
recovery-topology CAS/leader selection, audit fixture accounting, stopped offline
backup mutation, retained-generation release, canonical snapshot accounting,
opaque installed leases and narrowly typed replication-close assertions.
Snapshot work revision 5 was applied after attempts 102–106 drained, together
with original-I/O preservation, bounded cache invalidation and the stopped-epoch
fixture correction; `107-prerequisites-applied.json` records exact hashes.
The new source remains uncompiled at this application checkpoint. Its transfer
section runs pending executor callbacks before removing Output and performs no
callback after taking it. This corrects the preserved revision-4 panic/custody
finding; runtime tests and production integration remain required.

Attempts 96–101 preserve unchanged inventoried Rust/manifests, actual
process-group drain, no timeout and no termination signals. Attempt 96 completes
in 176.234 seconds: three previously failing cases pass in this smaller cohort,
but this does not explain the preceding full-cohort availability failures. The
stopped-epoch case progresses to a later assertion and observes UnknownOutcome
instead of Conflict. Attempt 97 completes in 372.603 seconds: two original
materialization/recovery cases and the negative classifier pass, while activation
projection returns UnknownOutcome and another close retains the exact sealed
Store/Write error from a replication stream, rather than the state-machine
worker. Further original-cause diagnostics and exact child checks are required.

Attempt 98 completes in 498.538 seconds. Contracts pass 23/23, guarded staging
passes 11/11, schema activation passes 11/13 and staged transactions pass 5/11.
Both real crash/recovery tests now pass. The schema target retains its original
60-second restore timeout and retained-generation reopen failure. The new helper
incorrectly excluded permanent terminal rows from snapshot quota comparisons;
six staged cases expose that error. This correction attempt remains failed.
Two native observations of the actual failing schema restore capture independent
snapshot validation creating an encrypted scratch index and then performing
individual durable index inserts. These samples establish real work, not an
isolated performance measurement or the complete distribution of timeout cost.
The unchanged restore case remains required and should not be retried again
until its implementation changes. Attempts 100 and 101 take 50.081 and 1.810
seconds respectively; the existing three vendored rmcp warnings remain visible.

Attempt 88 completes in 1,186.851 seconds with unchanged inventoried Rust/manifests,
actual process-group drain and no timeout or termination signals. Its 22 failures
remain preserved: two contract fixtures, two guarded staging fixtures, three
history cases, five lifecycle cases, eight schema activation cases and two staged
transaction cases. Review identified obsolete resident/full-stream comparisons,
harness files inside the installed census, stale control topology/audit setup and
retained generation ownership. The schema restore's original 60-second backup
verification deadline expires and remains unresolved. Its native stack sample
captures the subsequent 100,001-entry schema fixture's live encoding work; it
does not identify the phase of the preceding restore timeout.

After attempt 88 drained, six reviewed correction packages were applied with
exact before/after hashes in `96-corrections-applied.json`. They retain original
limits, workloads and deadlines, authenticate complete snapshot framing before
comparing resident bytes, inspect actual permanent terminal point rows, and keep
crash harness markers outside the private installation. Authority corrections
preserve immediate production fencing and inspect exact original typed shutdown
failures; temporary test-only diagnostics expose underlying unavailable causes.
Attempt 99 validates the cancellation backing retirement change with 34 passes
in 68.984 seconds, unchanged inventoried source and actual process-group drain,
without timeout or signals. Other correction successors remain separate runs.

`assembly-python-02` passes **105 tests** through complete Python tooling
discovery in 12.018 seconds of owned process time. The inventoried scripts,
assembly documentation and workflow remain unchanged; the original process group
drains and an independent census finds no remaining member. The applied
`repeatable-assembly-v3` package adds mandatory native input declarations, two
owned assembly invocations and semantic verification. Its first reviewed
documentation invocation was corrected to execute from the actual frozen source.
The domain registry remains empty. Native probes, a complete candidate pair,
platform dependency declarations and the full native acceptance path are unrun;
synthetic-process tests do not qualify them.

Attempt 87 completes in 780.653 seconds with unchanged inventoried Rust/manifests,
actual process-group drain and no timeout or termination signals. All 12 backup
checkpoint tests pass, alongside two admission, three clock, one response-release
and ten retirement cases. A native stack sample during the long historical backup
case observes actual encrypted point-row redb commit/write/sync work; the case
subsequently passes. Its original sample and observation receipt are retained.
This is scoped integration validation, not an isolated performance measurement
or final release qualification. Attempt 88 covers the other integration targets
separately and fails as recorded above.

Attempt 94 completes in 638.143 seconds with unchanged inventoried Rust/manifests,
actual process-group drain, no timeout and no termination signal. It passes all
five previously failing fixtures, both maintenance guards, and the construction,
snapshot and journal foreign-core checks. The 512-by-256 restore case remains
explicitly excluded and required; the 100,000-row permanent capacity test remains
ignored and unrun. Expected injected panic diagnostics in the uncaptured log
belong to passing ownership tests, not hidden failures. Integration targets are
separate attempts 87 and 88 and are not covered by this library result.

Attempts 91, 92, 93 and 95 preserve unchanged inventoried Rust/manifests,
actual process-group drain and no timeout or termination signal. Their elapsed
times are respectively 815.381, 122.372, 144.801 and 1.866 seconds. Attempt 91
validates the explicit response-fence fix but fails eight other authority cases.
Four expose `Unavailable` during signer/restart/stop operations; three expose
original OpenRaft storage errors during target close, and one times out waiting
for maintained membership/suspension. Their original panic locations and errors
are retained. No broader authority pass is claimed. Attempt 92 retains three
vendored rmcp dependency warnings; the strict workspace command exits zero.

The separately named `assembly-metadata-python-01` run passes **50 tests** across
metadata custody, release-gate ownership, package provenance and acceptance
counterexamples. Its actual process group drains, no timeout/signals occur, and
all eight inventoried Python source/test files remain unchanged. The applied
five-file `assembly-metadata-custody` patch owns Cargo metadata dispatch and
binds its original executable, frozen source, separate outputs and actual drain
before parsing. These synthetic-process tests are a packaging prerequisite;
they do not execute native Cargo/two complete assemblies or register a final
acceptance domain. Repeatable assembly remains open.

Attempts 84, 85, 86, 89 and 90 all preserve unchanged inventoried Rust/manifests
and actual process-group drain. Attempt 84 timed out, sent SIGTERM and recorded
exit -15; its partial log is not a completed suite. The other four recorded no
timeout or termination signal. Attempts overlap as recorded by their runners and
the explicit observation receipts; these are development checks, not isolated
host resource measurements. Attempt 90 binds its original binary SHA-256 and
does not erase or explain the coverage failure in attempt 84.

Attempt 89 passes the previously unselected construction case and the new
snapshot and journal exact-core regressions. Two new maintenance tests failed
before exercising their guards because their policies lacked an administrator.
The other failures are exact fixture mismatches: bootstrap and audit shutdown
omitted 29,350,630 bytes of retained installed metadata, and the archive restart
assertion enumerated the obsolete fixture directory. Corrections preserve the
original workloads, quotas, resource deltas, object counts and deadlines. The
512-by-256 restore case remains separately failed and required; the ignored
permanent-capacity case remains unrun.

The queued-activation fixture retained a response fence through shutdown because
its wildcard match did not consume that field. The successor explicitly drops
the fence before closing. A standalone language probe and native stall sample
support that diagnosis; only a completed successor can validate the correction.
The census correction removes the needless borrow reported by attempt 85.

After both full suites drained, a separate storage correction keeps each file's
handle and metadata allowance until both descriptors, path/native-mutex backing,
and its exact weak registration allocation have retired. It also keeps abandoned
preparation resources under serialization. Five new regressions cover concurrent
final release, reclaim and abandoned preparation/publication; the original
zero-allocation assertions and operating caps remain unchanged. Application
receipts bind these changes separately from the failed predecessors. Attempt 93
passes all 220 enabled store cases and attempt 94 passes the 215 selected engine
library cases. Engine integrations remain in progress, and authority's eight
failures remain unresolved.

Attempts 77–83 use base `600c0ca2b2c4c22b89b44ccd932eca02272c70f1`
with the separately recorded pending mandatory memory stack. All seven terminal
receipts record unchanged inventoried workspace/vendor Rust and manifests,
actual process-group drain, no timeout and no termination signals. This inventory
does not cover all documentation or qualify binaries/native resource limits.
Attempt 81's filename-based `database_construction_tests` selector matches no
test module; its 50 actual tests do not include the new construction regression.
That case remains required in the broader successor.
Attempt 82 adds all three shared-cluster memory cases to the prior 46-case
server cohort. Its macOS test-binary link reports a large unwind-section warning;
the test process completes normally. The warning remains in the original log.
Attempt 83 preserves the original 72 selected library and 18 integration cases;
the separately failed custody-capacity workload remains excluded and required.

After attempt 83 drained, review corrections added early exact-core checks to
the public snapshot paths, target-journal create/reopen and audit-maintenance
installation. `83-core-guards-applied.json` binds both reviewed patches and six
resulting source files. The four new regressions check foreign equal-policy
cores, unchanged charges/physical state, missing maintenance storage and healthy
same-core operation. This application record precedes their validation; it does
not extend the scope of attempts 77–83.

`installed-memory-combined.patch` has SHA-256
`be2dad44d5a0c261a6c36023af37780c91effa65723f7bd3e0896de0cc2dbddb`.
Its manifest binds all 13 ordered component patches and 178 affected files;
`installed-memory-applied.json` records application before validation. The
unchanged preparation manifests retain their original uncompiled status.
`77-corrections-applied.json` binds the subsequent corrections separately:
missing caller arguments, one unused reexport, stable scratch fixture reuse,
actual retirement snapshot owners and a duplicate publication-state lock. The
lock correction keeps one guard across preparation and physical validation.
The superseded combined draft and fixed-memory fixture correction remain
preserved; their preparation records are not passing test evidence.

The stack requires the installed core before production disk creation, retains
real persistent/scratch/device metadata leases, rejects foreign-core composition
before mutation and replaces all supported constructors directly. Installed
scratch registries retain their memory charges for their actual lifetime.
Fixture planning preserves original payload, operation and RSS limits; it adds
only the newly required metadata and lease fees. New installation policy is
explicit, with no compatibility default or production contention retry.
The full store successor passes the new metadata/identity/publication cases.
The new backend fixture retains an actual admitted physical owner even when its
synthetic backend has no pathname; the separate pure-redb fault fixture keeps
its distinct explicit purpose. Directory accounting, retained filesystem/snapshot
children, startup resource adapters, full callers and native qualification remain
open. Earlier failures and ignored external/capacity cases are not waived.

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
