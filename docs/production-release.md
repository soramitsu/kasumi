# First production release

This is the active implementation and acceptance ledger for the approved first
release. An unchecked gate is unfinished. The September 5 baseline and later
branch evidence remain historical records; they do not certify this integration.

The explicit release goal remains active. Per the latest user instruction, all
implementation, edits and builds use only `/Users/mtakemiya/dev/kasumi` on
`master`. This supersedes the original external-worktree direction, including
that stale location in the active goal text. Existing master changes and prior
release work are preserved through integration. First-release API removal, permanent
point-addressed receipts, explicit physical/catalog creation, retained startup and
request owners, and canonical planned recovery are integrated in source. Persistent
disk admission, native reservations, complete HA/local lifecycle, and final live,
capacity, platform, endurance and artifact gates remain open.

The 2026-09-24 native KV direction replaces the earlier redb-backed G02
target; [its active criteria](native-kv-goal.md) forbid old-format migration
and fallback. The current native crate passes 34 unit and six crash/recovery
integration tests plus strict crate Clippy. Its close-custody, failed-owner
read, named-file directory sync, and same-host reopen gaps have focused fixes
and regressions; full downstream reruns remain in progress. The G01
current-byte bootstrap-manifest engine and server fingerprint cases each
pass **1/1** after an in-progress native KV read-bound mismatch was corrected.
Full-source suites are pending. The latest seven-case G09 Control lifecycle
run passes **3/7**; four cases fail around cached-route reads or negative
outcome responses under leadership changes. Positive signed first
membership and historical status remain absent. Bundled Python 3.12 discovery
passes **191/191** while the native KV source is still changing. These are
development checkpoints; no G01–G14 goal or final release gate is closed.

Latest master-only development evidence is recorded in the
[integration bundle](evidence/installed-disk-integration-20260923/README.md).
The later exact-byte storage, Raft and authority cutovers pass the full serial
Raft library **81/81** and authority library **66/66** on their recorded source
checkpoints. The applied node key-catalog, host-keyring, live signer trust,
verifier installation and checkpoint binding-catalog cutovers pass their
focused cases. The later full serial store library passes **408/408 runnable
cases**, with two ignored. All-target/all-feature workspace checking, strict
Clippy and formatting pass on the combined G01/G09 source. The later full
engine library has one initial-leader fixture timeout among 273 runnable
cases; that named test passes alone, so a clean later-source full engine pass
remains pending.
The installed protected three-node recovery-status test reads a real committed
`Prepare` record, but the full recovery still fails before terminal status.
G01 also retains target lifecycle, checkpoint point/ordinal rows and bootstrap
manifest readers. The G09 Control TargetCommand marker prerequisite is applied
with passing focused marker and 13-case receiver tests; its six-case synthetic
Control fixture is being repaired. The mandatory receiver envelope, historical
status and first committed Raft-membership proof remain absent. Every G01–G14
gate remains open.
The latest applied G01 snapshot readers pass 77/77 serial Raft cases with one
historically long custody-capacity case filtered. Bounded encrypted scratch
batching now passes that large case 1/1 in 403.88 seconds, including
snapshot/reopen identity; the uninstrumented full Raft library suite then
passes **78/78**. A
test-only native administrative DTO regression, the local JWT
missing-claim case, and the five-case same-process standalone staging fixture
pass. The marker-codec source passes 398 runnable store library tests with two
ignored. A later G06 archive-reference validation passes 25 types tests and
nine affected store archive tests; its wider final-source suites remain open.
The later G04 cursor-anchor client and protected-TLS server cases pass 1/1
each. G10's protected recovery-status TLS case passes 1/1, but its positive
replicated observation remains unqualified. The G11 functional-evidence
export/transport tooling passes its 149-test Python checkpoint. Native
workflow tar and independent producer-record uploads, exact Cargo executable
and compiled-feature replay, and the local collector are applied. After
correcting the synthetic package fixture and a feature-inventory false-pass,
complete repository Python discovery passes **168/168** again on the later
G05/G09 source under Python 3.12.14. A reviewed owned-assembly raw tar,
producer and failure-snapshot transport prerequisite is now applied, with
**15/15** focused tests and workflow syntax checks passing. Complete Python
discovery passes **183/183** on that source. A reviewed post-download
projection then passes **8/8** focused and **191/191** complete Python tests
on the applied source, but its result is always `unqualified`: physical-host
and permanent attempt-registry evidence are still missing. Native
upload/download and semantic adapters remain open. A reviewed G10 assertion
now checks the actual protected HTTPS membership epoch and all 129 complete,
fresh groups; its focused installed rerun passes **1/1**. The serial G07 authority library rerun failed **3 of 64** cases:
two fixture reopen waits incorrectly included a learner or removed voter, and
target shutdown produced an exact sealed-serving error absent from its strict
test classifier. The three cases and classifier regression pass focused, and
the corrected full serial library passes **64/64 in 766.75 seconds** before
the later G09 journal-format edit. The journal-format source's 13-case
materialization rerun failed one strict shutdown classifier; its corrected
named case passes focused and the complete serial authority library passes
**65/65** on the format-2 source. The full
engine library on that source failed one backup credential fixture among 267
runnable cases. The corrected credential timing and strict serving-expiry
classifier then pass their focused cases; the complete serial engine library
passes **272/272 runnable cases**, with one ignored, on the later format-2
target-journal source. The dormant G05 exact
S3 destination index and G09 Start-owner format pass **5/5** and **2/2** focused
cases respectively, but neither is wired to its production writer. Exact logs and
hashes are preserved in the linked integration bundle. None of these
development results closes G01–G14 or supplies final-source native
acceptance. The paragraphs below preserve earlier source checkpoints.

The earlier dirty combined source had passing focused canonical replay,
authenticated HTTP/2 Raft transport, production-only server check, and a
partial admitted redb direct-header slice (233 serial vendor library tests and
strict vendor Clippy after a narrow lint correction). A reviewed semantic
recovery digest now binds shared endpoints, parsed certificate pins and exact
CA trust bytes while allowing Control-local credentials; its native mTLS test
passes. The uninstrumented installed three-node runtime advances beyond the
former `Prepare` stall but still fails at its original recovery deadline in
`Materialize`. A bounded test-only probe traced the repeated unresolved
outcome to a generation file path outside the installed NodeDisk accounting
root: the runtime joined the file name to a canonicalized root while NodeDisk
binds the configured root spelling. The path correction preserves the
configured spelling after checking its canonical identity. The installed
three-node rerun verified all three voter materializations, then failed at
`Initialize`: a prior target initialization identity was durably bound but
Control did not resolve its exact outcome before issuing a fresh phase.
The registered redb Ready proof passes 20 focused store opening cases; its
retained-reader prerequisite passes 215 vendored redb library tests. The
retained-reader census prerequisite is applied and its full serial store
library suite passes (388 cases, two ignored); later panic and output-credit
tests pass the 24-case opening module. A dormant fixed catalog input-buffer
plan now passes three focused tests and the full serial store suite (393 cases,
two ignored), with strict types/store Clippy. Redb cache pages and transaction
terminal allocations still lack complete admission, so no production writer
cutover is claimed. The exact backup namespace binding,
immutable Control binding value and historical-key resolver are applied as
dormant prerequisites. The types library passes 24 cases, and strict all-target
types/store Clippy passes. The focused StopLocal shutdown suite passes seven cases after replacing
path-only absence with managed NodeDisk observation. A
combined committed MCP mutation and credential-renewal response-fence test
passes. Neither result completes G02 or G07. The full serial engine library
run had 254 passes, one ignored and one serving-expiry quorum timeout; a
fixture-only election correction passes three focused repeats.
The full server/workspace cohort has not passed on this source; earlier
sequential attempts, fixture failures and stack-overflow aborts remain in the
linked evidence. Redb transaction-memory admission and production caller
adoption, durable backup namespace binding, recovery exact outcomes and
post-marker liveness, serving-route peer membership admission, remaining
readiness scale/native acceptance, final native runs and release artifacts all
remain open.
The installed 129-group TLS fixture passes with an explicit 2 GiB work total
and 129 snapshot-startup slots: all groups are healthy under complete fresh
coverage, membership-change fencing works, and a failed group beyond the
128-entry detail page revokes readiness. The protected archive-outage case also
passes. Remaining G10 observations and final-source qualification are open.
Every G01–G14 goal remains open; these development results are not release
acceptance.
The reviewed G11 dependency runner revision 2 is applied without registering
an acceptance adapter; its focused Python tests pass 10/10 and full repository
Python discovery passes 129/129. The later reviewed redb provenance rebind
passes the official seven-package source and locked-Cargo checker, and a
Git-free synthetic cargo-audit diagnostic detects its injected redb advisory.
Native owned scanning with authenticated current advisory data, runner
provenance and final acceptance remain open.

The earlier combined-checkout native attempt is
[preserved as failed and source-drift-invalidated](evidence/installed-disk-actual-master-20260923/README.md).
The failed-opening/scratch-close recovery revision 8 and redb provenance passed
the frozen native-09 cohort: 46 of 46 phases, including the complete store,
vendor and official dependency checks, with unchanged inventoried source and
drained process groups. All 56 proposed files were then applied and verified on
`master`. This qualifies that exact recovery slice on macOS ARM64; it does not
qualify the subsequent combined source. The eight-file service/G07 prerequisite,
five-file G10 physical-capacity observation and six-file G07 correction were also
applied with exact readback. The first integrated workspace check found two
server compile errors in the serving runtime and owned management gate. The
three-file repair is now applied; a pinned Rust 1.97.1 all-target/all-feature
workspace check and strict workspace Clippy pass on that combined checkpoint.
Focused G07 custody, deadline, gate and enrollment tests pass, after a
separate test-frame repair preserved the first enrollment SIGABRT. The G07 API
audit-failure fixture passes its exact all-features case; a managed-
directory local-recovery repair and one-file fixture correction now pass three
focused cases on the normal test harness stack. The earlier fixture failures
remain preserved. Two unfiltered all-features server attempts are failed:
the first stalled after local-recovery fixture failures, and the second exposed
same-process local-recovery/RPC failures before an audit TLS test stack
overflow. A two-test reproduction traced one failure to a cancelled startup
task retained in the process-wide local-operator registry. Explicit test
teardown now passes the whole local-recovery module **10/10 in one process**
on the normal stack; the complete server cohort remains pending. Test-only
audit TLS and runtime-lifecycle fixture stack repairs pass their named cases
on the normal stack. The authority RPC retirement fixture now accounts for its
deliberate post-activation delay and passes 1/1. Its first same-process pair
exposed an intermittent lifecycle issuer-quorum readiness timeout; the revised
test still requires a real barrier, and the corrected pair passes **2/2 in one
process**. A sequential unfiltered diagnostic then passed all local-recovery
cases and the authority RPC case, but failed on a lifecycle recovery
`UNKNOWN_OUTCOME` and another runtime-lifecycle test stack overflow. The
test-only stack repair and exact-status uncertainty fixture correction pass
their focused cases; the authority→lifecycle pair passes 2/2. A complete
same-process server cohort remains required. The six-file G11 owned assembly launcher and verifier
bridge, its one-file test-path correction and two-file selected-primary adapter
slice, a four-file owned dependency-review runner, and G02's two-file
non-consuming registered-opening close are applied
with exact readback. G02's isolated overlay passes 16 focused opening and 368
runnable store cases with strict store Clippy; these are prerequisite results,
not validation of the latest combined source.
A fresh complete combined-source run remains pending. The
[current integration evidence](evidence/installed-disk-integration-20260923/README.md)
records the exact scopes and open gates. All release goals remain open.

The [approved completion plan](first-release-plan.md) and
[fourteen workstream goals](first-release-goals.md) define the remaining work
and its dependency order. Backward compatibility is forbidden for this first
release. No goal closes without implementation, final-source validation and
usable release artifacts or operating documentation.

The [acceptance manifest verifier](release-acceptance-manifest.md) now validates
the fixed native/domain/artifact roster, complete workload samples, process
ownership and source identities. It deliberately rejects every domain whose
semantic adapter remains unimplemented. The applied G11 revision 3 launcher
tracks its outer runner and nested process groups. The selected-primary adapter
slice binds the assembly's retained functional receipt to the manifest-selected
native primary; its [exact application receipt](evidence/installed-disk-integration-20260923/README.md)
has SHA256 `1b20595a8452a6c0afc3cb6bf869b51aa590b34f9ce3bffd85c4fa9c37556ddd`.
Full repository Python discovery passes **122/122** on the applied source (log
`target/installed-disk-validation/g11-dependency-review-runner-application/full-python-discovery.log`).
The adapter registry remains empty. Complete semantic adapters and required
native platform runs remain open, so G11 and final release acceptance remain
open. Physical host observations in [Linux acceptance](linux-acceptance.md) are
not resource reservations.

## Current development diagnostics on master

The latest pending mandatory-memory stack, based on `600c0ca`, requires the
installed core and runtime facade before production disk opening. It retains
actual persistent/scratch/device metadata leases and rejects foreign memory
owners before storage mutation or Database startup. Superseded constructors and
their supported callers were replaced together without compatibility defaults.
Attempt 77 preserves the compile failures and exact correction patches;
78 passes all-target/all-feature workspace compilation and 79 passes formatting.
Attempt 80 passes the full store library with **215 passed, zero failed and two
ignored**. Attempt 81 passes **50** selected engine admission, startup, codec and
clock tests; its filename-based construction selector did not select the new
construction case, which remains required in the broader successor. Attempt 82
passes **49** server memory-sharing, readiness, credential and cleanup cases.
Attempt 83 passes **90** selected Raft library/integration cases, with the earlier
custody-capacity failure still explicitly excluded and required. All seven
receipts record unchanged inventoried source, drained process groups and no
signals/timeouts. The [raw evidence](evidence/installed-disk-main-20260920/README.md)
preserves the applied stack and previous failures. Directory accounting,
retained blocking-worker outcomes, production startup-resource adapters, full
caller/native qualification and all G01–G14 remain open. The following paragraphs
retain the preceding diagnostic history and its original scopes.

Subsequent review added early foreign-core rejection to snapshot work,
target-journal construction and audit-maintenance installation. Attempt 89 passes
the construction, snapshot and journal guards, but finishes with 210 passes and
five fixture failures; the separately failed large restore case remains excluded
and required. Attempt 84 times out during queued-activation shutdown after an
earlier coverage failure. The exact binary passes that coverage case alone in
attempt 90, leaving its cohort failure unexplained. Attempts 85 and 86 preserve
the census lint failure and invalid Cargo invocation. Corrections now include
explicit response-fence release, exact retained metadata assertions, valid
administrator fixtures, the actual archive directory, and complete file-owner
resource retirement before handle-credit reuse. Attempt 93 passes all **220**
enabled store tests; attempts 92 and 95 pass strict workspace Clippy and formatting.
Attempt 91 finishes with **53 passes and eight failures**: the queued-activation
hang is fixed, while signer/restart/stop availability, target-close diagnostics
and maintained membership remain unresolved. The separate packaging metadata
ownership change passes **50** Python tests; complete repeatable assembly and
its semantic adapter remain open. Attempt 94 passes **215** engine library tests,
including all five corrected fixtures; the prior large restore failure remains
excluded and required, and permanent-capacity testing remains unrun. Engine
integration attempt 87 passes all **28** selected cases, including the complete
12-case backup checkpoint target. Attempt 88 completes all remaining fourteen
integration targets with **72 passes and 22 failures**; exact fixture corrections
and unresolved restore/recovery causes remain under investigation. Attempt 99
passes **34** admission/core/startup tests after cancellation backing retirement.
The two-invocation assembly runner and mandatory native input contract are now
applied; complete Python discovery passes **105 tests**. Native assembly and its
acceptance adapter remain unqualified, with the registry disabled. None of these
results qualifies the release.

The next reviewed corrections directly replace the installed memory lease with
an opaque allocation-before-credit owner and correct snapshot quota comparisons.
Attempt 106 passes all **223** enabled store tests; attempt 104 passes **49**
admission/codec cases, including canonical completion-history accounting. The
new retained redb terminal prerequisite passes five tests and fails three in
attempt 102: two fixture page-size mismatches and an original I/O diagnostic lost
by the backend fence. Production terminal adoption, physical close, bounded
batching and both unchanged restore deadlines remain open. Snapshot-worker
revision 5 addresses the reviewed callback-panic output-custody defect and is
now applied but uncompiled. Attempt 103 passes **40** integration cases with two
lifecycle failures and the prior schema restore failure excluded and required.
Attempt 105 passes four targeted authority cases and reports a generic route
failure for the remaining stopped-epoch fixture. That branch also checks term
and core state, so its message alone does not prove a leader change. The next applied corrections
preserve original backend I/O objects, bound redb cache queue registrations and
pin that fixture's current leader before its one mutation. These changes do not
complete any release goal.

Attempt 107 passes all **120** vendor redb library tests, including original I/O
retention and borrowed database close with actual file-lock custody. Attempt 110
passes **223** store cases; 111 and 112 pass strict workspace lint and formatting.
Attempt 108 passes **232** engine cases, including all **17** snapshot ownership
tests, and fails the backup serving-expiry fixture's ordinary cleanup assertion.
Its prior large restore failure and ignored permanent-capacity case remain
required. Attempt 109 passes **61** authority cases and fails stopped-epoch
proposal resolution and a historical signer read. Attempt 113 passes one recovery
lifecycle case and fails another at the original ten-second leader-selection
deadline. Every process group drained with unchanged inventoried source, without
outer timeout or signals. Original failures and exact source inventories remain
in the evidence archive. Borrowed spool closure, precise expiry cleanup and
original Raft-state diagnostics are the next applied, unvalidated prerequisites;
production retained-close adoption and full resource bounds remain open.

The borrowed spool prerequisite now passes all three actual-resource cases in
attempt 114's complete **226-pass** store cohort. Attempt 115 passes all **three**
serving-expiry/cleanup successors. Attempt 116 passes the signer-history read but
fails stop verification earlier than the prior mutation failure; no current
leader is available at that read. Attempt 117 aborts its native test process on
stack overflow. Their owned process groups all drain with unchanged source;
the native abort remains distinct from the runner's no-signal observation.
Review rejected transaction disposal without a live database witness because it
could invoke an unobserved deferred backend close. The applied successor requires
the matching borrowed retained database through actual disposal and preserves
original terminal/rollback outcomes. Attempt 121 passes all **131** vendor tests,
including eleven retained transaction cases and eight new fixed-cache tests.
Attempt 122 also passes all **226** enabled store cases; two remain ignored.
Workspace formatting passes in 119, and the new lifecycle binary compiles in 123.
The cache now checks actual room after bounded eligible-page selection; original
I/O and rollback uncertainty remain distinct from capacity refusal. The checked
cache collection metadata is only one component of the unfinished memory proof.

Attempt 120 runs the exact overflowing binary under LLDB: the test passes, then
the debugger exits 1 because no stopped process remains for a backtrace. All
three descendant groups are absent in the terminal census; this is diagnostic
evidence, not a passing successor or a reproduced crash. Static disassembly shows
about 1.35 MB of recovery preparation poll stack directly enclosing another
312 KB expiry-resolution poll. An applied phase handoff returns the first frame
before polling the next while preserving actual owners, identities and original
deadlines. The new binary confirms outer-plus-expiry-and-adapter frames total
422,080 bytes, compared with 1,732,976 bytes for the old three named frames before
adapters. This is a static phase comparison, not a whole-thread bound. Attempt
124 completes all fourteen lifecycle cases: **12 pass and two fail**. The expired
completion case passes; the failures are a fresh bootstrap election that never
completes and a phase read sent to a healthy replica that has become a follower.
No stack overflow occurs. Exact stopped-epoch witness/error assertions are then
applied, and strict workspace Clippy passes in 118. These scoped results do not
close any release workstream.

Attempt 125 passes all six exact stop-drain observations, including the full
post-restart interval, then fails the final rejection with `UnknownOutcome`.
Its original diagnostic captures a healthy executing node changing term and role.
The applied fixture successor resolves only the same signed request and original
context, within one five-second caller budget, after observed route movement and
healthy-owner checks. It requires the exact stopped-epoch `Conflict`; no unresolved
result counts as success. Attempt 133 passes that original focused case, including
an actual term/role transition followed by exact rejection and successful drain.
It finishes in 85.802 seconds with unchanged source, no timeout and no signals.

Checked redb page-list shapes and explicit extraction close are now applied.
Attempt 126 preserves a compile failure caused by the copied key changing a
closure's call trait; the correction makes that binding mutable and disambiguates
a test panic macro. Attempt 132 passes all **134** vendor library cases, including
malformed-record atomicity and original extraction-close failure custody. Its
process drains with unchanged source and no timeout or signals. This does not
bound historical reclaim workspace or complete production retained-owner adoption.
Attempt 127 also passes all **226** enabled store cases; two remain ignored. Its
88.756-second run records unchanged source and actual process drain without signals
or timeout.
The lifecycle successor also carries a bounded vote-response diagnostic and reads
the original recovery phase from the current leader; attempt 128 compiles it in
34.582 seconds. Attempt 129 then runs the complete fourteen-case lifecycle target
against that exact unchanged binary: **12 pass and two fail**, with no stack
overflow. One first-dispatch read reaches a healthy cached node after it becomes
a follower; a later confirming-intent write in the other case reaches its original
deadline with `UnknownOutcome`. The latter has no captured child-stage evidence
and is not an established leadership failure or proof of an absent commit.
The 402.974-second run drains without outer timeout or runner signals. Its earlier
bootstrap failure does not recur, which is not proof of a cause-specific fix.
Election settings and original deadlines remain unchanged. Attempts 130 and 131
pass strict workspace Clippy and formatting, with unchanged source and actual
process drain; these checks do not resolve the runtime failures.
Attempt 134 completes all 63 authority library cases: **62 pass and one fails**.
After confirming every other voter, the failed activation-maintenance case tries
to publish a local journal using its earlier leader-bound proof. That proof's
release recheck receives a forwarding error and returns `UnknownOutcome`. The
770.377-second run records unchanged source and process drain, with no timeout or
runner signals. The applied local-confirmation fixture successor verifies the
same signed activation against the selected voter's persisted application before
projection. Attempts 140 and 141 pass both original cases using that helper, in
74.521 and 56.387 seconds, with unchanged source and actual process drain. The
failed broader authority gate remains preserved and requires later qualification.

Attempt 135 preserves a compile failure in the new lifecycle diagnostic's metrics
receiver lifetime; 136 compiles the correction. Attempt 137 then fails both focused
cases at their first reopen because the new route binding had left its predecessor
Arc alive. Explicitly dropping that stale alias preserves actual lock enforcement
and the original close/reopen assertions. Attempt 138 compiles it, and 139 passes
both original lifecycle cases in 112.434 seconds against an unchanged exact binary.
No deadline, election setting or file-lock retry is added. The original confirming
write timeout does not recur, which does not establish its cause.

The canonical format4/DATA400 reclamation successor is applied on master. It
directly rejects prior slot/savepoint versions and the obsolete system-history
table, removes its writer/decoder, and excludes current system frees only from the
prepared winning allocator until commit succeeds. Historical DATA selection owns
one fixed native-layout array; total COW, allocation-history and maintenance-at-cap
resource bounds remain open. Attempt 142 fails compilation before any test: the
internal dirty-marker change affected unrelated user-table methods, the adjacent
public statistics method was accidentally removed, and a test trait import is
missing. Attempt 143 passes all **142 vendor library tests** after restoring the
original user-table block, statistics/debug methods and required import. The
42.052-second run records unchanged source, actual process drain and no signals
or outer timeout. Public integration/fault gates and finite maintenance resource
bounds still require qualification. Attempt 144 passes all **148 vendor library
cases** after bounding allocation-history purge and removing the two obsolete
helpers. The run takes 42.612 seconds with unchanged source and actual drain. It
checks cold reopen after every batch, savepoint release and restoration, both
malformed namespaces and original physical I/O failure custody. Public integration
targets run separately in attempt 145: **255 pass and two fail** across ten
dispatched targets; cursor cases are feature-disabled in that run. The 235.203-second
run drains without signals or timeout and keeps source unchanged. One corruption
fixture still searches for a format3 savepoint. The other expects an exact version
error for a real upstream file which, as diagnostic attempt 146 establishes,
is rejected earlier for its 130 noncanonical region-header pages. The two fixture
corrections preserve the original corruption/rejection checks and unchanged-file
assertions; no production decoder or fallback is restored. Attempt147 passes
both corrected cases with unchanged source and actual process drain. Attempt148
passes all **296 public integration cases** with cursor/API5 paths enabled,
including37cursor cases. The 277.981-second run keeps source unchanged and drains
without signals or timeout. The next applied allocator-planning change computes
checked encoded lengths without creating serialization temporaries solely to
measure them. Attempt149 passes all 155 library cases, including seven new
geometry and allocation tests, in 52.601 seconds with unchanged source and actual
process drain. Attempt 150 passes strict workspace Clippy in 121.918 seconds with
unchanged source and actual drain. Attempt 151 then passes all 162 vendor library
cases in 50.900 seconds after replacing nested allocator serialization vectors with
one exact output buffer. The seven new cases check byte identity, guarded output,
untouched refusals and zero allocations for caller-buffer encoding. The final
output, full prepared allocator copy, COW workspace and total resource bounds
remain open. These results and their exact packages are preserved in the
4,041-entry installed-storage evidence archive.
Attempt 152 passes all 226 enabled store library cases in 171.622 seconds after
these changes; two pre-existing cases remain ignored. The separate strict vendor
all-target/all-feature check fails in attempts 153–154 on an API5 trait import,
one checked-conversion requirement and test-only lints. Narrow corrections retain
all identity/failure assertions, check fixture conversions and explicitly consume
each history iterator result. Attempt 155 passes that same strict command in
10.502 seconds. Attempt 156 applies retained database-opening custody and passes
all 197 all-feature vendor library cases in 108.533 seconds, including eleven
new actual-backend fault and close tests. Every run preserves inventoried source
and records actual process drain without timeout or runner signals. Production
owner registration, queued-writer admission, complete error/workspace accounting
and managed directory caller adoption remain open.
Attempt 157 then passes all 204 all-feature vendor library cases in 101.610
seconds after removing obsolete allocator-key tags and their writer. Raw leaf
keys, branch separators, record geometry and transaction-stamp lengths are
checked before typed comparison or stale-snapshot repair. Tests preserve original
files and show malformed keys cannot invoke repair. Attempt 158 passes strict
vendor Clippy in 12.196 seconds; both runs retain unchanged source and actual
drain. Full allocator payload/layout validation remains open.

Attempt 159 passes strict all-target/all-feature workspace Clippy in 175.315
seconds, with the same three existing rmcp dependency warnings. Attempt 160
passes workspace and standalone vendor formatting in 2.229 seconds. Attempt 161
passes all 296 public vendor integration cases across ten targets, with
experimental cursor/API5 enabled, in 346.368 seconds. Groups 16859, 17763 and
17971 drain; all three runs preserve inventoried source and have no timeout or
runner signals. The immutable evidence append now verifies 4,941 raw entries,
including failures 153/154 and unapplied namespace candidates; those candidates
and complete production owner/workspace adoption remain unqualified.

Attempt 162 applies the reviewed five-file allocator payload successor and passes
all 211 all-feature vendor unit cases in 136.457 seconds (125.54 testing).
Borrowed bitmap/buddy/tracker views reject malformed nested geometry, inconsistent
summaries, overlapping/unmerged free blocks and missing/noncontiguous records
before decoding or repair. They accept the current producer's retained capacity,
shrink and extension states. A matching winner must prove a discarded suffix is
free; stale valid snapshots remain repairable. Raw branch routing uses the
comparator's actual lower-exclusive/upper-inclusive bounds. All seven added tests
pass, including all-order producer mutations and 16 clean/unclean malformed native
fixtures across consuming, read-only and retained opening. Attempt 163 passes
strict vendor Clippy in 11.983 seconds; 164 passes all 296 original public vendor
integration cases in 341.737 seconds. Groups 24263, 26707 and 27344 drain with
unchanged source and no timeout or runner signals. Complete allocation ownership
correspondence and resource bounds remain open. The payload evidence append
preserves the earlier 4,941 entries and adds 39, for 4,980 verified raw entries.

Attempt 165 deliberately updates the redb inventory to the reviewed 109-file
[current source checkpoint](evidence/redb-current-source-20260922/README.md),
preserving both original removals and 134 exact historical/gate bindings. Original
provenance and the checker stay unchanged; other dependency inventories and
support records stay exact apart from the reviewed vendor README text. All 18
existing verifier tests and the actual seven-package source/Cargo selection check
pass in 1.184 seconds with bundled Python 3.12.14. Group 38305 drains, no timeout
or signals occur, and the expanded inventory (including vendor metadata and review
inputs) remains unchanged. The archive now verifies 5,160 raw entries, preserving
the prior 4,980 and adding 180. This source checkpoint does not complete G11 or
the unpassed upstream, native, ownership and resource qualification gates.

The separate storage-census candidate's first native run passes all eight census
cases, then passes four and fails two physical-opening cases. It stops before its
two later phases. Both failures concern already-disposed NodeTables requests
remaining retained after the database is closed; groups 36453 and 37043 drain and
inputs remain unchanged. Independent review also identifies a shared report-release
latch that could discard errors produced by later close or queued execution.
Revision2 corrects both issues. Its native02 reused the old shared-target test
executable and is preserved as a qualification failure, with no successor test
credit. Native03 uses a fresh candidate-specific Cargo target, verifies exact test
names before dispatch, and passes 33 cases across census, opening, lease,
device/scratch/node metadata and engine provider checks. All 14 stages drain;
source and actual executable hashes stay unchanged. Independent review closes
the future-outcome relinquishment finding. Revision3 only relocates a test import;
strict combined workspace qualification and all twelve production caller
migrations remain open.

The separate managed-directory candidate passes 47 scoped native cases after a
Darwin removal correction. Review then identifies a newly added generic-parent
acquisition outside retained custody. Its four-file successor routes generic
nonroot opens through the retained operation and passes the full prior cohort
plus two new cases: 49 pass, five inherited device cases filtered. Both packages
remain unapplied pending aggregate session and caller adoption. Their requested
1,353,059,396-byte owner geometry does not establish full process fit or native
descriptor memory. Original failures and both root reviews remain preserved.

The aggregate namespace/session successor reserves both fixed terminal inodes
before first session publication and uses the original reserve inode for each
create-only terminal rename. Canonical framing rejects unframed/obsolete inputs;
classification streams a charged 4 KiB buffer and reads reject the caller limit
before allocating exact ciphertext. A shared physical claim covers classification
through publication. Its first preparation failure and seven-error harness
compile failure remain preserved; candidate03 passes 65 scoped cases. Root review
then identifies owned path allocation before claim acquisition. Revision4 derives
the claim from the retained directory and stack UUID first, and passes all prior
cases plus two regressions: 67 passed, five inherited device tests filtered.
Recorded source, executable hashes and all process groups remain unchanged/drained.
The scoped harness excludes authenticated GC methods; its result does not qualify
full store/server construction or GC integration. Their revised 73-file cumulative
composition is now qualified as a target-only prerequisite: offline locked full
workspace checking and strict Clippy pass, its exact 326-test store inventory
finishes with 324 passed and the two pre-existing ignores, and all 17 Python
smoke-script tests pass. The first combined compile failure, strict-lint failure,
full-store inventory mismatch and later fixture failures remain preserved. The
final qualification uses a conservative terminal recheck that rejects timeout or
forced descendant cleanup. Actual source is unchanged by this composition.

The separate retained file-custody successor passes 132 selected native tests
with fixed H+1 failure storage, original operation/native close outcomes and
explicit one-shot file retirement before credit. Its independent review verifies
unchanged inputs, original failed attempts and drained process groups; it has
not yet been composed with the 73-file prerequisite. Full production caller,
worker, ciphertext, diagnostic and native stack admission, configured-root and
inherited-directory custody, native descriptor memory and filesystem-specific
physical bounds remain open.

The cumulative storage, namespace and file-custody revision 6 is now applied to
the exact `master` bases: 75 before/after hashes and modes were verified, and
the [compact evidence bundle](evidence/installed-disk-storage-namespace-custody-20260923-rev6/README.md)
passes live-proposed verification after application. Its source-bound native
cohort passes all 19 stages in 482.655 seconds, including locked full-workspace
all-target/all-feature check, strict Clippy, exact 338-name store inventory,
all 14 focused regressions and unfiltered store results of 336 passed, zero
failed and two pre-existing ignored. Separate workspace formatting passes;
all 21 process groups drain without timeout or cleanup signals. Revision 4's
four failures and revision 5's two failures remain retained. This qualifies
only the prerequisite. Mandatory production caller adoption, failed-owner
acknowledgement and verified recovery, complete memory/RSS bounds, configured
root custody, canonical PageNumber migration and release-wide runtime gates
remained open at that checkpoint.

The reviewed [filesystem-backup admission revision 5](evidence/installed-disk-filesystem-backup-20260923-rev5/README.md)
is now applied to `master`, with exact three-file before/after hashes and modes
verified. Its native cohort passes locked full-workspace check, strict Clippy,
343 unfiltered runnable store cases with zero failures and two inherited ignores,
and a separate formatting check. The preserved `format-01` inventory-preparation
failure dispatched no native child. This change admits pending inode and extent
before publication; it does not qualify opaque worker, ciphertext, stack,
configured-root or inherited-directory custody.

The canonical redb `PageNumber` freeze 05 and reviewed provenance update are
also applied to `master`. All 19 source/support paths and 144 policy/evidence
paths match their recorded after hashes and modes. The official dependency
checker passes on the combined source for all seven vendored packages, locked
Cargo metadata and exact selected package versions; all 18 checker regressions
pass. The earlier 225-case vendor and strict Clippy results remain component
evidence. Full post-application workspace integration and release-wide gates
remain open; no compatibility decoder, alias or fallback is authorized.

The source-pinned PageNumber audit found that the pre-migration decoder discarded
reserved bits and aliased malformed addresses before validation. The canonical
successor now replaces that sole decoder across roots, table metadata, branches
and used PageLists while preserving opaque checksum-invalid recovery slots.
The audit's 5,133 arithmetic counterexamples remain diagnostic evidence only;
combined native qualification, descendant reachability and memory bounds remain
open.

The census/session evidence append preserves all prior 5,160 raw entries and adds
1,229, for 6,389 verified entries. It includes the frozen candidates, reviews,
successful scoped runs, original failures, stale-executable diagnosis and page
audit. Eight local executable/dependency files (355,202,784 bytes) are hashed and
omitted; no Cargo build tree or outside dependency bytes are copied. The combined
workspace candidate and newer custody/decoder work are outside this append. A
subsequent append preserves the 6,389 entries and adds 2,804, for **9,193
verified entries**. It freezes the original and five revised combined candidates,
their failure/success transcripts, the separately qualified file-custody
candidates and reviews. Eight native files (176,603,688 bytes) are inventoried
and omitted, with no Cargo assembly or cache copied. The new 75-file composition,
unfinished caller adoption and decoder migration are outside this append.

The [installed-storage diagnostics](evidence/installed-disk-main-20260920/README.md)
now pass the store library's enabled cases: 183 passed, zero failed, with the
subprocess helper and external real-MinIO case ignored. The earlier compile
failure, 101-failure run, four-failure successor and one-failure namespace
successor are preserved. Process drain is recorded by the terminal receipts or,
for attempt 29, an independent recovery audit. Scoped source stayed unchanged
except in attempt 35, whose limitation is recorded below.
These runs use pending master source;
they are not a clean combined or final release checkpoint. Mandatory physical
ownership and canonical redb are integrated. Installed server markers now use the
same physical owner in source. Directory accounting, retained metadata charges,
cancellation-safe filesystem jobs and full qualification remain open. The
combined workspace check now passes all targets and features after admitted
future boundaries corrected the type-depth failures. Those raw failures remain
preserved alongside the successful successor, store and Python diagnostics.
The earlier full Raft library attempt failed with 39 passes and 34 failures. An isolated
run reproduces the first failure in an encrypted scratch append; one affected
snapshot case passes alone. The failure trace proved speculative physical
allocation beyond the admitted scratch extent. Scratch flush now prepares the
admitted ciphertext EOF before payload write and verifies allocation before and
afterward; both new regressions and the full store successor pass. Shared-device
failure fencing remains unchanged.
The isolated custody successor, attempt 29, produced no terminal test result after
its 20-minute deadline and remains **failed/unresolved**. Its runner exited with
status 1 when the post-run liveness probe raised `PermissionError`, before writing
the original result receipt. Fresh process inventory independently confirmed the
group drained, and the recovery source inventory matches the original exactly.
The original timeout and signal fields were not persisted; neither an exact
signal history nor absence of signals is asserted. The recovery receipt, stderr,
runner, incomplete test log and diagnostic stack sample are preserved in the
[installed-storage evidence](evidence/installed-disk-main-20260920/README.md).
Six focused integration gates now pass: actual snapshot-child shutdown, startup
inventory charges, three backup-future cases, 12 readiness cases, two installed
marker cases and protected TLS observability covering 131 assigned groups. The
complete Raft successor and original combined qualification cohort remain open.

Later diagnostics preserve strict-lint failures 33 (one authority and eight
engine lints) and 37 (one engine fixture and thirteen server lints). Formatting
attempt 34 passes on unchanged inventoried source. Attempt 35 reports eight
passing snapshot-buffer ownership tests, but its original receipt records
`inventoried_source_unchanged: false`: six engine/authority files changed during
mechanical edits. The inventoried Raft scope stayed unchanged, but this is **not
a fixed-source qualifying pass**. The coordinated partial successor, attempt 38,
passes all 72 selected library cases on unchanged source, with the separately
failed custody-capacity case explicitly excluded. Cluster integration then passes
six and fails one stale shutdown expectation after an injected snapshot failure;
its other integration targets remain unrun. The failure is retained, and the
successor must verify the original typed Complete drain and immediate recovery.
Attempt 45 does so and passes all 18 Raft integration cases (seven cluster, five
read-barrier, one actual-child shutdown and five storage-conformance cases).
It preserves the failure and checks repeated issue identity plus immediate
reopen/replay. This does not qualify the excluded custody-capacity workload. Attempts 33, 34, 35 and 37 drained their process groups
within their deadlines without recorded signals; original logs, receipts,
inventories and runners remain byte-exact. Further strict-lint attempts 39, 41 and
42 failed on test-code findings and remain preserved. Attempt 43 now passes strict
workspace Clippy across all targets and features on unchanged pending source;
its process group drained without signals. Formatting attempt 44 and all four
TLS listener lifecycle tests in attempt 40 also pass on unchanged source. The
complete combined qualification remains open. After the fatal-shutdown test
correction, attempts 46 and 47 pass strict workspace lint and formatting again
on unchanged inventoried source, with their actual process groups drained.

The shared memory foundation now retains one core across fresh runtime facades,
uses a fixed reservation ledger, separately charges bookkeeping and resident
owners, and joins the actual sampler. Database construction derives mandatory
admission from its audit; the lazy fallback and late setter are removed.
Attempt 49 passes 24 admission regressions, 50 passes workspace compilation and
56 passes strict workspace lint after preserving the two initializer failures
from attempt 51. Installed process-core selection, mandatory disk-metadata
admission and directory accounting remain open.

The full engine successor, attempt 52, records **184 passed, 13 failed and one
ignored**; its actual cancelled Raft startup/census regression passes. The ignored
permanent-receipt capacity requirement remains unrun. Immediate replay 57
reproduces the first nine failures. Corrections retain exact audit failures,
wait for actual proposal-child admission before cancellation, preserve permanent
point-history owners and establish canonical bootstrap identity in fixtures.
Raft, custody and server startup cleanup now propagate the original typed drain
reports and their Complete/Retained status. Compilation failures 58 and 59 are
preserved; successor 60 passes all workspace targets/features. These are pending
development changes, not release acceptance. Focused successor 61 passes the ten
corrected failures and seven proposal-ownership regressions on unchanged source,
with actual process drain. It does not rerun the three unresolved production
failures or qualify the ignored permanent-receipt capacity case.

The namespace correction now distinguishes an unknown missing leaf from
disappearance of an enrolled file while preserving physical identity fencing.
Attempt 63 passes all 196 enabled store tests, including 13 new namespace cases;
the real MinIO case remains unrun. Attempt 64 passes 32 core/startup/archive cases,
including both formerly failing archive-cache consumers, exact installed-policy
reuse/rejection and preservation of the failed sampler's original panic. These
attempts retain unchanged source and actual process drain. Installed selection
still needs adoption at every production entry point.

Integration attempt 53 passes both admission cases and nine backup cases, then
fails three backup fixtures; the later fixture-clock, response-release and
retirement targets remain unrun in that attempt. Corrected fixtures account for the second
Database's actual proposal registry and inject remote read faults without
unauthorized local inode replacement. Full successor 70 passes eleven backup
cases and fails one later reopen step that incorrectly initializes an existing
catalog. Focused successor 72 passes that corrected reopen case and all eight
terminal-row cases. A failed staging push now permanently rejects finish, even
when its digest has already advanced to the expected head. Attempt 69
passes eight backup filesystem/session cases, including missing enrolled-leaf
fencing and healthy repeated cleanup after admitted deletion. All these receipts
record unchanged source and actual process drain.

Server attempt 65 passes 37 and fails nine fixtures. Its eight typed startup-owner
cases pass. Corrections retain one MCP membership registry across routers, reopen
serving storage through the same physical owners after actual close, and require
old signer facades to stay sealed while a fresh owner serves. Successor 71 passes
all 46 selected cases on unchanged source with actual process drain; production
identity fences remain intact. Full server qualification remains open.

Public restore also fails its unchanged verification deadline while staging
permanent rows with individual durable commits. Its original workload and deadline,
the failed custody-capacity case and all final qualification gates remain required.
Startup-registry repeated-error retention and abandoned target cleanup ownership
also remain open.

Raft successor 66 passes 72 selected library and all 18 integration cases on
unchanged source with actual process drain, exercising the direct typed drain
contract and actual-child ownership. The separately failed custody-capacity case
is explicitly excluded and remains required; this is not a complete Raft gate.

Attempt 68 reaches the three previously unrun engine integration targets: all ten
retirement cases and response release pass, while the clock target has two passes
and one obsolete receipt-expiry expectation. That fixture is corrected to require
permanent outcome retention, with unchanged credential/lease expiry and simulated
elapsed time. Successor 74 passes all three clock cases and all 32 admission/core/
startup cases; its actual child and shared report tests cover the newly integrated
fixed startup-scope foundation. Workspace compilation 73 and formatting 55 pass.
The new required policy, charged fixed census and shared report views do not yet
have production runtime/resource adapters or whole-process shutdown integration.

Strict lint attempt 67 preserves one backup cleanup expression failure. Its
semantics-preserving inspect_err correction passes strict workspace Clippy in
75, and formatting passes in 76. Both record unchanged source and actual process
drain. All G01–G14 and the final-source acceptance gates remain open.


## Latest frozen combined checkpoint

The [frozen `6d969f3` attempt](evidence/first-release-6d969f3-interrupted-20260920/README.md)
passed four gates (workspace compilation, formatting, nine rmcp ownership tests
and 60 upstream protocol tests). The fifth Raft classification gate was terminated
with SIGTERM to comply with the user's main-checkout-only instruction; it did
not produce a test result. The raw runner correctly remains failed, with 42
later gates unrun. All five process groups drained, source stayed unchanged,
and all eight preserved executables match their recorded hashes. This is an
interrupted attempt, not evidence of a Raft assertion failure. The NodeDisk
allocation correction and Control genesis stack correction remain unqualified.

The release integration is now on master, with its prior public-repository and
ordered-seek changes preserved. Pending mandatory storage-owner, canonical redb
and caller changes have been transferred here for continued implementation.
Transferred source and historical dependency passes do not qualify this combined
source. G01–G14 remain open.

## Preceding combined checkpoint

The [frozen `c681ba3` successor](evidence/first-release-c681ba3-check-20260920/README.md)
passed 17 gates before the store library reported 154 passes and three failed
allocation assertions. All 29 later gates were unrun; all 18 process groups
drained and source remained unchanged. The correction prepares dormant test
mutexes before the measured physical I/O and destructor boundaries. The full
47-gate, 252-mandatory-case successor remains required, including the unrun
Control genesis stack correction.

## Preceding proposal and authority checkpoint

The [frozen `5233e96` successor](evidence/first-release-5233e96-check-20260920/README.md)
passed 26 gates, including proposal/authority custody, all MCP response fences,
complete store/serving libraries and the corrected retired-source ownership
case. The next Control genesis gate aborted with a stack overflow in its first
case. All 19 later gates were unrun. All 27 dispatched process groups drained;
source stayed unchanged and 13 preserved executables were rehashed. The original
46-gate, 247-mandatory-case cohort and all deadlines remain required.

Source-only disk-owner progress additionally prepares path verification before
I/O, avoids heap-allocated errors in the physical publication path, and adds
explicit durable settlement plus allocation-counting regressions. It is not in
the frozen `5233e96` source and has not yet passed its successor tests. Installed
constructor integration and G02 remain open.

## Preceding authority compilation checkpoint

The [frozen `207ae69` successor](evidence/first-release-207ae69-check-20260920/README.md)
failed its first compilation gate: the new shared authority request helper had
private child-module visibility. All 45 later gates were unrun. Its process
group drained and source stayed unchanged. The scoped correction also ensures
the unwind guard lives inside the actual authority child. All 46 gates and 247
mandatory cases remain required for the successor.

## Preceding SDK and ownership checkpoint

The [frozen `f2921f5` successor](evidence/first-release-f2921f5-check-20260920/README.md)
passed 16 gates, including all 69 SDK cases, all 11 MCP cases, 154 store tests,
strict store lint and all six repaired serving owner fixtures. The next
retired-source gate passed one case and failed its registration-rejection
ownership case with an elapsed deadline. All 21 later gates were unrun.
All dispatched process groups drained and source stayed unchanged. The failure
and exact executable bytes are retained for diagnosis; the original deadlines
and mandatory cohort remain required for the next frozen successor.

## Preceding MCP checkpoint

The [frozen `b5001b1` successor](evidence/first-release-b5001b1-check-20260920/README.md)
passed workspace compilation, formatting and the new engine owned-response-fence
regression. The next MCP gate passed three existing tests and failed seven new
tests whose assertions expected lower-case errors while the API emits upper-case
ErrorCode values. All 32 later gates were unrun. All dispatched process groups
drained and source remained unchanged. Corrected assertions require a new frozen
successor; production serialization and the original retained cohort are unchanged.

## Preceding compiler checkpoint

The [frozen `e9f39b2` successor](evidence/first-release-e9f39b2-check-20260920/README.md)
failed its first workspace all-targets/features compilation gate after 154.208
seconds on native macOS ARM64 with Rust 1.97.1. The previously integrated local
cleanup fixture has an ambiguous `Result` alias. All 30 later gates were unrun;
the process group drained and source remained unchanged. The pending correction
selects `anyhow::Result<()>` explicitly. Its private-directory ownership fixture
repair still requires execution on a passing successor. Pending MCP and owned
response-fence changes are excluded from this frozen source.

## Preceding ownership checkpoint

The [frozen `be2667d` cohort](evidence/first-release-be2667d-check-20260919/README.md)
**failed after eight passing gates**: workspace compilation, formatting,
complete store library (150 passed, zero failed, two ignored), strict store lint,
complete serving library (23 passed), database-worker outcomes (four passed),
audit-worker outcomes (two passed), and corrected Control genesis (five passed).
All 55 mandatory store cases passed, including the seven new NodeDisk and
filesystem-backup cases. The ignored store entries remain the live MinIO test
and the subprocess helper exercised by its passing parent. These are scoped
results, not full workspace tests or strict workspace lint.

The ninth gate, `server-serving-owner`, passed one case and failed five ownership
fixtures with `operator material must be owner-only`. The fixtures created
installation directories without the required private permissions. Correct their
setup and validate the ownership assertions on a newly frozen source; keep
production permission enforcement unchanged. All **22 later gates were unrun**,
including the five audit gates. All nine dispatched process groups drained and
the frozen source remained unchanged. Original logs, manifests and hashes remain
preserved. The original evidence's scope text still says "Prepared only"; its
terminal gate records and failed status establish that the run actually executed.
That original evidence is not rewritten to correct its stale scope text.

This run used source `be2667d804e483dce2b3bcc408ecb7cb7f3ae66a`, tree
`5cc19f163e7f0b7b53ef53da9dfc998578ba0f20`. Later integration source and pending MCP
changes are not qualified by it. Persistent NodeDisk admission, recoverable redb
capacity handling and all final production, platform, live, capacity, performance,
endurance and artifact gates remain open.

## Preceding combined checkpoint

The [frozen `32825cf` cohort](evidence/first-release-32825cf-check-20260919/README.md)
**failed** after seven passing gates: workspace compilation and formatting,
complete store library (143 passed, zero failed, two ignored), strict store lint,
complete serving library (23 passed), engine database-worker outcomes (four
passed), and engine audit-worker outcomes (two passed). All 48 required store,
12 serving and six engine-worker cases passed. The ignored store entries were
the live MinIO test and a subprocess helper exercised by its passing parent.
Strict workspace lint and full workspace tests were not part of these passes.

The next gate, engine Control genesis, passed four tests and failed
`control_genesis_rejects_wrong_storage_purpose_before_deployment_publication`.
Its fixture inadvertently selected the permitted `NodeControl` purpose for the
reserved tenant; the production purpose check remained intact. Source correction
`d14c4b3` explicitly supplies and asserts the wrong purpose. The failed log remains
preserved. Its correction subsequently passed in the `be2667d` cohort above.

All 18 later gates in the 26-gate/124-case plan were withheld. Server ownership,
TLS/lifecycle, SDK/native receipts, authority enrollment and explicit-voter gates
remain unrun on this source. All eight dispatched process groups drained, source
remained unchanged, and raw logs plus source/tool/lock/executable hashes are
preserved. These scoped results do not qualify final production, platform, live,
capacity, performance, endurance or artifact gates.

Source successors add exclusive NodeDisk acquisition and verified live shrink
(`9c8309c`) and durable filesystem backup outcome readback (`db4b123`). Their seven
new storage regressions passed in `be2667d`. That successor also includes the
audit outage correction; its five audit gates requiring ten cases were withheld
after the ownership failure. The 31-gate/141-case plan retains every previous
command, deadline and required case and binds the successor source/tree. These
results do not establish installed production disk admission or recoverable redb
quota handling.

## Contract

- Self-hosted standalone and replicated HA, Apache-2.0, Rust 1.97.1.
- One canonical first-release API, configuration and storage format. No legacy
  aliases, compatibility decoders, migrations or automatic HA downgrade.
- Secure local initialization; externally managed HA trust; original invocation
  deadlines and permanent incarnation fences remain mandatory.
- Streaming storage and resource-budget capacity, archive-before-prune audits,
  complete recovery, and usable release artifacts.

Choose the strongest first-release design without preserving earlier prototype
APIs, configuration shapes, digests or storage layouts for compatibility. Update
all supported callers and writers together, remove superseded paths, and reject
unsupported inputs explicitly. Retained test evidence documents earlier sources;
it does not make their interfaces or formats part of the release contract.

## Implementation milestones

- [x] Create `codex/production-v1` and integrate committed resource credentials,
  Control lifecycle and schema admission (`c30437f`, `d9ef813`, `15f35b2`).
- [x] Import a source-frozen copy of the owned target runner; preserve its original
  worktree, failed attempts and focused evidence; reconcile with schema admission.
- [ ] Streaming engine/Raft/backup snapshots, encrypted staging, paged manifests,
  checked 64-bit aggregate lengths, and shared/delta-accounted coherent reads.
- [ ] Verified 8 MiB audit archive segments, 75%/50% hot-budget maintenance,
  atomic pruning watermarks, HA archive coverage and paginated export/status.
- [ ] Disk-backed permanent identities and expandable durable budgets, preserving
  exact replay, stops and reserved completion capacity.
- [ ] Durable backup sessions, exact completion/abort recovery and namespace-owned
  orphan reclamation that cannot delete completed backups or audit archives.
- [ ] Secure standalone initialization, production file keyrings, local JWT
  credential lifecycle, TLS profiles, key backup and stopped admin recovery.
- [ ] Installed endpoint failover, renewable credential sources, automatic fresh
  readmission, authority/data membership maintenance, signer and TLS rotation.
- [ ] Durable planned/source-unavailable recovery coordinator, exact target
  phases, physical generation bindings, cleanup/rebind proof and local recovery.
- [ ] Protected health/readiness/metrics, structured logs and complete runbooks.
- [ ] Dependency fixes, licensing/attribution, reproducible builds and packaging.

## Final-source acceptance gates

- [ ] Full workspace tests, strict lint, formatting, Python checks and production
  builds excluding fixture features on Linux x86-64, Linux ARM64 and macOS ARM64.
- [ ] Actual OpenBao/MinIO interoperability using final binaries.
- [ ] Offline standalone initialization and native/MCP lifecycle, revocation,
  rotation, backup/restore and stopped-instance recovery.
- [ ] Native HA endpoint/leader failures, outages exceeding lease lifetime,
  automatic fresh admission and maintenance under load.
- [ ] Source-quorum-absent recovery, exact phased crash/cancellation outcomes,
  cleanup isolation, permanent stops and immutable lineage.
- [ ] Incompressible standalone/HA corpus exceeding 3 GiB, snapshots, compaction,
  restart, member replacement, filesystem/S3 backup/restore and bounded workspaces.
- [ ] Repeated audit cap crossings, archive failure/recovery, old administrative
  ceiling crossings, member replacement and GC/delayed-upload races.
- [ ] Final 15-case million-document matrix, concurrency measurements and genuine
  24-hour HA endurance run. No duration substitutions or waived failures.
- [ ] Source/configuration/dependency/executable-bound evidence, dependency
  dispositions, notices, SBOM, checksums and validated release artifacts.

## Next integration checkpoints

These are concrete steps toward the active release goal, not separate release
approvals. Source integration does not accept an implementation milestone. Each change must
pass its stated regressions on the combined source, followed by the complete final
gates above. Source-only changes and failed attempts remain explicitly identified.

1. Validate the combined explicit singleton/pair creation and strict reopen paths,
   canonical administration, stopped-operator ownership and live configured-tenant
   enrollment. The generic singleton create-or-open API is removed. Complete
   validation of explicit immutable Control genesis, standalone tenant enrollment and permanent
   cleanup/replacement of incomplete HA creation without restoring creation rights.
2. Close and validate stopped-operator ownership from first exclusive lock through
   every failure/cancellation. Propagate actual worker/core terminal failures;
   joined errors must survive cancelled drains, and elapsed deadlines never prove
   owner release. Repeat the restored-runtime restart failure on final source.
   The [OpenRaft shutdown patch](evidence/openraft-707e82e-source-20260910/README.md)
   retains core/ticker outcomes and adds post-core cancellation regressions in
   source only; it is uninstalled and untested. The preceding artifact is retained.
3. Run full store and authority regressions for acknowledged catalog outcomes,
   admitted-request/fence retention and exact signer authorization reuse. Follow
   with the real TLS canonical coordinator and source-unavailable phase faults.
4. Complete persistent node disk admission and native reservations, then validate
   canonical `KASUMIT7` permanent receipts, history archival and streaming
   snapshots/restores under actual pressure exceeding 3 GiB. Scratch or payload
   limits do not establish disk capacity.
5. Complete standalone and HA maintenance, secure credential/key/TLS lifecycle,
   actual provider interoperability and replacement-member recovery. Earlier
   small standalone and native branch diagnostics remain historical evidence.
6. Execute all final-source platform/performance/endurance gates and generate
   source/configuration/dependency/executable-bound installation artifacts. Preserve
   failed attempts and do not shorten the genuine 24-hour soak.

Persistent disk admission and native durable resource reservations must be
implemented before claiming configured node disk capacity or reserved import
completion. A scratch-file budget or an application payload limit does not
account for persistent databases, indexes, WALs, archived objects or retained
versions. The exact reservation dependency is specified below.

The source-frozen `f650b99` NodeDisk foundation passes store all-target
compilation and [23 focused ownership/device/scratch tests](evidence/node-disk-f650b99-20260909/README.md).
It retains closed-file charges, bounds descriptor metadata and shares filesystem
promises with scratch storage. Production constructors and redb lifecycle paths
remain unwired; this result does not close persistent capacity acceptance.

The separate redb owner-failure prototype `4f62863` passes
[20 focused regressions](evidence/redb-owner-failure-4f62863-20260909/README.md),
including permanent failure fencing and ordinary capacity rollback. Its
[complete upstream source overlay](evidence/redb-upstream-preparation-20260909/README.md)
is prepared at `bdde797`. Offline dependency preparation failed on missing cached
packages and is preserved. [Online metadata preparation](evidence/redb-upstream-metadata-online-20260909/README.md)
resolved both complete verification graphs without compilation and committed
their lockfiles at `3a87154`. Pinned tools/harness, full upstream verification,
fuzzing and production integration remain open.

## Work ownership

The only authorized checkout is `/Users/mtakemiya/dev/kasumi`, on `master`.
Do not create or switch branches, create worktrees, or run edits/builds from
another checkout. All previous external jobs have stopped. Preserve existing
external work and evidence as historical inputs; transfer pending source into
master before resuming it. Parallel agents require explicitly disjoint file
scopes in this checkout. Source integration is not validation.

Mark a milestone complete only when its implementation is integrated and its
required checks actually pass. Completing scaffolding or a focused diagnostic
does not complete a whole milestone. Release readiness requires every acceptance
gate above and usable installation artifacts.

## Preserved master checkpoint before release integration

The following checkpoint list is preserved from master `2e8049a`. These are
historical source-specific observations, not current acceptance claims. Its
Linux `3a8d512` failure and all linked evidence remain preserved.

1. Repeat the complete Linux acceptance after the integrated shutdown and SDK
   changes. The corrected three-node TLS restore/restart passed on macOS in the
   [native `61b5f0b` cohort](evidence/combined-61b5f0b-native-20260909/README.md).
   The subsequent [combined SDK, strict and fixture-free compilation checks](evidence/combined-4e3a29d-native-20260909/README.md)
   passed at their recorded sources; a final whitespace-only successor passed
   formatting. These changes are integrated through `4815312`. The earlier
   Linux failure remains failed until a new complete Linux run passes.
2. Finish ordinary receipt lifetime and permanent identity storage. Original
   mutation scope/digest, native/MCP resolution and literal JSON changes have
   focused integrated evidence. An [external stock-JSON SDK consumer](evidence/stock-json-sdk-3f88b44-20260909/README.md)
   passed 13 tests without the workspace patch. Neither those tests nor explicit
   SDK decode accounting prove permanent retention or a hard process RSS bound.
3. Complete the encrypted staged/target terminal-prefix functional matrix.
   Source `8bf5e27` passed six point-prefix tests and one indexed-genesis test,
   then its two atomic-publication fault tests failed during fixture setup:
   the table's 1 MiB budget could not initialize redb. The [failed cohort](evidence/combined-prefix-8bf5e27-functional-20260909/README.md)
   is retained. Successor `769b834` funds that fixture at 8 MiB; both actual
   fault tests pass in the later `b17eaf5` cohort. Its [remainder](evidence/combined-t5-b17eaf5-remainder-20260909/README.md)
   passes point-read admission and missing-stop restart, then fails an obsolete
   assertion that completed restored transactions remain in the resident map.
   `5daf4d3` verifies exact permanent counts and public original-scope outcomes;
   `deb8ead` reconciles the other staged terminal fixtures. Those successors
   pass in the [combined `f4a472f` functional cohort](evidence/followon-f4a472f-functional-20260909/README.md),
   including the actual killed-upload test. The [successor continuation](evidence/recovery-bd42e74-continuation-20260909/README.md)
   passes all six target-prefix and eight completion-machine tests, then fails
   the native issuer fixture's private-directory setup. Native coverage remains open.
4. Validate the combined KASUMIT5 format and restore admission checkpoint.
   `4dddb8d` replaces the prototype decoder directly, inspects typed frames with
   fixed scratch, and separates resident bytes from permanent history. It adds
   structural record-work accounting and a real 512-terminal-row preparation
   fixture. Combined `77bddb1` [failed compilation](evidence/combined-t5-77bddb1-check-20260909/README.md);
   `a159ebc` corrects admission ownership at the verifier/relocation boundary,
   then [fails on missing fixture imports](evidence/combined-t5-a159ebc-check-20260909/README.md).
   `1682a8f` fixes ten imports but [retains one incorrect type name](evidence/combined-t5-1682a8f-check-20260909/README.md).
   `0336024` uses the canonical target prefix head. Its formatting successor
   `b17eaf5` [passes all-target/all-feature workspace compilation and formatting](evidence/combined-t5-b17eaf5-check-20260909/README.md).
   Its [functional cohort](evidence/combined-t5-b17eaf5-functional-20260909/README.md)
   accepted21 tests; two more worker-failure tests passed but expected panic
   output split the required-name line, so the evidence guard rejected the
   cohort. The captured-output continuation and its later failure are retained
   separately. Independent review
   found that external history chunks still need structural admission alongside
   retained logical indexes. That correction is included in `f4a472f`, which
   [passes combined workspace compilation and formatting](evidence/followon-f4a472f-check-20260909/README.md).
   Its [predecessor compilation failure](evidence/followon-9814949-check-20260909/README.md)
   remains preserved; the successor retains the owning zeroizing plaintext
   buffer without another copy. Its three new history ownership/admission tests
   pass in that functional cohort. Structural
   accounting and the resident/index estimator require actual capacity validation.
5. Complete signer coverage, authority genesis-prefix reopen and the durable
   target completion coordinator. The source-frozen receiver and coordinator
   retain exact preparation, observation and resolution phases; their combined
   functional gates are incomplete. Three positive receiver/coordinator tests
   passed in the typed-snapshot cohort. Terminal-only status is source-frozen at
   `ef772f3` and combined at `c1ba870`. Review also found that
   fresh unanimous startup blocks established-quorum status, and live Complete
   admission must independently reject a changed original cap; `6a4cf3e` implements
   both corrections and is compiled in `f4a472f`. Seven pure receiver tests and
   two replicated Control tests pass. The third replicated activation test aborted
   with stack overflow during nested route-publication setup; its failure and
   executable are preserved. `bd42e74` separates the sequential fixture futures
   without raising stack size and passes all five recovery callers. That
   continuation passes30 actual tests across16 gates, then fails the native
   issuer credential fixture; four later gates are unrun. `d37e33e` corrects its
   parent directory and still requires execution. Automatic safe successors, physical cleanup and actual
   source-unavailable recovery remain unfinished. Absence never resolves a mutation.
6. Expand the [successful small offline Linux diagnostic](evidence/small-offline-native-3a8d512-20260909/README.md)
   to final-source acceptance. It exercised 129 documents through private
   initialization, native/MCP access, renewal, backup, restart and stopped local
   restore using exact prior fixture-free binaries. Its processes drained and
   confidential installation files remain private. It does not replace full
   credential rotation, HA recovery, 3 GiB or 24-hour acceptance.
7. Require existing authenticated state on restart. The source assembly now
   includes strict local and replicated bootstrap, immutable stored genesis,
   explicit standalone initialization, mandatory node UUIDs, and distinct
   create/existing/owned-empty file constructors. The target journal has explicit
   installation, permanent original-materialization file intent and strict reopen.
   Service audit initialization is separate from existing-head validation.
   These changes and their new regressions remain uncompiled together.
   Review additionally found and corrected a concurrent resize/write race,
   empty-read bounds, target opener-registry ownership and failed-startup drains.
   Cold HA and authority callers still need their separate explicit enrollment
   operations before all startup paths can require existing state. Empty/torn
   pre-header target cleanup and external namespace custody remain open.
   No missing-state fallback or compatibility constructor is permitted.

## Historical checkpoints

The following records describe their named sources at the time of each run or
source review. Present-tense limitations inside these historical records are
source-specific; the latest combined checkpoint above governs current evidence.
Neither branch passes nor source integration replace final release acceptance.

On September 19 the temporary worktrees and build targets from the previous
session were absent. Committed source and tracked evidence survived; no old
process or prepared plan is treated as a running or completed gate. The surviving
91-file convergence was preserved byte-for-byte as `055a9b6` (tree
`a3158704dcd09a0cbd65839fa9f391da0e9746f0`). It combines ordered seek, installed
member endpoint pools, exact recovery attempt/completion identities, the single
`KASUMIT7` snapshot format, and compiler/caller reconciliation. This is integrated
source, not qualified release evidence. The original staged worktree is untouched.

A [fresh checkpoint on the preceding `46ae68f` source](evidence/first-release-46ae68f-check-20260919/README.md)
failed compilation in 218.329 seconds: engine dependency/type reconciliation and
15 obsolete Raft fixture calls. Source stayed unchanged and all processes drained.
Subsequent gates were withheld. The source fixes are included in `055a9b6`, whose
new checkpoint preserves the original commands and deadlines.
The ownership regression plan includes 110 mandatory cases across 20 gates;
preparing that plan does not count as executing it. Any failure must remain in
the evidence, with fixes validated on a newly frozen successor source.

The [integrated `15e64dd` checkpoint](evidence/first-release-15e64dd-check-20260919/README.md)
passed workspace compilation, formatting and the complete store library (143
passed, zero failed, two ignored; all 48 mandatory store cases passed), then
stopped on strict store lint. The ignored entries are the explicitly configured
MinIO test and a subprocess helper exercised by its parent crash-recovery test.
A subsequent store lint diagnostic at `654c074` found one more fixture UUID
formatting issue. Both failed attempts remain preserved; `32825cf` fixes the
known lint findings and adds retained authority enrollment plus mandatory
explicit original-voter configuration. Its 26-gate/124-case cohort later ran
with the exact partial results described above; server, receipt, authority,
capacity and final release gates remain unqualified.

The separately scoped Python tooling suite at `055a9b6` passed all 44 tests in
3.467 seconds, with unchanged source and a drained process group. Its raw
evidence remains in
`/Users/mtakemiya/dev/kasumi-release-evidence/20260919-055a9b6-python`.
The storage diagnostic on that same source also passed 143 tests before the
combined successor repeated those results. These are historical scoped results,
not a substitute for final-source acceptance.

The combined `3b932ee` source adds explicit singleton creation/reopening,
standalone operator ownership from first lock through cleanup, and Control-approved
HA tenant enrollment with dormant configuration templates. Its
[actual frozen cohort](evidence/first-release-3b932ee-check-20260910/README.md)
failed compilation on three missing redb trait-method diagnostics in the new
singleton module. All later formatting, full-store and strict-store gates were
withheld, so the 44 mandatory storage regressions remain **UNRUN** on this source.
Root `198bb6c` adds the missing trait import; its actual validation is pending.
The [original prepared cohort](evidence/first-release-3b932ee-prepared-20260910/README.md)
and failed run retain unchanged deadlines, commands, source and process evidence.

Subsequent development integrates typed drain completion (`b02c60f`), retained
startup owners across polling panics (`0f940a4`), required immutable Control
genesis (`2547bad`), standalone tenant staging (`a3b3976`), nested preparation
ownership (`31ea437`), typed store/audit outcomes (`6778f30`), runtime propagation
(`c7f72aa`) and serving-task outcome retention (`d4a5e52`, caller reconciliation
`71fc4e3`). Retired-source preparation (`836f9f1`) retains its new custody owner
through completed cleanup before returning an error to its retained caller.
The genesis tag replaces empty-Control startup creation and binds its encrypted
baseline to enrollment. These changes and their new tests were excluded from the
failed `3b932ee` cohort. Later scoped results are listed in the current checkpoint above.

Authority memory admission is now an explicitly required operational setting
(`ed0507a`). Database inner blocking-child custody is integrated (`61ce101`):
cooperative worker shutdown retains actual child failures and cancels only
undispatched waits for shared maintenance capacity. Its four encrypted-store
regressions subsequently passed at `32825cf`. Live signer-worker custody
(`309b3e5`) now retains one actual child handle with bounded synchronous reaping and no helper supervisor.
Outer serving ownership (`63a5951`) retains the runtime separately from its
supervisor and the listener's nested connection/HTTP2 task inventories. Shared
runtime admission and typed lease callers are reconciled in `bb2f22a`. Static
metadata keeps its byte charge while releasing the in-flight operation slot.
The store/serving libraries and engine worker regressions subsequently passed
at `32825cf`; its server gates were withheld after the Control genesis failure.
Neither typed parent results nor cooperative loops alone establish a complete
child census. Standalone staging is integrated in source, while incomplete
creation cleanup, replacement enrollment and the full local lifecycle remain
unfinished. No implementation or release gate is accepted by these source-only
checkpoints.

Retained original error objects can themselves carry opaque owner references.
The [database-worker qualification](database-worker-outcomes.md) distinguishes
structural ownership from arbitrary Rust panic payload disposal. No checkpoint
claims those payloads are resource-free or treats an elapsed timeout as evidence
that physical owners disappeared.

The preceding [frozen compiler/store cohort](evidence/first-release-7a21995-check-20260909/README.md)
passed workspace compilation and formatting, then failed one store identity
assertion: 126 passed, one failed, two ignored. Strict store lint did not run after
the original stop-on-failure rule. All owned processes drained and source stayed
unchanged. This source excludes the later canonical administration and ownership
changes. The failed assertion concerns an obsolete administrative-generation API
already removed in the newer source; only a new actual run can validate that source.
The [preceding compilation failure](evidence/first-release-1ff2fe2-check-20260909/README.md)
and its exact inputs remain retained.

The canonical administration fixture now uses actual encrypted backup data,
separate pinned TLS issuer/Control/data groups, target materialization, quorum loss,
source retirement, activation and restart assertions. It remains **UNRUN**; its
previously missing live enrollment path is now implemented in source and pending
combined validation. Its
[source coverage and corrected review note](evidence/canonical-runtime-f7fa592-source-20260909/README.md)
distinguish fixture-owned target/signing services from full production lifecycle.

Release tooling requires original deadlines, verified process-group drain and exact
runner/helper provenance. Its [44 macOS and 20 Linux Python checks](evidence/release-process-abc8794-20260909/README.md)
passed after preserving a failed cleanup counterexample. The separate redb prototype
[outer containment harness](evidence/redb-outer-92a6a94-guards-20260909/README.md)
passed 14 Python guard tests; its actual VM/container build, full upstream suite and
fuzz runs are unrun. Neither tool result replaces a database gate. The latest
historical Linux reference run (`3a8d512`) failed restored-runtime restart and is
not evidence for this integration.

## Historical branch increments

The combined SDK metadata checkpoint `e17a5eb` passed all 11 literal-decoder
tests, client strict Clippy and formatting. Feed after-images now require their
exact event identity and commit version; schema responses reject impossible
epoch metadata before constructing schema bodies. Source and all owned process
groups closed cleanly. [The retained evidence](evidence/sdk-metadata-e17a5eb-20260909/README.md)
does not certify the server TLS regression, which remains pending execution.

- The combined SDK, original-receipt, canonical JSON and shutdown changes are
  integrated through source `980daa4`. Frozen `4e3a29d` passes eleven selected
  native/codec tests, strict all-target/all-feature workspace Clippy and
  fixture-free server binary compilation on Rust 1.97.1/macOS ARM64. Its final
  formatting failure is retained; `980daa4` changes only the reported line wrap
  and passes formatting. Earlier `61b5f0b` passes the three-node TLS restore and
  restart test, target/signing worker drains and native/MCP receipt checks.
  The indexed original-lineage defect and SDK fixture spelling failure are
  preserved alongside their successors in `docs/evidence/combined-*20260909`.
  These focused results do not substitute for full workspace, final-platform,
  capacity or endurance gates, nor validate the newer permanent-prefix and
  target completion receiver/status implementation.
- The retained Linux `3a8d512` binaries pass the offline standalone diagnostic:
  private initialization, pinned native/MCP access, renewal, encrypted backup,
  restart, local restore and explicit old-resource credential rejection.
  Source/binary/runner hashes and verified process/container drains are recorded
  in `docs/evidence/small-offline-native-3a8d512-20260909`. Only allowlisted
  metadata and hashes were exported; operator secrets remain in private storage.
  The earlier Linux full functional failure remains failed. This small diagnostic
  is not final-source, capacity, HA or complete secure-installation acceptance.
- External stock SDK checkpoint `3f88b44` passes the exact canonical-admission
  test under `preserve_order` and all six public literal-decoding tests in each
  default/ordered graph (13 test executions). Locked metadata and actual compiled
  artifacts verify stock serde_json and the permitted SDK-only dependency graph;
  source/lock stay unchanged and every process group drains. Preparation, the
  initial package-selection failure, the corrected compile-only diagnostic and
  final actual results are retained in
  `docs/evidence/stock-json-sdk-3f88b44-20260909`. This closes the scoped external
  consumer check; combined engine/server/native and final release gates remain
  open. No compatibility API, decoder fallback or format alias was introduced.
- Validation checkpoint `075e24d` combines current release tooling, corrected
  JSON dependency, canonical SDK and shutdown/receipt source. It passes all 36
  release-tool Python tests, exact vendored dependency checks, formatting, six
  canonical payload tests, 13 type-library tests and strict type-library lint.
  Exact evidence is in `docs/evidence/combined-canonical-source-075e24d-20260909`.
  Full workspace, native and production gates have not run for this combination.
- Combined SDK/canonical-payload checkpoint `785dd7f` passes 26 focused tests,
  strict client lint and no-default-feature compilation. Both previous compile
  and lint failures remain retained in `docs/evidence/sdk-literal-small-20260909`.
  It is merged with corrected JSON dependency and shutdown/receipt work only in
  validation checkpoint `b1851d5`; actual combined native and production checks
  remain unrun. External consumer and actual SDK feed/schema TLS coverage are
  being added with their own exact scope.
- Broader SDK literal decoding passed nine focused tests at `0523c64`, then
  failed two stale diagnostic assertions in the snapshot cohort (11 passed).
  The preceding `3027530` compile failure and both exact attempts are retained in
  `docs/evidence/sdk-literal-small-20260909`. Canonical serialization still needs
  charged sorting workspace before combination; no combined or native gate is
  claimed. First-release APIs are replaced directly without compatibility aliases.
- Experimental redb capacity admission at `ccf76d6` compiles, but its first
  seven-test cohort has one pass and six fixture failures. Missing dependencies,
  the preceding compile failure and all raw outcomes are retained in
  `docs/evidence/redb-capacity-leaf-20260909`. The prototype is outside the
  production dependency graph; persistent disk ownership and safe commit-time
  capacity recovery remain open.
- Redb prototype successor `2886774` passes all seven focused pre-commit
  capacity tests, including rollback/reopen, shared allocator state, retained
  physical charges, genuine I/O failures and commit-time failure fencing. Its
  exact bounded split geometry fixes the remaining `dad7479` fixture failure.
  All previous failures and executable hashes remain in
  `docs/evidence/redb-capacity-leaf-20260909`. Full upstream validation, the
  database-wide persistent owner and nonallocating commit publication remain
  unfinished; this prototype is not installed in Kasumi's dependency graph.
- JSON correction `13fbbc1` passes exact vendored-input checks and all four
  complete upstream suites: default 239, number 245, raw 257 and combined 265
  tests passed, with one unchanged nightly-only UI ignore in each. Original
  failures remain retained in `docs/evidence/literal-json-upstream-20260909`.
  It is combined with the corrected shutdown/receipt and SDK snapshot work only
  in validation branch `eb1f31e`; combined Kasumi and production gates remain
  unrun. Broader SDK literal decoding and canonical input helpers are separately
  under source review, including external-consumer behavior without root patches.
- Prepared JSON dependency patch `8f4cf74` passed exact resolver/hash checks and
  the default upstream suite (239 tests passed, one upstream test ignored), then
  failed an added large-number tagged-value regression in its number-only suite.
  The identical failure reproduces against pristine serde_json 1.0.151 with only
  that test added. Raw-only/combined suites and Kasumi boundary tests did not run.
  Exact failures and source inventories are retained in
  `docs/evidence/literal-json-upstream-20260909`; neither source review nor the
  pristine reproduction closes the required correction and execution gates.
- Bounded SDK checkpoint `fb172be` passes 13 snapshot decoder/ownership tests,
  the bearer-metadata redaction regression, strict client lint and a no-default
  client library check. Initial `2b9061d` passed the tests but failed three lint
  checks; that failure and the narrow successor are retained in
  `docs/evidence/sdk-snapshot-small-20260909`. Native endpoints, MCP, combined
  workspace and production builds did not run. The SDK is combined with the
  corrected shutdown fixture in validation branch `f93414e`, not accepted into
  the release implementation. The subsequent `eb1f31e` validation integration includes the corrected JSON
  dependency; it has not run combined gates.
- Frozen shutdown/receipt checkpoint `711b32d` passed one verifier-worker and
  five security-audit tests, then failed its new tenant-audit shutdown fixture
  because that tenant had no administrator. The other tenant maintenance test
  passed. All later functional/strict/production gates were skipped, and every
  owned process group drained. Preserve this failure in
  `docs/evidence/shutdown-receipts-711b32d-20260909`; the combined source remains
  unmerged pending correction and execution, including the original Linux
  restored-runtime restart regression.
- A read-only audit of the locked JSON decoder and the actual historical Linux
  production feature inventory identifies literal-key reinterpretation in
  native and MCP requests. Canonical snapshot and history integrity checks reject
  changed values; document validation still runs after request decoding. The
  source-derived counterexamples have not yet been reproduced by execution and
  no correction is integrated. Exact source/dependency hashes and affected fields
  are retained in `docs/evidence/literal-json-source-audit-20260909`.
- `7200732` integrates the preserved target runner with schema admission. The
  merged workspace compiles; composed recovery process acceptance is still open.
- `f2e64af` vendors the minimal bitmaps/lru fixes. All 107 upstream unit/doctests
  pass; both patched regressions pass Miri, and isolated copies with the fixes
  removed reproduce both memory errors. Raw logs, rejected stale-cache attempts,
  input hashes and compiler versions are in
  `docs/evidence/dependency-patches-20260908`. Full release dependency disposition
  remains open until every final target graph and all third-party notices pass.
- The bounded audit archive codec and filesystem publication primitive pass four
  focused tests: authenticated counts before release, 8 MiB capacity with u64
  positions, exact durable replay, and symlink/corruption isolation. Automatic
  pruning, replica preservation and runtime wiring are separate unfinished work.
- `3854f91` integrates installed authority endpoint pools, renewable credential
  files, TLS reload handles, and target phase adaptation. `80f5d8f` adds original
  instance closure/drain followed by fresh admission and new storage handles.
  Both merged workspaces compile; final multi-process fault acceptance remains
  open, as do operational membership, signer rotation and SDK routing.
- A dedicated Debian ARM64 Lima VM is provisioned for Linux acceptance. The
  Rust 1.97.1 validation image is digest-pinned. VM/image provisioning does not
  close any platform, capacity, performance or endurance gate.

- `6b07159` integrates secure standalone initialization and credential families;
  `85fb812` adds the native endpoint pool and live TLS reload. The combined
  workspace compiles. `231ef86` enforces owner-only node file descriptors.
- `b3fd5bd` integrates streaming snapshots, paged backup manifests and coherent
  read roots. Its frozen validation run passed 45 engine tests and 62 server
  tests, and found two restore-preparation failures; the store group did not
  run after those failures. Raw logs and executable/source hashes are preserved
  in `docs/evidence/integration-b3fd5bd-20260908`. The failures remain open until
  the corrected integrated source passes them.

- `f598722` and `3e64543` add service-audit archive-before-prune maintenance,
  durable uncertain-publication recovery, snapshot-bound export cursors and
  drained maintenance accounting. Tenant replicated archival remains unfinished.
- `daef351` integrates authenticated backup-session storage and scoped cleanup;
  engine session orchestration is still being integrated. Its frozen parallel
  library run passed 58 store tests (one live-provider test ignored), but failed
  2 authority, 12 engine and 13 server tests. Raw output and executable hashes are
  retained in `docs/evidence/integration-daef351-20260908`. The run exposed audit
  reservations incorrectly shared across independent fixture nodes.
- `9878677` keeps historical audit verification bound to its exact authenticated
  source purpose and freshly authorized wrapping key. Seven archive tests and
  strict store lint passed; the original live-store access rules remain enforced.
- `8a62c55` is now integrated with the stopped standalone recovery coordinator.
  Its branch tests exercised real TLS backups, phase restart, target activation,
  permanent stops, substituted-file refusal and active-generation maintenance.
  Final combined-source and source-unavailable HA recovery acceptance remain open.

- `f8e9618` requires an explicit node governor for service-audit retention. Its
  frozen parallel library rerun passes 46 engine and 60 store tests (one live
  provider test ignored), with 25/26 authority and 66/67 server tests passing.
  The remaining authority acknowledgement and obsolete standalone restore test
  are retained in `docs/evidence/integration-f8e9618-20260908`; neither is waived.
- `f144d1a` integrates exact configured operator-key backups, private dependency
  verification and durable credential-renewal retry coverage. Historical archive
  dependencies must still be proven before any wrapping-key retirement.
- Live backup verification still decodes a complete logical state after encrypted
  spooling. Removing tenant-sized serialized buffers does not yet establish the
  bounded maintenance-workspace gate; streaming invariant verification remains
  necessary before the 3 GiB acceptance run.

- `49e7182` integrates durable backup session creation, permanent completion/abort,
  completed-root restore ownership and bounded aborted-namespace cleanup. The
  source-purpose check also binds each root's exact recovery checkpoint to its
  authenticated restore lineage. Full live verification still materializes a
  logical tenant and is not a bounded-workspace acceptance result.
- `708a881` adds the ordered tenant audit pruning primitive. Each applying
  replica checks the exact hot prefix, verifies the original encryption purpose,
  preserves its local ciphertext cache and installed external destination, then
  publishes the matching archive root, byte/count totals and pruning watermark.
  Two focused fault tests pass, and the frozen checkpoint passes strict workspace
  Clippy. Automatic pruning remains disabled until snapshot and full-backup
  dependency transfer is complete. Removing the old hot-record count setting,
  reserving shared node maintenance capacity and runtime S3 installation remain
  open; the new byte-budget fields do not complete those requirements.
- `b7d0754` integrates permanent local signer trust, generation fences and a
  separate historical verification path. Runtime lease envelopes and distributed
  activation/retirement coordination remain unwired.
- `4f4e203` integrates protected service-audit status/export/archive verification
  through native SDK and CLI. Export attempts retain their original stream/end
  and endpoint/trust/resource bindings; current Control policy, original
  credentials and independent audit-store access fence response release. The
  implementation branch passed its real TLS acceptance and scoped strict checks;
  final integration gates remain open.
- Frozen `18667b9` workspace validation finished with 423 passed, one failed and
  two ignored tests. The failure was an in-memory fault fixture without a durable
  audit archive; `708a881` supplies an explicit private archive. Results and exact
  executable hashes are retained in `docs/evidence/integration-18667b9-20260908`.
- Intermediate Linux ARM64 production binaries at `f8e9618` built successfully
  without fixture features. An offline installation passed initialization,
  configuration and private-file checks, native renewal, stopped administrator
  recovery, restart and MCP discovery over TLS 1.3. Source, configuration,
  executable hashes and failed harness attempts are retained in
  `docs/evidence/linux-arm64-f8e9618-20260908`. These precede current integration
  and do not close final platform, recovery, capacity or endurance gates.

- `2d6c66b` fixes the service-audit restart counter mismatch exposed by the
  expanded archive graph tests. One canonical persisted retention position owns
  byte totals, segment counts and drain state; the four focused service-audit
  fault/restart tests passed. No decoder for the superseded development head is
  retained.
- `1a31e35` integrates complete Raft snapshot bundles with verified original audit
  dependencies, bounded framing and matching retention counters. `c21bcbe`
  extends the completed backup session graph with the same exact original audit
  objects and wrapping dependencies. Its branch checkpoint passed all nine
  backup tests and 54 engine library tests. Public snapshot API replacement and
  bootstrap-cache verification on every reopen are still being integrated.
- `8df1234` includes typed backup session CLI commands and exact completion retry
  journals. Its frozen full workspace run is in progress; it is an intermediate
  interface snapshot, not a production acceptance claim.
- `1dd752b` removes the tenant hot audit record-count setting, rejects that old
  configuration field, and reserves Control completion/retirement by exact byte
  headroom. The mutation rejection/administrator expansion test passed. The first
  expanded Control fixture lost its held leader while issuing hundreds of small
  records; the bounded-record successor still requires its focused rerun. Custody
  and other permanent-record count ceilings remain separate unfinished work.
- `4293660` reserves two shared node archive lanes (128 MiB total across tenants)
  for preparation/proposal and replica application, in addition to the existing
  64 MiB service-audit workspace. Queued blocking work retains its actual owners,
  and shutdown drains proposals. Automatic startup is not wired until the public
  snapshot and bootstrap dependency paths are complete. Focused worker validation
  is in progress; initial capacity fixtures omitted required observed revisions
  and their failures are retained.
- Intermediate Linux x86-64 production binaries at `f8e9618` built successfully
  using Rust 1.97.1 under Rosetta translation in the isolated Linux VM. The normal
  and build feature graph excludes fixtures. Source, executable and log hashes
  are in `docs/evidence/linux-amd64-f8e9618-20260908`. Translation is explicitly
  not native performance or endurance evidence.

- Frozen `8df1234` completed 43 test groups with 413 passed, one failed and two
  ignored; its authority process aborted after another 17 passed tests with a
  target recovery stack overflow. The server failure rejected newly created
  target archive-cache entries during physical cleanup. Both failures are
  retained in `docs/evidence/integration-8df1234-20260908`. `e80475a` pins the
  recovery future before composing monitors; its branch regression passed on the
  default stack. Exact local archive ownership cleanup remains in progress.
- Corrected `bfc1f73` passes all 12 audit-focused engine tests and the Control
  completion capacity test. `b5d3f10` passes strict workspace Clippy, native full
  audit-budget expansion, retirement byte-headroom and closed-configuration
  checks. `1dd752b` also passes the mutation rollback/expansion check. Failures
  and corrected results are retained in
  `docs/evidence/audit-maintenance-bfc1f73-20260908`; production startup wiring
  is still separate from these explicit worker tests.
- `c0f3a9` integrates protected health/readiness/Prometheus and structured daemon
  diagnostics. The branch passed actual TLS authorization, expiry/revocation,
  policy and storage release fences, bounded projections, strict server lint and
  production checks. Authority/coordinator observations, missing measurements,
  follower semantics and readiness limits remain explicit in `observability.md`.
- `189e164` replaces public logical snapshot/overwrite APIs with an async admitted
  complete snapshot and staged-only verification. Raft or an exclusive stopped
  coordinator owns publication. Startup now verifies bootstrap archive chains;
  the branch passed missing-cache reopen, nine snapshot and nine backup tests,
  strict affected lint and production checks. Final bounded verification remains
  open because historical verification still materializes logical state.
- `4831c4c` installs explicit tenant archive destinations before normal, target and
  offline runtime materialization/replay. A required map selects filesystem or
  renewable-file-backed S3 destinations; encrypted placement binding rejects a
  removed or changed destination. Local stopped recovery supplies its observed
  cache separately. Both configuration tests and strict server Clippy passed;
  the first helper compile failure is preserved.

- `d53aa94` combines the production audit bootstrap pool, exact shared governor
  checks, and generation-certified authority envelopes. The merged source passed
  all 37 Raft library tests and server all-target/all-feature compilation. The
  streaming checkpoint passed 44 affected integration tests; its corrected
  admission contract test passed another two. The canonical authority branch
  passed authority, serving, live trust, initializer and focused TLS checks.
  Coordinated online signer activation and complete verifier retirement drains
  remain in progress. These are intermediate results, not final release gates.
- Tenant archive placement, reserved capacity and current administration limits
  are documented in [tenant audit retention](tenant-audit-retention.md).

- `c8d20ff` stores custody command identities/receipts and audit entries in
  independently addressed encrypted records. A bounded policy head and exact
  history accounting publish atomically with each new receipt/event and applied
  cursor. Current authorization and original replay actors/outcomes are unchanged.
  The full Raft library passed 38 tests at `b2fd97d`; the following fault test
  passed every storage-write failure and strict Raft Clippy. The latest custody
  filter passed 22 tests, and three engine custody/credential/expansion tests
  passed. Source, lockfile, executable and log hashes are retained in
  `docs/evidence/custody-point-tables-20260908`. Custody snapshot materialization
  and existing lifetime count/aggregate limits remain explicit unfinished work.

- `c8d20ff` Linux ARM64 production binaries built successfully in 13m05s with
  Rust 1.97.1 and no fixture features. Executables are preserved separately from
  the reusable build directory in the dedicated validation VM. The source,
  compiler, binary and feature-graph evidence is in
  `docs/evidence/linux-arm64-c8d20ff-20260908`. This remains an intermediate build;
  the newer live-backup and custody publication changes need their final gates.

- `6661559` streams custody table replacement into the same transaction as the
  snapshot manifest and applied cursor. Every previously committed permanent
  receipt and audit record must remain byte-identical in a later snapshot. Store
  tests passed 69 with one ignored external-service test, custody tests passed 23,
  and strict store/Raft/authority Clippy passed. Exact inputs and the corrected
  initial test API failure are in `docs/evidence/custody-stream-publication-20260908`.
- `26210c1` durably records exact local recovery cache/object ownership before
  publication and cleanup. Focused archive tests passed 11, actual local recovery
  passed two, and strict lint, production checks and formatting passed. Shared
  archive objects remain outside cleanup ownership. Evidence is in
  `docs/evidence/local-recovery-archive-cleanup-20260908`; Linux exclusive rename
  and final integration checks remain open.
- `c8d20ff` Linux x86-64 production binaries built in 25m56s, with preserved
  executable hashes and a fixture-free normal/build feature graph. This uses
  Rosetta translation inside the dedicated ARM64 validation VM. Evidence is in
  `docs/evidence/linux-amd64-c8d20ff-20260908`; it is neither native performance
  evidence nor final-source acceptance.

- `2558874` replaces custody history embedded in snapshot metadata with canonical
  typed receipt/audit records and authenticated terminal counts/digests. Encrypted
  point indexes validate exact history without a whole-history buffer; closed
  snapshots publish encrypted chunks atomically with records and the applied
  cursor. Prior stream/storage formats are rejected before rewriting storage.
  The preceding full Raft library passed 41 tests; final custody tests passed 25
  and strict Raft Clippy passed. Evidence and the corrected initial hostile-test
  failure are in `docs/evidence/custody-stream-format-20260908`. Fixed custody
  lifetime quotas and the closed transport budget remain the next storage work.

- `0735672` binds enrolled data/Control nodes and authority members to exact
  physical verifier identities; installations require the matching verifier
  roster. Authority tests passed 36, serving/types 18, TLS tests five, stored
  trust seven and initializer tests three, with strict workspace Clippy and
  production checks. `d190465` fixes the finite lifecycle fixture by resolving
  an ambiguous original completion against fresh quorum state before retrying
  the unchanged command; all four lifecycle tests pass with unchanged deadlines.
  Bound evidence is in `docs/evidence/physical-verifier-bindings-20260908`.

## Native resource reservation dependency

The financial integration consumer requires an ordered, durable reservation for
an exact finite prefix whose derived upper demand is 80,563 new documents and
2,558,574,592 canonical serialized bytes (up to 19,843 chunks, 128 profiles and
156 segments). These numbers exclude framing, index, journal and audit overhead
and are not capacity measurements. Existing staged admission reserves uploaded
chunk bytes; `NativeAdmission` is an invocation fence. Neither is a durable
reservation for final concurrent document/index/journal/audit headroom. The
resource-budget milestone must define server-accounted consumption, original
attempt/service binding, recovery/release and permanent outcome resolution;
a read-only quota getter or caller capacity claim cannot close this dependency.

- The immutable `7732c06` macOS functional attempt completed with a **failed**
  workspace gate. Four targets reported fixture governor/lifecycle rejection
  failures; raw output and all source/executable hashes are retained in
  `docs/evidence/frozen-functional-7732c06-20260908`. Formatting, Python, patched
  dependencies, strict workspace Clippy, fixture-free production graph and all
  production binaries passed. Later focused fixes are integrated, but a new
  full integration run is required; the failed attempt is never treated as pass.

- `ab9b203` removes fixed custody command/audit lifetime ceilings and the 1 MiB
  hard state ceiling. A checked 64-bit durable byte budget defaults to 64 MiB;
  `SetLimits` can expand exhausted capacity without discarding history. Closed
  transfer uses explicit installed `CustodyRaftConfig` capacity. At `b65e0b4`,
  custody tests passed 26, including 4,200 identities/8,400 audit records and an
  encrypted snapshot exceeding the old 2 MiB limit, atomic publication, reopen,
  exact replay and changed-input rejection. Three engine custody tests passed;
  final affected strict Clippy and production checks passed after removing one
  obsolete test struct update. Evidence and initial fixture/lint failures are in
  `docs/evidence/expandable-custody-budget-20260908`. Shared node disk admission
  and other permanent administrative tables still remain unfinished.
- `2eba1e3` makes every authority request capture one immutable signer instance.
  Installing the already activated replacement requires current administrative
  authority and the same live trust owner. Old response fences remain sealed.
  Authority tests passed 37, actual TLS replacement/old-response rejection passed,
  and strict workspace Clippy/production checks passed. Bound evidence is in
  `docs/evidence/immutable-authority-signers-20260908`; native key-file reload and
  coordinated global rotation remain separate unfinished work.

- `679a8e8` verifies historical backup snapshots through bounded encrypted point
  indexes and the canonical engine record rules. All 62 engine library tests and
  strict engine Clippy passed. Bound evidence and every retained stalled/failed
  attempt are in `docs/evidence/indexed-backup-verification-20260908`; earlier
  uncommitted-source tests remain explicitly qualified. This does not establish
  the 3 GiB/RSS gate or cross-member backup-key failover. Combined workspace
  checks passed at integration `3ee5787` and then `cf369cd`.
- `00b1446` permits exact retained target materialization only through a separately
  committed fresh Control intent and verified source-purpose digest. Authority
  materialization tests passed ten, Control lifecycle tests five, and strict
  workspace Clippy/fixture-free production checks passed. Exact evidence and the
  corrected assertion failure are in `docs/evidence/fresh-materialization-20260908`.
  The durable distributed recovery coordinator remains in progress.

- `7d8c817` adds explicit native reload of the exact activated operational signer
  from private descriptor/key files. Source tests passed four, actual TLS reload
  passed one and authority tests passed 37, with strict workspace Clippy and
  fixture-free production checks. Evidence in
  `docs/evidence/native-authority-key-reload-20260908` preserves initial failures.
  The replicated signing head and coordinated verifier/issuer drains remain open.
- `ee0b1e0` includes typed Control recovery records in canonical snapshots and
  moves cold-history semantic verification into owned blocking workers. Snapshot
  tests passed 14, backup tests ten, and affected strict Clippy/production checks
  passed. Evidence is in `docs/evidence/recovery-records-cold-workers-20260908`.
  The distributed recovery reducer and dispatch remain under implementation.

- Frozen `3ee5787` native Linux ARM64 functional validation completed **failed**:
  479 workspace tests passed, three failed and two were ignored. The failures
  cover ambiguous voter replacement observation, resource-destructor timing and
  overlapping restore reservations; the last also reproduces in isolation.
  Formatting, Python/dependency checks, strict workspace Clippy and all three
  fixture-free production binaries passed. Exact source, logs and executable
  hashes are in `docs/evidence/frozen-linux-arm64-functional-3ee5787-20260908`.
  Binaries are preserved separately in the dedicated VM. Subsequent fixes require
  a fresh final-source run; this failed attempt is never substituted by a pass.

- `ad71568` removes target-journal lifetime count caps and the 256 MiB metadata
  ceiling. Checked 64-bit counts and configurable byte capacity retain completion,
  activation and permanent-stop reserves. Actual encrypted exhaustion, drained
  expansion, original retry, full-budget stop/restart and unsupported-head
  rejection pass; nine materialization-filter cases and affected strict Clippy
  pass. Combined `a59ddb4` passes fixture-free server checks and strict runtime
  private-key validation. Evidence is in `docs/evidence/expandable-target-journal-20260908`.
- `5859d8e` adds a replicated authority signing head, explicit staged activation,
  generation fences and current administrative outcome resolution. Authority
  tests pass 40, actual TLS transition passes, and strict workspace/production
  checks pass. Evidence is in `docs/evidence/replicated-signing-head-20260908`.
  Complete verifier enrollment, remote acknowledgments and global retirement
  drains remain unfinished.
- Exact voter replacement and actual restore-worker drain regressions pass on
  their recorded macOS sources. Evidence is in
  `docs/evidence/exact-voter-replacement-20260908` and
  `docs/evidence/restore-worker-drain-20260908`. These do not replace the failed
  frozen Linux workspace gate.

- `9f870cd` and `cc7fbeb` provide explicit shared installed scratch disk admission
  for encrypted spools and derived indexes. Core store tests passed 79; integrated
  store tests passed 80, Raft 44, snapshot filters 15, backups ten and corrected
  standalone/recovery/signer filters eight. Strict workspace and fixture-free
  checks passed; combined `42b9fba` workspace check passed. Evidence is in
  `docs/evidence/shared-scratch-disk-core-20260908` and
  `docs/evidence/shared-scratch-disk-callers-20260908`, including failed and
  zero-test attempts. Persistent disk/native reservations remain unfinished.
- `b002771` hands off restore workspace after actual index drain and retains it
  through target publication, resolving the default 512 MiB overlap without
  raising budgets. Actual encrypted restore/reopen, eleven backups and the real
  three-runtime TLS fixture pass, as do strict workspace and production checks.
  Evidence is in `docs/evidence/restore-reservation-handoff-20260908`; fresh
  Linux integration, owned blocking publication and 3 GiB gates remain open.

- `f3c0185` adds durable Control recovery preparation/materialization and stop
  orchestration with typed native API, SDK and CLI. Replicated journal, real
  mTLS Control/issuer, snapshot, deadline and authorization cases pass along
  with strict workspace and production checks. Bound evidence and retained
  failures are in `docs/evidence/control-recovery-preparation-20260908`.
  Initialize and later phases plus expired non-target dispatch remain open.
  Combined `40e7154` workspace check passes.
- The frozen functional runner now includes a separate workspace documentation
  test gate. On `8e90ff2` macOS, eleven documentation tests pass; evidence is in
  `docs/evidence/workspace-doctests-20260908`. Native Linux ARM64 full functional
  validation of that exact source finished failed, as recorded below.

- `f401a09` publishes restore state in an owned blocking worker that retains the
  original finite invocation, bootstrap lock, source/target stores and workspace
  reservation through actual disk drain. Four restore cases, deadline queue,
  real three-node TLS lifecycle and local recovery pass with strict/production
  checks. Evidence: `docs/evidence/owned-restore-publication-20260908`.
- `c1dc8b0` freezes explicit physical verifier enrollment during signing rotation.
  Authority tests pass42 and native TLS passes, with strict/production checks.
  Evidence: `docs/evidence/frozen-verifier-roster-20260908`. Current remote
  acknowledgments, live Control registry binding and full issuer drain remain
  unfinished. Combined `97a14cd` workspace check passes in130seconds.
- Candidate packaging (`f084e03`, `531d86e`) retains compiled dependency identity,
  exact source/binary/log provenance, normalized archives, SPDX Cargo inventory,
  original notices, referenced author lists and hardened systemd units. Sixteen
  Python tests pass, including tamper/relabeling rejection and deterministic
  archive assembly; conservative metadata license provenance passes438packages.
  These are development checks. Actual end-to-end candidate production assembly,
  OS/OCI SBOMs, OCI images, reproducible compiler builds and release acceptance
  remain open. Procedures are in `docs/release-artifacts.md`.

- Frozen Linux ARM64 `8e90ff2` finished with499workspace passes, three failures
  and two ignored tests. All other gates passed, including doctests, strict
  Clippy and production builds (1110.499seconds). Raw source/binary-bound evidence
  is in `docs/evidence/frozen-linux-arm64-functional-8e90ff2-20260908`. This failed
  historical attempt cannot be promoted by later fixture fixes.
- `cabebf8` completes current target-voter materialization, initialization and
  signed completion orchestration. Evidence is in
  `docs/evidence/control-recovery-quorum-20260908`; source fencing, activation and
  publication remain later work. Exact audit/recovery fixture corrections and
  their unavailable historical binary hashes are recorded separately in
  `docs/evidence/control-fixture-resolution-20260908`.
- `c50ad3b` binds every staged operation to the immutable original resource and
  principal. Native two-principal/renewal, restored lineage, SDK, ordered stop,
  replication and encrypted backup gates pass. Evidence and failed earlier
  attempts: `docs/evidence/staged-original-scope-20260908`. The additional exact
  append fixture and its unresolved earlier status failure are preserved in
  `docs/evidence/history-exact-append-20260908`.
- `49c9338` requires exact partition credential-file coverage and preserves one
  credential snapshot across each original endpoint attempt. Configuration and
  actual native/authority TLS gates pass. Evidence:
  `docs/evidence/partition-credentials-20260908`. The separate restart Fence
  fixture resolution is in `docs/evidence/restart-fence-resolution-20260908`.
- `42c018e` adds an owned current Control quorum observation, permanently closed
  on failed/canceled checks or release. Three encrypted quorum tests and scoped
  strict/production checks pass. Evidence:
  `docs/evidence/current-control-fence-20260908`. Fresh physical registry binding,
  remote acknowledgments and full rotation retirement remain required.
- Packaging source531d86e test/provenance checks and earlier failures are retained
  in `docs/evidence/release-packaging-20260908`. No final candidate package has
  yet passed end-to-end assembly and deployment.

- `bf9f240` independently authenticates planned source application retirement and
  custody receipt verification, and dispatches the exact unavailable-source
  issuer fence. Seven engine lifecycle tests, actual TLS backup/retirement and
  strict workspace checks pass; final fixture-free check remains pending after
  the custody split. Evidence: `docs/evidence/control-source-fencing-20260908`.
  Phase-time retirement deadlines and complete activation/publication remain open.

- `42bf607` adds a pinned native acceptance workflow, exact gate-command
  verification, host provenance, a dated Debian package snapshot and an OCI
  recipe that verifies binary hashes and architecture. Sixteen Python tests and
  native macOS host preflight pass; the corrected workflow passes actionlint.
  The initial lint failure and source-qualified results are retained in
  `docs/evidence/candidate-workflow-20260908`. Actual workflow execution, image
  builds, final candidate assembly and compiler reproducibility remain open.

- `4cc27db` replaces schema activation and retirement lifetime record-count
  ceilings with exact checked 64-bit byte budgets. Terminal outcome capacity is
  reserved before publication, source fencing or positive Raft commitment;
  exhausted identities remain exactly replayable and budgets can expand beyond
  2 GiB. Twenty-three engine cases and all45Raft tests pass, followed by strict
  workspace Clippy, fixture-free server checks and formatting. Source-qualified
  evidence and the initial Clippy fixture failure are retained in
  `docs/evidence/permanent-history-byte-budgets-20260908`. Resident permanent-map
  migration, persistent disk admission and native import reservations remain open.

- Recipe `42bf607` built the pinned Linux validation image and passed an initial
  native ARM64 runtime-image and exact systemd data-unit smoke with historical
  `8e90ff2` binaries. Offline initialization, native audit/credential access,
  encrypted backup verification, TLS reload, restart and drained shutdown pass.
  The original 2 GiB work-admission rejection and same-session success after a
  clean 4 GiB restart are preserved. Both units pass static verification; the
  authority service was not run. Evidence:
  `docs/evidence/linux-image-systemd-smoke-20260908`. These recipe checks do not
  approve the failed historical workspace source or close final OCI/SBOM,
  compiler reproducibility, capacity and endurance gates.

- `8c99af9` coordinates permanent issuer activation, exact StopActivation
  resolution, all-voter fresh startup and signed local confirmations. Planned
  retirement receives its finite cutoff at the actual source-fencing phase;
  activation voter comparisons include physical verifier identity. Ten lifecycle
  and fifteen snapshot tests, two focused regressions, strict workspace and
  fixture-free checks pass. Evidence:
  `docs/evidence/control-recovery-activation-20260908`. Actual target processes,
  route publication and expired original Complete resolution remain open.

- `82a9e3c` publishes exact current-leader Control signer Stage and forward
  Activation directives to the installed physical verifier. Forty-three
  authority tests, actual private-admin TLS, strict workspace and fixture-free
  checks pass. Evidence: `docs/evidence/remote-control-signer-20260908`.
  Follower authorization, durable global coverage, revocation and issuer drains
  remain open, including global winner/abort binding of the older issuer-local
  StopStage path. The remote path rejects StopStage and retirement.

- `c53aeb4` makes live native/MCP benchmark requests read one fresh owner-only
  credential file snapshot per request and rejects the old environment-token
  contract. Two regressions and strict benchmark checks pass; evidence is in
  `docs/evidence/live-benchmark-credentials-20260908`. This prepares external
  renewal for long runs; it does not close the matrix or endurance gates.

- `c951fe9` integrates exclusive manager ownership of coherent document/ID roots,
  shared archived payloads, retained-version accounting and bounded selected
  page values. Committed publication expires over-budget leases synchronously;
  response fences reject expired snapshots without changing committed writes.
  All eleven frozen gates pass before and after the permanent-counter merge,
  including actual native pages and encrypted history backup/restore. Evidence:
  `docs/evidence/bounded-snapshot-lease-ownership-20260908`. Final integrated
  release, 3 GiB and sustained resource-pressure gates remain open.

- Frozen native Linux ARM64 `d403c55` failed its workspace gate while linking
  server tests: kernel/cgroup evidence confirms an OOM kill under the 7 GiB
  container limit. Toolchain, formatting, Python, patched dependencies and
  documentation tests passed; remaining gates continue. This attempt cannot
  produce a candidate. The reference memory allocation/preflight must increase
  before a fresh frozen run; the failed source/logs remain unchanged.
  Launch provenance and the passing combined macOS compile check are in
  `docs/evidence/frozen-linux-arm64-d403c55-launch-20260908`. This is not a
  completed functional result or final release acceptance.

- `4f5550f` raises the functional host requirement to 15 GiB effective memory
  and the reference VM template to 16 GiB, checking visible Linux cgroup limits
  before expensive linking. Eighteen Python tests and actual macOS preflight
  pass; the running 7 GiB container is correctly rejected. Evidence:
  `docs/evidence/functional-memory-preflight-20260908`. The failed `d403c55`
  attempt retains its original allocation while its remaining gates finish.

- `1b35c28` and integration `f44133a` publish the normal Control topology change
  and permanent recovery phase outcome in one ordered apply. All exact target
  confirmations precede publication; topology CAS rejection and expired phase
  supersession are permanent, and replay preserves a later authorized route.
  Lifecycle13/13, snapshots15/15 and strict/production checks pass within the
  recorded source scopes. Evidence: `docs/evidence/control-recovery-route-20260908`.
  Expired completion resolution and actual target-process recovery remain open.
- `786bffb` replaces the staged lifetime record ceiling with checked64-bit byte
  budgets, exact used/reserved counters and original terminal-outcome headroom.
  All9 frozen focused gates pass, including encrypted history backup/restore.
  Evidence: `docs/evidence/staged-history-byte-budget-20260908`. Terminal records
  are still resident; no point-table or million-record capacity result is claimed.
- `fd8b270` requires issuer-local signer changes to bind the exact committed
  global stage and activation winner. Local abort cannot bypass a global winner;
  first publication retains its original current-policy/term/physical-member
  response fence. Authority45/45 and actual native TLS1/1 pass, as do strict and
  production checks. Evidence: `docs/evidence/issuer-local-global-winner-20260908`.
  Global coverage, revocation, abort and full issuer retirement remain unfinished.
- Frozen Linux ARM64 `d403c55` is terminal and failed: the workspace linker was
  killed by the7GiB container memory ceiling. All other10 gates passed, including
  the fixture-free production build in834.847s. All original logs and executable
  hashes are in `docs/evidence/frozen-linux-arm64-d403c55-terminal-20260908`;
  no candidate was produced. The subsequent owned VM expansion to16GiB is bound
  separately in `docs/evidence/linux-reference-memory-expansion-20260908` and
  does not amend the failed result. A fresh complete run is required.

- `036eeff` isolates the native network benchmark from all server/engine/store
  fixture dependencies. Embedded and loopback fixture capabilities are explicit,
  historical matrix reports declare that scope, and frozen functional gates now
  require the production network driver graph/build plus actual compiled-feature
  and executable validation. Two credential tests, strict workspace Clippy,
  formatting and all19 Python tests pass. Combined `b3c2c45` all-target/all-feature
  workspace check passes in65s. Evidence is in
  `docs/evidence/production-network-feature-isolation-20260908`; no new native
  capacity or final production benchmark execution is claimed.

- `2466c1f` adds the fixture-free native capacity driver: checked 64-bit corpus
  totals, bounded absent-only batches, durable original-command journaling,
  exhaustive body verification, and resource/principal binding across JWT
  renewal and receipt lookup. Four capacity and two network tests, client-only
  strict Clippy, Python19, formatting and actual dependency graph pass. Evidence
  is in `docs/evidence/native-capacity-driver-20260908`. This is not a real 3 GiB
  load, a compressibility measurement or a live production gate; the key-only
  receipt RPC limitation remains explicit.

- `fbae79f` adds actual-container preflight and terminal-state retention to the
  release workflow, plus hashed per-gate cgroup observations required by the
  packager. Twenty Python checks and workflow YAML/bash syntax pass; an idle
  native Linux container reports its actual15GiB/zero-swap ceilings. Failures and
  scope are in `docs/evidence/release-cgroup-provenance-20260908`. The hosted
  workflow and pressure/OOM injection are not claimed by this checkpoint.

- `0aaaae5` keeps the historical fixture matrix's scope and input hash in derived
  capacity JSON/Markdown and explicitly marks production acceptance false. All20
  Python checks pass; no new benchmark measurement is claimed. Evidence is in
  `docs/evidence/historical-capacity-scope-20260908`.

- `b5ad88d` adds positive resolution of expired Complete through a fresh exact
  signed inspection, preserving the original identity/input/deadline and causal
  snapshot dependencies. Lifecycle14/14, authority45/45, snapshots16/16, strict
  workspace and fixture-free production compile checks pass. Full source/failed
  attempts and final fixture-only validation scope are retained in
  `docs/evidence/control-positive-completion-20260908`. Missing completion still
  remains unknown; negative resolution and actual three-target TLS acceptance
  are separate unfinished work.

- Frozen Linux ARM64 `3a8d512` completed with 545 workspace passes, one failure
  and two ignored tests. The three-node restored-runtime restart could not acquire
  its still-owned database lock. All other gates, including strict lint and
  fixture-free production builds, passed. Actual container exit1/PID0 and no-OOM
  counters, raw logs, executable hashes and observed shared-host overlap are in
  `docs/evidence/frozen-linux-arm64-3a8d512-terminal-20260908`. The workspace failure
  blocks packaging; no release candidate was produced. A separately identified
  audit-worker ownership gap is under validation, not an accepted explanation or
  a substitute for the corrected runtime gate.

- `a276db6` adds a private standalone diagnostic using existing, hash-verified
  fixture-free binaries, protected TLS readiness, native/MCP corpus checks,
  credential renewal, encrypted backup, restart and stopped local restore.
  Integration `e6c80c8` passes all 36 combined Python tests. Evidence is in
  `docs/evidence/small-native-runner-20260909`. These are pure runner checks;
  the first actual Linux diagnostic is still unrun. A diagnostic of the failed
  `3a8d512` checkpoint cannot change its workspace result or approve a candidate.

- Source checkpoint: service-audit initialization is now explicit and established
  daemon/operator opens require the retained canonical head even with no hot
  records. Bounded hot-range, pending-publication and current archive-root checks
  preserve the installed stream; HA node provisioning creates/drains the initial
  audit catalog. Four new source regressions and explicit fixture create/reopen
  phases are documented in [Service audit installation](security-audit-installation.md).
  Compilation and functional gates are pending; this does not close release or
  retention acceptance.
