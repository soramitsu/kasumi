# First production release goals

Status: **active; release not accepted**. Established 2026-09-20 from the
[complete approved plan](first-release-plan.md). That plan is the requirement
baseline; this document supplies workstream goals, dependencies and completion
criteria under the existing [release ledger](production-release.md) and
[acceptance checklist](release-checklist.md).

The 2026-09-24 instruction to implement Kasumi's own key-value engine supersedes
this document's redb-backed G02 direction. The active replacement criteria are
in [native KV engine goal](native-kv-goal.md); historical redb checkpoints below
remain evidence of earlier work, not the target architecture.

## Release contract

This is Kasumi's first release. **Backward compatibility is forbidden.** Replace
superseded APIs, configuration and storage formats directly. Update supported
callers and writers together; remove compatibility decoders, aliases, migrations
and fallback paths; explicitly reject unsupported inputs. Preserve the document
model and supported Rust, gRPC and MCP interfaces without preserving obsolete
prototype shapes.

The earlier compatibility audit found nested administrative DTO leniency,
noncanonical ordinary Raft command replay and omission of the local JWT
access-use claim (`target/first-release-compatibility-audit/README.md`). Current
`master` source closes those three scoped findings; source-bound reviews are in
`target/g01-admin-dto-strict-candidate/REVIEW.md`,
`target/g01-ordinary-raft-replay-audit-20260924/README.md` and
`target/g01-jwt-strict-candidate/README.md`. Their current-source release
qualification and the wider compatibility audit remain open.

Keep Apache-2.0, Rust 1.97.1, owner-only installation files, loopback listener
defaults, TLS 1.3, one-hour local JWTs and fixture-free production builds.

The latest user instruction requires all work in `/Users/mtakemiya/dev/kasumi`
on `master` only. This overrides the original worktree direction in the approved
plan and the stale location in the active goal's stored objective. Do not create
or switch branches or worktrees. Preserve pending source and historical evidence;
transfer prior work into master before resuming edits or builds. Parallel agents
must use disjoint file scopes in this same checkout.

## Tracking and completion

There is one active release objective. G01–G14 are its implementation goals, not
independent release approvals. Every goal remains open until its implementation
is integrated, its required final-source validation passes and its release
artifacts or operating documentation are usable. Record focused progress and
source-bound evidence in the release ledger; never turn a source-only change,
prepared command, historical pass or candidate package into final acceptance.

The later `master` checkpoint adds a G04 cursor bound to both the frozen
snapshot head and preceding page boundary (focused client and protected-TLS
server tests pass 1/1 each), and a G10 protected durable recovery-status point
read (standalone TLS test passes 1/1). A later installed three-node protected
test observes an exact committed `Prepare` point record twice; terminal
recovery remains pending. The latest G01 exact-byte cutovers pass a full serial
Raft library **81/81** and authority library **66/66** on source-bound
checkpoints; the later key-catalog, host-keyring and signer-trust changes pass
full serial store library **408/408 runnable cases**, with two ignored.
Combined workspace check, strict Clippy and formatting pass. The later engine
suite has one initial-leader fixture timeout, while that case passes alone;
clean engine and complete combined qualification remain open. A G09 Control
effect-marker prerequisite now passes focused marker and receiver tests, but
its synthetic Control lifecycle fixture and signed first-membership chain
remain open.
The latest selected checkpoint-row cutover passes four focused current-byte
cases and one physical restart case; strict combined workspace Clippy passes
on that source. Two serial six-case G09 lifecycle attempts still fail under
replicated Control leadership changes (4/6 and 5/6), despite each initially
failed name passing alone. The target envelope/status patch and bootstrap
manifest revision 2 remain unapplied after independent HOLD reviews. G01 and
G09 are open; final-source suites and installed fault tests remain pending.
The later one-send Stop fixture rerun passes **2/6**: two exact preparation
timeouts and two stale-leader phase reads. The approved G01 manifest-only cut
passes its engine and server focused cases **1/1** each after the native KV
read-bound mismatch was corrected. The G07 signer receipt-resolution fixture
passes **1/1** focused, while its full authority cohort remains open. The G09
lost-ack marker test is applied and passes **1/1** focused; the complete
seven-case lifecycle cohort passed **4/7** before the exact-preparation replay
repair; the latest rerun passes **3/7** and exposes more cached-route assertions
during leadership changes. G09 remains open.
The G01 deployment binding admission bound and G09 positive signed
first-membership path remain open. The evidence ledger records exact source,
failed logs and review hashes.
An independently reviewed test-only current-leader reread replaces the
stale-leader phase assertion. The later exact replay and negative-preparation
fixture changes each pass their focused case, but the seven-case rerun still
has four failures around cached-route reads and negative outcome responses.
These require verified resolution without replaying a consumed effect ticket.
The native KV cutover compiles as a crate, but read-only reviews found close
custody and failed-owner negative-read bugs requiring fixes and regression
evidence. G02 remains open.
The current native KV close-entry, failed-owner read-fence, FileBackend native
close and public repeat-close-report slices are applied on this mandated
`master` checkout. Locked offline KV tests pass **31/31 unit and 6/6 crash**;
the immediately preceding source passed all **412** runnable store library
cases with two ignored, and its repeat-close successor is under a full store
rerun. Production registered-owner caller adoption and final-source release
qualification remain open. The independently reviewed G09 test-only leader
read/negative-response fixture improves the serial lifecycle cohort to **5/7**;
two cached-leader operations still return `Unavailable`, so G09 remains open.
The G01 deployment admission candidate and its structural preparse revision
remain held because retained typed allocation ownership and several installed
readers are not yet covered. Source-bound logs and reviews are in the
integration evidence ledger; every G01–G14 goal remains open.
G11 declared functional-evidence export and mode-preserving tar readback pass
their 149-test Python checkpoint. Native workflow tar/producer uploads, exact
Cargo executable and compiled-feature replay, and the downloaded-tar collector
are applied; after correcting the synthetic package fixture and a feature
inventory false-pass, complete repository Python discovery passes **168/168**.
An independently reviewed G11 owned-assembly raw tar, producer and failed-attempt
transport prerequisite is applied; its 15 focused tests and workflow syntax
checks pass. The complete Python suite passes **183/183** on that source. A
reviewed post-download projection is also applied: its eight focused tests and
complete **191/191** Python discovery pass, but it always reports
`unqualified` and keeps host and attempt claims unverified. Native
upload/download, authenticated host evidence, durable failed-attempt custody
and semantic adapters remain pending. A reviewed G10 test-only assertion now
checks the full changed membership epoch and 129 fresh groups in the protected
HTTPS response; its focused native rerun passes **1/1**. The serial G07 authority library
run failed **61 passed, 3 failed**. Focused owner-zero, signer and
materialization corrections pass; the target-stop case passes 1/1 after a
test-only reopen leader-convergence correction, and the subsequent full
authority library passes **64/64** before the later G09 journal-format change.
The format-2 source's first 13-case materialization rerun passed **12/13**;
after a strict Raft-core shutdown-classifier correction, the named case and
the complete serial authority library pass **1/1** and **65/65** respectively.
G01's formerly unbounded custody case now passes
1/1 in 403.88 seconds after bounded encrypted scratch batching; the
uninstrumented full Raft library suite subsequently passes **78/78**. Exact
patches, logs and hashes are
in the [integration evidence](evidence/installed-disk-integration-20260923/README.md).
Every G01–G14 row below remains open.

The failed-opening recovery revision 8 passed its frozen 46-phase native macOS
cohort and its 56-file application was verified on this `master` checkout.
Service/G07 and G10 physical-capacity slices have also been applied, followed
by a G07 ordering and shutdown correction. The first combined all-target check
found server integration compile errors; a three-file repair now compiles and
strict workspace Clippy passes on that source checkpoint. Subsequent exact
applications add G07's API fixture and managed-directory repair, G11's owned
assembly launcher and selected-primary adapter slice, and G02's non-consuming
registered-opening close. A four-file G11 owned dependency-review runner is
also applied and its three synthetic runner tests and 18 checker regressions
pass; native upstream suites and advisory evidence remain outstanding. A
further one-file G07 fixture correction passes
three focused normal-stack local-recovery cases while preserving the prior
failures. Two later unfiltered all-features server attempts remain failed:
one stalled after local-recovery fixture failures, and one exposed same-process
local-recovery/RPC failures before an audit TLS fixture stack overflow. The
process-wide local-operator startup registry retained a cancelled task in a
two-test reproduction. Explicit fixture drains now pass the entire module
**10/10 in one process**. Test-only audit TLS and runtime-lifecycle stack
repairs pass their focused normal-stack cases. A timing-invalid authority RPC
assertion is corrected, and a separate intermittent lifecycle fixture timeout
now bounds each real quorum probe; the authority→lifecycle pair passes **2/2 in
one process**. The full server cohort remains open.
At that checkpoint, all **122/122** repository Python tests passed on the
then-applied source. Complete qualification of the latest combined source and native
multi-platform acceptance remain pending. G02's production redb transaction
adoption, G05's
durable backup index and G11's remaining semantic adapters and native assembly
still require implementation and validation. No row below is closed by these
scoped results.

The later `master` development slice passes pinned all-target/all-feature
workspace checking, strict Clippy, formatting and focused G05/G07/G08/G10 cases;
the [integration evidence](evidence/installed-disk-integration-20260923/README.md)
records the exact logs, failures and source scopes. The unchanged 512-row
restore test passes twice after bounded terminal batching, but its transaction
memory admission and failed-owner custody are unproved. G05 still lacks a durable
backup destination binding/index; G08/G09 still lack class-bound durable
dispatch grants and safe resume. At this earlier checkpoint G10 still lacked an
installed healthy more-than-128-group readiness result; the later focused
129-group pass is recorded under G10. Its other observations and the complete
combined server/workspace, native platform, installed HA, capacity, endurance
and artifact gates remain open. A subsequent sequential server run reported
168 passes and four failures before a stack-overflow abort; focused corrections
pass for the backup CLI stack and shared-owner directory cases, while replicated
runtime failures and the retired-source same-process interaction remain open.
The G08 SourceRetirement marker cases and G07 lost abort-response case pass
their focused scopes; G02's unsafe retained-close candidate was not applied,
and G05's physical binding is still design-only. None of G01–G14 is complete.
The next sequential server-library run reached 173 passes and three failures
before a standalone ownership fixture stack-overflowed; its raw log is retained
in the [integration evidence](evidence/installed-disk-integration-20260923/README.md).
All five standalone ownership cases now pass together after test-only stack
isolation. A corrected election/read deadline precondition reached the installed
three-node recovery loop, but that focused case still failed at its original
240-second deadline with no positive target materialization. A sequential
diagnostic rerun captured exact failures before another standalone provision
fixture stack-overflowed: 156 tests reported passing, five reported failing,
and the process aborted before completing the 222-test library. The five were
an uncertain authority enrollment result, an uncertain initial write in spare
replacement, split issuer election before three-node recovery, a partial-sweep
observability assertion, and a provisioning fixture path outside its canonical
installed accounting root. The [integration evidence](evidence/installed-disk-integration-20260923/README.md)
records the source-bound log. A read-only exact-receipt correction for the
authority test, canonical provision paths and test-stack corrections, and a
fail-closed observability sweep assertion are applied. Their focused tests now
pass **1/1**, **3/3**, and **1/1**, respectively; runtime recovery and complete
same-process qualification remain open. Strict first-release DTO and committed
command replay tests pass their initial focused scopes, with additional
combined-source validation pending. None is release acceptance.
The local issuer now rejects a signed token missing its first-release
`token_use: "access"` claim; its real issuer/revocation fixture passes. A retained
database blocking child now reports the original typed preparation error after
caller and drain-waiter cancellation, with a focused passing regression. Other
G07 child paths remain open. The Raft network adapter's premature soft-TTL
abort was replaced by OpenRaft's original hard deadline; installed quorum and
recovery verification is still failed. A focused three-node run got past issuer
startup but exhausted its recovery operation deadline before target dispatch
while Control lacked a leader. The exact log is in the integration evidence;
neither the prior 240-second materialization stall nor this earlier Control
churn is resolved.

A further focused installed three-node diagnostic failed at tenant registry
readiness with split Control voters. Its bounded timing probes observed 170
append hard timeouts at 250 ms and 93 five-second accepted TLS audit timeouts;
the probes were removed afterward. The pinned peer client was found to lack
HTTP/2 ALPN, while production reqwest enabled HTTP/2 only for dev builds. An
HTTP/2 correction is applied; the real pinned-mTLS transport suite passes
**2/2** with observed HTTP/2 and the production-only binary check passes.
An earlier installed three-node rerun failed at the unchanged recovery deadline
in `Prepare` because the dispatch digest included Control-local credentials.
The reviewed semantic digest correction now passes its native mTLS case and
advances that installed fixture to `Materialize`, but target node 1 then
repeatedly reports an unresolved exact outcome until the same deadline. A
bounded test-only cause probe identified a generation path outside its installed
NodeDisk accounting root: canonicalization changed the configured root spelling.
The path correction preserves that spelling while checking canonical identity.
Its installed rerun verified all three materialized voters, then failed in
`Initialize` when a new Control phase encountered the target's durably bound
earlier initialization identity. Exact earlier-outcome resolution is still
missing; HA remains open. The reviewed managed-absence StopLocal correction
passes seven focused server shutdown cases. The retired-custody Raft
route now derives the original application bootstrap fingerprint from validated
custody and fences it on custody access. Its new fixture passes, but the
three-test retired-source module still fails an existing preparation-panic
deadline, and current peer membership fencing remains open. A reviewed G02
direct-header workspace admission slice is applied and passes **233/233**
serial vendor library cases plus its focused engine/store checks. Vendor
strict Clippy passes after a narrow equivalent style correction. A reviewed
one-shot registered-opening Ready proof passes 20 focused cases. A bounded
retained-reader prerequisite is now applied and passes 215 vendored redb library
tests; its registered census, complete admission and production caller adoption
remain open. The reviewed registered-reader census is now also applied: its
full serial store library suite passes 388 runnable cases with two ignored;
two later panic/credit tests pass the 24-case opening module. Strict all-target
types/store Clippy passes after the dormant Control backup binding value was
applied. Production reader adoption remains open.
The reviewed fixed catalog input-buffer prerequisite is applied with an
exact-limit regression; its three focused tests and the full serial store
library suite pass (393 runnable cases, two ignored), and strict types/store
Clippy passes. It does not admit redb write transactions. A source audit found
unleased cache pages and transaction/terminal allocations, so production G02
writer cutover remains open.
The combined MCP mutation/renewal response-fence regression passes; installed
process custody still needs qualification. The full serial engine library run
has one serving-expiry quorum failure among 254 passes and one ignored case;
a fixture-only correction passes three focused repeats, while the full library
cohort has not been rerun on that newer source. All release goals
remain open.

On the later G05 source, the serial store library passes **395/395** runnable
cases with two ignored, and strict all-target/all-feature store/server Clippy
passes. The full serial types/engine rerun reaches **261 passed, one failed,
one ignored** in the engine; its serving-expiry leader fixture passes alone,
but the combined failure remains under diagnosis. Reviewed G05 owner-retention
prerequisites are applied, while the durable physical marker, mandatory
destination grant, Control claim and cleanup are not. At that checkpoint the
first G01 snapshot-JSON candidate and G05 staging fixture candidate were still
unapplied. Their reviewed successors are now applied and have the focused
results recorded below; neither closes a goal or qualifies a release candidate.

| Goal | Workstream | Dependencies for completion | Implementation | Final validation | Artifacts/docs |
| --- | --- | --- | --- | --- | --- |
| G01 | Integration, contract and truthful baseline | None | Open | Open | Open |
| G02 | Physical ownership and native Kasumi KV engine | G01 | Open | Open | Open |
| G03 | Streaming generations and bounded resources | G02 | Open | Open | Open |
| G04 | Retained history and audit dependencies | G02, G03 | Open | Open | Open |
| G05 | Durable backup ownership and cleanup | G02, G03 | Open | Open | Open |
| G06 | Historical keys and authoritative retention | G04, G05 | Open | Open | Open |
| G07 | Response fencing and retained task/drain ownership | G01 | Open | Open | Open |
| G08 | Credentials, endpoints and membership maintenance | G06, G07 | Open | Open | Open |
| G09 | Distributed/local recovery and exact deletion | G03–G08 | Open | Open | Open |
| G10 | Protected observability and complete readiness | G04–G09 | Open | Open | Open |
| G11 | Acceptance manifest, infrastructure and dependencies | G01 | Open | Open | Open |
| G12 | Native, installed and HA final qualification | G02–G11 | Open | Open | Open |
| G13 | Capacity, performance and full-duration endurance | G02–G12 | Open | Open | Open |
| G14 | Verified deliverables and release closure | G01–G13 | Open | Open | Open |

Dependencies govern acceptance, not when independent preparation can begin.
Packaging, runner provisioning, dependency tests and evidence tooling can proceed
alongside implementation. Qualification consumes the actual candidate packages
and binaries; G14 verifies their complete evidence before release closure.
G11 delivers the implemented and validated acceptance verifier and manifest
contract; G14 requires the fully populated passing manifest for the final release.

## Workstream outcomes

### G01 — Integration, contract and truthful baseline

- Preserve the approved plan, pending MCP work, historical independent-worktree
  evidence and failed attempts. Apply the first-release contract to every
  integration review on the mandated master checkout.
- Correct the latest frozen checkpoint to eight passing gates, one ownership
  gate with five failing fixtures, and 22 later unrun gates. Preserve the prior
  `32825cf` failure as historical evidence and the original `be2667d` run bytes.
- Create private fixture installation directories; leave production permission
  enforcement unchanged. Validate the corrected ownership cases and the retained
  successor cohort on a newly frozen revision with original mandatory cases and
  deadlines. Record exact results, unchanged source and actual process drains.

A reviewed first-release snapshot metadata cutover is now applied. It rejects
noncanonical manifest and coverage JSON, UUID aliases and writer-oversized
coverage on all identified Raft read paths. Its Raft library test build and
three new focused boundary cases pass. Its serial library run excluding the
historically long custody-capacity case passes **75/75**; the original full run
was stopped in that case after the next source correction was approved, so it
is not a full pass. The reviewed adjacent closed-manifest/retirement-projection
revision is now applied with size preflight before any application pending
snapshot write. Its two focused tests and updated **77/77** serial Raft cases
pass with the historically long custody-capacity case filtered. Strict
all-target/all-feature Raft/store Clippy passes on that earlier source.
Bounded encrypted scratch batching now lets the large case complete; the
uninstrumented serial Raft library passes **78/78** on the later combined
source (`target/custody-capacity-timeout-next/applied-full-raft-final.log`).
G01 remains open because its corrected frozen checkpoint, ownership fixtures
and exact successor cohort have not passed together on final source.
The later first-release source audit identifies alternate durable JSON bytes
accepted by current target-journal, storage-binding and Raft metadata readers,
without finding a live predecessor decoder in the inspected administrative
DTO, local JWT, recovery wire or snapshot paths. The exact-byte storage-binding
cutover is applied and its new negative/positive fixture passes **1/1**; the
complete serial store library passes **404/404 runnable cases**, with two
ignored. The independently reviewed format-2 target-journal exact-byte
reader is also applied; its complete open-test module passes **11/11** and
repository Python discovery passes **191/191** on that source. Generic Raft
metadata and custody point-row exact-byte readers are now applied as separate
independently reviewed first-release cutovers. Their three new Raft cases and
the server retired-bootstrap digest case pass focused; the combined complete
serial Raft library passes **81/81**. The wider compatibility audit, frozen
final-source integration and release acceptance remain open. The
[integration evidence](evidence/installed-disk-integration-20260923/README.md)
binds this result to its source and log.

### G02 — Physical ownership and native Kasumi KV engine

The active G02 target is the [native KV engine goal](native-kv-goal.md):
durable atomic batches and snapshots, crash recovery, corruption rejection,
owner-charged storage and explicit close custody, with all production callers
cut over and redb removed. The first release rejects older physical formats;
no migration, fallback reader or dual writer is permitted. Focused, complete
and final native-source qualification remain open. The redb records below are
preserved only as historical development evidence, not current G02 criteria.

The next storage-accounting slice is specified in
[installed storage admission](installed-storage-admission-plan.md). The shared
memory core, fixed reservation ledger and separately retained runtime facades are
implemented in master source. Pending changes now require the exact installed
memory core before production disk opening, charge persistent/scratch/device
metadata for its actual retained lifetime, and reject foreign-core construction
before mutation. The migrated workspace compiles; store and focused engine
successors pass. Caller, native and complete release qualification remain open,
along with directory accounting and every affected parent during namespace
mutation. The development evidence records the exact scope of each result.

The retained redb prerequisites pass all 134 vendor cases in attempt 132:
matching-database witnessed disposal preserves original outcomes while releasing
the actual settled transaction; fixed cache admission checks actual available
slots and retains physical growth and rollback uncertainty on refusal. Checked
page-list records reject malformed selected ranges before removal, and extraction
explicitly observes close failures. The format4/DATA400 successor is now applied,
with its first compile failure preserved in attempt 142. After the narrow compile
correction, attempt 143 passes all 142 vendor library tests.
It directly rejects older formats and the obsolete system-history table. Attempt
144 then passes all 148 vendor library cases with allocation-history removal
bounded to 400 page IDs before DATA reclamation can proceed. Current-system
metadata, COW workspace, savepoint restoration and reserved maintenance capacity
remain open. After two fixture corrections, attempt148 passes all 296 public
integration cases with cursor/API5 enabled, preserving the failed145/146 evidence.
Attempt 127 passed all 226 enabled store cases before the format4/reclamation
successors (two remain ignored); it does not qualify those later changes.
Attempt 150 passes strict workspace Clippy. Attempt 151 passes all 162 vendor
library cases after one-buffer allocator encoding, including seven new cases
that check exact bytes, untouched refusal buffers and actual allocation counts.
Complete transaction workspace and protected maintenance capacity remain open.
Attempt 152 passes all 226 enabled store cases after the allocator changes (two
remain ignored). The direct all-target/all-feature vendor lint run exposes an
API5 import error and strict test lints in attempts 153–154; their corrections
pass attempt 155. Attempt 156 then passes all 197 all-feature vendor library
cases, including eleven actual-backend tests of retained database opening,
bootstrap terminal/rollback/disposal, original failure identity and waiting close.
The opening primitive is applied; mandatory production census/adoption is open.
Attempt 157 passes all 204 all-feature vendor cases after direct removal of
obsolete allocator-key decoding and validation before typed traversal or repair.
Attempt 158 passes strict vendor Clippy on those combined changes.
Attempt 159 passes strict workspace Clippy, 160 passes workspace/vendor
formatting, and 161 passes all 296 public vendor integration cases across ten
targets with experimental cursor/API5 enabled. Each run preserves inventoried
source and records actual process-group drain. These component passes do not
close production adoption or release qualification.
Attempt 162 applies mandatory allocator payload validation and passes all 211
all-feature vendor unit cases. Borrowed views check nested lengths, summaries,
buddy overlap/merging, contiguous records, retained tracker capacity, safe
current-winner contraction and branch routing before typed decoding or repair.
The all-order producer and 16 native malformed-file cases pass. Attempt 163
passes strict vendor Clippy and 164 passes all 296 public integration cases.
Reachable-root allocation correspondence, total traversal/decoder workspace and
protected maintenance remain open. Attempt 165 applies an explicit reviewed
109-file provenance successor and passes the unchanged dependency verifier;
details and remaining qualification limits are recorded under G11.
The separate 49-file directory census candidate passes 37 native cases in its
second run with source/executable hashes unchanged and all five process groups
drained. It remains unapplied pending coherent managed mkdir/rmdir adoption. Its
mandatory file/subdirectory/work-step policy and retained cursor session replace
the old restart-on-exhaustion census design. The 1,331,918,436-byte owner layout
is an admission requirement, not a measured whole-process RSS bound. The later
51-file managed namespace candidate and generic-opening correction pass 49
scoped native cases, preserving the compile and four-case failure trials. Review
required the newly added generic parent acquisition to use the same retained
operation protocol; that correction passes both added cases. The new owner
geometry is 1,353,059,396 bytes, still not a whole-process bound. This candidate
remains unapplied pending aggregate session admission and coherent caller changes.
Production NodeDatabase adoption, complete admitted transaction workspace and
filesystem directory bounds remain open; these prerequisites do not close G02.
The corrected census/opening prerequisite passes 33 source-bound cases; its
shared-target stale-binary attempt remains a failed qualification, not test
credit. The aggregate namespace/session successor passes 67 scoped cases after
fixing both a classification race and pre-claim path allocation. Their revised
73-file target-only composition passes offline locked all-target/all-feature
workspace checking, strict Clippy, all 324 enabled store tests (two existing
ignores), and 17 Python smoke-script tests. It remains unapplied. A separate
retained file-custody candidate passes 132 selected tests with original outcome
and native-close failure custody; its composition with the 73-file prerequisite
is still pending. Production NodeDatabase caller adoption, now inventoried as
13 raw commit sites (nine persistent and four scratch),
complete memory bounds, configured-root and inherited-directory custody, and
canonical PageNumber decoder migration remain open. No candidate pass closes a
release goal.

The later cumulative 75-file storage, namespace and file-custody revision 6 is
now applied to the mandated `master` checkout with all recorded before/after
hashes and modes verified. Its [immutable qualification bundle](evidence/installed-disk-storage-namespace-custody-20260923-rev6/README.md)
records strict all-target/all-feature workspace check and Clippy, 336 passing
unfiltered store tests, zero failures, two existing ignores, all 14 focused
regressions, separate formatting, unchanged inputs and drained process groups.
Earlier revision 4 and 5 full-store failures remain preserved. This is a
prerequisite, not G02 acceptance: production caller migration,
failed-opening acknowledgement/recovery, complete memory admission and
configured-root/directory custody remain open.

The reviewed three-file filesystem-backup admission revision 5 is also applied
to `master` with its before/after hashes and modes verified. Its
[source-bound qualification bundle](evidence/installed-disk-filesystem-backup-20260923-rev5/README.md)
passes locked full-workspace check and strict Clippy, all 343 runnable store
cases with two inherited ignores, and separate formatting. This admits the
pending inode and extent before publication but does not complete whole-call
worker, ciphertext, stack or configured-root custody. G05 remains open.

The canonical redb `PageNumber` freeze 05 and its exact provenance update are
applied to `master`: all 163 source, policy and evidence paths match the reviewed
after hashes and modes. The official dependency-patch checker passes against
the combined source, including locked Cargo metadata and exact package
selection; its 18 Python regression tests also pass. Prior freeze-05 native
results remain component evidence, not qualification of this combined checkout.
The post-application workspace/native cohort and deeper reachable-root and
resource bounds remain open. No obsolete decoder or compatibility alias is
retained for the first release.

The first combined-checkout native trial is preserved as a
[failed and source-drift-invalidated attempt](evidence/installed-disk-actual-master-20260923/README.md).
Formatting, all-target/all-feature check, strict Clippy, test compilation and
46 binary inventories ran, but the unfiltered workspace command stopped at
authority 62 passed/one failed before the other 45 targets or doctests. Two
`Box::pin` additions to engine `service.rs` appeared during the run, so its
earlier phase passes do not qualify one frozen source set. The dependency
checker and all 18 regressions passed separately against the final observed
source. A one-file authority fixture correction now passes the exact original
case on the current `master` checkout with unchanged inputs and binary; the
full authority and workspace cohorts remain unrun after that correction. Those
two new production heap allocations also need admission review. At that earlier
checkpoint, the failed-opening, native-close and private opening-admission
successor was frozen only as
a target-only 46-file proposal with reviewed vendor provenance; it had not been
compiled or applied. Implicit scratch destruction, constructor failures,
production caller adoption and complete resource bounds keep G02 open.

The later two-file registered-opening close prerequisite is now applied with
exact [integration evidence](evidence/installed-disk-integration-20260923/README.md).
It seals admission, returns the retained close settlement without consuming the
owner, and preserves the original failed-close report for the existing explicit
recovery path. Its isolated overlay passes 16 focused opening and 368 runnable
store cases, strict store Clippy and formatting. Those results precede the
latest combined source; production constructor, transaction and reader adoption,
complete bounds and final qualification remain open.
The latest production-caller audit confirms that no `NodeStore` yet uses the
registered owner: its persistent reads, nine commits and Ready publication
still use the legacy aggregate, while three scratch commits require a separate
registered owner. The coherent cutover is the entire persistent `NodeStore`,
including actual read-view lifetime and owned queued writes; no constructor-only
compatibility route is acceptable.
The applied registered reader now holds an exact snapshot in the storage
census and returns admitted owned bytes, but no production read caller uses it.

- Require installed `NodeDisk` at every production storage constructor. Account
  for creation, growth, write, sync, shrink, deletion and directory publication
  through the same physical owner, including archives, journals and local backups
  under their configured roots. Remove production admission bypasses.
- Complete redb admission for construction, repair, writes, commit, compaction
  and close. Distinguish pre-publication `CapacityDenied` transaction rollback
  from `OwnerFailed` fencing on uncertain I/O or identity substitution. Reopen
  only after resources drain and a fresh census completes.
- Prepare allocation, bookkeeping, repair metadata and publication before the
  winning commit header. Use immediate durability and two-phase publication,
  fallible explicit close, non-allocating destructor fallback and settlement of
  retained growth after aborts. Test every allocation/publication boundary,
  rollback, interruption and owner failure.

### G03 — Streaming generations and bounded resources

The current-source audit in `target/g03-generation-publication-next/audit.md`
pinpoints the unbounded redb replacement transaction: snapshot install copies
every encrypted row while deleting old namespaces in one write transaction.
The existing read view has no generation pointer, so splitting that transaction
would expose partial replacement. A coordinated staged-generation writer,
pointer cutover, reader pin and bounded reclamation remain necessary; G03 is
open.

[Custody staging](custody-staging-plan.md) records the unimplemented bounded
transaction writer identified by the failed capacity diagnostic. It depends on
explicit memory admission and retained worker cleanup; the 4,200-command and
8,400-audit workload, durability and original deadlines remain unchanged.
The later 512-terminal-row restore passes its unchanged deadline twice with
bounded batches. The input cap is not a redb transaction memory bound, and
consuming commit/close APIs can lose the exact failed owner. The local
`target/snapshot-restore-deadline-candidate/follow-up-design/README.md` records
the retained-transaction/database and decoder-owner sequence still required.

- Replace whole-namespace replacement with generation-addressed typed records
  streamed into unpublished encrypted generations. Authenticate final checked
  64-bit counts, digests and dependencies; atomically publish generation pointers,
  custody bindings and the matching applied position for snapshots, Raft transfer,
  restore and administrative state.
- Reclaim abandoned/superseded generations in bounded transactions after readers
  drain. Share coherent document/ID roots, charge lease metadata and retained
  versions, and explicitly expire pressured leases while preserving their
  snapshot identity until expiry.
- Reserve maintenance separately from foreground work, initially serialize it
  per owner, and use bounded compaction and synchronized shrink without another
  full database copy. Reserve bounded Raft backlog and application workspace;
  committed entries under capacity pressure remain unapplied until recovery.
  Never manufacture a rejection or advance an unapplied position.

### G04 — Retained history and audit dependencies

The current-source archive threshold review in
`target/g04-archive-threshold-next/review.md`
finds the 8 MiB encrypted segment cap and 75%/50% maintenance hysteresis
already enforced in tenant and service paths. It is a source review, not final
replica-dependency, typed-API or native acceptance evidence; G04 remains open.

- Produce encrypted immutable audit segments of at most 8 MiB; start maintenance
  at 75% of the hot budget and drain toward 50%. Persist the exact pending segment
  before publication, verify it before proposing pruning, and require every HA
  replica to durably preserve the dependency before applying that transition.
  Carry dependencies through snapshots and replacement enrollment.
- Keep permanent command identities, receipts, incarnation/lifecycle history and
  session outcomes in encrypted point-addressed tables governed by disk budgets.
- Expose typed audit status/export/verification/capacity through Rust, gRPC and
  CLI with bounded pages and cursors bound to stream, range and snapshot; never
  silently restart pagination. Qualify outages, restarts and lifetime ceilings.

### G05 — Durable backup ownership and cleanup

The target generation root now retains its managed directory through cleanup;
the four-case shutdown module and seven persistent-directory cases pass. A
post-open root substitution fences the physical owner before a cleanup claim.
Backup-session intent still lacks a durable physical destination identity and
Control-backed session index, so alias changes across restart cannot safely find the
original namespace for status or cleanup. An exact namespace-binding value and
S3 constructor validation are applied as a dormant prerequisite; the type is
not yet a durable session/Control binding. An immutable Control claim/record
value is also applied with 24 passing types tests, but its public shape checks
cannot authenticate a source or create the missing Control point row. G05
now has a reviewed encrypted Control point-table scaffold. Its four focused
table/snapshot tests pass after two direct snapshot-writer test callers were
updated to the new signature. It changes the first-release snapshot format
directly and has no production claim command. A source-registry audit found
missing authenticated physical destination identity and a producer revision
race; full caller cutover, Control claim/readback and cleanup remain open. A
serial full types/engine run found one indexed-validation regression in a
twice-restored application snapshot (**258 passed, 1 failed, 1 ignored** in
the engine); the focused reproduction also fails. It is under correction,
and this scaffold is not yet qualified. Supplemental physical-reopen and
corruption tests are applied and pass **7/7** in the actual binding test group;
they do not supply the missing production Control claim. A reviewed two-hop
snapshot correction now passes its focused case; a full engine rerun stalled
in a credential/backup test that passes alone, and was preserved as failed
evidence. Full qualification remains open.

The later full serial store library passes **395/395** runnable cases, with two
ignored. The full types/engine rerun reaches **261 passed, one failed, one
ignored**; the sole serving-fixture timeout passes alone and is now instrumented
for its next same-process occurrence. Reviewed installed owner/directory
identity prerequisites and a strict fixed marker codec are applied. The codec
is dormant and grants no writer; its focused store tests pass **3/3**. A
test-only standalone staging fixture correction is applied after review. Its
first run hung in the panic case; a test-only lifetime repair retains the
installation directory through same-runtime owner drain, and the corrected
normal-stack group passes **5/5 in one process**. Mandatory marker enrollment,
operation-time verification,
source-authenticated Control claim/readback and exact cleanup remain open.
On the source with the marker codec and staging repair, the serial store library
passes **398/398** runnable tests with two ignored. A subsequent G06 archive
dependency validation edit requires its own relevant final-source checks.
An exact, bounded S3 destination index is now applied as a dormant prerequisite
(`target/g05-exact-destination-index/candidate.patch`, SHA-256
`8a11109f729275ff5d530c06fc02df339302610ee299073bc0ed96fa67a0ccda`).
The applied-source tests pass **5/5**. Registration rejects equal physical
namespaces across signing regions and overlapping S3 prefixes, including a
parent session-object/child direct-backup key collision; exact lookup never
falls back to an alias. No production caller installs or consults this index.
Filesystem destinations remain unregistrable until marker enrollment, and
source-authenticated Control claim/readback plus complete caller cutover are
still required. G05 remains open.
The filesystem marker audit at
`target/g05-marker-enrollment-boundary-20260924/README.md`
finds that the public destination constructor still opens an unmarked writable
root and has no authenticated installed-owner handoff. Marker publication,
operation-time verification and filesystem index registration therefore need
one coordinated fail-closed cutover before any first backup write.

- Resolve durable session completion and abort, publishing roots only after
  dependency verification. Cleanup must page boundedly and delete exact objects
  or S3 versions only inside aborted namespaces. Repeat passes to catch uploads
  arriving late.
- Preserve completed backups, audit archives and permanent session tombstones;
  qualify completion uncertainty, cancellation, restart and late-upload races.

### G06 — Historical keys and authoritative retention

The current source includes a dormant exact historical-provider resolver and
security descriptor, but no server caller installs a bound historical source
set. Backup, session, history and
audit reads still receive one writable/current provider. `ReadKeyRetention` is
absent from types, store, engine, server, client and proto, and G05's missing
durable session index prevents truthful complete coverage. The next coherent
slice is exact read-only provider dispatch, followed by a durable cross-category
dependency ledger and race-safe retention API; no fallback to the writable
primary is permitted.
A narrow first-release validation now rejects a zero archive wrapping-key
version; its focused case and full types library pass. This does not create
`ReadKeyRetention`, an authoritative dependency inventory or retirement grant.
The affected store archive module and engine service-audit retention case also
pass on that validation source.
The source-bound sequence in
`target/g06-historical-dispatch-next/implementation-sequence.md` confirms that
production still passes the writable provider to historical audit, backup,
session and history reads. Recovery input also lacks a committed historical
source-set identity. The read-only resolver, accepted recovery binding and
restore reader require one coordinated cutover; the dormant resolver alone
does not establish historical dispatch.

- Install a historical-key resolver keyed by exact authenticated wrapping
  identities, separate from the writable primary. Reject duplicate/ambiguous
  bindings and trial decryption. Bind historical provider identities into accepted
  recovery inputs; credential refresh cannot redirect accepted recovery.
- Add `ReadKeyRetention(scope, cursor, limit)` with at most 256 entries per page,
  exact key versions and referencing catalogs, sessions, backups, archives and
  recovery records. Missing/unavailable dependencies mean incomplete coverage.
  Retirement requires complete authoritative coverage and a final race-safe check.

### G07 — Response fencing and retained task/drain ownership

[Filesystem job ownership](filesystem-job-ownership-plan.md) records the remaining
unimplemented archive/backup child registry, pre-open disk fence, output-charge
handoff, constructor plumbing and shutdown order. A caller retaining a resource
charge does not by itself retain the actual child outcome.

The fixed startup-scope foundation is integrated in pending source. It admits
its core census and resource cells, preserves original outcomes through canceled
drains, and retains shared report charges. Production runtime/resource adapters
and a complete process shutdown traversal remain unimplemented; this primitive
does not close G07.

The fixed snapshot-child census is applied in pending source. Its reviewed fifth
revision corrects allocation retirement, completed-failure census release,
synchronous executor reentry under owner locks and output-custody loss during a
deferred callback panic. All seventeen runtime tests pass in development attempt
108; its serving-expiry cleanup failure has a three-case passing successor in
attempt 115. The required large restore and permanent-capacity cases remain
unqualified. Production
adapters, preparation fencing, shutdown traversal and precise operation/backend
memory bounds remain open. A retained handle alone does not close this workstream.

The G07 all-features API audit-failure fixture now asserts the original sealed
audit persistence error during teardown; its exact case passes. A two-file local
recovery repair uses tracked managed directories for generations and archive
cache. Subsequent test-only corrections preserve the prior failed logs and pass
the full ten-case local-recovery module in one process on the normal stack.
Audit TLS and runtime-lifecycle aggregate fixture stack repairs pass focused
normal-stack cases. The corrected authority and lifecycle RPC pair passes 2/2
in one process, after a separate intermittent quorum-wait failure was diagnosed.
An installed `NodeRuntime` TLS 1.3 MCP case now passes **1/1**, exercising a
committed mutation withheld before response release, original credential
expiry, `UNKNOWN_OUTCOME`, and renewed exact receipt/retry. It remains a
same-process fixture; separate-process and complete child-drain evidence is
open.
The [integration evidence](evidence/installed-disk-integration-20260923/README.md)
binds the receipts. Complete combined-source and process-custody qualification
remain open.
The MCP terminal response now rejects duplicate, invalid or conflicting explicit
Content-Length values before its final credential/family fence; the focused
server regression passes. A strict workspace Clippy run first found a
collapsible-if lint in that change; the equivalent correction passes formatting
and all-target/all-feature strict Clippy. Authority request observation also
had a separate lost-outcome path for timed-out or cancelled callers: the
reviewed bounded registry correction is applied. After two preserved
test-contract failures and a timing correction, the nine-case authority drain
module passes **9/9** in one process. These scoped changes do not complete the
installed drain contract.
The subsequent full serial authority library first failed **61/64**: two
fixture reopen waits included nonvoters and one strict target-shutdown
classifier omitted the exact sealed-serving diagnostic. Test-only corrections
preserve original receipt/status checks and pass each affected case; the
unfiltered serial library then passes **64/64 in 766.75 seconds** on the
pre-journal-format source. Installed process custody, complete typed drains and
final-source native qualification remain open.

- Materialize bounded terminal MCP responses under request ownership before the
  final credential/family check. Reject SSE. Withheld responses after mutation
  dispatch yield `UnknownOutcome`, resolved by the original command identity.
  Renewal never extends an existing request deadline.
- Retain actual children and terminal outcomes in a bounded task registry for
  authority commands, lifecycle, signer and membership work across cancellation
  and timeout. Complete and qualify the retained OpenRaft shutdown changes.
- Use one typed drain result across Raft, authority, custody and serving. Preserve
  core, ticker, blocking, network and storage-child outcomes; report drained only
  when actual ownership ends. Test cancellation, child panic and revocation.

### G08 — Credentials, endpoints and membership maintenance

Issuer/lifecycle/retirement pools now bound a single invocation to one mutating
RPC with exact read-only receipt resolution, and the focused real TLS regressions
pass. Recovery state requires a one-way effect marker and signed positive issuer
acceptance before an activation command marker. SourceRetirement, issuer,
activation acceptance and Control intent now consume committed one-use grants;
the recovery snapshot module passes 11/11 and receiver module 13/13. The
focused native source marker case and server API module pass. TargetCommand
still lacks an exact read-only outcome query, and cancellation after a marker
but before send can remain unresolved without an ordered no-admission proof.
The separate abort-retirement pool is one-send per invocation and its real
lost-response case passes across fresh client pools; independent-server and
coordinator-restart resolution remain open. G08/G09 require complete target
integration, typed uncertain outcomes and actual multi-node qualification.
The source audit in `target/g08-tls-replacement-next/README.md` confirms live
SIGHUP reload prevalidates listener candidates and preserves the old listener
on an invalid certificate/key pair. Stopped-installation certificate rotation
still renames four cert/key pairs separately, then commits Control and rewrites
profiles. Failure after the first rename can leave mixed generations across
restart; a durable generation bundle, pointer, overlap pins and recovery
journal are required before G08 can close.

- Qualify installed endpoint pools, renewable credential files, original-deadline
  routing, exact receipt resolution and fresh admission after authority expiry.
  Drain the old serving instance before reopening.
- Complete learner/voter, certificate, signer-generation and endpoint-trust
  maintenance and rotation. Invalid TLS replacements retain the last valid
  configuration and expose failure. Exercise maintenance under load and outages.

### G09 — Distributed/local recovery and exact deletion

An independent target-owner audit (`target/g09-owner-state-machine-independent-audit/README.md`)
found that the target journal and Raft apply cursor commit separately. A
positive Initialize outcome needs an exclusive exact-phase owner and an
immutable first-membership fact retained through snapshot installation;
current membership and RAM call jobs cannot establish the original effect.
The exact transport-envelope proposal remains unapplied until its Control,
target and Raft evidence paths are integrated. G09 remains open.
The reviewed first-release Start-intent format and read-only unresolved
classifier are applied as a private, dormant engine module
(`target/g09-initialize-exact-outcome-next/start-slice.patch`, SHA-256
`a311cdd5aae66188d61dfccfca2b7e892286b35cbaafce76beedfd05564770e8`).
The applied-source focused cases pass **2/2**. The current production writer
still uses its old format because it lacks authenticated operation/phase/attempt
custody; wiring it now would fabricate provenance. The new exact wire slice is
staged but intentionally unapplied: without one-use journal admission and an
atomic first-applied membership fact, it would leave Start/Initialize pending
with only `UnknownOutcome`, not resolve them.
The independently reviewed format-2 target journal prerequisite is also
applied (`target/g09-initialize-exact-outcome-next/journal-slice.patch`, SHA-256
`14874971943b79813152975a157fcdfc0068d06bc68f0c2e3a1d02dae79dd10b`).
It intentionally rejects format 1, reserves exact Start/Initialize dispatch
history and future terminal bytes, treats equal replay as status only, and
recounts bounded encrypted rows on reopen. Applied-source journal tests pass
**8/8**. Its reservation method remains uncalled by live Execute and cannot
prove Raft membership or Control completion; G09 stays open.
The exact-deletion audit in `target/g09-exact-deletion-next/README.md` finds a
separate restart gap: distributed target creation records a command identity,
but not the original file's device/inode or a durable physical cleanup fact.
Current StopLocal compares a fresh claim to a fresh path observation, so a
substituted same-header file can be deleted while the original survives.
Journal, installed-owner and Control cleanup evidence must be cut over
together before a signed completion can be trusted.
The target-only implementation sequence in
`target/g09-exact-deletion-next/implementation-sequence.md` binds the original
empty inode and enrolled parent before initialization, then persists the exact
signed cleanup fact after unlink and parent sync. It keeps both create-before-
binding and unlink-before-fact crash windows unresolved pending a reconciliation
protocol; it is not an applied G09 fix.
The reviewed format-2 target journal and dormant exact Start/Initialize-owner
prerequisites are applied. The latter's four focused tests pass, but production
still lacks authenticated Control marking before Execute, one-use journal
admission before child creation, a single owned first Raft membership fact,
snapshot continuity and read-only signed same-attempt resolution. A serial
diagnostic engine library reproduced a test's one-second credential expiry
before its intended backup pause (**266 passed, one failed, one ignored**).
The reviewed test-only timing and serving-expiry classifier corrections pass
their focused cases. The complete serial engine library on the corrected
source passes **272/272 runnable cases**, with one ignored. No positive G09
recovery outcome is claimed.

- Exercise durable preparation, every target's materialization, initialization,
  source fencing, activation, confirmation and route publication. Preserve
  independently verified source/target authorization, a single activation winner
  and forward progress after committed activation, including absent source quorum.
- Complete cleanup through permanent stop, issuer drain, gate closure,
  worker/storage drain, exact deletion, parent sync and durable evidence. Preserve
  physical generation bindings across path, alias, provider and restart changes.
- Keep standalone recovery exclusive and local. Qualify initialization,
  credentials, operator key backup, rotations and stopped-installation admin
  recovery. Advertise OAuth discovery only for an installed external provider.
  Inject crashes/cancellation at every recovery/deletion phase and sync failures.

### G10 — Protected observability and complete readiness

Protected archive backlog/worker counters pass their focused unit, installed TLS
and archive-outage regressions. The fixed 128-group *coverage* cutoff is already
removed; 128 remains the bounded diagnostic detail page. Existing 131-group TLS
coverage has 129 absent routes, while the 1,025 healthy-group case is synthetic.
The installed 129-group protected-TLS fixture and its response-gate correction
are applied, but its first run failed at runtime open under the generic
at-most-512 MiB fixture work budget before readiness probing. A rerun with the
installation example's explicit 2 GiB total then failed at runtime open because
the default 64-slot snapshot startup inventory was exhausted. A third run with
one pre-reserved snapshot-startup slot per installed group passed runtime open
but failed before readiness probing: the fixture queried the installed-route
registry before serving reconciliation had published its routes. The failed
run is preserved. The reviewed lifecycle correction now passes an installed
129-group protected-TLS run: all groups are healthy with complete fresh
coverage, membership-change response fencing works, and a failed store beyond
the 128-entry detail page revokes readiness. The sweep waited 594 ms after
serving began; other resource and deadline limits are unchanged.
The reviewed archive-outage TLS fixture and serving-phase registry correction
are applied; each focused case passes 1/1. Remaining backup, authority,
recovery and outage observations are required for G10.
The source-bound durable-backup audit in
`target/g10-durable-backup-outcomes-audit/REVIEW.md` finds that protected
metrics count in-memory RPC returns while durable status is only
point-addressed by destination and session UUID. A prepublication durable
session index and bounded verified coverage probe are prerequisites for
truthful post-restart totals and completeness; an HTTP counter alone cannot
close G10.
The current-source readiness review in
`target/g10-readiness-ceiling-next/REVIEW.md`
confirms that all committed routes are swept and 128 limits only diagnostic
details. The installed 129-group result is still a focused development test;
native observability acceptance and supported-scale throughput remain open.
The later reviewed assertion strengthens that fixture's actual protected
HTTPS `/ready` readback after a membership change: it compares the full
installed epoch and all 129 expected, examined and healthy groups with
`complete`, `fresh` and `ready`. It passes **1/1** on the combined source
before the subsequent journal-byte edit. This remains a standalone installed
fixture, not a positive replicated recovery-status or full G10 acceptance
result; the [integration evidence](evidence/installed-disk-integration-20260923/README.md)
retains its exact log.
The later independent installed three-node test now observes the real
committed `Prepare` record over protected HTTPS and matches the native
operation, revision and pending/terminal fields; its two focused runs pass
**1/1** each after test-only call-site and public-certificate reader fixes.
The terminal `Finished` assertion remains blocked by G09's unresolved
Initialize proof, and aggregate backup/issuer observations and complete
replicated readiness remain open.

- Expose protected physical capacity, archive failures/backlog, durable backup
  outcomes, authority health, membership maintenance and distributed recovery
  phases through operational diagnostics and documentation.
- Replace the fixed 128-group readiness ceiling with bounded background probes
  and membership-epoch coverage. Require fresh complete coverage for readiness;
  qualify changes in membership, stale probes and former group ceilings.

### G11 — Acceptance manifest, infrastructure and dependencies

The current redb source checkpoint is explicitly inventoried with all 109 files,
the two original removals and 134 exact historical/gate bindings. The original
provenance remains immutable, and only redb's inventory/review binding plus the
vendor README support record change. Root adoption review is recorded beside the
[checkpoint proposal](evidence/redb-current-source-20260922/README.md).
Attempt 165 passes all 18 existing verifier tests and actual source/Cargo selection
for seven patched packages on unchanged inventoried inputs; its process group
drains. The checker is unchanged. This is a component checkpoint, not final-source
qualification or acceptance of the unpassed upstream, native or release gates.
After the canonical `PageNumber` and backup applications, the unchanged official
dependency checker again passes source verification, locked Cargo metadata and
exact selection of all seven vendored packages on the combined `master` source;
all 18 checker regressions pass. These development checks do not substitute for
the frozen native, upstream and final-acceptance cohorts.

The six-file revision 3 owned-assembly launcher and verifier bridge are applied
with exact readback. The later one-file test-path correction and two-file
selected-primary acceptance adapter slice are also applied. The latter binds
the assembly's retained functional receipt to the manifest-selected native
primary; its exact application receipt is
`target/installed-disk-validation/g11-selected-primary-acceptance-adapter/application-receipt.json`
(SHA256 `1b20595a8452a6c0afc3cb6bf869b51aa590b34f9ce3bffd85c4fa9c37556ddd`).
Full repository Python discovery passes **122/122** on the applied source; the
log is `target/installed-disk-validation/g11-dependency-review-runner-application/full-python-discovery.log`.
On the later master source, the independently reviewed unregistered dependency
runner revision 2 is applied; its scanner receipt now binds exact stdout,
stderr and process disposition before parsing. Its focused Python cases pass
10/10 and complete repository Python discovery passes **129/129** under Python
3.12.14. The native owned advisory scan, authenticated current advisory fetch
and runner provenance are still missing. An earlier Git-free scanner probe
stopped before cargo-audit because redb's old source provenance no longer
matches the applied G02 patch source. That failed attempt is preserved; the
corrected provenance and synthetic diagnostic outcome follow.
The reviewed revision-3 rebind is now applied and the official checker verifies
all seven vendored packages against locked Cargo selection. Focused checker
and runner Python tests pass **18/18** and **10/10**, complete Python discovery
passes **129/129**, and a Git-free synthetic cargo-audit probe detects the
injected redb advisory on the exact projected lockfile. This is diagnostic
local evidence only; authenticated current advisory data, native owned runner
provenance, complete adapters and platform gates remain open.
The adapter registry remains empty. The launcher has not run a native release
assembly on the required platforms, and complete semantic domain adapters
remain open. The [integration evidence](evidence/installed-disk-integration-20260923/README.md)
records the source-bound receipts. G11 and final acceptance remain open.
The reviewed ownership-graph correction now binds every child-ledger and
terminal-census row to its original process receipt's parent, executable and
birth observation. Its real nested-process focused tests pass **14/14**, and
repository Python discovery passes **131/131** from the repository root. The
native assembly, authenticated advisory acceptance and final-source platform
gates remain open.
The further dependency launcher verifier now binds all 30 original child
receipts to their ordered ledger and terminal census rows. Its substitution
regression is applied, and repository Python discovery passes **132/132**.
Native dependency/assembly runs and semantic adapter registration remain open.
The native host preflight now records schema 2 with its actual OS and machine;
acceptance requires their exact supported target pairing and rejects schema 1.
Repository Python discovery passes **134/134** on that applied verifier source.
A later failed-attempt verifier fix binds each claimed cleanup group and terminal
return code to its original process receipt, including strict integer types;
its focused acceptance suite passes **20/20**, while full discovery on this
newer source remains pending. The adapter audit in
`target/g11-semantic-adapter-audit/blockers.md` found that the native workflow
invoked the inner assembly runner directly. The reviewed workflow/operator
cutover now invokes the frozen owned launcher on Linux and macOS; its documented
dispatch module passes **13/13**. A native outer-launch receipt, complete
transitive upload, domain collector, registered semantic adapter and full Python
discovery on this newer source remain open. G11 is not accepted.
The later master source now includes the full declared functional roster,
bounded mode-preserving raw tar, exact Cargo executable and compiled-feature
replay, separate native producer-record upload with cross-artifact digest
binding, and a downloaded-tar collector that requires that independently
observed producer digest. The repository Python suite passes **168/168** on
that applied tooling source; the [integration evidence](evidence/installed-disk-integration-20260923/README.md)
retains the earlier failed fixture run, the independent feature false-pass
review, patch hashes and final Python log. No native upload/download, domain
adapter or final clean-source acceptance has passed, so G11 remains open.
After the G05 and G09 prerequisite applications, complete Python discovery
again passes **168/168** with Python 3.12.14. A separate invocation with the
macOS system Python 3.9.6 failed on a missing standard-library API and is
retained as an invalid-interpreter attempt; it does not change acceptance.
The source-bound semantic-adapter audit at
`target/g11-semantic-adapter-next/README.md` confirms the owned launcher is
wired, but no native repeatable-assembly domain receipt, complete
mode-preserving assembly transport/readback, host reservation attestation or
permanent attempt index exists. The adapter registry remains empty until those
original native facts are collected and verified.
The later owned-assembly raw transport and non-acceptance projection are now
applied. Complete repository Python discovery passes **191/191** on that source;
the [integration evidence](evidence/installed-disk-integration-20260923/README.md)
binds the exact patch, independent review and test logs. The projection joins
the selected functional receipt to verified downloaded raw bytes but always
reports `unqualified`. The native-lineage audit in
`target/g11-native-lineage-next/README.md` identifies missing independent
physical-host attestation and a durable before-dispatch attempt registry.
`DOMAIN_ADAPTERS` remains empty; no native assembly or final acceptance
claim follows from the Python tests.

- Add final acceptance verification above candidate packaging. Require every
  gate, exact clean source/tree/lockfile/configuration/patch/binary hashes,
  complete workload samples and drained test processes. Reject missing, failed,
  shortened or mismatched evidence; retain every failed attempt.
- Reserve explicit capacity on the native Linux ARM64 reference deployment and
  provide a native Linux x86-64 runner. Emulation cannot satisfy native acceptance.
  Document shared-host limits and operator durability/failure-domain requirements.
- Qualify memory-safety fixes and every retained dependency patch with upstream
  tests and provenance checks; record explicit remaining-advisory dispositions.

### G12 — Native, installed and HA final qualification

- Freeze a clean source revision and its candidate binaries. On native Linux
  x86-64, Linux ARM64 and macOS ARM64 with Rust 1.97.1 run the complete workspace,
  doctests, strict Clippy, formatting, Python, dependency regressions and
  fixture-free production builds.
- Use those candidates for offline standalone native/MCP lifecycle and actual
  OpenBao/MinIO interoperability: credentials, rotations, revocation, restart,
  backup/restore and administrator recovery.
- Run separate three-member data, Control and authority groups with distinct TLS
  identities. Inject leader loss, partitions, lease-length outages, replacement
  under load and every required recovery/deletion crash and cancellation,
  including absent source quorum. Preserve exact outcomes and process drains.

### G13 — Capacity, performance and full-duration endurance

- Run an incompressible corpus **exceeding 3 GiB** through standalone and HA
  snapshots, compaction, restart, follower replacement, filesystem/S3 backup and
  restore. Record compression, exhaustive integrity, retained-read pressure,
  memory peaks, allocated disk and maintenance workspace. Cross former lifetime
  ceilings and repeatedly test archive outages and delayed-upload cleanup.
- Preserve all 15 million-document cases across raw/local/replicated/text/network
  and 1/100/1,000 tenants; use production providers for production claims and add
  concurrent workloads with complete samples and measured operating limits.
- Run a genuine **86,400-second HA soak** containing credential renewal,
  archival, backup and membership maintenance. Never shorten, substitute or waive
  this gate; retain failures and rerun corrected final candidates as required.

### G14 — Verified deliverables and release closure

- Deliver Linux binaries, macOS ARM64 development binaries, both Linux OCI
  architectures, systemd units, source archives, checksums, dependency and image
  SBOMs, notices, contribution/security guidance and installation, maintenance
  and recovery documentation.
- Smoke-test actual packages and images, verify repeatable assembly and
  independent reproducible builds, and publish measured operating limits with
  source-bound evidence. Final acceptance must bind artifacts to qualified
  binaries and reject any missing gate or identity mismatch.
- Close the active objective only after G01–G14, every required acceptance gate
  and every usable deliverable are complete. Infrastructure gaps or unfinished
  qualification remain open work, never implicit waivers.

## Immediate execution order

1. Validate the current authority and full lifecycle successors on master,
   preserving the original deadlines, workload and all failed evidence. The
   passing vendor/store prerequisites and focused stopped-epoch successor are
   development evidence, not release acceptance.
2. Complete G02's fixed inode backing, managed directory creation/removal and
   physical growth bounds. Adopt retained database/writer ownership at every
   production constructor and transaction, with complete memory admission.
3. Bound historical redb reclamation with reserved maintenance progress, then
   implement G03's admitted custody/terminal batch writer. Keep the failed large
   restore and 4,200-command/8,400-audit cases unchanged for validation.
4. Advance G07's actual child census and production shutdown adapters alongside
   G11's native assembly and semantic acceptance adapters. Preserve and reconcile
   pending MCP changes before final source freezes; complete G04–G10 as their
   prerequisites land.
5. Freeze the combined implementation, qualify G12 and G13, and verify G14 using
   the exact packages/images and complete G11 acceptance manifest.

Initial evidence: [latest failed frozen ownership run](evidence/first-release-be2667d-check-20260919/README.md).
No implementation or qualification goal is marked complete by this planning update.
