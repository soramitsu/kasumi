# Installed-disk integration evidence, 2026-09-23

All work and validation here used `/Users/mtakemiya/dev/kasumi` on
`master` at HEAD `600c0ca2b2c4c22b89b44ccd932eca02272c70f1`. The
working tree contains uncommitted first-release changes. Local
`target/installed-disk-validation/` receipts are retained for exact byte and
process review; their presence is not final release acceptance.

The failed-opening/scratch-close revision 8 plus redb provenance passed its
source-frozen `native-09` run: 46/46 clean phases in 966.797 seconds. Those
phases include Rust formatting, all-target/all-feature workspace check, strict
Clippy, all 364 enabled store library cases (two existing ignores), 31 focused
cases, 231 vendored redb cases, the admission integration case, 18 Python
dependency regressions and exact selection of all seven official vendored
packages. No phase timeout, signal, source/control/tool drift or surviving
process group was observed. The native result is
`target/installed-disk-validation/failed-opening-explicit-recovery-revision8/native-09/result.json`
(SHA256 `37c3e57df3531150232f773ae6f3229d6543ce0680cf163763055c896a5a8707`).
Its independent audit receipt is
`target/installed-disk-validation/failed-opening-recovery-native09-independent-audit/receipt.json`
(SHA256 `8dff4d054619400dd0ccc11f4401e1c8b8a190a342dba0bf986be15556ff2b18`).

The exact 56 files were applied and read back against the candidate
(`actual-application-recovery-revision8-native09/receipt.json`, SHA256
`2852adb397b1262d7859479e55e65bda72d37b0cc80b43382d3d9363e77522e3`).
Official dependency verification and its 18 Python regressions passed again
after application. The initial service/G07 eight-file application receipt is
`actual-application-service-g07-revision1/receipt.json` (SHA256
`5bfb0460c0c4045f6b873a9877c14729375f0eb56b5a2f2f9a524ae86f0e7838`).
The five-file G10 physical-capacity application receipt is
`actual-application-g10-physical-capacity-revision1/receipt.json` (SHA256
`e5479c8a851e4961c6522bb1315ce32f454fc987c210cc7dbff5e2f9a103d0c0`).
Its two actual-filesystem store tests, strict store Clippy and formatting
passed. The six-file G07 correction receipt is
`actual-application-g07-combined-correction-revision2/receipt.json`
(SHA256 `97f97dfa5b2ba1013da3c0954f14e3b8f9e6af0c29b5c505785f37300a153996`).

The first pinned Rust 1.97.1 all-target/all-feature check after those
applications failed to compile `kasumi-server`: `Duration` was missing from
`target_serving_runtime.rs`, and `configured_tenant_enrollment.rs` still
expected an owned guard from the newly introduced `ManagementGate`. The
three-file repair adds the import and retains the command's owned, checked
gate throughout enrollment. Its receipt is
`g07-integration-compile-repair/receipt.json` (SHA256
`fdeae69557a566635bd9b11e134b91243c3dc7279aa3c304a28b8733a7982d7c`).
The package README discloses that pre-edit copies were reconstructed after
editing, while the administration base exactly matches the prior application.
The historical eight-call `jobs()` test-helper qualification between the
initial G07 receipt and its correction was also reconstructed and verified
from both archived endpoints in `g07-target-call-helper-bridge/receipt.json`
(SHA256 `e18a1c1c093e3fa4c8730f39e382df6d30cc0e0189fcb1d02a806b3d852b7e05`).
It is provenance for an already performed edit, not a new application.
Pinned all-target/all-feature workspace check and strict workspace Clippy
now pass on the combined source. Seven target-call ownership tests, ten
administrative command custody tests, the shutdown-gate case and two
target-invocation deadline tests pass. The first default-stack enrollment
fixture run aborted on a stack overflow before manager construction; a larger
diagnostic stack reached the first approval's expected response-fence conflict.
The one-file test repair boxes the large setup futures and verifies the exact
durable approval when the production release boundary reports uncertainty.
All three original enrollment tests now pass on the normal stack. The original
SIGABRT, diagnostic logs and passing cohort are retained under
`g07-enrollment-stack-overflow/`; its application receipt SHA256 is
`c66c496022b42e97b695aa181715946952d19d525166ab8ed019feee2fb350fb`.

The G07 all-features API audit-failure fixture repair changes only test teardown:
it now asserts the sealed audit store's original persistence failure during
database drain. Its exact previously failing case passes 1/1 on the normal
stack. The one-file application receipt is
`target/installed-disk-validation/g07-api-audit-failure/receipt.json`
(SHA256 `ff2a8980bc9813c6f7be9761dc2b9d33be12e148df0adf647d2e2b3007c26742`).
The two-file G07 local-recovery repair replaces raw generation/archive-cache
directory creation and removal under installed accounting roots with tracked
`NodeDisk` operations. Its receipt is
`target/installed-disk-validation/g07-local-recovery-managed-directory-repair/receipt.json`
(SHA256 `c8f93b49a4c60ef789199251091ab1c15bdffc2ed3fa69461457ff3b603f2533`).
Two focused all-features cases pass with a 16 MiB diagnostic stack. Separate
local-stop and incomplete-replay fixture failures are preserved in that repair
package. A subsequent one-file test correction is applied with exact readback
in `target/installed-disk-validation/local-recovery-stack-repair/local-stop-fixture-repair/receipt.json`
(SHA256 `e2d94101f3aeef4ea8f60a13e890b7c8e20ccd34fa3646b60f17d6cea8057231`).
It uses tracked NodeDisk operations for the test's unrelated files, pauses and
reconciles the owner around deliberate inode substitutions, and checks durable
logical replay authority rather than raw redb bytes that repair may rewrite.
The large aggregate fixture runs on its own 16 MiB test thread; production
stack policy is unchanged. Local-stop, incomplete replay and missing-topology
cases now pass individually on the normal test harness stack. The first
unfiltered all-features server library attempt still failed in several local
recovery fixtures and was stopped after a stalled test; its log and process
sample are preserved under `local-recovery-stack-repair/`. A second test-only
fixture correction passed all ten local-recovery cases in separate normal-stack
processes, but the next unfiltered same-process server run still reported local
recovery and RPC failures before aborting on a stack overflow in the audit TLS
fixture. Its log is preserved at
`target/installed-disk-validation/local-recovery-stack-repair/unfiltered-fixture-repair/unfiltered-server-all-features-normal-stack-rerun.log`.
A two-test same-process reproduction identified a retained cancelled startup
task in the process-wide local-operator registry. The fixture now drains each
actual local-operator startup owner before its short-lived Tokio runtime ends.
The exact two-test pair passes 2/2, and the complete local-recovery module
passes **10/10 in one process** on the normal stack
(`unfiltered-fixture-repair/local-recovery-module-same-process-after-drains.log`,
212.00 seconds). The corrected second-layer one-file transition is resealed
with exact readback in `unfiltered-fixture-repair/receipt.json` (SHA256
`b3b3a3ca0a07e566eb438d404848fc41233bd1e6ab0bb33fa2183810fa93e462`).
The next unfiltered all-features server attempt passed all ten local-recovery
cases and reached two RPC failures before a runtime-lifecycle fixture stack
overflow. Its failed log is preserved as
`unfiltered-fixture-repair/unfiltered-server-all-features-normal-stack-final.log`.
The complete server and full workspace cohorts remain pending; the earlier
failures remain preserved.
The one-file audit TLS fixture stack repair is applied with exact readback in
`target/installed-disk-validation/runtime-audit-stack-repair/receipt.json`
(SHA256 `c580359febbb92df460ea3428f9442ae2ee13b1871763ea96b6ba868fa400407`).
Its original named all-features case passes 1/1 on the normal test harness
stack in 115.30 seconds. A separate one-file runtime-lifecycle fixture repair
also passes its original all-features case 1/1 on the normal stack, with exact
readback in `target/installed-disk-validation/runtime-lifecycle-stack-repair/receipt.json`
(SHA256 `4d67ff99222ab756d23a5c690235c035db484bfc1ebe483d5c3e9b5fcf56c4db`).
Both repairs change only test-thread stack allocation; production stack policy
is unchanged.

The authority RPC fixture had asserted that local retirement must be too early
after its own transport had held the activation response longer than the
configured drain. The corrected test requires completion and exact receipt
replay; its all-features case passes 1/1. Exact one-file readback is preserved
in `target/installed-disk-validation/rpc-authority-retirement-fixture-repair/receipt.json`
(SHA256 `c34f911fdf904c238a2fc4d474d724f16a1b6436e0fdb2ba69a912761f4ee74b`).
The first corrected same-process RPC pair passed authority but timed out in
the lifecycle fixture's initial issuer-quorum readiness. An unchanged rerun
passed 2/2, proving the original ten-second loop intermittent. The separate
test-only correction bounds each real linearizable-barrier probe, retains the
quorum requirement and adds node metrics on timeout. Its focused case passes
1/1, and the authority→lifecycle pair passes **2/2 in one process**. Exact
readback is in `target/installed-disk-validation/rpc-lifecycle-quorum-fixture-repair/receipt.json`
(SHA256 `b0c5ed27d0b98365ddffc8d39a67c26566d3396bfe8f7e12e233bceefaacf384`).
The unfiltered all-features server suite still requires a fresh run.
A diagnostic run using libtest's default parallelism completed 59 passing and
five failing cases before it was deliberately terminated with SIGTERM. The
failures were configured-tenant/Control-genesis fixture startup-owner
cancellations or ten-second waits while other tests used the same process-wide
owner kinds. Its raw log and termination are preserved under
`target/installed-disk-validation/rpc-lifecycle-quorum-fixture-repair/`;
`default-parallel-diagnostic.md` explains the boundary. The source-owned
qualification runner requires `--test-threads=1` for the shared-process
workspace suite. That sequential all-features server run reached all ten
passing local-recovery cases, both RPC cases and the audit TLS fixture. The
authority RPC and audit TLS cases passed, but lifecycle RPC failed on a
structured `UNKNOWN_OUTCOME` from a ten-second recovery proposal deadline;
a later runtime-lifecycle aggregate fixture stack-overflowed and SIGABRTed.
The raw sequential log is `unfiltered-server-all-features-sequential.log` in
the same package. The parallel diagnostic is not a pass or release acceptance.

The completed-shutdown lifecycle stack repair is applied with exact readback
in `target/installed-disk-validation/runtime-lifecycle-stack-repair/completed-shutdown/receipt.json`
(SHA256 `728469171926ad4f0f1dbaa2ac565117bf2f54606663907f49a5a41b3f8fdcb3`),
and its original case passes 1/1 on the normal harness stack. The recovery
fixture now reads the original operation's status after a structured uncertain
reply without resending its mutation. Its first focused build exposed an
`rcgen::Error` name collision, preserved and fixed as a separate one-line
transition. The original and correction receipts have SHA256
`f8a391ae3d6932096312b339e825797095edd5918366da44a00317a04550cb2b`
and `b7865ff0231a676a98cfebd452d9efb3d08c3b788f1545498a26951a3a2e61d1`.
The corrected lifecycle RPC case passes 1/1 in a fresh process and the
authority→lifecycle pair passes 2/2 in one process. An uncertain first
preparation can still leave a pending phase that read-only status cannot
advance; durable resolve-only handling remains open. The runtime-lifecycle
module and complete server cohort remain pending.

The G11 revision 3 owned-assembly launcher and verifier bridge were applied
with six exact file readbacks:
`target/installed-disk-validation/actual-application-g11-owned-runner-revision3/receipt.json`
(SHA256 `df871ac96817115ebb0a31923afd0af1ae090d745d9594c444561536375302a0`).
The one-file repeatable-assembly test path canonicalization is bound by
`target/installed-disk-validation/g11-repeatable-test-canonicalization/receipt.json`
(SHA256 `9ae52a6ce679c1c226ef03019f1cda4cc95380d3f5798edc65f81c2ec66f90ff`).
The two-file selected-primary acceptance adapter slice is applied and read back
in `target/installed-disk-validation/g11-selected-primary-acceptance-adapter/application-receipt.json`
(SHA256 `1b20595a8452a6c0afc3cb6bf869b51aa590b34f9ce3bffd85c4fa9c37556ddd`).
Its exact base/proposed patch and 51 focused tests are retained there. That
checkpoint's Python discovery passed **119/119**.
The four-file G11 owned dependency-review runner is also applied with exact
readback in `target/installed-disk-validation/g11-dependency-review-runner-application/receipt.json`
(SHA256 `882ba3111d39cf65c41a35f1b3ed659a7b7764caab5a2020617b263830fed9e7`).
Its three runner-contract and eighteen dependency-checker Python regressions
pass on the applied source. The runner selects seven locked/offline upstream
suite roots and requires a native Linux ARM64 host; it has not run those suites
or produced an advisory scan, so it supplies no release acceptance evidence.
Full repository Python discovery now passes **122/122** on the applied source;
the log is
`target/installed-disk-validation/g11-dependency-review-runner-application/full-python-discovery.log`
(SHA256 `9c154ce4cf95b154366e1c34fef2998f4793ac94caf9afbae88a49283b9c4704`).
The source-owned check binds the assembly's retained functional receipt to the
manifest-selected primary. The adapter registry remains empty; complete
semantic adapters and native assembly qualification on all required platforms
remain open.

The two-file G02 registered-opening explicit-close prerequisite was applied
with exact readback in
`target/installed-disk-validation/actual-application-g02-registered-opening-close-candidate/receipt.json`
(SHA256 `5192dc30030c38e4b7a476642472f05a9005710bc438b44ac90181c97f2a50a7`).
The target-only candidate's isolated overlay passes 16 focused opening cases,
all 368 runnable store library cases (two existing ignores), strict store
Clippy and formatting; see
`target/installed-disk-validation/g02-registered-opening-close-candidate/VALIDATION.md`.
Those overlay results do not qualify the later applied combined source. Its
production constructor, transaction and reader adoption remain open.

The unfiltered combined-source cohort after these applications remains pending.

## Later focused development on the mandated master checkout

All work below used `/Users/mtakemiya/dev/kasumi` on `master` at HEAD
`600c0ca2b2c4c22b89b44ccd932eca02272c70f1` with a dirty integration
tree. It is development evidence, not a frozen final-source or release run.
The prior failed logs remain intact.

- G07 backup-producer custody and real caller-cancellation patches were applied
  (SHA-256 `9fd45e782f4c83639991c794d8adb64ce3323af48fd2a334bf1a1cfe1c966ab5`
  and `8a3ab29771d37a100ab5860414acca875dbaebd65c46f76cb07c85e1ccb52be9`).
  Serving 2/2, engine registry 3/3, shutdown 1/1, and real cancellation 1/1
  pass in the local logs under `target/installed-disk-validation/`. The broader
  serving/engine run failed with 241 passing, one failing and one ignored case:
  the unchanged 512-row snapshot restore expired its 60-second verification
  deadline. This remains a failed cohort.
- The bounded terminal-batch patch (SHA-256
  `5ee8c91bb6e39d1d8326bb3600759b9ef6030243abb8874823f57fb88bd46846`)
  passes store scratch-table 9/9 and engine terminal 8/8. The unchanged 512-row
  restore case subsequently passes twice, with whole-test times of 91.77 and
  95.78 seconds, in `target/snapshot-restore-deadline-candidate/`.
  The local independent review at
  `target/snapshot-restore-deadline-candidate/independent-review/README.md`
  and its follow-up design still require an admitted transaction-memory
  bound and retained exact owners after uncertain transaction and database
  close failures. Neither focused pass closes G02/G03 or replaces the failed
  earlier cohort.
- G05's managed target generation-directory custody patch (SHA-256
  `4721555bc78cb141d208ac4ad29e51e12003b17bc19dedba7549daaed34b13f5`)
  and root-substitution regression patch (SHA-256
  `0a5ed2b1cea9917b287666693bf72c7b1f3766d938560ec53f5cb8da7eee3e52`)
  are applied. The shutdown module passes 4/4, persistent-disk module 7/7,
  and the substitution case fences the disk before a cleanup claim. Its first
  run failed because the test mixed `/var` and `/private/var` fixture paths;
  the canonical-path correction and successful rerun are both preserved under
  `target/g05-stop-local-root-substitution-regression/`. A durable physical
  backup destination binding and session index remain unimplemented.
- G08 now retains one-way effect markers and signed positive activation
  acceptance in recovery state (positive-evidence patch SHA-256
  `91389fb17a0beb03a1b3aea7d7c0a2d3de80c49c7289ed6c9209418e9a7d617d`).
  Its real-signature test revision (SHA-256
  `41e8fbbda2c1d34abc9cdf170b7706010d55d4309340f761511ac97ab2c2e0c7`)
  passes the complete recovery snapshot module 10/10; the superseded test
  fixture proposal and its independent failure finding are preserved. The
  lifecycle one-send client change passes the full client library 48/48, and
  its repaired real two-route server case passes 1/1 in
  `target/g08-lifecycle-uncertainty-fixture-repair/`. The test's scoped TLS
  handshake audit override does not qualify real audited issuer HA.
- The source-retirement pool now limits one invocation to one mutation
  (SHA-256 `066c3b2af2be4574d3648a4f0ce22814efc9bd7a4869792b168f7b56b3994081`).
  Its two-route mTLS regression and stronger original-success-frame assertion
  (SHA-256 `46d57ac6de637fae2e72be61a563e067186d21b2f9410d450c6373ddfd512e5a`
  and `20c0ae8d5f4c04afb6e4157af39722238261a1f7d8356649984b0a6c199bfc8d`)
  pass 1/1 under `target/g08-retirement-tls-test-review/revision1/`. The
  exact first response is decoded and equals the later read-only receipt;
  no second route receives a mutating RPC. This is two installed client
  origins sharing one test server, not independently booted HA nodes. The
  recovery coordinator still lacks class-bound durable grants, receipt-only
  resume, and a guard against superseding unresolved effects. The separate
  `abort_retirement` pool now also sends at most once per invocation and the
  full client library passes 48/48 again. A later real two-route mTLS
  abort-response-loss regression passes 1/1: its first successful response is
  decoded, then the caller receives an unavailable reply, no second route
  receives a mutation, and a read-only status resolves the original operation.
  The log is `target/installed-disk-validation/focused-abort-retirement-lost-reply.log`.
  Cross-invocation resolution remains open. Ambiguous source
  retirement still lacks consistent typed `UNKNOWN_OUTCOME` reporting. G08/G09
  remain open.
- G10's protected archive backlog and worker counters patch (SHA-256
  `8a4de35d54e04aa7ab6b7e8bf82111b300978f3b672917e14ae4e7126270bc4e`)
  passes its backlog unit, real protected TLS scrape, and archive-outage
  regression, each 1/1 under `target/g10-readiness-next-slice/revision2/`.
  The TLS case first aborted on libtest's stack, then passed with the same
  16 MiB fixture-thread pattern used elsewhere. The fixed 128-group coverage
  cutoff is already removed in source; an installed healthy >128-group result
  and other G10 observations remain open. The local
  `target/g10-readiness-coverage-design/README.md` records the exact proof gap.
- On the latest combined source after those focused edits, pinned Rust 1.97.1
  all-target/all-feature workspace `cargo check`, strict workspace Clippy
  (`-D warnings`), `cargo fmt --all -- --check` and `git diff --check` pass.
  Logs are `target/installed-disk-validation/combined-master-after-abort-once-check.log`
  and `combined-master-after-abort-once-clippy.log`. The first strict Clippy attempt
  failed eight mechanical local-recovery test lints; its log and the corrected
  second and latest passing attempts are preserved. A complete unfiltered
  server/workspace cohort and all native release gates remained unrun at this
  source checkpoint.

The subsequent G08 SourceRetirement effect patch (SHA-256
`d27d033b8be4ac239c0ec6a1a9d431b5a5df1e9a2624d8967c90090647973dbc`)
commits its marker before the one-use source retirement send, requires the
marker for its resolution and snapshot, and confines marked resume to status
and custody reads. Its engine recovery snapshot module passes 11/11; its
server helper and native marker cases each pass 1/1. The native case first
failed because the fixture attempted an application-token read after retirement
had fenced it; that failed log and the corrected passing run are both retained
under `target/installed-disk-validation/`. The other one-way effect classes,
full concurrent coordinator fault exercise and cross-invocation resolution
remain open. After this patch, pinned all-target/all-feature workspace checking,
strict workspace Clippy, formatting and `git diff --check` passed. Logs include
`combined-after-g08-source-retirement-check.log` and
`combined-after-g08-source-retirement-clippy.log`.

An unfiltered sequential all-features server attempt on an earlier combined
source reached **168 reported passes, four reported failures**, then aborted
with a libtest stack overflow in the standalone backup CLI fixture. Its raw
log is `target/installed-disk-validation/full-server-current-20260923.log`;
remaining cases never ran. The four failures were both replicated runtime
lifecycle cases, a retired-source panic fixture, and a shared physical-owner
directory fixture. The backup CLI fixture now uses a bounded 16 MiB fixture
thread and passes its original focused case. The directory fixture now creates
its roots through the installed persistent-disk owner and also passes its
focused case. The retired-source fixture passes alone, leaving its
same-process interaction unresolved. The spare replacement fixture reproduces
an `UNKNOWN_OUTCOME` at its first tenant collection proposal. The three-node
fixture first reproduced a 25-second registry-readiness timeout with a
disconnected Control Raft candidate; a later diagnostic run passed that stage
but failed on an `UNKNOWN_OUTCOME` while verification issued a maintenance
audit proposal through its earlier selected leader. The diagnostic patch
preserves the original deadlines and failure result; no complete server pass
has followed these corrections. Focused logs are under
`target/installed-disk-validation/` with names beginning `focused-runtime-`,
`focused-retired-`, `focused-shared-owner-`, and `focused-backup-cli-`.

Further failure-only probes leave the original 25-second registry, 20-second
replica-application, 45-second membership and five-second installed Control
read deadlines intact. The spare-node fixture failed once after a successful
document write had not appeared on every replica, then failed at membership
replacement, and then passed its complete focused case **1/1** in 34.53 test
seconds. Logs are `focused-runtime-spare-diagnostic.log`,
`focused-runtime-spare-applied-diagnostic.log`, and
`focused-runtime-spare-membership-diagnostic.log`. The three-node fixture
alternated among no Control quorum at registry readiness, an uncertain
backup-verification audit proposal, and an installed recovery failure. In the
last two runs it reached installed recovery but its five-second read after
deliberately isolating the Control leader expired. The latest failure showed
**no replacement leader at the deadline**: the isolated node still reported
Leader term 1, node 2 remained Follower term 1, and node 3 was Candidate term 2
with one fewer applied log. The exact log is
`focused-runtime-three-failover-diagnostic.log`. Thus the client did not merely
select a stale endpoint after a successful new election. The host showed load
averages from roughly 14 to above 100 on ten CPUs during these probes;
memory-pressure reporting showed 71% free. This is timing context, not a
qualification waiver or proof of the sole cause. The complete same-process
server cohort remains failed and unqualified.

The G02 retained-database-close revision 1/2 candidate was reviewed and not
applied: dropping a busy close could still lose the terminal owner, and it
did not connect that owner to the installed storage census. Its revision 3
plan is retained under `target/g02-retained-node-database-close-candidate/`.
Later target-only revisions through revision 6 add a positive vendor read-close
disposal witness and precharge the actual redb read-guard allocation before
`begin_read`; static patch and formatting checks pass. They remain **unmerged**
and have no Cargo qualification. Tracker-map, cache, table-operation, writer
and opaque diagnostic allocations still lack a complete pre-effect resident
admission protocol. The revision 6 patch and admission analysis remain under
the same target directory; G02 production adoption is open.
The later production-caller audit (`target/g02-production-caller-adoption-next/README.md`)
finds **13 raw commit sites** in current source, nine persistent and four
scratch; the earlier twelve-site inventory omitted
`EncryptedTableBatch::commit` in `scratch_table.rs`. Registered opening covers
only fresh initial tables. Retained read terminals, same-owner Ready proof,
general writes, scratch ownership and actual redb workspace admission remain
prerequisites, so no caller-only migration was applied.
G05's target-only durable backup binding design is retained under
`target/g05-durable-backup-binding-design/`; Control's permanent per-session
index, encrypted physical identity and index-first cleanup are still required
as one coherent change. Candidate designs are not production implementation.

The later G08 recovery-effect grant patch (SHA-256
`43f74b275b37a0f257176ab317f76318d0ff41e8fcfb37c5ac87b66cea743f8e`)
is applied. Its non-cloneable committed BeginEffect ticket now covers issuer
commands, activation-intent acceptance and Control intents as well as source
retirement. The reducer and snapshot validation require the corresponding
marker before accepting a positive issuer or Control result. A retained signed
activation acceptance is committed before an authority activation command can
begin. The installed exact StopActivation resolver is the narrowly permitted
transition from an expired marked activation. Engine recovery snapshot tests
pass **11/11** and receiver tests **13/13**; the server API cohort passes
**31/31** in 249.81 test seconds on this patch before the later G07 test edit.
Logs are `focused-g08-effect-grants-engine-snapshot.log`,
`focused-g08-effect-grants-engine-receiver.log`, and
`focused-g08-effect-grants-server-api.log`. TargetCommand still lacks an exact
read-only outcome RPC. Marker-before-send cancellation can also leave an
unresolved effect without an ordered no-admission proof. Concurrent coordinator,
restart and installed HA faults remain unqualified; G08/G09 remain open.

The later G07 test edit (SHA-256
`58ac1eb68ea689c9437b678807edd44fb1a73baee498a26df898e6fd502db436`
for its staged patch, followed by a comment-only correction) extends the real
two-route pinned-mTLS abort-response-loss case across fresh client invocations.
With both status routes unavailable it returns an error and performs zero
additional mutations; a further fresh pool reads the exact original committed
stop through read-only failover. Its focused case passes **1/1** in
`focused-g07-abort-cross-invocation.log`. Both TLS routes share one registry
and database; this is not an independent-server durability or coordinator
restart result.

Pinned Rust 1.97.1 offline locked all-target/all-feature workspace checking,
strict workspace Clippy (`-D warnings`), formatting and `git diff --check`
pass after these applied G08/G07 changes and failure-only runtime probes.
The check and lint logs are
`target/installed-disk-validation/combined-after-g08-effect-grants-g07-cross-check.log`
and `combined-after-g08-effect-grants-g07-cross-clippy.log`. These static passes
do not replace the failed complete server cohort or final-source qualification.

The next pinned, offline, locked sequential all-features server-library run
reached **173 reported passes and three reported failures** (native authority
RPC, the installed three-node runtime recovery case, and protected observability
TLS), then aborted on a libtest stack overflow in the standalone ownership
fixture before libtest could print the captured failure details. Its raw log is
`target/installed-disk-validation/full-server-after-g08-g07-20260923.log`
(SHA-256 `41f1a3454460fa1206179d4549293b914ea03d0922da2c85a1d76655b6761bc6`).
The run did pass every same-process local recovery case, both earlier audit and
runtime-lifecycle stack fixtures, and the spare-voter runtime case; the abort
leaves the rest of the 222-test library suite unrun. The ownership overflow
reproduced alone and then in its five-test module. A test-only runner now gives
the fixture caller and its original two Tokio workers 16 MiB stacks, and the
complete ownership module passes **5/5 in one process** on the normal harness
(`focused-standalone-ownership-module-third.log`, SHA-256
`fa914a92fb6a5380cebe6c44bc046bcebee7579b807fdf795e6c844db6ff3c92`).
Production stack policy is unchanged. The first focused invocation accidentally
used the shared default Cargo target and failed to compile against an existing
Rust 1.99 metadata artifact. Its log path was overwritten by the subsequent
isolated reproduction of the stack overflow; only the tool response retains
that compile failure, so it supplies no local evidence credit. The next
sequential, `--nocapture` server-library attempt reported **156 passes, five
failures, then SIGABRT** before completing all 222 tests. The exact raw log is
`target/installed-disk-validation/full-server-after-ownership-election-diagnostic-nocapture.log`
(SHA-256 `e92c2f934870e7ce8b9390f6f7e5b8a084e1461c7e11c5d68dce0ebba361abc6`).
The captured failures are: an `UNKNOWN_OUTCOME` at the first actual pinned
issuer enrollment (`rpc_authority_tests.rs:1122`); an `UNKNOWN_OUTCOME` at the
initial `Put docs/a` in spare replacement (`runtime.rs:4758`); three issuer
members with divergent candidate/leader views and no applied index at the
three-node fixture's 30-second linearizable-quorum boundary
(`runtime_recovery_tests.rs:575`); a partial-readiness-sweep tenant row unwrap
after an asserted 503 (`runtime_observability_tests.rs:580`); and a standalone
provisioning fixture's `persistent file is outside installed accounting roots`
error. The following standalone provision case then overflowed the ordinary
libtest stack and aborted the process. Failure-only diagnosis and focused
corrections are required; none of these cases counts as passing.

The following test-only corrections are applied on `master` and pass their
focused cases on pinned Rust 1.97.1 with the isolated Cargo target: canonical
installed NodeDisk paths, exact injected-failure witness, first-release format
3 assertion and 16 MiB two-worker provision fixtures pass **3/3**
(`focused-standalone-provision-after-correction.log`, SHA-256
`45a5fa0601cdd0109adcc9f8aba156d372caa7b63a86e5dfe62d737d025c9b8e`);
the protected TLS observability fixture retains the immediate held-response
503, asserts every intermediate response stays unavailable, and waits for the
sealed tenant row before redaction checks, passing **1/1**
(`focused-protected-observability-after-correction.log`, SHA-256
`11346e4b8c13c25898e49d1b54eaec30adae42a507c54de3c6d55df18332b219`);
the native authority fixture uses the exact read-only receipt after structured
`UNKNOWN_OUTCOME`, with bounded per-member quorum probes and failure-state
reporting, passing **1/1** on its second focused run
(`focused-authority-exact-receipt-second.log`, SHA-256
`a879eebb2f764154a4889f3e27dbe61abdb09ce74d1c1a4e8da49f2b67265411`).
Its first focused run still failed at the earlier ten-second quorum boundary
(`focused-authority-exact-receipt.log`, SHA-256
`742cc2be3e0196625c3f4e4a56f5f8d346b2ad4304b918c16035a4b0a0074b69`),
so the successful rerun is not evidence that startup election is stable.
The P1 first-release DTO/replay patch also passes its initial two type tests and
one engine canonical-command test (`focused-first-release-types.log` and
`focused-first-release-command.log`); after nested TextIndex strictness was
added, the two type tests passed again on the later source
(`focused-first-release-types-final-slice.log`, SHA-256
`a705ada8311f60d20add04d600ec486b0b7e65dd76c3cdd89645b1aa890aef7a`).
A local access-token omission rejection and a
database-child terminal-error repair are now applied and pass their focused
cases: the locally re-signed missing-`token_use` credential is rejected while
normal issue/renew/revoke remains accepted
(`focused-first-release-local-token-use.log`, SHA-256
`3cd383251b697b1a9eba759b2653425d0723cd12a276ac51d56eb4aa13ab6d14`),
and a canceled caller plus canceled drain waiter retains the original typed
database audit-preparation error **1/1**
(`focused-g07-database-child-terminal.log`, SHA-256
`631aaaab49812b79013d4858f8599f8079e98c57081a607bb1b4be9a398e5f66`).
These checks do not cover all G07 children or all external input DTOs. The
Raft adapter now respects OpenRaft's `hard_ttl()` rather than ending an RPC at
its earlier graceful-cancel `soft_ttl()`; focused installed runtime verification
of that production change is **not passing**. The focused three-node native
test on this change passed issuer quorum construction and reached installed
Control/data activity, but failed **0/1** at its unchanged recovery operation
deadline before any target dispatch. Control had no leader, with members in
terms 7/7/8 and all applied through log index 8; its last step returned read
quorum unavailable while the recovery head remained `Prepare` with no pending
phase. The raw log is
`target/runtime-recovery-diagnostic/focused-three-with-hard-ttl.log`
(SHA-256 `7eee06cbc5e16555d2358a4a27ca182e9883e1f5492ac637a6f6f3a970d7d1da`).
This run neither validates installed HA nor reaches the separate earlier
materialization stall. Raft/audit transport timing and recovery exact dispatch
remain open.
The focused spare-voter test on the same source also failed **0/1** before its
initial mutation receipt path: its existing 20-second Control `AddLearner`
boundary expired amid lost leadership
(`target/runtime-recovery-diagnostic/focused-spare-exact-receipt.log`, SHA-256
`ffccdf1e5ffd4d1275d48cc51977bb403160d5f4e88985ba280f655fb94866a7`).
The applied exact read-only mutation-receipt resolution is compiled but was not
exercised by that run.

The first-release internal Raft envelope now requires an explicit
`bootstrap_sha256` key, including explicit `null` for an intentionally unbound
route. A direct transparent-option attempt still accepted an omitted field;
its real authenticated TLS suite failed **1/2** and the log is preserved as
`focused-first-release-peer-envelope.log` (SHA-256
`8a6e72564dee9f8de07e30195b16afe0018272fc459405a8958e2fef1cf26dea`).
The explicit visitor decoder then passed the same complete suite **2/2**
(`focused-first-release-peer-envelope-manual.log`, SHA-256
`eaa952036b2ac76ebe6b20d9fcbb546afbf65949b46e6e7cd873ba1a09185a36`).
The production retired-custody route now reconstructs the original application
bootstrap fingerprint from its validated custody binding and bounded retained
initial-digest record, then registers with an access-fenced non-null bootstrap
binding. Independent static review is preserved under
`target/first-release-peer-envelope/retired-source-binding/`. Its new real
retired-source fixture passes and confirms the route rejects fingerprint lookup
after custody shutdown, but the same three-test module passed **2/3**: the
existing preparation-panic test exhausted its ten-second fixture deadline
(`target/first-release-peer-envelope/retired-source-binding/focused-retired-source-after-binding-second.log`).
The first attempt did not compile because a concurrent G02 candidate briefly
had a missing `Result` error type; that compilation failure is preserved in
`focused-retired-source-after-binding.log`. Peer membership fencing and the
complete server cohort remain open.

An instrumented three-node installed run on the hard-TTL adapter change failed
**0/1** at tenant registry readiness in 51.58 seconds, before recovery target
dispatch (`target/runtime-recovery-diagnostic/focused-three-transport-timing.log`,
SHA-256 `4829efe59f5faa351e249ec770e5422ac9408b6e3e4572fa1b821c21675366d9`).
The capped diagnostic reports include 170 append hard timeouts at a 250 ms
deadline, six vote hard timeouts at 1500 ms, 161 accepted TLS audits above
100 ms (63 above 1500 ms), and 93 accepted-audit five-second timeouts.
Control voters were split; cross-node bootstrap probes timed out while local
probes and storage access succeeded. These are capped observations from one
instrumented run, not an uninstrumented rate or proof of one exclusive cause.
The temporary timing probes were removed after this run. Source inspection
found that the preconfigured pinned-peer TLS client advertised no ALPN, and
the server's production reqwest dependency lacked `http2`; the locked reqwest
preconfigured path does not fill ALPN. A narrow HTTP/2 correction is now
applied with a real negotiated-protocol assertion in the authenticated
transport test. The real pinned-mTLS transport suite subsequently passed
**2/2**, including its received-HTTP/2 assertion
(`target/runtime-recovery-diagnostic/h2-peer-candidate/focused-cluster-transport.log`,
SHA-256 `142501df89f0847d57f9d212d76e2f46f34429d19f0d5ccd77e79b7b798dcc82`).
The production-only `kasumid` check passed without dev dependency feature
unification (`production-only-kasumid-check.log`, SHA-256
`3194cce43da1dbd6250085afeddfa3298a4ed7659b9ec2eeacd355dfb482578b`).
The uninstrumented installed three-node run then failed **0/1** at its unchanged
240-second recovery success deadline (`focused-three-after-h2.log`, SHA-256
`955516337709404b2aae8eaf1a9b7c7dbfc99a196fc00c5b3323bd60a2c73003`).
Unlike the earlier instrumented run, Control remained a healthy three-member
group and the source was leader, but recovery stayed in `Prepare` with no
pending phase. All eight retained dispatch results were the generic
`recovery phase unresolved` response; the test had not reached any target
materialization. This is a narrower liveness improvement, not an installed
HA pass. The hidden original coordinator error and recovery admission remain
under investigation; no deadline was changed.

The reviewed partial G02 direct-header admission slice was applied with its
stacked correction, followed by a narrow compile-typo repair and test-only
wrapper gate. Its full serial vendor library cohort passed **233/233**
(`target/g02-admitted-redb-next/applied-validation/vendor-lib-serial.log`,
SHA-256 `627524601f4f40f029f42243a2b01a70fc5d3a165a69c30847a2a93131c908a7`).
Vendor all-target compilation, focused installed engine reservation,
retained-spool, scratch-table and serial node-file checks also passed, with
exact logs under `target/g02-admitted-redb-next/applied-validation/`.
Concurrent node-file fixture execution first failed two cases, which then
passed together in the serial module run. Strict vendor Clippy still fails on
three diagnostics in untouched `optimized.rs` and
`retained_database_tests.rs` (`vendor-strict-clippy.log`, SHA-256
`d1a9c4ad91573b05147fbfc4747c75822ad3c53285a094eeb5a3feb207fc9092`).
The direct-header lease is only one allocation site; cache/page guards,
tracker and transaction workspace, production NodeDatabase adoption and other
G02 terminals remain open.
The first strict vendor Clippy run failed on three untouched-file style lints.
A two-file equivalent correction moved retained test statics before statements
and used `let...else` for the poisoned write-lock branch. The pinned
all-target/all-feature vendor Clippy run then passed with `-D warnings`
(`vendor-strict-clippy-after-correction.log`, SHA-256
`e8c9c1a4189d4992f9b0bcd9523424fd45f2bea971e339b9c89fdfb5e88c8178`).

The first-release committed command decoder now applies its streaming
canonical-byte check to prefixed recovery and target commands as well as
ordinary commands, before replay state changes. An initial focused compile
failed because the new test used `unwrap_err()` on a result whose success type
has no `Debug` implementation (`target/first-release-prefixed-command-replay-next/focused-engine-prefixed-replay.log`,
SHA-256 `128c7e719db7c2b5508cabfaa341b58371666db60b146f526a537c593ccc2743`).
The corrected assertion then passed all **3/3** focused ordinary, recovery and
target cases, including a noncanonical target envelope rejected through the
actual apply path without changing its generation pointer
(`focused-engine-prefixed-replay-second.log`, SHA-256
`5a75252fd27ed003e379407851209826c68efbe8eb3c214ccce094468b687a2a`).
Other on-disk/wire DTOs and combined-source qualification remain open.

The original five-second installed Control read began immediately after leader
isolation, while the configured three-second OpenRaft lease plus its 1.5–3
second randomized election window can exceed five seconds. The prior failure
snapshot showed no replacement leader at 5.03 seconds. A test-only correction
now requires a bounded, linearizable replacement election on the two surviving
members before starting the unchanged five-second client read. Its target-only
patch is `target/runtime-failover-candidate/candidate.patch` (SHA-256
`b3d06745f75275fe94dc92f8a73f938466921edcd5850d4283140c1b2ac53422`),
subsequently applied to this checkout. It does not alter production election
timing or the client deadline.
The focused case then passed that replacement-election boundary but failed
**0/1** after its unchanged 240-second recovery success deadline
(`focused-runtime-three-after-election-readiness.log`, SHA-256
`fe0ccf3c55fbe2190ea8de8f457c3b0678b84932cf5203653906e929d196d1d5`,
272.59 test seconds). Control was a healthy three-member group at the end,
but no voter had a positive materialization result; the latest pending target
phase was `ResumeMaterialization` with no outcome. This is a separate recovery
resolution failure, not a passing HA case. A subsequent failure-only fixture
diagnostic retains the last eight dispatch results as well as the last eight
Control heads so the next sequential run can distinguish absent target status
from transport and resource errors without resending a target effect.

The reviewed semantic recovery route now hashes the shared issuer manifest,
target/source/custody identities and endpoints, parsed certificate pin sets,
and the exact CA bytes used by dispatch. Control-local credential and CA file
paths do not change the digest; no old digest is accepted. The native mTLS
recovery test passes **1/1** after pin normalization
(`target/runtime-recovery-diagnostic/prepare-failover-binding/applied-validation/focused-native-recovery-pin-v3.log`,
SHA-256 `6406f2d0806f6751f6bdad2a600f3b6a5e193ec03d7ff60ae31fd84a9822e275`).
The uninstrumented installed three-node case then advanced beyond its old
`Prepare` stall but failed **0/1** after the unchanged 240-second recovery
deadline (`focused-three-after-semantic-digest.log`, SHA-256
`5524127d28445f0d75fdf3697a3813556fb5d872bab5b469680112d95b5e330b`,
292.09 test seconds). Its durable head reached `Materialize`; target node 1
repeatedly returned `target outcome unresolved; recover the exact committed
identity` for `ResumeMaterialization`. Both a pre-result response-waiter
timeout and several post-admission errors map to that safe unknown result, so
the log does not prove effect acceptance or the underlying cause.
No no-effect conclusion, extended deadline or HA acceptance follows from this
run. A subsequent full test-only target-cause run also failed **0/1** after
306.39 test seconds (`target/runtime-recovery-diagnostic/materialize-unresolved/focused-three-with-target-cause.log`,
SHA-256 `c8130da4da2eba1edc5ea175d049a27a52c8c501457e26f37cb7ee8147561a9f`).
It located the unknown result at the target journal's generation-file open;
the other visible error was `persistent file is outside installed accounting
roots`. A narrower journal probe confirmed that same exact inner cause at
`MaterializationFile::open` (`target/runtime-recovery-diagnostic/materialize-unresolved/focused-three-with-journal-cause.log`,
SHA-256 `6ad6db06c80387c46471893457141f2a30b39b7096eae990faffcbdd4470f1e7`);
that diagnostic was stopped with SIGTERM after the cause was reproduced,
without claiming a test result. `checked_generation_path` had
constructed the child path from a canonicalized root, while NodeDisk binds the
configured lexical root. This can diverge on macOS (`/var` and `/private/var`).
The correction constructs the child below the installed root after checking
its canonical identity, with a regression assertion for the returned parent.
The installed three-node rerun on the correction failed **0/1** after 302.31
test seconds (`target/runtime-recovery-diagnostic/materialize-unresolved/focused-three-after-lexical-path.log`,
SHA-256 `bee52807381f2c195d8d26a292379143bd0fe85c0d1bbfe6f40315d0c661fa4b`).
Its Control head reached `Initialize`, with all three voters recorded as
materialized; the fixture reported `materialized_one=true`. An initial target
grant expired during the phase. Later fresh Control phases encountered the
target's existing `InitialTargetIntent` and returned `target initialization
identity already bound`, so no initialization success was inferred. The
remaining G09 solution needs authenticated exact status/evidence for the
earlier target command before Control may issue a successor; merely ignoring
the stored intent or extending the deadline would not establish safety.
A source-hashed blocked proof (`target/g09-initialize-evidence-candidate/README.md`,
SHA-256 `e591a18454b9859d12082de5ac8512092cc96c35a164de69e97c12b290983cba`)
shows why the current pre-Raft `InitialTargetIntent` plus current membership
cannot authenticate which recovery phase initialized the target. It specifies
the missing exclusive phase owner, committed/applied initial-membership fact,
read-only signed status, and Control one-use/retained outcome contract. This
is a target-only design, not implemented recovery evidence.
The later exact-target Execute envelope proposal (`target/g09-target-execute-envelope-candidate/README.md`,
patch SHA-256 `88d5a587b405b2a07d5194a588111370221cff257fc356f4a8011de390121669`)
is also target-only and **not applied**: it has no durable same-effect owner,
Raft first-membership proof, signed historical status or Control retained
resolution. The independent owner audit
(`target/g09-owner-state-machine-independent-audit/README.md`, SHA-256
`8539133dc14dc9c27c22f2649c166e50edc4a1a62bf2f5e3b23efe62ca8b0734`)
traces the separate journal/target/Raft commits and requires a first-membership
fact paired with the applied cursor and snapshot custody. No safe callable
narrow patch or positive recovery result is claimed.
Independent path review also identified a pre-existing StopLocal false-absence
race during transient generation-root substitution. The lexical path fix does
not close that gap. An independently reviewed managed `NodeDisk::open_file`
absence check is now applied for StopLocal cleanup and reply release (patch
SHA-256 `f3b516e52ed12d80533241a1092a8b3ca0aa0bd7c360971390d7b6504776a851`);
its focused server shutdown suite passes **7/7**
(`target/runtime-recovery-diagnostic/materialize-unresolved/stop-local-managed-absence-applied-focused.log`,
SHA-256 `94f89f66d3c49e81aeabeef5688571120b1dc53867a132cc5f28c476b1b5e066`).
The full signed StopLocal sequence has not been qualified on this combined source.
G09 and HA remain open.

The full serial engine library run after prefixed-command replay completed
with **254 passed, one ignored, one failed** (`target/first-release-prefixed-command-replay-next/engine-lib-serial-after-prefixed.log`,
SHA-256 `a2ff6d699dbff67a4580735d7bbe7153bc29fe6722469a13a9bb2e69fe660faa`).
The failure was a serving-expiry fixture's 10-second local read-barrier wait:
another replica won the election, so that original node remained a healthy
follower. A fixture-only change disables automatic elections after initial
and reopened leader readiness. The named case subsequently passed **3/3
separate focused runs** (`target/first-release-prefixed-command-replay-next/serving-expiry-after-election-freeze-focused-{1,2,3}.log`,
SHA-256 respectively `3a177c942ca758cff6412a02b8f2e7981746932e7b7748e29c16805ecc73042e`,
`cfb1dac899f2e8546983728b0240bcb088d1dbca1c905ab1081cd9c0dbfc1b7e`, and
`733a0d8aaea2888300a863ffe85a6648b2da8802f3e41117e929c2926c6fcd5c`).
This does not establish the masked cause of the earlier uncertain backup
attempt, and the full serial engine library cohort has not been repeated on
this newer source. The G02
registered-opening one-shot Ready proof is applied and passes **20/20** focused
store cases, including close during census registration
(`target/g02-registered-opening-next/applied-focused.log`, SHA-256
`cf663db1e50f0629f7db1569e38d4d27736dd2a9572b353671606b25f337c1b7`).
It remains a dormant prerequisite: no production reader census or caller
cutover exists, and final-sync uncertainty still needs fault coverage. The
first reader candidate was rejected because a consuming close panic loses
the exact snapshot owner; v2 was rejected because untyped table handles could
outlive the guard count. Reviewed v3 (patch SHA-256
`cc657a09e83b938c9df2cfe31ef9a8a022a116c20cd28333826e4da6200cf843`)
is now applied. Its six focused vendored redb tests pass (`target/g02-registered-opening-next/reader-v3-applied-focused.log`,
SHA-256 `eeb26e1dc61dc22043dc76fabbfd455a5b5283ca762e5bd3fe829aa7b20471f0`);
the full serial vendored library run passes **215/215**
(`target/g02-registered-opening-next/reader-v3-applied-full-lib.log`, SHA-256
`ec69ec56d619dd2d0cdff156391127c49d2e25c6ff6087066d92b6f95053147e`).
Strict vendored all-target/all-feature Clippy passed after five narrow lint
corrections (`target/g02-registered-opening-next/reader-v3-applied-strict-clippy-v2.log`,
SHA-256 `229e4ef5ba4f617caef519ac56f474acb6beb8d69befdeb7105ffe923740c7e9`).
The six reader tests passed again after the one iterator rewrite
(`target/g02-registered-opening-next/reader-v3-after-clippy-fix-focused.log`,
SHA-256 `3203c93bfe44018b5e8ecb88a7a62a464ba57490ef5f64b00d84de269c54f107`).
A production reader-census caller cutover and admission-backed `TenantReadView`
are still absent. G07's combined committed MCP mutation, family
renewal and original-deadline response-fence regression passes **1/1**
(`target/g07-mcp-response-fence-review/applied-focused.log`, SHA-256
`43bc7d844e38d3299bbeae1668db1f60a1dd31204a1f78a7cf4de836eaa2bfcc`).
An independently reviewed test-only successor (patch SHA-256
`f0ad2ea2e2adbdb2214f092df69376e06b448791b896fbef5589ed225a8ad8fc`;
`target/g07-mcp-installed-tls-candidate/independent-review.md`) adds an
installed `NodeRuntime` TLS 1.3 case with a held committed mutation, original
deadline expiry, `UNKNOWN_OUTCOME`, renewed receipt lookup and identical retry.
Its focused server case passes **1/1** in 20.30 test seconds
(`target/g07-mcp-installed-tls-candidate/applied-focused.log`, SHA-256
`30ae420a3343c4c60b991620973069d23d7daadea136f37a4110852da2fd8933`).
Separate-process cancellation, panic and drain qualification remain open.

The independently reviewed retained-reader census patch (SHA-256
`b4bb4c41d222c19bd93dd7470a8f282b202ccd89f8c903db7873baf199372cf1`;
`target/g02-retained-reader-integration/independent-review.md`) is applied as
a bounded opening prerequisite. The first compile command used a filter with
zero matching tests (`applied-focused.log`, SHA-256
`15aae2bab9290285c84ee995b5e94382f884ccd1c855e357267efa68dd230e7e`),
so it is not counted as test evidence. The corrected opening-module run passes
**22/22** (`applied-opening-module.log`, SHA-256
`205cec7dec002467ca384ef814926f186944ef3ff2fbd6a7db668c2caa940193`).
The full serial store library suite on that applied patch passes **388/388**
with two existing ignores (`applied-full-store-lib.log`, SHA-256
`e8ccd35ea27e5d84fd9325c44386405d51808485cb38b6e6338db3e91f87d4f0`,
240.53 seconds). Two later focused tests establish output-admission panic
retention/sealing and exact point/range output-credit lifetime after reader
close; the now **24/24** opening module passes (`applied-opening-fault-and-credit.log`,
SHA-256 `e31548083306efbf9f2eb379294425a6f08e43839e9c68d3be34e1b4e6fbbdae`).
Production `NodeStore` constructors, writes, `TenantReadView` and point/range
callers still use the old raw transaction path. This patch does not close G02.

The independently reviewed fixed catalog input-buffer patch (SHA-256
`2b7f337394b0f73616a802d95f8ab26d7e215b67fe65200d94f60ff4dada5bb9`;
`target/g02-production-reader-cutover-candidate/revision2/independent-review.md`)
is applied as a dormant G02 prerequisite. An added boundary case confirms
exact `MAX_KEY_CATALOG_BYTES` success and one-byte-over refusal with no leaked
reservation. The first compile exposed a test-only `assert_eq!` requiring
`Debug` on `KeyCatalog`; its failed log is preserved at
`target/g02-production-reader-cutover-candidate/revision2/applied-focused-compile-failure.log`
(SHA-256 `f1c82316108c2b9e323d4366ec3756fe3db3497e0ed2e0e154cb3b4e40f9649d`).
The corrected focused suite passes **3/3** (`applied-focused-corrected.log`,
SHA-256 `9c5a50d10bc9223cff597bd8b33802655a525b4bf57dbd3e45d1293172822229`),
the full serial store library passes **393/393** with two ignored after
320.46 seconds (`applied-full-store-lib.log`, SHA-256
`07c3525a724ae52f453c8271a2644ecc64c358bc9ee38c247223e91e1384590a`),
and strict all-target/all-feature types/store Clippy passes
(`applied-types-store-strict-clippy.log`, SHA-256
`666d60bfeed95ad8a23f512e6dcedcab6c3deea30ad126dd7919e90ca3f92231`).
The plan funds only its materialized serialized input buffer. A separate
source audit (`target/g02-write-transaction-bound-audit/README.md`, SHA-256
`bf82a0978a8bd061ee0da159e1c089672301744e4a7480e87da118572af0fb2c`)
found redb cache-page and transaction/terminal allocations without complete
resident admission. Its cache-page follow-up (`cache-page-primitive-blockers.md`,
SHA-256 `9889bb31e30610bbc9caea80e55b453b15bcc792fda1d2f3708945b6126d8cda`)
found raw page `Arc` escapes and allocation after cache mutation; a cache-only
lease would release credit too soon or deny after effect. No runnable
catalog-put request or production caller switch is claimed. G02 remains open.

Two further dormant store prerequisites were applied after independent source
review. The G05 exact namespace-binding/S3 constructor patch is SHA-256
`a3b3724699d410901d4ca793963dddad0e36791edc3f0b7d07b610610a90449b`;
its type cases pass **2/2** (`target/g05-backup-binding-next/applied-types-focused.log`,
SHA-256 `58949df6bf8181fe26c7ce0a4a9b6af74d0596652c20796280255fd2bf4d8bf1`)
and its S3 store case passes **1/1** (`applied-store-focused.log`, SHA-256
`a6260995f787c0e12ffd8acf8f03ab3a04131103ce1b2de46e57bc8a13224e0f`).
No session intent, destination capability or Control index uses the binding.
An independently reviewed immutable `BackupBindingClaim`/`BackupBindingRecord`
value patch (SHA-256 `dc72e225dde5c3a93f0fbad7484bf63e20ff2cb27a0392cd0c787d76247c46dd`;
`target/g05-control-binding-next-candidate/independent-review.md`) is also
applied as a dormant type prerequisite. Its three focused tests pass
(`applied-focused.log`, SHA-256
`a5a9bbf995dc6e5b9181a8f9f889364de40eaa6113057a9e9b1a4a099971e9cc`),
and the complete types library passes **24/24** (`applied-types-full-lib.log`,
SHA-256 `251918ddd968d801238df8f6370c2974c8bf4af14250b56a36530fc9d7960d07`).
The public value validates shape and ciphertext digest, not source authority;
Control publication/readback, encoded-row admission, filesystem marker and
UUID-only callers are still absent. G05 remains open.
The independently reviewed 21-path G05 Control point-table scaffold (patch
SHA-256 `e86a095b9f375efc32ed66e64c9127b5abdd79a852921bc4ddc750c2894fc183`;
`target/g05-control-point-table-safe-candidate/independent-review.md`) is now
applied. It introduces a selected encrypted Control namespace and advances
the snapshot format directly to `KASUMIT8`, without a production claim
command, reducer or backup caller. The first focused compilation found two
snapshot test helpers still calling the old writer signature; the failed log
is preserved at `target/g05-control-point-table-safe-candidate/applied-focused-compile-failure.log`
(SHA-256 `d5ff79ce286ed14e729fa967314c4626fd966ab22588a927660e93e57c691a9f`).
Those test callers now pass an explicit empty binding view, without retaining
an overload or old format. The four focused engine tests pass
(`applied-focused-corrected.log`, SHA-256
`6715c5c5d8c4e5e21588fea9f03aa66ccf7cc03854b7094cf4d439fcdf860d45`,
3.91 test seconds). The serial full types/engine suite subsequently failed
with **258 passed, 1 failed, 1 ignored** in the engine after 724.06 seconds
(`applied-types-engine-full-lib.log`, SHA-256
`dd3736c89ff1c51d472bf6730190fc311cf4e9bc596afef8cb572eb0b605a5d1`).
The failing two-hop restored application snapshot passed full decoding but
failed indexed validation; the exact focused rerun reproduced 0/1 after
32.32 seconds (`applied-snapshot-two-hop-focused.log`, SHA-256
`5bd3bba9240c766de83c3f9a0c2e29424fbc7348a04154a141eb7e25a511f898`).
The indexed Control-empty-head check compares against the current incarnation,
while a restored application retains the authenticated original head origin.
This regression is unresolved in this recorded attempt.
An independently reviewed revision-2 correction (patch SHA-256
`98ae4f70a5b7f6e36e88b555d2f38712583155cfc01191836fdfd8c3921c6932`;
`target/g05-snapshot-two-hop-correction/revision2/independent-review.md`)
is now applied. Both validation paths accept the authentic retained empty
head after two restore hops and reject a canonical empty head whose origin is
outside the verified lineage. The exact focused case passes **1/1** in
64.35 seconds (`revision2/applied-focused.log`, SHA-256
`6e354f775ab81da7ba97ae44987f93ef8cae4b0233ce78f319ca592359d259e4`).
Its first full types/engine rerun reached 137 passed engine cases, then
stalled in `long_backup_verification_and_encoded_read_recheck_original_credential`;
the idle process was interrupted and the failed log is preserved at
`revision2/applied-types-engine-full-lib.log` (SHA-256
`389251f1363d2b79097ff66a5bd86c9996eacef750a4b3e501bfd6b5f625e35c`).
The same case passes alone in 4.53 seconds (`revision2/applied-credential-focused-before-instrumentation.log`,
SHA-256 `8887a8f938ec5f1f67320f6de2fca891eb9ea757241936945912baf2573aebac`).
The suite-level stall remains under diagnosis, so no full-suite pass is claimed.
The independently reviewed supplemental G05 fault-test patch (SHA-256
`bd852a3ccc6b07acdbb499fe21b643a18fd3cc721ac5f39f4e03690856c5e975`;
`target/g05-point-table-fault-tests/revision2/independent-review.md`) is
applied. Its first focused compile exposed three test-only module paths; the
failure is preserved in `revision2/applied-focused.log` (SHA-256
`c0afc3559b4842021eaec015d2e0f792f2df0f352eb946bb1de757a447e528ef`).
After correcting them, the actual `backup_binding::tests` group passes **7/7**
(`revision2/applied-focused-actual.log`, SHA-256
`e35774f39a9fa290818f183b90d3eda25fc44800a6491834758a9bdfe4f90d02`).
The tests cover healthy physical reopen, selected point readback, future-row
invisibility and exact replay, three durable damage cases, and application
snapshot rejection. They do not exercise a production Control claim.
A target-only source-registry audit (`target/g05-source-registry-prerequisite/README.md`)
finds the trait lacks physical binding, public backup paths bypass a mandatory
registry, Admin can address suspended/retired generations, and a producer may
capture revision R+1 after a preflight for R. A separate physical-binding
audit (`target/g05-physical-binding-capability/README.md`) finds the verified
installation ID and directory device/inode do not reach filesystem destination
opening, so no trustworthy marker can yet be issued. These are design
findings, not a source claim or backup PUT. G05 remains open.
The subsequent serial types/engine rerun completed with **261 passed, one
failed, one ignored** in the engine after 908.10 seconds
(`target/g05-snapshot-two-hop-correction/revision2/test-handshake-candidate/revision2/applied-types-engine-full-lib-retry.log`,
SHA-256 `40f15634b68e5b8617b78f97527b1f8323b21739d44aa15cda908b8b25c1f9d8`).
The prior long-backup case passed in this cohort. The sole failure was a
10-second leader-fixture timeout in
`serving_expiry_suppresses_long_backup_verification_and_post_publication_proof`;
the exact case passes alone (`applied-serving-expiry-focused.log`, SHA-256
`495a43bba7b655b7020f9747a61833a03db21242632643079154d9fa3b572ea3`).
A reviewed test-only diagnostic now reports its timeout phase, last barrier
error and node metrics without changing its deadline. The full engine suite
has not passed on this source.

Three reviewed G05 physical-identity/owner prerequisites are applied:
verified `NodeDiskDirectory` identity (patch SHA-256
`53069d0df64b0441e4b139185d0210aafa654bb81c1bca5bd31d855444f32eea`),
standalone installed owner custody (patch SHA-256
`3c24251b2ae4c8488aeebf0a5a52a3a8063595a469b112ca5d3ff5a30f4e3eac`),
and replicated signer identity retention (patch SHA-256
`a0901a27a11e6301579ecd3ab9a25a59f3591f65e6b90b52e67c19e0536147e8`).
The complete serial store library passes **395/395**, with two ignored
(`target/g05-verified-directory-identity-primitive/applied-full-store-lib.log`,
SHA-256 `1c6bba36fec1e68d0d066c5b6ba96488af7da91b450ad53ba9b7f63176e4f0aa`).
Focused server provision **3/3**, standalone ownership **5/5**, installed MCP
regression **1/1**, and strict all-target/all-feature store/server Clippy pass;
the corrected Clippy log is
`target/g05-installed-owner-handoff-candidate/applied-strict-clippy-corrected2.log`
(SHA-256 `7e3da3dd68562840f99bbfe3bc364cce28d00f0066a447cdc5787a00c639a423`).
The standalone staging group still overflows a normal libtest stack, and its
large-stack same-process run revealed a cancelled process-wide startup owner.
Two test-only patch revisions are rejected and remain unapplied; revision 2
(`target/g05-tenant-staging-stack-isolation/revision2/independent-review.md`,
SHA-256 `59344b63e17c3f7066c9edfa5b00e907f4ea2e56eb54035b7fee79e727603843`)
still skips the registry drain on a fixture panic. The installed identity
prerequisites grant no backup writer. The marker, mandatory destination gate,
Control claim/readback and cleanup remain open.
The independently reviewed G01 snapshot-metadata revision 5 (patch SHA-256
`c1421d1634294467c0bd53513bc22ac503fab30c2bf469d64f75a14900fd3c40`)
is applied on `master`. It uses one canonical bounded reader for snapshot
manifest/coverage, rejects UUID aliases and unknown fields, and checks the
shared 2 MiB coverage limit before application or custody publication. The
Raft library test build passes (`target/g01-no-compatibility-audit/revision5/applied-raft-lib-no-run.log`,
SHA-256 `74e1e3fb77c35b8312427120381688e1f2f57eab667da8f5b015d992bb3e08f3`).
The three new focused cases pass independently: strict metadata
(`applied-focused-metadata.log`, SHA-256
`f9fbbbdb89bec13f4b35d4eb7762e5d41be54593d84bce1ec7cadbba3fa9ed03`),
application coverage boundary (`applied-focused-coverage-boundary.log`, SHA-256
`232b67d642bf9e78cd9acfcc30961a9ade5ca68a17b7d74b9ecad9fceeac6ca8`),
and near-limit closed custody coverage (`applied-focused-closed-boundary.log`,
SHA-256 `dbd4531324c0d879aa354fbfc45dd72b49076842f88a93fa079ed965e329c3ca`).
The revision-5 serial library run was stopped by SIGTERM after the long
`custody_capacity_tests` case remained active for about 16 minutes; its
incomplete log is preserved as `applied-raft-full-lib.log` (SHA-256
`f2ec5e18b505e73f3dc3554e4ef000f8e209b0c51ffe15d3bb4c4a7a1ddb07d0`).
The same compiled source passes its other **75/75** serial Raft cases with
that single long case filtered (`applied-raft-lib-excluding-long-capacity.log`,
SHA-256 `1b24c85818514bad9dff8d29390a1d426af4fd01eee5cce1df1785616003d193`).
The first adjacent closed-manifest/retirement-projection candidate was
rejected because oversized projection refusal followed durable pending chunk
staging (`target/g01-no-compatibility-audit/adjacent-records/independent-review.md`,
SHA-256 `ba4ec77e915ac8ce2ff05d6652f18e30485d65e853fa24a71604c0e0f16c6f5f`).
Reviewed revision 2 is now applied (patch SHA-256
`f91852822679e4b6883c9f8cf4be83004cd631d43a2ed03660706971c6531562`;
review SHA-256 `d5ae68a42566e8fee6bb2a75453c398e6b21e8dd754c072a22825b703cb315c5`).
It preflights exact projection bytes before application snapshot staging,
retains the publication-time check, and uses strict Manifest/Projection
readers. Its focused closed-manifest case passes **1/1** (`revision2/applied-focused-manifest.log`,
SHA-256 `16f18c9c911f8469025ca663bf30d162874889a678257ee98f40a95b536f707c`),
and its 2 MiB projection/no-residue case passes **1/1**
(`revision2/applied-focused-projection.log`, SHA-256
`306061deedc0b2820173dbf198382c6c3c95aa6ea717359957cb4be88dd78dc1`).
The updated serial Raft cohort passes **77/77** with only that same long
custody-capacity case filtered (`revision2/applied-raft-lib-excluding-long-capacity.log`,
SHA-256 `1fed51e2ab35363e301ef316357b252239117be11a0f2492421d9c85185535fb`,
383.92 seconds). Strict all-target/all-feature Raft/store Clippy passes
(`revision2/applied-raft-store-strict-clippy.log`, SHA-256
`798972d56c53b79a461ced96a13bae8b992b78737576168302a391f86dc11e1c`).
The historically long case and full Raft suite remain unqualified. G01 remains open.
The earlier administrative DTO, ordinary Raft replay and local JWT omission
findings are source-closed on this `master` checkout. Scoped source reviews are
`target/g01-admin-dto-strict-candidate/REVIEW.md` (SHA-256
`c101c94a392e42e576f0a32def4febe8ed6ed76a481f0b324475cd2895cb910f`),
`target/g01-ordinary-raft-replay-audit-20260924/README.md` (SHA-256
`580923862794e0913c7b5248b247ba27e9c6170d3fa1df892ec63ca7c7592f12`),
and `target/g01-jwt-strict-candidate/README.md` (SHA-256
`247180e386825e754c26bd61cc357cc07332dfc972e24eb2584bf12ab0f9936e`).
A test-only native administrative boundary regression is applied (patch SHA-256
`0c37f30fe5ed063253ca5a7034c75abc11abac989eaa109a302c99010859fb71`)
and passes **1/1** (`applied-focused-server.log`, SHA-256
`8938adb4996833b47d0d16e4762b8f30d9db2e71a4ca0d6f9e4b5f30072ca2ca`).
The existing local JWT missing-claim case passes **1/1** on the current server
binary (`current-source-focused-server.log`, SHA-256
`dfc72b6ad6d443b47c87d27832df80f1a455f989797824f0e03574bb7b13edc6`).
Strict all-target/all-feature server Clippy passes after that test addition
(`applied-strict-server-clippy.log`, SHA-256
`0ce42209e59e75163a5b2ea858238f518bcf4b095bde7521304f4fed4fbd9a0e`).
The current-source engine replay cases pass **3/3**
(`target/g01-ordinary-raft-replay-audit-20260924/current-source-engine-focused.log`,
SHA-256 `274f9d3374b00fa985f72a439a8269e57ecdb7c7848f48f9c23cafee1b18f5e7`).
No full engine or release pass is claimed.
Two independently reviewed G05 target-only patches are also applied: the
standalone staging fixture panic-safe drain (patch SHA-256
`72ec1fa71cc24dd971bfa128b0255d479afe896c0d70ec487183987b92b32918`;
review SHA-256 `46b5894ed3819706d14d63bb24d3e580de00066c53c592ec9266adac13fbfebe`)
and the dormant strict 100-byte marker codec (patch SHA-256
`8cc57303d2f0375c67174b515321c0d4200119f803718bdf935cfeec8fda1c7a`;
review SHA-256 `002f7c7988ed29005d75e74933b9b32c8022e9bd132db8980f379ff19d9c5f9e`).
The marker codec passes **3/3** focused store tests
(`target/g05-marker-codec-candidate/applied-focused-store.log`, SHA-256
`862f00c32818968353f8e59fbeb3af8a93642f79f367acfdcd5f324e19e3c2b5`).
The staging fixture's first server compile failed at the test wrapper's
`resume_unwind` function-item coercion (log SHA-256
`8cd1cb7aa2688035305b117e6a149532c71a550a5ab049981abfb9c02b761f51`).
A closure fixes that compile error. The corrected normal-stack five-case run
then passed its first case and hung in the new panic-cleanup case; it was
terminated after about 90 seconds. The stalled log (`revision3/applied-focused-server-corrected.log`,
SHA-256 `5e42894892cf6f3706f61c640ec2ace6170f070cd98a276c1365fa0628bfd43f`)
and process sample (SHA-256
`d7c222e23986242b844cdc5e4f521a8b01b7b849f9815bcec40e4542e35e2015`)
are retained. The follow-on test-only directory-lifetime repair (patch SHA-256
`c8ce5aa51f65421cd72796f5e4618f686b7fe738c801a4f74800e150108ed98d`)
keeps the installation rooted until same-runtime operator drain finishes.
The original panic case passes **1/1** (`revision3/panic-lifetime-fix/early-panic-focused.log`,
SHA-256 `9970c8526e7170e62c0d3aba098e2fc716a5648c7115ce1cff5b8f9b794cf24f`),
and the complete normal-stack staging group passes **5/5 in one process**
(`revision3/panic-lifetime-fix/five-case-focused.log`, SHA-256
`54fce9b0b1044bd87c33e8be26af1b4d9d6b8e3faa76687a51a7c446b9a88b7b`,
76.20 seconds). The marker codec has no publication path or writer authority;
G05 remains open.
The same marker-codec source passes the serial store library **398/398**
runnable tests with two ignored (`target/g05-marker-codec-candidate/applied-full-store-lib.log`,
SHA-256 `0d170f05ff2c177e4816df755a712648b2122a403861fa91aa40b0136c4d1f2e`,
171.25 seconds). This run predates the later G06 audit-reference validation
edit and is not a full final-source store claim.
The reviewed G06 archive-reference validation patch (SHA-256
`b7d28a395b769736347d2a412e851dfc56af5369f319722979fd6e0b18d1d0a1`)
rejects wrapping-key version zero in the existing exact dependency record.
Its new focused types case passes **1/1**
(`target/g06-key-retention-page-next/applied-focused-types.log`, SHA-256
`69ff3a10a72784e9a590d7b971b4a052b30b42bb68fe6468ad02328e3c2fd76e`),
and the full types library passes **25/25** (`applied-full-types-lib.log`,
SHA-256 `163ed7863ae290d4c3d77868d2313b5e786af764faa5ad43f2f60bbde5540ee6`).
The affected store audit-archive module passes **9/9**
(`applied-store-audit-archive.log`, SHA-256
`923cf01d2ffc8210bd757fe1a577b773b38e8c8d350cd7da098745dada3189ea`).
The engine service-audit retention case passes **1/1** on the same source
(`applied-engine-audit-retention-correct-filter.log`, SHA-256
`1a7519612f6386cadcac08ef9b71a925f2b83674c76c202231a0d9eca7494f05`,
64.75 seconds). The preceding file-name filter selected zero tests; its
`applied-engine-audit-retention.log` (SHA-256
`25a9416a5aaecc536370a1bdae4963a0dd1b29b15b009f648f02e2dd71f5b212`)
is retained only as a compile receipt.
The source audit `target/g06-key-retention-page-next/REVIEW.md` maps the
missing cross-category dependency ledger and `ReadKeyRetention` API; G06
remains open.
The reviewed G11 nested-process ownership patch (SHA-256
`d3b5d1362d9b2e4bbc47306af6c36336556081f5a1910696d4df07d4d5f8a504`;
`target/installed-disk-validation/g11-assembly-process-ownership/independent-applied-review.md`,
SHA-256 `90e7b729de3d8d46aa925c9638da34b490252d9e695c7a4489f35efc87488538`)
is applied. It binds every nested ledger and terminal-census row to its
original process receipt's parent PID, executable digest and birth witness.
Real nested-process and substitution tests pass **14/14**
(`applied-focused-python.log`, SHA-256
`ff0b2b5eff8a88a95b7492a005249f5b395c45a2700e86495a3e77af07748696`).
An initial full discovery from the `scripts` directory failed six unrelated
tests that expect repository-root `target/` paths; its failed log is preserved
as `applied-full-python.log` (SHA-256
`6725e2529a0aba4f3d23e41816cf6c27ba566d5be591ca10c48991d8e7eda463`).
The correct repository-root discovery passes **131/131**
(`applied-full-python-root-cwd.log`, SHA-256
`3e872b273ec1e80f270c53283e09e0fedf35de00863ebffe6a425d4b8f9aa804`).
Native owned assembly and final-source platform gates remain open.
A further reviewed G11 dependency-verifier patch (SHA-256
`2319c1c5fc57875bf35ebca72c65f603170ba46b7a96d528df5c8f588ff4ca0a`;
`target/g11-semantic-adapter-next/review-notes.md`, SHA-256
`bd232f3b6a08bdcd2761b7aaf51c1b954b6559a25d0f957a9fac7539bf9e9e13`)
binds the original 30 Git, upstream-suite and advisory-scanner child receipts
to exact ordered ledger rows and terminal census. Consistently rehashed
parent, executable, birth and order substitutions are rejected. Complete
repository-root Python discovery passes **132/132** under bundled Python 3.12
(`target/g11-semantic-adapter-next/applied-full-python-root-cwd.log`, SHA-256
`a72b1e82c684e01b5843e0b8c8a9ab0bc3f4da362aba37eb69ca3e3e5f2d49af`).
The dependency and assembly semantic adapters remain unregistered; native
qualification and G11 acceptance remain open.
After the G06 validation and G11 verifier edits, pinned Rust 1.97.1 strict
all-target/all-feature **workspace Clippy** passes
(`target/first-release-current-source-20260924/strict-workspace-clippy.log`,
SHA-256 `fd320cdb38f8488d820a66af3cfd0b2e12610c8f84177745d0a37b3f22d3e80c`).
`cargo fmt --all -- --check` and `git diff --check` also pass on that source.
This is a development check, not final-source native qualification.
The merged G06 historical resolver/descriptor patch is SHA-256
`fe00a8c91dc510d2a799df368ceaa49565ec3e8745629f1514159fc9a64c9c35`;
the focused historical store cases pass **14/14**
(`target/g06-merged-resolver-descriptor/applied-historical-focused.log`, SHA-256
`a296e8a21572cbcad8a62643c2e27ecb9804bf9c3dcbbb80aaa2c4126b201723`)
and all-target/all-feature store check passes (`applied-store-all-targets-check.log`,
SHA-256 `a0fa4a033133d0b7bdf4c84b9cc8cd1a80b96b1abd852985ab3d32fd20aec605`).
It is not installed into accepted recovery or historical read callers. The
first full store library run failed **385 passed, one failed, two ignored**
(`target/g06-merged-resolver-descriptor/applied-store-full-lib.log`, SHA-256
`7e138e512ae171c7e6d5babfd9e84608c95886be4383eee71dddc7dc8c0cb137`,
140.62 seconds). Its sole failure was the existing managed-directory fixture's
ancestor-lock depth calculated from lexical `/var` rather than physical
`/private/var`. That fixture now calculates the canonical ancestor depth; the
named case passes **1/1** (`target/g06-merged-resolver-descriptor/store-managed-depth-focused.log`,
SHA-256 `ff16e09a9e0bf7d0636b1e9982c1270124d2d8a3d8cefa92f6871ca024174ada`).
The corrected full serial store library suite passes **386/386**, with two
ignored (`target/g06-merged-resolver-descriptor/applied-store-full-lib-v2.log`,
SHA-256 `50c44097066a9f7f08fdad1e945d13bbcee75bc2eb6180450add90723fd891e8`,
207.06 seconds). Strict all-target/all-feature store Clippy passes with
`-D warnings` (`target/g06-merged-resolver-descriptor/applied-store-strict-clippy.log`,
SHA-256 `d6d7ec8c573b6970f859084de2aed4d7a3dfbe6cb856e97cb840caccf60c198e`).
Workspace formatting and `git diff --check` pass on this source checkpoint.
G05 and G06 remain open.
After the reader fault tests and Control binding type were applied, strict
all-target/all-feature Clippy for `kasumi-types` and `kasumi-store` passed on
the combined source (`target/g02-retained-reader-integration/applied-types-store-strict-clippy.log`,
SHA-256 `9d1c197107bb95ad6e2670c31fa5fec5dd7deaab68d81f1febc133535d50cbf2`).

Several independent proposals remain **unapplied**. G05's permanent Control
backup point-table and filesystem marker patches are static-only candidates
under `target/g05-control-backup-binding-protocol/`; the filesystem patch alone
misses three recovery constructor calls. A later combined candidate includes
the newly applied S3 identity but still lacks trusted source-to-Control
routing, pre-upload Control claims, first-marker crash recovery and capacity
reservation, so it remains unapplied. G08's signed issuer `Effect|NoEffect` seal candidate is under
`target/g08-issuer-seal-candidate/`; its review requires Control linkage and
pre-reserved terminal capacity before integration. G06's accepted source-set
binding and G09's target exact-status requirements are target-only designs.
The independently reviewed G10 installed 129-healthy-group fixture (patch SHA-256
`019503f3e9c39ad94ed0bebdfae0cd2f51f2ee35ce7ff54093617e06da74c514`)
and its healthy-at-gate review correction (SHA-256
`a3709be927335db342170c0c9b3dc24e2a47942a8bebfa87e5dd6f865f1070fb`)
are now applied. The first focused protected-TLS run compiled, then failed
**0/1** at `NodeRuntime::open_using_storage` with
`ResourceExhausted: node memory or work admission budget exhausted` before
readiness probing (`target/g10-healthy-readiness-candidate/applied-focused.log`,
SHA-256 `03875a10447576c58bd584a7d2e1452553b6fd261caf878b61374cb49de0f096`,
358.38 test seconds). It used the generic single-tenant fixture total, which
resolves to at most 512 MiB. The fixture now selects the installation example's
explicit 2 GiB work total for this 129-group case, preserving host high-water,
operation/file slots, and original freshness/probe deadlines; it also reports
the policy and admission snapshot on another open failure. That rerun again
failed **0/1** at runtime open after 446.02 test seconds, now with the exact
`snapshot startup inventory exhausted` cause and a policy showing only 64
snapshot slots (`target/g10-healthy-readiness-candidate/applied-focused-production-budget.log`,
SHA-256 `da723bd77fbfd0527356420a8a3673592ec9cbfdd2e46bbe11dce579292f243f`).
Each installed Control/tenant Raft group retains one snapshot owner. The
fixture now pre-reserves exactly 129 snapshot-startup slots for its 129 groups
while leaving other slot limits unchanged. The third focused run passed
`NodeRuntime::open_using_storage`, then failed **0/1** after 390.60 test seconds
at the fixture's premature `installed_generation` assertion for `healthy-000`
(`target/g10-healthy-readiness-candidate/applied-focused-production-budget-and-snapshot-slots.log`,
SHA-256 `f31ea479f5fb72194ef227b55be8784ea8f3e0d500acb4d7910d476066bd91af`).
Runtime opening retains all 128 tenant stores, but serving reconciliation
publishes the installed routes; the assertion ran before `serve`. That failed
attempt is preserved separately from the later passing correction.
The independently reviewed protected archive-outage fixture revision 3
(patch SHA-256 `05d19b2b4d6b852ba9b7baf2577ba409e6a22370ec6a4a23246987353b7b42cf`;
`target/g10-archive-observability-candidate/outage-tls/revision3/independent-review.md`)
and the reviewed serving-phase registry assertion correction (patch SHA-256
`47d09ac2badd8569ff81cee9cdb83bfb9657542de9f39c33850a712ee53df9e7`;
`target/g10-healthy-readiness-candidate/catalog-registration-phase-correction/after-outage-revision3/independent-review.md`)
were applied in that order. The resulting observability test source matches
SHA-256 `7689aa900303f85d6b93d352b7c3616090831fe5d5c4727e771840217e7e6978`.
The archive-outage protected-TLS test passes **1/1**
(`target/g10-archive-observability-candidate/outage-tls/revision3/applied-focused.log`,
SHA-256 `ac4146c1a46ebdc95ad205232a0875975b9be84b71b4fc6abde550b453ebcea9`,
28.48 test seconds). It observes an installed missing-credential S3 failure and
nonzero due backlog through protected `/ready` and `/metrics`, without a
synthetic counter. The corrected installed 129-group protected-TLS run passes
**1/1** (`target/g10-healthy-readiness-candidate/applied-focused-after-archive-and-registry-phase.log`,
SHA-256 `236a9a535598b5b64b44b378f5811fa87f7bd83b2e09a3089a2b71845f483673`,
429.81 test seconds). It observes all 129 installed Control/tenant groups
healthy with complete fresh membership-epoch coverage while the JSON detail
page remains capped at 128. It verifies protected readiness and metrics,
withholds a previously healthy response across an actual membership change,
then seals a store beyond the detail page and observes 128/129 healthy plus
HTTP 503. At the first healthy certificate, the sweep waited 594 ms after
serving began; oldest probe age was 0.164672042 s, admission reserved bytes
1,446,581,800, resident bytes 96,600,064, and persistent charged bytes
8,953,856. This focused fixture does not prove the remaining backup,
authority, recovery and outage observations, ambiguous S3 reply handling or
repaired-credential recovery; G10 remains open.
G11's original owned dependency/advisory runner proposal was unregistered
because path-patched crates evaded its advisory scan, a fabricated Git HEAD
could be accepted, and serde_json feature combinations were omitted. A first
correction remained unapplied after independent review found its scanner report
was not bound to the owned child's stdout/stderr receipt. The reviewed revision
2 patch (SHA-256 `ef5cab6981725edcdf31789a9e1f3f3b6aaf5660dd48f67bc32f9191ca76881c`;
`target/g11-dependency-runner-corrected/revision2/independent-review.md`) is
now applied as an **unregistered** runner prerequisite. It uses an exact
path-patch scan projection, packed/loose Git object verification, four
serde_json feature modes, and exact scanner receipt binding. The first applied
test attempt used macOS Python 3.9, which lacks `tomllib`, and failed before
running tests (`applied-runner-tests.log`, SHA-256
`7679dd94ba8c7041a6a95cb6eb846a4e51a333aa2a905defa0a5058c65b35010`).
With bundled Python 3.12.14, its focused suite passes **10/10**
(`applied-runner-tests-py312.log`, SHA-256
`8768565996d183391681cdbf056c29beb30536ac022a8c8949934ff77d086d60`)
and complete repository Python discovery passes **129/129**
(`applied-python-suite.log`, SHA-256
`6c8efeecd665a35c2f4a05218dfdf92eebb9571b21666f2f2d6e92bade9a9fce`).
The adapter remains unregistered. A Git-free injected scanner probe ran its
path-patch projection but stopped at the source-only verifier before invoking
the scanner: existing redb provenance still identifies the source preceding
the applied G02 patches (`target/g11-actual-scanner-probe-prep/run-gitless.s0bx9bfl/attempt.json`,
SHA-256 `4955df40aaa8df3837c9369da6374927dbe106966c6075740c69e116dd5365d6`).
The first source-rebind proposal failed independent review because it omitted
exact post-patch edits; its reviewed successor is described below. A native
owned advisory scan, authenticated current advisory fetch/Git and scanner
provenance, and native Linux ARM64 qualification remain missing; no G11 or
release acceptance is claimed.
The independently reviewed revision-3 redb source rebind is now applied
(`target/g11-actual-scanner-probe-prep/vendor-rebind-candidate/revision3/candidate.patch`,
SHA-256 `2ae2f9b5804b4151485d19d59fafe3ab0d5ff61dd6a89d770b422fa6d14a5eb8`;
final review SHA-256 `daa31a27c54fc0fa633633d24dc658c4881b58baa73ea66d93bbc0276638a21d`).
It retains all four exact G02 patches, five post-patch integration deltas and
the prior independent review; the live manifest is SHA-256
`63ab0a193d3137eb6237beb5ace5f4533eb9ede0e92a843d227b477792b84fe3`.
The official source-plus-locked-Cargo checker verifies all seven vendored
packages (`revision3/applied-official-checker.log`, SHA-256
`eb0dd3737aba60ccd80fde615f3eebe4d60bf632e9d01a1db97a80bf4bbec7c6`);
its focused checker and runner tests pass **18/18** and **10/10**. Complete
Python discovery passes **129/129** (`revision3/applied-full-python-discovery.log`,
SHA-256 `a6c13ff4428d9ed582e1cbd289ef93e89110275d8ec310708202d9a5d6c775b7`).
The Git-free injected cargo-audit diagnostic now completes and detects the
synthetic `RUSTSEC-2026-9999` against projected redb 4.2.0; its exact attempt
is `target/g11-actual-scanner-probe-prep/run-gitless.dz239bhp/attempt.json`
(SHA-256 `538bfa21c2c2b48eb4965467285f17fdb5c5f42c48e736b5613c5e13aba162e4`).
An independent artifact audit (`run-gitless.dz239bhp/independent-audit.md`,
SHA-256 `f4c9673ec6fe3baff4e9bc66e30c17f7e40b13315e2568ca98e3f8b921f71201`)
confirms the raw scanner finding and undisposed rejection on the projected
lockfile, with unchanged selected source hashes before and after.
That synthetic local probe is not an authenticated advisory fetch, native
runner qualification, or G11 acceptance.

The reviewed G07 MCP Content-Length terminal-fence patch is applied
(`target/g07-mcp-terminal-fence-next/candidate.patch`, SHA-256
`eb7798f2d37a02bd948c1d8c2aa881b5757555ef491b13fdf575e3b261236f81`).
Its focused server regression passes **1/1**
(`applied-focused-server.log`, SHA-256
`ac5c382b286f5638ed00a56f3d2155c5b5867645e44a676a57f86963f5e750f6`).
The first strict workspace run failed on a collapsible-if lint
(`target/first-release-current-source-20260924/post-g07-strict-workspace-clippy.log`,
SHA-256 `eb4f6f29388562e5620478744dff1550b047ebf77c52435758336b42e5959754`).
After the equivalent style correction, formatting and all-target/all-feature
strict workspace Clippy pass (`post-g07-strict-workspace-clippy-revision2.log`,
SHA-256 `594027eae1845a3aa22be2c42196834ae8473e7a64788b74f3a5458076757ea0`).
The reviewed authority outcome-custody patch
(`target/g07-authority-terminal-custody/candidate.patch`, SHA-256
`3545e2bfe32653024ee77bc277d8f32d0b741be837e1a62614291e569d83ae59`)
is applied. The first focused authority run failed **7 passed, 2 failed**
because the older cancellation fixtures expected every completed slot to be
released (`applied-focused-authority.log`, SHA-256
`b4de5f0ddf423f3823ee9cd93c2f68043aa73f19701a3b2538de4957b61fefdf`).
Two test-only revisions first raced shutdown with final response fencing, then
expected the underlying policy conflict rather than the actual post-dispatch
`UnknownOutcome` (`applied-focused-authority-revision2.log`, SHA-256
`7fc58594ac871a2f72283fb31d3b1b4d66431a61695d11b80497c7f32252638a`;
`applied-focused-authority-revision3.log`, SHA-256
`6fde2880805fc1fe012ee4aa80f223f4314b073ffb1583dad9344bd4795ec3eb`).
The corrected fixtures wait for the original terminal child, then assert its
typed outcome in a complete shutdown drain; the module passes **9/9**
(`applied-focused-authority-revision4.log`, SHA-256
`933bbd472cede72bcf460993cee20eb98e8dd8d01cfcb878db95f8ae696dd610`).
Neither focused result is an installed process-drain or complete G07 gate.

The G11 native preflight schema-2 patch is applied
(`target/g11-acceptance-failclosed-next/candidate.patch`, SHA-256
`6b3904260b7e85b6acb65c9f3a35c55f7f4f2327c540b73a3fb860e6d256d35f`).
Its complete repository Python suite passes **134/134**
(`applied-full-python.log`, SHA-256
`c7041653870b3efd555bfa1e687a4feafd7d1cedc30b63f483217909795d32bc`).
The later failed-attempt process-group/return-code binding patch
(`target/g11-acceptance-failclosed-process-group/candidate.patch`, SHA-256
`e0e2aecc083343bb62f9144079e5517324dea50fda2fd31e247115af0bc5e80e`)
is applied with additional exact integer checks. The affected acceptance
suite passes **20/20** (`applied-focused-python.log`, SHA-256
`a86edfbac6b4cd3c43c4712f4835f953b514dd3bc0f13167cf27c7696c8bc4f9`).
The complete Python suite on this newer verifier source remains pending.
The target-only adapter audit (`target/g11-semantic-adapter-audit/blockers.md`,
SHA-256 `f3b6c9101f195d1c1a871f8b749020a657f3212d3e1c33a20015c39d6abdcf72`)
finds no native outer-launch receipt, so no semantic adapter is registered.
The reviewed producer cutover (`target/g11-owned-assembly-workflow-cutover/candidate.patch`,
SHA-256 `9aaa26d18f9c4d551e8c2061c08524d77573acf1b2b630e1b9ca5af673b4414e`)
now invokes the frozen owned launcher in both native workflow paths and the
operator command. Its affected Python module passes **13/13**
(`applied-focused-python.log`, SHA-256
`7e074beab9559f9256990fe3732d7bb4b8d1b2739dbf38140f792f2889bbccc8`).
The workflow still lacks a complete transitive functional-evidence upload and
has not run natively; its G11 domain adapter is not registered.
Source-bound G06/G10 design audits are retained at
`target/g06-historical-dispatch-next/implementation-sequence.md` (SHA-256
`d734a07e4c54044cd022627adec62b216f396a448b029d58c25c7ddae94fdf28`)
and `target/g10-durable-backup-outcomes-audit/REVIEW.md` (SHA-256
`61b0d7c3f84909812cf195c464c218ba497431a59e122876d7d44333f8f5a24b`).

The original frozen evidence qualifies only its exact recovery slice on native
macOS ARM64. The later focused results above have their narrower scopes.
Retained redb production construction/transaction/reader ownership, scratch and
backup admission, distributed recovery, full G07 process custody, G11 semantic
acceptance, full combined-source qualification, native Linux qualification,
capacity, the 86,400-second HA soak and release artifacts remain open. Backward
compatibility is forbidden; no G01–G14 goal or release gate is closed by this
record.

## Later master-only scoped results

The reviewed G04 archive cursor requires both a frozen snapshot head and the
previous page's chain boundary. Its patch is
`target/g04-archive-cursor-anchor-next/candidate.patch` (SHA-256
`2f56862cdfa5ca495cdbfa96b15f66b17c5eef2fd4b538767ff212aa94ad04e9`).
The applied client case passes 1/1 (`applied-focused-client.log`, SHA-256
`9408b9766e5b4e5783f1f7f7e1da62c60806498e9d3677f0ec86c163c9ed677f`),
as does the protected-TLS server case (`applied-focused-server.log`, SHA-256
`f5fff9734fa1d1ca56f3a4cf99e5b729583e650398128d9e8b16f087210f925f`).
These checks include later appends and a changed page boundary; archive
dependency and final native qualification remain open.

The first serial G07 authority library run on the later combined source had
**61 passed and 3 failed** (`target/g07-authority-terminal-custody/applied-full-authority-lib.log`,
SHA-256 `014f49aa5236ff118d5577be307c37e78d227e13639e42b07f51c07aef72e69c`).
The test-only owner-zero shutdown correction passes its focused case
(`target/g07-authority-full-suite-diagnosis/applied-focused-owner-zero.log`,
SHA-256 `ba5239c0fe0a83e68979447acc6f83ac66185fb33ab14506059ec04d25808524`).
An exact-status and receipt fixture correction then passes the isolated signer
case (`target/g07-authority-full-suite-diagnosis/exact-fixture/applied-focused-signer.log`,
SHA-256 `d8c0536ccfcbf1bc2297752dc35480f62635019ccf171f1006ccb843a8aa465b`)
and the restarted materialization case (`applied-focused-materialization.log`,
SHA-256 `5e23e2859ab957ad70ba13c65c8c152f9bc190cffa02ffcf57a2d991d975c45c`).
The target-stop case **still fails in isolation** after 60 seconds without a
positive administrative receipt during authority leader churn
(`applied-focused-target-stop.log`, SHA-256
`41f19aeed62efa9ce2151dac14a93173b513792b09044f9cfa7f5fb8a0354f95`).
The full authority, installed process-drain and G07 gates remain open.

The G10 protected `GET /recovery/{operation_id}` point read exposes only the
operation UUID, durable phase, revision and pending/terminal flags under the
administrative TLS, credential, Control-quorum, admission and response fences.
The applied patch is
`target/g10-recovery-authority-observability-next/recovery-point-status.patch`
(SHA-256 `d0459920cc9af44d21bece9d7ae31dc1f14fe708f2c992b53ee49bbf6830c0ce`).
Its first build failed because a borrowed request made the handler future
non-Send (`applied-focused-standalone-tls.log`, SHA-256
`688051883d31a1cad9f7708a28656dc64be2596ea24bd66727a28eb616c7c610`).
The owned-request correction passes the standalone protected-TLS case 1/1
(`applied-focused-standalone-tls-revision2.log`, SHA-256
`1feb8eb9b1cf91fbec0d39b211627089c1faeed64e3a3fcdf1fa1a704f96ddf2`).
The replicated positive phase assertion and durable aggregate coverage remain
unqualified, so G10 remains open.

G09's installed three-node recovery reached voter materialization but retained
an unresolved `Initialize` outcome: the first `Start(Quorum)` request can write
`target.lifecycle/initialize` before Raft membership, and a later fresh phase
cannot infer whether that earlier effect committed. The staged
`target/g09-initialize-exact-outcome-next/prerequisite-marker.patch` is
**not applied**; independent review found that it marks only the later
Initialize request and misses the first writer
(`target/g09-initialize-exact-outcome-next/INDEPENDENT-REVIEW.md`, SHA-256
`00c5024685718662a9320ea4838dafd15b6cdc035964204311714fbb53944dbd`).
The target-only `target/g09-initialize-exact-outcome-next/positive-resolution-plan.md`
(SHA-256 `a03d01cfaff992519c5c98b3a8ebc0141894f66d7f2ec941a7e2067320245f25`)
requires an exact owner for both writers and an immutable first-applied Raft
membership fact before a positive historical status. No intent-only or live
metrics observation is accepted as success. G09 remains open.

The G11 frozen-roster verifier rejects omitted or added functional-evidence
blobs. Its then-current complete Python suite passed **136/136**
(`target/g11-assembly-frozen-roster/applied-full-python.log`, SHA-256
`55fedf9cd44ee00b585b67df0d00b28b9a655c4425d78d62dd144055fb2fca73`).
The declared functional-evidence exporter retains receipt-listed gate
executables, logs, process/resource records, source archive and hidden source,
while excluding build cache; the next full suite passed **143/143**
(`target/g11-functional-export/applied-full-python.log`, SHA-256
`77a78d2ead9a49d089ebbf7999053c38912eb75a110b71da6fba666196b5e5aa`).
The digest-bound PAX tar preserves exact bytes and executable modes and
verifies safe readback; a failed final readback withdraws its success manifest.
The later full repository Python suite passes **149/149**
(`target/g11-functional-transport/applied-full-python.log`, SHA-256
`fcaef69087cf67d19a64fafb8b557c950d3f3fc6f02991198e19640ba6957c85`).
The native workflow has not yet transported the export end to end, the receipt
is not yet checked against all Cargo compiler-artifact executables, and no
semantic domain adapter is registered. G11 and release acceptance remain open.

The subsequent G01 custody-capacity diagnostic bounded the original long
case at 360 seconds and found the first command-builder pass still inserting
records (`target/custody-capacity-timeout-next/applied-diagnostic-360s.log`,
SHA-256 `7fc281cd29f886a69eed2e4cccd4d69b5456d5fad67c774aeefeed4ae2d2d1`).
The reviewed production change batches at most 16 encrypted command or audit
records per scratch transaction, under the existing 64 KiB per-record bound
(`batch-custody-builder.patch`, SHA-256
`44ffbb4c8069b86a856ab8d404e74cc8e73d33c37cdb4b5456203c31bae7ab35`).
The same large case passes **1/1 in 403.88 seconds**, including snapshot
publication, crash/reopen and exact digest and receipt identity
(`applied-batched-900s.log`, SHA-256
`417470805d7f0624c152ed952d7c63c9de0f6e74cc6aed8f10d737145e8b96ff`).
Timing-only test markers were reversed; the test file matches its original
SHA-256 `acebc8f3a409bfb5f4080fbd872dbfffedbd49a52daa71cf18d200ae06f264fb`.
The uninstrumented full Raft library suite then passed **78/78** in 842.68
seconds (`applied-full-raft-final.log`, SHA-256
`c678c72f95df57054bf0f896608ec6118906f6ae4b68af4eb6286868a37e4862`).
This does not close G01 or the broader capacity and native gates.

A bounded G07 leader diagnostic showed the target-stop case **passing 1/1**
after all three reopened authority members converged to term 3
(`target/g07-authority-leader-diagnosis/applied-focused-target-stop-diagnostic.log`,
SHA-256 `aaf675c6108838e634a20880c70f9840922c557f7bc60ab9c679a0ddfa3ccbdf`).
The earlier 60-second failure remains valid. The timing markers were removed,
and a test-only reopen readiness correction now waits for all members to agree
on one leader and term before and after a real linearizable barrier
(`target/g07-authority-reopen-readiness-candidate/candidate.patch`, SHA-256
`74111053834b527c3fca669b434f43b715a683bcda0e8fba695189b50cfe01e8`).
The first focused invocation used an exact libtest name without its module
prefix and ran **zero** tests; it is retained as
`applied-focused-target-stop.log` and is not evidence of a pass. The corrected
uninstrumented invocation passes the target-stop case **1/1 in 10.49 seconds**
(`applied-focused-target-stop-revision2.log`, SHA-256
`ed1b2b838305ef301f1fbe1c98c3732220e25e7110330a87349a5f8a09448046`).
The uninstrumented serial authority library rerun **failed 61/64 in 875.30
seconds** (`applied-full-authority-final.log`, SHA-256
`d3a1b88087f9e456c8c24f7b5710399a7218110a79c66c8b04aabaa74c97d3ba`).
Two maintenance cases timed out because fixture readiness required a learner or
removed voter to follow the current quorum leader. An inspection case observed
the exact `Store/Write` access fence `Sealed: independent serving authority
unavailable` during target shutdown. The independent diagnosis at
`target/g07-authority-reopen-readiness-candidate/INDEPENDENT-FULL-SUITE-DIAGNOSIS.md`
records the failure-run source hashes and panics. The fixture now selects a
self-reported leader, requires only its committed current voters to agree on
leader and term, and repeats that check after the real linearizable barrier.
The shutdown classifier accepts only the additional exact serving-authority
fence and rejects unrelated errors and wrong storage subject/verb. The three
failed cases and the classifier regression each pass separately. The next
uninstrumented serial authority library run passes **64/64 in 766.75 seconds**
(`applied-full-authority-after-fixtures.log`, SHA-256
`9b0b9fd9f57b51fb3a2fc1a4b474204137e14b1111e066a1804d8474ca268159`,
process-group exit 0). That run precedes the later G09 journal format change;
it is scoped G07 library evidence, not final release qualification. Production
authority behavior and strict receipt/status assertions were not changed.

G11's workflow now exports and verifies the bounded raw PAX transport on its
native functional jobs and uploads the tar without GitHub artifact archive
wrapping (`target/g11-workflow-transport-next/candidate.patch`, SHA-256
`246f009a0b1c7fdaf2214fced42e2e777b476d9a32d434d206bcf4050118fce0`).
It has not yet run natively. The corrected compiler-artifact completeness
patch shares a bounded Cargo JSON parser across producer and package verifier
(`target/g11-compiler-artifact-review-next/candidate.patch`, SHA-256
`f96db0e745f1d2b3c7655b6492bb09c60451316f7ef1c05d2043207a530321bf`).
Its first complete Python run **failed 13 of 156** because the old synthetic
package fixture lacked the newly required Cargo log events, executable mode
and process working directory (`applied-full-python.log`, SHA-256
`be0c136c9b2e66b537fae05f8484a6e5ed2f2cc1e83bb73c110dd27cc3eed46b`).
After correcting only that fixture, the package module passes **7/7**
(`applied-package-fixture-correction.log`, SHA-256
`a17bdc5689ce29176f8be3b2db0e65b0c13a0ba0135f445469a13f9fdd43a523`).
The local downloaded-tar collector is also applied
(`target/g11-functional-collector/candidate.patch`, SHA-256
`3e684cd03596d5b1696cbac16fab4f88d83b0a17bc6dcc110fb24a7f387ea5b2`)
and passes **9/9** focused synthetic tests (`applied-focused-python.log`,
SHA-256 `123d3142dec5d7ce713761f4882685a9f1bddd10435b7f2290b0f2d11012593a`).
It still requires independently retained native producer identities and
transport, downloaded-tar custody, semantic adapters, and final-source
multi-platform qualification. G11 remains open.
The complete repository Python discovery on the corrected compiler receipt,
fixture and collector source passes **165/165**
(`target/g11-functional-collector/applied-full-python-after-fixture.log`,
SHA-256 `01b0a83b65e4b0ab8332d093a839264ecb4876e0b808a54d7fbb02bd02e55542`).
This is source-level tooling validation, not a native functional gate or an
accepted release domain.

An independent G11 review reproduced a separate rehashed feature-inventory
false-pass in the compiler-artifact verifier: the Cargo log could report
`test-utils` while the receipt claimed no compiled fixture feature
(`target/g11-applied-compiler-artifact-review/REVIEW.md`, SHA-256
`64c6b47af99756ce4950d0cbe62d25b8af95721330b992367971723bfb2bd327`).
The applied producer and verifier now share typed reconstruction of every
compiler-artifact package, feature and target, including non-executable events;
the package verifier requires an exact receipt match and independently rejects
forbidden compiled fixture features. Focused producer tests pass **21/21**
(`target/g11-compiler-artifact-review-next/applied-inventory-replay-release-gate.log`,
SHA-256 `7f978f620b7fcc929f8a9ac620e5fd6277483bb631ccec052f23cb8ba5a3e790`),
and package tests pass **7/7** with both rehashed-feature counterexamples
(`applied-inventory-replay-package-revision2.log`, SHA-256
`c51030184aecc38a867c66946d9bb2c9d9e731c370440c5a026370af9ed7ff59`).
Independent post-correction review confirms the false-pass is closed and the
typed parser accepts 1,151 artifact events from retained ARM64 logs
(`target/g11-compiled-packages-replay-review/REVIEW.md`). Current-source native
Cargo output remains unqualified.

The revised G11 producer identity patch is applied with exact five-file
postimage readback (`target/g11-functional-producer-identity-next/candidate.patch`,
SHA-256 `45aebd8b31fa5d193c759e5de10ab64e4dcb45794f6428f938912cb1dcf856f8`).
It adds a separately uploaded, digest-bound native producer record and a
host-side cross-check of the uploaded tar/producer pair, manifest, target and
Git source identity. The collector now requires that producer record and an
independently observed producer digest. Its staged producer/collector tests
pass **11/11** and exporter tests **18/18**; the independent review found no
static blocker (`target/g11-functional-producer-identity-independent-review/REVIEW.md`,
SHA-256 `d780840041e255ddd64cb642d3807d25f2fb733f144ec97170804f7f5c9a4733`).
Complete repository Python discovery on the applied combined source passes
**168/168** (`target/g11-functional-producer-identity-next/applied-full-python.log`,
SHA-256 `b7566ba0e04c57186a7b12cf7f6eec516167b88bdf10b88731bd28f8468bb305`).
No native workflow upload/download, multi-platform functional gate or semantic
acceptance adapter is yet qualified; G11 remains open.

The reviewed G09 Start-intent prerequisite is applied with exact two-file
postimage readback (`target/g09-initialize-exact-outcome-next/start-slice.patch`,
SHA-256 `a311cdd5aae66188d61dfccfca2b7e892286b35cbaafce76beedfd05564770e8`).
Its private first-release record binds the exact marked Start owner and full
installed Control root; its read returns only unresolved local observations.
The applied-source focused engine tests pass **2/2**
(`target/g09-initialize-exact-outcome-next/applied-start-focused.log`, SHA-256
`69c14ef9f86e48e5b666edba44660ea0790f451051569a8ea6b8e0a8c550dbea`).
No production writer calls this module. The staged wire revision (SHA-256
`846cd12f8f2c83e910125bfdf8b628ceb62f3b2ccdcd27a1a5afa534eea2b6e3`)
is not applied because Start/Initialize would remain unresolved until the
one-use target journal, Raft first-membership proof and Control resolution are
integrated. The installed three-node recovery test remains failing and G09 is
open.

The independently reviewed G09 format-2 target journal slice is applied with
exact three-file postimage readback (`target/g09-initialize-exact-outcome-next/journal-slice.patch`,
SHA-256 `14874971943b79813152975a157fcdfc0068d06bc68f0c2e3a1d02dae79dd10b`).
It rejects format 1 without a compatibility decoder, reserves a bounded exact
Start/Initialize dispatch and terminal capacity atomically, and reopens only
with a matching encrypted row count/charge. Duplicate equal packets remain
status-only and local absence is unresolved. Applied-source journal tests pass
**8/8** (`target/g09-initialize-exact-outcome-next/applied-journal-focused.log`,
SHA-256 `a607e5499cc5fc19b3e8a5661450c9939267b6d61bb64f5b41ce0041b05f4b3d`).
There is no live Execute caller or first-applied Raft fact; this cannot close
G09. The serial 13-case authority materialization rerun on the format-2
source passed **12/13** and failed in
`activated_target_keeps_operational_suspension_and_membership_across_restart`
(`target/g09-initialize-exact-outcome-next/applied-authority-materialization-after-journal.log`,
SHA-256 `8489adc784d87e84218afb5a77d71315dde5dfddf3452ce57fb0c1797780de35`).
The shutdown diagnostic retained an exact access-fenced `Store/Write` error
in the Raft core, whereas the test classifier permitted that original error
only in state-machine and replication children. A test-only correction now
checks the core with the same strict typed predicate and adds negative cases
for other subject, verb, message and fatal variants
(`target/g09-initialize-exact-outcome-next/authority-core-drain-fixture.patch`,
SHA-256 `82d5e3c0a6b3a3a39feea4bb435afc7b95dcb8242c617158d0f13aede9bf489e`).
The correction is applied; its exact negative-classifier test passes **1/1**
(`applied-authority-core-diagnostic-focused.log`, SHA-256
`83384c8d4b949ac3fe975919d481bf9301d93b488df34f19a9aad875af172671`).
The formerly failing materialization case passes **1/1 in 70.87 seconds**
(`applied-authority-activated-focused.log`, SHA-256
`148c622207f54fe1422d0825a72f6c674f1491539c8339b07ed23f02e2c1e0f5`).
The complete serial authority library rerun on the format-2 source passes
**65/65 in 782.39 seconds** (`applied-full-authority-after-journal-core-fix.log`,
SHA-256 `77714854cde119ca3f9f216ca8937902278920271b951905be97ac37a7791c65`,
process-group exit 0). The earlier 12/13 run remains failed evidence; this
pass qualifies only the authority library on this source, not native recovery.

The uninstrumented serial engine library on the format-2 journal source
finished **266 passed, one failed, one ignored** in 723.19 seconds
(`target/g09-initialize-exact-outcome-next/applied-full-engine-after-journal.log`,
SHA-256 `a0f3220edc0f10d721d2866274b34d11c8f53b06f03408949f6e5e1914fd7170`,
process-group exit 101). The failed backup credential case returned
`UnknownOutcome` before its test pause at an object read. An initial exact-name
rerun selected zero tests and grants no pass credit
(`applied-engine-backup-credential-focused.log`, SHA-256
`4891694ae6ab89af30027ed9a357bb8f5bf99356638f4968a5b920d16fced9ff`).
The corrected full-name invocation on the same compiled binary passes **1/1**
(`applied-engine-backup-credential-focused-exact.log`, SHA-256
`184ff45d380d30e0b01f2f6fd3bbab181aa582483f5933f4644e6b7888f45927`).
The full-suite interaction remains unresolved; the focused pass does not
replace the failed library result.

The independently reviewed G05 exact S3 destination index is applied with
exact two-file postimage readback (`target/g05-exact-destination-index/candidate.patch`,
SHA-256 `8a11109f729275ff5d530c06fc02df339302610ee299073bc0ed96fa67a0ccda`).
Its first two staged revisions were held after reviewers found a same-key
collision across signing regions, then a parent session-object/child direct
backup collision across nested prefixes. The final index rejects equal and
slash-boundary nested prefixes under the same canonical origin/bucket while
retaining exact binding lookup. The applied-source focused store group passes
**5/5** (`target/g05-exact-destination-index/applied-focused.log`, SHA-256
`5a380824f885f86a8b5285cfafdd7352d07c528a6edc750fe3d1d92758cef4fa`).
This index has no production caller or Control claim and cannot authorize a
backup write. Filesystem marker enrollment, physical readback, alias cutover
and exact cleanup are still open; G05 is not accepted.

On the combined G05/G07/G09 source, the first repository Python rerun used the
macOS system Python 3.9.6 and failed because `hashlib.file_digest` is absent
(`target/g11-functional-producer-identity-next/applied-full-python-after-g05-g09.log`,
SHA-256 `37882e7e76e52f668af490a61e702c99645d6caf473f3c7009f1f83729af4b7f`).
That is a wrong-interpreter attempt, not a passing release gate. Repeating the
same discovery with bundled Python 3.12.14 passes **168/168 in 84.922 seconds**
(`applied-full-python-after-g05-g09-py312.log`, SHA-256
`87a6a24d27725e9b468ae8ecdaf2d3c673dc9afed6c2777d0326d15877702dc8`).
Native functional transport and semantic acceptance remain open.

The independently reviewed G11 owned-assembly transport prerequisite is
applied on `master` with exact four-file postimage readback
(`target/g11-assembly-transport-candidate/candidate.patch`, SHA-256
`f396643e1480f1a2c9ae50647e833b7d635d2cad6d65af3ad9bb1531facb87ce`;
`hashes.json`, SHA-256
`f84abd26fc2e606e64a632463a41bda1febda5301dbe39bc230b01698b51ae31`).
The independent review (`target/g11-assembly-transport-independent-review/REVIEW.md`,
SHA-256 `2884ae8578930aa291deded0ab8243c78d67083b2011bc6513253416f73eb0f2`)
accepted it as a transport prerequisite only. Its raw PAX tar includes
explicit file and directory members, including empty directories, and an
independent downloaded producer digest is required for collector readback.
Failed/interrupted attempts have separate raw transport and never supply a
passing domain receipt. Applied-source focused tests pass **15/15**
(`target/g11-assembly-transport-candidate/applied-focused.log`, SHA-256
`ac7a4cc81ae9675a026d306ba5a2a4edf64aaf2ed5484257ee629b2b99255e3d`).
The workflow parses and its eight Bash blocks pass `bash -n`
(`applied-workflow-syntax-ruby-retry.log`, SHA-256
`ca29bbc4ae6afc72498b8b119b3330ff7aabca7467f92d38262cbe10a504205a`).
An initial Python YAML check lacked PyYAML and the first Ruby check used a
method unsupported by the installed Ruby; their failed logs remain in the same
target directory and grant no test credit. Native upload/download, physical
host evidence, permanent failed-attempt custody and semantic acceptance remain
unqualified; `DOMAIN_ADAPTERS` is still empty and G11 stays open.

Source-only boundary audits keep three later cutovers explicit. The G05
filesystem marker/owner review (`target/g05-installed-owner-cutover-20260924/README.md`,
SHA-256 `11ab48538a84c85eab5645817ea7f4730b88102a6c79be6014026b62d1e169af`)
found no safe isolated owner pass-through while the public raw constructor and
six cached filesystem routes can write without a checked marker; normal startup,
stopped recovery and Control's physical claim must change together. The G09
Initialize contract (`target/g09-initialize-exact-outcome-next/minimal-initialize-vertical-contract.md`,
SHA-256 `7c4cc537f0ad9eb8098d3672c28c2b2cb5fa8f5381a8708584f53885d793312a`)
orders authenticated Control marking, journal-before-child admission, the
designated owner, the atomic first membership fact, snapshot continuity and
read-only exact resolution. Its revised dormant owner patch (SHA-256
`4130e038965c7698b99b7742c687482202fd80e8e568c3406eda79d7383f08c2`)
retains the structural predecessor/sequence but is staged, not yet applied or
Cargo-tested. Independent review
(`target/g09-initialize-owner-independent-review/REVIEW.md`, SHA-256
`398209f9ce244ba1a7b2d179981c32b5ddb7c0e0d37c25fcbc0fb693f3c97774`)
confirms that full authenticated Control ancestry remains a future writer
requirement. The G11 registration audit
(`target/g11-registration-audit/README.md`, SHA-256
`a98bfd8d66b640474e7408451a5ea6463274893f6cbb81feb69da9a7eba023ab`)
found that the existing semantic bridge lacks a native domain-result producer,
host/attempt lineage and durable complete failed-attempt index. Its two scoped
bridge/closed-registry tests pass but do not justify registration. These audits
make no positive G05, G09 or G11 acceptance claim.

The applied G11 transport source passes complete repository Python discovery
**183/183** with the bundled Python 3.12.14
(`target/g11-assembly-transport-candidate/applied-full-python.log`, SHA-256
`10f39c3c300e9c88b47946726f9850aeb35a2499e1252cedfd635187fa5bb6ae`,
process-group exit 0). A separately reviewed post-download projection
(`target/g11-domain-projection-candidate/candidate.patch`, SHA-256
`e19afece19d9b12d804fd76b3481176adb4ee832f259f2955f5d171d497eb1c0`;
independent review SHA-256
`d48374eb4f715ab2e92e5c5730fefac14361c46dfb9c84bf36e98863ba22d4ba`)
is applied with exact two-file postimage readback. It joins the original
selected functional receipt to the independently digested raw assembly
collector, but labels the host, reservation and attempt records as unverified
claims and always publishes `unqualified`. Its synthetic focused tests pass
**8/8** (`target/g11-domain-projection-candidate/applied-focused.log`,
SHA-256 `91bb11e4bf1d34d559315cfe7ecee9220094268b14ffa46c50ebaaf164f80716`);
complete Python discovery on that applied source passes **191/191**
(`applied-full-python.log`, SHA-256
`7ee242659c7619c2df73944b41318bd50c017b7de61ceb4d13c979ce75914902`,
process-group exit 0). The native-lineage audit
(`target/g11-native-lineage-next/README.md`, SHA-256
`1decf8df1be663a026bb0b62dd5ed6fe04a12595ff147c942ea5b6c792f4c912`)
identifies the missing independent host attestor and durable before-dispatch
attempt registry. No native assembly, authenticated lineage or final semantic
adapter is qualified; G11 remains open.

The first diagnostic engine service subset after the format-2 journal passes
**35/36** (`target/g09-initialize-exact-outcome-next/backup-prepause-diagnostic/applied-service-subset.log`,
SHA-256 `825a34e01270ac5931962fa36bc79ad8a256e81c9eb2bc79ea20f5bfd5eecafd`,
process-group exit 101). The earlier backup-credential case reaches its pause
and passes with the expected post-pause `Unauthorized` inner error, while a
different serving-expiry/reopen case fails its test classifier on the exact
`Store/Write` post-commit key-access-loss error. This does not resolve the
first full-library backup failure. The diagnostic instrumentation is temporary,
and neither failed suite is treated as passing evidence.

The independently reviewed G10 assertion-only patch
(`target/g10-replicated-status-readiness-next/candidate.patch`, SHA-256
`bf10e557f68ff2a91fdecd6325b3f0390ce3921f5af0ff94658cb33068eebe4a`;
review SHA-256 `d0300e332765a5d5204b52104a2aab690e5c025dfe110aaf02c08086b2655bb7`)
is applied with exact postimage readback. It strengthens the existing installed
129-group test to compare the actual protected HTTPS `/ready` response's full
changed membership epoch and 129 complete, fresh group counts. This newer
source's focused installed native test passes **1/1 in 368.86 seconds**
(`target/g10-replicated-status-readiness-next/applied-129-protected-readiness-focused.log`,
SHA-256 `17cd4546b48d28dcd45f8fde923145e049381e24e1440bd82dca794549e266fb`,
process-group exit 0). It observes the actual protected response after the
membership change; the earlier result alone could not qualify this new
assertion. The fixture is standalone, and replicated positive recovery status
and the complete G10 source cohort remain open. This run preceded the later
format-2 journal canonical-byte application.

The instrumented complete serial engine library reproduced the original
pre-pause backup failure: **266 passed, one failed, one ignored** in 767.73
seconds (`target/g09-initialize-exact-outcome-next/backup-prepause-diagnostic/applied-full-engine-diagnostic.log`,
SHA-256 `9cdffb833888a46714765bcaf1c6d8a8f273e4fea634b358d26cb143c2709f7e`,
process-group exit 101). The captured inner error was `Unauthorized:
authenticated credential expired`. Source tracing in
`backup-prepause-diagnostic/CAUSE.md` (SHA-256
`29c5d36d24dc4f3a4b139f3be609602f58c7fd6327b78c7184d5c1d84e9ef443`)
shows the test credential allowed one second from a real wall observation
while the backup's pre-object Raft maintenance command used the independently
advancing real `SystemCommandClock`; a slower full run could expire before the
intended pause. The temporary diagnostic-only logging was reversed with exact
preimage hashes restored to `backup_checkpoints.rs` and `proposal_jobs.rs`.

Two independently reviewed test-only corrections are applied. The long
backup test alone now uses a 600-second initial credential and deliberately
advances its fake elapsed clock to that exact deadline after each observed
paused read (`credential-validity-candidate.patch`, SHA-256
`162a0f11e52e15142fb31c6a9e6e06f3f770ab12ecf080e93d6d8e6bf58309e6`;
review SHA-256
`4c86523f0a7457fb6a6e9f756fa6f44dc401d0b78ca9e2f13667e7287307faa9`).
Its applied-source exact case passes **1/1**
(`target/g09-initialize-exact-outcome-next/applied-backup-credential-validity-focused.log`,
SHA-256 `560dae299bde896581913ae19ef009e8a3794aef3f248a7e9c9fa7112221053e`).
The serving-expiry drain classifier now admits only the exact post-commit
key-access-loss `Store/Write` cause seen in the other failed subset, with
negative subject, verb and message cases
(`serving-expiry-classifier-candidate/candidate.patch`, SHA-256
`956169abccd5ba17d8bde303faa4aff4675e3c8c5362b0f990d78d20abe92ac8`;
review SHA-256
`c3fa28669e597af601a758698e3c49f4b889ee89a010039ea1300816599e53cd`).
Its classifier and affected expiry/reopen cases pass **1/1 each**
(`applied-serving-expiry-classifier-focused.log`, SHA-256
`a00354b03fc21d15c37c56a80c3e7918506a09a65cef1dd8082095eb1ae5f802`;
`applied-serving-expiry-reopen-focused.log`, SHA-256
`cb60e23014e64a113a9f1069538b18c52e47e3020c19ad71bad87437cdebb3dc`).
These focused passes do not replace the failed full engine-library result.

The independently reviewed dormant G09 Initialize-owner patch
(`target/g09-initialize-exact-outcome-next/initialize-owner-slice.patch`,
SHA-256 `4130e038965c7698b99b7742c687482202fd80e8e568c3406eda79d7383f08c2`)
is now applied with exact postimage readback. Its four applied-source focused
tests pass (`applied-owner-focused.log`, SHA-256
`900db70b2fc1f955ba6c530877e643bcdd0935fb11220d8d2c62c1ec63ed1d46`).
It retains structural Initialize predecessor/sequence and a one-winner local
owner, but has no live caller, full authenticated Control ancestry, atomic
first Raft membership fact or positive status. G09 remains open.

The G01 first-release source audit
(`target/g01-first-release-compat-next/README.md`, SHA-256
`976315571529485ba81d957a50095bf74cbe69a15017f9ae2ac63ba27feafdcd`)
found no live predecessor decoder in the inspected administrative DTO, local
JWT, recovery wire or snapshot paths. It identified alternate durable JSON
bytes accepted by several current readers. The independently reviewed narrow
storage-binding cutover (`target/g01-storage-binding-canonical-next/candidate.patch`,
SHA-256 `91987a20a624c7bc5847454f981f21d5c9000dab06b348d042fa0ccd0969cd6a`;
review SHA-256
`a203eeb4e47f235dcbec13a39422102d688240dbe2b3223d6693440570247f7e`)
is applied with exact three-file postimage readback. Existing binding readers
now require the current writer's exact bytes, without a decoder or repair.
Its negative alternate-JSON/no-repair and positive restore test passes **1/1**
(`target/g01-storage-binding-canonical-next/applied-focused.log`, SHA-256
`ed1caf2b9423e7b64973cb14e11a25e68304136d01e311798d98fa2d3fb77413`).
The complete serial store library passes **404/404 runnable cases**, with
two ignored, in 268.23 seconds
(`target/g01-storage-binding-canonical-next/applied-full-store.log`, SHA-256
`90ebc115faabfb9b6fdac699c47884e8f591c1513073db672c558b5e35fa621a`,
process-group exit 0). Target-journal and Raft metadata canonical-byte gaps
remain; G01 is open.

Complete repository Python discovery after the combined G01/G09/G10 source
edits passes **191/191 in 130.336 seconds**
(`target/g11-domain-projection-candidate/applied-full-python-after-g01-g09-g10.log`,
SHA-256 `e7b20ba1a108ac9411a845551a84798a118d62d73a7d2f7a6845c7bde9310f2e`,
process-group exit 0). This is local development validation, not the frozen
native release acceptance suite.

The independently reviewed G01/G09 format-2 target-journal canonical-byte
cutover is applied with exact three-file postimage readback
(`target/g01-target-journal-canonical-next/candidate.patch`, SHA-256
`4865fe169ffcbffe88c6e24e81e5c4bfda89619e7d8f04308ce140d2843d333b`;
independent review SHA-256
`88029f1556a1afc25f8c56d9dde197fcff699ca87572c0948a2f8632e472a8c9`).
It compares already bounded head, intent, generation, file, stop, activation
and serving records to the exact current writer serialization during startup
and point reads. No alternate-byte decoder or repair remains for those rows;
the dispatch row already had exact-byte validation. The complete
`target_journal::open_tests` module passes **11/11** on applied source
(`target/g01-target-journal-canonical-next/applied-focused-open.log`,
SHA-256 `226325d1dacbae7981eaac33c3a862bbebf0804224878210c26f1931232f306a`).
Complete repository Python discovery again passes **191/191**
(`applied-full-python-after-journal.log`, SHA-256
`3c5e4c4141dfe4b2fbfe6fad670657e392847f18f68f96023b3b58fa9f752c2e`,
process-group exit 0), and workspace formatting passes. The serial engine
library rerun on this source passes **272/272 runnable cases**, with one
ignored, in 789.19 seconds
(`applied-full-engine-after-corrections.log`, SHA-256
`2deda2000e9f5bd42517b491dba686ad6f787076a76147d93e75ced8a94d78b2`,
process-group exit 0). The formerly failing backup and serving-expiry cases
both pass in that complete same-process serial suite. Generic Raft metadata
canonicality, G09's live first-membership chain and final native acceptance
remain open.

The all-target/all-feature offline locked workspace check passes on that
format-2 source (`applied-workspace-check-after-corrections.log`, SHA-256
`7a21c5b7f21f5cead89e4286199769b1041e31c6ead1d65c335376a334e1530e`,
process-group exit 0). Strict workspace Clippy then reports two lint-only
errors: the target-journal negative test used `.err().expect()`, and the server
audit cursor used a simplifiable `map_or(true, ...)` predicate
(`applied-workspace-clippy-after-corrections.log`, SHA-256
`ac50940cc08a33667643ff7fc4633719e25efcdf5952587559ce12ff62103cec`,
process-group exit 101). Those exact lines are corrected to `expect_err` and
`is_none_or`, with no predicate or assertion change. Formatting and diff checks
pass; strict all-target/all-feature Clippy on the corrected source passes
(`applied-workspace-clippy-after-lint-fix.log`, SHA-256
`1106ab8ed9498b91c941e12cd0de4ba2155a678ae98995ea72ffa3aca2896e67`,
process-group exit 0). The full target-journal open-test module rerun on those
corrected bytes passes **11/11**
(`applied-focused-open-after-lint-fix.log`, SHA-256
`dbd5ea65a4c91ae196bfbc4cfe4ab7e1be487117b43fbf4a499ab9077067d098`,
process-group exit 0). The earlier complete engine pass predates those two
lint-only source edits; none of these development checks is release acceptance.

A target-only G11 signed-lineage binder candidate is retained under
`target/g11-lineage-binder-next/` (patch SHA-256
`0afec1246dd7eacd339217d51402d67fc9f8ca21d8dfaa3d7197650ea47d0160`;
10 synthetic focused tests pass). Independent review SHA-256
`089c3aa024aca3a3980682ff0a8c3281f3640e7b0af09d6ef8f3cfeac7bddb47`
recommends **not applying** it as a release prerequisite yet: its
`cryptography` dependency is not pinned for the release verifier, issuer keys
and checkpoint anchor are caller supplied, complete external attempt history
is not proved, and no release adapter invokes it. No tracked G11 source was
changed by this candidate. G11 remains open.

The G07 spare-replacement initial Put fixture's exact-receipt correction now
passes the installed all-features test twice on the same pre-Raft-cutover
source/binary: **1/1 in 51.48 seconds**
(`target/g07-spare-initial-put-audit/applied-focused-after-exact-receipt.log`,
SHA-256 `bef750f7fafab1bbfa21c4f271734c4e3f4d43263397163f2c49e3f778509836`)
and **1/1 in 45.21 seconds**
(`applied-focused-after-exact-receipt-repeat.log`, SHA-256
`065156541ca8ccdc47c39b44d0a764374320df086f207f45e211f6da31f5a3fd`),
both process-group exit 0. This resolves only the former focused fixture
uncertainty; the full same-process server cohort and installed HA recovery
remain open.

The independently reviewed G01 Raft metadata byte-canonicality cutover
(`target/g01-raft-canonical-candidate/candidate.patch`, SHA-256
`c8b395e6d56cb73fa16e25a9780628cf09a70ca0cadbe5e5515b8193f24f4095`;
review SHA-256
`773c3e678b9c8a14002d608e524d14f9b12078830474b65b374684d54008b2d4`)
is applied on `master` with exact four-file postimage readback. Both generic
Raft JSON loaders, both direct header scans and the server's retired-bootstrap
digest read now require exact current-writer bytes; no normalization, repair or
predecessor reader remains in those paths. New writer-byte/alternate-byte/
restoration cases pass **1/1 each** for metadata
(`target/g01-raft-canonical-candidate/applied-focused-metadata.log`, SHA-256
`3718e152b36f8b27a36ddb100a7f504d33e7fa11abfdca649f0c82ca1ca28e61`),
retirement recovery (`applied-focused-retirement.log`, SHA-256
`b0e8d129a0d888db40d98b88a6b8879af891f4c8094b5a0f619d80b461291666`)
and the direct server digest reader (`applied-focused-server-digest.log`,
SHA-256 `180fbf24a522dd281eaeb90545c0899fea2b7330e4636ace650ac419bb807d75`),
all process-group exit 0. At this checkpoint, complete Raft/workspace
qualification and the separate custody point-row canonicality gap remained open.

The separate G01 custody point-row exact-byte cutover is also applied
(`target/g01-custody-point-canonical-candidate/candidate.patch`, SHA-256
`d22363c5175b0092dc2ec8dd70a00e27b0753649b52d652f0f8eb9b8f0edc8d7`;
independent review SHA-256
`9ef20303c7c3999c460bf00fe8c5333d48cc66d5bc8b6755ea739b030a547aae`)
with exact three-file postimage readback. It rejects semantically equal
alternate bytes in live head and receipt point reads, snapshot capture and
replacement preflight, and linked command/audit reads. Its encrypted-row
mutation/restore case passes **1/1**
(`target/g01-custody-point-canonical-candidate/applied-focused-custody.log`,
SHA-256 `27c4dc24a8d12ac1ece3c8f462fbefe54541606ebd6bd2a25e5a45ff5dd35712`,
process-group exit 0). At this checkpoint the combined serial Raft library
was pending; a wider source compatibility audit and all release gates remain open.

The combined serial Raft library on both G01 cutovers subsequently passes
**81/81 in 721.18 seconds**, including the large permanent-custody and native
snapshot cases (`target/g01-custody-point-canonical-candidate/applied-full-raft-combined.log`,
SHA-256 `82089e750a3ad458f08994360e569dc0c8d8c8f1840f39db55205075fdf3df0a`,
process-group exit 0). Workspace and affected downstream final-source
validation remain open.

The read-only post-cutover audit
(`target/g01-post-cutover-audit/README.md`, SHA-256
`5c727128bc0829dada879d98ff06073aa306dfb24fd41ef878d11df999b6f5f0`)
confirms the four inspected G01 cutovers but finds additional current-format
alternate-byte readers in engine/authority startup, authority state and
committed operations, key/signer stores, and engine checkpoint tables. It
found no concrete predecessor-version decoder in those inspected paths.

The G10 read-only audit (`target/g10-replicated-status-audit/README.md`,
SHA-256 `575067bddae196cb8c56d92e951ad2b38444b16f398355b3c907244aaae0a56d`)
found that the existing positive three-node protected status assertion is
unreached because G09 Initialize remains unresolved, and that its saved
dispatch node may be a follower after deliberate Control failover. An
independently reviewed test-only patch
(`target/g10-replicated-status-candidate/candidate.patch`, SHA-256
`3ddc7eeaf326d74292226272221627f3f9f2d3691b930452057e395a5023b880`;
review SHA-256
`29d31848b7ef066a106cd0126aaec04ca0dcc4341eada7730e9e0f6360c5cc12`)
adds a separate installed three-node protected HTTPS read of the real
committed `Prepare` point record and selects the current quorum-ready Control
leader for the terminal helper. Its first focused attempt failed compilation
because one old fixture call lacked the new test-only flag
(`applied-focused-prepare-status.log`, SHA-256
`b62c79cc3b0014ef000c5ba416f66261ca2979d1b50bf066c9cec816e2541a9b`,
exit 101). After that call-site correction, the test reached public TLS
certificate loading but the fixture used the owner-only secret reader on a
public certificate (`applied-focused-prepare-status-after-callsite.log`,
SHA-256 `661818e0df4aed035788d82d0e5b037ad970a5f5ae4f01760eef07f36836fd0e`,
exit 101). The fixture now uses a bounded public reader for certificate and
CA, retaining the owner-only private-key read. The exact installed test passes
twice on that source: **1/1 in 36.28 seconds**
(`applied-focused-prepare-status-after-public-cert-fix.log`, SHA-256
`db06318ff6ca700b4229236a4790ba00592e6aae2c4e2f6fd6ee06eb1d4a91cd`)
and **1/1 in 25.15 seconds** (`applied-focused-prepare-status-repeat.log`,
SHA-256 `3ddcb6a2c4b59342da6b181c839809a54fa9307e5c3f3980289a6d1a946fdc46`),
both process-group exit 0. These are positive replicated `Prepare` point reads,
not a completed G09 recovery or full G10 certificate.

The first G01 startup-identity candidate was rejected before application:
it incorrectly required a custody `resource-floor` that the current authority
writer never creates (`target/g01-priority-a-canonical-candidate/REVIEW.md`,
SHA-256 `c15d2232f96ef8d85960460079f892386a211af131d13090e05340820fe04873`).
The corrected, independently reviewed revision 2
(`target/g01-priority-a-canonical-candidate-rev2/candidate.patch`, SHA-256
`caf8e73806f477976795ec80966f44d1ce38a5c11e4726d9fd471be4e4bbc078`;
review SHA-256
`3c3279f54d3ea5f4ae3387040800ac4cd6b9ebf78326a9ab0b724e2a230ee1ac`)
is applied with exact four-file postimage readback. It requires current writer
bytes for the engine replicated deployment and authority installation/local
member, while checking the application-only resource floor in its actual
domain. The new engine and authority negative/no-repair/restore cases pass
**1/1 each** (`applied-focused-engine.log`, SHA-256
`53411166fad9a895d5b174fa002ddc5864845baabfe0e3bc022f8b17fd84620f`;
`applied-focused-authority.log`, SHA-256
`fe8e6832acad9b48331f9d38aa915b6fec4e5a793ac71531bf89781285302534`,
both process-group exit 0). Broader authority/engine and combined-workspace
validation remain open.

Locked offline all-target/all-feature workspace checking passes on this
combined G01/G10 source (`applied-workspace-check.log`, SHA-256
`7600e0ff130d9ef3e98a3ce0341ee0feb1231ce4fff848252f0c4e5d103996cd`,
process-group exit 0). Strict workspace Clippy also passes with `-D warnings`
(`applied-workspace-clippy.log`, SHA-256
`fa507f2e255d0a32b1a15a308bba4b710344bcf3f57f7def0adf47e4dd70a4ac`,
process-group exit 0), as do formatting and `git diff --check`. The complete
authority and engine library reruns on this later source remain pending;
these workspace checks do not close any release goal.

The corrected G01 Priority A and G10 source completed its full serial
`kasumi-authority` library run: **66/66 passed in 667.29 seconds**
(`target/g01-priority-a-canonical-candidate-rev2/applied-full-authority-combined.log`,
SHA-256 `1817553f391f258f8e9b424a7417cf368a5ca7572b690a6a8ace2322fcdaa39f`,
process-group exit 0). This run preceded the later key-catalog source edit.

The independently reviewed G01 node key-catalog exact-byte patch
(`target/g01-key-catalog-canonical-candidate/candidate.patch`, SHA-256
`c89954882f4e4949b1755d9fd051c7246e3da9d7888333affe10b990d9420382`;
review SHA-256 `671e45ce9943cf6e4b0adba382e95f812c687ec17588048c487ca85caa05fb0d`)
is applied on `master` with exact two-file postimage readback. It compares each
bounded catalog row with the current writer's bytes using a streaming sink,
without retaining a second catalog-sized buffer. Its rotated-catalog
alternate-byte/no-repair/restore regression passes **1/1**
(`target/g01-key-catalog-canonical-candidate/applied-focused-store.log`,
SHA-256 `c4ab60fdd0d28665c3601b9351c8a9ac690fb5802c5ff59eed9901c4e0d1fc39`,
process-group exit 0). An initial focused invocation selected zero tests due
to an over-specific `--exact` filter and is superseded by this actual pass.
The complete serial store library also passes **405/405 runnable cases**, with
two ignored, in 193.28 seconds
(`target/g01-key-catalog-canonical-candidate/applied-full-store.log`, SHA-256
`6a9cea9aa5285d1d3f12e9d959f0e55b59bd687128034bb863c11810c01a8d22`,
process-group exit 0). This does not close G01.

The first residual engine/authority canonical-reader candidate is explicitly
held before application. Independent review
(`target/g01-post-priority-a-canonical-candidate/REVIEW.md`, SHA-256
`19ea5d2b4ef514be2b779e455222683428feed9d468523d5e611d0b2e3c92b2c`)
found a confirmed `&Vec<u8>` compile error in its new authority test and an
unbounded target-row reread that weakened an existing 256-KiB bound. A revised
target-only candidate is staged at
`target/g01-post-priority-a-canonical-candidate-rev2/`; independent review
and native tests remain pending. The read-only G01 live-trust audit
(`target/g01-live-trust-audit/README.md`, SHA-256
`867250bd03d6bd980472951d6574447ed7fe31ed4a92cdd1a0c847d38e4cd5c4`)
identifies three trust-store row families and one server verifier-installation
marker that still accept alternate current-format bytes. G01 remains open.

Independent review accepted the revised residual G01 patch
(`target/g01-post-priority-a-canonical-candidate-rev2/candidate.patch`, SHA-256
`aa30a83411a8ee4b9f79acb70ec96b4d2ee70303c45aaed882c69dca2f344ded`;
review SHA-256 `25f4849dd20f764f4219cf2b43aed9301addea48b2fa7d070303aa898308b6ff`).
The seven exact preimages and postimages matched its manifest when it was
applied on `master`. The direct target readers retain bounded 256-KiB custody
reads and compare against an equally bounded application row before canonical
decoding; the live authority maintenance reader now checks the current writer's
application-only floor bytes. The new authority and engine
alternate-byte/no-repair/restore cases each pass **1/1**
(`target/g01-post-priority-a-canonical-candidate-rev2/applied-focused-authority.log`,
SHA-256 `b30b77734e530205027307f98e48f91cb2fd1de176a4dc66692d1574dbef580d`;
`target/g01-post-priority-a-canonical-candidate-rev2/applied-focused-engine.log`,
SHA-256 `9fb6d5cf314c0f90dd3bf5ecec97b30bf7f2ee314d07ac3c713a69a7f8f0fbb1`,
both process-group exit 0). The complete serial engine suite is running on
this later source; complete authority and workspace reruns remain pending.

The read-only host file keyring audit (`target/g01-host-keyring-audit/README.md`,
SHA-256 `94dd027f8fcc3679e772f4143e527b8d7093debb33445342acadc6547f7029f0`)
found that a bounded but noncanonical keyring can be silently normalized by
rotation and that read validation admits invalid domain names and missing
intermediate generations never produced by the current writer. A separate
first-membership audit (`target/g09-first-membership-audit/README.md`, SHA-256
`d8b239dfae8076df2a1fa10adaf5cc3760f57a5296aafc02263f4d6e8d7116ca`)
finds no safe production-callable positive Initialize outcome yet; G09 remains
open until the original Control phase, receiver, owner, committed Raft effect,
and status read are joined with exact evidence.

The subsequent serial engine library run passed 272 cases, failed one, and
ignored one in 814.29 seconds (`target/g01-post-priority-a-canonical-candidate-rev2/applied-full-engine-combined.log`,
SHA-256 `0e71d03df8f64df0c020c941e0b454112395e5c05479a442deb265d0122fc20d`,
exit 101). The failure was an initial three-node leader barrier timeout in the
serving-expiry fixture, before its changed reader was exercised. The named case
passed 1/1 in an isolated 9.27-second rerun (`applied-focused-serving-expiry-rerun.log`,
SHA-256 `e31b66af6e409305562009e6a102357858bdc269e90403f93a1c83d428bab737`,
exit 0). The failed full run is retained and is not a full-suite pass.

Four more independently reviewed G01 exact-byte patches are applied on `master`
with exact postimage readback: host file keyring
(`target/g01-host-keyring-canonical-candidate/candidate.patch`, SHA-256
`0dd862f67e09c7e215ad4bb368764a027ed1012c4fcb0956afd7dd31f2f68c57`),
three bounded live signer trust rows
(`target/g01-live-trust-canonical-candidate/candidate.patch`, SHA-256
`5a505152cc8caac0383cbeabdd9c0330cde2a6614b6a39624b0f93539a383182`),
the verifier installation marker
(`target/g01-verifier-installation-canonical-candidate/candidate.patch`, SHA-256
`50009a4d2ba9ae7a1246bad51fdd0db78f681ee6d32ad84c6e2e91c137f7513b`),
and four 64-KiB checkpoint binding catalogs
(`target/g01-checkpoint-catalog-canonical-candidate/candidate.patch`, SHA-256
`b7cf900118403153eea5fd20626d53e75e5ce32ce39dc68956e3962e5c21b778`).
Their focused host-keyring, trust, verifier startup, and catalog regressions
pass **5/5**, **1/1**, **1/1**, and **4/4** respectively (logs in those four
candidate directories, SHA-256
`c4ae2ea9c18780495e9965bd665bdb534278f9cf919246ade7d8dd291bc704c0`,
`8335212e1767dbdf3330e58614fecc0d728f78a89c10f58d66fd9b81cbf8c075`,
`cf1d2c73ce09e4fa9e9ce1d4e5cd2a3e68fe6e7b0c04a68c29388b3823ba1e8c`,
`60b682032e97950cc61c9e4e20f2b6932acd1a20094b5238e8abe77c970367ce`),
all process-group exit 0. The later full serial store library passes
**408/408 runnable cases**, with two ignored, in 218.19 seconds
(`target/g01-live-trust-canonical-candidate/applied-full-store-combined.log`,
SHA-256 `23635f18929e788d1e2e3716ca3493571335f2d88fca1adf5aaccce7c3d05633`,
process-group exit 0).

The reviewed G09 marker prerequisite revision 2
(`target/g09-effect-marker-audit-rev2/marker-only.patch`, SHA-256
`a204d9bbc9e77770c97a4b04635ef4e9ef93e2785cdfce8c41b770d1e5952718`)
is applied with exact four-file postimage readback. It commits one Control
`TargetCommand` marker before an initial target Start/Initialize send, blocks
redispatch for a retained marker, and rejects unmarked positive outcomes. Its
marker unit passes **1/1** (`applied-focused-marker.log`, SHA-256
`e49c7e387f5dbdfdf3199b25660a74e64a33f9d9a5149e567cfaf369f2aed20a`),
and the correctly filtered receiver cohort passes **13/13**
(`applied-focused-receiver.log`, SHA-256
`9e01384bf3a8f661b6ef4a8b2369695ad0f71a1acdeae5285aabf8a698e8fb70`).
The six-case replicated-Control lifecycle run fails **0/6**
(`applied-focused-lifecycle-control.log`, SHA-256
`bb8fc708e50e1885b062c6be8cced2e92734d362a65e78555a51c8c7d275a8dc`,
exit 101). A temporary diagnostic, since removed with exact source hash
restored, showed its first synthetic Authority `PrepareTarget` outcome lacks
the pre-existing required `AuthorityCommand` marker. A test-only fixture
repair is being staged. G09 still lacks the authenticated target envelope,
historical status read, local owner and committed first-membership Raft fact.

The applied G01 verifier installation change also passes the complete focused
`signer_runtime::tests` server module **11/11**
(`target/g01-verifier-installation-canonical-candidate/applied-signer-runtime-cohort.log`,
SHA-256 `8785d9831954832f5653beeefc0ee8471d069c662928c42b78fc3f1fee4c394e`,
exit 0). On the combined G01/G09 source, locked offline all-target/all-feature
workspace checking passes (`target/g09-effect-marker-audit-rev2/applied-workspace-check-combined.log`,
SHA-256 `5781fe606412ea0a04c020f704cb59a79d7011def16bdae3d4444e32bbb8ae34`,
exit 0). The first strict Clippy run found seven test-only `.err().expect`
uses in the new store regressions, and a second run found the new G09 test
module before later production items. Both were corrected without changing
production behavior: a generic `must_fail` helper avoids requiring secret
types to implement `Debug`, and the G09 module was moved to the end of its
source file. Strict all-target/all-feature Clippy then passes with `-D warnings`
(`target/g09-effect-marker-audit-rev2/applied-workspace-clippy-combined-after-module-move.log`,
SHA-256 `145bb68cfe092fc96282e7b9b9cc1602a9e47951f2075c11a4bc109251d18c5c`,
exit 0). Pinned formatting and `git diff --check` also pass on that source.

The independently reviewed G09 synthetic lifecycle fixture revision 3 is now
applied (`target/g09-applied-lifecycle-marker-fixture-candidate-rev3/candidate.patch`,
SHA-256 `ab9781e83de3ad42135ca15ceecadcb5579c47147331e659513ddeda6bcb492e`).
Its six-case serial run finished **4 passed, 2 failed** in 344.29 seconds
(`applied-focused-lifecycle-control.log`, SHA-256
`c7e0b304b053967eea47a081762d518149fe029a536f4e9d3c31ad3eeb5b154a`,
exit 101). The failed cases hit a ten-second exact-preparation timeout after
lost read quorum and a retained marker/outcome that forbids a new one-use
ticket. Each failed name passed alone on the later selected-row source (logs
under `target/g09-fixture-failure-diagnosis/`, SHA-256
`1f7d0f03ffffa9395f5e5f219303aea0acd1c74773fb596cfd07bc1c4c1b43d3`
and `6aa8a503081ae4de9591d2a6c775cda4f61226e8665ba4a10580865af1ace8a0`).
Those isolated passes do not turn the six-case run green. An exact G09
wire/status candidate was independently held because it would consume the
Control marker then reject the first target Execute before receiver admission;
its review is `target/g09-wire-status-candidate/REVIEW.md`, SHA-256
`3236407f8afb1ad1bd0e12ed9e325dcaea999466226f16a58ca752de2b223183`.
The candidate remains unapplied. The positive first-membership implementation
sequence is in `target/g09-first-membership-owner-design/README.md`, SHA-256
`4297e9f9549b82badb7b8e419d8aaaddfe3d7ad62652c8ece8607bfa75f0be8b`.

The independently reviewed G01 selected checkpoint-row patch is applied
(`target/g01-checkpoint-selected-rows-candidate/candidate.patch`, SHA-256
`3bb3992c38a9fec22d8a4d34e9c86f0bc4ca60ccb72ff0848ecdff1b2b1789ef`;
review SHA-256 `f9038d2e650ccd3f193ba6355ba92d107ed374ac69d355a0be227b54e47cb25a`).
It enforces the current writer bytes on four bounded selected ordinal and point
families, after the ahead-row visibility gate. Its first focused compile failed
on 16 test-only `&Vec<u8>` key arguments (retained log SHA-256
`cecae21f69fcb23c1b2ffbf2e0c59ebef789266bd297331ae9994ec9a49a71c1`).
Changing those arguments to slices leaves the production patch intact; all
four selected-row cases then pass (`applied-focused-selected-rows-after-key-fix.log`,
SHA-256 `76b19b02bc6ea35f02be5012e4f795c78c62bd708472aec5cb68f039fd322576`,
exit 0), as does the backup-binding physical restart case (`applied-focused-backup-restart.log`,
SHA-256 `7293d9f1f1372c0f46d6b5da7430d19c7f526f74cd4e2816d33b8503fd2ff08c`,
exit 0). Full engine and final-source workspace qualification remain open.
The subsequent full authority attempt was interrupted by a turn reset before
its test process returned; its partial log cannot be counted as a pass.

A later six-case G09 lifecycle rerun on the selected-row source finished
**5 passed, 1 failed** in 314.10 seconds (`target/g09-fixture-failure-diagnosis/applied-six-rerun-after-g01-selected.log`,
SHA-256 `9fb0d52ac21c2cc4eb5c29912dbaf3367ec19ee0ddd12e501186ba8c678ae857`,
exit 101). The remaining failure used a cached node-1 Control handle after
leadership moved to node 3; the Stop request returned `Unavailable` at the
test's direct `unwrap`. A single-send current-leader fixture correction is
staged under `target/g09-stop-current-leader-fixture-candidate/`, pending
independent review and application. These two failed full cohorts remain
release blockers. Strict all-target/all-feature workspace Clippy passes on
the selected-row and applied fixture source (`target/g01-checkpoint-selected-rows-candidate/applied-workspace-clippy-after-key-fix.log`,
SHA-256 `710cec2ddd4fe7bebb239a89357011f82ccd4a848a9145f7d311b5857ceb752a`,
exit 0).

The staged G01 bootstrap-manifest revision 2 remains **unapplied** after an
independent HOLD review (`target/g01-bootstrap-manifest-canonical-candidate-rev2/REVIEW.md`,
SHA-256 `63cab748b5b5e108a0c2540dc61a1d5675032642769f3043752928fa84e5e354`).
It would read a deployment binding at 256 KiB even though a valid current
writer can durably publish a binding above 1 MiB under the 32 MiB record
limit. A coherent writer/reader-size revision is being staged; the manifest
canonical decoder itself has not been applied or tested.

The later full serial authority library on the selected-row source finished
**66 passed, 1 failed** in 1,072.81 seconds (`target/g01-checkpoint-selected-rows-candidate/applied-full-authority-after-selected.log`,
SHA-256 `7f1fdd1bf1763878d2abb56b70890132bb406488b3e982772315f62c8c41a8ef`,
exit 101). Its signer-head fixture received `UnknownOutcome` after a command
acknowledgement deadline and directly unwrapped it. The same test passed alone
in 23.81 seconds (`isolated-authority-signer-head-after-failure.log`, SHA-256
`ea446194da58c13cd9e7652a1651e6137bb55f2ee8f88e7121ce0e54c005c3f3`,
exit 0). That isolated pass does not qualify the full authority suite. The
independently reviewed G09 single-send Stop fixture correction is applied
(`target/g09-stop-current-leader-fixture-candidate/candidate.patch`, SHA-256
`e52a0e03c36ad1feb68e2b62206194a59d93a27555bb9826340f95df132be6cc`;
review SHA-256 `8a828ad497f9edba27de36ba427338f515a1edb5c259acfcf824f5b316bbb356`).
Its complete six-case rerun is pending; neither G07 nor G09 is closed.

The separate G01 bootstrap-manifest revision 3 is also unapplied after a
HOLD review (`target/g01-bootstrap-manifest-canonical-candidate-rev3/REVIEW.md`,
SHA-256 `0169d533ee73733524844037761e6bf113d86bde4f059371c99da950838b194a`):
its fixed 96 MiB recovery reservation would reject even tiny valid target
opens under the documented 64 MiB default work budget on a 512 MiB host.
Manifest-only revision 4 is staged for review while actual-size deployment
admission is designed separately; no final-source G01 pass is claimed.

The independently reviewed G01 manifest-only revision 4 is now applied
(`target/g01-bootstrap-manifest-only-candidate-rev4/candidate.patch`, SHA-256
`e5f3499d3a74eee01fde0ce6903e70a1fbb2c0b0d5eb5d1f10b5fe18255d1e6a`;
review SHA-256 `cf31fdb42ffbf85dc9c4d544f03832b44cffe3e29260d2558ee4ab6da56a11e8`).
It admits only exact current-writer, 256-byte bootstrap manifests and bounds
snapshot chunks at the writer's 4 MiB size across engine and server reads.
Deployment binding admission remains open: neither the held 256 KiB read
ceiling nor the held fixed 96 MiB reservation was applied. The focused engine
test first could not start because the concurrently assembled `kasumi-kv`
manifest was absent (`applied-focused-engine-manifest.log`, SHA-256
`dadefcf056dee52dc02e6894ae3d3a08edbf8f6837ed3ce742185160d8c6625a`).
After that manifest appeared, a locked offline rerun also stopped before
compilation because the lockfile needed updating
(`applied-focused-engine-manifest-after-kv-manifest.log`, SHA-256
`3a50ecff49866d437195d0924da40ace7d2760f6e6d31f3f5d57a8562b37f112`).
Neither is a test result for the manifest behavior.

The six-case G09 lifecycle rerun after the approved one-send current-leader
Stop correction finished **2 passed, 4 failed** in 332.76 seconds
(`target/g09-stop-current-leader-fixture-candidate/applied-six-lifecycle-after-stop.log`,
SHA-256 `032712befa5f51183147a9f61f25b87d0f2ff9f765ac62566b822c45c30a9186`,
exit 101). Two failures were ten-second exact preparation timeouts, and two
were `Unavailable` from a cached node-1 phase read after Control leadership
moved. The corrected Stop assertion itself was not the failing line. This
failure supersedes the earlier note that the six-case rerun was pending; no
complete G09 lifecycle pass is claimed.

The independently reviewed G07 signer test-only correction is applied
(`target/g07-authority-signer-deadline-audit/candidate.patch`, SHA-256
`cb0dbc896904df9bb3b2c070f3cac445710346fe15b3010f59faccb493b68af9`;
review SHA-256 `2c5af760e80874c5e0e4b596245b9af7f50b3e7f4c6ca923ce570193289d9235`).
On an uncertain first Start acknowledgement, it resolves only the original
operation's read-only receipt and checks the complete command and digest; it
does not resubmit Start. The focused signer and full authority library runs
remain pending on this exact source.

The independently reviewed G09 lost-ack test is also applied
(`target/g09-begineffect-lost-ack-test-candidate-rev2/candidate.patch`, SHA-256
`9d47122ce28dff810b98949132415f9d4b27619c3efd7d712da8cb13fecc9723`;
review SHA-256 `f7557adacbef1e5d2b3ac0be188c5be51b0e648ae101cc39c3bdaa0b5a393246`).
It tests an applied BeginEffect marker followed by a lost release, one retained
marker, no fabricated outcome or child, and rejection of a second admission
attempt. Compilation and behavior remain unverified while the new native KV
crate is being assembled. The signed first-membership path and historical
status read are still absent, so G09 remains open.

A further locked offline focused G01 attempt began compilation after the native
KV manifest and lockfile appeared, but the concurrently assembled
`kasumi-kv` crate failed with 18 Rust errors in its unfinished core/table
facade (`target/g01-bootstrap-manifest-only-candidate-rev4/applied-focused-engine-manifest-after-kv-assembly.log`,
SHA-256 `52f2fa78a2248e965d0d7e620e69f52d367d95c7819a4463b837a0f3e37c4059`,
exit 101). No G01 test executed in that attempt. This records an exact
compilation blocker, not a behavior failure or a release pass.

The G09 test-only current-leader phase-read correction is present in the
tracked source at SHA-256
`ada98b56c3a526e7611b695c004f95a934eddc549c5e8afff48bf20acc45bd1c`,
matching `target/g09-phase-read-candidate/candidate.patch` (SHA-256
`4b269127b8d7aac9120d259f85e8c36aa7c4a4c970e0feef991e3ec84c3337f8`).
An independent review approved the exact pre/post image
(`target/g09-phase-read-candidate/REVIEW.md`, SHA-256
`b9ab77f4a6aa9637224797cf87d54ad62281973ffcfe14f258c54fb921256b5a`).
It pins the original operation, phase, dispatch and finite read context while
retrying only an uncertain read on the current Control leader. The focused
cases and full lifecycle cohort have not run on this source; the separate
preparation timeout still needs resolution.

The next focused G01 attempt, after more native KV core methods appeared,
still stopped before the test: three replay helpers were not yet defined
(`target/g01-bootstrap-manifest-only-candidate-rev4/applied-focused-engine-manifest-after-kv-core.log`,
SHA-256 `a4ff4be1bb13183999862d348d081b819af84bbdb44cf0c99b1c48d426377ff3`,
exit 101). The separate G09 positive first-membership audit
(`target/g09-positive-membership-slice/README.md`, SHA-256
`c1a6cdc8ea26e6451347950b69ad1ffd5e41d04fb36af57da02b5f8a69e57c5d`)
finds no safe standalone positive patch: wire, receiver admission, local owner,
applied and committed Raft first event, snapshot provenance and signed
terminal status must form one verified chain. It changed no tracked source.

The current `master` Python discovery passes **191/191** in 60.226 seconds
with the bundled Python 3.12 runtime
(`target/g11-current-master-python312-discovery-20260924.log`, SHA-256
`a3430eb4176493e50ae9d332b1e2fe5169e4701a30d4969d72321274c181449d`,
exit 0). A prior invocation with the host's Python 3.9 failed at import and
runtime API use (`target/g11-current-master-python-discovery-20260924.log`,
SHA-256 `70c15cf3702b386583ad788616641c8461b76f29de820acf7678bf94aee18259`,
exit 1); it was an interpreter mismatch, not a source qualification result.
The passing run occurred while native KV source was still changing, so final
frozen-source Python qualification remains open.

The independently reviewed G09 exact-preparation diagnostic is applied to
`recovery_control.rs` at SHA-256
`93fe9e27910df3ac7499a455566cfcf86a588ac04d25fc42d7521ec3b5bc5075`
(`target/g09-prepare-instrumentation/candidate.patch`, SHA-256
`42529853f7d9a8444e248d42dee9b583b39adb813663a76006b760aead8cf641`;
review SHA-256 `34c32febf2dd5d493107a4e5efff23af75cf88635cca6ce83797021715483ef4`).
It keeps the exact command and original 60-second credential, records stage,
route and explicitly unverified member-local rows on timeout, and still
fails if no verified phase is observed. Its 40-second observation bound
covers more than the former 10-second outer bound but does not guarantee a
maximal service call can complete. No lifecycle rerun on this source has
finished; G09 remains open.

The native KV crate's locked offline check passes
(`target/native-kv-current-master-check-20260924.log`, SHA-256
`6ad24c7f3a1f3c882b83ffb5e07866ab6266e278ed4f98fec1e72e93ea86455a`,
exit 0). The first combined focused G01 engine run reached its test but
failed because the new table facade's 64 MiB read ceiling exceeded a 32 MiB
core ceiling (`target/g01-bootstrap-manifest-only-candidate-rev4/applied-focused-engine-manifest-after-kv-check.log`,
SHA-256 `f054cfc252b419983f384f466d1f51263f0fd3665543defc77e5c6b44b4443ab`,
exit 101). The concurrently developed core then removed that inconsistent
read-bound rejection and raised its physical value limit to cover encrypted
record framing. The same focused manifest test passes **1/1** on the later
combined source (`applied-focused-engine-manifest-after-kv-bound-fix.log`,
SHA-256 `46ff53b0d2e4576dd7389667c335286a502ccb1211e92756f206ec083ca274d8`,
exit 0). The matching server fingerprint case also passes **1/1**
(`applied-focused-server-fingerprint-after-kv.log`, SHA-256
`9a7d9411e55b7e587028c2c517ca313651e80877b9c0974e44bc947874265ef2`,
exit 0). The new engine/server and final frozen-source suites remain open.

The reviewed G07 signer receipt-resolution fixture passes its focused case
**1/1** on the native KV combined source
(`target/g07-authority-signer-deadline-audit/applied-focused-signer-after-native-kv.log`,
SHA-256 `512db42b7e210a882fd11f61a405d55af9058400855221d91e82df8824e1e48e`,
exit 0). This does not qualify the complete authority library; the earlier
66/1 full run remains the latest complete cohort result.

Two independent read-only reviews of the new native KV core and table facade
identify a release-blocking close-custody transition: a proved pre-effect
`WouldBlock` from the NodeDisk backend becomes terminal after `Core::close`
marks native close entered. The core review also finds that a fenced owner can
return a successful absent-key/empty-range observation and that the public
standalone `FileBackend` claims native drain after an unobserved `File` drop.
These are source findings, not yet fixed or verified; see
`target/native-kv-crash-review/README.md` (SHA-256
`1c1ac6370f862cea9986ef65f394bccdb44975650e78fd9aa78c1d14f109098a`)
and `target/native-kv-facade-review/README.md` (SHA-256
`a6a0b5a6e5e47e63a07a8281a28df86bf87d2a72e09639a1e6a5e77aa769ad3d`).
G02 remains open.

The newly applied G09 lost-ack Control test passes **1/1** on the combined
native KV source
(`target/g09-begineffect-lost-ack-test-candidate-rev2/applied-focused-lost-ack-after-native-kv.log`,
SHA-256 `195a9f43b463707a1fbf916e9c7a200c21be3b555e55f28c09796120f651566a`,
exit 0). It verifies a committed marker followed by a revoked response
release, an unresolved original phase and no fabricated outcome or child.
The complete seven-case Control lifecycle cohort and installed target fault
test remain pending; this single case does not close G09.

The first native KV library-suite attempt stopped during compilation because
the concurrent compaction implementation called `Core::compact` before that
method existed (`target/native-kv-current-master-lib-tests-20260924.log`,
SHA-256 `74a457b088484809fee2d0f0afa12ba5ce222ee2b68c0f1f7510a3eefb28689c`,
exit 101). No native KV unit test executed in that attempt. The prior crate
check and focused integrated passes apply only to their earlier source
checkpoints; current-source G02 qualification remains open.

After the compaction method appeared, the native KV crate library suite
passes **14/14** (`target/native-kv-current-master-lib-tests-after-compact-20260924.log`,
SHA-256 `c0a181089715aef5e9b2a2e90be9a4095c187f86b2acaf0ffd294f96b0c0558e`,
exit 0). The independently identified close-custody, failed-owner negative
read and standalone file-close witness gaps are not covered by that pass;
G02 still requires their fixes and wider source-bound validation.

Pinned workspace `cargo fmt --all -- --check` fails on the in-progress native
KV cutover with 22 formatting diffs in store, engine test, authority test and
server files (`target/native-kv-current-master-format-20260924.log`, SHA-256
`0cefd2713deb093ec81d5de53fc5415ba55e258b210f1c1e70b816ecdedd6dde`,
exit 1). Formatting has not been changed during this concurrent edit; the
final-source gate remains open.

The seven-case G09 Control lifecycle rerun on the reviewed read-route and
exact-preparation diagnostic fixture passes **4/7** in 239.36 seconds
(`target/g09-prepare-instrumentation/applied-seven-lifecycle-after-native-kv.log`,
SHA-256 `e3f00bd914e4658c76374ed8fc6f4f304d6cab6527ed62b53785091f8ee90637`,
exit 101). `recovery_journal_persists...` reaches a retained marker without a
one-use ticket; `recovery_planned_retirement...` observes `Unavailable` rather
than the expected conflicting issuer outcome; and
`recovery_uncertain_activation_requires_permanent_stop...` gets an uncertain
write response during Control intent commitment. The passing cases include
the new lost-ack test, expired completion, expired target and positive
activation. These failures are preserved, not converted to positive effects;
G09 and its full lifecycle acceptance remain open. The test fixture source was
`crates/kasumi-engine/tests/common/recovery_control.rs` SHA-256
`93fe9e27910df3ac7499a455566cfcf86a588ac04d25fc42d7521ec3b5bc5075`.

The journal case alone next failed at its cached leader's otherwise identical
Prepare replay (`target/g09-prepare-instrumentation/isolated-journal-after-native-kv.log`,
SHA-256 `4a110ede96da7f6ab81ecfbb1cb592b9b8989a1925b07b90f382333cc97df74e`,
exit 101). A test-only change retries that exact phase, sequence, command and
finite credential through the current leader on `UnknownOutcome` or
`Unavailable`; it does not create a new effect ticket. The isolated case then
passes **1/1** (`target/g09-prepare-instrumentation/isolated-journal-exact-replay-rerun.log`,
SHA-256 `41db169f85b9d59a1fd9ac186616f3a86b1f8e94e67c1ff42aacf72238beb345`,
exit 0). Its wider cohort has not been rerun on this revised fixture.

The planned-retirement case alone passes **1/1** on the exact-replay fixture
(`target/g09-prepare-instrumentation/isolated-planned-after-replay.log`,
SHA-256 `36641cd06766b91fe6e31d9696c7ca5a84c8ac8b674331794b1ffd9d42d64325`,
exit 0). The uncertain-stop case first failed when its negative altered
Prepare received an ambiguous response
(`isolated-uncertain-stop-after-replay.log`, SHA-256
`2199c613f43ac8dfe1d9eb7b0561dbdaef10494307c7b96ecfb04c97feb15142`,
exit 101). The test now rereads the exact retained phase after ambiguity
before retrying the same altered input; its isolated case passes **1/1**
(`isolated-uncertain-stop-after-negative-preparation.log`, SHA-256
`22b3c5b9a47fe7429a5328dc874cc01f59b2ccbb38a56e56c404c7e6574bcf89`,
exit 0). The seven-case serial rerun on test source SHA-256
`5a61f2e548900fee529e16eca476193366aa46030479c97441ca81e2a06aa20a`
passes **3/7** (`applied-seven-lifecycle-exact-replay-rerun.log`, SHA-256
`9ff76bcad05652e5876230f5c36a74d0be7bac47effb961c293e49926ec7b385`,
exit 101). Four cases fail at cached-route reads or negative issuer outcome
assertions under leader changes. They remain failures; no synthetic positive
outcome has been accepted.

The independently reviewed native KV close-entry revision 3 is rebased a
second time over concurrent compaction-only core/facade edits and applied on
the existing `master`. Its revision 4 patch is
`target/native-kv-close-fix-candidate-rev4/candidate.patch` (SHA-256
`fc88d180d706d63095ea3d40c316cc2fe3d94984fbd22658c09d4f76867a5cdb`);
`source.json` (SHA-256
`9f881b56e217052bcf305dedad0852885eeaf67ea9f0ff2e272a6cadf2e939a3`)
records eight exact pre/post source hashes. The revision 4 patch text differs
from independently approved revision 3 only in hunk offsets, with all changed
source lines identical. Its native KV library suite passes **21/21**
(`applied-kv-lib.log`, SHA-256
`1d992d373fb04386b8a07e98fdfe3d83b60efcf701376d5b6f2740ec60442fdb`,
exit 0). This fixes typed pre-entry close retry and entered one-shot retention
in that checkpoint. The first full store attempt stopped at a new test's
temporary-borrow compile error (`applied-store-lib.log`, SHA-256
`bd9c944cb060232cd25a1f0be7690ad22e151d78391806a414c31ba7f3948689`,
exit 101). After that test-only fix, the next attempt stopped while a
concurrent native KV index-pool initializer was incomplete
(`applied-store-lib-borrow-fix.log`, SHA-256
`5153edcb838889c420257aca823dbeb3cba127dc54dc1d1fb1c32689d5161510`,
exit 101). With the initializer present, the serial store library ran **409
passed, three failed, two ignored** (`applied-store-lib-after-index-pool.log`,
SHA-256 `e0579661c5d8c6a263bd885f0b60dbb145b98ed773596607cf6946075fe657f2`,
exit 101). The three new tests expected one native close attempt after a
pre-entry retry; the clean NodeDiskFile actually closes both the data and
retained parent descriptors. Corrected exact-count assertions pass **3/3**
focused (`applied-store-close-focused-count-fix.log`, SHA-256
`44845a055c21f462db7cb4494c6bdef8ef33596487ac7ef037a122fa05546786`,
exit 0). The full store suite has not been repeated on that final test source,
and the public FileBackend native-close witness remains unresolved. G02 is open.

The target-only G01 native deployment-binding candidate is not applied
(`target/g01-native-deployment-admission-candidate/candidate.patch`, SHA-256
`b97fd434cff0a35fc03f9b8f87d8e8c6b813d030c9652487c5f8c592a037f5c1`).
Its independent review (`INDEPENDENT_REVIEW.md`, SHA-256
`4e88628c877b6288a9b7cebf8a4f48195334380fb42b98ada60cd2d913c304fa`)
holds it because the widened target row can allocate typed JSON before an
admission charge, surviving typed owners would shed their byte charge, and
application-only/server/retired readers remain outside the paired contract.
Same-generation pair selection and pre-decrypt byte admission were reviewed
as useful but insufficient; G01 remains open.

The independently reviewed native KV failed-owner read fence is applied from
`target/native-kv-read-fence-candidate-rev2/candidate.patch` (SHA-256
`b7e1cfc31dc7025ace39ab42d021970ed6ade5538cf6520c97995f910a2f09b6`);
its review SHA-256 is
`cff0acd22af99e82d8249a590cd27f45939a4f555574e8a3bcb2d6a26721753d`.
The first complete crate run passed all 24 unit tests but one of six crash
cases failed (`applied-kv-all-tests.log`, SHA-256
`4ca46629b688e7b4878932163fc2ffa9f7009a6b6898c3a971cb1f0f4cea10c8`,
exit 101): the admission-injection fixture kept denying the value read used
to inspect a denied commit. After the fixture reset denial before the value
check, the locked offline crate suite passes **24/24 unit and 6/6 crash
cases** (`applied-kv-all-tests-after-fixture.log`, SHA-256
`dad79a2abfd29b19d87705e726a485d7efe8f24e991923b5bdde9d10200bc3aa`,
exit 0). The failed attempt remains evidence; this is a crate-local result,
not the final G02 gate.

The independently reviewed FileBackend native-close witness patch is applied
on `master` with exact source and postimage hashes from
`target/file-backend-native-close-witness-candidate/source.json`. Its patch
SHA-256 is `40f9f88f07d057eaa6bb76f32c11465e5c8e1282d8fdda0764b2cad89d78ad79`;
the PASS-for-this-slice review SHA-256 is
`588345df87a21fcb67dbcc8a0db9c8ebabefc98340c52303e9d11506301b9e94`.
The locked offline crate suite passes **29/29 unit and 6/6 crash cases**
(`target/file-backend-native-close-witness-candidate/applied-kv-all-tests.log`,
SHA-256 `38aeffe30cd5f698e0d5dc7d765f5612665b1aa5ad155983244d281458397767`,
exit 0). A repeated public `Core::close` can still misreport an earlier failed
drain as success, or replace an uncertain native errno with `BrokenPipe`; the
retained facade preserves the original result. That public API gap, the full
store suite and installed G02 qualification remain open.

The first target-only G09 current-leader read/negative-response patch was
held by independent review (SHA-256
`19726fb667118afd2259ca30aaa4f74047edb3edb70d46c5a9e86de81f061c9b`):
six generic negative checks could accept a different `Conflict` before
reaching the intended validator. Revision 2 is applied test-only from
`target/g09-control-read-negative-candidate-rev2/candidate.patch` (SHA-256
`ea02a7f07a4c9c56476083344b590ccc73ad5727ffc24b57fbd3bb81a68e027b`)
after independent PASS review (SHA-256
`047441cc77b43d22dbed454fae06e2b788c9366015209abf5a0551dd19425cd6`).
It pins exact code/message at all ten negative sites and checks the same phase
is pending around the attempted invalid response. The seven-case serial
lifecycle cohort has not yet run on this revised fixture; G09 remains open.

The full serial store library suite after the FileBackend patch passes **412
passed, zero failed, two ignored**
(`target/file-backend-native-close-witness-candidate/applied-store-all-tests.log`,
SHA-256 `06d495775d063b80e08b40e4be833af30136828bceca0c32f658d7e4717a5423`,
exit 0). This includes the corrected exact-count NodeDiskFile close tests, but
precedes the next public `Core::close` report patch and does not qualify a
frozen final workspace.

The seven-case G09 serial lifecycle run on the independently reviewed test-only
revision 2 passes **5/7** (`target/g09-control-read-negative-candidate-rev2/applied-seven-lifecycle.log`,
SHA-256 `76296c764637bfed08a3fdb59e18dcf564c0179718f3bf13989bfaf9e6c0d6d2`,
exit 101; fixture SHA-256
`6a5ab5eb2b834aae9878bf35bbf1c1dea0e3aaf65980982f20e46eeb51b9c695`).
The expired-completion case receives `Unavailable` while preparing the exact
Control intent through a cached leader at line 591. The positive uncertain
activation case receives `Unavailable` from another cached leader status read
at line 1331. All other five pass. These two failures remain open; the
negative-response validation proof is not counted as full G09 acceptance.

The independently reviewed one-file public `Core::close` terminal-report patch
is applied on `master` from
`target/native-kv-core-close-report-candidate/candidate.patch` (SHA-256
`56e7a05644c2c8f8930d8e3883ab37432aaa0637b6167ba0b3e74db68ec2ab9f`),
with exact pre/post hashes in `source.json` and independent PASS review SHA-256
`9dd1c332b855197b68365867df620024a0cee9cb16be6d5d2b783bad9c382fa1`.
It returns the first backend close outcome unchanged and latches bounded
native-disposition/errno evidence for repeat reports without a second native
close. The locked offline KV suite now passes **31/31 unit and 6/6 crash
cases** (`applied-kv-all-tests.log`, SHA-256
`46270a6790b664bb2cf8bac7768ca9945ebfe8f35f751b3984066bb9a97eaea3`,
exit 0). A full store rerun on this newer source is in progress. G02 remains
open for production registered-owner cutover, wider/final qualification and
measured installed release gates.
