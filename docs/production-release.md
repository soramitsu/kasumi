# First production release

This is the active implementation and acceptance ledger for the approved first
release. An unchecked gate is unfinished. The September 5 baseline and later
branch evidence remain historical records; they do not certify this integration.

## Contract

- Self-hosted standalone and replicated HA, Apache-2.0, Rust 1.97.1.
- One canonical first-release API, configuration and storage format. No legacy
  aliases, compatibility decoders, migrations or automatic HA downgrade.
- Secure local initialization; externally managed HA trust; original invocation
  deadlines and permanent incarnation fences remain mandatory.
- Streaming storage and resource-budget capacity, archive-before-prune audits,
  complete recovery, and usable release artifacts.

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
- [ ] Real 3 GiB incompressible standalone/HA tenant, snapshots, compaction,
  restart, member replacement, filesystem/S3 backup/restore and bounded workspaces.
- [ ] Repeated audit cap crossings, archive failure/recovery, old administrative
  ceiling crossings, member replacement and GC/delayed-upload races.
- [ ] Final 15-case million-document matrix, concurrency measurements and genuine
  24-hour HA endurance run. No duration substitutions or waived failures.
- [ ] Source/configuration/dependency/executable-bound evidence, dependency
  dispositions, notices, SBOM, checksums and validated release artifacts.

## Work ownership

The integration checkout is `/Users/mtakemiya/dev/kasumi`. Implementation branches
use separate worktrees for streaming storage, standalone runtime and HA runtime.
The existing `/private/tmp/kasumi-target-runner` remains preserved. Unrelated
untracked files in the integration checkout are not release inputs.

Mark a milestone complete only when its implementation is integrated and its
required checks actually pass. Completing scaffolding or a focused diagnostic
does not complete a whole milestone. Release readiness requires every acceptance
gate above and usable installation artifacts.

## Current verified increments

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
