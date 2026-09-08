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
