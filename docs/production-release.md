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
