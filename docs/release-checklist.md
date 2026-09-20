# First production release acceptance

Kasumi is **not yet certified for production release**. This checklist covers the
combined credential, Control lifecycle, target recovery, schema admission,
streaming, standalone, HA maintenance and retention implementation. The precise
implementation status is tracked in [the active ledger](production-release.md).
The [approved plan](first-release-plan.md) is tracked through
[fourteen workstream goals](first-release-goals.md). Backward compatibility is
forbidden for this first release: remove superseded paths and explicitly reject
unsupported APIs, configuration and storage formats.

## Required release evidence

- [ ] Final Git source and clean input manifest, Rust 1.97.1, configuration hashes,
  dependency lockfile, vendored patch hashes, and executable hashes agree across
  every claimed result. Retain failed, interrupted and rejected attempts.
- [ ] Full workspace, strict Clippy, formatting, Python checks, patched dependency
  regressions, and production builds without fixture features pass on Linux
  x86-64, Linux ARM64 and macOS ARM64.
- [ ] Fresh offline standalone installation exercises native mTLS and MCP access,
  one-hour local JWT lifecycle, renewal files, live revocation, wrapping/signer/
  certificate rotation, restart, backup/restore and stopped administrator recovery.
- [ ] Separate TLS data, Control and authority processes withstand leader loss,
  outages longer than verified lease lifetime, fresh automatic admission,
  credential and trust rotation, learner catch-up and voter replacement under load.
- [ ] Actual encrypted source-unavailable recovery passes every durable phase,
  crash and cancellation point, exact activation winner, lineage, permanent stop,
  physical deletion, ownership drain and unrelated-file isolation checks.
- [ ] An incompressible corpus exceeding 3 GiB passes standalone and HA snapshot,
  compaction, restart, replacement, filesystem/S3 backup and restore with bounded
  maintenance memory. Coherent reads use a substantially smaller retention budget.
- [ ] Audit hot-budget crossings preserve verified immutable contiguous archives;
  archive failure cannot permit pruning; replicas retain their dependencies.
  Permanent identities exceed former lifetime ceilings without replay/fencing loss.
- [ ] Backup completion uncertainty, abort ownership, repeated namespace cleanup
  and delayed uploads preserve completed backups, archives and permanent tombstones.
- [ ] The final fifteen-case million-document matrix, concurrency workloads and a
  genuine 86,400-second HA soak pass with zero unexpected errors or integrity
  mismatches, including credential renewal, archival, backup and membership
  maintenance and production providers for production claims.
- [ ] Actual OpenBao/MinIO interoperability, protected health/readiness/metrics,
  structured logging, capacity and failure/backlog measurements are recorded.
- [ ] Linux binaries, macOS ARM64 development binaries, OCI images, systemd units,
  source archives, checksums, SBOM, third-party notices and reproducible workflows
  are usable. Fresh-install examples and maintenance/recovery runbooks match them.
- [ ] Actual packages and both Linux OCI architectures pass smoke tests,
  repeatable assembly and independent reproducible builds; dependency and image
  SBOMs, contribution/security guidance and measured operating limits are present.
- [ ] Final acceptance verification above candidate packaging binds every
  required gate, complete workload samples and drained test processes to the
  exact source/tree/lockfile/configuration/patch/binary hashes. Missing, failed,
  shortened or mismatched evidence rejects the release.

## Evidence interpretation

A focused test or development checkpoint closes only its stated scope. A CI file,
image recipe or pending test is not a passing gate. Earlier branch results cannot
stand in for final integration results. Functional emulation, shared-host
measurements and virtual-machine failure tests must state those limitations;
software acceptance does not establish physical controller or failure-domain
behavior for an operator's deployment.

The [September 5 acceptance record](historical-acceptance-20260905.md) and its raw
failures/measurements remain available as historical evidence. They certify only
their recorded sources and prior scope. Release completion requires every gate
above and every implementation milestone in the active ledger.
