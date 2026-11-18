# November 18 release integration

**Release status remains open.** The contract is [G01–G14](first-release-goals.md).
Both deployed formats remain supported. BOI's fresh installation decision
applies to its own release window. Its environment owner controls live installation.

## Source and custody

At takeover, local master, the tracking ref and the upstream branch identified
`05d7ba291b1d3602108cfbbe6e6c619bb920835d`. This merge has parents `17a1dfa7`
and `813483ff`. At the earlier inspection the six staged Store files belonged
to the concurrent Codex merge-resolution chat
`01a1ec00-ea83-7b82-bba0-a99f3f49565b` and its helper. The merge retained the
local positive-disposal proof and the upstream tests. The upstream parent
retries transient native census metadata at publication and shutdown. It leaves
reconstruction and disposal failures visible.

The nine local-parent commits had already incorporated staged generations,
shutdown drains, applied-cursor reopen, whole-namespace deletion and deployed
fixtures. The upstream merge contains the 28,798,481-byte fixture archive. Its
SHA-256 is `ccb60432bbf0f18a9d2198cdd62d7d4c2addf79c85a7295614068aa8fc375d2b`.
The takeover added local commits. No new fixture transfer is awaiting approval.

The private originals from Claude session `72b21a40-40b8-492b-8a1e-dd276a8e9556`
are retained outside the checkout at
`~/.local/share/kasumi-release/20261118-72b21a40`. They include laneB, laneC,
lbm, private merge deltas and original job outputs. The inventory of 78 original
files has SHA-256 `1d4c4bb649a73a6a2defe58f40dc5b0a3f69b459a0061fee95c9a74b94612230`.
The same directory contains OS/limits in `host.json`, source and artifact hashes
in `artifact-hashes.json`, individual test outputs, and timestamped component
receipts. The native provider and test executables are development inputs.

## Acceptance by goal

| Goal | Incorporated or observed | Evidence still required |
| --- | --- | --- |
| G01 | The two deployed revisions are pinned, their persisted exceptions recorded and the external witness deferred. The security and operations guides now document trust in offline storage. | Reconcile all source and release claims on the eventual final revision. |
| G02 | Fixed inode backing, managed directory operations, native segmented storage and cache paths exist. Newly created groups use LZ4. Snapshots now atomically select a bounded application descriptor tree. Reopen compares its streamed rows and permanent catalog bindings with the exact authenticated Raft snapshot. Store supports ordered pages, chunked overflow verification and pinned readers. | Complete the serving cutover for primary and secondary indexes, budget cache/compiler and native heap ownership, and measure sustained physical growth, retained readers and reclamation. |
| G03 | New generations stage in bounded Store batches and publish with fixed-size selector writes. Prior source covers over-cap selection. The original laneC workload failed its greater-than-96-MiB precondition. The successor generates 100 MiB. | Pass the unchanged large restore and 4,200-command/8,400-audit cases, plus interruption, bounded workspace and real native restart on final source. |
| G04 | Tenant status and capacity now use authenticated Rust, private gRPC and CLI reads. Capacity checks the local encrypted pending publication against the committed stream, with release-time authorization. | Complete export and archive verification including expiring cursors. Qualify private status, capacity, outages, replacement and lifetime crossings. |
| G05 | Server startup and stopped recovery index opened destinations by physical namespace. Distinct aliases for the same namespace are rejected. | Publish the authoritative Control session claim before upload, enforce ownership on every effect and exercise recovery, abort and delayed cleanup against real destinations. |
| G06 | Stopped local recovery binds its primary and historical read providers. New replicated target enrollment binds source tenant, incarnation, destination alias, primary, historical keys and CA trust. The old journal representation retains its original comparison. | Qualify replicated recovery and cover archives, history and all backup paths. Implement paged cross-category retention and an atomic retirement decision. |
| G07 | Existing native shutdown code owns and drains blocking tasks. The macOS tooling now checks Darwin process groups, including unreaped children. The combined process-census and release roster regressions passed 41 cases in 21.155 seconds. | Prove the actual authority, data, target and nested worker processes drain on every required cancellation, panic and deadline on the frozen binary. |
| G08 | Stopped TLS rotation publishes a recoverable generation. | Exercise stopped rotation crash points on the final binary and qualify live trust/endpoint rotation and membership replacement under load. |
| G09 | LaneB binds target storage at creation. Cleanup checks original ownership before destruction and uses durable deletion evidence. A regression exercises encrypted journal reopen after a signed stop. | Finish the distributed crash/cancellation matrix, missing-quorum recovery, old-target isolation and actual process shutdown/restart on the candidate. |
| G10 | Dedicated Control voter enrollment separates Control TLS/peer identities and remote data routes. Coverage tracks topology version, installed routes and actual membership. A recovered protected-TLS test covering 129 installed groups passed in 167.99 seconds on macOS ARM64. | Qualify dedicated Control startup and implement data-only remote Control access. Complete durable backup/authority observations, replicated membership invalidation and protected observations on the final candidate. |
| G11 | Seven domain adapters are registered. They cover correctness, providers on native Linux, repeatable assembly, dependency review, package smoke, OCI smoke and HA soak. The correctness roster selects 25 named native tests covering 13 required scenarios. | Collect authenticated passes for all 19 domains. Add installed, HA faults, recovery, audit retention, backup cleanup, key retention, observability, concurrency, systemd smoke, standalone capacity, HA capacity and benchmark matrix. |
| G12 | Native macOS ARM64 component attempts and a frozen functional run retain original failures and reruns. The earlier deployed KV component passed four tests with one ignored. The actual Store deployed-format integration target passed 4/4 on frozen f65c3d56 (5.23 seconds test time). Native OpenBao 2.6.2 restart/refresh/revocation runs retained process/output receipts. | Freeze a complete implementation and verify identical source across native macOS ARM64, Linux ARM64 and Linux x86-64, including actual OpenBao/MinIO and three separate three-member groups. |
| G13 | Capacity criteria are unchanged. | Retain the greater-than-3-GiB incompressible standalone and HA runs, 15 million-document configurations, concurrency, operating limits, and the full 86,400-second HA soak. |
| G14 | Source export verification now checks committed files, bytes and modes. Native package smoke has an evidence adapter. | Assemble and verify deliverables, checksums, SBOMs, independent builds, both Linux OCI images, systemd and native packages against the qualified binary identities. |

## Failures retained

- The private combined laneB run passed 961 Store tests with seven ignored,
  228 Raft and 82 Authority. The selected Server run passed 96 and failed
  `target_monitor_and_outer_owner_survive_cancelled_shutdown_until_journal_reopens`.
  Its filtered log discarded the assertion. Three later isolated runs passed in
  5.71, 6.35 and 5.42 seconds. Their results establish intermittency. The
  original failure's precise cause remains unknown.
- The first macOS qualification attempt timed out collecting process custody.
  A second frozen input, `0ab73f2f`, reached Python discovery and failed four
  cases. The first Darwin replacement also failed to enumerate zombies.
  Original evidence and all corrections remain available. Corrected component
  results never supersede a failed frozen qualification on a different commit.
- The November dependency review began with 35 reported items. A refreshed
  patched-lock projection after the imbl and rmcp changes scanned 501 packages
  and reported zero vulnerabilities. At that checkpoint the reviewed lru
  disposition remained applicable, while unsafe-libyaml and chrono had
  undisposed maintenance warnings. Removing the Japanese YAML wrapper cleared
  unsafe-libyaml. Frozen Clippy then caught a missing English stemmer feature.
  On `f4c613a1` the restored feature selected 492 packages. The authenticated
  RustSec database reported zero vulnerabilities, the reviewed LRU advisory
  and the undisposed chrono advisory RUSTSEC-2026-0543. Cargo-audit also emitted
  yanked-status lookup errors for the two patched OpenRaft crates. The three
  published vendor archives passed the reviewed byte-difference check. The
  OpenRaft subtree matched its separate review record.
- Frozen `26805929` ran 401 Python tests and failed two transport tests.
  Both expected mode 0750 on a synthetic directory created under umask 077.
  An explicit fixture chmod passed 15 transport tests under each of 077 and
  022. Frozen `f65c3d56` subsequently passed Python discovery with two skips.
  The latter invocation lacked Gitleaks and the optional published archives.
- The original session's server executable path was revisited. The binary then
  present (SHA-256 `dd625405bdf7fa60cd69d4b6833f555ae8d226e244ebec2505013c9dfe817c56`)
  passed the shutdown test in 2.12 seconds. Its filtered-test count differed
  from the historical reruns. The revised regression additionally reopens the
  encrypted TargetJournal and records the last shutdown phase at its original
  15-second deadline.
- A Store fixture attempt selected zero tests through the library target.
  Only executions of the deployed-format integration target with positive
  test counts supply fixture evidence.

## Required infrastructure and decisions

The available machine is native macOS ARM64, macOS 27.2.1 build 26B131, 16
cores, 128 GiB physical memory, Rust 1.97.1. Resource observations belong to a
shared system. The contracted Linux ARM64 reference needs its existing 2 CPUs,
16 GiB and 200 GiB and an explicit reservation. The only Lima instance visible
during inspection belonged to another project. The user supplies the native
Linux x86-64 host alias. Linux-hosted MinIO requires the approved pinned image
and an owned Docker endpoint. Preserve the independent build and physical
failure-domain attestations with the native evidence.

The format owner acts only if retirement beyond the two pinned revisions is
proposed. BOI's owner handles its live installation. Resolve remaining
dependency findings through upstream remediation, removal, or a documented
owner disposition bound to the exact dependency and advisory. Release owners
can authorize publishing the qualified candidate after all gates pass.
