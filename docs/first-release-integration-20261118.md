# November 18 release integration

**Release status remains open.** The contract is [G01–G14](first-release-goals.md).
Both deployed formats remain supported. The owner directed replacement of Chrono on November 18. BOI's fresh installation decision
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
At 12:42 local time on November 19, both the remote branch and tracking ref
identified `7ac33a24c7577134488fc57a90e0abfddc27ca6f`. The tracking reflog
records an update by push at 12:37. The fixture already exists upstream.

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
| G02 | Fixed inode backing, managed directory operations, native segmented storage and cache paths exist. Newly created groups use LZ4. Snapshots now atomically select a bounded application descriptor tree. Reopen compares its streamed rows and permanent catalog bindings with the exact authenticated Raft snapshot. Large ordered edits journal added and displaced pages, select one durable decision with the root and reclaim bounded batches. A pinned reader survived four generations (173.32 seconds). Sampled publication crashes recovered the old or new tree with exact row reachability (836.51 seconds). | At 3de7e790 point reads consult the exact selected snapshot’s primary directory, including archived references. At 597f92f4 feed reads use individual disk-backed after-images at that position. 029a30cb adds on-disk presence and absence postings. 2389e531 resolves equality and array containment from the selected snapshot’s ordered scalar dictionary. fca0a89e reads result IDs from stored Tantivy fields and removes both per-collection resident ID maps. Complete ordinary writes, remaining structured indexes and bounded text shards, logical body collection and ordinary-log feed ownership, budget cache/compiler and native heap ownership, and measure sustained physical growth, retained readers and reclamation. |
| G03 | New generations stage in bounded Store batches and publish with fixed-size selector writes. Prior source covers over-cap selection. The original laneC workload failed its greater-than-96-MiB precondition. The successor generates 100 MiB. A recovered native Store executable ran the larger-than-one-transaction tree case in 45.01 seconds and the interleaved 4,200/8,400 spool case in 1.35 seconds. | All 228 Raft tests passed on 8d331a48, including permanent 4,200-command and 8,400-audit custody, in 337.53 seconds. Pass the large application restore, interruption, bounded-workspace and native restart checks on the final source. |
| G04 | Tenant status and capacity now use authenticated Rust, private gRPC and CLI reads. Chronological export pins the end and digest across pruning and later appends. A durable per-segment directory supports seeking. Verification checks both archive copies with caller-bound expiring cursors. Three type tests passed. | Qualify private status, capacity, export and verification under outages, replacement and lifetime crossings. |
| G05 | Physical aliases are indexed. New backups commit the source identity, destination, randomized encrypted intent and original Raft position in Control before first upload. On 1ff31a91 Control selects one terminal outcome and exact encrypted bytes before destination publication. A later writer can repair a missing destination outcome. Status reads the selected decision and verifies any published copy. | The native claim and terminal decision test passed in 1.99 seconds. Qualify all interruption, source suspension and restart paths on the common candidate. Complete remote Control routing and exercise delayed remote cleanup. |
| G06 | Stopped local recovery binds its primary and historical read providers. New replicated target enrollment binds source tenant, incarnation, destination alias, primary, historical keys and CA trust. Installed archive, backup-session and history reads resolve historical keys. A native encrypted-store test read the prior ciphertext and rejected omitted or substituted rosters after reopen (1.29 seconds). | The paged private read on 194d4a8d fingerprints both installed wrapping catalogs and reports exact provider/key/version tuples and the audit head. Commit 2a40a45c follows the entire selected encrypted tenant audit chain, reports the first unreadable ancestor by UUID and binds cursors to the visited archive references. The scan uses one bounded row at a time. It revisits the chain for each result page. Ten native key-retention type tests passed. The inventory reports missing sources. Complete remote replica and backup coverage and the atomic retirement decision. |
| G07 | Installed native workers retain the child join for tenant audit, backup claim, point, staged, receipt and change-feed reads. The macOS tooling now checks Darwin process groups, including unreaped children. The combined process-census and release roster regressions passed 41 cases in 21.155 seconds. | On 17720a50 front-door admission closes before the physical Raft writer drains, and its independent grant survives through that join. A protected native three-voter regression passed in 11.24 seconds. Qualify actual authority, data, target and nested worker drains on every required cancellation, panic and deadline on the frozen binary. |
| G08 | Stopped TLS rotation publishes a recoverable generation. Both native laneB interruption and damaged-generation tests passed in 73.77 seconds on b236ad6b. | b63f3430 rebinds the exact authorized ledger-backed local credential on journaled leaf rotation. A native 16-scenario installed lifecycle passed. Exercise all crash points on the final binary and qualify live trust/endpoint rotation and membership replacement under load. |
| G09 | LaneB binds target storage at creation. Cleanup checks original ownership before destruction and uses durable deletion evidence. Ten native shutdown cases passed on b236ad6b in 7.70 seconds. All ten shutdown cases passed again on frozen 2389e531, including encrypted journal reopen after a signed stop. | Finish the distributed crash/cancellation matrix, missing-quorum recovery, old-target isolation and actual process shutdown/restart on the candidate. |
| G10 | Dedicated Control voter enrollment separates Control TLS/peer identities and remote data routes. Coverage tracks topology version, installed routes and actual membership. A recovered protected-TLS test covering 129 installed groups passed in 167.99 seconds on macOS ARM64. | Protected TLS maintenance and log checks replay original responses. A recovery probe failed once during Transit access. Three fresh Prepare operations passed with the TLS fixture running on its own reactor. Qualify dedicated Control startup and implement data-only remote Control access. c6611f41 adds the protected recovery observation to the installed CLI, with a 1 MiB streaming limit. 921488c5 supplies aggregate pending, completed and aborted Control backup sessions through health, readiness and Prometheus. Complete authority observations, replicated membership invalidation and final protected checks. |
| G11 | Thirteen of the 19 domain adapters are registered. They cover correctness, providers on native Linux, repeatable assembly, dependency review, package smoke, OCI smoke, backup cleanup, HA soak, the 15-case installed benchmark matrix, two-worker concurrency, installed lifecycle, protected observability and systemd smoke. The correctness roster selects 25 named native tests covering 13 required scenarios. | Collect authenticated passes for all 19 domains. Implement HA faults, recovery, audit retention, key retention, standalone capacity and HA capacity. |
| G12 | Native macOS ARM64 component attempts and a frozen functional run retain original failures and reruns. The earlier deployed KV component passed four tests with one ignored. The actual Store deployed-format integration target passed 4/4 on frozen f65c3d56 (5.23 seconds test time). Native OpenBao 2.6.2 restart/refresh/revocation runs retained process/output receipts. | Strict workspace Clippy passed on 17720a50 (653.08 seconds, 1,960,673,280 bytes peak RSS). Formatting passed in 13.573 seconds and all 440 Python cases passed in 252.821 seconds. The earlier 8d331a48 native Authority suite passed all 82 tests. Freeze a complete implementation and verify identical source across native macOS ARM64, Linux ARM64 and Linux x86-64, including actual OpenBao/MinIO and three separate three-member groups. |
| G13 | The raw million-document cases passed for 1, 100 and 1,000 tenants in 223.36, 337.34 and 342.76 seconds, with peak RSS of 1,940,078,592 bytes. An installed-node rehearsal completed ten authenticated gRPC/MCP workloads with 1,000 operations per workload (675.21 seconds). A separate 32-document, 16-operation trial passed ten workloads in 154.39 seconds. The installed concurrent read/write component ran 1,000 operations in 257.26 seconds. The three-voter rehearsal elected its own leader and committed 32 seed documents. Two component runs passed all six workloads. A later failed run captured premature expiry of a follower’s storage grant after commit. The standalone snapshot-write component finished all 6,000 operations and then required SIGKILL at shutdown. | Retain the greater-than-3-GiB incompressible standalone and HA runs, 15 million-document configurations, concurrency, operating limits, and the full 86,400-second HA soak. |
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

- The owner's Chrono instruction was implemented in `96bdb3ab`. The release lock
  selected 483 packages, including time 0.3.55. A fresh projected-lock scan
  reported zero vulnerabilities. Its only finding is the reviewed LRU backport
  RUSTSEC-2026-0253. Cargo-audit returned zero and emitted no stderr after
  index hydration. The root graph including all workspace features contains
  no Chrono. rmcp's separately locked, unused OAuth example dependency is
  outside that graph. The native rmcp library passed 372 tests. The native
  OpenRaft library passed 235, including its date and instant regressions.
  The corrected Japanese/English tokenizer suite passed 100 unit tests and
  four integration tests, with two ignored.
- Frozen `4ef0c40d` passed format and all 418 Python tests (256.289 seconds
  inside unittest). The earlier full strict workspace Clippy passed on
  `f4c613a1`. Clippy on `62b85f55` caught a missing server macro import and
  incompatible error conversion in the new Control claim fixture. Both were
  corrected and the later frozen runs have their own receipts.
- The Linux release command had selected an extra fixture-independent
  benchmark comparison tool. The build now selects the two executable names
  its verifier actually expects. Its release gate regression suite passed
  28 cases. Benchmark raw probes and development provider results retain
  separate binary identities.

- On frozen 194bc449 strict workspace Clippy exited 101 on the key-retention
  CLI return type. Commit 7b4bb02d corrected it. The successor 17720a50 passed
  strict workspace Clippy, formatting and all 440 Python cases.
- Three-voter benchmark attempt 6 captured the original Raft error. The acme
  follower had applied position 27 while committing position 28 and lost access
  before acknowledgment. Its raw stderr SHA-256 is
  `b932522baea07a4f7b2307a707c74d6170a4d6e6b2e185341aeec24a6ddb7f0f`.
  The independent-grant fix allowed a native protected three-voter fixture to
  close request admission while still serving outstanding storage work, then
  complete shutdown. That component passed in 11.24 seconds, peak RSS
  143,671,296 bytes. Earlier benchmark attempts 3 and 4 passed in 106.73 and
  156.57 seconds. Attempt 5 failed during the Transit key probe.
- The separate standalone concurrency run completed 5,500 writes and 500
  snapshots in 1,937.528 seconds. Shutdown exceeded 90 seconds and the harness
  killed the daemon at 100.077 seconds. Its failure and preceding timeout
  remain recorded pending diagnosis.
- Installed attempts 2, 3, 6, 7 and 8 observed a 401 using the freshly rotated
  Control credential. Commit b63f3430 updates the certificate binding only after
  validating the original signature and issued ledger identity. b40e55a9 tests
  restored MCP access with the restored incarnation’s credential. Attempt 9
  replayed 64 processes across all 16 scenarios with six clean daemon exits.
  Wall time was 146.003 seconds, peak RSS 111,362,048 bytes. The executable
  predates the final single-inode bearer check. Its component
  binaries have SHA-256 `5ee7cdb3ad41c3323070d66876177116bee3d42fede7eb00b043e9a04b31583c`
  (kasumid) and `142e7534431a1d5586c947f9a6b1de3d5e7b79d9f0bec0c2940f18d91a7c75ff`
  (kasumictl).

- Frozen `2389e531` passed formatting in 24.222 seconds, strict workspace
  Clippy in 636.125 seconds and all 440 Python tests. Its Engine suite passed
  761 cases. The Raft suite passed 228, Authority passed 82, and both deployed
  fixture targets passed four each. The standalone encrypted backup reopen
  regression exercises the installed durable Control decision across restart.
  The separate full Store and workspace runs require terminal receipts.
- On the same source the TLS suite passed three tests and failed the original
  issuance case with “operation would block”. The stopped-operator test kept
  its filesystem lock while starting another stopped rotation. Commit
  `01b809b5` drops that owner before rotating and adds a bearer-alias regression.
- Installed attempt 10 passed all 16 scenarios, 64 original process commands
  and six clean daemon exits in 153.826 seconds, peak RSS 94,912,512 bytes.
  The assembled binaries were `762d9de18d8dec54502ffa0ea400c98be485269e647a1dde4f75bf63ce50a24f`
  (kasumid) and `b932d3c827e8d46b101f2f35171d53bfe992de6e673bde9207b4cf93b3ea55f5`
  (kasumictl). Existing installations that already lost the original bound
  credential during an earlier rotation need stopped administrator recovery.
- After `17720a50`, replicated benchmark attempts 8 and 9 each passed all
  six workload types and 96 operations. All three members reached tenant
  position 28 and Control position 3, then drained cleanly. Driver times were
  28.571 and 37.074 seconds. Attempt 7 failed before workload dispatch because
  it ran from the wrong working directory.
- A second standalone run completed all 6,000 operations in 1,014.949 seconds,
  then required SIGKILL after 100.070 seconds. Three native stack captures
  located the daemon in standalone log purging, hashing and decompressing
  pages with 21,845 entries selected. Commit `919178dc` finishes an admitted
  atomic chunk and defers further optional purge to reopen when admission closes.
  Both original SIGKILL receipts are preserved. The 6,000-operation replay is
  required on the corrected source.

- On `919178dc`, formatting, all 440 Python tests and strict workspace
  Clippy passed. The partial-purge restart fixture passed in 0.81 seconds.
  The Query suite failed while fetching the IPADIC build input. The successor
  uses the original 12,907,073-byte archive, verified against upstream MD5
  `a95c409f12f1023fce8ef91f991ef042` and SHA-256
  `a7ba9f645ffe7094e56ae1c4a81d100df8fbb1e28bbe1792622e9728e162db3d`.
- The first 6,000-operation replay on the purge fix stopped before reaching
  shutdown. The Mac's power log records sleep at 08:35 and a wake at 08:52
  local time. The daemon recorded a sealed key lease and an uncertain
  post-commit acknowledgment on wake. This is a separate failure from the two
  original shutdown hangs. The awake replay uses the identical executables,
  with SHA-256 `ec81bedea4214b3ae31f7bb7c990c26832ba505af281190a24d2caaf9adb9f28`
  and `937f79e11d14aea25c1277c0d7f14372db5a86ddf8e46b87141f1961d6feed81`.
- Commit `6748524b` adds inclusive, exclusive and open structured range
  queries on disk. Its first native check failed compiling the test because
  the assertion destructured the ID vector as a pair. `9630c679` fixes the
  assertion. `8d18f2b5` moves snapshot evaluation, lease selection and scans
  to the installed blocking-child owner. `250fa69b` covers query and cursor
  pages and routes denial records through the independently owned audit writer.
- `837d73cf` collects native archive outage, replacement and permanent
  identity evidence. `2fc4bf71` adds authenticated observations and verifies
  ciphertexts on three physical data voters. Three negative evidence tests
  passed for each collector. The unintegrated nine-process qualification
  still needs its installed topology and a valid verification page limit.
  A native production validator accepted 10,000 lifecycle intents and refused
  10,001 with the existing hard quota. The original refusal is retained under
  `audit-legacy-lifecycle-ceiling`.

## November 19 native and implementation evidence

| Goal | Observation |
| --- | --- |
| G02 | `f1c4c2ad` reads leased scan IDs from the selected encrypted primary and archive directories. It merges overlapping IDs and rechecks the exact lease before releasing the result. `77a97d70` resolves indexed membership predicates through the selected snapshot dictionary and reads each matching scalar rank once. Ordinary mutation manifests, persistent structured and text indexes, and logical object garbage collection remain open. |
| G04, G07, G10 | `2e33b5a7` exposes authenticated service audit capacity through the client, native service and CLI. `7ac33a24` retains archive cursor reads under the audit writer through their join. Native tests for the protected routes are running. The legacy reducer accepted 10,000 Control lifecycle intents and refused 10,001. The successor is under review. |
| G06 | `e13d2c17` obtains the wrapping-key versions of each retained history manifest and chunk after authenticating the object. The page identifies unreadable objects and binds its cursor to the selected inventory. The current implementation reads the history objects again on each page. Coverage of backup sessions, remote members, recovery and retirement remains open. |
| G07, G08 | The frozen 2389e531 run passed 10 target-shutdown cases and its independent protected drain case. Three of four TLS tests passed. A stopped operator still held the installation lock in the failed test. `01b809b5` releases it before reopen. The original 6,000-operation process failure and its replay are detailed below. |
| G11 | `0d73393a` binds transported audit observations to nine voters and uses eight-entry verification pages. The native page of eight succeeded. A request for 32 produced the original InvalidArgument response. `7b229a95` fixed the invocation of the ignored 100,000-receipt capacity test. The first attempt selected zero tests. The corrected attempt passed its preceding seven cases, then received SIGTERM after 612.539 seconds in the capacity case, with child exit −15 and runner exit 143. It has no capacity verdict. |
| G12, G14 | Two prior full workspace attempts ended with runner exit 130 after 566.411 and 4,181.283 seconds. Frozen `9630c679` failed the Engine libtest build after 3,024.971 seconds, peak RSS 5,247,565,824 bytes. The errors identified four fixture calls affected by the snapshot worker return type. The successor surfaced four further diagnostics accessing a nested response. `c5308969` measures the error-path workspace on the live worker and checks its release. |
| G13 | `c8cc6c7b` measures every canonical document as one level-9 gzip stream. The example now specifies 98,400 documents of 32,768 bytes each, totalling 3,224,371,200 bytes. `6ae8d7cc` records per-batch expected and observed body digests from installed reads. `2984f1af` replays the original compression journal and 32 acceptance-verifier tests passed. The installed standalone and HA operations and physical resource samples remain required. |

The awake macOS replay under `concurrency-native-purge-drain2` completed
5,500 writes and 500 snapshots in 2,472.599 seconds. The original daemon exited
zero 11.317 seconds after SIGTERM. On the same installation, the readiness probe
timed out after 30.173 seconds while the new daemon was opening its tenant. A
stop during that startup produced process exit −15. The complete attempt took
2,531.02 seconds with peak RSS of 672,530,432 bytes. `d21b2b3a` registers
SIGTERM and SIGINT before opening storage in both daemons, routes a canceled
open into the startup registry drain and joins any admitted TLS reload. The
separate-process regression sends both Unix signals during an admitted open.

The dependency change removed Chrono. The reviewed lock scan covered 483
packages with zero vulnerabilities and the existing LRU backport disposition.
Both deployed format fixtures continue to receive read/write coverage.

The source archive and Cargo.lock hashes, target triples, resource limits and
commands for each frozen revision are in its private candidate directory. The
three-platform input following the startup-signal change is `d21b2b3a`, under
`startup-signal-candidate`. Its local qualification is in progress. On
`8dbc3e02`, formatting and all 448 Python tests passed. On the preceding
`e13d2c17` run a synthetic timeout child failed to print its startup marker
before its 200-ms deadline. `dc3cbbfc` waits for that child in the test
observer, and all 17 assembly tests passed in 4.158 seconds.

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
proposed. BOI's owner handles its live installation. The dependency update has been applied and the existing LRU disposition is recorded. Release owners
can authorize publishing the qualified candidate after all gates pass.
