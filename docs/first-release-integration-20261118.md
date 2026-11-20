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

## November 19 dependency, capacity and recovery results

| Goal | Observation |
| --- | --- |
| G02, G03 | `187aca4b` adds a nine-byte version and kind entry for each unique live or archived document ID in new snapshot manifests. Lease scans seek one ordered directory. Earlier manifest layouts retain their original reader. Native snapshot reopen and both deployed fixture targets remain part of the pending final run. |
| G04 | The lifecycle donor passed Engine test compilation and focused strict Clippy. Its three-member test panicked on snapshot record kind 25 because the kind array had 25 slots. The original process exited 101 in 23.84 seconds. The successor corrects the shared roster and the zero-backup restore budget. The donor remains outside the release tree pending its native results. |
| G05, G06 | The historical-key archive/read/restart regression passed on `e13d2c17` in 38.86 seconds. The complete compiler and test process took 3,321.26 seconds with peak RSS 5,462,097,920 bytes. `2f622693` binds cursors to Control backup and recovery checkpoints. `7b74c9f8` authenticates the encrypted tenant intent, selected terminal decision and original historical catalog before reporting a session's wrapping keys. Completed backup contents, legacy destination-only sessions, remote member coverage and retirement still require evidence. |
| G07, G11 | On the third 6,000-operation rehearsal, the original interactive credential expired at write 5,311. The unchanged receipt includes the uncertain outcome. A distinct run retains the installation for restart diagnostics. `b868325e` records a failed soak at its source when a daemon or client exits uncleanly. Seven shortened soak-runner tests passed in 202.753 seconds. They exercise the runner and its verifier. The 24-hour native run remains outstanding. |
| G12, G14 | The `2f622693` projected lock scan covered 483 packages and 1,533 RustSec advisories at database commit `472a4c9a785030434f15d7da84964d60fbe789ab`. It reported zero vulnerabilities and the existing source-patched LRU warning. The scanner could not find OpenRaft or its macros in its local yank index. Direct crates.io index responses confirm that both 0.9.25 versions were unyanked. The `68c04bea` all-target check exposed a Rust compiler query depth of 130 in the Authority executable. `b8859c64` applies the existing daemon bound of 256. The locked offline workspace all-features/all-targets check passed at `4e252658`. The immutable `b868325e` Python run also exposed two credential watcher processes racing to overwrite one test PID file. `d094b0c9` waits independently for both watchers and all 21 development supervisor tests passed in 24.037 seconds. |
| G13 | The native macOS ARM64 `c8cc6c7b` driver measured 98,400 documents and 3,224,371,200 canonical bytes in 1,012.543 seconds. One level-9 gzip stream produced 2,669,413,656 bytes, ratio 0.82788658. Peak RSS for the measuring process was 4,292,608 bytes. Canonical SHA-256 was `4dfacafe48e5b485d424be392eb29d436c5902de64012369817687ba4f0760cc`. The retained executable SHA-256 was `c491893a03d3f6b25aac6dc73de3781bbf330461d457b3839e4321a32820fbf3`. The verifier replayed the original journal. Five native driver tests passed. |
| G13, G11 | Both the preliminary 96-document load and the 98,400-document installed attempt with batches of 96 timed out on their first write. Each installation stopped cleanly. Reopening each installation and resolving its original idempotency key confirmed the committed batch against the retained input digest. A separate 32-document run with batches of eight passed load, full read-back and stop in 35.039 seconds. The larger eight-document-batch run has its own journal. `4e252658` and `7554da48` bind each installed verification prefix, raw integrity file and final observed digest to the measured generator inputs. All 33 verifier tests passed in 5.131 seconds. Installed maintenance, physical resource ceilings and HA qualification remain open. |

## Integrated lifecycle candidate and native restart

The common source for the three native platforms is
`dd43ef2840ad46b7176d5e87605e30a18ea466f1`. Its source archive is
69,754,880 bytes with SHA-256
`4b2cae3c364615e583ffded14540c89eb04ee83219fa08218441811cf7d5c667`.
The verified 105,722-byte Git bundle applies on top of `7ac33a24` and has
SHA-256 `b4969bc7ffe39c7943f2e6b64bd7c4341ddefa48c738393d0a02484f3d9b615b`.
The macOS ARM64 formatting check passed in 49.62 seconds. This candidate is
on hold for the implementation and qualification work below.

| Goal | Observation |
| --- | --- |
| G02, G03 | `8423155b` reads query records from the selected primary directory. `986bfc69` joins a retained snapshot change-feed prefix and a newer ordinary-log tail in the same page. `755d8c01` measures full document framing using the authenticated body length. Coverage still needs ordinary mutation manifests, persistent indexes, collection and the physical capacity run. |
| G04, G05 | The integrated lifecycle change writes permanent Control intents to authenticated bounded rows. On native macOS, the three-voter test physically reopened the encrypted stores and replayed the original decision in 15.03 seconds with peak RSS 40,517,632 bytes. A second test rejected a substituted intent and enforced the configured byte budget in 17.76 seconds with peak RSS 40,976,384 bytes. Both ran in executable SHA-256 `280d8dbbc558ac0b6ee1f5a2cf18a40a0873cd1c6d02c16aef91b9e34fa6219a`. Mixed backup and lifecycle restore budgeting and the lifetime workloads remain under test. |
| G06 | `2fe9eaed` authenticates the checkpoint graph and inventory, including stored document, history and audit objects, under their original tenant, alias and session. It revalidates checkpoint identity before reporting keys. Unreadable objects prevent retirement. Its locked offline workspace all-targets/all-features check passed in 1,580.48 seconds. The focused native proof, remote membership inventory and retirement are separate requirements. |
| G07, G11 | The six outstanding acceptance adapters are key retention, audit retention, HA faults, recovery, standalone capacity and HA capacity. Thirteen of the nineteen are registered. `c07d8c18` and `47e88250` bind transported audit observations to original native process receipts. `2fe135a9` adds a physical Authority reopen test for permanent incarnation and receipt rows. The installed audit qualification still requires nine enrolled voters and the permanent-history workload. Review of 27 revisions and 39 distinct blobs found a 64-KiB backup-session record bound and a 256-object cleanup page. The historical global session-count threshold requested by the contract remains unidentified. |
| G12, G14 | Strict workspace Clippy passed in 1,051.82 seconds on `4e252658`. On `187aca4b` the full Python run timed out in a package smoke listener. A separate reproduction also observed connection refusal. With `c9decf89`, twelve consecutive package fixture attempts passed using listener ports outside the ephemeral client range. The original failing daemon stderr was unavailable. |
| G13 | A second native measurement reproduced all three hashes and the level-9 gzip size for the 98,400-document corpus in 811.90 seconds. On the installed eight-document-batch run, 477 batches were acknowledged before a write deadline at ordinal 3,816. The authenticated original receipt reported all eight writes committed at revision 480. A second physical reopen recovered the same receipt for batch SHA-256 `c601bcc97426b774b25c4931e60587c938e2cf11aa570aa6b73597f30f987623` and stopped cleanly in 1,079.40 seconds including startup and verification. The original failed run took 1,751.22 seconds. |

`4a7a11e7` permits continuation only after verifying every earlier durable
receipt against the original generated input. On the completed 32-document
installation it authenticated the original four batches, dispatched zero
additional writes, verified every document and stopped cleanly in 35.33
seconds. The larger continuation uses the same installation that recovered
the original 3,824 documents. Neither the remaining 94,576 documents nor
their maintenance, physical resource and HA workloads have a passing receipt
at this checkpoint.

## November 19 shutdown recovery and permanent history

| Goal | Evidence through 15:51 ICT |
| --- | --- |
| G04, G05 | `94e33123` checks actual selected backup and lifecycle prefixes independently. Its donor passed strict Engine library and test Clippy in 523.69 seconds. `3f16cb5c` requires a confirmed audited Control read during lifecycle fixture startup and retains each failed attempt. The earlier native suite passed 15 of 16. The ambiguous-commit case failed during startup when Control could not confirm its audit. A fresh exact-case run passed in 121.83 seconds. |
| G07, G13 | The standalone concurrency attempt completed 500 snapshot reads and 5,155 writes before write 5,156 timed out. The workload took 3,341.89 seconds. The process still held snapshot serialization work after SIGTERM and required SIGKILL. Its original installation reopened and returned the exact original digest for write 5,156 at revision 5,159. Both documents had that revision. This read-only recovery and clean stop took 515.10 seconds. `e7720cab` stops unpublished application snapshot serialization and `177ba79f` also checks shutdown between transport chunks and custody records. Snapshots that have begun durable staging finish publication. |
| G11 | Fable 5.2 at xhigh effort advised a prospective floor of 100,001 permanent sessions after the historical audit. The original assistant response is in `fable-session-threshold/desktop-answer.md`, SHA-256 `2ea02391e2a5f511b53e4def0e3ea8cd64cd8c1bb17f8939bce5c6d286eb0856`. `1f70060a` records the new contract and pins the four historical count ceilings. All 34 acceptance-verifier tests passed in 6.32 seconds. Native cold-kill and replay evidence remains due. |
| G11, G12 | The 100,000-receipt fixture constructed the entire source cohort. Restore exhausted its original 64 reservation slots at row 17,657. `af18b860` keeps the 64-MiB budget, uses 1,024 bounded slots and measures both owners. Three Authority enrollments replayed after physical reopen. At production cohort size, the original run lost its application key lease before acknowledgement. `5f416f76` renews independent application and custody grants throughout writing and verification. |
| G01, G12 | The strict replicated bootstrap decoder rejected the first native nondefault lifecycle budget on reopen. `591c802b` admits the writer's canonical field while preserving old default bytes. The corrected native decoder accepted both encodings and rejected duplicate, explicit-default, quoted and zero budgets. Both deployed-format fixtures remain in the release contract. |
| G12, G14 | On the common provisional input `dd43ef2840ad46b7176d5e87605e30a18ea466f1`, formatting passed in 49.62 seconds and the 457-test Python suite passed in 483.20 seconds including startup. The macOS locked all-targets Engine check also passed on `cd07540b`. Later implementation commits need their own qualification. |

The subsequent audited-startup suite passed all 16 native cases in 928.88
seconds, including the earlier ambiguous-commit failure. The permanent Control
history test reopened 10,001 lifecycle intents against the former ceiling of
10,000 in 2,005.28 seconds. It authenticated 29,399,633 bytes with a peak
RSS of 14,893,056 bytes. The selected ledger SHA-256 was
`e247f0259affa43f240c325441ee6a4095b75a72966380409a56c16d0a96eac7`.

For G06, `e0457b0f` attributes the key inventory from a completed checkpoint
to the selected tenant recovery record. The source and Control fences cover
the original identity, destination and checkpoint graph. For G11, `3e9cbbdf`
schedules fixture renewals using the Authority node's lease clock. The corrected
small enrollment, physical reopen and replay passed. The full-scale restart
still requires a matching receipt.

The next G13 run authenticated the preceding 478 durable batches before adding
more writes. The client timed out at document 6,760. A separate authenticated
receipt for the original eight-document request recovered revision 848 for
every document. Its SHA-256 was
`072e4bcb2b1617bc7e5fde55bae0ecc0ef63ac32017d5096b703b28a2fab38f0`.
This brings the installed count to 6,768 of 98,400. The attempt stopped cleanly
after 2,472.77 seconds. Its write deadline remains recorded as a failure.

## November 20 native results

| Goal | New evidence and open checks |
| --- | --- |
| G01, G03 | Both deployed installations opened, served, wrote and reopened with the frozen `dd43ef28` server in a serial native run of all three deployed-format cases (135.975 seconds). The parallel run failed when two copies used the original installation UUID simultaneously. The original Store crash-cut case passed alone in 146.838 seconds. Full-suite qualification still includes the original concurrency failures. |
| G02 | `bd190402` publishes the ordinary document directory with each applied cursor. `630400df` adds ordinary structured postings. The structured implementation passed four native tests covering publication, interruption, stale recovery and reopen. The same process failed a separate change-feed test because an ordinary applied position lacked its preceding snapshot. `898bf96b` authenticates that snapshot on the pinned application and Control read view. The original GC rehearsal retained 18 to 162 objects across nine churn rounds. A final native run still needs to prove that collection plateaus and supports retained readers. |
| G04, G05, G06 | The lifecycle run crossed 10,000 intents with 10,001 and reopened in 1,961.697 seconds. The mixed backup/lifecycle fixture failed with a mismatch between the backup binding head and installed Control state. For backup sessions, 520 original outcomes included 261 failures, two intercepted writes and a further hard kill before reopening. Independent replay in 4.394 seconds reproduced the original witness digest `e15ee04e2b5317ece99309b4e372a7337514bb10bae10bbedceaecda3443ed68`. The full threshold is 100,001. Fixed filesystem slots would occupy 432,573,125,688 bytes. `2cac4d66` releases padding after durable terminal publication and retains the v1 reader. Six independent verifier tests passed. The full session cohort and key retirement remain open. |
| G07, G08 | The frozen native process passed the initial signal test and the historical backup claim/reopen case. The integration exposed additional drain and lease errors. A fresh native run retained and replayed 100,001 mutation receipts in 2,730.065 seconds with 1,024 memory reservation slots. The Authority retained 100,001 incarnations, replayed the first and last after reopen, and wrote 356,781,360 bytes in 12,095.859 seconds. Earlier reservation and grant failures remain in the evidence index. |
| G09, G10 | Remote-Control placement and protected observations still need an installed nine-process test. An earlier remote-Control test build failed because its test module was missing. |
| G11 | The branch now registers 18 of the 19 domain adapters. `9dd05e34` verifies audit originals, `c8fd08ce` adds standalone and HA capacity, and `275d9ccc` adds HA faults and recovery. The missing adapter covers key retention. Three sets of component tests passed (29 capacity, seven HA, 34 registry). A separate full Python tooling run passed 463 cases in 392.013 seconds. The original audit runner would have stopped the 100,001-incarnation case at 7,200 seconds. `147e7760` binds execution and replay to the 86,400-second Authority timeout. |
| G12, G14 | On native macOS ARM64, `dd43ef28` passed formatting, 457 Python cases, locked offline all-target/all-feature workspace checking (674.031 seconds) and strict workspace Clippy (501.841 seconds). Building all three production binaries took 7,765.595 seconds. The focused Engine library reported 762 passes and three failures, its separate binary target failed one case, and the Server library reported 531 passes and six failures. The Store run also identified an impossible randomized key-generation request. `081933ba` fixes its fixture. No complete passing workspace run exists for this candidate. |
| G13 | The installed corpus retained 6,768 authenticated documents. The next startup on the earlier daemon failed after 1,639.309 seconds and its drain reported an unavailable security-audit key lease. The frozen `dd43ef28` daemon subsequently reopened the same installation, authenticated the original last eight receipts at revision 848, and stopped cleanly in 24.207 seconds including startup and readback. A separate attempt continues writing from that verified boundary. The reference Linux run, physical capacity operations and 24-hour soak remain open. |

On macOS ARM64, the frozen OpenBao interoperability test ran against the actual
OpenBao 2.6.2 Transit daemon and passed in 5.555 seconds. It checked a round
trip, rotation, backup reads and warm revocation. The OpenBao archive SHA-256
was `4e495376174accc0e014d31e9901f518a974f966850c839f626347eaac05fd52`.
The Kasumi test executable SHA-256 was
`c2ca9b506f3b7ce599df67b17f806878095bec3b2d99bd33087a366ae6f89294`.
The native result, command, limits and log SHA-256 are in
`openbao-native-dd43-repeat/result.json` in the private evidence index.

Two executions of the frozen Store crash-cut test reached different results
on adjacent native installations. One passed in 128.632 seconds. The other
failed after 125.735 seconds because a random stage still incurred an injected
mutation at the count measured on another stage. Its original log SHA-256 is
`be9d585d4a77f91b25fe19797b8af542509cae6dc4cd00b4d8f70dcb5da09b64`.
The corrected case records the actual rejected backend mutation and verifies
every recovered key and byte against the selected tree.

The native macOS production executable hashes for `dd43ef28` are
`e19de27289bea7c22254572f38bc741089224324c521132bb77396ce8bfd154e`
(kasumid, 126,799,168 bytes),
`36af4d07c1320d965d41d06f251d40066ff9d46e875248d678d345e163c2867a`
(kasumi-authority, 33,084,512 bytes), and
`6b4e4238b432a24f9bdf594b5c6e68af2a109fed61f4755a72e031fefde2aad7`
(kasumictl, 8,827,360 bytes). The release ledger indexes the build commands,
resource limits, durations, original failures and retained hashes by source.

## November 20 integration after the frozen run

| Gate | Incorporated change and measured result |
| --- | --- |
| G01, G03, G07–G09 | The original cancelled target monitor also passed alone on the frozen source in 4.251 seconds. The Store crash-cut regression in `f392577d` passed three native runs in 79.722, 51.219 and 44.754 seconds. Each run verifies every recovered key and value after the backend reports a real injected failure. |
| G02 | `68832bb2` collects displaced document bodies and shared proof chunks after authenticating the snapshot selected by the current view. `fdc50370` stores full-text postings in versioned Tantivy shards alongside ordinary primary and structured indexes. Readers retain their memory reservation through cache eviction. The combined native GC and text checks are pending. |
| G04–G06 | `930604a0`, `2ef6ef25` and `59d15670` persist scoped key-retirement decisions, reserve their outcomes, spend request ordinals once and check membership when Raft applies the fence and decision. Eleven type tests passed on the retirement protocol. Existing format generations report missing session origin until an authoritative census exists. Independent storage owners and remote replicas still need complete, authenticated reports. |
| G09, G10 | `7a457acc` routes data-only processes through their configured remote Control identity and retains protected observation readers through shutdown. Local native testing and nine-voter installed qualification remain open. |
| G11 | `db974e57` registers the nineteenth adapter. It exercises a fresh Control catalog, pages and rotates its wrapping keys, refuses a referenced or stale retirement and checks the durable decision after restart. Two key-adapter tests and the 34-test acceptance verifier passed. All 19 domains still require their original qualifying runs. |
| G12 | The workspace all-target, all-feature check passed on `54e74d07` in 308.103 seconds after a backup test binding shadowed its authorization helper. `599f1a0f` addresses the subsequent strict Clippy map-entry finding. Both original failures are retained. The Linux OpenBao 2.6.2 archives and extracted amd64 and arm64 executables passed digest and architecture verification. Native Linux interoperability remains open. |
| G13 | The frozen daemon acknowledged 44,824 of 98,400 documents at revision 5,605. Its next eight-document request reached the configured 1.5-GiB serialized snapshot limit. A separate cold reopen in 153.692 seconds confirmed the original quota refusal and stopped cleanly. `92801ac5` verifies that both logical and serialized limits can hold the capacity corpus. All 30 capacity adapter tests passed. A fresh installed cohort uses a 6-GiB serialized limit and a 4-GiB logical limit. |
| G14 | The previous archive, binary hashes and original failures are retained under the exact provisional source. The integrated storage, remote Control and retirement changes require a new common candidate and independent native qualification. |

## Required infrastructure and decisions

The available machine is native macOS ARM64, macOS 27.2.1 build 26B131, 16
cores, 128 GiB physical memory, Rust 1.97.1. Resource observations belong to a
shared system. The contracted Linux ARM64 reference needs its existing 2 CPUs,
16 GiB and 200 GiB and an explicit reservation. The only Lima instance visible
during inspection belonged to another project. At 08:51 UTC on November 19, the repository's
GitHub Actions runner API returned zero registered runners. Claude Fable 5.2
at xhigh effort could find neither a host reservation nor an admitted plan
for the three Data, three Control and three Authority voters. The September
ARM64 reference is a past measurement. At this check the Mac had 77 GiB free.
The infrastructure owner supplies the Linux x86-64 alias, the ARM64 reservation
and the nine voter placements. The Linux providers adapter extracts MinIO directly from a verified OCI archive. Docker Hub and Quay returned HTTP 401 for anonymous access to the pin, and Google’s mirror returned HTTP 404. The verified offline archive obtained on November 20 is recorded below. The separate OCI smoke gate requires a Linux container runtime. Preserve the independent build and physical
failure-domain attestations with the native evidence.

The format owner acts only if retirement beyond the two pinned revisions is
proposed. BOI's owner handles its live installation. The dependency update has been applied and the existing LRU disposition is recorded. Release owners
can authorize publishing the qualified candidate after all gates pass.

## November 20 native rechecks and successor repairs

The common source archive for the new three-platform attempt is commit
`37fcea5a398d45a2569cb11f9899e67bc6e59f9d`, tree
`ffb5c35ed820763d723da1112bd0e0d5dedf2b62`. Its 2,345 paths occupy
70,912,000 archive bytes, SHA-256
`4f7e42574073b309522342fba7ff973d15635189a08f28875d66e7bf7cc28b04`.
Subsequent fixes require a new common candidate before final qualification.

| Gate | Original result and follow-up |
| --- | --- |
| G01, G03 | The repaired native deployed-format suite passed all five cases in 181.589 seconds, including writes and reopens against the committed 12140939 and cf9959f1 fixtures. The process receipt has SHA-256 `fb255e3c857b025e56465b48e5057199c386ddfe36f1f03766805332cb20f754`. |
| G02 | `8171d7ef` budgets each change-feed slot during document GC, resumes inside a commit and retains memory for each discovered owner. `c5876ddd` exercises text reads across ordinary writes, encrypted snapshot transfer and reopen. The frozen Store ordered-page regression passed. |
| G04–G06 | The mixed backup and lifecycle test retained an old store handle through retirement. After `06df0a38`, the repaired test passed in 8.506 seconds, authenticated all three intent rows and the backup and exercised the snapshot limit in the writer and decoder. The separate offline backup-inventory test exposed a fenced native owner and remains open. `336b396c` prevents rewrapping a catalog under a substituted key identity or a lower version. |
| G07, G08 | The repaired cancelled target monitor passed in 3.577 seconds and management drain in 12.767 seconds. The single-execution-slot response release regression passed in 3.407 seconds. Its process receipt has SHA-256 `37971a348114c86d84fb842ed666fe61107b1bd94198bdbd29d69bf4f40d9267`. |
| G05, G09, G10 | In a native three-voter run, the data leader attempted a leader-only backup-binding read on its local Control follower. `cf4246ca` reads at the authenticated Control leader's quorum index. The repaired run completed retirement, activation, all three confirmations, drain, physical reopen and target readiness in 396.804 seconds. Its process receipt has SHA-256 `9159dc72130c606cf566c9180fc192edbe09f05f6bff2afd08af693b422d4fec`. Dedicated nine-process qualification remains open. |
| G11, G12 | On the archived source, native formatting and the locked workspace all-feature/all-target check passed. Strict Clippy failed on the unused Control watcher. `06df0a38` and `cf8d9c92` remove the unused publisher and fixture field. The 58 targeted HA and capacity adapter tests passed in 370.050 seconds. Full Python discovery ran 510 tests and failed one when a second status call lost the authenticated recovery observation. `7148adf4` counts and replays the receipt of the original successful poll. |
| G12 | The archived lock's projected audit counted 483 dependencies and zero vulnerabilities. Its sole advisory was the reviewed LRU backport. Cargo-audit could not find the two patched OpenRaft crates in its local yank index. New crates.io responses for both 0.9.25 archives confirm their reviewed SHA-256 values and report both unyanked. |
| G13 | On the 6-GiB snapshot-limit installation, 55,864 acknowledged documents were followed by a write deadline. Its retained original committed the next eight at revision 6,986. The process stopped cleanly after 2,473.388 seconds. A new process on that same installation returned the same revision, eight versions and original request SHA-256 `b05a59ff72b834e953ddb0dabc9f37878047c2b63ff210b37874170799b2e5f3`. Its readback took 7.769 seconds after startup. The required corpus has 98,400 documents. |
| G14 | The prior macOS release binaries remain attributable to their original source. Successor binaries, native Linux runs, the independent build, delivery bundles and final release checks remain open. |


## November 20 storage, recovery and platform receipts

| Gate | Result |
| --- | --- |
| G02 | On `a6856f52`, all five primary-directory tests, five permanent-receipt publication tests, the selected encrypted snapshot test, six text-directory tests and the text snapshot/reopen test passed. All three native document GC cases failed. The churn run grew from 18 to 162 objects. The immediate-flush setting prevented the census from advancing after its last owner was flushed. `67a155a0` corrects that condition. |
| G05, G06 | The installed `37fcea5a` daemon completed private paged inventory, rejection of stale coverage, rotation, retirement, process restart and original status readback in 28.410 seconds. Daemon SHA-256 `8ce63d6b1fbde666ba94992d0f3dfacddd99c4a7d2231696379cac9129f8d33b`. The multi-member catalog request and report validation passed on `a6856f52`. `17ff6bf6` reads Control session pages and key inventory at the authenticated quorum index. On `7c7ff5d2`, the physical test independently removed and restored each tenant audit archive copy through its installed disk owner. The test passed in 8.24 seconds. |
| G07, G09 | The pinned three-member test with the original Initialize node unavailable passed in 570.057 seconds. The process receipt has SHA-256 `7012dcbc2dafcf2f2d7b014e4f4cbc1b366b509e3649fd71929287a11c349b3b`. The separately pinned owned-restart case completed recovery and failed its drain in 554.676 seconds. Its original receipt has SHA-256 `10666aa45e74d5efeda9f2411c7a8cf12ece97679ce34ae8dd39cceb5a2ee77e`. `5544c672` transfers the original settled diagnostic to the joined report and preserves physical causes in their original cells. Seven native cleanup cases passed in 14.675 seconds with the storage changes incorporated as `200c924a`. |
| G11 | The 100,001-session attempt on `37fcea5a` stopped after 821 journaled sessions. Intent publication returned an unknown outcome after 3,019.512 seconds. The original installation, journal and logs were preserved. `55c8a0f5` retains the underlying storage cause through the public uncertainty response. |
| G12 | Native Python discovery passed all 510 tests on `a6856f52` in 851.468 seconds. Formatting and the pinned dependency checks also passed. Sources and scopes for focused and complete workspace runs are recorded separately in the native receipts. |
| G13 | The installed `dd43ef28` daemon completed all 98,400 documents. All 12,300 batches matched across 3,224,371,200 canonical bytes. The exhaustive integrity stream has SHA-256 `e764a42370a033dfebbfb4326704017e948dfea2111437f032f61fef47de536e`. Verification took 859.863 seconds. The continued run stopped cleanly in 4,953.951 seconds total. Peak sampled daemon RSS was 2,054,782,976 bytes. The run used a 4-GiB logical limit and a 6-GiB serialized snapshot limit on the shared macOS ARM64 host. |
| G12, G14 | The pinned MinIO multi-platform index and both Linux dependency chains were recovered via a mirror. The verified offline archive contains 119,818,240 bytes with SHA-256 `52732c4a667a05fe1948390fff268a40a35c4136267f83ddbe2ca903f88723b3`. The pinned index is `14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e`. Extracted amd64 and arm64 executable digests are in the provider receipt. Both pinned Linux OpenBao archives are staged alongside it. Native Linux execution, all nine voter placements, the 86,400-second HA soak and signed-off release artifacts remain open. [Mirror manifest inventory](https://hub.docker.com/r/jcometki/minio) |

### November 20 native follow-up on document ownership, catalogs and recovery

| Goals | Native result and source |
| --- | --- |
| G02, G03 | On `a6856f52`, all three document GC cases failed. On `5544c672`, shared-chunk retention and bounded inner-slot change-feed traversal passed. Continuous overwrites still grew from 18 to 162 objects, and the reopen fixture presented a live engine's newer receipt ledger to an older snapshot. `ceb89e49` gives a bounded deletion a turn after all newly counted owners are durable. The restart case now shuts down and reopens the original encrypted store before replay. |
| G02, G07 | The original workspace run on `a6856f52` also found two reader-count regressions, excess retained point workspace, and a malformed backup-binding rollback fixture. `08cb27f0` releases the primary lookup allocation with the descriptor and constructs the selected backup head before streaming the fixture. `19d56918` shares the exact selected reader across directory and body reads and checks authorization and cancellation on a point miss before release. |
| G04–G06, G10 | The actual three-runtime pinned-mTLS case passed on `a6856f52` in 403.50 seconds of test execution. The protected route returned six distinct catalog IDs from the three enrolled data voters, one entry per page. Total command duration was 2,526.010 seconds and the log SHA-256 was `9995ccd1cbde0d5fb63a39cd82408e7ba4ea58489e1274011de24f112a812a86`. `8fa3e5c4` and `84e17cb0` add private reports from the actual service-audit and signer stores. The signer report includes unreported independent issuer partitions. These scopes still need distributed coverage. |
| G07–G11 | `200c924a`, `b6e97cf8` and `bc0fbefd` retain authenticated physical cleanup, gate, worker and storage stages. A native encrypted journal reopen passed in 1.879 seconds. The subsequent durable high-water test passed in 1.43 seconds, and a separate Authority and target reopen verified monotonic progress in 17.82 seconds. Those component builds contain the recorded donor patches. The first `5544c672` server rerun failed to compile the unavailable-error assertion. `fc4b4491` corrects its type path. |
| G05, G11 | The earlier full backup-session attempt retained 821 journaled originals. A native process on `55c8a0f5` reopened that installation, reached 880 originals and reported that the backup audit copy was unavailable before proof release. Its public outcome remained uncertain. Total command time was 1,825.806 seconds. The captured diagnostic has SHA-256 `089c2b56fd1932b560970bdd04edc1ab531564aacaba05bb3086faa51adbdb49`. `607debc8` persists each observed cleanup page; `c9a37fde` records the original destination upload and readback failures; `9f6f5f84` can replay the first unacknowledged input separately from the acceptance journal. The 100,001-session gate remains open. |
| G12–G14 | The verified `ceb89e49` interim archive has SHA-256 `6e7bd325d781011a4294ce30701202e0687255f605cf38dc1a9aff83efb172b1`. Native functional checks started on macOS ARM64. Later changes require renewed qualification. The earlier 98,400-document installation cold-reopened and reached protected readiness with its original binaries. Its independent exhaustive read and filesystem backup have separate receipts. |

### November 20 cold backup and native process results

| Goals | Source-bound result |
| --- | --- |
| G01, G12 | The common provisional source is `820ebd907ffa5d6d6512ba75eecb88f2a924ece1`, tree `81279a1b48fa823f3ee8fcc45e02db78bd264f40`. Its verified 2,350-file export is 71,075,840 bytes with SHA-256 `cc79252a830c0d5be432e9fb07be9d184a7e4bf43441071c1e0cab45e8f5cebc`. The later reader, diagnostic, process-test and cold-validation changes require another freeze before release. |
| G02, G03 | All three native document GC tests passed on `ceb89e49` in 127.19 seconds, including actual cold reopen and bounded churn. On `c9a37fde` the point-deadline case, all ten point-memory cases and backup binding rollback passed. Snapshot scans still opened two readers. `337a254b` carries the original selected reader from the physical ID scan through body decoding and response release. |
| G04–G06 | The target-journal inventory on `820ebd90` passed its physical reopen test for current intents and generations in 2.26 seconds. It retains each unresolved checkpoint separately. A dedicated data process still needs a source-authorized backup binding to remote Control. Independent key owners require their own coverage before retirement. |
| G07–G09 | On `820ebd90` the persisted Authority stop survived missing and prepared generations and a cold reopen after drain in 12.13 seconds. On the separate physical-process build, three real Authority members elected a successor after the active issuer was killed during its grace interval. The original member reopened its encrypted files and retained its original issuing identity and interval. The first successful run took 21.829 seconds and peaked at 68,272,128 bytes child RSS. The same executable and the checked-in driver ran again in 27.334 seconds, with report SHA-256 `3c7b9c23370d8b4102b4c26ba85e226ffe7b4021e3f5b15a84c5b4be4035f4d1`. The failed first attempt and both successful reports remain in the evidence index. The driver and fixture were incorporated in `a9c68ff7`. |
| G10, G11 | The HA rehearsal's full 14-case adapter run passed in 542.239 seconds on the corrected process-state observer. The original lost partition-operation observation remains recorded. For the 100,001-session gate, the physically reopened 880-row journal on `9f6f5f84` had the same SHA-256 before and after retry. The next original session retained its intent and twelve object files. Its root manifest was absent, so replay correctly returned an unknown outcome. Its drain completed. A fresh full-size cohort has its own installation and journal. |
| G12 | On `820ebd90`, formatting passed in 3.921 seconds, Python discovery passed 517 tests in 858.888 seconds, and strict locked workspace Clippy passed in 178.108 seconds. The reviewed dependency-patch, LRU, serde-json, MCP and OpenRaft gates each exited zero. The refreshed advisory database was `074ea9a7ed619f511b5b7374c7a97e98d1e98be4`. Scanning all 483 packages found zero vulnerabilities and the reviewed LRU advisory. The scanner's two local-index warnings and the public unyanked records for both OpenRaft packages are preserved. |
| G13 | A fresh `dd43ef28` daemon on the original installation read and checked all 98,400 documents and 3,224,371,200 canonical bytes in 1,356.461 seconds. Its SHA-256 matched the warm run exactly. Backup creation took 165.996 seconds and status took 0.287 seconds. Independent verification reached its five-minute deadline at 300.219 seconds. The daemon later exited with retained owners. The entire cold attempt took 3,371.865 seconds. `b02da9dd` preserves the original storage read and shutdown causes. `485a098f` batches scratch identities and validates each feed commit's original item span. The cold verification gate remains open. |
| G14 | All three production binaries built with no default features on native macOS ARM64 in 1,327.187 seconds. SHA-256 values are `cea8d7d4d43c295d273f677d3a16fdfe88e6536fec08124c5a98e02d13228575` for kasumid, `f1789a222b08ba0f26a47650a2873afc10628213d4753880e5760e00ee5eea6f` for kasumictl and `4991a0876ba79d99267ee8bd5ddea247d253f4cbcaf3e481fca40297925b79d7` for kasumi-authority. The binary and process receipts identify this build as `820ebd90` on an Apple M3 Max, 16 logical CPUs and 128 GiB RAM, with two build jobs. Linux packages, independent reproducibility, nine-voter HA and the 24-hour soak remain open. |

### November 20 native ARM64, backup and resource evidence

| Goals | Observation |
| --- | --- |
| G02, G03, G13 | A second cold start of the 98,400-document installation reached protected readiness in 2,034.687 seconds on `820ebd90`. The original backup ID resolved. Verification timed out at 300.577 seconds. The daemon retained owners through its 60-second drain and exited 1. Total elapsed time was 2,397.590 seconds. Receipt SHA-256 was `7c002eef882c01a79b7f568b07a7e5145fd355af235acf1d4040e6f0a2be5154`. Native process samples at 25, 100, 200 and 265 seconds traced the work through encrypted spool writes, structural index commits and semantic identity inserts. A startup sample reached per-document GC registration during Raft replay. `4a9bd384` reads those registration points through a single authenticated reader per batch. `485a098f` passed the 19 native structural, semantic and identity regressions. |
| G05 | The three-voter source-quorum rehearsal cut the original Data leader off from both peers, observed refusal, restored quorum and authenticated the original intent and outcome. It took 35.83 seconds on donor `57db852b`, incorporated in `f78fdbc7`. Receipt SHA-256 was `cd2b1ef49354bb0759b39351b3752d26fa5dfcc65efb2128044cd4c0c6a5e025`. The independent Control writer and the 100,001 terminal sessions still need original evidence. |
| G06 | On `b2ca4049` the stopped original standalone installation enumerated five encrypted recovery tables, observed old and new wrapping versions and refused its stale cursor. The native verification took 11.573 seconds and peaked at 101,335,040 bytes RSS. Report SHA-256 was `6e4e56e49454ba34a13bdb3f958bc333c9b5ee1a3470ed96234131e6f05f79e2`. Independent Authority, service/signer and external checkpoint owners remain relevant to a distributed retirement. |
| G07, G09 | On `fc4b4491` the original cancelled target monitor retained the outer owner and reopened its journal in 1.61 seconds. The three-runtime Initialize recovery physically restarted its owned target in 586.50 seconds. The two native log SHA-256 values were `87171975ccd74598d5d6858c013367f010d8f75de4aae4a28c1b6112c7fe7ccc` and `2ab708f3d4f7d4fe34984f0f8dcc0236236faeab5ff6541c87e874bf2124e7b3`. |
| G10 | The isolated native protected metrics test exhausted request admission before its authenticated audit could commit. Its original log SHA-256 was `c8230d7865b7b0d9a3bc0619a9c2ecf3198a342bc7ab96d447446347fe93026a`. `b519310b` reserves one 4-KiB record for the service-audit writer and holds the charge until the actual write joins. |
| G12 | A separate native Linux aarch64 VZ guest ran Debian kernel 6.12.95, with two CPUs, 16,753,451,008 bytes of visible RAM and a 200-GiB virtual disk. On `820ebd90` live OpenBao 2.6.2 took 5.619 seconds and live MinIO took 4.285 seconds. The combined run with a private process umask took 10.784 seconds. The earlier non-private-file refusal remains in the first receipt. On the source-isolated provider runner MinIO initially returned HTTP 503 on the first signed bucket PUT. `a5ee8785` waits for write-quorum readiness. Both providers passed with fresh restarts on that source. Receipt hashes were `a98add78687fec6180417f2c5959dc5bb3c23be51e83478a87060d5b8739af88` and `6d33fe5500d222654eae06ca43b4a85328b0dcf7a905985aeee6e509ac8589b2`. The VM is on a shared physical host. |
| G12, G14 | Strict all-feature/all-target workspace Clippy passed on `f78fdbc7` in 372.457 seconds. Its format check found one expression in the GC batch reader, corrected in `55314ae0`. Both pinned Debian OCI base manifests, layers and package inventories were verified, including 88 packages per architecture. Base input receipt SHA-256 was `ef4790271978446f7c7652213ddabc43006e778d558aea593eaadaa716ef33e4`. |

### G11 domain disposition

All 19 domains have executable adapters. Their qualifying receipts must bind original observations to the same final source, binaries and declared native hosts. The observations below describe component progress.

| Domain | Available evidence or remaining qualifying observation |
| --- | --- |
| correctness | The adapter selects original native cases for 13 fault and ownership scenarios. The complete final native functional record remains open. |
| installed | Earlier macOS enrollment exercised 16 scenarios. Fresh installations on the final native binaries remain open. |
| providers | Native Linux ARM64 ran OpenBao and MinIO through real provider restarts. Other required native receipts and the final source remain open. |
| ha-faults | Fourteen HA adapter tests passed. The final deployment must still exercise the seven fault scenarios with its original voters and learner. |
| recovery | Three independent Authority processes exercised issuer death and cold reopen. Three Data runtimes exercised owned-target restart. The installed phase-by-fault and deletion matrix remains open. |
| audit-retention | Native permanent histories crossed 100,000 mutation receipts, 100,000 Authority incarnations and 10,000 lifecycle intents. Both tenant archive copies were exercised individually. The session floor, command crossing and complete nine-process observation must be evidenced together. |
| backup-cleanup | Original attempts stopped at 821 and 880 sessions. The missing original manifest and readback failure are retained. The new 100,001-session attempt has passed both earlier stopping points. |
| key-retention | Standalone rotation, retirement, cold readback and stale-cursor refusal passed. Distributed dependencies still require independently observed reports. |
| observability | Six authenticated catalogs across three Data voters and an earlier 129-group protected observation have native receipts. Protected pressure and complete topology observations remain open. |
| concurrency | The adapter verifies original overlapping operations. The final nine-process reads, backup, snapshot and membership run remains open. |
| ha-soak | The contract requires 86,400 measured seconds on the reserved nine-voter deployment, with credential renewal, archival, backup and membership observations. |
| package-smoke | Requires the actual delivered native packages, authenticated native and MCP reads, restart and clean stop. |
| oci-smoke | Both base-image inputs are verified. Requires a real Linux runtime to load each assembled image and exercise the entrypoint before and after restart. |
| systemd-smoke | Requires delivered units to start both services, restart and stop cleanly on native Linux. |
| repeatable-assembly | Requires original independently built artifacts, assembly receipts and physical-host attestation. |
| dependency-review | The locked 483-package scan, patched upstream suites, LRU backport, OpenRaft archive hashes and yank status are recorded. Refresh and bind to final source. |
| capacity-standalone | All 98,400 documents matched after cold reopen. The five-minute backup verification failed twice. Restore, remaining shapes and final limits remain open. |
| capacity-ha | Requires the capacity operations on the reserved HA topology and verified follower replacement. |
| benchmark-matrix | Requires five modes at each of one, 100 and 1,000 tenants, with all prescribed workloads and resource samples. |

### Native component results on November 20

The Linux ARM64 development guest completed all 16 installed lifecycle scenarios
on `820ebd90` in 67.99 seconds across 64 measured process invocations. All
three production binaries loaded on the pinned Bookworm filesystem. The
Authority CLI printed usage and exited 1 for explicit help. Commit `ed252e1b`
implements the successful help path. The installed report SHA-256 is
`be7c0340c440fa8da61f217581428fff0eb5046fc234832757e2af4c67a67042`.

On macOS ARM64 the original protected pressure scrape passed on `b519310b` in
17.00 seconds. The audit writer cancellation and panic cases both retained
their original outcomes through drain and reopen. The three-member Authority
catalog test on `9e9dd130` passed in 13.92 seconds, including a refused
isolated follower, key rotation, cursor expiration and physical reopen.

The third cold verification of the original 98,400-document checkpoint on
`b2ba4ac9` again exceeded the native client deadline, at 300.344 seconds.
The resident stream took 54.857 seconds. The structural index committed 9,289
temporary batches in 170.796 seconds before verification was cancelled.
Commit `bb0146f9` permits 512 compact index rows per transaction under the
existing 4 MiB limit and native per-row admission. The original backup ID is
`3c11afd2-dc88-4f0f-8af3-002580be2809`.

The original full session workload on `820ebd90` stopped after 1,440
acknowledged originals in 4,555.531 seconds. The next original hit the
persistent filesystem floor. The physical destination then contained 23,687
files and 2,893 directories across the installation. The first completed
checkpoint had 3 objects totalling 7,603 bytes. Ordinal 1,439 had 28 objects
totalling 974,570 bytes. The generic fixture reserves 1 MiB per directory and
an additional 1 MiB per regular file. The standing allowances for just one
directory and two terminal files per session already exceed the 200 GiB
installation at the full count.

The session adapter also accepts a prospective workload and filesystem policy.
Run `python3 -B scripts/probe_session_floor_filesystem.py --output <new-directory> --complete-interval 193`
on the witness filesystem. Pass its `session-profile.json` to
`run_audit_retention.py --session-profile` or set `KASUMI_BACKUP_FLOOR_PROFILE`
for the native component. Interval 193 selects a full backup every 193rd
ordinary request and a durably claimed, published and aborted session for the
other requests. Both original in-flight kills, the full 100,001 identities,
the fixed 200 GiB disk ceiling and the three independent ledger reads still
apply. Omitting the interval selects the earlier completion-heavy workload.
The retained plan, original records, observed device, filesystem measurements,
and both shutdown outcomes belong to the evidence for each run. Workload
measurements alone do not qualify a production filesystem policy.

### Dedicated backup binding and physical key catalogs

Commit `53dc2094` incorporated the dedicated Data-to-Control transport from
`28862ab6`. The macOS ARM64 test used six separately opened encrypted stores,
two three-voter Raft groups and two pinned TLS administrative listeners. The
first Control reply was discarded after commit. A retry recovered that
decision, refused a stale nonce and reproduced the original session UUID and
external ciphertext. The test also covered duplicate completion, abortion,
cleanup and revoked authorization. The three selected transport tests passed
in 39.73 seconds and repeated in 37.14 seconds. They used an in-process Raft
router and a fixture Authority lease. The earlier admission refusal and every
retry are indexed in the private donor receipt, SHA-256
`0dab7699da42726021d31538ea489e59e3ea1b3865cef7d6fdf5356f68c2b6ad`.
The 100,001-session disk workload is separate.

The first integrated build failed because the Engine used `async-trait` in an
ordinary library path while declaring it only for tests. Commit `3fa4ab97`
corrected the dependency declaration. Strict all-target, all-feature Clippy
for Server, Engine, Client and Types passed in 618.00 seconds with 2,382,594,048
bytes peak RSS. All 95 Types tests passed on that commit.

The real three-member Authority test on `1767dd0a` followed an enrolled
member through quorum loss, rotation and physical reopen. It passed in 6.27
seconds. Its raw build-and-test log has SHA-256
`d76218e25c57f2a5b4e4b62a9d857829fddc9b0c3ff10a5a0ee28d0aa0e4eee5`.
Commit `6ea1062b` uses a distinct read credential for each installed issuer
partition. Commit `39bfb96c` collects the signer catalog of each current
Control voter and learner over its enrolled cluster connection. It reads
each reported catalog twice, binds it to the requesting term and membership,
and records unreported members in the public coverage result.

The 513-row snapshot change-identity regression on `bb0146f9` requested
143,059,946 bytes for a commit with a 134,217,728-byte scratch group limit.
Commit `8b5e32dc` sizes batches from remaining group capacity and the maximum
copy-on-write page cost of one edit. The original failure log has SHA-256
`dc02781753046bbb7a23dc6a84ba12aa5e32f0566b135e7d591fc6451f594b42`.
On `f3d3cba0`, eight native text-directory tests, the indexed snapshot
reopen and four query shard tests passed.

The second native Linux ARM64 Python run used a container init process.
On `ff387173`, 518 cases finished in 957.592 seconds with one error, one
failure and three skips. Both failures were in the recovery adapter fixture.
The next fixture pins the original daemon PID until its operation completes.
Original Linux outcomes remain part of G11. The macOS ARM64 full workspace
also found a distinct MCP failure on `820ebd90`. An isolated original hit
the source query deadline before the intended tool-result allocation check.
The same binary subsequently passed the full unchanged test in 10.03 seconds.

### Common candidate and later findings, November 20

The common source archive for Linux x86-64, Linux ARM64 and macOS ARM64 is
`99cfb12eebbd949eacfd29b01b24a9c47253690a`. Its SHA-256 is
`f083e9304d52f11ddc20007a16f27b039345b97d34c81434f0f66806e2cae54a`
over 71,403,520 bytes. On macOS ARM64, formatting passed and all 519 Python
cases passed in 864.799 seconds. The Python log has SHA-256
`77a4a1247220d459e70dc04f5b539dd6f5b566907c4934ec54e998d79a786724`.
The 483-package projected lockfile was also scanned against 1,550 advisories
from observed upstream RustSec commit `074ea9a7ed619f511b5b7374c7a97e98d1e98be4`.
The scan reported zero vulnerabilities and the previously reviewed LRU warning.
Its receipt SHA-256 is
`7f305128cbfb9648cdd119c48797632e57ec5fea887ed83b96f2471db3cfc1de`.

The earlier `820ebd90` macOS workspace completed in 10,130.296 seconds
with exit 101. Engine had 791 passes, one failure and seven ignores. Server
had 536 passes, five failures and one ignore. On Linux ARM64, ten of eleven
upstream dependency commands passed on `1747dbde`. The first OpenRaft
integration command could not mount its log directory. Repeating with a
writable copy of the test directory reached the real tests. Two client cases
failed concurrently. Both passed individually with the original binary and
crate working directory. A serial suite run still failed while a 200-ms
assertion waited for leader election. The original process receipts and
test-directory comparisons remain in the release evidence.

The previous 98,400-document backup took 2,112.289 seconds to reopen on
`bb0146f9`. Verification timed out at 300.522 seconds and shutdown also
exceeded its deadline. The verifier recorded 49,156 document offsets over
132.280 seconds. Commit `d097c4f2` packs document locations into bounded
encrypted pages. All seven structural index cases and the separate 513-change
identity test passed on `99cfb12e`. Qualification still requires the full
original checkpoint within the installed deadline.

Linux Btrfs allocated 4,096 bytes of directory metadata during the first
fsync of a freshly created private directory. The old Store rejected that
change despite its prepaid allowance. `68e382d4` settles the observed child
and parent together. A native create and shutdown then passed. A separate
100,009-entry filesystem calibration measured 102,400 bytes after sync.
`95b3bbb0` measures both sides of the synchronization and produced a
204,800-byte directory allowance on this device. The calibration and the
100,001-session workload have separate receipts.

A native Authority catalog test on `1747dbde` incorrectly expected a fourth,
pre-enrolled identity in a three-member committed roster. Its original log
has SHA-256 `ffeeeb23299e948a5af91feec9e578b130ae3a75d14f4119bf614f151ae00774`.
`b6e093ae` compares the returned members and membership digest with the
committed bootstrap. The fourth identity remains explicitly covered by the
assertions. `f51cfe88` covers materialization, physical-directory and
publication records in the standalone recovery inventory. `1bb3af71`
includes the journaled archive objects, their declared wrapping versions and
the physical ciphertext and inode checks. The external backup graph and
independent generation inventory still require separate evidence.

## November 20 native evidence through 07:49 UTC

The common qualification export remains `99cfb12e`. On macOS ARM64 its three
fixture-free binaries built in 2,926.249 seconds. SHA-256 digests for
`kasumid`, `kasumictl` and `kasumi-authority` respectively were
`ced4f7b7e9ad01c871ca7e1f2b369123126d9a194f24bab24003461b7b5ceef6`,
`9b298600809c0e3c9eb6e01f880a2acef209cb323f57245988125766b9636dd9` and
`12459dfe346b8c5cf7db31869713d1e1c0affcccf693ca28ff18a0bf2e9ccaff`.
The installed macOS lifecycle exercised 16 scenarios and 64 processes in
115.945 seconds. The three-Authority deletion test killed the issuer during
grace, finished on its successor and reopened the first member's physical
store in 24.180 seconds. Native development Linux ARM64 clients on the same
source passed OpenBao in 52.741 seconds and MinIO in 16.907 seconds. Each
provider restarted during its run. The provider receipt SHA-256 is
`b723bf69968676812875444f918d9323ca35285f699c3d4400a3cf732413818c`.

Four unoptimized macOS three-node component tests overflowed the default test
thread stack during their first backup. The four original failures, crash
reports and native function frame sizes are recorded with the test binary.
With the debug server's 64 MiB stack, the same binary passed the owned-target
restart in 567.677 seconds and the unavailable-original-node case in 573.509
seconds. The regular workspace uses its declared test profile and has a
separate result. The cancelled administrative drain and protected metrics
tests also passed on this component binary.

The explicit recovery publication owner in `7a7db191` and the authenticated
versions for individual target journal rows in `db5684a1` passed the
all-features Engine and Server compilation check including tests in 909.24
seconds. Two earlier test builds lost their shared Cargo directory before
execution. The source export, failures and repeats use separate receipts.
`fe81c6b8` reads Control members' audit catalogs and archives. `e893c49c`
does the same for each enrolled Authority using its own partition credential.
Both bind each response to the member and the physical stream. The protected
peer report's Raft wire regression passed on `fe81c6b8`. Complete Data,
external checkpoint and generation coverage remain open.

On Btrfs the 102 terminal files produced by 51 original sessions each pinned
a distinct 2,166,784-byte extent after publication. The inode block counts
alone underreported that allocation. `abda500e` clears only stale tail
chunks before synchronizing and publishing the same inode. After two forced
process exits a third process reopened six original ciphertexts. The six
distinct retained extents each measured 4,096 bytes. The physical receipt
SHA-256 is `5fde790bdece374f8819d430d9149949e926b8567e7b70e4ede5810ca030684d`.
In the regular macOS Store suite eight session admission cases passed and one
failed on the pre-publication allocation check. A direct APFS experiment
measured 2,166,784 bytes after a 12,377-byte prefix write and 4,096 bytes
after publication-sized truncation. `98d9bbdc` measures the successful writes
issued by Kasumi and the published allocation separately. The 100,001-session
cold-replay floor still needs its own complete process receipts.

`af2152c9` restricts host receipt collection for OCI probing to the seven
required inputs and records separate copies for each generation. All nine
adapter tests passed on both ARM64 platforms. The first real Linux Docker
run then failed during initialization because the policies inherited
world-readable permissions. `327798c3` creates them with owner-only access.
The matching native development Docker rerun passed 33 steps in 76.795
seconds, including authenticated native and MCP requests before and after
restart, exit and cleanup. It used the `820ebd90` binaries, Debian ARM64
manifest `6bd27d44e6c32a66bbd72d7cb2b76a8ae3497ec2e5274a81abd1b37f6013fa1f`
and image `1946c8842f0bac6e4cb5e064e9358b3528af7e253328392433ab51f8f2fa071f`
on two virtual CPUs with 16,360,792 KiB guest memory. The receipt SHA-256
is `5a0efcd5c628926d9b6cc34519c05eec96793a0ecef0d31c9d544a3d6f840fcb`.
Packaged smoke and independently built release artifacts remain outstanding.

## November 20 native results through 08:32 UTC

The common provisional source for macOS ARM64, Linux ARM64 and Linux x86-64
is `04cd8265e5aa9d942343731e418509ae6d198fd3`. Its 2,367-file archive
contains 71,516,160 bytes and has SHA-256
`30062b56e3108573dda32d2c8891e61d12799480c746df8d38bdac910b0d03f3`.
Its native macOS RustSec scan checked 483 packages against 1,550 advisories
at upstream `074ea9a7ed619f511b5b7374c7a97e98d1e98be4`. It reported zero
known vulnerabilities and the reviewed LRU informational advisory. The scan
receipt SHA-256 is `6710bbd83f025bc65ff36e8b79faeaa5335dec70831d4eb851d77401aedd2caa`.

| Goals | Native development result | Outstanding qualification |
| --- | --- | --- |
| G01, G07 | The five installed deployed-format cases passed in 139.32 s on `99cfb12e`. Cancelled shutdown retained the original target monitor until its journal reopened in 1.71 s. All four original three-node debug regressions passed with the server debug stack size in 567.677, 573.509, 479.450 and 126.936 s. The original stack overflows are retained. | Repeat under the packaged candidate and installed topology. |
| G02, G03, G13 | On the 16-core, 128 GiB macOS ARM64 host the original 98,400-document database reopened in 3,123.568 s. Its 3,224,371,200-byte corpus produced the original checkpoint, which passed cold verification in 229.911 s under the 300 s limit. Shutdown drained cleanly. Receipt SHA-256 `fe165b95ed9efdd7dcb9e35188d58847667e19e4061f66e8700c4866e01855cb`. | Validate fresh filesystem and S3 restores, all prescribed workloads and the full-duration soak on the final source. |
| G02, G07, G13 | A separately initialized target read 410 byte-identical encrypted session objects totaling 3,397,487,022 bytes. The original 600 s deadline elapsed during genesis decode at 600.004 s. Its worker remained alive. In a native sample, 150 of 160 observations showed document scratch batch commits. Sample SHA-256 `60eaa5cfb572e9b1dc6ab27fc2cef383544c45841a7089c3be05d2b4bc870aad`. | `3f1b50cf` stages objects directly under their authorized target incarnation and checks the original deadline during decode and genesis writes. `82b5f6b0` compares pending duplicates in the native transaction and batches up to its physical limits. Rerun the original restore and compare every document. |
| G05 | Native macOS passed all nine session-admission tests in 1.78 s on `98d9bbdc`. The Linux ARM64 sparse-terminal suite passed 29 cases in 2.13 s on the repair donor. The suite archive SHA-256 is `fe31db6fd949187ef9260b021abad7df66cc1ccd690794f501a0c1e4e97b299b`. A protected cold read of the failed first population confirmed its collection creation had committed despite returning UnknownOutcome. A separate native process crossed 276 original sessions. | Reach 100,001 completed or aborted originals, perform the prescribed kills and authenticate every original outcome and checkpoint. |
| G06 | `f012ddf3` binds both active standalone recovery catalogs to the installed physical generation. Strict native workspace Clippy passed in 999.847 s. `04cd8265` binds remote backup key inventory to the dedicated Data and Control quorums. Its donor passed the six-voter regression in 18.51 s. | Verify historical recovery records, independent Data service catalogs, external checkpoint dependencies and the complete retirement lifecycle. |
| G11, G12 | The stock macOS workspace on `99cfb12e` reproduced the stale four-member Authority assertion. On its original binary, the legacy replica-budget check differed by exactly 4,096 bytes and the real standalone backup/reopen case failed during snapshot location-page allocation. The native backtrace SHA-256 is `528fee547f1d82fd837db0d90d1cfeefa1da6b9ce3a15281e7250530196c229f`. | `5994f82e` compares the legacy floor with its historical audit obligations. `0271bbe2` charges the temporary index page as structural work. Native regressions and the full combined suites remain open. |

G01–G14 remain open. Native Linux x86-64, the prescribed ARM64 reference
placement, nine-voter HA placements, independent builders and publication
authorization still require owners. The 86,400-second HA soak awaits the
installed topology. The deployed fixture is already on origin/master.

### November 20 local backup and native acceptance follow-up

| Gate | Observation | Remaining qualification |
| --- | --- | --- |
| G02, G03 | On `5ec151ae` the shared-chunk, interrupted collection and storage plateau regressions passed in 124.74 seconds. Authenticated feed resumption also passed. | Run the configured physical capacity cases on the release hosts. |
| G05 | Native Linux ARM64 retained 1,024 distinct original sessions, including 6 completions and 1,018 aborts. Each of the 2,048 intent and terminal files occupied one 4,096-byte Btrfs extent, totaling 8,388,608 bytes. Archive SHA-256 `8ffc60b302917e6613d08c317060fa253a1bcc535410dd8f1634a666fba2fc2a`. The unsuccessful ten-second collection create cold-reopened as committed under its original owner. All 29 Store cases passed in 2.13 seconds on the native guest. | Reach the agreed 100,001 distinct sessions and complete cold replay of all original records and checkpoints. |
| G06 | `246614a0` incorporates the six-voter credential and historical recovery regression. Its original binary authenticated two historical recovery records under a signed, expiring credential. It reported incomplete coverage for the wrong source purpose and the missing manifest. Test duration was 64.44 seconds. Binary SHA-256 `2a5aef37baeaf40e2b5f4fdeeb06b1ac6439c673858435e07c96be0192da8c6e`. The three standalone recovery and inventory cases passed on `f012ddf3`. | `a95ce30c` includes verification of external standalone checkpoints, their session catalogs and the enrolled historical providers. The added native case withholds and restores the original manifest. Native verification, independent Data identities and materialized target coverage remain open. |
| G07, G12 | The stock `99cfb12e` Engine suite finished with 796 passed, two failed and seven ignored in 1,711.57 seconds. Three of 13 backup checkpoint integration cases failed. All three reproduced on the original binary. Two backtraces reached `LocationPage::new`. Strict workspace Clippy passed on `04cd8265` in 649.329 seconds and on `3f1b50cf` in 591.336 seconds. | Run the checkpoint cases under their original resource limits on the corrected source. The workspace process survived the desktop restart. Its final process status is being collected independently. |
| G13, G14 | The fixture-free macOS ARM64 `f012ddf3` production build passed in 2,302.028 seconds. Daemon SHA-256 `523003b355e2d74ef5c20c53f58880a8c26b2542a2a0f0672b2ce6d438f2f4fe`. Native Linux MinIO accepted a signed bucket create from the macOS host. Two corpus attempts stopped during macOS credential renewal while its tenant replayed. | Complete the corpus backup and restore against the real provider, verify the original documents and run the HA soak. |

### November 20 native qualification through 09:41 UTC

The common provisional source is `fdc32a1aef7cc6e9d940df85744333ed9dc7c194`.
Its archive SHA-256 is `de7e04731a050a3c9c997dd911bb1b077f1be662505c01a15901b19949963437`.
Its macOS formatting check passed, Python discovery ran 509 tests with two skips,
and the 483-package dependency scan reported zero known vulnerabilities. The
advisory receipt SHA-256 is `40cc40c14c928d1731eac8bd5c4dadd198c871f30c542e642c7cbea111ab4e6d`.

| Gate | Original observation and correction | Outstanding evidence |
| --- | --- | --- |
| G02, G07, G12 | All 13 backup checkpoint integration tests passed on `0271bbe2` in 96.04 seconds. A separate restore test caught the loss of its typed deadline inside an I/O error. On `b1483d92` the same test passed in 5.89 seconds, verified scratch release, and completed target installation. Log SHA-256 `c42170483609098e299bb441b3bd12227541db44a05e46a88954fc7aff2f2919`. | Qualify full cold restore and shutdown on the release systems. |
| G02, G04 | On the `99cfb12e` executable six of 12 runs of the concurrent strict-read test failed. The original allocation backtrace reached primary descriptor decode. The `ffe3945f` repair on the original dependency build passed 48 consecutive native runs. Strict workspace Clippy on `ffe3945f` passed in 557 seconds. | Exercise sustained contention in the full workspace, capacity and HA suites. |
| G05, G11 | A separate Linux ARM64 reader verified 4,096 encrypted intent and terminal files from 2,048 original sessions. It matched 2,037 aborts to their original intent ciphertexts and 11 checkpoints to their root manifests. Archive SHA-256 `08371981f2c5be2186a27be27d91a792a03d76378da0bc124434426d789b4a3b`. `3e438c5e` verifies the requested operation at interruption and compares the durable outcome at replay. The 16-session fixture survived three SIGKILLs and replayed on both ARM64 systems. | Complete the 100,001-session workload and independent cold replay. |
| G06 | `fdc32a1a` binds a standalone recovery inventory cursor to its authenticated permanent intent, terminal and checkpoint. `3118d66a` also verifies the historical backup of a serving materialized target against its journal and physical directory. | The active target change is on a later source and awaits native qualification. Inactive materializations and distributed report coverage remain open. |
| G12, G13 | On `f012ddf3`, the macOS ARM64 daemon wrote the 98,400-document corpus to native Linux ARM64 MinIO. Permanent session `5a83ed39-8321-4c96-9c48-baf1dc6e2cbe` returned the same checkpoint on status and verification. The daemon drained and MinIO exited successfully. Receipt SHA-256 `f07b2278049c74faac840aee5a1d06da43e98fe0602cc1f401df06ec72ef5964`. | Restore the same session on an independently initialized target and read back all original documents. |
