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

### November 20 native results through 10:15 UTC

| Gates | Source and observed result | Outstanding work |
| --- | --- | --- |
| G06, G07 | On `874854f8` the three-node protected Prepare test passed in 19.77 s and reached the original Data and Authority credential checks. The active target test passed in 39.88 s, including removal and replacement of the original backup manifest. Active target receipt SHA-256 `49dfe2ba9483f8b82939f50b2cbb4939eb1319d21ca184fc82d7ca0834e5efb8`. The earlier `0c888535` protected test failed at no-clobber credential replacement after its Data checks. | Verify coverage of inactive stores and the independent distributed Data report. |
| G02, G03, G07, G13 | Two fresh `82b5f6b0` targets verified the original 410 ciphertexts and entered snapshot decode. Both expired at their 600 s internal deadline and recorded the worker failure before process exit. The second verified the graph in 221.91 s and ended its decode worker 1.9 s after the caller deadline. The sample showed native segment encryption, writes and file extension. Second restore receipt SHA-256 `5fcf23b214977b097cdb7c3e4f3e40f762194865dc75c5697a97108bb91d4566`. | Repeat the filesystem and S3 restorations with target document readback. |
| G02, G03 | `b39ef12c` transfers a segment’s separately prepaid extent to its original encrypted spool. `0a6de038` groups consecutive encrypted slots into one write while preserving each slot’s offset authentication. The native Store run passed 12 transaction-claim cases, five spool cases and 41 scratch-table cases, including the 20-to-seven write comparison and rejection of a transplanted slot. The test linked the original `99cfb12e` external dependencies. Receipt SHA-256 `f2349d3803901b70bf59b2a3b22271d34cfde1daa332a50ecbef3444e5683805`. | Verify the complete fresh restore within the original limits and the final locked workspace. |
| G03, G05, G07 | `1447c9a4` passes the original cancellation token through target generation preparation. The strict build found the earlier unchecked helper had only test callers. `1c3aebb4` compiles it with those callers. `af11fbb0` includes the separate mutation, backup, target and lifecycle prefixes when reserving a public snapshot. | Run the before-and-after receipt regression, final strict Clippy and snapshot suites. |
| G11, G12, G14 | The original `99cfb12e` macOS workspace exited 101. Across 84 summaries it ran 4,047 passing and eight failing tests with 26 ignored. Raw log SHA-256 `5069f8bf63ea1787d8044bdb8be91e78cc24f15bec59f60cbd33848ad501521d`. The common provisional `fdc32a1a` passed strict workspace Clippy in 634.6 s, and `3118d66a` passed in 726.8 s. At 10:08 UTC origin/master still identified `65695b77` and contained the 28,798,481-byte deployed fixture. | Finish qualification on one source, reserve the Linux reference hosts and HA placements, and run the 24-hour soak. |

### November 20 qualification through 10:49 UTC

The common candidate is `b3fcdf1a6715970003644b7e2c15b403504a50e7`. Its 71,680,000-byte, 2,375-file source archive has SHA-256 `551ff5f05b9fd7a267ed36ae140e49e451498c7dca505f4b3a31174da4e4e553`. The lockfile digest is `f04d0527f8debea0e02e2f93ea959e349ab574adac64d10f1531b89a91c6a362`. Native macOS ARM64 and development Linux ARM64 checks are in progress. The Linux x86-64 reservation, dedicated ARM64 reservation, voter and learner placements, and independent build host remain outstanding.

| Gates | Source and evidence | Work outstanding |
| --- | --- | --- |
| G02, G03, G07 | With the original native dependency set, a public snapshot with eight groups of permanent receipts ran out of storage on the earlier source. The same test passed on `af11fbb0`; its receipt SHA-256 is `40a93584faceb2c2e3443527527cd6ad3de916bad8c7e463da88172ac76872c0`. On `15a8bed2`, all 12 transaction-claim, five encrypted-slot and 42 scratch-table cases passed. The new writer test distinguishes pending and committed content collisions. | Final workspace, physical capacity matrix and bounded restore. |
| G03, G13 | On `033d5ba1`, seven authenticated framing tests, target rekey and restore cancellation passed on macOS ARM64. Receipt SHA-256 `4e846e77409340a02cbc1a7316bd8f5ebebeaa8db32689b4642bf90f55e591ae`. This test linked the earlier Store implementation to isolate framing. | Complete both whole-corpus restorations and compare the original row digests. |
| G05, G11 | The development ARM64 session population produced 10,044 ledger lines by 10:49 UTC. The independently read physical checkpoint remains 2,048 distinct sessions, 4,096 encrypted files, 11 completed and 2,037 aborted. | Reach 100,001 distinct sessions, then verify the final physical records and perform cold replay. |
| G04, G06, G09, G10 | The five private Data reader commits from `e6be2baa` through `12255f77` are ancestors of the common candidate. Its reconciliation with `033d5ba1` reproduces the private patch digest `517e0fe370deb54fd0193a4ac7c2bc240f1fc9cbd85b279ea4eecbc5e10a6041`. The `b90fcdc5` stopped-generation test on an older linked dependency cohort reached a real Corruption outcome after withholding an original backup manifest, before its new directory-reappearance assertion. | Verify that failure and the corrected tree, complete remote journal coverage, and fence distributed dependency writers before retirement. |
| G08, G11, G12 | `b3fcdf1a` passed formatting in 29.3 s. Its refreshed RustSec scan found zero known vulnerabilities across 483 packages and 1,550 advisories. The reviewed LRU advisory remains visible. The scan receipt SHA-256 is `fecb312250c9b0efaa9a342742cf7cafd3e3af7fa66531b427a19012327cebfb`. | Finish the locked focused and full native suites, live providers and 19 qualifying domains on this source. |
| G05, G07, G12, G13 | A fresh `0c888535` installation retrieved the original MinIO session and completed authorized graph loading in 374.622 s. The 600.010 s deadline elapsed in snapshot decode. Its worker ended 1.024 s later, the drain recorded the failure and both original MinIO and the SSH tunnel exited zero. Restore receipt SHA-256 `039684c122365e7d7c302824535b4aaa8271dba8ac678a88611813f71fa05a47`. | Both fresh-target tests are queued on `b3fcdf1a` with the original 600-second bound and full 98,400-document readback. |
| G12, G14 | Development Linux ARM64 built fixture-free `fdc32a1a` and exercised binary help. Its daemon SHA-256 was `738ca91f33e38f7b12948f1ba19a3443ab10f323d4dec223d24b5e58cbdd4289`. Native macOS ARM64 built fixture-free `0c888535` in 3,483.678 s. Its daemon SHA-256 was `03a9d130e520c691e7816bd739f3ba92ee4fe91addc86a96357bc99f77872de3`. | Freeze all deliverables from one qualified source, compare independent builds, and run the required nine-process faults and 86,400-second soak. |

G01 continues to cover read, write and cold reopen for both installed formats. The fixture is already on the observed remote. A format retirement would require the format owner's decision. The BOI environment owner controls its live installation.

### November 20 qualification through 11:34 UTC

The common candidate is `d2654b68e07ff691843aac7cf7503d2446247f90`, tree `b29d88e7098226bc9e280c5f593557084c4f1080`. Its 2,378-file source archive is 71,782,400 bytes, SHA-256 `1f5477f80a1f18ae99715af3d252aa4acbd01f7a7b6f3b02d244e3e9f6ab81d4`. The unchanged lockfile SHA-256 is `f04d0527f8debea0e02e2f93ea959e349ab574adac64d10f1531b89a91c6a362`. Full macOS and Linux ARM64 development runs retain their queue and source identities. Release remains on hold.

| Gates | Observed result | Outstanding qualification |
| --- | --- | --- |
| G02, G07 | On native ARM64 Linux, the original `99cfb12e` Store binary independently reproduced all three reported filesystem failures. The corresponding Authority binary reproduced the missing-target error. `6a439fca` retains the original close error through an eviction retry and checks the same storage fence at either filesystem detection point. | Run all four cases against the immutable candidate. The focused Linux container has one CPU, 6 GiB RAM and a read-only original build cache. |
| G04, G06, G09 | The original local recovery test moved an enrolled manifest outside its disk owner, which also fenced its journal. On `7e8bf4aa` the test moved that inode through its owner, verified actual absence and return, and passed in 6.784 s on macOS ARM64 with the original dependency build. `a9b1fe22` adds authenticated physical journal inventory across enrolled Control and Data members. | Complete the combined native journal tests and prove independent writer fencing before distributed key retirement. |
| G05, G11 | The original Linux Btrfs ledger reached 13,307 rows. An independent 13.374 s read matched 8,192 distinct sessions to 16,384 encrypted physical records, covering 43 completions and 8,149 aborts across 67,108,864 allocated bytes. The evidence archive SHA-256 is `e4c3fae47da65adbb118de75095816135b2e57debb637e6af37114951cc0109a`. | Complete all 100,001 originals and cold replay. |
| G08, G10, G11, G12 | `ddb232ff` admits a separately enrolled learner in the installed transport roster. `ca38e0a2` binds learner activation to a fresh remote Control route. `481c8306` publishes Data voter replacement through dedicated Control after two enrolled original Data voters attest the stable membership. The 61 HA and capacity adapter tests passed on macOS in 42.481 s. | Run the physical voter replacement on the combined binaries, observe an actual network partition and complete the fault matrix. |
| G11, G12 | The complete older Linux workspace runs exited 101. `99cfb12e` recorded 4,043 passes, 13 failures and 26 ignored in 11,417.671 s, log SHA-256 `edc315751c16a8334768a37935115c73ac5c691b2f1534262b96d17e0b349699`. `ff387173` recorded 4,041 passes, ten failures and 26 ignored in 19,801.406 s, log SHA-256 `5425bd57ac91119c35b341e8a3c1b891d04157f7cba26c42817c3d01d6f24406`. The post-freeze test changes in `50f72820` wait for the final published audit index and collect the transfer child's exit when it closes stdin early. | Native before-and-after and complete release-source checks retain independent results. |
| G03, G07, G13 | Both 98,400-document restore jobs are bound to the fixture-free candidate products and original checkpoints. Earlier filesystem and MinIO runs exceeded the original 600 s operation deadline. | Observe full fresh-target restore, drain and exhaustive readback on both backends, then run the required capacity matrix and 86,400-second HA soak. |
| G12, G14 | The common candidate passed macOS formatting in 14.772 s. RustSec database `074ea9a7` reported zero vulnerabilities and the reviewed LRU informational advisory. The earlier Linux ARM64 `b3fcdf1a` fixture-free build produced all three binaries and passed their help checks. Its daemon SHA-256 is `4d37833b20a4cc96b63d632ebc15692aa63d597cc529bbfc8cfa2f2b6fff3104`. | Complete release-source build, provider and artifact comparisons on all three native systems. |

The release owner supplies native Linux x86-64 access, reserves the ARM64 reference, and attests the three-by-three voter placement, learner, physical failure domains and independent builder. The release owner authorizes publication after qualification. The deployed fixture is already on the observed remote. Both installed formats remain covered. BOI's live installation belongs to its environment owner.

### November 20 native qualification through 12:00 UTC

| Gates | Observed result | Remaining check |
| --- | --- | --- |
| G02, G07 | All three previously failing Store cases passed on the frozen `d2654b68` source under native Linux ARM64 Cargo with a one-CPU, 6-GiB container limit. The earlier Store and Authority failures are retained individually. | Finish the Authority case and repeat full workspace qualification. |
| G04, G11 | The old Linux audit test reproduced its 51-versus-50 applied-revision race. All eight repetitions of the `50f72820` correction passed on the original dependencies. The original stream-transfer suite reproduced the broken-pipe race. All three corrected transfer tests passed in eight repetitions with the original installed client. The receipts have SHA-256 `fe9288aa310c8e6329747180d10449b0734d619f63ce581a34b4a0a06948312b` and `98d58a866a0aca98dbbb41200912b053d0cd0f8a1bdc895f69ebe62df49db6af`. | Include both corrections in the final frozen workspace. |
| G08, G11, G12 | `959333d0` and `331a8198` cut live traffic to and from the selected Data leader and require the healed member to apply the majority's receipted write. On Linux, three original TCP client processes exercised both existing and new connections. All 28 adapter and socket cases passed in 26.268 s. Raw log SHA-256 `800358bec12a56f16f35a9db1354075b439ac225b31deef3d8e6d0c5aa0f0903`. | Exercise the cut on the reserved nine-voter Kasumi installation and verify the protected status, majority receipt and recovery evidence. |
| G03, G05, G13 | The development Linux guest independently copied the original MinIO checkpoint's 829 cold objects and compared each file with its original SHA-256. The objects total 3,393,449,671 bytes. Inventory SHA-256 `9917056e2ec8f79e6da4ca243768b10e484db574c4624767d608aa79392d3ce4`. The original Btrfs session ledger reached 14,713 rows. | Finish the 600-second fresh-target restore, cold status and 98,400-row exhaustive readback. Complete the separate 100,001-session run and cold replay. |
| G11, G12, G14 | On `d2654b68`, macOS discovered 510 Python cases, skipped two and exited zero in 506.683 s wall time. Receipt SHA-256 `9b3703f1f07fc3b05042715fa55f641e9a489c2846d458e0ecd864aa078c96a4`. On `fdc32a1a`, the macOS ARM64 fixture-free build produced all three binaries in 4,783.482 s. Its 131,115,536-byte daemon has SHA-256 `3d730de961752d99b7782487c5dd8cebdb99ebc62b62aa237e71a3fa57eb861e`. | Run the common products, live providers, installed lifecycle, platform artifacts and independent build comparison on the final source. |

### November 20 original MinIO restore and native products

| Gates | Source and result | Open acceptance work |
| --- | --- | --- |
| G01, G02 | The KV fixture suite passed four cases and skipped its fixture generator. Store passed all four deployed-format cases on native Linux ARM64 at `d2654b68`. The four previously failing physical Store and Authority cases also passed. Physical receipt SHA-256 `34f29a2a97645ce6e6f86c05fb1f7d02a8bb168d58b7a92a14ab4bb2d2804d5e`. | Complete installed compatibility and the physical capacity workloads on the final products. |
| G02, G03, G13 | On the 2-CPU Debian ARM64 development guest, the restored copy of the original MinIO checkpoint contained 829 verified objects totaling 3,393,449,671 bytes. Graph verification took 288.857 s, target snapshot decode 270.003 s and rebind 0.016 s. Generation preparation ran for 41.506 s before the owned worker stopped. The original application deadline expired after 600.000 s. A separate cold process returned the persisted phase `materialize` with `Unavailable: backup verification deadline expired`. Receipt SHA-256 `914424938d822dcd08844f085a31df1b6d3badd63a2c0677a797d248786c3abd`, timing log `a720d6d2bf55082b6c27f67af5a0faf73e6c91d62c088db82b61635847a494b6`. | Finish restoration and exhaustively verify all 98,400 original documents on both destinations within the accepted limits. |
| G02, G03, G07 | `786b4fc4` bounds the resident reopened document name index. In the native Store probe, 132,097 inputs left retained digest vectors at 6,291,456 bytes. The prior implementation grew to 12,582,912 bytes. The new index spilled 1,025 encrypted markers and excluded them from publication. Receipt SHA-256 `8fe97470568600cce470c9ec112645660f434a33e09ba8cf94b6f70d0ca62a61`. `3686e9be`, `5ad244bc` and `64d8ddb5` bind credential and inspector work to the bounded native worker registry, preserve I/O failures and protect encoded credential replies. | Repeat interruption, cold install and full runtime drains on the final source. |
| G05, G06, G08, G10 | `0820e2ad` persists signed backup writer fences. `46175daa` authenticates the original ciphertext graph before admission under the writer journal. On `a9b1fe22`, the dedicated Control inventory, active-target loss and restart, and issuer-substitution and restart tests passed in 104.92 s, 156.68 s and 45.67 s. Receipt SHA-256 `9311efce0397fdd9c00eb035cd2a7bc5acf049c862bdb0d0e64531542fdbe0e6`. | Complete physical coverage of the enrolled writers and full original-session and historical-key runs. |
| G09, G11, G12, G14 | Three fixture-free Linux ARM64 binaries built from `d2654b68` in 2,801.868 s with peak child RSS of 7,145,768 KiB. The daemon SHA-256 is `1ab1162db168ca7b4c87017625a5aca6e7bdcf8b9893df2aef44dc42fc56f19b`. OpenBao passed in 7.923 s and MinIO in 9.407 s. All 16 installed lifecycle scenarios passed. Rootless image `sha256:da2299541395fa21d42a326490417a6220689cb37bb83f6f6db8784edd30c091` served authenticated native and MCP requests before and after restart. The original image probe failed with exit 126 for each private mode-0500 build copy. All three byte-identical mode-0755 delivery copies then ran in the pinned base image. | Qualify all 19 acceptance domains, complete the three native platforms and assemble and compare the final artifacts from one commit. |

### November 20 native integration through 13:00 UTC

| Gates | Observed result | Outstanding work |
| --- | --- | --- |
| G01, G11, G12 | The common native pin `1c419e0acc99d48135977efd338c4863dd9e3ff1` has 2,381 files and a 71,915,520-byte archive, SHA-256 `11c5a14e4b220b843751e6bb899469e9f1392657af1596b249df64ec0148276b`. macOS workspace Clippy passed all targets and features with warnings denied in 596.97 s. Python discovered 512 cases and skipped three in 606.16 s wall time. Formatting failed on one wrapped reducer call. `e42a3e4d` corrects it. | Recheck formatting and the full workspace on the source selected for delivery. |
| G02, G03 | `1279f68a` combines schema validation and structured index construction in one document loan. Its native query suite passed 107 with two ignored. `81617fa9` replays the immutable, previously validated restore image under its measured record bounds and rechecks its full SHA-256. `11c61ebd` builds primary IDs while staging live bodies in collections without secondary indexes. The native query suite on that source passed 108 with two ignored. Receipt SHA-256 `4be38511bc4905e8c34f568c4c30892dfe2cc282c4b14f8d909979921ae8aa58`. | Repeat the real 98,400-document restore and exhaustive readback. |
| G05 | The original Linux Btrfs ledger independently verified 16,384 original session IDs, 85 completion manifests, 16,299 abort-intent digests and 32,768 terminal ciphertext files in 23.481 s. The files occupy 134,217,728 allocated bytes. Archive SHA-256 `84b4dcc0a0abe082ddd1fc3d5409235dfeb1b32b89f07e6bbf9b1bbcb0423a1b`. | Finish all 100,001 originals and the crash and cold-replay checks. |
| G05, G06, G10 | `04e1edd1` and its predecessors add persisted writer registration, a protected Control observation and first-prepare admission. On macOS the six affected crates passed all-target/all-feature strict Clippy in 402.78 s. One original `46175daa` Store regression still failed at the ordinary tenant envelope check when a target journal read a different tenant's backup. A separately scoped read-only session correction reached a second failure in the fixture's assumed key count. | Verify the actual retained key catalog, the original Store graph and the protected retirement and recovery operations on the integration. |
| G01, G07, G12 | On `fdc32a1a`, the workspace reported failures for the local recovery key inventory and all three deployed server fixtures. A separate run of the original binary reproduced the inventory error after the test moved the manifest outside the disk owner. `7e8bf4aa` routes this move through that owner. The original clean `12140939` fixture independently passed in 23.85 s. Replay receipt SHA-256 `46356480e96b5e550c1be5f3bc5fb169dcac893f7d87bc94513b4286a9577d25`. | Examine all three full-suite failures and repeat the deployed lifecycle on the delivery source. |
| G03, G13, G14 | The 16-GiB shared Linux ARM64 guest killed the `81617fa9` release compiler after 1,035.780 s. The kernel recorded 6,629,364 KiB anonymous RSS for that compiler while other native builds were active. The waiting restore stopped before starting its target. Kernel log SHA-256 `39b0f9ff410150fcfeb8121da3146b5f12e798a0a7a821d667f89a456210872f`. | Retry the same release profile with the native compilers serialized, then rerun the original checkpoint. |

### November 20 native integration through 13:23 UTC

| Gates | Observed result | Outstanding work |
| --- | --- | --- |
| G01, G11, G12 | The three registered targets use source `e09fdb526313c3e065151fc0bc5dfaefba07f4a7`, tree `1feadc8ed40c171edd799dbc56af678abdf5d7aa`, archive SHA-256 `4eebad898e503a0915268d7757d9cefbedbe647b420b18d332039c73fd998f34`. Its macOS formatting check passed in 7.27 s. The previous integration `701d91c3` passed strict workspace Clippy in 707.07 s and 512 Python cases with three skips in 745.81 s. | Complete the pinned workspace and native qualification on each required architecture. |
| G01, G07 | On `d2654b68` native Linux ARM64 passed four KV fixture cases, four Store cases and five installed Server cases in 6.79, 1.59 and 81.81 s respectively. KV skipped the fixture generator. On `03bd5f2c`, the cancelled target monitor reopened its original journal in 0.51 s and expired-credential recovery passed in 3.50 s. | Repeat the immutable production lifecycle on the delivery source. |
| G01, G04, G07 | The original `fdc32a1a` macOS Server library reported 541 passes, five failures and three ignores in 1,982.74 s. The first clean fixture lost a required read audit during an apply failure. The next two fixtures encountered its prior serving owner. All three original fixtures passed in a two-worker replay with neighboring audit cases. The independently reproducible local-inventory failure is addressed by `7e8bf4aa`. The three-node Prepare fixture tried no-clobber publication over an existing issuer JWT. `874854f8` uses the enrolled file replacement API. Failure analysis SHA-256 `89dcd511b51cc79d1f9429d9e0cbdd9a9c8c981b128e911f3677b6605808efeb`. | Complete the final checks and establish the cause of the initial audit write failure if it recurs. |
| G05, G06, G10 | On `781119bb` the historical cross-tenant session verified the original backup and every physical wrapping identity in 1.62 s. Two earlier failed Store runs remain preserved. `e09fdb52` extends the signed registration to a journal's first terminal stop and checks every physical key minimum against committed retirement floors. | Complete the signed first-stop and Control tests on the pin. |
| G08, G11, G12 | The `03bd5f2c` native three-node learner catch-up and replacement case passed in 16.22 s. The original 6-GiB container rejected the other three fixtures during admission. The fixtures requested 5,020,338,920 bytes against a 3,221,225,472-byte high-water mark. The replay uses the same original executable on the development guest and the workspace container's 15-GiB limit. | Complete all original runtime cases and the independent reserved voter topology. |
| G11, G14 | The pinned dependency review first detected that RustSec had advanced from `074ea9a7`. A fresh scan of the same 483 locked packages with `f291af9b1cc0d21dfcea1709d6b037963cef262b` found zero vulnerabilities and the previously reviewed LRU advisory. Both OpenRaft registry entries remain unyanked. Current scan receipt SHA-256 `39a19c21c6d9dc1e9dc8c3fb7bb20fd29cb700770aed57e7129e7a0a539be556`. | Repeat the time-sensitive observations during final release verification. |

## Native results and storage integration, November 20 at 13:49 UTC

| Gates | Result | Qualification still required |
| --- | --- | --- |
| G01, G11, G12 | On the frozen source `e09fdb52`, native macOS ARM64 workspace Clippy passed all targets and features with warnings denied in 556.22 s. Formatting passed in 7.27 s. Python discovery ran 512 cases, skipped three and passed in 675.87 s wall time. | The full workspace and native release matrix remain open on a source containing the subsequent repairs. |
| G01, G07 | Six two-worker repetitions paired the original `fdc32a1a` clean deployed fixture with its adjacent audit-prune test. All twelve test executions passed. Native Linux ARM64 on `d2654b68` passed four KV, four Store and five Server compatibility cases. One fixture generator was intentionally ignored. | The earlier full macOS run still records the first strict-audit failure and two subsequent owner failures. Its isolated and paired reruns do not establish the cause. Both deployed formats continue to require write/reopen qualification. |
| G02, G03 | `2a889f8c` rebuilds a missing or stale bounded primary directory at the exact applied position. `48f9ebc1` streams an ordinary delta in 64-ID windows, under 16 MiB of encoded input and 256 staged transactions. `555d159f` resolves snapshot and query cold-body metadata under the pinned primary reader. A lease scan keeps its selected native reader through page evaluation. `a9205ef7` exercises an obsolete resident archive entry against the encrypted reopened directory. | Complete integrated tests and the recoverable background rebuild for an already stale or missing large directory. Demonstrate the full storage ownership, warm-cache and capacity contract. |
| G03, G05 | Two independently opened status commands using the original `d2654b68` production binary and request reproduced the same persisted materialization deadline failure. Native Linux ARM64 passed isolated immutable-image substitution, replay and semantic scratch checks on `81617fa9`. The original large filesystem graph carries 410 objects and 3,397,487,022 ciphertext bytes. | Complete a fresh 98,400-document restore and exhaustive readback under the 600-second production deadline. |
| G05, G06, G08, G10 | On `701d91c3`, the native Store session, signed writer, signed dispatch, stopped journal reopen and protected prepare cases passed. Whole-cluster retirement failed on a signed observation whose zero genesis position was rejected. `7d52d867` accepts authenticated genesis positions. A separate dedicated Control test failed while reading topology with an admin-only session. The first signed StopLocal native fixture also had the wrong physical verifier on its second member. `53b9f9e0` binds that member to its enrolled verifier. | Rerun all protected membership, retirement and first-stop paths on the integrated source. |
| G08, G11, G12 | On `03bd5f2c`, the original native Linux ARM64 binary passed expired-initialize inspection with an unavailable original member in 465.77 s and after an owned target restart in 345.01 s. The same binary failed the Control quorum inventory pagination case in 274.37 s with `CursorExpired`. Each run had one CPU and a 15-GiB container memory limit. A separate learner replacement case passed under 6 GiB. | Verify why the inventory changed across pages. Complete the independently placed nine-voter topology and the 24-hour soak. |
| G11, G14 | Two separate packing processes on this Mac produced the same 37,703,734-byte source archive from `e09fdb52`. SHA-256 is `377053e288a3571b515835f3d0fff4bfe276ca89b6cba9001b8058b6cf00876b`. The `701d91c3` fixture-free ARM64 macOS release build passed in 1,792.52 s. The daemon SHA-256 is `35607cd5496f856dff024dcb7cda5c14c85702b11cc9ea97647ef3810946a9cd`. | Run independent builders and qualify all three platform packages on one final source. |

## November 20 native qualification at 14:38 UTC

| Gates | Observed result | Still required |
| --- | --- | --- |
| G01, G03, G07 | Native Linux ARM64 on `fdc32a1a` passed 15 of 16 executed release steps. The workspace command exited 101 across four targets. Its process group drained. The inventory found one 39,247,872-byte core in the Engine crate and no changed or removed source files. The snapshot crash fixture calls `abort` after a real snapshot capture. The workspace log SHA-256 is `af2d1b7d08ebc569e1463f7ba9799d4193c0e62a07ad5c9ad5368f393b6143f4`. | Rerun the full suites, the four failing targets and both deployed-format suites on a common successor. Target cleanup needs a durable identity independent of inode reuse. The first intermittent macOS audit failure remains open. |
| G02, G03 | All ten bounded primary rebuild and Store recovery tests passed on `154ce668`. Clippy passed in 104.09 s. The native build took 925.23 s and peaked at 11,280,236,544 bytes RSS. All eight text tests and both cache admission cases passed on the prior cache repair. Selected-text warmup strict Clippy passed in 336.11 s. | Complete exact selected-generation cache, field, text and restore tests. Measure installed capacity with the protected census. |
| G03, G05 | The Linux ARM64 production restore on `81617fa9` read the 829-object MinIO backup, decoded 98,400 live documents and persisted the prepared target. Start then failed with maintenance headroom unavailable after 453.91 s. A fresh status reader recovered the failure. On macOS, `e09fdb52` expired during snapshot decoding on the separate filesystem backup. | Verify that the repair reserving maintenance headroom before verification completes both original restores, including readback, within 600 s. |
| G05, G06, G08, G10 | Native macOS ARM64 three-member protected retirement passed in 56.96 s and signed Prepare passed in 23.82 s on `b9dbe246`. Dedicated Control reached final topology restore and retained an admin-only authorization failure. Its fixture correction is `b6ea80eb`. | Rerun dedicated Control and the HA pagination repair. Independent Data, Control and Authority placements and sustained fault qualification remain outstanding. |
| G11, G12, G14 | Native macOS ARM64 release build on `e09fdb52` took 1,248.43 s. The daemon SHA-256 is `e562fc6e15ee19fe917645669e07d1d5c5ed3f88ead1afd6f5dc7d429de798a6`. The million-document memory-only benchmark completed 1,000 measured operations at each of 1, 100 and 1,000 tenants with zero failures. | Run all installed workload profiles on the final candidate, native Linux x86-64, reserved ARM64, independent artifact verification and the full 24-hour soak. |

### November 20 development qualification through 15:31 UTC

The registered qualification source is `eab380852c938329094d8b9d0f30e2a383511b49` (tree `fc7c32a4eb7cfc3bfc4f341a89fdbefd85db7d56`). Its 72,099,840-byte Git archive has SHA-256 `de22f4c27683d5de9f3dbbdc315b75c91f9b20a7cda6ac2a15282a1b3d957daa`. Release acceptance is **HOLD**.

| Gate | Observation | Outstanding |
| --- | --- | --- |
| G01, G11, G12, G14 | On native macOS ARM64, 16 logical CPUs and 128 GiB, the frozen source passed formatting in 4.75 s, strict workspace Clippy in 348.0 s and 512 Python cases with three skips in 684.02 s. Its fixture-free release build completed in 1,160.62 s. The kasumid SHA-256 is `50a70d14e7a473f9de0b933d1862f072d1592faff792425af0cbfce167a14267`. The independently invoked source assemblers on this host matched all 2,385 files and produced the same 37,735,690-byte package with SHA-256 `9e43ef427235aa3b388ff8c029947b73262054141996f9fb881da4dfcb7c8caa`. RustSec revision `f291af9b` returned zero known vulnerabilities for the 483-package lock and the previously dispositioned LRU maintenance warning. | Complete native workspace, installation, independent assembly and delivery checks on one source. |
| G02, G03 | On the common source, the authenticated 32-row primary traversal and encrypted reopen passed. At `8dc7f0da` two or more positive structured predicates can combine the selected generation's native field postings. The native Query suite passed 109 with two ignored. | Complete physical ownership for the remaining resident indexes and document metadata, large structured replacement and bounded covered-replay verification. |
| G03, G07, G13 | On shared native Linux ARM64 (2 CPUs, 16 GiB, 200 GiB virtual disk), the installed e09fdb52 MinIO restore reached bootstrap persistence. Loading and verification took 73.295 s, decode took 286.786 s and genesis took 111.128 s. The operation expired after 600.771 s. Its following drain repeatedly retained a registered opening. | Identify the original live owner, complete physical reopen, and read back all 98,400 documents from a fresh restore. |
| G05, G11 | The original native Linux Btrfs run contains 16,657 distinct terminal-journal session IDs, from ordinal 0 through 16,656. A public abort returned UnknownOutcome after 17,351.56 s wall time. | Verify 100,001 distinct originals with process termination, restart and independent cold readback. |
| G06, G08, G10 | The c251f396 six-member dedicated Control/Data test passed. Three members recovered an uncertain activation and produced matching physical inventories. A later credential-withholding assertion failed after 435.32 s. The direct native wire reproduction isolates rejected identity seeks on both Data and Control journals. `712adbe5` corrects the validator and passed both direct probes. | Repeat protected retirement and credential controls, exercise the complete reserved topology and measure 86,400 s of qualifying service. |
| G07, G09 | Eight native target cleanup cases and the original cancelled monitor/journal reopen case passed on c3a7cd78. `f6a6782a` admits an originally stamped, still-empty directory and writes its first binding, Deleting record and permanent charge in one transaction. | Complete its fresh-process journal readback and both platform suites. Occupied, unstamped legacy targets require original provenance for irreversible deletion. |

The owner still needs to identify the reserved native Linux x86-64 and ARM64 hosts, the three Data, three Control and three Authority voter placements and learner, and the independent builders. Release signing and publication follow qualification. The large deployed fixture already exists on origin/master. BOI's environment owner performs its live installation. Both existing store formats retain read/write coverage.

### November 20 native qualification through 16:08 UTC

| Gate | Result | Remaining acceptance work |
| --- | --- | --- |
| G01, G07, G11 | The complete e09fdb52 workspace runs finished on macOS ARM64 (4,067 passed, seven failed and 26 ignored, 5,921.03 s) and the native Linux ARM64 guest (4,068 passed, seven failed and 26 ignored, 5,398.34 s). Linux peaked at 11,632,984,064 bytes under its 15 GiB limit. The original logs and each failed case remain in the evidence. | Run the corrected source across the full workspace and all required native platforms. |
| G02, G03 | The integrated code bounds foreground primary replay to 8,192 rows and 16 MiB, and covered structured verification to 65,536 rows and 16 MiB. Larger structured layouts rebuild with a persisted field cursor. Bootstrap cold reopen admits encrypted scratch from the authenticated manifest length before reading the first chunk. Integrated native regressions are in progress. | Verify the large rebuild, pinned-reader and cold-reopen cases, resident storage ownership, the reference disk capacity workload and the installed twelve-profile benchmark. |
| G03, G07, G13 | The e09fdb52 native Linux MinIO restore expired during bootstrap persistence at 600.771 s. After 3,600.356 s the process supervisor sent SIGTERM. A separate cold process reopened the encrypted journal in 0.553 s and found the materialization phase with no recorded failure. The 98,400 documents still require successful target readback. A harness race that skipped readback while the process was running has a separate regression receipt. | Verify the original failure is persisted before drain, native transactions close, and a new original restore completes exhaustive readback on the candidate. |
| G05, G06, G08, G10 | On 712adbe5 the protected three-member repeat completed credential withdrawal, restoration and retirement in 372.91 s. Its first route-readiness timeout is retained. On eab38085 the unavailable-member recovery repeat passed in 381.77 s after an initial configured-tenant Prepare timeout. Lost Start and Initialize passed in 37.14 s. The eab38085 protected quorum still failed the withheld-writer assertion after 210.09 s. | Verify the integrated source and complete sustained fault tests on the reserved topology and the 100,001-original-session acceptance run. |
| G11, G12, G14 | All 19 G11 adapter names match the attempt index and scenario registry. The retained RustSec, artifact and installed results are identified by their measured source. | All 19 domains require accepted release evidence on one candidate. Native x86-64, independent builders, approved hardware placements, the 86,400-second soak, and release signing remain open. |

### Native recovery, Raft and capacity evidence

All fourteen release gates remain open. The frozen three-platform source
`2d4adade` has reproducible workspace failures. The qualification record keeps
its original runs alongside the results from subsequent integration commits.

| Gates | Source and result |
| --- | --- |
| G01, G02, G03 | On `920c703b` all four Store and four KV deployed-format cases passed after an isolated rebuild. The earlier Store executable failed to build against a stale KV library. On `3dc87180` the production reopen reclaimed the 278 unselected rows in 17.47 s. The 71,393-row interrupted structured rebuild passed in 219.87 s. Its native qualification receipt has SHA-256 `29ae0b6cec9727b0c3c806e390bd162184396a30685d1a3a94fc4240cda1c3ea`. |
| G02 | On `5c5a68e1` the unique and nonunique single-field indexes retained 5,914,081 and 5,913,229 bytes respectively for 8,192 documents. Sharing their posting root removed 2,399,230 bytes from the unique case. The general compound ordering and final reference workload still require qualification. |
| G03, G05, G08, G09 | The original MinIO restore on `04b272e5` exited successfully in 1,414.636 s. Cold status returned finished in 17.997 s. The subsequent database credential renewal was refused because its original scopes exceeded the restored policy. `7a650940` selects new profile scopes from the restored principal's grants. Strict workspace Clippy passed in 1,037.97 s. |
| G03, G07, G09 | On `2d4adade` the awake macOS filesystem restore exhausted its original 600-second verification deadline during snapshot decode. Cold status retained the error. Same-operation resume refused an absent deployment binding. This follows step 4 of the [local recovery preparation contract](explicit-catalog-lifecycle.md). The original installation was preserved and checked across 454 files. Stop, cold status, repeated stop and final cold status each succeeded and the target directory was absent. The cleanup receipt has SHA-256 `d34430ad6e1255f0b8c0c7c830e8aa7380b1a6427c59dd671fe9cebb9a66ced0`. |
| G07, G11, G12 | The original Linux ARM64 Raft custody binary failed 21 of 48 isolated repetitions. `359ab42f` removed a competing warm-up read and observed both voters' application of the concurrent write before teardown. Each ARM64 platform then passed 192 repetitions and the entire 23-case lifecycle suite. The macOS run took 12.81 s and the Linux run took 28.93 s after compilation. |
| G10, G11, G13 | `ab54eff5` keeps the Control and operator families current during the installed capacity workloads and starts Control renewal before protected readiness after standalone restore. All 30 capacity adapter tests passed in 8.45 s. The full capacity and soak workloads remain open. |

On `04b272e5`, the same restored MinIO target accepted a certificate-bound
read-only credential issued through its installed Control. It returned all
98,400 documents, totaling 3,224,371,200 logical bytes in 399.89 seconds.
All 12,300 eight-document batches matched the source ledger, with SHA-256
`e764a42370a033dfebbfb4326704017e948dfea2111437f032f61fef47de536e`.
The initial renewal failure and refusal of an unbound replacement were retained.

On frozen `2d4adade`, native Linux ARM64 Cargo built the KV, Store and Server
test executables from the candidate source. Four KV and four Store
deployed-format cases passed. The fixture generator was skipped. The Server
harness opened the clean and killed first-revision installations and the
second-revision installation. Cancelled shutdown passed in 0.28 seconds and
the independent Authority journal recovered its encrypted stop record in 1.73
seconds. The pinned OpenBao and MinIO interoperability probes passed in 2.94
and 2.23 seconds, respectively. Each probe recorded two provider processes.
The guest had two CPUs and 16 GiB RAM on a shared ARM64 workstation.

The same frozen Linux history executable reproduced an archived snapshot page
failure and a cold restore memory admission failure individually in 1.09 and
2.41 seconds. Lease selection retained the archived references while recording
zero bytes in the selected collection. Commit `42551dc3` carries the selected
entries' encoded sizes, and `9d1f84ec` corrects the module path after the first
native build failed. The regression covers both leased point reads and scans.

### Frozen workspace and successor qualification

The common candidate `2d4adade9c3d5a528dcb6d2c435eeedd10f7d74a` remains on **HOLD**. Its native Linux ARM64 functional run completed 22 checks. Nineteen passed. The workspace, strict Clippy and vendored Raft integration failed. The workspace ran 4,087 passing tests, three failing tests and 26 ignored tests in 5,023.705 seconds. Peak memory was 14,169,436,160 bytes under a 15 GiB container limit. The compressed terminal evidence has SHA-256 `e000b6ce7ccabf9c8cf2173204282ee0bf4f5051c6f9f4d6aa2cf24fb0c76a17`. The shared macOS ARM64 host reproduced all three workspace failures independently.

| Goals | Source and observed result | Release work outstanding |
| --- | --- | --- |
| G01, G07 | At 03:52 UTC on November 21 the remote master was `c19bf2b353b2174526140f02254fd5dfc0649410`. Its 28,798,481-byte deployed fixture has SHA-256 `ccb60432bbf0f18a9d2198cdd62d7d4c2addf79c85a7295614068aa8fc375d2b`. Both original formats passed write and reopen. Frozen Linux passed cancelled shutdown and encrypted Authority journal recovery. | Repeat lifecycle and both format suites on the final products. The fixture is already on the remote. |
| G02, G03 | `f09afadf` bounded archived document materialization. Six Linux backup-history cases passed in 44.06 s, including cold restore, alongside four body admission and ownership cases. On `ceb1a578` native Query passed 116 tests with two ignored, including mixed short and oversized compound keys in both directions. The grouped write regression verified five results across two actual append boundaries and cold encrypted reopen. | Complete physical ownership, largest replacement and the prescribed capacity profiles on the reference host. |
| G03, G05, G09, G13 | The installed Linux MinIO restore on `04b272e5` completed internal service verification in 449.698 s and the CLI exited in 1,414.636 s. A cold protected read verified all 98,400 original documents in 399.89 s. On `7a650940` four native credential recovery cases passed. A fresh macOS filesystem target using that commit took 624.01 s and hit its 600.001 s verification deadline during snapshot decode. An independent cold status recovered the same operation, phase and error in 4.507 s. | Complete an installed filesystem restore within its original deadline and verify every original digest on the successor. Run the full backup session cohort through interruption and cold replay. |
| G07, G11, G12 | `359ab42f` passed 192 Raft lifecycle repetitions on each ARM64 operating system. `870ac00e` passed 689 KV units and four deployed-format tests on Linux. On integrated `c19bf2b3`, strict all-target, all-feature workspace Clippy completed in 373.444 s and fixture-free Engine lint in 52.169 s. | Run the complete native tests and all 19 installed acceptance domains on one source. |
| G02, G13 | `3d52e619` fills the existing segment write window across adjacent records. Linux ARM64 passed the new physical-write and cold-offset regression, all 690 KV unit tests and four deployed-format tests. The fixture generator was ignored. | Measure the fresh installed corpus restore and verify the final capacity and endurance runs. |

The native Linux development guest had two CPUs, 16 GiB RAM and a 200 GiB virtual disk on a shared Mac. G04 and G06 still require final installed audit, historical-key and retirement evidence. G08 through G10 require fault and access-control results on the reserved voter topology. G11 through G14 require final candidate artifacts, native x86-64 and reserved ARM64 qualification, independent builds and the 86,400-second soak. The release owner signs and publishes after qualification. BOI's owner conducts its live installation.

### Qualification of candidate `0e0a6d9d`

The three-platform candidate is `0e0a6d9d7cf26a0fa8523661f90967124e35d29e`. Its 2,390-file Git archive is 72,325,120 bytes with SHA-256 `0acb9350cf7edbde60abae929adff214c7528f7c2da097e1338fdfb62ee89f30`. The two source-package assemblies on macOS ARM64 each produced 37,786,977 bytes with SHA-256 `7087e67afa96a5e7cb29207cebc357a5f60a516e4756e517f44d3ca1819f83cd`. The dependency review covered 483 locked packages against RustSec revision `f291af9b` and found zero known vulnerabilities. The sole maintenance warning concerns the reviewed LRU fork. Release status remains **HOLD**.

| Goals | Source and observation |
| --- | --- |
| G02, G03 | `2b75a775` incorporates accepted-journal compound tuple edits and 16-row checkpoint windows. On `0789d8ee`, native grouped conflict and reopen took 5.34 s, independent cold journal replay took 4.24 s, and replicated snapshot install and encrypted reopen took 15.83 s. On the earlier integrated `c19bf2b3`, Linux passed all six history cases and 116 Query cases with two ignored. Workspace Clippy passed on that source on Linux in 373.44 s and macOS in 1,903.11 s. |
| G02, G13 | On `0e0a6d9d`, all nine isolated native document encoding tests passed. Across eight alternating trials per build, encoding 512 documents took a median of 29.24 ms compared with 45.18 ms on `3d52e619`. Every run produced the same logical and physical digest. Both executables linked the same native dependency libraries. The full installed corpus restore is a separate check. |
| G10, G11, G12 | The original macOS workspace on `2d4adade` also reported a failure in `small_integer_query_is_refused_before_its_value_tree_under_a_tight_budget`. Its original Linux workspace passed this case. The macOS executable has been retained for isolated replay. |
| G11, G14 | The native Linux ARM64 and macOS ARM64 workspace, installed, provider and restore runs are registered for the new candidate. The x86-64 runner, physically reserved ARM64 reference, nine voter placements and learner, independent builders, 24-hour soak, signing and publication remain open. |

### Native delivery, checkpoint and memory results

| Goals | Evidence by source |
| --- | --- |
| G02, G03 | The native checkpoint test on `bcfa55e4` failed to establish the owner of a wide compound key. On `852d9eeb`, it found the duplicate and proved the absent combination within the read and byte limits. The same executable installed a replicated snapshot and reopened it under encryption in 9.86 s. Merge `d5d0372a` incorporates the fix. The larger applying-generation memory and capacity tests remain open. |
| G02, G12 | On Linux ARM64, the original `222a1b52` Store test executable exhausted a 4 GiB cgroup during the bulk staged-tree test. Six smaller layout cases passed under that limit. Under 15 GiB, the original bulk test passed in 7.06 s and the full executable passed 999 tests with seven ignored in 448.46 s. |
| G07, G11, G14 | On `2d4adade` the native Linux release build recompiled all 25 Cargo artifacts from local paths, including the three delivery binaries. The installed suite passed all 16 scenarios in 42.15 s and the ABI check passed in 7.33 s. The OCI image passed 33 lifecycle steps in 21.47 s, including restart. Its digest is `sha256:0878ed29529499906918773be9ffb837a64e5cf028b268dc1038b0aeaeab7de4`. Real pinned OpenBao and MinIO interoperability passed. |
| G10, G12 | Five of six original `2d4adade` macOS replays expired during the preparatory Engine query before the MCP call. One completed the test. The first corrected fixture failed compilation. `05512bdb` fixes that error and retains the original MCP budget and request deadline. |
| G11 | On frozen `0e0a6d9d` the scenario registry, verifier adapters and attempt index agree on 19 domains and 27 target-specific results. The evidence ledger identifies the scenarios, targets, observed source and remaining work for each domain. |

### Native candidate results and unresolved restore

| Goals | Evidence by source and target |
| --- | --- |
| G02, G03 | On `753d7021`, the registered query worker retained 6,543 bytes at the first document and 2,724 bytes after the first page over 8,192 oversized keys. The prior version retained 10,998,796 and 10,998,484 bytes. All 117 active Query tests and five original Engine tests passed. `0790099a` incorporates this change. `969269ff` incorporates the grouped-write fix `ea572650`, which passed the previously failing original participant case. |
| G02, G13 | On `7a4f0b25`, nine alternating trials compared the same document digest, wire length and structural charge. Median time for 1,024 opaque documents went from 40.71 to 26.96 ms, and for 1,024 dense numeric documents from 11.25 to 6.83 ms. For 32,768 small documents it went from 11.00 to 10.46 ms. All four isolated measurement and depth tests passed. Full installed restore qualification remains open. |
| G03, G05, G07 | The installed Linux ARM64 `2d4adade` MinIO run opened 834 original objects spanning 3,393,453,778 bytes. The restore CLI hit its 3,600.422 s bound. A cold process recovered the original request in the publication phase with the retained snapshot preparation error. The original stderr and 32 retained drain diagnostic file hashes are archived. |
| G07, G11 | On the shared native Linux ARM64 guest, the original Data unit reached serving but the first root CLI used a service-account profile. Using a root-owned operator profile exposed a separate verification failure. PID 1 released the stopped unit's main exit status before the observer read it. `20c47418` keeps a systemd reference until that read. With the same binaries, the `2d4adade` replay passed in 3.61 s. The `0e0a6d9d` unit passed in 9.88 s, including authenticated readiness, TLS, a new process on restart and an empty original cgroup on SIGTERM. The Authority unit and complete packaged dual-service gate remain open. |
| G10, G12 | The full `2d4adade` macOS workspace finished in 9,739.433 s with 4,085 passed, four failed and 26 ignored across 85 suite summaries. Documentation tests passed in 91.502 s. All six isolated unoptimized MCP fixture replays on `05512bdb` failed. Five hit the preparatory read deadline and one hit a write deadline. A separate replay uses the workspace's original level-one test profile. |
| G11, G12, G14 | Frozen `0e0a6d9d` passed strict macOS workspace Clippy in 2,723.101 s and formatting in 33.175 s. The release-script suite ran 512 tests with three skips. On native Linux ARM64 the fixture-free production build, 16 installed scenarios, package ABI inspection and OCI restart exercise passed. The container image ID is `sha256:25e30da5389e675a522f3d0aced9ccc0ab185c15d46c00430d03796ea8b563e1`. |

### Original MinIO recovery and applying-index costs

| Goals | Measured results |
| --- | --- |
| G02, G03 | On `010c5931`, the interrupted generation cleanup and independent encrypted reopen passed in 65.76 s. The 71,393-row restart with intervening writes passed in 306.17 s at 80,543,744 bytes peak RSS. At the supported width of 64 indexes with eight paths, `b9cf0798` reduced the measured peak for the 2,048-to-2,049-document replacement from 299,477,120 to 1,820,248 bytes. It passed 120 Query cases, with two ignored. On `b1ad609e` two generations of heterogeneous 8,192/8,193-row data retained 36,421,226 bytes, down from 58,292,531. The independent oracle verified all 651 qualifying rows in each direction for both generations. All 121 active Query cases passed. |
| G03, G07, G09 | The original `2d4adade` Linux MinIO publication resumed in 572.735 s after 113 files were archived and compared. Separate cold processes before and after resume recovered the same request. The second reported finished with no failure. On `0e0a6d9d`, the new 98,400-document restore exhausted its 600-second budget during decode and exited 1 in 603.395 s. Cold status recovered the deadline in 0.404 s. The original target then refused resume because its deployment binding was absent. The replay observer expected a different error string and failed. A cold process preserved the actual binding error. Four further native invocations stopped the retained target, reopened the stopped journal, repeated the cleanup and confirmed identical deletion evidence. |
| G02, G13 | On `b4948df1` foreground writes and restore staging each emit the validated manifest once. All 11 focused encoding cases passed. Eight alternating trials per build produced identical physical digests. For 2,048 dense or small documents the medians moved from 19.37 to 15.14 ms and 4.12 to 3.09 ms. For opaque 32 KiB strings the median increased from 1.151 to 1.255 s on the shared Mac. These measurements cover the document encoder. The installed capacity run remains open. |
| G11, G12, G14 | On the frozen `0e0a6d9d` native Linux ARM64 guest the production build recompiled 25 path artifacts in 3,979.56 s. The 16 installed scenarios, package ABI check and 33 OCI lifecycle steps passed. The new provider run used two actual process incarnations of each of OpenBao and MinIO. Native x86-64, reserved ARM64, the nine voters and learner, independent builds and the 86,400-second soak remain open. |

### Full protected readback and native Authority faults

The current qualification source is `0f806ea89b5abb732ebd6ff701b3514d4b9656fb`, tree `aa2e8333f91dcdada07b03cdc5554ff690244120`. The 2,392-file archive is 72,427,520 bytes with SHA-256 `e083c59aabffddb0708b8bd0c063d868db9f3e237d3949f4e492719c40ca1b69`. Two source-package assemblies each produced 37,805,450 bytes with SHA-256 `22096c5c26246884ca2ea25028427b8a37cb715acdc8b3a711ed2aca2c9fdcd5`. The native functional and delivery jobs are registered on both available ARM64 systems. An upstream RustSec check of all 483 packages returned zero known vulnerabilities and the reviewed LRU warning. Production release remains on hold.

| Goals | Measured result |
| --- | --- |
| G03, G05, G07, G09, G13 | On the original recovered `2d4adade` MinIO target, opening the native TCP port took 2.01 s. Authenticated Control renewal first succeeded at 473.86 s. Two earlier readback attempts stopped the service during cold open and both hit its 60-second exit grace. On the completed run, the certificate-bound reader verified 98,400 documents and 3,224,371,200 canonical bytes in 434.091 s. Its 12,300 batch rows exactly matched the original digest `e764a42370a033dfebbfb4326704017e948dfea2111437f032f61fef47de536e`. SIGTERM then drained all service owners and exited zero. |
| G06, G07, G08, G10, G12 | The three enrolled Authority processes on `0e0a6d9d` returned their operational membership before a stop, with two survivors and after cold rejoin in 16.26 s total. A second run killed two actual processes. The minority declined the protected read after 40.042 s, and both cold reentries recovered the identical configuration. This run took 51.49 s on the shared Linux ARM64 guest. |
| G07, G11, G14 | The shipped Authority unit passed authenticated membership, TLS pinning, restart with a new PID and invocation ID, and SIGTERM with an empty cgroup in 19.46 s. Two live enrolled voters continued answering after the unit stopped. The first enrollment fixture omitted a separate MCP audience and the second used a certificate missing an Authority Key Identifier. Both failed attempts are retained. The original Data and Authority unit evidence is separate from the formal packaged two-role run. |
| G10, G12 | On `05512bdb`, all six isolated reruns of the original macOS MCP case passed under the workspace's actual level-one test profile, taking 15.65 to 23.63 s each. The original workspace run and six level-zero failures remain in the ledger. |
### Native nine-process failure recovery and storage ownership

| Goals | Result and source |
| --- | --- |
| G05, G06, G07, G10, G12 | On frozen `0f806ea8`, all nine fixture-free Linux ARM64 daemons served together on one 2-vCPU, 16-GiB development guest. The three Control voters installed the signed remote Data topology. An Authority voter signed the original Data enrollment. All three Data voters served the tenant using independent Authority leases. The driver killed the Data leader and its replacement. The surviving minority refused a protected read. A recovered majority returned the original document, and restarting all three original Data installations recovered the same document and permanent write receipt. This run took 58.77 s. On `0e0a6d9d` the same exercise passed in 84.77 s after an earlier run polled a returning member before its first readiness coverage. Separate native Control leader loss, minority refusal and cold reentry took 14.73 s. |
| G10, G11, G14 | On `0f806ea8` macOS ARM64, formatting passed in 19.80 s and workspace Clippy passed in 863.85 s. Python tooling ran 512 tests with three skips. On the shared native Linux ARM64 guest, the fixture-free release build took 1,925.45 s. The 16 installed cases passed in 29.11 s, the ABI check in 4.31 s and 33 OCI lifecycle steps in 16.06 s. The OCI image ID was `sha256:66dd4494be51d8d94a6b3b351facc53b3a2cd0cc556e8e95c55777929e79b816`. Real OpenBao and MinIO interoperability used two processes per provider and took 3.76 s and 3.00 s respectively. |
| G02, G03 | Merge `072d2faf` incorporates the maximum installed schema-replacement fix. The ordinary regression on `35080a6e` replaced 128 collections and 65,536 indexed fields at the 8 MiB wire limit under the default work policy. It retained the predecessor, verified 256 document bodies, reopened encrypted storage and replayed the original activation in 62.88 s at 221,642,752 bytes peak RSS. For a different 512-field heterogeneous schema, `d0d40f05` reduced retained bytes for two generations of 2,048 and 2,049 documents from 238,450,469 to 75,109,487. |
| G02, G12 | On `841fbc0b`, five native Engine cases covered querying the encrypted primary directory with both resident document maps removed, cold restart, Raft snapshot install and compaction. Eight text publications over 1.28 million distinct tokens reduced simultaneously open segment bytes from 64,763,390 to 24,290,124 while all eight remained selected. On `94012c19` validation of 4,096 strings containing 65,536 terms peaked at 402 allocator bytes after the caller had constructed the input. The scalar limit and the first rejected token count were tested separately. `5b1f7b4a` and `e79fbbf8` integrate the fixes. |
| G07, G10, G11 | The exact three updated process-drain files from `be276fce`, compiled on the original `2d4adade` macOS test graph, passed all four exit-registry cases and the cancelled shutdown/journal reopen regression. On the original `2d4adade` executable, seven protected observability probes passed, including 129 groups, archived backlog, recovery, backup, Authority replacement and redacted logs. |
| G11, G13 | The soak adapter's original `kasumid credential renew` returned unavailable against the real replicated external issuer deployment. Source `2ba333e6` observes the exact externally renewed bearer through an authenticated native catalog read. All eight soak harness tests passed, including refusal of an unchanged bearer, stale expiry and a substituted profile. The native product and the full 86,400-second rotation, archival, backup and membership workload still require qualification. |
| G01, G11 | Four opt-in application schema checks were run against two archived BOI project revisions. At `d7655b2b`, BOI, shared FI Auth templates and FI governance passed. A per-FI rendered Auth bundle correctly rejected the test's second FI, and the KYC renderer produced 13 collections where the historical case expected ten. At `4dc9d2bc`, the published bundle counts were BOI 9, FI Auth 15, KYC 14 and FI governance 15. All four exact historical expectations rejected those inputs. Original results and hashes were retained. |

### Protected restore, native membership and historical keys on November 21

The common qualification source is `ceb83a1bf5ef4fb16fb24f5b93de3f6d95d87798`. Its 2,393-file source archive has SHA-256 `7b9412197eb71eb7e31c530ef712a261c7c9234c415e6eae4bcd6000077b6031`. Two source-package assemblies produced SHA-256 `341f4ed04c9d6ebba33a608270a8bc4e7a7f2938cf11d6a1a46346e82bd55224`. On native macOS ARM64 this revision passed formatting in 19.03 s and strict workspace Clippy in 1,352.66 s. Python discovery ran 516 tests with three skips.

| Goals | Original observation |
| --- | --- |
| G02, G03, G05, G09, G13 | On `0f806ea8` the original 98,400-document MinIO restore completed in 1,507.818 s. A cold process found the finished operation in 0.434 s. Certificate-bound readback verified 3,224,371,200 canonical bytes in 386.206 s. All 12,300 rows matched the original integrity file SHA-256 `e764a42370a033dfebbfb4326704017e948dfea2111437f032f61fef47de536e`. The run took 2,641.075 s including clean shutdown. The earlier `0e0a6d9d` restore deadline and `2d4adade` publication timeout remain recorded. |
| G02, G03 | `e3d83e4b` fixes a primary with the wrong Raft term shadowing checkpoint-selected text. Six Engine regressions passed. `c166996f` incorporates per-collection text publication. Over six collections and 384,000 terms, the buffered file span fell from 19,171,795 to 3,196,218 bytes. Nine tests passed, including rollback after physical writes. Peak RSS rose from 105,594,880 to 108,871,680 bytes in the measured workload. |
| G04, G08, G10 | On `0f806ea8` the Control leader served 256 protected requests and verified its own encrypted MinIO audit stream through sequence 321 across 11 segments. In a separate 126.36 s run, 10 reads and 11 writes succeeded during the 2.551 s learner promotion. After the original voter and leader stopped, learner 10 returned the original body and write receipt and cold-opened at applied index 29. |
| G05, G06 | A cold replacement Data leader verified the original MinIO session with its writer offline. A deployment with independent tenant keyrings failed checkpoint decryption. On `0f806ea8`, withdrawing the original Data reader's OpenBao version-1 decrypt permission made checkpoint verification fail and prevented retirement. Restoring that permission recovered the identical checkpoint in a 21.24 s nine-process trial. A separate 28.24 s trial withheld and restored the provider version. Two Data peers in an earlier trial exceeded their shutdown grace after key access returned. |
| G06, G07, G09 | On `0f806ea8` Control retained a target-journal fence after the target's return callback failed certificate-bound authorization. The callback repair requires native verification. A separate 12-process recovery trial failed `check-config` on the first of three separately enrolled targets. `8abf3672` admits the target-only role with its remote Control quorum. |
| G08, G11, G13 | On native Linux ARM64, `e79fbbf8` observed a genuinely rotated external credential on the same profile and confirmed an additional 1,200 s of validity. The unchanged bearer failed renewal comparison and a valid bearer for another principal failed the native probe. Nine services completed the rotation and Data leader loss, minority refusal and cold restart in 51.45 s. |

The nine voters and learner may share one reserved native ARM64 guest for qualification. Independent physical failure domains apply to live deployment. The reference still needs a reserved interval, and the x86-64 host and independent clean build environments remain outstanding. The 86,400-second soak, complete platform tests and final artifact verification remain open. Both deployed-format fixtures still have read/write coverage. The large fixture already exists on the remote. BOI's environment owner handles its live installation.

### Native recovery after the November 21 desktop restart

The three-platform qualification source is `ceb83a1bf5ef4fb16fb24f5b93de3f6d95d87798`. The following fixes and measurements extend the integration branch. The full release remains on hold.

| Goals | Source and observed result |
| --- | --- |
| G02, G05, G13 | The native Btrfs session cohort on `2d4adade` accepted the first 17,531 ordinals. The next public abort returned a Control binding read error. On cold open, tracing the original binary showed an empty directory retaining its inode and length while fsync changed its allocation from zero to eight blocks. `9899f78a` preserves the underlying physical error in the local qualification record. `78638368` charges the synchronized directory and checks its namespace timestamps. The original journal and read-only Btrfs snapshot are retained. |
| G04, G10 | On `e79fbbf8`, the original Data leader, its surviving peer and a cold leader returned identical verification for two encrypted tenant audit segments in the local cache and original MinIO bucket. The original fixed-end export ended at sequence 6. A later export reached 582. Cold verification took 8.003 s. All nine original services reopened and then drained cleanly. |
| G06, G09 | `fa6be4b5` integrates the signed target-journal callback exercised on `948d91a6`. Missing and wrong-principal readers preserved the Control fence at revision 7. The enrolled reader completed revision 11. A cold replay returned the identical record. All 76 native steps passed in 63.949 s. All 16 process incarnations and MinIO exited zero. `afc9e4ad` separately integrates the declared file-key retirement floor, tested on all fifteen original deployed keyrings. |
| G07, G11, G12 | The original `0e0a6d9d` Linux ARM64 workspace logged 4,090 passing, four failing and 26 ignored cases in 6,152.837 s. The Store process received SIGKILL as the cgroup OOM-kill count increased by one. Its eleven unfinished cases passed individually on the same executable. The cancelled Raft apply test reproduced four failures in 50 repeats. With `5bbdee51`, the changed Raft crate on the same native dependency graph passed all 50 repeats and its entire 231-test library. The three original Server failures remain recorded. |
| G11, G14 | The native systemd observer `ed4de600` exercised the published Data and Authority units with the `e79fbbf8` binaries. Both services restarted, served pinned TLS and stopped with empty original cgroups. The 53-step exercise took 15.014 s. The earlier manager-inventory and service-user failures remain recorded. |

### Native workspace, dependency and recovery results on November 21

The common qualification archive at this checkpoint is `eb309609c9c6912368ae7a95c16a53b68bfa2048`, tree `04ca2769a65d2fd1c5961ce7965c889e9cb7e533`. Its 2,394 files occupy 72,519,680 tar bytes with SHA-256 `576e334ebe6e38d880229f720b1ad0422817194246fb1665faf6bb01e4e97af8`. Newer integration commits require their own common qualification. Production remains on hold.

| Goals | Observed result |
| --- | --- |
| G02, G03, G13 | `c9747a02` shares each document identifier across scalar and compound index entries. With 64 indexes, the two measured generations containing 2,048 and 2,049 documents retained 174,263,098 bytes, down from 237,660,270 before this series. For the 8,192/8,193 heterogeneous generations the result was 27,588,493 bytes, down from 36,473,725. In four alternating writable opens, the original and changed executables independently read the previous writer’s persisted idempotency receipt on the same encrypted inode and advanced the collection from 385 through 387 documents. Receipt SHA-256 `9890c56e200f5f4bf432df125938873f152dc21314283ad71668a3961e46190b`. |
| G05 | On the original Btrfs volume the synchronized census accounted for 143,495,168 directory bytes across 35,076 unique directories. The original installation reopened. Attempting a fresh claim for ordinal 17,531 then returned a source or destination conflict. The original operation and first 17,531 journal records were retained. `970b34d4` uses the original public session status and recorded intent to retry the outstanding abort. Full population, crash cuts and cold comparison remain open. |
| G06, G07 | On `0f806ea8` all three original Data processes retained custody after the OpenBao outage and failed their final drain. The six other voters and both provider incarnations exited cleanly. The development provider tests now separately cover a withdrawn version permission and an actual refused TCP connection. The whole installed outage must pass on the repaired tree. |
| G07, G11, G12 | The three Server failures from the original Linux ARM64 workspace were replayed individually on the same binary. The owned-target restart case exhausted its public Control status deadline after 413.42 s. The unavailable-original case received the retryable pending-admission response after 308.90 s. The pinned-mTLS replication case passed in 315.56 s. All three cgroup runs recorded zero OOM events. The same three cases passed individually on macOS ARM64. Linux receipt SHA-256 `27b636a80ae7064af55f8ad4b356522bbe811d21d4a0421fcbfc913beb2575e8`. |
| G07, G08, G11 | All four `e79fbbf8` concurrency workloads completed 9,002 sample windows on nine native processes. The run failed after 2,790.047 s. Voter 6 retained the original committed-but-unacknowledged apply response for indexes 5023–5024 and exited 1. The other eight voters and MinIO exited zero. The protected observations and the private shutdown diagnostic have receipt SHA-256 `a54b006149505ffb8b5fa5b57f6dfc16ab672c7abf0b83d51e5af339e68cb14d`. |
| G09, G10 | `1d133448` binds an authenticated target’s read-only phase return to the active Control dispatch. `a5da5b8f` also reads the stopped target’s physical deletion journal through its original Control route. The earlier 12-process trial reached target initialization but the original callback credential failed certificate binding. The new positive installed phase return, stopped target and cold replay require native results. |
| G11, G14 | On `eb309609`, macOS ARM64 passed format checks and strict workspace Clippy. The Python suite ran 518 cases, with three skips. The projected RustSec review covered 483 packages, with zero vulnerabilities and the reviewed LRU maintenance warning. Two source-package assemblies produced 37,829,500 bytes apiece with SHA-256 `ae5ebb2cc64310b4bdaa6621f3750138f287ab57900c64c410ecda173ea2a4ea`. The original upstream matrix detected an OpenRaft test compilation error, an exact-index membership assertion after a leadership change, and MCP stdio tests compiled without their transport. `fc6a1798` declares the two MCP test targets’ actual transport and includes them in the upstream test feature set. |
| G12 | The serial Linux ARM64 production build of `ceb83a1b` completed after the earlier OOM. The installed scenarios, native ABI, OCI lifecycle and live OpenBao/MinIO interoperability passed on this development guest. The native x86-64 run, reserved reference capacity, 24-hour soak and independently reproduced final native artifacts remain open. |

### November 21 native recovery and candidate selection

The qualification source is `903e297ba3e06a27caa8bd02408d6cff3f990b0e`, tree
`d19ba5d149ec4dc35f9be5dd9659cea75308f318`. The 2,395 tracked inputs form a
72,560,640-byte source archive with SHA-256
`ab3fc23aee6e2330d445f8ba4dd4fe09008e8196163c83bfe3bff77df2b350eb`.
The three native targets share this selection. Release acceptance remains open.

| Gates | Observation and remaining check |
| --- | --- |
| G02, G03 | On macOS ARM64, six pairs of native processes validated 512 documents across 32 text-indexed collections apiece. Snapshot schema validation in `7fe11ff2` retained about 0.73 MB at peak, compared with 5.5 MB when it constructed resident text indexes. The measurement covers the schema constructor. Applying-generation ownership and reference-system capacity remain open. Measurement receipt SHA-256 `4d0b1c9e2459ff406cf5e302f887f440f9b920f486b990ad4699fa89e634e5f1`. |
| G05 | The original Linux run retained exactly 17,531 acknowledged session rows. Its first repair regression reopened the disk in the original process with a different admission owner and was refused. In `d74d6075` the writer exits before the reader opens the same installation. On macOS the independent process verified the retained intent and purpose, wrote one terminal row, and verified replay in 5.45 s. The original Linux population, crash boundaries and complete enumeration remain open. Regression receipt `e3a93f2c1cb778ea304bf4c68340c0877952b871fb70b658e116917c0f49d8e5`. |
| G06, G07 | When OpenBao returned, the three Data voters reached route readmission and each retained a shutdown failure. `e60c0453` verifies this read against the installed Control routes, including a remote Control quorum. The native regression covered unavailable, unchanged, changed and absent routes. Full native provider-outage replay remains open. Regression receipt `773a201f3f66507b204b39b5d2047f0ddcab488d7c347631a4efef215de3a388`. In a separate concurrency trial all four workloads completed. Voter 6 retained its committed response for indexes 5023–5024 and exited 1. Three later cold Control probes returned HTTP 401 with expired credentials. |
| G09, G10 | One original Linux Control quorum reopened the same Prepare phase at revision 9. The Authority quorum returned the original enrollment receipt and no PrepareTarget receipt. Missing, wrong and subsequently corrected target readers in a separate trial all left materialization unresolved at revision 21. With the enrolled readers present at startup, a fresh 12-process trial confirmed materialization on all three targets by revision 27 and Start on all three by revision 38. Its Initialize became unresolved. The inspection replica needed the original three Start records and the Initialize record. `903e297b` registers this exact history when starting the inspection replica. With the original Linux request bytes, both versions of the native callback registry were exercised on an encrypted store. The earlier version withheld the four records in the startup path. The fix authorized them and rejected a foreign operation, principal and certificate. Original native observations `947c06f1ef143348213ee529806ae9e7f4bf99bbf39a726777a9903941085832`. Callback comparison `95c3e7af7f8d48b4a8ac971b32408bfa2c6f1658db2d4323491552c5e122ba5b`. Distributed completion, original-document readback and physical deletion after cold reopen still require native evidence. |
| G11 | `fc6a1798` declares the two stdio-only MCP test targets. All 520 product cases and 12 dedicated stdio cases passed on the corrected MCP tree. `1ae9cbf8` verifies merged and standalone Rustdoc groups from the same launch. `b489f39b` restores the bounded OpenRaft tests' crate-private access to the sealed storage trait. Native macOS strict workspace Clippy passed on that tree, and its Python suite ran 520 cases with three skips. On Linux ARM64 the production Server compiler received SIGKILL after 1,129.65 s in the build step. Peak child RSS was 6,470,772 KiB. That attempt produced no accepted binaries. The first-release inventory continues to require all 19 domains and 27 target-specific results. |
| G12–G14 | Two source-package assemblies of `903e297b` produced 37,841,877 bytes apiece, SHA-256 `ca88c9fb097bc895032b491500b7d51fa300ef8f74ed5636da9be3d963c0be29`. Native Linux x86-64, reserved ARM64 capacity, the uninterrupted 86,400-second soak, final interoperability and independently reproduced native deliverables remain open. The BOI environment owner controls live installation. |


### November 21 frozen source and native storage incident

The common qualification source is `0fea5408909db77751b39cea74a9db505f126a4b`,
tree `e8961347684cea0ce1852c434122bb71b24e5164`. Its 2,395-file Git archive
is 72,570,880 bytes with SHA-256
`ce243e92a99f574af639712917e02d9e2be6ad685e09c537b88f6c4c5ad573a1`.
The complete acceptance manifest remains open.

| Gates | Observed result | Outstanding proof |
| --- | --- | --- |
| G01 | The candidate passed eight native KV and Store deployed-format cases. KV compacted, wrote and reopened the encrypted fixtures. Store checked the envelopes, keyrings, archive chain and backup marker. | Run both deployed revisions through the candidate Server lifecycle and verify cold restart. |
| G02 | Commits `184c7f4e` and `f32fc1e2` retain unchanged unique keys across pinned generations. A 1,024-document edit with 16 unchanged indexes reduced measured live overhead from 4,295,788 to 9,964 bytes. All 124 enabled Query tests passed. Four independent processes read and wrote the same encrypted database using the predecessor and updated binaries. | Complete remaining applying-generation ownership and reference capacity workloads. |
| G03, G07 | The earlier ceb83a1b MinIO restore required 3,129,344 scratch bytes with 2,797,568 available after reservations. A retained drain timed out after 3,601.424 seconds. Cold status reopened the same operation in materialization. | Recover the original operation and verify restored documents on the final products. |
| G05, G13 | The Linux run resolved ordinal 17,531 to the original durable aborted outcome. Its journal reached 17,650 rows before a fresh virtual disk I/O failure. Btrfs became read-only. The externally preserved journal is 7,916,635 bytes. The copy mounted without tree-log replay contains 17,647 rows and is 1,345 bytes shorter. | Compare normal log replay against the external witness on a private writable copy. Complete 100,001 sessions, both crash cuts and independent cleanup enumeration. |
| G09 | Three enrolled targets materialized and started on 1d133448. Control reached Initialize revision 149. The attempt ended when a protected status read expired. Both native Engine regressions for the shortened issuer dispatch ticket passed. Commit `0fea5408` acquires the source response before the restart fixture starts the actual recovery. | Complete stopped-target cleanup, fresh membership inspection, fault cases and terminal readback on the combined candidate. |
| G11 | The candidate dependency scan checked 483 packages with zero vulnerabilities and one reviewed LRU maintenance warning. The fresh Linux run passed 12 dependency, 11 scanner and two socket-partition cases. The applicable 23 cases passed on macOS. The upstream 33-command suite passed on b489f39b. A later upstream link failed with ENOSPC. The candidate passed fmt. Its initial Python attempt exited 1. | Finish exact-candidate strict Clippy, focused and full workspace runs, and the installed receipts across 19 domains and 27 target results. |
| G12, G14 | All three macOS ARM64 production binaries compiled from the frozen source. Two source-package assemblies independently produced 37,844,262 bytes at SHA-256 `7d949645aea2f9babaef3b4020c72fd81d0fec980ce262d082a59dd91ac15ffb` on the same host. | Complete native Linux x86-64, reserved Linux ARM64, independent builds, the 24-hour soak and release artifacts. |

The failed development guest had two CPUs, 16 GiB RAM and a 200 GiB virtual disk.
An atomic copy preserves all 214,748,364,800 bytes of the virtual device. A
separate rescue guest mounted the copied ext4 partition and nested Btrfs
read-only with journal replay disabled. The original disk and the independent
17,650-row journal remain available for comparison.

The macOS ARM64 `kasumid`, `kasumictl` and `kasumi-authority` SHA-256 hashes
are `3977ed130f4a300d3f476f61e8cb3e74cd1c2783c1b31fbb93e6330299fa158c`,
`4953dcf6b15d96973d3ce767f052c0d5a10e57a97402c12d269b6c66fb13a3ce`
and `587cb607f896707092d4a6a184d07dbe750a1658cd8df1997f71817f9e6dd8f6`.

### Original storage recovery and native assembly inputs

| Goals | Observed result | Qualification still open |
| --- | --- | --- |
| G03, G07, G09 | On a writable clone booted with the original disk identity, the interrupted MinIO restore reopened its operation and detected the incomplete deployment binding. Two stop requests and a cold status read returned the same persisted cleanup proof, `be60d8d114651882c76b7703a13dfd17b86f05dd842f9727cbc5b8b4dfebd2ab`. A separate read verified all 815 encrypted backup files and the original node-group directory inode. The preserved 200 GiB virtual disk has SHA-256 `bd5f3c80fb6b4376df48650415533040c09d159197e6d80139a4a9d4d2258a91`. | Start a fresh restore from that checkpoint and verify every document on the final candidate. |
| G05, G13 | The original 520-session macOS installation resumed after a disk-space refusal. The driver killed processes at the claim and terminal-write boundaries. Across three cleanup pages, the 259 completed and 261 aborted records had the same SHA-256 before restart, after restart and after replay, `521f3e723a903853dbeab0e9c01e00c5d8bc8c550cef95de49e5a2c98eeed08e`. Cold verification took 1,033.4 seconds. | Resolve the three disputed rows in the separate Linux installation and complete its 100,001-session qualification. |
| G01, G08, G11, G12 | On `0fea5408`, macOS ARM64 passed strict workspace Clippy with all targets and features in 3,468.5 seconds. Its Python suite ran 531 cases with one Linux-only skip. The installed executables passed 16 lifecycle scenarios across 64 processes in 173.772 seconds. | Finish the focused and full Rust suites, including the original shutdown and cold-reopen cases, on the release revision. |
| G11, G14 | The first native macOS notice audit rejected two OpenRaft workspace members. Packaging fix `5280dee4` verified the reviewed Git-vendored license files for both. A replay verified all 407 compiled packages, including 390 registry packages, with 709 notice records and 269 distinct texts. The native assembly declaration separately verified 21,499 input files and bound the 17,081 files consumed by package metadata and Python imports. | Run both owned assemblies with passing functional evidence on each native target. |

### November 21 cold recovery and native qualification

The common qualification source is `17a327a4a53b1c5e4bcea28d2e08a5992fef9baa`.
Its 72,591,360-byte Git archive has SHA-256
`cb1aec082582b47a491d1e0996df4dc4979470ce9b84ec55bda40a2aebe84d78`.

| Check | Observed result |
| --- | --- |
| macOS ARM64 installed lifecycle | The three native products passed all 16 installed scenarios across 64 processes in 54.026 seconds on a 16-core, 128 GiB host. |
| Compatibility | The clean and interrupted 12140939 images and the cf9959f1 image passed eight KV and Store fixture checks on macOS ARM64. |
| Dependencies | Strict workspace Clippy passed in 2,162 seconds. After an initial OpenRaft membership timeout, all 33 upstream commands passed on the same source, covering 4,199 tests. Independent macOS ARM64 and Linux ARM64 scans checked 483 packages and reported zero vulnerabilities. The LRU maintenance warning has a reviewed source patch. Both scanners completed their yank checks. |
| Backup replay | Separate native Linux ARM64 processes cold-opened the original installation and recovered the six original public outcome fields for ordinals 17,647 through 17,649. The three API calls took 0.436, 0.331 and 0.114 seconds after cold reopens of 3,276, 2,308 and 1,968 seconds respectively. The repaired caller in `8133f770` resumed the original population across the interrupted witness journal. |
| Record and cleanup boundaries | The restored original and two independent Linux trees matched all eight boundary-evidence files. A 65,536-byte record was accepted and a 65,537-byte record was rejected. The 300-object cleanup returned 256 objects, 44 objects and then zero. |
| Local checkpoint verification | `9fde8161` verifies the restored backup rows and their point lookup through one pinned view. The combined Engine tree passed 14 focused selectors. |
| Stopped-target recovery | The Linux ARM64 development run on `0fea5408` ended after 12 observations could not find the target journal. Six native processes on an isolated clone reopened the same installation. The direct Control leader call returned Unavailable in 0.154 seconds. End-to-end recovery remains open. |
| Packaging | Two independent source-package builds produced 37,849,462 bytes each at SHA-256 `a39e24291fc8f41d58782e9580ff77bb5493ab5fb746d30912e77670e160847d`. The macOS notice inventory verified all 407 compiled packages. |

| Native macOS ARM64 binary | Bytes | SHA-256 |
| --- | ---: | --- |
| kasumid | 133,498,016 | `2f9b7424b577e60a52ae5c86f14ac40bb70ad41bd8d854265bc7bf34c641c0e4` |
| kasumictl | 9,024,608 | `460ae6b6813f8c281b0243028db52e8e427ce9b50129c8736a5e4cbf9d9a5546` |
| kasumi-authority | 93,720,432 | `b6d32f2df9eca2f720e086b7435a140453a7665567e705225d7fa9155580f9e0` |

Qualification still needs a reserved native Linux x86-64 runner, an uninterrupted
reservation on the 2-CPU, 16-GiB, 200-GiB ARM64 reference or its replacement,
the 24-hour soak, native assembly comparisons and final release authorization.
The original fixture blob is on origin/master. The BOI environment owner conducts
the live installation.

### November 21 native qualification and recovery findings

| Goals | Source and observed result |
| --- | --- |
| G01, G07, G10 | On `78b0ba4e`, the native macOS Server reopened the two deployed formats after writes, compaction, a killed store and a failed read drain. The cancelled target shutdown reopened its original journal. Seven protected probes passed, including readiness over 129 groups. The focused Engine, Store, KV, Raft, Authority and Server binaries passed 9, 4, 4, 1, 3 and 13 cases respectively. The original Engine log collector interleaved an expected physical capacity refusal with a libtest result. A replay of the same binary verified stdout and stderr independently. |
| G02 | `e4463e5d` and `9f22758c` moved cursor continuation versions and bodies to a pinned primary reader. Both initially retained the applying generation. `13b51a6d` charged the captured reader against the cursor budget. `0b68ce32` retained the verified bootstrap body resolver and released the original generation. The next page returned the original version of a deleted row after another commit. On `c8fa8dbd`, a scalar unique seek released the live descriptor map after its first authenticated page. Each final component passed 15 native Engine tests. Applying-generation descriptor and posting ownership and the full capacity matrix remain open. |
| G05 | Native cold replay verified 20,000 contiguous requests on the original cohort. The hash of the 17,647-row pre-interruption prefix was unchanged. Independent verification of a separate 520-session archive matched each original request to its checkpoint or abort across four cold enumerations and three cleanup pages. The acceptance floor remains 100,001. |
| G07, G09 | A native nine-voter `0fea5408` cluster failed to reopen its three original Data owners within 100 seconds after the same suspended Authority processes resumed. In a separate OpenBao fault all three reopened the same checkpoint after a cold unseal. One Data voter retained the access-stage failure and exited 1 on shutdown. `a65fedf6` distinguishes locally elapsed lease acquisition from an error returned by an Authority member. In a separate twelve-voter process study, three targets signed cleanup, but reading the completed physical journal requested a fresh grant against the expired StopLocal intent. `0ad93bb8` checks the retained signatures and terminal journal under the observer's current authorization. After correcting the test fixture's commit order, `909a9f7e` passed all 24 target-journal open cases. Native process-level comparisons are still required. |
| G11, G12 | Frozen `78b0ba4e` passed formatting, strict workspace Clippy and 4,199 upstream tests in 33 commands. The 534-case Python suite had one Linux-only skip on macOS. Both Linux socket ownership/partition cases passed on native ARM64. Advisory scans on macOS and Linux ARM64 covered 483 packages with zero vulnerabilities and the reviewed patched LRU maintenance warning. The three production macOS ARM64 binaries took 3,283 seconds to build on a 16-CPU, 128-GiB host. They passed 16 installed lifecycle scenarios across 64 processes. The initial installed-source check rejected generated Python bytecode. |
| G14 | Two source assemblies reproduced 37,855,219 bytes at SHA-256 `6850027b30433c4cfc7d32df1670c6169df2376aa8cdae8a250429dba9b92aa3`. Two executions of the native Cargo inventory builder produced identical SPDX, notices and 269 license texts for 407 compiled packages. The SPDX file has SHA-256 `96ccd0a3c6024694a57e82b5f2dffbb0a3b1e2e4fe6737ff100b995fc61e2281`. The original inventory attempt rejected an undeclared driver. Independent binary assembly, signatures and release publication remain open. |

The original source, process records, resource limits and hashes remain under
`~/.local/share/kasumi-release/20261118-72b21a40`. Its `GATE-SUMMARY.md`
links each check and each outstanding release gate. The native Linux x86-64
placement and the reserved ARM64 capacity and soak interval remain owner inputs.

### November 21 storage ownership and native recovery comparisons

| Goals | Incorporated change and measured result |
| --- | --- |
| G01, G11 | On `ff178bb9`, eight native macOS KV and Store fixture cases passed across the clean and killed `12140939` images and the clean `cf9959f1` image. KV wrote, compacted and reopened the groups. Both ARM64 advisory scans covered 483 packages, with zero vulnerabilities and one reviewed LRU maintenance warning. The 33 upstream commands passed 4,199 tests. Eleven secret-scan exception tests passed. Gitleaks found no leaks in the exported files or the 1,540 commits reachable from this candidate. |
| G02, G03 | `844ed499` binds an ordinary page to its original verified primary, body resolver and selected collection. `2e5cdf8e` removes the duplicate uniqueness pass and stops retaining document IDs in the temporary validation sets. Schema replacement reduced stored-body loans from three to two while preserving the duplicate-value conflict. On 16,384 rows with 240-byte IDs, single-field validation peaked at 1,412,928 allocator bytes, down from 8,568,596. Three-field validation peaked at 3,816,384 bytes, down from 9,027,226. On combined `ac8c4b1e`, 125 active Query tests passed, with two ignored. Nine Engine selections passed, including encrypted reopen, snapshot install, text, paging and the change feed. A two-collection test verified that the unselected planner was freed while the page retained the original layout digest. |
| G02 | `9ae90c0f` shares a sparse field's presence set with its covering scalar posting when cardinality proves they have identical members. Two simultaneous generations of 2,048 and 2,049 documents across 512 sparse fields peaked at 81,170,966 allocator bytes, down from 140,499,478. The regression covers empty arrays and subsequent writes. Merge `58062a29` joins this change with both reader and schema-validation changes. Full physical ownership and installed capacity qualification remain open. |
| G05, G06, G07 | By the native observation on November 21 the original cohort had recorded 22,099 of the 100,001 sessions. A separate cold benchmark stopped at physical OpenChild/InvalidData before native store opening. On matched `ebc5cade` all three original Data voters reopened after the Authority processes resumed. The corresponding baseline reopened none in 100 seconds. The corrected run returned the original document and checkpoint, and all nine voters and both providers drained in 73.292 seconds. Withdrawing and restoring the original OpenBao grant and restarting the provider passed in 74.927 and 100.594 seconds respectively, including all eight protected inventory pages. The original v2-only File Control voter separately recovered its signed revision 10 retirement and all three Control voters drained. |
| G09, G12–G14 | The original failed stopped-target observation and native linker OOM remain in the evidence archive. The Linux x86-64 input bundle for `ff178bb9` passed readback of all ten files, including the native OpenBao, MinIO and Gitleaks executables. The bundle SHA-256 is `84236fa7e6eaeee1d480d1efb768779a5c12d644a278ae54d8c6fa777a4bb08d`. Native x86-64 execution, the reserved ARM64 reference, full installed HA recovery, the 24-hour soak, independent assemblies and release approval remain open. |

### November 21 late native runs

| Goals | Source and observation |
| --- | --- |
| G01, G07, G10 | On `14c7086b`, eight KV and Store fixture cases and four native Server cases wrote and reopened the deployed formats. The Server passed the cancelled target monitor and journal reopen case and seven protected observability cases. A separate installed Control test failed after an ambiguous Start deadline. The `e16b7421` fixture follows the original operation ID and queries the quorum-confirmed leader. Two native repetitions passed in 296.871 and 477.785 seconds. |
| G02, G05 | The original Btrfs case on `14c7086b` reported eight 512-byte sectors before inode-cache reclaim and zero after reclaim for the same inode, directory entries and timestamps. Commits `1fbc725a` and `9e221683` conserve the directory reservation and keep the observed allocation available. The same native harness on `cb8eb32f` accepted the unchanged directory and rejected an equal-length rename. Its 136-byte inode entry reduced the two fixed tables' reservation by 134,217,728 bytes relative to the first repair. All 1,003 enabled macOS Store unit tests passed, with seven ignored. Merge `5d6a5257` includes the repair and the Control fixture. |
| G05 | On native Linux ARM64, independent writable views of the original 120 GiB volume on `712715a7` and `de8015ce` returned the same public backup outcome from the same 17,647-session journal. Cold recovery took 1,624.964 and 1,524.097 seconds. Both runs left the source volume unchanged. The 100,001-session population, interruptions and exhaustive cleanup remain open. |
| G08, G12, G13 | On `a65fedf6`, one native rehearsal stopped after 102 successful protected readiness probes. A second run completed 240 authenticated operations through credential renewal, MinIO archival, backup and learner enrollment. All ten Kasumi processes and both providers exited cleanly in this 212.113-second run. The earlier `17a327a4` run completed 232 operations but four Data processes reported retained owners. The reserved 86,400-second soak remains open. |
| G11, G14 | On `14c7086b`, formatting, strict workspace Clippy, and the focused Engine, Store, KV, Raft, Authority and Server suites passed. The first upstream matrix failed the OpenRaft partial replication deadline. Five isolated reruns and all 33 commands in the full repeat passed. Both native ARM64 advisory scans found zero vulnerabilities among 483 packages, with one reviewed maintenance warning. macOS built all three production executables, passed 16 installed scenarios across 64 processes, verified 709 notices for 407 compiled packages, and reproduced 272 SPDX and notice files. |
| G11, G14 | The earlier native macOS functional run on `17a327a4` passed all 22 gates. Its export omitted OpenRaft's retained log, and its first package assembly wrote Cargo compiler metadata into the frozen source. Commit `0c71f7b3` exported all 2,605 files and verified the original 9,197,902-byte log on archive readback. The 4,088,156,160-byte archive has SHA-256 `f2d205a8c4f97b65da20bec5f74380b952b094b7c852022e49c780685b0e8762`. Commit `2c6fd9eb` directs Cargo metadata to its private attempt directory. Its native replay returned all 448 packages and preserved the source inventory. |

Release status remains **HOLD**. The `14c7086b` manifest preflight accepted zero of the 27 required target results across 19 domains. Its supplemental ARM64 compiler reached the 6 GiB cgroup limit while compiling the server. The kernel failure and the independent 11 GiB retry are recorded separately. The upstream fixture is already on origin/master. Both deployed-format readers and writers remain supported.

### November 21 index ownership, backup recovery and package installation

| Goals | Source and observation |
| --- | --- |
| G02, G03 | `7eaa2e18` shares index roots across schema-only replacements. On 2,048 documents with 128 fields, two pinned generations retained 18,401,676 allocator bytes, down from 36,757,748. `b26367a2` pages fieldless IDs from live or archived primary rows. The installed encrypted comparison used 1,024 long IDs and retained 240,130 fewer bytes at installation and 240,167 fewer after cold reopen with 1,025 rows. A registered cursor still returned the original bodies after replacement. |
| G02 | `e7907e76` charges normalized UTF-8 bytes when cutting persisted text shards. The previous writer counted 11 bytes for a 17-byte normalized input across indexed values. The corrected regression and all 128 enabled Query tests passed. Two Query tests were ignored. |
| G05 | The native population on the original encrypted 120 GiB volume persisted 25,090 of the required 100,001 session outcomes. The next completion returned UnknownOutcome. The failure archive retains the 11,263,814-byte journal. The cold continuation uses the same session, command and installation to resolve the ambiguous outcome. |
| G07, G09 | The `14c7086b` workspace run withheld a Control phase read when the commitment audit reached its five-second deadline. `af20002f` retries observation of the same recovery operation within the original fixture budget. Two native repetitions of the three-member case passed in 118.50 and 94.30 seconds. |
| G11, G14 | Two native macOS ARM64 package assemblies on `17a327a4` produced the same 72,757,832-byte archive with SHA-256 `69731ff4ad9f243bc24b1dcbb144a816b3a40d7f651ac30d49fd68c87ebe42f1`. The original installed smoke failed at initialization because the retained tenant-audit policy had mode 0644. A fresh attempt with owner-only inputs passed all six scenarios, including restart and clean shutdown. `68175f87` creates retained input files with mode 0600 even under umask 0022. The package, assembly and domain-runner test suites passed 31 cases. |

The two assemblies used the same verified native products. Independent native builds on all three targets, the reserved reference capacity run, the full HA fault matrix and the uninterrupted 24-hour soak remain release requirements.

### Native journal, storage and release artifact results, November 21

The qualification archive at `aef27e3b3c82619f5d6e6118d9b6ca52e494dafc` has SHA-256 `9c7827d4229cf2fd8c78b44c4290e97fb1ec04054fa1ed9f377fac0b1cca50cb`. Subsequent master commits below require a new common-source qualification. The release manifest still needs all 27 target results.

| Goals | Source and observed result |
| --- | --- |
| G01, G07, G10 | Native macOS ARM64 Cargo on the archive passed eight KV and Store deployed-format tests. The Server passed four further deployed-format cases, seven protected observability cases and the cancelled target shutdown followed by reopening its durable journal. The last case took 3.160 seconds. An independent focused Server runner initially rejected six generated Python bytecode files in its source inventory. After preserving the files, removing bytecode generation from the reporter and verifying all 2,397 original source files, the runner passed its 14 cases. |
| G02, G03 | Master includes `93a0cb6b` and `2e016c70`. The first preserves the actual deadline and cancellation error during encrypted primary reads. The second builds fieldless installed indexes using canonical rows. The 32,768-ID comparison reduced transient construction from 8,749,552 to 1,232 allocator bytes and snapshot validation from 8,751,140 to 4,652 bytes. Native encrypted 128-to-129-row comparisons passed on both builds. At 1,024 rows both sources returned an ambiguous write at the ten-second deadline. Same-key checks after cold reopen recovered revision 34 and both affected rows. Native stacks placed the delay in postcommit collection of encrypted primary rows. The original failures remain in the release evidence. |
| G05 | The original 25,090-session journal reopened. The same session and request recovered the previously ambiguous completion. The continuation processed more than 25,700 sessions. The 100,001-session population, further interruptions and exhaustive terminal verification remain open. |
| G11 | `9ad41467` verifies the complete set of transported native journals against operator-held heads. Replaying all four original macOS attempts from another path took 203.364 seconds and retained two failures and two passes. Its Python suite reported 541 tests with one Linux socket test skipped. `aa8beaa3` makes the isolated verifier and domain adapters share the final check of the files they read. |
| G11, G14 | `0272e6a2` composes the release manifest from retained evidence. On the qualification archive it verified ten deliverables and four configuration declarations. The complete-manifest invocation rejected the missing gates and produced no final manifest. `37281275` derives the operating-limits document from both capacity runs, concurrency, all 15 benchmark cases and the full-duration soak. The final verifier checks the document against those measurements. |

The native host and duration limits, original command logs and SHA-256 records are retained in the private qualification directory under `candidate-aef27e3b`, `three-native-attempt-journals` and `no-field-initial-construction`. The deployed fixture is present in upstream `6ae92f26` as blob `e6f7e3a19bf256e5df825140ceccbec63da98e6d`, 28,798,481 bytes.

### November 21 Claude Desktop integration

| Goals | Incorporated work and qualification evidence |
| --- | --- |
| G01, G07, G10 | On `aef27e3b`, the native macOS ARM64 focused suites passed 9 Engine, 4 Store, 4 KV, 1 Raft, 3 Authority and 14 Server cases. The Raft case exercised cancellation and the original durable callback. The separate Server shutdown case reopened the target journal in 3.160 seconds. Native Query passed 129 tests with two ignored. |
| G02–G04 | Two retained 1,024-row writes reached the client deadline. Cold reopen and replay of the original key returned revision 34 with all 1,025 rows. Native samples showed that postcommit garbage collection could scan 4,096 authenticated slots before returning. `c22ac62b` yields after at most one 32-row disk page. On the earlier integrated source `0775e4bd`, all 690 native KV library tests passed in 119.824 seconds with peak RSS of 4,734,156,800 bytes. |
| G04, G07 | The original feed cancellation test failed an exact cache comparison. Four same-binary reruns passed three times and exposed a concurrent resident allocation on the fourth run. `2f382317` holds background database maintenance outside both exact read-ownership measurements. |
| G05, G11 | Fable 5.2 reviewed the actual receipts and the original lifetime-limit decision. The release contract requires 100,001 distinct sessions including at least 257 permanently failed or aborted. The prospective profile schedules 520 complete and 99,481 aborted sessions. On the development installation, cold replay resolved the original request at revision 50,639. The recovery guest stopped with 25,952 sessions observed. `7740df75` verifies the qualifying process populated its complete cohort and supports a 14-day session process budget. Its 36 related tests passed. |
| G11, G14 | Opus 5.5 produced the independent native build runner in `bd1757fd` and documented its Rustup input in `64d14f7f`. Eight producer tests passed. `0a1830d2` journals OCI assembly on native Linux and binds both delivered files to the original package, build and process. Eleven OCI tests and 38 release-verifier tests passed. |
| G12, G13 | Fable's live lookup found zero registered repository runners. The native ARM64 `release-build` guest passed preflight at 2 CPUs, 16 GiB and 200 GiB before it stopped. Direct read-only recovery of its disk found 500 Cargo artifact messages and zero production executables from the interrupted `aef27e3b` compilation. All three prior nine-voter plans use development products. The measured soak lasts 86,400 seconds and the runner budgets 93,660 seconds including startup and drain. Native Linux x86-64 placement, the reference reservation and independent qualifying evidence remain outstanding. |
