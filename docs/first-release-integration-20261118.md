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
and the nine voter placements. Linux-hosted MinIO requires the approved pinned image
and an owned Docker endpoint. Preserve the independent build and physical
failure-domain attestations with the native evidence.

The format owner acts only if retirement beyond the two pinned revisions is
proposed. BOI's owner handles its live installation. The dependency update has been applied and the existing LRU disposition is recorded. Release owners
can authorize publishing the qualified candidate after all gates pass.
