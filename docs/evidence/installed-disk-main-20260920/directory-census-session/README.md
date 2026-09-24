# Frozen retained-census successor

This package is a target-only, directly migrated first-release census implementation. Its 15-file successor applies to the frozen 48-file fixed-map proposal; its 49-file cumulative patch applies to the recorded actual master baseline. No actual source was edited and no Cargo command was run. Every cumulative source baseline still matched actual source at this freeze. Both target-prefix apply checks and exact target application passed.

- `census-session.patch`: `b755f21124065b94d96db325c6d2ac5031335c1f338218c933986a40b8ac3569`
- `cumulative.patch`: `a3ab99fa45947e5c44e031c849c61892f32aa27e746e9067b8baad6a88ee29f9`
- `manifest.json`: `afc7f858b97f4ad1e30cd2c1438e9c25c9614d22e5972d4475665923ee15a665`
- Final source snapshot: `review-snapshot-04`, files manifest `238a542dfdab67cd1a42ba9ab95cbbf95f86207c7d531cf1634153247b29f2c2`.
- Prior dependency: `directory-fixed-maps/cumulative.patch`, `ef2c07b01c7d4a9acc7b5e606a023cb530cda354a5ec342d60bf3ee9c3a302f0`.
- Disjoint caller dependency: `directory-policy-callers/callers.patch`, `7c030bba5066762fd99321f0ae0c6465e22aca071ecd6c0ca7d55961187d0ca5`.

`DESIGN.md` explains the code and remaining limits. The required policy is `max_persistent_files` (F), `max_persistent_subdirectories` (D, excluding roots), and `census_work_per_step`. Both retained banks fund F+D+R. The original default F=D=1,000,000, work-per-step=1,000,000, 4096 handles and 2 GiB total policy are preserved. The checked whole native-call bound F+4D+3R includes dots and EOF. Every Pending step retains the same candidate, root/stream descriptors, progress and caller-held serialization. No scan restart, arbitrary retry cap or public async scheduling contract is introduced.

Initial census now registers the already-admitted resource aggregate before its first native stream. Uncertain close retains the registry owner, exact first native errno/count, physical locks/banks and actual leases through errors and unwinds. Ordinary closed failures remove the actual registry backing before resource/lease retirement. Private post-census Arc custody retires its allocation with `Arc::into_inner` before NodeDisk fields can credit memory on publication failure. The primary error remains downcastable alongside a typed independent close context. Successful publication accepts complete shared promises before installing the owner.

Operational directory cursors use their retained child count plus dot entries as their whole returned-entry bound. Runtime files retain their independent full file quota. Supported generators, fixtures and the standalone example use the three required fields directly. The only supported-source occurrences of the old field name are intentional serde rejection tests. Historical evidence remains unchanged.

## Native evidence

`native-02` is the final scoped gate: production and test compilation succeeded, production geometry ran, and **37 tests passed / 5 existing device tests filtered**. The five command PGs 75860, 75862, 75873, 75889 and 75894 all exited zero, drained, and preserved the exact executable hash. All 1727 consumed/frozen inputs and additional actual crates/vendor/Cargo source witnesses were unchanged across the gate. Root independently verified termination before resuming its own work.

- Results: `0ee2a604af58bc0d495f647c5d973424287e831cffa93fab0e8b7ea81f611970`.
- Test executable: `0369e08b71d08ad2bb1b426073acc7eb9458132f564de65765324764e84fdcf0`.
- Compiler: pinned Rust 1.97.1, `8bab26f4f68e0e26f0bb7960be334d5b520ea452`, aarch64-apple-darwin.
- Each native command had a 120-second owned process-group bound and `TMPDIR` under the repository's target directory.

The twelve census tests cover seven and all eight managed files under the original tiny N=8 counterexample; full F=8/D=8 traversal in eight-call steps; retained native stream identity; independent logical cardinality excess; cancellation, incomplete finish and unwind; typed dual-error retention; old ledger/shared-promise preservation; registered initial uncertain-close outcome through return and panic; actual root/ancestor FD and registry allocation retirement before credit; private Arc backing retirement before credit; and an actual initial shared-promise overflow. The remaining 25 tests retain the fixed-map, Weak ownership, enrolled-cursor and typed-ledger coverage.

`native-01` also passed all 37 tests. A subsequent source review found that its promise-overflow fixture could receive typed RegistryBusy under integrated parallel testing. The final fixture retains the same physical anchor/pending aggregate and uses the existing bounded registry-only retry helper with fresh zero-pending registrations. Its original overflow assertion remains required. `native-02` preserves that separate successor; the original run is unchanged. Expected caught-panic messages in stderr belong to explicit unwind tests, whose tests and process exited successfully.

Native source extraction and excluded external test modules are recorded in each run's `copies.json` and `selection.json`. This gate uses exact proposed storage modules and the frozen real TestDiskMemory extraction, not installed MemoryCore. Root `node_disk/tests.rs`, disk-memory tests, external directory/namespace tests and integrated server serde tests are outside this standalone execution scope. Their proposed bytes remain available for later Cargo integration. No full crate, workspace, Clippy or integration-test result is claimed.

The measured production metadata requirement is 1,331,918,436 bytes for the owner, 4,576 for its registry node, 8,304 for the device, and 4,160 for device registration. That leaves 815,548,172 bytes beneath 2 GiB before other owners/reservations and RSS. This is **not** a whole-server fit proof: the actual high-water condition includes RSS plus all existing reserved owners, and physical native/allocator allowances remain unqualified.

## Review and qualification

Read-only reviews are in sibling `directory-census-session-independent-review`. Earlier snapshots preserve the initial diagnostic-custody blocker and later private-Arc publication blocker. Final source incorporates both corrections; no rejected draft was installed. Formatting PGs 74566 and 75500 exited zero and drained. `final-checks.json` records target apply validation and final native receipts; `raw-sha256.json` binds the completed package bytes.

The original tiny-N failure remains independently frozen in `namespace-census-contract-gap/native-baseline-01`; it is not relabelled as successful reopening behavior.

This is a completed bounded census prerequisite, not release-ready directory adoption. Managed mkdir/rmdir and remaining raw caller migration are still unfinished. A caller-supplied directory policy ceiling still does not prove a supported filesystem's pre-effect physical allocation bound. Native memory/allocator bounds, whole-server RSS plus reserved high-water fit, and integrated caller/configuration gates remain open. The retained error contract is the first native close errno and total unretired count; it does not archive every stream's failure or retain opaque panic payloads.
