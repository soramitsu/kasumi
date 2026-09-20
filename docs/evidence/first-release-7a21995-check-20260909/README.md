# Frozen 7a21995 compilation and store gate failure

This is the actual bounded execution of the previously prepared plan, not a final
release acceptance. Source `7a21995b7488980f63cf100dbd90eb0d0680c520`, tree
`f5506136b3650fca75e728e70270a53cdfe29862`, and all tracked inputs were unchanged.
The run lasted from 2026-09-09 14:32:54.763390 UTC through 14:36:54.022125 UTC.

| Gate | Original deadline | Actual outcome |
| --- | --- | --- |
| Locked offline workspace, all targets/features check | 900 seconds | PASS; exit 0; 150.676 seconds; PG 80183 drained |
| Workspace formatting | 300 seconds | PASS; exit 0; 1.501 seconds; PG 81367 drained |
| Complete store library, all features, one test thread | 900 seconds | FAIL; exit 101; 85.814 seconds including wrapper/drain; 126 passed, 1 failed, 2 ignored; PG 81422 drained |
| Strict store Clippy, all targets/features | 600 seconds | UNRUN after the original stop-on-failure rule |

The inner store process reports 85.802 seconds and the test harness 44.87 seconds;
these are narrower durations than the full gate. All three process groups had no
remaining processes, signals, drain errors or timeouts. No follow-up gate ran after
the failure. Runner and process-helper hashes, exact commands, executable inventory,
source and dependency provenance are retained in the unmodified evidence JSON.

The one failing test was
`node_store_ids::tests::immutable_identity_derivations_are_stable_and_domain_separated`:
its assertion that `administrative_generation(a, "../tenant", c)` returns an error
failed at line 172. The later canonical-management checkpoint had already removed
that obsolete API and its dedicated assertions as part of deleting the alternate
administrative generation lifecycle. This does not turn this recorded failure into
a pass. The remaining identity functions and canonical source require their own
actual checks; no assertion was weakened to make this frozen run succeed.

All other 31 required regression names passed, including explicit existing-state
catalog checks, retained fresh/existing catalog owners, physical file custody,
real subprocess crash recovery and cancellation of a drain after a joined panic.
The two ignored top-level entries were the crash subprocess helper (invoked by its
parent regression) and the separate MinIO test requiring explicitly installed
Docker host/configuration/workspace. Actual MinIO interoperability remains open.

The raw logs, source manifest, original plan, exact runner and full evidence JSON
are copied byte for byte. SHA-256 values:

- evidence.json: `f49ed9f7b9adcbc718d3942807c88459ef5101143e55fa644681f4a364741822`
- source-before.json: `d667c01e0333e01f2d83f5afc8dd230df4b417e8b86245a58353ec0c72a8b43e`
- plan.json: `fa4c66fe1a70c6fad08d0290cfe92635739f179f7db02bbabed029e5099483b7`
- runner.py: `ad3d647fbb73d9d32e04e4e202814f68aea2cb5aa80acbed03a10fa8a3855a6f`
- workspace-all-targets-check.log: `c1e6cbe3a51c244fb3b2fdef27126ede0a4d47c2692059edc06d52c8e297b069`
- workspace-format.log: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- complete-store-library.log: `9c0c70b0fa0e7eb49108b1d23b0b6b24dcb28556469ad4f5a0ba4a0aa2d67ae0`

This source excludes canonical administration/its real TLS coordinator fixture,
explicit target/local catalog lifecycle, acknowledged ordinary catalog errors,
authority request drain, and foreign uncommitted ordered-seek work. Full workspace
functional/strict/production/platform gates, real 3 GiB capacity, actual external
providers and 24-hour endurance remain unfinished.
