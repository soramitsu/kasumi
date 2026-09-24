# Authority and benchmark mandatory disk-memory callers

Prepared only under `target/installed-disk-validation/authority-bench-callers` on
main/master. This package is **unapplied and uncompiled**. No Cargo process was
started and actual source is unchanged. See `manifest.json` for exact source and
patch hashes and prerequisite hashes. This is a direct first-release API
migration; there are no compatibility constructors, inferred governors, or
optional admission arguments.

## Scope and ordering

The eleven-file patch changes all direct store-memory callers in
`kasumi-authority` and `kasumi-bench`, including their Cargo feature declarations.
Authority production code already receives storage, budget and snapshot owners;
it does not construct disk governors. Its tests now supply the real exact core
through those owners. No engine/server implementation files are included.

Apply only together with store metadata revision 2 (`10ebc1c6...`), the MemoryCore
store-trait adapter, and engine fixture helper (`e3bebad9...`). The loopback
subprocess also needs the prepared server example configuration's explicit 2 GiB
new-install total. The package itself does not rewrite an AdmissionConfig default.

## Authority ownership

`PhysicalFixture` retains private persistent and scratch TempDir guards and one
`FixtureStorage`. It constructs the exact NodeAdmission/core before either disk
owner, and retains the owners through every reopen. Each modeled authority voter,
backup source, and target uses a separate physical fixture. Target generation
files, independent target journals, and materialization-file replay use their
actual target's persistent and scratch owners. Source backup files use the
source's already admitted persistent owner, with no unused second disk allowance.

The old process-global request-budget governor is removed. Every authority
service receives a direct resident request-metadata reservation from its storage
core, and its exact facade creates the real admitted SnapshotBufferOwner. The
request-job-only unit tests construct explicit local admissions and compare real
reservation deltas against the unchanged bookkeeping baseline. No unrelated test
provider replaces a real NodeAdmission core.

The original generic fixture policies are retained (256 GiB scratch and generic
persistent file policy). PhysicalFixture uses `FixtureStorage::open`: it resolves
the previous canonical total and adds only the actual eight new disk leases. It
does not add bookkeeping twice, expand operation allowances, or increase RSS.
The separate roots replace accidental shared parent-directory ownership between
fixtures that already modeled independent processes and admission governors.

## Embedded benchmark accounting

One retained BenchmarkStorage owns the original single scratch quota (64 GiB,
minimum free 256 MiB), one persistent root, and N distinct NodeAdmission facades
on their exact same MemoryCore (N=1 local/text; N=3 replicated). This scope lives
outside Databases and survives complete close/reopen. Databases drains its actual
NodeStore owners after tenant/audit shutdown before clearing them.

For original default policy C, let T be its resolved total, B(C) the core plus
first-facade bookkeeping, M(A) the shared core bookkeeping under aggregate policy
A, F(A)=B(A)-M(A), and D the actual single persistent+scratch metadata pair, with
all eight boxed reservation fees. The new total is:

`N * (T - B(C)) + M(A) + N * F(A) + D`.

This preserves the exact prior combined payload allowance. Operation slots,
reservation slots and core startup scopes are checked N-fold sums; snapshot
startup inventory remains the original per-facade limit. High/low RSS policies
remain unchanged. A host unable to fund this aggregate is rejected; there is no
higher-RSS fallback. The aggregate allows replicas to share the original combined
allowance, whereas the old unrelated cores partitioned it. No extra unplanned
facade is constructed: FixtureStorage retains the first audit facade.

Benchmark document/tenant/operation limits, workloads, deadlines, timing config,
scratch quota and capacity-report semantics are unchanged. Loopback subprocess
configuration keeps the full installed 1M/4096 metadata policy and supplies a
private persistent root alongside its scratch root instead of accidentally
retaining `/var/lib/kasumi` roots from the example.

## Prepared checks and remaining evidence

- `patch-check.json`: exact before hashes match current source; `git apply --check`
  succeeds.
- Target-only Rust formatting succeeded for all nine Rust files.
- `fixture-audit.json`: all 44 original test entrypoints and original Duration
  expressions remain unchanged.
- No obsolete zero-argument ScratchDisk fixture, three-argument NodeStore fixture,
  or unrelated global authority request governor remains in this caller overlay.
- No direct authority/bench apply_command, fixture_snapshot or candidate-encoder
  call sites were found requiring the separate mandatory-disk codec API change.

No Rust typecheck, runtime tests, benchmark execution, RSS proof, or platform
allocation qualification is claimed. After coherent integration, run workspace
all-target/all-feature check and strict lint, authority library tests, and the
embedded benchmark's failure-workload test. Actual heavy benchmark and subprocess
workloads remain release evidence work; their input coverage is not reduced.
