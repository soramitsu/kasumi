# Matrix interpretation

This run uses the source that passed the Mac and Linux validation gates. Its
remaining unrelated host activity is recorded explicitly; it is not an isolated
machine measurement and supports no external database speed comparison or launch
SLA. `execution.json` records the temporary `caffeinate -i` wrapper, which inhibits
automatic idle sleep only while this driver runs.

There are two deliberately different source hash scopes:

- Matrix `358b623bee1e6a9189cdec2aeadbe047b4e1499e179386be4613b3684708db44`
  includes Cargo manifests/lockfile, crate sources, scripts, applicable `.cargo`
  files and toolchain files using the extensions listed in the matrix driver.
- Inner local harness `81ca9f085c67f48d3bc1acf40948bda70e97a202306a6f0fe379c4bf07842e41`
  includes root Cargo.toml/Cargo.lock and crate `.rs`, `.toml`, and `.proto` files.

Both were independently recomputed and matched during the run. Executable
SHA256 hashes identify the built binaries; per-result hashes bind completed
observations to `matrix.json`. The inner reports' hardcoded preliminary
measurement labels are preserved. Frozen source provenance does not make one
loaded-host run a repeatability study or maximum-capacity validation.

Workloads run sequentially. Local owned point reads precede shared-handle reads
using the same deterministic 1,000 IDs, followed by writes, mixed traffic and
queries. A shared read may therefore benefit from cache warmth left by owned
reads. Raw maps run in a separate process and have different representation and
access costs. Native RPC precedes MCP on the same server; each performs one
untimed warmup read per credential before its measured workloads. Cache,
allocator, receipt and audit growth can affect later workloads. No ordering
randomization or repeated-run confidence interval is claimed. At 1,000 samples,
the p99 tail comprises roughly ten observations.

Embedded reads, native RPC, MCP, local durable writes and replicated durable
writes have distinct guarantees and must retain their separate reported labels.
The three voters use separate durable stores within one process on one host;
physical failure-domain and remote-network behavior is tested separately.
Successful-read strict auditing is disabled, while mutation audits remain
enabled. Network requests additionally persist successful authentication audits.

The run's completion or failure is authoritative in `matrix.json`. Partial
results and failed outcomes remain evidence; this note does not mark an
unfinished matrix as complete. Memory stages and recovery contracts are defined
in `benchmarks/CAPACITY.md`; shared API footprints must not be added together.
