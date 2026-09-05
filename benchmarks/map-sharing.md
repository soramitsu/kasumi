# Immutable document leaf-copy experiment

`cargo run --release -p kasumi-engine --example map_sharing -- OUTPUT.json`
compares `imbl::HashMap<String, Document>` with
`imbl::HashMap<String, Arc<Document>>`. The two maps use identical cloned
`RandomState` hashers and keys within a run. Each sample applies 8,192 updates to
100,000 documents, retaining the preceding immutable generation during each
batch. Incoming write bodies and keys are allocated before timing. Five samples
alternate the order of the owned and shared variants.

The exploratory run on this macOS/aarch64 host produced:

| Target document bytes | Batch operations | Owned median ns/update | Arc median ns/update | Owned / Arc |
| ---: | ---: | ---: | ---: | ---: |
| 1,024 | 1 | 7,535 | 1,355 | 5.56 |
| 1,024 | 256 | 6,235 | 857 | 7.28 |
| 8,192 | 1 | 10,942 | 1,322 | 8.28 |
| 8,192 | 256 | 9,918 | 850 | 11.67 |

Separate untimed clone instrumentation counted 8.58 and 8.06 stored document
payload clones per update for batch sizes 1 and 256. The Arc variant performed
zero stored payload clones. Incoming document construction is excluded from that
count. This establishes that copying hash-map nodes deep-cloned unrelated JSON
values in this workload.

The raw samples and context are in
[`results/map-sharing-exploratory.json`](results/map-sharing-exploratory.json).
A 1,000-tenant Kasumi baseline was opening groups and other Rust builds were
active on the machine. This is mechanism evidence, not an isolated capacity
measurement. The experiment excludes validation, durability, replication,
indexing, and recovery; it does not establish the fraction of end-to-end loading
time attributable to document copies. Randomized hash layout can vary across
separate runs. Set `KASUMI_MAP_BENCH_CONTEXT` to record concurrent work for future
runs.

Kasumi consequently stores resident documents in `Arc<Document>`. Updated
hash-map nodes copy handles; unchanged document bodies remain shared. Serde's Arc
representation preserves the previous snapshot JSON bytes, with dedicated tests
for exact numbers, byte equality, reconstruction, and historical immutability.
`Database::get_shared` exposes an immutable handle through the same authorization,
consistency, key-access, and audit gates as `get`. The original `get` still returns
an owned document and prepares its clone before final authorized release.

Future engine benchmarks report shared embedded reads and owned embedded reads
separately. The ratios above must not be reported as a durable-database speedup or
a Redis comparison. Arc metadata, allocation overhead, and lookup indirection
also require capacity and read measurements at the full target dataset sizes.
