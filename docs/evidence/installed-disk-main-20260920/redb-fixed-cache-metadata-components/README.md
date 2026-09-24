# Fixed cache collection metadata component

This is checked arithmetic using the already frozen native Rust 1.97.1 layouts
and pinned collection geometry. It is not a fresh native allocation measurement,
a complete cache/table/workspace allowance, or an RSS claim. No Rust or Cargo
process was run for this calculation. Actual source remains root-owned.

Dependency: fixed-cache-capacity revision2 patch
3f2548f12aad8c27f72a8645162296ec85079d9cdc9a2adf6363f5c9a1e4bcdc,
plus its separate clean-close assertion follow-up. The capacity logic needs the
revision2 eligible-entry selection and actual post-flush slot check; revision1
alone did not enforce the proposed cap in every mixed-borrowed ordering.

## Exact inputs and formula

The existing EncryptedTable sets its cache byte target to 8,388,608. The default
redb page size remains 4,096, there are 131 stripes, and MAX_BTREE_DEPTH is 128.
Thus R=max(1,ceil(ceil(8388608/4096)/131))=16 and W=R+128+4=148. The additive
write allowance retains its explicit capacity-policy qualification in revision2;
it is not a promise that arbitrary external table guards cannot exhaust it.

The frozen native report establishes 32-byte, alignment-8 hash key/value entries
for both read Arc and write Option<Arc> records. Queue entries are 8-byte u64s.
The pinned aarch64 hashbrown group width is 8. Hash-map churn is bounded using
2*n as capacity input, then the pinned 7/8 load and power-of-two bucket geometry.
The request is aligned data bytes plus bucket control bytes plus one control
group. VecDeque backing uses max(2*n,4) queue slots. These bounds cover every
reserve request, not only current live length; fixed cardinality and queue
registration removal are therefore prerequisites.

| Per-stripe component | Entry cap | Conservative retained requested bytes | Allocations |
|---|---:|---:|---:|
| Read hash table |16|2,120|1|
| Read queue |16|256|1|
| Write hash table |148|16,904|1|
| Write queue |148|2,368|1|

Summing all four and multiplying by 131 gives 2,835,888 requested bytes in 524
allocations per table. Conservatively allowing old and new backing to coexist
for every map and queue simultaneously gives 5,671,776 bytes in 1,048 allocations.
This deliberately overcounts concurrent reallocations rather than relying on a
thread scheduling argument. It also covers retained capacity after clear.

At the engine's existing, separately named 4,096-per-allocation policy allowance,
those components become 4,982,192 retained and 9,964,384 with overlap. This is a
policy calculation; the 4,096 allowance is not a new proof about libc or RSS.
The two simultaneous custody table owners double those values: 5,671,776 /
11,343,552 requested bytes, or 9,964,384 /19,928,768 with the existing allowance.
The terminal table has the same cache collection component. Its larger physical
extent still increases allocator and debug-page accounting elsewhere.

`calculate.py` checks 64-bit arithmetic and Layout's isize bound; it rejects
multiplication, addition and capacity growth overflow. Its embedded arithmetic
assertions passed. `components.json` records exact numeric results. Input hashes
in manifest.json link the fixed capacity source, existing policy/page/depth, and
frozen native geometry and layout report.

## Remaining owners and qualification

This component does not include fixed cache/stripe Vec and Arc backing or native
synchronization allocations; these are bounded by stripe count but must be
added using exact target layouts. It does not include Arc page payloads,
WritablePage/AccessGuard/PageImpl-retained payloads, simultaneous read misses,
allocator copies, free-page/debug/transaction collections, database/backend/spool
or task/census/report ownership. Arbitrary callback captures and panic payloads
remain outside the restricted profile proof. No memory reservation may silently
use this component alone as a complete admitted workspace.

The original scratch cache byte target, physical disk formulas, 256-row/1MiB
custody profile, 2MiB terminal row ceiling, all payload quotas and deadlines are
unchanged. The result replaces only the earlier very loose disk-offset-universe
bound for cache collection metadata after revision2 is qualified.
