# Run06 completed one-tenant analysis

**All five one-tenant cases passed; the full matrix is still running.** At the
inspected 2026-09-05 10:57:48 UTC snapshot, six of 15 total cases had completed
(these five plus raw-100). This note interprets only raw/local/replicated/text/
network at one tenant, not the remaining tenant-count matrix or a final release
capacity result. Their 33 workloads each completed 1,000 operations: 33,000
successes, zero failed attempts and zero unattempted operations.

Each case loaded 1,000,000 exact 1,024-byte JSON bodies, totaling 1,024,000,000
logical payload bytes. The [live matrix](matrix.json) binds source
`a3205990001d86ea66e4ac457fba29ef634b7b6923dfdaa5d80cf2916d517df2`. Its recorded result hashes were
verified against all five files. Client and server executable identities also
match the [passed release build](../macos-validation-20260905-embedded-audit/release-build.json).
Current source identity remains unchanged; no raw result was edited.

| Completed case | Verified result SHA256 |
| --- | --- |
| [raw-1](raw-1.json) | `8bb8b7a23426818098563ddda7fd418ed4bcf007606c52afa0693f5c0cb80dee` |
| [local-1](local-1.json) | `81c25fe8892a0858c36880225216ba992ae1428ae827c2130ab0c71ef91393d8` |
| [replicated-1](replicated-1.json) | `97b966bcfff78ce790d6ce4db24aa7da7a4597f78f46a9d537f376bc565118f7` |
| [text-1](text-1.json) | `8a7b0f9656421dacb6725b49d607aac7351535c3c2a1a8aa1bd32b021af5167a` |
| [network-1](network-1.json) | `70dab3b230dc07219c5989f9c761d1a982ff633bfe7147ec95cfa1dd8cf8723e` |

The text/in-process executable is
`a1f93ade86ddfe7096bb0afccc9ae72b4f196254657595d4f6409525f0be52b7`;
the network client is
`f1b7f8493eff2b03170854237845fa0bf026fff3d0f88dcb9dbdcf79284f273c`;
its separate production server is
`5ecf74b71ffaa6bd1897927ed0dff7f0f73a5863757044b595326cc1f351bf16`.
Per-report Rust/Cargo source fingerprints cover a narrower documented file set;
network provenance is supplied by the bound client/server executables and matrix.

## Access and durable operations

Selected latency columns are microseconds; throughput is successes per second
over the whole workload interval. Full mixed/query rows remain in the linked
JSON. Each row has 1,000 sequential samples, roughly ten p99 tail observations,
one run and no confidence interval or saturation-throughput claim.

| Path | Operation | p50 µs | p99 µs | Successes/s |
| --- | --- | ---: | ---: | ---: |
| raw | Borrowed map lookup | 0.375 | 0.542 | 2,570,965.063 |
| local | Owned point get | 3.125 | 6.625 | 195,977.561 |
| local | Shared point get | 1.042 | 1.292 | 344,288.359 |
| local | Durable single-document write | 23,801.084 | 28,839.041 | 36.629 |
| replicated | Owned point get | 19.375 | 30.875 | 46,870.055 |
| replicated | Shared point get | 18.250 | 27.083 | 48,394.610 |
| replicated | Durable single-document write | 65,922.625 | 122,481.333 | 12.387 |
| text | Durable single-document write | 32,343.792 | 91,316.167 | 22.243 |
| grpc | Authenticated point get | 12,887.333 | 22,658.333 | 60.496 |
| grpc | Durable single-document write | 37,034.167 | 64,900.958 | 22.254 |
| grpc | Indexed equality, complete query | 12,827.584 | 37,774.292 | 55.435 |
| mcp | Authenticated point get | 12,836.916 | 26,652.208 | 58.790 |
| mcp | Durable single-document write | 38,701.208 | 118,652.375 | 18.837 |
| mcp | Indexed equality, complete query | 13,207.792 | 133,290.042 | 33.779 |

Raw lookup borrows a body and omits authorization, cloning and persistence.
Embedded methods include the actual common authorization/consistency layer;
owned and shared-handle returns are distinct paths. Replicated reads require
a fresh quorum barrier; durable writes include schema/index work, encrypted
immediate two-phase redb persistence, receipts and mutation auditing. The
replicated case has three real voters in separate files on the same host/process;
it does not measure independent physical failure domains or remote transport.

Network is one-voter loopback TCP/TLS 1.3 against a separate `kasumid` process,
with native mTLS, signed user tokens, TLS JWKS and actual OpenBao 2.6.2 Transit.
Authentication events are durable even for successful reads; strict tenant
successful-read auditing is disabled. Embedded fixtures use real encryption with
a test wrapping provider and exclude Transit latency. The network fixture also
verified native invalid-token/unconfigured-tenant rejection and MCP invalid-token
rejection before timing. These costs cannot be attributed solely to serialization
or treated as a Redis comparison.

Persistent connections and one warmup read per credential precede measured
network requests. Native runs before MCP against the same server, with growing
audits/receipts and changing cache state. Owned embedded reads precede shared
reads. The 90/10 and 50/50 workloads all passed, but their percentiles combine
different read/write distributions and do not isolate a single operation cost.

## Indexed text and page scope

The text case has a numeric index plus English and Japanese text indexes.
Measured writes change indexed text and include Tantivy commit/reload before
acknowledgment. Each query begins with no cursor and follows every returned
cursor until exhausted before completing its timed sample.

| Full-query workload | p50 µs | p99 µs | Queries/s | Fixture-derived rows/query |
| --- | ---: | ---: | ---: | ---: |
| text_english_Phrase_complete_pages | 3,337.458 | 7,921.458 | 282.190 | 1,000 |
| text_english_Prefix_complete_pages | 32,525.208 | 48,718.250 | 30.065 | 10,000 |
| text_english_Fuzzy_complete_pages | 1,498.833 | 2,677.417 | 625.159 | 1,000 |
| text_japanese_Terms_complete_pages | 1,369.666 | 2,601.417 | 671.160 | 1,000 |

The row counts above derive from the deterministic fixture distribution and
query definitions; result files do not record observed row/page counts or assert
cardinality in the timing loop. At the configured 1,000-row page limit, prefix
work entails multiple pages. This is full-query latency, not per-page latency.
The native/MCP query loops also drain every cursor, but their fixture performs
ordinal equality with one expected row; those rows are not evidence of measured
multi-page network search. Index and pagination correctness have separate tests.

## Memory, stores and recovery

Memory/disk units are GiB. In-process rows include the entire harness and all
voters; network includes the server only, excluding client, issuer and OpenBao.
Native/MCP share a single network footprint and must not be added together.

| Deployment | Data voters | Control voters | Audit stores | Loaded RSS | After work RSS | After recovery RSS | Disk |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| raw | 0 | 0 | 0 | 1.969 | 1.969 | — | 0.000 |
| local | 1 | 0 | 1 | 4.061 | 5.540 | 9.884 | 4.000 |
| replicated | 3 | 0 | 3 | 13.967 | 15.303 | 26.254 | 12.000 |
| text | 1 | 0 | 1 | 5.275 | 5.683 | 10.623 | 4.000 |
| network | 1 | 1 | 1 | 4.031 | 4.202 | 6.955 | 4.000 |

Audit stores use separate encryption keys and share a writer per replica node;
memory/disk/key costs are included without adding another Raft group. At one
customer tenant, network also retains a control-group voter. Empty-state RSS
and initialization measurements remain in each JSON, but incremental tenant/group
overhead requires the completed 100/1,000-tenant cases. Whole-process differences
between local and text are not isolated index-object measurements.

| Deployment | Open s | Load s | Shutdown s | Verified recovery s |
| --- | ---: | ---: | ---: | ---: |
| raw | 0.000001 | 1.345809 | — | — |
| local | 0.202037 | 156.815198 | 1.801610 | 47.113793 |
| replicated | 0.533787 | 376.497120 | 4.442756 | 119.991308 |
| text | 0.228655 | 234.404795 | 1.172810 | 104.870261 |
| network | 1.195545 | 209.603821 | 0.991338 | 27.985550 |

All five cases reached normal completion. Shutdown is separate from recovery,
which begins afterward and includes reopen/spawn, key access, reconstruction,
readiness and one verified point read per tenant. Network shutdown spans SIGTERM
to successful server exit; its fresh server restart preserves encrypted storage
while issuer and OpenBao remain running. Final cleanup is outside these timers.
These are clean restart observations, not crash or power-cut measurements.

For database cases, `peak_rss_bytes` is sampled before shutdown and not refreshed
after recovery. Text has a sampled 8.457 GiB peak but later 10.623 GiB recovery
RSS; local/replicated show the same distinction. Network has no server lifetime
peak measurement. Separate recovery RSS and headroom must therefore remain visible.

## Host and interpretation limits

The host is macOS arm64, 16 logical CPUs and 128 GiB RAM. Unrelated activity
is explicitly permitted and retained in [host samples](host-samples.jsonl). Text
has 92 samples with approximately 635–1,551% aggregate background CPU; network
has 112 samples with 373–1,471% (100% represents one CPU). Competing `cargo`,
`rustc` and `qemu-system-aarch64-headless` processes are recorded. At the inspected
snapshot the manifest counted 409 competing-process violations. Earlier case
load is detailed in [the three-case note](early-case-analysis.md).

No source or executable mismatch was found, but the shared-host load excludes
isolated latency or intrinsic-speed claims. The observations do not identify
which background process caused a particular tail, compare equivalent Redis
guarantees, certify physical failure domains, or establish a maximum capacity.
Keep all remaining cases and finite failures in the terminal matrix; no full
capacity report was regenerated while it was live.
