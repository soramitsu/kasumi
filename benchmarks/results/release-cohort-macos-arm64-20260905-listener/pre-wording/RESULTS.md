# Kasumi v1 measured results

Recorded cohort outcome: **`completed_under_host_load`**. Full measurement coverage: **yes**. This report selects twelve unchanged engine measurements and three later network case outcomes. It is not a single execution or a relabeling of old results as corrected-source measurements. Shared-host observations do not establish production capacity, a launch SLA or a Redis speed ratio.

The [cohort manifest](results/release-cohort-macos-arm64-20260905-listener/cohort.json) binds every selected origin, and the [derived capacity view](results/release-cohort-macos-arm64-20260905-listener/capacity.json) retains those origins. The original [run06 manifest](results/release-matrix-macos-arm64-20260905-06/matrix.json), [host samples](results/release-matrix-macos-arm64-20260905-06/host-samples.jsonl) and [run notes](results/release-matrix-macos-arm64-20260905-06/RUN_NOTES.md), and the network supplement's [manifest](results/network-rerun-macos-arm64-20260905-listener/matrix.json), [host samples](results/network-rerun-macos-arm64-20260905-listener/host-samples.jsonl) and [run notes](results/network-rerun-macos-arm64-20260905-listener/RUN_NOTES.md) remain separate records.

## Cohort provenance

The twelve raw/local/replicated/text cases retain source `a3205990001d86ea66e4ac457fba29ef634b7b6923dfdaa5d80cf2916d517df2`. Network cases use corrected source `28aeb80168d3ab02a0eec7bf2a0163a7cb99dbfd74adf596e849de17e1fa3c1d`. The complete [source-change proof](results/listener-startup-20260905/source-change.json) contains exactly one changed file, server `tls.rs`; dependencies and engine/benchmark sources are unchanged. Reuse additionally requires the new release build to produce the exact previously measured `kasumi-bench` SHA256 `a1f93ade86ddfe7096bb0afccc9ae72b4f196254657595d4f6409525f0be52b7`. Network client, fixture launcher and server identities are bound to their new release build. All raw hashes, original source labels and the unsuccessful earlier network case are preserved.

| Case | Origin | Recorded outcome |
| --- | --- | --- |
| [raw-1](results/release-matrix-macos-arm64-20260905-06/raw-1.json) | run06 / a3205990 | passed |
| [local-1](results/release-matrix-macos-arm64-20260905-06/local-1.json) | run06 / a3205990 | passed |
| [replicated-1](results/release-matrix-macos-arm64-20260905-06/replicated-1.json) | run06 / a3205990 | passed |
| [text-1](results/release-matrix-macos-arm64-20260905-06/text-1.json) | run06 / a3205990 | passed |
| [network-1](results/network-rerun-macos-arm64-20260905-listener/network-1.json) | network supplement / 28aeb801 | passed |
| [raw-100](results/release-matrix-macos-arm64-20260905-06/raw-100.json) | run06 / a3205990 | passed |
| [local-100](results/release-matrix-macos-arm64-20260905-06/local-100.json) | run06 / a3205990 | passed |
| [replicated-100](results/release-matrix-macos-arm64-20260905-06/replicated-100.json) | run06 / a3205990 | passed |
| [text-100](results/release-matrix-macos-arm64-20260905-06/text-100.json) | run06 / a3205990 | passed |
| [network-100](results/network-rerun-macos-arm64-20260905-listener/network-100.json) | network supplement / 28aeb801 | passed |
| [raw-1000](results/release-matrix-macos-arm64-20260905-06/raw-1000.json) | run06 / a3205990 | passed |
| [local-1000](results/release-matrix-macos-arm64-20260905-06/local-1000.json) | run06 / a3205990 | passed |
| [replicated-1000](results/release-matrix-macos-arm64-20260905-06/replicated-1000.json) | run06 / a3205990 | passed |
| [text-1000](results/release-matrix-macos-arm64-20260905-06/text-1000.json) | run06 / a3205990 | passed |
| [network-1000](results/network-rerun-macos-arm64-20260905-listener/network-1000.json) | network supplement / 28aeb801 | passed |

## Dataset and guarantees

Each configured case targets 1,000,000 documents whose serialized JSON bodies are exactly 1,024 bytes: 1,024,000,000 logical payload bytes, distributed across 1, 100 or 1,000 tenants. Replicated cases hold three copies of that logical dataset. Each mode/count runs in its own process. Every measured workload requests 1,000 sequential operations. Incomplete loads and unattempted cases are not counted as full-size observations.

The host is macOS arm64 with 16 logical CPUs and 128 GiB RAM; Rust/Cargo 1.94.1, locked dependencies, thin LTO and one release code-generation unit. Unrelated host work remained running. The dedicated Linux validation VM and this task’s builds were stopped before measurements. Permitted host load stays visible in the evidence.


Raw map reads borrow a body without authorization, body cloning or durability. Embedded reads use the actual shared authorization and consistency layer. Local writes persist through encrypted redb with immediate durability and two-phase commit. Replicated reads require a fresh quorum barrier; writes require quorum persistence and complete local application. The three voters have separate redb files in one process; physical failure domains and remote-network latency are not measured.

Native RPC uses real TLS 1.3, mTLS and OAuth; MCP uses TLS 1.3 and OAuth with protocol 2026-07-28. Both target a separate production server process with one voter per tenant, actual OpenBao Transit, and durable authentication and mutation audits. Strict tenant successful-read auditing is disabled, while network authentication events remain durable for successful reads and are included in request latency. Local/replicated in-process cases use the explicit test wrapping provider with real encryption; Transit latency is excluded from those cases.

## Latency and throughput

All latency columns use **microseconds**; displayed values are rounded. Throughput is completed successes divided by the entire workload interval, including any failed-attempt delay. Success percentiles exclude failed attempts; failures and unattempted operations are shown separately. A workload stops at its first failure, with no hidden client retry. At 1,000 samples, p99 has roughly ten tail observations. There is one run per case, with no confidence interval or saturation claim. Mixed-workload percentiles combine reads and writes. In a 50/50 mix, the median lies near the boundary between their latency distributions; use the dedicated write row for write latency.

### Raw map access

| Tenants | Workload | Success / failed / unattempted | p50 µs | p99 µs | Successes/s |
| --- | --- | --- | --- | --- | --- |
| 1 | `raw_hashmap_borrowed_lookup` | 1000 / 0 / 0 | 0.375 | 0.542 | 2,570,965 |
| 100 | `raw_hashmap_borrowed_lookup` | 1000 / 0 / 0 | 0.458 | 1.667 | 1,998,170 |
| 1000 | `raw_hashmap_borrowed_lookup` | 1000 / 0 / 0 | 0.333 | 0.542 | 2,670,819 |

### Embedded reads and structured queries

| Tenants | Workload | Success / failed / unattempted | p50 µs | p99 µs | Successes/s |
| --- | --- | --- | --- | --- | --- |
| 1 | `embedded_authorized_owned_point_get` | 1000 / 0 / 0 | 3.125 | 6.625 | 195,978 |
| 1 | `embedded_authorized_shared_point_get` | 1000 / 0 / 0 | 1.042 | 1.292 | 344,288 |
| 1 | `structured_indexed_equality` | 1000 / 0 / 0 | 25.125 | 57.792 | 32,459 |
| 100 | `embedded_authorized_owned_point_get` | 1000 / 0 / 0 | 1.75 | 6.958 | 285,990 |
| 100 | `embedded_authorized_shared_point_get` | 1000 / 0 / 0 | 0.542 | 0.792 | 576,161 |
| 100 | `structured_indexed_equality` | 1000 / 0 / 0 | 12.709 | 28.208 | 64,861 |
| 1000 | `embedded_authorized_owned_point_get` | 1000 / 0 / 0 | 2.291 | 10.625 | 207,218 |
| 1000 | `embedded_authorized_shared_point_get` | 1000 / 0 / 0 | 0.625 | 1.125 | 523,846 |
| 1000 | `structured_indexed_equality` | 1000 / 0 / 0 | 14 | 32.542 | 56,733 |

### Local durable writes and mixed traffic

| Tenants | Workload | Success / failed / unattempted | p50 µs | p99 µs | Successes/s |
| --- | --- | --- | --- | --- | --- |
| 1 | `durable_single_document_write` | 1000 / 0 / 0 | 23,801 | 28,839 | 36.629 |
| 1 | `read_heavy_90_read_10_write` | 1000 / 0 / 0 | 3.583 | 28,750 | 131.216 |
| 1 | `balanced_50_read_50_write` | 1000 / 0 / 0 | 32.666 | 203,462 | 52.562 |
| 100 | `durable_single_document_write` | 1000 / 0 / 0 | 25,689 | 101,452 | 27.381 |
| 100 | `read_heavy_90_read_10_write` | 1000 / 0 / 0 | 2.625 | 31,991 | 372.885 |
| 100 | `balanced_50_read_50_write` | 1000 / 0 / 0 | 185.542 | 69,073 | 52.622 |
| 1000 | `durable_single_document_write` | 1000 / 0 / 0 | 24,858 | 43,803 | 29.625 |
| 1000 | `read_heavy_90_read_10_write` | 1000 / 0 / 0 | 2.458 | 28,723 | 380.385 |
| 1000 | `balanced_50_read_50_write` | 1000 / 0 / 0 | 20.666 | 34,272 | 59.571 |

### Replicated access

| Tenants | Workload | Success / failed / unattempted | p50 µs | p99 µs | Successes/s |
| --- | --- | --- | --- | --- | --- |
| 1 | `embedded_authorized_owned_point_get` | 1000 / 0 / 0 | 19.375 | 30.875 | 46,870 |
| 1 | `embedded_authorized_shared_point_get` | 1000 / 0 / 0 | 18.25 | 27.083 | 48,395 |
| 1 | `durable_single_document_write` | 1000 / 0 / 0 | 65,923 | 122,481 | 12.387 |
| 1 | `read_heavy_90_read_10_write` | 1000 / 0 / 0 | 26.25 | 140,265 | 70.097 |
| 1 | `balanced_50_read_50_write` | 1000 / 0 / 0 | 50,002 | 874,020 | 14.914 |
| 1 | `structured_indexed_equality` | 1000 / 0 / 0 | 45.292 | 75.417 | 20,047 |
| 100 | `embedded_authorized_owned_point_get` | 1000 / 0 / 0 | 31.791 | 121.417 | 25,299 |
| 100 | `embedded_authorized_shared_point_get` | 1000 / 0 / 0 | 19 | 60.583 | 40,003 |
| 100 | `durable_single_document_write` | 1000 / 0 / 0 | 77,244 | 354,077 | 8.365 |
| 100 | `read_heavy_90_read_10_write` | 1000 / 0 / 0 | 26 | 73,977 | 153.835 |
| 100 | `balanced_50_read_50_write` | 1000 / 0 / 0 | 174.625 | 146,708 | 23.339 |
| 100 | `structured_indexed_equality` | 1000 / 0 / 0 | 27.667 | 50.333 | 31,587 |
| 1000 | `embedded_authorized_owned_point_get` | 1000 / 0 / 0 | 36.458 | 83.416 | 11,808 |
| 1000 | `embedded_authorized_shared_point_get` | 1000 / 0 / 0 | 29.334 | 49.083 | 28,459 |
| 1000 | `durable_single_document_write` | 1000 / 0 / 0 | 66,769 | 358,769 | 11.253 |
| 1000 | `read_heavy_90_read_10_write` | 1000 / 0 / 0 | 39.667 | 120,518 | 115.078 |
| 1000 | `balanced_50_read_50_write` | 1000 / 0 / 0 | 10,173 | 330,236 | 15.751 |
| 1000 | `structured_indexed_equality` | 1000 / 0 / 0 | 61.458 | 94.792 | 9,319 |

### Authenticated native RPC

| Tenants | Workload | Success / failed / unattempted | p50 µs | p99 µs | Successes/s |
| --- | --- | --- | --- | --- | --- |
| 1 | `authenticated_point_get` | 1000 / 0 / 0 | 12,946 | 32,744 | 59.102 |
| 1 | `durable_single_document_write` | 1000 / 0 / 0 | 37,496 | 108,114 | 21.407 |
| 1 | `read_heavy_90_read_10_write` | 1000 / 0 / 0 | 13,183 | 399,990 | 30.147 |
| 1 | `balanced_50_read_50_write` | 1000 / 0 / 0 | 33,450 | 78,874 | 30.741 |
| 1 | `authenticated_query_complete_pages` | 1000 / 0 / 0 | 14,023 | 126,517 | 39.969 |
| 100 | `authenticated_point_get` | 1000 / 0 / 0 | 12,897 | 26,356 | 76.175 |
| 100 | `durable_single_document_write` | 1000 / 0 / 0 | 38,029 | 70,313 | 20.759 |
| 100 | `read_heavy_90_read_10_write` | 1000 / 0 / 0 | 13,513 | 55,767 | 48.158 |
| 100 | `balanced_50_read_50_write` | 1000 / 0 / 0 | 33,629 | 49,637 | 29.249 |
| 100 | `authenticated_query_complete_pages` | 1000 / 0 / 0 | 12,928 | 21,985 | 75.636 |
| 1000 | `authenticated_point_get` | 1000 / 0 / 0 | 13,032 | 68,859 | 55.483 |
| 1000 | `durable_single_document_write` | 1000 / 0 / 0 | 39,455 | 187,459 | 16.002 |
| 1000 | `read_heavy_90_read_10_write` | 1000 / 0 / 0 | 13,077 | 72,651 | 56.184 |
| 1000 | `balanced_50_read_50_write` | 1000 / 0 / 0 | 32,469 | 117,483 | 28.29 |
| 1000 | `authenticated_query_complete_pages` | 1000 / 0 / 0 | 12,993 | 49,177 | 67.786 |

### Authenticated MCP

| Tenants | Workload | Success / failed / unattempted | p50 µs | p99 µs | Successes/s |
| --- | --- | --- | --- | --- | --- |
| 1 | `authenticated_point_get` | 1000 / 0 / 0 | 12,941 | 84,875 | 48.05 |
| 1 | `durable_single_document_write` | 1000 / 0 / 0 | 41,761 | 252,530 | 11.673 |
| 1 | `read_heavy_90_read_10_write` | 1000 / 0 / 0 | 14,895 | 194,894 | 28.71 |
| 1 | `balanced_50_read_50_write` | 1000 / 0 / 0 | 40,309 | 252,572 | 15.403 |
| 1 | `authenticated_query_complete_pages` | 1000 / 0 / 0 | 45,741 | 97,134 | 23.141 |
| 100 | `authenticated_point_get` | 1000 / 0 / 0 | 12,846 | 34,358 | 57.855 |
| 100 | `durable_single_document_write` | 1000 / 0 / 0 | 38,105 | 113,351 | 18.227 |
| 100 | `read_heavy_90_read_10_write` | 1000 / 0 / 0 | 13,895 | 92,086 | 42.021 |
| 100 | `balanced_50_read_50_write` | 1000 / 0 / 0 | 45,182 | 497,253 | 11.222 |
| 100 | `authenticated_query_complete_pages` | 1000 / 0 / 0 | 14,147 | 49,413 | 62.315 |
| 1000 | `authenticated_point_get` | 1000 / 0 / 0 | 13,011 | 52,134 | 53.949 |
| 1000 | `durable_single_document_write` | 1000 / 0 / 0 | 40,860 | 116,545 | 18.322 |
| 1000 | `read_heavy_90_read_10_write` | 1000 / 0 / 0 | 13,012 | 64,299 | 47.768 |
| 1000 | `balanced_50_read_50_write` | 1000 / 0 / 0 | 34,256 | 184,729 | 23.89 |
| 1000 | `authenticated_query_complete_pages` | 1000 / 0 / 0 | 12,971 | 57,533 | 51.973 |

### Filesystem activity during setup

The [incremental-cache cleanup record](results/release-matrix-macos-arm64-20260905-06/artifact-cleanup-incremental/result.json) records filesystem activity from 2026-09-05T11:32:37.361619+00:00 through 2026-09-05T11:33:14.871082+00:00, while local-1000 was in progress. Inventoried Cargo incremental caches were removed; the record preserves unchanged source and 130,488 retained compiled files. This overlapped collection setup and may have extended into initial loading based on the case start and recorded phase durations; phase checkpoints have no exact timestamps. Setup/load timing and subsequent host I/O/cache state are additionally qualified. No isolated setup cost or causal performance improvement is inferred. [Run notes](results/release-matrix-macos-arm64-20260905-06/RUN_NOTES.md) retain the cleanup scope and tradeoff.

### English and Japanese indexed text

Text cases include one numeric index and two text indexes per tenant. Writes change indexed text and include Tantivy commit/reload before acknowledgment. Queries consume all historical pages before the next operation. At 1/100/1,000 tenants, the fixture-derived result sizes are 1,000/10/1 rows for phrase, fuzzy and Japanese terms, and 10,000/100/10 for English prefix. Structured equality expects one row. These cardinalities follow from fixture definitions; timed reports do not emit or assert observed row/page counts. Text latency changes include this changing result work, not a fixed-cardinality speed comparison.

| Tenants | Workload | Success / failed / unattempted | p50 µs | p99 µs | Successes/s |
| --- | --- | --- | --- | --- | --- |
| 1 | `embedded_authorized_owned_point_get` | 1000 / 0 / 0 | 2.917 | 8.125 | 212,448 |
| 1 | `embedded_authorized_shared_point_get` | 1000 / 0 / 0 | 0.833 | 1.292 | 430,324 |
| 1 | `durable_single_document_write` | 1000 / 0 / 0 | 32,344 | 91,316 | 22.243 |
| 1 | `read_heavy_90_read_10_write` | 1000 / 0 / 0 | 3.709 | 54,239 | 153.909 |
| 1 | `balanced_50_read_50_write` | 1000 / 0 / 0 | 58.75 | 375,711 | 34.505 |
| 1 | `structured_indexed_equality` | 1000 / 0 / 0 | 26.708 | 3,076 | 5,942 |
| 1 | `text_english_Phrase_complete_pages` | 1000 / 0 / 0 | 3,337 | 7,921 | 282.19 |
| 1 | `text_english_Prefix_complete_pages` | 1000 / 0 / 0 | 32,525 | 48,718 | 30.065 |
| 1 | `text_english_Fuzzy_complete_pages` | 1000 / 0 / 0 | 1,499 | 2,677 | 625.159 |
| 1 | `text_japanese_Terms_complete_pages` | 1000 / 0 / 0 | 1,370 | 2,601 | 671.16 |
| 100 | `embedded_authorized_owned_point_get` | 1000 / 0 / 0 | 1.709 | 6.125 | 297,678 |
| 100 | `embedded_authorized_shared_point_get` | 1000 / 0 / 0 | 0.583 | 0.958 | 553,991 |
| 100 | `durable_single_document_write` | 1000 / 0 / 0 | 27,850 | 96,382 | 26.336 |
| 100 | `read_heavy_90_read_10_write` | 1000 / 0 / 0 | 2.459 | 38,385 | 347.632 |
| 100 | `balanced_50_read_50_write` | 1000 / 0 / 0 | 8.875 | 48,252 | 54.497 |
| 100 | `structured_indexed_equality` | 1000 / 0 / 0 | 11.917 | 27.792 | 67,031 |
| 100 | `text_english_Phrase_complete_pages` | 1000 / 0 / 0 | 27.833 | 54.625 | 31,306 |
| 100 | `text_english_Prefix_complete_pages` | 1000 / 0 / 0 | 193.333 | 254.583 | 5,072 |
| 100 | `text_english_Fuzzy_complete_pages` | 1000 / 0 / 0 | 36.167 | 59.375 | 25,164 |
| 100 | `text_japanese_Terms_complete_pages` | 1000 / 0 / 0 | 26.208 | 47.666 | 34,270 |
| 1000 | `embedded_authorized_owned_point_get` | 1000 / 0 / 0 | 2.459 | 11 | 185,675 |
| 1000 | `embedded_authorized_shared_point_get` | 1000 / 0 / 0 | 0.959 | 1.542 | 396,681 |
| 1000 | `durable_single_document_write` | 1000 / 0 / 0 | 46,070 | 56,472 | 20.397 |
| 1000 | `read_heavy_90_read_10_write` | 1000 / 0 / 0 | 4.667 | 49,782 | 220.393 |
| 1000 | `balanced_50_read_50_write` | 1000 / 0 / 0 | 68.458 | 60,634 | 37.98 |
| 1000 | `structured_indexed_equality` | 1000 / 0 / 0 | 25.333 | 57.709 | 14,007 |
| 1000 | `text_english_Phrase_complete_pages` | 1000 / 0 / 0 | 51.5 | 124.083 | 9,523 |
| 1000 | `text_english_Prefix_complete_pages` | 1000 / 0 / 0 | 121.542 | 272.542 | 5,387 |
| 1000 | `text_english_Fuzzy_complete_pages` | 1000 / 0 / 0 | 69.084 | 127.75 | 11,274 |
| 1000 | `text_japanese_Terms_complete_pages` | 1000 / 0 / 0 | 45 | 108.083 | 12,066 |

## Memory and recovery

Memory columns are whole-process **GiB**. Local, text and replicated RSS include the driver and all resident voters. Network RSS is the server only; OpenBao, issuer and client remain visible separately in host samples. Native and MCP share one footprint and must not be added together.

| Deployment | Tenants | Configured data voter groups | Control groups | Service audit stores | Qualified observation |
| --- | --- | --- | --- | --- | --- |
| raw | 1 | 0 | 0 | 0 | yes |
| local | 1 | 1 | 0 | 1 | yes |
| replicated | 1 | 3 | 0 | 3 | yes |
| text | 1 | 1 | 0 | 1 | yes |
| network | 1 | 1 | 1 | 1 | yes |
| raw | 100 | 0 | 0 | 0 | yes |
| local | 100 | 100 | 0 | 1 | yes |
| replicated | 100 | 300 | 0 | 3 | yes |
| text | 100 | 100 | 0 | 1 | yes |
| network | 100 | 100 | 1 | 1 | yes |
| raw | 1000 | 0 | 0 | 0 | yes |
| local | 1000 | 1000 | 0 | 1 | yes |
| replicated | 1000 | 3000 | 0 | 3 | yes |
| text | 1000 | 1000 | 0 | 1 | yes |
| network | 1000 | 1000 | 1 | 1 | yes |

Service audit stores share a writer per node and are counted separately from Raft groups. Their footprint is included when that fixture provides the store; historical fixtures retain their original counts. For failed startup entries, configured topology does not establish ready groups, and absent RSS/payload observations must not be interpreted as an observed empty database.

| Deployment | Tenants | Empty maps/groups GiB | Empty indexes GiB | Loaded GiB | After work GiB | Pre-shutdown sampled peak GiB | After recovery GiB |
| --- | --- | --- | --- | --- | --- | --- | --- |
| raw | 1 | 0.067 | — | 1.969 | 1.969 | 1.969 | — |
| local | 1 | 0.070 | 0.074 | 4.061 | 5.540 | 7.529 | 9.884 |
| replicated | 1 | 0.071 | 0.074 | 13.967 | 15.303 | 23.370 | 26.254 |
| text | 1 | 0.071 | 0.079 | 5.275 | 5.683 | 8.457 | 10.623 |
| network | 1 | 0.019 | 0.021 | 4.093 | 4.808 | — | 6.953 |
| raw | 100 | 0.067 | — | 1.912 | 1.912 | 1.912 | — |
| local | 100 | 0.079 | 0.084 | 4.032 | 4.071 | 4.071 | 4.459 |
| replicated | 100 | 0.105 | 0.116 | 12.082 | 12.197 | 12.197 | 12.356 |
| text | 100 | 0.078 | 0.090 | 4.476 | 4.507 | 4.507 | 4.473 |
| network | 100 | 0.035 | 0.040 | 4.190 | 4.321 | — | 4.038 |
| raw | 1000 | 0.067 | — | 1.999 | 1.999 | 1.999 | — |
| local | 1000 | 0.114 | 0.166 | 4.336 | 4.379 | 4.379 | 4.773 |
| replicated | 1000 | 0.738 | 0.951 | 14.380 | 14.811 | 14.811 | 15.047 |
| text | 1000 | 0.090 | 0.132 | 5.489 | 5.583 | 5.583 | 6.128 |
| network | 1000 | 0.187 | 0.230 | 4.607 | 4.717 | — | 4.480 |

| Deployment | Tenants | Open s | Index setup s | Load s | Shutdown s | Clean recovery s | Loaded RSS / resident payload bytes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| raw | 1 | 0.000000667 | — | 1.346 | — | — | 2.065 |
| local | 1 | 0.202 | 0.029 | 156.815 | 1.802 | 47.114 | 4.258 |
| replicated | 1 | 0.534 | 0.057 | 376.497 | 4.443 | 119.991 | 4.882 |
| text | 1 | 0.229 | 0.028 | 234.405 | 1.173 | 104.87 | 5.531 |
| network | 1 | 0.417 | 0.035 | 223.429 | 1.09 | 29.221 | 4.291 |
| raw | 100 | 0.000002666 | — | 0.995 | — | — | 2.005 |
| local | 100 | 19.527 | 2.797 | 160.8 | 0.634 | 17.746 | 4.228 |
| replicated | 100 | 55.734 | 7.023 | 384.576 | 2.079 | 52.699 | 4.223 |
| text | 100 | 18.473 | 2.632 | 213.427 | 0.687 | 65.062 | 4.694 |
| network | 100 | 33.06 | 7.961 | 327.798 | 0.657 | 19.266 | 4.393 |
| raw | 1000 | 0.000003334 | — | 1.016 | — | — | 2.096 |
| local | 1000 | 191.966 | 41.802 | 192.086 | 0.576 | 17.692 | 4.546 |
| replicated | 1000 | 500.84 | 80.192 | 424.858 | 6.363 | 106.412 | 5.026 |
| text | 1000 | 173.486 | 48.556 | 271.754 | 2.444 | 119.304 | 5.755 |
| network | 1000 | 196.725 | 72.03 | 263.039 | 1.608 | 52.016 | 4.831 |

Shutdown drains database-owned work and releases storage. Recovery starts after completed shutdown and measures reopening with one verified read per tenant, including index reconstruction and readiness. Network recovery restarts the actual server while OpenBao and the issuer stay running. Crash and I/O-failure correctness have separate acceptance tests. In database case files, peak_rss_bytes is the OS process peak sampled after workloads and before shutdown; it is not refreshed after recovery and is not the final whole-run peak. The separately reported after-recovery RSS can exceed it. Raw cases sample their peak after lookups; network fixtures do not report a server lifetime peak. RSS snapshots and five-second sampling can miss short peaks; these figures are not heap-object sizes or maximum safe capacity.

### Incremental tenant overhead

These estimates divide the RSS difference from an independent one-tenant process by the added tenant count. They include runtime, policies, keys, audits, schemas and allocator effects, not isolated Raft allocations. Only completed cases with verified identities contribute. Negative estimates are retained as measurement noise, not described as memory savings.

| Deployment | Tenants | Stage | MiB/additional tenant | MiB/additional resident voter |
| --- | --- | --- | --- | --- |
| raw | 100 | empty_groups | 0.000789141 | — |
| local | 100 | empty_groups | 0.084 | 0.084 |
| local | 100 | empty_indexes | 0.107 | 0.107 |
| replicated | 100 | empty_groups | 0.348 | 0.116 |
| replicated | 100 | empty_indexes | 0.429 | 0.143 |
| text | 100 | empty_groups | 0.08 | 0.08 |
| text | 100 | empty_indexes | 0.116 | 0.116 |
| raw | 1000 | empty_groups | 0.000015641 | — |
| local | 1000 | empty_groups | 0.045 | 0.045 |
| local | 1000 | empty_indexes | 0.095 | 0.095 |
| replicated | 1000 | empty_groups | 0.683 | 0.228 |
| replicated | 1000 | empty_indexes | 0.899 | 0.3 |
| text | 1000 | empty_groups | 0.019 | 0.019 |
| text | 1000 | empty_indexes | 0.054 | 0.054 |
| network | 100 | empty_groups | 0.167 | 0.167 |
| network | 100 | empty_indexes | 0.194 | 0.194 |
| network | 1000 | empty_groups | 0.172 | 0.172 |
| network | 1000 | empty_indexes | 0.214 | 0.214 |

## Failures, retained runs and interpretation

The cohort manifest records 15 of 15 expected case outcomes. Terminal case coverage: **yes**. Completion with failures means the configured cases finished being attempted; it does not make failed or unattempted operations successful.

| Case | Recorded outcome | Exit code |
| --- | --- | --- |
| [raw-1](results/release-matrix-macos-arm64-20260905-06/raw-1.json) | passed | 0 |
| [local-1](results/release-matrix-macos-arm64-20260905-06/local-1.json) | passed | 0 |
| [replicated-1](results/release-matrix-macos-arm64-20260905-06/replicated-1.json) | passed | 0 |
| [text-1](results/release-matrix-macos-arm64-20260905-06/text-1.json) | passed | 0 |
| [network-1](results/network-rerun-macos-arm64-20260905-listener/network-1.json) | passed | 0 |
| [raw-100](results/release-matrix-macos-arm64-20260905-06/raw-100.json) | passed | 0 |
| [local-100](results/release-matrix-macos-arm64-20260905-06/local-100.json) | passed | 0 |
| [replicated-100](results/release-matrix-macos-arm64-20260905-06/replicated-100.json) | passed | 0 |
| [text-100](results/release-matrix-macos-arm64-20260905-06/text-100.json) | passed | 0 |
| [network-100](results/network-rerun-macos-arm64-20260905-listener/network-100.json) | passed | 0 |
| [raw-1000](results/release-matrix-macos-arm64-20260905-06/raw-1000.json) | passed | 0 |
| [local-1000](results/release-matrix-macos-arm64-20260905-06/local-1000.json) | passed | 0 |
| [replicated-1000](results/release-matrix-macos-arm64-20260905-06/replicated-1000.json) | passed | 0 |
| [text-1000](results/release-matrix-macos-arm64-20260905-06/text-1000.json) | passed | 0 |
| [network-1000](results/network-rerun-macos-arm64-20260905-listener/network-1000.json) | passed | 0 |


All selected cases in this cohort completed and matched their recorded result/executable identities.

The [first matrix](results/release-matrix-macos-arm64-20260905-01/matrix.json) failed at a replicated balanced-workload read. The [investigation](../docs/read-barrier-investigation.md) separates that observed failure from the controlled regressions proving snapshot scheduling and bounded fresh-quorum retry fixes. The [second matrix](results/release-matrix-macos-arm64-20260905-02/matrix.json) was interrupted to correct a disk-guard precedence bug; its completed raw case and partial local load are retained. The [third matrix](results/release-matrix-macos-arm64-20260905-03/matrix.json) passed the raw/local/replicated one-tenant cases and then stopped with a broken driver output pipe. The [fourth matrix](results/release-matrix-macos-arm64-20260905-04/TERMINATION.md) retained a separate five-second replicated read-quorum timeout and a redb reopen failure, then was explicitly stopped. The [shutdown investigation](../docs/shutdown-investigation.md) documents worker lifetime fixes and their controlled regressions; it does not claim the quorum timeout was caused by that defect. The [fifth matrix](results/release-matrix-macos-arm64-20260905-05/TERMINATION.md) passed raw/local; its replicated case completed all six 1,000-operation workloads and verified recovery, then was explicitly interrupted before final cleanup to correct missing embedded denial audits. The [audit investigation](../docs/embedded-audit-investigation.md) records that contract gap and its focused corrections. Subsequent runs log to regular files independently of the initiating tool session. Incomplete runs are not substituted for a completed matrix.

The [sixth matrix](results/release-matrix-macos-arm64-20260905-06/TERMINATION.md) completed fourteen cases, then its 1,000-tenant network fixture exited before readiness with `Invalid argument (os error 22)`. No network-1000 workload or document load ran. The [listener investigation](../docs/listener-startup-investigation.md) distinguishes the reproduced macOS reset-socket mechanism and connection-isolation correction from the inferred original syscall. The original failure is retained even if a later corrected network case succeeds. A configured 1,000-group entry in its partial capacity report does not prove those groups became ready.

Owned embedded reads precede shared reads over the same deterministic IDs. Owned calls return a document clone; shared calls return a retained immutable handle. Raw borrowing and these authenticated return paths have different contracts and cache state, so their ratio does not isolate the copying cost. Raw maps run in another process. Native RPC precedes MCP on the same server with a warmup read per credential. Cache state, retained allocations, receipts and audit growth therefore differ across these paths. Comparing their numerical ratios does not isolate one implementation cost or justify a Redis multiplier.

Leave headroom for snapshots, staged indexes, search writers, cursor results, receipts, audits and recovery. Repeat on the selected Linux deployment with concurrent clients and sustained pressure before setting operational capacity policy. The [benchmark protocol](README.md), [capacity definitions](CAPACITY.md) and [acceptance checklist](../docs/release-checklist.md) identify reproducible commands and the limits of these observations.
