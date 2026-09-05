# Final query and interface acceptance audit

Current acceptance is closed in the [final release closure](#release-closure-after-completed-measurements)
below. Earlier audit statements retain their historical source and status.

Inspected the current implementation and named passing test entries on source
`fffa308bc84d9ab5d015ec7f7f0c33af9b592d04a49ff0005b5633c4ab58ed33`.
This audit covers the query/interface requirements of the agreed plan. It does
not declare the full release complete: the full-size measurement matrix and its
interpretation remain separate deliverables.

The primary execution records are the
[macOS workspace log](../benchmarks/results/macos-validation-20260905-shutdown/1-test.log)
and [Linux full-gate log](../benchmarks/results/linux-validation-20260905-shutdown/full-gate.log).
Both contain the named tests below and have zero failures. Their manifests bind
the same source before and after execution. Review included the assertions and
implementation paths, rather than treating the test count or checklist as proof.

| Agreed requirement | Current source and direct evidence | Conclusion |
| --- | --- | --- |
| Typed JSON expression tree, JSON Pointer paths, Boolean/equality/range/membership filters | [wire types](../crates/kasumi-types/src/lib.rs), [structured evaluator](../crates/kasumi-query/src/structured.rs), [scalar validation](../crates/kasumi-query/src/scalar.rs). The independent-reference test compares 16 compound predicates over 180 documents against native integer/string logic; pointer and invalid-query tests exercise escaping and validation even without hits. | Covered. Declared index types govern indexed values; explicitly admitted scans retain JSON scalar distinctions. |
| Sorting, projection, bounded grouping and count/sum/min/max/avg | [query execution and accumulators](../crates/kasumi-query/src/lib.rs), tests `aggregate_validation_and_empty_collection_are_data_independent`, `groups_distinguish_absent_and_null_and_skip_empty_numeric_inputs`, `candidate_group_and_response_budgets_fail_closed`. Field counts, candidates, groups and exact serialized output are bounded. | Covered. Count is a JSON integer; exact numeric aggregates are decimal strings as documented. |
| Missing distinct from null, no implicit coercion or floating-point rounding; explicit average scale with half-even rounding | [scalar](../crates/kasumi-query/src/scalar.rs) uses a distinct Missing variant and BigDecimal; `exact_average` computes integer quotient/remainder and rounds ties to even. Tests cover values beyond f64 precision, missing/null/empty arrays, positive/negative ties and absent scale. | Covered within documented number-size/exponent/work limits. Search rank alone uses floating-point scores. |
| JSON Schema 2020-12, no remote/file resolution or executable extensions | [validation](../crates/kasumi-query/src/validation.rs) validates the draft meta-schema, installs an always-rejecting external retriever, permits only local fragments and registers no executable extensions. [manifest](../crates/kasumi-query/Cargo.toml) disables default network/file features and enables arbitrary precision. Exact-schema and forbidden-resolution tests inspect these behaviors. | Covered. The documented supported profile excludes `$id` rebasing and uses non-backtracking regex. |
| Versioned schema/index operations; incomplete indexes never serve | [ordered engine application](../crates/kasumi-engine/src/state.rs) assigns the tenant revision, validates a staged definition, advances policy generation, materializes indexes, then publishes one ArcSwap generation. [query update](../crates/kasumi-query/src/lib.rs) rebuilds changed definitions. Receipt/schema and incremental-definition tests verify historical data and rebuild behavior. | Covered through tenant operation revisions; no separate schema-version field is claimed. |
| RAM Tantivy, versioned Unicode/English/Japanese analyzers, Lindera, ranked terms/phrase/prefix/bounded fuzzy | [search](../crates/kasumi-query/src/search.rs), lockfile and analyzer enum; named tests cover English stemming/surface prefixes/phrase positions, Unicode normalization and rank, Japanese segmentation/phrases/typos, fuzzy distance and expansion limits. | Covered. Query expansion, planned postings, input text and candidate counts have explicit bounds. |
| Reader commit/reload before matching document publication and acknowledgment | Text build/update commits the writer, completes merges, and captures a manually reloaded reader before returning. Engine publication follows complete index materialization. Tests `text_generation_is_immutable_and_reader_is_ready_when_published`, `incremental_text_updates_reuse_index_and_preserve_every_old_snapshot` and stale-branch rejection inspect successive readers and rows. | Covered. A failed committed materialization makes the replica unavailable; it does not publish a partial reader. |
| Linearizable first query; historical subsequent pages bound to identity, policy, query, incarnation and leadership; 60-second default expiry; current access checked each page | [Database query](../crates/kasumi-engine/src/service.rs) establishes its barrier before capturing the generation, stores a random opaque token with all bindings, and checks current policy and key access before release. [concurrent pagination](../crates/kasumi-engine/tests/concurrent_pagination.rs) overlaps 31 pages with atomic 32-document writes; [replicated service test](../crates/kasumi-engine/tests/replicated.rs) rejects old cursors after leader change. | Covered. Already released plaintext remains with the trusted caller. |
| Shared embedded/native/MCP authorization and exact JSON serialization | Native methods and MCP tools call the same [Database service](../crates/kasumi-engine/src/service.rs). [Protobuf](../crates/kasumi-server/proto/kasumi.proto) uses UTF-8 JSON bytes. The adapter round-trip test verifies `90071992547409931234567890.123456789`, receipt replay, queries and discovery through both adapters; cross-tenant/scope/admin tests require matching denials. | Covered. The embedding application is trusted to supply its authenticated context. |
| Current MCP 2026-07-28 through official SDK, protected-resource discovery, per-request authentication, no legacy mode or token passthrough | [MCP adapter](../crates/kasumi-server/src/mcp.rs) selects only the SDK's 2026-07-28 version, disables legacy sessions, requires stateless protocol metadata and verifies each HTTP request. Tests exercise current discovery/tools, forbidden legacy/metadata/origin combinations and configured metadata/challenges. The five tools have no admin tool or tenant override. | Covered. Network TLS and token signature/issuer/audience/expiry/scope validation have additional auth/TLS tests and live process fixtures. |
| Data/schema discovery, point/query/atomic mutations/receipt lookup; separate administration | Five [native data methods](../crates/kasumi-server/proto/kasumi.proto) match five MCP tools; administration uses a distinct service/listener and [CLI](../crates/kasumi-server/src/bin/kasumictl.rs). Adapter tests reject admin/control route escalation. | Covered. Storage/security audit covers the administrative lifecycle itself. |
| Bounded query/cursor/response work, cancellation and release checks | [admission](../crates/kasumi-engine/src/admission.rs), [Database worker and output ownership](../crates/kasumi-engine/src/service.rs), [query cancellation](../crates/kasumi-query/src/cancellation.rs), MCP envelope counter and native byte limits. Tests cover candidate/group/result caps, cancellation, response-policy/key changes and abandoned worker output through shutdown. | Covered with the documented distinction between logical quotas, sampled RSS and estimated workspace reservations. |

No missing query/interface feature was identified within this scope. This is
acceptance evidence for the documented software contracts, not an assertion of
independent MCP certification, arbitrary unbounded queries, or production
latency/capacity. The [main checklist](release-checklist.md) retains the complete
plan and outstanding release measurements.

## Subsequent embedded audit correction

The source and macOS/Linux gate identities above are historical and remain
unchanged. A later cross-interface review found that embedded `Database`
authorization/seal denials were enforced but lacked the durable independent
service record that network adapters supplied. The shared authorization result
was covered above; parity of the denial-audit side effect was missing. Run05
was explicitly stopped before correcting that gap.

The [embedded audit investigation](embedded-audit-investigation.md) documents
the mandatory common service writer, public database and standalone restore
coverage, per-error nonwire attempt marker, cancellation/drain handling, and
retained adapter routing/protocol/response-fence audits. Its focused tests
establish exactly one denial record across embedded/native/MCP and continued
durable coverage before dispatch and after encoding. These are subsequent
changes, not claims about the earlier frozen source. Fresh
[macOS](../benchmarks/results/macos-validation-20260905-embedded-audit/evidence.json)
and [Linux](../benchmarks/results/linux-validation-20260905-embedded-audit/evidence.json)
gates now pass on source
`a3205990001d86ea66e4ac457fba29ef634b7b6923dfdaa5d80cf2916d517df2`:
186 workspace test entries with zero failures on each platform, strict Clippy,
formatting, six Python checks and one actual OpenBao test per platform. The
fresh [MinIO test](../benchmarks/results/linux-validation-20260905-embedded-audit/minio-evidence.json)
also passed using the corrected source. Complete release measurements remain
required before final release acceptance.

## Current frozen-source supplement

The historical identities and conclusions above are retained. The current
review covers source
`28aeb80168d3ab02a0eec7bf2a0163a7cb99dbfd74adf596e849de17e1fa3c1d`.
The [source-change manifest](../benchmarks/results/listener-startup-20260905/source-change.json)
proves that only `crates/kasumi-server/src/tls.rs` changed after the corrected
`a320…` source. Its connection setup failure now closes and audits that connection
while allowing the listener to serve subsequent clients.

The current [macOS gate](../benchmarks/results/macos-validation-20260905-listener/evidence.json)
and [Linux gate](../benchmarks/results/linux-validation-20260905-listener/evidence.json)
each passed **188 workspace test entries**, with zero failures and two explicit
external-service opt-ins ignored in the workspace invocation. Strict Clippy,
formatting and six Python tests passed. Actual OpenBao passed separately on
[macOS](../benchmarks/results/macos-validation-20260905-listener/5-test.log)
and [Linux](../benchmarks/results/linux-validation-20260905-listener/full-gate.log).
The [MinIO evidence](../benchmarks/results/linux-validation-20260905-listener/minio-evidence.json)
records a passing current macOS client against the pinned Linux container.
These records bind unchanged source hashes and preserve the client/platform
distinction.

A narrow read-only review of the evaluator, schema validator, text reader
publication, pagination and adapter dispatch/release paths found no additional
uncovered query/interface requirement within the documented limits. The
[macOS test log](../benchmarks/results/macos-validation-20260905-listener/1-test.log)
and [Linux test log](../benchmarks/results/linux-validation-20260905-listener/full-gate.log)
both contain these direct checks:

- `indexed_boolean_filters_match_independent_reference_evaluator`,
  `decimal_sort_range_and_sum_preserve_more_than_f64_precision`, and
  `schemas_never_resolve_remote_or_file_resources_or_rebase_fragments`.
- `japanese_lindera_terms_phrases_and_fuzzy_typos`,
  `incremental_text_updates_reuse_index_and_preserve_every_old_snapshot`, and
  `snapshot_pages_overlap_atomic_writers_and_current_policy_revocation`.
- `native_and_mcp_share_exact_data_receipts_query_and_authorization`,
  `embedded_native_and_mcp_denials_have_one_durable_record_per_request`, and
  `mcp_rejects_legacy_mismatched_metadata_bad_origins_and_unauthenticated_calls`.
- `quoted_payload_stays_within_wire_limit_without_redundant_text_copy` and
  `shared_adapter_release_audits_a_seal_after_response_encoding`.
- `socket_setup_failure_is_audited_and_does_not_stop_listener` and
  `reset_queued_before_listener_start_is_audited_and_next_tls_request_succeeds`.

The full-size benchmark proof remains pending. Passing these gates does not
erase the retained sixth matrix's network startup failure or establish its
replacement measurement outcome, production capacity, or a speedup claim.

## Release closure after completed measurements

The measurement prerequisite recorded above is now satisfied by the
[selected cohort](../benchmarks/results/release-cohort-macos-arm64-20260905-listener/cohort.json):
**15 passing cases and 99,000 successful measured operations**, with zero failed
or unattempted operations. Each case loaded one million 1 KiB documents across
1, 100 or 1,000 tenants. Coverage includes raw access, embedded reads, local and
replicated durable writes, structured queries, English/Japanese search, and
authenticated native RPC and MCP. The corrected network supplement contributes
30,000 successful operations; its 1,000-tenant case completed shutdown in
1.60811675 seconds and recovery in 52.016212458 seconds.

This is an explicitly selected cohort across two source identities, rather than
one execution. Twelve engine cases retain their original `a320…` identity and
exact matching engine executable; all three network cases use `28aeb…` after the
proven TLS-only change. The earlier network startup failure remains archived.
The [results](../benchmarks/RESULTS.md) and
[capacity evidence](../benchmarks/results/release-cohort-macos-arm64-20260905-listener/capacity.json)
retain the original records, host-load qualifications, setup filesystem activity,
separate interface guarantees and sample-size limits. They establish neither
maximum production capacity nor a Redis speedup ratio.

With the implementation review, current platform/service gates and completed
measurement coverage, no agreed query/interface requirement remains open within
this audit's documented scope. The historical pending statements above describe
their respective review stages; this closure does not rewrite those records.
