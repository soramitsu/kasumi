# Query and validation contract

`QueryIndexes::build` constructs immutable per-collection structured indexes and RAM
Tantivy readers. Publish its result with the corresponding document generation.
`execute` accepts that same generation and returns all bounded, ordered rows; the
tenant engine owns authorization, revision assignment, and snapshot pagination.

## Structured queries

Field paths are JSON Pointers. Declared indexes maintain ordered scalar postings
and a separate presence set. Filters actually consult those postings; undeclared
filter/sort/group/aggregate paths require `allow_scan: true`. A collection-wide
`all` query walks the resident ID set and remains candidate-budget limited.
Boolean predicates support at most 16 levels and 256 nodes. `in` accepts at most
256 values. `contains` targets declared string/number arrays, with non-null elements.

Scalars sort as absent, null, Boolean, number, then string. Declared scalar types
do not coerce: `number` is an exact JSON number; `decimal` is an exact decimal
string. Numeric input is limited to 100 digits, 256 bytes, and exponent ±1000.
Array values cannot be used as sort or group keys. Stable ID order breaks ties;
text search defaults to descending BM25 score unless explicit field sorting is used.

Projection returns an object keyed by the requested pointers, omitting absent
values. For example, `projection: ["/profile/name"]` yields
`{"/profile/name":"Ada"}`. An empty projection returns the complete body.

Aggregation operates over the complete filtered snapshot. Every entry is
`{"group": {"/field": value}, "values": {"alias": value}}`. Missing group keys
are omitted and therefore remain distinct from explicit null. `count` without a
field counts rows; with a field, it counts non-null present values. `sum`, `min`,
`max`, and `avg` require numeric values and skip absent/null inputs. Numeric outputs
are exact decimal strings; count is a JSON integer. Empty sum is `"0"`; empty
min/max/average are null. Average requires scale 0–1000 and uses integer arithmetic
for one final half-even rounding. Group cardinality and serialized result bytes
are explicitly bounded by tenant limits. The page limit does not silently truncate
the snapshot before aggregation or pagination.

## Full text

`unicode_v1` uses NFKC, Unicode word splitting, and lowercase. `english_v1` adds
English stemming for terms and phrases; prefix/fuzzy use unstemmed surface tokens.
`japanese_v1` uses Lindera's embedded IPADIC segmentation with NFKC and lowercase.
Dependency versions are fixed by the workspace lockfile; changing tokenization
requires a new analyzer version and index rebuild.

Terms are conjunctive within each indexed field, with alternative fields ranked
by their best score. Phrase queries preserve positions. Prefix expands only the
last token. Fuzzy supports edit distance 0–2, including adjacent transpositions.
English/Unicode fuzzy terms require three characters for nonzero distance.
Single-character Japanese tokens stay exact; Japanese fuzzy also tests whole
whitespace-separated compounds, because a typo can change morphological splitting.

Query text is limited to 4096 bytes and 64 tokens. Each expansion has at most 64
terms, with 256 expanded terms across the entire query. Planned term-document
postings cannot exceed eight times the query candidate limit. Matches are counted
while driving Tantivy scorers, rather than relying on a top-k output limit.
Document text has at most 65,536 tokens across all declared fields/indexes, with
240 bytes per token. These deterministic limits run during validation, before
consensus application materializes an index. Writers commit, finish merges, and
explicitly reload the reader before a generation can be published.

## Schemas and uniqueness

Validators compile JSON Schema 2020-12 with exact-number support and a non-
backtracking regex engine. Documents must be objects. Schemas are at most 256 KiB;
documents/schemas are limited to 48 nesting levels and 20,000 JSON nodes. References
are local fragments only; `$id` rebasing is not supported. A custom retriever
unconditionally rejects external resources, and network/file features are disabled.
No executable extensions are registered. Validator errors mask instance values.

Unique indexes compare compound typed keys exactly. Missing components do not
participate; explicit null does. Unique arrays and unique text indexes are rejected.

## Incremental publication and cost

`QueryIndexes::update` accepts the previous and staged collections plus every
changed document ID from ordered application. It reuses unchanged collections and
updates only changed keys in persistent ordered maps/sets. Compound unique-index
checks similarly remove all old keys before checking the entire staged batch, so
atomic key swaps work. The engine can call `validate_unique_changes` to reject
conflicts deterministically before materializing a new generation.

Text updates reopen the same RAM index, delete/add changed documents, commit, and
capture a freshly reloaded reader. Historical generations keep their own searchers
and persistent row maps. Changes to unrelated document fields retain the text
reader directly. The writer and its worker buffers are released between applies.
Stale update branches are rejected; a failed writer corridor requires recovery.
New or changed index definitions rebuild before publication. A changed collection
without supplied delta IDs falls back to a full rebuild.

These mechanisms are tested against full rebuilds and retained snapshots, including
successive text commits. They are not evidence of the final write-throughput or
million-document capacity targets: the release benchmark must measure writer
creation, commit/reload, memory, and replica-application costs.
