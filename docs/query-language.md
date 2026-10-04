# Query language

Every interface accepts the same query JSON: Rust (`kasumi_types::QueryRequest`),
native gRPC (`Query`), MCP (`kasumi_query`) and snapshot reads. Snapshot reads
accept complete snapshot queries, so they reject cursors and seek paging. The
Rust types also have a builder, shown beside each JSON form.

```json
{
  "collection": "invoices",
  "filter": {"/status": "open", "/amount": {"gte": 10, "lt": 100}},
  "sort": ["-/amount"],
  "select": ["/amount", "/customer/name"],
  "limit": 20
}
```

```rust
let query = QueryRequest::new("invoices")
    .filter(Filter::new().eq("/status", "open").gte("/amount", 10).lt("/amount", 100))
    .sort_desc("/amount")
    .select(["/amount", "/customer/name"])
    .limit(20);
```

Only `collection` is required. Unknown members, duplicate members and
operators in the wrong place are rejected with a message that names the fix.

## Field paths

Fields are [JSON Pointers](https://www.rfc-editor.org/rfc/rfc6901): `/amount`,
`/customer/name`, `/tags`. A key containing `/` or `~` is escaped as `~1` or
`~0`. Index definitions use the same paths.

## Filters

A filter is an object, and every entry must hold. `{}` (or no filter) matches
every document.

- A key that starts with `/` is a field. Map it to a value for equality, or to
  an object of operators that must all hold.
- `and` takes a list of filters that must all hold. It is needed only for two
  conditions that cannot share one object, such as two `contains` on one array.
- `or` takes a list of filters, at least one of which must hold.
- `not` takes one filter that must not hold.

Because fields always start with `/`, a document field can never be mistaken
for an operator.

```json
{
  "/status": "open",
  "/deleted_at": {"exists": false},
  "or": [{"/region": {"in": ["eu", "jp"]}}, {"/priority": {"gte": 8}}],
  "not": {"/tags": {"contains": "test"}}
}
```

```rust
Filter::new()
    .eq("/status", "open")
    .missing("/deleted_at")
    .and(Filter::or([
        Filter::new().is_in("/region", ["eu", "jp"]),
        Filter::new().gte("/priority", 8),
    ]))
    .and(!Filter::new().contains("/tags", "test"))
```

| Operator | Matches documents where the field… | Builder |
| --- | --- | --- |
| `value` or `{"eq": value}` | equals `value` (`null` matches an explicit null) | `.eq(path, v)` |
| `{"ne": value}` | is absent or does not equal `value` | `.ne(path, v)` |
| `{"gt": v}` `{"gte": v}` `{"lt": v}` `{"lte": v}` | is in the range; bounds on one field form one range | `.gt` `.gte` `.lt` `.lte` |
| `{"in": [v, …]}` | equals one of up to 256 values | `.is_in(path, values)` |
| `{"nin": [v, …]}` | is absent or equals none of the values | `.not_in(path, values)` |
| `{"exists": true}` / `{"exists": false}` | is present (even as null) / absent | `.exists(path)` / `.missing(path)` |
| `{"contains": value}` | is an array containing `value` | `.contains(path, v)` |

Missing fields and explicit `null` stay distinct. Range operators never match
absent, null, or differently typed values, and a range cannot mix types. Use
either `gt` or `gte`, and either `lt` or `lte`. Equality to an object or array
is written `{"eq": …}`, because an object value is read as operators.

Declared index fields keep their type: `number` fields compare exact JSON
numbers and `decimal` fields compare decimal strings. There is no coercion, so
`{"/amount": "10"}` on a number field is an error, not a silent mismatch.

Filters nest at most 16 levels and hold at most 256 conditions.

### Indexes and scans

Filtering, sorting or grouping on a field needs a declared index on it. A
query on an undeclared field fails with `INDEX_REQUIRED` unless it sets
`"allow_scan": true`. Scans read documents and stay bounded by the tenant's
candidate limit, so declare indexes for anything on a hot path.

The planner evaluates the conditions of a filter cheapest first. It uses index
cardinalities (an equality on a rare value runs before a broad range), walks
each field's bounds as a single index range, and checks scanned and negated
conditions last, only against the remaining candidates. The order of entries
in your JSON does not affect performance.

## Sorting

`sort` lists up to 8 keys: a JSON Pointer, prefixed with `-` for descending.
Ties fall back to document ID order.

```json
"sort": ["-/amount", "/created_at"]
```

Values order as: absent, null, booleans, numbers, strings. Array fields cannot
be sort keys. A search query without `sort` is ordered by relevance.

## Selecting fields

`select` returns only the listed fields, keeping their nesting, so a selected
row has the same shape as the document:

```json
"select": ["/amount", "/customer/name"]
```

returns bodies such as `{"amount": 12.5, "customer": {"name": "Ada"}}`. Paths
cannot repeat or contain one another, and a path through an array is treated
as absent: select the whole array instead. Without `select`, rows hold whole
documents. In Rust, `QueryPage::decode::<T>()` deserializes selected rows into
a struct of the same shape.

## Pages

`limit` (default 100, at most the tenant's `max_page_size`, 1000 by default)
caps rows per page. A page also stays within the tenant's `max_result_bytes`
(8 MiB by default); a page of large documents may hold fewer rows, and then
returns a cursor. If a single row together with the required cursor exceeds
the byte limit, the query fails with `RESOURCE_EXHAUSTED`; select fewer fields
or increase the configured limit.

For the next page, resubmit the identical query with the returned `cursor`. All
pages read the snapshot of the first page: no row is skipped or repeated even
while documents change. A cursor lasts `cursor_ttl_ms` (60 seconds by default)
and is bound to the caller, the query, the policy and the leader term. After
expiry, a policy change or a leader change, continuing reports
`CURSOR_EXPIRED`; run the query again.

Only the first page is copied. The rows after it stay in memory as references
to the documents the query read, and each continuation copies just its own
page. Because later writes may replace those documents, each one is charged as
if only the cursor kept it alive. A tenant's open cursors may retain at most
`max_cursor_bytes` (256 MiB by default) on that basis, about 1 KiB per object
member, and at most `max_cursors` (128) cursors at once. A query whose rows
exceed the budget fails with `RESOURCE_EXHAUSTED`; narrow its filter or use
seek paging.

The Rust client follows cursors for you: `Kasumi::next_page(&page)` and
`Kasumi::query_all(&query)`. `query_all` collects row queries into one vector,
whose memory may exceed a single page's decode budget; it rejects aggregate
queries. Use `query` and `QueryPage::aggregates()` for aggregates.

### Seek paging

For results too large for a snapshot cursor, or walks that outlast one, set
`"paging": "seek"`. Each page is read straight from a unique index, after the
last row of the previous page, so a page costs the same however large the
result is and the server keeps nothing between pages.

```json
{
  "collection": "events",
  "filter": {"/tenant": "acme", "/at": {"gte": "2026-01-01"}},
  "sort": ["/at", "/event_id"],
  "paging": "seek",
  "limit": 500
}
```

```rust
let query = QueryRequest::new("events")
    .filter(Filter::new().eq("/tenant", "acme").gte("/at", "2026-01-01"))
    .sort_asc("/at")
    .sort_asc("/event_id")
    .paging(Paging::Seek)
    .limit(500);
```

The query must describe one unique index, here one on `/tenant`, `/at` and
`/event_id`:

- the filter fixes the index's leading fields with equality and may bound the
  next field with one range (`gt`, `gte`, `lt`, `lte`);
- `sort` lists the remaining fields through the index's last one, all in one
  direction; it may also start with fixed fields;
- there are no other conditions, no `search` and no aggregates.

Other queries fail with `INDEX_REQUIRED` or `INVALID_ARGUMENT` stating these
rules. `select` and `limit` work as usual.

Unique indexes are sparse: documents missing any indexed field are omitted
from a seek walk; explicit `null` values remain indexed.

Continue with the returned `cursor` as for snapshot paging. Seek cursors never
time out, and every page reports the first page's revision: if the collection,
its indexes, the policy or the schema change between pages, continuing reports
`CURSOR_EXPIRED`. To resume, start a new walk with a `gte` range from the last
row's value of the ranged field and skip the rows already processed. Seek pages
read resident documents only; they do not walk archived history.

## Aggregates

A query with `aggregate` returns groups instead of rows. Name each aggregate:

```json
{
  "collection": "invoices",
  "filter": {"/status": "paid"},
  "group_by": ["/region"],
  "aggregate": {
    "invoices": {"count": "*"},
    "with_due_date": {"count": "/due_at"},
    "revenue": {"sum": "/amount"},
    "largest": {"max": "/amount"},
    "mean": {"avg": "/amount", "scale": 2}
  }
}
```

```rust
QueryRequest::new("invoices")
    .filter(Filter::new().eq("/status", "paid"))
    .group_by(["/region"])
    .aggregate("invoices", Aggregation::count())
    .aggregate("revenue", Aggregation::sum("/amount"))
    .aggregate("mean", Aggregation::avg("/amount", 2))
```

The response's `aggregates` holds one entry per group, ordered by group key:

```json
{"group": {"region": "eu"}, "values": {"invoices": 12, "revenue": 4310.75, "mean": 359.23}}
```

- `{"count": "*"}` counts matching documents; `{"count": "/f"}` counts
  documents where `/f` is present and not null.
- `sum`, `min`, `max` and `avg` need a numeric field and skip absent or null
  values. Results keep the field's type: exact JSON numbers for `number`
  fields, decimal strings for `decimal` fields. Arithmetic is exact.
- `avg` requires `scale` (0–1000 decimal places) and rounds half-even once.
- An empty group sums to `0`; its `min`, `max` and `avg` are `null`.
- `group_by` keys are scalar fields; a missing key is omitted from `group`,
  which keeps it distinct from an explicit `null`.
- `sort`, `select` and `limit` do not apply to aggregate queries and are
  rejected. Groups are bounded by `max_query_groups` (10,000 by default).

Counting matching documents (`{"count": "*"}` without `group_by`) under an
indexed filter reads no documents at all: it is answered from the indexes.

## Full-text search

`search` ranks documents with a declared text index:

```json
"search": {"index": "description_ja", "query": "東京 タワー"}
```

`mode` is `terms` (default: every term, any order), `phrase`, `prefix` (the last
term is a prefix) or `fuzzy` (each term within `distance` edits, default 1, at
most 2). Search combines with `filter`, `sort`, `select`, paging and
aggregates. Analyzers are chosen per index: `unicode_v1`, `english_v1`
(stemming) or `japanese_v1` (Lindera IPADIC).

## Writes

A `MutationBatch` applies atomically within one tenant:

```json
{
  "idempotency_key": "order-1001",
  "operations": [
    {"op": "put", "collection": "orders", "id": "1001", "body": {"total": 42}, "expected": "absent"},
    {"op": "put", "collection": "stock", "id": "sku-7", "body": {"count": 3}, "expected": {"version": 18}},
    {"op": "delete", "collection": "carts", "id": "c-55"}
  ]
}
```

```rust
let batch = MutationBatch::with_key("order-1001")
    .insert("orders", "1001", json!({"total": 42}))
    .replace("stock", "sku-7", json!({"count": 3}), 18)
    .delete("carts", "c-55");
```

`patch` changes part of an existing document with an
[RFC 7396 JSON Merge Patch](https://www.rfc-editor.org/rfc/rfc7396). A document
patch must be a JSON object: members
set to `null` are removed, nested objects merge, and any other value (including
an array) replaces the member. The merged document is validated like a `put`
body, so a patch that removes a required field is rejected. Patching a missing
document fails with `NOT_FOUND`; use `put` to create it.

Patches also budget the existing documents they must copy. Their combined
source size must fit `max_batch_bytes` for an ordinary batch or
`atomic.max_transaction_bytes` for a staged transaction. Copying must fit the
admitted workspace as well. Oversized expansion returns `RESOURCE_EXHAUSTED`
before any document changes; use smaller batches when needed.

```json
{"op": "patch", "collection": "orders", "id": "1001", "patch": {"status": "paid", "note": null}, "expected": {"version": 19}}
```

```rust
MutationBatch::new().patch_version("orders", "1001", json!({"status": "paid", "note": null}), 19)
```

`expected` is checked against the document when the batch applies: `"any"`
(the default), `"absent"`, or `{"version": n}`. The builder spells these
`upsert`, `insert`, `replace`/`patch_version`/`delete_version`. Any failed check, schema
violation, uniqueness conflict or quota rejects the whole batch (for example
with `CONFLICT` or `SCHEMA_VIOLATION`); nothing is partially applied.

The idempotency key makes retries safe. `MutationBatch::new()` generates a
random key; derive it from a stable request ID with `with_key` when a retry may
come from another process. After a lost response or `UNKNOWN_OUTCOME`, resend
the identical batch: the database returns the original outcome instead of
applying it twice. `Kasumi::mutate` does this automatically until its deadline.

`read_set` (optional) makes a batch conditional on earlier reads, including
phantoms: use `SnapshotReadResponse::read_assertions()` from a coherent snapshot
read. See [transaction contracts](transactions.md).

## Command line

`kasumictl --profile` runs the same reads and writes from a shell, using an
installed client profile. Rows, groups and receipts print as one JSON object per
line, ready for `jq`; a missing document exits with status 1.

```sh
kasumictl --profile /var/lib/kasumi/profiles/default.json get invoices inv-1
kasumictl --profile /var/lib/kasumi/profiles/default.json query invoices '{"/status":"open"}' --sort -/amount --limit 20
kasumictl --profile /var/lib/kasumi/profiles/default.json query --json @monthly-totals.json
kasumictl --profile /var/lib/kasumi/profiles/default.json put invoices inv-2 '{"status":"open","amount":42}' --if absent
kasumictl --profile /var/lib/kasumi/profiles/default.json patch invoices inv-2 '{"status":"paid"}' --if 7
kasumictl --profile /var/lib/kasumi/profiles/default.json delete invoices inv-2
kasumictl --profile /var/lib/kasumi/profiles/default.json mutate @batch.json
kasumictl --profile /var/lib/kasumi/profiles/default.json collections
```

JSON arguments can be inline, `@path` or `-` for standard input. `query` prints
the first page and notes when more remain; `--all` follows every cursor,
including with `query --json @query.json --all`, and
`--seek` selects [seek paging](#seek-paging) for walks of any size. Writes
use a fresh idempotency key unless `--key` names one, and resend it themselves
after an uncertain outcome. Use a stable `--key` when a script may retry a
write across invocations. A failed write reports its key so an uncertain
outcome can be resolved by retrying the identical batch with that key.

## Limits

| Limit | Default | Tenant setting |
| --- | --- | --- |
| Rows per page | 100 (max 1000) | `max_page_size` |
| Bytes per page | 8 MiB | `max_result_bytes` |
| Data retained by open cursors | 256 MiB | `max_cursor_bytes` |
| Open cursors | 128 | `max_cursors` |
| Cursor lifetime | 60 s | `cursor_ttl_ms` |
| Candidate documents | 100,000 | `max_query_candidates` |
| Groups | 10,000 | `max_query_groups` |
| Filter depth / conditions | 16 / 256 | fixed |
| `in` / `nin` values | 256 | fixed |
| Sort / select / group_by / aggregates | 8 / 64 / 8 / 16 | fixed |
| Search text | 4096 bytes, 64 tokens | fixed |
