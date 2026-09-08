# Literal JSON inbound audit

Scope: read-only source audit of checkout `47b28e421670bb8f02036edc6bbc65dd7e06e2c4`,
locked serde_json 1.0.151 and rmcp 3.2.0. No code was changed, compiled or executed.
Examples below are deductions from the exact decoder branches, not a report of
native execution. The SDK parser under development was reviewed for sharing;
its uncompiled state is not acceptance evidence.

## Confirmed mechanism and baseline

`serde_json-1.0.151/src/value/de.rs:125–134` classifies the **first decoded object
key**. With `arbitrary_precision`, `$serde_json::private::Number` invokes
`NumberFromString` and returns a Number. With `raw_value`,
`$serde_json::private::RawValue` takes the string and invokes a new
`crate::from_str(value.get())`, returning the parsed Value rather than the
literal object. `KeyClassifier` at lines 1357–1379 compares decoded strings, so
Unicode-escaped spellings of the same key have the same behavior. Other first
keys take the ordinary object path. Invalid marker string contents fail parsing;
they are not preserved as ordinary user data.

The checked-in frozen Linux report
`docs/evidence/frozen-linux-arm64-3a8d512-terminal-20260908/run/evidence.json`
names source `3a8d5121e1ddee14ae8a6d938d12152eaa04e417`, overall `failed`, and
passed production and network-driver compilation gates. Its actual compiled
serde_json feature sets are:

- Production: `alloc, arbitrary_precision, default, float_roundtrip, raw_value, std`.
- Network driver: `arbitrary_precision, default, std`.

Thus both marker branches already affect the old production server; Number also
affects that old network driver. The new SDK work does not introduce this server
problem. This audit does not attribute raw_value to a particular dependency.

## Concrete counterexamples

These fragments occupy a `Value` field, with marker as its first/only key:

| Input literal | Source-derived decoded value |
|---|---|
| `{"x":{"$serde_json::private::Number":"7"}}` | `{"x":7}` |
| `{"x":{"$serde_json::private::RawValue":"{\"ok\":true}"}}` | `{"x":{"ok":true}}` |
| `{"x":{"$serde_json::private::RawValue":"not JSON"}}` | Decode error, although the outer JSON is valid |
| `{"op":"eq","field":"/x","value":{"$serde_json::private::Number":"7"}}` | Predicate with numeric value 7, instead of the supplied object |

The first two can be `Mutation::Put.body` contents while the document root stays
an object. Existing schema validation then sees the transformed body. A numeric
predicate object which should fail scalar validation can instead become a valid
numeric predicate (`kasumi-query/src/structured.rs:166–187`).

This also prevents valid schema property names: in a collection schema,
`"properties":{"$serde_json::private::RawValue":{"type":"string"}}`
reaches the marker branch for the properties object, which expects a string
instead of its legitimate nested schema object.

The RawValue branch parses JSON hidden inside a JSON string with a fresh
deserializer (default recursion budget 128 at serde_json `de.rs:63`). For example,
a string containing a nested array is no longer one string node: it creates the
array's nodes after the outer parse. Outer array nesting plus separately parsed
inner array nesting can exceed one combined parser depth budget. Current document
validation still checks the resulting tree for depth 48 and 20,000 nodes
(`kasumi-query/src/validation.rs:11–30,155–163`), but only **after** allocation and
reinterpretation. This is not evidence that oversized documents can commit.
Likewise, the byte limits still bound transport/record input; this audit makes no
claim of unbounded or measured resource consumption.

## Exact typed Value inventory

All of these fields currently derive ordinary serde Deserialize:

| Canonical type and source | Value-bearing fields | Relevant wrappers |
|---|---|---|
| `kasumi-types/src/lib.rs:250` Document | `body: Value` | CollectionState, change events/records, history chunks, snapshot points/scans |
| `lib.rs:258` CollectionDefinition | `schema: Value` | Create/replace collection, SchemaChangeSet, schema views, CollectionState |
| `lib.rs:329` Mutation::Put | `body: Value` | MutationBatch, StagedChunk, AppendStagedChunk, Command/Operation, snapshots |
| `lib.rs:530` Predicate | Eq/Compare/Contains `value`, In `values: Vec<Value>` | QueryRequest and coherent read queries |
| `lib.rs:646` QueryRow | `body: Value` | QueryResponse and coherent read results |
| `lib.rs:653` QueryResponse | `aggregates: Vec<Value>` | Native/MCP read output and SDK input |
| `history.rs:142` ArchivedDocument | `indexed_fields: BTreeMap<String, Value>` | Archived snapshot records |
| `security_audit.rs:46` SecurityAuditPage | `records: Vec<Value>` | Audit response/SDK path, not document mutation input |

ReadAssertion and document version Precondition contain typed names, integer
versions and timestamps, not Value. They do not add another generic JSON-value
condition surface. Their enclosing mutation/stage still carries the fields above.

## Affected decoding boundaries

1. **Native input:** `server/api.rs:257` checks `(8 MiB + 64 KiB)` and calls
   `serde_json::from_slice<T>`. `rpc.rs:270` uses it for MutationBatch, `:312` for
   AppendStagedChunk, `:167/:245` for QueryRequest/read snapshots, `:1039/:1048`
   for collection schemas; schema activation and generic management also pass
   Value-bearing canonical DTOs through this helper. This occurs before database
   command workspace reservation. An API-helper correction alone cannot repair
   the independent downstream decoding sites.
2. **MCP input, before Kasumi handler:** rmcp's
   `transport/common/server_side_http.rs:205–254` bounds collected bytes, then
   decodes `ClientJsonRpcMessage`. `model.rs:4054–4062` defines tool arguments as
   `Option<JsonObject>` (map values are Value). The tree is already materialized
   by the time `server/mcp.rs:429` assembles arguments. `mcp.rs:262–264` then
   calls `from_value<T>`, reaching Value decoding again for MutationBatch/query
   fields. Changing only `arguments()` is too late.
3. **MCP output:** `mcp.rs:266–270` encodes a typed result and parses it back into
   Value. Legitimate literal document keys can change or fail on this outbound
   round trip too; final JSON-RPC envelope byte accounting does not repair that.
4. **Ordered durable apply/replay:** `engine/state.rs:115` decodes canonical
   Command bytes with stock serde, including mutation/stage/schema Value fields.
   Fixing inbound RPC construction without this boundary leaves a second parse
   of exact committed bytes. `raft/command.rs:365` also decodes Command while
   checking retirement seed commitments (Value-bearing variants elsewhere share
   this canonical type).
5. **Canonical snapshots:** `engine/snapshot_codec.rs:563` decodes a bounded
   32 MiB Record, then compares emitted canonical bytes to the original.
   Document, Collection, Archived, StageChunk, Change/ChangeItem and schema
   Activation records can transitively carry Values. A marker that changes the
   value fails canonical comparison before publication; it is not silently
   accepted as another snapshot. Decode/allocation precedes that rejection.
   `snapshot_index.rs:295` redecodes authenticated indexed record bytes with the
   same generic parser and must remain consistent with the canonical visitor.
6. **History archives/backup dependencies:** `history_reads.rs:176` and
   `backup_verify.rs:609` decode HistoryArchiveChunk with Document bodies. The
   history read checks each returned document's digest, encoded length and index
   values at `history_reads.rs:217–226`, so altered bodies fail that integrity
   check. The same literal parser still belongs on this bounded chunk boundary.

## Smallest coherent shared boundary

Share a **literal byte-to-Value parser and resource meter**, not a new
`serde_json::from_value<T>` convenience wrapper. The SDK's current private
`snapshot_decode/tokens.rs` already separates allocation-free syntax admission
from literal building: object/array nodes are constructed directly; only isolated
JSON string tokens decode to String and numeric lexemes parse to Number. Neither
operation invokes Value::Deserialize or interprets a string as new JSON.

`kasumi-types` can host that primitive without a dependency cycle: engine,
query, server and SDK already depend on it. Alternatively a small leaf JSON
crate can depend only on serde/serde_json and expose an injected synchronous
budget/deadline check; types and SDK depend on that leaf. It must not depend on
SDK Call/ClientError or engine admission implementations. Share checked byte,
decoded-work, node, depth, string and numeric-token budgets. Keep one finite
caller deadline through admission and building, reserve before allocation, and
apply it to each bounded request or snapshot/history record, never a tenant-sized
aggregate parse.

At typed boundaries, borrow raw lexical spans for open JSON fields and construct
the final canonical DTO explicitly (or provide equivalent literal-aware typed
decoding). A literal Value followed by **stock `from_value<T>` is insufficient**:
the target's nested Value fields run KeyClassifier again. Similarly, a generic
map visitor cannot distinguish an actual arbitrary-precision number's synthetic
serde map from a user object with the same marker after serde's internally tagged
enum buffering has discarded lexical distinctions. Mutation and Predicate are
internally tagged; simply annotating a leaf with an unexamined generic visitor is
not a complete solution. Preserve raw syntax until the discriminator and open
fields are decoded, then use the shared literal builder directly.

MCP needs a boundary **before rmcp materializes arguments**, either a reviewed SDK
parser adapter or bounded Kasumi transport integration retaining the literal raw
arguments. Re-encoding/reparsing the original request through current rmcp does
not solve it. Continue enforcing actual protocol metadata, auth and response
fences; this audit proposes no replacement protocol or compatibility behavior.

Required future counterexamples: both markers and escaped keys, marker-first and
ordinary-first ordering, nested arrays/objects, invalid JSON inside literal marker
strings, exact arbitrary-precision numeric tokens, direct/native/staged/MCP
mutation and query paths, Command round trips, canonical snapshot/index/backup
round trips, and rejection before allocation of over-budget ordinary JSON. These
are unrun follow-up checks, not claims made by this read-only audit.
