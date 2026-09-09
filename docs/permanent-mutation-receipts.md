# Permanent ordinary mutation receipts

This is a source checkpoint awaiting coordinated compilation and functional
validation. It is not a completed release or capacity acceptance result.

Ordinary mutation identities no longer expire. `Limits.max_receipts` and
`receipt_ttl_ms` are removed. `max_mutation_receipt_bytes` is a mandatory checked
`u64` canonical-row budget, defaulting to 128 MiB. An authorized limit change can
expand it, or reduce it no lower than the selected used bytes. No lifetime count
cap, TTL cleanup, resident outcome map, compatibility alias, or old decoder exists.

A principal and idempotency key select one immutable encrypted point row. The row
retains the original tenant/incarnation/principal, canonical batch digest,
result, collections, and exact original applied command/position. Authorization
uses the current verified context; these stored fields never grant authority.
An exact retry returns the retained result even after batch/receipt limits change.
Public mutation submission keeps the immutable 8 MiB request envelope; ordered
application enforces today’s batch limits only for a newly admitted identity.
Different input conflicts. A restore keeps every original scope and position;
sparse verified lineage establishes the original genesis floor and closing
revision. Historical outcomes never acquire a fabricated target incarnation.

The selected Generation owns a fixed prefix head (origin, count, canonical bytes,
last applied revision, and SHA-256 root) plus its immutable namespace owner.
Rows bind consecutive ordinals, parent roots, and strictly increasing original
applied revisions. Point reads use short storage transactions rather than a
lifetime map or a database-wide pinned read transaction. Two MiB is a bounded
individual receipt format envelope, derived from at most 256 bounded collection
names/document paths and an outcome with no document Values. It is not a
permanent history limit.

Before document changes, the dedicated mutation apply path admits the larger of
its complete possible success row and a maximum deterministic error row. The
closed error codes and 512-byte error message bound include worst-case six-byte
JSON escapes. The required audit uses the longer committed outcome; preflight
also covers aggregate byte/count/revision decimal widths and existing staged,
target, and Control completion reservations. After this admission, deterministic
schema, logical, index, feed, or snapshot-budget rejection preserves one failure
row and rolls back document changes. The generic revision-only quota fallback
cannot receive an admitted ordinary mutation. An unexpected failure of the
reserved terminal path is an outer replica failure, not a release that silently
forgets the identity. Before admission, authorization, envelope, permanent byte,
or audit-capacity denial can leave the identity absent. Failure to audit an exact
replay can reject its response, but cannot change its original point result.

Appending a row and its ordinal index uses one storage transaction. A durable row
written before its matching applied cursor remains invisible to the earlier
selected head. Replay may reuse it only if its complete original row and index
match; an uncertain write never selects a later physical prefix as applied.
Snapshot publication joins the receipt namespace replacement and checkpoint
binding with the existing application tables, snapshot, and applied cursor in
the same durable publication. Old live views retain their exact earlier prefix.

The canonical tenant stream is `KASUMIT6`. Rank 5 is now a typed receipt point row;
T4/T5 images, the old tuple record, resident `receipts` headers, and old limit
fields reject. Full backups copy these rows; both full and indexed restore
validate their root/count/bytes, uniqueness, and original provenance before
publication. Rank 5 does not enter the three-times-resident restoration estimate;
its per-record structural decode work still enters admission. Planned retirement
uses the new v4 closure, committing the verified receipt prefix root in both
resident and indexed paths.

Receipt lookups reserve their bounded physical I/O floor before dispatch, then
structurally meter the plaintext before DTO allocation. Owned blocking workers
retain the selected Generation/namespace, reservation, cancellation token, and
shutdown registration. An explicit worker owner releases its Generation before
its shutdown registration on every error or cancellation path. The finite deadline starts before the read barrier and
is checked after worker completion and audit/response release. Completed lookup
DTOs remain bounded independently of history length. This is an accounting model,
not a hard RSS guarantee. The selected Generation may retain existing document
roots while its bounded point worker runs; this change adds no lifetime receipt
RAM map. A returned plain DTO is not a revocable memory capability.

Required gates are recorded in `permanent-mutation-receipts-gates.json`. They
include encrypted future-row/reopen/prefix tests, an actual Database service retry
after former TTL boundaries and lowered batch limits, byte exhaustion/expansion,
audit exhaustion, original
scope across two restore geneses, and existing joint snapshot publication fault
and cancellation tests. A separately ignored source fixture streams 100,000
canonical encrypted historical rows, restores them, then applies an actual new
mutation and checks old replay/conflict. It is manufactured historical fixture
state, not proof of 100,000 actual HA commits, production maintenance capacity,
throughput, or hard RSS. No large-count or Rust result is claimed before execution.

Persistent physical disk accounting, old namespace reclamation, and final 3 GiB
resident/index workspace acceptance remain separate release requirements.
Canonical row bytes exclude index/envelope/redb overhead; the shared encrypted
scratch governor accounts its own physical work, not persistent database space.

Source validation for this checkpoint: Rust 1.97.1 rustfmt parsed and formatted
the changed Rust files, and `git diff --check` passed. Compilation, Clippy, all
functional tests, and the large-count fixture remain unrun.
