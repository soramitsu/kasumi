# Restore admission for permanent point history

This first-release change replaces the tenant logical codec directly with
`KASUMIT7`. There is no T4/T5 reader or conversion path. Each nonterminal frame is
`u64 payload_bytes | u8 semantic_rank | canonical_json`; the zero-length footer
still verifies exact 64-bit count, framed bytes, digest and EOF. The outer bundle
also checks its logical/archive counts and digest. Encrypted envelopes and
installed source authorization supply authenticity; the digest alone does not.

A fixed-buffer inspection pass checks kind-specific payload lengths, category
order, nesting and the complete framing before any JSON DTO allocation. It
retains a fixed 23-entry summary of record counts, framed bytes, maximum payload
and maximum structurally accounted decode work. The semantic pass checks the
actual enum rank before accumulating or forwarding each record, then recomputes
that summary. A permanent tag on resident JSON cannot spend the permanent class's
budget or reach the resident-state consumer. Permanent row roots and their exact
framed-byte counters are still independently verified by the receipt/staged/target table
builders before publication.

Public restore preparation reserves a 64 MiB maintenance floor, then adds three
times the resident framed bytes plus the maximum structural record work. Ranks
5, 21 and 22 do not enter the resident term. Historical backup verification reserves
its 128 MiB index/cache floor plus the maximum record work before building its
point index. Relocation repeats this admission after the old index has dropped;
genesis materialization transfers the same reservation to the resident formula
only after the verification indexes have drained. Original deadlines,
cancellation, work registration and exact store ownership stay with the actual
blocking worker and returned publication state. Public preparation returns only
a verified image and fixed identity, and never publishes a live generation.

External history chunks have an independent structural peak: their document
bodies are not records in the logical snapshot. Before decoding each bounded
8 MiB plaintext chunk, the verifier scans it with the same fixed-space JSON
meter and expands the existing reservation to the retained logical index and
point-read workspace **plus** the external chunk work. The immutable captured
generation path adds the same external work to its existing 64 MiB verification
floor. The expanded charge covers the chunk DTO, validation temporaries and
concurrent point reads. Successful verification drops the body and plaintext
before returning to the base charge. Decode or validation failure and panic
keep the expanded reservation with the worker/result until drain; cancelling
the waiter never releases the worker's reservation or shutdown registration.

The structural model counts all JSON containers, scalars, strings and object
keys, including duplicate or ignored fields. It scans arbitrary-precision
numeric lexemes even when a number is only `0`. It counts scalar wire bytes;
decoded escape sequences cannot require more bytes than their wire spelling.
For each site it charges the sum of the compiled sizes of `(String, Value)`,
`Value`, two pointers and a Vec header. Four transient representations and
twofold container capacity are reserved: Serde Content buffering, final DTO/Value
storage, row-validation cloning and canonical/table serialization work. Scalar
bytes receive the same eight-copy allowance plus the original record bytes.
The model uses checked arithmetic and a fixed 128-byte container stack. It is
an explicit work-accounting model, not a custom allocator or hard RSS promise.
Malformed JSON is still rejected by canonical typed decoding; structural
preflight alone never authorizes a snapshot.

The existing three-times-resident estimate and query-index rebuild memory still
need measured capacity validation. This change does not make ordinary documents or all lifecycle history disk resident.
The separate [permanent receipt contract](permanent-mutation-receipts.md) moves ordinary receipt outcomes into encrypted point rows. Fixed cache/DTO assumptions,
allocator overhead, production maintenance floors and encrypted scratch usage
must be measured together during the final 3 GiB gate. It does not certify a
million permanent records, namespace reclamation or persistent disk admission.

The focused source regressions include a real encrypted 512-terminal-row
snapshot under an 80 MiB fixture governor. That fixture installs no production
maintenance lanes. It proves that the former whole-stream formula cannot fit,
that the new admitted preparation leaves the target unchanged, and that an
accounted-work-minus-one request is denied before scratch staging and drains its
reservation. Separate count arithmetic crosses 2 GiB without allocating that
payload; it is not a large-capacity measurement. Typed-tag substitution, unknown
kinds, bounds before payload reads, duplicate/out-of-order frames, footer
substitution, dense numbers, escaped keys and cross-frame lexer state are also
covered by named source regressions. No Rust compilation or functional result is
claimed until the separately scheduled source-frozen gates complete.

External history source regressions use a bounded dense numeric document to
check exact peak admission and rejection at one byte less, before typed
verification. They also cover decode failure, validation panic and deterministic
waiter cancellation while the body and then only the base workspace remain
live. These tests are work-accounting and ownership checks, not a measured
8 MiB archive or 3 GiB tenant capacity result.
