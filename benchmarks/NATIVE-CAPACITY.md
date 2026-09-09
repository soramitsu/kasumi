# Native corpus load and verification

`kasumi-bench-capacity` loads a deterministic corpus into an existing dedicated
collection through the installed TLS 1.3/mTLS native service. It has no server,
engine, storage or fixture dependencies. Build the separate production server
with the release workflow, and build the client tools with:

```sh
CARGO_TARGET_DIR=target/production-bench cargo build --locked --release \
  -p kasumi-bench --no-default-features --features network --bins
```

Create [the capacity collection](capacity-collection.json) through the native
administrative interface. Configure tenant RAM, document, snapshot and audit
budgets and actual node resources before loading. The driver neither changes
quotas nor interprets configured capacity as measured capacity.

Copy [the example configuration](capacity.example.json), select a new corpus UUID,
and replace its endpoint, certificate, key, CA, pin and token-file paths with the
values in the installed client profile. Relative input paths resolve beneath
the configuration directory. The TLS key and bearer file must be owner-only;
bearer files are read afresh for every request. Run the installed renewal watcher
separately. The same configured file path may receive atomic token replacements.
The first JWT's issuer, audience, principal, tenant, database incarnation,
credential family, token use and scope are recorded in the private journal and
must remain identical on every request. Renewal may change expiry, issuance
identity and signer. The client checks claim continuity; the native server
authenticates each JWT. Switching a credential binding requires a separate run.

The example describes 98,304 documents of exactly 32,768 canonical JSON bytes,
totalling 3,221,225,472 bytes (3 GiB). Payload characters are drawn uniformly from
92 printable ASCII characters using a seeded SHA256 counter and rejection
sampling. This avoids repeated padding; its real compression ratio must still
be measured for any incompressibility acceptance claim. The configuration alone
is not evidence that a 3 GiB tenant was loaded.

```sh
target/production-bench/release/kasumi-bench-capacity capacity.json load \
  /absolute/new-load-evidence --allow-writes
target/production-bench/release/kasumi-bench-capacity capacity.json verify \
  /absolute/new-restart-verification
```

Every write requires absent document IDs. A load never replaces an existing
document and stops at the first failure without automatically retrying. It then
verifies every document with point reads and compares exact canonical bodies and
an ordered, length-framed SHA256 digest. The separate `verify` command can check
the same corpus after restart, snapshot replacement or restore; the connection
may change for a new authorized destination, while the corpus definition stays
identical. These individual point reads do not claim a coherent snapshot under
concurrent mutation. Use a dedicated corpus without concurrent body changes.

Each new owner-only evidence directory retains a synchronously flushed event
journal, the original configuration digest, executable hash, exact corpus plan,
progress, receipts and failures. The exact most recent bounded batch is durably
published before dispatch. After an uncertain write or interruption, inspect its
original receipt without issuing another mutation:

```sh
target/production-bench/release/kasumi-bench-capacity capacity.json resolve \
  /absolute/new-receipt-observation /absolute/original-load-evidence
```

Inspection requires the byte-identical original connection/corpus configuration
and exact generated batch, plus the original recorded credential binding;
renewal of the token file is still supported. A retained outcome must include
the server's original canonical batch digest, which the inspector compares with
the complete original key, read set, operations and preconditions. A different
body under the same key fails resolution. The returned original principal,
tenant and incarnation must also match the journaled credential binding. An absent receipt remains unknown
and never authorizes blind replay. The command does not automatically resume
a partial load. A completed receipt observation
is distinct from a complete verified corpus.

Work stays bounded by one batch (at most 256 documents and 4 MiB including
framing) or one document (at most 1 MiB). Aggregate counts and byte totals use
checked 64-bit arithmetic. Per-batch durable client journaling affects elapsed
load time, so these logs are integrity evidence rather than latency benchmarks.
Snapshots, backup, compaction, lease pressure, node memory/disk measurements,
crash injection and HA replacement require the separate acceptance runbooks.
