# Guarded staged resolution checkpoint

The source-bound native gate passed 291 tests with two opt-in external-service
tests ignored. Strict all-target/all-feature Clippy, workspace formatting,
formatting of the two newly included test modules, and diff checks passed. All
136 recorded Rust/protobuf/manifest/lock inputs remained unchanged across the run.
The base is `65c7ff40271d2bcc7c68f57a89bcd256bb162052`; exact final file hashes and
commands are in [verification.json](verification.json).

The 16 added tests cover encrypted missing-stop restart, delayed same-ID begin,
manifest/TTL conflicts, permanent identity and snapshot quotas, original failed
and successful outcomes, 604 fresh authority assertions, final-release authority
changes, queued deadline/credential expiry, caller cancellation, post-acceptance
acknowledgement loss and real authenticated TLS SDK calls. The complete existing
Raft, backup, history, retirement and storage suites also passed.

The acknowledgement-loss test exercises the private post-Raft release boundary
using an actual accepted stop, closes storage before releasing those result bytes,
and reopens encrypted state to recover the exact tombstone. It is a service-boundary
test, not a claim that a network client received bytes before or after a crash.

The ignored tests require the separate MinIO and OpenBao fixtures. This macOS
checkpoint does not claim the Linux release gate, application authority-graph
completeness, custody-only native startup, snapshot-carried custody metadata,
independent serving leases, unavailable-source DR activation, or 10,000-tenant
capacity validation.
