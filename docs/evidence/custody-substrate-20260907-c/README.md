# Custody storage substrate checkpoint

The complete locked, offline workspace run passed **275 tests**, including six
private-proof compile-fail checks; two opt-in external service tests were ignored.
Strict all-target/all-feature Clippy, formatting and whitespace checks passed.
`verification.json` binds the commands and results to unchanged native source
inputs. Product repositories are outside this inventory. This run used macOS
aarch64 and Rust 1.97.1; it does not repeat the earlier Linux/performance release
qualification for these changed sources.

This checkpoint implements independently keyed application/control stores,
atomic Raft body/header/closed-seed append, exact applied retirement linkage,
snapshot coverage and metadata-only local committed recovery. It includes actual
engine backup/retirement/reopen and native mTLS proof regressions, storage fault
injection, stale/substituted metadata rejection and key-seal denial tests.

The earlier source-bound failures remain in sibling `custody-substrate-20260907-a`
and `custody-substrate-20260907-b`. They exposed fixtures bypassing installation,
installing after sealing, reusing wrapping key identities and submitting the old
Raft command representation. The fixtures now exercise the explicit first-release
contracts; storage and authorization checks were not relaxed.

The remaining custody-only runtime, snapshot-carried retirement metadata,
current-policy proof release, independent incarnation serving leases and
unavailable-source activation are **not** established by this checkpoint. See
[the contract](../../custody-control.md).
