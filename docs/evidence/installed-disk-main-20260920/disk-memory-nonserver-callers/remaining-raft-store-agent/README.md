# Raft disk-memory fixture callers — prepared, not applied

This layer prepares all current `kasumi-raft` scratch and physical-disk fixture constructor call sites for mandatory store metadata admission revision 2. It is target-only under the main/master checkout. No actual source was edited and no Cargo build/test ran.

`combined-raft-callers.patch` applies directly to current actual source. Alternatively, apply the preserved six-file `pure-codec-store-agent/callers.patch` then this directory's `followup.patch`. Never apply the combined patch and the first layer together. The manifest records actual, intermediate, and proposed SHA256 values for every file, plus both patch hashes. The first six-file artifact remains unchanged as requested.

Each independent pure Raft fixture explicitly acquires one bounded metadata governor and one scratch owner at a caller-owned private directory. Every crash/reopen iteration reuses that exact scratch Arc and resource governor. Private control/fault-store/envelope/common-store helpers now require the actual scratch owner. Physical NodeStore constructors derive the mandatory memory token from that same owner; no second governor or lookup fallback is introduced.

Cluster fixtures retain their scratch directory and owner across replica reopen. Read-barrier fixtures retain the directory in their fixture object. The OpenRaft conformance builder returns a scope guard containing both persistent and scratch TempDir custodians, preserving directory names until the builder's store lifetime ends. Other tests retain their directory in the enclosing scope. The installed process-static registry owns no TempDir cleanup.

No NodeAdmission/MemoryCore appears in these changed Raft fixtures. The remaining engine/server/authority/client/bench migration must use the exact actual MemoryCore where those components are present; this pure-codec TestDiskMemory setup must not be copied across that boundary.

All existing test attributes, failure-injection ranges, assertions, payload byte caps, and record counts remain. The 4200-command/8400-audit capacity test still crosses the former ceilings and rejects the same 2 MiB transfer budget. The large-record and SIGKILL recovery workloads are unchanged. TestDiskMemory's 256 MiB/4096 resident lease cap pays disk metadata only; it is not a substitute for production payload/task workspace admission.

Preparation checks: target-only rustfmt, exact baseline/intermediate comparison, combined patch applicability, and an arity audit over every current Raft source file. These checks do not establish type correctness, runtime behavior, RSS bounds, or platform layout qualification. Coordinated compilation/tests remain required after the complete caller/adapter stack is applied.
