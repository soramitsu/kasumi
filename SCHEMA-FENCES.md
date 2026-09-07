# First-release ordered schema activation fences

This isolated branch begins at verified d9ef813fe13723e9020d53cae1a91265c6b88ae3. Original /Users/mtakemiya/dev/kasumi remains at clean revision 5174ae1595414829e800605919be72f2f869bb5b; the target-runner worktree remains separately owned.

Required immutable SchemaChangeSet.read_set participates in the exact permanent effect digest. It uses the same bounded ReadAssertion validation and dependency Read authorization as MutationBatch. Fresh ordered activation evaluates it against pre-transition state and leader-stamped time together with schema/data epochs and definition writes. Failed deterministic assertions retain a permanent failed outcome; they do not partially activate definitions.

Original pre-transition Snapshot assertions must NOT be re-evaluated after successful schema/policy increments or on permanent replay. Retained result access still requires current native resource/Admin and original dependency Read authorization. Preserve the invocation's native credential lifetime and its original Before deadline through encoded acknowledgement release.

Status/recovery uses a separate required ReadSchemaActivation { reference, read_set }. Its current admission assertions are not part of the original effect digest, are read against the current coherent generation, and remain fenced through audited response encoding. Stale lookup cannot alter the stored original result. No old bare-reference request decoder or serde default is retained.

Tests required: changed/missing quiescence document, schema/policy/incarnation changes, query collection phantom, dependency Read denial, native current revocation, expired Before at ordered execution and after commit before encoded release, no-op audited reads preserving data dependency, immutable identity conflicts, original response recovery after schema increment, fresh lookup guards after later activations, queued/encoded lookup changes, closed JSON request shape, encrypted restart and authenticated native gRPC/SDK.

The application installer needs an independent Kasumi journal containing exact chunked request bytes and permanent native reference before dispatch, then a complete final inventory read plus an ordered readiness transaction with current lifecycle/runtime authority. Native schema support alone is not a completed installer or tenant-readiness proof.

Diagnostic integration tests passed 12 cases, service tests passed 3 cases, and the authenticated native API handler passed its schema activation case. The first service run exposed a post-commit deadline error reported as Conflict; that path now reports UnknownOutcome and the repeated service run passed. A subsequent assertion also checks the independent status deadline. These diagnostics were not source-frozen release evidence. The complete workspace and strict source-bound gate remains to be run against this commit.
