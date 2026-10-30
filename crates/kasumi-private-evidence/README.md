# Private evidence custody

`kasumi-private-evidence` retains original evidence bytes in one authenticated
Kasumi tenant. It creates deterministic append-only chunk IDs, verifies every
write by exact receipt resolution and point read, and publishes the manifest
last. Reads return bytes only after checking the manifest, every chunk digest,
all indices, and the complete SHA-256. An interrupted upload leaves orphan
chunks that can be retried with the same identity and bytes; it never exposes a
partially committed object as complete.

Construct each `EvidenceIdentity` with `EvidenceIdentity::new` from the exact
stage operation SHA-256 and one component purpose. Its version-8 UUID is
domain-separated and deterministic over that subject and the original Kasumi
tenant/incarnation/principal, so a lost reply cannot lead to a fresh ID.

Quota refusals are durable mutation outcomes. A later call resolves each exact
attempt before dispatch. Only a retained `QuotaExceeded` receipt whose scope and
full request digest match permits the next deterministic attempt. The retry key
binds the complete original batch and its attempt number; document identities,
bytes and absent-only preconditions remain unchanged. Exact existing documents
are read back, while conflicting originals fail closed. An unavailable or missing
receipt after dispatch never authorizes a different attempt.

Each call creates at most one newly refused attempt per exact append batch. Recovery has a lifetime
budget of 64 successors per exact batch, bounded further by the caller's deadline;
exhaustion returns `RetryLimitReached` without deleting receipts or changing
evidence. Applications must report that condition rather than treating it as a
successful append or generating a new evidence identity. Restore capacity before
retrying an ongoing quota refusal. Non-quota refusals do not authorize successors.

The operator must install both definitions returned by
`collection_definitions(manifests, chunks)` in the intended tenant. They require
append-only operational retention and strict read audit. Grant only the
application's specific principal access to these collections. The signed
application runtime must pin the installed profile digest, tenant,
incarnation, principal, credential family, collection names and its explicit
`max_component_bytes`, plus both definition SHA-256 values from
`collection_definition_sha256`. `InstalledProfileBinding` consumes those values but
does not produce trust from the profile itself. Set tenant byte, document,
audit and mutation-receipt budgets for the expected number of retained
components before use. The separate deployment administrator must run native
`ReadSchema` and pass its authenticated result to
`verify_installed_collection_definitions`; data credentials cannot certify the
installed schema by naming it.

One component may be at most 256 MiB, split into 384 KiB original-byte chunks.
The application must name separate components and retain its own complete
proof-bundle manifest when more than one original wire is required. Kasumi
custody does not verify Iroha signatures, execution, finality, physical route,
or the completeness of a protocol-4 proof bundle. A caller must verify those
against independently authenticated anchors before acting on the bytes and
again after restoration.

The Iroha source currently permits a 256 MiB canonical executed block wire,
while its authenticated block-proof carrier refuses blocks over 32 MiB. A
single 192 KiB proof field cannot hold either general full-wire bound. This
crate can retain an original block wire as one component within its explicit
cap, but it does not relax Iroha's separate proof-carrier admission or claim
that every possible block has a first-release proof.
