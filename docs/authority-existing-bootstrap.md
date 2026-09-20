# Authority initialization and strict restart

First state publication uses `TenantStorageSet::initialize_state`. It holds both
application and custody mutation owners and checks the complete physical tenant
prefixes inside the same durable transaction that publishes initial state. The
application prefix must be empty. Custody must contain exactly its authenticated,
canonical storage-domain binding and no other record. Unknown namespaces,
malformed extra keys, missing binding and substituted binding fail closed.

The check visits at most the first two physical entries of a domain. It does not
materialize a namespace or allocate a tenant-sized index. The binding is checked
against the already installed catalog descriptor. Concurrent initializers cannot
both publish: the second observes existing state under the same mutation owners.
The synchronous caller must retain its installation authorization, storage owner
and blocking-work admission through commit and acknowledgement. This primitive
is not an application authorization grant or a physical disk budget.

Only nonempty Put-only operation slices are accepted, so a successful
publication cannot leave either domain pristine through deletes of absent keys.

The four new store regressions exercise unknown records in both domains,
concurrent initial publication with one matching winner in both domains, and
missing/substituted custody bindings, and rejection of delete-only initial state. They are source-only and unexecuted.


## Authority service contract

`IndependentAuthority::initialize_storage` accepts the immutable installation,
original typed bootstrap and exact physical verifier identity. It validates the
independent-authority domain and initial signing certificate, then publishes one
joint transaction containing the application genesis META, resource floor, the
same tagged installation descriptor in both domains, the same local verifier
binding in both domains, and the canonical Raft node/group identity in custody.
`kasumi_raft::initial_storage_identity` prepares only those two bounded identity
rows; it does not create membership or grant any serving authority.

`IndependentAuthority::open_existing_replicated` takes the expected immutable
installation plus live node settings. `AuthorityNodeSettings` contains only the
resource budget and approved operational transport pool. It cannot supply genesis.
The strict opener reads the bounded original descriptor once, requires identical
authenticated application/custody bytes, validates its replicated tag and initial
certificate, and checks the exact local physical verifier. META, resource floor,
and the matching existing Raft node/group identity are mandatory before opening
Raft. Missing or unsupported state fails without recreating any head. There is
no old descriptor decoder or open-or-create compatibility wrapper.

The returned service retains that original bootstrap and derives its enrollment
fingerprint/voters from it. Current membership, policy, signer head and capacity
remain durable operational state. Normal transport settings are checked against
that current membership, including normalized endpoint and certificate uniqueness,
independently of the original placement. The existing consensus `initialize`
operation may act only if Raft is uninitialized and the retained authority state
is exactly its original genesis; otherwise it preserves operational membership.

Four new encrypted authority fixture sources cover each missing required head,
corrupt and unsupported descriptors/META, immutable installation or physical
verifier substitution, and complete shutdown/drain/reopen with changed operational
resources and unused learner routing. The existing real voter-replacement/restart
fixture additionally checks that every service retains the original bootstrap.
Authority and native TLS fixture setup now explicitly initializes fresh state;
subsequent opens use the strict API. These sources have not been compiled or run.
The production authority runtime/provisioning caller adaptation is a coordinated
separate change and must land before a workspace validation attempt.

## Remaining recovery boundary

This increment does not solve the separate authority logical-prefix replay issue:
physical permanent rows can be ahead of an older retained snapshot. Existing
snapshot/history validation remains fail-closed. Correct prefix reconstruction,
immutable future-row visibility, exact-position replay and the conservative
physical deny fences still need their own complete implementation and gates.
Nothing here claims completed authority recovery, rotation retirement, physical
disk admission, or first-release production acceptance.
