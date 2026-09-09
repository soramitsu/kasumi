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
missing/substituted custody bindings, and rejection of delete-only initial state. They are source-only and unexecuted; no
production authority caller is wired in this foundation commit.
