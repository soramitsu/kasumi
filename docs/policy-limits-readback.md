# Current policy and limits readback

The private native administrative endpoint exposes `ReadPolicyLimits`. The
request is exact JSON:

```json
{"tenant":"fi-core-leumi-is2","expected_incarnation":"00000000-0000-4000-8000-000000000001"}
```

Run `kasumictl --config <pinned-admin-client.json> read-policy-limits
<request.json>` with an Admin credential for that database. The response
contains `tenant`, `incarnation`, `revision`, `policy_epoch`, `schema_epoch`,
the complete current `policy`, and the complete current `limits`. The native
engine takes a quorum read barrier, checks tenant and incarnation against the
authenticated database route, enforces Admin before and after the barrier,
durably audits the read, and checks the response authority again during
serialization. The typed SDK method `KasumiAdminClient::read_policy_limits`
uses the same private endpoint and bounded literal response admission.

Pair this result with `kasumictl read-schema` for the same tenant and
incarnation to verify collection definitions and modes. A host admission
checker should compare the returned values against its independently pinned
release policy and reject missing grants, insufficient limits, wrong
incarnation, or a readback whose policy/schema epochs changed during the
check. A captured CLI result is evidence of that read; it is not a standing
authorization for future requests.

The current native validator caps `max_document_bytes` at 1 MiB,
`max_batch_bytes` at 8 MiB, and `max_result_bytes` at 8 MiB. A requested limit
above those bounds is rejected; readback cannot make an unsupported value
admissible.
