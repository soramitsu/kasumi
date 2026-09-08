# Authority membership and capacity maintenance

`kasumictl --config /etc/kasumi/authority-client.json authority-maintenance request.json`
sends an `AuthorityMaintenanceRequest` through an installed member endpoint set.
The native mTLS listener authenticates the exact authority resource and a current
administrator. Each attempt rereads the private token file, retains the same
operation identity and uses one overall client deadline.

Read the current configuration first:

```json
{"kind":"configuration"}
```

The reply contains current policy and operational revisions, three voter IDs,
live members, byte capacity and any unfinished operation identity. Copy both
revisions into a new command with a fresh operation UUID and an initial admission
deadline in Unix milliseconds:

```json
{
  "kind":"start",
  "command":{
    "operation_id":"60bdbcae-6b30-4c95-9274-f7707b2175de",
    "expected_policy_epoch":1,
    "expected_operational_revision":0,
    "not_after_ms":1790000000000,
    "action":{
      "kind":"enroll_learner",
      "node_id":4,
      "member":{
        "endpoint":"https://authority-4.example:9446",
        "failure_domain":"zone-d",
        "certificate_pins":["REPLACE_WITH_LOWERCASE_SHA256"]
      }
    }
  }
}
```

Before enrollment, install the candidate's endpoint, failure domain and leaf pins
in every current member's replication peer pool. Start the new learner using the
same immutable `installation` and original `bootstrap`; its own member ID and
durable directory must be new. The learner receives state through the original
voters. It must never bootstrap an independent authority group. The coordinator
checks each current member and the learner over their pinned mTLS peer endpoints
before recording admission. Each acknowledgement durably reserves the required
resource floor locally, so a restart cannot silently lower a promise already seen
by the coordinator. A request cannot substitute a URL or readiness proof.

Enrollment records `prepared` and then `dispatched` before invoking Raft. The
coordinator waits for catch-up before recording completion. To replace a voter,
start a new operation with `action:{"kind":"replace_voters","voters":[1,2,4]}`.
Every replacement must already be enrolled. Membership remains three voters in
three distinct failure domains. If the leader itself is replaced, query or resume
the same operation through the new leader; an interrupted response is not failure
of the committed membership transition.

After replacement completes, revoke the retired member with
`action:{"kind":"revoke_member","node_id":3}`. The coordinator removes any
remaining learner membership, permanently records the member identity and closes
its peer admission on current members. It reports `draining` until the complete
issuer interval has elapsed. A process restart or leadership change restarts this
private monotonic drain. The revoked ID remains forbidden after restart and
snapshot transfer, even if its files or endpoint are presented again.

Resolve any lost response using the original identity:

```json
{"kind":"status","operation_id":"60bdbcae-6b30-4c95-9274-f7707b2175de"}
```

Use `kind:"resume"` to advance recorded work with a current administrator.
Resumption preserves the original command and its original initial admission
deadline. Use `kind:"stop"` only before dispatch. A dispatched operation must
resolve forward; stop cannot claim that an uncertain external effect did not
happen. Terminal completion, rejection and stop records are permanent. Reusing
an identity with changed inputs returns a conflict.

Authority capacities are replicated operational state. `installation` contains
only the immutable manifest and partition; `bootstrap` contains the original
three-voter membership, administrators and initial capacity. An existing store
never reapplies bootstrap settings to live operational state. Each physical
store also binds its local member ID and rejects an attempt to reopen it under
another node ID.

To grow capacity, first increase `resource_budget_bytes` in every active member's
installed node configuration and restart those members safely. Submit a fresh
operation with `action:{"kind":"set_capacity","capacity":{"max_tenants":1000,
"max_state_bytes":67108864,"maintenance_reserve_bytes":1048576}}`. The coordinator
requires readiness from every live member before committing the change. Retained
receipts, history and revocations have no lifetime count ceiling. Ordinary work
cannot consume the maintenance reserve; expanding the byte budget remains
possible after ordinary admission exhausts its capacity. Shrinking the operational quota below durable
history and completion reserves is rejected. Installed resource budgets cannot
fall below a previously acknowledged maintenance floor, including an operation
whose acknowledgement or outcome was lost.

Authority maintenance currently covers membership and capacity. Staged authority
signer generations, operational replication trust rotation and the data-node
maintenance coordinator remain separate release work. The focused tests are not
substitutes for the final process, platform, endurance or source-bound release gates.
