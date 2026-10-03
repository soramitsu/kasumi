//! One private owner for newly constructed topology JSON and its exact grant.
//! Generic command input and encoded Raft bytes keep their existing accounting;
//! this module neither adopts a caller DTO nor claims to close those corridors.
use crate::admission::{NodeAdmission, Reservation};
use kasumi_query::QueryCancellation;
use kasumi_types::{control_topology::ControlTopology, *};
use serde_json::Value;
use std::{mem::size_of, sync::Arc};

struct TopologyCredit {
    node: Arc<NodeAdmission>,
    _reservation: Reservation,
}
// Field order is part of the custody contract, including an unpolled future.
// Neither owner exposes owned payload/grant extraction or a public adopter.
pub(crate) struct OperationInput {
    pub(super) operation: Operation,
    topology: Option<TopologyCredit>,
}
pub(super) struct ProposalCommand {
    pub(super) command: Command,
    _topology: Option<TopologyCredit>,
}

impl OperationInput {
    pub(super) fn ordinary(operation: Operation) -> Self {
        Self {
            operation,
            topology: None,
        }
    }
    pub(super) fn check_admission(&self, destination: &NodeAdmission) -> Result<()> {
        if self
            .topology
            .as_ref()
            .is_some_and(|credit| !credit.node.shares_memory(destination))
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "topology input belongs to another node",
            ));
        }
        Ok(())
    }
    pub(super) fn into_command(self, context: RequestContext) -> ProposalCommand {
        let Self {
            operation,
            topology,
        } = self;
        ProposalCommand {
            command: Command {
                context,
                // Longest stamp for preflight; trusted ordered admission later
                // replaces it without expanding the accepted wire size.
                timestamp_ms: u64::MAX,
                operation,
            },
            _topology: topology,
        }
    }
    /// Synchronous concrete producer. The caller's source DTO dies before this
    /// returns. Its new JSON/key/batch backing is preclaimed and never separated
    /// from the returned owner, including submission denial and cancellation.
    pub(crate) fn topology(
        node: &Arc<NodeAdmission>,
        topology: ControlTopology,
        expected: Precondition,
        key: &str,
    ) -> Result<Self> {
        let quote = quote(&topology, key.len())?;
        let mut reservation = node.reserve(quote.peak, None)?;
        let cancellation = QueryCancellation::default();
        node.check_release(&cancellation)?;
        topology.validate()?;
        if matches!(expected, Precondition::Any) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "control updates require an explicit CAS precondition",
            ));
        }
        node.check_release(&cancellation)?;
        // to_value borrows the consumed argument internally and destroys it
        // before returning. It does not transfer source Strings into the Value.
        let body = serde_json::to_value(topology).map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                "control topology encoding failed",
            )
        })?;
        let operation = Operation::Mutate(MutationBatch {
            read_set: Vec::new(),
            idempotency_key: key.to_owned(),
            operations: vec![Mutation::Put {
                collection: "topology".into(),
                id: "current".into(),
                body,
                expected,
            }],
        });
        // operation was constructed after reservation: on a failed final check
        // it is destroyed before that grant, just as in the returned owner.
        node.check_release(&cancellation)?;
        drop(cancellation);
        reservation.retain(quote.retained);
        Ok(Self {
            operation,
            topology: Some(TopologyCredit {
                node: node.clone(),
                _reservation: reservation,
            }),
        })
    }
}

fn overflow() -> Error {
    Error::new(
        ErrorCode::ResourceExhausted,
        "topology input workspace overflow",
    )
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or_else(overflow)
}
fn mul(a: u64, b: u64) -> Result<u64> {
    a.checked_mul(b).ok_or_else(overflow)
}
fn count(n: usize) -> Result<u64> {
    u64::try_from(n).map_err(|_| overflow())
}
fn backing(n: usize) -> Result<u64> {
    if n == 0 {
        return Ok(0);
    }
    if n > isize::MAX as usize {
        return Err(overflow());
    }
    n.checked_next_power_of_two()
        .and_then(|n| n.checked_add(64))
        .and_then(|n| u64::try_from(n).ok())
        .ok_or_else(overflow)
}
fn tree<K, V>(entries: usize) -> Result<u64> {
    // Pinned Rust B=6: one whole internal node per input entry bounds sparse
    // nodes. Requalify this policy with Rust/Serde/serde_json/allocator updates.
    let n = size_of::<K>()
        .checked_add(size_of::<V>())
        .and_then(|n| n.checked_mul(11))
        .and_then(|n| n.checked_add(16 * size_of::<usize>()))
        .ok_or_else(overflow)?;
    mul(count(entries)?, backing(n)?)
}
fn vector<T>(entries: usize) -> Result<u64> {
    if entries == 0 {
        return Ok(0);
    }
    // Exact serializer hints normally allocate once. Also cover RawVec's
    // minimum/growth capacity and overlapping old/new buffers conservatively.
    let n = size_of::<T>()
        .checked_mul(entries.max(4))
        .and_then(|n| n.checked_mul(2))
        .ok_or_else(overflow)?;
    mul(backing(n)?, 2)
}
struct Quote {
    retained: u64,
    peak: u64,
}
fn quote(topology: &ControlTopology, key_bytes: usize) -> Result<Quote> {
    let mut total = add(tree::<String, Value>(2)?, mul(backing(16)?, 2)?)?;
    total = add(total, tree::<String, Value>(topology.nodes.len())?)?;
    let mut pins = 0usize;
    let mut url = 0;
    for node in topology.nodes.values() {
        total = add(total, backing(20)?)?; // u64 object key
        total = add(
            total,
            add(tree::<String, Value>(3)?, mul(backing(32)?, 3)?)?,
        )?;
        total = add(
            total,
            add(
                backing(node.endpoint.len())?,
                backing(node.failure_domain.len())?,
            )?,
        )?;
        total = add(total, vector::<Value>(node.certificate_pins.len())?)?;
        pins = pins
            .checked_add(node.certificate_pins.len())
            .ok_or_else(overflow)?;
        for pin in &node.certificate_pins {
            total = add(total, backing(pin.len())?)?;
        }
        url = url.max(ControlTopology::endpoint_workspace_bytes(&node.endpoint)?);
    }
    total = add(total, tree::<String, Value>(topology.tenants.len())?)?;
    let mut voters = 0;
    for (tenant, route) in &topology.tenants {
        total = add(
            total,
            add(backing(tenant.len())?, backing(route.incarnation.len())?)?,
        )?;
        // Three keys plus DeploymentMode's new JSON String.
        total = add(
            total,
            add(tree::<String, Value>(3)?, mul(backing(16)?, 4)?)?,
        )?;
        total = add(total, vector::<Value>(route.voters.len())?)?;
        // serde_json arbitrary_precision retains each numeric lexeme.
        total = add(total, mul(count(route.voters.len())?, backing(20)?)?)?;
        voters = voters.max(route.voters.len());
    }
    total = add(total, add(backing(key_bytes)?, mul(backing(8)?, 2)?)?)?;
    total = add(total, backing(size_of::<Mutation>())?)?;
    // Fixed owner/capture backing in addition to the existing generic proposal
    // budget; no source DTO, response or arbitrary diagnostic heap is adopted.
    total = add(
        total,
        mul(
            backing(size_of::<OperationInput>() + size_of::<ProposalCommand>())?,
            2,
        )?,
    )?;
    let validation = add(
        tree::<&String, ()>(pins)?,
        url.max(add(tree::<&String, ()>(voters)?, backing(36)?)?),
    )?;
    let cancellation = backing(
        QueryCancellation::shared_state_bytes()
            .checked_add(2 * size_of::<usize>())
            .ok_or_else(overflow)?,
    )?;
    let fixed = add(cancellation, add(backing(Error::MAX_MESSAGE_BYTES)?, 4096)?)?;
    Ok(Quote {
        retained: total,
        peak: add(add(total, validation)?, fixed)?,
    })
}

#[cfg(test)]
#[path = "proposal_input_tests.rs"]
mod tests;

#[cfg(test)]
pub(super) fn retained_for_test(topology: &ControlTopology, key: &str) -> u64 {
    quote(topology, key.len()).unwrap().retained
}
#[cfg(test)]
pub(super) fn payload_address_for_test(input: &ProposalCommand) -> usize {
    let Operation::Mutate(batch) = &input.command.operation else {
        panic!("topology input")
    };
    let Mutation::Put { body, .. } = &batch.operations[0] else {
        panic!("topology put")
    };
    body["nodes"]["1"]["endpoint"].as_str().unwrap().as_ptr() as usize
}
