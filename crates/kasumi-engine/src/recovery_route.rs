//! Route publication and its permanent recovery outcome share one Control Raft
//! apply. A replay returns that outcome before inspecting or changing a later
//! topology. Ordinary topology writes cannot produce this closed journal fact.
use super::*;
use crate::control::{ControlTopology, DeploymentMode, TenantRoute};

pub(crate) const COLLECTION: &str = "topology";
pub(crate) const DOCUMENT: &str = "current";
/// Parsing, canonical rebuilding, mutation validation, and the change event are
/// bounded by this one document. No tenant-sized workspace is serialized.
pub(crate) fn workspace(state: &TenantState) -> Result<u64> {
    let bytes = state
        .collections
        .get(COLLECTION)
        .and_then(|c| c.documents.get(DOCUMENT))
        .map(|document| encoded_len(&document.body))
        .transpose()?
        .unwrap_or(0);
    u64::try_from(bytes)
        .ok()
        .and_then(|bytes| bytes.checked_mul(16))
        .and_then(|bytes| bytes.checked_add(256 << 10))
        .ok_or_else(|| {
            error(
                ErrorCode::ResourceExhausted,
                "topology publication workspace overflow",
            )
        })
}
fn current(state: &TenantState) -> Result<(&Document, ControlTopology)> {
    let document = state
        .collections
        .get(COLLECTION)
        .and_then(|c| c.documents.get(DOCUMENT))
        .ok_or_else(|| error(ErrorCode::NotFound, "installed Control topology absent"))?;
    let topology: ControlTopology = serde_json::from_value(document.body.clone())
        .map_err(|_| error(ErrorCode::Corruption, "invalid installed Control topology"))?;
    topology.validate()?;
    Ok((document, topology))
}
pub(crate) fn next_input(
    state: &TenantState,
    operation: &RecoveryRecord,
) -> Result<RecoveryRouteChange> {
    activation::winner(state, operation)?;
    if !operation.voters.values().all(|v| v.confirmation.is_some()) {
        return Err(conflict(
            "route publication requires every local activation confirmation",
        ));
    }
    let (document, topology) = current(state)?;
    let source = topology
        .tenants
        .get(&operation.request.tenant)
        .ok_or_else(|| conflict("source route absent"))?;
    if source.incarnation != operation.request.source_incarnation.to_string()
        || source.mode != DeploymentMode::Replicated
    {
        return Err(conflict(
            "source route differs from frozen recovery incarnation",
        ));
    }
    for (node_id, identity) in &operation.request.target_nodes {
        let installed = topology
            .nodes
            .get(node_id)
            .ok_or_else(|| conflict("target voter is not approved in Control topology"))?;
        let placement = &operation.request.materialization.voters[node_id];
        let endpoint = url::Url::parse(&placement.endpoint)
            .map_err(|_| conflict("target replication endpoint is invalid"))?;
        if installed.endpoint != endpoint.origin().ascii_serialization()
            || installed.failure_domain != placement.failure_domain
            || !installed
                .certificate_pins
                .contains(&identity.certificate_sha256)
        {
            return Err(conflict(
                "target route differs from approved endpoint, trust or failure domain",
            ));
        }
    }
    Ok(RecoveryRouteChange {
        expected_topology_version: document.version,
        expected_source_incarnation: operation.request.source_incarnation,
        target_incarnation: operation.request.target_incarnation,
        target_voters: operation.voters.keys().copied().collect(),
    })
}
pub(crate) fn validate_input(
    operation: &RecoveryRecord,
    input: &RecoveryRouteChange,
) -> Result<()> {
    if input.expected_topology_version == 0
        || input.expected_source_incarnation != operation.request.source_incarnation
        || input.target_incarnation != operation.request.target_incarnation
        || !input.target_voters.iter().eq(operation.voters.keys())
    {
        return Err(conflict(
            "route publication input differs from frozen source and target",
        ));
    }
    Ok(())
}
pub(crate) fn apply(
    state: &mut TenantState,
    operation: &RecoveryRecord,
    input: &RecoveryRouteChange,
    now: u64,
) -> Result<RecoveryDispatchOutcome> {
    validate_input(operation, input)?;
    let observed = state
        .collections
        .get(COLLECTION)
        .and_then(|c| c.documents.get(DOCUMENT))
        .map(|d| d.version);
    if observed != Some(input.expected_topology_version) {
        return Ok(RecoveryDispatchOutcome::RouteRejected {
            observed_topology_version: observed,
        });
    }
    if *input != next_input(state, operation)? {
        return Err(conflict("route publication compare-and-set differs"));
    }
    let (_, mut topology) = current(state)?;
    topology.tenants.insert(
        operation.request.tenant.clone(),
        TenantRoute {
            incarnation: input.target_incarnation.to_string(),
            mode: DeploymentMode::Replicated,
            voters: input.target_voters.clone(),
        },
    );
    topology.validate()?;
    let revision = state.revision;
    apply_batch(
        state,
        &MutationBatch {
            idempotency_key: format!("recovery-route-{}", operation.request.operation_id),
            read_set: vec![],
            operations: vec![Mutation::Put {
                collection: COLLECTION.into(),
                id: DOCUMENT.into(),
                body: serde_json::to_value(topology)
                    .map_err(|_| conflict("route encoding failed"))?,
                expected: Precondition::Version(input.expected_topology_version),
            }],
        },
        revision,
        now,
        &QueryIndexes::default(),
    )?;
    Ok(RecoveryDispatchOutcome::RoutePublished { revision })
}
pub(crate) fn validate_outcome(
    prepared: &RecoveryPhaseRecord,
    input: &RecoveryRouteChange,
    outcome: &RecoveryDispatchOutcome,
) -> Result<()> {
    match outcome {
        RecoveryDispatchOutcome::RouteSuperseded { replacement_phase }
            if !replacement_phase.is_nil()
                && *replacement_phase != prepared.phase_id
                && prepared
                    .resolved_revision
                    .is_some_and(|revision| revision > prepared.prepared_revision) =>
        {
            Ok(())
        }
        RecoveryDispatchOutcome::RoutePublished { revision }
            if Some(*revision) == prepared.resolved_revision
                && *revision > prepared.prepared_revision =>
        {
            Ok(())
        }
        RecoveryDispatchOutcome::RouteRejected {
            observed_topology_version,
        } if *observed_topology_version != Some(input.expected_topology_version)
            && observed_topology_version.is_none_or(|version| {
                prepared
                    .resolved_revision
                    .is_some_and(|resolved| version < resolved)
            }) =>
        {
            Ok(())
        }
        _ => Err(conflict(
            "route publication lacks exact ordered permanent outcome",
        )),
    }
}
