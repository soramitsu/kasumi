//! Actual current Control routing reads. Serialized replies cannot construct
//! this original invocation or its final quorum/authorization fence.
use super::control_administration::ControlQuorumFence;
use super::*;
use crate::control::ControlPlane;

pub struct VerifiedControlTopology {
    database: Arc<Database>,
    fence: Arc<ControlQuorumFence>,
    observation: ControlTopologyObservation,
    _reservation: Reservation,
}
impl VerifiedControlTopology {
    pub fn observation(&self) -> &ControlTopologyObservation {
        &self.observation
    }
    pub async fn release(&self) -> Result<()> {
        self.fence.release().await?;
        let state = self.database.engine.generation()?;
        let document = state
            .state
            .collections
            .get("topology")
            .and_then(|collection| collection.documents.get("current"))
            .ok_or_else(|| changed("Control topology disappeared before release"))?;
        if document.version != self.observation.topology.version
            || serde_json::to_value(&self.observation.topology.topology)
                .map_err(|_| changed("Control topology release encoding failed"))?
                != document.body
            || state.state.revision < self.observation.revision
        {
            return Err(changed("Control topology changed before release"));
        }
        drop(state);
        self.fence.check()
    }
}
fn changed(message: &str) -> Error {
    Error::new(ErrorCode::Unavailable, message)
}

/// Counts before cloning. A large installed topology fails closed instead of
/// truncating inventory or allocating its whole encoded form before admission.
struct BoundedSize(usize);
impl std::io::Write for BoundedSize {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|size| *size <= MAX_CONTROL_TOPOLOGY_BYTES - 16_384)
            .ok_or_else(|| {
                std::io::Error::other("complete Control topology exceeds response bound")
            })?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Database {
    pub async fn observe_control_topology(
        self: &Arc<Self>,
        mut context: RequestContext,
        request: ReadControlTopology,
        caller: ControlTopologyCaller,
    ) -> Result<VerifiedControlTopology> {
        request
            .validate()
            .map_err(|error| Error::new(ErrorCode::InvalidArgument, error.to_string()))?;
        caller
            .validate()
            .map_err(|error| Error::new(ErrorCode::InvalidArgument, error.to_string()))?;
        if caller.principal != context.principal {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "Control routing caller differs",
            ));
        }
        let admitted_at_ms = self.lifecycle_now()?;
        let not_after_ms = admitted_at_ms
            .checked_add(request.maximum_lifetime_ms)
            .ok_or_else(|| changed("Control routing deadline overflow"))?
            .min(context.authorization.expires_at_ms().ok_or_else(|| {
                Error::new(
                    ErrorCode::Unauthorized,
                    "finite Control credential required",
                )
            })?);
        context.authorization = context.authorization.with_expiry_limit(not_after_ms)?;
        let fence = self.authorize_control_quorum(context.clone()).await?;
        if request.control_incarnation != fence.installation().root.control_incarnation
            || fence.voters().count() != 3
        {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "exact installed three-voter Control required",
            ));
        }
        let (observation, mut reservation) = {
            let state = self.engine.generation()?;
            let document = state
                .state
                .collections
                .get("topology")
                .and_then(|collection| collection.documents.get("current"))
                .ok_or_else(|| changed("installed Control topology unavailable"))?;
            let mut size = BoundedSize(0);
            serde_json::to_writer(&mut size, &document.body).map_err(|_| {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    "complete Control topology exceeds response bound",
                )
            })?;
            let bytes = u64::try_from(size.0)
                .ok()
                .and_then(|size| size.checked_mul(8))
                .and_then(|size| size.checked_add(65_536))
                .ok_or_else(|| changed("Control topology accounting overflow"))?;
            let reservation = self.admission().reserve(bytes, None)?;
            let observation = ControlTopologyObservation {
                request,
                root: fence.installation().root.clone(),
                caller,
                policy_epoch: fence.policy_epoch(),
                revision: state.state.revision,
                term: fence.term(),
                leader_node_id: fence.local_node_id(),
                voters: fence.voters().collect(),
                topology: ControlPlane::applied_topology(&state.state)?,
                admitted_at_ms,
                not_after_ms,
            };
            (observation, reservation)
        };
        observation
            .validate()
            .map_err(|error| changed(&error.to_string()))?;
        self.control_observation_audit(
            &context,
            observation.request.request_id,
            kasumi_serving::digest(&observation).map_err(|error| changed(&error.to_string()))?,
            observation.revision,
            observation.policy_epoch,
        )
        .await?;
        reservation.retain_workspace();
        let proof = VerifiedControlTopology {
            database: self.clone(),
            fence,
            observation,
            _reservation: reservation,
        };
        proof.release().await?;
        Ok(proof)
    }

    /// The original signed read is historical input. A new authenticated quorum
    /// read checks that exact caller and original deadline; it cannot renew them.
    pub async fn release_control_topology(
        self: &Arc<Self>,
        context: RequestContext,
        request: &ReleaseControlTopology,
        caller: ControlTopologyCaller,
        trust: &kasumi_serving::ControlTrust,
    ) -> Result<VerifiedControlTopology> {
        trust.verify_topology(&request.original).map_err(|_| {
            Error::new(
                ErrorCode::Forbidden,
                "invalid original Control routing signature",
            )
        })?;
        let old = &request.original.observation;
        if request.request_id.is_nil()
            || old.caller != caller
            || self.lifecycle_now()? >= old.not_after_ms
        {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "original Control routing caller or deadline differs",
            ));
        }
        let context = RequestContext {
            authorization: context.authorization.with_expiry_limit(old.not_after_ms)?,
            ..context
        };
        let current = self
            .observe_control_topology(context, old.request.clone(), caller)
            .await?;
        let actual = current.observation();
        if actual.root != old.root
            || actual.policy_epoch != old.policy_epoch
            || actual.term != old.term
            || actual.leader_node_id != old.leader_node_id
            || actual.voters != old.voters
            || actual.topology != old.topology
            || actual.revision < old.revision
            || actual.not_after_ms != old.not_after_ms
        {
            return Err(changed(
                "original Control routing observation is no longer current",
            ));
        }
        Ok(current)
    }
}
