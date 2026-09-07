use super::*;
impl IndependentAuthority {
    /// Audited native adapters additionally retain the returned live fence
    /// through encoding/current quorum release. The signed observation is only
    /// irrevocable metadata; it grants no new materialization lease.
    pub async fn verify_target_stop(
        self: &Arc<Self>,
        context: RequestContext,
        reference: TargetStopReference,
    ) -> Result<(SignedTargetStop, AuthorityResponseFence)> {
        let _permit = self.permit()?;
        reference
            .validate()
            .map_err(|_| Error::new(ErrorCode::InvalidArgument, "invalid target stop reference"))?;
        self.route(&reference.tenant)?;
        let term = self.barrier(&context).await?;
        let epoch = self.backend.authorize_admin(&context)?;
        let stop = self
            .backend
            .stopped_target(&reference)
            .map_err(unavailable)?;
        let digest = stop.digest().map_err(unavailable)?;
        self.require_drain(&format!("target/{digest}"), term)?;
        if self.barrier(&context).await? != term {
            return Err(unavailable("target drain term changed"));
        }
        let fence = self.fence(context, Some(epoch), None, term);
        fence.check()?;
        let current = self
            .backend
            .stopped_target(&reference)
            .map_err(unavailable)?;
        if current != stop {
            return Err(unavailable("target stop changed"));
        }
        self.require_drain(&format!("target/{digest}"), term)?;
        let observation = TargetStopObservation {
            reference,
            observed_term: term,
            observed_revision: self.backend.revision().map_err(unavailable)?,
            stop,
            drain_ms: self
                .installation()
                .manifest
                .drain_ms()
                .map_err(unavailable)?,
        };
        let signed = self
            .signer
            .sign_target_stop(observation)
            .map_err(unavailable)?;
        fence.check()?;
        Ok((signed, fence))
    }
}
