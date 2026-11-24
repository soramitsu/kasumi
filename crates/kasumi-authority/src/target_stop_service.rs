use super::*;
use kasumi_types::{IssuerStopQuery, IssuerStopStage, IssuerStopStatus};

impl IndependentAuthority {
    pub(super) fn note_issuer_stop(
        &self,
        command: &AuthorityCommand,
        target: Uuid,
        term: u64,
        stage: IssuerStopStage,
        first: Option<String>,
        interval_id: Option<Uuid>,
    ) -> Result<()> {
        let status = IssuerStopStatus {
            query: IssuerStopQuery {
                tenant: command.tenant.clone(),
                command_id: command.command_id,
                target_incarnation: target,
            },
            command_sha256: command.digest().map_err(unavailable)?,
            partition: self.installation().partition,
            authority_id: self.installation().manifest.authority_id,
            node_id: self.local_node_id,
            boot_id: self.process_boot_id,
            term,
            stage,
            first_stop_sha256: first,
            interval_id,
        };
        self.backend.note_stop(&status).map_err(unavailable)
    }

    /// Read only. The current quorum and policy fence the return of this
    /// member's historical observation. This path never calls require_drain.
    pub async fn issuer_stop_status(
        self: &Arc<Self>,
        context: RequestContext,
        query: IssuerStopQuery,
    ) -> Result<(Option<IssuerStopStatus>, AuthorityResponseFence)> {
        let permit = self.permit()?;
        let signer = self.request_signer()?;
        query
            .validate()
            .map_err(|_| Error::new(ErrorCode::InvalidArgument, "invalid issuer stop query"))?;
        self.route(&query.tenant)?;
        let term = self.barrier(&context).await?;
        let epoch = self.backend.authorize_admin(&context)?;
        let result = self.backend.observed_stop(&query).map_err(unavailable)?;
        if let Some(found) = &result
            && (found.authority_id != self.installation().manifest.authority_id
                || found.partition != self.installation().partition
                || found.node_id != self.local_node_id)
        {
            return Err(unavailable(
                "issuer stop history belongs to another installed member",
            ));
        }
        if self.barrier(&context).await? != term {
            return Err(unavailable("issuer observation term changed"));
        }
        let fence = self.fence(permit, signer, context, Some(epoch), None, term);
        fence.check()?;
        Ok((result, fence))
    }

    /// Audited native adapters additionally retain the returned live fence
    /// through encoding/current quorum release. The signed observation is only
    /// irrevocable metadata; it grants no new materialization lease.
    pub async fn verify_target_stop(
        self: &Arc<Self>,
        context: RequestContext,
        reference: TargetStopReference,
    ) -> Result<(SignedTargetStop, AuthorityResponseFence)> {
        let permit = self.permit()?;
        let signer = self.request_signer()?;
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
        let command = self
            .backend
            .receipt(&reference.tenant, reference.command_id)
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("original issuer stop command absent"))?
            .command;
        let AuthorityAction::StopTarget { target, .. } = &command.action else {
            return Err(unavailable("original command is not a target stop"));
        };
        let observation_key = format!("target/{digest}");
        // Observe the issuing timer where its actual leader registers the
        // monotonic start. Resource/term failures never masquerade as a wait.
        let interval_id = {
            let mut drains = self.drains.lock().map_err(unavailable)?;
            let required = Duration::from_millis(
                self.installation()
                    .manifest
                    .drain_ms()
                    .map_err(unavailable)?,
            );
            let now = self.elapsed.now();
            let readiness =
                require_drain_witness(&mut drains, &observation_key, term, now, required, 10_000);
            if self.term() != term {
                return Err(unavailable("issuer drain term changed"));
            }
            if let Err(err) = readiness {
                if let Some(witness) = drains.get(&observation_key)
                    && witness.term == term
                    && now
                        .checked_sub(witness.started)
                        .is_some_and(|elapsed| elapsed < required)
                {
                    self.note_issuer_stop(
                        &command,
                        target.incarnation,
                        term,
                        IssuerStopStage::Draining,
                        Some(digest.clone()),
                        Some(witness.interval_id),
                    )?;
                }
                return Err(err);
            }
            drains
                .get(&observation_key)
                .ok_or_else(|| unavailable("target drain unavailable"))?
                .interval_id
        };
        if self.barrier(&context).await? != term {
            return Err(unavailable("target drain term changed"));
        }
        let fence = self.fence(permit, signer.clone(), context, Some(epoch), None, term);
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
        let signed = signer.sign_target_stop(observation).map_err(unavailable)?;
        fence.check()?;
        {
            let drains = self.drains.lock().map_err(unavailable)?;
            let original = drains
                .get(&observation_key)
                .ok_or_else(|| unavailable("target drain witness no longer owned"))?;
            if original.term != term || original.interval_id != interval_id {
                return Err(unavailable("target drain changed before proof release"));
            }
            self.note_issuer_stop(
                &command,
                target.incarnation,
                term,
                IssuerStopStage::Drained,
                Some(digest),
                Some(interval_id),
            )?;
        }
        fence.check()?;
        Ok((signed, fence))
    }
}
