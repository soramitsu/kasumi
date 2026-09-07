use super::*;
use crate::VerifiedRestoreLineage;

impl Database {
    /// Read only immutable historical commitments under the current permission
    /// to read one existing collection. This grants no schema/admin privileges.
    pub async fn read_restore_lineage(
        &self,
        context: &RequestContext,
        request: ReadRestoreLineage,
    ) -> Result<VerifiedRestoreLineage> {
        let result = self.read_restore_lineage_inner(context, request).await;
        self.audit_result(context, result).await
    }

    async fn read_restore_lineage_inner(
        &self,
        context: &RequestContext,
        request: ReadRestoreLineage,
    ) -> Result<VerifiedRestoreLineage> {
        validate_name(&request.collection)?;
        validate_name(&request.expected_incarnation)?;
        self.access()?;
        self.engine
            .authorize(context, Some(&request.collection), Action::Read)?;
        let mut reservation = self
            .admission()
            .reserve((MAX_RESTORE_LINEAGE_BYTES * 3 + (64 << 10)) as u64, None)?;
        let response = self.response_fence(context)?;
        self.barrier().await?;
        let generation = self.engine.generation()?;
        if generation.state.incarnation != request.expected_incarnation {
            return Err(Error::new(
                ErrorCode::Conflict,
                "lineage incarnation differs",
            ));
        }
        let collection = generation
            .state
            .collections
            .get(&request.collection)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "collection does not exist"))?;
        let strict = collection.definition.strict_read_audit;
        self.engine.authorize_release(
            context,
            Some(&request.collection),
            Action::Read,
            generation.state.policy_epoch,
        )?;
        let links = generation
            .state
            .restore_lineage
            .iter()
            .map(|link| {
                Ok(RestoreLineageCommitment {
                    source_incarnation: link.checkpoint.source_incarnation.clone(),
                    target_incarnation: link.target_incarnation.clone(),
                    source_revision: link.checkpoint.revision,
                    source_resident_sha256: link.checkpoint.resident_sha256.clone(),
                    checkpoint_sha256: staged_digest(&link.checkpoint)?.0,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let observation = RestoreLineageObservation {
            tenant: generation.state.tenant.clone(),
            incarnation: generation.state.incarnation.clone(),
            collection: request.collection,
            revision: generation.state.revision,
            policy_epoch: generation.state.policy_epoch,
            links,
        };
        observation.validate()?;
        drop(generation);
        reservation.retain_workspace();
        self.release_event(
            context,
            Some(&observation.collection),
            observation.revision,
            strict,
            observation.policy_epoch,
            "restore_lineage",
        )
        .await?;
        let proof = VerifiedRestoreLineage::from_verified_read(observation);
        self.check_restore_lineage_release(context, &proof).await?;
        response.check()?;
        Ok(proof)
    }

    /// Native adapters additionally retain their original ResponseFence through
    /// encoding and repeat this quorum/current collection check before handoff.
    pub async fn check_restore_lineage_release(
        &self,
        context: &RequestContext,
        proof: &VerifiedRestoreLineage,
    ) -> Result<()> {
        self.access()?;
        self.barrier().await?;
        let observation = proof.observation();
        let state = self.engine.generation()?;
        if context.tenant != observation.tenant
            || state.state.incarnation != observation.incarnation
            || !state
                .state
                .collections
                .contains_key(&observation.collection)
        {
            return Err(Error::new(
                ErrorCode::Conflict,
                "lineage release target changed",
            ));
        }
        self.engine.authorize_release(
            context,
            Some(&observation.collection),
            Action::Read,
            observation.policy_epoch,
        )?;
        self.access()
    }
}
