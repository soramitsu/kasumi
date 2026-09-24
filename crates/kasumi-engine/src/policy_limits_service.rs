use super::*;

impl Database {
    /// Quorum-coherent administrative readback of the current policy and
    /// limits. Neither the request nor the response may select another tenant.
    pub async fn read_policy_limits(
        &self,
        context: &RequestContext,
        request: ReadPolicyLimits,
    ) -> Result<PolicyLimitsSnapshot> {
        let result = self.read_policy_limits_inner(context, request).await;
        self.audit_result(context, result).await
    }

    async fn read_policy_limits_inner(
        &self,
        context: &RequestContext,
        request: ReadPolicyLimits,
    ) -> Result<PolicyLimitsSnapshot> {
        self.access()?;
        validate_name(&request.tenant)?;
        if request.tenant != context.tenant {
            return Err(Error::new(ErrorCode::Forbidden, "tenant access denied"));
        }
        if uuid::Uuid::parse_str(&request.expected_incarnation)
            .ok()
            .is_none_or(|id| id.is_nil() || id.to_string() != request.expected_incarnation)
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "policy/limits read requires a canonical nonzero incarnation",
            ));
        }
        self.engine.authorize(context, None, Action::Admin)?;
        let mut reservation = self.admission().reserve(
            (MAX_POLICY_LIMITS_SNAPSHOT_BYTES * 3 + (1 << 20)) as u64,
            None,
        )?;
        self.barrier().await?;
        let generation = self.engine.generation()?;
        if generation.state.tenant != request.tenant
            || generation.state.incarnation != request.expected_incarnation
        {
            return Err(Error::new(
                ErrorCode::Conflict,
                "policy/limits database identity differs",
            ));
        }
        self.engine.authorize_release(
            context,
            None,
            Action::Admin,
            generation.state.policy_epoch,
        )?;
        let snapshot = PolicyLimitsSnapshot {
            tenant: generation.state.tenant.clone(),
            incarnation: generation.state.incarnation.clone(),
            revision: generation.state.revision,
            policy_epoch: generation.state.policy_epoch,
            schema_epoch: generation.state.schema_epoch,
            policy: generation.state.policy.clone(),
            limits: generation.state.limits.clone(),
        };
        if crate::accounting::encoded_len(&snapshot)? > MAX_POLICY_LIMITS_SNAPSHOT_BYTES {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "policy/limits readback exceeds byte budget",
            ));
        }
        drop(generation);
        reservation.retain_workspace();
        self.release_event(
            context,
            None,
            snapshot.revision,
            true,
            snapshot.policy_epoch,
            "policy_limits_read",
        )
        .await?;
        self.access()?;
        Ok(snapshot)
    }
}
