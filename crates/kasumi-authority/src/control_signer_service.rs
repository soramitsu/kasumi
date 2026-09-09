//! Current read admission for an installed physical Control receiver. This
//! channel does not depend on an operational signing key that rotation seals.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

pub struct ControlSignerObservationFence {
    authority: Arc<IndependentAuthority>,
    context: RequestContext,
    request: ControlSignerRequest,
    material: ControlSignerObservation,
    term: u64,
    deadline: kasumi_clock::ElapsedDeadline,
    closed: AtomicBool,
    _permit: RequestPermit,
}
impl ControlSignerObservationFence {
    pub fn check(&self) -> Result<()> {
        self.authority.check_open()?;
        if self.closed.load(Ordering::SeqCst) {
            return Err(unavailable("remote observation closed"));
        }
        let checked = (|| {
            self.context.authorization.check_live()?;
            self.deadline.check().map_err(unavailable)?;
            self.authority.group.check_access().map_err(unavailable)?;
            self.authority
                .check_installed_configuration()
                .map_err(unavailable)?;
            if self.authority.term() != self.term
                || self
                    .authority
                    .backend
                    .control_signer_observation(&self.request)
                    .map_err(unavailable)?
                    != self.material
            {
                return Err(unavailable("current remote directive observation changed"));
            }
            self.context.authorization.check_live()?;
            self.deadline.check().map_err(unavailable)
        })();
        if checked.is_err() {
            self.closed.store(true, Ordering::SeqCst);
        }
        if self.closed.load(Ordering::SeqCst) {
            return Err(unavailable("remote observation closed"));
        }
        checked?;
        self.authority.check_open()
    }
    pub async fn release(&self) -> Result<()> {
        struct Attempt<'a>(&'a AtomicBool, bool);
        impl Drop for Attempt<'_> {
            fn drop(&mut self) {
                if !self.1 {
                    self.0.store(true, Ordering::SeqCst);
                }
            }
        }
        let mut attempt = Attempt(&self.closed, false);
        self.check()?;
        if self.authority.barrier(&self.context).await? != self.term {
            return Err(unavailable("remote directive quorum changed"));
        }
        self.check()?;
        attempt.1 = true;
        Ok(())
    }
}
impl IndependentAuthority {
    pub async fn observe_control_signer(
        self: &Arc<Self>,
        caller: AuthenticatedNode,
        request: ControlSignerRequest,
    ) -> Result<(ControlSignerObservation, ControlSignerObservationFence)> {
        let permit = self.permit()?;
        request
            .digest()
            .map_err(|error| Error::new(ErrorCode::InvalidArgument, error.to_string()))?;
        let context = caller.context;
        context.authorization.require_authority(
            self.installation().manifest.authority_id,
            self.installation().partition,
        )?;
        if context.tenant != self.installation().tenant()
            || !context.scopes.contains(&kasumi_types::Action::Read)
            || context.principal != request.directive.node.principal
            || caller.certificate_sha256 != request.directive.node.certificate_sha256
        {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "actual Control receiver credential or TLS peer differs",
            ));
        }
        let anchor = self.clock.observe().map_err(unavailable)?;
        let lifetime = context
            .authorization
            .expires_at_ms()
            .and_then(|expiry| expiry.checked_sub(anchor.utc_ms()))
            .filter(|remaining| *remaining > 0)
            .map(|remaining| remaining.min(self.installation().manifest.max_lease_ms))
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Unauthorized,
                    "finite Control receiver credential expired",
                )
            })?;
        let deadline = anchor
            .until(
                anchor
                    .utc_ms()
                    .checked_add(lifetime)
                    .ok_or_else(|| unavailable("remote deadline overflow"))?,
            )
            .map_err(unavailable)?;
        let term = self.barrier(&context).await?;
        let material = self
            .backend
            .control_signer_observation(&request)
            .map_err(|error| Error::new(ErrorCode::Forbidden, error.to_string()))?;
        let mut reply = material.clone();
        reply.authority_term = term;
        reply.lifetime_ms = lifetime;
        reply
            .validate_for(&request, &self.installation().manifest)
            .map_err(unavailable)?;
        let fence = ControlSignerObservationFence {
            authority: self.clone(),
            context,
            request,
            material,
            term,
            deadline,
            closed: AtomicBool::new(false),
            _permit: permit,
        };
        fence.release().await?;
        Ok((reply, fence))
    }
}
