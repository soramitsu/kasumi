//! One continuously live target phase. A later phase or boot cannot reopen this
//! gate or release a response captured by it; the runner drains and reopens.
use crate::{ServingGate, VerifiedLifecycleLease};
use anyhow::{Result, ensure};
use kasumi_types::{Action, LifecyclePhase, RequestContext};
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

struct PhaseState {
    lease: VerifiedLifecycleLease,
    closed: bool,
}
/// The original Control credential and issuer grant are held together. Only
/// immutable exact phase renewals are allowed before the previous deadline.
pub struct LifecycleGate {
    context: RequestContext,
    clock: Arc<kasumi_clock::EpochClock>,
    state: Mutex<PhaseState>,
    closed: watch::Sender<bool>,
}
impl LifecycleGate {
    pub fn new(context: RequestContext, lease: VerifiedLifecycleLease) -> Result<Arc<Self>> {
        Self::with_clock(context, lease, kasumi_clock::EpochClock::system()?.clone())
    }
    #[cfg(any(test, feature = "test-utils"))]
    pub fn with_test_clock(
        context: RequestContext,
        lease: VerifiedLifecycleLease,
        clock: Arc<kasumi_clock::EpochClock>,
    ) -> Result<Arc<Self>> {
        Self::with_clock(context, lease, clock)
    }
    fn with_clock(
        context: RequestContext,
        lease: VerifiedLifecycleLease,
        clock: Arc<kasumi_clock::EpochClock>,
    ) -> Result<Arc<Self>> {
        let gate = Arc::new(Self {
            context,
            clock,
            state: Mutex::new(PhaseState {
                lease,
                closed: false,
            }),
            closed: watch::channel(false).0,
        });
        gate.check()?;
        Ok(gate)
    }
    fn check_credential(&self, lease: &VerifiedLifecycleLease) -> Result<()> {
        self.context.authorization.check_live()?;
        let intent = &lease.commitment().intent;
        self.context
            .authorization
            .require_control(&intent.control_incarnation.to_string())?;
        ensure!(
            self.context.tenant == "__kasumi_control"
                && self.context.scopes.contains(&Action::Admin)
                && self.context.principal == intent.original_principal
                && self.context.authorization.expires_at_ms().is_some(),
            "original finite Control credential required"
        );
        let now = self.clock.now_ms()?;
        self.context.authorization.check_admitted_at(now)?;
        ensure!(
            now < intent.original_credential_expires_at_ms,
            "original committed phase credential expired"
        );
        lease.check()
    }
    fn check_locked(&self, state: &mut PhaseState) -> Result<()> {
        if state.closed || self.check_credential(&state.lease).is_err() {
            state.closed = true;
            self.closed.send_replace(true);
            anyhow::bail!("target phase closed or expired");
        }
        Ok(())
    }
    pub fn check(&self) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("phase gate poisoned"))?;
        self.check_locked(&mut state)
    }
    pub fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
        }
        self.closed.send_replace(true);
    }
    pub fn notifications(&self) -> watch::Receiver<bool> {
        self.closed.subscribe()
    }
    pub fn admission_time_ms(&self) -> Result<u64> {
        self.check()?;
        let now = self.clock.now_ms()?;
        self.check()?;
        Ok(now)
    }
    pub fn context(&self) -> &RequestContext {
        &self.context
    }
    pub fn current(&self) -> Result<VerifiedLifecycleLease> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("phase gate poisoned"))?;
        self.check_locked(&mut state)?;
        Ok(state.lease.clone())
    }
    pub fn renew(&self, lease: VerifiedLifecycleLease) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("phase gate poisoned"))?;
        self.check_locked(&mut state)?;
        self.check_credential(&lease)?;
        state.lease.require_continuous_renewal(&lease)?;
        state.lease = lease;
        Ok(())
    }
    pub fn check_target(&self, serving: &ServingGate, phase: LifecyclePhase) -> Result<()> {
        let lease = self.current()?;
        serving.check()?;
        let intent = &lease.commitment().intent.request;
        let identity = serving.identity();
        ensure!(
            intent.phase == phase
                && lease.signed().claims.application_purpose
                    == Some(if serving.is_prepared()? {
                        crate::LeasePurpose::RestorePreparation
                    } else {
                        crate::LeasePurpose::Serving
                    })
                && identity.tenant == intent.tenant
                && identity.incarnation == intent.target_incarnation
                && Some(identity.authority_epoch) == intent.source_authority_epoch.checked_add(1)
                && identity.node == lease.signed().claims.request.target_node
                && serving.authority_digest()
                    == lease.signed().claims.request.authority_manifest_sha256
                && serving.recovery_checkpoint()?.as_ref() == Some(&intent.checkpoint),
            "phase capability differs from installed target storage"
        );
        self.check()
    }
    pub fn capture(self: &Arc<Self>) -> Result<LifecycleFence> {
        self.check()?;
        Ok(LifecycleFence(self.clone()))
    }
}
#[derive(Clone)]
pub struct LifecycleFence(Arc<LifecycleGate>);
impl LifecycleFence {
    pub fn check(&self) -> Result<()> {
        self.0.check()
    }
}
