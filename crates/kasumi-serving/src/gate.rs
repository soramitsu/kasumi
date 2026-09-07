use crate::{LeasePurpose, ServingIdentity, VerifiedLease};
use anyhow::{Result, ensure};
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

struct GateState {
    lease: VerifiedLease,
    closed: bool,
}
/// Once any access observes expiry or clock regression, this gate is permanently
/// closed. Renewal cannot revive captured results or a failed state machine.
pub struct ServingGate {
    state: Mutex<GateState>,
    closed: watch::Sender<bool>,
    identity: ServingIdentity,
    authority_digest: String,
}
impl ServingGate {
    pub fn new(lease: VerifiedLease) -> Result<Arc<Self>> {
        lease.check()?;
        let identity = lease.identity().clone();
        let authority_digest = lease.boot.trust.digest().to_owned();
        Ok(Arc::new(Self {
            state: Mutex::new(GateState {
                lease,
                closed: false,
            }),
            closed: watch::channel(false).0,
            identity,
            authority_digest,
        }))
    }
    pub fn identity(&self) -> &ServingIdentity {
        &self.identity
    }
    pub fn authority_digest(&self) -> &str {
        &self.authority_digest
    }
    pub fn activation_digest(&self) -> Result<String> {
        self.check()?;
        Ok(self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("serving gate poisoned"))?
            .lease
            .activation_digest()
            .into())
    }
    pub fn recovery_checkpoint(&self) -> Result<Option<kasumi_types::FullBackupCheckpoint>> {
        self.check()?;
        Ok(self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("serving gate poisoned"))?
            .lease
            .signed
            .claims
            .recovery_checkpoint
            .clone())
    }
    pub fn notifications(&self) -> watch::Receiver<bool> {
        self.closed.subscribe()
    }
    pub fn check_serving(&self) -> Result<()> {
        self.check()?;
        ensure!(
            self.state
                .lock()
                .map_err(|_| anyhow::anyhow!("serving gate poisoned"))?
                .lease
                .signed
                .claims
                .request
                .purpose
                == LeasePurpose::Serving,
            "restore preparation cannot serve tenant traffic"
        );
        Ok(())
    }
    /// Promotion consumes a fresh issuer-verified active-incarnation lease for
    /// the exact same prepared target and original process. It cannot revive a
    /// gate that observed expiry; such a replica must reopen under a fresh boot.
    pub fn promote_prepared(&self, lease: VerifiedLease) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("serving gate poisoned"))?;
        if state.closed || state.lease.check().is_err() {
            state.closed = true;
            self.closed.send_replace(true);
            anyhow::bail!("expired prepared generation requires reopen");
        }
        lease.check()?;
        ensure!(
            state.lease.signed.claims.request.purpose == LeasePurpose::RestorePreparation
                && lease.signed.claims.request.purpose == LeasePurpose::Serving
                && lease.identity() == &self.identity
                && lease.boot.id == state.lease.boot.id
                && lease.boot.trust.digest() == self.authority_digest
                && lease.signed.claims.recovery_checkpoint
                    == state.lease.signed.claims.recovery_checkpoint,
            "active lease does not match exact prepared target"
        );
        state.lease = lease;
        Ok(())
    }
    pub fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
        }
        self.closed.send_replace(true);
    }
    pub fn check(&self) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("serving gate poisoned"))?;
        if state.closed || state.lease.check().is_err() {
            state.closed = true;
            self.closed.send_replace(true);
            anyhow::bail!("serving generation fenced or expired");
        }
        Ok(())
    }
    pub fn renew(&self, lease: VerifiedLease) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("serving gate poisoned"))?;
        if state.closed || state.lease.check().is_err() {
            state.closed = true;
            self.closed.send_replace(true);
            anyhow::bail!("renewal cannot revive an expired generation");
        }
        lease.check()?;
        ensure!(
            lease.identity() == &self.identity
                && lease.boot.id == state.lease.boot.id
                && lease.boot.trust.digest() == self.authority_digest
                && lease.activation_digest() == state.lease.activation_digest()
                && lease.signed.claims.request.purpose == state.lease.signed.claims.request.purpose,
            "renewal installation, boot or activation differs"
        );
        ensure!(
            lease.start >= state.lease.start && lease.deadline >= state.lease.deadline,
            "stale renewal attempt"
        );
        state.lease = lease;
        Ok(())
    }
    pub fn capture(self: &Arc<Self>) -> Result<ServingFence> {
        self.check_serving()?;
        Ok(ServingFence(self.clone()))
    }
}
#[derive(Clone)]
pub struct ServingFence(Arc<ServingGate>);
impl ServingFence {
    pub fn check(&self) -> Result<()> {
        self.0.check_serving()
    }
}
