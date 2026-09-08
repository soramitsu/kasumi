//! Closed target authority: original verified Control credential, exact issuer
//! phase and local storage capability survive cloning, queues and worker waits.
use kasumi_serving::{AuthorityTrust, LifecycleGate, SignedLifecycleLease};
use kasumi_store::TenantStore;
use kasumi_types::*;
use serde::{Deserialize, Serialize};
use std::{future::Future, sync::Arc};

#[derive(Clone)]
pub struct TargetLifecycleInvocation {
    gate: Arc<LifecycleGate>,
}
impl TargetLifecycleInvocation {
    pub fn from_verified(gate: Arc<LifecycleGate>) -> Result<Self> {
        gate.check().map_err(unauthorized)?;
        Ok(Self { gate })
    }
    pub fn context(&self) -> &RequestContext {
        self.gate.context()
    }
    pub fn gate(&self) -> &Arc<LifecycleGate> {
        &self.gate
    }
    pub fn check(&self) -> Result<()> {
        self.gate.check().map_err(unauthorized)
    }
    pub fn check_target(&self, target: &TenantStore, phase: LifecyclePhase) -> Result<()> {
        self.check()?;
        target.check_access().map_err(unauthorized)?;
        let serving = target
            .storage_access()
            .serving_gate()
            .ok_or_else(|| unauthorized("missing serving authority"))?;
        let actual = target
            .storage_access()
            .lifecycle_gate()
            .ok_or_else(|| unauthorized("missing phase authority"))?;
        if !Arc::ptr_eq(actual, &self.gate) {
            return Err(unauthorized(
                "target store belongs to a different phase invocation",
            ));
        }
        self.gate.check_target(serving, phase).map_err(unauthorized)
    }
    pub(crate) async fn run<T>(
        &self,
        token: &kasumi_query::QueryCancellation,
        future: impl Future<Output = anyhow::Result<T>>,
    ) -> anyhow::Result<T> {
        self.check()?;
        token.check()?;
        let mut closed = self.gate.notifications();
        let monitoring = async {
            loop {
                tokio::select! {
                    _=closed.changed()=> {self.check()?;token.check()?;},
                    _=tokio::time::sleep(std::time::Duration::from_millis(100))=>{self.check()?;token.check()?;},
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), Error>(())
        };
        tokio::pin!(future);
        let result = tokio::select! {
            biased;
            expired=monitoring=>return Err(expired.err().unwrap_or_else(||unauthorized("target phase closed")).into()),
            result=&mut future=>result?,
        };
        token.check()?;
        self.check()?;
        Ok(result)
    }
    pub(crate) fn prepare(
        &self,
        context: &RequestContext,
        phase: LifecyclePhase,
        input_sha256: &str,
        admitted_at_ms: u64,
    ) -> Result<PreparedTargetAuthorization> {
        self.check()?;
        let lease = self.gate.current().map_err(unauthorized)?;
        let intent = &lease.commitment().intent;
        if intent.request.phase != phase
            || intent.request.phase_input_sha256 != input_sha256
            || admitted_at_ms < intent.accepted_at_ms
            || admitted_at_ms >= intent.original_credential_expires_at_ms
        {
            return Err(Error::new(
                ErrorCode::Conflict,
                "target phase input or original deadline differs",
            ));
        }
        self.check_request_context(context)?;
        context.authorization.check_admitted_at(admitted_at_ms)?;
        Ok(PreparedTargetAuthorization {
            context: context.clone(),
            grant: lease.signed().clone(),
            admitted_at_ms,
        })
    }
    fn check_request_context(&self, context: &RequestContext) -> Result<()> {
        self.check()?;
        context.authorization.check_live()?;
        let lease = self.gate.current().map_err(unauthorized)?;
        let intent = &lease.commitment().intent;
        context
            .authorization
            .require_control(&intent.control_incarnation.to_string())?;
        if context.tenant != "__kasumi_control"
            || !context.scopes.contains(&Action::Admin)
            || context.principal != intent.original_principal
            || context.authorization.expires_at_ms().is_none()
        {
            return Err(unauthorized(
                "request differs from the current target phase",
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparedTargetAuthorization {
    pub context: RequestContext,
    pub grant: SignedLifecycleLease,
    pub admitted_at_ms: u64,
}
impl PreparedTargetAuthorization {
    pub fn verify(
        &self,
        trust: &AuthorityTrust,
        origin: &TargetOrigin,
        phase: LifecyclePhase,
        input_sha256: &str,
        actual_leader_node: u64,
    ) -> Result<()> {
        trust
            .verify_lifecycle_claims(&self.grant)
            .map_err(unauthorized)?;
        let intent = &self.grant.claims.commitment.intent;
        origin.accepts_phase(intent, phase)?;
        self.context
            .authorization
            .require_control(&intent.control_incarnation.to_string())?;
        self.context
            .authorization
            .check_admitted_at(self.admitted_at_ms)?;
        if self.context.tenant != "__kasumi_control"
            || !self.context.scopes.contains(&Action::Admin)
            || self.context.principal != intent.original_principal
            || self.context.authorization.expires_at_ms().is_none()
            || self.admitted_at_ms < intent.accepted_at_ms
            || self.admitted_at_ms >= intent.original_credential_expires_at_ms
            || self.grant.claims.request.target_node.node_id != actual_leader_node
            || intent.request.phase_input_sha256 != input_sha256
            || trust.digest() != origin.authority_manifest_sha256
        {
            return Err(unauthorized(
                "ordered target authorization differs from actual leader and phase",
            ));
        }
        Ok(())
    }
}
fn unauthorized(_: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorCode::Unauthorized,
        "target lifecycle grant or original credential unavailable",
    )
}

/// Captured once at the native boundary, before Control/issuer acquisition.
/// It cannot be deserialized, cloned or re-anchored into a later operation.
pub struct TargetRequestAdmission {
    context: RequestContext,
    elapsed: kasumi_clock::ElapsedDeadline,
    deadline: crate::backup_verify::VerificationDeadline,
    timeout_ms: u64,
}
impl TargetRequestAdmission {
    pub fn capture(context: RequestContext, timeout_ms: u64) -> Result<Self> {
        let clock = kasumi_clock::EpochClock::system().map_err(unauthorized)?;
        Self::capture_with_clock(context, timeout_ms, clock.as_ref())
    }
    fn capture_with_clock(
        context: RequestContext,
        timeout_ms: u64,
        clock: &kasumi_clock::EpochClock,
    ) -> Result<Self> {
        context.authorization.check_live()?;
        if context.authorization.expires_at_ms().is_none() {
            return Err(unauthorized("finite native credential required"));
        }
        let deadline = crate::backup_verify::VerificationDeadline::new(timeout_ms)
            .map_err(|_| Error::new(ErrorCode::InvalidArgument, "target timeout outside bounds"))?;
        let observation = clock.observe().map_err(unauthorized)?;
        let expires = observation
            .utc_ms()
            .checked_add(timeout_ms)
            .ok_or_else(|| unauthorized("target deadline exhausted"))?;
        let elapsed = observation.until(expires).map_err(unauthorized)?;
        Ok(Self {
            context,
            elapsed,
            deadline,
            timeout_ms,
        })
    }
    pub fn require_context(&self, context: &RequestContext) -> Result<()> {
        self.check()?;
        if self.context != *context
            || !self
                .context
                .authorization
                .same_live_invocation(&context.authorization)
        {
            return Err(unauthorized(
                "native acquisition changed original credential invocation",
            ));
        }
        Ok(())
    }
    pub fn check(&self) -> Result<()> {
        self.context.authorization.check_live()?;
        self.elapsed.check().map_err(unauthorized)?;
        self.deadline.check().map_err(unauthorized)
    }
    pub async fn run<T>(
        &self,
        future: impl Future<Output = anyhow::Result<T>>,
    ) -> anyhow::Result<T> {
        self.check()?;
        let monitoring = async {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                self.check()?;
            }
            #[allow(unreachable_code)]
            Ok::<(), Error>(())
        };
        let result = tokio::select! {
            biased;
            closed = monitoring => return Err(closed.err().unwrap_or_else(|| unauthorized("request closed")).into()),
            result = self.deadline.run(future) => result??,
        };
        self.check()?;
        Ok(result)
    }
}

/// Per-generation admission is installed before provider construction. Closing
/// it cancels current waiters and drains actual detached verification ownership.
pub struct TargetOperationScope {
    invocation: Arc<TargetLifecycleInvocation>,
    work: Arc<crate::admission::WorkFence>,
    slot: Arc<tokio::sync::Semaphore>,
}
impl TargetOperationScope {
    pub fn new(invocation: TargetLifecycleInvocation) -> Result<Arc<Self>> {
        invocation.check()?;
        Ok(Arc::new(Self {
            invocation: Arc::new(invocation),
            work: Arc::new(crate::admission::WorkFence::default()),
            slot: Arc::new(tokio::sync::Semaphore::new(1)),
        }))
    }
    pub fn invocation(&self) -> &Arc<TargetLifecycleInvocation> {
        &self.invocation
    }
    /// Used only by the installed owner while holding its generation lock.
    /// Returned proofs retain the operation slot until final response release.
    pub fn is_idle(&self) -> bool {
        self.slot.available_permits() == 1
    }
    pub fn close(&self) {
        self.work.seal();
        self.invocation.gate.close();
    }
    pub async fn drain(&self) {
        self.work.drain().await;
    }
    pub(crate) fn begin(
        &self,
        admission: Arc<TargetRequestAdmission>,
    ) -> Result<(
        Arc<crate::backup_verify::VerificationWork>,
        kasumi_query::QueryCancellation,
    )> {
        self.invocation.check()?;
        let permit = self.slot.clone().try_acquire_owned().map_err(|_| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "target phase operation already active",
            )
        })?;
        let token = kasumi_query::QueryCancellation::default();
        let registration = self.work.begin(token.clone())?;
        let work = crate::backup_verify::VerificationWork::for_target(
            registration,
            permit,
            self.invocation.clone(),
            token.clone(),
            admission,
        );
        self.invocation.check()?;
        Ok((work, token))
    }
}

/// Original bounded operation ownership. A native runner obtains this before
/// constructing any application provider and retains it through response release.
#[derive(Clone)]
pub struct TargetOperation {
    identity: Arc<()>,
    scope: Arc<TargetOperationScope>,
    admission: Arc<TargetRequestAdmission>,
    pub(crate) work: Arc<crate::backup_verify::VerificationWork>,
    pub(crate) token: kasumi_query::QueryCancellation,
    pub(crate) deadline: crate::backup_verify::VerificationDeadline,
    pub(crate) timeout_ms: u64,
}
impl TargetOperationScope {
    pub fn begin_operation(self: &Arc<Self>, timeout_ms: u64) -> Result<TargetOperation> {
        let admission =
            TargetRequestAdmission::capture(self.invocation.context().clone(), timeout_ms)?;
        self.begin_admitted(admission)
    }
    pub fn begin_admitted(
        self: &Arc<Self>,
        admission: TargetRequestAdmission,
    ) -> Result<TargetOperation> {
        admission.check()?;
        admission.require_context(self.invocation.context())?;
        self.begin_followup(admission)
    }
    /// A later request receives its own original credential and timeout while
    /// retaining the continuously live phase's original credential and grant.
    /// The native runner additionally repeats current Control authorization for
    /// that request; this method cannot renew or replace the installed phase.
    pub fn begin_followup(
        self: &Arc<Self>,
        admission: TargetRequestAdmission,
    ) -> Result<TargetOperation> {
        admission.check()?;
        self.invocation.check_request_context(&admission.context)?;
        let deadline = admission.deadline;
        let timeout_ms = admission.timeout_ms;
        let admission = Arc::new(admission);
        let (work, token) = self.begin(admission.clone())?;
        Ok(TargetOperation {
            identity: Arc::new(()),
            scope: self.clone(),
            admission,
            work,
            token,
            deadline,
            timeout_ms,
        })
    }
}
impl TargetOperation {
    pub fn context(&self) -> &RequestContext {
        &self.admission.context
    }
    pub fn invocation(&self) -> &TargetLifecycleInvocation {
        &self.scope.invocation
    }
    pub fn check(&self) -> anyhow::Result<()> {
        self.deadline.check()?;
        self.work.check()?;
        Ok(())
    }
    pub(crate) fn prepare(
        &self,
        phase: LifecyclePhase,
        input_sha256: &str,
        admitted_at_ms: u64,
    ) -> Result<PreparedTargetAuthorization> {
        self.check().map_err(unauthorized)?;
        self.invocation()
            .prepare(self.context(), phase, input_sha256, admitted_at_ms)
    }
    pub async fn run<T>(
        &self,
        future: impl Future<Output = anyhow::Result<T>>,
    ) -> anyhow::Result<T> {
        self.check()?;
        let result = self
            .admission
            .run(self.invocation().run(&self.token, future))
            .await?;
        self.check()?;
        Ok(result)
    }
}

/// Readback/signing cannot replace the original operation timeout merely by
/// reusing the same still-live phase. This fence owns no renewable admission.
#[derive(Clone)]
pub(crate) struct TargetReleaseFence {
    identity: Arc<()>,
    invocation: TargetLifecycleInvocation,
    token: kasumi_query::QueryCancellation,
    deadline: crate::backup_verify::VerificationDeadline,
}
impl TargetReleaseFence {
    pub fn check(&self, operation: &TargetOperation) -> anyhow::Result<()> {
        anyhow::ensure!(
            Arc::ptr_eq(&self.identity, &operation.identity),
            "target proof belongs to a different original operation"
        );
        self.deadline.check()?;
        self.token.check()?;
        self.invocation.check()?;
        operation.check()
    }
}
impl TargetOperation {
    pub(crate) fn release_fence(&self) -> TargetReleaseFence {
        TargetReleaseFence {
            identity: self.identity.clone(),
            invocation: self.invocation().clone(),
            token: self.token.clone(),
            deadline: self.deadline,
        }
    }
}

impl TargetOperation {
    pub(crate) fn register_group(&self) -> Result<crate::admission::WorkRegistration> {
        self.scope.work.begin(self.token.clone())
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use std::{
        collections::BTreeSet,
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };
    struct Clock(AtomicU64);
    impl kasumi_clock::LeaseClock for Clock {
        fn now(&self) -> Duration {
            Duration::from_millis(self.0.load(Ordering::SeqCst))
        }
    }
    struct Wall;
    impl kasumi_clock::WallClock for Wall {
        fn now_ms(&self) -> anyhow::Result<u64> {
            Ok(1_000_000)
        }
    }
    #[tokio::test]
    async fn original_short_timeout_expires_during_acquisition_and_cannot_reanchor_after_suspend() {
        let clock = Arc::new(Clock(AtomicU64::new(0)));
        let epoch = kasumi_clock::EpochClock::new(clock.clone(), Arc::new(Wall)).unwrap();
        let context = RequestContext {
            tenant: "__kasumi_control".into(),
            principal: "control-admin".into(),
            request_id: "short-acquisition".into(),
            scopes: BTreeSet::from([Action::Admin]),
            authorization: RequestAuthorization::from_verified_credential(
                1_500_000,
                &epoch.observe().unwrap(),
                CredentialResource::Control {
                    incarnation: uuid::Uuid::new_v4(),
                },
            )
            .unwrap(),
        };
        let admission =
            TargetRequestAdmission::capture_with_clock(context.clone(), 25, &epoch).unwrap();
        // Models remote acquisition plus system suspend. The much longer actual
        // credential remains live; only the original operation timeout expires.
        clock.0.store(26, Ordering::SeqCst);
        assert!(context.authorization.check_live().is_ok());
        let polled = std::sync::atomic::AtomicBool::new(false);
        assert!(
            admission
                .run(async {
                    polled.store(true, Ordering::SeqCst);
                    Ok(())
                })
                .await
                .is_err()
        );
        assert!(!polled.load(Ordering::SeqCst));
        clock.0.store(1, Ordering::SeqCst);
        assert!(admission.check().is_err());
    }
}
