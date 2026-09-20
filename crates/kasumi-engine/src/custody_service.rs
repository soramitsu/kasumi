//! Closed administrative service. Successful local recovery is not proof release:
//! every operation still requires current quorum, Admin and the original credential.
use super::*;
use kasumi_raft::{CustodyCommand, CustodyRaftGroup, CustodyView};
use kasumi_store::CustodyStore;

#[derive(Clone)]
enum CustodyGroup {
    Serving(RaftGroup),
    Closed(CustodyRaftGroup),
}
impl CustodyGroup {
    fn receipt(&self, command_id: &str) -> anyhow::Result<Option<CustodyReceipt>> {
        match self {
            Self::Serving(group) => group.custody_receipt(command_id),
            Self::Closed(group) => group.receipt(command_id),
        }
    }
    fn view(&self) -> anyhow::Result<CustodyView> {
        match self {
            Self::Serving(group) => group.custody_view(),
            Self::Closed(group) => group.view(),
        }
    }
    async fn barrier(&self) -> anyhow::Result<()> {
        match self {
            Self::Serving(group) => {
                group.linearizable_barrier().await?;
            }
            Self::Closed(group) => {
                group.linearizable_barrier().await?;
            }
        }
        Ok(())
    }
    async fn write(&self, command: CustodyCommand) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Serving(group) => group.write_custody(command).await,
            Self::Closed(group) => group.write(command).await,
        }
    }
}

// Field order keeps storage ownership and reservations alive until the job
// really finishes; the final registration drop is what releases shutdown drain.
struct CustodyProposalWork {
    group: CustodyGroup,
    gate: Arc<tokio::sync::Mutex<()>>,
    clock: Arc<dyn CommandClock>,
    admission: Arc<NodeAdmission>,
    cancellation: QueryCancellation,
    _reservation: Reservation,
    _registration: WorkRegistration,
}
impl CustodyProposalWork {
    async fn run(self, context: RequestContext, request: CustodyRequest) -> Result<Vec<u8>> {
        let _gate = self.gate.clone().lock_owned().await;
        let admitted = (|| -> Result<CustodyCommand> {
            self.admission.check_release(&self.cancellation)?;
            context.authorization.check_live()?;
            let view = self.group.view().map_err(unavailable)?;
            view.authorize(&context)?;
            let admitted_at_ms = self.clock.now_ms()?;
            context.authorization.check_admitted_at(admitted_at_ms)?;
            Ok(CustodyCommand {
                context,
                request,
                admitted_at_ms,
            })
        })();
        match admitted {
            Ok(command) => self.group.write(command).await.map_err(unknown),
            Err(error) => serde_json::to_vec(&Err::<CustodyReceipt, _>(error)).map_err(unavailable),
        }
    }
}

pub struct CustodyResponseFence {
    group: CustodyGroup,
    context: RequestContext,
    policy_epoch: u64,
    accepted_invocation: Option<Box<crate::VerifiedRetirementReceipt>>,
    admission: Arc<NodeAdmission>,
    cancellation: QueryCancellation,
    _reservation: Reservation,
}
impl CustodyResponseFence {
    pub fn check(&self) -> Result<()> {
        self.context.authorization.check_live()?;
        self.admission.check_release(&self.cancellation)?;
        let view = self.group.view().map_err(unavailable)?;
        authorize_observation(&view, &self.context, self.accepted_invocation.as_deref())?;
        if view.policy_epoch() != self.policy_epoch {
            return Err(Error::new(
                ErrorCode::Conflict,
                "custody policy changed before response release",
            ));
        }
        Ok(())
    }
}

/// A retired source has no document, query, application schema or general admin
/// method. Opening this service never constructs an application provider/backend.
pub struct RetiredCustody {
    group: CustodyGroup,
    admission: Arc<NodeAdmission>,
    audit: Arc<SecurityAudit>,
    work: Arc<WorkFence>,
    proposal_gate: Arc<tokio::sync::Mutex<()>>,
    clock: Arc<dyn CommandClock>,
    closing: AtomicBool,
    shutdown_report: tokio::sync::Mutex<DrainReport>,
}
fn unavailable(_: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorCode::Unavailable,
        "retired source custody requires recovery",
    )
}
fn unknown(_: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorCode::UnknownOutcome,
        "custody command acknowledgement unavailable; recover its exact permanent identity with current authority",
    )
}

fn authorize_observation(
    view: &CustodyView,
    context: &RequestContext,
    invocation: Option<&crate::VerifiedRetirementReceipt>,
) -> Result<()> {
    let Some(proof) = invocation else {
        return view.authorize(context);
    };
    context.authorization.check_live()?;
    context
        .authorization
        .require_database(&view.retirement().source_incarnation)?;
    if !proof.is_accepted_invocation(context)
        || proof.receipt() != view.retirement()
        || context.principal != view.retirement().principal
        || context.tenant != view.retirement().tenant
        || !context.scopes.contains(&Action::Admin)
        || !view.administrators().contains(&context.principal)
    {
        return Err(Error::new(
            ErrorCode::Forbidden,
            "original accepted retirement invocation required",
        ));
    }
    Ok(())
}

impl RetiredCustody {
    pub async fn open_replicated(
        custody: Arc<CustodyStore>,
        node_id: u64,
        group: String,
        transport: Arc<dyn kasumi_raft::RaftTransport>,
        config: kasumi_raft::RaftGroupConfig,
        admission: Arc<NodeAdmission>,
        audit: Arc<SecurityAudit>,
    ) -> anyhow::Result<Arc<Self>> {
        audit.require_admission(&admission)?;
        let group = CustodyRaftGroup::open(
            node_id,
            group,
            custody,
            transport,
            config,
            admission.snapshot_buffer_owner()?,
        )
        .await?;
        Ok(Arc::new(Self {
            group: CustodyGroup::Closed(group),
            admission,
            audit,
            work: Arc::new(WorkFence::default()),
            proposal_gate: Arc::new(tokio::sync::Mutex::new(())),
            clock: Arc::new(SystemCommandClock),
            closing: AtomicBool::new(false),
            shutdown_report: tokio::sync::Mutex::new(DrainReport::default()),
        }))
    }
    pub fn identity(&self) -> Result<(String, String)> {
        let view = self.group.view().map_err(unavailable)?;
        Ok((
            view.retirement().tenant.clone(),
            view.retirement().source_incarnation.clone(),
        ))
    }
    pub fn raft_group(&self) -> Option<&CustodyRaftGroup> {
        match &self.group {
            CustodyGroup::Closed(group) => Some(group),
            _ => None,
        }
    }
    fn check(&self, context: &RequestContext) -> Result<CustodyView> {
        if self.closing.load(Ordering::Acquire) {
            return Err(unavailable("custody closing"));
        }
        context.authorization.check_live()?;
        let view = self.group.view().map_err(unavailable)?;
        view.authorize(context)?;
        Ok(view)
    }
    pub fn response_fence(&self, context: &RequestContext) -> Result<CustodyResponseFence> {
        self.observation_fence(context, None)
    }
    fn observation_fence(
        &self,
        context: &RequestContext,
        invocation: Option<&crate::VerifiedRetirementReceipt>,
    ) -> Result<CustodyResponseFence> {
        if self.closing.load(Ordering::Acquire) {
            return Err(unavailable("custody closing"));
        }
        context.authorization.check_live()?;
        let cancellation = QueryCancellation::default();
        let mut reservation = self
            .admission
            .reserve(4 << 20, Some(cancellation.clone()))?;
        reservation.retain(4 << 20);
        let view = self.group.view().map_err(unavailable)?;
        authorize_observation(&view, context, invocation)?;
        Ok(CustodyResponseFence {
            group: self.group.clone(),
            context: context.clone(),
            policy_epoch: view.policy_epoch(),
            accepted_invocation: invocation.cloned().map(Box::new),
            admission: self.admission.clone(),
            cancellation,
            _reservation: reservation,
        })
    }
    async fn denied<T>(&self, context: &RequestContext, mut result: Result<T>) -> Result<T> {
        if let Err(error) = &mut result
            && matches!(
                error.code,
                ErrorCode::Unauthorized | ErrorCode::Forbidden | ErrorCode::Sealed
            )
            && !error.denial_audit_attempted()
        {
            let _ = self
                .audit
                .record(SecurityEvent {
                    kind: SecurityEventKind::AccessDenied,
                    principal: Some(context.principal.clone()),
                    tenant: Some(context.tenant.clone()),
                    request_id: context.request_id.clone(),
                    outcome: SecurityOutcome::Denied,
                })
                .await;
            error.mark_denial_audit_attempted();
        }
        result
    }
    pub async fn execute(
        &self,
        context: RequestContext,
        request: CustodyRequest,
    ) -> Result<CustodyReceipt> {
        let result = self.execute_inner(&context, request).await;
        self.denied(&context, result).await
    }
    /// Read an exact permanent command without proposing it again. An absence
    /// is only an observation; it never fences a previously dispatched write.
    pub async fn receipt(
        &self,
        context: &RequestContext,
        request: &CustodyRequest,
    ) -> Result<Option<CustodyReceipt>> {
        let result = async {
            let cancellation = QueryCancellation::default();
            let _work = self.work.begin(cancellation)?;
            let fence = self.response_fence(context)?;
            request.validate()?;
            // This audited observation checks the exact retirement and the
            // current custodian before and after its actual quorum barriers.
            self.retirement_status(context, &request.retirement).await?;
            let receipt = self
                .group
                .receipt(&request.command_id)
                .map_err(unavailable)?;
            let view = self.check(context)?;
            if let Some(receipt) = &receipt {
                receipt.validate()?;
                if receipt.command_id != request.command_id
                    || receipt.request_digest != request.digest()?
                {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "custody command identity differs",
                    ));
                }
                if receipt.revision > view.revision() || receipt.policy_epoch > view.policy_epoch()
                {
                    return Err(Error::new(
                        ErrorCode::Corruption,
                        "custody receipt exceeds applied state",
                    ));
                }
            }
            self.group.barrier().await.map_err(unavailable)?;
            fence.check()?;
            Ok(receipt)
        }
        .await;
        self.denied(context, result).await
    }
    async fn execute_inner(
        &self,
        context: &RequestContext,
        request: CustodyRequest,
    ) -> Result<CustodyReceipt> {
        let cancellation = QueryCancellation::default();
        let registration = self.work.begin(cancellation.clone())?;
        let reservation = self
            .admission
            .reserve(4 << 20, Some(cancellation.clone()))?;
        self.check(context)?;
        request.validate()?;
        self.group.barrier().await.map_err(unavailable)?;
        self.check(context)?;
        let work = CustodyProposalWork {
            group: self.group.clone(),
            gate: self.proposal_gate.clone(),
            clock: self.clock.clone(),
            admission: self.admission.clone(),
            cancellation,
            _reservation: reservation,
            _registration: registration,
        };
        let work = tokio::spawn(work.run(context.clone(), request));
        let bytes = tokio::time::timeout(Duration::from_secs(5), work)
            .await
            .map_err(unknown)?
            .map_err(unknown)??;
        let receipt: Result<CustodyReceipt> = serde_json::from_slice(&bytes).map_err(unknown)?;
        let receipt = receipt?;
        // A permanent rejected outcome is also an accepted command identity.
        // Self-revocation or expiry after either effect cannot imply rollback.
        let release = async {
            let fence = self.response_fence(context)?;
            self.audit
                .record(SecurityEvent {
                    kind: SecurityEventKind::Administration,
                    principal: Some(context.principal.clone()),
                    tenant: Some(context.tenant.clone()),
                    request_id: context.request_id.clone(),
                    outcome: if receipt.outcome.is_ok() {
                        SecurityOutcome::Succeeded
                    } else {
                        SecurityOutcome::Failed
                    },
                })
                .await
                .map_err(unavailable)?;
            self.group.barrier().await.map_err(unavailable)?;
            fence.check()?;
            Ok::<_, Error>(receipt)
        }
        .await;
        self.denied(context, release).await.map_err(unknown)
    }
    /// A bounded audited observation, with no API to read arbitrary municipality
    /// payload or failed identities once this exact source is permanently retired.
    pub async fn retirement_status(
        &self,
        context: &RequestContext,
        reference: &RetirementRef,
    ) -> Result<Option<RetirementStatus>> {
        self.observe_retirement(context, reference, None).await
    }
    async fn observe_retirement(
        &self,
        context: &RequestContext,
        reference: &RetirementRef,
        invocation: Option<&crate::VerifiedRetirementReceipt>,
    ) -> Result<Option<RetirementStatus>> {
        let result = async {
            let fence = self.observation_fence(context, invocation)?;
            self.group.barrier().await.map_err(unavailable)?;
            let view = self.group.view().map_err(unavailable)?;
            authorize_observation(&view, context, invocation)?;
            reference.validate()?;
            if *reference != view.request().reference()? {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "retired source identity differs",
                ));
            }
            // Observation is an audited read, not a permanent mutation ID.
            // Its audit stays in separately keyed append-only node storage.
            let receipt = view.retirement().clone();
            self.audit
                .record(SecurityEvent {
                    kind: SecurityEventKind::RetirementObserved {
                        source_incarnation: receipt.source_incarnation.clone(),
                        retirement_id: receipt.retirement_id.clone(),
                        request_digest: receipt.request_digest.clone(),
                        source_revision: receipt.revision,
                        custody_policy_epoch: view.policy_epoch(),
                    },
                    principal: Some(context.principal.clone()),
                    tenant: Some(context.tenant.clone()),
                    request_id: context.request_id.clone(),
                    outcome: SecurityOutcome::Succeeded,
                })
                .await
                .map_err(unavailable)?;
            // A stalled audit cannot release from a now-isolated old leader.
            self.group.barrier().await.map_err(unavailable)?;
            fence.check()?;
            Ok(Some(RetirementStatus {
                tenant: receipt.tenant.clone(),
                principal: receipt.principal.clone(),
                reference: reference.clone(),
                accepted_revision: receipt.revision,
                outcome: Ok(receipt),
            }))
        }
        .await;
        self.denied(context, result).await
    }
    pub async fn status(
        &self,
        context: &RequestContext,
        reference: &RetirementRef,
    ) -> Result<CustodyStatus> {
        let fence = self.response_fence(context)?;
        self.retirement_status(context, reference).await?;
        let view = self.check(context)?;
        let status = CustodyStatus {
            retirement: view.request().reference()?,
            revision: view.revision(),
            policy_epoch: view.policy_epoch(),
            administrators: view.administrators().clone(),
            limits: view.limits().clone(),
        };
        fence.check()?;
        Ok(status)
    }
    pub async fn verify_retirement_receipt(
        &self,
        context: RequestContext,
        reference: &RetirementRef,
    ) -> Result<crate::VerifiedRetirementReceipt> {
        let status = self
            .retirement_status(&context, reference)
            .await?
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "retirement absent"))?;
        let proof = crate::VerifiedRetirementReceipt::new(status.outcome?);
        self.retirement_response_fence(&context, &proof)?.check()?;
        Ok(proof)
    }
    /// Called only after the exact RetireSource submission returned success.
    /// No wire value or fresh proof read can select this transition path.
    pub(crate) async fn accepted_retirement_invocation(
        &self,
        context: &RequestContext,
        reference: &RetirementRef,
    ) -> Result<crate::VerifiedRetirementReceipt> {
        let view = self.group.view().map_err(unavailable)?;
        if *reference != view.request().reference()? {
            return Err(Error::new(
                ErrorCode::Conflict,
                "accepted retirement identity differs",
            ));
        }
        let proof = crate::VerifiedRetirementReceipt::from_accepted_invocation(
            view.retirement().clone(),
            context,
        );
        self.observe_retirement(context, reference, Some(&proof))
            .await?;
        self.retirement_response_fence(context, &proof)?.check()?;
        Ok(proof)
    }
    pub fn retirement_response_fence(
        &self,
        context: &RequestContext,
        proof: &crate::VerifiedRetirementReceipt,
    ) -> Result<CustodyResponseFence> {
        let invocation = proof.is_accepted_invocation(context).then_some(proof);
        let fence = self.observation_fence(context, invocation)?;
        if self.group.view().map_err(unavailable)?.retirement() != proof.receipt() {
            return Err(Error::new(ErrorCode::Conflict, "retirement proof differs"));
        }
        fence.check()?;
        Ok(fence)
    }
    pub async fn shutdown(&self) -> DrainResult {
        let mut report = self.shutdown_report.lock().await;
        let mut retained = None;
        self.closing.store(true, Ordering::Release);
        self.work.seal();
        if let CustodyGroup::Closed(group) = &self.group {
            if let Err(failure) = group.shutdown().await {
                report.merge(&failure);
                if failure.completion() == DrainCompletion::Retained {
                    retained = Some(failure);
                }
            }
            self.work.drain().await;
            if let Err(failure) = group.custody_store().store().shutdown().await {
                report.merge(&failure);
                if failure.completion() == DrainCompletion::Retained {
                    retained = Some(failure);
                }
            }
        } else {
            self.work.drain().await;
        }
        report.outcome(retained)
    }
}

impl Database {
    /// Warm custody shares the original ordered gate and work fence. A native
    /// runtime may then drain it and reopen only the installed custody domain.
    pub fn retired_custody(&self) -> Result<Arc<RetiredCustody>> {
        self.group.custody_view().map_err(unavailable)?;
        let clock = self
            .command_clock
            .lock()
            .map_err(|_| unavailable("clock poisoned"))?
            .clone();
        Ok(Arc::new(RetiredCustody {
            group: CustodyGroup::Serving(self.group.clone()),
            admission: self.admission().clone(),
            audit: self.security_audit.clone(),
            work: self.work.clone(),
            proposal_gate: self.proposal_gate.clone(),
            clock,
            closing: AtomicBool::new(false),
            shutdown_report: tokio::sync::Mutex::new(DrainReport::default()),
        }))
    }
}
