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
    admission: Arc<NodeAdmission>,
    cancellation: QueryCancellation,
    _reservation: Reservation,
}
impl CustodyResponseFence {
    pub fn check(&self) -> Result<()> {
        self.context.authorization.check_live()?;
        self.admission.check_release(&self.cancellation)?;
        let view = self.group.view().map_err(unavailable)?;
        view.authorize(&self.context)?;
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

impl RetiredCustody {
    pub async fn open_replicated(
        custody: Arc<CustodyStore>,
        node_id: u64,
        group: String,
        transport: Arc<dyn kasumi_raft::RaftTransport>,
        config: kasumi_raft::Config,
        admission: Arc<NodeAdmission>,
        audit: Arc<SecurityAudit>,
    ) -> anyhow::Result<Arc<Self>> {
        let group = CustodyRaftGroup::open(node_id, group, custody, transport, config).await?;
        Ok(Arc::new(Self {
            group: CustodyGroup::Closed(group),
            admission,
            audit,
            work: Arc::new(WorkFence::default()),
            proposal_gate: Arc::new(tokio::sync::Mutex::new(())),
            clock: Arc::new(SystemCommandClock),
            closing: AtomicBool::new(false),
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
        let cancellation = QueryCancellation::default();
        let mut reservation = self
            .admission
            .reserve(4 << 20, Some(cancellation.clone()))?;
        reservation.retain(4 << 20);
        let view = self.check(context)?;
        Ok(CustodyResponseFence {
            group: self.group.clone(),
            context: context.clone(),
            policy_epoch: view.policy_epoch(),
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
        let result = async {
            let fence = self.response_fence(context)?;
            self.group.barrier().await.map_err(unavailable)?;
            let view = self.check(context)?;
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
    pub fn retirement_response_fence(
        &self,
        context: &RequestContext,
        proof: &crate::VerifiedRetirementReceipt,
    ) -> Result<CustodyResponseFence> {
        let fence = self.response_fence(context)?;
        if self.check(context)?.retirement() != proof.receipt() {
            return Err(Error::new(ErrorCode::Conflict, "retirement proof differs"));
        }
        fence.check()?;
        Ok(fence)
    }
    pub async fn shutdown(&self) -> anyhow::Result<()> {
        self.closing.store(true, Ordering::Release);
        self.work.seal();
        if let CustodyGroup::Closed(group) = &self.group {
            let result = group.shutdown().await;
            self.work.drain().await;
            group.custody_store().store().shutdown().await;
            result
        } else {
            self.work.drain().await;
            Ok(())
        }
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
        }))
    }
}
