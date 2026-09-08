use crate::admission::{CancelOnDrop, NodeAdmission, Reservation, WorkFence, WorkRegistration};
use crate::{SecurityAudit, SecurityEvent, SecurityEventKind, SecurityOutcome, TenantEngine};
use kasumi_clock::{LeaseClock, SystemLeaseClock};
use kasumi_query::QueryCancellation;
use kasumi_raft::RaftGroup;
use kasumi_store::{BackupDestination, TenantStore};
use kasumi_types::*;
use sha2::{Digest, Sha256};
#[path = "backup_checkpoints.rs"]
mod backup_checkpoints;
#[path = "change_feed.rs"]
mod change_feed;
#[path = "custody_service.rs"]
mod custody_service;
#[path = "full_backup.rs"]
mod full_backup;
#[path = "history_export.rs"]
mod history_export;
#[path = "history_reads.rs"]
mod history_reads;
pub use custody_service::{CustodyResponseFence, RetiredCustody};
#[path = "lifecycle_service.rs"]
pub(crate) mod lifecycle_service;
#[path = "restore_lineage_service.rs"]
mod restore_lineage_service;
#[path = "retirement_service.rs"]
mod retirement_service;
pub use retirement_service::RetirementResponseFence;
#[path = "schema_service.rs"]
mod schema_service;
#[path = "snapshot_leases.rs"]
mod snapshot_leases;
#[path = "target_activation_service.rs"]
pub(crate) mod target_activation_service;
#[path = "target_inspection_service.rs"]
pub(crate) mod target_inspection_service;
#[path = "target_service.rs"]
pub(crate) mod target_service;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

struct Cursor {
    principal: String,
    query_digest: String,
    incarnation: String,
    policy_epoch: u64,
    created: Duration,
    ttl: Duration,
    response: Arc<QueryResponse>,
    reservation: Arc<Reservation>,
    offset: usize,
    bytes: usize,
    term: u64,
}

struct ProposalWork {
    // Drop storage ownership before notifying shutdown that this job drained.
    group: RaftGroup,
    admission_gate: Arc<tokio::sync::Mutex<()>>,
    clock: Arc<dyn CommandClock>,
    source_engine: Arc<TenantEngine>,
    admission: Arc<NodeAdmission>,
    _reservation: Reservation,
    _registration: Arc<WorkRegistration>,
}

impl ProposalWork {
    async fn run(mut self, mut command: Command, max_bytes: usize) -> anyhow::Result<Vec<u8>> {
        // The background proposal owns this gate; caller timeout/cancellation
        // cannot let later commands overtake an unresolved write. Time is
        // sampled only after the previous write has finished.
        let _guard = self.admission_gate.clone().lock_owned().await;
        if let Err(error) = command.context.authorization.check_live() {
            return Ok(serde_json::to_vec(&Err::<WriteReceipt, _>(error))?);
        }
        if let Err(error) = self
            .source_engine
            .check_operation_access(&command.operation)
        {
            return Ok(serde_json::to_vec(&Err::<WriteReceipt, _>(error))?);
        }
        if self.source_engine.generation()?.state.retired {
            return Ok(serde_json::to_vec(&Err::<WriteReceipt, _>(Error::new(
                ErrorCode::Sealed,
                "application commands are frozen after retirement",
            )))?);
        }
        if let Operation::ActivateSchema(request) = &command.operation {
            let engine = &self.source_engine;
            let admitted = (|| -> Result<()> {
                let generation = engine.generation()?;
                crate::state::schema::authorize(&generation.state, &command.context, request)?;
                self._reservation
                    .reserve_additional(generation.snapshot_bytes()?.saturating_mul(2) as u64)
            })();
            if let Err(error) = admitted {
                // No proposal was made and no activation identity was accepted.
                return Ok(serde_json::to_vec(&Err::<WriteReceipt, _>(error))?);
            }
        }
        if let Operation::RetireSource(prepared) = &mut command.operation {
            let engine = &self.source_engine;
            let generation = engine.generation()?;
            let admitted = crate::state::retirement::admit(
                &generation.state,
                &command.context,
                &prepared.request,
            );
            match admitted {
                Err(error) => return Ok(serde_json::to_vec(&Err::<WriteReceipt, _>(error))?),
                Ok(Some(_)) => {}
                Ok(None) => {
                    let workspace = self.admission.reserve(
                        crate::retirement_closure::workspace_bytes(&generation.state)?,
                        None,
                    )?;
                    let registration = self._registration.clone();
                    let credential = command.context.authorization.clone();
                    struct Output {
                        result: Result<RetirementObservation>,
                        _workspace: Reservation,
                        _registration: Arc<WorkRegistration>,
                    }
                    let output = tokio::task::spawn_blocking(move || {
                        let result = crate::retirement_closure::digest(&generation.state, || {
                            credential.check_live()
                        })
                        .map(|closure_digest| RetirementObservation {
                            revision: generation.state.revision,
                            closure_digest,
                        });
                        Output {
                            result,
                            _workspace: workspace,
                            _registration: registration,
                        }
                    })
                    .await?;
                    match output.result {
                        Ok(observed) => prepared.observation = Some(observed),
                        Err(error) => {
                            return Ok(serde_json::to_vec(&Err::<WriteReceipt, _>(error))?);
                        }
                    }
                }
            }
        }
        command.timestamp_ms = self.clock.now_ms()?;
        if let Err(error) = command.context.authorization.check_live().and_then(|()| {
            command
                .context
                .authorization
                .check_admitted_at(command.timestamp_ms)
        }) {
            return Ok(serde_json::to_vec(&Err::<WriteReceipt, _>(error))?);
        }
        let bytes = serde_json::to_vec(&command)?;
        anyhow::ensure!(
            bytes.len() <= max_bytes,
            "command exceeds proposal byte budget"
        );
        if matches!(&command.operation, Operation::RetireSource(prepared) if prepared.observation.is_some())
        {
            let engine = &self.source_engine;
            let seed = kasumi_raft::RetirementLogSeed::prepare(
                &command,
                engine.retirement_replay_state(&command)?,
            )?;
            if let Err(error) = seed.reserve_success_capacity() {
                return Ok(serde_json::to_vec(&Err::<WriteReceipt, _>(error))?);
            }
            self.group.write_retirement(bytes, seed).await
        } else {
            self.group.write(bytes).await
        }
    }
}

trait CommandClock: Send + Sync {
    fn now_ms(&self) -> Result<u64>;
}
struct SystemCommandClock;
impl CommandClock for SystemCommandClock {
    fn now_ms(&self) -> Result<u64> {
        now_ms()
    }
}

struct DenialWork {
    audit: Arc<SecurityAudit>,
    event: SecurityEvent,
    // A canceled caller cannot release shutdown until the durable writer drops.
    _registration: WorkRegistration,
}
impl DenialWork {
    fn run(self) -> anyhow::Result<()> {
        let result = self.audit.record_sync(self.event.clone());
        drop(self);
        result
    }
}

struct QueryWork {
    generation: Arc<crate::Generation>,
    request: QueryRequest,
    cancellation: QueryCancellation,
    _permit: tokio::sync::OwnedSemaphorePermit,
    reservation: Option<Reservation>,
    // Registration must outlive every captured input, including on unwinding.
    registration: Arc<WorkRegistration>,
}

struct QueryOutput {
    response: Result<QueryResponse>,
    reservation: Reservation,
    // A completed task can retain its output after its caller disconnects.
    // Shutdown must also wait for that output and its reservation to drop.
    _registration: Arc<WorkRegistration>,
}

impl QueryWork {
    fn run(mut self) -> QueryOutput {
        let response = self.generation.indexes.execute_with_cancellation(
            &self.generation.state.collections,
            &self.request,
            &self.generation.state.limits,
            &self.cancellation,
        );
        let output = QueryOutput {
            response,
            reservation: self.reservation.take().expect("query workspace reserved"),
            _registration: self.registration.clone(),
        };
        drop(self);
        output
    }
}

struct SnapshotWork {
    generation: Arc<crate::Generation>,
    request: ReadSnapshotRequest,
    cancellation: QueryCancellation,
    _permit: tokio::sync::OwnedSemaphorePermit,
    reservation: Reservation,
    registration: Arc<WorkRegistration>,
}
struct SnapshotOutput {
    response: Result<SnapshotReadResponse>,
    reservation: Reservation,
    _registration: Arc<WorkRegistration>,
}
impl SnapshotWork {
    fn run(self) -> SnapshotOutput {
        let response = self.evaluate();
        SnapshotOutput {
            response,
            reservation: self.reservation,
            _registration: self.registration,
        }
    }

    fn evaluate(&self) -> Result<SnapshotReadResponse> {
        let state = &self.generation.state;
        let mut result = SnapshotReadResponse {
            revision: state.revision,
            incarnation: state.incarnation.clone(),
            policy_epoch: state.policy_epoch,
            schema_epoch: state.schema_epoch,
            collection_epochs: BTreeMap::new(),
            documents: Vec::new(),
            queries: Vec::new(),
        };
        for key in &self.request.documents {
            self.cancellation.check()?;
            let collection = &state.collections[&key.collection];
            let document = collection.documents.get(&key.id);
            // Check output capacity before cloning a potentially large body.
            if crate::accounting::encoded_len(&result)?
                .saturating_add(document.map_or(Ok(0), crate::accounting::encoded_len)?)
                > state.limits.max_result_bytes
            {
                return Err(Error::new(
                    ErrorCode::ResourceExhausted,
                    "snapshot result exceeds byte limit",
                ));
            }
            result.documents.push(SnapshotDocument {
                key: key.clone(),
                document: document.map(|document| document.as_ref().clone()),
            });
        }
        for query in &self.request.queries {
            self.cancellation.check()?;
            let mut response = self.generation.indexes.execute_with_cancellation(
                &state.collections,
                query,
                &state.limits,
                &self.cancellation,
            )?;
            if response.rows.len() > query.limit {
                return Err(Error::new(
                    ErrorCode::ResourceExhausted,
                    "snapshot query exceeds complete row limit",
                ));
            }
            response.revision = state.revision;
            result.collection_epochs.insert(
                query.collection.clone(),
                state.collections[&query.collection].data_epoch,
            );
            result.queries.push(response);
            if crate::accounting::encoded_len(&result)? > state.limits.max_result_bytes {
                return Err(Error::new(
                    ErrorCode::ResourceExhausted,
                    "snapshot result exceeds byte limit",
                ));
            }
        }
        if crate::accounting::encoded_len(&result)? > state.limits.max_result_bytes {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "snapshot result exceeds byte limit",
            ));
        }
        self.cancellation.check()?;
        Ok(result)
    }
}

/// Every adapter calls this service; it cannot read a map without access and consistency gates.
pub struct Database {
    engine: Arc<TenantEngine>,
    group: RaftGroup,
    store: Arc<TenantStore>,
    cursors: Mutex<HashMap<String, Cursor>>,
    snapshot_leases: Mutex<HashMap<String, Arc<snapshot_leases::RetainedSnapshot>>>,
    archive_destinations: Mutex<BTreeMap<String, Arc<dyn BackupDestination>>>,
    query_slots: Arc<tokio::sync::Semaphore>,
    clock: Arc<dyn LeaseClock>,
    admission: OnceLock<Arc<NodeAdmission>>,
    work: Arc<WorkFence>,
    security_audit: Arc<SecurityAudit>,
    audit_work: Arc<WorkFence>,
    embedded: bool,
    closing: AtomicBool,
    custody_detached: AtomicBool,
    shutdown_gate: tokio::sync::Mutex<()>,
    seal_monitor: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    proposal_gate: Arc<tokio::sync::Mutex<()>>,
    command_clock: Mutex<Arc<dyn CommandClock>>,
}

/// Extends an already authorized operation through adapter response encoding.
/// Capture before the operation, and check after constructing its final payload.
/// This is an additional release gate, not authorization to read tenant state.
pub struct ResponseFence<'a> {
    database: &'a Database,
    context: RequestContext,
    policy_epoch: u64,
    cancellation: QueryCancellation,
    read_admission: Option<(Vec<ReadAssertion>, Reservation)>,
    schema_admission: Option<(Vec<ReadAssertion>, Reservation)>,
    _workspace: Reservation,
}

fn staged_stop_acknowledgement(_error: Error) -> Error {
    Error::new(
        ErrorCode::UnknownOutcome,
        "staged resolution response was fenced; resolve the original transaction with fresh authority",
    )
}

impl ResponseFence<'_> {
    /// Successful return is the adapter's authorized handoff boundary. Bytes
    /// handed to a transport are previously released plaintext; client receipt
    /// is not asserted, and transport buffering cannot recall those bytes.
    pub fn check(&self) -> Result<()> {
        self.context.authorization.check_live()?;
        self.database.access()?;
        self.database
            .admission()
            .check_release(&self.cancellation)?;
        let generation = self.database.engine.generation()?;
        crate::state::authorize_resource(&generation.state, &self.context)?;
        if generation.state.tenant != self.context.tenant {
            return Err(Error::new(ErrorCode::Forbidden, "tenant access denied"));
        }
        if generation.state.policy_epoch != self.policy_epoch {
            return Err(Error::new(
                ErrorCode::Conflict,
                "access policy changed before encoded response release",
            ));
        }
        if let Some((assertions, _workspace)) = &self.read_admission {
            let now = self
                .database
                .command_clock
                .lock()
                .map_err(|_| Error::new(ErrorCode::Unavailable, "command clock unavailable"))?
                .now_ms()?;
            crate::state::staging::validate_admission(
                &generation.state,
                &self.context,
                assertions,
                now,
            )?;
        }
        if let Some((assertions, _workspace)) = &self.schema_admission {
            let now = self
                .database
                .command_clock
                .lock()
                .map_err(|_| Error::new(ErrorCode::Unavailable, "command clock unavailable"))?
                .now_ms()?;
            crate::state::schema::validate_admission(
                &generation.state,
                &self.context,
                assertions,
                now,
            )?;
        }
        Ok(())
    }
}

impl Database {
    /// Network adapters must retain this gate across the authorized engine call
    /// and response serialization. It never replaces that call's RBAC checks,
    /// quorum barrier, strict audit, or operation-receipt semantics.
    pub fn response_fence(&self, context: &RequestContext) -> Result<ResponseFence<'_>> {
        context.authorization.check_live()?;
        self.access()?;
        let generation = self.engine.generation()?;
        crate::state::authorize_resource(&generation.state, context)?;
        if generation.state.tenant != context.tenant {
            return Err(Error::new(ErrorCode::Forbidden, "tenant access denied"));
        }
        // Retain a bounded response workspace through adapter serialization.
        // The engine operation owns its separate execution slot, so release
        // this reservation's temporary slot while keeping its byte charge.
        let bytes = generation
            .state
            .limits
            .max_result_bytes
            .max(generation.state.limits.max_document_bytes)
            .max(320 << 10)
            .saturating_add(64 << 10)
            .saturating_mul(3) as u64;
        let cancellation = QueryCancellation::default();
        let mut workspace = self
            .admission()
            .reserve(bytes, Some(cancellation.clone()))?;
        workspace.retain(bytes);
        Ok(ResponseFence {
            database: self,
            context: context.clone(),
            policy_epoch: generation.state.policy_epoch,
            cancellation,
            read_admission: None,
            schema_admission: None,
            _workspace: workspace,
        })
    }

    /// Retains exactly this stop attempt's authority dependencies through final
    /// native response encoding. Assertions never become permanent stop identity.
    pub fn staged_stop_response_fence(
        &self,
        context: &RequestContext,
        request: &StopStagedTransaction,
    ) -> Result<ResponseFence<'_>> {
        let mut fence = self.response_fence(context)?;
        let generation = self.engine.generation()?;
        crate::state::staging::authorize_stop(&generation.state, context, request)?;
        if request.admission.len() > generation.state.limits.atomic.max_read_assertions {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "staged stop admission exceeds assertion limit",
            ));
        }
        let (_, bytes) = staged_digest(request)?;
        if bytes > generation.state.limits.max_batch_bytes {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "staged stop request too large",
            ));
        }
        let charge = bytes
            .saturating_mul(3)
            .saturating_add(request.admission.len().saturating_mul(128))
            as u64;
        let mut workspace = self
            .admission()
            .reserve(charge, Some(fence.cancellation.clone()))?;
        workspace.retain(charge);
        fence.read_admission = Some((request.admission.clone(), workspace));
        fence.check()?;
        Ok(fence)
    }

    /// Bootstrap paths with internal operations (such as restore auditing) must
    /// install the server's shared governor before submitting those operations.
    pub fn new_with_admission(
        engine: Arc<TenantEngine>,
        group: RaftGroup,
        store: Arc<TenantStore>,
        admission: Arc<NodeAdmission>,
        security_audit: Arc<SecurityAudit>,
    ) -> Arc<Self> {
        Self::new_inner(engine, group, store, Some(admission), security_audit)
    }

    pub fn new(
        engine: Arc<TenantEngine>,
        group: RaftGroup,
        store: Arc<TenantStore>,
        security_audit: Arc<SecurityAudit>,
    ) -> Arc<Self> {
        Self::new_inner(engine, group, store, None, security_audit)
    }

    fn new_inner(
        engine: Arc<TenantEngine>,
        group: RaftGroup,
        store: Arc<TenantStore>,
        admission: Option<Arc<NodeAdmission>>,
        security_audit: Arc<SecurityAudit>,
    ) -> Arc<Self> {
        // This authenticated durable bootstrap binding is immutable for the
        // lifetime of the database. A one-member view is never a local-mode signal.
        // Missing/manual bindings retain the quorum contract.
        let embedded = store
            .get("engine.deployment", b"mode")
            .ok()
            .flatten()
            .is_some_and(|mode| mode == b"local-v1");
        let database = Arc::new(Self {
            engine,
            group,
            store,
            cursors: Mutex::new(HashMap::new()),
            snapshot_leases: Mutex::new(HashMap::new()),
            archive_destinations: Mutex::new(BTreeMap::new()),
            query_slots: Arc::new(tokio::sync::Semaphore::new(4)),
            clock: Arc::new(SystemLeaseClock),
            admission: admission.map(OnceLock::from).unwrap_or_default(),
            work: Arc::new(WorkFence::default()),
            security_audit,
            audit_work: Arc::new(WorkFence::default()),
            embedded,
            closing: AtomicBool::new(false),
            custody_detached: AtomicBool::new(false),
            shutdown_gate: tokio::sync::Mutex::new(()),
            seal_monitor: tokio::sync::Mutex::new(None),
            proposal_gate: Arc::new(tokio::sync::Mutex::new(())),
            command_clock: Mutex::new(Arc::new(SystemCommandClock)),
        });
        database.spawn_seal_monitor();
        database
    }

    /// Install one node-wide governor before the first admitted operation. Every
    /// tenant and the control group on a server must share the same instance.
    pub fn install_admission(&self, admission: Arc<NodeAdmission>) -> Result<()> {
        self.admission.set(admission).map_err(|_| {
            Error::new(
                ErrorCode::Conflict,
                "admission already configured or in use",
            )
        })
    }

    fn admission(&self) -> &Arc<NodeAdmission> {
        self.admission.get_or_init(NodeAdmission::process_default)
    }

    pub fn engine(&self) -> &Arc<TenantEngine> {
        &self.engine
    }
    pub fn raft_group(&self) -> &RaftGroup {
        &self.group
    }
    /// Stop admission, drain background work, and release owned keys and state.
    /// Retained application handles still own this database/store; drop them
    /// before reopening the same node file. A canceled shutdown can be awaited again.
    pub async fn shutdown(&self) -> anyhow::Result<()> {
        self.shutdown_inner(false).await
    }

    /// Trusted installed lifecycle transition. The source is already permanently
    /// retired; this neither authorizes a proof nor reopens an application route.
    /// Retained old Database handles cannot later seal the new custody owner.
    pub async fn detach_retired_custody(&self) -> anyhow::Result<Arc<kasumi_store::CustodyStore>> {
        self.shutdown_inner(true).await?;
        Ok(self.group.storage_domains().custody().clone())
    }

    async fn shutdown_inner(&self, detach_custody: bool) -> anyhow::Result<()> {
        let _shutdown = self.shutdown_gate.lock().await;
        if detach_custody && !self.custody_detached.load(Ordering::Acquire) {
            let control =
                kasumi_raft::ControlLog::installed(self.group.storage_domains().custody().clone())?
                    .ok_or_else(|| anyhow::anyhow!("installed custody identity absent"))?;
            anyhow::ensure!(
                control.recover_retired()?,
                "source is not permanently retired"
            );
            self.custody_detached.store(true, Ordering::Release);
        }
        self.closing.store(true, Ordering::Release);
        self.work.seal();
        self.audit_work.seal();
        {
            let mut monitor = self.seal_monitor.lock().await;
            if let Some(task) = monitor.as_mut() {
                task.abort();
                let _ = task.await;
                monitor.take();
            }
        }
        let result = self.group.shutdown().await;
        self.work.drain().await;
        self.audit_work.drain().await;
        self.store.shutdown().await;
        if !self.custody_detached.load(Ordering::Acquire) {
            self.group
                .storage_domains()
                .custody()
                .store()
                .shutdown()
                .await;
        }
        self.engine.seal();
        self.snapshot_leases
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
        self.cursors
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
        result
    }
    pub(crate) fn store(&self) -> &Arc<TenantStore> {
        &self.store
    }

    fn access(&self) -> Result<()> {
        self.materialization_access()?;
        let generation = self.engine.generation()?;
        if generation
            .state
            .target_lifecycle
            .get(&generation.state.incarnation)
            .is_some_and(|target| target.activation.is_none())
        {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "native target activation is incomplete",
            ));
        }
        drop(generation);
        self.store.storage_access().check_serving().map_err(|_| {
            Error::new(
                ErrorCode::Forbidden,
                "restore preparation cannot serve ordinary tenant operations",
            )
        })
    }
    pub fn check_serving(&self) -> Result<()> {
        self.access()
    }
    fn materialization_access(&self) -> Result<()> {
        if self.closing.load(Ordering::Acquire) {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "database is shutting down",
            ));
        }
        if self.store.check_access().is_err() {
            self.work.seal();
            self.engine.seal();
            self.snapshot_leases
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clear();
            self.cursors
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clear();
            return Err(Error::new(
                ErrorCode::Sealed,
                "tenant key authorization expired; recovery required",
            ));
        }
        self.group
            .check_access()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "tenant replica requires recovery"))?;
        self.engine.generation()?;
        Ok(())
    }

    /// TenantStore refreshes keys. Its watch signal plus independent expiry checks
    /// evict idle resident state even if no client makes another request.
    fn spawn_seal_monitor(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        let mut notices = self.store.seal_notifications();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = notices.changed() => { if changed.is_err() { break; } },
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {},
                }
                let Some(db) = weak.upgrade() else { break };
                let _ = db.access();
                if db.engine.generation().is_err() {
                    db.work.seal();
                }
                let pressured = db.admission.get().is_some_and(|node| {
                    let status = node.snapshot();
                    status.pressured || !status.sample_usable
                });
                let now = db.clock.now();
                db.cursors
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .retain(|_, c| !pressured && now.saturating_sub(c.created) < c.ttl);
                db.snapshot_leases
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .retain(|_, lease| {
                        lease.retain(now, pressured)
                            && db
                                .engine
                                .generation()
                                .is_ok_and(|generation| lease.refresh(&generation))
                    });
                if db.engine.generation().is_err() {
                    break;
                }
            }
        });
        *self
            .seal_monitor
            .try_lock()
            .expect("seal monitor is registered before database publication") = Some(task);
    }

    async fn barrier(&self) -> Result<()> {
        self.access()?;
        if self.embedded {
            return Ok(());
        }
        tokio::time::timeout(Duration::from_secs(5), self.group.linearizable_barrier())
            .await
            .map_err(|_| Error::new(ErrorCode::Unavailable, "read quorum deadline exceeded"))?
            .map_err(|_| Error::new(ErrorCode::Unavailable, "read quorum unavailable"))?;
        self.access()
    }

    pub async fn mutate(
        &self,
        context: RequestContext,
        batch: MutationBatch,
    ) -> Result<WriteReceipt> {
        let result = self.submit(context.clone(), Operation::Mutate(batch)).await;
        self.audit_write_result(&context, result).await
    }

    pub async fn begin_staged_transaction(
        &self,
        context: RequestContext,
        request: BeginStagedTransaction,
    ) -> Result<WriteReceipt> {
        let result = self
            .submit(context.clone(), Operation::BeginStaged(request))
            .await;
        self.audit_write_result(&context, result).await
    }

    pub async fn append_staged_chunk(
        &self,
        context: RequestContext,
        request: AppendStagedChunk,
    ) -> Result<WriteReceipt> {
        let result = self
            .submit(context.clone(), Operation::AppendStaged(request))
            .await;
        self.audit_write_result(&context, result).await
    }

    pub async fn finalize_staged_transaction(
        &self,
        context: RequestContext,
        reference: StagedTransactionRef,
    ) -> Result<WriteReceipt> {
        let result = self
            .submit(context.clone(), Operation::FinalizeStaged(reference))
            .await;
        self.audit_write_result(&context, result).await
    }

    pub async fn stop_staged_transaction(
        &self,
        context: RequestContext,
        request: StopStagedTransaction,
    ) -> Result<StagedTransactionStatus> {
        let result = self.stop_staged_transaction_inner(&context, request).await;
        self.audit_write_result(&context, result).await
    }

    async fn stop_staged_transaction_inner(
        &self,
        context: &RequestContext,
        request: StopStagedTransaction,
    ) -> Result<StagedTransactionStatus> {
        let fence = self.staged_stop_response_fence(context, &request)?;
        let reference = request.original.reference()?;
        self.submit(context.clone(), Operation::StopStaged(request))
            .await?;
        // From here, failure cannot establish that no stop/original outcome was
        // accepted. The permanent identity is the recovery path after uncertainty.
        let result = async {
            let status = self.staged_transaction_status(context, &reference).await?;
            fence.check()?;
            Ok(status)
        }
        .await;
        result.map_err(staged_stop_acknowledgement)
    }

    pub async fn staged_transaction_status(
        &self,
        context: &RequestContext,
        reference: &StagedTransactionRef,
    ) -> Result<StagedTransactionStatus> {
        let result = self
            .staged_transaction_status_inner(context, reference)
            .await;
        self.audit_result(context, result).await
    }

    async fn staged_transaction_status_inner(
        &self,
        context: &RequestContext,
        reference: &StagedTransactionRef,
    ) -> Result<StagedTransactionStatus> {
        context.authorization.check_live()?;
        self.access()?;
        crate::state::staging::lookup(&self.engine.generation()?.state, context, reference)?;
        let mut reservation = self.admission().reserve(1 << 20, None)?;
        self.barrier().await?;
        let generation = self.engine.generation()?;
        let stage = crate::state::staging::lookup(&generation.state, context, reference)?;
        let status = stage.status();
        let policy_epoch = generation.state.policy_epoch;
        let revision = generation.state.revision;
        let mut collections = BTreeMap::new();
        for collection in &stage.manifest.read_collections {
            collections.insert(collection.clone(), "read");
        }
        for collection in &stage.manifest.write_collections {
            collections.insert(collection.clone(), "receipt");
        }
        let release: Vec<_> = collections
            .into_iter()
            .map(|(collection, kind)| {
                let strict = generation.state.policy.strict_read_audit
                    || generation
                        .state
                        .collections
                        .get(&collection)
                        .is_some_and(|collection| collection.definition.strict_read_audit);
                (collection, kind, strict)
            })
            .collect();
        drop(generation);
        reservation.retain_workspace();
        for (collection, kind, strict) in release {
            self.release_event(
                context,
                Some(&collection),
                revision,
                strict,
                policy_epoch,
                kind,
            )
            .await?;
        }
        self.access()?;
        crate::state::staging::lookup(&self.engine.generation()?.state, context, reference)?;
        Ok(status)
    }

    /// Every public request owns one denial record, including failures before a
    /// Raft proposal. This independent service store remains usable after tenant
    /// key revocation. Audit-storage failure never turns a denial into access.
    async fn audit_result<T>(&self, context: &RequestContext, mut result: Result<T>) -> Result<T> {
        if result.is_ok() {
            result = context.authorization.check_live().and(result);
        }
        if let Err(error) = &mut result {
            if error.denial_audit_attempted() {
                return result;
            }
            let kind = match error.code {
                ErrorCode::Forbidden | ErrorCode::Unauthorized => {
                    Some(SecurityEventKind::AccessDenied)
                }
                ErrorCode::Sealed => Some(SecurityEventKind::TenantSealed),
                _ => None,
            };
            if let Some(kind) = kind
                && let Ok(registration) = self.audit_work.begin(QueryCancellation::default())
            {
                let work = DenialWork {
                    audit: self.security_audit.clone(),
                    event: SecurityEvent {
                        kind,
                        principal: Some(context.principal.clone()),
                        tenant: Some(context.tenant.clone()),
                        request_id: context.request_id.clone(),
                        outcome: SecurityOutcome::Denied,
                    },
                    _registration: registration,
                };
                let _ = tokio::task::spawn_blocking(move || work.run()).await;
                error.mark_denial_audit_attempted();
            }
        }
        result
    }

    // Only an already successful effect may become uncertain at handoff. A
    // pre-proposal rejection must remain a definite rejection and accept no ID.
    async fn audit_write_result<T>(
        &self,
        context: &RequestContext,
        result: Result<T>,
    ) -> Result<T> {
        let committed = result.is_ok();
        let result = self.audit_result(context, result).await;
        if committed {
            result.map_err(credential_acknowledgement)
        } else {
            result
        }
    }

    pub async fn administer(
        &self,
        context: RequestContext,
        operation: Operation,
    ) -> Result<WriteReceipt> {
        let result = self.administer_inner(context.clone(), operation).await;
        self.audit_write_result(&context, result).await
    }

    async fn administer_inner(
        &self,
        context: RequestContext,
        operation: Operation,
    ) -> Result<WriteReceipt> {
        if matches!(
            operation,
            Operation::Mutate(_)
                | Operation::Audit(_)
                | Operation::MaintenanceAudit(_)
                | Operation::BeginStaged(_)
                | Operation::AppendStaged(_)
                | Operation::FinalizeStaged(_)
                | Operation::StopStaged(_)
                | Operation::PublishHistoryArchive(_)
                | Operation::RetireSource(_)
                | Operation::AbortRetirement(_)
        ) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "operation is not administrative",
            ));
        }
        let lifecycle = matches!(operation, Operation::LifecycleControl(_));
        let receipt = self.submit(context.clone(), operation).await?;
        if lifecycle {
            self.lifecycle_write_release(&context)?;
        }
        Ok(receipt)
    }

    /// Finalize a prepared restore through consensus before it can be activated.
    /// Repeating this after a lost response is harmless and rechecks access.
    pub async fn complete_restore(&self, context: RequestContext) -> Result<()> {
        let result = self.complete_restore_inner(context.clone()).await;
        self.audit_write_result(&context, result).await
    }

    async fn complete_restore_inner(&self, context: RequestContext) -> Result<()> {
        self.materialization_access()?;
        self.engine.authorize(&context, None, Action::Admin)?;
        self.group.linearizable_barrier().await.map_err(|_| {
            Error::new(
                ErrorCode::Unavailable,
                "prepared restore quorum unavailable",
            )
        })?;
        self.materialization_access()?;
        self.engine.authorize(&context, None, Action::Admin)?;
        let pending = self.engine.generation()?.state.pending_restore.clone();
        if let Some(pending) = pending {
            self.maintenance_audit_inner(context, "restore", "completed", pending.source_revision)
                .await?;
        }
        self.materialization_access()
    }

    pub async fn maintenance_audit(
        &self,
        context: RequestContext,
        action: &str,
        outcome: &str,
        revision: u64,
    ) -> Result<WriteReceipt> {
        let result = self
            .maintenance_audit_inner(context.clone(), action, outcome, revision)
            .await;
        self.audit_write_result(&context, result).await
    }

    async fn maintenance_audit_inner(
        &self,
        context: RequestContext,
        action: &str,
        outcome: &str,
        revision: u64,
    ) -> Result<WriteReceipt> {
        let event = AuditEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            principal: context.principal.clone(),
            action: action.into(),
            request_id: context.request_id.clone(),
            timestamp_ms: now_ms()?,
            data_revision: Some(revision),
            outcome: outcome.into(),
            collection: None,
        };
        self.submit(context, Operation::MaintenanceAudit(event))
            .await
    }

    pub async fn backup(
        &self,
        context: RequestContext,
        destination: &dyn BackupDestination,
    ) -> Result<uuid::Uuid> {
        self.backup_checkpoint(context, destination)
            .await
            .map(|proof| proof.backup_id())
    }

    async fn submit(&self, context: RequestContext, operation: Operation) -> Result<WriteReceipt> {
        context.authorization.check_live()?;
        self.materialization_access()?;
        self.engine.check_operation_access(&operation)?;
        let restore_completion = matches!(&operation, Operation::MaintenanceAudit(event) if event.action == "restore" && event.outcome == "completed");
        if context.tenant != self.engine.generation()?.state.tenant {
            return Err(Error::new(ErrorCode::Forbidden, "tenant access denied"));
        }
        // Authorization repeats during ordered apply, so queued operations cannot bypass policy changes.
        match &operation {
            Operation::ActivateSchema(request) => crate::state::schema::authorize(
                &self.engine.generation()?.state,
                &context,
                request,
            )?,
            Operation::BeginStaged(request) => crate::state::staging::authorize_manifest(
                &self.engine.generation()?.state,
                &context,
                &request.manifest,
            )?,
            Operation::AppendStaged(request) => {
                crate::state::staging::lookup(
                    &self.engine.generation()?.state,
                    &context,
                    &request.transaction,
                )?;
            }
            Operation::StopStaged(request) => crate::state::staging::authorize_stop(
                &self.engine.generation()?.state,
                &context,
                request,
            )?,
            Operation::FinalizeStaged(reference) => {
                crate::state::staging::lookup(
                    &self.engine.generation()?.state,
                    &context,
                    reference,
                )?;
            }
            Operation::Mutate(batch) => {
                for mutation in &batch.operations {
                    self.engine
                        .authorize(&context, Some(mutation.target().0), Action::Write)?;
                }
            }
            Operation::Audit(event) => {
                let action = match event.action.as_str() {
                    "receipt" => Action::Write,
                    "schema_activation_status" | "schema_read" => Action::Admin,
                    _ => Action::Read,
                };
                if event.collection.is_none() {
                    self.engine.authorize_discovery(&context, action, None)?;
                } else {
                    self.engine
                        .authorize(&context, event.collection.as_deref(), action)?;
                }
            }
            Operation::CreateCollection(c) | Operation::ReplaceCollection(c) => self
                .engine
                .authorize(&context, Some(&c.name), Action::Admin)?,
            _ => self.engine.authorize(&context, None, Action::Admin)?,
        }
        let generation = self.engine.generation()?;
        let has_text = |definition: &CollectionDefinition| {
            definition.indexes.iter().any(|index| index.text.is_some())
        };
        let needs_writer = match &operation {
            Operation::ActivateSchema(request) => request
                .changes
                .iter()
                .any(|change| has_text(change.definition())),
            Operation::FinalizeStaged(reference) => {
                let stage = crate::state::staging::lookup(&generation.state, &context, reference)?;
                stage.manifest.write_collections.iter().any(|name| {
                    generation
                        .state
                        .collections
                        .get(name)
                        .is_some_and(|collection| has_text(&collection.definition))
                })
            }
            Operation::Mutate(batch) => batch.operations.iter().any(|mutation| {
                generation
                    .state
                    .collections
                    .get(mutation.target().0)
                    .is_some_and(|collection| has_text(&collection.definition))
            }),
            Operation::CreateCollection(definition) | Operation::ReplaceCollection(definition) => {
                has_text(definition)
            }
            _ => false,
        };
        // Cover serialization/replication workspace plus the configured Tantivy
        // writer buffer when applicable. Persistent staged index nodes still feed
        // RSS; this is an admission estimate, not exact allocator accounting.
        let staged_workspace = if matches!(operation, Operation::PublishHistoryArchive(_)) {
            MAX_ARCHIVE_SOURCE_BYTES.saturating_mul(3)
        } else if let Operation::FinalizeStaged(reference) = &operation {
            let stage = crate::state::staging::lookup(&generation.state, &context, reference)?;
            if stage.is_active() {
                stage
                    .manifest
                    .encoded_chunk_bytes
                    .saturating_mul(3)
                    .saturating_add(
                        stage
                            .manifest
                            .operation_count
                            .saturating_add(stage.manifest.read_assertion_count)
                            .saturating_mul(512),
                    )
            } else {
                0
            }
        } else {
            0
        };
        let max_command_payload = if matches!(operation, Operation::ActivateSchema(_)) {
            MAX_SCHEMA_CHANGESET_BYTES
        } else {
            generation.state.limits.max_batch_bytes
        };
        let command_budget = max_command_payload
            .saturating_add(64 << 10)
            .saturating_mul(3)
            .saturating_add(staged_workspace)
            .saturating_add(if matches!(operation, Operation::RetireSource(_)) {
                kasumi_raft::MAX_RETIREMENT_SEED_BYTES.saturating_mul(4)
            } else {
                0
            })
            .saturating_add(if needs_writer { 15_000_000 } else { 0 })
            as u64;
        drop(generation);
        let reservation = self.admission().reserve(command_budget, None)?;
        let release_context = context.clone();
        let command = Command {
            context,
            // Budget the longest possible stamp before the worker replaces it
            // with trusted admission time. Time must not expand a queued input
            // beyond a limit that preflight already accepted.
            timestamp_ms: u64::MAX,
            operation,
        };
        let bytes = serde_json::to_vec(&command)
            .map_err(|_| Error::new(ErrorCode::InvalidArgument, "command encoding failed"))?;
        let max_bytes = max_command_payload.saturating_add(64 << 10);
        if bytes.len() > max_bytes {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "command too large",
            ));
        }
        let registration = self.work.begin(QueryCancellation::default())?;
        let proposal = tokio::spawn(
            ProposalWork {
                source_engine: self.engine.clone(),
                admission: self.admission().clone(),
                group: self.group.clone(),
                admission_gate: self.proposal_gate.clone(),
                clock: self
                    .command_clock
                    .lock()
                    .map_err(|_| Error::new(ErrorCode::Unavailable, "command clock unavailable"))?
                    .clone(),
                _reservation: reservation,
                _registration: Arc::new(registration),
            }
            .run(command, max_bytes),
        );
        let result = tokio::time::timeout(Duration::from_secs(10), proposal)
            .await
            .map_err(|_| {
                Error::new(
                    ErrorCode::UnknownOutcome,
                    "write deadline exceeded; resolve or retry with the same idempotency key",
                )
            })?
            .map_err(|_| {
                Error::new(
                    ErrorCode::UnknownOutcome,
                    "write result unavailable; resolve or retry with the same idempotency key",
                )
            })?
            .map_err(|_| {
                Error::new(
                    ErrorCode::UnknownOutcome,
                    "write task failed; resolve or retry with the same idempotency key",
                )
            })?;
        if restore_completion {
            let outcome =
                serde_json::from_slice::<Result<WriteReceipt>>(&result).map_err(|_| {
                    Error::new(
                        ErrorCode::UnknownOutcome,
                        "restore completion response unavailable",
                    )
                })?;
            if outcome.is_ok() {
                self.materialization_access()
                    .map_err(staged_stop_acknowledgement)?;
            }
            self.audit_write_result(&release_context, outcome).await
        } else {
            self.release_submitted_response(&release_context, &result)
                .await
        }
    }

    async fn release_submitted_response(
        &self,
        context: &RequestContext,
        response: &[u8],
    ) -> Result<WriteReceipt> {
        // An ordered rejection remains definite. Once the state machine accepted
        // an effect, loss of access cannot be reported as if it rejected that
        // effect; only fresh authorized identity recovery can settle the caller.
        let result = serde_json::from_slice::<Result<WriteReceipt>>(response)
            .map_err(|_| Error::new(ErrorCode::UnknownOutcome, "state machine response could not be decoded; resolve the original operation identity"))?;
        if result.is_ok() {
            self.access().map_err(|_| Error::new(
                ErrorCode::UnknownOutcome,
                "access ended after effect acceptance; resolve the original operation with fresh authority",
            ))?;
        }
        self.audit_write_result(context, result).await
    }

    pub async fn get(
        &self,
        context: &RequestContext,
        collection: &str,
        id: &str,
    ) -> Result<Document> {
        let result = self
            .read_document(context, collection, id, |document| {
                document.as_ref().clone()
            })
            .await;
        self.audit_result(context, result).await
    }

    /// Return an immutable document handle without cloning its JSON body. The
    /// same authorization, consistency, key lease and read-audit gates apply.
    /// A retained handle is previously released plaintext owned by the trusted
    /// embedding application; revocation cannot recall it.
    pub async fn get_shared(
        &self,
        context: &RequestContext,
        collection: &str,
        id: &str,
    ) -> Result<Arc<Document>> {
        let result = self
            .read_document(context, collection, id, Arc::clone)
            .await;
        self.audit_result(context, result).await
    }

    /// Read all requested documents and complete bounded queries from exactly
    /// one authorized generation. Returned assertions can fence a later batch.
    pub async fn read_snapshot(
        &self,
        context: &RequestContext,
        request: ReadSnapshotRequest,
    ) -> Result<SnapshotReadResponse> {
        let result = self.read_snapshot_inner(context, request).await;
        self.audit_result(context, result).await
    }

    async fn read_snapshot_inner(
        &self,
        context: &RequestContext,
        request: ReadSnapshotRequest,
    ) -> Result<SnapshotReadResponse> {
        self.access()?;
        if request.documents.len() > 256
            || request.queries.len() > 16
            || (request.documents.is_empty() && request.queries.is_empty())
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "snapshot request outside bounds",
            ));
        }
        let mut keys = BTreeSet::new();
        let mut collections = BTreeSet::new();
        for key in &request.documents {
            validate_name(&key.collection)?;
            validate_name(&key.id)?;
            if !keys.insert(key) {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "duplicate snapshot document",
                ));
            }
            collections.insert(key.collection.clone());
        }
        for query in &request.queries {
            validate_name(&query.collection)?;
            if query.cursor.is_some() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "snapshot reads do not accept cursors",
                ));
            }
            collections.insert(query.collection.clone());
        }
        for collection in &collections {
            self.engine
                .authorize(context, Some(collection), Action::Read)?;
        }
        let cancellation = QueryCancellation::default();
        let _cancel_on_drop = CancelOnDrop(cancellation.clone());
        let registration = Arc::new(self.work.begin(cancellation.clone())?);
        let workspace = snapshot_workspace(&self.engine.generation()?.state.limits, &request);
        let reservation = self
            .admission()
            .reserve(workspace, Some(cancellation.clone()))?;
        tokio::select! {
            result = self.barrier() => result?,
            _ = cancelled(&cancellation) => return Err(cancelled_error()),
        }
        let generation = self.engine.generation()?;
        let state = &generation.state;
        if snapshot_workspace(&state.limits, &request) > workspace {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "snapshot limits changed during admission",
            ));
        }
        let mut release_collections = BTreeMap::new();
        for collection in &collections {
            self.engine.authorize_release(
                context,
                Some(collection),
                Action::Read,
                state.policy_epoch,
            )?;
            let definition = &state
                .collections
                .get(collection)
                .ok_or_else(|| Error::new(ErrorCode::NotFound, "snapshot collection not found"))?
                .definition;
            release_collections.insert(
                collection.clone(),
                state.policy.strict_read_audit || definition.strict_read_audit,
            );
        }
        for query in &request.queries {
            if query.limit == 0 || query.limit > state.limits.max_page_size {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "snapshot query row limit outside bounds",
                ));
            }
        }
        let permit = self.query_slots.clone().try_acquire_owned().map_err(|_| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "query concurrency limit reached",
            )
        })?;
        let work = SnapshotWork {
            generation: self
                .hydrate_history(
                    generation.clone(),
                    &request.documents,
                    &request.queries,
                    &cancellation,
                )
                .await?,
            request,
            cancellation: cancellation.clone(),
            _permit: permit,
            reservation,
            registration,
        };
        let worker = tokio::task::spawn_blocking(move || work.run());
        let SnapshotOutput {
            response,
            mut reservation,
            _registration,
        } = tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(5), worker) => result
                .map_err(|_| Error::new(ErrorCode::ResourceExhausted, "snapshot deadline exceeded"))?
                .map_err(|_| Error::new(ErrorCode::Unavailable, "snapshot worker failed"))?,
            _ = cancelled(&cancellation) => return Err(cancelled_error()),
        };
        let response = response?;
        reservation.retain(state.limits.max_result_bytes.saturating_mul(3) as u64);
        drop(generation);
        for (collection, strict) in &release_collections {
            self.release(
                context,
                collection,
                response.revision,
                *strict,
                response.policy_epoch,
            )
            .await?;
        }
        // Recheck every collection after the last asynchronous audit. A policy
        // change during an earlier release must not leak the assembled result.
        self.access()?;
        self.admission().check_release(&cancellation)?;
        for collection in release_collections.keys() {
            self.engine.authorize_release(
                context,
                Some(collection),
                Action::Read,
                response.policy_epoch,
            )?;
        }
        Ok(response)
    }

    async fn read_document<T>(
        &self,
        context: &RequestContext,
        collection: &str,
        id: &str,
        select: impl FnOnce(&Arc<Document>) -> T,
    ) -> Result<T> {
        self.access()?;
        self.engine
            .authorize(context, Some(collection), Action::Read)?;
        let mut reservation = self.admission().reserve(
            self.engine
                .generation()?
                .state
                .limits
                .max_document_bytes
                .saturating_mul(3) as u64,
            None,
        )?;
        self.barrier().await?;
        self.engine
            .authorize(context, Some(collection), Action::Read)?;
        let generation = self.engine.generation()?;
        let cancellation = QueryCancellation::default();
        let _cancel_on_drop = CancelOnDrop(cancellation.clone());
        let _registration = self.work.begin(cancellation.clone())?;
        let mut history = history_reads::HistoryReadCache::new();
        let document = self
            .history_document(&generation, collection, id, &cancellation, &mut history)
            .await?
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "document not found"))?;
        // Both shared and owned variants prepare their result before auditing and
        // the final access release. Owned callers keep the original API contract.
        let document = select(&document);
        let revision = generation.state.revision;
        let policy_epoch = generation.state.policy_epoch;
        let strict = generation.state.policy.strict_read_audit
            || generation.state.collections[collection]
                .definition
                .strict_read_audit;
        drop(generation);
        reservation.retain_workspace();
        self.release(context, collection, revision, strict, policy_epoch)
            .await?;
        Ok(document)
    }

    async fn release(
        &self,
        context: &RequestContext,
        collection: &str,
        revision: u64,
        strict: bool,
        policy_epoch: u64,
    ) -> Result<()> {
        self.release_event(
            context,
            Some(collection),
            revision,
            strict,
            policy_epoch,
            "read",
        )
        .await
    }

    async fn release_event(
        &self,
        context: &RequestContext,
        collection: Option<&str>,
        revision: u64,
        strict: bool,
        policy_epoch: u64,
        kind: &str,
    ) -> Result<()> {
        if strict {
            let event = AuditEvent {
                event_id: uuid::Uuid::new_v4().to_string(),
                principal: context.principal.clone(),
                action: kind.into(),
                request_id: context.request_id.clone(),
                timestamp_ms: now_ms()?,
                data_revision: Some(revision),
                outcome: "authorized_release".into(),
                collection: collection.map(Into::into),
            };
            self.submit(context.clone(), Operation::Audit(event))
                .await
                .map_err(|error| {
                    if matches!(error.code, ErrorCode::Forbidden | ErrorCode::Sealed) {
                        error
                    } else {
                        Error::new(
                            ErrorCode::AuditUnavailable,
                            "required read audit could not be confirmed durable",
                        )
                    }
                })?;
        }
        self.access()?;
        let action = match kind {
            "receipt" => Action::Write,
            "schema_activation_status" | "schema_read" => Action::Admin,
            _ => Action::Read,
        };
        if collection.is_none() {
            self.engine
                .authorize_discovery(context, action, Some(policy_epoch))
        } else {
            self.engine
                .authorize_release(context, collection, action, policy_epoch)
        }
    }

    pub async fn collections(&self, context: &RequestContext) -> Result<Vec<CollectionDefinition>> {
        let result = self.collections_inner(context).await;
        self.audit_result(context, result).await
    }

    async fn collections_inner(
        &self,
        context: &RequestContext,
    ) -> Result<Vec<CollectionDefinition>> {
        self.access()?;
        self.engine
            .authorize_discovery(context, Action::Read, None)?;
        let mut reservation = self.admission().reserve(
            self.engine
                .generation()?
                .state
                .limits
                .max_schema_bytes
                .saturating_add(64 << 10)
                .saturating_mul(3) as u64,
            None,
        )?;
        self.barrier().await?;
        let generation = self.engine.generation()?;
        if context.tenant != generation.state.tenant {
            return Err(Error::new(ErrorCode::Forbidden, "tenant access denied"));
        }
        let definitions: Vec<_> = generation
            .state
            .collections
            .values()
            .filter(|c| {
                generation
                    .state
                    .policy
                    .allows(context, Some(&c.definition.name), Action::Read)
            })
            .map(|c| c.definition.clone())
            .collect();
        if crate::accounting::encoded_len(&definitions)? > generation.state.limits.max_result_bytes
        {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "collection catalog exceeds result byte limit",
            ));
        }
        let epoch = generation.state.policy_epoch;
        let revision = generation.state.revision;
        let strict = generation.state.policy.strict_read_audit;
        drop(generation);
        reservation.retain_workspace();
        if definitions.is_empty() {
            self.release_event(context, None, revision, strict, epoch, "discovery")
                .await?;
        }
        for definition in &definitions {
            self.release(
                context,
                &definition.name,
                revision,
                strict || definition.strict_read_audit,
                epoch,
            )
            .await?;
        }
        self.access()?;
        Ok(definitions)
    }

    pub async fn operation_receipt(
        &self,
        context: &RequestContext,
        idempotency_key: &str,
    ) -> Result<Option<Result<WriteReceipt>>> {
        let result = self.operation_receipt_inner(context, idempotency_key).await;
        self.audit_result(context, result).await
    }

    async fn operation_receipt_inner(
        &self,
        context: &RequestContext,
        idempotency_key: &str,
    ) -> Result<Option<Result<WriteReceipt>>> {
        self.access()?;
        self.engine
            .authorize_discovery(context, Action::Write, None)?;
        let mut reservation = self.admission().reserve(
            self.engine
                .generation()?
                .state
                .limits
                .max_batch_operations
                .saturating_mul(1024)
                .saturating_add(64 << 10)
                .saturating_mul(3) as u64,
            None,
        )?;
        self.barrier().await?;
        let generation = self.engine.generation()?;
        if context.tenant != generation.state.tenant {
            return Err(Error::new(ErrorCode::Forbidden, "tenant access denied"));
        }
        let identity = serde_json::to_vec(&(&context.principal, idempotency_key))
            .map_err(|_| Error::new(ErrorCode::InvalidArgument, "receipt identity invalid"))?;
        let key = hex::encode(Sha256::digest(identity));
        let now = now_ms()?;
        let receipt = generation
            .state
            .receipts
            .get(&key)
            .filter(|r| r.expires_at_ms > now)
            .cloned();
        let epoch = generation.state.policy_epoch;
        let revision = generation.state.revision;
        let strict = generation.state.policy.strict_read_audit;
        reservation.retain_workspace();
        if let Some(receipt) = &receipt {
            for collection in &receipt.collections {
                let strict = strict
                    || generation
                        .state
                        .collections
                        .get(collection)
                        .is_some_and(|c| c.definition.strict_read_audit);
                self.release_event(
                    context,
                    Some(collection),
                    revision,
                    strict,
                    epoch,
                    "receipt",
                )
                .await?;
            }
        } else {
            self.release_event(context, None, revision, strict, epoch, "receipt")
                .await?;
        }
        self.access()?;
        Ok(receipt.map(|r| r.outcome))
    }

    pub async fn query(
        &self,
        context: &RequestContext,
        request: QueryRequest,
    ) -> Result<QueryResponse> {
        let result = self.query_inner(context, request).await;
        self.audit_result(context, result).await
    }

    async fn query_inner(
        &self,
        context: &RequestContext,
        request: QueryRequest,
    ) -> Result<QueryResponse> {
        self.access()?;
        self.engine
            .authorize(context, Some(&request.collection), Action::Read)?;
        let cancellation = QueryCancellation::default();
        let _cancel_on_drop = CancelOnDrop(cancellation.clone());
        let registration = Arc::new(self.work.begin(cancellation.clone())?);
        let workspace = query_workspace(&self.engine.generation()?.state.limits, &request);
        let mut pending_reservation = Some(
            self.admission()
                .reserve(workspace, Some(cancellation.clone()))?,
        );
        let mut normalized = request.clone();
        normalized.cursor = None;
        let digest = hex::encode(Sha256::digest(
            serde_json::to_vec(&normalized)
                .map_err(|_| Error::new(ErrorCode::InvalidArgument, "query encoding failed"))?,
        ));
        // Continuations retain old data but must establish current authority on a serving leader.
        tokio::select! {
            result = self.barrier() => result?,
            _ = cancelled(&cancellation) => return Err(cancelled_error()),
        }
        self.engine
            .authorize(context, Some(&request.collection), Action::Read)?;
        let generation = self.engine.generation()?;
        let state = &generation.state;
        if query_workspace(&state.limits, &request) > workspace {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "query limits changed during admission; retry",
            ));
        }
        let term = self.group.raft().metrics().borrow().current_term;
        if request.limit == 0 || request.limit > state.limits.max_page_size {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "page limit outside allowed range",
            ));
        }
        let strict = state.policy.strict_read_audit
            || state
                .collections
                .get(&request.collection)
                .is_some_and(|c| c.definition.strict_read_audit);
        let policy_epoch = state.policy_epoch;
        let incarnation = state.incarnation.clone();
        let ttl = Duration::from_millis(state.limits.cursor_ttl_ms);
        let mut _continuation_admission = None;
        let (full, reservation, offset, created) = if let Some(token) = &request.cursor {
            _continuation_admission = pending_reservation.take();
            let cursors = self
                .cursors
                .lock()
                .map_err(|_| Error::new(ErrorCode::Unavailable, "cursor storage unavailable"))?;
            let cursor = cursors
                .get(token)
                .ok_or_else(|| Error::new(ErrorCode::CursorExpired, "cursor unavailable"))?;
            if self.clock.now().saturating_sub(cursor.created) >= cursor.ttl
                || cursor.principal != context.principal
                || cursor.query_digest != digest
                || cursor.incarnation != incarnation
                || cursor.policy_epoch != policy_epoch
                || cursor.term != term
            {
                return Err(Error::new(
                    ErrorCode::CursorExpired,
                    "cursor expired or its access policy changed",
                ));
            }
            (
                cursor.response.clone(),
                cursor.reservation.clone(),
                cursor.offset,
                cursor.created,
            )
        } else {
            let reservation = pending_reservation
                .take()
                .expect("query admission reservation");
            let permit = self.query_slots.clone().try_acquire_owned().map_err(|_| {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    "query concurrency limit reached",
                )
            })?;
            let work = QueryWork {
                generation: self
                    .hydrate_history(
                        generation.clone(),
                        &[],
                        std::slice::from_ref(&request),
                        &cancellation,
                    )
                    .await?,
                request: request.clone(),
                cancellation: cancellation.clone(),
                _permit: permit,
                reservation: Some(reservation),
                registration: registration.clone(),
            };
            let worker = tokio::task::spawn_blocking(move || work.run());
            let QueryOutput {
                response,
                mut reservation,
                _registration,
            } = tokio::select! {
                result = tokio::time::timeout(Duration::from_secs(5), worker) => result
                    .map_err(|_| Error::new(ErrorCode::ResourceExhausted, "query deadline exceeded"))?
                    .map_err(|_| Error::new(ErrorCode::Unavailable, "query worker failed"))?,
                _ = cancelled(&cancellation) => return Err(cancelled_error()),
            };
            let mut response = response?;
            response.revision = state.revision;
            // Keep the full output allowance (not only serialized bytes) while a
            // cursor owns this result; release the worker operation slot now.
            reservation.retain(state.limits.max_result_bytes.saturating_mul(3) as u64);
            (
                Arc::new(response),
                Arc::new(reservation),
                0,
                self.clock.now(),
            )
        };
        let max_cursors = state.limits.max_cursors;
        let max_cursor_bytes = state.limits.max_cursor_bytes;
        let page_end = offset.saturating_add(request.limit).min(full.rows.len());
        let mut page = QueryResponse {
            revision: full.revision,
            rows: full.rows[offset..page_end].to_vec(),
            aggregates: full.aggregates.clone(),
            cursor: None,
        };
        drop(generation);
        tokio::select! {
            result = self.release(context, &request.collection, full.revision, strict, policy_epoch) => result?,
            _ = cancelled(&cancellation) => return Err(cancelled_error()),
        }
        cancellation.check()?;
        if self.engine.generation()?.state.policy_epoch != policy_epoch {
            return Err(Error::new(
                ErrorCode::CursorExpired,
                "query policy changed before release",
            ));
        }
        let mut cursors = self
            .cursors
            .lock()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "cursor storage unavailable"))?;
        cursors.retain(|_, c| {
            self.clock.now().saturating_sub(c.created) < c.ttl
                && c.policy_epoch == policy_epoch
                && c.term == term
        });
        if page_end < full.rows.len() {
            let bytes = serde_json::to_vec(&*full)
                .map_err(|_| {
                    Error::new(
                        ErrorCode::ResourceExhausted,
                        "query response cannot be retained",
                    )
                })?
                .len();
            let replaced = request.cursor.as_ref().and_then(|token| cursors.get(token));
            let retained_bytes: usize = cursors.values().map(|cursor| cursor.bytes).sum();
            if cursors
                .len()
                .saturating_sub(usize::from(replaced.is_some()))
                >= max_cursors
                || retained_bytes
                    .saturating_sub(replaced.map_or(0, |c| c.bytes))
                    .saturating_add(bytes)
                    > max_cursor_bytes
            {
                return Err(Error::new(
                    ErrorCode::ResourceExhausted,
                    "cursor memory budget exhausted",
                ));
            }
            let token = uuid::Uuid::new_v4().to_string();
            cursors.insert(
                token.clone(),
                Cursor {
                    principal: context.principal.clone(),
                    query_digest: digest,
                    incarnation,
                    policy_epoch,
                    created,
                    ttl,
                    response: full,
                    reservation,
                    offset: page_end,
                    bytes,
                    term,
                },
            );
            page.cursor = Some(token);
        }
        if let Some(token) = request.cursor {
            cursors.remove(&token);
        }
        drop(cursors);
        self.access()?;
        self.admission().check_release(&cancellation)?;
        self.work.release(&cancellation, || {
            self.store.check_access().map_err(|_| {
                Error::new(
                    ErrorCode::Sealed,
                    "tenant key access expired before query release",
                )
            })?;
            self.group.check_access().map_err(|_| {
                Error::new(
                    ErrorCode::Unavailable,
                    "replica unavailable before query release",
                )
            })?;
            self.engine.authorize_release(
                context,
                Some(&request.collection),
                Action::Read,
                policy_epoch,
            )?;
            Ok(page)
        })
    }
}

pub fn now_ms() -> Result<u64> {
    kasumi_clock::EpochClock::system()
        .and_then(|clock| clock.now_ms())
        .map_err(|_| Error::new(ErrorCode::Unavailable, "trusted clock unavailable"))
}

async fn cancelled(token: &QueryCancellation) {
    // Polling avoids tying the standalone synchronous evaluator to an async
    // runtime. The worker observes cancellation directly at its loop checkpoints.
    while !token.is_cancelled() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
fn cancelled_error() -> Error {
    Error::new(ErrorCode::ResourceExhausted, "query work cancelled")
}

fn query_workspace(limits: &Limits, request: &QueryRequest) -> u64 {
    if request.cursor.is_some() {
        return limits.max_result_bytes.saturating_mul(2) as u64;
    }
    // Full output, page copy, candidate IDs/sort keys, group accumulators.
    limits
        .max_result_bytes
        .saturating_mul(3)
        .saturating_add(
            limits
                .max_query_candidates
                .saturating_mul(128usize.saturating_add(request.sort.len().saturating_mul(64))),
        )
        .saturating_add(
            limits.max_query_groups.saturating_mul(
                128usize.saturating_add(request.aggregates.len().saturating_mul(96)),
            ),
        ) as u64
}

fn snapshot_workspace(limits: &Limits, request: &ReadSnapshotRequest) -> u64 {
    // Queries run sequentially: reserve one maximum query workspace, plus the
    // retained combined result and one document clone through final release.
    request
        .queries
        .iter()
        .map(|query| query_workspace(limits, query))
        .max()
        .unwrap_or(0)
        .saturating_add(limits.max_result_bytes.saturating_mul(3) as u64)
        .saturating_add(limits.max_document_bytes.saturating_mul(3) as u64)
}

fn credential_acknowledgement(error: Error) -> Error {
    if error.code == ErrorCode::Unauthorized {
        Error::new(
            ErrorCode::UnknownOutcome,
            "credential expired after effect admission; use a fresh credential to resolve the original operation identity",
        )
    } else {
        error
    }
}

#[cfg(test)]
mod tests {
    include!("service_staging_tests.rs");
    include!("service_staged_stop_tests.rs");
    include!("service_schema_tests.rs");
    include!("service_credential_tests.rs");
    include!("service_serving_tests.rs");
    include!("service_retirement_tests.rs");
    include!("service_custody_tests.rs");
    use super::*;
    use crate::admission::AdmissionConfig;
    use kasumi_store::{NodeStore, test_utils::LocalKeyProvider};
    use serde_json::json;
    use std::{future::Future, task::Poll};

    struct ControlledCommandClock(std::sync::atomic::AtomicU64);
    impl CommandClock for ControlledCommandClock {
        fn now_ms(&self) -> Result<u64> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }

    #[tokio::test]
    async fn queued_deadlines_use_admission_time_and_survive_caller_cancellation() {
        let directory = tempfile::tempdir().unwrap();
        let node = NodeStore::open(directory.path().join("node.redb")).unwrap();
        let audit_store = TenantStore::open_fixture(
            node.clone(),
            crate::SECURITY_TENANT.into(),
            Arc::new(LocalKeyProvider::new([0xA7; 32])),
        )
        .await
        .unwrap();
        let audit = SecurityAudit::open(audit_store, 100_000).unwrap();
        let context = RequestContext {
            authorization: kasumi_types::RequestAuthorization::service_identity(),
            tenant: "deadline".into(),
            principal: "owner".into(),
            scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin, Action::Audit]),
            request_id: "deadline-test".into(),
        };
        let store = TenantStore::open_fixture(
            node,
            context.tenant.clone(),
            Arc::new(LocalKeyProvider::new([0xB7; 32])),
        )
        .await
        .unwrap();
        let db = crate::open_local(
            kasumi_store::test_utils::with_custody(
                store,
                std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
            )
            .await
            .unwrap(),
            Policy {
                grants: vec![Grant {
                    principal: context.principal.clone(),
                    collection: None,
                    actions: context.scopes.clone(),
                }],
                strict_read_audit: false,
            },
            Limits::default(),
            audit,
        )
        .await
        .unwrap();
        db.administer(
            context.clone(),
            Operation::CreateCollection(CollectionDefinition {
                retention_class: kasumi_types::CollectionRetentionClass::Operational,
                name: "docs".into(),
                schema: json!({"type":"object"}),
                indexes: vec![],
                strict_read_audit: false,
                write_mode: CollectionWriteMode::Mutable,
            }),
        )
        .await
        .unwrap();
        let base = now_ms().unwrap();
        let clock = Arc::new(ControlledCommandClock(std::sync::atomic::AtomicU64::new(
            base,
        )));
        *db.command_clock.lock().unwrap() = clock.clone();
        let batch = |id: &str, not_after_ms| MutationBatch {
            idempotency_key: id.into(),
            read_set: vec![ReadAssertion::Before { not_after_ms }],
            operations: vec![Mutation::Put {
                collection: "docs".into(),
                id: id.into(),
                body: json!({"value":1}),
                expected: Precondition::Absent,
            }],
        };

        let gate = db.proposal_gate.lock().await;
        let mut queued = Box::pin(db.mutate(context.clone(), batch("queued", base + 10)));
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(queued.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        clock.0.store(base + 11, Ordering::SeqCst);
        drop(gate);
        assert_eq!(queued.await.unwrap_err().code, ErrorCode::Conflict);
        assert_eq!(
            db.get(&context, "docs", "queued").await.unwrap_err().code,
            ErrorCode::NotFound
        );

        let gate = db.proposal_gate.lock().await;
        let mut canceled = Box::pin(db.mutate(context.clone(), batch("canceled", base + 20)));
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(canceled.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        drop(canceled);
        clock.0.store(base + 21, Ordering::SeqCst);
        drop(gate);
        db.work.drain().await;
        assert_eq!(
            db.operation_receipt(&context, "canceled")
                .await
                .unwrap()
                .unwrap()
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        assert_eq!(
            db.get(&context, "docs", "canceled").await.unwrap_err().code,
            ErrorCode::NotFound
        );

        // Inclusive boundary succeeds. An exact retry resolves the durable
        // result even once its authorization deadline has subsequently passed.
        let accepted = batch("accepted", base + 21);
        let receipt = db.mutate(context.clone(), accepted.clone()).await.unwrap();
        let data_epoch = db.engine.generation().unwrap().state.collections["docs"].data_epoch;
        clock.0.store(base + 22, Ordering::SeqCst);
        assert_eq!(db.mutate(context.clone(), accepted).await.unwrap(), receipt);
        assert_eq!(
            db.engine.generation().unwrap().state.collections["docs"].data_epoch,
            data_epoch
        );
        db.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn query_shutdown_drains_abandoned_output_and_captured_generation() {
        let engine = TenantEngine::new(
            "tenant".into(),
            "incarnation".into(),
            Policy {
                grants: vec![Grant {
                    principal: "owner".into(),
                    collection: None,
                    actions: std::collections::BTreeSet::from([Action::Admin]),
                }],
                strict_read_audit: false,
            },
            Limits::default(),
        )
        .unwrap();
        let generation = engine.generation().unwrap();
        let weak = Arc::downgrade(&generation);
        drop(engine);
        let fence = Arc::new(WorkFence::default());
        let cancellation = QueryCancellation::default();
        let registration = Arc::new(fence.begin(cancellation.clone()).unwrap());
        let admission = NodeAdmission::new(AdmissionConfig::default()).unwrap();
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let work = QueryWork {
            generation,
            request: serde_json::from_value(serde_json::json!({
                "collection": "docs", "allow_scan": true, "limit": 1
            }))
            .unwrap(),
            cancellation,
            _permit: slots.clone().try_acquire_owned().unwrap(),
            reservation: Some(admission.reserve(1024, None).unwrap()),
            registration,
        };
        fence.seal();
        let output = tokio::task::spawn_blocking(move || work.run())
            .await
            .unwrap();
        assert!(output.response.is_err());
        assert!(weak.upgrade().is_none());
        assert_eq!(slots.available_permits(), 1);
        assert_eq!(admission.snapshot().reserved_bytes, 1024);
        let mut draining = Box::pin(fence.drain());
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(draining.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        // Represents a disconnected caller abandoning a completed task output.
        drop(output);
        draining.await;
        assert_eq!(admission.snapshot().reserved_bytes, 0);
    }
}
