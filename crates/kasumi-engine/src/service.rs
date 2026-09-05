use crate::admission::{CancelOnDrop, NodeAdmission, Reservation, WorkFence, WorkRegistration};
use crate::{SecurityAudit, SecurityEvent, SecurityEventKind, SecurityOutcome, TenantEngine};
use kasumi_query::QueryCancellation;
use kasumi_raft::RaftGroup;
use kasumi_store::{BackupDestination, LeaseClock, SystemLeaseClock, TenantStore};
use kasumi_types::*;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
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
    _reservation: Reservation,
    _registration: WorkRegistration,
}

impl ProposalWork {
    async fn run(self, bytes: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        let result = self.group.write(bytes).await;
        drop(self);
        result
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

/// Every adapter calls this service; it cannot read a map without access and consistency gates.
pub struct Database {
    engine: Arc<TenantEngine>,
    group: RaftGroup,
    store: Arc<TenantStore>,
    cursors: Mutex<HashMap<String, Cursor>>,
    query_slots: Arc<tokio::sync::Semaphore>,
    clock: Arc<dyn LeaseClock>,
    admission: OnceLock<Arc<NodeAdmission>>,
    work: Arc<WorkFence>,
    security_audit: Arc<SecurityAudit>,
    audit_work: Arc<WorkFence>,
    embedded: bool,
    closing: AtomicBool,
    shutdown_gate: tokio::sync::Mutex<()>,
    seal_monitor: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

/// Extends an already authorized operation through adapter response encoding.
/// Capture before the operation, and check after constructing its final payload.
/// This is an additional release gate, not authorization to read tenant state.
pub struct ResponseFence<'a> {
    database: &'a Database,
    context: RequestContext,
    policy_epoch: u64,
    cancellation: QueryCancellation,
    _workspace: Reservation,
}

impl ResponseFence<'_> {
    /// Successful return is the adapter's authorized handoff boundary. Bytes
    /// handed to a transport are previously released plaintext; client receipt
    /// is not asserted, and transport buffering cannot recall those bytes.
    pub fn check(&self) -> Result<()> {
        self.database.access()?;
        self.database
            .admission()
            .check_release(&self.cancellation)?;
        let generation = self.database.engine.generation()?;
        if generation.state.tenant != self.context.tenant {
            return Err(Error::new(ErrorCode::Forbidden, "tenant access denied"));
        }
        if generation.state.policy_epoch != self.policy_epoch {
            return Err(Error::new(
                ErrorCode::Conflict,
                "access policy changed before encoded response release",
            ));
        }
        Ok(())
    }
}

impl Database {
    /// Network adapters must retain this gate across the authorized engine call
    /// and response serialization. It never replaces that call's RBAC checks,
    /// quorum barrier, strict audit, or operation-receipt semantics.
    pub fn response_fence(&self, context: &RequestContext) -> Result<ResponseFence<'_>> {
        self.access()?;
        let generation = self.engine.generation()?;
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
            _workspace: workspace,
        })
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
            query_slots: Arc::new(tokio::sync::Semaphore::new(4)),
            clock: Arc::new(SystemLeaseClock),
            admission: admission.map(OnceLock::from).unwrap_or_default(),
            work: Arc::new(WorkFence::default()),
            security_audit,
            audit_work: Arc::new(WorkFence::default()),
            embedded,
            closing: AtomicBool::new(false),
            shutdown_gate: tokio::sync::Mutex::new(()),
            seal_monitor: tokio::sync::Mutex::new(None),
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
        let _shutdown = self.shutdown_gate.lock().await;
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
        self.engine.seal();
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
        if self.closing.load(Ordering::Acquire) {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "database is shutting down",
            ));
        }
        if self.store.check_access().is_err() {
            self.work.seal();
            self.engine.seal();
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
        self.audit_result(&context, result).await
    }

    /// Every public request owns one denial record, including failures before a
    /// Raft proposal. This independent service store remains usable after tenant
    /// key revocation. Audit-storage failure never turns a denial into access.
    async fn audit_result<T>(&self, context: &RequestContext, mut result: Result<T>) -> Result<T> {
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

    pub async fn administer(
        &self,
        context: RequestContext,
        operation: Operation,
    ) -> Result<WriteReceipt> {
        let result = self.administer_inner(context.clone(), operation).await;
        self.audit_result(&context, result).await
    }

    async fn administer_inner(
        &self,
        context: RequestContext,
        operation: Operation,
    ) -> Result<WriteReceipt> {
        if matches!(
            operation,
            Operation::Mutate(_) | Operation::Audit(_) | Operation::MaintenanceAudit(_)
        ) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "operation is not administrative",
            ));
        }
        self.submit(context, operation).await
    }

    /// Finalize a prepared restore through consensus before it can be activated.
    /// Repeating this after a lost response is harmless and rechecks access.
    pub async fn complete_restore(&self, context: RequestContext) -> Result<()> {
        let result = self.complete_restore_inner(context.clone()).await;
        self.audit_result(&context, result).await
    }

    async fn complete_restore_inner(&self, context: RequestContext) -> Result<()> {
        self.engine.authorize(&context, None, Action::Admin)?;
        self.barrier().await?;
        self.engine.authorize(&context, None, Action::Admin)?;
        let pending = self.engine.generation()?.state.pending_restore.clone();
        if let Some(pending) = pending {
            self.maintenance_audit_inner(context, "restore", "completed", pending.source_revision)
                .await?;
        }
        self.access()
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
        self.audit_result(&context, result).await
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
        let result = self.backup_inner(context.clone(), destination).await;
        self.audit_result(&context, result).await
    }

    async fn backup_inner(
        &self,
        context: RequestContext,
        destination: &dyn BackupDestination,
    ) -> Result<uuid::Uuid> {
        self.engine.authorize(&context, None, Action::Admin)?;
        self.barrier().await?;
        self.engine.authorize(&context, None, Action::Admin)?;
        let generation = self.engine.generation()?;
        let revision = generation.state.revision;
        let bytes = serde_json::to_vec(&generation.state)
            .map_err(|_| Error::new(ErrorCode::Corruption, "backup snapshot encoding failed"))?;
        drop(generation);
        let backup = self
            .store
            .encrypt_backup(revision, &bytes)
            .map_err(|_| Error::new(ErrorCode::Unavailable, "backup encryption failed"))?;
        let id = backup.id();
        let bytes = backup.to_bytes().map_err(|_| {
            Error::new(ErrorCode::ResourceExhausted, "backup exceeds format limits")
        })?;
        self.maintenance_audit_inner(context.clone(), "backup", "started", revision)
            .await?;
        self.engine.authorize(&context, None, Action::Admin)?;
        let result = destination.put(id, bytes).await;
        self.access()?;
        self.maintenance_audit_inner(
            context,
            "backup",
            if result.is_ok() {
                "completed"
            } else {
                "failed"
            },
            revision,
        )
        .await?;
        result.map_err(|_| {
            Error::new(
                ErrorCode::UnknownOutcome,
                format!("backup destination result uncertain; inspect {id} before retry"),
            )
        })?;
        Ok(id)
    }

    async fn submit(&self, context: RequestContext, operation: Operation) -> Result<WriteReceipt> {
        self.access()?;
        if context.tenant != self.engine.generation()?.state.tenant {
            return Err(Error::new(ErrorCode::Forbidden, "tenant access denied"));
        }
        // Authorization repeats during ordered apply, so queued operations cannot bypass policy changes.
        match &operation {
            Operation::Mutate(batch) => {
                for mutation in &batch.operations {
                    self.engine
                        .authorize(&context, Some(mutation.target().0), Action::Write)?;
                }
            }
            Operation::Audit(event) => {
                let action = if event.action == "receipt" {
                    Action::Write
                } else {
                    Action::Read
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
        let command_budget = generation
            .state
            .limits
            .max_batch_bytes
            .saturating_add(64 << 10)
            .saturating_mul(3)
            .saturating_add(if needs_writer { 15_000_000 } else { 0 })
            as u64;
        drop(generation);
        let reservation = self.admission().reserve(command_budget, None)?;
        let command = Command {
            context,
            timestamp_ms: now_ms()?,
            operation,
        };
        let bytes = serde_json::to_vec(&command)
            .map_err(|_| Error::new(ErrorCode::InvalidArgument, "command encoding failed"))?;
        if bytes.len()
            > self
                .engine
                .generation()?
                .state
                .limits
                .max_batch_bytes
                .saturating_add(64 << 10)
        {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "command too large",
            ));
        }
        let registration = self.work.begin(QueryCancellation::default())?;
        let proposal = tokio::spawn(
            ProposalWork {
                group: self.group.clone(),
                _reservation: reservation,
                _registration: registration,
            }
            .run(bytes),
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
        self.access()?;
        serde_json::from_slice::<Result<WriteReceipt>>(&result)
            .map_err(|_| Error::new(ErrorCode::Corruption, "invalid state machine response"))?
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
        let document = generation
            .state
            .collections
            .get(collection)
            .and_then(|c| c.documents.get(id))
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "document not found"))?;
        // Both shared and owned variants prepare their result before auditing and
        // the final access release. Owned callers keep the original API contract.
        let document = select(document);
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
        let action = if kind == "receipt" {
            Action::Write
        } else {
            Action::Read
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
                generation: generation.clone(),
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .map_err(|_| Error::new(ErrorCode::Unavailable, "system clock precedes epoch"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::AdmissionConfig;
    use std::{future::Future, task::Poll};

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
