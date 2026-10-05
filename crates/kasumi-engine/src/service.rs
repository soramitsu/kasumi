use crate::admission::{
    CancelOnDrop, NodeAdmission, ProposalBudget, Reservation, WorkFence, WorkRegistration,
};
use crate::output::{AdmittedOutput, OUTPUT_CHARGE_BYTES};
use crate::{SecurityAudit, SecurityEvent, SecurityEventKind, SecurityOutcome, TenantEngine};
#[path = "audit_maintenance_service.rs"]
mod audit_maintenance_service;
#[path = "backup_producer_jobs.rs"]
mod backup_producer_jobs;
#[path = "database_construction.rs"]
pub(crate) mod construction;
#[path = "control_administration.rs"]
pub(crate) mod control_administration;
#[path = "control_topology_service.rs"]
pub(crate) mod control_topology_service;
#[cfg(test)]
#[path = "database_worker_outcome_tests.rs"]
mod database_worker_outcome_tests;
#[path = "database_workers.rs"]
mod database_workers;
#[path = "proposal_input.rs"]
pub(crate) mod proposal_input;
#[path = "proposal_jobs.rs"]
mod proposal_jobs;
#[path = "query_seek.rs"]
mod query_seek;
#[cfg(test)]
#[path = "service_allocation_tests.rs"]
mod service_allocation_tests;
use kasumi_clock::{LeaseClock, SystemLeaseClock};
use kasumi_query::{DocumentSource, QueryCancellation, QueryMemory, ReadFailure, Record};
use kasumi_raft::RaftGroup;
use kasumi_store::{BackupDestination, TenantStorageSet, TenantStore};
use kasumi_types::drain::{DrainCompletion, DrainFailure, DrainReport, DrainResult};
use kasumi_types::*;
use sha2::{Digest, Sha256};
#[path = "backup_checkpoints.rs"]
mod backup_checkpoints;
#[path = "backup_sessions.rs"]
mod backup_sessions;
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
#[path = "point_read.rs"]
mod point_read;
pub use custody_service::{CustodyResponseFence, RetiredCustody};
#[path = "lifecycle_service.rs"]
pub(crate) mod lifecycle_service;
#[path = "recovery_service.rs"]
pub(crate) mod recovery_service;
#[path = "restore_lineage_service.rs"]
mod restore_lineage_service;
#[path = "retirement_service.rs"]
mod retirement_service;
pub use retirement_service::RetirementResponseFence;
#[path = "mutation_receipt_reads.rs"]
mod mutation_receipt_reads;
#[path = "policy_limits_service.rs"]
mod policy_limits_service;
#[path = "schema_service.rs"]
mod schema_service;
#[path = "snapshot_leases.rs"]
mod snapshot_leases;
#[path = "staged_reads.rs"]
mod staged_reads;
#[path = "target_activation_service.rs"]
pub(crate) mod target_activation_service;
#[path = "target_initial_membership_service.rs"]
pub(crate) mod target_initial_membership_service;
#[path = "target_inspection_service.rs"]
pub(crate) mod target_inspection_service;
#[path = "target_receiver_service.rs"]
pub(crate) mod target_receiver_service;
#[path = "target_service.rs"]
pub(crate) mod target_service;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

// Charge each boxed release future before constructing its heap backing.
// The allowance matches the node governor's fixed-allocation estimate.
const RELEASE_FUTURE_ALLOCATION_ALLOWANCE: u64 = 4096;

async fn admitted_release_future<T, F>(
    admission: &Arc<NodeAdmission>,
    make_future: impl FnOnce() -> F,
) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    let bytes = u64::try_from(std::mem::size_of::<F>())
        .ok()
        .and_then(|size| size.checked_add(RELEASE_FUTURE_ALLOCATION_ALLOWANCE))
        .ok_or_else(|| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "read release future allocation size overflow",
            )
        })?;
    let _charge = admission.reserve_resident(bytes)?;
    // On completion or cancellation, the boxed future dies before its charge.
    {
        let mut future = Box::pin(make_future());
        future.as_mut().await
    }
}

struct Cursor {
    principal: String,
    query_digest: String,
    incarnation: String,
    policy_epoch: u64,
    created: Duration,
    ttl: Duration,
    /// Every row after the first page; continuations share it.
    rows: Arc<PinnedRows>,
    revision: u64,
    reservation: Arc<Reservation>,
    /// The first row of the next page.
    offset: usize,
    term: u64,
}

/// The rows after a query's first page: shared handles to documents in the
/// generation the query read, never copies. Each is charged as if it alone
/// kept its document alive, since later writes may replace it.
#[derive(Debug, Default)]
struct PinnedRows {
    rows: Vec<PinnedRow>,
    /// Admitted resident bytes, including the row vector: the measure that
    /// `max_cursor_bytes` bounds across a tenant's open cursors.
    bytes: usize,
}
#[derive(Debug)]
struct PinnedRow {
    document: Arc<Document>,
    score: Option<f32>,
}

/// Pin the rows after a query's first page for its cursor, in result order.
fn pin_rows(
    remaining: kasumi_query::RemainingRows<'_>,
    documents: &imbl::OrdMap<String, Arc<Document>>,
    max_cursor_bytes: usize,
    cancellation: &QueryCancellation,
    memory: &mut QueryMemory<Reservation>,
) -> Result<(PinnedRows, u64)> {
    if remaining.len() == 0 {
        return Ok((PinnedRows::default(), 0));
    }
    let mut charged = kasumi_query::vec_bytes::<PinnedRow>(remaining.len())?;
    memory.reserve(charged)?;
    let mut rows = Vec::with_capacity(remaining.len());
    for (id, score) in remaining {
        cancellation.check()?;
        let document = documents.get(id).ok_or_else(|| {
            Error::new(
                ErrorCode::Unavailable,
                "selected archived content requires bounded hydration",
            )
        })?;
        let bytes = crate::retained_document_bytes(document)? as u64;
        charged = charged
            .checked_add(bytes)
            .filter(|charged| *charged <= max_cursor_bytes as u64)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    "query result exceeds max_cursor_bytes; narrow the filter or use seek paging",
                )
            })?;
        memory.reserve(bytes)?;
        rows.push(PinnedRow {
            document: document.clone(),
            score,
        });
    }
    let bytes = usize::try_from(charged).map_err(|_| query_workspace_overflow())?;
    Ok((PinnedRows { rows, bytes }, charged))
}

struct ProposalWork {
    // Drop storage ownership before notifying shutdown that this job drained.
    group: RaftGroup,
    admission_gate: Arc<tokio::sync::Mutex<()>>,
    clock: Arc<dyn CommandClock>,
    source_engine: Arc<TenantEngine>,
    admission: Arc<NodeAdmission>,
    _registration: Arc<WorkRegistration>,
    // LAST: work fields/control aliases are retired before the same credit.
    _reservation: ProposalBudget,
}

// Concrete Command fields are immutable across these two serialization passes.
// The first pass allocates no bytes. Exactly counted capacity is then allocated
// under the prospective original proposal grant, before consensus submission.
fn proposal_input_len(command: &Command) -> anyhow::Result<usize> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or(std::io::ErrorKind::InvalidInput)?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, command)?;
    Ok(count.0)
}
fn encode_proposal_input(command: &Command, max_bytes: usize) -> anyhow::Result<Vec<u8>> {
    let count = proposal_input_len(command)?;
    anyhow::ensure!(count <= max_bytes, "command exceeds proposal byte budget");
    let mut bytes = Vec::with_capacity(count);
    serde_json::to_writer(&mut bytes, command)?;
    anyhow::ensure!(
        bytes.len() == count && bytes.capacity() == count,
        "concrete command encoding differs from its prospective input quote"
    );
    Ok(bytes)
}

impl ProposalWork {
    async fn run(
        &mut self,
        mut input: proposal_input::ProposalCommand,
        max_bytes: usize,
    ) -> anyhow::Result<Vec<u8>> {
        // This owner keeps the original payload before its optional topology
        // grant through every await, return and unwind. Raft receives a new Vec.
        let command = &mut input.command;
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
                    let workspace = match self.admission.reserve(
                        crate::retirement_closure::workspace_bytes(&generation.state)?,
                        None,
                    ) {
                        Ok(workspace) => workspace,
                        Err(error) if error.code == ErrorCode::ResourceExhausted => {
                            // Nothing was proposed and no retirement identity was
                            // accepted. Local capacity pressure is a definite
                            // request rejection, not a failed proposal child.
                            return Ok(serde_json::to_vec(&Err::<WriteReceipt, _>(error))?);
                        }
                        Err(error) => return Err(error.into()),
                    };
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
        let bytes = encode_proposal_input(command, max_bytes)?;
        anyhow::ensure!(
            bytes.len() <= max_bytes,
            "command exceeds proposal byte budget"
        );
        let response = if matches!(&command.operation, Operation::RetireSource(prepared) if prepared.observation.is_some())
        {
            let engine = &self.source_engine;
            let seed = kasumi_raft::RetirementLogSeed::prepare(
                command,
                engine.retirement_replay_state(command)?,
            )?;
            if let Err(error) = seed.reserve_success_capacity() {
                return Ok(serde_json::to_vec(&Err::<WriteReceipt, _>(error))?);
            }
            self.group.write_retirement(bytes, seed).await
        } else {
            let provider: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> =
                self.admission.memory().clone();
            let mut input = kasumi_raft::ApplicationInputInstall::new(bytes, provider);
            if let Operation::Mutate(batch) = &command.operation {
                input.prepare_mutation_change_tree(batch).map_err(|error| {
                    anyhow::anyhow!("mutation change-tree recipe refused: {error:?}")
                })?;
            }
            self.admission
                .memory()
                .bind_application_input(&self._reservation, &mut input)
                .map_err(|error| {
                    anyhow::anyhow!("original proposal input binding refused: {error:?}")
                })?;
            let input = input
                .finish()
                .unwrap_or_else(|_| unreachable!("original input installed once"));
            self.group
                .write(kasumi_raft::ApplicationProposal::admitted_input(input))
                .await
        };
        match response {
            Err(error) if kasumi_raft::is_application_write_capacity_denied(&error) => {
                // This typed API rejection precedes log publication. It is a
                // recoverable request result, never a failed custody child or
                // a rejection manufactured while applying a committed entry.
                Ok(serde_json::to_vec(&Err::<WriteReceipt, _>(Error::new(
                    ErrorCode::ResourceExhausted,
                    "replication task capacity is exhausted",
                )))?)
            }
            Err(error) if kasumi_raft::is_application_write_redirect(&error) => {
                // Leadership changes are request outcomes. Preserve the existing
                // uncertain-write contract: only original identity resolution
                // settles whether an earlier attempt committed.
                Ok(serde_json::to_vec(&Err::<WriteReceipt, _>(Error::new(
                    ErrorCode::UnknownOutcome,
                    "write leadership changed; resolve or retry with the same idempotency key",
                )))?)
            }
            Err(error) if kasumi_raft::is_post_commit_access_loss(&error) => {
                // The entry committed and applied; only its result release lost
                // access. That is the documented uncertain outcome, not a failed
                // custody child. The lost access itself still closes the tenant
                // through its own gate, and no result data is released here.
                Ok(serde_json::to_vec(&Err::<WriteReceipt, _>(Error::new(
                    ErrorCode::UnknownOutcome,
                    "write committed before access was lost; resolve or retry with the same idempotency key",
                )))?)
            }
            outcome => outcome,
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

#[cfg(any(test, feature = "test-utils"))]
struct FixtureCommandClock(Arc<kasumi_clock::EpochClock>);
#[cfg(any(test, feature = "test-utils"))]
impl CommandClock for FixtureCommandClock {
    fn now_ms(&self) -> Result<u64> {
        self.0
            .now_ms()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "trusted fixture clock unavailable"))
    }
}

struct DatabaseClocks {
    elapsed: Arc<dyn LeaseClock>,
    command: Arc<dyn CommandClock>,
}
impl Default for DatabaseClocks {
    fn default() -> Self {
        Self {
            elapsed: Arc::new(SystemLeaseClock),
            command: Arc::new(SystemCommandClock),
        }
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
    memory: QueryMemory<Reservation>,
    // Registration must outlive every captured input, including on unwinding.
    registration: Arc<WorkRegistration>,
}

struct QueryOutput {
    response: Result<(QueryResponse, PinnedRows)>,
    request: QueryRequest,
    memory: QueryMemory<Reservation>,
    // A completed task can retain its output after its caller disconnects.
    // Shutdown must also wait for that output and its reservation to drop.
    _registration: Arc<WorkRegistration>,
}

impl QueryWork {
    /// Copy the first page and pin the rest for a cursor, or read one seek page.
    fn run(mut self) -> QueryOutput {
        let generation = &self.generation;
        let limits = &generation.state.limits;
        let cancellation = &self.cancellation;
        let bound = kasumi_query::PageBound {
            rows: self.request.page_size(),
            bytes: limits.max_result_bytes,
        };
        if self.request.paging == Paging::Seek {
            let response =
                query_seek::seek_page(generation, &self.request, cancellation, &mut self.memory)
                    .map(|page| (page, PinnedRows::default()));
            return QueryOutput {
                response,
                request: self.request,
                memory: self.memory,
                _registration: self.registration.clone(),
            };
        }
        let response = generation
            .document_source(&self.request.collection)
            .and_then(|source| {
                let documents = &generation.state.collections[&self.request.collection].documents;
                generation
                    .indexes
                    .execute_page(
                        &source,
                        &self.request,
                        limits,
                        bound,
                        cancellation,
                        &mut self.memory,
                        |remaining, memory| {
                            pin_rows(
                                remaining,
                                documents,
                                limits.max_cursor_bytes,
                                cancellation,
                                memory,
                            )
                        },
                    )
                    .map_err(ReadFailure::into_query_error)
            });
        QueryOutput {
            response,
            request: self.request,
            memory: self.memory,
            _registration: self.registration.clone(),
        }
    }
}

// Public release audits must keep the completed payload and its charge ahead
// of the worker registration. The public method removes only the registration
// when it hands the admitted payload to its caller.
struct RegisteredOutput<T> {
    response: AdmittedOutput<T>,
    _registration: Arc<WorkRegistration>,
}

struct QueryInput {
    request: QueryRequest,
    memory: QueryMemory<Reservation>,
}

struct SnapshotInput {
    request: ReadSnapshotRequest,
    memory: QueryMemory<Reservation>,
}

// Both fresh output and cursor continuations keep their inputs and pinned
// rows before the physical charges through every fallible asynchronous release.
struct QueryResultOwner {
    request: QueryRequest,
    rows: Arc<PinnedRows>,
    memory: Option<QueryMemory<Reservation>>,
    reservation: Option<Arc<Reservation>>,
    // A continuation's page and request keep their independent charge through
    // every final release check, even if the outgoing page is dropped first.
    page_charge: Option<Arc<Reservation>>,
    _registration: Arc<WorkRegistration>,
}

impl QueryResultOwner {
    /// Copy a continuation page from the pinned rows starting at `offset`.
    fn copy_page(
        &mut self,
        offset: usize,
        revision: u64,
        max_result_bytes: usize,
        cancellation: &QueryCancellation,
    ) -> Result<QueryResponse> {
        let bound = kasumi_query::PageBound {
            rows: self.request.page_size(),
            bytes: max_result_bytes,
        };
        let rows = kasumi_query::copy_page(
            self.rows.rows[offset.min(self.rows.rows.len())..]
                .iter()
                .map(|row| (row.document.as_ref(), row.score)),
            &self.request.select,
            bound,
            cancellation,
            self.memory
                .as_mut()
                .expect("query page keeps its operation ledger"),
        )?;
        Ok(QueryResponse {
            revision,
            rows,
            aggregates: Vec::new(),
            cursor: None,
        })
    }

    fn cursor_reservation(&mut self) -> Result<Arc<Reservation>> {
        if self.reservation.is_none() {
            let memory = self
                .memory
                .as_mut()
                .expect("fresh cursor keeps its operation ledger");
            memory.reserve(OUTPUT_CHARGE_BYTES)?;
            let mut reservation = self
                .memory
                .take()
                .expect("fresh cursor keeps its operation ledger")
                .into_workspace();
            reservation.retain_workspace();
            self.reservation = Some(Arc::new(reservation));
        }
        Ok(self
            .reservation
            .as_ref()
            .expect("retained cursor charge")
            .clone())
    }

    fn prepare_page_handoff(&mut self) -> Result<()> {
        if self.reservation.is_some() && self.memory.is_some() {
            // A completed continuation releases its operation slot before the
            // strict audit, while its page and request retain their own bytes.
            self.memory
                .as_mut()
                .expect("continuation keeps its page ledger")
                .reserve(OUTPUT_CHARGE_BYTES)?;
            let mut reservation = self
                .memory
                .take()
                .expect("continuation keeps its page ledger")
                .into_workspace();
            reservation.retain_workspace();
            self.page_charge = Some(Arc::new(reservation));
        }
        drop(self.cursor_reservation()?);
        Ok(())
    }

    fn take_page_charge(&self) -> Arc<Reservation> {
        // Keep an owner copy until the request has dropped. A final release
        // failure can destroy the outgoing page before QueryResultOwner.
        self.page_charge
            .as_ref()
            .or(self.reservation.as_ref())
            .expect("prepared output charge")
            .clone()
    }
}

struct SnapshotWork {
    generation: Arc<crate::Generation>,
    request: ReadSnapshotRequest,
    cancellation: QueryCancellation,
    _permit: tokio::sync::OwnedSemaphorePermit,
    memory: QueryMemory<Reservation>,
    registration: Arc<WorkRegistration>,
}
struct SnapshotOutput {
    response: Result<SnapshotReadResponse>,
    memory: QueryMemory<Reservation>,
    _registration: Arc<WorkRegistration>,
}
impl SnapshotOutput {
    fn into_admitted(mut self) -> Result<RegisteredOutput<SnapshotReadResponse>> {
        self.response.as_ref().map_err(|error| error.clone())?;
        self.memory.reserve(OUTPUT_CHARGE_BYTES)?;
        let mut reservation = self.memory.into_workspace();
        reservation.retain_workspace();
        let charge = Arc::new(reservation);
        Ok(RegisteredOutput {
            response: AdmittedOutput::new(
                self.response.expect("checked snapshot response"),
                charge,
            ),
            _registration: self._registration,
        })
    }
}
impl SnapshotWork {
    fn run(mut self) -> SnapshotOutput {
        let response = self.evaluate();
        SnapshotOutput {
            response,
            memory: self.memory,
            _registration: self.registration,
        }
    }

    fn evaluate(&mut self) -> Result<SnapshotReadResponse> {
        let state = &self.generation.state;
        let generation = &self.generation;
        let request = &self.request;
        let cancellation = &self.cancellation;
        self.memory.scope(|memory| {
            let baseline = memory.live_bytes();
            // These are provisional output allowances, independent of the
            // separately retained source generation and archive chunk charges.
            let metadata_bytes = request.queries.iter().try_fold(
                512u64
                    .checked_add(state.incarnation.len() as u64)
                    .ok_or_else(query_workspace_overflow)?,
                |bytes, query| {
                    bytes
                        .checked_add(query.collection.len() as u64)
                        .and_then(|bytes| bytes.checked_add(256))
                        .ok_or_else(query_workspace_overflow)
                },
            )?;
            memory.reserve(metadata_bytes)?;
            let mut result = SnapshotReadResponse {
                revision: state.revision,
                incarnation: state.incarnation.clone(),
                policy_epoch: state.policy_epoch,
                schema_epoch: state.schema_epoch,
                collection_epochs: BTreeMap::new(),
                trusted_leader_time_ms: None,
                documents: Vec::new(),
                queries: Vec::new(),
            };
            for key in &request.documents {
                cancellation.check()?;
                let source = generation.document_source(&key.collection)?;
                source
                    .with_record(&key.id, None, cancellation, |record| {
                        let document = match record {
                            Some(Record::Live(document)) => Some(document),
                            Some(Record::Archived(_)) => {
                                return Err(Error::new(
                                    ErrorCode::Unavailable,
                                    "snapshot archived content requires bounded hydration",
                                ));
                            }
                            None => None,
                        };
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
                        memory.reserve(snapshot_point_workspace(key, document)?)?;
                        result.documents.push(SnapshotDocument {
                            key: key.clone(),
                            document: document.cloned(),
                        });
                        Ok(())
                    })
                    .map_err(ReadFailure::into_query_error)?;
            }
            for query in &request.queries {
                cancellation.check()?;
                let source = generation.document_source(&query.collection)?;
                // Snapshot queries are complete: no cursor follows their page.
                let bound = kasumi_query::PageBound {
                    rows: query.page_size(),
                    bytes: state.limits.max_result_bytes,
                };
                let (mut response, ()) = generation
                    .indexes
                    .execute_page(
                        &source,
                        query,
                        &state.limits,
                        bound,
                        cancellation,
                        memory,
                        |remaining, _| {
                            if remaining.len() != 0 {
                                return Err(Error::new(
                                    ErrorCode::ResourceExhausted,
                                    "snapshot query matches more rows than its limit or max_result_bytes allows",
                                ));
                            }
                            Ok(((), 0))
                        },
                    )
                    .map_err(ReadFailure::into_query_error)?;
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
            cancellation.check()?;
            let retained = memory.live_bytes() - baseline;
            Ok((result, retained))
        })
    }
}

fn query_workspace_overflow() -> Error {
    Error::new(
        ErrorCode::ResourceExhausted,
        "query workspace byte overflow",
    )
}

fn snapshot_point_workspace(key: &DocumentKey, document: Option<&Document>) -> Result<u64> {
    let body = document
        .map(|document| crate::state::lease_retention::document_heap(document, usize::MAX))
        .transpose()?
        .unwrap_or(0) as u64;
    body.checked_add(key.collection.len() as u64)
        .and_then(|bytes| bytes.checked_add(key.id.len() as u64))
        .and_then(|bytes| bytes.checked_add(256))
        .ok_or_else(query_workspace_overflow)
}

// Request clones are a provisional encoded-size allowance. They remain a
// logical baseline when later query allocations grow beyond the prepaid floor.
fn query_input_workspace<T: serde::Serialize>(request: &T, copies: u64) -> Result<u64> {
    (crate::accounting::encoded_len(request)? as u64)
        .checked_mul(3)
        .and_then(|bytes| bytes.checked_mul(copies))
        .and_then(|bytes| bytes.checked_add(512))
        .ok_or_else(query_workspace_overflow)
}

#[cfg(test)]
#[derive(Default)]
struct BoundedReadPause {
    entered: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}

fn attach_trusted_leader_time(
    response: &mut SnapshotReadResponse,
    now: u64,
    max_result_bytes: usize,
) -> Result<()> {
    response.trusted_leader_time_ms = Some(now);
    if crate::accounting::encoded_len(response)? > max_result_bytes {
        return Err(Error::new(
            ErrorCode::ResourceExhausted,
            "bounded snapshot result exceeds byte limit",
        ));
    }
    Ok(())
}

/// Every adapter calls this service; it cannot read a map without access and consistency gates.
pub struct Database {
    engine: Arc<TenantEngine>,
    group: RaftGroup,
    stores: Arc<TenantStorageSet>,
    store: Arc<TenantStore>,
    cursors: Mutex<HashMap<String, Cursor>>,
    archive_destinations: Mutex<BTreeMap<String, Arc<dyn BackupDestination>>>,
    query_slots: Arc<tokio::sync::Semaphore>,
    clock: Arc<dyn LeaseClock>,
    admission: Arc<NodeAdmission>,
    work: Arc<WorkFence>,
    security_audit: Arc<SecurityAudit>,
    audit_work: Arc<WorkFence>,
    embedded: bool,
    closing: AtomicBool,
    custody_detached: AtomicBool,
    shutdown_gate: tokio::sync::Mutex<DrainReport>,
    seal_monitor: tokio::sync::Mutex<Option<tokio::task::JoinHandle<DrainResult>>>,
    audit_worker: tokio::sync::Mutex<Option<tokio::task::JoinHandle<DrainResult>>>,
    monitor_check: database_workers::BlockingChild<bool>,
    audit_preparation:
        database_workers::BlockingChild<anyhow::Result<audit_maintenance_service::Prepared>>,
    background_stop: tokio::sync::watch::Sender<bool>,
    seal_monitor_wake: Arc<tokio::sync::Notify>,
    audit_worker_wake: Arc<tokio::sync::Notify>,
    #[cfg(test)]
    audit_worker_pause: Mutex<Option<Arc<audit_maintenance_service::WorkerPause>>>,
    #[cfg(test)]
    bounded_read_pause: Mutex<Option<Arc<BoundedReadPause>>>,
    #[cfg(test)]
    worker_test_hooks: database_worker_outcome_tests::BlockingHooks,
    audit_worker_started: AtomicBool,
    audit_worker_failures: AtomicU64,
    audit_worker_completed: AtomicU64,
    proposal_gate: Arc<tokio::sync::Mutex<()>>,
    proposals: proposal_jobs::Jobs,
    backup_producers: backup_producer_jobs::Jobs,
    command_clock: Mutex<Arc<dyn CommandClock>>,
}

/// An unexpected worker exit closes request admission even before an operator
/// joins its handle. The handle retains the actual terminal cause; this guard
/// contains only a Weak reference and does not create an owner/task cycle.
struct BackgroundWorkerExit {
    database: std::sync::Weak<Database>,
    completed: bool,
}
impl BackgroundWorkerExit {
    fn complete(&mut self, result: &DrainResult) {
        self.completed = result.is_ok();
    }
}
impl Drop for BackgroundWorkerExit {
    fn drop(&mut self) {
        if !self.completed
            && let Some(database) = self.database.upgrade()
        {
            database.closing.store(true, Ordering::Release);
            database.work.seal();
            database.audit_work.seal();
            database.background_stop.send_replace(true);
        }
    }
}

/// Extends an already authorized operation through adapter response encoding.
/// Capture before the operation, and check after constructing its final payload.
/// This is an additional release gate, not authorization to read tenant state.
pub struct ResponseFence<'a> {
    database: ResponseDatabase<'a>,
    context: RequestContext,
    policy_epoch: u64,
    cancellation: QueryCancellation,
    read_admission: Option<(Vec<ReadAssertion>, Reservation)>,
    schema_admission: Option<(Vec<ReadAssertion>, Reservation)>,
    snapshot_lease: Option<Arc<crate::state::lease_retention::LeaseHandle>>,
    // One retained ledger charge: the fixed workspace plus every adapter
    // materialization charge, released together when this fence drops.
    workspace: Reservation,
}

enum ResponseDatabase<'a> {
    Borrowed(&'a Database),
    Owned(Arc<Database>),
}

impl std::ops::Deref for ResponseDatabase<'_> {
    type Target = Database;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(database) => database,
            Self::Owned(database) => database,
        }
    }
}

fn staged_stop_acknowledgement(_error: Error) -> Error {
    Error::new(
        ErrorCode::UnknownOutcome,
        "staged resolution response was fenced; resolve the original transaction with fresh authority",
    )
}

impl<'a> ResponseFence<'a> {
    fn capture(database: ResponseDatabase<'a>, context: &RequestContext) -> Result<Self> {
        context.authorization.check_live()?;
        database.access()?;
        let generation = database.engine.generation()?;
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
        let mut workspace = database
            .admission()
            .reserve(bytes, Some(cancellation.clone()))?;
        workspace.retain(bytes);
        Ok(Self {
            database,
            context: context.clone(),
            policy_epoch: generation.state.policy_epoch,
            cancellation,
            read_admission: None,
            schema_admission: None,
            snapshot_lease: None,
            workspace,
        })
    }

    /// Charge adapter response materialization that the fixed workspace does
    /// not bound, such as a decoded JSON tree or an encoded protocol body.
    /// Charge before allocating. A refused charge leaves the fence unchanged;
    /// an accepted one stays retained until the fence drops.
    pub fn retain_response_bytes(&mut self, bytes: u64) -> Result<()> {
        self.cancellation.check()?;
        self.workspace.reserve_additional(bytes).map_err(|error| {
            if error.code == ErrorCode::ResourceExhausted {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    "response workspace budget exhausted",
                )
            } else {
                error
            }
        })
    }

    /// Bind the exact retained snapshot through final transport handoff. The
    /// handle carries expiry and identity only; it owns no document or ID roots.
    pub async fn bind_snapshot_lease(&mut self, lease_id: &str) -> Result<()> {
        if self.snapshot_lease.is_some() {
            return Err(Error::new(
                ErrorCode::Conflict,
                "response snapshot lease is already bound",
            ));
        }
        self.snapshot_lease = Some(
            self.database
                .checked_snapshot_lease(&self.context, lease_id)
                .await?,
        );
        self.check()
    }

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
        if let Some(lease) = &self.snapshot_lease
            && (!lease.live()
                || lease.term != self.database.group.raft().metrics().borrow().current_term
                || lease.header.incarnation != generation.state.incarnation
                || lease.header.policy_epoch != generation.state.policy_epoch
                || lease.header.schema_epoch != generation.state.schema_epoch)
        {
            return Err(Error::new(
                ErrorCode::CursorExpired,
                "snapshot lease expired before encoded response release",
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
        ResponseFence::capture(ResponseDatabase::Borrowed(self), context)
    }

    /// Retain this database and the original response admission through adapters
    /// whose response body outlives the engine call. Capturing an owned fence
    /// does not renew authorization or replace the original cancellation token.
    pub fn owned_response_fence(
        self: &Arc<Self>,
        context: &RequestContext,
    ) -> Result<ResponseFence<'static>> {
        ResponseFence::capture(ResponseDatabase::Owned(self.clone()), context)
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
        crate::state::staging::authorize_stop_envelope(&generation.state, context, request)?;
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

    fn finish_construction(
        engine: Arc<TenantEngine>,
        group: RaftGroup,
        stores: Arc<TenantStorageSet>,
        security_audit: Arc<SecurityAudit>,
        clocks: DatabaseClocks,
        embedded: bool,
    ) -> Arc<Self> {
        // Raft construction has already selected local or replicated semantics.
        // Do not infer that mode from a second application-only storage read.
        let store = stores.application().clone();
        let database = Arc::new(Self {
            engine,
            group,
            stores,
            store,
            cursors: Mutex::new(HashMap::new()),
            archive_destinations: Mutex::new(BTreeMap::new()),
            query_slots: Arc::new(tokio::sync::Semaphore::new(4)),
            clock: clocks.elapsed,
            admission: security_audit.admission().clone(),
            work: Arc::new(WorkFence::default()),
            security_audit,
            audit_work: Arc::new(WorkFence::default()),
            embedded,
            closing: AtomicBool::new(false),
            custody_detached: AtomicBool::new(false),
            shutdown_gate: tokio::sync::Mutex::new(DrainReport::default()),
            seal_monitor: tokio::sync::Mutex::new(None),
            audit_worker: tokio::sync::Mutex::new(None),
            monitor_check: database_workers::BlockingChild::new("database retention check"),
            audit_preparation: database_workers::BlockingChild::new("database audit preparation"),
            background_stop: tokio::sync::watch::channel(false).0,
            seal_monitor_wake: Arc::new(tokio::sync::Notify::new()),
            audit_worker_wake: Arc::new(tokio::sync::Notify::new()),
            #[cfg(test)]
            audit_worker_pause: Mutex::new(None),
            #[cfg(test)]
            bounded_read_pause: Mutex::new(None),
            #[cfg(test)]
            worker_test_hooks: Default::default(),
            audit_worker_started: AtomicBool::new(false),
            audit_worker_failures: AtomicU64::new(0),
            audit_worker_completed: AtomicU64::new(0),
            proposal_gate: Arc::new(tokio::sync::Mutex::new(())),
            proposals: proposal_jobs::Jobs::default(),
            backup_producers: backup_producer_jobs::Jobs::default(),
            command_clock: Mutex::new(clocks.command),
        });
        database.spawn_seal_monitor();
        database.start_audit_worker();
        database
    }

    pub(crate) fn admission(&self) -> &Arc<NodeAdmission> {
        &self.admission
    }

    pub fn engine(&self) -> &Arc<TenantEngine> {
        &self.engine
    }
    pub fn raft_group(&self) -> &RaftGroup {
        &self.group
    }
    pub fn stores(&self) -> &Arc<TenantStorageSet> {
        &self.stores
    }
    /// Stop admission, drain background work, and release owned keys and state.
    /// Retained application handles still own this database/store; drop them
    /// before reopening the same node file. A canceled shutdown can be awaited again.
    pub async fn shutdown(&self) -> DrainResult {
        self.shutdown_inner(false).await
    }

    /// Fence new application work without revoking storage access still needed
    /// by the owned Raft runtime while its shutdown is in progress.
    pub fn seal_admission(&self) {
        self.closing.store(true, Ordering::Release);
        self.work.seal();
        self.audit_work.seal();
    }

    /// Trusted installed lifecycle transition. The source is already permanently
    /// retired; this neither authorizes a proof nor reopens an application route.
    /// Retained old Database handles cannot later seal the new custody owner.
    pub async fn detach_retired_custody(&self) -> anyhow::Result<Arc<kasumi_store::CustodyStore>> {
        self.shutdown_inner(true).await?;
        Ok(self.group.storage_domains().custody().clone())
    }

    async fn shutdown_inner(&self, detach_custody: bool) -> DrainResult {
        let mut report = self.shutdown_gate.lock().await;
        let mut retained = None;
        if detach_custody && !self.custody_detached.load(Ordering::Acquire) {
            let detached = self
                .group
                .recover_retired_custody(self.stores.custody())
                .and_then(|retired| {
                    if retired {
                        Ok(())
                    } else {
                        Err(kasumi_store::ScratchOperationFailure::Operation(
                            anyhow::anyhow!("source is not permanently retired"),
                        ))
                    }
                });
            if let Err(error) = detached {
                let marker = match error {
                    kasumi_store::ScratchOperationFailure::Operation(original) => original,
                    preparation => {
                        // The group's prepaid seat retains an initial admission
                        // original; the Store census retains registered native
                        // originals. This foreign marker owns neither original.
                        anyhow::anyhow!("{preparation}")
                    }
                };
                return Err(DrainFailure::retained(report.record(
                    "custody detach",
                    0,
                    marker,
                )));
            }
            self.custody_detached.store(true, Ordering::Release);
        }
        self.seal_admission();
        self.engine.seal_application_source_consumers();
        self.background_stop.send_replace(true);
        self.audit_worker_wake.notify_one();
        {
            let mut monitor = self.seal_monitor.lock().await;
            if let Some(task) = monitor.as_mut() {
                match task.await {
                    Ok(Ok(())) => {}
                    Ok(Err(failure)) => report.merge(&failure),
                    Err(error) => {
                        report.record("database seal monitor", 0, error.into());
                    }
                }
                monitor.take();
            }
        }
        if let Err(failure) = self.monitor_check.drain().await {
            report.merge(&failure);
        }
        // A caller timeout never stops an admitted application proposal. Join
        // its actual child before stopping Raft or releasing durable owners.
        if let Err(failure) = self.proposals.drain().await {
            report.merge(&failure);
            if failure.completion() == DrainCompletion::Retained {
                return report.outcome(Some(failure));
            }
        }
        // A cancelled backup caller does not own its blocking producer. Join
        // the exact child and retain its terminal result before Raft or storage
        // can close beneath its generation and work reservation.
        if let Err(failure) = self.backup_producers.drain().await {
            report.merge(&failure);
            if failure.completion() == DrainCompletion::Retained {
                return report.outcome(Some(failure));
            }
        }
        if let Err(failure) = self.group.shutdown().await {
            report.merge(&failure);
            if failure.completion() == DrainCompletion::Retained {
                retained = Some(failure);
            }
        }
        {
            let mut worker = self.audit_worker.lock().await;
            if let Some(task) = worker.as_mut() {
                match task.await {
                    Ok(Ok(())) => {}
                    Ok(Err(failure)) => report.merge(&failure),
                    Err(error) => {
                        report.record("database audit worker", 0, error.into());
                    }
                }
                worker.take();
            }
        }
        if let Err(failure) = self.audit_preparation.drain().await {
            report.merge(&failure);
        }
        self.work.drain().await;
        self.audit_work.drain().await;
        if let Err(failure) = self.store.shutdown().await {
            report.merge(&failure);
            if failure.completion() == DrainCompletion::Retained {
                retained = Some(failure);
            }
        }
        if !self.custody_detached.load(Ordering::Acquire)
            && let Err(failure) = self
                .group
                .storage_domains()
                .custody()
                .store()
                .shutdown()
                .await
        {
            report.merge(&failure);
            if failure.completion() == DrainCompletion::Retained {
                retained = Some(failure);
            }
        }
        self.engine.seal();
        self.cursors
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
        report.outcome(retained)
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

    /// Fixed, non-sensitive class of the first failed serving gate, in the same
    /// order as `access`. Diagnostics only: admission still uses check_serving,
    /// and this neither seals resident state nor reveals a provider message.
    pub fn serving_failure_class(&self) -> Option<&'static str> {
        if self.closing.load(Ordering::Acquire) {
            return Some("shutting_down");
        }
        if self.proposals.check().is_err() {
            return Some("proposal_work_closed");
        }
        if self.store.check_access().is_err() {
            return Some("key_lease_sealed");
        }
        if let Some(class) = self.group.access_failure_class() {
            return Some(class);
        }
        let Ok(generation) = self.engine.generation() else {
            return Some("engine_sealed");
        };
        if generation
            .state
            .target_lifecycle
            .get(&generation.state.incarnation)
            .is_some_and(|target| target.activation.is_none())
        {
            return Some("target_activation_incomplete");
        }
        drop(generation);
        self.store
            .storage_access()
            .check_serving()
            .err()
            .map(|_| "restore_preparation")
    }
    fn materialization_access(&self) -> Result<()> {
        if self.closing.load(Ordering::Acquire) {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "database is shutting down",
            ));
        }
        self.proposals.check()?;
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
        let mut stop = self.background_stop.subscribe();
        let wake = self.seal_monitor_wake.clone();
        let mut exit = BackgroundWorkerExit {
            database: weak.clone(),
            completed: false,
        };
        let task = tokio::spawn(async move {
            let result = async {
                loop {
                    if *stop.borrow() {
                        break;
                    }
                    tokio::select! {
                        _ = stop.changed() => break,
                        _ = wake.notified() => {},
                        changed = notices.changed() => { if changed.is_err() { break; } },
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {},
                    }
                    let Some(db) = weak.upgrade() else { break };
                    // Explicit shutdown stops the idle loop and joins this actual
                    // blocking child before discarding the monitor handle. The work
                    // registration also retains roots if an external actor aborts it.
                    let Ok(registration) = db.work.begin(QueryCancellation::default()) else {
                        break;
                    };
                    struct RetentionCheck {
                        database: Arc<Database>,
                        _registration: WorkRegistration,
                    }
                    let work = RetentionCheck {
                        database: db.clone(),
                        _registration: registration,
                    };
                    #[cfg(test)]
                    let hook = work
                        .database
                        .worker_test_hooks
                        .monitor
                        .lock()
                        .unwrap()
                        .take();
                    let serving =
                        db.monitor_check
                            .run(move || {
                                #[cfg(test)]
                                if let Some(hook) = hook {
                                    hook();
                                }
                                let db = &work.database;
                                let _ = db.access();
                                if db.engine.generation().is_err() {
                                    db.work.seal();
                                }
                                let status = db.admission.snapshot();
                                let pressured = status.pressured || !status.sample_usable;
                                let now = db.clock.now();
                                db.cursors.lock().unwrap_or_else(|p| p.into_inner()).retain(
                                    |_, c| !pressured && now.saturating_sub(c.created) < c.ttl,
                                );
                                let term = db.group.raft().metrics().borrow().current_term;
                                db.engine.leases.expire_idle(pressured, term);
                                let serving = db.engine.generation().is_ok();
                                drop(work);
                                serving
                            })
                            .await?;
                    if !serving {
                        break;
                    }
                }
                Ok(())
            }
            .await;
            exit.complete(&result);
            result
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
            .map_err(|_cause| {
                // Retain the erased Raft cause only in explicit fixture builds.
                // Metrics distinguish a cached follower from a current leader
                // whose quorum/storage failed. Error behavior stays unchanged.
                #[cfg(any(test, feature = "test-utils"))]
                eprintln!(
                    "kasumi-engine read quorum unavailable: cause={_cause:#}; metrics={:?}",
                    self.group.raft().metrics().borrow(),
                );
                Error::new(ErrorCode::Unavailable, "read quorum unavailable")
            })?;
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
        crate::state::staging::authorize_scope(
            &self.engine.generation()?.state,
            context,
            &reference.scope,
        )?;
        self.barrier().await?;
        let mut observed = self
            .read_staged_identity(context, &reference.scope, &reference.transaction_id)
            .await?;
        let stage = crate::state::staging::lookup(&observed.state, context, reference)?;
        let policy_epoch = observed.state.policy_epoch;
        let revision = observed.state.revision;
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
                let strict = observed.state.policy.strict_read_audit
                    || observed.strict_collections.contains(&collection);
                (collection, kind, strict)
            })
            .collect();
        let status = observed
            .status
            .take()
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "staged transaction not found"))?;
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
        let current = self.engine.generation()?;
        crate::state::staging::authorize_scope(&current.state, context, &reference.scope)?;
        crate::state::staging::authorize_manifest(&current.state, context, &status.manifest)?;
        if current.state.policy_epoch != policy_epoch {
            return Err(Error::new(
                ErrorCode::Conflict,
                "staged status policy changed before release",
            ));
        }
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

    async fn audit_snapshot_result<T>(
        &self,
        context: &RequestContext,
        result: std::result::Result<T, crate::SnapshotFailure>,
    ) -> std::result::Result<T, crate::SnapshotFailure> {
        match result {
            Err(crate::SnapshotFailure::AdmissionRefused(original)) => {
                Err(crate::SnapshotFailure::AdmissionRefused(original))
            }
            Err(crate::SnapshotFailure::Creation(original)) => {
                Err(crate::SnapshotFailure::Creation(original))
            }
            Err(crate::SnapshotFailure::Source(original)) => {
                Err(crate::SnapshotFailure::Source(original))
            }
            Err(crate::SnapshotFailure::Operation(original)) => self
                .audit_result(context, Err(original))
                .await
                .map_err(Into::into),
            Ok(value) => self
                .audit_result(context, Ok(value))
                .await
                .map_err(Into::into),
        }
    }

    async fn audit_snapshot_write_result<T>(
        &self,
        context: &RequestContext,
        result: std::result::Result<T, crate::SnapshotFailure>,
    ) -> std::result::Result<T, crate::SnapshotFailure> {
        let committed = result.is_ok();
        let result = self.audit_snapshot_result(context, result).await;
        if committed {
            result.map_err(|original| match original {
                crate::SnapshotFailure::AdmissionRefused(original) => {
                    crate::SnapshotFailure::AdmissionRefused(original)
                }
                crate::SnapshotFailure::Operation(original) => {
                    credential_acknowledgement(original).into()
                }
                crate::SnapshotFailure::Creation(original) => {
                    crate::SnapshotFailure::Creation(original)
                }
                crate::SnapshotFailure::Source(original) => {
                    crate::SnapshotFailure::Source(original)
                }
            })
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
        session_id: uuid::Uuid,
    ) -> std::result::Result<uuid::Uuid, crate::SnapshotFailure> {
        self.backup_checkpoint(context, destination, session_id)
            .await
            .map(|proof| proof.backup_id())
    }

    pub(crate) async fn mutate_topology(
        &self,
        context: RequestContext,
        input: proposal_input::OperationInput,
    ) -> Result<WriteReceipt> {
        let result = self.submit_input(context.clone(), input).await;
        self.audit_write_result(&context, result).await
    }

    async fn submit(&self, context: RequestContext, operation: Operation) -> Result<WriteReceipt> {
        self.submit_input(context, proposal_input::OperationInput::ordinary(operation))
            .await
    }

    async fn submit_input(
        &self,
        context: RequestContext,
        input: proposal_input::OperationInput,
    ) -> Result<WriteReceipt> {
        input.check_admission(self.admission())?;
        let operation = &input.operation;
        context.authorization.check_live()?;
        self.materialization_access()?;
        self.engine.check_operation_access(operation)?;
        let restore_completion = matches!(operation, Operation::MaintenanceAudit(event) if event.action == "restore" && event.outcome == "completed");
        if context.tenant != self.engine.generation()?.state.tenant {
            return Err(Error::new(ErrorCode::Forbidden, "tenant access denied"));
        }
        let staged_read = self.staged_operation_read(&context, operation).await?;
        let preflight = self.engine.generation()?;
        let stage_state = staged_read
            .as_ref()
            .map_or(&preflight.state, |read| &read.state);
        // Authorization repeats during ordered apply, so queued operations cannot bypass policy changes.
        match operation {
            Operation::ActivateSchema(request) => crate::state::schema::authorize(
                &self.engine.generation()?.state,
                &context,
                request,
            )?,
            Operation::BeginStaged(request) => {
                crate::state::staging::authorize_begin(stage_state, &context, request)?
            }
            Operation::AppendStaged(request) => {
                crate::state::staging::authorize_upload(
                    stage_state,
                    &context,
                    &request.transaction,
                )?;
            }
            Operation::StopStaged(request) => {
                crate::state::staging::authorize_stop(stage_state, &context, request)?
            }
            Operation::FinalizeStaged(reference) => {
                crate::state::staging::authorize_upload(stage_state, &context, reference)?;
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
                    "schema_activation_status" | "schema_read" | "policy_limits_read" => {
                        Action::Admin
                    }
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
        let needs_writer = match operation {
            Operation::ActivateSchema(request) => request
                .changes
                .iter()
                .any(|change| has_text(change.definition())),
            Operation::FinalizeStaged(reference) => {
                let stage = crate::state::staging::lookup(stage_state, &context, reference)?;
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
        } else if let Operation::FinalizeStaged(reference) = operation {
            let stage = crate::state::staging::lookup(stage_state, &context, reference)?;
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
        let patch_workspace =
            merge_patch_proposal_workspace(operation, stage_state, &generation.state, &context)?;
        let max_command_payload = match operation {
            Operation::ActivateSchema(_) => MAX_SCHEMA_CHANGESET_BYTES,
            // Permanent receipt replay is ordered before today's tenant batch
            // admission. Retain the immutable request envelope so lowering a
            // tenant budget cannot hide an already committed outcome. A new
            // identity still meets the configured limit in apply_batch.
            Operation::Mutate(_) => 8 << 20,
            _ => generation.state.limits.max_batch_bytes,
        };
        let command_budget = max_command_payload
            .saturating_add(64 << 10)
            .saturating_mul(3)
            .saturating_add(staged_workspace)
            .saturating_add(patch_workspace)
            .saturating_add(if matches!(operation, Operation::RetireSource(_)) {
                kasumi_raft::MAX_RETIREMENT_SEED_BYTES.saturating_mul(4)
            } else {
                0
            })
            .saturating_add(if needs_writer { 15_000_000 } else { 0 })
            as u64;
        drop(generation);
        drop(preflight);
        drop(staged_read);
        self.proposals.prepare(self.admission())?;
        // This exact input/control/token quote is additional to the existing
        // producer work estimate. It does not certify that estimate as an apply
        // candidate model. A known mutation change-tree recipe is included
        // separately above the old estimate; all scopes share ONE reservation.
        let max_bytes = max_command_payload.saturating_add(64 << 10);
        let input_requirements = kasumi_raft::ApplicationInputRequirements::for_capacity(max_bytes);
        let input_requirements = if let Operation::Mutate(batch) = operation {
            input_requirements
                .with_mutation_change_tree(batch)
                .map_err(|_| {
                    Error::new(
                        ErrorCode::ResourceExhausted,
                        "mutation change-tree quote overflow",
                    )
                })?
        } else {
            input_requirements
        };
        let input_request = input_requirements
            .with_token::<ProposalBudget>()
            .map_err(|_| {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    "proposal input quote overflow",
                )
            })?;
        let command_budget = command_budget
            .checked_add(input_request)
            .and_then(|bytes| {
                ProposalBudget::required_bytes()
                    .ok()
                    .and_then(|control| bytes.checked_add(control))
            })
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    "proposal input quote overflow",
                )
            })?;
        let reservation = self.admission().reserve(command_budget, None)?;
        let release_context = context.clone();
        // Transfer the actual input and its exact optional grant together;
        // even an unpolled/refused proposal future has one ordered owner.
        let command = input.into_command(context);
        let encoded_len = proposal_input_len(&command.command)
            .map_err(|_| Error::new(ErrorCode::InvalidArgument, "command encoding failed"))?;
        let max_bytes = max_command_payload.saturating_add(64 << 10);
        if encoded_len > max_bytes {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "command too large",
            ));
        }
        let registration = self.work.begin(QueryCancellation::default())?;
        let proposal = self.proposals.start(
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
                _reservation: ProposalBudget::new(reservation),
                _registration: Arc::new(registration),
            },
            command,
            max_bytes,
        )?;
        let response = proposal.wait(Duration::from_secs(10)).await?;
        let result = &response.bytes;
        if restore_completion {
            let outcome = serde_json::from_slice::<Result<WriteReceipt>>(result).map_err(|_| {
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
            self.release_submitted_response(&release_context, result)
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

    /// Read all requested documents and complete bounded queries from exactly
    /// one authorized generation. Returned assertions can fence a later batch.
    pub async fn read_snapshot(
        &self,
        context: &RequestContext,
        request: ReadSnapshotRequest,
    ) -> Result<AdmittedOutput<SnapshotReadResponse>> {
        let result = self.read_snapshot_inner(context, request).await;
        self.audit_result(context, result)
            .await
            .map(|output| output.response)
    }

    async fn read_snapshot_inner(
        &self,
        context: &RequestContext,
        request: ReadSnapshotRequest,
    ) -> Result<RegisteredOutput<SnapshotReadResponse>> {
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
        if request
            .time_bounds
            .as_ref()
            .is_some_and(|bounds| bounds.not_before_ms > bounds.not_after_ms)
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "snapshot time bounds are inverted",
            ));
        }
        let time_bounds = request.time_bounds.clone();
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
            if query.cursor.is_some() || query.paging != Paging::Snapshot {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "snapshot reads require complete queries without cursors or seek paging",
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
        let workspace = snapshot_workspace(&self.engine.generation()?.state.limits, &request)?;
        let reservation = self
            .admission()
            .reserve(workspace, Some(cancellation.clone()))?;
        drop(keys);
        let mut input = SnapshotInput {
            request,
            memory: QueryMemory::empty(reservation),
        };
        input
            .memory
            .reserve(query_input_workspace(&input.request, 1)?)?;
        let request = &input.request;
        tokio::select! {
            result = self.barrier() => result?,
            _ = cancelled(&cancellation) => return Err(cancelled_error()),
        }
        let generation = self.engine.generation()?;
        let state = &generation.state;
        if snapshot_workspace(&state.limits, request)? > workspace {
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
            if query.page_size() == 0 || query.page_size() > state.limits.max_page_size {
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
        let mut work = SnapshotWork {
            generation: generation.clone(),
            request: input.request,
            cancellation: cancellation.clone(),
            _permit: permit,
            memory: input.memory,
            registration,
        };
        work.generation = self
            .hydrate_history(
                work.generation.clone(),
                &work.request.documents,
                &work.request.queries,
                &cancellation,
                &mut work.memory,
            )
            .await?;
        let worker = tokio::task::spawn_blocking(move || work.run());
        let mut output = tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(5), worker) => result
                .map_err(|_| Error::new(ErrorCode::ResourceExhausted, "snapshot deadline exceeded"))?
                .map_err(|_| Error::new(ErrorCode::Unavailable, "snapshot worker failed"))?,
            _ = cancelled(&cancellation) => return Err(cancelled_error()),
        };
        let response = output.response.as_mut().map_err(|error| error.clone())?;
        let max_result_bytes = state.limits.max_result_bytes;
        drop(generation);
        if let Some(bounds) = time_bounds {
            #[cfg(test)]
            {
                let pause = self.bounded_read_pause.lock().unwrap().clone();
                if let Some(pause) = pause {
                    pause.entered.notify_one();
                    pause.resume.notified().await;
                }
            }
            // Serialize with command admission. A completed prior proposal is
            // included by the second barrier; a new proposal cannot overtake
            // this witness while the gate is held.
            let _gate = self.proposal_gate.lock().await;
            self.barrier().await?;
            let leader_term = if self.embedded {
                None
            } else {
                let metrics = self.group.raft().metrics().borrow().clone();
                if metrics.current_leader != Some(metrics.id) {
                    return Err(Error::new(
                        ErrorCode::Unavailable,
                        "trusted leader time requires the current leader",
                    ));
                }
                Some(metrics.current_term)
            };
            // Strict read auditing (including this request's own confirmed
            // audit) advances the tenant revision without changing the data
            // observed by the snapshot. Fence the exact snapshot read set
            // instead: authority epochs, point versions, and query collection
            // epochs still reject a concurrent change to the result.
            let read_set = response.read_assertions();
            crate::state::validate_read_assertions(
                &self.engine.generation()?.state,
                &read_set.iter().collect::<Vec<_>>(),
                0,
                read_set.len(),
            )?;
            let now = self
                .command_clock
                .lock()
                .map_err(|_| Error::new(ErrorCode::Unavailable, "command clock unavailable"))?
                .now_ms()?;
            if now < bounds.not_before_ms || now > bounds.not_after_ms {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "snapshot time is outside trusted leader bounds",
                ));
            }
            context.authorization.check_live()?;
            context.authorization.check_admitted_at(now)?;
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
            if let Some(term) = leader_term {
                let metrics = self.group.raft().metrics().borrow().clone();
                if metrics.current_leader != Some(metrics.id) || metrics.current_term != term {
                    return Err(Error::new(
                        ErrorCode::Unavailable,
                        "trusted leader changed during snapshot read",
                    ));
                }
            }
            attach_trusted_leader_time(response, now, max_result_bytes)?;
        }
        let output = output.into_admitted()?;
        let response = &output.response;
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
        Ok(output)
    }

    async fn release(
        &self,
        context: &RequestContext,
        collection: &str,
        revision: u64,
        strict: bool,
        policy_epoch: u64,
    ) -> Result<()> {
        admitted_release_future(self.admission(), || {
            self.release_event(
                context,
                Some(collection),
                revision,
                strict,
                policy_epoch,
                "read",
            )
        })
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
            admitted_release_future(self.admission(), || {
                self.submit(context.clone(), Operation::Audit(event))
            })
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
            "schema_activation_status" | "schema_read" | "policy_limits_read" => Action::Admin,
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
    ) -> Result<Option<MutationReceipt>> {
        let result = self.operation_receipt_inner(context, idempotency_key).await;
        self.audit_result(context, result).await
    }

    async fn operation_receipt_inner(
        &self,
        context: &RequestContext,
        idempotency_key: &str,
    ) -> Result<Option<MutationReceipt>> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        self.access()?;
        self.engine
            .authorize_discovery(context, Action::Write, None)?;
        validate_name(idempotency_key)?;
        self.barrier().await?;
        let read = self
            .read_mutation_receipt(context, idempotency_key, deadline)
            .await?;
        let receipt = &read.receipt;
        let epoch = read.epoch;
        let revision = read.revision;
        let strict = read.strict;
        if let Some(receipt) = receipt {
            for collection in &receipt.collections {
                let strict = strict || read.strict_collections.contains(collection);
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
        context.authorization.check_live()?;
        if tokio::time::Instant::now() >= deadline {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "mutation receipt deadline exceeded",
            ));
        }
        Ok(read.receipt.map(|r| MutationReceipt {
            scope: r.scope,
            request_digest: r.request_digest,
            outcome: r.outcome,
        }))
    }

    pub async fn query(
        &self,
        context: &RequestContext,
        request: QueryRequest,
    ) -> Result<AdmittedOutput<QueryResponse>> {
        let result = self.query_inner(context, request).await;
        self.audit_result(context, result)
            .await
            .map(|output| output.response)
    }

    async fn query_inner(
        &self,
        context: &RequestContext,
        request: QueryRequest,
    ) -> Result<RegisteredOutput<QueryResponse>> {
        self.access()?;
        self.engine
            .authorize(context, Some(&request.collection), Action::Read)?;
        let cancellation = QueryCancellation::default();
        let _cancel_on_drop = CancelOnDrop(cancellation.clone());
        let registration = Arc::new(self.work.begin(cancellation.clone())?);
        let workspace = query_workspace(&self.engine.generation()?.state.limits, &request)?;
        let mut input = QueryInput {
            request,
            memory: QueryMemory::empty(
                self.admission()
                    .reserve(workspace, Some(cancellation.clone()))?,
            ),
        };
        input
            .memory
            .reserve(query_input_workspace(&input.request, 3)?)?;
        let request = &input.request;
        let digest = query_digest(request)?;
        // Continuations retain old data but must establish current authority on a serving leader.
        tokio::select! {
            result = self.barrier() => result?,
            _ = cancelled(&cancellation) => return Err(cancelled_error()),
        }
        self.engine
            .authorize(context, Some(&request.collection), Action::Read)?;
        let generation = self.engine.generation()?;
        let state = &generation.state;
        if query_workspace(&state.limits, request)? > workspace {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "query limits changed during admission; retry",
            ));
        }
        let term = self.group.raft().metrics().borrow().current_term;
        if request.page_size() == 0 || request.page_size() > state.limits.max_page_size {
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
        // A fresh query's page comes from its worker, as does every seek page;
        // a snapshot continuation copies the next page from its pinned rows.
        let seek = request.paging == Paging::Seek;
        let continuation = request.cursor.as_ref().filter(|_| !seek);
        let (mut full, mut page, offset, created) = if let Some(token) = continuation {
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
            let (offset, revision, created) = (cursor.offset, cursor.revision, cursor.created);
            let mut full = QueryResultOwner {
                request: input.request,
                rows: cursor.rows.clone(),
                memory: Some(input.memory),
                reservation: Some(cursor.reservation.clone()),
                page_charge: None,
                _registration: registration.clone(),
            };
            drop(cursors);
            let page = full.copy_page(
                offset,
                revision,
                state.limits.max_result_bytes,
                &cancellation,
            )?;
            let next = offset + page.rows.len();
            (full, page, next, created)
        } else {
            let permit = self.query_slots.clone().try_acquire_owned().map_err(|_| {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    "query concurrency limit reached",
                )
            })?;
            let mut work = QueryWork {
                generation: generation.clone(),
                request: input.request,
                cancellation: cancellation.clone(),
                _permit: permit,
                memory: input.memory,
                registration: registration.clone(),
            };
            // Seek pages read resident rows straight from their index.
            if !seek {
                work.generation = self
                    .hydrate_history(
                        work.generation.clone(),
                        &[],
                        std::slice::from_ref(&work.request),
                        &cancellation,
                        &mut work.memory,
                    )
                    .await?;
            }
            let worker = tokio::task::spawn_blocking(move || work.run());
            let output = tokio::select! {
                result = tokio::time::timeout(Duration::from_secs(5), worker) => result
                    .map_err(|_| Error::new(ErrorCode::ResourceExhausted, "query deadline exceeded"))?
                    .map_err(|_| Error::new(ErrorCode::Unavailable, "query worker failed"))?,
                _ = cancelled(&cancellation) => return Err(cancelled_error()),
            };
            let QueryOutput {
                response,
                request,
                memory,
                _registration,
            } = output;
            let (mut page, rows) = response?;
            if !seek {
                page.revision = state.revision;
            }
            (
                QueryResultOwner {
                    request,
                    rows: Arc::new(rows),
                    memory: Some(memory),
                    reservation: None,
                    page_charge: None,
                    _registration,
                },
                page,
                0,
                self.clock.now(),
            )
        };
        let max_cursors = state.limits.max_cursors;
        let max_cursor_bytes = state.limits.max_cursor_bytes;
        // Each completed page releases its operation slot before a strict
        // read needs to submit its audit, while retaining every admitted byte.
        // Continuations retain a page charge independent of the full cursor.
        full.prepare_page_handoff()?;
        let request = &full.request;
        drop(generation);
        tokio::select! {
            result = self.release(context, &request.collection, page.revision, strict, policy_epoch) => result?,
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
        if !seek && offset < full.rows.rows.len() {
            let bytes = full.rows.bytes;
            let replaced = request.cursor.as_ref().and_then(|token| cursors.get(token));
            let retained_bytes: usize = cursors.values().map(|cursor| cursor.rows.bytes).sum();
            if cursors
                .len()
                .saturating_sub(usize::from(replaced.is_some()))
                >= max_cursors
                || retained_bytes
                    .saturating_sub(replaced.map_or(0, |c| c.rows.bytes))
                    .saturating_add(bytes)
                    > max_cursor_bytes
            {
                return Err(Error::new(
                    ErrorCode::ResourceExhausted,
                    "cursor memory budget exhausted",
                ));
            }
            let reservation = full.cursor_reservation()?;
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
                    rows: full.rows.clone(),
                    revision: page.revision,
                    reservation,
                    offset,
                    term,
                },
            );
            page.cursor = Some(token);
        }
        let request = &full.request;
        if let Some(token) = request.cursor.as_ref().filter(|_| !seek) {
            cursors.remove(token);
        }
        drop(cursors);
        let output = RegisteredOutput {
            response: AdmittedOutput::new(page, full.take_page_charge()),
            _registration: full._registration.clone(),
        };
        let request = &full.request;
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
            Ok(output)
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

fn merge_patch_proposal_workspace(
    operation: &Operation,
    state: &TenantState,
    current: &TenantState,
    context: &RequestContext,
) -> Result<usize> {
    // Use the immutable ceilings enforced by validate_limits: an administrator
    // can raise current limits while this proposal waits behind the write gate.
    let (patch_count, expansion_limit) = match operation {
        Operation::Mutate(batch) => (
            batch
                .operations
                .iter()
                .filter(|mutation| matches!(mutation, Mutation::Patch { .. }))
                .count(),
            8 << 20,
        ),
        Operation::FinalizeStaged(reference) => {
            let stage = crate::state::staging::lookup(state, context, reference)?;
            if !stage.is_active() {
                return Ok(0);
            }
            // The admitted identity read retains only the stage header. Match
            // its immutable identity to the live generation's uploaded chunks
            // so completed put/delete-only stages need no patch workspace.
            let stage = crate::state::staging::lookup(current, context, reference)
                .ok()
                .filter(|stage| stage.is_active())
                .unwrap_or(stage);
            let patch_count = if stage.chunks.len() == stage.manifest.chunk_digests.len() {
                stage
                    .chunks
                    .values()
                    .flat_map(|chunk| &chunk.operations)
                    .filter(|mutation| matches!(mutation, Mutation::Patch { .. }))
                    .count()
            } else {
                // Missing chunks can arrive before ordered finalization. Their
                // manifest commits their count but not their decoded operation kinds.
                stage.manifest.operation_count
            };
            (patch_count, 64 << 20)
        }
        _ => return Ok(0),
    };
    Ok(crate::state::merge_patch_workspace(
        patch_count,
        expansion_limit,
    ))
}

fn query_workspace(limits: &Limits, request: &QueryRequest) -> Result<u64> {
    kasumi_query::query_workspace_estimate(limits, request)
}

/// Identity of a query apart from its cursor: continuations must repeat it.
fn query_digest(request: &QueryRequest) -> Result<String> {
    let mut normalized = request.clone();
    normalized.cursor = None;
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(&normalized)
            .map_err(|_| Error::new(ErrorCode::InvalidArgument, "query encoding failed"))?,
    )))
}

fn snapshot_workspace(limits: &Limits, request: &ReadSnapshotRequest) -> Result<u64> {
    // Queries run sequentially: reserve one maximum query workspace, plus the
    // retained combined result and one document clone through final release.
    request
        .queries
        .iter()
        .try_fold(0, |maximum, query| {
            query_workspace(limits, query).map(|bytes| maximum.max(bytes))
        })?
        .checked_add(
            (limits.max_result_bytes as u64)
                .checked_mul(3)
                .ok_or_else(query_workspace_overflow)?,
        )
        .and_then(|bytes| bytes.checked_add((limits.max_document_bytes as u64).checked_mul(3)?))
        .ok_or_else(query_workspace_overflow)
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
    include!("service_proposal_tests.rs");
    include!("service_topology_input_tests.rs");
    include!("service_mutation_receipt_tests.rs");
    include!("service_serving_tests.rs");
    include!("service_query_workspace_tests.rs");
    include!("service_query_pagination_memory_tests.rs");
    include!("service_change_feed_memory_tests.rs");
    include!("service_point_memory_tests.rs");
    include!("service_retirement_tests.rs");
    include!("service_custody_tests.rs");
    use super::*;
    use crate::admission::AdmissionConfig;
    use kasumi_store::test_utils::LocalKeyProvider;
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
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let (persistent_config, scratch_config) =
            crate::test_utils::fixture_disk_configs(directory.path()).unwrap();
        let storage = crate::test_utils::FixtureStorage::open(
            &persistent_config,
            &scratch_config,
            Default::default(),
        )
        .unwrap();
        let node = storage
            .create_new(
                directory.path().join("persistent/node.kv"),
                kasumi_store::test_utils::NODE_STORE_ID,
            )
            .unwrap();
        let audit_store = TenantStore::initialize_catalog_fixture(
            node.clone(),
            crate::SECURITY_TENANT.into(),
            Arc::new(LocalKeyProvider::new([0xA7; 32])),
        )
        .await
        .unwrap();
        let audit = SecurityAudit::initialize(
            audit_store,
            kasumi_types::AuditRetentionBudget::default(),
            storage.admission.clone(),
        )
        .unwrap();
        let context = RequestContext {
            authorization: kasumi_types::RequestAuthorization::service_identity(),
            tenant: "deadline".into(),
            principal: "owner".into(),
            scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin, Action::Audit]),
            request_id: "deadline-test".into(),
        };
        let store = TenantStore::initialize_catalog_fixture(
            node,
            context.tenant.clone(),
            Arc::new(LocalKeyProvider::new([0xB7; 32])),
        )
        .await
        .unwrap();
        let db = crate::test_utils::open_fixture(
            kasumi_store::test_utils::initialize_custody_fixture(
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
                strict_read_audit: true,
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
        assert!(db.get(&context, "docs", "queued").await.unwrap().is_none());

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
                .outcome
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        assert!(
            db.get(&context, "docs", "canceled")
                .await
                .unwrap()
                .is_none()
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
        let read = |not_before_ms, not_after_ms| ReadSnapshotRequest {
            documents: vec![DocumentKey {
                collection: "docs".into(),
                id: "accepted".into(),
            }],
            queries: vec![],
            time_bounds: Some(ReadTimeBounds {
                not_before_ms,
                not_after_ms,
            }),
        };
        let exact = db
            .read_snapshot(&context, read(base + 22, base + 22))
            .await
            .unwrap();
        assert_eq!(exact.trusted_leader_time_ms, Some(base + 22));
        let audited = db.engine.generation().unwrap();
        assert!(audited.state.revision > exact.revision);
        assert_eq!(audited.state.audits.back().unwrap().action, "read");
        assert_eq!(
            audited.state.audits.back().unwrap().data_revision,
            Some(exact.revision)
        );
        drop(audited);
        assert_eq!(
            exact.documents[0].document.as_ref().unwrap().version,
            data_epoch
        );
        assert_eq!(
            db.read_snapshot(&context, read(base + 23, base + 23))
                .await
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        clock.0.store(base + 23, Ordering::SeqCst);
        let exact = db
            .read_snapshot(&context, read(base + 23, base + 23))
            .await
            .unwrap();
        assert_eq!(exact.trusted_leader_time_ms, Some(base + 23));
        assert_eq!(
            db.read_snapshot(&context, read(base + 24, base + 23))
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        let pause = Arc::new(BoundedReadPause::default());
        *db.bounded_read_pause.lock().unwrap() = Some(pause.clone());
        let pending_db = db.clone();
        let pending_context = context.clone();
        let pending_request = read(base + 23, base + 23);
        let pending = tokio::spawn(async move {
            pending_db
                .read_snapshot(&pending_context, pending_request)
                .await
        });
        pause.entered.notified().await;
        db.mutate(
            context.clone(),
            MutationBatch {
                idempotency_key: "competing".into(),
                read_set: vec![ReadAssertion::Before {
                    not_after_ms: base + 23,
                }],
                operations: vec![Mutation::Put {
                    collection: "docs".into(),
                    id: "accepted".into(),
                    body: json!({"value":2}),
                    expected: Precondition::Version(
                        exact.documents[0].document.as_ref().unwrap().version,
                    ),
                }],
            },
        )
        .await
        .unwrap();
        pause.resume.notify_one();
        assert_eq!(
            pending.await.unwrap().unwrap_err().code,
            ErrorCode::Conflict
        );
        *db.bounded_read_pause.lock().unwrap() = None;
        let before_audit = db.engine.generation().unwrap().state.revision;
        let strict = db
            .read_snapshot(&context, read(base + 23, base + 23))
            .await
            .unwrap();
        assert_eq!(strict.trusted_leader_time_ms, Some(base + 23));
        assert!(db.engine.generation().unwrap().state.revision > before_audit);
        let strict_read_set = strict.read_assertions();
        crate::state::validate_read_assertions(
            &db.engine.generation().unwrap().state,
            &strict_read_set.iter().collect::<Vec<_>>(),
            0,
            strict_read_set.len(),
        )
        .unwrap();
        // A second strict read also advances the revision solely for audit.
        db.read_snapshot(&context, read(base + 23, base + 23))
            .await
            .unwrap();
        crate::state::validate_read_assertions(
            &db.engine.generation().unwrap().state,
            &strict_read_set.iter().collect::<Vec<_>>(),
            0,
            strict_read_set.len(),
        )
        .unwrap();
        db.mutate(
            context.clone(),
            MutationBatch {
                idempotency_key: "change-after-strict-read".into(),
                read_set: vec![],
                operations: vec![Mutation::Put {
                    collection: "docs".into(),
                    id: "accepted".into(),
                    body: json!({"value":3}),
                    expected: Precondition::Version(
                        strict.documents[0].document.as_ref().unwrap().version,
                    ),
                }],
            },
        )
        .await
        .unwrap();
        assert_eq!(
            crate::state::validate_read_assertions(
                &db.engine.generation().unwrap().state,
                &strict_read_set.iter().collect::<Vec<_>>(),
                0,
                strict_read_set.len(),
            )
            .unwrap_err()
            .code,
            ErrorCode::Conflict
        );
        db.shutdown().await.unwrap();
    }

    #[test]
    fn bounded_snapshot_witness_checks_final_encoded_result_limit() {
        let response = SnapshotReadResponse {
            revision: 1,
            incarnation: uuid::Uuid::new_v4().to_string(),
            policy_epoch: 1,
            schema_epoch: 1,
            collection_epochs: BTreeMap::new(),
            trusted_leader_time_ms: None,
            documents: Vec::new(),
            queries: Vec::new(),
        };
        let plain_bytes = crate::accounting::encoded_len(&response).unwrap();
        let mut witnessed = response.clone();
        attach_trusted_leader_time(&mut witnessed, u64::MAX, usize::MAX).unwrap();
        let witnessed_bytes = crate::accounting::encoded_len(&witnessed).unwrap();
        assert!(witnessed_bytes > plain_bytes);
        assert_eq!(
            attach_trusted_leader_time(&mut response.clone(), u64::MAX, plain_bytes)
                .unwrap_err()
                .code,
            ErrorCode::ResourceExhausted
        );
        let mut response = response;
        attach_trusted_leader_time(&mut response, u64::MAX, witnessed_bytes).unwrap();
        assert_eq!(response.trusted_leader_time_ms, Some(u64::MAX));
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
            memory: QueryMemory::new(admission.reserve(1024, None).unwrap(), 0).unwrap(),
            registration,
        };
        fence.seal();
        let output = tokio::task::spawn_blocking(move || work.run())
            .await
            .unwrap();
        assert!(output.response.is_err());
        assert!(weak.upgrade().is_none());
        assert_eq!(slots.available_permits(), 1);
        assert_eq!(crate::test_utils::reserved_payload_bytes(&admission), 1024);
        let mut draining = Box::pin(fence.drain());
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(draining.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        // Represents a disconnected caller abandoning a completed task output.
        drop(output);
        draining.await;
        assert_eq!(crate::test_utils::reserved_payload_bytes(&admission), 0);
    }

    #[tokio::test]
    async fn response_fence_retains_adapter_charges_in_its_entry_until_drop() {
        let fixture = CredentialFixture::new().await;
        let before = fixture.db.admission().snapshot();
        let mut fence = fixture.db.owned_response_fence(&fixture.context).unwrap();
        let fixed = fixture.db.admission().snapshot();
        assert!(fixed.reserved_bytes > before.reserved_bytes);
        fence.retain_response_bytes(4096).unwrap();
        fence.retain_response_bytes(1 << 20).unwrap();
        let charged = fixture.db.admission().snapshot();
        assert_eq!(
            charged.reserved_bytes,
            fixed.reserved_bytes + 4096 + (1 << 20)
        );
        // Adapter charges join the fence's retained entry: no ledger entry or
        // operation slot of their own, and nothing to leak on a later error.
        assert_eq!(charged.live_reservations, fixed.live_reservations);
        assert_eq!(charged.inflight_operations, before.inflight_operations);
        // A charge beyond the node budget is refused before any allocation
        // and leaves the retained charge unchanged.
        let refused = fence.retain_response_bytes(u64::MAX / 2).unwrap_err();
        assert_eq!(refused.code, ErrorCode::ResourceExhausted);
        assert_eq!(
            fixture.db.admission().snapshot().reserved_bytes,
            charged.reserved_bytes
        );
        fence.check().unwrap();
        // Pressure-cancelled responses take no further materialization.
        fence.cancellation.cancel();
        assert_eq!(
            fence.retain_response_bytes(1).unwrap_err().code,
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            fixture.db.admission().snapshot().reserved_bytes,
            charged.reserved_bytes
        );
        drop(fence);
        let released = fixture.db.admission().snapshot();
        assert_eq!(released.reserved_bytes, before.reserved_bytes);
        assert_eq!(released.live_reservations, before.live_reservations);
        fixture.close().await;
    }
}

// Component qualification only; production wiring requires the exact per-Database
// source-worker registry and shutdown drain described in this module.
#[cfg(test)]
#[path = "query_source_work.rs"]
mod query_source_work;
