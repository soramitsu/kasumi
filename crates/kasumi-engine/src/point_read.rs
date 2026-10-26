//! Point-result custody. The lookup owns only its registration workspace;
//! native/archive sources admit their decoding separately, and owned outputs
//! admit their exact cloned representation before allocation.
use super::*;
use std::mem::size_of;

pub(super) fn point_arc_bytes<T>() -> Result<u64> {
    size_of::<T>()
        .checked_add(2 * size_of::<usize>())
        .and_then(usize::checked_next_power_of_two)
        .and_then(|bytes| bytes.checked_add(64))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(query_workspace_overflow)
}

// Every selected source and history chunk dies before the ledger. Registration
// backing is also admitted by that ledger, so it precedes the charge fields.
pub(super) struct PointRead {
    pub(super) document: Option<history_reads::ReadDocument>,
    pub(super) generation: Option<Arc<crate::Generation>>,
    history: history_reads::HistoryReadCache,
    pub(super) registration: Option<Arc<WorkRegistration>>,
    memory: Option<QueryMemory<Reservation>>,
    charge: Option<Arc<Reservation>>,
}
impl PointRead {
    pub(super) fn new(reservation: Reservation) -> Self {
        Self {
            document: None,
            generation: None,
            history: history_reads::HistoryReadCache::new(),
            registration: None,
            memory: Some(QueryMemory::empty(reservation)),
            charge: None,
        }
    }
    fn claim(&mut self, bytes: u64) -> Result<()> {
        self.memory
            .as_mut()
            .expect("point workspace present")
            .reserve(bytes)
    }
    fn retain_charge(&mut self) -> Arc<Reservation> {
        let mut reservation = self
            .memory
            .take()
            .expect("point workspace present")
            .into_workspace();
        reservation.retain_workspace();
        let charge = Arc::new(reservation);
        self.charge = Some(charge.clone());
        charge
    }
    pub(super) fn owned(&mut self) -> Result<AdmittedOutput<Document>> {
        let bytes = kasumi_query::document_clone_bytes(
            self.document.as_deref().expect("selected point document"),
        )?
        .checked_add(OUTPUT_CHARGE_BYTES)
        .ok_or_else(query_workspace_overflow)?;
        self.claim(bytes)?;
        // Both source and admitted clone coexist until PointRead is destroyed.
        let document = self
            .document
            .as_deref()
            .expect("selected point document")
            .clone();
        Ok(AdmittedOutput::new(document, self.retain_charge()))
    }
    pub(super) fn shared(&mut self) -> Result<SharedDocument> {
        if matches!(self.document.as_ref(), Some(OwnedDocument::Stored(_))) {
            self.claim(OUTPUT_CHARGE_BYTES)?;
            let OwnedDocument::Stored(document) =
                self.document.take().expect("selected point document")
            else {
                unreachable!()
            };
            // Native decoding already supplied an independently admitted owner.
            // The point workspace stays with registration through final release,
            // then retires instead of becoming a second output memory charge.
            self.retain_charge();
            return Ok(document);
        }
        self.claim(
            point_arc_bytes::<SharedPointOwner>()?
                .checked_add(OUTPUT_CHARGE_BYTES)
                .ok_or_else(query_workspace_overflow)?,
        )?;
        let charge = self.retain_charge();
        let owner = Arc::new(SharedPointOwner {
            document: self.document.take().expect("selected point document"),
            // A cold point's document Arc alone does not retain the chunk's
            // charge. Transfer the entire bounded single-point cache with it.
            _history: std::mem::replace(&mut self.history, history_reads::HistoryReadCache::new()),
            _charge: charge,
        });
        Ok(SharedDocument::from_admitted_owner(owner))
    }
}

struct SharedPointOwner {
    document: history_reads::ReadDocument,
    _history: history_reads::HistoryReadCache,
    _charge: Arc<Reservation>,
}
impl AdmittedDocumentOwner for SharedPointOwner {
    fn document(&self) -> &Document {
        self.document.as_ref()
    }
}

// The additional Arc refers to the same reservation, not another ledger slot.
// It keeps registration backing charged on failure as response is destroyed.
struct RegisteredPoint<T> {
    response: T,
    _registration: Arc<WorkRegistration>,
    _charge: Arc<Reservation>,
}
pub(super) struct PendingPoint<T> {
    response: T,
    read: PointRead,
}

fn point_deadline_error() -> Error {
    Error::new(ErrorCode::ResourceExhausted, "point read deadline exceeded")
}

impl PointRead {
    /// The original registered owner moves into the blocking child. A cancelled
    /// waiter cannot release its source, input credit or worker permit early.
    pub(super) async fn read_native<T: Send + 'static>(
        mut self,
        slot: Arc<DocumentSlot>,
        permit: tokio::sync::OwnedSemaphorePermit,
        cancellation: &QueryCancellation,
        select: impl FnOnce(&mut Self) -> Result<T> + Send + 'static,
    ) -> Result<PendingPoint<Option<T>>> {
        // This bounds native work only. Queueing and the existing read barrier
        // do not consume the selected source's native operation allowance.
        let deadline = tokio::time::Instant::now() + kasumi_store::NATIVE_READ_TIMEOUT;
        let worker_cancellation = cancellation.clone();
        let worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            worker_cancellation.check()?;
            let generation = self.generation.as_ref().expect("selected point generation");
            self.document = Some(
                slot.load_owned(generation.document_resolver())
                    .map_err(document_load_error)?,
            );
            worker_cancellation.check()?;
            let response = Some(select(&mut self)?);
            drop(self.document.take());
            self.history = history_reads::HistoryReadCache::new();
            Ok(PendingPoint {
                response,
                read: self,
            })
        });
        tokio::select! {
            result = tokio::time::timeout_at(deadline, worker) => result
                .map_err(|_| point_deadline_error())?
                .map_err(|_| Error::new(ErrorCode::Unavailable, "point read worker failed"))?,
            _ = cancelled(cancellation) => Err(cancelled_error()),
        }
    }
}

impl Database {
    /// Read one document after a read barrier. A missing document is
    /// `Ok(None)`; a missing collection or denied access is an error.
    pub async fn get(
        &self,
        context: &RequestContext,
        collection: &str,
        id: &str,
    ) -> Result<Option<AdmittedOutput<Document>>> {
        let result = self
            .read_document(context, collection, id, PointRead::owned)
            .await;
        self.audit_result(context, result)
            .await
            .map(|output| output.response)
    }

    /// Return immutable previously released plaintext without cloning its JSON
    /// body. Handle clones retain the same source and real admission; current
    /// authorization, key access and read-audit gates still apply to each read.
    pub async fn get_shared(
        &self,
        context: &RequestContext,
        collection: &str,
        id: &str,
    ) -> Result<Option<SharedDocument>> {
        let result = self
            .read_document(context, collection, id, PointRead::shared)
            .await;
        self.audit_result(context, result)
            .await
            .map(|output| output.response)
    }

    async fn read_document<T: Send + 'static>(
        &self,
        context: &RequestContext,
        collection: &str,
        id: &str,
        select: impl FnOnce(&mut PointRead) -> Result<T> + Send + 'static,
    ) -> Result<RegisteredPoint<Option<T>>> {
        self.access()?;
        self.engine
            .authorize(context, Some(collection), Action::Read)?;
        let cancellation = QueryCancellation::default();
        let _cancel_on_drop = CancelOnDrop(cancellation.clone());
        let floor = point_arc_bytes::<WorkRegistration>()?;
        let waiting = self
            .admission()
            .reserve_waiting(floor, Some(cancellation.clone()))?;
        let registration = Arc::new(self.work.begin(cancellation.clone())?);
        // Point reads share the existing four read workers. Waiting requests
        // keep their registration charged without occupying active work slots.
        // The caller deadline/cancellation bounds this wait; a native timeout
        // starts only when the selected source is dispatched below.
        let permit = tokio::select! {
            result = self.query_slots.clone().acquire_owned() =>
                result.map_err(|_| Error::new(ErrorCode::Sealed, "query workers sealed"))?,
            _ = cancelled(&cancellation) => return Err(cancelled_error()),
        };
        let mut read = PointRead::new(
            self.admission()
                .reserve(floor, Some(cancellation.clone()))?,
        );
        read.claim(floor)?;
        read.registration = Some(registration);
        drop(waiting);
        tokio::select! {
            result = self.barrier() => result?,
            _ = cancelled(&cancellation) => return Err(cancelled_error()),
        }
        cancellation.check()?;
        self.engine
            .authorize(context, Some(collection), Action::Read)?;
        read.generation = Some(self.engine.generation()?);
        let generation = read.generation.as_ref().expect("selected point generation");
        let selected = generation
            .state
            .collections
            .get(collection)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "collection not found"))?;
        // Reuse the captured source's identity/version checks for hot and cold
        // records before the history resolver may clone an internal Arc.
        let _header = crate::index_source::header(selected, id, generation.state.revision)?;
        let revision = generation.state.revision;
        let policy_epoch = generation.state.policy_epoch;
        let strict =
            generation.state.policy.strict_read_audit || selected.definition.strict_read_audit;
        let mut pending = if let Some(slot) = selected.documents.get(id).cloned() {
            read.read_native(slot, permit, &cancellation, select)
                .await?
        } else {
            let document = tokio::select! {
                result = self.history_document(
                    generation, collection, id, &cancellation, &mut read.history,
                ) => result?,
                _ = cancelled(&cancellation) => return Err(cancelled_error()),
            };
            let Some(document) = document else {
                // Absence releases no body and preserves the existing audit
                // boundary, before the read-release audit and output fences.
                read.retain_charge();
                return Ok(RegisteredPoint {
                    response: None,
                    _registration: read.registration.clone().expect("point registration"),
                    _charge: read.charge.clone().expect("retained point charge"),
                });
            };
            read.document = Some(document);
            cancellation.check()?;
            let response = Some(select(&mut read)?);
            drop(read.document.take());
            read.history = history_reads::HistoryReadCache::new();
            drop(permit);
            PendingPoint { response, read }
        };
        // A hot returned handle retains only its exact Document, never the
        // complete Generation and unrelated indexes/history/state roots.
        drop(pending.read.generation.take());
        tokio::select! {
            result = self.release(
                context, collection, revision, strict, policy_epoch,
            ) => result?,
            _ = cancelled(&cancellation) => return Err(cancelled_error()),
        }
        cancellation.check()?;
        self.admission().check_release(&cancellation)?;
        self.access()?;
        Ok(RegisteredPoint {
            response: pending.response,
            _registration: pending
                .read
                .registration
                .as_ref()
                .expect("point registration")
                .clone(),
            _charge: pending
                .read
                .charge
                .as_ref()
                .expect("retained point charge")
                .clone(),
        })
    }
}
