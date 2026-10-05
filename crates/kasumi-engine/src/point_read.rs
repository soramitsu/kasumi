//! Point-result custody. This does not change resident cache membership or
//! claim complete per-document source capacity accounting: the existing point
//! floor and archived decoder allowances remain provisional.
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
    pub(super) document: Option<Arc<Document>>,
    generation: Option<Arc<crate::Generation>>,
    history: history_reads::HistoryReadCache,
    registration: Option<Arc<WorkRegistration>>,
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
    document: Arc<Document>,
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
struct PendingPoint<T> {
    response: T,
    read: PointRead,
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

    async fn read_document<T>(
        &self,
        context: &RequestContext,
        collection: &str,
        id: &str,
        select: impl FnOnce(&mut PointRead) -> Result<T>,
    ) -> Result<RegisteredPoint<Option<T>>> {
        self.access()?;
        self.engine
            .authorize(context, Some(collection), Action::Read)?;
        let cancellation = QueryCancellation::default();
        let _cancel_on_drop = CancelOnDrop(cancellation.clone());
        let floor = (self.engine.generation()?.state.limits.max_document_bytes as u64)
            .checked_mul(3)
            .ok_or_else(query_workspace_overflow)?;
        let mut read = PointRead::new(
            self.admission()
                .reserve(floor, Some(cancellation.clone()))?,
        );
        read.claim(point_arc_bytes::<WorkRegistration>()?)?;
        read.registration = Some(Arc::new(self.work.begin(cancellation.clone())?));
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
        let _record = crate::index_source::record(selected, id, generation.state.revision)?;
        let revision = generation.state.revision;
        let policy_epoch = generation.state.policy_epoch;
        let strict =
            generation.state.policy.strict_read_audit || selected.definition.strict_read_audit;
        let Some(document) = self
            .history_document(generation, collection, id, &cancellation, &mut read.history)
            .await?
        else {
            // Absence releases no document body. It returns where the former
            // NOT_FOUND outcome did: before the read-release audit and fences.
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
        let mut pending = PendingPoint { response, read };
        // A hot returned handle retains only its exact Document, never the
        // complete Generation and unrelated indexes/history/state roots.
        drop(pending.read.generation.take());
        self.release(context, collection, revision, strict, policy_epoch)
            .await?;
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
