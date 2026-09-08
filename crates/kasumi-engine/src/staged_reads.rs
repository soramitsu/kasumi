//! Bounded permanent-stage point reads run under owned blocking work. Outputs
//! retain only headers and authorization metadata, never document/index roots or
//! uploaded payloads after the worker has completed.
use super::*;

pub(super) struct StagedRead {
    pub state: TenantState,
    pub status: Option<StagedTransactionStatus>,
    pub strict_collections: BTreeSet<String>,
    _reservation: Reservation,
    _registration: Arc<WorkRegistration>,
}
impl Database {
    pub(super) async fn read_staged_identity(
        &self,
        context: &RequestContext,
        scope: &StagedTransactionScope,
        transaction_id: &str,
    ) -> Result<StagedRead> {
        context.authorization.check_live()?;
        self.access()?;
        let generation = self.engine.generation()?;
        crate::state::staging::authorize_scope(&generation.state, context, scope)?;
        let key = crate::state::staging::identity(&context.principal, transaction_id)?;
        // Select the header and terminal namespace without retaining the full
        // document/index generation while the blocking job waits for storage.
        let terminals = generation.terminals.clone();
        let mut selected = generation.state.staged_transactions.get(&key).cloned();
        let selected_status = selected.as_ref().map(StagedTransaction::status);
        if let Some(stage) = &mut selected { stage.chunks.clear(); }
        let mut state = crate::snapshot_codec::metadata(&generation.state);
        state.restore_lineage = generation.state.restore_lineage.clone();
        state.target_lifecycle = generation.state.target_lifecycle.clone();
        let strict_collections = generation.state.collections.iter()
            .filter(|(_, collection)| collection.definition.strict_read_audit)
            .map(|(name, _)| name.clone()).collect();
        drop(generation);
        let cancellation = QueryCancellation::default();
        let _cancel = CancelOnDrop(cancellation.clone());
        let reservation = self.admission().reserve(8 << 20, Some(cancellation.clone()))?;
        let registration = Arc::new(self.work.begin(cancellation.clone())?);
        let context = context.clone();
        let scope = scope.clone();
        let worker = tokio::task::spawn_blocking(move || -> Result<StagedRead> {
            cancellation.check()?;
            context.authorization.check_live()?;
            crate::state::staging::authorize_scope(&state, &context, &scope)?;
            let (stage, status) = if let Some(active) = selected {
                (Some(active), selected_status)
            } else {
                let stage = terminals.get(&key).map_err(point_error)?
                    .map(|row| {
                        row.validate(&state).map_err(point_error)?;
                        Ok::<_, Error>(row.stage)
                    }).transpose()?;
                let status = stage.as_ref().map(StagedTransaction::status);
                (stage, status)
            };
            if let Some(mut stage) = stage {
                stage.chunks.clear();
                state.staged_transactions.insert(key, stage);
            }
            cancellation.check()?;
            context.authorization.check_live()?;
            drop(terminals);
            Ok(StagedRead { state, status, strict_collections, _reservation: reservation, _registration: registration })
        });
        tokio::time::timeout(Duration::from_secs(10), worker).await
            .map_err(|_| Error::new(ErrorCode::Unavailable, "staged point read deadline exceeded"))?
            .map_err(|_| Error::new(ErrorCode::Unavailable, "staged point read worker failed"))?
    }
    pub(super) async fn staged_operation_read(&self, context: &RequestContext, operation: &Operation) -> Result<Option<StagedRead>> {
        let (scope, id) = match operation {
            Operation::BeginStaged(request) => (&request.scope, &request.transaction_id),
            Operation::AppendStaged(request) => (&request.transaction.scope, &request.transaction.transaction_id),
            Operation::FinalizeStaged(reference) => (&reference.scope, &reference.transaction_id),
            Operation::StopStaged(request) => (&request.original.scope, &request.original.transaction_id),
            _ => return Ok(None),
        };
        self.read_staged_identity(context, scope, id).await.map(Some)
    }
}
fn point_error(error: anyhow::Error) -> Error {
    error.downcast_ref::<Error>().cloned().unwrap_or_else(|| Error::new(ErrorCode::Corruption, error.to_string()))
}
