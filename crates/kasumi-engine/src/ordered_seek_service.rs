//! A separate bounded operation. Complete Query and snapshot semantics stay intact.
use super::*;

struct OrderedSeekWork {
    generation: Arc<crate::Generation>,
    request: OrderedSeekRequest,
    cancellation: QueryCancellation,
    _permit: tokio::sync::OwnedSemaphorePermit,
    reservation: Reservation,
    registration: Arc<WorkRegistration>,
}
struct OrderedSeekOutput {
    response: Result<OrderedSeekResponse>,
    _reservation: Reservation,
    _registration: Arc<WorkRegistration>,
}
fn content_hash(value: &impl serde::Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(value).map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                "ordered seek content encoding failed",
            )
        })?,
    )))
}
fn conflict(message: &str) -> Error {
    Error::new(ErrorCode::Conflict, message)
}
fn source_identity(
    state: &TenantState,
    request: &OrderedSeekRequest,
) -> Result<(u64, String, String)> {
    let collection = state
        .collections
        .get(&request.collection)
        .ok_or_else(|| Error::new(ErrorCode::NotFound, "ordered seek collection absent"))?;
    let index = collection
        .definition
        .indexes
        .iter()
        .find(|index| index.name == request.index && index.unique)
        .ok_or_else(|| {
            Error::new(
                ErrorCode::IndexRequired,
                "ordered seek requires a declared unique tuple index",
            )
        })?;
    let index_sha256 = content_hash(index)?;
    let request_sha256 = kasumi_query::ordered_seek_request_sha256(request)?;
    if let Some(cursor) = &request.continuation {
        if cursor.revision == 0
            || cursor.revision > state.revision
            || cursor.tenant != state.tenant
            || cursor.incarnation != state.incarnation
            || cursor.collection_epoch != collection.data_epoch
            || cursor.policy_epoch != state.policy_epoch
            || cursor.schema_epoch != state.schema_epoch
            || cursor.index_sha256 != index_sha256
            || cursor.request_sha256 != request_sha256
        {
            return Err(conflict("ordered seek continuation source changed"));
        }
    }
    Ok((collection.data_epoch, index_sha256, request_sha256))
}
impl OrderedSeekWork {
    fn run(self) -> OrderedSeekOutput {
        let response = (|| {
            let state = &self.generation.state;
            let (collection_epoch, index_sha256, request_sha256) =
                source_identity(state, &self.request)?;
            let page = self.generation.indexes.ordered_seek_with_cancellation(
                &state.collections,
                &self.request,
                &state.limits,
                &self.cancellation,
            )?;
            let revision = self
                .request
                .continuation
                .as_ref()
                .map_or(state.revision, |cursor| cursor.revision);
            if page
                .rows
                .iter()
                .any(|row| row.version > revision || row.version == 0)
            {
                return Err(conflict(
                    "ordered seek source version exceeds original revision",
                ));
            }
            let continuation = page.after_key.map(|after_key| OrderedSeekContinuation {
                revision,
                tenant: state.tenant.clone(),
                incarnation: state.incarnation.clone(),
                collection_epoch,
                policy_epoch: state.policy_epoch,
                schema_epoch: state.schema_epoch,
                index_sha256: index_sha256.clone(),
                request_sha256: request_sha256.clone(),
                after_key,
            });
            let response = OrderedSeekResponse {
                revision,
                observed_revision: state.revision,
                tenant: state.tenant.clone(),
                incarnation: state.incarnation.clone(),
                collection_epoch,
                policy_epoch: state.policy_epoch,
                schema_epoch: state.schema_epoch,
                index_sha256,
                request_sha256,
                rows: page.rows,
                continuation,
                index_entries_visited: page.index_entries_visited,
            };
            if serde_json::to_vec(&response)
                .map_err(|_| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        "ordered seek result encoding failed",
                    )
                })?
                .len()
                > state.limits.max_result_bytes
            {
                return Err(Error::new(
                    ErrorCode::ResourceExhausted,
                    "ordered seek result byte budget exceeded",
                ));
            }
            Ok(response)
        })();
        OrderedSeekOutput {
            response,
            _reservation: self.reservation,
            _registration: self.registration,
        }
    }
}
fn workspace(limits: &Limits, request: &OrderedSeekRequest) -> u64 {
    // A bounded page, one lookahead and encoding copy; no lifetime candidate set,
    // sort workspace, text index copy or generation retained between requests.
    limits
        .max_result_bytes
        .saturating_mul(3)
        .saturating_add(limits.max_document_bytes.saturating_mul(4))
        .saturating_add(
            request
                .limit
                .saturating_add(1)
                .min(limits.max_page_size.saturating_add(1))
                .saturating_mul(8192),
        )
        .saturating_add(65536) as u64
}
impl Database {
    pub async fn ordered_seek(
        &self,
        context: &RequestContext,
        request: OrderedSeekRequest,
    ) -> Result<OrderedSeekResponse> {
        let result = self.ordered_seek_inner(context, request).await;
        self.audit_result(context, result).await
    }
    async fn ordered_seek_inner(
        &self,
        context: &RequestContext,
        request: OrderedSeekRequest,
    ) -> Result<OrderedSeekResponse> {
        self.access()?;
        self.engine
            .authorize(context, Some(&request.collection), Action::Read)?;
        let cancellation = QueryCancellation::default();
        let _cancel_on_drop = CancelOnDrop(cancellation.clone());
        let registration = Arc::new(self.work.begin(cancellation.clone())?);
        let admitted = workspace(&self.engine.generation()?.state.limits, &request);
        let reservation = self
            .admission()
            .reserve(admitted, Some(cancellation.clone()))?;
        tokio::select! {result=self.barrier()=>result?,_ = cancelled(&cancellation)=>return Err(cancelled_error())};
        self.engine
            .authorize(context, Some(&request.collection), Action::Read)?;
        let generation = self.engine.generation()?;
        let state = &generation.state;
        if workspace(&state.limits, &request) > admitted {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "ordered seek limits changed during admission",
            ));
        }
        // Validate continuation before starting work; the retained worker
        // generation establishes immutable custody until computation completes.
        source_identity(state, &request)?;
        let strict = state.policy.strict_read_audit
            || state
                .collections
                .get(&request.collection)
                .is_some_and(|collection| collection.definition.strict_read_audit);
        let policy_epoch = state.policy_epoch;
        let schema_epoch = state.schema_epoch;
        let incarnation = state.incarnation.clone();
        let permit = self.query_slots.clone().try_acquire_owned().map_err(|_| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "ordered seek concurrency limit reached",
            )
        })?;
        let work = OrderedSeekWork {
            generation,
            request: request.clone(),
            cancellation: cancellation.clone(),
            _permit: permit,
            reservation,
            registration,
        };
        let worker = tokio::task::spawn_blocking(move || work.run());
        let output = tokio::select! {result=tokio::time::timeout(Duration::from_secs(5),worker)=>result.map_err(|_|Error::new(ErrorCode::ResourceExhausted,"ordered seek deadline exceeded"))?.map_err(|_|Error::new(ErrorCode::Unavailable,"ordered seek worker failed"))?,_ = cancelled(&cancellation)=>return Err(cancelled_error())};
        let OrderedSeekOutput {
            response,
            _reservation,
            _registration,
        } = output;
        let response = response?;
        tokio::select! {result=self.release(context,&request.collection,response.revision,strict,policy_epoch)=>result?,_ = cancelled(&cancellation)=>return Err(cancelled_error())};
        let current = self.engine.generation()?;
        if current.state.schema_epoch != schema_epoch || current.state.incarnation != incarnation {
            return Err(conflict(
                "ordered seek schema or incarnation changed before release",
            ));
        }
        context.authorization.check_live()?;
        cancellation.check()?;
        Ok(response)
    }
}
